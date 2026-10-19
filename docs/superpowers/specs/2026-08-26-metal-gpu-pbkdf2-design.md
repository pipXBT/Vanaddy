# Metal GPU PBKDF2 Offload for EVM Search — Design Spec

- **Date:** 2026-08-26
- **Status:** approved for implementation
- **Scope:** EVM chain only. Solana / Bitcoin / TON / Monero are out of scope.
- **Goal:** offload BIP-39 PBKDF2-HMAC-SHA512 (c = 2048, salt `"mnemonic"`, dkLen 64)
  to the Apple GPU, running alongside the existing CPU workers.
- **Expected gain:** 1.2x-2.0x on EVM candidate throughput. Not a clean 2x - see
  "Risks that remain" #4 (compositor contention).

## How this design was produced

Four independent design agents (kernel, FFI, search-loop integration, correctness)
each covered one dimension; each design was then attacked by two adversarial
reviewers, one with a correctness lens and one with a liveness/resource lens.
29 high-severity defects were surfaced and folded in. One dimension came back
`broken` and its topology was rejected outright (see the verdict roll-up below).

## Measurement provenance

Every performance figure in this document was measured on the target machine
(Apple M1, 4P+4E CPU, 8-core GPU), not estimated:

| Quantity | Measured |
|---|---|
| EVM candidate, 1 P-core | 308.1 us (PBKDF2 260.8 = 84.7%, BIP-32 40.2 = 13.0%, kG+Keccak 16.9 = 5.5%) |
| CPU all-core EVM | 11,500-14,900 cand/s |
| CPU SHA-512 | 15.7 M compressions/s/core; 52-61 M/s all-core (hardware `sha512h`) |
| GPU SHA-512 | 59-64 M compressions/s |
| GPU BIP-39 seeds, sustained | 13,634-14,768 seeds/s at 2.2-4.6 ms/dispatch |
| CPU/GPU contention (static screen) | none: GPU held 59.3 M/s (92% of solo peak) for 75 s under a saturated CPU |

The adopted kernel was independently re-validated before this spec was written:
SHA-512("abc") correct; the BIP-39 canonical vector reproduced under six chunk
schedules including irregular ones (`[1,1000,46,1000]`, `[2046,1]`, `[1,1,2045]`);
and 2,048 distinct passwords of length 1-128 matched CommonCrypto with 0
mismatches. The kernel and its two validation harnesses lived under
`docs/superpowers/specs/prototype/` and have since been removed: the kernel
ships as `src/gpu/pbkdf2_bip39.metal`, and the Rust GPU tests plus the startup
self-test cover what the harnesses checked. Recover any of them with
`git show c979d32:docs/superpowers/specs/prototype/<file>`:

- `pbkdf2_bip39.metal` - the kernel this spec adopts
- `verifyC.m` - correctness harness (vectors, chunk-schedule invariance, CommonCrypto differential)
- `verify7.m` - the dispatch-granularity tuning grid

---

# Vanaddy — Metal GPU PBKDF2 Offload (EVM only) — Merged Design Spec

**Reviewer verdict roll-up.** Three of four dimension designs came back `sound_with_fixes`. **The `ffi` dimension came back `broken`** on its central choice: a *persistent-slot, rotating-group* GPU topology (`keys/cur/acc/rem` buffers, harvest group `launch % groups` every launch). Two independent reviewers reproduced the same fatal result — the slot pool is never primed, launch 0 harvests 512 slots that have received zero PBKDF2 iterations, the 1-in-256 `ring` audit fires immediately, and **the feature self-disables within 36 ms of every start, on every machine, having produced zero usable seeds**. Its self-test (one R=2048 dispatch on a fresh pool) structurally cannot exercise the rotating schedule, so the bug is invisible to it. That topology is **rejected outright**.

The adopted topology is the `kernel` dimension's **resumable wave model**, which existed as working, independently re-verified code at `docs/superpowers/specs/prototype/pbkdf2_bip39.metal` (since removed; recover with `git show c979d32:docs/superpowers/specs/prototype/pbkdf2_bip39.metal`) (2,048 distinct passwords, lengths 1–128, 0 mismatches vs CommonCrypto at count=2048 across 8 threadgroups; chunk-schedule invariance verified at R ∈ {2047,1024,…,1} and under irregular schedules).

Everything else below is the merge, with every high- and medium-severity defect folded in as the design.

---

## Architecture

```
                      ┌───────────────────────── GPU thread "vanaddy-gpu" ─────────────────────────┐
                      │  (owns every Objective-C object; nothing Metal-shaped crosses this line)   │
                      │                                                                            │
                      │  init (ON this thread, not the UI thread):                                 │
                      │    MTLCreateSystemDefaultDevice → queue → newLibraryWithSource              │
                      │    (include_str! kernel, ~60-95 ms cold / ~1.5 ms warm)                     │
                      │    → 2 pipelines → self_test(count=512, 3 chunk schedules)                  │
                      │    stop checked after EACH step                                             │
                      │                                                                            │
                      │  steady state, per WAVE = 8192 candidates:                                  │
                      │    1. fill:   8192 × Mnemonic::new(Words12, English)   (thread_rng)         │
                      │               → entropy[8192] (Zeroizing) + pack_key_block → keys buf       │
                      │               stop checked every 512                                        │
                      │    2. prologue dispatch (1 cb, waited, status checked)                      │
                      │    3. 256 iterate dispatches, R=8, 4 per command buffer, depth 3            │
                      │       stop + fault checked at every command-buffer boundary (~8.8 ms)       │
                      │       status checked at EVERY waitUntilCompleted                            │
                      │       final dispatch carries finalize=1 → writes seeds buf                  │
                      │    4. audit: 4 RANDOM indices re-derived with ring::pbkdf2                  │
                      │    5. carve into 16 SeedBlocks of 512, send_timeout(100 ms) each            │
                      │    6. zeroize keys/states/seeds, next wave                                  │
                      └───────────────────────────────┬────────────────────────────────────────────┘
                                                      │ crossbeam bounded(32) of Box<SeedBlock>
                                                      │ payload = 512 × { entropy:[u8;16], seed:[u8;64] }
                      ┌───────────────────────────────▼────────────────────────────────────────────┐
                      │ Rayon pool (unchanged size, user's Threads setting)                        │
                      │                                                                            │
                      │  search_hybrid::<Evm>:                                                     │
                      │    if let Ok(b) = rx.try_recv() {          // non-blocking, self-balancing  │
                      │        for chunk in b.chunks(64) {          // stop checked per 64 (~3.2 ms)│
                      │            Evm::from_gpu_seed(seed) → matches_raw → verify → tx.send        │
                      │            counter += 64                                                    │
                      │        }                                                                    │
                      │        continue;                                                            │
                      │    }                                                                        │
                      │    search_cpu_step::<Evm>()                // BYTE-IDENTICAL to today       │
                      └───────────────────────────────┬────────────────────────────────────────────┘
                                                      │ mpsc::Sender<Match>  (unchanged)
                      ┌───────────────────────────────▼────────────────────────────────────────────┐
                      │ UI thread, 100 ms tick: drain_matches → append_match_row(&Match)            │
                      │ Match cannot be constructed without a verify::Verified token.               │
                      └────────────────────────────────────────────────────────────────────────────┘
```

**Load-bearing invariants**

1. **One command buffer topology, one wave in flight.** No second `WaveSlot`, no `slot:` parameter, no double-buffering. Both reviewers showed the second slot was unreachable (`run_wave(&mut self, ..) -> &[..]` is a blocking exclusive borrow) and that advertising "double-buffered" invites an aliasing bug on `states`. 3.5 MiB of buffers, not 7.0.
2. **Pipelining lives strictly *inside* one wave** — `PIPELINE_DEPTH = 3` command buffers in flight, all writing the same `states` buffer, serialized by commit order. It is *not* wave-level overlap.
3. **The host reads `seeds` only after every command buffer of the wave reports `Completed`.**
4. **Phrase ↔ seed pairing is established by exactly one `zip` and never re-ordered, filtered, or sorted afterwards.** `SeedBlock` exposes no mutating API.

---

## Components

### `src/gpu/mod.rs` — NEW, portable surface (no Objective-C types)

```rust
//! GPU offload of BIP-39 PBKDF2-HMAC-SHA512 (c = 2048, salt "mnemonic", dkLen = 64).
//! Apple Silicon + Metal only; every other target builds `stub.rs`.
//! The GPU is a *seed accelerator*: never a source of entropy, never a source of
//! truth. Every GPU-sourced match is re-derived with `ring` before it can exist.

pub const WAVE: usize = 8_192;                      // candidates per GPU wave
pub const BLOCK: usize = 512;                       // candidates per channel message (16/wave)
pub const CHANNEL_CAPACITY: usize = 32;             // 2 waves of blocks
pub const ITERS_PER_DISPATCH: u32 = 8;              // 2047 = 255*8 + 7 → 256 dispatches
pub const DISPATCHES_PER_COMMAND_BUFFER: usize = 4; // → 8.8 ms per command buffer
pub const PIPELINE_DEPTH: usize = 3;                // command buffers in flight, within a wave
pub const MAX_THREADS_PER_THREADGROUP: usize = 256; // 384 measured 13% SLOWER on M1
pub const COMPRESSIONS_PER_SEED: u32 = 4_098;       // 2 + 2 + 2*2047
pub const AUDITS_PER_WAVE: usize = 4;               // RANDOM indices, not a fixed stride

/// One GPU-produced candidate. POD + Copy: no allocation on the hot path.
/// `entropy`, not the phrase — the worker rebuilds the phrase itself with
/// `Mnemonic::from_entropy`, so the String written to the CSV is always
/// produced by trusted CPU code.
#[derive(Clone, Copy, Zeroize)]
#[repr(C)]
pub struct GpuCandidate {
    pub entropy: [u8; 16],
    /// UNTRUSTED until re-derived. Used only to *filter*.
    pub seed: [u8; 64],
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SeedBlock(Vec<GpuCandidate>);
impl SeedBlock {
    pub fn len(&self) -> usize;
    pub fn chunks(&self, n: usize) -> std::slice::Chunks<'_, GpuCandidate>;
    // deliberately NO mutating API — see invariant 4
}

pub type GpuRx = crossbeam_channel::Receiver<Box<SeedBlock>>;

#[derive(Clone, Debug, PartialEq)]
pub enum GpuStatus {
    Unavailable(String),          // not aarch64-macos, no device, or --no-default-features
    /// `probe()` succeeded: a device exists, but no GPU thread has been started
    /// yet. This is the pre-search resting state and the one `gpu_effective()`
    /// checks before `start_search` spawns the producer.
    Ready { device: String },
    Initializing,                 // thread spawned; compiling + self-testing
    Running { device: String },
    Disabled(GpuDisableReason),   // sticky for the process
}

#[derive(Clone, Debug, PartialEq)]
pub enum GpuDisableReason {
    NotSupported, NoDevice, UserOff,
    ShaderCompile(String), PipelineCreate(String), BufferAlloc, BadConfig(String),
    SelfTest(SelfTestError),
    /// Command buffer status != Completed, or error() was set.
    CommandBuffer { status: i64, message: String },
    /// The in-wave random ring audit disagreed.
    AuditMismatch { index: usize },
    /// A GPU-sourced candidate that MATCHED failed the verify gate.
    VerifyMismatch { address: String },
    Panicked,
}

/// Shared, lock-free-on-the-read-path health cell. Never a `Mutex` on the UI path.
pub struct GpuHealth {
    pub disable: AtomicBool,
    reason: OnceLock<GpuDisableReason>,   // set-once, no poisoning
    pub seeds_delivered: AtomicU64,
    pub blocks_dropped: AtomicU64,
    pub verify_rejections: AtomicU64,
}
impl GpuHealth {
    pub fn raise(&self, r: GpuDisableReason);   // set-once + store(true)
    pub fn take_reason(&self) -> Option<GpuDisableReason>;  // clone, never unwraps a lock
}

#[cfg_attr(all(target_os="macos", target_arch="aarch64", feature="metal"), path = "metal.rs")]
#[cfg_attr(not(all(target_os="macos", target_arch="aarch64", feature="metal")), path = "stub.rs")]
mod backend;
pub use backend::{GpuEngine, probe};

const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<GpuEngine>();     // App owns one; must stay Obj-C-free
    assert_send_sync::<SeedBlock>();
};
```

**Resolved contradiction — channel type.** `crossbeam-channel` (integration dimension) beats `Arc<Mutex<mpsc::Receiver>>` (ffi + correctness dimensions). `std::sync::mpsc::Receiver` is `!Sync` so it cannot be shared across Rayon workers; and a reviewer showed the `try_lock().ok()?` spelling makes a **poisoned mutex indistinguishable from "nothing ready"** — one panicking worker silently disables the GPU forever while the producer keeps filling the queue. Crossbeam's `Receiver` is `Clone + Send + Sync`, has a real `Disconnected`, and adds exactly one crate (`crossbeam-utils` is already in `Cargo.lock` via rayon). It is declared **unconditionally**, not target-gated, so `search_hybrid`'s signature is platform-independent.

### `src/gpu/pack.rs` — NEW, all byte-level work in Rust, testable with no GPU

```rust
/// One zero-padded HMAC key block, decoded to 16 big-endian u64 words.
/// The kernel therefore contains zero endianness code.
#[repr(C, align(16))]
#[derive(Clone, Copy, Zeroize)]
pub struct KeyBlock(pub [u64; 16]);

/// Hard assert, NOT debug_assert: a longer key would be silently zero-padded by
/// the GPU instead of SHA-512 pre-hashed (the CPU reference pre-hashes at
/// src/pbkdf2_lanes.rs:236), producing a wrong-but-plausible seed.
/// A 12-word English phrase is provably 47..=107 bytes.
pub fn pack_key_block(password: &[u8]) -> KeyBlock {
    assert!(!password.is_empty() && password.len() <= crate::pbkdf2_lanes::HMAC_BLOCK_LEN,
            "GPU PBKDF2 key must be 1..={} bytes (no pre-hash path), got {}",
            crate::pbkdf2_lanes::HMAC_BLOCK_LEN, password.len());
    let mut b = [0u8; 128];
    b[..password.len()].copy_from_slice(password);
    KeyBlock(std::array::from_fn(|i| u64::from_be_bytes(b[8*i..8*i+8].try_into().unwrap())))
}

/// Byte-exact mirror of `padded_block(&salted[..salt.len()+4], 128)`
/// at src/pbkdf2_lanes.rs:250-254. Fallible, mirroring the CPU's MAX_SALT_LEN
/// assert at src/pbkdf2_lanes.rs:21-25.
pub fn pack_salt_block(salt: &[u8]) -> Result<[u64; 16], GpuError> {
    if salt.len() > crate::pbkdf2_lanes::MAX_SALT_LEN {
        return Err(GpuError::SaltTooLong { len: salt.len() });
    }
    let mut b = [0u8; 128];
    b[..salt.len()].copy_from_slice(salt);
    b[salt.len()..salt.len()+4].copy_from_slice(&1u32.to_be_bytes());   // INT(1)
    b[salt.len()+4] = 0x80;
    let bits = ((128 + salt.len() + 4) as u128) * 8;
    b[112..].copy_from_slice(&bits.to_be_bytes());
    Ok(std::array::from_fn(|i| u64::from_be_bytes(b[8*i..8*i+8].try_into().unwrap())))
}
```

### `src/gpu/pbkdf2_bip39.metal` — NEW, `include_str!`-ed (8,661 bytes)

Copy `scratchpad/gpu2/pbkdf2_bip39.metal` **verbatim**, minus the measurement-only `pbkdf2_iterate_noacc` A/B kernel.

```c
struct Pbkdf2State {
    ulong inner[8];   // SHA-512 state after absorbing K0 ^ ipad
    ulong outer[8];   // SHA-512 state after absorbing K0 ^ opad
    ulong u[8];       // U_j
    ulong t[8];       // T = U_1 ^ .. ^ U_j     ← the accumulator both prototypes LACK
};                    // 32 ulongs = 256 B

struct Params { uint count; uint iters; uint finalize; uint _pad; };

kernel void pbkdf2_prologue(device const ulong *keyblocks [[buffer(0)]],
                            device Pbkdf2State *states    [[buffer(1)]],
                            constant ulong     *saltblock [[buffer(2)]],
                            constant Params    &p         [[buffer(3)]],
                            uint tid [[thread_position_in_grid]]);

kernel void pbkdf2_iterate(device Pbkdf2State *states [[buffer(0)]],
                           device uchar       *seeds  [[buffer(1)]],
                           constant Params    &p      [[buffer(2)]],
                           uint tid [[thread_position_in_grid]]);
```

The iterate body — the 15 load-bearing lines, resumable, `p.iters` the only thing that varies:

```c
if (tid >= p.count) return;                       // unconditional bounds guard
device Pbkdf2State *s = states + tid;
ulong ist[8], ost[8], u[8], t[8], st[8];
for (uint i=0;i<8;i++){ ist[i]=s->inner[i]; ost[i]=s->outer[i]; u[i]=s->u[i]; t[i]=s->t[i]; }
for (uint r=0; r<p.iters; r++) {
    for (uint i=0;i<8;i++) st[i]=ist[i];
    sha512_hash64(st, u);          // inner: H(K^ipad ‖ U_{j-1})
    for (uint i=0;i<8;i++) u[i]=ost[i];
    sha512_hash64(u, st);          // outer: U_j = H(K^opad ‖ inner)
    for (uint i=0;i<8;i++) t[i]^=u[i];
}
for (uint i=0;i<8;i++){ s->u[i]=u[i]; s->t[i]=t[i]; }
if (p.finalize) {
    device uchar *o = seeds + 64 * (ulong)tid;     // widen BEFORE multiply
    for (uint i=0;i<8;i++){ ulong v=t[i]; for (uint b=0;b<8;b++) o[8*i+b] = (uchar)(v >> (56-8*b)); }
}
```

`pbkdf2_prologue` writes `s->u[i] = U1[i]` **and** `s->t[i] = U1[i]`, so both the U register and the T accumulator are fully reinitialised every wave and `states` needs no clearing between waves (confirmed by review at `pbkdf2_bip39.metal:130`).

Two SHA-512 routines, split by kernel: the general 16-word-schedule `sha512_compress` lives **only** in `pbkdf2_prologue`; the constant-tail `sha512_hash64` (message is always a 64-byte digest → `w[8]=0x80..`, `w[9..15]=0`, `w[15]=(128+64)*8`) is the only one in `pbkdf2_iterate`. `w[15]` is the exact GPU mirror of `padded_block(&[0u8;64], 128)` at `src/pbkdf2_lanes.rs:260`; the finalize serialization mirrors `digest_bytes` at `src/pbkdf2_lanes.rs:212-218`. Both kernels report `maxTotalThreadsPerThreadgroup = 384`, `threadExecutionWidth = 32` on M1.

**Banned in this file**, pinned by a source-grep test that needs no GPU: `threadgroup`, `simd_`, `barrier`, `atomic`. Every thread is an independent PBKDF2 with zero cross-thread communication, which eliminates the uninitialised-shared-memory / missing-barrier bug class by construction.

**Hard prohibition**, also grep-pinned: `thread_position_in_grid` may appear ONLY in slot-offset index expressions. `scratchpad/gpu/k2.metal:183` (`ipad[i]=H0[i]^(ulong)tid`) is bench scaffolding; GPU-derived key material would make every wallet the tool ever emits recoverable from one 64-bit value while still passing every address test.

**Prototype status, stated once so nobody mistakes it:** the *validated* part of the prototypes is the SHA-512 compression arithmetic (checked against `SHA-512("abc")`). Neither `pbkdf2_inner` (`kernels.metal:66-88`) nor `pbkdf2_opt` (`k2.metal:181-192`) accumulates T, both fabricate ipad/opad from `H0 ^ tid`, and **neither ever reads an input buffer** — `out[tid] = …` is the only buffer access in the whole prototype. The input path, per-thread indexing, and endianness are unvalidated there. The gpu2 kernel is the one that is validated end-to-end.

### `src/gpu/metal.rs` — NEW, the only file naming an Objective-C type

Binding: **`objc2` 0.6 + `objc2-metal` 0.3 + `objc2-foundation` 0.3**, target-gated. `metal-rs` 0.33 is self-deprecated in its own README and blanket-declares every wrapped object `Sync + Send` including `CommandBuffer`/`ComputeCommandEncoder`, which Apple documents as not thread-safe. objc2-metal encodes the real guarantees as supertraits — `MTLDevice`/`MTLCommandQueue`/`MTLLibrary`/`MTLComputePipelineState` are `Send + Sync`; **`MTLBuffer`, `MTLCommandBuffer`, `MTLCommandEncoder` are not** — so "all Metal state lives and dies on one thread" is type-checked, not documented. It also gives `objc2::rc::autoreleasepool` and typed `Retained<T>`, which is the mechanism the leak fix below requires.

```rust
#[link(name = "CoreGraphics", kind = "framework")] extern "C" {}   // for MTLCreateSystemDefaultDevice

const KERNEL_SRC: &str = include_str!("pbkdf2_bip39.metal");

pub struct GpuEngine {
    stop: Arc<AtomicBool>,          // PRODUCER-ONLY flag; never App::stop
    finished: Arc<AtomicBool>,
    health: Arc<GpuHealth>,
    status: Arc<Mutex<GpuStatus>>,  // read via a poison-immune helper, never .unwrap()
    join: Option<JoinHandle<()>>,
}

impl GpuEngine {
    /// ~1 ms device probe. Called ONCE from main(), BEFORE enable_raw_mode().
    pub fn probe() -> GpuStatus;

    /// Returns IMMEDIATELY with status = Initializing. Device creation, library
    /// compile (~60-95 ms cold), pipeline build, and the self-test all run on the
    /// spawned thread. Nothing Metal-shaped ever crosses a thread boundary.
    pub fn start(tx: Sender<Box<SeedBlock>>, health: Arc<GpuHealth>) -> GpuEngine;

    pub fn status(&self) -> GpuStatus;
    /// Sets the producer-only stop flag. NON-BLOCKING. Never joins.
    pub fn signal_stop(&self);
    pub fn is_finished(&self) -> bool;
    /// Only called once is_finished() is true, or from the reaper at process exit.
    pub fn reap(self);
}

struct WaveBuffers {          // ONE set. No slot ring.
    keys:   Retained<ProtocolObject<dyn MTLBuffer>>,   // WAVE*128 =  1.00 MiB, StorageModeShared
    states: Retained<ProtocolObject<dyn MTLBuffer>>,   // WAVE*256 =  2.00 MiB
    seeds:  Retained<ProtocolObject<dyn MTLBuffer>>,   // WAVE* 64 =  0.50 MiB
}                                                      //            3.50 MiB total
impl Drop for WaveBuffers {   // zeroizes all three; no command buffer is in flight here
    fn drop(&mut self) { /* write_bytes(contents(), 0, len) for each */ }
}
```

**Compile options.** Set only `setLanguageVersion(MTLLanguageVersion::Version3_0)`. **Do not call `setMathMode` / `setFastMathEnabled`.** Two reviewers converged here: `setMathMode:` is macOS 15.0+ and objc2-metal emits it with no availability guard, so on an M1 running Ventura/Sonoma it raises `NSInvalidArgumentException` — an Objective-C exception, which `catch_unwind` cannot catch — aborting the process inside raw mode with the alternate screen still active. It is also worthless: SHA-512 is integer-only and MSL fast-math relaxes IEEE-754 float semantics only. (For the record, the kernel design's claim that `fastMathEnabled` defaults to `NO` is **inverted** — a fresh `MTLCompileOptions` reports `YES` — but that default cannot change an integer instruction, so simply not touching it is correct.)

**Threadgroup size.**

```rust
let tew  = pipe.threadExecutionWidth().max(1);
let maxt = pipe.maxTotalThreadsPerThreadgroup();
let tg   = (((maxt.min(MAX_THREADS_PER_THREADGROUP)) / tew).max(1) * tew).min(maxt).max(1);
if tg == 0 { return Err(PipelineCreate("threadgroup size 0")) }
```
The final `.min(maxt)` closes the case where `maxt < tew` (would otherwise dispatch a threadgroup larger than the pipeline permits → another uncatchable ObjC exception). `VANADDY_GPU_TG` overrides for tuning on non-M1 hardware; the 256 clamp is a measured M1 result, not a universal truth (384 measured **13% slower** here).

**`run_wave` — the chunking loop, with every reviewer fix applied:**

```rust
fn run_wave(
    &mut self,
    keys: &[KeyBlock],                 // len may be < WAVE
    salt_block: &[u64; 16],
    total_iters: u32,                  // 2048 for BIP-39
    stop: &AtomicBool,
) -> Result<Option<&[[u8; 64]]>, GpuError>   // Ok(None) == abandoned on stop
{
    assert!(total_iters >= 1);                     // mirrors src/pbkdf2_lanes.rs:26
    let count = keys.len() as u32;

    // Poison the seeds region so a missing finalize yields obvious garbage
    // rather than the PREVIOUS wave's still-valid 64-byte seed.
    unsafe { write_bytes(self.bufs.seeds.contents().as_ptr() as *mut u8, 0xA5, WAVE * 64) };
    copy_keys_into(&self.bufs.keys, keys);

    // 1 prologue command buffer.
    autoreleasepool(|_| {
        let cb = encode_prologue(count, salt_block)?;
        cb.commit(); cb.waitUntilCompleted();
        check_status(&cb)                          // ← checked, not assumed
    })?;

    // do-while: ALWAYS at least one iterate dispatch, so total_iters == 1
    // still carries finalize=1. (Verified: c=1 via [iters=0, finalize=1]
    // matches CommonCrypto byte-for-byte — the loop no-ops and t = U_1.)
    let mut remaining = total_iters - 1;           // 2047
    let mut ring: [Option<Retained<..CommandBuffer>>; PIPELINE_DEPTH] = Default::default();
    let mut slot_ix = 0usize;
    loop {
        if stop.load(Relaxed) { drain_ring(&mut ring)?; return Ok(None); }

        // ONE AUTORELEASE POOL PER COMMAND BUFFER. Non-negotiable — see below.
        autoreleasepool(|_| -> Result<(), GpuError> {
            if let Some(prev) = ring[slot_ix].take() {
                prev.waitUntilCompleted();
                check_status(&prev)?;              // ← at EVERY wait, not just the last
            }
            let cb = self.queue.commandBuffer().ok_or(BufferAlloc)?;
            let enc = cb.computeCommandEncoder().ok_or(BufferAlloc)?;   // serial ⇒ auto-barrier
            enc.setComputePipelineState(&self.iterate);
            unsafe {
                enc.setBuffer_offset_atIndex(Some(&self.bufs.states), 0, 0);
                enc.setBuffer_offset_atIndex(Some(&self.bufs.seeds),  0, 1);
            }
            for _ in 0..DISPATCHES_PER_COMMAND_BUFFER {
                let iters = remaining.min(ITERS_PER_DISPATCH);
                remaining -= iters;
                let p = Params { count, iters, finalize: (remaining == 0) as u32, _pad: 0 };
                unsafe { enc.setBytes_length_atIndex(NonNull::from(&p).cast(), size_of::<Params>(), 2) };
                enc.dispatchThreads_threadsPerThreadgroup(
                    MTLSize{width: count as usize, height:1, depth:1},
                    MTLSize{width: self.tg,        height:1, depth:1});
                if remaining == 0 { break; }
            }
            enc.endEncoding();
            cb.commit();
            ring[slot_ix] = Some(cb.retain());      // retain INSIDE the pool
            Ok(())
        })?;
        slot_ix = (slot_ix + 1) % PIPELINE_DEPTH;
        if remaining == 0 { break; }
    }
    for cb in ring.iter().flatten() { cb.waitUntilCompleted(); check_status(cb)?; }

    // Returns EXACTLY keys.len() entries. Slots >= count still hold 0xA5 poison.
    Ok(Some(&seeds_slice[..keys.len()]))
}
```

`check_status` returns `Err(CommandBuffer{..})` unless `status == Completed` **and** `error()` is nil. **The whole wave is discarded on any failure — there is no partial-success shape.** Without this, a mid-wave GPU reset (macOS resets a hung GPU after ~5 s and `waitUntilCompleted` returns rather than hanging) silently drops 8 of 2048 U-iterations and finalize writes a T that is the XOR of only 2,039 values — a wrong-but-plausible seed with nothing surfaced anywhere.

**The autorelease pool is mandatory, not stylistic.** Two reviewers measured it independently on this machine. Without a pool: `+1,861 B per command buffer` (`leakwave.m`, 60 waves at the exact production geometry) = 199 KB/s = **700 MB/hour = 16.4 GB/day**. With a per-command-buffer pool: RSS flat or negative. Throughput is identical (13,829 vs 13,804 seeds/s) — **the fix is free**. A bare `std::thread::spawn` body has no ambient pool, and a single outer pool never drains and leaks identically. The prototype it was transcribed from *has* one (`scratchpad/gpu2/verify7.m:19`); the detail was lost in translation to Rust. A multi-day vanity search is the stated use case; without this the process is jetsammed overnight.

### `src/gpu/stub.rs` — NEW

Same public surface, all no-ops, zero dependencies, compiled on every target that is not `aarch64-apple-darwin` with `feature = "metal"`. `GpuEngine { _never: Infallible }`, `probe() -> GpuStatus::Unavailable("not supported on this target")`.

### `src/gpu/selftest.rs` — NEW, injectable so the checker itself is testable without a GPU

```rust
#[derive(Debug, Clone, PartialEq)]
pub enum SelfTestError {
    WrongLength { got: usize, want: usize },
    CanonicalVectorMismatch { got: String },
    RingMismatch { index: usize, phrase: String, got: String, want: String },
    AllZero { index: usize },
    Poisoned { index: usize },          // 0xA5 survived → kernel never wrote this slot
    ScheduleDivergence { schedule: &'static str, index: usize },
    Backend(String),
}

/// `derive` is injected so the fault-detection logic can be unit-tested on any
/// machine by passing a deliberately faulty closure.
pub fn self_test<F>(derive: F) -> Result<(), SelfTestError>
where F: FnMut(&[&str], u32) -> Result<Vec<Zeroizing<[u8; 64]>>, GpuError>;
```

**Self-test content — the count=1 version is rejected.** A reviewer showed a `count = 1` self-test structurally cannot exercise `keyblocks + 16*tid`, `states + tid`, `seeds + 64*tid`, or the host-side 128-byte `KeyBlock` stride — every candidate except tid 0 could derive from the wrong key block and the test would pass cleanly. The self-test therefore runs:

1. **count = 512** (2 threadgroups at tg=256), all **distinct** phrases, cross-checked against `crate::seed::derive_seed` (`ring`).
2. The **BIP-39 canonical vector** at index 0 **and** index 511, against the same hex constant already pinned at `src/seed.rs:41`.
3. A **count = 511** dispatch (deliberately not a multiple of 256 or 32) exercising the non-uniform tail; slots 511..512 must still hold 0xA5 poison.
4. **Chunk-schedule invariance**: index 0's seed must be bit-identical under three schedules — one-shot (`iters = 2047`), the production schedule (`R = 8`), and an irregular one (`[1, 1000, 46, 1000]`).
5. Entropy distinctness: `HashSet<[u8;16]>` over the fresh phrases, `len() == 510`. (Note: `src/chains/evm.rs:168-170`'s `Vec::dedup` on an unsorted vec of *addresses* is **not** a pairwise-distinctness assertion and must not be copied as precedent.)
6. No output all-zero, no output still poisoned.

Measured cost: ~154 ms of GPU + ~512 × 260 µs = 133 ms of `ring`, i.e. **~300 ms one-time on the GPU thread**, off the UI thread. `stop` is checked between each phase.

### `src/gpu/producer.rs` — NEW, the wave loop

```rust
fn producer(tx: Sender<Box<SeedBlock>>, stop: &AtomicBool, health: &GpuHealth,
            status: &Arc<Mutex<GpuStatus>>) -> Result<(), GpuDisableReason>
{
    // QoS so macOS does not demote this to an E-core, where the ~5 ms of
    // per-wave phrase generation and packing stretches proportionally.
    unsafe { pthread_set_qos_class_self_np(QOS_CLASS_USER_INITIATED, 0) };

    let mut engine = MetalPbkdf2::new()?;        if stop.load(Relaxed) { return Ok(()); }
    selftest::self_test(|p, it| engine.derive(p, it))?;
                                                 if stop.load(Relaxed) { return Ok(()); }
    set_status(status, GpuStatus::Running { device: engine.device_name() });

    let salt = pack::pack_salt_block(crate::seed::BIP39_SALT)?;
    // 8192 × 16 B of raw entropy — the most valuable object in the process.
    let mut entropy: Zeroizing<Vec<[u8; 16]>> = Zeroizing::new(vec![[0u8;16]; WAVE]);
    let mut keys:    Zeroizing<Vec<KeyBlock>>  = Zeroizing::new(vec![KeyBlock([0;16]); WAVE]);
    let mut rng = rand::thread_rng();

    while !stop.load(Relaxed) && !health.disable.load(Relaxed) {
        // 1. Fill. Measured: Mnemonic::new = 0.527 µs, +pack = 0.495 µs total
        //    → 8192 candidates = ~4.1 ms per 600 ms wave = 0.7%. ONE thread is
        //    ample (14,500/s needs 0.7% of a core); NO Rayon par_iter — that
        //    would put allocations on the threads whose PBKDF2 is the CPU-side
        //    throughput. (Closes the design's open question.)
        for i in 0..WAVE {
            if i % 512 == 0 && stop.load(Relaxed) { return Ok(()); }
            let m = Mnemonic::new(MnemonicType::Words12, Language::English);
            entropy[i].copy_from_slice(m.entropy());
            keys[i] = pack::pack_key_block(m.phrase().as_bytes());
        }

        // 2-3. Dispatch. None == abandoned on stop.
        let Some(seeds) = engine.run_wave(&keys, &salt, crate::seed::PBKDF2_ROUNDS, stop)? else {
            return Ok(());
        };

        // 4. Audit AUDITS_PER_WAVE *random* indices against ring. A fixed stride
        //    equal to the block size would sample the same tid forever and be
        //    blind to every tid-dependent kernel bug.
        for _ in 0..AUDITS_PER_WAVE {
            let i = rng.gen_range(0..WAVE);
            let m = Mnemonic::from_entropy(&entropy[i], Language::English)
                        .map_err(|_| AuditMismatch { index: i })?;
            if crate::seed::derive_seed(&m) != seeds[i] {
                return Err(AuditMismatch { index: i });
            }
        }

        // 5. Carve + send. The ONLY place entropy and seeds meet. Never sorted,
        //    filtered, or reordered afterwards.
        for c in 0..(WAVE / BLOCK) {
            let mut block = Box::new(SeedBlock::with_capacity(BLOCK));
            for i in c*BLOCK..(c+1)*BLOCK {
                block.push(GpuCandidate { entropy: entropy[i], seed: seeds[i] });
            }
            let mut pending = Some(block);
            while let Some(b) = pending.take() {
                if stop.load(Relaxed) || health.disable.load(Relaxed) { drop(b); return Ok(()); }
                match tx.send_timeout(b, Duration::from_millis(100)) {
                    Ok(()) => {}
                    Err(SendTimeoutError::Timeout(b))      => pending = Some(b),   // backpressure
                    Err(SendTimeoutError::Disconnected(b)) => { drop(b); return Ok(()); }
                }
            }
        }
        // 6. engine zeroizes keys/states/seeds; entropy/keys Vecs wiped at next fill.
    }
    Ok(())
}
```

**Entropy source, hard requirement.** `bip39::Mnemonic::new(MnemonicType::Words12, Language::English)` — the identical call the CPU path already makes at `src/chains/evm.rs:59` and `:67`. (Correcting a claim made in two designs: this is **`rand::thread_rng()`** — a thread-local ChaCha12 CSPRNG seeded from the OS via getrandom and auto-reseeded, `tiny-bip39-0.8.2/src/crypto.rs:9,25` — not `OsRng` directly. Thread-local is the property that matters: the producer gets its own independently OS-seeded instance.) Anything counter-derived would break the uniform-independent-draw assumption behind `App::expected_attempts()` *and* be a total key-recovery break.

### `src/chains/mod.rs` — CHANGED

```rust
/// A chain whose entire candidate is a pure function of a 64-byte BIP-39 seed.
/// Implementing this — and nothing else — opts a chain into the GPU pipeline.
/// Evm implements it. Solana and Bitcoin each already have a private `from_seed`
/// of exactly this shape and are one line away; Ton (own mnemonic, 100k rounds,
/// different salt) and Monero (no BIP-39) structurally cannot — that is the
/// reuse seam, and it is the entirety of the non-EVM design in this milestone.
pub trait Bip39GpuChain: Chain {
    fn from_gpu_seed(seed: &[u8; 64]) -> (Self::AddressBytes, Self::SecretRaw);
    /// Re-derive from the phrase alone with the reference (`ring`) path.
    /// MUST NOT use the batched or GPU path. Returns `bool`, never `Option`.
    fn verify(address: &str, secret_hex: &str, phrase: &str) -> bool;
}

/// The unchanged CPU batch, factored out so `search` and `search_hybrid` share
/// ONE body and cannot drift. Byte-identical to today's loop interior.
#[inline(always)]
fn search_cpu_step<C: Chain>(matcher: &Matcher, counter: &AtomicU64, tx: &Sender<Match>) {
    C::generate_batch(|addr_bytes, secret_raw, phrase| {
        if C::matches_raw(matcher, &addr_bytes) {
            let _ = tx.send(Match {
                chain: C::LABEL.to_string(),
                address: C::encode_address(&addr_bytes),
                secret_hex: C::encode_secret(&secret_raw),
                mnemonic: phrase,
                verified: crate::verify::Verified::cpu_reference(),
            });
        }
    });
    counter.fetch_add(C::BATCH as u64, Ordering::Relaxed);
}

/// Unchanged signature. Solana/Bitcoin/Ton/Monero still call THIS.
pub fn search<C: Chain>(matcher: &Matcher, stop: &AtomicBool,
                        counter: &AtomicU64, tx: &Sender<Match>) {
    while !stop.load(Ordering::Relaxed) { search_cpu_step::<C>(matcher, counter, tx); }
}

/// Stop check granularity inside a GPU block: 16 × C::BATCH = 64 candidates
/// ≈ 3.2 ms at the measured 50.5 µs tail — comparable to the CPU path's
/// ~1.3 ms, versus 25.9 ms for a whole 512-block.
const GPU_CHUNK_BATCHES: usize = 16;

pub fn search_hybrid<C: Bip39GpuChain>(
    matcher: &Matcher, stop: &AtomicBool, counter: &AtomicU64,
    tx: &Sender<Match>, gpu: Option<&crate::gpu::GpuRx>, health: &crate::gpu::GpuHealth,
) {
    while !stop.load(Ordering::Relaxed) {
        if let Some(rx) = gpu {
            if !health.disable.load(Ordering::Relaxed) {
                if let Ok(block) = rx.try_recv() {          // non-blocking, self-balancing
                    drain_gpu_block::<C>(&block, matcher, stop, counter, tx, health);
                    continue;                                // block zeroized on drop
                }
            }
        }
        search_cpu_step::<C>(matcher, counter, tx);
    }
}

fn drain_gpu_block<C: Bip39GpuChain>(
    block: &crate::gpu::SeedBlock, matcher: &Matcher, stop: &AtomicBool,
    counter: &AtomicU64, tx: &Sender<Match>, health: &crate::gpu::GpuHealth,
) {
    debug_assert_eq!(block.len() % C::BATCH.max(1), 0);
    for chunk in block.chunks(C::BATCH.max(1) * GPU_CHUNK_BATCHES) {
        if stop.load(Ordering::Relaxed) { return; }   // only what was checked has been counted
        for cand in chunk {
            let (addr, _gpu_secret) = C::from_gpu_seed(&cand.seed);
            if C::matches_raw(matcher, &addr) {
                emit_gpu_match::<C>(tx, &cand.entropy, &addr, health);
            }
        }
        counter.fetch_add(chunk.len() as u64, Ordering::Relaxed);
        health.seeds_delivered.fetch_add(chunk.len() as u64, Ordering::Relaxed);
    }
}
```

`ChainKind::search` gains `gpu: Option<&GpuRx>` and `health: &GpuHealth`; only the `Evm` arm routes to `search_hybrid`, the other four call the unchanged `search::<C>` and ignore both parameters. **Resolved contradiction:** three designs proposed `const GPU_SEEDS: bool` + a defaulted `from_gpu_seed` whose body is `unreachable!()`. A reviewer correctly flagged that a future maintainer can set the const `true` without implementing the tail, compiling cleanly and then panicking inside a Rayon worker in raw terminal mode. A separate trait makes that state unrepresentable, costs no `dyn` (both `search` and `search_hybrid` are monomorphized once at thread spawn), and — because both call the same `#[inline(always)] search_cpu_step` — preserves the "one CPU body, cannot drift" property the const was chosen for. The existing pinned test at `src/chains/mod.rs:130-146` spawns `search::<Solana>` and is completely untouched, including its `n % LANES == 0` assertion at line 145.

### `src/verify.rs` — NEW, the proof token

```rust
/// Proof that a Match's phrase re-derives to its address and secret via the
/// reference (`ring`) path — either because the CPU path produced it directly
/// (the CPU path IS the reference, per CLAUDE.md) or because a GPU-sourced
/// candidate was re-derived and agreed. The private unit field means only this
/// module can mint one, and `app::append_match_row` takes a `&Match`, which
/// cannot exist without one.
#[derive(Clone, Copy)]
pub struct Verified(());

impl Verified {
    /// The CPU path derives with `derive_seeds`/`derive_seed` and encodes from
    /// what it derived; there is nothing to cross-check it against that is more
    /// trusted than itself.
    pub(crate) fn cpu_reference() -> Self { Verified(()) }
}

/// Re-derive a GPU-sourced candidate from its 16-byte entropy alone and confirm
/// it reproduces the address the GPU seed produced. `None` ⇒ reject.
/// NOTE the polarity: there is deliberately no `Option<bool>` and no
/// "unverifiable" arm. Every failure mode — unparseable entropy, bad checksum,
/// address disagreement — is a rejection.
pub fn verify_gpu<C: crate::chains::Bip39GpuChain>(
    entropy: &[u8; 16], gpu_addr: &C::AddressBytes,
) -> Option<(C::AddressBytes, C::SecretRaw, String, Verified)> {
    let m = bip39::Mnemonic::from_entropy(entropy, bip39::Language::English).ok()?;
    let seed = crate::seed::derive_seed(&m);              // ring::pbkdf2, src/seed.rs:8
    let (addr, secret) = C::from_gpu_seed(&seed);
    if addr.as_ref() != gpu_addr.as_ref() { return None; }
    Some((addr, secret, m.phrase().to_string(), Verified(())))
}
```

**Two resolutions folded in here.**

*Polarity.* The correctness design's `verify` mapped `Some(true) | None => Some(Verified(()))` — meaning the token proved "verified **or** the verifier declared itself unable to check". A reviewer showed that the idiomatic `.ok()?` inside any future edit to a chain verifier then converts a corrupted phrase into a *pass*, turning the gate into a decoration on exactly the input it exists to catch. `bool`/`Option<Verified>` with reject-on-anything is the only safe shape.

*Scope.* The correctness design applied the gate to **all five chains**, requiring a new Monero forward-verifier (new, untested crypto) and `Ton::verify` calling `ton_mnemonic::mnemonic_to_signing_key` — which is **`#[cfg(test)]` at `src/chains/ton_mnemonic.rs:122` and does not exist in a release build**, so the design as written does not compile, and un-gating it violates the design's own file freeze. A second reviewer independently showed the all-chains gate could *silently delete* a genuine 6-hour Monero match if the new verifier had a bug. **The gate applies to GPU-sourced candidates only.** There is exactly one such chain, `#[cfg(test)]` never becomes a problem, no new crypto is written, and CPU-path behaviour is byte-identical to today. This is the YAGNI-correct call and it removes three defects at once.

*Never destroy evidence.* On rejection:

```rust
fn emit_gpu_match<C: Bip39GpuChain>(tx: &Sender<Match>, entropy: &[u8;16],
                                    gpu_addr: &C::AddressBytes, health: &GpuHealth) {
    match crate::verify::verify_gpu::<C>(entropy, gpu_addr) {
        Some((addr, secret, phrase, proof)) => {
            let _ = tx.send(Match { chain: C::LABEL.to_string(),
                                    address: C::encode_address(&addr),
                                    secret_hex: C::encode_secret(&secret),
                                    mnemonic: phrase, verified: proof });
        }
        None => {
            // A GPU seed that MATCHED the pattern but does not re-derive is a
            // GPU fault, never a false positive. Disable the GPU, keep the CPU
            // search alive, and surface it. The candidate is dropped — it is
            // provably not a wallet anyone can open, so there is nothing to save.
            health.verify_rejections.fetch_add(1, Ordering::Relaxed);
            health.raise(GpuDisableReason::VerifyMismatch {
                address: C::encode_address(gpu_addr) });
        }
    }
}
```

### `src/app.rs` — CHANGED

```rust
pub struct App {
    // ...existing...
    pub gpu_status: GpuStatus,                 // from probe(), promoted by drain_matches
    pub gpu_requested: bool,                   // form toggle; default = probe() was Ready
    pub validated_gpu: bool,                   // mirrors validated_thread_count
    pub gpu_health: Arc<GpuHealth>,
    pub gpu_rx: Option<GpuRx>,                 // App's clone; dropping it is shutdown path #2
    gpu_engines: Vec<GpuEngine>,               // reaper; NEVER joined on the UI thread
}

/// GPU actually runs iff: user wants it, a device exists, chain is EVM, and
/// nothing has disabled it. Advisory — `validate()` NEVER returns Err for a
/// GPU reason, so a stale toggle can never block a search from starting.
pub fn gpu_effective(&self) -> bool {
    self.gpu_requested
        && matches!(self.gpu_status, GpuStatus::Ready | GpuStatus::Initializing
                                    | GpuStatus::Running { .. })
        && self.chain == ChainKind::Evm
}
```

`open_csv_secure` gains a `path: &Path` parameter (`const CSV_PATH: &str = "vanity_wallets.csv"` for production callers) so the 0600 tests can use a temp dir — `cargo test` runs tests as threads in one process, so `set_current_dir` is racy, and `start_stop_restart_does_not_leak_threads` already writes the real CSV into the repo root today. **Both halves of the guarantee are preserved verbatim**: `.mode(0o600)` on create (`src/app.rs:304`) and the post-open `set_permissions` re-assert (`src/app.rs:308-314`). `append_match_row(path, &Match)` becomes the single writer.

### `src/main.rs` — CHANGED

```rust
pub mod gpu;      // + pub mod verify;

fn main() -> io::Result<()> {
    // Probe BEFORE raw mode: a panic or Metal stderr noise here must not land
    // inside the alternate screen. Also removes the deferral rationale's
    // (incorrect) stderr argument — App::new() at line 29 is already past
    // EnterAlternateScreen at line 25.
    let gpu_status = std::panic::catch_unwind(gpu::probe)
        .unwrap_or(GpuStatus::Unavailable("Metal probe panicked".into()));

    // Restore the terminal on ANY panic. The GPU path adds panic sites
    // (pack_key_block's assert, every Metal Result) to a binary that has none.
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = disable_raw_mode();
        let _ = stdout().execute(LeaveAlternateScreen);
        prev(info);
    }));

    enable_raw_mode()?;
    // ...unchanged loop...
}
```

### `Cargo.toml`

```toml
[features]
default = ["metal"]
metal = ["dep:objc2", "dep:objc2-foundation", "dep:objc2-metal"]

[dependencies]
crossbeam-channel = "0.5"     # bounded MPMC; crossbeam-utils already present via rayon

[target.'cfg(all(target_os = "macos", target_arch = "aarch64"))'.dependencies]
objc2 = { version = "0.6", optional = true }
objc2-foundation = { version = "0.3", optional = true, default-features = false,
                     features = ["std", "NSString", "NSError"] }
objc2-metal = { version = "0.3", optional = true, default-features = false, features = [
  "std", "MTLDevice", "MTLCommandQueue", "MTLCommandBuffer", "MTLCommandEncoder",
  "MTLComputeCommandEncoder", "MTLComputePipeline", "MTLLibrary", "MTLBuffer",
  "MTLResource", "MTLAllocation", "MTLTypes", "objc2-core-foundation" ] }

[dev-dependencies]
tempfile = "3"
```

Resolves to objc2 0.6.4, objc2-encode 4.1.0, objc2-foundation 0.3.2, objc2-core-foundation 0.3.2, objc2-metal 0.3.2 on aarch64-apple-darwin; **zero** additional crates on linux and x86_64-apple-darwin (`bitflags` 2.x is already at `Cargo.lock:78` via ratatui/crossterm). The `aarch64` restriction (rather than all of macOS) deletes two whole failure classes that do not exist on Apple Silicon: automatic graphics switching between iGPU/dGPU, and eGPU device removal.

### Additive visibility edits to frozen files

Two constants are currently duplicated between the GPU and CPU paths with no compiler-enforced link, in the one place the tool's correctness rests. Permit exactly these additive edits — no logic moves, and each is still guarded by its existing pinned test:

```rust
// src/seed.rs (guarded by derive_seed_matches_bip39_vector)
pub const PBKDF2_ROUNDS: u32 = 2048;               // was private, line 5
pub const BIP39_SALT: &[u8; 8] = b"mnemonic";      // was an inline literal, line 10

// src/pbkdf2_lanes.rs (guarded by exactly_128_byte_password_matches_ring, :370)
pub const HMAC_BLOCK_LEN: usize = 128;             // was a bare literal at line 236
pub const MAX_SALT_LEN: usize = 107;               // was private, line 38
```

`Evm::from_seed` (`src/chains/evm.rs:36`) widens from private to `pub(crate)` — behaviour-neutral; it is already the shared tail of `generate` (`:61`) and `generate_batch` (`:70`), which is precisely what makes the pinned `bip44_canonical_vector` (`:142`) and `generate_batch_emits_lane_count_candidates_matching_single_path` (`:156`) transitively cover the GPU tail.

*(Naming note to prevent a future misread: `MAX_SALT_LEN = 107` is `128 − 4 (INT) − 1 (0x80) − 16 (length field)` and is entirely unrelated to the 107-byte maximum length of a 12-word English phrase. The coincidence is arithmetic.)*

---

## Data flow

```
thread_rng() ─► Mnemonic::new(Words12, English)        [GPU thread, CPU]
     │            └─ phrase (47..=107 bytes, empirically 58..92 over 20k samples)
     ├─► m.entropy() ──► entropy[i] : [u8;16]           Zeroizing<Vec<..>>, host only
     └─► pack_key_block(phrase.as_bytes())              assert len ∈ 1..=128
            └─ K0 zero-padded to 128 B, → 16 BE u64 words
                     │
                     ▼  memcpy into `keys` MTLBuffer (StorageModeShared, zero copy)
        pbkdf2_prologue: ipad/opad midstates + U_1 ; states[i].u = states[i].t = U_1
                     │
                     ▼  256 × pbkdf2_iterate (R = 8), resumable via Pbkdf2State
        U_j = HMAC(P, U_{j-1});  T ^= U_j          (registers within a dispatch,
                                                    merged to device at each boundary)
                     │
                     ▼  finalize=1 on the last dispatch
        seeds[i] = T serialized big-endian → 64 bytes    (host does NO byteswap)
                     │
                     ▼  4 random indices re-derived with ring  → AuditMismatch on disagree
        zip(entropy[i], seeds[i]) ──► GpuCandidate      ← THE ONLY PAIRING POINT
                     │
                     ▼  16 × SeedBlock(512)  →  crossbeam bounded(32)  →  try_recv
        Rayon worker: Evm::from_gpu_seed(&cand.seed) → (addr, sk)
                     │
                     ▼  Evm::matches_raw(matcher, &addr)    ~1 in 16^n
        verify_gpu::<Evm>(&cand.entropy, &addr):
            Mnemonic::from_entropy(entropy) → phrase
            seed::derive_seed(&m)              ← ring::pbkdf2, the reference
            Evm::from_gpu_seed(&seed) → addr'
            addr' == addr ?  ── no ──► GpuHealth::raise(VerifyMismatch), GPU off, CPU continues
                             └─ yes ─► Verified(())
                     │
                     ▼  Match { .., mnemonic: CPU-rebuilt phrase, verified }
        mpsc::Sender<Match> ──► drain_matches ──► append_match_row(CSV_PATH, &m)   [0600]
```

The `Match` written to the CSV carries the **CPU-derived** address, secret, and phrase — never the GPU-derived ones. A wrong GPU seed can therefore only cost a *missed* match, never an unspendable CSV row.

*(Entropy round-trip is exact and was verified: `Mnemonic::entropy()` at `tiny-bip39-0.8.2/src/mnemonic.rs:249` returns the stored 16 bytes without the checksum, and `from_entropy` → `from_entropy_unchecked` recomputes it deterministically, reproducing `phrase()` byte-for-byte.)*

---

## Concurrency & shutdown

**Thread ownership.** One dedicated OS thread, `vanaddy-gpu`, QoS `USER_INITIATED`. It owns the `MTLDevice`, queue, library, both pipelines, and all three buffers, and it creates them *inside its own closure* — nothing Metal-shaped ever crosses a thread boundary, so `objc2`'s `Send`/`Sync` bounds do the enforcing. This is type-checked, not documented: a probe confirms `Retained<ProtocolObject<dyn MTLBuffer>>` fails `assert_send`, and since every dispatch needs the buffers, confinement follows.

**What crosses threads:** `Box<SeedBlock>` (`String`-free POD — `Send` trivially), `Arc<GpuHealth>` (atomics + `OnceLock`), `Arc<AtomicBool>`, and `crossbeam::Receiver<Box<SeedBlock>>` (`Clone + Send + Sync`). `GpuEngine` itself is `Send + Sync` and holds no Objective-C type — a `const _: fn()` assertion in `gpu/mod.rs` pins this so a refactor cannot smuggle one into `App`.

**Two independent stop flags.** The producer gets its **own** `Arc<AtomicBool>`, created inside `GpuEngine::start`, never `App::stop`. This is a correctness fix, not tidiness: if `stop_gpu()` set `App::stop`, then a GPU self-disable (audit mismatch, three command-buffer errors) would set the flag every Rayon worker reads at `src/chains/mod.rs:107` and **silently end the entire search** — the exact inverse of "the app keeps searching on CPU". The producer loop exits when `producer_stop || App::stop || health.disable`.

**Never join on the UI thread.** `stop_search` (currently non-blocking at `src/app.rs:264-270`) stays non-blocking: it sets `App::stop`, calls `engine.signal_stop()`, drops `App`'s `gpu_rx` clone, moves the engine into `gpu_engines`, and returns. `start_search` reaps `gpu_engines` **non-blockingly** via `is_finished()`; if any engine has not finished, it **skips the GPU for this run** and shows `GPU: previous session winding down` rather than blocking. Two reviewers independently showed the alternative — the "force-join interlock at the top of `start_search`" — blocks the render loop for the remainder of a ~250 ms cold shader compile on an Enter-Ctrl+C-Enter sequence, and blocks *forever* if the GPU wedges inside `waitUntilCompleted`, leaving the terminal in raw mode with the alternate screen active and only `kill -9` as an exit.

**Termination proof.** Once `producer_stop` is set, every operation the producer can be inside is individually bounded:

| Phase | Bound | How `stop` is observed |
|---|---|---|
| Fill (8192 mnemonics + packing) | ~4.1 ms total | checked every 512 candidates (~0.26 ms) |
| `waitUntilCompleted` on one command buffer | ~8.8 ms (4 dispatches × 2.2 ms) | n/a — bounded by construction |
| Drain in-flight ring | ≤ 3 × 8.8 ms = 26.4 ms | n/a |
| `send_timeout` | ≤ 100 ms, or immediate `Disconnected` | checked per attempt |
| Library compile / self-test (startup only) | ~95 ms + ~300 ms | checked after each phase |

Worst case in steady state: **8.8 + 26.4 + 100 ≈ 135 ms**; typical ~15 ms. Worst case during startup: ~400 ms, still non-blocking for the UI. Two independent wake paths exist — the stop flag, and channel `Disconnected` once `App` and every worker have dropped their `Receiver` clones — so losing either does not hang. `Sender::send` is **never** called bare and **never** `unwrap`ped: a `Disconnected` is a clean `return Ok(())`, not a panic on a background thread writing a backtrace across the Ratatui frame.

**Backpressure.** `crossbeam::bounded(32)` — 2 waves' worth of blocks. A wave produces all 8192 seeds as one burst; 8 workers absorb 8192 × 50.5 µs = 414 core-ms ≈ 52 ms of wall time against a ~600 ms wave, so the queue drains with enormous margin and `send_timeout` essentially never fires. If it does (Threads = 1 on an E-core, or a worker stall), the producer self-throttles to exactly the rate the workers can absorb — the correct behaviour when the CPU is the binding constraint — and `blocks_dropped` stays 0 because nothing is discarded.

**A panicking GPU thread is visible.** The thread body runs inside `catch_unwind(AssertUnwindSafe(..))` with a `Drop` guard setting `finished`. On `Err(_)` it raises `GpuDisableReason::Panicked`. `drain_matches` additionally treats "engine finished while `state == Searching` and `health.disable` is false" as an unexpected exit and raises it, so a GPU that dies quietly cannot leave the TUI reporting `Running` at `0/s` forever. (`catch_unwind` catches Rust unwinds only — this is precisely why `setMathMode` is not called and why the threadgroup clamp is bounded: an Objective-C exception is uncatchable and would abort.)

---

## Error handling & degradation

**One path for every failure.** `GpuDisableReason` → `GpuHealth::raise` (set-once `OnceLock`, no `Mutex`, no poisoning on the UI read path) → producer returns → `drain_matches` promotes to `GpuStatus::Disabled(reason)` on the next 100 ms tick → sticky for the process (`gpu_requested = false`, `validated_gpu = false`) → workers see `health.disable` and stop draining, or see `Disconnected` → **the CPU search continues, uninterrupted, at full CPU-only rate.** The app never dies.

Everything routes here: device absent, `newLibraryWithSource` failure, `newFunctionWithName` returning nil, pipeline creation failure, buffer allocation failure, an invalid `GpuConfig`, self-test failure, any command buffer not `Completed`, the in-wave random `ring` audit disagreeing, a verify-gate rejection, and a producer panic.

**Sticky, not auto-retrying.** A mis-derived seed is a correctness fault, not a transient. Silently retrying a GPU that has already produced one wrong seed is not a trade worth a 2× speedup. Recovery is a restart of the app (or the env/feature levers below).

**Rollback levers, softest first.**

1. **TUI toggle** — `GPU [On/Off]` field, takes effect on the next `start_search`.
2. **`VANADDY_GPU=0`** (equivalently `VANADDY_NO_GPU=1`) — read once in `main`, forces the field off and labels it `(disabled by VANADDY_GPU=0)`. Env always wins. No rebuild.
3. **`cargo build --release --no-default-features`** — compiles `stub.rs`, links no Metal, contains no GPU code. Doubles as a CI leg proving the CPU binary stands alone.
4. **Automatic** — the self-disable above.
5. **Git** — ship as ONE commit so `git revert` is one command.

**No stderr scribbling.** A deliberately malformed shader compile was verified to produce **0 bytes on stderr** — the error returns purely as an `NSError` (`MTLLibraryErrorDomain` code 3). Metal's validation layer is opt-in via `METAL_DEVICE_WRAPPER_TYPE` and off by default; the design never calls `MTLCaptureManager` and leaves `enableLogging` at its default false. The far likelier stderr source — a Rust panic — is handled by the `main()` panic hook. If a future macOS becomes chatty, the fallback is `dup2`-ing fd 2 to `/dev/null` for the lifetime of the alternate screen (noted, not implemented).

---

## Correctness & testing

### Every pinned vector stays valid, untouched

`src/seed.rs`, `src/pbkdf2_lanes.rs`, `src/bip32.rs`, `src/slip10.rs`, `src/chains/ton_cell.rs`, `src/chains/ton_mnemonic.rs`, and all five `src/chains/*.rs` derivation bodies keep byte-identical logic. The only edits are the four `pub` visibility changes listed above, `Evm::from_seed` → `pub(crate)`, and **additive** items. `src/chains/mod.rs:130-146`'s `search_counts_whole_batches_and_honours_stop` needs **no argument change at all** (it calls `search::<Solana>`, whose signature is unchanged) and its `n % LANES == 0` assertion at line 145 stands. All 63 existing tests must pass with identical names under both `cargo test` and `cargo test --no-default-features`.

### The two agreement properties

**P1 (seed agreement — tested).** For every valid English 12-word phrase `p` with byte length 47..=107:
```
gpu.derive(&[p], 2048)[0] == derive_seed(&Mnemonic::from_phrase(p))
                          == derive_seeds::<4>(&[p; 4])[i]  for all i
```
Asserting against `ring` **and** the 4-lane NEON path in one test is deliberate: `ring`-only would miss a case where the GPU and `ring` agree but the accelerated CPU path has drifted — the situation where CPU-found and GPU-found matches in the same CSV disagree with each other.

**P2 (coherence — enforced, not tested).** For every `Match` that reaches `vanity_wallets.csv`:
```
Evm::from_seed(derive_seed(Mnemonic::from_phrase(m.mnemonic))) == (m.address, m.secret_hex)
```
This is a runtime invariant enforced by the `Verified` token, not a test — no test on random phrases can cover the specific phrase a user actually gets.

### New tests

**No GPU required (run on every CI leg, including Linux):**

| File | Test |
|---|---|
| `gpu/pack.rs` | `pack_key_block_matches_reference_ipad_opad`; `pack_is_big_endian_for_known_vector`; `pack_rejects_password_over_128_bytes`; `pack_rejects_empty_password`; `every_english_12_word_phrase_fits_one_block` (4096 samples, asserts 47 ≤ len ≤ 107 < 128); `salt_block_matches_host_computation`; `salt_block_rejects_salt_over_max_salt_len`; `kernel_source_bans_threadgroup_simd_barrier_atomic`; `kernel_source_uses_tid_only_in_index_expressions` |
| `gpu/selftest.rs` | `accepts_a_correct_derive_fn` (derive = `ring`); `detects_single_bit_flip`; `detects_swapped_outputs` (permutation); `detects_all_zero_output`; `detects_surviving_poison`; `detects_stale_previous_result`; `detects_short_output_vec`; `detects_schedule_divergence` |
| `verify.rs` | `verify_gpu_accepts_a_real_candidate`; `rejects_flipped_address_nibble`; `rejects_entropy_from_a_different_candidate` (the mis-pairing case); `verified_token_cannot_be_constructed_outside_this_module` (compile-fail doc test) |
| `chains/mod.rs` | `gpu_block_is_consumed_counted_and_cpu_verified` (build a `SeedBlock` from `ring` seeds — no Metal needed); `corrupted_gpu_seed_raises_fault_and_emits_nothing` (**full body, not a stub**: flip one bit of `entries[3].seed`, all-accepting matcher, assert 3 matches emitted, `health.disable == true`, `take_reason()` is `Some(VerifyMismatch{..})`); `gpu_drain_honours_stop_mid_block`; `search_with_no_gpu_source_is_unchanged` |
| `app.rs` | `unverified_match_is_never_written_to_csv`; `verified_match_is_written_and_file_is_0600`; `open_csv_secure_reasserts_0600_on_preexisting_0644`; `mismatch_disables_gpu_and_leaves_app_running` (asserts `!should_quit`, `state == Searching`); `start_stop_restart_does_not_leak_threads` extended with `app.gpu_requested = false` **and** an assert that `gpu_engines` is empty after reap; `gpu_field_index_is_stable_across_match_positions` |

**GPU required** (`gpu/metal.rs`): `gpu_seed_matches_bip39_canonical_vector`; `gpu_ring_and_4lane_agree_over_512_deterministic_phrases`; `gpu_matches_ring_at_total_iters_1_2_3_16_2048`; `gpu_chunk_schedule_invariance` (R ∈ {2047, 8, irregular}); `gpu_handles_ragged_counts` (n ∈ {1, 2, 31, 33, 255, 257, 511, 512, 513}); `gpu_slots_beyond_count_keep_their_poison`; `gpu_repeat_wave_is_bit_identical`; `gpu_command_buffer_error_yields_err_not_partial_output`; `gpu_no_rss_growth_over_100k_dispatches` (`#[ignore]`, the autorelease-pool regression guard — invisible in short tests, only surfaces after hours); `gpu_soak_matches_ring` (`#[ignore]`, `VANADDY_GPU_SOAK_N`).

**Deterministic corpus.** `ChaCha20Rng::seed_from_u64(0x5EED_1234)` from `rand_chacha` — **not** `StdRng`, whose algorithm `rand` explicitly reserves the right to change in a minor release, which would silently reshuffle the corpus exactly when someone is bisecting a GPU failure. Composition: the canonical `abandon…about` at index 0 **and** index 511; two length extremes pinned as string constants (47 and 107 bytes — a random draw of 500 phrases will essentially never contain a 47-byte one, and length-dependent zero-padding is precisely where a packing bug lives); the rest from the stream. Failure messages carry index, phrase, and both hex seeds so a red build replays by index.

**The skip helper — absence must be loud where the backend ships.**

```rust
#[cfg(test)]
pub(crate) fn gpu_for_test() -> Option<MetalPbkdf2> {
    if std::env::var_os("VANADDY_NO_GPU").is_some() { eprintln!("SKIP: VANADDY_NO_GPU"); return None }
    match MetalPbkdf2::new() {
        Ok(g) => Some(g),
        Err(e) => {
            if cfg!(all(target_os="macos", target_arch="aarch64", feature="metal")) {
                panic!("Metal backend must be available on Apple Silicon: {e:?}\n\
                        Set VANADDY_NO_GPU=1 to skip GPU tests deliberately.");
            }
            eprintln!("SKIP: no Metal backend ({e:?})"); None
        }
    }
}
```
A test that returns early passes. On the one machine where the backend actually ships, an early return means the differential silently never ran and a broken kernel reaches a user's wallet with a green suite.

**CI matrix:** (1) `cargo test` on macOS aarch64 — GPU tests run for real; (2) `cargo test --no-default-features` on macOS — GPU compiled out; (3) `cargo test` on linux x86_64 — GPU skips, `pbkdf2_lanes` fallback exercised; (4) `VANADDY_NO_GPU=1 cargo test` on macOS — proves the skip path itself compiles; (5) `cargo clippy --all-targets` + `cargo fmt --check`.

**On `ring` as the reference.** Both the gate and the differential compare against `ring::pbkdf2`, which is what `derive_seed` uses — circular if `ring` were wrong. Every layer therefore anchors to external ground truth *first*: the self-test checks the BIP-39 canonical vector before any `ring` cross-check, using the same constant already pinned at `src/seed.rs:41`. The honest framing: the GPU is proven to agree with the code that the pinned vectors already pin, which is exactly the property wanted.

---

## TUI changes

**Field placement — resolved against both prior designs.** Three designs put `GPU` **last**. Reviewers showed that breaks the app: `field_count() - 1` is load-bearing in `is_text_field` (`src/app.rs:88`) and in the thread-count input arm (`src/app.rs:520`), and transitively in the `q`-quits guard (`:372`) and `h`-help guard (`:358`). Put GPU last and pressing `y` does nothing, typing a digit appends to `thread_count`, the Threads field becomes unresponsive, and `q` quits the app mid-configuration. Put it before Case and it hits no arm at all.

**GPU goes between Case and Threads.** Verified against the real indices: Case's hard-coded `if both { 4 } else { 3 }` (`src/app.rs:512`) stays correct; Threads stays at `field_count() - 1` so both `is_text_field` and its input arm are untouched; GPU lands at `field_count() - 2`, which currently matches no arm, so it needs exactly one new arm. `field_count()` goes 5→6 / 6→7. This is a **strictly smaller and safer diff** than "GPU last", and Case → GPU → Threads reads as a coherent compute-resources group. Add `gpu_field_index_is_stable_across_match_positions` to pin it.

```rust
// handle_field_input, new arm:
f if f == app.field_count() - 2 => {
    let want = match key.code {
        KeyCode::Char('y') | KeyCode::Char('Y') => Some(true),
        KeyCode::Char('n') | KeyCode::Char('N') => Some(false),
        KeyCode::Left | KeyCode::Right          => Some(!app.gpu_requested),
        _ => None,
    };
    match (want, &app.gpu_status, app.chain == ChainKind::Evm) {
        (None, _, _) => {}
        (Some(false), _, _) => { app.gpu_requested = false; app.error_message = None; }
        (Some(true), GpuStatus::Unavailable(r), _) =>
            app.error_message = Some(format!("GPU unavailable: {r}")),
        (Some(true), GpuStatus::Disabled(r), _) =>
            app.error_message = Some(format!("GPU disabled this session: {r:?}")),
        (Some(true), _, false) => app.error_message =
            Some(format!("GPU offload is EVM-only — {} runs on CPU", app.chain.label())),
        (Some(true), _, true) => { app.gpu_requested = true; app.error_message = None; }
    }
}
// gpu_requested is deliberately NOT cleared when the chain changes: the
// preference survives a round-trip through Solana and back to EVM.
```

**Config form row** (label keeps focus styling so the field is discoverable; the *value* carries the disabled styling and the reason — "visibly disabled, not silently ignored"):

```
 GPU:      [On]  Apple M1 — EVM only
 GPU:      [Off]
 GPU:      [n/a — no Metal device]                    (DarkGray)
 GPU:      [n/a — EVM only]                           (DarkGray)
 GPU:      [disabled — VerifyMismatch]                (Red)
```

**Stats pane.** Build an **owned `String`** before the `Line::from` — the `match`-of-`&format!` sketched in two designs does not compile (`E0515`), and `GpuDisableReason::ShaderCompile(String)` carries multi-line Metal compiler diagnostics, so sanitize control characters to spaces and truncate to the available width. `stats_height()` must not count both a live line and a fault line (setting `gpu_rx = None` in the fault-promotion block prevents the doubled `GPU:` row).

```
 GPU       : initialising (compiling shader, self-testing)
 GPU       : Apple M1   13.6k/s (54%)                 ← MEASURED per wave, never modelled
 GPU       : OFF — AuditMismatch { index: 5183 } (CPU search continues)   (Red)
```

The displayed GPU rate must be **measured** from wave completion times published into an `AtomicU64`, never modelled — mid-run throughput collapse to 3,000–7,000 seeds/s was reproducibly observed while the desktop compositor was busy, and a modelled rate would lie by up to 4×.

**Match list.** `App.matches` becomes a `VecDeque` capped at 500 with a separate `total_matches: u64` counter, and `render_match_table` renders only the visible window. This is not gold-plating: a reviewer showed that at a 1-character EVM vanity the match rate is ~1 in 16, which the GPU roughly doubles to ~1,700/s; `src/ui.rs:353-370` rebuilds every row (3 `String` allocations each) 10× per second, so after 60 s the render thread is doing ~300,000 allocations per frame and the TUI hard-freezes — through the exact render-tick path the gate placement was chosen to protect. `drain_matches` should also hold the CSV `File` open for the search rather than reopening per row (~5,100 syscalls/s at that rate), still re-asserting 0600 on open.

**Help popup:** `y/n   Case sensitivity, GPU offload` and `GPU offload   Metal PBKDF2, EVM only (Apple Silicon)`.

**ETA.** `projected_seconds` already switches to the measured live rate once `start_time` is `Some` (`src/app.rs:163-166`), and that is automatically correct because GPU candidates increment the same `counter`. Only the pre-search estimate changes:

```rust
const EVM_GPU_SEEDS_PER_SEC: f64 = 13_600.0;   // measured under CPU load, not the 14,767 idle peak
const EVM_GPU_TAIL_SECS: f64 = 50.5e-6;        // measured directly on a GPU-supplied seed

fn estimated_rate(&self) -> f64 {
    let threads = self.thread_count.parse::<f64>().unwrap_or(1.0).max(1.0);
    let per_thread = self.single_thread_rate();
    if !(self.gpu_effective() && matches!(self.gpu_status, GpuStatus::Running { .. })) {
        return per_thread * threads;
    }
    let tail = (EVM_GPU_SEEDS_PER_SEC * EVM_GPU_TAIL_SECS).min(threads);   // ≈ 0.69 cores
    EVM_GPU_SEEDS_PER_SEC + (threads - tail) * per_thread
}
```

**Honest arithmetic, correcting two designs.** The integration design claimed this formula "reproduces the measured result: 24,981"; with the actual defaults (`threads = 8`, `single_thread_rate() = 3_115`) it yields **36,799**, because `single_thread_rate() × threads` is *already* ~1.6× optimistic on an M1 (8 threads measure 11,500–14,900 EVM cand/s, not 24,920 — four of those cores are E-cores). The kernel design separately claimed the GPU's CPU tail costs only 249 cand/s; it actually displaces `13,600 × (50.5/308.1) ≈ 2,230` CPU cand/s, ~9× more. **Honest hybrid: ~23,000–26,000 cand/s, ≈2×.** The pre-existing CPU-side optimism is *not* fixed here (it would change ETA behaviour for all five chains — a separate change with its own blast radius) but it is called out so nobody attributes the post-Enter ETA jump to the GPU. Also recommend defaulting `validated_thread_count` to `cores - 1` when the GPU is on, since the tail consumes ~0.69 core-seconds per wall-second.

---

## Risks that remain

**Accepted, not fixed:**

1. **Plaintext phrase bytes live in GPU-visible unified memory.** The adopted kernel computes the HMAC prologue on the GPU, so the `keys` buffer holds the zero-padded 12-word phrase (`K0`) itself, and `states` holds ipad/opad midstates which are seed-equivalent. *The ffi design's claim that "the plaintext phrase never enters GPU-visible memory" is false under the adopted topology and is retracted.* Mitigation: `StorageModeShared` pages are wiped by `WaveBuffers::drop` and at the end of every wave (bounding the window to one wave, ~600 ms); the host entropy mirror is `Zeroizing<Vec<[u8;16]>>`; `SeedBlock` is `ZeroizeOnDrop`; the channel is bounded at 32 blocks. **Residual:** 3.5 MiB of GPU-visible secret material plus 128 KiB of host entropy are resident during a wave, in ordinary swappable memory. This is a genuinely new exposure surface versus the CPU path's 4 lanes per worker. `mlock()` is deliberately not used — the CSV writes the same material to disk in plaintext (0600) anyway, so it would be inconsistent hardening. Stated so nobody calls this "hardened".

2. **Feeder phrase `String`s are not zeroized.** `Mnemonic::new` heap-allocates a ~80-byte plaintext phrase per candidate (~13,600/s on the GPU thread), freed without wiping. This exactly mirrors the pre-existing CPU path at `src/chains/evm.rs:71` and is **not a regression** — but the entropy-payload decision bounds the *resident backlog*, it does not eliminate transient plaintext. Do not describe it as doing so.

3. **A wrong GPU seed causes silent *misses*, not bad rows.** A faulty GPU produces seeds that simply fail `matches_raw`, so the user sees the counter climbing while up to ~55% of it is noise. The emit path is structurally safe; the detection path is probabilistic. Mitigation: the self-test, plus 4 **random** `ring` audits per wave (~0.05% CPU, expected detection of any ≥1-in-2048 systematic bug within a few waves), plus the immediate `verify_gpu` rejection on any match. A localised bug affecting a handful of specific `tid`s could still evade detection for a long time — this is the honest floor.

4. **GPU contention with the compositor.** Throughput was observed collapsing to 3,000–7,000 seeds/s (from ~14,500) while other apps composited — a 2–4× drop reproducible enough to have polluted two measurement grids. The `try_recv` architecture self-balances so this degrades gracefully, but the TUI rate must be measured (see above), and no static CPU/GPU split may ever be built on the 14,500 figure.

5. **Metal ordering guarantees are relied upon.** Correctness depends on (a) command buffers on one queue executing in commit order, and (b) dispatches within one `MTLDispatchTypeSerial` compute encoder being barriered. Both are documented and were empirically verified (every depth-3 run in the tuning grid produced the exact BIP-39 vector, checked on the *last* candidate of an 8192 wave). If ever in doubt, the fallback is one dispatch per command buffer at depth 1 — measured 12,984 seeds/s, a 10% loss, not a cliff. **Do not reach for `MTLFence` speculatively**; add it only if a schedule-invariance test fails.

6. **`objc2-metal` 0.3.x is pre-1.0** and regenerated against Apple SDK releases. The surface actually used is ~14 methods in one file, `Cargo.lock` pins exact versions, and the stub backend means a broken bump never blocks any other platform. Versions must be verified against crates.io before merge — this is the one interface no agent could check (no network).

7. **`GPU_BLOCK`/wave sizing is measured only on this M1.** The 8192-vs-32768 knee (14,462 vs 13,345 seeds/s) is hypothesised to be the M1 system-level cache (8192 × 256 B = 2 MiB of state fits; 32768 × 256 B = 8 MiB does not) but is unconfirmed. `maxTotalThreadsPerThreadgroup = 384` and the 256 clamp being 13% faster are likewise M1-specific. Both are runtime-queried or env-overridable; neither is hardcoded.

8. **A detached, wedged GPU thread leaks 3.5 MiB unwiped.** If `waitUntilCompleted` never returns (driver fault, system GPU reset), the reaper eventually gives up and the process exits with buffers un-zeroized. Accepted: the alternative (blocking the UI thread forever) is strictly worse, and the case is rare.

**Explicitly out of scope (reuse seams, one sentence):** `Bip39GpuChain` is a one-line impl away for Solana and Bitcoin (both already have a private `from_seed` of exactly that shape), and the kernel is already salt- and iteration-agnostic for TON — but TON additionally needs a compaction step between its 390- and 100,000-round stages (only ~1/256 candidates pass the intermediate filter) and 24-word phrases straddle the 128-byte HMAC block, so both need real design work that is not attempted here.

---

## Implementation order

Each milestone is independently testable and independently revertable.

**1 — Host-side packing and constants. No Metal, no threads.**
Add `src/gpu/mod.rs` (constants, `GpuCandidate`, `SeedBlock`, `GpuError`, `GpuStatus`, `GpuHealth`) and `src/gpu/pack.rs`. Make `PBKDF2_ROUNDS`/`BIP39_SALT`/`HMAC_BLOCK_LEN`/`MAX_SALT_LEN` public. Add `pub mod gpu;` to `main.rs` with the stub backend selected on every target.
*Verify:* the whole GPU-free pack test set passes on Linux and macOS; all 63 existing tests unchanged; `cargo test --no-default-features` green.

**2 — The verify gate and the `Verified` token, CPU-only.**
Add `src/verify.rs`, `Bip39GpuChain` for `Evm`, `Match.verified`, `search_cpu_step`, `search_hybrid` (with `gpu: None`), `append_match_row`, `open_csv_secure(path)`.
*Verify:* `verify_gpu_*` tests; `gpu_block_is_consumed_counted_and_cpu_verified` and `corrupted_gpu_seed_raises_fault_and_emits_nothing` — both built from `ring` seeds, so this milestone proves the entire trust boundary with no GPU in the tree. `unverified_match_is_never_written_to_csv`, `open_csv_secure_reasserts_0600_on_preexisting_0644`.

**3 — The Metal backend, offline. No TUI wiring.**
Add `src/gpu/pbkdf2_bip39.metal` (verbatim copy), `src/gpu/metal.rs` (device, library, pipelines, `WaveBuffers`, `run_wave` with the do-while, per-command-buffer autorelease pool, status checks, poison, exact-length return), `src/gpu/stub.rs`, `src/gpu/selftest.rs`, the Cargo deps and the `metal` feature.
*Verify:* all GPU-required tests, driven from `#[cfg(test)]` — the canonical vector, the 512-phrase three-way differential, iteration counts {1,2,3,16,2048}, chunk-schedule invariance, ragged counts, poison survival, repeat-wave bit-identity, injected command-buffer error. Run `gpu_no_rss_growth_over_100k_dispatches` manually and confirm RSS is flat. **Do not proceed until the canonical vector reproduces and RSS is flat.**

**4 — The producer thread. Still no TUI.**
Add `src/gpu/producer.rs` and `GpuEngine::{start, signal_stop, is_finished, reap}` with the producer-only stop flag, the QoS call, `Zeroizing` entropy mirror, random per-wave audits, block carving, `send_timeout` loop, and `catch_unwind` + `Drop` guard.
*Verify:* a test harness that starts an engine, consumes 3 waves, checks every seed against `ring`, sets stop, and asserts the thread finishes within 200 ms; a test that drops the receiver and asserts a clean exit (no panic); a test that injects an audit mismatch and asserts `GpuHealth::disable` with the right reason. **Measure the real end-to-end seeds/s here and update `EVM_GPU_SEEDS_PER_SEC` if it differs from 13,600.**

**5 — Worker integration.**
Wire `gpu: Option<&GpuRx>` and `health` through `ChainKind::search`, `search_hybrid`'s `try_recv` drain, `drain_gpu_block`'s chunked stop checks and counter increments, and `emit_gpu_match`.
*Verify:* `gpu_drain_honours_stop_mid_block`; `search_with_no_gpu_source_is_unchanged`; `search_counts_whole_batches_and_honours_stop` still green untouched. Run a real EVM search with a 1-character prefix and confirm every CSV row re-derives and the counter is honest.

**6 — App lifecycle.**
`App` GPU fields, `main()`'s pre-raw-mode probe and panic hook, `gpu_effective()`, `validate()`'s advisory GPU line, `start_search`'s non-blocking reap-then-spawn, `stop_search`'s signal-and-park, `drain_matches`'s fault promotion, the `VecDeque` match cap, the held-open CSV file.
*Verify:* `mismatch_disables_gpu_and_leaves_app_running`; `start_stop_restart_does_not_leak_threads` extended; hammer Enter/Ctrl+C for 30 s and confirm no UI stall, no thread accumulation, and at most one live engine.

**7 — TUI surface.**
The `GPU` field between Case and Threads, `field_count()` 5→6/6→7, the new input arm, the config-form row, the measured-rate stats line, the fault line, `stats_height`, help entries, `estimated_rate`.
*Verify:* `gpu_field_index_is_stable_across_match_positions`; manually confirm the Threads field still edits, `q` still quits from every non-text field, `h` still opens help, and every `GpuStatus` renders without control characters or clipping.

**8 — Soak and ship.**
`VANADDY_GPU_SOAK_N=1e7 cargo test -- --ignored` (full `ring` differential); a 12-hour real search with RSS sampled every 10 minutes; a run with `VANADDY_GPU=0`; a run with `--no-default-features`; `cargo clippy --all-targets` and `cargo fmt --check` clean. Update `CLAUDE.md` — the pinned-vector list gains the GPU chunk-schedule-invariance and canonical-vector tests, the performance table gains a GPU row with the *measured* hybrid figure, and the Conventions section gains the four new hard rules (autorelease pool per command buffer, command-buffer status checked at every wait, no GPU-derived key material, never join the GPU thread from the UI thread). Ship as **one commit**.