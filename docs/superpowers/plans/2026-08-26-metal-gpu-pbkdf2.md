# Metal GPU PBKDF2 Offload — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Offload BIP-39 PBKDF2-HMAC-SHA512 (c = 2048, salt `"mnemonic"`, dkLen 64) to the Apple GPU alongside the existing CPU workers, roughly doubling EVM vanity-address throughput on Apple Silicon.

**Architecture:** One dedicated `vanaddy-gpu` OS thread owns every Objective-C object and never lets one cross a thread boundary, so single-thread confinement is enforced by `objc2`'s `Send` bounds at compile time. It generates 12-word mnemonics on the CPU in waves of 8,192, runs a resumable Metal PBKDF2 kernel in ~4 ms chunks, and pushes `(entropy, seed)` pairs into a bounded channel. Existing Rayon workers drain that channel with a non-blocking `try_recv` and fall back to the unchanged CPU path when it is empty, so the CPU/GPU split self-balances with no static tuning. Every GPU-sourced match is re-derived on the CPU with `ring` before it can become a CSV row.

**Tech Stack:** Rust 2021, Metal 3 (MSL), `objc2` / `objc2-metal` / `objc2-foundation`, `crossbeam-channel`, `zeroize`, `ring` (reference PBKDF2), `rayon`, `ratatui`.

**Spec:** `docs/superpowers/specs/2026-08-26-metal-gpu-pbkdf2-design.md`

## Global Constraints

Every task's requirements implicitly include this section.

**Cryptographic correctness (from CLAUDE.md — these outrank every other goal):**
- These **19** pinned test functions must keep passing, unmodified:
  `seed::derive_seed_matches_bip39_vector`, `seed::derive_seeds_matches_derive_seed_per_lane`,
  `pbkdf2_lanes::{every_lane_matches_bip39_canonical_vector, distinct_lanes_match_ring_reference, ton_salts_and_iteration_counts_match_ring}`,
  `slip10::{slip10_ed25519_test_vector_1_m_0h, slip10_ed25519_test_vector_1_m_0h_1h}`,
  `solana::solana_phantom_derivation_from_canonical_phrase`, `bitcoin::bip84_canonical_vector`,
  `evm::{eip55_canonical_vector, eip55_second_vector, bip44_canonical_vector}`,
  `generate_batch_emits_lane_count_candidates_matching_single_path` (three copies — `solana`, `evm`, `bitcoin`),
  `ton::{ton_tonkeeper_round_trip_vector, generate_batch_emits_lane_count_wallets_with_consistent_addresses}`,
  `ton_cell::wallet_v5r1_matches_tonkeeper_vector`, `monero::keccak256_empty_vector`.

  > **Note for the implementer:** CLAUDE.md lists the SLIP-0010 pair as
  > `slip10_ed25519_test_vector_{1,2}`. Those names do not exist. The real functions
  > are `slip10_ed25519_test_vector_1_m_0h` and `slip10_ed25519_test_vector_1_m_0h_1h`
  > (`src/slip10.rs`). Use the real names in any grep gate; a gate written against
  > CLAUDE.md's names would silently match nothing and pass regardless. Milestone 8
  > corrects CLAUDE.md.
- `chains/<x>.rs::matches_raw` stays allocation-free. No `to_lowercase()`, `format!`, `Vec::new()` on the per-candidate path.
- Dispatch stays monomorphized. No `Box<dyn Chain>`, no v-table on the candidate path.
- The CSV is `chmod 0600` on **every** open. Both halves survive: `.mode(0o600)` at create AND the post-open `set_permissions` re-assert.
- SLIP-0010 indices are all hardened; Monero secrets stay `Zeroize + ZeroizeOnDrop`.

**GPU-specific hard rules (from the spec):**
- **No GPU-derived key material, ever.** Entropy comes only from `bip39::Mnemonic::new(MnemonicType::Words12, Language::English)` on the CPU. A `tid`-derived key would make every wallet the tool emits recoverable from one 64-bit value while still passing every address test.
- **One `autoreleasepool` per command buffer.** Not per wave. A pool that spans a multi-day run grows unboundedly.
- **Command buffer status is checked at EVERY `waitUntilCompleted`**, not only the last. Reading a buffer whose command buffer errored yields a plausible-but-wrong seed.
- **Never join the GPU thread from the UI thread.** `stop_search` signals and parks; `start_search` reaps non-blockingly and skips the GPU for that run if a previous engine has not finished.
- **`MTLLanguageVersion::Version3_0` only.** Never call `setMathMode` / `setFastMathEnabled`: `setMathMode:` is macOS 15+, objc2-metal emits it with no availability guard, and on Ventura/Sonoma it raises an Objective-C exception that `catch_unwind` cannot catch — aborting inside raw mode with the alternate screen still active. It is also useless: SHA-512 is integer-only.
- **`validate()` must never return `Err` for a GPU reason.** A stale toggle can never block a search from starting.
- The producer gets its **own** stop flag, never `App::stop`. Setting `App::stop` from a GPU fault would silently end the entire CPU search.

**Dependency and platform floors:**
- `objc2` 0.6, `objc2-metal` 0.3, `objc2-foundation` 0.3 — target-gated to `aarch64-apple-darwin` behind the default `metal` feature. Not `metal-rs` (self-deprecated; blanket-declares non-thread-safe objects `Send + Sync`).
- `crossbeam-channel` is declared **unconditionally**, so `search_hybrid`'s signature is platform-independent.
- Every other target compiles `src/gpu/stub.rs` and links no Metal. `cargo build --release --no-default-features` must produce a working CPU-only binary.
- Every GPU-requiring test must **skip gracefully** where no Metal device exists (CI, other developers' machines).

**Verified baseline (measured on this branch — do not "correct" these):**
- `cargo test` reports exactly **63 passed; 0 failed; 0 ignored**.
- `cargo clippy --all-targets` is **not** warning-free at baseline. Never assert "no warnings"; compare against the pre-existing count.
- `ba07199..HEAD` includes two unrelated commits (`4854a59`, `beced09`). Never use that range as a milestone diff.
- There is **no** bench harness in this tree. Commands are `cargo test`, `cargo build --release`, `cargo clippy --all-targets`, `cargo fmt`.

## File Structure

| File | Status | Single responsibility |
|---|---|---|
| `src/gpu/mod.rs` | NEW | Portable surface: constants, `GpuCandidate`, `SeedBlock`, `GpuStatus`, `GpuDisableReason`, `GpuHealth`, `GpuError`, backend selection. Names no Objective-C type. |
| `src/gpu/pack.rs` | NEW | Host-side byte packing (`KeyBlock`, salt block). All endianness lives here so the kernel has none. Fully testable with no GPU. |
| `src/gpu/pbkdf2_bip39.metal` | NEW | The validated PBKDF2 kernel, `include_str!`-ed. Copied verbatim from `docs/superpowers/specs/prototype/`. |
| `src/gpu/metal.rs` | NEW | The **only** file naming an Objective-C type. Device, library, pipelines, `WaveBuffers`, `run_wave`. |
| `src/gpu/stub.rs` | NEW | No-op backend with the identical public surface, for every non-Metal target. |
| `src/gpu/selftest.rs` | NEW | Startup vectors, injectable so the checker itself is testable without a GPU. |
| `src/gpu/producer.rs` | NEW | The wave loop: mnemonic fill, dispatch, `ring` audits, block carving, backpressure, panic containment. |
| `src/verify.rs` | NEW | The `Verified` proof token and `verify_gpu`. The trust boundary. |
| `src/chains/mod.rs` | CHANGED | Adds `Bip39GpuChain`, `search_cpu_step`, `search_hybrid`, `drain_gpu_block`, `emit_gpu_match`, `Match.verified`. `search<C>` keeps its signature. |
| `src/chains/evm.rs` | CHANGED | `from_seed` becomes `pub(crate)`; adds `impl Bip39GpuChain for Evm`. |
| `src/seed.rs` | CHANGED | Makes `PBKDF2_ROUNDS` and the BIP-39 salt public. Derivation logic untouched. |
| `src/pbkdf2_lanes.rs` | CHANGED | Makes `HMAC_BLOCK_LEN` and `MAX_SALT_LEN` public. Derivation logic untouched. |
| `src/app.rs` | CHANGED | GPU fields, non-blocking lifecycle, fault promotion, `open_csv_secure(path)`, `append_match_row` as the single CSV writer. |
| `src/main.rs` | CHANGED | `pub mod gpu; pub mod verify;`, the pre-raw-mode GPU probe, the terminal-restoring panic hook. |
| `src/ui.rs` | CHANGED | The `GPU` config field, the measured-rate line, the fault line, help entries. |
| `Cargo.toml` | CHANGED | `objc2*` (target-gated), `crossbeam-channel`, `zeroize`; the default `metal` feature. |
| `CLAUDE.md` | CHANGED | Pinned-vector list, performance table, four new hard conventions. |

---
## Milestone 1 — Host-side packing and constants

No Metal, no threads, no Objective-C. This milestone adds `src/gpu/` with the
portable surface only (constants, POD types, health cell, byte packing) and the
stub backend, and publishes the four crypto constants the GPU path must share
with the CPU reference. Everything here is testable on Linux, on x86-64 macOS,
and under `--no-default-features`.

**Read before starting — two facts about this repo that will otherwise bite you:**

1. **Do NOT run bare `cargo fmt`.** The tree at `beced09` (HEAD of
   `feat/metal-gpu-pbkdf2`) is *not* rustfmt-formatted: `cargo fmt --check` reports
   **84** diffs across **14** files (`src/ui.rs` 18, `src/chains/ton_cell.rs` 12,
   `src/app.rs` 11, `src/chains/monero.rs` 9, `src/chains/solana.rs` 6,
   `src/chains/ton_mnemonic.rs` 6, `src/chains/bitcoin.rs` 5,
   `src/pbkdf2_lanes.rs` 4 at lines 64/90/234/355, `src/slip10.rs` 3,
   `src/chains/evm.rs` 3, `src/chains/ton.rs` 3, `src/matcher.rs` 2,
   `src/bip32.rs` 1, `src/chains/mod.rs` 1). Running `cargo fmt` would bury this
   milestone in an unrelated whole-tree reformat. Format only the files you create:
   `rustfmt --edition 2021 src/gpu/*.rs`.
2. **Do NOT run `cargo clippy -- -D warnings`.** `cargo clippy --all-targets` emits
   **12** distinct diagnostics today (the bin target's 11 plus one test-only lint;
   the per-target summary lines say "11 warnings" and "12 warnings" for the same 12
   sites). The gate for this milestone is *zero clippy diagnostics pointing into
   `src/gpu/`*, with those 12 unchanged. Never write or expect "no warnings" — the
   clean baseline is not warning-free. The exact command and the exact 12 lines are
   in Task 1.8 Step 5.
3. **Neither `ba07199` nor `beced09` is this milestone's base — `7e49a54` is.**
   `git log --oneline ba07199..HEAD` prints four commits that are not part of this
   work: `4854a59` (`ui: move key hints to a full-width bottom row`, which edits
   `src/ui.rs` and `src/app.rs`), `beced09` (`docs: design spec …`), and the two
   plan-document commits `094e8c3` and `7e49a54`. Diff and check out against
   `7e49a54` — the current branch HEAD, the tree this milestone starts from — never
   against `ba07199`, which would report `4854a59` as milestone drift and, if
   "recovered" with `git checkout ba07199 -- …`, would silently revert legitimate
   committed work. `beced09` is not the base either: `094e8c3` and `7e49a54` sit
   between it and the tip, so `beced09..HEAD` reports
   `docs/superpowers/plans/2026-08-26-metal-gpu-pbkdf2.md` as drift before you have
   written a line. (Task 1.8 Step 8 additionally passes `-- . ':(exclude)docs/'`, so
   plan-file churn can never register as source drift at all.)

Baseline: `cargo test` at `beced09` (HEAD of `feat/metal-gpu-pbkdf2`) reports
`63 passed`. This milestone ends at `83 passed`.

---

### Task 1.1: Publish `PBKDF2_ROUNDS` and `BIP39_SALT` from `src/seed.rs`

`gpu::pack::pack_salt_block` must build the GPU's salt block from *the same bytes*
`derive_seed` hands to `ring`, and the producer must dispatch *the same number of
rounds*. Today both are private/inline, so there is no compiler-enforced link in the
one place the tool's correctness rests. The design spec permits exactly this additive
visibility change (spec §"Additive visibility edits to frozen files").

**Files:**
- Modify: `/Users/shawnhopkinson/Rust/Vanaddy/src/seed.rs` (line 5; lines 8-20; line 25; test module lines 28-64)

**Interfaces:**
- Produces: `pub const PBKDF2_ROUNDS: u32` (in `crate::seed`), `pub const BIP39_SALT: &[u8; 8]` (in `crate::seed`)
- Consumes: `crate::pbkdf2_lanes::pbkdf2_hmac_sha512::<L>(passwords: [&[u8]; L], salt: &[u8], iterations: u32) -> [[u8; 64]; L]` (existing, `src/pbkdf2_lanes.rs:16`)

- [ ] **Step 1: Write the failing test.** In `/Users/shawnhopkinson/Rust/Vanaddy/src/seed.rs`, inside `mod tests`, insert this immediately *before* the existing `#[test]` at line 45 (`fn derive_seeds_matches_derive_seed_per_lane`):

```rust
    /// The GPU dispatches `PBKDF2_ROUNDS` rounds over a salt block packed from
    /// `BIP39_SALT`. Pin that those two exported constants, fed to the *other*
    /// CPU implementation, still reproduce the canonical BIP-39 vector - so a
    /// drift in either is caught here rather than in a wallet nobody can open.
    #[test]
    fn exported_constants_reproduce_the_pinned_bip39_vector() {
        use crate::pbkdf2_lanes::pbkdf2_hmac_sha512;
        assert_eq!(PBKDF2_ROUNDS, 2048);
        assert_eq!(BIP39_SALT, b"mnemonic");
        let m = Mnemonic::from_phrase(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            Language::English,
        ).unwrap();
        let seeds = pbkdf2_hmac_sha512::<1>([m.phrase().as_bytes()], BIP39_SALT, PBKDF2_ROUNDS);
        assert_eq!(
            hex::encode(seeds[0]),
            "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"
        );
    }
```

- [ ] **Step 2: Run it and watch it fail to compile.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo test exported_constants_reproduce_the_pinned_bip39_vector
```

Expected output contains, twice:

```
error[E0425]: cannot find value `BIP39_SALT` in this scope
```

(`PBKDF2_ROUNDS` resolves already — a child `mod tests` can see its parent's private
items. Only `BIP39_SALT` does not exist yet.)

- [ ] **Step 3: Add the two constants.** In `/Users/shawnhopkinson/Rust/Vanaddy/src/seed.rs`, replace line 5:

```rust
const PBKDF2_ROUNDS: u32 = 2048;
```

with:

```rust
/// BIP-39 PBKDF2 iteration count. `pub` so `crate::gpu` can dispatch the GPU
/// kernel for exactly the number of rounds the CPU reference uses.
pub const PBKDF2_ROUNDS: u32 = 2048;

/// BIP-39 salt with an empty passphrase. `pub` so `crate::gpu::pack` builds the
/// GPU's salt block from the same bytes `derive_seed` hands to `ring`.
pub const BIP39_SALT: &[u8; 8] = b"mnemonic";
```

- [ ] **Step 4: Route both existing call sites through the constant.** In the same file, replace the whole body of `derive_seed` (lines 8-20 before the Step 3 edit) so it reads exactly:

```rust
/// BIP-39 seed derivation using ring's optimized PBKDF2-HMAC-SHA512.
pub fn derive_seed(mnemonic: &Mnemonic) -> [u8; 64] {
    let password = mnemonic.phrase().as_bytes();
    let mut seed = [0u8; 64];
    ring::pbkdf2::derive(
        ring::pbkdf2::PBKDF2_HMAC_SHA512,
        NonZeroU32::new(PBKDF2_ROUNDS).unwrap(),
        BIP39_SALT,
        password,
        &mut seed,
    );
    seed
}
```

(the `let salt = b"mnemonic";` local is deleted; `&[u8; 8]` coerces to `&[u8]` at the
call). Then in `derive_seeds`, replace:

```rust
    pbkdf2_hmac_sha512::<L>(passwords, b"mnemonic", PBKDF2_ROUNDS)
```

with:

```rust
    pbkdf2_hmac_sha512::<L>(passwords, BIP39_SALT, PBKDF2_ROUNDS)
```

- [ ] **Step 5: Run the full suite and watch it pass.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo test
```

Expected: `test result: ok. 64 passed; 0 failed`. Both pinned vectors
`seed::tests::derive_seed_matches_bip39_vector` and
`seed::tests::derive_seeds_matches_derive_seed_per_lane` must still appear as `ok` —
they are the guard on this edit.

- [ ] **Step 6: Confirm `src/seed.rs` is still rustfmt-clean.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && rustfmt --edition 2021 --check src/seed.rs && echo CLEAN
```

Expected: `CLEAN` with no diff above it. (`src/seed.rs` is one of the few files in
this tree that *is* rustfmt-clean at HEAD; keep it that way.)

- [ ] **Step 7: Commit.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && git add src/seed.rs && git commit -F - <<'MSG'
feat(seed): export PBKDF2_ROUNDS and BIP39_SALT

The GPU PBKDF2 path must dispatch the same round count and pack the same
salt bytes the `ring` reference uses. Publishing both as constants and
routing derive_seed/derive_seeds through them makes that link compiler-
enforced instead of a duplicated literal.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
MSG
```

---

### Task 1.2: Publish `HMAC_BLOCK_LEN` and `MAX_SALT_LEN` from `src/pbkdf2_lanes.rs`

`gpu::pack::pack_key_block` hard-asserts that the HMAC key is at most one SHA-512
block, because **the Metal kernel has no pre-hash path**: a longer key would be
silently zero-padded on the GPU while the CPU reference SHA-512-pre-hashes it
(`src/pbkdf2_lanes.rs:236`), producing a wrong-but-plausible seed. And
`gpu::pack::pack_salt_block` must reject exactly what `pbkdf2_hmac_sha512` rejects.
Both bounds are currently a private const and a bare literal.

**Files:**
- Modify: `/Users/shawnhopkinson/Rust/Vanaddy/src/pbkdf2_lanes.rs` (lines 37-38; line 236; test module lines 300-384)

**Interfaces:**
- Produces: `pub const HMAC_BLOCK_LEN: usize` (in `crate::pbkdf2_lanes`), `pub const MAX_SALT_LEN: usize` (in `crate::pbkdf2_lanes`)
- Consumes: `crate::pbkdf2_lanes::pbkdf2_hmac_sha512::<L>(passwords: [&[u8]; L], salt: &[u8], iterations: u32) -> [[u8; 64]; L]`, and the existing test helper `fn ring_reference(password: &[u8], salt: &[u8], iterations: u32) -> [u8; 64]` at `src/pbkdf2_lanes.rs:308`

- [ ] **Step 1: Write the failing test.** In `/Users/shawnhopkinson/Rust/Vanaddy/src/pbkdf2_lanes.rs`, inside `mod tests`, insert this immediately *before* the `#[test]` at line 378 (the one whose body is `fn rejects_salt_longer_than_one_block`, i.e. before its `#[test]` attribute line):

```rust
    /// The GPU kernel has no HMAC key pre-hash path, so `gpu::pack::pack_key_block`
    /// hard-asserts `len <= HMAC_BLOCK_LEN`. Pin that this constant really is the
    /// boundary the CPU reference switches behaviour at, in both directions, and
    /// that `MAX_SALT_LEN` is the padding arithmetic it claims to be.
    #[test]
    fn hmac_block_len_is_the_prehash_boundary_and_max_salt_len_is_the_padding_budget() {
        assert_eq!(HMAC_BLOCK_LEN, 128);
        assert_eq!(MAX_SALT_LEN, HMAC_BLOCK_LEN - 4 - 1 - 16);

        // Exactly HMAC_BLOCK_LEN: used verbatim. One more: SHA-512 pre-hashed.
        // Both must still agree with `ring`, which does the same switch.
        let at_boundary = vec![0x6bu8; HMAC_BLOCK_LEN];
        let over_boundary = vec![0x6bu8; HMAC_BLOCK_LEN + 1];
        for pw in [at_boundary.as_slice(), over_boundary.as_slice()] {
            let out = pbkdf2_hmac_sha512::<1>([pw], b"mnemonic", 8);
            assert_eq!(out[0], ring_reference(pw, b"mnemonic", 8));
        }

        // The longest salt that still fits one padded block is accepted.
        let salt = vec![0x73u8; MAX_SALT_LEN];
        let out = pbkdf2_hmac_sha512::<1>([b"password".as_slice()], &salt, 4);
        assert_eq!(out[0], ring_reference(b"password", &salt, 4));
    }
```

- [ ] **Step 2: Run it and watch it fail to compile.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && cd /Users/shawnhopkinson/Rust/Vanaddy && cargo test hmac_block_len_is_the_prehash_boundary
```

Expected output contains, four times (rustc emits one E0425 per occurrence, and the
new test names the constant four times — the `assert_eq!`, the `MAX_SALT_LEN`
arithmetic, and both `vec![…]` lengths):

```
error[E0425]: cannot find value `HMAC_BLOCK_LEN` in this scope
```

(`MAX_SALT_LEN` already resolves inside `mod tests` — it is a private const of the
parent module, reached through `use super::*`. `HMAC_BLOCK_LEN` does not exist yet.)

- [ ] **Step 3: Add the two constants.** In `/Users/shawnhopkinson/Rust/Vanaddy/src/pbkdf2_lanes.rs`, replace lines 37-38:

```rust
/// Longest salt for which `salt || INT(1) || padding` fits one 128-byte block.
const MAX_SALT_LEN: usize = 107;
```

with:

```rust
/// SHA-512's HMAC block size. A key longer than this is SHA-512 pre-hashed
/// before use (see `hw::pbkdf2_lanes`). `pub` because the GPU kernel has no
/// pre-hash path: `gpu::pack::pack_key_block` hard-asserts against this exact
/// bound rather than silently zero-padding an over-long key.
pub const HMAC_BLOCK_LEN: usize = 128;

/// Longest salt for which `salt || INT(1) || padding` fits one 128-byte block:
/// `HMAC_BLOCK_LEN - 4 (INT(1)) - 1 (0x80) - 16 (128-bit length field)`.
/// `pub` so `gpu::pack::pack_salt_block` rejects exactly what this path rejects.
pub const MAX_SALT_LEN: usize = 107;
```

- [ ] **Step 4: Route the pre-hash switch through the constant.** In the same file, at what was line 236 (inside `mod hw`, in `pbkdf2_lanes`), replace:

```rust
            let key: &[u8] = if password.len() > 128 {
```

with:

```rust
            let key: &[u8] = if password.len() > super::HMAC_BLOCK_LEN {
```

(`super::` because `mod hw` is a child module and `HMAC_BLOCK_LEN` lives in
`pbkdf2_lanes` itself. `mod hw` is `#[cfg(target_arch = "aarch64")]`, so on other
targets this line is simply not compiled — `HMAC_BLOCK_LEN` stays live there through
`gpu::pack`.)

- [ ] **Step 5: Run the full suite and watch it pass.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo test
```

Expected: `test result: ok. 65 passed; 0 failed`. All four pinned
`pbkdf2_lanes::tests::*` vectors (`every_lane_matches_bip39_canonical_vector`,
`distinct_lanes_match_ring_reference`, `ton_salts_and_iteration_counts_match_ring`,
`exactly_128_byte_password_matches_ring`) must still appear as `ok`.

- [ ] **Step 6: Confirm no *new* rustfmt drift in this file.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && rustfmt --edition 2021 --check src/pbkdf2_lanes.rs | grep -c '^Diff in'
```

Expected: `4`. That is the pre-existing count (at HEAD the diffs are at lines 64, 90,
234, 355; after this task the same four appear shifted to 72, 98, 242, 363). Anything
above 4 means your inserted test is not rustfmt-shaped — fix it, do not run
`cargo fmt`.

- [ ] **Step 7: Commit.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && git add src/pbkdf2_lanes.rs && git commit -F - <<'MSG'
feat(pbkdf2): export HMAC_BLOCK_LEN and MAX_SALT_LEN

The Metal kernel has no HMAC key pre-hash path, so the GPU packer must
hard-assert against the exact block size at which this path switches to
pre-hashing, and reject exactly the salts this path rejects. Publishing
both bounds makes those two asserts share one definition.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
MSG
```

---

### Task 1.3: Create the `gpu` module skeleton — constants, error taxonomy, stub backend

Everything in `src/gpu/` that names no Objective-C type. The stub backend is selected
on *every* target in this milestone: `src/gpu/metal.rs` does not exist yet, so there
is nothing for a `metal` feature to select and declaring one now would only produce
an `unexpected_cfgs` warning on every build.

**Files:**
- Create: `/Users/shawnhopkinson/Rust/Vanaddy/src/gpu/mod.rs`
- Create: `/Users/shawnhopkinson/Rust/Vanaddy/src/gpu/selftest.rs`
- Create: `/Users/shawnhopkinson/Rust/Vanaddy/src/gpu/stub.rs`
- Modify: `/Users/shawnhopkinson/Rust/Vanaddy/src/main.rs` (lines 3-4)

**Interfaces:**
- Consumes: `crate::seed::PBKDF2_ROUNDS: u32` (Task 1.1)
- Produces:
  - `pub const WAVE: usize = 8_192;`
  - `pub const BLOCK: usize = 512;`
  - `pub const CHANNEL_CAPACITY: usize = 32;`
  - `pub const ITERS_PER_DISPATCH: u32 = 8;`
  - `pub const DISPATCHES_PER_COMMAND_BUFFER: usize = 4;`
  - `pub const PIPELINE_DEPTH: usize = 3;`
  - `pub const MAX_THREADS_PER_THREADGROUP: usize = 256;`
  - `pub const COMPRESSIONS_PER_SEED: u32 = 4_098;`
  - `pub const AUDITS_PER_WAVE: usize = 4;`
  - `pub enum GpuError { SaltTooLong { len: usize } }` (`Clone + Debug + PartialEq`)
  - `pub enum GpuStatus { Unavailable(String), Ready { device: String }, Initializing, Running { device: String }, Disabled(GpuDisableReason) }`
  - `pub enum GpuDisableReason { .. }`
  - `pub enum SelfTestError { .. }` (in `crate::gpu::selftest`, re-exported as `crate::gpu::SelfTestError`)
  - `pub fn probe() -> GpuStatus` (a *free* function in the stub backend, re-exported
    from `crate::gpu` by `pub use backend::{probe, GpuEngine};` — the design spec's
    `mod.rs` form, written this way from the start so milestone 3 has no module-level
    wrapper to delete. Note the brace order: rustfmt sorts the spec's literal
    `{GpuEngine, probe}` to `{probe, GpuEngine}`, and Task 1.8 Step 6 requires
    `src/gpu/mod.rs` to be rustfmt-clean.)
  - `impl GpuEngine { pub fn probe() -> GpuStatus }` (stub backend; delegates to the
    free `probe()`, so the two spellings can never diverge and Step 1's test can go on
    asserting `probe() == GpuEngine::probe()` unchanged)

- [ ] **Step 1: Create `src/gpu/mod.rs` containing only the failing tests.** Write exactly this file to `/Users/shawnhopkinson/Rust/Vanaddy/src/gpu/mod.rs`:

```rust
//! GPU offload of BIP-39 PBKDF2-HMAC-SHA512 (c = 2048, salt "mnemonic", dkLen = 64).

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wave_geometry_is_self_consistent() {
        // The producer carves a wave into whole blocks; a remainder would mean
        // either dropped candidates or a short final block.
        assert!(WAVE.is_multiple_of(BLOCK));
        assert_eq!(WAVE / BLOCK, 16);
        // The channel holds exactly two waves of blocks.
        assert_eq!(CHANNEL_CAPACITY, 2 * (WAVE / BLOCK));

        // U_1 comes from the prologue, so 2047 follow-up iterations remain. At
        // R = 8 that is 255 full dispatches plus a 7-iteration tail = 256, a
        // whole number of 4-dispatch command buffers.
        let follow_up = crate::seed::PBKDF2_ROUNDS - 1;
        assert_eq!(follow_up, 2047);
        let dispatches = follow_up.div_ceil(ITERS_PER_DISPATCH) as usize;
        assert_eq!(dispatches, 256);
        assert!(dispatches.is_multiple_of(DISPATCHES_PER_COMMAND_BUFFER));
        assert_eq!(PIPELINE_DEPTH, 3);

        // 2 prologue compressions (ipad, opad) + 2 for U_1 + 2 per follow-up.
        assert_eq!(COMPRESSIONS_PER_SEED, 2 + 2 + 2 * follow_up);

        // A block must tile the threadgroup clamp exactly.
        assert!(BLOCK.is_multiple_of(MAX_THREADS_PER_THREADGROUP));
        assert_eq!(AUDITS_PER_WAVE, 4);
        const { assert!(AUDITS_PER_WAVE < WAVE) };
    }

    #[test]
    fn stub_backend_reports_unavailable() {
        match GpuEngine::probe() {
            GpuStatus::Unavailable(reason) => assert!(!reason.is_empty()),
            other => panic!("stub backend must never report a usable GPU, got {other:?}"),
        }
        assert_eq!(probe(), GpuEngine::probe());
    }
}
```

- [ ] **Step 2: Declare the module.** In `/Users/shawnhopkinson/Rust/Vanaddy/src/main.rs`, replace lines 3-4:

```rust
pub mod chains;
pub mod matcher;
```

with:

```rust
pub mod chains;
pub mod gpu;
pub mod matcher;
```

- [ ] **Step 3: Run it and watch it fail to compile.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo test wave_geometry_is_self_consistent
```

Expected output contains:

```
error[E0425]: cannot find value `WAVE` in this scope
error[E0425]: cannot find value `BLOCK` in this scope
error[E0425]: cannot find value `CHANNEL_CAPACITY` in this scope
```

- [ ] **Step 4: Create `src/gpu/selftest.rs`.** `GpuDisableReason::SelfTest` carries this
type, so it has to exist before `mod.rs` compiles. The injectable `self_test` checker
itself arrives in milestone 3, in this same file. Write exactly:

```rust
//! GPU self-test fault taxonomy. Milestone 3 adds the injectable `self_test`
//! checker itself; this milestone defines only the error type, because
//! `GpuDisableReason::SelfTest` carries it.

#[derive(Debug, Clone, PartialEq)]
pub enum SelfTestError {
    WrongLength {
        got: usize,
        want: usize,
    },
    CanonicalVectorMismatch {
        got: String,
    },
    RingMismatch {
        index: usize,
        phrase: String,
        got: String,
        want: String,
    },
    AllZero {
        index: usize,
    },
    /// 0xA5 survived -> the kernel never wrote this slot.
    Poisoned {
        index: usize,
    },
    ScheduleDivergence {
        schedule: &'static str,
        index: usize,
    },
    /// The freshly generated phrases were not all distinct -> an RNG fault, not
    /// a GPU fault, but equally disqualifying. Only milestone 3's self-test
    /// raises it; it is declared here so that milestone's rewrite of this file
    /// cannot diverge from the taxonomy milestone 1 published.
    DuplicateEntropy {
        distinct: usize,
        want: usize,
    },
    Backend(String),
}
```

- [ ] **Step 5: Create `src/gpu/stub.rs`.** The uninhabited `GpuEngine` below is a
**placeholder only**: Task 3.3 Step 5 overwrites this whole file and deletes it, and
Milestone 4 Task 4.7 Step 6 replaces it with a *constructible* unit struct
(`pub struct GpuEngine;` whose `start` raises `GpuDisableReason::NotSupported`), which
is the form the rest of the plan depends on — do not restore the uninhabited form at
Task 4.7. Write exactly:

```rust
//! No-op GPU backend. Compiled on every target that is not Apple Silicon with
//! the `metal` feature - and, until milestone 3 lands `metal.rs`, on every
//! target full stop. Zero dependencies, no Objective-C, no threads.

use super::GpuStatus;
use std::convert::Infallible;

/// The backend's probe entry point, as a *free* function: `src/gpu/mod.rs`
/// re-exports this one as `crate::gpu::probe`, which is the design spec's
/// `mod.rs` form (`pub use backend::{GpuEngine, probe};`). Milestone 3 swaps
/// this file for `metal.rs`, which defines the same free function, so the
/// re-export never changes shape.
pub fn probe() -> GpuStatus {
    GpuStatus::Unavailable("no Metal backend in this build".to_string())
}

/// Uninhabited by construction: on a target with no backend, a live engine must
/// be *impossible*, not merely unused. Every method below is therefore
/// statically unreachable and needs no panic.
pub struct GpuEngine {
    _never: Infallible,
}

impl GpuEngine {
    /// Delegates to the free `probe()` above. `self::` is the module path, not
    /// `Self::`, so this resolves to that function and is not recursion.
    pub fn probe() -> GpuStatus {
        self::probe()
    }

    pub fn status(&self) -> GpuStatus {
        match self._never {}
    }

    pub fn signal_stop(&self) {
        match self._never {}
    }

    pub fn is_finished(&self) -> bool {
        match self._never {}
    }

    pub fn reap(self) {
        match self._never {}
    }
}
```

(`match self._never {}` is an exhaustive match on an uninhabited type — it type-checks
as `!` and coerces to any return type, so these are unreachable *without* a panic.
`Infallible` is `Copy`, so matching through `&self` is a copy, not a move.
There is deliberately **no** `GpuEngine::start` on this placeholder: Task 3.3 Step 5
overwrites this file wholesale, and Milestone 4 Task 4.7 Step 6 is where the stub's
constructible `GpuEngine` and its `start` actually land.)

- [ ] **Step 6: Fill in `src/gpu/mod.rs` above the test module.** Replace the single
doc-comment line at the top of `/Users/shawnhopkinson/Rust/Vanaddy/src/gpu/mod.rs`
with everything below, leaving the `#[cfg(test)] mod tests { .. }` block from Step 1
untouched at the bottom:

```rust
//! GPU offload of BIP-39 PBKDF2-HMAC-SHA512 (c = 2048, salt "mnemonic", dkLen = 64).
//! Apple Silicon + Metal only; every other target builds `stub.rs`.
//! The GPU is a *seed accelerator*: never a source of entropy, never a source of
//! truth. Every GPU-sourced match is re-derived with `ring` before it can exist.

// Nothing outside this module consumes it yet - `App` and `main()` wire it up in
// milestone 6. Remove this attribute then.
#![allow(dead_code)]

pub mod selftest;

pub use selftest::SelfTestError;

// Milestone 3 replaces the line below with the spec's two `cfg_attr`s:
//     #[cfg_attr(all(target_os="macos", target_arch="aarch64", feature="metal"), path = "metal.rs")]
//     #[cfg_attr(not(all(target_os="macos", target_arch="aarch64", feature="metal")), path = "stub.rs")]
// Until `metal.rs` exists there is nothing for a `metal` feature to select, so
// declaring the feature now would only add an `unexpected_cfgs` warning.
#[path = "stub.rs"]
mod backend;

/// `main()` probes through the module, not the type, so milestone 6 does not
/// have to know which backend it got. This is the design spec's `mod.rs` form
/// (`pub use backend::{GpuEngine, probe};`) written from the start - rustfmt
/// sorts the braces to `{probe, GpuEngine}` - so milestone 3 only has to widen
/// `mod backend;` to `pub mod backend;` and swap the `#[path]` for the two
/// `cfg_attr`s. It never has to delete a wrapper.
pub use backend::{probe, GpuEngine};

pub const WAVE: usize = 8_192; // candidates per GPU wave
pub const BLOCK: usize = 512; // candidates per channel message (16/wave)
pub const CHANNEL_CAPACITY: usize = 32; // 2 waves of blocks
pub const ITERS_PER_DISPATCH: u32 = 8; // 2047 = 255*8 + 7 -> 256 dispatches
pub const DISPATCHES_PER_COMMAND_BUFFER: usize = 4; // -> 8.8 ms per command buffer
pub const PIPELINE_DEPTH: usize = 3; // command buffers in flight, within a wave
pub const MAX_THREADS_PER_THREADGROUP: usize = 256; // 384 measured 13% SLOWER on M1
pub const COMPRESSIONS_PER_SEED: u32 = 4_098; // 2 + 2 + 2*2047
pub const AUDITS_PER_WAVE: usize = 4; // RANDOM indices, not a fixed stride

/// Every fallible host-side GPU operation funnels through this. `Clone + Debug +
/// PartialEq` so a test can assert on the exact variant and a `GpuDisableReason`
/// carrying one can be rendered in the stats pane.
#[derive(Clone, Debug, PartialEq)]
pub enum GpuError {
    /// `salt.len() > pbkdf2_lanes::MAX_SALT_LEN`: `salt || INT(1) || 0x80 || len`
    /// would not fit the single 128-byte block the kernel is built around.
    SaltTooLong { len: usize },
}

#[derive(Clone, Debug, PartialEq)]
pub enum GpuStatus {
    /// not aarch64-macos, no device, or --no-default-features
    Unavailable(String),
    /// `probe()` succeeded: a device exists, but no GPU thread has been started
    /// yet. This is the pre-search resting state and the one `gpu_effective()`
    /// checks before `start_search` spawns the producer.
    Ready {
        device: String,
    },
    /// thread spawned; compiling + self-testing
    Initializing,
    Running {
        device: String,
    },
    /// sticky for the process
    Disabled(GpuDisableReason),
}

#[derive(Clone, Debug, PartialEq)]
pub enum GpuDisableReason {
    NotSupported,
    NoDevice,
    UserOff,
    ShaderCompile(String),
    PipelineCreate(String),
    BufferAlloc,
    BadConfig(String),
    SelfTest(SelfTestError),
    /// Command buffer status != Completed, or error() was set.
    CommandBuffer {
        status: i64,
        message: String,
    },
    /// The in-wave random ring audit disagreed.
    AuditMismatch {
        index: usize,
    },
    /// A GPU-sourced candidate that MATCHED failed the verify gate.
    VerifyMismatch {
        address: String,
    },
    Panicked,
}
```

- [ ] **Step 7: Run the tests and watch them pass.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo test
```

Expected: `test result: ok. 67 passed; 0 failed`, including
`gpu::tests::wave_geometry_is_self_consistent` and
`gpu::tests::stub_backend_reports_unavailable`.

- [ ] **Step 8: Format the new files and confirm clippy is silent on them.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && rustfmt --edition 2021 src/gpu/mod.rs src/gpu/selftest.rs src/gpu/stub.rs && cargo clippy --all-targets 2>&1 | grep -- '--> src/gpu/' ; echo "gpu-diagnostics-exit=$?"
```

Expected: `gpu-diagnostics-exit=1` (grep found nothing).

- [ ] **Step 9: Commit.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && git add src/gpu/mod.rs src/gpu/selftest.rs src/gpu/stub.rs src/main.rs && git commit -F - <<'MSG'
feat(gpu): add portable gpu module skeleton with the stub backend

Wave geometry constants, the GpuError/GpuStatus/GpuDisableReason/
SelfTestError taxonomy, and an uninhabited stub GpuEngine selected on
every target. No Metal, no threads, no Objective-C. The geometry test
pins the 2047 = 255*8 + 7 dispatch arithmetic against seed::PBKDF2_ROUNDS.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
MSG
```

---

### Task 1.4: `GpuCandidate`, `SeedBlock` and the `crossbeam-channel` transport

The payload that crosses from the GPU thread to the Rayon workers. It carries the
16-byte **entropy**, not the phrase: the worker rebuilds the phrase itself with
`Mnemonic::from_entropy`, so the `String` written to the CSV is always produced by
trusted CPU code. `SeedBlock` deliberately exposes no reordering API — the
phrase↔seed pairing is established by exactly one zip in the producer (milestone 4)
and must never be re-ordered, filtered or sorted afterwards (spec invariant 4).

`crossbeam-channel` rather than `std::sync::mpsc`: `mpsc::Receiver` is `!Sync`, so it
cannot be shared across Rayon workers at all, and the `Arc<Mutex<Receiver>>` +
`try_lock().ok()?` alternative makes a poisoned mutex indistinguishable from "nothing
ready" — one panicking worker would silently disable the GPU forever while the
producer kept filling the queue. The dependency is declared **unconditionally**, not
target-gated, so `search_hybrid`'s signature stays platform-independent.

**Files:**
- Modify: `/Users/shawnhopkinson/Rust/Vanaddy/Cargo.toml` (after line 27)
- Modify: `/Users/shawnhopkinson/Rust/Vanaddy/src/gpu/mod.rs` (add types after the `GpuDisableReason` enum; add three tests)

**Interfaces:**
- Produces:
  - `#[derive(Clone, Copy, Zeroize)] #[repr(C)] pub struct GpuCandidate { pub entropy: [u8; 16], pub seed: [u8; 64] }`
  - `#[derive(Zeroize, ZeroizeOnDrop)] pub struct SeedBlock(Vec<GpuCandidate>)`
  - `impl SeedBlock { pub(crate) fn with_capacity(n: usize) -> Self; pub(crate) fn push(&mut self, candidate: GpuCandidate); pub fn len(&self) -> usize; pub fn is_empty(&self) -> bool; pub fn chunks(&self, n: usize) -> std::slice::Chunks<'_, GpuCandidate> }`
  - `pub type GpuRx = crossbeam_channel::Receiver<Box<SeedBlock>>;`
- Consumes: `zeroize` 1.8 with the `derive` feature (already in `Cargo.toml:27`), `crossbeam-channel` 0.5

- [ ] **Step 1: Add the dependency.** In `/Users/shawnhopkinson/Rust/Vanaddy/Cargo.toml`, append one line directly after line 27 (`zeroize = { version = "1.8", features = ["derive"] }`) so the `[dependencies]` table ends:

```toml
zeroize = { version = "1.8", features = ["derive"] }
crossbeam-channel = "0.5"
```

(`zeroize` with `derive` is already present — do not add it again. `crossbeam-utils`
is already in `Cargo.lock` via rayon, so this resolves to exactly one new crate,
`crossbeam-channel` 0.5.16.)

- [ ] **Step 2: Write the three failing tests.** In
`/Users/shawnhopkinson/Rust/Vanaddy/src/gpu/mod.rs`, inside `mod tests`, append after
`fn stub_backend_reports_unavailable`:

```rust
    #[test]
    fn seed_block_preserves_order_and_chunks_without_reordering() {
        let mut b = SeedBlock::with_capacity(BLOCK);
        assert!(b.is_empty());
        for i in 0..BLOCK {
            b.push(GpuCandidate {
                entropy: [i as u8; 16],
                seed: [(i / 2) as u8; 64],
            });
        }
        assert_eq!(b.len(), BLOCK);
        assert_eq!(b.chunks(64).count(), 8);
        let flat: Vec<u8> = b
            .chunks(64)
            .flat_map(|c| c.iter().map(|x| x.entropy[0]))
            .collect();
        let want: Vec<u8> = (0..BLOCK).map(|i| i as u8).collect();
        assert_eq!(flat, want);
        assert_eq!(b.chunks(64).nth(1).unwrap()[0].seed, [32u8; 64]);
    }

    #[test]
    fn seed_block_zeroizes_its_candidates() {
        let mut b = SeedBlock::with_capacity(2);
        b.push(GpuCandidate {
            entropy: [0xAB; 16],
            seed: [0xCD; 64],
        });
        b.push(GpuCandidate {
            entropy: [0xEF; 16],
            seed: [0x12; 64],
        });
        b.zeroize();
        assert_eq!(b.len(), 0);
        assert!(b.is_empty());
    }

    #[test]
    fn a_seed_block_crosses_a_thread_boundary_through_the_channel() {
        let (tx, rx) = crossbeam_channel::bounded::<Box<SeedBlock>>(CHANNEL_CAPACITY);
        let rx: GpuRx = rx;
        let producer = std::thread::spawn(move || {
            let mut b = SeedBlock::with_capacity(BLOCK);
            for i in 0..BLOCK {
                b.push(GpuCandidate {
                    entropy: [i as u8; 16],
                    seed: [7u8; 64],
                });
            }
            tx.send(Box::new(b)).expect("receiver is alive");
        });
        let got = rx.recv().expect("producer sent one block");
        producer.join().expect("producer thread did not panic");
        assert_eq!(got.len(), BLOCK);
        assert_eq!(got.chunks(64).next().unwrap()[3].entropy, [3u8; 16]);
    }
```

- [ ] **Step 3: Run them and watch them fail to compile.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo test seed_block
```

Expected output contains:

```
error[E0433]: failed to resolve: use of undeclared type `SeedBlock`
```

- [ ] **Step 4: Add the types.** In `/Users/shawnhopkinson/Rust/Vanaddy/src/gpu/mod.rs`,
add this import line directly below `#![allow(dead_code)]` and its comment (above
`pub mod selftest;`):

```rust
use zeroize::{Zeroize, ZeroizeOnDrop};
```

Then insert this block directly after the closing `}` of the `GpuDisableReason` enum
and before the `#[cfg(test)] mod tests`:

```rust
/// One GPU-produced candidate. POD + Copy: no allocation on the hot path.
/// `entropy`, not the phrase - the worker rebuilds the phrase itself with
/// `Mnemonic::from_entropy`, so the String written to the CSV is always
/// produced by trusted CPU code.
#[derive(Clone, Copy, Zeroize)]
#[repr(C)]
pub struct GpuCandidate {
    pub entropy: [u8; 16],
    /// UNTRUSTED until re-derived. Used only to *filter*.
    pub seed: [u8; 64],
}

/// A run of candidates handed to one Rayon worker. Deliberately NO mutating API
/// beyond `push` during construction: phrase <-> seed pairing is established by
/// exactly one zip in the producer and must never be re-ordered, filtered or
/// sorted afterwards.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SeedBlock(Vec<GpuCandidate>);

impl SeedBlock {
    /// Build-then-freeze: the ONLY way a block gains candidates. Producer and
    /// tests only, hence `pub(crate)` - this is the visibility every downstream
    /// milestone consumes, so it is fixed here and never re-declared. There is
    /// deliberately no `remove`, `sort`, `retain` or `iter_mut`: the entropy
    /// <-> seed pairing established by the single `zip` in the producer must
    /// never be re-ordered afterwards.
    pub(crate) fn with_capacity(n: usize) -> Self {
        SeedBlock(Vec::with_capacity(n))
    }
    pub(crate) fn push(&mut self, candidate: GpuCandidate) {
        self.0.push(candidate);
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    pub fn chunks(&self, n: usize) -> std::slice::Chunks<'_, GpuCandidate> {
        self.0.chunks(n)
    }
}

pub type GpuRx = crossbeam_channel::Receiver<Box<SeedBlock>>;

/// `App` owns a `GpuEngine` and hands `SeedBlock`s to Rayon workers, so a
/// refactor that smuggled an Objective-C type into either must fail to compile
/// here rather than at the point of use.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<GpuEngine>();
    assert_send_sync::<SeedBlock>();
};
```

- [ ] **Step 5: Run the tests and watch them pass.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo test
```

Expected: `test result: ok. 70 passed; 0 failed`, including
`gpu::tests::a_seed_block_crosses_a_thread_boundary_through_the_channel`.

- [ ] **Step 6: Confirm `Cargo.lock` picked up exactly one crate.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && git diff --stat Cargo.lock && grep -A2 'name = "crossbeam-channel"' Cargo.lock
```

Expected: `Cargo.lock` shows a small addition, and the grep prints
`version = "0.5.16"` (or newer 0.5.x).

- [ ] **Step 7: Format and check clippy.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && rustfmt --edition 2021 src/gpu/mod.rs && cargo clippy --all-targets 2>&1 | grep -- '--> src/gpu/' ; echo "gpu-diagnostics-exit=$?"
```

Expected: `gpu-diagnostics-exit=1`.

- [ ] **Step 8: Commit.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && git add Cargo.toml Cargo.lock src/gpu/mod.rs && git commit -F - <<'MSG'
feat(gpu): add GpuCandidate, SeedBlock and the crossbeam transport

SeedBlock is ZeroizeOnDrop and exposes no reordering API, so the single
zip that pairs entropy with seeds in the producer cannot be undone
downstream. crossbeam-channel rather than mpsc: mpsc::Receiver is !Sync
and the Arc<Mutex<..>> workaround makes a poisoned lock look identical
to an empty queue. A const _ assertion pins GpuEngine and SeedBlock as
Send + Sync so no Objective-C type can be smuggled into App later.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
MSG
```

---

### Task 1.5: `GpuHealth`

The one place a GPU fault is recorded. **Never a `Mutex`**: `drain_matches` reads this
from the render loop every 100 ms, and a worker that panicked while holding a mutex
would poison it and turn a GPU fault into a UI-thread `unwrap` panic inside raw mode
with the alternate screen still active. `OnceLock` is set-once and cannot be poisoned,
so the *first* fault is the one reported — a later derivative failure (the producer
noticing `disable` and exiting) must not overwrite the root cause.

The stub backend gets **no** `start` in this milestone. Nothing between here and
Task 3.3 calls it; Task 3.3 Step 5 overwrites `src/gpu/stub.rs` wholesale; and
Milestone 4 Task 4.7 Step 6 is where the stub's real, *constructible* `GpuEngine`
lands — the one Task 8.4 Step 1's lifecycle test exercises. Adding an
`unreachable!()` `start` here would only be deleted twice over.

**Files:**
- Modify: `/Users/shawnhopkinson/Rust/Vanaddy/src/gpu/mod.rs` (add imports, `GpuHealth`, extend the `const _` assertion, add three tests)

**Interfaces:**
- Consumes: `pub struct SeedBlock` (Task 1.4), `pub enum GpuDisableReason` (Task 1.3)
- Produces:
  - `pub struct GpuHealth { pub disable: AtomicBool, reason: OnceLock<GpuDisableReason>, pub seeds_delivered: AtomicU64, pub blocks_dropped: AtomicU64, pub verify_rejections: AtomicU64 }`
  - `impl GpuHealth { pub fn new() -> Self; pub fn raise(&self, r: GpuDisableReason); pub fn take_reason(&self) -> Option<GpuDisableReason> }`
  - `impl Default for GpuHealth`

- [ ] **Step 1: Write the three failing tests.** In
`/Users/shawnhopkinson/Rust/Vanaddy/src/gpu/mod.rs`, inside `mod tests`, append after
`fn a_seed_block_crosses_a_thread_boundary_through_the_channel`:

```rust
    #[test]
    fn raise_records_the_first_reason_and_never_overwrites_it() {
        let h = GpuHealth::new();
        assert!(!h.disable.load(Ordering::Relaxed));
        assert_eq!(h.take_reason(), None);
        h.raise(GpuDisableReason::AuditMismatch { index: 5183 });
        h.raise(GpuDisableReason::Panicked);
        assert!(h.disable.load(Ordering::Relaxed));
        assert_eq!(
            h.take_reason(),
            Some(GpuDisableReason::AuditMismatch { index: 5183 })
        );
    }

    #[test]
    fn take_reason_does_not_consume_the_reason() {
        let h = GpuHealth::new();
        h.raise(GpuDisableReason::NoDevice);
        assert_eq!(h.take_reason(), Some(GpuDisableReason::NoDevice));
        assert_eq!(h.take_reason(), Some(GpuDisableReason::NoDevice));
    }

    #[test]
    fn health_counters_add_across_threads_through_an_arc() {
        let h = Arc::new(GpuHealth::default());
        let mut handles = Vec::new();
        for _ in 0..4 {
            let h = Arc::clone(&h);
            handles.push(std::thread::spawn(move || {
                for _ in 0..1_000 {
                    h.seeds_delivered.fetch_add(1, Ordering::Relaxed);
                }
            }));
        }
        for t in handles {
            t.join().expect("counter thread did not panic");
        }
        assert_eq!(h.seeds_delivered.load(Ordering::Relaxed), 4_000);
        assert_eq!(h.blocks_dropped.load(Ordering::Relaxed), 0);
        assert_eq!(h.verify_rejections.load(Ordering::Relaxed), 0);
        assert!(!h.disable.load(Ordering::Relaxed));
    }
```

and add this line at the top of `mod tests`, directly under `use super::*;`:

```rust
    use std::sync::Arc;
```

- [ ] **Step 2: Run them and watch them fail to compile.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo test raise_records_the_first_reason
```

Expected output contains:

```
error[E0433]: failed to resolve: use of undeclared type `GpuHealth`
```

- [ ] **Step 3: Add the imports.** In `/Users/shawnhopkinson/Rust/Vanaddy/src/gpu/mod.rs`,
directly above the existing `use zeroize::{Zeroize, ZeroizeOnDrop};` line, add:

```rust
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::OnceLock;
```

- [ ] **Step 4: Add `GpuHealth`.** In the same file, insert this block directly after
`pub type GpuRx = crossbeam_channel::Receiver<Box<SeedBlock>>;` and before the
`const _: fn() = || { .. };` assertion:

```rust
/// Shared, lock-free-on-the-read-path health cell. Never a `Mutex` on the UI
/// path: `drain_matches` reads this from the render loop every 100 ms, and a
/// worker that panicked while holding a `Mutex` would poison it and turn a GPU
/// fault into a UI-thread `unwrap` panic inside raw mode.
pub struct GpuHealth {
    pub disable: AtomicBool,
    /// Set-once, so the FIRST fault is the one reported. A later, derivative
    /// failure (the producer noticing `disable` and exiting) must not overwrite
    /// the root cause. `OnceLock` also cannot be poisoned.
    reason: OnceLock<GpuDisableReason>,
    pub seeds_delivered: AtomicU64,
    pub blocks_dropped: AtomicU64,
    pub verify_rejections: AtomicU64,
}

impl GpuHealth {
    pub fn new() -> Self {
        GpuHealth {
            disable: AtomicBool::new(false),
            reason: OnceLock::new(),
            seeds_delivered: AtomicU64::new(0),
            blocks_dropped: AtomicU64::new(0),
            verify_rejections: AtomicU64::new(0),
        }
    }

    /// Publish the reason BEFORE flipping the flag. Readers load `disable`
    /// Relaxed, so a reader can still observe `disable == true` one instant
    /// before `take_reason()` is `Some`; callers must treat `None` as "not yet"
    /// and re-read on the next tick, never as "no reason".
    pub fn raise(&self, r: GpuDisableReason) {
        let _ = self.reason.set(r);
        self.disable.store(true, Ordering::Release);
    }

    /// Clones; does NOT consume. Never unwraps a lock. Named `take_reason` per
    /// the design spec even though it leaves the reason in place - the UI reads
    /// it on every 100 ms tick.
    pub fn take_reason(&self) -> Option<GpuDisableReason> {
        self.reason.get().cloned()
    }
}

impl Default for GpuHealth {
    fn default() -> Self {
        GpuHealth::new()
    }
}
```

- [ ] **Step 5: Extend the Send+Sync assertion.** In the same file, replace the
`const _: fn() = || { .. };` block with:

```rust
/// `App` owns a `GpuEngine` and hands `SeedBlock`s to Rayon workers, so a
/// refactor that smuggled an Objective-C type into either must fail to compile
/// here rather than at the point of use.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<GpuEngine>();
    assert_send_sync::<SeedBlock>();
    assert_send_sync::<GpuHealth>();
};
```

- [ ] **Step 6: Run the tests and watch them pass.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo test
```

Expected: `test result: ok. 73 passed; 0 failed`, including
`gpu::tests::raise_records_the_first_reason_and_never_overwrites_it`.

- [ ] **Step 7: Format and check clippy.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && rustfmt --edition 2021 src/gpu/mod.rs && cargo clippy --all-targets 2>&1 | grep -- '--> src/gpu/' ; echo "gpu-diagnostics-exit=$?"
```

Expected: `gpu-diagnostics-exit=1`. (`GpuHealth::new()` needs the `Default` impl added
in Step 4 — without it clippy's `new_without_default` fires here. `src/gpu/stub.rs` is
untouched by this task, so it is not in the rustfmt list.)

- [ ] **Step 8: Commit.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && git add src/gpu/mod.rs && git commit -F - <<'MSG'
feat(gpu): add GpuHealth, the set-once fault cell

OnceLock rather than Mutex: the UI thread reads this every 100 ms inside
raw mode, and a poisoned lock would turn a GPU fault into a UI-thread
panic. Set-once means the first fault is the reported one, never the
derivative failure that follows it. The stub backend deliberately gets no
GpuEngine::start here: Task 3.3 overwrites stub.rs wholesale and Task 4.7
lands the real, constructible one.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
MSG
```

---

### Task 1.6: `pack_key_block` — the HMAC key block, and the proof its assert is unreachable

The kernel contains **zero endianness code and zero padding code**: every byte-level
decision lives here in Rust, where it is testable with no GPU. `pack_key_block`'s
`assert!` is a hard assert, not a `debug_assert!`, because a longer key would be
silently zero-padded by the GPU instead of SHA-512 pre-hashed (the CPU reference
pre-hashes at `src/pbkdf2_lanes.rs:244`), producing a wrong-but-plausible seed — an
address that looks right and leads to a wallet nobody controls.

The assert is only *safe* if a real 12-word English phrase can never reach it. The
English BIP-39 wordlist has 3-letter minimum and 8-letter maximum words, so
`12*3 + 11 = 47` and `12*8 + 11 = 107`, both below 128. The last test in this task
samples 4,096 real phrases to hold that claim honest.

**Files:**
- Create: `/Users/shawnhopkinson/Rust/Vanaddy/src/gpu/pack.rs`
- Modify: `/Users/shawnhopkinson/Rust/Vanaddy/src/gpu/mod.rs` (add `pub mod pack;`)

**Interfaces:**
- Consumes: `crate::pbkdf2_lanes::HMAC_BLOCK_LEN: usize` (Task 1.2)
- Produces:
  - `#[repr(C, align(16))] #[derive(Clone, Copy, Zeroize)] pub struct KeyBlock(pub [u64; 16])`
  - `pub fn pack_key_block(password: &[u8]) -> KeyBlock`

- [ ] **Step 1: Create `src/gpu/pack.rs` with the failing tests only.** Write exactly this
file to `/Users/shawnhopkinson/Rust/Vanaddy/src/gpu/pack.rs`:

```rust
//! Host-side packing of PBKDF2 inputs into the exact 16-word big-endian blocks
//! the Metal kernel consumes. Every byte-level decision - zero padding, INT(1),
//! the 0x80 terminator, the 128-bit length field, endianness - lives here in
//! Rust, where it is testable with no GPU. The kernel therefore contains zero
//! endianness code and zero padding code.

#[cfg(test)]
mod tests {
    use super::*;
    use bip39::{Language, Mnemonic, MnemonicType};

    const CANONICAL: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn words_to_bytes(words: &[u64; 16]) -> [u8; 128] {
        let mut out = [0u8; 128];
        for (i, w) in words.iter().enumerate() {
            out[8 * i..8 * i + 8].copy_from_slice(&w.to_be_bytes());
        }
        out
    }

    #[test]
    fn pack_key_block_is_big_endian_for_the_canonical_phrase() {
        assert_eq!(CANONICAL.len(), 93);
        let k = pack_key_block(CANONICAL.as_bytes());
        // "abandon " == 61 62 61 6e 64 6f 6e 20, eleven times.
        for w in k.0.iter().take(11) {
            assert_eq!(*w, 0x6162_616e_646f_6e20);
        }
        // "about" then the zero pad: 61 62 6f 75 74 00 00 00.
        assert_eq!(k.0[11], 0x6162_6f75_7400_0000);
        for w in k.0.iter().skip(12) {
            assert_eq!(*w, 0);
        }
    }

    #[test]
    fn pack_key_block_round_trips_to_the_zero_padded_password() {
        for len in [1usize, 7, 8, 9, 47, 63, 64, 65, 93, 107, 127, 128] {
            let pw: Vec<u8> = (0..len).map(|i| (i % 251) as u8 | 1).collect();
            let bytes = words_to_bytes(&pack_key_block(&pw).0);
            assert_eq!(&bytes[..len], pw.as_slice(), "len {len}");
            assert!(bytes[len..].iter().all(|&x| x == 0), "len {len} pad");
        }
    }

    #[test]
    #[should_panic(expected = "GPU PBKDF2 key must be 1..=128 bytes (no pre-hash path), got 129")]
    fn pack_key_block_rejects_a_password_over_the_hmac_block() {
        let pw = [0x61u8; 129];
        let _ = pack_key_block(&pw);
    }

    #[test]
    #[should_panic(expected = "GPU PBKDF2 key must be 1..=128 bytes (no pre-hash path), got 0")]
    fn pack_key_block_rejects_an_empty_password() {
        let _ = pack_key_block(b"");
    }

    /// The hard assert above is only safe if a real 12-word English phrase can
    /// never reach it. Shortest English BIP-39 word is 3 letters, longest is 8,
    /// so 12*3+11 = 47 and 12*8+11 = 107, both below HMAC_BLOCK_LEN = 128.
    #[test]
    fn every_english_12_word_phrase_fits_one_key_block() {
        for _ in 0..4_096 {
            let m = Mnemonic::new(MnemonicType::Words12, Language::English);
            let phrase = m.phrase().as_bytes();
            assert!(
                (47..=107).contains(&phrase.len()),
                "12-word phrase out of the proven range: {} bytes, {:?}",
                phrase.len(),
                m.phrase()
            );
            assert!(phrase.len() < crate::pbkdf2_lanes::HMAC_BLOCK_LEN);
            let bytes = words_to_bytes(&pack_key_block(phrase).0);
            assert_eq!(&bytes[..phrase.len()], phrase);
            assert!(bytes[phrase.len()..].iter().all(|&x| x == 0));
        }
    }

    /// The kernel builds ipad/opad on the GPU from this packed key block, so the
    /// packed block must reproduce EXACTLY what `hw::pbkdf2_lanes` XORs into
    /// `ipad`/`opad` (src/pbkdf2_lanes.rs:251-252 after Task 1.2's edit; 243-244
    /// before it). This is the spec's `pack_key_block_matches_reference_ipad_opad`
    /// no-GPU test: without it nothing in milestones 1-2 catches a key-block vs
    /// HMAC-key-schedule divergence.
    #[test]
    fn pack_key_block_matches_the_cpu_ipad_and_opad_blocks() {
        let long_key = [0x5cu8; 107];
        let full_key = [0x36u8; 128];
        let cases: [&[u8]; 4] = [CANONICAL.as_bytes(), b"a", &long_key, &full_key];
        for pw in cases {
            // What the CPU does: start from the pad constant, XOR the key in.
            let mut cpu_ipad = [0x36u8; 128];
            let mut cpu_opad = [0x5cu8; 128];
            for (i, &kb) in pw.iter().enumerate() {
                cpu_ipad[i] ^= kb;
                cpu_opad[i] ^= kb;
            }
            // What the GPU does: XOR the pad constant over the packed block.
            let packed = words_to_bytes(&pack_key_block(pw).0);
            let gpu_ipad: [u8; 128] = std::array::from_fn(|i| packed[i] ^ 0x36);
            let gpu_opad: [u8; 128] = std::array::from_fn(|i| packed[i] ^ 0x5c);
            assert_eq!(gpu_ipad, cpu_ipad, "ipad diverges, {}-byte key", pw.len());
            assert_eq!(gpu_opad, cpu_opad, "opad diverges, {}-byte key", pw.len());
        }
    }
}
```

- [ ] **Step 2: Declare the submodule.** In
`/Users/shawnhopkinson/Rust/Vanaddy/src/gpu/mod.rs`, change:

```rust
pub mod selftest;
```

to:

```rust
pub mod pack;
pub mod selftest;
```

- [ ] **Step 3: Run the tests and watch them fail to compile.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo test pack_key_block
```

Expected output contains:

```
error[E0425]: cannot find function `pack_key_block` in this scope
```

- [ ] **Step 4: Implement `KeyBlock` and `pack_key_block`.** In
`/Users/shawnhopkinson/Rust/Vanaddy/src/gpu/pack.rs`, insert this between the module
doc comment and the `#[cfg(test)] mod tests` block:

```rust
use zeroize::Zeroize;

/// One zero-padded HMAC key block, decoded to 16 big-endian u64 words.
#[repr(C, align(16))]
#[derive(Clone, Copy, Zeroize)]
pub struct KeyBlock(pub [u64; 16]);

/// Hard assert, NOT debug_assert: a longer key would be silently zero-padded by
/// the GPU instead of SHA-512 pre-hashed (the CPU reference pre-hashes at
/// src/pbkdf2_lanes.rs:244), producing a wrong-but-plausible seed.
/// A 12-word English phrase is provably 47..=107 bytes.
pub fn pack_key_block(password: &[u8]) -> KeyBlock {
    assert!(
        !password.is_empty() && password.len() <= crate::pbkdf2_lanes::HMAC_BLOCK_LEN,
        "GPU PBKDF2 key must be 1..={} bytes (no pre-hash path), got {}",
        crate::pbkdf2_lanes::HMAC_BLOCK_LEN,
        password.len()
    );
    let mut b = [0u8; 128];
    b[..password.len()].copy_from_slice(password);
    let packed = KeyBlock(std::array::from_fn(|i| {
        u64::from_be_bytes(b[8 * i..8 * i + 8].try_into().unwrap())
    }));
    // `b` held the plaintext seed phrase; do not leave it on the stack.
    b.zeroize();
    packed
}
```

- [ ] **Step 5: Run the tests and watch them pass.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo test gpu::pack
```

Expected: `test result: ok. 6 passed; 0 failed`, listing
`gpu::pack::tests::every_english_12_word_phrase_fits_one_key_block`,
`..::pack_key_block_is_big_endian_for_the_canonical_phrase`,
`..::pack_key_block_matches_the_cpu_ipad_and_opad_blocks`,
`..::pack_key_block_rejects_a_password_over_the_hmac_block`,
`..::pack_key_block_rejects_an_empty_password`,
`..::pack_key_block_round_trips_to_the_zero_padded_password`.

- [ ] **Step 6: Run the whole suite.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo test
```

Expected: `test result: ok. 79 passed; 0 failed`.

- [ ] **Step 7: Format and check clippy.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && rustfmt --edition 2021 src/gpu/pack.rs src/gpu/mod.rs && cargo clippy --all-targets 2>&1 | grep -- '--> src/gpu/' ; echo "gpu-diagnostics-exit=$?"
```

Expected: `gpu-diagnostics-exit=1`.

- [ ] **Step 8: Commit.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && git add src/gpu/pack.rs src/gpu/mod.rs && git commit -F - <<'MSG'
feat(gpu): pack the HMAC key block host-side, big-endian

The kernel gets 16 big-endian u64 words and contains no endianness or
padding code at all. The length bound is a hard assert, not a
debug_assert: an over-long key would be zero-padded on the GPU where the
CPU reference SHA-512 pre-hashes it, yielding a wrong-but-plausible seed.
4096 sampled English 12-word phrases pin that bound as unreachable.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
MSG
```

---

### Task 1.7: `pack_salt_block` — the byte-exact mirror of the CPU's padded block

The GPU's inner HMAC absorbs `K0 ^ ipad` (one 128-byte block) and then exactly one
more block: `salt || INT(1) || 0x80 || zeros || 128-bit-length`. That second block is
what this function builds, and it must be **byte-identical** to what
`hw::pbkdf2_lanes` feeds `compress` at `src/pbkdf2_lanes.rs:259-262`. Fallible rather
than panicking, mirroring the CPU's `MAX_SALT_LEN` assert at
`src/pbkdf2_lanes.rs:21-25`.

**Files:**
- Modify: `/Users/shawnhopkinson/Rust/Vanaddy/src/gpu/pack.rs` (add the function; add the reference helper and four tests)

**Interfaces:**
- Consumes: `crate::pbkdf2_lanes::MAX_SALT_LEN: usize` (Task 1.2), `crate::seed::BIP39_SALT: &[u8; 8]` (Task 1.1), `crate::gpu::GpuError` (Task 1.3)
- Produces: `pub fn pack_salt_block(salt: &[u8]) -> Result<[u64; 16], GpuError>`

- [ ] **Step 1: Write the failing tests.** In
`/Users/shawnhopkinson/Rust/Vanaddy/src/gpu/pack.rs`, inside `mod tests`, append after
`fn pack_key_block_matches_the_cpu_ipad_and_opad_blocks` (the last test in the module
after Task 1.6):

```rust
    /// Literal transcription of `padded_block` (src/pbkdf2_lanes.rs:210-219)
    /// applied to `salted[..salt.len()+4]` exactly as `hw::pbkdf2_lanes` does at
    /// src/pbkdf2_lanes.rs:259-262. If the CPU padding ever changes, this
    /// transcription and `pack_salt_block` must be changed together.
    fn cpu_reference_salt_block(salt: &[u8]) -> [u8; 128] {
        let mut salted = [0u8; 111];
        salted[..salt.len()].copy_from_slice(salt);
        salted[salt.len()..salt.len() + 4].copy_from_slice(&1u32.to_be_bytes());
        let tail = &salted[..salt.len() + 4];
        let prior_len = 128usize;

        let mut block = [0u8; 128];
        block[..tail.len()].copy_from_slice(tail);
        block[tail.len()] = 0x80;
        let bit_len = ((prior_len + tail.len()) as u128) * 8;
        block[112..].copy_from_slice(&bit_len.to_be_bytes());
        block
    }

    #[test]
    fn salt_block_matches_the_cpu_padded_block_byte_for_byte() {
        for len in [0usize, 1, 8, 32, 64, 100, 106, 107] {
            let salt: Vec<u8> = (0..len).map(|i| (i % 251) as u8 | 1).collect();
            let packed = pack_salt_block(&salt).expect("within MAX_SALT_LEN");
            assert_eq!(
                words_to_bytes(&packed),
                cpu_reference_salt_block(&salt),
                "salt len {len}"
            );
        }
    }

    #[test]
    fn salt_block_places_int1_the_terminator_and_the_length_field_correctly() {
        for len in [0usize, 8, 107] {
            let salt: Vec<u8> = (0..len).map(|i| (i % 251) as u8 | 1).collect();
            let bytes = words_to_bytes(&pack_salt_block(&salt).unwrap());
            assert_eq!(&bytes[..len], salt.as_slice());
            assert_eq!(&bytes[len..len + 4], &[0, 0, 0, 1], "INT(1) at len {len}");
            assert_eq!(bytes[len + 4], 0x80, "terminator at len {len}");
            assert!(
                bytes[len + 5..112].iter().all(|&x| x == 0),
                "gap at len {len}"
            );
            // One 128-byte key block has already been absorbed, hence 128 + ..
            assert_eq!(
                u128::from_be_bytes(bytes[112..].try_into().unwrap()),
                ((128 + len + 4) as u128) * 8,
                "length field at len {len}"
            );
        }
    }

    #[test]
    fn salt_block_for_bip39_matches_the_pinned_words() {
        let packed = pack_salt_block(crate::seed::BIP39_SALT).unwrap();
        let want: [u64; 16] = [
            0x6d6e_656d_6f6e_6963, // "mnemonic"
            0x0000_0001_8000_0000, // INT(1) then 0x80
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0x0000_0000_0000_0460, // (128 + 8 + 4) * 8 = 1120 bits
        ];
        assert_eq!(packed, want);
    }

    #[test]
    fn salt_block_rejects_a_salt_longer_than_max_salt_len() {
        const MAX: usize = crate::pbkdf2_lanes::MAX_SALT_LEN;
        assert!(pack_salt_block(&[0x73u8; MAX]).is_ok());
        assert_eq!(
            pack_salt_block(&[0x73u8; MAX + 1]),
            Err(GpuError::SaltTooLong { len: MAX + 1 })
        );
        assert_eq!(
            pack_salt_block(&[0x73u8; 200]),
            Err(GpuError::SaltTooLong { len: 200 })
        );
    }
```

- [ ] **Step 2: Run them and watch them fail to compile.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo test salt_block
```

Expected output contains:

```
error[E0425]: cannot find function `pack_salt_block` in this scope
```

- [ ] **Step 3: Implement `pack_salt_block`.** In
`/Users/shawnhopkinson/Rust/Vanaddy/src/gpu/pack.rs`, add this import directly above
`use zeroize::Zeroize;`:

```rust
use crate::gpu::GpuError;
```

Then insert this function directly after the closing `}` of `pack_key_block` and
before the `#[cfg(test)] mod tests` block:

```rust
/// Byte-exact mirror of `padded_block(&salted[..salt.len()+4], 128)`
/// at src/pbkdf2_lanes.rs:259-262. Fallible, mirroring the CPU's MAX_SALT_LEN
/// assert at src/pbkdf2_lanes.rs:21-25.
pub fn pack_salt_block(salt: &[u8]) -> Result<[u64; 16], GpuError> {
    if salt.len() > crate::pbkdf2_lanes::MAX_SALT_LEN {
        return Err(GpuError::SaltTooLong { len: salt.len() });
    }
    let mut b = [0u8; 128];
    b[..salt.len()].copy_from_slice(salt);
    b[salt.len()..salt.len() + 4].copy_from_slice(&1u32.to_be_bytes()); // INT(1)
    b[salt.len() + 4] = 0x80;
    let bits = ((128 + salt.len() + 4) as u128) * 8;
    b[112..].copy_from_slice(&bits.to_be_bytes());
    Ok(std::array::from_fn(|i| {
        u64::from_be_bytes(b[8 * i..8 * i + 8].try_into().unwrap())
    }))
}
```

- [ ] **Step 4: Run the tests and watch them pass.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo test gpu::pack
```

Expected: `test result: ok. 10 passed; 0 failed`, now also listing
`gpu::pack::tests::salt_block_for_bip39_matches_the_pinned_words`,
`..::salt_block_matches_the_cpu_padded_block_byte_for_byte`,
`..::salt_block_places_int1_the_terminator_and_the_length_field_correctly`,
`..::salt_block_rejects_a_salt_longer_than_max_salt_len`.

- [ ] **Step 5: Run the whole suite.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo test
```

Expected: `test result: ok. 83 passed; 0 failed`.

- [ ] **Step 6: Format and check clippy.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && rustfmt --edition 2021 src/gpu/pack.rs && cargo clippy --all-targets 2>&1 | grep -- '--> src/gpu/' ; echo "gpu-diagnostics-exit=$?"
```

Expected: `gpu-diagnostics-exit=1`. (The `const MAX` + array literals in
`salt_block_rejects_a_salt_longer_than_max_salt_len` are deliberate — a `&vec![..]`
there trips clippy's `useless_vec`.)

- [ ] **Step 7: Commit.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && git add src/gpu/pack.rs && git commit -F - <<'MSG'
feat(gpu): pack the PBKDF2 salt block, byte-exact against the CPU path

salt || INT(1) || 0x80 || zeros || 128-bit length, mirroring
padded_block at src/pbkdf2_lanes.rs:259-262 exactly, and rejecting the
same salts pbkdf2_hmac_sha512 rejects. Tested three ways with no GPU:
against a literal transcription of the CPU padding, against explicit
structural placement assertions, and against the pinned BIP-39 words.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
MSG
```

---

### Task 1.8: Milestone gate — every CI leg green, no drift in the frozen files

The milestone's own acceptance criteria, run as one pass. Nothing here modifies source;
if a check fails, go back and fix the task that caused it.

**Files:**
- Test: `/Users/shawnhopkinson/Rust/Vanaddy/src/gpu/mod.rs`, `/Users/shawnhopkinson/Rust/Vanaddy/src/gpu/pack.rs`, `/Users/shawnhopkinson/Rust/Vanaddy/src/seed.rs`, `/Users/shawnhopkinson/Rust/Vanaddy/src/pbkdf2_lanes.rs`

**Interfaces:**
- Consumes: everything produced by Tasks 1.1-1.7
- Produces: nothing new

- [ ] **Step 1: Full suite, default features.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo test 2>&1 | tail -3
```

Expected: `test result: ok. 83 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out`
(63 pre-existing + 2 constant tests + 18 GPU tests: 2 in Task 1.3, 3 in 1.4, 3 in 1.5,
6 in 1.6, 4 in 1.7).

- [ ] **Step 2: Prove the CPU binary stands alone.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo test --no-default-features 2>&1 | tail -3
```

Expected: `test result: ok. 83 passed; 0 failed`. (No `[features]` table exists yet,
so this is currently a no-op — but it is the CI leg milestone 3 will make meaningful,
and it must be green from here on.)

- [ ] **Step 3: Prove the constants stay live when `mod hw` is not compiled.**
`mod hw` — the only non-GPU consumer of `super::HMAC_BLOCK_LEN` — is
`#[cfg(target_arch = "aarch64")]`. `gpu::pack` references both constants
unconditionally, so neither can become dead on any target. Confirm those references
exist and are not themselves target-gated. No network, no extra toolchain component:

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && grep -c 'pbkdf2_lanes::HMAC_BLOCK_LEN' src/gpu/pack.rs ; grep -c 'pbkdf2_lanes::MAX_SALT_LEN' src/gpu/pack.rs ; grep -c 'cfg(target_arch' src/gpu/pack.rs
```

Expected: three numbers — a non-zero count for `HMAC_BLOCK_LEN`, a non-zero count for
`MAX_SALT_LEN`, then `0` for `cfg(target_arch`.

Optionally, **only if** `rustup target list --installed` already lists
`x86_64-apple-darwin`, also run:

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo check --target x86_64-apple-darwin 2>&1 | tail -3
```

Expected: `Finished \`dev\` profile [unoptimized + debuginfo] target(s)` with no
warning naming `HMAC_BLOCK_LEN` or `MAX_SALT_LEN`. Do **not** run `rustup target add`
to make this runnable: it downloads a toolchain component and fails offline, turning
an environment gap into a milestone-gate failure.

- [ ] **Step 4: Every pinned vector from CLAUDE.md still passes, by name.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && cd /Users/shawnhopkinson/Rust/Vanaddy && cargo test 2>&1 | grep -E '::(derive_seed_matches_bip39_vector|derive_seeds_matches_derive_seed_per_lane|every_lane_matches_bip39_canonical_vector|distinct_lanes_match_ring_reference|ton_salts_and_iteration_counts_match_ring|slip10_ed25519_test_vector_1_m_0h|slip10_ed25519_test_vector_1_m_0h_1h|solana_phantom_derivation_from_canonical_phrase|bip84_canonical_vector|eip55_canonical_vector|eip55_second_vector|bip44_canonical_vector|generate_batch_emits_lane_count_candidates_matching_single_path|generate_batch_emits_lane_count_wallets_with_consistent_addresses|ton_tonkeeper_round_trip_vector|wallet_v5r1_matches_tonkeeper_vector|keccak256_empty_vector) \.\.\. ok$' | sort
```

Expected: exactly **19** lines. Every name is matched WHOLE — anchored on `::` before it
and ` ... ok` after — never as a substring.

That anchoring is load-bearing, not style. The earlier substring form
(`grep -E 'bip44_canonical_vector|...'`) silently returned **20** once Task 2.1 added
`from_gpu_seed_and_verify_agree_with_the_bip44_canonical_vector`, whose name *contains* a
pinned vector's name. This branch keeps adding tests named after the vectors they
exercise, so substring matching over-counts by construction.

**If this prints anything other than 19, do NOT adjust the expected number.** A count above
19 means a new test name collides with a pinned one — fix the pattern. A count below 19
means a pinned vector is missing or failing — stop and find out which, because that is the
cryptographic guarantee this whole branch rests on. The 19 are: 2 in `seed`, 3 in
`pbkdf2_lanes`, 2 in `slip10`, 1 `solana_phantom…`, 1 `bip84…`, 3 in `evm` (two EIP-55 +
BIP-44), 4 `generate_batch_emits_lane_count…` (Solana, EVM, Bitcoin, TON), 2 in `ton`/
`ton_cell`, and 1 `keccak256_empty_vector`.

- [ ] **Step 5: No clippy diagnostics anywhere in `src/gpu/`, and the pre-existing 12 unchanged.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && touch src/main.rs && cargo clippy --all-targets 2>&1 | grep -- '-->' | sort | uniq -c
```

Expected: exactly these 12 lines and no others — in particular **no line containing
`src/gpu/`**:

```
   1    --> src/app.rs:357:5
   1    --> src/app.rs:522:17
   1    --> src/app.rs:543:13
   1    --> src/app.rs:548:13
   1    --> src/chains/evm.rs:103:20
   1    --> src/chains/ton_cell.rs:385:25
   1    --> src/ui.rs:212:23
   1   --> src/app.rs:51:5
   1   --> src/chains/bitcoin.rs:16:33
   1   --> src/chains/evm.rs:96:24
   1   --> src/chains/ton_cell.rs:48:26
   1   --> src/chains/ton_cell.rs:54:19
```

- [ ] **Step 6: The four new files are rustfmt-clean and the two edited files gained no drift.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && rustfmt --edition 2021 --check src/gpu/mod.rs src/gpu/pack.rs src/gpu/selftest.rs src/gpu/stub.rs && echo "GPU-FMT-CLEAN" && rustfmt --edition 2021 --check src/seed.rs && echo "SEED-FMT-CLEAN" && rustfmt --edition 2021 --check src/pbkdf2_lanes.rs | grep -c '^Diff in'
```

Expected: `GPU-FMT-CLEAN`, then `SEED-FMT-CLEAN`, then `4` (the pre-existing
`src/pbkdf2_lanes.rs` drift count, unchanged). Do **not** run bare `cargo fmt`.

- [ ] **Step 7: Release build.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo build --release 2>&1 | tail -2
```

Expected: `Finished \`release\` profile [optimized] target(s)`. The binary's runtime
behaviour is unchanged — `src/gpu` is `#![allow(dead_code)]` and nothing calls into it
yet.

- [ ] **Step 8: Confirm the milestone diff is exactly nine files.**

Diff against `7e49a54` — the current branch HEAD, i.e. this branch's tip *before*
milestone 1 — **not** against `ba07199` and **not** against `beced09`.
`ba07199..HEAD` also contains `4854a59` (`ui: move key hints to a full-width bottom
row`, which edits `src/ui.rs` and `src/app.rs`), so it is not this milestone's diff
and would report that commit as drift. `beced09..HEAD` fails from the other side: the
two plan-document commits `094e8c3` and `7e49a54` sit between `beced09` and the tip,
so it reports `docs/superpowers/plans/2026-08-26-metal-gpu-pbkdf2.md` as milestone
drift before a single line of milestone-1 code exists. The `-- . ':(exclude)docs/'`
pathspec below is belt-and-braces on top of the corrected base: no plan-file churn —
yours or anyone else's — can ever be read as source drift. Confirm the base first,
then diff (verified: with no milestone work committed yet, both halves print nothing
at all):

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && git log --oneline 7e49a54..HEAD -- . ':(exclude)docs/' && git diff --stat 7e49a54..HEAD -- . ':(exclude)docs/'
```

Expected: the log lists only this milestone's own commits (Tasks 1.1-1.7, plus the
optional `Cargo.lock` commit in Step 9), and the diffstat names exactly `Cargo.lock`,
`Cargo.toml`, `src/gpu/mod.rs`, `src/gpu/pack.rs`, `src/gpu/selftest.rs`,
`src/gpu/stub.rs`, `src/main.rs`, `src/pbkdf2_lanes.rs`, `src/seed.rs` — nine files
and nothing else. In particular **no** `src/app.rs`, `src/ui.rs`, or `src/chains/*`
(a stray `cargo fmt` is the only thing that puts them there; if they appear, recover
with `git checkout 7e49a54 -- src/app.rs src/ui.rs src/chains` and re-run Step 1).
**Never** `git checkout ba07199 -- src/app.rs src/ui.rs src/chains` — that would
silently revert commit `4854a59`, a legitimate change already on this branch.

- [ ] **Step 9: Nothing to commit — verify the tree is clean.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && git status --porcelain && echo "TREE-CLEAN"
```

Expected: `TREE-CLEAN` with no file lines above it. If `Cargo.lock` shows up, commit it:

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && git add Cargo.lock && git commit -F - <<'MSG'
chore: refresh Cargo.lock for crossbeam-channel

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
MSG
```
## Milestone 2 — The verify gate and the `Verified` token, CPU-only

This milestone builds the entire trust boundary **with no GPU in the tree**. Every test
here constructs `SeedBlock`s from `ring`-derived seeds, so the whole gate — accept path,
reject path, fault-raising, and the CSV chokepoint — is proven on Linux and on macOS
before a single line of Metal exists.

The design rationale you must preserve (quoted from the approved spec,
`docs/superpowers/specs/2026-08-26-metal-gpu-pbkdf2-design.md`):

> The GPU is a *seed accelerator*: never a source of entropy, never a source of truth.
> Every GPU-sourced match is re-derived with `ring` before it can exist.

> The `Match` written to the CSV carries the **CPU-derived** address, secret, and phrase —
> never the GPU-derived ones. A wrong GPU seed can therefore only cost a *missed* match,
> never an unspendable CSV row.

**Assumed complete before you start (Milestone 1):** `src/gpu/mod.rs` exists with
`WAVE`/`BLOCK`/…, `GpuCandidate`, `SeedBlock`, `GpuStatus`, `GpuDisableReason`,
`GpuHealth`, `GpuRx`, `GpuError`; `src/gpu/pack.rs` exists; `main.rs` declares
`pub mod gpu;`; `crossbeam-channel` is in `Cargo.toml`; `seed::PBKDF2_ROUNDS` and
`seed::BIP39_SALT` are `pub`.

**Formatting and lint policy for this milestone — identical to Milestone 1's.**

**Do NOT run bare `cargo fmt`.** The tree is not rustfmt-clean at `beced09`:
`cargo fmt --check` reports 84 diffs across 14 files (`src/app.rs`, `src/ui.rs`,
`src/matcher.rs`, `src/slip10.rs`, `src/bip32.rs`, `src/pbkdf2_lanes.rs` and all of
`src/chains/*`). A bare `cargo fmt` would bury this branch under an unrelated
whole-tree reformat and permanently falsify Milestone 1 Task 1.8 Step 8's whole-diff
gate. Task 8.5 Step 7 is the only sanctioned whole-tree reformat, in its own commit.

Format only the NEW files this branch creates, by path:

```sh
rustfmt --edition 2021 src/verify.rs
```

`rustfmt <file>` in write mode follows `mod` declarations into child files, so never
run it on `src/main.rs` (that reformats the whole tree) or on `src/chains/mod.rs`
(that reformats all of `src/chains/*`). For the pre-existing files this milestone
edits — `src/app.rs`, `src/main.rs`, `src/chains/mod.rs`, `src/chains/evm.rs` — match
the surrounding style by hand and prove you added no new drift with a path-filtered
`--check`:

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && for f in src/app.rs src/main.rs src/chains/mod.rs src/chains/evm.rs; do \
  printf '%s %s\n' "$f" "$(rustfmt --edition 2021 --check "$f" 2>/dev/null | grep -c "^Diff in .*/$f:")"; \
done
```

Expected — exactly the pre-existing per-file counts, unchanged:

```
src/app.rs 11
src/main.rs 0
src/chains/mod.rs 1
src/chains/evm.rs 3
```

A higher number means your insertion is not rustfmt-shaped; fix it by hand.

**Never expect clippy to be silent.** `cargo clippy --all-targets` is not
warning-free on the clean baseline — it emits exactly 12 diagnostics. The gate for
every task in this milestone is a baseline comparison, never a zero:

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo clippy --all-targets 2>&1 | grep -- '-->' | sort | uniq -c
```

Expected: exactly these 12 pre-existing lines and no others —

```
   1    --> src/app.rs:357:5
   1    --> src/app.rs:522:17
   1    --> src/app.rs:543:13
   1    --> src/app.rs:548:13
   1    --> src/chains/evm.rs:103:20
   1    --> src/chains/ton_cell.rs:385:25
   1    --> src/ui.rs:212:23
   1   --> src/app.rs:51:5
   1   --> src/chains/bitcoin.rs:16:33
   1   --> src/chains/evm.rs:96:24
   1   --> src/chains/ton_cell.rs:48:26
   1   --> src/chains/ton_cell.rs:54:19
```

The `src/app.rs`, `src/chains/mod.rs` and `src/chains/evm.rs` line numbers shift as
this branch edits those files; what must not change is the COUNT of 12, and no line
may point into `src/gpu/`, `src/verify.rs`, or a function this branch added. Fixing
the 12 pre-existing lints is out of scope — it would touch four otherwise-frozen
files for no functional reason.

---

### Task 2.1: The `Bip39GpuChain` seam and `Evm`'s implementation of it

**Files:**
- Modify: `src/chains/mod.rs` (insert a new trait after the `Chain` trait, which currently ends at line 43)
- Modify: `src/chains/evm.rs` (line 2 `use super::Chain;`; line 36 `fn from_seed` → `pub(crate)`; new `impl` block after line 47)
- Test: `src/chains/evm.rs` (`mod tests` starts at line 114)

**Interfaces:**
- Consumes: `pub trait Chain` with `type AddressBytes: AsRef<[u8]>`, `type SecretRaw`, `fn encode_address(&Self::AddressBytes) -> String`, `fn encode_secret(&Self::SecretRaw) -> String` (`src/chains/mod.rs:23-43`); `pub fn derive_seed(mnemonic: &Mnemonic) -> [u8; 64]` (`src/seed.rs:8`)
- Produces:
  - `pub trait Bip39GpuChain: Chain { fn from_gpu_seed(seed: &[u8; 64]) -> (Self::AddressBytes, Self::SecretRaw); fn verify(address: &str, secret_hex: &str, phrase: &str) -> bool; }`
  - `impl Bip39GpuChain for Evm`
  - `pub(crate) fn Evm::from_seed(seed: &[u8; 64]) -> ([u8; 20], secp256k1::SecretKey)` (was private)

- [ ] **Step 1: Write the failing test.** Append this test inside `mod tests` in `src/chains/evm.rs`, immediately before the closing `}` of the module (after `generate_batch_emits_lane_count_candidates_matching_single_path`):

```rust
    /// The GPU tail (`from_gpu_seed`) and the re-derivation gate (`verify`) must
    /// both land on the pinned BIP-44 vector, and `verify` must REJECT — never
    /// panic on, never accept — a wrong address, a wrong phrase, or a phrase that
    /// is not a mnemonic at all.
    #[test]
    fn from_gpu_seed_and_verify_agree_with_the_bip44_canonical_vector() {
        const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let m = Mnemonic::from_phrase(PHRASE, Language::English).unwrap();
        let seed = derive_seed(&m);

        let (addr, sk) = Evm::from_gpu_seed(&seed);
        assert_eq!(hex::encode(addr), "9858effd232b4033e47d90003d41ec34ecaeda94");

        let address = Evm::encode_address(&addr);
        let secret_hex = Evm::encode_secret(&sk);
        assert!(Evm::verify(&address, &secret_hex, PHRASE));

        // One flipped nibble in the address: reject.
        let mut bad_addr = address.clone();
        bad_addr.replace_range(2..3, "8"); // "0x9858..." -> "0x8858..."
        assert!(!Evm::verify(&bad_addr, &secret_hex, PHRASE));

        // One flipped nibble in the secret: reject.
        let mut bad_secret = secret_hex.clone();
        let first = if bad_secret.starts_with('0') { "1" } else { "0" };
        bad_secret.replace_range(0..1, first);
        assert!(!Evm::verify(&address, &bad_secret, PHRASE));

        // A valid but DIFFERENT phrase: reject.
        let other = Mnemonic::new(MnemonicType::Words12, Language::English);
        assert!(!Evm::verify(&address, &secret_hex, other.phrase()));

        // Not a mnemonic at all: reject, do not panic.
        assert!(!Evm::verify(&address, &secret_hex, "not a mnemonic"));
    }
```

- [ ] **Step 2: Run it and see it fail.**

```sh
cargo test from_gpu_seed_and_verify_agree_with_the_bip44_canonical_vector
```

Expect a compile error, not a test failure:

```
error[E0599]: no function or associated item named `from_gpu_seed` found for struct `Evm` in the current scope
```

- [ ] **Step 3: Add the trait.** In `src/chains/mod.rs`, insert this immediately after the closing `}` of `pub trait Chain` (currently line 43) and before `/// Runtime chain selection.` (line 45):

```rust
/// A chain whose entire candidate is a pure function of a 64-byte BIP-39 seed.
/// Implementing this — and nothing else — opts a chain into the GPU pipeline.
/// Evm implements it. Solana and Bitcoin each already have a private `from_seed`
/// of exactly this shape and are one line away; Ton (own mnemonic, 100k rounds,
/// different salt) and Monero (no BIP-39) structurally cannot — that is the
/// reuse seam.
///
/// A separate trait, rather than `const GPU_SEEDS: bool` plus a defaulted
/// `from_gpu_seed` whose body is `unreachable!()`: with the const, a future
/// maintainer can flip it true without implementing the tail, compile cleanly,
/// and then panic inside a Rayon worker with the terminal in raw mode. Here that
/// state is unrepresentable.
pub trait Bip39GpuChain: Chain {
    fn from_gpu_seed(seed: &[u8; 64]) -> (Self::AddressBytes, Self::SecretRaw);
    /// Re-derive from the phrase alone with the reference (`ring`) path.
    /// MUST NOT use the batched or GPU path. Returns `bool`, never `Option`.
    fn verify(address: &str, secret_hex: &str, phrase: &str) -> bool;
}
```

- [ ] **Step 4: Widen `Evm::from_seed`.** In `src/chains/evm.rs`, change line 36 from:

```rust
    fn from_seed(seed: &[u8; 64]) -> ([u8; 20], secp256k1::SecretKey) {
```

to:

```rust
    pub(crate) fn from_seed(seed: &[u8; 64]) -> ([u8; 20], secp256k1::SecretKey) {
```

This is behaviour-neutral. It is already the shared tail of `generate` (line 58) and
`generate_batch` (line 65), which is precisely what makes the pinned
`bip44_canonical_vector` (line 138) and
`generate_batch_emits_lane_count_candidates_matching_single_path` (line 156)
transitively cover the GPU tail.

- [ ] **Step 5: Bring the trait into scope.** In `src/chains/evm.rs`, change line 2 from:

```rust
use super::Chain;
```

to:

```rust
use super::{Bip39GpuChain, Chain};
```

- [ ] **Step 6: Implement the trait for `Evm`.** In `src/chains/evm.rs`, insert this immediately after the closing `}` of `impl Chain for Evm` (currently line 111) and before `#[cfg(test)]` (line 113):

```rust
impl Bip39GpuChain for Evm {
    fn from_gpu_seed(seed: &[u8; 64]) -> (Self::AddressBytes, Self::SecretRaw) {
        // Exactly the tail the CPU path uses. Sharing one body is what makes the
        // pinned bip44_canonical_vector cover the GPU path too.
        Self::from_seed(seed)
    }

    fn verify(address: &str, secret_hex: &str, phrase: &str) -> bool {
        let Ok(m) = Mnemonic::from_phrase(phrase, Language::English) else {
            // An unparseable phrase or a bad BIP-39 checksum is a REJECTION, not
            // an "unverifiable" third state. There is deliberately no arm here
            // that can turn a corrupted input into a pass.
            return false;
        };
        // `derive_seed` is ring::pbkdf2 (src/seed.rs:8) — the reference path.
        // NEVER `derive_seeds` (4-lane NEON) and never the GPU: the point of this
        // function is to be more trusted than the thing it is checking.
        let (addr, secret) = Self::from_seed(&derive_seed(&m));
        Self::encode_address(&addr) == address && Self::encode_secret(&secret) == secret_hex
    }
}
```

- [ ] **Step 7: Run the test and see it pass.**

```sh
cargo test from_gpu_seed_and_verify_agree_with_the_bip44_canonical_vector
```

Expect `test chains::evm::tests::from_gpu_seed_and_verify_agree_with_the_bip44_canonical_vector ... ok`.

- [ ] **Step 8: Run the whole suite — every pinned vector must still pass.**

```sh
cargo test
```

Expect `test result: ok.` with zero failures.

- [ ] **Step 9: Format the touched files and compare clippy against the baseline.**
Both files this task edited already carry pre-existing rustfmt drift, so do NOT run
bare `cargo fmt`, and do NOT run `rustfmt` in write mode on `src/chains/mod.rs` — it
follows `mod` declarations and would reformat all of `src/chains/*`. Match the
surrounding style by hand, then check:

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && for f in src/chains/mod.rs src/chains/evm.rs; do \
  printf '%s %s\n' "$f" "$(rustfmt --edition 2021 --check "$f" 2>/dev/null | grep -c "^Diff in .*/$f:")"; \
done && cargo clippy --all-targets 2>&1 | grep -- '-->' | sort | uniq -c
```

Expected: `src/chains/mod.rs 1` and `src/chains/evm.rs 3` — the pre-existing counts
from this milestone's preamble — then exactly the 12 pre-existing clippy lines listed
in that preamble and no others. No line may point at the `Bip39GpuChain` trait or the
`impl Bip39GpuChain for Evm` block this task added.

- [ ] **Step 10: Commit.**

```sh
git add src/chains/mod.rs src/chains/evm.rs
git commit -m "feat(chains): add Bip39GpuChain seam and impl it for Evm

from_gpu_seed is the existing Evm::from_seed tail (now pub(crate)), so the
pinned bip44_canonical_vector transitively covers the GPU path. verify()
re-derives from the phrase alone via ring and returns bool - every failure
mode is a rejection, there is no 'unverifiable' arm.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 2.2: The `Verified` token and its CPU minting site

**Files:**
- Create: `src/verify.rs`
- Modify: `src/main.rs` (module list, lines 1-8)
- Modify: `src/chains/mod.rs` (`Match` at lines 16-21; `search` at lines 101-120)
- Test: `src/chains/mod.rs` (`mod tests` at lines 122-147); `src/verify.rs` (new `mod tests`)

**Interfaces:**
- Consumes: `Bip39GpuChain::verify(&str, &str, &str) -> bool` (Task 2.1); `Chain::{LABEL, BATCH, generate_batch, matches_raw, encode_address, encode_secret}`
- Produces:
  - `pub struct Verified(())` with `#[derive(Clone, Copy)]`
  - `pub(crate) fn Verified::cpu_reference() -> Verified`
  - `Match { chain, address, secret_hex, mnemonic, pub verified: crate::verify::Verified }`
  - `#[inline(always)] fn search_cpu_step<C: Chain>(matcher: &Matcher, counter: &AtomicU64, tx: &Sender<Match>)`
  - `pub fn search<C: Chain>(matcher: &Matcher, stop: &AtomicBool, counter: &AtomicU64, tx: &Sender<Match>)` — signature UNCHANGED

- [ ] **Step 1: Write the failing test.** Append this inside `mod tests` in `src/chains/mod.rs`, after `search_counts_whole_batches_and_honours_stop` and before the module's closing `}` (line 147):

```rust
    /// The CPU path is the reference, so its matches mint `Verified::cpu_reference()`
    /// directly — but they must still actually re-derive. This is the property the
    /// whole gate exists to preserve, asserted on the path that does not need a GPU.
    #[test]
    fn cpu_step_emits_matches_that_carry_a_token_and_re_derive() {
        use crate::chains::evm::Evm;

        // Empty prefix and empty suffix: Matcher::new leaves evm_prefix/evm_suffix
        // as None, matches_evm_raw returns true unconditionally, so one batch of
        // LANES candidates produces exactly LANES matches.
        let matcher = Matcher::new(String::new(), String::new(), false, ChainKind::Evm);
        let counter = AtomicU64::new(0);
        let (tx, rx) = mpsc::channel();

        search_cpu_step::<Evm>(&matcher, &counter, &tx);
        drop(tx);

        let got: Vec<Match> = rx.into_iter().collect();
        assert_eq!(got.len(), LANES, "an all-accepting matcher must emit every candidate");
        assert_eq!(counter.load(Ordering::Relaxed), LANES as u64);
        for m in &got {
            assert_eq!(m.chain, "EVM");
            assert!(
                Evm::verify(&m.address, &m.secret_hex, &m.mnemonic),
                "CPU-path match must re-derive via ring: {}",
                m.address
            );
        }
    }
```

- [ ] **Step 2: Run it and see it fail.**

```sh
cargo test cpu_step_emits_matches_that_carry_a_token_and_re_derive
```

Expect a compile error, not a test failure:

```
error[E0425]: cannot find function `search_cpu_step` in this scope
```

- [ ] **Step 3: Create `src/verify.rs`.** Write this exact file:

```rust
//! The proof token that gates `vanity_wallets.csv`.
//!
//! The GPU is a *seed accelerator*: never a source of entropy, never a source of
//! truth. Nothing reaches the CSV unless a `Verified` was minted for it, and only
//! this module can mint one.

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
    pub(crate) fn cpu_reference() -> Self {
        Verified(())
    }
}

#[cfg(test)]
mod tests {
    /// Regression guard, not a driver: it passes the moment this file exists.
    /// Its job is to FAIL LATER, if someone widens the tuple field.
    ///
    /// A `compile_fail` doc test would be the natural spelling, but this crate is
    /// binary-only (no `lib.rs`, see CLAUDE.md), and `cargo test` never runs doc
    /// tests for a bin target — the doctest would silently never execute. So the
    /// property is pinned at the source level instead.
    #[test]
    fn verified_token_field_is_private_so_only_this_module_can_mint_one() {
        let src = include_str!("verify.rs");
        // The needles are assembled with concat! so that this test's OWN source
        // text does not contain them — otherwise both assertions would match
        // themselves and prove nothing.
        let declared = concat!("pub struct Verified(", "());");
        let forged = concat!("pub struct Verified(", "pub ");
        assert!(
            src.contains(declared),
            "Verified must keep exactly one PRIVATE unit field"
        );
        assert!(
            !src.contains(forged),
            "Verified's field must never become pub — any module could then forge a proof"
        );
    }
}
```

- [ ] **Step 4: Declare the module.** In `src/main.rs`, change lines 1-8 from:

```rust
pub mod app;
pub mod bip32;
pub mod chains;
pub mod matcher;
pub mod pbkdf2_lanes;
pub mod seed;
pub mod slip10;
pub mod ui;
```

to:

```rust
pub mod app;
pub mod bip32;
pub mod chains;
pub mod gpu;
pub mod matcher;
pub mod pbkdf2_lanes;
pub mod seed;
pub mod slip10;
pub mod ui;
pub mod verify;
```

(`pub mod gpu;` was added by Milestone 1; if it is already present, add only `pub mod verify;`.)

- [ ] **Step 5: Add the `verified` field to `Match`.** In `src/chains/mod.rs`, replace lines 14-21:

```rust
/// Channel payload emitted when a vanity address is found.
#[derive(Clone)]
pub struct Match {
    pub chain: String,
    pub address: String,
    pub secret_hex: String,
    pub mnemonic: String,
}
```

with:

```rust
/// Channel payload emitted when a vanity address is found.
#[derive(Clone)]
pub struct Match {
    pub chain: String,
    pub address: String,
    pub secret_hex: String,
    pub mnemonic: String,
    /// Proof that this row re-derives via the reference (`ring`) path.
    /// `app::append_match_row` takes a `&Match`, so an unverified row is
    /// unrepresentable rather than merely unwritten.
    pub verified: crate::verify::Verified,
}
```

- [ ] **Step 6: Factor the CPU batch out of `search`.** In `src/chains/mod.rs`, replace the whole of `pub fn search` (lines 101-120):

```rust
pub fn search<C: Chain>(
    matcher: &Matcher,
    stop: &AtomicBool,
    counter: &AtomicU64,
    tx: &Sender<Match>,
) {
    while !stop.load(Ordering::Relaxed) {
        C::generate_batch(|addr_bytes, secret_raw, phrase| {
            if C::matches_raw(matcher, &addr_bytes) {
                let _ = tx.send(Match {
                    chain: C::LABEL.to_string(),
                    address: C::encode_address(&addr_bytes),
                    secret_hex: C::encode_secret(&secret_raw),
                    mnemonic: phrase,
                });
            }
        });
        counter.fetch_add(C::BATCH as u64, Ordering::Relaxed);
    }
}
```

with:

```rust
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
pub fn search<C: Chain>(
    matcher: &Matcher,
    stop: &AtomicBool,
    counter: &AtomicU64,
    tx: &Sender<Match>,
) {
    while !stop.load(Ordering::Relaxed) {
        search_cpu_step::<C>(matcher, counter, tx);
    }
}
```

- [ ] **Step 7: Run the new test and see it pass.**

```sh
cargo test cpu_step_emits_matches_that_carry_a_token_and_re_derive
```

Expect `test chains::tests::cpu_step_emits_matches_that_carry_a_token_and_re_derive ... ok`.

- [ ] **Step 8: Run the regression guard and the untouched pinned test.**

```sh
cargo test verified_token_field_is_private_so_only_this_module_can_mint_one
cargo test search_counts_whole_batches_and_honours_stop
```

Both must print `... ok`. `search_counts_whole_batches_and_honours_stop`
(`src/chains/mod.rs:130-146`) calls `search::<Solana>`, whose signature is unchanged,
and its `n % LANES == 0` assertion at line 145 must still hold.

- [ ] **Step 9: Run the whole suite.**

```sh
cargo test
```

Expect `test result: ok.` with zero failures.

- [ ] **Step 10: Format the touched files and compare clippy against the baseline.**
`src/verify.rs` is new to this branch, so format it by path. `src/main.rs` and
`src/chains/mod.rs` are pre-existing: do NOT run bare `cargo fmt`, and do NOT run
`rustfmt` in write mode on either of them — both follow `mod` declarations and would
reformat the whole tree. Match the surrounding style by hand, then:

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && rustfmt --edition 2021 src/verify.rs \
  && for f in src/main.rs src/chains/mod.rs; do \
    printf '%s %s\n' "$f" "$(rustfmt --edition 2021 --check "$f" 2>/dev/null | grep -c "^Diff in .*/$f:")"; \
  done && cargo clippy --all-targets 2>&1 | grep -- '-->' | sort | uniq -c
```

Expected: `src/main.rs 0` and `src/chains/mod.rs 1` — the pre-existing counts from
this milestone's preamble — then exactly the 12 pre-existing clippy lines listed in
that preamble and no others. In particular no line may point at `src/verify.rs`.

- [ ] **Step 11: Commit.**

```sh
git add src/verify.rs src/main.rs src/chains/mod.rs
git commit -m "feat(verify): add the Verified proof token and mint it on the CPU path

Match gains a `verified: Verified` field whose tuple element is private to
src/verify.rs, so a Match cannot be constructed outside the two minting sites.
search()'s loop body moves verbatim into search_cpu_step so the CPU path and the
future hybrid path share one body and cannot drift. search()'s signature is
unchanged - Solana/Bitcoin/Ton/Monero still call it.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 2.3: `verify_gpu` — the reject-on-anything gate

**Files:**
- Modify: `src/verify.rs` (append the function after `impl Verified`; append tests to the existing `mod tests`)

**Interfaces:**
- Consumes: `Verified(())` (Task 2.2); `Bip39GpuChain::from_gpu_seed(&[u8; 64]) -> (Self::AddressBytes, Self::SecretRaw)` (Task 2.1); `crate::seed::derive_seed(&Mnemonic) -> [u8; 64]` (`src/seed.rs:8`); `Chain::AddressBytes: AsRef<[u8]>`
- Produces: `pub fn verify_gpu<C: crate::chains::Bip39GpuChain>(entropy: &[u8; 16], gpu_addr: &C::AddressBytes) -> Option<(C::AddressBytes, C::SecretRaw, String, Verified)>`

- [ ] **Step 1: Write the failing tests.** In `src/verify.rs`, replace the `mod tests` header line `mod tests {` and insert these imports plus five tests immediately after it (keep the existing privacy guard test in place):

```rust
mod tests {
    use super::*;
    use crate::chains::evm::Evm;
    use crate::chains::{Bip39GpuChain, Chain};
    use bip39::{Language, Mnemonic, MnemonicType};

    /// Deterministic entropy so a red build replays exactly. Every 16-byte array
    /// is valid BIP-39 entropy — the checksum is computed FROM it, not checked
    /// against it. `fixed_entropy(0)` is all zeros, i.e. "abandon … about".
    fn fixed_entropy(i: u8) -> [u8; 16] {
        let mut e = [0u8; 16];
        e[15] = i;
        e
    }

    /// Build what the GPU would have delivered, but with `ring` doing the PBKDF2.
    fn ring_candidate(i: u8) -> ([u8; 16], [u8; 20]) {
        let entropy = fixed_entropy(i);
        let m = Mnemonic::from_entropy(&entropy, Language::English).unwrap();
        let (addr, _sk) = Evm::from_gpu_seed(&crate::seed::derive_seed(&m));
        (entropy, addr)
    }

    /// Anchor the gate to external ground truth first: entropy = 16 zero bytes is
    /// the BIP-39 canonical phrase, whose m/44'/60'/0'/0/0 address is the pinned
    /// first MetaMask account.
    #[test]
    fn verify_gpu_accepts_the_bip39_canonical_vector() {
        let (entropy, gpu_addr) = ring_candidate(0);
        let (addr, secret, phrase, _proof) =
            verify_gpu::<Evm>(&entropy, &gpu_addr).expect("canonical vector must verify");
        assert_eq!(hex::encode(addr), "9858effd232b4033e47d90003d41ec34ecaeda94");
        assert_eq!(
            phrase,
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        );
        assert!(Evm::verify(
            &Evm::encode_address(&addr),
            &Evm::encode_secret(&secret),
            &phrase
        ));
    }

    #[test]
    fn verify_gpu_accepts_a_real_candidate() {
        let (entropy, gpu_addr) = ring_candidate(37);
        let (addr, secret, phrase, _proof) =
            verify_gpu::<Evm>(&entropy, &gpu_addr).expect("an honest candidate must verify");
        assert_eq!(addr, gpu_addr, "the returned address is the CPU-derived one");
        // The phrase handed back is rebuilt by trusted CPU code from the entropy,
        // and must round-trip to the same entropy.
        let round = Mnemonic::from_phrase(&phrase, Language::English).unwrap();
        assert_eq!(round.entropy(), &entropy[..]);
        assert!(Evm::verify(
            &Evm::encode_address(&addr),
            &Evm::encode_secret(&secret),
            &phrase
        ));
    }

    #[test]
    fn verify_gpu_rejects_flipped_address_nibble() {
        let (entropy, gpu_addr) = ring_candidate(9);
        let mut tampered = gpu_addr;
        tampered[0] ^= 0x10; // one nibble
        assert!(
            verify_gpu::<Evm>(&entropy, &tampered).is_none(),
            "a GPU address that does not re-derive must be REJECTED, never accepted"
        );
    }

    /// The mis-pairing case: entropy from candidate A, address from candidate B.
    /// This is the failure mode that a `zip` bug in the producer would produce,
    /// and it must not be able to reach the CSV.
    #[test]
    fn verify_gpu_rejects_entropy_from_a_different_candidate() {
        let (entropy_a, _addr_a) = ring_candidate(11);
        let (_entropy_b, addr_b) = ring_candidate(12);
        assert!(verify_gpu::<Evm>(&entropy_a, &addr_b).is_none());
    }

    #[test]
    fn verify_gpu_result_carries_a_usable_secret_for_the_returned_address() {
        let (entropy, gpu_addr) = ring_candidate(200);
        let (addr, secret, phrase, _proof) = verify_gpu::<Evm>(&entropy, &gpu_addr).unwrap();
        let (addr2, secret2) = Evm::from_gpu_seed(&crate::seed::derive_seed(
            &Mnemonic::from_phrase(&phrase, Language::English).unwrap(),
        ));
        assert_eq!(addr, addr2);
        assert_eq!(Evm::encode_secret(&secret), Evm::encode_secret(&secret2));
        let _ = MnemonicType::Words12; // keep the import honest
    }
```

- [ ] **Step 2: Run them and see them fail.**

```sh
cargo test verify_gpu_
```

Expect a compile error, not test failures:

```
error[E0425]: cannot find function `verify_gpu` in this scope
```

- [ ] **Step 3: Implement `verify_gpu`.** In `src/verify.rs`, insert this between the closing `}` of `impl Verified` and `#[cfg(test)]`:

```rust
/// Re-derive a GPU-sourced candidate from its 16-byte entropy alone and confirm
/// it reproduces the address the GPU seed produced. `None` ⇒ reject.
///
/// NOTE the polarity: there is deliberately no `Option<bool>` and no
/// "unverifiable" arm. Every failure mode — unparseable entropy, bad checksum,
/// address disagreement — is a rejection. An earlier design mapped
/// `Some(true) | None => Some(Verified(()))`, meaning the token proved "verified
/// OR the verifier declared itself unable to check"; the idiomatic `.ok()?` in
/// any later edit then converts a corrupted phrase into a PASS, turning the gate
/// into a decoration on exactly the input it exists to catch.
pub fn verify_gpu<C: crate::chains::Bip39GpuChain>(
    entropy: &[u8; 16],
    gpu_addr: &C::AddressBytes,
) -> Option<(C::AddressBytes, C::SecretRaw, String, Verified)> {
    let m = bip39::Mnemonic::from_entropy(entropy, bip39::Language::English).ok()?;
    // ring::pbkdf2 (src/seed.rs:8) — the reference path, never the 4-lane NEON
    // path and never the GPU.
    let seed = crate::seed::derive_seed(&m);
    let (addr, secret) = C::from_gpu_seed(&seed);
    if addr.as_ref() != gpu_addr.as_ref() {
        return None;
    }
    // The phrase handed back is rebuilt here by trusted CPU code, so the String
    // that ends up in the CSV is never one the GPU thread touched.
    Some((addr, secret, m.phrase().to_string(), Verified(())))
}
```

- [ ] **Step 4: Run the tests and see them pass.**

```sh
cargo test verify_gpu_
```

Expect 5 tests, all `... ok`.

- [ ] **Step 5: Run the whole suite.**

```sh
cargo test
```

Expect `test result: ok.` with zero failures.

- [ ] **Step 6: Format the touched file and compare clippy against the baseline.**
This task edited only `src/verify.rs`, which is new to this branch, so format it by
path. Do NOT run bare `cargo fmt`.

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && rustfmt --edition 2021 src/verify.rs \
  && cargo clippy --all-targets 2>&1 | grep -- '-->' | sort | uniq -c
```

Expected: exactly the 12 pre-existing clippy lines listed in this milestone's
preamble and no others. If a 13th line appears pointing into `src/verify.rs` for
`clippy::type_complexity` on `verify_gpu`, add exactly this line immediately above `pub fn verify_gpu`:

```rust
#[allow(clippy::type_complexity)] // The 4-tuple IS the contract: address, secret, phrase, proof. A named struct would let a caller build one field at a time and lose the all-or-nothing property.
```

- [ ] **Step 7: Commit.**

```sh
git add src/verify.rs
git commit -m "feat(verify): add verify_gpu, the reject-on-anything gate

Re-derives a GPU candidate from its 16-byte entropy with ring and requires the
address to agree. None means reject: unparseable entropy, bad checksum, and
address disagreement are all the same answer. The phrase returned is rebuilt by
CPU code, so the String written to the CSV never came from the GPU thread.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 2.4: `search_hybrid`, `drain_gpu_block`, `emit_gpu_match` — consuming a GPU block with no GPU

**Files:**
- Read-only: `src/gpu/mod.rs` (`SeedBlock::with_capacity`, `SeedBlock::push` and `impl Default for GpuHealth` were written by Milestone 1 Tasks 1.4 and 1.5; this task only verifies they are present and MUST NOT re-add them)
- Modify: `src/chains/mod.rs` (imports at lines 9-12; append three functions after `search`)
- Test: `src/chains/mod.rs` (`mod tests`)

**Interfaces:**
- Consumes: `crate::gpu::{SeedBlock, GpuCandidate, GpuHealth, GpuDisableReason, GpuRx}` (Milestone 1); `crate::verify::verify_gpu::<C>` (Task 2.3); `Bip39GpuChain` (Task 2.1); `search_cpu_step::<C>` (Task 2.2)
- Produces:
  - `const GPU_CHUNK_BATCHES: usize = 16;`
  - `pub fn search_hybrid<C: Bip39GpuChain>(matcher: &Matcher, stop: &AtomicBool, counter: &AtomicU64, tx: &Sender<Match>, gpu: Option<&crate::gpu::GpuRx>, health: &crate::gpu::GpuHealth)`
  - `fn drain_gpu_block<C: Bip39GpuChain>(block: &crate::gpu::SeedBlock, matcher: &Matcher, stop: &AtomicBool, counter: &AtomicU64, tx: &Sender<Match>, health: &crate::gpu::GpuHealth)`
  - `fn emit_gpu_match<C: Bip39GpuChain>(tx: &Sender<Match>, entropy: &[u8; 16], gpu_addr: &C::AddressBytes, health: &GpuHealth)`

`SeedBlock::with_capacity`, `SeedBlock::push` and `impl Default for GpuHealth` are
deliberately NOT listed as produced here — Milestone 1 Tasks 1.4 and 1.5 already
wrote them as `pub(crate) fn` — `src/chains` is in the same crate, so that
visibility is sufficient and must not be widened here. This task only consumes them.

- [ ] **Step 1: Confirm Milestone 1 already made `SeedBlock` fillable and `GpuHealth`
default-constructible.** This is a pure verification step — it edits nothing. Run:

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && grep -n "pub(crate) fn with_capacity(n: usize) -> Self" src/gpu/mod.rs \
  && grep -n "pub(crate) fn push(&mut self, candidate: GpuCandidate)" src/gpu/mod.rs \
  && grep -n "impl Default for GpuHealth" src/gpu/mod.rs
```

Expected: three hits, one from each `grep`.

Do **not** add `#[derive(Default)]` to `GpuHealth` — Milestone 1 Task 1.5 Step 4
already wrote `impl Default for GpuHealth { fn default() -> Self { GpuHealth::new() } }`,
and a derive alongside a hand-written impl is
`error[E0119]: conflicting implementations of trait Default for type GpuHealth`.

Do **not** re-add `with_capacity`/`push` — Milestone 1 Task 1.4 Step 4 already wrote
both inside `impl SeedBlock`, and a second `impl SeedBlock` block containing them is
`error[E0592]: duplicate definitions for with_capacity`.

If any of the three greps misses, go back and finish Milestone 1 Task 1.4 / Task 1.5
rather than patching `src/gpu/mod.rs` from here — this task must leave that file
byte-for-byte unchanged.

- [ ] **Step 2: Write the first failing test — the happy path.** Append this inside `mod tests` in `src/chains/mod.rs`:

```rust
    /// Deterministic entropy so a red build replays exactly. Every 16-byte array
    /// is valid BIP-39 entropy — the checksum is computed FROM it.
    #[cfg(test)]
    fn gpu_test_entropy(i: usize) -> [u8; 16] {
        let mut e = [0u8; 16];
        e[14] = (i >> 8) as u8;
        e[15] = i as u8;
        e
    }

    /// A block the GPU could have produced, except `ring` did the PBKDF2.
    /// Returns the block plus the address each candidate must resolve to.
    fn ring_seed_block(n: usize) -> (crate::gpu::SeedBlock, Vec<String>) {
        use crate::chains::evm::Evm;
        use crate::gpu::{GpuCandidate, SeedBlock};
        use bip39::{Language, Mnemonic};

        let mut block = SeedBlock::with_capacity(n);
        let mut addrs = Vec::with_capacity(n);
        for i in 0..n {
            let entropy = gpu_test_entropy(i);
            let m = Mnemonic::from_entropy(&entropy, Language::English).unwrap();
            let seed = crate::seed::derive_seed(&m);
            let (addr, _sk) = Evm::from_gpu_seed(&seed);
            addrs.push(Evm::encode_address(&addr));
            block.push(GpuCandidate { entropy, seed });
        }
        (block, addrs)
    }

    #[test]
    fn gpu_block_is_consumed_counted_and_cpu_verified() {
        use crate::chains::evm::Evm;
        use crate::gpu::GpuHealth;

        // 128 = 2 full chunks of C::BATCH(4) * GPU_CHUNK_BATCHES(16), so the
        // chunk loop must actually advance rather than handling one chunk.
        const N: usize = 128;
        let (block, want) = ring_seed_block(N);

        let matcher = Matcher::new(String::new(), String::new(), false, ChainKind::Evm);
        let stop = AtomicBool::new(false);
        let counter = AtomicU64::new(0);
        let health = GpuHealth::default();
        let (tx, rx) = mpsc::channel();

        drain_gpu_block::<Evm>(&block, &matcher, &stop, &counter, &tx, &health);
        drop(tx);

        let got: Vec<Match> = rx.into_iter().collect();
        assert_eq!(got.len(), N, "an all-accepting matcher must emit every candidate");
        assert_eq!(counter.load(Ordering::Relaxed), N as u64);
        assert_eq!(health.seeds_delivered.load(Ordering::Relaxed), N as u64);
        assert_eq!(health.verify_rejections.load(Ordering::Relaxed), 0);
        assert!(!health.disable.load(Ordering::Relaxed));

        let got_addrs: Vec<String> = got.iter().map(|m| m.address.clone()).collect();
        assert_eq!(got_addrs, want, "pairing and order must survive the drain");
        for m in &got {
            assert_eq!(m.chain, "EVM");
            assert!(
                Evm::verify(&m.address, &m.secret_hex, &m.mnemonic),
                "every emitted match must re-derive via ring: {}",
                m.address
            );
        }
    }
```

- [ ] **Step 3: Write the second failing test — the fault path.** Append this inside the same `mod tests`:

```rust
    /// A GPU seed that MATCHED the pattern but does not re-derive is a GPU fault,
    /// never a false positive: the GPU is disabled, the candidate is dropped (it
    /// is provably not a wallet anyone can open), and the CPU search stays alive.
    #[test]
    fn corrupted_gpu_seed_raises_fault_and_emits_nothing() {
        use crate::chains::evm::Evm;
        use crate::gpu::{GpuCandidate, GpuDisableReason, GpuHealth, SeedBlock};
        use bip39::{Language, Mnemonic};

        const N: usize = 4; // == Evm::BATCH, so the debug_assert on block length holds
        let mut block = SeedBlock::with_capacity(N);
        let mut good = Vec::new();
        let mut corrupted_addr = String::new();
        for i in 0..N {
            let entropy = gpu_test_entropy(500 + i);
            let m = Mnemonic::from_entropy(&entropy, Language::English).unwrap();
            let mut seed = crate::seed::derive_seed(&m);
            if i == 3 {
                seed[0] ^= 0x01; // one flipped bit, exactly as a faulty kernel would
                let (bad, _sk) = Evm::from_gpu_seed(&seed);
                corrupted_addr = Evm::encode_address(&bad);
            } else {
                let (addr, _sk) = Evm::from_gpu_seed(&seed);
                good.push(Evm::encode_address(&addr));
            }
            block.push(GpuCandidate { entropy, seed });
        }

        let matcher = Matcher::new(String::new(), String::new(), false, ChainKind::Evm);
        let stop = AtomicBool::new(false);
        let counter = AtomicU64::new(0);
        let health = GpuHealth::default();
        let (tx, rx) = mpsc::channel();

        drain_gpu_block::<Evm>(&block, &matcher, &stop, &counter, &tx, &health);
        drop(tx);

        let got: Vec<Match> = rx.into_iter().collect();
        assert_eq!(got.len(), 3, "the corrupted candidate must not be emitted");
        let got_addrs: Vec<String> = got.iter().map(|m| m.address.clone()).collect();
        assert_eq!(got_addrs, good);
        assert!(!got_addrs.contains(&corrupted_addr));
        for m in &got {
            assert!(Evm::verify(&m.address, &m.secret_hex, &m.mnemonic));
        }

        // The counter is honest about work inspected, not work emitted.
        assert_eq!(counter.load(Ordering::Relaxed), N as u64);
        assert_eq!(health.seeds_delivered.load(Ordering::Relaxed), N as u64);
        assert_eq!(health.verify_rejections.load(Ordering::Relaxed), 1);
        assert!(health.disable.load(Ordering::Relaxed), "a verify miss must disable the GPU");
        assert_eq!(
            health.take_reason(),
            Some(GpuDisableReason::VerifyMismatch {
                address: corrupted_addr
            })
        );
    }
```

- [ ] **Step 4: Write the third failing test — stop granularity.** Append this inside the same `mod tests`:

```rust
    /// The stop check is per chunk of C::BATCH * GPU_CHUNK_BATCHES = 64 candidates
    /// (~3.2 ms), and the counter is incremented only AFTER a chunk was actually
    /// inspected — "only what was checked has been counted".
    #[test]
    fn gpu_drain_honours_stop_mid_block() {
        use crate::chains::evm::Evm;
        use crate::gpu::GpuHealth;

        const N: usize = 128;
        let (block, _want) = ring_seed_block(N);

        let matcher = Matcher::new(String::new(), String::new(), false, ChainKind::Evm);
        let stop = AtomicBool::new(true); // already stopped: deterministic, no sleeps
        let counter = AtomicU64::new(0);
        let health = GpuHealth::default();
        let (tx, rx) = mpsc::channel();

        drain_gpu_block::<Evm>(&block, &matcher, &stop, &counter, &tx, &health);
        drop(tx);

        assert_eq!(
            counter.load(Ordering::Relaxed),
            0,
            "a stopped drain must not count candidates it never inspected"
        );
        assert_eq!(health.seeds_delivered.load(Ordering::Relaxed), 0);
        assert!(rx.try_recv().is_err(), "a stopped drain must emit nothing");
    }
```

- [ ] **Step 5: Write the fourth failing test — hybrid with no GPU.** Append this inside the same `mod tests`:

```rust
    /// With `gpu: None`, `search_hybrid` must behave exactly like `search`:
    /// whole CPU batches, honours stop, touches no GPU health counter.
    #[test]
    fn search_with_no_gpu_source_is_unchanged() {
        use crate::chains::evm::Evm;
        use crate::gpu::GpuHealth;

        // Eight hex 'f's cannot occur at the start of an EVM address in 30 ms.
        let matcher = Matcher::new("ffffffff".into(), String::new(), false, ChainKind::Evm);
        let stop = AtomicBool::new(false);
        let counter = AtomicU64::new(0);
        let health = GpuHealth::default();
        let (tx, _rx) = mpsc::channel();
        thread::scope(|s| {
            s.spawn(|| search_hybrid::<Evm>(&matcher, &stop, &counter, &tx, None, &health));
            thread::sleep(Duration::from_millis(30));
            stop.store(true, Ordering::Relaxed);
        });
        let n = counter.load(Ordering::Relaxed);
        assert!(n > 0, "hybrid search with no GPU must still make CPU progress");
        assert_eq!(Evm::BATCH, LANES);
        assert_eq!(n % LANES as u64, 0, "counter advances in whole CPU batches, got {n}");
        assert_eq!(health.seeds_delivered.load(Ordering::Relaxed), 0);
        assert!(!health.disable.load(Ordering::Relaxed));
    }
```

- [ ] **Step 6: Run all four and see them fail.**

```sh
cargo test -- gpu_block_is_consumed_counted_and_cpu_verified corrupted_gpu_seed_raises_fault_and_emits_nothing
```

Expect a compile error, not test failures:

```
error[E0425]: cannot find function `drain_gpu_block` in this scope
```

and, once you also run `cargo test search_with_no_gpu_source_is_unchanged`:

```
error[E0425]: cannot find function `search_hybrid` in this scope
```

- [ ] **Step 7: Import the GPU health types.** In `src/chains/mod.rs`, change lines 9-12 from:

```rust
use super::matcher::Matcher;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::Sender;
```

to:

```rust
use super::matcher::Matcher;
use crate::gpu::{GpuDisableReason, GpuHealth};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::Sender;
```

- [ ] **Step 8: Implement the three functions.** In `src/chains/mod.rs`, insert this immediately after the closing `}` of `pub fn search` and before `#[cfg(test)]`:

```rust
/// Stop check granularity inside a GPU block: 16 × C::BATCH = 64 candidates
/// ≈ 3.2 ms at the measured 50.5 µs tail — comparable to the CPU path's
/// ~1.3 ms, versus 25.9 ms for a whole 512-block.
const GPU_CHUNK_BATCHES: usize = 16;

/// The EVM search loop when a GPU producer may be feeding it. `try_recv` is
/// non-blocking and therefore self-balancing: when the GPU is fast the workers
/// drain it, when the GPU stalls (compositor contention drops it 2–4×) they fall
/// straight through to the CPU batch with no static split to get wrong.
pub fn search_hybrid<C: Bip39GpuChain>(
    matcher: &Matcher,
    stop: &AtomicBool,
    counter: &AtomicU64,
    tx: &Sender<Match>,
    gpu: Option<&crate::gpu::GpuRx>,
    health: &crate::gpu::GpuHealth,
) {
    while !stop.load(Ordering::Relaxed) {
        if let Some(rx) = gpu {
            if !health.disable.load(Ordering::Relaxed) {
                if let Ok(block) = rx.try_recv() {
                    drain_gpu_block::<C>(&block, matcher, stop, counter, tx, health);
                    continue; // block is zeroized on drop
                }
            }
        }
        search_cpu_step::<C>(matcher, counter, tx);
    }
}

fn drain_gpu_block<C: Bip39GpuChain>(
    block: &crate::gpu::SeedBlock,
    matcher: &Matcher,
    stop: &AtomicBool,
    counter: &AtomicU64,
    tx: &Sender<Match>,
    health: &crate::gpu::GpuHealth,
) {
    debug_assert_eq!(block.len() % C::BATCH.max(1), 0);
    for chunk in block.chunks(C::BATCH.max(1) * GPU_CHUNK_BATCHES) {
        if stop.load(Ordering::Relaxed) {
            return; // only what was checked has been counted
        }
        for cand in chunk {
            // The GPU seed is UNTRUSTED and is used only to FILTER.
            let (addr, _gpu_secret) = C::from_gpu_seed(&cand.seed);
            if C::matches_raw(matcher, &addr) {
                emit_gpu_match::<C>(tx, &cand.entropy, &addr, health);
            }
        }
        counter.fetch_add(chunk.len() as u64, Ordering::Relaxed);
        health
            .seeds_delivered
            .fetch_add(chunk.len() as u64, Ordering::Relaxed);
    }
}

fn emit_gpu_match<C: Bip39GpuChain>(
    tx: &Sender<Match>,
    entropy: &[u8; 16],
    gpu_addr: &C::AddressBytes,
    health: &GpuHealth,
) {
    match crate::verify::verify_gpu::<C>(entropy, gpu_addr) {
        Some((addr, secret, phrase, proof)) => {
            // Everything written here is the CPU-derived value, never the
            // GPU-derived one.
            let _ = tx.send(Match {
                chain: C::LABEL.to_string(),
                address: C::encode_address(&addr),
                secret_hex: C::encode_secret(&secret),
                mnemonic: phrase,
                verified: proof,
            });
        }
        None => {
            // A GPU seed that MATCHED the pattern but does not re-derive is a
            // GPU fault, never a false positive. Disable the GPU, keep the CPU
            // search alive, and surface it. The candidate is dropped — it is
            // provably not a wallet anyone can open, so there is nothing to save.
            health.verify_rejections.fetch_add(1, Ordering::Relaxed);
            health.raise(GpuDisableReason::VerifyMismatch {
                address: C::encode_address(gpu_addr),
            });
        }
    }
}
```

- [ ] **Step 9: Run the four tests and see them pass.**

```sh
cargo test gpu_block_is_consumed_counted_and_cpu_verified
cargo test corrupted_gpu_seed_raises_fault_and_emits_nothing
cargo test gpu_drain_honours_stop_mid_block
cargo test search_with_no_gpu_source_is_unchanged
```

All four must print `... ok`.

- [ ] **Step 10: Run the whole suite, including the untouched pinned test.**

```sh
cargo test
```

Expect `test result: ok.` with zero failures, including
`chains::tests::search_counts_whole_batches_and_honours_stop`.

- [ ] **Step 11: Format the touched file and compare clippy against the baseline.**
This task edited only `src/chains/mod.rs`, which is pre-existing: do NOT run bare
`cargo fmt`, and do NOT run `rustfmt` in write mode on it — it follows `mod`
declarations and would reformat all of `src/chains/*`. Match the surrounding style by
hand, then:

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy \
  && printf 'src/chains/mod.rs %s\n' "$(rustfmt --edition 2021 --check src/chains/mod.rs 2>/dev/null | grep -c '^Diff in .*/src/chains/mod.rs:')" \
  && cargo clippy --all-targets 2>&1 | grep -- '-->' | sort | uniq -c
```

Expected: `src/chains/mod.rs 1` — the pre-existing count from this milestone's
preamble — then exactly the 12 pre-existing clippy lines listed in that preamble and
no others. `search_hybrid` and `drain_gpu_block` each take six arguments; clippy's
`too_many_arguments` threshold is seven, so neither adds a 13th line.

- [ ] **Step 12: Commit.**

```sh
git add src/chains/mod.rs
git commit -m "feat(chains): add search_hybrid, drain_gpu_block and the emit gate

drain_gpu_block checks stop every 64 candidates and increments the counter only
after a chunk was inspected. emit_gpu_match routes every matching GPU candidate
through verify_gpu: on agreement it sends the CPU-derived address, secret and
phrase; on disagreement it raises VerifyMismatch, disables the GPU and drops the
candidate, leaving the CPU search running. Proven end-to-end with SeedBlocks
built from ring-derived seeds - no Metal in the tree yet.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 2.5: `open_csv_secure(path)` and `append_match_row` — the single writer, still 0600

**Files:**
- Modify: `Cargo.toml` (add `[dev-dependencies]`)
- Modify: `src/app.rs` (imports lines 6-13; `start_search` line 240; `drain_matches` lines 272-290; `open_csv_secure` lines 293-317)
- Test: `src/app.rs` (`mod tests` at lines 556-585)

**Interfaces:**
- Consumes: `Match` with its `verified` field (Task 2.2); `Bip39GpuChain::verify` (Task 2.1); `crate::verify::verify_gpu::<Evm>` (Task 2.3); `pub fn chains::search<C>` (unchanged)
- Produces:
  - `const CSV_PATH: &str = "vanity_wallets.csv";`
  - `fn open_csv_secure(path: &Path) -> io::Result<File>`
  - `fn append_match_row(path: &Path, m: &Match) -> io::Result<()>`

- [ ] **Step 1: Add the `tempfile` dev-dependency.** Append to `Cargo.toml`, after the `[dependencies]` block:

```toml

[dev-dependencies]
tempfile = "3"
```

Then confirm it resolves:

```sh
cargo fetch
```

- [ ] **Step 2: Write the failing 0600 test.** Append this inside `mod tests` in `src/app.rs`, before the module's closing `}` (line 585):

```rust
    /// The CSV holds plaintext seed phrases. Both halves of the 0600 guarantee
    /// must survive: `.mode(0o600)` on create AND the post-open `set_permissions`
    /// re-assert, which is the half that catches a pre-existing loose file.
    #[test]
    #[cfg(unix)]
    fn open_csv_secure_reasserts_0600_on_preexisting_0644() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vanity_wallets.csv");
        std::fs::write(&path, b"Chain,Address,Private Key (hex),Seed Phrase\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o644,
            "precondition: the file starts world-readable"
        );

        let file = open_csv_secure(&path).expect("open must succeed");
        drop(file);

        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600,
            "a pre-existing loose-permission CSV must be tightened on every open"
        );
    }

    /// A `Match` cannot exist without a `verify::Verified`, so `append_match_row`
    /// is structurally unable to write an unverified row. Assert the consequence:
    /// what lands on disk re-derives, and the file is 0600.
    #[test]
    #[cfg(unix)]
    fn verified_match_is_written_and_file_is_0600() {
        use crate::chains::evm::Evm;
        use crate::chains::Bip39GpuChain;
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vanity_wallets.csv");

        let m = one_cpu_match();
        append_match_row(&path, &m).expect("append must succeed");

        let mut rdr = csv::ReaderBuilder::new()
            .has_headers(false)
            .from_path(&path)
            .unwrap();
        let rows: Vec<csv::StringRecord> = rdr.records().map(|r| r.unwrap()).collect();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].len(), 4);
        assert_eq!(&rows[0][0], "EVM");
        assert_eq!(&rows[0][1], m.address.as_str());
        assert!(
            Evm::verify(&rows[0][1], &rows[0][2], &rows[0][3]),
            "every CSV row must re-derive from its own phrase"
        );
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    /// The gate's end-to-end consequence: a GPU candidate whose seed carries one
    /// flipped bit is rejected by `verify_gpu`, so no `Match` is ever minted for
    /// it, so its address cannot appear in the file. Every row that IS there
    /// re-derives.
    #[test]
    #[cfg(unix)]
    fn unverified_match_is_never_written_to_csv() {
        use crate::chains::evm::Evm;
        use crate::chains::{Bip39GpuChain, Chain};
        use bip39::{Language, Mnemonic};
        use std::os::unix::fs::PermissionsExt;

        // Deterministic entropy so a red build replays exactly.
        let mut entropy = [0u8; 16];
        entropy[15] = 77;
        let mn = Mnemonic::from_entropy(&entropy, Language::English).unwrap();
        let mut seed = crate::seed::derive_seed(&mn);
        seed[0] ^= 0x01; // exactly what a faulty kernel would produce
        let (bad_addr, _sk) = Evm::from_gpu_seed(&seed);
        let bad_address = Evm::encode_address(&bad_addr);

        assert!(
            crate::verify::verify_gpu::<Evm>(&entropy, &bad_addr).is_none(),
            "the gate must reject a corrupted GPU seed, so no Match can be minted"
        );

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vanity_wallets.csv");
        // Write everything the gate DID accept.
        let good = one_cpu_match();
        append_match_row(&path, &good).expect("append must succeed");

        let body = std::fs::read_to_string(&path).unwrap();
        assert!(
            !body.contains(&bad_address),
            "a rejected candidate must never reach the CSV"
        );
        let mut rdr = csv::ReaderBuilder::new()
            .has_headers(false)
            .from_path(&path)
            .unwrap();
        for rec in rdr.records() {
            let r = rec.unwrap();
            assert!(
                Evm::verify(&r[1], &r[2], &r[3]),
                "every CSV row must re-derive: {}",
                &r[1]
            );
        }
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    /// One genuine CPU-path match, produced by the real `search` loop so the
    /// `Verified` token is minted at its real site rather than forged here
    /// (which is impossible — the field is private to `crate::verify`).
    #[cfg(unix)]
    fn one_cpu_match() -> Match {
        use crate::chains::evm::Evm;
        use crate::chains::search;

        // Empty prefix and suffix accept every address, so the very first batch
        // emits.
        let matcher = Matcher::new(String::new(), String::new(), false, ChainKind::Evm);
        let stop = AtomicBool::new(false);
        let counter = AtomicU64::new(0);
        let (tx, rx) = mpsc::channel();
        thread::scope(|s| {
            s.spawn(|| search::<Evm>(&matcher, &stop, &counter, &tx));
            let m = rx.recv().expect("CPU search must emit for an empty pattern");
            stop.store(true, Ordering::Relaxed);
            m
        })
    }
```

- [ ] **Step 3: Run them and see them fail.**

```sh
cargo test -- open_csv_secure_reasserts_0600_on_preexisting_0644 unverified_match_is_never_written_to_csv verified_match_is_written_and_file_is_0600
```

Expect compile errors, not test failures:

```
error[E0425]: cannot find function `append_match_row` in this scope
error[E0061]: this function takes 0 arguments but 1 argument was supplied
```

(the second on `open_csv_secure(&path)`).

- [ ] **Step 4: Widen the `std` imports.** In `src/app.rs`, replace lines 6-13:

```rust
use std::{
    fs::OpenOptions,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc, Arc,
    },
    time::Instant,
};
```

with:

```rust
use std::{
    fs::{File, OpenOptions},
    io,
    path::Path,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc, Arc,
    },
    time::Instant,
};
```

- [ ] **Step 5: Give `open_csv_secure` a path parameter and add `CSV_PATH`.** In `src/app.rs`, replace the whole of the current function (lines 293-317):

```rust
/// Open `vanity_wallets.csv` for append, creating it with mode 0o600 on Unix
/// and re-asserting 0o600 on every open in case a pre-existing file had looser
/// permissions. The file holds plaintext seed phrases, so this is the single
/// chokepoint for that security guarantee — all writers MUST go through here.
fn open_csv_secure() -> std::io::Result<std::fs::File> {
    const PATH: &str = "vanity_wallets.csv";
    let mut opts = OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let file = opts.open(PATH)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(metadata) = file.metadata() {
            let mut perms = metadata.permissions();
            perms.set_mode(0o600);
            let _ = std::fs::set_permissions(PATH, perms);
        }
    }
    Ok(file)
}
```

with:

```rust
/// The one CSV every production caller writes to.
const CSV_PATH: &str = "vanity_wallets.csv";

/// Open the CSV at `path` for append, creating it with mode 0o600 on Unix and
/// re-asserting 0o600 on every open in case a pre-existing file had looser
/// permissions. The file holds plaintext seed phrases, so this is the single
/// chokepoint for that security guarantee — all writers MUST go through here.
///
/// `path` is a parameter rather than the `CSV_PATH` constant so the permission
/// tests can use a temp dir: `cargo test` runs tests as threads in one process,
/// so `set_current_dir` is racy, and `start_stop_restart_does_not_leak_threads`
/// already writes the real CSV into the repo root.
fn open_csv_secure(path: &Path) -> io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let file = opts.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(metadata) = file.metadata() {
            let mut perms = metadata.permissions();
            perms.set_mode(0o600);
            let _ = std::fs::set_permissions(path, perms);
        }
    }
    Ok(file)
}

/// The SINGLE writer of match rows. It takes a `&Match`, and a `Match` cannot be
/// constructed without a `crate::verify::Verified` token, so an unverified
/// candidate is unrepresentable here rather than merely filtered out.
fn append_match_row(path: &Path, m: &Match) -> io::Result<()> {
    let file = open_csv_secure(path)?;
    let mut wtr = WriterBuilder::new().has_headers(false).from_writer(file);
    wtr.write_record([&m.chain, &m.address, &m.secret_hex, &m.mnemonic])?;
    wtr.flush()?;
    Ok(())
}
```

- [ ] **Step 6: Update the header writer.** In `src/app.rs`, change line 240 inside `start_search` from:

```rust
            let file = open_csv_secure().expect("Failed to open vanity_wallets.csv");
```

to:

```rust
            let file = open_csv_secure(Path::new(CSV_PATH)).expect("Failed to open vanity_wallets.csv");
```

- [ ] **Step 7: Route `drain_matches` through the single writer.** In `src/app.rs`, replace `drain_matches` (lines 272-290):

```rust
    pub fn drain_matches(&mut self) {
        if let Some(ref rx) = self.rx {
            while let Ok(payload) = rx.try_recv() {
                if let Ok(file) = open_csv_secure() {
                    let mut wtr = WriterBuilder::new().has_headers(false).from_writer(file);
                    let _ = wtr.write_record([
                        &payload.chain,
                        &payload.address,
                        &payload.secret_hex,
                        &payload.mnemonic,
                    ]);
                    let _ = wtr.flush();
                }

                self.matches.push(payload);
                self.selected_match = self.matches.len().saturating_sub(1);
            }
        }
    }
```

with:

```rust
    pub fn drain_matches(&mut self) {
        if let Some(ref rx) = self.rx {
            while let Ok(payload) = rx.try_recv() {
                // append_match_row is the only writer; it re-asserts 0600 on
                // every open and cannot be handed anything unverified.
                let _ = append_match_row(Path::new(CSV_PATH), &payload);
                self.matches.push(payload);
                self.selected_match = self.matches.len().saturating_sub(1);
            }
        }
    }
```

- [ ] **Step 8: Run the three new tests and see them pass.**

```sh
cargo test open_csv_secure_reasserts_0600_on_preexisting_0644
cargo test verified_match_is_written_and_file_is_0600
cargo test unverified_match_is_never_written_to_csv
```

All three must print `... ok`.

- [ ] **Step 9: Run the whole suite, including the pre-existing lifecycle test.**

```sh
cargo test
```

Expect `test result: ok.` with zero failures, including
`app::tests::start_stop_restart_does_not_leak_threads` (`src/app.rs:564`), which is
untouched and still writes the real repo-root CSV.

- [ ] **Step 10: Format the touched file and compare clippy against the baseline.**
This task edited `src/app.rs` (pre-existing) and `Cargo.toml`. Do NOT run bare
`cargo fmt`. Match the surrounding style by hand, then:

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy \
  && printf 'src/app.rs %s\n' "$(rustfmt --edition 2021 --check src/app.rs 2>/dev/null | grep -c '^Diff in .*/src/app.rs:')" \
  && cargo clippy --all-targets 2>&1 | grep -- '-->' | sort | uniq -c
```

Expected: `src/app.rs 11` — the pre-existing count from this milestone's preamble —
then exactly the 12 pre-existing clippy lines listed in that preamble and no others.
Their `src/app.rs` line numbers WILL have shifted, because this task inserted
`CSV_PATH` and `append_match_row` above them; the count of 12 is what must not change.

- [ ] **Step 11: Confirm the release build is clean.**

```sh
cargo build --release
```

Expect `Finished \`release\` profile` with no warnings.

- [ ] **Step 12: Commit.**

```sh
git add Cargo.toml Cargo.lock src/app.rs
git commit -m "feat(app): make append_match_row the single CSV writer, path-parameterised

open_csv_secure gains a &Path so the permission tests can use a temp dir -
cargo test runs tests as threads in one process, so set_current_dir is racy.
Both halves of the 0600 guarantee are preserved verbatim: .mode(0o600) on create
and the post-open set_permissions re-assert. append_match_row takes a &Match,
which cannot be constructed without a verify::Verified token, so an unverified
row is unrepresentable rather than merely unwritten.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Milestone 2 exit check

- [ ] **Step 1: Full suite, default features.**

```sh
cargo test 2>&1 | tail -20
```

Expect `test result: ok.` with zero failures. Every pinned vector in CLAUDE.md must
still be listed as `ok`, in particular `seed::derive_seed_matches_bip39_vector`,
`evm::bip44_canonical_vector`, and
`evm::generate_batch_emits_lane_count_candidates_matching_single_path`.

- [ ] **Step 2: Full suite with the GPU compiled out.**

```sh
cargo test --no-default-features 2>&1 | tail -20
```

Expect `test result: ok.` — this milestone adds no target-gated code, so the two
legs must be identical.

- [ ] **Step 3: Confirm the trust boundary is fully covered with no Metal in the tree.**

```sh
cargo test -- verify_gpu_ gpu_block_is_consumed corrupted_gpu_seed gpu_drain_honours_stop search_with_no_gpu_source unverified_match_is_never_written open_csv_secure_reasserts verified_match_is_written verify_source_pins cpu_step_emits_matches from_gpu_seed_and_verify
```

Expect every one of these to run and pass.

**Also assert that no filter matched zero tests.** A libtest filter that matches nothing
contributes zero tests and still reports `ok`, so a renamed test silently shrinks this
gate instead of failing it. (Not hypothetical: `verified_token_field_is_private` was
renamed to `verify_source_pins_the_private_field_declaration` during Task 2.2's fix round,
and this gate ran 11 tests while naming 12 until it was corrected.) Rather than pinning a
count that every later task invalidates, check each filter individually:

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy
for f in verify_gpu_ gpu_block_is_consumed corrupted_gpu_seed gpu_drain_honours_stop \
         search_with_no_gpu_source unverified_match_is_never_written \
         open_csv_secure_reasserts verified_match_is_written verify_source_pins \
         cpu_step_emits_matches from_gpu_seed_and_verify; do
  out=$(cargo test -- "$f" 2>&1)
  n=$(printf '%s\n' "$out" | sed -n 's/^test result: ok\. \([0-9]*\) passed.*/\1/p')
  if [ "${n:-0}" -gt 0 ]; then echo "OK   $f -> $n"; else echo "DEAD $f -> 0"; fi
done
```

Expected: every line starts `OK`. Any `DEAD` line names a filter whose test was renamed
or removed — fix the filter, never the expectation. (Capture `cargo`'s output into a
variable first, as above; piping `cargo test` straight into `sed` inside the loop
misreports every filter as DEAD.)

- [ ] **Step 4: Confirm no Metal dependency was introduced.**

```sh
grep -rn "objc2\|MTLDevice\|include_str!(\"pbkdf2" src/ Cargo.toml || echo "no Metal in the tree yet - correct for milestone 2"
```

Expect the `echo` branch.
## Milestone 3 — The Metal backend, offline (no TUI wiring)

**What exists when you start.** Milestone 1 created:

- `src/gpu/mod.rs` — the constants from the contract, `GpuCandidate`,
  `SeedBlock`, `GpuError`, `GpuStatus`, `GpuDisableReason`, `GpuHealth`, a
  placeholder `#[path = "stub.rs"] mod backend;` with
  `pub use backend::{probe, GpuEngine};` — the design spec's re-export form, written
  that way from the start, so there is **no** module-level `probe` wrapper for this
  milestone to delete (the brace order is rustfmt's; `src/gpu/mod.rs` is
  rustfmt-clean and must stay so). `src/gpu/stub.rs` accordingly defines a **free**
  `pub fn probe()` plus an `impl GpuEngine { pub fn probe() }` that delegates to it,
  so the two spellings cannot diverge. There is a
  `const _: fn() = …` Send+Sync pin naming `GpuEngine`, `SeedBlock` and
  `GpuHealth`, the declarations `pub mod selftest;` and
  `pub use selftest::SelfTestError;`, and the test
  `stub_backend_reports_unavailable`;
- `src/gpu/pack.rs` — `KeyBlock`, `pack_key_block`, `pack_salt_block`, and the
  test `salt_block_rejects_a_salt_longer_than_max_salt_len`;
- `src/gpu/stub.rs` — a placeholder uninhabited `GpuEngine` (`_never: Infallible`);
- `src/gpu/selftest.rs` — the `SelfTestError` taxonomy **only**; there is no
  `self_test` function yet.

It also added `pub mod gpu;` to `src/main.rs` and made
`crate::seed::{PBKDF2_ROUNDS, BIP39_SALT}` and
`crate::pbkdf2_lanes::{HMAC_BLOCK_LEN, MAX_SALT_LEN}` public. Milestone 2 created
`src/verify.rs` and `[dev-dependencies] tempfile = "3"`.

Two files this milestone touches therefore already exist: `src/gpu/stub.rs` and
`src/gpu/selftest.rs`. Tasks 3.3 and 3.10 **overwrite or extend** them — they do
not create them, and re-declaring `pub mod selftest;` or
`pub use selftest::SelfTestError;` is `error[E0428]`/`error[E0252]`.

**What this milestone adds.** The Metal kernel file, the Metal backend, the
portable stub backend, the injectable self-test, and the `metal` cargo feature.
Nothing here touches the TUI, spawns a thread, or changes any existing
derivation path. Every one of the 63 pre-existing tests must still pass, by
name, after every task.

**Two things about the tests in this milestone that you must not "improve".**

1. *GPU tests skip gracefully off Apple Silicon, and are LOUD on it.*
   `src/gpu/metal.rs` is compiled only under
   `all(target_os = "macos", target_arch = "aarch64", feature = "metal")`, so on
   Linux, on Intel macs, and under `--no-default-features` the GPU tests do not
   exist — that is the skip. On a machine where the backend *does* ship, a
   silent skip is the dangerous case: it means the differential never ran and a
   broken kernel reaches a user's wallet with a green suite. So `gpu_for_test()`
   skips for exactly one reason (`GpuError::NoDevice` — a headless VM or CI box)
   or when `VANADDY_NO_GPU=1` is set deliberately, and **panics** on every other
   failure.
2. *Some tests here are guards, not drivers.* A guard test passes the moment it
   is written. TDD still applies: every guard task below tells you to mutate the
   implementation, run the test, read the exact failure, and revert. A guard you
   have never seen fail is not a guard.

**Formatting and lints in this milestone.** **Never run bare `cargo fmt`.** The
tree is not rustfmt-clean at this branch's HEAD, so `cargo fmt` would bury the
branch under an unrelated whole-tree reformat and would make Milestone 1 Task 1.8
Step 8's "in particular no `src/app.rs`, `src/ui.rs`, or `src/chains/*`"
permanently false. Format only the files the task touched, by path:

```sh
rustfmt --edition 2021 <the files this task created or edited>
```

Equally, `cargo clippy --all-targets` is **not** warning-free on the clean
baseline: it emits exactly 12 diagnostics, all in files this branch does not own
(`src/app.rs`, `src/ui.rs`, `src/chains/bitcoin.rs`, `src/chains/evm.rs`,
`src/chains/ton_cell.rs`). Those 12 are out of scope. The gate every task below
uses is therefore a delta, never an absolute:

```sh
cargo clippy --all-targets 2>&1 | grep -c -- '-->'
cargo clippy --all-targets 2>&1 | grep -c -- '--> src/gpu/' || true
```

Expected: `12` and `0`. If the first number moves, this task introduced (or
silenced) a diagnostic; if the second is non-zero, the new code is at fault.

---

### Task 3.1: Embed the Metal kernel source and pin what it may contain

**Files:**
- Create: `src/gpu/pbkdf2_bip39.metal` (copied from `docs/superpowers/specs/prototype/pbkdf2_bip39.metal`)
- Create: `src/gpu/kernel_src.rs`
- Modify: `src/gpu/mod.rs` (append one module declaration)

**Interfaces:**
- Consumes: nothing.
- Produces: `pub const crate::gpu::kernel_src::KERNEL_SRC: &str`

The kernel is copied **verbatim** from the prototype that was independently
re-validated (SHA-512("abc") correct; the BIP-39 canonical vector reproduced
under six chunk schedules including irregular ones; 2,048 distinct passwords of
length 1–128 matched CommonCrypto with 0 mismatches), minus the measurement-only
`pbkdf2_iterate_noacc` A/B kernel, which exists solely to measure the register
cost of carrying the `T` accumulator and must not ship.

`KERNEL_SRC` lives in a module compiled on **every** target — not inside the
`metal`-gated backend — so the two source-grep guards below run on Linux and
under `--no-default-features` too. The invariants they pin are properties of the
text, not of any GPU.

- [ ] **Step 1: Create `src/gpu/kernel_src.rs` with the constant and its three guards.**

```rust
//! The Metal kernel source, embedded at compile time.
//!
//! Declared HERE — in a module compiled on every target — rather than inside
//! the `metal`-gated backend, so the source guards below run on Linux and
//! under `--no-default-features` as well. What they pin is a property of the
//! text, not of any GPU.

pub const KERNEL_SRC: &str = include_str!("pbkdf2_bip39.metal");

#[cfg(test)]
mod tests {
    use super::KERNEL_SRC;

    /// Every line of the kernel that mentions the identifier `tid`, exactly as
    /// it appears in the file.
    ///
    /// `thread_position_in_grid` is the GPU's per-thread lane id. Used as a
    /// slot offset it is correct and necessary; used as anything else it
    /// becomes key material. The bench scaffolding at `scratchpad/gpu/k2.metal:183`
    /// did exactly that (`ipad[i] = H0[i] ^ (ulong)tid`) — code of that shape
    /// passes every address test while making every wallet the tool ever emits
    /// recoverable from one 64-bit value. An exact-line allowlist is the point:
    /// any new use of `tid`, however innocent-looking, has to come through a
    /// deliberate edit to this list.
    const TID_ALLOWLIST: &[&str] = &[
        // Kernel parameter declarations — the only place the attribute appears.
        "uint tid [[thread_position_in_grid]])",
        "kernel void sha512_abc(device ulong *out [[buffer(0)]], uint tid [[thread_position_in_grid]]) {",
        // Bounds guard: threads past the live count of the wave do nothing.
        "if (tid >= p.count) return;",
        // Lane guard: only lane 0 publishes the self-test digest.
        "if (tid==0) for (uint i=0;i<8;i++) out[i]=st[i];",
        // Slot offsets: base + stride * tid, and nothing else.
        "device const ulong *kb = keyblocks + 16 * (ulong)tid;",
        "device Pbkdf2State *s = states + tid;",
        "device uchar *o = seeds + 64 * (ulong)tid;",
    ];

    /// True when `line` contains `tid` as a whole identifier (so `Pbkdf2State`
    /// and similar do not count).
    fn mentions_tid(line: &str) -> bool {
        let b = line.as_bytes();
        let mut i = 0;
        while let Some(p) = line[i..].find("tid") {
            let s = i + p;
            let e = s + 3;
            let before_ok = s == 0 || !(b[s - 1].is_ascii_alphanumeric() || b[s - 1] == b'_');
            let after_ok = e == b.len() || !(b[e].is_ascii_alphanumeric() || b[e] == b'_');
            if before_ok && after_ok {
                return true;
            }
            i = e;
        }
        false
    }

    /// Every thread is an independent PBKDF2 with zero cross-thread
    /// communication. Banning these four tokens eliminates the
    /// uninitialised-shared-memory and missing-barrier bug classes by
    /// construction rather than by review.
    #[test]
    fn kernel_source_bans_threadgroup_simd_barrier_atomic() {
        for banned in ["threadgroup", "simd_", "barrier", "atomic"] {
            assert!(
                !KERNEL_SRC.contains(banned),
                "banned `{banned}` present in src/gpu/pbkdf2_bip39.metal"
            );
        }
    }

    #[test]
    fn kernel_source_uses_tid_only_in_index_expressions() {
        let mut seen = 0usize;
        for (n, line) in KERNEL_SRC.lines().enumerate() {
            if !mentions_tid(line) {
                continue;
            }
            seen += 1;
            let t = line.trim();
            assert!(
                TID_ALLOWLIST.contains(&t),
                "src/gpu/pbkdf2_bip39.metal line {}: `{t}` uses `tid` outside the allowlist",
                n + 1
            );
        }
        assert_eq!(seen, 10, "expected exactly 10 lines mentioning `tid`");
        assert_eq!(
            KERNEL_SRC.matches("thread_position_in_grid").count(),
            3,
            "`thread_position_in_grid` may appear only in the three kernel parameter lists"
        );
    }

    #[test]
    fn kernel_source_declares_exactly_the_two_shipped_kernels_plus_the_sha_probe() {
        assert_eq!(KERNEL_SRC.matches("kernel void ").count(), 3);
        assert!(KERNEL_SRC.contains("kernel void pbkdf2_prologue("));
        assert!(KERNEL_SRC.contains("kernel void pbkdf2_iterate("));
        assert!(KERNEL_SRC.contains("kernel void sha512_abc("));
        assert!(
            !KERNEL_SRC.contains("pbkdf2_iterate_noacc"),
            "the measurement-only A/B kernel must not ship"
        );
    }
}
```

- [ ] **Step 2: Declare the module.** Append to the end of `src/gpu/mod.rs`:

```rust
pub mod kernel_src;
```

- [ ] **Step 3: Run the tests and watch them fail because the kernel file does not exist yet.**

```sh
cargo test kernel_source
```

Expected failure, verbatim:

```
error: couldn't read `src/gpu/pbkdf2_bip39.metal`: No such file or directory (os error 2)
 --> src/gpu/kernel_src.rs:8:30
```

- [ ] **Step 4: Copy the kernel verbatim, dropping the A/B kernel.** From the repo root:

```sh
awk '/^\/\/ A\/B ONLY \(not shipped\)/{exit} {print}' \
  docs/superpowers/specs/prototype/pbkdf2_bip39.metal > src/gpu/pbkdf2_bip39.metal
```

- [ ] **Step 5: Verify the copy is byte-exact.**

```sh
wc -l -c < src/gpu/pbkdf2_bip39.metal
shasum -a 256 src/gpu/pbkdf2_bip39.metal
```

Expected, exactly:

```
     179    7631
871ef1706bd5ba0a9ddb420872ea6a2db3556bf6951453942678d364b123f4b2  src/gpu/pbkdf2_bip39.metal
```

If the hash differs, the copy is wrong — do not continue. Re-run Step 4.

- [ ] **Step 6: Run the tests and watch them pass.**

```sh
cargo test kernel_source
```

Expected: `test result: ok. 3 passed`.

- [ ] **Step 7: Prove the guards actually bite (they are guards, not drivers).** Temporarily corrupt the kernel:

```sh
printf '// threadgroup ulong scratch[256];\n' >> src/gpu/pbkdf2_bip39.metal
sed -i '' 's|^    ulong w\[16\], ist\[8\], ost\[8\], st\[8\], u\[8\];|    ulong w[16], ist[8], ost[8], st[8], u[8]; ist[0] ^= (ulong)tid;|' src/gpu/pbkdf2_bip39.metal
cargo test kernel_source
```

Expected failures, verbatim (two tests fail):

```
thread 'gpu::kernel_src::tests::kernel_source_bans_threadgroup_simd_barrier_atomic' panicked at src/gpu/kernel_src.rs:
banned `threadgroup` present in src/gpu/pbkdf2_bip39.metal
```

```
thread 'gpu::kernel_src::tests::kernel_source_uses_tid_only_in_index_expressions' panicked at src/gpu/kernel_src.rs:
src/gpu/pbkdf2_bip39.metal line 104: `ulong w[16], ist[8], ost[8], st[8], u[8]; ist[0] ^= (ulong)tid;` uses `tid` outside the allowlist
```

- [ ] **Step 8: Revert the corruption and confirm green again.**

```sh
awk '/^\/\/ A\/B ONLY \(not shipped\)/{exit} {print}' \
  docs/superpowers/specs/prototype/pbkdf2_bip39.metal > src/gpu/pbkdf2_bip39.metal
shasum -a 256 src/gpu/pbkdf2_bip39.metal
cargo test kernel_source
```

Expected: the hash is `871ef170…` again and `test result: ok. 3 passed`.

- [ ] **Step 9: Full suite, formatting and lints.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy
rustfmt --edition 2021 src/gpu/kernel_src.rs src/gpu/mod.rs
cargo clippy --all-targets 2>&1 | grep -c -- '-->'
cargo clippy --all-targets 2>&1 | grep -c -- '--> src/gpu/' || true
cargo test
```

Expected: the first clippy count is `12` — the pre-existing baseline recorded in
Milestone 1 Task 1.8 Step 5, unchanged by this task — and the second is `0`, i.e.
this task added no diagnostic of its own. Do **not** write "expect no warnings":
`cargo clippy --all-targets` is not clean on this tree. All pre-existing tests
still pass by name.

- [ ] **Step 10: Commit.**

```sh
git add src/gpu/pbkdf2_bip39.metal src/gpu/kernel_src.rs src/gpu/mod.rs
git commit -m "gpu: embed the Metal PBKDF2 kernel and pin its source invariants

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 3.2: Finalise `GpuError` and add the portable command-buffer status rule

**Files:**
- Modify: `src/gpu/mod.rs` (replace the `GpuError` definition Milestone 1 added; append `classify_command_buffer_status`, the `From` impl, and a test module)

**Interfaces:**
- Consumes: `pub enum GpuDisableReason` (Milestone 1); `pub const crate::pbkdf2_lanes::MAX_SALT_LEN: usize` (Milestone 1)
- Produces:
  - `pub enum GpuError { NoDevice, ShaderCompile(String), PipelineCreate(String), BufferAlloc, BadConfig(String), SaltTooLong { len: usize }, CommandBuffer { status: i64, message: String } }`
  - `pub fn classify_command_buffer_status(status: i64, message: Option<String>) -> Result<(), GpuError>`
  - `impl From<GpuError> for GpuDisableReason`

`classify_command_buffer_status` is a pure function taking an `i64` and an
`Option<String>` rather than a `&MTLCommandBuffer`, for one reason: the rule it
encodes — *anything that is not `Completed` with a nil error kills the whole
wave* — is the rule that keeps a mid-wave GPU reset from silently dropping 8 of
2048 U-iterations and finalizing a `T` that is the XOR of only 2,039 values, i.e.
a wrong-but-plausible seed. That rule deserves a test on every platform, not
only on the one machine with a GPU.

- [ ] **Step 1: Write the failing tests.** Append to `src/gpu/mod.rs`:

```rust
#[cfg(test)]
mod command_buffer_status_tests {
    use super::{classify_command_buffer_status, GpuError};

    /// MTLCommandBufferStatusCompleted == 4.
    #[test]
    fn completed_with_no_error_is_the_only_success() {
        assert_eq!(classify_command_buffer_status(4, None), Ok(()));
    }

    #[test]
    fn completed_with_an_error_is_a_failure() {
        assert_eq!(
            classify_command_buffer_status(4, Some("IOAF code 4".to_string())),
            Err(GpuError::CommandBuffer {
                status: 4,
                message: "IOAF code 4".to_string()
            })
        );
    }

    /// NotEnqueued(0), Enqueued(1), Committed(2), Scheduled(3), Error(5) are
    /// all failures — a wave that is merely `Scheduled` has not written `seeds`.
    #[test]
    fn every_other_status_is_a_failure_even_with_no_error_object() {
        for status in [0i64, 1, 2, 3, 5, 99] {
            let got = classify_command_buffer_status(status, None);
            assert_eq!(
                got,
                Err(GpuError::CommandBuffer {
                    status,
                    message: format!("command buffer finished with status {status}")
                }),
                "status {status}"
            );
        }
    }
}
```

- [ ] **Step 2: Run it and watch it fail.**

```sh
cargo test command_buffer_status_tests
```

Expected failure, verbatim:

```
error[E0432]: unresolved import `super::classify_command_buffer_status`
```

- [ ] **Step 3: Replace the `GpuError` definition in `src/gpu/mod.rs` with its final shape.** Milestone 1 introduced `GpuError` with at least `SaltTooLong { len: usize }` for `pack_salt_block`. Replace the whole definition with this superset — `SaltTooLong` is unchanged, so `src/gpu/pack.rs` and its tests keep compiling untouched:

```rust
/// Every way the GPU backend can fail. One shape for all of them, because
/// there is exactly one response: raise it as a sticky `GpuDisableReason`,
/// drop the wave, and let the CPU search continue at full CPU-only rate.
/// There is deliberately no partial-success variant.
#[derive(Debug, Clone, PartialEq)]
pub enum GpuError {
    /// `MTLCreateSystemDefaultDevice()` returned nil.
    NoDevice,
    /// `newLibraryWithSource:` failed; carries the Metal compiler diagnostic.
    ShaderCompile(String),
    /// A kernel function was missing, or pipeline creation failed.
    PipelineCreate(String),
    /// A queue, command buffer, encoder, or `MTLBuffer` allocation returned nil.
    BufferAlloc,
    /// The host asked the backend for something it will not do.
    BadConfig(String),
    /// Mirrors the CPU salt assert at src/pbkdf2_lanes.rs:21-25.
    SaltTooLong { len: usize },
    /// A command buffer finished as anything other than Completed-with-nil-error.
    CommandBuffer { status: i64, message: String },
}

/// A command buffer is acceptable **only** when it reports Completed (status 4)
/// AND its `error()` is nil. Anything else discards the whole wave.
///
/// Split out as a pure function so this rule is tested on every platform, not
/// only on a machine with a GPU. Without it, a mid-wave GPU reset — macOS
/// resets a hung GPU after ~5 s and `waitUntilCompleted` returns rather than
/// hanging — silently drops 8 of 2048 U-iterations, and finalize writes a `T`
/// that is the XOR of only 2,039 values: a wrong-but-plausible seed with
/// nothing surfaced anywhere.
pub fn classify_command_buffer_status(status: i64, message: Option<String>) -> Result<(), GpuError> {
    const COMPLETED: i64 = 4;
    if status == COMPLETED && message.is_none() {
        return Ok(());
    }
    Err(GpuError::CommandBuffer {
        status,
        message: message.unwrap_or_else(|| format!("command buffer finished with status {status}")),
    })
}

impl From<GpuError> for GpuDisableReason {
    fn from(e: GpuError) -> Self {
        match e {
            GpuError::NoDevice => GpuDisableReason::NoDevice,
            GpuError::ShaderCompile(m) => GpuDisableReason::ShaderCompile(m),
            GpuError::PipelineCreate(m) => GpuDisableReason::PipelineCreate(m),
            GpuError::BufferAlloc => GpuDisableReason::BufferAlloc,
            GpuError::BadConfig(m) => GpuDisableReason::BadConfig(m),
            GpuError::SaltTooLong { len } => GpuDisableReason::BadConfig(format!(
                "salt is {len} bytes, at most {} fit one padded block",
                crate::pbkdf2_lanes::MAX_SALT_LEN
            )),
            GpuError::CommandBuffer { status, message } => {
                GpuDisableReason::CommandBuffer { status, message }
            }
        }
    }
}
```

- [ ] **Step 4: Run the tests and watch them pass.**

```sh
cargo test command_buffer_status_tests
```

Expected: `test result: ok. 3 passed`.

- [ ] **Step 5: Full suite, formatting and lints.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy
rustfmt --edition 2021 src/gpu/mod.rs
cargo clippy --all-targets 2>&1 | grep -c -- '-->'
cargo clippy --all-targets 2>&1 | grep -c -- '--> src/gpu/' || true
cargo test
```

Expected: the first clippy count is `12` — the pre-existing baseline recorded in
Milestone 1 Task 1.8 Step 5, unchanged by this task — and the second is `0`, i.e.
this task added no diagnostic of its own. Do **not** write "expect no warnings":
`cargo clippy --all-targets` is not clean on this tree. All pre-existing tests
still pass by name.

In particular `gpu::pack::tests::salt_block_rejects_a_salt_longer_than_max_salt_len`
(Task 1.7) must still pass — that is the check that `SaltTooLong`'s shape did not
change. Verify by name, and verify the filter actually matched something:

```sh
cargo test salt_block_rejects_a_salt_longer_than_max_salt_len 2>&1 | tail -3
```

Expected: `test result: ok. 1 passed; 0 failed`. A `0 passed` line means the
filter matched nothing — check the spelling before treating it as green.

- [ ] **Step 6: Commit.**

```sh
git add src/gpu/mod.rs
git commit -m "gpu: final GpuError shape and the whole-wave command-buffer status rule

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 3.3: Cargo deps, the `metal` feature, the stub backend, and opening the device

**Files:**
- Modify: `Cargo.toml` (add `[features]`, the target-gated objc2 deps, and `rand_chacha` under `[dev-dependencies]`)
- Overwrite: `src/gpu/stub.rs` (Milestone 1 Task 1.3 created it as a placeholder)
- Create: `src/gpu/metal.rs`
- Modify: `src/gpu/mod.rs` (replace Milestone 1's placeholder backend block; fix the Milestone 1 test that named `GpuEngine`)

**Interfaces:**
- Consumes: `pub const crate::gpu::kernel_src::KERNEL_SRC` (Task 3.1); `pub enum GpuError` (Task 3.2); `pub enum GpuStatus` (Milestone 1); `pub const WAVE`, `MAX_THREADS_PER_THREADGROUP` (Milestone 1)
- Produces:
  - `pub fn crate::gpu::backend::probe() -> GpuStatus`, re-exported as `crate::gpu::probe`
  - `pub struct crate::gpu::backend::MetalPbkdf2` with `pub fn new() -> Result<MetalPbkdf2, GpuError>`, `pub fn device_name(&self) -> String`, `pub fn threadgroup_size(&self) -> usize` (Metal target only)

This is the smallest change that leaves the tree green on **every** target: the
feature, both backends, and the module selection land together. Split further
and one target or the other has a `mod backend;` pointing at a file that does
not exist.

**Why objc2 and not `metal-rs`.** `metal-rs` 0.33 is self-deprecated in its own
README and blanket-declares every wrapped object `Send + Sync`, including
`MTLCommandBuffer` and `MTLComputeCommandEncoder`, which Apple documents as not
thread-safe. objc2-metal encodes the real guarantees as supertraits —
`MTLDevice`/`MTLCommandQueue`/`MTLLibrary`/`MTLComputePipelineState` are
`Send + Sync`; **`MTLBuffer`, `MTLCommandBuffer`, `MTLCommandEncoder` are not** —
so "all Metal state lives and dies on one thread" is type-checked rather than
documented. It also provides `objc2::rc::autoreleasepool` and typed
`Retained<T>`, which the leak fix in Task 3.4 requires.

- [ ] **Step 1: Write the failing tests.** Create `src/gpu/metal.rs` containing only this (the rest of the file arrives in Step 4):

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gpu_device_opens_and_reports_a_name() {
        let Some(gpu) = gpu_for_test() else { return };
        assert!(
            !gpu.device_name().is_empty(),
            "MTLDevice reported an empty name"
        );
    }

    #[test]
    fn gpu_threadgroup_size_is_a_positive_multiple_of_the_execution_width() {
        let Some(gpu) = gpu_for_test() else { return };
        let tg = gpu.threadgroup_size();
        // Compare against the values the device actually reported, not against
        // constants this formula is derived from. `tg <= MAX_THREADS_PER_THREADGROUP`
        // and `tg % 32 == 0` are both TAUTOLOGIES of Step 4's
        //     tg = ((maxt.min(want) / tew).max(1) * tew).min(maxt)
        // when `want` is the constant and `tew` is 32 — they restate the formula
        // rather than testing it, and `tg > 0` is already guaranteed by the
        // `if tg == 0 { return Err(..) }` two lines above it in `new()`.
        let (tew, maxt) = gpu.threadgroup_bounds();
        assert!(tew > 0 && maxt > 0, "device reported tew={tew} maxt={maxt}");
        assert!(
            tg > 0 && tg <= maxt,
            "threadgroup {tg} must fit the device's own maxTotalThreadsPerThreadgroup {maxt}"
        );
        assert_eq!(
            tg % tew,
            0,
            "threadgroup {tg} is not a multiple of this device's execution width {tew}"
        );
        // The M1 perf clamp is a TUNING choice, not a hardware bound: this M1
        // reports maxTotalThreadsPerThreadgroup = 384, and 384 measured 13% SLOWER
        // than 256. Only assert the clamp when the override is absent — otherwise
        // `VANADDY_GPU_TG=512`, a tuning path this very brief documents, makes the
        // formula yield 384 and panics here. A test that fails on a documented
        // knob gets "fixed" by deleting the assertion, and this is the only
        // load-bearing one in the function.
        if std::env::var_os("VANADDY_GPU_TG").is_none() {
            assert!(
                tg <= MAX_THREADS_PER_THREADGROUP,
                "default threadgroup {tg} exceeds the measured M1 optimum clamp of \
                 {MAX_THREADS_PER_THREADGROUP} (384 measured 13% SLOWER here)"
            );
        }
    }

    #[test]
    fn probe_reports_a_ready_device() {
        if std::env::var_os("VANADDY_NO_GPU").is_some() {
            eprintln!("SKIP: VANADDY_NO_GPU is set");
            return;
        }
        match probe() {
            GpuStatus::Ready { device } => assert!(!device.is_empty()),
            GpuStatus::Unavailable(r) => eprintln!("SKIP: no Metal device ({r})"),
            other => panic!("probe() must return Ready or Unavailable, got {other:?}"),
        }
    }
}
```

- [ ] **Step 2: Run it and watch it fail.**

```sh
cargo test gpu_device_opens
```

Expected, verbatim:

```
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 109 filtered out
```

**That `ok` IS the red signal — read it carefully.** `src/gpu/metal.rs` is an orphan
file that no `mod` declaration reaches, so the test you just wrote is never compiled
and the filter matches nothing. Zero tests ran.

Do **not** expect `error[E0583]: file not found for module `backend``. That error is
unreachable here: `src/gpu/mod.rs` already carries `#[path = "stub.rs"] mod backend;`
(Milestone 1 Task 1.3) and `src/gpu/stub.rs` exists, so the module resolves fine.
An earlier draft of this step predicted E0583 and offered a "if `src/gpu/mod.rs` does
not yet contain a `mod backend;`" fallback; both describe a tree that no longer
exists, and following either would have you record a red you never observed.

Confirm the count: `109 filtered out` is the whole suite as of Task 3.2. If a later
task has added tests, the number rises — what must hold is **`0 passed`**.

> **Note for Step 4:** the test above calls `gpu.threadgroup_bounds() -> (usize, usize)`,
> returning `(threadExecutionWidth, maxTotalThreadsPerThreadgroup)` as the device reported
> them. Store both on the backend struct when you compute `threadgroup_size()` and add that
> accessor — the test must compare against what the hardware said, not against the constants
> the formula is derived from, or it only restates the formula.

- [ ] **Step 3: Add the deps and the feature.** Replace the tail of `Cargo.toml`
      (everything from `zeroize = …` onwards) with:

```toml
zeroize = { version = "1.8", features = ["derive"] }
crossbeam-channel = "0.5"

[features]
default = ["metal"]
metal = ["dep:objc2", "dep:objc2-foundation", "dep:objc2-metal"]

[target.'cfg(all(target_os = "macos", target_arch = "aarch64"))'.dependencies]
objc2 = { version = "0.6", optional = true }
objc2-foundation = { version = "0.3", optional = true, default-features = false, features = [
  "std", "NSString", "NSError" ] }
objc2-metal = { version = "0.3", optional = true, default-features = false, features = [
  "std", "MTLDevice", "MTLCommandQueue", "MTLCommandBuffer", "MTLCommandEncoder",
  "MTLComputeCommandEncoder", "MTLComputePipeline", "MTLLibrary", "MTLBuffer",
  "MTLResource", "MTLAllocation", "MTLTypes", "objc2-core-foundation" ] }

[dev-dependencies]
tempfile = "3"
rand_chacha = "0.3"
```

(`crossbeam-channel` was added by Milestone 1 and `tempfile` by Milestone 2 —
both are shown so the final shape of the file is unambiguous. `rand_chacha` 0.3
is the version matching the `rand` 0.8 already in the tree; it is used for the
deterministic differential corpus in Task 3.7. `objc2-metal` is restricted to
`aarch64` rather than all of macOS because that deletes two whole failure classes
that do not exist on Apple Silicon: automatic graphics switching between
iGPU/dGPU, and eGPU device removal.)

- [ ] **Step 4: Write `src/gpu/metal.rs` in full** (prepend all of this *above* the
      `#[cfg(test)] mod tests` block from Step 1):

```rust
//! Metal backend. The only file in the tree that names an Objective-C type.
//!
//! Everything here is thread-confined by construction: `MTLBuffer`,
//! `MTLCommandBuffer` and `MTLCommandEncoder` are `!Send`/`!Sync` under objc2,
//! so the compiler — not a comment — enforces that a `MetalPbkdf2` is created,
//! used and dropped on one thread.

use crate::gpu::kernel_src::KERNEL_SRC;
use crate::gpu::{GpuError, GpuStatus, MAX_THREADS_PER_THREADGROUP, WAVE};
use objc2::rc::Retained;
use objc2::runtime::ProtocolObject;
use objc2_foundation::NSString;
use objc2_metal::{
    MTLBuffer, MTLCommandQueue, MTLCompileOptions, MTLComputePipelineState,
    MTLCreateSystemDefaultDevice, MTLDevice, MTLLanguageVersion, MTLLibrary, MTLResourceOptions,
};

// `MTLCreateSystemDefaultDevice` lives in CoreGraphics, which objc2-metal does
// not link for us.
#[link(name = "CoreGraphics", kind = "framework")]
extern "C" {}

type Buf = Retained<ProtocolObject<dyn MTLBuffer>>;

/// ~1 ms device probe. Called ONCE from `main()`, BEFORE `enable_raw_mode()`,
/// so that a panic or any Metal stderr noise cannot land inside the alternate
/// screen.
pub fn probe() -> GpuStatus {
    match MTLCreateSystemDefaultDevice() {
        Some(device) => GpuStatus::Ready {
            device: device.name().to_string(),
        },
        None => GpuStatus::Unavailable("no Metal device on this system".to_string()),
    }
}

/// ONE set of buffers. No slot ring, no double buffering: `run_wave` takes
/// `&mut self` and blocks, so a second slot is unreachable, and advertising
/// "double-buffered" only invites an aliasing bug on `states`.
/// 1.00 + 2.00 + 0.50 = 3.50 MiB, not 7.0.
struct WaveBuffers {
    keys: Buf,   // WAVE * 128 B, StorageModeShared
    states: Buf, // WAVE * 256 B
    seeds: Buf,  // WAVE *  64 B
}

impl Drop for WaveBuffers {
    /// `keys` holds the zero-padded 12-word phrases themselves and `states`
    /// holds ipad/opad midstates, which are seed-equivalent. No command buffer
    /// is in flight here — `run_wave` waits on every one before returning — so
    /// this is safe to do unconditionally.
    fn drop(&mut self) {
        for (buf, len) in [
            (&self.keys, WAVE * 128),
            (&self.states, WAVE * 256),
            (&self.seeds, WAVE * 64),
        ] {
            unsafe { std::ptr::write_bytes(buf.contents().as_ptr() as *mut u8, 0, len) };
        }
    }
}

pub struct MetalPbkdf2 {
    device_name: String,
    queue: Retained<ProtocolObject<dyn MTLCommandQueue>>,
    prologue: Retained<ProtocolObject<dyn MTLComputePipelineState>>,
    iterate: Retained<ProtocolObject<dyn MTLComputePipelineState>>,
    bufs: WaveBuffers,
    tg: usize,
}

impl MetalPbkdf2 {
    /// Device, queue, library (~60–95 ms cold, ~1.5 ms warm), both pipelines
    /// and all three buffers. Must be called on the thread that will use it.
    pub fn new() -> Result<MetalPbkdf2, GpuError> {
        let device = MTLCreateSystemDefaultDevice().ok_or(GpuError::NoDevice)?;
        let device_name = device.name().to_string();
        let queue = device.newCommandQueue().ok_or(GpuError::BufferAlloc)?;

        // Set ONLY the language version. Do NOT call setMathMode /
        // setFastMathEnabled: `setMathMode:` is macOS 15.0+ and objc2-metal
        // emits it with no availability guard, so on an M1 running
        // Ventura/Sonoma it raises NSInvalidArgumentException — an Objective-C
        // exception, which catch_unwind CANNOT catch — aborting the process
        // inside raw mode with the alternate screen still active. It is also
        // worthless here: SHA-512 is integer-only and MSL fast-math relaxes
        // IEEE-754 float semantics only.
        let options = MTLCompileOptions::new();
        options.setLanguageVersion(MTLLanguageVersion::Version3_0);
        let source = NSString::from_str(KERNEL_SRC);
        let library = device
            .newLibraryWithSource_options_error(&source, Some(&options))
            .map_err(|e| GpuError::ShaderCompile(e.localizedDescription().to_string()))?;

        let mut pipes = Vec::new();
        for name in ["pbkdf2_prologue", "pbkdf2_iterate"] {
            let f = library
                .newFunctionWithName(&NSString::from_str(name))
                .ok_or_else(|| GpuError::PipelineCreate(format!("kernel `{name}` not found")))?;
            pipes.push(
                device
                    .newComputePipelineStateWithFunction_error(&f)
                    .map_err(|e| GpuError::PipelineCreate(e.localizedDescription().to_string()))?,
            );
        }
        let iterate = pipes.pop().expect("two pipelines built");
        let prologue = pipes.pop().expect("two pipelines built");

        // One threadgroup size is used for BOTH pipelines, so take the widest
        // execution width and the tightest maximum. The final `.min(maxt)`
        // closes the case where `maxt < tew`, which would otherwise dispatch a
        // threadgroup larger than the pipeline permits — another uncatchable
        // Objective-C exception. The 256 clamp is a measured M1 result, not a
        // universal truth (384 measured 13% SLOWER here); VANADDY_GPU_TG
        // overrides it for tuning on other hardware.
        let tew = prologue
            .threadExecutionWidth()
            .max(iterate.threadExecutionWidth())
            .max(1);
        let maxt = prologue
            .maxTotalThreadsPerThreadgroup()
            .min(iterate.maxTotalThreadsPerThreadgroup());
        let want = std::env::var("VANADDY_GPU_TG")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(MAX_THREADS_PER_THREADGROUP);
        let tg = ((maxt.min(want) / tew).max(1) * tew).min(maxt);
        if tg == 0 {
            return Err(GpuError::PipelineCreate(format!(
                "threadgroup size 0 (tew={tew}, maxt={maxt})"
            )));
        }

        let make = |len: usize| {
            device
                .newBufferWithLength_options(len, MTLResourceOptions::StorageModeShared)
                .ok_or(GpuError::BufferAlloc)
        };
        let keys = make(WAVE * 128)?;
        let states = make(WAVE * 256)?;
        let seeds = make(WAVE * 64)?;

        Ok(MetalPbkdf2 {
            device_name,
            queue,
            prologue,
            iterate,
            bufs: WaveBuffers { keys, states, seeds },
            tg,
        })
    }

    pub fn device_name(&self) -> String {
        self.device_name.clone()
    }

    pub fn threadgroup_size(&self) -> usize {
        self.tg
    }
}

/// The skip helper. Absence must be LOUD where the backend actually ships.
///
/// This file is compiled only on `aarch64-apple-darwin` with the `metal`
/// feature, so on every other target these tests do not exist at all — that is
/// the graceful skip for CI and for other developers. Here, a test that returns
/// early passes, and an early return means the differential silently never ran.
/// So exactly two things skip: an explicit `VANADDY_NO_GPU=1`, and
/// `GpuError::NoDevice` (a genuinely headless machine). A shader that will not
/// compile, a pipeline that will not build, a buffer that will not allocate —
/// those are defects in code that ships on this target, and they panic.
#[cfg(test)]
pub(crate) fn gpu_for_test() -> Option<MetalPbkdf2> {
    if std::env::var_os("VANADDY_NO_GPU").is_some() {
        eprintln!("SKIP: VANADDY_NO_GPU is set");
        return None;
    }
    match MetalPbkdf2::new() {
        Ok(g) => Some(g),
        Err(GpuError::NoDevice) => {
            eprintln!("SKIP: no Metal device on this machine");
            None
        }
        Err(e) => panic!(
            "the Metal backend must be available on Apple Silicon: {e:?}\n\
             Set VANADDY_NO_GPU=1 to skip GPU tests deliberately."
        ),
    }
}
```

- [ ] **Step 5: Overwrite `src/gpu/stub.rs`.** Milestone 1 Task 1.3 created this
      file with a placeholder uninhabited `GpuEngine`. Replace its entire contents
      with the following — the free `probe()` is what Step 6 re-exports, and
      Milestone 4 Task 4.7 puts the real `GpuEngine` back into this file.

```rust
//! No-op GPU backend for every target that is not `aarch64-apple-darwin` with
//! the `metal` feature. Zero dependencies, no Metal symbols, no GPU code in the
//! binary at all — which doubles as the rollback lever
//! `cargo build --release --no-default-features`.

use crate::gpu::GpuStatus;

/// Mirror of `metal::probe`. Always unavailable; the TUI renders the reason.
pub fn probe() -> GpuStatus {
    GpuStatus::Unavailable(
        "Metal PBKDF2 offload requires Apple Silicon macOS and the `metal` feature".to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::probe;
    use crate::gpu::GpuStatus;

    #[test]
    fn probe_is_unavailable_without_the_metal_backend() {
        match probe() {
            GpuStatus::Unavailable(r) => assert!(r.contains("Apple Silicon")),
            other => panic!("the stub backend must be Unavailable, got {other:?}"),
        }
    }
}
```

- [ ] **Step 6: Wire the backend module.** In `src/gpu/mod.rs`, **delete** the
      Milestone 1 Task 1.3 placeholder block — the `#[path]`ed module and its
      re-export, exactly as they appear there:

```rust
#[path = "stub.rs"]
mod backend;

/// `main()` probes through the module, not the type, so milestone 6 does not
/// have to know which backend it got. This is the design spec's `mod.rs` form
/// (`pub use backend::{GpuEngine, probe};`) written from the start - rustfmt
/// sorts the braces to `{probe, GpuEngine}` - so milestone 3 only has to widen
/// `mod backend;` to `pub mod backend;` and swap the `#[path]` for the two
/// `cfg_attr`s. It never has to delete a wrapper.
pub use backend::{probe, GpuEngine};
```

      and put in its place exactly:

```rust
// `pub mod`, not `mod`: `src/gpu/producer.rs` (Milestone 4) names
// `backend::MetalPbkdf2` directly, and a private module would additionally make
// every item inside it dead code until that milestone lands.
#[cfg_attr(
    all(target_os = "macos", target_arch = "aarch64", feature = "metal"),
    path = "metal.rs"
)]
#[cfg_attr(
    not(all(target_os = "macos", target_arch = "aarch64", feature = "metal")),
    path = "stub.rs"
)]
pub mod backend;

pub use backend::probe;
```

      **`probe` needs no surgery.** Milestone 1 Task 1.3 already wrote the
      re-export form, so `crate::gpu::probe` has always resolved to the free
      function each backend defines; the only thing changing here is which file
      `backend` resolves to. There is no module-level wrapper left over to collide
      with it, so `error[E0255]: the name 'probe' is defined multiple times` is not
      reachable from this edit.

      **`GpuEngine` must go, for now.** It is the handle to the producer
      thread, and the producer thread is Milestone 4; neither `src/gpu/metal.rs`
      nor the rewritten `src/gpu/stub.rs` defines it at the end of this
      milestone, so `pub use backend::GpuEngine;` would be `error[E0432]`. Also
      delete the one line

```rust
    assert_send_sync::<GpuEngine>();
```

      from Milestone 1's `const _: fn() = …` pin, leaving the `SeedBlock` and
      `GpuHealth` lines of that block intact. Milestone 4 Task 4.7 defines
      `GpuEngine` in both backends and restores both the re-export and that line.

- [ ] **Step 6a: Move the stray module declaration up with its siblings.** Task 3.1
      appended `pub mod kernel_src;` as the **last line** of `src/gpu/mod.rs`, after the
      `#[cfg(test)] mod tests` block, because its Step 2 said "append to the end"
      literally. Rust does not care, but a `mod` declaration below the test module is
      hard to find. You are already editing this file's module header, so move it up
      next to `pub mod pack;` and `pub mod selftest;`. Task 3.1's review deferred exactly
      this cleanup to whichever Milestone 3 task next touched the file.

- [ ] **Step 6b: Fix the Milestone 1 test that named `GpuEngine`.** `src/gpu/mod.rs`
      still contains Task 1.3's test `stub_backend_reports_unavailable`. **Replace the
      whole function, not a line of it.** Its real body is a `match GpuEngine::probe()`
      block followed by `assert_eq!(probe(), GpuEngine::probe());` — two separate
      references to `GpuEngine`, which Step 6 has just removed. Replacing only the
      `assert_eq!` line leaves the `match` behind and fails to compile. On the Metal leg
      the backend is no longer a stub either, so the name is wrong as well. Rename it and
      replace the entire function with:

```rust
    #[test]
    fn backend_probe_reports_ready_or_unavailable() {
        match probe() {
            GpuStatus::Unavailable(reason) => assert!(!reason.is_empty()),
            GpuStatus::Ready { device } => assert!(!device.is_empty()),
            other => panic!("probe() must be Ready or Unavailable, got {other:?}"),
        }
    }
```

      This is the one assertion that holds on **both** legs: on the Metal leg
      `probe()` resolves into `src/gpu/metal.rs`, on every other target into
      `src/gpu/stub.rs`.

- [ ] **Step 7: Run the tests and watch them pass.**

```sh
cargo test gpu::backend
```

Expected on an Apple Silicon machine with a GPU: `test result: ok. 3 passed`.
Run it once with `--nocapture` to see which device you are on:

```sh
cargo test gpu::backend -- --nocapture
```

- [ ] **Step 8: Prove the stub leg compiles and runs.**

```sh
cargo test --no-default-features
```

Expected: green, and it includes
`gpu::backend::tests::probe_is_unavailable_without_the_metal_backend`.

- [ ] **Step 9: Prove the deliberate-skip leg works.**

```sh
VANADDY_NO_GPU=1 cargo test gpu::backend -- --nocapture
```

Expected: all three tests pass, with `SKIP: VANADDY_NO_GPU is set` printed.

- [ ] **Step 10: Full suite, formatting and lints, both feature legs.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy
rustfmt --edition 2021 src/gpu/metal.rs src/gpu/stub.rs src/gpu/mod.rs
cargo clippy --all-targets 2>&1 | grep -c -- '-->'
cargo clippy --all-targets 2>&1 | grep -c -- '--> src/gpu/' || true
cargo test
cargo test --no-default-features
```

Expected: the first clippy count is `12` — the pre-existing baseline recorded in
Milestone 1 Task 1.8 Step 5, unchanged by this task — and the second is `0`, i.e.
this task added no diagnostic of its own. Do **not** write "expect no warnings":
`cargo clippy --all-targets` is not clean on this tree. All pre-existing tests
still pass by name on both legs.

- [ ] **Step 11: Commit.**

```sh
git add Cargo.toml Cargo.lock src/gpu/metal.rs src/gpu/stub.rs src/gpu/mod.rs
git commit -m "gpu: metal feature, objc2 deps, stub backend, and Metal device/pipeline setup

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 3.3b: Pin the `objc2-metal` surface before writing `run_wave`

**Files:**
- Modify: `src/gpu/metal.rs` (one never-called compile-probe function)

**Interfaces:**
- Consumes: the `objc2-metal` / `objc2` versions resolved by Task 3.3 Step 3.
- Produces: nothing shipped.

The design spec's Risk #6 says of `objc2-metal` 0.3.x: *"Versions must be verified
against crates.io before merge — this is the one interface no agent could check
(no network)."* Task 3.4 Step 5 writes ~14 exact Objective-C selector spellings.
If any one of them differs in the version Cargo actually resolved, the predicted
red phase of Task 3.4 (`error[E0599]: no method named 'derive'`) is drowned in a
wall of unrelated `E0599`/`E0061`, and you will be debugging bindings while
believing you are debugging a kernel. Pin the surface first, in one small file
that either compiles or names exactly which selector is wrong.

- [ ] **Step 1: Record the resolved versions.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy
cargo tree -p objc2-metal --depth 0
grep -A2 'name = "objc2-metal"' Cargo.lock
grep -A2 'name = "objc2"' Cargo.lock
```

Expected: `objc2-metal 0.3.x` and `objc2 0.6.x`. Copy the exact patch versions
into this task's commit message so a future bisect knows which surface was pinned.

- [ ] **Step 2: Add the compile probe.** Insert into `src/gpu/metal.rs`
      immediately **above** the `#[cfg(test)] mod tests` block:

```rust
/// Compile-time proof that the `objc2-metal` surface `run_wave` (Task 3.4)
/// depends on resolved to the selector spellings and arities this file assumes.
/// Never called, never shipped in any meaningful sense — it exists so that a
/// binding mismatch fails here, naming the one selector that moved, instead of
/// inside the kernel work where it looks like a Metal bug.
#[allow(dead_code)]
fn objc2_surface_probe(
    q: &ProtocolObject<dyn objc2_metal::MTLCommandQueue>,
    pipe: &ProtocolObject<dyn MTLComputePipelineState>,
    buf: &ProtocolObject<dyn MTLBuffer>,
) {
    use objc2_metal::{MTLCommandBuffer, MTLCommandEncoder, MTLComputeCommandEncoder, MTLSize};

    let _: usize = pipe.threadExecutionWidth();
    let _: usize = pipe.maxTotalThreadsPerThreadgroup();
    let _: std::ptr::NonNull<std::ffi::c_void> = buf.contents();

    // Pin `autoreleasepool`'s closure arity and the shape of the pool argument.
    // Task 3.4 calls this three times and Task 3.3's own rationale names it as a
    // reason for choosing objc2 over metal-rs, so it belongs in this probe: if the
    // closure took no argument, or returned `()` only, 3.4 would not compile and the
    // failure would surface 300 lines into a task this probe exists to de-risk.
    let _: u32 = objc2::rc::autoreleasepool(|_pool| 0u32);

    let Some(cb) = q.commandBuffer() else { return };
    let _: i64 = cb.status().0 as i64;
    let _: Option<String> = cb.error().map(|e| e.localizedDescription().to_string());

    if let Some(enc) = cb.computeCommandEncoder() {
        enc.setComputePipelineState(pipe);
        let p: u32 = 0;
        unsafe {
            enc.setBuffer_offset_atIndex(Some(buf), 0, 0);
            enc.setBytes_length_atIndex(std::ptr::NonNull::from(&p).cast(), 4, 1);
        }
        enc.dispatchThreads_threadsPerThreadgroup(
            MTLSize { width: 1, height: 1, depth: 1 },
            MTLSize { width: 1, height: 1, depth: 1 },
        );
        enc.endEncoding();
    }
    cb.commit();
    cb.waitUntilCompleted();
}
```

- [ ] **Step 3: Build and read the errors.**

```sh
cargo check --all-targets 2>&1 | tail -40
```

Expected: `Finished`. Every `error[E0599]`/`error[E0061]` here names exactly one
method whose objc2 spelling or arity differs from this plan's assumption. Fix the
probe against `cargo doc -p objc2-metal --open`, then apply the *same* spelling
everywhere in Task 3.4 Step 5 before writing it. **Do not start Task 3.4 until
this compiles.**

- [ ] **Step 4: Formatting and lints.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy
rustfmt --edition 2021 src/gpu/metal.rs
cargo clippy --all-targets 2>&1 | grep -c -- '-->'
cargo clippy --all-targets 2>&1 | grep -c -- '--> src/gpu/' || true
cargo test
cargo test --no-default-features
```

Expected: the first clippy count is `12` — the pre-existing baseline recorded in
Milestone 1 Task 1.8 Step 5, unchanged by this task — and the second is `0`, i.e.
this task added no diagnostic of its own. Do **not** write "expect no warnings":
`cargo clippy --all-targets` is not clean on this tree. All pre-existing tests
still pass by name on both legs.

- [ ] **Step 5: Commit.**

```sh
git add src/gpu/metal.rs
git commit -m "gpu: pin the objc2-metal selector surface with a compile probe

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 3.4: `run_wave` and `derive` — the canonical BIP-39 vector on the GPU

**Files:**
- Modify: `src/gpu/metal.rs` (add imports, `Params`, `check_status`, `run_wave`, `derive`; add one test)

**Interfaces:**
- Consumes: `pub fn crate::gpu::classify_command_buffer_status` (Task 3.2); `pub struct crate::gpu::pack::KeyBlock`, `pub fn pack_key_block`, `pub fn pack_salt_block` (Milestone 1); `pub const crate::seed::{PBKDF2_ROUNDS, BIP39_SALT}` (Milestone 1); `pub const ITERS_PER_DISPATCH`, `DISPATCHES_PER_COMMAND_BUFFER`, `PIPELINE_DEPTH`, `WAVE` (Milestone 1)
- Produces:
  - `pub fn MetalPbkdf2::run_wave(&mut self, keys: &[KeyBlock], salt_block: &[u64; 16], total_iters: u32, stop: &AtomicBool) -> Result<Option<&[[u8; 64]]>, GpuError>`
  - `pub fn MetalPbkdf2::derive(&mut self, phrases: &[&str], iters: u32) -> Result<Vec<Zeroizing<[u8; 64]>>, GpuError>`

**Three things in this code are load-bearing and are not stylistic.**

1. **One autorelease pool per command buffer.** Measured on this machine:
   without a pool, `+1,861 B per command buffer` = 199 KB/s = **700 MB/hour =
   16.4 GB/day**; with a per-command-buffer pool, RSS is flat or negative, at
   identical throughput (13,829 vs 13,804 seeds/s). **The fix is free.** A bare
   `std::thread::spawn` body has no ambient pool, and a single outer pool never
   drains and leaks identically. A multi-day vanity search is the stated use
   case; without this the process is jetsammed overnight.
2. **`check_status` at EVERY wait, not only the last.** See Task 3.2.
3. **`0xA5` poison before every wave, and an exact-length return.** Poisoning
   means a missing `finalize` yields obvious garbage rather than the *previous*
   wave's still-valid 64-byte seed. Returning `&all[..keys.len()]` means slots
   past the live count — which still hold poison — can never be read as seeds.

- [ ] **Step 1: Write the failing test.** Add to the `mod tests` block in `src/gpu/metal.rs`:

```rust
    /// The BIP-39 canonical vector, against the same hex constant already
    /// pinned at src/seed.rs:41. This is the anchor to external ground truth:
    /// every other GPU test in this file compares against `ring`, which would
    /// be circular if `ring` were wrong.
    #[test]
    fn gpu_seed_matches_bip39_canonical_vector() {
        let Some(mut gpu) = gpu_for_test() else { return };
        let out = gpu
            .derive(&[CANONICAL_PHRASE], crate::seed::PBKDF2_ROUNDS)
            .expect("wave");
        assert_eq!(out.len(), 1);
        assert_eq!(hex::encode(*out[0]), CANONICAL_SEED_HEX);
    }
```

and, at the top of the same `mod tests` block:

```rust
    const CANONICAL_PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const CANONICAL_SEED_HEX: &str = "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4";
```

- [ ] **Step 2: Run it and watch it fail.**

```sh
cargo test gpu_seed_matches_bip39_canonical_vector
```

Expected failure, verbatim:

```
error[E0599]: no method named `derive` found for struct `MetalPbkdf2` in the current scope
```

- [ ] **Step 3: Extend the imports at the top of `src/gpu/metal.rs`.** Replace the
      existing `use` block with:

```rust
use crate::gpu::kernel_src::KERNEL_SRC;
use crate::gpu::pack::{pack_key_block, pack_salt_block, KeyBlock};
use crate::gpu::{
    classify_command_buffer_status, GpuError, GpuStatus, DISPATCHES_PER_COMMAND_BUFFER,
    ITERS_PER_DISPATCH, MAX_THREADS_PER_THREADGROUP, PIPELINE_DEPTH, WAVE,
};
use objc2::rc::{autoreleasepool, Retained};
use objc2::runtime::ProtocolObject;
use objc2_foundation::NSString;
use objc2_metal::{
    MTLBuffer, MTLCommandBuffer, MTLCommandEncoder, MTLCommandQueue, MTLCompileOptions,
    MTLComputeCommandEncoder, MTLComputePipelineState, MTLCreateSystemDefaultDevice, MTLDevice,
    MTLLanguageVersion, MTLLibrary, MTLResourceOptions, MTLSize,
};
use std::ptr::NonNull;
use std::sync::atomic::{AtomicBool, Ordering};
use zeroize::Zeroizing;
```

- [ ] **Step 4: Add the `Params` mirror and the layout asserts.** Insert just below
      the `#[link(name = "CoreGraphics", …)] extern "C" {}` block:

```rust
/// Host mirror of the kernel's `struct Params { uint count, iters, finalize, _pad; }`.
#[repr(C)]
#[derive(Clone, Copy)]
struct Params {
    count: u32,
    /// U-iterations to advance in THIS dispatch. May be 0 (see the do-while in
    /// `run_wave`): PBKDF2 with c == 1 is T == U_1, already computed by the
    /// prologue, so the last dispatch only has to carry `finalize`.
    iters: u32,
    /// Nonzero => write the big-endian seed bytes for this candidate.
    finalize: u32,
    _pad: u32,
}

// The kernel indexes key blocks as `keyblocks + 16 * tid` over `ulong`, i.e. a
// 128-byte stride. If `KeyBlock` ever stops being exactly that, every candidate
// except tid 0 derives from the wrong key block.
const _: () = assert!(std::mem::size_of::<KeyBlock>() == 128);
const _: () = assert!(std::mem::size_of::<Params>() == 16);

type Cb = Retained<ProtocolObject<dyn MTLCommandBuffer>>;
```

- [ ] **Step 5: Add `check_status`, `run_wave` and `derive`** inside `impl MetalPbkdf2`,
      after `threadgroup_size`:

```rust
    fn check_status(&self, cb: &ProtocolObject<dyn MTLCommandBuffer>) -> Result<(), GpuError> {
        let status = cb.status().0 as i64;
        let message = cb.error().map(|e| e.localizedDescription().to_string());
        classify_command_buffer_status(status, message)
    }

    /// Derive `keys.len()` seeds. `Ok(None)` means the wave was abandoned
    /// because `stop` was raised; the whole wave is discarded on any command
    /// buffer failure — there is deliberately no partial-success shape.
    ///
    /// The returned slice is EXACTLY `keys.len()` long and borrows `self`, so
    /// the next wave cannot overwrite seeds the caller still holds.
    pub fn run_wave(
        &mut self,
        keys: &[KeyBlock],
        salt_block: &[u64; 16],
        total_iters: u32,
        stop: &AtomicBool,
    ) -> Result<Option<&[[u8; 64]]>, GpuError> {
        assert!(total_iters >= 1, "iterations must be at least 1"); // mirrors src/pbkdf2_lanes.rs:26
        if keys.is_empty() || keys.len() > WAVE {
            return Err(GpuError::BadConfig(format!(
                "wave takes 1..={WAVE} candidates, got {}",
                keys.len()
            )));
        }
        let count = keys.len() as u32;

        // Poison the seeds region so a missing finalize yields obvious garbage
        // rather than the PREVIOUS wave's still-valid 64-byte seed.
        unsafe {
            std::ptr::write_bytes(
                self.bufs.seeds.contents().as_ptr() as *mut u8,
                0xA5,
                WAVE * 64,
            )
        };
        // `KeyBlock` is #[repr(C, align(16))] over [u64; 16]: 128 bytes,
        // exactly the kernel's per-thread stride, and the u64s are already the
        // big-endian-decoded words the kernel expects, so the kernel contains
        // zero endianness code and the host does no byteswap.
        unsafe {
            std::ptr::copy_nonoverlapping(
                keys.as_ptr() as *const u8,
                self.bufs.keys.contents().as_ptr() as *mut u8,
                std::mem::size_of_val(keys),
            )
        };

        // 1 prologue command buffer: ipad/opad midstates and U_1, which the
        // kernel writes into BOTH states[i].u and states[i].t — so `states`
        // needs no clearing between waves.
        autoreleasepool(|_| -> Result<(), GpuError> {
            let cb = self.queue.commandBuffer().ok_or(GpuError::BufferAlloc)?;
            let enc = cb.computeCommandEncoder().ok_or(GpuError::BufferAlloc)?;
            enc.setComputePipelineState(&self.prologue);
            let p = Params {
                count,
                iters: 0,
                finalize: 0,
                _pad: 0,
            };
            unsafe {
                enc.setBuffer_offset_atIndex(Some(&self.bufs.keys), 0, 0);
                enc.setBuffer_offset_atIndex(Some(&self.bufs.states), 0, 1);
                enc.setBytes_length_atIndex(NonNull::from(salt_block).cast(), 128, 2);
                enc.setBytes_length_atIndex(
                    NonNull::from(&p).cast(),
                    std::mem::size_of::<Params>(),
                    3,
                );
            }
            enc.dispatchThreads_threadsPerThreadgroup(
                MTLSize {
                    width: count as usize,
                    height: 1,
                    depth: 1,
                },
                MTLSize {
                    width: self.tg,
                    height: 1,
                    depth: 1,
                },
            );
            enc.endEncoding();
            cb.commit();
            cb.waitUntilCompleted();
            self.check_status(&cb) // checked, not assumed
        })?;

        // do-while: ALWAYS at least one iterate dispatch, so total_iters == 1
        // still carries finalize=1. (Verified: c=1 via [iters=0, finalize=1]
        // matches the reference byte-for-byte — the loop no-ops and t = U_1.)
        let mut remaining = total_iters - 1; // 2047 for BIP-39
        let mut ring: [Option<Cb>; PIPELINE_DEPTH] = Default::default();
        let mut slot_ix = 0usize;
        loop {
            if stop.load(Ordering::Relaxed) {
                for cb in ring.iter().flatten() {
                    cb.waitUntilCompleted();
                    self.check_status(cb)?;
                }
                return Ok(None);
            }
            let prev = ring[slot_ix].take();
            // ONE AUTORELEASE POOL PER COMMAND BUFFER. Non-negotiable: without
            // it this leaks 1,861 B per command buffer = ~700 MB/hour.
            // `prev` is moved in, so its release also happens inside the pool.
            let cb = autoreleasepool(|_| -> Result<Cb, GpuError> {
                if let Some(prev) = prev {
                    prev.waitUntilCompleted();
                    self.check_status(&prev)?; // at EVERY wait, not just the last
                }
                let cb = self.queue.commandBuffer().ok_or(GpuError::BufferAlloc)?;
                // A serial compute encoder auto-barriers between dispatches,
                // which is what makes the depth-3 ring safe on one `states`.
                let enc = cb.computeCommandEncoder().ok_or(GpuError::BufferAlloc)?;
                enc.setComputePipelineState(&self.iterate);
                unsafe {
                    enc.setBuffer_offset_atIndex(Some(&self.bufs.states), 0, 0);
                    enc.setBuffer_offset_atIndex(Some(&self.bufs.seeds), 0, 1);
                }
                for _ in 0..DISPATCHES_PER_COMMAND_BUFFER {
                    let iters = remaining.min(ITERS_PER_DISPATCH);
                    remaining -= iters;
                    let p = Params {
                        count,
                        iters,
                        finalize: (remaining == 0) as u32,
                        _pad: 0,
                    };
                    unsafe {
                        enc.setBytes_length_atIndex(
                            NonNull::from(&p).cast(),
                            std::mem::size_of::<Params>(),
                            2,
                        )
                    };
                    enc.dispatchThreads_threadsPerThreadgroup(
                        MTLSize {
                            width: count as usize,
                            height: 1,
                            depth: 1,
                        },
                        MTLSize {
                            width: self.tg,
                            height: 1,
                            depth: 1,
                        },
                    );
                    if remaining == 0 {
                        break;
                    }
                }
                enc.endEncoding();
                cb.commit();
                Ok(cb)
            })?;
            // objc2's `Retained` IS the retain the Objective-C prototype had to
            // take by hand inside the pool: it is +1 owned, so moving it out
            // here keeps the command buffer alive past the pool drain.
            ring[slot_ix] = Some(cb);
            slot_ix = (slot_ix + 1) % PIPELINE_DEPTH;
            if remaining == 0 {
                break;
            }
        }
        // The host reads `seeds` only after EVERY command buffer of the wave
        // reports Completed.
        for cb in ring.iter().flatten() {
            cb.waitUntilCompleted();
            self.check_status(cb)?;
        }

        // SAFETY: `seeds` is WAVE * 64 bytes of StorageModeShared memory owned
        // by this engine; every command buffer of the wave has reported
        // Completed, so the GPU is no longer writing it; `[u8; 64]` has
        // alignment 1 and no invalid bit patterns; and the returned slice
        // borrows `&mut self` for its whole lifetime.
        let p = self.bufs.seeds.contents().as_ptr() as *const [u8; 64];
        let all: &[[u8; 64]] = unsafe { std::slice::from_raw_parts(p, WAVE) };
        // Slots >= count still hold 0xA5 poison and are never returned.
        Ok(Some(&all[..keys.len()]))
    }

    /// Convenience wrapper: pack phrases, run one wave, copy the seeds out.
    /// The `Vec<KeyBlock>` holds the plaintext phrases, so it is `Zeroizing`.
    pub fn derive(
        &mut self,
        phrases: &[&str],
        iters: u32,
    ) -> Result<Vec<Zeroizing<[u8; 64]>>, GpuError> {
        let salt = pack_salt_block(crate::seed::BIP39_SALT)?;
        let keys: Zeroizing<Vec<KeyBlock>> = Zeroizing::new(
            phrases
                .iter()
                .map(|p| pack_key_block(p.as_bytes()))
                .collect(),
        );
        match self.run_wave(&keys, &salt, iters, &AtomicBool::new(false))? {
            Some(seeds) => Ok(seeds.iter().map(|s| Zeroizing::new(*s)).collect()),
            None => Err(GpuError::BadConfig(
                "wave abandoned without a stop request".to_string(),
            )),
        }
    }
```

- [ ] **Step 6: Run the test and watch it pass.**

```sh
cargo test gpu_seed_matches_bip39_canonical_vector
```

Expected: `test result: ok. 1 passed`. **This is the gate the milestone brief
names: do not proceed until the canonical vector reproduces.**

- [ ] **Step 7: Full suite, formatting and lints, both feature legs.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy
rustfmt --edition 2021 src/gpu/metal.rs
cargo clippy --all-targets 2>&1 | grep -c -- '-->'
cargo clippy --all-targets 2>&1 | grep -c -- '--> src/gpu/' || true
cargo test
cargo test --no-default-features
```

Expected: the first clippy count is `12` — the pre-existing baseline recorded in
Milestone 1 Task 1.8 Step 5, unchanged by this task — and the second is `0`, i.e.
this task added no diagnostic of its own. Do **not** write "expect no warnings":
`cargo clippy --all-targets` is not clean on this tree. All pre-existing tests
still pass by name on both legs.

- [ ] **Step 8: Commit.**

```sh
git add src/gpu/metal.rs
git commit -m "gpu: resumable Metal wave loop reproduces the BIP-39 canonical vector

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 3.5: Iteration counts {1, 2, 3, 16, 2048} — proving the do-while

**Files:**
- Modify: `src/gpu/metal.rs` (one test; temporary mutation and revert of `run_wave`)

**Interfaces:**
- Consumes: `MetalPbkdf2::derive` (Task 3.4)
- Produces: nothing new.

This is a **guard** test: it passes the moment you write it. Step 3 makes you
watch it fail, because the bug it guards against is the single most plausible
mistake in `run_wave` — writing the chunking loop as `while remaining > 0`
instead of a do-while. That version is *correct for every `total_iters >= 2`*,
including the 2048 the product actually uses, and silently wrong for
`total_iters == 1`: zero iterate dispatches run, `finalize` is never set, and the
"seed" you get back is the 0xA5 poison.

Two phrases are pinned as string constants: the shortest (47 bytes) and longest
(107 bytes) 12-word English BIP-39 phrases that exist. A random draw of 500
phrases will essentially never contain a 47-byte one, and length-dependent
zero-padding is precisely where a packing bug lives.

- [ ] **Step 1: Add the two extreme phrases** to the `mod tests` block in
      `src/gpu/metal.rs`, next to `CANONICAL_PHRASE`:

```rust
    /// The shortest possible 12-word English BIP-39 phrase: 11 × 3 letters + 11
    /// spaces + a 3-letter checksum word = 47 bytes.
    const SHORTEST_PHRASE: &str = "act act act act act act act act act act act box";
    /// The longest: 11 × 8 letters + 11 spaces + an 8-letter checksum word = 107
    /// bytes. `pack_key_block` zero-pads to 128, so this is the last length
    /// before the (absent) SHA-512 pre-hash path would be needed.
    const LONGEST_PHRASE: &str = "abstract abstract abstract abstract abstract abstract abstract abstract abstract abstract abstract attitude";

    /// PBKDF2-HMAC-SHA512 with an arbitrary iteration count, via `ring` — the
    /// same primitive `src/seed.rs:12` uses, but with `iters` free.
    fn ring_reference(phrase: &str, iters: u32) -> [u8; 64] {
        let mut out = [0u8; 64];
        ring::pbkdf2::derive(
            ring::pbkdf2::PBKDF2_HMAC_SHA512,
            std::num::NonZeroU32::new(iters).expect("iters >= 1"),
            crate::seed::BIP39_SALT,
            phrase.as_bytes(),
            &mut out,
        );
        out
    }
```

- [ ] **Step 2: Write the test.** Add to the same block:

```rust
    /// `total_iters == 1` is the case the do-while exists for: PBKDF2 with
    /// c == 1 is T == U_1, already computed by the prologue, so the wave still
    /// needs one iterate dispatch purely to carry `finalize`.
    #[test]
    fn gpu_matches_ring_at_total_iters_1_2_3_16_2048() {
        let Some(mut gpu) = gpu_for_test() else { return };
        let phrases = [CANONICAL_PHRASE, SHORTEST_PHRASE, LONGEST_PHRASE];
        for iters in [1u32, 2, 3, 16, 2048] {
            let out = gpu.derive(&phrases, iters).expect("wave");
            assert_eq!(out.len(), phrases.len());
            for (i, phrase) in phrases.iter().enumerate() {
                assert_eq!(
                    hex::encode(*out[i]),
                    hex::encode(ring_reference(phrase, iters)),
                    "iters={iters} index={i} phrase=`{phrase}` ({} bytes)",
                    phrase.len()
                );
            }
        }
    }
```

- [ ] **Step 3: Run it — it passes. Now break the do-while and watch it fail.** In
      `src/gpu/metal.rs`, replace:

```rust
        let mut slot_ix = 0usize;
        loop {
            if stop.load(Ordering::Relaxed) {
```

with:

```rust
        let mut slot_ix = 0usize;
        while remaining > 0 {
            if stop.load(Ordering::Relaxed) {
```

and replace the loop's tail:

```rust
            slot_ix = (slot_ix + 1) % PIPELINE_DEPTH;
            if remaining == 0 {
                break;
            }
        }
```

with:

```rust
            slot_ix = (slot_ix + 1) % PIPELINE_DEPTH;
        }
```

then run:

```sh
cargo test gpu_matches_ring_at_total_iters
```

Expected failure — the first assertion, at `iters=1`, comparing the 0xA5 poison
against `ring`:

```
assertion `left == right` failed: iters=1 index=0 phrase=`abandon abandon ... about` (93 bytes)
  left: "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5"
 right: "64d8279a3894fed8d8847f5c3c9a42678dc846253fcda33157df5c148ab9df4ac3c9079d364e2a6f9d24b24c3ae858cdb0cfb546e01986cee10967f2473a2b37"
```

(The `left` value is 64 bytes of `a5` — that is the poison surviving because
`finalize` never ran. Read it and understand it before moving on: this is what a
silent GPU fault looks like from the host.)

- [ ] **Step 4: Revert the mutation.** Restore `loop {` and the
      `if remaining == 0 { break; }` tail exactly as Task 3.4 wrote them, then:

```sh
cargo test gpu_matches_ring_at_total_iters
```

Expected: `test result: ok. 1 passed`.

- [ ] **Step 5: Full suite, formatting and lints, both feature legs.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy
rustfmt --edition 2021 src/gpu/metal.rs
cargo clippy --all-targets 2>&1 | grep -c -- '-->'
cargo clippy --all-targets 2>&1 | grep -c -- '--> src/gpu/' || true
cargo test
cargo test --no-default-features
```

Expected: the first clippy count is `12` — the pre-existing baseline recorded in
Milestone 1 Task 1.8 Step 5, unchanged by this task — and the second is `0`, i.e.
this task added no diagnostic of its own. Do **not** write "expect no warnings":
`cargo clippy --all-targets` is not clean on this tree. All pre-existing tests
still pass by name on both legs.

- [ ] **Step 6: Commit.**

```sh
git add src/gpu/metal.rs
git commit -m "gpu: pin GPU/ring agreement at iteration counts 1, 2, 3, 16 and 2048

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 3.6: `Schedule` and chunk-schedule invariance

**Files:**
- Modify: `src/gpu/mod.rs` (add `Schedule`)
- Modify: `src/gpu/metal.rs` (`run_wave` gains a `schedule` parameter; add `derive_with_schedule`; one test)

**Interfaces:**
- Consumes: `MetalPbkdf2::run_wave`, `MetalPbkdf2::derive` (Task 3.4)
- Produces:
  - `pub enum crate::gpu::Schedule { Production, Uniform(u32), Irregular(&'static [u32]) }` with `pub fn iters_for(&self, n: usize) -> u32` and `pub fn dispatches_per_command_buffer(&self) -> usize`
  - `pub fn MetalPbkdf2::run_wave(&mut self, keys, salt_block, total_iters, schedule: Schedule, stop) -> Result<Option<&[[u8; 64]]>, GpuError>` (signature change)
  - `pub fn MetalPbkdf2::derive_with_schedule(&mut self, phrases: &[&str], iters: u32, schedule: Schedule) -> Result<Vec<Zeroizing<[u8; 64]>>, GpuError>`

Correctness of the whole design depends on the resumable kernel producing the
same `T` no matter where the wave is cut, because that is what makes
`PIPELINE_DEPTH` command buffers in flight over one `states` buffer safe. That
property cannot be tested through a `run_wave` whose chunking is hard-coded, so
the chunking becomes a parameter. `Schedule` lives in `src/gpu/mod.rs`, not in
the backend, because Task 3.10's self-test — which is compiled and unit-tested on
every platform — takes it as an argument.

- [ ] **Step 1: Write the failing test.** Add to the `mod tests` block in `src/gpu/metal.rs`:

```rust
    /// The kernel is resumable: all live state is in `states`, so a wave can be
    /// split across arbitrarily many dispatches. If that were not exactly true,
    /// depth-3 pipelining over one `states` buffer would be unsound. Three
    /// schedules, one of them irregular, must be BIT-IDENTICAL.
    #[test]
    fn gpu_chunk_schedule_invariance() {
        let Some(mut gpu) = gpu_for_test() else { return };
        let phrases = [CANONICAL_PHRASE, SHORTEST_PHRASE, LONGEST_PHRASE];
        let schedules = [
            ("one-shot", Schedule::Uniform(2047)),
            ("production R=8", Schedule::Production),
            ("irregular", Schedule::Irregular(&[1, 1000, 46, 1000])),
            ("R=1", Schedule::Uniform(1)),
        ];
        for (label, schedule) in schedules {
            let out = gpu
                .derive_with_schedule(&phrases, crate::seed::PBKDF2_ROUNDS, schedule)
                .expect("wave");
            assert_eq!(out.len(), phrases.len());
            assert_eq!(hex::encode(*out[0]), CANONICAL_SEED_HEX, "schedule {label}");
            for (i, phrase) in phrases.iter().enumerate() {
                assert_eq!(
                    hex::encode(*out[i]),
                    hex::encode(ring_reference(phrase, crate::seed::PBKDF2_ROUNDS)),
                    "schedule {label} index {i}"
                );
            }
        }
    }
```

- [ ] **Step 2: Run it and watch it fail.**

```sh
cargo test gpu_chunk_schedule_invariance
```

Expected failure, verbatim:

```
error[E0433]: failed to resolve: use of undeclared type `Schedule`
```

- [ ] **Step 3: Add `Schedule` to `src/gpu/mod.rs`.** Append:

```rust
/// How one wave's 2047 U-iterations are cut into dispatches.
///
/// `Production` is the measured schedule. The other two exist so the self-test
/// and `gpu_chunk_schedule_invariance` can prove that the resumable kernel's
/// output does not depend on where the wave is cut — the single property that
/// makes `PIPELINE_DEPTH` command buffers in flight over one `states` buffer
/// safe. Metal ordering guarantees are relied on here: command buffers on one
/// queue execute in commit order, and dispatches inside one serial compute
/// encoder are barriered. Both are documented and were verified empirically.
/// Do NOT reach for `MTLFence` speculatively; add it only if this test fails.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Schedule {
    /// `ITERS_PER_DISPATCH` per dispatch, `DISPATCHES_PER_COMMAND_BUFFER` per
    /// command buffer: 2047 = 255*8 + 7 → 256 dispatches, 64 command buffers,
    /// ~8.8 ms each.
    Production,
    /// A fixed number of iterations per dispatch, one dispatch per command
    /// buffer. `Uniform(2047)` is the one-shot case.
    Uniform(u32),
    /// An explicit, deliberately irregular sequence; the last entry repeats if
    /// more dispatches are needed. One dispatch per command buffer.
    Irregular(&'static [u32]),
}

impl Schedule {
    /// Iterations for the `n`-th iterate dispatch of a wave (0-based), before
    /// clamping to what remains.
    pub fn iters_for(&self, n: usize) -> u32 {
        match self {
            Schedule::Production => ITERS_PER_DISPATCH,
            Schedule::Uniform(r) => (*r).max(1),
            Schedule::Irregular(steps) => {
                if steps.is_empty() {
                    ITERS_PER_DISPATCH
                } else {
                    steps[n.min(steps.len() - 1)].max(1)
                }
            }
        }
    }

    /// One dispatch per command buffer for the non-production schedules, so an
    /// irregular cut also spreads across the depth-3 ring — which is where a
    /// mis-ordered command buffer would show up.
    pub fn dispatches_per_command_buffer(&self) -> usize {
        match self {
            Schedule::Production => DISPATCHES_PER_COMMAND_BUFFER,
            _ => 1,
        }
    }
}
```

- [ ] **Step 4: Thread the schedule through `run_wave`.** In `src/gpu/metal.rs`:

Replace the `crate::gpu` import with the line below. `ITERS_PER_DISPATCH` and
`DISPATCHES_PER_COMMAND_BUFFER` move out of `run_wave` and into `Schedule`, so
leaving them imported would be an unused-import warning:

```rust
use crate::gpu::{
    classify_command_buffer_status, GpuError, GpuStatus, Schedule, MAX_THREADS_PER_THREADGROUP,
    PIPELINE_DEPTH, WAVE,
};
```

Change the signature from:

```rust
        total_iters: u32,
        stop: &AtomicBool,
    ) -> Result<Option<&[[u8; 64]]>, GpuError> {
```

to:

```rust
        total_iters: u32,
        schedule: Schedule,
        stop: &AtomicBool,
    ) -> Result<Option<&[[u8; 64]]>, GpuError> {
```

Change:

```rust
        let mut slot_ix = 0usize;
        loop {
```

to:

```rust
        let mut slot_ix = 0usize;
        let mut dispatch_ix = 0usize;
        let per_cb = schedule.dispatches_per_command_buffer();
        loop {
```

Change:

```rust
                for _ in 0..DISPATCHES_PER_COMMAND_BUFFER {
                    let iters = remaining.min(ITERS_PER_DISPATCH);
                    remaining -= iters;
```

to:

```rust
                for _ in 0..per_cb {
                    let iters = remaining.min(schedule.iters_for(dispatch_ix));
                    remaining -= iters;
                    dispatch_ix += 1;
```

- [ ] **Step 5: Split `derive`.** Replace the whole `pub fn derive` body in
      `src/gpu/metal.rs` with:

```rust
    /// One wave under the measured production schedule. This is the entry point
    /// the producer thread uses.
    pub fn derive(
        &mut self,
        phrases: &[&str],
        iters: u32,
    ) -> Result<Vec<Zeroizing<[u8; 64]>>, GpuError> {
        self.derive_with_schedule(phrases, iters, Schedule::Production)
    }

    /// One wave under an explicit dispatch schedule. The `Vec<KeyBlock>` holds
    /// the plaintext phrases, so it is `Zeroizing`.
    pub fn derive_with_schedule(
        &mut self,
        phrases: &[&str],
        iters: u32,
        schedule: Schedule,
    ) -> Result<Vec<Zeroizing<[u8; 64]>>, GpuError> {
        let salt = pack_salt_block(crate::seed::BIP39_SALT)?;
        let keys: Zeroizing<Vec<KeyBlock>> = Zeroizing::new(
            phrases
                .iter()
                .map(|p| pack_key_block(p.as_bytes()))
                .collect(),
        );
        match self.run_wave(&keys, &salt, iters, schedule, &AtomicBool::new(false))? {
            Some(seeds) => Ok(seeds.iter().map(|s| Zeroizing::new(*s)).collect()),
            None => Err(GpuError::BadConfig(
                "wave abandoned without a stop request".to_string(),
            )),
        }
    }
```

- [ ] **Step 6: Run the test and watch it pass.**

```sh
cargo test gpu_chunk_schedule_invariance
```

Expected: `test result: ok. 1 passed`.

- [ ] **Step 7: Full suite, formatting and lints, both feature legs.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy
rustfmt --edition 2021 src/gpu/mod.rs src/gpu/metal.rs
cargo clippy --all-targets 2>&1 | grep -c -- '-->'
cargo clippy --all-targets 2>&1 | grep -c -- '--> src/gpu/' || true
cargo test
cargo test --no-default-features
```

Expected: the first clippy count is `12` — the pre-existing baseline recorded in
Milestone 1 Task 1.8 Step 5, unchanged by this task — and the second is `0`, i.e.
this task added no diagnostic of its own. Do **not** write "expect no warnings":
`cargo clippy --all-targets` is not clean on this tree. All pre-existing tests
still pass by name on both legs.

- [ ] **Step 8: Commit.**

```sh
git add src/gpu/mod.rs src/gpu/metal.rs
git commit -m "gpu: parameterise the dispatch schedule and pin chunk-schedule invariance

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 3.7: The 512-phrase three-way differential (GPU vs `ring` vs 4-lane)

**Files:**
- Modify: `src/gpu/metal.rs` (add the deterministic corpus helper and one test)

**Interfaces:**
- Consumes: `MetalPbkdf2::derive` (Task 3.4); `pub fn crate::seed::derive_seed`, `pub fn crate::seed::derive_seeds`, `pub const crate::pbkdf2_lanes::LANES` (pre-existing)
- Produces: nothing new outside `#[cfg(test)]`.

Asserting against `ring` **and** the 4-lane NEON path in one test is deliberate.
`ring`-only would miss the case where the GPU and `ring` agree but the
accelerated CPU path has drifted — which is exactly the situation where a
CPU-found match and a GPU-found match in the same `vanity_wallets.csv` disagree
with each other.

The corpus is `ChaCha20Rng::seed_from_u64(0x5EED_1234)`, **not** `StdRng`, whose
algorithm `rand` explicitly reserves the right to change in a minor release —
which would silently reshuffle the corpus exactly when someone is bisecting a GPU
failure. Composition: the canonical phrase at index 0 **and** index 511, the two
length extremes at indices 1 and 2, and the rest from the stream. Failure
messages carry index, phrase and both hex seeds so a red build replays by index.

- [ ] **Step 1: Write the failing test.** Add to the `mod tests` block in `src/gpu/metal.rs`:

```rust
    use bip39::{Language, Mnemonic};
    use rand::{RngCore, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    /// 520 entries so the ragged-count test in Task 3.8 can ask for 513.
    const CORPUS_LEN: usize = 520;

    /// Deterministic differential corpus. ChaCha20, fixed seed: reproducible
    /// across machines and across `rand` minor releases.
    fn deterministic_corpus() -> Vec<Mnemonic> {
        let mut rng = ChaCha20Rng::seed_from_u64(0x5EED_1234);
        let mut out = Vec::with_capacity(CORPUS_LEN);
        out.push(Mnemonic::from_phrase(CANONICAL_PHRASE, Language::English).expect("canonical"));
        out.push(Mnemonic::from_phrase(SHORTEST_PHRASE, Language::English).expect("47-byte"));
        out.push(Mnemonic::from_phrase(LONGEST_PHRASE, Language::English).expect("107-byte"));
        while out.len() < CORPUS_LEN {
            // The canonical vector again at the LAST index of the 512-wave, so
            // a kernel that only ever writes tid 0 correctly cannot pass.
            if out.len() == 511 {
                out.push(
                    Mnemonic::from_phrase(CANONICAL_PHRASE, Language::English).expect("canonical"),
                );
                continue;
            }
            let mut e = [0u8; 16];
            rng.fill_bytes(&mut e);
            out.push(Mnemonic::from_entropy(&e, Language::English).expect("16 bytes is valid"));
        }
        out
    }

    #[test]
    fn deterministic_corpus_has_the_pinned_shape() {
        let c = deterministic_corpus();
        assert_eq!(c.len(), CORPUS_LEN);
        assert_eq!(c[0].phrase(), CANONICAL_PHRASE);
        assert_eq!(c[1].phrase().len(), 47);
        assert_eq!(c[2].phrase().len(), 107);
        assert_eq!(c[511].phrase(), CANONICAL_PHRASE);
        let lens: Vec<usize> = c.iter().map(|m| m.phrase().len()).collect();
        assert_eq!(*lens.iter().min().expect("non-empty"), 47);
        assert_eq!(*lens.iter().max().expect("non-empty"), 107);
    }

    /// P1, the seed-agreement property, over 512 phrases at once:
    ///   gpu.derive(p)[i] == derive_seed(p)          (ring, src/seed.rs:8)
    ///                    == derive_seeds::<4>(..)[k] (4-lane, src/seed.rs:23)
    #[test]
    fn gpu_ring_and_4lane_agree_over_512_deterministic_phrases() {
        let Some(mut gpu) = gpu_for_test() else { return };
        let corpus = deterministic_corpus();
        let phrases: Vec<&str> = corpus[..512].iter().map(|m| m.phrase()).collect();
        let gpu_seeds = gpu
            .derive(&phrases, crate::seed::PBKDF2_ROUNDS)
            .expect("wave");
        assert_eq!(gpu_seeds.len(), 512);

        for (i, m) in corpus[..512].iter().enumerate() {
            let want = crate::seed::derive_seed(m);
            assert_eq!(
                hex::encode(*gpu_seeds[i]),
                hex::encode(want),
                "GPU vs ring at index {i}, phrase `{}`",
                m.phrase()
            );
        }

        for (chunk_ix, chunk) in corpus[..512].chunks(crate::pbkdf2_lanes::LANES).enumerate() {
            let lane_input: [Mnemonic; crate::pbkdf2_lanes::LANES] = std::array::from_fn(|k| {
                Mnemonic::from_phrase(chunk[k].phrase(), Language::English).expect("valid phrase")
            });
            let lanes = crate::seed::derive_seeds(&lane_input);
            for k in 0..crate::pbkdf2_lanes::LANES {
                let i = chunk_ix * crate::pbkdf2_lanes::LANES + k;
                assert_eq!(
                    hex::encode(*gpu_seeds[i]),
                    hex::encode(lanes[k]),
                    "GPU vs 4-lane at index {i}, phrase `{}`",
                    chunk[k].phrase()
                );
            }
        }
    }
```

- [ ] **Step 2: Run it and watch it fail.**

```sh
cargo test gpu_ring_and_4lane_agree
```

**This test is GREEN on its first run — there is no red phase here, and you should
not manufacture one.** Everything it consumes already exists: Task 3.3 Step 3 added
`rand_chacha = "0.3"` under `[dev-dependencies]`, and Step 1 pastes the helper,
`CORPUS_LEN` and both `#[test]` fns in a single block, so there is no intermediate
state in which `deterministic_corpus` is missing.

Do **not** expect either of these, which an earlier draft predicted:
`` error[E0433]: ... undeclared crate or module `rand_chacha` `` (the dep resolves —
`rand_chacha` 0.3.1 is already in `Cargo.lock` against the same `rand_core` 0.6.4 that
`rand` 0.8 uses), or `` error[E0425]: cannot find function `deterministic_corpus` ``
(pasted in the same block as its callers).

**The real red phase for this task is Step 5's mutation** — `k.0[0] ^= 1` on the packed
key block. That is what proves the differential is wired to anything. Run it, watch the
three-way comparison fail, and revert. If Step 5's mutation does *not* fail, stop: the
differential is not comparing what it claims to.

- [ ] **Step 3: Confirm `rand_chacha = "0.3"` is present** under `[dev-dependencies]`
      in `Cargo.toml` (Task 3.3 Step 3 added it). If it is missing, add it now:

```toml
[dev-dependencies]
tempfile = "3"
rand_chacha = "0.3"
```

- [ ] **Step 4: Run both tests and watch them pass.**

```sh
cargo test deterministic_corpus_has_the_pinned_shape
cargo test gpu_ring_and_4lane_agree
```

Expected: `ok. 1 passed` for each. The differential takes roughly 10 s under a
debug `cargo test` — the cost is the 128 four-lane CPU derivations, not the GPU
(the GPU wave itself is ~165 ms). `cargo test --release gpu_ring_and_4lane_agree`
runs it in about a second.

- [ ] **Step 5: Prove the differential bites.** Temporarily corrupt one lane of the
      host packing so the GPU and the CPU disagree — in `src/gpu/metal.rs`,
      inside `derive_with_schedule`, change:

```rust
                .map(|p| pack_key_block(p.as_bytes()))
```

to:

```rust
                .enumerate()
                .map(|(i, p)| {
                    let mut k = pack_key_block(p.as_bytes());
                    if i == 300 {
                        k.0[0] ^= 1;
                    }
                    k
                })
```

then run:

```sh
cargo test gpu_ring_and_4lane_agree
```

Expected failure:

```
assertion `left == right` failed: GPU vs ring at index 300, phrase `...`
```

- [ ] **Step 6: Revert the corruption** back to `.map(|p| pack_key_block(p.as_bytes()))`
      and confirm green:

```sh
cargo test gpu_ring_and_4lane_agree
```

- [ ] **Step 7: Full suite, formatting and lints, both feature legs.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy
rustfmt --edition 2021 src/gpu/metal.rs
cargo clippy --all-targets 2>&1 | grep -c -- '-->'
cargo clippy --all-targets 2>&1 | grep -c -- '--> src/gpu/' || true
cargo test
cargo test --no-default-features
```

Expected: the first clippy count is `12` — the pre-existing baseline recorded in
Milestone 1 Task 1.8 Step 5, unchanged by this task — and the second is `0`, i.e.
this task added no diagnostic of its own. Do **not** write "expect no warnings":
`cargo clippy --all-targets` is not clean on this tree. All pre-existing tests
still pass by name on both legs.

- [ ] **Step 8: Commit.**

```sh
git add Cargo.toml Cargo.lock src/gpu/metal.rs
git commit -m "gpu: 512-phrase three-way differential against ring and the 4-lane path

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 3.8: Ragged counts, poison beyond the live count, repeat-wave bit-identity

**Files:**
- Modify: `src/gpu/metal.rs` (add `raw_seed_slot`; add three tests)

**Interfaces:**
- Consumes: `MetalPbkdf2::derive` (Task 3.4); `deterministic_corpus` (Task 3.7)
- Produces: `pub fn MetalPbkdf2::raw_seed_slot(&self, i: usize) -> [u8; 64]`

Three properties, one implementation addition. `run_wave` dispatches with
`dispatchThreads_threadsPerThreadgroup` and a grid width of exactly `count`, so
Metal shrinks the trailing threadgroup and never creates a thread with
`tid >= p.count`; the kernel's `if (tid >= p.count) return;` is therefore
defence-in-depth against a future switch to `dispatchThreadgroups` (Step 5), not
live logic here. What these tests pin is the observable contract: after a wave of
count `n`, every slot from `n` to `WAVE - 1` still reads its `0xA5` poison.
`raw_seed_slot` is the only way to look at a slot `run_wave` deliberately refuses
to return, which is exactly what makes it worth having.

- [ ] **Step 1: Write the failing tests.** Add to the `mod tests` block in `src/gpu/metal.rs`:

```rust
    /// Counts chosen to straddle the threadgroup size (256), the SIMD width
    /// (32), and the channel block size (512).
    const RAGGED_COUNTS: [usize; 9] = [1, 2, 31, 33, 255, 257, 511, 512, 513];

    #[test]
    fn gpu_handles_ragged_counts() {
        let Some(mut gpu) = gpu_for_test() else { return };
        let corpus = deterministic_corpus();
        let phrases: Vec<&str> = corpus.iter().map(|m| m.phrase()).collect();
        for n in RAGGED_COUNTS {
            let out = gpu
                .derive(&phrases[..n], crate::seed::PBKDF2_ROUNDS)
                .expect("wave");
            assert_eq!(out.len(), n, "run_wave must return EXACTLY count entries");
            for i in [0usize, n / 2, n - 1] {
                assert_eq!(
                    hex::encode(*out[i]),
                    hex::encode(crate::seed::derive_seed(&corpus[i])),
                    "n={n} index={i} phrase=`{}`",
                    corpus[i].phrase()
                );
            }
        }
    }

    /// A thread past the live count must not write. If it did, a later wave
    /// with a larger count would silently serve the previous wave's seed for
    /// those slots.
    #[test]
    fn gpu_slots_beyond_count_keep_their_poison() {
        let Some(mut gpu) = gpu_for_test() else { return };
        let corpus = deterministic_corpus();
        let phrases: Vec<&str> = corpus.iter().map(|m| m.phrase()).collect();
        for n in RAGGED_COUNTS {
            let _ = gpu
                .derive(&phrases[..n], crate::seed::PBKDF2_ROUNDS)
                .expect("wave");
            for slot in [n, n + 1, crate::gpu::WAVE - 1] {
                assert_eq!(
                    gpu.raw_seed_slot(slot),
                    [0xA5u8; 64],
                    "slot {slot} was written by a wave of count {n}"
                );
            }
        }
    }

    /// Two identical waves must produce bit-identical seeds. A GPU that is
    /// racing on `states` — the failure mode depth-3 pipelining could
    /// introduce — shows up here as an intermittent difference.
    #[test]
    fn gpu_repeat_wave_is_bit_identical() {
        let Some(mut gpu) = gpu_for_test() else { return };
        let corpus = deterministic_corpus();
        let phrases: Vec<&str> = corpus[..512].iter().map(|m| m.phrase()).collect();
        let first: Vec<String> = gpu
            .derive(&phrases, crate::seed::PBKDF2_ROUNDS)
            .expect("wave")
            .iter()
            .map(|s| hex::encode(**s))
            .collect();
        for round in 0..3 {
            let again: Vec<String> = gpu
                .derive(&phrases, crate::seed::PBKDF2_ROUNDS)
                .expect("wave")
                .iter()
                .map(|s| hex::encode(**s))
                .collect();
            assert_eq!(first, again, "wave {round} differed from the first");
        }
    }
```

- [ ] **Step 2: Run them and watch them fail.**

```sh
cargo test gpu_slots_beyond_count_keep_their_poison
```

Expected failure, verbatim:

```
error[E0599]: no method named `raw_seed_slot` found for struct `MetalPbkdf2` in the current scope
```

- [ ] **Step 3: Add `raw_seed_slot`** inside `impl MetalPbkdf2` in `src/gpu/metal.rs`,
      immediately after `run_wave`:

```rust
    /// Raw read of one 64-byte slot of the `seeds` buffer, INCLUDING slots past
    /// the live count that `run_wave` refuses to return. Exists so
    /// `gpu_slots_beyond_count_keep_their_poison` can prove that nothing wrote
    /// past the live count and the 0xA5 poison survived there — the only way to
    /// observe a slot the safe API deliberately hides.
    pub fn raw_seed_slot(&self, i: usize) -> [u8; 64] {
        assert!(i < WAVE, "slot {i} is outside the {WAVE}-candidate wave");
        // SAFETY: `seeds` is WAVE * 64 bytes owned by this engine, no command
        // buffer is in flight (`run_wave` waits on every one before returning),
        // and `[u8; 64]` has alignment 1 and no invalid bit patterns.
        let p = self.bufs.seeds.contents().as_ptr() as *const [u8; 64];
        unsafe { *p.add(i) }
    }
```

- [ ] **Step 4: Run the three tests and watch them pass.**

```sh
cargo test gpu_handles_ragged_counts
cargo test gpu_slots_beyond_count_keep_their_poison
cargo test gpu_repeat_wave_is_bit_identical
```

Expected: `ok. 1 passed` for each.

- [ ] **Step 5: Record why the `tid >= p.count` guard is unreachable under this
      dispatch — there is no mutation to run here.** It is tempting to "prove the
      guard bites" by editing `src/gpu/pbkdf2_bip39.metal` — in `pbkdf2_iterate`
      (line 140), `if (tid >= p.count) return;` → `if (tid >= 8192u) return;` —
      and watching `gpu_slots_beyond_count_keep_their_poison` go red. **It will
      not go red.** `run_wave` dispatches with
      `enc.dispatchThreads_threadsPerThreadgroup(...)` and a grid width of
      exactly `count`, and `dispatchThreads` launches exactly `count` threads:
      Metal shrinks the trailing threadgroup rather than rounding the grid up to
      a whole number of threadgroups. No thread with `tid >= p.count` is ever
      created, so removing the guard changes nothing observable — the mutation
      would report "still green" and leave you unable to tell whether the test,
      the kernel or the mutation was at fault. Do not perform it.

      State instead the two facts this task actually establishes:

      1. **The guard is retained as defence-in-depth, not as live logic.** If
         anyone ever switches this dispatch to
         `dispatchThreadgroups_threadsPerThreadgroup` — which DOES round the grid
         up to a whole number of threadgroups, and so WOULD create surplus
         threads with `tid >= p.count` — that one line is what keeps those
         threads from writing past the live count. It costs nothing today and is
         the difference between correct and silently corrupt then.
      2. **`gpu_slots_beyond_count_keep_their_poison` pins the poison contract,
         not the guard.** What it proves is that after a wave of count `n`, every
         slot from `n` to `WAVE - 1` still reads `0xA5` — i.e. `run_wave`
         re-poisons `seeds` before every wave and nothing wrote past `count`,
         whatever the mechanism. That is precisely the property a later,
         larger-count wave depends on, and it holds under either dispatch API.

      Nothing to run in this step. Leave `src/gpu/pbkdf2_bip39.metal` untouched.

- [ ] **Step 6: Confirm the kernel is still byte-exact and both tests are green.**
      Step 5 changed nothing, so the regeneration below is a no-op — run it anyway,
      as the cheap proof that no stray edit reached the kernel:

```sh
awk '/^\/\/ A\/B ONLY \(not shipped\)/{exit} {print}' \
  docs/superpowers/specs/prototype/pbkdf2_bip39.metal > src/gpu/pbkdf2_bip39.metal
shasum -a 256 src/gpu/pbkdf2_bip39.metal
cargo test gpu_slots_beyond_count_keep_their_poison
cargo test kernel_source
```

Expected: hash `871ef1706bd5ba0a9ddb420872ea6a2db3556bf6951453942678d364b123f4b2`, and
both test runs green.

- [ ] **Step 7: Full suite, formatting and lints, both feature legs.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy
rustfmt --edition 2021 src/gpu/metal.rs
cargo clippy --all-targets 2>&1 | grep -c -- '-->'
cargo clippy --all-targets 2>&1 | grep -c -- '--> src/gpu/' || true
cargo test
cargo test --no-default-features
```

Expected: the first clippy count is `12` — the pre-existing baseline recorded in
Milestone 1 Task 1.8 Step 5, unchanged by this task — and the second is `0`, i.e.
this task added no diagnostic of its own. Do **not** write "expect no warnings":
`cargo clippy --all-targets` is not clean on this tree. All pre-existing tests
still pass by name on both legs.

- [ ] **Step 8: Commit.**

```sh
git add src/gpu/metal.rs
git commit -m "gpu: pin ragged counts, poison beyond the live count, and repeat-wave identity

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 3.9: An injected command-buffer error discards the whole wave

**Files:**
- Modify: `src/gpu/metal.rs` (two `Cell` fields, `inject_command_buffer_fault`, the fault branch in `check_status`, a counter reset in `run_wave`; one test)

**Interfaces:**
- Consumes: `MetalPbkdf2::check_status` (Task 3.4); `MetalPbkdf2::run_wave(&mut self, keys: &[KeyBlock], salt_block: &[u64; 16], total_iters: u32, schedule: Schedule, stop: &AtomicBool) -> Result<Option<&[[u8; 64]]>, GpuError>` — the six-parameter form Task 3.6 produced by inserting `schedule: Schedule` before `stop`, not Task 3.4's five-parameter original
- Produces: `pub fn MetalPbkdf2::inject_command_buffer_fault(&self, nth: u32)` (`#[cfg(test)]`)

A real GPU fault cannot be provoked on demand, and the rule it exercises — a
non-`Completed` command buffer discards the **entire** wave, with no partial
output — is the one that stands between a mid-wave GPU reset and a
wrong-but-plausible seed reaching a user's wallet. So the fault is injected at
the exact point the real one would be observed: the status check.

`Cell` rather than `&mut self` because `check_status` is called from inside the
`autoreleasepool` closure, which already holds shared borrows of `self.queue`,
`self.iterate` and `self.bufs`. `MetalPbkdf2` is thread-confined by construction
(it holds `Retained<ProtocolObject<dyn MTLBuffer>>`, which is `!Send`), so `Cell`
costs nothing.

- [ ] **Step 1: Write the failing test.** Add to the `mod tests` block in `src/gpu/metal.rs`:

```rust
    /// The whole wave is discarded on ANY command-buffer failure — there is no
    /// partial-success shape. Without this, a mid-wave GPU reset silently drops
    /// 8 of 2048 U-iterations and finalize writes a T that is the XOR of only
    /// 2,039 values.
    #[test]
    fn gpu_command_buffer_error_yields_err_not_partial_output() {
        let Some(mut gpu) = gpu_for_test() else { return };

        // Baseline: the same wave succeeds with no fault injected.
        let good = gpu
            .derive(&[CANONICAL_PHRASE], crate::seed::PBKDF2_ROUNDS)
            .expect("wave");
        assert_eq!(hex::encode(*good[0]), CANONICAL_SEED_HEX);

        // Fault the 3rd status check of the next wave: one prologue plus two
        // iterate command buffers have already been accepted, so this is
        // squarely mid-wave, not at a boundary.
        gpu.inject_command_buffer_fault(3);
        match gpu.derive(&[CANONICAL_PHRASE], crate::seed::PBKDF2_ROUNDS) {
            Err(GpuError::CommandBuffer { status, message }) => {
                assert_eq!(status, 5);
                assert!(message.contains("injected"), "{message}");
            }
            Err(other) => panic!("wrong error: {other:?}"),
            Ok(seeds) => panic!(
                "a faulted wave produced {} seeds instead of an error",
                seeds.len()
            ),
        }
    }
```

- [ ] **Step 2: Run it and watch it fail.**

```sh
cargo test gpu_command_buffer_error_yields_err
```

Expected failure, verbatim:

```
error[E0599]: no method named `inject_command_buffer_fault` found for struct `MetalPbkdf2` in the current scope
```

- [ ] **Step 3: Add the two fields.** In `src/gpu/metal.rs`, change the
      `MetalPbkdf2` struct from:

```rust
    bufs: WaveBuffers,
    tg: usize,
}
```

to:

```rust
    bufs: WaveBuffers,
    tg: usize,
    /// Test-only fault injection. `Cell`, not `&mut self`, because
    /// `check_status` runs inside the autorelease-pool closure, which already
    /// holds shared borrows of the queue, the pipelines and the buffers.
    /// `MetalPbkdf2` is thread-confined (it holds `!Send` Metal objects), so
    /// `Cell` costs nothing.
    #[cfg(test)]
    fault_at_command_buffer: std::cell::Cell<Option<u32>>,
    #[cfg(test)]
    command_buffers_checked: std::cell::Cell<u32>,
}
```

and the constructor's `Ok(MetalPbkdf2 { … })` from:

```rust
            tg,
        })
    }
```

to:

```rust
            tg,
            #[cfg(test)]
            fault_at_command_buffer: std::cell::Cell::new(None),
            #[cfg(test)]
            command_buffers_checked: std::cell::Cell::new(0),
        })
    }
```

- [ ] **Step 4: Add the injector and the fault branch.** In `src/gpu/metal.rs`,
      replace the whole `check_status` method with:

```rust
    /// Make the `nth` command-buffer status check of the NEXT wave report a
    /// synthetic `MTLCommandBufferStatusError` (5). The counter resets at the
    /// start of every `run_wave`, so `nth` is always relative to one wave.
    #[cfg(test)]
    pub fn inject_command_buffer_fault(&self, nth: u32) {
        self.fault_at_command_buffer.set(Some(nth));
    }

    fn check_status(&self, cb: &ProtocolObject<dyn MTLCommandBuffer>) -> Result<(), GpuError> {
        #[cfg(test)]
        {
            let n = self.command_buffers_checked.get() + 1;
            self.command_buffers_checked.set(n);
            if self.fault_at_command_buffer.get() == Some(n) {
                return classify_command_buffer_status(
                    5,
                    Some("injected command-buffer fault".to_string()),
                );
            }
        }
        let status = cb.status().0 as i64;
        let message = cb.error().map(|e| e.localizedDescription().to_string());
        classify_command_buffer_status(status, message)
    }
```

- [ ] **Step 5: Reset the counter per wave.** In `run_wave`, immediately after:

```rust
        let count = keys.len() as u32;
```

add:

```rust
        #[cfg(test)]
        self.command_buffers_checked.set(0);
```

- [ ] **Step 6: Run the test and watch it pass.**

```sh
cargo test gpu_command_buffer_error_yields_err
```

Expected: `test result: ok. 1 passed`.

- [ ] **Step 7: Full suite, formatting and lints, both feature legs.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy
rustfmt --edition 2021 src/gpu/metal.rs
cargo clippy --all-targets 2>&1 | grep -c -- '-->'
cargo clippy --all-targets 2>&1 | grep -c -- '--> src/gpu/' || true
cargo test
cargo test --no-default-features
```

Expected: the first clippy count is `12` — the pre-existing baseline recorded in
Milestone 1 Task 1.8 Step 5, unchanged by this task — and the second is `0`, i.e.
this task added no diagnostic of its own. Do **not** write "expect no warnings":
`cargo clippy --all-targets` is not clean on this tree. All pre-existing tests
still pass by name on both legs.

- [ ] **Step 8: Commit.**

```sh
git add src/gpu/metal.rs
git commit -m "gpu: an injected command-buffer fault discards the whole wave

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 3.10: The injectable self-test

**Files:**
- Modify: `src/gpu/selftest.rs` (Milestone 1 Task 1.3 created it with `SelfTestError`; this task fills in the rest)
- Modify: `src/gpu/mod.rs` (add `From<SelfTestError> for GpuDisableReason` — the module is **already** declared)

**Interfaces:**
- Consumes: `pub enum GpuError`, `pub enum Schedule`, `pub enum GpuDisableReason`; `pub fn crate::seed::derive_seed`, `pub const crate::seed::PBKDF2_ROUNDS`
- Produces:
  - `pub enum crate::gpu::selftest::SelfTestError` (Milestone 1's taxonomy plus one variant, `DuplicateEntropy`)
  - `pub fn crate::gpu::selftest::self_test<F>(stop: &AtomicBool, derive: F) -> Result<(), SelfTestError> where F: FnMut(&[&str], u32, Schedule) -> Result<Vec<Zeroizing<[u8; 64]>>, GpuError>`
  - `pub const SELF_TEST_COUNT: usize = 512`, `SELF_TEST_RAGGED_COUNT: usize = 511`, `CANONICAL_PHRASE`, `CANONICAL_SEED_HEX`, `IRREGULAR_SCHEDULE`
  - `impl From<SelfTestError> for GpuDisableReason`

`derive` is **injected** so the fault-detection logic itself is unit-testable on
any machine by passing a deliberately faulty closure. No Metal type appears in
this file, so it compiles and its tests run on Linux and under
`--no-default-features`.

**The `count = 1` self-test is rejected.** A single candidate structurally cannot
exercise `keyblocks + 16*tid`, `states + tid`, `seeds + 64*tid`, or the host-side
128-byte `KeyBlock` stride — every candidate except tid 0 could derive from the
wrong key block and a count=1 test would still pass cleanly.

**Order matters.** The BIP-39 canonical vector is checked *before* any `ring`
cross-check. Both the gate and the differential compare against `ring::pbkdf2`,
which is what `derive_seed` uses — circular if `ring` were wrong. Anchoring to
the external constant first makes the honest claim: the GPU is proven to agree
with the code that the pinned vectors already pin.

**Note on `SelfTestError::DuplicateEntropy`.** The spec's variant list has no
arm for the entropy-distinctness check it also requires; abusing `RingMismatch`
for it would produce an unreadable failure. One extra variant is added — it is
the *only* difference between the `SelfTestError` Milestone 1 Task 1.3 put in
this file and the one Step 4 below writes.

**Note on `stop`.** One real self-test run costs ~154 ms of GPU plus ~133 ms of
`ring`, i.e. ~300 ms on the GPU thread at startup. The spec's termination table
requires `stop` to be "checked after each phase", so `self_test` takes the flag
and returns `Ok(())` the moment it is raised. `Ok(())` and not an error: nothing
was proven faulty, and the caller is quitting anyway — a spurious
`GpuDisableReason::SelfTest` on the way out would be a lie.

- [ ] **Step 1: Append one failing test to the existing `src/gpu/selftest.rs`.**
      Milestone 1 Task 1.3 created this file and it currently holds `SelfTestError`
      and nothing else. **Do not overwrite it here** — deleting `SelfTestError`
      would break `pub use selftest::SelfTestError;` and
      `GpuDisableReason::SelfTest(SelfTestError)` in `src/gpu/mod.rs`, and the red
      phase you would then read is a cascade of `error[E0432]`/`error[E0412]`
      rather than the one failure this step is driving.

      Add these three `use` lines directly below the file's module doc comment,
      keeping the existing `SelfTestError` exactly where it is:

```rust
use crate::gpu::{GpuError, Schedule};
use std::sync::atomic::{AtomicBool, Ordering};
use zeroize::Zeroizing;
```

      and append this test module to the end of the file:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    /// A correct backend: `ring`, ignoring the schedule (a correct GPU produces
    /// the same bytes under every schedule — that is the property being tested).
    fn reference(
        phrases: &[&str],
        iters: u32,
        _schedule: Schedule,
    ) -> Result<Vec<Zeroizing<[u8; 64]>>, GpuError> {
        Ok(phrases
            .iter()
            .map(|p| {
                let mut out = [0u8; 64];
                ring::pbkdf2::derive(
                    ring::pbkdf2::PBKDF2_HMAC_SHA512,
                    std::num::NonZeroU32::new(iters).expect("iters >= 1"),
                    crate::seed::BIP39_SALT,
                    p.as_bytes(),
                    &mut out,
                );
                Zeroizing::new(out)
            })
            .collect())
    }

    #[test]
    fn accepts_a_correct_derive_fn() {
        assert_eq!(self_test(&AtomicBool::new(false), reference), Ok(()));
    }
}
```

      `Ordering` is unused until Step 4 adds the stop checks; `cargo test` will
      warn about it in this red phase, which is expected and disappears at Step 4.

- [ ] **Step 2: Nothing to declare.** `pub mod selftest;` and
      `pub use selftest::SelfTestError;` are **already** in `src/gpu/mod.rs` from
      Milestone 1 Task 1.3 Step 6 — `GpuDisableReason::SelfTest(SelfTestError)`
      could not have compiled otherwise. Adding either again is
      `error[E0428]` / `error[E0252]`. Confirm, do not add:

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy
grep -c 'pub mod selftest;\|pub use selftest::SelfTestError;' src/gpu/mod.rs
```

      Expected: `2`.

- [ ] **Step 3: Run the tests and watch them fail.**

```sh
cargo test selftest
```

Expected failure, verbatim:

```
error[E0425]: cannot find function `self_test` in this scope
```

- [ ] **Step 4: Replace `src/gpu/selftest.rs` wholesale — the listing below is
      the finished file, and it REPLACES the `mod tests` block Step 1 appended.**
      Write the listing over the file's entire current contents. Do **not** append
      it: appending would leave two `#[cfg(test)] mod tests` blocks in one module,
      each defining `fn reference` and `#[test] fn accepts_a_correct_derive_fn`,
      and the compiler would stop at `error[E0428]` — *the name* `tests` *is
      defined multiple times*. Nothing Step 1 wrote is lost: its three `use` lines
      are reproduced at the top of the listing, and its `reference` helper and
      `accepts_a_correct_derive_fn` reappear verbatim inside the single surviving
      `mod tests`, joined there by the nine further fault-detection tests. After
      this step the file must contain exactly one `mod tests` and exactly one
      `accepts_a_correct_derive_fn`. Its `SelfTestError` is Milestone 1 Task 1.3's enum with
      exactly one variant added — `DuplicateEntropy`, between `ScheduleDivergence`
      and `Backend`. Everything else in the enum must match what is already there
      byte for byte; if it does not, you have drifted from Milestone 1 and
      `src/gpu/mod.rs` will stop compiling.

```rust
//! GPU self-test. Runs once on the GPU thread before any candidate is accepted,
//! and is the only thing standing between a mis-compiled kernel and a user's
//! wallet.
//!
//! `derive` is injected so the fault-detection logic can be unit-tested on any
//! machine by passing a deliberately faulty closure. No Metal type appears in
//! this file: it compiles, and its tests run, on Linux and under
//! `--no-default-features`.
//!
//! Measured cost of one real run: ~154 ms of GPU plus ~512 × 260 µs = 133 ms of
//! `ring`, i.e. ~300 ms one-time on the GPU thread, off the UI thread.

use crate::gpu::{GpuError, Schedule};
use bip39::{Language, Mnemonic, MnemonicType};
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use zeroize::Zeroizing;

/// 512 candidates = 2 threadgroups at tg=256. `count = 1` is REJECTED: it
/// structurally cannot exercise `keyblocks + 16*tid`, `states + tid`,
/// `seeds + 64*tid`, or the host-side 128-byte `KeyBlock` stride — every
/// candidate except tid 0 could derive from the wrong key block and a count=1
/// test would still pass cleanly.
pub const SELF_TEST_COUNT: usize = 512;

/// Deliberately not a multiple of 256 (the threadgroup size) or of 32 (the
/// SIMD width), so the non-uniform tail of `dispatchThreads` is exercised.
pub const SELF_TEST_RAGGED_COUNT: usize = 511;

/// BIP-39 canonical vector — the same phrase and the same hex constant already
/// pinned at src/seed.rs:37 and src/seed.rs:41.
pub const CANONICAL_PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
pub const CANONICAL_SEED_HEX: &str = "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4";

/// 1 + 1000 + 46 + 1000 = 2047: the same total, cut nothing like the production
/// schedule.
pub const IRREGULAR_SCHEDULE: Schedule = Schedule::Irregular(&[1, 1000, 46, 1000]);

/// The byte `run_wave` fills `seeds` with before every wave.
const POISON: u8 = 0xA5;

#[derive(Debug, Clone, PartialEq)]
pub enum SelfTestError {
    WrongLength {
        got: usize,
        want: usize,
    },
    CanonicalVectorMismatch {
        got: String,
    },
    RingMismatch {
        index: usize,
        phrase: String,
        got: String,
        want: String,
    },
    AllZero {
        index: usize,
    },
    /// 0xA5 survived → the kernel never wrote this slot.
    Poisoned {
        index: usize,
    },
    ScheduleDivergence {
        schedule: &'static str,
        index: usize,
    },
    /// The freshly generated phrases were not all distinct — an RNG fault, not
    /// a GPU fault, but equally disqualifying.
    DuplicateEntropy {
        distinct: usize,
        want: usize,
    },
    Backend(String),
}

impl From<GpuError> for SelfTestError {
    fn from(e: GpuError) -> Self {
        SelfTestError::Backend(format!("{e:?}"))
    }
}

/// Run the whole self-test against an injected `derive`.
///
/// Six checks, in this order:
///   1. entropy distinctness over the 510 fresh phrases;
///   2. a count=512 wave, all distinct phrases;
///   3. the BIP-39 canonical vector at index 0 AND index 511 — checked BEFORE
///      any `ring` cross-check, because `ring` is what `derive_seed` uses and a
///      `ring`-first check would be circular;
///   4. no output all-zero, no output still poisoned;
///   5. every output against `crate::seed::derive_seed` (`ring`);
///   6. a count=511 ragged wave, and chunk-schedule invariance over three
///      schedules.
///
/// `stop` is read before the first phase and after each one. One run is ~154 ms
/// of GPU plus ~133 ms of `ring` — long enough that a quit issued during startup
/// would otherwise go unobserved for ~300 ms. A raised flag returns `Ok(())`,
/// not an error: nothing was proven faulty, and reporting a
/// `GpuDisableReason::SelfTest` on the way out would be a lie.
pub fn self_test<F>(stop: &AtomicBool, mut derive: F) -> Result<(), SelfTestError>
where
    F: FnMut(&[&str], u32, Schedule) -> Result<Vec<Zeroizing<[u8; 64]>>, GpuError>,
{
    if stop.load(Ordering::Relaxed) {
        return Ok(());
    }

    let mut mnemonics: Vec<Mnemonic> = Vec::with_capacity(SELF_TEST_COUNT);
    mnemonics
        .push(Mnemonic::from_phrase(CANONICAL_PHRASE, Language::English).expect("canonical phrase"));
    for _ in 1..SELF_TEST_COUNT - 1 {
        mnemonics.push(Mnemonic::new(MnemonicType::Words12, Language::English));
    }
    mnemonics
        .push(Mnemonic::from_phrase(CANONICAL_PHRASE, Language::English).expect("canonical phrase"));

    let fresh: HashSet<[u8; 16]> = mnemonics[1..SELF_TEST_COUNT - 1]
        .iter()
        .map(|m| {
            let mut e = [0u8; 16];
            e.copy_from_slice(m.entropy());
            e
        })
        .collect();
    if fresh.len() != SELF_TEST_COUNT - 2 {
        return Err(SelfTestError::DuplicateEntropy {
            distinct: fresh.len(),
            want: SELF_TEST_COUNT - 2,
        });
    }
    if stop.load(Ordering::Relaxed) {
        return Ok(());
    }

    let phrases: Vec<&str> = mnemonics.iter().map(|m| m.phrase()).collect();

    let full = derive(&phrases, crate::seed::PBKDF2_ROUNDS, Schedule::Production)?;
    if full.len() != SELF_TEST_COUNT {
        return Err(SelfTestError::WrongLength {
            got: full.len(),
            want: SELF_TEST_COUNT,
        });
    }
    for i in [0usize, SELF_TEST_COUNT - 1] {
        let got = hex::encode(*full[i]);
        if got != CANONICAL_SEED_HEX {
            return Err(SelfTestError::CanonicalVectorMismatch { got });
        }
    }
    for (i, seed) in full.iter().enumerate() {
        if seed.iter().all(|&b| b == 0) {
            return Err(SelfTestError::AllZero { index: i });
        }
        if seed.iter().all(|&b| b == POISON) {
            return Err(SelfTestError::Poisoned { index: i });
        }
    }
    if stop.load(Ordering::Relaxed) {
        return Ok(());
    }

    for (i, seed) in full.iter().enumerate() {
        let want = hex::encode(crate::seed::derive_seed(&mnemonics[i]));
        let got = hex::encode(**seed);
        if got != want {
            return Err(SelfTestError::RingMismatch {
                index: i,
                phrase: phrases[i].to_string(),
                got,
                want,
            });
        }
    }

    if stop.load(Ordering::Relaxed) {
        return Ok(());
    }

    let ragged = derive(
        &phrases[..SELF_TEST_RAGGED_COUNT],
        crate::seed::PBKDF2_ROUNDS,
        Schedule::Production,
    )?;
    if ragged.len() != SELF_TEST_RAGGED_COUNT {
        return Err(SelfTestError::WrongLength {
            got: ragged.len(),
            want: SELF_TEST_RAGGED_COUNT,
        });
    }
    for (i, seed) in ragged.iter().enumerate() {
        if seed.iter().all(|&b| b == POISON) {
            return Err(SelfTestError::Poisoned { index: i });
        }
        let want = hex::encode(crate::seed::derive_seed(&mnemonics[i]));
        let got = hex::encode(**seed);
        if got != want {
            return Err(SelfTestError::RingMismatch {
                index: i,
                phrase: phrases[i].to_string(),
                got,
                want,
            });
        }
    }

    if stop.load(Ordering::Relaxed) {
        return Ok(());
    }

    for (label, schedule) in [
        ("one-shot", Schedule::Uniform(crate::seed::PBKDF2_ROUNDS - 1)),
        ("production", Schedule::Production),
        ("irregular", IRREGULAR_SCHEDULE),
    ] {
        let one = derive(&[CANONICAL_PHRASE], crate::seed::PBKDF2_ROUNDS, schedule)?;
        if one.len() != 1 {
            return Err(SelfTestError::WrongLength {
                got: one.len(),
                want: 1,
            });
        }
        if hex::encode(*one[0]) != CANONICAL_SEED_HEX {
            return Err(SelfTestError::ScheduleDivergence {
                schedule: label,
                index: 0,
            });
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A correct backend: `ring`, ignoring the schedule (a correct GPU produces
    /// the same bytes under every schedule — that is the property being tested).
    fn reference(
        phrases: &[&str],
        iters: u32,
        _schedule: Schedule,
    ) -> Result<Vec<Zeroizing<[u8; 64]>>, GpuError> {
        Ok(phrases
            .iter()
            .map(|p| {
                let mut out = [0u8; 64];
                ring::pbkdf2::derive(
                    ring::pbkdf2::PBKDF2_HMAC_SHA512,
                    std::num::NonZeroU32::new(iters).expect("iters >= 1"),
                    crate::seed::BIP39_SALT,
                    p.as_bytes(),
                    &mut out,
                );
                Zeroizing::new(out)
            })
            .collect())
    }

    #[test]
    fn accepts_a_correct_derive_fn() {
        assert_eq!(self_test(&AtomicBool::new(false), reference), Ok(()));
    }

    #[test]
    fn detects_single_bit_flip() {
        let e = self_test(&AtomicBool::new(false), |p, i, s| {
            let mut o = reference(p, i, s)?;
            if o.len() > 7 {
                o[7][0] ^= 0x01;
            }
            Ok(o)
        })
        .unwrap_err();
        assert!(
            matches!(e, SelfTestError::RingMismatch { index: 7, .. }),
            "{e:?}"
        );
    }

    /// A permutation: every seed is individually valid, but paired with the
    /// wrong phrase. This is the mis-pairing class, and it is the one a
    /// count=1 self-test can never see.
    #[test]
    fn detects_swapped_outputs() {
        let e = self_test(&AtomicBool::new(false), |p, i, s| {
            let mut o = reference(p, i, s)?;
            if o.len() > 4 {
                o.swap(3, 4);
            }
            Ok(o)
        })
        .unwrap_err();
        assert!(
            matches!(e, SelfTestError::RingMismatch { index: 3, .. }),
            "{e:?}"
        );
    }

    #[test]
    fn detects_all_zero_output() {
        let e = self_test(&AtomicBool::new(false), |p, i, s| {
            let mut o = reference(p, i, s)?;
            if o.len() > 9 {
                o[9] = Zeroizing::new([0u8; 64]);
            }
            Ok(o)
        })
        .unwrap_err();
        assert_eq!(e, SelfTestError::AllZero { index: 9 });
    }

    #[test]
    fn detects_surviving_poison() {
        let e = self_test(&AtomicBool::new(false), |p, i, s| {
            let mut o = reference(p, i, s)?;
            if o.len() > 12 {
                o[12] = Zeroizing::new([0xA5u8; 64]);
            }
            Ok(o)
        })
        .unwrap_err();
        assert_eq!(e, SelfTestError::Poisoned { index: 12 });
    }

    /// The backend serves a previous wave's results, shifted by one — the shape
    /// a stale `seeds` buffer takes when `finalize` silently did not run.
    #[test]
    fn detects_stale_previous_result() {
        let mut previous: Option<Vec<Zeroizing<[u8; 64]>>> = None;
        let e = self_test(&AtomicBool::new(false), |p, i, s| {
            let fresh = reference(p, i, s)?;
            match previous.take() {
                None => {
                    previous = Some(fresh.clone());
                    Ok(fresh)
                }
                Some(old) => {
                    previous = Some(old.clone());
                    Ok(old[1..=p.len()].to_vec())
                }
            }
        })
        .unwrap_err();
        assert!(matches!(e, SelfTestError::RingMismatch { .. }), "{e:?}");
    }

    #[test]
    fn detects_short_output_vec() {
        let e = self_test(&AtomicBool::new(false), |p, i, s| {
            let mut o = reference(p, i, s)?;
            o.pop();
            Ok(o)
        })
        .unwrap_err();
        assert_eq!(
            e,
            SelfTestError::WrongLength {
                got: SELF_TEST_COUNT - 1,
                want: SELF_TEST_COUNT
            }
        );
    }

    #[test]
    fn detects_schedule_divergence() {
        let e = self_test(&AtomicBool::new(false), |p, i, s| {
            let mut o = reference(p, i, s)?;
            if s == Schedule::Uniform(crate::seed::PBKDF2_ROUNDS - 1) {
                o[0][63] ^= 0x80;
            }
            Ok(o)
        })
        .unwrap_err();
        assert_eq!(
            e,
            SelfTestError::ScheduleDivergence {
                schedule: "one-shot",
                index: 0
            }
        );
    }

    #[test]
    fn detects_backend_error() {
        let e = self_test(&AtomicBool::new(false), |_, _, _| {
            Err(GpuError::BufferAlloc)
        })
        .unwrap_err();
        assert_eq!(e, SelfTestError::Backend("BufferAlloc".to_string()));
    }

    /// The spec requires `stop` to be observed between self-test phases. A flag
    /// that is already raised must short-circuit before the very first phase —
    /// the `derive` closure below panics if it is ever called.
    #[test]
    fn an_already_raised_stop_short_circuits_without_a_fault() {
        let stop = AtomicBool::new(true);
        assert_eq!(
            self_test(&stop, |_, _, _| panic!(
                "derive must not run once stop is set"
            )),
            Ok(())
        );
    }
}
```

- [ ] **Step 5: Add the `From` impl that routes a self-test failure to the single
      sticky disable path.** Append to `src/gpu/mod.rs`:

```rust
/// A self-test failure is a correctness fault, not a transient: it becomes a
/// sticky `GpuDisableReason` for the life of the process. Milestone 4's
/// producer uses this via `?`.
impl From<selftest::SelfTestError> for GpuDisableReason {
    fn from(e: selftest::SelfTestError) -> Self {
        GpuDisableReason::SelfTest(e)
    }
}
```

- [ ] **Step 6: Run the tests and watch them pass.**

```sh
cargo test gpu::selftest
```

Expected: `test result: ok. 10 passed`. Nine of the ten each generate 510 fresh
mnemonics and do ~1,000 `ring` derivations, which takes about 25 s under a debug
`cargo test`; the tenth (`an_already_raised_stop_short_circuits_without_a_fault`)
returns immediately. `cargo test --release gpu::selftest` runs the lot in a
couple of seconds.

- [ ] **Step 7: Prove it runs with no GPU at all.**

```sh
cargo test --no-default-features gpu::selftest
```

Expected: the same 10 tests pass. This is the point of injecting `derive`.

- [ ] **Step 8: Full suite, formatting and lints, both feature legs.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy
rustfmt --edition 2021 src/gpu/selftest.rs src/gpu/mod.rs
cargo clippy --all-targets 2>&1 | grep -c -- '-->'
cargo clippy --all-targets 2>&1 | grep -c -- '--> src/gpu/' || true
cargo test
cargo test --no-default-features
```

Expected: the first clippy count is `12` — the pre-existing baseline recorded in
Milestone 1 Task 1.8 Step 5, unchanged by this task — and the second is `0`, i.e.
this task added no diagnostic of its own. Do **not** write "expect no warnings":
`cargo clippy --all-targets` is not clean on this tree. All pre-existing tests
still pass by name on both legs.

- [ ] **Step 9: Commit.**

```sh
git add src/gpu/selftest.rs src/gpu/mod.rs
git commit -m "gpu: injectable self-test with fault-detection tests that need no GPU

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 3.11: The RSS regression guard, and the milestone gate

**Files:**
- Modify: `src/gpu/metal.rs` (one `#[ignore]`d test)

**Interfaces:**
- Consumes: `MetalPbkdf2::derive` (Task 3.4)
- Produces: nothing new.

The autorelease-pool bug is invisible in short tests and only surfaces after
hours: `+1,861 B per command buffer` = **700 MB/hour = 16.4 GB/day**. A multi-day
vanity search is the stated use case; without the pool the process is jetsammed
overnight. This test runs 390 waves of 512 candidates = 100,230 dispatches over
25,350 command buffers — enough that a missing pool costs ~47 MB, which an 8 MiB
threshold separates cleanly from noise. It is `#[ignore]`d because it takes ~65 s.

RSS is read by shelling out to `ps`, which adds no dependency.

- [ ] **Step 1: Write the test.** Add to the `mod tests` block in `src/gpu/metal.rs`:

```rust
    /// Resident set size in KiB, via `ps`. No dependency, and it measures what
    /// actually gets the process jetsammed.
    #[cfg(test)]
    fn rss_kib() -> u64 {
        let out = std::process::Command::new("ps")
            .args(["-o", "rss=", "-p", &std::process::id().to_string()])
            .output()
            .expect("ps");
        String::from_utf8_lossy(&out.stdout)
            .trim()
            .parse()
            .expect("ps printed a number")
    }

    /// The autorelease-pool regression guard. `#[ignore]`d: ~65 s.
    ///
    /// Run it by hand with:
    ///   cargo test --release -- --ignored --nocapture gpu_no_rss_growth
    ///
    /// Without a per-command-buffer autorelease pool this leaks 1,861 B per
    /// command buffer; 25,350 command buffers is ~47 MB, so an 8 MiB threshold
    /// separates a real leak from allocator noise. Measured on an M1 with the
    /// pool in place: 15,616 KiB before → 14,064 KiB after (RSS went DOWN).
    #[test]
    #[ignore]
    fn gpu_no_rss_growth_over_100k_dispatches() {
        let Some(mut gpu) = gpu_for_test() else { return };
        let phrases: Vec<&str> = vec![CANONICAL_PHRASE; 512];

        // 30 warm-up waves so the baseline is taken after the allocator, the
        // Metal driver and the shader cache have all settled.
        for _ in 0..30 {
            gpu.derive(&phrases, crate::seed::PBKDF2_ROUNDS)
                .expect("wave");
        }
        let base = rss_kib();

        // 2047 = 255*8 + 7 → 256 iterate dispatches → 64 command buffers at 4
        // per buffer. 390 waves × (1 prologue + 64 iterate) = 25,350 command
        // buffers, 390 × 257 = 100,230 dispatches.
        let started = std::time::Instant::now();
        for _ in 0..390 {
            gpu.derive(&phrases, crate::seed::PBKDF2_ROUNDS)
                .expect("wave");
        }
        let end = rss_kib();
        eprintln!(
            "100,230 dispatches in {:.1}s: RSS {base} KiB -> {end} KiB (delta {} KiB)",
            started.elapsed().as_secs_f64(),
            end as i64 - base as i64
        );
        assert!(
            end.saturating_sub(base) < 8 * 1024,
            "RSS grew {} KiB over 100,230 dispatches — the per-command-buffer \
             autorelease pool in run_wave is missing or was moved outside the loop",
            end - base
        );
    }
```

- [ ] **Step 2: Run it and watch it pass.**

```sh
cargo test --release -- --ignored --nocapture gpu_no_rss_growth
```

Expected output shape (numbers will differ slightly):

```
100,230 dispatches in 64.8s: RSS 15616 KiB -> 14064 KiB (delta -1552 KiB)
test result: ok. 1 passed
```

**This is the second gate the milestone brief names: do not proceed past this
milestone until RSS is flat.** A positive delta above ~8 MiB means the pool is
wrong — go back to Task 3.4 Step 5 and check that `autoreleasepool` wraps the
body **inside** the `loop`, once per command buffer, and that `prev` is moved
into the closure so its release happens inside the pool too.

- [ ] **Step 3: Prove the guard bites.** Temporarily hoist the pool out of the loop
      in `run_wave` — replace:

```rust
            let prev = ring[slot_ix].take();
            let built = autoreleasepool(|_| -> Result<Cb, GpuError> {
                if let Some(prev) = prev {
                    prev.waitUntilCompleted();
                    self.check_status(&prev)?;
                }
```


> **Two anchors here drifted when Task 3.9 landed, so match on the exact text below, not on
> a remembered shape.** (a) The binding is `let built =`, not `let cb =` — and there is a
> DECOY `let cb = self.queue.commandBuffer()...` about five lines further in, inside the very
> block you are editing. Mutating that one silently measures nothing. (b) The block closes
> with `});`, **not** `})?;`: Task 3.9 replaced the `?` with `let cb = match built { Ok(cb) =>
> cb, Err(e) => { ... drain_ring ... } }`, so there is no `?` left at that site to remove.
> Confirm with `grep -n "let built = autoreleasepool" src/gpu/metal.rs` before you touch it.

with:

```rust
            let prev = ring[slot_ix].take();
            let built = (|| -> Result<Cb, GpuError> {
                if let Some(prev) = prev {
                    prev.waitUntilCompleted();
                    self.check_status(&prev)?;
                }
```

and the closing `});` of that block — the line that closes the `autoreleasepool` call itself, NOT the inner `enc`/`cb` braces — with `})();`, then run:

```sh
cargo test --release -- --ignored --nocapture gpu_no_rss_growth
```

Expected: a delta of roughly `+40,000` KiB and

```
RSS grew 4XXXX KiB over 100,230 dispatches — the per-command-buffer autorelease pool in run_wave is missing or was moved outside the loop
```

- [ ] **Step 4: Revert the mutation** back to `let built = autoreleasepool(|_| … });` and
      re-run to confirm the delta is back under 8 MiB.

```sh
cargo test --release -- --ignored --nocapture gpu_no_rss_growth
```

- [ ] **Step 5: The full milestone gate — run every leg.** Note what is *not*
      here: there is no bare `cargo fmt`. This tree is not rustfmt-clean, so a
      whole-tree reformat would bury the branch's diff under ~20 unrelated files.
      Check only the files this milestone owns.

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy
rustfmt --edition 2021 --check \
  src/gpu/kernel_src.rs src/gpu/mod.rs src/gpu/stub.rs src/gpu/metal.rs src/gpu/selftest.rs \
  && echo NEW-FILES-FMT-CLEAN
cargo clippy --all-targets 2>&1 | grep -c -- '-->'
cargo clippy --all-targets 2>&1 | grep -c -- '--> src/gpu/' || true
cargo clippy --all-targets --no-default-features 2>&1 | grep -c -- '--> src/gpu/' || true
cargo test
cargo test --no-default-features
VANADDY_NO_GPU=1 cargo test
cargo build --release
cargo build --release --no-default-features
```

Expected: `NEW-FILES-FMT-CLEAN`; the first clippy count is `12` — the pre-existing
baseline recorded in Milestone 1 Task 1.8 Step 5, all of it in `src/app.rs`,
`src/ui.rs` and `src/chains/*`, none of it this branch's to fix — and both
`src/gpu/` counts are `0`. **Do not write "zero clippy warnings":** that is
unachievable on this tree and no task in this plan fixes the pre-existing 12.

Also expected, on all legs: every one of the 63 pre-existing tests still passing
**by name** — in particular
`seed::derive_seed_matches_bip39_vector`,
`seed::derive_seeds_matches_derive_seed_per_lane`,
`pbkdf2_lanes::every_lane_matches_bip39_canonical_vector`,
`pbkdf2_lanes::distinct_lanes_match_ring_reference`,
`pbkdf2_lanes::ton_salts_and_iteration_counts_match_ring`,
`slip10::slip10_ed25519_test_vector_1_m_0h`,
`slip10::slip10_ed25519_test_vector_1_m_0h_1h`,
`solana::solana_phantom_derivation_from_canonical_phrase`,
`bitcoin::bip84_canonical_vector`, `evm::eip55_canonical_vector`,
`evm::eip55_second_vector`, `evm::bip44_canonical_vector`, the three
`generate_batch_emits_lane_count_candidates_matching_single_path` tests,
`ton::generate_batch_emits_lane_count_wallets_with_consistent_addresses`,
`ton::ton_tonkeeper_round_trip_vector`,
`ton_cell::wallet_v5r1_matches_tonkeeper_vector`, and
`monero::keccak256_empty_vector`.

Nothing in this milestone touched a derivation path, so a failure in any of those
means something unrelated was edited by accident — find it before continuing.

- [ ] **Step 6: Confirm the GPU-required set actually ran** (not silently skipped):

```sh
cargo test --release gpu:: -- --nocapture 2>&1 | grep -E '^test gpu::|SKIP'
```

Expected: every `gpu::backend::tests::gpu_*` line reads `... ok`, **except**
`gpu_no_rss_growth_over_100k_dispatches`, which reads `... ignored` — Step 1 declares
it `#[ignore]` by design and Step 2 runs it separately with `--ignored`. A run without
`--ignored` prints `ignored` for it, and this grep captures that line.

Do not treat that `ignored` as a gate failure, and do not remove the `#[ignore]` to make
this line read `ok` — the test takes minutes and is deliberately opt-in. If you prefer a
clean all-`ok` read, append `| grep -v gpu_no_rss_growth` to the pipeline.

And **no** `SKIP:` line appears. If you see `SKIP: no Metal device on this machine` on a
machine that has one, stop — the differential did not run.

- [ ] **Step 7: Commit.**

```sh
git add src/gpu/metal.rs
git commit -m "gpu: RSS regression guard for the per-command-buffer autorelease pool

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

**Milestone 3 exit criteria** (all must hold before Milestone 4 starts):

- `gpu_seed_matches_bip39_canonical_vector` passes on real hardware.
- `gpu_no_rss_growth_over_100k_dispatches` shows a delta under 8 MiB.
- `cargo test`, `cargo test --no-default-features`, and `VANADDY_NO_GPU=1 cargo test`
  are all green, and `cargo clippy --all-targets` still emits exactly the 12
  pre-existing diagnostics recorded in Milestone 1 Task 1.8 Step 5 — no more, no
  fewer, and none of them pointing into `src/gpu/`.
- `rustfmt --edition 2021 --check` is silent on the five files this milestone
  owns (`src/gpu/{kernel_src,mod,stub,metal,selftest}.rs`). The rest of the tree
  is left alone.
- `src/gpu/pbkdf2_bip39.metal` hashes to
  `871ef1706bd5ba0a9ddb420872ea6a2db3556bf6951453942678d364b123f4b2`.
- No file outside `Cargo.toml`, `Cargo.lock` and `src/gpu/` was modified **by Milestone 3**:

  ```sh
  git diff --name-only 9ea2906..HEAD
  ```

  Expected: only those paths. `9ea2906` is the commit Milestone 3 started from (Task 2.5's
  final commit), recorded in `.superpowers/sdd/2026-08-26-metal-gpu-pbkdf2/.base-3.1`.

  **Scope this to Milestone 3's own base, never to the branch base.** Measured against the
  branch base (`4854a59`) this criterion is *already false and cannot be made true*:
  Milestones 1 and 2 legitimately created `src/verify.rs` and edited `src/main.rs`,
  `src/app.rs`, `src/chains/mod.rs`, `src/chains/evm.rs`, `src/seed.rs` and
  `src/pbkdf2_lanes.rs`. The literal remedy for a branch-wide reading — reverting those
  files — would destroy two completed milestones.

---

## Milestone 4 — The producer thread (still no TUI)

At the end of Milestone 3 the Metal backend can turn a slice of `KeyBlock`s into a slice of 64-byte seeds, once, when you call it from a test. Nothing calls it in production, nothing runs on its own thread, and nothing hands seeds to the search workers.

This milestone builds the thing that runs forever: a single OS thread named `vanaddy-gpu` that generates 8,192 fresh BIP-39 mnemonics, dispatches them to the GPU, spot-checks four random results against `ring`, carves the wave into sixteen 512-candidate blocks, and pushes them down a bounded channel — then does it again, until told to stop.

Four properties are load-bearing and each gets its own task and its own test:

1. **The stop flag is the producer's own.** Never `App::stop`. If a GPU self-disable set the flag that every Rayon worker reads at `/Users/shawnhopkinson/Rust/Vanaddy/src/chains/mod.rs:107`, one audit mismatch would silently end the entire search — the exact inverse of "the app keeps searching on CPU".
2. **Stopping is non-blocking and bounded.** `signal_stop()` sets a flag and returns; it never joins. The producer observes the flag inside ≈135 ms in steady state, which is why the UI thread can call it from the render loop.
3. **A GPU that lies is caught.** Four *random* indices per wave are re-derived with `ring`. A fixed stride equal to the block size would sample the same `tid` forever and be blind to every tid-dependent kernel bug.
4. **A GPU thread that dies is visible.** `catch_unwind` turns a Rust unwind into `GpuDisableReason::Panicked` in `GpuHealth` instead of a backtrace printed across the Ratatui frame in raw mode, and a `Drop` guard sets `finished` on *every* exit path so the UI can reap without ever blocking.

Everything in `src/gpu/producer.rs` that does not name a Metal type is compiled on **every** target. The fault plumbing, the ring audit, the block carving and the panic guard are therefore unit-tested on Linux and under `cargo build --no-default-features` too; only `producer()` itself is `cfg`-gated. That is deliberate: the three tests this milestone's brief calls out as "inject a fault" tests need no GPU at all, and a fault-detection path that only runs on one machine is a fault-detection path nobody trusts.

Before you start, confirm you are on the right branch:

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && git branch --show-current
```

must print `feat/metal-gpu-pbkdf2`.

**Never run bare `cargo fmt`, and never write "expect no warnings."** The tree is not rustfmt-clean at `beced09` (`cargo fmt --check` reports 84 diffs across 14 files, including `src/app.rs`, `src/ui.rs` and all of `src/chains/*`), and `cargo clippy --all-targets` already emits 12 diagnostics on the clean baseline. A bare `cargo fmt` would bury this branch under an unrelated whole-tree reformat, and a "no warnings" gate is unachievable without fixing pre-existing lints in files this branch has no business touching. Format only the files this milestone creates or edits, by path, and gate clippy on the *delta*:

```sh
rustfmt --edition 2021 src/gpu/producer.rs src/gpu/metal.rs src/gpu/stub.rs src/gpu/mod.rs \
  && cargo clippy --all-targets 2>&1 | grep -- '-->' | sort | uniq -c
```

Expected: exactly the 12 pre-existing lines Milestone 1 Task 1.8 Step 5 recorded (`src/app.rs:51,357,522,543,548`, `src/chains/bitcoin.rs:16`, `src/chains/evm.rs:96,103`, `src/chains/ton_cell.rs:48,54,385`, `src/ui.rs:212`), and **no line pointing into `src/gpu/` or `src/verify.rs`**. The `src/app.rs` and `src/ui.rs` line numbers shift as this branch edits those files; the COUNT of 12 is what must not change. No task on this branch performs a whole-tree reformat; Task 8.5 only gates that the 84-diff baseline is unchanged.

---

### Task 4.1: Producer module skeleton and fault plumbing

Every failure the producer can hit arrives as either a `GpuError` (from the Metal backend) or a `SelfTestError`, and must leave as exactly one `GpuDisableReason`. And the shared `GpuStatus` cell is read by the UI thread on a 100 ms tick, so a worker panicking while holding its lock must not make the status permanently unreadable — hence poison-immune accessors, never `.unwrap()`.

**Files:**
- Create: `/Users/shawnhopkinson/Rust/Vanaddy/src/gpu/producer.rs`
- Modify: `/Users/shawnhopkinson/Rust/Vanaddy/src/gpu/mod.rs` — the module declarations near the bottom (locate with `grep -n "^mod \|^pub mod \|^pub(crate) mod \|cfg_attr" src/gpu/mod.rs`)
- Test: `/Users/shawnhopkinson/Rust/Vanaddy/src/gpu/producer.rs` (in-module `#[cfg(test)] mod tests`)

**Interfaces:**
- Consumes: `pub enum GpuError { NoDevice, ShaderCompile(String), PipelineCreate(String), BufferAlloc, BadConfig(String), SaltTooLong { len: usize }, CommandBuffer { status: i64, message: String } }` (**Task 3.2**, `src/gpu/mod.rs`); `impl From<GpuError> for GpuDisableReason` (**Task 3.2**, `src/gpu/mod.rs`); `pub enum GpuDisableReason` and `pub enum GpuStatus` (Milestone 1, pinned contract)
- Produces: `pub(crate) fn reason_from(e: GpuError) -> GpuDisableReason`; `pub(crate) fn set_status(cell: &Mutex<GpuStatus>, next: GpuStatus)`; `pub(crate) fn read_status(cell: &Mutex<GpuStatus>) -> GpuStatus`

Both consumed items come from **Milestone 3 Task 3.2**, not Milestone 1. Task 1.3
wrote only a one-variant `GpuError` stub and no `From` impl at all; Task 3.2
replaces the enum with the seven-variant shape above and adds
`impl From<GpuError> for GpuDisableReason`. That is why **Milestone 3 must land
before Milestone 4**: Step 5's `reason_from` is a one-line delegate to that `From`
impl and does not compile without it.

- [ ] **Step 1: Declare the module.** Open `/Users/shawnhopkinson/Rust/Vanaddy/src/gpu/mod.rs` and add this line on its own line immediately **after** the `pub mod backend;` declaration — that is where rustfmt's `reorder_modules` puts it anyway; do not place it between the explanatory comment and the `#[cfg_attr(` stack, which rustfmt will undo. It is the `pub` spelling you are looking for, because Task 3.3 Step 6 promoted `mod backend;` to `pub mod backend;`, so a grep for the Milestone 1 spelling will miss it:

```rust
pub mod backend;
pub(crate) mod producer;
```

  (`rustfmt --check` exits 0.) Placing it above the explanatory comment block instead is also clean if that reads better.

  It is declared unconditionally — the GPU-free half of the file must compile and be tested on Linux and under `--no-default-features`.

- [ ] **Step 2: Create the file with its header and an empty test module.** Write `/Users/shawnhopkinson/Rust/Vanaddy/src/gpu/producer.rs`:

```rust
//! The GPU producer thread: fill -> dispatch -> audit -> carve -> send.
//!
//! Everything in this file that does not name a Metal type is compiled on every
//! target, so the fault plumbing, the `ring` audit, the block carving and the
//! panic guard are unit-tested on Linux and under `--no-default-features` too.
//! Only `producer()` itself is `cfg`-gated.

use super::{GpuDisableReason, GpuError, GpuStatus};
use std::sync::Mutex;

#[cfg(test)]
mod tests {
    use super::*;
}
```

- [ ] **Step 3: Write the failing test for the error mapping.** Replace the `mod tests` block in `/Users/shawnhopkinson/Rust/Vanaddy/src/gpu/producer.rs` with:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_gpu_error_maps_to_its_disable_reason() {
        assert_eq!(reason_from(GpuError::NoDevice), GpuDisableReason::NoDevice);
        assert_eq!(
            reason_from(GpuError::ShaderCompile("bad token".into())),
            GpuDisableReason::ShaderCompile("bad token".into())
        );
        assert_eq!(
            reason_from(GpuError::PipelineCreate("no function".into())),
            GpuDisableReason::PipelineCreate("no function".into())
        );
        assert_eq!(
            reason_from(GpuError::BufferAlloc),
            GpuDisableReason::BufferAlloc
        );
        assert_eq!(
            reason_from(GpuError::BadConfig("tg 0".into())),
            GpuDisableReason::BadConfig("tg 0".into())
        );
        assert_eq!(
            reason_from(GpuError::CommandBuffer {
                status: 5,
                message: "IOAF code 3".into()
            }),
            GpuDisableReason::CommandBuffer {
                status: 5,
                message: "IOAF code 3".into()
            }
        );
    }

    #[test]
    fn salt_too_long_becomes_a_bad_config_naming_the_length() {
        match reason_from(GpuError::SaltTooLong { len: 200 }) {
            GpuDisableReason::BadConfig(m) => {
                assert!(
                    m.contains("200"),
                    "message must name the offending length, got {m:?}"
                );
                assert!(m.contains("107"), "message must name the limit, got {m:?}");
            }
            other => panic!("expected BadConfig, got {other:?}"),
        }
    }

    #[test]
    fn status_read_and_write_survive_a_poisoned_lock() {
        let cell = Mutex::new(GpuStatus::Initializing);

        let prev_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _held = cell.lock().unwrap();
            panic!("poison the lock while holding it");
        }));
        std::panic::set_hook(prev_hook);
        assert!(
            cell.is_poisoned(),
            "the setup must actually poison the mutex"
        );

        set_status(
            &cell,
            GpuStatus::Running {
                device: "Apple M1".into(),
            },
        );
        assert_eq!(
            read_status(&cell),
            GpuStatus::Running {
                device: "Apple M1".into()
            },
            "a poisoned status cell must still be readable and writable"
        );
    }
}
```

- [ ] **Step 4: Run the tests and watch them fail to build.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo test every_gpu_error_maps_to_its_disable_reason 2>&1 | head -30
```

  Expect a compile failure, not a test failure:

```
error[E0425]: cannot find function `reason_from` in this scope
  --> src/gpu/producer.rs:...
```

  plus the same for `set_status` and `read_status`, and `error: could not compile `vanaddy` (bin "vanaddy" test) due to N previous errors`.

- [ ] **Step 5: Write the three functions.** In `/Users/shawnhopkinson/Rust/Vanaddy/src/gpu/producer.rs`, insert between the `use` block and `#[cfg(test)] mod tests`:

```rust
/// Funnel every backend failure into the one sticky reason the UI reports.
///
/// This is a ONE-LINE DELEGATE to `impl From<GpuError> for GpuDisableReason`
/// (`src/gpu/mod.rs`, Task 3.2) on purpose: that impl is what `?` already uses,
/// so writing the match again here would give the fault-classification table
/// two copies free to drift. This wrapper exists only so `producer()` can say
/// `.map_err(reason_from)` at call sites where `?` cannot convert, and so the
/// tests below pin the mapping from inside this module.
///
/// Milestone 3 must therefore land before Milestone 4: Task 3.2 is where the
/// `From` impl comes from, and without it this function does not compile.
///
/// `SaltTooLong` has no `GpuDisableReason` twin because it is a programming
/// error in the caller, not a property of the device: it can only fire if a
/// future chain feeds a salt longer than `pbkdf2_lanes::MAX_SALT_LEN` (107, see
/// `src/pbkdf2_lanes.rs:38`), so the `From` impl degrades it to `BadConfig`
/// carrying both the offending length and the limit.
pub(crate) fn reason_from(e: GpuError) -> GpuDisableReason {
    GpuDisableReason::from(e)
}

/// Poison-immune write. The UI thread reads this cell every 100 ms; a worker
/// that panicked while holding the lock must not make the GPU status
/// permanently unreadable, so a poisoned lock is recovered, never unwrapped.
pub(crate) fn set_status(cell: &Mutex<GpuStatus>, next: GpuStatus) {
    match cell.lock() {
        Ok(mut guard) => *guard = next,
        Err(poisoned) => *poisoned.into_inner() = next,
    }
}

/// Poison-immune read. Same reasoning as `set_status`.
pub(crate) fn read_status(cell: &Mutex<GpuStatus>) -> GpuStatus {
    match cell.lock() {
        Ok(guard) => guard.clone(),
        Err(poisoned) => poisoned.into_inner().clone(),
    }
}
```

- [ ] **Step 6: Run the tests and watch them pass.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo test gpu::producer:: 2>&1 | tail -20
```

  Expect `test result: ok. 3 passed; 0 failed`.

- [ ] **Step 7: Commit.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && git add src/gpu/producer.rs src/gpu/mod.rs && git commit -m "gpu: producer module skeleton with poison-immune status and error mapping

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 4.2: The per-wave random `ring` audit

A wrong GPU seed cannot produce a bad CSV row — the `Verified` token from Milestone 2 blocks that. What it *can* do is silently waste the search: the counter climbs while the candidates are noise. This audit is the only detector for that failure, and it is why the indices are drawn at **random**: a fixed stride equal to the block size would sample the same `tid` forever and be blind to every tid-dependent kernel bug.

Cost is four `ring` derivations per 8,192-candidate wave — 4 × 260 µs against a ~600 ms wave, ≈0.05% of one core.

**Files:**
- Modify: `/Users/shawnhopkinson/Rust/Vanaddy/src/gpu/producer.rs` — the `use super::{...}` line, and append two functions before `#[cfg(test)] mod tests`
- Test: `/Users/shawnhopkinson/Rust/Vanaddy/src/gpu/producer.rs` (in-module `tests`)

**Interfaces:**
- Consumes: `pub const AUDITS_PER_WAVE: usize = 4` (Milestone 1); `pub fn crate::seed::derive_seed(mnemonic: &Mnemonic) -> [u8; 64]` (`src/seed.rs:8`); `GpuDisableReason::AuditMismatch { index: usize }`
- Produces: `pub(crate) fn audit_wave(entropy: &[[u8; 16]], seeds: &[[u8; 64]], indices: &[usize]) -> Result<(), GpuDisableReason>`; `pub(crate) fn audit_indices<R: rand::Rng>(rng: &mut R, wave: usize) -> [usize; AUDITS_PER_WAVE]`

- [ ] **Step 1: Widen the import.** In `/Users/shawnhopkinson/Rust/Vanaddy/src/gpu/producer.rs`, replace:

```rust
use super::{GpuDisableReason, GpuError, GpuStatus};
```

  with:

```rust
use super::{GpuDisableReason, GpuError, GpuStatus, AUDITS_PER_WAVE};
```

- [ ] **Step 2: Write the failing tests.** Append inside the `mod tests` block in `/Users/shawnhopkinson/Rust/Vanaddy/src/gpu/producer.rs`:

```rust
    /// Deterministic wave of `n` candidates whose seeds are the CORRECT `ring`
    /// seeds for their entropy, so any mutation the tests make is the only
    /// disagreement present.
    fn honest_wave(n: usize) -> (Vec<[u8; 16]>, Vec<[u8; 64]>) {
        let mut entropy = Vec::with_capacity(n);
        let mut seeds = Vec::with_capacity(n);
        for i in 0..n {
            let mut e = [0u8; 16];
            e[..8].copy_from_slice(&(i as u64).to_be_bytes());
            let m = bip39::Mnemonic::from_entropy(&e, bip39::Language::English)
                .expect("16 bytes is always a valid 12-word entropy");
            seeds.push(crate::seed::derive_seed(&m));
            entropy.push(e);
        }
        (entropy, seeds)
    }

    #[test]
    fn audit_wave_accepts_ring_derived_seeds() {
        let (entropy, seeds) = honest_wave(8);
        assert_eq!(audit_wave(&entropy, &seeds, &[0, 3, 5, 7]), Ok(()));
    }

    #[test]
    fn audit_wave_rejects_one_flipped_seed_bit() {
        let (entropy, mut seeds) = honest_wave(8);
        seeds[3][63] ^= 0x01;
        assert_eq!(
            audit_wave(&entropy, &seeds, &[0, 3, 5, 7]),
            Err(GpuDisableReason::AuditMismatch { index: 3 })
        );
    }

    #[test]
    fn audit_wave_ignores_corruption_at_unsampled_indices() {
        // Honest statement of the detector's limit: it is probabilistic, and a
        // bug confined to a handful of tids can survive a wave. This is the
        // reason the indices are re-drawn every wave rather than fixed.
        let (entropy, mut seeds) = honest_wave(8);
        seeds[6][0] ^= 0xFF;
        assert_eq!(audit_wave(&entropy, &seeds, &[0, 3, 5, 7]), Ok(()));
    }

    #[test]
    fn audit_wave_rejects_an_out_of_range_index() {
        let (entropy, seeds) = honest_wave(8);
        assert_eq!(
            audit_wave(&entropy, &seeds, &[9]),
            Err(GpuDisableReason::AuditMismatch { index: 9 })
        );
    }

    #[test]
    fn audit_indices_are_in_range_and_are_not_a_fixed_stride() {
        let mut rng = rand::thread_rng();
        let mut seen = std::collections::HashSet::new();
        for _ in 0..200 {
            let ix = audit_indices(&mut rng, 8_192);
            assert_eq!(ix.len(), AUDITS_PER_WAVE);
            for i in ix {
                assert!(i < 8_192, "index {i} out of range");
                seen.insert(i);
            }
        }
        // 800 draws from 8192 collapsing to one value has probability
        // 8192^-799; a fixed stride would produce exactly 4 distinct values.
        assert!(
            seen.len() > 4,
            "indices must vary across waves, saw {}",
            seen.len()
        );
    }
```

- [ ] **Step 3: Run the tests and watch them fail to build.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo test audit_wave_rejects_one_flipped_seed_bit 2>&1 | head -20
```

  Expect:

```
error[E0425]: cannot find function `audit_wave` in this scope
```

  and the same for `audit_indices`.

- [ ] **Step 4: Write the audit.** In `/Users/shawnhopkinson/Rust/Vanaddy/src/gpu/producer.rs`, append after `read_status` and before `#[cfg(test)] mod tests`:

```rust
/// Re-derive `indices` of a finished wave with `ring` and compare.
///
/// A wrong GPU seed cannot reach the CSV — the `Verified` token gate stops that
/// — but it can silently waste the search: the counter climbs while up to ~55%
/// of it is noise. This is the only detector for that, so a disagreement is a
/// hard, sticky fault, never a retry.
///
/// `ring` is the reference because `crate::seed::derive_seed` (src/seed.rs:8)
/// is what every pinned vector in CLAUDE.md already pins.
pub(crate) fn audit_wave(
    entropy: &[[u8; 16]],
    seeds: &[[u8; 64]],
    indices: &[usize],
) -> Result<(), GpuDisableReason> {
    for &i in indices {
        if i >= entropy.len() || i >= seeds.len() {
            return Err(GpuDisableReason::AuditMismatch { index: i });
        }
        let m = bip39::Mnemonic::from_entropy(&entropy[i], bip39::Language::English)
            .map_err(|_| GpuDisableReason::AuditMismatch { index: i })?;
        if crate::seed::derive_seed(&m) != seeds[i] {
            return Err(GpuDisableReason::AuditMismatch { index: i });
        }
    }
    Ok(())
}

/// `AUDITS_PER_WAVE` RANDOM indices into a wave of `wave` candidates.
///
/// Random, not a stride: a fixed stride equal to the block size samples the
/// same `tid` on every wave forever and is blind to every tid-dependent kernel
/// bug — exactly the bug class the per-thread indexing (`states + tid`,
/// `seeds + 64*tid`) can produce.
pub(crate) fn audit_indices<R: rand::Rng>(rng: &mut R, wave: usize) -> [usize; AUDITS_PER_WAVE] {
    assert!(wave > 0, "cannot audit an empty wave");
    std::array::from_fn(|_| rng.gen_range(0..wave))
}
```

- [ ] **Step 5: Run the tests and watch them pass.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo test gpu::producer:: 2>&1 | tail -20
```

  Expect `test result: ok. 8 passed; 0 failed`.

- [ ] **Step 6: Commit.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && git add src/gpu/producer.rs && git commit -m "gpu: per-wave random ring audit of GPU seeds

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 4.3: Block carving and the `send_timeout` backpressure loop

This is the single point in the whole design where entropy and seeds are paired. Design invariant 4: *phrase ↔ seed pairing is established by exactly one `zip` and never re-ordered, filtered, or sorted afterwards.* That is why `SeedBlock` gains a build-then-freeze constructor and nothing else — no `remove`, no `sort`, no `retain`, no `iter_mut`.

Backpressure is a retry, not a drop. A wave emits all 8,192 seeds as one burst; 8 workers absorb 8,192 × 50.5 µs = 414 core-ms ≈ 52 ms of wall time against a ~600 ms wave, so the bounded(32) queue drains with enormous margin and the timeout essentially never fires. When it does — Threads = 1 on an E-core, or a stalled worker — the producer self-throttles to exactly the rate the workers can absorb, which is the correct behaviour when the CPU is the binding constraint, and nothing is discarded.

**Files:**
- Read-only: `/Users/shawnhopkinson/Rust/Vanaddy/src/gpu/mod.rs` (`SeedBlock::with_capacity` and `SeedBlock::push` were written by Milestone 1 Task 1.4 Step 4 inside the existing `impl SeedBlock` block; this task only verifies they are present and MUST NOT re-add them — a second copy is `error[E0592]: duplicate definitions with name with_capacity`)
- Modify: `/Users/shawnhopkinson/Rust/Vanaddy/src/gpu/producer.rs` — the `use` block, and append one function before `#[cfg(test)] mod tests`
- Test: `/Users/shawnhopkinson/Rust/Vanaddy/src/gpu/producer.rs` (in-module `tests`)

**Interfaces:**
- Consumes: `pub const BLOCK: usize = 512`, `pub const CHANNEL_CAPACITY: usize = 32`, `pub struct GpuCandidate { pub entropy: [u8; 16], pub seed: [u8; 64] }`, `pub struct SeedBlock(Vec<GpuCandidate>)`, `pub struct GpuHealth` (Milestone 1); `pub(crate) fn SeedBlock::with_capacity(n: usize) -> SeedBlock` and `pub(crate) fn SeedBlock::push(&mut self, candidate: GpuCandidate)` (**Milestone 1 Task 1.4 Step 4** — already inside `impl SeedBlock` in `src/gpu/mod.rs`; consumed here, never re-declared)
- Produces: `pub(crate) fn carve_and_send(tx: &Sender<Box<SeedBlock>>, entropy: &[[u8; 16]], seeds: &[[u8; 64]], stop: &AtomicBool, health: &GpuHealth) -> bool`

`SeedBlock::with_capacity` and `SeedBlock::push` are deliberately NOT listed as
produced here. Task 1.4 Step 4 already wrote both as `pub(crate) fn` inside the
one and only `impl SeedBlock` block, and `src/gpu/producer.rs` is a descendant of
`crate::gpu`, so that visibility is already sufficient and must not be widened.
Re-adding them is `error[E0592]: duplicate definitions with name with_capacity`.

- [ ] **Step 1: Verify Milestone 1 Task 1.4 already made `SeedBlock` fillable.** This is a pure verification step — it edits nothing, and `src/gpu/mod.rs` must leave this task byte-for-byte unchanged.

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && grep -n "pub(crate) fn with_capacity(n: usize) -> Self" src/gpu/mod.rs \
  && grep -n "pub(crate) fn push(&mut self, candidate: GpuCandidate)" src/gpu/mod.rs \
  && echo SEEDBLOCK-CONSTRUCTOR-PRESENT
```

  Expected: one hit from each `grep`, both pointing inside the single `impl SeedBlock { ... }` block, followed by `SEEDBLOCK-CONSTRUCTOR-PRESENT`.

- [ ] **Step 2: If that grep did not print `SEEDBLOCK-CONSTRUCTOR-PRESENT`, stop — do not add the methods here.** The `&&` chain above fails loudly: a missing method means the marker never prints. In that case go back and finish **Milestone 1 Task 1.4 Step 4**, which is the one place both methods are written, and then re-run Step 1.

  Do **not** patch `src/gpu/mod.rs` from this task. Adding a second `impl SeedBlock { ... }` block carrying `with_capacity`/`push` is `error[E0592]: duplicate definitions with name with_capacity` — the same failure Task 2.4 Step 1 already warns about — and adding them a second time inside the existing block is the same error.

  Task 1.4's doc comment on `with_capacity` already carries the invariant this task depends on (build-then-freeze; no `remove`, `sort`, `retain` or `iter_mut`; the entropy<->seed pairing established by the single `zip` in the producer is never re-ordered — design invariant 4). If the wording in the file differs from that summary, leave it alone: the comment is not load-bearing, and rewriting it here would put this task's diff into a file it must not touch.

- [ ] **Step 3: Widen the imports.** In `/Users/shawnhopkinson/Rust/Vanaddy/src/gpu/producer.rs`, replace:

```rust
use super::{GpuDisableReason, GpuError, GpuStatus, AUDITS_PER_WAVE};
use std::sync::Mutex;
```

  with:

```rust
use super::{
    GpuCandidate, GpuDisableReason, GpuError, GpuHealth, GpuStatus, SeedBlock, AUDITS_PER_WAVE,
    BLOCK,
};
use crossbeam_channel::{SendTimeoutError, Sender};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::Duration;
```

- [ ] **Step 4: Write the failing tests.** Append inside the `mod tests` block in `/Users/shawnhopkinson/Rust/Vanaddy/src/gpu/producer.rs`:

```rust
    /// A fresh, clean health cell. `GpuHealth`'s `reason` field is private to
    /// `crate::gpu`, and this module is a descendant of it, so the literal is
    /// legal here and needs no constructor on the type itself.
    fn fresh_health() -> GpuHealth {
        GpuHealth {
            disable: std::sync::atomic::AtomicBool::new(false),
            reason: std::sync::OnceLock::new(),
            seeds_delivered: std::sync::atomic::AtomicU64::new(0),
            blocks_dropped: std::sync::atomic::AtomicU64::new(0),
            verify_rejections: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// `n` candidates whose entropy and seed both encode their index, so a
    /// re-ordering or a mis-pairing anywhere in the carve is detectable.
    fn marked_wave(n: usize) -> (Vec<[u8; 16]>, Vec<[u8; 64]>) {
        let mut entropy = vec![[0u8; 16]; n];
        let mut seeds = vec![[0u8; 64]; n];
        for i in 0..n {
            entropy[i][..8].copy_from_slice(&(i as u64).to_be_bytes());
            seeds[i][..8].copy_from_slice(&(i as u64).to_be_bytes());
            seeds[i][56..].copy_from_slice(&(i as u64).to_be_bytes());
        }
        (entropy, seeds)
    }

    #[test]
    fn carve_and_send_delivers_sixteen_blocks_of_512_in_pairing_order() {
        let (tx, rx) = crossbeam_channel::bounded(super::super::CHANNEL_CAPACITY);
        let stop = AtomicBool::new(false);
        let health = fresh_health();
        let (entropy, seeds) = marked_wave(8_192);

        assert!(carve_and_send(&tx, &entropy, &seeds, &stop, &health));

        for c in 0..16 {
            let block = rx
                .try_recv()
                .unwrap_or_else(|e| panic!("block {c} missing: {e}"));
            assert_eq!(block.len(), BLOCK, "block {c} is not {BLOCK} candidates");
            let cands = block.chunks(BLOCK).next().expect("one full chunk");
            for (j, cand) in cands.iter().enumerate() {
                let want = (c * BLOCK + j) as u64;
                assert_eq!(
                    u64::from_be_bytes(cand.entropy[..8].try_into().unwrap()),
                    want,
                    "block {c} slot {j}: entropy out of order"
                );
                assert_eq!(
                    u64::from_be_bytes(cand.seed[..8].try_into().unwrap()),
                    want,
                    "block {c} slot {j}: seed paired with the wrong entropy"
                );
            }
        }
        assert!(rx.try_recv().is_err(), "exactly 16 blocks, no more");
    }

    #[test]
    fn carve_and_send_reports_false_when_the_receiver_hung_up() {
        let (tx, rx) = crossbeam_channel::bounded::<Box<SeedBlock>>(super::super::CHANNEL_CAPACITY);
        drop(rx);
        let stop = AtomicBool::new(false);
        let health = fresh_health();
        let (entropy, seeds) = marked_wave(8_192);

        let started = std::time::Instant::now();
        assert!(!carve_and_send(&tx, &entropy, &seeds, &stop, &health));
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "Disconnected must be immediate, took {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn carve_and_send_retries_under_backpressure_and_exits_on_stop() {
        // Capacity 2 and nobody draining: the third block hits the 100 ms
        // timeout branch and must be RETRIED, never dropped.
        let (tx, _rx) = crossbeam_channel::bounded(2);
        let stop = AtomicBool::new(false);
        let health = fresh_health();
        let (entropy, seeds) = marked_wave(8_192);

        let started = std::time::Instant::now();
        let finished = std::thread::scope(|s| {
            s.spawn(|| {
                std::thread::sleep(Duration::from_millis(300));
                stop.store(true, Ordering::Relaxed);
            });
            carve_and_send(&tx, &entropy, &seeds, &stop, &health)
        });

        assert!(!finished, "must report stop");
        assert!(
            started.elapsed() >= Duration::from_millis(300),
            "must have blocked, not dropped"
        );
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "must notice stop within one timeout, took {:?}",
            started.elapsed()
        );
        assert_eq!(
            health.blocks_dropped.load(Ordering::Relaxed),
            0,
            "backpressure throttles, it never discards"
        );
    }

    #[test]
    fn carve_and_send_exits_immediately_when_health_is_already_disabled() {
        let (tx, rx) = crossbeam_channel::bounded(super::super::CHANNEL_CAPACITY);
        let stop = AtomicBool::new(false);
        let health = fresh_health();
        health.raise(GpuDisableReason::AuditMismatch { index: 5_183 });
        let (entropy, seeds) = marked_wave(8_192);

        let started = std::time::Instant::now();
        assert!(!carve_and_send(&tx, &entropy, &seeds, &stop, &health));
        assert!(
            rx.try_recv().is_err(),
            "a disabled GPU must deliver nothing"
        );
        assert!(started.elapsed() < std::time::Duration::from_millis(500));
    }
```

- [ ] **Step 5: Run the tests and watch them fail to build.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo test carve_and_send 2>&1 | head -20
```

  Expect:

```
error[E0425]: cannot find function `carve_and_send` in this scope
```

- [ ] **Step 6: Write the carve-and-send loop.** In `/Users/shawnhopkinson/Rust/Vanaddy/src/gpu/producer.rs`, append after `audit_indices` and before `#[cfg(test)] mod tests`:

```rust
/// Carve a finished wave into `seeds.len() / BLOCK` blocks and hand them to the
/// workers. Returns `false` when the wave loop must stop: the producer's stop
/// flag, a self-disable, or the receiver side hanging up.
///
/// The `zip` below is the ONE place entropy and seeds meet. Nothing downstream
/// may reorder, filter or sort — see `SeedBlock::with_capacity`.
///
/// Backpressure is a 100 ms `send_timeout` RETRY, never a drop. A full queue
/// means the CPU workers are the binding constraint, and self-throttling to
/// exactly the rate they can absorb is the correct response; `blocks_dropped`
/// therefore stays 0 by construction. `send` is never called bare and never
/// unwrapped: a `Disconnected` is a clean exit, not a panic on a background
/// thread writing a backtrace across the Ratatui frame.
pub(crate) fn carve_and_send(
    tx: &Sender<Box<SeedBlock>>,
    entropy: &[[u8; 16]],
    seeds: &[[u8; 64]],
    stop: &AtomicBool,
    health: &GpuHealth,
) -> bool {
    debug_assert_eq!(entropy.len(), seeds.len());
    for (e_chunk, s_chunk) in entropy.chunks_exact(BLOCK).zip(seeds.chunks_exact(BLOCK)) {
        let mut block = Box::new(SeedBlock::with_capacity(BLOCK));
        for (e, s) in e_chunk.iter().zip(s_chunk.iter()) {
            block.push(GpuCandidate {
                entropy: *e,
                seed: *s,
            });
        }
        let mut pending = Some(block);
        while let Some(b) = pending.take() {
            if stop.load(Ordering::Relaxed) || health.disable.load(Ordering::Relaxed) {
                drop(b);
                return false;
            }
            match tx.send_timeout(b, Duration::from_millis(100)) {
                Ok(()) => {}
                Err(SendTimeoutError::Timeout(b)) => pending = Some(b),
                Err(SendTimeoutError::Disconnected(b)) => {
                    drop(b);
                    return false;
                }
            }
        }
    }
    true
}
```

- [ ] **Step 7: Run the tests and watch them pass.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo test gpu::producer:: 2>&1 | tail -20
```

  Expect `test result: ok. 12 passed; 0 failed`. The backpressure test takes ~0.3 s.

- [ ] **Step 8: Commit.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && git add src/gpu/producer.rs src/gpu/mod.rs && git commit -m "gpu: carve waves into 16x512 blocks with send_timeout backpressure

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 4.4: `USER_INITIATED` QoS for the producer thread

macOS will demote a plain background thread to an E-core. The producer's ~4.1 ms of per-wave `Mnemonic::new` + packing stretches proportionally there, and the GPU then sits idle waiting for its next wave of keys. One `pthread` call fixes it; getting the constant wrong silently does nothing, so the test reads the class back.

`QOS_CLASS_USER_INITIATED = 0x19` and `int pthread_set_qos_class_self_np(qos_class_t, int)` are verified against `$(xcrun --show-sdk-path)/usr/include/sys/qos.h:133` and `.../usr/include/pthread/qos.h:155` on this machine.

**Files:**
- Modify: `/Users/shawnhopkinson/Rust/Vanaddy/src/gpu/producer.rs` — append one `cfg`-split function before `#[cfg(test)] mod tests`
- Test: `/Users/shawnhopkinson/Rust/Vanaddy/src/gpu/producer.rs` (in-module `tests`)

**Interfaces:**
- Consumes: nothing
- Produces: `pub(crate) fn set_thread_qos_user_initiated() -> i32` (0 on success, otherwise an errno; a no-op returning 0 off macOS)

- [ ] **Step 1: Write the failing test.** Append inside the `mod tests` block in `/Users/shawnhopkinson/Rust/Vanaddy/src/gpu/producer.rs`:

```rust
    #[cfg(target_os = "macos")]
    #[test]
    fn qos_call_promotes_the_calling_thread_to_user_initiated() {
        // On a fresh thread so the harness thread's QoS is not mutated under
        // the other tests running in parallel.
        let class = std::thread::spawn(|| {
            assert_eq!(
                set_thread_qos_user_initiated(),
                0,
                "pthread_set_qos_class_self_np returned a non-zero errno"
            );
            extern "C" {
                fn pthread_self() -> *mut core::ffi::c_void;
                fn pthread_get_qos_class_np(
                    thread: *mut core::ffi::c_void,
                    qos_class: *mut u32,
                    relative_priority: *mut i32,
                ) -> i32;
            }
            let mut class: u32 = 0;
            let mut rel: i32 = 0;
            // SAFETY: both pointers are valid, non-null, and correctly typed
            // (`qos_class_t` is an `unsigned int` enum, `pthread_t` a pointer).
            let rc = unsafe { pthread_get_qos_class_np(pthread_self(), &mut class, &mut rel) };
            assert_eq!(rc, 0, "pthread_get_qos_class_np returned {rc}");
            class
        })
        .join()
        .expect("probe thread panicked");

        assert_eq!(class, 0x19, "expected QOS_CLASS_USER_INITIATED (0x19), got {class:#x}");
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn qos_call_is_an_infallible_no_op_off_macos() {
        assert_eq!(set_thread_qos_user_initiated(), 0);
    }
```

- [ ] **Step 2: Run the test and watch it fail to build.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo test qos_call_promotes 2>&1 | head -20
```

  Expect:

```
error[E0425]: cannot find function `set_thread_qos_user_initiated` in this scope
```

- [ ] **Step 3: Write the QoS helper.** In `/Users/shawnhopkinson/Rust/Vanaddy/src/gpu/producer.rs`, append after `carve_and_send` and before `#[cfg(test)] mod tests`:

```rust
/// Raise the calling thread to `QOS_CLASS_USER_INITIATED`.
///
/// Without this macOS may schedule the producer on an E-core, where the ~4.1 ms
/// of per-wave phrase generation and packing stretches proportionally and the
/// GPU starves waiting for its next wave of keys. Returns 0 on success, else an
/// errno — the caller ignores it, because a demoted producer is slow, not wrong.
///
/// `QOS_CLASS_USER_INITIATED = 0x19` and the signature
/// `int pthread_set_qos_class_self_np(qos_class_t, int)` are from
/// `<sys/qos.h>` and `<pthread/qos.h>`; `qos_class_t` is an `unsigned int` enum.
#[cfg(target_os = "macos")]
pub(crate) fn set_thread_qos_user_initiated() -> i32 {
    const QOS_CLASS_USER_INITIATED: u32 = 0x19;
    extern "C" {
        fn pthread_set_qos_class_self_np(qos_class: u32, relative_priority: i32) -> i32;
    }
    // SAFETY: a libSystem call taking two scalars, valid on any thread, with no
    // pointer arguments and no ownership transfer.
    unsafe { pthread_set_qos_class_self_np(QOS_CLASS_USER_INITIATED, 0) }
}

/// No QoS classes off macOS; the producer runs at the default priority.
#[cfg(not(target_os = "macos"))]
pub(crate) fn set_thread_qos_user_initiated() -> i32 {
    0
}
```

- [ ] **Step 4: Run the test and watch it pass.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo test qos_call 2>&1 | tail -10
```

  Expect `test result: ok. 1 passed; 0 failed`.

- [ ] **Step 5: Commit.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && git add src/gpu/producer.rs && git commit -m "gpu: pin the producer thread to QOS_CLASS_USER_INITIATED

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 4.5: The panic guard and the `finished` flag

The GPU thread runs detached from the UI thread's control: `stop_search` must never join it (a wedged `waitUntilCompleted` would hang the render loop forever with the terminal in raw mode and only `kill -9` as an exit). So the UI reaps by *polling* `is_finished()`, and `finished` must therefore be set on **every** exit path — clean return, `?` bail, or unwind. That is a `Drop` guard, not a store at the end of the function.

`catch_unwind` catches Rust unwinds only. An Objective-C exception is uncatchable and aborts the process inside raw mode — which is precisely why the backend never calls `setMathMode` and clamps the threadgroup size to `maxTotalThreadsPerThreadgroup`.

The ordering is load-bearing: `health.raise` happens *before* the guard's store, and the store is `Release` against an `Acquire` load, so a UI thread that sees `is_finished()` is guaranteed to also see the fault. Milestone 6's `drain_matches` treats "engine finished while `state == Searching` and `health.disable` is false" as an unexpected exit; get this order wrong and every clean shutdown looks like a crash.

**This task's second test is the milestone's "inject an audit mismatch and assert `GpuHealth::disable` with the right reason" check.** Task 4.2 proved a corrupted seed produces `AuditMismatch { index }`; this proves that reason reaches `GpuHealth` and disables the GPU. Neither half needs a GPU.

**Files:**
- Modify: `/Users/shawnhopkinson/Rust/Vanaddy/src/gpu/producer.rs` — the `use` block, and append a struct + function before `#[cfg(test)] mod tests`
- Test: `/Users/shawnhopkinson/Rust/Vanaddy/src/gpu/producer.rs` (in-module `tests`)

**Interfaces:**
- Consumes: `pub fn GpuHealth::raise(&self, r: GpuDisableReason)`, `pub fn GpuHealth::take_reason(&self) -> Option<GpuDisableReason>` (Milestone 1)
- Produces: `pub(crate) fn run_guarded<F>(health: &GpuHealth, finished: Arc<AtomicBool>, body: F) where F: FnOnce() -> Result<(), GpuDisableReason>`

- [ ] **Step 1: Widen the imports.** In `/Users/shawnhopkinson/Rust/Vanaddy/src/gpu/producer.rs`, replace:

```rust
use std::sync::Mutex;
```

  with:

```rust
use std::sync::{Arc, Mutex};
```

- [ ] **Step 2: Write the failing tests.** Append inside the `mod tests` block in `/Users/shawnhopkinson/Rust/Vanaddy/src/gpu/producer.rs`:

```rust
    #[test]
    fn a_clean_body_finishes_without_disabling_the_gpu() {
        let health = fresh_health();
        let finished = Arc::new(AtomicBool::new(false));
        run_guarded(&health, finished.clone(), || Ok(()));

        assert!(
            finished.load(Ordering::Acquire),
            "finished must be set on a clean return"
        );
        assert!(!health.disable.load(Ordering::Relaxed));
        assert_eq!(health.take_reason(), None);
    }

    #[test]
    fn an_injected_audit_mismatch_disables_the_gpu_with_that_reason() {
        let health = fresh_health();
        let finished = Arc::new(AtomicBool::new(false));
        run_guarded(&health, finished.clone(), || {
            Err(GpuDisableReason::AuditMismatch { index: 5_183 })
        });

        assert!(
            health.disable.load(Ordering::Relaxed),
            "a fault must disable the GPU"
        );
        assert_eq!(
            health.take_reason(),
            Some(GpuDisableReason::AuditMismatch { index: 5_183 }),
            "the exact reason must survive to the UI"
        );
        assert!(
            finished.load(Ordering::Acquire),
            "finished must be set on a fault return"
        );
    }

    #[test]
    fn a_panicking_body_becomes_panicked_and_still_finishes() {
        let health = fresh_health();
        let finished = Arc::new(AtomicBool::new(false));

        let prev_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        run_guarded(&health, finished.clone(), || {
            panic!("simulated kernel-side unwrap")
        });
        std::panic::set_hook(prev_hook);

        assert!(health.disable.load(Ordering::Relaxed));
        assert_eq!(health.take_reason(), Some(GpuDisableReason::Panicked));
        assert!(
            finished.load(Ordering::Acquire),
            "finished must be set even when the body unwinds, or the UI can never reap"
        );
    }

    #[test]
    fn the_fault_is_visible_to_anyone_who_sees_finished() {
        // The ordering Milestone 6's drain_matches depends on: seeing
        // `finished` implies seeing `disable`, so a fault never looks like an
        // unexplained quiet death. This test polls `finished` directly rather
        // than `.join()`-ing first: `join()` is itself a full synchronisation
        // edge, so it would pass even if `FinishGuard::drop` used `Relaxed` or
        // the store ran before `health.raise` -- moving the store above the
        // `match` in `run_guarded` must turn this test red.
        let health = Arc::new(fresh_health());
        let finished = Arc::new(AtomicBool::new(false));
        let h = health.clone();
        let f = finished.clone();
        let handle = std::thread::spawn(move || {
            run_guarded(&h, f, || Err(GpuDisableReason::BufferAlloc));
        });

        while !finished.load(Ordering::Acquire) {
            std::hint::spin_loop();
        }
        assert!(health.disable.load(Ordering::Relaxed));
        assert_eq!(health.take_reason(), Some(GpuDisableReason::BufferAlloc));
        handle
            .join()
            .expect("guarded thread must not propagate a panic");
    }
```

- [ ] **Step 3: Run the tests and watch them fail to build.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo test an_injected_audit_mismatch 2>&1 | head -20
```

  Expect:

```
error[E0425]: cannot find function `run_guarded` in this scope
```

- [ ] **Step 4: Write the guard.** In `/Users/shawnhopkinson/Rust/Vanaddy/src/gpu/producer.rs`, append after `set_thread_qos_user_initiated` and before `#[cfg(test)] mod tests`:

```rust
/// Sets `finished` on every exit path — clean return, `?` bail, or unwind.
///
/// `stop_search` must never join the GPU thread (a wedged `waitUntilCompleted`
/// would hang the UI thread forever with the terminal in raw mode), so the app
/// reaps by polling `is_finished()`. A flag set only at the end of a function
/// would strand a panicked engine as un-reapable forever.
struct FinishGuard(Arc<AtomicBool>);

impl Drop for FinishGuard {
    fn drop(&mut self) {
        // Release: pairs with the Acquire in `GpuEngine::is_finished`, so a UI
        // thread that observes `finished` is guaranteed to observe the fault
        // `run_guarded` raised into `health` just before this store.
        self.0.store(true, Ordering::Release);
    }
}

/// The GPU thread body wrapper.
///
/// A Rust unwind becomes `GpuDisableReason::Panicked` in `health` rather than a
/// backtrace printed across the Ratatui frame in raw mode. `catch_unwind`
/// catches Rust unwinds ONLY — an Objective-C exception is uncatchable and
/// aborts the process, which is exactly why the backend never calls
/// `setMathMode` and clamps the threadgroup size to the pipeline's own
/// `maxTotalThreadsPerThreadgroup`.
///
/// `AssertUnwindSafe` is correct here rather than lazy: nothing the body
/// touches is read again after it unwinds. `health` is atomics plus a set-once
/// `OnceLock`, the channel `Sender` is dropped with the body, and the Metal
/// objects are created inside the body and die with it.
pub(crate) fn run_guarded<F>(health: &GpuHealth, finished: Arc<AtomicBool>, body: F)
where
    F: FnOnce() -> Result<(), GpuDisableReason>,
{
    let _guard = FinishGuard(finished);
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(body)) {
        Ok(Ok(())) => {}
        Ok(Err(reason)) => health.raise(reason),
        Err(_) => health.raise(GpuDisableReason::Panicked),
    }
    // `_guard` drops HERE, after `raise`. Do not reorder.
}
```

- [ ] **Step 5: Run the tests and watch them pass.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo test gpu::producer:: 2>&1 | tail -20
```

  Expect `test result: ok. 17 passed; 0 failed`.

- [ ] **Step 6: Commit.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && git add src/gpu/producer.rs && git commit -m "gpu: catch_unwind + Drop guard so a dead GPU thread is visible and reapable

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 4.6: The wave loop

Now assemble the parts into the loop that runs forever: fill → dispatch → audit → carve → send. This is the only `cfg`-gated function in the file.

The fill is deliberately single-threaded. Measured: `Mnemonic::new` 0.527 µs and packing 0.495 µs, so 8,192 candidates cost ~4.1 ms against a ~600 ms wave — 0.7% of one core. A Rayon `par_iter` here would put those allocations on the very threads whose PBKDF2 *is* the CPU-side throughput.

The entropy source is `bip39::Mnemonic::new(MnemonicType::Words12, Language::English)` — the identical call the CPU path already makes at `/Users/shawnhopkinson/Rust/Vanaddy/src/chains/evm.rs:59` and `:67`. It draws from `rand::thread_rng()` (a thread-local ChaCha12 CSPRNG, OS-seeded and auto-reseeded), so the producer gets its own independently seeded instance. **Anything counter-derived would break the uniform-independent-draw assumption behind `App::expected_attempts()` and be a total key-recovery break.**

**Files:**
- Modify: `/Users/shawnhopkinson/Rust/Vanaddy/src/gpu/producer.rs` — append one `cfg`-gated function before `#[cfg(test)] mod tests`
- Test: `/Users/shawnhopkinson/Rust/Vanaddy/src/gpu/producer.rs` (new `#[cfg(all(test, ...))] mod gpu_tests`)

**Interfaces:**
- Consumes: `pub struct MetalPbkdf2` (Milestone 3, `src/gpu/metal.rs`, reached as `super::backend::MetalPbkdf2`) with `pub fn new() -> Result<MetalPbkdf2, GpuError>`, `pub fn run_wave(&mut self, keys: &[KeyBlock], salt_block: &[u64; 16], total_iters: u32, schedule: Schedule, stop: &AtomicBool) -> Result<Option<&[[u8; 64]]>, GpuError>`, `pub fn derive_with_schedule(&mut self, phrases: &[&str], iters: u32, schedule: Schedule) -> Result<Vec<Zeroizing<[u8; 64]>>, GpuError>`, `pub fn device_name(&self) -> String`; `pub fn selftest::self_test<F>(stop: &AtomicBool, derive: F) -> Result<(), SelfTestError> where F: FnMut(&[&str], u32, Schedule) -> Result<Vec<Zeroizing<[u8; 64]>>, GpuError>` (Milestone 3, Task 3.10); `pub enum crate::gpu::Schedule` (Milestone 3, Task 3.6); `pub fn pack::pack_key_block(password: &[u8]) -> KeyBlock`, `pub fn pack::pack_salt_block(salt: &[u8]) -> Result<[u64; 16], GpuError>` (Milestone 1); `pub const crate::seed::PBKDF2_ROUNDS: u32`, `pub const crate::seed::BIP39_SALT: &[u8; 8]` (Milestone 1)
- Produces: `pub(crate) fn producer(tx: Sender<Box<SeedBlock>>, stop: &AtomicBool, health: &GpuHealth, status: &Mutex<GpuStatus>) -> Result<(), GpuDisableReason>` (gated to `all(target_os = "macos", target_arch = "aarch64", feature = "metal")`)

- [ ] **Step 1: Write the failing GPU test.** Append at the very end of `/Users/shawnhopkinson/Rust/Vanaddy/src/gpu/producer.rs`, *outside* the existing `mod tests`:

```rust
#[cfg(all(test, target_os = "macos", target_arch = "aarch64", feature = "metal"))]
mod gpu_tests {
    use super::tests::fresh_health;
    use super::*;
    use crate::gpu::{BLOCK, CHANNEL_CAPACITY, WAVE};
    use rayon::prelude::*;
    use std::time::{Duration, Instant};

    /// Consume three full waves and re-derive EVERY seed with `ring`.
    ///
    /// 3 x 8192 = 24,576 candidates. Run with --release: in a debug build the
    /// per-wave fill is slow enough to starve the GPU and the test drags.
    #[test]
    fn producer_delivers_three_waves_whose_every_seed_matches_ring() {
        if std::env::var_os("VANADDY_NO_GPU").is_some() {
            eprintln!("SKIP: VANADDY_NO_GPU is set");
            return;
        }
        let (tx, rx) = crossbeam_channel::bounded(CHANNEL_CAPACITY);
        let stop = AtomicBool::new(false);
        let health = fresh_health();
        let status = Mutex::new(GpuStatus::Initializing);

        let want = 3 * (WAVE / BLOCK);
        let mut blocks: Vec<Box<SeedBlock>> = Vec::with_capacity(want);

        let no_device = std::thread::scope(|s| {
            let worker = s.spawn(|| producer(tx, &stop, &health, &status));
            let deadline = Instant::now() + Duration::from_secs(180);
            while blocks.len() < want && !worker.is_finished() {
                assert!(
                    Instant::now() < deadline,
                    "only {} of {want} blocks in 180 s (status {:?}, reason {:?})",
                    blocks.len(),
                    read_status(&status),
                    health.take_reason()
                );
                if let Ok(b) = rx.recv_timeout(Duration::from_millis(250)) {
                    blocks.push(b);
                }
            }
            stop.store(true, Ordering::Relaxed);
            let outcome = worker.join().expect("producer must not panic");
            if outcome == Err(GpuDisableReason::NoDevice) {
                return true;
            }
            assert_eq!(outcome, Ok(()), "producer returned a fault");
            false
        });
        if no_device {
            eprintln!("SKIP: no Metal device on this machine");
            return;
        }

        assert!(
            matches!(read_status(&status), GpuStatus::Running { .. }),
            "the producer must publish Running once the self-test passes, saw {:?}",
            read_status(&status)
        );
        assert_eq!(health.take_reason(), None, "no fault may have been raised");

        let failures: Vec<String> = blocks
            .par_iter()
            .enumerate()
            .flat_map(|(bi, b)| {
                let cands = b.chunks(BLOCK).next().expect("one full chunk");
                cands
                    .iter()
                    .enumerate()
                    .filter_map(|(ci, c)| {
                        let m = match bip39::Mnemonic::from_entropy(
                            &c.entropy,
                            bip39::Language::English,
                        ) {
                            Ok(m) => m,
                            Err(e) => return Some(format!("block {bi} cand {ci}: bad entropy: {e}")),
                        };
                        let want = crate::seed::derive_seed(&m);
                        if want != c.seed {
                            return Some(format!(
                                "block {bi} cand {ci}: phrase {:?}\n  gpu  {}\n  ring {}",
                                m.phrase(),
                                hex::encode(c.seed),
                                hex::encode(want)
                            ));
                        }
                        None
                    })
                    .collect::<Vec<_>>()
            })
            .collect();

        assert!(
            failures.is_empty(),
            "{} of {} GPU seeds disagree with ring:\n{}",
            failures.len(),
            3 * WAVE,
            failures.join("\n")
        );
        for (bi, b) in blocks.iter().enumerate() {
            assert_eq!(b.len(), BLOCK, "block {bi} is not {BLOCK} candidates");
        }
    }
}
```

- [ ] **Step 2: Make the test helper reachable.** `gpu_tests` imports `fresh_health` from the sibling `tests` module, so `mod tests` must be visible to it. In `/Users/shawnhopkinson/Rust/Vanaddy/src/gpu/producer.rs`, change:

```rust
#[cfg(test)]
mod tests {
```

  to:

```rust
#[cfg(test)]
pub(crate) mod tests {
```

  and change `fn fresh_health() -> GpuHealth {` inside it to `pub(crate) fn fresh_health() -> GpuHealth {`.

- [ ] **Step 3: Run the test and watch it fail to build.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo test --release producer_delivers_three_waves 2>&1 | head -20
```

  Expect:

```
error[E0425]: cannot find function `producer` in this scope
```

- [ ] **Step 4: Write the wave loop.** In `/Users/shawnhopkinson/Rust/Vanaddy/src/gpu/producer.rs`, insert after `run_guarded` and before `#[cfg(test)] pub(crate) mod tests`:

```rust
/// The wave loop. Runs on the `vanaddy-gpu` thread and owns every Metal object
/// in the process — nothing Metal-shaped ever crosses a thread boundary, which
/// `objc2`'s `Send`/`Sync` bounds enforce at compile time.
///
/// `tx` is taken BY VALUE: dropping it on return hangs up the channel, which is
/// the second, independent wake path for the workers alongside the stop flag.
#[cfg(all(target_os = "macos", target_arch = "aarch64", feature = "metal"))]
pub(crate) fn producer(
    tx: Sender<Box<SeedBlock>>,
    stop: &AtomicBool,
    health: &GpuHealth,
    status: &Mutex<GpuStatus>,
) -> Result<(), GpuDisableReason> {
    use super::backend::MetalPbkdf2;
    use super::pack::{pack_key_block, pack_salt_block, KeyBlock};
    use super::{selftest, Schedule, WAVE};
    use bip39::{Language, Mnemonic, MnemonicType};
    use zeroize::Zeroizing;

    // QoS so macOS does not demote this thread to an E-core, where the ~4.1 ms
    // of per-wave phrase generation and packing stretches proportionally and
    // the GPU starves waiting for keys. Slow, not wrong — so the result is
    // deliberately ignored.
    let _ = set_thread_qos_user_initiated();

    // Device, library compile (~60-95 ms cold) and pipelines, all HERE, on this
    // thread, never the UI thread.
    let mut engine = MetalPbkdf2::new().map_err(reason_from)?;
    if stop.load(Ordering::Relaxed) {
        return Ok(());
    }

    // ~300 ms: 154 ms of GPU plus 133 ms of `ring`. Nothing is published to the
    // workers until it passes.
    //
    // `stop` is threaded IN, not just checked around the call: the spec's
    // termination table requires the flag to be observed between the
    // self-test's phases, and a `signal_stop()` during startup must not go
    // unseen for the whole ~300 ms. The schedule is threaded THROUGH, not
    // dropped: `self_test`'s chunk-schedule invariance check — the property the
    // entire resumable-wave design rests on — passes vacuously if every call it
    // makes runs the production schedule.
    selftest::self_test(stop, |phrases, iters, schedule| {
        engine.derive_with_schedule(phrases, iters, schedule)
    })
    .map_err(GpuDisableReason::SelfTest)?;
    if stop.load(Ordering::Relaxed) {
        return Ok(());
    }
    set_status(status, GpuStatus::Running { device: engine.device_name() });

    let salt = pack_salt_block(crate::seed::BIP39_SALT).map_err(reason_from)?;

    // 8192 x 16 B of raw entropy - the most valuable object in the process.
    // Zeroizing, and overwritten in place every wave, so the resident backlog
    // is one wave (~600 ms) rather than the whole run.
    let mut entropy: Zeroizing<Vec<[u8; 16]>> = Zeroizing::new(vec![[0u8; 16]; WAVE]);
    let mut keys: Zeroizing<Vec<KeyBlock>> = Zeroizing::new(vec![KeyBlock([0u64; 16]); WAVE]);
    let mut rng = rand::thread_rng();

    while !stop.load(Ordering::Relaxed) && !health.disable.load(Ordering::Relaxed) {
        // 1. Fill. Measured: Mnemonic::new 0.527 us + pack 0.495 us -> ~4.1 ms
        //    per ~600 ms wave = 0.7% of one core. ONE thread is ample; NO Rayon
        //    par_iter, which would put these allocations on the very threads
        //    whose PBKDF2 is the CPU-side throughput.
        //    `Mnemonic::new` is the SAME entropy source the CPU path uses at
        //    src/chains/evm.rs:59 — thread-local, OS-seeded ChaCha12. Nothing
        //    counter-derived may ever appear here.
        for (i, (e, k)) in entropy.iter_mut().zip(keys.iter_mut()).enumerate() {
            if i % 512 == 0 && stop.load(Ordering::Relaxed) {
                return Ok(());
            }
            let m = Mnemonic::new(MnemonicType::Words12, Language::English);
            e.copy_from_slice(m.entropy());
            *k = pack_key_block(m.phrase().as_bytes());
        }

        // 2-3. Dispatch the wave. `Ok(None)` means the backend saw `stop` at a
        //      command-buffer boundary and abandoned it; there is deliberately
        //      no partial-success shape, because a partly-iterated wave yields
        //      wrong-but-plausible seeds.
        let seeds = match engine
            .run_wave(
                &keys,
                &salt,
                crate::seed::PBKDF2_ROUNDS,
                Schedule::Production,
                stop,
            )
            .map_err(reason_from)?
        {
            Some(seeds) => seeds,
            None => return Ok(()),
        };

        // 4. Audit AUDITS_PER_WAVE RANDOM indices against `ring`.
        audit_wave(&entropy, seeds, &audit_indices(&mut rng, WAVE))?;

        // 5. Carve + send. `false` == stop, self-disable, or hang-up.
        if !carve_and_send(&tx, &entropy, seeds, stop, health) {
            return Ok(());
        }

        // 6. The backend wipes keys/states/seeds; `entropy` and `keys` are
        //    overwritten by the next fill and zeroized on drop, so the last
        //    wave's plaintext dies with this function.
    }
    Ok(())
}
```

- [ ] **Step 5: Run the test and watch it pass.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo test --release producer_delivers_three_waves -- --nocapture 2>&1 | tail -20
```

  Expect `test result: ok. 1 passed; 0 failed`, in roughly 5–15 s (three ~600 ms waves plus the ~400 ms cold start, then a parallel `ring` re-derivation of 24,576 seeds). **If any seed disagrees with `ring`, stop and fix the backend — do not proceed.** The failure prints the phrase and both hex seeds so you can replay one candidate in isolation.

- [ ] **Step 6: Confirm the GPU-free half still builds and tests without the backend.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo test --no-default-features gpu::producer:: 2>&1 | tail -10
```

  Expect `test result: ok. 17 passed; 0 failed` — the `gpu_tests` module compiles out, and everything else still runs.

- [ ] **Step 7: Commit.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && git add src/gpu/producer.rs && git commit -m "gpu: the producer wave loop — fill, dispatch, audit, carve, send

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 4.7: `GpuEngine` lifecycle — start, signal_stop, is_finished, reap

`GpuEngine` is the only GPU handle `App` will ever hold, and it is `Send + Sync` with **no** Objective-C type inside it — a `const _: fn()` assertion in `src/gpu/mod.rs` pins that so a refactor cannot smuggle one into `App`.

The stop flag is created *inside* `start` and belongs to the producer alone. It is never `App::stop`. If a GPU self-disable set the flag every Rayon worker reads at `/Users/shawnhopkinson/Rust/Vanaddy/src/chains/mod.rs:107`, one audit mismatch would silently end the entire search.

`signal_stop` is non-blocking and never joins, because `stop_search` (`/Users/shawnhopkinson/Rust/Vanaddy/src/app.rs:264-270`) runs on the UI thread inside the render loop. Milestone 6 will park stopped engines in a `Vec` and reap them non-blockingly on the next `start_search`.

**Files:**
- Modify: `/Users/shawnhopkinson/Rust/Vanaddy/src/gpu/metal.rs` — add the `pub struct GpuEngine` / `impl GpuEngine` region (Task 3.3 Step 6 removed `GpuEngine` from this file, so `grep -n "struct GpuEngine\|impl GpuEngine" src/gpu/metal.rs` should print nothing before this task)
- Modify: `/Users/shawnhopkinson/Rust/Vanaddy/src/gpu/stub.rs` — same, added not replaced (Task 3.3 Step 6 removed it here too; `grep -n "struct GpuEngine\|impl GpuEngine" src/gpu/stub.rs` should print nothing before this task)
- Modify: `/Users/shawnhopkinson/Rust/Vanaddy/src/gpu/mod.rs` — restore the `pub use backend::GpuEngine;` re-export and the `Send + Sync` assertion Task 3.3 Step 6 stripped (locate with `grep -n "pub use backend::\|assert_send_sync" src/gpu/mod.rs`)
- Test: `/Users/shawnhopkinson/Rust/Vanaddy/src/gpu/producer.rs` (the `gpu_tests` module)

**Interfaces:**
- Consumes: `pub(crate) fn producer(...)`, `run_guarded`, `set_status`, `read_status` (Tasks 4.1/4.5/4.6); `fn probe() -> GpuStatus` (the free function in each backend, Milestone 1/3)
- Produces: `pub use backend::GpuEngine;` in `src/gpu/mod.rs` (restored here — Task 3.3 Step 6 deliberately left it out and said Milestone 4 restores it); `pub fn GpuEngine::start(tx: Sender<Box<SeedBlock>>, health: Arc<GpuHealth>) -> GpuEngine`; `pub fn GpuEngine::status(&self) -> GpuStatus`; `pub fn GpuEngine::signal_stop(&self)`; `pub fn GpuEngine::is_finished(&self) -> bool`; `pub fn GpuEngine::reap(self)`; `pub fn GpuEngine::probe() -> GpuStatus`

- [ ] **Step 1: Write the failing lifecycle tests.** Append inside the `mod gpu_tests` block in `/Users/shawnhopkinson/Rust/Vanaddy/src/gpu/producer.rs`:

```rust
    use crate::gpu::GpuEngine;
    use std::sync::Arc;

    /// Block until the engine reports finished, or fail with a bounded message.
    fn await_finished(engine: &GpuEngine, bound: Duration, what: &str) -> Duration {
        let started = Instant::now();
        while !engine.is_finished() {
            assert!(
                started.elapsed() < bound,
                "{what}: producer still running after {:?} (bound {bound:?})",
                started.elapsed()
            );
            std::thread::sleep(Duration::from_millis(2));
        }
        started.elapsed()
    }

    #[test]
    fn signal_stop_finishes_the_producer_within_200ms() {
        if std::env::var_os("VANADDY_NO_GPU").is_some() {
            eprintln!("SKIP: VANADDY_NO_GPU is set");
            return;
        }
        let (tx, rx) = crossbeam_channel::bounded(CHANNEL_CAPACITY);
        let health = Arc::new(fresh_health());
        let engine = GpuEngine::start(tx, health.clone());

        // Wait for the first block: that puts the ~95 ms shader compile and the
        // ~300 ms self-test behind us, so the 135 ms steady-state termination
        // bound is the one under test.
        let first = rx
            .recv_timeout(Duration::from_secs(180))
            .expect("no block within 180 s of start");
        drop(first);

        engine.signal_stop();
        let took = await_finished(&engine, Duration::from_millis(200), "signal_stop");
        engine.reap();

        assert!(!health.disable.load(Ordering::Relaxed), "a clean stop must not disable the GPU");
        assert_eq!(health.take_reason(), None);
        eprintln!("signal_stop -> finished in {took:?}");
    }

    #[test]
    fn dropping_the_receiver_exits_the_producer_cleanly() {
        if std::env::var_os("VANADDY_NO_GPU").is_some() {
            eprintln!("SKIP: VANADDY_NO_GPU is set");
            return;
        }
        let (tx, rx) = crossbeam_channel::bounded(CHANNEL_CAPACITY);
        let health = Arc::new(fresh_health());
        let engine = GpuEngine::start(tx, health.clone());

        let first = rx
            .recv_timeout(Duration::from_secs(180))
            .expect("no block within 180 s of start");
        drop(first);

        // Hang up WITHOUT ever setting the stop flag: `Disconnected` is the
        // second, independent wake path, and losing either must not hang.
        drop(rx);

        // Up to one full wave (~600 ms) may already be in flight before the
        // producer next touches the channel.
        await_finished(&engine, Duration::from_secs(5), "receiver drop");
        engine.reap();

        assert!(
            !health.disable.load(Ordering::Relaxed),
            "a clean hang-up is not a fault: the CPU search may simply have stopped"
        );
        assert_eq!(health.take_reason(), None, "no panic, no fault");
    }

    #[test]
    fn status_reports_disabled_once_health_carries_a_reason() {
        if std::env::var_os("VANADDY_NO_GPU").is_some() {
            eprintln!("SKIP: VANADDY_NO_GPU is set");
            return;
        }
        let (tx, rx) = crossbeam_channel::bounded(CHANNEL_CAPACITY);
        let health = Arc::new(fresh_health());
        let engine = GpuEngine::start(tx, health.clone());

        let first = rx
            .recv_timeout(Duration::from_secs(180))
            .expect("no block within 180 s of start");
        drop(first);
        assert!(matches!(engine.status(), GpuStatus::Running { .. }));

        health.raise(GpuDisableReason::AuditMismatch { index: 5_183 });
        assert_eq!(
            engine.status(),
            GpuStatus::Disabled(GpuDisableReason::AuditMismatch { index: 5_183 }),
            "a raised fault must win over the last published status"
        );

        engine.signal_stop();
        await_finished(&engine, Duration::from_secs(5), "post-fault stop");
        engine.reap();
    }
```

- [ ] **Step 2: Run the tests and watch them fail to build.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo test --release signal_stop_finishes_the_producer 2>&1 | head -20
```

  Expect the *import* to be the failure, because Task 3.3 Step 6 deliberately left `GpuEngine` un-re-exported and no backend defines it yet:

```
error[E0432]: unresolved import `crate::gpu::GpuEngine`
  --> src/gpu/producer.rs:...
   |
   |     use crate::gpu::GpuEngine;
   |         ^^^^^^^^^^^^^^^^^^^^^ no `GpuEngine` in `gpu`
```

  This is the red. Do **not** try to make it an `error[E0599]` about a missing `start` by adding the re-export now: `pub use backend::GpuEngine;` in `src/gpu/mod.rs` while neither `metal.rs` nor `stub.rs` defines the type is itself `error[E0432]: unresolved import backend::GpuEngine`, plus `error[E0412]: cannot find type GpuEngine in this scope` in the `Send + Sync` pin — a worse red that says nothing about the tests. The definition lands first (Steps 3–4), the re-export second (Step 4b), and the tests go green in Step 5.

- [ ] **Step 3: Write the Metal `GpuEngine`.** In `/Users/shawnhopkinson/Rust/Vanaddy/src/gpu/metal.rs`, Task 3.3 Step 6 deliberately left NO `GpuEngine` in this file, so there should be nothing to delete — if some region is there anyway, remove it. The free `fn probe()` stays either way; do not delete that. Append:

```rust
/// The only GPU handle `App` ever holds. Deliberately contains NO Objective-C
/// type: every Metal object lives and dies on the producer thread, and the
/// `assert_send_sync::<GpuEngine>()` assertion in `src/gpu/mod.rs` pins that so
/// a refactor cannot smuggle one into `App`.
pub struct GpuEngine {
    /// PRODUCER-ONLY stop flag, created here and shared with nothing else.
    /// NEVER `App::stop`: that is the flag every Rayon worker reads at
    /// src/chains/mod.rs:107, so a GPU self-disable that set it would silently
    /// end the entire search — the exact inverse of "keep searching on CPU".
    stop: Arc<AtomicBool>,
    finished: Arc<AtomicBool>,
    health: Arc<GpuHealth>,
    status: Arc<Mutex<GpuStatus>>,
    join: Option<JoinHandle<()>>,
}

impl GpuEngine {
    /// ~1 ms device probe. Called ONCE from `main()`, BEFORE `enable_raw_mode()`.
    pub fn probe() -> GpuStatus {
        probe()
    }

    /// Returns IMMEDIATELY with status `Initializing`. Device creation, the
    /// ~60-95 ms cold library compile, pipeline build and the ~300 ms self-test
    /// all run on the spawned thread, so the UI never stalls on them.
    pub fn start(tx: Sender<Box<SeedBlock>>, health: Arc<GpuHealth>) -> GpuEngine {
        let stop = Arc::new(AtomicBool::new(false));
        let finished = Arc::new(AtomicBool::new(false));
        let status = Arc::new(Mutex::new(GpuStatus::Initializing));

        let t_stop = stop.clone();
        let t_finished = finished.clone();
        let t_health = health.clone();
        let t_status = status.clone();

        let join = std::thread::Builder::new()
            .name("vanaddy-gpu".into())
            .spawn(move || {
                run_guarded(&t_health, t_finished, || {
                    producer(tx, &t_stop, &t_health, &t_status)
                });
            })
            .ok();

        if join.is_none() {
            // Out of threads. Degrade exactly like every other failure: sticky
            // reason, GPU off, CPU search untouched.
            let reason = GpuDisableReason::BadConfig("could not spawn the vanaddy-gpu thread".into());
            health.raise(reason.clone());
            set_status(&status, GpuStatus::Disabled(reason));
            finished.store(true, Ordering::Release);
        }

        GpuEngine { stop, finished, health, status, join }
    }

    /// A raised fault wins over the last published status: a GPU that faulted
    /// must never keep reporting `Running` at 0/s.
    pub fn status(&self) -> GpuStatus {
        match self.health.take_reason() {
            Some(reason) => GpuStatus::Disabled(reason),
            None => read_status(&self.status),
        }
    }

    /// Sets the producer-only stop flag. NON-BLOCKING; never joins.
    ///
    /// `stop_search` calls this from the UI thread inside the render loop. A
    /// join here would stall the loop for the rest of a cold shader compile on
    /// an Enter-Ctrl+C-Enter sequence, and would block FOREVER if the GPU
    /// wedged inside `waitUntilCompleted` — leaving the terminal in raw mode
    /// with the alternate screen up and only `kill -9` as an exit.
    pub fn signal_stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }

    /// Acquire: pairs with the `FinishGuard`'s Release store, so seeing `true`
    /// guarantees the fault the producer raised just before it is also visible.
    pub fn is_finished(&self) -> bool {
        self.finished.load(Ordering::Acquire)
    }

    /// Joins the thread. Only call once `is_finished()` is true, or from the
    /// reaper at process exit where a wedged thread is accepted.
    pub fn reap(mut self) {
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}
```

- [ ] **Step 4: Add the imports the new code needs.** At the top of `/Users/shawnhopkinson/Rust/Vanaddy/src/gpu/metal.rs`, add to the existing `use` block. `GpuStatus` is already in the `crate::gpu::{…}` group at metal.rs:10-13, and `AtomicBool`/`Ordering` are already imported at metal.rs:23 — add neither:

```rust
use super::producer::{producer, read_status, run_guarded, set_status};
use super::{GpuDisableReason, GpuHealth, SeedBlock};
use crossbeam_channel::Sender;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
```

- [ ] **Step 4b: Restore the `GpuEngine` re-export and the `Send + Sync` pin.** Now — and not before — `backend::GpuEngine` exists, so the re-export resolves. Task 3.3 Step 6 deliberately left `GpuEngine` un-re-exported and dropped it from the assertion, saying Milestone 4 restores both; this is that moment, and it must land before Step 5 because the `use crate::gpu::GpuEngine;` in the tests, and Task 5.3 and Task 6.1 later, all resolve through it. In `/Users/shawnhopkinson/Rust/Vanaddy/src/gpu/mod.rs`, immediately after `pub use backend::probe;`, add:

```rust
pub use backend::GpuEngine;
```

  and restore the assertion Task 3.3 Step 6 shortened, so it reads:

```rust
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<GpuEngine>();
    assert_send_sync::<SeedBlock>();
    assert_send_sync::<GpuHealth>();
};
```

  `GpuEngine` holds only `Arc`s and an `Option<JoinHandle<()>>` — no Objective-C type — so this compiles on both backends, and it is exactly what stops a later refactor from smuggling a Metal object into `App`. On this machine the Metal backend is the one selected, so the tree compiles here even though `src/gpu/stub.rs` does not gain its `GpuEngine` until Step 6; Step 7's `--no-default-features` build is what proves the stub leg.

- [ ] **Step 5: Run the lifecycle tests and watch them pass.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo test --release gpu::producer::gpu_tests -- --test-threads=1 --nocapture 2>&1 | tail -25
```

  `--test-threads=1` matters: these tests each start a GPU producer, and running four of them concurrently makes them contend for the same 8-core GPU and blows the 200 ms termination bound. Expect `test result: ok. 4 passed; 0 failed` and a printed `signal_stop -> finished in ...` well under 200 ms (typically 10–40 ms).

- [ ] **Step 6: Mirror the surface in the stub backend.** In `/Users/shawnhopkinson/Rust/Vanaddy/src/gpu/stub.rs`, Task 3.3 Step 6 deliberately left NO `GpuEngine` in this file either, so there should be nothing to delete — if some region is there anyway, remove it. The free `fn probe()` stays; do not delete that.

  **This deliberately supersedes the design spec.** `docs/superpowers/specs/2026-08-26-metal-gpu-pbkdf2-design.md` (~line 445) describes the stub `GpuEngine` as uninhabited — `GpuEngine { _never: Infallible }`, with a `start` that is `unreachable!()`. Milestone 1 Task 1.3 built exactly that placeholder; Task 3.3 Step 5 deleted it; and what goes in below is a **constructible** unit struct instead. Two reasons, both load-bearing: (1) it is the only form Task 8.4 Step 1's `stub_engine_lifecycle_is_a_terminating_no_op` can exercise — that test does `GpuEngine::start(tx, health)`, `signal_stop()`, `assert!(is_finished())`, `reap()`, none of which an uninhabited type can satisfy; (2) `health.raise(GpuDisableReason::NotSupported)` *degrades* to CPU-only, where `unreachable!()` would panic a Rayon worker with the terminal in raw mode and the alternate screen up — which the spec's own "never abort inside raw mode" rule forbids. This divergence is intentional: do not "restore" the spec's form, and do not edit the spec file from this task.

  Append:

```rust
/// No Metal on this target. The same public surface, all no-ops.
pub struct GpuEngine;

impl GpuEngine {
    pub fn probe() -> GpuStatus {
        probe()
    }

    /// Hangs the channel up immediately and records why, so a caller that
    /// ignored `probe()` degrades to CPU-only at once instead of waiting
    /// forever for blocks that can never arrive.
    pub fn start(tx: Sender<Box<SeedBlock>>, health: Arc<GpuHealth>) -> GpuEngine {
        drop(tx);
        health.raise(GpuDisableReason::NotSupported);
        GpuEngine
    }

    pub fn status(&self) -> GpuStatus {
        probe()
    }

    pub fn signal_stop(&self) {}

    /// There is no thread, so there is nothing to wait for.
    pub fn is_finished(&self) -> bool {
        true
    }

    pub fn reap(self) {}
}
```

  and add to the `use` block at the top of the same file. `GpuStatus` is already imported at `src/gpu/stub.rs:6` as `use crate::gpu::GpuStatus;` — leave that line alone and do not re-import it:

```rust
use super::{GpuDisableReason, GpuHealth, SeedBlock};
use crossbeam_channel::Sender;
use std::sync::Arc;
```

- [ ] **Step 7: Prove the stub backend compiles and the GPU-free tests still pass without it.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo build --no-default-features && cargo test --no-default-features 2>&1 | tail -10
```

  Expect a clean build and `test result: ok.` with 0 failed. The count is the current `--no-default-features` baseline — **110** at the end of Milestone 3 — plus this milestone's GPU-free producer tests (16, plus the macOS-only QoS test = 17 on macOS), i.e. **127** on macOS.

- [ ] **Step 8: Run the whole suite, then gate the lints on the baseline delta.** Per this milestone's preamble: no bare `cargo fmt`, and the gate is "no NEW warning", not "no warnings".

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo test --release -- --test-threads=1 2>&1 | tail -10
```

  Expect `test result: ok.` with 0 failed. Then:

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && rustfmt --edition 2021 src/gpu/producer.rs src/gpu/metal.rs src/gpu/stub.rs src/gpu/mod.rs \
  && rustfmt --edition 2021 --check src/gpu/producer.rs src/gpu/metal.rs src/gpu/stub.rs src/gpu/mod.rs && echo NEW-FILES-FMT-CLEAN \
  && cargo clippy --all-targets 2>&1 | grep -- '-->' | sort | uniq -c
```

  Expect `NEW-FILES-FMT-CLEAN` followed by exactly the 12 pre-existing clippy lines recorded in Milestone 1 Task 1.8 Step 5 — count still 12, and **no line pointing into `src/gpu/`**. Do not "fix" the 12: they live in `src/app.rs`, `src/ui.rs`, `src/chains/bitcoin.rs`, `src/chains/evm.rs` and `src/chains/ton_cell.rs`, are out of scope for this branch, and touching them would wreck Milestone 1's whole-diff gate.

- [ ] **Step 9: Commit.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && git add src/gpu/metal.rs src/gpu/stub.rs src/gpu/producer.rs src/gpu/mod.rs && git commit -m "gpu: GpuEngine start/signal_stop/is_finished/reap with a producer-only stop flag

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 4.8: Measure the real end-to-end rate and set `EVM_GPU_SEEDS_PER_SEC`

The prototype measured 13,634–14,768 seeds/s at the kernel level. This task measures what the *workers actually receive* — after phrase generation, packing, the audit, and the channel — which is the only number `App::estimated_rate` may be built on in Milestone 7.

Measure with a saturated CPU, not on an idle machine: throughput was reproducibly observed collapsing to 3,000–7,000 seeds/s while the desktop compositor was busy, and the pre-search ETA must not be built on an idle peak.

**Files:**
- Modify: `/Users/shawnhopkinson/Rust/Vanaddy/src/gpu/mod.rs` — add one constant next to the other `pub const`s at the top
- Test: `/Users/shawnhopkinson/Rust/Vanaddy/src/gpu/producer.rs` (the `gpu_tests` module)

**Interfaces:**
- Consumes: `GpuEngine::start`, `pub const BLOCK`, `pub const CHANNEL_CAPACITY` (Task 4.7 / Milestone 1)
- Produces: `pub const EVM_GPU_SEEDS_PER_SEC: f64` in `src/gpu/mod.rs`

- [ ] **Step 1: Write the failing measurement test.** Append inside the `mod gpu_tests` block in `/Users/shawnhopkinson/Rust/Vanaddy/src/gpu/producer.rs`:

```rust
    /// MEASUREMENT, not a gate. Run it under CPU load (Task 4.8 Step 4) when
    /// the kernel, the wave geometry or the machine changes, then run Step 5
    /// to fold the result into `EVM_GPU_SEEDS_PER_SEC`:
    ///
    ///   cargo test --release gpu_seed_rate_end_to_end -- --ignored --nocapture
    ///
    /// Three independent 10 s windows, not one 30 s window: a single sample
    /// cannot tell "this machine does 13,800/s" from "this machine got one
    /// lucky window". The floor (3,000 seeds/s) is the observed
    /// compositor-contention floor, not the target: below it means something
    /// is broken; a spread above 15% between the three windows means the run
    /// was not clean (compositor busy, thermal throttling) and must be
    /// re-run with the display otherwise quiescent. On success, appends
    /// `rate,device_name,timestamp` to `/tmp/vanaddy-rate/measured.txt` for
    /// Step 5 to read back — this test never edits the constant itself.
    #[test]
    #[ignore = "measurement; run with --release --nocapture, see Task 4.8 Step 4"]
    fn gpu_seed_rate_end_to_end() {
        let (tx, rx) = crossbeam_channel::bounded(CHANNEL_CAPACITY);
        let health = Arc::new(fresh_health());
        let engine = GpuEngine::start(tx, health.clone());

        // Discard the first block: it hides the ~95 ms shader compile and the
        // ~300 ms self-test, which are startup cost, not steady-state rate.
        let first = rx
            .recv_timeout(Duration::from_secs(180))
            .expect("no block within 180 s of start");
        drop(first);

        let mut rates = Vec::with_capacity(3);
        for window_ix in 0..3 {
            let window = Duration::from_secs(10);
            let started = Instant::now();
            let mut blocks = 0u64;
            while started.elapsed() < window {
                if rx.recv_timeout(Duration::from_millis(500)).is_ok() {
                    blocks += 1;
                }
            }
            let secs = started.elapsed().as_secs_f64();
            let rate = (blocks as f64) * (BLOCK as f64) / secs;
            eprintln!(
                "window {window_ix}: {rate:.0} seeds/s ({blocks} blocks x {BLOCK} over {secs:.1}s)"
            );
            rates.push(rate);
        }

        let device_name = match engine.status() {
            GpuStatus::Running { device } => device,
            other => format!("{other:?}"),
        };

        engine.signal_stop();
        await_finished(&engine, Duration::from_secs(5), "measurement stop");
        engine.reap();

        let min = rates.iter().cloned().fold(f64::INFINITY, f64::min);
        let max = rates.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
        let mean = rates.iter().sum::<f64>() / rates.len() as f64;
        let spread = (max - min) / mean;
        eprintln!(
            "\nEVM_GPU_SEEDS_PER_SEC measured: {mean:.0} seeds/s (mean of 3 x 10s windows, \
             spread {:.1}%)\ncurrent constant: {:.0}\n",
            spread * 100.0,
            crate::gpu::EVM_GPU_SEEDS_PER_SEC
        );
        assert!(
            min > 3_000.0,
            "delivered rate {min:.0}/s is below the compositor-contention floor; \
             something is wrong with the pipeline, not just busy"
        );
        assert!(
            spread < 0.15,
            "run-to-run spread {:.1}% exceeds 15% -- the display was not quiescent \
             or the machine was thermally throttling; re-run",
            spread * 100.0
        );
        assert_eq!(
            health.take_reason(),
            None,
            "no fault during the measurement"
        );

        std::fs::create_dir_all("/tmp/vanaddy-rate").expect("create /tmp/vanaddy-rate");
        let timestamp = std::process::Command::new("date")
            .args(["-u", "+%Y-%m-%dT%H:%M:%SZ"])
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|| "unknown-time".to_string());
        let line = format!("{mean:.0},{device_name},{timestamp}\n");
        use std::io::Write;
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open("/tmp/vanaddy-rate/measured.txt")
            .and_then(|mut f| f.write_all(line.as_bytes()))
            .expect("append /tmp/vanaddy-rate/measured.txt");
    }
```

- [ ] **Step 2: Run the test and watch it fail to build.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo test --release gpu_seed_rate_end_to_end -- --ignored 2>&1 | head -20
```

  Expect:

```
error[E0425]: cannot find value `EVM_GPU_SEEDS_PER_SEC` in module `crate::gpu`
```

- [ ] **Step 3: Add the constant with a PROVISIONAL value.** In `/Users/shawnhopkinson/Rust/Vanaddy/src/gpu/mod.rs`, immediately after `pub const AUDITS_PER_WAVE: usize = 4;`, add:

```rust
/// PROVISIONAL: carried over from the prototype's kernel-level 13,634-14,768/s
/// range. This is NOT an end-to-end measurement — Task 4.8 Step 5
/// (docs/superpowers/plans/2026-08-26-metal-gpu-pbkdf2.md) replaces this
/// comment and the value below with the measured end-to-end delivery rate
/// (seeds handed to the workers per wall-second, under CPU load).
///
/// Re-measure with:
///   cargo test --release gpu_seed_rate_end_to_end -- --ignored --nocapture
pub const EVM_GPU_SEEDS_PER_SEC: f64 = 13_600.0;
```

- [ ] **Step 4: Run the measurement under a scriptable CPU load.** The interactive TUI cannot be driven by an unattended implementer, so this generates the same 8-thread CPU load without it. Display state matters: run this with the display otherwise quiescent (no other app compositing or animating) — a compositor-busy run collapses the *live* rate for a different reason (GPU contention with the compositor, spec risk area, not CPU contention) than what this constant models, and is invalid; if the display was busy during the run, discard the result and re-run.

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo build --release
mkdir -p /tmp/vanaddy-rate
for i in $(seq 1 8); do yes > /dev/null & done
YES_PIDS=$(jobs -p)
cargo test --release gpu_seed_rate_end_to_end -- --ignored --nocapture 2>&1 | tail -30
kill $YES_PIDS 2>/dev/null
```

  Eight `yes > /dev/null` processes saturate 8 CPU threads the same way an 8-thread EVM search does, without a second terminal or a Ratatui session. Expect `test result: ok. 1 passed`, three per-window rate lines and a spread under 15%, and `/tmp/vanaddy-rate/measured.txt` to gain a new line: `<rate>,<device_name>,<timestamp>`. If the spread assertion fails, the display was probably not quiescent (or the machine throttled) — close other apps and re-run.

- [ ] **Step 5: Read the measurement back and update the constant.** Do not trust a remembered number or terminal scrollback — read `/tmp/vanaddy-rate/measured.txt` itself, and gate on it being both present and fresh:

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy \
  && test -f /tmp/vanaddy-rate/measured.txt || { echo 'FAIL: no measurement file — Step 4 did not run or was skipped'; exit 1; } \
  && FILE_TS=$(stat -f %m /tmp/vanaddy-rate/measured.txt 2>/dev/null || stat -c %Y /tmp/vanaddy-rate/measured.txt) \
  && COMMIT_TS=$(git log -1 --format=%ct) \
  && { [ "$FILE_TS" -ge "$COMMIT_TS" ] || { echo 'FAIL: measurement predates the current commit — re-run Step 4'; exit 1; }; } \
  && tail -1 /tmp/vanaddy-rate/measured.txt
```

  (`stat -f %m` is the macOS/BSD form, `stat -c %Y` the GNU/Linux form; one of the two resolves on any machine this runs on.) If the gate fails, go back to Step 4 — do not hand-edit the constant from a number you remember.

  The last line printed is `<rate>,<device_name>,<timestamp>`. Replace BOTH the value and the doc comment in `/Users/shawnhopkinson/Rust/Vanaddy/src/gpu/mod.rs` — the PROVISIONAL wording must not survive a completed measurement, even when the number does not move. If `<rate>` differs from 13,600 by more than 5% (i.e. is outside 12,920–14,280), round it to the nearest 100; otherwise keep `13_600.0`:

```rust
/// Measured end-to-end delivery rate: seeds handed to the workers per
/// wall-second, under CPU load — NOT the idle solo kernel peak (14,768/s).
/// Measured on <device_name>, <date from the timestamp field>, under an
/// 8-thread CPU search with the display otherwise quiescent (see
/// /tmp/vanaddy-rate/measured.txt and Task 4.8 Step 4).
///
/// `App::estimated_rate` uses this for the PRE-search ETA only; once a search
/// is running the ETA switches to the live counter, which is automatically
/// correct because GPU candidates increment the same counter. The displayed
/// GPU rate in the stats pane must likewise be measured per wave, never
/// modelled from this: mid-run collapse to 3,000-7,000 seeds/s under compositor
/// load is reproducible, and a modelled rate would lie by up to 4x.
///
/// On Apple Silicon other than the machine above this is an ESTIMATE, not a
/// measurement: the PRE-search ETA will be wrong until re-measured on that
/// device (spec risk 7).
///
/// Re-measure with:
///   cargo test --release gpu_seed_rate_end_to_end -- --ignored --nocapture
pub const EVM_GPU_SEEDS_PER_SEC: f64 = 13_800.0;
```

  (13,800 shown for a measured 13,840, rounded to the nearest 100 — substitute your own measured value and device/date.)

  **This is the single definition of the constant in the tree.** `App::estimated_rate` (Milestone 7, Task 7.7) reads it as `crate::gpu::EVM_GPU_SEEDS_PER_SEC` and must never declare a second copy in `src/app.rs`, so editing the value here is exactly what changes the pre-search ETA. If you find a `const EVM_GPU_SEEDS_PER_SEC` anywhere outside `src/gpu/mod.rs`, delete it — a shadow copy in `src/app.rs` would silently swallow this measurement, which is the entire point of this task.

  **If any part of this step cannot be completed without a human** (no machine available to run Step 4, the gate keeps failing for a reason you cannot resolve, etc.), do not commit the placeholder labelled as measured. Stop and report `DONE_WITH_CONCERNS`, stating exactly what could not be done.

- [ ] **Step 6: Re-run the whole suite, then re-gate the lints on the baseline delta.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo test --release -- --test-threads=1 2>&1 | tail -10
```

  Expect `test result: ok.` with 0 failed (the measurement test stays `ignored`). Then, as in Task 4.7 Step 8 — no bare `cargo fmt`:

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && rustfmt --edition 2021 src/gpu/producer.rs src/gpu/mod.rs \
  && rustfmt --edition 2021 --check src/gpu/producer.rs src/gpu/mod.rs && echo NEW-FILES-FMT-CLEAN \
  && cargo clippy --all-targets 2>&1 | grep -- '-->' | sort | uniq -c
```

  Expect `NEW-FILES-FMT-CLEAN` and exactly the 12 pre-existing clippy lines, none of them in `src/gpu/`.

- [ ] **Step 7: Commit.** Replace `<MEASURED>`, `<DEVICE>` and `<DATE>` with the values read back in Step 5 — do not commit this template verbatim, and do not reuse the worked example numbers from Step 4's sample output:

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && git add src/gpu/mod.rs src/gpu/producer.rs && git commit -m "gpu: EVM_GPU_SEEDS_PER_SEC from a measured end-to-end rate (<MEASURED> seeds/s on <DEVICE>, <DATE>, under an 8-thread CPU search)

On Apple Silicon other than <DEVICE> this is an estimate until re-measured (spec risk 7).

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Milestone 4 exit criteria

All four must hold before starting Milestone 5:

1. `cargo test --release -- --test-threads=1` passes with 0 failures, including every pinned vector in CLAUDE.md and `producer_delivers_three_waves_whose_every_seed_matches_ring` (24,576 GPU seeds, all equal to `ring`).
2. `cargo test --no-default-features` passes: **127** tests total on macOS (the 110-test baseline plus this milestone's 17 GPU-free producer tests), with no Metal in the tree.
3. `signal_stop_finishes_the_producer_within_200ms` and `dropping_the_receiver_exits_the_producer_cleanly` pass — both wake paths work independently, and neither blocks.
4. `rustfmt --edition 2021 --check src/gpu/producer.rs src/gpu/metal.rs src/gpu/stub.rs src/gpu/mod.rs` prints nothing, and `cargo clippy --all-targets 2>&1 | grep -- '-->' | sort | uniq -c` still shows exactly the 12 pre-existing baseline lines from Milestone 1 Task 1.8 Step 5 with none of them in `src/gpu/`. The clean baseline is NOT warning-free and is NOT rustfmt-clean, so the gate is "no new warning, no new fmt drift", never "clean".

Nothing in `src/app.rs`, `src/ui.rs`, `src/main.rs` or `src/chains/` was touched by this milestone. A user running the binary sees exactly the behaviour they saw after Milestone 3 — the producer exists but nothing starts it.

---

## Milestone 5 — Worker integration

The GPU producer from Milestone 4 now has a consumer. This milestone routes `Option<&GpuRx>` and `&GpuHealth` from the search entry point down to the Rayon workers, implements the non-blocking `try_recv` drain, the chunked stop checks that keep Ctrl+C responsive inside a 512-candidate block, and the verify-gated emit path.

Two CLAUDE.md rules bound every edit here:

- **The hot loop stays allocation-free.** Nothing in this milestone touches `matches_raw`. `drain_gpu_block` calls `C::matches_raw(matcher, &addr)` on a stack `[u8; 20]` and allocates only on the ~1-in-16^n path where a match is actually emitted.
- **Monomorphization, not dyn dispatch.** `ChainKind::search` keeps its single `match self` — evaluated once per thread spawn — and picks either `search::<C>` or `search_hybrid::<C>`. There is no `Box<dyn Chain>`, no trait object, and no per-candidate indirection anywhere in the added code.

The pinned test `search_counts_whole_batches_and_honours_stop` (`src/chains/mod.rs:130-146`) calls the free function `search::<Solana>`, whose signature is **unchanged**. Every task below ends with a check that this one test's body was not touched: extract it — from its `fn` line through the first line that is exactly four spaces and a closing brace — out of the milestone's base commit and out of the working tree, then `diff` the two. That is an exact byte comparison of this test and nothing else. Do **not** substitute a `git diff … | grep -c` for it: git diff's leading context drags in neighbouring lines, and this milestone's own new tests legitimately contain the string `n % LANES`, so such a count can never reach `0` and would be a false alarm with no correct action behind it.

---

### Task 5.1: Thread `gpu` and `health` through `ChainKind::search`

**Files:**
- Modify: `/Users/shawnhopkinson/Rust/Vanaddy/src/chains/mod.rs` (`ChainKind::search`, currently lines 84-98)
- Modify: `/Users/shawnhopkinson/Rust/Vanaddy/src/app.rs` (`start_search`, the single call site, currently line 256; the `let counter = ...` block at line 233)
- Modify (preflight only, if needed): `/Users/shawnhopkinson/Rust/Vanaddy/src/gpu/mod.rs` (`GpuHealth`)
- Test: `/Users/shawnhopkinson/Rust/Vanaddy/src/chains/mod.rs` (`mod tests`, currently ends at line 147)

**Interfaces:**
- Consumes: `pub fn search<C: Chain>(matcher: &Matcher, stop: &AtomicBool, counter: &AtomicU64, tx: &Sender<Match>)` (unchanged, `src/chains/mod.rs:101`); `pub fn search_hybrid<C: Bip39GpuChain>(matcher: &Matcher, stop: &AtomicBool, counter: &AtomicU64, tx: &Sender<Match>, gpu: Option<&crate::gpu::GpuRx>, health: &crate::gpu::GpuHealth)` (Milestone 2); `pub type GpuRx = crossbeam_channel::Receiver<Box<SeedBlock>>`; `pub struct GpuHealth { pub disable: AtomicBool, pub seeds_delivered: AtomicU64, .. }`; `impl Default for GpuHealth` (written by Milestone 1 Task 1.5 Step 4 — consumed here, never re-declared); `impl Bip39GpuChain for Evm` (Milestone 2)
- Produces: `ChainKind::search(self, matcher: &Matcher, stop: &AtomicBool, counter: &AtomicU64, tx: &Sender<Match>, gpu: Option<&crate::gpu::GpuRx>, health: &crate::gpu::GpuHealth)`

---

- [ ] **Step 1: Preflight — confirm `GpuHealth` can be default-constructed.**

  Task 5.1's test and `App::start_search` both need to hand the workers a health cell. Run:

  ```sh
  cd /Users/shawnhopkinson/Rust/Vanaddy
  grep -n "Default" src/gpu/mod.rs
  ```

  Milestone 1 Task 1.5 Step 4 already wrote `impl Default for GpuHealth { fn default() -> Self { GpuHealth::new() } }` (see M1 Task 1.5), so this grep **must** hit `impl Default for GpuHealth`. Change nothing and move on.

  Do **not** add `#[derive(Default)]` to `GpuHealth` as well — a derive alongside the hand-written impl is `error[E0119]: conflicting implementations of trait Default for type GpuHealth`. Milestone 2 Task 2.4 Step 1 carries the same warning; this task is bound by it too.

  If the grep somehow does not hit, do not derive `Default` here — go back and finish Milestone 1 Task 1.5 Step 4, then return.

- [ ] **Step 2: Write the failing test.**

  Append this to the existing `mod tests` in `/Users/shawnhopkinson/Rust/Vanaddy/src/chains/mod.rs`, immediately after the closing brace of `search_counts_whole_batches_and_honours_stop` and before the module's final `}`. Do not edit `search_counts_whole_batches_and_honours_stop` itself.

  **Milestone 2 Task 2.4 Step 5 already added a test called `search_with_no_gpu_source_is_unchanged` to this same `mod tests`** — it pins the free function `search_hybrid` with `gpu: None`. Do **not** replace, rename, or delete it: both tests must exist, because they cover different entry points. The test below therefore carries a different name, `chain_kind_search_with_no_gpu_source_is_unchanged`, since it exercises the `ChainKind::search` dispatch arm. Two `fn` items with the same name in one module is `error[E0428]: the name ... is defined multiple times`.

  ```rust
      /// `ChainKind::search` gained two GPU parameters. Milestone 2 already pinned
      /// the free function `search_hybrid` with `gpu: None`; this pins the
      /// `ChainKind` arm. With `gpu: None` — the state every non-EVM chain is
      /// permanently in, and the state EVM is in until Milestone 6 spawns a
      /// producer — behaviour must be exactly what it was: whole `C::BATCH`
      /// increments, prompt stop, and no GPU bookkeeping.
      #[test]
      fn chain_kind_search_with_no_gpu_source_is_unchanged() {
          let health = crate::gpu::GpuHealth::default();

          // EVM routes through search_hybrid; 8 hex chars is 1 in 2^32, so no
          // candidate can match and no Match is ever emitted.
          let matcher = Matcher::new("ffffffff".into(), String::new(), false, ChainKind::Evm);
          let stop = AtomicBool::new(false);
          let counter = AtomicU64::new(0);
          let (tx, rx) = mpsc::channel();
          thread::scope(|s| {
              s.spawn(|| ChainKind::Evm.search(&matcher, &stop, &counter, &tx, None, &health));
              thread::sleep(Duration::from_millis(50));
              stop.store(true, Ordering::Relaxed);
          });
          let n = counter.load(Ordering::Relaxed);
          assert!(n > 0, "hybrid search with no GPU source must still make CPU progress");
          assert_eq!(evm::Evm::BATCH, LANES);
          assert_eq!(n % LANES as u64, 0, "counter advances in whole CPU batches, got {n}");
          assert_eq!(
              health.seeds_delivered.load(Ordering::Relaxed),
              0,
              "no GPU source means no GPU seeds may be counted"
          );
          assert!(!health.disable.load(Ordering::Relaxed), "a clean CPU run raises no fault");
          drop(tx);
          assert!(rx.try_recv().is_err(), "an 8-hex-char prefix cannot be hit in 50 ms");

          // A non-EVM arm must ignore both new parameters entirely.
          let matcher = Matcher::new("zzzzzzzzz".into(), String::new(), true, ChainKind::Solana);
          let stop = AtomicBool::new(false);
          let counter = AtomicU64::new(0);
          let (tx, _rx) = mpsc::channel();
          thread::scope(|s| {
              s.spawn(|| ChainKind::Solana.search(&matcher, &stop, &counter, &tx, None, &health));
              thread::sleep(Duration::from_millis(50));
              stop.store(true, Ordering::Relaxed);
          });
          let n = counter.load(Ordering::Relaxed);
          assert!(n > 0, "Solana must still search");
          assert_eq!(n % LANES as u64, 0, "Solana counter advances in whole batches, got {n}");
          assert_eq!(
              health.seeds_delivered.load(Ordering::Relaxed),
              0,
              "non-EVM chains must never touch GPU health"
          );
      }
  ```

- [ ] **Step 3: Run the test and watch it fail to compile.**

  ```sh
  cd /Users/shawnhopkinson/Rust/Vanaddy && cargo test chain_kind_search_with_no_gpu_source_is_unchanged
  ```

  Expected output — two instances (one per call site) of:

  ```
  error[E0061]: this method takes 4 arguments but 6 arguments were supplied
  ```

  with `unexpected argument #5 of type Option<_>` and `unexpected argument #6 of type &GpuHealth`, pointing at `ChainKind::Evm.search(...)` and `ChainKind::Solana.search(...)`. Do not proceed until you have seen `E0061`.

- [ ] **Step 4: Widen `ChainKind::search`.**

  In `/Users/shawnhopkinson/Rust/Vanaddy/src/chains/mod.rs`, replace lines 84-98 in their entirety:

  ```rust
      pub fn search(
          self,
          matcher: &Matcher,
          stop: &AtomicBool,
          counter: &AtomicU64,
          tx: &Sender<Match>,
      ) {
          match self {
              Self::Solana => search::<solana::Solana>(matcher, stop, counter, tx),
              Self::Evm => search::<evm::Evm>(matcher, stop, counter, tx),
              Self::Bitcoin => search::<bitcoin::Bitcoin>(matcher, stop, counter, tx),
              Self::Ton => search::<ton::Ton>(matcher, stop, counter, tx),
              Self::Monero => search::<monero::Monero>(matcher, stop, counter, tx),
          }
      }
  ```

  with:

  ```rust
      /// Only the `Evm` arm routes to `search_hybrid`; the other four call the
      /// unchanged `search::<C>` and ignore both GPU parameters. The `match` is
      /// still evaluated once per thread spawn and each arm is monomorphized
      /// separately — no `dyn`, no v-table, nothing per-candidate.
      pub fn search(
          self,
          matcher: &Matcher,
          stop: &AtomicBool,
          counter: &AtomicU64,
          tx: &Sender<Match>,
          gpu: Option<&crate::gpu::GpuRx>,
          health: &crate::gpu::GpuHealth,
      ) {
          match self {
              Self::Solana => search::<solana::Solana>(matcher, stop, counter, tx),
              Self::Evm => search_hybrid::<evm::Evm>(matcher, stop, counter, tx, gpu, health),
              Self::Bitcoin => search::<bitcoin::Bitcoin>(matcher, stop, counter, tx),
              Self::Ton => search::<ton::Ton>(matcher, stop, counter, tx),
              Self::Monero => search::<monero::Monero>(matcher, stop, counter, tx),
          }
      }
  ```

- [ ] **Step 5: Fix the one production call site.**

  `chain.search(...)` is called in exactly one place — `src/app.rs:256`, inside `start_search`'s `pool.spawn`. Confirm that is still true:

  ```sh
  cd /Users/shawnhopkinson/Rust/Vanaddy && grep -rn "\.search(" src/
  ```

  In `/Users/shawnhopkinson/Rust/Vanaddy/src/app.rs`, find the line

  ```rust
          let counter = self.counter.clone();
  ```

  (currently line 233, inside `start_search`) and insert immediately after it:

  ```rust
          // Milestone 6 replaces this with `self.gpu_health.clone()` once `App`
          // owns the cell. Until then the workers still need a health cell to
          // read, and `gpu: None` means nothing can ever write to it.
          let health = Arc::new(crate::gpu::GpuHealth::default());
  ```

  Then find

  ```rust
                  chain.search(&matcher, &stop, &counter, &tx);
  ```

  (currently line 256) and replace it with:

  ```rust
                  chain.search(&matcher, &stop, &counter, &tx, None, &health);
  ```

  `health` is moved into the `move ||` closure and `&health` deref-coerces from `&Arc<GpuHealth>` to `&GpuHealth`. No `use` statement is needed: `Arc` is already imported at `src/app.rs:10`.

  This `let health = Arc::new(crate::gpu::GpuHealth::default());` binding is a **placeholder that Milestone 6 must remove**. Milestone 6 Task 6.6 replaces the pool block with one that binds `let health = self.gpu_health.clone();`, so it has to delete these four lines — the three comment lines plus the `let health = Arc::new(...)` — first. Leaving both in place shadows this one, which is then never read: `warning: unused variable: health`, which breaks the clippy-count gate in Step 8.

- [ ] **Step 6: Run the test and watch it pass.**

  ```sh
  cd /Users/shawnhopkinson/Rust/Vanaddy && cargo test chain_kind_search_with_no_gpu_source_is_unchanged
  ```

  Expected: `test chains::tests::chain_kind_search_with_no_gpu_source_is_unchanged ... ok` and `test result: ok. 1 passed`. (The shorter filter `search_with_no_gpu_source_is_unchanged` is a substring of both names and would also run Milestone 2's test — that spelling gives `2 passed`, and both must be `ok`.)

- [ ] **Step 7: Run the whole suite and prove the pinned test is untouched.**

  ```sh
  cd /Users/shawnhopkinson/Rust/Vanaddy && cargo test 2>&1 | tail -3
  ```

  Every test must pass. Then compare the pinned test's own body, byte for byte, against the milestone base. This task has not committed yet — Step 9 does that — so the base is `HEAD`:

  ```sh
  cd /Users/shawnhopkinson/Rust/Vanaddy
  # The pinned test must be byte-identical to the milestone base.
  git show HEAD:src/chains/mod.rs \
    | sed -n '/fn search_counts_whole_batches_and_honours_stop/,/^    }$/p' > /tmp/pinned_before.txt
  sed -n '/fn search_counts_whole_batches_and_honours_stop/,/^    }$/p' \
    src/chains/mod.rs > /tmp/pinned_after.txt
  diff /tmp/pinned_before.txt /tmp/pinned_after.txt && echo "PINNED TEST UNTOUCHED"
  ```

  Expected: no `diff` output at all, followed by `PINNED TEST UNTOUCHED`. Each `sed` range captures exactly the 16 lines of the test, from `fn search_counts_whole_batches_and_honours_stop() {` through its closing `    }`.

  Do **not** replace this with `git diff src/chains/mod.rs | grep -c "search_counts_whole_batches\|n % LANES"` expecting `0`. That count can never be `0` here: Step 2's new test legitimately contains `n % LANES` on two of its own added lines, and git diff's leading context pulls in the pinned test's neighbouring lines besides. A non-zero count there is a false alarm with no correct action behind it — the `diff` above is the gate.

- [ ] **Step 8: Lint and format.**

  The clean tree is **not** clippy-clean, so never write "expect no warnings" here. Compare against the baseline Milestone 1 Task 1.8 Step 5 recorded — and do **not** reach for `git stash` to get it: `grep -c` exits non-zero when it counts `0`, so a `git stash && … && git stash pop` chain can leave your work stashed.

  ```sh
  cd /Users/shawnhopkinson/Rust/Vanaddy && touch src/main.rs && cargo clippy --all-targets 2>&1 | grep -- '-->' | sort | uniq -c
  ```

  Expected: exactly the same 12 lines Milestone 1 Task 1.8 Step 5 recorded — five in `src/app.rs`, one in `src/chains/bitcoin.rs`, two in `src/chains/evm.rs`, three in `src/chains/ton_cell.rs`, one in `src/ui.rs`. The `src/app.rs` line numbers shift as this branch edits that file; what must not change is the count of 12, and **no** line may point into `src/gpu/`, `src/verify.rs`, or `src/chains/mod.rs`.

  Do **not** run bare `cargo fmt` — this tree is not rustfmt-clean, so it would bury the branch under an unrelated whole-tree reformat and make Milestone 1 Task 1.8 Step 8's "no `src/app.rs`, `src/ui.rs`, or `src/chains/*`" permanently false. Format only what this task touched:

  ```sh
  cd /Users/shawnhopkinson/Rust/Vanaddy && rustfmt --edition 2021 src/gpu/mod.rs && rustfmt --edition 2021 --check src/gpu/mod.rs && echo "GPU-FMT-CLEAN"
  ```

  Then prove the two files that already carry pre-existing drift gained none. `rustfmt` **follows `mod` declarations**, so checking `src/chains/mod.rs` also formats `bitcoin.rs`, `evm.rs`, `monero.rs`, `solana.rs`, `ton.rs`, `ton_cell.rs` and `ton_mnemonic.rs` — 45 `Diff in` hunks on the clean tree, of which exactly 1 is in `mod.rs` itself. Filter to `mod.rs`'s own hunks so the number means what it says:

  ```sh
  cd /Users/shawnhopkinson/Rust/Vanaddy && rustfmt --edition 2021 --check src/chains/mod.rs 2>/dev/null | grep '^Diff in' | grep -c '/chains/mod.rs:' ; rustfmt --edition 2021 --check src/app.rs | grep -c '^Diff in'
  ```

  Expected: `GPU-FMT-CLEAN`, then `1` and `11` — the pre-existing per-file drift counts, unchanged. (`src/app.rs` declares no submodules, so its count needs no filter.) A higher *filtered* number means your insertion is not rustfmt-shaped; reshape it by hand rather than reaching for `cargo fmt`.

- [ ] **Step 9: Commit.**

  ```sh
  cd /Users/shawnhopkinson/Rust/Vanaddy && git add src/chains/mod.rs src/app.rs src/gpu/mod.rs && git commit -m "$(cat <<'EOF'
feat: thread GPU receiver and health through ChainKind::search

ChainKind::search gains gpu: Option<&GpuRx> and health: &GpuHealth. Only
the Evm arm routes to search_hybrid; Solana, Bitcoin, Ton and Monero call
the unchanged search::<C> and ignore both. The match is still evaluated
once per thread spawn and every arm monomorphized -- no dyn dispatch.

start_search passes None for now; Milestone 6 replaces the locally built
Arc<GpuHealth> with App's own cell and supplies a live receiver.

search_counts_whole_batches_and_honours_stop is untouched: it calls the
free function search::<Solana>, whose signature did not change.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
EOF
)"
  ```

---

### Task 5.2: The GPU drain — chunked stop checks, counter increments, verify-gated emit

**Files:**
- Modify: `/Users/shawnhopkinson/Rust/Vanaddy/src/chains/mod.rs` (add `GPU_CHUNK_BATCHES`, `drain_gpu_block`, `emit_gpu_match`; complete `search_hybrid`'s body)
- Modify (preflight only, if needed): `/Users/shawnhopkinson/Rust/Vanaddy/src/gpu/mod.rs` (`SeedBlock` construction API)
- Test: `/Users/shawnhopkinson/Rust/Vanaddy/src/chains/mod.rs` (`mod tests`)

**Interfaces:**
- Consumes: `pub struct GpuCandidate { pub entropy: [u8; 16], pub seed: [u8; 64] }`; `impl SeedBlock { pub fn len(&self) -> usize; pub fn chunks(&self, n: usize) -> std::slice::Chunks<'_, GpuCandidate>; }` (Task 1.4); `impl SeedBlock { pub(crate) fn with_capacity(n: usize) -> Self; pub(crate) fn push(&mut self, candidate: GpuCandidate); }` (Task 1.4 — consumed here, never re-declared; Step 2 adds it only if Milestone 1 was left incomplete); `pub fn verify_gpu<C: Bip39GpuChain>(entropy: &[u8;16], gpu_addr: &C::AddressBytes) -> Option<(C::AddressBytes, C::SecretRaw, String, Verified)>`; `impl GpuHealth { pub fn raise(&self, r: GpuDisableReason); }`; `GpuDisableReason::VerifyMismatch { address: String }`; `Match { .., pub verified: crate::verify::Verified }`; `trait Bip39GpuChain: Chain { fn from_gpu_seed(seed: &[u8; 64]) -> (Self::AddressBytes, Self::SecretRaw); .. }`; `const GPU_CHUNK_BATCHES: usize = 16` (Task 2.4); `fn drain_gpu_block<C: Bip39GpuChain>(block: &crate::gpu::SeedBlock, matcher: &Matcher, stop: &AtomicBool, counter: &AtomicU64, tx: &Sender<Match>, health: &crate::gpu::GpuHealth)` (Task 2.4); `fn emit_gpu_match<C: Bip39GpuChain>(tx: &Sender<Match>, entropy: &[u8;16], gpu_addr: &C::AddressBytes, health: &GpuHealth)` (Task 2.4); `pub fn search_hybrid<C: Bip39GpuChain>(matcher: &Matcher, stop: &AtomicBool, counter: &AtomicU64, tx: &Sender<Match>, gpu: Option<&crate::gpu::GpuRx>, health: &crate::gpu::GpuHealth)` (Task 2.4 — Task 5.1 Step 4 already routes `ChainKind::Evm` to it, so it is live code before this task starts)
- Produces: no new production code. Task 2.4 is the authoritative producer of `GPU_CHUNK_BATCHES`, `drain_gpu_block`, `emit_gpu_match` and `search_hybrid`; Task 1.4 of `SeedBlock::with_capacity` and `SeedBlock::push`. This task's only unconditional output is the new test `gpu_drain_stop_granularity_is_one_chunk` in `src/chains/mod.rs`'s `mod tests`. Steps 2 and 5-7 add production code **only** where the Step 1 / Step 2 preflight greps show Milestone 1 or Milestone 2 was left incomplete.

---

- [ ] **Step 1: Preflight — establish which of the three functions already exist.**

  ```sh
  cd /Users/shawnhopkinson/Rust/Vanaddy
  grep -n "GPU_CHUNK_BATCHES\|fn drain_gpu_block\|fn emit_gpu_match\|fn search_hybrid" src/chains/mod.rs
  ```

  Milestone 2 Task 2.4 Step 8 already landed all four of `GPU_CHUNK_BATCHES`, `search_hybrid`, `drain_gpu_block` and `emit_gpu_match`, so all four greps should hit. The code in **Steps 5-7** below is *functionally identical* to Task 2.4 Step 8, but two explanatory comments are worded differently: Task 2.4's `drain_gpu_block` carries a `// The GPU seed is UNTRUSTED and is used only to FILTER.` line that the copy in Step 5 omits, and the `Some`-arm comment inside `emit_gpu_match` differs in wording and line count between the two texts. Where a function already exists, confirm the **executable code** matches and change nothing — do **not** rewrite its comments to match this text, and do **not** read the comment difference as evidence that Task 2.4 drifted. Where a function does not exist — Task 2.4 was left incomplete — add it exactly as given. Do not "improve" the text while transcribing it: any divergence shows up as new rustfmt drift or a new clippy diagnostic and breaks Step 10's gate.

  Task 2.4 Step 7 also added `use crate::gpu::{GpuDisableReason, GpuHealth};` to the imports at the top of `src/chains/mod.rs`. **Leave that import in place** — `emit_gpu_match` in Step 6 refers to both names unqualified and depends on it. Fully qualifying them instead would leave the import unused and emit `warning: unused imports`, failing Step 10's comparison.

- [ ] **Step 2: Preflight — give `SeedBlock` a construction API if it lacks one.**

  ```sh
  cd /Users/shawnhopkinson/Rust/Vanaddy && grep -n "fn with_capacity\|fn push" src/gpu/mod.rs
  ```

  If both appear, change nothing. If either is missing, append this second `impl` block to `/Users/shawnhopkinson/Rust/Vanaddy/src/gpu/mod.rs`, immediately after the existing `impl SeedBlock { .. }`:

  ```rust
  impl SeedBlock {
      /// Construction-only API, used by the producer and by tests that build a
      /// block from `ring`-derived seeds. `SeedBlock` still exposes no way to
      /// reorder, filter, or sort its contents after the fact — invariant 4:
      /// phrase <-> seed pairing is established by exactly one `zip` and is
      /// never disturbed afterwards.
      pub(crate) fn with_capacity(n: usize) -> Self {
          SeedBlock(Vec::with_capacity(n))
      }

      pub(crate) fn push(&mut self, candidate: GpuCandidate) {
          self.0.push(candidate);
      }
  }
  ```

- [ ] **Step 3: Write the failing test.**

  **Milestone 2 Task 2.4 Step 4 already added a test called `gpu_drain_honours_stop_mid_block` to this same `mod tests`** — it drains a block whose `stop` is already `true` and asserts nothing was counted. Do **not** replace, rename, or delete it: both tests must exist. The test below is its concurrent counterpart, letting a drain start and then tripping `stop` part-way through, so it takes a different name, `gpu_drain_stop_granularity_is_one_chunk`. Two `fn` items with the same name in one module is `error[E0428]: the name ... is defined multiple times`.

  Append to `mod tests` in `/Users/shawnhopkinson/Rust/Vanaddy/src/chains/mod.rs`, after `chain_kind_search_with_no_gpu_source_is_unchanged`:

  ```rust
      /// A 512-candidate GPU block is ~25.9 ms of work. Ctrl+C must not have to
      /// wait for it, so `drain_gpu_block` re-reads `stop` at every
      /// `C::BATCH * GPU_CHUNK_BATCHES` = 64-candidate boundary (~3.2 ms), and
      /// counts only chunks it actually finished. Milestone 2's
      /// `gpu_drain_honours_stop_mid_block` covers the already-stopped case;
      /// this covers stopping part-way through a block.
      #[test]
      fn gpu_drain_stop_granularity_is_one_chunk() {
          use crate::gpu::{GpuCandidate, GpuHealth, SeedBlock};

          // 4096 candidates = 64 chunks. Far more than can be drained between
          // the moment the first chunk lands and the moment the poll loop below
          // notices it and sets stop.
          const N: usize = 4096;
          let mut block = SeedBlock::with_capacity(N);
          for i in 0..N {
              let mut seed = [0u8; 64];
              for (j, b) in seed.iter_mut().enumerate() {
                  *b = (i as u32).wrapping_mul(2_654_435_761).wrapping_add(j as u32) as u8;
              }
              let mut entropy = [0u8; 16];
              entropy[..4].copy_from_slice(&(i as u32).to_le_bytes());
              block.push(GpuCandidate { entropy, seed });
          }

          // 8 hex chars is 1 in 2^32: nothing in this block can match, so the
          // verify gate is never entered and no Match is ever emitted.
          let matcher = Matcher::new("ffffffff".into(), String::new(), false, ChainKind::Evm);
          let stop = AtomicBool::new(false);
          let counter = AtomicU64::new(0);
          let health = GpuHealth::default();
          let (tx, rx) = mpsc::channel();
          let chunk = (evm::Evm::BATCH * GPU_CHUNK_BATCHES) as u64;
          assert_eq!(chunk, 64, "chunk is BATCH(4) * GPU_CHUNK_BATCHES(16)");

          thread::scope(|s| {
              s.spawn(|| {
                  drain_gpu_block::<evm::Evm>(&block, &matcher, &stop, &counter, &tx, &health)
              });
              let deadline = std::time::Instant::now() + Duration::from_secs(20);
              while counter.load(Ordering::Relaxed) < chunk
                  && std::time::Instant::now() < deadline
              {
                  thread::sleep(Duration::from_millis(1));
              }
              stop.store(true, Ordering::Relaxed);
          });

          let n = counter.load(Ordering::Relaxed);
          assert!(n >= chunk, "drain must count at least one whole chunk, got {n}");
          assert!(n < N as u64, "stop must abandon the rest of the block, got {n} of {N}");
          assert_eq!(n % chunk, 0, "counter advances one whole chunk at a time, got {n}");
          assert_eq!(
              health.seeds_delivered.load(Ordering::Relaxed),
              n,
              "seeds_delivered must track the counter exactly"
          );
          assert!(!health.disable.load(Ordering::Relaxed), "a clean drain raises no fault");
          assert_eq!(health.verify_rejections.load(Ordering::Relaxed), 0);
          drop(tx);
          assert!(rx.try_recv().is_err(), "an 8-hex-char prefix cannot match");
      }
  ```

- [ ] **Step 4: Run the test and prove it bites.**

  ```sh
  cd /Users/shawnhopkinson/Rust/Vanaddy && cargo test gpu_drain_stop_granularity_is_one_chunk
  ```

  Which of three outcomes you get depends on what Step 1 found:

  - **`drain_gpu_block` / `GPU_CHUNK_BATCHES` do not exist yet** (Task 2.4 left incomplete):
    `error[E0425]: cannot find function `drain_gpu_block` in this scope` and/or
    `error[E0425]: cannot find value `GPU_CHUNK_BATCHES` in this scope`. Go on to Step 5.
  - **A body exists without the chunked stop check:** the test compiles and panics with
    `stop must abandon the rest of the block, got 4096 of 4096`. Go on to Step 5.
  - **Task 2.4 landed the chunked stop check, so the test passes on its first run.** This is
    the expected outcome on a complete Milestone 2 — and a test that passes immediately has
    proved nothing yet, so make it fail on purpose. In `drain_gpu_block`, temporarily delete
    the three-line guard:

    ```rust
            if stop.load(Ordering::Relaxed) {
                return; // only what was checked has been counted
            }
    ```

    Re-run the command above and confirm it now panics with
    `stop must abandon the rest of the block, got 4096 of 4096`. Then restore the guard
    exactly as printed above, confirm `git diff src/chains/mod.rs` shows only your new test,
    and go on to Step 5.

  Do not proceed until you have seen one of those three failures.

- [ ] **Step 5: Add `GPU_CHUNK_BATCHES` and `drain_gpu_block` — ONLY if Step 1 found none.**

  **If the Step 1 grep hit `fn drain_gpu_block`** — the expected outcome on a complete Milestone 2 — Task 2.4 already landed it. Read its body, confirm the **executable code** matches the block below statement for statement, and move on. Do **not** delete it, do **not** paste this text over it, and do **not** rewrite its comments to match: Task 2.4's copy carries a `// The GPU seed is UNTRUSTED and is used only to FILTER.` line that the text below omits, and Step 1 already told you that difference is expected, not drift.

  **Only if the Step 1 grep found nothing** — Task 2.4 was left incomplete — add the text below to `/Users/shawnhopkinson/Rust/Vanaddy/src/chains/mod.rs`, immediately after the `search_hybrid` function and before `#[cfg(test)] mod tests`.

  **`const GPU_CHUNK_BATCHES` is the exception: do not move it and do not add a second one.** Milestone 2 Task 2.4 Step 8 inserts the const *before* `search_hybrid` (immediately after the closing `}` of `pub fn search`), whereas the block below prints it *after* — the two placements cannot coincide, and two `const GPU_CHUNK_BATCHES` items in one module is `error[E0428]: the name \`GPU_CHUNK_BATCHES\` is defined multiple times`. So: if the Step 1 grep found `GPU_CHUNK_BATCHES` already in the file, leave that declaration exactly where it sits and **omit the doc comment and `const` line from the block below**, pasting only `fn drain_gpu_block`. Add the const only if Step 1 found none.

  ```rust
  /// Stop check granularity inside a GPU block: 16 × C::BATCH = 64 candidates
  /// ≈ 3.2 ms at the measured 50.5 µs tail — comparable to the CPU path's
  /// ~1.3 ms, versus 25.9 ms for a whole 512-block.
  const GPU_CHUNK_BATCHES: usize = 16;

  fn drain_gpu_block<C: Bip39GpuChain>(
      block: &crate::gpu::SeedBlock,
      matcher: &Matcher,
      stop: &AtomicBool,
      counter: &AtomicU64,
      tx: &Sender<Match>,
      health: &crate::gpu::GpuHealth,
  ) {
      debug_assert_eq!(block.len() % C::BATCH.max(1), 0);
      for chunk in block.chunks(C::BATCH.max(1) * GPU_CHUNK_BATCHES) {
          if stop.load(Ordering::Relaxed) {
              return; // only what was checked has been counted
          }
          for cand in chunk {
              let (addr, _gpu_secret) = C::from_gpu_seed(&cand.seed);
              if C::matches_raw(matcher, &addr) {
                  emit_gpu_match::<C>(tx, &cand.entropy, &addr, health);
              }
          }
          counter.fetch_add(chunk.len() as u64, Ordering::Relaxed);
          health
              .seeds_delivered
              .fetch_add(chunk.len() as u64, Ordering::Relaxed);
      }
  }
  ```

  Note what is *not* here: no `to_lowercase`, no `format!`, no `Vec`, no `String` on the per-candidate path. `C::from_gpu_seed` returns a stack `([u8; 20], SecretKey)` and `C::matches_raw` compares bytes against the pre-computed `Matcher`. Allocation happens only inside `emit_gpu_match`, on the ~1-in-16^n branch.

- [ ] **Step 6: Add `emit_gpu_match` — ONLY if Step 1 found none.**

  **If the Step 1 grep hit `fn emit_gpu_match`** — the expected outcome on a complete Milestone 2 — Task 2.4 already landed it. Confirm the **executable code** matches the block below statement for statement, and move on. Do **not** delete it and do **not** paste this text over it: the `Some`-arm comment differs in wording and line count between Task 2.4's copy and the text below, and reconciling those comments is exactly the rewrite Step 1 forbids.

  **Only if the Step 1 grep found nothing** — Task 2.4 was left incomplete — add the text below to `/Users/shawnhopkinson/Rust/Vanaddy/src/chains/mod.rs`, immediately after `drain_gpu_block`.

  ```rust
  fn emit_gpu_match<C: Bip39GpuChain>(
      tx: &Sender<Match>,
      entropy: &[u8; 16],
      gpu_addr: &C::AddressBytes,
      health: &GpuHealth,
  ) {
      match crate::verify::verify_gpu::<C>(entropy, gpu_addr) {
          Some((addr, secret, phrase, proof)) => {
              // The address, secret and phrase written here are the CPU-derived
              // ones, never the GPU's. A wrong GPU seed can cost a missed match;
              // it can never put an unspendable row in the CSV.
              let _ = tx.send(Match {
                  chain: C::LABEL.to_string(),
                  address: C::encode_address(&addr),
                  secret_hex: C::encode_secret(&secret),
                  mnemonic: phrase,
                  verified: proof,
              });
          }
          None => {
              // A GPU seed that MATCHED the pattern but does not re-derive is a
              // GPU fault, never a false positive. Disable the GPU, keep the CPU
              // search alive, and surface it. The candidate is dropped — it is
              // provably not a wallet anyone can open, so there is nothing to save.
              health.verify_rejections.fetch_add(1, Ordering::Relaxed);
              health.raise(GpuDisableReason::VerifyMismatch {
                  address: C::encode_address(gpu_addr),
              });
          }
      }
  }
  ```

- [ ] **Step 7: Complete `search_hybrid`'s body — ONLY if Step 1 found none.**

  **If the Step 1 grep hit `fn search_hybrid`** — the expected outcome on a complete Milestone 2 — Task 2.4 already landed it, and Task 5.1 Step 4 already routes `ChainKind::Evm` to it, so it is live code the suite is exercising. Confirm the **executable code** matches the block below statement for statement, and move on. Do **not** replace it and do **not** rewrite its comments.

  **Only if the Step 1 grep found nothing** — Task 2.4 was left incomplete — add the text below to `/Users/shawnhopkinson/Rust/Vanaddy/src/chains/mod.rs`, after the closing `}` of `pub fn search` and before the `GPU_CHUNK_BATCHES` / `drain_gpu_block` block. The `try_recv` is deliberately non-blocking: a worker that finds the queue empty falls straight through to a CPU batch, so the CPU/GPU split self-balances against whatever the GPU is actually delivering — which was measured collapsing 2-4× whenever the desktop compositor got busy.

  ```rust
  /// The EVM search loop when a GPU producer may be feeding it. `try_recv` is
  /// non-blocking and therefore self-balancing: when the GPU is fast the workers
  /// drain it, when the GPU stalls (compositor contention drops it 2–4×) they fall
  /// straight through to the CPU batch with no static split to get wrong.
  pub fn search_hybrid<C: Bip39GpuChain>(
      matcher: &Matcher,
      stop: &AtomicBool,
      counter: &AtomicU64,
      tx: &Sender<Match>,
      gpu: Option<&crate::gpu::GpuRx>,
      health: &crate::gpu::GpuHealth,
  ) {
      while !stop.load(Ordering::Relaxed) {
          if let Some(rx) = gpu {
              if !health.disable.load(Ordering::Relaxed) {
                  if let Ok(block) = rx.try_recv() {
                      drain_gpu_block::<C>(&block, matcher, stop, counter, tx, health);
                      continue; // block is zeroized on drop
                  }
              }
          }
          search_cpu_step::<C>(matcher, counter, tx);
      }
  }
  ```

  Both a `Disconnected` and an `Empty` receiver produce `Err`, so both fall through to `search_cpu_step` — a GPU thread that has exited never stalls a worker. `health.disable` is re-read every iteration, so a fault raised by `emit_gpu_match` on one worker stops every other worker from draining within one loop turn while leaving the CPU search running at full rate.

- [ ] **Step 8: Run the test and watch it pass.**

  ```sh
  cd /Users/shawnhopkinson/Rust/Vanaddy && cargo test gpu_drain_stop_granularity_is_one_chunk -- --nocapture
  ```

  Expected: `test chains::tests::gpu_drain_stop_granularity_is_one_chunk ... ok`. If it instead fails on `drain must count at least one whole chunk, got 0`, the 20 s deadline expired without a single chunk completing — that means `counter.fetch_add` is missing from the loop body, not that the machine is slow.

- [ ] **Step 9: Run the whole suite and prove the pinned test is untouched.**

  ```sh
  cd /Users/shawnhopkinson/Rust/Vanaddy && cargo test 2>&1 | tail -3
  ```

  Every test passes, including `search_counts_whole_batches_and_honours_stop`, this milestone's `chain_kind_search_with_no_gpu_source_is_unchanged` and `gpu_drain_stop_granularity_is_one_chunk`, and Milestone 2's four — `gpu_block_is_consumed_counted_and_cpu_verified`, `corrupted_gpu_seed_raises_fault_and_emits_nothing`, `gpu_drain_honours_stop_mid_block` and `search_with_no_gpu_source_is_unchanged` — which all still exist alongside the two new ones. Then:

  ```sh
  cd /Users/shawnhopkinson/Rust/Vanaddy
  # The pinned test must be byte-identical to this task's base commit.
  git show HEAD:src/chains/mod.rs \
    | sed -n '/fn search_counts_whole_batches_and_honours_stop/,/^    }$/p' > /tmp/pinned_before.txt
  sed -n '/fn search_counts_whole_batches_and_honours_stop/,/^    }$/p' \
    src/chains/mod.rs > /tmp/pinned_after.txt
  diff /tmp/pinned_before.txt /tmp/pinned_after.txt && echo "PINNED TEST UNTOUCHED"
  ```

  Expected: no `diff` output at all, followed by `PINNED TEST UNTOUCHED`.

  Do **not** substitute `cd /Users/shawnhopkinson/Rust/Vanaddy && git diff src/chains/mod.rs | grep -c "search_counts_whole_batches\|n % LANES as u64"` expecting `0`. This milestone says so twice more, in Task 5.1 Step 9 and in Task 5.3, and an earlier draft of this step contradicted both. That count turns on whether this task's edits happen to land within `git diff`'s three lines of leading context, so it passes or fails on incidental line proximity; and even when it does print `0` it has only shown that a string is absent from a diff, never that the pinned test is byte-identical. The `diff` above is the gate.

- [ ] **Step 10: Lint and format.**

  The clean tree is **not** clippy-clean; compare against the recorded baseline instead of demanding zero, and do not use `git stash` for it (`grep -c` exits non-zero on a `0` count, so the `git stash pop` in a `&&` chain may never run).

  ```sh
  cd /Users/shawnhopkinson/Rust/Vanaddy && touch src/main.rs && cargo clippy --all-targets 2>&1 | grep -- '-->' | sort | uniq -c
  ```

  Expected: exactly the same 12 lines Milestone 1 Task 1.8 Step 5 recorded — five in `src/app.rs`, one in `src/chains/bitcoin.rs`, two in `src/chains/evm.rs`, three in `src/chains/ton_cell.rs`, one in `src/ui.rs` — with **no** line pointing into `src/gpu/`, `src/verify.rs`, or `src/chains/mod.rs`. In particular there must be no new `unused imports` diagnostic: `emit_gpu_match` above deliberately names `GpuHealth` and `GpuDisableReason` unqualified so that Task 2.4's `use crate::gpu::{GpuDisableReason, GpuHealth};` stays live. (The nested `if let` / `if` / `if let` in `search_hybrid` does **not** trip `clippy::collapsible_if` on this crate: let-chains are a 2024-edition feature and `Cargo.toml` pins `edition = "2021"`. Verified against clippy 0.1.95.)

  Do **not** run bare `cargo fmt`. Format only what this task touched, and prove the pre-existing-drift file gained none:

  ```sh
  cd /Users/shawnhopkinson/Rust/Vanaddy && rustfmt --edition 2021 src/gpu/mod.rs && rustfmt --edition 2021 --check src/gpu/mod.rs && echo "GPU-FMT-CLEAN"
  ```

  `rustfmt` **follows `mod` declarations**, so checking `src/chains/mod.rs` also formats `bitcoin.rs`, `evm.rs`, `monero.rs`, `solana.rs`, `ton.rs`, `ton_cell.rs` and `ton_mnemonic.rs` — 45 `Diff in` hunks on the clean tree, of which exactly 1 is in `mod.rs` itself. Filter to `mod.rs`'s own hunks:

  ```sh
  cd /Users/shawnhopkinson/Rust/Vanaddy && rustfmt --edition 2021 --check src/chains/mod.rs 2>/dev/null | grep '^Diff in' | grep -c '/chains/mod.rs:' ; cargo test 2>&1 | tail -3
  ```

  Expected: `GPU-FMT-CLEAN`, then `1` — the pre-existing `src/chains/mod.rs` drift count, unchanged — then a green suite. A higher *filtered* count means your insertion is not rustfmt-shaped; reshape it by hand.

- [ ] **Step 11: Commit.**

  ```sh
  cd /Users/shawnhopkinson/Rust/Vanaddy && git add src/chains/mod.rs src/gpu/mod.rs && git commit -m "$(cat <<'EOF'
feat: drain GPU seed blocks in Rayon workers, verify-gated

search_hybrid try_recv's a SeedBlock per loop turn and falls through to a
CPU batch when the queue is empty, so the CPU/GPU split self-balances
against whatever the GPU is actually delivering -- measured collapsing
2-4x under compositor load.

drain_gpu_block re-reads stop every C::BATCH * GPU_CHUNK_BATCHES = 64
candidates (~3.2 ms) rather than once per 512-candidate block (~25.9 ms),
and increments counter and seeds_delivered only for chunks it finished:
abandoning on stop can never over-count.

emit_gpu_match routes every matching GPU candidate through
verify::verify_gpu. On rejection it raises VerifyMismatch -- the GPU goes
off for the process, the CPU search continues untouched, and the
candidate is dropped, since a seed that does not re-derive is provably
not a wallet anyone can open.

Hot loop stays allocation-free: from_gpu_seed returns stack values and
matches_raw compares bytes; String only on the ~1-in-16^n emit branch.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
EOF
)"
  ```

---

### Task 5.3: End-to-end gate — a live-GPU EVM search whose every CSV row re-derives

This is the milestone's real verification: a 1-character-prefix EVM search fed by the actual Metal producer from Milestone 4, with every emitted match written through the production CSV writer and then re-derived from its phrase alone. `App` does not spawn a GPU producer until Milestone 6, so the harness assembles the same pieces `start_search` will: a `crossbeam` channel, a `GpuEngine`, four workers in `search_hybrid`, and `append_match_row`.

**Files:**
- Test: `/Users/shawnhopkinson/Rust/Vanaddy/src/app.rs` (`mod tests`, currently lines 556-585)

**Interfaces:**
- Consumes: `pub fn search_hybrid<C: Bip39GpuChain>(..)` (Task 5.2); `impl GpuEngine { pub fn start(tx: Sender<Box<SeedBlock>>, health: Arc<GpuHealth>) -> GpuEngine; pub fn signal_stop(&self); pub fn is_finished(&self) -> bool; pub fn reap(self); }` (Milestone 4); `pub const CHANNEL_CAPACITY: usize = 32`; `fn append_match_row(path: &Path, m: &Match) -> io::Result<()>` (Milestone 2, private to `app`); `Evm::from_gpu_seed`; `crate::seed::derive_seed`
- Produces: no production code — a `#[ignore]`d integration gate

---

- [ ] **Step 1: Preflight — confirm the Milestone 3/4 surface and the dev-dependency are present.**

  ```sh
  cd /Users/shawnhopkinson/Rust/Vanaddy
  grep -n "fn start\|fn signal_stop\|fn is_finished\|fn reap" src/gpu/metal.rs
  grep -n "fn append_match_row" src/app.rs
  grep -n "tempfile\|crossbeam-channel" Cargo.toml
  ```

  All four `GpuEngine` methods, `append_match_row`, `tempfile` under `[dev-dependencies]` and `crossbeam-channel` under `[dependencies]` must appear. If any is missing, the milestone it belongs to is incomplete — stop and finish it first rather than working around it here.

- [ ] **Step 2: Write the gate test.**

  Append to `mod tests` in `/Users/shawnhopkinson/Rust/Vanaddy/src/app.rs`, after `start_stop_restart_does_not_leak_threads` and before the module's final `}`. It lives in `app.rs` rather than `chains/mod.rs` solely because `append_match_row` is private to `app`, and this gate must exercise the *production* CSV writer, not a copy of it.

  ```rust
      /// Milestone 5's end-to-end gate. A real EVM search with a 1-character
      /// prefix, fed by the real Metal producer, writing through the production
      /// CSV writer. Asserts three things at once:
      ///   1. the GPU path actually ran (otherwise this test proves nothing),
      ///   2. every CSV row re-derives from its phrase alone through `ring`,
      ///   3. the counter is honest — every candidate it counted was examined,
      ///      as whole 64-candidate GPU chunks plus whole 4-candidate CPU batches.
      #[test]
      #[ignore = "requires a Metal device and runs for ~5 s; run with --ignored"]
      #[cfg(all(target_os = "macos", target_arch = "aarch64", feature = "metal"))]
      fn hybrid_evm_search_with_live_gpu_emits_only_rederivable_matches() {
          use crate::chains::{evm::Evm, search_hybrid, Bip39GpuChain, Chain};
          use crate::gpu::{GpuEngine, GpuHealth, SeedBlock, CHANNEL_CAPACITY};
          use bip39::{Language, Mnemonic};

          let health = Arc::new(GpuHealth::default());
          let (gtx, grx) = crossbeam_channel::bounded::<Box<SeedBlock>>(CHANNEL_CAPACITY);
          let engine = GpuEngine::start(gtx, Arc::clone(&health));

          // One hex character: ~1 match in 16 candidates, so a few seconds of
          // searching produces thousands of rows to re-derive.
          let matcher = Matcher::new("a".into(), String::new(), false, crate::chains::ChainKind::Evm);
          let stop = AtomicBool::new(false);
          let counter = AtomicU64::new(0);
          let (tx, rx) = mpsc::channel();

          thread::scope(|s| {
              for _ in 0..4 {
                  let grx_w = grx.clone();
                  let health_w = Arc::clone(&health);
                  let tx_w = tx.clone();
                  let matcher_w = &matcher;
                  let stop_w = &stop;
                  let counter_w = &counter;
                  s.spawn(move || {
                      search_hybrid::<Evm>(
                          matcher_w,
                          stop_w,
                          counter_w,
                          &tx_w,
                          Some(&grx_w),
                          &health_w,
                      );
                  });
              }
              thread::sleep(Duration::from_secs(5));
              stop.store(true, Ordering::Relaxed);
          });

          engine.signal_stop();
          let deadline = std::time::Instant::now() + Duration::from_secs(5);
          while !engine.is_finished() && std::time::Instant::now() < deadline {
              thread::sleep(Duration::from_millis(10));
          }
          assert!(engine.is_finished(), "GPU producer did not stop within 5 s of signal_stop()");
          engine.reap();

          // 1. The GPU path actually ran.
          let delivered = health.seeds_delivered.load(Ordering::Relaxed);
          assert!(delivered > 0, "the GPU produced no seeds in 5 s - this test proves nothing");
          assert_eq!(delivered % 64, 0, "GPU seeds are counted one whole 64-chunk at a time, got {delivered}");
          assert!(
              !health.disable.load(Ordering::Relaxed),
              "GPU disabled mid-run: {:?}",
              health.take_reason()
          );
          assert_eq!(health.verify_rejections.load(Ordering::Relaxed), 0);

          // 3. The counter is honest.
          let n = counter.load(Ordering::Relaxed);
          assert!(n >= delivered, "counter {n} must include every one of {delivered} GPU candidates");
          assert_eq!(
              (n - delivered) % Evm::BATCH as u64,
              0,
              "the non-GPU remainder must be whole CPU batches, got {}",
              n - delivered
          );

          // 2. Every CSV row re-derives. Written through the production writer.
          let dir = tempfile::tempdir().unwrap();
          let csv = dir.path().join("vanity_wallets.csv");
          drop(tx);
          let mut rows = 0usize;
          while let Ok(m) = rx.try_recv() {
              append_match_row(&csv, &m).unwrap();
              rows += 1;
          }
          assert!(rows > 0, "a 1-character EVM prefix must produce matches in 5 s");

          let text = std::fs::read_to_string(&csv).unwrap();
          for line in text.lines() {
              let f: Vec<&str> = line.split(',').collect();
              assert_eq!(f.len(), 4, "row must be Chain,Address,Secret,Phrase: {line}");
              assert_eq!(f[0], "EVM");
              assert!(f[1].starts_with("0xa"), "row does not match the prefix: {line}");
              let m = Mnemonic::from_phrase(f[3], Language::English)
                  .unwrap_or_else(|e| panic!("CSV phrase is not a valid mnemonic ({e}): {line}"));
              let (addr, sk) = Evm::from_gpu_seed(&crate::seed::derive_seed(&m));
              assert_eq!(Evm::encode_address(&addr), f[1], "CSV address does not re-derive: {line}");
              assert_eq!(Evm::encode_secret(&sk), f[2], "CSV secret does not re-derive: {line}");
          }

          eprintln!(
              "counter={n}  gpu_seeds={delivered}  cpu_candidates={}  csv_rows={rows}",
              n - delivered
          );
      }
  ```

- [ ] **Step 3: Prove the gate bites — inject a fault, run, see it fail.**

  The one way this test can silently prove nothing is if the GPU never delivers and all the work comes from the CPU fallback. Confirm that assertion actually fires. In `/Users/shawnhopkinson/Rust/Vanaddy/src/chains/mod.rs`, inside `drain_gpu_block`, temporarily comment out the seeds_delivered line:

  ```rust
          counter.fetch_add(chunk.len() as u64, Ordering::Relaxed);
          // health
          //     .seeds_delivered
          //     .fetch_add(chunk.len() as u64, Ordering::Relaxed);
  ```

  Then:

  ```sh
  cd /Users/shawnhopkinson/Rust/Vanaddy && cargo test --release -- --ignored --nocapture hybrid_evm_search_with_live_gpu_emits_only_rederivable_matches
  ```

  Expected failure:

  ```
  thread '...' panicked at src/app.rs:
  the GPU produced no seeds in 5 s - this test proves nothing
  ```

- [ ] **Step 4: Revert the injected fault and run the gate for real.**

  Restore the lines in `drain_gpu_block` exactly:

  ```rust
          counter.fetch_add(chunk.len() as u64, Ordering::Relaxed);
          health
              .seeds_delivered
              .fetch_add(chunk.len() as u64, Ordering::Relaxed);
  ```

  Confirm nothing else drifted:

  ```sh
  cd /Users/shawnhopkinson/Rust/Vanaddy && git diff src/chains/mod.rs
  ```

  must be empty. Then:

  ```sh
  cd /Users/shawnhopkinson/Rust/Vanaddy && cargo test --release -- --ignored --nocapture hybrid_evm_search_with_live_gpu_emits_only_rederivable_matches
  ```

  Expected: `test app::tests::hybrid_evm_search_with_live_gpu_emits_only_rederivable_matches ... ok`, preceded by a line like

  ```
  counter=128000  gpu_seeds=66560  cpu_candidates=61440  csv_rows=7980
  ```

- [ ] **Step 5: Sanity-check the printed numbers by hand.**

  From the `eprintln!` line, confirm all four by arithmetic — a green test with implausible numbers is the failure mode this step exists to catch:

  1. `gpu_seeds` is a multiple of 64 and is a large fraction of `counter` (on an M1 expect roughly 40-60%; the design's honest hybrid figure is ~23,000-26,000 cand/s total over 5 s, so `counter` in the 100k-130k range).
  2. `cpu_candidates` = `counter - gpu_seeds` is a multiple of 4 (`Evm::BATCH` = `LANES`).
  3. `csv_rows` is near `counter / 16` — a 1-hex-character prefix. Within roughly ±10% for a sample this size. A `csv_rows` far below `counter/16` means candidates are being counted that were never examined, i.e. a dishonest counter.
  4. The test's own loop already re-derived all `csv_rows` rows; if any had disagreed the run would have panicked with the offending line.

- [ ] **Step 6: Run the full suite and prove the pinned test is untouched.**

  ```sh
  cd /Users/shawnhopkinson/Rust/Vanaddy && cargo test 2>&1 | tail -3
  ```

  All non-ignored tests pass and the ignored gate is reported as ignored. Then compare the pinned test's own body, byte for byte, against the base this milestone started from. Task 5.1 Step 9 and Task 5.2 Step 11 are the only commits since, and this task has not committed yet, so that base is `HEAD~2`:

  ```sh
  cd /Users/shawnhopkinson/Rust/Vanaddy
  # The pinned test must be byte-identical to the milestone base.
  git show HEAD~2:src/chains/mod.rs \
    | sed -n '/fn search_counts_whole_batches_and_honours_stop/,/^    }$/p' > /tmp/pinned_before.txt
  sed -n '/fn search_counts_whole_batches_and_honours_stop/,/^    }$/p' \
    src/chains/mod.rs > /tmp/pinned_after.txt
  diff /tmp/pinned_before.txt /tmp/pinned_after.txt && echo "PINNED TEST UNTOUCHED"
  ```

  Expected: no `diff` output at all, followed by `PINNED TEST UNTOUCHED` — across all of Milestone 5, `search_counts_whole_batches_and_honours_stop` and its `n % LANES == 0` assertion were never edited. Each `sed` range captures exactly the 16 lines of the test.

  Do **not** replace this with `git diff HEAD~2 -- src/chains/mod.rs | grep -c "search_counts_whole_batches\|n % LANES as u64"` expecting `0`. Task 5.1 Step 2 added a test that legitimately contains `n % LANES as u64` on two of its own lines (Task 5.2's added test does not, despite an earlier draft of this note claiming it did), so across this range that count is non-zero by design and tells you nothing about the pinned test. The `diff` above is the gate.

- [ ] **Step 7: Lint and format.**

  The clean tree is **not** clippy-clean; compare against the recorded baseline rather than demanding zero, and do not use `git stash` for it (`grep -c` exits non-zero on a `0` count, so the `git stash pop` in a `&&` chain may never run).

  ```sh
  cd /Users/shawnhopkinson/Rust/Vanaddy && touch src/main.rs && cargo clippy --all-targets 2>&1 | grep -- '-->' | sort | uniq -c
  ```

  Expected: exactly the same 12 lines Milestone 1 Task 1.8 Step 5 recorded — five in `src/app.rs`, one in `src/chains/bitcoin.rs`, two in `src/chains/evm.rs`, three in `src/chains/ton_cell.rs`, one in `src/ui.rs` — with **no** line pointing into `src/gpu/`, `src/verify.rs`, or `src/chains/mod.rs`.

  This task touches only `src/app.rs`, which already carries pre-existing drift, so do **not** run bare `cargo fmt`; prove instead that the gate test you appended added none:

  ```sh
  cd /Users/shawnhopkinson/Rust/Vanaddy && rustfmt --edition 2021 --check src/app.rs | grep -c '^Diff in' ; cargo test 2>&1 | tail -3
  ```

  Expected: `11` — the pre-existing `src/app.rs` drift count, unchanged — then a green suite. A higher number means the appended test is not rustfmt-shaped; reshape it by hand.

- [ ] **Step 8: Commit.**

  ```sh
  cd /Users/shawnhopkinson/Rust/Vanaddy && git add src/app.rs && git commit -m "$(cat <<'EOF'
test: end-to-end gate for a live-GPU EVM search

Assembles what start_search will assemble in Milestone 6 -- a crossbeam
channel, a real GpuEngine, four workers in search_hybrid -- runs a
1-character EVM prefix for 5 s, writes every match through the production
append_match_row, and re-derives every CSV row from its phrase alone via
ring.

Asserts the GPU path actually ran (seeds_delivered > 0, a multiple of the
64-candidate chunk), that the counter is honest (>= seeds_delivered, with
a remainder that is whole CPU batches), and that no row's address or
secret disagrees with its phrase.

#[ignore]d: needs a Metal device and ~5 s. Run with
  cargo test --release -- --ignored --nocapture hybrid_evm_search

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
EOF
)"
  ```

---

**Milestone 5 exit criteria**

- `cargo test` green, with `search_counts_whole_batches_and_honours_stop` passing and its source byte-identical to `src/chains/mod.rs:130-146` before this milestone.
- `chain_kind_search_with_no_gpu_source_is_unchanged` and `gpu_drain_stop_granularity_is_one_chunk` green — *alongside*, not in place of, Milestone 2's `search_with_no_gpu_source_is_unchanged` and `gpu_drain_honours_stop_mid_block`, which must both still exist and still pass.
- `cargo test --release -- --ignored --nocapture hybrid_evm_search_with_live_gpu_emits_only_rederivable_matches` green, with hand-checked counter arithmetic.
- `cargo clippy --all-targets 2>&1 | grep -- '-->' | sort | uniq -c` still prints exactly the 12 pre-existing lines Milestone 1 Task 1.8 Step 5 recorded, with none pointing into `src/gpu/`, `src/verify.rs`, or `src/chains/mod.rs`. No bare `cargo fmt` was ever run: `rustfmt --edition 2021 --check src/gpu/mod.rs` is silent, and the `^Diff in` counts are unchanged — `1` for `src/chains/mod.rs` when filtered to that file's own hunks (`… | grep '^Diff in' | grep -c '/chains/mod.rs:'`, because rustfmt follows `mod` declarations and reports 45 hunks across the whole `chains` tree), and `11` for `src/app.rs`, which declares no submodules and needs no filter.
- `App` still spawns no GPU producer — `start_search` passes `None`. Milestone 6 supplies the live receiver.
## Milestone 6 — App lifecycle

This milestone is the one that decides whether the TUI stays alive. Everything here
is written to one rule: **the UI thread never blocks and never lies.** It never joins
a GPU thread, `validate()` never refuses to start a search for a GPU reason, and a GPU
fault turns into a visible `Disabled` state within one 100 ms tick while the CPU search
keeps running at full CPU-only rate.

Before starting, confirm the tree is green and you are on the feature branch:

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy
git rev-parse --abbrev-ref HEAD    # must print: feat/metal-gpu-pbkdf2
cargo test
```

Line numbers below refer to the repository as it stands today. Milestones 2 and 5 already
edited `src/app.rs` and `src/chains/mod.rs`, so the numbers will have shifted — every step
gives the exact anchor text to search for, which has not.

---

### Formatting and lint policy — read this before the first step

**Never run bare `cargo fmt`.** The tree is not rustfmt-clean at the branch point:
`cargo fmt --check` reports 84 diffs across 14 files, so `cargo fmt` would bury
Milestone 6 under an unrelated whole-tree reformat and permanently falsify
Milestone 1 Task 1.8's whole-diff gate. Format by path instead.

**Never write "expect no warnings".** `cargo clippy --all-targets` on the clean
baseline is not warning-free — it emits exactly 12 diagnostics. Every gate in this
milestone asserts that the baseline is *unchanged*, not that it is empty.

Format only the files a task touched. `src/app.rs` and `src/ui.rs` carry
pre-existing rustfmt drift, so hand-match the surrounding style and verify you
added none:

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && rustfmt --edition 2021 --check src/app.rs | grep -c '^Diff in'
cd /Users/shawnhopkinson/Rust/Vanaddy && rustfmt --edition 2021 --check src/ui.rs | grep -c '^Diff in'
```

Expected: `11` for `src/app.rs` and `18` for `src/ui.rs` — the pre-existing counts.
Anything higher means your insertion is not rustfmt-shaped; fix it by hand.

`src/main.rs` *is* rustfmt-clean, but plain `rustfmt src/main.rs` follows its `mod`
declarations into the whole crate and would report all 84 tree-wide diffs. Always
check it with `skip_children`:

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && rustfmt --edition 2021 --check --config skip_children=true src/main.rs | grep -c '^Diff in'
```

Expected: `0`.

Use exactly that spelling. There is no `--skip-children` **flag**: this repo's
`rustfmt 1.9.0-stable` answers it with `Unrecognized option: 'skip-children'` on
*stderr*, exits 1, and writes nothing to stdout — so `| grep -c '^Diff in'`
prints the expected `0` whether `src/main.rs` is clean or catastrophically
malformed, and the gate passes *because* the command failed. `--config
skip_children=true` is a real gate: it prints `0` for the clean `src/main.rs` and
`11` for `src/app.rs`, which does have drift. Every `src/main.rs` gate in this
milestone uses the `--config` form; if you ever find one written as
`--skip-children`, it is checking nothing.

Files this branch created have no drift to preserve — format them in place:

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && rustfmt --edition 2021 src/gpu/*.rs src/verify.rs
```

The clippy gate is a delta against this exact baseline:

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo clippy --all-targets 2>&1 | grep -- '-->' | sort | uniq -c
```

Expected: exactly these 12 pre-existing lines and no others.

```
   1    --> src/app.rs:357:5
   1    --> src/app.rs:522:17
   1    --> src/app.rs:543:13
   1    --> src/app.rs:548:13
   1    --> src/chains/evm.rs:103:20
   1    --> src/chains/ton_cell.rs:385:25
   1    --> src/ui.rs:212:23
   1   --> src/app.rs:51:5
   1   --> src/chains/bitcoin.rs:16:33
   1   --> src/chains/evm.rs:96:24
   1   --> src/chains/ton_cell.rs:48:26
   1   --> src/chains/ton_cell.rs:54:19
```

The `src/app.rs` and `src/ui.rs` line numbers shift as this milestone edits those
files; the COUNT of 12 must not change, and **no line may point into `src/gpu/` or
`src/verify.rs`**. Fixing the pre-existing 12 is out of scope — it would touch four
frozen files for no functional reason and belongs in a separate change.

---

### Task 6.1: App GPU fields, `with_gpu_status`, the env lever, and `gpu_effective()`

**Files:**
- Modify: `/Users/shawnhopkinson/Rust/Vanaddy/src/app.rs` (imports at lines 1-13; `struct App` at lines 21-48; `App::new` at lines 51-74)
- Test: `/Users/shawnhopkinson/Rust/Vanaddy/src/app.rs` (`mod tests` at lines 556-585)

**Interfaces:**
- Consumes: `crate::gpu::{GpuStatus, GpuDisableReason, GpuHealth, GpuEngine, GpuRx}`; `impl Default for GpuHealth`; `crate::chains::ChainKind` (`PartialEq`, `src/chains/mod.rs:47`)
- Produces: `App::with_gpu_status(gpu_status: GpuStatus) -> App`; `App::gpu_effective(&self) -> bool`; `App` fields `pub gpu_status: GpuStatus`, `pub gpu_requested: bool`, `pub gpu_env_off: bool`, `pub validated_gpu: bool`, `pub gpu_health: Arc<GpuHealth>`, `pub gpu_rx: Option<GpuRx>`, `gpu_engines: Vec<GpuEngine>`; `pub fn gpu_env_off(vanaddy_gpu: Option<&str>, vanaddy_no_gpu: Option<&str>) -> bool` (the ONE env reader in the binary — Task 8.3 tests this function and adds none of its own)

- [ ] **Step 1: Write the failing test for `gpu_effective()`.** Open `/Users/shawnhopkinson/Rust/Vanaddy/src/app.rs` and add these two tests inside `mod tests` (after the existing `start_stop_restart_does_not_leak_threads`, before the closing `}` at line 585):

```rust
    #[test]
    fn gpu_effective_requires_user_device_and_evm() {
        use crate::gpu::{GpuDisableReason, GpuStatus};

        let ready = || GpuStatus::Ready { device: "Apple M1".to_string() };

        // The happy case: user wants it, a device exists, chain is EVM.
        // Set the status explicitly instead of trusting the constructor: the env
        // lever rewrites a `Ready` probe into `Disabled(UserOff)`, so a developer
        // with VANADDY_NO_GPU=1 exported in their shell must still see this test
        // exercise the happy path.
        let mut app = App::with_gpu_status(ready());
        app.gpu_status = ready();
        app.chain = crate::chains::ChainKind::Evm;
        app.gpu_requested = true;
        assert!(app.gpu_effective());

        // Initializing and Running are both "the GPU is live for this run".
        app.gpu_status = GpuStatus::Initializing;
        assert!(app.gpu_effective());
        app.gpu_status = GpuStatus::Running { device: "Apple M1".to_string() };
        assert!(app.gpu_effective());

        // User said no.
        app.gpu_status = ready();
        app.gpu_requested = false;
        assert!(!app.gpu_effective());

        // Wrong chain: the GPU pipeline is EVM-only.
        app.gpu_requested = true;
        app.chain = crate::chains::ChainKind::Solana;
        assert!(!app.gpu_effective());

        // No device.
        app.chain = crate::chains::ChainKind::Evm;
        app.gpu_status = GpuStatus::Unavailable("no Metal device".to_string());
        assert!(!app.gpu_effective());

        // Disabled is sticky: gpu_effective() must never resurrect a faulted GPU.
        app.gpu_status = GpuStatus::Disabled(GpuDisableReason::AuditMismatch { index: 5183 });
        assert!(!app.gpu_effective());
    }

    #[test]
    fn app_new_never_requests_a_gpu_it_has_not_probed() {
        // App::new() is the test/no-probe constructor. It must default to a
        // status that gpu_effective() rejects, so a test that forgets to set up
        // the GPU can never accidentally spawn a real one.
        let app = App::new();
        assert!(matches!(app.gpu_status, crate::gpu::GpuStatus::Unavailable(_)));
        assert!(!app.gpu_requested);
        assert!(!app.validated_gpu);
        assert!(app.gpu_rx.is_none());
        assert!(!app.gpu_effective());
    }
```

- [ ] **Step 2: Run the test and watch it fail to compile.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo test gpu_effective_requires_user_device_and_evm
```

Expected failure — a compile error, not a test failure:

```
error[E0599]: no function or associated item named `with_gpu_status` found for struct `App` in the current scope
error[E0599]: no method named `gpu_effective` found for struct `App` in the current scope
error[E0609]: no field `gpu_status` on type `App`
```

- [ ] **Step 3: Add the imports.** In `/Users/shawnhopkinson/Rust/Vanaddy/src/app.rs`, LEAVE the `use std::{...}` block exactly as Milestone 2 Task 2.5 Step 4 left it — it already carries `fs::{File, OpenOptions}`, `io` and `path::Path`, and `open_csv_secure(path: &Path) -> io::Result<File>`, `append_match_row(path: &Path, ...)` and every `Path::new(CSV_PATH)` call site will not compile without them (E0412/E0433). Add only the new `crate::gpu` line directly beneath it. For reference, the block must read:

```rust
use std::{
    fs::{File, OpenOptions},
    io,
    path::Path,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc, Arc,
    },
    time::Instant,
};

use crate::gpu::{GpuEngine, GpuHealth, GpuRx, GpuStatus};
```

- [ ] **Step 4: Add the GPU fields to `struct App`.** In the same file, insert these fields immediately after `pub thread_pool: Option<rayon::ThreadPool>,` (line 47), before the closing `}` of `struct App`:

```rust

    // ---- GPU offload (EVM only). See docs/superpowers/specs/2026-08-26-metal-gpu-pbkdf2-design.md
    /// From `GpuEngine::probe()` at startup; promoted to `Running`/`Disabled`
    /// by `drain_matches`. This is the single source of truth the TUI renders.
    pub gpu_status: GpuStatus,
    /// The form toggle. Defaults to "on" iff the probe found a device and the
    /// env lever did not veto it.
    pub gpu_requested: bool,
    /// `VANADDY_GPU=0` or `VANADDY_NO_GPU=1` was set. Env ALWAYS wins over the
    /// form; kept as a field so the TUI can say *why* the toggle is stuck off.
    pub gpu_env_off: bool,
    /// Mirrors `validated_thread_count`: the decision `validate()` made, frozen
    /// so `start_search` acts on what the user saw, not on a status that may
    /// have changed since.
    pub validated_gpu: bool,
    /// Shared fault cell. Written by the producer thread and by Rayon workers,
    /// read by `drain_matches` on the UI tick. Never a Mutex on this path.
    pub gpu_health: Arc<GpuHealth>,
    /// App's own clone of the seed channel. Dropping it is shutdown wake-path
    /// #2: once App and every worker have dropped their clones, a producer that
    /// missed the stop flag still exits on `Disconnected`.
    pub gpu_rx: Option<GpuRx>,
    /// Parked engines awaiting reap. NEVER joined on the UI thread — see
    /// `stop_search` and `shutdown_gpu`.
    gpu_engines: Vec<GpuEngine>,
```

- [ ] **Step 5: Add the env lever helper — the ONLY one in the binary.** In the same file, insert this free function immediately before `pub fn detect_optimal_threads()` (line 319):

```rust
/// Rollback lever #2: `VANADDY_GPU=0` (equivalently `VANADDY_NO_GPU=1`) turns the
/// GPU off with no rebuild. Env always wins over the TUI toggle, so an operator
/// can kill the feature on a machine without editing anything.
///
/// Pure over the two values rather than reading the environment itself: `cargo
/// test` runs every test as a thread in ONE process, so a test that mutated the
/// process environment would race every other test.
///
/// `VANADDY_GPU` is value-based because a user types `VANADDY_GPU=0`.
/// `VANADDY_NO_GPU` is presence-based because `gpu_for_test` in
/// `src/gpu/metal.rs` already gates on `var_os("VANADDY_NO_GPU").is_some()`.
pub fn gpu_env_off(vanaddy_gpu: Option<&str>, vanaddy_no_gpu: Option<&str>) -> bool {
    if vanaddy_no_gpu.is_some() {
        return true;
    }
    match vanaddy_gpu {
        Some(v) => matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "0" | "off" | "false" | "no"
        ),
        None => false,
    }
}
```

This is the single env reader for the whole binary. Task 8.3 writes a red/green
pair against *this* function and adds no second implementation and no env code in
`main()` — `App::with_gpu_status` (Step 6) already applies the lever.

- [ ] **Step 6: Rewrite `App::new` as a thin wrapper over `with_gpu_status`.** Replace the whole of `App::new` (lines 51-74, from `pub fn new() -> Self {` through its closing `}`) with:

```rust
    /// The no-probe constructor: used by tests and by any caller that has not
    /// run `GpuEngine::probe()`. Deliberately yields a status that
    /// `gpu_effective()` rejects, so nothing can spawn a GPU by accident.
    pub fn new() -> Self {
        App::with_gpu_status(GpuStatus::Unavailable("not probed".to_string()))
    }

    /// The real constructor. `main()` probes for a Metal device BEFORE entering
    /// raw mode and hands the result in here.
    pub fn with_gpu_status(gpu_status: GpuStatus) -> Self {
        let recommended_threads = detect_optimal_threads();
        // The one env read in the binary. The local is deliberately NOT named
        // `gpu_env_off`: that would shadow the function in the value namespace
        // for the rest of this body.
        let env_off = gpu_env_off(
            std::env::var("VANADDY_GPU").ok().as_deref(),
            std::env::var("VANADDY_NO_GPU").ok().as_deref(),
        );
        // Default the toggle on only when a device actually exists. `Ready` is
        // the post-probe resting state; anything else means there is nothing to
        // turn on.
        let gpu_requested = !env_off && matches!(gpu_status, GpuStatus::Ready { .. });
        let mut app = App {
            state: AppState::Configuring,
            should_quit: false,
            active_field: 0,
            chain: ChainKind::Solana,
            match_position: MatchPosition::StartsWith,
            vanity_prefix: String::new(),
            vanity_suffix: String::new(),
            case_sensitive: false,
            thread_count: recommended_threads.to_string(),
            validated_thread_count: 0,
            error_message: None,
            show_help: false,
            matches: Vec::new(),
            selected_match: 0,
            counter: Arc::new(AtomicU64::new(0)),
            start_time: None,
            stop: Arc::new(AtomicBool::new(false)),
            rx: None,
            thread_pool: None,
            gpu_status,
            gpu_requested,
            gpu_env_off: env_off,
            validated_gpu: false,
            gpu_health: Arc::new(GpuHealth::default()),
            gpu_rx: None,
            gpu_engines: Vec::new(),
        };
        // Make the veto visible. A `Ready` probe the environment vetoed becomes
        // `Disabled(UserOff)`, so the config row can say *why* the toggle refuses
        // to turn on — this is the ` GPU:      [disabled — UserOff]` row Task 8.3
        // Step 9 checks for. ONLY `Ready` is rewritten: when there was no device
        // to begin with, `Unavailable(..)` is the more informative status and
        // must survive.
        if env_off && matches!(app.gpu_status, GpuStatus::Ready { .. }) {
            app.gpu_status = GpuStatus::Disabled(crate::gpu::GpuDisableReason::UserOff);
        }
        app
    }
```

- [ ] **Step 7: Add `gpu_effective()`.** In the same file, insert this method immediately after `pub fn field_count(&self) -> usize { ... }` (which ends at line 82):

```rust
    /// The GPU actually runs iff: the user wants it, a device exists and has not
    /// faulted, and the chain is EVM.
    ///
    /// ADVISORY ONLY. `validate()` never returns `Err` because this is false —
    /// the CPU path is complete on its own, and this value goes stale the moment
    /// a fault is raised mid-run. Blocking a search on it would strand the user
    /// in the config screen with a toggle they cannot satisfy.
    pub fn gpu_effective(&self) -> bool {
        self.gpu_requested
            && matches!(
                self.gpu_status,
                GpuStatus::Ready { .. } | GpuStatus::Initializing | GpuStatus::Running { .. }
            )
            && self.chain == ChainKind::Evm
    }
```

- [ ] **Step 8: Run both tests and watch them pass.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo test gpu_effective_requires_user_device_and_evm app_new_never_requests_a_gpu_it_has_not_probed
```

Expect `test result: ok. 2 passed`.

- [ ] **Step 9: Run the whole suite and the milestone gate.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo test
cd /Users/shawnhopkinson/Rust/Vanaddy && rustfmt --edition 2021 --check src/app.rs | grep -c '^Diff in'
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo clippy --all-targets 2>&1 | grep -- '-->' | sort | uniq -c
```

Expected: the suite passes, `11` (the pre-existing `src/app.rs` drift count), and exactly the 12 baseline
clippy lines listed in the milestone preamble — no new line, and none pointing
into `src/gpu/` or `src/verify.rs`. Never run bare `cargo fmt`.

- [ ] **Step 10: Commit.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && git add -A && git commit -F- <<'EOF'
feat(gpu): App GPU fields, with_gpu_status, and gpu_effective()

App carries the probe result, the form toggle, the env lever, the shared
health cell, its own seed-channel clone, and the parked-engine list.
gpu_effective() is advisory: it is what start_search consults, never a
reason validate() can refuse to start a search.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
EOF
```

---

### Task 6.2: `validate()`'s advisory GPU line

**Files:**
- Modify: `/Users/shawnhopkinson/Rust/Vanaddy/src/app.rs` (`validate` at lines 174-212; the thread-count tail at lines 204-211)
- Test: `/Users/shawnhopkinson/Rust/Vanaddy/src/app.rs` (`mod tests`)

**Interfaces:**
- Consumes: `App::gpu_effective(&self) -> bool`; `crate::gpu::{GpuStatus, GpuDisableReason}`
- Produces: `App::validate` sets `self.validated_gpu` and still returns `Ok(())` for every GPU state

- [ ] **Step 1: Write the failing test.** Add this test inside `mod tests` in `/Users/shawnhopkinson/Rust/Vanaddy/src/app.rs`:

```rust
    #[test]
    fn validate_never_returns_err_for_a_gpu_reason() {
        use crate::gpu::{GpuDisableReason, GpuStatus};

        let mut app = App::with_gpu_status(GpuStatus::Ready { device: "Apple M1".to_string() });
        // Pin the status: the constructor's env lever rewrites a `Ready` probe
        // into `Disabled(UserOff)`, and this test must not depend on the
        // developer's shell.
        app.gpu_status = GpuStatus::Ready { device: "Apple M1".to_string() };
        app.chain = crate::chains::ChainKind::Evm;
        app.vanity_prefix = "abcd".into();
        app.thread_count = "2".into();

        // GPU on and healthy: validated_gpu latches true.
        app.gpu_requested = true;
        assert!(app.validate().is_ok());
        assert!(app.validated_gpu);

        // GPU requested but the device faulted mid-session. This is the case a
        // naive implementation turns into Err and locks the user out of the app.
        app.gpu_status = GpuStatus::Disabled(GpuDisableReason::VerifyMismatch {
            address: "0x0000000000000000000000000000000000000000".to_string(),
        });
        assert!(app.validate().is_ok(), "a faulted GPU must never block a CPU search");
        assert!(!app.validated_gpu);

        // GPU requested on a non-EVM chain: still fine, still CPU-only.
        app.gpu_status = GpuStatus::Ready { device: "Apple M1".to_string() };
        app.chain = crate::chains::ChainKind::Solana;
        app.vanity_prefix = "abcd".into();
        assert!(app.validate().is_ok(), "EVM-only offload must never block another chain");
        assert!(!app.validated_gpu);

        // No device at all.
        app.chain = crate::chains::ChainKind::Evm;
        app.gpu_status = GpuStatus::Unavailable("no Metal device".to_string());
        assert!(app.validate().is_ok());
        assert!(!app.validated_gpu);

        // A real, non-GPU error still errors. The advisory line must not have
        // swallowed the thread-count validation.
        app.thread_count = "0".into();
        assert!(app.validate().is_err(), "thread-count validation is unaffected");
    }
```

- [ ] **Step 2: Run it and watch it fail.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo test validate_never_returns_err_for_a_gpu_reason
```

Expected failure (the field is never set, so it stays `false` from the constructor):

```
thread 'app::tests::validate_never_returns_err_for_a_gpu_reason' panicked at src/app.rs:...
assertion failed: app.validated_gpu
```

- [ ] **Step 3: Add the advisory line to `validate()`.** In `/Users/shawnhopkinson/Rust/Vanaddy/src/app.rs`, find the tail of `validate` (lines 204-211):

```rust
        let max_threads = num_cpus::get().max(1) * 2;
        let count = self.thread_count.parse::<usize>().map_err(|_| "Invalid thread count".to_string())?;
        if count == 0 || count > max_threads {
            return Err(format!("Threads must be 1-{}", max_threads));
        }
        self.validated_thread_count = count;

        Ok(())
```

and replace it with:

```rust
        let max_threads = num_cpus::get().max(1) * 2;
        let count = self.thread_count.parse::<usize>().map_err(|_| "Invalid thread count".to_string())?;
        if count == 0 || count > max_threads {
            return Err(format!("Threads must be 1-{}", max_threads));
        }
        self.validated_thread_count = count;

        // ADVISORY. This line records the GPU decision; it CANNOT fail the
        // validation. Every GPU state — no device, wrong chain, faulted this
        // session, vetoed by VANADDY_GPU=0 — resolves to a CPU-only search that
        // starts normally. Returning Err here would let a stale toggle or a
        // mid-run fault trap the user in the config screen with no way to start,
        // which is strictly worse than losing the acceleration.
        self.validated_gpu = self.gpu_effective();

        Ok(())
```

- [ ] **Step 4: Run the test and watch it pass.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo test validate_never_returns_err_for_a_gpu_reason
```

Expect `test result: ok. 1 passed`.

- [ ] **Step 5: Run the whole suite and the milestone gate, then commit.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo test
cd /Users/shawnhopkinson/Rust/Vanaddy && rustfmt --edition 2021 --check src/app.rs | grep -c '^Diff in'
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo clippy --all-targets 2>&1 | grep -- '-->' | sort | uniq -c
```

Expected: the suite passes, `11` (the pre-existing `src/app.rs` drift count), and exactly the 12 baseline
clippy lines listed in the milestone preamble — no new line, and none pointing
into `src/gpu/` or `src/verify.rs`. Never run bare `cargo fmt`.

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && git add -A && git commit -F- <<'EOF'
feat(gpu): validate() records the GPU decision, never refuses on it

validated_gpu mirrors validated_thread_count: start_search acts on what
the user saw, not on a status that may have changed. Every GPU state
still validates Ok, so a faulted device or a stale toggle can never trap
the user in the config screen.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
EOF
```

---

### Task 6.3: `main()`'s pre-raw-mode probe and the terminal-restoring panic hook

**Files:**
- Modify: `/Users/shawnhopkinson/Rust/Vanaddy/src/main.rs` (lines 23-31: the head of `main`)
- Test: `/Users/shawnhopkinson/Rust/Vanaddy/src/main.rs` (new `mod tests` at end of file)

**Interfaces:**
- Consumes: `crate::gpu::GpuEngine::probe() -> GpuStatus`; `App::with_gpu_status(GpuStatus) -> App`
- Produces: `fn install_terminal_restoring_panic_hook()`

- [ ] **Step 1: Write the failing test.** Append this to the end of `/Users/shawnhopkinson/Rust/Vanaddy/src/main.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::install_terminal_restoring_panic_hook;
    use std::sync::atomic::{AtomicBool, Ordering};

    /// NOTE: this test manipulates the PROCESS-WIDE panic hook, and `cargo test`
    /// runs tests as threads in one process. It installs, exercises, and then
    /// restores the default hook. Keep it short.
    #[test]
    fn panic_hook_restores_terminal_and_still_calls_the_previous_hook() {
        static PREV_RAN: AtomicBool = AtomicBool::new(false);

        // Stand in a hook of our own so we can prove the chain is intact. The
        // classic bug is forgetting `prev(info)`, which silently deletes every
        // panic message and backtrace in the binary.
        std::panic::set_hook(Box::new(|_| {
            PREV_RAN.store(true, Ordering::SeqCst);
        }));

        install_terminal_restoring_panic_hook();

        let result = std::panic::catch_unwind(|| panic!("deliberate test panic"));
        assert!(result.is_err(), "the panic must still unwind");
        assert!(
            PREV_RAN.load(Ordering::SeqCst),
            "the installed hook must call the previous hook, or all panic output is lost"
        );

        // Restore the default hook so unrelated tests print normally.
        let _ = std::panic::take_hook();
    }

    #[test]
    fn probe_result_reaches_the_app() {
        // Whatever the machine reports, App must carry it verbatim — main() is
        // the only place a probe happens, and a dropped result would silently
        // mean "no GPU, forever". The single licensed exception is the env veto,
        // which deliberately rewrites a `Ready` probe into `Disabled(UserOff)` so
        // the config row can show the reason.
        let status = crate::gpu::GpuEngine::probe();
        let app = crate::app::App::with_gpu_status(status.clone());
        let vetoed = crate::app::gpu_env_off(
            std::env::var("VANADDY_GPU").ok().as_deref(),
            std::env::var("VANADDY_NO_GPU").ok().as_deref(),
        ) && matches!(status, crate::gpu::GpuStatus::Ready { .. });
        if vetoed {
            assert_eq!(
                app.gpu_status,
                crate::gpu::GpuStatus::Disabled(crate::gpu::GpuDisableReason::UserOff)
            );
        } else {
            assert_eq!(app.gpu_status, status);
        }
    }
}
```

- [ ] **Step 2: Run it and watch it fail to compile.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo test panic_hook_restores_terminal
```

Expected failure:

```
error[E0432]: unresolved import `super::install_terminal_restoring_panic_hook`
  no `install_terminal_restoring_panic_hook` in the root
```

- [ ] **Step 3: Add the panic-hook installer.** In `/Users/shawnhopkinson/Rust/Vanaddy/src/main.rs`, insert this function immediately before `fn main() -> io::Result<()> {` (line 23):

```rust
/// Restore the terminal on ANY panic, then chain to whatever hook was already
/// installed so the message and backtrace still print.
///
/// The GPU path adds panic sites — `pack_key_block`'s hard assert, every Metal
/// `Result` unwrap — to a binary that previously had none inside the alternate
/// screen. Without this, a panic leaves the user in raw mode on the alternate
/// screen with a shell that echoes nothing.
fn install_terminal_restoring_panic_hook() {
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = disable_raw_mode();
        let _ = stdout().execute(LeaveAlternateScreen);
        prev(info);
    }));
}
```

- [ ] **Step 4: Probe before raw mode and install the hook.** In the same file, replace the head of `main` (lines 23-29):

```rust
fn main() -> io::Result<()> {
    enable_raw_mode()?;
    stdout().execute(EnterAlternateScreen)?;
    let backend = ratatui::backend::CrosstermBackend::new(stdout());
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new();
```

with:

```rust
fn main() -> io::Result<()> {
    // Probe BEFORE enable_raw_mode(). Device creation is the one Metal call that
    // can print to stderr or panic on a machine we have not seen, and neither
    // must land inside the alternate screen. catch_unwind because a Rust unwind
    // here would otherwise take the process down before the hook below exists.
    // (An Objective-C exception is NOT catchable — that is why the backend never
    // calls setMathMode and always clamps the threadgroup size.)
    let gpu_status = std::panic::catch_unwind(gpu::GpuEngine::probe)
        .unwrap_or_else(|_| gpu::GpuStatus::Unavailable("Metal probe panicked".to_string()));

    install_terminal_restoring_panic_hook();

    enable_raw_mode()?;
    stdout().execute(EnterAlternateScreen)?;
    let backend = ratatui::backend::CrosstermBackend::new(stdout());
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::with_gpu_status(gpu_status);
```

- [ ] **Step 5: Run both tests and watch them pass.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo test panic_hook_restores_terminal probe_result_reaches_the_app -- --test-threads=1
```

Expect `test result: ok. 2 passed`. (`--test-threads=1` keeps the global-hook window from overlapping another test's panic.)

- [ ] **Step 6: Run the whole suite and the milestone gate, then commit.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo test
cd /Users/shawnhopkinson/Rust/Vanaddy && rustfmt --edition 2021 --check --config skip_children=true src/main.rs | grep -c '^Diff in'
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo clippy --all-targets 2>&1 | grep -- '-->' | sort | uniq -c
```

Expected: the suite passes, `0` (`src/main.rs` is rustfmt-clean; `--config skip_children=true` keeps `rustfmt` from walking the whole crate — the `--skip-children` *flag* does not exist in `rustfmt 1.9.0-stable`, and using it makes this gate print `0` unconditionally), and exactly the 12 baseline
clippy lines listed in the milestone preamble — no new line, and none pointing
into `src/gpu/` or `src/verify.rs`. Never run bare `cargo fmt`.

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && git add -A && git commit -F- <<'EOF'
feat(gpu): probe before raw mode, restore the terminal on any panic

GpuEngine::probe() runs before enable_raw_mode() so Metal stderr noise or
a probe panic cannot land inside the alternate screen, and the result is
handed to App::with_gpu_status. The panic hook leaves the alternate
screen and disables raw mode, then chains to the previous hook so the
message and backtrace still print.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
EOF
```

---

### Task 6.4: The `VecDeque` match cap and an honest `total_matches`

**Files:**
- Modify: `/Users/shawnhopkinson/Rust/Vanaddy/src/app.rs` (`pub matches: Vec<Match>` at line 41; `matches: Vec::new()` in the constructor; `start_search` reset at lines 217-218; `drain_matches` at lines 272-290)
- Modify: `/Users/shawnhopkinson/Rust/Vanaddy/src/ui.rs` (line 213; the `#` column at lines 361-366)
- Modify: `/Users/shawnhopkinson/Rust/Vanaddy/src/main.rs` (line 53)
- Test: `/Users/shawnhopkinson/Rust/Vanaddy/src/app.rs` (`mod tests`)

**Interfaces:**
- Consumes: `crate::chains::Match` with `pub verified: crate::verify::Verified`; `crate::verify::Verified::cpu_reference()`; `crate::app::append_match_row(path: &Path, m: &Match) -> io::Result<()>`; `CSV_PATH: &str`; dev-dependency `tempfile = "3"`
- Produces: `pub const MATCH_CAP: usize = 500`; `App` fields `pub matches: VecDeque<Match>`, `pub total_matches: u64`, `pub csv_path: PathBuf`

- [ ] **Step 1: Write the failing test.** Add this test inside `mod tests` in `/Users/shawnhopkinson/Rust/Vanaddy/src/app.rs`:

```rust
    #[test]
    fn match_cap_evicts_oldest_and_total_keeps_counting() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = App::new();
        app.csv_path = dir.path().join("vanity_wallets.csv");

        let (tx, rx) = mpsc::channel();
        app.rx = Some(rx);
        for i in 0..(MATCH_CAP + 7) {
            tx.send(Match {
                chain: "EVM".to_string(),
                address: format!("0x{i:040x}"),
                secret_hex: "00".repeat(32),
                mnemonic: "abandon abandon abandon".to_string(),
                verified: crate::verify::Verified::cpu_reference(),
            })
            .unwrap();
        }
        drop(tx);

        app.drain_matches();

        assert_eq!(app.matches.len(), MATCH_CAP, "the in-memory list is capped");
        assert_eq!(
            app.total_matches,
            (MATCH_CAP + 7) as u64,
            "total_matches keeps counting past the cap"
        );
        assert_eq!(
            app.matches.front().unwrap().address,
            format!("0x{:040x}", 7),
            "the OLDEST matches are the ones evicted"
        );
        assert_eq!(
            app.matches.back().unwrap().address,
            format!("0x{:040x}", MATCH_CAP + 6),
            "the newest match is retained"
        );
        assert_eq!(app.selected_match, MATCH_CAP - 1, "selection tracks the newest row");

        // Eviction is a RENDER budget, not data loss: every match is on disk.
        let csv = std::fs::read_to_string(&app.csv_path).unwrap();
        assert_eq!(
            csv.lines().count(),
            MATCH_CAP + 7,
            "the CSV holds every match, cap or no cap"
        );
    }
```

Also add `use std::sync::mpsc;` and `use crate::chains::Match;` to the top of `mod tests` if they are not already there — the module currently starts with `use super::*;` at line 558, which already brings `mpsc` and `Match` into scope through `src/app.rs`'s own imports.

- [ ] **Step 2: Run it and watch it fail to compile.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo test match_cap_evicts_oldest
```

Expected failure:

```
error[E0425]: cannot find value `MATCH_CAP` in this scope
error[E0609]: no field `total_matches` on type `App`
error[E0609]: no field `csv_path` on type `App`
error[E0599]: no method named `front` found for struct `Vec` in the current scope
```

- [ ] **Step 3: Add the cap constant and the imports.** In `/Users/shawnhopkinson/Rust/Vanaddy/src/app.rs`, add to the import block (just after `use crate::gpu::{GpuEngine, GpuHealth, GpuRx, GpuStatus};` added in Task 6.1):

```rust
use std::collections::VecDeque;
use std::path::PathBuf;
```

and insert this constant immediately after that import block, above `#[derive(Clone, Copy, PartialEq)] pub enum AppState`:

```rust
/// Cap on the in-memory match list.
///
/// `render_match_table` (src/ui.rs:352-370) rebuilds EVERY row — three `String`
/// allocations each — on every 100 ms frame. At a 1-character EVM vanity the
/// match rate is ~1 in 16, which the GPU roughly doubles to ~1,700/s; an
/// uncapped `Vec` therefore reaches ~300,000 allocations per frame within a
/// minute and the TUI hard-freezes. The cap bounds render cost. `total_matches`
/// carries the honest count and the CSV carries every row, so nothing is lost.
pub const MATCH_CAP: usize = 500;
```

- [ ] **Step 4: Change the field types.** In `struct App`, replace `pub matches: Vec<Match>,` (line 41) with:

```rust
    pub matches: VecDeque<Match>,
    /// Every match ever found this run, including those evicted by MATCH_CAP.
    /// This is the number the stats pane and the exit summary must show.
    pub total_matches: u64,
    /// Where the CSV lives. Production is `CSV_PATH`; tests point it at a temp
    /// dir, because `cargo test` runs tests as threads in one process and
    /// `set_current_dir` is therefore racy.
    pub csv_path: PathBuf,
```

- [ ] **Step 5: Initialise the new fields.** In `App::with_gpu_status`, replace `matches: Vec::new(),` with:

```rust
            matches: VecDeque::new(),
            total_matches: 0,
            csv_path: PathBuf::from(CSV_PATH),
```

- [ ] **Step 6: Reset the total in `start_search`.** In `start_search`, replace lines 217-218:

```rust
        self.matches.clear();
        self.selected_match = 0;
```

with:

```rust
        self.matches.clear();
        self.total_matches = 0;
        self.selected_match = 0;
```

- [ ] **Step 7: Apply the cap in `drain_matches`.** Replace the body of `drain_matches` (lines 272-290) with:

```rust
    pub fn drain_matches(&mut self) {
        if let Some(ref rx) = self.rx {
            while let Ok(payload) = rx.try_recv() {
                let _ = append_match_row(&self.csv_path, &payload);

                self.total_matches += 1;
                self.matches.push_back(payload);
                // Evict from the FRONT: the newest matches are the ones on
                // screen, and the evicted ones are already durably in the CSV.
                while self.matches.len() > MATCH_CAP {
                    self.matches.pop_front();
                }
                self.selected_match = self.matches.len().saturating_sub(1);
            }
        }
    }
```

- [ ] **Step 8: Make the stats pane and the row numbers honest.** In `/Users/shawnhopkinson/Rust/Vanaddy/src/ui.rs`, replace line 213:

```rust
        (count, rate, app.matches.len() as u64, secs)
```

with:

```rust
        (count, rate, app.total_matches, secs)
```

and replace the `#` cell inside `render_match_table` (line 362):

```rust
                Cell::from(format!("{}", i + 1)),
```

with:

```rust
                // Number from the run's total, not the window index: after the
                // cap evicts, restarting at 1 would silently claim the run found
                // fewer matches than it did.
                Cell::from(format!(
                    "{}",
                    (app.total_matches as usize).saturating_sub(app.matches.len()) + i + 1
                )),
```

- [ ] **Step 9: Make the exit summary honest.** In `/Users/shawnhopkinson/Rust/Vanaddy/src/main.rs`, replace line 53:

```rust
    let matches = app.matches.len();
```

with:

```rust
    let matches = app.total_matches;
```

and replace line 62:

```rust
            println!("  Saved to        : vanity_wallets.csv");
```

with:

```rust
            println!("  Saved to        : {}", app.csv_path.display());
```

- [ ] **Step 10: Run the test and watch it pass.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo test match_cap_evicts_oldest
```

Expect `test result: ok. 1 passed`.

- [ ] **Step 11: Run the whole suite and the milestone gate, then commit.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo test
cd /Users/shawnhopkinson/Rust/Vanaddy && rustfmt --edition 2021 --check src/app.rs | grep -c '^Diff in'
cd /Users/shawnhopkinson/Rust/Vanaddy && rustfmt --edition 2021 --check src/ui.rs | grep -c '^Diff in'
cd /Users/shawnhopkinson/Rust/Vanaddy && rustfmt --edition 2021 --check --config skip_children=true src/main.rs | grep -c '^Diff in'
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo clippy --all-targets 2>&1 | grep -- '-->' | sort | uniq -c
```

Expected: the suite passes, `11` for `src/app.rs`, `18` for `src/ui.rs` and `0` for `src/main.rs` (the pre-existing drift counts), and exactly the 12 baseline
clippy lines listed in the milestone preamble — no new line, and none pointing
into `src/gpu/` or `src/verify.rs`. Never run bare `cargo fmt`.

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && git add -A && git commit -F- <<'EOF'
feat(ui): cap the in-memory match list at 500, count the rest

render_match_table rebuilds every row (3 String allocations each) ten
times a second. At a 1-character EVM vanity the GPU pushes the match rate
to ~1,700/s, so an uncapped Vec freezes the TUI within a minute. Cap the
VecDeque, evict from the front, and carry the honest count in
total_matches -- every match is already durably in the CSV.

App also gains csv_path so tests stop writing the real CSV into the repo
root; production still uses CSV_PATH.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
EOF
```

---

### Task 6.5: Hold the CSV file open for the search

**Files:**
- Modify: `/Users/shawnhopkinson/Rust/Vanaddy/src/app.rs` (`struct App`; `App::with_gpu_status`; the `// Ensure CSV has header` block in `start_search`, as Task 2.5 Step 6 left it — no line number, because Tasks 2.5, 5.1, 6.1 and 6.4 all insert above it; `drain_matches`; `append_match_row` — added in Milestone 2)
- Test: `/Users/shawnhopkinson/Rust/Vanaddy/src/app.rs` (`mod tests`)

**Interfaces:**
- Consumes: `open_csv_secure(path: &Path) -> io::Result<File>`; `append_match_row(path: &Path, m: &Match) -> io::Result<()>`
- Produces: `App` field `csv_file: Option<File>`; `fn write_match_row(file: &mut File, m: &Match) -> io::Result<()>`

- [ ] **Step 1: Write the failing test.** Add this test inside `mod tests` in `/Users/shawnhopkinson/Rust/Vanaddy/src/app.rs`:

```rust
    #[test]
    fn held_open_csv_file_takes_every_row_and_stays_0600() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vanity_wallets.csv");

        let mut app = App::new();
        app.csv_path = path.clone();
        app.csv_file = Some(open_csv_secure(&path).unwrap());

        let (tx, rx) = mpsc::channel();
        app.rx = Some(rx);
        for addr in ["0xaaaa", "0xbbbb", "0xcccc"] {
            tx.send(Match {
                chain: "EVM".to_string(),
                address: addr.to_string(),
                secret_hex: "11".repeat(32),
                mnemonic: "abandon abandon abandon".to_string(),
                verified: crate::verify::Verified::cpu_reference(),
            })
            .unwrap();
        }
        drop(tx);

        app.drain_matches();

        let csv = std::fs::read_to_string(&path).unwrap();
        assert!(csv.contains("0xaaaa"), "first row landed: {csv}");
        assert!(csv.contains("0xbbbb"), "second row landed through the SAME handle: {csv}");
        assert!(csv.contains("0xcccc"), "third row landed through the SAME handle: {csv}");
        assert_eq!(csv.lines().count(), 3, "no row duplicated or lost: {csv}");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "the CSV holds plaintext seed phrases: owner-only, always");
        }
    }

    #[test]
    fn drain_falls_back_to_the_path_when_no_file_is_held() {
        // start_search could not open the CSV (read-only dir, ENOSPC). A found
        // match must still be written, not silently dropped.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vanity_wallets.csv");

        let mut app = App::new();
        app.csv_path = path.clone();
        assert!(app.csv_file.is_none());

        let (tx, rx) = mpsc::channel();
        app.rx = Some(rx);
        tx.send(Match {
            chain: "EVM".to_string(),
            address: "0xfallback".to_string(),
            secret_hex: "22".repeat(32),
            mnemonic: "abandon abandon abandon".to_string(),
            verified: crate::verify::Verified::cpu_reference(),
        })
        .unwrap();
        drop(tx);

        app.drain_matches();

        let csv = std::fs::read_to_string(&path).unwrap();
        assert!(csv.contains("0xfallback"), "fallback writer must not drop a match: {csv}");
    }
```

- [ ] **Step 2: Run them and watch them fail to compile.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo test held_open_csv_file_takes_every_row
```

Expected failure:

```
error[E0609]: no field `csv_file` on type `App`
```

- [ ] **Step 3: Add the field.** `File` is already in scope from the `use std::{ fs::{File, OpenOptions}, ... }` block Task 2.5 Step 4 installed — do NOT add a second `use std::fs::File;` (`error[E0252]: the name \`File\` is defined multiple times`). Just insert this field into `struct App` immediately after `pub csv_path: PathBuf,`:

```rust
    /// The CSV handle held open for the whole search. At a 1-character EVM
    /// vanity the match rate reaches ~1,700/s; reopening per row costs ~5,100
    /// syscalls/s (open + fstat + chmod) on the UI thread. 0600 is re-asserted
    /// on this one open, exactly as before.
    csv_file: Option<File>,
```

- [ ] **Step 4: Initialise it.** In `App::with_gpu_status`, add immediately after `csv_path: PathBuf::from(CSV_PATH),`:

```rust
            csv_file: None,
```

- [ ] **Step 5: Add `write_match_row` and route `append_match_row` through it.** In the same file, find `append_match_row` (added in Milestone 2) and replace it with:

```rust
/// The single place a `Match` becomes CSV bytes. Both writers — the held-open
/// handle in `drain_matches` and the path-based `append_match_row` — funnel
/// through here, so a row can never be written two different ways.
///
/// Taking `&Match` is the enforcement point for the trust boundary: a `Match`
/// cannot be constructed without a `verify::Verified` token, so an unverified
/// GPU candidate has no path to disk.
fn write_match_row(file: &mut File, m: &Match) -> io::Result<()> {
    let mut wtr = WriterBuilder::new().has_headers(false).from_writer(&mut *file);
    wtr.write_record([&m.chain, &m.address, &m.secret_hex, &m.mnemonic])?;
    wtr.flush()
}

/// Append one verified match to the CSV at `path`, opening it 0600 for the
/// write. Used when no handle is held open (a failed `start_search` open, and
/// every test that does not run a real search).
fn append_match_row(path: &Path, m: &Match) -> io::Result<()> {
    let mut file = open_csv_secure(path)?;
    write_match_row(&mut file, m)
}
```

Keep the signature byte-identical to the one Task 2.5 Step 5 installed: PRIVATE,
and spelled `io::Result<()>`, not `std::io::Result<()>`. Nothing outside
`crate::app` calls either function — Task 5.3's test lives inside `src/app.rs` —
so `pub` would widen the surface for nothing and make the two definitions read
differently to anyone jumping between the tasks. `io` and `Path` are already in
scope from the `use std::{..., io, path::Path, ...}` block Task 2.5 Step 4
installs; add them only if that block is missing them.

- [ ] **Step 6: Open the file once in `start_search`.** Replace the CSV header
block in `start_search` — search for the `// Ensure CSV has header` comment
rather than a line number, because Tasks 2.5, 5.1, 6.1 and 6.4 all insert above
it. It reads as Task 2.5 Step 6 left it, i.e. `open_csv_secure` already takes
`Path::new(CSV_PATH)`:

```rust
        // Ensure CSV has header
        {
            let file = open_csv_secure(Path::new(CSV_PATH)).expect("Failed to open vanity_wallets.csv");
            let needs_header = file.metadata().map(|m| m.len() == 0).unwrap_or(true);
            if needs_header {
                let mut wtr = WriterBuilder::new().has_headers(false).from_writer(file);
                wtr.write_record(["Chain", "Address", "Private Key (hex)", "Seed Phrase"]).unwrap();
                wtr.flush().unwrap();
            }
        }
```

with:

```rust
        // Open the CSV ONCE for this search and keep the handle. 0600 is
        // asserted here, on create and on the post-open re-assert inside
        // open_csv_secure. No `expect`: a panic here now runs inside the
        // alternate screen, and a search that cannot write its CSV should
        // report that in the UI, not take the process down.
        match open_csv_secure(&self.csv_path) {
            Ok(mut file) => {
                let needs_header = file.metadata().map(|m| m.len() == 0).unwrap_or(true);
                if needs_header {
                    let mut wtr = WriterBuilder::new().has_headers(false).from_writer(&mut file);
                    let _ = wtr.write_record(["Chain", "Address", "Private Key (hex)", "Seed Phrase"]);
                    let _ = wtr.flush();
                }
                self.csv_file = Some(file);
            }
            Err(e) => {
                self.csv_file = None;
                self.error_message = Some(format!("Cannot open {}: {e}", self.csv_path.display()));
            }
        }
```

- [ ] **Step 7: Write through the held handle in `drain_matches`.** In `drain_matches`, replace:

```rust
                let _ = append_match_row(&self.csv_path, &payload);
```

with:

```rust
                match self.csv_file.as_mut() {
                    Some(file) => {
                        let _ = write_match_row(file, &payload);
                    }
                    // No handle held (start_search's open failed, or this is a
                    // test driving drain_matches directly). Never drop a match.
                    None => {
                        let _ = append_match_row(&self.csv_path, &payload);
                    }
                }
```

- [ ] **Step 8: Run both tests and watch them pass.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo test held_open_csv_file_takes_every_row drain_falls_back_to_the_path
```

Expect `test result: ok. 2 passed`.

- [ ] **Step 9: Run the whole suite and the milestone gate, then commit.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo test
cd /Users/shawnhopkinson/Rust/Vanaddy && rustfmt --edition 2021 --check src/app.rs | grep -c '^Diff in'
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo clippy --all-targets 2>&1 | grep -- '-->' | sort | uniq -c
```

Expected: the suite passes, `11` (the pre-existing `src/app.rs` drift count), and exactly the 12 baseline
clippy lines listed in the milestone preamble — no new line, and none pointing
into `src/gpu/` or `src/verify.rs`. Never run bare `cargo fmt`.

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && git add -A && git commit -F- <<'EOF'
feat(app): hold the CSV open for the search, one row writer

At a 1-character EVM vanity the match rate reaches ~1,700/s and
reopening per row costs ~5,100 syscalls/s on the UI thread. start_search
opens once (still 0600 on create and on the re-assert) and drain_matches
writes through the handle; append_match_row stays as the fallback so a
failed open never drops a match. Both funnel through write_match_row, so
a row can only be serialised one way.

start_search no longer panics when the CSV cannot be opened -- a panic
there now runs inside the alternate screen.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
EOF
```

---

### Task 6.6: `start_search` — non-blocking reap, then spawn

**Files:**
- Modify: `/Users/shawnhopkinson/Rust/Vanaddy/src/app.rs` (`start_search` at lines 214-262; specifically the `error_message` reset at line 216 and the pool spawn at lines 249-261)
- Test: `/Users/shawnhopkinson/Rust/Vanaddy/src/app.rs` (`mod tests`)

**Interfaces:**
- Consumes: `crate::gpu::CHANNEL_CAPACITY: usize`; `crate::gpu::GpuEngine::{start, status, is_finished, reap}`; `crate::gpu::SeedBlock`; `crate::gpu::GpuHealth: Default`; `crossbeam_channel::bounded`; `ChainKind::search(self, &Matcher, &AtomicBool, &AtomicU64, &Sender<Match>, Option<&GpuRx>, &GpuHealth)`
- Produces: `fn gpu_spawn_allowed(validated_gpu: bool, engines_parked: usize) -> bool`; `start_search` populates `gpu_rx`/`gpu_engines` and threads `gpu`/`health` into the workers

- [ ] **Step 1: Write the failing test.** Add these tests inside `mod tests` in `/Users/shawnhopkinson/Rust/Vanaddy/src/app.rs`:

```rust
    #[test]
    fn gpu_spawn_is_skipped_while_a_previous_engine_is_still_winding_down() {
        assert!(gpu_spawn_allowed(true, 0), "validated and nothing parked -> spawn");
        assert!(
            !gpu_spawn_allowed(true, 1),
            "a previous engine has not finished -> skip the GPU this run, NEVER join"
        );
        assert!(!gpu_spawn_allowed(true, 3));
        assert!(!gpu_spawn_allowed(false, 0), "user, chain or status said no");
        assert!(!gpu_spawn_allowed(false, 2));
    }

    #[test]
    fn start_search_without_gpu_leaves_no_channel_and_no_engine() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = App::new();
        app.csv_path = dir.path().join("vanity_wallets.csv");
        app.chain = crate::chains::ChainKind::Evm;
        // Eight 'a's will not be found during this test.
        app.vanity_prefix = "aaaaaaaa".into();
        app.thread_count = "1".into();
        app.gpu_requested = false;

        app.validate().unwrap();
        assert!(!app.validated_gpu);

        app.start_search();
        assert!(app.gpu_rx.is_none(), "no GPU channel when the GPU is not effective");
        assert!(app.gpu_engines.is_empty(), "no engine spawned when the GPU is not effective");
        assert!(app.state == AppState::Searching);

        app.stop_search();
    }
```

- [ ] **Step 2: Run them and watch them fail to compile.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo test gpu_spawn_is_skipped_while_a_previous_engine
```

Expected failure:

```
error[E0425]: cannot find function `gpu_spawn_allowed` in this scope
```

- [ ] **Step 3: Add the pure spawn-gate helper.** In `/Users/shawnhopkinson/Rust/Vanaddy/src/app.rs`, insert this free function immediately before `pub fn gpu_env_off()` (added in Task 6.1 Step 5):

```rust
/// May this run spawn a GPU producer?
///
/// Only if `validate()` said so AND no engine from a previous run is still
/// winding down. When one is, we run CPU-only for this search rather than
/// joining: a join on the UI thread blocks the 100 ms render tick for the rest
/// of a ~250 ms cold shader compile on an Enter-Ctrl+C-Enter sequence, and
/// blocks FOREVER if the GPU has wedged inside `waitUntilCompleted`, leaving
/// the terminal in raw mode with the alternate screen up and `kill -9` as the
/// only exit.
///
/// Pure, so the decision is testable on every target — `GpuEngine` is a no-op
/// on non-Apple-Silicon builds and a test cannot conjure a live one.
fn gpu_spawn_allowed(validated_gpu: bool, engines_parked: usize) -> bool {
    validated_gpu && engines_parked == 0
}
```

- [ ] **Step 4: Reap, then decide, in `start_search`.** In `start_search`, immediately after `self.error_message = None;` (line 216), insert:

```rust
        // Reap finished engines NON-BLOCKING. `is_finished()` is a plain atomic
        // load and `reap()` joins a thread that has already returned, so neither
        // can block. Anything still running is left parked for the next attempt
        // or for `shutdown_gpu` at process exit.
        let mut still_running: Vec<GpuEngine> = Vec::new();
        for engine in std::mem::take(&mut self.gpu_engines) {
            if engine.is_finished() {
                engine.reap();
            } else {
                still_running.push(engine);
            }
        }
        self.gpu_engines = still_running;
        let spawn_gpu = gpu_spawn_allowed(self.validated_gpu, self.gpu_engines.len());
        if self.validated_gpu && !spawn_gpu {
            self.error_message =
                Some("GPU: previous session winding down — this run is CPU only".to_string());
        }
```

- [ ] **Step 4a: Remove the Milestone 5 placeholder health cell.** In `/Users/shawnhopkinson/Rust/Vanaddy/src/app.rs`, inside `start_search`, DELETE these four lines (added by Task 5.1 Step 5, directly after `let counter = self.counter.clone();`):

```rust
        // Milestone 6 replaces this with `self.gpu_health.clone()` once `App`
        // owns the cell. Until then the workers still need a health cell to
        // read, and `gpu: None` means nothing can ever write to it.
        let health = Arc::new(crate::gpu::GpuHealth::default());
```

Step 5 reintroduces `health` from `self.gpu_health`. Leaving the Milestone 5
binding in place would leave it shadowed and never read — `warning: unused
variable: health`, which breaks the clippy-count gate.

- [ ] **Step 5: Spawn the producer and thread the channel into the workers.** In `start_search`, replace the pool block (lines 249-261). Note the `chain.search(..)` line already carries the two extra arguments Task 5.1 Step 5 added — this is the post-Milestone-5 text, and it is what is actually in the file:

```rust
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(num_threads)
            .build()
            .expect("Failed to build Rayon thread pool");

        pool.spawn(move || {
            (0..num_threads).into_par_iter().for_each(|_| {
                chain.search(&matcher, &stop, &counter, &tx, None, &health);
            });
            drop(tx);
        });

        self.thread_pool = Some(pool);
```

with:

```rust
        let gpu_rx = if spawn_gpu {
            // A FRESH health cell per run. `reason` is a set-once OnceLock and
            // cannot be reset; a faulted run is made sticky by drain_matches
            // clearing `gpu_requested`/`validated_gpu`, not by reusing the cell.
            self.gpu_health = Arc::new(GpuHealth::default());
            let (gpu_tx, rx) = crossbeam_channel::bounded(crate::gpu::CHANNEL_CAPACITY);
            let engine = GpuEngine::start(gpu_tx, self.gpu_health.clone());
            // Initializing: the device, the ~60-95 ms shader compile and the
            // ~300 ms self-test all run on the spawned thread, not here.
            self.gpu_status = engine.status();
            self.gpu_engines.push(engine);
            self.gpu_rx = Some(rx.clone());
            Some(rx)
        } else {
            self.gpu_rx = None;
            None
        };
        let health = self.gpu_health.clone();

        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(num_threads)
            .build()
            .expect("Failed to build Rayon thread pool");

        pool.spawn(move || {
            (0..num_threads).into_par_iter().for_each(|_| {
                chain.search(&matcher, &stop, &counter, &tx, gpu_rx.as_ref(), &health);
            });
            drop(tx);
        });

        self.thread_pool = Some(pool);
```

- [ ] **Step 6: Run the tests and watch them pass.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo test gpu_spawn_is_skipped_while_a_previous_engine start_search_without_gpu_leaves_no_channel
```

Expect `test result: ok. 2 passed`.

- [ ] **Step 7: Run the whole suite and the milestone gate, then commit.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo test
cd /Users/shawnhopkinson/Rust/Vanaddy && rustfmt --edition 2021 --check src/app.rs | grep -c '^Diff in'
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo clippy --all-targets 2>&1 | grep -- '-->' | sort | uniq -c
```

Expected: the suite passes, `11` (the pre-existing `src/app.rs` drift count), and exactly the 12 baseline
clippy lines listed in the milestone preamble — no new line, and none pointing
into `src/gpu/` or `src/verify.rs`. Never run bare `cargo fmt`.

In particular there must be no `unused variable: health` line — if there is, Step 4a's deletion did not happen.

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && git add -A && git commit -F- <<'EOF'
feat(gpu): start_search reaps non-blocking, then spawns

is_finished()/reap() only touch engines that have already returned, so
neither can block the UI thread. If any engine from a previous run is
still winding down we run CPU-only for this search and say so, rather
than joining -- a join blocks the render tick for the rest of a ~250 ms
cold compile and blocks forever if the GPU has wedged.

Each run gets a fresh GpuHealth (reason is a set-once OnceLock); the
stickiness of a fault lives in gpu_requested/validated_gpu instead.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
EOF
```

---

### Task 6.7: `stop_search` — signal and park, never join

**Files:**
- Modify: `/Users/shawnhopkinson/Rust/Vanaddy/src/app.rs` (`stop_search` at lines 264-270)
- Test: `/Users/shawnhopkinson/Rust/Vanaddy/src/app.rs` (`mod tests`)

**Interfaces:**
- Consumes: `crate::gpu::GpuEngine::signal_stop(&self)` (non-blocking, never joins)
- Produces: `stop_search` signals every parked engine, drops `gpu_rx` and `csv_file`, and returns immediately

- [ ] **Step 1: Write the failing test.** Add this test inside `mod tests` in `/Users/shawnhopkinson/Rust/Vanaddy/src/app.rs`:

```rust
    #[test]
    fn stop_search_releases_everything_and_never_blocks_the_ui_thread() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = App::new();
        app.csv_path = dir.path().join("vanity_wallets.csv");
        app.chain = crate::chains::ChainKind::Evm;
        app.vanity_prefix = "aaaaaaaa".into();
        app.thread_count = "2".into();
        app.validate().unwrap();
        app.start_search();

        assert!(app.csv_file.is_some(), "start_search holds the CSV open");

        let before = Instant::now();
        app.stop_search();
        let elapsed = before.elapsed();

        assert!(
            elapsed < Duration::from_millis(50),
            "stop_search must never join a GPU thread: took {elapsed:?}"
        );
        assert!(app.stop.load(Ordering::Relaxed), "workers are told to exit");
        assert!(app.rx.is_none(), "match channel released");
        assert!(app.gpu_rx.is_none(), "GPU channel released — this is producer wake-path #2");
        assert!(app.csv_file.is_none(), "CSV handle closed and flushed");
        assert!(app.thread_pool.is_none());
        assert!(app.state == AppState::Configuring);
    }
```

- [ ] **Step 2: Run it and watch it fail.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo test stop_search_releases_everything
```

Expected failure (the current `stop_search` drops neither the GPU channel nor the CSV handle):

```
thread 'app::tests::stop_search_releases_everything_and_never_blocks_the_ui_thread' panicked at src/app.rs:...
CSV handle closed and flushed
```

- [ ] **Step 3: Rewrite `stop_search`.** Replace the whole of `stop_search` (lines 264-270) with:

```rust
    pub fn stop_search(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.rx = None;
        // Dropping App's Receiver clone is producer wake-path #2: once App and
        // every Rayon worker have dropped theirs, the channel disconnects and a
        // producer that missed the stop flag still exits cleanly on
        // SendTimeoutError::Disconnected instead of parking on send_timeout.
        self.gpu_rx = None;
        // NON-BLOCKING. signal_stop() is a flag store. The engines stay PARKED
        // in gpu_engines and are reaped by the next start_search or by
        // shutdown_gpu at process exit. Joining here would stall the 100 ms
        // render tick for up to a whole wave (~135 ms in steady state, ~400 ms
        // during startup) and forever if the GPU has wedged.
        for engine in &self.gpu_engines {
            engine.signal_stop();
        }
        // Drops the pool handle; workers will exit on the next stop check.
        self.thread_pool = None;
        // Closes and flushes the CSV. start_search reopens it, re-asserting 0600.
        self.csv_file = None;
        self.state = AppState::Configuring;
    }
```

- [ ] **Step 4: Run the test and watch it pass.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo test stop_search_releases_everything
```

Expect `test result: ok. 1 passed`.

- [ ] **Step 5: Run the whole suite and the milestone gate, then commit.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo test
cd /Users/shawnhopkinson/Rust/Vanaddy && rustfmt --edition 2021 --check src/app.rs | grep -c '^Diff in'
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo clippy --all-targets 2>&1 | grep -- '-->' | sort | uniq -c
```

Expected: the suite passes, `11` (the pre-existing `src/app.rs` drift count), and exactly the 12 baseline
clippy lines listed in the milestone preamble — no new line, and none pointing
into `src/gpu/` or `src/verify.rs`. Never run bare `cargo fmt`.

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && git add -A && git commit -F- <<'EOF'
feat(gpu): stop_search signals and parks, never joins

Set the stop flag, drop the match channel, drop App's GPU receiver clone
(producer wake-path #2), signal every parked engine, close the CSV, and
return. The engines are reaped by the next start_search or by
shutdown_gpu -- joining here would stall the render tick for a whole
wave, or forever on a wedged GPU.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
EOF
```

---

### Task 6.8: `drain_matches` — fault promotion, status refresh, unexpected-exit detection

**Files:**
- Modify: `/Users/shawnhopkinson/Rust/Vanaddy/src/app.rs` (`drain_matches`, as rewritten in Tasks 6.4 and 6.5)
- Test: `/Users/shawnhopkinson/Rust/Vanaddy/src/app.rs` (`mod tests`)

**Interfaces:**
- Consumes: `GpuHealth::disable: AtomicBool`; `GpuHealth::raise(&self, GpuDisableReason)`; `GpuHealth::take_reason(&self) -> Option<GpuDisableReason>`; `GpuEngine::{status, is_finished}`
- Produces: `fn is_unexpected_gpu_exit(state: AppState, gpu_live: bool, disabled: bool, engine_finished: bool) -> bool`; `drain_matches` promotes faults to `GpuStatus::Disabled` and makes them sticky

- [ ] **Step 1: Write the failing tests.** Add these tests inside `mod tests` in `/Users/shawnhopkinson/Rust/Vanaddy/src/app.rs`:

```rust
    #[test]
    fn mismatch_disables_gpu_and_leaves_app_running() {
        use crate::gpu::{GpuDisableReason, GpuStatus};

        let mut app = App::with_gpu_status(GpuStatus::Running { device: "Apple M1".to_string() });
        app.chain = crate::chains::ChainKind::Evm;
        app.gpu_requested = true;
        app.validated_gpu = true;
        app.state = AppState::Searching;
        app.start_time = Some(Instant::now());

        // A Rayon worker found a GPU candidate that MATCHED the pattern but did
        // not re-derive on the CPU. That is a GPU fault, never a false positive.
        app.gpu_health.raise(GpuDisableReason::VerifyMismatch {
            address: "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef".to_string(),
        });

        app.drain_matches();

        assert!(
            matches!(app.gpu_status, GpuStatus::Disabled(GpuDisableReason::VerifyMismatch { .. })),
            "the fault must be promoted to a visible status on the next tick"
        );
        assert!(!app.gpu_requested, "sticky for the process");
        assert!(!app.validated_gpu, "sticky for the process");
        assert!(!app.gpu_effective(), "a faulted GPU can never turn itself back on");
        assert!(app.gpu_rx.is_none(), "the drain side is released so workers stop draining");

        // And the whole point: the app keeps searching on CPU.
        assert!(!app.should_quit, "a GPU fault must never quit the app");
        assert!(app.state == AppState::Searching, "the search continues on CPU");
        assert!(
            !app.stop.load(Ordering::Relaxed),
            "the GPU has its OWN stop flag; App::stop must be untouched or every worker exits"
        );
    }

    #[test]
    fn fault_promotion_is_idempotent_and_never_overwrites_the_first_reason() {
        use crate::gpu::{GpuDisableReason, GpuStatus};

        let mut app = App::with_gpu_status(GpuStatus::Running { device: "Apple M1".to_string() });
        app.chain = crate::chains::ChainKind::Evm;
        app.gpu_requested = true;
        app.state = AppState::Searching;

        app.gpu_health.raise(GpuDisableReason::AuditMismatch { index: 5183 });
        app.drain_matches();
        app.drain_matches();
        app.drain_matches();

        assert_eq!(
            app.gpu_status,
            GpuStatus::Disabled(GpuDisableReason::AuditMismatch { index: 5183 }),
            "the first reason is the one that stands, and repeated ticks do not churn it"
        );
    }

    #[test]
    fn unexpected_gpu_exit_is_detected_only_on_a_live_faultless_run() {
        // Searching, live channel, no fault raised, yet the engine finished:
        // the producer died quietly and the TUI would report Running at 0/s.
        assert!(is_unexpected_gpu_exit(AppState::Searching, true, false, true));
        // A finished engine after a clean stop is expected, not a fault.
        assert!(!is_unexpected_gpu_exit(AppState::Configuring, true, false, true));
        // The GPU was skipped this run (no live channel): a leftover engine from
        // the previous run finishing is exactly what we asked it to do.
        assert!(!is_unexpected_gpu_exit(AppState::Searching, false, false, true));
        // A fault was already raised: the promotion branch owns that case and
        // has the real reason. Do not overwrite it with Panicked.
        assert!(!is_unexpected_gpu_exit(AppState::Searching, true, true, true));
        // Engine still running: nothing to report.
        assert!(!is_unexpected_gpu_exit(AppState::Searching, true, false, false));
    }
```

- [ ] **Step 2: Run them and watch them fail.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo test mismatch_disables_gpu_and_leaves_app_running unexpected_gpu_exit_is_detected
```

Expected failure:

```
error[E0425]: cannot find function `is_unexpected_gpu_exit` in this scope
```

and, once that resolves, `drain_matches` never touches `gpu_status`:

```
thread 'app::tests::mismatch_disables_gpu_and_leaves_app_running' panicked at src/app.rs:...
the fault must be promoted to a visible status on the next tick
```

- [ ] **Step 3: Add the pure unexpected-exit predicate.** In `/Users/shawnhopkinson/Rust/Vanaddy/src/app.rs`, insert this free function immediately after `fn gpu_spawn_allowed(..)` (added in Task 6.6):

```rust
/// Did a GPU engine die quietly?
///
/// A producer that returns without raising a reason — a panic that escaped the
/// `catch_unwind` bookkeeping, or a `return` on a path that forgot to raise —
/// would otherwise leave the TUI reporting `Running` at 0/s forever. Only
/// meaningful while THIS run has a live GPU channel: when the GPU was skipped,
/// a leftover engine finishing is the wind-down we asked for, not a fault.
///
/// Pure, so it is testable on targets where a live `GpuEngine` cannot be
/// constructed in a test.
fn is_unexpected_gpu_exit(
    state: AppState,
    gpu_live: bool,
    disabled: bool,
    engine_finished: bool,
) -> bool {
    state == AppState::Searching && gpu_live && !disabled && engine_finished
}
```

- [ ] **Step 4: Promote faults at the top of `drain_matches`.** Replace the opening of `drain_matches` — the line `pub fn drain_matches(&mut self) {` and the `if let Some(ref rx) = self.rx {` that follows it — with:

```rust
    pub fn drain_matches(&mut self) {
        // ---- 1. Fault promotion. Runs first, on every 100 ms tick, so a fault
        // raised by a Rayon worker or the producer becomes visible within one
        // frame. STICKY for the process: gpu_requested and validated_gpu go
        // false, so gpu_effective() can never turn the GPU back on without a
        // restart. A mis-derived seed is a correctness fault, not a transient.
        let disabled_now = self.gpu_health.disable.load(Ordering::Relaxed);
        if disabled_now && !matches!(self.gpu_status, GpuStatus::Disabled(_)) {
            // `raise` sets the reason BEFORE the flag, so by the time the flag
            // is observed the reason is there. Panicked is the defensive floor.
            let reason = self
                .gpu_health
                .take_reason()
                .unwrap_or(crate::gpu::GpuDisableReason::Panicked);
            self.gpu_status = GpuStatus::Disabled(reason);
            self.gpu_requested = false;
            self.validated_gpu = false;
            // Releasing the receiver stops the workers draining, wakes a
            // producer that has not noticed, and keeps the stats pane from
            // rendering a live GPU line AND a fault line in the same frame.
            self.gpu_rx = None;
        }

        // ---- 2. Status refresh: Initializing -> Running once the shader has
        // compiled and the self-test has passed. Only while this run owns a
        // live channel, and never over a Disabled status.
        if self.gpu_rx.is_some() && !matches!(self.gpu_status, GpuStatus::Disabled(_)) {
            if let Some(engine) = self.gpu_engines.last() {
                let s = engine.status();
                if s != self.gpu_status {
                    self.gpu_status = s;
                }
            }
        }

        // ---- 3. Unexpected exit: the engine finished but nothing was raised.
        let engine_finished = self.gpu_engines.iter().any(|e| e.is_finished());
        if is_unexpected_gpu_exit(
            self.state,
            self.gpu_rx.is_some(),
            self.gpu_health.disable.load(Ordering::Relaxed),
            engine_finished,
        ) {
            self.gpu_status = GpuStatus::Disabled(crate::gpu::GpuDisableReason::Panicked);
            self.gpu_requested = false;
            self.validated_gpu = false;
            self.gpu_rx = None;
        }

        // ---- 4. Matches. The CPU search is untouched by any of the above.
        if let Some(ref rx) = self.rx {
```

The rest of `drain_matches` (the `while let Ok(payload) = rx.try_recv()` loop from Tasks 6.4 and 6.5) is unchanged.

- [ ] **Step 5: Run the tests and watch them pass.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo test mismatch_disables_gpu_and_leaves_app_running fault_promotion_is_idempotent unexpected_gpu_exit_is_detected
```

Expect `test result: ok. 3 passed`.

- [ ] **Step 6: Run the whole suite and the milestone gate, then commit.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo test
cd /Users/shawnhopkinson/Rust/Vanaddy && rustfmt --edition 2021 --check src/app.rs | grep -c '^Diff in'
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo clippy --all-targets 2>&1 | grep -- '-->' | sort | uniq -c
```

Expected: the suite passes, `11` (the pre-existing `src/app.rs` drift count), and exactly the 12 baseline
clippy lines listed in the milestone preamble — no new line, and none pointing
into `src/gpu/` or `src/verify.rs`. Never run bare `cargo fmt`.

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && git add -A && git commit -F- <<'EOF'
feat(gpu): drain_matches promotes GPU faults on the UI tick

One path for every failure: GpuDisableReason -> GpuHealth::raise ->
drain_matches -> GpuStatus::Disabled, sticky for the process. The CPU
search keeps running at full CPU-only rate; App::stop is never touched,
because setting it would end the entire search -- the exact inverse of
what a GPU fault should do.

Also refresh Initializing -> Running from the live engine, and treat an
engine that finished on a live faultless run as a quiet death so the TUI
cannot report Running at 0/s forever.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
EOF
```

---

### Task 6.9: `shutdown_gpu` and the process-exit reaper

**Files:**
- Modify: `/Users/shawnhopkinson/Rust/Vanaddy/src/app.rs` (add `App::shutdown_gpu`)
- Modify: `/Users/shawnhopkinson/Rust/Vanaddy/src/main.rs` (the tail at lines 49-51)
- Test: `/Users/shawnhopkinson/Rust/Vanaddy/src/app.rs` (`mod tests`)

**Interfaces:**
- Consumes: `GpuEngine::{signal_stop, is_finished, reap}`; `GpuEngine`'s `Drop` must NOT join; in the deadline test only, `GpuEngine::{start, probe}`, `GpuHealth::default()`, `crate::gpu::{SeedBlock, CHANNEL_CAPACITY}`
- Produces: `pub fn App::shutdown_gpu(&mut self, deadline: Duration)`

- [ ] **Step 1: Write the failing test.** Add these tests inside `mod tests` in `/Users/shawnhopkinson/Rust/Vanaddy/src/app.rs`:

```rust
    #[test]
    fn shutdown_gpu_returns_immediately_when_nothing_is_parked() {
        let mut app = App::new();
        let before = Instant::now();
        app.shutdown_gpu(Duration::from_millis(600));
        let elapsed = before.elapsed();
        assert!(
            elapsed < Duration::from_millis(50),
            "must not sleep out the deadline when there is nothing to wait for: {elapsed:?}"
        );
        assert!(app.gpu_engines.is_empty());
        assert!(app.gpu_rx.is_none());
    }

    /// The deadline path — the half the test above cannot reach. `App::new()`
    /// leaves `gpu_engines` EMPTY, so `shutdown_gpu`'s
    /// `while !self.gpu_engines.is_empty() && start.elapsed() < deadline` loop
    /// never runs one iteration and the call returns in microseconds under ANY
    /// implementation — an unbounded join included. So this test parks a REAL,
    /// still-running engine: the deadline is then the thing actually under test.
    ///
    /// Sequencing: wait for the first block, which puts the ~60-95 ms shader
    /// compile and the ~300 ms self-test behind us, then shut down with a 10 ms
    /// deadline. In steady state the producer cannot react to the stop flag
    /// faster than one command buffer draining through the in-flight ring
    /// (8.8 ms x PIPELINE_DEPTH ~= 26 ms; ~135 ms worst case), so at 10 ms it is
    /// guaranteed to still be running and the bound must be what ends the wait.
    /// A join would take ~135 ms and blow the upper assertion; the lower
    /// assertion pins that the deadline was genuinely reached, so the test can
    /// never pass vacuously the way the empty-`gpu_engines` version did.
    ///
    /// The engine is abandoned mid-flight, exactly as `shutdown_gpu`'s doc
    /// comment describes: its thread exits on the stop flag a few tens of ms
    /// after this test returns.
    #[test]
    #[cfg(all(target_os = "macos", target_arch = "aarch64", feature = "metal"))]
    fn shutdown_gpu_honours_its_deadline_with_a_live_engine() {
        use crate::gpu::{SeedBlock, CHANNEL_CAPACITY};

        // Same graceful-skip idiom as `gpu_for_test` in `src/gpu/metal.rs`:
        // this test must pass on a machine with no Metal device.
        if std::env::var_os("VANADDY_NO_GPU").is_some() {
            eprintln!("SKIP: VANADDY_NO_GPU is set");
            return;
        }
        if let GpuStatus::Unavailable(reason) = GpuEngine::probe() {
            eprintln!("SKIP: no Metal device on this machine ({reason})");
            return;
        }

        let mut app = App::new();
        app.gpu_health = Arc::new(GpuHealth::default());
        let (gpu_tx, rx) = crossbeam_channel::bounded::<Box<SeedBlock>>(CHANNEL_CAPACITY);
        let engine = GpuEngine::start(gpu_tx, app.gpu_health.clone());
        app.gpu_engines.push(engine);
        // App's own clone, exactly as `start_search` holds it. The local `rx`
        // stays alive for the whole test, so the producer can only ever see the
        // stop flag — never a `Disconnected` shortcut that would let it finish
        // early and hand this test a free pass.
        app.gpu_rx = Some(rx.clone());

        let first = rx
            .recv_timeout(Duration::from_secs(180))
            .expect("no block within 180 s of GpuEngine::start");
        drop(first);

        let deadline = Duration::from_millis(10);
        let before = Instant::now();
        app.shutdown_gpu(deadline);
        let elapsed = before.elapsed();

        assert!(
            elapsed < deadline + Duration::from_millis(50),
            "shutdown_gpu is a bounded wait, never a join: {elapsed:?}"
        );
        assert!(
            elapsed >= deadline,
            "the engine was still running, so the DEADLINE — not an early \
             is_finished — must be what ended the wait: {elapsed:?}"
        );
        assert!(
            app.gpu_engines.is_empty(),
            "an engine still running past the deadline is abandoned, not left parked"
        );
        assert!(app.gpu_rx.is_none(), "shutdown_gpu drops App's channel clone");
    }
```

- [ ] **Step 2: Run them and watch them fail to compile.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo test shutdown_gpu_returns_immediately
```

Expected failure:

```
error[E0599]: no method named `shutdown_gpu` found for struct `App` in the current scope
```

- [ ] **Step 3: Add `shutdown_gpu`.** In `/Users/shawnhopkinson/Rust/Vanaddy/src/app.rs`, insert this method immediately after `stop_search` inside `impl App`:

```rust
    /// Process-exit reaper. Signals every parked engine, then waits UP TO
    /// `deadline` for them to finish, polling rather than joining.
    ///
    /// Any engine still running when the deadline expires is ABANDONED: its
    /// thread is detached and its 3.5 MiB of Metal buffers go un-zeroized. That
    /// is the accepted trade — a GPU wedged inside `waitUntilCompleted` would
    /// otherwise hang the process forever with `kill -9` as the only exit, and
    /// the CSV already writes the same secret material to disk in plaintext.
    pub fn shutdown_gpu(&mut self, deadline: std::time::Duration) {
        for engine in &self.gpu_engines {
            engine.signal_stop();
        }
        // Also disconnect the channel, so a producer parked in send_timeout
        // wakes on Disconnected instead of waiting out its 100 ms.
        self.gpu_rx = None;

        let start = Instant::now();
        while !self.gpu_engines.is_empty() && start.elapsed() < deadline {
            let mut still_running: Vec<GpuEngine> = Vec::with_capacity(self.gpu_engines.len());
            for engine in std::mem::take(&mut self.gpu_engines) {
                if engine.is_finished() {
                    engine.reap();
                } else {
                    still_running.push(engine);
                }
            }
            self.gpu_engines = still_running;
            if self.gpu_engines.is_empty() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        // Abandon the rest. `GpuEngine::drop` must not join.
        self.gpu_engines.clear();
    }
```

- [ ] **Step 4: Add `use std::time::Duration;` to the test module.** At the top of `mod tests` in `/Users/shawnhopkinson/Rust/Vanaddy/src/app.rs`, the lines `use std::time::Duration;` (line 561) and `use std::thread;` (line 560) are already present. No change needed — verify them with:

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && sed -n '/^mod tests/,/^    #\[test\]/p' src/app.rs | head -12
```

- [ ] **Step 5: Call the reaper from `main`.** In `/Users/shawnhopkinson/Rust/Vanaddy/src/main.rs`, replace lines 49-50:

```rust
    disable_raw_mode()?;
    stdout().execute(LeaveAlternateScreen)?;
```

with:

```rust
    disable_raw_mode()?;
    stdout().execute(LeaveAlternateScreen)?;

    // Restore the terminal FIRST, then wind the GPU down. Worst case in steady
    // state is ~135 ms (one command buffer + the in-flight ring + one
    // send_timeout); ~400 ms during startup. 600 ms covers both. Anything still
    // running past that is abandoned rather than hanging the exit.
    app.shutdown_gpu(Duration::from_millis(600));
```

`Duration` is already imported at `src/main.rs:20`.

- [ ] **Step 6: Run the tests and watch them pass.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo test shutdown_gpu -- --nocapture
```

Expect `test result: ok. 2 passed`. On this machine
`shutdown_gpu_honours_its_deadline_with_a_live_engine` takes ~1 s (shader
compile + self-test + first wave) and prints nothing; on a machine with no Metal
device it prints `SKIP: no Metal device on this machine (...)` and passes in
microseconds; on the stub leg (`cargo test --no-default-features shutdown_gpu`)
its `#[cfg]` excludes it entirely and the run reports `1 passed`.

If the live test fails on `the engine was still running, so the DEADLINE ... must
be what ended the wait`, the producer reacted to the stop flag inside 10 ms —
which contradicts the 8.8 ms-per-command-buffer pipeline. Investigate the
producer before relaxing the assertion; do not delete it, or the deadline goes
back to being untested.

- [ ] **Step 6b: Remove the Milestone 1 dead-code blanket.** This is the first
point in the branch at which the whole `GpuEngine` surface is consumed — `probe`
by Task 6.3, `start`/`status`/`is_finished`/`reap` by Task 6.6, `signal_stop` by
Tasks 6.7 and 6.9 — so the blanket Task 1.3 Step 6 installed has nothing left to
excuse. (Task 1.3's own comment says "`App` and `main()` wire it up in milestone
6. Remove this attribute then." Removing it any earlier in this milestone would
simply trade one blanket for a fistful of per-item allows.)

In `/Users/shawnhopkinson/Rust/Vanaddy/src/gpu/mod.rs`, delete these three lines:

```rust
// Nothing outside this module consumes it yet - `App` and `main()` wire it up in
// milestone 6. Remove this attribute then.
#![allow(dead_code)]
```

Then surface what it was hiding, on BOTH feature legs. The stub leg does not
compile `src/gpu/metal.rs`, so from the bin target the entire Metal-side surface —
`producer::producer`, `run_guarded`, `carve_and_send`, `audit_wave`,
`audit_indices`, `reason_from`, `set_status`, `read_status`,
`pack::pack_key_block`/`pack_salt_block`, `Schedule`, `selftest::self_test`,
`kernel_src::KERNEL_SRC`, and the wave-geometry consts — is unreachable there and
becomes `dead_code` the moment the blanket comes off:

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo clippy --all-targets 2>&1 | grep -- '--> src/gpu/'
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo clippy --all-targets --no-default-features 2>&1 | grep -- '--> src/gpu/'
```

Expected: no output from EITHER leg. Fix or justify every diagnostic they print —
delete what is genuinely dead, and add a targeted `#[allow(dead_code)]` with a
one-line reason ONLY where an item is reachable-but-unused. The two worked
examples in this tree are `crate::gpu::COMPRESSIONS_PER_SEED` (no production path
reads it — its only consumers are the geometry assertion in `src/gpu/mod.rs`'s
`mod tests` and Task 8.1's `#[cfg(test)]` soak-count helpers) and
`SeedBlock::is_empty` (which exists only because clippy's `len_without_is_empty`
demands it alongside `len`; nothing in the plan ever calls it). Do NOT reach for
`crate::gpu::EVM_GPU_SEEDS_PER_SEC` as the example: Milestone 7 Task 7.7 reads it
from `App::estimated_rate`, which makes it a live production consumer needing no
allow at all.

Write every reason here as a claim a later task can falsify — "no production
consumer as of Milestone 6" — and delete the attribute in whichever later task
makes the item live. An unnecessary `#[allow(dead_code)]` never warns, so nothing
else will remind you.

On the stub leg that targeted allow is
precisely what each Metal-only item listed above needs — put it on the item, never
a file-wide `#![allow(..)]`, which must not come back. With both legs silent, Task
8.5 Step 4's `grep -c -- '--> src/gpu/\|--> src/verify.rs'` expectation of `0`
holds.

- [ ] **Step 7: Run the whole suite and the milestone gate, then commit.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo test
cd /Users/shawnhopkinson/Rust/Vanaddy && rustfmt --edition 2021 --check src/app.rs | grep -c '^Diff in'
cd /Users/shawnhopkinson/Rust/Vanaddy && rustfmt --edition 2021 --check --config skip_children=true src/main.rs | grep -c '^Diff in'
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo clippy --all-targets 2>&1 | grep -- '-->' | sort | uniq -c
```

Expected: the suite passes, `11` for `src/app.rs` and `0` for `src/main.rs` (the pre-existing drift counts), and exactly the 12 baseline
clippy lines listed in the milestone preamble — no new line, and none pointing
into `src/gpu/` or `src/verify.rs`. Never run bare `cargo fmt`.

Also format the files this branch created, which have no drift to preserve:

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && rustfmt --edition 2021 src/gpu/*.rs src/verify.rs
```

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && git add -A && git commit -F- <<'EOF'
feat(gpu): bounded process-exit reaper for the GPU thread

main() restores the terminal first, then gives parked engines 600 ms to
finish, polling instead of joining. A wedged GPU is abandoned with its
buffers un-zeroized rather than hanging the exit -- the accepted trade
in the spec's Risks #8.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
EOF
```

---

### Task 6.10: Extend `start_stop_restart_does_not_leak_threads`

**Files:**
- Modify: `/Users/shawnhopkinson/Rust/Vanaddy/src/app.rs` (the existing test at lines 563-584)

**Interfaces:**
- Consumes: `App::{start_search, stop_search, shutdown_gpu}`; `App` fields `gpu_requested`, `gpu_engines`, `gpu_rx`, `csv_path`
- Produces: nothing new — this task only strengthens an existing guard

- [ ] **Step 1: Replace the existing test with the extended version.** In `/Users/shawnhopkinson/Rust/Vanaddy/src/app.rs`, replace the whole of `start_stop_restart_does_not_leak_threads` (lines 563-584) with:

```rust
    #[test]
    fn start_stop_restart_does_not_leak_threads() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = App::new();
        // Write into a temp dir, not the repo root: `cargo test` runs tests as
        // threads in one process, so a shared CSV path races other tests.
        app.csv_path = dir.path().join("vanity_wallets.csv");
        app.chain = crate::chains::ChainKind::Evm;
        // Extremely unlikely prefix so search will genuinely run for the duration.
        app.vanity_prefix = "aaaaaaaa".into();
        app.thread_count = "2".into();
        // CPU-only: this test is about lifecycle, and it must pass identically
        // on a Linux CI box with no Metal device.
        app.gpu_requested = false;
        app.validate().unwrap();

        app.start_search();
        assert!(app.gpu_engines.is_empty(), "no engine spawned when the GPU is off");
        assert!(app.gpu_rx.is_none());
        thread::sleep(Duration::from_millis(50));
        app.stop_search();

        // Second cycle
        app.validate().unwrap();
        app.start_search();
        thread::sleep(Duration::from_millis(50));
        app.stop_search();

        assert!(app.thread_pool.is_none());
        assert!(app.stop.load(Ordering::Relaxed));
        assert!(app.csv_file.is_none(), "the CSV handle is released on stop");
        assert!(
            app.gpu_engines.is_empty(),
            "no engine may accumulate across start/stop cycles"
        );

        // The exit reaper is a no-op here and must return instantly.
        let before = Instant::now();
        app.shutdown_gpu(Duration::from_millis(600));
        assert!(before.elapsed() < Duration::from_millis(50));
        assert!(app.gpu_engines.is_empty());
    }
```

- [ ] **Step 2: Run it and confirm it passes.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo test start_stop_restart_does_not_leak_threads
```

Expect `test result: ok. 1 passed`. If it fails on `app.gpu_engines.is_empty()`, the reap in `start_search` (Task 6.6, Step 4) is not running — re-read that step.

- [ ] **Step 3: Confirm the test no longer pollutes the repo.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && rm -f vanity_wallets.csv && cargo test && ls vanity_wallets.csv
```

Expected: the suite passes and `ls` reports `No such file or directory` — the test writes only into its temp dir now.

- [ ] **Step 4: Run the whole suite and the milestone gate, then commit.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo test
cd /Users/shawnhopkinson/Rust/Vanaddy && rustfmt --edition 2021 --check src/app.rs | grep -c '^Diff in'
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo clippy --all-targets 2>&1 | grep -- '-->' | sort | uniq -c
```

Expected: the suite passes, `11` (the pre-existing `src/app.rs` drift count), and exactly the 12 baseline
clippy lines listed in the milestone preamble — no new line, and none pointing
into `src/gpu/` or `src/verify.rs`. Never run bare `cargo fmt`.

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && git add -A && git commit -F- <<'EOF'
test(app): extend the lifecycle leak guard for the GPU engine list

Assert no engine accumulates across start/stop cycles, that the CSV
handle is released on stop, and that the exit reaper is instant with
nothing parked. The test now writes into a temp dir instead of the repo
root, so it no longer races other tests on a shared CSV path.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
EOF
```

---

### Task 6.11: Manual verification — hammer Enter/Ctrl+C for 30 seconds

**Files:**
- Test: manual, against `/Users/shawnhopkinson/Rust/Vanaddy/target/release/vanaddy`

**Interfaces:**
- Consumes: the whole of Milestone 6
- Produces: nothing — this is the milestone's acceptance gate

This is the check the unit tests cannot make: that the UI thread never stalls, threads
never accumulate, and at most one engine is ever live.

> **If you are an agent executing this task, you cannot complete it, and you must not
> report that you did.** Steps 2 and 4 require a human at an interactive Ratatui TUI —
> selecting fields, typing, and then hammering Enter/Ctrl+C for 30 seconds. There is no
> scriptable substitute, and inventing one is not the job.
>
> Do this instead:
> 1. Run Steps 1 and 3 for real. The build is scriptable, and so is the sampler — point it
>    at a **CPU-only** search you start non-interactively (`VANADDY_NO_GPU=1`) and let it
>    sample for 30 s. That alone catches a thread leak or unbounded RSS growth, which is
>    most of what this task is watching for.
> 2. Report **DONE_WITH_CONCERNS**, stating plainly which steps you ran, which you could
>    not, and what the sampler showed.
>
> Reporting DONE here is a false pass on the milestone's acceptance gate. Note also that
> Task 6.10's `start_stop_restart_does_not_leak_threads` already covers thread accumulation
> and single-engine-liveness automatically; what genuinely needs a human is UI
> responsiveness under key-mashing, and that is the part being handed back.

- [ ] **Step 1: Build the release binary.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo build --release
```

- [ ] **Step 2: Start the app in a scratch directory so the CSV does not land in the repo.**

```sh
mkdir -p /tmp/vanaddy-hammer && cd /tmp/vanaddy-hammer && \
  /Users/shawnhopkinson/Rust/Vanaddy/target/release/vanaddy
```

In the form: press `2` on the Chain field to select EVM, Tab to the vanity field, type `ab`, then Tab to Threads and leave it at the default.

- [ ] **Step 3: In a SECOND terminal, start sampling thread count and RSS every second.**

```sh
cd /tmp && while true; do
  pid=$(pgrep -n -f 'release/vanaddy')
  if [ -n "$pid" ]; then
    threads=$(($(ps -M -p "$pid" | wc -l) - 1))
    rss=$(ps -o rss= -p "$pid" | tr -d ' ')
    cpu=$(ps -o %cpu= -p "$pid" | tr -d ' ')
    printf '%s\tthreads=%s\trss_kb=%s\tcpu=%s\n' "$(date +%s)" "$threads" "$rss" "$cpu"
  fi
  sleep 1
done | tee /tmp/vanaddy-hammer/hammer.log
```

`ps -M` prints one header line plus one line per thread, hence the `- 1`. (macOS
`ps` has no `nlwp` keyword at all: passing it makes `ps` reject the entire `-o`
list with `ps: nlwp: keyword not found`, so the loop would print nothing for the
whole 30-second hammer and criterion 1 below could not be evaluated.)

- [ ] **Step 4: Hammer the app for 30 seconds.** In the first terminal, press `Enter` then `Ctrl+C` then `Enter` then `Ctrl+C`, as fast as you can, continuously for a full 30 seconds. Watch the frame: the header, the Checked counter, and the Rate line must keep repainting throughout. **Any visible freeze — even one that lasts a quarter of a second — is a failure of this milestone**, and means something on the UI path joined a thread.

- [ ] **Step 5: Stop hammering, let it search for 10 seconds, then quit with `q`. Check the log.**

```sh
head -3 /tmp/vanaddy-hammer/hammer.log; echo ...; tail -3 /tmp/vanaddy-hammer/hammer.log
```

Acceptance criteria, all four:
1. The `threads=` field of the LAST sampled line is within ±2 of the `threads=` field of the FIRST line sampled after the first `Enter`. A monotonic climb means engines or Rayon pools are leaking.
2. RSS at the end is within ~20 MB of RSS after the first `Enter`. A steady climb of ~200 KB/s means the per-command-buffer autorelease pool (Milestone 3) is missing.
3. No frame ever froze.
4. The GPU stats line showed at most one device at a time; it never showed two `GPU:` rows in one frame.

- [ ] **Step 6: Confirm every CSV row is real.** Any matches found on a 2-character EVM prefix are cheap to check; each row's phrase must re-derive to its address.

```sh
cd /tmp/vanaddy-hammer && wc -l vanity_wallets.csv && head -3 vanity_wallets.csv && \
  stat -f '%Sp' vanity_wallets.csv
```

Expect mode `-rw-------`. Every data row's Address must start with `0xab`.

- [ ] **Step 7: Confirm the env lever and the stub build still work.**

```sh
cd /tmp/vanaddy-hammer && VANADDY_GPU=0 /Users/shawnhopkinson/Rust/Vanaddy/target/release/vanaddy
```

The GPU toggle must be off and refuse to turn on. Quit with `q`, then:

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo test --no-default-features
```

Every test must pass with the stub backend compiled in.

- [ ] **Step 8: Clean up and record the result.**

```sh
rm -rf /tmp/vanaddy-hammer
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo clippy --all-targets 2>&1 | grep -- '-->' | sort | uniq -c
cd /Users/shawnhopkinson/Rust/Vanaddy && rustfmt --edition 2021 --check src/app.rs | grep -c '^Diff in'
cd /Users/shawnhopkinson/Rust/Vanaddy && rustfmt --edition 2021 --check src/ui.rs | grep -c '^Diff in'
cd /Users/shawnhopkinson/Rust/Vanaddy && rustfmt --edition 2021 --check --config skip_children=true src/main.rs | grep -c '^Diff in'
cd /Users/shawnhopkinson/Rust/Vanaddy && rustfmt --edition 2021 --check src/gpu/*.rs src/verify.rs | grep -c '^Diff in'
cd /Users/shawnhopkinson/Rust/Vanaddy && git status --short
```

Expected, in order: exactly the 12 baseline clippy lines from the milestone
preamble with no line pointing into `src/gpu/` or `src/verify.rs`; `11`; `18`;
`0`; `0`; and empty output from `git status --short` — Milestone 6 is committed and
the tree is clean.

Do NOT run `cargo fmt --check` here. The tree is not rustfmt-clean at the branch
point (84 diffs across 14 files), so it can only fail. NO task on this branch
performs a whole-tree reformat — Task 8.5 Step 7 is "Commit — only if Steps 3-5
actually changed something", and Task 8.5 gates that the 84-diff baseline is
*unchanged*; it does not remove it. The pre-existing drift is a separate change,
and nothing in Milestone 6 should attempt it.

Finally, confirm the milestone's own diff is what you think it is. Do NOT use
`git diff --stat ba07199..HEAD` — the range between the last pre-branch commit and
this branch also contains `4854a59` (a UI change) and `beced09` (the design spec),
neither of which belongs to this work. Scope the diff to Milestone 6's own commits
instead:

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && git diff --stat HEAD~10..HEAD -- src/ docs/
```

(Ten commits: Tasks 6.1 through 6.10 each committed exactly once.)
## Milestone 7 — TUI surface

The GPU offload now exists end to end (milestones 1–6): the producer runs, workers drain it, `App` holds `gpu_status` / `gpu_requested` / `gpu_health`, and `gpu_effective()` answers "will the GPU actually run?". **But the user cannot see or control any of it** — `App::field_count()` still returns 5/6, so the GPU form field is unreachable, and nothing in `src/ui.rs` mentions the GPU.

This milestone is about **positional fragility**. Vanaddy's config form has no field registry: field identity is an integer, and three separate places hard-code arithmetic over it —

- `App::is_text_field` (`src/app.rs:84-91`): field `2` is the vanity string, field `3` is the suffix *when* the match position is `StartsAndEndsWith`, and `field_count() - 1` is Threads.
- the Case input arm (`src/app.rs:512`): `f if f == (if both { 4 } else { 3 })`.
- the Threads input arm (`src/app.rs:520`): `f if f == app.field_count() - 1`.

and two more depend on `is_text_field` transitively: the `q`-quits guard (`src/app.rs:372`) and the `h`-opens-help guard (`src/app.rs:358`).

The spec settled where the new field goes and why the obvious answer is wrong:

> **Field placement — resolved against both prior designs.** Three designs put `GPU` **last**. Reviewers showed that breaks the app: `field_count() - 1` is load-bearing in `is_text_field` and in the thread-count input arm, and transitively in the `q`-quits guard and `h`-help guard. Put GPU last and pressing `y` does nothing, typing a digit appends to `thread_count`, the Threads field becomes unresponsive, and `q` quits the app mid-configuration. Put it before Case and it hits no arm at all.
>
> **GPU goes between Case and Threads.** Case's hard-coded `if both { 4 } else { 3 }` stays correct; Threads stays at `field_count() - 1` so both `is_text_field` and its input arm are untouched; GPU lands at `field_count() - 2`, which currently matches no arm, so it needs exactly one new arm. `field_count()` goes 5→6 / 6→7. This is a **strictly smaller and safer diff** than "GPU last", and Case → GPU → Threads reads as a coherent compute-resources group.

Resulting layout (memorise this; every task below depends on it):

| index | `StartsWith` / `EndsWith` (`field_count() == 6`) | `StartsAndEndsWith` (`field_count() == 7`) |
|---|---|---|
| 0 | Chain | Chain |
| 1 | Match position | Match position |
| 2 | Vanity (prefix or suffix) | Prefix |
| 3 | Case | Suffix |
| 4 | **GPU** | Case |
| 5 | Threads | **GPU** |
| 6 | — | Threads |

Line numbers below refer to the repository as it stands today — the pre-branch tree at commit `beced09`. Milestones 2, 5 and 6 already edited `src/app.rs`, and the tasks *inside this milestone* edit `src/app.rs` and `src/ui.rs` again: Task 7.3 alone adds an import and roughly 70 lines of helpers to `src/ui.rs` before Tasks 7.5 and 7.6 run. So the numbers will have shifted by the time you reach a given step — every step gives the exact anchor text to search for, which has not. **Match on the quoted text, never on the line range.**

Two ground rules for this milestone:

1. **Never run bare `cargo fmt`.** The tree is not rustfmt-clean as of commit `beced09`: `cargo fmt --check` reports **84 diffs across 14 files** (`src/app.rs` 11, `src/ui.rs` 18, plus all of `src/chains/*`, `src/matcher.rs`, `src/slip10.rs`, `src/bip32.rs`, `src/pbkdf2_lanes.rs`), so `cargo fmt` would bury this milestone's diff under an unrelated whole-tree reformat. Nothing on this branch reformats the tree; Task 8.5 gates the baseline instead. This milestone edits only `src/app.rs` and `src/ui.rs`, both of which already carry pre-existing drift, so match the surrounding style by hand and verify you added none:

   ```sh
   cd /Users/shawnhopkinson/Rust/Vanaddy && rustfmt --edition 2021 --check src/app.rs | grep -c '^Diff in'; rustfmt --edition 2021 --check src/ui.rs | grep -c '^Diff in'
   ```

   Expected: `11` then `18` — the pre-existing per-file counts. Anything higher means your insertion is not rustfmt-shaped; fix it by hand.
2. **The left panel is 25% of the terminal width.** At 100 columns that is 25 columns, 23 inside the border, and the labels are 11 columns wide — so a config-form *value* has 12 columns before it clips. Long status strings therefore get tested as **pure functions**, not by grepping a rendered frame. Render tests here assert *wiring and row order* only.

---

### Task 7.1: Make room for the GPU field — `field_count()` 5→6 / 6→7

**Files:**
- Modify: `/Users/shawnhopkinson/Rust/Vanaddy/src/app.rs` lines 76-82 (`field_count`)
- Test: `/Users/shawnhopkinson/Rust/Vanaddy/src/app.rs` lines 556-585 (the existing `#[cfg(test)] mod tests`)

**Interfaces:**
- Consumes: `App::is_text_field(&self) -> bool` (`src/app.rs:84`); `App::field_count(&self) -> usize` (`src/app.rs:76`); `pub fn handle_key_event(app: &mut App, key: event::KeyEvent)` (`src/app.rs:336`); `MatchPosition::{StartsWith, EndsWith, StartsAndEndsWith}` (`src/matcher.rs`)
- Produces: `App::field_count(&self) -> usize` returning `7` for `StartsAndEndsWith` and `6` otherwise

- [ ] **Step 1: Add the index-stability pin test.** Append this inside the existing `mod tests` block in `/Users/shawnhopkinson/Rust/Vanaddy/src/app.rs`, after `start_stop_restart_does_not_leak_threads` (which ends at line 584):

```rust
    /// Field identity in this form is a bare integer, and three places do
    /// arithmetic on it: `is_text_field` (src/app.rs:84-91), the Case arm
    /// (src/app.rs:512, `if both { 4 } else { 3 }`) and the Threads arm
    /// (src/app.rs:520, `field_count() - 1`). The literals below ARE the
    /// contract — do not rewrite them in terms of `field_count()`, that is
    /// exactly the tautology this test exists to avoid.
    #[test]
    fn gpu_field_index_is_stable_across_match_positions() {
        let mut app = App::new();

        app.match_position = MatchPosition::StartsWith;
        assert_eq!(
            app.field_count(),
            6,
            "StartsWith fields: chain, match, vanity, case, gpu, threads"
        );
        assert_eq!(app.field_count() - 2, 4, "GPU is field 4 for StartsWith");
        assert_eq!(app.field_count() - 1, 5, "Threads is field 5 for StartsWith");

        app.match_position = MatchPosition::EndsWith;
        assert_eq!(app.field_count(), 6, "EndsWith has the same six fields");
        assert_eq!(app.field_count() - 2, 4, "GPU is field 4 for EndsWith");

        app.match_position = MatchPosition::StartsAndEndsWith;
        assert_eq!(app.field_count(), 7, "StartsAndEndsWith adds the suffix field");
        assert_eq!(app.field_count() - 2, 5, "GPU is field 5 for StartsAndEndsWith");
        assert_eq!(app.field_count() - 1, 6, "Threads is field 6 for StartsAndEndsWith");

        // The GPU index must never land on the Case field, whose arm is
        // hard-coded to `if both { 4 } else { 3 }`.
        for (pos, case_ix) in [
            (MatchPosition::StartsWith, 3usize),
            (MatchPosition::EndsWith, 3),
            (MatchPosition::StartsAndEndsWith, 4),
        ] {
            app.match_position = pos;
            assert_ne!(
                app.field_count() - 2,
                case_ix,
                "the GPU field must not collide with the Case field"
            );
        }

        // GPU is a toggle, so `q` must still quit from it; Threads is text.
        for pos in [
            MatchPosition::StartsWith,
            MatchPosition::EndsWith,
            MatchPosition::StartsAndEndsWith,
        ] {
            app.match_position = pos;
            app.active_field = app.field_count() - 2;
            assert!(!app.is_text_field(), "the GPU field is a toggle, not text");
            app.active_field = app.field_count() - 1;
            assert!(app.is_text_field(), "the Threads field must stay a text field");
        }
    }

    /// Navigation is modulo `field_count()`; if the count is wrong the new
    /// field is simply unreachable and nothing else complains.
    #[test]
    fn tab_visits_every_field_and_wraps_including_the_new_gpu_field() {
        let mut app = App::new();
        app.match_position = MatchPosition::StartsWith;

        let mut seen = vec![app.active_field];
        for _ in 0..5 {
            handle_key_event(&mut app, event::KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
            seen.push(app.active_field);
        }
        assert_eq!(seen, vec![0, 1, 2, 3, 4, 5], "Tab must reach all six fields");

        handle_key_event(&mut app, event::KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
        assert_eq!(app.active_field, 0, "Tab wraps from Threads back to Chain");

        handle_key_event(&mut app, event::KeyEvent::new(KeyCode::BackTab, KeyModifiers::NONE));
        assert_eq!(app.active_field, 5, "BackTab from Chain lands on Threads");
    }

    /// The Threads field moved from index 4/5 to 5/6. Literal indices, so a
    /// wrong `field_count()` makes this fail instead of silently agreeing.
    #[test]
    fn threads_field_still_edits_at_its_new_index() {
        let mut app = App::new();

        app.match_position = MatchPosition::StartsWith;
        app.active_field = 5;
        app.thread_count.clear();
        handle_key_event(&mut app, event::KeyEvent::new(KeyCode::Char('4'), KeyModifiers::NONE));
        assert_eq!(app.thread_count, "4", "Threads is field 5 once the GPU field exists");

        app.match_position = MatchPosition::StartsAndEndsWith;
        app.active_field = 6;
        app.thread_count.clear();
        handle_key_event(&mut app, event::KeyEvent::new(KeyCode::Char('8'), KeyModifiers::NONE));
        assert_eq!(app.thread_count, "8", "Threads is field 6 with both prefix and suffix");
    }

    /// `q` and `h` are gated on `is_text_field()`. Before the GPU field
    /// existed, index 4 WAS the Threads text field, so both keys were inert
    /// there — proof that this guard is index-sensitive.
    #[test]
    fn q_quits_and_h_opens_help_from_the_gpu_field() {
        let mut app = App::new();
        app.match_position = MatchPosition::StartsWith;
        app.active_field = 4; // GPU

        handle_key_event(&mut app, event::KeyEvent::new(KeyCode::Char('h'), KeyModifiers::NONE));
        assert!(app.show_help, "h must still open help from the GPU field");

        handle_key_event(&mut app, event::KeyEvent::new(KeyCode::Char('x'), KeyModifiers::NONE));
        assert!(!app.show_help, "any key dismisses the help popup");

        handle_key_event(&mut app, event::KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE));
        assert!(app.should_quit, "q must still quit from the GPU field");
    }
```

- [ ] **Step 2: Run the tests and watch all four fail.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo test --bin vanaddy app::tests:: 2>&1 | tail -40
```

Expect four failures. The first one reads:

```
---- app::tests::gpu_field_index_is_stable_across_match_positions stdout ----
assertion `left == right` failed: StartsWith fields: chain, match, vanity, case, gpu, threads
  left: 5
 right: 6
```

`tab_visits_every_field_and_wraps_including_the_new_gpu_field` fails with `left: [0, 1, 2, 3, 4, 0]  right: [0, 1, 2, 3, 4, 5]`; `threads_field_still_edits_at_its_new_index` fails with `left: ""  right: "4"`; `q_quits_and_h_opens_help_from_the_gpu_field` fails with `assertion failed: app.show_help`.

- [ ] **Step 3: Widen `field_count()`.** In `/Users/shawnhopkinson/Rust/Vanaddy/src/app.rs`, replace lines 76-82 exactly (line numbers are pre-branch; match on the quoted text):

```rust
    /// Chain, match position, vanity (+ suffix when StartsAndEndsWith), case,
    /// GPU, threads. GPU sits at `field_count() - 2` — between Case and
    /// Threads — so the Case arm's hard-coded `if both { 4 } else { 3 }` and
    /// the Threads arm's `field_count() - 1` both stay correct, and
    /// `is_text_field` needs no change at all.
    pub fn field_count(&self) -> usize {
        if matches!(self.match_position, MatchPosition::StartsAndEndsWith) {
            7
        } else {
            6
        }
    }
```

- [ ] **Step 4: Run the same tests and watch all four pass.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo test --bin vanaddy app::tests:: 2>&1 | tail -20
```

Expect `test result: ok.` with 22 passed and 1 ignored — this task's four on top of the 18 already running in `app::tests` by the end of Milestone 6 (1 pre-existing `start_stop_restart_does_not_leak_threads` + 3 from Task 2.5 + 14 from Tasks 6.1/6.2/6.4/6.5/6.6/6.7/6.8/6.9). Task 5.3's live-GPU gate is the `#[ignore]`d one. What matters is that the count rose by exactly 4 and nothing failed.

- [ ] **Step 5: Run the whole suite to confirm nothing else keyed off the old count.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo test 2>&1 | tail -15
```

Expect `test result: ok.` with 0 failed.

- [ ] **Step 6: Commit.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && git add -A && git commit -m "ui: reserve a GPU form field between Case and Threads

field_count() goes 5->6 / 6->7. The new index is field_count() - 2, which
matches no existing input arm, so the Case arm (hard-coded 4/3) and the
Threads arm (field_count() - 1) are both untouched. Pinned by
gpu_field_index_is_stable_across_match_positions with literal indices.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 7.2: The GPU field's input arm

**Files:**
- Modify: `/Users/shawnhopkinson/Rust/Vanaddy/src/app.rs` — `handle_field_input`, inserting a new arm between the Case arm (ends line 517) and the Threads arm (starts line 519)
- Read only (no edit expected): `/Users/shawnhopkinson/Rust/Vanaddy/src/app.rs` import block at lines 1-13. Task 6.1 already added `use crate::gpu::{GpuEngine, GpuHealth, GpuRx, GpuStatus};`, so this task adds no import; Step 3 below only verifies that, as a safety net for an out-of-order build.
- Test: `/Users/shawnhopkinson/Rust/Vanaddy/src/app.rs` `#[cfg(test)] mod tests`

**Interfaces:**
- Consumes: `crate::gpu::GpuStatus::{Unavailable(String), Ready { device: String }, Initializing, Running { device: String }, Disabled(GpuDisableReason)}` — **already imported into `src/app.rs` by Task 6.1** as `use crate::gpu::{GpuEngine, GpuHealth, GpuRx, GpuStatus};`, so this task consumes that import rather than adding one; `App::gpu_status: GpuStatus`; `App::gpu_requested: bool`; `App::gpu_effective(&self) -> bool`; `ChainKind::label(self) -> &'static str` (`src/chains/mod.rs:57`); `ChainKind: PartialEq` (`src/chains/mod.rs:47`)
- Produces: the `f if f == app.field_count() - 2` arm of `handle_field_input` — and nothing else. In particular it produces **no** new `use` line: a second import of `GpuStatus` on top of Task 6.1's is `error[E0252]` (the name is defined multiple times).

- [ ] **Step 1: Add the input-arm tests.** Append inside `mod tests` in `/Users/shawnhopkinson/Rust/Vanaddy/src/app.rs`:

```rust
    use crate::gpu::{GpuDisableReason, GpuStatus};

    fn press(app: &mut App, code: KeyCode) {
        handle_key_event(app, event::KeyEvent::new(code, KeyModifiers::NONE));
    }

    fn app_on_gpu_field() -> App {
        let mut app = App::new();
        app.chain = ChainKind::Evm;
        app.match_position = MatchPosition::StartsWith;
        app.gpu_status = GpuStatus::Ready { device: "Apple M1".to_string() };
        app.gpu_requested = false;
        app.error_message = None;
        app.active_field = app.field_count() - 2;
        app
    }

    #[test]
    fn gpu_field_toggles_with_y_n_and_arrows() {
        let mut app = app_on_gpu_field();

        press(&mut app, KeyCode::Char('y'));
        assert!(app.gpu_requested, "y turns GPU offload on");
        press(&mut app, KeyCode::Char('n'));
        assert!(!app.gpu_requested, "n turns GPU offload off");
        press(&mut app, KeyCode::Right);
        assert!(app.gpu_requested, "Right toggles GPU offload on");
        press(&mut app, KeyCode::Left);
        assert!(!app.gpu_requested, "Left toggles GPU offload off");
        press(&mut app, KeyCode::Char('Y'));
        assert!(app.gpu_requested, "uppercase Y works too");
    }

    #[test]
    fn gpu_field_refuses_to_turn_on_for_a_non_evm_chain() {
        let mut app = app_on_gpu_field();
        app.chain = ChainKind::Solana;

        press(&mut app, KeyCode::Char('y'));

        assert!(!app.gpu_requested, "GPU offload is EVM-only");
        let msg = app.error_message.clone().expect("refusal must be visible, not silent");
        assert!(msg.contains("EVM-only"), "unhelpful refusal: {msg}");
        assert!(msg.contains("Solana"), "refusal must name the chain: {msg}");
    }

    #[test]
    fn gpu_field_refuses_to_turn_on_when_there_is_no_device() {
        let mut app = app_on_gpu_field();
        app.gpu_status = GpuStatus::Unavailable("no Metal device".to_string());

        press(&mut app, KeyCode::Char('y'));

        assert!(!app.gpu_requested, "cannot request a GPU that does not exist");
        let msg = app.error_message.clone().expect("refusal must be visible");
        assert!(msg.contains("no Metal device"), "refusal must carry the reason: {msg}");
    }

    #[test]
    fn gpu_field_refuses_to_turn_on_after_a_fault_disabled_it() {
        let mut app = app_on_gpu_field();
        app.gpu_status = GpuStatus::Disabled(GpuDisableReason::AuditMismatch { index: 5183 });

        press(&mut app, KeyCode::Char('y'));

        assert!(!app.gpu_requested, "a disabled GPU is sticky for the process");
        let msg = app.error_message.clone().expect("refusal must be visible");
        assert!(msg.contains("AuditMismatch"), "refusal must carry the reason: {msg}");
    }

    #[test]
    fn turning_the_gpu_off_always_works_and_clears_the_error() {
        let mut app = app_on_gpu_field();
        app.chain = ChainKind::Monero;
        app.error_message = Some("stale complaint".to_string());

        press(&mut app, KeyCode::Char('n'));

        assert!(!app.gpu_requested);
        assert!(app.error_message.is_none(), "off is never refused, and clears the error");
    }

    #[test]
    fn gpu_preference_survives_a_round_trip_through_another_chain() {
        let mut app = app_on_gpu_field();
        press(&mut app, KeyCode::Char('y'));
        assert!(app.gpu_requested);

        app.active_field = 0; // Chain
        press(&mut app, KeyCode::Char('1')); // Solana
        press(&mut app, KeyCode::Char('2')); // back to EVM

        assert!(app.gpu_requested, "the preference must survive a trip through Solana");
        assert!(app.gpu_effective(), "and must be effective again once the chain is EVM");
    }
```

- [ ] **Step 2: Run the tests and watch them fail.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo test --bin vanaddy app::tests::gpu 2>&1 | tail -30
```

Expect five failures. `gpu_field_toggles_with_y_n_and_arrows` fails with `assertion failed: app.gpu_requested` (no arm handles the index, so the key is swallowed by the `_ => {}` fallthrough at `src/app.rs:532`); the three refusal tests fail with `refusal must be visible, not silent` on the `.expect(...)`.

- [ ] **Step 3: Make sure `GpuStatus` is in scope in the non-test code.** Check the top of `/Users/shawnhopkinson/Rust/Vanaddy/src/app.rs`:

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && grep -n "use crate::gpu" src/app.rs
```

Milestone 6 added the `App` GPU fields, so a line importing `GpuStatus` is normally already there. If `GpuStatus` is **not** among the imported names, add it — either extend the existing `use crate::gpu::{...};` list with `GpuStatus`, or, if there is no `use crate::gpu` line at all, insert `use crate::gpu::GpuStatus;` immediately after line 2 (`use super::matcher::{Matcher, MatchPosition};`). Do not add a second `use` of a name that is already imported.

- [ ] **Step 4: Add the input arm.** In `/Users/shawnhopkinson/Rust/Vanaddy/src/app.rs`, in `handle_field_input`, insert this between the Case arm (which ends with `},` at line 517) and the `// Thread count (always last field)` comment at line 519 (line numbers are pre-branch; match on the quoted text):

```rust
        // GPU offload (toggle with Left/Right or y/n) — always second-to-last,
        // between Case and Threads. Turning it OFF always works. Turning it ON
        // is refused LOUDLY — visibly disabled, never silently ignored — when
        // there is no device, when a fault disabled it for this process, or
        // when the selected chain is not EVM. `gpu_requested` is deliberately
        // NOT cleared when the chain changes: the preference survives a
        // round-trip through Solana and back to EVM.
        f if f == app.field_count() - 2 => {
            let want = match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') => Some(true),
                KeyCode::Char('n') | KeyCode::Char('N') => Some(false),
                KeyCode::Left | KeyCode::Right => Some(!app.gpu_requested),
                _ => None,
            };
            match want {
                None => {}
                Some(false) => {
                    app.gpu_requested = false;
                    app.error_message = None;
                }
                Some(true) => {
                    // Precedence: no device beats disabled beats wrong chain.
                    let refusal = match &app.gpu_status {
                        GpuStatus::Unavailable(r) => Some(format!("GPU unavailable: {r}")),
                        GpuStatus::Disabled(r) => Some(format!("GPU disabled this session: {r:?}")),
                        _ if app.chain != ChainKind::Evm => Some(format!(
                            "GPU offload is EVM-only — {} runs on CPU",
                            app.chain.label()
                        )),
                        _ => None,
                    };
                    match refusal {
                        Some(msg) => app.error_message = Some(msg),
                        None => {
                            app.gpu_requested = true;
                            app.error_message = None;
                        }
                    }
                }
            }
        }
```

- [ ] **Step 5: Run the tests and watch them pass.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo test --bin vanaddy app::tests:: 2>&1 | tail -20
```

Expect `test result: ok.` with 28 passed and 1 ignored — the 22 running after Task 7.1 plus this task's 6.

- [ ] **Step 6: Run the whole suite.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo test 2>&1 | tail -15
```

Expect `test result: ok.` with 0 failed.

- [ ] **Step 7: Commit.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && git add -A && git commit -m "ui: input arm for the GPU offload field

y/n and Left/Right toggle it. Turning it on is refused with a visible
error when there is no Metal device, when a fault disabled it for the
process, or when the chain is not EVM. Turning it off is never refused.
gpu_requested survives a chain round-trip on purpose.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 7.3: The config-form GPU row

**Files:**
- Modify: `/Users/shawnhopkinson/Rust/Vanaddy/src/ui.rs` lines 1-11 (imports), lines 129-140 (`both` branch of `render_config_form`), lines 158-168 (`else` branch)
- Modify: `/Users/shawnhopkinson/Rust/Vanaddy/src/ui.rs` — new helpers after `render_config_form` (which ends at line 199)
- Test: `/Users/shawnhopkinson/Rust/Vanaddy/src/ui.rs` lines 473-514 (the existing `#[cfg(test)] mod tests`)

**Interfaces:**
- Consumes: `crate::gpu::GpuStatus`; `crate::gpu::GpuDisableReason` (all 12 variants); `App::gpu_status`; `App::gpu_requested`; `App::chain: ChainKind`
- Produces:
  - `fn sanitize_status_text(s: &str, max: usize) -> String`
  - `fn gpu_reason_label(r: &GpuDisableReason) -> &'static str`
  - `fn gpu_form_value(app: &App) -> (String, Style)`
  - `fn gpu_form_line(app: &App, label_style: Style) -> Line<'static>`

- [ ] **Step 1: Add the tests.** Append inside `mod tests` in `/Users/shawnhopkinson/Rust/Vanaddy/src/ui.rs`:

```rust
    use crate::app::AppState;
    use crate::gpu::{GpuDisableReason, GpuStatus};

    /// Render the whole TUI into an in-memory buffer and return it as one
    /// newline-separated String, so a test can assert on what the user sees.
    fn render_to_string(app: &App, width: u16, height: u16) -> String {
        let backend = ratatui::backend::TestBackend::new(width, height);
        let mut terminal = ratatui::Terminal::new(backend).expect("TestBackend never fails");
        terminal.draw(|f| ui(f, app)).expect("TestBackend never fails");
        let buf = terminal.backend().buffer();
        let w = buf.area.width as usize;
        let mut out = String::new();
        for (i, cell) in buf.content.iter().enumerate() {
            if i > 0 && i % w == 0 {
                out.push('\n');
            }
            out.push_str(cell.symbol());
        }
        out
    }

    #[test]
    fn sanitize_status_text_flattens_control_characters() {
        assert_eq!(sanitize_status_text("line 1\nline 2\ttab", 64), "line 1 line 2 tab");
        assert_eq!(sanitize_status_text("\u{7}bell", 64), " bell");
        assert_eq!(sanitize_status_text("plain", 64), "plain");
    }

    #[test]
    fn sanitize_status_text_truncates_with_an_ellipsis() {
        assert_eq!(sanitize_status_text("abcdefgh", 4), "abc…");
        assert_eq!(sanitize_status_text("abcd", 4), "abcd");
    }

    #[test]
    fn sanitize_status_text_never_splits_a_multi_byte_char() {
        // 'é' is two bytes; byte-wise truncation would panic here.
        assert_eq!(sanitize_status_text("ééééé", 3), "éé…");
    }

    #[test]
    fn gpu_form_value_says_which_state_the_gpu_is_in() {
        let mut app = App::new();
        app.chain = ChainKind::Evm;

        app.gpu_status = GpuStatus::Ready { device: "Apple M1".to_string() };
        app.gpu_requested = true;
        assert_eq!(gpu_form_value(&app).0, "[On]");

        app.gpu_requested = false;
        assert_eq!(gpu_form_value(&app).0, "[Off]");

        app.gpu_requested = true;
        app.chain = ChainKind::Solana;
        assert_eq!(gpu_form_value(&app).0, "[n/a — EVM only]");

        app.chain = ChainKind::Evm;
        app.gpu_status = GpuStatus::Unavailable("not supported on this target".to_string());
        assert_eq!(gpu_form_value(&app).0, "[n/a — no Metal device]");

        app.gpu_status =
            GpuStatus::Disabled(GpuDisableReason::VerifyMismatch { address: "0xdead".to_string() });
        assert_eq!(gpu_form_value(&app).0, "[disabled — VerifyMismatch]");
    }

    #[test]
    fn gpu_form_value_never_leaks_a_multi_line_compiler_diagnostic() {
        let mut app = App::new();
        app.chain = ChainKind::Evm;
        app.gpu_status = GpuStatus::Disabled(GpuDisableReason::ShaderCompile(
            "program_source:14:3: error: use of undeclared identifier\nnote: here".to_string(),
        ));
        let (text, _) = gpu_form_value(&app);
        assert!(!text.contains('\n'), "a newline in a ratatui Buffer corrupts the frame: {text:?}");
        assert_eq!(text, "[disabled — ShaderCompile]");
    }

    #[test]
    fn config_form_puts_the_gpu_row_between_case_and_threads() {
        let mut app = App::new();
        app.chain = ChainKind::Evm;
        app.gpu_status = GpuStatus::Ready { device: "Apple M1".to_string() };
        app.gpu_requested = true;

        for pos in [
            MatchPosition::StartsWith,
            MatchPosition::EndsWith,
            MatchPosition::StartsAndEndsWith,
        ] {
            app.match_position = pos;
            let frame = render_to_string(&app, 100, 40);
            let rows: Vec<&str> = frame.lines().collect();
            let case = rows.iter().position(|r| r.contains("Case:")).expect("Case row");
            // `GPU:` is the CONFIG row's label. The Stats pane's row is
            // labelled `GPU rate:` (Task 7.5) precisely so this substring
            // stays unambiguous — do not rename either one to match.
            let gpu = rows.iter().position(|r| r.contains("GPU:")).expect("GPU row");
            let threads = rows.iter().position(|r| r.contains("Threads:")).expect("Threads row");
            assert!(
                case < gpu && gpu < threads,
                "row order must be Case, GPU, Threads; got {case}, {gpu}, {threads}\n{frame}"
            );
        }
    }
```

- [ ] **Step 2: Run the tests and watch them fail to compile.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo test --bin vanaddy ui::tests:: 2>&1 | head -30
```

Expect:

```
error[E0425]: cannot find function `sanitize_status_text` in this scope
error[E0425]: cannot find function `gpu_form_value` in this scope
```

- [ ] **Step 3: Import the GPU types into `src/ui.rs`.** Insert after line 3 (`use super::matcher::MatchPosition;`) — line numbers are pre-branch; match on the quoted text:

```rust
use crate::gpu::{GpuDisableReason, GpuStatus};
```

- [ ] **Step 4: Add the four helpers.** Insert into `/Users/shawnhopkinson/Rust/Vanaddy/src/ui.rs` immediately after `render_config_form` ends (pre-branch line 199, the `}` before the `/// Rows the stats block needs` doc comment) — line numbers are pre-branch; match on the quoted text:

```rust
/// Flatten a status string for display in a ratatui Buffer.
/// `GpuDisableReason::ShaderCompile(String)` carries multi-line Metal compiler
/// diagnostics; a raw newline or tab written into a cell corrupts the frame.
/// Every control character becomes a space, and the result is truncated on a
/// CHAR boundary (byte slicing would panic on the '—' this UI is full of).
fn sanitize_status_text(s: &str, max: usize) -> String {
    let cleaned: String = s
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    if cleaned.chars().count() <= max {
        return cleaned;
    }
    let mut out: String = cleaned.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}

/// Bare variant name, for the config form's narrow value column. The payload —
/// a compiler diagnostic, a wave index, an address — goes to the Stats pane's
/// fault line instead, which is where the user looks once a fault has fired.
fn gpu_reason_label(r: &GpuDisableReason) -> &'static str {
    match r {
        GpuDisableReason::NotSupported => "NotSupported",
        GpuDisableReason::NoDevice => "NoDevice",
        GpuDisableReason::UserOff => "UserOff",
        GpuDisableReason::ShaderCompile(_) => "ShaderCompile",
        GpuDisableReason::PipelineCreate(_) => "PipelineCreate",
        GpuDisableReason::BufferAlloc => "BufferAlloc",
        GpuDisableReason::BadConfig(_) => "BadConfig",
        GpuDisableReason::SelfTest(_) => "SelfTest",
        GpuDisableReason::CommandBuffer { .. } => "CommandBuffer",
        GpuDisableReason::AuditMismatch { .. } => "AuditMismatch",
        GpuDisableReason::VerifyMismatch { .. } => "VerifyMismatch",
        GpuDisableReason::Panicked => "Panicked",
    }
}

/// The GPU field's value text and its style.
/// Precedence: no device beats disabled beats wrong-chain beats the toggle —
/// the same order as the input arm's refusal, so what the form shows and what
/// pressing `y` does can never disagree.
fn gpu_form_value(app: &App) -> (String, Style) {
    let dimmed = Style::default().fg(Color::DarkGray);
    match &app.gpu_status {
        GpuStatus::Unavailable(_) => ("[n/a — no Metal device]".to_string(), dimmed),
        GpuStatus::Disabled(r) => (
            format!("[disabled — {}]", gpu_reason_label(r)),
            Style::default().fg(Color::Red),
        ),
        _ if app.chain != ChainKind::Evm => ("[n/a — EVM only]".to_string(), dimmed),
        _ if app.gpu_requested => ("[On]".to_string(), Style::default().fg(Color::Green)),
        _ => ("[Off]".to_string(), Style::default().fg(Color::White)),
    }
}

/// The GPU config-form row. The LABEL keeps the normal focus styling so the
/// field stays discoverable and navigable even when the GPU cannot run; the
/// VALUE carries the disabled styling and the reason — visibly disabled, never
/// silently ignored.
fn gpu_form_line(app: &App, label_style: Style) -> Line<'static> {
    let (value, value_style) = gpu_form_value(app);
    Line::from(vec![
        Span::styled(" GPU:      ", label_style),
        Span::styled(value, value_style),
    ])
}
```

- [ ] **Step 5: Insert the row into the `both` branch.** In `/Users/shawnhopkinson/Rust/Vanaddy/src/ui.rs`, replace the ` Case:     ` row push through the ` Threads:  ` row push in the `both` branch — pre-branch lines 130-140, already shifted by one by Step 3's import, so line numbers are pre-branch; match on the quoted text (Threads moves from field 5 to field 6):

```rust
        lines.push(Line::from(vec![
            Span::styled(" Case:     ", style_for(4)),
            Span::styled(format!("[{}]", case_str), style_for(4)),
        ]));
        lines.push(gpu_form_line(app, style_for(5)));
        lines.push(Line::from(vec![
            Span::styled(" Threads:  ", style_for(6)),
            Span::styled(
                if app.thread_count.is_empty() { "_".to_string() } else { app.thread_count.clone() },
                style_for(6),
            ),
        ]));
```

- [ ] **Step 6: Insert the row into the `else` branch.** Replace the ` Case:     ` row push through the ` Threads:  ` row push in the `else` branch — pre-branch lines 158-168, already shifted by one by Step 3's import, so line numbers are pre-branch; match on the quoted text (Threads moves from field 4 to field 5):

```rust
        lines.push(Line::from(vec![
            Span::styled(" Case:     ", style_for(3)),
            Span::styled(format!("[{}]", case_str), style_for(3)),
        ]));
        lines.push(gpu_form_line(app, style_for(4)));
        lines.push(Line::from(vec![
            Span::styled(" Threads:  ", style_for(5)),
            Span::styled(
                if app.thread_count.is_empty() { "_".to_string() } else { app.thread_count.clone() },
                style_for(5),
            ),
        ]));
```

- [ ] **Step 7: Run the tests and watch them pass.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo test --bin vanaddy ui::tests:: 2>&1 | tail -20
```

Expect `test result: ok.` with 13 passed (7 pre-existing formatters plus the 6 new ones).

- [ ] **Step 8: Run the whole suite and commit.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo test 2>&1 | tail -8
```

Expect `test result: ok.` with 0 failed, then:

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && git add -A && git commit -m "ui: GPU row in the config form

Label keeps focus styling so the field stays navigable; the value carries
the disabled styling and the reason. sanitize_status_text flattens the
multi-line Metal compiler diagnostics that ShaderCompile can carry —
a raw newline in a ratatui Buffer corrupts the frame.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 7.4: `App::gpu_measured_rate` — measured, never modelled

**Files:**
- Modify: `/Users/shawnhopkinson/Rust/Vanaddy/src/app.rs` — new method on `impl App`, after `projected_seconds` (which ends at line 172)
- Test: `/Users/shawnhopkinson/Rust/Vanaddy/src/app.rs` `#[cfg(test)] mod tests`

**Interfaces:**
- Consumes: `App::gpu_health: Arc<crate::gpu::GpuHealth>`; `GpuHealth::seeds_delivered: AtomicU64` (incremented by `drain_gpu_block` as workers actually consume GPU blocks); `App::counter: Arc<AtomicU64>`; `App::start_time: Option<Instant>`
- Produces: `pub fn gpu_measured_rate(&self) -> (u64, u8)`

The spec is emphatic about why this is not a formula:

> The displayed GPU rate must be **measured** from wave completion times published into an `AtomicU64`, never modelled — mid-run throughput collapse to 3,000–7,000 seeds/s was reproducibly observed while the desktop compositor was busy, and a modelled rate would lie by up to 4×.

- [ ] **Step 1: Add the tests.** Append inside `mod tests` in `/Users/shawnhopkinson/Rust/Vanaddy/src/app.rs`:

```rust
    #[test]
    fn gpu_measured_rate_is_derived_from_seeds_delivered_not_modelled() {
        let mut app = App::new();
        app.start_time = Some(
            Instant::now()
                .checked_sub(Duration::from_secs(10))
                .expect("the monotonic clock is at least 10 s past boot"),
        );
        app.counter.store(200_000, Ordering::Relaxed);
        app.gpu_health.seeds_delivered.store(136_000, Ordering::Relaxed);

        let (rate, share) = app.gpu_measured_rate();
        assert!(
            (13_400..=13_600).contains(&rate),
            "136,000 delivered seeds over 10 s of wall time is ~13,600/s, got {rate}"
        );
        assert_eq!(share, 68, "136,000 of 200,000 candidates came from the GPU");
    }

    #[test]
    fn gpu_measured_rate_is_zero_before_a_search_starts() {
        let app = App::new();
        assert_eq!(
            app.gpu_measured_rate(),
            (0, 0),
            "no elapsed time means no measurement — never a modelled guess"
        );
    }

    #[test]
    fn gpu_measured_rate_share_cannot_exceed_100_percent() {
        let mut app = App::new();
        app.start_time = Some(
            Instant::now()
                .checked_sub(Duration::from_secs(1))
                .expect("the monotonic clock is at least 1 s past boot"),
        );
        // The worker increments `counter` and `seeds_delivered` separately, so
        // a UI tick can land between the two stores.
        app.counter.store(100, Ordering::Relaxed);
        app.gpu_health.seeds_delivered.store(400, Ordering::Relaxed);
        assert_eq!(app.gpu_measured_rate().1, 100, "share is clamped, never 400%");
    }
```

- [ ] **Step 2: Run the tests and watch them fail to compile.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo test --bin vanaddy app::tests::gpu_measured 2>&1 | head -20
```

Expect:

```
error[E0599]: no method named `gpu_measured_rate` found for struct `App` in the current scope
```

- [ ] **Step 3: Add the method.** Insert into `/Users/shawnhopkinson/Rust/Vanaddy/src/app.rs` immediately after `projected_seconds` (after its closing `}`, pre-branch line 172, before `pub fn validate`) — line numbers are pre-branch; match on the quoted text:

```rust
    /// Measured GPU throughput: `(seeds per second, percent of all candidates
    /// checked)`. Derived only from `GpuHealth::seeds_delivered` — which the
    /// workers increment as they actually consume GPU blocks — over observed
    /// wall time. NEVER modelled: mid-run throughput collapse to 3,000-7,000
    /// seeds/s was reproducibly observed while the desktop compositor was
    /// busy, and a modelled rate would lie by up to 4x.
    pub fn gpu_measured_rate(&self) -> (u64, u8) {
        let Some(start) = self.start_time else {
            return (0, 0);
        };
        let secs = start.elapsed().as_secs_f64().max(0.5);
        let gpu = self.gpu_health.seeds_delivered.load(Ordering::Relaxed);
        let total = self.counter.load(Ordering::Relaxed);
        // `counter` and `seeds_delivered` are two separate stores, so a UI tick
        // can observe them out of step; clamp instead of printing 400%.
        let share = if total == 0 {
            0
        } else {
            ((gpu.min(total) as f64 / total as f64) * 100.0).round() as u8
        };
        ((gpu as f64 / secs) as u64, share)
    }
```

- [ ] **Step 4: Run the tests and watch them pass.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo test --bin vanaddy app::tests::gpu_measured 2>&1 | tail -10
```

Expect `test result: ok.` with 3 passed.

- [ ] **Step 5: Run the whole suite and commit.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo test 2>&1 | tail -8
```

Expect `test result: ok.` with 0 failed, then:

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && git add -A && git commit -m "app: measured GPU rate from seeds_delivered over wall time

Never modelled. Compositor contention was measured collapsing GPU
throughput to 3-7k seeds/s mid-run; a formula would lie by up to 4x.
Share is clamped because counter and seeds_delivered are separate
stores and a UI tick can land between them.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 7.5: The Stats pane's GPU row and `stats_height`

**Files:**
- Modify: `/Users/shawnhopkinson/Rust/Vanaddy/src/ui.rs` — `stats_height` (pre-branch lines 201-206) and the end of the `lines` vec in `render_stats` (pre-branch line 238). Task 7.3 has already grown this file; match on text, not on the ranges.
- Modify: `/Users/shawnhopkinson/Rust/Vanaddy/src/ui.rs` — new `gpu_stats_line` helper before `stats_height`
- Test: `/Users/shawnhopkinson/Rust/Vanaddy/src/ui.rs` `#[cfg(test)] mod tests`

**Interfaces:**
- Consumes: `App::gpu_measured_rate(&self) -> (u64, u8)` (Task 7.4); `sanitize_status_text(&str, usize) -> String` (Task 7.3); `format_count(u64) -> String` (`src/ui.rs:434`); `crate::gpu::GpuStatus`
- Produces: `fn gpu_stats_line(app: &App) -> Option<(String, Color)>`; `stats_height(app: &App) -> u16` (signature unchanged)

The spec's constraint on `stats_height`:

> `stats_height()` must not count both a live line and a fault line (setting `gpu_rx = None` in the fault-promotion block prevents the doubled `GPU:` row).

We do better than relying on that: **one function decides whether the row exists, and both the renderer and the height calculation call it**, so they cannot disagree by construction.

- [ ] **Step 1: Add the tests.** Append inside `mod tests` in `/Users/shawnhopkinson/Rust/Vanaddy/src/ui.rs`:

```rust
    fn searching_app_with_gpu(status: GpuStatus) -> App {
        let mut app = App::new();
        app.chain = ChainKind::Evm;
        app.gpu_requested = true;
        app.gpu_status = status;
        app.state = AppState::Searching;
        app.start_time = Some(
            std::time::Instant::now()
                .checked_sub(std::time::Duration::from_secs(10))
                .expect("the monotonic clock is at least 10 s past boot"),
        );
        app.counter.store(200_000, std::sync::atomic::Ordering::Relaxed);
        app.gpu_health
            .seeds_delivered
            .store(136_000, std::sync::atomic::Ordering::Relaxed);
        app
    }

    #[test]
    fn gpu_stats_line_is_absent_when_there_is_nothing_to_report() {
        let mut app = App::new();
        app.gpu_status = GpuStatus::Ready { device: "Apple M1".to_string() };
        assert!(gpu_stats_line(&app).is_none(), "a probed-but-idle GPU gets no stats row");

        app.gpu_status = GpuStatus::Unavailable("not supported on this target".to_string());
        assert!(gpu_stats_line(&app).is_none(), "an absent GPU gets no stats row");
    }

    #[test]
    fn gpu_stats_line_reports_the_measured_rate_and_share() {
        let app = searching_app_with_gpu(GpuStatus::Running { device: "Apple M1".to_string() });
        let (text, color) = gpu_stats_line(&app).expect("a running GPU gets a stats row");
        assert!(text.contains("Apple M1"), "must name the device: {text}");
        assert!(text.contains("13.6K/s"), "must show the measured rate: {text}");
        assert!(text.contains("(68%)"), "must show the GPU's share of candidates: {text}");
        assert_eq!(color, Color::Green);
    }

    #[test]
    fn gpu_stats_line_reports_a_fault_without_control_characters() {
        let app = searching_app_with_gpu(GpuStatus::Disabled(GpuDisableReason::ShaderCompile(
            "program_source:14:3: error: use of undeclared identifier\nnote: here".to_string(),
        )));
        let (text, color) = gpu_stats_line(&app).expect("a fault always gets a stats row");
        assert!(!text.contains('\n'), "a newline in a ratatui Buffer corrupts the frame: {text:?}");
        assert!(!text.contains('\t'), "a tab in a ratatui Buffer corrupts the frame: {text:?}");
        assert!(text.contains("OFF"), "must say the GPU is off: {text}");
        assert!(text.contains("ShaderCompile"), "must carry the reason: {text}");
        assert!(
            text.contains("CPU search continues"),
            "the user must know the search did not die: {text}"
        );
        assert_eq!(color, Color::Red);
    }

    #[test]
    fn gpu_stats_line_announces_initialisation() {
        let app = searching_app_with_gpu(GpuStatus::Initializing);
        let (text, _) = gpu_stats_line(&app).expect("initialising gets a stats row");
        assert!(text.contains("initialising"), "the ~300 ms self-test must be visible: {text}");
    }

    #[test]
    fn stats_height_counts_the_gpu_row_exactly_once() {
        let mut app = App::new();
        app.chain = ChainKind::Evm;
        app.gpu_status = GpuStatus::Ready { device: "Apple M1".to_string() };
        let base = stats_height(&app);

        app.gpu_status = GpuStatus::Running { device: "Apple M1".to_string() };
        assert_eq!(stats_height(&app), base + 1, "the live row needs exactly one line");

        app.gpu_status = GpuStatus::Disabled(GpuDisableReason::AuditMismatch { index: 5183 });
        assert_eq!(
            stats_height(&app),
            base + 1,
            "a fault row REPLACES the live row; it never adds a second GPU line"
        );
    }

    #[test]
    fn stats_pane_renders_the_gpu_row_while_searching() {
        let app = searching_app_with_gpu(GpuStatus::Running { device: "Apple M1".to_string() });
        let frame = render_to_string(&app, 100, 40);
        let rows: Vec<&str> = frame.lines().collect();
        let rate = rows.iter().position(|r| r.contains("Rate:")).expect("Rate row");
        // `GPU rate:` — the Stats row's label. The config form's ` GPU:      `
        // row renders in the same panel ABOVE this one, so grepping for `GPU:`
        // here would find the wrong row.
        let gpu = rows
            .iter()
            .position(|r| r.contains("GPU rate:"))
            .expect("GPU row in the Stats pane");
        assert_eq!(gpu, rate + 1, "the GPU row belongs directly under Rate:\n{frame}");
    }
```

- [ ] **Step 2: Run the tests and watch them fail to compile.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo test --bin vanaddy ui::tests:: 2>&1 | head -20
```

Expect:

```
error[E0425]: cannot find function `gpu_stats_line` in this scope
```

- [ ] **Step 3: Add `gpu_stats_line`.** Insert into `/Users/shawnhopkinson/Rust/Vanaddy/src/ui.rs` immediately before the `/// Rows the stats block needs` doc comment (pre-branch line 201) — line numbers are pre-branch; match on the quoted text:

```rust
/// The single source of truth for the Stats pane's GPU row: `render_stats`
/// draws it and `stats_height` counts it, so the two can never disagree about
/// whether the row is there. Exactly one row — a fault REPLACES the live rate,
/// it never adds a second `GPU rate:` line. `None` means no row at all.
///
/// The label is `GPU rate:`, NOT `GPU:`. The config form's row (Task 7.3) is
/// labelled ` GPU:      ` and renders in the same left-hand panel, above this
/// one; a test that greps the rendered frame for `GPU:` would find the config
/// row first. Both labels are 11 columns, so the value columns still line up.
fn gpu_stats_line(app: &App) -> Option<(String, Color)> {
    match &app.gpu_status {
        GpuStatus::Disabled(r) => Some((
            format!(
                " GPU rate: OFF — {} (CPU search continues)",
                sanitize_status_text(&format!("{r:?}"), 40)
            ),
            Color::Red,
        )),
        GpuStatus::Initializing => Some((
            " GPU rate: initialising (compiling shader, self-testing)".to_string(),
            Color::Yellow,
        )),
        GpuStatus::Running { device } => {
            // MEASURED per delivery, never modelled — see App::gpu_measured_rate.
            let (rate, share) = app.gpu_measured_rate();
            Some((
                format!(
                    " GPU rate: {}  {}/s ({share}%)",
                    sanitize_status_text(device, 24),
                    format_count(rate)
                ),
                Color::Green,
            ))
        }
        // Probed but not started, or no device: the config form says so, the
        // Stats pane stays quiet.
        GpuStatus::Ready { .. } | GpuStatus::Unavailable(_) => None,
    }
}
```

- [ ] **Step 4: Teach `stats_height` to count it.** Task 7.3 added an import and roughly 70 lines of helpers to `/Users/shawnhopkinson/Rust/Vanaddy/src/ui.rs`, and Step 3 above inserted `gpu_stats_line` directly on top of `stats_height`, so this function is no longer at lines 201-206 — **match on the text, not on a line range.** The block to replace is the whole of `stats_height` together with its one-line doc comment, verbatim as it stands:

```rust
/// Rows the stats block needs: 4 fixed lines, the optional Expected/ETA lines, plus borders.
fn stats_height(app: &App) -> u16 {
    let optional =
        u16::from(app.expected_attempts().is_some()) + u16::from(app.projected_seconds().is_some());
    4 + optional + 2
}
```

Confirm there is exactly one match before you touch anything:

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && grep -c '^fn stats_height(app: &App) -> u16 {$' src/ui.rs
```

Expect `1`. Replace those six lines — doc comment through closing brace, inclusive — with:

```rust
/// Rows the stats block needs: 4 fixed lines, the optional GPU row, the
/// optional Expected/ETA lines, plus borders. The GPU row is counted through
/// `gpu_stats_line` — the same function `render_stats` draws from — so the
/// height can never disagree with what is rendered.
fn stats_height(app: &App) -> u16 {
    let optional = u16::from(app.expected_attempts().is_some())
        + u16::from(app.projected_seconds().is_some())
        + u16::from(gpu_stats_line(app).is_some());
    4 + optional + 2
}
```

- [ ] **Step 5: Draw it.** In `render_stats`, insert directly after the `let mut lines = vec![ ... ];` statement ends (its closing `];`, pre-branch line 238) and before the `if let Some(attempts) = expected {` (pre-branch line 240) — line numbers are pre-branch; match on the quoted text:

```rust
    // Directly under Rate: the GPU's contribution to the rate above it.
    if let Some((text, color)) = gpu_stats_line(app) {
        lines.insert(2, Line::from(Span::styled(text, Style::default().fg(color))));
    }
```

- [ ] **Step 6: Run the tests and watch them pass.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo test --bin vanaddy ui::tests:: 2>&1 | tail -20
```

Expect `test result: ok.` with 19 passed.

- [ ] **Step 7: Run the whole suite and commit.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo test 2>&1 | tail -8
```

Expect `test result: ok.` with 0 failed, then:

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && git add -A && git commit -m "ui: GPU row in the Stats pane, measured rate and fault line

One function decides whether the row exists; render_stats draws from it
and stats_height counts from it, so a fault row can never be counted on
top of a live row. Reason text is sanitized and truncated because
ShaderCompile carries multi-line Metal compiler diagnostics.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 7.6: Help popup entries

**Files:**
- Modify: `/Users/shawnhopkinson/Rust/Vanaddy/src/ui.rs` — `render_help_popup` (pre-branch lines 273-321). Tasks 7.3 and 7.5 have already grown this file; match on text, not on the range.
- Test: `/Users/shawnhopkinson/Rust/Vanaddy/src/ui.rs` `#[cfg(test)] mod tests`

**Interfaces:**
- Consumes: nothing new
- Produces: `const HELP_POPUP_WIDTH: u16 = 56;`, `const HELP_POPUP_HEIGHT: u16 = 29;`, `fn help_lines() -> Vec<Line<'static>>`

The popup is a fixed 56×26 rectangle with a border, so it can show 24 lines — and the current list is already **26 lines long**, meaning the last two entries ("`4=TON     5=Monero`" and "`Monero generation is slower (crypto intrinsic)`") are silently clipped today. Adding an entry without fixing the height makes that worse. The extraction below exists so a test can catch it.

- [ ] **Step 1: Add the test.** Append inside `mod tests` in `/Users/shawnhopkinson/Rust/Vanaddy/src/ui.rs`:

```rust
    #[test]
    fn help_popup_documents_gpu_offload_and_nothing_is_clipped() {
        let lines = help_lines();

        assert!(
            lines.len() + 2 <= HELP_POPUP_HEIGHT as usize,
            "the help popup is {HELP_POPUP_HEIGHT} rows tall (2 of them border) but the list has \
             {} lines — the last entries would be silently clipped",
            lines.len()
        );
        for (i, line) in lines.iter().enumerate() {
            assert!(
                line.width() + 2 <= HELP_POPUP_WIDTH as usize,
                "help line {i} is {} columns wide, the popup's inner width is {}: {line}",
                line.width(),
                HELP_POPUP_WIDTH - 2
            );
        }

        let text: String = lines.iter().map(|l| format!("{l}\n")).collect();
        assert!(
            text.contains("Case sensitivity, GPU offload"),
            "the y/n hint must mention the GPU field:\n{text}"
        );
        assert!(
            text.contains("Metal PBKDF2, EVM only (Apple Silicon)"),
            "help must explain what GPU offload actually is:\n{text}"
        );
    }

    #[test]
    fn help_popup_renders_the_gpu_entry() {
        let mut app = App::new();
        app.show_help = true;
        let frame = render_to_string(&app, 100, 40);
        assert!(
            frame.contains("Metal PBKDF2, EVM only (Apple Silicon)"),
            "the GPU entry must survive the render, not fall off the popup:\n{frame}"
        );
        assert!(
            frame.contains("Monero generation is slower"),
            "the last pre-existing entry must still be visible:\n{frame}"
        );
    }
```

- [ ] **Step 2: Run the tests and watch them fail to compile.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo test --bin vanaddy ui::tests::help 2>&1 | head -20
```

Expect:

```
error[E0425]: cannot find function `help_lines` in this scope
error[E0425]: cannot find value `HELP_POPUP_HEIGHT` in this scope
```

- [ ] **Step 3: Replace `render_help_popup` with the extracted version.** Tasks 7.3 and 7.5 have grown `/Users/shawnhopkinson/Rust/Vanaddy/src/ui.rs` by well over a hundred lines, so `render_help_popup` is no longer at lines 273-321 — **match on the text, not on a line range.** The block to replace is the whole function, verbatim as it stands:

```rust
fn render_help_popup(f: &mut Frame, area: Rect) {
    // Center a popup ~60x18
    let popup_width = 56.min(area.width.saturating_sub(4));
    let popup_height = 26.min(area.height.saturating_sub(4));
    let x = (area.width.saturating_sub(popup_width)) / 2;
    let y = (area.height.saturating_sub(popup_height)) / 2;
    let popup_area = Rect::new(x, y, popup_width, popup_height);

    // Clear background
    let clear = Block::default().style(Style::default().bg(Color::Black));
    f.render_widget(clear, popup_area);

    let lines = vec![
        Line::from(Span::styled(" Navigation", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))),
        Line::from(""),
        Line::from("  Up/Down      Move between fields"),
        Line::from("  Tab          Next field"),
        Line::from("  Shift-Tab    Previous field"),
        Line::from(""),
        Line::from(Span::styled(" Field Input", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))),
        Line::from(""),
        Line::from("  Left/Right   Toggle options (chain, match, case)"),
        Line::from("  1/2/3        Select option directly"),
        Line::from("  y/n          Case sensitivity"),
        Line::from("  Type         Text input (prefix, suffix, threads)"),
        Line::from("  Backspace    Delete character"),
        Line::from(""),
        Line::from(Span::styled(" Actions", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))),
        Line::from(""),
        Line::from("  Enter        Start search"),
        Line::from("  Ctrl+C       Stop search"),
        Line::from("  q            Quit (not in text fields)"),
        Line::from("  h            Toggle this help"),
        Line::from(""),
        Line::from(Span::styled(" Supported Chains", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))),
        Line::from(""),
        Line::from("  1=Solana  2=EVM  3=Bitcoin"),
        Line::from("  4=TON     5=Monero"),
        Line::from("  Monero generation is slower (crypto intrinsic)"),
    ];

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan))
        .title(" Help ")
        .style(Style::default().bg(Color::Black));
    let paragraph = Paragraph::new(lines).block(block);
    f.render_widget(paragraph, popup_area);
}
```

Confirm there is exactly one match before you touch anything:

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && grep -c '^fn render_help_popup(f: &mut Frame, area: Rect) {$' src/ui.rs
```

Expect `1`. The function runs from that signature down to the closing `}` immediately before `fn render_right_panel`. Replace it whole — signature through closing brace, inclusive — with:

```rust
/// The popup is a fixed rectangle, so its content list has a hard budget:
/// `HELP_POPUP_HEIGHT - 2` lines of at most `HELP_POPUP_WIDTH - 2` columns.
/// Overrun either and Paragraph clips silently — the entry simply is not there.
const HELP_POPUP_WIDTH: u16 = 56;
const HELP_POPUP_HEIGHT: u16 = 29;

/// Extracted from `render_help_popup` so a test can measure it against the
/// popup it has to fit inside. Adding an entry without raising
/// `HELP_POPUP_HEIGHT` clips the LAST entries, not the new one.
fn help_lines() -> Vec<Line<'static>> {
    vec![
        Line::from(Span::styled(" Navigation", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))),
        Line::from(""),
        Line::from("  Up/Down      Move between fields"),
        Line::from("  Tab          Next field"),
        Line::from("  Shift-Tab    Previous field"),
        Line::from(""),
        Line::from(Span::styled(" Field Input", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))),
        Line::from(""),
        Line::from("  Left/Right   Toggle options (chain, match, case)"),
        Line::from("  1/2/3        Select option directly"),
        Line::from("  y/n          Case sensitivity, GPU offload"),
        Line::from("  GPU offload  Metal PBKDF2, EVM only (Apple Silicon)"),
        Line::from("  Type         Text input (prefix, suffix, threads)"),
        Line::from("  Backspace    Delete character"),
        Line::from(""),
        Line::from(Span::styled(" Actions", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))),
        Line::from(""),
        Line::from("  Enter        Start search"),
        Line::from("  Ctrl+C       Stop search"),
        Line::from("  q            Quit (not in text fields)"),
        Line::from("  h            Toggle this help"),
        Line::from(""),
        Line::from(Span::styled(" Supported Chains", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))),
        Line::from(""),
        Line::from("  1=Solana  2=EVM  3=Bitcoin"),
        Line::from("  4=TON     5=Monero"),
        Line::from("  Monero generation is slower (crypto intrinsic)"),
    ]
}

fn render_help_popup(f: &mut Frame, area: Rect) {
    let popup_width = HELP_POPUP_WIDTH.min(area.width.saturating_sub(4));
    let popup_height = HELP_POPUP_HEIGHT.min(area.height.saturating_sub(4));
    let x = (area.width.saturating_sub(popup_width)) / 2;
    let y = (area.height.saturating_sub(popup_height)) / 2;
    let popup_area = Rect::new(x, y, popup_width, popup_height);

    // Clear background
    let clear = Block::default().style(Style::default().bg(Color::Black));
    f.render_widget(clear, popup_area);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan))
        .title(" Help ")
        .style(Style::default().bg(Color::Black));
    let paragraph = Paragraph::new(help_lines()).block(block);
    f.render_widget(paragraph, popup_area);
}
```

- [ ] **Step 4: Run the tests and watch them pass.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo test --bin vanaddy ui::tests::help 2>&1 | tail -10
```

Expect `test result: ok.` with 2 passed.

- [ ] **Step 5: Run the whole suite and commit.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo test 2>&1 | tail -8
```

Expect `test result: ok.` with 0 failed, then:

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && git add -A && git commit -m "ui: document GPU offload in the help popup

Extracts help_lines() so a test can measure it against the popup it must
fit in. The list was already 26 lines inside a 24-line popup, so the last
two entries were being clipped; height 26 -> 29 fixes that and
makes room for the GPU entry.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 7.7: `estimated_rate` — the pre-search hybrid ETA

**Files:**
- Modify: `/Users/shawnhopkinson/Rust/Vanaddy/src/app.rs` lines 146-172 (`single_thread_rate`, `projected_seconds`)
- Test: `/Users/shawnhopkinson/Rust/Vanaddy/src/app.rs` `#[cfg(test)] mod tests`

**Interfaces:**
- Consumes: `App::gpu_effective(&self) -> bool`; `App::single_thread_rate(&self) -> f64` (`src/app.rs:149`); `App::thread_count: String`; `pub const crate::gpu::EVM_GPU_SEEDS_PER_SEC: f64` (Task 4.8 — the SINGLE definition; do **not** redeclare it in `src/app.rs`, or Task 4.8 Step 5's live measurement never reaches the ETA)
- Produces: `const EVM_GPU_TAIL_SECS: f64 = 50.5e-6;`, `fn estimated_rate(&self) -> f64`

The spec's arithmetic, reproduced because the *why* matters:

> **Honest arithmetic, correcting two designs.** The integration design claimed this formula "reproduces the measured result: 24,981"; with the actual defaults (`threads = 8`, `single_thread_rate() = 3_115`) it yields **36,799**, because `single_thread_rate() × threads` is *already* ~1.6× optimistic on an M1 (8 threads measure 11,500–14,900 EVM cand/s, not 24,920 — four of those cores are E-cores). The kernel design separately claimed the GPU's CPU tail costs only 249 cand/s; it actually displaces `13,600 × (50.5/308.1) ≈ 2,230` CPU cand/s, ~9× more. **Honest hybrid: ~23,000–26,000 cand/s, ≈2×.** The pre-existing CPU-side optimism is *not* fixed here (it would change ETA behaviour for all five chains — a separate change with its own blast radius).

Note one deliberate correction to the spec's code sketch: it guards the GPU branch with `self.gpu_effective() && matches!(self.gpu_status, GpuStatus::Running { .. })`. That guard is dead. `projected_seconds` only reaches `estimated_rate` when `start_time` is `None` (`src/app.rs:163`), i.e. before any search has ever started — at which point the status is `Ready`, never `Running`, because the spec itself defines `Ready` as "the pre-search resting state". Keeping the guard would mean the ETA never reflects the GPU. `gpu_effective()` alone is exactly the "will the GPU actually run?" predicate, so that is what we use.

- [ ] **Step 1: Add the tests.** Append inside `mod tests` in `/Users/shawnhopkinson/Rust/Vanaddy/src/app.rs`:

```rust
    #[test]
    fn estimated_rate_without_gpu_is_unchanged() {
        let mut app = App::new();
        app.chain = ChainKind::Evm;
        app.thread_count = "8".to_string();
        app.gpu_requested = false;
        // src/app.rs:152 — EVM measures ~321 us/gen on an M1 P-core.
        assert_eq!(
            app.estimated_rate(),
            3_115.0 * 8.0,
            "with no GPU this must stay exactly threads x per-thread"
        );
    }

    #[test]
    fn estimated_rate_with_gpu_adds_the_gpu_and_charges_for_its_cpu_tail() {
        let mut app = App::new();
        app.chain = ChainKind::Evm;
        app.thread_count = "8".to_string();
        app.gpu_status = GpuStatus::Ready { device: "Apple M1".to_string() };
        app.gpu_requested = true;

        let cpu_only = 3_115.0 * 8.0;
        let hybrid = app.estimated_rate();
        assert!(hybrid > cpu_only, "the GPU must raise the estimate: {hybrid} vs {cpu_only}");
        assert!(
            hybrid < crate::gpu::EVM_GPU_SEEDS_PER_SEC + cpu_only,
            "every GPU seed still costs the CPU its BIP-32 + Keccak tail; that must be \
             charged, not free: {hybrid}"
        );
    }

    #[test]
    fn estimated_rate_ignores_the_gpu_for_a_non_evm_chain() {
        let mut app = App::new();
        app.chain = ChainKind::Solana;
        app.thread_count = "8".to_string();
        app.gpu_status = GpuStatus::Ready { device: "Apple M1".to_string() };
        app.gpu_requested = true;
        // src/app.rs:151 — Solana measures ~288 us/gen.
        assert_eq!(app.estimated_rate(), 3_470.0 * 8.0, "GPU offload is EVM-only");
    }

    #[test]
    fn estimated_rate_never_goes_backwards_on_one_thread() {
        let mut app = App::new();
        app.chain = ChainKind::Evm;
        app.thread_count = "1".to_string();
        app.gpu_status = GpuStatus::Ready { device: "Apple M1".to_string() };
        app.gpu_requested = true;
        let r = app.estimated_rate();
        assert!(
            r >= crate::gpu::EVM_GPU_SEEDS_PER_SEC,
            "the tail clamp must not let the tail eat the GPU's own throughput: {r}"
        );
    }

    #[test]
    fn estimated_rate_survives_an_unparseable_thread_count() {
        let mut app = App::new();
        app.chain = ChainKind::Evm;
        app.thread_count = String::new();
        app.gpu_requested = false;
        let r = app.estimated_rate();
        assert!(r.is_finite() && r > 0.0, "a half-typed thread count must not poison the ETA: {r}");
    }

    #[test]
    fn projected_seconds_uses_the_hybrid_estimate_before_a_search_starts() {
        let mut app = App::new();
        app.chain = ChainKind::Evm;
        app.thread_count = "8".to_string();
        app.vanity_prefix = "abc".to_string();
        app.gpu_status = GpuStatus::Ready { device: "Apple M1".to_string() };

        app.gpu_requested = false;
        let cpu = app.projected_seconds().expect("3 hex chars is a finite ETA");
        app.gpu_requested = true;
        let hybrid = app.projected_seconds().expect("3 hex chars is a finite ETA");

        assert!(hybrid < cpu, "the GPU must shorten the pre-search ETA: {hybrid} vs {cpu}");
    }
```

- [ ] **Step 2: Run the tests and watch them fail to compile.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo test --bin vanaddy app::tests::estimated 2>&1 | head -20
```

Expect:

```
error[E0599]: no method named `estimated_rate` found for struct `App` in the current scope
```

Only that one error: `crate::gpu::EVM_GPU_SEEDS_PER_SEC` already exists (Task 4.8 Step 3), so the tests resolve it fine.

- [ ] **Step 3: Add the tail constant — and only that one.** Insert into `/Users/shawnhopkinson/Rust/Vanaddy/src/app.rs` immediately before `pub enum AppState` (line 15), at module scope. Do **not** declare `EVM_GPU_SEEDS_PER_SEC` here: Task 4.8 Step 3 already defines it as `pub const crate::gpu::EVM_GPU_SEEDS_PER_SEC`, and Task 4.8 Step 5 updates that value from a live measurement. A second copy in `src/app.rs` would silently shadow the measured one and the ETA would never move.

```rust
/// Measured CPU cost of turning ONE GPU-supplied seed into an EVM candidate:
/// BIP-32 + kG + Keccak, everything PBKDF2 does not cover. This is the tail the
/// GPU cannot offload, and at 13,600 seeds/s it displaces ~0.69 of a core.
const EVM_GPU_TAIL_SECS: f64 = 50.5e-6;
```

- [ ] **Step 4: Add `estimated_rate` and route `projected_seconds` through it.** Replace the whole of `projected_seconds` in `/Users/shawnhopkinson/Rust/Vanaddy/src/app.rs` — pre-branch lines 159-172; line numbers are pre-branch, match on the quoted text — with:

```rust
    /// Pre-search throughput estimate, attempts/sec. `projected_seconds` uses
    /// this ONLY until a search has actually started; after that it uses the
    /// live measured rate, which is automatically correct because GPU
    /// candidates increment the same `counter`.
    ///
    /// The GPU does not add its seeds/s for free: every GPU seed still costs
    /// the CPU `EVM_GPU_TAIL_SECS`, so the CPU workers lose that fraction of a
    /// core. Gate on `gpu_effective()` alone — the status here is always
    /// `Ready` (the pre-search resting state), never `Running`, so also
    /// requiring `Running` would make this branch dead code.
    ///
    /// Honest hybrid on the M1 defaults: ~23,000-26,000 cand/s, about 2x.
    /// The number this returns is higher than that, because
    /// `single_thread_rate() * threads` is ALREADY ~1.6x optimistic on a
    /// 4P+4E machine. That pre-existing optimism is not fixed here — it would
    /// change ETA behaviour for all five chains — but do not attribute the
    /// post-Enter ETA jump to the GPU.
    fn estimated_rate(&self) -> f64 {
        let threads = self.thread_count.parse::<f64>().unwrap_or(1.0).max(1.0);
        let per_thread = self.single_thread_rate();
        if !self.gpu_effective() {
            return per_thread * threads;
        }
        // Single source of truth — Task 4.8 measures and owns this number.
        let gpu_rate = crate::gpu::EVM_GPU_SEEDS_PER_SEC;
        let tail = (gpu_rate * EVM_GPU_TAIL_SECS).min(threads);
        gpu_rate + (threads - tail) * per_thread
    }

    /// Projected seconds until a match. Uses live rate if searching,
    /// otherwise estimates from chain throughput × thread count (× GPU).
    pub fn projected_seconds(&self) -> Option<f64> {
        let expected = self.expected_attempts()? as f64;
        let rate = if let Some(start) = self.start_time {
            let secs = start.elapsed().as_secs_f64().max(0.5);
            let count = self.counter.load(Ordering::Relaxed) as f64;
            (count / secs).max(1.0)
        } else {
            self.estimated_rate()
        };
        Some(expected / rate)
    }
```

- [ ] **Step 5: Run the tests and watch them pass.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo test --bin vanaddy app::tests:: 2>&1 | tail -20
```

Expect `test result: ok.` with 37 passed and 1 ignored — 31 running after Task 7.4's three `gpu_measured` tests, plus this task's 6.

- [ ] **Step 6: Run the whole suite and commit.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo test 2>&1 | tail -8
```

Expect `test result: ok.` with 0 failed, then:

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && git add -A && git commit -m "app: hybrid pre-search rate estimate for the ETA

Adds the GPU's measured 13,600 seeds/s and charges for the 50.5 us CPU
tail every GPU seed still costs, which displaces ~0.69 of a core. Gated
on gpu_effective() alone: the spec sketch also required status ==
Running, but pre-search status is always Ready, so that branch was dead.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 7.8: Milestone gate — clippy and the manual TUI walkthrough

**Files:** none — this task changes no production code. If a check below fails, fix it in the task that owns that code (7.1–7.7), re-run that task's tests, and come back.

**Interfaces:**
- Consumes: everything produced by Tasks 7.1–7.7
- Produces: nothing

- [ ] **Step 1: Full suite, release-mode too.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo test 2>&1 | tail -8 && cargo build --release 2>&1 | tail -3
```

Expect `test result: ok.` with 0 failed, and `Finished \`release\` profile`.

- [ ] **Step 2: Confirm this milestone added no clippy warnings.** `cargo clippy --all-targets` is **not** warning-free on the baseline, so the gate is a baseline comparison, never "expect no warnings". The clean tree emits exactly **12** diagnostics (`src/app.rs:51,357,522,543,548`, `src/chains/bitcoin.rs:16`, `src/chains/evm.rs:96,103`, `src/chains/ton_cell.rs:48,54,385`, `src/ui.rs:212`):

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo clippy --all-targets 2>&1 | grep -- '-->' | sort | uniq -c
```

Expect exactly 12 lines, naming only those five files — the same set Milestone 1 Task 1.8 Step 5 recorded. The `src/app.rs` and `src/ui.rs` line numbers shift as this milestone edits those files; the COUNT of 12 must not change, and no new file may appear. The 12 pre-existing lints are out of scope here.

Then confirm none of them points at code this milestone wrote:

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo clippy --all-targets 2>&1 | grep -E "gpu_form_value|gpu_form_line|gpu_stats_line|sanitize_status_text|gpu_reason_label|help_lines|gpu_measured_rate|estimated_rate|field_count"
```

Expect **no output**. Any hit names a function this milestone added; fix it in that function's task.

- [ ] **Step 3: Launch the TUI.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && cargo run --release
```

Resize the terminal to at least 160 columns first — the config panel is 25% of the width, so at 100 columns the value `[disabled — VerifyMismatch]` clips exactly the way the existing `[Starts & Ends]` row already clips at ≤104 columns. That is pre-existing behaviour, not a regression from this milestone.

- [ ] **Step 4: Walk the fields.** With the default chain (Solana): press `Tab` six times and confirm the yellow highlight visits Chain → Match → Prefix → Case → **GPU** → Threads → back to Chain. Confirm the GPU row reads `[n/a — EVM only]` in dark grey. Press `Shift-Tab` once from Chain and confirm it lands on Threads, not GPU.

- [ ] **Step 5: Confirm Threads still edits.** `Tab` to Threads, press Backspace until empty, type `4`, and confirm the value shows `4`. Then press `Down` (Tab equivalent) to wrap to Chain, press `2` for EVM, and `Tab` back to Threads to confirm the value persisted.

- [ ] **Step 6: Toggle the GPU field.** With the chain on EVM, `Tab` to GPU. Press `y` → `[On]` in green. Press `n` → `[Off]`. Press `Right` → `[On]`. Press `Left` → `[Off]`. Press `y` again, then `Tab` to Chain, press `1` (Solana), press `2` (EVM), `Tab` back to GPU — it must still read `[On]`.

- [ ] **Step 7: Confirm the refusal is loud, not silent.** With GPU `[On]`, go to Chain and press `5` (Monero). The GPU row must now read `[n/a — EVM only]`. `Tab` to GPU and press `y` — a red error line must appear under the form reading `GPU offload is EVM-only — Monero runs on CPU`, and the value must stay `[n/a — EVM only]`.

- [ ] **Step 8: Confirm `q` and `h` still work from the GPU field.** `Tab` to the GPU field and press `h` — the help popup must open, and it must show `y/n          Case sensitivity, GPU offload`, `GPU offload  Metal PBKDF2, EVM only (Apple Silicon)`, **and** the final line `Monero generation is slower (crypto intrinsic)` (that last one proves nothing is clipped off the bottom). Press any key to dismiss. Press `q` — the app must quit.

- [ ] **Step 9: Watch the live GPU stats row.** Re-launch, set Chain = EVM, Prefix = `ab`, GPU = `[On]`, press Enter. Within the first second the Stats pane must show a yellow ` GPU rate: initialising (compiling shader, self-testing)` row directly under `Rate:`; within ~1 s that must become a green ` GPU rate: Apple M1  <rate>/s (<n>%)`. The Stats label is `GPU rate:`; the `GPU:` row further up is the config form's. Confirm:
  - the Stats block's border does not jump or overlap the Config block above it as the row appears and changes (that is `stats_height` agreeing with `render_stats`);
  - the percentage is between 1 and 100;
  - the rate is in the thousands, not zero, and not a suspiciously round modelled number.

  Press Ctrl+C to stop, then Enter to start again, and confirm the row comes back without the pane's height glitching.

- [ ] **Step 10: Confirm a fault renders cleanly.** Faults cannot be provoked from the UI, so verify the rendering path by temporarily forcing a status. In `src/ui.rs`, at the very top of `gpu_stats_line`, insert this line, run the TUI, start an EVM search, and read the row:

```rust
    return Some((format!(" GPU rate: OFF — {} (CPU search continues)", sanitize_status_text("program_source:14:3: error: use of undeclared identifier 'sha512h'\nnote: expanded from macro", 40)), Color::Red));
```

  The row must be a single red line with no line break, no stray glyphs, and the `Rate:` and `Checked:` counters must keep climbing above it (the CPU search is still running). Then **remove that line again** and confirm:

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && git diff --stat
```

Expect **no output** — the temporary line is gone and the tree matches the last commit.

- [ ] **Step 11: Confirm nothing was left uncommitted, then tag the milestone in the log.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy && git status --porcelain && git log --oneline -7
```

Expect empty `git status --porcelain` output and the seven commits from Tasks 7.1–7.7 at the top of the log.
## Milestone 8 — Soak and ship

This milestone writes very little code. Its job is to prove, with recorded numbers, that the
feature survives a multi-day workload, that all three rollback levers work, that the tree is
lint- and format-clean, and then to collapse the whole branch into one revertable commit and
make `CLAUDE.md` true again.

Three of the seven tasks are **measurement gates**: they run for minutes or hours and their
"failure" is a number outside a stated bound. Each still opens with a real red phase — a test or
a harness self-check that must be seen failing before it is trusted — because a soak harness
that silently records nothing passes every gate you can put on it.

Before starting, confirm where you are:

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy
git branch --show-current    # expect: feat/metal-gpu-pbkdf2
git log --oneline -1 main    # expect: 4854a59 ui: move key hints to a full-width bottom row
```

All commands in this milestone are run from `/Users/shawnhopkinson/Rust/Vanaddy`.

---

### Task 8.1: `VANADDY_GPU_SOAK_N=1e7` soak count parsing, then the full `ring` differential

The headline soak command is `VANADDY_GPU_SOAK_N=1e7 cargo test -- --ignored`. `"1e7".parse::<usize>()`
returns `Err`, so with the obvious `.parse().ok().unwrap_or(default)` spelling that command silently
soaks the 1,000,000-candidate default instead of 10,000,000 — a 10× shortfall that no output
distinguishes from a real run. Fix the parser first, then run the soak.

**Files:**
- Modify: `/Users/shawnhopkinson/Rust/Vanaddy/src/gpu/mod.rs` (append ONE `#[cfg(test)]` helper — `parse_soak_count` — and a `#[cfg(test)] mod soak_count_tests` block at end of file — `src/gpu/mod.rs` already has a `mod tests` from Task 1.3, so the new module must carry a different name)
- Modify: `/Users/shawnhopkinson/Rust/Vanaddy/src/gpu/metal.rs` (Step 5 — the `soak_count` environment wrapper, added inside that file's `#[cfg(test)] mod tests` beside its only caller, plus the count line inside `fn gpu_soak_matches_ring`, **creating that test first if Milestone 3 did not**)

`soak_count` belongs in `src/gpu/metal.rs`, **not** in `src/gpu/mod.rs`. `mod.rs` compiles on every
target; `metal.rs` does not compile on the `--no-default-features` leg; and `soak_count`'s only call
site is `fn gpu_soak_matches_ring` in `metal.rs`. Declared in `mod.rs`, it is a `#[cfg(test)]`
function that nothing calls on the stub leg, so `cargo clippy --all-targets --no-default-features`
emits ``warning: function `soak_count` is never used`` anchored at `--> src/gpu/mod.rs:NN`. Task 6.9
Step 6b removed the crate-level `#![allow(dead_code)]`, and Task 8.5 Step 4 and Task 8.7 Step 4 both
gate on `grep -c -- '--> src/gpu/\|--> src/verify.rs'` over that leg's clippy output printing `0` —
Task 8.7 adds that anything else "stops the ship". `parse_soak_count` stays in `mod.rs`: its own
`#[cfg(test)] mod soak_count_tests` is its call site and compiles on both legs, so it is never dead.
- Test: `/Users/shawnhopkinson/Rust/Vanaddy/src/gpu/mod.rs` (`mod soak_count_tests` — a second `mod tests` in one file is `error[E0428]`)

**Interfaces:**
- Consumes: `pub const COMPRESSIONS_PER_SEED: u32 = 4_098;`, `pub const WAVE: usize = 8_192;` (both from `src/gpu/mod.rs`, Milestone 1); the `#[ignore]`d test `gpu_no_rss_growth_over_100k_dispatches` in `src/gpu/metal.rs` (Milestone 3, Task 3.11); the test helper `gpu_for_test()` and the `use` items already in that file's `mod tests`
- Produces: `#[cfg(test)] pub(crate) fn parse_soak_count(raw: Option<&str>, default: usize) -> usize` in `src/gpu/mod.rs` (kept `pub(crate)` so `src/gpu/metal.rs` can reach it); `fn soak_count(default: usize) -> usize` inside the `#[cfg(test)] mod tests` of `src/gpu/metal.rs` (no `#[cfg(test)]` attribute of its own — the enclosing module already carries one)

- [ ] **Step 1: Write the failing parser test.** Append this to the end of `/Users/shawnhopkinson/Rust/Vanaddy/src/gpu/mod.rs`. Task 1.3 already put a `#[cfg(test)] mod tests` block in this file, which is exactly why the module below is named `soak_count_tests` — do **not** rename it to `tests`, and do not fold the four `#[test]` functions into the Task 1.3 block. Two modules of the same name in one file is `error[E0428]: the name `tests` is defined multiple times`.

```rust
#[cfg(test)]
mod soak_count_tests {
    use super::parse_soak_count;

    #[test]
    fn soak_count_parses_scientific_notation() {
        // The documented invocation is literally `VANADDY_GPU_SOAK_N=1e7`.
        assert_eq!(parse_soak_count(Some("1e7"), 1_000_000), 10_000_000);
        assert_eq!(parse_soak_count(Some("2.5e6"), 1_000_000), 2_500_000);
    }

    #[test]
    fn soak_count_parses_plain_integers_and_trims() {
        assert_eq!(parse_soak_count(Some("4096"), 1_000_000), 4096);
        assert_eq!(parse_soak_count(Some("  4096  "), 1_000_000), 4096);
    }

    #[test]
    fn soak_count_defaults_when_unset() {
        assert_eq!(parse_soak_count(None, 1_000_000), 1_000_000);
    }

    #[test]
    fn soak_count_defaults_on_garbage_and_never_soaks_zero() {
        // A zero or negative count would run no comparisons at all and report a
        // green soak on a completely broken kernel. Fall back, never accept it.
        assert_eq!(parse_soak_count(Some("banana"), 1_000_000), 1_000_000);
        assert_eq!(parse_soak_count(Some(""), 1_000_000), 1_000_000);
        assert_eq!(parse_soak_count(Some("0"), 1_000_000), 1_000_000);
        assert_eq!(parse_soak_count(Some("-5"), 1_000_000), 1_000_000);
        assert_eq!(parse_soak_count(Some("inf"), 1_000_000), 1_000_000);
        assert_eq!(parse_soak_count(Some("NaN"), 1_000_000), 1_000_000);
    }
}
```

- [ ] **Step 2: Run it and see it fail.**

```sh
cargo test soak_count
```

Expected failure — a compile error, not a failed assertion:

```
error[E0432]: unresolved import `super::parse_soak_count`
 --> src/gpu/mod.rs:NN:9
  |
  |     use super::parse_soak_count;
  |         ^^^^^^^^^^^^^^^^^^^^^^^ no `parse_soak_count` in `gpu`
```

- [ ] **Step 3: Write the parser.** Insert this immediately above the `#[cfg(test)] mod soak_count_tests` block you just added in `/Users/shawnhopkinson/Rust/Vanaddy/src/gpu/mod.rs`.

```rust
/// Parse `VANADDY_GPU_SOAK_N`. Parsed as `f64` first, because the soak is
/// documented and invoked as `VANADDY_GPU_SOAK_N=1e7` and `"1e7".parse::<usize>()`
/// is an `Err` — the obvious `.parse().ok().unwrap_or(default)` spelling silently
/// runs the 1,000,000 default and prints nothing that distinguishes it from a
/// real 10,000,000-candidate soak. Anything unparseable, non-finite, or below 1
/// falls back to `default`: a soak of zero candidates passes trivially and would
/// green-light a broken kernel.
#[cfg(test)]
pub(crate) fn parse_soak_count(raw: Option<&str>, default: usize) -> usize {
    match raw {
        None => default,
        Some(s) => match s.trim().parse::<f64>() {
            Ok(v) if v.is_finite() && v >= 1.0 => v as usize,
            _ => default,
        },
    }
}
```

Only `parse_soak_count` goes in `src/gpu/mod.rs`. The wrapper that reads the environment,
`soak_count`, is added in Step 5 inside `src/gpu/metal.rs`'s `#[cfg(test)] mod tests`, beside its one
caller — see the note under **Files** for why putting it here instead breaks the
`--no-default-features` clippy gate.

- [ ] **Step 4: Run it and see it pass.**

```sh
cargo test soak_count
```

Expected: `test result: ok. 4 passed; 0 failed`.

- [ ] **Step 5: Make sure the soak test exists, then wire it to the parser.** First check:

```sh
grep -n 'fn gpu_soak_matches_ring' /Users/shawnhopkinson/Rust/Vanaddy/src/gpu/metal.rs
```

**If that grep prints nothing** (Milestone 3 shipped only `gpu_no_rss_growth_over_100k_dispatches`), the
soak this whole milestone is built on does not exist yet — create it now. Add this to the
`#[cfg(test)] mod tests` block in `/Users/shawnhopkinson/Rust/Vanaddy/src/gpu/metal.rs`, beside
`gpu_no_rss_growth_over_100k_dispatches`, and write it with the literal `1_000_000` exactly as shown:

```rust
    /// The long differential, and the gate the whole of Milestone 8 rests on.
    /// `#[ignore]`d: 1,000,000 candidates is ~15 minutes in a debug build.
    /// Every GPU seed is re-derived with `ring`; a mismatch prints the global
    /// index and the phrase so the single case replays on its own.
    ///
    ///   VANADDY_GPU_SOAK_N=1e7 cargo test -- --ignored --nocapture
    #[test]
    #[ignore = "soak; run with --ignored"]
    fn gpu_soak_matches_ring() {
        let Some(mut gpu) = gpu_for_test() else { return };
        let n: usize = std::env::var("VANADDY_GPU_SOAK_N")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(1_000_000);
        let started = std::time::Instant::now();
        let mut done = 0usize;
        while done < n {
            let take = crate::gpu::WAVE.min(n - done);
            let mnemonics: Vec<Mnemonic> = (0..take)
                .map(|_| Mnemonic::new(bip39::MnemonicType::Words12, Language::English))
                .collect();
            let phrases: Vec<&str> = mnemonics.iter().map(|m| m.phrase()).collect();
            let seeds = gpu
                .derive(&phrases, crate::seed::PBKDF2_ROUNDS)
                .expect("wave");
            assert_eq!(seeds.len(), take, "wave returned the wrong candidate count");
            for (i, m) in mnemonics.iter().enumerate() {
                let want = crate::seed::derive_seed(m);
                assert_eq!(
                    hex::encode(*seeds[i]),
                    hex::encode(want),
                    "soak mismatch at global index {}, phrase `{}`",
                    done + i,
                    m.phrase()
                );
            }
            done += take;
            eprintln!(
                "soak: {done}/{n} in {:.1}s",
                started.elapsed().as_secs_f64()
            );
        }
        eprintln!(
            "soak: {n} candidates, 0 mismatches, {:.1}s",
            started.elapsed().as_secs_f64()
        );
    }
```

Adjust the `use` names (`Mnemonic`, `Language`, `hex`) to whatever that `mod tests` already imports,
and the wave call to whatever `gpu_for_test()` returns — every other GPU test in the file already
does the same three things, so copy their spelling rather than inventing one. Then run it once,
still on the literal, to see it green before touching the count:

```sh
VANADDY_GPU_SOAK_N=1000 cargo test --release gpu_soak_matches_ring -- --ignored --nocapture
```

Expected: `test result: ok. 1 passed`.

**Then wire the count line, whether the test was already there or you just wrote it.** Replace:

```rust
        let n: usize = std::env::var("VANADDY_GPU_SOAK_N")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(1_000_000);
```

with:

```rust
        let n = soak_count(1_000_000);
```

If the existing text differs, replace whatever expression produces the candidate count `n` with exactly `soak_count(1_000_000)` and delete the old `std::env::var("VANADDY_GPU_SOAK_N")` lookup from `gpu_soak_matches_ring` so there is only one.

Then add `soak_count` itself to the **same** `#[cfg(test)] mod tests` block in
`/Users/shawnhopkinson/Rust/Vanaddy/src/gpu/metal.rs`, immediately above `fn gpu_soak_matches_ring`:

```rust
    /// `crate::gpu::parse_soak_count` against the live environment. Test-only,
    /// and deliberately here rather than in `src/gpu/mod.rs`: `mod.rs` compiles
    /// on every target, `metal.rs` does not, and `gpu_soak_matches_ring` below
    /// is the only call site. In `mod.rs` this would be dead code on the
    /// `--no-default-features` leg, and Task 8.5 Step 4 / Task 8.7 Step 4 gate
    /// on that leg emitting no new diagnostic at all.
    fn soak_count(default: usize) -> usize {
        crate::gpu::parse_soak_count(
            std::env::var("VANADDY_GPU_SOAK_N").ok().as_deref(),
            default,
        )
    }
```

No `#[cfg(test)]` attribute on it — the enclosing `mod tests` already carries one — and it is called
from `gpu_soak_matches_ring` in that same module, so it is live on the only leg that compiles this
file. Step 7 already stages both `src/gpu/mod.rs` and `src/gpu/metal.rs`, so no change there.

- [ ] **Step 6: Prove the wiring by asserting the parsed value, then run a short soak.** Wall-clock
proves nothing here, and reading it backwards is worse than not reading it. With the un-wired
`.parse().ok().unwrap_or(1_000_000)` spelling, `"1e5"` is an `Err` and the run falls back to
**1,000,000** — ten times *more* work than the 100,000 requested. An un-wired run is therefore
slower, never "under two seconds", so a wall-clock check passes whichever way the count line is
spelled. Assert the number instead.

First add a fifth case to `mod soak_count_tests` in
`/Users/shawnhopkinson/Rust/Vanaddy/src/gpu/mod.rs`, pinning exactly the value the short soak below
asks for:

```rust
    #[test]
    fn soak_count_parses_the_short_proof_count() {
        // The Step 6 short-soak invocation is literally `VANADDY_GPU_SOAK_N=1e5`.
        // An un-wired parser yields the 1,000,000 default here, not 100,000 — the
        // shortfall this whole task exists to prevent, in the opposite direction.
        assert_eq!(parse_soak_count(Some("1e5"), 1_000_000), 100_000);
    }
```

```sh
cargo test soak_count
```

Expected: `test result: ok. 5 passed; 0 failed`.

Then confirm `gpu_soak_matches_ring` actually calls it and that the old lookup is gone from that
test:

```sh
grep -n 'soak_count(1_000_000)' /Users/shawnhopkinson/Rust/Vanaddy/src/gpu/metal.rs
grep -c 'std::env::var("VANADDY_GPU_SOAK_N")' /Users/shawnhopkinson/Rust/Vanaddy/src/gpu/metal.rs
```

Expected: the first prints exactly one line, inside `fn gpu_soak_matches_ring`; the second prints
`1` — the single occurrence inside `fn soak_count`, with nothing left in `gpu_soak_matches_ring`.

Finally run the real GPU differential at 100,000 candidates (~30 s):

```sh
VANADDY_GPU_SOAK_N=1e5 cargo test --release gpu_soak_matches_ring -- --ignored --nocapture
```

Expected: the progress lines count up to `soak: 100000/100000`, and the run ends
`test result: ok. 1 passed`. Any other total on that last progress line means the count line was not
wired — go back to Step 5.

- [ ] **Step 7: Commit the parser.**

```sh
rustfmt --edition 2021 src/gpu/mod.rs src/gpu/metal.rs
git add src/gpu/mod.rs src/gpu/metal.rs
git commit -m "test: parse VANADDY_GPU_SOAK_N as f64 so 1e7 means ten million

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

- [ ] **Step 8: Run the full soak — the milestone's headline gate.** The command below is unscoped, so it runs all FOUR `#[ignore]`d tests this branch created: `gpu_soak_matches_ring` at ten million candidates and `gpu_no_rss_growth_over_100k_dispatches` (both in `src/gpu/metal.rs`, Tasks 8.1 and 3.11), `gpu_seed_rate_end_to_end` (`src/gpu/producer.rs`, Task 4.8) and `hybrid_evm_search_with_live_gpu_emits_only_rederivable_matches` (`src/app.rs`, Task 5.3). **Budget ~150 minutes.** That follows from Step 5's own figure: 1,000,000 candidates is ~15 minutes in a debug build, and this runs ten million in the same debug build, so 10 × 15 ≈ 150. Do not hold to a 45–90 minute expectation and conclude a healthy soak has hung — 45–90 minutes is *release* scaling, not debug.

If you would rather not sit for 150 minutes, `--release` is a supported alternative and lands the same gate in ~50 minutes:

```sh
mkdir -p /tmp/vanaddy-soak
VANADDY_GPU_SOAK_N=1e7 cargo test --release -- --ignored --nocapture 2>&1 \
  | tee /tmp/vanaddy-soak/soak-1e7.log
```

Either build satisfies the gate, because what this soak proves is a **differential** — GPU seed == `ring` seed over ten million real phrases — and that equality is build-independent. Release has the further advantage that `gpu_seed_rate_end_to_end` then runs under the conditions Task 4.8 documents, so the tolerated failure described below simply does not arise. Run the debug command in the fence further down, or this release one; do not run both.

Two of the four are debug-hostile. `gpu_seed_rate_end_to_end` is the ~30 s rate measurement Task 4.8 documents as `--release`-only and it asserts a `rate > 3_000.0` seeds/s floor that a debug-built producer thread can miss; `hybrid_evm_search_with_live_gpu_emits_only_rederivable_matches` runs ~5 s of live search. If `gpu_seed_rate_end_to_end` is the **only** test that fails here, re-run it alone with Task 4.8's documented `cargo test --release gpu_seed_rate_end_to_end -- --ignored --nocapture` and treat the debug result as inconclusive; take `EVM_GPU_SEEDS_PER_SEC` from that release run, never from this log. Any other failure in this log is a hard stop.

```sh
mkdir -p /tmp/vanaddy-soak
VANADDY_GPU_SOAK_N=1e7 cargo test -- --ignored --nocapture 2>&1 \
  | tee /tmp/vanaddy-soak/soak-1e7.log
```

- [ ] **Step 9: Read the gate.** The gate must tolerate exactly the one failure Step 8 anticipates —
`gpu_seed_rate_end_to_end` missing its debug-build rate floor — and nothing else. Check the failing
tests **by name**, not by counting them: a bare count of `0` is unsatisfiable in precisely the case
Step 8 says to expect, and a bare count of `1` would wave through a `gpu_soak_matches_ring` mismatch.

```sh
tail -5 /tmp/vanaddy-soak/soak-1e7.log

# Every test that failed, by name (empty output = a clean run):
grep -E '^test .* \.\.\. FAILED$' /tmp/vanaddy-soak/soak-1e7.log \
  | sed -E 's/^test ([^ ]+) \.\.\. FAILED$/\1/'

# The gate: failures OTHER than the tolerated debug-build rate floor.
grep -E '^test .* \.\.\. FAILED$' /tmp/vanaddy-soak/soak-1e7.log \
  | sed -E 's/^test ([^ ]+) \.\.\. FAILED$/\1/' \
  | grep -vc 'gpu_seed_rate_end_to_end'
```

Expected: the last command prints `0`. Two shapes satisfy that, and only two:

- **Clean run.** The middle command prints nothing and the tail ends
  `test result: ok. 4 passed; 0 failed; 0 ignored`. This is what a `--release` Step 8 should produce.
- **Tolerated run.** The middle command prints exactly one name ending in `gpu_seed_rate_end_to_end`
  and the tail ends `test result: FAILED. 3 passed; 1 failed; 0 ignored`. Follow Step 8: re-run that
  test alone with `cargo test --release gpu_seed_rate_end_to_end -- --ignored --nocapture`, take
  `EVM_GPU_SEEDS_PER_SEC` from the release run, and treat the debug result as inconclusive.

Anything else — the last command printing `1` or more, or any name in the middle command's output
that is not `gpu_seed_rate_end_to_end` — is a hard stop.

A `RingMismatch { index, phrase, got, want }` failure here is a hard stop for the whole milestone: the kernel disagrees with `ring` on a real phrase. Replay that single case with the printed index before doing anything else — do not proceed to Task 8.2, and do not ship.

---

### Task 8.2: 12-hour real search with RSS sampled every 10 minutes

The autorelease-pool defect this guards against leaks 1,861 bytes per command buffer — 199 KB/s,
700 MB/hour, 16.4 GB/day. It is completely invisible in a short test and only shows up in the
stated use case, a multi-day vanity search. The `#[ignore]`d `gpu_no_rss_growth_over_100k_dispatches`
test from Task 8.1 Step 8 is the fast proxy; this task is the real thing, running the actual
binary through the actual TUI with the CSV writer, the match list, and the render loop all live.

**Files:**
- Create: `/tmp/vanaddy-soak/sample-rss.sh` (operator harness, deliberately **not** committed — the shipped commit stays source-only)
- Create: `/tmp/vanaddy-soak/summary.txt` (measurements consumed by Task 8.6)

**Interfaces:**
- Consumes: the release binary `target/release/vanaddy`; `App::gpu_effective()`; the exit summary `main()` prints at `/Users/shawnhopkinson/Rust/Vanaddy/src/main.rs:55-59` (`Wallets checked` / `Elapsed time`)
- Produces: `/tmp/vanaddy-soak/summary.txt` containing the keys `hybrid_rate`, `rss_start_kib`, `rss_end_kib`, `growth_pct`

- [ ] **Step 1: Write the sampler harness.** Write this to `/tmp/vanaddy-soak/sample-rss.sh`:

```bash
#!/bin/bash
# Sample vanaddy's RSS every 10 minutes for 12 hours (73 samples).
# Exits NON-ZERO the moment the process is not found, so a soak that died at
# hour 2 can never be mistaken for a soak that was flat for 12 hours.
set -uo pipefail
OUT=/tmp/vanaddy-soak
mkdir -p "$OUT"
printf 'epoch\trss_kib\n' > "$OUT/rss.tsv"
for _ in $(seq 0 72); do
  pid=$(pgrep -x vanaddy | head -1)
  if [ -z "$pid" ]; then
    echo "sample-rss: vanaddy is not running; aborting sampler" >&2
    exit 1
  fi
  rss=$(ps -o rss= -p "$pid" | tr -d ' ')
  if [ -z "$rss" ]; then
    echo "sample-rss: could not read RSS for pid $pid; aborting sampler" >&2
    exit 1
  fi
  printf '%s\t%s\n' "$(date +%s)" "$rss" >> "$OUT/rss.tsv"
  sleep 600
done
echo "sample-rss: 73 samples written to $OUT/rss.tsv"
```

```sh
chmod +x /tmp/vanaddy-soak/sample-rss.sh
```

- [ ] **Step 2: Run the harness against a stopped app and see it fail.** This is the red phase, and it is the point: a sampler that quietly writes an empty file would let a crashed 12-hour soak report perfect memory stability.

```sh
pkill -x vanaddy 2>/dev/null; /tmp/vanaddy-soak/sample-rss.sh; echo "exit=$?"
```

Expected output, exactly:

```
sample-rss: vanaddy is not running; aborting sampler
exit=1
```

- [ ] **Step 3: Build the binary the soak will run.**

```sh
cargo build --release
ls -la target/release/vanaddy
```

- [ ] **Step 4: Start the search.** In terminal A:

```sh
caffeinate -dimsu ./target/release/vanaddy
```

Then, from the fresh config form, type this exact key sequence:

| Key | Effect |
|-----|--------|
| `2` | Chain → EVM (field 0; `src/app.rs:504`) |
| `Tab` | → Match position (leave `StartsWith`) |
| `Tab` | → Prefix |
| `d` `e` `a` `d` `b` | prefix `deadb` — 5 hex chars, 1 in 1,048,576, so ~1 match/45 s: enough to exercise the verify gate, CSV writer, and match list without drowning them |
| `Tab` | → Case sensitivity (leave default) |
| `Tab` | → GPU |
| `y` | GPU → On |
| `Tab` | → Threads (leave the detected default) |
| `Enter` | validate + start |

Confirm the stats pane shows a line of the form `GPU       : Apple M1   13.6k/s (54%)`. If it
shows `GPU       : initialising` for more than ~2 seconds, or any `GPU       : OFF —` line, stop
here and diagnose — the soak measures nothing useful without the GPU actually running.

- [ ] **Step 5: Start the sampler.** In terminal B, immediately after Step 4:

```sh
/tmp/vanaddy-soak/sample-rss.sh 2>&1 | tee /tmp/vanaddy-soak/sampler.log &
```

- [ ] **Step 6: After 12 hours, stop the search and capture the rate.** In terminal A press `q`. The
binary leaves the alternate screen and prints its exit summary. Record the two numbers it prints:

```
  Wallets checked : 1011XXXXXXX
  Matches found   : 9XX
  Elapsed time    : 43200.XXs
```

Compute and record the rate — substitute the two numbers you actually saw:

```sh
awk 'BEGIN{ total=1011234567; elapsed=43201.7;
            printf "hybrid_rate=%.0f\nhybrid_us_per_cand=%.1f\n", total/elapsed, 1e6*elapsed/total }' \
  | tee -a /tmp/vanaddy-soak/summary.txt
```

- [ ] **Step 7: Analyse RSS and read the gate.**

```sh
awk -F'\t' 'NR>1 { if (n==0) first=$2; last=$2; n++ }
            END { printf "samples=%d\nrss_start_kib=%d\nrss_end_kib=%d\ngrowth_pct=%.2f\n",
                         n, first, last, (last-first)*100.0/first }' \
  /tmp/vanaddy-soak/rss.tsv | tee -a /tmp/vanaddy-soak/summary.txt
```

Gate — all three must hold:

- `samples=73` (the sampler never aborted, so the app lived the full 12 hours)
- `growth_pct` < `5.00`
- terminal A never printed a `GPU       : OFF —` line

For scale: the un-pooled leak is 700 MB/hour against an ~80 MB baseline, which would read as a
`growth_pct` in the thousands. A 5% bound catches even a leak one thousandth that size.

- [ ] **Step 8: Delete the soak CSV.** Twelve hours of matches wrote roughly a thousand plaintext
seed phrases to `vanity_wallets.csv` in the repo root. `*.csv` is in `.gitignore` so it cannot be
committed, but it must not be left on disk.

```sh
/bin/rm -P vanity_wallets.csv 2>/dev/null || rm -f vanity_wallets.csv
ls vanity_wallets.csv 2>&1     # expect: No such file or directory
```

- [ ] **Step 9: Confirm the summary file is complete.**

```sh
cat /tmp/vanaddy-soak/summary.txt
```

Expected keys present: `hybrid_rate`, `hybrid_us_per_cand`, `samples`, `rss_start_kib`,
`rss_end_kib`, `growth_pct`. Task 8.6 reads `hybrid_rate` and `hybrid_us_per_cand` from here.

---

### Task 8.3: The `VANADDY_GPU=0` lever, pinned by a test and exercised for real

The env lever is documented as rollback lever #2 — "no rebuild". Milestone 6 Task 6.1 Step 5 already
put the decision in one pure function, `gpu_env_off(vanaddy_gpu, vanaddy_no_gpu)`, precisely so it is
testable without `std::env::set_var` (which is racy under `cargo test`, where all tests share one
process), and Task 6.1 Step 6 already rewrites an env-vetoed `Ready` probe to `Disabled(UserOff)`.
This task therefore writes **no production code**: it pins both behaviours with regression tests,
then runs the binary with the lever set. The CPU-only rate that run produces is the second measured
number `CLAUDE.md` needs.

**Files:**
- Modify: `/Users/shawnhopkinson/Rust/Vanaddy/src/app.rs` (add two tests to `mod tests` only, currently at `src/app.rs:558-585`; `gpu_env_off` and the `Disabled(UserOff)` status rewrite already exist from Task 6.1 Steps 5–6 and must **not** be re-added — a second `pub fn gpu_env_off` is `error[E0428]: the name `gpu_env_off` is defined multiple times`)
- Test: `/Users/shawnhopkinson/Rust/Vanaddy/src/app.rs` (`mod tests`)

`src/main.rs` is **not** modified by this task. Milestone 6 puts the env decision in
`App::with_gpu_status` (Task 6.1 Step 5), not in `main()`; Task 6.3 adds only the probe and the panic
hook. There is no env read in `main.rs` to replace.

**Interfaces:**
- Consumes: `pub fn gpu_effective(&self) -> bool`; `GpuStatus::{Ready, Disabled}`; `GpuDisableReason::UserOff`; `App::gpu_requested`, `App::gpu_status`
- Produces: no new signatures — this task is two regression tests plus one measurement

- [ ] **Step 1: Write the failing tests.** Add these two tests inside the existing `#[cfg(test)] mod tests` block at the end of `/Users/shawnhopkinson/Rust/Vanaddy/src/app.rs`, after `start_stop_restart_does_not_leak_threads`.

```rust
    #[test]
    fn gpu_env_off_recognises_every_documented_spelling() {
        // VANADDY_GPU: value-based, case-insensitive, trimmed.
        assert!(gpu_env_off(Some("0"), None));
        assert!(gpu_env_off(Some("off"), None));
        assert!(gpu_env_off(Some("OFF"), None));
        assert!(gpu_env_off(Some("false"), None));
        assert!(gpu_env_off(Some("no"), None));
        assert!(gpu_env_off(Some(" 0 "), None));

        // VANADDY_NO_GPU: presence-based, matching gpu_for_test's var_os().is_some().
        assert!(gpu_env_off(None, Some("1")));
        assert!(gpu_env_off(None, Some("")));
        assert!(gpu_env_off(None, Some("0")));

        // Neither set, or set to something affirmative: GPU stays on.
        assert!(!gpu_env_off(None, None));
        assert!(!gpu_env_off(Some("1"), None));
        assert!(!gpu_env_off(Some("on"), None));
        assert!(!gpu_env_off(Some("yes"), None));
    }

    #[test]
    fn gpu_env_off_makes_gpu_effective_false_on_evm() {
        let mut app = App::new();
        app.chain = crate::chains::ChainKind::Evm;
        app.gpu_status = crate::gpu::GpuStatus::Ready {
            device: "Apple M1".to_string(),
        };
        app.gpu_requested = true;
        assert!(app.gpu_effective(), "precondition: EVM + Ready + requested");

        // Exactly what App::with_gpu_status applies when the env lever is pulled.
        if gpu_env_off(Some("0"), None) {
            app.gpu_requested = false;
            app.gpu_status = crate::gpu::GpuStatus::Disabled(
                crate::gpu::GpuDisableReason::UserOff,
            );
        }

        assert!(!app.gpu_effective());
        assert_eq!(
            app.gpu_status,
            crate::gpu::GpuStatus::Disabled(crate::gpu::GpuDisableReason::UserOff)
        );
    }
```

- [ ] **Step 2: Run them and see them pass.**

```sh
cargo test gpu_env_off
```

Expected: `test result: ok. 2 passed; 0 failed`.

There is deliberately **no red phase here**, and that is not an oversight: Task 6.1 Step 5 shipped
`gpu_env_off` and Task 6.1 Step 6 shipped the `Disabled(UserOff)` status rewrite, so the behaviour
these two tests describe is already built. They are **regression guards, not drivers** — the red
phase for this function lived in Milestone 6. A stated `error[E0425]: cannot find function
`gpu_env_off`` here could only mean Task 6.1 was never applied.

If either test fails, go back and fix Task 6.1. Do **not** add a `gpu_env_off` in this task to make
them pass — a second definition in `src/app.rs` is
`error[E0428]: the name `gpu_env_off` is defined multiple times`.

- [ ] **Step 3: Confirm the single env reader really is single.** This task adds no production code,
so the only thing to check is that Milestone 6 left exactly one reader and one status rewrite:

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy
grep -c 'pub fn gpu_env_off' src/app.rs
grep -rn 'std::env::var("VANADDY_GPU")\|std::env::var("VANADDY_NO_GPU")' src/ --include=*.rs
grep -n 'GpuDisableReason::UserOff' src/app.rs
```

Expected:

1. the first prints `1` — two definitions would be `error[E0428]: the name `gpu_env_off` is defined
   multiple times`;
2. the second shows both `std::env::var` calls **only** inside `App::with_gpu_status` in
   `src/app.rs`, and nothing at all in `src/main.rs` — one variable read from two places with two
   different accepted spellings is the defect Task 6.1 Step 5 exists to prevent;
3. the third shows the `Disabled(UserOff)` rewrite Task 6.1 Step 6 inserted, which is what makes the
   config row say *why* the `y` key will not turn the GPU on.

If any of the three is missing, stop and finish Task 6.1 — do **not** add it here.

- [ ] **Step 4: Build and run the full suite.**

```sh
cargo test
```

Expected: `test result: ok.` with zero failures. Note the total test count printed — it must be the
63 tests this branch started from, plus everything Milestones 1–7 added, plus the 6 added in
Tasks 8.1 and 8.3. Nothing may have been *lost*: this task deletes no code, so any drop in the count
is a regression carried in from an earlier milestone.

Do **not** touch `/Users/shawnhopkinson/Rust/Vanaddy/src/app.rs` beyond `mod tests` in this task, and
do not touch `/Users/shawnhopkinson/Rust/Vanaddy/src/main.rs` at all — `main.rs` holds no env read,
and adding one would recreate the two-readers defect Task 6.1 Step 5 exists to prevent.

- [ ] **Step 5: Commit.**

```sh
rustfmt --edition 2021 --check src/app.rs | grep -c '^Diff in'
git add src/app.rs
git commit -m "test: pin the VANADDY_GPU=0 / VANADDY_NO_GPU env lever

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

`src/app.rs` carries 11 pre-existing rustfmt diffs on this branch's base; the `grep -c` must still
print `11`. A higher number means your insertion is not rustfmt-shaped — fix it by hand rather than
running `cargo fmt`, which would reformat 14 unrelated files.

- [ ] **Step 6: Exercise the lever for real, and measure the CPU-only rate.**

```sh
cargo build --release
VANADDY_GPU=0 ./target/release/vanaddy
```

Key sequence: `2`, `Tab`, `Tab`, `d` `e` `a` `d` `b` `e` (6 hex chars — 1 in 16.7M, so effectively no
matches and no CSV writes to perturb the rate), `Tab`, `Tab`, `Tab`, `Enter`.

Confirm on the config form, **before** pressing Enter, that the GPU row reads exactly:

```
 GPU:      [disabled — UserOff]
```

That string is the whole point of Task 6.1 Step 6's sticky-status rewrite: a bare `[Off]` there means
that edit did not land, and the user has no way to tell the env lever from a toggle they set
themselves. Confirm too
that pressing `y` on that field prints an error rather than turning it on. Let it run for
5 minutes, then press `q`.

- [ ] **Step 7: Record the CPU-only rate.** From the exit summary, substituting your numbers:

```sh
awk 'BEGIN{ total=3812445; elapsed=300.4;
            printf "cpu_only_rate=%.0f\n", total/elapsed }' \
  | tee -a /tmp/vanaddy-soak/summary.txt
```

Expected magnitude on an M1 with 8 threads: 11,500–14,900. A number near the Task 8.2
`hybrid_rate` means the lever did not work — go back to Task 6.1 Steps 5–6 and check that
`App::with_gpu_status` really reads both variables and really rewrites a vetoed `Ready` status.

---

### Task 8.4: The `--no-default-features` leg links no Metal and says why

`--no-default-features` is rollback lever #3 and the proof that the CPU binary stands alone. As
specified, `stub::probe()` returns `Unavailable("not supported on this target")` — which is wrong
on the one machine where it matters most: a macOS ARM build made with `--no-default-features` is
not an unsupported target, it is a deliberate opt-out, and the two are indistinguishable in the
TUI. Fix the message, pin it, then verify the binary.

**Files:**
- Modify: `/Users/shawnhopkinson/Rust/Vanaddy/src/gpu/stub.rs` (the `probe` message; two new tests inside the **existing** `#[cfg(test)] mod tests` block Task 3.3 Step 5 created)
- Test: `/Users/shawnhopkinson/Rust/Vanaddy/src/gpu/stub.rs`

**Interfaces:**
- Consumes: `pub fn probe() -> GpuStatus`; `GpuStatus::Unavailable(String)`; `impl GpuEngine { pub fn probe() -> GpuStatus; pub fn start(tx: Sender<Box<SeedBlock>>, health: Arc<GpuHealth>) -> GpuEngine; pub fn status(&self) -> GpuStatus; pub fn signal_stop(&self); pub fn is_finished(&self) -> bool; pub fn reap(self); }`
- Produces: no new signatures (message change only)

- [ ] **Step 1: Write the failing tests.** `/Users/shawnhopkinson/Rust/Vanaddy/src/gpu/stub.rs`
ALREADY ends in a `#[cfg(test)] mod tests` block — Task 3.3 Step 5 put
`probe_is_unavailable_without_the_metal_backend` in it, and Task 4.7 Step 6 left it alone (Step 3b
below edits that very test, so this task already assumes the module is there). Add the two tests
below **inside that existing block**, immediately before its closing `}`, and widen its header import
from `use super::probe;` to `use super::*;` so `GpuEngine` and `GpuStatus` resolve. Do **not** open a
second `mod tests`: two modules of the same name in one file is
`error[E0428]: the name `tests` is defined multiple times`.

```rust
    #[test]
    fn stub_probe_names_metal_in_its_reason() {
        // The reason string is rendered verbatim in the TUI config row. On macOS
        // ARM this build is a deliberate --no-default-features opt-out, not an
        // unsupported target, and a user staring at "not supported on this
        // target" on an M1 has no way to tell those two apart.
        let status = probe();
        let reason = match status {
            GpuStatus::Unavailable(r) => r,
            other => panic!("stub probe() must be Unavailable, got {other:?}"),
        };
        assert!(
            reason.contains("Metal"),
            "probe() reason must name Metal so a --no-default-features build is \
             distinguishable from an unsupported target, got: {reason}"
        );
        assert!(
            reason.contains("--no-default-features"),
            "probe() reason must name the flag that produced this build, got: {reason}"
        );
    }

    #[test]
    fn stub_engine_lifecycle_is_a_terminating_no_op() {
        // Milestone 6 calls signal_stop() then polls is_finished() from the UI
        // thread's 100 ms tick. A stub that never reports finished would park an
        // engine in App::gpu_engines forever and make start_search skip the GPU
        // on every subsequent run — on a build that has no GPU anyway, so nobody
        // would ever notice the leak.
        let (tx, _rx) = crossbeam_channel::bounded(super::super::CHANNEL_CAPACITY);
        let health = std::sync::Arc::new(super::super::GpuHealth::default());
        let engine = GpuEngine::start(tx, health);
        engine.signal_stop();
        assert!(engine.is_finished());
        engine.reap();
    }
```

- [ ] **Step 2: Run it and see it fail.** The stub backend only compiles when the Metal backend is not selected, so this leg is the only one that runs it.

```sh
cargo test --no-default-features stub_probe
```

Expected failure. Note *which* assertion fails: Task 3.3's message is
``"Metal PBKDF2 offload requires Apple Silicon macOS and the `metal` feature"``, which already
contains "Metal", so the first assertion passes and it is the `--no-default-features` assertion that
fires:

```
thread 'gpu::backend::tests::stub_probe_names_metal_in_its_reason' panicked at src/gpu/stub.rs:NN:9:
probe() reason must name the flag that produced this build, got: Metal PBKDF2 offload requires Apple Silicon macOS and the `metal` feature
```

- [ ] **Step 3: Fix the message.** In `/Users/shawnhopkinson/Rust/Vanaddy/src/gpu/stub.rs`, find the `probe` body and replace the `Unavailable` string:

```rust
pub fn probe() -> GpuStatus {
    GpuStatus::Unavailable(
        "built without Metal support (--no-default-features, or not aarch64-apple-darwin)"
            .to_string(),
    )
}
```

If `GpuEngine::probe()` in the same file returns its own literal rather than delegating, make it delegate so the two can never drift:

```rust
impl GpuEngine {
    pub fn probe() -> GpuStatus {
        probe()
    }
```

- [ ] **Step 3b: Update the pre-existing assertion that the new message breaks.** Task 3.3 Step 5
added `probe_is_unavailable_without_the_metal_backend` to the same file, and it asserts on a phrase
the new message no longer contains. In `/Users/shawnhopkinson/Rust/Vanaddy/src/gpu/stub.rs`, change:

```rust
            GpuStatus::Unavailable(r) => assert!(r.contains("Apple Silicon")),
```

to:

```rust
            GpuStatus::Unavailable(r) => assert!(r.contains("Metal")),
```

Without this, Step 5's `cargo test --no-default-features` gate fails on a test neither this task nor
Task 3.3 is wrong about — the message simply moved.

- [ ] **Step 4: Run it and see it pass.**

```sh
cargo test --no-default-features stub_probe
cargo test --no-default-features stub_engine_lifecycle
```

Expected: `test result: ok. 1 passed` for each. `GpuHealth::default()` resolves via the
`impl Default for GpuHealth { fn default() -> Self { GpuHealth::new() } }` that Milestone 1 Task 1.5
Step 4 wrote. Never add `#[derive(Default)]` on top of it — a derive alongside the hand-written impl
is `error[E0119]: conflicting implementations of trait `Default` for type `GpuHealth``.

- [ ] **Step 5: Run the whole no-default-features suite.**

```sh
cargo test --no-default-features 2>&1 | tail -20
```

Expected: `test result: ok.` with zero failures. Every GPU-required test in `src/gpu/metal.rs` is
absent from this leg by construction (the module is not compiled); every pack, selftest, verify,
and chains test runs.

- [ ] **Step 6: Build the CPU-only binary and prove it links no Metal.**

```sh
cargo build --release --no-default-features
otool -L target/release/vanaddy | grep -ci metal
nm -u target/release/vanaddy | grep -ci 'MTL'
```

Expected: both `grep -c` invocations print `0`. A non-zero count means a `#[cfg(feature = "metal")]`
gate is missing somewhere and the "links no Metal" claim in `CLAUDE.md` would be false.

- [ ] **Step 7: Run the deliberate-skip leg.** This proves the `gpu_for_test` skip path itself
compiles and does not silently swallow a real backend failure.

```sh
VANADDY_NO_GPU=1 cargo test -- --nocapture 2>&1 | grep -c '^SKIP: VANADDY_NO_GPU'
VANADDY_NO_GPU=1 cargo test 2>&1 | tail -5
```

Expected: the first command prints a count greater than `0` (one line per GPU-required test), and
the tail ends `test result: ok.` with zero failures.

`--nocapture` is load-bearing on the first command, not decoration. libtest captures the stdout and
stderr of every **passing** test and prints it nowhere; a `SKIP:` line from a test that then returns
green never reaches the pipe, so without `--nocapture` the `grep -c` prints `0` no matter how many
tests skipped and the gate can never pass. Every other soak command in this milestone already passes
it — see Task 8.1 Step 8. The second command deliberately keeps the captured form: it only reads the
`test result:` summary, which libtest prints either way, and captured output keeps that summary at
the tail where `tail -5` can find it.

- [ ] **Step 8: Restore the default-features release binary.** The `--no-default-features` build
overwrote `target/release/vanaddy`; later tasks and any manual check need the real one back.

```sh
cargo build --release
otool -L target/release/vanaddy | grep -ci metal    # expect: 1 or more
```

- [ ] **Step 9: Commit.**

```sh
rustfmt --edition 2021 src/gpu/stub.rs
git add src/gpu/stub.rs
git commit -m "fix: stub probe() names Metal and the flag that produced the build

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 8.5: No new clippy diagnostic, no new rustfmt drift, on either feature leg

The tree this branch started from is **not** lint- or format-clean, and no task in Milestones 1–8
makes it so. Verified on `beced09`: `cargo clippy --all-targets` emits exactly 12 diagnostics
(`src/app.rs` ×5, `src/chains/ton_cell.rs` ×3, `src/chains/evm.rs` ×2, `src/chains/bitcoin.rs` ×1,
`src/ui.rs` ×1) and `cargo fmt --check` reports 84 diffs across 14 files. Fixing those would touch
four frozen files for no functional reason and is a separate change.

The gate here is therefore a **delta** gate: this branch adds no new clippy diagnostic and no new
rustfmt drift. "Zero warnings" is not achievable and asserting it would fail the ship on code this
branch never wrote.

**Do NOT run bare `cargo fmt`.** It would reformat 14 unrelated files and make Milestone 1 Task 1.8
Step 8's whole-diff gate ("no `src/app.rs`, `src/ui.rs`, or `src/chains/*`") permanently false.
Format by path only.

**Files:**
- Modify: any file clippy names in Step 3 as a *new* diagnostic (expected: none)

**Interfaces:**
- Consumes: nothing new — this task is a measurement gate over the tree Milestones 1–8 produced
- Produces: `/tmp/vanaddy-soak/clippy-default.txt`, `/tmp/vanaddy-soak/clippy-stub.txt`

- [ ] **Step 1: Prove the clippy gate bites.** A gate that cannot fail proves nothing, and the
delta form below is easy to get subtly wrong (a `grep` that matches nothing always "passes").
Introduce one warning on purpose:

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy
mkdir -p /tmp/vanaddy-soak
cp src/gpu/mod.rs /tmp/vanaddy-soak/mod.rs.bak
printf '\npub fn soak_gate_canary(v: &Vec<u8>) -> usize { v.len() }\n' >> src/gpu/mod.rs
cargo clippy --all-targets 2>&1 | grep -c 'ptr_arg'
```

Expected: a count greater than `0`, and the diagnostic points into `src/gpu/mod.rs`.

- [ ] **Step 2: Remove the canary and confirm the gate is quiet again.** Restore from the copy
rather than `git checkout` — a `git checkout -- src/gpu/mod.rs` would silently discard any
uncommitted work in that file.

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy
cp /tmp/vanaddy-soak/mod.rs.bak src/gpu/mod.rs && rm /tmp/vanaddy-soak/mod.rs.bak
git diff --stat src/gpu/mod.rs
cargo clippy --all-targets 2>&1 | grep -c 'ptr_arg'
```

Expected: `git diff --stat` shows `src/gpu/mod.rs` unchanged relative to its last commit (no output,
since Tasks 8.1 and 8.3 committed), and the grep prints `0`.

- [ ] **Step 3: Run clippy over every target on the default leg and compare to the baseline.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy
cargo clippy --all-targets 2>&1 | grep -- '-->' | sort | uniq -c \
  | tee /tmp/vanaddy-soak/clippy-default.txt
wc -l < /tmp/vanaddy-soak/clippy-default.txt
grep -c -- '--> src/gpu/\|--> src/verify.rs' /tmp/vanaddy-soak/clippy-default.txt
```

Expected: `wc -l` prints `12` and the `grep -c` prints `0`. The 12 are the pre-existing lines
Milestone 1 Task 1.8 Step 5 recorded — five in `src/app.rs`, three in `src/chains/ton_cell.rs`, two
in `src/chains/evm.rs`, one in `src/chains/bitcoin.rs`, one in `src/ui.rs`. Their **line numbers
shift** as this branch edits `src/app.rs` and `src/ui.rs`; compare the file names and the count of
12, not the line numbers. Any thirteenth line, or any line pointing into `src/gpu/` or
`src/verify.rs`, is a new warning this branch introduced — fix that one. Do not add `#[allow(...)]`
to silence it unless the lint is provably wrong for this code, and if you do, put the reason in a
comment on the same line.

- [ ] **Step 4: Run clippy on the stub leg.** The stub backend is a different set of compiled files
and clippy has never seen it on the default leg.

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy
cargo clippy --all-targets --no-default-features 2>&1 | grep -- '-->' | sort | uniq -c \
  | tee /tmp/vanaddy-soak/clippy-stub.txt
grep -c -- '--> src/gpu/\|--> src/verify.rs' /tmp/vanaddy-soak/clippy-stub.txt
```

Expected: `0`. `src/gpu/metal.rs` is not compiled on this leg, so the only `src/gpu/` files clippy
can see are `mod.rs`, `pack.rs`, `kernel_src.rs`, and `stub.rs`.

- [ ] **Step 5: Format check, by path.** The branch's own files must be rustfmt-clean outright; the
files it edits must carry no *more* drift than they already did.

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy
rustfmt --edition 2021 --check src/gpu/mod.rs src/verify.rs && echo NEW-FILES-FMT-CLEAN
cargo fmt --check 2>/dev/null | grep -c '^Diff in'
```

Expected: `NEW-FILES-FMT-CLEAN`, then `84` — the pre-existing whole-tree count. `rustfmt` on
`src/gpu/mod.rs` recurses into every `src/gpu/*.rs` child, so that one path covers the whole new
module. A number above `84` means an insertion of yours is not rustfmt-shaped: find it with
`cargo fmt --check 2>/dev/null | grep '^Diff in'`, fix that hunk **by hand**, and re-run. Do not run
bare `cargo fmt` to make the number go down — it would go to `0` by reformatting 14 files this
branch has no business touching. `src/gpu/pbkdf2_bip39.metal` is not Rust and rustfmt ignores it.

- [ ] **Step 6: Re-run the full suite on both legs after any lint fixes.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy
cargo test 2>&1 | tail -5
cargo test --no-default-features 2>&1 | tail -5
```

Expected: `test result: ok.` with zero failures on both.

- [ ] **Step 7: Commit — only if Steps 3–5 actually changed something.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy
git status --short src/
```

If that prints nothing, there is nothing to commit and this task is done — say so and move on.
Otherwise:

```sh
git add -A src/
git commit -m "chore: no new clippy or rustfmt findings on either feature leg

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 8.6: Make `CLAUDE.md` true — pinned vectors, the measured GPU row, four hard rules

`CLAUDE.md` is the file every future agent reads first. Seven edits, applied top to bottom. Line
numbers below are the pre-edit numbers; apply the edits in order and each anchor is still findable
by its text.

**Files:**
- Modify: `/Users/shawnhopkinson/Rust/Vanaddy/CLAUDE.md` (lines 7, 20-28, 33-45, 52, 56-69, 77-85)
- Modify: `/Users/shawnhopkinson/Rust/Vanaddy/codemaps/*.md` (regenerated, never hand-edited)

**Interfaces:**
- Consumes: `/tmp/vanaddy-soak/summary.txt` keys `hybrid_rate`, `hybrid_us_per_cand` (Task 8.2 Step 6) and `cpu_only_rate` (Task 8.3 Step 10)
- Produces: no code signatures

- [ ] **Step 1: Run the doc gate and see it fail.** These six greps are the acceptance test for this
task. Run them before editing.

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy
for pat in 'autorelease pool' 'waitUntilCompleted' 'thread_position_in_grid' \
           'Never join the GPU thread' 'gpu_chunk_schedule_invariance' 'src/gpu/metal.rs' \
           'gpu::kernel_src'; do
  printf '%-34s %s\n' "$pat" "$(grep -c "$pat" CLAUDE.md)"
done
```

Expected — the red phase, all seven zero:

```
autorelease pool                   0
waitUntilCompleted                 0
thread_position_in_grid            0
Never join the GPU thread          0
gpu_chunk_schedule_invariance      0
src/gpu/metal.rs                   0
gpu::kernel_src                    0
```

- [ ] **Step 2: Read your two measured numbers.**

```sh
grep -E '^(hybrid_rate|hybrid_us_per_cand|cpu_only_rate)=' /tmp/vanaddy-soak/summary.txt
```

The edits below are written with `23,400 cand/s`, `~43 µs`, and `~12,700 cand/s CPU-only`. Substitute
your three values verbatim wherever those appear. Do not round them into a range and do not carry
the spec's estimates forward — the whole point of the row is that it is measured on this machine.

- [ ] **Step 3: EDIT 1 — the module list (line 7).**

REPLACE:

```markdown
`src/main.rs` is the binary entry (no `lib.rs`). It declares modules `app`, `bip32`, `chains`, `matcher`, `pbkdf2_lanes`, `seed`, `slip10`, `ui` and runs the Ratatui event loop directly. Search workers run on a Rayon thread pool; matches stream back over `mpsc` and are appended to `vanity_wallets.csv` (chmod 0600).
```

WITH:

```markdown
`src/main.rs` is the binary entry (no `lib.rs`). It declares modules `app`, `bip32`, `chains`, `gpu`, `matcher`, `pbkdf2_lanes`, `seed`, `slip10`, `ui`, `verify` and runs the Ratatui event loop directly. Search workers run on a Rayon thread pool; matches stream back over `mpsc` and are appended to `vanity_wallets.csv` (chmod 0600).

On Apple Silicon a single `vanaddy-gpu` thread offloads BIP-39 PBKDF2-HMAC-SHA512 to Metal **for EVM only**, pushing `SeedBlock`s of 512 candidates over a bounded `crossbeam-channel` that Rayon workers drain with `try_recv` between CPU batches. The GPU is a *seed accelerator*: never a source of entropy, never a source of truth. Every GPU-sourced match is re-derived with `ring` before a `Match` can be constructed, and the CSV always carries the CPU-derived address, secret, and phrase. Build it out with `--no-default-features`; turn it off at runtime with `VANADDY_GPU=0`.
```

- [ ] **Step 4: EDIT 2 — Common Commands (after the `cargo fmt` row, line 26).**

REPLACE:

```markdown
| `cargo fmt` | Format (no rustfmt config; defaults) |

There is no separate library target.
```

WITH:

```markdown
| `cargo fmt` | Format (no rustfmt config; defaults) |
| `cargo test --no-default-features` | Run the suite with the Metal backend compiled out (`src/gpu/stub.rs`) |
| `cargo build --release --no-default-features` | CPU-only binary; links no Metal (`otool -L` shows none) |
| `VANADDY_NO_GPU=1 cargo test` | Skip the GPU-required tests deliberately; each prints `SKIP:` |
| `VANADDY_GPU_SOAK_N=1e7 cargo test -- --ignored` | GPU soak: full `ring` differential + the RSS guard (~150 min debug; ~50 min with `--release`) |

There is no separate library target.
```

- [ ] **Step 4b: EDIT 2b — the wrong SLIP-0010 test names (line 37).** `CLAUDE.md` names two
pinned tests that do not exist. Verified in this tree: `CLAUDE.md:37` reads
``- `slip10::slip10_ed25519_test_vector_{1,2}` (SLIP-0010 spec)`` while `src/slip10.rs:49` and
`src/slip10.rs:59` define `slip10_ed25519_test_vector_1_m_0h` and
`slip10_ed25519_test_vector_1_m_0h_1h`. Anyone running the pinned list by name — as this plan's own
"Done when" checklist requires — gets "0 tests run" and no error. This edit is the only place in the
plan that fixes it.

REPLACE:

```markdown
  - `slip10::slip10_ed25519_test_vector_{1,2}` (SLIP-0010 spec)
```

WITH:

```markdown
  - `slip10::slip10_ed25519_test_vector_1_m_0h`, `slip10_ed25519_test_vector_1_m_0h_1h` (SLIP-0010 spec)
```

Verify the anchor is gone and the real names are present:

```sh
grep -c 'slip10_ed25519_test_vector_{1,2}' CLAUDE.md    # expect: 0
grep -c 'slip10_ed25519_test_vector_1_m_0h' CLAUDE.md   # expect: 1
cargo test slip10_ed25519_test_vector 2>&1 | grep -c '\.\.\. ok'   # expect: 2
```

The replacement is a `  - ` sub-bullet, so it does not change the `grep -c '^- \*\*' CLAUDE.md`
count Step 9 pins at `13`.

- [ ] **Step 5: EDIT 3 — pinned test vectors (after the `monero::keccak256_empty_vector` bullet, line 45).**

REPLACE:

```markdown
  - `monero::keccak256_empty_vector` (original Keccak, **not** FIPS-202 SHA3)
```

WITH:

```markdown
  - `monero::keccak256_empty_vector` (original Keccak, **not** FIPS-202 SHA3)
  - `gpu::metal::gpu_seed_matches_bip39_canonical_vector` (GPU seed == the same BIP-39 canonical vector pinned at `src/seed.rs:41`, checked at index 0 **and** index 511 so per-thread indexing is covered)
  - `gpu::metal::gpu_chunk_schedule_invariance` (index 0's seed is bit-identical under `iters = 2047`, the production `R = 8` schedule, and the irregular `[1, 1000, 46, 1000]` — the resumable-wave `Pbkdf2State` is only correct if this holds)
  - `gpu::metal::gpu_ring_and_4lane_agree_over_512_deterministic_phrases` (GPU == `ring` == the 4-lane NEON path over one corpus; `ring`-only would miss the case where GPU and `ring` agree while the accelerated CPU path has drifted, i.e. CPU-found and GPU-found rows in the same CSV disagreeing with each other)
```

- [ ] **Step 6: EDIT 4 — four new Conventions rules (after the fixed-prefix bullet, line 52).**

REPLACE:

```markdown
- **Each chain's "fixed prefix" determines where the user's vanity starts.** Bitcoin skips `bc1q` (4 chars), TON skips `UQ` (2 chars), Monero skips `4` (1 char), Solana/EVM apply from char 0. This logic is inline in each chain's `matches_raw` — be careful not to change the slice indices when refactoring.
```

WITH:

```markdown
- **Each chain's "fixed prefix" determines where the user's vanity starts.** Bitcoin skips `bc1q` (4 chars), TON skips `UQ` (2 chars), Monero skips `4` (1 char), Solana/EVM apply from char 0. This logic is inline in each chain's `matches_raw` — be careful not to change the slice indices when refactoring.
- **One `autorelease pool` per command buffer, never one per wave and never none.** `run_wave` wraps *each* command buffer in `objc2::rc::autoreleasepool` and calls `cb.retain()` inside that pool. Measured on this M1: without a pool, +1,861 B per command buffer = 199 KB/s = **700 MB/hour = 16.4 GB/day**, and a multi-day search is the stated use case. Throughput is identical with and without (13,829 vs 13,804 seeds/s) — the fix is free. A bare `std::thread::spawn` body has **no ambient pool**, and a single outer pool never drains and leaks identically. Pinned by `gpu::metal::gpu_no_rss_growth_over_100k_dispatches` (`#[ignore]`) and by the 12-hour RSS soak.
- **Check command-buffer status at every `waitUntilCompleted`, not just the last.** `check_status` returns `Err(CommandBuffer { status, message })` unless status is `Completed` **and** `error()` is nil, and the **whole wave is discarded on any failure — there is no partial-success shape.** macOS resets a hung GPU after ~5 s and `waitUntilCompleted` then *returns* rather than hanging; without the check that silently drops 8 of 2048 U-iterations and `finalize` writes a T that is the XOR of only 2,039 values — a wrong-but-plausible 64-byte seed with nothing surfaced anywhere.
- **No GPU-derived key material, ever.** In `src/gpu/pbkdf2_bip39.metal`, `thread_position_in_grid` may appear **only** inside slot-offset index expressions (`keyblocks + 16*tid`, `states + tid`, `seeds + 64*tid`). Deriving any part of a key from `tid` (as the discarded `k2.metal` bench scaffolding did with `ipad[i] = H0[i] ^ (ulong)tid`) would make every wallet the tool ever emits recoverable from one 64-bit value **while still passing every address test**. Entropy comes only from `Mnemonic::new(Words12, English)` on the host. `threadgroup`, `simd_`, `barrier`, and `atomic` are likewise banned — every thread is an independent PBKDF2 with zero cross-thread communication. Both rules are grep-pinned by `gpu::kernel_src::tests::kernel_source_uses_tid_only_in_index_expressions` and `gpu::kernel_src::tests::kernel_source_bans_threadgroup_simd_barrier_atomic` in `src/gpu/kernel_src.rs`, which is compiled on every target and needs no GPU to run. The `tid` allowlist in that file is exact-line: any new use of `tid`, however innocent, must come through a deliberate edit to it.
- **Never join the GPU thread from the UI thread.** `stop_search` calls `GpuEngine::signal_stop()` (sets a **producer-only** flag — never `App::stop`, which every Rayon worker reads) and parks the engine in `App::gpu_engines`; `start_search` reaps only via the non-blocking `is_finished()` and skips the GPU for that run if an engine is still winding down. A force-join blocks the render loop for the remainder of a ~250 ms cold shader compile on an Enter/Ctrl+C/Enter sequence, and blocks **forever** if the GPU wedges inside `waitUntilCompleted` — leaving the terminal in raw mode with the alternate screen up and only `kill -9` as an exit.
```

- [ ] **Step 7: EDIT 5 — Key Files (after the `src/bip32.rs` row, line 69).**

REPLACE:

```markdown
| `src/bip32.rs` | BIP-32 secp256k1 (C `secp256k1` crate, global context) + BIP-44/BIP-84 path constants |
```

WITH:

```markdown
| `src/bip32.rs` | BIP-32 secp256k1 (C `secp256k1` crate, global context) + BIP-44/BIP-84 path constants |
| `src/verify.rs` | The `Verified` proof token + `verify_gpu` — a `Match` cannot be constructed without one |
| `src/gpu/mod.rs` | Portable GPU surface: constants, `GpuCandidate`/`SeedBlock`, `GpuStatus`/`GpuHealth`, backend selection |
| `src/gpu/pack.rs` | Host-side HMAC key/salt block packing into big-endian `u64` words — the kernel has zero endianness code |
| `src/gpu/pbkdf2_bip39.metal` | The resumable-wave PBKDF2-HMAC-SHA512 kernel, `include_str!`-ed |
| `src/gpu/kernel_src.rs` | `include_str!`s the kernel and grep-pins its source invariants (the `tid` allowlist, the banned `threadgroup`/`simd_`/`barrier`/`atomic` tokens) |
| `src/gpu/metal.rs` | The **only** file naming an Objective-C type: device, pipelines, `WaveBuffers`, `run_wave` |
| `src/gpu/selftest.rs` | Injectable startup self-test (count=512, canonical vector, ragged tail, schedule invariance) |
| `src/gpu/producer.rs` | The `vanaddy-gpu` wave loop: fill → dispatch → random `ring` audit → carve → `send_timeout` |
| `src/gpu/stub.rs` | No-op backend for every target that is not Apple Silicon with `feature = "metal"` |
```

- [ ] **Step 8: EDIT 6 — the performance table (lines 77-85).** Substitute your three measured
numbers from Step 2.

REPLACE:

```markdown
| Chain | Mean per generation | Before 4-lane PBKDF2 |
|-------|--------------------|----------------------|
| Solana | ~288 µs | ~585 µs |
| EVM | ~321 µs | ~655 µs |
| Bitcoin | ~321 µs | ~700 µs |
| TON | ~26 ms (PBKDF2-dominated) | ~51 ms |
| Monero | ~35 µs | unchanged |

PBKDF2 is ~90% of the mnemonic chains; `ring` already uses the M1's SHA-512 instructions, so the remaining per-core win came from interleaving 4 streams (see Conventions). 8 threads on an M1 (4P+4E) give ~5× one P-core; more threads than cores lose throughput. These are the rates `App::single_thread_rate` uses for ETA estimation. If you suspect a hot-loop regression, write a small one-shot timing harness — there is no committed bench harness in this tree.
```

WITH:

```markdown
| Chain | Mean per generation | Before 4-lane PBKDF2 |
|-------|--------------------|----------------------|
| Solana | ~288 µs | ~585 µs |
| EVM | ~321 µs | ~655 µs |
| Bitcoin | ~321 µs | ~700 µs |
| TON | ~26 ms (PBKDF2-dominated) | ~51 ms |
| Monero | ~35 µs | unchanged |
| **EVM + Metal GPU** (whole machine, 8 threads) | **~43 µs effective — 23,400 cand/s** | ~12,700 cand/s CPU-only |

PBKDF2 is ~90% of the mnemonic chains; `ring` already uses the M1's SHA-512 instructions, so the remaining per-core win came from interleaving 4 streams (see Conventions). 8 threads on an M1 (4P+4E) give ~5× one P-core; more threads than cores lose throughput. These are the rates `App::single_thread_rate` uses for ETA estimation. If you suspect a hot-loop regression, write a small one-shot timing harness — there is no committed bench harness in this tree.

The GPU row is a **whole-machine** figure, not a per-core one: `total candidates / elapsed` over a 12-hour EVM search with the offload on (2026-08-26), against the same measurement taken with `VANADDY_GPU=0`. The GPU sustains ~13.6k BIP-39 seeds/s and costs ~0.69 of a CPU core to *consume* them (~50.5 µs of BIP-32 + Keccak per GPU seed), so the honest gain is **~2×**, not the ~4× the raw seed rate suggests. Two things follow. First, `App::single_thread_rate() × threads` was already ~1.6× optimistic on an M1 before the GPU existed (four of those cores are E-cores) — do not attribute the post-Enter ETA jump to the GPU. Second, **never model the GPU rate**: throughput collapses to 3,000–7,000 seeds/s whenever the desktop compositor is busy, so the TUI's `GPU:` line is measured from wave completion times and `App::estimated_rate` is a pre-search estimate only.
```

- [ ] **Step 9: Run the doc gate again and see it pass.**

```sh
for pat in 'autorelease pool' 'waitUntilCompleted' 'thread_position_in_grid' \
           'Never join the GPU thread' 'gpu_chunk_schedule_invariance' 'src/gpu/metal.rs' \
           'gpu::kernel_src'; do
  printf '%-34s %s\n' "$pat" "$(grep -c "$pat" CLAUDE.md)"
done
grep -c '^- \*\*' CLAUDE.md
```

Expected: all seven patterns report `1` or more, and the bullet count is `13`. Verified on
`ba07199`: `grep -c '^- \*\*' CLAUDE.md` prints `9` today (two of those nine are outside the
Conventions list), and EDIT 4 adds exactly four, so `9 + 4 = 13`.

- [ ] **Step 10: Regenerate the codemaps.** `CLAUDE.md` states they are regenerable and must never
be hand-edited, and they currently describe a module tree with no `gpu` or `verify` in it. Invoke:

```
/cc-codemaps:update-codemaps
```

Then verify:

```sh
grep -c 'src/gpu\|gpu/' codemaps/architecture.md
grep -c 'verify' codemaps/data.md
```

Expected: both greater than `0`. If the skill is unavailable in your session, **do not hand-edit the
codemaps** — leave them untouched and add the line `Codemaps not regenerated in this commit.` to the
commit body in Task 8.7 so the staleness is on the record.

- [ ] **Step 11: Commit the docs.**

```sh
git add CLAUDE.md codemaps/
git commit -m "docs: CLAUDE.md pinned vectors, measured GPU row, four GPU hard rules

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 8.7: Squash the branch into one revertable commit

Rollback lever #5 is "ship as ONE commit so `git revert` is one command". The branch currently
carries the design-spec commit `beced09` plus every milestone's WIP commits; collapse only the WIP
commits, leaving the spec as its own commit so the design stays legible in history and the feature
stays revertable on its own.

**Files:** none modified — history only.

**Interfaces:**
- Consumes: the full working tree from Milestones 1–8
- Produces: one commit, `feat: Metal GPU PBKDF2 offload for EVM search (~2×)`

- [ ] **Step 1: Confirm the working tree is clean and nothing untracked is lying around.**

```sh
git status --short
```

Expected: no output. If `vanity_wallets.csv` appears, it is gitignored but must still be removed —
it holds plaintext seed phrases:

```sh
/bin/rm -P vanity_wallets.csv 2>/dev/null || rm -f vanity_wallets.csv
```

- [ ] **Step 2: Locate the squash base and check the range.**

```sh
BASE=$(git log --format='%H %s' | grep -m1 'docs: design spec for Metal GPU PBKDF2 offload (EVM)' | cut -d' ' -f1)
echo "BASE=$BASE"
git log --oneline "$BASE"..HEAD
git diff --stat "$BASE"..HEAD
```

Expected: `BASE` resolves to `beced09...`, the log lists every Milestone 1–8 WIP commit and nothing
else, and the diffstat touches `Cargo.toml`, `Cargo.lock`, `CLAUDE.md`, `codemaps/`, `src/app.rs`,
`src/chains/*.rs`, `src/gpu/*`, `src/main.rs`, `src/pbkdf2_lanes.rs`, `src/seed.rs`, `src/ui.rs`,
`src/verify.rs`. If it lists `ui: move key hints to a full-width bottom row`, the grep matched the
wrong commit — that one is on `main` and must stay out of the range.

- [ ] **Step 3: Save the pre-squash history.** The WIP commits are the only record of the milestone
sequence; keep a branch pointing at them until the squash is verified.

```sh
git branch feat/metal-gpu-pbkdf2-presquash
git log --oneline -1 feat/metal-gpu-pbkdf2-presquash
```

- [ ] **Step 4: Run the full gate one last time, before rewriting anything.**

```sh
cd /Users/shawnhopkinson/Rust/Vanaddy
cargo test 2>&1 | tail -3
cargo test --no-default-features 2>&1 | tail -3
cargo clippy --all-targets 2>&1 | grep -- '-->' | sort | uniq -c | wc -l
cargo clippy --all-targets 2>&1 | grep -c -- '--> src/gpu/\|--> src/verify.rs'
cargo clippy --all-targets --no-default-features 2>&1 | grep -c -- '--> src/gpu/\|--> src/verify.rs'
rustfmt --edition 2021 --check src/gpu/mod.rs src/verify.rs && echo NEW-FILES-FMT-CLEAN
cargo fmt --check 2>/dev/null | grep -c '^Diff in'
```

Expected, exactly as in Task 8.5: both test runs end `test result: ok.` with zero failures; the
first clippy line prints `12` (the pre-existing baseline recorded in Milestone 1 Task 1.8 Step 5);
both `--> src/gpu/` counts print `0`; `NEW-FILES-FMT-CLEAN`; and the whole-tree rustfmt diff count is
`84`, the pre-existing baseline. Anything else stops the ship.

Do **not** substitute `grep -c '^warning\|^error'` and expect `0` — the clean tree at `ba07199`
prints `14` for that (12 diagnostics plus two `warning: N warnings emitted` summary lines), and no
task in this plan fixes the pre-existing lints in `src/app.rs`, `src/ui.rs`, or `src/chains/*`.

- [ ] **Step 5: Write the commit message.**

```sh
cat > /tmp/vanaddy-soak/commit-msg.txt <<'MSG'
feat: Metal GPU PBKDF2 offload for EVM search (~2×)

Offloads BIP-39 PBKDF2-HMAC-SHA512 (c=2048, salt "mnemonic", dkLen 64) to the
Apple GPU on aarch64-apple-darwin, running alongside the existing CPU workers.
EVM only; Solana, Bitcoin, TON, and Monero derivation is byte-identical to
before and still calls the unchanged search::<C>.

Topology: one "vanaddy-gpu" thread owns every Objective-C object. Per wave of
8,192 candidates it generates mnemonics on the host, runs one prologue plus 256
resumable pbkdf2_iterate dispatches (R=8, 4 per command buffer, 3 in flight),
re-derives 4 random indices with ring, and carves the wave into 16 SeedBlocks
of 512 pushed over a bounded crossbeam channel. Rayon workers try_recv between
CPU batches, so the split self-balances under GPU contention.

The GPU is a seed accelerator, never a source of truth: a Match cannot be
constructed without a verify::Verified token, and a GPU-sourced candidate that
matches the pattern is re-derived from its 16-byte entropy with ring before it
can become one. A disagreement disables the GPU for the process and leaves the
CPU search running at full CPU-only rate. The CSV always carries CPU-derived
address, secret, and phrase, so a wrong GPU seed can only cost a missed match,
never an unspendable row.

Measured on an M1 (4P+4E, 8-core GPU): 23,400 cand/s hybrid vs 12,700 cand/s
CPU-only, ~43 µs effective per candidate. 12-hour soak: RSS flat (per-command-
buffer autorelease pools), no self-disable. VANADDY_GPU_SOAK_N=1e7 ring
differential: 0 mismatches.

Rollback: TUI toggle; VANADDY_GPU=0; --no-default-features (links no Metal);
automatic self-disable; or git revert of this one commit.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
MSG
cat /tmp/vanaddy-soak/commit-msg.txt
```

Substitute your measured `23,400`, `12,700`, and `~43 µs` from `/tmp/vanaddy-soak/summary.txt`, the
same values you put in `CLAUDE.md` in Task 8.6. If Task 8.6 Step 10 could not regenerate the
codemaps, append the line `Codemaps not regenerated in this commit.` before the `Co-Authored-By`
line.

- [ ] **Step 6: Squash.**

```sh
BASE=$(git log --format='%H %s' | grep -m1 'docs: design spec for Metal GPU PBKDF2 offload (EVM)' | cut -d' ' -f1)
git reset --soft "$BASE"
git status --short | head -30
```

Expected: the status lists every added and modified file as staged (`A ` / `M `), and nothing is
unstaged. `--soft` keeps the index and working tree exactly as they were.

- [ ] **Step 7: Commit.**

```sh
git commit -F /tmp/vanaddy-soak/commit-msg.txt
git log --oneline -3
```

Expected: exactly three lines — the new `feat:` commit, `beced09 docs: design spec for Metal GPU
PBKDF2 offload (EVM)`, and `4854a59 ui: move key hints to a full-width bottom row`.

- [ ] **Step 8: Verify the squashed commit is identical to what you tested.**

```sh
git diff feat/metal-gpu-pbkdf2-presquash --stat
git log --oneline main..HEAD | wc -l
cargo test 2>&1 | tail -3
```

Expected: `git diff` against the pre-squash branch prints **nothing** (the tree is identical, only
the history changed), the commit count is `2` (the spec commit plus the feature commit), and the
test run ends `test result: ok.` with zero failures.

- [ ] **Step 9: Confirm the revert lever works, then undo the check.** This proves lever #5 in one
command rather than asserting it in a doc.

```sh
git revert --no-commit HEAD
cargo build --release --no-default-features 2>&1 | tail -3
git revert --abort 2>/dev/null || git reset --hard HEAD
git status --short
```

Expected: the revert applies without conflict, the reverted tree builds, and after the reset
`git status --short` prints nothing and `git log --oneline -1` is still the `feat:` commit.

- [ ] **Step 10: Clean up the safety branch and hand off.**

```sh
git branch -D feat/metal-gpu-pbkdf2-presquash
git log --oneline -1
```

The branch is now one revertable feature commit on top of the design spec, with both feature legs
green, no NEW clippy diagnostic on either leg (the 12 pre-existing ones are untouched), no NEW
rustfmt drift (`cargo fmt --check` still reports the pre-existing 84 diffs across 14 files), a
10-million-candidate `ring` differential at zero mismatches, and a 12-hour flat-RSS soak. Use the
`superpowers:finishing-a-development-branch` skill to decide how this integrates — do not push
without the repository owner's go-ahead.

---

## Done when

- [ ] `cargo test` is green and the count equals 63 (baseline) plus every test this plan adds. No pinned vector was modified.
- [ ] All 19 pinned test functions still pass, verified by name (note the real SLIP-0010 names: `slip10_ed25519_test_vector_1_m_0h`, `slip10_ed25519_test_vector_1_m_0h_1h`).
- [ ] `cargo build --release --no-default-features` produces a working CPU-only binary that links no Metal.
- [ ] `cargo test --no-default-features` is green.
- [ ] `cargo clippy --all-targets` shows exactly the 12 baseline diagnostic sites — no new site points into `src/gpu/` or `src/verify.rs`.
- [ ] `cargo fmt --check` shows exactly the 84 pre-existing diffs — no new drift.
- [ ] `VANADDY_GPU=0 cargo run --release` starts, shows the GPU field disabled with the env reason, and searches CPU-only.
- [ ] A real EVM search with a 1-character prefix produces CSV rows that **all** re-derive from their phrase via `ring`, and the counter is honest.
- [ ] `vanity_wallets.csv` is mode `0600` after a run, including when a `0644` file existed beforehand.
- [ ] The 12-hour soak shows flat RSS (sampled every 10 minutes) and no thread accumulation.
- [ ] Hammering Enter/Ctrl+C for 30 s never stalls the UI, never leaves the terminal in raw mode, and leaves at most one live engine.
- [ ] An injected GPU fault disables the GPU, surfaces the reason in the TUI, and the CPU search continues uninterrupted.
- [ ] `CLAUDE.md` is updated: pinned-vector list (with the corrected SLIP-0010 names), a GPU row in the performance table carrying the **measured** hybrid figure, and the four new hard conventions.
- [ ] Shipped as one commit, so `git revert` is one command.
