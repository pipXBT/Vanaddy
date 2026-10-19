> Generated: 2026-10-19 | Token-lean format for LLM context

# Architecture

Single-binary Rust TUI for multi-chain vanity wallet addresses. No `lib.rs`, no workspace, no `build.rs`, no `[[bench]]`. `src/main.rs` declares the modules and runs the event loop.

## Crate

| Field | Value |
|-------|-------|
| Name / version | `vanaddy` `0.6.0`, edition 2021 |
| Type | Binary only, entry `src/main.rs` |
| Features | `default = ["metal"]`; `metal = ["dep:objc2", "dep:objc2-foundation", "dep:objc2-metal"]` |
| Unix-only | `stop_search` uses `std::os::unix::fs::MetadataExt` without a `cfg` |

## Module Tree

```
src/main.rs                # gpu::probe, ratatui::try_init, 100 ms loop, exit drains
├── app                    # App/AppState, validate, start/stop_search, drain_matches, CSV, keys
├── ui                     # Ratatui: banner, config form, stats (+ GPU rate), matches, detail, help
├── matcher                # Matcher: prefix/suffix, EVM hex bytes + odd nibble, Bech32 5-bit prefix
├── verify                 # verify_gpu: ring re-derive of a GPU-sourced match
├── pbkdf2_lanes           # LANES=4 PBKDF2-HMAC-SHA512 (aarch64 hw), ring fallback
├── seed                   # PBKDF2_ROUNDS=2048, BIP39_SALT, CANONICAL_*; derive_seed / derive_seeds
├── slip10                 # SLIP-0010 Ed25519, PHANTOM_SOLANA_PATH
├── bip32                  # BIP-32 secp256k1, EVM_PATH, BTC_BIP84_PATH
├── gpu/                   # EVM BIP-39 seed accelerator
│   ├── mod                # constants, GpuError, GpuStatus, GpuDisableReason, SeedBlock, GpuHealth, Schedule
│   ├── pack               # KeyBlock, pack_key_block, BIP39_SALT_BLOCK (all BE padding host-side)
│   ├── kernel_src         # KERNEL_SRC = include_str!("pbkdf2_bip39.metal") + source guards
│   ├── pbkdf2_bip39.metal # kernels pbkdf2_prologue, pbkdf2_iterate
│   ├── selftest           # self_test(stop, derive): derive injected, no Metal type
│   ├── producer           # pub(crate): audit_wave, carve_and_send, run_guarded, producer()
│   ├── metal.rs           # backend: probe, MetalPbkdf2, GpuEngine (cfg metal)
│   └── stub.rs            # backend: probe → Unavailable, no-op GpuEngine
└── chains/
    ├── mod                # Match, Chain, ChainKind, search / search_hybrid, emit_gpu_match
    ├── solana             # Ed25519 + Base58, m/44'/501'/0'/0'
    ├── evm                # secp256k1 + 0x-hex, m/44'/60'/0'/0/0, EIP-55; from_seed, verify
    ├── bitcoin            # secp256k1 + Bech32 bc1q, m/84'/0'/0'/0/0
    ├── ton                # Ed25519 + base64url UQ, W5 wallet
    ├── ton_cell           # private: W5 state_init cell hash
    ├── ton_mnemonic       # private: 24-word TON mnemonic, 390-iter filter + 100k PBKDF2
    ├── monero             # Ed25519 scalars + Base58, Electrum 25-word
    └── monero_wordlist    # private: MONERO_WORDLIST &[&str; 1626]
```

`main.rs`: `pub mod app, bip32, chains, gpu, matcher, pbkdf2_lanes, seed, slip10, ui, verify`. `gpu::backend` is `metal.rs` when `all(target_os = "macos", target_arch = "aarch64", feature = "metal")`, else `stub.rs` (`#[cfg_attr(..., path = ...)]`). Both export `probe` and `GpuEngine`.

## High-Level Data Flow

```
main: catch_unwind(gpu::probe)  BEFORE ratatui::try_init (try_init owns the panic hook)
      App::with_gpu_status(status)
      loop 100 ms: draw → poll key → drain_matches → should_quit? set app.stop, break
exit: ratatui::restore → drain_matches → shutdown_gpu(600 ms) → drain_matches → summary

Configuring ── Enter (validate Ok) ──► Searching
     ▲                                    │
     └──── Ctrl+C / stop_search ──────────┘    q quits (Configuring: not in a text field; Searching: stop_search first)

start_search: open_csv_secure (+ header) → fresh GpuHealth → [GPU spawn] → Rayon pool
  pool.spawn: (0..N).into_par_iter() → ChainKind::search(matcher, stop, counter, tx, gpu_rx, health)
    Solana|Bitcoin|Ton|Monero → search::<C>        loop search_cpu_step::<C> (GPU args ignored)
    Evm                       → search_hybrid      try_recv SeedBlock → drain_gpu_block
                                                   else               → search_cpu_step::<Evm>
  match → mpsc::Sender<Match> → App.rx → drain_matches → CSV row + VecDeque (MATCH_CAP 500)
```

`Match` (`chains/mod.rs`) is `{ chain, address, secret_hex, mnemonic }`, all `String`. `search_cpu_step` is the one CPU batch body shared by `search` and `search_hybrid`; it adds `C::BATCH` to `counter`.

### Seed derivation (CPU BIP-39 chains: Solana, EVM, Bitcoin)

```
generate_batch: LANES × Mnemonic::new → seed::derive_seeds
  → pbkdf2_hmac_sha512::<LANES>(phrases, BIP39_SALT, PBKDF2_ROUNDS)
       aarch64 && is_aarch64_feature_detected!("sha3") → hw::pbkdf2_lanes
       else                                            → ring_pbkdf2_sha512 per lane
  → per-chain from_seed tail
```

`generate()` uses `derive_seed` (`ring`) and the same tail. GPU seeds go through `Evm::from_seed` too. `verify_gpu` and `audit_wave` call `derive_seed` only, never `derive_seeds` or the GPU. TON skips `seed`: `ton_mnemonic::generate_ton_wallets` calls `pbkdf2_hmac_sha512::<LANES>` directly (390-iter filter, then 100k).

## GPU Offload Path (EVM only)

```
probe (main, once)    metal: MTLCreateSystemDefaultDevice → Ready{device} | Unavailable
                      stub:  Unavailable("built without Metal support ...")
App::with_gpu_status  gpu_requested = !gpu_env_off(..) && Ready;  env veto of Ready → Disabled(UserOff)
validate              validated_gpu = gpu_effective()   (requested && Ready|Initializing|Running && Evm)
start_search          spawn_gpu = validated_gpu && gpu_engines.is_empty()   (reap finished first)
                      crossbeam_channel::bounded(CHANNEL_CAPACITY=32) → GpuEngine::start(tx, health)

vanaddy-gpu thread (metal GpuEngine::start, returns at once with Initializing):
  run_guarded(health, finished, producer)   catch_unwind → Panicked; FinishGuard sets finished
  producer: QoS USER_INITIATED → MetalPbkdf2::new (device, compile, 2 pipelines, 3.5 MiB buffers)
          → selftest::self_test(stop, derive_with_schedule)  ~1 s, before anything is sent
          → status Running{device}
          → per wave (WAVE=8192), until stop || health.disable:
              1. Mnemonic::new(Words12) entropy + pack_key_block      (host entropy only)
              2. run_wave(keys, BIP39_SALT_BLOCK, 2048, Production, stop)  Ok(None) = stopped
              3. audit_wave: AUDITS_PER_WAVE=4 random indices vs ring → AuditMismatch
              4. carve_and_send: one zip → Box<SeedBlock> of BLOCK=512, send_timeout 100 ms retry
stub GpuEngine::start: drops tx, raises NotSupported.

worker (search_hybrid): if !health.disable, rx.try_recv() → drain_gpu_block
  chunks of Evm::BATCH × 16 = 64 (stop checked per chunk)
  Evm::from_seed(untrusted seed) → matches_raw?  → emit_gpu_match
      verify::verify_gpu(entropy, gpu_addr): from_entropy → derive_seed (ring) → Evm::from_seed
        Some((addr, secret, phrase)) → Match built from CPU values only
        None → health.raise(VerifyMismatch{address}); candidate dropped
  counter += chunk.len(); health.seeds_delivered += chunk.len()
```

Fault handling: every fault is `GpuHealth::raise` (set-once `OnceLock` reason, then `disable`). `drain_matches` promotes it to sticky `GpuStatus::Disabled` (clears `gpu_requested`, `validated_gpu`, `gpu_rx`); the CPU search keeps running. An engine that finishes without a raised reason is treated as `Panicked`. `GpuDisableReason`: `NotSupported, UserOff, Backend(GpuError), SelfTest(SelfTestError), AuditMismatch{index}, VerifyMismatch{address}, Panicked`.

Self-test (`selftest.rs`): 510 fresh distinct entropies + canonical phrase at index 0 and 511; canonical vector checked before any `ring` cross-check; no all-zero or `0xA5`-poisoned output; every output vs `derive_seed`; ragged count 511; schedule invariance over `Production`, `IRREGULAR_SCHEDULE` `[1, 1000, 46, 1000]`, one-shot `[2047]`. Any failure → `SelfTest(..)`.

Metal backend (`metal.rs`, only file naming Objective-C types): one prologue command buffer, then 2047 iterations at `ITERS_PER_DISPATCH=8`, `DISPATCHES_PER_COMMAND_BUFFER=4`, `PIPELINE_DEPTH=3` in flight, threadgroup `MAX_THREADS_PER_THREADGROUP=256` (`VANADDY_GPU_TG` overrides) clamped to the pipelines' max. `check_status` (`classify_command_buffer_status`: Completed=4 with nil error, else `CommandBuffer{..}`; message `localizedDescription [domain=…, code=…]`) at every `waitUntilCompleted`; failure discards the wave. Seeds poisoned `0xA5` before each wave; `WaveBuffers` zeroed on drop. Never calls `setMathMode`.

Kernel guards (`kernel_src` tests): bans `threadgroup`, `simd_`, `barrier`, `atomic`; `tid` only on allowlisted index lines; exactly the two kernels. SHA-512 rounds: Ch = `g^(e&(f^g))`, Maj = `b^((a^b)&(b^c))` with `a^b` carried as the next round's `b^c`; both round loops `#pragma unroll(16)` (full unroll of `sha512_hash64` measured 41% slower on M1).

## Concurrency Primitives

| Primitive | Type | Purpose |
|-----------|------|---------|
| `App.stop` | `Arc<AtomicBool>` | Worker cancel. NOT the GPU stop flag |
| `App.counter` | `Arc<AtomicU64>` | Candidates checked (CPU `+ BATCH`, GPU `+ chunk.len()`) |
| `App.rx` | `Option<mpsc::Receiver<Match>>` | Matches → UI thread |
| `App.thread_pool` | `Option<rayon::ThreadPool>` | Drop signals workers to exit; does NOT join (rayon `terminate`) |
| `App.gpu_rx` | `Option<GpuRx>` | `crossbeam_channel::Receiver<Box<SeedBlock>>`, App's clone |
| `App.gpu_engines` | `Vec<GpuEngine>` | Parked engines; reaped only once `is_finished()` |
| `App.gpu_health` | `Arc<GpuHealth>` | `disable`, set-once reason, `seeds_delivered`; fresh per search |
| `GpuEngine.stop` | producer-only `Arc<AtomicBool>` | `signal_stop`; non-blocking, never joins |
| `GpuEngine.finished` | `Arc<AtomicBool>` | Release in `FinishGuard`, Acquire in `is_finished` |
| `GpuEngine.status` | `Arc<Mutex<GpuStatus>>` | poison-immune `set_status` / `read_status` |

`GpuEngine`, `SeedBlock`, `GpuHealth` are asserted `Send + Sync` in `gpu/mod.rs`. `stop_search`: set stop → drop pool (non-blocking) → `rx.iter()` until the job's only `Sender` drops (every worker returned) → drain → drop `rx`, `gpu_rx` → `signal_stop` engines → CSV dev/inode check → drop file. `shutdown_gpu(deadline)` polls `is_finished` every 5 ms, then abandons the rest.

## Build & Test

| Command | Purpose |
|---------|---------|
| `cargo build --release` / `cargo run` | `target/release/vanaddy` / dev TUI, Metal on by default |
| `cargo build --release --no-default-features` | CPU-only binary (`stub.rs`, no Metal link) |
| `cargo test` | In-module `#[cfg(test)]`: 173 `#[test]`, 4 `#[ignore]` |
| `VANADDY_NO_GPU=1 cargo test` | Metal tests print `SKIP:` and pass |
| `cargo test --release gpu_seed_rate_end_to_end -- --ignored --nocapture` | Re-measure `EVM_GPU_SEEDS_PER_SEC` |
| `cargo clippy --all-targets` / `cargo fmt` | Default lints / format, no config files |
| `VANADDY_GPU=0` or `VANADDY_NO_GPU=1` | Runtime GPU off; env beats the form toggle |

## Platform Notes

- `pbkdf2_lanes::hw` compiles only on `aarch64`, runs when `is_aarch64_feature_detected!("sha3")`.
- Metal backend: `target_os = "macos"` + `target_arch = "aarch64"` + `feature = "metal"`. objc2 deps are declared under `[target.'cfg(all(target_os = "macos", target_arch = "aarch64"))'.dependencies]`.
- `producer.rs`, `selftest.rs`, `pack.rs`, `kernel_src.rs` compile on every target and their `tests` run without a GPU; only `producer()`, `set_thread_qos_user_initiated` and `producer::gpu_tests` are `cfg`-gated to Metal.

## Key Dependencies

| Crate | Role |
|-------|------|
| `ratatui 0.29` + `crossterm 0.28` | TUI |
| `rayon 1.8` | Worker pool |
| `crossbeam-channel 0.5` | GPU `SeedBlock` queue |
| `ring 0.17` | Reference PBKDF2, HMAC-SHA512 (`bip32::hmac512`, also SLIP-10; TON mnemonic), SHA-256 (Bitcoin, TON cells) |
| `tiny-bip39 0.8` (`bip39`) | BIP-39 mnemonics, also the GPU entropy source |
| `ed25519-dalek 2`, `curve25519-dalek 4` | Solana/TON keys, Monero scalars |
| `secp256k1 0.30` (`global-context`) | EVM, Bitcoin; builds a C library (needs a C toolchain) |
| `sha3 0.9` | `Keccak256` for EVM and Monero (original Keccak, not FIPS-202) |
| `ripemd 0.1` | Bitcoin hash160 |
| `bs58 0.4`, `bech32 0.9`, `base64 0.22`, `hex 0.4` | Encoding |
| `csv 1.3` | `vanity_wallets.csv` |
| `zeroize 1.8` (`derive`) | Monero keys, `SeedBlock`, `KeyBlock`, producer wave buffers |
| `num_cpus 1.16`, `rand 0.8`, `crc32fast 1.4` | Threads; audit indices + Monero `OsRng`; Monero checksum |
| `objc2 0.6`, `objc2-foundation 0.3`, `objc2-metal 0.3` | Optional, `metal` feature, macOS aarch64 only |
| dev: `tempfile 3`, `rand_chacha 0.3` | Test temp dirs, seeded RNG |

## Output

`vanity_wallets.csv` in the process CWD (`App.csv_path`, tests redirect it). Header `Chain, Address, Private Key (hex), Seed Phrase`, written by `start_search` when the file is empty; a failed open or header aborts the search back to Configuring. `open_csv_secure` is the 0o600 chokepoint (mode on create, then `fchmod` on the handle after every open; error propagates). The search holds that `File` and writes via `write_match_row`; `append_match_row` is the no-handle fallback. A failed row write counts `csv_write_failures` and sets `stop`. In-memory list is a `VecDeque` capped at `MATCH_CAP` (500); `total_matches` counts every drained row.

## Performance Notes

Apple M1 P-core, release, 4-lane PBKDF2 (`App::single_thread_rate`):

| Chain | Per candidate | Dominant cost |
|-------|---------------|---------------|
| Solana | ~288 µs (3470/s) | PBKDF2 |
| EVM | ~321 µs (3115/s) | PBKDF2 + secp256k1 |
| Bitcoin | ~321 µs (3115/s) | same shape as EVM |
| TON | ~26 ms (38.4/s) | 390-iter filter + 100k PBKDF2 |
| Monero | ~35 µs (28600/s) | two Ed25519 mults, no PBKDF2 |
| EVM + Metal | `EVM_GPU_SEEDS_PER_SEC = 13_600` | whole machine; CPU tail `EVM_GPU_TAIL_SECS = 50.5e-6` (~0.69 core) |

`estimated_rate` (whenever no search runs) = `gpu_rate + (threads - tail) × per_thread` when `gpu_effective()`. The stats `GPU rate:` line is `gpu_measured_rate()` = `seeds_delivered / wall time`, never modelled.

Hot loop is `search::<C>` / `search_hybrid`, no `dyn`. Solana, Bitcoin, TON and Monero `matches_raw` encode into stack buffers (Solana: `bs58::encode(..).into(&mut [u8; 44])`). EVM compares raw bytes (`matches_evm_raw`); case-sensitive EIP-55 is a stack `[u8; 40]` (`hex::encode_to_slice`). `search_cpu_step` zeroizes every non-matching phrase.
