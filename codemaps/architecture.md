> Generated: 2026-10-19 | Token-lean format for LLM context | Source: update-codemaps

# Architecture

Single-binary Rust TUI for multi-chain vanity wallet addresses. No library crate, no workspace, no committed bench harness. `src/main.rs` declares the modules and runs the event loop.

## Crate

| Field | Value |
|-------|-------|
| Name | `vanaddy` |
| Version | `0.6.0` |
| Edition | 2021 |
| Type | Binary (no `lib.rs`) |
| Entry | `src/main.rs` |
| Features | `default = ["metal"]`. `--no-default-features` builds `src/gpu/stub.rs` (no Metal link). |

## Module Tree

```
src/main.rs              # probe GPU, panic hook, 100 ms loop, exit drains
├── app                  # AppState, validation, search lifecycle, CSV, keys
├── ui                   # Ratatui: banner, config, stats, matches, detail, help
├── matcher              # precomputed prefix/suffix (+ EVM nibbles, Bech32 u5)
├── verify               # Verified token + verify_gpu (ring re-derive)
├── pbkdf2_lanes         # 4-lane PBKDF2-HMAC-SHA512; ring fallback
├── seed                 # derive_seed (ring) + derive_seeds (lanes)
├── slip10               # SLIP-0010 Ed25519 (Solana)
├── bip32                # BIP-32 secp256k1 (EVM, Bitcoin)
├── gpu/                 # EVM BIP-39 seed accelerator only
│   ├── mod              # constants, GpuStatus, SeedBlock, GpuHealth, Schedule
│   ├── pack             # host HMAC key/salt blocks (kernel has no endian code)
│   ├── kernel_src       # include_str! of pbkdf2_bip39.metal + source pins
│   ├── selftest         # startup self-test (injected derive)
│   ├── producer         # vanaddy-gpu loop: fill → dispatch → audit → carve
│   ├── metal.rs         # ONLY file naming an Objective-C type (cfg metal)
│   └── stub.rs          # no-op backend otherwise
└── chains/
    ├── mod              # Chain, Bip39GpuChain, ChainKind, search / search_hybrid
    ├── solana           # Ed25519 + Base58, m/44'/501'/0'/0'
    ├── evm              # secp256k1 + 0x-hex, m/44'/60'/0'/0/0, EIP-55, GPU tail
    ├── bitcoin          # secp256k1 + Bech32 bc1q, m/84'/0'/0'/0/0
    ├── ton              # Ed25519 + base64url UQ, W5, native 24-word
    ├── ton_cell         # TVM cell hashing
    ├── ton_mnemonic     # HMAC + 100k PBKDF2 (private)
    ├── monero           # Ed25519 scalar + Base58 4..., Electrum 25-word
    └── monero_wordlist  # 1626-word list (private)
```

`pub mod` from `main.rs`: `app, bip32, chains, gpu, matcher, pbkdf2_lanes, seed, slip10, ui, verify`. `gpu::backend` is `metal.rs` or `stub.rs` via `#[cfg_attr(..., path = ...)]`.

## High-Level Data Flow

```
main: GpuEngine::probe() BEFORE raw mode
      install panic hook (LeaveAlternateScreen, then previous hook)
      loop 100 ms: draw → poll key → drain_matches
quit: leave alt screen → drain → shutdown_gpu(600 ms) → drain → summary

Configuring ── Enter (validate OK) ──► Searching
                ▲                         │
                └── Ctrl+C / stop_search ─┘   (q quits)

Rayon pool, N workers:
  ChainKind::search(...)          once per spawn, monomorphized
    Solana|Bitcoin|Ton|Monero → search::<C>          (GPU args ignored)
    Evm                       → search_hybrid::<Evm>
         try_recv SeedBlock → drain_gpu_block (filter only)
         else               → search_cpu_step (generate_batch)

vanaddy-gpu thread (EVM, only if gpu_spawn_allowed):
  Mnemonic::new (host entropy) → pack → Metal PBKDF2 wave
  → AUDITS_PER_WAVE random ring checks → carve BLOCK=512
  → crossbeam send_timeout 100 ms
  A pattern hit calls verify_gpu (ring). CSV gets the CPU address,
  secret, and phrase. Verify mismatch disables the GPU; CPU keeps going.
```

`Match` (`chains/mod.rs:16`) is `{ chain, address, secret_hex, mnemonic, verified }`. `Verified` is a private-unit token. `write_match_row` takes `&Match`, so a row cannot be written without one. Neither type is `Clone`/`Copy`.

### Seed derivation (CPU mnemonic chains)

```
generate_batch: 4 × Mnemonic::new → seed::derive_seeds
  → pbkdf2_hmac_sha512::<4>(phrases, b"mnemonic", 2048)
       aarch64 && sha3 feature → hw::pbkdf2_lanes
       else                    → ring per lane
  → C::from_seed
```

`generate()` uses `derive_seed` (`ring`) and the same `from_seed` tail. GPU `from_gpu_seed` on EVM is that same tail. `verify` / `verify_gpu` call `derive_seed`, never `derive_seeds` and never the GPU.

## Concurrency Primitives

| Primitive | Type | Purpose |
|-----------|------|---------|
| `App.stop` | `Arc<AtomicBool>` | Worker cancel. NOT the GPU stop flag |
| `App.counter` | `Arc<AtomicU64>` | Candidates checked (CPU: `+ BATCH`; GPU: `+ chunk.len()`) |
| `App.rx` | `Option<mpsc::Receiver<Match>>` | Verified matches → UI thread |
| `App.thread_pool` | `Option<rayon::ThreadPool>` | Drop joins workers |
| `App.gpu_rx` | `Option<GpuRx>` | `crossbeam` `Receiver<Box<SeedBlock>>`, capacity 32 |
| `App.gpu_engines` | `Vec<GpuEngine>` | Parked producers. Never joined on the UI thread |
| `App.gpu_health` | `Arc<GpuHealth>` | `disable` + set-once reason, `seeds_delivered` |
| `GpuEngine.stop` | producer-only `AtomicBool` | `signal_stop`. Setting `App.stop` would kill the CPU search |

`stop_search` drops the Rayon pool (joins), drains, drops both receivers, `signal_stop`s engines, checks the CSV inode, then drops the file handle. `shutdown_gpu` polls up to its deadline and abandons a wedged engine. `GpuEngine::reap` joins only after `is_finished()`.

## Build & Test

| Command | Purpose |
|---------|---------|
| `cargo build --release` | `target/release/vanaddy` (Metal on by default) |
| `cargo build --release --no-default-features` | CPU-only binary |
| `cargo test` | in-module `#[cfg(test)]` — 239 `#[test]` fns, 3 `#[ignore]` |
| `VANADDY_NO_GPU=1 cargo test` | GPU-required tests print `SKIP:` |
| `VANADDY_GPU=0` or `VANADDY_NO_GPU=1` | runtime off; env beats the form toggle |

No `[[bench]]`. `[dev-dependencies]`: `tempfile`, `rand_chacha`.

## Platform Notes

- `pbkdf2_lanes::hw` compiles only for `aarch64` and runs when `is_aarch64_feature_detected!("sha3")`.
- Metal backend compiles only for `target_os = "macos"` + `target_arch = "aarch64"` + `feature = "metal"`. `src/gpu/metal.rs` is the only file that names an Objective-C type. `GpuEngine` and `SeedBlock` are `Send + Sync` (asserted in `gpu/mod.rs`).
- `secp256k1` builds the C library, so a C toolchain is required.

## Key Dependencies

| Crate | Role |
|-------|------|
| `ratatui 0.29` + `crossterm 0.28` | TUI |
| `rayon 1.8` | Worker pool |
| `crossbeam-channel 0.5` | GPU `SeedBlock` queue |
| `ring 0.17` | Reference PBKDF2, CKD HMAC, GPU audit / verify |
| `tiny-bip39 0.8` | BIP-39 mnemonics (also the GPU entropy source) |
| `ed25519-dalek 2`, `curve25519-dalek 4` | Ed25519 / Monero scalars |
| `secp256k1 0.30` (`global-context`) | EVM, Bitcoin |
| `sha3`, `tiny-keccak`, `sha2`, `ripemd` | Address hashes (Monero Keccak is not FIPS-202) |
| `bs58`, `bech32 0.9`, `base64`, `hex` | Encoding |
| `csv 1.3` | `vanity_wallets.csv` |
| `zeroize 1.8` | Monero keys, `SeedBlock`, GPU wave buffers |
| `objc2` / `objc2-metal` 0.6/0.3 | optional, `metal` feature only |
| `num_cpus`, `rand`, `crc32fast` | threads, audit indices, Monero checksum |

## Output

`vanity_wallets.csv` in the process CWD (`App.csv_path`; tests redirect it). Header `Chain, Address, Private Key (hex), Seed Phrase`, written by `start_search` when the file is empty. `open_csv_secure` (`app.rs:767`) is the 0o600 chokepoint: mode on create and re-assert after open. The search holds that `File` and writes via `write_match_row`. `append_match_row` is the no-handle fallback (failed open, or a test). 0600 is per open, not per row. In-memory list is a `VecDeque` capped at `MATCH_CAP` (500); `total_matches` counts every drained row.

## Performance Notes

Apple M1 P-core, release, 4-lane PBKDF2 (rates in `App::single_thread_rate`, `app.rs:281`):

| Chain | Per candidate | Dominant cost |
|-------|---------------|---------------|
| Solana | ~288 µs (3470/s) | PBKDF2 |
| EVM | ~321 µs (3115/s) | PBKDF2 + secp256k1 |
| Bitcoin | ~321 µs (3115/s) | same shape as EVM |
| TON | ~26 ms (38.4/s) | 390-iter filter + 100k PBKDF2 |
| Monero | ~35 µs (28600/s) | two Ed25519 mults; no PBKDF2 |
| EVM + Metal | ~13600 GPU seeds/s | whole machine; tail ~50.5 µs/seed (~0.69 core) |

Honest hybrid gain is ~2×, not 4×. `estimated_rate` is pre-search only. The stats `GPU rate:` line is `seeds_delivered / wall time`, never modelled (compositor load drops the GPU to 3–7k seeds/s).

Hot loop is `search::<C>` / `search_hybrid::<C>` — no `dyn`. Bitcoin, TON, and Monero `matches_raw` encode the address into a stack buffer (no `String`). Solana still heap-encodes Base58. EVM compares raw bytes (`matches_evm_raw`); EIP-55 is a stack `[u8; 40]` after one `hex::encode`.

## GPU Seed Accelerator

EVM only. Never a source of entropy or of truth. Entropy is `Mnemonic::new(Words12, English)` on the host thread. `thread_position_in_grid` may appear only as a slot offset (`kernel_src` allowlist). `threadgroup`, `simd_`, `barrier`, and `atomic` are banned in the kernel. One `autoreleasepool` per command buffer. `check_status` at every `waitUntilCompleted`; any non-Completed or non-nil `error()` discards the whole wave. Production schedule: 8192 candidates, 8 iters/dispatch, 4 dispatches/command buffer, pipeline depth 3. Self-test (~300 ms) runs on the GPU thread before `Running`.

See `chains.md`, `tui.md`, `data.md`.
