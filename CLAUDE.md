# Vanaddy — Claude Code Notes

A multi-threaded, multi-chain vanity wallet address generator in Rust. Single-binary TUI built with Ratatui; supports Solana, EVM, Bitcoin, TON, and Monero.

## Quick Architecture

`src/main.rs` is the binary entry (no `lib.rs`). It declares modules `app`, `bip32`, `chains`, `gpu`, `matcher`, `pbkdf2_lanes`, `seed`, `slip10`, `ui`, `verify` and runs the Ratatui event loop directly. Search workers run on a Rayon thread pool; matches stream back over `mpsc` and are appended to `vanity_wallets.csv` (chmod 0600).

On Apple Silicon a single `vanaddy-gpu` thread offloads BIP-39 PBKDF2-HMAC-SHA512 to Metal **for EVM only**, pushing `SeedBlock`s of 512 candidates over a bounded `crossbeam-channel` that Rayon workers drain with `try_recv` between CPU batches. The GPU is a *seed accelerator*: never a source of entropy, never a source of truth. Every GPU-sourced match is re-derived with `ring` before a `Match` can be constructed, and the CSV always carries the CPU-derived address, secret, and phrase. Build it out with `--no-default-features`; turn it off at runtime with `VANADDY_GPU=0`.

For full architectural detail, see `codemaps/`:

- `codemaps/architecture.md` — module graph, data flow, dependencies
- `codemaps/chains.md` — `Chain` trait + per-chain (Solana / EVM / Bitcoin / TON / Monero) detail
- `codemaps/tui.md` — App state machine, key handling, render layout
- `codemaps/data.md` — types, crypto helpers, path constants, pinned vectors

The codemaps are regenerable via `/cc-codemaps:update-codemaps`. Don't hand-edit them — put rules and constraints here in CLAUDE.md instead.

## Common Commands

| Command | Purpose |
|---------|---------|
| `cargo build --release` | Production binary at `target/release/vanaddy` |
| `cargo run` | Dev TUI. Debug build. Do not use it to judge speed. |
| `cargo test` | Run all unit tests (in-module `#[cfg(test)]`) |
| `cargo clippy --all-targets` | Lint (no clippy config file; default lints) |
| `cargo fmt` | Formats the whole tree. A large pre-existing rustfmt diff is already there. Format only the file you edited. |
| `cargo test --no-default-features` | Run the suite with the Metal backend compiled out (`src/gpu/stub.rs`) |
| `cargo build --release --no-default-features` | CPU-only binary; links no Metal (`otool -L` shows none) |
| `VANADDY_NO_GPU=1 cargo test` | Skip the GPU-required tests deliberately; each prints `SKIP:` |
| `VANADDY_GPU_SOAK_N=1e7 cargo test -- --ignored` | GPU soak: full `ring` differential + the RSS guard (~150 min debug; ~50 min with `--release`) |

There is no separate library target.

## Conventions

- **Cryptographic correctness is paramount.** The whole point of this tool is that vanity addresses import into the user's wallet for the *full* secret/seed material we display. If derivation drifts, addresses produced by this tool look correct but lead to wallets nobody controls.
- **Pinned test vectors are load-bearing.** The following tests must continue to pass on any change touching their pipeline:
  - `seed::derive_seed_matches_bip39_vector` (BIP-39 seed)
  - `seed::derive_seeds_matches_derive_seed_per_lane` (4-lane seeds == ring seeds)
  - `pbkdf2_lanes::every_lane_matches_bip39_canonical_vector`, `distinct_lanes_match_ring_reference`, `ton_salts_and_iteration_counts_match_ring` (hardware SHA-512 PBKDF2 vs BIP-39 vector and `ring`)
  - `slip10::slip10_ed25519_test_vector_1_m_0h`, `slip10_ed25519_test_vector_1_m_0h_1h` (SLIP-0010 spec)
  - `solana::solana_phantom_derivation_from_canonical_phrase` (Phantom-importable)
  - `bitcoin::bip84_canonical_vector` (BIP-84 spec)
  - `evm::eip55_canonical_vector`, `eip55_second_vector` (EIP-55 spec)
  - `evm::bip44_canonical_vector` (m/44'/60'/0'/0/0 of the canonical phrase = first MetaMask account)
  - `{solana,evm,bitcoin}::generate_batch_emits_lane_count_candidates_matching_single_path`, `ton::generate_batch_emits_lane_count_wallets_with_consistent_addresses` (batched path == single path)
  - `ton::ton_tonkeeper_round_trip_vector` (full Tonkeeper W5 round-trip)
  - `ton_cell::wallet_v5r1_matches_tonkeeper_vector` (W5 state_init hash)
  - `monero::keccak256_empty_vector` (original Keccak, **not** FIPS-202 SHA3)
  - `gpu::metal::gpu_seed_matches_bip39_canonical_vector` (a single phrase at index 0 against the same BIP-39 canonical vector pinned at `src/seed.rs:41` — the anchor to external ground truth, since every other GPU test compares against `ring`)
  - `gpu::metal::gpu_chunk_schedule_invariance` (index 0's seed is bit-identical under `iters = 2047`, the production `R = 8` schedule, and the irregular `[1, 1000, 46, 1000]` — the resumable-wave `Pbkdf2State` is only correct if this holds)
  - `gpu::metal::gpu_ring_and_4lane_agree_over_512_deterministic_phrases` (GPU == `ring` == the 4-lane NEON path over one corpus; `ring`-only would miss the case where GPU and `ring` agree while the accelerated CPU path has drifted, i.e. CPU-found and GPU-found rows in the same CSV disagreeing with each other; this is the only test that spans indices 0..511, so it is what pins per-thread indexing)
- **Seed derivation runs 4 lanes at a time.** `pbkdf2_lanes::pbkdf2_hmac_sha512` interleaves `LANES` (= 4) independent PBKDF2-HMAC-SHA512 streams on the ARMv8.2 SHA-512 instructions (~2× per core on M1; runtime-detected, falls back to `ring` elsewhere). Solana/EVM/Bitcoin/TON set `Chain::BATCH = LANES` and override `generate_batch`; `search<C>` advances the counter per batch. Keep `generate()` (single, `ring`) and `generate_batch` (lanes) sharing one `from_seed` tail — the batch tests cross-check the two paths against each other, so any divergence in derivation is caught.
- **Keep the hot loop allocation-free.** `chains/<x>.rs::matches_raw` is called per-candidate. Don't introduce `to_lowercase()` (allocates), `format!`, `Vec::new()`, etc. inside it. Use `eq_ignore_ascii_case` over byte slices, stack arrays, and pre-computed `Matcher` fields.
- **Monomorphization, not dyn dispatch.** `ChainKind::search` chooses `search::<C: Chain>` once at thread spawn. Don't refactor to `Box<dyn Chain>` or any v-table-based dispatch — it would re-introduce per-candidate indirection.
- **Monero secrets must be zeroized.** `MoneroKeypair: Zeroize + ZeroizeOnDrop`. Don't hold them in plain `[u8; 32]` arrays beyond the candidate that produced them. Discarded keys must be wiped on drop.
- **CSV is `chmod 0600` always.** `open_csv_secure` is the single chokepoint: it sets `.mode(0o600)` at create AND re-asserts 0600 after every open. A failed `set_permissions` returns. Do not swallow it.
- **Ends-with text is `vanity_suffix`.** `start_search` and `total_vanity_chars` read that field. `vanity_prefix` is only the starts-with string, and the prefix half of starts-and-ends.
- **`stop_search` drops the Rayon pool, then drains.** Joining first keeps the last send. A failed CSV row sets `App::stop` and the on-screen list still caps at `MATCH_CAP`.
- **SLIP-0010 indices must all be hardened.** `slip10_derive_ed25519` panics on non-hardened input — Ed25519 doesn't support non-hardened derivation. If you add a new Solana/Ed25519 path, all components need the `0x80000000` flag.
- **Each chain's "fixed prefix" determines where the user's vanity starts.** Bitcoin skips `bc1q` (4 chars), TON skips `UQ` (2 chars), Monero skips `4` (1 char), Solana/EVM apply from char 0. This logic is inline in each chain's `matches_raw` — be careful not to change the slice indices when refactoring.
- **One autorelease pool per Metal command buffer.** `run_wave` wraps each buffer. Not one pool per wave, and not none. A `std::thread` has no ambient pool.
- **A failed command buffer drops the whole wave.** No partial PBKDF2 result. `waitUntilCompleted` returning is not success.
- **`tid` is only a buffer index.** Entropy comes from `Mnemonic::new` on the host. No `threadgroup`, `simd_`, `barrier`, or `atomic` in the kernel. Both rules are grep-pinned in `src/gpu/kernel_src.rs`. A new `tid` use has to be added to that allowlist on purpose.
- **Never join the GPU thread from the UI thread.** `stop_search` calls `GpuEngine::signal_stop()` (sets a **producer-only** flag — never `App::stop`, which every Rayon worker reads) and parks the engine in `App::gpu_engines`; `start_search` reaps only via the non-blocking `is_finished()` and skips the GPU for that run if an engine is still winding down. A force-join blocks the render loop for the remainder of a ~250 ms cold shader compile on an Enter/Ctrl+C/Enter sequence, and blocks **forever** if the GPU wedges inside `waitUntilCompleted` — leaving the terminal in raw mode with the alternate screen up and only `kill -9` as an exit.

## Key Files

| File | Role |
|------|------|
| `src/main.rs` | Binary entry, terminal setup, event loop |
| `src/app.rs` | `App` struct + `AppState` machine, key handling, search lifecycle |
| `src/ui.rs` | Ratatui rendering: banner, config form, stats, matches, detail, help |
| `src/matcher.rs` | `Matcher` with pre-computed prefix/suffix data |
| `src/chains/mod.rs` | `Chain` trait (`generate` / `generate_batch`), `ChainKind` enum, monomorphized batched `search<C>` |
| `src/chains/{solana,evm,bitcoin,ton,monero}.rs` | Per-chain key gen, address encoding, match logic |
| `src/chains/ton_cell.rs` | TVM cell representation hashing (W5 wallet) |
| `src/chains/ton_mnemonic.rs` | TON-native 24-word mnemonic (HMAC + 100k PBKDF2) |
| `src/seed.rs` | BIP-39 seed derivation: `derive_seed` (`ring`) and `derive_seeds` (4-lane) |
| `src/pbkdf2_lanes.rs` | Multi-lane PBKDF2-HMAC-SHA512 on aarch64 SHA-512 intrinsics, `ring` fallback |
| `src/slip10.rs` | SLIP-0010 Ed25519 + Phantom path constant |
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

## Output

Single CSV at `vanity_wallets.csv` in the current working directory. Header: `Chain, Address, Private Key (hex), Seed Phrase`. Appended one row per match. Contains plaintext seed phrases — the tool prints a security warning on exit when matches were found.

## Performance Targets (Apple M1 P-core, release, 2026-08)

| Chain | Mean per generation | Before 4-lane PBKDF2 |
|-------|--------------------|----------------------|
| Solana | ~288 µs | ~585 µs |
| EVM | ~321 µs | ~655 µs |
| Bitcoin | ~321 µs | ~700 µs |
| TON | ~26 ms (PBKDF2-dominated) | ~51 ms |
| Monero | ~35 µs | unchanged |
| **EVM + Metal GPU** (whole machine, 8 threads) | *estimated, not yet measured on this machine* | — |

PBKDF2 is ~90% of the mnemonic chains; `ring` already uses the M1's SHA-512 instructions, so the remaining per-core win came from interleaving 4 streams (see Conventions). 8 threads on an M1 (4P+4E) give ~5× one P-core; more threads than cores lose throughput. These are the rates `App::single_thread_rate` uses for ETA estimation. If you suspect a hot-loop regression, write a small one-shot timing harness — there is no committed bench harness in this tree.

The GPU row is a **whole-machine** figure, not a per-core one — and on this tree it is still an estimate: the 12-hour soak and the `VANADDY_GPU=0` comparison have not been run here. The GPU sustains ~13.6k BIP-39 seeds/s and costs ~0.69 of a CPU core to *consume* them (~50.5 µs of BIP-32 + Keccak per GPU seed), so the honest gain is **~2×**, not the ~4× the raw seed rate suggests. Two things follow. First, `App::single_thread_rate() × threads` was already ~1.6× optimistic on an M1 before the GPU existed (four of those cores are E-cores) — do not attribute the post-Enter ETA jump to the GPU. Second, **never model the GPU rate**: throughput collapses to 3,000–7,000 seeds/s whenever the desktop compositor is busy, so the TUI's `GPU rate:` line is measured from wave completion times and `App::estimated_rate` is a pre-search estimate only.
