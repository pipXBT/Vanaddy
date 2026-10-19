# Vanaddy — Claude Code Notes

A multi-threaded, multi-chain vanity wallet address generator in Rust. Single-binary TUI built with Ratatui; supports Solana, EVM, Bitcoin, TON, and Monero.

## Quick Architecture

`src/main.rs` is the binary entry (no `lib.rs`). It declares modules `app`, `bip32`, `chains`, `gpu`, `matcher`, `pbkdf2_lanes`, `seed`, `slip10`, `ui`, `verify` and runs the Ratatui event loop directly. Search workers run on a Rayon thread pool; matches stream back over `mpsc` and are appended to `vanity_wallets.csv` (chmod 0600).

On Apple Silicon a `vanaddy-gpu` thread offloads BIP-39 PBKDF2 to Metal **for EVM only**. The GPU is a *seed accelerator*: never a source of entropy, never a source of truth. `chains::emit_gpu_match` is the only place a GPU candidate becomes a `Match`, and only after `verify::verify_gpu` re-derives it with `ring`; the CSV always carries the CPU-derived address, secret, and phrase. Build it out with `--no-default-features`; turn it off at runtime with `VANADDY_GPU=0`.

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
| `cargo test` | Unit tests (in-module `#[cfg(test)]`). Skips the 4 `#[ignore]` GPU tests, including the live GPU→CSV gate `hybrid_evm_search_with_live_gpu_emits_only_rederivable_matches` (run it by name with `-- --ignored`) |
| `cargo clippy --all-targets` | Lint (no clippy config file; default lints) |
| `cargo fmt` | Don't: 12 files carry a pre-existing rustfmt diff. Use `rustfmt --edition 2021 src/<file>.rs`; on `main.rs` or a `mod.rs` it also rewrites child modules, so revert hunks you didn't write. |
| `cargo test --no-default-features` | Run the suite with the Metal backend compiled out (`src/gpu/stub.rs`) |
| `cargo build --release --no-default-features` | CPU-only binary; links no Metal (`otool -L` shows none) |
| `VANADDY_NO_GPU=1 cargo test` | Skip the GPU-required tests deliberately; they pass, and print `SKIP:` only with `-- --nocapture` |
| `VANADDY_GPU_SOAK_N=1e7 cargo test --release gpu_soak_matches_ring -- --ignored --nocapture` | GPU soak: every GPU seed vs `ring` (~50 min; ~150 min debug). RSS guard alone: `cargo test --release gpu_rss_does_not_run_away -- --ignored`. A bare `-- --ignored` runs all 4 ignored GPU tests at once on one GPU. |


## Conventions

- **Cryptographic correctness is paramount.** The whole point of this tool is that vanity addresses import into the user's wallet for the *full* secret/seed material we display. If derivation drifts, addresses produced by this tool look correct but lead to wallets nobody controls.
- **Pinned test vectors are load-bearing.** These must pass on any change touching their pipeline. Paths omit `chains::` and `tests::`; run one with `cargo test <fn_name>`:
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
  - `gpu::backend::gpu_seed_matches_bip39_canonical_vector` (`metal.rs` is mounted as `gpu::backend`; GPU vs `seed::CANONICAL_SEED_HEX`, the only GPU test anchored to external ground truth instead of `ring`)
  - `gpu::backend::gpu_chunk_schedule_invariance` (5 schedules — one-shot `[2047]`, production `R = 8`, `[1, 1000, 46, 1000]`, `[1]`, `[500, 500, 500]` — each give `ring`'s seed for all 3 phrases; the resumable `Pbkdf2State` is only correct if this holds)
  - `gpu::backend::gpu_ring_and_4lane_agree_over_512_deterministic_phrases` (GPU == `ring` == the 4-lane NEON path over one corpus; `ring`-only would miss a drifted CPU lane path, i.e. CPU-found and GPU-found rows in one CSV disagreeing)
  - Monero has no external wallet vector (`monero_seed_phrase_*_pinned` are self-captured). Add a `monero-wallet-cli` spend key → address + 25-word vector before touching `generate_keys`, `monero_seed_phrase` or the address layout.
- **Seed derivation runs 4 lanes at a time.** `pbkdf2_lanes::pbkdf2_hmac_sha512` interleaves `LANES` (= 4) independent PBKDF2-HMAC-SHA512 streams on the ARMv8.2 SHA-512 instructions (~2× per core on M1; runtime-detected, falls back to `ring` elsewhere). Solana/EVM/Bitcoin/TON set `Chain::BATCH = LANES` and override `generate_batch`; `search_cpu_step` adds `BATCH` to the counter. Solana/EVM/Bitcoin keep `generate()` (single, `ring`) and `generate_batch` (lanes) on one `from_seed` tail; TON has none (`mnemonic_to_signing_key` vs inline in `generate_ton_wallets`), so change both together. The batch tests cross-check the two paths, so any divergence in derivation is caught.
- **Keep the hot loop allocation-free.** `chains/<x>.rs::matches_raw` is called per-candidate. Don't introduce `to_lowercase()` (allocates), `format!`, `Vec::new()`, etc. inside it. Use `eq_ignore_ascii_case` over byte slices, stack arrays, and pre-computed `Matcher` fields.
- **Monomorphization, not dyn dispatch.** `ChainKind::search` picks the arm once per thread: `search::<C>`, or `search_hybrid` for EVM (don't "simplify" EVM to `search::<Evm>`: that silently drops the GPU). Don't refactor to `Box<dyn Chain>` or any v-table-based dispatch — it would re-introduce per-candidate indirection.
- **Monero secrets must be zeroized.** `MoneroKeypair: Zeroize + ZeroizeOnDrop`. Don't hold them in plain `[u8; 32]` arrays beyond the candidate that produced them. Discarded keys must be wiped on drop. `search_cpu_step` also wipes every non-matching candidate's phrase (the whole wallet, any chain); keep that `else`.
- **CSV is `chmod 0600` always.** `open_csv_secure` is the single chokepoint: it sets `.mode(0o600)` at create AND re-asserts 0600 after every open. The re-assert is `fchmod` on the handle (`file.set_permissions`), not the path, and its error propagates. Do not swallow it.
- **Ends-with text is `vanity_suffix`.** `App::patterns()` is the single source; `start_search`, `total_vanity_chars` and `validate` go through it. `vanity_prefix` is only the starts-with string, and the prefix half of starts-and-ends.
- **`stop_search` waits for the workers, then drains.** Dropping a Rayon pool does not join it. `stop_search` blocks on `rx.iter()` until the job's only `Sender` drops, after every worker returns, so a send that passed the last stop check still lands. Never hand `tx` to anything that outlives the workers, or stop hangs. A failed CSV row sets `App::stop` and the on-screen list still caps at `MATCH_CAP`.
- **SLIP-0010 indices must all be hardened.** `slip10_derive_ed25519` panics on non-hardened input — Ed25519 doesn't support non-hardened derivation. If you add a new Solana/Ed25519 path, all components need the `0x80000000` flag.
- **Each chain's "fixed prefix" determines where the user's vanity starts.** Bitcoin skips `bc1q` (4), TON `UQ` (2), Monero `4` (1), EVM `0x` (matched on raw bytes / the 40-char EIP-55 body), Solana none. The slices live in each `matches_raw`; Bitcoin's `bech32_prefix_5bit` fast path and `matches_evm_raw` assume the same offsets, so change them together.
- **One autorelease pool per Metal command buffer.** `run_wave` wraps each buffer. Not one pool per wave, and not none. A `std::thread` has no ambient pool.
- **A failed command buffer fails the wave and disables the GPU for the process** (`GpuDisableReason::Backend`, sticky; the CPU search continues). No partial PBKDF2 result, no retry. `waitUntilCompleted` returning is not success.
- **`tid` is only a buffer index.** Entropy comes from `Mnemonic::new` on the host. No `threadgroup`, `simd_`, `barrier`, or `atomic` in the kernel. Both rules are grep-pinned in `src/gpu/kernel_src.rs`. A new `tid` line needs a `TID_ALLOWLIST` entry and a bump to the `seen == 8` count, on purpose.
- **Never join the GPU thread from the UI thread.** `stop_search` calls `GpuEngine::signal_stop()` (sets a **producer-only** flag — never `App::stop`, which every Rayon worker reads) and parks the engine in `App::gpu_engines`; `start_search` reaps only via the non-blocking `is_finished()` and skips the GPU for that run if an engine is still winding down. A force-join blocks the render loop for up to a whole wave (~135 ms steady state, ~400 ms during cold compile + self-test), and blocks **forever** if the GPU wedges inside `waitUntilCompleted` — leaving the terminal in raw mode with the alternate screen up and only `kill -9` as an exit.

## Key Files

| File | Role |
|------|------|
| `src/main.rs` | Binary entry, terminal setup, event loop |
| `src/app.rs` | `App` struct + `AppState` machine, key handling, search lifecycle |
| `src/ui.rs` | Ratatui rendering: banner, config form, stats, matches, detail, help |
| `src/matcher.rs` | `Matcher` with pre-computed prefix/suffix data |
| `src/chains/mod.rs` | `Chain` trait (`generate` / `generate_batch`), `ChainKind`, `Match`, monomorphized `search<C>`; EVM `search_hybrid` drains GPU `SeedBlock`s and `emit_gpu_match` is the only GPU → `Match` path |
| `src/chains/{solana,evm,bitcoin,ton,monero}.rs` | Per-chain key gen, address encoding, match logic |
| `src/chains/ton_cell.rs` | TVM cell representation hashing (W5 wallet) |
| `src/chains/ton_mnemonic.rs` | TON-native 24-word mnemonic (HMAC + 100k PBKDF2) |
| `src/seed.rs` | BIP-39 seed derivation: `derive_seed` (`ring`) and `derive_seeds` (4-lane) |
| `src/pbkdf2_lanes.rs` | Multi-lane PBKDF2-HMAC-SHA512 on aarch64 SHA-512 intrinsics, `ring` fallback |
| `src/slip10.rs` | SLIP-0010 Ed25519 + Phantom path constant |
| `src/bip32.rs` | BIP-32 secp256k1 (C `secp256k1` crate, global context) + BIP-44/BIP-84 path constants |
| `src/verify.rs` | `verify_gpu`: `ring` re-derivation of a GPU candidate from its entropy; `None` = reject. Not type-enforced (`Match` has pub fields): the gate holds because `emit_gpu_match` is the sole GPU → `Match` path |
| `src/gpu/mod.rs` | Portable GPU surface: constants, `GpuCandidate`/`SeedBlock`, `GpuStatus`/`GpuHealth`, backend selection |
| `src/gpu/pack.rs` | Host-side HMAC key packing into big-endian `u64` words, plus the constant BIP-39 salt block — the kernel has zero endianness code |
| `src/gpu/pbkdf2_bip39.metal` | The resumable-wave PBKDF2-HMAC-SHA512 kernel, `include_str!`-ed |
| `src/gpu/kernel_src.rs` | `include_str!`s the kernel and grep-pins its source invariants (the `tid` allowlist, the banned `threadgroup`/`simd_`/`barrier`/`atomic` tokens) |
| `src/gpu/metal.rs` | The **only** file naming an Objective-C type: `probe`, `MetalPbkdf2` (device, pipelines, `WaveBuffers`, `run_wave`), `GpuEngine` (start / `signal_stop` / `is_finished` / `reap`) |
| `src/gpu/selftest.rs` | Injectable startup self-test (count=512, canonical vector, ragged tail, schedule invariance) |
| `src/gpu/producer.rs` | The `vanaddy-gpu` wave loop: fill → dispatch → random `ring` audit → carve → `send_timeout` |
| `src/gpu/stub.rs` | No-op backend for every target that is not Apple Silicon with `feature = "metal"` |

## Output

Single CSV at `vanity_wallets.csv` in the current working directory. Header: `Chain, Address, Private Key (hex), Seed Phrase`. Header written only when the file is empty; one appended row per match. Plaintext seed phrases. The exit SECURITY WARNING covers only the last search and is skipped if any row failed, so it is not a signal that the file holds no secrets.

## Performance Targets (Apple M1 P-core, release, 2026-08)

| Chain | Mean per generation | Before 4-lane PBKDF2 |
|-------|--------------------|----------------------|
| Solana | ~288 µs | ~585 µs |
| EVM | ~321 µs | ~655 µs |
| Bitcoin | ~321 µs | ~700 µs |
| TON | ~26 ms (PBKDF2-dominated) | ~51 ms |
| Monero | ~35 µs | unchanged |
| **EVM + Metal GPU** (whole machine, 8 threads) | *estimated, not yet measured on this machine* | — |

PBKDF2 is ~90% of the mnemonic chains; `ring` already uses the M1's SHA-512 instructions, so the remaining per-core win came from interleaving 4 streams (see Conventions). 8 threads on an M1 (4P+4E) give ~5× one P-core; more threads than cores lose throughput. These are the rates `App::single_thread_rate` uses for ETA estimation. If you suspect a hot-loop regression, write a small one-shot timing harness — there is no committed CPU bench. GPU seed rate: `cargo test --release gpu_seed_rate_end_to_end -- --ignored --nocapture`.

The GPU row is a **whole-machine** figure, not a per-core one — and on this tree it is still an estimate: the 12-hour real-search RSS run (plan Task 8.2, not the `VANADDY_GPU_SOAK_N` test) has not been run. The GPU delivers ~14.3k BIP-39 seeds/s measured (`EVM_GPU_SEEDS_PER_SEC` keeps 13,600, within 5%) and costs ~0.7 of a CPU core to *consume* them (~50.5 µs of BIP-32 + Keccak per GPU seed), so the honest gain is **~2×**, not the ~4× the raw seed rate suggests. Two things follow. First, `App::single_thread_rate() × threads` was already ~1.6× optimistic on an M1 before the GPU existed (four of those cores are E-cores) — do not attribute the post-Enter ETA jump to the GPU. Second, **never model the GPU rate**: throughput collapses to 3,000–7,000 seeds/s whenever the desktop compositor is busy, so the TUI's `GPU rate:` line is `GpuHealth::seeds_delivered` over time since search start, and `App::estimated_rate` drives the ETA only while no search runs.
