# Vanaddy — Claude Code Notes

A multi-threaded, multi-chain vanity wallet address generator in Rust. Single-binary TUI built with Ratatui; supports Solana, EVM, Bitcoin, TON, and Monero.

## Quick Architecture

`src/main.rs` is the binary entry (no `lib.rs`). It declares modules `app`, `bip32`, `chains`, `matcher`, `pbkdf2_lanes`, `seed`, `slip10`, `ui` and runs the Ratatui event loop directly. Search workers run on a Rayon thread pool; matches stream back over `mpsc` and are appended to `vanity_wallets.csv` (chmod 0600).

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
| `cargo run` | Dev TUI |
| `cargo test` | Run all unit tests (in-module `#[cfg(test)]`) |
| `cargo clippy --all-targets` | Lint (no clippy config file; default lints) |
| `cargo fmt` | Format (no rustfmt config; defaults) |

There is no separate library target.

## Conventions

- **Cryptographic correctness is paramount.** The whole point of this tool is that vanity addresses import into the user's wallet for the *full* secret/seed material we display. If derivation drifts, addresses produced by this tool look correct but lead to wallets nobody controls.
- **Pinned test vectors are load-bearing.** The following tests must continue to pass on any change touching their pipeline:
  - `seed::derive_seed_matches_bip39_vector` (BIP-39 seed)
  - `seed::derive_seeds_matches_derive_seed_per_lane` (4-lane seeds == ring seeds)
  - `pbkdf2_lanes::every_lane_matches_bip39_canonical_vector`, `distinct_lanes_match_ring_reference`, `ton_salts_and_iteration_counts_match_ring` (hardware SHA-512 PBKDF2 vs BIP-39 vector and `ring`)
  - `slip10::slip10_ed25519_test_vector_{1,2}` (SLIP-0010 spec)
  - `solana::solana_phantom_derivation_from_canonical_phrase` (Phantom-importable)
  - `bitcoin::bip84_canonical_vector` (BIP-84 spec)
  - `evm::eip55_canonical_vector`, `eip55_second_vector` (EIP-55 spec)
  - `evm::bip44_canonical_vector` (m/44'/60'/0'/0/0 of the canonical phrase = first MetaMask account)
  - `{solana,evm,bitcoin}::generate_batch_emits_lane_count_candidates_matching_single_path`, `ton::generate_batch_emits_lane_count_wallets_with_consistent_addresses` (batched path == single path)
  - `ton::ton_tonkeeper_round_trip_vector` (full Tonkeeper W5 round-trip)
  - `ton_cell::wallet_v5r1_matches_tonkeeper_vector` (W5 state_init hash)
  - `monero::keccak256_empty_vector` (original Keccak, **not** FIPS-202 SHA3)
- **Seed derivation runs 4 lanes at a time.** `pbkdf2_lanes::pbkdf2_hmac_sha512` interleaves `LANES` (= 4) independent PBKDF2-HMAC-SHA512 streams on the ARMv8.2 SHA-512 instructions (~2× per core on M1; runtime-detected, falls back to `ring` elsewhere). Solana/EVM/Bitcoin/TON set `Chain::BATCH = LANES` and override `generate_batch`; `search<C>` advances the counter per batch. Keep `generate()` (single, `ring`) and `generate_batch` (lanes) sharing one `from_seed` tail — the batch tests cross-check the two paths against each other, so any divergence in derivation is caught.
- **Keep the hot loop allocation-free.** `chains/<x>.rs::matches_raw` is called per-candidate. Don't introduce `to_lowercase()` (allocates), `format!`, `Vec::new()`, etc. inside it. Use `eq_ignore_ascii_case` over byte slices, stack arrays, and pre-computed `Matcher` fields.
- **Monomorphization, not dyn dispatch.** `ChainKind::search` chooses `search::<C: Chain>` once at thread spawn. Don't refactor to `Box<dyn Chain>` or any v-table-based dispatch — it would re-introduce per-candidate indirection.
- **Monero secrets must be zeroized.** `MoneroKeypair: Zeroize + ZeroizeOnDrop`. Don't hold them in plain `[u8; 32]` arrays beyond the candidate that produced them. Discarded keys must be wiped on drop.
- **CSV is `chmod 0600` always.** `start_search` and `drain_matches` both reassert mode-0o600 on every open in case the user (or another process) loosened it. Don't remove that.
- **SLIP-0010 indices must all be hardened.** `slip10_derive_ed25519` panics on non-hardened input — Ed25519 doesn't support non-hardened derivation. If you add a new Solana/Ed25519 path, all components need the `0x80000000` flag.
- **Each chain's "fixed prefix" determines where the user's vanity starts.** Bitcoin skips `bc1q` (4 chars), TON skips `UQ` (2 chars), Monero skips `4` (1 char), Solana/EVM apply from char 0. This logic is inline in each chain's `matches_raw` — be careful not to change the slice indices when refactoring.

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

PBKDF2 is ~90% of the mnemonic chains; `ring` already uses the M1's SHA-512 instructions, so the remaining per-core win came from interleaving 4 streams (see Conventions). 8 threads on an M1 (4P+4E) give ~5× one P-core; more threads than cores lose throughput. These are the rates `App::single_thread_rate` uses for ETA estimation. If you suspect a hot-loop regression, write a small one-shot timing harness — there is no committed bench harness in this tree.
