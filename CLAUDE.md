# Vanaddy — Claude Code Notes

A multi-threaded, multi-chain vanity wallet address generator in Rust. Single-binary TUI built with Ratatui; supports Solana, EVM, Bitcoin, TON, and Monero.

## Quick Architecture

`src/main.rs` is the binary entry (no `lib.rs`). It declares modules `app`, `bip32`, `chains`, `matcher`, `seed`, `slip10`, `ui` and runs the Ratatui event loop directly. Search workers run on a Rayon thread pool; matches stream back over `mpsc` and are appended to `vanity_wallets.csv` (chmod 0600).

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
| `cargo bench` | Criterion benchmarks (`benches/generation.rs`) |
| `cargo clippy --all-targets` | Lint (no clippy config file; default lints) |
| `cargo fmt` | Format (no rustfmt config; defaults) |

There is no separate library target. `benches/generation.rs` re-includes the binary via `#[path = "../src/main.rs"] mod vanaddy;`.

## Conventions

- **Cryptographic correctness is paramount.** The whole point of this tool is that vanity addresses import into the user's wallet for the *full* secret/seed material we display. If derivation drifts, addresses produced by this tool look correct but lead to wallets nobody controls.
- **Pinned test vectors are load-bearing.** The following tests must continue to pass on any change touching their pipeline:
  - `seed::derive_seed_matches_bip39_vector` (BIP-39 seed)
  - `slip10::slip10_ed25519_test_vector_{1,2}` (SLIP-0010 spec)
  - `solana::solana_phantom_derivation_from_canonical_phrase` (Phantom-importable)
  - `bitcoin::bip84_canonical_vector` (BIP-84 spec)
  - `evm::eip55_canonical_vector`, `eip55_second_vector` (EIP-55 spec)
  - `ton::ton_tonkeeper_round_trip_vector` (full Tonkeeper W5 round-trip)
  - `ton_cell::wallet_v5r1_matches_tonkeeper_vector` (W5 state_init hash)
  - `monero::keccak256_empty_vector` (original Keccak, **not** FIPS-202 SHA3)
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
| `src/chains/mod.rs` | `Chain` trait, `ChainKind` enum, monomorphized `search<C>` |
| `src/chains/{solana,evm,bitcoin,ton,monero}.rs` | Per-chain key gen, address encoding, match logic |
| `src/chains/ton_cell.rs` | TVM cell representation hashing (W5 wallet) |
| `src/chains/ton_mnemonic.rs` | TON-native 24-word mnemonic (HMAC + 100k PBKDF2) |
| `src/seed.rs` | BIP-39 PBKDF2 seed derivation (via `ring`) |
| `src/slip10.rs` | SLIP-0010 Ed25519 + Phantom path constant |
| `src/bip32.rs` | BIP-32 secp256k1 + BIP-44/BIP-84 path constants |
| `benches/generation.rs` | Criterion per-chain `generate()` benches |

## Output

Single CSV at `vanity_wallets.csv` in the current working directory. Header: `Chain, Address, Private Key (hex), Seed Phrase`. Appended one row per match. Contains plaintext seed phrases — the tool prints a security warning on exit when matches were found.

## Performance Targets (Apple Silicon, release)

| Chain | Mean per generation |
|-------|--------------------|
| Solana | ~570 µs |
| EVM | ~655 µs |
| Bitcoin | ~645 µs |
| TON | ~51 ms (PBKDF2-dominated) |
| Monero | ~35 µs |

If a benchmark regresses noticeably (>10%) after a change, that's a signal the hot loop picked up an allocation or a non-monomorphized call.
