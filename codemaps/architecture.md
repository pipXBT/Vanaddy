> Generated: 2026-05-05 | Token-lean format for LLM context

# Architecture

Single-binary Rust TUI for generating multi-chain vanity wallet addresses. No library crate, no workspace — `src/main.rs` declares the modules and runs the event loop directly.

## Crate

| Field | Value |
|-------|-------|
| Name | `vanaddy` |
| Version | `0.6.0` |
| Edition | 2021 |
| Type | Binary (no `lib.rs`) |
| Entry | `src/main.rs` |

## Module Tree

```
src/main.rs              # Entry: terminal setup, event loop, drain matches
├── app                  # AppState machine, validation, search lifecycle, key handling
├── ui                   # Ratatui rendering: banner, config form, stats, matches, detail, help popup
├── matcher              # Matcher struct: precomputed prefix/suffix data (hex bytes, 5-bit groups)
├── seed                 # BIP-39 seed derivation (PBKDF2-HMAC-SHA512 via ring)
├── slip10               # SLIP-0010 Ed25519 derivation (Solana)
├── bip32                # BIP-32 secp256k1 derivation (EVM, Bitcoin) + path constants
└── chains/
    ├── mod              # Chain trait, ChainKind enum, monomorphized search<C>
    ├── solana           # Ed25519 + Base58, SLIP-0010 m/44'/501'/0'/0'
    ├── evm              # secp256k1 + 0x-hex, BIP-44 m/44'/60'/0'/0/0, EIP-55
    ├── bitcoin          # secp256k1 + Bech32 bc1q, BIP-84 m/84'/0'/0'/0/0
    ├── ton              # Ed25519 + base64url UQ, native 24-word, W5 cell hashing
    ├── ton_cell         # TVM cell representation hashing (whitepaper §3.1.5)
    ├── ton_mnemonic     # TON native mnemonic (HMAC+PBKDF2, 1/256 filter)
    ├── monero           # Ed25519 scalar + Base58 4..., 25-word Electrum, Keccak-256
    └── monero_wordlist  # 1626-word English Electrum-style list
```

`pub mod` from `main.rs`: `app, bip32, chains, matcher, seed, slip10, ui` (no `lib.rs`). `monero_wordlist` and `ton_mnemonic` are private submodules of `chains`.

## High-Level Data Flow

```
              ┌─────────────────────────────────────┐
              │  main.rs event loop (100ms tick)    │
              │  draw → poll key → handle → drain   │
              └──────────────┬──────────────────────┘
                             │
            ┌────────────────┴────────────────┐
            │                                 │
       AppState::Configuring          AppState::Searching
       (form input, validate)        (display stats, drain rx)
            │                                 ▲
            │  Enter → validate → start_search
            ▼                                 │
       Rayon ThreadPool ── N threads ─────────┘
            │
            ▼
       (0..N).par_iter().for_each(|_| chain.search(matcher, stop, counter, tx))
            │
            ▼
       search::<C: Chain> (monomorphized hot loop)
            │
       loop:
         (addr, secret, phrase) = C::generate()    ← per-chain key derivation
         counter.fetch_add(1)
         if C::matches_raw(matcher, &addr):
            tx.send((label, encode_address, encode_secret, phrase))
         if stop.load(): break
            │
            ▼
       App::drain_matches() reads rx → appends CSV (chmod 0600) → matches.push
```

## Concurrency Primitives

| Primitive | Type | Purpose |
|-----------|------|---------|
| `App.stop` | `Arc<AtomicBool>` | Cooperative cancellation flag, polled in worker hot loop |
| `App.counter` | `Arc<AtomicU64>` | Total candidates checked across all threads |
| `App.match_count` | `Arc<AtomicU64>` | Successful matches found |
| `App.rx` | `Option<mpsc::Receiver<MatchPayload>>` | Workers → main thread for CSV write |
| `App.thread_pool` | `Option<rayon::ThreadPool>` | Owns worker threads; dropped on stop |

`MatchPayload = (chain_label, address, secret_hex, mnemonic)` — 4-tuple of `String`.

## Build & Test

| Command | Purpose |
|---------|---------|
| `cargo build --release` | Production binary (`target/release/vanaddy`) |
| `cargo run` | Dev TUI |
| `cargo test` | Unit tests (in-module `#[cfg(test)]`) |

There is no library target and no committed bench harness. `App::single_thread_rate` carries the historical per-chain throughput numbers used for ETA estimation.

## Key Dependencies

| Crate | Role |
|-------|------|
| `ratatui 0.29` + `crossterm 0.28` | TUI rendering and input |
| `rayon 1.8` | Work-stealing thread pool |
| `ring 0.17` | PBKDF2-HMAC-SHA512 (NEON-optimized on ARM64) |
| `bip39 (tiny-bip39 0.8)` | BIP-39 wordlist + mnemonic generation |
| `ed25519-dalek 2`, `curve25519-dalek 4` | Ed25519 keys, scalar arithmetic (Monero) |
| `libsecp256k1 0.6` | secp256k1 keys (EVM, Bitcoin) |
| `sha3 0.9`, `tiny-keccak 2`, `sha2 0.10`, `ripemd 0.1` | Address hashing |
| `bs58 0.4`, `bech32 0.9`, `base64 0.22`, `hex 0.4` | Address encoding |
| `csv 1.3` | Output to `vanity_wallets.csv` |
| `zeroize 1.8` | Wipe Monero secret material on drop |
| `crc32fast 1.4` | Monero seed phrase checksum |

## Output

Single CSV file `vanity_wallets.csv` (created with `chmod 0600` on Unix). Header: `Chain, Address, Private Key (hex), Seed Phrase`. Appended to on every match. Permissions reasserted on each open in case the user fixed them up.

## Performance Notes

- Hot loop is monomorphized per chain via `search::<C: Chain>` — no dynamic dispatch.
- `Matcher` precomputes byte-level filters: EVM stores `(Vec<u8>, Option<u8>)` for partial-nibble prefix/suffix matching; Bitcoin stores 5-bit Bech32 groups so candidate hashes can be byte-compared without full Bech32 encoding.
- `expand_5bit` (Bitcoin) is a hand-rolled stack-buffer alternative to `bytes.to_base32()` to avoid a `Vec` allocation per candidate.
- TON is intrinsically slow (~50 ms/wallet) due to 100k PBKDF2 iters × ~256 retries from the `basic_seed[0] == 0` acceptance filter. `MAX_VANITY = 4`.
- Monero is fastest (~35 µs/wallet) — no PBKDF2, just two Ed25519 scalar multiplications.

See `chains.md` for per-chain detail, `tui.md` for the TUI/state machine, `data.md` for type and helper internals.
