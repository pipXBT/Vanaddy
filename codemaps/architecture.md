> Generated: 2026-08-24 | Token-lean format for LLM context

# Architecture

Single-binary Rust TUI for generating multi-chain vanity wallet addresses. No library crate, no workspace, no committed bench harness — `src/main.rs` declares the modules and runs the event loop directly.

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
├── matcher              # Matcher struct: precomputed prefix/suffix data + prefix/suffix_matches helpers
├── pbkdf2_lanes         # 4-lane PBKDF2-HMAC-SHA512 on aarch64 SHA-512 intrinsics; ring fallback
├── seed                 # BIP-39 seed derivation: derive_seed (ring) + derive_seeds (lanes)
├── slip10               # SLIP-0010 Ed25519 derivation (Solana)
├── bip32                # BIP-32 secp256k1 derivation (EVM, Bitcoin) via C secp256k1 + path constants
└── chains/
    ├── mod              # Chain trait (generate / generate_batch), ChainKind, Match, batched search<C>
    ├── solana           # Ed25519 + Base58, SLIP-0010 m/44'/501'/0'/0'
    ├── evm              # secp256k1 + 0x-hex, BIP-44 m/44'/60'/0'/0/0, EIP-55
    ├── bitcoin          # secp256k1 + Bech32 bc1q, BIP-84 m/84'/0'/0'/0/0
    ├── ton              # Ed25519 + base64url UQ, native 24-word, W5 cell hashing
    ├── ton_cell         # TVM cell representation hashing (whitepaper §3.1.5)
    ├── ton_mnemonic     # TON native mnemonic (HMAC+PBKDF2, 1/256 filter), single + 4-lane generators
    ├── monero           # Ed25519 scalar + Base58 4..., 25-word Electrum, Keccak-256
    └── monero_wordlist  # 1626-word English Electrum-style list
```

`pub mod` from `main.rs`: `app, bip32, chains, matcher, pbkdf2_lanes, seed, slip10, ui` (no `lib.rs`). `monero_wordlist` and `ton_mnemonic` are private submodules of `chains`.

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
         C::generate_batch(|addr, secret, phrase| {      ← BATCH candidates per call
            if C::matches_raw(matcher, &addr):           (4 for Solana/EVM/Bitcoin/TON,
               tx.send(Match { chain, address, secret_hex, mnemonic })   1 for Monero)
         })
         counter.fetch_add(C::BATCH)
         if stop.load(): break
            │
            ▼
       App::drain_matches() reads rx → open_csv_secure → append → matches.push
```

### Seed derivation (mnemonic chains)

```
generate_batch:  4 × Mnemonic::new()  →  seed::derive_seeds(&[Mnemonic; 4])
                                              │
                        pbkdf2_lanes::pbkdf2_hmac_sha512::<4>(phrases, "mnemonic", 2048)
                                              │
              aarch64 && sha3 detected ───────┴─────── otherwise
              hw::pbkdf2_lanes::<4>                     fallback: ring::pbkdf2 per lane
              (one compress() drives 4 states,
               instructions interleaved)
                                              │
                        per lane: C::from_seed(&seed) → (AddressBytes, SecretRaw)
```

`generate()` (single candidate, `ring`) shares the same `from_seed` tail; the batch tests re-derive every batch candidate through it.

## Concurrency Primitives

| Primitive | Type | Purpose |
|-----------|------|---------|
| `App.stop` | `Arc<AtomicBool>` | Cooperative cancellation flag, polled once per batch in the worker loop |
| `App.counter` | `Arc<AtomicU64>` | Total candidates checked across all threads (advances by `C::BATCH`) |
| `App.rx` | `Option<mpsc::Receiver<Match>>` | Workers → main thread for CSV write |
| `App.thread_pool` | `Option<rayon::ThreadPool>` | Owns worker threads; dropped on stop |

`Match` (defined in `chains/mod.rs:16`) is a 4-field struct: `{ chain, address, secret_hex, mnemonic }`.

## Build & Test

| Command | Purpose |
|---------|---------|
| `cargo build --release` | Production binary (`target/release/vanaddy`) |
| `cargo run` | Dev TUI |
| `cargo test` | 63 unit tests (in-module `#[cfg(test)]`); ~8 s in debug because the 100k-iteration TON vectors run through unoptimized intrinsics, <1 s with `--release` |

There is no library target and no committed bench harness. Per-chain throughput numbers used for ETA estimation live in `App::single_thread_rate` (`src/app.rs:149`).

## Platform Notes

- `pbkdf2_lanes::hw` is compiled only for `target_arch = "aarch64"` and selected at runtime via `is_aarch64_feature_detected!("sha3")` (the `sha3` feature carries the SHA-512 instructions; static on `aarch64-apple-darwin`). Other targets use the `ring` fallback with identical output.
- `secp256k1` builds bitcoin-core's C library (`secp256k1-sys`), so a C toolchain is required — `ring` already required one.

## Key Dependencies

| Crate | Role |
|-------|------|
| `ratatui 0.29` + `crossterm 0.28` | TUI rendering and input |
| `rayon 1.8` | Work-stealing thread pool |
| `std::arch::aarch64` (no crate) | `vsha512hq/h2q/su0q/su1q_u64` intrinsics for the 4-lane PBKDF2 |
| `ring 0.17` | HMAC-SHA512 for CKD steps + TON entropy, PBKDF2 fallback / single-candidate path, SHA-512 of >128-byte HMAC keys |
| `bip39 (tiny-bip39 0.8)` | BIP-39 wordlist + mnemonic generation |
| `ed25519-dalek 2`, `curve25519-dalek 4` | Ed25519 keys, scalar arithmetic (Monero) |
| `secp256k1 0.30` (`global-context`; `secp256k1-sys 0.10.1`) | secp256k1 keys (EVM, Bitcoin) — C libsecp256k1, replaced pure-Rust `libsecp256k1 0.6` |
| `sha3 0.9`, `tiny-keccak 2`, `sha2 0.10`, `ripemd 0.1` | Address hashing |
| `bs58 0.4`, `bech32 0.9`, `base64 0.22`, `hex 0.4` | Address encoding |
| `csv 1.3` | Output to `vanity_wallets.csv` |
| `zeroize 1.8` | Wipe Monero secret material on drop |
| `crc32fast 1.4` | Monero seed phrase checksum |

No `[dev-dependencies]`. No `[[bench]]` targets. No `[profile.*]` overrides (measured: LTO / codegen-units=1 change nothing — the hot paths are C/asm/intrinsics).

## Output

Single CSV file `vanity_wallets.csv` (created with `chmod 0600` on Unix). Header: `Chain, Address, Private Key (hex), Seed Phrase`. Appended on every match. All file opens go through the `open_csv_secure()` helper (`src/app.rs:297`) — the single chokepoint enforcing the 0o600 invariant.

## Performance Notes

Measured on an Apple M1 P-core, release build (2026-08):

| Chain | Per candidate | Dominant cost |
|-------|---------------|---------------|
| Solana | ~288 µs | 4-lane PBKDF2 ≈ 256 µs; ed25519 keygen 13.5 µs |
| EVM | ~321 µs | PBKDF2 + 3 secp256k1 fixed-base mults (17 µs each, C lib) |
| Bitcoin | ~321 µs | same shape as EVM |
| TON | ~26 ms | 256 trial phrases × 390-iter PBKDF2 + one 100k-iter PBKDF2, both 4-lane |
| Monero | ~35 µs | two Ed25519 fixed-base mults + compress; no PBKDF2 |

- PBKDF2 is ~90% of the mnemonic chains. `ring` already uses the ARMv8.2 SHA-512 instructions (single stream: 539 µs/2048 iters); interleaving 4 independent streams per core hides instruction latency → ~256 µs per candidate. 6–8 lanes spill NEON registers and regress.
- 8 threads on M1 (4P+4E) ≈ 5× one P-core; E-cores ≈ 0.5× a P-core; more threads than cores loses throughput.
- Hot loop is monomorphized per chain via `search::<C: Chain>` — no dynamic dispatch. Stop flag is checked once per batch (≤ ~100 ms latency for TON, ~1 ms otherwise).
- `Matcher` precomputes byte-level filters: EVM stores `(Vec<u8>, Option<u8>)` for partial-nibble prefix/suffix matching; Bitcoin stores 5-bit Bech32 groups so candidate hashes can be byte-compared without full Bech32 encoding.
- Solana / Bitcoin / TON / Monero share `Matcher::prefix_matches` and `Matcher::suffix_matches` (`#[inline]`, allocation-free); EVM uses `Matcher::matches_evm_raw` exclusively (byte-level).
- `expand_5bit` (Bitcoin) is a hand-rolled stack-buffer alternative to `bytes.to_base32()`.

See `chains.md` for per-chain detail, `tui.md` for the TUI/state machine, `data.md` for type and helper internals.
