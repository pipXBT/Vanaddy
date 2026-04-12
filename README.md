# Vanaddy

A multi-threaded, multi-chain vanity wallet address generator written in Rust.

Generates wallet-compatible seed phrases and keypairs for five chains, each using the correct native derivation scheme so vanity addresses import directly into their respective wallets (Phantom, MetaMask, Tonkeeper, Monero CLI, etc.).

EVM addresses are chain-agnostic — the same vanity address works on Ethereum, Base, Arbitrum, Optimism, Polygon, BSC, Avalanche, HyperEVM, and any other EVM chain.

## Supported Chains

- **Solana** — Ed25519 / Base58; BIP-39 12-word phrase; **Phantom-compatible** SLIP-0010 derivation at `m/44'/501'/0'/0'` (verified against SLIP-0010 spec vectors)
- **EVM** — secp256k1 / `0x` + hex (Ethereum, Base, Arbitrum, Optimism, Polygon, BSC, Avalanche, HyperEVM, etc.); BIP-39 12-word phrase; BIP-44 `m/44'/60'/0'/0/0`; **EIP-55 checksum matching** when case-sensitive
- **Bitcoin** — secp256k1 / Native SegWit Bech32 (`bc1q...`); BIP-39 12-word phrase; BIP-84 `m/84'/0'/0'/0/0`; vanity applies after `bc1q`
- **TON** — Ed25519 / user-friendly Base64 (`UQ...`, non-bounceable mainnet); native TON 24-word mnemonic (not BIP-39); **wallet-v5r1 (W5)** addresses using proper TVM cell hashing per TON whitepaper §3.1.5 — verified against Tonkeeper's own computation via pinned round-trip vector. W5 is Tonkeeper's current default, so no "Versions" switch is needed when importing.
- **Monero** — Ed25519 / Base58 (`4...`); **25-word Electrum-style seed phrase** (not BIP-39); standard spend/view key derivation; prefix matching only, and generation is intrinsically slower than other chains

## Features

- **Multi-chain**: Solana, EVM, Bitcoin, TON, and Monero — one tool, one workflow
- **Wallet-compatible seed phrases**: 12-word BIP-39 (Solana/EVM/Bitcoin), 24-word TON native, or 25-word Monero Electrum — each importable into the native wallet
- **Flexible matching**: Starts with, ends with, or starts _and_ ends with
- **Case-sensitive or insensitive** search; EVM case-sensitive uses EIP-55 checksum matching
- **Multi-threaded**: Rayon work-stealing thread pool with auto-detected optimal core count
- **Optimized crypto**: `ring` crate with ARM64 NEON assembly for PBKDF2, stack-buffer Bech32 expansion, byte-wise case-insensitive matching — zero hot-loop heap allocations
- **Fast-path matching**: EVM compares Keccak-256 hash bytes before hex-encoding; Bitcoin compares 5-bit Bech32 groups before full encoding — expensive string formatting only happens on candidates that pass the byte-level filter
- **Full TUI**: Ratatui-powered terminal UI with config form, live stats dashboard, scrollable match table, and detail view — all at 10fps
- **Graceful shutdown**: Press Ctrl+C to stop search and return to config, `q` to quit — all matches saved
- **Continuous search**: Finds multiple matching addresses until you stop
- **Secrets hygiene**: CSV output created with `chmod 0600` (owner-only); Monero secret key material zeroized on drop

## Installation

Requires [Rust](https://rustup.rs/).

```bash
git clone https://github.com/pipXBT/Vanaddy.git
cd Vanaddy
cargo build --release
```

## Usage

```bash
./target/release/vanaddy
```

The TUI launches with a config form on the left and results panel on the right:

```
┌──────────────────── Vanaddy ─────────────────────┐
│         VANADDY v0.6 — Multi-Chain               │
├──────────┬───────────────────────────────────────┤
│ Config   │ Matches                               │
│          │ #  Chain   Address                    │
│ Chain:   │ 1  Solana  ABcF7k...xyz               │
│ [Solana] │ 2  Solana  ABcD9m...qrs               │
│ Match:   │───────────────────────────────────────│
│ [Starts] │ Detail                                │
│ Prefix:  │ Address: ABcF7k9...full...xyz         │
│ ABC      │ Key:     a1b2c3...                    │
│ Case:[No]│ Phrase:  word1 word2 ... word12       │
│ Threads: │                                       │
│ 8        │                                       │
│──────────│                                       │
│ Stats    │                                       │
│ Checked: │                                       │
│ 1.2M     │                                       │
│ Rate:    │                                       │
│ 160K/s   │                                       │
├──────────┴───────────────────────────────────────┤

```

**Keybindings:**

| Key | Action |
|-----|--------|
| **Up/Down** | Move between fields |
| **Left/Right** | Toggle options (chain, match position, case) |
| **Tab / Shift-Tab** | Next/previous field |
| **1-5** | Select chain directly (1=Solana, 2=EVM, 3=Bitcoin, 4=TON, 5=Monero); 1-3 for match position |
| **y/n** | Case sensitivity |
| **Enter** | Start search |
| **Ctrl+C** | Stop search (return to config) |
| **Up/Down** | Browse found matches (during search) |
| **h** | Show/dismiss help popup |
| **q** | Quit (not in text input fields) |

Results are saved to `vanity_wallets.csv`:

| Chain | Address | Private Key (hex) | Seed Phrase |
|-------|---------|-------------------|-------------|
| Solana | ABcF7k...xyz | a1b2c3... | word1 word2 word3 ... |
| EVM | 0xdead...beef | d4e5f6... | word1 word2 word3 ... |

## Performance

The generator uses several optimizations:

- **`ring` PBKDF2**: ARM64 NEON-optimized HMAC-SHA512 assembly replaces the pure-Rust `pbkdf2` crate, ~1.5-2× faster seed derivation on Apple Silicon
- **Byte-level fast-paths**: EVM compares Keccak-256 hash bytes with nibble-level precision before hex-encoding; Bitcoin compares 5-bit Bech32 groups via a stack-buffer expansion — the encoder is only called on candidates that pass the byte-level filter
- **Zero hot-loop allocations**: Byte-wise ASCII case comparison via `eq_ignore_ascii_case` (no `to_lowercase()` per candidate); fixed-size arrays in BIP-32/SLIP-0010 derivation; secrets are raw structs until `encode_secret()` is called on a match
- **Monomorphized generics**: Each chain's search loop is monomorphized by the compiler (`search::<C: Chain>`) — no trait-object dispatch, no v-table lookups in the hot loop
- **Auto-detected thread count**: Detects physical vs logical cores, recommends optimal count for Apple Silicon (all cores) or x86 with hyperthreading (physical cores only)
- **Rayon work-stealing** thread pool with atomic counters — no lock contention between threads

### Per-chain throughput (Apple Silicon, release build)

| Chain    | Mean / generation  | Notes |
|----------|-------------------|-------|
| Solana   | ~570 µs          | SLIP-0010 at `m/44'/501'/0'/0'` (Phantom-compat) |
| EVM      | ~655 µs          | Keccak-256 + optional EIP-55 for case-sensitive |
| Bitcoin  | ~645 µs          | BIP-84 Bech32 with stack-buffer 5-bit fast-path |
| TON      | ~51 ms           | Native 24-word mnemonic; PBKDF2-dominated (~100k iters/wallet) |
| Monero   | ~35 µs           | Two Ed25519 scalars + Keccak; no PBKDF2 |

### Difficulty scaling

Each additional character in your vanity makes the search exponentially harder. Approximate attempts per match:

| Chars | Solana / Monero (Base58) | EVM (hex) | Bitcoin (Bech32) | TON (Base64url) |
|-------|-------------------------|-----------|------------------|-----------------|
| 1 | ~58 | ~16 | ~32 | ~64 |
| 2 | ~3,364 | ~256 | ~1,024 | ~4,096 |
| 3 | ~195,112 | ~4,096 | ~32,768 | ~262,144 |
| 4 | ~11.3M | ~65,536 | ~1M | ~16.7M |
| 5 | ~656M | ~1M | ~33M | ~1B |
| 6 | ~38B | ~16.7M | ~1B | — |

**TON note:** TON's `MAX_VANITY = 4` because each wallet takes ~50 ms to generate; a 4-char vanity is roughly a full day of multi-threaded search. Longer prefixes would take months.

**Monero note:** Prefix-only matching (no suffix). `MAX_VANITY = 4` after the fixed leading `4` character.

## Security

- **No network requests** — all key generation is local, nothing leaves your machine.
- **OS CSPRNG** for entropy (`ring`'s PBKDF2 with OS-supplied seed; `rand::rngs::OsRng` for Monero scalars).
- **Industry-standard derivations** matching wallet implementations:
  - Solana → SLIP-0010 Ed25519 at `m/44'/501'/0'/0'` (verified against SLIP-0010 spec test vectors)
  - EVM → BIP-44 secp256k1 at `m/44'/60'/0'/0/0` (standard MetaMask path)
  - Bitcoin → BIP-84 at `m/84'/0'/0'/0/0` (verified against the BIP-84 canonical vector `bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu`)
  - TON → `@ton/crypto`-compatible HMAC+PBKDF2 scheme with wallet-v5r1 TVM cell hashing (verified against real Tonkeeper-generated addresses)
  - Monero → standard `spend_sec = reduce32(random)`, `view_sec = reduce32(Keccak(spend_sec))`, 25-word Electrum phrase
- **CSV file is created with `chmod 0600`** (owner read/write only). On quit, a warning prints reminding you the file contains plaintext secrets.
- **Monero secret key material is zeroized on drop** (only generated keys that match are kept; discarded candidates have their secrets wiped).
- **EVM/Solana/Bitcoin secrets** rely on `libsecp256k1` / `ed25519-dalek`'s internal zeroization.

**Keep your `vanity_wallets.csv` file secure.** Anyone with the seed phrase or private key has full control of the wallet. After transferring vanity addresses to their final wallet, consider moving the CSV to an encrypted location and removing the original.

## Supported Address Formats

| Chain | Key Type | Address Format | Seed Phrase | Derivation | Compatible With |
|-------|----------|---------------|-------------|------------|-----------------|
| Solana | Ed25519 | Base58 (32-44 chars) | BIP-39 12-word | SLIP-0010 `m/44'/501'/0'/0'` | Phantom, Solflare |
| EVM | secp256k1 | Hex, 0x-prefixed (42 chars) | BIP-39 12-word | BIP-44 `m/44'/60'/0'/0/0` | MetaMask, Rabby, any EVM wallet |
| Bitcoin | secp256k1 | Native SegWit Bech32 (`bc1q...`) | BIP-39 12-word | BIP-84 `m/84'/0'/0'/0/0` | Sparrow, Electrum, any BIP-84 wallet |
| TON | Ed25519 | User-friendly Base64 (`UQ...`, 48 chars) | TON native 24-word | `@ton/crypto` HMAC+PBKDF2, wallet-v5r1 cell hash | Tonkeeper (default W5), MyTonWallet |
| Monero | Ed25519 | Base58 (`4...`, 95 chars) | 25-word Electrum English | Random spend key; `view_sec = Keccak(spend_sec)` | `monero-wallet-cli --restore-deterministic-wallet`, Cake, Feather |

## License

MIT

## Ratatui UI

<img width="1084" height="1162" alt="Screenshot 2026-04-11 at 4 08 22 am" src="https://github.com/user-attachments/assets/cbb77e73-f775-4f6c-b158-07072459b7af" />

