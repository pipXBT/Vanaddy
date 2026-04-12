# Vanaddy

A multi-threaded, multi-chain vanity wallet address generator written in Rust.

Generates BIP-39 seed phrases and derives keypairs using standard wallet-compatible paths, so found addresses can be imported directly into Phantom (Solana), MetaMask (EVM), and other supported wallets.

EVM addresses are chain-agnostic — the same vanity address works on Ethereum, Base, Arbitrum, Optimism, Polygon, BSC, Avalanche, HyperEVM, and any other EVM chain.

## Supported Chains

- **Solana** — Ed25519 / Base58
- **EVM** — secp256k1 / `0x` + hex (Ethereum, Base, Arbitrum, Optimism, Polygon, BSC, Avalanche, HyperEVM, etc.)
- **Bitcoin** — secp256k1 / Native SegWit Bech32 (`bc1q...`); vanity applies after the `bc1q` prefix
- **TON** — Ed25519 / user-friendly Base64 (`UQ...`, non-bounceable mainnet); vanity applies from char 3 onward
  - Generates **wallet-v3r2** addresses using proper TVM cell hashing (per TON whitepaper §3.1.5); verified against Tonkeeper's own computation via pinned round-trip test vector. Tonkeeper's current default is W5, so users should switch to v3R2 in Tonkeeper's "Versions" screen when importing vanaddy-generated mnemonics.
- **Monero** — Ed25519 / Base58 (`4...`); prefix matching only, and generation is noticeably slower (crypto intrinsic)

## Features

- **Multi-chain**: Solana, EVM, Bitcoin, TON, and Monero — one tool
- **Flexible matching**: Starts with, ends with, or starts _and_ ends with
- **Case-sensitive or insensitive** search
- **BIP-39 seed phrases**: 12-word mnemonic output, compatible with Phantom and MetaMask
- **Standard derivation paths**: Solana uses first 32 bytes of BIP-39 seed; EVM uses BIP-44 `m/44'/60'/0'/0/0`
- **Multi-threaded**: Rayon work-stealing thread pool with auto-detected optimal core count
- **Optimized PBKDF2**: Uses `ring` crate with ARM64 NEON assembly (Apple Silicon) for ~1.5-2x faster seed derivation
- **Raw byte matching**: Solana compares raw pubkey bytes (skips base58 encoding); EVM compares Keccak hash bytes directly (skips hex encoding) — string formatting only happens on match
- **Full TUI**: Ratatui-powered terminal UI with config form, live stats dashboard, scrollable match table, and detail view — all at 10fps
- **Graceful shutdown**: Press Ctrl+C to stop search and return to config, q to quit — all matches saved
- **Continuous search**: Finds multiple matching addresses until you stop
- **CSV output**: Appends results to `vanity_wallets.csv` with chain, address, private key, and seed phrase

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
| **1/2/3** | Select option directly |
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

- **`ring` PBKDF2**: ARM64 NEON-optimized HMAC-SHA512 assembly replaces the pure-Rust `pbkdf2` crate, ~1.5-2x faster seed derivation on Apple Silicon
- **Raw byte matching**: Solana compares raw Ed25519 pubkey bytes before base58-encoding; EVM compares raw Keccak-256 hash bytes with nibble-level precision before hex-encoding — expensive string formatting only runs on match
- **Zero hot-loop allocations**: Pre-computed lowercase patterns, fixed-size arrays in BIP-32 derivation, no cloning or formatting per iteration
- **Auto-detected thread count**: Detects physical vs logical cores, recommends optimal count for Apple Silicon (all cores) or x86 with hyperthreading (physical cores only)
- **Rayon work-stealing** thread pool with atomic counters — no lock contention between threads

### Difficulty scaling

Each additional character in your vanity string makes the search exponentially harder:

| Chars | Solana (base58) | EVM (hex) |
|-------|----------------|-----------|
| 1 | ~58 attempts | ~16 attempts |
| 2 | ~3,364 | ~256 |
| 3 | ~195,112 | ~4,096 |
| 4 | ~11.3M | ~65,536 |
| 5 | ~656M | ~1M |
| 6 | ~38B | ~16.7M |

## Security

- Seed phrases and private keys are written to a local CSV file only
- No network requests are made — all key generation is local
- Uses OS CSPRNG for entropy
- BIP-39/BIP-32/BIP-44 derivation matches industry-standard wallet implementations

**Keep your `vanity_wallets.csv` file secure.** Anyone with the seed phrase or private key has full control of the wallet.

## Supported Address Formats

| Chain | Key Type | Address Format | Derivation | Compatible With |
|-------|----------|---------------|------------|-----------------|
| Solana | Ed25519 | Base58 (32-44 chars) | BIP-39 seed, first 32 bytes | Phantom, Solflare |
| EVM | secp256k1 | Hex, 0x-prefixed (42 chars) | BIP-44 `m/44'/60'/0'/0/0` | MetaMask, Rabby, any EVM wallet |
| Bitcoin | secp256k1 | Native SegWit Bech32 (`bc1q...`) | BIP-84 `m/84'/0'/0'/0/0` | Most modern BTC wallets |
| TON | Ed25519 | User-friendly Base64 (`UQ...`) | TON 24-word mnemonic, Ed25519, wallet-v3r2 | Tonkeeper (switch to v3R2 in Versions screen) |
| Monero | Ed25519 | Base58 (`4...`) | Monero spend/view keys | Official Monero wallets (prefix match only) |

## License

MIT

## Ratatui UI

<img width="1084" height="1162" alt="Screenshot 2026-04-11 at 4 08 22 am" src="https://github.com/user-attachments/assets/cbb77e73-f775-4f6c-b158-07072459b7af" />

