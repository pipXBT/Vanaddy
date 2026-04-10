# Vanaddy

A multi-threaded vanity wallet address generator for **Solana** and **EVM** chains, written in Rust.

Generates BIP-39 seed phrases and derives keypairs using standard wallet-compatible paths, so found addresses can be imported directly into Phantom (Solana), MetaMask, or any EVM-compatible wallet.

EVM addresses are chain-agnostic — the same vanity address works on Ethereum, Base, Arbitrum, Optimism, Polygon, BSC, Avalanche, HyperEVM, and any other EVM chain.

## Features

- **Multi-chain**: Solana (Ed25519) and EVM (secp256k1) — one tool, all EVM networks
- **Flexible matching**: Starts with, ends with, or starts _and_ ends with
- **Case-sensitive or insensitive** search
- **BIP-39 seed phrases**: 12-word mnemonic output, compatible with Phantom and MetaMask
- **Standard derivation paths**: Solana uses first 32 bytes of BIP-39 seed; EVM uses BIP-44 `m/44'/60'/0'/0/0`
- **Multi-threaded**: Rayon work-stealing thread pool with auto-detected optimal core count
- **Optimized PBKDF2**: Uses `ring` crate with ARM64 NEON assembly (Apple Silicon) for ~1.5-2x faster seed derivation
- **Raw byte matching**: Solana compares raw pubkey bytes (skips base58 encoding); EVM compares Keccak hash bytes directly (skips hex encoding) — string formatting only happens on match
- **Graceful shutdown**: Press Ctrl+C at any time — all matches found so far are saved
- **Continuous search**: Finds multiple matching addresses until you stop
- **CSV output**: Appends results to `vanity_wallets.csv` with chain, address, private key, and seed phrase

## Installation

Requires [Rust](https://rustup.rs/).

```bash
git clone https://github.com/pipXBT/Vanaddy.git
cd Vanaddy/vanaddy
cargo build --release
```

## Usage

```bash
./target/release/vanaddy
```

The interactive prompt will guide you through:

```
Select chain:
  [1] Solana
  [2] EVM (Ethereum, Base, Arbitrum, etc.)

Match position:
  [1] Starts with
  [2] Ends with
  [3] Starts and ends with

Enter vanity prefix (1-9 chars, base58 charset):
> ABC

Case-sensitive? (yes/no):
> no

Threads (1-16) [detected 8 cores, recommended: 8]:
  Press Enter for recommended (8), or type a number:
> 

Searching for addresses that starts with 'ABC' (case-insensitive)... Press Ctrl+C to stop.

  Checked: 1284031 | Matches: 1 | Rate: 160503/s | Elapsed: 8s
  >> MATCH FOUND: ABcF7k...xyz [Solana]
```

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
- Uses OS CSPRNG (via `rand`) for entropy
- BIP-39/BIP-32/BIP-44 derivation matches industry-standard wallet implementations

**Keep your `vanity_wallets.csv` file secure.** Anyone with the seed phrase or private key has full control of the wallet.

## Supported Address Formats

| Chain | Key Type | Address Format | Derivation | Compatible With |
|-------|----------|---------------|------------|-----------------|
| Solana | Ed25519 | Base58 (32-44 chars) | BIP-39 seed, first 32 bytes | Phantom, Solflare |
| EVM | secp256k1 | Hex, 0x-prefixed (42 chars) | BIP-44 `m/44'/60'/0'/0/0` | MetaMask, Rabby, any EVM wallet |

## License

MIT
