# Vanaddy

A multi-threaded vanity wallet address generator for **Solana** and **HyperEVM** (Ethereum-compatible) chains, written in Rust.

Generates BIP-39 seed phrases and derives keypairs using standard wallet-compatible paths, so found addresses can be imported directly into Phantom (Solana) or MetaMask (EVM).

## Features

- **Multi-chain**: Solana (Ed25519) and HyperEVM/Ethereum (secp256k1)
- **Flexible matching**: Starts with, ends with, or starts _and_ ends with
- **Case-sensitive or insensitive** search
- **BIP-39 seed phrases**: 12-word mnemonic output, compatible with Phantom and MetaMask
- **Standard derivation paths**: Solana uses first 32 bytes of BIP-39 seed; EVM uses BIP-44 `m/44'/60'/0'/0/0`
- **Multi-threaded**: Rayon work-stealing thread pool for true parallel search
- **Raw byte optimization**: For Solana prefix matching, skips expensive base58 encoding by comparing raw pubkey bytes directly
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
  [2] HyperEVM

Match position:
  [1] Starts with
  [2] Ends with
  [3] Starts and ends with

Enter vanity prefix (1-9 chars, base58 charset):
> ABC

Case-sensitive? (yes/no):
> no

Threads (1-64):
> 8

Searching for addresses that starts with 'ABC' (case-insensitive)... Press Ctrl+C to stop.

  Checked: 1284031 | Matches: 1 | Rate: 160503/s | Elapsed: 8s
  >> MATCH FOUND: ABcF7k...xyz [Solana]
```

Results are saved to `vanity_wallets.csv`:

| Chain | Address | Private Key (hex) | Seed Phrase |
|-------|---------|-------------------|-------------|
| Solana | ABcF7k...xyz | a1b2c3... | word1 word2 word3 ... |

## Performance

The generator uses several optimizations:

- **Rayon thread pool** with work-stealing for optimal CPU utilization across all cores
- **Raw byte prefix matching** (Solana, case-sensitive starts-with): decodes the vanity prefix from base58 once, then compares raw pubkey bytes directly — avoids base58-encoding millions of keys per second
- **Atomic counters** instead of mutexes — no lock contention between threads
- **No stdout in hot loop** — progress display runs on a separate thread with 200ms updates

Thread count recommendation: start with your CPU core count. On Apple Silicon M-series, 8-10 threads is a good starting point.

## Security

- Seed phrases and private keys are written to a local CSV file only
- No network requests are made — all key generation is local
- Uses OS CSPRNG (via `rand`) for entropy
- BIP-39/BIP-32 derivation matches industry-standard wallet implementations

**Keep your `vanity_wallets.csv` file secure.** Anyone with the seed phrase or private key has full control of the wallet.

## Supported Address Formats

| Chain | Key Type | Address Format | Derivation |
|-------|----------|---------------|------------|
| Solana | Ed25519 | Base58 (32-44 chars) | BIP-39 seed, first 32 bytes |
| HyperEVM | secp256k1 | Hex, 0x-prefixed (42 chars) | BIP-44 `m/44'/60'/0'/0/0` |

## License

MIT
