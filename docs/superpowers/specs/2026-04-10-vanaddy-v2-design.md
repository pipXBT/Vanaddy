# Vanaddy v2 Design Spec

## Overview

Rewrite of vanaddy — a Solana vanity address generator — to add HyperEVM wallet support, significant performance improvements, and graceful multi-match searching.

## Architecture

Single binary, trait-based chain abstraction. User selects chain at startup via interactive prompt, then configures vanity string, match position, and thread count.

## Core Components

### 1. KeyGenerator Trait

```rust
trait KeyGenerator: Send + Sync {
    fn generate(&self) -> (String, Vec<u8>);  // (address, secret_bytes)
    fn valid_charset(&self) -> &str;
}
```

- `SolanaGenerator` — Ed25519 via `solana-sdk`, base58 addresses
- `EvmGenerator` — secp256k1 via `k256` + `sha3` (Keccak-256), 0x-prefixed hex addresses

### 2. Match Engine

- Enum: `MatchPosition::StartsWith | EndsWith`
- For starts-with on Solana: decode the vanity string from base58 to raw bytes, compare against pubkey bytes directly (avoids expensive `to_string()` base58 encoding per iteration)
- For ends-with and EVM: compare against the address string
- Case-insensitive option for both chains

### 3. Threading

- Rayon global thread pool sized to user-specified thread count
- Workers loop: generate keypair, check match, send matches through `mpsc` channel
- AtomicU64 counter for progress (no mutex)
- No per-iteration stdout writes from workers

### 4. Graceful Shutdown (Ctrl+C)

- `ctrlc` crate sets an `AtomicBool` stop flag
- Workers check the flag each iteration and exit
- All matches already flushed to CSV before shutdown
- On stop: print summary with matches found, wallets checked, elapsed time

### 5. CSV Output

- File: `vanity_wallets.csv`
- Columns: `Chain, Address, Secret Key (hex)`
- Appends to existing file (preserves previous runs)
- Each match flushed immediately so nothing lost on interrupt

### 6. Interactive Flow

```
Select chain: [1] Solana  [2] HyperEVM
Match position: [1] Starts with  [2] Ends with
Enter vanity string: ___
Case-sensitive? (yes/no): ___
Number of threads (1-64): ___
Searching... Press Ctrl+C to stop.
```

### 7. Input Validation

- Solana vanity string: 1-9 chars, base58 alphabet only (no 0, O, I, l)
- EVM vanity string: 1-8 chars, hex only (0-9, a-f, A-F)
- Thread count: 1-64
- Match position: 1 or 2

## Dependencies

- `solana-sdk = "1.8"` — Solana keypair generation
- `k256` — secp256k1 elliptic curve for EVM keys
- `sha3` — Keccak-256 for EVM address derivation
- `rayon` — work-stealing thread pool
- `ctrlc` — graceful signal handling
- `csv` — CSV output
- `bs58` — base58 decode for raw byte prefix matching optimization

## Out of Scope

- GPU/Metal acceleration (future enhancement)
- CLI flag mode (stays interactive only)
- Multiple vanity patterns per run
- BIP-39 mnemonic output (secret key bytes only)
