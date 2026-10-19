# Vanaddy

Vanity addresses for Solana, EVM, Bitcoin, TON, and Monero. One binary, a terminal UI, local key generation. The seed or private key it prints imports into the wallet named below.

EVM addresses are not tied to one network. The same key works on Ethereum, Base, Arbitrum, Optimism, Polygon, BSC, Avalanche, and any other EVM chain.

## Chains

| Chain | Address | Seed | Path | Imports into |
|-------|---------|------|------|----------------|
| Solana | Base58 | BIP-39, 12 words | SLIP-0010 `m/44'/501'/0'/0'` | Phantom, Solflare |
| EVM | `0x` + hex | BIP-39, 12 words | BIP-44 `m/44'/60'/0'/0/0` | MetaMask, Rabby, any EVM wallet |
| Bitcoin | `bc1q…` | BIP-39, 12 words | BIP-84 `m/84'/0'/0'/0/0` | Sparrow, Electrum, any BIP-84 wallet |
| TON | `UQ…`, 48 chars | TON native, 24 words | wallet-v5r1 (W5) | Tonkeeper, MyTonWallet |
| Monero | `4…`, 95 chars | 25-word Electrum | spend key random; view key = Keccak(spend) | `monero-wallet-cli --restore-deterministic-wallet`, Cake, Feather |

Bitcoin vanity starts after `bc1q`. TON starts after `UQ`. Monero starts after `4`. Solana and EVM start at the first character.

Match the start, the end, or both. Case-sensitive EVM uses the EIP-55 checksum. Monero and TON cap the pattern at 4 characters.

## Build

Rust stable. Release build:

```bash
git clone https://github.com/pipXBT/Vanaddy.git
cd Vanaddy
cargo build --release
./target/release/vanaddy
```

`cargo run` is a debug build. It is several times slower. Do not use it to judge speed.

CPU-only binary, no Metal linked:

```bash
cargo build --release --no-default-features
```

## Keys

| Key | Action |
|-----|--------|
| Up / Down | Move between fields. During a search, move through hits. |
| Left / Right | Change chain, match mode, case, GPU. |
| Tab / Shift-Tab | Next / previous field. |
| 1–5 | Chain: Solana, EVM, Bitcoin, TON, Monero. On the match field, 1–3 picks the mode. |
| y / n | Case, and the GPU toggle. |
| Enter | Start. |
| Ctrl+C | Stop and return to the form. Hits already found are kept. |
| h | Help. |
| q | Quit. Ignored while a text field is focused. |

## Output

Matches append to `vanity_wallets.csv` in the current directory.

```
Chain, Address, Private Key (hex), Seed Phrase
```

The file is mode `0600`. It contains the seed phrase in plaintext. Anyone who can read it owns the wallet. On exit, if anything was saved, the program says so.

## GPU

On Apple Silicon, EVM seed stretching (BIP-39 PBKDF2) runs on the Metal GPU. Entropy is generated on the CPU. A hit is written only after the CPU re-derives that seed with `ring` and the address matches. The CSV never stores a GPU-produced key.

The GPU toggle is EVM-only. `VANADDY_GPU=0` or `VANADDY_NO_GPU=1` forces CPU. `--no-default-features` builds the CPU binary.

With the terminal window open, a release EVM search on an M1 is a few thousand candidates per second. One performance core, CPU only, is about 3,100/s. Eight threads, CPU only, is about 12,000–15,000/s. The GPU's offline seed rate is higher than the number the window shows. The window is the number that matters while you are watching it.

Other chains do not use the GPU.

| Chain | One M1 performance core, release |
|-------|----------------------------------|
| Solana | ~288 µs (~3,500/s) |
| EVM | ~321 µs (~3,100/s) |
| Bitcoin | ~321 µs (~3,100/s) |
| TON | ~26 ms (~38/s) |
| Monero | ~35 µs (~29,000/s) |

Solana, EVM, Bitcoin, and TON spend most of that time in PBKDF2. Monero does not.

## How long a pattern takes

Attempts per hit, roughly. Case-insensitive Solana/Monero is a smaller alphabet than the table.

| Chars | Solana / Monero | EVM | Bitcoin | TON |
|-------|-----------------|-----|---------|-----|
| 1 | 58 | 16 | 32 | 64 |
| 2 | 3.4K | 256 | 1.0K | 4.1K |
| 3 | 195K | 4.1K | 33K | 262K |
| 4 | 11M | 66K | 1.0M | 17M |
| 5 | 656M | 1.0M | 33M | 1.1B |
| 6 | 38B | 17M | 1.1B | — |

A 4-character TON pattern is about a day on 8 threads. Longer than the cap is not offered.

## Security

No network. Entropy comes from the OS.

Derivations are pinned to known vectors: SLIP-0010, BIP-39, BIP-44 (first MetaMask account of the standard phrase), BIP-84 (`bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu`), EIP-55, and a Tonkeeper W5 round-trip.

Monero secret keys are wiped on drop. Solana and TON signing keys are wiped by `ed25519-dalek`. EVM and Bitcoin secret keys are `Copy` and are not wiped. They live on the stack for one batch.

Move the CSV off the disk you search on once the address is in a wallet. Deleting the file is not enough if the disk is backed up.

## License

MIT
