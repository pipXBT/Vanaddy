> Generated: 2026-10-19 | Token-lean format for LLM context | Source: update-codemaps

# Data & Helpers

Core types, enums, and the cross-chain crypto helpers.

## Top-Level Types

| Type | Defined in | Notes |
|------|------------|-------|
| `App` | `src/app.rs:42` | TUI + search + GPU fields |
| `AppState` | `src/app.rs:37` | `Configuring \| Searching` |
| `Chain` | `src/chains/mod.rs:31` | `BATCH` + `generate_batch` |
| `Bip39GpuChain` | `src/chains/mod.rs:65` | EVM only: `from_gpu_seed`, `verify` |
| `ChainKind` | `src/chains/mod.rs:75` | `Solana \| Evm \| Bitcoin \| Ton \| Monero` |
| `Match` | `src/chains/mod.rs:16` | `{ chain, address, secret_hex, mnemonic, verified }`. Not `Clone` |
| `Verified` | `src/verify.rs:44` | private `()`. `cpu_reference()` or `gpu_reverified()` |
| `Matcher` | `src/matcher.rs:11` | precomputed prefix/suffix |
| `MatchPosition` | `src/matcher.rs:5` | `StartsWith \| EndsWith \| StartsAndEndsWith` |
| `Cell` / `CellRef` | `src/chains/ton_cell.rs` | TVM cell + `(hash, max_depth)` |
| `MoneroKeypair` | `src/chains/monero.rs:28` | `{ spend_sec, view_sec }`, `Zeroize + ZeroizeOnDrop` |
| `GpuCandidate` | `src/gpu/mod.rs:183` | `{ entropy: [u8; 16], seed: [u8; 64] }`, `Copy` |
| `SeedBlock` | `src/gpu/mod.rs:194` | `Vec<GpuCandidate>`, `ZeroizeOnDrop`. push-only |
| `GpuStatus` | `src/gpu/mod.rs:133` | `Unavailable \| Ready \| Initializing \| Running \| Disabled` |
| `GpuHealth` | `src/gpu/mod.rs:239` | `disable`, set-once reason, `seeds_delivered` |
| `GpuRx` | `src/gpu/mod.rs:233` | `crossbeam_channel::Receiver<Box<SeedBlock>>` |
| `Schedule` | `src/gpu/mod.rs:314` | `Production \| Uniform(u32) \| Irregular(&[u32])` |
| `KeyBlock` | `src/gpu/pack.rs:13` | `[u64; 16]` big-endian HMAC block |

## Matcher Internals (`src/matcher.rs`)

```rust
pub struct Matcher {
    pub(crate) prefix: String,
    pub(crate) suffix: String,
    pub(crate) case_sensitive: bool,
    pub(crate) evm_prefix: Option<(Vec<u8>, Option<u8>)>, // full bytes, extra high nibble
    pub(crate) evm_suffix: Option<(Vec<u8>, Option<u8>)>, // full bytes, extra low nibble
    pub(crate) bech32_prefix_5bit: Option<Vec<u5>>,
}
pub fn new(prefix: String, suffix: String, case_sensitive: bool, chain: ChainKind) -> Self
```

| Helper | Purpose |
|--------|---------|
| `hex_prefix_to_bytes` | `"dead"` → `([0xde, 0xad], None)`; `"dea"` → `([0xde], Some(0x0a))` |
| `hex_suffix_to_bytes` | `"beef"` → `([0xbe, 0xef], None)`; `"def"` → `([0xef], Some(0x0d))` |
| `matches_evm_raw(&[u8; 20])` | byte + nibble compare (EVM only) |
| `prefix_matches(&str)` | empty → true; else leading bytes, optional `eq_ignore_ascii_case` |
| `suffix_matches(&str)` | same for the tail |

Bitcoin `bech32_prefix_5bit` maps each vanity char through `qpzry9x8gf2tvdw0s3jn54khce6mua7l`.

Built as: `StartsWith` → prefix only; `EndsWith` → suffix only; `StartsAndEndsWith` → both.

## Crypto Helpers

| File | Function | Returns |
|------|----------|---------|
| `pbkdf2_lanes.rs:16` | `pbkdf2_hmac_sha512::<L>` | `[[u8; 64]; L]`. salt ≤ 107, iterations ≥ 1 |
| `pbkdf2_lanes.rs:49` | `fallback::<L>` | one `ring::pbkdf2::derive` per lane |
| `pbkdf2_lanes.rs:138` | `hw::compress::<L>` | `#[target_feature(enable = "sha3")]` |
| `pbkdf2_lanes.rs:231` | `hw::pbkdf2_lanes::<L>` | interleaved HMAC-SHA512 PBKDF2 |
| `seed.rs:14` | `derive_seed` | ring, `PBKDF2_ROUNDS` (2048), salt `BIP39_SALT` |
| `seed.rs:28` | `derive_seeds::<L>` | same via `pbkdf2_hmac_sha512` |
| `slip10.rs:6` | `slip10_derive_ed25519` | panics if any index is not hardened |
| `bip32.rs:6` | `bip32_derive_secp256k1` | BIP-32 CKD → `SecretKey` |
| `ton_mnemonic.rs:57` | `generate_ton_wallet` | one accepted phrase + key (ring) |
| `ton_mnemonic.rs:88` | `generate_ton_wallets` | `[_; LANES]` |
| `verify.rs:73` | `verify_gpu::<C>` | `Option<(addr, secret, phrase, Verified)>`. `None` rejects |

`hw::round_pair` (`pbkdf2_lanes.rs:106`) is one SHA-512 round pair. Keys longer than `HMAC_BLOCK_LEN` (128) are pre-hashed with ring on the CPU path. `pack_key_block` asserts the key is ≤ 128; the kernel has no pre-hash.

### Path Constants

| Constant | Value | Used by |
|----------|-------|---------|
| `slip10::PHANTOM_SOLANA_PATH` | m/44'/501'/0'/0' | Solana |
| `bip32::EVM_PATH` | m/44'/60'/0'/0/0 | EVM |
| `bip32::BTC_BIP84_PATH` | m/84'/0'/0'/0/0 | Bitcoin |

### Other Constants

| Constant | Value | File |
|----------|-------|------|
| `LANES` | 4 | `pbkdf2_lanes.rs:11`. Also `BATCH` for Solana/EVM/Bitcoin/TON |
| `MAX_SALT_LEN` | 107 | `pbkdf2_lanes.rs:46` |
| `PBKDF2_ROUNDS` / `BIP39_SALT` | 2048 / `b"mnemonic"` | `seed.rs:7`, `:11` |
| `PBKDF2_BASIC_ITER` / `PBKDF2_SEED_ITER` | 390 / 100_000 | TON filter / seed |
| `W5_MAINNET_WALLET_ID` | `0x7FFF_FF11` | `ton_cell.rs:164` |
| `NETWORK_BYTE_MAINNET` | `0x12` | Monero → leading `4` |
| `MONERO_ADDRESS_LEN` | 95 | stack buffer in `matches_raw` |
| `MATCH_CAP` | 500 | in-memory `VecDeque` |
| `WAVE` / `BLOCK` | 8192 / 512 | GPU wave / channel message |
| `CHANNEL_CAPACITY` | 32 | two waves of blocks |
| `ITERS_PER_DISPATCH` | 8 | 2047 = 255×8+7 → 256 dispatches |
| `DISPATCHES_PER_COMMAND_BUFFER` | 4 | ~8.8 ms per command buffer |
| `PIPELINE_DEPTH` | 3 | command buffers in flight |
| `AUDITS_PER_WAVE` | 4 | random indices, not a stride |
| `EVM_GPU_SEEDS_PER_SEC` | 13600 | pre-search ETA only |
| `EVM_GPU_TAIL_SECS` | 50.5e-6 | BIP-32 + Keccak per GPU seed |
| `tick_rate` | 100 ms | `main.rs` |

## Address Encoding

| Chain | Display (`encode_address`) | Hot `matches_raw` |
|-------|----------------------------|-------------------|
| Solana | `bs58::encode` → `String` | same heap encode |
| EVM | `0x` + `hex::encode` | raw 20 bytes; EIP-55 is `[u8; 40]` |
| Bitcoin | `bech32::encode("bc", ...)` → `String` | stack `AddrBuf` + `encode_to_fmt`. Vanity skips `bc1q` |
| TON | `user_friendly_ascii` copied to `String` | `[u8; 48]` via `encode_slice`. Vanity skips `UQ` |
| Monero | `encode_address_into` copied to `String` | `[u8; 95]`. Vanity skips `4` |

Monero Base58: 8-byte blocks, `BLOCK_SIZES = [0,2,3,5,6,7,9,10,11]`, alphabet index 0 pads as `1`. Payload is 65 bytes + 4-byte Keccak checksum.

## Match Logic Conventions

1. Optional fast-path: EVM `matches_evm_raw`; Bitcoin `expand_5bit` vs `bech32_prefix_5bit` (prefix only — a miss returns before encode).
2. Bitcoin, TON, Monero: one stack encode, then `prefix_matches(vanity_target) && suffix_matches(full)`.
3. Solana: heap Base58, then both helpers on the full string.
4. EVM case-sensitive: exact compare of the EIP-55 stack chars. No `prefix_matches`.

| Chain | Fixed prefix | Vanity applies to |
|-------|--------------|-------------------|
| Solana | none | `addr[..]` |
| EVM | `0x` in display only | hex chars from index 0 |
| Bitcoin | `bc1q` | `addr[4..]`; suffix is the full addr |
| TON | `UQ` | `encoded[2..]`; suffix is the full encoded |
| Monero | `4` | `addr[1..]`; suffix is the full addr |

## Memory & Secrets

- Solana / TON: `SigningKey` zeroizes on drop. EVM / Bitcoin: `SecretKey` is `Copy` and is not wiped; hex is built only on a match.
- Monero: `MoneroKeypair` wipes `spend_sec` and `view_sec` on drop.
- GPU: `SeedBlock` zeroizes on drop. Producer entropy and key blocks are `Zeroizing` and overwritten each wave. `verify_gpu` rebuilds the phrase with `Mnemonic::from_entropy` on the CPU. The GPU seed is a filter, never a CSV field.
- CSV: `open_csv_secure` sets and re-asserts mode `0o600`. The search holds one `File`. `stop_search` stats the path inode against that handle.
- Entropy: `Mnemonic::new` (OS CSPRNG) for BIP-39 and the GPU fill. `OsRng` for Monero scalars. Nothing is derived from `tid`.

## Test Vectors (pinned)

239 `#[test]` fns, 3 `#[ignore]`. Load-bearing:

| Test | What it pins |
|------|--------------|
| `seed::derive_seed_matches_bip39_vector` | canonical 64-byte seed |
| `seed::derive_seeds_matches_derive_seed_per_lane` | lanes == ring |
| `pbkdf2_lanes::every_lane_matches_bip39_canonical_vector` | hardware PBKDF2 |
| `pbkdf2_lanes::distinct_lanes_match_ring_reference` | 4 phrases == ring |
| `pbkdf2_lanes::ton_salts_and_iteration_counts_match_ring` | TON 390 and 100_000 |
| `slip10::slip10_ed25519_test_vector_1_m_0h` (+ `_1h`) | SLIP-0010 |
| `solana::solana_phantom_derivation_from_canonical_phrase` | Phantom address |
| `bitcoin::bip84_canonical_vector` | `bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu` |
| `bitcoin::matches_raw_agrees_with_encode_address_for_one_char_prefix_and_suffix` | stack Bech32 == `encode_address` |
| `evm::bip44_canonical_vector` | `0x9858EfFD232B4033E47d90003D41EC34EcaEda94` |
| `evm::eip55_canonical_vector`, `eip55_second_vector` | EIP-55 |
| `{solana,evm,bitcoin}::generate_batch_emits_lane_count_candidates_matching_single_path` | batch == single |
| `ton::ton_tonkeeper_round_trip_vector` | W5 address |
| `ton::matches_raw_agrees_with_encode_address_for_one_char_affix` | stack base64 == encode |
| `ton_cell::wallet_v5r1_matches_tonkeeper_vector` | state_init hash |
| `monero::keccak256_empty_vector` | original Keccak |
| `monero::monero_matches_raw_agrees_with_encode_address` | stack Base58 == encode |
| `chains::tests::search_counts_whole_batches_and_honours_stop` | counter steps by `BATCH` |
| `gpu::metal::gpu_seed_matches_bip39_canonical_vector` | index 0 vs BIP-39 vector |
| `gpu::metal::gpu_chunk_schedule_invariance` | `iters=2047`, production `R=8`, irregular `[1,1000,46,1000]` |
| `gpu::metal::gpu_ring_and_4lane_agree_over_512_deterministic_phrases` | GPU == ring == 4-lane, indices 0..511 |
| `gpu::kernel_src` tid allowlist + banned `threadgroup`/`simd_`/`barrier`/`atomic` | kernel source |
| `verify::verify_gpu_accepts_the_bip39_canonical_vector` | entropy 0 → MetaMask account |
