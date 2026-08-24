> Generated: 2026-08-24 | Token-lean format for LLM context

# Data & Helpers

Core types, enums, and the cross-chain crypto helpers.

## Top-Level Types

| Type | Defined in | Notes |
|------|------------|-------|
| `App` | `src/app.rs:21` | Whole TUI state |
| `AppState` | `src/app.rs:16` | `Configuring \| Searching` |
| `Chain` (trait) | `src/chains/mod.rs:23` | Per-chain contract; `Send + Sync + 'static`; `BATCH` const + `generate_batch` |
| `ChainKind` (enum) | `src/chains/mod.rs:48` | `Solana \| Evm \| Bitcoin \| Ton \| Monero` |
| `Match` (struct) | `src/chains/mod.rs:16` | `{ chain, address, secret_hex, mnemonic: String }` — channel payload |
| `Matcher` | `src/matcher.rs:11` | Pre-computed prefix/suffix matchers |
| `MatchPosition` | `src/matcher.rs:5` | `StartsWith \| EndsWith \| StartsAndEndsWith` (App/UI only — Matcher itself doesn't carry it) |
| `Cell` | `src/chains/ton_cell.rs:12` | TVM cell (data bits + refs) |
| `CellRef` | `src/chains/ton_cell.rs:24` | `(hash: [u8; 32], max_depth: u16)` |
| `MoneroKeypair` | `src/chains/monero.rs:28` | `{ spend_sec, view_sec }` with `Zeroize + ZeroizeOnDrop` |
| `pbkdf2_lanes::hw::State` / `Block` | `src/pbkdf2_lanes.rs` (private) | `[u64; 8]` SHA-512 state / `[u8; 128]` block |

## Matcher Internals (`src/matcher.rs`)

```rust
pub struct Matcher {
    pub(crate) prefix: String,
    pub(crate) suffix: String,
    pub(crate) case_sensitive: bool,
    pub(crate) evm_prefix: Option<(Vec<u8>, Option<u8>)>,   // (full_bytes, extra_high_nibble)
    pub(crate) evm_suffix: Option<(Vec<u8>, Option<u8>)>,   // (full_bytes, extra_low_nibble)
    pub(crate) bech32_prefix_5bit: Option<Vec<u5>>,
}

pub fn new(prefix: String, suffix: String, case_sensitive: bool, chain: ChainKind) -> Self
```

| Helper | Purpose |
|--------|---------|
| `hex_prefix_to_bytes(hex)` | "dead" → ([0xde, 0xad], None); "dea" → ([0xde], Some(0x0a)) |
| `hex_suffix_to_bytes(hex)` | "beef" → ([0xbe, 0xef], None); "def" → ([0xef], Some(0x0d)) |
| `Matcher::matches_evm_raw(&[u8; 20])` | Byte+nibble compare against `evm_prefix`/`evm_suffix` (EVM only) |
| `Matcher::prefix_matches(&str)` | `#[inline]` — empty → true; else byte-slice eq with optional `eq_ignore_ascii_case`. No alloc. |
| `Matcher::suffix_matches(&str)` | Mirror of `prefix_matches` for trailing chars. |

For Bitcoin: `bech32_prefix_5bit` is precomputed by mapping each user-typed Bech32 char to its u5 index via the `qpzry9x8gf2tvdw0s3jn54khce6mua7l` charset.

## Crypto Helpers

| File | Function | Returns |
|------|----------|---------|
| `src/pbkdf2_lanes.rs:16` | `pbkdf2_hmac_sha512::<L>([&[u8]; L], salt, iterations) -> [[u8; 64]; L]` | First 64-byte PBKDF2-HMAC-SHA512 block per lane; `salt.len() <= 107`, `iterations >= 1` (asserts) |
| `src/pbkdf2_lanes.rs:41` | `fallback::<L>` | One `ring::pbkdf2::derive` per lane (non-aarch64, or no `sha3`) |
| `src/pbkdf2_lanes.rs:130` | `hw::compress::<L>(&mut [State; L], &[Block; L])` | `#[target_feature(enable = "sha3")]`; one SHA-512 block into each of L states, lanes interleaved per round pair |
| `src/pbkdf2_lanes.rs:223` | `hw::pbkdf2_lanes::<L>` | HMAC key schedule (keys > 128 B pre-hashed with `ring` SHA-512), `U_1 = PRF(salt‖INT(1))`, then `iterations-1` rounds of inner+outer compress |
| `src/seed.rs:8` | `derive_seed(&Mnemonic) -> [u8; 64]` | PBKDF2-HMAC-SHA512 × 2048 (ring) |
| `src/seed.rs:23` | `derive_seeds::<L>(&[Mnemonic; L]) -> [[u8; 64]; L]` | Same, L phrases through `pbkdf2_hmac_sha512` |
| `src/slip10.rs:6` | `slip10_derive_ed25519(&[u8], &[u32]) -> [u8; 32]` | All indices must be hardened (≥ 0x80000000) — panics otherwise |
| `src/bip32.rs:6` | `bip32_derive_secp256k1(&[u8], &[u32]) -> secp256k1::SecretKey` | BIP-32 CKD; hardened steps hash `00‖secret_bytes`, non-hardened hash `PublicKey::from_secret_key_global().serialize()`; child = `add_tweak(Scalar::from_be_bytes(IL))` |
| `src/chains/ton_mnemonic.rs:28` | `hmac_sha512_empty_key(phrase) -> [u8; 64]` | TON entropy: `HMAC-SHA512(key=phrase, msg="")` |
| `src/chains/ton_mnemonic.rs:88` | `generate_ton_wallets() -> [(String, SigningKey); LANES]` | 4-lane filter + 4-lane 100k seed |

`hw::round_pair` / `hw::schedule` (`:98`, `:117`) implement one SHA-512 round pair and the `su0`/`su1` message-schedule step; working-variable pairs `(ab, cd, ef, gh)` rotate roles with period 4, message slots with period 8, matching the reference `sha512-armv8` hardware path.

### Path Constants

| Constant | Value | Used by |
|----------|-------|---------|
| `slip10::PHANTOM_SOLANA_PATH` | `[0x8000002C, 0x800001F5, 0x80000000, 0x80000000]` (m/44'/501'/0'/0') | Solana |
| `bip32::EVM_PATH` | `[0x8000002C, 0x8000003C, 0x80000000, 0, 0]` (m/44'/60'/0'/0/0) | EVM |
| `bip32::BTC_BIP84_PATH` | `[0x80000054, 0x80000000, 0x80000000, 0, 0]` (m/84'/0'/0'/0/0) | Bitcoin |

### Other Constants

| Constant | Value | File |
|----------|-------|------|
| `pbkdf2_lanes::LANES` | 4 | `src/pbkdf2_lanes.rs:11` — measured optimum on M1; also `Chain::BATCH` for the PBKDF2 chains |
| `pbkdf2_lanes::MAX_SALT_LEN` | 107 | `:38` — salt ‖ INT(1) ‖ padding must fit one block |
| `pbkdf2_lanes::hw::K`, `H0` | FIPS 180-4 SHA-512 constants | `:66`, `:90` |
| `seed::PBKDF2_ROUNDS` | 2048 | `src/seed.rs:5` |
| `ton_mnemonic::PBKDF2_BASIC_ITER` | 390 | acceptance filter (~100k/256) |
| `ton_mnemonic::PBKDF2_SEED_ITER` | 100_000 | TON Ed25519 seed |
| `ton_cell::W5_MAINNET_WALLET_ID` | `0x7FFF_FF11` | TON W5 mainnet |
| `ton_cell::WALLET_V5R1_CODE.max_depth` | 6 | W5 code cell depth |
| `monero::NETWORK_BYTE_MAINNET` | `0x12` | leading address byte → produces "4..." |
| `tick_rate` | `Duration::from_millis(100)` | main event loop |

### Test-Only (`#[cfg(test)]`)

| Item | Location | Purpose |
|------|----------|---------|
| `WALLET_V3R2_CODE` | `chains/ton_cell.rs:101` | regression coverage of cell-hashing pipeline |
| `wallet_v3r2_data_cell` | `chains/ton_cell.rs:114` | builds 320-bit data cell |
| `wallet_v3r2_state_init` | `chains/ton_cell.rs:129` | builds StateInit cell with v3r2 code+data refs |
| `ton_mnemonic::mnemonic_to_signing_key` | `chains/ton_mnemonic.rs:123` | phrase → key via the ring path; reference for batch tests |

Production TON path uses W5 (v5r1) — v3r2 is preserved purely for test pins.

## Address Encoding

| Chain | Encode |
|-------|--------|
| Solana | `bs58::encode(&[u8; 32]).into_string()` |
| EVM | `format!("0x{}", hex::encode(&[u8; 20]))` |
| Bitcoin | `bech32::encode("bc", [u5(0), ..to_base32(hash160)], Variant::Bech32)` |
| TON | `URL_SAFE_NO_PAD.encode(&[u8; 36])` |
| Monero | Custom Base58 in 8-byte blocks (BLOCK_SIZES = `[0,2,3,5,6,7,9,10,11]`) over `payload(65) \|\| keccak256(payload)[..4]` |

## Match Logic Conventions

`Matcher` is built with:
- For `StartsWith`: `prefix=user_input`, `suffix=""`.
- For `EndsWith`: `prefix=""`, `suffix=user_input`.
- For `StartsAndEndsWith`: both filled.

Per-chain `matches_raw` does:
1. Optional fast-path (EVM byte/nibble compare via `matches_evm_raw`; Bitcoin 5-bit group compare).
2. For Solana/Bitcoin/TON/Monero: full address encode, then `matcher.prefix_matches(vanity_target) && matcher.suffix_matches(&addr)`.
3. EVM: in case-sensitive mode, additionally re-compute `eip55_encode(addr)` and compare prefix/suffix exactly. Does NOT use `prefix_matches`/`suffix_matches`.

The vanity-skip rule per chain:

| Chain | Fixed prefix | Vanity applies to |
|-------|--------------|-------------------|
| Solana | none | `addr[..]` |
| EVM | `0x` (in display only — raw bytes have no skip) | EIP-55 hex chars from index 0 |
| Bitcoin | `bc1q` | `addr[4..]` (suffix matches against full `addr`) |
| TON | `UQ` | `addr[2..]` (suffix matches against full `encoded`) |
| Monero | `4` | `addr[1..]` (suffix matches against full `addr`) |

## Memory & Secrets

- Solana / TON: `ed25519_dalek::SigningKey` zeroizes on drop. EVM / Bitcoin: `secp256k1::SecretKey` is `Copy` and is **not** wiped on drop (only `non_secure_erase()` exists); discarded candidates live on the stack for one batch. Secret hex is computed only on a successful match (`encode_secret` not in hot loop).
- `pbkdf2_lanes::hw::pbkdf2_lanes` keeps HMAC pads, `U`, and `T` states in stack arrays; they are not zeroized (matches the rest of the seed pipeline).
- Monero: `MoneroKeypair: Clone + Zeroize + ZeroizeOnDrop`. Discarded candidates have their `spend_sec` and `view_sec` wiped on drop.
- CSV file: every open via `app::open_csv_secure()`, which sets `chmod 0600` on create AND re-asserts after open.
- `OsRng` is the entropy source for Monero scalars; BIP-39 / TON phrases come from `tiny-bip39`'s `Mnemonic::new` (uses OS CSPRNG).

## Test Vectors (pinned)

63 tests total (`cargo test`). Load-bearing ones:

| Test | What it pins |
|------|--------------|
| `pbkdf2_lanes::every_lane_matches_bip39_canonical_vector` | 4-lane hardware PBKDF2 → canonical BIP-39 seed in every lane |
| `pbkdf2_lanes::distinct_lanes_match_ring_reference` | 4 distinct phrases (one > 128 B key) == `ring` per lane |
| `pbkdf2_lanes::ton_salts_and_iteration_counts_match_ring` | TON salts at 390 and 100_000 iterations == `ring` |
| `pbkdf2_lanes::{single_lane_and_single_iteration, exactly_128_byte_password}_match_ring` | L=1, iterations=1/2, key == block size |
| `seed::derive_seed_matches_bip39_vector` | BIP-39 "abandon...about" → canonical 64-byte seed |
| `seed::derive_seeds_matches_derive_seed_per_lane` | batch seeds == single seeds |
| `slip10::slip10_ed25519_test_vector_{1,2}` | SLIP-0010 spec vectors |
| `solana::solana_phantom_derivation_from_canonical_phrase` | Phantom-importable address for canonical phrase |
| `bitcoin::bip84_canonical_vector` | BIP-84 spec vector → `bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu` |
| `evm::bip44_canonical_vector` | m/44'/60'/0'/0/0 of canonical phrase → `0x9858EfFD232B4033E47d90003D41EC34EcaEda94` |
| `evm::eip55_canonical_vector`, `eip55_second_vector` | EIP-55 spec examples |
| `{solana,evm,bitcoin}::generate_batch_emits_lane_count_candidates_matching_single_path` | batch path == `from_phrase → derive_seed → from_seed` |
| `ton::generate_batch_emits_lane_count_wallets_with_consistent_addresses`, `ton_mnemonic::batch_wallets_match_single_path_and_pass_filter` | batch TON wallets == ring path, pass 1/256 filter |
| `ton::ton_tonkeeper_round_trip_vector` | Full pipeline matches Tonkeeper's W5 address for a known phrase |
| `ton_cell::wallet_v5r1_matches_tonkeeper_vector` | W5 state_init hash matches base64-decoded Tonkeeper address |
| `monero::keccak256_empty_vector` | Confirms original Keccak (not FIPS-202) |
| `monero::monero_seed_phrase_*` | 25-word phrase format + determinism |
| `chains::tests::search_counts_whole_batches_and_honours_stop` | worker counter advances by `BATCH`, stops on flag |
