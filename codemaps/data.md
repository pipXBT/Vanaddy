> Generated: 2026-05-05 | Token-lean format for LLM context

# Data & Helpers

Core types, enums, and the cross-chain crypto helpers.

## Top-Level Types

| Type | Defined in | Notes |
|------|------------|-------|
| `App` | `src/app.rs:25` | Whole TUI state |
| `AppState` | `src/app.rs:20` | `Configuring \| Searching` |
| `Chain` (trait) | `src/chains/mod.rs:18` | Per-chain contract; `Send + Sync + 'static` |
| `ChainKind` (enum) | `src/chains/mod.rs:35` | `Solana \| Evm \| Bitcoin \| Ton \| Monero` |
| `MatchPayload` | `src/chains/mod.rs:16` | `(String, String, String, String) = (label, address, secret_hex, mnemonic)` |
| `Matcher` | `src/matcher.rs:11` | Pre-computed prefix/suffix matchers |
| `MatchPosition` | `src/matcher.rs:5` | `StartsWith \| EndsWith \| StartsAndEndsWith` |
| `Cell` | `src/chains/ton_cell.rs:12` | TVM cell (data bits + refs) |
| `CellRef` | `src/chains/ton_cell.rs:24` | `(hash: [u8; 32], max_depth: u16)` |
| `MoneroKeypair` | `src/chains/monero.rs:28` | `{ spend_sec, view_sec }` with `Zeroize + ZeroizeOnDrop` |

## Matcher Internals (`src/matcher.rs`)

```rust
pub struct Matcher {
    pub(crate) prefix: String,
    pub(crate) suffix: String,
    pub(crate) position: MatchPosition,
    pub(crate) case_sensitive: bool,
    pub(crate) prefix_lower: String,    // pre-lowercased
    pub(crate) suffix_lower: String,
    pub(crate) evm_prefix: Option<(Vec<u8>, Option<u8>)>,   // (full_bytes, extra_high_nibble)
    pub(crate) evm_suffix: Option<(Vec<u8>, Option<u8>)>,   // (full_bytes, extra_low_nibble)
    pub(crate) bech32_prefix_5bit: Option<Vec<u5>>,
}
```

| Helper | Purpose |
|--------|---------|
| `hex_prefix_to_bytes(hex)` | "dead" → ([0xde, 0xad], None); "dea" → ([0xde], Some(0x0a)) |
| `hex_suffix_to_bytes(hex)` | "beef" → ([0xbe, 0xef], None); "def" → ([0xef], Some(0x0d)) |
| `Matcher::matches_evm_raw(&[u8; 20])` | Byte+nibble compare against `evm_prefix`/`evm_suffix` |
| `Matcher::matches_str(&str)` | Generic string `starts_with`/`ends_with`, strips `0x` prefix |

For Bitcoin: `bech32_prefix_5bit` is precomputed by mapping each user-typed Bech32 char to its u5 index via the `qpzry9x8gf2tvdw0s3jn54khce6mua7l` charset.

## Crypto Helpers

| File | Function | Returns |
|------|----------|---------|
| `src/seed.rs` | `derive_seed(&Mnemonic) -> [u8; 64]` | PBKDF2-HMAC-SHA512 × 2048 (ring) |
| `src/slip10.rs` | `slip10_derive_ed25519(&[u8], &[u32]) -> [u8; 32]` | All indices must be hardened (≥ 0x80000000) — panics otherwise |
| `src/bip32.rs` | `bip32_derive_secp256k1(&[u8], &[u32]) -> SecretKey` | BIP-32 child key derivation; mixed hardened/non-hardened |

### Path Constants

| Constant | Value | Used by |
|----------|-------|---------|
| `slip10::PHANTOM_SOLANA_PATH` | `[0x8000002C, 0x800001F5, 0x80000000, 0x80000000]` (m/44'/501'/0'/0') | Solana |
| `bip32::EVM_PATH` | `[0x8000002C, 0x8000003C, 0x80000000, 0, 0]` (m/44'/60'/0'/0/0) | EVM |
| `bip32::BTC_BIP84_PATH` | `[0x80000054, 0x80000000, 0x80000000, 0, 0]` (m/84'/0'/0'/0/0) | Bitcoin |

### Other Constants

| Constant | Value | File |
|----------|-------|------|
| `seed::PBKDF2_ROUNDS` | 2048 | `src/seed.rs:4` |
| `ton_mnemonic::PBKDF2_BASIC_ITER` | 390 | acceptance filter (~100k/256) |
| `ton_mnemonic::PBKDF2_SEED_ITER` | 100_000 | TON Ed25519 seed |
| `ton_cell::W5_MAINNET_WALLET_ID` | `0x7FFF_FF11` | TON W5 mainnet |
| `ton_cell::WALLET_V5R1_CODE.max_depth` | 6 | W5 code cell depth |
| `monero::NETWORK_BYTE_MAINNET` | `0x12` | leading address byte → produces "4..." |
| `tick_rate` | `Duration::from_millis(100)` | main event loop |

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
- For `EndsWith`: `prefix=""`, `suffix=user_input`. (Note: validation uses `vanity_suffix` for both, but the Matcher field semantics are independent.)
- For `StartsAndEndsWith`: both filled.

Per-chain `matches_raw` does:
1. Optional fast-path (EVM byte/nibble compare; Bitcoin 5-bit group compare).
2. Full address encode (always for Solana/Bitcoin/TON/Monero — fast-path is for filtering, not skipping the encode entirely).
3. String-level prefix/suffix check, with case-insensitive paths using `eq_ignore_ascii_case` over byte slices to avoid `to_lowercase()` allocations.
4. EVM case-sensitive: additionally re-compute `eip55_encode(addr)` and compare prefix/suffix exactly.

The vanity-skip rule per chain:

| Chain | Fixed prefix | Vanity applies to |
|-------|--------------|-------------------|
| Solana | none | `addr[..]` |
| EVM | `0x` (in display only — raw bytes have no skip) | EIP-55 hex chars from index 0 |
| Bitcoin | `bc1q` | `addr[4..]` |
| TON | `UQ` | `addr[2..]` (suffix can extend into trailing CRC bytes) |
| Monero | `4` | `addr[1..]` |

## Memory & Secrets

- Solana / EVM / Bitcoin: secret hex is computed only on a successful match (`encode_secret` not in hot loop). Internal zeroize is whatever `ed25519-dalek` / `libsecp256k1` provide.
- Monero: `MoneroKeypair: Clone + Zeroize + ZeroizeOnDrop`. Discarded candidates have their `spend_sec` and `view_sec` wiped on drop.
- CSV file: created `chmod 0600`; permissions reasserted on every open.
- `OsRng` is the entropy source for Monero scalars; BIP-39 phrases come from `tiny-bip39`'s `Mnemonic::new` (uses OS CSPRNG).

## Test Vectors (pinned)

| Test | What it pins |
|------|--------------|
| `seed::derive_seed_matches_bip39_vector` | BIP-39 "abandon...about" → canonical 64-byte seed |
| `slip10::slip10_ed25519_test_vector_{1,2}` | SLIP-0010 spec vectors |
| `solana::solana_phantom_derivation_from_canonical_phrase` | Phantom-importable address for canonical phrase |
| `bitcoin::bip84_canonical_vector` | BIP-84 spec vector → `bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu` |
| `evm::eip55_canonical_vector`, `eip55_second_vector` | EIP-55 spec examples |
| `ton::ton_tonkeeper_round_trip_vector` | Full pipeline matches Tonkeeper's W5 address for a known phrase |
| `ton_cell::wallet_v5r1_matches_tonkeeper_vector` | W5 state_init hash matches base64-decoded Tonkeeper address |
| `monero::keccak256_empty_vector` | Confirms original Keccak (not FIPS-202) |
| `monero::monero_seed_phrase_*` | 25-word phrase format + determinism |
