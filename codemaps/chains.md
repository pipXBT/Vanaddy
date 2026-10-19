> Generated: 2026-10-19 | Token-lean format for LLM context | Source: update-codemaps

# Chains

The `Chain` trait (`src/chains/mod.rs:31`) is the per-chain contract. `ChainKind` (`mod.rs:75`) is the runtime enum. `ChainKind::search` (`mod.rs:115`) matches once at thread spawn: EVM goes to `search_hybrid::<Evm>`; the other four call `search::<C>` and ignore the GPU arguments. No `dyn`.

## `Chain` Trait

```rust
pub trait Chain: Send + Sync + 'static {
    const LABEL: &'static str;
    const CHARSET: &'static str;
    const MAX_VANITY: usize;
    const BATCH: usize = 1;
    type AddressBytes: AsRef<[u8]>;
    type SecretRaw;
    fn generate() -> (Self::AddressBytes, Self::SecretRaw, String);
    fn generate_batch(mut emit: impl FnMut(...)) { /* one generate() */ }
    fn encode_address(bytes: &Self::AddressBytes) -> String;
    fn encode_secret(raw: &Self::SecretRaw) -> String;
    fn matches_raw(matcher: &Matcher, bytes: &Self::AddressBytes) -> bool;
}
```

`Bip39GpuChain` (`mod.rs:65`): `from_gpu_seed(&[u8; 64])` and `verify(address, secret_hex, phrase) -> bool`. Only `Evm` implements it. Solana and Bitcoin already have a private `from_seed` of that shape; TON (own mnemonic) and Monero (no BIP-39) cannot.

`Match` (`mod.rs:16`) is the channel payload:

```rust
pub struct Match { chain, address, secret_hex, mnemonic: String, verified: Verified }
```

`verified` is `Verified::cpu_reference()` on the CPU path and `Verified::gpu_reverified()` after `verify_gpu`. Not `Clone`.

## Per-Chain Summary

| Chain | LABEL | CHARSET | MAX | BATCH | AddressBytes | SecretRaw | Vanity skips |
|-------|-------|---------|-----|-------|--------------|-----------|--------------|
| Solana | "Solana" | Base58 (58) | 9 | 4 | `[u8; 32]` | `SigningKey` | none |
| EVM | "EVM" | hex | 8 | 4 | `[u8; 20]` | `SecretKey` | `0x` display only |
| Bitcoin | "Bitcoin" | Bech32 (32) | 8 | 4 | `[u8; 20]` HASH160 | `SecretKey` | `bc1q` (4 chars) |
| TON | "TON" | Base64url (64) | 4 | 4 | `[u8; 36]` | `SigningKey` | `UQ` (2 chars) |
| Monero | "Monero" | Base58 (58) | 4 | 1 | `[u8; 65]` | `MoneroKeypair` | `4` (1 char) |

Bitcoin vanity skips `bc1q`. TON vanity skips `UQ`. Monero vanity skips `4`. Suffix checks use the full encoded address, including that fixed prefix.

## Batch Pattern (Solana / EVM / Bitcoin)

Private `from_seed(&[u8; 64])` (`solana.rs:13`, `evm.rs:36`, `bitcoin.rs:76`) is shared by `generate` (`derive_seed` / ring) and `generate_batch` (`derive_seeds` / 4 lanes). `Evm::from_gpu_seed` is `from_seed`. `generate_batch_emits_lane_count_candidates_matching_single_path` re-derives each emitted candidate through the single path.

TON batch is `generate_ton_wallets()` (filter, then one 4-lane 100k PBKDF2). Monero uses the default `generate_batch` (`BATCH = 1`).

## Match Logic Pattern

`prefix_matches` / `suffix_matches` stay allocation-free byte compares (`eq_ignore_ascii_case` when case-insensitive). What changed is the encode in front of them:

| Chain | `matches_raw` encode | Prefix target | Suffix target |
|-------|----------------------|---------------|---------------|
| Solana | `bs58::encode().into_string()` (heap) | full addr | full addr |
| EVM | no string; `matches_evm_raw` on `[u8; 20]` | raw bytes from index 0 | raw bytes |
| Bitcoin | `expand_5bit` early-reject, then `encode_to_fmt` into stack `AddrBuf` (`[u8; 64]`) | `&addr[4..]` | full addr |
| TON | `URL_SAFE_NO_PAD.encode_slice` into `[u8; 48]` | `&encoded[2..]` | full encoded |
| Monero | `encode_address_into` → `[u8; 95]` | `&addr[1..]` | full addr |

Bitcoin vanity skips `bc1q`. TON vanity skips `UQ`. Monero vanity skips `4`. Empty prefix/suffix is a pass. A too-short address yields `""` and fails a non-empty prefix.

EVM case-sensitive mode, after the byte filter, builds `eip55_encode` → `[u8; 40]` and compares the user's exact prefix/suffix. It does not call `prefix_matches` / `suffix_matches`. `eip55_encode` still `hex::encode`s the lowercase form (one heap string) before the stack checksum.

Bitcoin's 5-bit fast path compares `expand_5bit` (`[u8; 32]`, no `Vec`) to `Matcher::bech32_prefix_5bit` and returns before the stack encode on a prefix miss. A suffix-only search still encodes. `encode_address` (match display / CSV) still uses `bech32::encode` and allocates; only `matches_raw` is stack.

## Solana — `chains/solana.rs`

| Step | Detail |
|------|--------|
| Mnemonic | BIP-39 12-word English |
| Derivation | `slip10_derive_ed25519` at `PHANTOM_SOLANA_PATH` (all hardened) |
| Address | 32-byte pubkey, Base58 |
| Secret | 64-byte hex: secret (32) \|\| pubkey (32) |
| Match | heap Base58, then prefix and suffix on the full string |
| Pinned | "abandon...about" → `HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk` |

## EVM — `chains/evm.rs`

| Step | Detail |
|------|--------|
| Derivation | `bip32_derive_secp256k1` at `EVM_PATH` = m/44'/60'/0'/0/0 |
| Address | `Keccak256(uncompressed[1..])[12..]` → 20 bytes, display `0x` + hex |
| Secret | 32-byte hex |
| Fast-path | `Matcher::matches_evm_raw` (full bytes + odd nibble) |
| GPU | `from_gpu_seed` = `from_seed`. `verify` re-derives with `derive_seed` (ring) and compares encoded address + secret |
| Pinned | EIP-55 `5aAeb6053F3E94...`, `fB6916095ca1df...`; BIP-44 → `0x9858EfFD232B4033E47d90003D41EC34EcaEda94` |

`eip55_encode` (`evm.rs:15`): uppercase a hex letter when the matching nibble of `Keccak256(lowercase)` is ≥ 8.

## Bitcoin — `chains/bitcoin.rs`

| Step | Detail |
|------|--------|
| Derivation | `bip32_derive_secp256k1` at `BTC_BIP84_PATH` = m/84'/0'/0'/0/0 |
| Address | HASH160 of the 33-byte compressed pubkey |
| Encoding | Bech32 P2WPKH, hrp `bc`, witness version 0 → `bc1q...` (42 chars) |
| Secret | 32-byte hex |
| Match | Bitcoin vanity skips `bc1q`. Stack `AddrBuf` + `encode_to_fmt`. Prefix on `&addr[4..]`, suffix on the full address |
| Pinned | "abandon...about" → `bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu` |

`matches_raw_agrees_with_encode_address_for_one_char_prefix_and_suffix` pins the stack path against `encode_address`.

## TON — `chains/ton.rs`, `ton_cell.rs`, `ton_mnemonic.rs`

| Step | Detail |
|------|--------|
| Mnemonic | TON-native 24-word (BIP-39 wordlist, not BIP-39 derivation) |
| Entropy | `HMAC-SHA512(key=phrase, msg="")` |
| Filter | `pbkdf2(entropy, "TON seed version", 390, 64)[0] == 0` (~1/256) |
| Seed | `pbkdf2(entropy, "TON default seed", 100_000, 32)` |
| Address | tag `0x51` (UQ) \|\| workchain `0x00` \|\| W5 account_id (32) \|\| crc16-xmodem (2) |
| Encoding | URL-safe base64, no pad, 48 chars, starts with `UQ` |
| Match | TON vanity skips `UQ`. `user_friendly_ascii` writes `[u8; 48]`. Prefix on `&encoded[2..]`, suffix on the full string |
| Pinned | known phrase → `UQAkFCMtkN0Q1TNP6Gk9SqYWsBFc6Aglwckj6ES4AeBEzWja` |

`WALLET_V5R1_CODE.max_depth` = 6, hash `20834b7b...52d2b72f`. `W5_MAINNET_WALLET_ID` = `0x7FFF_FF11`. Data cell is 322 bits: sig-allowed, seqno 0, wallet_id, pubkey, empty extensions dict. v3r2 helpers are `#[cfg(test)]` only.

## Monero — `chains/monero.rs`

| Step | Detail |
|------|--------|
| Mnemonic | 25-word Electrum (not BIP-39). `MONERO_WORDLIST` is 1626 words |
| Keys | `spend_sec` random mod l; `view_sec` = keccak256(spend) mod l |
| Keccak | `tiny_keccak::Keccak::v256`, not FIPS-202 SHA3-256 |
| Address | 65 = `0x12` \|\| spend_pub \|\| view_pub; +4 checksum → 95-char Base58 starting with `4` |
| Secret | `"{spend_hex}:{view_hex}"` |
| Match | Monero vanity skips `4`. `encode_address_into` writes `[u8; 95]`. Prefix on `&addr[1..]`, suffix on the full address |
| Zeroize | `MoneroKeypair: Zeroize + ZeroizeOnDrop` |

`monero_base58_encode` (CSV / tests) heap-wraps the same `monero_base58_encode_into` the hot path uses. 8-byte blocks → 11 chars (`BLOCK_SIZES`).

## Hot Loop

`search_cpu_step` (`mod.rs:137`) is the one CPU body:

```rust
C::generate_batch(|addr, secret, phrase| {
    if C::matches_raw(matcher, &addr) {
        tx.send(Match { ..., verified: Verified::cpu_reference() });
    }
});
counter.fetch_add(C::BATCH);
```

`search` loops that until `stop`. `search_hybrid` (`mod.rs:173`) `try_recv`s a `SeedBlock` first. `drain_gpu_block` checks `stop` every `GPU_CHUNK_BATCHES` (16) batches, calls `from_gpu_seed` only to filter, and on a hit `verify_gpu`s from the 16-byte entropy. Agreement sends the CPU-derived row with `gpu_reverified()`. Disagreement raises `VerifyMismatch` and drops the candidate. The GPU seed is never a CSV field. A verified hit encodes the CPU address and secret. A mismatch still `encode_address`es the GPU bytes into `VerifyMismatch`, then drops the candidate.
