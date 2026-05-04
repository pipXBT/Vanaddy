> Generated: 2026-05-05 | Token-lean format for LLM context

# Chains

The `Chain` trait (`src/chains/mod.rs:18`) is the per-chain contract. `ChainKind` is the runtime enum picked by the user; its `search()` method (`mod.rs:71`) dispatches once at thread-spawn into the monomorphized `search::<C: Chain>` hot loop (`mod.rs:88`).

## `Chain` Trait

```rust
pub trait Chain: Send + Sync + 'static {
    const LABEL: &'static str;          // "Solana", "EVM", ...
    const CHARSET: &'static str;        // valid vanity chars for this chain
    const MAX_VANITY: usize;            // upper bound on prefix/suffix length

    type AddressBytes: AsRef<[u8]>;
    type SecretRaw;

    fn generate() -> (Self::AddressBytes, Self::SecretRaw, String);
    fn encode_address(bytes: &Self::AddressBytes) -> String;
    fn encode_secret(raw: &Self::SecretRaw) -> String;
    fn matches_raw(matcher: &Matcher, bytes: &Self::AddressBytes) -> bool;
}
```

`MatchPayload = (String, String, String, String)` = `(label, address, secret_hex, mnemonic)`.

## Per-Chain Summary

| Chain | LABEL | CHARSET | MAX_VANITY | AddressBytes | SecretRaw | Vanity skips |
|-------|-------|---------|-----------|--------------|-----------|--------------|
| Solana | "Solana" | Base58 (58) | 9 | `[u8; 32]` | `ed25519_dalek::SigningKey` | none |
| EVM | "EVM" | hex (0-9, a-f, A-F) | 8 | `[u8; 20]` | `libsecp256k1::SecretKey` | `0x` (encoded), 0 raw |
| Bitcoin | "Bitcoin" | Bech32 (32) | 8 | `[u8; 20]` (HASH160) | `libsecp256k1::SecretKey` | `bc1q` (4 chars) |
| TON | "TON" | Base64url (64) | 4 | `[u8; 36]` | `ed25519_dalek::SigningKey` | `UQ` (2 chars) |
| Monero | "Monero" | Base58 (58) | 4 | `[u8; 65]` | `MoneroKeypair` (zeroized) | `4` (1 char) |

## Solana — `chains/solana.rs`

| Step | Detail |
|------|--------|
| Mnemonic | BIP-39 12-word English (`Mnemonic::new(Words12)`) |
| Seed | `seed::derive_seed` → PBKDF2-HMAC-SHA512 × 2048 |
| Derivation | `slip10_derive_ed25519` at `PHANTOM_SOLANA_PATH = m/44'/501'/0'/0'` (all hardened) |
| Address | 32-byte ed25519 pubkey, Base58-encoded |
| Secret format | 64-byte hex: `secret_key (32) || public_key (32)` (Phantom keypair format) |
| Match | Always full Base58 encode; case-insensitive uses `eq_ignore_ascii_case` over byte slices |
| Pinned | "abandon...about" → `HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk` |

## EVM — `chains/evm.rs`

| Step | Detail |
|------|--------|
| Mnemonic | BIP-39 12-word English |
| Derivation | `bip32_derive_secp256k1` at `EVM_PATH = m/44'/60'/0'/0/0` |
| Address | `Keccak256(uncompressed_pubkey[1..])[12..]` → 20 bytes, displayed as `0x` + hex |
| Secret format | 32-byte hex (raw secp256k1 scalar) |
| Fast-path | `Matcher::matches_evm_raw` checks `evm_prefix`/`evm_suffix` byte tuples (full bytes + odd nibble) |
| Case-sensitive | Computes `eip55_encode(addr) → [u8; 40]` then compares prefix/suffix chars (mixed case) |
| Pinned | EIP-55 spec vectors `5aAeb6053F3E94...` and `fB6916095ca1df...` |

`eip55_encode` (line 14) hashes the lowercase hex form, then uppercases hex letters whose corresponding nibble of `Keccak256(lower)` is ≥ 8.

## Bitcoin — `chains/bitcoin.rs`

| Step | Detail |
|------|--------|
| Mnemonic | BIP-39 12-word English |
| Derivation | `bip32_derive_secp256k1` at `BTC_BIP84_PATH = m/84'/0'/0'/0/0` |
| Address | HASH160 (`Ripemd160(Sha256(compressed_pubkey))`) → 20 bytes |
| Encoding | Bech32 P2WPKH: hrp=`bc`, witness version 0, program=HASH160 → `bc1q...` |
| Secret format | 32-byte hex |
| Fast-path | `expand_5bit(bytes) → [u8; 32]` (stack-buffer 5-bit groups) compared to `Matcher::bech32_prefix_5bit` before string encode |
| Suffix match | Falls back to full encode + ASCII compare |
| Vanity skips | First 4 chars `bc1q` are fixed; user's prefix applies to `addr[4..]` |
| Pinned | "abandon...about" at m/84'/0'/0'/0/0 → `bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu` |

`expand_5bit` is a hand-rolled bits→u5 packer (no Vec); cross-checked against `bytes.to_base32()` in tests.

## TON — `chains/ton.rs`, `ton_cell.rs`, `ton_mnemonic.rs`

| Step | Detail |
|------|--------|
| Mnemonic | TON-native 24-word (BIP-39 wordlist, **non-BIP-39** derivation) |
| Acceptance | Loop until `pbkdf2(entropy, "TON seed version", 390, 64)[0] == 0` (~1/256) |
| Entropy | `HMAC-SHA512(key=phrase, msg="")` |
| Seed | `pbkdf2(entropy, "TON default seed", 100_000, 32)` |
| Address | 36 bytes: `tag(0x51 = UQ non-bounceable mainnet) \|\| workchain(0x00) \|\| account_id(32) \|\| crc16_xmodem(2)` |
| `account_id` | Representation hash of W5 (`wallet-v5r1`) StateInit cell |
| Encoding | URL-safe base64 (no pad) — always 48 chars, starts with `UQ` |
| Vanity skips | First 2 chars `UQ`; user's prefix applies to chars 3+ |
| Pinned | A 24-word phrase yields exact Tonkeeper-displayed `UQAkFCMtkN0Q1TNP6Gk9SqYWsBFc6Aglwckj6ES4AeBEzWja` |

Why slow: 100k PBKDF2 iters × ~256 retries × per-thread → ~50 ms/wallet, ~20/s/thread.

### W5 cell hashing (`ton_cell.rs`)

| Constant | Value |
|----------|-------|
| `WALLET_V5R1_CODE.hash` | `20834b7b...52d2b72f` (root cell of `@ton/ton` v5r1 BOC) |
| `WALLET_V5R1_CODE.max_depth` | 6 |
| `W5_MAINNET_WALLET_ID` | `0x7FFF_FF11` (= `global_id(-239) ^ context_id` for mainnet defaults) |
| `WALLET_V3R2_CODE.hash` | `84dafa44...75d2d599` (max_depth = 0) — kept for reference but not used in production |

`Cell::repr` = `refs_desc || bits_desc || augmented_data || for_each_ref(max_depth_be) || for_each_ref(hash)`. `Cell::hash` = `SHA-256(repr)`.

`wallet_v5r1_data_cell` packs **322 bits** MSB-first:
`is_signature_allowed(1=true)(1) || seqno(u32=0) || wallet_id(i32) || pubkey(u256) || extensions_dict(0=empty)(1)`.

## Monero — `chains/monero.rs`, `monero_wordlist.rs`

| Step | Detail |
|------|--------|
| Mnemonic | 25-word Electrum-style (24 from spend_sec + 1 checksum) — **not BIP-39** |
| Wordlist | `MONERO_WORDLIST: [&str; 1626]` |
| `spend_sec` | `Scalar::from_bytes_mod_order(OsRng.fill_bytes(32))` |
| `view_sec` | `Scalar::from_bytes_mod_order(Keccak256(spend_sec))` |
| Pubkeys | `spend_pub = spend_scalar · G`, `view_pub = view_scalar · G` (compressed Edwards) |
| Keccak | Original Keccak-256 (`tiny_keccak::Keccak::v256`), **not** FIPS-202 SHA3-256 |
| Address bytes | 65 = `network(0x12) \|\| spend_pub(32) \|\| view_pub(32)` |
| Encoding | Append 4-byte Keccak checksum → 69 bytes → Monero Base58 (8-byte blocks → 11 chars each) |
| Final | 95-char Base58 starting with `4` |
| Secret format | `"{spend_hex}:{view_hex}"` (importable via `monero-wallet-cli --generate-from-keys`) |
| Vanity skips | First char `4`; user's prefix applies from char 2 |
| Zeroize | `MoneroKeypair: Zeroize + ZeroizeOnDrop` — discarded candidates wiped |

`monero_seed_phrase` (line 55): for each of 8 little-endian u32 chunks, derive 3 wordlist indices via mod-1626 arithmetic; the 25th word is the first 3 chars of the 24 trimmed words CRC32-hashed mod 24.

## Hot Loop

`search::<C>` (`mod.rs:88`) is the only function that runs per-candidate:

```rust
while !stop.load(Relaxed) {
    let (addr_bytes, secret_raw, phrase) = C::generate();
    counter.fetch_add(1, Relaxed);
    if C::matches_raw(matcher, &addr_bytes) {
        let addr = C::encode_address(&addr_bytes);
        let secret_hex = C::encode_secret(&secret_raw);
        let _ = tx.send((C::LABEL.to_string(), addr, secret_hex, phrase));
    }
}
```

`encode_address` and `encode_secret` are only called on matches; the per-candidate cost is `generate()` + `matches_raw()`.
