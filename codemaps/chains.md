> Generated: 2026-10-19 | Token-lean format for LLM context

# Chains

`Chain` trait (`src/chains/mod.rs:25`) is the per-chain contract. `ChainKind` (`mod.rs:50`) is the runtime enum. `ChainKind::search` (`mod.rs:90`) matches once per Rayon thread (`app.rs` `chain.search(.., gpu_rx.as_ref(), &health)`): EVM → `search_hybrid`; the other four → `search::<C>` and ignore both GPU args. No `dyn`.

## `Chain` Trait

```rust
pub trait Chain: Send + Sync + 'static {
    const LABEL: &'static str;
    const CHARSET: &'static str;
    const MAX_VANITY: usize;
    const BATCH: usize = 1;                      // candidates per generate_batch
    type AddressBytes: AsRef<[u8]>;
    type SecretRaw;
    fn generate() -> (Self::AddressBytes, Self::SecretRaw, String);
    fn generate_batch(mut emit: impl FnMut(Self::AddressBytes, Self::SecretRaw, String)) { /* one generate() */ }
    fn encode_address(bytes: &Self::AddressBytes) -> String;
    fn encode_secret(raw: &Self::SecretRaw) -> String;
    fn matches_raw(matcher: &Matcher, bytes: &Self::AddressBytes) -> bool;
}
```

`ChainKind { Solana, Evm, Bitcoin, Ton, Monero }` (`Clone, Copy, PartialEq`): `label()`, `charset()`, `max_vanity()` forward the consts; `search(self, matcher, stop, counter, tx, gpu: Option<&GpuRx>, health: &GpuHealth)`.

`Match` (`mod.rs:18`), the `mpsc` payload, no derives: `pub struct Match { pub chain, pub address, pub secret_hex, pub mnemonic: String }`.

## Per-Chain Summary

| Chain | LABEL | CHARSET | MAX | BATCH | AddressBytes | SecretRaw | Vanity skips |
|-------|-------|---------|-----|-------|--------------|-----------|--------------|
| Solana | "Solana" | Base58 (58) | 9 | `LANES` (4) | `[u8; 32]` pubkey | `ed25519_dalek::SigningKey` | none |
| EVM | "EVM" | `0-9a-fA-F` (22) | 8 | `LANES` (4) | `[u8; 20]` | `secp256k1::SecretKey` | none (`0x` display only) |
| Bitcoin | "Bitcoin" | Bech32 lowercase (32) | 8 | `LANES` (4) | `[u8; 20]` HASH160 | `secp256k1::SecretKey` | `bc1q` (4) |
| TON | "TON" | Base64url (64) | 4 | `LANES` (4) | `[u8; 36]` | `ed25519_dalek::SigningKey` | `UQ` (2) |
| Monero | "Monero" | Base58 (58) | 4 | 1 (default) | `[u8; 65]` | `MoneroKeypair` | `4` (1) |

Prefix is matched after the skip (`addr.get(N..).unwrap_or("")`); suffix is matched on the full encoded address.

## Batch Pattern (Solana / EVM / Bitcoin)

Private `from_seed(&[u8; 64])` (`solana.rs:13`, `evm.rs:35` `pub(crate)`, `bitcoin.rs:76`) is the shared tail:

```
generate()       = Mnemonic::new(Words12, English) → seed::derive_seed (ring) → from_seed
generate_batch() = [Mnemonic; LANES]              → seed::derive_seeds (4-lane)  → from_seed ×4 → emit
```

`assert_batch_matches_single_path::<C, _>(from_seed)` (`mod.rs:247`, test) re-derives each emitted candidate via `derive_seed` (address + `encode_secret` must agree), checks `BATCH == LANES`, and `dedup` (adjacent-only) leaves `LANES` addresses. TON batches via `ton_mnemonic::generate_ton_wallets()`. Monero keeps the default `generate_batch`.

## Matcher — `src/matcher.rs`

```rust
pub struct Matcher {                                   // all pub(crate)
    prefix: String, suffix: String, case_sensitive: bool,
    evm_prefix: Option<(Vec<u8>, Option<u8>)>,         // full bytes + trailing high nibble
    evm_suffix: Option<(Vec<u8>, Option<u8>)>,         // full bytes + leading low nibble
    bech32_prefix_5bit: Option<Vec<u8>>,               // Bitcoin::CHARSET index per prefix char
}
pub enum MatchPosition { StartsWith, EndsWith, StartsAndEndsWith }   // UI state only
```

| Item | Detail |
|------|--------|
| `Matcher::new(prefix, suffix, case_sensitive, ChainKind)` | precomputes `evm_*` only for `Evm` + non-empty; `bech32_prefix_5bit` only for `Bitcoin` + non-empty prefix (`expect("validated in TUI")`) |
| `hex_prefix_to_bytes` / `hex_suffix_to_bytes` | `"dea"` → `([0xde], Some(0x0a))` / `"def"` → `([0xef], Some(0x0d))` |
| `prefix_matches(&str)` / `suffix_matches(&str)` | allocation-free; empty → `true`; shorter than pattern → `false`; `eq_ignore_ascii_case` unless `case_sensitive` |
| `matches_evm_raw(&[u8; 20])` | byte `starts_with` + high nibble of next byte; suffix bytes + low nibble of preceding byte |

## Match Logic Pattern

| Chain | `matches_raw` encode | Prefix target | Suffix target |
|-------|----------------------|---------------|---------------|
| Solana | `bs58::encode().into(&mut [u8; 44])` (stack) | full addr | full addr |
| EVM | none: `matches_evm_raw`; case-sensitive adds `eip55_encode` → `[u8; 40]` | raw bytes / EIP-55 str | raw bytes / EIP-55 str |
| Bitcoin | `expand_5bit` early-reject, then `bech32::encode_to_fmt` into stack `AddrBuf` (`[u8; 64]`) | `&addr[4..]` | full addr |
| TON | `URL_SAFE_NO_PAD.encode_slice` into `[u8; 48]` | `&encoded[2..]` | full encoded |
| Monero | `encode_address_into` → `[u8; 95]` | `&addr[1..]` | full addr |

EVM case-sensitive: after the byte filter passes, runs `prefix_matches` / `suffix_matches` against the 40-char EIP-55 form (no `0x`). `eip55_encode` is stack-only: `hex::encode_to_slice` into `[u8; 40]`, Keccak of that, uppercase in place.

Bitcoin: `expand_5bit` (`[u8; 32]`, no `Vec`) vs `bech32_prefix_5bit` rejects before the encode. A suffix-only search still encodes. `encode_address` (CSV / display) uses heap `bech32::encode`.

## Solana — `chains/solana.rs`

| Step | Detail |
|------|--------|
| Derivation | `slip10_derive_ed25519` at `PHANTOM_SOLANA_PATH` = m/44'/501'/0'/0' `[0x8000002C, 0x800001F5, 0x80000000, 0x80000000]` |
| Address | 32-byte Ed25519 pubkey, `bs58` |
| Secret | 64-byte hex: secret (32) \|\| pubkey (32) |
| Crates | `ed25519-dalek`, `bs58`, `hex` |
| Pinned | `CANONICAL_PHRASE` → `HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk` |

## EVM — `chains/evm.rs`

| Step | Detail |
|------|--------|
| Derivation | `bip32_derive_secp256k1` at `EVM_PATH` = m/44'/60'/0'/0/0 `[0x8000002C, 0x8000003C, 0x80000000, 0, 0]` |
| Address | `Keccak256(uncompressed_pubkey[1..])[12..]` → 20 bytes; display `format!("0x{}", hex)` lowercase |
| Secret | 32-byte hex |
| Crates | `secp256k1` (global ctx), `sha3::Keccak256`, `hex` |
| Pinned | EIP-55 `5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed`, `fB6916095ca1df60bB79Ce92cE3Ea74c37c5d359`; BIP-44 → `0x9858EfFD232B4033E47d90003D41EC34EcaEda94` |

`eip55_encode` (`evm.rs:15`): uppercase a hex letter when the matching nibble of `Keccak256(lowercase_hex)` ≥ 8. `Evm::verify(address, secret_hex, phrase)` (`evm.rs:51`) is `#[cfg(test)]`: re-derive via `derive_seed` (ring), compare encoded address + secret; bad phrase → `false`.

## Bitcoin — `chains/bitcoin.rs`

| Step | Detail |
|------|--------|
| Derivation | `bip32_derive_secp256k1` at `BTC_BIP84_PATH` = m/84'/0'/0'/0/0 `[0x80000054, 0x80000000, 0x80000000, 0, 0]` |
| Address | `hash160` = RIPEMD160(SHA256(33-byte compressed pubkey)) |
| Encoding | Bech32 P2WPKH, hrp `bc`, witness v0 → `bc1q…` (42 chars) |
| Secret | 32-byte hex |
| Crates | `ring::digest::SHA256`, `ripemd::Ripemd160`, `bech32` 0.9, `secp256k1` |
| Pinned | `CANONICAL_PHRASE` → `bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu`; `matches_raw_agrees_with_encode_address_for_one_char_prefix_and_suffix` + `expand_5bit_matches_bech32_to_base32` pin the stack path vs the crate |

## TON — `chains/ton.rs`, `ton_mnemonic.rs`, `ton_cell.rs`

| Step | Detail |
|------|--------|
| Mnemonic | TON-native 24 words (`Mnemonic::new(Words24)` for word sampling only; BIP-39 checksum irrelevant) |
| Entropy | `HMAC-SHA512(key = phrase, msg = "")` (`ring::hmac`) |
| Filter | `pbkdf2(entropy, "TON seed version", PBKDF2_BASIC_ITER = 390)[0] == 0` (~1/256) |
| Key | `pbkdf2(entropy, "TON default seed", PBKDF2_SEED_ITER = 100_000)[..32]` → `SigningKey` |
| Address | `0x51` (UQ, non-bounceable) \|\| `0x00` workchain \|\| W5 account_id (32) \|\| `crc16_xmodem` BE (2) |
| Encoding | `base64` `URL_SAFE_NO_PAD` → 48 chars starting `UQ` |
| Secret | 32-byte hex (`SigningKey::to_bytes`) |
| Crates | `ring` (HMAC, SHA-256), `pbkdf2_lanes`, `base64` 0.22, `ed25519-dalek`; CRC16 hand-rolled (poly `0x1021`) |
| Pinned | `cloth orbit … tube` → `UQAkFCMtkN0Q1TNP6Gk9SqYWsBFc6Aglwckj6ES4AeBEzWja` |

| `ton_mnemonic` / `ton_cell` | Detail |
|-----------------------------|--------|
| `generate_ton_wallet()` | single path: loop until filter passes, then `mnemonic_to_signing_key` (`ring_pbkdf2_sha512`) |
| `generate_ton_wallets() -> [(String, SigningKey); LANES]` | phase 1: `LANES` trial phrases per `pbkdf2_hmac_sha512::<LANES>(.., 390)` until `LANES` pass (extras dropped); phase 2: one 4-lane 100k PBKDF2 |
| `mnemonic_to_signing_key(&str)` | ring 100k PBKDF2 from phrase; single-path tail and test re-derivation |
| `ton_cell` scope | W5 (wallet-v5r1) only; ring SHA-256 TVM representation hashes; no BOC parsing |
| `WALLET_V5R1_CODE_HASH` | `20834b7b…52d2b72f`, code max_depth 6 |
| `W5_MAINNET_WALLET_ID` | `0x7FFF_FF11` (i32) |
| `wallet_v5r1_data_hash` | 322 bits, 0 refs, bits_desc 81: sig_allowed=1 \|\| seqno u32=0 \|\| wallet_id \|\| pubkey \|\| empty ext dict; zero-pubkey pin `0f80a4e3…be84cf31` |
| `wallet_v5r1_state_init_hash` (pub) | refs_desc 2, bits_desc 1, data `0b0011_0100`, depths 6/0, code hash, data hash → account_id; pin `2414232d…01e044cd` |

## Monero — `chains/monero.rs`

| Step | Detail |
|------|--------|
| Keys | `spend_sec` = `OsRng` 32 bytes mod l; `view_sec` = `keccak256(spend_sec)` mod l; pubs = scalar × `ED25519_BASEPOINT_TABLE` |
| Keccak | `sha3::Keccak256` (original Keccak, not FIPS-202 SHA3-256) |
| Address | 65 = `NETWORK_BYTE_MAINNET` `0x12` \|\| spend_pub \|\| view_pub; + `keccak256[..4]` → 69 bytes → 95-char Base58 starting `4` |
| Base58 | 8-byte blocks → `BLOCK_SIZES = [0, 2, 3, 5, 6, 7, 9, 10, 11]` chars; `monero_base58_encode_into` writes a caller buffer |
| Mnemonic | `monero_seed_phrase`: 8 LE u32 chunks × 3 words over `MONERO_WORDLIST` (`&[&str; 1626]`), + checksum word `words[crc32(first 3 chars each) % 24]` = 25 words; built from word indices (`Vec<usize>`) into a pre-sized `String` |
| Secret | `"{spend_hex}:{view_hex}"` |
| Crates | `curve25519-dalek`, `rand::OsRng`, `sha3`, `crc32fast`, `zeroize` |
| Zeroize | `MoneroKeypair { spend_sec, view_sec }: Zeroize + ZeroizeOnDrop`; `generate_keys` wipes `spend_raw`, `view_raw` and both `Scalar`s; `monero_seed_phrase` wipes word indices and `trimmed` |
| Test-only | `monero_base58_encode` heap wrapper; pins `keccak256("")` = `c5d24601…5d85a470`, `[0xff; 8]` → `jpXCZedGfVQ`; seed phrase pinned on all-zero and `0..32` keys (self-captured); `monero_generate_keys_are_consistent` (view = H(spend), pubs = secret·G) |

## Hot Loop

`search_cpu_step::<C>` (`mod.rs:113`, `#[inline(always)]`) is the one CPU body:

```rust
C::generate_batch(|addr, secret, mut phrase| {
    if C::matches_raw(matcher, &addr) {
        let _ = tx.send(Match { chain: C::LABEL.to_string(), address: C::encode_address(&addr),
                                secret_hex: C::encode_secret(&secret), mnemonic: phrase });
    } else {
        phrase.zeroize();                  // non-match: wipe the whole wallet
    }
});
counter.fetch_add(C::BATCH as u64, Relaxed);
```

`search::<C>` (`mod.rs:130`): `while !stop { search_cpu_step::<C>() }`. Modules: pub `bitcoin evm monero solana ton`; private `monero_wordlist ton_cell ton_mnemonic`.

## EVM GPU Path — `mod.rs`, `src/verify.rs`

```
search_hybrid (mod.rs:150), loop until stop:
  gpu Some && !health.disable && rx.try_recv() = Ok(Box<SeedBlock>)
      → drain_gpu_block; continue            (SeedBlock: ZeroizeOnDrop)
  else → search_cpu_step::<Evm>              (non-blocking, self-balancing)

drain_gpu_block (mod.rs:171):
  for chunk in block.chunks(Evm::BATCH * GPU_CHUNK_BATCHES)   // 4 × 16 = 64
      if stop → return                       (unfinished chunks not counted)
      for cand: (addr, _) = Evm::from_seed(&cand.seed)        // UNTRUSTED, filter only
                if Evm::matches_raw → emit_gpu_match(tx, &cand.entropy, &addr, health)
      counter += chunk.len(); health.seeds_delivered += chunk.len()

emit_gpu_match (mod.rs:198):
  verify::verify_gpu(entropy, gpu_addr)
    Some((addr, secret, phrase)) → send Match built from CPU-derived values
    None → health.raise(GpuDisableReason::VerifyMismatch { address: encode(gpu_addr) }); drop candidate
```

`verify_gpu(entropy: &[u8; 16], gpu_addr: &[u8; 20]) -> Option<([u8; 20], secp256k1::SecretKey, String)>` (`verify.rs:16`): `Mnemonic::from_entropy(..).ok()?` → `seed::derive_seed` (ring, never lanes/GPU) → `Evm::from_seed` → `None` unless `addr == *gpu_addr`; phrase rebuilt by CPU. Every failure is `None`; there is no "unverifiable" pass. `GpuCandidate { entropy: [u8; 16], seed: [u8; 64] }`, `GpuRx = crossbeam_channel::Receiver<Box<SeedBlock>>`.
