# Seed Phrase Alignment Plan

**Date:** 2026-04-13
**Parent plan:** `2026-04-13-multichain-addy.md`
**Goal:** Make Solana, TON, and Monero produce seed phrases that import into their native wallets (Phantom, Tonkeeper, Monero CLI).

## Scope

Three independent chain-level changes:

1. **Monero** — Emit 25-word Electrum-style mnemonic (currently empty)
2. **Solana** — Switch from "first 32 bytes of seed" to SLIP-0010 Ed25519 at `m/44'/501'/0'/0'` (Phantom-compatible)
3. **TON** — Switch from BIP-39 12-word to TON's native 24-word scheme (Tonkeeper-compatible, with ~100× perf cost accepted)

All three are independent files. Execute serially to avoid bench-noise conflicts.

## Known Constraints

- **TON cost:** Native TON derivation does ~200,000 PBKDF2-SHA512 iters per wallet (vs. 2,048 currently). Per-attempt time rises from ~800µs to ~80ms. **Reduce `Ton::MAX_VANITY` from 6 → 4** to keep searches tractable.
- **Solana test vector:** The existing `solana_derivation_from_canonical_phrase` test will produce a DIFFERENT address after SLIP-0010 migration. Update the test to pin the new Phantom-compatible address.
- **Monero wordlist:** Embed the Monero English wordlist (1626 words) as a `&[&str; 1626]` const. Source: `monero-project/monero/src/mnemonics/english.h`.
- **Dep additions:** `crc32fast` (Monero checksum).

## Task 14: Monero 25-word mnemonic

**Files:**
- Create: `src/chains/monero_wordlist.rs` (1626-word const array)
- Modify: `src/chains/monero.rs` (add `monero_seed_phrase` fn, wire into `generate`)
- Modify: `Cargo.toml` (add `crc32fast = "1.4"`)

**Algorithm (Electrum-style):**
```
Input: spend_sec [u8; 32]
1. Split into 8 × u32 little-endian
2. For each u32 x:
     w1 = x mod 1626
     w2 = (x / 1626 + w1) mod 1626
     w3 = (x / 1626 / 1626 + w2) mod 1626
   Emit words[w1], words[w2], words[w3]  → 24 words total
3. Checksum: concatenate first 3 chars of each of 24 words;
   checksum_idx = CRC32(trimmed) mod 24
   Append words[checksum_idx] → 25 words
Output: 25 space-separated words
```

**Known vector test:**
- spend_sec = all zeros (`[0u8; 32]`) should produce a deterministic 25-word phrase; pin after first computation.
- Alternative: a real Monero CLI-generated test vector if one can be cross-verified.

## Task 15: Solana SLIP-0010 alignment

**Files:**
- Create: `src/slip10.rs` (SLIP-0010 Ed25519 derivation)
- Modify: `src/chains/solana.rs` (use SLIP-0010 instead of first-32-bytes-of-seed)
- Modify: `src/main.rs` (add `pub mod slip10;`)

**Algorithm (SLIP-0010 Ed25519):**
```
Input: seed [u8; 64], path [u32; N] (ALL indices must be hardened ≥ 0x80000000)

1. Master: HMAC-SHA512(key=b"ed25519 seed", msg=seed)
     key   = master[..32]
     chain = master[32..]

2. For each index in path:
     data = 0x00 || key || index_be_bytes  (37 bytes)
     result = HMAC-SHA512(key=chain, msg=data)
     key   = result[..32]
     chain = result[32..]

Output: final key [u8; 32] → Ed25519 seed
```

**Phantom path:** `m/44'/501'/0'/0'` → `[0x8000002C, 0x800001F5, 0x80000000, 0x80000000]`

**Update test:** Replace the loose "check base58 format" test with a pinned Phantom-compatible address derived from the canonical "abandon...about" phrase. Cross-verify with Phantom extension or Solana CLI.

## Task 16: TON native mnemonic

**Files:**
- Create: `src/chains/ton_mnemonic.rs` (TON 24-word generation + seed derivation)
- Modify: `src/chains/ton.rs` (replace BIP-39 with TON native scheme, reduce MAX_VANITY)

**Algorithm (per tonweb-mnemonic):**
```
generate_ton_wallet():
  loop:
    1. Pick 24 random BIP-39 English words (use tiny-bip39's wordlist directly; OsRng)
    2. phrase = words.join(" ")
    3. entropy = HMAC-SHA512(key=b"", msg=phrase)  // 64 bytes
    4. basic_seed = PBKDF2-HMAC-SHA512(
           password=entropy, salt=b"TON seed version",
           iter=390,         // ~= 100000 / 256
           out=64 bytes)
    5. if basic_seed[0] != 0x00: continue  // ~1/256 acceptance rate
    6. seed = PBKDF2-HMAC-SHA512(
           password=entropy, salt=b"TON default seed",
           iter=100000,
           out=32 bytes)
    7. return (phrase, seed)  // seed is Ed25519 seed → SigningKey
```

**Skip the `isPasswordNeeded` check.** That's a separate filter for password-protected wallets; we're not using a password.

**Perf impact:** ~100× slower TON generation. Reflect in:
- `Ton::MAX_VANITY: usize = 4` (down from 6)
- Help popup note: "TON native mnemonic is slow (~100× slower than other chains)"

**Test:**
- Round-trip test: generate a TON wallet, verify phrase regenerates the same seed when fed back through `mnemonic_to_seed(phrase)`.
- Format test: phrase has exactly 24 words, all from BIP-39 wordlist.

## Perf Gates

All three changes affect their own chain's generation throughput only. EVM and Bitcoin are not touched. The existing gate applies:
- EVM and Solana (after SLIP-0010) within ±5% of post-Task-13 baseline, OR
- Criterion reports "no change" / improvement

Note: Solana perf will genuinely change by ~5-10% due to SLIP-0010's HMAC rounds. That's within tolerance.

## Out of Scope

- Tonkeeper's `isPasswordNeeded` check (password-protected wallets)
- Monero subaddresses, integrated addresses, or view-only keys
- Solana paths other than Phantom's default (`m/44'/501'/0'/0'`)
- BIP-39 passphrase support

## Commits

Three commits, one per task:
- `feat(monero): emit 25-word Electrum-style seed phrase`
- `feat(solana): align derivation to Phantom SLIP-0010`
- `feat(ton): switch to native 24-word mnemonic scheme`
