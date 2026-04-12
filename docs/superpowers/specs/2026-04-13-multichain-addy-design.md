# Vanaddy Multi-Chain Refactor — Design

**Date:** 2026-04-13
**Status:** Approved
**Version target:** v0.6.0

## Goal

Add **Bitcoin** (Native SegWit / Bech32), **TON** (user-friendly Base64), and **Monero** (prefix-matched) to vanaddy, alongside the existing Solana and EVM support. Refactor the single-file `main.rs` (~1221 lines) into a modular per-chain structure that preserves the current EVM generation throughput.

## Non-Goals (YAGNI)

- Cargo feature flags for optional chains — linker dead-code elimination is sufficient
- Hardware wallet integration, QR export, passphrase support
- Custom derivation paths (only per-chain defaults)
- Case-insensitive matching for chains where case is cryptographically significant (Bech32 lowercase-only, Monero Base58 mixed)
- P2SH-SegWit (`3...`) and Legacy (`1...`) Bitcoin addresses — Bech32 only
- TON raw hex address format — user-friendly only
- Monero subaddresses, integrated addresses, or custom view/spend key schemes
- Support for more than one TON workchain or bounceable/non-bounceable toggle (default: bounceable mainnet)

## Architecture

### File layout

```
src/
├── main.rs              — entry point, terminal setup
├── app.rs               — App state, event handling
├── ui.rs                — ratatui rendering (banner, panels, help)
├── matcher.rs           — Matcher + MatchPosition (chain-agnostic)
├── seed.rs              — BIP-39 mnemonic + PBKDF2 seed derivation (shared)
├── bip32.rs             — BIP-32 secp256k1 derivation (shared by EVM + BTC)
└── chains/
    ├── mod.rs           — Chain trait + ChainKind enum (for TUI dispatch)
    ├── solana.rs
    ├── evm.rs
    ├── bitcoin.rs
    ├── ton.rs
    └── monero.rs
```

### Chain trait

```rust
pub trait Chain: Send + Sync + 'static {
    const LABEL: &'static str;
    const CHARSET: &'static str;
    const MAX_VANITY: usize;

    type AddressBytes: AsRef<[u8]>;

    fn generate() -> (Self::AddressBytes, SecretPayload, String);
    fn encode_address(bytes: &Self::AddressBytes) -> String;
    fn matches_raw(matcher: &Matcher, bytes: &Self::AddressBytes) -> bool;
}

pub fn search<C: Chain>(
    matcher: &Matcher,
    stop: &AtomicBool,
    counter: &AtomicU64,
    tx: &Sender<MatchPayload>,
) {
    while !stop.load(Ordering::Relaxed) {
        let (addr_bytes, secret, phrase) = C::generate();
        counter.fetch_add(1, Ordering::Relaxed);
        if C::matches_raw(matcher, &addr_bytes) {
            let addr = C::encode_address(&addr_bytes);
            let _ = tx.send((C::LABEL.to_string(), addr, secret.hex(), phrase));
        }
    }
}
```

### TUI dispatch

A `ChainKind` enum stays at the TUI layer for runtime selection. Dispatch happens **once** on search start:

```rust
enum ChainKind { Solana, Evm, Bitcoin, Ton, Monero }

impl ChainKind {
    fn charset(self) -> &'static str { /* match → C::CHARSET */ }
    fn max_vanity(self) -> usize { /* match → C::MAX_VANITY */ }
    fn spawn_search(self, matcher, stop, counter, tx) {
        match self {
            Self::Solana => search::<Solana>(matcher, stop, counter, tx),
            Self::Evm => search::<Evm>(matcher, stop, counter, tx),
            Self::Bitcoin => search::<Bitcoin>(matcher, stop, counter, tx),
            Self::Ton => search::<Ton>(matcher, stop, counter, tx),
            Self::Monero => search::<Monero>(matcher, stop, counter, tx),
        }
    }
}
```

The `match` is **outside** the hot loop — once per thread spawn. Inside the loop, `search::<C>` is fully monomorphized with zero dynamic dispatch.

## Per-Chain Specifications

### Solana (ported unchanged)

| Field | Value |
|-------|-------|
| Crypto | Ed25519, first 32 bytes of BIP-39 seed |
| Address | Base58(pubkey) |
| Charset | Base58 alphabet |
| Max vanity | 9 |
| Fast-path | Base58-decoded prefix bytes, starts-with only |

### EVM (ported unchanged)

| Field | Value |
|-------|-------|
| Crypto | secp256k1, BIP-32 path `m/44'/60'/0'/0/0` |
| Address | `0x` + last 20 bytes of Keccak256(uncompressed pubkey) |
| Charset | `0-9 a-f A-F` |
| Max vanity | 8 |
| Fast-path | Raw byte comparison with nibble handling for odd-length patterns |

### Bitcoin (new)

| Field | Value |
|-------|-------|
| Crypto | secp256k1, BIP-32 path `m/84'/0'/0'/0/0` (BIP-84) |
| Address | `bc1q` + Bech32(HASH160(compressed_pubkey)) where HASH160 = RIPEMD160(SHA256(pubkey)) |
| Charset | Bech32 alphabet `qpzry9x8gf2tvdw0s3jn54khce6mua7l` |
| Max vanity | 8 |
| Fast-path | Convert user's Bech32 prefix to 5-bit groups once at matcher creation; compare against 5-bit chunks of HASH160 before full Bech32 encoding |
| New deps | `ripemd` 0.1, `bech32` 0.9, `sha2` 0.10 |

### TON (new)

| Field | Value |
|-------|-------|
| Crypto | Ed25519 from first 32 bytes of BIP-39 seed (TON standard) |
| Address | User-friendly Base64url-encoded 36-byte payload: `tag (1)` + `workchain (1)` + `account_id (32)` + `crc16 (2)`. Defaults: tag `0x11` (bounceable), workchain `0x00` (mainnet). `account_id = SHA256(wallet-v4r2 state init with pubkey)` |
| Charset | Base64url `A-Z a-z 0-9 _ -` |
| Max vanity | 6 (matchable portion starts at position 3; first 2 chars are fixed `EQ`) |
| Fast-path | Pre-compute expected leading account_id bytes from user's vanity chars at matcher creation; compare after SHA256 |
| New deps | `base64` 0.22, `sha2` 0.10 (shared with BTC) |

**Note:** The user-friendly address always starts with `EQ` (or `UQ` for non-bounceable) due to the fixed tag+workchain. TUI must communicate that vanity applies to chars 3+.

### Monero (new)

| Field | Value |
|-------|-------|
| Crypto | Two Ed25519 scalars. spend_key = random 32 bytes (reduced mod l). view_key = Keccak256(spend_key) reduced mod l. |
| Address | Base58 of `network_byte (0x12)` + `spend_pub (32)` + `view_pub (32)` + `checksum (4)` where checksum = first 4 bytes of Keccak256 of the preceding 65 bytes. Network byte `0x12` produces leading `4` character. |
| Charset | Base58 (standard Monero alphabet) |
| Max vanity | 4 (prefix only, starts right after the fixed leading `4`) |
| Fast-path | Match on raw spend_pub bytes before Base58-encoding the full 69-byte payload |
| New deps | `curve25519-dalek` 4 (scalar reduction), `tiny-keccak` 2 (Monero uses a Keccak variant distinct from the `sha3` crate's Keccak256 in padding; verify compatibility in unit tests) |

**Performance note:** Monero generation is intrinsically slower per attempt than other chains (two scalar clamps + Keccak hash to derive view key). Expected throughput will be lower; this is a property of Monero, not a bug.

## TUI Changes

- Chain selector extended to 5 options: `1=Solana 2=EVM 3=Bitcoin 4=TON 5=Monero`
- Banner subtitle: `"v0.6 — Multi-Chain Vanity Address Generator"`
- Help popup: add "Supported Chains" section listing each chain's charset and max vanity length
- Results table: Chain column widens from 8 to 10 chars to fit "Bitcoin"/"Monero"
- TON-specific hint rendered when TON selected: "TON addresses always start with EQ; vanity begins at char 3"
- Monero-specific hint: "Monero addresses always start with 4; vanity begins at char 2"

## Performance Protection

1. **Static generics:** `search::<C>` monomorphized per chain. EVM compiles to a dedicated function identical in shape to today's `search_evm_raw`. No trait-object indirection.

2. **Benchmark harness:** `benches/generation.rs` using Criterion. Measures per-chain keys/sec. Gate: Solana and EVM post-refactor rates within **±2%** of baseline captured before refactor starts. Regression blocks merge.

3. **Cold-path isolation:** New-chain crypto deps (`ripemd`, `bech32`, `curve25519-dalek`, `tiny-keccak`) are only referenced from their respective chain modules. Rust's linker dead-code elimination removes unused code paths from compiled hot loops.

4. **Hot-loop allocation audit:** Matcher construction happens once before search spawn. All per-iteration allocations (Strings, Vecs) are prohibited inside `search::<C>` except on match.

## Testing Strategy

- **Known-vector tests per chain:** Fixed mnemonic → expected address computed by a reference wallet:
  - Solana: Phantom
  - EVM: MetaMask
  - Bitcoin: Sparrow or reference BIP-84 vectors
  - TON: Tonkeeper
  - Monero: Monero CLI `monero-wallet-cli`
- **Matcher tests:** Raw-byte fast-paths agree with string-based matching for each chain (empty prefix, max-length, odd-nibble where applicable).
- **Integration smoke tests:** Start search with a 1-char prefix per chain; assert at least one match within a per-chain timeout (short for EVM/Solana, longer for Monero).
- **Benchmark regression test:** CI runs `cargo bench` and fails if Solana or EVM rate drops >2% vs checked-in baseline.

## Dependencies Added

```toml
ripemd = "0.1"           # Bitcoin HASH160
bech32 = "0.9"           # Bitcoin address encoding
sha2 = "0.10"            # Bitcoin + TON
base64 = "0.22"          # TON user-friendly address
curve25519-dalek = "4"   # Monero scalar reduction
tiny-keccak = { version = "2", features = ["keccak"] }  # Monero Keccak variant
criterion = "0.5"        # dev-dep, benchmarks
```

Existing `sha3` stays for EVM Keccak256; Monero uses `tiny-keccak` because its Keccak variant differs in padding from the `sha3` crate. To be verified by unit test — if equivalent, consolidate.

## Open Questions (resolved)

- **Monero matching depth:** Prefix-only, short (2–4 chars) is acceptable. ✅
- **TON address format:** User-friendly Base64. ✅
- **Bitcoin address format:** Native SegWit / Bech32 only. ✅
- **Dispatch strategy:** Static generics (monomorphization). ✅
