use super::super::bip32::{bip32_derive_secp256k1, BTC_BIP84_PATH};
use super::super::matcher::Matcher;
use super::super::seed::{derive_seed, derive_seeds};
use crate::pbkdf2_lanes::LANES;
use super::Chain;
use bech32::{u5, ToBase32, Variant};
use bip39::{Language, Mnemonic, MnemonicType};
use ring::digest::{digest, SHA256};
use ripemd::{Digest, Ripemd160};
use std::fmt::{self, Write};

pub struct Bitcoin;

/// HASH160 = RIPEMD160(SHA256(compressed_pubkey))
fn hash160(pubkey_compressed: &[u8]) -> [u8; 20] {
    let sha = digest(&SHA256, pubkey_compressed);
    let rip = Ripemd160::digest(&sha);
    let mut out = [0u8; 20];
    out.copy_from_slice(&rip);
    out
}

/// Expand 20 bytes (160 bits) into 32 5-bit groups, big-endian.
/// Zero-allocation replacement for `bytes.to_base32()`.
fn expand_5bit(bytes: &[u8; 20]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut acc: u16 = 0;
    let mut bits: u8 = 0;
    let mut i = 0;
    for &b in bytes {
        acc = (acc << 8) | b as u16;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out[i] = ((acc >> bits) & 0x1f) as u8;
            i += 1;
        }
    }
    // 160 bits / 5 = 32 groups exactly; no trailing bits left.
    debug_assert_eq!(bits, 0);
    debug_assert_eq!(i, 32);
    out
}

/// `fmt::Write` over a fixed buffer. bc1q P2WPKH addresses are 42 bytes.
struct AddrBuf {
    buf: [u8; 64],
    len: usize,
}

impl AddrBuf {
    fn new() -> Self {
        Self { buf: [0; 64], len: 0 }
    }

    fn as_str(&self) -> &str {
        std::str::from_utf8(&self.buf[..self.len]).expect("bech32 is ascii")
    }
}

impl Write for AddrBuf {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let bytes = s.as_bytes();
        let end = self.len + bytes.len();
        if end > self.buf.len() {
            return Err(fmt::Error);
        }
        self.buf[self.len..end].copy_from_slice(bytes);
        self.len = end;
        Ok(())
    }
}

impl Bitcoin {
    /// BIP-84 m/84'/0'/0'/0/0 HASH160 + secret key from a BIP-39 seed.
    fn from_seed(seed: &[u8; 64]) -> ([u8; 20], secp256k1::SecretKey) {
        let secret_key = bip32_derive_secp256k1(seed, &BTC_BIP84_PATH);
        let public_key = secp256k1::PublicKey::from_secret_key_global(&secret_key);
        let addr_hash = hash160(&public_key.serialize());
        (addr_hash, secret_key)
    }
}

impl Chain for Bitcoin {
    const LABEL: &'static str = "Bitcoin";
    // Bech32 alphabet (lowercase only)
    const CHARSET: &'static str = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    const MAX_VANITY: usize = 8;
    const BATCH: usize = LANES;

    type AddressBytes = [u8; 20];
    type SecretRaw = secp256k1::SecretKey;

    fn generate() -> (Self::AddressBytes, Self::SecretRaw, String) {
        let mnemonic = Mnemonic::new(MnemonicType::Words12, Language::English);
        let seed_bytes = derive_seed(&mnemonic);
        let (addr_hash, secret_key) = Self::from_seed(&seed_bytes);
        (addr_hash, secret_key, mnemonic.phrase().to_string())
    }

    fn generate_batch(mut emit: impl FnMut(Self::AddressBytes, Self::SecretRaw, String)) {
        let mnemonics: [Mnemonic; LANES] =
            std::array::from_fn(|_| Mnemonic::new(MnemonicType::Words12, Language::English));
        let seeds = derive_seeds(&mnemonics);
        for (mnemonic, seed) in mnemonics.iter().zip(seeds.iter()) {
            let (addr, secret) = Self::from_seed(seed);
            emit(addr, secret, mnemonic.phrase().to_string());
        }
    }

    fn encode_address(bytes: &Self::AddressBytes) -> String {
        // Native SegWit (P2WPKH): hrp="bc", witness version 0, program = HASH160
        let mut data = vec![u5::try_from_u8(0).unwrap()]; // witness version
        data.extend(bytes.as_ref().to_base32());
        bech32::encode("bc", data, Variant::Bech32).expect("valid bech32")
    }

    fn encode_secret(raw: &Self::SecretRaw) -> String {
        hex::encode(raw.secret_bytes())
    }

    fn matches_raw(matcher: &Matcher, bytes: &Self::AddressBytes) -> bool {
        // Fast-path: compare 5-bit expansion of HASH160 against user's Bech32 prefix.
        let data_5bit = expand_5bit(bytes);
        if let Some(ref expected) = matcher.bech32_prefix_5bit {
            if !data_5bit.starts_with(expected) {
                return false;
            }
        }

        // One stack encode for prefix + suffix. Bitcoin vanity applies after "bc1q".
        // HRP "bc" is already lowercase, so encode_to_fmt does not allocate it.
        let mut data = [u5::try_from_u8(0).unwrap(); 33];
        for (slot, group) in data[1..].iter_mut().zip(data_5bit) {
            *slot = u5::try_from_u8(group).unwrap();
        }
        let mut buf = AddrBuf::new();
        bech32::encode_to_fmt(&mut buf, "bc", &data, Variant::Bech32)
            .expect("valid hrp")
            .expect("bech32 fits");
        const FIXED_PREFIX_LEN: usize = 4;
        let addr = buf.as_str();
        let vanity_target = addr.get(FIXED_PREFIX_LEN..).unwrap_or("");
        matcher.prefix_matches(vanity_target) && matcher.suffix_matches(addr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seed::CANONICAL_PHRASE;
    use bip39::{Language, Mnemonic};

    /// BIP-84 canonical test vector from the BIP-84 specification itself.
    /// Mnemonic "abandon abandon ... about" at m/84'/0'/0'/0/0 derives to
    /// bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu.
    #[test]
    fn bip84_canonical_vector() {
        let m = Mnemonic::from_phrase(CANONICAL_PHRASE, Language::English).unwrap();
        let seed = derive_seed(&m);
        let sk = bip32_derive_secp256k1(&seed, &BTC_BIP84_PATH);
        let pk = secp256k1::PublicKey::from_secret_key_global(&sk);
        let hash = hash160(&pk.serialize());
        let addr = Bitcoin::encode_address(&hash);
        assert_eq!(addr, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
    }

    #[test]
    fn bitcoin_starts_and_ends_with_both_required() {
        use super::super::{assert_prefix_suffix, ChainKind};

        let m = Mnemonic::from_phrase(CANONICAL_PHRASE, Language::English).unwrap();
        // "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu": "cr8" after "bc1q", "fyu".
        let (hash, _) = Bitcoin::from_seed(&derive_seed(&m));
        assert_prefix_suffix::<Bitcoin>(ChainKind::Bitcoin, &hash, 4, true);
    }

    #[test]
    fn matches_raw_agrees_with_encode_address_for_one_char_prefix_and_suffix() {
        use super::super::ChainKind;

        let (bytes, _secret, _phrase) = Bitcoin::generate();
        let addr = Bitcoin::encode_address(&bytes);
        assert!(addr.starts_with("bc1q"), "vanity starts after bc1q");
        assert_eq!(addr.len(), 42);
        let prefix = addr[4..5].to_string();
        let suffix = addr[addr.len() - 1..].to_string();

        let matcher = Matcher::new(prefix.clone(), suffix.clone(), true, ChainKind::Bitcoin);
        assert!(matcher.prefix_matches(&addr[4..]) && matcher.suffix_matches(&addr));
        assert!(Bitcoin::matches_raw(&matcher, &bytes));

        let absent = if prefix == "q" { "p" } else { "q" };
        let reject = Matcher::new(absent.to_string(), suffix, true, ChainKind::Bitcoin);
        assert!(!Bitcoin::matches_raw(&reject, &bytes));
    }

    #[test]
    fn expand_5bit_matches_bech32_to_base32() {
        // Cross-check our stack-buffer expansion against the bech32 crate's output.
        let hash = [
            0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4,
            0x54, 0x94, 0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23,
            0xf1, 0x43, 0x3b, 0xd6,
        ];
        let ours = expand_5bit(&hash);
        let theirs = hash.as_ref().to_base32();
        assert_eq!(ours.len(), theirs.len());
        for (a, b) in ours.iter().zip(theirs.iter()) {
            assert_eq!(*a, b.to_u8());
        }
    }

    #[test]
    fn generate_batch_emits_lane_count_candidates_matching_single_path() {
        super::super::assert_batch_matches_single_path::<Bitcoin, _>(Bitcoin::from_seed);
    }
}
