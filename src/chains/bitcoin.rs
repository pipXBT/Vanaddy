use super::super::bip32::{bip32_derive_secp256k1, BTC_BIP84_PATH};
use super::super::matcher::Matcher;
use super::super::seed::{derive_seed, derive_seeds};
use crate::pbkdf2_lanes::LANES;
use super::Chain;
use bech32::{u5, ToBase32, Variant};
use bip39::{Language, Mnemonic, MnemonicType};
use ripemd::Ripemd160;
use sha2::{Digest as Sha2Digest, Sha256};

pub struct Bitcoin;

/// HASH160 = RIPEMD160(SHA256(compressed_pubkey))
fn hash160(pubkey_compressed: &[u8]) -> [u8; 20] {
    let sha = Sha256::digest(pubkey_compressed);
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
        if let Some(ref expected) = matcher.bech32_prefix_5bit {
            let data_5bit = expand_5bit(bytes);
            if data_5bit.len() < expected.len() {
                return false;
            }
            for (a, b) in data_5bit.iter().zip(expected.iter()) {
                if *a != b.to_u8() {
                    return false;
                }
            }
        }

        // Full encode for prefix + suffix string checks.
        // Bitcoin vanity applies after "bc1q" (4 chars).
        const FIXED_PREFIX_LEN: usize = 4;
        let addr = Bitcoin::encode_address(bytes);
        let vanity_target = if addr.len() > FIXED_PREFIX_LEN {
            &addr[FIXED_PREFIX_LEN..]
        } else {
            ""
        };
        matcher.prefix_matches(vanity_target) && matcher.suffix_matches(&addr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bip39::{Language, Mnemonic};

    /// BIP-84 canonical test vector from the BIP-84 specification itself.
    /// Mnemonic "abandon abandon ... about" at m/84'/0'/0'/0/0 derives to
    /// bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu.
    #[test]
    fn bip84_canonical_vector() {
        let m = Mnemonic::from_phrase(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            Language::English,
        ).unwrap();
        let seed = derive_seed(&m);
        let sk = bip32_derive_secp256k1(&seed, &BTC_BIP84_PATH);
        let pk = secp256k1::PublicKey::from_secret_key_global(&sk);
        let hash = hash160(&pk.serialize());
        let addr = Bitcoin::encode_address(&hash);
        assert_eq!(addr, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
    }

    #[test]
    fn bitcoin_starts_and_ends_with_both_required() {
        use super::super::super::matcher::Matcher;
        use super::super::ChainKind;

        let m = Mnemonic::from_phrase(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            Language::English,
        ).unwrap();
        let seed = derive_seed(&m);
        let sk = bip32_derive_secp256k1(&seed, &BTC_BIP84_PATH);
        let pk = secp256k1::PublicKey::from_secret_key_global(&sk);
        let hash = hash160(&pk.serialize());
        let addr = Bitcoin::encode_address(&hash);
        // addr = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
        // after "bc1q": "cr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
        let vanity_target = &addr[4..];
        let actual_prefix = &vanity_target[..3]; // "cr8"
        let actual_suffix = &addr[addr.len() - 3..]; // "fyu"

        let wrong_suffix = if actual_suffix == "zzz" { "aaa" } else { "zzz" };
        let matcher = Matcher::new(
            actual_prefix.to_string(),
            wrong_suffix.to_string(),
            true,
            ChainKind::Bitcoin,
        );
        assert!(!Bitcoin::matches_raw(&matcher, &hash), "must reject wrong suffix");

        let matcher = Matcher::new(
            actual_prefix.to_string(),
            actual_suffix.to_string(),
            true,
            ChainKind::Bitcoin,
        );
        assert!(Bitcoin::matches_raw(&matcher, &hash), "must accept both correct");
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
        use crate::pbkdf2_lanes::LANES;
        let mut got = Vec::new();
        Bitcoin::generate_batch(|addr, secret, phrase| got.push((addr, secret, phrase)));
        assert_eq!(Bitcoin::BATCH, LANES);
        assert_eq!(got.len(), LANES);
        for (addr, secret, phrase) in &got {
            let m = Mnemonic::from_phrase(phrase, Language::English).unwrap();
            let (addr2, secret2) = Bitcoin::from_seed(&derive_seed(&m));
            assert_eq!(addr, &addr2, "batch address must match single-path derivation");
            assert_eq!(Bitcoin::encode_secret(secret), Bitcoin::encode_secret(&secret2));
        }
        let mut addrs: Vec<_> = got.iter().map(|c| c.0).collect();
        addrs.dedup();
        assert_eq!(addrs.len(), LANES, "every lane must use fresh entropy");
    }
}
