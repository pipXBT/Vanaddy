use super::super::bip32::{bip32_derive_secp256k1, BTC_BIP84_PATH};
use super::super::matcher::Matcher;
use super::super::seed::derive_seed;
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

impl Chain for Bitcoin {
    const LABEL: &'static str = "Bitcoin";
    // Bech32 alphabet (lowercase only)
    const CHARSET: &'static str = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    const MAX_VANITY: usize = 8;

    type AddressBytes = [u8; 20];
    type SecretRaw = libsecp256k1::SecretKey;

    fn generate() -> (Self::AddressBytes, Self::SecretRaw, String) {
        let mnemonic = Mnemonic::new(MnemonicType::Words12, Language::English);
        let seed_bytes = derive_seed(&mnemonic);
        let secret_key = bip32_derive_secp256k1(&seed_bytes, &BTC_BIP84_PATH);
        let public_key = libsecp256k1::PublicKey::from_secret_key(&secret_key);
        let pubkey_compressed = public_key.serialize_compressed();
        let addr_hash = hash160(&pubkey_compressed);
        (addr_hash, secret_key, mnemonic.phrase().to_string())
    }

    fn encode_address(bytes: &Self::AddressBytes) -> String {
        // Native SegWit (P2WPKH): hrp="bc", witness version 0, program = HASH160
        let mut data = vec![u5::try_from_u8(0).unwrap()]; // witness version
        data.extend(bytes.as_ref().to_base32());
        bech32::encode("bc", data, Variant::Bech32).expect("valid bech32")
    }

    fn encode_secret(raw: &Self::SecretRaw) -> String {
        hex::encode(raw.serialize())
    }

    fn matches_raw(matcher: &Matcher, bytes: &Self::AddressBytes) -> bool {
        // Fast-path: compare the HASH160 bytes' 5-bit representation against the
        // user's vanity (pre-computed as 5-bit groups at Matcher construction).
        // The user's vanity applies AFTER the fixed "bc1q" prefix, so we compare
        // directly against the 5-bit groups of the HASH160 bytes.
        if let Some(ref expected) = matcher.bech32_prefix_5bit {
            let data_5bit = bytes.as_ref().to_base32();
            if data_5bit.len() < expected.len() {
                return false;
            }
            for (a, b) in data_5bit.iter().zip(expected.iter()) {
                if a.to_u8() != b.to_u8() {
                    return false;
                }
            }
            true
        } else {
            let addr = Bitcoin::encode_address(bytes);
            matcher.matches_str(&addr)
        }
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
        let pk = libsecp256k1::PublicKey::from_secret_key(&sk);
        let hash = hash160(&pk.serialize_compressed());
        let addr = Bitcoin::encode_address(&hash);
        assert_eq!(addr, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
    }
}
