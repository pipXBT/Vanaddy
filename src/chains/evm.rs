use super::super::bip32::{bip32_derive_secp256k1, EVM_PATH};
use super::Chain;
use super::super::matcher::Matcher;
use super::super::seed::{derive_seed, derive_seeds};
use crate::pbkdf2_lanes::LANES;
use bip39::{Language, Mnemonic, MnemonicType};
use sha3::{Digest, Keccak256};

pub struct Evm;

/// EIP-55 checksum encoding: returns the 40-char hex address with uppercase
/// hex chars where the nibble of Keccak256(lowercase_hex) is >= 8.
///
/// Example: 0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed
fn eip55_encode(addr: &[u8; 20]) -> [u8; 40] {
    let lower = hex::encode(addr);
    let hash = Keccak256::digest(lower.as_bytes());
    let mut out = [0u8; 40];
    for (i, c) in lower.as_bytes().iter().enumerate() {
        let hash_nibble = if i % 2 == 0 {
            hash[i / 2] >> 4
        } else {
            hash[i / 2] & 0x0f
        };
        out[i] = if c.is_ascii_alphabetic() && hash_nibble >= 8 {
            c.to_ascii_uppercase()
        } else {
            *c
        };
    }
    out
}

impl Evm {
    /// BIP-44 m/44'/60'/0'/0/0 address + secret key from a BIP-39 seed.
    fn from_seed(seed: &[u8; 64]) -> ([u8; 20], secp256k1::SecretKey) {
        let secret_key = bip32_derive_secp256k1(seed, &EVM_PATH);
        let public_key = secp256k1::PublicKey::from_secret_key_global(&secret_key);
        let pubkey_bytes = public_key.serialize_uncompressed();
        let pubkey_uncompressed = &pubkey_bytes[1..];
        let hash = Keccak256::digest(pubkey_uncompressed);

        let mut addr = [0u8; 20];
        addr.copy_from_slice(&hash[12..]);
        (addr, secret_key)
    }
}

impl Chain for Evm {
    const LABEL: &'static str = "EVM";
    const CHARSET: &'static str = "0123456789abcdefABCDEF";
    const MAX_VANITY: usize = 8;
    const BATCH: usize = LANES;

    type AddressBytes = [u8; 20];
    type SecretRaw = secp256k1::SecretKey;

    fn generate() -> (Self::AddressBytes, Self::SecretRaw, String) {
        let mnemonic = Mnemonic::new(MnemonicType::Words12, Language::English);
        let seed_bytes = derive_seed(&mnemonic);
        let (addr, secret_key) = Self::from_seed(&seed_bytes);
        (addr, secret_key, mnemonic.phrase().to_string())
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
        format!("0x{}", hex::encode(bytes))
    }

    fn encode_secret(raw: &Self::SecretRaw) -> String {
        hex::encode(raw.secret_bytes())
    }

    fn matches_raw(matcher: &Matcher, bytes: &Self::AddressBytes) -> bool {
        // Fast byte-level filter (case-agnostic on hex)
        if !matcher.matches_evm_raw(bytes) {
            return false;
        }

        // If case-sensitive, also check EIP-55 casing against the user's exact input.
        if matcher.case_sensitive {
            let eip55 = eip55_encode(bytes);
            let eip55_str = std::str::from_utf8(&eip55).expect("ascii");

            if !matcher.prefix.is_empty() {
                let ok = eip55_str.len() >= matcher.prefix.len()
                    && &eip55_str[..matcher.prefix.len()] == matcher.prefix;
                if !ok {
                    return false;
                }
            }
            if !matcher.suffix.is_empty() {
                let start = eip55_str.len() - matcher.suffix.len();
                if &eip55_str[start..] != matcher.suffix {
                    return false;
                }
            }
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// EIP-55 canonical test vector from the spec.
    #[test]
    fn eip55_canonical_vector() {
        // From EIP-55 spec examples
        let addr_bytes = hex::decode("5aaeb6053f3e94c9b9a09f33669435e7ef1beaed").unwrap();
        let mut arr = [0u8; 20];
        arr.copy_from_slice(&addr_bytes);
        let checksummed = eip55_encode(&arr);
        let got = std::str::from_utf8(&checksummed).unwrap();
        assert_eq!(got, "5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed");
    }

    #[test]
    fn eip55_second_vector() {
        let addr_bytes = hex::decode("fb6916095ca1df60bb79ce92ce3ea74c37c5d359").unwrap();
        let mut arr = [0u8; 20];
        arr.copy_from_slice(&addr_bytes);
        let checksummed = eip55_encode(&arr);
        let got = std::str::from_utf8(&checksummed).unwrap();
        assert_eq!(got, "fB6916095ca1df60bB79Ce92cE3Ea74c37c5d359");
    }

    /// BIP-44 pinned vector: the canonical BIP-39 phrase at m/44'/60'/0'/0/0 is the
    /// first MetaMask account, 0x9858EfFD232B4033E47d90003D41EC34EcaEda94.
    #[test]
    fn bip44_canonical_vector() {
        use bip39::{Language, Mnemonic};
        let m = Mnemonic::from_phrase(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            Language::English,
        ).unwrap();
        let seed = derive_seed(&m);
        let (addr, _sk) = Evm::from_seed(&seed);
        assert_eq!(hex::encode(addr), "9858effd232b4033e47d90003d41ec34ecaeda94");
        let eip55 = eip55_encode(&addr);
        assert_eq!(std::str::from_utf8(&eip55).unwrap(), "9858EfFD232B4033E47d90003D41EC34EcaEda94");
    }

    #[test]
    fn generate_batch_emits_lane_count_candidates_matching_single_path() {
        use crate::pbkdf2_lanes::LANES;
        let mut got = Vec::new();
        Evm::generate_batch(|addr, secret, phrase| got.push((addr, secret, phrase)));
        assert_eq!(Evm::BATCH, LANES);
        assert_eq!(got.len(), LANES);
        for (addr, secret, phrase) in &got {
            let m = Mnemonic::from_phrase(phrase, Language::English).unwrap();
            let (addr2, secret2) = Evm::from_seed(&derive_seed(&m));
            assert_eq!(addr, &addr2, "batch address must match single-path derivation");
            assert_eq!(Evm::encode_secret(secret), Evm::encode_secret(&secret2));
        }
        let mut addrs: Vec<_> = got.iter().map(|c| c.0).collect();
        addrs.dedup();
        assert_eq!(addrs.len(), LANES, "every lane must use fresh entropy");
    }
}
