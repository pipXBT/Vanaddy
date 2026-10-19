use super::super::bip32::{bip32_derive_secp256k1, EVM_PATH};
use super::{Bip39GpuChain, Chain};
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
    pub(crate) fn from_seed(seed: &[u8; 64]) -> ([u8; 20], secp256k1::SecretKey) {
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

impl Bip39GpuChain for Evm {
    fn from_gpu_seed(seed: &[u8; 64]) -> (Self::AddressBytes, Self::SecretRaw) {
        // Exactly the tail the CPU path uses. Sharing one body is what makes the
        // pinned bip44_canonical_vector cover the GPU path too.
        Self::from_seed(seed)
    }

    fn verify(address: &str, secret_hex: &str, phrase: &str) -> bool {
        let Ok(m) = Mnemonic::from_phrase(phrase, Language::English) else {
            // An unparseable phrase or a bad BIP-39 checksum is a REJECTION, not
            // an "unverifiable" third state. There is deliberately no arm here
            // that can turn a corrupted input into a pass.
            return false;
        };
        // `derive_seed` is ring::pbkdf2 (src/seed.rs:8) — the reference path.
        // NEVER `derive_seeds` (4-lane NEON) and never the GPU: the point of this
        // function is to be more trusted than the thing it is checking.
        let (addr, secret) = Self::from_seed(&derive_seed(&m));
        Self::encode_address(&addr) == address && Self::encode_secret(&secret) == secret_hex
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
        super::super::assert_batch_matches_single_path::<Evm, _>(Evm::from_seed);
    }

    /// The GPU tail (`from_gpu_seed`) and the re-derivation gate (`verify`) must
    /// both land on the pinned BIP-44 vector, and `verify` must REJECT — never
    /// panic on, never accept — a wrong address, a wrong phrase, or a phrase that
    /// is not a mnemonic at all.
    #[test]
    fn from_gpu_seed_and_verify_agree_with_the_bip44_canonical_vector() {
        const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let m = Mnemonic::from_phrase(PHRASE, Language::English).unwrap();
        let seed = derive_seed(&m);

        let (addr, sk) = Evm::from_gpu_seed(&seed);
        assert_eq!(
            hex::encode(addr),
            "9858effd232b4033e47d90003d41ec34ecaeda94"
        );

        let address = Evm::encode_address(&addr);
        let secret_hex = Evm::encode_secret(&sk);
        assert!(Evm::verify(&address, &secret_hex, PHRASE));

        // One flipped nibble in the address: reject.
        let mut bad_addr = address.clone();
        bad_addr.replace_range(2..3, "8"); // "0x9858..." -> "0x8858..."
        assert!(!Evm::verify(&bad_addr, &secret_hex, PHRASE));

        // One flipped nibble in the secret: reject.
        let mut bad_secret = secret_hex.clone();
        let first = if bad_secret.starts_with('0') {
            "1"
        } else {
            "0"
        };
        bad_secret.replace_range(0..1, first);
        assert!(!Evm::verify(&address, &bad_secret, PHRASE));

        // A valid but DIFFERENT phrase: reject.
        let other = Mnemonic::new(MnemonicType::Words12, Language::English);
        assert!(!Evm::verify(&address, &secret_hex, other.phrase()));

        // Not a mnemonic at all: reject, do not panic.
        assert!(!Evm::verify(&address, &secret_hex, "not a mnemonic"));
    }
}
