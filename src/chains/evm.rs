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
    // Stack-only: runs per candidate in case-sensitive `matches_raw`.
    let mut out = [0u8; 40];
    hex::encode_to_slice(addr, &mut out).expect("20 bytes -> 40 hex chars");
    let hash = Keccak256::digest(&out);
    for (i, c) in out.iter_mut().enumerate() {
        let hash_nibble = if i % 2 == 0 {
            hash[i / 2] >> 4
        } else {
            hash[i / 2] & 0x0f
        };
        if hash_nibble >= 8 {
            c.make_ascii_uppercase(); // no-op on digits
        }
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

    /// Test-only reference check: re-derive from the phrase alone with the
    /// reference (`ring`) path. MUST NOT use the batched or GPU path. Any
    /// unparseable phrase or bad BIP-39 checksum is a rejection, never a pass.
    #[cfg(test)]
    pub(crate) fn verify(address: &str, secret_hex: &str, phrase: &str) -> bool {
        let Ok(m) = Mnemonic::from_phrase(phrase, Language::English) else {
            return false;
        };
        let (addr, secret) = Self::from_seed(&derive_seed(&m));
        Self::encode_address(&addr) == address && Self::encode_secret(&secret) == secret_hex
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
            return matcher.prefix_matches(eip55_str) && matcher.suffix_matches(eip55_str);
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
        let m = Mnemonic::from_phrase(crate::seed::CANONICAL_PHRASE, Language::English).unwrap();
        let seed = derive_seed(&m);
        let (addr, _sk) = Evm::from_seed(&seed);
        assert_eq!(hex::encode(addr), "9858effd232b4033e47d90003d41ec34ecaeda94");
        let eip55 = eip55_encode(&addr);
        assert_eq!(std::str::from_utf8(&eip55).unwrap(), "9858EfFD232B4033E47d90003D41EC34EcaEda94");
    }

    /// Case-sensitive matching must compare against the EIP-55 casing exactly.
    #[test]
    fn case_sensitive_match_uses_eip55_casing() {
        use super::super::ChainKind;
        let addr: [u8; 20] = hex::decode("9858effd232b4033e47d90003d41ec34ecaeda94")
            .unwrap()
            .try_into()
            .unwrap();
        let m = |pre: &str, suf: &str| Matcher::new(pre.into(), suf.into(), true, ChainKind::Evm);
        assert!(Evm::matches_raw(&m("9858EfFD", "EcaEda94"), &addr));
        assert!(Evm::matches_raw(&m("", "Eda94"), &addr));
        assert!(!Evm::matches_raw(&m("9858effd", ""), &addr));
        assert!(!Evm::matches_raw(&m("9858EfFD", "ecaeda94"), &addr));
    }

    /// Stack `eip55_encode` must equal the allocating EIP-55 of `encode_address`'s
    /// hex on random addresses, and case-sensitive `matches_raw` must hit on that
    /// casing and miss on the all-lowercase form whenever they differ.
    #[test]
    fn matches_raw_agrees_with_encode_address_on_random_candidates() {
        use super::super::ChainKind;
        for _ in 0..16 {
            let addr: [u8; 20] = rand::random();
            let lower = Evm::encode_address(&addr)[2..].to_string();
            let hash = Keccak256::digest(lower.as_bytes());
            let want: String = lower
                .chars()
                .enumerate()
                .map(|(i, c)| {
                    let n = if i % 2 == 0 {
                        hash[i / 2] >> 4
                    } else {
                        hash[i / 2] & 0x0f
                    };
                    if n >= 8 {
                        c.to_ascii_uppercase()
                    } else {
                        c
                    }
                })
                .collect();
            assert_eq!(std::str::from_utf8(&eip55_encode(&addr)).unwrap(), want);

            let m = |p: &str| Matcher::new(p.into(), String::new(), true, ChainKind::Evm);
            assert!(Evm::matches_raw(&m(&want), &addr));
            assert_eq!(Evm::matches_raw(&m(&lower), &addr), want == lower);
        }
    }

    #[test]
    fn generate_batch_emits_lane_count_candidates_matching_single_path() {
        super::super::assert_batch_matches_single_path::<Evm, _>(Evm::from_seed);
    }

    /// `from_seed` and the re-derivation check (`verify`) must both land on the
    /// pinned BIP-44 vector, and `verify` must REJECT — never panic on, never
    /// accept — a wrong address, a wrong phrase, or a phrase that is not a
    /// mnemonic at all.
    #[test]
    fn from_seed_and_verify_agree_with_the_bip44_canonical_vector() {
        use crate::seed::CANONICAL_PHRASE as PHRASE;
        let m = Mnemonic::from_phrase(PHRASE, Language::English).unwrap();
        let seed = derive_seed(&m);

        let (addr, sk) = Evm::from_seed(&seed);
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
