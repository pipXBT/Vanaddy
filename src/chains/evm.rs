use super::super::bip32::{bip32_derive_secp256k1, EVM_PATH};
use super::Chain;
use super::super::matcher::Matcher;
use super::super::seed::derive_seed;
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

impl Chain for Evm {
    const LABEL: &'static str = "EVM";
    const CHARSET: &'static str = "0123456789abcdefABCDEF";
    const MAX_VANITY: usize = 8;

    type AddressBytes = [u8; 20];
    type SecretRaw = libsecp256k1::SecretKey;

    fn generate() -> (Self::AddressBytes, Self::SecretRaw, String) {
        let mnemonic = Mnemonic::new(MnemonicType::Words12, Language::English);
        let seed_bytes = derive_seed(&mnemonic);
        let secret_key = bip32_derive_secp256k1(&seed_bytes, &EVM_PATH);
        let public_key = libsecp256k1::PublicKey::from_secret_key(&secret_key);
        let pubkey_bytes = public_key.serialize();
        let pubkey_uncompressed = &pubkey_bytes[1..];
        let hash = Keccak256::digest(pubkey_uncompressed);

        let mut addr = [0u8; 20];
        addr.copy_from_slice(&hash[12..]);

        (addr, secret_key, mnemonic.phrase().to_string())
    }

    fn encode_address(bytes: &Self::AddressBytes) -> String {
        format!("0x{}", hex::encode(bytes))
    }

    fn encode_secret(raw: &Self::SecretRaw) -> String {
        hex::encode(raw.serialize())
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
}
