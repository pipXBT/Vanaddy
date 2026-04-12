use super::Chain;
use super::super::matcher::Matcher;
use super::super::seed::derive_seed;
use bip39::{Language, Mnemonic, MnemonicType};
use ed25519_dalek::SigningKey;

pub struct Solana;

impl Chain for Solana {
    const LABEL: &'static str = "Solana";
    const CHARSET: &'static str =
        "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    const MAX_VANITY: usize = 9;

    type AddressBytes = [u8; 32];
    type SecretRaw = SigningKey;

    fn generate() -> (Self::AddressBytes, Self::SecretRaw, String) {
        let mnemonic = Mnemonic::new(MnemonicType::Words12, Language::English);
        let seed_bytes = derive_seed(&mnemonic);
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&seed_bytes[..32]);
        let signing_key = SigningKey::from_bytes(&key_bytes);
        let pubkey_bytes = signing_key.verifying_key().to_bytes();
        (pubkey_bytes, signing_key, mnemonic.phrase().to_string())
    }

    fn encode_address(bytes: &Self::AddressBytes) -> String {
        bs58::encode(bytes).into_string()
    }

    fn encode_secret(raw: &Self::SecretRaw) -> String {
        // Solana keypair format: 64 bytes = secret_key (32) || public_key (32)
        let pubkey_bytes = raw.verifying_key().to_bytes();
        let mut keypair_bytes = [0u8; 64];
        keypair_bytes[..32].copy_from_slice(raw.as_bytes());
        keypair_bytes[32..].copy_from_slice(&pubkey_bytes);
        hex::encode(keypair_bytes)
    }

    fn matches_raw(matcher: &Matcher, bytes: &Self::AddressBytes) -> bool {
        // Fast-path: if the matcher has decoded raw prefix bytes, match on those.
        // Otherwise, encode and match the string.
        if matcher.raw_prefix.is_some() {
            matcher.matches_raw(bytes)
        } else {
            let addr = bs58::encode(bytes).into_string();
            matcher.matches_str(&addr)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bip39::{Language, Mnemonic};

    /// Sanity check: derivation from canonical phrase produces a valid Base58 pubkey.
    /// This test doesn't pin a specific address; it verifies the code path works.
    #[test]
    fn solana_derivation_from_canonical_phrase() {
        let m = Mnemonic::from_phrase(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            Language::English,
        ).unwrap();
        let seed_bytes = derive_seed(&m);
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&seed_bytes[..32]);
        let signing_key = SigningKey::from_bytes(&key_bytes);
        let pubkey = signing_key.verifying_key().to_bytes();
        let addr = bs58::encode(&pubkey).into_string();
        assert!(addr.len() >= 32 && addr.len() <= 44);
        assert!(addr.chars().all(|c| Solana::CHARSET.contains(c)));
    }
}
