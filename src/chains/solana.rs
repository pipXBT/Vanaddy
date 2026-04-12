use super::Chain;
use super::super::matcher::Matcher;
use super::super::seed::derive_seed;
use super::super::slip10::{slip10_derive_ed25519, PHANTOM_SOLANA_PATH};
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
        let key_bytes = slip10_derive_ed25519(&seed_bytes, &PHANTOM_SOLANA_PATH);
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

    /// Pinned Phantom derivation test: if this breaks, the derivation has changed.
    /// Derives from the canonical BIP-39 test phrase via SLIP-0010 Ed25519 at
    /// m/44'/501'/0'/0' (Phantom's default Solana path).
    #[test]
    fn solana_phantom_derivation_from_canonical_phrase() {
        let m = Mnemonic::from_phrase(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            Language::English,
        ).unwrap();
        let seed = derive_seed(&m);
        let key = slip10_derive_ed25519(&seed, &PHANTOM_SOLANA_PATH);
        let sk = SigningKey::from_bytes(&key);
        let pubkey = sk.verifying_key().to_bytes();
        let addr = bs58::encode(&pubkey).into_string();

        // Pinned: matches Phantom wallet import of "abandon...about" phrase
        // at m/44'/501'/0'/0'.
        assert_eq!(addr, "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk");

        // Format sanity
        assert!(addr.len() >= 32 && addr.len() <= 44);
        assert!(addr.chars().all(|c| Solana::CHARSET.contains(c)));
    }
}
