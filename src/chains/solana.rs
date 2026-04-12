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
        // Fast-path: reject on raw prefix bytes before Base58-encoding.
        if let Some(ref raw) = matcher.raw_prefix {
            if !bytes.starts_with(raw) {
                return false;
            }
        }

        let addr = bs58::encode(bytes).into_string();
        // Solana has no fixed leading chars — vanity applies to the whole address.
        let vanity_target: &str = &addr;

        // Prefix check
        if !matcher.prefix.is_empty() {
            let prefix_ok = if matcher.case_sensitive {
                vanity_target.starts_with(&matcher.prefix)
            } else {
                vanity_target.to_lowercase().starts_with(&matcher.prefix_lower)
            };
            if !prefix_ok {
                return false;
            }
        }

        // Suffix check
        if !matcher.suffix.is_empty() {
            let suffix_ok = if matcher.case_sensitive {
                addr.ends_with(&matcher.suffix)
            } else {
                addr.to_lowercase().ends_with(&matcher.suffix_lower)
            };
            if !suffix_ok {
                return false;
            }
        }

        true
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

    #[test]
    fn solana_starts_and_ends_with_both_required() {
        use super::super::super::matcher::{Matcher, MatchPosition};
        use super::super::ChainKind;

        // Derive the canonical pinned address as a reliable test payload.
        let m = Mnemonic::from_phrase(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            Language::English,
        ).unwrap();
        let seed = derive_seed(&m);
        let key = slip10_derive_ed25519(&seed, &PHANTOM_SOLANA_PATH);
        let sk = SigningKey::from_bytes(&key);
        let pubkey: [u8; 32] = sk.verifying_key().to_bytes();
        let addr = bs58::encode(&pubkey).into_string();

        let actual_prefix = &addr[..3];
        let actual_suffix = &addr[addr.len() - 3..];

        // Use case_sensitive=false so raw_prefix fast-path is skipped (it decodes
        // base58 byte-wise which isn't a clean string-prefix match). The matches_raw
        // path then goes through the full encode + string compare.
        let wrong_suffix = if actual_suffix == "zzz" { "aaa" } else { "zzz" };
        let matcher = Matcher::new(
            actual_prefix.to_string(),
            wrong_suffix.to_string(),
            MatchPosition::StartsAndEndsWith,
            false,
            ChainKind::Solana,
        );
        assert!(!Solana::matches_raw(&matcher, &pubkey), "must reject wrong suffix");

        let matcher = Matcher::new(
            actual_prefix.to_string(),
            actual_suffix.to_string(),
            MatchPosition::StartsAndEndsWith,
            false,
            ChainKind::Solana,
        );
        assert!(Solana::matches_raw(&matcher, &pubkey), "must accept both correct");
    }
}
