use super::Chain;
use super::super::matcher::Matcher;
use super::super::seed::{derive_seed, derive_seeds};
use crate::pbkdf2_lanes::LANES;
use super::super::slip10::{slip10_derive_ed25519, PHANTOM_SOLANA_PATH};
use bip39::{Language, Mnemonic, MnemonicType};
use ed25519_dalek::SigningKey;

pub struct Solana;

impl Solana {
    /// Phantom m/44'/501'/0'/0' public key + signing key from a BIP-39 seed.
    fn from_seed(seed: &[u8; 64]) -> ([u8; 32], SigningKey) {
        let key_bytes = slip10_derive_ed25519(seed, &PHANTOM_SOLANA_PATH);
        let signing_key = SigningKey::from_bytes(&key_bytes);
        (signing_key.verifying_key().to_bytes(), signing_key)
    }
}

impl Chain for Solana {
    const LABEL: &'static str = "Solana";
    const CHARSET: &'static str =
        "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    const MAX_VANITY: usize = 9;
    const BATCH: usize = LANES;

    type AddressBytes = [u8; 32];
    type SecretRaw = SigningKey;

    fn generate() -> (Self::AddressBytes, Self::SecretRaw, String) {
        let mnemonic = Mnemonic::new(MnemonicType::Words12, Language::English);
        let seed_bytes = derive_seed(&mnemonic);
        let (pubkey_bytes, signing_key) = Self::from_seed(&seed_bytes);
        (pubkey_bytes, signing_key, mnemonic.phrase().to_string())
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
        // 32 bytes encode to at most 44 base58 chars; stack buffer, no String.
        let mut buf = [0u8; 44];
        let len = bs58::encode(bytes)
            .into(&mut buf[..])
            .expect("44 fits 32 bytes");
        let addr = std::str::from_utf8(&buf[..len]).expect("base58 is ascii");
        matcher.prefix_matches(addr) && matcher.suffix_matches(addr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seed::CANONICAL_PHRASE;
    use bip39::{Language, Mnemonic};

    /// Pinned Phantom derivation test: if this breaks, the derivation has changed.
    /// Derives from the canonical BIP-39 test phrase via SLIP-0010 Ed25519 at
    /// m/44'/501'/0'/0' (Phantom's default Solana path).
    #[test]
    fn solana_phantom_derivation_from_canonical_phrase() {
        let m = Mnemonic::from_phrase(CANONICAL_PHRASE, Language::English).unwrap();
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
        use super::super::{assert_prefix_suffix, ChainKind};

        // Derive the canonical pinned address as a reliable test payload.
        let m = Mnemonic::from_phrase(CANONICAL_PHRASE, Language::English).unwrap();
        let (pubkey, _) = Solana::from_seed(&derive_seed(&m));
        assert_prefix_suffix::<Solana>(ChainKind::Solana, &pubkey, 0, false);
    }

    #[test]
    fn solana_case_sensitive_prefix_matches() {
        use super::super::super::matcher::Matcher;
        use super::super::ChainKind;

        // Generate a fresh Solana address; take its actual first 3 chars as prefix.
        // With case-sensitive matching, the matcher must accept this exact address.
        let (pubkey_bytes, _sk, _phrase) = Solana::generate();
        let addr = bs58::encode(&pubkey_bytes).into_string();
        let actual_prefix = addr.chars().take(3).collect::<String>();

        let m = Matcher::new(
            actual_prefix.clone(),
            String::new(),
            true,
            ChainKind::Solana,
        );
        assert!(
            Solana::matches_raw(&m, &pubkey_bytes),
            "case-sensitive prefix '{}' must match its own address '{}'",
            actual_prefix, addr
        );
    }

    #[test]
    fn generate_batch_emits_lane_count_candidates_matching_single_path() {
        super::super::assert_batch_matches_single_path::<Solana, _>(Solana::from_seed);
    }

    /// The stack-buffer encode in `matches_raw` must agree with `encode_address`
    /// on random keys, a leading-zero key ('1' prefix) and the all-zero key
    /// (32 chars, far short of the 44-byte buffer).
    #[test]
    fn matches_raw_agrees_with_encode_address_on_random_candidates() {
        use super::super::ChainKind;
        let mut cands: Vec<[u8; 32]> = (0..16).map(|_| rand::random()).collect();
        cands[0][0] = 0;
        cands.push([0; 32]);
        for bytes in &cands {
            let addr = Solana::encode_address(bytes);
            let (pre, suf) = (&addr[..3], &addr[addr.len() - 3..]);
            let last = if suf.ends_with(['z', 'Z']) { "2" } else { "z" };
            let wrong = format!("{}{last}", &suf[..2]);
            for cs in [true, false] {
                let m = |s: &str| Matcher::new(pre.into(), s.into(), cs, ChainKind::Solana);
                assert!(Solana::matches_raw(&m(suf), bytes), "must match {addr}");
                assert!(!Solana::matches_raw(&m(&wrong), bytes), "{wrong} vs {addr}");
            }
        }
    }
}
