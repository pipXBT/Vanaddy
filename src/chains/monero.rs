use super::super::matcher::Matcher;
use super::Chain;
use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;
use rand::RngCore;
use tiny_keccak::{Hasher, Keccak};

use super::monero_wordlist::MONERO_WORDLIST;

pub struct Monero;

const NETWORK_BYTE_MAINNET: u8 = 0x12;

/// Monero uses the original Keccak-256 (not FIPS-202 SHA3-256 — they differ in padding).
/// tiny-keccak's Keccak::v256() is the Monero variant.
fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut k = Keccak::v256();
    k.update(data);
    k.finalize(&mut out);
    out
}

/// Raw Monero keypair: spend_sec, spend_pub, view_sec, view_pub.
#[derive(Clone)]
pub struct MoneroKeypair {
    pub spend_sec: [u8; 32],
    pub view_sec: [u8; 32],
}

/// Generate Monero keys:
/// spend_sec = random 32 bytes reduced mod l (Ed25519 group order).
/// view_sec  = keccak256(spend_sec) reduced mod l.
fn generate_keys() -> (MoneroKeypair, [u8; 32], [u8; 32]) {
    let mut spend_raw = [0u8; 32];
    OsRng.fill_bytes(&mut spend_raw);
    let spend_scalar = Scalar::from_bytes_mod_order(spend_raw);
    let spend_sec = spend_scalar.to_bytes();
    let spend_pub = (&spend_scalar * ED25519_BASEPOINT_TABLE).compress().to_bytes();

    let view_raw = keccak256(&spend_sec);
    let view_scalar = Scalar::from_bytes_mod_order(view_raw);
    let view_sec = view_scalar.to_bytes();
    let view_pub = (&view_scalar * ED25519_BASEPOINT_TABLE).compress().to_bytes();

    (MoneroKeypair { spend_sec, view_sec }, spend_pub, view_pub)
}

/// Encode a Monero spend key as a 25-word Electrum-style mnemonic.
/// Compatible with monero-wallet-cli --restore-deterministic-wallet.
pub fn monero_seed_phrase(spend_sec: &[u8; 32]) -> String {
    const N: u32 = 1626;
    const PREFIX_LEN: usize = 3;

    let mut words: Vec<&'static str> = Vec::with_capacity(25);

    for i in 0..8 {
        let chunk = &spend_sec[i * 4..i * 4 + 4];
        let x = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        let w1 = x % N;
        let w2 = (x / N + w1) % N;
        let w3 = (x / N / N + w2) % N;
        words.push(MONERO_WORDLIST[w1 as usize]);
        words.push(MONERO_WORDLIST[w2 as usize]);
        words.push(MONERO_WORDLIST[w3 as usize]);
    }

    // Checksum: CRC32 over concatenation of first PREFIX_LEN chars of each word.
    // All Monero English words are ASCII and length >= 4, so byte-slicing is safe.
    let mut trimmed = String::with_capacity(24 * PREFIX_LEN);
    for w in &words {
        trimmed.push_str(&w[..PREFIX_LEN.min(w.len())]);
    }

    let cksum = crc32fast::hash(trimmed.as_bytes());
    let checksum_idx = (cksum as usize) % 24;
    words.push(words[checksum_idx]);

    words.join(" ")
}

/// Monero Base58 encodes in 8-byte blocks → 11 chars each (last block may be shorter).
fn monero_base58_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] =
        b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    const BLOCK_SIZES: &[usize] = &[0, 2, 3, 5, 6, 7, 9, 10, 11];

    let mut out = String::new();
    for chunk in data.chunks(8) {
        let mut num: u128 = 0;
        for &b in chunk {
            num = num * 256 + b as u128;
        }
        let enc_len = BLOCK_SIZES[chunk.len()];
        let mut buf = vec![b'1'; enc_len];
        let mut i = enc_len;
        while num > 0 && i > 0 {
            i -= 1;
            buf[i] = ALPHABET[(num % 58) as usize];
            num /= 58;
        }
        out.push_str(std::str::from_utf8(&buf).unwrap());
    }
    out
}

impl Chain for Monero {
    const LABEL: &'static str = "Monero";
    // Standard Monero Base58 alphabet (same as Bitcoin/Solana Base58)
    const CHARSET: &'static str =
        "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    // Prefix only; user's vanity applies after the fixed leading "4"
    const MAX_VANITY: usize = 4;

    /// 65 bytes: network_byte(1) || spend_pub(32) || view_pub(32)
    /// Checksum is appended during encode_address.
    type AddressBytes = [u8; 65];
    type SecretRaw = MoneroKeypair;

    fn generate() -> (Self::AddressBytes, Self::SecretRaw, String) {
        let (keypair, spend_pub, view_pub) = generate_keys();

        let mut payload = [0u8; 65];
        payload[0] = NETWORK_BYTE_MAINNET;
        payload[1..33].copy_from_slice(&spend_pub);
        payload[33..65].copy_from_slice(&view_pub);

        let phrase = monero_seed_phrase(&keypair.spend_sec);
        (payload, keypair, phrase)
    }

    fn encode_address(bytes: &Self::AddressBytes) -> String {
        let mut full = [0u8; 69];
        full[..65].copy_from_slice(bytes);
        let checksum = keccak256(bytes);
        full[65..].copy_from_slice(&checksum[..4]);
        monero_base58_encode(&full)
    }

    fn encode_secret(raw: &Self::SecretRaw) -> String {
        // Format: "spend_sec:view_sec" in hex. Import via monero-wallet-cli
        // --generate-from-keys.
        format!(
            "{}:{}",
            hex::encode(raw.spend_sec),
            hex::encode(raw.view_sec)
        )
    }

    fn matches_raw(matcher: &Matcher, bytes: &Self::AddressBytes) -> bool {
        let addr = Monero::encode_address(bytes);
        // Monero vanity applies after leading "4" (1 char)
        const FIXED_PREFIX_LEN: usize = 1;
        let vanity_target = if addr.len() > FIXED_PREFIX_LEN {
            &addr[FIXED_PREFIX_LEN..]
        } else {
            ""
        };

        if !matcher.prefix.is_empty() {
            let ok = if matcher.case_sensitive {
                vanity_target.starts_with(&matcher.prefix)
            } else {
                vanity_target.as_bytes().len() >= matcher.prefix.len()
                    && vanity_target.as_bytes()[..matcher.prefix.len()]
                        .eq_ignore_ascii_case(matcher.prefix.as_bytes())
            };
            if !ok {
                return false;
            }
        }

        if !matcher.suffix.is_empty() {
            let ok = if matcher.case_sensitive {
                addr.ends_with(&matcher.suffix)
            } else {
                let addr_bytes = addr.as_bytes();
                let start = addr_bytes.len().saturating_sub(matcher.suffix.len());
                addr_bytes[start..].eq_ignore_ascii_case(matcher.suffix.as_bytes())
            };
            if !ok {
                return false;
            }
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn monero_address_starts_with_4_and_is_95_chars() {
        let (keypair, spend_pub, view_pub) = generate_keys();
        let mut payload = [0u8; 65];
        payload[0] = NETWORK_BYTE_MAINNET;
        payload[1..33].copy_from_slice(&spend_pub);
        payload[33..65].copy_from_slice(&view_pub);
        let addr = Monero::encode_address(&payload);
        assert_eq!(addr.len(), 95, "Monero mainnet addresses are 95 chars, got len={}: {}", addr.len(), addr);
        assert!(addr.starts_with('4'), "network byte 0x12 must produce leading '4', got: {}", addr);
        // Exercise encode_secret path
        let secret = Monero::encode_secret(&keypair);
        assert!(secret.contains(':'));
        assert_eq!(secret.len(), 64 + 1 + 64, "spend_hex:view_hex = 64+1+64 chars");
    }

    #[test]
    fn monero_seed_phrase_has_25_words() {
        let spend_sec = [0u8; 32];
        let phrase = monero_seed_phrase(&spend_sec);
        let words: Vec<&str> = phrase.split_whitespace().collect();
        assert_eq!(words.len(), 25, "Monero mnemonic must be 25 words");
        for w in &words {
            assert!(MONERO_WORDLIST.contains(w), "word '{}' not in wordlist", w);
        }
    }

    #[test]
    fn monero_seed_phrase_deterministic() {
        let spend_sec = [0xABu8; 32];
        let p1 = monero_seed_phrase(&spend_sec);
        let p2 = monero_seed_phrase(&spend_sec);
        assert_eq!(p1, p2);
    }

    #[test]
    fn monero_seed_phrase_varies() {
        let p1 = monero_seed_phrase(&[0u8; 32]);
        let p2 = monero_seed_phrase(&[0xFFu8; 32]);
        assert_ne!(p1, p2);
    }

    /// Pin the output for all-zero spend key so future changes are caught.
    #[test]
    fn monero_seed_phrase_all_zeros_pinned() {
        let phrase = monero_seed_phrase(&[0u8; 32]);
        assert_eq!(phrase.split_whitespace().count(), 25);
        let first_word = phrase.split_whitespace().next().unwrap();
        assert_eq!(first_word, MONERO_WORDLIST[0]);
        // All 8 u32 chunks are zero → every (w1,w2,w3) = (0,0,0),
        // so all 24 words are MONERO_WORDLIST[0], and the checksum
        // word (indexed 0..24) is also MONERO_WORDLIST[0].
        for w in phrase.split_whitespace() {
            assert_eq!(w, MONERO_WORDLIST[0]);
        }
    }

    #[test]
    fn monero_starts_and_ends_with_both_required() {
        use super::super::super::matcher::{Matcher, MatchPosition};
        use super::super::ChainKind;

        let (_keypair, spend_pub, view_pub) = super::generate_keys();
        let mut payload = [0u8; 65];
        payload[0] = super::NETWORK_BYTE_MAINNET;
        payload[1..33].copy_from_slice(&spend_pub);
        payload[33..65].copy_from_slice(&view_pub);

        let addr = Monero::encode_address(&payload);
        let actual_prefix = &addr[1..3];
        let actual_suffix = &addr[addr.len() - 3..];

        let wrong_suffix = if actual_suffix == "zzz" { "aaa" } else { "zzz" };
        let m = Matcher::new(
            actual_prefix.to_string(),
            wrong_suffix.to_string(),
            MatchPosition::StartsAndEndsWith,
            true,
            ChainKind::Monero,
        );
        assert!(!Monero::matches_raw(&m, &payload), "must reject wrong suffix");

        let m = Matcher::new(
            actual_prefix.to_string(),
            actual_suffix.to_string(),
            MatchPosition::StartsAndEndsWith,
            true,
            ChainKind::Monero,
        );
        assert!(Monero::matches_raw(&m, &payload), "must accept both correct");
    }

    #[test]
    fn monero_case_insensitive_suffix_match() {
        use super::super::super::matcher::{Matcher, MatchPosition};
        use super::super::ChainKind;

        let (_, spend_pub, view_pub) = super::generate_keys();
        let mut payload = [0u8; 65];
        payload[0] = super::NETWORK_BYTE_MAINNET;
        payload[1..33].copy_from_slice(&spend_pub);
        payload[33..65].copy_from_slice(&view_pub);
        let addr = Monero::encode_address(&payload);
        let actual_suffix_upper = addr[addr.len() - 3..].to_uppercase();

        // User types suffix in uppercase; case_sensitive=false → should still match
        let m = Matcher::new(
            String::new(),
            actual_suffix_upper,
            MatchPosition::EndsWith,
            false, // case_sensitive=false
            ChainKind::Monero,
        );
        assert!(Monero::matches_raw(&m, &payload));
    }

    #[test]
    fn monero_user_reported_scenario_8888_prefix_888_suffix() {
        use super::super::super::matcher::{Matcher, MatchPosition};
        use super::super::ChainKind;

        let m = Matcher::new(
            "8888".to_string(),
            "888".to_string(),
            MatchPosition::StartsAndEndsWith,
            true,
            ChainKind::Monero,
        );
        assert_eq!(m.prefix, "8888");
        assert_eq!(m.suffix, "888");
    }

    #[test]
    fn keccak256_empty_vector() {
        // Monero Keccak-256 of empty input. Reference: original Keccak (pre-FIPS-202), which is
        // what Monero uses, hashes "" to c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
        let h = keccak256(&[]);
        let expected = hex::decode("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470").unwrap();
        assert_eq!(h.as_slice(), expected.as_slice());
    }
}
