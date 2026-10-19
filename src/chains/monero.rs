use super::super::matcher::Matcher;
use super::Chain;
use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;
use rand::RngCore;
use sha3::{Digest, Keccak256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::monero_wordlist::MONERO_WORDLIST;

pub struct Monero;

const NETWORK_BYTE_MAINNET: u8 = 0x12;

/// Monero uses the original Keccak-256 (not FIPS-202 SHA3-256 — they differ in padding).
/// sha3's Keccak256 is that variant (the one EVM addresses use too).
fn keccak256(data: &[u8]) -> [u8; 32] {
    Keccak256::digest(data).into()
}

/// Raw Monero keypair: spend_sec, spend_pub, view_sec, view_pub.
#[derive(Zeroize, ZeroizeOnDrop)]
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
    let mut spend_scalar = Scalar::from_bytes_mod_order(spend_raw);
    spend_raw.zeroize();
    let spend_pub = (&spend_scalar * ED25519_BASEPOINT_TABLE).compress().to_bytes();

    let mut view_raw = keccak256(spend_scalar.as_bytes());
    let mut view_scalar = Scalar::from_bytes_mod_order(view_raw);
    view_raw.zeroize();
    let view_pub = (&view_scalar * ED25519_BASEPOINT_TABLE).compress().to_bytes();

    let keypair = MoneroKeypair {
        spend_sec: spend_scalar.to_bytes(),
        view_sec: view_scalar.to_bytes(),
    };
    spend_scalar.zeroize();
    view_scalar.zeroize();
    (keypair, spend_pub, view_pub)
}

/// Encode a Monero spend key as a 25-word Electrum-style mnemonic.
/// Compatible with monero-wallet-cli --restore-deterministic-wallet.
pub fn monero_seed_phrase(spend_sec: &[u8; 32]) -> String {
    const N: u32 = 1626;
    const PREFIX_LEN: usize = 3;

    // Word indices (and `trimmed`) encode spend_sec losslessly, so both are
    // wiped; a Vec<&str> of the words themselves could not be.
    let mut words: Vec<usize> = Vec::with_capacity(25);

    for i in 0..8 {
        let chunk = &spend_sec[i * 4..i * 4 + 4];
        let x = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        let w1 = x % N;
        let w2 = (x / N + w1) % N;
        let w3 = (x / N / N + w2) % N;
        words.push(w1 as usize);
        words.push(w2 as usize);
        words.push(w3 as usize);
    }

    // Checksum: CRC32 over concatenation of first PREFIX_LEN chars of each word.
    // All Monero English words are ASCII and length >= 4, so byte-slicing is safe.
    let mut trimmed = String::with_capacity(24 * PREFIX_LEN);
    for &i in &words {
        let w = MONERO_WORDLIST[i];
        trimmed.push_str(&w[..PREFIX_LEN.min(w.len())]);
    }

    let cksum = crc32fast::hash(trimmed.as_bytes());
    trimmed.zeroize();
    let checksum_idx = (cksum as usize) % 24;
    words.push(words[checksum_idx]);

    // Sized up front: a realloc would free an unwiped partial copy.
    let len = words.iter().map(|&i| MONERO_WORDLIST[i].len() + 1).sum();
    let mut phrase = String::with_capacity(len);
    for &i in &words {
        if !phrase.is_empty() {
            phrase.push(' ');
        }
        phrase.push_str(MONERO_WORDLIST[i]);
    }
    words.zeroize();
    phrase
}

/// Monero Base58 encodes in 8-byte blocks → 11 chars each (last block may be shorter).
/// Writes into `out` (no heap) and returns the number of bytes written.
/// `out` must hold at least `(data.len() + 7) / 8 * 11` bytes.
fn monero_base58_encode_into(data: &[u8], out: &mut [u8]) -> usize {
    const ALPHABET: &[u8] =
        b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    const BLOCK_SIZES: &[usize] = &[0, 2, 3, 5, 6, 7, 9, 10, 11];

    let mut written = 0;
    for chunk in data.chunks(8) {
        let mut num: u128 = 0;
        for &b in chunk {
            num = num * 256 + b as u128;
        }
        let enc_len = BLOCK_SIZES[chunk.len()];
        // Longest block is 11 chars. Pad with '1' (alphabet index 0), same as before.
        let mut block = [b'1'; 11];
        let mut i = enc_len;
        while num > 0 && i > 0 {
            i -= 1;
            block[i] = ALPHABET[(num % 58) as usize];
            num /= 58;
        }
        out[written..written + enc_len].copy_from_slice(&block[..enc_len]);
        written += enc_len;
    }
    written
}

#[cfg(test)]
fn monero_base58_encode(data: &[u8]) -> String {
    let cap = (data.len() + 7) / 8 * 11;
    let mut buf = vec![0u8; cap];
    let n = monero_base58_encode_into(data, &mut buf);
    buf.truncate(n);
    String::from_utf8(buf).unwrap()
}

/// 69-byte payload (65-byte address + 4-byte checksum) encodes to 95 chars.
const MONERO_ADDRESS_LEN: usize = 95;

fn encode_address_into(bytes: &[u8; 65], out: &mut [u8; MONERO_ADDRESS_LEN]) -> usize {
    let mut full = [0u8; 69];
    full[..65].copy_from_slice(bytes);
    let checksum = keccak256(bytes);
    full[65..].copy_from_slice(&checksum[..4]);
    monero_base58_encode_into(&full, out)
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
        let mut buf = [0u8; MONERO_ADDRESS_LEN];
        let n = encode_address_into(bytes, &mut buf);
        std::str::from_utf8(&buf[..n]).unwrap().to_owned()
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
        // Monero vanity applies after the leading "4" (mainnet network byte).
        const FIXED_PREFIX_LEN: usize = 1;
        let mut buf = [0u8; MONERO_ADDRESS_LEN];
        let n = encode_address_into(bytes, &mut buf);
        let addr = std::str::from_utf8(&buf[..n]).unwrap();
        let vanity_target = addr.get(FIXED_PREFIX_LEN..).unwrap_or("");
        matcher.prefix_matches(vanity_target) && matcher.suffix_matches(addr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn monero_address_starts_with_4_and_is_95_chars() {
        let (payload, keypair, _) = Monero::generate();
        let addr = Monero::encode_address(&payload);
        assert_eq!(addr.len(), 95, "Monero mainnet addresses are 95 chars, got len={}: {}", addr.len(), addr);
        assert!(addr.starts_with('4'), "network byte 0x12 must produce leading '4', got: {}", addr);
        // Exercise encode_secret path
        let secret = Monero::encode_secret(&keypair);
        assert!(secret.contains(':'));
        assert_eq!(secret.len(), 64 + 1 + 64, "spend_hex:view_hex = 64+1+64 chars");
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
        use super::super::{assert_prefix_suffix, ChainKind};

        let (payload, _, _) = Monero::generate();
        assert_prefix_suffix::<Monero>(ChainKind::Monero, &payload, 1, true);
    }

    #[test]
    fn monero_matches_raw_agrees_with_encode_address() {
        use super::super::super::matcher::Matcher;
        use super::super::ChainKind;

        let mut payload = [0u8; 65];
        payload[0] = NETWORK_BYTE_MAINNET;
        payload[1] = 0xAB;
        payload[64] = 0xCD;

        let addr = Monero::encode_address(&payload);
        assert_eq!(addr.len(), 95);
        assert!(addr.starts_with('4'));

        let prefix = addr[1..2].to_string();
        let suffix = addr[addr.len() - 1..].to_string();
        let matcher = Matcher::new(prefix, suffix.clone(), true, ChainKind::Monero);
        assert!(matcher.prefix_matches(&addr[1..]));
        assert!(matcher.suffix_matches(&addr));
        assert!(Monero::matches_raw(&matcher, &payload));

        let missing = if addr.as_bytes()[1] == b'2' { "3" } else { "2" };
        let missing_prefix = Matcher::new(missing.to_string(), suffix, true, ChainKind::Monero);
        assert!(!matcher.prefix_matches(&addr[..1]));
        assert!(!Monero::matches_raw(&missing_prefix, &payload));
    }

    #[test]
    fn monero_case_insensitive_suffix_match() {
        use super::super::super::matcher::Matcher;
        use super::super::ChainKind;

        let (payload, _, _) = Monero::generate();
        let addr = Monero::encode_address(&payload);
        let actual_suffix_upper = addr[addr.len() - 3..].to_uppercase();

        // User types suffix in uppercase; case_sensitive=false → should still match
        let m = Matcher::new(
            String::new(),
            actual_suffix_upper,
            false, // case_sensitive=false
            ChainKind::Monero,
        );
        assert!(Monero::matches_raw(&m, &payload));
    }

    #[test]
    fn monero_base58_known_vectors() {
        // Empty input
        assert_eq!(monero_base58_encode(&[]), "");

        // 1-byte block: 0x00 → 2 chars
        // Published vector: byte 0x00 base58-encoded in Monero's 8-byte-block scheme
        // produces "11" (the alphabet's index 0 is '1').
        assert_eq!(monero_base58_encode(&[0x00]), "11");

        // u64::MAX in one full 8-byte block → 11 Base58 chars
        let all_ff = [0xffu8; 8];
        let encoded = monero_base58_encode(&all_ff);
        assert_eq!(encoded.len(), 11);
        assert_eq!(encoded, "jpXCZedGfVQ");
    }

    /// Non-degenerate pin: all-zeros cannot catch a word-order or checksum-index
    /// slip. Captured from the encoder before it switched to wipeable indices.
    #[test]
    fn monero_seed_phrase_sequential_bytes_pinned() {
        let k: [u8; 32] = std::array::from_fn(|i| i as u8);
        assert_eq!(
            monero_seed_phrase(&k),
            "amaze buffet cake entrance symptoms tiger lamb maze nestle python dusted \
             faxed update vague zinger boxes ornament renting glass gained island \
             nabbing afield calamity boxes"
        );
    }

    /// The address must belong to the phrase: view_sec = H(spend_sec) mod l and
    /// each pub is its secret times G. Catches a wipe that lands too early.
    #[test]
    fn monero_generate_keys_are_consistent() {
        let (payload, kp, _) = Monero::generate();
        let spend = Scalar::from_bytes_mod_order(kp.spend_sec);
        let view = Scalar::from_bytes_mod_order(keccak256(&kp.spend_sec));
        assert_eq!(view.to_bytes(), kp.view_sec);
        let pub_of = |s: &Scalar| (s * ED25519_BASEPOINT_TABLE).compress().to_bytes();
        assert_eq!(payload[1..33], pub_of(&spend));
        assert_eq!(payload[33..], pub_of(&view));
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
