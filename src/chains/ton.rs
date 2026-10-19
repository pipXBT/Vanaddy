use super::super::matcher::Matcher;
use super::ton_cell::wallet_v5r1_state_init_hash;
use super::ton_mnemonic::{generate_ton_wallet, generate_ton_wallets};
use crate::pbkdf2_lanes::LANES;
use super::Chain;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::SigningKey;

pub struct Ton;

/// CRC16/XMODEM polynomial 0x1021 (TON address checksum variant).
fn crc16_xmodem(data: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for &b in data {
        crc ^= (b as u16) << 8;
        for _ in 0..8 {
            if (crc & 0x8000) != 0 {
                crc = (crc << 1) ^ 0x1021;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

impl Ton {
    /// Raw user-friendly address: tag(1) || workchain(1) || account_id(32) || crc16(2).
    fn address_bytes(pubkey: &[u8; 32]) -> [u8; 36] {
        let mut addr = [0u8; 36];
        addr[0] = 0x51; // non-bounceable mainnet (UQ) — Tonkeeper's default receive tag
        addr[1] = 0x00; // mainnet workchain
        addr[2..34].copy_from_slice(&wallet_v5r1_state_init_hash(pubkey)); // account_id
        let crc = crc16_xmodem(&addr[..34]);
        addr[34] = (crc >> 8) as u8;
        addr[35] = crc as u8;
        addr
    }

    /// 36-byte user-friendly address as 48 ASCII chars of URL-safe unpadded base64.
    fn user_friendly_ascii(bytes: &[u8; 36]) -> [u8; 48] {
        let mut out = [0u8; 48];
        let n = URL_SAFE_NO_PAD
            .encode_slice(bytes, &mut out)
            .expect("48-byte buffer holds a 36-byte unpadded base64 address");
        assert_eq!(n, 48);
        out
    }
}

impl Chain for Ton {
    const LABEL: &'static str = "TON";
    // Base64url alphabet (A-Z a-z 0-9 - _)
    const CHARSET: &'static str =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    // Reduced from 6: TON's native mnemonic is ~100x slower than other chains due to
    // 100,000 PBKDF2-HMAC-SHA512 iterations per valid wallet (plus a ~1/256 acceptance
    // filter). A 4-char vanity is the practical maximum; 5+ chars would take days to
    // months at realistic multi-threaded throughput (~200 wallets/sec on an M1).
    const MAX_VANITY: usize = 4;
    const BATCH: usize = LANES;

    /// 36 bytes: tag(1) || workchain(1) || account_id(32) || crc16(2)
    type AddressBytes = [u8; 36];
    type SecretRaw = SigningKey;

    fn generate() -> (Self::AddressBytes, Self::SecretRaw, String) {
        let (phrase, signing_key) = generate_ton_wallet();
        let addr = Self::address_bytes(&signing_key.verifying_key().to_bytes());
        (addr, signing_key, phrase)
    }

    fn generate_batch(mut emit: impl FnMut(Self::AddressBytes, Self::SecretRaw, String)) {
        for (phrase, signing_key) in generate_ton_wallets() {
            let addr = Self::address_bytes(&signing_key.verifying_key().to_bytes());
            emit(addr, signing_key, phrase);
        }
    }

    fn encode_address(bytes: &Self::AddressBytes) -> String {
        let ascii = Self::user_friendly_ascii(bytes);
        String::from_utf8(ascii.to_vec()).expect("base64 alphabet is ASCII")
    }

    fn encode_secret(raw: &Self::SecretRaw) -> String {
        hex::encode(raw.to_bytes())
    }

    fn matches_raw(matcher: &Matcher, bytes: &Self::AddressBytes) -> bool {
        // TON vanity applies after the fixed tag prefix "UQ" (non-bounceable mainnet).
        const FIXED_PREFIX_LEN: usize = 2;
        let ascii = Self::user_friendly_ascii(bytes);
        let encoded = str::from_utf8(&ascii).expect("base64 alphabet is ASCII");
        let vanity_target = encoded.get(FIXED_PREFIX_LEN..).unwrap_or("");
        matcher.prefix_matches(vanity_target) && matcher.suffix_matches(encoded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_raw_agrees_with_encode_address_for_one_char_affix() {
        use super::super::super::matcher::Matcher;
        use super::super::ChainKind;

        let (_phrase, sk) = super::super::ton_mnemonic::generate_ton_wallet();
        let addr = Ton::address_bytes(&sk.verifying_key().to_bytes());
        let encoded = Ton::encode_address(&addr);
        let prefix = &encoded[2..3];
        let suffix = &encoded[encoded.len() - 1..];
        let missing = if prefix == "A" { "B" } else { "A" };

        let hit = Matcher::new(prefix.to_string(), suffix.to_string(), true, ChainKind::Ton);
        assert!(
            Ton::matches_raw(&hit, &addr),
            "1-char prefix after UQ and 1-char suffix must match {}",
            encoded
        );

        let miss = Matcher::new(missing.to_string(), suffix.to_string(), true, ChainKind::Ton);
        assert!(
            !Ton::matches_raw(&miss, &addr),
            "must reject a prefix that is not the character after UQ"
        );
    }

    #[test]
    fn ton_starts_and_ends_with_both_required() {
        use super::super::{assert_prefix_suffix, ChainKind};

        let (_phrase, sk) = generate_ton_wallet();
        let addr = Ton::address_bytes(&sk.verifying_key().to_bytes());
        // Vanity starts after "UQ".
        assert_prefix_suffix::<Ton>(ChainKind::Ton, &addr, 2, true);
    }

    #[test]
    fn crc16_known_vector() {
        // CRC-16/XMODEM of ASCII "123456789" is 0x31C3 per standard test vectors
        assert_eq!(crc16_xmodem(b"123456789"), 0x31C3);
    }

    /// Tonkeeper round-trip: for this 24-word TON-native mnemonic, Tonkeeper's
    /// "Versions" screen shows the W5 address `UQAkFC...` as the default.
    /// vanaddy MUST produce the same address; if this test fails, funds sent
    /// to a displayed vanity address would go to a wallet nobody controls.
    ///
    /// This is the correctness anchor for the entire TVM cell-hashing pipeline:
    /// if this passes, mnemonic derivation, data-cell layout, state_init
    /// encoding, code-cell constants, and base64 address formatting are all
    /// verified against Tonkeeper's own W5 (v5r1) computation.
    #[test]
    fn ton_tonkeeper_round_trip_vector() {
        use super::super::ton_mnemonic::mnemonic_to_signing_key;

        let phrase = "cloth orbit much expose crater arrow success drop verify then letter song field million quantum fame ankle stereo quote rhythm believe farm property tube";
        let sk = mnemonic_to_signing_key(phrase);
        let pubkey: [u8; 32] = sk.verifying_key().to_bytes();

        let encoded = Ton::encode_address(&Ton::address_bytes(&pubkey));
        assert_eq!(encoded, "UQAkFCMtkN0Q1TNP6Gk9SqYWsBFc6Aglwckj6ES4AeBEzWja");
    }

    #[test]
    fn generate_batch_emits_lane_count_wallets_with_consistent_addresses() {
        use super::super::ton_mnemonic::mnemonic_to_signing_key;
        use crate::pbkdf2_lanes::LANES;
        let mut got = Vec::new();
        Ton::generate_batch(|addr, secret, phrase| got.push((addr, secret, phrase)));
        assert_eq!(Ton::BATCH, LANES);
        assert_eq!(got.len(), LANES);
        for (addr, secret, phrase) in &got {
            let sk = mnemonic_to_signing_key(phrase);
            assert_eq!(sk.to_bytes(), secret.to_bytes(), "batch key must match single-path derivation");
            assert_eq!(addr, &Ton::address_bytes(&sk.verifying_key().to_bytes()));
        }
    }
}
