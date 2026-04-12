use super::super::matcher::Matcher;
use super::ton_cell::{wallet_v5r1_state_init, W5_MAINNET_WALLET_ID};
use super::ton_mnemonic::generate_ton_wallet;
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

/// Compute the wallet-v5r1 (W5) account_id for a pubkey via proper TVM cell
/// hashing.
///
/// The account_id is the representation hash of the StateInit cell:
/// `SHA-256(refs_desc || bits_desc || data || code_depth || data_depth || code_hash || data_hash)`,
/// where the code ref is wallet-v5r1's constant code cell and the data ref
/// is `sig_allowed(1) || seqno(u32=0) || wallet_id(i32) || pubkey(u256) ||
/// extensions_dict(1=empty)` packed into 322 bits.
///
/// W5 is now Tonkeeper's default wallet version. Verified against Tonkeeper's
/// own computation in `ton_tonkeeper_round_trip_vector`: for the canonical
/// mnemonic that function produces the exact `UQAkFC...` W5 address Tonkeeper
/// displays.
fn account_id_from_pubkey(pubkey: &[u8; 32]) -> [u8; 32] {
    wallet_v5r1_state_init(pubkey, W5_MAINNET_WALLET_ID).hash()
}

impl Chain for Ton {
    const LABEL: &'static str = "TON";
    // Base64url alphabet (A-Z a-z 0-9 - _)
    const CHARSET: &'static str =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    // Reduced from 6: TON's native mnemonic is ~100x slower than other chains due to
    // 100,000 PBKDF2-HMAC-SHA512 iterations per valid wallet (plus a ~1/256 acceptance
    // filter). A 4-char vanity is the practical maximum; 5+ chars would take days to
    // months at realistic multi-threaded throughput (~100 wallets/sec).
    const MAX_VANITY: usize = 4;

    /// 36 bytes: tag(1) || workchain(1) || account_id(32) || crc16(2)
    type AddressBytes = [u8; 36];
    type SecretRaw = SigningKey;

    fn generate() -> (Self::AddressBytes, Self::SecretRaw, String) {
        let (phrase, signing_key) = generate_ton_wallet();
        let pubkey: [u8; 32] = signing_key.verifying_key().to_bytes();

        let account = account_id_from_pubkey(&pubkey);

        let mut addr = [0u8; 36];
        addr[0] = 0x51; // non-bounceable mainnet (UQ) — Tonkeeper's default receive tag
        addr[1] = 0x00; // mainnet workchain
        addr[2..34].copy_from_slice(&account);
        let crc = crc16_xmodem(&addr[..34]);
        addr[34] = (crc >> 8) as u8;
        addr[35] = crc as u8;

        (addr, signing_key, phrase)
    }

    fn encode_address(bytes: &Self::AddressBytes) -> String {
        URL_SAFE_NO_PAD.encode(bytes)
    }

    fn encode_secret(raw: &Self::SecretRaw) -> String {
        hex::encode(raw.to_bytes())
    }

    fn matches_raw(matcher: &Matcher, bytes: &Self::AddressBytes) -> bool {
        let encoded = Ton::encode_address(bytes);
        // TON vanity applies after the fixed tag prefix ("UQ" non-bounceable mainnet) — 2 chars
        const FIXED_PREFIX_LEN: usize = 2;
        let vanity_target = if encoded.len() > FIXED_PREFIX_LEN {
            &encoded[FIXED_PREFIX_LEN..]
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
                encoded.ends_with(&matcher.suffix)
            } else {
                let encoded_bytes = encoded.as_bytes();
                let start = encoded_bytes.len().saturating_sub(matcher.suffix.len());
                encoded_bytes[start..].eq_ignore_ascii_case(matcher.suffix.as_bytes())
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
    fn ton_address_starts_with_uq_and_is_48_chars() {
        // TON's native mnemonic uses randomness with a ~1/256 rejection rate,
        // so we can't pin to a canonical phrase. Generate a fresh wallet and
        // verify format invariants.
        let (_phrase, sk) = super::super::ton_mnemonic::generate_ton_wallet();
        let pubkey = sk.verifying_key().to_bytes();
        let account = account_id_from_pubkey(&pubkey);

        let mut addr = [0u8; 36];
        addr[0] = 0x51;
        addr[1] = 0x00;
        addr[2..34].copy_from_slice(&account);
        let crc = crc16_xmodem(&addr[..34]);
        addr[34] = (crc >> 8) as u8;
        addr[35] = crc as u8;

        let encoded = Ton::encode_address(&addr);
        assert_eq!(encoded.len(), 48, "TON addresses must be 48 chars, got: {}", encoded);
        assert!(encoded.starts_with("UQ"), "non-bounceable mainnet must start with UQ, got: {}", encoded);
    }

    #[test]
    fn ton_starts_and_ends_with_both_required() {
        use super::super::super::matcher::{Matcher, MatchPosition};
        use super::super::ChainKind;

        let (_phrase, sk) = super::super::ton_mnemonic::generate_ton_wallet();
        let pubkey = sk.verifying_key().to_bytes();
        let account = account_id_from_pubkey(&pubkey);

        let mut addr = [0u8; 36];
        addr[0] = 0x51;
        addr[1] = 0x00;
        addr[2..34].copy_from_slice(&account);
        let crc = crc16_xmodem(&addr[..34]);
        addr[34] = (crc >> 8) as u8;
        addr[35] = crc as u8;

        let encoded = Ton::encode_address(&addr);
        // encoded starts with "UQ" — vanity target begins after that.
        let vanity_target = &encoded[2..];
        let actual_prefix = &vanity_target[..3];
        let actual_suffix = &encoded[encoded.len() - 3..];

        let wrong_suffix = if actual_suffix == "zzz" { "aaa" } else { "zzz" };
        let m = Matcher::new(
            actual_prefix.to_string(),
            wrong_suffix.to_string(),
            MatchPosition::StartsAndEndsWith,
            true,
            ChainKind::Ton,
        );
        assert!(!Ton::matches_raw(&m, &addr), "must reject wrong suffix");

        let m = Matcher::new(
            actual_prefix.to_string(),
            actual_suffix.to_string(),
            MatchPosition::StartsAndEndsWith,
            true,
            ChainKind::Ton,
        );
        assert!(Ton::matches_raw(&m, &addr), "must accept both correct");
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

        let account = account_id_from_pubkey(&pubkey);

        let mut addr = [0u8; 36];
        addr[0] = 0x51; // non-bounceable mainnet (UQ) — Tonkeeper default
        addr[1] = 0x00; // mainnet workchain
        addr[2..34].copy_from_slice(&account);
        let crc = crc16_xmodem(&addr[..34]);
        addr[34] = (crc >> 8) as u8;
        addr[35] = crc as u8;

        let encoded = Ton::encode_address(&addr);
        assert_eq!(encoded, "UQAkFCMtkN0Q1TNP6Gk9SqYWsBFc6Aglwckj6ES4AeBEzWja");
    }
}
