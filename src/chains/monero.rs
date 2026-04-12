use super::super::matcher::Matcher;
use super::Chain;
use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;
use rand::RngCore;
use tiny_keccak::{Hasher, Keccak};

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

        // Monero doesn't use BIP-39 — mnemonic field left empty.
        (payload, keypair, String::new())
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
        if let Some(ref want) = matcher.monero_prefix {
            // Vanity applies after fixed leading '4'
            addr.len() >= 1 + want.len() && addr[1..].starts_with(want.as_str())
        } else {
            matcher.matches_str(&addr)
        }
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
    fn keccak256_empty_vector() {
        // Monero Keccak-256 of empty input. Reference: original Keccak (pre-FIPS-202), which is
        // what Monero uses, hashes "" to c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
        let h = keccak256(&[]);
        let expected = hex::decode("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470").unwrap();
        assert_eq!(h.as_slice(), expected.as_slice());
    }
}
