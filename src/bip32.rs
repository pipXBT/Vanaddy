use ring::hmac;

/// BIP-32 child key derivation for secp256k1.
/// `path` is a slice of indices; indices ≥ 0x80000000 are hardened.
pub fn bip32_derive_secp256k1(seed: &[u8], path: &[u32]) -> libsecp256k1::SecretKey {
    let master_key = hmac::Key::new(hmac::HMAC_SHA512, b"Bitcoin seed");
    let result = hmac::sign(&master_key, seed);
    let result = result.as_ref();
    let mut key = [0u8; 32];
    let mut chain_code = [0u8; 32];
    key.copy_from_slice(&result[..32]);
    chain_code.copy_from_slice(&result[32..]);

    for &index in path {
        let hmac_key = hmac::Key::new(hmac::HMAC_SHA512, &chain_code);
        let parent = libsecp256k1::SecretKey::parse_slice(&key).expect("valid key");

        let result = if index >= 0x80000000 {
            let mut data = [0u8; 37];
            data[1..33].copy_from_slice(&key);
            data[33..].copy_from_slice(&index.to_be_bytes());
            hmac::sign(&hmac_key, &data)
        } else {
            let pk = libsecp256k1::PublicKey::from_secret_key(&parent);
            let mut data = [0u8; 37];
            data[..33].copy_from_slice(&pk.serialize_compressed());
            data[33..].copy_from_slice(&index.to_be_bytes());
            hmac::sign(&hmac_key, &data)
        };

        let result = result.as_ref();
        let il_key = libsecp256k1::SecretKey::parse_slice(&result[..32]).expect("valid IL");
        let mut child = parent;
        child.tweak_add_assign(&il_key).expect("valid tweak");
        key.copy_from_slice(&child.serialize());
        chain_code.copy_from_slice(&result[32..]);
    }

    libsecp256k1::SecretKey::parse_slice(&key).expect("valid derived key")
}

/// BIP-44 Ethereum: m/44'/60'/0'/0/0
pub const EVM_PATH: [u32; 5] = [0x8000002C, 0x8000003C, 0x80000000, 0, 0];

/// BIP-84 Bitcoin: m/84'/0'/0'/0/0
pub const BTC_BIP84_PATH: [u32; 5] = [0x80000054, 0x80000000, 0x80000000, 0, 0];
