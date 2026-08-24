use ring::hmac;
use secp256k1::{PublicKey, Scalar, SecretKey};

/// BIP-32 child key derivation for secp256k1.
/// `path` is a slice of indices; indices ≥ 0x80000000 are hardened.
pub fn bip32_derive_secp256k1(seed: &[u8], path: &[u32]) -> SecretKey {
    let master_key = hmac::Key::new(hmac::HMAC_SHA512, b"Bitcoin seed");
    let result = hmac::sign(&master_key, seed);
    let result = result.as_ref();
    let mut key = SecretKey::from_byte_array(result[..32].try_into().expect("32 bytes"))
        .expect("valid master key");
    let mut chain_code = [0u8; 32];
    chain_code.copy_from_slice(&result[32..]);

    for &index in path {
        let hmac_key = hmac::Key::new(hmac::HMAC_SHA512, &chain_code);
        let mut data = [0u8; 37];
        if index >= 0x80000000 {
            data[0] = 0x00;
            data[1..33].copy_from_slice(&key.secret_bytes());
        } else {
            data[..33].copy_from_slice(&PublicKey::from_secret_key_global(&key).serialize());
        }
        data[33..].copy_from_slice(&index.to_be_bytes());
        let result = hmac::sign(&hmac_key, &data);
        let result = result.as_ref();

        let il = Scalar::from_be_bytes(result[..32].try_into().expect("32 bytes")).expect("valid IL");
        key = key.add_tweak(&il).expect("valid tweak");
        chain_code.copy_from_slice(&result[32..]);
    }

    key
}

/// BIP-44 Ethereum: m/44'/60'/0'/0/0
pub const EVM_PATH: [u32; 5] = [0x8000002C, 0x8000003C, 0x80000000, 0, 0];

/// BIP-84 Bitcoin: m/84'/0'/0'/0/0
pub const BTC_BIP84_PATH: [u32; 5] = [0x80000054, 0x80000000, 0x80000000, 0, 0];
