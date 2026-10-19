use ring::hmac;
use secp256k1::{PublicKey, Scalar, SecretKey};

/// HMAC-SHA512 of `data` under `key`, split into its left and right halves.
fn hmac512(key: &[u8], data: &[u8]) -> ([u8; 32], [u8; 32]) {
    let tag = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA512, key), data);
    let (l, r) = tag.as_ref().split_at(32);
    (l.try_into().unwrap(), r.try_into().unwrap())
}

/// BIP-32 child key derivation for secp256k1.
/// `path` is a slice of indices; indices ≥ 0x80000000 are hardened.
pub fn bip32_derive_secp256k1(seed: &[u8], path: &[u32]) -> SecretKey {
    let (master, mut chain_code) = hmac512(b"Bitcoin seed", seed);
    let mut key = SecretKey::from_byte_array(&master).expect("valid master key");

    for &index in path {
        let mut data = [0u8; 37];
        if index >= 0x80000000 {
            data[0] = 0x00;
            data[1..33].copy_from_slice(&key.secret_bytes());
        } else {
            data[..33].copy_from_slice(&PublicKey::from_secret_key_global(&key).serialize());
        }
        data[33..].copy_from_slice(&index.to_be_bytes());
        let (il, child_chain_code) = hmac512(&chain_code, &data);

        let il = Scalar::from_be_bytes(il).expect("valid IL");
        key = key.add_tweak(&il).expect("valid tweak");
        chain_code = child_chain_code;
    }

    key
}

/// BIP-44 Ethereum: m/44'/60'/0'/0/0
pub const EVM_PATH: [u32; 5] = [0x8000002C, 0x8000003C, 0x80000000, 0, 0];

/// BIP-84 Bitcoin: m/84'/0'/0'/0/0
pub const BTC_BIP84_PATH: [u32; 5] = [0x80000054, 0x80000000, 0x80000000, 0, 0];
