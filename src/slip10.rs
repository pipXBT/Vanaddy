use ring::hmac;

/// SLIP-0010 Ed25519 child-key derivation.
/// All indices in `path` MUST be hardened (>= 0x80000000); Ed25519 does not support
/// non-hardened derivation. Panics if a non-hardened index is supplied.
pub fn slip10_derive_ed25519(seed: &[u8], path: &[u32]) -> [u8; 32] {
    // Master key
    let key = hmac::Key::new(hmac::HMAC_SHA512, b"ed25519 seed");
    let master = hmac::sign(&key, seed);
    let master = master.as_ref();
    let mut key_bytes = [0u8; 32];
    let mut chain_code = [0u8; 32];
    key_bytes.copy_from_slice(&master[..32]);
    chain_code.copy_from_slice(&master[32..]);

    for &index in path {
        assert!(
            index >= 0x80000000,
            "SLIP-0010 Ed25519 requires hardened indices (>= 0x80000000); got {:#x}",
            index
        );
        let hmac_key = hmac::Key::new(hmac::HMAC_SHA512, &chain_code);
        let mut data = [0u8; 37];
        data[0] = 0x00;
        data[1..33].copy_from_slice(&key_bytes);
        data[33..].copy_from_slice(&index.to_be_bytes());
        let result = hmac::sign(&hmac_key, &data);
        let result = result.as_ref();
        key_bytes.copy_from_slice(&result[..32]);
        chain_code.copy_from_slice(&result[32..]);
    }

    key_bytes
}

/// Phantom wallet derivation path: m/44'/501'/0'/0'
pub const PHANTOM_SOLANA_PATH: [u32; 4] =
    [0x8000002C, 0x800001F5, 0x80000000, 0x80000000];

#[cfg(test)]
mod tests {
    use super::*;

    /// SLIP-0010 test vector 1 from the spec (https://github.com/satoshilabs/slips/blob/master/slip-0010.md)
    /// Seed: 000102030405060708090a0b0c0d0e0f
    /// Path: m/0'
    /// Expected key: 68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3
    #[test]
    fn slip10_ed25519_test_vector_1_m_0h() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let key = slip10_derive_ed25519(&seed, &[0x80000000]);
        let expected = hex::decode("68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3").unwrap();
        assert_eq!(key.as_slice(), expected.as_slice());
    }

    /// SLIP-0010 test vector 1, path m/0'/1'
    /// Expected key: b1d0bad404bf35da785a64ca1ac54b2617211d2777696fbffaf208f746ae84f2
    #[test]
    fn slip10_ed25519_test_vector_1_m_0h_1h() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let key = slip10_derive_ed25519(&seed, &[0x80000000, 0x80000001]);
        let expected = hex::decode("b1d0bad404bf35da785a64ca1ac54b2617211d2777696fbffaf208f746ae84f2").unwrap();
        assert_eq!(key.as_slice(), expected.as_slice());
    }

    #[test]
    #[should_panic(expected = "hardened")]
    fn slip10_rejects_unhardened() {
        let seed = [0u8; 64];
        let _ = slip10_derive_ed25519(&seed, &[0]); // 0 is non-hardened
    }
}
