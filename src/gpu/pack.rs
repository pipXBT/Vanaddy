//! Host-side packing of PBKDF2 inputs into the exact 16-word big-endian blocks
//! the Metal kernel consumes. Every byte-level decision - zero padding, INT(1),
//! the 0x80 terminator, the 128-bit length field, endianness - lives here in
//! Rust, where it is testable with no GPU. The kernel therefore contains zero
//! endianness code and zero padding code.

use crate::gpu::GpuError;
use zeroize::Zeroize;

/// One zero-padded HMAC key block, decoded to 16 big-endian u64 words.
#[repr(C, align(16))]
#[derive(Clone, Copy, Zeroize)]
pub struct KeyBlock(pub [u64; 16]);

/// Hard assert, NOT debug_assert: a longer key would be silently zero-padded by
/// the GPU instead of SHA-512 pre-hashed (the CPU reference pre-hashes at
/// src/pbkdf2_lanes.rs:244), producing a wrong-but-plausible seed.
/// A 12-word English phrase is provably 47..=107 bytes.
pub fn pack_key_block(password: &[u8]) -> KeyBlock {
    assert!(
        !password.is_empty() && password.len() <= crate::pbkdf2_lanes::HMAC_BLOCK_LEN,
        "GPU PBKDF2 key must be 1..={} bytes (no pre-hash path), got {}",
        crate::pbkdf2_lanes::HMAC_BLOCK_LEN,
        password.len()
    );
    let mut b = [0u8; 128];
    b[..password.len()].copy_from_slice(password);
    let packed = KeyBlock(std::array::from_fn(|i| {
        u64::from_be_bytes(b[8 * i..8 * i + 8].try_into().unwrap())
    }));
    // `b` held the plaintext seed phrase; do not leave it on the stack.
    b.zeroize();
    packed
}

/// Byte-exact mirror of `padded_block(&salted[..salt.len()+4], 128)`
/// at src/pbkdf2_lanes.rs:259-262. Fallible, mirroring the CPU's MAX_SALT_LEN
/// assert at src/pbkdf2_lanes.rs:21-25.
pub fn pack_salt_block(salt: &[u8]) -> Result<[u64; 16], GpuError> {
    if salt.len() > crate::pbkdf2_lanes::MAX_SALT_LEN {
        return Err(GpuError::SaltTooLong { len: salt.len() });
    }
    let mut b = [0u8; 128];
    b[..salt.len()].copy_from_slice(salt);
    b[salt.len()..salt.len() + 4].copy_from_slice(&1u32.to_be_bytes()); // INT(1)
    b[salt.len() + 4] = 0x80;
    let bits = ((128 + salt.len() + 4) as u128) * 8;
    b[112..].copy_from_slice(&bits.to_be_bytes());
    Ok(std::array::from_fn(|i| {
        u64::from_be_bytes(b[8 * i..8 * i + 8].try_into().unwrap())
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bip39::{Language, Mnemonic, MnemonicType};

    const CANONICAL: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn words_to_bytes(words: &[u64; 16]) -> [u8; 128] {
        let mut out = [0u8; 128];
        for (i, w) in words.iter().enumerate() {
            out[8 * i..8 * i + 8].copy_from_slice(&w.to_be_bytes());
        }
        out
    }

    #[test]
    fn key_block_has_pinned_repr_c_layout() {
        // Matches the precedent set by `gpu_candidate_has_pinned_repr_c_layout`
        // (src/gpu/mod.rs): KeyBlock is uploaded to a GPU buffer and read by
        // raw byte offset, so a field reorder, alignment change, or a derive
        // that isn't repr(C)-safe would compile clean and pass every other
        // test here, then only surface as a plausible-but-wrong seed once the
        // Metal kernel reads it.
        assert_eq!(core::mem::size_of::<KeyBlock>(), 128);
        assert_eq!(core::mem::align_of::<KeyBlock>(), 16);
    }

    #[test]
    fn pack_key_block_is_big_endian_for_the_canonical_phrase() {
        assert_eq!(CANONICAL.len(), 93);
        let k = pack_key_block(CANONICAL.as_bytes());
        // "abandon " == 61 62 61 6e 64 6f 6e 20, eleven times.
        for w in k.0.iter().take(11) {
            assert_eq!(*w, 0x6162_616e_646f_6e20);
        }
        // "about" then the zero pad: 61 62 6f 75 74 00 00 00.
        assert_eq!(k.0[11], 0x6162_6f75_7400_0000);
        for w in k.0.iter().skip(12) {
            assert_eq!(*w, 0);
        }
    }

    #[test]
    fn pack_key_block_round_trips_to_the_zero_padded_password() {
        for len in [1usize, 7, 8, 9, 47, 63, 64, 65, 93, 107, 127, 128] {
            let pw: Vec<u8> = (0..len).map(|i| (i % 251) as u8 | 1).collect();
            let bytes = words_to_bytes(&pack_key_block(&pw).0);
            assert_eq!(&bytes[..len], pw.as_slice(), "len {len}");
            assert!(bytes[len..].iter().all(|&x| x == 0), "len {len} pad");
        }
    }

    #[test]
    #[should_panic(expected = "GPU PBKDF2 key must be 1..=128 bytes (no pre-hash path), got 129")]
    fn pack_key_block_rejects_a_password_over_the_hmac_block() {
        let pw = [0x61u8; 129];
        let _ = pack_key_block(&pw);
    }

    #[test]
    #[should_panic(expected = "GPU PBKDF2 key must be 1..=128 bytes (no pre-hash path), got 0")]
    fn pack_key_block_rejects_an_empty_password() {
        let _ = pack_key_block(b"");
    }

    /// The hard assert above is only safe if a real 12-word English phrase can
    /// never reach it. Shortest English BIP-39 word is 3 letters, longest is 8,
    /// so 12*3+11 = 47 and 12*8+11 = 107, both below HMAC_BLOCK_LEN = 128.
    #[test]
    fn every_english_12_word_phrase_fits_one_key_block() {
        for _ in 0..4_096 {
            let m = Mnemonic::new(MnemonicType::Words12, Language::English);
            let phrase = m.phrase().as_bytes();
            assert!(
                (47..=107).contains(&phrase.len()),
                "12-word phrase out of the proven range: {} bytes, {:?}",
                phrase.len(),
                m.phrase()
            );
            assert!(phrase.len() < crate::pbkdf2_lanes::HMAC_BLOCK_LEN);
            let bytes = words_to_bytes(&pack_key_block(phrase).0);
            assert_eq!(&bytes[..phrase.len()], phrase);
            assert!(bytes[phrase.len()..].iter().all(|&x| x == 0));
        }
    }

    /// The kernel builds ipad/opad on the GPU from this packed key block, so the
    /// packed block must reproduce EXACTLY what `hw::pbkdf2_lanes` XORs into
    /// `ipad`/`opad` (src/pbkdf2_lanes.rs:251-252 after Task 1.2's edit; 243-244
    /// before it). This is the spec's `pack_key_block_matches_reference_ipad_opad`
    /// no-GPU test: without it nothing in milestones 1-2 catches a key-block vs
    /// HMAC-key-schedule divergence.
    #[test]
    fn pack_key_block_matches_the_cpu_ipad_and_opad_blocks() {
        let long_key = [0x5cu8; 107];
        let full_key = [0x36u8; 128];
        let cases: [&[u8]; 4] = [CANONICAL.as_bytes(), b"a", &long_key, &full_key];
        for pw in cases {
            // What the CPU does: start from the pad constant, XOR the key in.
            let mut cpu_ipad = [0x36u8; 128];
            let mut cpu_opad = [0x5cu8; 128];
            for (i, &kb) in pw.iter().enumerate() {
                cpu_ipad[i] ^= kb;
                cpu_opad[i] ^= kb;
            }
            // What the GPU does: XOR the pad constant over the packed block.
            let packed = words_to_bytes(&pack_key_block(pw).0);
            let gpu_ipad: [u8; 128] = std::array::from_fn(|i| packed[i] ^ 0x36);
            let gpu_opad: [u8; 128] = std::array::from_fn(|i| packed[i] ^ 0x5c);
            assert_eq!(gpu_ipad, cpu_ipad, "ipad diverges, {}-byte key", pw.len());
            assert_eq!(gpu_opad, cpu_opad, "opad diverges, {}-byte key", pw.len());
        }
    }

    /// Literal transcription of `padded_block` (src/pbkdf2_lanes.rs:210-219)
    /// applied to `salted[..salt.len()+4]` exactly as `hw::pbkdf2_lanes` does at
    /// src/pbkdf2_lanes.rs:259-262. If the CPU padding ever changes, this
    /// transcription and `pack_salt_block` must be changed together.
    fn cpu_reference_salt_block(salt: &[u8]) -> [u8; 128] {
        let mut salted = [0u8; 111];
        salted[..salt.len()].copy_from_slice(salt);
        salted[salt.len()..salt.len() + 4].copy_from_slice(&1u32.to_be_bytes());
        let tail = &salted[..salt.len() + 4];
        let prior_len = 128usize;

        let mut block = [0u8; 128];
        block[..tail.len()].copy_from_slice(tail);
        block[tail.len()] = 0x80;
        let bit_len = ((prior_len + tail.len()) as u128) * 8;
        block[112..].copy_from_slice(&bit_len.to_be_bytes());
        block
    }

    #[test]
    fn salt_block_matches_the_cpu_padded_block_byte_for_byte() {
        for len in [0usize, 1, 8, 32, 64, 100, 106, 107] {
            let salt: Vec<u8> = (0..len).map(|i| (i % 251) as u8 | 1).collect();
            let packed = pack_salt_block(&salt).expect("within MAX_SALT_LEN");
            assert_eq!(
                words_to_bytes(&packed),
                cpu_reference_salt_block(&salt),
                "salt len {len}"
            );
        }
    }

    #[test]
    fn salt_block_places_int1_the_terminator_and_the_length_field_correctly() {
        for len in [0usize, 8, 107] {
            let salt: Vec<u8> = (0..len).map(|i| (i % 251) as u8 | 1).collect();
            let bytes = words_to_bytes(&pack_salt_block(&salt).unwrap());
            assert_eq!(&bytes[..len], salt.as_slice());
            assert_eq!(&bytes[len..len + 4], &[0, 0, 0, 1], "INT(1) at len {len}");
            assert_eq!(bytes[len + 4], 0x80, "terminator at len {len}");
            assert!(
                bytes[len + 5..112].iter().all(|&x| x == 0),
                "gap at len {len}"
            );
            // One 128-byte key block has already been absorbed, hence 128 + ..
            assert_eq!(
                u128::from_be_bytes(bytes[112..].try_into().unwrap()),
                ((128 + len + 4) as u128) * 8,
                "length field at len {len}"
            );
        }
    }

    #[test]
    fn salt_block_for_bip39_matches_the_pinned_words() {
        let packed = pack_salt_block(crate::seed::BIP39_SALT).unwrap();
        let want: [u64; 16] = [
            0x6d6e_656d_6f6e_6963, // "mnemonic"
            0x0000_0001_8000_0000, // INT(1) then 0x80
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0x0000_0000_0000_0460, // (128 + 8 + 4) * 8 = 1120 bits
        ];
        assert_eq!(packed, want);
    }

    #[test]
    fn salt_block_rejects_a_salt_longer_than_max_salt_len() {
        const MAX: usize = crate::pbkdf2_lanes::MAX_SALT_LEN;
        assert!(pack_salt_block(&[0x73u8; MAX]).is_ok());
        assert_eq!(
            pack_salt_block(&[0x73u8; MAX + 1]),
            Err(GpuError::SaltTooLong { len: MAX + 1 })
        );
        assert_eq!(
            pack_salt_block(&[0x73u8; 200]),
            Err(GpuError::SaltTooLong { len: 200 })
        );
    }
}
