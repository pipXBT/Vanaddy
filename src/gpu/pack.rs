//! Host-side packing of PBKDF2 inputs into the exact 16-word big-endian blocks
//! the Metal kernel consumes. Every byte-level decision - zero padding, INT(1),
//! the 0x80 terminator, the 128-bit length field, endianness - lives here in
//! Rust, where it is testable with no GPU. The kernel therefore contains zero
//! endianness code and zero padding code.

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

/// `crate::seed::BIP39_SALT` ("mnemonic") || INT(1) || 0x80 || zero pad ||
/// the 128-bit bit length, as 16 big-endian words: the byte-exact mirror of
/// `padded_block(&salted[..salt.len()+4], 128)` in src/pbkdf2_lanes.rs for the
/// one salt the GPU ever uses. The self-test's canonical-vector check proves it
/// at startup.
pub const BIP39_SALT_BLOCK: [u64; 16] = [
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seed::CANONICAL_PHRASE as CANONICAL;
    use bip39::{Language, Mnemonic, MnemonicType};

    fn words_to_bytes(words: &[u64; 16]) -> [u8; 128] {
        let mut out = [0u8; 128];
        for (i, w) in words.iter().enumerate() {
            out[8 * i..8 * i + 8].copy_from_slice(&w.to_be_bytes());
        }
        out
    }

    #[test]
    fn key_block_has_pinned_repr_c_layout() {
        // KeyBlock is uploaded to a GPU buffer and read by raw byte offset, so
        // a field reorder, alignment change, or a derive that isn't
        // repr(C)-safe would compile clean and pass every other test here, then only surface as a plausible-but-wrong seed once the
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
}
