//! Multi-lane PBKDF2-HMAC-SHA512.
//!
//! PBKDF2 is one serial chain of SHA-512 compressions, so a single stream
//! leaves most of an Apple Silicon core's SHA-512 unit idle. Running `LANES`
//! independent derivations interleaved inside one compression routine hides
//! that latency (~2x per core, measured on M1). Falls back to `ring` when the
//! ARMv8.2 SHA-512 instructions are unavailable.

/// Number of independent PBKDF2 streams interleaved per call. Measured optimum
/// on M1 (more lanes spill NEON registers and regress).
pub const LANES: usize = 4;

/// PBKDF2-HMAC-SHA512 for `L` passwords sharing one `salt`; returns the first
/// 64-byte output block per lane (dkLen <= 64, which covers BIP-39 and TON).
/// `salt` must be at most 107 bytes so `salt || INT(1)` fits one padded block.
pub fn pbkdf2_hmac_sha512<const L: usize>(
    passwords: [&[u8]; L],
    salt: &[u8],
    iterations: u32,
) -> [[u8; 64]; L] {
    assert!(
        salt.len() <= MAX_SALT_LEN,
        "salt must be at most {MAX_SALT_LEN} bytes, got {}",
        salt.len()
    );
    assert!(iterations >= 1, "iterations must be at least 1");
    #[cfg(target_arch = "aarch64")]
    {
        if std::arch::is_aarch64_feature_detected!("sha3") {
            // SAFETY: `sha3` (which carries the SHA-512 instructions) was just detected.
            return unsafe { hw::pbkdf2_lanes::<L>(&passwords, salt, iterations) };
        }
    }
    fallback(&passwords, salt, iterations)
}

/// Longest salt for which `salt || INT(1) || padding` fits one 128-byte block.
const MAX_SALT_LEN: usize = 107;

/// Portable path: one `ring` derivation per lane.
fn fallback<const L: usize>(passwords: &[&[u8]; L], salt: &[u8], iterations: u32) -> [[u8; 64]; L] {
    let mut out = [[0u8; 64]; L];
    for (password, lane) in passwords.iter().zip(out.iter_mut()) {
        ring::pbkdf2::derive(
            ring::pbkdf2::PBKDF2_HMAC_SHA512,
            std::num::NonZeroU32::new(iterations).expect("checked above"),
            salt,
            password,
            lane,
        );
    }
    out
}

#[cfg(target_arch = "aarch64")]
mod hw {
    //! ARMv8.2 SHA-512 (`sha512h`/`sha512h2`/`sha512su0`/`sha512su1`) backend.
    //! Round-pair structure follows the reference `sha512-armv8` hardware path:
    //! the four working-variable pairs (ab, cd, ef, gh) rotate roles every pair.
    use core::arch::aarch64::*;

    type State = [u64; 8];
    type Block = [u8; 128];

    /// FIPS 180-4 SHA-512 round constants.
    const K: [u64; 80] = [
        0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
        0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
        0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
        0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
        0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
        0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
        0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
        0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
        0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
        0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
        0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
        0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
        0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
        0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
        0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
        0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
        0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
        0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
        0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
        0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
    ];

    /// FIPS 180-4 SHA-512 initial hash value.
    const H0: State = [
        0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
        0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
    ];

    /// One SHA-512 round pair. `(a, b, c, d)` are the working-variable pairs in
    /// their current roles; `w` holds two message words and `k` two constants.
    #[inline(always)]
    unsafe fn round_pair(
        a: uint64x2_t,
        b: &mut uint64x2_t,
        c: uint64x2_t,
        d: &mut uint64x2_t,
        w: uint64x2_t,
        k: uint64x2_t,
    ) {
        let wk = vaddq_u64(w, k);
        let sum = vaddq_u64(vextq_u64(wk, wk, 1), *d);
        let intermed = vsha512hq_u64(sum, vextq_u64(c, *d, 1), vextq_u64(*b, c, 1));
        let new_d = vsha512h2q_u64(intermed, *b, a);
        *b = vaddq_u64(*b, intermed);
        *d = new_d;
    }

    /// Message-schedule update: replace the two words in slot `p % 8` (just
    /// consumed by pair `p`) with the words needed by pair `p + 8`.
    #[inline(always)]
    unsafe fn schedule(w: &mut [uint64x2_t; 8], p: usize) {
        let i = p % 8;
        let partial = vsha512su0q_u64(w[i], w[(p + 1) % 8]);
        w[i] = vsha512su1q_u64(
            partial,
            w[(p + 7) % 8],
            vextq_u64(w[(p + 4) % 8], w[(p + 5) % 8], 1),
        );
    }

    /// Compress one block into each of `L` independent states, interleaving
    /// the lanes instruction-by-instruction so their dependency chains overlap.
    #[target_feature(enable = "sha3")]
    unsafe fn compress<const L: usize>(states: &mut [State; L], blocks: &[Block; L]) {
        let zero = vdupq_n_u64(0);
        let mut ab = [zero; L];
        let mut cd = [zero; L];
        let mut ef = [zero; L];
        let mut gh = [zero; L];
        let mut w = [[zero; 8]; L];
        for l in 0..L {
            let st = states[l].as_ptr();
            ab[l] = vld1q_u64(st);
            cd[l] = vld1q_u64(st.add(2));
            ef[l] = vld1q_u64(st.add(4));
            gh[l] = vld1q_u64(st.add(6));
            let blk = blocks[l].as_ptr();
            for (i, slot) in w[l].iter_mut().enumerate() {
                *slot = vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(blk.add(16 * i))));
            }
        }

        // 40 round pairs. Roles rotate with period 4 and message slots with
        // period 8, so unroll 8 pairs per outer iteration to keep every index
        // a compile-time constant. Pairs 0..32 also advance the schedule.
        for octet in 0..5 {
            for half in 0..2 {
                let base = 8 * octet + 4 * half;
                let k0 = vld1q_u64(K.as_ptr().add(2 * base));
                let k1 = vld1q_u64(K.as_ptr().add(2 * base + 2));
                let k2 = vld1q_u64(K.as_ptr().add(2 * base + 4));
                let k3 = vld1q_u64(K.as_ptr().add(2 * base + 6));
                let s0 = (4 * half) % 8;
                let s1 = (4 * half + 1) % 8;
                let s2 = (4 * half + 2) % 8;
                let s3 = (4 * half + 3) % 8;
                let advance = octet < 4;
                for l in 0..L {
                    round_pair(ab[l], &mut cd[l], ef[l], &mut gh[l], w[l][s0], k0);
                    if advance {
                        schedule(&mut w[l], base);
                    }
                }
                for l in 0..L {
                    round_pair(gh[l], &mut ab[l], cd[l], &mut ef[l], w[l][s1], k1);
                    if advance {
                        schedule(&mut w[l], base + 1);
                    }
                }
                for l in 0..L {
                    round_pair(ef[l], &mut gh[l], ab[l], &mut cd[l], w[l][s2], k2);
                    if advance {
                        schedule(&mut w[l], base + 2);
                    }
                }
                for l in 0..L {
                    round_pair(cd[l], &mut ef[l], gh[l], &mut ab[l], w[l][s3], k3);
                    if advance {
                        schedule(&mut w[l], base + 3);
                    }
                }
            }
        }

        for l in 0..L {
            let st = states[l].as_mut_ptr();
            vst1q_u64(st, vaddq_u64(ab[l], vld1q_u64(st)));
            vst1q_u64(st.add(2), vaddq_u64(cd[l], vld1q_u64(st.add(2))));
            vst1q_u64(st.add(4), vaddq_u64(ef[l], vld1q_u64(st.add(4))));
            vst1q_u64(st.add(6), vaddq_u64(gh[l], vld1q_u64(st.add(6))));
        }
    }

    /// Final padded block for a message tail of at most 111 bytes that follows
    /// `prior_len` bytes already absorbed.
    fn padded_block(tail: &[u8], prior_len: usize) -> Block {
        debug_assert!(tail.len() <= 111);
        let mut block = [0u8; 128];
        block[..tail.len()].copy_from_slice(tail);
        block[tail.len()] = 0x80;
        let bit_len = ((prior_len + tail.len()) as u128) * 8;
        block[112..].copy_from_slice(&bit_len.to_be_bytes());
        block
    }

    fn digest_bytes(state: &State) -> [u8; 64] {
        let mut out = [0u8; 64];
        for (chunk, word) in out.chunks_exact_mut(8).zip(state.iter()) {
            chunk.copy_from_slice(&word.to_be_bytes());
        }
        out
    }

    /// PBKDF2-HMAC-SHA512 first output block for `L` lanes. Caller guarantees
    /// the `sha3` feature is present and `salt.len() <= 107`.
    #[target_feature(enable = "sha3")]
    pub unsafe fn pbkdf2_lanes<const L: usize>(
        passwords: &[&[u8]; L],
        salt: &[u8],
        iterations: u32,
    ) -> [[u8; 64]; L] {
        // HMAC key schedule: states after absorbing (key ^ ipad) / (key ^ opad).
        let mut inner_init = [H0; L];
        let mut outer_init = [H0; L];
        let mut ipad = [[0x36u8; 128]; L];
        let mut opad = [[0x5cu8; 128]; L];
        for l in 0..L {
            let password = passwords[l];
            let mut hashed = [0u8; 64];
            let key: &[u8] = if password.len() > 128 {
                hashed.copy_from_slice(ring::digest::digest(&ring::digest::SHA512, password).as_ref());
                &hashed
            } else {
                password
            };
            for (i, &kb) in key.iter().enumerate() {
                ipad[l][i] ^= kb;
                opad[l][i] ^= kb;
            }
        }
        compress::<L>(&mut inner_init, &ipad);
        compress::<L>(&mut outer_init, &opad);

        // U_1 = PRF(salt || INT(1)).
        let mut salted = [0u8; 111];
        salted[..salt.len()].copy_from_slice(salt);
        salted[salt.len()..salt.len() + 4].copy_from_slice(&1u32.to_be_bytes());
        let first = padded_block(&salted[..salt.len() + 4], 128);
        let mut inner = inner_init;
        compress::<L>(&mut inner, &[first; L]);

        // Every later PRF input is a 64-byte digest after one key block, so one
        // padded template serves both the inner and the outer hash.
        let mut msg = [padded_block(&[0u8; 64], 128); L];
        for l in 0..L {
            msg[l][..64].copy_from_slice(&digest_bytes(&inner[l]));
        }
        let mut u = outer_init;
        compress::<L>(&mut u, &msg);
        let mut t = u;

        // U_j = PRF(U_{j-1}); T ^= U_j.
        for _ in 1..iterations {
            for l in 0..L {
                msg[l][..64].copy_from_slice(&digest_bytes(&u[l]));
            }
            let mut inner = inner_init;
            compress::<L>(&mut inner, &msg);
            for l in 0..L {
                msg[l][..64].copy_from_slice(&digest_bytes(&inner[l]));
            }
            u = outer_init;
            compress::<L>(&mut u, &msg);
            for (t_lane, u_lane) in t.iter_mut().zip(u.iter()) {
                for (tw, uw) in t_lane.iter_mut().zip(uw_iter(u_lane)) {
                    *tw ^= uw;
                }
            }
        }

        let mut out = [[0u8; 64]; L];
        for l in 0..L {
            out[l] = digest_bytes(&t[l]);
        }
        out
    }

    #[inline(always)]
    fn uw_iter(lane: &State) -> impl Iterator<Item = u64> + '_ {
        lane.iter().copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::num::NonZeroU32;

    const BIP39_VECTOR_PHRASE: &[u8] = b"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const BIP39_VECTOR_SEED: &str = "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4";

    fn ring_reference(password: &[u8], salt: &[u8], iterations: u32) -> [u8; 64] {
        let mut out = [0u8; 64];
        ring::pbkdf2::derive(
            ring::pbkdf2::PBKDF2_HMAC_SHA512,
            NonZeroU32::new(iterations).unwrap(),
            salt,
            password,
            &mut out,
        );
        out
    }

    #[test]
    fn every_lane_matches_bip39_canonical_vector() {
        let out = pbkdf2_hmac_sha512::<LANES>([BIP39_VECTOR_PHRASE; LANES], b"mnemonic", 2048);
        for lane in out {
            assert_eq!(hex::encode(lane), BIP39_VECTOR_SEED);
        }
    }

    #[test]
    fn distinct_lanes_match_ring_reference() {
        // Lane 2 is a 24-word phrase (> 128 bytes), which forces HMAC key pre-hashing.
        let pws: [&[u8]; 4] = [
            BIP39_VECTOR_PHRASE,
            b"legal winner thank year wave sausage worth useful legal winner thank yellow",
            b"letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",
            b"zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
        ];
        assert!(pws[2].len() > 128);
        let out = pbkdf2_hmac_sha512::<4>(pws, b"mnemonic", 2048);
        for (pw, lane) in pws.iter().zip(out.iter()) {
            assert_eq!(lane, &ring_reference(pw, b"mnemonic", 2048));
        }
    }

    #[test]
    fn ton_salts_and_iteration_counts_match_ring() {
        let entropy: [[u8; 64]; LANES] = std::array::from_fn(|i| {
            let mut e = [0u8; 64];
            for (j, b) in e.iter_mut().enumerate() {
                *b = (i * 37 + j * 11) as u8;
            }
            e
        });
        let pws: [&[u8]; LANES] = std::array::from_fn(|i| entropy[i].as_slice());
        let basic = pbkdf2_hmac_sha512::<LANES>(pws, b"TON seed version", 390);
        let seed = pbkdf2_hmac_sha512::<LANES>(pws, b"TON default seed", 100_000);
        for i in 0..LANES {
            assert_eq!(basic[i], ring_reference(pws[i], b"TON seed version", 390));
            assert_eq!(seed[i], ring_reference(pws[i], b"TON default seed", 100_000));
        }
    }

    #[test]
    fn single_lane_and_single_iteration_match_ring() {
        let one = pbkdf2_hmac_sha512::<1>([b"password".as_slice()], b"salt", 1);
        assert_eq!(one[0], ring_reference(b"password", b"salt", 1));
        let two = pbkdf2_hmac_sha512::<1>([b"password".as_slice()], b"salt", 2);
        assert_eq!(two[0], ring_reference(b"password", b"salt", 2));
    }

    #[test]
    fn exactly_128_byte_password_matches_ring() {
        // HMAC key == block size: must not be pre-hashed.
        let pw = [0x61u8; 128];
        let out = pbkdf2_hmac_sha512::<1>([pw.as_slice()], b"mnemonic", 16);
        assert_eq!(out[0], ring_reference(&pw, b"mnemonic", 16));
    }

    #[test]
    #[should_panic(expected = "salt")]
    fn rejects_salt_longer_than_one_block() {
        let salt = [0u8; 108];
        let _ = pbkdf2_hmac_sha512::<1>([b"x".as_slice()], &salt, 1);
    }
}
