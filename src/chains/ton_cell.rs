//! TVM cell hashing per TON whitepaper §3.1.5.
//!
//! A cell has 0-1023 data bits and 0-4 refs. Its "representation hash" is
//! `SHA-256(refs_desc || bits_desc || data || for_each_ref(depth_be_u16) || for_each_ref(hash))`.
//!
//! We only implement the minimum required to hash wallet-v3r2 state_init, so
//! we don't parse BOC: the code cell is hardcoded as a (hash, max_depth) pair.

use sha2::{Digest, Sha256};

/// A TVM cell: 0-1023 data bits and 0-4 references.
pub struct Cell {
    /// Data bits, packed MSB-first. May be longer than needed for `bit_len`.
    pub data: Vec<u8>,
    /// Number of significant bits in `data`.
    pub bit_len: u16,
    /// References to child cells, by pre-computed hash + max_depth.
    pub refs: Vec<CellRef>,
}

/// A handle on a hashed cell — just its representation hash and max_depth,
/// which is all a parent needs when building its own representation.
#[derive(Clone, Copy)]
pub struct CellRef {
    pub hash: [u8; 32],
    pub max_depth: u16,
}

impl Cell {
    /// max_depth = 0 if no refs, else 1 + max(child.max_depth). Saturates at u16::MAX.
    pub fn max_depth(&self) -> u16 {
        if self.refs.is_empty() {
            0
        } else {
            let m = self.refs.iter().map(|r| r.max_depth).max().unwrap_or(0);
            m.saturating_add(1)
        }
    }

    /// Serialize the cell's representation (the bytes hashed to produce the cell hash).
    pub fn repr(&self) -> Vec<u8> {
        // Ordinary cell, no exotic, level=0 → refs_desc = num_refs.
        let num_refs = self.refs.len() as u8;
        let refs_desc = num_refs;

        let bits = self.bit_len as usize;
        let full_bytes = bits / 8;
        let ceil_bytes = (bits + 7) / 8;
        let bits_desc = (full_bytes + ceil_bytes) as u8;

        // Augmented data: if bit_len isn't a multiple of 8, pad with a 1 bit then 0s.
        let data_bytes: Vec<u8> = if bits == 0 {
            Vec::new()
        } else if bits % 8 == 0 {
            self.data[..ceil_bytes].to_vec()
        } else {
            let mut padded = self.data[..ceil_bytes].to_vec();
            let tail_bits = bits % 8;
            let last = ceil_bytes - 1;
            // Keep the first `tail_bits` bits of the last byte; set the next bit to 1;
            // zero out the rest.
            let keep_mask = !((1u8 << (8 - tail_bits)) - 1);
            let aug_bit = 1u8 << (7 - tail_bits);
            padded[last] = (padded[last] & keep_mask) | aug_bit;
            padded
        };

        let mut repr = Vec::with_capacity(2 + data_bytes.len() + self.refs.len() * (2 + 32));
        repr.push(refs_desc);
        repr.push(bits_desc);
        repr.extend_from_slice(&data_bytes);
        for r in &self.refs {
            repr.extend_from_slice(&r.max_depth.to_be_bytes());
        }
        for r in &self.refs {
            repr.extend_from_slice(&r.hash);
        }
        repr
    }

    /// SHA-256 of the representation.
    pub fn hash(&self) -> [u8; 32] {
        let h = Sha256::digest(self.repr());
        let mut out = [0u8; 32];
        out.copy_from_slice(&h);
        out
    }

    /// Package this cell as a reference for inclusion in a parent.
    pub fn as_ref(&self) -> CellRef {
        CellRef {
            hash: self.hash(),
            max_depth: self.max_depth(),
        }
    }
}

/// Wallet-v3r2 code cell — a well-known constant. Hash matches @ton/crypto's
/// compiled v3r2 code BOC. `max_depth = 0` because the compiled v3r2 code
/// BOC is a single cell with no outgoing refs; verified empirically against
/// Tonkeeper's computed v3r2 address for a known mnemonic.
pub const WALLET_V3R2_CODE: CellRef = CellRef {
    hash: [
        0x84, 0xda, 0xfa, 0x44, 0x9f, 0x98, 0xa6, 0x98,
        0x77, 0x89, 0xba, 0x23, 0x23, 0x58, 0x07, 0x2b,
        0xc0, 0xf7, 0x6d, 0xc4, 0x52, 0x40, 0x02, 0xa5,
        0xd0, 0x91, 0x8b, 0x9a, 0x75, 0xd2, 0xd5, 0x99,
    ],
    max_depth: 0,
};

/// Wallet-v3r2 data cell: seqno(u32=0) || subwallet_id(u32) || pubkey(u256).
/// Total 320 bits = 40 bytes exactly (no plugins bit — that's v4, not v3r2).
pub fn wallet_v3r2_data_cell(pubkey: &[u8; 32], subwallet_id: u32) -> Cell {
    let mut data = Vec::with_capacity(40);
    data.extend_from_slice(&0u32.to_be_bytes()); // seqno = 0
    data.extend_from_slice(&subwallet_id.to_be_bytes());
    data.extend_from_slice(pubkey);
    Cell {
        data,
        bit_len: 320,
        refs: vec![],
    }
}

/// Wallet-v3r2 state_init: StateInit TL-B with code + data refs, no split_depth,
/// no special, no library.
///
/// Header bits (MSB-first): 0 (split_depth?) 0 (special?) 1 (code?) 1 (data?) 0 (library?)
/// = 0b00110_000 as an augmented byte. bit_len = 5, 2 refs.
pub fn wallet_v3r2_state_init(pubkey: &[u8; 32], subwallet_id: u32) -> Cell {
    let data_cell = wallet_v3r2_data_cell(pubkey, subwallet_id);
    Cell {
        data: vec![0b0011_0000],
        bit_len: 5,
        refs: vec![WALLET_V3R2_CODE, data_cell.as_ref()],
    }
}

/// Wallet-v5r1 (W5) code cell — constant across all W5 wallets.
///
/// Root cell hash of the W5 code BOC published in `@ton/ton`
/// (`src/wallets/v5r1/WalletContractV5R1.ts`); verified empirically against
/// Tonkeeper's W5 address for a known mnemonic.
///
/// Unlike v3r2 (flat code cell), the W5 code cell is a tree of depth 6, so
/// `max_depth` is non-zero here.
pub const WALLET_V5R1_CODE: CellRef = CellRef {
    hash: [
        0x20, 0x83, 0x4b, 0x7b, 0x72, 0xb1, 0x12, 0x14,
        0x7e, 0x1b, 0x2f, 0xb4, 0x57, 0xb8, 0x4e, 0x74,
        0xd1, 0xa3, 0x0f, 0x04, 0xf7, 0x37, 0xd4, 0xf6,
        0x2a, 0x66, 0x8e, 0x95, 0x52, 0xd2, 0xb7, 0x2f,
    ],
    max_depth: 6,
};

/// Wallet-v5r1 wallet_id for mainnet (global_id = -239), workchain 0,
/// wallet_version 0, subwalletNumber 0.
///
/// Per `@ton/ton`'s `WalletV5R1WalletId`, `wallet_id = global_id ^ context_id`
/// where the client context packs
/// `[has_client_context=1 : 1][workchain : i8][wallet_version=0 : u8][subwallet=0 : u15]`
/// into a signed 32-bit int. For mainnet defaults, that evaluates to
/// `0x7FFFFF11` = 2147483409.
pub const W5_MAINNET_WALLET_ID: i32 = 0x7FFF_FF11;

/// Wallet-v5r1 (W5) data cell:
/// `is_signature_allowed(1=true) || seqno(u32=0) || wallet_id(i32) ||
///  pubkey(u256) || extensions_dict(1=empty)`.
///
/// Total 322 bits, packed MSB-first. Field widths are irregular (not byte-
/// aligned) because of the single-bit sig flag at the start and the single-bit
/// plugin-dict flag at the end, so we go through a tiny bit-packer rather than
/// try to concatenate byte-aligned chunks.
pub fn wallet_v5r1_data_cell(pubkey: &[u8; 32], wallet_id: i32) -> Cell {
    fn push_bits(
        buf: &mut Vec<u8>,
        pending: &mut u64,
        pending_bits: &mut u32,
        value: u64,
        num_bits: u32,
    ) {
        // Flush out whole bytes greedily before adding more — keeps `pending`
        // below 64 bits at all times and sidesteps the `x << 64` UB on u64
        // when num_bits can be 64 (happens for the pubkey chunks).
        debug_assert!(num_bits <= 64);
        let mask = if num_bits >= 64 { u64::MAX } else { (1u64 << num_bits) - 1 };
        let value = value & mask;

        // Feed the new bits in, one whole-byte flush at a time so we can keep
        // the working window ≤ 64 bits.
        let mut remaining = num_bits;
        let mut val = value;
        while remaining > 0 {
            // How many of the new bits can we take without overflowing 64?
            let take = remaining.min(64 - *pending_bits);
            let chunk = (val >> (remaining - take)) & if take >= 64 { u64::MAX } else { (1u64 << take) - 1 };
            *pending = (*pending << take) | chunk;
            *pending_bits += take;
            remaining -= take;
            val &= if remaining >= 64 { u64::MAX } else { (1u64 << remaining) - 1 };
            // Drain whole bytes.
            while *pending_bits >= 8 {
                let shift = *pending_bits - 8;
                let byte = ((*pending >> shift) & 0xff) as u8;
                buf.push(byte);
                *pending &= if shift == 0 { 0 } else { (1u64 << shift) - 1 };
                *pending_bits -= 8;
            }
        }
    }

    let mut buf: Vec<u8> = Vec::with_capacity(41);
    let mut pending: u64 = 0;
    let mut pending_bits: u32 = 0;

    push_bits(&mut buf, &mut pending, &mut pending_bits, 1, 1); // is_signature_allowed = true
    push_bits(&mut buf, &mut pending, &mut pending_bits, 0u64, 32); // seqno = 0
    push_bits(
        &mut buf,
        &mut pending,
        &mut pending_bits,
        wallet_id as u32 as u64,
        32,
    );
    // pubkey 256 bits as 4×64-bit chunks (big-endian).
    for chunk in pubkey.chunks(8) {
        let mut x: u64 = 0;
        for &b in chunk {
            x = (x << 8) | b as u64;
        }
        push_bits(&mut buf, &mut pending, &mut pending_bits, x, 64);
    }
    push_bits(&mut buf, &mut pending, &mut pending_bits, 0u64, 1); // extensions dict = empty

    // 322 bits pushed → pending_bits = 2. Stash the leftover as the high bits
    // of a final byte; Cell::repr() will handle augmentation using bit_len=322.
    if pending_bits > 0 {
        let byte = (pending << (8 - pending_bits)) as u8;
        buf.push(byte);
    }

    Cell {
        data: buf,
        bit_len: 322,
        refs: vec![],
    }
}

/// Wallet-v5r1 (W5) state_init. Same TL-B header as v3r2 (no split_depth,
/// no special, has code, has data, no library) — the difference is entirely
/// in the code cell and the data cell layout.
pub fn wallet_v5r1_state_init(pubkey: &[u8; 32], wallet_id: i32) -> Cell {
    let data_cell = wallet_v5r1_data_cell(pubkey, wallet_id);
    Cell {
        data: vec![0b0011_0000],
        bit_len: 5,
        refs: vec![WALLET_V5R1_CODE, data_cell.as_ref()],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_cell_descriptors() {
        // 0 refs, 0 bits → refs_desc=0, bits_desc=0, no data, no ref fields.
        let c = Cell { data: vec![], bit_len: 0, refs: vec![] };
        let r = c.repr();
        assert_eq!(r, vec![0u8, 0u8]);
    }

    #[test]
    fn byte_aligned_no_augmentation() {
        // 8 bits = 0xAB → bits_desc = 1 + 1 = 2, data = [0xAB]
        let c = Cell { data: vec![0xAB], bit_len: 8, refs: vec![] };
        let r = c.repr();
        assert_eq!(r, vec![0u8, 2u8, 0xAB]);
    }

    #[test]
    fn five_bit_augmented() {
        // 5 bits 00110_ → pad to 0b00110_100 = 0x34 (augmentation bit at position 6)
        // floor(5/8)=0, ceil(5/8)=1 → bits_desc = 0 + 1 = 1
        let c = Cell { data: vec![0b0011_0000], bit_len: 5, refs: vec![] };
        let r = c.repr();
        assert_eq!(r, vec![0u8, 1u8, 0b0011_0100]);
    }

    #[test]
    fn data_cell_layout_is_40_bytes() {
        let pk = [0u8; 32];
        let d = wallet_v3r2_data_cell(&pk, 698983191);
        assert_eq!(d.data.len(), 40);
        assert_eq!(d.bit_len, 320);
        assert_eq!(d.refs.len(), 0);
        // First 4 bytes = 0 (seqno), next 4 = subwallet BE
        assert_eq!(&d.data[0..4], &0u32.to_be_bytes());
        assert_eq!(&d.data[4..8], &698983191u32.to_be_bytes());
    }

    #[test]
    fn state_init_has_two_refs_and_five_bits() {
        let pk = [0u8; 32];
        let s = wallet_v3r2_state_init(&pk, 698983191);
        assert_eq!(s.bit_len, 5);
        assert_eq!(s.refs.len(), 2);
        // max_depth = max(code.max_depth=0, data.max_depth=0) + 1 = 1
        assert_eq!(s.max_depth(), 1);
    }

    /// Self-pinned hash of the v3r2 data cell (all-zero pubkey, default subwallet).
    /// The data cell has no refs and a fixed 320-bit layout, so this hash is
    /// purely a function of this file's data-cell encoding. Useful for catching
    /// any accidental change to seqno/subwallet/pubkey byte order or length.
    #[test]
    fn data_cell_with_zero_pubkey_has_expected_hash() {
        let pubkey = [0u8; 32];
        let data = wallet_v3r2_data_cell(&pubkey, 698983191);
        let hash = data.hash();
        let expected = hex::decode(
            "ad9fcf6aa8dd2d590c97fb0790f8088febeaa4ea544b8e1cc139124e90c5a746",
        )
        .unwrap();
        assert_eq!(&hash[..], &expected[..]);
    }

    /// Self-pinned hash of the v3r2 state_init (all-zero pubkey). Catches any
    /// drift in the state_init encoding, code-cell constants, or ref ordering.
    #[test]
    fn wallet_v3r2_state_init_all_zero_pubkey() {
        let pubkey = [0u8; 32];
        let state = wallet_v3r2_state_init(&pubkey, 698983191);
        let hash = state.hash();
        let expected = hex::decode(
            "a0e5f653bed80ca00f12a09e86034d50f1235f43e5f9e5782438c88489938ff1",
        )
        .unwrap();
        assert_eq!(&hash[..], &expected[..]);
    }

    /// Self-pinned data-cell hash for W5 with an all-zero pubkey and the
    /// mainnet default wallet_id. Purely a function of this file's W5 data-cell
    /// encoding: catches any accidental regression in the 322-bit bit-packer
    /// (sig-flag position, seqno width, wallet_id endianness, pubkey byte
    /// order, plugin-dict bit). Verified against `tonsdk` independently.
    #[test]
    fn wallet_v5r1_data_cell_zero_pubkey_pins_hash() {
        let pubkey = [0u8; 32];
        let data = wallet_v5r1_data_cell(&pubkey, W5_MAINNET_WALLET_ID);
        assert_eq!(data.bit_len, 322);
        assert_eq!(data.refs.len(), 0);
        let hash = data.hash();
        let expected = hex::decode(
            "0f80a4e3e2630cba3f6f37d12dbcf6afaaa015cd889eeb681a334a4fbe84cf31",
        )
        .unwrap();
        assert_eq!(&hash[..], &expected[..]);
    }

    /// W5 (v5r1) Tonkeeper round-trip pin. For the canonical mnemonic we
    /// use for v3r2 round-trips, Tonkeeper's W5 tab shows the address
    /// `UQAkFCMtkN0Q1TNP6Gk9SqYWsBFc6Aglwckj6ES4AeBEzWja`. Its account_id
    /// (bytes [2..34] of the base64url-decoded address) must equal the hash
    /// of our W5 state_init cell. If this fails, W5 derivation is wrong and
    /// no W5-flavored address we produce should be trusted.
    #[test]
    fn wallet_v5r1_matches_tonkeeper_vector() {
        use super::super::ton_mnemonic::mnemonic_to_signing_key;
        let phrase = "cloth orbit much expose crater arrow success drop verify then letter song field million quantum fame ankle stereo quote rhythm believe farm property tube";
        let sk = mnemonic_to_signing_key(phrase);
        let pubkey: [u8; 32] = sk.verifying_key().to_bytes();

        let state = wallet_v5r1_state_init(&pubkey, W5_MAINNET_WALLET_ID);
        let hash = state.hash();

        let expected = hex::decode(
            "2414232d90dd10d5334fe8693d4aa616b0115ce80825c1c923e844b801e044cd",
        )
        .unwrap();
        assert_eq!(
            &hash[..],
            &expected[..],
            "W5 state_init hash mismatch — derived pubkey = {} — if wallet_id or code hash drifted this will flag it",
            hex::encode(&pubkey),
        );
    }
}
