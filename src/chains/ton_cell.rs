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
}
