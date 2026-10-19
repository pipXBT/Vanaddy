use super::chains::bitcoin::Bitcoin;
use super::chains::{Chain, ChainKind};

#[derive(Clone, Copy)]
pub enum MatchPosition {
    StartsWith,
    EndsWith,
    StartsAndEndsWith,
}

pub struct Matcher {
    pub(crate) prefix: String,
    pub(crate) suffix: String,
    pub(crate) case_sensitive: bool,
    /// For EVM: pre-decoded hex bytes for raw comparison (skips hex::encode in hot loop)
    pub(crate) evm_prefix: Option<(Vec<u8>, Option<u8>)>, // (full_bytes, extra_high_nibble)
    pub(crate) evm_suffix: Option<(Vec<u8>, Option<u8>)>, // (full_bytes, extra_low_nibble)
    /// For Bitcoin Bech32: pre-computed 5-bit groups of the user's vanity prefix
    pub(crate) bech32_prefix_5bit: Option<Vec<u8>>,
}

/// Parse a hex string into full bytes + optional trailing high nibble (for prefix matching).
/// e.g. "dead" -> ([0xde, 0xad], None), "dea" -> ([0xde], Some(0x0a))
fn hex_prefix_to_bytes(hex: &str) -> (Vec<u8>, Option<u8>) {
    let (full, odd) = hex.split_at(hex.len() & !1);
    let extra = odd.chars().next().map(|c| c.to_digit(16).unwrap() as u8);
    (hex::decode(full).unwrap(), extra)
}

/// Parse a hex string into full bytes + optional leading low nibble (for suffix matching).
/// e.g. "beef" -> ([0xbe, 0xef], None), "def" -> ([0xef], Some(0x0d))
fn hex_suffix_to_bytes(hex: &str) -> (Vec<u8>, Option<u8>) {
    let (odd, full) = hex.split_at(hex.len() % 2);
    let extra = odd.chars().next().map(|c| c.to_digit(16).unwrap() as u8);
    (hex::decode(full).unwrap(), extra)
}

impl Matcher {
    pub fn new(
        prefix: String,
        suffix: String,
        case_sensitive: bool,
        chain: ChainKind,
    ) -> Self {
        let evm_prefix = match chain {
            ChainKind::Evm if !prefix.is_empty() => Some(hex_prefix_to_bytes(&prefix)),
            _ => None,
        };

        let evm_suffix = match chain {
            ChainKind::Evm if !suffix.is_empty() => Some(hex_suffix_to_bytes(&suffix)),
            _ => None,
        };

        let bech32_prefix_5bit = match chain {
            ChainKind::Bitcoin if !prefix.is_empty() => Some(
                prefix
                    .chars()
                    .map(|c| Bitcoin::CHARSET.find(c).expect("validated in TUI") as u8)
                    .collect(),
            ),
            _ => None,
        };

        Matcher {
            prefix,
            suffix,
            case_sensitive,
            evm_prefix,
            evm_suffix,
            bech32_prefix_5bit,
        }
    }

    /// Whether the user's prefix matches `addr` (already stripped of any
    /// chain-specific fixed leading chars). Allocation-free.
    #[inline]
    pub fn prefix_matches(&self, addr: &str) -> bool {
        if self.prefix.is_empty() {
            return true;
        }
        let addr = addr.as_bytes();
        let pre = self.prefix.as_bytes();
        if addr.len() < pre.len() {
            return false;
        }
        if self.case_sensitive {
            &addr[..pre.len()] == pre
        } else {
            addr[..pre.len()].eq_ignore_ascii_case(pre)
        }
    }

    /// Whether the user's suffix matches the trailing chars of `addr`.
    /// Allocation-free.
    #[inline]
    pub fn suffix_matches(&self, addr: &str) -> bool {
        if self.suffix.is_empty() {
            return true;
        }
        let addr = addr.as_bytes();
        let suf = self.suffix.as_bytes();
        if addr.len() < suf.len() {
            return false;
        }
        let start = addr.len() - suf.len();
        if self.case_sensitive {
            &addr[start..] == suf
        } else {
            addr[start..].eq_ignore_ascii_case(suf)
        }
    }

    /// Match EVM address bytes directly — no hex encoding needed.
    pub fn matches_evm_raw(&self, addr_bytes: &[u8; 20]) -> bool {
        if let Some((ref full, ref extra)) = self.evm_prefix {
            if !addr_bytes[..full.len()].starts_with(full) {
                return false;
            }
            if let Some(nibble) = extra {
                if (addr_bytes[full.len()] >> 4) != *nibble {
                    return false;
                }
            }
        }

        if let Some((ref full, ref extra)) = self.evm_suffix {
            let start = 20 - full.len();
            if &addr_bytes[start..] != full.as_slice() {
                return false;
            }
            if let Some(nibble) = extra {
                debug_assert!(start > 0, "EVM suffix of 20 bytes + extra nibble is invalid (would exceed address length)");
                let idx = start - 1;
                if (addr_bytes[idx] & 0x0f) != *nibble {
                    return false;
                }
            }
        }

        true
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evm_matches_raw_prefix() {
        let m = Matcher::new("dead".into(), "".into(), false, ChainKind::Evm);
        let mut addr = [0u8; 20];
        addr[0] = 0xde;
        addr[1] = 0xad;
        assert!(m.matches_evm_raw(&addr));
    }

    #[test]
    fn evm_odd_nibble_prefix() {
        let m = Matcher::new("dea".into(), "".into(), false, ChainKind::Evm);
        let mut addr = [0u8; 20];
        addr[0] = 0xde;
        addr[1] = 0xa5;
        assert!(m.matches_evm_raw(&addr));
        addr[1] = 0xb5;
        assert!(!m.matches_evm_raw(&addr));
    }

    #[test]
    fn evm_suffix_odd_nibble() {
        let m = Matcher::new("".into(), "beef".into(), false, ChainKind::Evm);
        let mut addr = [0u8; 20];
        addr[18] = 0xbe;
        addr[19] = 0xef;
        assert!(m.matches_evm_raw(&addr));
    }

    #[test]
    fn hex_to_bytes_splits_odd_nibble() {
        assert_eq!(hex_prefix_to_bytes("dEa"), (vec![0xde], Some(0x0a)));
        assert_eq!(hex_suffix_to_bytes("dEf"), (vec![0xef], Some(0x0d)));
        assert_eq!(hex_prefix_to_bytes("a"), (vec![], Some(0x0a)));
        assert_eq!(hex_suffix_to_bytes("BEEF"), (vec![0xbe, 0xef], None));
        assert_eq!(hex_prefix_to_bytes(""), (vec![], None));
    }
}
