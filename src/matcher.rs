use super::chains::ChainKind;
use bech32::u5;

#[derive(Clone, Copy)]
pub enum MatchPosition {
    StartsWith,
    EndsWith,
    StartsAndEndsWith,
}

pub struct Matcher {
    pub(crate) prefix: String,
    pub(crate) suffix: String,
    pub(crate) position: MatchPosition,
    pub(crate) case_sensitive: bool,
    /// Pre-lowercased for case-insensitive string matching (avoids alloc in hot loop)
    pub(crate) prefix_lower: String,
    pub(crate) suffix_lower: String,
    /// For EVM: pre-decoded hex bytes for raw comparison (skips hex::encode in hot loop)
    pub(crate) evm_prefix: Option<(Vec<u8>, Option<u8>)>, // (full_bytes, extra_high_nibble)
    pub(crate) evm_suffix: Option<(Vec<u8>, Option<u8>)>, // (full_bytes, extra_low_nibble)
    /// For Bitcoin Bech32: pre-computed 5-bit groups of the user's vanity prefix
    pub(crate) bech32_prefix_5bit: Option<Vec<u5>>,
}

/// Parse a hex string into full bytes + optional trailing high nibble (for prefix matching).
/// e.g. "dead" -> ([0xde, 0xad], None), "dea" -> ([0xde], Some(0x0a))
fn hex_prefix_to_bytes(hex: &str) -> (Vec<u8>, Option<u8>) {
    let hex_lower = hex.to_lowercase();
    let nibbles: Vec<u8> = hex_lower
        .chars()
        .map(|c| c.to_digit(16).unwrap() as u8)
        .collect();
    let full_count = nibbles.len() / 2;
    let mut bytes = Vec::with_capacity(full_count);
    for i in 0..full_count {
        bytes.push((nibbles[i * 2] << 4) | nibbles[i * 2 + 1]);
    }
    let extra = if nibbles.len() % 2 == 1 {
        Some(nibbles[nibbles.len() - 1])
    } else {
        None
    };
    (bytes, extra)
}

/// Parse a hex string into full bytes + optional leading low nibble (for suffix matching).
/// e.g. "beef" -> ([0xbe, 0xef], None), "def" -> ([0xef], Some(0x0d))
fn hex_suffix_to_bytes(hex: &str) -> (Vec<u8>, Option<u8>) {
    let hex_lower = hex.to_lowercase();
    let nibbles: Vec<u8> = hex_lower
        .chars()
        .map(|c| c.to_digit(16).unwrap() as u8)
        .collect();
    let has_extra = nibbles.len() % 2 == 1;
    let start = if has_extra { 1 } else { 0 };
    let full_count = (nibbles.len() - start) / 2;
    let mut bytes = Vec::with_capacity(full_count);
    for i in 0..full_count {
        let idx = start + i * 2;
        bytes.push((nibbles[idx] << 4) | nibbles[idx + 1]);
    }
    let extra = if has_extra { Some(nibbles[0]) } else { None };
    (bytes, extra)
}

impl Matcher {
    pub fn new(
        prefix: String,
        suffix: String,
        position: MatchPosition,
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
            ChainKind::Bitcoin if !prefix.is_empty() => {
                let charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
                Some(
                    prefix
                        .chars()
                        .map(|c| {
                            let idx = charset.find(c).expect("validated in TUI") as u8;
                            u5::try_from_u8(idx).unwrap()
                        })
                        .collect::<Vec<_>>(),
                )
            }
            _ => None,
        };

        let prefix_lower = prefix.to_lowercase();
        let suffix_lower = suffix.to_lowercase();

        Matcher {
            prefix,
            suffix,
            position,
            case_sensitive,
            prefix_lower,
            suffix_lower,
            evm_prefix,
            evm_suffix,
            bech32_prefix_5bit,
        }
    }

    /// Match EVM address bytes directly — no hex encoding needed.
    pub fn matches_evm_raw(&self, addr_bytes: &[u8; 20]) -> bool {
        let prefix_ok = if let Some((ref full, ref extra)) = self.evm_prefix {
            if !addr_bytes[..full.len()].starts_with(full) {
                return false;
            }
            if let Some(nibble) = extra {
                if (addr_bytes[full.len()] >> 4) != *nibble {
                    return false;
                }
            }
            true
        } else {
            true
        };

        if !prefix_ok {
            return false;
        }

        if let Some((ref full, ref extra)) = self.evm_suffix {
            let start = 20 - full.len();
            if &addr_bytes[start..] != full.as_slice() {
                return false;
            }
            if let Some(nibble) = extra {
                let idx = start - 1;
                if (addr_bytes[idx] & 0x0f) != *nibble {
                    return false;
                }
            }
        }

        true
    }

    pub fn matches_str(&self, address: &str) -> bool {
        let addr = if address.starts_with("0x") {
            &address[2..]
        } else {
            address
        };

        if self.case_sensitive {
            match self.position {
                MatchPosition::StartsWith => addr.starts_with(&self.prefix),
                MatchPosition::EndsWith => addr.ends_with(&self.suffix),
                MatchPosition::StartsAndEndsWith => {
                    addr.starts_with(&self.prefix) && addr.ends_with(&self.suffix)
                }
            }
        } else {
            let a = addr.to_lowercase();
            match self.position {
                MatchPosition::StartsWith => a.starts_with(&self.prefix_lower),
                MatchPosition::EndsWith => a.ends_with(&self.suffix_lower),
                MatchPosition::StartsAndEndsWith => {
                    a.starts_with(&self.prefix_lower) && a.ends_with(&self.suffix_lower)
                }
            }
        }
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evm_matches_raw_prefix() {
        let m = Matcher::new("dead".into(), "".into(), MatchPosition::StartsWith, false, ChainKind::Evm);
        let mut addr = [0u8; 20];
        addr[0] = 0xde;
        addr[1] = 0xad;
        assert!(m.matches_evm_raw(&addr));
    }

    #[test]
    fn evm_odd_nibble_prefix() {
        let m = Matcher::new("dea".into(), "".into(), MatchPosition::StartsWith, false, ChainKind::Evm);
        let mut addr = [0u8; 20];
        addr[0] = 0xde;
        addr[1] = 0xa5;
        assert!(m.matches_evm_raw(&addr));
        addr[1] = 0xb5;
        assert!(!m.matches_evm_raw(&addr));
    }

    #[test]
    fn evm_suffix_odd_nibble() {
        let m = Matcher::new("".into(), "beef".into(), MatchPosition::EndsWith, false, ChainKind::Evm);
        let mut addr = [0u8; 20];
        addr[18] = 0xbe;
        addr[19] = 0xef;
        assert!(m.matches_evm_raw(&addr));
    }
}
