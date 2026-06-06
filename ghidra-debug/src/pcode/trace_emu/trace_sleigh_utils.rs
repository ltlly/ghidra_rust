//! TraceSleighUtils ported from TraceSleighUtils.java.
//!
//! Utilities for working with Sleigh language specifications in traces.

/// Utility functions for Sleigh in the context of traces.
pub struct TraceSleighUtils;

impl TraceSleighUtils {
    /// Parse a Sleigh address space name from a space description.
    pub fn parse_space_name(description: &str) -> Option<&str> {
        description.split_whitespace().next()
    }

    /// Format an address as hex.
    pub fn format_address(offset: u64) -> String {
        format!("0x{:x}", offset)
    }

    /// Parse a hex address string.
    pub fn parse_hex_address(s: &str) -> Option<u64> {
        let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
        u64::from_str_radix(s, 16).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_address() {
        assert_eq!(TraceSleighUtils::format_address(0xDEAD), "0xdead");
    }

    #[test]
    fn test_parse_hex() {
        assert_eq!(TraceSleighUtils::parse_hex_address("0xFF"), Some(255));
        assert_eq!(TraceSleighUtils::parse_hex_address("0XFF"), Some(255));
        assert_eq!(TraceSleighUtils::parse_hex_address("FF"), Some(255));
        assert_eq!(TraceSleighUtils::parse_hex_address("not_hex"), None);
    }
}
