//! `HexSearchFormat` -- hexadecimal byte input.
//!
//! Ported from `ghidra.features.base.memsearch.format.HexSearchFormat`.

use crate::memsearch::format::{SearchFormat, SearchFormatType};
use crate::memsearch::gui::SearchSettings;
use crate::memsearch::matcher::{ByteMatcher, MaskedByteSequenceByteMatcher, InvalidByteMatcher};

const WILD_CARDS: &str = ".?";
const VALID_CHARS: &str = "0123456789abcdefABCDEF.?";
const MAX_GROUP_SIZE: usize = 16;

/// Search format for parsing hex byte sequences with optional wildcards.
///
/// Accepts hex digits (0-9, a-f, A-F) and wildcard characters (`.`, `?`).
/// Spaces separate byte groups.
///
/// Ported from `HexSearchFormat.java`.
#[derive(Debug, Clone, Copy)]
pub struct HexSearchFormat;

impl SearchFormat for HexSearchFormat {
    fn name(&self) -> &str {
        "Hex"
    }

    fn tooltip(&self) -> &str {
        "Interpret value as a sequence of hexadecimal bytes. Use '.' or '?' for wildcard nibbles."
    }

    fn format_type(&self) -> SearchFormatType {
        SearchFormatType::Byte
    }

    fn parse(&self, input: &str, _settings: &SearchSettings) -> Box<dyn ByteMatcher> {
        let input = input.trim();
        if input.is_empty() {
            return Box::new(InvalidByteMatcher::new(""));
        }

        // Split into byte groups by whitespace
        let groups: Vec<&str> = input.split_whitespace().collect();
        let groups = if groups.is_empty() {
            vec![input]
        } else {
            groups
        };

        // Validate characters
        for group in &groups {
            for ch in group.chars() {
                if !VALID_CHARS.contains(ch) {
                    return Box::new(InvalidByteMatcher::new("Invalid character"));
                }
            }
        }

        // Check group sizes (each group should be max 2 chars = 1 byte)
        for group in &groups {
            if group.len() > MAX_GROUP_SIZE {
                return Box::new(InvalidByteMatcher::new(
                    "Max group size exceeded. Enter <space> to add more.",
                ));
            }
        }

        // Parse each group into bytes and masks
        let mut bytes = Vec::new();
        let mut masks = Vec::new();

        for group in &groups {
            let chars: Vec<char> = group.chars().collect();
            let mut i = 0;
            while i < chars.len() {
                let high = chars[i];
                let low = if i + 1 < chars.len() {
                    chars[i + 1]
                } else {
                    // Odd number of hex chars - treat as incomplete byte
                    return Box::new(InvalidByteMatcher::incomplete("Incomplete hex byte"));
                };

                let high_nibble = hex_nibble(high);
                let low_nibble = hex_nibble(low);

                match (high_nibble, low_nibble) {
                    (Some(h), Some(l)) => {
                        bytes.push((h << 4) | l);
                        masks.push(0xFF);
                    }
                    (Some(h), None) => {
                        // High nibble specified, low is wildcard
                        bytes.push(h << 4);
                        masks.push(0xF0);
                    }
                    (None, Some(l)) => {
                        // High is wildcard, low nibble specified
                        bytes.push(l);
                        masks.push(0x0F);
                    }
                    (None, None) => {
                        // Both wildcards
                        bytes.push(0x00);
                        masks.push(0x00);
                    }
                }

                i += 2;
            }
        }

        if bytes.is_empty() {
            return Box::new(InvalidByteMatcher::new("No bytes specified"));
        }

        Box::new(MaskedByteSequenceByteMatcher::new_masked(
            input, bytes, masks,
        ))
    }

    fn value_string(&self, bytes: &[u8], _settings: &SearchSettings) -> String {
        bytes
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join(" ")
    }

    fn compare_values(&self, a: &[u8], b: &[u8], _settings: &SearchSettings) -> i32 {
        for (x, y) in a.iter().zip(b.iter()) {
            let cmp = (*x as i32) - (*y as i32);
            if cmp != 0 {
                return cmp;
            }
        }
        (a.len() as i32) - (b.len() as i32)
    }

    fn convert_text(&self, text: &str, _old: &SearchSettings, _new: &SearchSettings) -> String {
        text.to_string()
    }
}

fn hex_nibble(ch: char) -> Option<u8> {
    match ch {
        '0'..='9' => Some(ch as u8 - b'0'),
        'a'..='f' => Some(ch as u8 - b'a' + 10),
        'A'..='F' => Some(ch as u8 - b'A' + 10),
        '.' | '?' => None, // wildcard
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_settings() -> SearchSettings {
        SearchSettings::default()
    }

    #[test]
    fn test_hex_simple() {
        let fmt = HexSearchFormat;
        let m = fmt.parse("5589E5", &default_settings());
        assert_eq!(m.description(), "Masked: 5589E5");
        assert_eq!(m.pattern_length(), 3);
    }

    #[test]
    fn test_hex_with_spaces() {
        let fmt = HexSearchFormat;
        let m = fmt.parse("55 89 E5", &default_settings());
        assert_eq!(m.pattern_length(), 3);
    }

    #[test]
    fn test_hex_wildcards() {
        let fmt = HexSearchFormat;
        let m = fmt.parse("5? 89", &default_settings());
        assert_eq!(m.pattern_length(), 2);
    }

    #[test]
    fn test_hex_empty() {
        let fmt = HexSearchFormat;
        let m = fmt.parse("", &default_settings());
        assert_eq!(m.pattern_length(), 0);
    }

    #[test]
    fn test_hex_invalid() {
        let fmt = HexSearchFormat;
        let m = fmt.parse("ZZ", &default_settings());
        assert_eq!(m.pattern_length(), 0); // InvalidByteMatcher
    }

    #[test]
    fn test_hex_value_string() {
        let fmt = HexSearchFormat;
        assert_eq!(fmt.value_string(&[0x55, 0x89, 0xE5], &default_settings()), "55 89 E5");
    }

    #[test]
    fn test_hex_format_type() {
        assert_eq!(HexSearchFormat.format_type(), SearchFormatType::Byte);
    }
}
