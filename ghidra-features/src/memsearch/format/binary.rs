//! `BinarySearchFormat` -- binary digit input.
//!
//! Ported from `ghidra.features.base.memsearch.format.BinarySearchFormat`.

use crate::memsearch::format::{SearchFormat, SearchFormatType};
use crate::memsearch::gui::SearchSettings;
use crate::memsearch::matcher::{ByteMatcher, MaskedByteSequenceByteMatcher, InvalidByteMatcher};

const VALID_CHARS: &str = "01x?.";
const MAX_GROUP_SIZE: usize = 8;

/// Search format for parsing binary digit sequences (0, 1, x/. for wildcard).
///
/// Ported from `BinarySearchFormat.java`.
#[derive(Debug, Clone, Copy)]
pub struct BinarySearchFormat;

impl SearchFormat for BinarySearchFormat {
    fn name(&self) -> &str {
        "Binary"
    }

    fn tooltip(&self) -> &str {
        "Interpret value as a sequence of binary digits. Use 'x', '.', or '?' for wildcard bits."
    }

    fn format_type(&self) -> SearchFormatType {
        SearchFormatType::Byte
    }

    fn parse(&self, input: &str, _settings: &SearchSettings) -> Box<dyn ByteMatcher> {
        let input = input.trim();
        if input.is_empty() {
            return Box::new(InvalidByteMatcher::new(""));
        }

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
            if group.len() > MAX_GROUP_SIZE {
                return Box::new(InvalidByteMatcher::new(
                    "Max group size exceeded. Enter <space> to add more.",
                ));
            }
        }

        let mut bytes = Vec::new();
        let mut masks = Vec::new();

        for group in &groups {
            let mut byte_val: u8 = 0;
            let mut mask_val: u8 = 0;
            let bits: Vec<char> = group.chars().collect();

            for (i, &bit) in bits.iter().enumerate() {
                let shift = 7 - i;
                match bit {
                    '0' => {
                        // bit is 0, must match exactly
                        mask_val |= 1 << shift;
                    }
                    '1' => {
                        byte_val |= 1 << shift;
                        mask_val |= 1 << shift;
                    }
                    'x' | '.' | '?' => {
                        // wildcard - don't set mask bit
                    }
                    _ => unreachable!(),
                }
            }

            bytes.push(byte_val);
            masks.push(mask_val);
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
            .map(|b| format!("{:08b}", b))
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

#[cfg(test)]
mod tests {
    use super::*;

    fn default_settings() -> SearchSettings {
        SearchSettings::default()
    }

    #[test]
    fn test_binary_simple() {
        let fmt = BinarySearchFormat;
        let m = fmt.parse("01010101", &default_settings());
        assert_eq!(m.pattern_length(), 1);
    }

    #[test]
    fn test_binary_two_bytes() {
        let fmt = BinarySearchFormat;
        let m = fmt.parse("01010101 10001001", &default_settings());
        assert_eq!(m.pattern_length(), 2);
    }

    #[test]
    fn test_binary_wildcards() {
        let fmt = BinarySearchFormat;
        let m = fmt.parse("0101xxxx", &default_settings());
        assert_eq!(m.pattern_length(), 1);
    }

    #[test]
    fn test_binary_empty() {
        let fmt = BinarySearchFormat;
        let m = fmt.parse("", &default_settings());
        assert_eq!(m.pattern_length(), 0);
    }

    #[test]
    fn test_binary_value_string() {
        let fmt = BinarySearchFormat;
        assert_eq!(
            fmt.value_string(&[0x55, 0x89], &default_settings()),
            "01010101 10001001"
        );
    }
}
