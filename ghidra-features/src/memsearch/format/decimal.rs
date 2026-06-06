//! `DecimalSearchFormat` -- decimal integer input.
//!
//! Ported from `ghidra.features.base.memsearch.format.DecimalSearchFormat`.

use crate::memsearch::format::{SearchFormat, SearchFormatType, NumberParseResult};
use crate::memsearch::gui::SearchSettings;
use crate::memsearch::matcher::{ByteMatcher, MaskedByteSequenceByteMatcher, InvalidByteMatcher};

/// Search format for parsing decimal integer values.
///
/// Supports sizes of 2, 4, 8, and 16 bytes, and can be signed or unsigned.
///
/// Ported from `DecimalSearchFormat.java`.
#[derive(Debug, Clone, Copy)]
pub struct DecimalSearchFormat;

impl DecimalSearchFormat {
    fn parse_number(&self, tok: &str, settings: &SearchSettings) -> NumberParseResult {
        let tok = tok.trim();
        if tok.is_empty() {
            return NumberParseResult::error("Empty token", false);
        }

        let byte_size = settings.decimal_byte_size();
        let is_unsigned = settings.is_decimal_unsigned();

        if is_unsigned {
            match tok.parse::<u64>() {
                Ok(val) => {
                    let bytes = match byte_size {
                        2 => (val as u16).to_le_bytes().to_vec(),
                        4 => (val as u32).to_le_bytes().to_vec(),
                        8 => val.to_le_bytes().to_vec(),
                        16 => {
                            let mut b = val.to_le_bytes().to_vec();
                            b.extend_from_slice(&[0u8; 8]);
                            b
                        }
                        _ => (val as u32).to_le_bytes().to_vec(),
                    };
                    NumberParseResult::success(bytes)
                }
                Err(_) => NumberParseResult::error(
                    &format!("Invalid unsigned number: {}", tok),
                    true,
                ),
            }
        } else {
            match tok.parse::<i64>() {
                Ok(val) => {
                    let bytes = match byte_size {
                        2 => (val as i16).to_le_bytes().to_vec(),
                        4 => (val as i32).to_le_bytes().to_vec(),
                        8 => val.to_le_bytes().to_vec(),
                        16 => {
                            let mut b = (val as i64).to_le_bytes().to_vec();
                            b.extend_from_slice(&[0u8; 8]);
                            b
                        }
                        _ => (val as i32).to_le_bytes().to_vec(),
                    };
                    NumberParseResult::success(bytes)
                }
                Err(_) => {
                    // Check if it's valid but incomplete (e.g., just "-")
                    let valid_input = tok == "-" || tok == "+";
                    NumberParseResult::error(
                        &format!("Invalid number: {}", tok),
                        valid_input,
                    )
                }
            }
        }
    }
}

impl SearchFormat for DecimalSearchFormat {
    fn name(&self) -> &str {
        "Decimal"
    }

    fn tooltip(&self) -> &str {
        "Interpret value as a decimal integer (supports signed and unsigned)."
    }

    fn format_type(&self) -> SearchFormatType {
        SearchFormatType::Integer
    }

    fn parse(&self, input: &str, settings: &SearchSettings) -> Box<dyn ByteMatcher> {
        let input = input.trim();
        if input.is_empty() {
            return Box::new(InvalidByteMatcher::new(""));
        }

        let byte_size = settings.decimal_byte_size();
        let tokens: Vec<&str> = input.split_whitespace().collect();
        let token_count = tokens.len();

        let mut bytes = Vec::with_capacity(token_count * byte_size);
        for tok in &tokens {
            let result = self.parse_number(tok, settings);
            if let Some(err) = result.error_message() {
                return Box::new(InvalidByteMatcher::new(err));
            }
            bytes.extend_from_slice(result.bytes());
        }

        if bytes.is_empty() {
            return Box::new(InvalidByteMatcher::new("No values specified"));
        }

        Box::new(MaskedByteSequenceByteMatcher::new_exact(input, bytes))
    }

    fn value_string(&self, bytes: &[u8], settings: &SearchSettings) -> String {
        let byte_size = settings.decimal_byte_size();
        let is_unsigned = settings.is_decimal_unsigned();

        let mut values = Vec::new();
        for chunk in bytes.chunks(byte_size) {
            if chunk.len() < byte_size {
                break;
            }
            let val_str = if is_unsigned {
                match byte_size {
                    2 => {
                        let val = u16::from_le_bytes([chunk[0], chunk[1]]);
                        val.to_string()
                    }
                    4 => {
                        let val = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
                        val.to_string()
                    }
                    8 => {
                        let val = u64::from_le_bytes(chunk.try_into().unwrap_or([0; 8]));
                        val.to_string()
                    }
                    _ => format!("{:?}", chunk),
                }
            } else {
                match byte_size {
                    2 => {
                        let val = i16::from_le_bytes([chunk[0], chunk[1]]);
                        val.to_string()
                    }
                    4 => {
                        let val = i32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
                        val.to_string()
                    }
                    8 => {
                        let val = i64::from_le_bytes(chunk.try_into().unwrap_or([0; 8]));
                        val.to_string()
                    }
                    _ => format!("{:?}", chunk),
                }
            };
            values.push(val_str);
        }
        values.join(" ")
    }

    fn compare_values(&self, a: &[u8], b: &[u8], settings: &SearchSettings) -> i32 {
        let byte_size = settings.decimal_byte_size();
        if a.len() < byte_size || b.len() < byte_size {
            return 0;
        }
        let va = i64::from_le_bytes(a[..8].try_into().unwrap_or([0; 8]));
        let vb = i64::from_le_bytes(b[..8].try_into().unwrap_or([0; 8]));
        va.cmp(&vb) as i32
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
    fn test_decimal_simple() {
        let fmt = DecimalSearchFormat;
        let m = fmt.parse("255", &default_settings());
        assert!(m.pattern_length() > 0);
    }

    #[test]
    fn test_decimal_multiple() {
        let fmt = DecimalSearchFormat;
        let m = fmt.parse("255 128 64", &default_settings());
        assert!(m.pattern_length() > 0);
    }

    #[test]
    fn test_decimal_empty() {
        let fmt = DecimalSearchFormat;
        let m = fmt.parse("", &default_settings());
        assert_eq!(m.pattern_length(), 0);
    }

    #[test]
    fn test_decimal_negative() {
        let settings = SearchSettings::default().with_decimal_unsigned(false);
        let fmt = DecimalSearchFormat;
        let m = fmt.parse("-1", &settings);
        assert!(m.pattern_length() > 0);
    }
}
