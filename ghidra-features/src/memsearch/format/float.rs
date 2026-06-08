//! `FloatSearchFormat` -- floating-point value input.
//!
//! Ported from `ghidra.features.base.memsearch.format.FloatSearchFormat`.

use crate::memsearch::format::{SearchFormat, SearchFormatType, NumberParseResult};
use crate::memsearch::gui::SearchSettings;
use crate::memsearch::matcher::{ByteMatcher, MaskedByteSequenceByteMatcher, InvalidByteMatcher};

/// Search format for parsing floating-point values (float or double).
///
/// Ported from `FloatSearchFormat.java`.
#[derive(Debug, Clone, Copy)]
pub struct FloatSearchFormat {
    /// Display name (e.g., "Floating Point").
    pub long_name: &'static str,
    /// Byte size (4 for float, 8 for double).
    pub byte_size: usize,
}

impl FloatSearchFormat {
    fn parse_number(&self, tok: &str, _settings: &SearchSettings) -> NumberParseResult {
        let tok = tok.trim();
        if tok.is_empty() {
            return NumberParseResult::error("Empty token", false);
        }

        match tok.parse::<f64>() {
            Ok(val) => {
                let bytes = if self.byte_size == 4 {
                    (val as f32).to_le_bytes().to_vec()
                } else {
                    val.to_le_bytes().to_vec()
                };
                NumberParseResult::success(bytes)
            }
            Err(_) => NumberParseResult::error(
                &format!("Invalid floating point number: {}", tok),
                true,
            ),
        }
    }
}

impl SearchFormat for FloatSearchFormat {
    fn name(&self) -> &str {
        if self.byte_size == 4 { "Float" } else { "Double" }
    }

    fn tooltip(&self) -> &str {
        self.long_name
    }

    fn format_type(&self) -> SearchFormatType {
        SearchFormatType::FloatingPoint
    }

    fn parse(&self, input: &str, settings: &SearchSettings) -> Box<dyn ByteMatcher> {
        let input = input.trim();
        if input.is_empty() {
            return Box::new(InvalidByteMatcher::new(""));
        }

        let tokens: Vec<&str> = input.split_whitespace().collect();
        let mut bytes = Vec::with_capacity(tokens.len() * self.byte_size);

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

    fn value_string(&self, bytes: &[u8], _settings: &SearchSettings) -> String {
        let mut values = Vec::new();
        for chunk in bytes.chunks(self.byte_size) {
            if chunk.len() < self.byte_size {
                break;
            }
            let val = if self.byte_size == 4 {
                let arr: [u8; 4] = chunk.try_into().unwrap_or([0; 4]);
                f32::from_le_bytes(arr) as f64
            } else {
                let arr: [u8; 8] = chunk.try_into().unwrap_or([0; 8]);
                f64::from_le_bytes(arr)
            };
            values.push(format!("{}", val));
        }
        values.join(" ")
    }

    fn compare_values(&self, a: &[u8], b: &[u8], _settings: &SearchSettings) -> i32 {
        if a.len() < self.byte_size || b.len() < self.byte_size {
            return 0;
        }
        if self.byte_size == 4 {
            let va = f32::from_le_bytes(a[..4].try_into().unwrap_or([0; 4]));
            let vb = f32::from_le_bytes(b[..4].try_into().unwrap_or([0; 4]));
            va.partial_cmp(&vb).unwrap_or(std::cmp::Ordering::Equal) as i32
        } else {
            let va = f64::from_le_bytes(a[..8].try_into().unwrap_or([0; 8]));
            let vb = f64::from_le_bytes(b[..8].try_into().unwrap_or([0; 8]));
            va.partial_cmp(&vb).unwrap_or(std::cmp::Ordering::Equal) as i32
        }
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
    fn test_float_simple() {
        let fmt = FloatSearchFormat { long_name: "Float", byte_size: 4 };
        let m = fmt.parse("3.14", &default_settings());
        assert_eq!(m.pattern_length(), 4);
    }

    #[test]
    fn test_double_simple() {
        let fmt = FloatSearchFormat { long_name: "Double", byte_size: 8 };
        let m = fmt.parse("3.14", &default_settings());
        assert_eq!(m.pattern_length(), 8);
    }

    #[test]
    fn test_float_empty() {
        let fmt = FloatSearchFormat { long_name: "Float", byte_size: 4 };
        let m = fmt.parse("", &default_settings());
        assert_eq!(m.pattern_length(), 0);
    }

    #[test]
    fn test_float_invalid() {
        let fmt = FloatSearchFormat { long_name: "Float", byte_size: 4 };
        let m = fmt.parse("abc", &default_settings());
        assert_eq!(m.pattern_length(), 0);
    }

    #[test]
    fn test_float_multiple() {
        let fmt = FloatSearchFormat { long_name: "Float", byte_size: 4 };
        let m = fmt.parse("1.0 2.0 3.0", &default_settings());
        assert_eq!(m.pattern_length(), 12);
    }

    #[test]
    fn test_float_name() {
        let f32_fmt = FloatSearchFormat { long_name: "Float", byte_size: 4 };
        assert_eq!(f32_fmt.name(), "Float");

        let f64_fmt = FloatSearchFormat { long_name: "Double", byte_size: 8 };
        assert_eq!(f64_fmt.name(), "Double");
    }
}
