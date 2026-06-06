//! `StringSearchFormat` -- text string input with encoding support.
//!
//! Ported from `ghidra.features.base.memsearch.format.StringSearchFormat`.

use crate::memsearch::format::{SearchFormat, SearchFormatType};
use crate::memsearch::gui::SearchSettings;
use crate::memsearch::matcher::{ByteMatcher, MaskedByteSequenceByteMatcher, InvalidByteMatcher};

/// Search format for parsing text strings.
///
/// Supports various character encodings and escape sequences.
///
/// Ported from `StringSearchFormat.java`.
#[derive(Debug, Clone, Copy)]
pub struct StringSearchFormat;

impl SearchFormat for StringSearchFormat {
    fn name(&self) -> &str {
        "String"
    }

    fn tooltip(&self) -> &str {
        "Interpret value as a text string. Supports escape sequences and character encodings."
    }

    fn format_type(&self) -> SearchFormatType {
        SearchFormatType::StringType
    }

    fn parse(&self, input: &str, settings: &SearchSettings) -> Box<dyn ByteMatcher> {
        let input = input.trim();
        if input.is_empty() {
            return Box::new(InvalidByteMatcher::new(""));
        }

        // Process escape sequences if enabled
        let processed = if settings.use_escape_sequences() && input.len() >= 2 {
            process_escape_sequences(input)
        } else {
            input.to_string()
        };

        // Encode to bytes based on charset
        let bytes = if settings.is_big_endian() {
            processed.encode_utf16().flat_map(|c| c.to_be_bytes()).collect()
        } else {
            processed.as_bytes().to_vec()
        };

        let mut masks = vec![0xFF; bytes.len()];

        // Case-insensitive: mask out bit 5 of ASCII alpha characters
        if !settings.is_case_sensitive() {
            for (i, &b) in bytes.iter().enumerate() {
                if b.is_ascii_alphabetic() {
                    masks[i] = 0xDF;
                }
            }
        }

        Box::new(MaskedByteSequenceByteMatcher::new_masked(input, bytes, masks))
    }

    fn value_string(&self, bytes: &[u8], settings: &SearchSettings) -> String {
        if settings.is_big_endian() {
            // UTF-16 BE
            let chars: Vec<u16> = bytes
                .chunks(2)
                .filter(|c| c.len() == 2)
                .map(|c| u16::from_be_bytes([c[0], c[1]]))
                .collect();
            String::from_utf16_lossy(&chars)
        } else {
            String::from_utf8_lossy(bytes).to_string()
        }
    }

    fn compare_values(&self, a: &[u8], b: &[u8], _settings: &SearchSettings) -> i32 {
        let sa = String::from_utf8_lossy(a);
        let sb = String::from_utf8_lossy(b);
        sa.cmp(&sb) as i32
    }

    fn convert_text(&self, text: &str, _old: &SearchSettings, new: &SearchSettings) -> String {
        if new.is_case_sensitive() {
            text.to_string()
        } else {
            text.to_lowercase()
        }
    }
}

fn process_escape_sequences(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '\\' && i + 1 < chars.len() {
            match chars[i + 1] {
                'n' => result.push('\n'),
                'r' => result.push('\r'),
                't' => result.push('\t'),
                '\\' => result.push('\\'),
                '0' => result.push('\0'),
                '"' => result.push('"'),
                '\'' => result.push('\''),
                other => {
                    result.push('\\');
                    result.push(other);
                }
            }
            i += 2;
        } else {
            result.push(chars[i]);
            i += 1;
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_settings() -> SearchSettings {
        SearchSettings::default()
    }

    #[test]
    fn test_string_simple() {
        let fmt = StringSearchFormat;
        let m = fmt.parse("Hello", &default_settings());
        assert_eq!(m.pattern_length(), 5);
    }

    #[test]
    fn test_string_empty() {
        let fmt = StringSearchFormat;
        let m = fmt.parse("", &default_settings());
        assert_eq!(m.pattern_length(), 0);
    }

    #[test]
    fn test_string_value() {
        let fmt = StringSearchFormat;
        let v = fmt.value_string(b"Hello", &default_settings());
        assert_eq!(v, "Hello");
    }

    #[test]
    fn test_escape_sequences() {
        let settings = SearchSettings::default().with_escape_sequences(true);
        let fmt = StringSearchFormat;
        let m = fmt.parse("Hello\\nWorld", &settings);
        assert_eq!(m.pattern_length(), 11);
    }

    #[test]
    fn test_string_format_type() {
        assert_eq!(StringSearchFormat.format_type(), SearchFormatType::StringType);
    }

    #[test]
    fn test_process_escape_sequences() {
        assert_eq!(process_escape_sequences("Hello\\nWorld"), "Hello\nWorld");
        assert_eq!(process_escape_sequences("tab\\there"), "tab\there");
        assert_eq!(process_escape_sequences("back\\\\slash"), "back\\slash");
    }
}
