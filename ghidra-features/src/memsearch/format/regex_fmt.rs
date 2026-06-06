//! `RegExSearchFormat` -- regular expression input.
//!
//! Ported from `ghidra.features.base.memsearch.format.RegExSearchFormat`.

use crate::memsearch::format::{SearchFormat, SearchFormatType};
use crate::memsearch::gui::SearchSettings;
use crate::memsearch::matcher::{ByteMatcher, RegExByteMatcher, InvalidByteMatcher};

/// Search format for interpreting user input as a regular expression.
///
/// Ported from `RegExSearchFormat.java`.
#[derive(Debug, Clone, Copy)]
pub struct RegExSearchFormat;

impl SearchFormat for RegExSearchFormat {
    fn name(&self) -> &str {
        "Reg Ex"
    }

    fn tooltip(&self) -> &str {
        "Interpret value as a regular expression."
    }

    fn format_type(&self) -> SearchFormatType {
        SearchFormatType::StringType
    }

    fn parse(&self, input: &str, _settings: &SearchSettings) -> Box<dyn ByteMatcher> {
        let input = input.trim();
        if input.is_empty() {
            return Box::new(InvalidByteMatcher::new(""));
        }

        match RegExByteMatcher::new(input) {
            Ok(m) => Box::new(m),
            Err(e) => Box::new(InvalidByteMatcher::new(&e)),
        }
    }

    fn value_string(&self, bytes: &[u8], _settings: &SearchSettings) -> String {
        String::from_utf8_lossy(bytes).to_string()
    }

    fn compare_values(&self, a: &[u8], b: &[u8], _settings: &SearchSettings) -> i32 {
        let sa = String::from_utf8_lossy(a);
        let sb = String::from_utf8_lossy(b);
        sa.cmp(&sb) as i32
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
    fn test_regex_parse() {
        let fmt = RegExSearchFormat;
        let m = fmt.parse("\\x55\\x89", &default_settings());
        assert_eq!(m.description(), "Reg Ex");
    }

    #[test]
    fn test_regex_empty() {
        let fmt = RegExSearchFormat;
        let m = fmt.parse("", &default_settings());
        assert_eq!(m.pattern_length(), 0);
    }

    #[test]
    fn test_regex_invalid() {
        let fmt = RegExSearchFormat;
        let m = fmt.parse("[invalid", &default_settings());
        // Should return InvalidByteMatcher
        assert_eq!(m.pattern_length(), 0);
    }

    #[test]
    fn test_regex_value_string() {
        let fmt = RegExSearchFormat;
        let v = fmt.value_string(b"Hello", &default_settings());
        assert_eq!(v, "Hello");
    }
}
