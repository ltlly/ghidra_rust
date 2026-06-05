//! Watch service implementation for the debugger.
//!
//! Ported from Ghidra's `DebuggerWatchesService` and related watch types
//! in the Debugger-api and Debugger modules. Provides variable watch
//! expression management for debugging sessions.

use serde::{Deserialize, Serialize};

/// The format for displaying watch values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WatchFormat {
    /// Hexadecimal format.
    Hex,
    /// Decimal format.
    Decimal,
    /// Binary format.
    Binary,
    /// Octal format.
    Octal,
    /// ASCII character representation.
    Ascii,
    /// Floating point representation.
    Float,
    /// Signed integer representation.
    Signed,
    /// Unsigned integer representation.
    Unsigned,
}

impl WatchFormat {
    /// Get the display name.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Hex => "Hex",
            Self::Decimal => "Decimal",
            Self::Binary => "Binary",
            Self::Octal => "Octal",
            Self::Ascii => "ASCII",
            Self::Float => "Float",
            Self::Signed => "Signed",
            Self::Unsigned => "Unsigned",
        }
    }

    /// Format a 64-bit value according to this format.
    pub fn format_value(&self, value: u64) -> String {
        match self {
            Self::Hex => format!("0x{:x}", value),
            Self::Decimal => format!("{}", value),
            Self::Binary => format!("0b{:b}", value),
            Self::Octal => format!("0o{:o}", value),
            Self::Ascii => {
                let bytes = value.to_le_bytes();
                let s: String = bytes
                    .iter()
                    .filter(|b| b.is_ascii_graphic() || **b == b' ')
                    .map(|&b| b as char)
                    .collect();
                format!("'{}'", s)
            }
            Self::Float => {
                let f = f64::from_bits(value);
                format!("{}", f)
            }
            Self::Signed => {
                format!("{}", value as i64)
            }
            Self::Unsigned => format!("{}", value),
        }
    }
}

/// A watch row in the watches panel.
///
/// Ported from Ghidra's `WatchRow`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchRow {
    /// The expression being watched.
    pub expression: String,
    /// The current value (if resolved).
    pub value: Option<u64>,
    /// The display format.
    pub format: WatchFormat,
    /// The number of bytes to display.
    pub length: usize,
    /// Whether the expression is valid.
    pub valid: bool,
    /// An error message if the expression could not be evaluated.
    pub error: Option<String>,
}

impl WatchRow {
    /// Create a new watch row.
    pub fn new(expression: impl Into<String>) -> Self {
        Self {
            expression: expression.into(),
            value: None,
            format: WatchFormat::Hex,
            length: 4,
            valid: false,
            error: None,
        }
    }

    /// Set the value.
    pub fn with_value(mut self, value: u64) -> Self {
        self.value = Some(value);
        self.valid = true;
        self.error = None;
        self
    }

    /// Set the format.
    pub fn with_format(mut self, format: WatchFormat) -> Self {
        self.format = format;
        self
    }

    /// Set the length in bytes.
    pub fn with_length(mut self, length: usize) -> Self {
        self.length = length;
        self
    }

    /// Set an error.
    pub fn with_error(mut self, error: impl Into<String>) -> Self {
        self.error = Some(error.into());
        self.valid = false;
        self.value = None;
        self
    }

    /// Get the formatted display value.
    pub fn display_value(&self) -> String {
        match self.value {
            Some(v) => self.format.format_value(v),
            None => match &self.error {
                Some(e) => format!("Error: {}", e),
                None => "???".to_string(),
            },
        }
    }

    /// Whether the watch has a resolved value.
    pub fn has_value(&self) -> bool {
        self.value.is_some() && self.valid
    }
}

/// Saved watch settings for persistence.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SavedWatchSettings {
    /// The saved watch expressions.
    pub watches: Vec<SavedWatchEntry>,
}

/// A single saved watch entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SavedWatchEntry {
    /// The expression.
    pub expression: String,
    /// The display format.
    pub format: WatchFormat,
    /// The number of bytes.
    pub length: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_watch_format_display() {
        assert_eq!(WatchFormat::Hex.display_name(), "Hex");
        assert_eq!(WatchFormat::Decimal.display_name(), "Decimal");
    }

    #[test]
    fn test_watch_format_hex() {
        assert_eq!(WatchFormat::Hex.format_value(255), "0xff");
        assert_eq!(WatchFormat::Hex.format_value(0x400000), "0x400000");
    }

    #[test]
    fn test_watch_format_decimal() {
        assert_eq!(WatchFormat::Decimal.format_value(255), "255");
    }

    #[test]
    fn test_watch_format_binary() {
        assert_eq!(WatchFormat::Binary.format_value(5), "0b101");
    }

    #[test]
    fn test_watch_format_octal() {
        assert_eq!(WatchFormat::Octal.format_value(8), "0o10");
    }

    #[test]
    fn test_watch_format_signed() {
        assert_eq!(WatchFormat::Signed.format_value(u64::MAX), "-1");
    }

    #[test]
    fn test_watch_format_float() {
        let val = 1.0_f64.to_bits();
        assert_eq!(WatchFormat::Float.format_value(val), "1");
    }

    #[test]
    fn test_watch_row_basic() {
        let row = WatchRow::new("RAX");
        assert_eq!(row.expression, "RAX");
        assert!(!row.has_value());
        assert_eq!(row.display_value(), "???");
    }

    #[test]
    fn test_watch_row_with_value() {
        let row = WatchRow::new("RAX")
            .with_value(0x400000)
            .with_format(WatchFormat::Hex);
        assert!(row.has_value());
        assert_eq!(row.display_value(), "0x400000");
    }

    #[test]
    fn test_watch_row_with_error() {
        let row = WatchRow::new("INVALID")
            .with_error("Symbol not found");
        assert!(!row.has_value());
        assert!(row.display_value().contains("Symbol not found"));
    }

    #[test]
    fn test_watch_row_change_format() {
        let row = WatchRow::new("RAX")
            .with_value(255)
            .with_format(WatchFormat::Decimal);
        assert_eq!(row.display_value(), "255");
    }

    #[test]
    fn test_watch_row_length() {
        let row = WatchRow::new("RAX")
            .with_length(8);
        assert_eq!(row.length, 8);
    }

    #[test]
    fn test_saved_watch_settings() {
        let settings = SavedWatchSettings {
            watches: vec![
                SavedWatchEntry {
                    expression: "RAX".into(),
                    format: WatchFormat::Hex,
                    length: 8,
                },
                SavedWatchEntry {
                    expression: "[RSP]".into(),
                    format: WatchFormat::Decimal,
                    length: 4,
                },
            ],
        };
        assert_eq!(settings.watches.len(), 2);
    }

    #[test]
    fn test_watch_row_serde() {
        let row = WatchRow::new("RAX").with_value(42);
        let json = serde_json::to_string(&row).unwrap();
        let back: WatchRow = serde_json::from_str(&json).unwrap();
        assert_eq!(back.expression, "RAX");
        assert_eq!(back.value, Some(42));
    }
}
