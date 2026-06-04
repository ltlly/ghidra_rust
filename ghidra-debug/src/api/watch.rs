//! WatchRow - a watch expression row in the debugger watch panel.
//!
//! Ported from Ghidra's `ghidra.debug.api.watch.WatchRow`.

use serde::{Deserialize, Serialize};

/// The display format for a watch value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ValueFormat {
    /// Display as hexadecimal.
    Hex,
    /// Display as decimal.
    Decimal,
    /// Display as binary.
    Binary,
    /// Display as octal.
    Octal,
    /// Display as a string.
    String,
    /// Display as an address.
    Address,
}

impl Default for ValueFormat {
    fn default() -> Self {
        Self::Hex
    }
}

/// A row in the watch panel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchRow {
    /// The watch expression.
    pub expression: String,
    /// The resolved value (as bytes).
    pub value: Option<Vec<u8>>,
    /// The display format.
    pub format: ValueFormat,
    /// Whether this row is expanded (for composite types).
    pub expanded: bool,
    /// Error message if expression evaluation failed.
    pub error: Option<String>,
    /// Thread key for register watches.
    pub thread_key: Option<i64>,
    /// Frame level for register watches.
    pub frame_level: Option<i32>,
}

impl WatchRow {
    /// Create a new watch row.
    pub fn new(expression: impl Into<String>) -> Self {
        Self {
            expression: expression.into(),
            value: None,
            format: ValueFormat::Hex,
            expanded: false,
            error: None,
            thread_key: None,
            frame_level: None,
        }
    }

    /// Set the value.
    pub fn with_value(mut self, value: Vec<u8>) -> Self {
        self.value = Some(value);
        self
    }

    /// Set the display format.
    pub fn with_format(mut self, format: ValueFormat) -> Self {
        self.format = format;
        self
    }

    /// Set an error message.
    pub fn with_error(mut self, error: impl Into<String>) -> Self {
        self.error = Some(error.into());
        self
    }

    /// Whether this watch row has an error.
    pub fn has_error(&self) -> bool {
        self.error.is_some()
    }

    /// Get the value as a u64 (little-endian), if available.
    pub fn value_as_u64(&self) -> Option<u64> {
        self.value.as_ref().and_then(|v| {
            if v.len() >= 8 {
                let mut buf = [0u8; 8];
                buf.copy_from_slice(&v[..8]);
                Some(u64::from_le_bytes(buf))
            } else if v.len() >= 4 {
                let mut buf = [0u8; 4];
                buf.copy_from_slice(&v[..4]);
                Some(u32::from_le_bytes(buf) as u64)
            } else {
                None
            }
        })
    }
}

/// ValStr - a typed value string for displaying in the UI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValStr<T> {
    /// The value.
    pub value: T,
    /// The string representation.
    pub display: String,
}

impl<T: std::fmt::Display> ValStr<T> {
    /// Create a new ValStr.
    pub fn new(value: T) -> Self {
        Self {
            display: value.to_string(),
            value,
        }
    }

    /// Create with a custom display string.
    pub fn with_display(value: T, display: impl Into<String>) -> Self {
        Self {
            value,
            display: display.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_watch_row() {
        let row = WatchRow::new("RAX").with_value(vec![0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(row.expression, "RAX");
        assert!(!row.has_error());
        assert_eq!(row.value_as_u64(), Some(0x42));
    }

    #[test]
    fn test_watch_row_error() {
        let row = WatchRow::new("bad_expr").with_error("undefined symbol");
        assert!(row.has_error());
    }

    #[test]
    fn test_watch_row_format() {
        let row = WatchRow::new("RAX").with_format(ValueFormat::Decimal);
        assert_eq!(row.format, ValueFormat::Decimal);
    }

    #[test]
    fn test_val_str() {
        let vs = ValStr::new(42);
        assert_eq!(vs.display, "42");
        assert_eq!(vs.value, 42);

        let vs2 = ValStr::with_display(0xff, "0xFF");
        assert_eq!(vs2.display, "0xFF");
    }
}
