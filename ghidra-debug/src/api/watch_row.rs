//! Watch row types for the debugger watch panel.
//!
//! Ported from Ghidra's `ghidra.debug.api.watch`:
//! - `WatchRow`: A row in the watch panel representing a watched expression.
//!
//! The watch panel allows users to monitor variables and expressions during
//! debugging. Each row represents a single watched expression with its current
//! value, type, and formatting options.

use serde::{Deserialize, Serialize};

/// A row in the watch panel.
///
/// Ported from `WatchRow`. Represents a watched expression with its
/// current value, type information, and display formatting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchRow {
    /// The expression being watched (e.g., variable name, address expression).
    pub expression: String,
    /// The current value of the expression, if evaluated.
    pub value: Option<String>,
    /// The data type of the value.
    pub data_type: Option<String>,
    /// The display format for the value.
    pub format: WatchFormat,
    /// The snap at which the value was last evaluated.
    pub last_snap: Option<i64>,
    /// Whether this row is enabled (active).
    pub enabled: bool,
    /// An error message, if the expression could not be evaluated.
    pub error: Option<String>,
    /// The number of elements to display (for arrays).
    pub element_count: Option<usize>,
    /// Whether this is a user-entered expression.
    pub is_user_expression: bool,
    /// The address that the expression resolved to.
    pub resolved_address: Option<u64>,
    /// The size of the value in bytes.
    pub value_size: Option<u32>,
}

/// Display format for watch values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WatchFormat {
    /// Hexadecimal format.
    Hex,
    /// Decimal (signed) format.
    Decimal,
    /// Unsigned decimal format.
    UnsignedDecimal,
    /// Binary format.
    Binary,
    /// Octal format.
    Octal,
    /// Character format.
    Char,
    /// Floating-point format.
    Float,
    /// String format.
    String,
    /// Address/pointer format.
    Address,
    /// Auto-detect format.
    Auto,
}

impl WatchFormat {
    /// Get the display name for this format.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Hex => "Hex",
            Self::Decimal => "Decimal",
            Self::UnsignedDecimal => "Unsigned",
            Self::Binary => "Binary",
            Self::Octal => "Octal",
            Self::Char => "Char",
            Self::Float => "Float",
            Self::String => "String",
            Self::Address => "Address",
            Self::Auto => "Auto",
        }
    }
}

impl WatchRow {
    /// Create a new watch row for the given expression.
    pub fn new(expression: &str) -> Self {
        Self {
            expression: expression.to_string(),
            value: None,
            data_type: None,
            format: WatchFormat::Hex,
            last_snap: None,
            enabled: true,
            error: None,
            element_count: None,
            is_user_expression: true,
            resolved_address: None,
            value_size: None,
        }
    }

    /// Set the value.
    pub fn with_value(mut self, value: &str) -> Self {
        self.value = Some(value.to_string());
        self
    }

    /// Set the data type.
    pub fn with_data_type(mut self, data_type: &str) -> Self {
        self.data_type = Some(data_type.to_string());
        self
    }

    /// Set the display format.
    pub fn with_format(mut self, format: WatchFormat) -> Self {
        self.format = format;
        self
    }

    /// Set an error.
    pub fn with_error(mut self, error: &str) -> Self {
        self.error = Some(error.to_string());
        self
    }

    /// Check if this watch row has a value.
    pub fn has_value(&self) -> bool {
        self.value.is_some() && self.error.is_none()
    }

    /// Check if this watch row has an error.
    pub fn has_error(&self) -> bool {
        self.error.is_some()
    }

    /// Get the display value (value or error).
    pub fn display_value(&self) -> &str {
        if let Some(ref err) = self.error {
            err
        } else if let Some(ref val) = self.value {
            val
        } else {
            "<not evaluated>"
        }
    }
}

/// Saved watch settings for persistence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SavedWatchSettings {
    /// The list of saved watch expressions.
    pub watches: Vec<SavedWatchEntry>,
    /// The default format for new watches.
    pub default_format: WatchFormat,
    /// Whether to auto-evaluate watches on snap change.
    pub auto_evaluate: bool,
    /// The maximum number of watch entries.
    pub max_entries: Option<usize>,
}

/// A saved watch entry for persistence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SavedWatchEntry {
    /// The expression.
    pub expression: String,
    /// The format.
    pub format: WatchFormat,
    /// Whether enabled.
    pub enabled: bool,
    /// The element count (for arrays).
    pub element_count: Option<usize>,
}

impl SavedWatchSettings {
    /// Create new default settings.
    pub fn new() -> Self {
        Self {
            watches: Vec::new(),
            default_format: WatchFormat::Hex,
            auto_evaluate: true,
            max_entries: None,
        }
    }

    /// Add a watch entry.
    pub fn add_watch(&mut self, expression: &str, format: WatchFormat) {
        self.watches.push(SavedWatchEntry {
            expression: expression.to_string(),
            format,
            enabled: true,
            element_count: None,
        });
    }

    /// Remove a watch entry by expression.
    pub fn remove_watch(&mut self, expression: &str) -> bool {
        let before = self.watches.len();
        self.watches.retain(|w| w.expression != expression);
        self.watches.len() < before
    }
}

impl Default for SavedWatchSettings {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_watch_row_creation() {
        let row = WatchRow::new("myVar");
        assert_eq!(row.expression, "myVar");
        assert!(row.value.is_none());
        assert!(row.enabled);
        assert_eq!(row.format, WatchFormat::Hex);
        assert!(!row.has_value());
        assert!(!row.has_error());
    }

    #[test]
    fn test_watch_row_with_value() {
        let row = WatchRow::new("myVar")
            .with_value("0x42")
            .with_data_type("int");

        assert!(row.has_value());
        assert_eq!(row.display_value(), "0x42");
    }

    #[test]
    fn test_watch_row_with_error() {
        let row = WatchRow::new("badExpr")
            .with_error("symbol not found");

        assert!(row.has_error());
        assert!(!row.has_value());
        assert_eq!(row.display_value(), "symbol not found");
    }

    #[test]
    fn test_watch_row_not_evaluated() {
        let row = WatchRow::new("myVar");
        assert_eq!(row.display_value(), "<not evaluated>");
    }

    #[test]
    fn test_watch_format_display_names() {
        assert_eq!(WatchFormat::Hex.display_name(), "Hex");
        assert_eq!(WatchFormat::Decimal.display_name(), "Decimal");
        assert_eq!(WatchFormat::Binary.display_name(), "Binary");
        assert_eq!(WatchFormat::String.display_name(), "String");
        assert_eq!(WatchFormat::Auto.display_name(), "Auto");
    }

    #[test]
    fn test_saved_watch_settings() {
        let mut settings = SavedWatchSettings::new();
        assert!(settings.watches.is_empty());

        settings.add_watch("var1", WatchFormat::Hex);
        settings.add_watch("var2", WatchFormat::Decimal);
        assert_eq!(settings.watches.len(), 2);

        assert!(settings.remove_watch("var1"));
        assert_eq!(settings.watches.len(), 1);
        assert!(!settings.remove_watch("nonexistent"));
    }

    #[test]
    fn test_watch_row_builder_chain() {
        let row = WatchRow::new("*0x1000")
            .with_value("42")
            .with_data_type("int")
            .with_format(WatchFormat::Decimal);

        assert_eq!(row.format, WatchFormat::Decimal);
        assert_eq!(row.data_type.as_deref(), Some("int"));
        assert!(row.has_value());
    }
}
