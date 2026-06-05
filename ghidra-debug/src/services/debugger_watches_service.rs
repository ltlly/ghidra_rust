//! DebuggerWatchesService - service for watch expressions.
//!
//! Ported from Ghidra's `ghidra.app.services.DebuggerWatchesService`.

use serde::{Deserialize, Serialize};

/// A watch expression entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchExpression {
    /// The expression string (e.g., register name, memory address).
    pub expression: String,
    /// The current value, if evaluated.
    pub current_value: Option<String>,
    /// The display format.
    pub format: WatchFormat,
    /// Whether this expression is enabled.
    pub enabled: bool,
    /// User-provided label.
    pub label: Option<String>,
}

/// Display format for watch values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WatchFormat {
    /// Hexadecimal.
    Hex,
    /// Decimal.
    Decimal,
    /// Binary.
    Binary,
    /// Octal.
    Octal,
    /// ASCII character representation.
    Char,
    /// Floating point.
    Float,
    /// String.
    String,
    /// Auto-detect.
    Auto,
}

impl Default for WatchFormat {
    fn default() -> Self {
        Self::Hex
    }
}

impl WatchExpression {
    /// Create a new watch expression.
    pub fn new(expression: impl Into<String>) -> Self {
        Self {
            expression: expression.into(),
            current_value: None,
            format: WatchFormat::Hex,
            enabled: true,
            label: None,
        }
    }

    /// Create a watch expression with a specific format.
    pub fn with_format(expression: impl Into<String>, format: WatchFormat) -> Self {
        Self {
            format,
            ..Self::new(expression)
        }
    }
}

/// Service interface for watch expressions.
pub trait DebuggerWatchesServiceExt {
    /// Add a watch expression.
    fn add_watch(&mut self, expression: WatchExpression);

    /// Remove a watch expression by index.
    fn remove_watch(&mut self, index: usize);

    /// Get all watch expressions.
    fn watches(&self) -> &[WatchExpression];

    /// Update the value of a watch expression.
    fn update_value(&mut self, index: usize, value: String);

    /// Clear all watch expressions.
    fn clear(&mut self);

    /// Reorder watch expressions.
    fn move_watch(&mut self, from: usize, to: usize);

    /// Set the format for a watch expression.
    fn set_format(&mut self, index: usize, format: WatchFormat);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_watch_expression() {
        let expr = WatchExpression::new("RAX");
        assert_eq!(expr.expression, "RAX");
        assert!(expr.enabled);
        assert_eq!(expr.format, WatchFormat::Hex);
    }

    #[test]
    fn test_watch_formats() {
        assert_ne!(WatchFormat::Hex, WatchFormat::Decimal);
        assert_ne!(WatchFormat::Binary, WatchFormat::Float);
    }

    #[test]
    fn test_watch_with_format() {
        let expr = WatchExpression::with_format("RSP", WatchFormat::Decimal);
        assert_eq!(expr.format, WatchFormat::Decimal);
    }
}
