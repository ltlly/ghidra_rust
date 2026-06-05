//! Variable value hover data model.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.gui.stack.vars` package.
//! Provides data model types for the variable value hover and table
//! that shows variable values during debugging.

use serde::{Deserialize, Serialize};

use crate::model::memory::TraceMemoryState;

// ---------------------------------------------------------------------------
// Variable value row
// ---------------------------------------------------------------------------

/// A row displayed in the variable value hover table.
///
/// Ported from Ghidra's `VariableValueRow` interface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VariableValueRow {
    /// The variable name.
    pub name: String,
    /// The data type name.
    pub data_type: String,
    /// The formatted value (HTML styled).
    pub value: String,
    /// The memory state (known/stale/error).
    pub memory_state: TraceMemoryState,
    /// The value address.
    pub address: Option<u64>,
    /// Whether the value is stale (from a previous snapshot).
    pub is_stale: bool,
    /// The error message (if the value could not be read).
    pub error: Option<String>,
}

impl VariableValueRow {
    /// Create a new variable value row.
    pub fn new(
        name: impl Into<String>,
        data_type: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            data_type: data_type.into(),
            value: value.into(),
            memory_state: TraceMemoryState::Known,
            address: None,
            is_stale: false,
            error: None,
        }
    }

    /// Create a stale value row.
    pub fn stale(name: impl Into<String>, data_type: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            data_type: data_type.into(),
            value: String::new(),
            memory_state: TraceMemoryState::Unknown,
            address: None,
            is_stale: true,
            error: None,
        }
    }

    /// Create an error value row.
    pub fn error(
        name: impl Into<String>,
        data_type: impl Into<String>,
        error: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            data_type: data_type.into(),
            value: String::new(),
            memory_state: TraceMemoryState::Error,
            address: None,
            is_stale: false,
            error: Some(error.into()),
        }
    }

    /// Style the value as HTML based on memory state.
    pub fn styled_value(&self) -> String {
        if let Some(err) = &self.error {
            format!("<font color='red'>{}</font>", html_escape(err))
        } else if self.is_stale {
            format!("<font color='gray'>{}</font>", html_escape(&self.value))
        } else {
            self.value.clone()
        }
    }
}

/// Escape HTML special characters.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

// ---------------------------------------------------------------------------
// Variable value hover service
// ---------------------------------------------------------------------------

/// Configuration for the variable value hover.
///
/// Ported from Ghidra's `VariableValueHoverPlugin`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VariableValueHoverConfig {
    /// Whether the hover is enabled.
    pub enabled: bool,
    /// The maximum number of rows to show.
    pub max_rows: usize,
    /// Whether to show register variables.
    pub show_registers: bool,
    /// Whether to show stack variables.
    pub show_stack: bool,
    /// Whether to show memory state indicators.
    pub show_memory_state: bool,
    /// Whether to follow the cursor (vs. fixed to address).
    pub follow_cursor: bool,
}

impl Default for VariableValueHoverConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_rows: 50,
            show_registers: true,
            show_stack: true,
            show_memory_state: true,
            follow_cursor: true,
        }
    }
}

// ---------------------------------------------------------------------------
// Variable value table model
// ---------------------------------------------------------------------------

/// The data model for the variable value table.
///
/// Ported from Ghidra's `VariableValueTable`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VariableValueTableModel {
    /// The variable rows.
    pub rows: Vec<VariableValueRow>,
    /// The hover configuration.
    pub config: VariableValueHoverConfig,
    /// The function name being inspected.
    pub function_name: Option<String>,
    /// The instruction address being inspected.
    pub instruction_address: Option<u64>,
}

impl VariableValueTableModel {
    /// Create a new empty table model.
    pub fn new() -> Self {
        Self {
            rows: Vec::new(),
            config: VariableValueHoverConfig::default(),
            function_name: None,
            instruction_address: None,
        }
    }

    /// Add a row.
    pub fn add_row(&mut self, row: VariableValueRow) {
        if self.rows.len() < self.config.max_rows {
            self.rows.push(row);
        }
    }

    /// Clear all rows.
    pub fn clear(&mut self) {
        self.rows.clear();
        self.function_name = None;
        self.instruction_address = None;
    }

    /// Get the number of rows.
    pub fn row_count(&self) -> usize {
        self.rows.len()
    }

    /// Whether there are any stale values.
    pub fn has_stale_values(&self) -> bool {
        self.rows.iter().any(|r| r.is_stale)
    }

    /// Whether there are any errors.
    pub fn has_errors(&self) -> bool {
        self.rows.iter().any(|r| r.error.is_some())
    }

    /// Get rows filtered by register/stack.
    pub fn register_rows(&self) -> Vec<&VariableValueRow> {
        self.rows
            .iter()
            .filter(|r| r.address.is_none() || r.address.unwrap() < 0x10000)
            .collect()
    }

    /// Get rows filtered by stack addresses.
    pub fn stack_rows(&self) -> Vec<&VariableValueRow> {
        self.rows
            .iter()
            .filter(|r| r.address.is_some() && r.address.unwrap() >= 0x10000)
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Variable value utility functions
// ---------------------------------------------------------------------------

/// Utility functions for formatting variable values.
///
/// Ported from Ghidra's `VariableValueUtils`.
pub struct VariableValueUtils;

impl VariableValueUtils {
    /// Format a raw byte buffer as a hex string.
    pub fn format_hex(bytes: &[u8]) -> String {
        bytes
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Format a raw byte buffer as a decimal integer (little-endian).
    pub fn format_decimal_le(bytes: &[u8]) -> String {
        let val: u64 = bytes
            .iter()
            .enumerate()
            .map(|(i, &b)| (b as u64) << (i * 8))
            .sum();
        val.to_string()
    }

    /// Format a raw byte buffer as a hexadecimal integer (little-endian).
    pub fn format_hex_le(bytes: &[u8]) -> String {
        let val: u64 = bytes
            .iter()
            .enumerate()
            .map(|(i, &b)| (b as u64) << (i * 8))
            .sum();
        format!("0x{:X}", val)
    }

    /// Format a raw byte buffer as a decimal integer (big-endian).
    pub fn format_decimal_be(bytes: &[u8]) -> String {
        let val: u64 = bytes
            .iter()
            .fold(0u64, |acc, &b| (acc << 8) | (b as u64));
        val.to_string()
    }

    /// Format a floating-point value from bytes (32-bit little-endian).
    pub fn format_float32_le(bytes: &[u8]) -> String {
        if bytes.len() < 4 {
            return "<insufficient bytes>".into();
        }
        let val = f32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        format!("{}", val)
    }

    /// Format a floating-point value from bytes (64-bit little-endian).
    pub fn format_float64_le(bytes: &[u8]) -> String {
        if bytes.len() < 8 {
            return "<insufficient bytes>".into();
        }
        let val = f64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]);
        format!("{}", val)
    }

    /// Style a string with memory state coloring (HTML).
    pub fn style_state(state: TraceMemoryState, value: &str) -> String {
        match state {
            TraceMemoryState::Known => value.to_string(),
            TraceMemoryState::Unknown => {
                format!("<font color='gray'>{}</font>", html_escape(value))
            }
            TraceMemoryState::Error => {
                format!("<font color='red'>{}</font>", html_escape(value))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_variable_value_row_new() {
        let row = VariableValueRow::new("rax", "long", "0x1234");
        assert_eq!(row.name, "rax");
        assert_eq!(row.data_type, "long");
        assert_eq!(row.value, "0x1234");
        assert_eq!(row.memory_state, TraceMemoryState::Known);
        assert!(!row.is_stale);
    }

    #[test]
    fn test_variable_value_row_stale() {
        let row = VariableValueRow::stale("rbx", "long");
        assert!(row.is_stale);
        assert_eq!(row.memory_state, TraceMemoryState::Unknown);
    }

    #[test]
    fn test_variable_value_row_error() {
        let row = VariableValueRow::error("rcx", "long", "Cannot read memory");
        assert!(row.error.is_some());
        assert_eq!(row.memory_state, TraceMemoryState::Error);
    }

    #[test]
    fn test_styled_value() {
        let row = VariableValueRow::new("rax", "long", "0x1234");
        assert_eq!(row.styled_value(), "0x1234");

        let stale = VariableValueRow::stale("rbx", "long");
        assert!(stale.styled_value().contains("gray"));

        let err = VariableValueRow::error("rcx", "long", "fail");
        assert!(err.styled_value().contains("red"));
    }

    #[test]
    fn test_table_model() {
        let mut model = VariableValueTableModel::new();
        model.add_row(VariableValueRow::new("rax", "long", "42"));
        model.add_row(VariableValueRow::stale("rbx", "long"));
        assert_eq!(model.row_count(), 2);
        assert!(model.has_stale_values());
        assert!(!model.has_errors());
        model.clear();
        assert_eq!(model.row_count(), 0);
    }

    #[test]
    fn test_table_model_max_rows() {
        let mut model = VariableValueTableModel::new();
        model.config.max_rows = 2;
        model.add_row(VariableValueRow::new("a", "int", "1"));
        model.add_row(VariableValueRow::new("b", "int", "2"));
        model.add_row(VariableValueRow::new("c", "int", "3"));
        assert_eq!(model.row_count(), 2);
    }

    #[test]
    fn test_variable_value_utils_hex() {
        assert_eq!(VariableValueUtils::format_hex(&[0x0A, 0xFF, 0x00]), "0a ff 00");
    }

    #[test]
    fn test_variable_value_utils_decimal_le() {
        assert_eq!(
            VariableValueUtils::format_decimal_le(&[0x34, 0x12, 0x00, 0x00]),
            "4660"
        );
    }

    #[test]
    fn test_variable_value_utils_hex_le() {
        assert_eq!(
            VariableValueUtils::format_hex_le(&[0x34, 0x12, 0x00, 0x00]),
            "0x1234"
        );
    }

    #[test]
    fn test_variable_value_utils_decimal_be() {
        assert_eq!(
            VariableValueUtils::format_decimal_be(&[0x00, 0x00, 0x12, 0x34]),
            "4660"
        );
    }

    #[test]
    fn test_variable_value_utils_float() {
        let bytes = 1.0f32.to_le_bytes();
        assert_eq!(VariableValueUtils::format_float32_le(&bytes), "1");
    }

    #[test]
    fn test_style_state() {
        let styled = VariableValueUtils::style_state(TraceMemoryState::Unknown, "42");
        assert!(styled.contains("gray"));
        let styled = VariableValueUtils::style_state(TraceMemoryState::Known, "42");
        assert_eq!(styled, "42");
    }

    #[test]
    fn test_hover_config_default() {
        let config = VariableValueHoverConfig::default();
        assert!(config.enabled);
        assert_eq!(config.max_rows, 50);
        assert!(config.show_registers);
        assert!(config.show_stack);
    }
}
