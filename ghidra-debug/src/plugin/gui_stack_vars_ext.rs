//! Variable value panel extended data models.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.gui.stack.vars` package.
//! Provides data models for the variable value hover plugin, variable value
//! table, and supporting utilities.

use serde::{Deserialize, Serialize};

use crate::model::lifespan::Lifespan;

// ---------------------------------------------------------------------------
// VariableValueRow - row in the variable value table
// ---------------------------------------------------------------------------

/// A row in the variable value table.
///
/// Ported from `VariableValueRow.java`. Represents a single local variable
/// or parameter with its value at a given snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VariableValueRow {
    /// The variable name.
    pub name: String,
    /// The variable's data type name.
    pub data_type: String,
    /// The current value as a string.
    pub value: Option<String>,
    /// The raw bytes of the value, if available.
    pub raw_bytes: Option<Vec<u8>>,
    /// The register or stack offset where the value is stored.
    pub storage: StorageLocation,
    /// Whether the variable has a known value.
    pub has_value: bool,
    /// Whether this variable is a parameter (vs local).
    pub is_parameter: bool,
    /// The frame level (0 = innermost).
    pub frame_level: u32,
}

/// Where a variable's value is stored.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StorageLocation {
    /// Stored in a register.
    Register {
        /// Register name (e.g., "RAX", "x0").
        name: String,
        /// Register size in bytes.
        size: u32,
    },
    /// Stored on the stack at an offset.
    Stack {
        /// Offset from the frame base (can be negative).
        offset: i64,
        /// Size in bytes.
        size: u32,
    },
    /// Stored at a memory address.
    Address {
        /// The memory address.
        address: u64,
        /// Size in bytes.
        size: u32,
    },
    /// Location is unknown.
    Unknown,
}

impl VariableValueRow {
    /// Create a new variable value row.
    pub fn new(name: impl Into<String>, data_type: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            data_type: data_type.into(),
            value: None,
            raw_bytes: None,
            storage: StorageLocation::Unknown,
            has_value: false,
            is_parameter: false,
            frame_level: 0,
        }
    }

    /// Set the value.
    pub fn with_value(mut self, value: impl Into<String>) -> Self {
        self.value = Some(value.into());
        self.has_value = true;
        self
    }

    /// Set the raw bytes.
    pub fn with_raw_bytes(mut self, bytes: Vec<u8>) -> Self {
        self.raw_bytes = Some(bytes);
        self
    }

    /// Set the storage location.
    pub fn with_storage(mut self, storage: StorageLocation) -> Self {
        self.storage = storage;
        self
    }

    /// Mark as a parameter.
    pub fn as_parameter(mut self) -> Self {
        self.is_parameter = true;
        self
    }

    /// Set the frame level.
    pub fn with_frame_level(mut self, level: u32) -> Self {
        self.frame_level = level;
        self
    }

    /// Get a display string for the storage location.
    pub fn storage_display(&self) -> String {
        match &self.storage {
            StorageLocation::Register { name, .. } => format!("reg:{}", name),
            StorageLocation::Stack { offset, .. } => {
                if *offset >= 0 {
                    format!("stack:+0x{:x}", offset)
                } else {
                    format!("stack:-0x{:x}", -offset)
                }
            }
            StorageLocation::Address { address, .. } => format!("mem:0x{:x}", address),
            StorageLocation::Unknown => "unknown".to_string(),
        }
    }

    /// Format the raw bytes as hex.
    pub fn hex_value(&self) -> Option<String> {
        self.raw_bytes.as_ref().map(|bytes| {
            bytes.iter().map(|b| format!("{:02x}", b)).collect::<String>()
        })
    }
}

// ---------------------------------------------------------------------------
// VariableValueTable - table model for variable values
// ---------------------------------------------------------------------------

/// Table model for variable values in a stack frame.
///
/// Ported from `VariableValueTable.java`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VariableValueTable {
    /// The rows in the table.
    pub rows: Vec<VariableValueRow>,
    /// The thread key, if associated with a specific thread.
    pub thread_key: Option<i64>,
    /// The frame level being displayed.
    pub frame_level: u32,
    /// The snap at which values are shown.
    pub snap: i64,
}

impl VariableValueTable {
    /// Create a new empty table.
    pub fn new(snap: i64) -> Self {
        Self {
            rows: Vec::new(),
            thread_key: None,
            frame_level: 0,
            snap,
        }
    }

    /// Add a row to the table.
    pub fn add_row(&mut self, row: VariableValueRow) {
        self.rows.push(row);
    }

    /// Get the number of rows.
    pub fn row_count(&self) -> usize {
        self.rows.len()
    }

    /// Get a row by index.
    pub fn row(&self, index: usize) -> Option<&VariableValueRow> {
        self.rows.get(index)
    }

    /// Get all parameter rows.
    pub fn parameters(&self) -> Vec<&VariableValueRow> {
        self.rows.iter().filter(|r| r.is_parameter).collect()
    }

    /// Get all local variable rows.
    pub fn locals(&self) -> Vec<&VariableValueRow> {
        self.rows.iter().filter(|r| !r.is_parameter).collect()
    }

    /// Find a row by variable name.
    pub fn find_by_name(&self, name: &str) -> Option<&VariableValueRow> {
        self.rows.iter().find(|r| r.name == name)
    }

    /// Get rows that have values.
    pub fn rows_with_values(&self) -> Vec<&VariableValueRow> {
        self.rows.iter().filter(|r| r.has_value).collect()
    }

    /// Clear all rows.
    pub fn clear(&mut self) {
        self.rows.clear();
    }
}

// ---------------------------------------------------------------------------
// VariableValueHoverModel - data model for hover popups
// ---------------------------------------------------------------------------

/// Data model for the variable value hover plugin.
///
/// Ported from `VariableValueHoverPlugin.java` and `VariableValueHoverService.java`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VariableValueHoverModel {
    /// The variable being hovered.
    pub variable: VariableValueRow,
    /// The context information (address, register, etc.).
    pub context: HoverContext,
    /// Whether to show raw hex values.
    pub show_hex: bool,
    /// Whether to show the data type.
    pub show_type: bool,
    /// Maximum number of characters in the value display.
    pub max_value_display: usize,
}

/// Context for a hover popup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HoverContext {
    /// The address where the hover was triggered.
    pub address: u64,
    /// The snap at which to show values.
    pub snap: i64,
    /// The thread key, if applicable.
    pub thread_key: Option<i64>,
    /// The frame level.
    pub frame_level: u32,
}

impl VariableValueHoverModel {
    /// Create a new hover model.
    pub fn new(variable: VariableValueRow, address: u64, snap: i64) -> Self {
        Self {
            variable,
            context: HoverContext {
                address,
                snap,
                thread_key: None,
                frame_level: 0,
            },
            show_hex: true,
            show_type: true,
            max_value_display: 128,
        }
    }

    /// Format the hover text.
    pub fn format_hover_text(&self) -> String {
        let mut text = String::new();

        if self.show_type {
            text.push_str(&format!("{} ", self.variable.data_type));
        }
        text.push_str(&self.variable.name);

        if let Some(ref value) = self.variable.value {
            text.push_str(&format!(" = {}", value));
            if self.show_hex {
                if let Some(ref hex) = self.variable.hex_value() {
                    text.push_str(&format!(" (0x{})", hex));
                }
            }
        } else {
            text.push_str(" = <no value>");
        }

        text
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_variable_value_row_new() {
        let row = VariableValueRow::new("x", "int32");
        assert_eq!(row.name, "x");
        assert_eq!(row.data_type, "int32");
        assert!(!row.has_value);
        assert!(!row.is_parameter);
    }

    #[test]
    fn test_variable_value_row_with_value() {
        let row = VariableValueRow::new("x", "int32")
            .with_value("42")
            .as_parameter();
        assert!(row.has_value);
        assert_eq!(row.value.as_deref(), Some("42"));
        assert!(row.is_parameter);
    }

    #[test]
    fn test_variable_value_row_raw_bytes() {
        let row = VariableValueRow::new("x", "int32")
            .with_raw_bytes(vec![0x01, 0x02, 0x03, 0x04]);
        assert_eq!(row.hex_value(), Some("01020304".to_string()));
    }

    #[test]
    fn test_storage_location_register() {
        let row = VariableValueRow::new("x", "int64")
            .with_storage(StorageLocation::Register {
                name: "RAX".to_string(),
                size: 8,
            });
        assert_eq!(row.storage_display(), "reg:RAX");
    }

    #[test]
    fn test_storage_location_stack() {
        let row = VariableValueRow::new("x", "int32")
            .with_storage(StorageLocation::Stack {
                offset: -8,
                size: 4,
            });
        assert_eq!(row.storage_display(), "stack:-0x8");
    }

    #[test]
    fn test_storage_location_stack_positive() {
        let row = VariableValueRow::new("x", "int32")
            .with_storage(StorageLocation::Stack {
                offset: 16,
                size: 4,
            });
        assert_eq!(row.storage_display(), "stack:+0x10");
    }

    #[test]
    fn test_storage_location_address() {
        let row = VariableValueRow::new("x", "int32")
            .with_storage(StorageLocation::Address {
                address: 0x7FFE0000,
                size: 4,
            });
        assert_eq!(row.storage_display(), "mem:0x7ffe0000");
    }

    #[test]
    fn test_storage_location_unknown() {
        let row = VariableValueRow::new("x", "int32");
        assert_eq!(row.storage_display(), "unknown");
    }

    #[test]
    fn test_variable_value_table() {
        let mut table = VariableValueTable::new(10);
        table.add_row(VariableValueRow::new("a", "int").with_value("1").as_parameter());
        table.add_row(VariableValueRow::new("b", "int").with_value("2"));
        table.add_row(VariableValueRow::new("c", "int").with_value("3").as_parameter());

        assert_eq!(table.row_count(), 3);
        assert_eq!(table.parameters().len(), 2);
        assert_eq!(table.locals().len(), 1);
    }

    #[test]
    fn test_variable_value_table_find() {
        let mut table = VariableValueTable::new(0);
        table.add_row(VariableValueRow::new("x", "int").with_value("42"));
        assert!(table.find_by_name("x").is_some());
        assert!(table.find_by_name("y").is_none());
    }

    #[test]
    fn test_variable_value_table_rows_with_values() {
        let mut table = VariableValueTable::new(0);
        table.add_row(VariableValueRow::new("a", "int").with_value("1"));
        table.add_row(VariableValueRow::new("b", "int"));
        assert_eq!(table.rows_with_values().len(), 1);
    }

    #[test]
    fn test_variable_value_table_clear() {
        let mut table = VariableValueTable::new(0);
        table.add_row(VariableValueRow::new("x", "int"));
        assert_eq!(table.row_count(), 1);
        table.clear();
        assert_eq!(table.row_count(), 0);
    }

    #[test]
    fn test_variable_value_hover_model() {
        let row = VariableValueRow::new("x", "int32")
            .with_value("42")
            .with_raw_bytes(vec![0x2A, 0x00, 0x00, 0x00]);
        let model = VariableValueHoverModel::new(row, 0x1000, 5);
        let text = model.format_hover_text();
        assert!(text.contains("int32"));
        assert!(text.contains("x"));
        assert!(text.contains("42"));
        assert!(text.contains("0x2a000000"));
    }

    #[test]
    fn test_variable_value_hover_model_no_value() {
        let row = VariableValueRow::new("y", "void*");
        let model = VariableValueHoverModel::new(row, 0, 0);
        let text = model.format_hover_text();
        assert!(text.contains("<no value>"));
    }

    #[test]
    fn test_hover_context() {
        let row = VariableValueRow::new("x", "int");
        let mut model = VariableValueHoverModel::new(row, 0x1000, 5);
        model.context.thread_key = Some(42);
        model.context.frame_level = 2;
        assert_eq!(model.context.thread_key, Some(42));
        assert_eq!(model.context.frame_level, 2);
    }

    #[test]
    fn test_variable_value_row_serde() {
        let row = VariableValueRow::new("test", "float64")
            .with_value("3.14")
            .as_parameter()
            .with_frame_level(1);
        let json = serde_json::to_string(&row).unwrap();
        let back: VariableValueRow = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "test");
        assert_eq!(back.data_type, "float64");
        assert!(back.is_parameter);
        assert_eq!(back.frame_level, 1);
    }

    #[test]
    fn test_hex_value_none() {
        let row = VariableValueRow::new("x", "int");
        assert!(row.hex_value().is_none());
    }
}
