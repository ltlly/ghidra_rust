//! Register panel data model types.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.gui.register` package.
//! Provides the row types, column definitions, and action contexts for the
//! debugger registers panel.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::model::Lifespan;

// ---------------------------------------------------------------------------
// RegisterRow -- a row in the register table
// ---------------------------------------------------------------------------

/// Display format for a register value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegisterDisplayFormat {
    /// Display in hexadecimal.
    Hex,
    /// Display in decimal (signed).
    Decimal,
    /// Display in decimal (unsigned).
    Unsigned,
    /// Display in binary.
    Binary,
    /// Display in octal.
    Octal,
    /// Display as floating point.
    Float,
    /// Display as address.
    Address,
    /// Auto-detect best format based on register type.
    Auto,
}

impl RegisterDisplayFormat {
    /// Default display format.
    pub fn default_format() -> Self {
        Self::Hex
    }

    /// All available formats.
    pub fn all_formats() -> &'static [RegisterDisplayFormat] {
        &[
            Self::Hex,
            Self::Decimal,
            Self::Unsigned,
            Self::Binary,
            Self::Octal,
            Self::Float,
            Self::Address,
            Self::Auto,
        ]
    }

    /// Short display name for the format.
    pub fn short_name(&self) -> &'static str {
        match self {
            Self::Hex => "Hex",
            Self::Decimal => "Dec",
            Self::Unsigned => "Unsigned",
            Self::Binary => "Bin",
            Self::Octal => "Oct",
            Self::Float => "Float",
            Self::Address => "Addr",
            Self::Auto => "Auto",
        }
    }
}

impl fmt::Display for RegisterDisplayFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.short_name())
    }
}

/// A row representing a register in the registers panel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterRow {
    /// Register name (e.g., "RAX", "RIP", "RSP").
    pub name: String,
    /// Register group name (e.g., "General Purpose", "Segment", "XMM").
    pub group: String,
    /// The bit size of the register.
    pub bit_size: u32,
    /// The current value of the register, if known.
    pub value: Option<u64>,
    /// The previous value (for change highlighting).
    pub previous_value: Option<u64>,
    /// The display format for this register.
    pub format: RegisterDisplayFormat,
    /// Whether the value has changed since the last snapshot.
    pub changed: bool,
    /// The register's category/role (e.g., "PC", "SP", "FP").
    pub role: Option<String>,
    /// Whether this register is currently visible.
    pub visible: bool,
    /// The thread key this register belongs to.
    pub thread_key: Option<i64>,
    /// The frame index.
    pub frame_index: Option<usize>,
    /// Child register names (for composite registers).
    pub children: Vec<String>,
    /// Parent register name (for sub-registers).
    pub parent: Option<String>,
}

impl RegisterRow {
    /// Create a new register row.
    pub fn new(name: impl Into<String>, group: impl Into<String>, bit_size: u32) -> Self {
        Self {
            name: name.into(),
            group: group.into(),
            bit_size,
            value: None,
            previous_value: None,
            format: RegisterDisplayFormat::default_format(),
            changed: false,
            role: None,
            visible: true,
            thread_key: None,
            frame_index: None,
            children: Vec::new(),
            parent: None,
        }
    }

    /// Set the value.
    pub fn with_value(mut self, value: u64) -> Self {
        self.value = Some(value);
        self
    }

    /// Set the format.
    pub fn with_format(mut self, format: RegisterDisplayFormat) -> Self {
        self.format = format;
        self
    }

    /// Set the role.
    pub fn with_role(mut self, role: impl Into<String>) -> Self {
        self.role = Some(role.into());
        self
    }

    /// Set the thread key.
    pub fn with_thread_key(mut self, key: i64) -> Self {
        self.thread_key = Some(key);
        self
    }

    /// Set the parent register.
    pub fn with_parent(mut self, parent: impl Into<String>) -> Self {
        self.parent = Some(parent.into());
        self
    }

    /// Add a child register.
    pub fn add_child(&mut self, child: impl Into<String>) {
        self.children.push(child.into());
    }

    /// Whether this register is a sub-register (has a parent).
    pub fn is_sub_register(&self) -> bool {
        self.parent.is_some()
    }

    /// Whether this register is a composite (has children).
    pub fn is_composite(&self) -> bool {
        !self.children.is_empty()
    }

    /// Whether the value has been set.
    pub fn has_value(&self) -> bool {
        self.value.is_some()
    }

    /// Update the value and detect changes.
    pub fn update_value(&mut self, new_value: Option<u64>) {
        self.changed = self.value.is_some() && self.value != new_value;
        self.previous_value = self.value;
        self.value = new_value;
    }

    /// Format the value according to the current display format.
    pub fn formatted_value(&self) -> String {
        match self.value {
            None => "??".to_string(),
            Some(v) => match self.format {
                RegisterDisplayFormat::Hex => format!("0x{:0width$x}", v, width = (self.bit_size as usize + 3) / 4),
                RegisterDisplayFormat::Decimal => {
                    let signed = if self.bit_size < 64 {
                        let sign_bit = 1u64 << (self.bit_size - 1);
                        if v & sign_bit != 0 {
                            (v as i64) - (1i64 << self.bit_size)
                        } else {
                            v as i64
                        }
                    } else {
                        v as i64
                    };
                    format!("{}", signed)
                }
                RegisterDisplayFormat::Unsigned => format!("{}", v),
                RegisterDisplayFormat::Binary => format!("0b{:0width$b}", v, width = self.bit_size as usize),
                RegisterDisplayFormat::Octal => format!("0o{:o}", v),
                RegisterDisplayFormat::Float => {
                    if self.bit_size == 32 {
                        format!("{}", f32::from_bits(v as u32))
                    } else if self.bit_size == 64 {
                        format!("{}", f64::from_bits(v))
                    } else {
                        format!("0x{:x}", v)
                    }
                }
                RegisterDisplayFormat::Address => format!("0x{:x}", v),
                RegisterDisplayFormat::Auto => {
                    // Auto: use hex for most registers, float for FP registers
                    if self.group.to_lowercase().contains("float")
                        || self.group.to_lowercase().contains("xmm")
                        || self.group.to_lowercase().contains("ymm")
                        || self.name.to_lowercase().starts_with("xmm")
                        || self.name.to_lowercase().starts_with("ymm")
                    {
                        if self.bit_size >= 64 {
                            format!("{}", f64::from_bits(v))
                        } else if self.bit_size >= 32 {
                            format!("{}", f32::from_bits(v as u32))
                        } else {
                            format!("0x{:x}", v)
                        }
                    } else {
                        format!("0x{:0width$x}", v, width = (self.bit_size as usize + 3) / 4)
                    }
                }
            },
        }
    }
}

// ---------------------------------------------------------------------------
// RegisterColumn -- column definitions for the register table
// ---------------------------------------------------------------------------

/// Column identifiers for the register table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RegisterColumn {
    /// Register name column.
    Name,
    /// Register value column.
    Value,
    /// Register group column.
    Group,
    /// Register bit-size column.
    BitSize,
    /// Register role column.
    Role,
    /// Whether the value changed.
    Changed,
}

impl RegisterColumn {
    /// The display header for this column.
    pub fn header(&self) -> &'static str {
        match self {
            Self::Name => "Register",
            Self::Value => "Value",
            Self::Group => "Group",
            Self::BitSize => "Size",
            Self::Role => "Role",
            Self::Changed => "Changed",
        }
    }

    /// Default columns to display.
    pub fn default_columns() -> Vec<RegisterColumn> {
        vec![Self::Name, Self::Value, Self::Group]
    }

    /// All available columns.
    pub fn all_columns() -> Vec<RegisterColumn> {
        vec![
            Self::Name,
            Self::Value,
            Self::Group,
            Self::BitSize,
            Self::Role,
            Self::Changed,
        ]
    }
}

// ---------------------------------------------------------------------------
// RegisterTableModel -- model for the register table
// ---------------------------------------------------------------------------

/// The table model for the registers panel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterTableModel {
    /// The register rows.
    pub rows: Vec<RegisterRow>,
    /// The columns to display.
    pub columns: Vec<RegisterColumn>,
    /// Current display format override (None = per-register format).
    pub global_format: Option<RegisterDisplayFormat>,
    /// Filter to show only changed registers.
    pub show_changed_only: bool,
    /// Filter text for searching registers.
    pub filter_text: Option<String>,
    /// Sort column.
    pub sort_column: Option<RegisterColumn>,
    /// Sort ascending.
    pub sort_ascending: bool,
}

impl RegisterTableModel {
    /// Create a new register table model.
    pub fn new() -> Self {
        Self {
            rows: Vec::new(),
            columns: RegisterColumn::default_columns(),
            global_format: None,
            show_changed_only: false,
            filter_text: None,
            sort_column: None,
            sort_ascending: true,
        }
    }

    /// Add a register row.
    pub fn add_row(&mut self, row: RegisterRow) {
        self.rows.push(row);
    }

    /// Get all visible (filtered) rows.
    pub fn visible_rows(&self) -> Vec<&RegisterRow> {
        self.rows
            .iter()
            .filter(|r| r.visible)
            .filter(|r| {
                if self.show_changed_only {
                    r.changed
                } else {
                    true
                }
            })
            .filter(|r| {
                if let Some(ref filter) = self.filter_text {
                    let filter_lower = filter.to_lowercase();
                    r.name.to_lowercase().contains(&filter_lower)
                        || r.group.to_lowercase().contains(&filter_lower)
                        || r.role
                            .as_ref()
                            .map(|role| role.to_lowercase().contains(&filter_lower))
                            .unwrap_or(false)
                } else {
                    true
                }
            })
            .collect()
    }

    /// Get the number of visible rows.
    pub fn visible_count(&self) -> usize {
        self.visible_rows().len()
    }

    /// Get all changed registers.
    pub fn changed_registers(&self) -> Vec<&RegisterRow> {
        self.rows.iter().filter(|r| r.changed).collect()
    }

    /// Update all register values from a map of name -> value.
    pub fn update_values(&mut self, values: &HashMap<String, u64>) {
        for row in &mut self.rows {
            let new_value = values.get(&row.name).copied();
            row.update_value(new_value);
        }
    }

    /// Set the global display format.
    pub fn set_global_format(&mut self, format: Option<RegisterDisplayFormat>) {
        self.global_format = format;
    }

    /// Set the filter text.
    pub fn set_filter(&mut self, filter: Option<String>) {
        self.filter_text = filter;
    }

    /// Toggle show-changed-only mode.
    pub fn toggle_show_changed_only(&mut self) {
        self.show_changed_only = !self.show_changed_only;
    }

    /// Clear all rows.
    pub fn clear(&mut self) {
        self.rows.clear();
    }
}

impl Default for RegisterTableModel {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// AvailableRegisterRow -- a row in the available registers dialog
// ---------------------------------------------------------------------------

/// A row in the "available registers" dialog, which lets users choose
/// which registers to display in the registers panel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AvailableRegisterRow {
    /// Register name.
    pub name: String,
    /// Register group.
    pub group: String,
    /// Bit size.
    pub bit_size: u32,
    /// Whether the user has selected this register for display.
    pub selected: bool,
    /// Whether this register is currently displayed.
    pub currently_displayed: bool,
}

impl AvailableRegisterRow {
    /// Create a new available register row.
    pub fn new(name: impl Into<String>, group: impl Into<String>, bit_size: u32) -> Self {
        Self {
            name: name.into(),
            group: group.into(),
            bit_size,
            selected: false,
            currently_displayed: false,
        }
    }

    /// Toggle selection.
    pub fn toggle(&mut self) {
        self.selected = !self.selected;
    }

    /// Select this register.
    pub fn select(&mut self) {
        self.selected = true;
    }

    /// Deselect this register.
    pub fn deselect(&mut self) {
        self.selected = false;
    }
}

// ---------------------------------------------------------------------------
// RegisterActionContext -- context for register panel actions
// ---------------------------------------------------------------------------

/// Context for actions performed on register rows.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterActionContext {
    /// The register name.
    pub register_name: String,
    /// The current value, if known.
    pub value: Option<u64>,
    /// The bit size.
    pub bit_size: u32,
    /// The group.
    pub group: String,
    /// Whether the register is selected in the table.
    pub selected: bool,
}

impl RegisterActionContext {
    /// Create from a register row.
    pub fn from_row(row: &RegisterRow) -> Self {
        Self {
            register_name: row.name.clone(),
            value: row.value,
            bit_size: row.bit_size,
            group: row.group.clone(),
            selected: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_row_creation() {
        let row = RegisterRow::new("RAX", "General Purpose", 64)
            .with_value(0x12345678)
            .with_role("Accumulator")
            .with_format(RegisterDisplayFormat::Hex);

        assert_eq!(row.name, "RAX");
        assert_eq!(row.group, "General Purpose");
        assert_eq!(row.bit_size, 64);
        assert_eq!(row.value, Some(0x12345678));
        assert_eq!(row.role.as_deref(), Some("Accumulator"));
        assert!(row.has_value());
        assert!(!row.is_sub_register());
        assert!(!row.is_composite());
    }

    #[test]
    fn test_register_row_sub_register() {
        let mut row = RegisterRow::new("AL", "General Purpose", 8).with_parent("RAX");
        assert!(row.is_sub_register());
        assert!(!row.is_composite());

        row.add_child("AH");
        row.add_child("AL");
        assert!(row.is_composite());
    }

    #[test]
    fn test_register_row_update_value() {
        let mut row = RegisterRow::new("RAX", "General Purpose", 64).with_value(0x100);
        assert!(!row.changed);

        row.update_value(Some(0x200));
        assert!(row.changed);
        assert_eq!(row.previous_value, Some(0x100));
        assert_eq!(row.value, Some(0x200));
    }

    #[test]
    fn test_register_row_update_value_no_change() {
        let mut row = RegisterRow::new("RAX", "General Purpose", 64).with_value(0x100);
        row.update_value(Some(0x100));
        assert!(!row.changed);
    }

    #[test]
    fn test_register_row_formatted_hex() {
        let row = RegisterRow::new("RAX", "GP", 64)
            .with_value(0xDEADBEEF)
            .with_format(RegisterDisplayFormat::Hex);
        let fmt = row.formatted_value();
        assert!(fmt.contains("deadbeef") || fmt.contains("DEADBEEF") || fmt.starts_with("0x"));
    }

    #[test]
    fn test_register_row_formatted_decimal() {
        let row = RegisterRow::new("RAX", "GP", 8)
            .with_value(0xFF)
            .with_format(RegisterDisplayFormat::Decimal);
        let fmt = row.formatted_value();
        assert_eq!(fmt, "-1"); // -1 in signed 8-bit
    }

    #[test]
    fn test_register_row_formatted_unsigned() {
        let row = RegisterRow::new("RAX", "GP", 64)
            .with_value(42)
            .with_format(RegisterDisplayFormat::Unsigned);
        assert_eq!(row.formatted_value(), "42");
    }

    #[test]
    fn test_register_row_formatted_unknown() {
        let row = RegisterRow::new("RAX", "GP", 64);
        assert_eq!(row.formatted_value(), "??");
    }

    #[test]
    fn test_register_display_format() {
        assert_eq!(RegisterDisplayFormat::Hex.short_name(), "Hex");
        assert_eq!(RegisterDisplayFormat::Decimal.short_name(), "Dec");
        assert_eq!(RegisterDisplayFormat::Binary.short_name(), "Bin");
        assert_eq!(RegisterDisplayFormat::all_formats().len(), 8);
    }

    #[test]
    fn test_register_column_headers() {
        assert_eq!(RegisterColumn::Name.header(), "Register");
        assert_eq!(RegisterColumn::Value.header(), "Value");
        assert_eq!(RegisterColumn::Group.header(), "Group");
        assert_eq!(RegisterColumn::default_columns().len(), 3);
        assert_eq!(RegisterColumn::all_columns().len(), 6);
    }

    #[test]
    fn test_register_table_model_basics() {
        let mut model = RegisterTableModel::new();
        assert_eq!(model.visible_count(), 0);

        model.add_row(RegisterRow::new("RAX", "GP", 64).with_value(0x100));
        model.add_row(RegisterRow::new("RBX", "GP", 64).with_value(0x200));
        model.add_row(RegisterRow::new("RIP", "IP", 64).with_value(0x401000));

        assert_eq!(model.visible_count(), 3);
    }

    #[test]
    fn test_register_table_model_filter() {
        let mut model = RegisterTableModel::new();
        model.add_row(RegisterRow::new("RAX", "General Purpose", 64));
        model.add_row(RegisterRow::new("RBX", "General Purpose", 64));
        model.add_row(RegisterRow::new("RIP", "Instruction Pointer", 64));

        model.set_filter(Some("RAX".to_string()));
        assert_eq!(model.visible_count(), 1);

        model.set_filter(Some("general".to_string()));
        assert_eq!(model.visible_count(), 2);

        model.set_filter(None);
        assert_eq!(model.visible_count(), 3);
    }

    #[test]
    fn test_register_table_model_show_changed() {
        let mut model = RegisterTableModel::new();
        let mut rax = RegisterRow::new("RAX", "GP", 64).with_value(0x100);
        rax.changed = true;
        model.add_row(rax);
        model.add_row(RegisterRow::new("RBX", "GP", 64).with_value(0x200));

        assert_eq!(model.visible_count(), 2);

        model.show_changed_only = true;
        assert_eq!(model.visible_count(), 1);
    }

    #[test]
    fn test_register_table_model_update_values() {
        let mut model = RegisterTableModel::new();
        model.add_row(RegisterRow::new("RAX", "GP", 64).with_value(0x100));
        model.add_row(RegisterRow::new("RBX", "GP", 64).with_value(0x200));

        let mut new_values = HashMap::new();
        new_values.insert("RAX".to_string(), 0x300);
        new_values.insert("RBX".to_string(), 0x200); // unchanged

        model.update_values(&new_values);

        let changed = model.changed_registers();
        assert_eq!(changed.len(), 1);
        assert_eq!(changed[0].name, "RAX");
    }

    #[test]
    fn test_register_table_model_changed_registers() {
        let mut model = RegisterTableModel::new();
        model.add_row(RegisterRow::new("RAX", "GP", 64));
        model.add_row(RegisterRow::new("RBX", "GP", 64));
        assert!(model.changed_registers().is_empty());
    }

    #[test]
    fn test_available_register_row() {
        let mut row = AvailableRegisterRow::new("RAX", "GP", 64);
        assert!(!row.selected);
        assert!(!row.currently_displayed);

        row.select();
        assert!(row.selected);

        row.toggle();
        assert!(!row.selected);

        row.toggle();
        assert!(row.selected);
    }

    #[test]
    fn test_register_action_context() {
        let row = RegisterRow::new("RAX", "GP", 64).with_value(0x100);
        let ctx = RegisterActionContext::from_row(&row);
        assert_eq!(ctx.register_name, "RAX");
        assert_eq!(ctx.value, Some(0x100));
        assert_eq!(ctx.bit_size, 64);
        assert_eq!(ctx.group, "GP");
    }

    #[test]
    fn test_register_table_model_default() {
        let model = RegisterTableModel::default();
        assert!(model.rows.is_empty());
        assert!(model.global_format.is_none());
        assert!(!model.show_changed_only);
        assert!(model.filter_text.is_none());
    }

    #[test]
    fn test_register_table_model_clear() {
        let mut model = RegisterTableModel::new();
        model.add_row(RegisterRow::new("RAX", "GP", 64));
        model.add_row(RegisterRow::new("RBX", "GP", 64));
        assert_eq!(model.visible_count(), 2);

        model.clear();
        assert_eq!(model.visible_count(), 0);
    }

    #[test]
    fn test_register_row_formatted_binary() {
        let row = RegisterRow::new("FLAGS", "Flags", 8)
            .with_value(0b10101010)
            .with_format(RegisterDisplayFormat::Binary);
        let fmt = row.formatted_value();
        assert!(fmt.contains("10101010"));
    }

    #[test]
    fn test_register_row_formatted_octal() {
        let row = RegisterRow::new("RAX", "GP", 64)
            .with_value(64)
            .with_format(RegisterDisplayFormat::Octal);
        let fmt = row.formatted_value();
        assert!(fmt.contains("100")); // 64 in octal is 100
    }

    #[test]
    fn test_register_row_formatted_float32() {
        let row = RegisterRow::new("XMM0", "SSE", 32)
            .with_value(f32::to_bits(3.14f32) as u64)
            .with_format(RegisterDisplayFormat::Float);
        let fmt = row.formatted_value();
        assert!(fmt.contains("3.14"));
    }

    #[test]
    fn test_register_row_formatted_auto_float() {
        let row = RegisterRow::new("XMM0", "XMM Registers", 64)
            .with_value(f64::to_bits(2.718281828))
            .with_format(RegisterDisplayFormat::Auto);
        let fmt = row.formatted_value();
        assert!(fmt.contains("2.718"));
    }
}
