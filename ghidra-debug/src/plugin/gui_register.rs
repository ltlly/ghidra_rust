//! Register GUI data model types.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.gui.register`
//! package in the Debugger module. Provides register row types and
//! available register management for the register viewer panel.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A register row in the registers panel.
///
/// Ported from Ghidra's `RegisterRow`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterRow {
    /// Register name (e.g., "RAX", "EFLAGS").
    pub name: String,
    /// Register size in bytes.
    pub size: u16,
    /// The current value as a byte vector (little-endian).
    pub value: Vec<u8>,
    /// Whether this register has a known value.
    pub has_value: bool,
    /// The display group (e.g., "General", "Flags", "XMM").
    pub group: String,
    /// Register's address offset within the register space.
    pub offset: u64,
    /// Whether this register is a hidden/vector register.
    pub hidden: bool,
    /// The parent register name, if this is a sub-register.
    pub parent: Option<String>,
}

impl RegisterRow {
    /// Create a new register row.
    pub fn new(name: impl Into<String>, size: u16, offset: u64) -> Self {
        Self {
            name: name.into(),
            size,
            value: vec![0u8; size as usize],
            has_value: false,
            group: String::new(),
            offset,
            hidden: false,
            parent: None,
        }
    }

    /// Create a register row with a value.
    pub fn with_value(
        name: impl Into<String>,
        size: u16,
        offset: u64,
        value: &[u8],
    ) -> Self {
        Self {
            name: name.into(),
            size,
            value: value.to_vec(),
            has_value: true,
            group: String::new(),
            offset,
            hidden: false,
            parent: None,
        }
    }

    /// Set the register value.
    pub fn set_value(&mut self, value: &[u8]) {
        self.value = value.to_vec();
        self.has_value = true;
    }

    /// Get the register value as a u64 (little-endian).
    pub fn value_as_u64(&self) -> Option<u64> {
        if !self.has_value || self.value.is_empty() {
            return None;
        }
        let mut bytes = [0u8; 8];
        let len = self.value.len().min(8);
        bytes[..len].copy_from_slice(&self.value[..len]);
        Some(u64::from_le_bytes(bytes))
    }

    /// Get the register value as a hex string.
    pub fn value_hex(&self) -> String {
        if !self.has_value {
            return "?".to_string();
        }
        self.value
            .iter()
            .rev()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    }

    /// Whether this is a sub-register of another register.
    pub fn is_sub_register(&self) -> bool {
        self.parent.is_some()
    }

    /// The display group for this register.
    pub fn display_group(&self) -> &str {
        &self.group
    }
}

/// An available register entry for the "Add Register" dialog.
///
/// Ported from Ghidra's `AvailableRegisterRow`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AvailableRegisterRow {
    /// Register name.
    pub name: String,
    /// Register size in bytes.
    pub size: u16,
    /// Description.
    pub description: String,
    /// Whether this register is already being displayed.
    pub displayed: bool,
}

impl AvailableRegisterRow {
    /// Create a new available register row.
    pub fn new(name: impl Into<String>, size: u16) -> Self {
        Self {
            name: name.into(),
            size,
            description: String::new(),
            displayed: false,
        }
    }
}

/// Column definitions for the register table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RegisterColumn {
    /// Register name.
    Name,
    /// Register value (hex).
    Value,
    /// Register size.
    Size,
    /// Register group.
    Group,
}

/// Model for the registers display panel.
///
/// Holds the currently-displayed register rows and manages their
/// grouping and value updates.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RegisterTableModel {
    rows: Vec<RegisterRow>,
    /// Group expand/collapse state.
    group_collapsed: BTreeMap<String, bool>,
}

impl RegisterTableModel {
    /// Create a new register model.
    pub fn new() -> Self {
        Self::default()
    }

    /// The number of visible rows (excluding collapsed groups).
    pub fn visible_row_count(&self) -> usize {
        self.rows
            .iter()
            .filter(|r| {
                !self
                    .group_collapsed
                    .get(&r.group)
                    .copied()
                    .unwrap_or(false)
            })
            .count()
    }

    /// Get all rows.
    pub fn rows(&self) -> &[RegisterRow] {
        &self.rows
    }

    /// Add a register row.
    pub fn add_row(&mut self, row: RegisterRow) {
        self.rows.push(row);
    }

    /// Remove a register row by name.
    pub fn remove_row(&mut self, name: &str) -> bool {
        let before = self.rows.len();
        self.rows.retain(|r| r.name != name);
        self.rows.len() < before
    }

    /// Get a register row by name.
    pub fn get(&self, name: &str) -> Option<&RegisterRow> {
        self.rows.iter().find(|r| r.name == name)
    }

    /// Get a mutable register row by name.
    pub fn get_mut(&mut self, name: &str) -> Option<&mut RegisterRow> {
        self.rows.iter_mut().find(|r| r.name == name)
    }

    /// Toggle group collapsed state.
    pub fn toggle_group(&mut self, group: &str) {
        let entry = self.group_collapsed.entry(group.to_string()).or_insert(false);
        *entry = !*entry;
    }

    /// Check if a group is collapsed.
    pub fn is_group_collapsed(&self, group: &str) -> bool {
        self.group_collapsed.get(group).copied().unwrap_or(false)
    }

    /// Get all unique groups.
    pub fn groups(&self) -> Vec<&str> {
        let mut groups: Vec<&str> = self
            .rows
            .iter()
            .map(|r| r.group.as_str())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        groups.sort();
        groups
    }

    /// Update the value of a register by name.
    pub fn update_value(&mut self, name: &str, value: &[u8]) -> bool {
        if let Some(row) = self.get_mut(name) {
            row.set_value(value);
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_row_creation() {
        let row = RegisterRow::new("RAX", 8, 0x20);
        assert_eq!(row.name, "RAX");
        assert_eq!(row.size, 8);
        assert!(!row.has_value);
        assert_eq!(row.value, vec![0u8; 8]);
    }

    #[test]
    fn test_register_row_with_value() {
        let row = RegisterRow::with_value("RAX", 8, 0x20, &[0xef, 0xbe, 0xad, 0xde, 0, 0, 0, 0]);
        assert!(row.has_value);
        assert_eq!(row.value_as_u64(), Some(0xdeadbeef));
    }

    #[test]
    fn test_register_row_hex() {
        let row = RegisterRow::with_value("RAX", 4, 0x20, &[0x78, 0x56, 0x34, 0x12]);
        assert_eq!(row.value_hex(), "12345678");
    }

    #[test]
    fn test_register_row_sub_register() {
        let mut row = RegisterRow::new("EAX", 4, 0x20);
        assert!(!row.is_sub_register());
        row.parent = Some("RAX".to_string());
        assert!(row.is_sub_register());
    }

    #[test]
    fn test_register_table_model() {
        let mut model = RegisterTableModel::new();
        model.add_row(RegisterRow::new("RAX", 8, 0x20));
        model.add_row(RegisterRow::new("RBX", 8, 0x28));
        assert_eq!(model.visible_row_count(), 2);

        assert!(model.get("RAX").is_some());
        assert!(model.get("RCX").is_none());
    }

    #[test]
    fn test_register_table_model_update() {
        let mut model = RegisterTableModel::new();
        model.add_row(RegisterRow::new("RAX", 8, 0x20));
        assert!(model.update_value("RAX", &[0x42, 0, 0, 0, 0, 0, 0, 0]));
        assert_eq!(
            model.get("RAX").unwrap().value_as_u64(),
            Some(0x42)
        );
    }

    #[test]
    fn test_register_table_model_groups() {
        let mut model = RegisterTableModel::new();
        let mut rax = RegisterRow::new("RAX", 8, 0x20);
        rax.group = "General".to_string();
        let mut xmm0 = RegisterRow::new("XMM0", 16, 0x100);
        xmm0.group = "SSE".to_string();
        model.add_row(rax);
        model.add_row(xmm0);

        let groups = model.groups();
        assert_eq!(groups.len(), 2);
        assert!(groups.contains(&"General"));
        assert!(groups.contains(&"SSE"));
    }

    #[test]
    fn test_register_table_model_collapse() {
        let mut model = RegisterTableModel::new();
        let mut rax = RegisterRow::new("RAX", 8, 0x20);
        rax.group = "General".to_string();
        model.add_row(rax);

        assert!(!model.is_group_collapsed("General"));
        model.toggle_group("General");
        assert!(model.is_group_collapsed("General"));
        // Rows still exist, just hidden
        assert_eq!(model.rows().len(), 1);
        assert_eq!(model.visible_row_count(), 0);
    }

    #[test]
    fn test_available_register_row() {
        let row = AvailableRegisterRow::new("R8", 8);
        assert_eq!(row.name, "R8");
        assert_eq!(row.size, 8);
        assert!(!row.displayed);
    }
}
