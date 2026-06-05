//! VariableValueHover - hover display for variable values in the listing.
//!
//! Ported from Ghidra's `VariableValueHoverPlugin` and `VariableValueRow`
//! in `ghidra.app.plugin.core.debug.gui.stack.vars`.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The display format for a variable value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValueFormat {
    /// Display as hexadecimal.
    Hex,
    /// Display as decimal.
    Decimal,
    /// Display as binary.
    Binary,
    /// Display as octal.
    Octal,
    /// Display as ASCII characters.
    Ascii,
    /// Display as a floating-point number.
    Float,
    /// Display as an address/reference.
    Address,
    /// Auto-detect best format.
    Auto,
}

impl Default for ValueFormat {
    fn default() -> Self {
        Self::Auto
    }
}

/// A single variable value entry for hover display.
///
/// Ported from Ghidra's `VariableValueRow`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VariableValueEntry {
    /// The variable name.
    pub name: String,
    /// The variable type (e.g., "int", "char*").
    pub var_type: String,
    /// The raw value bytes.
    pub value_bytes: Vec<u8>,
    /// The current display format.
    pub format: ValueFormat,
    /// The register or memory location.
    pub location: String,
    /// The frame level (0 = innermost).
    pub frame_level: u32,
    /// Whether the value changed since last stop.
    pub changed: bool,
}

impl VariableValueEntry {
    /// Create a new variable value entry.
    pub fn new(
        name: impl Into<String>,
        var_type: impl Into<String>,
        value_bytes: Vec<u8>,
        location: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            var_type: var_type.into(),
            value_bytes,
            format: ValueFormat::Auto,
            location: location.into(),
            frame_level: 0,
            changed: false,
        }
    }

    /// Get the value as a u64 (little-endian interpretation).
    pub fn value_as_u64(&self) -> Option<u64> {
        if self.value_bytes.is_empty() || self.value_bytes.len() > 8 {
            return None;
        }
        let mut buf = [0u8; 8];
        buf[..self.value_bytes.len()].copy_from_slice(&self.value_bytes);
        Some(u64::from_le_bytes(buf))
    }

    /// Get the value as a formatted string.
    pub fn formatted_value(&self) -> String {
        match self.value_as_u64() {
            Some(val) => match self.format {
                ValueFormat::Hex => format!("0x{:x}", val),
                ValueFormat::Decimal => format!("{}", val),
                ValueFormat::Binary => format!("0b{:b}", val),
                ValueFormat::Octal => format!("0o{:o}", val),
                ValueFormat::Ascii => {
                    let chars: String = self
                        .value_bytes
                        .iter()
                        .map(|&b| {
                            if b.is_ascii_graphic() || b == b' ' {
                                b as char
                            } else {
                                '.'
                            }
                        })
                        .collect();
                    format!("\"{}\"", chars)
                }
                ValueFormat::Float => {
                    if self.value_bytes.len() == 4 {
                        let f = f32::from_le_bytes([
                            self.value_bytes[0],
                            self.value_bytes[1],
                            self.value_bytes[2],
                            self.value_bytes[3],
                        ]);
                        format!("{}", f)
                    } else if self.value_bytes.len() == 8 {
                        let f = f64::from_le_bytes([
                            self.value_bytes[0],
                            self.value_bytes[1],
                            self.value_bytes[2],
                            self.value_bytes[3],
                            self.value_bytes[4],
                            self.value_bytes[5],
                            self.value_bytes[6],
                            self.value_bytes[7],
                        ]);
                        format!("{}", f)
                    } else {
                        format!("0x{:x}", val)
                    }
                }
                ValueFormat::Address => format!("0x{:016x}", val),
                ValueFormat::Auto => format!("0x{:x}", val),
            },
            None => "<invalid>".to_string(),
        }
    }
}

/// Configuration for the variable value hover display.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HoverConfig {
    /// Whether to show variable values in hover tooltips.
    pub enabled: bool,
    /// The default display format.
    pub default_format: ValueFormat,
    /// Whether to show changed indicators.
    pub show_changes: bool,
    /// Maximum number of variables to show.
    pub max_variables: usize,
    /// Whether to show local variables.
    pub show_locals: bool,
    /// Whether to show parameters.
    pub show_params: bool,
}

impl Default for HoverConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            default_format: ValueFormat::Auto,
            show_changes: true,
            max_variables: 50,
            show_locals: true,
            show_params: true,
        }
    }
}

/// The hover model that provides variable values for display.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VariableValueHoverModel {
    /// Current variable values by frame level.
    pub variables: BTreeMap<u32, Vec<VariableValueEntry>>,
    /// Hover display configuration.
    pub config: HoverConfig,
    /// Previous values for change detection.
    previous_values: BTreeMap<String, Vec<u8>>,
}

impl VariableValueHoverModel {
    /// Create a new hover model.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a variable entry to a specific frame.
    pub fn add_variable(&mut self, frame_level: u32, entry: VariableValueEntry) {
        let key = format!("{}:{}", frame_level, entry.name);
        let mut entry = entry;
        entry.frame_level = frame_level;

        // Check if value changed
        if let Some(prev) = self.previous_values.get(&key) {
            entry.changed = *prev != entry.value_bytes;
        }
        self.previous_values
            .insert(key, entry.value_bytes.clone());

        self.variables
            .entry(frame_level)
            .or_default()
            .push(entry);
    }

    /// Get all variables for a frame.
    pub fn get_variables(&self, frame_level: u32) -> &[VariableValueEntry] {
        self.variables
            .get(&frame_level)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Get the total number of variables across all frames.
    pub fn total_variables(&self) -> usize {
        self.variables.values().map(|v| v.len()).sum()
    }

    /// Clear all variables.
    pub fn clear(&mut self) {
        self.variables.clear();
    }

    /// Get variables that changed since the last update.
    pub fn changed_variables(&self) -> Vec<&VariableValueEntry> {
        self.variables
            .values()
            .flat_map(|v| v.iter())
            .filter(|e| e.changed)
            .collect()
    }

    /// Mark the current state as the new baseline (clear change flags).
    pub fn commit_state(&mut self) {
        for entries in self.variables.values_mut() {
            for entry in entries.iter_mut() {
                entry.changed = false;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_variable_value_entry_u64() {
        let entry = VariableValueEntry::new("x", "int", vec![0x78, 0x56, 0x34, 0x12], "RAX");
        assert_eq!(entry.value_as_u64(), Some(0x12345678));
    }

    #[test]
    fn test_variable_value_entry_hex_format() {
        let entry = VariableValueEntry::new("x", "int", vec![0xFF, 0x00], "RAX")
            .set_format(ValueFormat::Hex);
        assert_eq!(entry.formatted_value(), "0xff");
    }

    #[test]
    fn test_variable_value_entry_decimal_format() {
        let entry = VariableValueEntry::new("x", "int", vec![42, 0, 0, 0], "RAX")
            .set_format(ValueFormat::Decimal);
        assert_eq!(entry.formatted_value(), "42");
    }

    #[test]
    fn test_hover_model_add_and_get() {
        let mut model = VariableValueHoverModel::new();
        model.add_variable(
            0,
            VariableValueEntry::new("x", "int", vec![1, 0, 0, 0], "RAX"),
        );
        model.add_variable(
            0,
            VariableValueEntry::new("y", "int", vec![2, 0, 0, 0], "RBX"),
        );
        assert_eq!(model.get_variables(0).len(), 2);
        assert_eq!(model.total_variables(), 2);
    }

    #[test]
    fn test_hover_model_change_detection() {
        let mut model = VariableValueHoverModel::new();
        model.add_variable(
            0,
            VariableValueEntry::new("x", "int", vec![1, 0, 0, 0], "RAX"),
        );

        // Add same variable with different value
        model.add_variable(
            0,
            VariableValueEntry::new("x", "int", vec![2, 0, 0, 0], "RAX"),
        );

        let changed = model.changed_variables();
        assert_eq!(changed.len(), 1);
        assert_eq!(changed[0].name, "x");
    }

    #[test]
    fn test_hover_model_commit() {
        let mut model = VariableValueHoverModel::new();
        // First add: no previous value, so not changed
        model.add_variable(
            0,
            VariableValueEntry::new("x", "int", vec![1, 0, 0, 0], "RAX"),
        );
        assert!(model.changed_variables().is_empty()); // first add, no previous

        // Second add with different value: now changed
        model.add_variable(
            0,
            VariableValueEntry::new("x", "int", vec![2, 0, 0, 0], "RAX"),
        );
        assert!(!model.changed_variables().is_empty());

        model.commit_state();
        assert!(model.changed_variables().is_empty());
    }

    #[test]
    fn test_hover_config_default() {
        let config = HoverConfig::default();
        assert!(config.enabled);
        assert!(config.show_changes);
        assert_eq!(config.max_variables, 50);
    }

    #[test]
    fn test_value_format_default() {
        assert_eq!(ValueFormat::default(), ValueFormat::Auto);
    }

    #[test]
    fn test_empty_entry() {
        let entry = VariableValueEntry::new("empty", "void", vec![], "none");
        assert!(entry.value_as_u64().is_none());
        assert_eq!(entry.formatted_value(), "<invalid>");
    }

    #[test]
    fn test_float_format_32() {
        let entry = VariableValueEntry::new("f", "float", 1.0f32.to_le_bytes().to_vec(), "XMM0")
            .set_format(ValueFormat::Float);
        let s = entry.formatted_value();
        assert!(s.contains("1"), "Expected '1' in '{}'", s);
    }

    #[test]
    fn test_hover_model_clear() {
        let mut model = VariableValueHoverModel::new();
        model.add_variable(
            0,
            VariableValueEntry::new("x", "int", vec![1, 0, 0, 0], "RAX"),
        );
        model.clear();
        assert_eq!(model.total_variables(), 0);
    }

    #[test]
    fn test_hover_model_serde() {
        let mut model = VariableValueHoverModel::new();
        model.add_variable(
            0,
            VariableValueEntry::new("x", "int", vec![1, 0, 0, 0], "RAX"),
        );
        let json = serde_json::to_string(&model).unwrap();
        let back: VariableValueHoverModel = serde_json::from_str(&json).unwrap();
        assert_eq!(back.total_variables(), 1);
    }
}

impl VariableValueEntry {
    /// Set the display format.
    pub fn set_format(mut self, format: ValueFormat) -> Self {
        self.format = format;
        self
    }
}
