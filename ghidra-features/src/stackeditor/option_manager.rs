// ===========================================================================
// Stack Editor Option Manager -- ported from Ghidra's
// `ghidra.app.plugin.core.stackeditor` package.
//
// Includes:
// - StackEditorOptionManager   -- manages stack editor display options
// - StackFrameDataType         -- data type representing a stack frame
// ===========================================================================

use std::collections::BTreeMap;

/// Stack editor display options.
///
/// Ported from `ghidra.app.plugin.core.stackeditor.StackEditorOptionManager`.
#[derive(Debug, Clone)]
pub struct StackEditorOptionManager {
    /// Whether to show variable names.
    pub show_variable_names: bool,
    /// Whether to show data types.
    pub show_data_types: bool,
    /// Whether to show offsets.
    pub show_offsets: bool,
    /// Whether to show sizes.
    pub show_sizes: bool,
    /// Whether to show comments.
    pub show_comments: bool,
    /// Whether to display in hex mode.
    pub hex_display: bool,
    /// The column widths.
    pub column_widths: BTreeMap<String, u32>,
    /// Sort order.
    pub sort_order: StackSortOrder,
}

/// Sort order for stack entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StackSortOrder {
    /// Sort by offset (ascending).
    ByOffset,
    /// Sort by name (alphabetical).
    ByName,
    /// Sort by data type.
    ByDataType,
    /// Sort by size.
    BySize,
}

impl Default for StackSortOrder {
    fn default() -> Self {
        Self::ByOffset
    }
}

impl StackEditorOptionManager {
    /// Create a new option manager with defaults.
    pub fn new() -> Self {
        let mut column_widths = BTreeMap::new();
        column_widths.insert("Name".into(), 200);
        column_widths.insert("DataType".into(), 150);
        column_widths.insert("Offset".into(), 100);
        column_widths.insert("Size".into(), 80);
        column_widths.insert("Comment".into(), 200);

        Self {
            show_variable_names: true,
            show_data_types: true,
            show_offsets: true,
            show_sizes: true,
            show_comments: true,
            hex_display: false,
            column_widths,
            sort_order: StackSortOrder::ByOffset,
        }
    }

    /// Set the column width.
    pub fn set_column_width(&mut self, column: impl Into<String>, width: u32) {
        self.column_widths.insert(column.into(), width);
    }

    /// Get the column width.
    pub fn column_width(&self, column: &str) -> u32 {
        self.column_widths.get(column).copied().unwrap_or(100)
    }

    /// Reset all options to defaults.
    pub fn reset(&mut self) {
        *self = Self::new();
    }
}

impl Default for StackEditorOptionManager {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// StackFrameDataType
// ---------------------------------------------------------------------------

/// A data type representing a function's stack frame.
///
/// Ported from `ghidra.app.plugin.core.stackeditor.StackFrameDataType`.
///
/// The stack frame is a composite of local variables, saved registers,
/// and parameters organized by their offsets relative to the frame pointer.
#[derive(Debug, Clone)]
pub struct StackFrameDataType {
    /// The function name this stack frame belongs to.
    pub function_name: String,
    /// The function address.
    pub function_address: u64,
    /// Frame size in bytes.
    pub frame_size: u32,
    /// Return address size in bytes.
    pub return_address_size: u32,
    /// Local variable area size.
    pub local_size: u32,
    /// Parameter area size.
    pub param_size: u32,
    /// Saved registers area size.
    pub saved_register_size: u32,
    /// Stack entries: offset -> entry info.
    pub entries: BTreeMap<i32, StackEntry>,
}

/// A single entry in the stack frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StackEntry {
    /// The name (variable or register name).
    pub name: String,
    /// The data type name.
    pub data_type_name: String,
    /// The size in bytes.
    pub size: u32,
    /// The offset from the frame pointer.
    pub offset: i32,
    /// Whether this is a parameter (vs. local variable).
    pub is_parameter: bool,
    /// Whether this entry is a saved register.
    pub is_saved_register: bool,
    /// The register name (if this is a saved register).
    pub register_name: Option<String>,
    /// Comment text.
    pub comment: Option<String>,
}

impl StackFrameDataType {
    /// Create a new stack frame data type.
    pub fn new(
        function_name: impl Into<String>,
        function_address: u64,
    ) -> Self {
        Self {
            function_name: function_name.into(),
            function_address,
            frame_size: 0,
            return_address_size: 0,
            local_size: 0,
            param_size: 0,
            saved_register_size: 0,
            entries: BTreeMap::new(),
        }
    }

    /// Add a stack entry.
    pub fn add_entry(&mut self, offset: i32, entry: StackEntry) {
        self.entries.insert(offset, entry);
    }

    /// Remove a stack entry at the given offset.
    pub fn remove_entry(&mut self, offset: i32) -> Option<StackEntry> {
        self.entries.remove(&offset)
    }

    /// Get the entry count.
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Get all parameter entries.
    pub fn parameters(&self) -> Vec<&StackEntry> {
        self.entries.values().filter(|e| e.is_parameter).collect()
    }

    /// Get all local variable entries.
    pub fn locals(&self) -> Vec<&StackEntry> {
        self.entries
            .values()
            .filter(|e| !e.is_parameter && !e.is_saved_register)
            .collect()
    }

    /// Get all saved register entries.
    pub fn saved_registers(&self) -> Vec<&StackEntry> {
        self.entries
            .values()
            .filter(|e| e.is_saved_register)
            .collect()
    }

    /// Set frame parameters.
    pub fn set_frame_size(&mut self, size: u32) {
        self.frame_size = size;
    }

    /// Set return address size.
    pub fn set_return_address_size(&mut self, size: u32) {
        self.return_address_size = size;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_option_manager_defaults() {
        let opts = StackEditorOptionManager::new();
        assert!(opts.show_variable_names);
        assert!(opts.show_data_types);
        assert!(opts.show_offsets);
        assert_eq!(opts.sort_order, StackSortOrder::ByOffset);
        assert_eq!(opts.column_width("Name"), 200);
    }

    #[test]
    fn test_option_manager_column_width() {
        let mut opts = StackEditorOptionManager::new();
        opts.set_column_width("Name", 300);
        assert_eq!(opts.column_width("Name"), 300);
        assert_eq!(opts.column_width("Unknown"), 100);
    }

    #[test]
    fn test_option_manager_reset() {
        let mut opts = StackEditorOptionManager::new();
        opts.show_variable_names = false;
        opts.hex_display = true;
        opts.reset();
        assert!(opts.show_variable_names);
        assert!(!opts.hex_display);
    }

    #[test]
    fn test_stack_frame_data_type() {
        let mut frame = StackFrameDataType::new("main", 0x400000);
        frame.set_frame_size(0x40);
        frame.set_return_address_size(8);

        frame.add_entry(
            -8,
            StackEntry {
                name: "saved_rbp".into(),
                data_type_name: "long".into(),
                size: 8,
                offset: -8,
                is_parameter: false,
                is_saved_register: true,
                register_name: Some("RBP".into()),
                comment: None,
            },
        );
        frame.add_entry(
            -16,
            StackEntry {
                name: "local_var".into(),
                data_type_name: "int".into(),
                size: 4,
                offset: -16,
                is_parameter: false,
                is_saved_register: false,
                register_name: None,
                comment: Some("local variable".into()),
            },
        );
        frame.add_entry(
            8,
            StackEntry {
                name: "arg1".into(),
                data_type_name: "char *".into(),
                size: 8,
                offset: 8,
                is_parameter: true,
                is_saved_register: false,
                register_name: None,
                comment: None,
            },
        );

        assert_eq!(frame.entry_count(), 3);
        assert_eq!(frame.parameters().len(), 1);
        assert_eq!(frame.locals().len(), 1);
        assert_eq!(frame.saved_registers().len(), 1);
    }

    #[test]
    fn test_stack_frame_remove() {
        let mut frame = StackFrameDataType::new("func", 0x400000);
        frame.add_entry(
            0,
            StackEntry {
                name: "x".into(),
                data_type_name: "int".into(),
                size: 4,
                offset: 0,
                is_parameter: false,
                is_saved_register: false,
                register_name: None,
                comment: None,
            },
        );
        assert_eq!(frame.entry_count(), 1);
        let removed = frame.remove_entry(0);
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().name, "x");
        assert_eq!(frame.entry_count(), 0);
    }
}
