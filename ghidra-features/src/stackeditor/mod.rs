//! Stack Editor -- edit function stack frames.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.stackeditor` Java package.
//!
//! Provides model-level logic for editing a function's stack frame layout,
//! including local variables, parameters, and stack growth direction.
//!
//! # Architecture
//!
//! - [`StackEditorModel`] -- the model for editing a function's stack frame.
//! - [`StackVariableEntry`] -- a single variable in the stack frame.
//! - [`StackEditorAction`] -- types of edit operations on stack frames.

use ghidra_core::Address;
use std::collections::BTreeMap;

// ============================================================================
// StackEditorAction -- types of stack editor actions
// ============================================================================

/// Types of stack editor actions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StackEditorAction {
    /// Add a new local variable.
    AddLocal,
    /// Add a new parameter.
    AddParameter,
    /// Remove a variable.
    RemoveVariable,
    /// Modify an existing variable.
    ModifyVariable,
    /// Change the stack frame size.
    ResizeFrame,
}

// ============================================================================
// StackVariableEntry -- a variable in the stack frame
// ============================================================================

/// A single variable in a stack frame.
#[derive(Debug, Clone)]
pub struct StackVariableEntry {
    /// Variable name.
    pub name: String,
    /// Offset from the frame base (can be negative for parameters).
    pub offset: i64,
    /// Size in bytes.
    pub size: usize,
    /// Data type name (e.g. `"int"`, `"char *"`, `"undefined4"`).
    pub data_type: String,
    /// Whether this is a parameter (vs. local).
    pub is_parameter: bool,
    /// Whether this variable has been modified since last save.
    pub dirty: bool,
}

impl StackVariableEntry {
    /// Create a new stack variable entry.
    pub fn new(
        name: impl Into<String>,
        offset: i64,
        size: usize,
        data_type: impl Into<String>,
        is_parameter: bool,
    ) -> Self {
        Self {
            name: name.into(),
            offset,
            size,
            data_type: data_type.into(),
            is_parameter,
            dirty: true,
        }
    }
}

// ============================================================================
// StackEditorModel -- the stack frame editor model
// ============================================================================

/// Business logic for editing a function's stack frame.
///
/// Corresponds to the `StackEditorModel` in Ghidra's Java source.
/// Manages variables in a stack frame and supports CRUD operations.
#[derive(Debug)]
pub struct StackEditorModel {
    /// The function address this stack frame belongs to.
    function_address: Address,
    /// Stack frame variables, keyed by offset.
    variables: BTreeMap<i64, StackVariableEntry>,
    /// The total frame size in bytes.
    frame_size: usize,
    /// Whether the frame has been modified.
    dirty: bool,
}

impl StackEditorModel {
    /// Create a new stack editor model for a function.
    pub fn new(function_address: Address, frame_size: usize) -> Self {
        Self {
            function_address,
            variables: BTreeMap::new(),
            frame_size,
            dirty: false,
        }
    }

    /// Get the function address.
    pub fn function_address(&self) -> Address {
        self.function_address
    }

    /// Get the frame size.
    pub fn frame_size(&self) -> usize {
        self.frame_size
    }

    /// Set the frame size.
    pub fn set_frame_size(&mut self, size: usize) {
        self.frame_size = size;
        self.dirty = true;
    }

    /// Add a variable to the stack frame.
    ///
    /// Returns `Err` if a variable already exists at the given offset.
    pub fn add_variable(&mut self, var: StackVariableEntry) -> Result<(), String> {
        if self.variables.contains_key(&var.offset) {
            return Err(format!("Variable already exists at offset {}", var.offset));
        }
        self.variables.insert(var.offset, var);
        self.dirty = true;
        Ok(())
    }

    /// Remove a variable at the given offset.
    pub fn remove_variable(&mut self, offset: i64) -> Option<StackVariableEntry> {
        let result = self.variables.remove(&offset);
        if result.is_some() {
            self.dirty = true;
        }
        result
    }

    /// Modify the name of a variable at the given offset.
    pub fn rename_variable(&mut self, offset: i64, new_name: &str) -> Result<(), String> {
        if let Some(var) = self.variables.get_mut(&offset) {
            var.name = new_name.to_string();
            var.dirty = true;
            self.dirty = true;
            Ok(())
        } else {
            Err(format!("No variable at offset {}", offset))
        }
    }

    /// Modify the data type of a variable at the given offset.
    pub fn set_data_type(&mut self, offset: i64, data_type: &str) -> Result<(), String> {
        if let Some(var) = self.variables.get_mut(&offset) {
            var.data_type = data_type.to_string();
            var.dirty = true;
            self.dirty = true;
            Ok(())
        } else {
            Err(format!("No variable at offset {}", offset))
        }
    }

    /// Get all variables.
    pub fn get_variables(&self) -> Vec<&StackVariableEntry> {
        self.variables.values().collect()
    }

    /// Get only local variables (non-parameters).
    pub fn get_locals(&self) -> Vec<&StackVariableEntry> {
        self.variables
            .values()
            .filter(|v| !v.is_parameter)
            .collect()
    }

    /// Get only parameters.
    pub fn get_parameters(&self) -> Vec<&StackVariableEntry> {
        self.variables
            .values()
            .filter(|v| v.is_parameter)
            .collect()
    }

    /// Get a variable at a specific offset.
    pub fn get_variable(&self, offset: i64) -> Option<&StackVariableEntry> {
        self.variables.get(&offset)
    }

    /// Whether the model has been modified.
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// Clear the dirty flag.
    pub fn clear_dirty(&mut self) {
        self.dirty = false;
        for var in self.variables.values_mut() {
            var.dirty = false;
        }
    }

    /// Return the number of variables.
    pub fn variable_count(&self) -> usize {
        self.variables.len()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_and_get_variable() {
        let mut model = StackEditorModel::new(Address::new(0x1000), 64);
        model
            .add_variable(StackVariableEntry::new("x", -8, 4, "int", false))
            .unwrap();
        let vars = model.get_variables();
        assert_eq!(vars.len(), 1);
        assert_eq!(vars[0].name, "x");
    }

    #[test]
    fn test_duplicate_offset_rejected() {
        let mut model = StackEditorModel::new(Address::new(0x1000), 64);
        model
            .add_variable(StackVariableEntry::new("x", -8, 4, "int", false))
            .unwrap();
        let result = model.add_variable(StackVariableEntry::new("y", -8, 4, "int", false));
        assert!(result.is_err());
    }

    #[test]
    fn test_remove_variable() {
        let mut model = StackEditorModel::new(Address::new(0x1000), 64);
        model
            .add_variable(StackVariableEntry::new("x", -8, 4, "int", false))
            .unwrap();
        let removed = model.remove_variable(-8);
        assert!(removed.is_some());
        assert_eq!(model.variable_count(), 0);
    }

    #[test]
    fn test_rename_variable() {
        let mut model = StackEditorModel::new(Address::new(0x1000), 64);
        model
            .add_variable(StackVariableEntry::new("x", -8, 4, "int", false))
            .unwrap();
        model.rename_variable(-8, "y").unwrap();
        assert_eq!(model.get_variable(-8).unwrap().name, "y");
    }

    #[test]
    fn test_set_data_type() {
        let mut model = StackEditorModel::new(Address::new(0x1000), 64);
        model
            .add_variable(StackVariableEntry::new("x", -8, 4, "int", false))
            .unwrap();
        model.set_data_type(-8, "float").unwrap();
        assert_eq!(model.get_variable(-8).unwrap().data_type, "float");
    }

    #[test]
    fn test_get_locals_and_parameters() {
        let mut model = StackEditorModel::new(Address::new(0x1000), 64);
        model
            .add_variable(StackVariableEntry::new("local", -8, 4, "int", false))
            .unwrap();
        model
            .add_variable(StackVariableEntry::new("param", 8, 4, "int", true))
            .unwrap();
        assert_eq!(model.get_locals().len(), 1);
        assert_eq!(model.get_parameters().len(), 1);
    }

    #[test]
    fn test_dirty_tracking() {
        let mut model = StackEditorModel::new(Address::new(0x1000), 64);
        assert!(!model.is_dirty());
        model.set_frame_size(128);
        assert!(model.is_dirty());
        model.clear_dirty();
        assert!(!model.is_dirty());
    }

    #[test]
    fn test_resize_frame() {
        let mut model = StackEditorModel::new(Address::new(0x1000), 64);
        model.set_frame_size(128);
        assert_eq!(model.frame_size(), 128);
    }
}
