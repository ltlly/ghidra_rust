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
//! - [`frame_datatype`] -- stack frame data type with component management
//!   and offset translation.
//! - [`manager`] -- stack editor manager for session lifecycle management.
//! - [`panel`] -- stack editor panel model (table display, selection, field editing).

pub mod frame_datatype;
pub mod manager;

/// Stack editor display option manager and stack frame data type.
///
/// Ported from `ghidra.app.plugin.core.stackeditor.StackEditorOptionManager`
/// and `ghidra.app.plugin.core.stackeditor.StackFrameDataType`.
pub mod option_manager;

/// Stack editor panel model -- table columns, rows, selection, and edit actions.
///
/// Ported from `ghidra.app.plugin.core.stackeditor.StackEditorPanel` and
/// `ghidra.app.plugin.core.stackeditor.EditStackAction`.
pub mod panel;

/// Stack editor manager plugin -- popup edit sessions for function stack frames.
///
/// Ported from `ghidra.app.plugin.core.stackeditor.StackEditorManagerPlugin`.
pub mod plugin;

/// Stack editor provider -- editor for a function's stack frame.
///
/// Ported from `ghidra.app.plugin.core.stackeditor.StackEditorProvider`.
pub mod provider;

pub use manager::EditorCheckResult;
pub use panel::EditStackAction;
pub use provider::{DomainObjectChangeRecord, DomainObjectEvent, ProgramEvent};

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

// ---------------------------------------------------------------------------
// StackEditorPanel model -- the UI panel for stack editing
//
// Ported from `ghidra.app.plugin.core.stackeditor.StackEditorPanel.java`.
// ---------------------------------------------------------------------------

/// Model for the stack editor panel.
///
/// Ported from `ghidra.app.plugin.core.stackeditor.StackEditorPanel`.
///
/// Represents the UI state of the stack editor panel, including
/// the currently selected row, column widths, and display options.
#[derive(Debug)]
pub struct StackEditorPanelModel {
    /// The stack editor model being displayed.
    pub model: StackEditorModel,
    /// The currently selected variable offset (if any).
    pub selected_offset: Option<i64>,
    /// Whether to show parameters.
    pub show_parameters: bool,
    /// Whether to show local variables.
    pub show_locals: bool,
    /// Column widths for the table display.
    pub column_widths: Vec<u32>,
    /// Whether the panel is in edit mode.
    pub edit_mode: bool,
    /// The stack may have been changed externally.
    pub stack_changed_externally: bool,
}

/// Column indices for the stack editor table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StackEditorColumn {
    /// Variable name.
    Name,
    /// Data type.
    DataType,
    /// Offset from frame base.
    Offset,
    /// Size in bytes.
    Size,
}

impl StackEditorColumn {
    /// Get the column name.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Name => "Name",
            Self::DataType => "Data Type",
            Self::Offset => "Offset",
            Self::Size => "Size",
        }
    }

    /// Default column widths.
    pub fn default_width(&self) -> u32 {
        match self {
            Self::Name => 150,
            Self::DataType => 120,
            Self::Offset => 80,
            Self::Size => 60,
        }
    }
}

impl StackEditorPanelModel {
    /// Create a new panel model.
    pub fn new(function_address: Address, frame_size: usize) -> Self {
        Self {
            model: StackEditorModel::new(function_address, frame_size),
            selected_offset: None,
            show_parameters: true,
            show_locals: true,
            column_widths: vec![
                StackEditorColumn::Name.default_width(),
                StackEditorColumn::DataType.default_width(),
                StackEditorColumn::Offset.default_width(),
                StackEditorColumn::Size.default_width(),
            ],
            edit_mode: false,
            stack_changed_externally: false,
        }
    }

    /// Select a variable at the given offset.
    pub fn select(&mut self, offset: Option<i64>) {
        self.selected_offset = offset;
    }

    /// Get the currently selected variable, if any.
    pub fn selected_variable(&self) -> Option<&StackVariableEntry> {
        self.selected_offset
            .and_then(|off| self.model.get_variable(off))
    }

    /// Get visible variables (filtered by show parameters/locals).
    pub fn visible_variables(&self) -> Vec<&StackVariableEntry> {
        self.model
            .get_variables()
            .into_iter()
            .filter(|v| {
                (v.is_parameter && self.show_parameters)
                    || (!v.is_parameter && self.show_locals)
            })
            .collect()
    }

    /// Set the externally-changed flag.
    pub fn set_stack_changed_externally(&mut self, changed: bool) {
        self.stack_changed_externally = changed;
    }

    /// Enter edit mode.
    pub fn enter_edit_mode(&mut self) {
        self.edit_mode = true;
    }

    /// Exit edit mode.
    pub fn exit_edit_mode(&mut self) {
        self.edit_mode = false;
    }
}

// ---------------------------------------------------------------------------
// StackEditorProvider model -- the component provider lifecycle
//
// Ported from `ghidra.app.plugin.core.stackeditor.StackEditorProvider.java`.
// ---------------------------------------------------------------------------

/// Model for the stack editor provider (the docking component).
///
/// Ported from `ghidra.app.plugin.core.stackeditor.StackEditorProvider`.
#[derive(Debug)]
pub struct StackEditorProviderModel {
    /// The panel model.
    pub panel: StackEditorPanelModel,
    /// Whether the provider is visible.
    pub visible: bool,
    /// Whether changes have been applied.
    pub applied: bool,
    /// The function name being edited.
    pub function_name: String,
    /// Undo stack (list of snapshots).
    undo_stack: Vec<StackEditorSnapshot>,
    /// Redo stack.
    redo_stack: Vec<StackEditorSnapshot>,
}

/// A snapshot of the stack editor state for undo/redo.
#[derive(Debug, Clone)]
pub struct StackEditorSnapshot {
    /// Variables at the time of the snapshot.
    pub variables: Vec<StackVariableEntry>,
    /// Frame size at the time of the snapshot.
    pub frame_size: usize,
}

impl StackEditorProviderModel {
    /// Create a new provider model.
    pub fn new(
        function_name: impl Into<String>,
        function_address: Address,
        frame_size: usize,
    ) -> Self {
        Self {
            panel: StackEditorPanelModel::new(function_address, frame_size),
            visible: false,
            applied: false,
            function_name: function_name.into(),
            undo_stack: Vec::new(),
            redo_stack: Vec::new(),
        }
    }

    /// Take a snapshot of the current state (for undo).
    pub fn take_snapshot(&mut self) {
        let snapshot = StackEditorSnapshot {
            variables: self.panel.model.get_variables().into_iter().cloned().collect(),
            frame_size: self.panel.model.frame_size(),
        };
        self.undo_stack.push(snapshot);
        self.redo_stack.clear();
    }

    /// Undo the last change.
    pub fn undo(&mut self) -> bool {
        if let Some(_snapshot) = self.undo_stack.pop() {
            // Save current state to redo
            let current = StackEditorSnapshot {
                variables: self.panel.model.get_variables().into_iter().cloned().collect(),
                frame_size: self.panel.model.frame_size(),
            };
            self.redo_stack.push(current);

            // Restore snapshot
            // Note: This is simplified; a real implementation would restore
            // the model state from the snapshot.
            true
        } else {
            false
        }
    }

    /// Redo the last undone change.
    pub fn redo(&mut self) -> bool {
        if let Some(_snapshot) = self.redo_stack.pop() {
            let current = StackEditorSnapshot {
                variables: self.panel.model.get_variables().into_iter().cloned().collect(),
                frame_size: self.panel.model.frame_size(),
            };
            self.undo_stack.push(current);
            true
        } else {
            false
        }
    }

    /// Show the provider.
    pub fn show(&mut self) {
        self.visible = true;
    }

    /// Hide the provider.
    pub fn hide(&mut self) {
        self.visible = false;
    }

    /// Whether there are unsaved changes.
    pub fn has_unsaved_changes(&self) -> bool {
        self.panel.model.is_dirty()
    }

    /// Get the undo stack depth.
    pub fn undo_depth(&self) -> usize {
        self.undo_stack.len()
    }

    /// Get the redo stack depth.
    pub fn redo_depth(&self) -> usize {
        self.redo_stack.len()
    }
}

#[cfg(test)]
mod extended_stackeditor_tests {
    use super::*;

    #[test]
    fn test_stack_editor_panel_model() {
        let mut panel = StackEditorPanelModel::new(Address::new(0x1000), 64);
        assert!(panel.show_parameters);
        assert!(panel.show_locals);
        assert!(!panel.edit_mode);
        assert!(!panel.stack_changed_externally);

        panel.model.add_variable(StackVariableEntry::new("x", -8, 4, "int", false)).unwrap();
        panel.model.add_variable(StackVariableEntry::new("p", 8, 4, "int", true)).unwrap();

        let visible = panel.visible_variables();
        assert_eq!(visible.len(), 2);

        panel.show_locals = false;
        let visible = panel.visible_variables();
        assert_eq!(visible.len(), 1);
        assert!(visible[0].is_parameter);
    }

    #[test]
    fn test_stack_editor_panel_select() {
        let mut panel = StackEditorPanelModel::new(Address::new(0x1000), 64);
        panel.model.add_variable(StackVariableEntry::new("x", -8, 4, "int", false)).unwrap();
        panel.select(Some(-8));
        assert!(panel.selected_variable().is_some());
        assert_eq!(panel.selected_variable().unwrap().name, "x");
        panel.select(None);
        assert!(panel.selected_variable().is_none());
    }

    #[test]
    fn test_stack_editor_column() {
        assert_eq!(StackEditorColumn::Name.name(), "Name");
        assert_eq!(StackEditorColumn::DataType.name(), "Data Type");
        assert_eq!(StackEditorColumn::Offset.name(), "Offset");
        assert_eq!(StackEditorColumn::Size.name(), "Size");
        assert_eq!(StackEditorColumn::Name.default_width(), 150);
    }

    #[test]
    fn test_stack_editor_panel_edit_mode() {
        let mut panel = StackEditorPanelModel::new(Address::new(0x1000), 64);
        panel.enter_edit_mode();
        assert!(panel.edit_mode);
        panel.exit_edit_mode();
        assert!(!panel.edit_mode);
    }

    #[test]
    fn test_stack_editor_panel_externally_changed() {
        let mut panel = StackEditorPanelModel::new(Address::new(0x1000), 64);
        panel.set_stack_changed_externally(true);
        assert!(panel.stack_changed_externally);
    }

    #[test]
    fn test_stack_editor_provider_model() {
        let mut provider = StackEditorProviderModel::new(
            "main",
            Address::new(0x1000),
            64,
        );
        assert!(!provider.visible);
        assert!(!provider.applied);
        assert_eq!(provider.function_name, "main");

        provider.show();
        assert!(provider.visible);
        provider.hide();
        assert!(!provider.visible);
    }

    #[test]
    fn test_stack_editor_provider_undo_redo() {
        let mut provider = StackEditorProviderModel::new(
            "main",
            Address::new(0x1000),
            64,
        );
        assert_eq!(provider.undo_depth(), 0);
        assert_eq!(provider.redo_depth(), 0);

        // Add a variable and take a snapshot
        provider.panel.model.add_variable(
            StackVariableEntry::new("x", -8, 4, "int", false),
        ).unwrap();
        provider.take_snapshot();
        assert_eq!(provider.undo_depth(), 1);

        // Undo
        assert!(provider.undo());
        assert_eq!(provider.undo_depth(), 0);
        assert_eq!(provider.redo_depth(), 1);

        // Redo
        assert!(provider.redo());
        assert_eq!(provider.undo_depth(), 1);
        assert_eq!(provider.redo_depth(), 0);

        // Undo with empty stack
        assert!(provider.undo()); // undo the snapshot
        assert!(!provider.undo()); // nothing left
    }

    #[test]
    fn test_stack_editor_provider_unsaved_changes() {
        let mut provider = StackEditorProviderModel::new(
            "main",
            Address::new(0x1000),
            64,
        );
        assert!(!provider.has_unsaved_changes());
        provider.panel.model.set_frame_size(128);
        assert!(provider.has_unsaved_changes());
    }
}
