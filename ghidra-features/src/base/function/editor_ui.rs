//! Function editor UI components -- ported from `ghidra.app.plugin.core.function.editor`.
//!
//! Provides the remaining UI models for the function signature editor that
//! were not included in the core `editor` module.  These include:
//!
//! | Rust struct                        | Java class                        |
//! |------------------------------------|-----------------------------------|
//! | `FunctionSignatureFieldModel`      | `FunctionSignatureTextField`      |
//! | `FunctionDataViewModel`            | `FunctionDataView`                |
//! | `FunctionEditorDialogModel`        | `FunctionEditorDialog`            |
//! | `ParameterDataTypeCellEditorModel` | `ParameterDataTypeCellEditor`     |
//! | `RegisterDropDownModel`            | `RegisterDropDownSelectionDataModel` |
//! | `StorageAddressEditorModel`        | `StorageAddressEditorDialog`      |
//! | `StorageAddressModel`              | `StorageAddressModel`             |
//! | `StorageTableCellEditorModel`      | `StorageTableCellEditor`          |
//! | `VarnodeLocationEditorModel`       | `VarnodeLocationCellEditor`       |
//! | `VarnodeLocationRendererModel`     | `VarnodeLocationTableCellRenderer`|
//! | `VarnodeSizeEditorModel`           | `VarnodeSizeCellEditor`           |
//! | `VarnodeTableModel`                | `VarnodeTableModel`               |
//! | `VarnodeTypeEditorModel`           | `VarnodeTypeCellEditor`           |

use std::fmt;

use crate::base::function::editor::{
    FunctionData, FunctionEditorModel, ParamInfo, VarnodeInfo, VarnodeType,
};

// ---------------------------------------------------------------------------
// FunctionSignatureFieldModel
// ---------------------------------------------------------------------------

/// Model for the function signature text field that supports both
/// free-text editing and structured editing of the signature.
///
/// Ported from `FunctionSignatureTextField.java`.
#[derive(Debug, Clone)]
pub struct FunctionSignatureFieldModel {
    /// The current signature text.
    signature_text: String,
    /// Whether the field is in edit mode.
    is_editing: bool,
    /// Whether the signature is valid.
    is_valid: bool,
    /// The error message if invalid.
    error_message: Option<String>,
    /// The column width of the field.
    columns: usize,
}

impl FunctionSignatureFieldModel {
    /// Creates a new signature field model.
    pub fn new(signature_text: impl Into<String>) -> Self {
        Self {
            signature_text: signature_text.into(),
            is_editing: false,
            is_valid: true,
            error_message: None,
            columns: 60,
        }
    }

    /// Returns the current signature text.
    pub fn signature_text(&self) -> &str {
        &self.signature_text
    }

    /// Sets the signature text.
    pub fn set_signature_text(&mut self, text: impl Into<String>) {
        self.signature_text = text.into();
    }

    /// Returns whether the field is in edit mode.
    pub fn is_editing(&self) -> bool {
        self.is_editing
    }

    /// Enters edit mode.
    pub fn begin_editing(&mut self) {
        self.is_editing = true;
    }

    /// Exits edit mode and commits the current text.
    pub fn commit(&mut self) {
        self.is_editing = false;
    }

    /// Exits edit mode and reverts to the previous text.
    pub fn cancel(&mut self, original: &str) {
        self.signature_text = original.to_string();
        self.is_editing = false;
        self.is_valid = true;
        self.error_message = None;
    }

    /// Returns whether the signature is valid.
    pub fn is_valid(&self) -> bool {
        self.is_valid
    }

    /// Sets the validity state.
    pub fn set_valid(&mut self, valid: bool, error: Option<String>) {
        self.is_valid = valid;
        self.error_message = error;
    }

    /// Returns the error message, if any.
    pub fn error_message(&self) -> Option<&str> {
        self.error_message.as_deref()
    }

    /// Returns the column width.
    pub fn columns(&self) -> usize {
        self.columns
    }

    /// Sets the column width.
    pub fn set_columns(&mut self, columns: usize) {
        self.columns = columns;
    }
}

// ---------------------------------------------------------------------------
// FunctionDataViewModel
// ---------------------------------------------------------------------------

/// The display mode for the function data view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataViewMode {
    /// Display parameters as a flat list.
    Flat,
    /// Display parameters grouped by category (return, params, locals).
    Grouped,
}

impl fmt::Display for DataViewMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Flat => write!(f, "Flat"),
            Self::Grouped => write!(f, "Grouped"),
        }
    }
}

/// Model for the function data view that shows the function's variables
/// (parameters and locals) in a table.
///
/// Ported from `FunctionDataView.java`.
#[derive(Debug, Clone)]
pub struct FunctionDataViewModel {
    /// The display mode.
    mode: DataViewMode,
    /// Whether the view is read-only.
    read_only: bool,
    /// Whether to show auto-parameters.
    show_auto_params: bool,
    /// The selected row index (if any).
    selected_row: Option<usize>,
}

impl FunctionDataViewModel {
    /// Creates a new function data view model.
    pub fn new() -> Self {
        Self {
            mode: DataViewMode::Flat,
            read_only: false,
            show_auto_params: false,
            selected_row: None,
        }
    }

    /// Returns the display mode.
    pub fn mode(&self) -> DataViewMode {
        self.mode
    }

    /// Sets the display mode.
    pub fn set_mode(&mut self, mode: DataViewMode) {
        self.mode = mode;
    }

    /// Returns whether the view is read-only.
    pub fn is_read_only(&self) -> bool {
        self.read_only
    }

    /// Sets the read-only flag.
    pub fn set_read_only(&mut self, read_only: bool) {
        self.read_only = read_only;
    }

    /// Returns whether auto-parameters are shown.
    pub fn shows_auto_params(&self) -> bool {
        self.show_auto_params
    }

    /// Sets whether to show auto-parameters.
    pub fn set_show_auto_params(&mut self, show: bool) {
        self.show_auto_params = show;
    }

    /// Returns the selected row index.
    pub fn selected_row(&self) -> Option<usize> {
        self.selected_row
    }

    /// Sets the selected row index.
    pub fn set_selected_row(&mut self, row: Option<usize>) {
        self.selected_row = row;
    }
}

impl Default for FunctionDataViewModel {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// FunctionEditorDialogModel
// ---------------------------------------------------------------------------

/// The state of the function editor dialog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EditorDialogState {
    /// The dialog is open and being edited.
    Open,
    /// The user committed changes.
    Committed,
    /// The user cancelled.
    Cancelled,
}

/// Model for the function editor dialog.
///
/// Ported from `FunctionEditorDialog.java`.  This is the top-level model
/// that combines the `FunctionEditorModel` with dialog-level state
/// (OK/Apply/Cancel buttons, panel switching, etc.).
#[derive(Debug)]
pub struct FunctionEditorDialogModel {
    /// The core function editor model.
    editor_model: FunctionEditorModel,
    /// The dialog state.
    state: EditorDialogState,
    /// Whether to apply changes on OK (vs. only on explicit Apply).
    apply_on_ok: bool,
    /// Whether the dialog is resizable.
    resizable: bool,
    /// Whether to show the calling convention combo box.
    show_calling_convention: bool,
    /// Whether to show the call fixup combo box.
    show_call_fixup: bool,
    /// Whether to show the inline checkbox.
    show_inline: bool,
    /// Whether to show the no-return checkbox.
    show_no_return: bool,
    /// The current panel index (for multi-panel dialogs).
    current_panel: usize,
}

impl FunctionEditorDialogModel {
    /// Creates a new function editor dialog model.
    pub fn new(function_data: FunctionData) -> Self {
        Self {
            editor_model: FunctionEditorModel::new(function_data),
            state: EditorDialogState::Open,
            apply_on_ok: true,
            resizable: true,
            show_calling_convention: true,
            show_call_fixup: false,
            show_inline: true,
            show_no_return: true,
            current_panel: 0,
        }
    }

    /// Returns a reference to the editor model.
    pub fn editor_model(&self) -> &FunctionEditorModel {
        &self.editor_model
    }

    /// Returns a mutable reference to the editor model.
    pub fn editor_model_mut(&mut self) -> &mut FunctionEditorModel {
        &mut self.editor_model
    }

    /// Returns the dialog state.
    pub fn state(&self) -> EditorDialogState {
        self.state
    }

    /// Commits the dialog (user pressed OK).
    pub fn ok(&mut self) {
        self.state = EditorDialogState::Committed;
    }

    /// Applies changes without closing (user pressed Apply).
    pub fn apply(&mut self) {
        // In a real implementation, this would execute the change commands
        // against the program.
    }

    /// Cancels the dialog.
    pub fn cancel(&mut self) {
        self.editor_model.reset();
        self.state = EditorDialogState::Cancelled;
    }

    /// Returns whether the dialog is still open.
    pub fn is_open(&self) -> bool {
        self.state == EditorDialogState::Open
    }

    /// Returns whether the calling convention combo is shown.
    pub fn shows_calling_convention(&self) -> bool {
        self.show_calling_convention
    }

    /// Returns whether the call fixup combo is shown.
    pub fn shows_call_fixup(&self) -> bool {
        self.show_call_fixup
    }

    /// Returns whether the inline checkbox is shown.
    pub fn shows_inline(&self) -> bool {
        self.show_inline
    }

    /// Returns whether the no-return checkbox is shown.
    pub fn shows_no_return(&self) -> bool {
        self.show_no_return
    }

    /// Returns the current panel index.
    pub fn current_panel(&self) -> usize {
        self.current_panel
    }

    /// Sets the current panel index.
    pub fn set_current_panel(&mut self, panel: usize) {
        self.current_panel = panel;
    }
}

// ---------------------------------------------------------------------------
// RegisterDropDownModel
// ---------------------------------------------------------------------------

/// Model for the register dropdown selection in the storage editor.
///
/// Ported from `RegisterDropDownSelectionDataModel.java`.
#[derive(Debug, Clone)]
pub struct RegisterDropDownModel {
    /// The available register names.
    registers: Vec<String>,
    /// The currently selected register.
    selected: Option<String>,
}

impl RegisterDropDownModel {
    /// Creates a new register dropdown model.
    pub fn new(registers: Vec<String>) -> Self {
        Self {
            registers,
            selected: None,
        }
    }

    /// Returns the register names.
    pub fn registers(&self) -> &[String] {
        &self.registers
    }

    /// Returns the selected register.
    pub fn selected(&self) -> Option<&str> {
        self.selected.as_deref()
    }

    /// Selects a register by name.
    pub fn select(&mut self, name: impl Into<String>) {
        let name_s = name.into();
        if self.registers.iter().any(|r| r == &name_s) {
            self.selected = Some(name_s);
        }
    }

    /// Clears the selection.
    pub fn clear_selection(&mut self) {
        self.selected = None;
    }

    /// Returns the index of the selected register.
    pub fn selected_index(&self) -> Option<usize> {
        self.selected
            .as_ref()
            .and_then(|s| self.registers.iter().position(|r| r == s))
    }
}

// ---------------------------------------------------------------------------
// StorageAddressModel
// ---------------------------------------------------------------------------

/// Model for editing the storage address of a variable.
///
/// Ported from `StorageAddressModel.java`.
#[derive(Debug, Clone)]
pub struct StorageAddressModel {
    /// The varnode type being edited.
    varnode_type: VarnodeType,
    /// The register name (for register storage).
    register_name: Option<String>,
    /// The stack offset (for stack storage).
    stack_offset: Option<i64>,
    /// The memory address (for memory storage).
    memory_address: Option<u64>,
    /// The size in bytes.
    size: usize,
    /// Whether the current configuration is valid.
    is_valid: bool,
    /// Validation error message.
    error_message: Option<String>,
}

impl StorageAddressModel {
    /// Creates a new storage address model.
    pub fn new(varnode_type: VarnodeType) -> Self {
        Self {
            varnode_type,
            register_name: None,
            stack_offset: None,
            memory_address: None,
            size: 1,
            is_valid: true,
            error_message: None,
        }
    }

    /// Creates a model from an existing `VarnodeInfo`.
    pub fn from_varnode(info: &VarnodeInfo) -> Self {
        match info.varnode_type() {
            VarnodeType::Register => Self {
                varnode_type: VarnodeType::Register,
                register_name: Some(info.name().to_string()),
                stack_offset: None,
                memory_address: None,
                size: info.size(),
                is_valid: true,
                error_message: None,
            },
            VarnodeType::Stack => Self {
                varnode_type: VarnodeType::Stack,
                register_name: None,
                stack_offset: Some(info.offset()),
                memory_address: None,
                size: info.size(),
                is_valid: true,
                error_message: None,
            },
            VarnodeType::Memory => Self {
                varnode_type: VarnodeType::Memory,
                register_name: None,
                stack_offset: None,
                memory_address: Some(info.offset() as u64),
                size: info.size(),
                is_valid: true,
                error_message: None,
            },
        }
    }

    /// Returns the varnode type.
    pub fn varnode_type(&self) -> VarnodeType {
        self.varnode_type
    }

    /// Sets the varnode type.
    pub fn set_varnode_type(&mut self, varnode_type: VarnodeType) {
        self.varnode_type = varnode_type;
    }

    /// Returns the register name.
    pub fn register_name(&self) -> Option<&str> {
        self.register_name.as_deref()
    }

    /// Sets the register name.
    pub fn set_register_name(&mut self, name: Option<String>) {
        self.register_name = name;
        self.validate();
    }

    /// Returns the stack offset.
    pub fn stack_offset(&self) -> Option<i64> {
        self.stack_offset
    }

    /// Sets the stack offset.
    pub fn set_stack_offset(&mut self, offset: Option<i64>) {
        self.stack_offset = offset;
        self.validate();
    }

    /// Returns the memory address.
    pub fn memory_address(&self) -> Option<u64> {
        self.memory_address
    }

    /// Sets the memory address.
    pub fn set_memory_address(&mut self, addr: Option<u64>) {
        self.memory_address = addr;
        self.validate();
    }

    /// Returns the size.
    pub fn size(&self) -> usize {
        self.size
    }

    /// Sets the size.
    pub fn set_size(&mut self, size: usize) {
        self.size = size;
        self.validate();
    }

    /// Returns whether the model is valid.
    pub fn is_valid(&self) -> bool {
        self.is_valid
    }

    /// Returns the error message, if any.
    pub fn error_message(&self) -> Option<&str> {
        self.error_message.as_deref()
    }

    /// Validates the model.
    fn validate(&mut self) {
        self.is_valid = true;
        self.error_message = None;

        if self.size == 0 {
            self.is_valid = false;
            self.error_message = Some("Size must be greater than 0".to_string());
        }
        match self.varnode_type {
            VarnodeType::Register => {
                if self.register_name.is_none() {
                    self.is_valid = false;
                    self.error_message = Some("Register name is required".to_string());
                }
            }
            VarnodeType::Stack => {
                if self.stack_offset.is_none() {
                    self.is_valid = false;
                    self.error_message = Some("Stack offset is required".to_string());
                }
            }
            VarnodeType::Memory => {
                if self.memory_address.is_none() {
                    self.is_valid = false;
                    self.error_message = Some("Memory address is required".to_string());
                }
            }
        }
    }

    /// Builds a `VarnodeInfo` from the current model state, if valid.
    pub fn to_varnode(&self) -> Option<VarnodeInfo> {
        if !self.is_valid {
            return None;
        }
        match self.varnode_type {
            VarnodeType::Register => {
                Some(VarnodeInfo::register(
                    self.register_name.as_deref().unwrap_or(""),
                    self.size,
                ))
            }
            VarnodeType::Stack => {
                Some(VarnodeInfo::stack(
                    self.stack_offset.unwrap_or(0),
                    self.size,
                ))
            }
            VarnodeType::Memory => {
                Some(VarnodeInfo::memory(
                    self.memory_address.unwrap_or(0),
                    self.size,
                ))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// VarnodeTableModel
// ---------------------------------------------------------------------------

/// Column identifiers for the varnode table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VarnodeColumn {
    /// The varnode type (Register/Stack/Memory).
    Type,
    /// The name (register name or address).
    Name,
    /// The size in bytes.
    Size,
    /// The offset (stack offset or memory address).
    Offset,
}

impl fmt::Display for VarnodeColumn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Type => write!(f, "Type"),
            Self::Name => write!(f, "Name"),
            Self::Size => write!(f, "Size"),
            Self::Offset => write!(f, "Offset"),
        }
    }
}

/// Table model for displaying varnodes in the function editor.
///
/// Ported from `VarnodeTableModel.java`.
#[derive(Debug, Clone)]
pub struct VarnodeTableModel {
    /// The varnodes.
    varnodes: Vec<VarnodeInfo>,
    /// Whether the model is editable.
    editable: bool,
    /// The selected row.
    selected_row: Option<usize>,
}

impl VarnodeTableModel {
    /// Creates a new varnode table model.
    pub fn new(editable: bool) -> Self {
        Self {
            varnodes: Vec::new(),
            editable,
            selected_row: None,
        }
    }

    /// Returns the varnodes.
    pub fn varnodes(&self) -> &[VarnodeInfo] {
        &self.varnodes
    }

    /// Adds a varnode.
    pub fn add_varnode(&mut self, vn: VarnodeInfo) {
        self.varnodes.push(vn);
    }

    /// Removes a varnode by index.
    pub fn remove_varnode(&mut self, index: usize) -> Option<VarnodeInfo> {
        if index < self.varnodes.len() {
            Some(self.varnodes.remove(index))
        } else {
            None
        }
    }

    /// Returns the row count.
    pub fn row_count(&self) -> usize {
        self.varnodes.len()
    }

    /// Returns the column count (always 4).
    pub fn column_count(&self) -> usize {
        4
    }

    /// Gets a cell value by row and column index.
    pub fn get_value_at(&self, row: usize, col: usize) -> Option<String> {
        let vn = self.varnodes.get(row)?;
        match col {
            0 => Some(vn.varnode_type().to_string()),
            1 => Some(vn.name().to_string()),
            2 => Some(vn.size().to_string()),
            3 => Some(format!("{}", vn.offset())),
            _ => None,
        }
    }

    /// Returns whether the model is editable.
    pub fn is_editable(&self) -> bool {
        self.editable
    }

    /// Returns the selected row.
    pub fn selected_row(&self) -> Option<usize> {
        self.selected_row
    }

    /// Sets the selected row.
    pub fn set_selected_row(&mut self, row: Option<usize>) {
        self.selected_row = row;
    }

    /// Clears all varnodes.
    pub fn clear(&mut self) {
        self.varnodes.clear();
        self.selected_row = None;
    }
}

impl Default for VarnodeTableModel {
    fn default() -> Self {
        Self::new(false)
    }
}

// ---------------------------------------------------------------------------
// Cell editor models (lightweight)
// ---------------------------------------------------------------------------

/// Cell editor model for varnode type selection.
///
/// Ported from `VarnodeTypeCellEditor.java`.
#[derive(Debug, Clone)]
pub struct VarnodeTypeEditorModel {
    /// The available types.
    types: Vec<VarnodeType>,
    /// The selected type.
    selected: VarnodeType,
}

impl VarnodeTypeEditorModel {
    /// Creates a new varnode type editor model.
    pub fn new() -> Self {
        Self {
            types: vec![VarnodeType::Register, VarnodeType::Stack, VarnodeType::Memory],
            selected: VarnodeType::Register,
        }
    }

    /// Returns the available types.
    pub fn types(&self) -> &[VarnodeType] {
        &self.types
    }

    /// Returns the selected type.
    pub fn selected(&self) -> VarnodeType {
        self.selected
    }

    /// Sets the selected type.
    pub fn set_selected(&mut self, vtype: VarnodeType) {
        self.selected = vtype;
    }
}

impl Default for VarnodeTypeEditorModel {
    fn default() -> Self {
        Self::new()
    }
}

/// Cell editor model for varnode size.
///
/// Ported from `VarnodeSizeCellEditor.java`.
#[derive(Debug, Clone)]
pub struct VarnodeSizeEditorModel {
    /// The current size value.
    size: usize,
    /// The minimum allowed size.
    min_size: usize,
    /// The maximum allowed size.
    max_size: usize,
}

impl VarnodeSizeEditorModel {
    /// Creates a new varnode size editor model.
    pub fn new(size: usize) -> Self {
        Self {
            size,
            min_size: 1,
            max_size: 512,
        }
    }

    /// Returns the current size.
    pub fn size(&self) -> usize {
        self.size
    }

    /// Sets the size (clamped to min/max).
    pub fn set_size(&mut self, size: usize) {
        self.size = size.clamp(self.min_size, self.max_size);
    }

    /// Returns whether the current size is valid.
    pub fn is_valid(&self) -> bool {
        self.size >= self.min_size && self.size <= self.max_size
    }
}

/// Cell editor model for varnode location (name/address).
///
/// Ported from `VarnodeLocationCellEditor.java`.
#[derive(Debug, Clone)]
pub struct VarnodeLocationEditorModel {
    /// The varnode type (determines what fields are shown).
    varnode_type: VarnodeType,
    /// The text value being edited.
    text_value: String,
    /// Whether the current value is valid.
    is_valid: bool,
}

impl VarnodeLocationEditorModel {
    /// Creates a new varnode location editor model.
    pub fn new(varnode_type: VarnodeType) -> Self {
        Self {
            varnode_type,
            text_value: String::new(),
            is_valid: false,
        }
    }

    /// Returns the text value.
    pub fn text_value(&self) -> &str {
        &self.text_value
    }

    /// Sets the text value.
    pub fn set_text_value(&mut self, value: impl Into<String>) {
        self.text_value = value.into();
        self.validate();
    }

    /// Returns the varnode type.
    pub fn varnode_type(&self) -> VarnodeType {
        self.varnode_type
    }

    /// Returns whether the value is valid.
    pub fn is_valid(&self) -> bool {
        self.is_valid
    }

    fn validate(&mut self) {
        self.is_valid = !self.text_value.is_empty();
    }
}

/// Display configuration for varnode location rendering.
///
/// Ported from `VarnodeLocationTableCellRenderer.java`.
#[derive(Debug, Clone)]
pub struct VarnodeLocationRendererConfig {
    /// The text color for register locations.
    pub register_color: String,
    /// The text color for stack locations.
    pub stack_color: String,
    /// The text color for memory locations.
    pub memory_color: String,
    /// Whether to show the varnode type prefix.
    pub show_type_prefix: bool,
}

impl VarnodeLocationRendererConfig {
    /// Creates a new renderer configuration with defaults.
    pub fn new() -> Self {
        Self {
            register_color: "#0000FF".to_string(),
            stack_color: "#800080".to_string(),
            memory_color: "#808000".to_string(),
            show_type_prefix: false,
        }
    }

    /// Returns the color for the given varnode type.
    pub fn color_for_type(&self, vtype: VarnodeType) -> &str {
        match vtype {
            VarnodeType::Register => &self.register_color,
            VarnodeType::Stack => &self.stack_color,
            VarnodeType::Memory => &self.memory_color,
        }
    }
}

impl Default for VarnodeLocationRendererConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// Model for the parameter data type cell editor.
///
/// Ported from `ParameterDataTypeCellEditor.java`.
#[derive(Debug, Clone)]
pub struct ParameterDataTypeCellEditorModel {
    /// The current data type name.
    data_type_name: String,
    /// Whether the editor is active.
    is_active: bool,
    /// Whether the value is valid.
    is_valid: bool,
}

impl ParameterDataTypeCellEditorModel {
    /// Creates a new parameter data type cell editor model.
    pub fn new(data_type_name: impl Into<String>) -> Self {
        Self {
            data_type_name: data_type_name.into(),
            is_active: false,
            is_valid: true,
        }
    }

    /// Returns the data type name.
    pub fn data_type_name(&self) -> &str {
        &self.data_type_name
    }

    /// Sets the data type name.
    pub fn set_data_type_name(&mut self, name: impl Into<String>) {
        self.data_type_name = name.into();
    }

    /// Returns whether the editor is active.
    pub fn is_active(&self) -> bool {
        self.is_active
    }

    /// Activates the editor.
    pub fn activate(&mut self) {
        self.is_active = true;
    }

    /// Deactivates the editor.
    pub fn deactivate(&mut self) {
        self.is_active = false;
    }

    /// Returns whether the value is valid.
    pub fn is_valid(&self) -> bool {
        self.is_valid
    }
}

/// Model for the storage table cell editor.
///
/// Ported from `StorageTableCellEditor.java`.
#[derive(Debug, Clone)]
pub struct StorageTableCellEditorModel {
    /// The current storage display text.
    storage_text: String,
    /// Whether the editor is active.
    is_active: bool,
}

impl StorageTableCellEditorModel {
    /// Creates a new storage table cell editor model.
    pub fn new(storage_text: impl Into<String>) -> Self {
        Self {
            storage_text: storage_text.into(),
            is_active: false,
        }
    }

    /// Returns the storage text.
    pub fn storage_text(&self) -> &str {
        &self.storage_text
    }

    /// Sets the storage text.
    pub fn set_storage_text(&mut self, text: impl Into<String>) {
        self.storage_text = text.into();
    }

    /// Returns whether the editor is active.
    pub fn is_active(&self) -> bool {
        self.is_active
    }

    /// Activates the editor.
    pub fn activate(&mut self) {
        self.is_active = true;
    }

    /// Deactivates the editor.
    pub fn deactivate(&mut self) {
        self.is_active = false;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- FunctionSignatureFieldModel --

    #[test]
    fn test_signature_field_model() {
        let mut model = FunctionSignatureFieldModel::new("int main(void)");
        assert_eq!(model.signature_text(), "int main(void)");
        assert!(!model.is_editing());
        assert!(model.is_valid());

        model.begin_editing();
        assert!(model.is_editing());

        model.set_signature_text("void new_func(int x)");
        model.commit();
        assert!(!model.is_editing());
        assert_eq!(model.signature_text(), "void new_func(int x)");
    }

    #[test]
    fn test_signature_field_model_cancel() {
        let mut model = FunctionSignatureFieldModel::new("original");
        model.begin_editing();
        model.set_signature_text("changed");
        model.cancel("original");
        assert_eq!(model.signature_text(), "original");
    }

    #[test]
    fn test_signature_field_model_error() {
        let mut model = FunctionSignatureFieldModel::new("test");
        model.set_valid(false, Some("Parse error".to_string()));
        assert!(!model.is_valid());
        assert_eq!(model.error_message(), Some("Parse error"));
    }

    // -- FunctionDataViewModel --

    #[test]
    fn test_data_view_model() {
        let mut model = FunctionDataViewModel::new();
        assert_eq!(model.mode(), DataViewMode::Flat);
        assert!(!model.is_read_only());
        assert!(!model.shows_auto_params());
        assert!(model.selected_row().is_none());

        model.set_mode(DataViewMode::Grouped);
        assert_eq!(model.mode(), DataViewMode::Grouped);
    }

    #[test]
    fn test_data_view_mode_display() {
        assert_eq!(DataViewMode::Flat.to_string(), "Flat");
        assert_eq!(DataViewMode::Grouped.to_string(), "Grouped");
    }

    // -- FunctionEditorDialogModel --

    #[test]
    fn test_editor_dialog_model() {
        let fd = FunctionData::new("main", "int", "__cdecl");
        let mut dialog = FunctionEditorDialogModel::new(fd);
        assert!(dialog.is_open());
        assert!(dialog.shows_calling_convention());
        assert!(dialog.shows_inline());
        assert!(dialog.shows_no_return());

        dialog.ok();
        assert_eq!(dialog.state(), EditorDialogState::Committed);
    }

    #[test]
    fn test_editor_dialog_cancel() {
        let fd = FunctionData::new("main", "int", "__cdecl");
        let mut dialog = FunctionEditorDialogModel::new(fd);
        dialog.editor_model_mut().set_name("changed");
        assert!(dialog.editor_model().has_changes());

        dialog.cancel();
        assert_eq!(dialog.state(), EditorDialogState::Cancelled);
        assert!(!dialog.editor_model().has_changes());
    }

    // -- RegisterDropDownModel --

    #[test]
    fn test_register_dropdown_model() {
        let mut model = RegisterDropDownModel::new(vec![
            "RAX".to_string(),
            "RBX".to_string(),
            "RCX".to_string(),
        ]);
        assert_eq!(model.registers().len(), 3);
        assert!(model.selected().is_none());

        model.select("RBX");
        assert_eq!(model.selected(), Some("RBX"));
        assert_eq!(model.selected_index(), Some(1));
    }

    #[test]
    fn test_register_dropdown_invalid_select() {
        let mut model = RegisterDropDownModel::new(vec!["RAX".to_string()]);
        model.select("INVALID");
        assert!(model.selected().is_none());
    }

    // -- StorageAddressModel --

    #[test]
    fn test_storage_address_model_register() {
        let mut model = StorageAddressModel::new(VarnodeType::Register);
        model.set_register_name(Some("RAX".to_string()));
        model.set_size(8);
        assert!(model.is_valid());

        let vn = model.to_varnode().unwrap();
        assert_eq!(vn.varnode_type(), VarnodeType::Register);
        assert_eq!(vn.name(), "RAX");
        assert_eq!(vn.size(), 8);
    }

    #[test]
    fn test_storage_address_model_stack() {
        let mut model = StorageAddressModel::new(VarnodeType::Stack);
        model.set_stack_offset(Some(-8));
        model.set_size(4);
        assert!(model.is_valid());

        let vn = model.to_varnode().unwrap();
        assert_eq!(vn.varnode_type(), VarnodeType::Stack);
    }

    #[test]
    fn test_storage_address_model_memory() {
        let mut model = StorageAddressModel::new(VarnodeType::Memory);
        model.set_memory_address(Some(0x401000));
        model.set_size(2);
        assert!(model.is_valid());

        let vn = model.to_varnode().unwrap();
        assert_eq!(vn.varnode_type(), VarnodeType::Memory);
    }

    #[test]
    fn test_storage_address_model_invalid_size() {
        let mut model = StorageAddressModel::new(VarnodeType::Register);
        model.set_register_name(Some("RAX".to_string()));
        model.set_size(0);
        assert!(!model.is_valid());
        assert!(model.error_message().is_some());
    }

    #[test]
    fn test_storage_address_model_from_varnode() {
        let vn = VarnodeInfo::register("RDI", 8);
        let model = StorageAddressModel::from_varnode(&vn);
        assert_eq!(model.varnode_type(), VarnodeType::Register);
        assert_eq!(model.register_name(), Some("RDI"));
        assert_eq!(model.size(), 8);
    }

    // -- VarnodeTableModel --

    #[test]
    fn test_varnode_table_model() {
        let mut model = VarnodeTableModel::new(true);
        assert!(model.is_editable());
        assert_eq!(model.row_count(), 0);
        assert_eq!(model.column_count(), 4);

        model.add_varnode(VarnodeInfo::register("RAX", 8));
        model.add_varnode(VarnodeInfo::stack(-8, 4));
        assert_eq!(model.row_count(), 2);
    }

    #[test]
    fn test_varnode_table_model_values() {
        let mut model = VarnodeTableModel::new(true);
        model.add_varnode(VarnodeInfo::register("RAX", 8));

        assert_eq!(model.get_value_at(0, 0), Some("Register".into()));
        assert_eq!(model.get_value_at(0, 1), Some("RAX".into()));
        assert_eq!(model.get_value_at(0, 2), Some("8".into()));
        assert!(model.get_value_at(0, 3).is_some());
        assert_eq!(model.get_value_at(1, 0), None);
    }

    #[test]
    fn test_varnode_table_model_remove() {
        let mut model = VarnodeTableModel::new(false);
        model.add_varnode(VarnodeInfo::register("RAX", 8));
        model.add_varnode(VarnodeInfo::register("RBX", 8));
        let removed = model.remove_varnode(0);
        assert!(removed.is_some());
        assert_eq!(model.row_count(), 1);
    }

    // -- Cell editor models --

    #[test]
    fn test_varnode_type_editor_model() {
        let mut model = VarnodeTypeEditorModel::new();
        assert_eq!(model.types().len(), 3);
        assert_eq!(model.selected(), VarnodeType::Register);

        model.set_selected(VarnodeType::Stack);
        assert_eq!(model.selected(), VarnodeType::Stack);
    }

    #[test]
    fn test_varnode_size_editor_model() {
        let mut model = VarnodeSizeEditorModel::new(4);
        assert!(model.is_valid());
        assert_eq!(model.size(), 4);

        model.set_size(0); // Clamped to min_size (1)
        assert_eq!(model.size(), 1);
        assert!(model.is_valid());

        model.set_size(1000); // Clamped to max_size (512)
        assert_eq!(model.size(), 512);
    }

    #[test]
    fn test_varnode_location_editor_model() {
        let mut model = VarnodeLocationEditorModel::new(VarnodeType::Register);
        assert!(!model.is_valid()); // empty text

        model.set_text_value("RAX");
        assert!(model.is_valid());
        assert_eq!(model.text_value(), "RAX");
    }

    #[test]
    fn test_varnode_location_renderer_config() {
        let config = VarnodeLocationRendererConfig::new();
        assert!(!config.show_type_prefix);
        assert_eq!(config.color_for_type(VarnodeType::Register), "#0000FF");
        assert_eq!(config.color_for_type(VarnodeType::Stack), "#800080");
    }

    #[test]
    fn test_parameter_data_type_cell_editor_model() {
        let mut model = ParameterDataTypeCellEditorModel::new("int");
        assert_eq!(model.data_type_name(), "int");
        assert!(!model.is_active());

        model.activate();
        assert!(model.is_active());

        model.deactivate();
        assert!(!model.is_active());
    }

    #[test]
    fn test_storage_table_cell_editor_model() {
        let mut model = StorageTableCellEditorModel::new("RAX:8");
        assert_eq!(model.storage_text(), "RAX:8");
        assert!(!model.is_active());

        model.activate();
        assert!(model.is_active());
    }

    // -- VarnodeColumn Display --

    #[test]
    fn test_varnode_column_display() {
        assert_eq!(VarnodeColumn::Type.to_string(), "Type");
        assert_eq!(VarnodeColumn::Name.to_string(), "Name");
        assert_eq!(VarnodeColumn::Size.to_string(), "Size");
        assert_eq!(VarnodeColumn::Offset.to_string(), "Offset");
    }
}
