//! Cell editor models for the function editor tables.
//!
//! Ported from `ParameterDataTypeCellEditor.java`,
//! `VarnodeTypeCellEditor.java`, `VarnodeSizeCellEditor.java`,
//! `VarnodeLocationCellEditor.java`, and
//! `VarnodeLocationTableCellRenderer.java` in
//! `ghidra.app.plugin.core.function.editor`.
//!
//! These are the non-UI business logic behind the table cell editors
//! used in the function parameter table and the varnode storage table.
//! The actual Swing rendering is handled elsewhere.

use super::{VarnodeInfo, VarnodeType};

/// The type of data-type selector to use in a cell editor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DataTypeSelectorKind {
    /// A simple text input.
    Text,
    /// A dropdown with recently used types.
    RecentDropDown,
    /// A full data-type chooser dialog.
    Chooser,
}

impl std::fmt::Display for DataTypeSelectorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Text => write!(f, "Text"),
            Self::RecentDropDown => write!(f, "RecentDropDown"),
            Self::Chooser => write!(f, "Chooser"),
        }
    }
}

/// Model for the parameter data-type cell editor.
///
/// Ported from `ParameterDataTypeCellEditor.java`.  Handles the
/// conversion between display text and data-type objects for the
/// parameter table.
#[derive(Debug, Clone)]
pub struct ParameterDataTypeCellEditorModel {
    /// The current data type name.
    current_value: String,
    /// Whether the editor is currently active.
    is_active: bool,
    /// The selector kind to use.
    selector_kind: DataTypeSelectorKind,
    /// The maximum allowed size (in bytes) for the data type.
    max_size: Option<usize>,
}

impl ParameterDataTypeCellEditorModel {
    /// Creates a new model.
    pub fn new() -> Self {
        Self {
            current_value: String::new(),
            is_active: false,
            selector_kind: DataTypeSelectorKind::Chooser,
            max_size: None,
        }
    }

    /// Creates a model with a specific initial value.
    pub fn with_value(value: impl Into<String>) -> Self {
        Self {
            current_value: value.into(),
            is_active: false,
            selector_kind: DataTypeSelectorKind::Chooser,
            max_size: None,
        }
    }

    /// Returns the current value.
    pub fn current_value(&self) -> &str {
        &self.current_value
    }

    /// Sets the current value.
    pub fn set_current_value(&mut self, value: impl Into<String>) {
        self.current_value = value.into();
    }

    /// Returns whether the editor is active.
    pub fn is_active(&self) -> bool {
        self.is_active
    }

    /// Sets the active state.
    pub fn set_active(&mut self, active: bool) {
        self.is_active = active;
    }

    /// Returns the selector kind.
    pub fn selector_kind(&self) -> DataTypeSelectorKind {
        self.selector_kind
    }

    /// Sets the selector kind.
    pub fn set_selector_kind(&mut self, kind: DataTypeSelectorKind) {
        self.selector_kind = kind;
    }

    /// Returns the maximum allowed size.
    pub fn max_size(&self) -> Option<usize> {
        self.max_size
    }

    /// Sets the maximum allowed size.
    pub fn set_max_size(&mut self, size: Option<usize>) {
        self.max_size = size;
    }

    /// Validates a data type name.
    ///
    /// Returns `Ok(())` if the name is valid, or an error message if not.
    pub fn validate(&self, name: &str) -> Result<(), String> {
        if name.trim().is_empty() {
            return Err("Data type name cannot be empty".to_string());
        }
        // Basic validation - real implementation would check against DataTypeManager
        if name.contains(' ') && !name.contains('*') && !name.contains('[') {
            return Err(format!("Invalid data type name: {}", name));
        }
        Ok(())
    }
}

impl Default for ParameterDataTypeCellEditorModel {
    fn default() -> Self {
        Self::new()
    }
}

/// Model for the varnode type cell editor.
///
/// Ported from `VarnodeTypeCellEditor.java`.  Provides a dropdown
/// selection of varnode types (Register, Stack, Memory).
#[derive(Debug, Clone)]
pub struct VarnodeTypeCellEditorModel {
    /// The available varnode types.
    available_types: Vec<VarnodeType>,
    /// The currently selected type.
    selected_type: VarnodeType,
}

impl VarnodeTypeCellEditorModel {
    /// Creates a new model with all types available.
    pub fn new() -> Self {
        Self {
            available_types: vec![
                VarnodeType::Register,
                VarnodeType::Stack,
                VarnodeType::Memory,
            ],
            selected_type: VarnodeType::Register,
        }
    }

    /// Creates a model with a specific selected type.
    pub fn with_selected(selected: VarnodeType) -> Self {
        let mut model = Self::new();
        model.selected_type = selected;
        model
    }

    /// Returns the available types.
    pub fn available_types(&self) -> &[VarnodeType] {
        &self.available_types
    }

    /// Returns the selected type.
    pub fn selected_type(&self) -> VarnodeType {
        self.selected_type
    }

    /// Sets the selected type.
    pub fn set_selected_type(&mut self, ty: VarnodeType) {
        if self.available_types.contains(&ty) {
            self.selected_type = ty;
        }
    }

    /// Returns the index of the selected type in the available list.
    pub fn selected_index(&self) -> usize {
        self.available_types
            .iter()
            .position(|t| *t == self.selected_type)
            .unwrap_or(0)
    }

    /// Sets the selected type by index.
    pub fn set_selected_index(&mut self, index: usize) {
        if let Some(ty) = self.available_types.get(index).copied() {
            self.selected_type = ty;
        }
    }
}

impl Default for VarnodeTypeCellEditorModel {
    fn default() -> Self {
        Self::new()
    }
}

/// Model for the varnode size cell editor.
///
/// Ported from `VarnodeSizeCellEditor.java`.  Validates and converts
/// size input for varnode storage.
#[derive(Debug, Clone)]
pub struct VarnodeSizeCellEditorModel {
    /// The current size value.
    current_size: usize,
    /// The minimum allowed size.
    min_size: usize,
    /// The maximum allowed size.
    max_size: usize,
}

impl VarnodeSizeCellEditorModel {
    /// Creates a new model.
    pub fn new() -> Self {
        Self {
            current_size: 1,
            min_size: 1,
            max_size: 512,
        }
    }

    /// Creates a model with specific bounds.
    pub fn with_bounds(current: usize, min: usize, max: usize) -> Self {
        Self {
            current_size: current.max(min).min(max),
            min_size: min,
            max_size: max,
        }
    }

    /// Returns the current size.
    pub fn current_size(&self) -> usize {
        self.current_size
    }

    /// Sets the current size, clamping to bounds.
    pub fn set_current_size(&mut self, size: usize) {
        self.current_size = size.max(self.min_size).min(self.max_size);
    }

    /// Returns the minimum size.
    pub fn min_size(&self) -> usize {
        self.min_size
    }

    /// Returns the maximum size.
    pub fn max_size(&self) -> usize {
        self.max_size
    }

    /// Validates a size value.
    pub fn validate(&self, size: usize) -> Result<(), String> {
        if size < self.min_size {
            return Err(format!("Size must be at least {}", self.min_size));
        }
        if size > self.max_size {
            return Err(format!("Size must be at most {}", self.max_size));
        }
        Ok(())
    }

    /// Parses a size from a string.
    pub fn parse_size(&self, text: &str) -> Result<usize, String> {
        let trimmed = text.trim();
        let (value, radix) = if trimmed.starts_with("0x") || trimmed.starts_with("0X") {
            (u64::from_str_radix(&trimmed[2..], 16), 16)
        } else {
            (trimmed.parse::<u64>(), 10)
        };

        match value {
            Ok(v) => {
                let size = v as usize;
                self.validate(size)?;
                Ok(size)
            }
            Err(_) => Err(format!("Invalid size value: {}", trimmed)),
        }
    }
}

impl Default for VarnodeSizeCellEditorModel {
    fn default() -> Self {
        Self::new()
    }
}

/// Renderer model for varnode locations.
///
/// Ported from `VarnodeLocationTableCellRenderer.java`.  Converts
/// varnode location information to display text.
#[derive(Debug, Clone)]
pub struct VarnodeLocationRendererModel;

impl VarnodeLocationRendererModel {
    /// Renders a varnode's location as a display string.
    pub fn render_location(varnode: &VarnodeInfo) -> String {
        match varnode.varnode_type() {
            VarnodeType::Register => varnode.name().to_string(),
            VarnodeType::Stack => format!("Stack[{}]", varnode.offset()),
            VarnodeType::Memory => format!("0x{:x}", varnode.offset() as u64),
        }
    }

    /// Renders a varnode's type as a display string.
    pub fn render_type(varnode: &VarnodeInfo) -> String {
        varnode.varnode_type().label().to_string()
    }

    /// Renders a varnode's size as a display string.
    pub fn render_size(varnode: &VarnodeInfo) -> String {
        format!("{}", varnode.size())
    }

    /// Renders a full varnode row.
    pub fn render_row(varnode: &VarnodeInfo) -> Vec<String> {
        vec![
            Self::render_type(varnode),
            Self::render_location(varnode),
            Self::render_size(varnode),
        ]
    }
}

/// Cell editor for varnode location editing.
///
/// Ported from `VarnodeLocationCellEditor.java`.  Handles the parsing
/// of location input based on the varnode type.
#[derive(Debug, Clone)]
pub struct VarnodeLocationCellEditorModel {
    /// The current varnode being edited.
    varnode: VarnodeInfo,
    /// The edit text.
    edit_text: String,
}

impl VarnodeLocationCellEditorModel {
    /// Creates a new model for editing the given varnode.
    pub fn new(varnode: VarnodeInfo) -> Self {
        let edit_text = VarnodeLocationRendererModel::render_location(&varnode);
        Self { varnode, edit_text }
    }

    /// Returns the varnode being edited.
    pub fn varnode(&self) -> &VarnodeInfo {
        &self.varnode
    }

    /// Returns the current edit text.
    pub fn edit_text(&self) -> &str {
        &self.edit_text
    }

    /// Sets the edit text.
    pub fn set_edit_text(&mut self, text: impl Into<String>) {
        self.edit_text = text.into();
    }

    /// Applies the edit text to produce a new varnode.
    ///
    /// Returns `Ok(new_varnode)` if the edit is valid, or an error
    /// message if parsing fails.
    pub fn apply(&self) -> Result<VarnodeInfo, String> {
        let text = self.edit_text.trim();
        match self.varnode.varnode_type() {
            VarnodeType::Register => {
                if text.is_empty() {
                    return Err("Register name cannot be empty".to_string());
                }
                Ok(VarnodeInfo::register(text, self.varnode.size()))
            }
            VarnodeType::Stack => {
                let offset: i64 = text
                    .parse()
                    .map_err(|_| format!("Invalid stack offset: {}", text))?;
                Ok(VarnodeInfo::stack(offset, self.varnode.size()))
            }
            VarnodeType::Memory => {
                let trimmed = text.trim_start_matches("0x").trim_start_matches("0X");
                let addr = u64::from_str_radix(trimmed, 16)
                    .map_err(|_| format!("Invalid memory address: {}", text))?;
                Ok(VarnodeInfo::memory(addr, self.varnode.size()))
            }
        }
    }

    /// Validates the current edit text without applying.
    pub fn validate(&self) -> Result<(), String> {
        self.apply().map(|_| ())
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -- ParameterDataTypeCellEditorModel --

    #[test]
    fn test_param_dt_editor_model() {
        let model = ParameterDataTypeCellEditorModel::new();
        assert!(model.current_value().is_empty());
        assert!(!model.is_active());
    }

    #[test]
    fn test_param_dt_editor_model_with_value() {
        let model = ParameterDataTypeCellEditorModel::with_value("int");
        assert_eq!(model.current_value(), "int");
    }

    #[test]
    fn test_param_dt_editor_model_active() {
        let mut model = ParameterDataTypeCellEditorModel::new();
        model.set_active(true);
        assert!(model.is_active());
    }

    #[test]
    fn test_param_dt_editor_model_selector() {
        let mut model = ParameterDataTypeCellEditorModel::new();
        model.set_selector_kind(DataTypeSelectorKind::RecentDropDown);
        assert_eq!(model.selector_kind(), DataTypeSelectorKind::RecentDropDown);
    }

    #[test]
    fn test_param_dt_editor_model_max_size() {
        let mut model = ParameterDataTypeCellEditorModel::new();
        model.set_max_size(Some(8));
        assert_eq!(model.max_size(), Some(8));
    }

    #[test]
    fn test_param_dt_editor_model_validate_empty() {
        let model = ParameterDataTypeCellEditorModel::new();
        assert!(model.validate("").is_err());
        assert!(model.validate("  ").is_err());
    }

    #[test]
    fn test_param_dt_editor_model_validate_valid() {
        let model = ParameterDataTypeCellEditorModel::new();
        assert!(model.validate("int").is_ok());
        assert!(model.validate("void *").is_ok());
        assert!(model.validate("char[16]").is_ok());
    }

    #[test]
    fn test_data_type_selector_kind_display() {
        assert_eq!(DataTypeSelectorKind::Text.to_string(), "Text");
        assert_eq!(DataTypeSelectorKind::Chooser.to_string(), "Chooser");
    }

    // -- VarnodeTypeCellEditorModel --

    #[test]
    fn test_varnode_type_editor_model() {
        let model = VarnodeTypeCellEditorModel::new();
        assert_eq!(model.available_types().len(), 3);
        assert_eq!(model.selected_type(), VarnodeType::Register);
    }

    #[test]
    fn test_varnode_type_editor_model_with_selected() {
        let model = VarnodeTypeCellEditorModel::with_selected(VarnodeType::Stack);
        assert_eq!(model.selected_type(), VarnodeType::Stack);
    }

    #[test]
    fn test_varnode_type_editor_model_set_selected() {
        let mut model = VarnodeTypeCellEditorModel::new();
        model.set_selected_type(VarnodeType::Memory);
        assert_eq!(model.selected_type(), VarnodeType::Memory);
        assert_eq!(model.selected_index(), 2);
    }

    #[test]
    fn test_varnode_type_editor_model_set_by_index() {
        let mut model = VarnodeTypeCellEditorModel::new();
        model.set_selected_index(1);
        assert_eq!(model.selected_type(), VarnodeType::Stack);
    }

    #[test]
    fn test_varnode_type_editor_model_invalid_index() {
        let mut model = VarnodeTypeCellEditorModel::new();
        model.set_selected_index(99);
        // Should not change
        assert_eq!(model.selected_type(), VarnodeType::Register);
    }

    // -- VarnodeSizeCellEditorModel --

    #[test]
    fn test_varnode_size_editor_model() {
        let model = VarnodeSizeCellEditorModel::new();
        assert_eq!(model.current_size(), 1);
        assert_eq!(model.min_size(), 1);
        assert_eq!(model.max_size(), 512);
    }

    #[test]
    fn test_varnode_size_editor_model_with_bounds() {
        let model = VarnodeSizeCellEditorModel::with_bounds(8, 1, 16);
        assert_eq!(model.current_size(), 8);
    }

    #[test]
    fn test_varnode_size_editor_model_set_clamping() {
        let mut model = VarnodeSizeCellEditorModel::with_bounds(4, 1, 16);
        model.set_current_size(0);
        assert_eq!(model.current_size(), 1);
        model.set_current_size(100);
        assert_eq!(model.current_size(), 16);
    }

    #[test]
    fn test_varnode_size_editor_model_validate() {
        let model = VarnodeSizeCellEditorModel::with_bounds(4, 1, 16);
        assert!(model.validate(1).is_ok());
        assert!(model.validate(16).is_ok());
        assert!(model.validate(0).is_err());
        assert!(model.validate(17).is_err());
    }

    #[test]
    fn test_varnode_size_editor_model_parse() {
        let model = VarnodeSizeCellEditorModel::new();
        assert_eq!(model.parse_size("8").unwrap(), 8);
        assert_eq!(model.parse_size("0x10").unwrap(), 16);
        assert_eq!(model.parse_size(" 4 ").unwrap(), 4);
        assert!(model.parse_size("abc").is_err());
    }

    // -- VarnodeLocationRendererModel --

    #[test]
    fn test_render_location_register() {
        let vn = VarnodeInfo::register("RAX", 8);
        assert_eq!(VarnodeLocationRendererModel::render_location(&vn), "RAX");
    }

    #[test]
    fn test_render_location_stack() {
        let vn = VarnodeInfo::stack(-8, 4);
        assert_eq!(VarnodeLocationRendererModel::render_location(&vn), "Stack[-8]");
    }

    #[test]
    fn test_render_location_memory() {
        let vn = VarnodeInfo::memory(0x100000, 8);
        assert_eq!(
            VarnodeLocationRendererModel::render_location(&vn),
            "0x100000"
        );
    }

    #[test]
    fn test_render_type() {
        let vn = VarnodeInfo::register("RAX", 8);
        assert_eq!(VarnodeLocationRendererModel::render_type(&vn), "Register");
    }

    #[test]
    fn test_render_size() {
        let vn = VarnodeInfo::register("RAX", 8);
        assert_eq!(VarnodeLocationRendererModel::render_size(&vn), "8");
    }

    #[test]
    fn test_render_row() {
        let vn = VarnodeInfo::register("RAX", 8);
        let row = VarnodeLocationRendererModel::render_row(&vn);
        assert_eq!(row.len(), 3);
        assert_eq!(row[0], "Register");
        assert_eq!(row[1], "RAX");
        assert_eq!(row[2], "8");
    }

    // -- VarnodeLocationCellEditorModel --

    #[test]
    fn test_location_editor_register() {
        let vn = VarnodeInfo::register("RAX", 8);
        let model = VarnodeLocationCellEditorModel::new(vn);
        assert_eq!(model.edit_text(), "RAX");
        assert_eq!(model.varnode().name(), "RAX");
    }

    #[test]
    fn test_location_editor_apply_register() {
        let vn = VarnodeInfo::register("RAX", 8);
        let mut model = VarnodeLocationCellEditorModel::new(vn);
        model.set_edit_text("RBX");
        let new_vn = model.apply().unwrap();
        assert_eq!(new_vn.name(), "RBX");
        assert_eq!(new_vn.size(), 8);
    }

    #[test]
    fn test_location_editor_apply_stack() {
        let vn = VarnodeInfo::stack(-8, 4);
        let mut model = VarnodeLocationCellEditorModel::new(vn);
        model.set_edit_text("-16");
        let new_vn = model.apply().unwrap();
        assert_eq!(new_vn.offset(), -16);
    }

    #[test]
    fn test_location_editor_apply_memory() {
        let vn = VarnodeInfo::memory(0x100000, 8);
        let mut model = VarnodeLocationCellEditorModel::new(vn);
        model.set_edit_text("0x200000");
        let new_vn = model.apply().unwrap();
        assert_eq!(new_vn.offset(), 0x200000);
    }

    #[test]
    fn test_location_editor_validate_register_empty() {
        let vn = VarnodeInfo::register("RAX", 8);
        let mut model = VarnodeLocationCellEditorModel::new(vn);
        model.set_edit_text("");
        assert!(model.validate().is_err());
    }

    #[test]
    fn test_location_editor_validate_stack_invalid() {
        let vn = VarnodeInfo::stack(0, 4);
        let mut model = VarnodeLocationCellEditorModel::new(vn);
        model.set_edit_text("abc");
        assert!(model.validate().is_err());
    }

    #[test]
    fn test_location_editor_validate_memory_invalid() {
        let vn = VarnodeInfo::memory(0, 8);
        let mut model = VarnodeLocationCellEditorModel::new(vn);
        model.set_edit_text("not_an_address");
        assert!(model.validate().is_err());
    }
}
