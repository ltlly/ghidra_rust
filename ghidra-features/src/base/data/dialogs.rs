//! Data plugin dialogs -- ported from `CreateStructureDialog.java`,
//! `EditDataFieldDialog.java`, `RenameDataFieldDialog.java`.
//!
//! These types model the dialog state and logic for creating structures,
//! editing data fields, and renaming data fields.  Actual rendering is
//! in the GUI layer.

use std::fmt;

use ghidra_core::addr::Address;

// ---------------------------------------------------------------------------
// StructureFieldInfo
// ---------------------------------------------------------------------------

/// Information about a field in a structure being created or edited.
///
/// Ported from the field model used by `CreateStructureDialog`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructureFieldInfo {
    /// The field name (e.g., "field_0", "size").
    pub name: Option<String>,
    /// The data type name.
    pub data_type_name: String,
    /// The size in bytes.
    pub size: usize,
    /// The offset within the structure.
    pub offset: usize,
    /// Whether this field is currently selected in the dialog.
    pub is_selected: bool,
    /// Whether this field has been edited.
    pub is_modified: bool,
}

impl StructureFieldInfo {
    /// Creates a new field info.
    pub fn new(
        name: Option<String>,
        data_type_name: impl Into<String>,
        size: usize,
        offset: usize,
    ) -> Self {
        Self {
            name,
            data_type_name: data_type_name.into(),
            size,
            offset,
            is_selected: false,
            is_modified: false,
        }
    }

    /// Returns the display name for this field.
    pub fn display_name(&self) -> &str {
        self.name.as_deref().unwrap_or("<unnamed>")
    }

    /// Returns the end offset (exclusive) of this field.
    pub fn end_offset(&self) -> usize {
        self.offset + self.size
    }
}

// ---------------------------------------------------------------------------
// CreateStructureDialogModel
// ---------------------------------------------------------------------------

/// Model for the Create Structure dialog.
///
/// Ported from `CreateStructureDialog.java`.  In Ghidra this dialog
/// lets the user create a structure from a selection and optionally
/// match it against existing types.
///
/// # Example
///
/// ```
/// use ghidra_features::base::data::dialogs::CreateStructureDialogModel;
///
/// let mut dialog = CreateStructureDialogModel::new("Create Structure");
/// dialog.add_field(None, "byte", 1, 0);
/// dialog.add_field(None, "byte", 1, 1);
/// dialog.add_field(None, "word", 2, 2);
/// assert_eq!(dialog.field_count(), 3);
/// assert_eq!(dialog.total_size(), 4);
/// ```
#[derive(Debug, Clone)]
pub struct CreateStructureDialogModel {
    /// Dialog title.
    title: String,
    /// The fields of the structure being created.
    fields: Vec<StructureFieldInfo>,
    /// Whether the dialog was accepted.
    accepted: bool,
    /// Whether the structure should replace the existing data.
    replace_existing: bool,
    /// The name entered by the user, if any.
    structure_name: Option<String>,
    /// The namespace for the structure, if any.
    namespace: Option<String>,
    /// Whether to use the default name.
    use_default_name: bool,
}

impl CreateStructureDialogModel {
    /// Creates a new dialog model.
    pub fn new(title: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            fields: Vec::new(),
            accepted: false,
            replace_existing: false,
            structure_name: None,
            namespace: None,
            use_default_name: true,
        }
    }

    /// Returns the dialog title.
    pub fn title(&self) -> &str {
        &self.title
    }

    /// Adds a field to the structure.
    pub fn add_field(
        &mut self,
        name: Option<String>,
        data_type_name: &str,
        size: usize,
        offset: usize,
    ) {
        self.fields.push(StructureFieldInfo::new(name, data_type_name, size, offset));
    }

    /// Returns the fields.
    pub fn fields(&self) -> &[StructureFieldInfo] {
        &self.fields
    }

    /// Returns a mutable reference to the fields.
    pub fn fields_mut(&mut self) -> &mut Vec<StructureFieldInfo> {
        &mut self.fields
    }

    /// Returns the number of fields.
    pub fn field_count(&self) -> usize {
        self.fields.len()
    }

    /// Returns the total size of the structure (offset of last field + size).
    pub fn total_size(&self) -> usize {
        self.fields
            .iter()
            .map(|f| f.end_offset())
            .max()
            .unwrap_or(0)
    }

    /// Sets whether the dialog was accepted.
    pub fn set_accepted(&mut self, accepted: bool) {
        self.accepted = accepted;
    }

    /// Returns whether the dialog was accepted.
    pub fn is_accepted(&self) -> bool {
        self.accepted
    }

    /// Sets whether to replace existing data.
    pub fn set_replace_existing(&mut self, replace: bool) {
        self.replace_existing = replace;
    }

    /// Returns whether to replace existing data.
    pub fn replace_existing(&self) -> bool {
        self.replace_existing
    }

    /// Sets the structure name.
    pub fn set_structure_name(&mut self, name: Option<String>) {
        self.use_default_name = name.is_none();
        self.structure_name = name;
    }

    /// Returns the structure name.
    pub fn structure_name(&self) -> Option<&str> {
        self.structure_name.as_deref()
    }

    /// Sets the namespace.
    pub fn set_namespace(&mut self, ns: Option<String>) {
        self.namespace = ns;
    }

    /// Returns the namespace.
    pub fn namespace(&self) -> Option<&str> {
        self.namespace.as_deref()
    }

    /// Returns whether to use the default name.
    pub fn uses_default_name(&self) -> bool {
        self.use_default_name
    }
}

// ---------------------------------------------------------------------------
// EditDataFieldDialogModel
// ---------------------------------------------------------------------------

/// Model for the Edit Data Field dialog.
///
/// Ported from `EditDataFieldDialog.java`.  Allows the user to change
/// the data type of a specific field within a structure.
///
/// # Example
///
/// ```
/// use ghidra_features::base::data::dialogs::EditDataFieldDialogModel;
///
/// let mut dialog = EditDataFieldDialogModel::new("word", 2);
/// assert_eq!(dialog.current_type(), "word");
/// assert_eq!(dialog.current_size(), 2);
/// dialog.set_new_type("dword");
/// dialog.set_new_size(4);
/// assert!(dialog.has_changes());
/// ```
#[derive(Debug, Clone)]
pub struct EditDataFieldDialogModel {
    /// The current data type name.
    current_type: String,
    /// The current size in bytes.
    current_size: usize,
    /// The new data type name (set by user).
    new_type: Option<String>,
    /// The new size in bytes (set by user).
    new_size: Option<usize>,
    /// Whether the dialog was accepted.
    accepted: bool,
    /// The component path for the field being edited.
    component_path: Vec<usize>,
}

impl EditDataFieldDialogModel {
    /// Creates a new edit data field dialog model.
    pub fn new(current_type: impl Into<String>, current_size: usize) -> Self {
        Self {
            current_type: current_type.into(),
            current_size,
            new_type: None,
            new_size: None,
            accepted: false,
            component_path: Vec::new(),
        }
    }

    /// Returns the current data type name.
    pub fn current_type(&self) -> &str {
        &self.current_type
    }

    /// Returns the current size in bytes.
    pub fn current_size(&self) -> usize {
        self.current_size
    }

    /// Sets the new data type.
    pub fn set_new_type(&mut self, type_name: impl Into<String>) {
        self.new_type = Some(type_name.into());
    }

    /// Returns the new data type name, if set.
    pub fn new_type(&self) -> Option<&str> {
        self.new_type.as_deref()
    }

    /// Sets the new size.
    pub fn set_new_size(&mut self, size: usize) {
        self.new_size = Some(size);
    }

    /// Returns the new size, if set.
    pub fn new_size(&self) -> Option<usize> {
        self.new_size
    }

    /// Returns `true` if the user has made changes.
    pub fn has_changes(&self) -> bool {
        self.new_type.is_some() || self.new_size.is_some()
    }

    /// Sets whether the dialog was accepted.
    pub fn set_accepted(&mut self, accepted: bool) {
        self.accepted = accepted;
    }

    /// Returns whether the dialog was accepted.
    pub fn is_accepted(&self) -> bool {
        self.accepted
    }

    /// Sets the component path.
    pub fn set_component_path(&mut self, path: Vec<usize>) {
        self.component_path = path;
    }

    /// Returns the component path.
    pub fn component_path(&self) -> &[usize] {
        &self.component_path
    }
}

// ---------------------------------------------------------------------------
// RenameDataFieldDialogModel
// ---------------------------------------------------------------------------

/// Model for the Rename Data Field dialog.
///
/// Ported from `RenameDataFieldDialog.java`.  Allows the user to
/// rename a field within a structure.
///
/// # Example
///
/// ```
/// use ghidra_features::base::data::dialogs::RenameDataFieldDialogModel;
///
/// let mut dialog = RenameDataFieldDialogModel::new("field_0");
/// assert_eq!(dialog.current_name(), "field_0");
/// dialog.set_new_name("size");
/// assert!(dialog.has_changes());
/// ```
#[derive(Debug, Clone)]
pub struct RenameDataFieldDialogModel {
    /// The current field name.
    current_name: String,
    /// The new name (set by user).
    new_name: Option<String>,
    /// Whether the dialog was accepted.
    accepted: bool,
    /// The component path for the field.
    component_path: Vec<usize>,
}

impl RenameDataFieldDialogModel {
    /// Creates a new rename data field dialog model.
    pub fn new(current_name: impl Into<String>) -> Self {
        Self {
            current_name: current_name.into(),
            new_name: None,
            accepted: false,
            component_path: Vec::new(),
        }
    }

    /// Returns the current field name.
    pub fn current_name(&self) -> &str {
        &self.current_name
    }

    /// Sets the new name.
    pub fn set_new_name(&mut self, name: impl Into<String>) {
        self.new_name = Some(name.into());
    }

    /// Returns the new name, if set.
    pub fn new_name(&self) -> Option<&str> {
        self.new_name.as_deref()
    }

    /// Returns `true` if the user has made changes.
    pub fn has_changes(&self) -> bool {
        self.new_name.is_some()
            && self.new_name.as_deref() != Some(self.current_name.as_str())
    }

    /// Sets whether the dialog was accepted.
    pub fn set_accepted(&mut self, accepted: bool) {
        self.accepted = accepted;
    }

    /// Returns whether the dialog was accepted.
    pub fn is_accepted(&self) -> bool {
        self.accepted
    }

    /// Sets the component path.
    pub fn set_component_path(&mut self, path: Vec<usize>) {
        self.component_path = path;
    }

    /// Returns the component path.
    pub fn component_path(&self) -> &[usize] {
        &self.component_path
    }
}

// ---------------------------------------------------------------------------
// ArrayCreationModel
// ---------------------------------------------------------------------------

/// Model for the Create Array dialog.
///
/// This represents the user input for creating an array -- the number
/// of elements and the element data type.
#[derive(Debug, Clone)]
pub struct ArrayCreationModel {
    /// The element data type name.
    element_type: String,
    /// The element size in bytes.
    element_size: usize,
    /// The number of elements requested.
    num_elements: usize,
    /// The maximum number of elements that fit without overwriting.
    max_no_conflict: usize,
    /// The absolute maximum elements.
    max_elements: usize,
    /// Whether the dialog was accepted.
    accepted: bool,
}

impl ArrayCreationModel {
    /// Creates a new array creation model.
    pub fn new(
        element_type: impl Into<String>,
        element_size: usize,
        max_no_conflict: usize,
        max_elements: usize,
    ) -> Self {
        Self {
            element_type: element_type.into(),
            element_size,
            num_elements: max_no_conflict,
            max_no_conflict,
            max_elements,
            accepted: false,
        }
    }

    /// Returns the element type name.
    pub fn element_type(&self) -> &str {
        &self.element_type
    }

    /// Returns the element size.
    pub fn element_size(&self) -> usize {
        self.element_size
    }

    /// Returns the number of elements.
    pub fn num_elements(&self) -> usize {
        self.num_elements
    }

    /// Sets the number of elements.
    pub fn set_num_elements(&mut self, n: usize) {
        self.num_elements = n.min(self.max_elements);
    }

    /// Returns the max no-conflict elements.
    pub fn max_no_conflict(&self) -> usize {
        self.max_no_conflict
    }

    /// Returns the absolute max elements.
    pub fn max_elements(&self) -> usize {
        self.max_elements
    }

    /// Returns `true` if creating this array would overwrite existing data.
    pub fn would_overwrite(&self) -> bool {
        self.num_elements > self.max_no_conflict
    }

    /// Returns the total array size in bytes.
    pub fn total_size(&self) -> usize {
        self.num_elements * self.element_size
    }

    /// Sets whether the dialog was accepted.
    pub fn set_accepted(&mut self, accepted: bool) {
        self.accepted = accepted;
    }

    /// Returns whether the dialog was accepted.
    pub fn is_accepted(&self) -> bool {
        self.accepted
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- StructureFieldInfo tests --

    #[test]
    fn test_field_info() {
        let f = StructureFieldInfo::new(Some("size".into()), "dword", 4, 0);
        assert_eq!(f.display_name(), "size");
        assert_eq!(f.end_offset(), 4);
    }

    #[test]
    fn test_field_info_unnamed() {
        let f = StructureFieldInfo::new(None, "byte", 1, 0);
        assert_eq!(f.display_name(), "<unnamed>");
    }

    // -- CreateStructureDialogModel tests --

    #[test]
    fn test_create_structure_dialog() {
        let mut dialog = CreateStructureDialogModel::new("Create Structure");
        assert_eq!(dialog.title(), "Create Structure");
        assert_eq!(dialog.field_count(), 0);

        dialog.add_field(None, "byte", 1, 0);
        dialog.add_field(Some("value".into()), "dword", 4, 4);
        assert_eq!(dialog.field_count(), 2);
        assert_eq!(dialog.total_size(), 8);
    }

    #[test]
    fn test_create_structure_dialog_name() {
        let mut dialog = CreateStructureDialogModel::new("Create Structure");
        assert!(dialog.uses_default_name());
        assert!(dialog.structure_name().is_none());

        dialog.set_structure_name(Some("MyStruct".into()));
        assert_eq!(dialog.structure_name(), Some("MyStruct"));
        assert!(!dialog.uses_default_name());
    }

    #[test]
    fn test_create_structure_dialog_namespace() {
        let mut dialog = CreateStructureDialogModel::new("Create Structure");
        assert!(dialog.namespace().is_none());

        dialog.set_namespace(Some("std".into()));
        assert_eq!(dialog.namespace(), Some("std"));
    }

    #[test]
    fn test_create_structure_dialog_replace() {
        let mut dialog = CreateStructureDialogModel::new("Create Structure");
        assert!(!dialog.replace_existing());

        dialog.set_replace_existing(true);
        assert!(dialog.replace_existing());
    }

    #[test]
    fn test_create_structure_dialog_accepted() {
        let mut dialog = CreateStructureDialogModel::new("Create Structure");
        assert!(!dialog.is_accepted());

        dialog.set_accepted(true);
        assert!(dialog.is_accepted());
    }

    // -- EditDataFieldDialogModel tests --

    #[test]
    fn test_edit_data_field_dialog() {
        let mut dialog = EditDataFieldDialogModel::new("word", 2);
        assert_eq!(dialog.current_type(), "word");
        assert_eq!(dialog.current_size(), 2);
        assert!(!dialog.has_changes());

        dialog.set_new_type("dword");
        dialog.set_new_size(4);
        assert!(dialog.has_changes());
        assert_eq!(dialog.new_type(), Some("dword"));
        assert_eq!(dialog.new_size(), Some(4));
    }

    #[test]
    fn test_edit_data_field_dialog_component_path() {
        let mut dialog = EditDataFieldDialogModel::new("byte", 1);
        dialog.set_component_path(vec![0, 2]);
        assert_eq!(dialog.component_path(), &[0, 2]);
    }

    #[test]
    fn test_edit_data_field_dialog_accepted() {
        let mut dialog = EditDataFieldDialogModel::new("byte", 1);
        assert!(!dialog.is_accepted());
        dialog.set_accepted(true);
        assert!(dialog.is_accepted());
    }

    // -- RenameDataFieldDialogModel tests --

    #[test]
    fn test_rename_data_field_dialog() {
        let mut dialog = RenameDataFieldDialogModel::new("field_0");
        assert_eq!(dialog.current_name(), "field_0");
        assert!(!dialog.has_changes()); // no new name set yet

        dialog.set_new_name("size");
        assert!(dialog.has_changes());
        assert_eq!(dialog.new_name(), Some("size"));
    }

    #[test]
    fn test_rename_data_field_same_name() {
        let mut dialog = RenameDataFieldDialogModel::new("field_0");
        dialog.set_new_name("field_0");
        assert!(!dialog.has_changes()); // same name = no change
    }

    #[test]
    fn test_rename_data_field_dialog_accepted() {
        let mut dialog = RenameDataFieldDialogModel::new("field_0");
        assert!(!dialog.is_accepted());
        dialog.set_accepted(true);
        assert!(dialog.is_accepted());
    }

    // -- ArrayCreationModel tests --

    #[test]
    fn test_array_creation_model() {
        let model = ArrayCreationModel::new("byte", 1, 10, 20);
        assert_eq!(model.element_type(), "byte");
        assert_eq!(model.element_size(), 1);
        assert_eq!(model.num_elements(), 10);
        assert_eq!(model.max_no_conflict(), 10);
        assert_eq!(model.max_elements(), 20);
        assert!(!model.would_overwrite());
        assert_eq!(model.total_size(), 10);
    }

    #[test]
    fn test_array_creation_model_overwrite() {
        let mut model = ArrayCreationModel::new("byte", 1, 10, 20);
        model.set_num_elements(15);
        assert!(model.would_overwrite());
        assert_eq!(model.total_size(), 15);
    }

    #[test]
    fn test_array_creation_model_clamp() {
        let mut model = ArrayCreationModel::new("dword", 4, 10, 20);
        model.set_num_elements(100);
        assert_eq!(model.num_elements(), 20); // clamped to max
    }

    #[test]
    fn test_array_creation_model_accepted() {
        let mut model = ArrayCreationModel::new("byte", 1, 10, 20);
        assert!(!model.is_accepted());
        model.set_accepted(true);
        assert!(model.is_accepted());
    }
}
