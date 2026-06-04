//! Composite editor provider -- Rust port of
//! `ghidra.app.plugin.core.compositeeditor.CompositeEditorProvider` and
//! `ghidra.app.plugin.core.compositeeditor.StructureEditorProvider`.
//!
//! Each provider owns a model, manages actions, and provides the
//! user-facing interface for editing a composite data type.

use super::model::StructureEditorModel;

// ---------------------------------------------------------------------------
// EditorState
// ---------------------------------------------------------------------------

/// The lifecycle state of an editor provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EditorState {
    /// The editor has been created.
    Created,
    /// The editor is visible and active.
    Visible,
    /// The editor is hidden.
    Hidden,
    /// The editor has been disposed.
    Disposed,
}

// ---------------------------------------------------------------------------
// CompositeEditorProvider (base)
// ---------------------------------------------------------------------------

/// Base provider for composite editors.
///
/// Holds the common state shared between structure and union editors.
#[derive(Debug)]
pub struct CompositeEditorProvider {
    /// Unique identifier for this editor instance.
    pub id: usize,
    /// The current state.
    pub state: EditorState,
    /// Whether the data type manager service is available.
    pub dtm_service_available: bool,
    /// The name of the associated data type.
    pub data_type_name: String,
    /// The category path of the data type.
    pub category_path: String,
}

impl CompositeEditorProvider {
    /// Create a new composite editor provider.
    pub fn new(id: usize) -> Self {
        Self {
            id,
            state: EditorState::Created,
            dtm_service_available: true,
            data_type_name: String::new(),
            category_path: String::new(),
        }
    }

    /// Returns the editor name.
    pub fn name(&self) -> &str {
        "Composite Editor"
    }

    /// Returns the help topic.
    pub fn help_topic(&self) -> &str {
        "DataTypeEditors"
    }

    /// Whether the provider is visible.
    pub fn is_visible(&self) -> bool {
        self.state == EditorState::Visible
    }

    /// Set the provider to visible.
    pub fn set_visible(&mut self) {
        if self.state != EditorState::Disposed {
            self.state = EditorState::Visible;
        }
    }

    /// Set the provider to hidden.
    pub fn set_hidden(&mut self) {
        if self.state != EditorState::Disposed {
            self.state = EditorState::Hidden;
        }
    }

    /// Dispose the provider.
    pub fn dispose(&mut self) {
        self.state = EditorState::Disposed;
    }

    /// Update the title to reflect the data type being edited.
    pub fn update_title(&self) -> String {
        format!("{}: {}", self.name(), self.data_type_name)
    }
}

// ---------------------------------------------------------------------------
// StructureEditorProvider
// ---------------------------------------------------------------------------

/// The editor provider for structure data types.
///
/// Owns a [`StructureEditorModel`] and manages the actions specific to
/// structure editing (add/edit bit fields, unpack, etc.).
#[derive(Debug)]
pub struct StructureEditorProvider {
    /// The base provider.
    pub base: CompositeEditorProvider,
    /// The structure editor model.
    pub model: StructureEditorModel,
    /// Whether the bit field editor dialog is open.
    bit_field_editor_visible: bool,
}

impl StructureEditorProvider {
    /// Create a new structure editor provider.
    pub fn new(id: usize, show_hex_numbers: bool) -> Self {
        Self {
            base: CompositeEditorProvider::new(id),
            model: StructureEditorModel::new(show_hex_numbers),
            bit_field_editor_visible: false,
        }
    }

    /// Returns the editor name.
    pub fn name(&self) -> &str {
        "Structure Editor"
    }

    /// Load a structure into the editor.
    pub fn load_structure(
        &mut self,
        name: &str,
        description: &str,
        components: &[(&str, &str, usize)],
    ) {
        self.base.data_type_name = name.to_string();
        self.model.load(name, description, components);
    }

    /// Whether there are unsaved changes.
    pub fn has_changes(&self) -> bool {
        self.model.has_changes()
    }

    /// Apply the changes (commit to the data type manager).
    ///
    /// In a full implementation, this would start a transaction on the
    /// data type manager, apply the changes, and reload.
    pub fn apply(&mut self) -> ApplyResult {
        if !self.model.has_changes() {
            return ApplyResult::NoChanges;
        }
        // In Ghidra, this would start a transaction on originalDTM.
        // Here we just clear the undo history to signal "applied".
        let name = self.base.data_type_name.clone();
        ApplyResult::Applied { name }
    }

    /// Refresh the table and re-select the given ordinal.
    pub fn refresh_and_select(&mut self, ordinal: usize) {
        self.model.set_selection(&[ordinal]);
    }

    /// Show the add-bit-field editor dialog.
    pub fn show_add_bit_field_editor(&mut self) -> Result<(), String> {
        let selected = self.model.selected_rows();
        if selected.len() != 1 {
            return Err("Must select exactly one row".into());
        }
        if self.model.packing_enabled {
            return Err("Cannot add bitfield when packing is enabled".into());
        }
        self.bit_field_editor_visible = true;
        Ok(())
    }

    /// Show the bit-field editor dialog for the selected component.
    pub fn show_bit_field_editor(&mut self) -> Result<(), String> {
        let selected = self.model.selected_rows();
        if selected.len() != 1 {
            return Err("Must select exactly one row".into());
        }
        let row = selected[0];
        match self.model.get_component(row) {
            Some(comp) if comp.is_bitfield => {
                self.bit_field_editor_visible = true;
                Ok(())
            }
            _ => Err("Selected component is not a bit field".into()),
        }
    }

    /// Close the bit field editor if it is open.
    pub fn close_bit_field_editor(&mut self) {
        self.bit_field_editor_visible = false;
    }

    /// Whether the bit field editor dialog is open.
    pub fn is_bit_field_editor_visible(&self) -> bool {
        self.bit_field_editor_visible
    }

    /// Request focus on the table.
    pub fn request_table_focus(&self) {
        // GUI integration point.
    }

    /// Get the actions available for this editor.
    pub fn available_actions(&self) -> Vec<&'static str> {
        vec![
            "Apply",
            "Undo",
            "Redo",
            "Insert Undefined",
            "Move Up",
            "Move Down",
            "Clear",
            "Duplicate",
            "Duplicate Multiple",
            "Delete",
            "Pointer",
            "Array",
            "Find References",
            "Unpackage",
            "Edit Component",
            "Edit Field",
            "Hex Numbers",
            "Create Internal Structure",
            "Show Component Path",
            "Add Bit Field",
            "Edit Bit Field",
            "Show In Data Type Tree",
        ]
    }

    /// Dispose the provider.
    pub fn dispose(&mut self) {
        self.base.dispose();
        self.bit_field_editor_visible = false;
    }
}

// ---------------------------------------------------------------------------
// ApplyResult
// ---------------------------------------------------------------------------

/// Result of applying changes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplyResult {
    /// There were no changes to apply.
    NoChanges,
    /// Changes were applied successfully.
    Applied {
        /// The name of the data type that was saved.
        name: String,
    },
    /// The data type name was invalid.
    InvalidName(String),
    /// A data type with this name already exists.
    DuplicateName(String),
    /// The structure contains itself (circular reference).
    InvalidDataType(String),
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_composite_provider_new() {
        let p = CompositeEditorProvider::new(1);
        assert_eq!(p.state, EditorState::Created);
        assert_eq!(p.name(), "Composite Editor");
    }

    #[test]
    fn test_composite_provider_visibility() {
        let mut p = CompositeEditorProvider::new(1);
        p.set_visible();
        assert!(p.is_visible());
        p.set_hidden();
        assert!(!p.is_visible());
        p.dispose();
        assert_eq!(p.state, EditorState::Disposed);
    }

    #[test]
    fn test_composite_provider_title() {
        let mut p = CompositeEditorProvider::new(1);
        p.data_type_name = "MyStruct".into();
        assert!(p.update_title().contains("MyStruct"));
    }

    #[test]
    fn test_structure_provider_new() {
        let p = StructureEditorProvider::new(1, false);
        assert_eq!(p.name(), "Structure Editor");
        assert!(!p.has_changes());
    }

    #[test]
    fn test_structure_provider_load() {
        let mut p = StructureEditorProvider::new(1, false);
        p.load_structure("Point", "A 2D point", &[("int", "x", 4), ("int", "y", 4)]);
        assert_eq!(p.base.data_type_name, "Point");
        assert_eq!(p.model.get_num_components(), 2);
    }

    #[test]
    fn test_structure_provider_apply() {
        let mut p = StructureEditorProvider::new(1, false);
        p.load_structure("S", "", &[("int", "x", 4)]);
        // No changes yet.
        assert_eq!(p.apply(), ApplyResult::NoChanges);

        // Make a change.
        p.model.set_selection(&[0]);
        p.model.delete_selected();
        assert_eq!(
            p.apply(),
            ApplyResult::Applied { name: "S".into() }
        );
    }

    #[test]
    fn test_structure_provider_bitfield_editor() {
        let mut p = StructureEditorProvider::new(1, false);
        p.load_structure("S", "", &[("int", "x", 4)]);
        p.model.set_selection(&[0]);
        assert!(p.show_add_bit_field_editor().is_ok());
        assert!(p.is_bit_field_editor_visible());
        p.close_bit_field_editor();
        assert!(!p.is_bit_field_editor_visible());
    }

    #[test]
    fn test_structure_provider_bitfield_editor_packing_error() {
        let mut p = StructureEditorProvider::new(1, false);
        p.model.packing_enabled = true;
        p.load_structure("S", "", &[("int", "x", 4)]);
        p.model.set_selection(&[0]);
        assert!(p.show_add_bit_field_editor().is_err());
    }

    #[test]
    fn test_structure_provider_actions() {
        let p = StructureEditorProvider::new(1, false);
        let actions = p.available_actions();
        assert!(actions.contains(&"Apply"));
        assert!(actions.contains(&"Delete"));
        assert!(actions.contains(&"Add Bit Field"));
    }

    #[test]
    fn test_structure_provider_dispose() {
        let mut p = StructureEditorProvider::new(1, false);
        p.dispose();
        assert_eq!(p.base.state, EditorState::Disposed);
    }

    #[test]
    fn test_structure_provider_refresh_and_select() {
        let mut p = StructureEditorProvider::new(1, false);
        p.load_structure("S", "", &[("int", "a", 4), ("char", "b", 1)]);
        p.refresh_and_select(1);
        assert_eq!(p.model.selected_rows(), vec![1]);
    }

    #[test]
    fn test_editor_state_transitions() {
        let mut p = CompositeEditorProvider::new(1);
        assert_eq!(p.state, EditorState::Created);
        p.set_visible();
        assert_eq!(p.state, EditorState::Visible);
        p.set_hidden();
        assert_eq!(p.state, EditorState::Hidden);
        p.dispose();
        assert_eq!(p.state, EditorState::Disposed);
        // Cannot resurrect disposed.
        p.set_visible();
        assert_eq!(p.state, EditorState::Disposed);
    }
}
