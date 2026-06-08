//! Union editor model -- Rust port of
//! `ghidra.app.plugin.core.compositeeditor.UnionEditorModel`.
//!
//! The model specific to union editing. Unions are like structures but
//! all components share offset 0 (each occupies the full union size).

use super::composite_model::{CompositeEditorModel, ViewComponent};

// ---------------------------------------------------------------------------
// UnionEditorModel
// ---------------------------------------------------------------------------

/// The model for the union data type editor.
///
/// Extends the base [`CompositeEditorModel`] with operations specific to
/// unions. In a union, all fields start at offset 0 and the total size
/// is the maximum component size. Reordering is less critical than in
/// structures because layout is implicit.
#[derive(Debug)]
pub struct UnionEditorModel {
    /// The base composite model.
    pub base: CompositeEditorModel,
}

impl UnionEditorModel {
    /// Column index for "Offset" (always 0 for unions).
    pub const OFFSET: usize = 0;
    /// Column index for "Length".
    pub const LENGTH: usize = 1;
    /// Column index for "DataType".
    pub const DATATYPE: usize = 3;
    /// Column index for "Name".
    pub const FIELDNAME: usize = 4;

    /// Create a new union editor model.
    pub fn new(show_hex_numbers: bool) -> Self {
        let mut base = CompositeEditorModel::new();
        base.show_hex_numbers = show_hex_numbers;
        Self { base }
    }

    /// Returns the type name ("Union").
    pub fn type_name(&self) -> &str {
        "Union"
    }

    /// Get the total length of the union.
    ///
    /// For a union, the length is the maximum component length.
    pub fn get_length(&self) -> usize {
        self.base.components.iter().map(|c| c.length).max().unwrap_or(0)
    }

    /// Get the number of components.
    pub fn get_num_components(&self) -> usize {
        self.base.num_components()
    }

    /// Get the component at the given row index.
    pub fn get_component(&self, row_index: usize) -> Option<&ViewComponent> {
        self.base.get_component(row_index)
    }

    /// Whether the union has changes.
    pub fn has_changes(&self) -> bool {
        self.base.has_changes()
    }

    /// Set the selection.
    pub fn set_selection(&mut self, rows: &[usize]) {
        self.base.set_selection(rows);
    }

    /// Get the selected rows.
    pub fn selected_rows(&self) -> Vec<usize> {
        self.base.selected_rows()
    }

    /// Toggle hex number display.
    pub fn toggle_hex_numbers(&mut self) {
        self.base.toggle_hex_numbers();
    }

    /// Clear the currently selected components.
    pub fn clear_selected(&mut self) -> Vec<usize> {
        let rows = self.base.selected_rows();
        self.base.push_undo();
        for &row in rows.iter().rev() {
            self.base.clear_component(row);
        }
        rows
    }

    /// Delete the currently selected components.
    pub fn delete_selected(&mut self) -> Vec<usize> {
        let rows = self.base.selected_rows();
        self.base.push_undo();
        for &row in rows.iter().rev() {
            self.base.remove_component(row);
        }
        rows
    }

    /// Add a component to the union.
    ///
    /// In a union, the new component always goes at the end with offset 0.
    pub fn add_component(
        &mut self,
        data_type_name: &str,
        field_name: &str,
        length: usize,
    ) {
        self.base.push_undo();
        let ordinal = self.base.num_components();
        let comp = ViewComponent::new(
            ordinal,
            0, // All union members at offset 0
            length,
            data_type_name,
            data_type_name,
            field_name,
            "",
        );
        self.base.components.push(comp);
    }

    /// Duplicate the component at the given index.
    pub fn duplicate(&mut self, index: usize) -> bool {
        self.base.push_undo();
        self.base.duplicate_component(index)
    }

    /// Load from a union definition.
    pub fn load(&mut self, name: &str, description: &str, components: &[(&str, &str, usize)]) {
        self.base.composite_name = name.to_string();
        self.base.composite_description = description.to_string();
        self.base.components.clear();
        for (i, &(dt_name, field_name, length)) in components.iter().enumerate() {
            self.base.components.push(ViewComponent::new(
                i, 0, length, dt_name, dt_name, field_name, "",
            ));
        }
        self.base.selection.clear();
    }

    /// Undo the last change.
    pub fn undo(&mut self) -> bool {
        self.base.undo()
    }

    /// Redo the last undone change.
    pub fn redo(&mut self) -> bool {
        self.base.redo()
    }
}

// ---------------------------------------------------------------------------
// UnionEditorProvider
// ---------------------------------------------------------------------------

/// The editor provider for union data types.
///
/// Owns a [`UnionEditorModel`] and manages the actions specific to
/// union editing.
#[derive(Debug)]
pub struct UnionEditorProvider {
    /// Unique identifier for this editor instance.
    pub id: usize,
    /// The union editor model.
    pub model: UnionEditorModel,
    /// The data type name.
    pub data_type_name: String,
    /// The category path.
    pub category_path: String,
    /// Whether the provider is visible.
    visible: bool,
    /// Whether the provider has been disposed.
    disposed: bool,
}

impl UnionEditorProvider {
    /// Create a new union editor provider.
    pub fn new(id: usize, show_hex_numbers: bool) -> Self {
        Self {
            id,
            model: UnionEditorModel::new(show_hex_numbers),
            data_type_name: String::new(),
            category_path: String::new(),
            visible: false,
            disposed: false,
        }
    }

    /// Returns the editor name.
    pub fn name(&self) -> &str {
        "Union Editor"
    }

    /// Load a union into the editor.
    pub fn load_union(
        &mut self,
        name: &str,
        description: &str,
        components: &[(&str, &str, usize)],
    ) {
        self.data_type_name = name.to_string();
        self.model.load(name, description, components);
    }

    /// Whether there are unsaved changes.
    pub fn has_changes(&self) -> bool {
        self.model.has_changes()
    }

    /// Whether the provider is visible.
    pub fn is_visible(&self) -> bool {
        self.visible && !self.disposed
    }

    /// Set the provider to visible.
    pub fn set_visible(&mut self) {
        if !self.disposed {
            self.visible = true;
        }
    }

    /// Hide the provider.
    pub fn set_hidden(&mut self) {
        if !self.disposed {
            self.visible = false;
        }
    }

    /// Dispose the provider.
    pub fn dispose(&mut self) {
        self.disposed = true;
        self.visible = false;
    }

    /// Get the actions available for this editor.
    pub fn available_actions(&self) -> Vec<&'static str> {
        vec![
            "Apply",
            "Undo",
            "Redo",
            "Insert Undefined",
            "Clear",
            "Delete",
            "Duplicate",
            "Pointer",
            "Array",
            "Hex Numbers",
            "Find References",
        ]
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_union_model_new() {
        let model = UnionEditorModel::new(false);
        assert_eq!(model.type_name(), "Union");
    }

    #[test]
    fn test_union_model_load() {
        let mut model = UnionEditorModel::new(false);
        model.load("MyUnion", "test union", &[
            ("int", "i", 4),
            ("float", "f", 4),
            ("char", "buf", 8),
        ]);
        assert_eq!(model.get_num_components(), 3);
        // Union length = max component = 8
        assert_eq!(model.get_length(), 8);
    }

    #[test]
    fn test_union_model_add_component() {
        let mut model = UnionEditorModel::new(false);
        model.add_component("int", "x", 4);
        assert_eq!(model.get_num_components(), 1);
        assert_eq!(model.get_component(0).unwrap().offset, 0);
        assert_eq!(model.get_component(0).unwrap().field_name, "x");
    }

    #[test]
    fn test_union_model_add_multiple() {
        let mut model = UnionEditorModel::new(false);
        model.add_component("int", "i", 4);
        model.add_component("float", "f", 4);
        // Both at offset 0
        assert_eq!(model.get_component(0).unwrap().offset, 0);
        assert_eq!(model.get_component(1).unwrap().offset, 0);
    }

    #[test]
    fn test_union_model_delete_selected() {
        let mut model = UnionEditorModel::new(false);
        model.load("U", "", &[("int", "a", 4), ("char", "b", 1)]);
        model.set_selection(&[0]);
        model.delete_selected();
        assert_eq!(model.get_num_components(), 1);
    }

    #[test]
    fn test_union_model_clear_selected() {
        let mut model = UnionEditorModel::new(false);
        model.load("U", "", &[("int", "x", 4)]);
        model.set_selection(&[0]);
        model.clear_selected();
        assert_eq!(model.get_component(0).unwrap().data_type_name, "undefined");
    }

    #[test]
    fn test_union_model_duplicate() {
        let mut model = UnionEditorModel::new(false);
        model.load("U", "", &[("int", "x", 4)]);
        assert!(model.duplicate(0));
        assert_eq!(model.get_num_components(), 2);
    }

    #[test]
    fn test_union_model_undo_redo() {
        let mut model = UnionEditorModel::new(false);
        model.load("U", "", &[("int", "x", 4)]);
        model.delete_selected();
        assert!(model.undo());
        assert!(model.redo());
    }

    #[test]
    fn test_union_model_empty_length() {
        let model = UnionEditorModel::new(false);
        assert_eq!(model.get_length(), 0);
    }

    #[test]
    fn test_union_model_hex_toggle() {
        let mut model = UnionEditorModel::new(false);
        model.load("U", "", &[("int", "x", 255)]);
        model.toggle_hex_numbers();
        assert!(model.base.show_hex_numbers);
    }

    #[test]
    fn test_union_provider_new() {
        let p = UnionEditorProvider::new(1, false);
        assert_eq!(p.name(), "Union Editor");
        assert!(!p.has_changes());
        assert!(!p.is_visible());
    }

    #[test]
    fn test_union_provider_load() {
        let mut p = UnionEditorProvider::new(1, false);
        p.load_union("Value", "A union value", &[
            ("int", "i", 4),
            ("float", "f", 4),
        ]);
        assert_eq!(p.data_type_name, "Value");
        assert_eq!(p.model.get_num_components(), 2);
    }

    #[test]
    fn test_union_provider_visibility() {
        let mut p = UnionEditorProvider::new(1, false);
        p.set_visible();
        assert!(p.is_visible());
        p.set_hidden();
        assert!(!p.is_visible());
    }

    #[test]
    fn test_union_provider_dispose() {
        let mut p = UnionEditorProvider::new(1, false);
        p.set_visible();
        p.dispose();
        assert!(!p.is_visible());
    }

    #[test]
    fn test_union_provider_actions() {
        let p = UnionEditorProvider::new(1, false);
        let actions = p.available_actions();
        assert!(actions.contains(&"Apply"));
        assert!(actions.contains(&"Delete"));
    }
}
