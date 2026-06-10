//! Field list editor for composite data types.
//!
//! Ported from `ghidra.app.plugin.core.compositeeditor.FieldListEditor`.
//!
//! Provides the field list editing logic used by the composite editor panel
//! to manage individual components (fields) of a composite type, including
//! adding, removing, replacing, reordering, and validating fields.

use super::{ComponentRow, DataTypePath};

// ---------------------------------------------------------------------------
// Field edit operation
// ---------------------------------------------------------------------------

/// Operations that can be performed on a field list.
#[derive(Debug, Clone)]
pub enum FieldEditOp {
    /// Add a new field at the given position.
    Add {
        /// Position to insert at.
        at: usize,
        /// The type name for the new field.
        type_name: String,
        /// The field name.
        field_name: String,
    },
    /// Remove the field at the given position.
    Remove {
        /// Position of the field to remove.
        at: usize,
    },
    /// Replace the type of a field.
    ReplaceType {
        /// Position of the field.
        at: usize,
        /// New type name.
        new_type: String,
    },
    /// Replace the name of a field.
    ReplaceName {
        /// Position of the field.
        at: usize,
        /// New field name.
        new_name: String,
    },
    /// Move a field from one position to another.
    Move {
        /// Source position.
        from: usize,
        /// Destination position.
        to: usize,
    },
    /// Replace all fields.
    ReplaceAll {
        /// New field list.
        fields: Vec<ComponentRow>,
    },
}

// ---------------------------------------------------------------------------
// Field validation
// ---------------------------------------------------------------------------

/// Result of a field validation check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldValidation {
    /// The field is valid.
    Valid,
    /// The field has an error.
    Invalid(String),
    /// The field has a warning.
    Warning(String),
}

impl FieldValidation {
    /// Whether the validation passed (no errors).
    pub fn is_valid(&self) -> bool {
        !matches!(self, Self::Invalid(_))
    }
}

// ---------------------------------------------------------------------------
// Field list editor
// ---------------------------------------------------------------------------

/// Editor for the list of fields (components) in a composite data type.
///
/// Manages the logical operations on the field list, including add/remove/
/// replace/reorder with undo support and validation.
///
/// Ported from `ghidra.app.plugin.core.compositeeditor.FieldListEditor`.
#[derive(Debug)]
pub struct FieldListEditor {
    /// The data type path being edited.
    pub dt_path: DataTypePath,
    /// Whether this is a struct (true) or union (false).
    pub is_struct: bool,
    /// Current fields.
    fields: Vec<ComponentRow>,
    /// Edit history for undo.
    history: Vec<Vec<ComponentRow>>,
    /// Redo stack.
    redo_stack: Vec<Vec<ComponentRow>>,
    /// Whether the list has been modified.
    dirty: bool,
    /// Maximum number of fields allowed.
    pub max_fields: usize,
}

impl FieldListEditor {
    /// Create a new field list editor.
    pub fn new(dt_path: DataTypePath, is_struct: bool) -> Self {
        Self {
            dt_path,
            is_struct,
            fields: Vec::new(),
            history: Vec::new(),
            redo_stack: Vec::new(),
            dirty: false,
            max_fields: 1024,
        }
    }

    /// Get the current fields.
    pub fn fields(&self) -> &[ComponentRow] {
        &self.fields
    }

    /// Set the fields (e.g., on initial load).
    pub fn set_fields(&mut self, fields: Vec<ComponentRow>) {
        self.push_undo();
        self.fields = fields;
        self.dirty = true;
    }

    /// The number of fields.
    pub fn field_count(&self) -> usize {
        self.fields.len()
    }

    /// Add a field at the given position.
    pub fn add_field(
        &mut self,
        at: usize,
        type_name: impl Into<String>,
        field_name: impl Into<String>,
    ) -> Result<(), String> {
        if self.fields.len() >= self.max_fields {
            return Err("Maximum field count reached".into());
        }
        let tn = type_name.into();
        let fn_ = field_name.into();

        // Validate uniqueness of field name for structs
        if self.is_struct && self.fields.iter().any(|f| f.field_name == fn_ && !fn_.is_empty()) {
            return Err(format!("Duplicate field name: {}", fn_));
        }

        self.push_undo();
        let offset = if self.is_struct {
            if at == 0 {
                0
            } else if at <= self.fields.len() {
                self.fields[at - 1].end_offset()
            } else {
                self.fields.last().map_or(0, |c| c.end_offset())
            }
        } else {
            0 // Unions always at offset 0
        };
        let row = ComponentRow::new(at, tn, fn_, offset, 1);
        if at >= self.fields.len() {
            self.fields.push(row);
        } else {
            self.fields.insert(at, row);
        }
        self.reindex();
        self.dirty = true;
        Ok(())
    }

    /// Remove the field at the given position.
    pub fn remove_field(&mut self, at: usize) -> Result<ComponentRow, String> {
        if at >= self.fields.len() {
            return Err("Index out of bounds".into());
        }
        self.push_undo();
        let removed = self.fields.remove(at);
        self.reindex();
        self.dirty = true;
        Ok(removed)
    }

    /// Replace the type of a field.
    pub fn replace_type(
        &mut self,
        at: usize,
        new_type: impl Into<String>,
    ) -> Result<(), String> {
        if at >= self.fields.len() {
            return Err("Index out of bounds".into());
        }
        self.push_undo();
        self.fields[at].type_name = new_type.into();
        self.dirty = true;
        Ok(())
    }

    /// Replace the name of a field.
    pub fn replace_name(
        &mut self,
        at: usize,
        new_name: impl Into<String>,
    ) -> Result<(), String> {
        if at >= self.fields.len() {
            return Err("Index out of bounds".into());
        }
        let name = new_name.into();
        if self.is_struct
            && !name.is_empty()
            && self.fields.iter().enumerate().any(|(i, f)| f.field_name == name && i != at)
        {
            return Err(format!("Duplicate field name: {}", name));
        }
        self.push_undo();
        self.fields[at].field_name = name;
        self.dirty = true;
        Ok(())
    }

    /// Move a field from one position to another.
    pub fn move_field(&mut self, from: usize, to: usize) -> Result<(), String> {
        if from >= self.fields.len() || to >= self.fields.len() {
            return Err("Index out of bounds".into());
        }
        if from == to {
            return Ok(());
        }
        self.push_undo();
        let field = self.fields.remove(from);
        self.fields.insert(to, field);
        self.reindex();
        self.dirty = true;
        Ok(())
    }

    /// Clear all fields.
    pub fn clear(&mut self) {
        self.push_undo();
        self.fields.clear();
        self.dirty = true;
    }

    /// Validate a field name.
    pub fn validate_field_name(&self, name: &str, exclude_index: Option<usize>) -> FieldValidation {
        if name.is_empty() {
            return FieldValidation::Valid; // Empty names are allowed
        }
        if name.chars().any(|c| c.is_whitespace()) {
            return FieldValidation::Warning("Field name contains whitespace".into());
        }
        let duplicate = self
            .fields
            .iter()
            .enumerate()
            .any(|(i, f)| f.field_name == name && exclude_index != Some(i));
        if duplicate {
            FieldValidation::Invalid(format!("Duplicate field name: {}", name))
        } else {
            FieldValidation::Valid
        }
    }

    /// Whether undo is available.
    pub fn can_undo(&self) -> bool {
        !self.history.is_empty()
    }

    /// Whether redo is available.
    pub fn can_redo(&self) -> bool {
        !self.redo_stack.is_empty()
    }

    /// Undo the last change.
    pub fn undo(&mut self) -> bool {
        if let Some(prev) = self.history.pop() {
            self.redo_stack.push(std::mem::replace(&mut self.fields, prev));
            self.dirty = true;
            true
        } else {
            false
        }
    }

    /// Redo the last undone change.
    pub fn redo(&mut self) -> bool {
        if let Some(next) = self.redo_stack.pop() {
            self.history.push(std::mem::replace(&mut self.fields, next));
            self.dirty = true;
            true
        } else {
            false
        }
    }

    /// Whether the list has been modified.
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// Mark as clean.
    pub fn mark_clean(&mut self) {
        self.dirty = false;
    }

    /// Total byte size of all fields.
    pub fn total_size(&self) -> u64 {
        if self.is_struct {
            self.fields.last().map_or(0, |c| c.end_offset())
        } else {
            self.fields.iter().map(|c| c.length as u64).max().unwrap_or(0)
        }
    }

    fn push_undo(&mut self) {
        self.history.push(self.fields.clone());
        self.redo_stack.clear();
    }

    fn reindex(&mut self) {
        for (i, f) in self.fields.iter_mut().enumerate() {
            f.ordinal = i;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_path() -> DataTypePath {
        DataTypePath::new("/test", "S")
    }

    #[test]
    fn test_field_edit_op_variants() {
        let op = FieldEditOp::Add {
            at: 0,
            type_name: "int".into(),
            field_name: "x".into(),
        };
        assert!(matches!(op, FieldEditOp::Add { .. }));
    }

    #[test]
    fn test_field_validation() {
        assert!(FieldValidation::Valid.is_valid());
        assert!(FieldValidation::Warning("w".into()).is_valid());
        assert!(!FieldValidation::Invalid("e".into()).is_valid());
    }

    #[test]
    fn test_field_list_editor_creation() {
        let editor = FieldListEditor::new(sample_path(), true);
        assert!(editor.is_struct);
        assert_eq!(editor.field_count(), 0);
        assert!(!editor.is_dirty());
    }

    #[test]
    fn test_field_list_editor_add_remove() {
        let mut editor = FieldListEditor::new(sample_path(), true);
        editor.add_field(0, "int", "x").unwrap();
        editor.add_field(1, "char", "c").unwrap();
        assert_eq!(editor.field_count(), 2);

        let removed = editor.remove_field(0).unwrap();
        assert_eq!(removed.type_name, "int");
        assert_eq!(editor.field_count(), 1);
    }

    #[test]
    fn test_field_list_editor_duplicate_name() {
        let mut editor = FieldListEditor::new(sample_path(), true);
        editor.add_field(0, "int", "x").unwrap();
        let result = editor.add_field(1, "char", "x");
        assert!(result.is_err());
    }

    #[test]
    fn test_field_list_editor_replace() {
        let mut editor = FieldListEditor::new(sample_path(), true);
        editor.add_field(0, "int", "x").unwrap();

        editor.replace_type(0, "long").unwrap();
        assert_eq!(editor.fields()[0].type_name, "long");

        editor.replace_name(0, "y").unwrap();
        assert_eq!(editor.fields()[0].field_name, "y");
    }

    #[test]
    fn test_field_list_editor_move() {
        let mut editor = FieldListEditor::new(sample_path(), true);
        editor.add_field(0, "int", "a").unwrap();
        editor.add_field(1, "char", "b").unwrap();
        editor.add_field(2, "short", "c").unwrap();

        editor.move_field(0, 2).unwrap();
        assert_eq!(editor.fields()[0].field_name, "b");
        assert_eq!(editor.fields()[2].field_name, "a");
    }

    #[test]
    fn test_field_list_editor_undo_redo() {
        let mut editor = FieldListEditor::new(sample_path(), true);
        editor.add_field(0, "int", "x").unwrap();
        assert!(editor.can_undo());

        editor.undo();
        assert_eq!(editor.field_count(), 0);
        assert!(editor.can_redo());

        editor.redo();
        assert_eq!(editor.field_count(), 1);
    }

    #[test]
    fn test_field_list_editor_validation() {
        let mut editor = FieldListEditor::new(sample_path(), true);
        editor.add_field(0, "int", "x").unwrap();

        assert!(editor.validate_field_name("x", None).is_valid() == false);
        assert!(editor.validate_field_name("x", Some(0)).is_valid());
        assert!(editor.validate_field_name("y", None).is_valid());
        assert!(matches!(
            editor.validate_field_name("a b", None),
            FieldValidation::Warning(_)
        ));
    }

    #[test]
    fn test_field_list_editor_total_size() {
        let mut editor = FieldListEditor::new(sample_path(), true);
        editor.add_field(0, "int", "x").unwrap();
        editor.add_field(1, "char", "c").unwrap();
        assert_eq!(editor.total_size(), 2); // default 1-byte each
    }

    #[test]
    fn test_field_list_editor_union() {
        let mut editor = FieldListEditor::new(DataTypePath::new("/u", "U"), false);
        editor.add_field(0, "int", "a").unwrap();
        editor.add_field(1, "char", "b").unwrap();
        // All union fields at offset 0
        for f in editor.fields() {
            assert_eq!(f.offset, 0);
        }
    }

    #[test]
    fn test_field_list_editor_clear() {
        let mut editor = FieldListEditor::new(sample_path(), true);
        editor.add_field(0, "int", "x").unwrap();
        editor.clear();
        assert_eq!(editor.field_count(), 0);
        assert!(editor.can_undo());
    }

    #[test]
    fn test_field_list_editor_out_of_bounds() {
        let mut editor = FieldListEditor::new(sample_path(), true);
        assert!(editor.remove_field(0).is_err());
        assert!(editor.replace_type(0, "int").is_err());
        assert!(editor.replace_name(0, "x").is_err());
        assert!(editor.move_field(0, 1).is_err());
    }
}
