//! Rename data field dialog -- ported from `RenameDataFieldDialog.java`.
//!
//! Provides a dialog model for renaming fields within a composite data
//! type (structure or union).  The dialog collects a new field name and
//! validates it before the rename is committed.
//!
//! # Example
//!
//! ```
//! use ghidra_features::base::data::rename_dialog::RenameDataFieldDialog;
//!
//! let mut dialog = RenameDataFieldDialog::new("myStruct", "field0", 3);
//! assert_eq!(dialog.current_name(), "field0");
//! assert!(!dialog.has_changes());
//!
//! dialog.set_new_name("renamed_field");
//! assert!(dialog.has_changes());
//! assert!(dialog.is_valid());
//! ```

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// RenameDataFieldDialog
// ---------------------------------------------------------------------------

/// Dialog model for renaming a field in a composite data type.
///
/// Ported from `RenameDataFieldDialog.java`.  The dialog validates
/// that the new name is non-empty, does not conflict with other field
/// names in the same composite, and is a legal identifier.
///
/// # Example
///
/// ```
/// use ghidra_features::base::data::rename_dialog::RenameDataFieldDialog;
///
/// let dialog = RenameDataFieldDialog::new("Point", "x", 0);
/// assert_eq!(dialog.composite_name(), "Point");
/// assert_eq!(dialog.current_name(), "x");
/// assert_eq!(dialog.field_index(), 0);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenameDataFieldDialog {
    /// The name of the parent composite data type.
    composite_name: String,
    /// The current field name.
    current_name: String,
    /// The new name entered by the user.
    new_name: String,
    /// The index of the field within the composite.
    field_index: usize,
    /// Validation status text.
    status_text: String,
    /// The list of existing field names in the composite (for conflict
    /// checking).
    existing_field_names: Vec<String>,
}

impl RenameDataFieldDialog {
    /// Creates a new rename dialog.
    pub fn new(
        composite_name: impl Into<String>,
        current_name: impl Into<String>,
        field_index: usize,
    ) -> Self {
        Self {
            composite_name: composite_name.into(),
            current_name: current_name.into(),
            new_name: String::new(),
            field_index,
            status_text: String::new(),
            existing_field_names: Vec::new(),
        }
    }

    /// Creates a new rename dialog with existing field names for
    /// conflict checking.
    pub fn with_existing_names(
        composite_name: impl Into<String>,
        current_name: impl Into<String>,
        field_index: usize,
        existing_field_names: Vec<String>,
    ) -> Self {
        Self {
            composite_name: composite_name.into(),
            current_name: current_name.into(),
            new_name: String::new(),
            field_index,
            status_text: String::new(),
            existing_field_names,
        }
    }

    /// Returns the parent composite name.
    pub fn composite_name(&self) -> &str {
        &self.composite_name
    }

    /// Returns the current field name.
    pub fn current_name(&self) -> &str {
        &self.current_name
    }

    /// Returns the new name entered by the user.
    pub fn new_name(&self) -> &str {
        &self.new_name
    }

    /// Returns the field index.
    pub fn field_index(&self) -> usize {
        self.field_index
    }

    /// Returns the validation status text.
    pub fn status_text(&self) -> &str {
        &self.status_text
    }

    /// Returns whether the name has been changed.
    pub fn has_changes(&self) -> bool {
        !self.new_name.is_empty() && self.new_name != self.current_name
    }

    /// Returns whether the current state is valid.
    pub fn is_valid(&self) -> bool {
        self.status_text.is_empty() && (self.new_name.is_empty() || self.has_changes())
    }

    /// Sets the new name and validates it.
    pub fn set_new_name(&mut self, name: impl Into<String>) {
        self.new_name = name.into();
        self.validate();
    }

    /// Validates the new name.
    fn validate(&mut self) {
        self.status_text.clear();

        if self.new_name.is_empty() {
            return;
        }

        if self.new_name == self.current_name {
            return;
        }

        // Check for valid identifier characters.
        if !is_valid_identifier(&self.new_name) {
            self.status_text = "Name must be a valid identifier".to_string();
            return;
        }

        // Check for conflicts with existing field names.
        for (i, existing) in self.existing_field_names.iter().enumerate() {
            if i != self.field_index && existing == &self.new_name {
                self.status_text = format!(
                    "Field name '{}' already exists in {}",
                    self.new_name, self.composite_name
                );
                return;
            }
        }
    }

    /// Returns the rename result (the new name to apply), or `None` if
    /// there are no valid changes.
    pub fn result(&self) -> Option<&str> {
        if self.has_changes() && self.is_valid() {
            Some(&self.new_name)
        } else {
            None
        }
    }
}

/// Checks whether a string is a valid identifier (starts with a letter
/// or underscore, followed by letters, digits, or underscores).
fn is_valid_identifier(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    let mut chars = name.chars();
    if let Some(first) = chars.next() {
        if !first.is_ascii_alphabetic() && first != '_' {
            return false;
        }
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

// ---------------------------------------------------------------------------
// RenameDataFieldRequest
// ---------------------------------------------------------------------------

/// A request to rename a field in a composite data type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RenameDataFieldRequest {
    /// The parent composite name.
    pub composite_name: String,
    /// The field index.
    pub field_index: usize,
    /// The old field name.
    pub old_name: String,
    /// The new field name.
    pub new_name: String,
}

impl RenameDataFieldRequest {
    /// Creates a new rename request.
    pub fn new(
        composite_name: impl Into<String>,
        field_index: usize,
        old_name: impl Into<String>,
        new_name: impl Into<String>,
    ) -> Self {
        Self {
            composite_name: composite_name.into(),
            field_index,
            old_name: old_name.into(),
            new_name: new_name.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rename_dialog_basic() {
        let dialog = RenameDataFieldDialog::new("Point", "x", 0);
        assert_eq!(dialog.composite_name(), "Point");
        assert_eq!(dialog.current_name(), "x");
        assert_eq!(dialog.field_index(), 0);
        assert!(!dialog.has_changes());
        assert!(dialog.is_valid());
    }

    #[test]
    fn test_rename_dialog_set_name() {
        let mut dialog = RenameDataFieldDialog::new("Point", "x", 0);
        dialog.set_new_name("x_coord");
        assert!(dialog.has_changes());
        assert!(dialog.is_valid());
        assert_eq!(dialog.result(), Some("x_coord"));
    }

    #[test]
    fn test_rename_dialog_same_name() {
        let mut dialog = RenameDataFieldDialog::new("Point", "x", 0);
        dialog.set_new_name("x");
        assert!(!dialog.has_changes());
    }

    #[test]
    fn test_rename_dialog_empty_name() {
        let mut dialog = RenameDataFieldDialog::new("Point", "x", 0);
        dialog.set_new_name("");
        assert!(!dialog.has_changes());
        assert!(dialog.is_valid()); // empty = no change, valid
        assert!(dialog.result().is_none());
    }

    #[test]
    fn test_rename_dialog_invalid_identifier() {
        let mut dialog = RenameDataFieldDialog::new("Point", "x", 0);
        dialog.set_new_name("123invalid");
        assert!(!dialog.is_valid());
        assert!(!dialog.status_text().is_empty());
        assert!(dialog.result().is_none());
    }

    #[test]
    fn test_rename_dialog_invalid_identifier_special_chars() {
        let mut dialog = RenameDataFieldDialog::new("Point", "x", 0);
        dialog.set_new_name("field-name");
        assert!(!dialog.is_valid());
    }

    #[test]
    fn test_rename_dialog_conflict() {
        let dialog = RenameDataFieldDialog::with_existing_names(
            "Point",
            "x",
            0,
            vec!["x".to_string(), "y".to_string()],
        );
        let mut dialog = dialog;
        dialog.set_new_name("y");
        assert!(!dialog.is_valid());
        assert!(dialog.status_text().contains("already exists"));
        assert!(dialog.result().is_none());
    }

    #[test]
    fn test_rename_dialog_no_conflict_same_index() {
        let dialog = RenameDataFieldDialog::with_existing_names(
            "Point",
            "x",
            0,
            vec!["x".to_string(), "y".to_string()],
        );
        let mut dialog = dialog;
        dialog.set_new_name("x");
        // Same as current name, so not a change
        assert!(!dialog.has_changes());
    }

    #[test]
    fn test_rename_dialog_underscore_start() {
        let mut dialog = RenameDataFieldDialog::new("S", "f", 0);
        dialog.set_new_name("_private");
        assert!(dialog.is_valid());
        assert_eq!(dialog.result(), Some("_private"));
    }

    #[test]
    fn test_is_valid_identifier() {
        assert!(is_valid_identifier("field"));
        assert!(is_valid_identifier("_field"));
        assert!(is_valid_identifier("field_0"));
        assert!(is_valid_identifier("F"));
        assert!(!is_valid_identifier(""));
        assert!(!is_valid_identifier("0field"));
        assert!(!is_valid_identifier("field-name"));
        assert!(!is_valid_identifier("field name"));
    }

    #[test]
    fn test_rename_request() {
        let req = RenameDataFieldRequest::new("Point", 0, "x", "x_coord");
        assert_eq!(req.composite_name, "Point");
        assert_eq!(req.field_index, 0);
        assert_eq!(req.old_name, "x");
        assert_eq!(req.new_name, "x_coord");
    }

    #[test]
    fn test_rename_dialog_serialization() {
        let mut dialog = RenameDataFieldDialog::new("S", "f", 0);
        dialog.set_new_name("new_f");

        let json = serde_json::to_string(&dialog).unwrap();
        let deserialized: RenameDataFieldDialog = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.new_name(), "new_f");
        assert_eq!(deserialized.current_name(), "f");
    }

    #[test]
    fn test_rename_dialog_with_existing_names() {
        let mut dialog = RenameDataFieldDialog::with_existing_names(
            "MyStruct",
            "old",
            1,
            vec!["first".to_string(), "old".to_string(), "third".to_string()],
        );

        // Try to rename to "first" (conflict)
        dialog.set_new_name("first");
        assert!(!dialog.is_valid());
        assert!(dialog.result().is_none());

        // Try to rename to "second" (no conflict)
        dialog.set_new_name("second");
        assert!(dialog.is_valid());
        assert_eq!(dialog.result(), Some("second"));
    }

    #[test]
    fn test_rename_dialog_result_none_when_empty() {
        let dialog = RenameDataFieldDialog::new("S", "f", 0);
        assert!(dialog.result().is_none());
    }
}
