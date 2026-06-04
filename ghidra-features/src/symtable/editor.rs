//! Symbol Editor -- ported from `SymbolEditor.java`.
//!
//! Provides in-place editing of symbol properties in the table view.

use std::fmt;

/// The type of edit being performed on a symbol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymbolEditType {
    /// Edit the symbol name.
    Name,
    /// Edit the symbol namespace.
    Namespace,
    /// Edit the symbol data type (for data symbols).
    DataType,
    /// Toggle the primary flag.
    Primary,
}

impl fmt::Display for SymbolEditType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Name => write!(f, "Name"),
            Self::Namespace => write!(f, "Namespace"),
            Self::DataType => write!(f, "DataType"),
            Self::Primary => write!(f, "Primary"),
        }
    }
}

/// Represents an in-progress symbol edit.
///
/// Ported from `SymbolEditor.java`.
#[derive(Debug, Clone)]
pub struct SymbolEditor {
    /// The type of edit.
    edit_type: SymbolEditType,
    /// The original value.
    original_value: String,
    /// The proposed new value.
    new_value: String,
    /// The symbol ID being edited.
    symbol_id: u64,
    /// The symbol address.
    address: u64,
    /// Whether the edit has been committed.
    committed: bool,
}

impl SymbolEditor {
    /// Creates a new symbol editor.
    pub fn new(
        edit_type: SymbolEditType,
        symbol_id: u64,
        address: u64,
        original_value: impl Into<String>,
    ) -> Self {
        let ov = original_value.into();
        Self {
            edit_type,
            new_value: ov.clone(),
            original_value: ov,
            symbol_id,
            address,
            committed: false,
        }
    }

    /// Returns the edit type.
    pub fn edit_type(&self) -> SymbolEditType {
        self.edit_type
    }

    /// Returns the original value.
    pub fn original_value(&self) -> &str {
        &self.original_value
    }

    /// Returns the new value.
    pub fn new_value(&self) -> &str {
        &self.new_value
    }

    /// Sets the new value.
    pub fn set_new_value(&mut self, value: impl Into<String>) {
        self.new_value = value.into();
    }

    /// Returns the symbol ID.
    pub fn symbol_id(&self) -> u64 {
        self.symbol_id
    }

    /// Returns the symbol address.
    pub fn address(&self) -> u64 {
        self.address
    }

    /// Returns `true` if the value has been changed.
    pub fn is_changed(&self) -> bool {
        self.original_value != self.new_value
    }

    /// Returns `true` if the edit has been committed.
    pub fn is_committed(&self) -> bool {
        self.committed
    }

    /// Commits the edit.
    pub fn commit(&mut self) {
        self.committed = true;
    }

    /// Cancels the edit (reverts to original).
    pub fn cancel(&mut self) {
        self.new_value = self.original_value.clone();
        self.committed = false;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_editor_creation() {
        let editor = SymbolEditor::new(SymbolEditType::Name, 1, 0x401000, "old_name");
        assert_eq!(editor.edit_type(), SymbolEditType::Name);
        assert_eq!(editor.original_value(), "old_name");
        assert_eq!(editor.new_value(), "old_name");
        assert!(!editor.is_changed());
        assert!(!editor.is_committed());
    }

    #[test]
    fn test_editor_change() {
        let mut editor = SymbolEditor::new(SymbolEditType::Name, 1, 0x401000, "old");
        editor.set_new_value("new");
        assert!(editor.is_changed());
        assert_eq!(editor.new_value(), "new");
    }

    #[test]
    fn test_editor_commit() {
        let mut editor = SymbolEditor::new(SymbolEditType::Name, 1, 0x401000, "old");
        editor.set_new_value("new");
        editor.commit();
        assert!(editor.is_committed());
    }

    #[test]
    fn test_editor_cancel() {
        let mut editor = SymbolEditor::new(SymbolEditType::Namespace, 1, 0x401000, "Global");
        editor.set_new_value("Local");
        assert!(editor.is_changed());
        editor.cancel();
        assert!(!editor.is_changed());
        assert_eq!(editor.new_value(), "Global");
    }

    #[test]
    fn test_edit_type_display() {
        assert_eq!(SymbolEditType::Name.to_string(), "Name");
        assert_eq!(SymbolEditType::Namespace.to_string(), "Namespace");
    }
}
