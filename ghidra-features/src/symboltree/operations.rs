//! Symbol tree operations.
//!
//! Ported from action classes in `ghidra.app.plugin.core.symboltree.actions`.
//!
//! Provides operations for manipulating symbols in the symbol tree,
//! including creating namespaces, classes, moving, renaming, and
//! deleting symbols.

/// Operations that can be performed on symbol tree nodes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SymbolOperation {
    /// Create a new namespace.
    CreateNamespace { name: String, parent_id: u64 },
    /// Create a new class.
    CreateClass { name: String, parent_id: u64 },
    /// Convert a namespace to a class.
    ConvertToClass { namespace_id: u64 },
    /// Rename a symbol.
    Rename { symbol_id: u64, new_name: String },
    /// Delete a symbol.
    Delete { symbol_id: u64 },
    /// Move a symbol to a new parent.
    Move { symbol_id: u64, new_parent_id: u64 },
    /// Cut a symbol (for clipboard).
    Cut { symbol_id: u64 },
    /// Paste from clipboard.
    Paste { parent_id: u64 },
    /// Pin a symbol (keep visible when filtering).
    Pin { symbol_id: u64 },
    /// Unpin a symbol.
    Unpin { symbol_id: u64 },
    /// Set symbol as primary.
    SetPrimary { symbol_id: u64 },
    /// Create an external library.
    CreateLibrary { name: String },
    /// Create an external location.
    CreateExternalLocation {
        library_name: String,
        label: String,
        address: Option<u64>,
    },
    /// Edit an external location.
    EditExternalLocation {
        location_id: u64,
        new_label: Option<String>,
        new_address: Option<u64>,
    },
    /// Set external program for a library.
    SetExternalProgram {
        library_name: String,
        program_path: String,
    },
}

/// Result of a symbol operation.
#[derive(Debug, Clone)]
pub enum SymbolOperationResult {
    /// The operation succeeded.
    Success {
        /// The ID of the affected symbol (if applicable).
        symbol_id: Option<u64>,
        /// A message describing the result.
        message: String,
    },
    /// The operation failed.
    Failure {
        /// The error message.
        error: String,
    },
    /// The operation requires user confirmation.
    NeedsConfirmation {
        /// The confirmation prompt.
        prompt: String,
        /// The operation to confirm.
        pending_operation: SymbolOperation,
    },
}

/// Manages symbol tree operations with undo/redo support.
#[derive(Debug, Default)]
pub struct SymbolOperationManager {
    /// History of performed operations (for undo).
    undo_history: Vec<SymbolOperation>,
    /// History of undone operations (for redo).
    redo_history: Vec<SymbolOperation>,
    /// Clipboard contents (symbol IDs).
    clipboard: Vec<u64>,
    /// Pinned symbol IDs.
    pinned_symbols: Vec<u64>,
}

impl SymbolOperationManager {
    /// Create a new operation manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an operation for undo support.
    pub fn record_operation(&mut self, op: SymbolOperation) {
        self.undo_history.push(op);
        self.redo_history.clear();
    }

    /// Get the last operation (for undo).
    pub fn undo(&mut self) -> Option<SymbolOperation> {
        let op = self.undo_history.pop()?;
        self.redo_history.push(op.clone());
        Some(op)
    }

    /// Redo the last undone operation.
    pub fn redo(&mut self) -> Option<SymbolOperation> {
        let op = self.redo_history.pop()?;
        self.undo_history.push(op.clone());
        Some(op)
    }

    /// Whether undo is available.
    pub fn can_undo(&self) -> bool {
        !self.undo_history.is_empty()
    }

    /// Whether redo is available.
    pub fn can_redo(&self) -> bool {
        !self.redo_history.is_empty()
    }

    /// Copy a symbol ID to the clipboard.
    pub fn copy_to_clipboard(&mut self, symbol_id: u64) {
        self.clipboard.push(symbol_id);
    }

    /// Clear the clipboard.
    pub fn clear_clipboard(&mut self) {
        self.clipboard.clear();
    }

    /// Get clipboard contents.
    pub fn clipboard(&self) -> &[u64] {
        &self.clipboard
    }

    /// Whether the clipboard has contents.
    pub fn has_clipboard_contents(&self) -> bool {
        !self.clipboard.is_empty()
    }

    /// Pin a symbol.
    pub fn pin(&mut self, symbol_id: u64) {
        if !self.pinned_symbols.contains(&symbol_id) {
            self.pinned_symbols.push(symbol_id);
        }
    }

    /// Unpin a symbol.
    pub fn unpin(&mut self, symbol_id: u64) {
        self.pinned_symbols.retain(|&id| id != symbol_id);
    }

    /// Whether a symbol is pinned.
    pub fn is_pinned(&self, symbol_id: u64) -> bool {
        self.pinned_symbols.contains(&symbol_id)
    }

    /// Get all pinned symbol IDs.
    pub fn pinned_symbols(&self) -> &[u64] {
        &self.pinned_symbols
    }

    /// Clear all pinned symbols.
    pub fn clear_pinned(&mut self) {
        self.pinned_symbols.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_operation_manager_new() {
        let mgr = SymbolOperationManager::new();
        assert!(!mgr.can_undo());
        assert!(!mgr.can_redo());
        assert!(!mgr.has_clipboard_contents());
    }

    #[test]
    fn test_record_and_undo() {
        let mut mgr = SymbolOperationManager::new();
        mgr.record_operation(SymbolOperation::Rename {
            symbol_id: 1,
            new_name: "foo".to_string(),
        });
        assert!(mgr.can_undo());
        let op = mgr.undo().unwrap();
        assert!(matches!(op, SymbolOperation::Rename { symbol_id: 1, .. }));
        assert!(!mgr.can_undo());
        assert!(mgr.can_redo());
    }

    #[test]
    fn test_redo() {
        let mut mgr = SymbolOperationManager::new();
        mgr.record_operation(SymbolOperation::Delete { symbol_id: 1 });
        mgr.undo();
        assert!(mgr.can_redo());
        let op = mgr.redo().unwrap();
        assert!(matches!(op, SymbolOperation::Delete { symbol_id: 1 }));
    }

    #[test]
    fn test_clipboard() {
        let mut mgr = SymbolOperationManager::new();
        mgr.copy_to_clipboard(42);
        mgr.copy_to_clipboard(43);
        assert!(mgr.has_clipboard_contents());
        assert_eq!(mgr.clipboard().len(), 2);
        mgr.clear_clipboard();
        assert!(!mgr.has_clipboard_contents());
    }

    #[test]
    fn test_pin_unpin() {
        let mut mgr = SymbolOperationManager::new();
        mgr.pin(10);
        mgr.pin(20);
        assert!(mgr.is_pinned(10));
        assert!(mgr.is_pinned(20));
        assert!(!mgr.is_pinned(30));
        assert_eq!(mgr.pinned_symbols().len(), 2);
        mgr.unpin(10);
        assert!(!mgr.is_pinned(10));
        assert!(mgr.is_pinned(20));
        mgr.clear_pinned();
        assert_eq!(mgr.pinned_symbols().len(), 0);
    }

    #[test]
    fn test_operation_variants() {
        let ops = vec![
            SymbolOperation::CreateNamespace { name: "ns".to_string(), parent_id: 0 },
            SymbolOperation::CreateClass { name: "cls".to_string(), parent_id: 0 },
            SymbolOperation::ConvertToClass { namespace_id: 1 },
            SymbolOperation::Rename { symbol_id: 1, new_name: "x".to_string() },
            SymbolOperation::Delete { symbol_id: 1 },
            SymbolOperation::Move { symbol_id: 1, new_parent_id: 2 },
            SymbolOperation::Cut { symbol_id: 1 },
            SymbolOperation::Paste { parent_id: 0 },
            SymbolOperation::Pin { symbol_id: 1 },
            SymbolOperation::Unpin { symbol_id: 1 },
            SymbolOperation::SetPrimary { symbol_id: 1 },
            SymbolOperation::CreateLibrary { name: "lib".to_string() },
            SymbolOperation::CreateExternalLocation {
                library_name: "lib".to_string(),
                label: "func".to_string(),
                address: Some(0x1000),
            },
            SymbolOperation::EditExternalLocation {
                location_id: 1,
                new_label: Some("new".to_string()),
                new_address: None,
            },
            SymbolOperation::SetExternalProgram {
                library_name: "lib".to_string(),
                program_path: "/path".to_string(),
            },
        ];
        assert_eq!(ops.len(), 15);
    }
}
