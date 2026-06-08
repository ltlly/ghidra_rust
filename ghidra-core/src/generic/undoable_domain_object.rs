//! Undoable domain object abstraction for the Ghidra framework.
//!
//! Ports Ghidra's `framework.model.UndoableDomainObject` interface. Extends
//! the base `DomainObject` with undo/redo capability, allowing changes to
//! be reverted or reapplied.

use super::domain_object::{DomainObject, DomainObjectError};

// ============================================================================
// UndoableDomainObject trait
// ============================================================================

/// A [`DomainObject`] that supports undo and redo operations.
///
/// Implementations maintain an internal undo/redo stack. Each discrete
/// change can be grouped into an undoable transaction. When an undo is
/// performed, the most recent transaction is reverted; redo re-applies
/// the most recently undone transaction.
pub trait UndoableDomainObject: DomainObject {
    /// Returns `true` if there is at least one transaction to undo.
    fn can_undo(&self) -> bool;

    /// Returns `true` if there is at least one transaction to redo.
    fn can_redo(&self) -> bool;

    /// Undo the most recent transaction.
    ///
    /// Returns an error if there is nothing to undo.
    fn undo(&mut self) -> Result<(), DomainObjectError>;

    /// Redo the most recently undone transaction.
    ///
    /// Returns an error if there is nothing to redo.
    fn redo(&mut self) -> Result<(), DomainObjectError>;

    /// Returns a description of the transaction that would be undone.
    fn get_undo_name(&self) -> Option<String>;

    /// Returns a description of the transaction that would be redone.
    fn get_redo_name(&self) -> Option<String>;

    /// Start a new undoable transaction with the given name.
    ///
    /// All changes made between `start_undo()` and `end_undo()` are
    /// grouped into a single undoable unit.
    fn start_undo(&mut self, name: &str);

    /// End the current undoable transaction.
    fn end_undo(&mut self);

    /// Returns `true` if an undo transaction is currently open.
    fn is_in_undo(&self) -> bool;

    /// Clear all undo and redo history.
    fn clear_undo(&mut self);

    /// Returns the current undo stack depth (number of undoable transactions).
    fn undo_depth(&self) -> usize;

    /// Returns the current redo stack depth.
    fn redo_depth(&self) -> usize;
}

// ============================================================================
// UndoableTransaction
// ============================================================================

/// RAII guard for an undoable transaction.
///
/// Begins a transaction on creation and ends it on drop. This ensures
/// transactions are always properly closed, even in the presence of
/// early returns or panics.
///
/// # Examples
///
/// ```ignore
/// use ghidra_core::generic::undoable_domain_object::UndoableTransaction;
///
/// {
///     let _txn = UndoableTransaction::new(&mut obj, "Rename symbol");
///     // ... make changes ...
/// } // transaction ends here
/// ```
pub struct UndoableTransaction<'a> {
    obj: &'a mut dyn UndoableDomainObject,
}

impl<'a> UndoableTransaction<'a> {
    /// Begin a new undoable transaction.
    pub fn new(obj: &'a mut dyn UndoableDomainObject, name: &str) -> Self {
        obj.start_undo(name);
        Self { obj }
    }
}

impl<'a> Drop for UndoableTransaction<'a> {
    fn drop(&mut self) {
        self.obj.end_undo();
    }
}

// ============================================================================
// UndoRedoState
// ============================================================================

/// Snapshot of the undo/redo state for inspection.
#[derive(Debug, Clone, Default)]
pub struct UndoRedoState {
    /// Number of undoable transactions.
    pub undo_count: usize,
    /// Number of redoable transactions.
    pub redo_count: usize,
    /// Name of the next undo transaction, if any.
    pub undo_name: Option<String>,
    /// Name of the next redo transaction, if any.
    pub redo_name: Option<String>,
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};
    use std::time::SystemTime;

    #[derive(Debug)]
    struct TestUndoableObject {
        name: String,
        changed: bool,
        undo_stack: VecDeque<String>,
        redo_stack: VecDeque<String>,
        in_undo: bool,
    }

    impl TestUndoableObject {
        fn new(name: &str) -> Self {
            Self {
                name: name.to_string(),
                changed: false,
                undo_stack: VecDeque::new(),
                redo_stack: VecDeque::new(),
                in_undo: false,
            }
        }
    }

    impl DomainObject for TestUndoableObject {
        fn get_name(&self) -> &str { &self.name }
        fn set_name(&mut self, name: String) { self.name = name; }
        fn get_domain_file_path(&self) -> Option<String> { None }
        fn get_last_modified_time(&self) -> SystemTime { SystemTime::now() }
        fn is_changed(&self) -> bool { self.changed }
        fn set_changed(&mut self, changed: bool) { self.changed = changed; }
        fn save(&mut self) -> Result<(), DomainObjectError> { self.changed = false; Ok(()) }
        fn close(&mut self) -> Result<(), DomainObjectError> { Ok(()) }
        fn is_lockable(&self) -> bool { true }
        fn is_locked(&self) -> bool { false }
        fn lock(&self) -> Result<super::super::domain_object::DomainObjectLock, DomainObjectError> {
            Ok(super::super::domain_object::DomainObjectLock::new("test"))
        }
        fn force_unlock(&self) {}
        fn add_listener(&self, _listener: Box<dyn DomainObjectListener>) {}
        fn remove_listener(&self, _listener_id: u64) {}
        fn is_undoable(&self) -> bool { true }
    }

    impl UndoableDomainObject for TestUndoableObject {
        fn can_undo(&self) -> bool { !self.undo_stack.is_empty() }
        fn can_redo(&self) -> bool { !self.redo_stack.is_empty() }
        fn undo(&mut self) -> Result<(), DomainObjectError> {
            if let Some(name) = self.undo_stack.pop_back() {
                self.redo_stack.push_back(name);
                Ok(())
            } else {
                Err(DomainObjectError::Other("Nothing to undo".to_string()))
            }
        }
        fn redo(&mut self) -> Result<(), DomainObjectError> {
            if let Some(name) = self.redo_stack.pop_back() {
                self.undo_stack.push_back(name);
                Ok(())
            } else {
                Err(DomainObjectError::Other("Nothing to redo".to_string()))
            }
        }
        fn get_undo_name(&self) -> Option<String> {
            self.undo_stack.back().cloned()
        }
        fn get_redo_name(&self) -> Option<String> {
            self.redo_stack.back().cloned()
        }
        fn start_undo(&mut self, name: &str) {
            self.undo_stack.push_back(name.to_string());
            self.redo_stack.clear();
            self.in_undo = true;
        }
        fn end_undo(&mut self) {
            self.in_undo = false;
        }
        fn is_in_undo(&self) -> bool { self.in_undo }
        fn clear_undo(&mut self) {
            self.undo_stack.clear();
            self.redo_stack.clear();
        }
        fn undo_depth(&self) -> usize { self.undo_stack.len() }
        fn redo_depth(&self) -> usize { self.redo_stack.len() }
    }

    #[test]
    fn test_undo_redo() {
        let mut obj = TestUndoableObject::new("test");
        assert!(!obj.can_undo());
        assert!(!obj.can_redo());

        obj.start_undo("change 1");
        obj.end_undo();
        assert!(obj.can_undo());
        assert_eq!(obj.get_undo_name(), Some("change 1".to_string()));

        obj.undo().unwrap();
        assert!(!obj.can_undo());
        assert!(obj.can_redo());
        assert_eq!(obj.get_redo_name(), Some("change 1".to_string()));

        obj.redo().unwrap();
        assert!(obj.can_undo());
        assert!(!obj.can_redo());
    }

    #[test]
    fn test_undo_clears_redo() {
        let mut obj = TestUndoableObject::new("test");
        obj.start_undo("change 1");
        obj.end_undo();
        obj.undo().unwrap();
        assert!(obj.can_redo());

        obj.start_undo("change 2");
        obj.end_undo();
        assert!(!obj.can_redo());
    }

    #[test]
    fn test_clear_undo() {
        let mut obj = TestUndoableObject::new("test");
        obj.start_undo("change 1");
        obj.end_undo();
        obj.start_undo("change 2");
        obj.end_undo();
        assert_eq!(obj.undo_depth(), 2);

        obj.clear_undo();
        assert_eq!(obj.undo_depth(), 0);
        assert_eq!(obj.redo_depth(), 0);
    }

    #[test]
    fn test_undo_on_empty() {
        let mut obj = TestUndoableObject::new("test");
        assert!(obj.undo().is_err());
        assert!(obj.redo().is_err());
    }

    #[test]
    fn test_is_in_undo() {
        let mut obj = TestUndoableObject::new("test");
        assert!(!obj.is_in_undo());
        obj.start_undo("txn");
        assert!(obj.is_in_undo());
        obj.end_undo();
        assert!(!obj.is_in_undo());
    }

    #[test]
    fn test_undo_redo_state_default() {
        let state = UndoRedoState::default();
        assert_eq!(state.undo_count, 0);
        assert_eq!(state.redo_count, 0);
        assert!(state.undo_name.is_none());
        assert!(state.redo_name.is_none());
    }
}
