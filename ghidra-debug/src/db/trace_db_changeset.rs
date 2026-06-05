//! Database change set for trace operations.
//!
//! Ported from Ghidra's `DBTraceChangeSet`. Tracks changes made to a
//! trace database, supporting undo/redo operations and change notification.

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

/// The type of change recorded in the change set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChangeOperation {
    /// A value was inserted.
    Insert,
    /// A value was updated.
    Update,
    /// A value was deleted.
    Delete,
    /// A schema or structure change.
    SchemaChange,
}

/// A single change record in the change set.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangeRecord {
    /// The type of operation.
    pub operation: ChangeOperation,
    /// The table or manager name.
    pub table: String,
    /// The key of the changed record.
    pub key: u64,
    /// A human-readable description of the change.
    pub description: String,
}

impl ChangeRecord {
    /// Create a new change record.
    pub fn new(
        operation: ChangeOperation,
        table: impl Into<String>,
        key: u64,
        description: impl Into<String>,
    ) -> Self {
        Self {
            operation,
            table: table.into(),
            key,
            description: description.into(),
        }
    }
}

/// A database change set supporting undo/redo.
///
/// Ported from Ghidra's `DBTraceChangeSet`. Implements the
/// `DomainObjectDBChangeSet` interface pattern.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbTraceChangeSet {
    /// Forward change history (for undo).
    undo_stack: VecDeque<Vec<ChangeRecord>>,
    /// Backward change history (for redo).
    redo_stack: VecDeque<Vec<ChangeRecord>>,
    /// Whether recording is enabled.
    recording: bool,
    /// The maximum number of undo levels.
    max_undos: usize,
    /// Current transaction records (not yet committed).
    pending: Vec<ChangeRecord>,
}

impl DbTraceChangeSet {
    /// Create a new empty change set.
    pub fn new() -> Self {
        Self {
            undo_stack: VecDeque::new(),
            redo_stack: VecDeque::new(),
            recording: true,
            max_undos: 25,
            pending: Vec::new(),
        }
    }

    /// Enable or disable change recording.
    pub fn set_recording(&mut self, recording: bool) {
        self.recording = recording;
    }

    /// Whether recording is active.
    pub fn is_recording(&self) -> bool {
        self.recording
    }

    /// Set the maximum number of undo levels.
    pub fn set_max_undos(&mut self, max_undos: usize) {
        self.max_undos = max_undos;
        while self.undo_stack.len() > self.max_undos {
            self.undo_stack.pop_front();
        }
    }

    /// Record a change within the current transaction.
    pub fn record(&mut self, record: ChangeRecord) {
        if self.recording {
            self.pending.push(record);
        }
    }

    /// Start a new transaction.
    pub fn start_transaction(&mut self) {
        self.pending.clear();
    }

    /// End the current transaction, committing or discarding.
    pub fn end_transaction(&mut self, commit: bool) {
        if commit && !self.pending.is_empty() {
            let records = std::mem::take(&mut self.pending);
            self.undo_stack.push_back(records);
            self.redo_stack.clear();
            while self.undo_stack.len() > self.max_undos {
                self.undo_stack.pop_front();
            }
        } else {
            self.pending.clear();
        }
    }

    /// Whether undo is available.
    pub fn can_undo(&self) -> bool {
        !self.undo_stack.is_empty()
    }

    /// Whether redo is available.
    pub fn can_redo(&self) -> bool {
        !self.redo_stack.is_empty()
    }

    /// Undo the last transaction. Returns the undone records.
    pub fn undo(&mut self) -> Option<Vec<ChangeRecord>> {
        let records = self.undo_stack.pop_back()?;
        self.redo_stack.push_back(records.clone());
        Some(records)
    }

    /// Redo the last undone transaction. Returns the redone records.
    pub fn redo(&mut self) -> Option<Vec<ChangeRecord>> {
        let records = self.redo_stack.pop_back()?;
        self.undo_stack.push_back(records.clone());
        Some(records)
    }

    /// Clear all undo/redo history.
    pub fn clear(&mut self) {
        self.undo_stack.clear();
        self.redo_stack.clear();
        self.pending.clear();
    }

    /// Get the current undo depth.
    pub fn undo_depth(&self) -> usize {
        self.undo_stack.len()
    }

    /// Get the current redo depth.
    pub fn redo_depth(&self) -> usize {
        self.redo_stack.len()
    }
}

impl Default for DbTraceChangeSet {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_changeset() {
        let cs = DbTraceChangeSet::new();
        assert!(!cs.can_undo());
        assert!(!cs.can_redo());
        assert!(cs.is_recording());
        assert_eq!(cs.undo_depth(), 0);
    }

    #[test]
    fn test_record_and_commit() {
        let mut cs = DbTraceChangeSet::new();
        cs.start_transaction();
        cs.record(ChangeRecord::new(ChangeOperation::Insert, "threads", 1, "new thread"));
        cs.end_transaction(true);

        assert!(cs.can_undo());
        assert_eq!(cs.undo_depth(), 1);
    }

    #[test]
    fn test_undo_redo() {
        let mut cs = DbTraceChangeSet::new();
        cs.start_transaction();
        cs.record(ChangeRecord::new(ChangeOperation::Insert, "threads", 1, "new thread"));
        cs.end_transaction(true);

        let undone = cs.undo().unwrap();
        assert_eq!(undone.len(), 1);
        assert_eq!(undone[0].table, "threads");
        assert!(!cs.can_undo());
        assert!(cs.can_redo());

        let redone = cs.redo().unwrap();
        assert_eq!(redone.len(), 1);
        assert!(cs.can_undo());
        assert!(!cs.can_redo());
    }

    #[test]
    fn test_discard_transaction() {
        let mut cs = DbTraceChangeSet::new();
        cs.start_transaction();
        cs.record(ChangeRecord::new(ChangeOperation::Insert, "test", 1, "test"));
        cs.end_transaction(false);

        assert!(!cs.can_undo());
    }

    #[test]
    fn test_max_undos() {
        let mut cs = DbTraceChangeSet::new();
        cs.set_max_undos(2);

        for i in 0..5 {
            cs.start_transaction();
            cs.record(ChangeRecord::new(ChangeOperation::Insert, "t", i, format!("op{}", i)));
            cs.end_transaction(true);
        }

        assert_eq!(cs.undo_depth(), 2);
    }

    #[test]
    fn test_no_recording() {
        let mut cs = DbTraceChangeSet::new();
        cs.set_recording(false);

        cs.start_transaction();
        cs.record(ChangeRecord::new(ChangeOperation::Insert, "t", 1, "test"));
        cs.end_transaction(true);

        assert!(!cs.can_undo());
    }

    #[test]
    fn test_clear() {
        let mut cs = DbTraceChangeSet::new();
        cs.start_transaction();
        cs.record(ChangeRecord::new(ChangeOperation::Insert, "t", 1, "test"));
        cs.end_transaction(true);
        cs.undo();

        cs.clear();
        assert!(!cs.can_undo());
        assert!(!cs.can_redo());
    }

    #[test]
    fn test_changeset_serde() {
        let mut cs = DbTraceChangeSet::new();
        cs.start_transaction();
        cs.record(ChangeRecord::new(ChangeOperation::Insert, "threads", 1, "new"));
        cs.end_transaction(true);

        let json = serde_json::to_string(&cs).unwrap();
        let back: DbTraceChangeSet = serde_json::from_str(&json).unwrap();
        assert!(back.can_undo());
    }

    #[test]
    fn test_change_record_serde() {
        let record = ChangeRecord::new(ChangeOperation::Update, "memory", 42, "write bytes");
        let json = serde_json::to_string(&record).unwrap();
        let back: ChangeRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back.operation, ChangeOperation::Update);
        assert_eq!(back.key, 42);
    }

    #[test]
    fn test_multiple_operations() {
        let mut cs = DbTraceChangeSet::new();
        cs.start_transaction();
        cs.record(ChangeRecord::new(ChangeOperation::Insert, "t", 1, "op1"));
        cs.record(ChangeRecord::new(ChangeOperation::Update, "t", 1, "op2"));
        cs.record(ChangeRecord::new(ChangeOperation::Delete, "t", 1, "op3"));
        cs.end_transaction(true);

        let undone = cs.undo().unwrap();
        assert_eq!(undone.len(), 3);
        assert_eq!(undone[0].operation, ChangeOperation::Insert);
        assert_eq!(undone[1].operation, ChangeOperation::Update);
        assert_eq!(undone[2].operation, ChangeOperation::Delete);
    }
}
