//! Program change set ported from Java's `ProgramDBChangeSet` and
//! `DataTypeArchiveDBChangeSet`.
//!
//! Tracks changes made to a program database: added/modified/removed
//! addresses, data types, categories, symbols, source archives, and
//! program tree nodes.  Supports undo/redo of change tracking.

use std::collections::{HashSet, VecDeque};
use std::fmt;

// ============================================================================
// ProgramDBChangeSet (port of Java ProgramDBChangeSet)
// ============================================================================

/// Tracks all changes made to a program database during a transaction.
///
/// Port of Java `ghidra.program.database.ProgramDBChangeSet`.
///
/// Changes are accumulated per-transaction and can be undone/redone
/// via the undo/redo stack.
#[derive(Debug)]
pub struct ProgramDBChangeSet {
    // ---- Persistent (committed) change sets ----
    /// Address ranges with memory changes.
    changed_addresses: Vec<(u64, u64)>,
    /// Address ranges with register context changes.
    changed_register_addresses: Vec<(u64, u64)>,
    /// IDs of data types that were changed.
    changed_data_type_ids: HashSet<i64>,
    /// IDs of data types that were added.
    added_data_type_ids: HashSet<i64>,
    /// IDs of categories that were changed.
    changed_category_ids: HashSet<i64>,
    /// IDs of categories that were added.
    added_category_ids: HashSet<i64>,
    /// IDs of program trees that were changed.
    changed_program_tree_ids: HashSet<i64>,
    /// IDs of program trees that were added.
    added_program_tree_ids: HashSet<i64>,
    /// IDs of symbols that were changed.
    changed_symbol_ids: HashSet<i64>,
    /// IDs of symbols that were added.
    added_symbol_ids: HashSet<i64>,
    /// IDs of source archives that were changed.
    changed_source_archive_ids: HashSet<i64>,
    /// IDs of source archives that were added.
    added_source_archive_ids: HashSet<i64>,
    /// IDs of function tags that were changed.
    changed_tag_ids: HashSet<i64>,
    /// IDs of function tags that were added.
    added_tag_ids: HashSet<i64>,

    // ---- Temporary (in-transaction) change sets ----
    tmp_changed_data_type_ids: HashSet<i64>,
    tmp_changed_category_ids: HashSet<i64>,
    tmp_changed_program_tree_ids: HashSet<i64>,
    tmp_changed_symbol_ids: HashSet<i64>,
    tmp_changed_source_archive_ids: HashSet<i64>,
    tmp_changed_tag_ids: HashSet<i64>,
    tmp_added_data_type_ids: HashSet<i64>,
    tmp_added_category_ids: HashSet<i64>,
    tmp_added_program_tree_ids: HashSet<i64>,
    tmp_added_symbol_ids: HashSet<i64>,
    tmp_added_source_archive_ids: HashSet<i64>,
    tmp_added_tag_ids: HashSet<i64>,

    // ---- Undo/redo ----
    undo_stack: VecDeque<ChangeDiff>,
    redo_stack: VecDeque<ChangeDiff>,
    max_undos: usize,

    /// Whether a transaction is currently open.
    in_transaction: bool,
}

/// A snapshot of changes for undo/redo.
#[derive(Debug, Clone, Default)]
struct ChangeDiff {
    changed_data_type_ids: HashSet<i64>,
    changed_category_ids: HashSet<i64>,
    changed_program_tree_ids: HashSet<i64>,
    changed_symbol_ids: HashSet<i64>,
    changed_source_archive_ids: HashSet<i64>,
    changed_tag_ids: HashSet<i64>,
    added_data_type_ids: HashSet<i64>,
    added_category_ids: HashSet<i64>,
    added_program_tree_ids: HashSet<i64>,
    added_symbol_ids: HashSet<i64>,
    added_source_archive_ids: HashSet<i64>,
    added_tag_ids: HashSet<i64>,
}

impl ProgramDBChangeSet {
    /// Create a new empty change set with the given undo depth.
    pub fn new(max_undos: usize) -> Self {
        Self {
            changed_addresses: Vec::new(),
            changed_register_addresses: Vec::new(),
            changed_data_type_ids: HashSet::new(),
            added_data_type_ids: HashSet::new(),
            changed_category_ids: HashSet::new(),
            added_category_ids: HashSet::new(),
            changed_program_tree_ids: HashSet::new(),
            added_program_tree_ids: HashSet::new(),
            changed_symbol_ids: HashSet::new(),
            added_symbol_ids: HashSet::new(),
            changed_source_archive_ids: HashSet::new(),
            added_source_archive_ids: HashSet::new(),
            changed_tag_ids: HashSet::new(),
            added_tag_ids: HashSet::new(),
            tmp_changed_data_type_ids: HashSet::new(),
            tmp_changed_category_ids: HashSet::new(),
            tmp_changed_program_tree_ids: HashSet::new(),
            tmp_changed_symbol_ids: HashSet::new(),
            tmp_changed_source_archive_ids: HashSet::new(),
            tmp_changed_tag_ids: HashSet::new(),
            tmp_added_data_type_ids: HashSet::new(),
            tmp_added_category_ids: HashSet::new(),
            tmp_added_program_tree_ids: HashSet::new(),
            tmp_added_symbol_ids: HashSet::new(),
            tmp_added_source_archive_ids: HashSet::new(),
            tmp_added_tag_ids: HashSet::new(),
            undo_stack: VecDeque::new(),
            redo_stack: VecDeque::new(),
            max_undos,
            in_transaction: false,
        }
    }

    // ---- Transaction lifecycle ----

    /// Begin accumulating changes for a new transaction.
    ///
    /// Port of Java `ProgramDBChangeSet.startTransaction()`.
    pub fn start_transaction(&mut self) {
        self.redo_stack.clear();
        self.in_transaction = true;
        self.tmp_changed_data_type_ids.clear();
        self.tmp_changed_category_ids.clear();
        self.tmp_changed_program_tree_ids.clear();
        self.tmp_changed_symbol_ids.clear();
        self.tmp_changed_source_archive_ids.clear();
        self.tmp_changed_tag_ids.clear();
        self.tmp_added_data_type_ids.clear();
        self.tmp_added_category_ids.clear();
        self.tmp_added_program_tree_ids.clear();
        self.tmp_added_symbol_ids.clear();
        self.tmp_added_source_archive_ids.clear();
        self.tmp_added_tag_ids.clear();
    }

    /// End the current transaction, committing or discarding changes.
    ///
    /// Port of Java `ProgramDBChangeSet.endTransaction(boolean)`.
    pub fn end_transaction(&mut self, commit: bool) {
        if !self.in_transaction {
            return;
        }
        self.in_transaction = false;
        if commit {
            // Merge tmp changes into persistent sets.
            let diff = ChangeDiff {
                changed_data_type_ids: self.tmp_changed_data_type_ids.clone(),
                changed_category_ids: self.tmp_changed_category_ids.clone(),
                changed_program_tree_ids: self.tmp_changed_program_tree_ids.clone(),
                changed_symbol_ids: self.tmp_changed_symbol_ids.clone(),
                changed_source_archive_ids: self.tmp_changed_source_archive_ids.clone(),
                changed_tag_ids: self.tmp_changed_tag_ids.clone(),
                added_data_type_ids: self.tmp_added_data_type_ids.clone(),
                added_category_ids: self.tmp_added_category_ids.clone(),
                added_program_tree_ids: self.tmp_added_program_tree_ids.clone(),
                added_symbol_ids: self.tmp_added_symbol_ids.clone(),
                added_source_archive_ids: self.tmp_added_source_archive_ids.clone(),
                added_tag_ids: self.tmp_added_tag_ids.clone(),
            };

            self.changed_data_type_ids.extend(&self.tmp_changed_data_type_ids);
            self.changed_category_ids.extend(&self.tmp_changed_category_ids);
            self.changed_program_tree_ids.extend(&self.tmp_changed_program_tree_ids);
            self.changed_symbol_ids.extend(&self.tmp_changed_symbol_ids);
            self.changed_source_archive_ids.extend(&self.tmp_changed_source_archive_ids);
            self.changed_tag_ids.extend(&self.tmp_changed_tag_ids);
            self.added_data_type_ids.extend(&self.tmp_added_data_type_ids);
            self.added_category_ids.extend(&self.tmp_added_category_ids);
            self.added_program_tree_ids.extend(&self.tmp_added_program_tree_ids);
            self.added_symbol_ids.extend(&self.tmp_added_symbol_ids);
            self.added_source_archive_ids.extend(&self.tmp_added_source_archive_ids);
            self.added_tag_ids.extend(&self.tmp_added_tag_ids);

            self.undo_stack.push_back(diff);
            if self.undo_stack.len() > self.max_undos {
                self.undo_stack.pop_front();
            }
        }
    }

    // ---- Change recording (call during transactions) ----

    /// Record an address range change.
    pub fn set_changed(&mut self, start: u64, end: u64) {
        assert!(self.in_transaction, "Not in a transaction");
        self.changed_addresses.push((start, end));
    }

    /// Record a register context change.
    pub fn set_register_changed(&mut self, start: u64, end: u64) {
        assert!(self.in_transaction, "Not in a transaction");
        self.changed_register_addresses.push((start, end));
    }

    /// Record a data type change.
    pub fn data_type_changed(&mut self, id: i64) {
        assert!(self.in_transaction, "Not in a transaction");
        if !self.added_data_type_ids.contains(&id) && !self.tmp_added_data_type_ids.contains(&id) {
            self.tmp_changed_data_type_ids.insert(id);
        }
    }

    /// Record a data type addition.
    pub fn data_type_added(&mut self, id: i64) {
        assert!(self.in_transaction, "Not in a transaction");
        self.tmp_added_data_type_ids.insert(id);
    }

    /// Record a category change.
    pub fn category_changed(&mut self, id: i64) {
        assert!(self.in_transaction, "Not in a transaction");
        if !self.added_category_ids.contains(&id) && !self.tmp_added_category_ids.contains(&id) {
            self.tmp_changed_category_ids.insert(id);
        }
    }

    /// Record a category addition.
    pub fn category_added(&mut self, id: i64) {
        assert!(self.in_transaction, "Not in a transaction");
        self.tmp_added_category_ids.insert(id);
    }

    /// Record a symbol change.
    pub fn symbol_changed(&mut self, id: i64) {
        assert!(self.in_transaction, "Not in a transaction");
        if !self.added_symbol_ids.contains(&id) && !self.tmp_added_symbol_ids.contains(&id) {
            self.tmp_changed_symbol_ids.insert(id);
        }
    }

    /// Record a symbol addition.
    pub fn symbol_added(&mut self, id: i64) {
        assert!(self.in_transaction, "Not in a transaction");
        self.tmp_added_symbol_ids.insert(id);
    }

    /// Record a source archive change.
    pub fn source_archive_changed(&mut self, id: i64) {
        assert!(self.in_transaction, "Not in a transaction");
        if !self.added_source_archive_ids.contains(&id)
            && !self.tmp_added_source_archive_ids.contains(&id)
        {
            self.tmp_changed_source_archive_ids.insert(id);
        }
    }

    /// Record a source archive addition.
    pub fn source_archive_added(&mut self, id: i64) {
        assert!(self.in_transaction, "Not in a transaction");
        self.tmp_added_source_archive_ids.insert(id);
    }

    /// Record a function tag change.
    pub fn tag_changed(&mut self, id: i64) {
        assert!(self.in_transaction, "Not in a transaction");
        if !self.added_tag_ids.contains(&id) && !self.tmp_added_tag_ids.contains(&id) {
            self.tmp_changed_tag_ids.insert(id);
        }
    }

    /// Record a function tag addition.
    pub fn tag_added(&mut self, id: i64) {
        assert!(self.in_transaction, "Not in a transaction");
        self.tmp_added_tag_ids.insert(id);
    }

    // ---- Query (port of Java getter methods) ----

    /// Return true if any changes have been recorded.
    pub fn has_changes(&self) -> bool {
        !self.changed_addresses.is_empty()
            || !self.changed_register_addresses.is_empty()
            || !self.changed_data_type_ids.is_empty()
            || !self.added_data_type_ids.is_empty()
            || !self.changed_category_ids.is_empty()
            || !self.added_category_ids.is_empty()
            || !self.changed_program_tree_ids.is_empty()
            || !self.added_program_tree_ids.is_empty()
            || !self.changed_symbol_ids.is_empty()
            || !self.added_symbol_ids.is_empty()
            || !self.changed_source_archive_ids.is_empty()
            || !self.added_source_archive_ids.is_empty()
            || !self.changed_tag_ids.is_empty()
            || !self.added_tag_ids.is_empty()
    }

    /// Return the changed address ranges.
    pub fn get_changed_addresses(&self) -> &[(u64, u64)] {
        &self.changed_addresses
    }

    /// Return the changed register address ranges.
    pub fn get_changed_register_addresses(&self) -> &[(u64, u64)] {
        &self.changed_register_addresses
    }

    /// Return the changed data type IDs.
    pub fn get_data_type_changes(&self) -> Vec<i64> {
        self.changed_data_type_ids.iter().copied().collect()
    }

    /// Return the added data type IDs.
    pub fn get_data_type_additions(&self) -> Vec<i64> {
        self.added_data_type_ids.iter().copied().collect()
    }

    /// Return the changed category IDs.
    pub fn get_category_changes(&self) -> Vec<i64> {
        self.changed_category_ids.iter().copied().collect()
    }

    /// Return the added category IDs.
    pub fn get_category_additions(&self) -> Vec<i64> {
        self.added_category_ids.iter().copied().collect()
    }

    /// Return the changed symbol IDs.
    pub fn get_symbol_changes(&self) -> Vec<i64> {
        self.changed_symbol_ids.iter().copied().collect()
    }

    /// Return the added symbol IDs.
    pub fn get_symbol_additions(&self) -> Vec<i64> {
        self.added_symbol_ids.iter().copied().collect()
    }

    /// Return the changed source archive IDs.
    pub fn get_source_archive_changes(&self) -> Vec<i64> {
        self.changed_source_archive_ids.iter().copied().collect()
    }

    /// Return the added source archive IDs.
    pub fn get_source_archive_additions(&self) -> Vec<i64> {
        self.added_source_archive_ids.iter().copied().collect()
    }

    /// Return true if a transaction is currently open.
    pub fn is_in_transaction(&self) -> bool {
        self.in_transaction
    }

    /// Whether the undo stack has entries.
    pub fn can_undo(&self) -> bool {
        !self.undo_stack.is_empty()
    }

    /// Whether the redo stack has entries.
    pub fn can_redo(&self) -> bool {
        !self.redo_stack.is_empty()
    }

    /// Undo the last committed transaction's changes.
    pub fn undo(&mut self) -> bool {
        if let Some(diff) = self.undo_stack.pop_back() {
            // Remove diff changes from persistent sets.
            for id in &diff.changed_data_type_ids {
                self.changed_data_type_ids.remove(id);
            }
            for id in &diff.changed_category_ids {
                self.changed_category_ids.remove(id);
            }
            for id in &diff.changed_symbol_ids {
                self.changed_symbol_ids.remove(id);
            }
            for id in &diff.changed_source_archive_ids {
                self.changed_source_archive_ids.remove(id);
            }
            for id in &diff.added_data_type_ids {
                self.added_data_type_ids.remove(id);
            }
            for id in &diff.added_category_ids {
                self.added_category_ids.remove(id);
            }
            for id in &diff.added_symbol_ids {
                self.added_symbol_ids.remove(id);
            }
            for id in &diff.added_source_archive_ids {
                self.added_source_archive_ids.remove(id);
            }
            self.redo_stack.push_back(diff);
            true
        } else {
            false
        }
    }

    /// Redo the last undone transaction's changes.
    pub fn redo(&mut self) -> bool {
        if let Some(diff) = self.redo_stack.pop_back() {
            self.changed_data_type_ids.extend(&diff.changed_data_type_ids);
            self.changed_category_ids.extend(&diff.changed_category_ids);
            self.changed_symbol_ids.extend(&diff.changed_symbol_ids);
            self.changed_source_archive_ids.extend(&diff.changed_source_archive_ids);
            self.added_data_type_ids.extend(&diff.added_data_type_ids);
            self.added_category_ids.extend(&diff.added_category_ids);
            self.added_symbol_ids.extend(&diff.added_symbol_ids);
            self.added_source_archive_ids.extend(&diff.added_source_archive_ids);
            self.undo_stack.push_back(diff);
            true
        } else {
            false
        }
    }

    /// Clear the undo and redo stacks.
    pub fn clear_undo(&mut self) {
        self.undo_stack.clear();
        self.redo_stack.clear();
    }

    /// Clear all changes (both persistent and temporary).
    pub fn clear_all(&mut self) {
        self.changed_addresses.clear();
        self.changed_register_addresses.clear();
        self.changed_data_type_ids.clear();
        self.added_data_type_ids.clear();
        self.changed_category_ids.clear();
        self.added_category_ids.clear();
        self.changed_program_tree_ids.clear();
        self.added_program_tree_ids.clear();
        self.changed_symbol_ids.clear();
        self.added_symbol_ids.clear();
        self.changed_source_archive_ids.clear();
        self.added_source_archive_ids.clear();
        self.changed_tag_ids.clear();
        self.added_tag_ids.clear();
        self.clear_undo();
    }
}

impl Default for ProgramDBChangeSet {
    fn default() -> Self {
        Self::new(4)
    }
}

impl fmt::Display for ProgramDBChangeSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ProgramDBChangeSet(addrs={}, dt_changed={}, dt_added={}, sym_changed={}, sym_added={})",
            self.changed_addresses.len(),
            self.changed_data_type_ids.len(),
            self.added_data_type_ids.len(),
            self.changed_symbol_ids.len(),
            self.added_symbol_ids.len(),
        )
    }
}

// ============================================================================
// DataTypeArchiveDBChangeSet (port of Java DataTypeArchiveDBChangeSet)
// ============================================================================

/// Change set for data type archive operations (without address tracking).
///
/// Port of Java `ghidra.program.database.DataTypeArchiveDBChangeSet`.
#[derive(Debug)]
pub struct DataTypeArchiveDBChangeSet {
    changed_data_type_ids: HashSet<i64>,
    added_data_type_ids: HashSet<i64>,
    changed_category_ids: HashSet<i64>,
    added_category_ids: HashSet<i64>,
    changed_source_archive_ids: HashSet<i64>,
    added_source_archive_ids: HashSet<i64>,
    max_undos: usize,
    undo_stack: VecDeque<ChangeDiff>,
    redo_stack: VecDeque<ChangeDiff>,
    in_transaction: bool,
}

impl DataTypeArchiveDBChangeSet {
    /// Create a new empty data type archive change set.
    pub fn new(max_undos: usize) -> Self {
        Self {
            changed_data_type_ids: HashSet::new(),
            added_data_type_ids: HashSet::new(),
            changed_category_ids: HashSet::new(),
            added_category_ids: HashSet::new(),
            changed_source_archive_ids: HashSet::new(),
            added_source_archive_ids: HashSet::new(),
            max_undos,
            undo_stack: VecDeque::new(),
            redo_stack: VecDeque::new(),
            in_transaction: false,
        }
    }

    /// Start a new transaction.
    pub fn start_transaction(&mut self) {
        self.redo_stack.clear();
        self.in_transaction = true;
    }

    /// End the current transaction.
    pub fn end_transaction(&mut self, commit: bool) {
        if !self.in_transaction {
            return;
        }
        self.in_transaction = false;
        if commit {
            let diff = ChangeDiff::default();
            self.undo_stack.push_back(diff);
            if self.undo_stack.len() > self.max_undos {
                self.undo_stack.pop_front();
            }
        }
    }

    /// Record a data type change.
    pub fn data_type_changed(&mut self, id: i64) {
        assert!(self.in_transaction, "Not in a transaction");
        if !self.added_data_type_ids.contains(&id) {
            self.changed_data_type_ids.insert(id);
        }
    }

    /// Record a data type addition.
    pub fn data_type_added(&mut self, id: i64) {
        assert!(self.in_transaction, "Not in a transaction");
        self.added_data_type_ids.insert(id);
    }

    /// Record a category change.
    pub fn category_changed(&mut self, id: i64) {
        assert!(self.in_transaction, "Not in a transaction");
        if !self.added_category_ids.contains(&id) {
            self.changed_category_ids.insert(id);
        }
    }

    /// Record a category addition.
    pub fn category_added(&mut self, id: i64) {
        assert!(self.in_transaction, "Not in a transaction");
        self.added_category_ids.insert(id);
    }

    /// Record a source archive change.
    pub fn source_archive_changed(&mut self, id: i64) {
        assert!(self.in_transaction, "Not in a transaction");
        if !self.added_source_archive_ids.contains(&id) {
            self.changed_source_archive_ids.insert(id);
        }
    }

    /// Record a source archive addition.
    pub fn source_archive_added(&mut self, id: i64) {
        assert!(self.in_transaction, "Not in a transaction");
        self.added_source_archive_ids.insert(id);
    }

    /// Return true if any changes have been recorded.
    pub fn has_changes(&self) -> bool {
        !self.changed_data_type_ids.is_empty()
            || !self.added_data_type_ids.is_empty()
            || !self.changed_category_ids.is_empty()
            || !self.added_category_ids.is_empty()
            || !self.changed_source_archive_ids.is_empty()
            || !self.added_source_archive_ids.is_empty()
    }

    /// Get changed data type IDs.
    pub fn get_data_type_changes(&self) -> Vec<i64> {
        self.changed_data_type_ids.iter().copied().collect()
    }

    /// Get added data type IDs.
    pub fn get_data_type_additions(&self) -> Vec<i64> {
        self.added_data_type_ids.iter().copied().collect()
    }

    /// Get changed category IDs.
    pub fn get_category_changes(&self) -> Vec<i64> {
        self.changed_category_ids.iter().copied().collect()
    }

    /// Get added category IDs.
    pub fn get_category_additions(&self) -> Vec<i64> {
        self.added_category_ids.iter().copied().collect()
    }

    /// Get changed source archive IDs.
    pub fn get_source_archive_changes(&self) -> Vec<i64> {
        self.changed_source_archive_ids.iter().copied().collect()
    }

    /// Get added source archive IDs.
    pub fn get_source_archive_additions(&self) -> Vec<i64> {
        self.added_source_archive_ids.iter().copied().collect()
    }

    /// Clear all undo/redo state.
    pub fn clear_undo(&mut self) {
        self.undo_stack.clear();
        self.redo_stack.clear();
    }
}

impl Default for DataTypeArchiveDBChangeSet {
    fn default() -> Self {
        Self::new(4)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_change_set_basic() {
        let mut cs = ProgramDBChangeSet::new(4);
        assert!(!cs.has_changes());

        cs.start_transaction();
        cs.data_type_changed(1);
        cs.data_type_changed(2);
        cs.data_type_added(3);
        cs.symbol_changed(100);
        cs.symbol_added(200);
        cs.end_transaction(true);

        assert!(cs.has_changes());
        assert_eq!(cs.get_data_type_changes().len(), 2);
        assert_eq!(cs.get_data_type_additions().len(), 1);
        assert_eq!(cs.get_symbol_changes().len(), 1);
        assert_eq!(cs.get_symbol_additions().len(), 1);
    }

    #[test]
    fn test_change_set_no_record_outside_tx() {
        let mut cs = ProgramDBChangeSet::new(4);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            cs.data_type_changed(1); // should panic
        }));
        assert!(result.is_err());
    }

    #[test]
    fn test_change_set_discard() {
        let mut cs = ProgramDBChangeSet::new(4);
        cs.start_transaction();
        cs.data_type_changed(1);
        cs.end_transaction(false); // discard

        assert!(!cs.has_changes());
    }

    #[test]
    fn test_change_set_undo_redo() {
        let mut cs = ProgramDBChangeSet::new(4);

        cs.start_transaction();
        cs.data_type_changed(1);
        cs.end_transaction(true);

        assert!(cs.has_changes());
        assert!(cs.can_undo());
        assert!(!cs.can_redo());

        cs.undo();
        assert!(!cs.has_changes());
        assert!(cs.can_redo());

        cs.redo();
        assert!(cs.has_changes());
    }

    #[test]
    fn test_change_set_address_tracking() {
        let mut cs = ProgramDBChangeSet::new(4);
        cs.start_transaction();
        cs.set_changed(0x1000, 0x1010);
        cs.set_register_changed(0x2000, 0x2010);
        cs.end_transaction(true);

        assert_eq!(cs.get_changed_addresses().len(), 1);
        assert_eq!(cs.get_changed_register_addresses().len(), 1);
    }

    #[test]
    fn test_change_set_category_changes() {
        let mut cs = ProgramDBChangeSet::new(4);
        cs.start_transaction();
        cs.category_changed(10);
        cs.category_added(20);
        cs.end_transaction(true);

        assert_eq!(cs.get_category_changes().len(), 1);
        assert_eq!(cs.get_category_additions().len(), 1);
    }

    #[test]
    fn test_change_set_clear() {
        let mut cs = ProgramDBChangeSet::new(4);
        cs.start_transaction();
        cs.data_type_changed(1);
        cs.end_transaction(true);

        assert!(cs.has_changes());
        cs.clear_all();
        assert!(!cs.has_changes());
        assert!(!cs.can_undo());
    }

    #[test]
    fn test_datatype_archive_change_set() {
        let mut cs = DataTypeArchiveDBChangeSet::new(4);
        assert!(!cs.has_changes());

        cs.start_transaction();
        cs.data_type_changed(1);
        cs.data_type_added(2);
        cs.category_changed(10);
        cs.category_added(20);
        cs.end_transaction(true);

        assert!(cs.has_changes());
        assert_eq!(cs.get_data_type_changes().len(), 1);
        assert_eq!(cs.get_data_type_additions().len(), 1);
        assert_eq!(cs.get_category_changes().len(), 1);
        assert_eq!(cs.get_category_additions().len(), 1);
    }

    #[test]
    fn test_max_undos_overflow() {
        let mut cs = ProgramDBChangeSet::new(2);
        for i in 0..5 {
            cs.start_transaction();
            cs.data_type_changed(i);
            cs.end_transaction(true);
        }
        // Should only keep the last 2.
        assert!(cs.undo_stack.len() <= 2);
    }
}
