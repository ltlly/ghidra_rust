//! Change set model for the Debug framework.
//!
//! Ported from `ghidra.trace.model.TraceChangeSet` — tracks what has changed
//! between snapshots.

use std::collections::BTreeSet;
use std::fmt;

// ---------------------------------------------------------------------------
// TraceChangeSet
// ---------------------------------------------------------------------------

/// Tracks changes between snapshots in a trace.
///
/// Ported from `ghidra.trace.model.TraceChangeSet`. This records which
/// addresses, objects, and other elements have been modified, added, or
/// removed between two snapshots.
#[derive(Debug, Clone)]
pub struct TraceChangeSet {
    /// The snapshot key that this change set tracks changes since.
    pub since_snap: i64,
    /// The addresses where code units were added.
    code_added: BTreeSet<u64>,
    /// The addresses where code units were removed.
    code_removed: BTreeSet<u64>,
    /// The addresses where comments were changed.
    comments_changed: BTreeSet<u64>,
    /// The addresses where bookmarks were changed.
    bookmarks_changed: BTreeSet<u64>,
    /// The addresses where properties were changed.
    properties_changed: BTreeSet<u64>,
    /// Symbol IDs that were added.
    symbols_added: BTreeSet<u64>,
    /// Symbol IDs that were removed.
    symbols_removed: BTreeSet<u64>,
    /// The addresses where equates were changed.
    equates_changed: BTreeSet<u64>,
    /// The addresses where references were changed.
    references_changed: BTreeSet<u64>,
    /// Thread keys that were added or changed.
    threads_changed: BTreeSet<u64>,
    /// Thread keys that were removed.
    threads_removed: BTreeSet<u64>,
    /// Breakpoint keys that were changed.
    breakpoints_changed: BTreeSet<u64>,
    /// Breakpoint keys that were removed.
    breakpoints_removed: BTreeSet<u64>,
    /// Module keys that were changed.
    modules_changed: BTreeSet<u64>,
    /// Module keys that were removed.
    modules_removed: BTreeSet<u64>,
    /// Memory addresses that were changed.
    memory_changed: BTreeSet<u64>,
    /// Memory regions that were changed.
    regions_changed: BTreeSet<u64>,
    /// Registers that were changed (register offsets).
    registers_changed: BTreeSet<u64>,
    /// Stack keys that were changed.
    stacks_changed: BTreeSet<u64>,
    /// Whether any changes have been recorded.
    changed: bool,
}

impl TraceChangeSet {
    /// Create a new empty change set since the given snapshot.
    pub fn new(since_snap: i64) -> Self {
        Self {
            since_snap,
            code_added: BTreeSet::new(),
            code_removed: BTreeSet::new(),
            comments_changed: BTreeSet::new(),
            bookmarks_changed: BTreeSet::new(),
            properties_changed: BTreeSet::new(),
            symbols_added: BTreeSet::new(),
            symbols_removed: BTreeSet::new(),
            equates_changed: BTreeSet::new(),
            references_changed: BTreeSet::new(),
            threads_changed: BTreeSet::new(),
            threads_removed: BTreeSet::new(),
            breakpoints_changed: BTreeSet::new(),
            breakpoints_removed: BTreeSet::new(),
            modules_changed: BTreeSet::new(),
            modules_removed: BTreeSet::new(),
            memory_changed: BTreeSet::new(),
            regions_changed: BTreeSet::new(),
            registers_changed: BTreeSet::new(),
            stacks_changed: BTreeSet::new(),
            changed: false,
        }
    }

    /// Returns `true` if any changes have been recorded.
    pub fn has_changes(&self) -> bool {
        self.changed
    }

    /// Clear all recorded changes.
    pub fn clear(&mut self) {
        self.code_added.clear();
        self.code_removed.clear();
        self.comments_changed.clear();
        self.bookmarks_changed.clear();
        self.properties_changed.clear();
        self.symbols_added.clear();
        self.symbols_removed.clear();
        self.equates_changed.clear();
        self.references_changed.clear();
        self.threads_changed.clear();
        self.threads_removed.clear();
        self.breakpoints_changed.clear();
        self.breakpoints_removed.clear();
        self.modules_changed.clear();
        self.modules_removed.clear();
        self.memory_changed.clear();
        self.regions_changed.clear();
        self.registers_changed.clear();
        self.stacks_changed.clear();
        self.changed = false;
    }

    // --- Code ---

    /// Record that a code unit was added at the given address.
    pub fn code_added(&mut self, address: u64) {
        self.code_added.insert(address);
        self.changed = true;
    }

    /// Record that a code unit was removed at the given address.
    pub fn code_removed(&mut self, address: u64) {
        self.code_removed.insert(address);
        self.changed = true;
    }

    /// Returns addresses where code was added.
    pub fn get_code_added(&self) -> &BTreeSet<u64> {
        &self.code_added
    }

    /// Returns addresses where code was removed.
    pub fn get_code_removed(&self) -> &BTreeSet<u64> {
        &self.code_removed
    }

    /// Returns `true` if code has changed.
    pub fn has_code_changes(&self) -> bool {
        !self.code_added.is_empty() || !self.code_removed.is_empty()
    }

    // --- Comments ---

    /// Record that a comment was changed at the given address.
    pub fn comment_changed(&mut self, address: u64) {
        self.comments_changed.insert(address);
        self.changed = true;
    }

    /// Returns addresses where comments were changed.
    pub fn get_comments_changed(&self) -> &BTreeSet<u64> {
        &self.comments_changed
    }

    // --- Bookmarks ---

    /// Record that a bookmark was changed at the given address.
    pub fn bookmark_changed(&mut self, address: u64) {
        self.bookmarks_changed.insert(address);
        self.changed = true;
    }

    /// Returns addresses where bookmarks were changed.
    pub fn get_bookmarks_changed(&self) -> &BTreeSet<u64> {
        &self.bookmarks_changed
    }

    // --- Properties ---

    /// Record that a property was changed at the given address.
    pub fn property_changed(&mut self, address: u64) {
        self.properties_changed.insert(address);
        self.changed = true;
    }

    // --- Symbols ---

    /// Record that a symbol was added.
    pub fn symbol_added(&mut self, id: u64) {
        self.symbols_added.insert(id);
        self.changed = true;
    }

    /// Record that a symbol was removed.
    pub fn symbol_removed(&mut self, id: u64) {
        self.symbols_removed.insert(id);
        self.changed = true;
    }

    /// Returns `true` if symbols have changed.
    pub fn has_symbol_changes(&self) -> bool {
        !self.symbols_added.is_empty() || !self.symbols_removed.is_empty()
    }

    // --- Equates ---

    /// Record that an equate was changed at the given address.
    pub fn equate_changed(&mut self, address: u64) {
        self.equates_changed.insert(address);
        self.changed = true;
    }

    // --- References ---

    /// Record that a reference was changed at the given address.
    pub fn reference_changed(&mut self, address: u64) {
        self.references_changed.insert(address);
        self.changed = true;
    }

    // --- Threads ---

    /// Record that a thread was added or changed.
    pub fn thread_changed(&mut self, key: u64) {
        self.threads_changed.insert(key);
        self.changed = true;
    }

    /// Record that a thread was removed.
    pub fn thread_removed(&mut self, key: u64) {
        self.threads_removed.insert(key);
        self.changed = true;
    }

    /// Returns `true` if threads have changed.
    pub fn has_thread_changes(&self) -> bool {
        !self.threads_changed.is_empty() || !self.threads_removed.is_empty()
    }

    // --- Breakpoints ---

    /// Record that a breakpoint was changed.
    pub fn breakpoint_changed(&mut self, key: u64) {
        self.breakpoints_changed.insert(key);
        self.changed = true;
    }

    /// Record that a breakpoint was removed.
    pub fn breakpoint_removed(&mut self, key: u64) {
        self.breakpoints_removed.insert(key);
        self.changed = true;
    }

    /// Returns `true` if breakpoints have changed.
    pub fn has_breakpoint_changes(&self) -> bool {
        !self.breakpoints_changed.is_empty() || !self.breakpoints_removed.is_empty()
    }

    // --- Modules ---

    /// Record that a module was changed.
    pub fn module_changed(&mut self, key: u64) {
        self.modules_changed.insert(key);
        self.changed = true;
    }

    /// Record that a module was removed.
    pub fn module_removed(&mut self, key: u64) {
        self.modules_removed.insert(key);
        self.changed = true;
    }

    // --- Memory ---

    /// Record that memory was changed at the given address.
    pub fn memory_changed(&mut self, address: u64) {
        self.memory_changed.insert(address);
        self.changed = true;
    }

    /// Record that a memory region was changed.
    pub fn region_changed(&mut self, key: u64) {
        self.regions_changed.insert(key);
        self.changed = true;
    }

    /// Returns `true` if memory has changed.
    pub fn has_memory_changes(&self) -> bool {
        !self.memory_changed.is_empty() || !self.regions_changed.is_empty()
    }

    // --- Registers ---

    /// Record that a register was changed.
    pub fn register_changed(&mut self, offset: u64) {
        self.registers_changed.insert(offset);
        self.changed = true;
    }

    // --- Stacks ---

    /// Record that a stack was changed.
    pub fn stack_changed(&mut self, key: u64) {
        self.stacks_changed.insert(key);
        self.changed = true;
    }

    // --- Aggregate ---

    /// Merge another change set into this one.
    pub fn merge(&mut self, other: &TraceChangeSet) {
        self.code_added.extend(&other.code_added);
        self.code_removed.extend(&other.code_removed);
        self.comments_changed.extend(&other.comments_changed);
        self.bookmarks_changed.extend(&other.bookmarks_changed);
        self.properties_changed.extend(&other.properties_changed);
        self.symbols_added.extend(&other.symbols_added);
        self.symbols_removed.extend(&other.symbols_removed);
        self.equates_changed.extend(&other.equates_changed);
        self.references_changed.extend(&other.references_changed);
        self.threads_changed.extend(&other.threads_changed);
        self.threads_removed.extend(&other.threads_removed);
        self.breakpoints_changed.extend(&other.breakpoints_changed);
        self.breakpoints_removed.extend(&other.breakpoints_removed);
        self.modules_changed.extend(&other.modules_changed);
        self.modules_removed.extend(&other.modules_removed);
        self.memory_changed.extend(&other.memory_changed);
        self.regions_changed.extend(&other.regions_changed);
        self.registers_changed.extend(&other.registers_changed);
        self.stacks_changed.extend(&other.stacks_changed);
        if other.changed {
            self.changed = true;
        }
    }
}

impl fmt::Display for TraceChangeSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ChangeSet(since={}, changed={}, code+={}, code-={}, symbols+={}, symbols-={})",
            self.since_snap,
            self.changed,
            self.code_added.len(),
            self.code_removed.len(),
            self.symbols_added.len(),
            self.symbols_removed.len()
        )
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_change_set_empty() {
        let cs = TraceChangeSet::new(0);
        assert!(!cs.has_changes());
        assert!(!cs.has_code_changes());
        assert!(!cs.has_symbol_changes());
        assert!(!cs.has_thread_changes());
        assert!(!cs.has_breakpoint_changes());
        assert!(!cs.has_memory_changes());
    }

    #[test]
    fn test_change_set_code() {
        let mut cs = TraceChangeSet::new(0);
        cs.code_added(0x400000);
        cs.code_added(0x400100);
        cs.code_removed(0x500000);

        assert!(cs.has_changes());
        assert!(cs.has_code_changes());
        assert_eq!(cs.get_code_added().len(), 2);
        assert_eq!(cs.get_code_removed().len(), 1);
    }

    #[test]
    fn test_change_set_symbols() {
        let mut cs = TraceChangeSet::new(0);
        cs.symbol_added(1);
        cs.symbol_added(2);
        cs.symbol_removed(3);

        assert!(cs.has_symbol_changes());
    }

    #[test]
    fn test_change_set_threads() {
        let mut cs = TraceChangeSet::new(0);
        cs.thread_changed(100);
        cs.thread_removed(200);

        assert!(cs.has_thread_changes());
    }

    #[test]
    fn test_change_set_breakpoints() {
        let mut cs = TraceChangeSet::new(0);
        cs.breakpoint_changed(1);
        cs.breakpoint_removed(2);

        assert!(cs.has_breakpoint_changes());
    }

    #[test]
    fn test_change_set_memory() {
        let mut cs = TraceChangeSet::new(0);
        cs.memory_changed(0x400000);
        cs.region_changed(1);

        assert!(cs.has_memory_changes());
    }

    #[test]
    fn test_change_set_clear() {
        let mut cs = TraceChangeSet::new(0);
        cs.code_added(0x400000);
        cs.symbol_added(1);
        assert!(cs.has_changes());

        cs.clear();
        assert!(!cs.has_changes());
        assert!(cs.get_code_added().is_empty());
    }

    #[test]
    fn test_change_set_merge() {
        let mut cs1 = TraceChangeSet::new(0);
        cs1.code_added(0x400000);
        cs1.symbol_added(1);

        let mut cs2 = TraceChangeSet::new(0);
        cs2.code_added(0x600000);
        cs2.symbol_added(2);
        cs2.thread_changed(100);

        cs1.merge(&cs2);
        assert_eq!(cs1.get_code_added().len(), 2);
        assert!(cs1.has_thread_changes());
    }

    #[test]
    fn test_change_set_display() {
        let mut cs = TraceChangeSet::new(5);
        cs.code_added(0x400000);
        let s = format!("{cs}");
        assert!(s.contains("since=5"));
        assert!(s.contains("changed=true"));
    }
}
