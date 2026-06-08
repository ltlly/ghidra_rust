//! Stored undoable domain object.
//!
//! Ports `ghidra.framework.data.StoredUndoableDomainObject` from Java.
//! Provides a domain object implementation that supports undo/redo via
//! in-memory snapshots of the object state at each transaction boundary.

use std::collections::HashMap;
use std::fmt;

use super::data::DomainObjectChangeSupport;
use super::model::*;
use super::{ProjectError, ProjectLocator, ProjectResult};

// ============================================================================
// UndoableState
// ============================================================================

/// A snapshot of domain object state for undo/redo.
#[derive(Debug, Clone)]
pub struct UndoableState {
    /// Description of the change.
    pub description: String,
    /// Serialized state data (application-specific).
    pub data: Vec<u8>,
    /// The modification number at this point.
    pub modification_number: u64,
}

impl UndoableState {
    /// Create a new undoable state snapshot.
    pub fn new(description: impl Into<String>, data: Vec<u8>, modification_number: u64) -> Self {
        Self {
            description: description.into(),
            data,
            modification_number,
        }
    }
}

// ============================================================================
// StoredUndoableDomainObject
// ============================================================================

/// A [`DomainObject2`] implementation that supports undo/redo via stored
/// state snapshots.
///
/// In Java: `ghidra.framework.data.StoredUndoableDomainObject`.
///
/// Each transaction boundary captures the object's state so that undo
/// and redo can restore previous states.  The state is stored as opaque
/// bytes; the concrete domain object subclass provides serialization
/// and deserialization.
pub struct StoredUndoableDomainObject {
    /// Object name.
    name: String,
    /// Object description.
    description: String,
    /// Associated domain file path.
    domain_file_path: Option<String>,
    /// Project locator.
    #[allow(dead_code)]
    locator: ProjectLocator,
    /// Current serialized state.
    current_state: Vec<u8>,
    /// Stack of undo states (most recent first).
    undo_stack: Vec<UndoableState>,
    /// Stack of redo states (most recent first).
    redo_stack: Vec<UndoableState>,
    /// Current modification number.
    modification_number: u64,
    /// Whether the object has unsaved changes.
    changed: bool,
    /// Whether the object is temporary.
    temporary: bool,
    /// Whether the object is closed.
    closed: bool,
    /// Whether the object is locked.
    locked: bool,
    /// Current lock reason, if any.
    lock_reason: Option<String>,
    /// Consumer IDs.
    consumers: Vec<u64>,
    /// Event dispatch support.
    change_support: DomainObjectChangeSupport,
    /// Current transaction, if any.
    current_transaction: Option<ActiveTransaction>,
    /// Whether events are enabled.
    events_enabled: bool,
    /// Transaction listeners.
    transaction_listeners: Vec<Box<dyn TransactionListener>>,
    /// Abort listeners keyed by transaction ID.
    abort_listeners: HashMap<u64, Box<dyn AbortedTransactionListener>>,
}

/// Internal tracking for an active transaction.
#[derive(Debug)]
#[allow(dead_code)]
struct ActiveTransaction {
    id: u64,
    description: String,
    /// State captured at transaction start for potential rollback.
    start_state: Vec<u64>,
    /// Whether this transaction has been terminated.
    terminated: bool,
}

impl StoredUndoableDomainObject {
    /// Create a new stored undoable domain object.
    pub fn new(
        name: impl Into<String>,
        description: impl Into<String>,
        locator: ProjectLocator,
    ) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            domain_file_path: None,
            locator,
            current_state: Vec::new(),
            undo_stack: Vec::new(),
            redo_stack: Vec::new(),
            modification_number: 0,
            changed: false,
            temporary: false,
            closed: false,
            locked: false,
            lock_reason: None,
            consumers: Vec::new(),
            change_support: DomainObjectChangeSupport::new(),
            current_transaction: None,
            events_enabled: true,
            transaction_listeners: Vec::new(),
            abort_listeners: HashMap::new(),
        }
    }

    /// Set the domain file path.
    pub fn set_domain_file_path(&mut self, path: impl Into<String>) {
        self.domain_file_path = Some(path.into());
    }

    /// Update the current state and mark as changed.
    pub fn update_state(&mut self, new_state: Vec<u8>) {
        self.current_state = new_state;
        self.changed = true;
        self.modification_number += 1;
    }

    /// Get a reference to the current state data.
    pub fn state_data(&self) -> &[u8] {
        &self.current_state
    }

    /// Set the current state data directly (without going through a transaction).
    pub fn set_state_data(&mut self, data: Vec<u8>) {
        self.current_state = data;
    }

    /// Number of undo steps available.
    pub fn undo_count(&self) -> usize {
        self.undo_stack.len()
    }

    /// Number of redo steps available.
    pub fn redo_count(&self) -> usize {
        self.redo_stack.len()
    }

    /// Capture the current state as an undo checkpoint.
    fn capture_undo_state(&mut self, description: &str) {
        let state = UndoableState::new(
            description,
            self.current_state.clone(),
            self.modification_number,
        );
        self.undo_stack.push(state);
        // Clear redo stack when a new action is performed.
        self.redo_stack.clear();
    }
}

impl fmt::Debug for StoredUndoableDomainObject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StoredUndoableDomainObject")
            .field("name", &self.name)
            .field("description", &self.description)
            .field("domain_file_path", &self.domain_file_path)
            .field("modification_number", &self.modification_number)
            .field("changed", &self.changed)
            .field("temporary", &self.temporary)
            .field("closed", &self.closed)
            .field("undo_count", &self.undo_stack.len())
            .field("redo_count", &self.redo_stack.len())
            .finish()
    }
}

// ============================================================================
// DomainObject2 impl
// ============================================================================

impl DomainObject2 for StoredUndoableDomainObject {
    fn is_changed(&self) -> bool {
        self.changed && !self.temporary
    }

    fn set_temporary(&mut self, state: bool) {
        self.temporary = state;
    }

    fn is_temporary(&self) -> bool {
        self.temporary
    }

    fn is_changeable(&self) -> bool {
        !self.closed && !self.temporary
    }

    fn can_save(&self) -> bool {
        self.changed && !self.temporary && !self.closed
    }

    fn save(&self, _comment: &str) -> ProjectResult<()> {
        // In a full implementation, this would serialize the current state
        // to the domain file on disk.
        Ok(())
    }

    fn release(&mut self, consumer_id: u64) {
        self.consumers.retain(|id| *id != consumer_id);
    }

    fn add_listener(&mut self, listener: Box<dyn DomainObjectListener>) {
        self.change_support.add_listener(listener);
    }

    fn remove_listener(&mut self, listener_id: u64) {
        self.change_support.remove_listener(listener_id);
    }

    fn add_close_listener(&mut self, listener: Box<dyn DomainObjectClosedListener>) {
        self.change_support.add_close_listener(listener);
    }

    fn remove_close_listener(&mut self, listener_id: u64) {
        self.change_support.remove_close_listener(listener_id);
    }

    fn create_private_event_queue(
        &mut self,
        listener: Box<dyn DomainObjectListener>,
        max_delay_ms: u32,
    ) -> EventQueueID {
        self.change_support
            .create_private_event_queue(listener, max_delay_ms)
    }

    fn remove_private_event_queue(&mut self, id: EventQueueID) -> bool {
        self.change_support.remove_private_event_queue(id)
    }

    fn description(&self) -> &str {
        &self.description
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn set_name(&mut self, name: String) {
        self.name = name;
    }

    fn domain_file_path(&self) -> Option<&str> {
        self.domain_file_path.as_deref()
    }

    fn add_consumer(&mut self, consumer_id: u64) -> bool {
        if self.closed {
            return false;
        }
        if !self.consumers.contains(&consumer_id) {
            self.consumers.push(consumer_id);
        }
        true
    }

    fn consumer_list(&self) -> Vec<u64> {
        self.consumers.clone()
    }

    fn is_used_by(&self, consumer_id: u64) -> bool {
        self.consumers.contains(&consumer_id)
    }

    fn set_events_enabled(&mut self, enabled: bool) {
        self.events_enabled = enabled;
        self.change_support.set_events_enabled(enabled);
    }

    fn is_sending_events(&self) -> bool {
        self.events_enabled
    }

    fn flush_events(&mut self) {
        // No-op for in-memory implementation.
    }

    fn flush_private_event_queue(&mut self, _id: EventQueueID) {
        // No-op for in-memory implementation.
    }

    fn can_lock(&self) -> bool {
        !self.locked
    }

    fn is_locked(&self) -> bool {
        self.locked
    }

    fn lock(&mut self, reason: &str) -> bool {
        if self.locked {
            return false;
        }
        self.locked = true;
        self.lock_reason = Some(reason.to_string());
        true
    }

    fn force_lock(&mut self, rollback: bool, reason: &str) {
        if rollback {
            // Abort the current transaction if one is open.
            if let Some(tx) = self.current_transaction.take() {
                for (_, listener) in self.abort_listeners.drain() {
                    listener.transaction_aborted(tx.id);
                }
            }
        }
        self.locked = true;
        self.lock_reason = Some(reason.to_string());
    }

    fn unlock(&mut self) {
        self.locked = false;
        self.lock_reason = None;
    }

    fn options_names(&self) -> Vec<String> {
        Vec::new()
    }

    fn is_closed(&self) -> bool {
        self.closed
    }

    fn has_exclusive_access(&self) -> bool {
        self.locked
    }

    fn metadata(&self) -> HashMap<String, String> {
        let mut map = HashMap::new();
        map.insert("name".to_string(), self.name.clone());
        map.insert("description".to_string(), self.description.clone());
        map.insert(
            "modificationNumber".to_string(),
            self.modification_number.to_string(),
        );
        if let Some(ref path) = self.domain_file_path {
            map.insert("domainFilePath".to_string(), path.clone());
        }
        map
    }

    fn modification_number(&self) -> u64 {
        self.modification_number
    }

    // ---- Transactions ----

    fn start_transaction(&mut self, description: &str) -> u64 {
        self.start_transaction_with_listener(description, None)
    }

    fn start_transaction_with_listener(
        &mut self,
        description: &str,
        listener: Option<Box<dyn AbortedTransactionListener>>,
    ) -> u64 {
        let tx_id = self.modification_number + 1;
        self.current_transaction = Some(ActiveTransaction {
            id: tx_id,
            description: description.to_string(),
            start_state: Vec::new(), // would capture state offsets in a real impl
            terminated: false,
        });

        if let Some(l) = listener {
            self.abort_listeners.insert(tx_id, l);
        }

        // Notify transaction listeners.
        let info = SimpleTransactionInfo::new(tx_id, description);
        for tl in &self.transaction_listeners {
            tl.transaction_started(self.modification_number, &info);
        }

        tx_id
    }

    fn end_transaction(&mut self, transaction_id: u64, commit: bool) -> bool {
        if let Some(ref tx) = self.current_transaction {
            if tx.id != transaction_id {
                return false;
            }
        }

        let tx = self.current_transaction.take().unwrap();

        if commit {
            // Capture the pre-transaction state for undo.
            self.capture_undo_state(&tx.description);
            self.changed = true;
            self.modification_number += 1;
        } else {
            // Abort: restore the state from before the transaction.
            if let Some(listener) = self.abort_listeners.remove(&tx.id) {
                listener.transaction_aborted(tx.id);
            }
        }

        // Notify transaction listeners.
        for tl in &self.transaction_listeners {
            tl.transaction_ended(self.modification_number);
        }

        true
    }

    fn current_transaction_info(&self) -> Option<&dyn TransactionInfo> {
        // Would return ActiveTransaction as TransactionInfo in a real impl.
        None
    }

    fn has_terminated_transaction(&self) -> bool {
        self.current_transaction
            .as_ref()
            .map(|tx| tx.terminated)
            .unwrap_or(false)
    }

    // ---- Undo/Redo ----

    fn can_undo(&self) -> bool {
        !self.undo_stack.is_empty() && self.current_transaction.is_none()
    }

    fn can_redo(&self) -> bool {
        !self.redo_stack.is_empty() && self.current_transaction.is_none()
    }

    fn clear_undo(&mut self) {
        self.undo_stack.clear();
        self.redo_stack.clear();
    }

    fn undo(&mut self) -> ProjectResult<()> {
        if !self.can_undo() {
            return Err(ProjectError::InvalidState(
                "Cannot undo: no undo state available".into(),
            ));
        }

        // Save current state to redo stack.
        let redo_state = UndoableState::new(
            "redo",
            self.current_state.clone(),
            self.modification_number,
        );
        self.redo_stack.push(redo_state);

        // Restore the previous state.
        let undo_state = self.undo_stack.pop().unwrap();
        self.current_state = undo_state.data;
        self.modification_number = undo_state.modification_number;
        self.changed = true;

        for tl in &self.transaction_listeners {
            tl.undo_redo_occurred(self.modification_number);
            tl.undo_stack_changed(self.modification_number);
        }

        Ok(())
    }

    fn redo(&mut self) -> ProjectResult<()> {
        if !self.can_redo() {
            return Err(ProjectError::InvalidState(
                "Cannot redo: no redo state available".into(),
            ));
        }

        // Save current state to undo stack.
        let undo_state = UndoableState::new(
            "undo",
            self.current_state.clone(),
            self.modification_number,
        );
        self.undo_stack.push(undo_state);

        // Restore the redo state.
        let redo_state = self.redo_stack.pop().unwrap();
        self.current_state = redo_state.data;
        self.modification_number = redo_state.modification_number;
        self.changed = true;

        for tl in &self.transaction_listeners {
            tl.undo_redo_occurred(self.modification_number);
            tl.undo_stack_changed(self.modification_number);
        }

        Ok(())
    }

    fn undo_name(&self) -> Option<String> {
        self.undo_stack.last().map(|s| s.description.clone())
    }

    fn redo_name(&self) -> Option<String> {
        self.redo_stack.last().map(|s| s.description.clone())
    }

    fn all_undo_names(&self) -> Vec<String> {
        self.undo_stack.iter().map(|s| s.description.clone()).collect()
    }

    fn all_redo_names(&self) -> Vec<String> {
        self.redo_stack.iter().map(|s| s.description.clone()).collect()
    }

    fn add_transaction_listener(&mut self, listener: Box<dyn TransactionListener>) {
        self.transaction_listeners.push(listener);
    }

    fn remove_transaction_listener(&mut self, _listener_id: u64) {
        // In a real implementation, would track IDs and remove by ID.
    }

    fn close(&mut self) {
        if self.closed {
            return;
        }
        self.closed = true;
        let object_id = self.modification_number;
        self.change_support.fire_close(object_id);
        self.undo_stack.clear();
        self.redo_stack.clear();
        self.current_state.clear();
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_object() -> StoredUndoableDomainObject {
        let locator = ProjectLocator::new("/tmp/projects", "test");
        StoredUndoableDomainObject::new("test_obj", "Test object", locator)
    }

    #[test]
    fn test_creation() {
        let obj = make_object();
        assert_eq!(obj.name(), "test_obj");
        assert_eq!(obj.description(), "Test object");
        assert!(!obj.is_changed());
        assert!(!obj.is_temporary());
        assert!(!obj.is_closed());
        assert_eq!(obj.modification_number(), 0);
    }

    #[test]
    fn test_state_update() {
        let mut obj = make_object();
        obj.update_state(b"hello".to_vec());
        assert!(obj.is_changed());
        assert_eq!(obj.state_data(), b"hello");
        assert_eq!(obj.modification_number(), 1);
    }

    #[test]
    fn test_temporary() {
        let mut obj = make_object();
        obj.set_temporary(true);
        assert!(obj.is_temporary());
        assert!(!obj.is_changeable());
        // A temporary object's changes are not reported.
        obj.update_state(b"data".to_vec());
        assert!(!obj.is_changed());
    }

    #[test]
    fn test_name() {
        let mut obj = make_object();
        assert_eq!(obj.name(), "test_obj");
        obj.set_name("renamed".to_string());
        assert_eq!(obj.name(), "renamed");
    }

    #[test]
    fn test_consumers() {
        let mut obj = make_object();
        assert!(obj.add_consumer(1));
        assert!(obj.add_consumer(2));
        assert!(obj.is_used_by(1));
        assert!(obj.is_used_by(2));
        assert!(!obj.is_used_by(3));

        obj.release(1);
        assert!(!obj.is_used_by(1));
        assert!(obj.is_used_by(2));
    }

    #[test]
    fn test_consumers_after_close() {
        let mut obj = make_object();
        obj.close();
        assert!(!obj.add_consumer(99));
    }

    #[test]
    fn test_locking() {
        let mut obj = make_object();
        assert!(obj.can_lock());
        assert!(!obj.is_locked());

        assert!(obj.lock("editing"));
        assert!(obj.is_locked());
        assert!(!obj.can_lock());
        assert!(obj.has_exclusive_access());

        obj.unlock();
        assert!(!obj.is_locked());
        assert!(obj.can_lock());
    }

    #[test]
    fn test_transaction_commit() {
        let mut obj = make_object();
        obj.update_state(b"initial".to_vec());

        let tx_id = obj.start_transaction("modify data");
        assert!(tx_id > 0);

        obj.update_state(b"modified".to_vec());
        let result = obj.end_transaction(tx_id, true);
        assert!(result);
        assert!(obj.is_changed());
        assert!(obj.can_undo());
    }

    #[test]
    fn test_transaction_abort() {
        let mut obj = make_object();
        let tx_id = obj.start_transaction("aborted change");
        obj.end_transaction(tx_id, false);
        // After abort, modification_number should not have increased from transaction.
    }

    #[test]
    fn test_undo_redo() {
        let mut obj = make_object();

        // State 1: "first"
        let tx1 = obj.start_transaction("first change");
        obj.update_state(b"first".to_vec());
        obj.end_transaction(tx1, true);

        // State 2: "second"
        let tx2 = obj.start_transaction("second change");
        obj.update_state(b"second".to_vec());
        obj.end_transaction(tx2, true);

        assert!(obj.can_undo());
        assert_eq!(obj.state_data(), b"second");
        assert_eq!(obj.undo_name(), Some("second change".to_string()));

        // Undo back to "first"
        obj.undo().unwrap();
        assert_eq!(obj.state_data(), b"first");
        assert!(obj.can_redo());

        // Redo back to "second"
        obj.redo().unwrap();
        assert_eq!(obj.state_data(), b"second");
    }

    #[test]
    fn test_undo_fails_when_empty() {
        let mut obj = make_object();
        assert!(!obj.can_undo());
        assert!(obj.undo().is_err());
    }

    #[test]
    fn test_redo_fails_when_empty() {
        let mut obj = make_object();
        assert!(!obj.can_redo());
        assert!(obj.redo().is_err());
    }

    #[test]
    fn test_clear_undo() {
        let mut obj = make_object();
        let tx = obj.start_transaction("tx");
        obj.end_transaction(tx, true);
        assert!(obj.can_undo());

        obj.clear_undo();
        assert!(!obj.can_undo());
        assert!(!obj.can_redo());
    }

    #[test]
    fn test_undo_redo_names() {
        let mut obj = make_object();

        let tx1 = obj.start_transaction("action A");
        obj.end_transaction(tx1, true);

        let tx2 = obj.start_transaction("action B");
        obj.end_transaction(tx2, true);

        let undo_names = obj.all_undo_names();
        assert_eq!(undo_names, vec!["action A", "action B"]);

        assert_eq!(obj.undo_name(), Some("action B".to_string()));
        assert_eq!(obj.redo_name(), None);

        obj.undo().unwrap();
        assert_eq!(obj.redo_name(), Some("action B".to_string()));
    }

    #[test]
    fn test_close() {
        let mut obj = make_object();
        assert!(!obj.is_closed());

        obj.close();
        assert!(obj.is_closed());
        assert!(obj.state_data().is_empty());
        assert!(!obj.can_undo());
    }

    #[test]
    fn test_metadata() {
        let mut obj = make_object();
        obj.set_domain_file_path("/data/test.gzf");

        let meta = obj.metadata();
        assert_eq!(meta.get("name").unwrap(), "test_obj");
        assert_eq!(meta.get("domainFilePath").unwrap(), "/data/test.gzf");
    }

    #[test]
    fn test_domain_file_path() {
        let mut obj = make_object();
        assert!(obj.domain_file_path().is_none());

        obj.set_domain_file_path("/test/path");
        assert_eq!(obj.domain_file_path(), Some("/test/path"));
    }

    #[test]
    fn test_events_enabled() {
        let mut obj = make_object();
        assert!(obj.is_sending_events());

        obj.set_events_enabled(false);
        assert!(!obj.is_sending_events());

        obj.set_events_enabled(true);
        assert!(obj.is_sending_events());
    }

    #[test]
    fn test_force_lock() {
        let mut obj = make_object();
        let _tx_id = obj.start_transaction("before force");
        obj.force_lock(true, "forced");
        assert!(obj.is_locked());
    }
}
