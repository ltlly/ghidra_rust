//! GUI-level domain object abstractions.
//!
//! Ports the GUI-facing parts of Ghidra's `framework.model.DomainObject`
//! interface.  Builds on the core-level [`DomainObject`] trait from
//! `ghidra-core` and adds the GUI-specific concerns that the framework
//! model Java interface exposes: transactions, event queues, options,
//! metadata, undo/redo with named transaction history, and
//! consumer/reference tracking.
//!
//! This module is intentionally independent of any particular concrete
//! domain object (Program, DataTypeArchive, etc.) -- it defines the
//! traits and supporting types that the GUI layer generically depends on.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::time::SystemTime;

// ---------------------------------------------------------------------------
// Options / property lists
// ---------------------------------------------------------------------------

/// A named group of key/value options on a domain object.
///
/// Mirrors Java's `Options` interface from `ghidra.framework.options`.
/// Each domain object may expose multiple named option lists (e.g. "Display",
/// "Listing Fields", etc.).
#[derive(Debug, Clone, Default)]
pub struct DomainOptions {
    /// The name of this options group.
    name: String,
    /// The key/value pairs in this group.
    entries: HashMap<String, OptionValue>,
}

/// A single option value within a [`DomainOptions`] list.
#[derive(Debug, Clone)]
pub enum OptionValue {
    /// A boolean value.
    Bool(bool),
    /// An integer value.
    Int(i64),
    /// A floating-point value.
    Double(f64),
    /// A string value.
    String(String),
}

impl DomainOptions {
    /// Create a new options group.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            entries: HashMap::new(),
        }
    }

    /// Returns the name of this options group.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Set a boolean option.
    pub fn set_bool(&mut self, key: impl Into<String>, value: bool) {
        self.entries.insert(key.into(), OptionValue::Bool(value));
    }

    /// Set an integer option.
    pub fn set_int(&mut self, key: impl Into<String>, value: i64) {
        self.entries.insert(key.into(), OptionValue::Int(value));
    }

    /// Set a double option.
    pub fn set_double(&mut self, key: impl Into<String>, value: f64) {
        self.entries.insert(key.into(), OptionValue::Double(value));
    }

    /// Set a string option.
    pub fn set_string(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.entries.insert(key.into(), OptionValue::String(value.into()));
    }

    /// Get a boolean option.
    pub fn get_bool(&self, key: &str) -> Option<bool> {
        match self.entries.get(key)? {
            OptionValue::Bool(v) => Some(*v),
            _ => None,
        }
    }

    /// Get an integer option.
    pub fn get_int(&self, key: &str) -> Option<i64> {
        match self.entries.get(key)? {
            OptionValue::Int(v) => Some(*v),
            _ => None,
        }
    }

    /// Get a double option.
    pub fn get_double(&self, key: &str) -> Option<f64> {
        match self.entries.get(key)? {
            OptionValue::Double(v) => Some(*v),
            _ => None,
        }
    }

    /// Get a string option.
    pub fn get_string(&self, key: &str) -> Option<&str> {
        match self.entries.get(key)? {
            OptionValue::String(v) => Some(v.as_str()),
            _ => None,
        }
    }

    /// Returns all option keys in this group.
    pub fn keys(&self) -> Vec<&str> {
        self.entries.keys().map(|s| s.as_str()).collect()
    }

    /// Returns the number of options in this group.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if this options group is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Event types
// ---------------------------------------------------------------------------

/// High-level domain object event categories.
///
/// Mirrors `DomainObjectEvent` from the Java framework.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DomainObjectEvent {
    /// The object was saved.
    Saved,
    /// The associated domain file changed (e.g. rename / save-as).
    FileChanged,
    /// The object was renamed.
    Renamed,
    /// The object was restored from a save or undo.
    Restored,
    /// A property on the object changed.
    PropertyChanged,
    /// The object was closed.
    Closed,
    /// A fatal error occurred rendering the object invalid.
    Error,
}

/// A listener that receives batched domain-object change events.
///
/// GUI components register listeners so they can refresh views when the
/// underlying data changes.
pub trait DomainObjectListener: fmt::Debug + Send + Sync {
    /// Called when one or more events have occurred on the domain object.
    fn domain_object_changed(&self, events: &[DomainObjectEvent]);
}

/// A listener that is notified when a domain object is about to be closed.
pub trait DomainObjectClosedListener: fmt::Debug + Send + Sync {
    /// Called when the domain object is closing.
    fn domain_object_closed(&self);
}

/// A listener for changes to the domain *file* associated with a domain
/// object (e.g. rename, save-as).  Unlike `DomainObjectListener`, these
/// notifications are not buffered.
pub trait DomainObjectFileListener: fmt::Debug + Send + Sync {
    /// Called when the associated domain file changes.
    fn domain_file_changed(&self);
}

// ---------------------------------------------------------------------------
// Event queue
// ---------------------------------------------------------------------------

/// Unique identifier for a private event queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EventQueueID(u64);

impl EventQueueID {
    /// Create a new event queue ID.
    pub fn new(id: u64) -> Self {
        Self(id)
    }

    /// Returns the raw numeric ID.
    pub fn as_u64(&self) -> u64 {
        self.0
    }
}

/// A private event queue that buffers events independently from the main
/// queue.
#[derive(Debug)]
#[allow(dead_code)]
struct PrivateEventQueue {
    id: EventQueueID,
    #[allow(dead_code)]
    listener: Arc<dyn DomainObjectListener>,
    /// Buffer of pending events.
    pending: Vec<DomainObjectEvent>,
    /// Maximum delay in milliseconds before events are flushed.
    #[allow(dead_code)]
    max_delay_ms: u32,
}

// ---------------------------------------------------------------------------
// Transaction support
// ---------------------------------------------------------------------------

/// Listener that is notified when a transaction is aborted.
pub trait AbortedTransactionListener: fmt::Debug + Send + Sync {
    /// Called when the transaction is aborted.
    fn transaction_aborted(&self);
}

/// Listener for transaction lifecycle events (start, end, undo, redo).
pub trait TransactionListener: fmt::Debug + Send + Sync {
    /// Called when a new transaction starts.
    fn transaction_started(&self, tx_id: u32, description: &str);
    /// Called when a transaction ends (committed or rolled back).
    fn transaction_ended(&self, tx_id: u32, committed: bool);
}

/// Information about the currently active transaction.
#[derive(Debug, Clone)]
pub struct TransactionInfo {
    /// Unique transaction ID.
    pub id: u32,
    /// Human-readable description.
    pub description: String,
    /// When the transaction was started.
    pub started_at: SystemTime,
    /// Whether this is a sub-transaction.
    pub is_sub_transaction: bool,
}

impl TransactionInfo {
    /// Create new transaction info.
    pub fn new(id: u32, description: impl Into<String>) -> Self {
        Self {
            id,
            description: description.into(),
            started_at: SystemTime::now(),
            is_sub_transaction: false,
        }
    }

    /// Mark this transaction as a sub-transaction.
    pub fn with_sub(mut self, is_sub: bool) -> Self {
        self.is_sub_transaction = is_sub;
        self
    }
}

/// RAII guard that commits or rolls back a transaction on drop.
///
/// This mirrors the Java `try (Transaction tx = dobj.openTransaction(...))`
/// pattern.
pub struct TransactionGuard<'a> {
    obj: &'a mut dyn GuiDomainObject,
    tx_id: u32,
    committed: bool,
}

impl<'a> TransactionGuard<'a> {
    /// Begin a new transaction, returning a guard.
    pub fn begin(obj: &'a mut dyn GuiDomainObject, description: &str) -> Self {
        let tx_id = obj.start_transaction(description);
        Self {
            obj,
            tx_id,
            committed: false,
        }
    }

    /// Mark the transaction as committed (changes will be kept).
    pub fn commit(&mut self) {
        self.committed = true;
    }

    /// Returns the transaction ID.
    pub fn id(&self) -> u32 {
        self.tx_id
    }
}

impl<'a> Drop for TransactionGuard<'a> {
    fn drop(&mut self) {
        self.obj.end_transaction(self.tx_id, self.committed);
    }
}

// ---------------------------------------------------------------------------
// GuiDomainObject trait
// ---------------------------------------------------------------------------

/// The GUI-level domain object interface.
///
/// This extends the minimal core `DomainObject` concept with the full set
/// of methods that Ghidra's GUI framework expects: transactions, event
/// queues, options, metadata, consumer tracking, and undo/redo.
pub trait GuiDomainObject: fmt::Debug + Send + Sync {
    // -- identity ----------------------------------------------------------

    /// Returns a word or short phrase describing this object for users.
    fn get_description(&self) -> &str;

    /// Returns the display name.
    fn get_name(&self) -> &str;

    /// Sets the display name.
    fn set_name(&mut self, name: &str);

    /// Returns the path of the associated domain file, if any.
    fn get_domain_file_path(&self) -> Option<String>;

    // -- change tracking ---------------------------------------------------

    /// Returns `true` if the object has unsaved changes.
    fn is_changed(&self) -> bool;

    /// Set the temporary state.  Temporary objects always report
    /// `is_changed() == false`.
    fn set_temporary(&mut self, state: bool);

    /// Returns `true` if this object is temporary.
    fn is_temporary(&self) -> bool;

    /// Returns `true` if changes are permitted.
    fn is_changeable(&self) -> bool;

    /// Returns `true` if the object can be saved.
    fn can_save(&self) -> bool;

    // -- persistence -------------------------------------------------------

    /// Save the object to its backing store.
    fn save(&mut self, comment: &str) -> Result<(), DomainObjectGuiError>;

    /// Save (serialize) the current content to a packed output file.
    ///
    /// Mirrors Java's `saveToPackedFile(File, TaskMonitor)`.
    fn save_to_packed_file(&self, _output_path: &std::path::Path) -> Result<(), DomainObjectGuiError> {
        Err(DomainObjectGuiError::NotSupported(
            "save_to_packed_file is not supported".into(),
        ))
    }

    // -- consumer management -----------------------------------------------

    /// Release a consumer.  When the last consumer releases, the object
    /// is closed.
    fn release(&mut self, consumer: &str);

    /// Add a consumer.  Returns `false` if the object is already closed.
    fn add_consumer(&mut self, consumer: &str) -> bool;

    /// Returns the list of active consumers.
    fn get_consumer_list(&self) -> Vec<String>;

    /// Returns `true` if the given consumer is using this object.
    fn is_used_by(&self, consumer: &str) -> bool;

    // -- listeners ---------------------------------------------------------

    /// Add a domain object listener.
    fn add_listener(&mut self, listener: Arc<dyn DomainObjectListener>);

    /// Remove a domain object listener.
    fn remove_listener(&mut self, listener: &Arc<dyn DomainObjectListener>);

    /// Add a close listener.
    fn add_close_listener(&mut self, listener: Arc<dyn DomainObjectClosedListener>);

    /// Remove a close listener.
    fn remove_close_listener(&mut self, listener: &Arc<dyn DomainObjectClosedListener>);

    /// Add a domain file listener.
    fn add_domain_file_listener(&mut self, listener: Arc<dyn DomainObjectFileListener>);

    /// Remove a domain file listener.
    fn remove_domain_file_listener(&mut self, listener: &Arc<dyn DomainObjectFileListener>);

    // -- private event queues ----------------------------------------------

    /// Create a private event queue.
    fn create_private_event_queue(
        &mut self,
        listener: Arc<dyn DomainObjectListener>,
        max_delay_ms: u32,
    ) -> EventQueueID;

    /// Remove a private event queue.  Returns `true` if it existed.
    fn remove_private_event_queue(&mut self, id: EventQueueID) -> bool;

    /// Flush events from a specific private queue.
    fn flush_private_event_queue(&mut self, id: EventQueueID);

    // -- events ------------------------------------------------------------

    /// Enable or disable event delivery.
    fn set_events_enabled(&mut self, enabled: bool);

    /// Returns `true` if events are being sent.
    fn is_sending_events(&self) -> bool;

    /// Flush all pending events to listeners.
    fn flush_events(&mut self);

    // -- locking -----------------------------------------------------------

    /// Returns `true` if a modification lock can be obtained.
    fn can_lock(&self) -> bool;

    /// Returns `true` if the object currently has a modification lock.
    fn is_locked(&self) -> bool;

    /// Attempt to acquire a modification lock.
    fn lock(&mut self, reason: &str) -> bool;

    /// Force a transaction lock and terminate the current transaction.
    fn force_lock(&mut self, rollback: bool, reason: &str);

    /// Release a modification lock.
    fn unlock(&mut self);

    // -- options -----------------------------------------------------------

    /// Returns all option names.
    fn get_options_names(&self) -> Vec<String>;

    /// Get the options (property list) for the given name.
    ///
    /// Returns `None` if no options group with the given name exists.
    /// Mirrors Java's `getOptions(String)`.
    fn get_options(&self, _name: &str) -> Option<&DomainOptions> {
        None
    }

    // -- state -------------------------------------------------------------

    /// Returns `true` if the object has been closed.
    fn is_closed(&self) -> bool;

    /// Returns `true` if the user has exclusive access.
    fn has_exclusive_access(&self) -> bool;

    /// Returns all stored metadata as key/value pairs.
    fn get_metadata(&self) -> HashMap<String, String>;

    /// Returns a monotonically increasing modification number.
    fn get_modification_number(&self) -> u64;

    // -- transactions ------------------------------------------------------

    /// Start a new transaction.  Returns a transaction ID.
    fn start_transaction(&mut self, description: &str) -> u32;

    /// End a transaction.
    fn end_transaction(&mut self, tx_id: u32, commit: bool) -> bool;

    /// Returns info about the current transaction, if any.
    fn get_current_transaction_info(&self) -> Option<TransactionInfo>;

    /// Returns `true` if the last transaction was terminated.
    fn has_terminated_transaction(&self) -> bool;

    /// Start a new transaction with an abort listener.
    ///
    /// When the transaction is aborted (rolled back), the provided listener
    /// will be notified.  Mirrors Java's
    /// `startTransaction(String, AbortedTransactionListener)`.
    fn start_transaction_with_abort_listener(
        &mut self,
        description: &str,
        _listener: Arc<dyn AbortedTransactionListener>,
    ) -> u32 {
        // Default implementation ignores the listener.
        self.start_transaction(description)
    }

    // -- synchronized domain objects ---------------------------------------

    /// Return the set of domain objects synchronized with this one via a
    /// shared transaction manager, or an empty slice if none.
    ///
    /// Mirrors Java's `getSynchronizedDomainObjects()`.
    fn get_synchronized_domain_objects(&self) -> &[String] {
        &[]
    }

    /// Synchronize another domain object with this one using a shared
    /// transaction manager.
    ///
    /// Mirrors Java's `addSynchronizedDomainObject(DomainObject)`.
    fn add_synchronized_domain_object(&mut self, _domain_file_path: String) -> Result<(), DomainObjectGuiError> {
        Err(DomainObjectGuiError::NotSupported(
            "add_synchronized_domain_object is not supported".into(),
        ))
    }

    /// Release this domain object from a shared transaction manager.
    ///
    /// Mirrors Java's `releaseSynchronizedDomainObject()`.
    fn release_synchronized_domain_object(&mut self) -> Result<(), DomainObjectGuiError> {
        Err(DomainObjectGuiError::NotSupported(
            "release_synchronized_domain_object is not supported".into(),
        ))
    }

    // -- undo / redo -------------------------------------------------------

    /// Returns `true` if there is a state to undo to.
    fn can_undo(&self) -> bool;

    /// Returns `true` if there is a state to redo to.
    fn can_redo(&self) -> bool;

    /// Clear all undo/redo history.
    fn clear_undo(&mut self);

    /// Undo the last transaction.
    fn undo(&mut self) -> Result<(), DomainObjectGuiError>;

    /// Redo the last undone transaction.
    fn redo(&mut self) -> Result<(), DomainObjectGuiError>;

    /// Returns the name of the next undoable transaction.
    fn get_undo_name(&self) -> Option<String>;

    /// Returns the name of the next redoable transaction.
    fn get_redo_name(&self) -> Option<String>;

    /// Returns all undo transaction names.
    fn get_all_undo_names(&self) -> Vec<String>;

    /// Returns all redo transaction names.
    fn get_all_redo_names(&self) -> Vec<String>;

    /// Add a transaction listener.
    fn add_transaction_listener(&mut self, listener: Arc<dyn TransactionListener>);

    /// Remove a transaction listener.
    fn remove_transaction_listener(&mut self, listener: &Arc<dyn TransactionListener>);
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors that can occur in GUI-level domain object operations.
#[derive(Debug, Clone)]
pub enum DomainObjectGuiError {
    /// The object is locked by another consumer.
    Locked(String),
    /// The object has been closed.
    Closed,
    /// An I/O error occurred.
    IoError(String),
    /// The operation is read-only.
    ReadOnly(String),
    /// A concurrent modification was detected.
    ConcurrentModification(String),
    /// The operation was cancelled.
    Cancelled,
    /// The operation is not supported.
    NotSupported(String),
    /// A generic error.
    Other(String),
}

impl fmt::Display for DomainObjectGuiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Locked(msg) => write!(f, "Locked: {}", msg),
            Self::Closed => write!(f, "Domain object is closed"),
            Self::IoError(msg) => write!(f, "I/O error: {}", msg),
            Self::ReadOnly(msg) => write!(f, "Read-only: {}", msg),
            Self::ConcurrentModification(msg) => {
                write!(f, "Concurrent modification: {}", msg)
            }
            Self::Cancelled => write!(f, "Operation cancelled"),
            Self::NotSupported(msg) => write!(f, "Not supported: {}", msg),
            Self::Other(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for DomainObjectGuiError {}

// ---------------------------------------------------------------------------
// Synchronized domain objects support
// ---------------------------------------------------------------------------

/// Manages a group of domain objects that share a transaction manager.
///
/// When objects are synchronized, a transaction started on one object
/// applies to all objects in the group.
#[derive(Debug, Default)]
pub struct SynchronizedDomainObjects {
    objects: Vec<String>, // domain file paths
}

impl SynchronizedDomainObjects {
    /// Create a new empty synchronization group.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an object path to the group.
    pub fn add(&mut self, path: String) {
        if !self.objects.contains(&path) {
            self.objects.push(path);
        }
    }

    /// Remove an object path from the group.
    pub fn remove(&mut self, path: &str) {
        self.objects.retain(|p| p != path);
    }

    /// Returns the paths of all synchronized objects.
    pub fn get_paths(&self) -> &[String] {
        &self.objects
    }

    /// Returns `true` if the group is empty.
    pub fn is_empty(&self) -> bool {
        self.objects.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    // -- Mock listener -----------------------------------------------------

    #[derive(Debug)]
    struct MockAbortedListener;

    impl AbortedTransactionListener for MockAbortedListener {
        fn transaction_aborted(&self) {}
    }

    #[derive(Debug)]
    struct MockListener {
        change_count: Arc<AtomicU32>,
    }

    impl MockListener {
        fn new() -> (Self, Arc<AtomicU32>) {
            let count = Arc::new(AtomicU32::new(0));
            (Self { change_count: count.clone() }, count)
        }
    }

    impl DomainObjectListener for MockListener {
        fn domain_object_changed(&self, _events: &[DomainObjectEvent]) {
            self.change_count.fetch_add(1, Ordering::Relaxed);
        }
    }

    // -- Mock domain object ------------------------------------------------

    #[derive(Debug)]
    struct MockGuiDomainObject {
        name: String,
        changed: bool,
        temporary: bool,
        closed: bool,
        locked: bool,
        events_enabled: bool,
        mod_number: u64,
        consumers: Vec<String>,
        listeners: Vec<Arc<dyn DomainObjectListener>>,
        next_tx_id: u32,
        current_tx: Option<TransactionInfo>,
        undo_stack: Vec<String>,
        redo_stack: Vec<String>,
    }

    impl MockGuiDomainObject {
        fn new(name: &str) -> Self {
            Self {
                name: name.to_string(),
                changed: false,
                temporary: false,
                closed: false,
                locked: false,
                events_enabled: true,
                mod_number: 0,
                consumers: Vec::new(),
                listeners: Vec::new(),
                next_tx_id: 1,
                current_tx: None,
                undo_stack: Vec::new(),
                redo_stack: Vec::new(),
            }
        }
    }

    impl GuiDomainObject for MockGuiDomainObject {
        fn get_description(&self) -> &str { "Mock Domain Object" }
        fn get_name(&self) -> &str { &self.name }
        fn set_name(&mut self, name: &str) { self.name = name.to_string(); }
        fn get_domain_file_path(&self) -> Option<String> { None }
        fn is_changed(&self) -> bool { self.changed && !self.temporary }
        fn set_temporary(&mut self, state: bool) { self.temporary = state; }
        fn is_temporary(&self) -> bool { self.temporary }
        fn is_changeable(&self) -> bool { !self.closed }
        fn can_save(&self) -> bool { !self.closed && self.changed }
        fn save(&mut self, _comment: &str) -> Result<(), DomainObjectGuiError> {
            self.changed = false;
            Ok(())
        }
        fn release(&mut self, consumer: &str) {
            self.consumers.retain(|c| c != consumer);
            if self.consumers.is_empty() {
                self.closed = true;
            }
        }
        fn add_consumer(&mut self, consumer: &str) -> bool {
            if self.closed { return false; }
            self.consumers.push(consumer.to_string());
            true
        }
        fn get_consumer_list(&self) -> Vec<String> { self.consumers.clone() }
        fn is_used_by(&self, consumer: &str) -> bool { self.consumers.contains(&consumer.to_string()) }
        fn add_listener(&mut self, listener: Arc<dyn DomainObjectListener>) {
            self.listeners.push(listener);
        }
        fn remove_listener(&mut self, _listener: &Arc<dyn DomainObjectListener>) {}
        fn add_close_listener(&mut self, _listener: Arc<dyn DomainObjectClosedListener>) {}
        fn remove_close_listener(&mut self, _listener: &Arc<dyn DomainObjectClosedListener>) {}
        fn add_domain_file_listener(&mut self, _listener: Arc<dyn DomainObjectFileListener>) {}
        fn remove_domain_file_listener(&mut self, _listener: &Arc<dyn DomainObjectFileListener>) {}
        fn create_private_event_queue(&mut self, _listener: Arc<dyn DomainObjectListener>, _max_delay_ms: u32) -> EventQueueID {
            EventQueueID::new(1)
        }
        fn remove_private_event_queue(&mut self, _id: EventQueueID) -> bool { true }
        fn flush_private_event_queue(&mut self, _id: EventQueueID) {}
        fn set_events_enabled(&mut self, enabled: bool) { self.events_enabled = enabled; }
        fn is_sending_events(&self) -> bool { self.events_enabled }
        fn flush_events(&mut self) {}
        fn can_lock(&self) -> bool { !self.locked }
        fn is_locked(&self) -> bool { self.locked }
        fn lock(&mut self, _reason: &str) -> bool {
            if self.locked { return false; }
            self.locked = true;
            true
        }
        fn force_lock(&mut self, _rollback: bool, _reason: &str) { self.locked = true; }
        fn unlock(&mut self) { self.locked = false; }
        fn get_options_names(&self) -> Vec<String> { vec![] }
        fn is_closed(&self) -> bool { self.closed }
        fn has_exclusive_access(&self) -> bool { true }
        fn get_metadata(&self) -> HashMap<String, String> { HashMap::new() }
        fn get_modification_number(&self) -> u64 { self.mod_number }
        fn start_transaction(&mut self, description: &str) -> u32 {
            let id = self.next_tx_id;
            self.next_tx_id += 1;
            self.current_tx = Some(TransactionInfo::new(id, description));
            id
        }
        fn end_transaction(&mut self, _tx_id: u32, commit: bool) -> bool {
            if commit {
                self.mod_number += 1;
                if let Some(ref tx) = self.current_tx {
                    self.undo_stack.push(tx.description.clone());
                    self.redo_stack.clear();
                }
            }
            self.current_tx = None;
            commit
        }
        fn get_current_transaction_info(&self) -> Option<TransactionInfo> { self.current_tx.clone() }
        fn has_terminated_transaction(&self) -> bool { false }
        fn can_undo(&self) -> bool { !self.undo_stack.is_empty() }
        fn can_redo(&self) -> bool { !self.redo_stack.is_empty() }
        fn clear_undo(&mut self) { self.undo_stack.clear(); self.redo_stack.clear(); }
        fn undo(&mut self) -> Result<(), DomainObjectGuiError> {
            if let Some(name) = self.undo_stack.pop() {
                self.redo_stack.push(name);
                Ok(())
            } else {
                Err(DomainObjectGuiError::Other("Nothing to undo".into()))
            }
        }
        fn redo(&mut self) -> Result<(), DomainObjectGuiError> {
            if let Some(name) = self.redo_stack.pop() {
                self.undo_stack.push(name);
                Ok(())
            } else {
                Err(DomainObjectGuiError::Other("Nothing to redo".into()))
            }
        }
        fn get_undo_name(&self) -> Option<String> { self.undo_stack.last().cloned() }
        fn get_redo_name(&self) -> Option<String> { self.redo_stack.last().cloned() }
        fn get_all_undo_names(&self) -> Vec<String> { self.undo_stack.clone() }
        fn get_all_redo_names(&self) -> Vec<String> { self.redo_stack.clone() }
        fn add_transaction_listener(&mut self, _listener: Arc<dyn TransactionListener>) {}
        fn remove_transaction_listener(&mut self, _listener: &Arc<dyn TransactionListener>) {}
    }

    // -- Tests -------------------------------------------------------------

    #[test]
    fn test_name_and_description() {
        let obj = MockGuiDomainObject::new("TestProgram");
        assert_eq!(obj.get_name(), "TestProgram");
        assert_eq!(obj.get_description(), "Mock Domain Object");
    }

    #[test]
    fn test_set_name() {
        let mut obj = MockGuiDomainObject::new("Old");
        obj.set_name("New");
        assert_eq!(obj.get_name(), "New");
    }

    #[test]
    fn test_change_tracking() {
        let mut obj = MockGuiDomainObject::new("Test");
        assert!(!obj.is_changed());
        obj.changed = true;
        assert!(obj.is_changed());
    }

    #[test]
    fn test_temporary_suppresses_changed() {
        let mut obj = MockGuiDomainObject::new("Test");
        obj.changed = true;
        assert!(obj.is_changed());
        obj.set_temporary(true);
        assert!(!obj.is_changed());
        assert!(obj.is_temporary());
    }

    #[test]
    fn test_consumer_management() {
        let mut obj = MockGuiDomainObject::new("Test");
        assert!(obj.add_consumer("tool1"));
        assert!(obj.add_consumer("tool2"));
        assert!(obj.is_used_by("tool1"));
        assert!(!obj.is_used_by("tool3"));
        assert_eq!(obj.get_consumer_list().len(), 2);

        obj.release("tool1");
        assert!(!obj.is_used_by("tool1"));
        assert!(!obj.is_closed());

        obj.release("tool2");
        assert!(obj.is_closed());
        assert!(!obj.add_consumer("tool3"));
    }

    #[test]
    fn test_locking() {
        let mut obj = MockGuiDomainObject::new("Test");
        assert!(obj.can_lock());
        assert!(!obj.is_locked());
        assert!(obj.lock("editing"));
        assert!(obj.is_locked());
        assert!(!obj.can_lock());
        assert!(!obj.lock("double lock"));
        obj.unlock();
        assert!(!obj.is_locked());
    }

    #[test]
    fn test_transaction_lifecycle() {
        let mut obj = MockGuiDomainObject::new("Test");
        let tx_id = obj.start_transaction("edit code");
        assert!(obj.get_current_transaction_info().is_some());
        assert_eq!(obj.get_current_transaction_info().unwrap().description, "edit code");

        obj.changed = true;
        let committed = obj.end_transaction(tx_id, true);
        assert!(committed);
        assert!(obj.get_current_transaction_info().is_none());
        assert_eq!(obj.get_modification_number(), 1);
    }

    #[test]
    fn test_transaction_rollback() {
        let mut obj = MockGuiDomainObject::new("Test");
        let tx_id = obj.start_transaction("bad change");
        obj.changed = true;
        let committed = obj.end_transaction(tx_id, false);
        assert!(!committed);
        assert_eq!(obj.get_modification_number(), 0);
    }

    #[test]
    fn test_undo_redo() {
        let mut obj = MockGuiDomainObject::new("Test");
        assert!(!obj.can_undo());
        assert!(!obj.can_redo());

        let tx1 = obj.start_transaction("change 1");
        obj.end_transaction(tx1, true);
        assert!(obj.can_undo());
        assert_eq!(obj.get_undo_name(), Some("change 1".into()));

        obj.undo().unwrap();
        assert!(obj.can_redo());
        assert_eq!(obj.get_redo_name(), Some("change 1".into()));

        obj.redo().unwrap();
        assert!(obj.can_undo());
        assert!(!obj.can_redo());
    }

    #[test]
    fn test_clear_undo() {
        let mut obj = MockGuiDomainObject::new("Test");
        let tx = obj.start_transaction("change");
        obj.end_transaction(tx, true);
        obj.clear_undo();
        assert!(!obj.can_undo());
        assert!(!obj.can_redo());
    }

    #[test]
    fn test_undo_redo_names() {
        let mut obj = MockGuiDomainObject::new("Test");
        let tx1 = obj.start_transaction("first");
        obj.end_transaction(tx1, true);
        let tx2 = obj.start_transaction("second");
        obj.end_transaction(tx2, true);

        let names = obj.get_all_undo_names();
        assert_eq!(names, vec!["first", "second"]);
    }

    #[test]
    fn test_save() {
        let mut obj = MockGuiDomainObject::new("Test");
        obj.changed = true;
        obj.save("initial save").unwrap();
        assert!(!obj.is_changed());
    }

    #[test]
    fn test_event_queue_id() {
        let id = EventQueueID::new(42);
        assert_eq!(id.as_u64(), 42);
    }

    #[test]
    fn test_domain_object_event_variants() {
        assert_ne!(DomainObjectEvent::Saved, DomainObjectEvent::Closed);
        assert_eq!(DomainObjectEvent::Renamed, DomainObjectEvent::Renamed);
    }

    #[test]
    fn test_error_display() {
        let err = DomainObjectGuiError::Locked("user1".into());
        assert!(err.to_string().contains("Locked"));

        let err = DomainObjectGuiError::Closed;
        assert!(err.to_string().contains("closed"));

        let err = DomainObjectGuiError::Cancelled;
        assert!(err.to_string().contains("cancelled"));

        let err = DomainObjectGuiError::IoError("disk full".into());
        assert!(err.to_string().contains("disk full"));
    }

    #[test]
    fn test_transaction_guard_commit() {
        let mut obj = MockGuiDomainObject::new("Test");
        {
            let mut guard = TransactionGuard::begin(&mut obj, "guarded change");
            // The guard holds &mut obj; we mark changed through the trait.
            guard.commit();
        }
        // After the guard drops, we can inspect the result.
        // The mock end_transaction with commit=true increments mod_number.
        assert_eq!(obj.get_modification_number(), 1);
        assert!(obj.get_current_transaction_info().is_none());
    }

    #[test]
    fn test_transaction_guard_rollback() {
        let mut obj = MockGuiDomainObject::new("Test");
        {
            let _guard = TransactionGuard::begin(&mut obj, "abandoned change");
            // guard dropped without commit -> rollback (commit=false)
        }
        assert_eq!(obj.get_modification_number(), 0);
    }

    #[test]
    fn test_synchronized_objects() {
        let mut sync = SynchronizedDomainObjects::new();
        assert!(sync.is_empty());

        sync.add("/path/a".into());
        sync.add("/path/b".into());
        sync.add("/path/a".into()); // duplicate, ignored
        assert_eq!(sync.get_paths().len(), 2);

        sync.remove("/path/a");
        assert_eq!(sync.get_paths().len(), 1);
        assert_eq!(sync.get_paths()[0], "/path/b");
    }

    #[test]
    fn test_transaction_info() {
        let info = TransactionInfo::new(7, "edit symbols");
        assert_eq!(info.id, 7);
        assert_eq!(info.description, "edit symbols");
        assert!(!info.is_sub_transaction);

        let sub = TransactionInfo::new(8, "sub").with_sub(true);
        assert!(sub.is_sub_transaction);
    }

    #[test]
    fn test_events_enabled() {
        let mut obj = MockGuiDomainObject::new("Test");
        assert!(obj.is_sending_events());
        obj.set_events_enabled(false);
        assert!(!obj.is_sending_events());
    }

    // -- Options tests -----------------------------------------------------

    #[test]
    fn test_domain_options_basic() {
        let mut opts = DomainOptions::new("Display");
        assert_eq!(opts.name(), "Display");
        assert!(opts.is_empty());

        opts.set_bool("show_line_numbers", true);
        opts.set_int("font_size", 14);
        opts.set_double("zoom", 1.5);
        opts.set_string("theme", "dark");

        assert_eq!(opts.len(), 4);
        assert_eq!(opts.get_bool("show_line_numbers"), Some(true));
        assert_eq!(opts.get_int("font_size"), Some(14));
        assert_eq!(opts.get_double("zoom"), Some(1.5));
        assert_eq!(opts.get_string("theme"), Some("dark"));
    }

    #[test]
    fn test_domain_options_missing_key() {
        let opts = DomainOptions::new("Empty");
        assert!(opts.get_bool("nope").is_none());
        assert!(opts.get_int("nope").is_none());
    }

    #[test]
    fn test_domain_options_type_mismatch() {
        let mut opts = DomainOptions::new("Test");
        opts.set_bool("flag", true);
        // Asking for int on a bool key returns None.
        assert!(opts.get_int("flag").is_none());
    }

    #[test]
    fn test_domain_options_keys() {
        let mut opts = DomainOptions::new("Test");
        opts.set_bool("a", true);
        opts.set_bool("b", false);
        let keys = opts.keys();
        assert_eq!(keys.len(), 2);
        assert!(keys.contains(&"a"));
        assert!(keys.contains(&"b"));
    }

    // -- save_to_packed_file default impl -----------------------------------

    #[test]
    fn test_save_to_packed_file_unsupported() {
        let obj = MockGuiDomainObject::new("Test");
        let result = obj.save_to_packed_file(std::path::Path::new("/tmp/out.bin"));
        assert!(result.is_err());
    }

    // -- start_transaction_with_abort_listener ------------------------------

    #[test]
    fn test_start_transaction_with_abort_listener() {
        let mut obj = MockGuiDomainObject::new("Test");
        // The default implementation delegates to start_transaction.
        let tx_id = obj.start_transaction_with_abort_listener(
            "abort test",
            Arc::new(MockAbortedListener),
        );
        assert!(tx_id > 0);
        obj.end_transaction(tx_id, true);
    }

    // -- synchronized domain objects trait methods ---------------------------

    #[test]
    fn test_synchronized_domain_object_trait_defaults() {
        let mut obj = MockGuiDomainObject::new("Test");
        assert!(obj.get_synchronized_domain_objects().is_empty());
        assert!(obj.add_synchronized_domain_object("/x".into()).is_err());
        assert!(obj.release_synchronized_domain_object().is_err());
    }

    // -- get_options default ------------------------------------------------

    #[test]
    fn test_get_options_default() {
        let obj = MockGuiDomainObject::new("Test");
        assert!(obj.get_options("anything").is_none());
    }
}
