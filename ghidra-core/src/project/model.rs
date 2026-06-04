//! Core domain model interfaces for the Ghidra Project framework.
//!
//! This module ports the key Java interfaces from `ghidra.framework.model`:
//! - `DomainObject` (full interface with transactions, undo/redo, consumers, events)
//! - `DomainFile` (storage interface for project files, version control, linking)
//! - `DomainFolder` (storage interface for project folders)
//! - `ProjectData` (access to all data files and folders in a project)
//! - Event and listener types (`EventType`, `DomainObjectEvent`, `DomainObjectChangeRecord`,
//!   `DomainObjectChangedEvent`, `DomainObjectListener`, `DomainFolderChangeListener`,
//!   `TransactionListener`, `DomainObjectClosedListener`, `AbortedTransactionListener`)
//! - `TransactionInfo`, `EventQueueID`, `ChangeSet`
//! - `Version`, `ItemCheckoutStatus`, `CheckinHandler`, `LinkFileInfo`
//!
//! The Java `DomainObject` here maps to [`DomainObject2`] to avoid conflicts with the existing
//! `program::program::DomainObject` trait which covers the program-specific model.

use std::collections::HashMap;
use std::fmt;
use std::time::SystemTime;

use super::{ProjectLocator, ProjectResult};

// ============================================================================
// EventType trait + DomainObjectEvent enum
// ============================================================================

/// Trait for objects that represent event types.
///
/// In Java: `ghidra.framework.model.EventType`.
/// Each event type gets a unique `id` for fast bitset-based containment checks.
pub trait EventType: Send + Sync + fmt::Debug {
    /// Returns a unique id for this event type.  The value is guaranteed to be
    /// constant for any given run of the application but may vary between runs.
    fn id(&self) -> u32;
    /// A human-readable label for this event type.
    fn label(&self) -> &str;
}

/// Global atomic counter for generating unique event type IDs.
static EVENT_ID_COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(1);

fn next_event_id() -> u32 {
    EVENT_ID_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

/// Basic event types for all Domain Objects.
///
/// In Java: `ghidra.framework.model.DomainObjectEvent`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DomainObjectEvent {
    Saved,
    FileChanged,
    Renamed,
    Restored,
    PropertyChanged,
    Closed,
    Error,
}

impl DomainObjectEvent {
    /// All variants in canonical order.
    pub const ALL: &'static [DomainObjectEvent] = &[
        Self::Saved,
        Self::FileChanged,
        Self::Renamed,
        Self::Restored,
        Self::PropertyChanged,
        Self::Closed,
        Self::Error,
    ];

    /// Stable numeric ID for bitset indexing.  Each variant gets a small
    /// deterministic value.
    pub fn stable_id(self) -> u32 {
        match self {
            Self::Saved => 0,
            Self::FileChanged => 1,
            Self::Renamed => 2,
            Self::Restored => 3,
            Self::PropertyChanged => 4,
            Self::Closed => 5,
            Self::Error => 6,
        }
    }
}

impl EventType for DomainObjectEvent {
    fn id(&self) -> u32 {
        self.stable_id()
    }
    fn label(&self) -> &str {
        match self {
            Self::Saved => "SAVED",
            Self::FileChanged => "FILE_CHANGED",
            Self::Renamed => "RENAMED",
            Self::Restored => "RESTORED",
            Self::PropertyChanged => "PROPERTY_CHANGED",
            Self::Closed => "CLOSED",
            Self::Error => "ERROR",
        }
    }
}

impl fmt::Display for DomainObjectEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// A boxed, heap-allocated event type for heterogeneous collections.
#[derive(Debug, Clone)]
pub struct DynamicEventType {
    id: u32,
    label: String,
}

impl DynamicEventType {
    /// Create a new dynamic event type with a unique ID.
    pub fn new(label: impl Into<String>) -> Self {
        Self {
            id: next_event_id(),
            label: label.into(),
        }
    }
}

impl EventType for DynamicEventType {
    fn id(&self) -> u32 {
        self.id
    }
    fn label(&self) -> &str {
        &self.label
    }
}

// ============================================================================
// DomainObjectChangeRecord
// ============================================================================

/// Information about a single change made to a domain object.
///
/// In Java: `ghidra.framework.model.DomainObjectChangeRecord`.
pub struct DomainObjectChangeRecord {
    event_type: Box<dyn EventType>,
    old_value: Option<String>,
    new_value: Option<String>,
}

impl fmt::Debug for DomainObjectChangeRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DomainObjectChangeRecord")
            .field("event_type_label", &self.event_type.label())
            .field("old_value", &self.old_value)
            .field("new_value", &self.new_value)
            .finish()
    }
}

impl DomainObjectChangeRecord {
    /// Create a new change record (event only, no old/new values).
    pub fn new(event_type: Box<dyn EventType>) -> Self {
        Self {
            event_type,
            old_value: None,
            new_value: None,
        }
    }

    /// Create a change record with old and new values.
    pub fn with_values(
        event_type: Box<dyn EventType>,
        old_value: Option<String>,
        new_value: Option<String>,
    ) -> Self {
        Self {
            event_type,
            old_value,
            new_value,
        }
    }

    /// The event type of this change.
    pub fn event_type(&self) -> &dyn EventType {
        self.event_type.as_ref()
    }

    /// The old value, if applicable.
    pub fn old_value(&self) -> Option<&str> {
        self.old_value.as_deref()
    }

    /// The new value, if applicable.
    pub fn new_value(&self) -> Option<&str> {
        self.new_value.as_deref()
    }
}

impl fmt::Display for DomainObjectChangeRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DomainObjectChangeRecord: event = {}", self.event_type.label())?;
        if let Some(old) = &self.old_value {
            write!(f, ", old = {}", old)?;
        }
        if let Some(new) = &self.new_value {
            write!(f, ", new = {}", new)?;
        }
        Ok(())
    }
}

// ============================================================================
// DomainObjectChangedEvent
// ============================================================================

/// An event indicating a DomainObject has changed.
///
/// Contains a list of [`DomainObjectChangeRecord`]s.
/// In Java: `ghidra.framework.model.DomainObjectChangedEvent`.
#[derive(Debug)]
pub struct DomainObjectChangedEvent {
    sub_events: Vec<DomainObjectChangeRecord>,
    event_bits: Vec<bool>,
}

impl DomainObjectChangedEvent {
    /// Maximum number of event type IDs tracked in the bitset.
    const BITSET_SIZE: usize = 256;

    /// Create a new changed event from a list of change records.
    pub fn new(sub_events: Vec<DomainObjectChangeRecord>) -> Self {
        let mut event_bits = vec![false; Self::BITSET_SIZE];
        for record in &sub_events {
            let id = record.event_type().id() as usize;
            if id < Self::BITSET_SIZE {
                event_bits[id] = true;
            }
        }
        Self {
            sub_events,
            event_bits,
        }
    }

    /// Number of change records in this event.
    pub fn num_records(&self) -> usize {
        self.sub_events.len()
    }

    /// Returns `true` if this event contains a record with the given event type.
    pub fn contains_event_type(&self, event_type: &dyn EventType) -> bool {
        let id = event_type.id() as usize;
        id < Self::BITSET_SIZE && self.event_bits[id]
    }

    /// Get the specified change record.
    pub fn get_change_record(&self, i: usize) -> Option<&DomainObjectChangeRecord> {
        self.sub_events.get(i)
    }

    /// Iterate over all change records.
    pub fn records(&self) -> &[DomainObjectChangeRecord] {
        &self.sub_events
    }

    /// Find the first record with the given event type.
    pub fn find_first(&self, event_type: &dyn EventType) -> Option<&DomainObjectChangeRecord> {
        let target_id = event_type.id();
        self.sub_events
            .iter()
            .find(|r| r.event_type().id() == target_id)
    }

    /// Iterate over records matching a given event type.
    pub fn for_each_matching(
        &self,
        event_type: &dyn EventType,
        mut f: impl FnMut(&DomainObjectChangeRecord),
    ) {
        let target_id = event_type.id();
        for record in &self.sub_events {
            if record.event_type().id() == target_id {
                f(record);
            }
        }
    }
}

impl<'a> IntoIterator for &'a DomainObjectChangedEvent {
    type Item = &'a DomainObjectChangeRecord;
    type IntoIter = std::slice::Iter<'a, DomainObjectChangeRecord>;
    fn into_iter(self) -> Self::IntoIter {
        self.sub_events.iter()
    }
}

// ============================================================================
// EventQueueID
// ============================================================================

/// Unique identifier for a private event queue.
///
/// In Java: `ghidra.framework.model.EventQueueID`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EventQueueID(u64);

impl EventQueueID {
    /// Create a new unique event queue ID.
    pub fn new() -> Self {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        Self(COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed))
    }

    /// The raw ID value.
    pub fn value(&self) -> u64 {
        self.0
    }
}

impl Default for EventQueueID {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Listener traits
// ============================================================================

/// The interface an object must support to be registered with a DomainObject
/// and informed of changes.
///
/// In Java: `ghidra.framework.model.DomainObjectListener`.
pub trait DomainObjectListener: Send + Sync + fmt::Debug {
    /// Called when a change is made to the domain object.
    fn domain_object_changed(&self, ev: &DomainObjectChangedEvent);
}

/// Callback for when a DomainObject is closed.
///
/// In Java: `ghidra.framework.model.DomainObjectClosedListener`.
pub trait DomainObjectClosedListener: Send + Sync + fmt::Debug {
    /// Called when the specified domain object has been closed.
    fn domain_object_closed(&self, object_id: u64);
}

/// Listener for transaction lifecycle events.
///
/// In Java: `ghidra.framework.model.TransactionListener`.
pub trait TransactionListener: Send + Sync {
    /// Invoked when a transaction is started.
    fn transaction_started(&self, object_id: u64, tx: &dyn TransactionInfo);
    /// Invoked when a transaction is ended.
    fn transaction_ended(&self, object_id: u64);
    /// Invoked when the stack of available undo/redo operations has changed.
    fn undo_stack_changed(&self, object_id: u64);
    /// Notification that undo or redo has occurred.
    fn undo_redo_occurred(&self, object_id: u64);
}

/// Listener notified when a transaction is aborted.
///
/// In Java: `ghidra.framework.model.AbortedTransactionListener`.
pub trait AbortedTransactionListener: Send + Sync {
    /// Called when the specified transaction is aborted.
    fn transaction_aborted(&self, transaction_id: u64);
}

/// Methods for notifications when changes are made to a domain folder or file.
///
/// In Java: `ghidra.framework.model.DomainFolderChangeListener`.
pub trait DomainFolderChangeListener: Send + Sync + fmt::Debug {
    /// A folder was added to parent.
    fn domain_folder_added(&self, _folder_path: &str) {}
    /// A file was added to parent folder.
    fn domain_file_added(&self, _file_path: &str) {}
    /// A folder was removed.
    fn domain_folder_removed(&self, _parent_path: &str, _name: &str) {}
    /// A file was removed.
    fn domain_file_removed(&self, _parent_path: &str, _name: &str, _file_id: Option<&str>) {}
    /// A folder was renamed.
    fn domain_folder_renamed(&self, _folder_path: &str, _old_name: &str) {}
    /// A file was renamed.
    fn domain_file_renamed(&self, _file_path: &str, _old_name: &str) {}
    /// A folder was moved.
    fn domain_folder_moved(&self, _folder_path: &str, _old_parent_path: &str) {}
    /// A file was moved.
    fn domain_file_moved(
        &self,
        _file_path: &str,
        _old_parent_path: &str,
        _old_name: &str,
    ) {
    }
    /// The setActive() method on a folder was called.
    fn domain_folder_set_active(&self, _folder_path: &str) {}
    /// The status for a domain file has changed.
    fn domain_file_status_changed(&self, _file_path: &str, _file_id_set: bool) {}
    /// A domain file has been opened for update.
    fn domain_file_object_opened_for_update(&self, _file_path: &str, _object_id: u64) {}
    /// A domain file previously open for update is in the process of closing.
    fn domain_file_object_closed(&self, _file_path: &str, _object_id: u64) {}
}

// ============================================================================
// TransactionInfo
// ============================================================================

/// Status of a transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransactionStatus {
    NotDone,
    Committed,
    Aborted,
    NotDoneButAborted,
}

/// Information about a transaction.
///
/// In Java: `ghidra.framework.model.TransactionInfo`.
pub trait TransactionInfo: Send + Sync + fmt::Debug {
    /// The transaction ID.
    fn id(&self) -> u64;
    /// A description of the transaction.
    fn description(&self) -> &str;
    /// The list of open sub-transactions.
    fn open_sub_transactions(&self) -> Vec<String>;
    /// The status of the transaction.
    fn status(&self) -> TransactionStatus;
    /// Whether the transaction (and all sub-transactions) has been committed to the DB.
    fn has_committed_db_transaction(&self) -> bool;
}

/// Simple in-memory implementation of [`TransactionInfo`].
#[derive(Debug, Clone)]
pub struct SimpleTransactionInfo {
    id: u64,
    description: String,
    status: TransactionStatus,
    sub_transactions: Vec<String>,
}

impl SimpleTransactionInfo {
    /// Create a new simple transaction info.
    pub fn new(id: u64, description: impl Into<String>) -> Self {
        Self {
            id,
            description: description.into(),
            status: TransactionStatus::NotDone,
            sub_transactions: Vec::new(),
        }
    }

    /// Set the transaction status.
    pub fn set_status(&mut self, status: TransactionStatus) {
        self.status = status;
    }

    /// Add a sub-transaction description.
    pub fn add_sub_transaction(&mut self, desc: impl Into<String>) {
        self.sub_transactions.push(desc.into());
    }
}

impl TransactionInfo for SimpleTransactionInfo {
    fn id(&self) -> u64 {
        self.id
    }
    fn description(&self) -> &str {
        &self.description
    }
    fn open_sub_transactions(&self) -> Vec<String> {
        self.sub_transactions.clone()
    }
    fn status(&self) -> TransactionStatus {
        self.status
    }
    fn has_committed_db_transaction(&self) -> bool {
        self.status == TransactionStatus::Committed
    }
}

// ============================================================================
// ChangeSet
// ============================================================================

/// Generic marker trait for changes made to some object.
///
/// In Java: `ghidra.framework.model.ChangeSet`.
pub trait ChangeSet: Send + Sync + fmt::Debug {
    /// Returns `true` if this change set is empty.
    fn is_empty(&self) -> bool;
    /// Returns the number of changes.
    fn change_count(&self) -> usize;
}

// ============================================================================
// Version
// ============================================================================

/// Represents a version in a version-controlled file system.
///
/// In Java: `ghidra.framework.store.Version`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version {
    /// The version number.
    pub version_number: i32,
    /// The user who created this version.
    pub user: String,
    /// The comment associated with this version.
    pub comment: String,
    /// The timestamp when this version was created (ms since epoch).
    pub timestamp: i64,
    /// Whether this version corresponds to a checkout.
    pub is_checkin: bool,
}

impl Version {
    /// Create a new version.
    pub fn new(
        version_number: i32,
        user: impl Into<String>,
        comment: impl Into<String>,
        timestamp: i64,
    ) -> Self {
        Self {
            version_number,
            user: user.into(),
            comment: comment.into(),
            timestamp,
            is_checkin: false,
        }
    }

    /// Create a version that represents a checkin.
    pub fn new_checkin(
        version_number: i32,
        user: impl Into<String>,
        comment: impl Into<String>,
        timestamp: i64,
    ) -> Self {
        Self {
            is_checkin: true,
            ..Self::new(version_number, user, comment, timestamp)
        }
    }
}

// ============================================================================
// ItemCheckoutStatus
// ============================================================================

/// Status of a checkout for a versioned file.
///
/// In Java: `ghidra.framework.store.ItemCheckoutStatus`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemCheckoutStatus {
    /// The checkout ID.
    pub checkout_id: u64,
    /// The user who performed the checkout.
    pub user: String,
    /// Whether this is an exclusive checkout.
    pub exclusive: bool,
    /// The version number at time of checkout.
    pub version: i32,
}

impl ItemCheckoutStatus {
    /// Create a new checkout status.
    pub fn new(checkout_id: u64, user: impl Into<String>, exclusive: bool, version: i32) -> Self {
        Self {
            checkout_id,
            user: user.into(),
            exclusive,
            version,
        }
    }
}

// ============================================================================
// CheckinHandler
// ============================================================================

/// Provides user input data to complete a checkin process.
///
/// In Java: `ghidra.framework.data.CheckinHandler`.
pub trait CheckinHandler: Send + Sync {
    /// The comment for the checkin.
    fn comment(&self) -> &str;
    /// Whether to keep the file checked out after checkin.
    fn keep_checked_out(&self) -> bool;
}

/// Simple in-memory checkin handler.
#[derive(Debug, Clone)]
pub struct SimpleCheckinHandler {
    comment: String,
    keep_checked_out: bool,
}

impl SimpleCheckinHandler {
    /// Create a new checkin handler.
    pub fn new(comment: impl Into<String>, keep_checked_out: bool) -> Self {
        Self {
            comment: comment.into(),
            keep_checked_out,
        }
    }
}

impl CheckinHandler for SimpleCheckinHandler {
    fn comment(&self) -> &str {
        &self.comment
    }
    fn keep_checked_out(&self) -> bool {
        self.keep_checked_out
    }
}

// ============================================================================
// LinkStatus / LinkFileInfo
// ============================================================================

/// Status of a link file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LinkStatus {
    /// The link is valid and internal to the project.
    Internal,
    /// The link points to an external project/repository.
    External,
    /// The link reference is broken.
    Broken,
}

/// Information about a link-file.
///
/// In Java: `ghidra.framework.data.LinkFileInfo` (used by `DomainFile.getLinkInfo()`).
#[derive(Debug, Clone)]
pub struct LinkFileInfo {
    /// The path or URL this link references.
    link_path: String,
    /// Whether this is a folder-link (as opposed to a file-link).
    is_folder_link: bool,
    /// Whether this is an external link.
    is_external: bool,
    /// The content type of the linked file (if a file-link).
    content_type: Option<String>,
    /// The link status.
    status: LinkStatus,
}

impl LinkFileInfo {
    /// Create a new link file info.
    pub fn new(
        link_path: impl Into<String>,
        is_folder_link: bool,
        is_external: bool,
        content_type: Option<String>,
    ) -> Self {
        let status = if is_external {
            LinkStatus::External
        } else {
            LinkStatus::Internal
        };
        Self {
            link_path: link_path.into(),
            is_folder_link,
            is_external,
            content_type,
            status,
        }
    }

    /// The path or URL this link references.
    pub fn link_path(&self) -> &str {
        &self.link_path
    }

    /// Whether this is a folder-link.
    pub fn is_folder_link(&self) -> bool {
        self.is_folder_link
    }

    /// Whether this is an external link.
    pub fn is_external_link(&self) -> bool {
        self.is_external
    }

    /// The content type of the linked file.
    pub fn content_type(&self) -> Option<&str> {
        self.content_type.as_deref()
    }

    /// The current link status.
    pub fn link_status(&self) -> LinkStatus {
        self.status
    }

    /// Set the link status.
    pub fn set_link_status(&mut self, status: LinkStatus) {
        self.status = status;
    }
}

// ============================================================================
// LinkedDomainFile
// ============================================================================

/// A domain file contained within a linked folder.
///
/// In Java: `ghidra.framework.model.LinkedDomainFile`.
pub trait LinkedDomainFile: DomainFile2 {
    /// Get the project file pathname relative to the linked-folder root.
    fn linked_pathname(&self) -> &str;
    /// Get the real domain file (may perform IO to resolve).
    fn real_file_path(&self) -> ProjectResult<String>;
}

// ============================================================================
// LinkedDomainFolder
// ============================================================================

/// A domain folder that was obtained by following a folder-link.
///
/// In Java: `ghidra.framework.model.LinkedDomainFolder`.
pub trait LinkedDomainFolder: DomainFolder2 {
    /// The source project data from which this link was established.
    fn source_path(&self) -> &str;
}

// ============================================================================
// DomainObject2 trait (full port of Java DomainObject)
// ============================================================================

/// Full port of the Java `DomainObject` interface.
///
/// This trait is named `DomainObject2` to avoid conflicts with the existing
/// `program::program::DomainObject` trait.  The "2" suffix is dropped in
/// re-exports at the module level where the context is clear.
///
/// `DomainObject` is the interface that must be supported by data objects
/// that are persistent.  They maintain an association with a [`DomainFile2`].
/// Supports transactions and the ability to undo/redo changes.
pub trait DomainObject2: Send + Sync + fmt::Debug {
    /// Whether the object has changed since last save.
    fn is_changed(&self) -> bool;
    /// Set the temporary state (temporary objects report `is_changed` as false).
    fn set_temporary(&mut self, state: bool);
    /// Whether this object is marked as temporary.
    fn is_temporary(&self) -> bool;
    /// Whether changes are permitted.
    fn is_changeable(&self) -> bool;
    /// Whether this object can be saved.
    fn can_save(&self) -> bool;

    /// Save changes to the DomainFile.
    fn save(&self, comment: &str) -> ProjectResult<()>;

    /// Notify the domain object that the specified consumer is no longer using it.
    fn release(&mut self, consumer_id: u64);

    /// Add a listener for this object.
    fn add_listener(&mut self, listener: Box<dyn DomainObjectListener>);
    /// Remove a listener by index.
    fn remove_listener(&mut self, listener_id: u64);
    /// Add a close listener.
    fn add_close_listener(&mut self, listener: Box<dyn DomainObjectClosedListener>);
    /// Remove a close listener.
    fn remove_close_listener(&mut self, listener_id: u64);

    /// Create a private event queue.
    fn create_private_event_queue(
        &mut self,
        listener: Box<dyn DomainObjectListener>,
        max_delay_ms: u32,
    ) -> EventQueueID;
    /// Remove a private event queue.
    fn remove_private_event_queue(&mut self, id: EventQueueID) -> bool;

    /// A short description of the object.
    fn description(&self) -> &str;
    /// The name of this domain object.
    fn name(&self) -> &str;
    /// Set the name.
    fn set_name(&mut self, name: String);
    /// The associated domain file path, if any.
    fn domain_file_path(&self) -> Option<&str>;

    /// Adds a consumer.  Returns false if the object has already been closed.
    fn add_consumer(&mut self, consumer_id: u64) -> bool;
    /// Returns the list of consumer IDs.
    fn consumer_list(&self) -> Vec<u64>;
    /// Returns true if the given consumer is using this domain object.
    fn is_used_by(&self, consumer_id: u64) -> bool;

    /// Enable or disable event sending.
    fn set_events_enabled(&mut self, enabled: bool);
    /// Whether events are being sent.
    fn is_sending_events(&self) -> bool;
    /// Flush all pending events.
    fn flush_events(&mut self);
    /// Flush a specific private event queue.
    fn flush_private_event_queue(&mut self, id: EventQueueID);

    /// Whether a modification lock can be obtained.
    fn can_lock(&self) -> bool;
    /// Whether the domain object is currently locked.
    fn is_locked(&self) -> bool;
    /// Attempt to acquire a modification lock.
    fn lock(&mut self, reason: &str) -> bool;
    /// Force transaction lock and terminate current transaction.
    fn force_lock(&mut self, rollback: bool, reason: &str);
    /// Release a modification lock.
    fn unlock(&mut self);

    /// All property option names.
    fn options_names(&self) -> Vec<String>;

    /// Whether this domain object has been closed.
    fn is_closed(&self) -> bool;
    /// Whether the user has exclusive access.
    fn has_exclusive_access(&self) -> bool;

    /// All stored metadata key-value pairs.
    fn metadata(&self) -> HashMap<String, String>;

    /// Modification counter incremented on each change, undo, or redo.
    fn modification_number(&self) -> u64;

    // ---- Transactions ----

    /// Start a new transaction.  Returns the transaction ID.
    fn start_transaction(&mut self, description: &str) -> u64;
    /// Start a new transaction with an abort listener.
    fn start_transaction_with_listener(
        &mut self,
        description: &str,
        listener: Option<Box<dyn AbortedTransactionListener>>,
    ) -> u64;
    /// End the specified transaction.
    fn end_transaction(&mut self, transaction_id: u64, commit: bool) -> bool;
    /// Current transaction info.
    fn current_transaction_info(&self) -> Option<&dyn TransactionInfo>;
    /// Whether the last transaction was terminated.
    fn has_terminated_transaction(&self) -> bool;

    // ---- Undo/Redo ----

    /// Whether there is a previous state to undo to.
    fn can_undo(&self) -> bool;
    /// Whether there is a later state to redo to.
    fn can_redo(&self) -> bool;
    /// Clear all undoable/redoable transactions.
    fn clear_undo(&mut self);
    /// Return to the previous state.
    fn undo(&mut self) -> ProjectResult<()>;
    /// Return to a latter state.
    fn redo(&mut self) -> ProjectResult<()>;
    /// Description of the change that would be undone.
    fn undo_name(&self) -> Option<String>;
    /// Description of the change that would be redone.
    fn redo_name(&self) -> Option<String>;
    /// All undo transaction names.
    fn all_undo_names(&self) -> Vec<String>;
    /// All redo transaction names.
    fn all_redo_names(&self) -> Vec<String>;

    /// Add a transaction listener.
    fn add_transaction_listener(&mut self, listener: Box<dyn TransactionListener>);
    /// Remove a transaction listener.
    fn remove_transaction_listener(&mut self, listener_id: u64);

    /// Close the domain object.
    fn close(&mut self);
}

// ============================================================================
// DomainFile2 trait (full port of Java DomainFile)
// ============================================================================

/// Full port of the Java `DomainFile` interface.
///
/// Provides a storage interface for a project file.  An immutable reference
/// to a stored file contained within a project.
pub trait DomainFile2: Send + Sync + fmt::Debug {
    /// The file name.
    fn name(&self) -> &str;
    /// Whether this file exists in storage.
    fn exists(&self) -> bool;
    /// A unique file-ID, or None if not established.
    fn file_id(&self) -> Option<&str>;
    /// Full path to this file within the project.
    fn pathname(&self) -> &str;
    /// Content-type string (e.g., "Program", "DataTypes").
    fn content_type(&self) -> &str;
    /// The ProjectLocator for this file's project.
    fn project_locator(&self) -> &ProjectLocator;
    /// The parent folder path.
    fn parent_path(&self) -> &str;
    /// Whether this file is explicitly marked read-only.
    fn is_read_only(&self) -> bool;
    /// Whether this file is versioned.
    fn is_versioned(&self) -> bool;
    /// Whether this file is checked out.
    fn is_checked_out(&self) -> bool;
    /// Whether this is a checked-out file with exclusive access.
    fn is_checked_out_exclusive(&self) -> bool;
    /// Whether modified since checkout.
    fn modified_since_checkout(&self) -> bool;
    /// Whether the file can be checked out.
    fn can_checkout(&self) -> bool;
    /// Whether the file can be checked in.
    fn can_checkin(&self) -> bool;
    /// Whether the file can be merged.
    fn can_merge(&self) -> bool;
    /// Whether this private file can be added to the repository.
    fn can_add_to_repository(&self) -> bool;
    /// The latest version number.
    fn latest_version(&self) -> i32;
    /// The version this file currently references.
    fn version(&self) -> i32;
    /// Whether this is the latest version.
    fn is_latest_version(&self) -> bool;
    /// Last-modified timestamp as milliseconds since epoch.
    fn last_modified_time(&self) -> i64;
    /// File length in bytes.
    fn length(&self) -> ProjectResult<u64>;

    /// Whether the associated domain object has changed.
    fn is_changed(&self) -> bool;
    /// Whether a domain object is currently open for this file.
    fn is_open(&self) -> bool;
    /// Whether the domain object is busy (has an open transaction).
    fn is_busy(&self) -> bool;
    /// Whether the file can be saved.
    fn can_save(&self) -> bool;
    /// Whether recovery data exists.
    fn can_recover(&self) -> bool;
    /// Whether this file is in a writable project.
    fn is_in_writable_project(&self) -> bool;
    /// Whether this is a link-file.
    fn is_link(&self) -> bool;
    /// Link info (if this is a link-file).
    fn link_info(&self) -> Option<&LinkFileInfo>;
    /// Whether linking is supported for this content type.
    fn is_linking_supported(&self) -> bool;
    /// Whether this file is hijacked (versioned but private copy also exists).
    fn is_hijacked(&self) -> bool;

    /// Get the consumers of this domain file.
    fn consumers(&self) -> Vec<u64>;

    /// All available version history.
    fn version_history(&self) -> ProjectResult<Vec<Version>>;

    /// Get checkout status.
    fn checkout_status(&self) -> ProjectResult<Option<ItemCheckoutStatus>>;
    /// Get all checkouts by all users.
    fn checkouts(&self) -> ProjectResult<Vec<ItemCheckoutStatus>>;

    /// Set read-only state.
    fn set_read_only(&mut self, state: bool) -> ProjectResult<()>;

    /// Get the domain file's metadata.
    fn metadata_map(&self) -> HashMap<String, String>;

    /// Save the associated domain object.
    fn save_object(&self) -> ProjectResult<()>;

    /// Delete this file.
    fn delete(&self) -> ProjectResult<()>;
    /// Delete a specific version.
    fn delete_version(&self, version: i32) -> ProjectResult<()>;

    /// Pack this file into an external file.
    fn pack_file(&self, output_path: &str) -> ProjectResult<()>;
}

// ============================================================================
// DomainFolder2 trait (full port of Java DomainFolder)
// ============================================================================

/// Full port of the Java `DomainFolder` interface.
///
/// Provides a storage interface for a project folder.
pub trait DomainFolder2: Send + Sync + fmt::Debug {
    /// The folder name.
    fn name(&self) -> &str;
    /// Full path to this folder.
    fn pathname(&self) -> &str;
    /// The ProjectLocator for this folder's project.
    fn project_locator(&self) -> &ProjectLocator;
    /// Whether this is the root folder.
    fn is_root(&self) -> bool;
    /// Whether this folder is in a writable project.
    fn is_in_writable_project(&self) -> bool;
    /// Whether this is a linked folder.
    fn is_linked(&self) -> bool;
    /// The parent folder path (None for root).
    fn parent_path(&self) -> Option<String>;
    /// Whether this folder is empty.
    fn is_empty(&self) -> bool;

    /// Get a child folder by name.
    fn get_folder(&self, name: &str) -> Option<String>;
    /// Get a file within this folder by name.
    fn get_file(&self, name: &str) -> Option<String>;
    /// List all sub-folder paths.
    fn folder_paths(&self) -> ProjectResult<Vec<String>>;
    /// List all file paths.
    fn file_paths(&self) -> ProjectResult<Vec<String>>;

    /// Create a subfolder.
    fn create_folder(&self, name: &str) -> ProjectResult<String>;
    /// Delete this folder (must be empty).
    fn delete(&self) -> ProjectResult<()>;

    /// Set the active folder.
    fn set_active(&self);
}

// ============================================================================
// ProjectData2 trait (full port of Java ProjectData)
// ============================================================================

/// Full port of the Java `ProjectData` interface.
///
/// Provides access to all the data files and folders in a project.
pub trait ProjectData2: Send + Sync + fmt::Debug {
    /// The root folder path.
    fn root_folder_path(&self) -> &str;
    /// Get a folder by absolute path.
    fn get_folder(&self, path: &str) -> Option<String>;
    /// Get a file by absolute path.
    fn get_file(&self, path: &str) -> Option<String>;
    /// Get a file by its unique file ID.
    fn get_file_by_id(&self, file_id: &str) -> Option<String>;
    /// Approximate number of files, or -1 if unknown.
    fn file_count(&self) -> i32;
    /// The ProjectLocator for this project data.
    fn project_locator(&self) -> &ProjectLocator;
    /// Maximum name length for folders or items.
    fn max_name_length(&self) -> usize {
        256
    }
    /// Transform a name into an acceptable folder or file item name.
    fn make_valid_name(&self, name: &str) -> String;
    /// Sync the folder/file structure with underlying storage.
    fn refresh(&self, force: bool);
    /// Close this project data instance.
    fn close(&self);

    /// Add a domain folder change listener.
    fn add_domain_folder_change_listener(&self, listener: Box<dyn DomainFolderChangeListener>);
    /// Remove a domain folder change listener.
    fn remove_domain_folder_change_listener(&self, listener_id: u64);

    /// Get the project locator for this data.
    fn get_project_locator(&self) -> &ProjectLocator;

    /// Generate a shared project URL (if applicable).
    fn shared_project_url(&self) -> Option<String>;
    /// Generate a local project URL (if applicable).
    fn local_project_url(&self) -> Option<String>;
}

// ============================================================================
// ToolAssociationInfo
// ============================================================================

/// Describes the association between a content type and the tool used to open it.
///
/// In Java: `ghidra.framework.model.ToolAssociationInfo`.
#[derive(Debug, Clone)]
pub struct ToolAssociationInfo {
    content_type: String,
    associated_tool_name: Option<String>,
    current_template_name: String,
    default_template_name: String,
}

impl ToolAssociationInfo {
    /// Create a new association.
    pub fn new(
        content_type: impl Into<String>,
        associated_tool_name: Option<String>,
        current_template_name: impl Into<String>,
        default_template_name: impl Into<String>,
    ) -> Self {
        Self {
            content_type: content_type.into(),
            associated_tool_name,
            current_template_name: current_template_name.into(),
            default_template_name: default_template_name.into(),
        }
    }

    /// The content type this association is for.
    pub fn content_type(&self) -> &str {
        &self.content_type
    }

    /// The currently assigned tool name.
    pub fn associated_tool_name(&self) -> Option<&str> {
        self.associated_tool_name.as_deref()
    }

    /// Whether this is the default association.
    pub fn is_default(&self) -> bool {
        self.associated_tool_name.is_none()
            || self.associated_tool_name.as_deref() == Some(&self.default_template_name)
    }

    /// Set the tool name.
    pub fn set_current_tool(&mut self, tool_name: impl Into<String>) {
        self.associated_tool_name = Some(tool_name.into());
    }

    /// Restore to default association.
    pub fn restore_default(&mut self) {
        self.associated_tool_name = None;
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_object_event_ids() {
        assert_eq!(DomainObjectEvent::Saved.stable_id(), 0);
        assert_eq!(DomainObjectEvent::Error.stable_id(), 6);
        assert_eq!(DomainObjectEvent::Saved.label(), "SAVED");
    }

    #[test]
    fn test_domain_object_event_display() {
        assert_eq!(format!("{}", DomainObjectEvent::Closed), "CLOSED");
    }

    #[test]
    fn test_event_type_trait() {
        let evt = DomainObjectEvent::Saved;
        assert_eq!(EventType::id(&evt), 0);
        assert_eq!(EventType::label(&evt), "SAVED");
    }

    #[test]
    fn test_dynamic_event_type() {
        let dyn_evt = DynamicEventType::new("CUSTOM_EVENT");
        assert!(dyn_evt.id() > 0);
        assert_eq!(dyn_evt.label(), "CUSTOM_EVENT");

        let dyn_evt2 = DynamicEventType::new("ANOTHER");
        assert_ne!(dyn_evt.id(), dyn_evt2.id());
    }

    #[test]
    fn test_domain_object_change_record() {
        let evt = Box::new(DomainObjectEvent::PropertyChanged);
        let record = DomainObjectChangeRecord::new(evt);
        assert_eq!(record.event_type().label(), "PROPERTY_CHANGED");
        assert!(record.old_value().is_none());
        assert!(record.new_value().is_none());

        let evt2 = Box::new(DomainObjectEvent::Renamed);
        let record2 = DomainObjectChangeRecord::with_values(
            evt2,
            Some("old_name".to_string()),
            Some("new_name".to_string()),
        );
        assert_eq!(record2.old_value(), Some("old_name"));
        assert_eq!(record2.new_value(), Some("new_name"));
    }

    #[test]
    fn test_domain_object_change_record_display() {
        let evt = Box::new(DomainObjectEvent::Saved);
        let record = DomainObjectChangeRecord::with_values(
            evt,
            None,
            Some("v2".to_string()),
        );
        let display = format!("{}", record);
        assert!(display.contains("SAVED"));
        assert!(display.contains("new = v2"));
    }

    #[test]
    fn test_domain_object_changed_event() {
        let records = vec![
            DomainObjectChangeRecord::new(Box::new(DomainObjectEvent::Saved)),
            DomainObjectChangeRecord::with_values(
                Box::new(DomainObjectEvent::Renamed),
                Some("old".to_string()),
                Some("new".to_string()),
            ),
        ];
        let event = DomainObjectChangedEvent::new(records);
        assert_eq!(event.num_records(), 2);

        assert!(event.contains_event_type(&DomainObjectEvent::Saved));
        assert!(event.contains_event_type(&DomainObjectEvent::Renamed));
        assert!(!event.contains_event_type(&DomainObjectEvent::Error));

        let found = event.find_first(&DomainObjectEvent::Renamed);
        assert!(found.is_some());
        assert_eq!(found.unwrap().old_value(), Some("old"));
    }

    #[test]
    fn test_domain_object_changed_event_iterator() {
        let records = vec![
            DomainObjectChangeRecord::new(Box::new(DomainObjectEvent::Saved)),
            DomainObjectChangeRecord::new(Box::new(DomainObjectEvent::Closed)),
        ];
        let event = DomainObjectChangedEvent::new(records);
        let labels: Vec<&str> = event.records().iter().map(|r| r.event_type().label()).collect();
        assert_eq!(labels, vec!["SAVED", "CLOSED"]);
    }

    #[test]
    fn test_domain_object_changed_event_for_each() {
        let records = vec![
            DomainObjectChangeRecord::new(Box::new(DomainObjectEvent::PropertyChanged)),
            DomainObjectChangeRecord::with_values(
                Box::new(DomainObjectEvent::PropertyChanged),
                Some("a".to_string()),
                Some("b".to_string()),
            ),
            DomainObjectChangeRecord::new(Box::new(DomainObjectEvent::Saved)),
        ];
        let event = DomainObjectChangedEvent::new(records);
        let mut count = 0;
        event.for_each_matching(&DomainObjectEvent::PropertyChanged, |_| {
            count += 1;
        });
        assert_eq!(count, 2);
    }

    #[test]
    fn test_event_queue_id() {
        let id1 = EventQueueID::new();
        let id2 = EventQueueID::new();
        assert_ne!(id1, id2);
        assert!(id1.value() > 0);
    }

    #[test]
    fn test_transaction_status() {
        let mut info = SimpleTransactionInfo::new(1, "test tx");
        assert_eq!(info.status(), TransactionStatus::NotDone);
        assert!(!info.has_committed_db_transaction());

        info.set_status(TransactionStatus::Committed);
        assert!(info.has_committed_db_transaction());

        info.add_sub_transaction("sub1");
        assert_eq!(info.open_sub_transactions().len(), 1);
    }

    #[test]
    fn test_version() {
        let v = Version::new(1, "alice", "initial import", 1000);
        assert_eq!(v.version_number, 1);
        assert_eq!(v.user, "alice");
        assert!(!v.is_checkin);

        let v2 = Version::new_checkin(2, "bob", "fix bug", 2000);
        assert!(v2.is_checkin);
    }

    #[test]
    fn test_item_checkout_status() {
        let status = ItemCheckoutStatus::new(42, "user1", true, 5);
        assert_eq!(status.checkout_id, 42);
        assert!(status.exclusive);
        assert_eq!(status.version, 5);
    }

    #[test]
    fn test_simple_checkin_handler() {
        let handler = SimpleCheckinHandler::new("fix #123", true);
        assert_eq!(handler.comment(), "fix #123");
        assert!(handler.keep_checked_out());
    }

    #[test]
    fn test_link_file_info() {
        let info = LinkFileInfo::new("/data/linked", false, false, Some("Program".to_string()));
        assert_eq!(info.link_path(), "/data/linked");
        assert!(!info.is_folder_link());
        assert!(!info.is_external_link());
        assert_eq!(info.content_type(), Some("Program"));
        assert_eq!(info.link_status(), LinkStatus::Internal);

        let mut ext = LinkFileInfo::new("ghidra://server/proj/file", false, true, None);
        assert_eq!(ext.link_status(), LinkStatus::External);
        ext.set_link_status(LinkStatus::Broken);
        assert_eq!(ext.link_status(), LinkStatus::Broken);
    }

    #[test]
    fn test_tool_association_info() {
        let mut assoc =
            ToolAssociationInfo::new("Program", None, "CodeBrowser", "CodeBrowser");
        assert!(assoc.is_default());
        assert_eq!(assoc.content_type(), "Program");

        assoc.set_current_tool("Debugger");
        assert!(!assoc.is_default());
        assoc.restore_default();
        assert!(assoc.is_default());
    }
}
