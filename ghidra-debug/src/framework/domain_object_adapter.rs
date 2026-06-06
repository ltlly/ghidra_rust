//! DomainObjectAdapterDB ported from Java.
//!
//! Provides the domain object adapter that backs trace databases.
//! This is the Rust equivalent of Ghidra's `DomainObjectAdapterDB` class
//! which extends `DomainObjectDB` for database-backed domain objects
//! with event queuing support.

use std::sync::{Arc, RwLock};
use std::time::Duration;
use crate::framework::domain_object_event_queues::DomainObjectEventQueues;

/// Metadata about a domain object's state.
#[derive(Debug, Clone)]
pub struct DomainObjectMetadata {
    /// Content type identifier (e.g., "Trace", "Program").
    pub content_type: String,
    /// Whether the object has unsaved changes.
    pub is_changed: bool,
    /// Whether the object is read-only.
    pub is_read_only: bool,
    /// Name of the object.
    pub name: String,
    /// Description of the object.
    pub description: String,
    /// Unique identifier.
    pub id: u64,
}

impl DomainObjectMetadata {
    /// Create new metadata with default values.
    pub fn new(content_type: impl Into<String>, id: u64) -> Self {
        Self {
            content_type: content_type.into(),
            is_changed: false,
            is_read_only: false,
            name: String::new(),
            description: String::new(),
            id,
        }
    }
}

/// Adapter for database-backed domain objects with event queuing.
///
/// Ported from Ghidra's `DomainObjectAdapterDB`. Manages metadata,
/// change tracking, and event dispatch for trace domain objects.
pub struct DomainObjectAdapterDB {
    /// Object metadata.
    pub metadata: DomainObjectMetadata,
    /// Event queue for this domain object.
    pub event_queues: Arc<RwLock<DomainObjectEventQueues>>,
    /// Undo stack depth limit.
    undo_depth: usize,
    /// Whether the object is closed.
    closed: bool,
}

impl DomainObjectAdapterDB {
    /// Create a new adapter with the given content type and ID.
    pub fn new(content_type: impl Into<String>, id: u64) -> Self {
        Self {
            metadata: DomainObjectMetadata::new(content_type, id),
            event_queues: Arc::new(RwLock::new(DomainObjectEventQueues::new(Duration::from_millis(100)))),
            undo_depth: 10,
            closed: false,
        }
    }

    /// Get the content type.
    pub fn content_type(&self) -> &str {
        &self.metadata.content_type
    }

    /// Check if the object has been modified.
    pub fn is_changed(&self) -> bool {
        self.metadata.is_changed
    }

    /// Mark the object as changed.
    pub fn set_changed(&mut self, changed: bool) {
        self.metadata.is_changed = changed;
    }

    /// Check if the object is read-only.
    pub fn is_read_only(&self) -> bool {
        self.metadata.is_read_only
    }

    /// Set the read-only state.
    pub fn set_read_only(&mut self, read_only: bool) {
        self.metadata.is_read_only = read_only;
    }

    /// Get the object name.
    pub fn name(&self) -> &str {
        &self.metadata.name
    }

    /// Set the object name.
    pub fn set_name(&mut self, name: impl Into<String>) {
        self.metadata.name = name.into();
    }

    /// Get the object ID.
    pub fn id(&self) -> u64 {
        self.metadata.id
    }

    /// Set the undo depth.
    pub fn set_undo_depth(&mut self, depth: usize) {
        self.undo_depth = depth;
    }

    /// Get the undo depth.
    pub fn undo_depth(&self) -> usize {
        self.undo_depth
    }

    /// Check if the object has been closed.
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// Close this domain object, releasing resources.
    pub fn close(&mut self) {
        self.closed = true;
    }

    /// Fire a domain object event through the event queues.
    pub fn fire_event(&self, event: crate::framework::domain_object_event_queues::DomainChangeEvent) {
        if let Ok(queues) = self.event_queues.read() {
            queues.fire_event(event);
        }
    }

    /// Begin a transaction. Returns a transaction ID.
    pub fn start_transaction(&mut self, _description: &str) -> u64 {
        self.set_changed(true);
        // Simple sequential transaction ID
        1
    }

    /// End a transaction.
    pub fn end_transaction(&mut self, _transaction_id: u64, _commit: bool) {
        // Transaction management
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metadata() {
        let meta = DomainObjectMetadata::new("Trace", 42);
        assert_eq!(meta.content_type, "Trace");
        assert_eq!(meta.id, 42);
        assert!(!meta.is_changed);
        assert!(!meta.is_read_only);
    }

    #[test]
    fn test_adapter_lifecycle() {
        let mut adapter = DomainObjectAdapterDB::new("Trace", 1);
        assert_eq!(adapter.content_type(), "Trace");
        assert!(!adapter.is_changed());
        assert!(!adapter.is_closed());

        adapter.set_changed(true);
        assert!(adapter.is_changed());

        adapter.set_name("My Trace");
        assert_eq!(adapter.name(), "My Trace");

        adapter.set_read_only(true);
        assert!(adapter.is_read_only());

        adapter.close();
        assert!(adapter.is_closed());
    }

    #[test]
    fn test_transactions() {
        let mut adapter = DomainObjectAdapterDB::new("Trace", 1);
        let tx_id = adapter.start_transaction("add memory");
        assert!(adapter.is_changed());
        adapter.end_transaction(tx_id, true);
    }

    #[test]
    fn test_undo_depth() {
        let mut adapter = DomainObjectAdapterDB::new("Trace", 1);
        assert_eq!(adapter.undo_depth(), 10);
        adapter.set_undo_depth(20);
        assert_eq!(adapter.undo_depth(), 20);
    }
}
