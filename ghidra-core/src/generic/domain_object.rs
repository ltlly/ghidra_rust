//! Domain object abstraction for the Ghidra framework.
//!
//! Ports Ghidra's `framework.model.DomainObject` interface. A `DomainObject`
//! is the base trait for all persistent, lockable, observable data objects
//! managed by the Ghidra framework (programs, data type archives, etc.).

use std::fmt;
use std::time::SystemTime;

use super::domain_object_listener::DomainObjectListener;

// ============================================================================
// DomainObject trait
// ============================================================================

/// The fundamental interface for domain objects in the Ghidra framework.
///
/// Every persistent entity in a Ghidra project (program, data type archive,
/// etc.) implements this trait. Domain objects support:
/// - Naming and path-based identification
/// - Change tracking
/// - Persistence (save/close)
/// - Cooperative locking
/// - Event-based listener notification
pub trait DomainObject: fmt::Debug + Send + Sync {
    /// Returns the display name of this domain object.
    fn get_name(&self) -> &str;

    /// Sets the display name of this domain object.
    fn set_name(&mut self, name: String);

    /// Returns the domain file path if this object is associated with a file.
    fn get_domain_file_path(&self) -> Option<String>;

    /// Returns the last modification timestamp.
    fn get_last_modified_time(&self) -> SystemTime;

    /// Returns `true` if this object has unsaved changes.
    fn is_changed(&self) -> bool;

    /// Mark this object as changed or unchanged.
    fn set_changed(&mut self, changed: bool);

    /// Save this object to its backing store.
    fn save(&mut self) -> Result<(), DomainObjectError>;

    /// Close this object, releasing any held resources.
    fn close(&mut self) -> Result<(), DomainObjectError>;

    /// Returns `true` if this object supports locking.
    fn is_lockable(&self) -> bool;

    /// Returns `true` if this object is currently locked.
    fn is_locked(&self) -> bool;

    /// Acquire a lock on this object.
    ///
    /// Returns a guard that releases the lock on drop.
    fn lock(&self) -> Result<DomainObjectLock, DomainObjectError>;

    /// Force-release the lock, even if held by another consumer.
    fn force_unlock(&self);

    /// Add a listener that will be notified of changes to this object.
    fn add_listener(&self, listener: Box<dyn DomainObjectListener>);

    /// Remove a listener by its ID.
    fn remove_listener(&self, listener_id: u64);

    /// Returns `true` if this object is temporary (not persisted).
    fn is_temporary(&self) -> bool {
        false
    }

    /// Returns `true` if this object supports undo/redo.
    fn is_undoable(&self) -> bool {
        false
    }

    /// Returns the description of this domain object type.
    fn get_domain_type_name(&self) -> &str {
        "DomainObject"
    }

    /// Returns `true` if this object can be saved.
    fn can_save(&self) -> bool {
        true
    }

    /// Release this object (decrement consumer count).
    fn release(&self) {}

    /// Add a consumer to this object (increment consumer count).
    fn add_consumer(&self, _consumer: &str) {}
}

// ============================================================================
// DomainObjectLock
// ============================================================================

/// RAII guard for a domain object lock.
///
/// The lock is released when this guard is dropped.
#[derive(Debug)]
pub struct DomainObjectLock {
    acquired_at: SystemTime,
    owner: String,
}

impl DomainObjectLock {
    /// Create a new lock guard with the given owner.
    pub fn new(owner: impl Into<String>) -> Self {
        Self {
            acquired_at: SystemTime::now(),
            owner: owner.into(),
        }
    }

    /// Returns the time at which this lock was acquired.
    pub fn acquired_at(&self) -> SystemTime {
        self.acquired_at
    }

    /// Returns the owner of this lock.
    pub fn owner(&self) -> &str {
        &self.owner
    }
}

impl Drop for DomainObjectLock {
    fn drop(&mut self) {}
}

// ============================================================================
// DomainObjectError
// ============================================================================

/// Errors that can occur when operating on a domain object.
#[derive(Debug, Clone)]
pub enum DomainObjectError {
    /// The object is locked by another consumer.
    Locked(String),
    /// The object has been closed.
    Closed,
    /// An I/O error occurred during save/load.
    IoError(String),
    /// The operation is not supported.
    NotSupported(String),
    /// A concurrent modification was detected.
    ConcurrentModification(String),
    /// A generic error with a message.
    Other(String),
}

impl fmt::Display for DomainObjectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DomainObjectError::Locked(msg) => write!(f, "Locked: {}", msg),
            DomainObjectError::Closed => write!(f, "Domain object is closed"),
            DomainObjectError::IoError(msg) => write!(f, "I/O error: {}", msg),
            DomainObjectError::NotSupported(msg) => write!(f, "Not supported: {}", msg),
            DomainObjectError::ConcurrentModification(msg) => {
                write!(f, "Concurrent modification: {}", msg)
            }
            DomainObjectError::Other(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for DomainObjectError {}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct TestDomainObject {
        name: String,
        changed: bool,
        locked: bool,
        listeners: Vec<u64>,
        next_id: u64,
    }

    impl TestDomainObject {
        fn new(name: &str) -> Self {
            Self {
                name: name.to_string(),
                changed: false,
                locked: false,
                listeners: Vec::new(),
                next_id: 1,
            }
        }
    }

    impl DomainObject for TestDomainObject {
        fn get_name(&self) -> &str {
            &self.name
        }
        fn set_name(&mut self, name: String) {
            self.name = name;
        }
        fn get_domain_file_path(&self) -> Option<String> {
            None
        }
        fn get_last_modified_time(&self) -> SystemTime {
            SystemTime::now()
        }
        fn is_changed(&self) -> bool {
            self.changed
        }
        fn set_changed(&mut self, changed: bool) {
            self.changed = changed;
        }
        fn save(&mut self) -> Result<(), DomainObjectError> {
            self.changed = false;
            Ok(())
        }
        fn close(&mut self) -> Result<(), DomainObjectError> {
            Ok(())
        }
        fn is_lockable(&self) -> bool {
            true
        }
        fn is_locked(&self) -> bool {
            self.locked
        }
        fn lock(&self) -> Result<DomainObjectLock, DomainObjectError> {
            Ok(DomainObjectLock::new("test"))
        }
        fn force_unlock(&self) {}
        fn add_listener(&self, _listener: Box<dyn DomainObjectListener>) {}
        fn remove_listener(&self, _listener_id: u64) {}
    }

    #[test]
    fn test_domain_object_name() {
        let mut obj = TestDomainObject::new("TestObject");
        assert_eq!(obj.get_name(), "TestObject");
        obj.set_name("Renamed".to_string());
        assert_eq!(obj.get_name(), "Renamed");
    }

    #[test]
    fn test_domain_object_changed() {
        let mut obj = TestDomainObject::new("Test");
        assert!(!obj.is_changed());
        obj.set_changed(true);
        assert!(obj.is_changed());
        obj.save().unwrap();
        assert!(!obj.is_changed());
    }

    #[test]
    fn test_domain_object_lock_guard() {
        let lock = DomainObjectLock::new("test_user");
        assert_eq!(lock.owner(), "test_user");
        assert!(lock.acquired_at() <= SystemTime::now());
    }

    #[test]
    fn test_domain_object_error_display() {
        let err = DomainObjectError::Locked("user1".to_string());
        assert!(err.to_string().contains("Locked"));

        let err = DomainObjectError::Closed;
        assert!(err.to_string().contains("closed"));

        let err = DomainObjectError::IoError("disk full".to_string());
        assert!(err.to_string().contains("disk full"));
    }

    #[test]
    fn test_domain_object_defaults() {
        let obj = TestDomainObject::new("Test");
        assert!(!obj.is_temporary());
        assert!(!obj.is_undoable());
        assert_eq!(obj.get_domain_type_name(), "DomainObject");
        assert!(obj.can_save());
        assert!(obj.get_domain_file_path().is_none());
    }
}
