//! ManagedDomainObject - lifecycle management for domain objects.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.utils.ManagedDomainObject`.

use serde::{Deserialize, Serialize};

/// The state of a domain object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DomainObjectState {
    /// The object is newly created.
    New,
    /// The object has been opened from storage.
    Opened,
    /// The object has been saved.
    Saved,
    /// The object has unsaved changes.
    Modified,
    /// The object is being closed.
    Closing,
    /// The object has been closed.
    Closed,
}

/// A managed domain object with lifecycle tracking.
///
/// Ported from Ghidra's `ManagedDomainObject`. Tracks the state
/// and change history of a domain object (e.g., a trace).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagedDomainObject {
    /// The object's unique identifier.
    pub id: String,
    /// The object's display name.
    pub name: String,
    /// The file path if saved.
    pub path: Option<String>,
    /// Current state.
    pub state: DomainObjectState,
    /// Whether the object is locked for writing.
    pub locked: bool,
    /// Number of unsaved changes.
    pub change_count: u32,
}

impl ManagedDomainObject {
    /// Create a new managed domain object.
    pub fn new(id: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            path: None,
            state: DomainObjectState::New,
            locked: false,
            change_count: 0,
        }
    }

    /// Mark as opened from a path.
    pub fn mark_opened(&mut self, path: impl Into<String>) {
        self.path = Some(path.into());
        self.state = DomainObjectState::Opened;
        self.change_count = 0;
    }

    /// Mark as saved.
    pub fn mark_saved(&mut self) {
        self.state = DomainObjectState::Saved;
        self.change_count = 0;
    }

    /// Record a change.
    pub fn record_change(&mut self) {
        self.change_count += 1;
        if self.state == DomainObjectState::Saved || self.state == DomainObjectState::Opened {
            self.state = DomainObjectState::Modified;
        }
    }

    /// Record N changes.
    pub fn record_changes(&mut self, count: u32) {
        self.change_count += count;
        if self.state == DomainObjectState::Saved || self.state == DomainObjectState::Opened {
            self.state = DomainObjectState::Modified;
        }
    }

    /// Begin closing the object.
    pub fn close(&mut self) {
        self.state = DomainObjectState::Closing;
    }

    /// Mark as fully closed.
    pub fn mark_closed(&mut self) {
        self.state = DomainObjectState::Closed;
    }

    /// Whether the object has unsaved changes.
    pub fn is_modified(&self) -> bool {
        self.change_count > 0
    }

    /// Whether the object is still usable (not closed/closing).
    pub fn is_usable(&self) -> bool {
        !matches!(
            self.state,
            DomainObjectState::Closing | DomainObjectState::Closed
        )
    }

    /// Set the name.
    pub fn set_name(&mut self, name: impl Into<String>) {
        self.name = name.into();
    }

    /// Set whether the object is locked.
    pub fn set_locked(&mut self, locked: bool) {
        self.locked = locked;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_object() {
        let obj = ManagedDomainObject::new("id1", "MyTrace");
        assert_eq!(obj.id, "id1");
        assert_eq!(obj.state, DomainObjectState::New);
        assert!(!obj.is_modified());
        assert!(obj.is_usable());
    }

    #[test]
    fn test_lifecycle() {
        let mut obj = ManagedDomainObject::new("id1", "trace");
        obj.mark_opened("/tmp/trace.db");
        assert_eq!(obj.state, DomainObjectState::Opened);
        assert!(obj.path.is_some());

        obj.record_change();
        assert!(obj.is_modified());
        assert_eq!(obj.state, DomainObjectState::Modified);

        obj.mark_saved();
        assert!(!obj.is_modified());
        assert_eq!(obj.change_count, 0);
    }

    #[test]
    fn test_close_lifecycle() {
        let mut obj = ManagedDomainObject::new("id1", "trace");
        obj.close();
        assert_eq!(obj.state, DomainObjectState::Closing);
        assert!(!obj.is_usable());

        obj.mark_closed();
        assert_eq!(obj.state, DomainObjectState::Closed);
    }

    #[test]
    fn test_record_changes() {
        let mut obj = ManagedDomainObject::new("id1", "trace");
        obj.mark_opened("path");
        obj.record_changes(5);
        assert_eq!(obj.change_count, 5);
        assert_eq!(obj.state, DomainObjectState::Modified);
    }

    #[test]
    fn test_locked() {
        let mut obj = ManagedDomainObject::new("id1", "trace");
        assert!(!obj.locked);
        obj.set_locked(true);
        assert!(obj.locked);
    }

    #[test]
    fn test_serde() {
        let obj = ManagedDomainObject::new("id1", "test");
        let json = serde_json::to_string(&obj).unwrap();
        let back: ManagedDomainObject = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, "id1");
    }
}
