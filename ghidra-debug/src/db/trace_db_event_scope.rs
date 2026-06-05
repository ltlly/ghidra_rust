//! Database-level EventScope implementation.
//!
//! Ported from Ghidra's `DBTraceObjectEventScope` in
//! Framework-TraceModeling. Tracks the event scope for target objects
//! (which events are visible in a given context).

use serde::{Deserialize, Serialize};

use crate::model::lifespan::Lifespan;

/// Database implementation of the EventScope interface.
///
/// An event scope determines which debug events (breakpoint hits,
/// signals, etc.) are visible or relevant in a given context. For
/// example, thread-level events may only be visible within that
/// thread's event scope.
///
/// Ported from Ghidra's `DBTraceObjectEventScope`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbObjectEventScope {
    /// The object key in the database.
    pub object_key: i64,
    /// The snap at which this scope was last modified.
    pub last_modified_snap: i64,
    /// Whether this scope is currently active (accepting events).
    pub active: bool,
    /// Optional parent scope key (for hierarchical scoping).
    pub parent_scope_key: Option<i64>,
    /// The event types this scope handles (empty = all events).
    pub handled_event_types: Vec<String>,
}

impl DbObjectEventScope {
    /// Create a new event scope.
    pub fn new(object_key: i64) -> Self {
        Self {
            object_key,
            last_modified_snap: 0,
            active: true,
            parent_scope_key: None,
            handled_event_types: Vec::new(),
        }
    }

    /// Set the parent scope.
    pub fn with_parent(mut self, parent_key: i64) -> Self {
        self.parent_scope_key = Some(parent_key);
        self
    }

    /// Add an event type that this scope handles.
    pub fn add_handled_event(&mut self, event_type: impl Into<String>) {
        let et = event_type.into();
        if !self.handled_event_types.contains(&et) {
            self.handled_event_types.push(et);
        }
    }

    /// Remove a handled event type.
    pub fn remove_handled_event(&mut self, event_type: &str) {
        self.handled_event_types.retain(|e| e != event_type);
    }

    /// Whether this scope handles all event types (wildcard).
    pub fn handles_all(&self) -> bool {
        self.handled_event_types.is_empty()
    }

    /// Whether this scope handles a specific event type.
    pub fn handles(&self, event_type: &str) -> bool {
        self.handles_all() || self.handled_event_types.iter().any(|e| e == event_type)
    }

    /// Activate this scope.
    pub fn activate(&mut self, snap: i64) {
        self.active = true;
        self.last_modified_snap = snap;
    }

    /// Deactivate this scope.
    pub fn deactivate(&mut self, snap: i64) {
        self.active = false;
        self.last_modified_snap = snap;
    }

    /// Whether this scope is active.
    pub fn is_active(&self) -> bool {
        self.active
    }
}

/// Manager for event scopes in a trace database.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DbEventScopeManager {
    scopes: Vec<DbObjectEventScope>,
}

impl DbEventScopeManager {
    /// Create a new manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register an event scope.
    pub fn register(&mut self, scope: DbObjectEventScope) {
        self.scopes.push(scope);
    }

    /// Find a scope by object key.
    pub fn find_by_object(&self, object_key: i64) -> Option<&DbObjectEventScope> {
        self.scopes.iter().find(|s| s.object_key == object_key)
    }

    /// Find a mutable scope by object key.
    pub fn find_by_object_mut(&mut self, object_key: i64) -> Option<&mut DbObjectEventScope> {
        self.scopes.iter_mut().find(|s| s.object_key == object_key)
    }

    /// Get all active scopes.
    pub fn active_scopes(&self) -> Vec<&DbObjectEventScope> {
        self.scopes.iter().filter(|s| s.is_active()).collect()
    }

    /// Get all scopes that handle a specific event type.
    pub fn scopes_for_event(&self, event_type: &str) -> Vec<&DbObjectEventScope> {
        self.scopes
            .iter()
            .filter(|s| s.is_active() && s.handles(event_type))
            .collect()
    }

    /// Remove a scope by object key.
    pub fn remove(&mut self, object_key: i64) -> bool {
        let before = self.scopes.len();
        self.scopes.retain(|s| s.object_key != object_key);
        self.scopes.len() < before
    }

    /// The number of registered scopes.
    pub fn len(&self) -> usize {
        self.scopes.len()
    }

    /// Whether there are no registered scopes.
    pub fn is_empty(&self) -> bool {
        self.scopes.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_scope_new() {
        let scope = DbObjectEventScope::new(42);
        assert_eq!(scope.object_key, 42);
        assert!(scope.is_active());
        assert!(scope.handles_all());
        assert!(scope.parent_scope_key.is_none());
    }

    #[test]
    fn test_event_scope_parent() {
        let scope = DbObjectEventScope::new(1).with_parent(100);
        assert_eq!(scope.parent_scope_key, Some(100));
    }

    #[test]
    fn test_event_scope_handled_events() {
        let mut scope = DbObjectEventScope::new(1);
        scope.add_handled_event("breakpoint-hit");
        scope.add_handled_event("signal");
        assert!(!scope.handles_all());
        assert!(scope.handles("breakpoint-hit"));
        assert!(scope.handles("signal"));
        assert!(!scope.handles("step-completed"));

        scope.remove_handled_event("signal");
        assert!(!scope.handles("signal"));
    }

    #[test]
    fn test_event_scope_activation() {
        let mut scope = DbObjectEventScope::new(1);
        assert!(scope.is_active());

        scope.deactivate(10);
        assert!(!scope.is_active());
        assert_eq!(scope.last_modified_snap, 10);

        scope.activate(20);
        assert!(scope.is_active());
        assert_eq!(scope.last_modified_snap, 20);
    }

    #[test]
    fn test_event_scope_manager() {
        let mut mgr = DbEventScopeManager::new();
        let mut s1 = DbObjectEventScope::new(1);
        s1.add_handled_event("breakpoint-hit");
        mgr.register(s1);

        let s2 = DbObjectEventScope::new(2);
        mgr.register(s2);

        assert_eq!(mgr.len(), 2);
        assert!(mgr.find_by_object(1).is_some());
        assert!(mgr.find_by_object(3).is_none());
    }

    #[test]
    fn test_event_scope_manager_active() {
        let mut mgr = DbEventScopeManager::new();
        let mut s1 = DbObjectEventScope::new(1);
        s1.deactivate(5);
        mgr.register(s1);
        mgr.register(DbObjectEventScope::new(2));

        assert_eq!(mgr.active_scopes().len(), 1);
    }

    #[test]
    fn test_event_scope_manager_filter() {
        let mut mgr = DbEventScopeManager::new();
        let mut s1 = DbObjectEventScope::new(1);
        s1.add_handled_event("breakpoint-hit");
        mgr.register(s1);
        mgr.register(DbObjectEventScope::new(2));

        assert_eq!(mgr.scopes_for_event("breakpoint-hit").len(), 2);
        assert_eq!(mgr.scopes_for_event("signal").len(), 1);
    }

    #[test]
    fn test_event_scope_manager_remove() {
        let mut mgr = DbEventScopeManager::new();
        mgr.register(DbObjectEventScope::new(1));
        assert!(mgr.remove(1));
        assert!(mgr.is_empty());
        assert!(!mgr.remove(1));
    }

    #[test]
    fn test_event_scope_serde() {
        let scope = DbObjectEventScope::new(1).with_parent(10);
        let json = serde_json::to_string(&scope).unwrap();
        let back: DbObjectEventScope = serde_json::from_str(&json).unwrap();
        assert_eq!(back.parent_scope_key, Some(10));
    }

    #[test]
    fn test_event_scope_manager_find_mut() {
        let mut mgr = DbEventScopeManager::new();
        mgr.register(DbObjectEventScope::new(1));

        let scope = mgr.find_by_object_mut(1).unwrap();
        scope.add_handled_event("signal");
        assert!(scope.handles("signal"));
    }

    #[test]
    fn test_event_scope_duplicate_event() {
        let mut scope = DbObjectEventScope::new(1);
        scope.add_handled_event("breakpoint-hit");
        scope.add_handled_event("breakpoint-hit");
        assert_eq!(scope.handled_event_types.len(), 1);
    }
}
