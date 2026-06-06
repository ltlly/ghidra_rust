//! Namespace management for trace database symbols.
//!
//! Ported from Ghidra's Framework-TraceModeling `DBTraceNamespaceSymbol`
//! and related classes. Provides hierarchical namespace support for
//! organizing symbols in a trace database.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::trace_db_record_manager::RecordKey;

/// A namespace in the trace symbol hierarchy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceNamespace {
    /// The unique key for this namespace.
    pub key: RecordKey,
    /// The name of this namespace (not including parent path).
    pub name: String,
    /// The parent namespace key (None for the global namespace).
    pub parent_key: Option<RecordKey>,
    /// The snap range during which this namespace exists.
    pub min_snap: i64,
    /// Maximum snap (i64::MAX for open-ended).
    pub max_snap: i64,
}

impl TraceNamespace {
    /// Create a new namespace.
    pub fn new(
        key: RecordKey,
        name: impl Into<String>,
        parent_key: Option<RecordKey>,
        min_snap: i64,
    ) -> Self {
        Self {
            key,
            name: name.into(),
            parent_key,
            min_snap,
            max_snap: i64::MAX,
        }
    }

    /// Check if this is the global (root) namespace.
    pub fn is_global(&self) -> bool {
        self.parent_key.is_none()
    }

    /// Check if this namespace is visible at the given snap.
    pub fn is_visible_at(&self, snap: i64) -> bool {
        snap >= self.min_snap && snap <= self.max_snap
    }

    /// Close this namespace at the given snap.
    pub fn close(&mut self, snap: i64) {
        if snap < self.max_snap {
            self.max_snap = snap;
        }
    }
}

/// Manages the hierarchy of namespaces in a trace database.
#[derive(Debug)]
pub struct TraceNamespaceManager {
    /// All namespaces keyed by their record key.
    namespaces: BTreeMap<RecordKey, TraceNamespace>,
    /// Children index: parent_key -> list of child keys.
    children: BTreeMap<RecordKey, Vec<RecordKey>>,
    /// Next key to allocate.
    next_key: RecordKey,
}

impl TraceNamespaceManager {
    /// Create a new namespace manager with a global namespace.
    pub fn new() -> Self {
        let mut mgr = Self {
            namespaces: BTreeMap::new(),
            children: BTreeMap::new(),
            next_key: 1,
        };
        // Create the global namespace at key 0
        let global = TraceNamespace::new(0, "::", None, i64::MIN);
        mgr.namespaces.insert(0, global);
        mgr
    }

    /// Get the global namespace key.
    pub fn global_key(&self) -> RecordKey {
        0
    }

    /// Create a new namespace under the given parent.
    pub fn create_namespace(
        &mut self,
        name: impl Into<String>,
        parent_key: RecordKey,
        min_snap: i64,
    ) -> Option<RecordKey> {
        if !self.namespaces.contains_key(&parent_key) {
            return None;
        }
        let key = self.next_key;
        self.next_key += 1;
        let ns = TraceNamespace::new(key, name, Some(parent_key), min_snap);
        self.namespaces.insert(key, ns);
        self.children
            .entry(parent_key)
            .or_default()
            .push(key);
        Some(key)
    }

    /// Get a namespace by key.
    pub fn get(&self, key: RecordKey) -> Option<&TraceNamespace> {
        self.namespaces.get(&key)
    }

    /// Get mutable access to a namespace.
    pub fn get_mut(&mut self, key: RecordKey) -> Option<&mut TraceNamespace> {
        self.namespaces.get_mut(&key)
    }

    /// Get all children of a namespace.
    pub fn children_of(&self, parent_key: RecordKey) -> &[RecordKey] {
        self.children
            .get(&parent_key)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Get all descendants of a namespace (recursive).
    pub fn descendants_of(&self, parent_key: RecordKey) -> Vec<RecordKey> {
        let mut result = Vec::new();
        let mut stack = vec![parent_key];
        while let Some(key) = stack.pop() {
            if let Some(children) = self.children.get(&key) {
                for &child in children {
                    result.push(child);
                    stack.push(child);
                }
            }
        }
        result
    }

    /// Resolve a path like "::std::io" to a namespace key.
    pub fn resolve_path(&self, path: &str) -> Option<RecordKey> {
        let parts: Vec<&str> = path.split("::").filter(|s| !s.is_empty()).collect();
        if parts.is_empty() {
            return Some(self.global_key());
        }

        let mut current = self.global_key();
        for part in &parts {
            let children = self.children_of(current);
            let found = children.iter().find(|&&child| {
                self.namespaces
                    .get(&child)
                    .map(|ns| ns.name == *part)
                    .unwrap_or(false)
            });
            match found {
                Some(&key) => current = key,
                None => return None,
            }
        }
        Some(current)
    }

    /// Get the full path for a namespace.
    pub fn path_of(&self, key: RecordKey) -> String {
        let mut parts = Vec::new();
        let mut current = Some(key);
        while let Some(k) = current {
            if let Some(ns) = self.namespaces.get(&k) {
                if !ns.is_global() {
                    parts.push(ns.name.clone());
                }
                current = ns.parent_key;
            } else {
                break;
            }
        }
        parts.reverse();
        format!("::{}", parts.join("::"))
    }

    /// Remove a namespace and all its descendants.
    pub fn remove_namespace(&mut self, key: RecordKey) -> Vec<TraceNamespace> {
        let mut removed = Vec::new();
        let descendants = self.descendants_of(key);
        for desc_key in descendants.into_iter().rev() {
            if let Some(ns) = self.namespaces.remove(&desc_key) {
                removed.push(ns);
            }
        }
        if let Some(ns) = self.namespaces.remove(&key) {
            removed.push(ns);
        }
        // Clean up children index
        for children in self.children.values_mut() {
            children.retain(|&k| self.namespaces.contains_key(&k));
        }
        removed
    }

    /// Get the total number of namespaces.
    pub fn len(&self) -> usize {
        self.namespaces.len()
    }

    /// Check if the manager is empty.
    pub fn is_empty(&self) -> bool {
        self.namespaces.is_empty()
    }

    /// Iterate over all namespaces.
    pub fn iter(&self) -> impl Iterator<Item = &TraceNamespace> {
        self.namespaces.values()
    }
}

impl Default for TraceNamespaceManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_global_namespace() {
        let mgr = TraceNamespaceManager::new();
        let global = mgr.get(mgr.global_key()).unwrap();
        assert!(global.is_global());
        assert_eq!(global.name, "::");
    }

    #[test]
    fn test_create_namespace() {
        let mut mgr = TraceNamespaceManager::new();
        let std_key = mgr.create_namespace("std", 0, 0).unwrap();
        let ns = mgr.get(std_key).unwrap();
        assert_eq!(ns.name, "std");
        assert_eq!(ns.parent_key, Some(0));
    }

    #[test]
    fn test_hierarchy() {
        let mut mgr = TraceNamespaceManager::new();
        let std_key = mgr.create_namespace("std", 0, 0).unwrap();
        let io_key = mgr.create_namespace("io", std_key, 0).unwrap();
        let fs_key = mgr.create_namespace("fs", io_key, 0).unwrap();

        assert_eq!(mgr.children_of(0), &[std_key]);
        assert_eq!(mgr.children_of(std_key), &[io_key]);

        let descendants = mgr.descendants_of(0);
        assert_eq!(descendants.len(), 3);
        assert!(descendants.contains(&std_key));
        assert!(descendants.contains(&io_key));
        assert!(descendants.contains(&fs_key));
    }

    #[test]
    fn test_resolve_path() {
        let mut mgr = TraceNamespaceManager::new();
        let std_key = mgr.create_namespace("std", 0, 0).unwrap();
        let io_key = mgr.create_namespace("io", std_key, 0).unwrap();

        assert_eq!(mgr.resolve_path("::std::io"), Some(io_key));
        assert_eq!(mgr.resolve_path("::std"), Some(std_key));
        assert_eq!(mgr.resolve_path("::nonexistent"), None);
        assert_eq!(mgr.resolve_path(""), Some(mgr.global_key()));
    }

    #[test]
    fn test_path_of() {
        let mut mgr = TraceNamespaceManager::new();
        let std_key = mgr.create_namespace("std", 0, 0).unwrap();
        let io_key = mgr.create_namespace("io", std_key, 0).unwrap();

        assert_eq!(mgr.path_of(io_key), "::std::io");
        assert_eq!(mgr.path_of(std_key), "::std");
        assert_eq!(mgr.path_of(0), "::");
    }

    #[test]
    fn test_remove_namespace() {
        let mut mgr = TraceNamespaceManager::new();
        let std_key = mgr.create_namespace("std", 0, 0).unwrap();
        let io_key = mgr.create_namespace("io", std_key, 0).unwrap();
        let _fs_key = mgr.create_namespace("fs", io_key, 0).unwrap();

        assert_eq!(mgr.len(), 4); // global + std + io + fs

        let removed = mgr.remove_namespace(std_key);
        assert_eq!(removed.len(), 3); // std, io, fs
        assert_eq!(mgr.len(), 1); // only global remains
        assert!(mgr.resolve_path("::std").is_none());
    }

    #[test]
    fn test_namespace_visibility() {
        let mut ns = TraceNamespace::new(1, "test", Some(0), 10);
        assert!(!ns.is_visible_at(5));
        assert!(ns.is_visible_at(10));
        assert!(ns.is_visible_at(100));

        ns.close(50);
        assert!(ns.is_visible_at(30));
        assert!(!ns.is_visible_at(60));
    }
}
