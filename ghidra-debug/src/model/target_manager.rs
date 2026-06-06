//! TraceObjectManager - manages all objects in the target tree.
//!
//! Ported from Ghidra's `ghidra.trace.model.target.TraceObjectManager` interface.
//! Provides CRUD operations on TraceObjects, tree traversal, and canonical
//! path resolution.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::target_object::TraceObject;
use super::target_schema::{SchemaContext, SchemaName};
use super::target_value::TraceObjectValPath;
use crate::target::key_path::KeyPath;

/// Errors from the target object manager.
#[derive(Debug, Error)]
pub enum TargetObjectError {
    /// The object was not found.
    #[error("object not found: key={0}")]
    NotFound(i64),

    /// Duplicate key conflict.
    #[error("duplicate key: {0}")]
    DuplicateKey(String),

    /// Schema violation.
    #[error("schema violation: {0}")]
    SchemaViolation(String),

    /// The object is deleted.
    #[error("object is deleted: key={0}")]
    Deleted(i64),

    /// Invalid key path.
    #[error("invalid key path: {0}")]
    InvalidPath(String),
}

/// Manages all objects in the debug target tree.
///
/// Provides CRUD operations, tree traversal, path resolution, and schema
/// validation. Objects are organized in a tree rooted at the "root" object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceObjectManager {
    next_key: i64,
    objects: HashMap<i64, TraceObject>,
    root_key: Option<i64>,
    /// The schema context governing object structure.
    #[serde(skip)]
    schema_context: Option<SchemaContext>,
}

impl Default for TraceObjectManager {
    fn default() -> Self {
        Self {
            next_key: 1,
            objects: HashMap::new(),
            root_key: None,
            schema_context: None,
        }
    }
}

impl TraceObjectManager {
    /// Create a new, empty manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the schema context for validation.
    pub fn set_schema_context(&mut self, ctx: SchemaContext) {
        self.schema_context = Some(ctx);
    }

    /// Get the root object.
    pub fn root(&self) -> Option<&TraceObject> {
        self.root_key.and_then(|k| self.objects.get(&k))
    }

    /// Get the root object key.
    pub fn root_key(&self) -> Option<i64> {
        self.root_key
    }

    /// Create the root object.
    pub fn create_root(&mut self, schema_name: SchemaName) -> i64 {
        let key = self.allocate_key();
        let obj = TraceObject::new(
            key,
            schema_name,
            KeyPath::ROOT,
            i64::MIN,
        );
        self.objects.insert(key, obj);
        self.root_key = Some(key);
        key
    }

    /// Create a new object.
    pub fn create_object(
        &mut self,
        schema_name: SchemaName,
        canonical_path: KeyPath,
        creation_snap: i64,
    ) -> i64 {
        let key = self.allocate_key();
        let obj = TraceObject::new(key, schema_name, canonical_path, creation_snap);
        self.objects.insert(key, obj);
        key
    }

    /// Get an object by key.
    pub fn get_object(&self, key: i64) -> Option<&TraceObject> {
        self.objects.get(&key)
    }

    /// Get a mutable reference to an object.
    pub fn get_object_mut(&mut self, key: i64) -> Option<&mut TraceObject> {
        self.objects.get_mut(&key)
    }

    /// Delete an object by key.
    pub fn delete_object(&mut self, key: i64) -> Result<(), TargetObjectError> {
        if let Some(obj) = self.objects.get_mut(&key) {
            obj.delete();
            Ok(())
        } else {
            Err(TargetObjectError::NotFound(key))
        }
    }

    /// Remove an object from the manager entirely.
    pub fn remove_object(&mut self, key: i64) -> Option<TraceObject> {
        self.objects.remove(&key)
    }

    /// Get all objects at a given snap.
    pub fn objects_at(&self, snap: i64) -> Vec<&TraceObject> {
        self.objects
            .values()
            .filter(|o| !o.is_deleted() && o.creation_snap <= snap)
            .collect()
    }

    /// Get the total number of objects (including deleted).
    pub fn total_count(&self) -> usize {
        self.objects.len()
    }

    /// Get the number of live (non-deleted) objects.
    pub fn live_count(&self) -> usize {
        self.objects.values().filter(|o| !o.is_deleted()).count()
    }

    /// Find an object by its canonical path at a given snap.
    pub fn find_by_path(&self, path: &KeyPath, snap: i64) -> Option<&TraceObject> {
        self.objects.values().find(|o| {
            !o.is_deleted() && o.canonical_path == *path && o.creation_snap <= snap
        })
    }

    /// Get children of an object at a given snap.
    pub fn children_of(&self, parent_key: i64, snap: i64) -> Vec<&TraceObject> {
        let parent = match self.objects.get(&parent_key) {
            Some(p) => p,
            None => return Vec::new(),
        };
        let child_keys: Vec<i64> = parent
            .values()
            .iter()
            .filter(|v| v.is_valid_at(snap) && v.is_object())
            .filter_map(|v| v.child_object_key)
            .collect();
        child_keys
            .iter()
            .filter_map(|k| self.objects.get(k))
            .filter(|o| !o.is_deleted())
            .collect()
    }

    /// Get the canonical parent of an object.
    ///
    /// Finds the object that has a canonical value entry pointing to the given key.
    pub fn canonical_parent(&self, child_key: i64, snap: i64) -> Option<&TraceObject> {
        self.objects.values().find(|o| {
            !o.is_deleted()
                && o.values().iter().any(|v| {
                    v.is_valid_at(snap)
                        && v.is_canonical()
                        && v.child_object_key == Some(child_key)
                })
        })
    }

    /// Get the canonical path of an object.
    pub fn canonical_path_of(&self, key: i64) -> Option<KeyPath> {
        self.objects.get(&key).map(|o| o.canonical_path.clone())
    }

    /// Resolve a value path: traverse the tree following the given path entries.
    pub fn resolve_value_path(
        &self,
        start_key: i64,
        path: &TraceObjectValPath,
        snap: i64,
    ) -> Result<i64, TargetObjectError> {
        let mut current_key = start_key;
        for entry in path.entry_list() {
            let obj = self
                .objects
                .get(&current_key)
                .ok_or(TargetObjectError::NotFound(current_key))?;
            let val = obj
                .values()
                .iter()
                .find(|v| v.entry_key == entry.entry_key && v.is_valid_at(snap))
                .ok_or_else(|| {
                    TargetObjectError::InvalidPath(entry.entry_key.clone())
                })?;
            current_key = val.child_object_key.ok_or_else(|| {
                TargetObjectError::InvalidPath(format!(
                    "value '{}' is not an object",
                    entry.entry_key
                ))
            })?;
        }
        Ok(current_key)
    }

    /// Get all ancestor keys of an object (walking canonical parents up to root).
    pub fn ancestors(&self, key: i64, snap: i64) -> Vec<i64> {
        let mut result = Vec::new();
        let mut current = key;
        while let Some(parent) = self.canonical_parent(current, snap) {
            result.push(parent.key);
            if self.root_key == Some(parent.key) {
                break;
            }
            current = parent.key;
        }
        result
    }

    /// Allocate a new unique key.
    fn allocate_key(&mut self) -> i64 {
        let key = self.next_key;
        self.next_key += 1;
        key
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Lifespan;

    #[test]
    fn test_manager_create_root() {
        let mut mgr = TraceObjectManager::new();
        let root_key = mgr.create_root(SchemaName::new("ROOT"));
        assert_eq!(root_key, 1);
        assert_eq!(mgr.root_key(), Some(1));
        assert!(mgr.root().is_some());
    }

    #[test]
    fn test_manager_create_and_get() {
        let mut mgr = TraceObjectManager::new();
        let key = mgr.create_object(
            SchemaName::new("THREAD"),
            KeyPath::parse("Threads[0]"),
            0,
        );
        let obj = mgr.get_object(key).unwrap();
        assert_eq!(obj.schema_name, SchemaName::new("THREAD"));
    }

    #[test]
    fn test_manager_delete() {
        let mut mgr = TraceObjectManager::new();
        let key = mgr.create_object(
            SchemaName::new("OBJECT"),
            KeyPath::parse("Objects[1]"),
            0,
        );
        assert_eq!(mgr.live_count(), 1);
        mgr.delete_object(key).unwrap();
        assert_eq!(mgr.live_count(), 0);
    }

    #[test]
    fn test_manager_children() {
        let mut mgr = TraceObjectManager::new();
        let root_key = mgr.create_root(SchemaName::new("ROOT"));
        let child_key = mgr.create_object(
            SchemaName::new("CHILD"),
            KeyPath::parse("Children[0]"),
            0,
        );

        // Link child to root
        mgr.get_object_mut(root_key)
            .unwrap()
            .set_child("Children", child_key, Lifespan::ALL, true);

        let children = mgr.children_of(root_key, 0);
        assert_eq!(children.len(), 1);
        assert_eq!(children[0].key, child_key);
    }

    #[test]
    fn test_manager_canonical_parent() {
        let mut mgr = TraceObjectManager::new();
        let parent_key = mgr.create_object(
            SchemaName::new("PARENT"),
            KeyPath::parse("Parent"),
            0,
        );
        let child_key = mgr.create_object(
            SchemaName::new("CHILD"),
            KeyPath::parse("Parent.Child"),
            0,
        );

        mgr.get_object_mut(parent_key)
            .unwrap()
            .set_child("Child", child_key, Lifespan::ALL, true);

        let parent = mgr.canonical_parent(child_key, 0).unwrap();
        assert_eq!(parent.key, parent_key);
    }

    #[test]
    fn test_manager_find_by_path() {
        let mut mgr = TraceObjectManager::new();
        let _ = mgr.create_object(
            SchemaName::new("THREAD"),
            KeyPath::parse("Processes[0].Threads[1]"),
            0,
        );
        let found = mgr.find_by_path(&KeyPath::parse("Processes[0].Threads[1]"), 0);
        assert!(found.is_some());
        let not_found = mgr.find_by_path(&KeyPath::parse("NonExistent"), 0);
        assert!(not_found.is_none());
    }

    #[test]
    fn test_manager_total_and_live_count() {
        let mut mgr = TraceObjectManager::new();
        let k1 = mgr.create_object(
            SchemaName::new("A"),
            KeyPath::parse("A"),
            0,
        );
        let _k2 = mgr.create_object(
            SchemaName::new("B"),
            KeyPath::parse("B"),
            0,
        );
        assert_eq!(mgr.total_count(), 2);
        assert_eq!(mgr.live_count(), 2);

        mgr.delete_object(k1).unwrap();
        assert_eq!(mgr.total_count(), 2);
        assert_eq!(mgr.live_count(), 1);
    }

    #[test]
    fn test_manager_ancestors() {
        let mut mgr = TraceObjectManager::new();
        let root = mgr.create_root(SchemaName::new("ROOT"));
        let mid = mgr.create_object(
            SchemaName::new("MID"),
            KeyPath::parse("Mid"),
            0,
        );
        let leaf = mgr.create_object(
            SchemaName::new("LEAF"),
            KeyPath::parse("Mid.Leaf"),
            0,
        );

        mgr.get_object_mut(root)
            .unwrap()
            .set_child("Mid", mid, Lifespan::ALL, true);
        mgr.get_object_mut(mid)
            .unwrap()
            .set_child("Leaf", leaf, Lifespan::ALL, true);

        let ancestors = mgr.ancestors(leaf, 0);
        assert_eq!(ancestors, vec![mid, root]);
    }

    #[test]
    fn test_manager_serde() {
        let mut mgr = TraceObjectManager::new();
        mgr.create_root(SchemaName::new("ROOT"));
        let json = serde_json::to_string(&mgr).unwrap();
        let back: TraceObjectManager = serde_json::from_str(&json).unwrap();
        assert_eq!(back.total_count(), 1);
    }
}
