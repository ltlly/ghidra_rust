//! Thread-safe bundle container mapping bundles by file and location.
//!
//! Ported from `ghidra.app.plugin.core.osgi.BundleMap`.
//!
//! Provides a concurrent-safe map that indexes [`GhidraBundle`]s by
//! both their source file path and their OSGi location identifier.
//! This dual-indexing supports both file-based and location-based lookups.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::RwLock;

use super::{BundleStatus, GhidraBundle};

/// A thread-safe container that maps bundles by file path and location identifier.
///
/// Ported from `ghidra.app.plugin.core.osgi.BundleMap`.
///
/// Uses `RwLock` for concurrent read access with exclusive write access.
/// This is an enhanced version of the top-level [`BundleMap`] that adds
/// file-based indexing and thread safety.
#[derive(Debug)]
pub struct ThreadSafeBundleMap {
    inner: RwLock<BundleMapInner>,
}

#[derive(Debug)]
struct BundleMapInner {
    by_source: HashMap<PathBuf, usize>,
    by_symbolic_name: HashMap<String, usize>,
    bundles: Vec<GhidraBundle>,
}

impl ThreadSafeBundleMap {
    /// Create a new empty thread-safe bundle map.
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(BundleMapInner {
                by_source: HashMap::new(),
                by_symbolic_name: HashMap::new(),
                bundles: Vec::new(),
            }),
        }
    }

    /// Add a bundle to the map.
    pub fn add(&self, bundle: GhidraBundle) {
        let mut inner = self.inner.write().unwrap();
        let idx = inner.bundles.len();
        inner.by_source.insert(bundle.source_path.clone(), idx);
        inner.by_symbolic_name.insert(bundle.symbolic_name.clone(), idx);
        inner.bundles.push(bundle);
    }

    /// Add multiple bundles.
    pub fn add_all(&self, bundles: Vec<GhidraBundle>) {
        let mut inner = self.inner.write().unwrap();
        for bundle in bundles {
            let idx = inner.bundles.len();
            inner.by_source.insert(bundle.source_path.clone(), idx);
            inner.by_symbolic_name.insert(bundle.symbolic_name.clone(), idx);
            inner.bundles.push(bundle);
        }
    }

    /// Remove a bundle by its symbolic name.
    pub fn remove_by_name(&self, name: &str) -> Option<GhidraBundle> {
        let mut inner = self.inner.write().unwrap();
        if let Some(&idx) = inner.by_symbolic_name.get(name) {
            let bundle = inner.bundles.remove(idx);
            // Rebuild indices (indices shifted after removal)
            let rebuild_data: Vec<_> = inner
                .bundles
                .iter()
                .enumerate()
                .map(|(i, b)| (b.source_path.clone(), b.symbolic_name.clone(), i))
                .collect();
            inner.by_source.clear();
            inner.by_symbolic_name.clear();
            for (source, symbolic, i) in rebuild_data {
                inner.by_source.insert(source, i);
                inner.by_symbolic_name.insert(symbolic, i);
            }
            Some(bundle)
        } else {
            None
        }
    }

    /// Look up a bundle by source path.
    pub fn get_by_source(&self, path: &PathBuf) -> Option<GhidraBundle> {
        let inner = self.inner.read().unwrap();
        inner
            .by_source
            .get(path)
            .and_then(|&idx| inner.bundles.get(idx))
            .cloned()
    }

    /// Look up a bundle by symbolic name.
    pub fn get_by_name(&self, name: &str) -> Option<GhidraBundle> {
        let inner = self.inner.read().unwrap();
        inner
            .by_symbolic_name
            .get(name)
            .and_then(|&idx| inner.bundles.get(idx))
            .cloned()
    }

    /// Get all bundles.
    pub fn all_bundles(&self) -> Vec<GhidraBundle> {
        let inner = self.inner.read().unwrap();
        inner.bundles.clone()
    }

    /// Get the number of bundles.
    pub fn len(&self) -> usize {
        let inner = self.inner.read().unwrap();
        inner.bundles.len()
    }

    /// Whether the map is empty.
    pub fn is_empty(&self) -> bool {
        let inner = self.inner.read().unwrap();
        inner.bundles.is_empty()
    }

    /// Get bundles filtered by status.
    pub fn bundles_with_status(&self, status: BundleStatus) -> Vec<GhidraBundle> {
        let inner = self.inner.read().unwrap();
        inner
            .bundles
            .iter()
            .filter(|b| b.status == status)
            .cloned()
            .collect()
    }

    /// Get all symbolic names.
    pub fn symbolic_names(&self) -> Vec<String> {
        let inner = self.inner.read().unwrap();
        inner.bundles.iter().map(|b| b.symbolic_name.clone()).collect()
    }

    /// Check if a bundle with the given symbolic name exists.
    pub fn contains_name(&self, name: &str) -> bool {
        let inner = self.inner.read().unwrap();
        inner.by_symbolic_name.contains_key(name)
    }

    /// Check if a bundle with the given source path exists.
    pub fn contains_source(&self, path: &PathBuf) -> bool {
        let inner = self.inner.read().unwrap();
        inner.by_source.contains_key(path)
    }

    /// Update the status of a bundle.
    pub fn set_status(&self, name: &str, status: BundleStatus) -> bool {
        let mut inner = self.inner.write().unwrap();
        if let Some(&idx) = inner.by_symbolic_name.get(name) {
            if let Some(bundle) = inner.bundles.get_mut(idx) {
                bundle.status = status;
                return true;
            }
        }
        false
    }

    /// Clear all bundles.
    pub fn clear(&self) {
        let mut inner = self.inner.write().unwrap();
        inner.bundles.clear();
        inner.by_source.clear();
        inner.by_symbolic_name.clear();
    }
}

impl Default for ThreadSafeBundleMap {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_bundle(name: &str, path: &str) -> GhidraBundle {
        GhidraBundle::new(name, name, "1.0.0", path)
    }

    #[test]
    fn test_thread_safe_bundle_map_add_and_get() {
        let map = ThreadSafeBundleMap::new();
        map.add(make_bundle("test", "/tmp/test.jar"));
        assert_eq!(map.len(), 1);

        let by_name = map.get_by_name("test");
        assert!(by_name.is_some());
        assert_eq!(by_name.unwrap().display_name, "test");

        let by_source = map.get_by_source(&PathBuf::from("/tmp/test.jar"));
        assert!(by_source.is_some());
    }

    #[test]
    fn test_thread_safe_bundle_map_remove() {
        let map = ThreadSafeBundleMap::new();
        map.add(make_bundle("a", "/a.jar"));
        map.add(make_bundle("b", "/b.jar"));

        let removed = map.remove_by_name("a");
        assert!(removed.is_some());
        assert_eq!(map.len(), 1);

        // Verify remaining bundle still findable
        assert!(map.get_by_name("b").is_some());
    }

    #[test]
    fn test_thread_safe_bundle_map_contains() {
        let map = ThreadSafeBundleMap::new();
        map.add(make_bundle("x", "/x.jar"));
        assert!(map.contains_name("x"));
        assert!(map.contains_source(&PathBuf::from("/x.jar")));
        assert!(!map.contains_name("y"));
    }

    #[test]
    fn test_thread_safe_bundle_map_status_filter() {
        let map = ThreadSafeBundleMap::new();
        map.add(make_bundle("a", "/a.jar"));
        map.add(make_bundle("b", "/b.jar"));
        map.set_status("b", BundleStatus::Active);

        let installed = map.bundles_with_status(BundleStatus::Installed);
        assert_eq!(installed.len(), 1);

        let active = map.bundles_with_status(BundleStatus::Active);
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].symbolic_name, "b");
    }

    #[test]
    fn test_thread_safe_bundle_map_set_status() {
        let map = ThreadSafeBundleMap::new();
        map.add(make_bundle("x", "/x.jar"));
        assert!(map.set_status("x", BundleStatus::Active));
        let bundle = map.get_by_name("x").unwrap();
        assert_eq!(bundle.status, BundleStatus::Active);
    }

    #[test]
    fn test_thread_safe_bundle_map_add_all() {
        let map = ThreadSafeBundleMap::new();
        let bundles = vec![
            make_bundle("a", "/a.jar"),
            make_bundle("b", "/b.jar"),
            make_bundle("c", "/c.jar"),
        ];
        map.add_all(bundles);
        assert_eq!(map.len(), 3);
    }

    #[test]
    fn test_thread_safe_bundle_map_clear() {
        let map = ThreadSafeBundleMap::new();
        map.add(make_bundle("x", "/x.jar"));
        map.clear();
        assert!(map.is_empty());
    }

    #[test]
    fn test_thread_safe_bundle_map_symbolic_names() {
        let map = ThreadSafeBundleMap::new();
        map.add(make_bundle("a", "/a.jar"));
        map.add(make_bundle("b", "/b.jar"));
        let names = map.symbolic_names();
        assert_eq!(names.len(), 2);
    }

    #[test]
    fn test_thread_safe_bundle_map_concurrent() {
        use std::sync::Arc;
        use std::thread;

        let map = Arc::new(ThreadSafeBundleMap::new());
        let mut handles = vec![];

        for i in 0..5 {
            let map = Arc::clone(&map);
            handles.push(thread::spawn(move || {
                map.add(make_bundle(&format!("bundle_{}", i), &format!("/{}.jar", i)));
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }

        assert_eq!(map.len(), 5);
    }
}
