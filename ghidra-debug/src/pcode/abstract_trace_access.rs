//! Abstract pcode trace access implementations.
//!
//! Ported from Ghidra's `ghidra.pcode.exec.trace.data` package:
//! - `AbstractPcodeTraceAccess`: Base for all trace access implementations.
//! - `AbstractPcodeTraceDataAccess`: Abstract data access with caching.
//! - `DefaultPcodeTracePropertyAccess`: Default property map access.
//! - `DefaultPcodeTraceThreadAccess`: Default thread-scoped access.
//!
//! These types provide the shared logic for reading and writing trace
//! data during p-code execution, including snap/thread context management
//! and property map access.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::model::Lifespan;

// ---------------------------------------------------------------------------
// SnapAndThread — context for trace data access
// ---------------------------------------------------------------------------

/// A (snap, thread, frame) context for trace data access.
///
/// Ported from Ghidra's internal snap+thread context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SnapAndThread {
    /// The snapshot (time) at which data is accessed.
    pub snap: i64,
    /// The thread key (0 for global access).
    pub thread_key: u64,
    /// The stack frame level.
    pub frame: i32,
}

impl SnapAndThread {
    /// Create a new snap-and-thread context.
    pub fn new(snap: i64, thread_key: u64, frame: i32) -> Self {
        Self { snap, thread_key, frame }
    }

    /// Create a global context (no thread).
    pub fn global(snap: i64) -> Self {
        Self { snap, thread_key: 0, frame: 0 }
    }

    /// Whether this is a global (thread-less) context.
    pub fn is_global(&self) -> bool {
        self.thread_key == 0
    }
}

impl Default for SnapAndThread {
    fn default() -> Self {
        Self::global(0)
    }
}

// ---------------------------------------------------------------------------
// Property access
// ---------------------------------------------------------------------------

/// A single property entry in a property map.
///
/// Ported from Ghidra's property map entries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PropertyEntry<T: Clone> {
    /// The address offset.
    pub address: u64,
    /// The address space name.
    pub space: String,
    /// The property value.
    pub value: T,
    /// The lifespan over which this property is valid.
    pub lifespan: Lifespan,
}

impl<T: Clone> PropertyEntry<T> {
    /// Create a new property entry.
    pub fn new(address: u64, space: impl Into<String>, value: T, lifespan: Lifespan) -> Self {
        Self {
            address,
            space: space.into(),
            value,
            lifespan,
        }
    }
}

/// Property map access interface for p-code trace execution.
///
/// Ported from Ghidra's `DefaultPcodeTracePropertyAccess`.
pub trait TracePropertyAccess: Send + Sync {
    /// Get a property value by name, space, and address.
    fn get_property(&self, name: &str, space: &str, address: u64) -> Option<String>;

    /// Set a property value.
    fn set_property(&mut self, name: &str, space: &str, address: u64, value: &str);

    /// Remove a property value.
    fn remove_property(&mut self, name: &str, space: &str, address: u64);

    /// Get all properties for a given space and address range.
    fn get_properties_in_range(
        &self,
        name: &str,
        space: &str,
        min_addr: u64,
        max_addr: u64,
    ) -> Vec<PropertyEntry<String>>;
}

/// Default property access implementation backed by an in-memory map.
///
/// Ported from Ghidra's `DefaultPcodeTracePropertyAccess`.
#[derive(Debug, Clone, Default)]
pub struct DefaultPropertyAccess {
    /// Inner storage: (property_name, space, address) -> value.
    properties: BTreeMap<(String, String, u64), String>,
}

impl DefaultPropertyAccess {
    /// Create a new empty property access.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the number of stored properties.
    pub fn len(&self) -> usize {
        self.properties.len()
    }

    /// Check if there are no stored properties.
    pub fn is_empty(&self) -> bool {
        self.properties.is_empty()
    }
}

impl TracePropertyAccess for DefaultPropertyAccess {
    fn get_property(&self, name: &str, space: &str, address: u64) -> Option<String> {
        self.properties
            .get(&(name.to_string(), space.to_string(), address))
            .cloned()
    }

    fn set_property(&mut self, name: &str, space: &str, address: u64, value: &str) {
        self.properties.insert(
            (name.to_string(), space.to_string(), address),
            value.to_string(),
        );
    }

    fn remove_property(&mut self, name: &str, space: &str, address: u64) {
        self.properties
            .remove(&(name.to_string(), space.to_string(), address));
    }

    fn get_properties_in_range(
        &self,
        name: &str,
        space: &str,
        min_addr: u64,
        max_addr: u64,
    ) -> Vec<PropertyEntry<String>> {
        self.properties
            .iter()
            .filter(|((n, s, a), _)| n == name && s == space && *a >= min_addr && *a <= max_addr)
            .map(|((_, _, a), v)| PropertyEntry::new(*a, space, v.clone(), Lifespan::ALL))
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Thread-scoped data access
// ---------------------------------------------------------------------------

/// Thread context for p-code trace data access.
///
/// Ported from Ghidra's `DefaultPcodeTraceThreadAccess`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadAccessContext {
    /// The thread key.
    pub thread_key: u64,
    /// The thread name.
    pub thread_name: String,
    /// The process key.
    pub process_key: u64,
    /// The current stack frame level.
    pub frame_level: i32,
}

impl ThreadAccessContext {
    /// Create a new thread access context.
    pub fn new(thread_key: u64, thread_name: impl Into<String>, process_key: u64) -> Self {
        Self {
            thread_key,
            thread_name: thread_name.into(),
            process_key,
            frame_level: 0,
        }
    }

    /// Whether this represents a valid thread.
    pub fn is_valid(&self) -> bool {
        self.thread_key != 0
    }
}

/// Trait for thread-aware p-code trace data access.
pub trait PcodeTraceThreadAware: Send + Sync {
    /// Get the thread context for the given thread key.
    fn get_thread_context(&self, thread_key: u64) -> Option<ThreadAccessContext>;

    /// Get all available thread contexts.
    fn all_thread_contexts(&self) -> Vec<ThreadAccessContext>;

    /// Set the current frame level for a thread.
    fn set_frame_level(&mut self, thread_key: u64, frame: i32);

    /// Get the current frame level for a thread.
    fn get_frame_level(&self, thread_key: u64) -> i32;
}

/// Default implementation of thread-aware access.
#[derive(Debug, Clone, Default)]
pub struct DefaultThreadAccess {
    threads: BTreeMap<u64, ThreadAccessContext>,
    frame_levels: BTreeMap<u64, i32>,
}

impl DefaultThreadAccess {
    /// Create a new empty thread access.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a thread context.
    pub fn register_thread(&mut self, ctx: ThreadAccessContext) {
        self.threads.insert(ctx.thread_key, ctx);
    }
}

impl PcodeTraceThreadAware for DefaultThreadAccess {
    fn get_thread_context(&self, thread_key: u64) -> Option<ThreadAccessContext> {
        self.threads.get(&thread_key).cloned()
    }

    fn all_thread_contexts(&self) -> Vec<ThreadAccessContext> {
        self.threads.values().cloned().collect()
    }

    fn set_frame_level(&mut self, thread_key: u64, frame: i32) {
        self.frame_levels.insert(thread_key, frame);
    }

    fn get_frame_level(&self, thread_key: u64) -> i32 {
        self.frame_levels.get(&thread_key).copied().unwrap_or(0)
    }
}

// ---------------------------------------------------------------------------
// Abstract trace data access with caching
// ---------------------------------------------------------------------------

/// Cache entry for trace data reads.
#[derive(Debug, Clone)]
pub struct CacheEntry {
    /// The cached bytes.
    pub data: Vec<u8>,
    /// The address from which data was read.
    pub address: u64,
    /// The snap at which data was read.
    pub snap: i64,
    /// Whether the data is still valid.
    pub valid: bool,
}

impl CacheEntry {
    /// Create a new cache entry.
    pub fn new(address: u64, snap: i64, data: Vec<u8>) -> Self {
        Self {
            data,
            address,
            snap,
            valid: true,
        }
    }

    /// Invalidate this cache entry.
    pub fn invalidate(&mut self) {
        self.valid = false;
    }
}

/// A simple read cache for trace data access.
///
/// Caches memory reads to avoid repeated database queries during
/// p-code execution of a single instruction.
#[derive(Debug, Clone, Default)]
pub struct TraceDataReadCache {
    /// Cache entries indexed by (space_name, address).
    entries: BTreeMap<(String, u64), CacheEntry>,
}

impl TraceDataReadCache {
    /// Create a new empty cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a cache entry.
    pub fn insert(&mut self, space: &str, address: u64, snap: i64, data: Vec<u8>) {
        self.entries.insert(
            (space.to_string(), address),
            CacheEntry::new(address, snap, data),
        );
    }

    /// Get cached data for the given space and address.
    pub fn get(&self, space: &str, address: u64) -> Option<&CacheEntry> {
        self.entries.get(&(space.to_string(), address))
    }

    /// Get the number of cached entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Invalidate all entries.
    pub fn invalidate_all(&mut self) {
        for entry in self.entries.values_mut() {
            entry.invalidate();
        }
    }

    /// Clear all entries.
    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_snap_and_thread_context() {
        let ctx = SnapAndThread::new(100, 5, 0);
        assert_eq!(ctx.snap, 100);
        assert_eq!(ctx.thread_key, 5);
        assert!(!ctx.is_global());

        let global = SnapAndThread::global(200);
        assert!(global.is_global());
        assert_eq!(global.snap, 200);
    }

    #[test]
    fn test_snap_and_thread_default() {
        let ctx = SnapAndThread::default();
        assert_eq!(ctx.snap, 0);
        assert!(ctx.is_global());
    }

    #[test]
    fn test_property_entry() {
        let entry = PropertyEntry::new(0x1000, "ram", "true".to_string(), Lifespan::span(0, 100));
        assert_eq!(entry.address, 0x1000);
        assert_eq!(entry.space, "ram");
        assert_eq!(entry.value, "true");
    }

    #[test]
    fn test_default_property_access_set_get() {
        let mut props = DefaultPropertyAccess::new();
        assert!(props.is_empty());

        props.set_property("ReadOnly", "ram", 0x1000, "true");
        assert_eq!(props.len(), 1);

        let val = props.get_property("ReadOnly", "ram", 0x1000);
        assert_eq!(val.as_deref(), Some("true"));

        assert!(props.get_property("ReadOnly", "ram", 0x2000).is_none());
        assert!(props.get_property("Writable", "ram", 0x1000).is_none());
    }

    #[test]
    fn test_default_property_access_remove() {
        let mut props = DefaultPropertyAccess::new();
        props.set_property("X", "ram", 0x100, "val");
        assert_eq!(props.len(), 1);

        props.remove_property("X", "ram", 0x100);
        assert!(props.is_empty());
    }

    #[test]
    fn test_default_property_access_range_query() {
        let mut props = DefaultPropertyAccess::new();
        for i in 0..10 {
            props.set_property("Flag", "ram", 0x1000 + i * 0x100, "yes");
        }

        let entries = props.get_properties_in_range("Flag", "ram", 0x1000, 0x1400);
        assert_eq!(entries.len(), 5); // 0x1000, 0x1100, 0x1200, 0x1300, 0x1400
    }

    #[test]
    fn test_thread_access_context() {
        let ctx = ThreadAccessContext::new(1, "main", 10);
        assert!(ctx.is_valid());
        assert_eq!(ctx.thread_key, 1);
        assert_eq!(ctx.frame_level, 0);

        let invalid = ThreadAccessContext::new(0, "", 0);
        assert!(!invalid.is_valid());
    }

    #[test]
    fn test_default_thread_access() {
        let mut ta = DefaultThreadAccess::new();
        assert!(ta.all_thread_contexts().is_empty());

        ta.register_thread(ThreadAccessContext::new(1, "main", 10));
        ta.register_thread(ThreadAccessContext::new(2, "worker", 10));

        assert_eq!(ta.all_thread_contexts().len(), 2);
        assert!(ta.get_thread_context(1).is_some());
        assert!(ta.get_thread_context(99).is_none());

        ta.set_frame_level(1, 3);
        assert_eq!(ta.get_frame_level(1), 3);
        assert_eq!(ta.get_frame_level(2), 0); // default
    }

    #[test]
    fn test_cache_entry() {
        let mut entry = CacheEntry::new(0x1000, 10, vec![1, 2, 3, 4]);
        assert!(entry.valid);
        assert_eq!(entry.data.len(), 4);

        entry.invalidate();
        assert!(!entry.valid);
    }

    #[test]
    fn test_trace_data_read_cache() {
        let mut cache = TraceDataReadCache::new();
        assert!(cache.is_empty());

        cache.insert("ram", 0x1000, 10, vec![0xAA, 0xBB]);
        cache.insert("ram", 0x2000, 10, vec![0xCC, 0xDD]);
        assert_eq!(cache.len(), 2);

        let entry = cache.get("ram", 0x1000).unwrap();
        assert_eq!(entry.data, vec![0xAA, 0xBB]);
        assert!(cache.get("ram", 0x3000).is_none());

        cache.invalidate_all();
        let entry = cache.get("ram", 0x1000).unwrap();
        assert!(!entry.valid);

        cache.clear();
        assert!(cache.is_empty());
    }
}
