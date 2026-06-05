//! The main trace database implementation.
//!
//! Ported from Ghidra's `DBTrace` - the SQLite-backed implementation
//! of the `Trace` interface that ties together all sub-managers.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

use crate::model::{
    Lifespan, TraceBookmarkManager, TraceCodeManager,
    TracePlatformManager, TraceRegisterContextManager,
    TraceStackManager, TraceSymbolManager, TraceTimeManager,
    TraceUserData,
    TraceMemoryManagerExt, TraceModuleManagerExt, TraceThreadManagerExt,
};

/// Configuration for creating a trace database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceDatabaseConfig {
    /// Name of the trace.
    pub name: String,
    /// Language ID (e.g. "x86:LE:64:default").
    pub language_id: String,
    /// Compiler spec ID (e.g. "default").
    pub compiler_spec_id: String,
    /// Maximum undo depth.
    pub max_undo_depth: usize,
}

impl TraceDatabaseConfig {
    /// Create a new config with defaults.
    pub fn new(name: impl Into<String>, language_id: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            language_id: language_id.into(),
            compiler_spec_id: "default".to_string(),
            max_undo_depth: 10,
        }
    }
}

/// The change set tracking modifications to a trace database.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DBTraceChangeSet {
    /// IDs of changed snapshots.
    pub changed_snapshots: Vec<i64>,
    /// IDs of changed threads.
    pub changed_threads: Vec<i64>,
    /// IDs of changed modules.
    pub changed_modules: Vec<i64>,
    /// IDs of changed breakpoints.
    pub changed_breakpoints: Vec<i64>,
    /// Whether memory was changed.
    pub memory_changed: bool,
    /// Whether the listing was changed.
    pub listing_changed: bool,
}

impl DBTraceChangeSet {
    /// Create a new empty change set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Mark a snapshot as changed.
    pub fn mark_snapshot_changed(&mut self, id: i64) {
        if !self.changed_snapshots.contains(&id) {
            self.changed_snapshots.push(id);
        }
    }

    /// Mark a thread as changed.
    pub fn mark_thread_changed(&mut self, id: i64) {
        if !self.changed_threads.contains(&id) {
            self.changed_threads.push(id);
        }
    }

    /// Clear the change set.
    pub fn clear(&mut self) {
        *self = Self::default();
    }

    /// Whether any changes were recorded.
    pub fn has_changes(&self) -> bool {
        !self.changed_snapshots.is_empty()
            || !self.changed_threads.is_empty()
            || !self.changed_modules.is_empty()
            || !self.changed_breakpoints.is_empty()
            || self.memory_changed
            || self.listing_changed
    }
}

/// A listener for direct changes to the trace database.
pub trait TraceDirectChangeListener: Send + Sync {
    /// Called when memory bytes change.
    fn on_memory_changed(&self, space: &str, addr: u64, len: usize);
    /// Called when a thread is added or removed.
    fn on_thread_changed(&self, thread_key: i64);
    /// Called when a module is added or removed.
    fn on_module_changed(&self, module_key: i64);
}

/// The main trace database, owning all sub-managers.
///
/// This is the Rust equivalent of Ghidra's `DBTrace`. It aggregates all
/// the individual managers that handle different aspects of a debug trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DBTrace {
    /// Database configuration.
    pub config: TraceDatabaseConfig,
    /// Whether the trace is open.
    pub open: bool,
    /// Whether the trace has been modified.
    pub changed: bool,
    /// The time manager (snapshots).
    pub time: TraceTimeManager,
    /// The thread/process manager.
    pub threads: TraceThreadManagerExt,
    /// The memory manager.
    pub memory: TraceMemoryManagerExt,
    /// The module/section/static mapping manager.
    pub modules: TraceModuleManagerExt,
    /// The code listing manager.
    pub listing: TraceCodeManager,
    /// The register context manager.
    pub register_context: TraceRegisterContextManager,
    /// The stack manager.
    pub stacks: TraceStackManager,
    /// The symbol manager.
    pub symbols: TraceSymbolManager,
    /// The bookmark manager.
    pub bookmarks: TraceBookmarkManager,
    /// The platform manager.
    pub platforms: TracePlatformManager,
    /// User data.
    pub user_data: TraceUserData,
    /// The change set.
    pub change_set: DBTraceChangeSet,
    /// User-defined options/properties.
    pub options: BTreeMap<String, String>,
    /// Database file path (if persisted).
    pub path: Option<PathBuf>,
}

impl DBTrace {
    /// Create a new trace database in memory.
    pub fn new(config: TraceDatabaseConfig) -> Self {
        Self {
            config,
            open: true,
            changed: false,
            time: TraceTimeManager::new(),
            threads: TraceThreadManagerExt::new(),
            memory: TraceMemoryManagerExt::new(),
            modules: TraceModuleManagerExt::new(),
            listing: TraceCodeManager::new(),
            register_context: TraceRegisterContextManager::new(),
            stacks: TraceStackManager::new(),
            symbols: TraceSymbolManager::new(),
            bookmarks: TraceBookmarkManager::new(),
            platforms: TracePlatformManager::new(),
            user_data: TraceUserData::new(),
            change_set: DBTraceChangeSet::new(),
            options: BTreeMap::new(),
            path: None,
        }
    }

    /// Whether the trace is still open.
    pub fn is_open(&self) -> bool {
        self.open
    }

    /// Close the trace.
    pub fn close(&mut self) {
        self.open = false;
    }

    /// Set a user option.
    pub fn set_option(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.options.insert(key.into(), value.into());
        self.changed = true;
    }

    /// Get a user option.
    pub fn get_option(&self, key: &str) -> Option<&String> {
        self.options.get(key)
    }

    /// Get the trace name.
    pub fn name(&self) -> &str {
        &self.config.name
    }

    /// Get the language ID.
    pub fn language_id(&self) -> &str {
        &self.config.language_id
    }

    /// Record that memory has changed.
    pub fn mark_memory_changed(&mut self) {
        self.changed = true;
        self.change_set.memory_changed = true;
    }

    /// Record that the listing has changed.
    pub fn mark_listing_changed(&mut self) {
        self.changed = true;
        self.change_set.listing_changed = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_db_trace() {
        let config = TraceDatabaseConfig::new("test_trace", "x86:LE:64:default");
        let trace = DBTrace::new(config);
        assert!(trace.is_open());
        assert_eq!(trace.name(), "test_trace");
        assert_eq!(trace.language_id(), "x86:LE:64:default");
    }

    #[test]
    fn test_close_trace() {
        let config = TraceDatabaseConfig::new("test", "x86:LE:64:default");
        let mut trace = DBTrace::new(config);
        assert!(trace.is_open());
        trace.close();
        assert!(!trace.is_open());
    }

    #[test]
    fn test_options() {
        let config = TraceDatabaseConfig::new("test", "x86:LE:64:default");
        let mut trace = DBTrace::new(config);
        trace.set_option("key1", "value1");
        assert_eq!(trace.get_option("key1"), Some(&"value1".to_string()));
        assert!(trace.get_option("missing").is_none());
    }

    #[test]
    fn test_change_set() {
        let mut cs = DBTraceChangeSet::new();
        assert!(!cs.has_changes());
        cs.mark_snapshot_changed(1);
        assert!(cs.has_changes());
        cs.mark_thread_changed(2);
        assert_eq!(cs.changed_snapshots.len(), 1);
        assert_eq!(cs.changed_threads.len(), 1);
        cs.clear();
        assert!(!cs.has_changes());
    }
}
