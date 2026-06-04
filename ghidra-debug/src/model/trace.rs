//! Trace - the top-level trace domain object.
//!
//! Ported from Ghidra's `ghidra.trace.model.Trace` interface.
//! A Trace is the root container for all debug observation data: memory,
//! registers, threads, modules, symbols, bookmarks, and code listings.

use serde::{Deserialize, Serialize};

use super::{
    bookmark::TraceBookmarkManager,
    guest::TracePlatformManager,
    listing::TraceCodeManager,
    register_context::TraceRegisterContextManager,
    stack::TraceStackManager,
    symbol::TraceSymbolManager,
    time::TraceTimeManager,
};

/// The user data associated with a trace.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TraceUserData {
    /// User-visible name for the trace.
    pub name: String,
    /// User comment.
    pub comment: String,
    /// Custom properties.
    pub properties: std::collections::BTreeMap<String, String>,
}

impl TraceUserData {
    /// Create new user data.
    pub fn new() -> Self {
        Self::default()
    }
}

/// The top-level trace object.
///
/// A Trace is the equivalent of Ghidra's `Trace` interface. It aggregates
/// all the managers that handle different aspects of a debug session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Trace {
    /// A unique identifier for this trace.
    pub id: String,
    /// Whether the trace has been closed.
    pub closed: bool,
    /// The time manager (snapshots).
    pub time: TraceTimeManager,
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
    /// Whether the trace supports write operations.
    writable: bool,
}

impl Trace {
    /// Create a new trace with the given ID.
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            closed: false,
            time: TraceTimeManager::new(),
            listing: TraceCodeManager::new(),
            register_context: TraceRegisterContextManager::new(),
            stacks: TraceStackManager::new(),
            symbols: TraceSymbolManager::new(),
            bookmarks: TraceBookmarkManager::new(),
            platforms: TracePlatformManager::new(),
            user_data: TraceUserData::new(),
            writable: true,
        }
    }

    /// Whether this trace has been closed.
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// Close this trace.
    pub fn close(&mut self) {
        self.closed = true;
    }

    /// Whether this trace is writable.
    pub fn is_writable(&self) -> bool {
        self.writable && !self.closed
    }

    /// Set whether this trace is writable.
    pub fn set_writable(&mut self, writable: bool) {
        self.writable = writable;
    }

    /// Create a new snapshot.
    pub fn create_snapshot(&mut self) -> i64 {
        let snap = self.time.create_snapshot();
        snap.key
    }

    /// Create a snapshot with a description.
    pub fn create_snapshot_with_desc(&mut self, desc: &str) -> i64 {
        let snap = self.time.create_snapshot();
        let key = snap.key;
        snap.description = desc.to_string();
        key
    }

    /// Get the number of snapshots.
    pub fn snap_count(&self) -> usize {
        self.time.len()
    }
}

/// A time viewport restricting which snaps are visible.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceTimeViewport {
    /// The minimum visible snap.
    pub min_snap: i64,
    /// The maximum visible snap.
    pub max_snap: i64,
    /// Whether to follow the "live" snap.
    pub live: bool,
}

impl TraceTimeViewport {
    /// Create a new viewport showing all time.
    pub fn all() -> Self {
        Self {
            min_snap: i64::MIN,
            max_snap: i64::MAX,
            live: true,
        }
    }

    /// Create a viewport for a specific range.
    pub fn range(min_snap: i64, max_snap: i64) -> Self {
        Self {
            min_snap,
            max_snap,
            live: false,
        }
    }

    /// Create a viewport for a single snap.
    pub fn at(snap: i64) -> Self {
        Self {
            min_snap: snap,
            max_snap: snap,
            live: false,
        }
    }

    /// Whether the viewport contains the given snap.
    pub fn contains(&self, snap: i64) -> bool {
        snap >= self.min_snap && snap <= self.max_snap
    }

    /// Update the viewport to follow a new snap.
    pub fn set_snap(&mut self, snap: i64) {
        if self.live {
            self.min_snap = snap;
            self.max_snap = snap;
        }
    }
}

/// Options for a trace.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TraceOptionsManager {
    options: std::collections::BTreeMap<String, String>,
}

impl TraceOptionsManager {
    /// Create a new options manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set an option.
    pub fn set_option(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.options.insert(key.into(), value.into());
    }

    /// Get an option.
    pub fn get_option(&self, key: &str) -> Option<&str> {
        self.options.get(key).map(|s| s.as_str())
    }

    /// Get an option with a default value.
    pub fn get_option_or<'a>(&'a self, key: &str, default: &'a str) -> &'a str {
        self.get_option(key).unwrap_or(default)
    }

    /// Remove an option.
    pub fn remove_option(&mut self, key: &str) -> Option<String> {
        self.options.remove(key)
    }

    /// All options.
    pub fn options(&self) -> &std::collections::BTreeMap<String, String> {
        &self.options
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::Lifespan;

    #[test]
    fn test_trace_create() {
        let trace = Trace::new("test-trace");
        assert_eq!(trace.id, "test-trace");
        assert!(!trace.is_closed());
        assert!(trace.is_writable());
        assert_eq!(trace.snap_count(), 0);
    }

    #[test]
    fn test_trace_close() {
        let mut trace = Trace::new("test");
        trace.close();
        assert!(trace.is_closed());
        assert!(!trace.is_writable());
    }

    #[test]
    fn test_trace_snapshot() {
        let mut trace = Trace::new("test");
        let snap = trace.create_snapshot_with_desc("initial state");
        assert_eq!(snap, 0);
        assert_eq!(trace.snap_count(), 1);
    }

    #[test]
    fn test_trace_managers() {
        let mut trace = Trace::new("test");
        // Bookmark
        trace.bookmarks.add_bookmark(
            0x400000,
            Lifespan::at(0),
            super::super::bookmark::TraceBookmarkType::Note,
            "test",
            "hello",
        );
        assert_eq!(trace.bookmarks.len(), 1);

        // Symbol
        trace.symbols.create_label("main", 0x400000, "ram", Lifespan::now_on(0));
        assert_eq!(trace.symbols.symbol_count(), 1);

        // Platform
        let _ = trace.platforms.add_platform("x86:LE:64:default", "default");
        assert_eq!(trace.platforms.platforms().len(), 1);
    }

    #[test]
    fn test_time_viewport() {
        let vp = TraceTimeViewport::all();
        assert!(vp.contains(0));
        assert!(vp.contains(i64::MIN));

        let vp = TraceTimeViewport::range(0, 10);
        assert!(vp.contains(5));
        assert!(!vp.contains(11));

        let vp = TraceTimeViewport::at(5);
        assert!(vp.contains(5));
        assert!(!vp.contains(6));
    }

    #[test]
    fn test_time_viewport_live() {
        let mut vp = TraceTimeViewport::all();
        vp.live = true;
        vp.set_snap(42);
        assert_eq!(vp.min_snap, 42);
        assert_eq!(vp.max_snap, 42);
    }

    #[test]
    fn test_options_manager() {
        let mut opts = TraceOptionsManager::new();
        opts.set_option("max-snaps", "1000");
        assert_eq!(opts.get_option("max-snaps"), Some("1000"));
        assert_eq!(opts.get_option_or("missing", "default"), "default");

        opts.remove_option("max-snaps");
        assert!(opts.get_option("max-snaps").is_none());
    }

    #[test]
    fn test_user_data() {
        let mut ud = TraceUserData::new();
        ud.name = "My Trace".into();
        ud.properties.insert("key".into(), "value".into());
        assert_eq!(ud.properties.get("key").map(|s| s.as_str()), Some("value"));
    }

    #[test]
    fn test_trace_serde() {
        let trace = Trace::new("test");
        let json = serde_json::to_string(&trace).unwrap();
        let back: Trace = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, "test");
    }
}
