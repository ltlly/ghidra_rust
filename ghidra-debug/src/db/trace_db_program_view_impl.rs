//! Full program view implementation for the trace database.
//!
//! Ported from Ghidra's `DBTraceProgramView` in
//! `ghidra.trace.database.program`. Wraps a trace at a specific snap
//! to provide the Ghidra Program API interface.

use serde::{Deserialize, Serialize};

use crate::model::Lifespan;

/// A program view over a trace at a specific snapshot.
///
/// Ported from Ghidra's `DBTraceProgramView`. This is the primary
/// bridge between the trace database and Ghidra's Program interface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbTraceProgramViewImpl {
    /// The trace database ID this view is over.
    pub trace_id: i64,
    /// The snap (snapshot time) this view is pinned to.
    pub snap: i64,
    /// The language ID.
    pub language_id: String,
    /// The compiler spec ID.
    pub compiler_spec_id: String,
    /// The time viewport for range queries.
    pub viewport_snap: i64,
    /// Whether this view has unsaved changes.
    pub has_changes: bool,
    /// A version tag for change detection.
    pub version_tag: u64,
    /// Associated sub-managers.
    pub bookmark_manager_id: Option<i64>,
    pub equate_table_id: Option<i64>,
    pub function_manager_id: Option<i64>,
    pub listing_id: Option<i64>,
    pub memory_id: Option<i64>,
    pub program_context_id: Option<i64>,
    pub property_map_manager_id: Option<i64>,
    pub reference_manager_id: Option<i64>,
    pub symbol_table_id: Option<i64>,
}

impl DbTraceProgramViewImpl {
    /// Create a new program view.
    pub fn new(
        trace_id: i64,
        snap: i64,
        language_id: impl Into<String>,
        compiler_spec_id: impl Into<String>,
    ) -> Self {
        Self {
            trace_id,
            snap,
            language_id: language_id.into(),
            compiler_spec_id: compiler_spec_id.into(),
            viewport_snap: snap,
            has_changes: false,
            version_tag: 0,
            bookmark_manager_id: None,
            equate_table_id: None,
            function_manager_id: None,
            listing_id: None,
            memory_id: None,
            program_context_id: None,
            property_map_manager_id: None,
            reference_manager_id: None,
            symbol_table_id: None,
        }
    }

    /// Get the snap this view is pinned to.
    pub fn get_snap(&self) -> i64 {
        self.snap
    }

    /// Set the snap this view is pinned to.
    pub fn set_snap(&mut self, snap: i64) {
        self.snap = snap;
        self.viewport_snap = snap;
    }

    /// Get the language ID.
    pub fn get_language_id(&self) -> &str {
        &self.language_id
    }

    /// Get the compiler spec ID.
    pub fn get_compiler_spec_id(&self) -> &str {
        &self.compiler_spec_id
    }

    /// Whether this view has unsaved changes.
    pub fn has_changes(&self) -> bool {
        self.has_changes
    }

    /// Increment the version tag (for change tracking).
    pub fn increment_version(&mut self) {
        self.version_tag += 1;
    }
}

/// A variable-snap program view that can change its snap.
///
/// Ported from Ghidra's `DBTraceVariableSnapProgramView`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbTraceVariableSnapProgramView {
    /// The underlying view.
    pub view: DbTraceProgramViewImpl,
    /// Whether auto-scroll to the current snap is enabled.
    pub auto_scroll: bool,
}

impl DbTraceVariableSnapProgramView {
    /// Create a new variable-snap view.
    pub fn new(view: DbTraceProgramViewImpl) -> Self {
        Self {
            view,
            auto_scroll: true,
        }
    }

    /// Set the snap and return the previous value.
    pub fn set_snap(&mut self, snap: i64) -> i64 {
        let old = self.view.snap;
        self.view.set_snap(snap);
        old
    }

    /// Get the current snap.
    pub fn snap(&self) -> i64 {
        self.view.snap
    }
}

/// A program view snapshot entry for database persistence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramViewSnapshot {
    /// The view ID.
    pub view_id: i64,
    /// The snapshot (snap) value.
    pub snap: i64,
    /// A display label for this snapshot.
    pub label: String,
    /// Creation timestamp.
    pub timestamp: i64,
}

/// A program view bookmark entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramViewBookmark {
    /// Bookmark type (e.g., "Info", "Warning", "Error").
    pub category: String,
    /// The address offset.
    pub address_offset: u64,
    /// The address space.
    pub address_space: String,
    /// Bookmark comment text.
    pub comment: String,
    /// The snap range.
    pub min_snap: i64,
    pub max_snap: i64,
}

impl ProgramViewBookmark {
    /// Create a new bookmark.
    pub fn new(
        category: impl Into<String>,
        address_space: impl Into<String>,
        address_offset: u64,
        comment: impl Into<String>,
        min_snap: i64,
        max_snap: i64,
    ) -> Self {
        Self {
            category: category.into(),
            address_offset,
            address_space: address_space.into(),
            comment: comment.into(),
            min_snap,
            max_snap,
        }
    }

    /// Get the lifespan.
    pub fn lifespan(&self) -> Lifespan {
        Lifespan::span(self.min_snap, self.max_snap)
    }
}

/// A program view change set entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramViewChangeSet {
    /// Changed address ranges (as offset pairs).
    pub address_changes: Vec<(u64, u64)>,
    /// Changed snap ranges.
    pub snap_changes: Vec<(i64, i64)>,
    /// Whether the entire program is marked as changed.
    pub all_changed: bool,
}

impl ProgramViewChangeSet {
    /// Create a new empty change set.
    pub fn new() -> Self {
        Self {
            address_changes: Vec::new(),
            snap_changes: Vec::new(),
            all_changed: false,
        }
    }

    /// Mark an address range as changed.
    pub fn add_address_range(&mut self, min: u64, max: u64) {
        self.address_changes.push((min, max));
    }

    /// Mark a snap range as changed.
    pub fn add_snap_range(&mut self, min: i64, max: i64) {
        self.snap_changes.push((min, max));
    }

    /// Whether there are any changes.
    pub fn has_changes(&self) -> bool {
        self.all_changed || !self.address_changes.is_empty() || !self.snap_changes.is_empty()
    }
}

impl Default for ProgramViewChangeSet {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_program_view_creation() {
        let view = DbTraceProgramViewImpl::new(1, 0, "x86:LE:64:default", "default");
        assert_eq!(view.trace_id, 1);
        assert_eq!(view.snap, 0);
        assert_eq!(view.language_id, "x86:LE:64:default");
    }

    #[test]
    fn test_program_view_set_snap() {
        let mut view = DbTraceProgramViewImpl::new(1, 0, "x86:LE:64:default", "default");
        view.set_snap(42);
        assert_eq!(view.get_snap(), 42);
        assert_eq!(view.viewport_snap, 42);
    }

    #[test]
    fn test_program_view_version() {
        let mut view = DbTraceProgramViewImpl::new(1, 0, "x86:LE:64:default", "default");
        assert_eq!(view.version_tag, 0);
        view.increment_version();
        assert_eq!(view.version_tag, 1);
    }

    #[test]
    fn test_variable_snap_view() {
        let view = DbTraceProgramViewImpl::new(1, 0, "x86:LE:64:default", "default");
        let mut var_view = DbTraceVariableSnapProgramView::new(view);
        assert_eq!(var_view.snap(), 0);
        let old = var_view.set_snap(10);
        assert_eq!(old, 0);
        assert_eq!(var_view.snap(), 10);
    }

    #[test]
    fn test_bookmark() {
        let bm = ProgramViewBookmark::new(
            "Info", "ram", 0x1000, "important location", 0, 100,
        );
        assert_eq!(bm.category, "Info");
        assert_eq!(bm.comment, "important location");
        assert_eq!(bm.lifespan(), Lifespan::span(0, 100));
    }

    #[test]
    fn test_change_set() {
        let mut cs = ProgramViewChangeSet::new();
        assert!(!cs.has_changes());
        cs.add_address_range(0x1000, 0x2000);
        assert!(cs.has_changes());
        assert_eq!(cs.address_changes.len(), 1);
    }
}
