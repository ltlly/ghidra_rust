//! Data type manager utilities -- ported from
//! `ghidra.app.plugin.core.datamgr.util`.
//!
//! Provides helper types for data type management: clipboard handlers,
//! data type chooser dialogs, and recently-opened archive tracking.

use std::collections::VecDeque;
use std::fmt;

use ghidra_core::data::DataTypePath;

/// The maximum number of recently opened archives to track.
const MAX_RECENT_ARCHIVES: usize = 10;

/// Tracks recently opened data type archive files.
///
/// Ported from Ghidra's recently-opened archive tracking.
///
/// # Example
///
/// ```
/// use ghidra_features::datamgr::util::*;
///
/// let mut recent = RecentArchiveTracker::new();
/// recent.add("/path/to/types.gdt");
/// assert_eq!(recent.count(), 1);
/// assert_eq!(recent.most_recent(), Some("/path/to/types.gdt"));
/// ```
#[derive(Debug, Clone)]
pub struct RecentArchiveTracker {
    /// The paths of recently opened archives (most recent first).
    paths: VecDeque<String>,
    /// The maximum number of entries.
    max_entries: usize,
}

impl RecentArchiveTracker {
    /// Creates a new tracker.
    pub fn new() -> Self {
        Self {
            paths: VecDeque::new(),
            max_entries: MAX_RECENT_ARCHIVES,
        }
    }

    /// Creates a new tracker with a custom maximum.
    pub fn with_max(max: usize) -> Self {
        Self {
            paths: VecDeque::new(),
            max_entries: max,
        }
    }

    /// Adds a path to the recent list.
    ///
    /// If the path already exists, it is moved to the front.
    pub fn add(&mut self, path: impl Into<String>) {
        let p = path.into();
        self.paths.retain(|x| x != &p);
        self.paths.push_front(p);
        while self.paths.len() > self.max_entries {
            self.paths.pop_back();
        }
    }

    /// Returns the most recently opened path.
    pub fn most_recent(&self) -> Option<&str> {
        self.paths.front().map(|s| s.as_str())
    }

    /// Returns all recent paths.
    pub fn all(&self) -> Vec<&str> {
        self.paths.iter().map(|s| s.as_str()).collect()
    }

    /// Returns the number of tracked paths.
    pub fn count(&self) -> usize {
        self.paths.len()
    }

    /// Clears all recent entries.
    pub fn clear(&mut self) {
        self.paths.clear();
    }
}

impl Default for RecentArchiveTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// A data type selection result.
///
/// Ported from the result of Ghidra's `DataTypeChooserDialog`.
#[derive(Debug, Clone)]
pub struct DataTypeSelection {
    /// The selected data type path.
    pub path: DataTypePath,
    /// Whether the selection was confirmed (vs cancelled).
    pub confirmed: bool,
}

impl DataTypeSelection {
    /// Creates a confirmed selection.
    pub fn confirmed(path: DataTypePath) -> Self {
        Self {
            path,
            confirmed: true,
        }
    }

    /// Creates a cancelled selection.
    pub fn cancelled() -> Self {
        Self {
            path: DataTypePath::new(ghidra_core::data::CategoryPath::ROOT, ""),
            confirmed: false,
        }
    }
}

/// The allowed data types for selection.
///
/// Ported from `AllowedDataTypes`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllowedDataTypes {
    /// All data types.
    ALL,
    /// Only pointers.
    POINTERS,
    /// Only arrays.
    ARRAYS,
    /// Only scalars (int, float, etc.).
    SCALARS,
    /// Only composites (structs, unions).
    COMPOSITES,
    /// Only enums.
    ENUMS,
    /// Only function definitions.
    FUNCTION_DEFS,
    /// Only typedefs.
    TYPEDEFS,
    /// Only composite and pointer types.
    COMPOSITE_AND_POINTER,
}

impl fmt::Display for AllowedDataTypes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ALL => write!(f, "All"),
            Self::POINTERS => write!(f, "Pointers"),
            Self::ARRAYS => write!(f, "Arrays"),
            Self::SCALARS => write!(f, "Scalars"),
            Self::COMPOSITES => write!(f, "Composites"),
            Self::ENUMS => write!(f, "Enums"),
            Self::FUNCTION_DEFS => write!(f, "Function Definitions"),
            Self::TYPEDEFS => write!(f, "Typedefs"),
            Self::COMPOSITE_AND_POINTER => write!(f, "Composite and Pointer"),
        }
    }
}

impl Default for AllowedDataTypes {
    fn default() -> Self {
        Self::ALL
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ghidra_core::data::CategoryPath;

    #[test]
    fn test_recent_archive_tracker() {
        let mut tracker = RecentArchiveTracker::new();
        tracker.add("/a.gdt");
        tracker.add("/b.gdt");
        tracker.add("/c.gdt");
        assert_eq!(tracker.count(), 3);
        assert_eq!(tracker.most_recent(), Some("/c.gdt"));
    }

    #[test]
    fn test_recent_archive_tracker_dedup() {
        let mut tracker = RecentArchiveTracker::new();
        tracker.add("/a.gdt");
        tracker.add("/b.gdt");
        tracker.add("/a.gdt"); // move to front
        assert_eq!(tracker.count(), 2);
        assert_eq!(tracker.most_recent(), Some("/a.gdt"));
    }

    #[test]
    fn test_recent_archive_tracker_max() {
        let mut tracker = RecentArchiveTracker::with_max(3);
        tracker.add("a");
        tracker.add("b");
        tracker.add("c");
        tracker.add("d");
        assert_eq!(tracker.count(), 3);
        assert_eq!(tracker.most_recent(), Some("d"));
    }

    #[test]
    fn test_recent_archive_tracker_clear() {
        let mut tracker = RecentArchiveTracker::new();
        tracker.add("a");
        tracker.clear();
        assert_eq!(tracker.count(), 0);
    }

    #[test]
    fn test_data_type_selection() {
        let path = DataTypePath::new(CategoryPath::ROOT, "int");
        let sel = DataTypeSelection::confirmed(path.clone());
        assert!(sel.confirmed);
        assert_eq!(sel.path.data_type_name, "int");

        let cancelled = DataTypeSelection::cancelled();
        assert!(!cancelled.confirmed);
    }

    #[test]
    fn test_allowed_data_types_display() {
        assert_eq!(AllowedDataTypes::ALL.to_string(), "All");
        assert_eq!(AllowedDataTypes::SCALARS.to_string(), "Scalars");
    }

    #[test]
    fn test_allowed_data_types_default() {
        assert_eq!(AllowedDataTypes::default(), AllowedDataTypes::ALL);
    }
}
