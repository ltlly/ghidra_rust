//! Trace diff GUI data model types.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.gui.diff`
//! package in the Debugger module. Provides types for comparing
//! two trace snapshots.

use serde::{Deserialize, Serialize};

/// The kind of difference between two trace elements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DiffKind {
    /// The element is the same in both traces.
    Same,
    /// The element exists only in the left trace.
    OnlyLeft,
    /// The element exists only in the right trace.
    OnlyRight,
    /// The element exists in both but has different values.
    Modified,
}

impl DiffKind {
    /// Whether this represents a difference.
    pub fn is_different(&self) -> bool {
        *self != Self::Same
    }

    /// Get a display symbol for this kind.
    pub fn symbol(&self) -> char {
        match self {
            Self::Same => ' ',
            Self::OnlyLeft => '<',
            Self::OnlyRight => '>',
            Self::Modified => '~',
        }
    }
}

/// A single memory diff entry.
///
/// Represents a difference at a specific memory address between
/// two trace snapshots.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryDiffEntry {
    /// The address of the difference.
    pub address: u64,
    /// The address space name.
    pub space_name: String,
    /// The kind of difference.
    pub kind: DiffKind,
    /// Left value (if present).
    pub left_value: Option<Vec<u8>>,
    /// Right value (if present).
    pub right_value: Option<Vec<u8>>,
    /// Size of the difference in bytes.
    pub size: usize,
}

impl MemoryDiffEntry {
    /// Create a new diff entry.
    pub fn new(address: u64, kind: DiffKind, size: usize) -> Self {
        Self {
            address,
            space_name: String::from("ram"),
            kind,
            left_value: None,
            right_value: None,
            size,
        }
    }

    /// Create a modified diff entry.
    pub fn modified(
        address: u64,
        left: Vec<u8>,
        right: Vec<u8>,
    ) -> Self {
        let size = left.len().max(right.len());
        Self {
            address,
            space_name: String::from("ram"),
            kind: DiffKind::Modified,
            left_value: Some(left),
            right_value: Some(right),
            size,
        }
    }

    /// Whether this entry represents a difference.
    pub fn is_different(&self) -> bool {
        self.kind.is_different()
    }
}

/// A register diff entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterDiffEntry {
    /// Register name.
    pub name: String,
    /// The kind of difference.
    pub kind: DiffKind,
    /// Left value (if present).
    pub left_value: Option<Vec<u8>>,
    /// Right value (if present).
    pub right_value: Option<Vec<u8>>,
}

impl RegisterDiffEntry {
    /// Create a new register diff entry.
    pub fn new(name: impl Into<String>, kind: DiffKind) -> Self {
        Self {
            name: name.into(),
            kind,
            left_value: None,
            right_value: None,
        }
    }

    /// Create a modified register diff entry.
    pub fn modified(name: impl Into<String>, left: Vec<u8>, right: Vec<u8>) -> Self {
        Self {
            name: name.into(),
            kind: DiffKind::Modified,
            left_value: Some(left),
            right_value: Some(right),
        }
    }
}

/// The result of comparing two trace snapshots.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TraceDiffResult {
    /// Memory differences.
    pub memory_diffs: Vec<MemoryDiffEntry>,
    /// Register differences.
    pub register_diffs: Vec<RegisterDiffEntry>,
    /// The left snap key.
    pub left_snap: i64,
    /// The right snap key.
    pub right_snap: i64,
}

impl TraceDiffResult {
    /// Create a new empty diff result.
    pub fn new(left_snap: i64, right_snap: i64) -> Self {
        Self {
            memory_diffs: Vec::new(),
            register_diffs: Vec::new(),
            left_snap,
            right_snap,
        }
    }

    /// Whether there are any differences.
    pub fn has_differences(&self) -> bool {
        self.memory_diffs.iter().any(|d| d.is_different())
            || !self.register_diffs.is_empty()
    }

    /// The total number of differences.
    pub fn diff_count(&self) -> usize {
        self.memory_diffs.iter().filter(|d| d.is_different()).count()
            + self.register_diffs.len()
    }

    /// Add a memory diff entry.
    pub fn add_memory_diff(&mut self, entry: MemoryDiffEntry) {
        self.memory_diffs.push(entry);
        self.memory_diffs.sort_by_key(|e| e.address);
    }

    /// Add a register diff entry.
    pub fn add_register_diff(&mut self, entry: RegisterDiffEntry) {
        self.register_diffs.push(entry);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_diff_kind() {
        assert!(!DiffKind::Same.is_different());
        assert!(DiffKind::Modified.is_different());
        assert!(DiffKind::OnlyLeft.is_different());
        assert!(DiffKind::OnlyRight.is_different());

        assert_eq!(DiffKind::Same.symbol(), ' ');
        assert_eq!(DiffKind::Modified.symbol(), '~');
        assert_eq!(DiffKind::OnlyLeft.symbol(), '<');
        assert_eq!(DiffKind::OnlyRight.symbol(), '>');
    }

    #[test]
    fn test_memory_diff_entry() {
        let entry = MemoryDiffEntry::modified(
            0x400000,
            vec![0x90, 0x90],
            vec![0xcc, 0xcc],
        );
        assert!(entry.is_different());
        assert_eq!(entry.kind, DiffKind::Modified);
        assert_eq!(entry.size, 2);
    }

    #[test]
    fn test_register_diff_entry() {
        let entry = RegisterDiffEntry::modified("RAX", vec![0x42; 8], vec![0x00; 8]);
        assert_eq!(entry.name, "RAX");
        assert_eq!(entry.kind, DiffKind::Modified);
    }

    #[test]
    fn test_trace_diff_result() {
        let mut diff = TraceDiffResult::new(0, 1);
        assert!(!diff.has_differences());
        assert_eq!(diff.diff_count(), 0);

        diff.add_memory_diff(MemoryDiffEntry::modified(0x400000, vec![0x90], vec![0xcc]));
        diff.add_register_diff(RegisterDiffEntry::modified("RAX", vec![1; 8], vec![2; 8]));

        assert!(diff.has_differences());
        assert_eq!(diff.diff_count(), 2);
    }

    #[test]
    fn test_trace_diff_result_sorted() {
        let mut diff = TraceDiffResult::new(0, 1);
        diff.add_memory_diff(MemoryDiffEntry::new(0x500000, DiffKind::Modified, 1));
        diff.add_memory_diff(MemoryDiffEntry::new(0x400000, DiffKind::OnlyLeft, 1));
        assert_eq!(diff.memory_diffs[0].address, 0x400000);
        assert_eq!(diff.memory_diffs[1].address, 0x500000);
    }
}
