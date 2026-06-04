//! Editor selection model -- Rust port of the selection tracking in
//! `ghidra.app.plugin.core.compositeeditor.CompositeEditorModel`.
//!
//! Tracks which rows (component ordinals) the user has selected in the
//! structure editor table.

/// A contiguous range of selected rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelectionRange {
    /// Inclusive start index.
    pub start: usize,
    /// Exclusive end index.
    pub end: usize,
}

impl SelectionRange {
    /// Create a new selection range.
    pub fn new(start: usize, end: usize) -> Self {
        debug_assert!(start <= end);
        Self { start, end }
    }

    /// The number of rows in this range.
    pub fn len(&self) -> usize {
        self.end.saturating_sub(self.start)
    }

    /// Returns `true` if this range contains the given index.
    pub fn contains(&self, index: usize) -> bool {
        index >= self.start && index < self.end
    }

    /// Returns `true` if this range contains the entire given range.
    pub fn contains_range(&self, other: &SelectionRange) -> bool {
        self.start <= other.start && self.end >= other.end
    }
}

/// The selection state of the composite editor.
///
/// Manages a list of non-overlapping ranges (sorted by start index)
/// representing the currently selected component rows.
#[derive(Debug, Clone, Default)]
pub struct EditorSelection {
    /// Non-overlapping, sorted ranges.
    ranges: Vec<SelectionRange>,
}

impl EditorSelection {
    /// Create an empty selection.
    pub fn new() -> Self {
        Self { ranges: Vec::new() }
    }

    /// Returns `true` if the selection is empty.
    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    /// The number of contiguous ranges.
    pub fn num_ranges(&self) -> usize {
        self.ranges.len()
    }

    /// Get a range by index.
    pub fn get_range(&self, index: usize) -> Option<&SelectionRange> {
        self.ranges.get(index)
    }

    /// Add a range from `start` (inclusive) to `end` (exclusive).
    ///
    /// Adjacent and overlapping ranges are merged.
    pub fn add_range(&mut self, start: usize, end: usize) {
        if start >= end {
            return;
        }
        let new_range = SelectionRange::new(start, end);
        self.ranges.push(new_range);
        self.normalize();
    }

    /// Select a single row.
    pub fn select_single(&mut self, row: usize) {
        self.ranges.clear();
        self.ranges.push(SelectionRange::new(row, row + 1));
    }

    /// Set the selection to the given list of row indices.
    ///
    /// Consecutive indices are collapsed into ranges.
    pub fn set_rows(&mut self, rows: &[usize]) {
        self.ranges.clear();
        if rows.is_empty() {
            return;
        }
        let mut sorted = rows.to_vec();
        sorted.sort_unstable();
        sorted.dedup();

        let mut start = sorted[0];
        let mut end = sorted[0] + 1;
        for &row in &sorted[1..] {
            if row == end {
                end += 1;
            } else {
                self.ranges.push(SelectionRange::new(start, end));
                start = row;
                end = row + 1;
            }
        }
        self.ranges.push(SelectionRange::new(start, end));
    }

    /// Clear the selection.
    pub fn clear(&mut self) {
        self.ranges.clear();
    }

    /// Returns `true` if the given row is selected.
    pub fn is_selected(&self, row: usize) -> bool {
        self.ranges.iter().any(|r| r.contains(row))
    }

    /// The total number of selected rows across all ranges.
    pub fn total_selected(&self) -> usize {
        self.ranges.iter().map(|r| r.len()).sum()
    }

    /// Returns all selected row indices as a sorted Vec.
    pub fn selected_rows(&self) -> Vec<usize> {
        let mut rows: Vec<usize> = self.ranges.iter().flat_map(|r| r.start..r.end).collect();
        rows.sort_unstable();
        rows
    }

    /// Shift all ranges that start at or after `position` by `offset` rows.
    ///
    /// `offset` can be positive (insert) or negative (delete).
    pub fn shift(&mut self, position: usize, offset: isize) {
        for range in &mut self.ranges {
            if range.start >= position {
                range.start = (range.start as isize + offset).max(0) as usize;
            }
            if range.end > position {
                range.end = (range.end as isize + offset).max(0) as usize;
            }
        }
        // Remove degenerate ranges.
        self.ranges.retain(|r| r.start < r.end);
        self.normalize();
    }

    /// Merge overlapping and adjacent ranges.
    fn normalize(&mut self) {
        if self.ranges.len() <= 1 {
            return;
        }
        self.ranges.sort_by_key(|r| r.start);
        let mut merged: Vec<SelectionRange> = Vec::with_capacity(self.ranges.len());
        for range in &self.ranges {
            if let Some(last) = merged.last_mut() {
                if range.start <= last.end {
                    last.end = last.end.max(range.end);
                    continue;
                }
            }
            merged.push(*range);
        }
        self.ranges = merged;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_selection_empty() {
        let sel = EditorSelection::new();
        assert!(sel.is_empty());
        assert_eq!(sel.num_ranges(), 0);
        assert_eq!(sel.total_selected(), 0);
    }

    #[test]
    fn test_selection_single_row() {
        let mut sel = EditorSelection::new();
        sel.select_single(5);
        assert_eq!(sel.num_ranges(), 1);
        assert!(sel.is_selected(5));
        assert!(!sel.is_selected(4));
        assert!(!sel.is_selected(6));
        assert_eq!(sel.total_selected(), 1);
    }

    #[test]
    fn test_selection_add_range() {
        let mut sel = EditorSelection::new();
        sel.add_range(0, 3);
        sel.add_range(5, 8);
        assert_eq!(sel.num_ranges(), 2);
        assert_eq!(sel.total_selected(), 6);
        assert!(sel.is_selected(0));
        assert!(sel.is_selected(7));
        assert!(!sel.is_selected(3));
    }

    #[test]
    fn test_selection_merge_adjacent() {
        let mut sel = EditorSelection::new();
        sel.add_range(0, 3);
        sel.add_range(3, 6);
        assert_eq!(sel.num_ranges(), 1);
        assert_eq!(sel.total_selected(), 6);
    }

    #[test]
    fn test_selection_merge_overlapping() {
        let mut sel = EditorSelection::new();
        sel.add_range(2, 8);
        sel.add_range(5, 12);
        assert_eq!(sel.num_ranges(), 1);
        assert_eq!(sel.total_selected(), 10);
    }

    #[test]
    fn test_selection_set_rows() {
        let mut sel = EditorSelection::new();
        sel.set_rows(&[0, 1, 2, 5, 6, 10]);
        assert_eq!(sel.num_ranges(), 3);
        assert_eq!(sel.total_selected(), 6);
        assert!(sel.is_selected(2));
        assert!(!sel.is_selected(3));
    }

    #[test]
    fn test_selection_shift_insert() {
        let mut sel = EditorSelection::new();
        sel.add_range(3, 6);
        sel.shift(3, 2); // insert 2 rows at position 3
        assert_eq!(sel.get_range(0).unwrap().start, 5);
        assert_eq!(sel.get_range(0).unwrap().end, 8);
    }

    #[test]
    fn test_selection_shift_delete() {
        let mut sel = EditorSelection::new();
        sel.add_range(5, 8);
        sel.shift(3, -1); // delete 1 row at position 3
        assert_eq!(sel.get_range(0).unwrap().start, 4);
        assert_eq!(sel.get_range(0).unwrap().end, 7);
    }

    #[test]
    fn test_selection_selected_rows() {
        let mut sel = EditorSelection::new();
        sel.add_range(2, 5);
        let rows = sel.selected_rows();
        assert_eq!(rows, vec![2, 3, 4]);
    }

    #[test]
    fn test_selection_range_contains() {
        let r = SelectionRange::new(5, 10);
        assert!(!r.contains(4));
        assert!(r.contains(5));
        assert!(r.contains(9));
        assert!(!r.contains(10));
    }

    #[test]
    fn test_selection_range_contains_range() {
        let outer = SelectionRange::new(0, 10);
        let inner = SelectionRange::new(2, 5);
        assert!(outer.contains_range(&inner));
        assert!(!inner.contains_range(&outer));
    }

    #[test]
    fn test_selection_clear() {
        let mut sel = EditorSelection::new();
        sel.add_range(0, 10);
        sel.clear();
        assert!(sel.is_empty());
    }
}
