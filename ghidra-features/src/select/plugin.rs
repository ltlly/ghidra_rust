//! Selection plugins: byte selection and selection restoration.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.select` Java package:
//! `SelectBytesPlugin`, `RestoreSelectionPlugin`, `SelectBytesDialog`.


// ============================================================================
// ByteSelection -- a selection of bytes in a program
// ============================================================================

/// A byte-level selection in a program.
///
/// Ported from selection logic in `SelectBytesPlugin`.
#[derive(Debug, Clone)]
pub struct ByteSelection {
    /// The selected address ranges (start, end) inclusive.
    pub ranges: Vec<(u64, u64)>,
}

impl ByteSelection {
    /// Create a new empty selection.
    pub fn new() -> Self {
        Self { ranges: Vec::new() }
    }

    /// Add a range to the selection.
    pub fn add_range(&mut self, start: u64, end: u64) {
        if start <= end {
            self.ranges.push((start, end));
        }
    }

    /// Whether the selection is empty.
    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    /// The total number of selected bytes.
    pub fn total_bytes(&self) -> u64 {
        self.ranges.iter().map(|(s, e)| e - s + 1).sum()
    }

    /// Whether an address is in the selection.
    pub fn contains(&self, address: u64) -> bool {
        self.ranges.iter().any(|&(s, e)| address >= s && address <= e)
    }

    /// Clear the selection.
    pub fn clear(&mut self) {
        self.ranges.clear();
    }

    /// Merge overlapping ranges.
    pub fn normalize(&mut self) {
        if self.ranges.is_empty() {
            return;
        }
        self.ranges.sort_by_key(|&(s, _)| s);
        let mut merged = Vec::new();
        let (mut cur_start, mut cur_end) = self.ranges[0];
        for &(s, e) in &self.ranges[1..] {
            if s <= cur_end + 1 {
                cur_end = cur_end.max(e);
            } else {
                merged.push((cur_start, cur_end));
                cur_start = s;
                cur_end = e;
            }
        }
        merged.push((cur_start, cur_end));
        self.ranges = merged;
    }

    /// Create a selection covering the entire range.
    pub fn full(start: u64, end: u64) -> Self {
        let mut sel = Self::new();
        sel.add_range(start, end);
        sel
    }
}

impl Default for ByteSelection {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// SelectBytesPlugin -- plugin for byte selection
// ============================================================================

/// Plugin for selecting bytes in a program.
///
/// Ported from `ghidra.app.plugin.core.select.SelectBytesPlugin`.
#[derive(Debug)]
pub struct SelectBytesPlugin {
    /// The current selection.
    pub selection: ByteSelection,
    /// The previous selection (for undo).
    previous_selection: Option<ByteSelection>,
    /// Whether the plugin is disposed.
    disposed: bool,
}

impl SelectBytesPlugin {
    /// Create a new select bytes plugin.
    pub fn new() -> Self {
        Self {
            selection: ByteSelection::new(),
            previous_selection: None,
            disposed: false,
        }
    }

    /// Select a range of bytes.
    pub fn select_range(&mut self, start: u64, end: u64) {
        self.previous_selection = Some(self.selection.clone());
        self.selection.add_range(start, end);
    }

    /// Select all bytes in the range.
    pub fn select_all(&mut self, start: u64, end: u64) {
        self.previous_selection = Some(self.selection.clone());
        self.selection = ByteSelection::full(start, end);
    }

    /// Clear the selection.
    pub fn clear_selection(&mut self) {
        self.previous_selection = Some(self.selection.clone());
        self.selection.clear();
    }

    /// Invert the selection within the given range.
    pub fn invert_selection(&mut self, start: u64, end: u64) {
        self.previous_selection = Some(self.selection.clone());
        self.selection.normalize();

        let mut new_sel = ByteSelection::new();
        let mut cursor = start;
        for &(s, e) in &self.selection.ranges {
            if cursor < s {
                new_sel.add_range(cursor, s - 1);
            }
            cursor = e + 1;
        }
        if cursor <= end {
            new_sel.add_range(cursor, end);
        }
        self.selection = new_sel;
    }

    /// Undo the last selection change.
    pub fn undo(&mut self) {
        if let Some(prev) = self.previous_selection.take() {
            self.selection = prev;
        }
    }

    /// Whether the plugin is disposed.
    pub fn is_disposed(&self) -> bool {
        self.disposed
    }

    /// Dispose the plugin.
    pub fn dispose(&mut self) {
        self.disposed = true;
    }
}

impl Default for SelectBytesPlugin {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// RestoreSelectionPlugin -- restores saved selections
// ============================================================================

/// Plugin for restoring saved program selections.
///
/// Ported from `ghidra.app.plugin.core.select.RestoreSelectionPlugin`.
#[derive(Debug)]
pub struct RestoreSelectionPlugin {
    /// Saved selections by name.
    saved_selections: std::collections::HashMap<String, ByteSelection>,
    /// Whether the plugin is disposed.
    disposed: bool,
}

impl RestoreSelectionPlugin {
    /// Create a new restore selection plugin.
    pub fn new() -> Self {
        Self {
            saved_selections: std::collections::HashMap::new(),
            disposed: false,
        }
    }

    /// Save a selection with a name.
    pub fn save_selection(&mut self, name: impl Into<String>, selection: ByteSelection) {
        self.saved_selections.insert(name.into(), selection);
    }

    /// Restore a named selection.
    pub fn restore_selection(&self, name: &str) -> Option<&ByteSelection> {
        self.saved_selections.get(name)
    }

    /// Remove a saved selection.
    pub fn remove_selection(&mut self, name: &str) -> Option<ByteSelection> {
        self.saved_selections.remove(name)
    }

    /// Get all saved selection names.
    pub fn saved_names(&self) -> Vec<&str> {
        self.saved_selections.keys().map(|s| s.as_str()).collect()
    }

    /// The number of saved selections.
    pub fn saved_count(&self) -> usize {
        self.saved_selections.len()
    }

    /// Whether the plugin is disposed.
    pub fn is_disposed(&self) -> bool {
        self.disposed
    }

    /// Dispose the plugin.
    pub fn dispose(&mut self) {
        self.disposed = true;
    }
}

impl Default for RestoreSelectionPlugin {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_byte_selection_basic() {
        let mut sel = ByteSelection::new();
        assert!(sel.is_empty());

        sel.add_range(0x1000, 0x1FFF);
        assert!(!sel.is_empty());
        assert_eq!(sel.total_bytes(), 0x1000);
        assert!(sel.contains(0x1500));
        assert!(!sel.contains(0x2000));
    }

    #[test]
    fn test_byte_selection_multiple_ranges() {
        let mut sel = ByteSelection::new();
        sel.add_range(0x1000, 0x1FFF);
        sel.add_range(0x3000, 0x3FFF);
        assert_eq!(sel.total_bytes(), 0x2000);
        assert!(sel.contains(0x1000));
        assert!(sel.contains(0x3FFF));
        assert!(!sel.contains(0x2500));
    }

    #[test]
    fn test_byte_selection_normalize() {
        let mut sel = ByteSelection::new();
        sel.add_range(0x1000, 0x2000);
        sel.add_range(0x1500, 0x3000);
        sel.normalize();
        assert_eq!(sel.ranges.len(), 1);
        assert_eq!(sel.ranges[0], (0x1000, 0x3000));
    }

    #[test]
    fn test_byte_selection_normalize_adjacent() {
        let mut sel = ByteSelection::new();
        sel.add_range(0x1000, 0x1FFF);
        sel.add_range(0x2000, 0x2FFF);
        sel.normalize();
        assert_eq!(sel.ranges.len(), 1);
        assert_eq!(sel.ranges[0], (0x1000, 0x2FFF));
    }

    #[test]
    fn test_byte_selection_clear() {
        let mut sel = ByteSelection::full(0x1000, 0x1FFF);
        assert!(!sel.is_empty());
        sel.clear();
        assert!(sel.is_empty());
    }

    #[test]
    fn test_byte_selection_full() {
        let sel = ByteSelection::full(0, 0xFF);
        assert_eq!(sel.total_bytes(), 0x100);
    }

    #[test]
    fn test_select_bytes_plugin() {
        let mut plugin = SelectBytesPlugin::new();
        plugin.select_range(0x1000, 0x1FFF);
        assert_eq!(plugin.selection.total_bytes(), 0x1000);

        plugin.select_range(0x3000, 0x3FFF);
        assert_eq!(plugin.selection.total_bytes(), 0x2000);
    }

    #[test]
    fn test_select_bytes_plugin_select_all() {
        let mut plugin = SelectBytesPlugin::new();
        plugin.select_all(0, 0xFF);
        assert_eq!(plugin.selection.total_bytes(), 0x100);
    }

    #[test]
    fn test_select_bytes_plugin_clear() {
        let mut plugin = SelectBytesPlugin::new();
        plugin.select_range(0x1000, 0x1FFF);
        plugin.clear_selection();
        assert!(plugin.selection.is_empty());
    }

    #[test]
    fn test_select_bytes_plugin_undo() {
        let mut plugin = SelectBytesPlugin::new();
        plugin.select_range(0x1000, 0x1FFF);
        plugin.clear_selection();
        assert!(plugin.selection.is_empty());

        plugin.undo();
        assert_eq!(plugin.selection.total_bytes(), 0x1000);
    }

    #[test]
    fn test_select_bytes_plugin_invert() {
        let mut plugin = SelectBytesPlugin::new();
        plugin.select_range(0x10, 0x1F);
        plugin.invert_selection(0x00, 0x3F);
        // Should select 0x00-0x0F and 0x20-0x3F
        assert!(plugin.selection.contains(0x05));
        assert!(!plugin.selection.contains(0x15));
        assert!(plugin.selection.contains(0x25));
        assert_eq!(plugin.selection.total_bytes(), 0x30);
    }

    #[test]
    fn test_select_bytes_plugin_dispose() {
        let mut plugin = SelectBytesPlugin::new();
        assert!(!plugin.is_disposed());
        plugin.dispose();
        assert!(plugin.is_disposed());
    }

    #[test]
    fn test_restore_selection_plugin() {
        let mut plugin = RestoreSelectionPlugin::new();
        assert_eq!(plugin.saved_count(), 0);

        let sel = ByteSelection::full(0x1000, 0x1FFF);
        plugin.save_selection("text", sel);
        assert_eq!(plugin.saved_count(), 1);

        let restored = plugin.restore_selection("text").unwrap();
        assert_eq!(restored.total_bytes(), 0x1000);

        assert!(plugin.restore_selection("missing").is_none());
    }

    #[test]
    fn test_restore_selection_plugin_remove() {
        let mut plugin = RestoreSelectionPlugin::new();
        plugin.save_selection("test", ByteSelection::new());
        assert_eq!(plugin.saved_count(), 1);
        plugin.remove_selection("test");
        assert_eq!(plugin.saved_count(), 0);
    }

    #[test]
    fn test_restore_selection_plugin_names() {
        let mut plugin = RestoreSelectionPlugin::new();
        plugin.save_selection("a", ByteSelection::new());
        plugin.save_selection("b", ByteSelection::new());
        let mut names: Vec<&str> = plugin.saved_names();
        names.sort();
        assert_eq!(names, vec!["a", "b"]);
    }

    #[test]
    fn test_restore_selection_plugin_dispose() {
        let mut plugin = RestoreSelectionPlugin::new();
        assert!(!plugin.is_disposed());
        plugin.dispose();
        assert!(plugin.is_disposed());
    }
}
