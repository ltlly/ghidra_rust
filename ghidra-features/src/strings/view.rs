//! View Strings provider and table model.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.strings` Java package.
//!
//! Provides the "Defined Strings" view that displays all defined string
//! data items in the program, with filtering, sorting, and column
//! constraint support.
//!
//! # Key Types
//!
//! - [`ViewStringsPlugin`] -- Plugin providing the defined strings view
//! - [`ViewStringsTableModel`] -- Table model for defined strings
//! - [`ViewStringsColumnConstraint`] -- Column constraints for filtering
//! - [`FoundStringIterator`] -- Iterator over strings found in memory


use super::{DefinedStringInfo, StringConstraint};

// ---------------------------------------------------------------------------
// ViewStringsPlugin
// ---------------------------------------------------------------------------

/// Plugin providing the "Defined Strings" table view.
///
/// Ported from `ghidra.app.plugin.core.strings.ViewStringsPlugin`.
///
/// Displays all defined string data items in the program with
/// filtering, sorting, and translation support.
#[derive(Debug)]
pub struct ViewStringsPlugin {
    /// Table model for defined strings.
    model: ViewStringsTableModel,
    /// Whether the plugin is visible.
    visible: bool,
    /// Active column constraints.
    active_constraints: Vec<StringConstraint>,
    /// Search filter text.
    filter_text: String,
}

impl ViewStringsPlugin {
    /// Create a new view strings plugin.
    pub fn new() -> Self {
        Self {
            model: ViewStringsTableModel::new(),
            visible: false,
            active_constraints: Vec::new(),
            filter_text: String::new(),
        }
    }

    /// Get the table model.
    pub fn model(&self) -> &ViewStringsTableModel {
        &self.model
    }

    /// Get a mutable reference to the table model.
    pub fn model_mut(&mut self) -> &mut ViewStringsTableModel {
        &mut self.model
    }

    /// Set visibility.
    pub fn set_visible(&mut self, visible: bool) {
        self.visible = visible;
    }

    /// Whether the plugin is visible.
    pub fn is_visible(&self) -> bool {
        self.visible
    }

    /// Add a column constraint filter.
    pub fn add_constraint(&mut self, constraint: StringConstraint) {
        if !self.active_constraints.contains(&constraint) {
            self.active_constraints.push(constraint);
        }
    }

    /// Remove a column constraint filter.
    pub fn remove_constraint(&mut self, constraint: &StringConstraint) {
        self.active_constraints.retain(|c| c != constraint);
    }

    /// Get the active constraints.
    pub fn active_constraints(&self) -> &[StringConstraint] {
        &self.active_constraints
    }

    /// Set the filter text.
    pub fn set_filter_text(&mut self, text: impl Into<String>) {
        self.filter_text = text.into();
    }

    /// Get the filter text.
    pub fn filter_text(&self) -> &str {
        &self.filter_text
    }

    /// Get the filtered (visible) string count.
    pub fn filtered_count(&self) -> usize {
        self.model.filtered_strings().len()
    }

    /// Refresh the model with new data.
    pub fn refresh(&mut self, strings: Vec<DefinedStringInfo>) {
        self.model.set_strings(strings);
    }
}

impl Default for ViewStringsPlugin {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// ViewStringsTableModel
// ---------------------------------------------------------------------------

/// Table model for defined strings in the "View Strings" window.
///
/// Ported from `ghidra.app.plugin.core.strings.ViewStringsTableModel`.
#[derive(Debug)]
pub struct ViewStringsTableModel {
    /// All defined strings.
    strings: Vec<DefinedStringInfo>,
    /// Filtered strings (after applying constraints and filter text).
    filtered_indices: Vec<usize>,
    /// The selected row index.
    selected: Option<usize>,
    /// Sort column index.
    sort_column: usize,
    /// Whether sort is ascending.
    sort_ascending: bool,
}

impl ViewStringsTableModel {
    /// Column headers.
    pub const COLUMNS: &'static [&'static str] = &[
        "Address", "Value", "Encoding", "Length", "Translation",
    ];

    /// Create a new table model.
    pub fn new() -> Self {
        Self {
            strings: Vec::new(),
            filtered_indices: Vec::new(),
            selected: None,
            sort_column: 0,
            sort_ascending: true,
        }
    }

    /// Set the strings and recompute the filter.
    pub fn set_strings(&mut self, strings: Vec<DefinedStringInfo>) {
        self.strings = strings;
        self.recompute_filter();
    }

    /// Get all strings (unfiltered).
    pub fn all_strings(&self) -> &[DefinedStringInfo] {
        &self.strings
    }

    /// Get the filtered strings.
    pub fn filtered_strings(&self) -> Vec<&DefinedStringInfo> {
        self.filtered_indices
            .iter()
            .filter_map(|&i| self.strings.get(i))
            .collect()
    }

    /// Number of rows (filtered).
    pub fn row_count(&self) -> usize {
        self.filtered_indices.len()
    }

    /// Number of columns.
    pub fn column_count(&self) -> usize {
        Self::COLUMNS.len()
    }

    /// Get column name.
    pub fn column_name(&self, col: usize) -> &str {
        Self::COLUMNS.get(col).copied().unwrap_or("")
    }

    /// Get the value at a specific cell.
    pub fn get_value_at(&self, row: usize, col: usize) -> Option<String> {
        let idx = self.filtered_indices.get(row)?;
        let info = self.strings.get(*idx)?;
        match col {
            0 => Some(format!("{:#x}", info.address)),
            1 => Some(info.value.clone()),
            2 => Some(info.encoding.clone()),
            3 => Some(info.byte_length.to_string()),
            4 => info.translation.clone().or_else(|| Some(String::new())),
            _ => None,
        }
    }

    /// Get a string info by row index.
    pub fn get_row(&self, row: usize) -> Option<&DefinedStringInfo> {
        let idx = self.filtered_indices.get(row)?;
        self.strings.get(*idx)
    }

    /// Apply a filter by text (case-insensitive substring match on value).
    pub fn apply_text_filter(&mut self, text: &str) {
        let lower = text.to_lowercase();
        self.filtered_indices = self
            .strings
            .iter()
            .enumerate()
            .filter(|(_, s)| {
                lower.is_empty() || s.value.to_lowercase().contains(&lower)
            })
            .map(|(i, _)| i)
            .collect();
    }

    /// Apply constraint filters.
    pub fn apply_constraints(&mut self, constraints: &[StringConstraint]) {
        if constraints.is_empty() {
            self.recompute_filter();
            return;
        }
        self.filtered_indices = self
            .strings
            .iter()
            .enumerate()
            .filter(|(_, s)| constraints.iter().all(|c| c.matches(s)))
            .map(|(i, _)| i)
            .collect();
    }

    /// Recompute the filter with no active filters (show all).
    fn recompute_filter(&mut self) {
        self.filtered_indices = (0..self.strings.len()).collect();
    }

    /// Set the selected row.
    pub fn set_selected(&mut self, index: Option<usize>) {
        self.selected = index;
    }

    /// Get the selected row.
    pub fn selected(&self) -> Option<usize> {
        self.selected
    }

    /// Get the selected string info.
    pub fn selected_string(&self) -> Option<&DefinedStringInfo> {
        let idx = self.filtered_indices.get(self.selected?)?;
        self.strings.get(*idx)
    }

    /// Set the sort column and direction.
    pub fn sort_by(&mut self, column: usize, ascending: bool) {
        self.sort_column = column;
        self.sort_ascending = ascending;

        // Sort the strings by the given column
        match column {
            1 => self.strings.sort_by(|a, b| {
                let cmp = a.value.cmp(&b.value);
                if ascending { cmp } else { cmp.reverse() }
            }),
            2 => self.strings.sort_by(|a, b| {
                let cmp = a.encoding.cmp(&b.encoding);
                if ascending { cmp } else { cmp.reverse() }
            }),
            3 => self.strings.sort_by(|a, b| {
                let cmp = a.byte_length.cmp(&b.byte_length);
                if ascending { cmp } else { cmp.reverse() }
            }),
            _ => self.strings.sort_by(|a, b| {
                let cmp = a.address.cmp(&b.address);
                if ascending { cmp } else { cmp.reverse() }
            }),
        }
        self.recompute_filter();
    }

    /// The current sort column.
    pub fn sort_column(&self) -> usize {
        self.sort_column
    }

    /// Whether the current sort is ascending.
    pub fn is_sort_ascending(&self) -> bool {
        self.sort_ascending
    }

    /// Total number of strings (unfiltered).
    pub fn total_count(&self) -> usize {
        self.strings.len()
    }

    /// Get encoding error info if any.
    pub fn encoding_errors(&self) -> Vec<&DefinedStringInfo> {
        self.strings
            .iter()
            .filter(|s| s.has_encoding_error)
            .collect()
    }
}

impl Default for ViewStringsTableModel {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// FoundStringIterator
// ---------------------------------------------------------------------------

/// Iterator over strings found in memory, yielding DefinedStringInfo items.
///
/// Ported from `ghidra.app.plugin.core.strings.FoundStringIterator`.
#[derive(Debug)]
pub struct FoundStringIterator {
    strings: Vec<DefinedStringInfo>,
    position: usize,
}

impl FoundStringIterator {
    /// Create a new iterator over the given strings.
    pub fn new(strings: Vec<DefinedStringInfo>) -> Self {
        Self {
            strings,
            position: 0,
        }
    }

    /// Number of remaining items.
    pub fn remaining(&self) -> usize {
        self.strings.len().saturating_sub(self.position)
    }

    /// Whether the iterator has more items.
    pub fn has_next(&self) -> bool {
        self.position < self.strings.len()
    }
}

impl Iterator for FoundStringIterator {
    type Item = DefinedStringInfo;

    fn next(&mut self) -> Option<Self::Item> {
        if self.position < self.strings.len() {
            let item = self.strings[self.position].clone();
            self.position += 1;
            Some(item)
        } else {
            None
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.remaining();
        (remaining, Some(remaining))
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_string(addr: u64, value: &str, encoding: &str) -> DefinedStringInfo {
        DefinedStringInfo::new(addr, value, encoding, value.len() + 1)
    }

    #[test]
    fn test_view_strings_plugin() {
        let mut plugin = ViewStringsPlugin::new();
        assert!(!plugin.is_visible());
        assert!(plugin.active_constraints().is_empty());
        assert!(plugin.filter_text().is_empty());

        plugin.set_visible(true);
        assert!(plugin.is_visible());
    }

    #[test]
    fn test_view_strings_plugin_constraints() {
        let mut plugin = ViewStringsPlugin::new();
        plugin.add_constraint(StringConstraint::IsAscii);
        assert_eq!(plugin.active_constraints().len(), 1);

        plugin.add_constraint(StringConstraint::HasTranslation);
        assert_eq!(plugin.active_constraints().len(), 2);

        plugin.remove_constraint(&StringConstraint::IsAscii);
        assert_eq!(plugin.active_constraints().len(), 1);
    }

    #[test]
    fn test_view_strings_plugin_filter() {
        let mut plugin = ViewStringsPlugin::new();
        plugin.set_filter_text("hello");
        assert_eq!(plugin.filter_text(), "hello");
    }

    #[test]
    fn test_view_strings_plugin_refresh() {
        let mut plugin = ViewStringsPlugin::new();
        plugin.refresh(vec![
            make_string(0x1000, "Hello", "ASCII"),
            make_string(0x2000, "World", "UTF-16"),
        ]);
        assert_eq!(plugin.model().total_count(), 2);
    }

    #[test]
    fn test_table_model_creation() {
        let model = ViewStringsTableModel::new();
        assert_eq!(model.row_count(), 0);
        assert_eq!(model.column_count(), 5);
    }

    #[test]
    fn test_table_model_column_names() {
        let model = ViewStringsTableModel::new();
        assert_eq!(model.column_name(0), "Address");
        assert_eq!(model.column_name(1), "Value");
        assert_eq!(model.column_name(2), "Encoding");
        assert_eq!(model.column_name(3), "Length");
        assert_eq!(model.column_name(4), "Translation");
    }

    #[test]
    fn test_table_model_set_strings() {
        let mut model = ViewStringsTableModel::new();
        model.set_strings(vec![
            make_string(0x1000, "Hello", "ASCII"),
            make_string(0x2000, "World", "ASCII"),
        ]);
        assert_eq!(model.row_count(), 2);
        assert_eq!(model.total_count(), 2);
    }

    #[test]
    fn test_table_model_get_value_at() {
        let mut model = ViewStringsTableModel::new();
        model.set_strings(vec![make_string(0x1000, "Hello", "ASCII")]);

        let addr = model.get_value_at(0, 0);
        assert!(addr.unwrap().contains("1000"));

        let val = model.get_value_at(0, 1);
        assert_eq!(val.as_deref(), Some("Hello"));

        let enc = model.get_value_at(0, 2);
        assert_eq!(enc.as_deref(), Some("ASCII"));

        assert!(model.get_value_at(0, 99).is_none()); // invalid column
    }

    #[test]
    fn test_table_model_text_filter() {
        let mut model = ViewStringsTableModel::new();
        model.set_strings(vec![
            make_string(0x1000, "Hello World", "ASCII"),
            make_string(0x2000, "Goodbye", "ASCII"),
            make_string(0x3000, "Hello Again", "ASCII"),
        ]);

        model.apply_text_filter("hello");
        assert_eq!(model.row_count(), 2);

        model.apply_text_filter("goodbye");
        assert_eq!(model.row_count(), 1);

        model.apply_text_filter("");
        assert_eq!(model.row_count(), 3);
    }

    #[test]
    fn test_table_model_constraints() {
        let mut model = ViewStringsTableModel::new();
        let mut s1 = make_string(0x1000, "Hello", "ASCII");
        s1.is_ascii = true;
        let mut s2 = make_string(0x2000, "Unicode", "UTF-16");
        s2.is_ascii = false;
        model.set_strings(vec![s1, s2]);

        model.apply_constraints(&[StringConstraint::IsAscii]);
        assert_eq!(model.row_count(), 1);

        model.apply_constraints(&[StringConstraint::IsNotAscii]);
        assert_eq!(model.row_count(), 1);

        model.apply_constraints(&[]);
        assert_eq!(model.row_count(), 2);
    }

    #[test]
    fn test_table_model_selection() {
        let mut model = ViewStringsTableModel::new();
        model.set_strings(vec![make_string(0x1000, "Hello", "ASCII")]);

        assert!(model.selected().is_none());
        assert!(model.selected_string().is_none());

        model.set_selected(Some(0));
        assert_eq!(model.selected(), Some(0));
        assert!(model.selected_string().is_some());
    }

    #[test]
    fn test_table_model_sort() {
        let mut model = ViewStringsTableModel::new();
        model.set_strings(vec![
            make_string(0x3000, "Charlie", "ASCII"),
            make_string(0x1000, "Alpha", "ASCII"),
            make_string(0x2000, "Bravo", "ASCII"),
        ]);

        // Sort by address (default column 0)
        model.sort_by(0, true);
        let sorted = model.filtered_strings();
        assert_eq!(sorted[0].address, 0x1000);
        assert_eq!(sorted[1].address, 0x2000);
        assert_eq!(sorted[2].address, 0x3000);

        // Sort descending
        model.sort_by(0, false);
        let sorted = model.filtered_strings();
        assert_eq!(sorted[0].address, 0x3000);
    }

    #[test]
    fn test_table_model_sort_by_value() {
        let mut model = ViewStringsTableModel::new();
        model.set_strings(vec![
            make_string(0x3000, "Charlie", "ASCII"),
            make_string(0x1000, "Alpha", "ASCII"),
            make_string(0x2000, "Bravo", "ASCII"),
        ]);

        model.sort_by(1, true);
        let sorted = model.filtered_strings();
        assert_eq!(sorted[0].value, "Alpha");
        assert_eq!(sorted[1].value, "Bravo");
        assert_eq!(sorted[2].value, "Charlie");
    }

    #[test]
    fn test_table_model_encoding_errors() {
        let mut model = ViewStringsTableModel::new();
        let mut s1 = make_string(0x1000, "Hello", "ASCII");
        s1.has_encoding_error = false;
        let mut s2 = make_string(0x2000, "Bad", "UTF-8");
        s2.has_encoding_error = true;
        model.set_strings(vec![s1, s2]);

        assert_eq!(model.encoding_errors().len(), 1);
    }

    #[test]
    fn test_found_string_iterator() {
        let strings = vec![
            make_string(0x1000, "Hello", "ASCII"),
            make_string(0x2000, "World", "ASCII"),
        ];
        let mut iter = FoundStringIterator::new(strings);
        assert!(iter.has_next());
        assert_eq!(iter.remaining(), 2);

        let first = iter.next().unwrap();
        assert_eq!(first.value, "Hello");

        let second = iter.next().unwrap();
        assert_eq!(second.value, "World");

        assert!(!iter.has_next());
        assert!(iter.next().is_none());
    }

    #[test]
    fn test_found_string_iterator_size_hint() {
        let strings = vec![
            make_string(0x1000, "A", "ASCII"),
            make_string(0x2000, "B", "ASCII"),
            make_string(0x3000, "C", "ASCII"),
        ];
        let mut iter = FoundStringIterator::new(strings);
        assert_eq!(iter.size_hint(), (3, Some(3)));
        iter.next();
        assert_eq!(iter.size_hint(), (2, Some(2)));
    }

    #[test]
    fn test_found_string_iterator_empty() {
        let mut iter = FoundStringIterator::new(vec![]);
        assert!(!iter.has_next());
        assert_eq!(iter.remaining(), 0);
        assert!(iter.next().is_none());
    }
}
