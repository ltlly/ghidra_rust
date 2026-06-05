//! String table viewer.
//!
//! Ported from `ghidra.app.plugin.core.string` viewer-related classes.
//!
//! Provides the viewer model for displaying found strings with
//! sorting, filtering, and selection capabilities.

use super::{FoundString, StringEncoding};

/// Column indices for the string table viewer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StringColumn {
    /// The address column.
    Address,
    /// The string value column.
    Value,
    /// The encoding column.
    Encoding,
    /// The byte length column.
    Length,
    /// Whether the string is defined.
    Defined,
}

impl StringColumn {
    /// Get the column header text.
    pub fn header(&self) -> &'static str {
        match self {
            Self::Address => "Address",
            Self::Value => "String",
            Self::Encoding => "Encoding",
            Self::Length => "Length",
            Self::Defined => "Defined",
        }
    }

    /// Get all columns in display order.
    pub fn all() -> &'static [StringColumn] {
        &[
            Self::Address,
            Self::Value,
            Self::Encoding,
            Self::Length,
            Self::Defined,
        ]
    }
}

/// Sort direction for the string table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortDirection {
    Ascending,
    Descending,
}

/// Sort configuration for the string table.
#[derive(Debug, Clone)]
pub struct StringSortConfig {
    /// The column to sort by.
    pub column: StringColumn,
    /// The sort direction.
    pub direction: SortDirection,
}

impl Default for StringSortConfig {
    fn default() -> Self {
        Self {
            column: StringColumn::Address,
            direction: SortDirection::Ascending,
        }
    }
}

/// Filter for the string table.
#[derive(Debug, Clone, Default)]
pub struct StringFilter {
    /// Text to match against string values (substring match).
    pub text_filter: Option<String>,
    /// Minimum string length.
    pub min_length: Option<usize>,
    /// Maximum string length.
    pub max_length: Option<usize>,
    /// Encoding filter (show only these encodings).
    pub encoding_filter: Vec<StringEncoding>,
    /// Show only defined strings.
    pub defined_only: bool,
    /// Show only undefined strings.
    pub undefined_only: bool,
}

impl StringFilter {
    /// Whether a string matches this filter.
    pub fn matches(&self, fs: &FoundString) -> bool {
        if let Some(ref text) = self.text_filter {
            if !fs.value.to_lowercase().contains(&text.to_lowercase()) {
                return false;
            }
        }
        if let Some(min) = self.min_length {
            if fs.byte_length < min {
                return false;
            }
        }
        if let Some(max) = self.max_length {
            if fs.byte_length > max {
                return false;
            }
        }
        if !self.encoding_filter.is_empty()
            && !self.encoding_filter.contains(&fs.encoding)
        {
            return false;
        }
        if self.defined_only && !fs.is_defined {
            return false;
        }
        if self.undefined_only && fs.is_defined {
            return false;
        }
        true
    }

    /// Whether the filter has any active criteria.
    pub fn is_active(&self) -> bool {
        self.text_filter.is_some()
            || self.min_length.is_some()
            || self.max_length.is_some()
            || !self.encoding_filter.is_empty()
            || self.defined_only
            || self.undefined_only
    }

    /// Clear all filter criteria.
    pub fn clear(&mut self) {
        self.text_filter = None;
        self.min_length = None;
        self.max_length = None;
        self.encoding_filter.clear();
        self.defined_only = false;
        self.undefined_only = false;
    }
}

/// Viewer model for the string table.
///
/// Combines found strings with sorting, filtering, and selection state.
#[derive(Debug)]
pub struct StringViewerModel {
    /// All strings.
    strings: Vec<FoundString>,
    /// Indices of visible (filtered) strings.
    visible_indices: Vec<usize>,
    /// Current sort config.
    sort_config: StringSortConfig,
    /// Current filter.
    filter: StringFilter,
    /// Selected indices (into visible_indices).
    selected: Vec<usize>,
}

impl StringViewerModel {
    /// Create a new viewer model.
    pub fn new() -> Self {
        Self {
            strings: Vec::new(),
            visible_indices: Vec::new(),
            sort_config: StringSortConfig::default(),
            filter: StringFilter::default(),
            selected: Vec::new(),
        }
    }

    /// Set the strings to display.
    pub fn set_strings(&mut self, strings: Vec<FoundString>) {
        self.strings = strings;
        self.apply_filter_and_sort();
    }

    /// Get all strings (unfiltered).
    pub fn all_strings(&self) -> &[FoundString] {
        &self.strings
    }

    /// Get visible (filtered) string count.
    pub fn visible_count(&self) -> usize {
        self.visible_indices.len()
    }

    /// Get a visible string by index.
    pub fn visible_string(&self, index: usize) -> Option<&FoundString> {
        self.visible_indices
            .get(index)
            .and_then(|&idx| self.strings.get(idx))
    }

    /// Set the sort configuration.
    pub fn set_sort(&mut self, config: StringSortConfig) {
        self.sort_config = config;
        self.apply_filter_and_sort();
    }

    /// Get the current sort config.
    pub fn sort_config(&self) -> &StringSortConfig {
        &self.sort_config
    }

    /// Set the filter.
    pub fn set_filter(&mut self, filter: StringFilter) {
        self.filter = filter;
        self.apply_filter_and_sort();
    }

    /// Get the current filter.
    pub fn filter(&self) -> &StringFilter {
        &self.filter
    }

    /// Get mutable access to the filter.
    pub fn filter_mut(&mut self) -> &mut StringFilter {
        &mut self.filter
    }

    /// Clear the filter and show all strings.
    pub fn clear_filter(&mut self) {
        self.filter.clear();
        self.apply_filter_and_sort();
    }

    /// Select a visible string by index.
    pub fn select(&mut self, index: usize) {
        if index < self.visible_count() {
            self.selected.clear();
            self.selected.push(index);
        }
    }

    /// Add to the selection.
    pub fn add_to_selection(&mut self, index: usize) {
        if index < self.visible_count() && !self.selected.contains(&index) {
            self.selected.push(index);
        }
    }

    /// Clear the selection.
    pub fn clear_selection(&mut self) {
        self.selected.clear();
    }

    /// Get selected visible indices.
    pub fn selected_indices(&self) -> &[usize] {
        &self.selected
    }

    /// Get the first selected string.
    pub fn selected_string(&self) -> Option<&FoundString> {
        self.selected
            .first()
            .and_then(|&idx| self.visible_string(idx))
    }

    fn apply_filter_and_sort(&mut self) {
        // Filter
        self.visible_indices.clear();
        for (i, fs) in self.strings.iter().enumerate() {
            if self.filter.matches(fs) {
                self.visible_indices.push(i);
            }
        }
        // Sort
        let strings = &self.strings;
        let col = self.sort_config.column;
        let asc = self.sort_config.direction == SortDirection::Ascending;
        self.visible_indices.sort_by(|&a, &b| {
            let fs_a = &strings[a];
            let fs_b = &strings[b];
            let cmp = match col {
                StringColumn::Address => fs_a.address.cmp(&fs_b.address),
                StringColumn::Value => fs_a.value.cmp(&fs_b.value),
                StringColumn::Encoding => {
                    format!("{:?}", fs_a.encoding).cmp(&format!("{:?}", fs_b.encoding))
                }
                StringColumn::Length => fs_a.byte_length.cmp(&fs_b.byte_length),
                StringColumn::Defined => fs_a.is_defined.cmp(&fs_b.is_defined),
            };
            if asc { cmp } else { cmp.reverse() }
        });
        self.selected.clear();
    }
}

impl Default for StringViewerModel {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_string(address: u64, value: &str, encoding: StringEncoding, len: usize, defined: bool) -> FoundString {
        FoundString {
            address,
            value: value.to_string(),
            encoding,
            byte_length: len,
            is_defined: defined,
        }
    }

    fn sample_strings() -> Vec<FoundString> {
        vec![
            make_string(0x2000, "world", StringEncoding::Ascii, 6, false),
            make_string(0x1000, "hello", StringEncoding::Ascii, 6, true),
            make_string(0x3000, "unicode", StringEncoding::Utf16Le, 16, false),
        ]
    }

    #[test]
    fn test_viewer_model_set_strings() {
        let mut model = StringViewerModel::new();
        model.set_strings(sample_strings());
        assert_eq!(model.visible_count(), 3);
        assert_eq!(model.all_strings().len(), 3);
    }

    #[test]
    fn test_sort_by_address() {
        let mut model = StringViewerModel::new();
        model.set_strings(sample_strings());
        // Default is ascending by address
        assert_eq!(model.visible_string(0).unwrap().address, 0x1000);
        assert_eq!(model.visible_string(1).unwrap().address, 0x2000);
        assert_eq!(model.visible_string(2).unwrap().address, 0x3000);
    }

    #[test]
    fn test_sort_descending() {
        let mut model = StringViewerModel::new();
        model.set_strings(sample_strings());
        model.set_sort(StringSortConfig {
            column: StringColumn::Address,
            direction: SortDirection::Descending,
        });
        assert_eq!(model.visible_string(0).unwrap().address, 0x3000);
    }

    #[test]
    fn test_filter_by_text() {
        let mut model = StringViewerModel::new();
        model.set_strings(sample_strings());
        model.set_filter(StringFilter {
            text_filter: Some("hel".to_string()),
            ..Default::default()
        });
        assert_eq!(model.visible_count(), 1);
        assert_eq!(model.visible_string(0).unwrap().value, "hello");
    }

    #[test]
    fn test_filter_by_encoding() {
        let mut model = StringViewerModel::new();
        model.set_strings(sample_strings());
        model.set_filter(StringFilter {
            encoding_filter: vec![StringEncoding::Utf16Le],
            ..Default::default()
        });
        assert_eq!(model.visible_count(), 1);
        assert_eq!(model.visible_string(0).unwrap().value, "unicode");
    }

    #[test]
    fn test_filter_defined_only() {
        let mut model = StringViewerModel::new();
        model.set_strings(sample_strings());
        model.set_filter(StringFilter {
            defined_only: true,
            ..Default::default()
        });
        assert_eq!(model.visible_count(), 1);
        assert_eq!(model.visible_string(0).unwrap().value, "hello");
    }

    #[test]
    fn test_selection() {
        let mut model = StringViewerModel::new();
        model.set_strings(sample_strings());
        model.select(1);
        assert_eq!(model.selected_indices(), &[1]);
        assert_eq!(model.selected_string().unwrap().value, "world");
    }

    #[test]
    fn test_multi_selection() {
        let mut model = StringViewerModel::new();
        model.set_strings(sample_strings());
        model.select(0);
        model.add_to_selection(2);
        assert_eq!(model.selected_indices().len(), 2);
    }

    #[test]
    fn test_column_headers() {
        assert_eq!(StringColumn::Address.header(), "Address");
        assert_eq!(StringColumn::Value.header(), "String");
        assert_eq!(StringColumn::all().len(), 5);
    }
}
