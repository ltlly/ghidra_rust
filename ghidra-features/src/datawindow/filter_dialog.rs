//! Data Window Filter Dialog.
//!
//! Ported from Ghidra's
//! `ghidra.app.plugin.core.datawindow.DataWindowFilterDialog` (307 lines).
//!
//! Provides filtering capabilities for the data window, allowing users
//! to filter the displayed data items by data type, address range, and
//! custom criteria.
//!
//! # Key Types
//!
//! - [`DataWindowFilterDialog`] -- The filter dialog model
//! - [`FilterCriteria`] -- Combined filter criteria
//! - [`DataTypeFilter`] -- Filter by data type
//! - [`AddressRangeFilter`] -- Filter by address range

use ghidra_core::Address;

use super::DataRowObject;

// ---------------------------------------------------------------------------
// DataTypeFilter -- filter by data type category/name
// ---------------------------------------------------------------------------

/// Filter for data items by data type.
///
/// Ported from the data type filtering in `DataWindowFilterDialog`.
#[derive(Debug, Clone)]
pub struct DataTypeFilter {
    /// Allowed data type names (empty = all).
    pub allowed_types: Vec<String>,
    /// Excluded data type names.
    pub excluded_types: Vec<String>,
    /// Whether to match substrings.
    pub substring_match: bool,
    /// Minimum size in bytes.
    pub min_size: Option<usize>,
    /// Maximum size in bytes.
    pub max_size: Option<usize>,
}

impl DataTypeFilter {
    /// Create a new filter that allows all types.
    pub fn new() -> Self {
        Self {
            allowed_types: Vec::new(),
            excluded_types: Vec::new(),
            substring_match: true,
            min_size: None,
            max_size: None,
        }
    }

    /// Create a filter that only allows specific types.
    pub fn allow_only(types: Vec<String>) -> Self {
        Self {
            allowed_types: types,
            ..Self::new()
        }
    }

    /// Check if a data type passes this filter.
    pub fn matches(&self, type_name: &str, size: usize) -> bool {
        // Check excluded types
        for excluded in &self.excluded_types {
            if self.matches_pattern(type_name, excluded) {
                return false;
            }
        }

        // Check allowed types
        if !self.allowed_types.is_empty() {
            let found = self
                .allowed_types
                .iter()
                .any(|allowed| self.matches_pattern(type_name, allowed));
            if !found {
                return false;
            }
        }

        // Check size constraints
        if let Some(min) = self.min_size {
            if size < min {
                return false;
            }
        }
        if let Some(max) = self.max_size {
            if size > max {
                return false;
            }
        }

        true
    }

    fn matches_pattern(&self, value: &str, pattern: &str) -> bool {
        if self.substring_match {
            value.contains(pattern)
        } else {
            value == pattern
        }
    }
}

impl Default for DataTypeFilter {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// AddressRangeFilter -- filter by address range
// ---------------------------------------------------------------------------

/// Filter for data items by address range.
#[derive(Debug, Clone)]
pub struct AddressRangeFilter {
    /// Minimum address (inclusive).
    pub min_address: Option<Address>,
    /// Maximum address (inclusive).
    pub max_address: Option<Address>,
}

impl AddressRangeFilter {
    /// Create a new filter with no address constraints.
    pub fn new() -> Self {
        Self {
            min_address: None,
            max_address: None,
        }
    }

    /// Create a filter for a specific range.
    pub fn range(min: Address, max: Address) -> Self {
        Self {
            min_address: Some(min),
            max_address: Some(max),
        }
    }

    /// Check if an address passes this filter.
    pub fn matches(&self, address: &Address) -> bool {
        if let Some(min) = &self.min_address {
            if address < min {
                return false;
            }
        }
        if let Some(max) = &self.max_address {
            if address > max {
                return false;
            }
        }
        true
    }
}

impl Default for AddressRangeFilter {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// FilterCriteria -- combined filter
// ---------------------------------------------------------------------------

/// Combined filter criteria for the data window.
///
/// Ported from the filter state in `DataWindowFilterDialog`.
#[derive(Debug, Clone)]
pub struct FilterCriteria {
    /// Data type filter.
    pub data_type: DataTypeFilter,
    /// Address range filter.
    pub address_range: AddressRangeFilter,
    /// Whether to show only defined data (not undefined).
    pub defined_only: bool,
    /// Whether to show only data with comments.
    pub commented_only: bool,
    /// Custom text filter (substring match on name).
    pub text_filter: Option<String>,
}

impl FilterCriteria {
    /// Create a new filter criteria with no constraints.
    pub fn new() -> Self {
        Self {
            data_type: DataTypeFilter::new(),
            address_range: AddressRangeFilter::new(),
            defined_only: false,
            commented_only: false,
            text_filter: None,
        }
    }

    /// Check if a data row object matches all criteria.
    pub fn matches(&self, row: &DataRowObject) -> bool {
        // Check data type filter
        if !self.data_type.matches(&row.type_name, row.length as usize) {
            return false;
        }

        // Check address range
        if !self.address_range.matches(&Address::new(row.address_key)) {
            return false;
        }

        // Check text filter
        if let Some(text) = &self.text_filter {
            let text_lower = text.to_lowercase();
            if !row.type_name.to_lowercase().contains(&text_lower)
                && !row.value.to_lowercase().contains(&text_lower)
            {
                return false;
            }
        }

        true
    }

    /// Check if any filter is active.
    pub fn is_active(&self) -> bool {
        !self.data_type.allowed_types.is_empty()
            || !self.data_type.excluded_types.is_empty()
            || self.data_type.min_size.is_some()
            || self.data_type.max_size.is_some()
            || self.address_range.min_address.is_some()
            || self.address_range.max_address.is_some()
            || self.defined_only
            || self.commented_only
            || self.text_filter.is_some()
    }

    /// Reset all filters to their default (no filter) state.
    pub fn clear(&mut self) {
        self.data_type = DataTypeFilter::new();
        self.address_range = AddressRangeFilter::new();
        self.defined_only = false;
        self.commented_only = false;
        self.text_filter = None;
    }
}

impl Default for FilterCriteria {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// DataWindowFilterDialog -- the dialog model
// ---------------------------------------------------------------------------

/// The filter dialog model for the data window.
///
/// Ported from `ghidra.app.plugin.core.datawindow.DataWindowFilterDialog`.
///
/// Manages the state of the filter dialog, including the current criteria
/// and the count of items that pass the filter.
#[derive(Debug)]
pub struct DataWindowFilterDialog {
    /// Current filter criteria.
    criteria: FilterCriteria,
    /// Previous criteria (for undo).
    previous_criteria: Option<FilterCriteria>,
    /// Number of items matching the current filter.
    matching_count: usize,
    /// Total number of items.
    total_count: usize,
    /// Whether the dialog is visible.
    visible: bool,
}

impl DataWindowFilterDialog {
    /// Create a new filter dialog.
    pub fn new() -> Self {
        Self {
            criteria: FilterCriteria::new(),
            previous_criteria: None,
            matching_count: 0,
            total_count: 0,
            visible: false,
        }
    }

    /// Get the current filter criteria.
    pub fn criteria(&self) -> &FilterCriteria {
        &self.criteria
    }

    /// Get a mutable reference to the filter criteria.
    pub fn criteria_mut(&mut self) -> &mut FilterCriteria {
        &mut self.criteria
    }

    /// Apply the current filter (save as previous for potential undo).
    pub fn apply(&mut self) {
        self.previous_criteria = Some(self.criteria.clone());
    }

    /// Undo the last filter change.
    pub fn undo(&mut self) {
        if let Some(prev) = self.previous_criteria.take() {
            self.criteria = prev;
        }
    }

    /// Whether an undo is available.
    pub fn can_undo(&self) -> bool {
        self.previous_criteria.is_some()
    }

    /// Update the count of matching items.
    pub fn set_matching_count(&mut self, matching: usize, total: usize) {
        self.matching_count = matching;
        self.total_count = total;
    }

    /// Get the matching count.
    pub fn matching_count(&self) -> usize {
        self.matching_count
    }

    /// Get the total count.
    pub fn total_count(&self) -> usize {
        self.total_count
    }

    /// Get the filter percentage.
    pub fn filter_percentage(&self) -> f64 {
        if self.total_count == 0 {
            100.0
        } else {
            (self.matching_count as f64 / self.total_count as f64) * 100.0
        }
    }

    /// Show the dialog.
    pub fn show(&mut self) {
        self.visible = true;
    }

    /// Hide the dialog.
    pub fn hide(&mut self) {
        self.visible = false;
    }

    /// Whether the dialog is visible.
    pub fn is_visible(&self) -> bool {
        self.visible
    }

    /// Apply a quick filter by data type name substring.
    pub fn quick_filter_by_type(&mut self, type_name: &str) {
        self.apply();
        self.criteria.data_type = DataTypeFilter::allow_only(vec![type_name.to_string()]);
    }

    /// Apply a quick filter by address range.
    pub fn quick_filter_by_range(&mut self, min: Address, max: Address) {
        self.apply();
        self.criteria.address_range = AddressRangeFilter::range(min, max);
    }

    /// Clear all filters.
    pub fn clear_filters(&mut self) {
        self.apply();
        self.criteria.clear();
    }
}

impl Default for DataWindowFilterDialog {
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

    fn make_row(value: &str, type_name: &str, addr_offset: u64, size: u32) -> DataRowObject {
        DataRowObject {
            address_key: addr_offset,
            address: format!("0x{:x}", addr_offset),
            type_name: type_name.to_string(),
            value: value.to_string(),
            length: size,
        }
    }

    #[test]
    fn test_data_type_filter_allows_all() {
        let filter = DataTypeFilter::new();
        assert!(filter.matches("int", 4));
        assert!(filter.matches("char", 1));
        assert!(filter.matches("anything", 100));
    }

    #[test]
    fn test_data_type_filter_allow_only() {
        let filter = DataTypeFilter::allow_only(vec!["int".into(), "float".into()]);
        assert!(filter.matches("int", 4));
        assert!(filter.matches("float", 4));
        assert!(!filter.matches("char", 1));
    }

    #[test]
    fn test_data_type_filter_excluded() {
        let mut filter = DataTypeFilter::new();
        filter.excluded_types.push("byte".into());
        assert!(filter.matches("int", 4));
        assert!(!filter.matches("byte", 1));
    }

    #[test]
    fn test_data_type_filter_size() {
        let mut filter = DataTypeFilter::new();
        filter.min_size = Some(4);
        filter.max_size = Some(8);
        assert!(filter.matches("int", 4));
        assert!(filter.matches("long", 8));
        assert!(!filter.matches("char", 1));
        assert!(!filter.matches("huge", 100));
    }

    #[test]
    fn test_data_type_filter_substring_match() {
        let filter = DataTypeFilter::allow_only(vec!["int".into()]);
        assert!(filter.matches("unsigned_int", 4));
        assert!(filter.matches("int", 4));
        assert!(!filter.matches("float", 4));
    }

    #[test]
    fn test_data_type_filter_exact_match() {
        let mut filter = DataTypeFilter::allow_only(vec!["int".into()]);
        filter.substring_match = false;
        assert!(filter.matches("int", 4));
        assert!(!filter.matches("unsigned_int", 4));
    }

    #[test]
    fn test_address_range_filter_no_constraints() {
        let filter = AddressRangeFilter::new();
        assert!(filter.matches(&Address::new(0)));
        assert!(filter.matches(&Address::new(0xFFFF_FFFF)));
    }

    #[test]
    fn test_address_range_filter_range() {
        let filter = AddressRangeFilter::range(Address::new(0x1000), Address::new(0x2000));
        assert!(filter.matches(&Address::new(0x1000)));
        assert!(filter.matches(&Address::new(0x1500)));
        assert!(filter.matches(&Address::new(0x2000)));
        assert!(!filter.matches(&Address::new(0x0FFF)));
        assert!(!filter.matches(&Address::new(0x2001)));
    }

    #[test]
    fn test_filter_criteria_inactive() {
        let criteria = FilterCriteria::new();
        assert!(!criteria.is_active());
    }

    #[test]
    fn test_filter_criteria_active_text() {
        let mut criteria = FilterCriteria::new();
        criteria.text_filter = Some("test".into());
        assert!(criteria.is_active());
    }

    #[test]
    fn test_filter_criteria_matches_text() {
        let mut criteria = FilterCriteria::new();
        criteria.text_filter = Some("42".into());
        let row = make_row("42", "int", 0x1000, 4);
        assert!(criteria.matches(&row));

        let row2 = make_row("0xFF", "int", 0x2000, 4);
        assert!(!criteria.matches(&row2));
    }

    #[test]
    fn test_filter_criteria_matches_type_name_text() {
        let mut criteria = FilterCriteria::new();
        criteria.text_filter = Some("float".into());
        let row = make_row("x", "float", 0x1000, 4);
        assert!(criteria.matches(&row));

        let row2 = make_row("x", "int", 0x1000, 4);
        assert!(!criteria.matches(&row2));
    }

    #[test]
    fn test_filter_criteria_clear() {
        let mut criteria = FilterCriteria::new();
        criteria.text_filter = Some("test".into());
        criteria.defined_only = true;
        criteria.data_type.min_size = Some(4);

        criteria.clear();
        assert!(!criteria.is_active());
        assert!(criteria.text_filter.is_none());
        assert!(!criteria.defined_only);
    }

    #[test]
    fn test_data_window_filter_dialog_new() {
        let dialog = DataWindowFilterDialog::new();
        assert!(!dialog.is_visible());
        assert_eq!(dialog.matching_count(), 0);
        assert_eq!(dialog.total_count(), 0);
        assert!(!dialog.can_undo());
    }

    #[test]
    fn test_data_window_filter_dialog_apply_undo() {
        let mut dialog = DataWindowFilterDialog::new();
        dialog.criteria_mut().text_filter = Some("test".into());

        dialog.apply();
        assert!(dialog.can_undo());

        dialog.criteria_mut().text_filter = Some("other".into());
        assert_eq!(
            dialog.criteria().text_filter.as_deref(),
            Some("other")
        );

        dialog.undo();
        assert_eq!(
            dialog.criteria().text_filter.as_deref(),
            Some("test")
        );
        assert!(!dialog.can_undo());
    }

    #[test]
    fn test_data_window_filter_dialog_visibility() {
        let mut dialog = DataWindowFilterDialog::new();
        assert!(!dialog.is_visible());

        dialog.show();
        assert!(dialog.is_visible());

        dialog.hide();
        assert!(!dialog.is_visible());
    }

    #[test]
    fn test_data_window_filter_dialog_counts() {
        let mut dialog = DataWindowFilterDialog::new();
        dialog.set_matching_count(75, 100);
        assert_eq!(dialog.matching_count(), 75);
        assert_eq!(dialog.total_count(), 100);
        assert!((dialog.filter_percentage() - 75.0).abs() < 0.01);
    }

    #[test]
    fn test_data_window_filter_dialog_filter_percentage_empty() {
        let dialog = DataWindowFilterDialog::new();
        assert!((dialog.filter_percentage() - 100.0).abs() < 0.01);
    }

    #[test]
    fn test_data_window_filter_dialog_quick_filter_type() {
        let mut dialog = DataWindowFilterDialog::new();
        dialog.quick_filter_by_type("int");
        assert!(dialog.criteria().is_active());
        assert!(dialog.can_undo());
        assert!(dialog.criteria().data_type.allowed_types.contains(&"int".to_string()));
    }

    #[test]
    fn test_data_window_filter_dialog_quick_filter_range() {
        let mut dialog = DataWindowFilterDialog::new();
        dialog.quick_filter_by_range(Address::new(0x1000), Address::new(0x2000));
        assert!(dialog.criteria().is_active());
        assert!(dialog.criteria().address_range.min_address.is_some());
        assert!(dialog.criteria().address_range.max_address.is_some());
    }

    #[test]
    fn test_data_window_filter_dialog_clear_filters() {
        let mut dialog = DataWindowFilterDialog::new();
        dialog.quick_filter_by_type("int");
        assert!(dialog.criteria().is_active());

        dialog.clear_filters();
        assert!(!dialog.criteria().is_active());
        assert!(dialog.can_undo()); // previous criteria is saved
    }

    #[test]
    fn test_data_window_filter_dialog_integration() {
        let mut dialog = DataWindowFilterDialog::new();
        let rows = vec![
            make_row("main", "int", 0x1000, 4),
            make_row("buf", "char", 0x2000, 1),
            make_row("header", "struct", 0x3000, 64),
            make_row("count", "int", 0x4000, 4),
        ];

        // Filter by type
        dialog.quick_filter_by_type("int");
        let matching: Vec<_> = rows.iter().filter(|r| dialog.criteria().matches(r)).collect();
        assert_eq!(matching.len(), 2);
        dialog.set_matching_count(matching.len(), rows.len());
        assert!((dialog.filter_percentage() - 50.0).abs() < 0.01);

        // Undo and filter by range
        dialog.undo();
        dialog.quick_filter_by_range(Address::new(0x2000), Address::new(0x3000));
        let matching: Vec<_> = rows.iter().filter(|r| dialog.criteria().matches(r)).collect();
        assert_eq!(matching.len(), 2);
    }

    #[test]
    fn test_data_type_filter_combined() {
        let mut filter = DataTypeFilter::new();
        filter.allowed_types.push("int".into());
        filter.min_size = Some(2);

        assert!(filter.matches("int", 4));
        assert!(!filter.matches("int", 1)); // too small
        assert!(!filter.matches("char", 4)); // wrong type
    }
}
