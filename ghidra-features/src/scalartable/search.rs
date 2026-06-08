//! Additional scalar search types: range filter and column constraint provider.
//!
//! Ported from `ghidra.app.plugin.core.scalartable.RangeFilterTextField`,
//! `ScalarColumnConstraintProvider`, and mapper types.
//!
//! Note: `ScalarSearchContext`, `ScalarSearchModel`, `ScalarSearchPlugin`,
//! `ScalarRowObject`, and mappers are defined in the parent `model` module.
//! This module provides only the additional types that were missing.


// ---------------------------------------------------------------------------
// RangeFilterTextField
// ---------------------------------------------------------------------------

/// A text field for filtering scalar values by range.
///
/// Ported from `ghidra.app.plugin.core.scalartable.RangeFilterTextField`.
#[derive(Debug, Clone)]
pub struct RangeFilterTextField {
    /// The filter text.
    text: String,
    /// Parsed minimum value.
    min: Option<u64>,
    /// Parsed maximum value.
    max: Option<u64>,
    /// Whether the filter is valid.
    valid: bool,
}

impl RangeFilterTextField {
    /// Create a new range filter.
    pub fn new() -> Self {
        Self {
            text: String::new(),
            min: None,
            max: None,
            valid: true,
        }
    }

    /// Set the filter text (e.g., "0x100..0x200", ">=0x100", "<0xFF").
    pub fn set_text(&mut self, text: impl Into<String>) {
        self.text = text.into();
        self.parse();
    }

    /// Get the filter text.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Whether the filter is valid.
    pub fn is_valid(&self) -> bool {
        self.valid
    }

    /// Get the parsed minimum value.
    pub fn min(&self) -> Option<u64> {
        self.min
    }

    /// Get the parsed maximum value.
    pub fn max(&self) -> Option<u64> {
        self.max
    }

    /// Check if a value matches the filter.
    pub fn matches(&self, value: u64) -> bool {
        if let Some(min) = self.min {
            if value < min {
                return false;
            }
        }
        if let Some(max) = self.max {
            if value > max {
                return false;
            }
        }
        true
    }

    fn parse(&mut self) {
        self.valid = true;
        self.min = None;
        self.max = None;

        let text = self.text.trim();
        if text.is_empty() {
            return;
        }

        // Try range format: "min..max"
        if let Some(idx) = text.find("..") {
            let (lo, hi) = text.split_at(idx);
            let hi = &hi[2..]; // skip ".."
            self.min = Self::parse_value(lo.trim());
            self.max = Self::parse_value(hi.trim());
            if self.min.is_none() && self.max.is_none() {
                self.valid = false;
            }
            return;
        }

        // Try comparison format: ">=val", "<=val", ">val", "<val", "=val"
        if text.starts_with(">=") {
            self.min = Self::parse_value(text[2..].trim());
        } else if text.starts_with("<=") {
            self.max = Self::parse_value(text[2..].trim());
        } else if text.starts_with('>') {
            self.min = Self::parse_value(text[1..].trim()).map(|v| v + 1);
        } else if text.starts_with('<') {
            self.max = Self::parse_value(text[1..].trim()).map(|v| v.saturating_sub(1));
        } else if text.starts_with('=') {
            let val = Self::parse_value(text[1..].trim());
            self.min = val;
            self.max = val;
        } else {
            // Exact match
            let val = Self::parse_value(text);
            self.min = val;
            self.max = val;
            if val.is_none() {
                self.valid = false;
            }
        }
    }

    fn parse_value(s: &str) -> Option<u64> {
        let s = s.trim();
        if s.is_empty() {
            return None;
        }
        if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
            u64::from_str_radix(hex, 16).ok()
        } else {
            s.parse::<u64>().ok()
        }
    }
}

impl Default for RangeFilterTextField {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// ScalarColumnConstraintProvider
// ---------------------------------------------------------------------------

/// Provides column-based constraints for filtering scalar values.
///
/// Ported from `ghidra.app.plugin.core.scalartable.ScalarColumnConstraintProvider`.
#[derive(Debug, Clone)]
pub struct ScalarColumnConstraintProvider {
    /// Column-specific filters.
    filters: Vec<ColumnFilter>,
}

/// A single column filter.
#[derive(Debug, Clone)]
pub struct ColumnFilter {
    /// The column index.
    pub column: usize,
    /// The filter text.
    pub filter_text: String,
    /// Whether the filter is active.
    pub active: bool,
}

impl ScalarColumnConstraintProvider {
    /// Create a new constraint provider.
    pub fn new() -> Self {
        Self {
            filters: Vec::new(),
        }
    }

    /// Add a column filter.
    pub fn add_filter(&mut self, column: usize, filter_text: impl Into<String>) {
        self.filters.push(ColumnFilter {
            column,
            filter_text: filter_text.into(),
            active: true,
        });
    }

    /// Remove all filters for a column.
    pub fn remove_filters(&mut self, column: usize) {
        self.filters.retain(|f| f.column != column);
    }

    /// Get the active filters for a column.
    pub fn filters_for_column(&self, column: usize) -> Vec<&ColumnFilter> {
        self.filters
            .iter()
            .filter(|f| f.column == column && f.active)
            .collect()
    }

    /// Whether any filters are active.
    pub fn has_active_filters(&self) -> bool {
        self.filters.iter().any(|f| f.active)
    }

    /// The total number of filters.
    pub fn filter_count(&self) -> usize {
        self.filters.len()
    }

    /// Clear all filters.
    pub fn clear(&mut self) {
        self.filters.clear();
    }
}

impl Default for ScalarColumnConstraintProvider {
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
    fn test_range_filter_parse_range() {
        let mut filter = RangeFilterTextField::new();
        filter.set_text("0x100..0x200");
        assert!(filter.is_valid());
        assert_eq!(filter.min(), Some(0x100));
        assert_eq!(filter.max(), Some(0x200));
        assert!(filter.matches(0x180));
        assert!(!filter.matches(0x50));
    }

    #[test]
    fn test_range_filter_parse_comparison() {
        let mut filter = RangeFilterTextField::new();
        filter.set_text(">=0x100");
        assert!(filter.is_valid());
        assert_eq!(filter.min(), Some(0x100));
        assert!(filter.matches(0x200));
        assert!(!filter.matches(0xFF));

        filter.set_text("<0xFF");
        assert_eq!(filter.max(), Some(0xFE));
        assert!(filter.matches(0x50));
        assert!(!filter.matches(0xFF));
    }

    #[test]
    fn test_range_filter_exact() {
        let mut filter = RangeFilterTextField::new();
        filter.set_text("0x42");
        assert!(filter.is_valid());
        assert!(filter.matches(0x42));
        assert!(!filter.matches(0x43));
    }

    #[test]
    fn test_range_filter_empty() {
        let mut filter = RangeFilterTextField::new();
        filter.set_text("");
        assert!(filter.is_valid());
        assert!(filter.matches(0));
    }

    #[test]
    fn test_range_filter_invalid() {
        let mut filter = RangeFilterTextField::new();
        filter.set_text("not_a_number");
        assert!(!filter.is_valid());
    }

    #[test]
    fn test_range_filter_decimal() {
        let mut filter = RangeFilterTextField::new();
        filter.set_text("256");
        assert!(filter.is_valid());
        assert!(filter.matches(256));
        assert!(!filter.matches(257));
    }

    #[test]
    fn test_column_constraint_provider() {
        let mut provider = ScalarColumnConstraintProvider::new();
        assert!(!provider.has_active_filters());

        provider.add_filter(0, "0x100..0x200");
        provider.add_filter(1, ">10");
        provider.add_filter(0, "<0xFFFF");
        assert_eq!(provider.filter_count(), 3);
        assert!(provider.has_active_filters());

        let col0_filters = provider.filters_for_column(0);
        assert_eq!(col0_filters.len(), 2);

        let col1_filters = provider.filters_for_column(1);
        assert_eq!(col1_filters.len(), 1);

        provider.remove_filters(0);
        assert_eq!(provider.filter_count(), 1);

        provider.clear();
        assert_eq!(provider.filter_count(), 0);
    }

    #[test]
    fn test_column_filter_active() {
        let mut provider = ScalarColumnConstraintProvider::new();
        provider.add_filter(0, "test");
        assert_eq!(provider.filters_for_column(0).len(), 1);

        // Deactivate filter
        provider.filters[0].active = false;
        assert_eq!(provider.filters_for_column(0).len(), 0);
        assert!(!provider.has_active_filters());
    }
}
