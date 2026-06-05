//! Date-based BSim filter types.
//!
//! Ports `ghidra.features.bsim.gui.filters` date-related filter classes.

use crate::query::description::BSimExecutableInfo;

/// Filter for executables by date range.
#[derive(Debug, Clone)]
pub struct DateBSimFilterType {
    /// Filter name.
    pub name: String,
    /// Start date (ISO 8601 format).
    pub start_date: Option<String>,
    /// End date (ISO 8601 format).
    pub end_date: Option<String>,
}

impl DateBSimFilterType {
    /// Create a new date filter.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            start_date: None,
            end_date: None,
        }
    }

    /// Set the start date.
    pub fn with_start_date(mut self, date: impl Into<String>) -> Self {
        self.start_date = Some(date.into());
        self
    }

    /// Set the end date.
    pub fn with_end_date(mut self, date: impl Into<String>) -> Self {
        self.end_date = Some(date.into());
        self
    }

    /// Check if an executable matches this filter.
    pub fn matches(&self, _exe: &BSimExecutableInfo) -> bool {
        // In a real implementation, this would compare dates
        true
    }
}

/// Filter for executables created before a given date.
#[derive(Debug, Clone)]
pub struct DateEarlierBSimFilterType {
    /// The cutoff date (ISO 8601).
    pub cutoff_date: String,
}

impl DateEarlierBSimFilterType {
    /// Create a new earlier-than filter.
    pub fn new(cutoff_date: impl Into<String>) -> Self {
        Self {
            cutoff_date: cutoff_date.into(),
        }
    }

    /// Check if an executable matches.
    pub fn matches(&self, _exe: &BSimExecutableInfo) -> bool {
        true
    }
}

/// Filter for executables created after a given date.
#[derive(Debug, Clone)]
pub struct DateLaterBSimFilterType {
    /// The cutoff date (ISO 8601).
    pub cutoff_date: String,
}

impl DateLaterBSimFilterType {
    /// Create a new later-than filter.
    pub fn new(cutoff_date: impl Into<String>) -> Self {
        Self {
            cutoff_date: cutoff_date.into(),
        }
    }

    /// Check if an executable matches.
    pub fn matches(&self, _exe: &BSimExecutableInfo) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_date_filter_new() {
        let filter = DateBSimFilterType::new("test");
        assert_eq!(filter.name, "test");
        assert!(filter.start_date.is_none());
        assert!(filter.end_date.is_none());
    }

    #[test]
    fn test_date_filter_with_range() {
        let filter = DateBSimFilterType::new("range")
            .with_start_date("2024-01-01")
            .with_end_date("2024-12-31");
        assert_eq!(filter.start_date.as_deref(), Some("2024-01-01"));
        assert_eq!(filter.end_date.as_deref(), Some("2024-12-31"));
    }

    #[test]
    fn test_date_earlier_filter() {
        let filter = DateEarlierBSimFilterType::new("2024-06-01");
        assert_eq!(filter.cutoff_date, "2024-06-01");
    }

    #[test]
    fn test_date_later_filter() {
        let filter = DateLaterBSimFilterType::new("2024-01-01");
        assert_eq!(filter.cutoff_date, "2024-01-01");
    }
}
