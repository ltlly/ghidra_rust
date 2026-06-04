//! Attribute-based filtering for graph visualization.
//!
//! Ported from Ghidra's `ghidra.graph.AttributeFilters` Java class.
//!
//! Filters are discovered automatically from the attributes of graph
//! elements. For each attribute key that appears across multiple elements,
//! a filter is created that lets the user show/hide elements by value.

use std::collections::HashMap;
use super::attributed::Attributed;

/// A filter for a single attribute key with a set of allowed values.
#[derive(Debug, Clone)]
pub struct AttributeFilter {
    /// The attribute key this filter matches on.
    pub key: String,
    /// The set of distinct values seen for this key.
    pub values: Vec<String>,
    /// Currently selected values (empty = all pass).
    pub selected: Vec<String>,
}

impl AttributeFilter {
    /// Create a new filter for the given attribute key.
    pub fn new(key: impl Into<String>, values: Vec<String>) -> Self {
        Self {
            key: key.into(),
            values,
            selected: Vec::new(),
        }
    }

    /// Check if a given value passes this filter.
    ///
    /// Returns `true` if no values are selected (all pass) or if the
    /// value is in the selected set.
    pub fn passes(&self, value: &str) -> bool {
        self.selected.is_empty() || self.selected.iter().any(|v| v == value)
    }

    /// Toggle a value in the selected set.
    pub fn toggle(&mut self, value: &str) {
        if let Some(pos) = self.selected.iter().position(|v| v == value) {
            self.selected.remove(pos);
        } else {
            self.selected.push(value.to_string());
        }
    }

    /// Select all values (clear the selected set so all pass).
    pub fn select_all(&mut self) {
        self.selected.clear();
    }

    /// Select only a single value.
    pub fn select_only(&mut self, value: &str) {
        self.selected.clear();
        self.selected.push(value.to_string());
    }

    /// Whether this filter is currently active (has a non-empty selection).
    pub fn is_active(&self) -> bool {
        !self.selected.is_empty()
    }
}

/// Build attribute filters from a set of attributed elements.
///
/// Scans all attributes of the given elements, discovers distinct values
/// for each key, and creates filters for keys that appear frequently enough.
///
/// * `excluded_keys` -- keys to ignore (e.g. "Name").
/// * `max_factor` -- threshold = max(2, elements.len() * max_factor).
pub fn build_filters(
    elements: &[&dyn Attributed],
    excluded_keys: &[&str],
    max_factor: f64,
) -> Vec<AttributeFilter> {
    let threshold = (2.0_f64).max(elements.len() as f64 * max_factor) as usize;
    let mut key_counts: HashMap<String, HashMap<String, usize>> = HashMap::new();

    for elem in elements {
        for (key, value) in elem.attributes() {
            if excluded_keys.contains(&key.as_str()) {
                continue;
            }
            *key_counts
                .entry(key.clone())
                .or_default()
                .entry(value.clone())
                .or_insert(0) += 1;
        }
    }

    let mut filters: Vec<AttributeFilter> = key_counts
        .into_iter()
        .filter(|(_, values)| values.len() >= 2 && values.len() <= threshold)
        .map(|(key, values)| {
            let mut sorted_values: Vec<String> = values.into_keys().collect();
            sorted_values.sort();
            AttributeFilter::new(key, sorted_values)
        })
        .collect();
    filters.sort_by(|a, b| a.key.cmp(&b.key));
    filters
}

/// Apply a set of filters to check if an element passes all active filters.
///
/// Returns `true` if the element passes all active filters.
pub fn passes_all_filters(element: &dyn Attributed, filters: &[AttributeFilter]) -> bool {
    for filter in filters {
        if filter.is_active() {
            if let Some(value) = element.get(&filter.key) {
                if !filter.passes(value) {
                    return false;
                }
            }
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::attributed::AttributedVertex;

    #[test]
    fn test_filter_passes_when_inactive() {
        let filter = AttributeFilter::new("type", vec!["code".to_string(), "data".to_string()]);
        assert!(filter.passes("code"));
        assert!(filter.passes("data"));
        assert!(!filter.is_active());
    }

    #[test]
    fn test_filter_toggle() {
        let mut filter =
            AttributeFilter::new("type", vec!["code".to_string(), "data".to_string()]);
        filter.toggle("code");
        assert!(filter.passes("code"));
        assert!(!filter.passes("data"));
        assert!(filter.is_active());

        filter.toggle("code");
        assert!(filter.passes("code"));
        assert!(!filter.is_active());
    }

    #[test]
    fn test_filter_select_only() {
        let mut filter = AttributeFilter::new(
            "type",
            vec![
                "a".to_string(),
                "b".to_string(),
                "c".to_string(),
            ],
        );
        filter.select_only("b");
        assert!(!filter.passes("a"));
        assert!(filter.passes("b"));
        assert!(!filter.passes("c"));
    }

    #[test]
    fn test_build_filters() {
        let mut v1 = AttributedVertex::new("A", "A");
        v1.set("type", "code");
        let mut v2 = AttributedVertex::new("B", "B");
        v2.set("type", "data");
        let mut v3 = AttributedVertex::new("C", "C");
        v3.set("type", "code");

        let elements: Vec<&dyn Attributed> = vec![&v1, &v2, &v3];
        let filters = build_filters(&elements, &["Name"], 1.0);
        assert_eq!(filters.len(), 1);
        assert_eq!(filters[0].key, "type");
        assert_eq!(filters[0].values.len(), 2);
        assert!(filters[0].values.contains(&"code".to_string()));
        assert!(filters[0].values.contains(&"data".to_string()));
    }

    #[test]
    fn test_build_filters_excludes_keys() {
        let mut v1 = AttributedVertex::new("A", "A");
        v1.set("Name", "alpha");
        let mut v2 = AttributedVertex::new("B", "B");
        v2.set("Name", "beta");

        let elements: Vec<&dyn Attributed> = vec![&v1, &v2];
        let filters = build_filters(&elements, &["Name"], 1.0);
        assert!(filters.is_empty());
    }

    #[test]
    fn test_passes_all_filters() {
        let mut v = AttributedVertex::new("A", "A");
        v.set("type", "code");
        v.set("color", "red");

        let mut f1 = AttributeFilter::new(
            "type",
            vec!["code".to_string(), "data".to_string()],
        );
        f1.toggle("code");

        let mut f2 = AttributeFilter::new(
            "color",
            vec!["red".to_string(), "blue".to_string()],
        );
        f2.toggle("red");

        assert!(passes_all_filters(&v, &[f1, f2]));
    }

    #[test]
    fn test_passes_all_filters_fails() {
        let mut v = AttributedVertex::new("A", "A");
        v.set("type", "data");

        let mut f = AttributeFilter::new(
            "type",
            vec!["code".to_string(), "data".to_string()],
        );
        f.toggle("code");

        assert!(!passes_all_filters(&v, &[f]));
    }
}
