//! GSpanField widget model for span/range display in docking components.
//!
//! Ported from Ghidra's `docking.widgets.model.GSpanField`.
//! Provides a data model for visualizing address span fields
//! in a UI widget (non-GUI data model only).

use serde::{Deserialize, Serialize};

/// A field within a span visualization, representing a discrete region.
///
/// Each field has a start position, a width (length), a label, and
/// an optional category for grouping/coloring.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GSpanField {
    /// The start position of this field within the span.
    pub start: u64,
    /// The width/length of this field.
    pub width: u64,
    /// An optional label for this field.
    pub label: Option<String>,
    /// An optional category for grouping or color assignment.
    pub category: Option<String>,
    /// Whether this field is currently selected.
    pub selected: bool,
}

impl GSpanField {
    /// Create a new span field.
    pub fn new(start: u64, width: u64) -> Self {
        Self {
            start,
            width,
            label: None,
            category: None,
            selected: false,
        }
    }

    /// Create a span field with a label.
    pub fn with_label(start: u64, width: u64, label: impl Into<String>) -> Self {
        Self {
            start,
            width,
            label: Some(label.into()),
            category: None,
            selected: false,
        }
    }

    /// Create a span field with a label and category.
    pub fn with_category(
        start: u64,
        width: u64,
        label: impl Into<String>,
        category: impl Into<String>,
    ) -> Self {
        Self {
            start,
            width,
            label: Some(label.into()),
            category: Some(category.into()),
            selected: false,
        }
    }

    /// Get the end position (exclusive) of this field.
    pub fn end(&self) -> u64 {
        self.start + self.width
    }

    /// Check if a position falls within this field.
    pub fn contains(&self, position: u64) -> bool {
        position >= self.start && position < self.end()
    }

    /// Check if this field overlaps with another.
    pub fn overlaps(&self, other: &GSpanField) -> bool {
        self.start < other.end() && other.start < self.end()
    }

    /// Get the overlap region with another field, if any.
    pub fn overlap(&self, other: &GSpanField) -> Option<(u64, u64)> {
        let start = self.start.max(other.start);
        let end = self.end().min(other.end());
        if start < end {
            Some((start, end - start))
        } else {
            None
        }
    }
}

/// A collection of span fields that make up a complete span visualization.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GSpanFieldModel {
    /// The fields in this model, ordered by start position.
    fields: Vec<GSpanField>,
}

impl GSpanFieldModel {
    /// Create a new empty span field model.
    pub fn new() -> Self {
        Self { fields: Vec::new() }
    }

    /// Add a field to the model.
    pub fn add_field(&mut self, field: GSpanField) {
        self.fields.push(field);
    }

    /// Get all fields.
    pub fn fields(&self) -> &[GSpanField] {
        &self.fields
    }

    /// Get a mutable reference to all fields.
    pub fn fields_mut(&mut self) -> &mut Vec<GSpanField> {
        &mut self.fields
    }

    /// Sort fields by start position.
    pub fn sort(&mut self) {
        self.fields.sort_by_key(|f| f.start);
    }

    /// Find all fields containing a given position.
    pub fn fields_at(&self, position: u64) -> Vec<&GSpanField> {
        self.fields.iter().filter(|f| f.contains(position)).collect()
    }

    /// Find all fields in a given category.
    pub fn fields_in_category(&self, category: &str) -> Vec<&GSpanField> {
        self.fields
            .iter()
            .filter(|f| f.category.as_deref() == Some(category))
            .collect()
    }

    /// Find all fields that overlap with the given range.
    pub fn fields_in_range(&self, start: u64, width: u64) -> Vec<&GSpanField> {
        let end = start + width;
        self.fields
            .iter()
            .filter(|f| f.start < end && start < f.end())
            .collect()
    }

    /// Get the total span covered by all fields.
    pub fn total_span(&self) -> Option<(u64, u64)> {
        if self.fields.is_empty() {
            return None;
        }
        let min = self.fields.iter().map(|f| f.start).min().unwrap();
        let max = self.fields.iter().map(|f| f.end()).max().unwrap();
        Some((min, max - min))
    }

    /// Remove all fields.
    pub fn clear(&mut self) {
        self.fields.clear();
    }

    /// Get the number of fields.
    pub fn len(&self) -> usize {
        self.fields.len()
    }

    /// Check if the model has no fields.
    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_span_field_basics() {
        let field = GSpanField::with_label(100, 50, "test");
        assert_eq!(field.end(), 150);
        assert!(field.contains(100));
        assert!(field.contains(149));
        assert!(!field.contains(150));
        assert!(!field.contains(99));
    }

    #[test]
    fn test_span_field_overlap() {
        let a = GSpanField::new(100, 50);
        let b = GSpanField::new(120, 50);
        let c = GSpanField::new(200, 50);

        assert!(a.overlaps(&b));
        assert!(b.overlaps(&a));
        assert!(!a.overlaps(&c));

        let overlap = a.overlap(&b).unwrap();
        assert_eq!(overlap, (120, 30));

        assert!(a.overlap(&c).is_none());
    }

    #[test]
    fn test_span_field_model() {
        let mut model = GSpanFieldModel::new();
        model.add_field(GSpanField::with_category(100, 50, "a", "memory"));
        model.add_field(GSpanField::with_category(200, 30, "b", "register"));
        model.add_field(GSpanField::with_category(150, 50, "c", "memory"));

        assert_eq!(model.len(), 3);
        assert_eq!(model.fields_at(160).len(), 1);
        assert_eq!(model.fields_in_category("memory").len(), 2);

        model.sort();
        assert_eq!(model.fields()[0].label.as_deref(), Some("a"));

        let span = model.total_span().unwrap();
        assert_eq!(span, (100, 130));

        assert_eq!(model.fields_in_range(90, 20).len(), 1);
        assert_eq!(model.fields_in_range(140, 20).len(), 2);
    }
}
