//! Docking widget model types ported from docking.widgets.model.
//!
//! Provides GSpanField for span-based field display in docking widgets.

/// A span of characters with associated metadata for display.
#[derive(Debug, Clone)]
pub struct GSpanField {
    /// The text content.
    pub text: String,
    /// Start offset in the display.
    pub start: usize,
    /// End offset (exclusive).
    pub end: usize,
    /// Whether this span is selectable.
    pub selectable: bool,
}

impl GSpanField {
    /// Create a new span field.
    pub fn new(text: impl Into<String>, start: usize, end: usize) -> Self {
        Self {
            text: text.into(),
            start,
            end,
            selectable: true,
        }
    }

    /// The length of this span.
    pub fn len(&self) -> usize {
        self.end - self.start
    }

    /// Whether this span is empty.
    pub fn is_empty(&self) -> bool {
        self.start >= self.end
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_span_field() {
        let f = GSpanField::new("hello", 0, 5);
        assert_eq!(f.len(), 5);
        assert!(!f.is_empty());
    }

    #[test]
    fn test_empty_span() {
        let f = GSpanField::new("", 5, 5);
        assert!(f.is_empty());
    }
}
