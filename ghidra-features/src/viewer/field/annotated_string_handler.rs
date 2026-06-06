//! `AnnotatedStringHandler` -- handles annotated strings in the listing.
//!
//! Ported from `ghidra.app.util.viewer.field.AnnotatedStringHandler`.

use crate::viewer::field::annotation::Annotation;

/// Handles annotated strings that contain color and style information.
///
/// Ported from `AnnotatedStringHandler.java`.
pub trait AnnotatedStringHandler {
    /// Get the plain text without annotations.
    fn plain_text(&self) -> &str;

    /// Get the annotations.
    fn annotations(&self) -> &[Annotation];

    /// Get the color for a character at the given position.
    fn color_at(&self, position: usize) -> Option<(u8, u8, u8)>;

    /// Returns true if the character at the given position is highlighted.
    fn is_highlighted_at(&self, position: usize) -> bool;
}

/// A basic annotated string implementation.
#[derive(Debug, Clone)]
pub struct BasicAnnotatedString {
    text: String,
    annotations: Vec<Annotation>,
}

impl BasicAnnotatedString {
    /// Create a new annotated string.
    pub fn new(text: &str) -> Self {
        Self {
            text: text.to_string(),
            annotations: Vec::new(),
        }
    }

    /// Add an annotation.
    pub fn add_annotation(&mut self, annotation: Annotation) {
        self.annotations.push(annotation);
    }
}

impl AnnotatedStringHandler for BasicAnnotatedString {
    fn plain_text(&self) -> &str {
        &self.text
    }

    fn annotations(&self) -> &[Annotation] {
        &self.annotations
    }

    fn color_at(&self, position: usize) -> Option<(u8, u8, u8)> {
        for ann in &self.annotations {
            if position >= ann.start() && position < ann.end() {
                return ann.color();
            }
        }
        None
    }

    fn is_highlighted_at(&self, position: usize) -> bool {
        for ann in &self.annotations {
            if ann.annotation_type() == crate::viewer::field::annotation::AnnotationType::Highlight
                && position >= ann.start()
                && position < ann.end()
            {
                return true;
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::viewer::field::annotation::Annotation;

    #[test]
    fn test_annotated_string_basic() {
        let s = BasicAnnotatedString::new("Hello World");
        assert_eq!(s.plain_text(), "Hello World");
        assert!(s.annotations().is_empty());
    }

    #[test]
    fn test_color_at() {
        let mut s = BasicAnnotatedString::new("Hello");
        s.add_annotation(Annotation::color_change(0, 5, (255, 0, 0)));
        assert_eq!(s.color_at(2), Some((255, 0, 0)));
        assert_eq!(s.color_at(10), None);
    }

    #[test]
    fn test_highlight_at() {
        let mut s = BasicAnnotatedString::new("Hello World");
        s.add_annotation(Annotation::highlight(6, 11, (255, 255, 0)));
        assert!(!s.is_highlighted_at(0));
        assert!(s.is_highlighted_at(8));
    }
}
