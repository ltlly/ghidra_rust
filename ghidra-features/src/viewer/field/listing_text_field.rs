//! `ListingTextField` -- text field implementation for the listing display.
//!
//! Ported from `ghidra.app.util.viewer.field.ListingTextField`.

use crate::viewer::field::annotation::Annotation;

/// A text field in the listing display, created by a [`FieldFactory`](crate::viewer::field::FieldFactory).
///
/// Holds the rendered text, position information, and optional annotations
/// (highlights, color changes, etc.).
///
/// Ported from `ListingTextField.java`.
#[derive(Debug, Clone)]
pub struct ListingTextField {
    /// The field factory name that created this field.
    factory_name: String,
    /// The display text for this field.
    text: String,
    /// The starting X position of this field.
    start_x: i32,
    /// The width of this field.
    width: i32,
    /// Annotations within this field (highlights, colors).
    annotations: Vec<Annotation>,
    /// Whether this field is in a word-wrapped layout.
    word_wrapped: bool,
    /// The maximum number of lines (for word-wrapped fields).
    max_lines: usize,
}

impl ListingTextField {
    /// Create a new single-line text field.
    pub fn new_single_line(
        factory_name: &str,
        text: &str,
        start_x: i32,
        width: i32,
    ) -> Self {
        Self {
            factory_name: factory_name.to_string(),
            text: text.to_string(),
            start_x,
            width,
            annotations: Vec::new(),
            word_wrapped: false,
            max_lines: 1,
        }
    }

    /// Create a new word-wrapped text field.
    pub fn new_word_wrapped(
        factory_name: &str,
        text: &str,
        start_x: i32,
        width: i32,
        max_lines: usize,
    ) -> Self {
        Self {
            factory_name: factory_name.to_string(),
            text: text.to_string(),
            start_x,
            width,
            annotations: Vec::new(),
            word_wrapped: true,
            max_lines,
        }
    }

    /// Get the factory name that created this field.
    pub fn factory_name(&self) -> &str {
        &self.factory_name
    }

    /// Get the display text.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Get the starting X position.
    pub fn start_x(&self) -> i32 {
        self.start_x
    }

    /// Get the width.
    pub fn width(&self) -> i32 {
        self.width
    }

    /// Get the annotations.
    pub fn annotations(&self) -> &[Annotation] {
        &self.annotations
    }

    /// Add an annotation.
    pub fn add_annotation(&mut self, annotation: Annotation) {
        self.annotations.push(annotation);
    }

    /// Returns true if this field is word-wrapped.
    pub fn is_word_wrapped(&self) -> bool {
        self.word_wrapped
    }

    /// Get the maximum number of lines.
    pub fn max_lines(&self) -> usize {
        self.max_lines
    }

    /// Get the number of text rows in this field.
    pub fn num_rows(&self) -> usize {
        if self.word_wrapped {
            // Estimate rows based on text length and width
            let chars_per_line = (self.width as usize / 8).max(1);
            let total_lines = (self.text.len() + chars_per_line - 1) / chars_per_line;
            total_lines.min(self.max_lines).max(1)
        } else {
            1
        }
    }

    /// Get the number of columns in a given row.
    pub fn num_cols(&self, row: usize) -> usize {
        if row == 0 || !self.word_wrapped {
            self.text.len()
        } else {
            0
        }
    }

    /// Get the row and column of a character position.
    pub fn row_col_for_position(&self, position: usize) -> (usize, usize) {
        if !self.word_wrapped {
            (0, position)
        } else {
            let chars_per_line = (self.width as usize / 8).max(1);
            let row = position / chars_per_line;
            let col = position % chars_per_line;
            (row.min(self.max_lines - 1), col)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_line_field() {
        let field = ListingTextField::new_single_line("Address", "0x00401000", 0, 100);
        assert_eq!(field.factory_name(), "Address");
        assert_eq!(field.text(), "0x00401000");
        assert!(!field.is_word_wrapped());
        assert_eq!(field.num_rows(), 1);
    }

    #[test]
    fn test_word_wrapped_field() {
        let field = ListingTextField::new_word_wrapped(
            "EOL Comment",
            "This is a very long comment that will be wrapped",
            0,
            80,
            3,
        );
        assert!(field.is_word_wrapped());
        assert_eq!(field.max_lines(), 3);
    }

    #[test]
    fn test_annotations() {
        let mut field = ListingTextField::new_single_line("Mnemonic", "mov", 0, 50);
        field.add_annotation(Annotation::highlight(0, 3, (255, 255, 0)));
        assert_eq!(field.annotations().len(), 1);
    }

    #[test]
    fn test_row_col() {
        let field = ListingTextField::new_single_line("Address", "0x00401000", 0, 100);
        let (row, col) = field.row_col_for_position(5);
        assert_eq!(row, 0);
        assert_eq!(col, 5);
    }
}
