//! `Annotation` -- an annotation within a listing field.
//!
//! Ported from `ghidra.app.util.viewer.field.Annotation`.

/// The type of annotation in a listing field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AnnotationType {
    /// A highlight (background color change).
    Highlight,
    /// A color change for text.
    ColorChange,
    /// A comment annotation.
    Comment,
    /// A label annotation.
    Label,
    /// A cross-reference annotation.
    Xref,
    /// A separator between field parts.
    Separator,
}

/// An annotation within a listing text field.
///
/// Annotations represent visual modifications to specific ranges of text
/// within a field, such as highlights, color changes, or structural markers.
///
/// Ported from `Annotation.java`.
#[derive(Debug, Clone)]
pub struct Annotation {
    /// The type of annotation.
    annotation_type: AnnotationType,
    /// The start position within the field text.
    start: usize,
    /// The end position within the field text.
    end: usize,
    /// The color as (R, G, B).
    color: Option<(u8, u8, u8)>,
    /// Optional text for display.
    text: Option<String>,
}

impl Annotation {
    /// Create a highlight annotation.
    pub fn highlight(start: usize, end: usize, color: (u8, u8, u8)) -> Self {
        Self {
            annotation_type: AnnotationType::Highlight,
            start,
            end,
            color: Some(color),
            text: None,
        }
    }

    /// Create a color change annotation.
    pub fn color_change(start: usize, end: usize, color: (u8, u8, u8)) -> Self {
        Self {
            annotation_type: AnnotationType::ColorChange,
            start,
            end,
            color: Some(color),
            text: None,
        }
    }

    /// Create a comment annotation.
    pub fn comment(start: usize, end: usize, text: &str) -> Self {
        Self {
            annotation_type: AnnotationType::Comment,
            start,
            end,
            color: None,
            text: Some(text.to_string()),
        }
    }

    /// Create a separator annotation.
    pub fn separator(position: usize) -> Self {
        Self {
            annotation_type: AnnotationType::Separator,
            start: position,
            end: position,
            color: None,
            text: None,
        }
    }

    /// Get the annotation type.
    pub fn annotation_type(&self) -> AnnotationType {
        self.annotation_type
    }

    /// Get the start position.
    pub fn start(&self) -> usize {
        self.start
    }

    /// Get the end position.
    pub fn end(&self) -> usize {
        self.end
    }

    /// Get the length of the annotated range.
    pub fn length(&self) -> usize {
        self.end.saturating_sub(self.start)
    }

    /// Get the color, if set.
    pub fn color(&self) -> Option<(u8, u8, u8)> {
        self.color
    }

    /// Get the text, if set.
    pub fn text(&self) -> Option<&str> {
        self.text.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_highlight_annotation() {
        let a = Annotation::highlight(0, 5, (255, 255, 0));
        assert_eq!(a.annotation_type(), AnnotationType::Highlight);
        assert_eq!(a.start(), 0);
        assert_eq!(a.end(), 5);
        assert_eq!(a.length(), 5);
        assert_eq!(a.color(), Some((255, 255, 0)));
    }

    #[test]
    fn test_comment_annotation() {
        let a = Annotation::comment(10, 20, "This is a comment");
        assert_eq!(a.annotation_type(), AnnotationType::Comment);
        assert_eq!(a.text(), Some("This is a comment"));
    }

    #[test]
    fn test_separator() {
        let a = Annotation::separator(42);
        assert_eq!(a.annotation_type(), AnnotationType::Separator);
        assert_eq!(a.start(), 42);
        assert_eq!(a.length(), 0);
    }
}
