//! Viewer utilities -- ported from `ghidra.app.util.viewer.util`.
//!
//! Utility functions and types for the listing viewer.

/// Computes the display width of a text string.
pub fn text_display_width(text: &str, char_width: f32) -> f32 {
    text.len() as f32 * char_width
}

/// Wraps text to fit within a given width.
pub fn wrap_text(text: &str, max_width: usize) -> Vec<String> {
    if text.len() <= max_width {
        return vec![text.to_string()];
    }

    let mut lines = Vec::new();
    let mut remaining = text;

    while remaining.len() > max_width {
        // Find the last space within the width limit
        let wrap_at = remaining[..max_width]
            .rfind(' ')
            .unwrap_or(max_width);
        lines.push(remaining[..wrap_at].to_string());
        remaining = remaining[wrap_at..].trim_start();
    }
    if !remaining.is_empty() {
        lines.push(remaining.to_string());
    }

    lines
}

/// Truncates text to a maximum length, adding ellipsis if needed.
pub fn truncate_with_ellipsis(text: &str, max_len: usize) -> String {
    if text.len() <= max_len {
        text.to_string()
    } else if max_len > 3 {
        format!("{}...", &text[..max_len - 3])
    } else {
        text[..max_len].to_string()
    }
}

/// Calculates the number of rows needed for a given text length and column width.
pub fn rows_needed(text_len: usize, cols_per_row: usize) -> usize {
    if cols_per_row == 0 {
        return 1;
    }
    ((text_len + cols_per_row - 1) / cols_per_row).max(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_text_display_width() {
        let w = text_display_width("Hello", 8.0);
        assert!((w - 40.0).abs() < 0.1);
    }

    #[test]
    fn test_wrap_text_short() {
        let lines = wrap_text("Hello", 80);
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0], "Hello");
    }

    #[test]
    fn test_wrap_text_long() {
        let lines = wrap_text("This is a very long text that needs wrapping", 15);
        assert!(lines.len() > 1);
    }

    #[test]
    fn test_truncate_short() {
        assert_eq!(truncate_with_ellipsis("Hello", 10), "Hello");
    }

    #[test]
    fn test_truncate_long() {
        assert_eq!(truncate_with_ellipsis("Hello World", 8), "Hello...");
    }

    #[test]
    fn test_truncate_tiny() {
        assert_eq!(truncate_with_ellipsis("Hello", 2), "He");
    }

    #[test]
    fn test_rows_needed() {
        assert_eq!(rows_needed(100, 40), 3);
        assert_eq!(rows_needed(40, 40), 1);
        assert_eq!(rows_needed(0, 40), 1);
    }
}
