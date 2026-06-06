//! Port of `HtmlLineSplitter`.
use std::collections::HashMap;
/// Struct porting `HtmlLineSplitter`.
#[derive(Debug, Clone)]
pub struct HtmlLineSplitter {
    /// max_word_length.
    pub max_word_length: i32,
}

impl HtmlLineSplitter {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for HtmlLineSplitter {
    fn default() -> Self {
        Self {
            max_word_length: 0,
}
    }
}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_html_line_splitter_new() { let _ = HtmlLineSplitter::new(); }
}
