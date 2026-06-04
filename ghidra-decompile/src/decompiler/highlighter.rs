//! Decompiler highlighter types.
//!
//! Port of Ghidra's `ghidra.app.decompiler.DecompilerHighlighter` and related.

/// The highlighter interface passed to clients of the DecompilerHighlightService.
///
/// The expected workflow is: create the highlighter, clients request highlights
/// via `apply_highlights()`, clients clear highlights via `clear_highlights()`,
/// and the highlighter may be removed via `dispose()`.
pub trait DecompilerHighlighter: std::fmt::Debug {
    /// Apply the highlights to the decompiler view.
    fn apply_highlights(&self);

    /// Clear all highlights from the decompiler view.
    fn clear_highlights(&self);

    /// Dispose of this highlighter, cleaning up resources.
    fn dispose(&self);
}

/// A token highlight matcher that matches tokens by name.
#[derive(Debug, Clone)]
pub struct CTokenHighlightMatcher {
    /// The token name to match.
    pub token_name: String,
    /// Whether the match is case-sensitive.
    pub case_sensitive: bool,
}

impl CTokenHighlightMatcher {
    /// Create a new CTokenHighlightMatcher.
    pub fn new(token_name: &str, case_sensitive: bool) -> Self {
        Self {
            token_name: token_name.to_string(),
            case_sensitive,
        }
    }

    /// Check if a token text matches.
    pub fn matches(&self, text: &str) -> bool {
        if self.case_sensitive {
            text == self.token_name
        } else {
            text.eq_ignore_ascii_case(&self.token_name)
        }
    }
}

/// Color provider for token highlights.
#[derive(Debug, Clone)]
pub struct TokenHighlightColors {
    /// Color for keyword tokens.
    pub keyword: String,
    /// Color for comment tokens.
    pub comment: String,
    /// Color for type tokens.
    pub type_color: String,
    /// Color for function tokens.
    pub function: String,
    /// Color for variable tokens.
    pub variable: String,
    /// Color for constant tokens.
    pub constant: String,
    /// Color for parameter tokens.
    pub parameter: String,
    /// Color for global tokens.
    pub global: String,
    /// Color for default tokens.
    pub default: String,
    /// Color for error tokens.
    pub error: String,
    /// Color for special tokens.
    pub special: String,
}

impl Default for TokenHighlightColors {
    fn default() -> Self {
        Self {
            keyword: "#0000ff".to_string(),
            comment: "#808080".to_string(),
            type_color: "#800080".to_string(),
            function: "#0000ff".to_string(),
            variable: "#000000".to_string(),
            constant: "#008000".to_string(),
            parameter: "#804000".to_string(),
            global: "#008080".to_string(),
            default: "#000000".to_string(),
            error: "#ff0000".to_string(),
            special: "#8000ff".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ctoken_highlight_matcher_case_sensitive() {
        let matcher = CTokenHighlightMatcher::new("main", true);
        assert!(matcher.matches("main"));
        assert!(!matcher.matches("Main"));
        assert!(!matcher.matches("MAIN"));
    }

    #[test]
    fn test_ctoken_highlight_matcher_case_insensitive() {
        let matcher = CTokenHighlightMatcher::new("main", false);
        assert!(matcher.matches("main"));
        assert!(matcher.matches("Main"));
        assert!(matcher.matches("MAIN"));
    }

    #[test]
    fn test_token_highlight_colors_default() {
        let colors = TokenHighlightColors::default();
        assert!(!colors.keyword.is_empty());
        assert!(!colors.comment.is_empty());
        assert!(!colors.error.is_empty());
    }
}
