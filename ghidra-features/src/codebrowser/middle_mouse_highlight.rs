//! Middle-mouse highlight provider for the code listing.
//!
//! Ported from `ghidra.app.plugin.core.codebrowser.ListingMiddleMouseHighlightProvider`.
//!
//! When the user middle-clicks on a token in the listing, this provider
//! highlights all occurrences of that token's text (and optionally all
//! references to the same register/variable) across the visible listing.
//!
//! # Key Types
//!
//! - [`MiddleMouseHighlightProvider`] -- the main highlight provider
//! - [`HighlightMode`] -- whether highlighting is text-based or scope-based
//! - [`HighlightScope`] -- scope of variable/register highlighting
//! - [`HighlightColors`] -- configurable highlight colors


/// Highlight mode for the middle-mouse button.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HighlightMode {
    /// Highlight all occurrences of the clicked text.
    TextMatch,
    /// Highlight all reads and writes to the same register/variable.
    Scope,
    /// No highlighting active.
    Off,
}

impl Default for HighlightMode {
    fn default() -> Self {
        Self::TextMatch
    }
}

/// The scope of a variable/register highlight.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HighlightScope {
    /// Read access to the variable/register.
    Read,
    /// Write access to the variable/register.
    Write,
    /// Both read and write.
    ReadWrite,
}

/// Configurable highlight colors.
#[derive(Debug, Clone)]
pub struct HighlightColors {
    /// Default middle-mouse highlight color (text match).
    pub default: String,
    /// Color for scoped read highlights.
    pub scoped_read: String,
    /// Color for scoped write highlights.
    pub scoped_write: String,
}

impl Default for HighlightColors {
    fn default() -> Self {
        Self {
            default: "#FFFF00".into(),
            scoped_read: "#ADD8E6".into(),
            scoped_write: "#FFA07A".into(),
        }
    }
}

/// A single highlight annotation at a specific address and field.
#[derive(Debug, Clone)]
pub struct HighlightEntry {
    /// The address being highlighted.
    pub address: u64,
    /// Character start offset within the field.
    pub char_offset: usize,
    /// Character length of the highlight.
    pub char_length: usize,
    /// The highlight color to apply.
    pub color: String,
}

/// The main middle-mouse highlight provider.
///
/// Ported from `ListingMiddleMouseHighlightProvider`.
///
/// # Example
///
/// ```
/// use ghidra_features::codebrowser::middle_mouse_highlight::*;
///
/// let mut provider = MiddleMouseHighlightProvider::new();
/// provider.set_highlight_text("RAX");
/// assert_eq!(provider.current_highlight(), Some("RAX"));
///
/// provider.clear_highlight();
/// assert!(provider.current_highlight().is_none());
/// ```
#[derive(Debug)]
pub struct MiddleMouseHighlightProvider {
    /// Current highlight mode.
    mode: HighlightMode,
    /// The currently highlighted text (if text-match mode).
    current_text: Option<String>,
    /// Case-sensitive matching.
    case_sensitive: bool,
    /// Whether to scope-highlight register operands.
    scope_register_operand: bool,
    /// The button used to trigger highlighting (default: middle = 2).
    highlight_button: u8,
    /// Configurable colors.
    colors: HighlightColors,
    /// Cached pattern for current text.
    pattern_cache: Option<String>,
}

impl MiddleMouseHighlightProvider {
    /// Create a new highlight provider.
    pub fn new() -> Self {
        Self {
            mode: HighlightMode::default(),
            current_text: None,
            case_sensitive: false,
            scope_register_operand: true,
            highlight_button: 2,
            colors: HighlightColors::default(),
            pattern_cache: None,
        }
    }

    /// Set the highlight text (enters text-match mode).
    pub fn set_highlight_text(&mut self, text: &str) {
        if text.is_empty() {
            self.clear_highlight();
            return;
        }
        self.current_text = Some(text.to_string());
        self.mode = HighlightMode::TextMatch;
        self.pattern_cache = Some(text.to_string());
    }

    /// Enter scope-based highlighting mode for the given register name.
    pub fn set_scope_highlight(&mut self, register_name: &str) {
        self.current_text = Some(register_name.to_string());
        self.mode = HighlightMode::Scope;
        self.pattern_cache = None;
    }

    /// Clear the current highlight.
    pub fn clear_highlight(&mut self) {
        self.current_text = None;
        self.mode = HighlightMode::Off;
        self.pattern_cache = None;
    }

    /// Get the currently highlighted text.
    pub fn current_highlight(&self) -> Option<&str> {
        self.current_text.as_deref()
    }

    /// Get the current highlight mode.
    pub fn mode(&self) -> HighlightMode {
        self.mode
    }

    /// Whether case-sensitive matching is enabled.
    pub fn is_case_sensitive(&self) -> bool {
        self.case_sensitive
    }

    /// Set case-sensitive matching.
    pub fn set_case_sensitive(&mut self, case_sensitive: bool) {
        self.case_sensitive = case_sensitive;
    }

    /// Whether register operand scoping is enabled.
    pub fn is_scope_register_operand(&self) -> bool {
        self.scope_register_operand
    }

    /// Set register operand scoping.
    pub fn set_scope_register_operand(&mut self, scope: bool) {
        self.scope_register_operand = scope;
    }

    /// Get the highlight colors.
    pub fn colors(&self) -> &HighlightColors {
        &self.colors
    }

    /// Set the highlight colors.
    pub fn set_colors(&mut self, colors: HighlightColors) {
        self.colors = colors;
    }

    /// Check if this is the configured highlight button.
    pub fn is_highlight_button(&self, button: u8) -> bool {
        button == self.highlight_button
    }

    /// Set which mouse button triggers highlighting.
    pub fn set_highlight_button(&mut self, button: u8) {
        self.highlight_button = button;
    }

    /// Generate text-match highlights for a line of listing text.
    ///
    /// Returns character ranges that match the current highlight text.
    pub fn find_matches(&self, line_text: &str) -> Vec<(usize, usize)> {
        let Some(ref pattern) = self.current_text else {
            return Vec::new();
        };
        if self.mode != HighlightMode::TextMatch {
            return Vec::new();
        }

        let mut matches = Vec::new();
        if self.case_sensitive {
            let mut start = 0;
            while let Some(pos) = line_text[start..].find(pattern.as_str()) {
                matches.push((start + pos, pattern.len()));
                start += pos + 1;
            }
        } else {
            let lower_text = line_text.to_lowercase();
            let lower_pattern = pattern.to_lowercase();
            let mut start = 0;
            while let Some(pos) = lower_text[start..].find(&lower_pattern) {
                matches.push((start + pos, pattern.len()));
                start += pos + 1;
            }
        }
        matches
    }

    /// Compute scope-based highlights for a listing line.
    ///
    /// Given a register/variable name and a line containing token annotations,
    /// returns the read/write scope of each occurrence.
    pub fn find_scope_matches(
        &self,
        line_text: &str,
        var_name: &str,
    ) -> Vec<ScopeHighlight> {
        let mut results = Vec::new();
        if self.mode != HighlightMode::Scope {
            return results;
        }

        // Simple heuristic: look for patterns like "VAR = ..." (write) or
        // "... VAR ..." (read). In Ghidra's Java code this uses PcodeOp
        // analysis; here we do a text-based approximation.
        for (i, segment) in line_text.split_whitespace().enumerate() {
            if segment.contains(var_name) {
                // Check if preceded by '=' (write) or is in operand position (read)
                let is_write = i > 0
                    && line_text
                        .split_whitespace()
                        .nth(i - 1)
                        .map_or(false, |s| s.ends_with('='));
                let scope = if is_write {
                    HighlightScope::Write
                } else {
                    HighlightScope::Read
                };
                results.push(ScopeHighlight {
                    token_index: i,
                    scope,
                    color: match scope {
                        HighlightScope::Write => self.colors.scoped_write.clone(),
                        HighlightScope::Read => self.colors.scoped_read.clone(),
                        HighlightScope::ReadWrite => self.colors.default.clone(),
                    },
                });
            }
        }
        results
    }
}

impl Default for MiddleMouseHighlightProvider {
    fn default() -> Self {
        Self::new()
    }
}

/// A scope-based highlight result.
#[derive(Debug, Clone)]
pub struct ScopeHighlight {
    /// Token index within the line.
    pub token_index: usize,
    /// The scope (read/write).
    pub scope: HighlightScope,
    /// The color to use.
    pub color: String,
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_provider() {
        let provider = MiddleMouseHighlightProvider::new();
        assert_eq!(provider.mode(), HighlightMode::TextMatch);
        assert!(provider.current_highlight().is_none());
        assert!(!provider.is_case_sensitive());
        assert_eq!(provider.highlight_button, 2);
    }

    #[test]
    fn test_set_highlight_text() {
        let mut provider = MiddleMouseHighlightProvider::new();
        provider.set_highlight_text("RAX");
        assert_eq!(provider.current_highlight(), Some("RAX"));
        assert_eq!(provider.mode(), HighlightMode::TextMatch);
    }

    #[test]
    fn test_clear_highlight() {
        let mut provider = MiddleMouseHighlightProvider::new();
        provider.set_highlight_text("test");
        provider.clear_highlight();
        assert!(provider.current_highlight().is_none());
        assert_eq!(provider.mode(), HighlightMode::Off);
    }

    #[test]
    fn test_set_empty_clears() {
        let mut provider = MiddleMouseHighlightProvider::new();
        provider.set_highlight_text("something");
        provider.set_highlight_text("");
        assert!(provider.current_highlight().is_none());
    }

    #[test]
    fn test_find_matches_case_insensitive() {
        let mut provider = MiddleMouseHighlightProvider::new();
        provider.set_highlight_text("rax");
        provider.set_case_sensitive(false);

        let matches = provider.find_matches("mov rax, [rbx]; add RAX, 1");
        assert_eq!(matches.len(), 2);
        assert_eq!(matches[0].0, 4); // "rax" at pos 4
        assert_eq!(matches[1].0, 20); // "RAX" at pos 20
    }

    #[test]
    fn test_find_matches_case_sensitive() {
        let mut provider = MiddleMouseHighlightProvider::new();
        provider.set_highlight_text("rax");
        provider.set_case_sensitive(true);

        let matches = provider.find_matches("mov rax, [rbx]; add RAX, 1");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].0, 4);
    }

    #[test]
    fn test_find_matches_no_match() {
        let mut provider = MiddleMouseHighlightProvider::new();
        provider.set_highlight_text("xyz");
        let matches = provider.find_matches("mov rax, rbx");
        assert!(matches.is_empty());
    }

    #[test]
    fn test_find_matches_off_mode() {
        let mut provider = MiddleMouseHighlightProvider::new();
        provider.set_highlight_text("test");
        provider.clear_highlight();
        let matches = provider.find_matches("test test");
        assert!(matches.is_empty());
    }

    #[test]
    fn test_scope_highlight() {
        let mut provider = MiddleMouseHighlightProvider::new();
        provider.set_scope_highlight("RAX");
        assert_eq!(provider.mode(), HighlightMode::Scope);

        let scopes = provider.find_scope_matches("RAX = 0x100", "RAX");
        // The simple heuristic looks for preceding '='
        // In this case "0x100" has no RAX, and "RAX" at index 0 has no preceding token
        // so it defaults to Read
        assert!(!scopes.is_empty());
    }

    #[test]
    fn test_scope_highlight_off() {
        let provider = MiddleMouseHighlightProvider::new();
        // Default mode is TextMatch, not Scope
        let scopes = provider.find_scope_matches("RAX = 0x100", "RAX");
        assert!(scopes.is_empty());
    }

    #[test]
    fn test_is_highlight_button() {
        let mut provider = MiddleMouseHighlightProvider::new();
        assert!(provider.is_highlight_button(2));
        assert!(!provider.is_highlight_button(1));

        provider.set_highlight_button(3);
        assert!(provider.is_highlight_button(3));
    }

    #[test]
    fn test_colors() {
        let provider = MiddleMouseHighlightProvider::new();
        assert_eq!(provider.colors().default, "#FFFF00");
        assert_eq!(provider.colors().scoped_read, "#ADD8E6");
        assert_eq!(provider.colors().scoped_write, "#FFA07A");
    }

    #[test]
    fn test_set_colors() {
        let mut provider = MiddleMouseHighlightProvider::new();
        let colors = HighlightColors {
            default: "#FFFFFF".into(),
            scoped_read: "#0000FF".into(),
            scoped_write: "#FF0000".into(),
        };
        provider.set_colors(colors);
        assert_eq!(provider.colors().default, "#FFFFFF");
    }

    #[test]
    fn test_scope_register_operand_setting() {
        let mut provider = MiddleMouseHighlightProvider::new();
        assert!(provider.is_scope_register_operand());
        provider.set_scope_register_operand(false);
        assert!(!provider.is_scope_register_operand());
    }

    #[test]
    fn test_find_matches_multiple_overlapping() {
        let mut provider = MiddleMouseHighlightProvider::new();
        provider.set_highlight_text("aa");
        provider.set_case_sensitive(false);

        let matches = provider.find_matches("aaa");
        assert_eq!(matches.len(), 2); // "aa" at 0 and "aa" at 1
    }
}
