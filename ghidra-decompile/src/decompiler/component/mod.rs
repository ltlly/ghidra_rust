//! Decompiler component types (UI-adjacent, but data structures only).
//!
//! Port of Ghidra's `ghidra.app.decompiler.component` package.
//!
//! These are data structures and interfaces used by the decompiler UI
//! component.  In the Rust port, we provide the data types and trait
//! definitions only (no Swing/AWT).

use super::clang_node::{ClangNodeId, SyntaxType};
use super::decompile_results::DecompileResults;

/// Data associated with a single decompile operation for the component.
#[derive(Debug, Clone)]
pub struct DecompileData {
    /// The function entry point.
    pub function_entry: u64,
    /// The function name.
    pub function_name: Option<String>,
    /// The decompile results (if available).
    pub results: Option<DecompileResults>,
    /// The address factory XML (for decode).
    pub address_factory_xml: Option<String>,
}

impl DecompileData {
    /// Create new empty DecompileData for the given function.
    pub fn new(function_entry: u64) -> Self {
        Self {
            function_entry,
            function_name: None,
            results: None,
            address_factory_xml: None,
        }
    }
}

/// An empty DecompileData (no function selected).
#[derive(Debug, Clone, Default)]
pub struct EmptyDecompileData;

impl EmptyDecompileData {
    /// Create a new EmptyDecompileData.
    pub fn new() -> DecompileData {
        DecompileData::new(0)
    }
}

/// A field element in the decompiler display (struct field with name and offset).
#[derive(Debug, Clone)]
pub struct ClangFieldElement {
    /// The field name.
    pub name: String,
    /// The data type name.
    pub datatype_name: Option<String>,
    /// The byte offset within the structure.
    pub offset: i32,
    /// The ClangNodeId in the AST.
    pub node_id: ClangNodeId,
}

impl ClangFieldElement {
    /// Create a new ClangFieldElement.
    pub fn new(name: String, node_id: ClangNodeId) -> Self {
        Self {
            name,
            datatype_name: None,
            offset: 0,
            node_id,
        }
    }
}

/// A token matcher for highlighting.
#[derive(Debug, Clone)]
pub struct NameTokenMatcher {
    /// The name to match.
    pub name: String,
    /// Whether to match case-sensitively.
    pub case_sensitive: bool,
    /// The syntax type to restrict matching to (None = all types).
    pub restrict_type: Option<SyntaxType>,
}

impl NameTokenMatcher {
    /// Create a new NameTokenMatcher.
    pub fn new(name: &str, case_sensitive: bool) -> Self {
        Self {
            name: name.to_string(),
            case_sensitive,
            restrict_type: None,
        }
    }

    /// Check if a token text matches.
    pub fn matches(&self, text: &str, syntax_type: Option<SyntaxType>) -> bool {
        if let Some(restrict) = self.restrict_type {
            if Some(restrict) != syntax_type {
                return false;
            }
        }
        if self.case_sensitive {
            text == self.name
        } else {
            text.eq_ignore_ascii_case(&self.name)
        }
    }
}

/// Key identifying a token for highlight tracking.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TokenKey {
    /// Token text.
    pub text: String,
    /// Token syntax type.
    pub syntax_type: i32,
}

impl TokenKey {
    /// Create a new TokenKey.
    pub fn new(text: String, syntax_type: i32) -> Self {
        Self { text, syntax_type }
    }
}

/// Listener for decompile results changes.
pub trait DecompileResultsListener: std::fmt::Debug {
    /// Called when decompile results are available.
    fn decompile_results_available(&self, results: &DecompileResults);

    /// Called when decompile results are cleared.
    fn decompile_results_cleared(&self);
}

/// Highlight token information.
#[derive(Debug, Clone)]
pub struct HighlightToken {
    /// The ClangNodeId of the token.
    pub node_id: ClangNodeId,
    /// The highlight color.
    pub color: String,
    /// Whether this is a primary or secondary highlight.
    pub is_primary: bool,
}

impl HighlightToken {
    /// Create a new HighlightToken.
    pub fn new(node_id: ClangNodeId, color: String, is_primary: bool) -> Self {
        Self {
            node_id,
            color,
            is_primary,
        }
    }
}

/// Token highlights container.
#[derive(Debug, Clone, Default)]
pub struct TokenHighlights {
    /// Primary highlights (current selection).
    pub primary: Vec<HighlightToken>,
    /// Secondary highlights (additional markers).
    pub secondary: Vec<HighlightToken>,
}

impl TokenHighlights {
    /// Create a new empty TokenHighlights.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a primary highlight.
    pub fn add_primary(&mut self, token: HighlightToken) {
        self.primary.push(token);
    }

    /// Add a secondary highlight.
    pub fn add_secondary(&mut self, token: HighlightToken) {
        self.secondary.push(token);
    }

    /// Clear all highlights.
    pub fn clear(&mut self) {
        self.primary.clear();
        self.secondary.clear();
    }

    /// Whether there are any highlights.
    pub fn is_empty(&self) -> bool {
        self.primary.is_empty() && self.secondary.is_empty()
    }
}

/// User-defined highlights.
#[derive(Debug, Clone, Default)]
pub struct UserHighlights {
    /// Per-text highlight colors.
    pub highlights: std::collections::HashMap<String, String>,
}

impl UserHighlights {
    /// Create a new empty UserHighlights.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set a highlight color for the given text.
    pub fn set_highlight(&mut self, text: String, color: String) {
        self.highlights.insert(text, color);
    }

    /// Get the highlight color for the given text.
    pub fn get_highlight(&self, text: &str) -> Option<&str> {
        self.highlights.get(text).map(|s| s.as_str())
    }

    /// Remove a highlight.
    pub fn remove_highlight(&mut self, text: &str) {
        self.highlights.remove(text);
    }

    /// Clear all highlights.
    pub fn clear(&mut self) {
        self.highlights.clear();
    }
}

/// Color provider interface.
pub trait ColorProvider: std::fmt::Debug {
    /// Get the background color.
    fn background_color(&self) -> &str;

    /// Get the color for the given syntax type.
    fn color_for_type(&self, syntax_type: SyntaxType) -> &str;
}

/// Default color provider.
#[derive(Debug, Clone)]
pub struct DefaultColorProvider;

impl ColorProvider for DefaultColorProvider {
    fn background_color(&self) -> &str {
        "#ffffff"
    }

    fn color_for_type(&self, syntax_type: SyntaxType) -> &str {
        match syntax_type {
            SyntaxType::Keyword => "#0000ff",
            SyntaxType::Comment => "#808080",
            SyntaxType::Type => "#800080",
            SyntaxType::Function => "#0000ff",
            SyntaxType::Variable => "#000000",
            SyntaxType::Const => "#008000",
            SyntaxType::Parameter => "#804000",
            SyntaxType::Global => "#008080",
            SyntaxType::Default => "#000000",
            SyntaxType::Error => "#ff0000",
            SyntaxType::Special => "#8000ff",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decompile_data() {
        let data = DecompileData::new(0x1000);
        assert_eq!(data.function_entry, 0x1000);
        assert!(data.results.is_none());
    }

    #[test]
    fn test_empty_decompile_data() {
        let data = EmptyDecompileData::new();
        assert_eq!(data.function_entry, 0);
    }

    #[test]
    fn test_clang_field_element() {
        let elem = ClangFieldElement::new("x".to_string(), 0);
        assert_eq!(elem.name, "x");
        assert_eq!(elem.node_id, 0);
    }

    #[test]
    fn test_name_token_matcher() {
        let matcher = NameTokenMatcher::new("main", true);
        assert!(matcher.matches("main", None));
        assert!(!matcher.matches("Main", None));
    }

    #[test]
    fn test_token_key() {
        let key = TokenKey::new("int".to_string(), 0);
        assert_eq!(key.text, "int");
        assert_eq!(key.syntax_type, 0);
    }

    #[test]
    fn test_token_highlights() {
        let mut th = TokenHighlights::new();
        assert!(th.is_empty());
        th.add_primary(HighlightToken::new(0, "#ff0000".to_string(), true));
        assert!(!th.is_empty());
        th.clear();
        assert!(th.is_empty());
    }

    #[test]
    fn test_user_highlights() {
        let mut uh = UserHighlights::new();
        uh.set_highlight("main".to_string(), "#ff0000".to_string());
        assert_eq!(uh.get_highlight("main"), Some("#ff0000"));
        assert!(uh.get_highlight("other").is_none());
        uh.remove_highlight("main");
        assert!(uh.get_highlight("main").is_none());
    }

    #[test]
    fn test_default_color_provider() {
        let provider = DefaultColorProvider;
        assert_eq!(provider.background_color(), "#ffffff");
        assert_eq!(provider.color_for_type(SyntaxType::Keyword), "#0000ff");
        assert_eq!(provider.color_for_type(SyntaxType::Error), "#ff0000");
    }
}
