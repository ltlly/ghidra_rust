//! DecompileOptions: configuration options for the decompiler.
//!
//! Port of Ghidra's `ghidra.app.decompiler.DecompileOptions`.

use std::collections::HashMap;

/// The default suggested size for cached decompile results.
pub const SUGGESTED_CACHED_RESULTS_SIZE: usize = 100;

/// How to display integer constants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IntegerFormat {
    /// Auto (default: hex for large values, decimal for small).
    Auto,
    /// Always hexadecimal.
    Hex,
    /// Always decimal.
    Decimal,
    /// Always octal.
    Octal,
    /// Always binary.
    Binary,
}

impl Default for IntegerFormat {
    fn default() -> Self {
        Self::Auto
    }
}

/// Comment style preference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CommentStyle {
    /// C-style block comments (/* ... */).
    CStyle,
    /// C++ style line comments (// ...).
    CppStyle,
}

impl Default for CommentStyle {
    fn default() -> Self {
        Self::CStyle
    }
}

/// Brace placement style.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BraceStyle {
    /// Same line as the control statement.
    SameLine,
    /// Next line (Allman style).
    NextLine,
}

impl Default for BraceStyle {
    fn default() -> Self {
        Self::SameLine
    }
}

/// NaN handling policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NanIgnore {
    /// Always ignore NaN operations.
    Always,
    /// Only ignore NaN when safe.
    Safe,
    /// Never ignore NaN operations.
    Never,
}

impl Default for NanIgnore {
    fn default() -> Self {
        Self::Always
    }
}

/// DecompileOptions holds all configuration options for the decompiler.
///
/// This corresponds to Ghidra's `DecompileOptions` class.  It is a flat
/// struct of options that control how the decompiler operates.
#[derive(Debug, Clone)]
pub struct DecompileOptions {
    // Analysis options
    /// Whether to follow predicate branches.
    pub predicate: bool,
    /// Whether to assume read-only for unspecified memory.
    pub read_only: bool,
    /// Whether to eliminate unreachable code.
    pub eliminate_unreachable: bool,
    /// Whether to simplify double-precision float operations.
    pub simplify_double_precision: bool,
    /// Whether to analyze for-loop patterns.
    pub analyze_for_loops: bool,
    /// Whether to split combined structure field copies.
    pub split_structures: bool,
    /// Whether to split combined array element copies.
    pub split_arrays: bool,
    /// Whether to split pointer copies to combined elements.
    pub split_pointers: bool,
    /// NaN handling policy.
    pub nan_mode: NanIgnore,

    // Display options
    /// Whether to display type casts.
    pub display_type_casts: bool,
    /// Maximum line width before wrapping.
    pub max_width: usize,
    /// Indentation width in spaces.
    pub indent_width: usize,
    /// Comment indentation multiplier.
    pub comment_indent: usize,
    /// Comment style.
    pub comment_style: CommentStyle,
    /// Show pre-comments (before the statement).
    pub comment_pre: bool,
    /// Show plate comments (function header/footer).
    pub comment_plate: bool,
    /// Show post-comments (after the statement).
    pub comment_post: bool,
    /// Show end-of-line comments.
    pub comment_eol: bool,
    /// Show warning comments.
    pub comment_warn: bool,
    /// Show header comments.
    pub comment_head: bool,
    /// Brace style for functions.
    pub brace_function: BraceStyle,
    /// Brace style for if/else.
    pub brace_if_else: BraceStyle,
    /// Brace style for loops.
    pub brace_loop: BraceStyle,
    /// Brace style for switch.
    pub brace_switch: BraceStyle,
    /// Whether to show namespace prefixes.
    pub namespace_display: bool,
    /// Integer format preference.
    pub integer_format: IntegerFormat,

    // Highlight options
    /// Current variable highlight color.
    pub highlight_current_variable: String,
    /// Keyword highlight color.
    pub highlight_keyword: String,
    /// Comment highlight color.
    pub highlight_comment: String,
    /// Variable highlight color.
    pub highlight_variable: String,
    /// Constant highlight color.
    pub highlight_const: String,
    /// Type highlight color.
    pub highlight_type: String,
    /// Parameter highlight color.
    pub highlight_parameter: String,
    /// Global highlight color.
    pub highlight_global: String,
    /// Special highlight color.
    pub highlight_special: String,
    /// Default highlight color.
    pub highlight_default: String,
    /// Search highlight color.
    pub highlight_search: String,
    /// Active search highlight color.
    pub highlight_search_active: String,
    /// Middle mouse button highlight color.
    pub highlight_middle_mouse: String,
    /// Background color.
    pub background_color: String,

    // Caching
    /// Size of the cached results cache.
    pub cached_results_size: usize,

    // Name transformer (stored as a string tag for portability)
    /// Name transformer type (e.g., "identity", "camel_to_snake").
    pub name_transformer: Option<String>,

    /// Extra property bag for tool/program-specific options.
    pub extra: HashMap<String, String>,
}

impl Default for DecompileOptions {
    fn default() -> Self {
        Self {
            predicate: false,
            read_only: true,
            eliminate_unreachable: true,
            simplify_double_precision: true,
            analyze_for_loops: true,
            split_structures: true,
            split_arrays: true,
            split_pointers: true,
            nan_mode: NanIgnore::default(),

            display_type_casts: true,
            max_width: 100,
            indent_width: 4,
            comment_indent: 1,
            comment_style: CommentStyle::default(),
            comment_pre: true,
            comment_plate: true,
            comment_post: true,
            comment_eol: true,
            comment_warn: true,
            comment_head: true,
            brace_function: BraceStyle::SameLine,
            brace_if_else: BraceStyle::SameLine,
            brace_loop: BraceStyle::SameLine,
            brace_switch: BraceStyle::SameLine,
            namespace_display: false,
            integer_format: IntegerFormat::default(),

            highlight_current_variable: "#ffff00".to_string(),
            highlight_keyword: "#ff0000".to_string(),
            highlight_comment: "#808080".to_string(),
            highlight_variable: "#0000ff".to_string(),
            highlight_const: "#00ff00".to_string(),
            highlight_type: "#ff00ff".to_string(),
            highlight_parameter: "#ff8000".to_string(),
            highlight_global: "#00ffff".to_string(),
            highlight_special: "#ff80ff".to_string(),
            highlight_default: "#000000".to_string(),
            highlight_search: "#00ffff".to_string(),
            highlight_search_active: "#ff0000".to_string(),
            highlight_middle_mouse: "#ffff00".to_string(),
            background_color: "#ffffff".to_string(),

            cached_results_size: SUGGESTED_CACHED_RESULTS_SIZE,
            name_transformer: None,
            extra: HashMap::new(),
        }
    }
}

impl DecompileOptions {
    /// Create a new DecompileOptions with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Serialize options to a JSON string for sending to the decompiler process.
    pub fn to_xml(&self) -> String {
        // In Ghidra this serializes to XML; here we use a simple XML-like format
        let mut xml = String::from("<options>");
        xml.push_str(&format!("<predicate>{}</predicate>", self.predicate));
        xml.push_str(&format!("<readonly>{}</readonly>", self.read_only));
        xml.push_str(&format!(
            "<eliminate_unreachable>{}</eliminate_unreachable>",
            self.eliminate_unreachable
        ));
        xml.push_str(&format!(
            "<simplify_double_precision>{}</simplify_double_precision>",
            self.simplify_double_precision
        ));
        xml.push_str(&format!(
            "<analyze_for_loops>{}</analyze_for_loops>",
            self.analyze_for_loops
        ));
        xml.push_str(&format!(
            "<split_structures>{}</split_structures>",
            self.split_structures
        ));
        xml.push_str(&format!(
            "<split_arrays>{}</split_arrays>",
            self.split_arrays
        ));
        xml.push_str(&format!(
            "<split_pointers>{}</split_pointers>",
            self.split_pointers
        ));
        xml.push_str(&format!(
            "<max_width>{}</max_width>",
            self.max_width
        ));
        xml.push_str(&format!(
            "<indent_width>{}</indent_width>",
            self.indent_width
        ));
        xml.push_str(&format!(
            "<display_type_casts>{}</display_type_casts>",
            self.display_type_casts
        ));
        xml.push_str("</options>");
        xml
    }

    /// Get a named extra option.
    pub fn get_extra(&self, key: &str) -> Option<&str> {
        self.extra.get(key).map(|s| s.as_str())
    }

    /// Set a named extra option.
    pub fn set_extra(&mut self, key: String, value: String) {
        self.extra.insert(key, value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_options() {
        let opts = DecompileOptions::default();
        assert!(opts.eliminate_unreachable);
        assert!(opts.split_structures);
        assert!(opts.display_type_casts);
        assert_eq!(opts.max_width, 100);
        assert_eq!(opts.indent_width, 4);
        assert!(opts.read_only);
    }

    #[test]
    fn test_to_xml() {
        let opts = DecompileOptions::default();
        let xml = opts.to_xml();
        assert!(xml.contains("<options>"));
        assert!(xml.contains("</options>"));
        assert!(xml.contains("<predicate>false</predicate>"));
        assert!(xml.contains("<max_width>100</max_width>"));
    }

    #[test]
    fn test_extra_options() {
        let mut opts = DecompileOptions::default();
        opts.set_extra("my_key".to_string(), "my_value".to_string());
        assert_eq!(opts.get_extra("my_key"), Some("my_value"));
        assert!(opts.get_extra("missing").is_none());
    }

    #[test]
    fn test_brace_style_default() {
        let opts = DecompileOptions::default();
        assert_eq!(opts.brace_function, BraceStyle::SameLine);
        assert_eq!(opts.brace_if_else, BraceStyle::SameLine);
    }

    #[test]
    fn test_comment_style_default() {
        let opts = DecompileOptions::default();
        assert_eq!(opts.comment_style, CommentStyle::CStyle);
        assert!(opts.comment_pre);
        assert!(opts.comment_eol);
    }
}
