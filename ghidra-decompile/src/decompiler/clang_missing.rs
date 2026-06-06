//! Missing decompiler types ported from Ghidra's Java Decompiler feature.
//!
//! Ports the following Java classes:
//! - `ghidra.app.decompiler.ClangNode`
//! - `ghidra.app.decompiler.ClangToken`
//! - `ghidra.app.decompiler.ClangBreak`
//! - `ghidra.app.decompiler.ClangMarkup`
//! - Decompiler action types (slice actions, convert actions)
//! - Hover plugin types
//! - Utility types

use std::fmt;

// ============================================================================
// ClangNode - the tree node interface for decompiler output
// ============================================================================

/// A node in the decompiler's Clang syntax tree.
///
/// Ported from `ghidra.app.decompiler.ClangNode`.
pub trait ClangNode {
    /// Get the parent node.
    fn parent(&self) -> Option<&dyn ClangNode>;

    /// Get the minimum program address associated with this node.
    fn min_address(&self) -> Option<u64>;

    /// Get the maximum program address associated with this node.
    fn max_address(&self) -> Option<u64>;

    /// Get the number of child nodes.
    fn num_children(&self) -> usize;

    /// Get the i-th child node.
    fn child(&self, i: usize) -> Option<&dyn ClangNode>;

    /// Flatten this node into a list of tokens.
    fn flatten(&self) -> Vec<&dyn ClangTokenNode>;
}

/// Trait for accessing ClangToken-specific properties on nodes.
pub trait ClangTokenNode: ClangNode {
    /// Get the text of this token.
    fn text(&self) -> &str;

    /// Get the syntax type (color category) of this token.
    fn syntax_type(&self) -> i32;

    /// Whether this is a matching token (e.g., matching braces).
    fn is_matching(&self) -> bool;
}

// ============================================================================
// ClangToken - source code language token
// ============================================================================

/// Color constants for decompiler syntax highlighting.
pub mod syntax_color {
    /// Keyword color.
    pub const KEYWORD: i32 = 0;
    /// Comment color.
    pub const COMMENT: i32 = 1;
    /// Type color.
    pub const TYPE: i32 = 2;
    /// Function name color.
    pub const FUNCTION: i32 = 3;
    /// Variable color.
    pub const VARIABLE: i32 = 4;
    /// Constant color.
    pub const CONSTANT: i32 = 5;
    /// Parameter color.
    pub const PARAMETER: i32 = 6;
    /// Global variable color.
    pub const GLOBAL: i32 = 7;
    /// Default color.
    pub const DEFAULT: i32 = 8;
    /// Error color.
    pub const ERROR: i32 = 9;
    /// Special color.
    pub const SPECIAL: i32 = 10;
    /// Maximum color index.
    pub const MAX: i32 = 11;
}

/// A token in the decompiler's C output.
///
/// Ported from `ghidra.app.decompiler.ClangToken`.
#[derive(Debug, Clone)]
pub struct ClangToken {
    /// The text of the token.
    pub text: String,
    /// The syntax type (color category).
    pub syntax_type: i32,
    /// Whether this token is a matching token (e.g., for brace matching).
    pub matching: bool,
    /// The varnode ID this token represents (if any).
    pub varnode_id: Option<i64>,
    /// The high variable ID (if any).
    pub high_var_id: Option<i64>,
    /// The address this token corresponds to (if any).
    pub address: Option<u64>,
}

impl ClangToken {
    /// Create a new ClangToken with default syntax type.
    pub fn new(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            syntax_type: syntax_color::DEFAULT,
            matching: false,
            varnode_id: None,
            high_var_id: None,
            address: None,
        }
    }

    /// Create a new ClangToken with a specific syntax type.
    pub fn with_syntax(text: impl Into<String>, syntax_type: i32) -> Self {
        Self {
            text: text.into(),
            syntax_type,
            matching: false,
            varnode_id: None,
            high_var_id: None,
            address: None,
        }
    }

    /// Create a keyword token.
    pub fn keyword(text: impl Into<String>) -> Self {
        Self::with_syntax(text, syntax_color::KEYWORD)
    }

    /// Create a variable token.
    pub fn variable(text: impl Into<String>) -> Self {
        Self::with_syntax(text, syntax_color::VARIABLE)
    }

    /// Create a type token.
    pub fn type_token(text: impl Into<String>) -> Self {
        Self::with_syntax(text, syntax_color::TYPE)
    }

    /// Create a function name token.
    pub fn function(text: impl Into<String>) -> Self {
        Self::with_syntax(text, syntax_color::FUNCTION)
    }

    /// Create a constant token.
    pub fn constant(text: impl Into<String>) -> Self {
        Self::with_syntax(text, syntax_color::CONSTANT)
    }

    /// Create a comment token.
    pub fn comment(text: impl Into<String>) -> Self {
        Self::with_syntax(text, syntax_color::COMMENT)
    }

    /// Create an error token.
    pub fn error(text: impl Into<String>) -> Self {
        Self::with_syntax(text, syntax_color::ERROR)
    }

    /// Set the varnode ID.
    pub fn with_varnode_id(mut self, id: i64) -> Self {
        self.varnode_id = Some(id);
        self
    }

    /// Set the address.
    pub fn with_address(mut self, addr: u64) -> Self {
        self.address = Some(addr);
        self
    }

    /// Get the text.
    pub fn get_text(&self) -> &str {
        &self.text
    }

    /// Get the syntax type.
    pub fn get_syntax_type(&self) -> i32 {
        self.syntax_type
    }

    /// Returns true if this token has a matching counterpart.
    pub fn is_matching(&self) -> bool {
        self.matching
    }

    /// Set the matching state.
    pub fn set_matching(&mut self, matching: bool) {
        self.matching = matching;
    }

    /// Returns true if this token has an associated varnode.
    pub fn has_varnode(&self) -> bool {
        self.varnode_id.is_some()
    }

    /// Get the color name for this token's syntax type.
    pub fn color_name(&self) -> &'static str {
        match self.syntax_type {
            syntax_color::KEYWORD => "keyword",
            syntax_color::COMMENT => "comment",
            syntax_color::TYPE => "type",
            syntax_color::FUNCTION => "function",
            syntax_color::VARIABLE => "variable",
            syntax_color::CONSTANT => "constant",
            syntax_color::PARAMETER => "parameter",
            syntax_color::GLOBAL => "global",
            syntax_color::DEFAULT => "default",
            syntax_color::ERROR => "error",
            syntax_color::SPECIAL => "special",
            _ => "unknown",
        }
    }
}

impl fmt::Display for ClangToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.text)
    }
}

impl PartialEq for ClangToken {
    fn eq(&self, other: &Self) -> bool {
        self.text == other.text && self.syntax_type == other.syntax_type
    }
}
impl Eq for ClangToken {}

// ============================================================================
// ClangBreak - a line break in the decompiler output
// ============================================================================

/// A line break element in the Clang syntax tree.
///
/// Ported from `ghidra.app.decompiler.ClangBreak`.
#[derive(Debug, Clone)]
pub struct ClangBreak {
    /// Whether this break is an indent-increase break.
    pub indent_increase: bool,
    /// Whether this break is an indent-decrease break.
    pub indent_decrease: bool,
    /// Whether this break forces a newline.
    pub force_newline: bool,
    /// The number of blank lines to emit.
    pub blank_lines: usize,
}

impl ClangBreak {
    /// Create a simple line break.
    pub fn newline() -> Self {
        Self {
            indent_increase: false,
            indent_decrease: false,
            force_newline: true,
            blank_lines: 0,
        }
    }

    /// Create an indent-increase break.
    pub fn indent_in() -> Self {
        Self {
            indent_increase: true,
            indent_decrease: false,
            force_newline: true,
            blank_lines: 0,
        }
    }

    /// Create an indent-decrease break.
    pub fn indent_out() -> Self {
        Self {
            indent_increase: false,
            indent_decrease: true,
            force_newline: true,
            blank_lines: 0,
        }
    }

    /// Create a blank-line break.
    pub fn blank_line(count: usize) -> Self {
        Self {
            indent_increase: false,
            indent_decrease: false,
            force_newline: true,
            blank_lines: count,
        }
    }
}

// ============================================================================
// ClangMarkup - a marked-up section of code
// ============================================================================

/// A marked-up section of code containing tokens.
///
/// Ported from `ghidra.app.decompiler.ClangMarkup`.
#[derive(Debug, Clone)]
pub struct ClangMarkup {
    /// The tokens in this markup.
    pub tokens: Vec<ClangToken>,
    /// The address range covered by this markup.
    pub address_range: Option<(u64, u64)>,
    /// The parent function name.
    pub function_name: Option<String>,
}

impl ClangMarkup {
    /// Create a new empty markup.
    pub fn new() -> Self {
        Self {
            tokens: Vec::new(),
            address_range: None,
            function_name: None,
        }
    }

    /// Add a token to this markup.
    pub fn add_token(&mut self, token: ClangToken) {
        self.tokens.push(token);
    }

    /// Get all tokens.
    pub fn tokens(&self) -> &[ClangToken] {
        &self.tokens
    }

    /// Get the full text of all tokens concatenated.
    pub fn full_text(&self) -> String {
        self.tokens
            .iter()
            .map(|t| t.text.as_str())
            .collect::<Vec<_>>()
            .join("")
    }
}

impl Default for ClangMarkup {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Decompiler Actions - Slice, Convert, etc.
// ============================================================================

/// Backwards slice action - slices backwards from the current token.
///
/// Ported from `ghidra.app.plugin.core.decompile.actions.BackwardsSliceAction`.
#[derive(Debug, Clone)]
pub struct BackwardsSliceAction {
    /// Action name.
    pub name: String,
    /// Whether to include all definitions in the slice.
    pub include_all_defs: bool,
}

impl BackwardsSliceAction {
    /// Create a new backwards slice action.
    pub fn new() -> Self {
        Self {
            name: "Backwards Slice".to_string(),
            include_all_defs: false,
        }
    }
}

impl Default for BackwardsSliceAction {
    fn default() -> Self {
        Self::new()
    }
}

/// Backwards slice to P-code operations action.
///
/// Ported from `ghidra.app.plugin.core.decompile.actions.BackwardsSliceToPCodeOpsAction`.
#[derive(Debug, Clone)]
pub struct BackwardsSliceToPCodeOpsAction {
    /// Action name.
    pub name: String,
    /// Whether to include P-code address info.
    pub include_addresses: bool,
}

impl BackwardsSliceToPCodeOpsAction {
    /// Create a new action.
    pub fn new() -> Self {
        Self {
            name: "Backwards Slice to PCode Ops".to_string(),
            include_addresses: true,
        }
    }
}

impl Default for BackwardsSliceToPCodeOpsAction {
    fn default() -> Self {
        Self::new()
    }
}

/// Forward slice action.
///
/// Ported from `ghidra.app.plugin.core.decompile.actions.ForwardSliceAction`.
#[derive(Debug, Clone)]
pub struct ForwardSliceAction {
    /// Action name.
    pub name: String,
    /// Whether to follow all uses.
    pub follow_all_uses: bool,
}

impl ForwardSliceAction {
    /// Create a new forward slice action.
    pub fn new() -> Self {
        Self {
            name: "Forward Slice".to_string(),
            follow_all_uses: false,
        }
    }
}

impl Default for ForwardSliceAction {
    fn default() -> Self {
        Self::new()
    }
}

/// Forward slice to P-code operations action.
///
/// Ported from `ghidra.app.plugin.core.decompile.actions.ForwardSliceToPCodeOpsAction`.
#[derive(Debug, Clone)]
pub struct ForwardSliceToPCodeOpsAction {
    /// Action name.
    pub name: String,
    /// Whether to include addresses.
    pub include_addresses: bool,
}

impl ForwardSliceToPCodeOpsAction {
    /// Create a new action.
    pub fn new() -> Self {
        Self {
            name: "Forward Slice to PCode Ops".to_string(),
            include_addresses: true,
        }
    }
}

impl Default for ForwardSliceToPCodeOpsAction {
    fn default() -> Self {
        Self::new()
    }
}

/// Convert constant display format actions.
///
/// Ported from `ghidra.app.plugin.core.decompile.actions.Convert*Action`.

/// Convert a constant to binary display.
#[derive(Debug, Clone)]
pub struct ConvertBinaryAction {
    /// Action name.
    pub name: String,
}

impl ConvertBinaryAction {
    /// Create a new action.
    pub fn new() -> Self {
        Self { name: "Convert to Binary".to_string() }
    }
}

impl Default for ConvertBinaryAction {
    fn default() -> Self { Self::new() }
}

/// Convert a constant to character display.
#[derive(Debug, Clone)]
pub struct ConvertCharAction {
    /// Action name.
    pub name: String,
}

impl ConvertCharAction {
    /// Create a new action.
    pub fn new() -> Self {
        Self { name: "Convert to Char".to_string() }
    }
}

impl Default for ConvertCharAction {
    fn default() -> Self { Self::new() }
}

/// Convert a constant to decimal display.
#[derive(Debug, Clone)]
pub struct ConvertDecAction {
    /// Action name.
    pub name: String,
}

impl ConvertDecAction {
    /// Create a new action.
    pub fn new() -> Self {
        Self { name: "Convert to Decimal".to_string() }
    }
}

impl Default for ConvertDecAction {
    fn default() -> Self { Self::new() }
}

/// Convert a constant to double (floating point) display.
#[derive(Debug, Clone)]
pub struct ConvertDoubleAction {
    /// Action name.
    pub name: String,
}

impl ConvertDoubleAction {
    /// Create a new action.
    pub fn new() -> Self {
        Self { name: "Convert to Double".to_string() }
    }
}

impl Default for ConvertDoubleAction {
    fn default() -> Self { Self::new() }
}

/// Convert a constant to float display.
#[derive(Debug, Clone)]
pub struct ConvertFloatAction {
    /// Action name.
    pub name: String,
}

impl ConvertFloatAction {
    /// Create a new action.
    pub fn new() -> Self {
        Self { name: "Convert to Float".to_string() }
    }
}

impl Default for ConvertFloatAction {
    fn default() -> Self { Self::new() }
}

/// Convert a constant to hex display.
#[derive(Debug, Clone)]
pub struct ConvertHexAction {
    /// Action name.
    pub name: String,
}

impl ConvertHexAction {
    /// Create a new action.
    pub fn new() -> Self {
        Self { name: "Convert to Hex".to_string() }
    }
}

impl Default for ConvertHexAction {
    fn default() -> Self { Self::new() }
}

/// Convert a constant to octal display.
#[derive(Debug, Clone)]
pub struct ConvertOctAction {
    /// Action name.
    pub name: String,
}

impl ConvertOctAction {
    /// Create a new action.
    pub fn new() -> Self {
        Self { name: "Convert to Octal".to_string() }
    }
}

impl Default for ConvertOctAction {
    fn default() -> Self { Self::new() }
}

/// Convert a constant using an equate (named constant).
///
/// Ported from `ghidra.app.plugin.core.decompile.actions.ConvertConstantEquateTask`.
#[derive(Debug, Clone)]
pub struct ConvertConstantEquateTask {
    /// The equate name.
    pub equate_name: String,
    /// The constant value.
    pub value: i64,
    /// The address of the constant.
    pub address: u64,
}

impl ConvertConstantEquateTask {
    /// Create a new equate conversion task.
    pub fn new(equate: impl Into<String>, value: i64, address: u64) -> Self {
        Self {
            equate_name: equate.into(),
            value,
            address,
        }
    }
}

// ============================================================================
// Hover Plugin Types
// ============================================================================

/// Data type decompiler hover plugin.
///
/// Ported from `ghidra.app.decompiler.component.hover.DataTypeDecompilerHoverPlugin`.
#[derive(Debug, Clone)]
pub struct DataTypeDecompilerHoverPlugin {
    /// Plugin name.
    pub name: String,
    /// Whether the plugin is enabled.
    pub enabled: bool,
    /// Hover delay in milliseconds.
    pub hover_delay_ms: u64,
}

impl DataTypeDecompilerHoverPlugin {
    /// Create a new plugin.
    pub fn new() -> Self {
        Self {
            name: "DataType Decompiler Hover".to_string(),
            enabled: true,
            hover_delay_ms: 300,
        }
    }
}

impl Default for DataTypeDecompilerHoverPlugin {
    fn default() -> Self { Self::new() }
}

/// Function signature decompiler hover plugin.
///
/// Ported from `ghidra.app.decompiler.component.hover.FunctionSignatureDecompilerHoverPlugin`.
#[derive(Debug, Clone)]
pub struct FunctionSignatureDecompilerHoverPlugin {
    /// Plugin name.
    pub name: String,
    /// Whether the plugin is enabled.
    pub enabled: bool,
    /// Hover delay in milliseconds.
    pub hover_delay_ms: u64,
}

impl FunctionSignatureDecompilerHoverPlugin {
    /// Create a new plugin.
    pub fn new() -> Self {
        Self {
            name: "FunctionSignature Decompiler Hover".to_string(),
            enabled: true,
            hover_delay_ms: 300,
        }
    }
}

impl Default for FunctionSignatureDecompilerHoverPlugin {
    fn default() -> Self { Self::new() }
}

/// Reference decompiler hover plugin.
///
/// Ported from `ghidra.app.decompiler.component.hover.ReferenceDecompilerHoverPlugin`.
#[derive(Debug, Clone)]
pub struct ReferenceDecompilerHoverPlugin {
    /// Plugin name.
    pub name: String,
    /// Whether the plugin is enabled.
    pub enabled: bool,
    /// Hover delay in milliseconds.
    pub hover_delay_ms: u64,
}

impl ReferenceDecompilerHoverPlugin {
    /// Create a new plugin.
    pub fn new() -> Self {
        Self {
            name: "Reference Decompiler Hover".to_string(),
            enabled: true,
            hover_delay_ms: 300,
        }
    }
}

impl Default for ReferenceDecompilerHoverPlugin {
    fn default() -> Self { Self::new() }
}

/// Scalar value decompiler hover plugin.
///
/// Ported from `ghidra.app.decompiler.component.hover.ScalarValueDecompilerHoverPlugin`.
#[derive(Debug, Clone)]
pub struct ScalarValueDecompilerHoverPlugin {
    /// Plugin name.
    pub name: String,
    /// Whether the plugin is enabled.
    pub enabled: bool,
    /// Hover delay in milliseconds.
    pub hover_delay_ms: u64,
}

impl ScalarValueDecompilerHoverPlugin {
    /// Create a new plugin.
    pub fn new() -> Self {
        Self {
            name: "ScalarValue Decompiler Hover".to_string(),
            enabled: true,
            hover_delay_ms: 300,
        }
    }
}

impl Default for ScalarValueDecompilerHoverPlugin {
    fn default() -> Self { Self::new() }
}

// ============================================================================
// NullClangHighlightController
// ============================================================================

/// A no-op highlight controller that does nothing.
///
/// Ported from `ghidra.app.decompiler.component.NullClangHighlightController`.
#[derive(Debug, Clone)]
pub struct NullClangHighlightController;

impl NullClangHighlightController {
    /// Create a new null controller.
    pub fn new() -> Self {
        Self
    }
}

impl Default for NullClangHighlightController {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// LineNumberDecompilerMarginProvider
// ============================================================================

/// Provides line number margins in the decompiler view.
///
/// Ported from `ghidra.app.decompiler.component.margin.LineNumberDecompilerMarginProvider`.
#[derive(Debug, Clone)]
pub struct LineNumberDecompilerMarginProvider {
    /// Whether line numbers are visible.
    pub visible: bool,
    /// Width of the margin in pixels.
    pub margin_width: u32,
}

impl LineNumberDecompilerMarginProvider {
    /// Create a new line number margin provider.
    pub fn new() -> Self {
        Self {
            visible: true,
            margin_width: 40,
        }
    }
}

impl Default for LineNumberDecompilerMarginProvider {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// RenameUnionFieldTask
// ============================================================================

/// Task for renaming a field in a union data type.
///
/// Ported from `ghidra.app.plugin.core.decompile.actions.RenameUnionFieldTask`.
#[derive(Debug, Clone)]
pub struct RenameUnionFieldTask {
    /// The union type name.
    pub union_name: String,
    /// The old field name.
    pub old_name: String,
    /// The new field name.
    pub new_name: String,
}

impl RenameUnionFieldTask {
    /// Create a new rename task.
    pub fn new(union: impl Into<String>, old: impl Into<String>, new: impl Into<String>) -> Self {
        Self {
            union_name: union.into(),
            old_name: old.into(),
            new_name: new.into(),
        }
    }
}

// ============================================================================
// FillOutStructureCmd
// ============================================================================

/// Command to fill out a structure type with fields discovered by the decompiler.
///
/// Ported from `ghidra.app.decompiler.util.FillOutStructureCmd`.
#[derive(Debug, Clone)]
pub struct FillOutStructureCmd {
    /// The structure type name.
    pub structure_name: String,
    /// The decompiler-suggested fields.
    pub suggested_fields: Vec<SuggestedField>,
    /// Whether to overwrite existing fields.
    pub overwrite_existing: bool,
}

/// A field suggested by the decompiler.
#[derive(Debug, Clone)]
pub struct SuggestedField {
    /// Field name.
    pub name: String,
    /// Field offset.
    pub offset: i64,
    /// Field size.
    pub size: usize,
    /// Field data type name.
    pub data_type: String,
}

impl FillOutStructureCmd {
    /// Create a new fill-out command.
    pub fn new(structure: impl Into<String>) -> Self {
        Self {
            structure_name: structure.into(),
            suggested_fields: Vec::new(),
            overwrite_existing: false,
        }
    }

    /// Add a suggested field.
    pub fn add_field(&mut self, field: SuggestedField) {
        self.suggested_fields.push(field);
    }
}

// ============================================================================
// DecompileCallback
// ============================================================================

/// Callback interface for the decompiler engine.
///
/// Ported from `ghidra.app.decompiler.DecompileCallback`.
#[derive(Debug, Clone)]
pub struct DecompileCallback {
    /// Callback name.
    pub name: String,
    /// Whether the callback is registered.
    pub registered: bool,
}

impl DecompileCallback {
    /// Create a new decompile callback.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            registered: false,
        }
    }

    /// Register the callback.
    pub fn register(&mut self) {
        self.registered = true;
    }

    /// Unregister the callback.
    pub fn unregister(&mut self) {
        self.registered = false;
    }
}

// ============================================================================
// Decompiler (main decompiler component)
// ============================================================================

/// Main decompiler component that manages the decompilation view.
///
/// Ported from `ghidra.app.decompiler.component.Decompiler`.
#[derive(Debug, Clone)]
pub struct DecompilerComponent {
    /// Whether decompilation is in progress.
    pub decompiling: bool,
    /// Current function address being decompiled.
    pub current_address: Option<u64>,
    /// Last decompile error (if any).
    pub last_error: Option<String>,
    /// Display options.
    pub options: DecompilerDisplayOptions,
}

/// Display options for the decompiler view.
#[derive(Debug, Clone)]
pub struct DecompilerDisplayOptions {
    /// Show C type casts.
    pub show_type_casts: bool,
    /// Show line numbers.
    pub show_line_numbers: bool,
    /// Show addresses.
    pub show_addresses: bool,
    /// Maximum line width.
    pub max_line_width: usize,
    /// Highlight color for current selection.
    pub highlight_color: (u8, u8, u8, u8),
}

impl Default for DecompilerDisplayOptions {
    fn default() -> Self {
        Self {
            show_type_casts: true,
            show_line_numbers: true,
            show_addresses: false,
            max_line_width: 120,
            highlight_color: (200, 200, 100, 128),
        }
    }
}

impl DecompilerComponent {
    /// Create a new decompiler component.
    pub fn new() -> Self {
        Self {
            decompiling: false,
            current_address: None,
            last_error: None,
            options: DecompilerDisplayOptions::default(),
        }
    }
}

impl Default for DecompilerComponent {
    fn default() -> Self {
        Self::new()
    }
}

/// Decompiler panel for rendering the decompiled code.
///
/// Ported from `ghidra.app.decompiler.component.DecompilerPanel`.
#[derive(Debug, Clone)]
pub struct DecompilerPanel {
    /// Lines of decompiled text.
    pub lines: Vec<String>,
    /// Whether the panel has been laid out.
    pub laid_out: bool,
    /// Current scroll position.
    pub scroll_y: f64,
}

impl DecompilerPanel {
    /// Create a new panel.
    pub fn new() -> Self {
        Self {
            lines: Vec::new(),
            laid_out: false,
            scroll_y: 0.0,
        }
    }

    /// Set the decompiled text.
    pub fn set_text(&mut self, text: &str) {
        self.lines = text.lines().map(|s| s.to_string()).collect();
    }

    /// Get the number of lines.
    pub fn line_count(&self) -> usize {
        self.lines.len()
    }
}

impl Default for DecompilerPanel {
    fn default() -> Self {
        Self::new()
    }
}

/// Decompiler utilities.
///
/// Ported from `ghidra.app.decompiler.component.DecompilerUtils`.
pub struct DecompilerUtils;

impl DecompilerUtils {
    /// Format decompiled code for display.
    pub fn format_code(code: &str, indent: usize) -> String {
        let mut result = String::new();
        let mut depth: usize = 0;
        for line in code.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with('}') || trimmed.starts_with(')') {
                depth = depth.saturating_sub(1);
            }
            let padding = " ".repeat(depth * indent);
            result.push_str(&padding);
            result.push_str(trimmed);
            result.push('\n');
            if trimmed.ends_with('{') || trimmed.ends_with('(') {
                depth += 1;
            }
        }
        result
    }

    /// Count the number of function calls in decompiled code.
    pub fn count_function_calls(code: &str) -> usize {
        code.matches('(').count()
    }

    /// Extract the function name from decompiled code (first word before '(').
    pub fn extract_function_name(code: &str) -> Option<String> {
        for line in code.lines() {
            if let Some(idx) = line.find('(') {
                let before = &line[..idx];
                if let Some(name) = before.split_whitespace().last() {
                    return Some(name.to_string());
                }
            }
        }
        None
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clang_token_new() {
        let token = ClangToken::new("if");
        assert_eq!(token.text, "if");
        assert_eq!(token.syntax_type, syntax_color::DEFAULT);
        assert!(!token.matching);
    }

    #[test]
    fn test_clang_token_keyword() {
        let token = ClangToken::keyword("return");
        assert_eq!(token.text, "return");
        assert_eq!(token.syntax_type, syntax_color::KEYWORD);
    }

    #[test]
    fn test_clang_token_variable() {
        let token = ClangToken::variable("x");
        assert_eq!(token.syntax_type, syntax_color::VARIABLE);
    }

    #[test]
    fn test_clang_token_type() {
        let token = ClangToken::type_token("int");
        assert_eq!(token.syntax_type, syntax_color::TYPE);
    }

    #[test]
    fn test_clang_token_function() {
        let token = ClangToken::function("main");
        assert_eq!(token.syntax_type, syntax_color::FUNCTION);
    }

    #[test]
    fn test_clang_token_constant() {
        let token = ClangToken::constant("42");
        assert_eq!(token.syntax_type, syntax_color::CONSTANT);
    }

    #[test]
    fn test_clang_token_comment() {
        let token = ClangToken::comment("// test");
        assert_eq!(token.syntax_type, syntax_color::COMMENT);
    }

    #[test]
    fn test_clang_token_error() {
        let token = ClangToken::error("ERROR");
        assert_eq!(token.syntax_type, syntax_color::ERROR);
    }

    #[test]
    fn test_clang_token_with_varnode() {
        let token = ClangToken::new("x").with_varnode_id(42);
        assert!(token.has_varnode());
        assert_eq!(token.varnode_id, Some(42));
    }

    #[test]
    fn test_clang_token_with_address() {
        let token = ClangToken::new("x").with_address(0x1000);
        assert_eq!(token.address, Some(0x1000));
    }

    #[test]
    fn test_clang_token_matching() {
        let mut token = ClangToken::new("{");
        assert!(!token.is_matching());
        token.set_matching(true);
        assert!(token.is_matching());
    }

    #[test]
    fn test_clang_token_color_name() {
        assert_eq!(ClangToken::keyword("if").color_name(), "keyword");
        assert_eq!(ClangToken::comment("...").color_name(), "comment");
        assert_eq!(ClangToken::error("err").color_name(), "error");
    }

    #[test]
    fn test_clang_token_display() {
        let token = ClangToken::new("hello");
        assert_eq!(format!("{}", token), "hello");
    }

    #[test]
    fn test_clang_token_equality() {
        let t1 = ClangToken::keyword("if");
        let t2 = ClangToken::keyword("if");
        let t3 = ClangToken::variable("if");
        assert_eq!(t1, t2);
        assert_ne!(t1, t3);
    }

    #[test]
    fn test_clang_break() {
        let br = ClangBreak::newline();
        assert!(br.force_newline);
        assert!(!br.indent_increase);
        assert!(!br.indent_decrease);

        let br_in = ClangBreak::indent_in();
        assert!(br_in.indent_increase);

        let br_out = ClangBreak::indent_out();
        assert!(br_out.indent_decrease);

        let br_blank = ClangBreak::blank_line(2);
        assert_eq!(br_blank.blank_lines, 2);
    }

    #[test]
    fn test_clang_markup() {
        let mut markup = ClangMarkup::new();
        markup.add_token(ClangToken::keyword("int"));
        markup.add_token(ClangToken::variable("x"));
        assert_eq!(markup.tokens().len(), 2);
        assert_eq!(markup.full_text(), "intx");
    }

    #[test]
    fn test_backwards_slice_action() {
        let action = BackwardsSliceAction::new();
        assert_eq!(action.name, "Backwards Slice");
        assert!(!action.include_all_defs);
    }

    #[test]
    fn test_backwards_slice_to_pcode_ops_action() {
        let action = BackwardsSliceToPCodeOpsAction::new();
        assert!(action.include_addresses);
    }

    #[test]
    fn test_forward_slice_action() {
        let action = ForwardSliceAction::new();
        assert_eq!(action.name, "Forward Slice");
    }

    #[test]
    fn test_forward_slice_to_pcode_ops_action() {
        let action = ForwardSliceToPCodeOpsAction::new();
        assert!(action.include_addresses);
    }

    #[test]
    fn test_convert_actions() {
        assert_eq!(ConvertBinaryAction::new().name, "Convert to Binary");
        assert_eq!(ConvertCharAction::new().name, "Convert to Char");
        assert_eq!(ConvertDecAction::new().name, "Convert to Decimal");
        assert_eq!(ConvertDoubleAction::new().name, "Convert to Double");
        assert_eq!(ConvertFloatAction::new().name, "Convert to Float");
        assert_eq!(ConvertHexAction::new().name, "Convert to Hex");
        assert_eq!(ConvertOctAction::new().name, "Convert to Octal");
    }

    #[test]
    fn test_convert_constant_equate_task() {
        let task = ConvertConstantEquateTask::new("MY_CONST", 42, 0x1000);
        assert_eq!(task.equate_name, "MY_CONST");
        assert_eq!(task.value, 42);
        assert_eq!(task.address, 0x1000);
    }

    #[test]
    fn test_data_type_decompiler_hover_plugin() {
        let plugin = DataTypeDecompilerHoverPlugin::new();
        assert!(plugin.enabled);
        assert_eq!(plugin.hover_delay_ms, 300);
    }

    #[test]
    fn test_function_signature_decompiler_hover_plugin() {
        let plugin = FunctionSignatureDecompilerHoverPlugin::new();
        assert!(plugin.enabled);
    }

    #[test]
    fn test_reference_decompiler_hover_plugin() {
        let plugin = ReferenceDecompilerHoverPlugin::new();
        assert!(plugin.enabled);
    }

    #[test]
    fn test_scalar_value_decompiler_hover_plugin() {
        let plugin = ScalarValueDecompilerHoverPlugin::new();
        assert!(plugin.enabled);
    }

    #[test]
    fn test_null_clang_highlight_controller() {
        let _ctrl = NullClangHighlightController::new();
    }

    #[test]
    fn test_line_number_decompiler_margin_provider() {
        let provider = LineNumberDecompilerMarginProvider::new();
        assert!(provider.visible);
        assert_eq!(provider.margin_width, 40);
    }

    #[test]
    fn test_rename_union_field_task() {
        let task = RenameUnionFieldTask::new("MyUnion", "oldField", "newField");
        assert_eq!(task.union_name, "MyUnion");
        assert_eq!(task.old_name, "oldField");
        assert_eq!(task.new_name, "newField");
    }

    #[test]
    fn test_fill_out_structure_cmd() {
        let mut cmd = FillOutStructureCmd::new("MyStruct");
        cmd.add_field(SuggestedField {
            name: "field1".to_string(),
            offset: 0,
            size: 4,
            data_type: "int".to_string(),
        });
        assert_eq!(cmd.suggested_fields.len(), 1);
        assert_eq!(cmd.structure_name, "MyStruct");
    }

    #[test]
    fn test_decompile_callback() {
        let mut cb = DecompileCallback::new("test_callback");
        assert!(!cb.registered);
        cb.register();
        assert!(cb.registered);
        cb.unregister();
        assert!(!cb.registered);
    }

    #[test]
    fn test_decompiler_component() {
        let comp = DecompilerComponent::new();
        assert!(!comp.decompiling);
        assert!(comp.current_address.is_none());
        assert!(comp.last_error.is_none());
    }

    #[test]
    fn test_decompiler_display_options() {
        let opts = DecompilerDisplayOptions::default();
        assert!(opts.show_type_casts);
        assert!(opts.show_line_numbers);
        assert!(!opts.show_addresses);
        assert_eq!(opts.max_line_width, 120);
    }

    #[test]
    fn test_decompiler_panel() {
        let mut panel = DecompilerPanel::new();
        panel.set_text("int main() {\n    return 0;\n}");
        assert_eq!(panel.line_count(), 3);
    }

    #[test]
    fn test_decompiler_utils_format_code() {
        let code = "int main() {\nreturn 0;\n}";
        let formatted = DecompilerUtils::format_code(code, 4);
        assert!(formatted.contains("    return 0;"));
    }

    #[test]
    fn test_decompiler_utils_extract_function_name() {
        let code = "int main(int argc) {\n    return 0;\n}";
        let name = DecompilerUtils::extract_function_name(code);
        assert_eq!(name, Some("main".to_string()));
    }

    #[test]
    fn test_decompiler_utils_count_calls() {
        let code = "foo(bar(1), baz(2))";
        assert_eq!(DecompilerUtils::count_function_calls(code), 3);
    }
}
