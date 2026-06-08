//! Decompile options -- Rust port of
//! `ghidra.app.decompiler.DecompileOptions`.
//!
//! Configuration options for the decompiler.  Stores all analysis,
//! display, and runtime options, and can serialize them to an XML-like
//! stream for the decompiler process.
//!
//! # Architecture
//!
//! ```text
//! DecompileOptions
//!   ├── Analysis options (predicate, read-only, unreachable, loops, ...)
//!   ├── Display options  (brace style, max width, comments, namespaces, ...)
//!   ├── Color/font config (token colors, highlights, background)
//!   ├── Runtime limits   (timeout, payload, max instructions, cache size)
//!   └── Program-specific (display language, prototype eval model)
//! ```
//!
//! The options are grouped into three categories that match Ghidra's
//! `ToolOptions` dialog:
//!
//! | Tab        | Prefix in option string |
//! |------------|------------------------|
//! | Analysis   | `Analysis.`            |
//! | Display    | `Display.`             |
//! | General    | *(no prefix)*          |

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Enums for option values
// ---------------------------------------------------------------------------

/// How NaN operations are handled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NanIgnoreMode {
    /// Do not ignore any NaN operations.
    None,
    /// Ignore NaN in comparisons.
    Compare,
    /// Ignore all NaN operations.
    All,
}

impl NanIgnoreMode {
    /// The option-string value sent to the decompiler process.
    pub fn option_string(&self) -> &'static str {
        match self {
            NanIgnoreMode::None => "none",
            NanIgnoreMode::Compare => "compare",
            NanIgnoreMode::All => "all",
        }
    }

    /// Human-readable label for the UI.
    pub fn label(&self) -> &'static str {
        match self {
            NanIgnoreMode::None => "Ignore none",
            NanIgnoreMode::Compare => "Ignore with comparisons",
            NanIgnoreMode::All => "Ignore all",
        }
    }
}

impl Default for NanIgnoreMode {
    fn default() -> Self {
        NanIgnoreMode::Compare
    }
}

/// How data-types block pointer aliasing on the stack.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AliasBlockMode {
    /// No blocking.
    None,
    /// Structures block aliasing.
    Struct,
    /// Arrays and structures block aliasing.
    Array,
    /// All data-types block aliasing.
    All,
}

impl AliasBlockMode {
    pub fn option_string(&self) -> &'static str {
        match self {
            AliasBlockMode::None => "none",
            AliasBlockMode::Struct => "struct",
            AliasBlockMode::Array => "array",
            AliasBlockMode::All => "all",
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            AliasBlockMode::None => "None",
            AliasBlockMode::Struct => "Structures",
            AliasBlockMode::Array => "Arrays and Structures",
            AliasBlockMode::All => "All Data-types",
        }
    }
}

impl Default for AliasBlockMode {
    fn default() -> Self {
        AliasBlockMode::Array
    }
}

/// Where the opening brace is displayed relative to a block header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BraceStyle {
    /// Same line as the header.
    Same,
    /// Next line after the header.
    Next,
    /// Skip one line after the header.
    Skip,
}

impl BraceStyle {
    pub fn option_string(&self) -> &'static str {
        match self {
            BraceStyle::Same => "same",
            BraceStyle::Next => "next",
            BraceStyle::Skip => "skip",
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            BraceStyle::Same => "Same line",
            BraceStyle::Next => "Next line",
            BraceStyle::Skip => "Skip one line",
        }
    }
}

impl Default for BraceStyle {
    fn default() -> Self {
        BraceStyle::Same
    }
}

/// Comment style.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CommentStyle {
    /// C-style `/* ... */`.
    CStyle,
    /// C++-style `// ...`.
    CppStyle,
}

impl CommentStyle {
    pub fn label(&self) -> &'static str {
        match self {
            CommentStyle::CStyle => "/* C-style comments */",
            CommentStyle::CppStyle => "// C++-style comments",
        }
    }
}

impl Default for CommentStyle {
    fn default() -> Self {
        CommentStyle::CStyle
    }
}

/// How namespace tokens are displayed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NamespaceStrategy {
    /// Display namespaces only when necessary to disambiguate.
    Minimal,
    /// Always display namespaces.
    All,
    /// Never display namespaces.
    Never,
}

impl NamespaceStrategy {
    pub fn option_string(&self) -> &'static str {
        match self {
            NamespaceStrategy::Minimal => "minimal",
            NamespaceStrategy::All => "all",
            NamespaceStrategy::Never => "none",
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            NamespaceStrategy::Minimal => "Minimally",
            NamespaceStrategy::All => "Always",
            NamespaceStrategy::Never => "Never",
        }
    }
}

impl Default for NamespaceStrategy {
    fn default() -> Self {
        NamespaceStrategy::Minimal
    }
}

/// Integer display format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IntegerFormat {
    /// Force hexadecimal.
    Hexadecimal,
    /// Force decimal.
    Decimal,
    /// Best fit (context-dependent).
    BestFit,
}

impl IntegerFormat {
    pub fn option_string(&self) -> &'static str {
        match self {
            IntegerFormat::Hexadecimal => "hex",
            IntegerFormat::Decimal => "dec",
            IntegerFormat::BestFit => "best",
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            IntegerFormat::Hexadecimal => "Force Hexadecimal",
            IntegerFormat::Decimal => "Force Decimal",
            IntegerFormat::BestFit => "Best Fit",
        }
    }
}

impl Default for IntegerFormat {
    fn default() -> Self {
        IntegerFormat::BestFit
    }
}

/// Decompiler output language.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DecompilerLanguage {
    /// C language output.
    CLanguage,
    /// Java language output.
    JavaLanguage,
}

impl Default for DecompilerLanguage {
    fn default() -> Self {
        DecompilerLanguage::CLanguage
    }
}

// ---------------------------------------------------------------------------
// Color configuration
// ---------------------------------------------------------------------------

/// A color value represented as RGBA.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Color {
    pub r: u8,
    pub g: u8,
    pub b: u8,
    pub a: u8,
}

impl Color {
    pub const fn new(r: u8, g: u8, b: u8, a: u8) -> Self {
        Self { r, g, b, a }
    }

    pub const fn rgb(r: u8, g: u8, b: u8) -> Self {
        Self { r, g, b, a: 255 }
    }
}

/// Token color configuration for the decompiler display.
#[derive(Debug, Clone)]
pub struct TokenColors {
    /// Color for keywords.
    pub keyword: Color,
    /// Color for type names.
    pub type_name: Color,
    /// Color for comments.
    pub comment: Color,
    /// Color for variables.
    pub variable: Color,
    /// Color for constants.
    pub constant: Color,
    /// Color for function parameters.
    pub parameter: Color,
    /// Color for global variables.
    pub global: Color,
    /// Color for special (volatile, etc.) tokens.
    pub special: Color,
    /// Default text color.
    pub default: Color,
    /// Background color.
    pub background: Color,
    /// Error/warning color.
    pub error: Color,
    /// Current variable highlight color.
    pub current_variable: Color,
    /// Find-match highlight color.
    pub search_highlight: Color,
    /// Active find-match highlight color.
    pub search_highlight_active: Color,
    /// Middle-mouse highlight color.
    pub middle_mouse: Color,
}

impl Default for TokenColors {
    fn default() -> Self {
        Self {
            keyword: Color::rgb(0, 0, 128),
            type_name: Color::rgb(0, 128, 0),
            comment: Color::rgb(128, 128, 128),
            variable: Color::rgb(0, 0, 0),
            constant: Color::rgb(0, 0, 128),
            parameter: Color::rgb(128, 0, 128),
            global: Color::rgb(128, 0, 0),
            special: Color::rgb(128, 128, 0),
            default: Color::rgb(0, 0, 0),
            background: Color::rgb(255, 255, 255),
            error: Color::rgb(255, 0, 0),
            current_variable: Color::rgb(200, 200, 255),
            search_highlight: Color::rgb(255, 255, 0),
            search_highlight_active: Color::rgb(255, 200, 0),
            middle_mouse: Color::rgb(200, 255, 200),
        }
    }
}

// ---------------------------------------------------------------------------
// DecompileOptions
// ---------------------------------------------------------------------------

/// Configuration options for the decompiler.
///
/// This stores all options and can serialize them to an XML-like stream
/// for the decompiler process.  It corresponds to Ghidra's
/// `DecompileOptions` class.
///
/// # Option Categories
///
/// - **Analysis**: predicate simplification, unreachable code elimination,
///   for-loop recovery, structure splitting, alias blocking, etc.
/// - **Display**: brace styles, max line width, comment inclusion,
///   namespace strategy, integer format, type cast printing, etc.
/// - **General**: timeout, payload limit, max instructions, cache size.
#[derive(Debug, Clone)]
pub struct DecompileOptions {
    // -- Analysis options --
    /// Simplify predication (combine conditionally executed instructions).
    pub predicate: bool,
    /// Treat read-only memory values as constants.
    pub respect_read_only: bool,
    /// Eliminate unreachable code branches.
    pub eliminate_unreachable: bool,
    /// Simplify extended (double-precision) integer operations.
    pub simplify_double_precision: bool,
    /// Treat unimplemented instructions as NOPs.
    pub ignore_unimplemented: bool,
    /// Infer constant pointers from constants that look like addresses.
    pub infer_constant_pointers: bool,
    /// Attempt to recover for-loop variables.
    pub analyze_for_loops: bool,
    /// Split combined structure field copies.
    pub split_structures: bool,
    /// Split combined array element copies.
    pub split_arrays: bool,
    /// Split pointer-based combined element copies.
    pub split_pointers: bool,
    /// How to handle NaN operations.
    pub nan_ignore: NanIgnoreMode,
    /// Which data-types block pointer aliasing on the stack.
    pub alias_block: AliasBlockMode,
    /// Simplify bitfield access expressions.
    pub bitfield_access: bool,

    // -- Display options --
    /// Print 'NULL' for null pointers instead of `(void *)0`.
    pub null_token: bool,
    /// Use inplace assignment operators (`+=`, `*=`, etc.).
    pub inplace_operators: bool,
    /// Print calling convention name when it differs from default.
    pub convention_print: bool,
    /// Disable printing of type casts.
    pub no_cast: bool,
    /// Brace style for function blocks.
    pub brace_function: BraceStyle,
    /// Brace style for if/else blocks.
    pub brace_if_else: BraceStyle,
    /// Brace style for loop blocks.
    pub brace_loop: BraceStyle,
    /// Brace style for switch blocks.
    pub brace_switch: BraceStyle,
    /// Maximum characters per line before forced line breaks.
    pub max_width: usize,
    /// Characters per indent level.
    pub indent_width: usize,
    /// Characters of indent for comment lines.
    pub comment_indent: usize,
    /// Comment style (C or C++).
    pub comment_style: CommentStyle,
    /// Display PRE (pre-instruction) comments.
    pub comment_pre: bool,
    /// Display PLATE comments.
    pub comment_plate: bool,
    /// Display POST (post-instruction) comments.
    pub comment_post: bool,
    /// Display EOL (end-of-line) comments.
    pub comment_eol: bool,
    /// Display warning comments.
    pub comment_warn: bool,
    /// Display header comment (entry point plate comment).
    pub comment_header: bool,
    /// Namespace display strategy.
    pub namespace_strategy: NamespaceStrategy,
    /// Integer display format.
    pub integer_format: IntegerFormat,
    /// Display line numbers.
    pub display_line_numbers: bool,

    // -- General / runtime --
    /// Decompiler timeout in seconds.
    pub decompile_timeout_secs: usize,
    /// Maximum decompiler payload in megabytes.
    pub payload_limit_mbytes: usize,
    /// Maximum instructions per function.
    pub max_instructions: usize,
    /// Maximum entries per jump table.
    pub max_jumptable_entries: usize,
    /// Number of decompiled functions to cache.
    pub cached_results_size: usize,

    // -- Program-specific --
    /// Output language for the decompiler.
    pub display_language: DecompilerLanguage,
    /// Name of the prototype evaluation model.
    pub proto_eval_model: String,

    // -- Display colors --
    /// Token color configuration.
    pub colors: TokenColors,

    // -- Font --
    /// Font ID for the decompiler display.
    pub font_id: String,

    // -- Cursor --
    /// Middle-mouse highlight button ID (MouseEvent.BUTTON2 = 2).
    pub middle_mouse_highlight_button: i32,
}

impl DecompileOptions {
    /// The option key for the no-cast setting (used by `DisplayTypeCastsAction`).
    pub const NOCAST_OPTION_STRING: &'static str = "Display.Disable printing of type casts";

    /// The default font ID.
    pub const DEFAULT_FONT_ID: &'static str = "font.decompiler";

    /// Suggested decompile timeout in seconds.
    pub const SUGGESTED_DECOMPILE_TIMEOUT_SECS: usize = 30;

    /// Suggested max payload in megabytes.
    pub const SUGGESTED_MAX_PAYLOAD_BYTES: usize = 50;

    /// Suggested max instructions per function.
    pub const SUGGESTED_MAX_INSTRUCTIONS: usize = 100_000;

    /// Suggested max jump-table entries.
    pub const SUGGESTED_MAX_JUMPTABLE_ENTRIES: usize = 1024;

    /// Suggested cache size (number of functions).
    pub const SUGGESTED_CACHED_RESULTS_SIZE: usize = 10;

    /// Create default options.
    pub fn new() -> Self {
        Self {
            // Analysis
            predicate: true,
            respect_read_only: true,
            eliminate_unreachable: true,
            simplify_double_precision: true,
            ignore_unimplemented: false,
            infer_constant_pointers: true,
            analyze_for_loops: true,
            split_structures: true,
            split_arrays: true,
            split_pointers: true,
            nan_ignore: NanIgnoreMode::default(),
            alias_block: AliasBlockMode::default(),
            bitfield_access: true,

            // Display
            null_token: false,
            inplace_operators: false,
            convention_print: true,
            no_cast: false,
            brace_function: BraceStyle::Skip,
            brace_if_else: BraceStyle::Same,
            brace_loop: BraceStyle::Same,
            brace_switch: BraceStyle::Same,
            max_width: 100,
            indent_width: 2,
            comment_indent: 20,
            comment_style: CommentStyle::default(),
            comment_pre: true,
            comment_plate: false,
            comment_post: false,
            comment_eol: false,
            comment_warn: true,
            comment_header: true,
            namespace_strategy: NamespaceStrategy::default(),
            integer_format: IntegerFormat::default(),
            display_line_numbers: true,

            // General
            decompile_timeout_secs: Self::SUGGESTED_DECOMPILE_TIMEOUT_SECS,
            payload_limit_mbytes: Self::SUGGESTED_MAX_PAYLOAD_BYTES,
            max_instructions: Self::SUGGESTED_MAX_INSTRUCTIONS,
            max_jumptable_entries: Self::SUGGESTED_MAX_JUMPTABLE_ENTRIES,
            cached_results_size: Self::SUGGESTED_CACHED_RESULTS_SIZE,

            // Program-specific
            display_language: DecompilerLanguage::default(),
            proto_eval_model: "default".to_string(),

            // Colors
            colors: TokenColors::default(),

            // Font
            font_id: Self::DEFAULT_FONT_ID.to_string(),

            // Cursor
            middle_mouse_highlight_button: 2,
        }
    }

    /// Whether type casts are disabled.
    pub fn is_no_cast(&self) -> bool {
        self.no_cast
    }

    /// Set whether type casts are disabled.
    pub fn set_no_cast(&mut self, no_cast: bool) {
        self.no_cast = no_cast;
    }

    /// Whether unreachable code is eliminated.
    pub fn is_eliminate_unreachable(&self) -> bool {
        self.eliminate_unreachable
    }

    /// Set whether unreachable code is eliminated.
    pub fn set_eliminate_unreachable(&mut self, eliminate: bool) {
        self.eliminate_unreachable = eliminate;
    }

    /// Whether read-only flags are respected.
    pub fn is_respect_read_only(&self) -> bool {
        self.respect_read_only
    }

    /// Set whether read-only flags are respected.
    pub fn set_respect_read_only(&mut self, respect: bool) {
        self.respect_read_only = respect;
    }

    /// Get the cache size.
    pub fn get_cache_size(&self) -> usize {
        self.cached_results_size
    }

    /// Set the cache size.
    pub fn set_cache_size(&mut self, size: usize) {
        self.cached_results_size = size;
    }

    /// Get the decompile timeout in seconds.
    pub fn get_timeout(&self) -> usize {
        self.decompile_timeout_secs
    }

    /// Set the decompile timeout in seconds.
    pub fn set_timeout(&mut self, secs: usize) {
        self.decompile_timeout_secs = secs;
    }

    /// Serialize the options to key-value pairs for the decompiler process.
    ///
    /// This produces a flat list of `(key, value)` pairs that can be
    /// encoded as XML attributes or command-line arguments.
    pub fn to_process_options(&self) -> Vec<(String, String)> {
        let mut opts = Vec::new();

        // Analysis options
        if !self.predicate {
            opts.push(("conditionalexe".into(), "off".into()));
        }
        if !self.eliminate_unreachable {
            opts.push(("unreachable".into(), "off".into()));
        }
        if !self.simplify_double_precision {
            opts.push(("doubleprecis".into(), "off".into()));
        }
        if self.ignore_unimplemented {
            opts.push(("ignoreunimpl".into(), "on".into()));
        }
        if !self.infer_constant_pointers {
            opts.push(("inferconstptr".into(), "off".into()));
        }
        if !self.analyze_for_loops {
            opts.push(("forloops".into(), "off".into()));
        }

        // Split options
        let mut split_parts = Vec::new();
        if self.split_structures {
            split_parts.push("struct");
        }
        if self.split_arrays {
            split_parts.push("array");
        }
        if self.split_pointers {
            split_parts.push("pointer");
        }
        if !split_parts.is_empty() {
            opts.push(("splitdatatype".into(), split_parts.join(",")));
        }

        // NaN handling
        if self.nan_ignore != NanIgnoreMode::default() {
            opts.push(("nanignore".into(), self.nan_ignore.option_string().into()));
        }

        // Read-only
        opts.push(("readonly".into(), if self.respect_read_only { "on" } else { "off" }.into()));

        // Display language
        let lang_str = match self.display_language {
            DecompilerLanguage::CLanguage => "c-language",
            DecompilerLanguage::JavaLanguage => "java-language",
        };
        opts.push(("setlanguage".into(), lang_str.into()));

        // Alias blocking
        if self.alias_block != AliasBlockMode::default() {
            opts.push(("aliasblock".into(), self.alias_block.option_string().into()));
        }

        // Bitfield access
        if !self.bitfield_access {
            opts.push(("bitfieldaccess".into(), "off".into()));
        }

        // Display options
        if self.null_token {
            opts.push(("nulltoken".into(), "on".into()));
        }
        if self.inplace_operators {
            opts.push(("inplaceops".into(), "on".into()));
        }
        if !self.convention_print {
            opts.push((" conventionprint".into(), "off".into()));
        }
        if self.no_cast {
            opts.push(("nocast".into(), "on".into()));
        }

        // Brace styles
        opts.push(("bracefunction".into(), self.brace_function.option_string().into()));
        opts.push(("braceifelse".into(), self.brace_if_else.option_string().into()));
        opts.push(("braceloop".into(), self.brace_loop.option_string().into()));
        opts.push(("braceswitch".into(), self.brace_switch.option_string().into()));

        // Width / indent
        opts.push(("maxwidth".into(), self.max_width.to_string()));
        opts.push(("indentwidth".into(), self.indent_width.to_string()));
        opts.push(("commentindent".into(), self.comment_indent.to_string()));

        // Comment style
        let cs = match self.comment_style {
            CommentStyle::CStyle => "c",
            CommentStyle::CppStyle => "cplusplus",
        };
        opts.push(("commentstyle".into(), cs.into()));

        // Comment inclusions
        opts.push(("commentpre".into(), if self.comment_pre { "on" } else { "off" }.into()));
        opts.push(("commentplate".into(), if self.comment_plate { "on" } else { "off" }.into()));
        opts.push(("commentpost".into(), if self.comment_post { "on" } else { "off" }.into()));
        opts.push(("commenteol".into(), if self.comment_eol { "on" } else { "off" }.into()));
        opts.push(("commentwarn".into(), if self.comment_warn { "on" } else { "off" }.into()));
        opts.push(("commenthead".into(), if self.comment_header { "on" } else { "off" }.into()));

        // Namespace
        opts.push(("namespace".into(), self.namespace_strategy.option_string().into()));

        // Integer format
        opts.push(("integerformat".into(), self.integer_format.option_string().into()));

        // Prototype evaluation model
        opts.push(("protoevalmodel".into(), self.proto_eval_model.clone()));

        opts
    }

    /// Build a summary string of all non-default analysis options, suitable
    /// for debug logging.
    pub fn analysis_summary(&self) -> String {
        let mut parts = Vec::new();
        if !self.predicate {
            parts.push("no-predicate");
        }
        if !self.eliminate_unreachable {
            parts.push("keep-unreachable");
        }
        if !self.simplify_double_precision {
            parts.push("no-double-precis");
        }
        if self.ignore_unimplemented {
            parts.push("ignore-unimpl");
        }
        if !self.infer_constant_pointers {
            parts.push("no-infer-ptrs");
        }
        if !self.analyze_for_loops {
            parts.push("no-for-loops");
        }
        if !self.split_structures {
            parts.push("no-split-struct");
        }
        if !self.split_arrays {
            parts.push("no-split-array");
        }
        if !self.split_pointers {
            parts.push("no-split-pointer");
        }
        if parts.is_empty() {
            "(all defaults)".to_string()
        } else {
            parts.join(", ")
        }
    }
}

impl Default for DecompileOptions {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- Enums ---

    #[test]
    fn test_nan_ignore_mode_defaults() {
        assert_eq!(NanIgnoreMode::default(), NanIgnoreMode::Compare);
        assert_eq!(NanIgnoreMode::Compare.option_string(), "compare");
        assert_eq!(NanIgnoreMode::All.option_string(), "all");
        assert_eq!(NanIgnoreMode::None.option_string(), "none");
    }

    #[test]
    fn test_alias_block_mode_defaults() {
        assert_eq!(AliasBlockMode::default(), AliasBlockMode::Array);
        assert_eq!(AliasBlockMode::Array.option_string(), "array");
        assert_eq!(AliasBlockMode::All.option_string(), "all");
    }

    #[test]
    fn test_brace_style_defaults() {
        assert_eq!(BraceStyle::default(), BraceStyle::Same);
        assert_eq!(BraceStyle::Skip.option_string(), "skip");
        assert_eq!(BraceStyle::Next.label(), "Next line");
    }

    #[test]
    fn test_comment_style_defaults() {
        assert_eq!(CommentStyle::default(), CommentStyle::CStyle);
        assert_eq!(CommentStyle::CppStyle.label(), "// C++-style comments");
    }

    #[test]
    fn test_namespace_strategy_defaults() {
        assert_eq!(NamespaceStrategy::default(), NamespaceStrategy::Minimal);
        assert_eq!(NamespaceStrategy::All.option_string(), "all");
    }

    #[test]
    fn test_integer_format_defaults() {
        assert_eq!(IntegerFormat::default(), IntegerFormat::BestFit);
        assert_eq!(IntegerFormat::Hexadecimal.option_string(), "hex");
    }

    // --- TokenColors ---

    #[test]
    fn test_token_colors_default() {
        let colors = TokenColors::default();
        assert_eq!(colors.background, Color::rgb(255, 255, 255));
        assert_eq!(colors.error, Color::rgb(255, 0, 0));
        assert_eq!(colors.default, Color::rgb(0, 0, 0));
    }

    #[test]
    fn test_color_rgba() {
        let c = Color::new(10, 20, 30, 128);
        assert_eq!(c.r, 10);
        assert_eq!(c.a, 128);
    }

    // --- DecompileOptions ---

    #[test]
    fn test_options_defaults() {
        let opts = DecompileOptions::new();
        assert!(opts.predicate);
        assert!(opts.respect_read_only);
        assert!(opts.eliminate_unreachable);
        assert!(opts.simplify_double_precision);
        assert!(!opts.ignore_unimplemented);
        assert!(opts.infer_constant_pointers);
        assert!(opts.analyze_for_loops);
        assert!(opts.split_structures);
        assert!(opts.split_arrays);
        assert!(opts.split_pointers);
        assert_eq!(opts.nan_ignore, NanIgnoreMode::Compare);
        assert_eq!(opts.alias_block, AliasBlockMode::Array);
        assert!(opts.bitfield_access);
    }

    #[test]
    fn test_options_display_defaults() {
        let opts = DecompileOptions::new();
        assert!(!opts.null_token);
        assert!(!opts.inplace_operators);
        assert!(opts.convention_print);
        assert!(!opts.no_cast);
        assert_eq!(opts.brace_function, BraceStyle::Skip);
        assert_eq!(opts.brace_if_else, BraceStyle::Same);
        assert_eq!(opts.brace_loop, BraceStyle::Same);
        assert_eq!(opts.brace_switch, BraceStyle::Same);
        assert_eq!(opts.max_width, 100);
        assert_eq!(opts.indent_width, 2);
        assert_eq!(opts.comment_indent, 20);
        assert_eq!(opts.comment_style, CommentStyle::CStyle);
        assert!(opts.comment_pre);
        assert!(!opts.comment_plate);
        assert!(!opts.comment_post);
        assert!(!opts.comment_eol);
        assert!(opts.comment_warn);
        assert!(opts.comment_header);
        assert_eq!(opts.namespace_strategy, NamespaceStrategy::Minimal);
        assert_eq!(opts.integer_format, IntegerFormat::BestFit);
        assert!(opts.display_line_numbers);
    }

    #[test]
    fn test_options_general_defaults() {
        let opts = DecompileOptions::new();
        assert_eq!(opts.decompile_timeout_secs, 30);
        assert_eq!(opts.payload_limit_mbytes, 50);
        assert_eq!(opts.max_instructions, 100_000);
        assert_eq!(opts.max_jumptable_entries, 1024);
        assert_eq!(opts.cached_results_size, 10);
    }

    #[test]
    fn test_options_program_defaults() {
        let opts = DecompileOptions::new();
        assert_eq!(opts.display_language, DecompilerLanguage::CLanguage);
        assert_eq!(opts.proto_eval_model, "default");
    }

    #[test]
    fn test_options_font_defaults() {
        let opts = DecompileOptions::new();
        assert_eq!(opts.font_id, DecompileOptions::DEFAULT_FONT_ID);
        assert_eq!(opts.middle_mouse_highlight_button, 2);
    }

    // --- Setters ---

    #[test]
    fn test_set_no_cast() {
        let mut opts = DecompileOptions::new();
        assert!(!opts.is_no_cast());
        opts.set_no_cast(true);
        assert!(opts.is_no_cast());
        opts.set_no_cast(false);
        assert!(!opts.is_no_cast());
    }

    #[test]
    fn test_set_eliminate_unreachable() {
        let mut opts = DecompileOptions::new();
        assert!(opts.is_eliminate_unreachable());
        opts.set_eliminate_unreachable(false);
        assert!(!opts.is_eliminate_unreachable());
    }

    #[test]
    fn test_set_respect_read_only() {
        let mut opts = DecompileOptions::new();
        assert!(opts.is_respect_read_only());
        opts.set_respect_read_only(false);
        assert!(!opts.is_respect_read_only());
    }

    #[test]
    fn test_set_cache_size() {
        let mut opts = DecompileOptions::new();
        assert_eq!(opts.get_cache_size(), 10);
        opts.set_cache_size(25);
        assert_eq!(opts.get_cache_size(), 25);
    }

    #[test]
    fn test_set_timeout() {
        let mut opts = DecompileOptions::new();
        assert_eq!(opts.get_timeout(), 30);
        opts.set_timeout(60);
        assert_eq!(opts.get_timeout(), 60);
    }

    // --- Serialization ---

    #[test]
    fn test_to_process_options_default() {
        let opts = DecompileOptions::new();
        let process_opts = opts.to_process_options();
        // All defaults should produce a minimal option set.
        // Check that readonly is always present.
        assert!(process_opts.iter().any(|(k, v)| k == "readonly" && v == "on"));
        // Check that setlanguage is present.
        assert!(process_opts.iter().any(|(k, _)| k == "setlanguage"));
        // Check that brace styles are present.
        assert!(process_opts.iter().any(|(k, _)| k == "bracefunction"));
    }

    #[test]
    fn test_to_process_options_no_cast() {
        let mut opts = DecompileOptions::new();
        opts.set_no_cast(true);
        let process_opts = opts.to_process_options();
        assert!(process_opts.iter().any(|(k, v)| k == "nocast" && v == "on"));
    }

    #[test]
    fn test_to_process_options_no_unreachable() {
        let mut opts = DecompileOptions::new();
        opts.set_eliminate_unreachable(false);
        let process_opts = opts.to_process_options();
        assert!(process_opts.iter().any(|(k, v)| k == "unreachable" && v == "off"));
    }

    #[test]
    fn test_to_process_options_nan_ignore() {
        let mut opts = DecompileOptions::new();
        opts.nan_ignore = NanIgnoreMode::All;
        let process_opts = opts.to_process_options();
        assert!(process_opts.iter().any(|(k, v)| k == "nanignore" && v == "all"));
    }

    // --- Analysis summary ---

    #[test]
    fn test_analysis_summary_all_defaults() {
        let opts = DecompileOptions::new();
        assert_eq!(opts.analysis_summary(), "(all defaults)");
    }

    #[test]
    fn test_analysis_summary_with_changes() {
        let mut opts = DecompileOptions::new();
        opts.predicate = false;
        opts.eliminate_unreachable = false;
        opts.split_structures = false;
        let summary = opts.analysis_summary();
        assert!(summary.contains("no-predicate"));
        assert!(summary.contains("keep-unreachable"));
        assert!(summary.contains("no-split-struct"));
    }

    // --- Clone ---

    #[test]
    fn test_options_clone() {
        let mut opts = DecompileOptions::new();
        opts.set_no_cast(true);
        opts.set_cache_size(42);
        opts.max_width = 120;
        opts.brace_function = BraceStyle::Next;

        let cloned = opts.clone();
        assert!(cloned.is_no_cast());
        assert_eq!(cloned.get_cache_size(), 42);
        assert_eq!(cloned.max_width, 120);
        assert_eq!(cloned.brace_function, BraceStyle::Next);
    }

    // --- Constants ---

    #[test]
    fn test_constants() {
        assert_eq!(
            DecompileOptions::NOCAST_OPTION_STRING,
            "Display.Disable printing of type casts"
        );
        assert_eq!(DecompileOptions::DEFAULT_FONT_ID, "font.decompiler");
        assert_eq!(DecompileOptions::SUGGESTED_DECOMPILE_TIMEOUT_SECS, 30);
        assert_eq!(DecompileOptions::SUGGESTED_MAX_PAYLOAD_BYTES, 50);
        assert_eq!(DecompileOptions::SUGGESTED_MAX_INSTRUCTIONS, 100_000);
        assert_eq!(DecompileOptions::SUGGESTED_MAX_JUMPTABLE_ENTRIES, 1024);
        assert_eq!(DecompileOptions::SUGGESTED_CACHED_RESULTS_SIZE, 10);
    }
}
