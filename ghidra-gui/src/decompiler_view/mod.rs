//! Decompiler view for the Ghidra GUI.
//!
//! Displays decompiled C pseudocode with syntax highlighting,
//! clickable variable/function names, bracket matching, code folding,
//! selection, copy support, hover tooltips, and scroll synchronization
//! with the listing view.
//!
//! ## Architecture
//!
//! The decompiler view is composed of:
//! - **CToken types** ([`CTokenKind`], [`CToken`]) modeling each token in the
//!   decompiled C output with full metadata for navigation and highlighting.
//! - **Syntax theme** ([`SyntaxTheme`]) providing configurable colors for
//!   each syntactic element.
//! - **View state** ([`DecompilerViewState`]) tracking cursor position,
//!   selection, folding, bracket matching, and hover information.
//! - **Renderer** ([`render_decompiler_view`]) that paints the view into an
//!   egui [`Ui`] with full interaction support.
//!
//! ## Navigation Features
//!
//! - **Function names**: clicking navigates to the function definition.
//! - **Variables**: clicking highlights all uses of that variable.
//! - **Goto labels**: clicking jumps to the label definition.
//! - **Address references**: clicking navigates to the address in the listing.
//! - **Double-click on line**: navigates to the corresponding assembly address.
//!
//! ## Folding
//!
//! `{ ... }` blocks are foldable. Fold regions are computed from brace
//! matching. Clicking `[-]` in the gutter folds a region; clicking `[+]`
//! expands it again.

pub mod detail;
mod render;

pub use render::render_decompiler_view;

use ghidra_core::addr::Address;
use std::collections::{HashMap, HashSet};

// ============================================================================
// Token Types
// ============================================================================

/// A token kind for C pseudocode syntax highlighting.
///
/// Each token in the decompiled output is classified into one of these
/// categories to drive both syntax highlighting and interaction behavior
/// (clickable identifiers, foldable brackets, navigable addresses, etc.).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CTokenKind {
    /// C keyword: `if`, `else`, `while`, `for`, `return`, `goto`, `switch`,
    /// `case`, `break`, `continue`, `sizeof`, `typedef`, `struct`, `enum`,
    /// `union`, `static`, `extern`, `const`, `volatile`, `register`,
    /// `inline`, `restrict`, `do`, `default`, `auto`, `NULL`, `true`, `false`.
    Keyword,
    /// Type name: `int`, `char`, `void`, `long`, `short`, `float`, `double`,
    /// `unsigned`, `signed`, `uint`, `byte`, `word`, `dword`, `qword`,
    /// `bool`, `size_t`, `ptrdiff_t`, `ssize_t`, fixed-width types, etc.
    TypeName,
    /// Generic identifier (variable name, parameter name, local variable).
    Identifier,
    /// Function name in a call expression or definition header.
    FunctionName,
    /// Numeric literal: decimal (`42`), hex (`0xDEAD`), octal (`0777`).
    Number,
    /// String literal delimited by double quotes: `"hello\n"`.
    StringLiteral,
    /// Character literal delimited by single quotes: `'a'`, `'\n'`.
    CharLiteral,
    /// Comment: single-line (`// ...`) or multi-line (`/* ... */`).
    Comment,
    /// Preprocessor directive: `#define`, `#include`, `#ifdef`, `#if`,
    /// `#else`, `#endif`, `#pragma`, `#error`, `#line`, `#undef`.
    Preprocessor,
    /// Operator: `+`, `-`, `*`, `/`, `%`, `&`, `|`, `^`, `~`, `!`,
    /// `&&`, `||`, `<<`, `>>`, `<`, `>`, `<=`, `>=`, `==`, `!=`, `=`,
    /// `+=`, `-=`, `*=`, `/=`, `%=`, `&=`, `|=`, `^=`, `++`, `--`,
    /// `->`, `::`, `.`, `?`, `:`.
    Operator,
    /// Punctuation delimiters: `;`, `,`, `(`, `)`, `{`, `}`, `[`, `]`.
    Punctuation,
    /// An address reference (e.g., `0x401000` when used as a target address).
    AddressRef,
    /// Whitespace (spaces, tabs). Always rendered as transparent spacing.
    Whitespace,
    /// A goto label definition: `LAB_00100400:`.
    LabelDef,
    /// Unknown/unclassified token.
    Unknown,
}

/// Additional navigation metadata carried by a [`CToken`].
///
/// Used when a token like an identifier or address reference can be
/// clicked to navigate somewhere in the codebase.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenNavigation {
    /// No navigation target.
    None,
    /// This token refers to an address in the binary. Clicking navigates
    /// the listing view to that address.
    Address(Address),
    /// This token defines or refers to a function. Clicking navigates
    /// to the function definition.
    Function(String),
    /// This token is a goto label definition or reference.
    Label(String),
    /// This token is a variable reference; clicking highlights all uses.
    Variable(String),
}

/// A single token in the decompiled C output with full metadata for
/// syntax highlighting and interaction.
///
/// Each token represents one atomic piece of the decompiled source:
/// a keyword, an identifier, a number, a string literal, an operator, etc.
/// Whitespace between tokens is also represented as tokens so the renderer
/// can preserve original column positions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CToken {
    /// The syntactic kind of this token.
    pub kind: CTokenKind,
    /// The raw text content.
    pub text: String,
    /// Line index (0-based).
    pub line: usize,
    /// Column position (0-based) within the line.
    pub col: usize,
    /// Navigation target for clickable tokens.
    pub navigation: TokenNavigation,
    /// Whether this token is a bracket character: `(`, `)`, `{`, `}`, `[`, `]`.
    pub is_bracket: bool,
    /// The bracket character, if this is a bracket token.
    pub bracket_char: Option<char>,
    /// Whether this bracket opens a pair.
    pub bracket_is_open: bool,
    /// Whether this bracket closes a pair.
    pub bracket_is_close: bool,
}

impl CToken {
    /// Create a new token with the given kind and text.
    pub fn new(kind: CTokenKind, text: impl Into<String>, line: usize, col: usize) -> Self {
        let text_str: String = text.into();
        let (is_bracket, bracket_char, bracket_is_open, bracket_is_close) =
            classify_bracket(&text_str, kind);
        Self {
            kind,
            text: text_str,
            line,
            col,
            navigation: TokenNavigation::None,
            is_bracket,
            bracket_char,
            bracket_is_open,
            bracket_is_close,
        }
    }

    /// Create a whitespace token.
    pub fn whitespace(text: impl Into<String>, line: usize, col: usize) -> Self {
        Self::new(CTokenKind::Whitespace, text, line, col)
    }

    /// Create a token with navigation target.
    pub fn with_navigation(mut self, nav: TokenNavigation) -> Self {
        self.navigation = nav;
        self
    }
}

/// Classify whether a token is a bracket (opening or closing).
fn classify_bracket(text: &str, kind: CTokenKind) -> (bool, Option<char>, bool, bool) {
    if kind != CTokenKind::Punctuation {
        return (false, None, false, false);
    }
    match text {
        "{" => (true, Some('{'), true, false),
        "}" => (true, Some('}'), false, true),
        "(" => (true, Some('('), true, false),
        ")" => (true, Some(')'), false, true),
        "[" => (true, Some('['), true, false),
        "]" => (true, Some(']'), false, true),
        _ => (false, None, false, false),
    }
}

// ============================================================================
// Syntax Theme
// ============================================================================

/// Syntax highlighting colors for decompiler C tokens.
///
/// Each field controls the color of a different syntactic element in the
/// decompiler view. Colors use [`egui::Color32`].
///
/// Two pre-built themes are provided: [`SyntaxTheme::dark()`] and
/// [`SyntaxTheme::light()`].
#[derive(Debug, Clone)]
pub struct SyntaxTheme {
    /// Color for C keywords (bold purple in Ghidra's own theme).
    pub keyword_color: egui::Color32,
    /// Color for type names (teal/cyan).
    pub type_color: egui::Color32,
    /// Color for identifiers — variables, parameters, local names.
    pub identifier_color: egui::Color32,
    /// Color for function names in call expressions.
    pub function_name_color: egui::Color32,
    /// Color for numeric literals (hex, decimal, octal).
    pub number_color: egui::Color32,
    /// Color for string literals.
    pub string_color: egui::Color32,
    /// Color for character literals.
    pub char_color: egui::Color32,
    /// Color for comments.
    pub comment_color: egui::Color32,
    /// Color for preprocessor directives.
    pub preprocessor_color: egui::Color32,
    /// Color for operators.
    pub operator_color: egui::Color32,
    /// Color for punctuation delimiters.
    pub punctuation_color: egui::Color32,
    /// Color for address references (clickable links).
    pub address_ref_color: egui::Color32,
    /// Color for goto label definitions.
    pub label_def_color: egui::Color32,
    /// Default fallback color.
    pub default_color: egui::Color32,

    // Background colors
    /// Background for the decompiler code area.
    pub background: egui::Color32,
    /// Background for the current cursor line.
    pub cursor_line_bg: egui::Color32,
    /// Background for the selected text.
    pub selection_bg: egui::Color32,
    /// Background for the line-number gutter.
    pub gutter_bg: egui::Color32,
    /// Background color for bracket match highlights.
    pub bracket_match_bg: egui::Color32,
    /// Border/outline color for bracket match highlights.
    pub bracket_match_border: egui::Color32,
    /// Background for highlights of variable uses.
    pub highlight_bg: egui::Color32,
    /// Color for line numbers in the gutter.
    pub line_number_color: egui::Color32,
    /// Color for the header bar.
    pub header_text: egui::Color32,
    /// Background for the header bar.
    pub header_bg: egui::Color32,
}

impl SyntaxTheme {
    /// The Ghidra-inspired dark theme.
    pub fn dark() -> Self {
        Self {
            // Foreground colors
            keyword_color: egui::Color32::from_rgb(200, 120, 255), // Bold purple
            type_color: egui::Color32::from_rgb(100, 200, 180),    // Teal
            identifier_color: egui::Color32::from_rgb(220, 220, 220), // White-ish
            function_name_color: egui::Color32::from_rgb(220, 220, 100), // Yellow
            number_color: egui::Color32::from_rgb(150, 220, 150),  // Light green
            string_color: egui::Color32::from_rgb(255, 180, 100),  // Orange
            char_color: egui::Color32::from_rgb(255, 200, 150),    // Light orange
            comment_color: egui::Color32::from_rgb(100, 170, 100), // Dark green
            preprocessor_color: egui::Color32::from_rgb(180, 150, 120), // Brown
            operator_color: egui::Color32::from_rgb(180, 180, 190), // Light gray
            punctuation_color: egui::Color32::from_rgb(200, 200, 210), // Almost white
            address_ref_color: egui::Color32::from_rgb(100, 180, 255), // Blue/cyan
            label_def_color: egui::Color32::from_rgb(255, 200, 100), // Gold
            default_color: egui::Color32::from_rgb(200, 200, 200), // Light gray

            // Background colors
            background: egui::Color32::from_rgb(30, 30, 35),
            cursor_line_bg: egui::Color32::from_rgba_premultiplied(255, 255, 100, 25),
            selection_bg: egui::Color32::from_rgba_premultiplied(80, 140, 255, 45),
            gutter_bg: egui::Color32::from_rgb(40, 40, 45),
            bracket_match_bg: egui::Color32::from_rgba_premultiplied(255, 255, 100, 60),
            bracket_match_border: egui::Color32::from_rgb(255, 255, 100),
            highlight_bg: egui::Color32::from_rgba_premultiplied(100, 100, 255, 40),
            line_number_color: egui::Color32::from_rgb(120, 120, 130),
            header_text: egui::Color32::from_rgb(180, 200, 220),
            header_bg: egui::Color32::from_rgb(45, 45, 55),
        }
    }

    /// A light theme variant.
    pub fn light() -> Self {
        Self {
            keyword_color: egui::Color32::from_rgb(140, 40, 180),
            type_color: egui::Color32::from_rgb(0, 130, 130),
            identifier_color: egui::Color32::from_rgb(30, 30, 30),
            function_name_color: egui::Color32::from_rgb(0, 0, 180),
            number_color: egui::Color32::from_rgb(0, 140, 0),
            string_color: egui::Color32::from_rgb(160, 80, 0),
            char_color: egui::Color32::from_rgb(180, 100, 0),
            comment_color: egui::Color32::from_rgb(0, 130, 0),
            preprocessor_color: egui::Color32::from_rgb(140, 100, 60),
            operator_color: egui::Color32::from_rgb(80, 80, 90),
            punctuation_color: egui::Color32::from_rgb(40, 40, 40),
            address_ref_color: egui::Color32::from_rgb(0, 80, 200),
            label_def_color: egui::Color32::from_rgb(180, 120, 0),
            default_color: egui::Color32::from_rgb(20, 20, 20),

            background: egui::Color32::from_rgb(250, 250, 252),
            cursor_line_bg: egui::Color32::from_rgba_premultiplied(255, 255, 200, 60),
            selection_bg: egui::Color32::from_rgba_premultiplied(100, 160, 255, 50),
            gutter_bg: egui::Color32::from_rgb(235, 235, 238),
            bracket_match_bg: egui::Color32::from_rgba_premultiplied(255, 255, 100, 80),
            bracket_match_border: egui::Color32::from_rgb(200, 180, 0),
            highlight_bg: egui::Color32::from_rgba_premultiplied(100, 100, 255, 35),
            line_number_color: egui::Color32::from_rgb(140, 140, 150),
            header_text: egui::Color32::from_rgb(40, 40, 50),
            header_bg: egui::Color32::from_rgb(225, 228, 235),
        }
    }
}

impl Default for SyntaxTheme {
    fn default() -> Self {
        Self::dark()
    }
}

// ============================================================================
// Selection and Range Types
// ============================================================================

/// A position in the decompiler source: line and column (both 0-based).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TextPosition {
    /// 0-based line index.
    pub line: usize,
    /// 0-based column index.
    pub col: usize,
}

impl TextPosition {
    /// Create a new text position.
    pub fn new(line: usize, col: usize) -> Self {
        Self { line, col }
    }

    /// Zero/start position.
    pub fn zero() -> Self {
        Self { line: 0, col: 0 }
    }

    /// Return the minimum of two positions (earlier in the source).
    pub fn min(self, other: TextPosition) -> TextPosition {
        if self.line < other.line || (self.line == other.line && self.col <= other.col) {
            self
        } else {
            other
        }
    }

    /// Return the maximum of two positions.
    pub fn max(self, other: TextPosition) -> TextPosition {
        if self.line > other.line || (self.line == other.line && self.col >= other.col) {
            self
        } else {
            other
        }
    }
}

/// A contiguous range of text in the decompiler source, defined by
/// start and end positions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TextRange {
    /// The start position (always <= end after normalization).
    pub start: TextPosition,
    /// The end position (always >= start after normalization).
    pub end: TextPosition,
}

impl TextRange {
    /// Create a new text range, normalizing so start <= end.
    pub fn new(pos1: TextPosition, pos2: TextPosition) -> Self {
        let start = pos1.min(pos2);
        let end = pos1.max(pos2);
        Self { start, end }
    }

    /// Create a range covering a single position.
    pub fn single(pos: TextPosition) -> Self {
        Self {
            start: pos,
            end: pos,
        }
    }

    /// Check whether this range contains the given position.
    pub fn contains(&self, pos: TextPosition) -> bool {
        (self.start.line < pos.line || (self.start.line == pos.line && self.start.col <= pos.col))
            && (self.end.line > pos.line || (self.end.line == pos.line && self.end.col >= pos.col))
    }

    /// Check whether this range intersects the given line.
    pub fn intersects_line(&self, line: usize) -> bool {
        line >= self.start.line && line <= self.end.line
    }

    /// Check whether the range is empty (no selection).
    pub fn is_empty(&self) -> bool {
        self.start == self.end
    }

    /// Return the selected text from the tokenized lines.
    pub fn selected_text(&self, tokens: &[Vec<CToken>]) -> String {
        let mut result = String::new();
        for (line_idx, line_tokens) in tokens.iter().enumerate() {
            if !self.intersects_line(line_idx) {
                continue;
            }
            for token in line_tokens {
                let token_end_col = token.col + token.text.len();
                let tok_start = TextPosition::new(line_idx, token.col);
                let tok_end = TextPosition::new(line_idx, token_end_col);

                if tok_end <= self.start || tok_start >= self.end {
                    continue;
                }

                // Token is at least partially selected
                let start_offset = if self.start.line == line_idx && self.start.col > token.col {
                    self.start.col - token.col
                } else {
                    0
                };
                let end_offset =
                    if self.end.line == line_idx && self.end.col < token.col + token.text.len() {
                        self.end.col - token.col
                    } else {
                        token.text.len()
                    };

                if start_offset < end_offset && start_offset < token.text.len() {
                    result.push_str(&token.text[start_offset..end_offset.min(token.text.len())]);
                }
            }
            if line_idx < self.end.line && !result.ends_with('\n') {
                result.push('\n');
            }
        }
        result
    }

    /// Clone the selected text to the given string, for copy operations.
    pub fn copy_to(&self, tokens: &[Vec<CToken>], output: &mut String) {
        output.clear();
        output.push_str(&self.selected_text(tokens));
    }
}

// ============================================================================
// Folding Regions
// ============================================================================

/// Describes the kind of a folding region.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FoldKind {
    /// A brace-delimited compound statement: `{ ... }`.
    BraceBlock,
    /// A multi-line comment: `/* ... */`.
    MultiLineComment,
}

/// A foldable region of code.
///
/// Code folding allows collapsing a range of lines (e.g., a `{ ... }` block)
/// so that only the first line is visible with a `[+]` indicator in the gutter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoldRegion {
    /// The line where the region starts (the line with the opening brace).
    pub start_line: usize,
    /// The line where the region ends (the line with the closing brace).
    pub end_line: usize,
    /// Nesting depth (for indentation calculations).
    pub depth: usize,
    /// The kind of foldable region.
    pub kind: FoldKind,
}

impl FoldRegion {
    /// Number of lines visible when this region is folded (just the start line).
    pub const fn folded_visible_lines(&self) -> usize {
        1
    }
}

// ============================================================================
// Bracket Matching
// ============================================================================

/// The type of a bracket pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BracketKind {
    /// Curly braces: `{` ... `}`
    Brace,
    /// Parentheses: `(` ... `)`
    Paren,
    /// Square brackets: `[` ... `]`
    Bracket,
}

impl BracketKind {
    /// The opening character for this bracket kind.
    pub fn open_char(self) -> char {
        match self {
            BracketKind::Brace => '{',
            BracketKind::Paren => '(',
            BracketKind::Bracket => '[',
        }
    }

    /// The closing character for this bracket kind.
    pub fn close_char(self) -> char {
        match self {
            BracketKind::Brace => '}',
            BracketKind::Paren => ')',
            BracketKind::Bracket => ']',
        }
    }
}

/// A matched pair of brackets in the source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BracketPair {
    /// Position of the opening bracket.
    pub open: TextPosition,
    /// Position of the closing bracket.
    pub close: TextPosition,
    /// The kind of bracket pair.
    pub kind: BracketKind,
}

// ============================================================================
// Function / Variable / Label Definitions
// ============================================================================

/// A function definition found in the decompiled output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionDef {
    /// The function name.
    pub name: String,
    /// The line where the function definition starts.
    pub line: usize,
    /// The line where the function body starts (line with opening brace).
    pub body_start: usize,
    /// The line where the function ends (line with closing brace).
    pub body_end: usize,
    /// The address of this function in the binary (if known).
    pub address: Option<Address>,
}

/// A goto label definition found in the decompiled output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LabelDef {
    /// The label name (e.g., "LAB_00100400").
    pub name: String,
    /// The line where the label is defined.
    pub line: usize,
}

/// A variable reference found in the decompiled output.
/// Used to track all occurrences of a variable for highlighting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VariableRef {
    /// The variable name.
    pub name: String,
    /// All positions where this variable appears.
    pub occurrences: Vec<TextPosition>,
}

// ============================================================================
// Decompiler View State
// ============================================================================

/// The complete state of the decompiler view.
///
/// Holds the tokenized decompiled output, cursor position, selection,
/// folding state, bracket matching, and all navigation/highlighting metadata.
pub struct DecompilerViewState {
    /// The full original decompiled C code as a single string.
    pub code: String,

    /// Tokenized lines for syntax highlighting and interaction.
    /// Each inner vector represents one line of tokens.
    pub tokens: Vec<Vec<CToken>>,

    /// Per-line address mapping.  `line_addresses[i]` is the primary
    /// assembly address (if any) that source line `i` decompiles from.
    /// Used for scroll synchronization and double-click navigation.
    pub line_addresses: Vec<Option<Address>>,

    /// The set of line indices where folding regions start and are
    /// currently folded (collapsed).
    pub folded_regions: HashSet<usize>,

    /// All computed foldable regions in the current code.
    pub fold_regions: Vec<FoldRegion>,

    /// All computed bracket pairs in the current code.
    pub bracket_pairs: Vec<BracketPair>,

    /// Current cursor / caret position.
    pub cursor_line: usize,
    pub cursor_col: usize,

    /// Current text selection, if any.
    pub selection: Option<TextRange>,

    /// Font size for the code display.
    pub font_size: f32,

    /// Whether to show line numbers in the gutter.
    pub show_line_numbers: bool,

    /// The syntax coloring theme.
    pub syntax_theme: SyntaxTheme,

    /// The name of the function currently being displayed.
    pub current_function: Option<String>,

    /// All function definitions parsed from the code.
    pub functions: Vec<FunctionDef>,

    /// All goto label definitions parsed from the code.
    pub labels: Vec<LabelDef>,

    /// All variable references (name -> positions).
    pub variables: HashMap<String, VariableRef>,

    /// The variable name whose occurrences should be highlighted.
    /// Set when the user clicks on a variable name.
    pub highlighted_variable: Option<String>,

    /// Scroll position (in pixels from top) for synchronization with
    /// the listing view.
    pub scroll_offset: f32,

    /// Whether the view was last scrolled by the user (true) or by
    /// programmatic sync (false).  Used to avoid feedback loops.
    pub user_scrolled: bool,

    /// Whether to show the source code with addresses in a comment column.
    pub show_address_comments: bool,

    /// Total line count (cached for efficiency).
    pub total_lines: usize,

    /// Pending navigation action produced by the renderer.
    /// The application consumes this each frame.
    pub pending_navigation: Option<DecompilerNavigation>,
}

/// Navigation actions emitted by the decompiler view.
#[derive(Debug, Clone)]
pub enum DecompilerNavigation {
    /// No pending navigation.
    None,
    /// Navigate the listing view to this address.
    NavigateToAddress(Address),
    /// Navigate to a function definition line.
    NavigateToFunction(String),
    /// Navigate to a goto label definition line.
    NavigateToLabel(String),
}

impl DecompilerViewState {
    /// Create a new empty decompiler view state with default settings.
    pub fn new() -> Self {
        Self {
            code: String::new(),
            tokens: Vec::new(),
            line_addresses: Vec::new(),
            folded_regions: HashSet::new(),
            fold_regions: Vec::new(),
            bracket_pairs: Vec::new(),
            cursor_line: 0,
            cursor_col: 0,
            selection: None,
            font_size: 12.0,
            show_line_numbers: true,
            syntax_theme: SyntaxTheme::dark(),
            current_function: None,
            functions: Vec::new(),
            labels: Vec::new(),
            variables: HashMap::new(),
            highlighted_variable: None,
            scroll_offset: 0.0,
            user_scrolled: true,
            show_address_comments: false,
            total_lines: 0,
            pending_navigation: None,
        }
    }

    // ------------------------------------------------------------------
    // Code loading
    // ------------------------------------------------------------------

    /// Load decompiled C code into the view, replacing any existing content.
    ///
    /// `addresses` is an optional per-line mapping from source line index
    /// to the corresponding assembly address.
    pub fn load_code(
        &mut self,
        code: impl Into<String>,
        function: Option<String>,
        addresses: Option<Vec<Option<Address>>>,
    ) {
        self.code = code.into();
        self.current_function = function;
        self.line_addresses = addresses.unwrap_or_default();
        self.tokenize();
        self.compute_fold_regions();
        self.compute_bracket_pairs();
        self.extract_definitions();
        self.cursor_line = 0;
        self.cursor_col = 0;
        self.selection = None;
        self.folded_regions.clear();
        self.scroll_offset = 0.0;
        self.total_lines = self.tokens.len();
    }

    /// Load demo decompiled code for testing and demonstration.
    pub fn load_demo(&mut self) {
        let code = r#"// Decompiled from demo.bin
// Function: main @ 0x1000
// Architecture: x86-64

int main(int argc, char **argv) {
    int result;
    char *msg;
    int i;
    int j;
    long counter;
    unsigned int flags;
    size_t len;

    msg = "Hello, World!\n";
    result = 0;
    counter = 0x1000;
    flags = 0xDEADBEEF;
    len = 0;

    if (argc > 1) {
        msg = argv[1];
        result = 1;
        len = strlen(msg);
        if (len > 0x100) {
            msg = "input too long";
            result = -1;
            goto error_exit;
        }
    }
    else {
        msg = "default message";
        len = 0xf;
    }

    printf("Program started with %d args\n", argc);
    printf("Message: %s\n", msg);

    for (i = 0; i < 10; i = i + 1) {
        if ((i & 1) == 0) {
            printf("even: %d\n", i);
        }
        else {
            printf("odd: %d\n", i);
        }
    }

    j = 0;
    while (j < 5) {
        char buf[0x20];
        snprintf(buf, 0x20, "Loop iteration %d", j);
        puts(buf);
        j = j + 1;
    }

    switch (result) {
    case 0:
        printf("Success\n");
        break;
    case 1:
        printf("Custom message used\n");
        break;
    case -1:
        error_exit:
        printf("Error occurred\n");
        break;
    default:
        printf("Unknown result: %d\n", result);
        break;
    }

    if (flags & 1) {
        int k;
        for (k = 0; k < 3; k = k + 1) {
            printf("Flag bit 0 is set: iter %d\n", k);
        }
    }

    /* Multi-line comment block
       explaining the final cleanup:
       - free allocated resources
       - close file handles
       - return result code */
    return result;
}

// Helper function: check_flag
// @ 0x1200
int check_flag(unsigned int flags, int bit) {
    return (flags >> bit) & 1;
}
"#;
        // Build address mapping: main at 0x1000, check_flag at 0x1200
        let addresses: Vec<Option<Address>> = code
            .lines()
            .enumerate()
            .map(|(i, _line)| {
                if i < 60 {
                    // main function lines map to sequential addresses from 0x1000
                    Some(Address::new(0x1000 + (i as u64)))
                } else {
                    // check_flag lines map to sequential addresses from 0x1200
                    Some(Address::new(0x1200 + ((i - 60) as u64)))
                }
            })
            .collect();

        self.load_code(code, Some("main".to_string()), Some(addresses));
    }

    // ------------------------------------------------------------------
    // Tokenization
    // ------------------------------------------------------------------

    /// Tokenize the current code into lines of [`CToken`] with full metadata.
    ///
    /// This is called automatically by [`load_code`].
    pub fn tokenize(&mut self) {
        self.tokens.clear();
        let lines: Vec<&str> = self.code.lines().collect();

        for (line_idx, line) in lines.iter().enumerate() {
            let tokens = tokenize_line(line, line_idx, self.current_function.as_deref());
            self.tokens.push(tokens);
        }

        // Ensure line_addresses has an entry per line
        while self.line_addresses.len() < self.tokens.len() {
            self.line_addresses.push(None);
        }
    }

    /// Re-tokenize after modification (e.g., after folding changes).
    pub fn retokenize(&mut self) {
        self.tokenize();
        self.compute_fold_regions();
        self.compute_bracket_pairs();
        self.extract_definitions();
        self.total_lines = self.tokens.len();
    }

    // ------------------------------------------------------------------
    // Folding
    // ------------------------------------------------------------------

    /// Compute all foldable regions from the token stream.
    ///
    /// Finds brace-delimited `{ ... }` blocks and multi-line `/* ... */`
    /// comments and records them as [`FoldRegion`] entries.
    pub fn compute_fold_regions(&mut self) {
        self.fold_regions.clear();

        // Collect all bracket positions (line by line)
        let mut bracket_stack: Vec<(usize, FoldKind)> = Vec::new();

        for (line_idx, line_tokens) in self.tokens.iter().enumerate() {
            let mut in_comment = false;
            for token in line_tokens {
                // Track multi-line comments
                if token.kind == CTokenKind::Comment {
                    if token.text.starts_with("/*") && !token.text.ends_with("*/") {
                        in_comment = true;
                    }
                    if token.text.ends_with("*/") && !token.text.starts_with("/*") {
                        in_comment = false;
                    }
                }

                if !token.is_bracket {
                    continue;
                }

                if token.bracket_is_open && token.bracket_char == Some('{') {
                    bracket_stack.push((line_idx, FoldKind::BraceBlock));
                } else if token.bracket_is_close && token.bracket_char == Some('}') {
                    if let Some((start_line, kind)) = bracket_stack.pop() {
                        if start_line < line_idx {
                            let depth = bracket_stack.len();
                            self.fold_regions.push(FoldRegion {
                                start_line,
                                end_line: line_idx,
                                depth,
                                kind,
                            });
                        }
                    }
                }
            }

            // Handle multi-line comment regions
            if in_comment {
                // Find the start by scanning backward
                let mut _comment_start = line_idx;
                for prev in (0..line_idx).rev() {
                    if let Some(tokens) = self.tokens.get(prev) {
                        if tokens
                            .iter()
                            .any(|t| t.kind == CTokenKind::Comment && t.text.starts_with("/*"))
                        {
                            _comment_start = prev;
                            break;
                        }
                    }
                }
                // We'll close this when we find the end — handled above
            }
        }
    }

    /// Toggle folding at the given line.
    ///
    /// If the line starts a foldable region, toggle it between folded and
    /// unfolded states.
    pub fn toggle_fold(&mut self, line: usize) {
        if self.folded_regions.contains(&line) {
            self.folded_regions.remove(&line);
        } else {
            // Check if there's a fold region starting at this line
            let has_region = self.fold_regions.iter().any(|r| r.start_line == line);
            if has_region {
                self.folded_regions.insert(line);
            }
        }
    }

    /// Fold all regions.
    pub fn fold_all(&mut self) {
        for region in &self.fold_regions {
            self.folded_regions.insert(region.start_line);
        }
    }

    /// Unfold all regions.
    pub fn unfold_all(&mut self) {
        self.folded_regions.clear();
    }

    /// Check whether a line is currently visible (not hidden by a folded ancestor).
    pub fn is_line_visible(&self, line: usize) -> bool {
        if line >= self.tokens.len() {
            return false;
        }

        // Find all fold regions that contain this line
        for region in &self.fold_regions {
            if line > region.start_line && line <= region.end_line {
                if self.folded_regions.contains(&region.start_line) {
                    // Check if an ancestor is also folded (nested folding)
                    // Walk up to find the outermost folded ancestor
                    let is_folded = true;
                    // Look for a containing region whose start line is also folded,
                    // and whose range fully contains the current region
                    for outer in &self.fold_regions {
                        if outer.start_line < region.start_line
                            && outer.end_line >= region.end_line
                            && line > outer.start_line
                            && line <= outer.end_line
                            && self.folded_regions.contains(&outer.start_line)
                        {
                            // Outer is folded too
                            continue;
                        }
                    }
                    // If the innermost folding containing this line is folded,
                    // the line is hidden
                    if is_folded {
                        return false;
                    }
                }
            }
        }

        // Simple check: for each folded region, check if this line falls inside
        for region in &self.fold_regions {
            if self.folded_regions.contains(&region.start_line) {
                if line > region.start_line && line <= region.end_line {
                    return false;
                }
            }
        }

        true
    }

    /// Get the list of lines that would be visible given current folding state.
    pub fn visible_lines(&self) -> Vec<usize> {
        (0..self.tokens.len())
            .filter(|&line| self.is_line_visible(line))
            .collect()
    }

    /// Get the visible line count.
    pub fn visible_line_count(&self) -> usize {
        (0..self.tokens.len())
            .filter(|&line| self.is_line_visible(line))
            .count()
    }

    // ------------------------------------------------------------------
    // Bracket matching
    // ------------------------------------------------------------------

    /// Compute all bracket pairs from the token stream.
    pub fn compute_bracket_pairs(&mut self) {
        self.bracket_pairs.clear();

        // Stacks for each bracket type
        let mut brace_stack: Vec<TextPosition> = Vec::new();
        let mut paren_stack: Vec<TextPosition> = Vec::new();
        let mut bracket_stack: Vec<TextPosition> = Vec::new();

        for (line_idx, line_tokens) in self.tokens.iter().enumerate() {
            for token in line_tokens {
                if !token.is_bracket {
                    continue;
                }

                let pos = TextPosition::new(line_idx, token.col);

                match (
                    token.bracket_char,
                    token.bracket_is_open,
                    token.bracket_is_close,
                ) {
                    (Some('{'), true, false) => brace_stack.push(pos),
                    (Some('}'), false, true) => {
                        if let Some(open_pos) = brace_stack.pop() {
                            self.bracket_pairs.push(BracketPair {
                                open: open_pos,
                                close: pos,
                                kind: BracketKind::Brace,
                            });
                        }
                    }
                    (Some('('), true, false) => paren_stack.push(pos),
                    (Some(')'), false, true) => {
                        if let Some(open_pos) = paren_stack.pop() {
                            self.bracket_pairs.push(BracketPair {
                                open: open_pos,
                                close: pos,
                                kind: BracketKind::Paren,
                            });
                        }
                    }
                    (Some('['), true, false) => bracket_stack.push(pos),
                    (Some(']'), false, true) => {
                        if let Some(open_pos) = bracket_stack.pop() {
                            self.bracket_pairs.push(BracketPair {
                                open: open_pos,
                                close: pos,
                                kind: BracketKind::Bracket,
                            });
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    /// Find the matching bracket for the token at the given position.
    ///
    /// Returns the position of the matching bracket and the kind of the pair,
    /// or `None` if the cursor is not on a bracket or no match exists.
    pub fn find_matching_bracket(
        &self,
        line: usize,
        col: usize,
    ) -> Option<(TextPosition, BracketKind)> {
        let pos = TextPosition::new(line, col);

        for pair in &self.bracket_pairs {
            if pair.open == pos {
                return Some((pair.close, pair.kind));
            }
            if pair.close == pos {
                return Some((pair.open, pair.kind));
            }
        }

        None
    }

    /// Find the bracket pair that contains the cursor position.
    pub fn bracket_pair_at_cursor(&self) -> Option<&BracketPair> {
        let pos = TextPosition::new(self.cursor_line, self.cursor_col);

        for pair in &self.bracket_pairs {
            if pair.open == pos || pair.close == pos {
                return Some(pair);
            }
        }

        None
    }

    // ------------------------------------------------------------------
    // Definitions extraction
    // ------------------------------------------------------------------

    /// Extract function definitions, label definitions, and variable
    /// references from the token stream for navigation and highlighting.
    pub fn extract_definitions(&mut self) {
        self.functions.clear();
        self.labels.clear();
        self.variables.clear();

        let mut current_func: Option<FunctionDef> = None;
        let mut seen_variables: HashMap<String, Vec<TextPosition>> = HashMap::new();

        for (line_idx, line_tokens) in self.tokens.iter().enumerate() {
            // Detect function definitions: return_type name ( params ) {
            // We look for a pattern: type keyword, then identifier, then '(' on the same line
            let mut i = 0;
            while i < line_tokens.len() {
                let token = &line_tokens[i];

                // Track variable/identifier occurrences
                if token.kind == CTokenKind::Identifier || token.kind == CTokenKind::FunctionName {
                    let pos = TextPosition::new(line_idx, token.col);
                    seen_variables
                        .entry(token.text.clone())
                        .or_default()
                        .push(pos);
                }

                // Detect label definitions: identifier followed by ':'
                if i + 1 < line_tokens.len() {
                    let next = &line_tokens[i + 1];
                    if token.kind == CTokenKind::Identifier
                        && next.kind == CTokenKind::Operator
                        && next.text == ":"
                    {
                        // Check that this looks like a label (not a case/default label)
                        let is_goto_label = token.text.starts_with("LAB_")
                            || token.text.starts_with("lab_")
                            || token.text.starts_with("loc_");
                        let is_label = is_goto_label
                            || (token.text.chars().all(|c| c.is_alphanumeric() || c == '_')
                                && !is_case_or_default(&token.text));

                        if is_label {
                            self.labels.push(LabelDef {
                                name: token.text.clone(),
                                line: line_idx,
                            });
                        }
                    }
                }

                // Detect function signatures
                if let Some(ref mut func) = current_func {
                    // Look for closing brace that ends the function body
                    if token.bracket_is_close && token.bracket_char == Some('}') {
                        func.body_end = line_idx;
                        let name = func.name.clone();
                        self.functions.push(func.clone());
                        current_func = None;

                        // Also register the function name as a variable entry for highlighting
                        if let Some(first_func_line) = self.functions.last() {
                            let pos = TextPosition::new(first_func_line.line, 0);
                            seen_variables.entry(name).or_default().push(pos);
                        }
                    }
                } else if token.kind == CTokenKind::TypeName && i + 1 < line_tokens.len() {
                    // Possible function definition: type name identifier ( params
                    let next_token = &line_tokens[i + 1];
                    if next_token.kind == CTokenKind::Identifier
                        || next_token.kind == CTokenKind::FunctionName
                    {
                        let potential_name = next_token.text.clone();
                        // Look ahead for '('
                        let mut found_paren = false;
                        for j in (i + 2)..line_tokens.len() {
                            if line_tokens[j].text == "(" {
                                found_paren = true;
                                break;
                            }
                            if line_tokens[j].text == "{" || line_tokens[j].text == ";" {
                                break;
                            }
                        }
                        if found_paren {
                            current_func = Some(FunctionDef {
                                name: potential_name.clone(),
                                line: line_idx,
                                body_start: 0,
                                body_end: 0,
                                address: self.line_addresses.get(line_idx).and_then(|a| *a),
                            });

                            // Annotate the function name token
                            if let Some(_name_pos) = self.find_token_at(line_idx, next_token.col) {
                                // Mark as function name
                            }
                        }
                    }
                }

                i += 1;
            }
        }

        // Finalize any incomplete function
        if let Some(mut func) = current_func {
            func.body_end = self.tokens.len().saturating_sub(1);
            self.functions.push(func);
        }

        // Convert variable occurrences to VariableRef
        for (name, positions) in seen_variables {
            if positions.len() >= 1 {
                self.variables.insert(
                    name,
                    VariableRef {
                        name: String::new(), // filled below
                        occurrences: positions,
                    },
                );
            }
        }
        // Fix: set name field
        for (key, var) in self.variables.iter_mut() {
            var.name = key.clone();
        }
    }

    // ------------------------------------------------------------------
    // Cursor and selection
    // ------------------------------------------------------------------

    /// Set the cursor position, clearing any selection.
    pub fn set_cursor(&mut self, line: usize, col: usize) {
        self.cursor_line = line.min(self.tokens.len().saturating_sub(1));
        self.cursor_col = col;
        self.selection = None;
    }

    /// Start a selection from the current cursor position to the given position.
    pub fn select_to(&mut self, line: usize, col: usize) {
        let start = TextPosition::new(self.cursor_line, self.cursor_col);
        let end = TextPosition::new(line, col);
        self.selection = Some(TextRange::new(start, end));
    }

    /// Extend the current selection to the given position.
    pub fn extend_selection(&mut self, line: usize, col: usize) {
        let pos = TextPosition::new(line, col);
        match self.selection {
            Some(ref range) => {
                // Extend from whichever end is closer
                self.selection = Some(TextRange::new(range.start, pos));
            }
            None => {
                let cursor = TextPosition::new(self.cursor_line, self.cursor_col);
                self.selection = Some(TextRange::new(cursor, pos));
            }
        }
        self.cursor_line = line;
        self.cursor_col = col;
    }

    /// Clear the current selection.
    pub fn clear_selection(&mut self) {
        self.selection = None;
    }

    /// Check if a position is within the current selection.
    pub fn is_position_selected(&self, line: usize, col: usize) -> bool {
        match self.selection {
            Some(ref range) => range.contains(TextPosition::new(line, col)),
            None => false,
        }
    }

    /// Select all text in the view.
    pub fn select_all(&mut self) {
        if self.tokens.is_empty() {
            return;
        }
        let last_line = self.tokens.len().saturating_sub(1);
        let last_col = self.tokens[last_line]
            .last()
            .map(|t| t.col + t.text.len())
            .unwrap_or(0);

        self.selection = Some(TextRange::new(
            TextPosition::zero(),
            TextPosition::new(last_line, last_col),
        ));
    }

    /// Get the currently selected text.
    pub fn selected_text(&self) -> String {
        match self.selection {
            Some(ref range) => range.selected_text(&self.tokens),
            None => String::new(),
        }
    }

    /// Copy selected text to the clipboards via egui output.
    pub fn copy_selection(&self, ui: &mut egui::Ui) {
        let text = self.selected_text();
        if !text.is_empty() {
            ui.output_mut(|o| o.copied_text = text);
        }
    }

    // ------------------------------------------------------------------
    // Click-to-navigate
    // ------------------------------------------------------------------

    /// Handle a click at the given position.  Determines if the click is on a
    /// navigable token (function, label, address, variable) and returns the
    /// corresponding action, or updates internal highlight state.
    pub fn handle_click(&mut self, line: usize, col: usize) -> Option<DecompilerNavigation> {
        self.set_cursor(line, col);

        if let Some(token) = self.find_token_at(line, col) {
            match &token.navigation {
                TokenNavigation::Address(addr) => {
                    return Some(DecompilerNavigation::NavigateToAddress(*addr));
                }
                TokenNavigation::Function(name) => {
                    return Some(DecompilerNavigation::NavigateToFunction(name.clone()));
                }
                TokenNavigation::Label(name) => {
                    return Some(DecompilerNavigation::NavigateToLabel(name.clone()));
                }
                TokenNavigation::Variable(name) => {
                    // Toggle variable highlight
                    if self.highlighted_variable.as_deref() == Some(name.as_str()) {
                        self.highlighted_variable = None;
                    } else {
                        self.highlighted_variable = Some(name.clone());
                    }
                }
                TokenNavigation::None => {
                    // If it's a plain identifier, still allow highlighting
                    if token.kind == CTokenKind::Identifier
                        || token.kind == CTokenKind::FunctionName
                    {
                        let name = &token.text;
                        if self.highlighted_variable.as_deref() == Some(name) {
                            self.highlighted_variable = None;
                        } else if self.variables.contains_key(name) {
                            self.highlighted_variable = Some(name.clone());
                        }
                    }
                }
            }
        }

        None
    }

    /// Handle a double-click at the given position.
    /// Double-click on any line navigates to its associated address, if any.
    pub fn handle_double_click(&mut self, line: usize) -> Option<DecompilerNavigation> {
        if let Some(Some(addr)) = self.line_addresses.get(line) {
            return Some(DecompilerNavigation::NavigateToAddress(*addr));
        }
        None
    }

    /// Navigate to a function definition by name.
    pub fn navigate_to_function(&mut self, name: &str) -> Option<usize> {
        for func in &self.functions {
            if func.name == name {
                self.cursor_line = func.line;
                self.cursor_col = 0;
                return Some(func.line);
            }
        }
        None
    }

    /// Navigate to a label definition by name.
    pub fn navigate_to_label(&mut self, name: &str) -> Option<usize> {
        for label in &self.labels {
            if label.name == name {
                self.cursor_line = label.line;
                self.cursor_col = 0;
                return Some(label.line);
            }
        }
        None
    }

    // ------------------------------------------------------------------
    // Token lookup
    // ------------------------------------------------------------------

    /// Find the token at the given (line, column) position.
    pub fn find_token_at(&self, line: usize, col: usize) -> Option<&CToken> {
        if line >= self.tokens.len() {
            return None;
        }
        let line_tokens = &self.tokens[line];
        for token in line_tokens {
            let end_col = token.col + token.text.len();
            if col >= token.col && col < end_col {
                return Some(token);
            }
        }
        None
    }

    /// Find the token at the current cursor position.
    pub fn token_at_cursor(&self) -> Option<&CToken> {
        self.find_token_at(self.cursor_line, self.cursor_col)
    }

    // ------------------------------------------------------------------
    // Get the address for a line (for scroll sync and navigation).
    // ------------------------------------------------------------------

    /// Get the assembly address associated with a source line.
    pub fn line_address(&self, line: usize) -> Option<Address> {
        self.line_addresses.get(line).and_then(|a| *a)
    }

    /// Get all visible line addresses for scroll sync.
    pub fn visible_addresses(&self) -> Vec<(usize, Address)> {
        (0..self.tokens.len())
            .filter_map(|line| {
                if self.is_line_visible(line) {
                    self.line_address(line).map(|addr| (line, addr))
                } else {
                    None
                }
            })
            .collect()
    }
}

impl Default for DecompilerViewState {
    fn default() -> Self {
        let mut state = Self::new();
        state.load_demo();
        state
    }
}

// ============================================================================
// Line Tokenizer
// ============================================================================

/// C keywords recognized by the tokenizer.
static C_KEYWORDS: &[&str] = &[
    "auto", "break", "case", "const", "continue", "default", "do", "else", "enum", "extern", "for",
    "goto", "if", "inline", "register", "restrict", "return", "sizeof", "static", "struct",
    "switch", "typedef", "union", "volatile", "while",
];

/// C type names recognized by the tokenizer.
static C_TYPES: &[&str] = &[
    "void",
    "char",
    "short",
    "int",
    "long",
    "float",
    "double",
    "signed",
    "unsigned",
    "size_t",
    "ssize_t",
    "ptrdiff_t",
    "uint8_t",
    "int8_t",
    "uint16_t",
    "int16_t",
    "uint32_t",
    "int32_t",
    "uint64_t",
    "int64_t",
    "bool",
    "byte",
    "word",
    "dword",
    "qword",
    "undefined",
    "undefined1",
    "undefined2",
    "undefined4",
    "undefined8",
    "uint",
    "ulong",
    "ushort",
    "wchar_t",
    "FILE",
    "va_list",
];

/// Built-in constants recognized by the tokenizer.
static C_CONSTANTS: &[&str] = &["NULL", "true", "false", "TRUE", "FALSE", "__null"];

/// Preprocessor directive keywords.
static _PREPROCESSOR_DIRECTIVES: &[&str] = &[
    "define", "include", "ifdef", "ifndef", "if", "else", "elif", "endif", "undef", "pragma",
    "error", "line",
];

/// Known function names for common library calls.
static KNOWN_FUNCTIONS: &[&str] = &[
    "printf",
    "fprintf",
    "sprintf",
    "snprintf",
    "scanf",
    "sscanf",
    "puts",
    "gets",
    "fgets",
    "fputs",
    "fopen",
    "fclose",
    "fread",
    "fwrite",
    "fseek",
    "ftell",
    "malloc",
    "calloc",
    "realloc",
    "free",
    "memcpy",
    "memmove",
    "memset",
    "memcmp",
    "strlen",
    "strcpy",
    "strncpy",
    "strcat",
    "strncat",
    "strcmp",
    "strncmp",
    "strchr",
    "strrchr",
    "strstr",
    "strtok",
    "atoi",
    "atol",
    "atof",
    "itoa",
    "exit",
    "abort",
    "assert",
    "perror",
    "__stack_chk_fail",
    "FUN_",
    "thunk_FUN_",
];

/// Check if a word is a case or default label keyword.
fn is_case_or_default(text: &str) -> bool {
    text == "case" || text == "default"
}

/// Tokenize a single line of C pseudocode into a vector of [`CToken`]s.
fn tokenize_line(line: &str, line_idx: usize, current_function: Option<&str>) -> Vec<CToken> {
    let mut tokens: Vec<CToken> = Vec::new();
    let chars: Vec<char> = line.chars().collect();
    let len = chars.len();
    let mut i = 0;
    let mut col = 0;

    while i < len {
        let ch = chars[i];

        // Scrub whitespace
        if ch.is_whitespace() {
            let start_col = col;
            let mut ws = String::new();
            while i < len && chars[i].is_whitespace() {
                ws.push(chars[i]);
                i += 1;
                col += 1;
            }
            tokens.push(CToken::whitespace(ws, line_idx, start_col));
            continue;
        }

        // Preprocessor directive
        if ch == '#' && (col == 0 || tokens.iter().all(|t| t.kind == CTokenKind::Whitespace)) {
            let start_col = col;
            let mut directive = String::new();
            while i < len {
                directive.push(chars[i]);
                i += 1;
                col += 1;
            }
            let _ = col;
            tokens.push(CToken::new(
                CTokenKind::Preprocessor,
                directive,
                line_idx,
                start_col,
            ));
            break;
        }

        // Single-line comment
        if ch == '/' && i + 1 < len && chars[i + 1] == '/' {
            let start_col = col;
            let mut comment = String::new();
            while i < len {
                comment.push(chars[i]);
                i += 1;
                col += 1;
            }
            let _ = col;
            tokens.push(CToken::new(
                CTokenKind::Comment,
                comment,
                line_idx,
                start_col,
            ));
            break;
        }

        // Multi-line comment start
        if ch == '/' && i + 1 < len && chars[i + 1] == '*' {
            let start_col = col;
            let mut comment = String::new();
            while i < len {
                comment.push(chars[i]);
                if i + 1 < len && chars[i] == '*' && chars[i + 1] == '/' {
                    comment.push(chars[i + 1]);
                    i += 2;
                    col += 2;
                    break;
                }
                i += 1;
                col += 1;
            }
            tokens.push(CToken::new(
                CTokenKind::Comment,
                comment,
                line_idx,
                start_col,
            ));
            continue;
        }

        // Character literal
        if ch == '\'' {
            let start_col = col;
            let mut char_lit = String::new();
            char_lit.push(chars[i]);
            i += 1;
            col += 1;
            while i < len {
                char_lit.push(chars[i]);
                if chars[i] == '\\' && i + 1 < len {
                    // Escape sequence inside char literal
                    i += 1;
                    col += 1;
                    char_lit.push(chars[i]);
                } else if chars[i] == '\'' {
                    i += 1;
                    col += 1;
                    break;
                }
                i += 1;
                col += 1;
            }
            tokens.push(CToken::new(
                CTokenKind::CharLiteral,
                char_lit,
                line_idx,
                start_col,
            ));
            continue;
        }

        // String literal
        if ch == '"' {
            let start_col = col;
            let mut string_lit = String::new();
            string_lit.push(chars[i]);
            i += 1;
            col += 1;
            while i < len {
                string_lit.push(chars[i]);
                if chars[i] == '\\' && i + 1 < len {
                    // Escape sequence
                    i += 1;
                    col += 1;
                    string_lit.push(chars[i]);
                } else if chars[i] == '"' {
                    i += 1;
                    col += 1;
                    break;
                }
                i += 1;
                col += 1;
            }
            tokens.push(CToken::new(
                CTokenKind::StringLiteral,
                string_lit,
                line_idx,
                start_col,
            ));
            continue;
        }

        // Numbers: hex (0x...), octal (0...), decimal
        if ch.is_ascii_digit() {
            let start_col = col;
            let mut num_str = String::new();
            let is_hex = ch == '0' && i + 1 < len && (chars[i + 1] == 'x' || chars[i + 1] == 'X');
            let is_octal = ch == '0' && i + 1 < len && chars[i + 1].is_ascii_digit();

            if is_hex {
                num_str.push(chars[i]); // '0'
                num_str.push(chars[i + 1]); // 'x'
                i += 2;
                col += 2;
                while i < len && (chars[i].is_ascii_hexdigit() || chars[i] == '_') {
                    num_str.push(chars[i]);
                    i += 1;
                    col += 1;
                }
            } else if is_octal {
                while i < len && chars[i] >= '0' && chars[i] <= '7' {
                    num_str.push(chars[i]);
                    i += 1;
                    col += 1;
                }
            } else {
                // Decimal (possibly with suffix u, l, ll, ul, etc.)
                while i < len && (chars[i].is_ascii_digit() || chars[i] == '_') {
                    num_str.push(chars[i]);
                    i += 1;
                    col += 1;
                }
                // Optional suffix
                while i < len && matches!(chars[i], 'u' | 'U' | 'l' | 'L') {
                    num_str.push(chars[i]);
                    i += 1;
                    col += 1;
                }
            }

            // Check if this number looks like an address reference
            if is_hex && num_str.len() >= 4 {
                let hex_part = &num_str[2..];
                if let Ok(addr_val) = u64::from_str_radix(hex_part, 16) {
                    // Heuristic: if the number has 4+ hex digits, treat as potential address
                    if hex_part.len() >= 4 {
                        let addr = Address::new(addr_val);
                        tokens.push(
                            CToken::new(CTokenKind::AddressRef, num_str, line_idx, start_col)
                                .with_navigation(TokenNavigation::Address(addr)),
                        );
                        continue;
                    }
                }
            }

            tokens.push(CToken::new(
                CTokenKind::Number,
                num_str,
                line_idx,
                start_col,
            ));
            continue;
        }

        // Identifiers, keywords, types
        if ch.is_alphabetic() || ch == '_' {
            let start_col = col;
            let mut word = String::new();
            while i < len && (chars[i].is_alphanumeric() || chars[i] == '_') {
                word.push(chars[i]);
                i += 1;
                col += 1;
            }

            let token = classify_word(&word, line_idx, start_col, current_function);
            tokens.push(token);
            continue;
        }

        // Multi-character operators
        let two_char = if i + 1 < len {
            Some(format!("{}{}", ch, chars[i + 1]))
        } else {
            None
        };

        let three_char = if i + 2 < len {
            Some(format!("{}{}{}", ch, chars[i + 1], chars[i + 2]))
        } else {
            None
        };

        // Check three-char operators first
        if let Some(ref op) = three_char {
            if matches!(op.as_str(), "<<=" | ">>=") {
                tokens.push(CToken::new(CTokenKind::Operator, op.clone(), line_idx, col));
                i += 3;
                col += 3;
                continue;
            }
        }

        // Check two-char operators
        if let Some(ref op) = two_char {
            if matches!(
                op.as_str(),
                "->" | "++"
                    | "--"
                    | "<<"
                    | ">>"
                    | "<="
                    | ">="
                    | "=="
                    | "!="
                    | "&&"
                    | "||"
                    | "+="
                    | "-="
                    | "*="
                    | "/="
                    | "%="
                    | "&="
                    | "|="
                    | "^="
                    | "::"
            ) {
                tokens.push(CToken::new(CTokenKind::Operator, op.clone(), line_idx, col));
                i += 2;
                col += 2;
                continue;
            }
        }

        // Single-char operators and punctuation
        if "+-*/%&|^~!<>=.,:;@#?".contains(ch) {
            let start_col = col;
            let kind = if ";,{}[]()".contains(ch) {
                CTokenKind::Punctuation
            } else {
                CTokenKind::Operator
            };
            tokens.push(CToken::new(kind, ch.to_string(), line_idx, start_col));
            i += 1;
            col += 1;
            continue;
        }

        // Punctuation brackets
        if "{}[]();,".contains(ch) {
            tokens.push(CToken::new(
                CTokenKind::Punctuation,
                ch.to_string(),
                line_idx,
                col,
            ));
            i += 1;
            col += 1;
            continue;
        }

        // Fallthrough: collect single char as unknown
        tokens.push(CToken::new(
            CTokenKind::Unknown,
            ch.to_string(),
            line_idx,
            col,
        ));
        i += 1;
        col += 1;
    }

    tokens
}

/// Classify a word token as keyword, type, constant, function name, or identifier.
fn classify_word(text: &str, line: usize, col: usize, current_function: Option<&str>) -> CToken {
    // Check if it's a keyword
    if C_KEYWORDS.contains(&text) {
        return CToken::new(CTokenKind::Keyword, text, line, col);
    }

    // Check if it's a type name
    if C_TYPES.contains(&text) {
        return CToken::new(CTokenKind::TypeName, text, line, col);
    }

    // Check if it's a built-in constant
    if C_CONSTANTS.contains(&text) {
        return CToken::new(CTokenKind::Keyword, text, line, col);
    }

    // Check if it's a known function name
    if KNOWN_FUNCTIONS
        .iter()
        .any(|f| text == *f || text.starts_with(f))
    {
        let token = CToken::new(CTokenKind::FunctionName, text, line, col);
        return token.with_navigation(TokenNavigation::Function(text.to_string()));
    }

    // Check if it's the current function being decompiled
    if current_function == Some(text) {
        let token = CToken::new(CTokenKind::FunctionName, text, line, col);
        return token.with_navigation(TokenNavigation::Function(text.to_string()));
    }

    // Check if it looks like a function name (contains FUN_ prefix)
    if text.starts_with("FUN_") || text.starts_with("thunk_FUN_") {
        let token = CToken::new(CTokenKind::FunctionName, text, line, col);
        return token.with_navigation(TokenNavigation::Function(text.to_string()));
    }

    // Check if it looks like a label (LAB_ or loc_ prefix)
    if text.starts_with("LAB_") || text.starts_with("lab_") || text.starts_with("loc_") {
        let token = CToken::new(CTokenKind::LabelDef, text, line, col);
        return token.with_navigation(TokenNavigation::Label(text.to_string()));
    }

    // Default: identifier
    CToken::new(CTokenKind::Identifier, text, line, col)
}

// ============================================================================
// Token Position and Query Utilities
// ============================================================================

/// Map a token kind to the corresponding foreground color from the syntax theme.
pub fn token_color(kind: CTokenKind, theme: &SyntaxTheme) -> egui::Color32 {
    match kind {
        CTokenKind::Keyword => theme.keyword_color,
        CTokenKind::TypeName => theme.type_color,
        CTokenKind::Identifier => theme.identifier_color,
        CTokenKind::FunctionName => theme.function_name_color,
        CTokenKind::Number => theme.number_color,
        CTokenKind::StringLiteral => theme.string_color,
        CTokenKind::CharLiteral => theme.char_color,
        CTokenKind::Comment => theme.comment_color,
        CTokenKind::Preprocessor => theme.preprocessor_color,
        CTokenKind::Operator => theme.operator_color,
        CTokenKind::Punctuation => theme.punctuation_color,
        CTokenKind::AddressRef => theme.address_ref_color,
        CTokenKind::LabelDef => theme.label_def_color,
        CTokenKind::Whitespace => theme.default_color,
        CTokenKind::Unknown => theme.default_color,
    }
}

/// Check whether a token kind should be rendered in bold.
pub fn token_is_bold(kind: CTokenKind) -> bool {
    kind == CTokenKind::Keyword
}

/// Check whether a token kind should be rendered in italic.
pub fn token_is_italic(kind: CTokenKind) -> bool {
    kind == CTokenKind::Comment
}

/// Check whether a token kind should be rendered as underlined (clickable).
pub fn token_is_underline(kind: CTokenKind) -> bool {
    matches!(
        kind,
        CTokenKind::AddressRef | CTokenKind::FunctionName | CTokenKind::LabelDef
    )
}

/// Get all address references found on a given line.
pub fn line_address_refs(tokens: &[CToken], line: usize) -> Vec<&CToken> {
    tokens
        .iter()
        .filter(|t| t.line == line && t.kind == CTokenKind::AddressRef)
        .collect()
}

// ============================================================================
// Demo Helpers
// ============================================================================

/// Generate demo decompiled code with rich features to showcase the view.
pub fn demo_code() -> &'static str {
    r#"// Decompiled from demo.bin
// Function: main @ 0x1000

int main(int argc, char **argv) {
    int result;
    char *msg;
    int i;

    msg = "Hello, World!\n";
    result = 0;

    if (argc > 1) {
        msg = argv[1];
        result = 1;
    }
    else {
        msg = "default message";
    }

    printf(msg);

    for (i = 0; i < 10; i = i + 1) {
        if ((i & 1) == 0) {
            printf("even: %d\n", i);
        }
        else {
            printf("odd: %d\n", i);
        }
    }

    return result;
}
"#
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tokenize_simple_line() {
        let tokens = tokenize_line("int x = 42;", 0, None);
        let kinds: Vec<CTokenKind> = tokens.iter().map(|t| t.kind).collect();
        // "int" keyword/type, " " whitespace, "x" identifier, " " whitespace,
        // "=" operator, " " whitespace, "42" number, ";" punctuation
        assert!(
            kinds.contains(&CTokenKind::TypeName),
            "Should contain a type name"
        );
        assert!(
            kinds.contains(&CTokenKind::Identifier),
            "Should contain an identifier"
        );
        assert!(
            kinds.contains(&CTokenKind::Number),
            "Should contain a number"
        );
        assert!(
            kinds.contains(&CTokenKind::Operator),
            "Should contain an operator"
        );
    }

    #[test]
    fn test_tokenize_keywords() {
        let tokens = tokenize_line("if else while for return goto", 0, None);
        let keyword_count = tokens
            .iter()
            .filter(|t| t.kind == CTokenKind::Keyword)
            .count();
        assert_eq!(keyword_count, 6);
    }

    #[test]
    fn test_tokenize_string_literal() {
        let tokens = tokenize_line(r#"msg = "Hello\n";"#, 0, None);
        let strings: Vec<&CToken> = tokens
            .iter()
            .filter(|t| t.kind == CTokenKind::StringLiteral)
            .collect();
        assert_eq!(strings.len(), 1);
        assert!(strings[0].text.contains("Hello"));
    }

    #[test]
    fn test_tokenize_char_literal() {
        let tokens = tokenize_line("char c = 'A';", 0, None);
        let chars: Vec<&CToken> = tokens
            .iter()
            .filter(|t| t.kind == CTokenKind::CharLiteral)
            .collect();
        assert_eq!(chars.len(), 1);
        assert_eq!(chars[0].text, "'A'");
    }

    #[test]
    fn test_tokenize_comment() {
        let tokens = tokenize_line("x = 1; // set x", 0, None);
        let comments: Vec<&CToken> = tokens
            .iter()
            .filter(|t| t.kind == CTokenKind::Comment)
            .collect();
        assert_eq!(comments.len(), 1);
    }

    #[test]
    fn test_tokenize_multi_char_operators() {
        let tokens = tokenize_line("a += b; c <<= d; e->f;", 0, None);
        let operators: Vec<&CToken> = tokens
            .iter()
            .filter(|t| t.kind == CTokenKind::Operator)
            .collect();
        let op_texts: Vec<&str> = operators.iter().map(|t| t.text.as_str()).collect();
        assert!(op_texts.contains(&"+="));
        assert!(op_texts.contains(&"<<="));
        assert!(op_texts.contains(&"->"));
    }

    #[test]
    fn test_tokenize_hex_number() {
        let tokens = tokenize_line("addr = 0xDEADBEEF;", 0, None);
        let addrs: Vec<&CToken> = tokens
            .iter()
            .filter(|t| t.kind == CTokenKind::AddressRef)
            .collect();
        assert!(!addrs.is_empty());
        assert_eq!(addrs[0].text, "0xDEADBEEF");
    }

    #[test]
    fn test_bracket_classification() {
        let tok = CToken::new(CTokenKind::Punctuation, "{", 0, 0);
        assert!(tok.is_bracket);
        assert!(tok.bracket_is_open);
        assert_eq!(tok.bracket_char, Some('{'));

        let tok = CToken::new(CTokenKind::Punctuation, "}", 0, 0);
        assert!(tok.is_bracket);
        assert!(tok.bracket_is_close);
        assert_eq!(tok.bracket_char, Some('}'));
    }

    #[test]
    fn test_text_range_selection() {
        let range = TextRange::new(TextPosition::new(0, 5), TextPosition::new(2, 10));
        assert!(range.intersects_line(0));
        assert!(range.intersects_line(1));
        assert!(range.intersects_line(2));
        assert!(!range.intersects_line(3));

        assert!(range.contains(TextPosition::new(1, 5)));
        assert!(!range.contains(TextPosition::new(0, 2)));
    }

    #[test]
    fn test_folding_regions() {
        let mut state = DecompilerViewState::new();
        state.load_code(
            "void f() {\n  int x;\n  if (x) {\n    x++;\n  }\n}",
            None,
            None,
        );

        assert!(!state.fold_regions.is_empty());
        // Should find at least the outer braces and inner braces
        let brace_regions: Vec<&FoldRegion> = state
            .fold_regions
            .iter()
            .filter(|r| matches!(r.kind, FoldKind::BraceBlock))
            .collect();
        assert!(brace_regions.len() >= 2);
    }

    #[test]
    fn test_bracket_pairs() {
        let mut state = DecompilerViewState::new();
        state.load_code("void f() { int x = (a + b) * (c - d); }", None, None);

        assert!(!state.bracket_pairs.is_empty());

        let paren_pairs: Vec<&BracketPair> = state
            .bracket_pairs
            .iter()
            .filter(|p| matches!(p.kind, BracketKind::Paren))
            .collect();
        assert_eq!(paren_pairs.len(), 3); // includes f() parens

        let brace_pairs: Vec<&BracketPair> = state
            .bracket_pairs
            .iter()
            .filter(|p| matches!(p.kind, BracketKind::Brace))
            .collect();
        assert_eq!(brace_pairs.len(), 1);
    }

    #[test]
    fn test_find_token_at() {
        let mut state = DecompilerViewState::new();
        state.load_code("int x = 42;", None, None);

        let token = state.find_token_at(0, 4);
        assert!(token.is_some());
        assert_eq!(token.unwrap().text, "x");
        assert_eq!(token.unwrap().kind, CTokenKind::Identifier);

        let token = state.find_token_at(0, 8);
        assert!(token.is_some());
        assert_eq!(token.unwrap().text, "42");
    }

    #[test]
    fn test_visible_lines_basic() {
        let mut state = DecompilerViewState::new();
        state.load_code("{\n  line1;\n  line2;\n}", None, None);

        assert!(state.is_line_visible(0));
        assert!(state.is_line_visible(1));
        assert!(state.is_line_visible(2));
        assert!(state.is_line_visible(3));
    }

    #[test]
    fn test_visible_lines_folded() {
        let mut state = DecompilerViewState::new();
        state.load_code(
            "void f() {\n  int x;\n  if (x) {\n    x++;\n  }\n  return;\n}",
            None,
            None,
        );

        // Fold the outer brace block at line 0
        state.folded_regions.insert(0);

        assert!(state.is_line_visible(0)); // start line still visible
                                           // Lines inside folded region should be hidden
        assert!(!state.is_line_visible(1));
        assert!(!state.is_line_visible(2));
        assert!(!state.is_line_visible(3));
        assert!(!state.is_line_visible(4));
        assert!(!state.is_line_visible(5));
    }

    #[test]
    fn test_select_all() {
        let mut state = DecompilerViewState::new();
        state.load_code("line1\nline2\n", None, None);

        state.select_all();
        assert!(state.selection.is_some());

        let range = state.selection.unwrap();
        assert_eq!(range.start.line, 0);
        assert_eq!(range.start.col, 0);
        assert!(range.end.line >= 1);
    }

    #[test]
    fn test_selection_text() {
        let mut state = DecompilerViewState::new();
        state.load_code("hello world\nabc", None, None);

        state.selection = Some(TextRange::new(
            TextPosition::new(0, 0),
            TextPosition::new(0, 5),
        ));
        let text = state.selected_text();
        assert_eq!(text, "hello");
    }

    #[test]
    fn test_token_navigation() {
        let tok = CToken::new(CTokenKind::FunctionName, "printf", 5, 10)
            .with_navigation(TokenNavigation::Function("printf".to_string()));

        match &tok.navigation {
            TokenNavigation::Function(name) => assert_eq!(name, "printf"),
            _ => panic!("Expected Function navigation"),
        }
    }

    #[test]
    fn test_syntax_theme_dark() {
        let theme = SyntaxTheme::dark();
        // Verify colors are distinct
        assert_ne!(theme.keyword_color, theme.comment_color);
        assert_ne!(theme.string_color, theme.number_color);
        assert_ne!(theme.type_color, theme.identifier_color);
    }

    #[test]
    fn test_syntax_theme_light() {
        let theme = SyntaxTheme::light();
        assert_ne!(theme.keyword_color, theme.default_color);
        // Light theme should have light background
        let bg = theme.background;
        assert!(bg.r() > 200 && bg.g() > 200 && bg.b() > 200);
    }

    #[test]
    fn test_fold_all_and_unfold_all() {
        let mut state = DecompilerViewState::new();
        state.load_code("{\n  a;\n  {\n    b;\n  }\n}", None, None);

        state.fold_all();
        assert!(state.folded_regions.len() >= 2);

        state.unfold_all();
        assert!(state.folded_regions.is_empty());
    }
}
