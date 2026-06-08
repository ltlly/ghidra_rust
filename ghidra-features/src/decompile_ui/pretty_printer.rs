//! Pretty printer -- Rust port of
//! `ghidra.app.decompiler.PrettyPrinter`.
//!
//! Converts a hierarchy of decompiler tokens (analogous to
//! `ClangTokenGroup`) into readable C/C++ source code.
//!
//! The printer takes a tree of [`ClangNode`]s, flattens it into
//! [`ClangLine`]s, pads empty lines with spacers, and then renders each
//! line to a string.  A [`NameTransformer`] can be applied to symbol
//! names to sanitize illegal characters.
//!
//! # Architecture
//!
//! ```text
//! PrettyPrinter
//!   ├── flatten_lines()        -- walk token tree -> Vec<ClangLine>
//!   ├── pad_empty_lines()      -- insert spacer tokens into empty lines
//!   ├── print()                -- render all lines -> DecompiledFunction
//!   ├── get_text(line)         -- render one line -> String
//!   └── find_signature()       -- extract function prototype string
//! ```

use std::fmt;

use ghidra_core::addr::Address;

use super::panel::{DecompiledFunction, DecompiledLine, DecompiledToken, DecompiledTokenType};

// ---------------------------------------------------------------------------
// NameTransformer
// ---------------------------------------------------------------------------

/// A trait for transforming symbol names during pretty-printing.
///
/// In Ghidra this is `ghidra.program.model.symbol.NameTransformer`.
/// The default (identity) implementation returns the name unchanged.
pub trait NameTransformer {
    /// Simplify / sanitize a symbol name for display.
    fn simplify(&self, name: &str) -> String;
}

/// The identity transformer -- returns names unchanged.
#[derive(Debug, Clone, Copy)]
pub struct IdentityNameTransformer;

impl NameTransformer for IdentityNameTransformer {
    fn simplify(&self, name: &str) -> String {
        name.to_string()
    }
}

// ---------------------------------------------------------------------------
// ClangNode -- the token tree node interface
// ---------------------------------------------------------------------------

/// A node in the decompiler's C language token tree.
///
/// In Ghidra this is the `ClangNode` interface.  A node can be either a
/// leaf [`ClangToken`] or a [`ClangTokenGroup`] (which contains children).
/// This enum models both cases.
#[derive(Debug, Clone)]
pub enum ClangNode {
    /// A leaf token (keyword, variable, operator, etc.).
    Token(ClangToken),
    /// A group of tokens (statement, block, function, etc.).
    Group(ClangTokenGroup),
}

impl ClangNode {
    /// Returns the number of immediate children (0 for tokens).
    pub fn num_children(&self) -> usize {
        match self {
            ClangNode::Token(_) => 0,
            ClangNode::Group(g) => g.children.len(),
        }
    }

    /// Get the i-th child (panics if out of range or leaf).
    pub fn child(&self, i: usize) -> &ClangNode {
        match self {
            ClangNode::Token(_) => panic!("ClangToken has no children"),
            ClangNode::Group(g) => &g.children[i],
        }
    }

    /// Returns the minimum address associated with this node.
    pub fn min_address(&self) -> Option<Address> {
        match self {
            ClangNode::Token(t) => t.address,
            ClangNode::Group(g) => {
                // Walk children to find the minimum address.
                g.children.iter().filter_map(|c| c.min_address()).min()
            }
        }
    }

    /// Returns the maximum address associated with this node.
    pub fn max_address(&self) -> Option<Address> {
        match self {
            ClangNode::Token(t) => t.address,
            ClangNode::Group(g) => {
                g.children.iter().filter_map(|c| c.max_address()).max()
            }
        }
    }

    /// Flatten this node tree into a list of leaf tokens.
    pub fn flatten(&self, list: &mut Vec<ClangNode>) {
        match self {
            ClangNode::Token(_) => list.push(self.clone()),
            ClangNode::Group(g) => {
                for child in &g.children {
                    child.flatten(list);
                }
            }
        }
    }

    /// Returns the text of this node (concatenation of all leaf tokens).
    pub fn text(&self) -> String {
        match self {
            ClangNode::Token(t) => t.text.clone(),
            ClangNode::Group(g) => {
                let mut s = String::new();
                for child in &g.children {
                    s.push_str(&child.text());
                }
                s
            }
        }
    }

    /// Returns `true` if this node is a ClangFuncProto group.
    pub fn is_func_proto(&self) -> bool {
        match self {
            ClangNode::Group(g) => g.group_type == ClangGroupType::FuncProto,
            _ => false,
        }
    }
}

impl fmt::Display for ClangNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClangNode::Token(t) => write!(f, "{}", t.text),
            ClangNode::Group(g) => {
                for child in &g.children {
                    write!(f, "{}", child)?;
                }
                Ok(())
            }
        }
    }
}

// ---------------------------------------------------------------------------
// ClangToken -- a single leaf token
// ---------------------------------------------------------------------------

/// A single token in the decompiled C source.
///
/// In Ghidra this is the `ClangToken` class.  Tokens are the leaves of
/// the ClangNode tree: keywords, variable names, operators, etc.
#[derive(Debug, Clone)]
pub struct ClangToken {
    /// The displayed text.
    pub text: String,
    /// The syntax type (determines coloring).
    pub syntax_type: ClangSyntaxType,
    /// The source address this token refers to (if any).
    pub address: Option<Address>,
    /// The parent line index (set after flattening).
    pub line_index: Option<usize>,
    /// Whether this token is a spacer (padding for empty lines).
    pub is_spacer: bool,
}

impl ClangToken {
    /// Create a new token.
    pub fn new(text: impl Into<String>, syntax_type: ClangSyntaxType) -> Self {
        Self {
            text: text.into(),
            syntax_type,
            address: None,
            line_index: None,
            is_spacer: false,
        }
    }

    /// Create a spacer token for padding empty lines.
    pub fn build_spacer(
        address: Option<Address>,
        indent: usize,
        indent_str: &str,
    ) -> Self {
        let text = indent_str.repeat(indent);
        Self {
            text,
            syntax_type: ClangSyntaxType::Whitespace,
            address,
            line_index: None,
            is_spacer: true,
        }
    }

    /// Returns `true` if this token represents a variable reference.
    pub fn is_variable_ref(&self) -> bool {
        matches!(
            self.syntax_type,
            ClangSyntaxType::Variable
                | ClangSyntaxType::FuncName
                | ClangSyntaxType::Type
                | ClangSyntaxType::Field
                | ClangSyntaxType::Label
        )
    }

    /// Returns `true` if this token should have its name simplified.
    pub fn is_cleanable(&self) -> bool {
        matches!(
            self.syntax_type,
            ClangSyntaxType::FuncName
                | ClangSyntaxType::Variable
                | ClangSyntaxType::Type
                | ClangSyntaxType::Field
                | ClangSyntaxType::Label
        )
    }
}

// ---------------------------------------------------------------------------
// ClangSyntaxType -- token coloring category
// ---------------------------------------------------------------------------

/// The syntax type of a Clang token, used for coloring.
///
/// In Ghidra this corresponds to the various ClangToken subclasses
/// (ClangFuncNameToken, ClangVariableToken, etc.) and the
/// `getSyntaxType()` return values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClangSyntaxType {
    /// A keyword (if, while, return, etc.).
    Keyword,
    /// A type name (int, char, struct, etc.).
    Type,
    /// A function name.
    FuncName,
    /// A variable name.
    Variable,
    /// A field name (struct/union member).
    Field,
    /// A label (goto target).
    Label,
    /// An operator (+, -, *, etc.).
    Operator,
    /// A literal value (number, string, char).
    Const,
    /// A comment.
    Comment,
    /// A separator (parentheses, braces, semicolons).
    Syntax,
    /// A space or whitespace.
    Whitespace,
    /// A bit field token.
    BitField,
    /// A case label token.
    CaseLabel,
    /// A return type token.
    ReturnType,
}

/// Alias for backward compatibility with Ghidra's `CONST_COLOR`.
impl ClangSyntaxType {
    /// Returns `true` if this is a constant-colored token.
    pub fn is_const_color(&self) -> bool {
        matches!(self, ClangSyntaxType::Const)
    }
}

// ---------------------------------------------------------------------------
// ClangGroupType -- the kind of a ClangTokenGroup
// ---------------------------------------------------------------------------

/// The kind of a Clang token group.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClangGroupType {
    /// A generic token group.
    Generic,
    /// A function definition (ClangFunction).
    Function,
    /// A function prototype (ClangFuncProto).
    FuncProto,
    /// A statement (ClangStatement).
    Statement,
    /// A variable declaration (ClangVariableDecl).
    VariableDecl,
    /// A return type (ClangReturnType).
    ReturnType,
}

// ---------------------------------------------------------------------------
// ClangTokenGroup -- a group of tokens
// ---------------------------------------------------------------------------

/// A group of ClangNode children.
///
/// In Ghidra this is the `ClangTokenGroup` class.  Groups form the
/// interior nodes of the token tree: statements, blocks, functions, etc.
#[derive(Debug, Clone)]
pub struct ClangTokenGroup {
    /// The child nodes.
    pub children: Vec<ClangNode>,
    /// The kind of this group.
    pub group_type: ClangGroupType,
}

impl ClangTokenGroup {
    /// Create a new empty token group.
    pub fn new(group_type: ClangGroupType) -> Self {
        Self {
            children: Vec::new(),
            group_type,
        }
    }

    /// Add a child node.
    pub fn add_child(&mut self, child: ClangNode) {
        self.children.push(child);
    }

    /// Returns the number of children.
    pub fn num_children(&self) -> usize {
        self.children.len()
    }

    /// Get the i-th child.
    pub fn child(&self, i: usize) -> &ClangNode {
        &self.children[i]
    }
}

// ---------------------------------------------------------------------------
// ClangLine -- a single line of decompiled output
// ---------------------------------------------------------------------------

/// A single line of decompiled C source.
///
/// In Ghidra this is the `ClangLine` class.  A line is produced by
/// splitting the token tree at `ClangBreak` (line-break) tokens.
#[derive(Debug, Clone)]
pub struct ClangLine {
    /// The tokens on this line.
    pub tokens: Vec<ClangToken>,
    /// The indent level (number of indent units).
    pub indent: usize,
    /// The index of this line within the function.
    pub line_index: usize,
}

impl ClangLine {
    /// Create a new empty line.
    pub fn new(indent: usize, line_index: usize) -> Self {
        Self {
            tokens: Vec::new(),
            indent,
            line_index,
        }
    }

    /// Add a token to this line.
    pub fn add_token(&mut self, token: ClangToken) {
        self.tokens.push(token);
    }

    /// Returns all tokens on this line.
    pub fn all_tokens(&self) -> &[ClangToken] {
        &self.tokens
    }

    /// Returns the indent string (spaces).
    pub fn indent_string(&self) -> String {
        PrettyPrinter::INDENT_STRING.repeat(self.indent)
    }

    /// Returns `true` if this line has no tokens.
    pub fn is_empty(&self) -> bool {
        self.tokens.is_empty()
    }
}

// ---------------------------------------------------------------------------
// PrettyPrinter
// ---------------------------------------------------------------------------

/// Converts a C language token tree into readable C/C++ code.
///
/// The printer takes a [`ClangTokenGroup`] (analogous to Ghidra's
/// `ClangTokenGroup`), flattens it into lines, pads empty lines, and
/// then renders each line to a string.
pub struct PrettyPrinter {
    /// The function name (for display).
    function_name: Option<String>,
    /// The root token group.
    tokgroup: ClangTokenGroup,
    /// The flattened lines.
    lines: Vec<ClangLine>,
    /// The name transformer to apply to symbol names.
    transformer: Box<dyn NameTransformer>,
}

/// The indent string (one space per indent level).
///
/// In Ghidra this is `PrettyPrinter.INDENT_STRING = " "`.
/// Some configurations use 4 spaces or a tab.
pub const INDENT_STRING: &str = "    ";

impl PrettyPrinter {
    /// The default indent string used by Ghidra.
    pub const INDENT_STRING: &'static str = "    ";

    /// Create a new pretty printer.
    ///
    /// # Arguments
    /// * `function_name` -- optional function name for display.
    /// * `tokgroup` -- the root token group to print.
    /// * `transformer` -- the name transformer (None for identity).
    pub fn new(
        function_name: Option<String>,
        tokgroup: ClangTokenGroup,
        transformer: Option<Box<dyn NameTransformer>>,
    ) -> Self {
        let mut printer = Self {
            function_name,
            tokgroup,
            lines: Vec::new(),
            transformer: transformer.unwrap_or_else(|| Box::new(IdentityNameTransformer)),
        };
        printer.flatten_lines();
        printer.pad_empty_lines();
        printer
    }

    /// Returns a reference to the function name.
    pub fn function_name(&self) -> Option<&str> {
        self.function_name.as_deref()
    }

    /// Returns a reference to the flattened lines.
    pub fn lines(&self) -> &[ClangLine] {
        &self.lines
    }

    /// Returns the flattened lines (mutable).
    pub fn lines_mut(&mut self) -> &mut Vec<ClangLine> {
        &mut self.lines
    }

    /// Print the token tree into a [`DecompiledFunction`].
    ///
    /// This renders all lines into a single string and extracts the
    /// function signature.
    pub fn print(&self) -> DecompiledFunction {
        let name = self.function_name.clone().unwrap_or_default();
        let mut func = DecompiledFunction::new(Address::new(0), name);
        func.lines = self.lines.iter().map(|l| Self::line_to_decompiled(l)).collect();
        func.is_complete = true;
        func
    }

    /// Render a single line to text (static helper).
    ///
    /// This is the Rust equivalent of Ghidra's
    /// `PrettyPrinter.getText(ClangLine, NameTransformer)`.
    pub fn get_text_static(
        buff: &mut String,
        line: &ClangLine,
        transformer: &dyn NameTransformer,
    ) {
        buff.push_str(&line.indent_string());
        for token in line.all_tokens() {
            let is_token_to_clean = token.is_cleanable() && !token.syntax_type.is_const_color();

            if is_token_to_clean {
                buff.push_str(&transformer.simplify(&token.text));
            } else {
                buff.push_str(&token.text);
            }
        }
    }

    /// Render a single line to text using the identity transformer.
    ///
    /// This is the Rust equivalent of Ghidra's
    /// `PrettyPrinter.getText(ClangLine)`.
    pub fn get_text(line: &ClangLine) -> String {
        let mut buff = String::new();
        Self::get_text_static(&mut buff, line, &IdentityNameTransformer);
        buff
    }

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    /// Flatten the token tree into lines.
    fn flatten_lines(&mut self) {
        self.lines = to_lines(&self.tokgroup);
    }

    /// Pad empty lines with spacer tokens.
    fn pad_empty_lines(&mut self) {
        for line in &mut self.lines {
            if line.tokens.is_empty() {
                let spacer = ClangToken::build_spacer(None, line.indent, Self::INDENT_STRING);
                line.tokens.push(spacer);
            }
        }
    }

    /// Find the function signature in the token tree.
    fn find_signature(&self) -> Option<String> {
        for child in &self.tokgroup.children {
            if child.is_func_proto() {
                let mut s = String::new();
                Self::node_to_string_static(&mut s, child);
                s.push(';');
                return Some(s);
            }
        }
        None
    }

    /// Recursively convert a node to a string.
    fn node_to_string_static(buff: &mut String, node: &ClangNode) {
        match node {
            ClangNode::Token(t) => buff.push_str(&t.text),
            ClangNode::Group(g) => {
                for child in &g.children {
                    Self::node_to_string_static(buff, child);
                }
            }
        }
    }

    /// Convert a ClangLine to a DecompiledLine.
    fn line_to_decompiled(line: &ClangLine) -> DecompiledLine {
        let tokens: Vec<DecompiledToken> = line
            .tokens
            .iter()
            .enumerate()
            .map(|(col, t)| {
                let dtype = match t.syntax_type {
                    ClangSyntaxType::Keyword => DecompiledTokenType::Keyword,
                    ClangSyntaxType::Type => DecompiledTokenType::TypeName,
                    ClangSyntaxType::FuncName => DecompiledTokenType::FunctionName,
                    ClangSyntaxType::Variable => DecompiledTokenType::Variable,
                    ClangSyntaxType::Field => DecompiledTokenType::FieldName,
                    ClangSyntaxType::Label => DecompiledTokenType::Label,
                    ClangSyntaxType::Operator => DecompiledTokenType::Operator,
                    ClangSyntaxType::Const => DecompiledTokenType::Literal,
                    ClangSyntaxType::Comment => DecompiledTokenType::Comment,
                    ClangSyntaxType::Syntax => DecompiledTokenType::Separator,
                    ClangSyntaxType::Whitespace => DecompiledTokenType::Whitespace,
                    ClangSyntaxType::BitField => DecompiledTokenType::BitField,
                    ClangSyntaxType::CaseLabel => DecompiledTokenType::Label,
                    ClangSyntaxType::ReturnType => DecompiledTokenType::TypeName,
                };
                DecompiledToken::new(&t.text, dtype, col, 0).with_maybe_address(t.address)
            })
            .collect();

        DecompiledLine::from_tokens(tokens, line.indent)
    }
}

// ---------------------------------------------------------------------------
// to_lines -- flatten a token group into lines
// ---------------------------------------------------------------------------

/// Flatten a [`ClangTokenGroup`] into a list of [`ClangLine`]s.
///
/// This is the Rust equivalent of Ghidra's `DecompilerUtils.toLines()`.
/// It walks the token tree and splits at `ClangBreak` tokens.
pub fn to_lines(group: &ClangTokenGroup) -> Vec<ClangLine> {
    let mut lines = Vec::new();
    let mut current_line = ClangLine::new(0, 0);
    let mut line_index = 0;

    to_lines_inner(group, &mut lines, &mut current_line, &mut line_index);

    // Push the last line if it has tokens.
    if !current_line.tokens.is_empty() {
        lines.push(current_line);
    }

    lines
}

/// Recursive helper for `to_lines`.
fn to_lines_inner(
    group: &ClangTokenGroup,
    lines: &mut Vec<ClangLine>,
    current_line: &mut ClangLine,
    line_index: &mut usize,
) {
    for child in &group.children {
        match child {
            ClangNode::Token(t) => {
                if t.is_spacer {
                    // Spacer tokens are line breaks.
                    let mut new_line = ClangLine::new(0, *line_index + 1);
                    std::mem::swap(current_line, &mut new_line);
                    lines.push(new_line);
                    *line_index += 1;
                } else {
                    current_line.add_token(t.clone());
                }
            }
            ClangNode::Group(g) => {
                to_lines_inner(g, lines, current_line, line_index);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Extensions for DecompiledToken / DecompiledLine
// ---------------------------------------------------------------------------

impl DecompiledToken {
    /// Set the address (builder-style, returns self).
    pub fn with_maybe_address(mut self, addr: Option<Address>) -> Self {
        self.address = addr;
        self
    }
}

impl DecompiledLine {
    /// Create a new decompiled line from tokens and indent level.
    pub fn from_tokens(tokens: Vec<DecompiledToken>, indent_level: usize) -> Self {
        Self {
            tokens,
            indent_level,
            ..Default::default()
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clang_token_new() {
        let t = ClangToken::new("int", ClangSyntaxType::Keyword);
        assert_eq!(t.text, "int");
        assert_eq!(t.syntax_type, ClangSyntaxType::Keyword);
        assert!(t.address.is_none());
        assert!(!t.is_spacer);
    }

    #[test]
    fn test_clang_token_spacer() {
        let t = ClangToken::build_spacer(None, 2, "    ");
        assert_eq!(t.text, "        ");
        assert!(t.is_spacer);
    }

    #[test]
    fn test_clang_token_is_variable_ref() {
        let t = ClangToken::new("x", ClangSyntaxType::Variable);
        assert!(t.is_variable_ref());

        let t = ClangToken::new("int", ClangSyntaxType::Keyword);
        assert!(!t.is_variable_ref());
    }

    #[test]
    fn test_clang_token_group() {
        let mut g = ClangTokenGroup::new(ClangGroupType::Statement);
        g.add_child(ClangNode::Token(ClangToken::new(
            "return",
            ClangSyntaxType::Keyword,
        )));
        g.add_child(ClangNode::Token(ClangToken::new(
            " ",
            ClangSyntaxType::Whitespace,
        )));
        g.add_child(ClangNode::Token(ClangToken::new(
            "0",
            ClangSyntaxType::Const,
        )));
        assert_eq!(g.num_children(), 3);
    }

    #[test]
    fn test_clang_node_text() {
        let mut g = ClangTokenGroup::new(ClangGroupType::Statement);
        g.add_child(ClangNode::Token(ClangToken::new(
            "return",
            ClangSyntaxType::Keyword,
        )));
        g.add_child(ClangNode::Token(ClangToken::new(
            " 0;",
            ClangSyntaxType::Syntax,
        )));
        let node = ClangNode::Group(g);
        assert_eq!(node.text(), "return 0;");
    }

    #[test]
    fn test_clang_node_display() {
        let mut g = ClangTokenGroup::new(ClangGroupType::Statement);
        g.add_child(ClangNode::Token(ClangToken::new(
            "x = 5;",
            ClangSyntaxType::Syntax,
        )));
        let node = ClangNode::Group(g);
        assert_eq!(format!("{}", node), "x = 5;");
    }

    #[test]
    fn test_clang_node_flatten() {
        let mut inner = ClangTokenGroup::new(ClangGroupType::Statement);
        inner.add_child(ClangNode::Token(ClangToken::new(
            "a",
            ClangSyntaxType::Variable,
        )));
        inner.add_child(ClangNode::Token(ClangToken::new(
            " + ",
            ClangSyntaxType::Operator,
        )));
        inner.add_child(ClangNode::Token(ClangToken::new(
            "b",
            ClangSyntaxType::Variable,
        )));

        let mut outer = ClangTokenGroup::new(ClangGroupType::Generic);
        outer.add_child(ClangNode::Group(inner));

        let node = ClangNode::Group(outer);
        let mut flat = Vec::new();
        node.flatten(&mut flat);
        assert_eq!(flat.len(), 3);
    }

    #[test]
    fn test_clang_line() {
        let mut line = ClangLine::new(2, 0);
        line.add_token(ClangToken::new("int", ClangSyntaxType::Keyword));
        line.add_token(ClangToken::new(" x;", ClangSyntaxType::Syntax));
        assert_eq!(line.tokens.len(), 2);
        assert_eq!(line.indent, 2);
        assert_eq!(line.indent_string(), "        ");
    }

    #[test]
    fn test_identity_transformer() {
        let t = IdentityNameTransformer;
        assert_eq!(t.simplify("hello"), "hello");
        assert_eq!(t.simplify("my_var"), "my_var");
    }

    #[test]
    fn test_pretty_printer_simple() {
        let mut group = ClangTokenGroup::new(ClangGroupType::Function);
        group.add_child(ClangNode::Token(ClangToken::new(
            "int",
            ClangSyntaxType::Keyword,
        )));
        group.add_child(ClangNode::Token(ClangToken::new(
            " ",
            ClangSyntaxType::Whitespace,
        )));
        group.add_child(ClangNode::Token(ClangToken::new(
            "main",
            ClangSyntaxType::FuncName,
        )));
        group.add_child(ClangNode::Token(ClangToken::new(
            "() { return 0; }",
            ClangSyntaxType::Syntax,
        )));

        let printer = PrettyPrinter::new(Some("main".to_string()), group, None);
        let result = printer.print();
        assert!(!result.lines.is_empty());
        // Check that the lines contain the expected tokens
        let all_text: String = result.lines.iter().flat_map(|l| l.tokens.iter()).map(|t| t.text.as_str()).collect();
        assert!(all_text.contains("int"));
        assert!(all_text.contains("main"));
    }

    #[test]
    fn test_to_lines() {
        let mut group = ClangTokenGroup::new(ClangGroupType::Generic);
        group.add_child(ClangNode::Token(ClangToken::new(
            "line1",
            ClangSyntaxType::Syntax,
        )));
        // Add a spacer to simulate a line break.
        group.add_child(ClangNode::Token(ClangToken::build_spacer(None, 0, "    ")));
        group.add_child(ClangNode::Token(ClangToken::new(
            "line2",
            ClangSyntaxType::Syntax,
        )));

        let lines = to_lines(&group);
        assert_eq!(lines.len(), 2);
    }

    #[test]
    fn test_syntax_type_is_const_color() {
        assert!(ClangSyntaxType::Const.is_const_color());
        assert!(!ClangSyntaxType::Keyword.is_const_color());
    }

    #[test]
    fn test_clang_node_is_func_proto() {
        let g = ClangTokenGroup::new(ClangGroupType::FuncProto);
        let node = ClangNode::Group(g);
        assert!(node.is_func_proto());

        let g = ClangTokenGroup::new(ClangGroupType::Statement);
        let node = ClangNode::Group(g);
        assert!(!node.is_func_proto());
    }
}
