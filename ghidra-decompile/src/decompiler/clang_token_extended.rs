//! Extended Clang token types ported from Ghidra's Java Decompiler.
//!
//! Ports the following Java classes that have non-trivial decode/behavior logic:
//! - `ClangCommentToken` -- tokens representing comments in decompiled output
//! - `ClangCaseToken` -- tokens for switch case labels with constant values
//! - `ClangFieldToken` -- tokens representing struct field accesses
//! - `ClangVariableDecl` -- group token for variable declarations
//! - `ClangFuncProto` -- group token for function prototypes
//! - `ClangReturnType` -- group token for return type of a function
//! - `ClangOpToken` -- token for operators (already partially ported, extended here)
//! - `ClangFuncNameToken` -- token for function name references
//! - `ClangSyntaxToken` -- token for syntax elements (braces, parens, etc.)
//! - `ClangTypeToken` -- token for data type names
//! - `ClangLabelToken` -- token for label references

use std::collections::HashMap;
use std::fmt;

// ============================================================================
// SyntaxType enum (mirrors the Java SyntaxType)
// ============================================================================

/// Syntax coloring categories for decompiler output.
///
/// Ported from `ghidra.app.decompiler.ClangNode.SyntaxType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum SyntaxType {
    /// Language keywords (if, while, return, etc.)
    Keyword = 0,
    /// Data type names
    Type = 1,
    /// Function names
    Function = 2,
    /// Variable references
    Variable = 3,
    /// Literal constants
    Const = 4,
    /// Special characters (braces, parens, semicolons)
    Special = 5,
    /// Error indicators
    Error = 6,
    /// Global variable references
    Global = 7,
    /// Comments
    Comment = 8,
    /// Parameter references
    Parameter = 9,
    /// Default / unknown
    Default = 10,
}

impl SyntaxType {
    /// Convert from an integer value.
    pub fn from_i32(value: i32) -> Self {
        match value {
            0 => Self::Keyword,
            1 => Self::Type,
            2 => Self::Function,
            3 => Self::Variable,
            4 => Self::Const,
            5 => Self::Special,
            6 => Self::Error,
            7 => Self::Global,
            8 => Self::Comment,
            9 => Self::Parameter,
            _ => Self::Default,
        }
    }

    /// Get the color string for this syntax type.
    pub fn color_name(&self) -> &'static str {
        match self {
            Self::Keyword => "keyword",
            Self::Type => "type",
            Self::Function => "function",
            Self::Variable => "variable",
            Self::Const => "const",
            Self::Special => "special",
            Self::Error => "error",
            Self::Global => "global",
            Self::Comment => "comment",
            Self::Parameter => "parameter",
            Self::Default => "default",
        }
    }
}

impl Default for SyntaxType {
    fn default() -> Self {
        Self::Default
    }
}

impl fmt::Display for SyntaxType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.color_name())
    }
}

// ============================================================================
// ClangCommentToken
// ============================================================================

/// A token representing part of a comment in decompiled output.
///
/// Ported from `ghidra.app.decompiler.ClangCommentToken`.
#[derive(Debug, Clone)]
pub struct ClangCommentToken {
    /// The text of the comment.
    pub text: String,
    /// Source address where the comment originates.
    pub source_address: Option<u64>,
    /// Parent node index (in an arena-based tree).
    pub parent_id: Option<usize>,
    /// Line parent index.
    pub line_parent_id: Option<usize>,
    /// Syntax type (always Comment).
    pub syntax_type: SyntaxType,
}

impl ClangCommentToken {
    /// Create a new comment token.
    pub fn new(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            source_address: None,
            parent_id: None,
            line_parent_id: None,
            syntax_type: SyntaxType::Comment,
        }
    }

    /// Create a derived comment token with new text but same metadata.
    pub fn derive(source: &ClangCommentToken, text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            source_address: source.source_address,
            parent_id: source.parent_id,
            line_parent_id: source.line_parent_id,
            syntax_type: source.syntax_type,
        }
    }

    /// Whether this token is a variable reference (always false for comments).
    pub fn is_variable_ref(&self) -> bool {
        false
    }

    /// The minimum address associated with this token.
    pub fn min_address(&self) -> Option<u64> {
        self.source_address
    }

    /// The maximum address associated with this token.
    pub fn max_address(&self) -> Option<u64> {
        self.source_address
    }
}

// ============================================================================
// ClangCaseToken
// ============================================================================

/// A token representing a switch "case" label or constant not directly linked to data-flow.
///
/// Has an associated constant value and optional data type.
/// Ported from `ghidra.app.decompiler.ClangCaseToken`.
#[derive(Debug, Clone)]
pub struct ClangCaseToken {
    /// The text of the token.
    pub text: String,
    /// The constant value of the case label.
    pub value: i64,
    /// The PcodeOp reference (op index) associated with this case.
    pub op_ref: Option<usize>,
    /// Address of the associated PcodeOp.
    pub op_address: Option<u64>,
    /// Data type name (if known).
    pub data_type_name: Option<String>,
    /// Data type id.
    pub data_type_id: Option<u64>,
    /// Whether signed.
    pub is_signed: bool,
    /// Bit size of the constant.
    pub bit_size: u32,
}

impl ClangCaseToken {
    /// Create a new case token.
    pub fn new() -> Self {
        Self {
            text: String::new(),
            value: 0,
            op_ref: None,
            op_address: None,
            data_type_name: None,
            data_type_id: None,
            is_signed: true,
            bit_size: 0,
        }
    }

    /// Get the constant value.
    pub fn get_value(&self) -> i64 {
        self.value
    }

    /// Whether this token is a variable reference (always true for case tokens).
    pub fn is_variable_ref(&self) -> bool {
        true
    }

    /// The minimum address (from the associated PcodeOp).
    pub fn min_address(&self) -> Option<u64> {
        self.op_address
    }

    /// The maximum address (from the associated PcodeOp).
    pub fn max_address(&self) -> Option<u64> {
        self.op_address
    }

    /// Whether the value is negative (for display formatting).
    pub fn is_negative(&self) -> bool {
        self.value < 0
    }

    /// Get the unsigned representation of the value.
    pub fn unsigned_value(&self) -> u64 {
        self.value as u64
    }
}

impl Default for ClangCaseToken {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// ClangFieldToken
// ============================================================================

/// A token representing a structure field access in decompiled code.
///
/// Ported from `ghidra.app.decompiler.ClangFieldToken`.
#[derive(Debug, Clone)]
pub struct ClangFieldToken {
    /// The text (field name).
    pub text: String,
    /// The structure data type name.
    pub data_type_name: Option<String>,
    /// The data type id.
    pub data_type_id: Option<u64>,
    /// Byte offset of the field within the structure.
    pub offset: i32,
    /// The PcodeOp reference (op index) associated with the field extraction.
    pub op_ref: Option<usize>,
    /// Address of the associated PcodeOp.
    pub op_address: Option<u64>,
}

impl ClangFieldToken {
    /// Create a new field token.
    pub fn new(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            data_type_name: None,
            data_type_id: None,
            offset: 0,
            op_ref: None,
            op_address: None,
        }
    }

    /// Get the structure data type name.
    pub fn data_type_name(&self) -> Option<&str> {
        self.data_type_name.as_deref()
    }

    /// Get the byte offset within the structure.
    pub fn offset(&self) -> i32 {
        self.offset
    }

    /// Whether this token is a variable reference.
    pub fn is_variable_ref(&self) -> bool {
        self.op_ref.is_some()
    }

    /// Get the minimum address (from the associated PcodeOp).
    pub fn min_address(&self) -> Option<u64> {
        self.op_address
    }

    /// Get the maximum address.
    pub fn max_address(&self) -> Option<u64> {
        self.op_address
    }
}

// ============================================================================
// ClangVariableDecl
// ============================================================================

/// A grouping of source code tokens representing a variable declaration.
///
/// Can be a one-line declaration (local variables) or part of a function prototype
/// declaring a parameter.
/// Ported from `ghidra.app.decompiler.ClangVariableDecl`.
#[derive(Debug, Clone)]
pub struct ClangVariableDecl {
    /// Child tokens (the tokens making up the declaration).
    pub children: Vec<usize>,
    /// The data type of the variable being declared.
    pub data_type_name: Option<String>,
    /// The data type id.
    pub data_type_id: Option<u64>,
    /// The symbol reference id.
    pub symbol_ref: Option<u64>,
    /// The variable name.
    pub variable_name: Option<String>,
    /// Parent node index.
    pub parent_id: Option<usize>,
}

impl ClangVariableDecl {
    /// Create a new variable declaration group.
    pub fn new() -> Self {
        Self {
            children: Vec::new(),
            data_type_name: None,
            data_type_id: None,
            symbol_ref: None,
            variable_name: None,
            parent_id: None,
        }
    }

    /// Get the data type name.
    pub fn data_type_name(&self) -> Option<&str> {
        self.data_type_name.as_deref()
    }

    /// Get the symbol reference id.
    pub fn symbol_ref(&self) -> Option<u64> {
        self.symbol_ref
    }

    /// Add a child token index.
    pub fn add_child(&mut self, child_id: usize) {
        self.children.push(child_id);
    }

    /// Number of child tokens.
    pub fn num_children(&self) -> usize {
        self.children.len()
    }
}

impl Default for ClangVariableDecl {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// ClangFuncProto
// ============================================================================

/// A grouping of source code tokens representing a function prototype.
///
/// Ported from `ghidra.app.decompiler.ClangFuncProto`.
#[derive(Debug, Clone)]
pub struct ClangFuncProto {
    /// Child tokens (the tokens making up the prototype).
    pub children: Vec<usize>,
    /// Parent node index.
    pub parent_id: Option<usize>,
}

impl ClangFuncProto {
    /// Create a new function prototype group.
    pub fn new() -> Self {
        Self {
            children: Vec::new(),
            parent_id: None,
        }
    }

    /// Add a child token index.
    pub fn add_child(&mut self, child_id: usize) {
        self.children.push(child_id);
    }

    /// Number of child tokens.
    pub fn num_children(&self) -> usize {
        self.children.len()
    }
}

impl Default for ClangFuncProto {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// ClangReturnType
// ============================================================================

/// A grouping of source code tokens representing the return type of a function.
///
/// Appears at the beginning of a function prototype.
/// Ported from `ghidra.app.decompiler.ClangReturnType`.
#[derive(Debug, Clone)]
pub struct ClangReturnType {
    /// Child tokens (the tokens making up the return type).
    pub children: Vec<usize>,
    /// The data type name.
    pub data_type_name: Option<String>,
    /// The data type id.
    pub data_type_id: Option<u64>,
    /// The varnode reference id (for linking to data-flow).
    pub varnode_ref: Option<usize>,
    /// Parent node index.
    pub parent_id: Option<usize>,
}

impl ClangReturnType {
    /// Create a new return type group.
    pub fn new() -> Self {
        Self {
            children: Vec::new(),
            data_type_name: None,
            data_type_id: None,
            varnode_ref: None,
            parent_id: None,
        }
    }

    /// Get the data type name.
    pub fn data_type_name(&self) -> Option<&str> {
        self.data_type_name.as_deref()
    }

    /// Whether this return type has an associated varnode.
    pub fn has_varnode(&self) -> bool {
        self.varnode_ref.is_some()
    }

    /// Add a child token index.
    pub fn add_child(&mut self, child_id: usize) {
        self.children.push(child_id);
    }
}

impl Default for ClangReturnType {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// ClangOpToken
// ============================================================================

/// A token representing an operator in decompiled code.
///
/// Ported from `ghidra.app.decompiler.ClangOpToken`.
#[derive(Debug, Clone)]
pub struct ClangOpToken {
    /// The operator text (e.g., "+", "->", "&&").
    pub text: String,
    /// The PcodeOp reference (op index).
    pub op_ref: Option<usize>,
    /// Address of the associated PcodeOp.
    pub op_address: Option<u64>,
    /// Syntax type (usually Special or Keyword).
    pub syntax_type: SyntaxType,
}

impl ClangOpToken {
    /// Create a new operator token.
    pub fn new(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            op_ref: None,
            op_address: None,
            syntax_type: SyntaxType::Special,
        }
    }

    /// Whether this is an assignment operator.
    pub fn is_assignment(&self) -> bool {
        matches!(
            self.text.as_str(),
            "=" | "+=" | "-=" | "*=" | "/=" | "%=" | "&=" | "|=" | "^=" | "<<=" | ">>="
        )
    }

    /// Whether this is a comparison operator.
    pub fn is_comparison(&self) -> bool {
        matches!(self.text.as_str(), "==" | "!=" | "<" | ">" | "<=" | ">=")
    }

    /// Whether this is an arithmetic operator.
    pub fn is_arithmetic(&self) -> bool {
        matches!(self.text.as_str(), "+" | "-" | "*" | "/" | "%")
    }

    /// Whether this is a logical operator.
    pub fn is_logical(&self) -> bool {
        matches!(self.text.as_str(), "&&" | "||" | "!")
    }

    /// Whether this is a bitwise operator.
    pub fn is_bitwise(&self) -> bool {
        matches!(self.text.as_str(), "&" | "|" | "^" | "~" | "<<" | ">>")
    }

    /// Whether this is a member access operator.
    pub fn is_member_access(&self) -> bool {
        matches!(self.text.as_str(), "." | "->")
    }

    /// Whether this is a unary prefix operator.
    pub fn is_unary_prefix(&self) -> bool {
        matches!(
            self.text.as_str(),
            "!" | "~" | "-" | "++" | "--" | "&" | "*" | "sizeof"
        )
    }

    /// Get the operator precedence (lower number = higher precedence).
    pub fn precedence(&self) -> Option<u8> {
        match self.text.as_str() {
            "()" | "[]" | "." | "->" => Some(1),
            "++" | "--" | "!" | "~" | "sizeof" | "&" | "*" => Some(2),
            "*" | "/" | "%" => Some(3),
            "+" | "-" => Some(4),
            "<<" | ">>" => Some(5),
            "<" | ">" | "<=" | ">=" => Some(6),
            "==" | "!=" => Some(7),
            "&" => Some(8),
            "^" => Some(9),
            "|" => Some(10),
            "&&" => Some(11),
            "||" => Some(12),
            "?" => Some(13),
            "=" | "+=" | "-=" | "*=" | "/=" | "%=" | "&=" | "|=" | "^=" | "<<=" | ">>=" => {
                Some(14)
            }
            "," => Some(15),
            _ => None,
        }
    }

    /// Whether this is a ternary operator part.
    pub fn is_ternary(&self) -> bool {
        self.text == "?"
    }

    /// Whether this is a semicolon.
    pub fn is_semicolon(&self) -> bool {
        self.text == ";"
    }

    /// Whether this is a comma.
    pub fn is_comma(&self) -> bool {
        self.text == ","
    }
}

// ============================================================================
// ClangFuncNameToken
// ============================================================================

/// A token representing a function name reference in decompiled code.
///
/// Ported from `ghidra.app.decompiler.ClangFuncNameToken`.
#[derive(Debug, Clone)]
pub struct ClangFuncNameToken {
    /// The function name text.
    pub text: String,
    /// The PcodeOp reference (op index) calling this function.
    pub op_ref: Option<usize>,
    /// Address of the associated PcodeOp.
    pub op_address: Option<u64>,
    /// The called function's entry address.
    pub function_address: Option<u64>,
    /// Syntax type (always Function).
    pub syntax_type: SyntaxType,
}

impl ClangFuncNameToken {
    /// Create a new function name token.
    pub fn new(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            op_ref: None,
            op_address: None,
            function_address: None,
            syntax_type: SyntaxType::Function,
        }
    }

    /// Whether this is a variable reference.
    pub fn is_variable_ref(&self) -> bool {
        self.function_address.is_some()
    }

    /// Get the minimum address.
    pub fn min_address(&self) -> Option<u64> {
        self.op_address
    }

    /// Get the maximum address.
    pub fn max_address(&self) -> Option<u64> {
        self.op_address
    }
}

// ============================================================================
// ClangSyntaxToken
// ============================================================================

/// A token representing a syntax element like braces, parentheses, or semicolons.
///
/// Ported from `ghidra.app.decompiler.ClangSyntaxToken`.
#[derive(Debug, Clone)]
pub struct ClangSyntaxToken {
    /// The syntax text (e.g., "{", "}", ";", ",").
    pub text: String,
    /// Syntax type (usually Special).
    pub syntax_type: SyntaxType,
    /// Parent node index.
    pub parent_id: Option<usize>,
}

impl ClangSyntaxToken {
    /// Create a new syntax token.
    pub fn new(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            syntax_type: SyntaxType::Special,
            parent_id: None,
        }
    }

    /// Whether this is an opening brace/bracket/paren.
    pub fn is_open(&self) -> bool {
        matches!(self.text.as_str(), "{" | "(" | "[")
    }

    /// Whether this is a closing brace/bracket/paren.
    pub fn is_close(&self) -> bool {
        matches!(self.text.as_str(), "}" | ")" | "]")
    }

    /// Whether this is a brace (curly bracket).
    pub fn is_brace(&self) -> bool {
        matches!(self.text.as_str(), "{" | "}")
    }

    /// Whether this is a semicolon.
    pub fn is_semicolon(&self) -> bool {
        self.text == ";"
    }

    /// Whether this is a comma.
    pub fn is_comma(&self) -> bool {
        self.text == ","
    }

    /// Whether this is a variable reference (always false).
    pub fn is_variable_ref(&self) -> bool {
        false
    }
}

// ============================================================================
// ClangTypeToken
// ============================================================================

/// A token representing a data type name in decompiled code.
///
/// Ported from `ghidra.app.decompiler.ClangTypeToken`.
#[derive(Debug, Clone)]
pub struct ClangTypeToken {
    /// The type name text.
    pub text: String,
    /// The data type id.
    pub data_type_id: Option<u64>,
    /// Syntax type (always Type).
    pub syntax_type: SyntaxType,
    /// Parent node index.
    pub parent_id: Option<usize>,
}

impl ClangTypeToken {
    /// Create a new type token.
    pub fn new(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            data_type_id: None,
            syntax_type: SyntaxType::Type,
            parent_id: None,
        }
    }

    /// Whether this is a variable reference.
    pub fn is_variable_ref(&self) -> bool {
        false
    }

    /// Whether this represents a primitive type.
    pub fn is_primitive(&self) -> bool {
        matches!(
            self.text.as_str(),
            "void" | "char" | "short" | "int" | "long" | "float" | "double"
                | "unsigned" | "signed" | "bool" | "uint8_t" | "uint16_t" | "uint32_t"
                | "uint64_t" | "int8_t" | "int16_t" | "int32_t" | "int64_t" | "size_t"
                | "uchar" | "ushort" | "uint" | "ulong" | "undefined" | "undefined1"
                | "undefined2" | "undefined4" | "undefined8"
        )
    }
}

// ============================================================================
// ClangLabelToken
// ============================================================================

/// A token representing a label reference in decompiled code (goto targets).
///
/// Ported from `ghidra.app.decompiler.ClangLabelToken`.
#[derive(Debug, Clone)]
pub struct ClangLabelToken {
    /// The label text.
    pub text: String,
    /// The PcodeOp reference (op index) for the jump to this label.
    pub op_ref: Option<usize>,
    /// Address of the associated PcodeOp.
    pub op_address: Option<u64>,
    /// Syntax type.
    pub syntax_type: SyntaxType,
}

impl ClangLabelToken {
    /// Create a new label token.
    pub fn new(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            op_ref: None,
            op_address: None,
            syntax_type: SyntaxType::Default,
        }
    }

    /// Whether this is a variable reference.
    pub fn is_variable_ref(&self) -> bool {
        false
    }

    /// Get the minimum address.
    pub fn min_address(&self) -> Option<u64> {
        self.op_address
    }

    /// Get the maximum address.
    pub fn max_address(&self) -> Option<u64> {
        self.op_address
    }
}

// ============================================================================
// ClangTokenClassifier
// ============================================================================

/// Classifies operator tokens into categories for highlighting.
///
/// Ported from the static methods in `ghidra.app.decompiler.ClangOpToken`.
#[derive(Debug, Clone)]
pub struct ClangTokenClassifier;

impl ClangTokenClassifier {
    /// Classify an operator token text into a category string.
    pub fn classify_operator(text: &str) -> &'static str {
        match text {
            "=" | "+=" | "-=" | "*=" | "/=" | "%=" | "&=" | "|=" | "^=" | "<<=" | ">>=" => {
                "assignment"
            }
            "==" | "!=" | "<" | ">" | "<=" | ">=" => "comparison",
            "+" | "-" | "*" | "/" | "%" => "arithmetic",
            "&&" | "||" | "!" => "logical",
            "&" | "|" | "^" | "~" | "<<" | ">>" => "bitwise",
            "." | "->" | "::" => "member_access",
            "?" | ":" => "ternary",
            "," => "comma",
            ";" => "semicolon",
            "{" | "}" | "(" | ")" | "[" | "]" => "grouping",
            "++" | "--" => "increment",
            "sizeof" | "typeof" => "sizeof",
            "return" | "goto" | "break" | "continue" => "flow",
            _ => "other",
        }
    }

    /// Whether a text string represents a keyword.
    pub fn is_keyword(text: &str) -> bool {
        matches!(
            text,
            "if" | "else"
                | "while"
                | "for"
                | "do"
                | "switch"
                | "case"
                | "default"
                | "break"
                | "continue"
                | "return"
                | "goto"
                | "struct"
                | "union"
                | "enum"
                | "typedef"
                | "const"
                | "volatile"
                | "static"
                | "extern"
                | "register"
                | "auto"
                | "sizeof"
                | "void"
                | "null"
                | "true"
                | "false"
        )
    }

    /// Whether a text string represents a type keyword.
    pub fn is_type_keyword(text: &str) -> bool {
        matches!(
            text,
            "void" | "char" | "short" | "int" | "long" | "float" | "double" | "signed"
                | "unsigned" | "bool" | "const" | "volatile" | "struct" | "union" | "enum"
                | "typedef"
        )
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_syntax_type_from_i32() {
        assert_eq!(SyntaxType::from_i32(0), SyntaxType::Keyword);
        assert_eq!(SyntaxType::from_i32(1), SyntaxType::Type);
        assert_eq!(SyntaxType::from_i32(2), SyntaxType::Function);
        assert_eq!(SyntaxType::from_i32(8), SyntaxType::Comment);
        assert_eq!(SyntaxType::from_i32(99), SyntaxType::Default);
    }

    #[test]
    fn test_syntax_type_color_name() {
        assert_eq!(SyntaxType::Keyword.color_name(), "keyword");
        assert_eq!(SyntaxType::Comment.color_name(), "comment");
    }

    #[test]
    fn test_clang_comment_token() {
        let mut token = ClangCommentToken::new("this is a comment");
        assert_eq!(token.text, "this is a comment");
        assert!(!token.is_variable_ref());
        assert!(token.min_address().is_none());

        token.source_address = Some(0x1000);
        assert_eq!(token.min_address(), Some(0x1000));
        assert_eq!(token.max_address(), Some(0x1000));

        let derived = ClangCommentToken::derive(&token, "derived comment");
        assert_eq!(derived.text, "derived comment");
        assert_eq!(derived.source_address, Some(0x1000));
    }

    #[test]
    fn test_clang_case_token() {
        let mut token = ClangCaseToken::new();
        token.value = 42;
        token.text = "case 42:".to_string();
        assert_eq!(token.get_value(), 42);
        assert!(token.is_variable_ref());
        assert!(!token.is_negative());

        token.value = -1;
        assert!(token.is_negative());
        assert_eq!(token.unsigned_value(), u64::MAX);
    }

    #[test]
    fn test_clang_field_token() {
        let mut token = ClangFieldToken::new("myField");
        token.data_type_name = Some("MyStruct".to_string());
        token.offset = 8;
        assert_eq!(token.text, "myField");
        assert_eq!(token.data_type_name(), Some("MyStruct"));
        assert_eq!(token.offset(), 8);
        assert!(!token.is_variable_ref());

        token.op_ref = Some(5);
        assert!(token.is_variable_ref());
    }

    #[test]
    fn test_clang_variable_decl() {
        let mut decl = ClangVariableDecl::new();
        decl.data_type_name = Some("int".to_string());
        decl.variable_name = Some("x".to_string());
        decl.add_child(0);
        decl.add_child(1);
        assert_eq!(decl.num_children(), 2);
        assert_eq!(decl.data_type_name(), Some("int"));
    }

    #[test]
    fn test_clang_func_proto() {
        let mut proto = ClangFuncProto::new();
        proto.add_child(0);
        proto.add_child(1);
        proto.add_child(2);
        assert_eq!(proto.num_children(), 3);
    }

    #[test]
    fn test_clang_return_type() {
        let mut ret = ClangReturnType::new();
        ret.data_type_name = Some("void".to_string());
        assert_eq!(ret.data_type_name(), Some("void"));
        assert!(!ret.has_varnode());
        ret.varnode_ref = Some(10);
        assert!(ret.has_varnode());
    }

    #[test]
    fn test_clang_op_token() {
        let op = ClangOpToken::new("+");
        assert!(op.is_arithmetic());
        assert!(!op.is_assignment());
        assert!(!op.is_comparison());
        assert_eq!(op.precedence(), Some(4));

        let assign = ClangOpToken::new("+=");
        assert!(assign.is_assignment());
        assert_eq!(assign.precedence(), Some(14));

        let member = ClangOpToken::new("->");
        assert!(member.is_member_access());
        assert_eq!(member.precedence(), Some(1));

        let logical = ClangOpToken::new("&&");
        assert!(logical.is_logical());
        assert_eq!(logical.precedence(), Some(11));

        let semi = ClangOpToken::new(";");
        assert!(semi.is_semicolon());
        assert!(semi.precedence().is_none());
    }

    #[test]
    fn test_clang_func_name_token() {
        let mut token = ClangFuncNameToken::new("printf");
        token.function_address = Some(0x804000);
        assert_eq!(token.text, "printf");
        assert!(token.is_variable_ref());

        let token2 = ClangFuncNameToken::new("unknown");
        assert!(!token2.is_variable_ref());
    }

    #[test]
    fn test_clang_syntax_token() {
        let open = ClangSyntaxToken::new("{");
        assert!(open.is_open());
        assert!(!open.is_close());
        assert!(open.is_brace());
        assert!(!open.is_variable_ref());

        let close = ClangSyntaxToken::new("}");
        assert!(!close.is_open());
        assert!(close.is_close());
        assert!(close.is_brace());

        let semi = ClangSyntaxToken::new(";");
        assert!(semi.is_semicolon());
        assert!(!semi.is_brace());
    }

    #[test]
    fn test_clang_type_token() {
        let int_type = ClangTypeToken::new("int");
        assert!(int_type.is_primitive());
        assert_eq!(int_type.syntax_type, SyntaxType::Type);

        let custom = ClangTypeToken::new("MyStruct");
        assert!(!custom.is_primitive());
    }

    #[test]
    fn test_clang_label_token() {
        let label = ClangLabelToken::new("LAB_001000");
        assert_eq!(label.text, "LAB_001000");
        assert!(!label.is_variable_ref());
    }

    #[test]
    fn test_token_classifier() {
        assert_eq!(
            ClangTokenClassifier::classify_operator("+"),
            "arithmetic"
        );
        assert_eq!(
            ClangTokenClassifier::classify_operator("=="),
            "comparison"
        );
        assert_eq!(
            ClangTokenClassifier::classify_operator("&&"),
            "logical"
        );
        assert_eq!(
            ClangTokenClassifier::classify_operator("->"),
            "member_access"
        );
        assert_eq!(
            ClangTokenClassifier::classify_operator("{"),
            "grouping"
        );
    }

    #[test]
    fn test_token_classifier_keywords() {
        assert!(ClangTokenClassifier::is_keyword("if"));
        assert!(ClangTokenClassifier::is_keyword("return"));
        assert!(ClangTokenClassifier::is_keyword("struct"));
        assert!(!ClangTokenClassifier::is_keyword("myvar"));
        assert!(!ClangTokenClassifier::is_keyword("printf"));

        assert!(ClangTokenClassifier::is_type_keyword("int"));
        assert!(ClangTokenClassifier::is_type_keyword("void"));
        assert!(ClangTokenClassifier::is_type_keyword("const"));
        assert!(!ClangTokenClassifier::is_type_keyword("myvar"));
    }

    #[test]
    fn test_op_token_precedence_order() {
        let dot = ClangOpToken::new(".");
        let mul = ClangOpToken::new("*");
        let add = ClangOpToken::new("+");
        let and = ClangOpToken::new("&&");
        let assign = ClangOpToken::new("=");
        let comma = ClangOpToken::new(",");

        assert!(dot.precedence() < mul.precedence());
        assert!(mul.precedence() < add.precedence());
        assert!(add.precedence() < and.precedence());
        assert!(and.precedence() < assign.precedence());
        assert!(assign.precedence() < comma.precedence());
    }
}
