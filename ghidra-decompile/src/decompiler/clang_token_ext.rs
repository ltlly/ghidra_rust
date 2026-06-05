//! Extended Clang token types for the decompiler.
//!
//! Ports Ghidra's specialized Clang token types:
//! - `ClangFuncNameToken` -- function name with HighFunction link
//! - `ClangSyntaxToken` -- keyword / syntax token
//! - `ClangVariableToken` -- variable reference token
//! - `ClangTypeToken` -- type name token
//! - `ClangOpToken` -- operator token
//! - `ClangFieldToken` -- struct field token
//! - `ClangBitFieldToken` -- bit-field token
//! - `ClangCommentToken` -- comment token
//! - `ClangLabelToken` -- label token
//! - `ClangCaseToken` -- case label token
//! - `ClangReturnType` -- return type token
//! - `ClangVariableDecl` -- variable declaration
//! - `ClangFuncProto` -- function prototype
//! - `ClangStatement` -- a single statement
//! - `ClangTokenGroup` -- group of tokens
//! - `ClangFunction` -- entire function body
//! - `ClangOpToken` -- operator token

use std::fmt;

use ghidra_core::addr::Address;

/// Trait for decompiler output tokens.
///
/// Ports Ghidra's `ClangToken` interface, providing a uniform
/// way to access text, type, address, and parent information for
/// all token types in the decompiler's AST.
pub trait ClangTokenExt {
    /// The display text of this token.
    fn text(&self) -> &str;
    /// The token type classifier string.
    fn token_type(&self) -> &str;
    /// Source address, if applicable.
    fn address(&self) -> Option<Address> { None }
    /// Parent node index, if applicable.
    fn parent(&self) -> Option<usize> { None }
}

// ============================================================================
// ClangSyntaxToken -- a keyword or syntax token
// ============================================================================

/// A keyword or syntax punctuation token in the decompiler output.
///
/// Port of Ghidra's `ClangSyntaxToken`.
#[derive(Debug, Clone)]
pub struct ClangSyntaxToken {
    /// The text of the syntax token.
    pub text: String,
    /// The parent node.
    pub parent: Option<usize>,
    /// Source address, if any.
    pub address: Option<Address>,
    /// Syntax category.
    pub category: SyntaxCategory,
}

/// The category of a syntax token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyntaxCategory {
    /// A language keyword (if, else, while, return, ...).
    Keyword,
    /// Punctuation (parentheses, braces, semicolons, ...).
    Punctuation,
    /// An operator (+, -, *, /, ...).
    Operator,
    /// Whitespace or formatting.
    Whitespace,
}

impl ClangSyntaxToken {
    /// Create a new syntax token.
    pub fn new(text: impl Into<String>, category: SyntaxCategory) -> Self {
        Self {
            text: text.into(),
            parent: None,
            address: None,
            category,
        }
    }

    /// Set the source address.
    pub fn with_address(mut self, addr: Address) -> Self {
        self.address = Some(addr);
        self
    }
}

impl ClangTokenExt for ClangSyntaxToken {
    fn text(&self) -> &str {
        &self.text
    }

    fn token_type(&self) -> &str {
        match self.category {
            SyntaxCategory::Keyword => "keyword",
            SyntaxCategory::Punctuation => "punctuation",
            SyntaxCategory::Operator => "operator",
            SyntaxCategory::Whitespace => "whitespace",
        }
    }

    fn address(&self) -> Option<Address> {
        self.address
    }

    fn parent(&self) -> Option<usize> {
        self.parent
    }
}

impl fmt::Display for ClangSyntaxToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.text)
    }
}

// ============================================================================
// ClangFuncNameToken -- function name with p-code link
// ============================================================================

/// A source code token representing a function name.
///
/// Contains a link back to the p-code function object.
/// Port of Ghidra's `ClangFuncNameToken`.
#[derive(Debug, Clone)]
pub struct ClangFuncNameToken {
    /// The function name text.
    pub text: String,
    /// The parent node.
    pub parent: Option<usize>,
    /// The function entry address.
    pub entry_address: Option<Address>,
    /// Whether the function is a thunk.
    pub is_thunk: bool,
    /// The calling convention name.
    pub calling_convention: Option<String>,
}

impl ClangFuncNameToken {
    /// Create a new function name token.
    pub fn new(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            parent: None,
            entry_address: None,
            is_thunk: false,
            calling_convention: None,
        }
    }

    /// Set the entry address.
    pub fn with_entry(mut self, addr: Address) -> Self {
        self.entry_address = Some(addr);
        self
    }

    /// Set whether this is a thunk function.
    pub fn with_thunk(mut self, is_thunk: bool) -> Self {
        self.is_thunk = is_thunk;
        self
    }
}

impl ClangTokenExt for ClangFuncNameToken {
    fn text(&self) -> &str {
        &self.text
    }

    fn token_type(&self) -> &str {
        "funcname"
    }

    fn address(&self) -> Option<Address> {
        self.entry_address
    }

    fn parent(&self) -> Option<usize> {
        self.parent
    }
}

impl fmt::Display for ClangFuncNameToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.text)
    }
}

// ============================================================================
// ClangVariableToken -- variable reference
// ============================================================================

/// A token representing a variable reference in the decompiler output.
///
/// Port of Ghidra's `ClangVariableToken`.
#[derive(Debug, Clone)]
pub struct ClangVariableToken {
    /// The variable name.
    pub text: String,
    /// The parent node.
    pub parent: Option<usize>,
    /// Source address.
    pub address: Option<Address>,
    /// Variable scope info.
    pub scope: VariableScope,
    /// Variable size in bytes.
    pub size: u32,
}

/// The scope of a variable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VariableScope {
    /// Local variable.
    Local,
    /// Global variable.
    Global,
    /// Parameter.
    Parameter,
    /// Register.
    Register,
}

impl ClangVariableToken {
    /// Create a new variable token.
    pub fn new(text: impl Into<String>, scope: VariableScope) -> Self {
        Self {
            text: text.into(),
            parent: None,
            address: None,
            scope,
            size: 0,
        }
    }

    /// Set the variable size.
    pub fn with_size(mut self, size: u32) -> Self {
        self.size = size;
        self
    }
}

impl ClangTokenExt for ClangVariableToken {
    fn text(&self) -> &str {
        &self.text
    }

    fn token_type(&self) -> &str {
        match self.scope {
            VariableScope::Local => "var_local",
            VariableScope::Global => "var_global",
            VariableScope::Parameter => "var_param",
            VariableScope::Register => "var_register",
        }
    }

    fn address(&self) -> Option<Address> {
        self.address
    }

    fn parent(&self) -> Option<usize> {
        self.parent
    }
}

impl fmt::Display for ClangVariableToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.text)
    }
}

// ============================================================================
// ClangTypeToken -- type name
// ============================================================================

/// A token representing a type name.
///
/// Port of Ghidra's `ClangTypeToken`.
#[derive(Debug, Clone)]
pub struct ClangTypeToken {
    /// The type name.
    pub text: String,
    /// The parent node.
    pub parent: Option<usize>,
    /// Source address.
    pub address: Option<Address>,
    /// Whether this is a pointer type.
    pub is_pointer: bool,
}

impl ClangTypeToken {
    /// Create a new type token.
    pub fn new(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            parent: None,
            address: None,
            is_pointer: false,
        }
    }
}

impl ClangTokenExt for ClangTypeToken {
    fn text(&self) -> &str { &self.text }
    fn token_type(&self) -> &str { "type" }
    fn address(&self) -> Option<Address> { self.address }
    fn parent(&self) -> Option<usize> { self.parent }
}

impl fmt::Display for ClangTypeToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.text)
    }
}

// ============================================================================
// ClangFieldToken -- struct field reference
// ============================================================================

/// A token representing a struct field access.
///
/// Port of Ghidra's `ClangFieldToken`.
#[derive(Debug, Clone)]
pub struct ClangFieldToken {
    /// The field name.
    pub text: String,
    /// The parent node.
    pub parent: Option<usize>,
    /// Source address.
    pub address: Option<Address>,
    /// The parent structure offset.
    pub struct_offset: Option<u64>,
    /// Field size in bytes.
    pub field_size: u32,
}

impl ClangFieldToken {
    /// Create a new field token.
    pub fn new(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            parent: None,
            address: None,
            struct_offset: None,
            field_size: 0,
        }
    }

    /// Set the struct offset.
    pub fn with_offset(mut self, offset: u64) -> Self {
        self.struct_offset = Some(offset);
        self
    }

    /// Set the field size.
    pub fn with_field_size(mut self, size: u32) -> Self {
        self.field_size = size;
        self
    }
}

impl ClangTokenExt for ClangFieldToken {
    fn text(&self) -> &str { &self.text }
    fn token_type(&self) -> &str { "field" }
    fn address(&self) -> Option<Address> { self.address }
    fn parent(&self) -> Option<usize> { self.parent }
}

impl fmt::Display for ClangFieldToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.text)
    }
}

// ============================================================================
// ClangBitFieldToken -- bit-field reference
// ============================================================================

/// A token representing a bit-field access.
///
/// Port of Ghidra's `ClangBitFieldToken`.
#[derive(Debug, Clone)]
pub struct ClangBitFieldToken {
    /// The field name.
    pub text: String,
    /// The parent node.
    pub parent: Option<usize>,
    /// Bit offset within the containing word.
    pub bit_offset: u32,
    /// Bit size of the field.
    pub bit_size: u32,
}

impl ClangBitFieldToken {
    /// Create a new bit-field token.
    pub fn new(text: impl Into<String>, bit_offset: u32, bit_size: u32) -> Self {
        Self {
            text: text.into(),
            parent: None,
            bit_offset,
            bit_size,
        }
    }
}

impl ClangTokenExt for ClangBitFieldToken {
    fn text(&self) -> &str { &self.text }
    fn token_type(&self) -> &str { "bitfield" }
    fn address(&self) -> Option<Address> { None }
    fn parent(&self) -> Option<usize> { self.parent }
}

impl fmt::Display for ClangBitFieldToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.text)
    }
}

// ============================================================================
// ClangCommentToken
// ============================================================================

/// A comment in the decompiler output.
///
/// Port of Ghidra's `ClangCommentToken`.
#[derive(Debug, Clone)]
pub struct ClangCommentToken {
    /// The comment text (without delimiters).
    pub text: String,
    /// The parent node.
    pub parent: Option<usize>,
    /// Source address.
    pub address: Option<Address>,
    /// Whether this is a pre-existing comment (from the binary) vs generated.
    pub is_user_comment: bool,
}

impl ClangCommentToken {
    /// Create a new comment token.
    pub fn new(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            parent: None,
            address: None,
            is_user_comment: false,
        }
    }

    /// Mark as a user (pre-existing) comment.
    pub fn user_comment(mut self) -> Self {
        self.is_user_comment = true;
        self
    }
}

impl ClangTokenExt for ClangCommentToken {
    fn text(&self) -> &str { &self.text }
    fn token_type(&self) -> &str { "comment" }
    fn address(&self) -> Option<Address> { self.address }
    fn parent(&self) -> Option<usize> { self.parent }
}

impl fmt::Display for ClangCommentToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "/* {} */", self.text)
    }
}

// ============================================================================
// ClangLabelToken -- goto label
// ============================================================================

/// A goto label in the decompiler output.
///
/// Port of Ghidra's `ClangLabelToken`.
#[derive(Debug, Clone)]
pub struct ClangLabelToken {
    /// The label name.
    pub text: String,
    /// The parent node.
    pub parent: Option<usize>,
    /// Source address.
    pub address: Option<Address>,
}

impl ClangLabelToken {
    /// Create a new label token.
    pub fn new(text: impl Into<String>) -> Self {
        Self { text: text.into(), parent: None, address: None }
    }
}

impl ClangTokenExt for ClangLabelToken {
    fn text(&self) -> &str { &self.text }
    fn token_type(&self) -> &str { "label" }
    fn address(&self) -> Option<Address> { self.address }
    fn parent(&self) -> Option<usize> { self.parent }
}

impl fmt::Display for ClangLabelToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:", self.text)
    }
}

// ============================================================================
// ClangCaseToken -- case label
// ============================================================================

/// A case label in a switch statement.
///
/// Port of Ghidra's `ClangCaseToken`.
#[derive(Debug, Clone)]
pub struct ClangCaseToken {
    /// The case value text.
    pub text: String,
    /// The parent node.
    pub parent: Option<usize>,
    /// Source address.
    pub address: Option<Address>,
    /// Whether this is the default case.
    pub is_default: bool,
    /// The case value (if numeric).
    pub value: Option<i64>,
}

impl ClangCaseToken {
    /// Create a new case token with a numeric value.
    pub fn new(value: i64) -> Self {
        Self {
            text: value.to_string(),
            parent: None,
            address: None,
            is_default: false,
            value: Some(value),
        }
    }

    /// Create a default case token.
    pub fn default_case() -> Self {
        Self {
            text: "default".to_string(),
            parent: None,
            address: None,
            is_default: true,
            value: None,
        }
    }
}

impl ClangTokenExt for ClangCaseToken {
    fn text(&self) -> &str { &self.text }
    fn token_type(&self) -> &str { "case" }
    fn address(&self) -> Option<Address> { self.address }
    fn parent(&self) -> Option<usize> { self.parent }
}

impl fmt::Display for ClangCaseToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_default {
            write!(f, "default:")
        } else {
            write!(f, "case {}:", self.text)
        }
    }
}

// ============================================================================
// ClangReturnType -- return type token
// ============================================================================

/// A return type token in a function prototype.
///
/// Port of Ghidra's `ClangReturnType`.
#[derive(Debug, Clone)]
pub struct ClangReturnType {
    /// The return type text.
    pub text: String,
    /// The parent node.
    pub parent: Option<usize>,
    /// Source address.
    pub address: Option<Address>,
}

impl ClangReturnType {
    /// Create a new return type token.
    pub fn new(text: impl Into<String>) -> Self {
        Self { text: text.into(), parent: None, address: None }
    }
}

impl ClangTokenExt for ClangReturnType {
    fn text(&self) -> &str { &self.text }
    fn token_type(&self) -> &str { "return_type" }
    fn address(&self) -> Option<Address> { self.address }
    fn parent(&self) -> Option<usize> { self.parent }
}

impl fmt::Display for ClangReturnType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.text)
    }
}

// ============================================================================
// ClangVariableDecl -- variable declaration
// ============================================================================

/// A variable declaration token.
///
/// Port of Ghidra's `ClangVariableDecl`.
#[derive(Debug, Clone)]
pub struct ClangVariableDecl {
    /// The variable name.
    pub name: String,
    /// The type text.
    pub type_text: String,
    /// The parent node.
    pub parent: Option<usize>,
    /// Source address.
    pub address: Option<Address>,
    /// Variable size in bytes.
    pub size: u32,
}

impl ClangVariableDecl {
    /// Create a new variable declaration.
    pub fn new(name: impl Into<String>, type_text: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            type_text: type_text.into(),
            parent: None,
            address: None,
            size: 0,
        }
    }
}

impl ClangTokenExt for ClangVariableDecl {
    fn text(&self) -> &str { &self.name }
    fn token_type(&self) -> &str { "var_decl" }
    fn address(&self) -> Option<Address> { self.address }
    fn parent(&self) -> Option<usize> { self.parent }
}

impl fmt::Display for ClangVariableDecl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.type_text, self.name)
    }
}

// ============================================================================
// ClangFuncProto -- function prototype
// ============================================================================

/// A function prototype token group.
///
/// Port of Ghidra's `ClangFuncProto`.
#[derive(Debug, Clone)]
pub struct ClangFuncProto {
    /// The function name.
    pub name: String,
    /// The return type text.
    pub return_type: String,
    /// Parameter names and types.
    pub parameters: Vec<(String, String)>,
    /// The parent node.
    pub parent: Option<usize>,
    /// Source address.
    pub address: Option<Address>,
    /// The calling convention.
    pub calling_convention: Option<String>,
}

impl ClangFuncProto {
    /// Create a new function prototype.
    pub fn new(name: impl Into<String>, return_type: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            return_type: return_type.into(),
            parameters: Vec::new(),
            parent: None,
            address: None,
            calling_convention: None,
        }
    }

    /// Add a parameter.
    pub fn add_param(&mut self, type_name: impl Into<String>, param_name: impl Into<String>) {
        self.parameters.push((type_name.into(), param_name.into()));
    }
}

impl ClangTokenExt for ClangFuncProto {
    fn text(&self) -> &str { &self.name }
    fn token_type(&self) -> &str { "func_proto" }
    fn address(&self) -> Option<Address> { self.address }
    fn parent(&self) -> Option<usize> { self.parent }
}

impl fmt::Display for ClangFuncProto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let params: Vec<String> = self.parameters.iter()
            .map(|(t, n)| format!("{} {}", t, n))
            .collect();
        write!(f, "{} {}({})", self.return_type, self.name, params.join(", "))
    }
}

// ============================================================================
// ClangStatement -- a single statement
// ============================================================================

/// A statement node containing tokens.
///
/// Port of Ghidra's `ClangStatement`.
#[derive(Debug, Clone)]
pub struct ClangStatement {
    /// Child token indices.
    pub children: Vec<usize>,
    /// The parent node.
    pub parent: Option<usize>,
    /// Source address.
    pub address: Option<Address>,
    /// Whether this is a compound statement (block).
    pub is_compound: bool,
}

impl ClangStatement {
    /// Create a new statement.
    pub fn new() -> Self {
        Self { children: Vec::new(), parent: None, address: None, is_compound: false }
    }

    /// Add a child token index.
    pub fn add_child(&mut self, child_idx: usize) {
        self.children.push(child_idx);
    }
}

impl Default for ClangStatement {
    fn default() -> Self { Self::new() }
}

impl ClangTokenExt for ClangStatement {
    fn text(&self) -> &str { ";" }
    fn token_type(&self) -> &str { "statement" }
    fn address(&self) -> Option<Address> { self.address }
    fn parent(&self) -> Option<usize> { self.parent }
}

// ============================================================================
// ClangTokenGroup -- a group of tokens
// ============================================================================

/// A group of tokens (used for grouping expressions, etc.).
///
/// Port of Ghidra's `ClangTokenGroup`.
#[derive(Debug, Clone)]
pub struct ClangTokenGroup {
    /// Child token indices.
    pub children: Vec<usize>,
    /// The parent node.
    pub parent: Option<usize>,
}

impl ClangTokenGroup {
    /// Create a new token group.
    pub fn new() -> Self {
        Self { children: Vec::new(), parent: None }
    }

    /// Add a child token index.
    pub fn add_child(&mut self, child_idx: usize) {
        self.children.push(child_idx);
    }

    /// Number of children.
    pub fn len(&self) -> usize {
        self.children.len()
    }

    /// Whether the group is empty.
    pub fn is_empty(&self) -> bool {
        self.children.is_empty()
    }
}

impl Default for ClangTokenGroup {
    fn default() -> Self { Self::new() }
}

// ============================================================================
// ClangFunction -- entire function
// ============================================================================

/// Root node representing an entire decompiled function.
///
/// Port of Ghidra's `ClangFunction`.
#[derive(Debug, Clone)]
pub struct ClangFunction {
    /// The function name.
    pub name: String,
    /// The return type.
    pub return_type: String,
    /// Entry address.
    pub entry_address: Address,
    /// Child token indices (includes prototype + body).
    pub children: Vec<usize>,
    /// Parameter declarations.
    pub parameters: Vec<ClangVariableDecl>,
    /// Local variable declarations.
    pub locals: Vec<ClangVariableDecl>,
}

impl ClangFunction {
    /// Create a new function node.
    pub fn new(name: impl Into<String>, return_type: impl Into<String>, entry: Address) -> Self {
        Self {
            name: name.into(),
            return_type: return_type.into(),
            entry_address: entry,
            children: Vec::new(),
            parameters: Vec::new(),
            locals: Vec::new(),
        }
    }

    /// Add a child token index.
    pub fn add_child(&mut self, child_idx: usize) {
        self.children.push(child_idx);
    }

    /// Add a parameter declaration.
    pub fn add_parameter(&mut self, param: ClangVariableDecl) {
        self.parameters.push(param);
    }

    /// Add a local variable declaration.
    pub fn add_local(&mut self, local: ClangVariableDecl) {
        self.locals.push(local);
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn syntax_token_basic() {
        let tok = ClangSyntaxToken::new("if", SyntaxCategory::Keyword);
        assert_eq!(tok.text(), "if");
        assert_eq!(tok.token_type(), "keyword");
    }

    #[test]
    fn func_name_token() {
        let tok = ClangFuncNameToken::new("main").with_entry(Address::new(0x1000));
        assert_eq!(tok.text(), "main");
        assert_eq!(tok.token_type(), "funcname");
        assert_eq!(tok.entry_address, Some(Address::new(0x1000)));
    }

    #[test]
    fn variable_token_scopes() {
        let local = ClangVariableToken::new("x", VariableScope::Local);
        assert_eq!(local.token_type(), "var_local");

        let param = ClangVariableToken::new("a", VariableScope::Parameter);
        assert_eq!(param.token_type(), "var_param");

        let global = ClangVariableToken::new("g", VariableScope::Global);
        assert_eq!(global.token_type(), "var_global");
    }

    #[test]
    fn type_token() {
        let tok = ClangTypeToken::new("int");
        assert_eq!(tok.text(), "int");
        assert_eq!(tok.token_type(), "type");
    }

    #[test]
    fn field_token_with_offset() {
        let tok = ClangFieldToken::new("value").with_offset(0x10).with_field_size(4);
        assert_eq!(tok.text(), "value");
        assert_eq!(tok.struct_offset, Some(0x10));
        assert_eq!(tok.field_size, 4);
    }

    #[test]
    fn bit_field_token() {
        let tok = ClangBitFieldToken::new("flags", 3, 5);
        assert_eq!(tok.text(), "flags");
        assert_eq!(tok.bit_offset, 3);
        assert_eq!(tok.bit_size, 5);
    }

    #[test]
    fn comment_token() {
        let tok = ClangCommentToken::new("hello").user_comment();
        assert_eq!(tok.text(), "hello");
        assert!(tok.is_user_comment);
        assert_eq!(format!("{}", tok), "/* hello */");
    }

    #[test]
    fn label_token() {
        let tok = ClangLabelToken::new("loop_start");
        assert_eq!(format!("{}", tok), "loop_start:");
    }

    #[test]
    fn case_token_numeric() {
        let tok = ClangCaseToken::new(42);
        assert_eq!(tok.value, Some(42));
        assert!(!tok.is_default);
        assert_eq!(format!("{}", tok), "case 42:");
    }

    #[test]
    fn case_token_default() {
        let tok = ClangCaseToken::default_case();
        assert!(tok.is_default);
        assert_eq!(format!("{}", tok), "default:");
    }

    #[test]
    fn return_type_token() {
        let tok = ClangReturnType::new("void");
        assert_eq!(tok.text(), "void");
    }

    #[test]
    fn variable_decl_display() {
        let decl = ClangVariableDecl::new("count", "int");
        assert_eq!(format!("{}", decl), "int count");
    }

    #[test]
    fn func_proto_display() {
        let mut proto = ClangFuncProto::new("add", "int");
        proto.add_param("int", "a");
        proto.add_param("int", "b");
        assert_eq!(format!("{}", proto), "int add(int a, int b)");
    }

    #[test]
    fn statement_basic() {
        let mut stmt = ClangStatement::new();
        stmt.add_child(0);
        stmt.add_child(1);
        assert_eq!(stmt.children.len(), 2);
    }

    #[test]
    fn token_group() {
        let mut group = ClangTokenGroup::new();
        assert!(group.is_empty());
        group.add_child(0);
        group.add_child(1);
        assert_eq!(group.len(), 2);
    }

    #[test]
    fn function_node() {
        let mut func = ClangFunction::new("main", "int", Address::new(0x1000));
        func.add_parameter(ClangVariableDecl::new("argc", "int"));
        func.add_parameter(ClangVariableDecl::new("argv", "char**"));
        func.add_local(ClangVariableDecl::new("result", "int"));
        func.add_child(0);
        assert_eq!(func.name, "main");
        assert_eq!(func.parameters.len(), 2);
        assert_eq!(func.locals.len(), 1);
    }
}
