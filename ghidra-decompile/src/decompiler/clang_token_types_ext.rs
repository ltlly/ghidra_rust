//! Extended Clang token types.
//!
//! Port of Ghidra's decompiler Clang token classes that were not
//! yet ported:
//! - `ClangReturnType`: return type token
//! - `ClangCaseToken`: case label token
//! - `ClangFuncNameToken`: function name token
//! - `ClangOpToken`: operator token
//! - `ClangCommentToken`: comment token
//! - `ClangSyntaxToken`: syntax/keyword token
//! - `ClangLabelToken`: label token

use super::clang_node::ClangNodeId;

/// A Clang return-type token.
///
/// Port of `ghidra.app.decompiler.ClangReturnType`.
#[derive(Debug, Clone)]
pub struct ClangReturnType {
    /// Node id in the AST.
    pub node_id: ClangNodeId,
    /// The return type text.
    pub text: String,
    /// Parent node id.
    pub parent: Option<ClangNodeId>,
}

impl ClangReturnType {
    /// Create a new return type token.
    pub fn new(text: impl Into<String>) -> Self {
        Self { node_id: 0, text: text.into(), parent: None }
    }

    /// Set the node id.
    pub fn with_id(mut self, id: ClangNodeId) -> Self {
        self.node_id = id;
        self
    }
}

/// A case label token (e.g., `case 0:`).
///
/// Port of `ghidra.app.decompiler.ClangCaseToken`.
#[derive(Debug, Clone)]
pub struct ClangCaseToken {
    /// Node id.
    pub node_id: ClangNodeId,
    /// The case expression text.
    pub text: String,
    /// The value (if numeric).
    pub value: Option<i64>,
    /// Whether this is a `default:` case.
    pub is_default: bool,
}

impl ClangCaseToken {
    /// Create a new case token.
    pub fn new(text: impl Into<String>) -> Self {
        Self { node_id: 0, text: text.into(), value: None, is_default: false }
    }

    /// Create a default case.
    pub fn default_case() -> Self {
        Self { node_id: 0, text: "default".into(), value: None, is_default: true }
    }
}

/// A function name token.
///
/// Port of `ghidra.app.decompiler.ClangFuncNameToken`.
#[derive(Debug, Clone)]
pub struct ClangFuncNameToken {
    /// Node id.
    pub node_id: ClangNodeId,
    /// The function name.
    pub name: String,
    /// The function's entry address (as string).
    pub address: Option<String>,
}

impl ClangFuncNameToken {
    /// Create a new function name token.
    pub fn new(name: impl Into<String>) -> Self {
        Self { node_id: 0, name: name.into(), address: None }
    }

    /// Set the address.
    pub fn with_address(mut self, addr: impl Into<String>) -> Self {
        self.address = Some(addr.into());
        self
    }
}

/// An operator token.
///
/// Port of `ghidra.app.decompiler.ClangOpToken`.
#[derive(Debug, Clone)]
pub struct ClangOpToken {
    /// Node id.
    pub node_id: ClangNodeId,
    /// The operator text (e.g., "+", "==", "->").
    pub text: String,
    /// The operator precedence.
    pub precedence: i32,
}

impl ClangOpToken {
    /// Create a new operator token.
    pub fn new(text: impl Into<String>, precedence: i32) -> Self {
        Self { node_id: 0, text: text.into(), precedence }
    }
}

/// A comment token.
///
/// Port of `ghidra.app.decompiler.ClangCommentToken`.
#[derive(Debug, Clone)]
pub struct ClangCommentToken {
    /// Node id.
    pub node_id: ClangNodeId,
    /// The comment text (without delimiters).
    pub text: String,
    /// Whether this is a line comment (`//`).
    pub is_line_comment: bool,
}

impl ClangCommentToken {
    /// Create a new comment token.
    pub fn new(text: impl Into<String>, is_line_comment: bool) -> Self {
        Self { node_id: 0, text: text.into(), is_line_comment }
    }
}

/// A syntax/keyword token.
///
/// Port of `ghidra.app.decompiler.ClangSyntaxToken`.
#[derive(Debug, Clone)]
pub struct ClangSyntaxToken {
    /// Node id.
    pub node_id: ClangNodeId,
    /// The keyword text (e.g., "if", "return", "while").
    pub text: String,
}

impl ClangSyntaxToken {
    /// Create a new syntax token.
    pub fn new(text: impl Into<String>) -> Self {
        Self { node_id: 0, text: text.into() }
    }
}

/// A label token (goto target).
///
/// Port of `ghidra.app.decompiler.ClangLabelToken`.
#[derive(Debug, Clone)]
pub struct ClangLabelToken {
    /// Node id.
    pub node_id: ClangNodeId,
    /// The label name.
    pub text: String,
    /// The address of the label (as string).
    pub address: Option<String>,
}

impl ClangLabelToken {
    /// Create a new label token.
    pub fn new(text: impl Into<String>) -> Self {
        Self { node_id: 0, text: text.into(), address: None }
    }
}

/// CToken highlight matcher for decompiler display.
///
/// Port of `ghidra.app.decompiler.CTokenHighlightMatcher`.
#[derive(Debug, Clone, Default)]
pub struct CTokenHighlightMatcher {
    /// Matched token node ids.
    pub matched: Vec<ClangNodeId>,
}

impl CTokenHighlightMatcher {
    /// Create a new matcher.
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if a node id is matched.
    pub fn is_matched(&self, node_id: ClangNodeId) -> bool {
        self.matched.contains(&node_id)
    }

    /// Add a match.
    pub fn add_match(&mut self, node_id: ClangNodeId) {
        if !self.matched.contains(&node_id) {
            self.matched.push(node_id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clang_return_type() {
        let rt = ClangReturnType::new("int").with_id(1);
        assert_eq!(rt.text, "int");
        assert_eq!(rt.node_id, 1);
    }

    #[test]
    fn test_clang_case_token() {
        let ct = ClangCaseToken::new("case 5:");
        assert_eq!(ct.text, "case 5:");
        assert!(!ct.is_default);

        let def = ClangCaseToken::default_case();
        assert!(def.is_default);
    }

    #[test]
    fn test_clang_func_name_token() {
        let ft = ClangFuncNameToken::new("main").with_address("0x00401000");
        assert_eq!(ft.name, "main");
        assert_eq!(ft.address.as_deref(), Some("0x00401000"));
    }

    #[test]
    fn test_clang_op_token() {
        let op = ClangOpToken::new("+", 12);
        assert_eq!(op.text, "+");
        assert_eq!(op.precedence, 12);
    }

    #[test]
    fn test_clang_comment_token() {
        let c = ClangCommentToken::new("TODO: fix this", true);
        assert!(c.is_line_comment);
        assert_eq!(c.text, "TODO: fix this");
    }

    #[test]
    fn test_clang_syntax_token() {
        let s = ClangSyntaxToken::new("return");
        assert_eq!(s.text, "return");
    }

    #[test]
    fn test_clang_label_token() {
        let l = ClangLabelToken::new("LAB_00401020");
        assert_eq!(l.text, "LAB_00401020");
    }

    #[test]
    fn test_ctoken_highlight_matcher() {
        let mut m = CTokenHighlightMatcher::new();
        assert!(!m.is_matched(5));
        m.add_match(5);
        assert!(m.is_matched(5));
        m.add_match(5); // no duplicate
        assert_eq!(m.matched.len(), 1);
    }
}
