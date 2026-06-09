//! ClangToken: base token type for decompiler C code markup.
//!
//! Port of Ghidra's `ghidra.app.decompiler.ClangToken`.
//!
//! A `ClangToken` represents a source code language token with numerous
//! display attributes.  It may link to the data-flow analysis.
//!
//! In the Rust implementation, the actual data lives in `ClangTokenData`
//! and the various specialized token types (defined in `clang_node.rs`),
//! stored in a `ClangNodeArena`.  This module provides convenience
//! functions for constructing and querying individual tokens.

use super::clang_node::{
    ClangNodeArena, ClangNodeId, ClangNodeKind, ClangTokenData, SyntaxType, DEFAULT_COLOR,
};

/// Re-export commonly used constants.
pub use super::clang_node::{
    NULL_NODE, COMMENT_COLOR, CONST_COLOR, ERROR_COLOR, FIELD_COLOR,
    FUNCTION_COLOR, GLOBAL_COLOR, KEYWORD_COLOR, MAX_COLOR, PARAMETER_COLOR,
    SPECIAL_COLOR, TYPE_COLOR, VARIABLE_COLOR,
};

/// Convenience constructor for a `ClangTokenData` with given text and syntax type.
pub fn clang_token(text: &str, syntax_type: SyntaxType) -> ClangTokenData {
    ClangTokenData {
        text: Some(text.to_string()),
        syntax_type,
        ..Default::default()
    }
}

/// Convenience constructor for a default-color token.
pub fn clang_token_default(text: &str) -> ClangTokenData {
    clang_token(text, SyntaxType::Default)
}

/// Convenience constructor for a keyword token.
pub fn clang_keyword(text: &str) -> ClangTokenData {
    clang_token(text, SyntaxType::Keyword)
}

/// Convenience constructor for a variable token.
pub fn clang_variable(text: &str) -> ClangTokenData {
    clang_token(text, SyntaxType::Variable)
}

/// Convenience constructor for a function name token.
pub fn clang_function_name(text: &str) -> ClangTokenData {
    clang_token(text, SyntaxType::Function)
}

/// Convenience constructor for a type token.
pub fn clang_type(text: &str) -> ClangTokenData {
    clang_token(text, SyntaxType::Type)
}

/// Convenience constructor for a constant token.
pub fn clang_constant(text: &str) -> ClangTokenData {
    clang_token(text, SyntaxType::Const)
}

/// Convenience constructor for a comment token.
pub fn clang_comment(text: &str) -> ClangTokenData {
    clang_token(text, SyntaxType::Comment)
}

/// Convenience constructor for a parameter token.
pub fn clang_parameter(text: &str) -> ClangTokenData {
    clang_token(text, SyntaxType::Parameter)
}

/// Convenience constructor for a global token.
pub fn clang_global(text: &str) -> ClangTokenData {
    clang_token(text, SyntaxType::Global)
}

/// Convenience constructor for a field token.
pub fn clang_field(text: &str) -> ClangTokenData {
    clang_token(text, SyntaxType::Field)
}

/// Convenience constructor for an error token.
pub fn clang_error(text: &str) -> ClangTokenData {
    clang_token(text, SyntaxType::Error)
}

/// Convenience constructor for a special token.
pub fn clang_special(text: &str) -> ClangTokenData {
    clang_token(text, SyntaxType::Special)
}

/// Whether a character is a letter, digit, or underscore (for token spacing).
pub fn is_ident_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// A helper struct providing an API similar to Java's `ClangToken` class.
///
/// Operates on a token node within a `ClangNodeArena`.
pub struct ClangTokenView<'a> {
    arena: &'a ClangNodeArena,
    node_id: ClangNodeId,
}

impl<'a> ClangTokenView<'a> {
    /// Create a view for a specific token node.
    pub fn new(arena: &'a ClangNodeArena, node_id: ClangNodeId) -> Self {
        Self { arena, node_id }
    }

    /// Get the node id.
    pub fn id(&self) -> ClangNodeId {
        self.node_id
    }

    /// Get the display text of this token.
    ///
    /// Corresponds to Java's `getText()`.
    pub fn get_text(&self) -> Option<String> {
        self.arena.token_text(self.node_id)
    }

    /// Get the syntax type (color) of this token.
    ///
    /// Corresponds to Java's `getSyntaxType()`.
    pub fn get_syntax_type(&self) -> Option<SyntaxType> {
        self.arena.syntax_type(self.node_id)
    }

    /// Get the color constant for this token.
    pub fn get_color(&self) -> i32 {
        self.get_syntax_type()
            .map(|st| st as i32)
            .unwrap_or(DEFAULT_COLOR)
    }

    /// Whether this token is a keyword.
    pub fn is_keyword(&self) -> bool {
        self.get_syntax_type() == Some(SyntaxType::Keyword)
    }

    /// Whether this token is a variable reference.
    ///
    /// In Ghidra Java, `ClangVariableToken` overrides this to return true.
    pub fn is_variable_ref(&self) -> bool {
        matches!(
            self.arena.get(self.node_id),
            Some(ClangNodeKind::VariableToken(_))
        )
    }

    /// Whether this token is a function name.
    pub fn is_function_name(&self) -> bool {
        matches!(
            self.arena.get(self.node_id),
            Some(ClangNodeKind::FuncNameToken(_))
        )
    }

    /// Whether this token is a field (struct member) reference.
    pub fn is_field_token(&self) -> bool {
        matches!(
            self.arena.get(self.node_id),
            Some(ClangNodeKind::FieldToken(_))
        )
    }

    /// Whether this token is a type name.
    pub fn is_type_token(&self) -> bool {
        matches!(
            self.arena.get(self.node_id),
            Some(ClangNodeKind::TypeToken(_))
        )
    }

    /// Whether this token is a comment.
    pub fn is_comment(&self) -> bool {
        matches!(
            self.arena.get(self.node_id),
            Some(ClangNodeKind::CommentToken(_))
        )
    }

    /// Whether this token is a label.
    pub fn is_label(&self) -> bool {
        matches!(
            self.arena.get(self.node_id),
            Some(ClangNodeKind::LabelToken(_))
        )
    }

    /// Whether this token is a case label.
    pub fn is_case_token(&self) -> bool {
        matches!(
            self.arena.get(self.node_id),
            Some(ClangNodeKind::CaseToken(_))
        )
    }

    /// Whether this token is a bitfield token.
    pub fn is_bitfield_token(&self) -> bool {
        matches!(
            self.arena.get(self.node_id),
            Some(ClangNodeKind::BitFieldToken(_))
        )
    }

    /// Whether this token is an operator.
    pub fn is_op_token(&self) -> bool {
        matches!(
            self.arena.get(self.node_id),
            Some(ClangNodeKind::OpToken(_))
        )
    }

    /// Whether this token is a syntax token (paren, brace, semicolon, etc.).
    pub fn is_syntax_token(&self) -> bool {
        matches!(
            self.arena.get(self.node_id),
            Some(ClangNodeKind::SyntaxToken(_))
        )
    }

    /// Whether this token is a line break.
    pub fn is_break(&self) -> bool {
        matches!(
            self.arena.get(self.node_id),
            Some(ClangNodeKind::Break(_))
        )
    }

    /// Whether this token has "matching" highlighting.
    ///
    /// Corresponds to Java's `isMatchingToken()`.
    pub fn is_matching_token(&self) -> bool {
        match self.arena.get(self.node_id) {
            Some(ClangNodeKind::Token(d)) => d.matching_token,
            Some(ClangNodeKind::SyntaxToken(d)) => d.token.matching_token,
            Some(ClangNodeKind::VariableToken(d)) => d.token.matching_token,
            Some(ClangNodeKind::FuncNameToken(d)) => d.token.matching_token,
            Some(ClangNodeKind::FieldToken(d)) => d.token.matching_token,
            Some(ClangNodeKind::TypeToken(d)) => d.token.matching_token,
            Some(ClangNodeKind::LabelToken(d)) => d.token.matching_token,
            Some(ClangNodeKind::CommentToken(d)) => d.token.matching_token,
            Some(ClangNodeKind::CaseToken(d)) => d.token.matching_token,
            Some(ClangNodeKind::BitFieldToken(d)) => d.token.matching_token,
            _ => false,
        }
    }

    /// Get the P-code op reference id associated with this token.
    ///
    /// Many tokens directly represent a pcode operator in the data-flow.
    /// Corresponds to Java's `getPcodeOp()`.
    pub fn get_op_ref(&self) -> Option<u32> {
        match self.arena.get(self.node_id) {
            Some(ClangNodeKind::OpToken(d)) => d.op_ref,
            Some(ClangNodeKind::VariableToken(d)) => d.op_ref,
            Some(ClangNodeKind::FuncNameToken(d)) => d.op_ref,
            Some(ClangNodeKind::FieldToken(d)) => d.op_ref,
            Some(ClangNodeKind::CaseToken(d)) => d.op_ref,
            Some(ClangNodeKind::BitFieldToken(d)) => d.op_ref,
            Some(ClangNodeKind::SyntaxToken(d)) => d.token.op_ref,
            Some(ClangNodeKind::Token(d)) => d.op_ref,
            _ => None,
        }
    }

    /// Get the varnode reference id associated with this token.
    ///
    /// Many tokens directly represent a variable in the data-flow.
    /// Corresponds to Java's `getVarnode()`.
    pub fn get_var_ref(&self) -> Option<u32> {
        match self.arena.get(self.node_id) {
            Some(ClangNodeKind::VariableToken(d)) => d.var_ref,
            Some(ClangNodeKind::ReturnType(d)) => d.var_ref,
            Some(ClangNodeKind::SyntaxToken(d)) => d.token.var_ref,
            Some(ClangNodeKind::Token(d)) => d.var_ref,
            _ => None,
        }
    }

    /// Get the symbol reference id associated with this token.
    ///
    /// Corresponds to Java's `getHighSymbol()`.
    pub fn get_sym_ref(&self) -> Option<u64> {
        match self.arena.get(self.node_id) {
            Some(ClangNodeKind::VariableDecl(d)) => d.sym_ref,
            Some(ClangNodeKind::SyntaxToken(d)) => d.token.sym_ref,
            Some(ClangNodeKind::Token(d)) => d.sym_ref,
            _ => None,
        }
    }

    /// Get the data type name associated with this token (for field/type tokens).
    pub fn get_datatype_name(&self) -> Option<&str> {
        match self.arena.get(self.node_id) {
            Some(ClangNodeKind::FieldToken(d)) => d.datatype_name.as_deref(),
            Some(ClangNodeKind::VariableDecl(d)) => d.datatype_name.as_deref(),
            Some(ClangNodeKind::ReturnType(d)) => d.datatype_name.as_deref(),
            Some(ClangNodeKind::BitFieldToken(d)) => d.datatype_name.as_deref(),
            _ => None,
        }
    }

    /// Get the data type id associated with this token.
    pub fn get_datatype_id(&self) -> Option<u64> {
        match self.arena.get(self.node_id) {
            Some(ClangNodeKind::FieldToken(d)) => d.datatype_id,
            Some(ClangNodeKind::VariableDecl(d)) => d.datatype_id,
            Some(ClangNodeKind::BitFieldToken(d)) => d.datatype_id,
            _ => None,
        }
    }

    /// Get the bracket match info for syntax tokens.
    ///
    /// Returns (open_match_id, close_match_id).
    pub fn get_bracket_matches(&self) -> Option<(i32, i32)> {
        match self.arena.get(self.node_id) {
            Some(ClangNodeKind::SyntaxToken(d)) => Some((d.open, d.close)),
            _ => None,
        }
    }

    /// Get the address associated with this token (from op seqnum).
    pub fn get_address(&self) -> Option<ghidra_core::addr::Address> {
        self.arena.min_address(self.node_id)
    }

    /// Get the value for case tokens.
    pub fn get_case_value(&self) -> Option<i64> {
        match self.arena.get(self.node_id) {
            Some(ClangNodeKind::CaseToken(d)) => Some(d.value),
            _ => None,
        }
    }

    /// Get the high function reference id (for function name tokens).
    pub fn get_high_function_ref(&self) -> Option<u32> {
        match self.arena.get(self.node_id) {
            Some(ClangNodeKind::FuncNameToken(d)) => d.high_function_ref,
            _ => None,
        }
    }

    /// Whether this node is a leaf token (a token-type node, not a group).
    ///
    /// In Ghidra Java, `ClangToken` is a leaf and `ClangTokenGroup` is not,
    /// regardless of children count.
    pub fn is_leaf(&self) -> bool {
        !self.is_group()
    }

    /// Whether this node is a group-type node (TokenGroup, Function, Statement, etc.).
    ///
    /// An empty group (with 0 children) is still a group.
    pub fn is_group(&self) -> bool {
        matches!(
            self.arena.get(self.node_id),
            Some(
                ClangNodeKind::TokenGroup(_)
                    | ClangNodeKind::Function(_)
                    | ClangNodeKind::FuncProto(_)
                    | ClangNodeKind::Statement(_)
                    | ClangNodeKind::VariableDecl(_)
                    | ClangNodeKind::ReturnType(_)
            )
        )
    }
}

/// Build a spacer token for indentation.
///
/// Corresponds to Java's `ClangToken.buildSpacer()`.
pub fn build_spacer(indent: usize, indent_str: &str) -> ClangTokenData {
    let spacing = indent_str.repeat(indent);
    ClangTokenData {
        text: Some(spacing),
        syntax_type: SyntaxType::Default,
        ..Default::default()
    }
}

/// Classify a token node by its syntax type and return the color constant.
///
/// This mirrors the logic in Java's various token subclasses.
pub fn classify_token_color(arena: &ClangNodeArena, node_id: ClangNodeId) -> i32 {
    arena
        .syntax_type(node_id)
        .map(|st| st as i32)
        .unwrap_or(DEFAULT_COLOR)
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::clang_node::{ClangNodeKind, ClangTokenGroupData};

    #[test]
    fn test_clang_token_convenience() {
        let tok = clang_token_default(";");
        assert_eq!(tok.text.as_deref(), Some(";"));
        assert_eq!(tok.syntax_type, SyntaxType::Default);
    }

    #[test]
    fn test_clang_keyword() {
        let tok = clang_keyword("if");
        assert_eq!(tok.text.as_deref(), Some("if"));
        assert_eq!(tok.syntax_type, SyntaxType::Keyword);
    }

    #[test]
    fn test_clang_variable() {
        let tok = clang_variable("x");
        assert_eq!(tok.syntax_type, SyntaxType::Variable);
    }

    #[test]
    fn test_clang_function_name() {
        let tok = clang_function_name("main");
        assert_eq!(tok.syntax_type, SyntaxType::Function);
    }

    #[test]
    fn test_clang_type() {
        let tok = clang_type("int");
        assert_eq!(tok.syntax_type, SyntaxType::Type);
    }

    #[test]
    fn test_clang_constant() {
        let tok = clang_constant("42");
        assert_eq!(tok.syntax_type, SyntaxType::Const);
    }

    #[test]
    fn test_clang_comment() {
        let tok = clang_comment("// hello");
        assert_eq!(tok.syntax_type, SyntaxType::Comment);
    }

    #[test]
    fn test_clang_error() {
        let tok = clang_error("ERR");
        assert_eq!(tok.syntax_type, SyntaxType::Error);
    }

    #[test]
    fn test_clang_special() {
        let tok = clang_special("...");
        assert_eq!(tok.syntax_type, SyntaxType::Special);
    }

    #[test]
    fn test_clang_field() {
        let tok = clang_field("offset");
        assert_eq!(tok.syntax_type, SyntaxType::Field);
    }

    #[test]
    fn test_is_ident_char() {
        assert!(is_ident_char('a'));
        assert!(is_ident_char('Z'));
        assert!(is_ident_char('0'));
        assert!(is_ident_char('_'));
        assert!(!is_ident_char(' '));
        assert!(!is_ident_char('('));
        assert!(!is_ident_char('+'));
    }

    #[test]
    fn test_build_spacer() {
        let spacer = build_spacer(2, "    ");
        assert_eq!(spacer.text.as_deref(), Some("        "));
        assert_eq!(spacer.syntax_type, SyntaxType::Default);
    }

    #[test]
    fn test_build_spacer_zero() {
        let spacer = build_spacer(0, "  ");
        assert_eq!(spacer.text.as_deref(), Some(""));
    }

    #[test]
    fn test_token_view_basic() {
        let mut arena = ClangNodeArena::new();
        let tok_id = arena.alloc(ClangNodeKind::Token(ClangTokenData {
            text: Some("hello".to_string()),
            syntax_type: SyntaxType::Keyword,
            ..Default::default()
        }));
        let view = ClangTokenView::new(&arena, tok_id);
        assert_eq!(view.get_text(), Some("hello".to_string()));
        assert_eq!(view.get_syntax_type(), Some(SyntaxType::Keyword));
        assert!(view.is_keyword());
        assert!(view.is_leaf());
        assert!(!view.is_group());
        assert!(view.is_matching_token() == false);
    }

    #[test]
    fn test_token_view_variable_ref() {
        let mut arena = ClangNodeArena::new();
        let tok_id = arena.alloc(ClangNodeKind::VariableToken(super::super::clang_node::ClangVariableTokenData {
            token: ClangTokenData {
                text: Some("x".to_string()),
                syntax_type: SyntaxType::Variable,
                ..Default::default()
            },
            ..Default::default()
        }));
        let view = ClangTokenView::new(&arena, tok_id);
        assert!(view.is_variable_ref());
        assert!(!view.is_keyword());
    }

    #[test]
    fn test_token_view_function_name() {
        let mut arena = ClangNodeArena::new();
        let tok_id = arena.alloc(ClangNodeKind::FuncNameToken(super::super::clang_node::ClangFuncNameTokenData {
            token: ClangTokenData {
                text: Some("main".to_string()),
                syntax_type: SyntaxType::Function,
                ..Default::default()
            },
            high_function_ref: Some(42),
            ..Default::default()
        }));
        let view = ClangTokenView::new(&arena, tok_id);
        assert!(view.is_function_name());
        assert_eq!(view.get_high_function_ref(), Some(42));
    }

    #[test]
    fn test_token_view_field() {
        let mut arena = ClangNodeArena::new();
        let tok_id = arena.alloc(ClangNodeKind::FieldToken(super::super::clang_node::ClangFieldTokenData {
            token: ClangTokenData {
                text: Some("offset".to_string()),
                syntax_type: SyntaxType::Field,
                ..Default::default()
            },
            datatype_name: Some("struct foo".to_string()),
            datatype_id: Some(100),
            offset: 8,
            ..Default::default()
        }));
        let view = ClangTokenView::new(&arena, tok_id);
        assert!(view.is_field_token());
        assert_eq!(view.get_datatype_name(), Some("struct foo"));
        assert_eq!(view.get_datatype_id(), Some(100));
    }

    #[test]
    fn test_token_view_case() {
        let mut arena = ClangNodeArena::new();
        let tok_id = arena.alloc(ClangNodeKind::CaseToken(super::super::clang_node::ClangCaseTokenData {
            token: ClangTokenData {
                text: Some("case 1:".to_string()),
                syntax_type: SyntaxType::Default,
                ..Default::default()
            },
            value: 1,
            ..Default::default()
        }));
        let view = ClangTokenView::new(&arena, tok_id);
        assert!(view.is_case_token());
        assert_eq!(view.get_case_value(), Some(1));
    }

    #[test]
    fn test_token_view_syntax() {
        let mut arena = ClangNodeArena::new();
        let tok_id = arena.alloc(ClangNodeKind::SyntaxToken(super::super::clang_node::ClangSyntaxTokenData {
            token: ClangTokenData {
                text: Some("(".to_string()),
                syntax_type: SyntaxType::Default,
                ..Default::default()
            },
            open: -1,
            close: 5,
            is_variable_ref: false,
        }));
        let view = ClangTokenView::new(&arena, tok_id);
        assert!(view.is_syntax_token());
        assert_eq!(view.get_bracket_matches(), Some((-1, 5)));
    }

    #[test]
    fn test_token_view_group() {
        let mut arena = ClangNodeArena::new();
        let group_id = arena.alloc(ClangNodeKind::TokenGroup(ClangTokenGroupData::default()));
        let view = ClangTokenView::new(&arena, group_id);
        assert!(!view.is_leaf());
        assert!(view.is_group());
        assert!(!view.is_variable_ref());
    }

    #[test]
    fn test_classify_token_color() {
        let mut arena = ClangNodeArena::new();
        let tok_id = arena.alloc(ClangNodeKind::Token(ClangTokenData {
            text: Some("if".to_string()),
            syntax_type: SyntaxType::Keyword,
            ..Default::default()
        }));
        assert_eq!(classify_token_color(&arena, tok_id), KEYWORD_COLOR);
    }

    #[test]
    fn test_color_constants() {
        assert_eq!(KEYWORD_COLOR, 0);
        assert_eq!(COMMENT_COLOR, 1);
        assert_eq!(TYPE_COLOR, 2);
        assert_eq!(FUNCTION_COLOR, 3);
        assert_eq!(VARIABLE_COLOR, 4);
        assert_eq!(CONST_COLOR, 5);
        assert_eq!(PARAMETER_COLOR, 6);
        assert_eq!(GLOBAL_COLOR, 7);
        assert_eq!(DEFAULT_COLOR, 8);
        assert_eq!(ERROR_COLOR, 9);
        assert_eq!(SPECIAL_COLOR, 10);
        assert_eq!(FIELD_COLOR, 11);
        assert_eq!(MAX_COLOR, 12);
    }

    #[test]
    fn test_token_view_break() {
        let mut arena = ClangNodeArena::new();
        let tok_id = arena.alloc(ClangNodeKind::Break(super::super::clang_node::ClangBreakData {
            indent: 2,
        }));
        let view = ClangTokenView::new(&arena, tok_id);
        assert!(view.is_break());
        assert!(view.is_leaf());
    }

    #[test]
    fn test_token_view_type() {
        let mut arena = ClangNodeArena::new();
        let tok_id = arena.alloc(ClangNodeKind::TypeToken(super::super::clang_node::ClangTypeTokenData {
            token: ClangTokenData {
                text: Some("int".to_string()),
                syntax_type: SyntaxType::Type,
                ..Default::default()
            },
        }));
        let view = ClangTokenView::new(&arena, tok_id);
        assert!(view.is_type_token());
        assert_eq!(view.get_text(), Some("int".to_string()));
    }

    #[test]
    fn test_token_view_comment() {
        let mut arena = ClangNodeArena::new();
        let tok_id = arena.alloc(ClangNodeKind::CommentToken(super::super::clang_node::ClangCommentTokenData {
            token: ClangTokenData {
                text: Some("// a comment".to_string()),
                syntax_type: SyntaxType::Comment,
                ..Default::default()
            },
            source_address: Some(ghidra_core::addr::Address::new(0x1000)),
        }));
        let view = ClangTokenView::new(&arena, tok_id);
        assert!(view.is_comment());
        assert_eq!(view.get_address(), Some(ghidra_core::addr::Address::new(0x1000)));
    }
}
