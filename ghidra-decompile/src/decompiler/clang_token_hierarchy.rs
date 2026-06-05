//! Full Clang token type hierarchy.
//!
//! Ported from the complete set of Java `ClangToken` subclasses:
//! - `ClangSyntaxToken` (keywords, punctuation)
//! - `ClangOpToken` (operators)
//! - `ClangFuncNameToken` (function names)
//! - `ClangFieldToken` (struct/union fields)
//! - `ClangTypeToken` (type names)
//! - `ClangVariableToken` (variables)
//! - `ClangVariableDecl` (variable declarations)
//! - `ClangLabelToken` (goto labels)
//! - `ClangCommentToken` (comments)
//! - `ClangCaseToken` (case labels)
//! - `ClangBitFieldToken` (bit-field tokens)
//! - `ClangReturnType` (return type)
//! - `ClangFuncProto` (function prototype)
//! - `ClangStatement` (statements)
//! - `ClangTokenGroup` (groups of tokens)

use super::clang_node::{SyntaxType, ClangNodeId};

/// Extended syntax type classification for tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenCategory {
    /// A keyword token (if, while, return, etc.).
    Keyword,
    /// An operator token (+, -, *, /, etc.).
    Operator,
    /// A function name token.
    FunctionName,
    /// A variable name token.
    VariableName,
    /// A type name token.
    TypeName,
    /// A field/member name token.
    FieldName,
    /// A constant/literal token.
    Constant,
    /// A comment token.
    Comment,
    /// A label token (goto target).
    Label,
    /// A case label.
    CaseLabel,
    /// A punctuation token (braces, parens, semicolons).
    Punctuation,
    /// A whitespace/formatting token.
    Whitespace,
    /// A return type token.
    ReturnType,
    /// A variable declaration token.
    VariableDecl,
    /// A bit-field token.
    BitField,
    /// A function prototype.
    FuncProto,
    /// A statement group.
    Statement,
}

impl TokenCategory {
    /// Get the default syntax type for this category.
    pub fn default_syntax_type(&self) -> SyntaxType {
        match self {
            TokenCategory::Keyword => SyntaxType::Keyword,
            TokenCategory::Operator => SyntaxType::Keyword,
            TokenCategory::FunctionName => SyntaxType::Function,
            TokenCategory::VariableName => SyntaxType::Variable,
            TokenCategory::TypeName => SyntaxType::Type,
            TokenCategory::FieldName => SyntaxType::Field,
            TokenCategory::Constant => SyntaxType::Const,
            TokenCategory::Comment => SyntaxType::Comment,
            TokenCategory::Label => SyntaxType::Default,
            TokenCategory::CaseLabel => SyntaxType::Keyword,
            TokenCategory::Punctuation => SyntaxType::Default,
            TokenCategory::Whitespace => SyntaxType::Default,
            TokenCategory::ReturnType => SyntaxType::Type,
            TokenCategory::VariableDecl => SyntaxType::Variable,
            TokenCategory::BitField => SyntaxType::Field,
            TokenCategory::FuncProto => SyntaxType::Function,
            TokenCategory::Statement => SyntaxType::Default,
        }
    }

    /// Whether this category represents a data-flow-linked token.
    pub fn is_data_linked(&self) -> bool {
        matches!(self,
            TokenCategory::VariableName
            | TokenCategory::FieldName
            | TokenCategory::FunctionName
            | TokenCategory::VariableDecl
            | TokenCategory::BitField
        )
    }
}

/// A token in the Clang AST with extended metadata.
#[derive(Debug, Clone)]
pub struct ClangTokenExtended {
    /// Node id in the arena.
    pub node_id: ClangNodeId,
    /// Token text.
    pub text: String,
    /// Token category.
    pub category: TokenCategory,
    /// Syntax color type.
    pub syntax_type: SyntaxType,
    /// Parent node id.
    pub parent: Option<ClangNodeId>,
    /// Line number (0-based).
    pub line: usize,
    /// Column offset within line.
    pub col: usize,
    /// Whether this token is part of a highlighted match.
    pub matching: bool,
}

impl ClangTokenExtended {
    /// Create a new extended token.
    pub fn new(
        node_id: ClangNodeId,
        text: impl Into<String>,
        category: TokenCategory,
        parent: Option<ClangNodeId>,
    ) -> Self {
        let syntax_type = category.default_syntax_type();
        Self {
            node_id,
            text: text.into(),
            category,
            syntax_type,
            parent,
            line: 0,
            col: 0,
            matching: false,
        }
    }

    /// Set the token text.
    pub fn with_text(mut self, text: impl Into<String>) -> Self {
        self.text = text.into();
        self
    }

    /// Set the syntax type.
    pub fn with_syntax_type(mut self, st: SyntaxType) -> Self {
        self.syntax_type = st;
        self
    }

    /// Set the position.
    pub fn with_position(mut self, line: usize, col: usize) -> Self {
        self.line = line;
        self.col = col;
        self
    }

    /// Whether this is a keyword.
    pub fn is_keyword(&self) -> bool { self.category == TokenCategory::Keyword }

    /// Whether this is an operator.
    pub fn is_operator(&self) -> bool { self.category == TokenCategory::Operator }

    /// Whether this token has data-flow linkage.
    pub fn is_data_linked(&self) -> bool { self.category.is_data_linked() }
}

/// A Clang token group (container of tokens and sub-groups).
#[derive(Debug, Clone)]
pub struct ClangTokenGroupData {
    /// Node id.
    pub node_id: ClangNodeId,
    /// Children (tokens or sub-groups).
    pub children: Vec<ClangNodeId>,
    /// Parent node.
    pub parent: Option<ClangNodeId>,
    /// Minimum address covered by this group.
    pub min_address: Option<u64>,
    /// Maximum address covered by this group.
    pub max_address: Option<u64>,
}

impl ClangTokenGroupData {
    /// Create a new empty token group.
    pub fn new(node_id: ClangNodeId, parent: Option<ClangNodeId>) -> Self {
        Self {
            node_id,
            children: Vec::new(),
            parent,
            min_address: None,
            max_address: None,
        }
    }

    /// Add a child node.
    pub fn add_child(&mut self, child: ClangNodeId, min_addr: Option<u64>, max_addr: Option<u64>) {
        self.children.push(child);
        if let Some(addr) = min_addr {
            self.min_address = Some(match self.min_address {
                Some(current) => current.min(addr),
                None => addr,
            });
        }
        if let Some(addr) = max_addr {
            self.max_address = Some(match self.max_address {
                Some(current) => current.max(addr),
                None => addr,
            });
        }
    }

    /// Number of children.
    pub fn num_children(&self) -> usize { self.children.len() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_category_syntax_type() {
        assert_eq!(TokenCategory::Keyword.default_syntax_type(), SyntaxType::Keyword);
        assert_eq!(TokenCategory::FunctionName.default_syntax_type(), SyntaxType::Function);
        assert_eq!(TokenCategory::TypeName.default_syntax_type(), SyntaxType::Type);
    }

    #[test]
    fn data_linked_categories() {
        assert!(TokenCategory::VariableName.is_data_linked());
        assert!(TokenCategory::FieldName.is_data_linked());
        assert!(!TokenCategory::Keyword.is_data_linked());
        assert!(!TokenCategory::Comment.is_data_linked());
    }

    #[test]
    fn extended_token_basic() {
        let t = ClangTokenExtended::new(0, "x", TokenCategory::VariableName, None);
        assert_eq!(t.text, "x");
        assert!(t.is_data_linked());
        assert!(!t.is_keyword());
    }

    #[test]
    fn token_group_children() {
        let mut g = ClangTokenGroupData::new(0, None);
        assert_eq!(g.num_children(), 0);
        g.add_child(1, Some(0x1000), Some(0x10FF));
        g.add_child(2, Some(0x1100), Some(0x11FF));
        assert_eq!(g.num_children(), 2);
        assert_eq!(g.min_address, Some(0x1000));
        assert_eq!(g.max_address, Some(0x11FF));
    }

    #[test]
    fn token_group_address_tracking() {
        let mut g = ClangTokenGroupData::new(0, None);
        g.add_child(1, Some(0x2000), Some(0x2FFF));
        g.add_child(2, Some(0x1000), Some(0x3FFF));
        assert_eq!(g.min_address, Some(0x1000));
        assert_eq!(g.max_address, Some(0x3FFF));
    }
}
