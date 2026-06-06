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

// ===========================================================================
// Additional decompiler enum types ported from Ghidra's Java source
// ===========================================================================

/// Comment style in decompiled output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CommentStyle {
    /// Single-line comment (//).
    Line,
    /// Block comment (/* ... */).
    Block,
    /// End-of-line comment.
    EndOfLine,
    /// Preprocessor comment.
    Preprocessor,
}

/// Strategy for namespace display in decompiler output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NamespaceDisplayStrategy {
    /// Always show full namespace paths.
    Always,
    /// Show namespace only when ambiguous.
    WhenAmbiguous,
    /// Never show namespaces.
    Never,
    /// Show namespace based on current scope.
    CurrentScope,
}

/// Integer display format in decompiler output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IntegerDisplayFormat {
    /// Hexadecimal (0x prefix).
    Hexadecimal,
    /// Decimal (no prefix).
    Decimal,
    /// Octal (0 prefix).
    Octal,
    /// Binary (0b prefix).
    Binary,
    /// Auto-detect based on value.
    Auto,
}

/// How to treat NaN values in floating-point comparisons.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NanComparisonMode {
    /// Treat NaN as equal to NaN.
    NanEqualsNan,
    /// Treat NaN as not equal to anything.
    NanNotEqual,
}

/// P-code graph sub-type for visualization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PcodeGraphSubType {
    /// Standard control-flow graph.
    ControlFlow,
    /// Data-flow graph.
    DataFlow,
    /// Combined CFG + DFG.
    Combined,
    /// Call graph.
    CallGraph,
}

/// Block alias type for variable analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AliasBlockType {
    /// No aliasing between variables.
    NoAlias,
    /// May alias (conservative).
    MayAlias,
    /// Must alias (definite overlap).
    MustAlias,
    /// Partial overlap.
    PartialAlias,
}

/// Offset + p-code operation pair for line mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OffsetPcodeOpPair {
    /// Byte offset in the function.
    pub offset: u32,
    /// P-code operation sequence number.
    pub op_seq: u32,
}

impl OffsetPcodeOpPair {
    /// Create a new offset/pcode-op pair.
    pub fn new(offset: u32, op_seq: u32) -> Self {
        Self { offset, op_seq }
    }
}

/// Strategy for renaming struct union fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UnionFieldRenameStrategy {
    /// Rename only the selected field.
    SelectedOnly,
    /// Rename all fields at the same offset.
    SameOffset,
    /// Prompt for each field.
    PromptEach,
}

// ===========================================================================
// ClangVariableDecl -- Port of `ghidra.app.decompiler.ClangVariableDecl`
// ===========================================================================

/// A grouping of source code tokens representing a variable declaration.
///
/// This can be for a one-line declaration (as for local variables) or
/// as part of a function prototype declaring a parameter.
///
/// Ports `ghidra.app.decompiler.ClangVariableDecl`.
#[derive(Debug, Clone)]
pub struct ClangVariableDecl {
    /// The parent token group node id.
    pub parent: Option<ClangNodeId>,
    /// The data-type of the variable being declared.
    pub datatype: Option<String>,
    /// The high-level symbol id (reference to HighSymbol).
    pub high_symbol_id: Option<usize>,
    /// The high-level variable id (reference to HighVariable).
    pub high_variable_id: Option<usize>,
    /// The variable name.
    pub variable_name: Option<String>,
    /// Whether this is a parameter declaration (vs. local).
    pub is_parameter: bool,
    /// The source address of this declaration.
    pub address: Option<u64>,
    /// Child tokens (type, name, initializers).
    pub children: Vec<ClangNodeId>,
}

impl ClangVariableDecl {
    /// Create a new variable declaration with no type/symbol info yet.
    pub fn new(parent: Option<ClangNodeId>) -> Self {
        Self {
            parent,
            datatype: None,
            high_symbol_id: None,
            high_variable_id: None,
            variable_name: None,
            is_parameter: false,
            address: None,
            children: Vec::new(),
        }
    }

    /// Set the data type.
    pub fn with_datatype(mut self, dt: impl Into<String>) -> Self {
        self.datatype = Some(dt.into());
        self
    }

    /// Set the variable name.
    pub fn with_variable_name(mut self, name: impl Into<String>) -> Self {
        self.variable_name = Some(name.into());
        self
    }

    /// Mark this as a parameter declaration.
    pub fn as_parameter(mut self) -> Self {
        self.is_parameter = true;
        self
    }

    /// Set the high symbol id.
    pub fn with_high_symbol(mut self, id: usize) -> Self {
        self.high_symbol_id = Some(id);
        self
    }

    /// Set the high variable id.
    pub fn with_high_variable(mut self, id: usize) -> Self {
        self.high_variable_id = Some(id);
        self
    }

    /// Set the source address.
    pub fn with_address(mut self, addr: u64) -> Self {
        self.address = Some(addr);
        self
    }

    /// Add a child token.
    pub fn add_child(&mut self, child: ClangNodeId) {
        self.children.push(child);
    }

    /// Get the number of child tokens.
    pub fn num_children(&self) -> usize {
        self.children.len()
    }

    /// Whether this declaration has a known data type.
    pub fn has_datatype(&self) -> bool {
        self.datatype.is_some()
    }

    /// Whether this declaration has a known variable name.
    pub fn has_variable_name(&self) -> bool {
        self.variable_name.is_some()
    }
}

/// A case label token in a switch statement.
///
/// Ports `ghidra.app.decompiler.ClangCaseToken`.
#[derive(Debug, Clone)]
pub struct ClangCaseTokenData {
    /// The constant value associated with this case.
    pub value: i64,
    /// P-code op associated with the start of the "case".
    pub op_seqnum: Option<(u64, u32)>,  // (address, seq)
    /// The parent node.
    pub parent: Option<ClangNodeId>,
    /// Token text (e.g., "case 42:" or "default:").
    pub text: String,
    /// Syntax type.
    pub syntax_type: SyntaxType,
    /// Source address.
    pub address: Option<u64>,
}

impl ClangCaseTokenData {
    /// Create a new case token.
    pub fn new(parent: Option<ClangNodeId>, value: i64, text: impl Into<String>) -> Self {
        Self {
            value,
            op_seqnum: None,
            parent,
            text: text.into(),
            syntax_type: SyntaxType::Keyword,
            address: None,
        }
    }

    /// Create a default case token.
    pub fn default_case(parent: Option<ClangNodeId>) -> Self {
        Self::new(parent, 0, "default:")
    }

    /// Set the source address.
    pub fn with_address(mut self, addr: u64) -> Self {
        self.address = Some(addr);
        self
    }

    /// Whether this is a default case.
    pub fn is_default(&self) -> bool {
        self.text.starts_with("default")
    }

    /// Get the source address.
    pub fn min_address(&self) -> Option<u64> {
        self.op_seqnum.map(|(addr, _)| addr).or(self.address)
    }
}

/// A syntax token (punctuation, braces, etc.) in the Clang AST.
///
/// Ports `ghidra.app.decompiler.ClangSyntaxToken`.
#[derive(Debug, Clone)]
pub struct ClangSyntaxTokenData {
    /// Token text (e.g., "(", ")", "{", ";", ",").
    pub text: String,
    /// The parent node.
    pub parent: Option<ClangNodeId>,
    /// Syntax color type.
    pub syntax_type: SyntaxType,
    /// For paired tokens (parens, braces), the id of the opening token (-1 = unpaired).
    pub open_id: i32,
    /// For paired tokens, the id of the closing token (-1 = unpaired).
    pub close_id: i32,
    /// Source address.
    pub address: Option<u64>,
}

impl ClangSyntaxTokenData {
    /// Create a new syntax token.
    pub fn new(parent: Option<ClangNodeId>, text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            parent,
            syntax_type: SyntaxType::Default,
            open_id: -1,
            close_id: -1,
            address: None,
        }
    }

    /// Create a paired open token.
    pub fn open_token(parent: Option<ClangNodeId>, text: impl Into<String>, pair_id: i32) -> Self {
        Self {
            text: text.into(),
            parent,
            syntax_type: SyntaxType::Default,
            open_id: pair_id,
            close_id: -1,
            address: None,
        }
    }

    /// Create a paired close token.
    pub fn close_token(parent: Option<ClangNodeId>, text: impl Into<String>, pair_id: i32) -> Self {
        Self {
            text: text.into(),
            parent,
            syntax_type: SyntaxType::Default,
            open_id: -1,
            close_id: pair_id,
            address: None,
        }
    }

    /// Whether this is part of a paired token.
    pub fn is_paired(&self) -> bool {
        self.open_id >= 0 || self.close_id >= 0
    }

    /// Whether this is the opening token of a pair.
    pub fn is_open(&self) -> bool {
        self.open_id >= 0
    }

    /// Whether this is the closing token of a pair.
    pub fn is_close(&self) -> bool {
        self.close_id >= 0
    }
}

/// A comment token in the Clang AST.
///
/// Ports `ghidra.app.decompiler.ClangCommentToken`.
#[derive(Debug, Clone)]
pub struct ClangCommentTokenData {
    /// Comment text.
    pub text: String,
    /// The parent node.
    pub parent: Option<ClangNodeId>,
    /// Source address of the comment.
    pub source_address: Option<u64>,
    /// The comment style.
    pub style: CommentStyle,
}

impl ClangCommentTokenData {
    /// Create a new comment token.
    pub fn new(parent: Option<ClangNodeId>, text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            parent,
            source_address: None,
            style: CommentStyle::Line,
        }
    }

    /// Set the source address.
    pub fn with_address(mut self, addr: u64) -> Self {
        self.source_address = Some(addr);
        self
    }

    /// Set the comment style.
    pub fn with_style(mut self, style: CommentStyle) -> Self {
        self.style = style;
        self
    }

    /// Derive a new comment token from this one with different text.
    pub fn derive(&self, new_text: impl Into<String>) -> Self {
        Self {
            text: new_text.into(),
            parent: self.parent,
            source_address: self.source_address,
            style: self.style,
        }
    }
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

    #[test]
    fn clang_variable_decl_basic() {
        let decl = ClangVariableDecl::new(None);
        assert!(decl.datatype.is_none());
        assert!(decl.variable_name.is_none());
        assert!(!decl.is_parameter);
        assert!(!decl.has_datatype());
        assert!(!decl.has_variable_name());
        assert_eq!(decl.num_children(), 0);
    }

    #[test]
    fn clang_variable_decl_builder() {
        let decl = ClangVariableDecl::new(Some(1))
            .with_datatype("int")
            .with_variable_name("x")
            .as_parameter()
            .with_high_symbol(42)
            .with_address(0x1000);
        assert_eq!(decl.datatype.as_deref(), Some("int"));
        assert_eq!(decl.variable_name.as_deref(), Some("x"));
        assert!(decl.is_parameter);
        assert!(decl.has_datatype());
        assert!(decl.has_variable_name());
        assert_eq!(decl.high_symbol_id, Some(42));
        assert_eq!(decl.address, Some(0x1000));
    }

    #[test]
    fn clang_variable_decl_children() {
        let mut decl = ClangVariableDecl::new(None);
        decl.add_child(10);
        decl.add_child(11);
        assert_eq!(decl.num_children(), 2);
    }

    #[test]
    fn clang_case_token_data() {
        let tok = ClangCaseTokenData::new(None, 42, "case 42:");
        assert_eq!(tok.value, 42);
        assert_eq!(tok.text, "case 42:");
        assert!(!tok.is_default());
    }

    #[test]
    fn clang_case_token_default() {
        let tok = ClangCaseTokenData::default_case(None);
        assert!(tok.is_default());
        assert_eq!(tok.value, 0);
    }

    #[test]
    fn clang_case_token_address() {
        let tok = ClangCaseTokenData::new(None, 1, "case 1:")
            .with_address(0x2000);
        assert_eq!(tok.min_address(), Some(0x2000));
    }

    #[test]
    fn clang_case_token_with_op_seqnum() {
        let mut tok = ClangCaseTokenData::new(None, 5, "case 5:");
        tok.op_seqnum = Some((0x3000, 3));
        assert_eq!(tok.min_address(), Some(0x3000));
    }

    #[test]
    fn clang_syntax_token_basic() {
        let tok = ClangSyntaxTokenData::new(None, "(");
        assert_eq!(tok.text, "(");
        assert!(!tok.is_paired());
        assert!(!tok.is_open());
        assert!(!tok.is_close());
    }

    #[test]
    fn clang_syntax_token_paired() {
        let open = ClangSyntaxTokenData::open_token(None, "(", 1);
        assert!(open.is_open());
        assert!(open.is_paired());
        assert!(!open.is_close());
        assert_eq!(open.open_id, 1);

        let close = ClangSyntaxTokenData::close_token(None, ")", 1);
        assert!(close.is_close());
        assert!(close.is_paired());
        assert!(!close.is_open());
        assert_eq!(close.close_id, 1);
    }

    #[test]
    fn clang_comment_token_data() {
        let tok = ClangCommentTokenData::new(None, "// a comment");
        assert_eq!(tok.text, "// a comment");
        assert!(tok.source_address.is_none());
        assert_eq!(tok.style, CommentStyle::Line);
    }

    #[test]
    fn clang_comment_token_with_address() {
        let tok = ClangCommentTokenData::new(None, "/* block */")
            .with_address(0x4000)
            .with_style(CommentStyle::Block);
        assert_eq!(tok.source_address, Some(0x4000));
        assert_eq!(tok.style, CommentStyle::Block);
    }

    #[test]
    fn clang_comment_token_derive() {
        let tok = ClangCommentTokenData::new(None, "original")
            .with_address(0x5000);
        let derived = tok.derive("modified");
        assert_eq!(derived.text, "modified");
        assert_eq!(derived.source_address, Some(0x5000));
    }

    #[test]
    fn comment_style_variants() {
        assert_ne!(CommentStyle::Line, CommentStyle::Block);
        assert_ne!(CommentStyle::EndOfLine, CommentStyle::Preprocessor);
    }

    #[test]
    fn namespace_display_strategy() {
        assert_ne!(NamespaceDisplayStrategy::Always, NamespaceDisplayStrategy::Never);
    }

    #[test]
    fn integer_display_format() {
        assert_ne!(IntegerDisplayFormat::Hexadecimal, IntegerDisplayFormat::Decimal);
    }

    #[test]
    fn offset_pcode_op_pair() {
        let pair = OffsetPcodeOpPair::new(0x10, 5);
        assert_eq!(pair.offset, 0x10);
        assert_eq!(pair.op_seq, 5);
    }

    #[test]
    fn pcode_graph_sub_type() {
        assert_ne!(PcodeGraphSubType::ControlFlow, PcodeGraphSubType::DataFlow);
    }

    #[test]
    fn alias_block_type() {
        assert_ne!(AliasBlockType::NoAlias, AliasBlockType::MustAlias);
    }
}
