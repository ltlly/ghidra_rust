//! Clang AST node types for decompiler C code markup.
//!
//! Port of Ghidra's `ghidra.app.decompiler.ClangNode` and related types.
//! These represent the structured C code output from the decompiler as a tree
//! of tokens and groups.

use std::fmt;

use ghidra_core::addr::Address;

// ============================================================================
// Syntax color constants (match Decompiler syntax_highlight)
// ============================================================================

/// Keyword color identifier.
pub const KEYWORD_COLOR: i32 = 0;
/// Comment color identifier.
pub const COMMENT_COLOR: i32 = 1;
/// Type color identifier.
pub const TYPE_COLOR: i32 = 2;
/// Function name color identifier.
pub const FUNCTION_COLOR: i32 = 3;
/// Variable color identifier.
pub const VARIABLE_COLOR: i32 = 4;
/// Constant color identifier.
pub const CONST_COLOR: i32 = 5;
/// Parameter color identifier.
pub const PARAMETER_COLOR: i32 = 6;
/// Global color identifier.
pub const GLOBAL_COLOR: i32 = 7;
/// Default color identifier.
pub const DEFAULT_COLOR: i32 = 8;
/// Error color identifier.
pub const ERROR_COLOR: i32 = 9;
/// Special color identifier.
pub const SPECIAL_COLOR: i32 = 10;
/// Maximum color identifier (sentinel).
pub const MAX_COLOR: i32 = 11;

// ============================================================================
// SyntaxType
// ============================================================================

/// Token syntax coloring type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum SyntaxType {
    Keyword = KEYWORD_COLOR,
    Comment = COMMENT_COLOR,
    Type = TYPE_COLOR,
    Function = FUNCTION_COLOR,
    Variable = VARIABLE_COLOR,
    Const = CONST_COLOR,
    Parameter = PARAMETER_COLOR,
    Global = GLOBAL_COLOR,
    Default = DEFAULT_COLOR,
    Error = ERROR_COLOR,
    Special = SPECIAL_COLOR,
}

impl SyntaxType {
    /// Convert from raw integer color value.
    pub fn from_i32(v: i32) -> Self {
        match v {
            0 => Self::Keyword,
            1 => Self::Comment,
            2 => Self::Type,
            3 => Self::Function,
            4 => Self::Variable,
            5 => Self::Const,
            6 => Self::Parameter,
            7 => Self::Global,
            9 => Self::Error,
            10 => Self::Special,
            _ => Self::Default,
        }
    }
}

impl Default for SyntaxType {
    fn default() -> Self {
        Self::Default
    }
}

// ============================================================================
// ClangNode (enum-based, replaces Java interface)
// ============================================================================

/// A node in the Clang AST tree.  In Ghidra Java this is an interface with
/// implementations in ClangToken, ClangTokenGroup, ClangFunction, etc.
/// Here we use a flat enum for efficiency and Rust ergonomics.
#[derive(Debug, Clone)]
pub enum ClangNodeKind {
    /// A generic token group.
    TokenGroup(ClangTokenGroupData),
    /// A function-level group containing all tokens for one function.
    Function(ClangFunctionData),
    /// A function prototype group.
    FuncProto(ClangFuncProtoData),
    /// A statement (grouped under one PcodeOp).
    Statement(ClangStatementData),
    /// A variable declaration.
    VariableDecl(ClangVariableDeclData),
    /// A return type group.
    ReturnType(ClangReturnTypeData),
    /// A syntax token (parenthesis, brace, semicolon, etc.).
    SyntaxToken(ClangSyntaxTokenData),
    /// An operator token.
    OpToken(ClangOpTokenData),
    /// A variable token.
    VariableToken(ClangVariableTokenData),
    /// A function name token.
    FuncNameToken(ClangFuncNameTokenData),
    /// A field (struct member) token.
    FieldToken(ClangFieldTokenData),
    /// A type token.
    TypeToken(ClangTypeTokenData),
    /// A label token.
    LabelToken(ClangLabelTokenData),
    /// A comment token.
    CommentToken(ClangCommentTokenData),
    /// A case label token.
    CaseToken(ClangCaseTokenData),
    /// A bitfield token.
    BitFieldToken(ClangBitFieldTokenData),
    /// A line-break token.
    Break(ClangBreakData),
    /// A generic token (base).
    Token(ClangTokenData),
}

// ============================================================================
// ClangNodeRef / ClangNodeId
// ============================================================================

/// Handle to a ClangNode in the AST arena.  Replaces Java object references.
pub type ClangNodeId = usize;

/// Index into the arena.
pub const NULL_NODE: ClangNodeId = usize::MAX;

// ============================================================================
// ClangNodeArena
// ============================================================================

/// Arena holding all ClangNode objects for a decompiled function.
/// This replaces the Java tree of parent/child references with an index-based arena.
#[derive(Debug, Clone, Default)]
pub struct ClangNodeArena {
    nodes: Vec<ClangNodeKind>,
}

impl ClangNodeArena {
    /// Create a new empty arena.
    pub fn new() -> Self {
        Self { nodes: Vec::new() }
    }

    /// Allocate a new node and return its id.
    pub fn alloc(&mut self, kind: ClangNodeKind) -> ClangNodeId {
        let id = self.nodes.len();
        self.nodes.push(kind);
        id
    }

    /// Get a reference to a node by id.
    pub fn get(&self, id: ClangNodeId) -> Option<&ClangNodeKind> {
        self.nodes.get(id)
    }

    /// Get a mutable reference to a node by id.
    pub fn get_mut(&mut self, id: ClangNodeId) -> Option<&mut ClangNodeKind> {
        self.nodes.get_mut(id)
    }

    /// Number of nodes in the arena.
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Whether the arena is empty.
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Iterate over all nodes.
    pub fn iter(&self) -> impl Iterator<Item = (ClangNodeId, &ClangNodeKind)> {
        self.nodes.iter().enumerate()
    }

    /// Get the min address of a node.
    pub fn min_address(&self, id: ClangNodeId) -> Option<Address> {
        match self.get(id)? {
            ClangNodeKind::TokenGroup(d) => d.min_address,
            ClangNodeKind::Function(d) => d.group.min_address,
            ClangNodeKind::FuncProto(d) => d.group.min_address,
            ClangNodeKind::Statement(d) => d.group.min_address,
            ClangNodeKind::VariableDecl(d) => d.group.min_address,
            ClangNodeKind::ReturnType(d) => d.group.min_address,
            ClangNodeKind::SyntaxToken(d) => d.token.min_address(),
            ClangNodeKind::OpToken(d) => d.min_address,
            ClangNodeKind::VariableToken(d) => d.min_address(),
            ClangNodeKind::FuncNameToken(d) => d.min_address,
            ClangNodeKind::FieldToken(d) => d.min_address(),
            ClangNodeKind::TypeToken(_) => None,
            ClangNodeKind::LabelToken(d) => Some(d.block_address),
            ClangNodeKind::CommentToken(d) => d.source_address,
            ClangNodeKind::CaseToken(d) => d.min_address(),
            ClangNodeKind::BitFieldToken(d) => d.min_address(),
            ClangNodeKind::Break(_) => None,
            ClangNodeKind::Token(d) => d.min_address(),
        }
    }

    /// Get the max address of a node.
    pub fn max_address(&self, id: ClangNodeId) -> Option<Address> {
        match self.get(id)? {
            ClangNodeKind::TokenGroup(d) => d.max_address,
            ClangNodeKind::Function(d) => d.group.max_address,
            ClangNodeKind::FuncProto(d) => d.group.max_address,
            ClangNodeKind::Statement(d) => d.group.max_address,
            ClangNodeKind::VariableDecl(d) => d.group.max_address,
            ClangNodeKind::ReturnType(d) => d.group.max_address,
            ClangNodeKind::SyntaxToken(d) => d.token.max_address(),
            ClangNodeKind::OpToken(d) => d.min_address,
            ClangNodeKind::VariableToken(d) => d.min_address(),
            ClangNodeKind::FuncNameToken(d) => d.min_address,
            ClangNodeKind::FieldToken(d) => d.min_address(),
            ClangNodeKind::TypeToken(_) => None,
            ClangNodeKind::LabelToken(d) => Some(d.block_address),
            ClangNodeKind::CommentToken(d) => d.source_address,
            ClangNodeKind::CaseToken(d) => d.min_address(),
            ClangNodeKind::BitFieldToken(d) => d.min_address(),
            ClangNodeKind::Break(_) => None,
            ClangNodeKind::Token(d) => d.min_address(),
        }
    }

    /// Get the number of children of a node.
    pub fn num_children(&self, id: ClangNodeId) -> usize {
        match self.get(id) {
            Some(ClangNodeKind::TokenGroup(d)) => d.children.len(),
            Some(ClangNodeKind::Function(d)) => d.group.children.len(),
            Some(ClangNodeKind::FuncProto(d)) => d.group.children.len(),
            Some(ClangNodeKind::Statement(d)) => d.group.children.len(),
            Some(ClangNodeKind::VariableDecl(d)) => d.group.children.len(),
            Some(ClangNodeKind::ReturnType(d)) => d.group.children.len(),
            _ => 0,
        }
    }

    /// Get the i-th child of a node.
    pub fn child(&self, id: ClangNodeId, i: usize) -> Option<ClangNodeId> {
        match self.get(id)? {
            ClangNodeKind::TokenGroup(d) => d.children.get(i).copied(),
            ClangNodeKind::Function(d) => d.group.children.get(i).copied(),
            ClangNodeKind::FuncProto(d) => d.group.children.get(i).copied(),
            ClangNodeKind::Statement(d) => d.group.children.get(i).copied(),
            ClangNodeKind::VariableDecl(d) => d.group.children.get(i).copied(),
            ClangNodeKind::ReturnType(d) => d.group.children.get(i).copied(),
            _ => None,
        }
    }

    /// Add a child to a group node.  Updates min/max address.
    pub fn add_child(&mut self, parent_id: ClangNodeId, child_id: ClangNodeId) {
        let child_min = self.min_address(child_id);
        let child_max = self.max_address(child_id);

        macro_rules! add_to_group {
            ($group:expr) => {{
                if let Some(min) = child_min {
                    $group.min_address = Some(match $group.min_address {
                        Some(cur) if cur <= min => cur,
                        _ => min,
                    });
                }
                if let Some(max) = child_max {
                    $group.max_address = Some(match $group.max_address {
                        Some(cur) if cur >= max => cur,
                        _ => max,
                    });
                }
                $group.children.push(child_id);
            }};
        }

        match self.get_mut(parent_id) {
            Some(ClangNodeKind::TokenGroup(d)) => add_to_group!(d),
            Some(ClangNodeKind::Function(d)) => add_to_group!(d.group),
            Some(ClangNodeKind::FuncProto(d)) => add_to_group!(d.group),
            Some(ClangNodeKind::Statement(d)) => add_to_group!(d.group),
            Some(ClangNodeKind::VariableDecl(d)) => add_to_group!(d.group),
            Some(ClangNodeKind::ReturnType(d)) => add_to_group!(d.group),
            _ => {} // Tokens have no children
        }
    }

    /// Flatten a subtree into a list of leaf token ids.
    pub fn flatten(&self, id: ClangNodeId) -> Vec<ClangNodeId> {
        let mut result = Vec::new();
        self.flatten_into(id, &mut result);
        result
    }

    fn flatten_into(&self, id: ClangNodeId, out: &mut Vec<ClangNodeId>) {
        let num = self.num_children(id);
        if num == 0 {
            out.push(id);
        } else {
            for i in 0..num {
                if let Some(child) = self.child(id, i) {
                    self.flatten_into(child, out);
                }
            }
        }
    }

    /// Get the text of a node (concatenation of all leaf tokens).
    pub fn to_string(&self, id: ClangNodeId) -> String {
        let leaves = self.flatten(id);
        let mut buf = String::new();
        let mut last_token_str: Option<String> = None;
        for leaf_id in leaves {
            let token_str = self.token_text(leaf_id).unwrap_or_default();
            if token_str.is_empty() {
                continue;
            }
            if let Some(ref last) = last_token_str {
                if !token_str.is_empty()
                    && !last.is_empty()
                    && is_letter_digit_or_underscore(token_str.chars().next().unwrap_or('\0'))
                    && is_letter_digit_or_underscore(last.chars().last().unwrap_or('\0'))
                {
                    buf.push(' ');
                }
            }
            last_token_str = Some(token_str.clone());
            buf.push_str(&token_str);
        }
        buf
    }

    /// Get the text of a leaf token node.
    pub fn token_text(&self, id: ClangNodeId) -> Option<String> {
        match self.get(id)? {
            ClangNodeKind::SyntaxToken(d) => d.token.text.clone(),
            ClangNodeKind::OpToken(d) => d.text.clone(),
            ClangNodeKind::VariableToken(d) => d.token.text.clone(),
            ClangNodeKind::FuncNameToken(d) => d.token.text.clone(),
            ClangNodeKind::FieldToken(d) => d.token.text.clone(),
            ClangNodeKind::TypeToken(d) => d.token.text.clone(),
            ClangNodeKind::LabelToken(d) => d.token.text.clone(),
            ClangNodeKind::CommentToken(d) => d.token.text.clone(),
            ClangNodeKind::CaseToken(d) => d.token.text.clone(),
            ClangNodeKind::BitFieldToken(d) => d.token.text.clone(),
            ClangNodeKind::Break(_) => Some(String::new()),
            ClangNodeKind::Token(d) => d.text.clone(),
            _ => None,
        }
    }

    /// Get the syntax type (color) of a leaf token.
    pub fn syntax_type(&self, id: ClangNodeId) -> Option<SyntaxType> {
        match self.get(id)? {
            ClangNodeKind::SyntaxToken(d) => Some(d.token.syntax_type),
            ClangNodeKind::OpToken(d) => Some(d.syntax_type),
            ClangNodeKind::VariableToken(d) => Some(d.token.syntax_type),
            ClangNodeKind::FuncNameToken(d) => Some(d.token.syntax_type),
            ClangNodeKind::FieldToken(d) => Some(d.token.syntax_type),
            ClangNodeKind::TypeToken(d) => Some(d.token.syntax_type),
            ClangNodeKind::LabelToken(d) => Some(d.token.syntax_type),
            ClangNodeKind::CommentToken(d) => Some(d.token.syntax_type),
            ClangNodeKind::CaseToken(d) => Some(d.token.syntax_type),
            ClangNodeKind::BitFieldToken(d) => Some(d.token.syntax_type),
            ClangNodeKind::Break(_) => Some(SyntaxType::Default),
            ClangNodeKind::Token(d) => Some(d.syntax_type),
            _ => None,
        }
    }
}

fn is_letter_digit_or_underscore(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

// ============================================================================
// Base token data (shared by all leaf tokens)
// ============================================================================

/// Base data shared by all ClangToken variants.
#[derive(Debug, Clone, Default)]
pub struct ClangTokenData {
    /// The display text.
    pub text: Option<String>,
    /// Syntax coloring type.
    pub syntax_type: SyntaxType,
    /// Whether this token has matching highlight.
    pub matching_token: bool,
    /// P-code op reference id (for decode).
    pub op_ref: Option<u32>,
    /// Varnode reference id (for decode).
    pub var_ref: Option<u32>,
    /// Symbol reference id (for decode).
    pub sym_ref: Option<u64>,
}

impl ClangTokenData {
    /// Get the min address (tokens have no address by default).
    pub fn min_address(&self) -> Option<Address> {
        None
    }

    /// Get the max address (tokens have no address by default).
    pub fn max_address(&self) -> Option<Address> {
        None
    }
}

// ============================================================================
// Group data (shared by all group tokens)
// ============================================================================

/// Base data for group nodes (ClangTokenGroup and subclasses).
#[derive(Debug, Clone, Default)]
pub struct ClangTokenGroupData {
    /// Parent group id.
    pub parent: ClangNodeId,
    /// Children node ids.
    pub children: Vec<ClangNodeId>,
    /// Minimum address covered by this group.
    pub min_address: Option<Address>,
    /// Maximum address covered by this group.
    pub max_address: Option<Address>,
}

// ============================================================================
// ClangFunctionData
// ============================================================================

/// A grouping of source code tokens representing an entire function.
#[derive(Debug, Clone)]
pub struct ClangFunctionData {
    /// The underlying token group.
    pub group: ClangTokenGroupData,
    /// High function reference id.
    pub high_function_ref: Option<u32>,
}

impl Default for ClangFunctionData {
    fn default() -> Self {
        Self {
            group: ClangTokenGroupData::default(),
            high_function_ref: None,
        }
    }
}

// ============================================================================
// ClangFuncProtoData
// ============================================================================

/// A grouping of source code tokens representing a function prototype.
#[derive(Debug, Clone, Default)]
pub struct ClangFuncProtoData {
    /// The underlying token group.
    pub group: ClangTokenGroupData,
}

// ============================================================================
// ClangStatementData
// ============================================================================

/// A C statement grouping.  The group contains the tokens for one C statement.
#[derive(Debug, Clone, Default)]
pub struct ClangStatementData {
    /// The underlying token group.
    pub group: ClangTokenGroupData,
    /// The P-code op reference id associated with this statement.
    pub op_ref: Option<u32>,
}

// ============================================================================
// ClangVariableDeclData
// ============================================================================

/// A variable declaration.
#[derive(Debug, Clone, Default)]
pub struct ClangVariableDeclData {
    /// The underlying token group.
    pub group: ClangTokenGroupData,
    /// Symbol reference id.
    pub sym_ref: Option<u64>,
    /// Data type name.
    pub datatype_name: Option<String>,
    /// Data type id.
    pub datatype_id: Option<u64>,
}

// ============================================================================
// ClangReturnTypeData
// ============================================================================

/// A return type token group.
#[derive(Debug, Clone, Default)]
pub struct ClangReturnTypeData {
    /// The underlying token group.
    pub group: ClangTokenGroupData,
    /// Varnode reference id.
    pub var_ref: Option<u32>,
    /// Data type name.
    pub datatype_name: Option<String>,
}

// ============================================================================
// ClangSyntaxTokenData
// ============================================================================

/// A syntax token (parenthesis, brace, semicolon, etc.).
#[derive(Debug, Clone, Default)]
pub struct ClangSyntaxTokenData {
    /// Base token data.
    pub token: ClangTokenData,
    /// Open bracket match id (-1 = not a bracket).
    pub open: i32,
    /// Close bracket match id (-1 = not a bracket).
    pub close: i32,
    /// Whether this is a variable reference (inside ClangVariableDecl).
    pub is_variable_ref: bool,
}

// ============================================================================
// ClangOpTokenData
// ============================================================================

/// An operator token.
#[derive(Debug, Clone, Default)]
pub struct ClangOpTokenData {
    /// Display text.
    pub text: Option<String>,
    /// Syntax coloring type.
    pub syntax_type: SyntaxType,
    /// P-code op reference id.
    pub op_ref: Option<u32>,
    /// Target address (from op seqnum).
    pub min_address: Option<Address>,
}

// ============================================================================
// ClangVariableTokenData
// ============================================================================

/// A variable token.
#[derive(Debug, Clone, Default)]
pub struct ClangVariableTokenData {
    /// Base token data.
    pub token: ClangTokenData,
    /// P-code op reference id.
    pub op_ref: Option<u32>,
    /// Varnode reference id.
    pub var_ref: Option<u32>,
    /// Address from op seqnum.
    pub address: Option<Address>,
}

impl ClangVariableTokenData {
    /// Get the min address.
    pub fn min_address(&self) -> Option<Address> {
        self.address
    }
}

// ============================================================================
// ClangFuncNameTokenData
// ============================================================================

/// A function name token.
#[derive(Debug, Clone, Default)]
pub struct ClangFuncNameTokenData {
    /// Base token data.
    pub token: ClangTokenData,
    /// High function reference id.
    pub high_function_ref: Option<u32>,
    /// P-code op reference id.
    pub op_ref: Option<u32>,
    /// Address from op seqnum.
    pub min_address: Option<Address>,
}

// ============================================================================
// ClangFieldTokenData
// ============================================================================

/// A field (struct member) token.
#[derive(Debug, Clone, Default)]
pub struct ClangFieldTokenData {
    /// Base token data.
    pub token: ClangTokenData,
    /// Data type name.
    pub datatype_name: Option<String>,
    /// Data type id.
    pub datatype_id: Option<u64>,
    /// Byte offset within structure.
    pub offset: i32,
    /// P-code op reference id.
    pub op_ref: Option<u32>,
    /// Address from op seqnum.
    pub address: Option<Address>,
}

impl ClangFieldTokenData {
    /// Get the min address.
    pub fn min_address(&self) -> Option<Address> {
        self.address
    }
}

// ============================================================================
// ClangTypeTokenData
// ============================================================================

/// A type name token.
#[derive(Debug, Clone, Default)]
pub struct ClangTypeTokenData {
    /// Base token data.
    pub token: ClangTokenData,
}

// ============================================================================
// ClangLabelTokenData
// ============================================================================

/// A control-flow label token.
#[derive(Debug, Clone)]
pub struct ClangLabelTokenData {
    /// Base token data.
    pub token: ClangTokenData,
    /// Address this label marks.
    pub block_address: Address,
}

impl Default for ClangLabelTokenData {
    fn default() -> Self {
        Self {
            token: ClangTokenData::default(),
            block_address: Address::NULL,
        }
    }
}

// ============================================================================
// ClangCommentTokenData
// ============================================================================

/// A comment token.
#[derive(Debug, Clone, Default)]
pub struct ClangCommentTokenData {
    /// Base token data.
    pub token: ClangTokenData,
    /// Source address of the comment.
    pub source_address: Option<Address>,
}

// ============================================================================
// ClangCaseTokenData
// ============================================================================

/// A switch case label token.
#[derive(Debug, Clone, Default)]
pub struct ClangCaseTokenData {
    /// Base token data.
    pub token: ClangTokenData,
    /// P-code op reference id.
    pub op_ref: Option<u32>,
    /// The constant value.
    pub value: i64,
    /// Address from op seqnum.
    pub address: Option<Address>,
}

impl ClangCaseTokenData {
    /// Get the min address.
    pub fn min_address(&self) -> Option<Address> {
        self.address
    }
}

// ============================================================================
// ClangBitFieldTokenData
// ============================================================================

/// A bitfield token.
#[derive(Debug, Clone, Default)]
pub struct ClangBitFieldTokenData {
    /// Base token data.
    pub token: ClangTokenData,
    /// Structure data type name.
    pub datatype_name: Option<String>,
    /// Data type id.
    pub datatype_id: Option<u64>,
    /// Identifier for the bitfield within its container.
    pub ident: i32,
    /// P-code op reference id.
    pub op_ref: Option<u32>,
    /// Address from op seqnum.
    pub address: Option<Address>,
}

impl ClangBitFieldTokenData {
    /// Get the min address.
    pub fn min_address(&self) -> Option<Address> {
        self.address
    }
}

// ============================================================================
// ClangBreakData
// ============================================================================

/// A line-break token.
#[derive(Debug, Clone, Default)]
pub struct ClangBreakData {
    /// Number of indent levels following this line break.
    pub indent: i32,
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arena_alloc_and_get() {
        let mut arena = ClangNodeArena::new();
        let id = arena.alloc(ClangNodeKind::Token(ClangTokenData {
            text: Some("hello".to_string()),
            syntax_type: SyntaxType::Keyword,
            ..Default::default()
        }));
        assert_eq!(arena.len(), 1);
        assert!(arena.get(id).is_some());
    }

    #[test]
    fn test_arena_group_add_child() {
        let mut arena = ClangNodeArena::new();
        let group_id = arena.alloc(ClangNodeKind::TokenGroup(ClangTokenGroupData::default()));
        let tok_id = arena.alloc(ClangNodeKind::Token(ClangTokenData {
            text: Some("int".to_string()),
            syntax_type: SyntaxType::Keyword,
            ..Default::default()
        }));
        arena.add_child(group_id, tok_id);
        assert_eq!(arena.num_children(group_id), 1);
        assert_eq!(arena.child(group_id, 0), Some(tok_id));
    }

    #[test]
    fn test_arena_flatten() {
        let mut arena = ClangNodeArena::new();
        let group_id = arena.alloc(ClangNodeKind::TokenGroup(ClangTokenGroupData::default()));
        for text in &["int", " ", "main", "(", ")"] {
            let tok_id = arena.alloc(ClangNodeKind::Token(ClangTokenData {
                text: Some(text.to_string()),
                syntax_type: SyntaxType::Default,
                ..Default::default()
            }));
            arena.add_child(group_id, tok_id);
        }
        let leaves = arena.flatten(group_id);
        assert_eq!(leaves.len(), 5);
    }

    #[test]
    fn test_arena_to_string() {
        let mut arena = ClangNodeArena::new();
        let group_id = arena.alloc(ClangNodeKind::TokenGroup(ClangTokenGroupData::default()));
        for text in &["int", " ", "main", "(", ")"] {
            let tok_id = arena.alloc(ClangNodeKind::Token(ClangTokenData {
                text: Some(text.to_string()),
                syntax_type: SyntaxType::Default,
                ..Default::default()
            }));
            arena.add_child(group_id, tok_id);
        }
        let s = arena.to_string(group_id);
        assert_eq!(s, "int main()");
    }

    #[test]
    fn test_syntax_type_from_i32() {
        assert_eq!(SyntaxType::from_i32(0), SyntaxType::Keyword);
        assert_eq!(SyntaxType::from_i32(1), SyntaxType::Comment);
        assert_eq!(SyntaxType::from_i32(8), SyntaxType::Default);
        assert_eq!(SyntaxType::from_i32(99), SyntaxType::Default);
    }

    #[test]
    fn test_is_letter_digit_or_underscore() {
        assert!(is_letter_digit_or_underscore('a'));
        assert!(is_letter_digit_or_underscore('Z'));
        assert!(is_letter_digit_or_underscore('0'));
        assert!(is_letter_digit_or_underscore('_'));
        assert!(!is_letter_digit_or_underscore(' '));
        assert!(!is_letter_digit_or_underscore('('));
    }
}
