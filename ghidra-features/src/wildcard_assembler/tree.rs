//! Wildcard assembly parse tree nodes.
//!
//! Ported from Ghidra's `ghidra.asm.wild.tree` Java package.

/// A parse token in the wildcard assembly tree.
#[derive(Debug, Clone)]
pub struct WildAssemblyParseToken {
    /// The text of this token.
    pub text: String,
    /// Start position in the source line.
    pub start: usize,
    /// End position in the source line.
    pub end: usize,
    /// The production index that generated this token.
    pub production_index: Option<usize>,
}

impl WildAssemblyParseToken {
    pub fn new(text: String, start: usize, end: usize) -> Self {
        Self { text, start, end, production_index: None }
    }

    pub fn with_production(mut self, index: usize) -> Self {
        self.production_index = Some(index);
        self
    }

    pub fn length(&self) -> usize {
        self.end - self.start
    }
}

/// A hidden node in the parse tree (for internal use).
#[derive(Debug, Clone)]
pub struct WildAssemblyParseHiddenNode {
    /// Child nodes.
    pub children: Vec<ParseNode>,
    /// The non-terminal name.
    pub name: String,
}

/// A node in the parse tree.
#[derive(Debug, Clone)]
pub enum ParseNode {
    /// A leaf token.
    Token(WildAssemblyParseToken),
    /// A hidden (internal) node.
    Hidden(WildAssemblyParseHiddenNode),
}

impl ParseNode {
    pub fn is_token(&self) -> bool { matches!(self, Self::Token(_)) }
    pub fn is_hidden(&self) -> bool { matches!(self, Self::Hidden(_)) }
}

/// Grammar production for wildcard assembly.
#[derive(Debug, Clone)]
pub struct WildAssemblyProduction {
    /// The left-hand side non-terminal.
    pub lhs: String,
    /// The right-hand side symbols.
    pub rhs: Vec<String>,
    /// Whether this production accepts wildcards.
    pub accepts_wildcards: bool,
}

impl WildAssemblyProduction {
    pub fn new(lhs: String, rhs: Vec<String>) -> Self {
        Self { lhs, rhs, accepts_wildcards: false }
    }

    pub fn with_wildcards(mut self, accepts: bool) -> Self {
        self.accepts_wildcards = accepts;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_token() {
        let t = WildAssemblyParseToken::new("eax".into(), 0, 3);
        assert_eq!(t.length(), 3);
        assert!(t.production_index.is_none());
        let t2 = t.with_production(5);
        assert_eq!(t2.production_index, Some(5));
    }

    #[test]
    fn test_parse_node() {
        let tok = ParseNode::Token(WildAssemblyParseToken::new("nop".into(), 0, 3));
        assert!(tok.is_token());
        assert!(!tok.is_hidden());
    }

    #[test]
    fn test_hidden_node() {
        let hidden = ParseNode::Hidden(WildAssemblyParseHiddenNode {
            children: vec![],
            name: "stmt".into(),
        });
        assert!(hidden.is_hidden());
    }

    #[test]
    fn test_production() {
        let p = WildAssemblyProduction::new(
            "instruction".into(),
            vec!["opcode".into(), "operand".into()],
        ).with_wildcards(true);
        assert!(p.accepts_wildcards);
        assert_eq!(p.rhs.len(), 2);
    }
}
