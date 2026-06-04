//! Parse tree nodes for SLEIGH assembly.
//!
//! Corresponds to Java's `ghidra.app.plugin.assembler.sleigh.tree`.

use crate::base::assembler::sleigh::symbol::AssemblySymbol;

/// A node in an assembly parse tree.
///
/// Parse trees are produced by the parser and consumed by the
/// semantic resolver to produce machine code patterns.
///
/// Corresponds to the various `AssemblyParseTreeNode` types in Java.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssemblyParseTreeNode {
    /// A branch node with children (non-terminal expansion).
    Branch {
        /// The non-terminal symbol.
        symbol: AssemblySymbol,
        /// Child nodes.
        children: Vec<AssemblyParseTreeNode>,
    },
    /// A leaf token (terminal match).
    Token {
        /// The matched text.
        text: String,
        /// The terminal symbol.
        symbol: AssemblySymbol,
    },
    /// A numeric token (matched number).
    NumericToken {
        /// The numeric value.
        value: u64,
        /// The terminal symbol.
        symbol: AssemblySymbol,
    },
    /// A hidden node (produces no visible output).
    Hidden {
        /// The hidden symbol name.
        name: String,
        /// Child node.
        child: Box<AssemblyParseTreeNode>,
    },
}

impl AssemblyParseTreeNode {
    /// Get the symbol at this node.
    pub fn symbol(&self) -> &AssemblySymbol {
        match self {
            Self::Branch { symbol, .. } => symbol,
            Self::Token { symbol, .. } => symbol,
            Self::NumericToken { symbol, .. } => symbol,
            Self::Hidden { name: _, .. } => {
                // Hidden nodes: callers should use the variant directly
                // rather than this generic accessor.  We return a dummy
                // symbol here as a fallback.
                panic!("AssemblyParseTreeNode::symbol() is not supported for Hidden nodes; match on the variant directly")
            }
        }
    }

    /// Get the child nodes (empty for leaves).
    pub fn children(&self) -> &[AssemblyParseTreeNode] {
        match self {
            Self::Branch { children, .. } => children,
            Self::Hidden { child, .. } => std::slice::from_ref(child),
            _ => &[],
        }
    }

    /// Get the text of a token node.
    pub fn token_text(&self) -> Option<&str> {
        match self {
            Self::Token { text, .. } => Some(text),
            _ => None,
        }
    }

    /// Get the value of a numeric token node.
    pub fn numeric_value(&self) -> Option<u64> {
        match self {
            Self::NumericToken { value, .. } => Some(*value),
            _ => None,
        }
    }

    /// Check if this is a leaf node.
    pub fn is_leaf(&self) -> bool {
        matches!(self, Self::Token { .. } | Self::NumericToken { .. })
    }

    /// Check if this is a branch node.
    pub fn is_branch(&self) -> bool {
        matches!(self, Self::Branch { .. })
    }

    /// Recursively collect all token texts.
    pub fn collect_tokens(&self) -> Vec<String> {
        let mut result = Vec::new();
        self.collect_tokens_impl(&mut result);
        result
    }

    fn collect_tokens_impl(&self, out: &mut Vec<String>) {
        match self {
            Self::Token { text, .. } => out.push(text.clone()),
            Self::NumericToken { value, .. } => out.push(format!("{}", value)),
            Self::Branch { children, .. } => {
                for child in children {
                    child.collect_tokens_impl(out);
                }
            }
            Self::Hidden { child, .. } => child.collect_tokens_impl(out),
        }
    }

    /// Recursively collect all tokens with their symbols.
    pub fn collect_terminal_symbols(&self) -> Vec<(String, AssemblySymbol)> {
        let mut result = Vec::new();
        self.collect_terminals_impl(&mut result);
        result
    }

    fn collect_terminals_impl(&self, out: &mut Vec<(String, AssemblySymbol)>) {
        match self {
            Self::Token { text, symbol } => out.push((text.clone(), symbol.clone())),
            Self::NumericToken { value, symbol } => {
                out.push((format!("{}", value), symbol.clone()))
            }
            Self::Branch { children, .. } => {
                for child in children {
                    child.collect_terminals_impl(out);
                }
            }
            Self::Hidden { child, .. } => child.collect_terminals_impl(out),
        }
    }
}

impl std::fmt::Display for AssemblyParseTreeNode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.fmt_indent(f, 0)
    }
}

impl AssemblyParseTreeNode {
    fn fmt_indent(&self, f: &mut std::fmt::Formatter<'_>, indent: usize) -> std::fmt::Result {
        let pad = " ".repeat(indent);
        match self {
            Self::Branch { symbol, children } => {
                writeln!(f, "{}[{}]", pad, symbol)?;
                for child in children {
                    child.fmt_indent(f, indent + 2)?;
                }
                Ok(())
            }
            Self::Token { text, symbol } => {
                writeln!(f, "{}'{}' ({})", pad, text, symbol)
            }
            Self::NumericToken { value, symbol } => {
                writeln!(f, "{}{} ({})", pad, value, symbol)
            }
            Self::Hidden { name, child } => {
                writeln!(f, "{}{{{}}}", pad, name)?;
                child.fmt_indent(f, indent + 2)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::assembler::sleigh::symbol::AssemblySymbol;

    #[test]
    fn test_token_node() {
        let node = AssemblyParseTreeNode::Token {
            text: "ADD".to_string(),
            symbol: AssemblySymbol::terminal("ADD"),
        };
        assert!(node.is_leaf());
        assert_eq!(node.token_text(), Some("ADD"));
        assert_eq!(node.children().len(), 0);
    }

    #[test]
    fn test_branch_node() {
        let node = AssemblyParseTreeNode::Branch {
            symbol: AssemblySymbol::non_terminal("instruction"),
            children: vec![
                AssemblyParseTreeNode::Token {
                    text: "MOV".to_string(),
                    symbol: AssemblySymbol::terminal("MOV"),
                },
                AssemblyParseTreeNode::NumericToken {
                    value: 0,
                    symbol: AssemblySymbol::numeric_terminal("R0", 0),
                },
            ],
        };
        assert!(node.is_branch());
        assert_eq!(node.children().len(), 2);
    }

    #[test]
    fn test_collect_tokens() {
        let node = AssemblyParseTreeNode::Branch {
            symbol: AssemblySymbol::non_terminal("instruction"),
            children: vec![
                AssemblyParseTreeNode::Token {
                    text: "PUSH".to_string(),
                    symbol: AssemblySymbol::terminal("PUSH"),
                },
                AssemblyParseTreeNode::Token {
                    text: "R0".to_string(),
                    symbol: AssemblySymbol::terminal("R0"),
                },
            ],
        };
        let tokens = node.collect_tokens();
        assert_eq!(tokens, vec!["PUSH", "R0"]);
    }

    #[test]
    fn test_numeric_token() {
        let node = AssemblyParseTreeNode::NumericToken {
            value: 42,
            symbol: AssemblySymbol::numeric_terminal("imm8", 42),
        };
        assert!(node.is_leaf());
        assert_eq!(node.numeric_value(), Some(42));
    }
}
