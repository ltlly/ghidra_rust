//! Grammar representation for the SLEIGH assembler.
//!
//! Corresponds to Java's `ghidra.app.plugin.assembler.sleigh.grammars`.
//!
//! The grammar models the structure of assembly language mnemonics
//! and their operands.  Productions map non-terminal symbols to
//! sequences of terminals and non-terminals.  The assembly grammar
//! is used by the parser to construct parse trees from textual
//! assembly instructions.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::base::assembler::sleigh::symbol::AssemblySymbol;

// ---------------------------------------------------------------------------
// AssemblySentential
// ---------------------------------------------------------------------------

/// A sequence of symbols (terminals and non-terminals).
///
/// This is the right-hand side of a production rule.
/// Corresponds to Java's `AssemblySentential`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct AssemblySentential {
    /// The symbols in order.
    pub symbols: Vec<AssemblySymbol>,
}

impl AssemblySentential {
    /// Create an empty sentential.
    pub fn new() -> Self {
        Self {
            symbols: Vec::new(),
        }
    }

    /// Append a symbol.
    pub fn push(&mut self, sym: AssemblySymbol) {
        self.symbols.push(sym);
    }

    /// Get the number of symbols.
    pub fn len(&self) -> usize {
        self.symbols.len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.symbols.is_empty()
    }

    /// Iterate over symbols.
    pub fn iter(&self) -> impl Iterator<Item = &AssemblySymbol> {
        self.symbols.iter()
    }
}

impl Default for AssemblySentential {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// AssemblyProduction
// ---------------------------------------------------------------------------

/// A single production rule: LHS (non-terminal) -> RHS (sentential form).
///
/// Corresponds to Java's `AssemblyProduction`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct AssemblyProduction {
    /// The left-hand side non-terminal.
    pub lhs: String,
    /// The right-hand side sentential form.
    pub rhs: AssemblySentential,
    /// The index of this production in the grammar.
    pub index: usize,
}

impl AssemblyProduction {
    /// Create a new production.
    pub fn new(lhs: impl Into<String>, rhs: AssemblySentential, index: usize) -> Self {
        Self {
            lhs: lhs.into(),
            rhs,
            index,
        }
    }
}

impl fmt::Display for AssemblyProduction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} -> ", self.lhs)?;
        for (i, sym) in self.rhs.symbols.iter().enumerate() {
            if i > 0 {
                write!(f, " ")?;
            }
            write!(f, "{}", sym)?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// AssemblyGrammar
// ---------------------------------------------------------------------------

/// A grammar for parsing assembly instructions.
///
/// Corresponds to Java's `AssemblyGrammar`.  This models a
/// context-free grammar where the start symbol is "instruction".
#[derive(Debug, Clone)]
pub struct AssemblyGrammar {
    /// Non-terminal symbols.
    pub non_terminals: BTreeSet<String>,
    /// Terminal symbols.
    pub terminals: BTreeSet<String>,
    /// Production rules, keyed by LHS non-terminal.
    pub productions: BTreeMap<String, Vec<AssemblyProduction>>,
    /// All productions in index order.
    pub all_productions: Vec<AssemblyProduction>,
}

impl AssemblyGrammar {
    /// Create a new empty grammar.
    pub fn new() -> Self {
        Self {
            non_terminals: BTreeSet::new(),
            terminals: BTreeSet::new(),
            productions: BTreeMap::new(),
            all_productions: Vec::new(),
        }
    }

    /// Add a production to the grammar.
    pub fn add_production(&mut self, prod: AssemblyProduction) {
        self.non_terminals.insert(prod.lhs.clone());
        for sym in &prod.rhs.symbols {
            match sym {
                AssemblySymbol::NonTerminal(nt) => {
                    self.non_terminals.insert(nt.clone());
                }
                other => {
                    self.terminals.insert(other.name().to_string());
                }
            }
        }
        self.productions
            .entry(prod.lhs.clone())
            .or_default()
            .push(prod.clone());
        self.all_productions.push(prod);
    }

    /// Get productions for a given non-terminal.
    pub fn get_productions(&self, non_terminal: &str) -> &[AssemblyProduction] {
        self.productions
            .get(non_terminal)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Get the start symbol productions.
    pub fn get_start_productions(&self) -> &[AssemblyProduction] {
        self.get_productions("instruction")
    }

    /// Check if a symbol is a non-terminal.
    pub fn is_non_terminal(&self, name: &str) -> bool {
        self.non_terminals.contains(name)
    }

    /// Check if a symbol is a terminal.
    pub fn is_terminal(&self, name: &str) -> bool {
        self.terminals.contains(name)
    }

    /// Get the total number of productions.
    pub fn num_productions(&self) -> usize {
        self.all_productions.len()
    }
}

impl Default for AssemblyGrammar {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::assembler::sleigh::symbol::AssemblySymbol;

    #[test]
    fn test_grammar_construction() {
        let mut grammar = AssemblyGrammar::new();

        let mut rhs = AssemblySentential::new();
        rhs.push(AssemblySymbol::terminal("MOV"));
        rhs.push(AssemblySymbol::non_terminal("register"));
        rhs.push(AssemblySymbol::terminal(","));
        rhs.push(AssemblySymbol::non_terminal("register"));

        let prod = AssemblyProduction::new("instruction", rhs, 0);
        grammar.add_production(prod);

        assert!(grammar.is_non_terminal("instruction"));
        assert!(grammar.is_non_terminal("register"));
        assert!(grammar.is_terminal("MOV"));
        assert_eq!(grammar.num_productions(), 1);
        assert_eq!(grammar.get_start_productions().len(), 1);
    }
}
