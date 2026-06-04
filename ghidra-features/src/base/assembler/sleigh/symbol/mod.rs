//! Assembly symbols for the SLEIGH grammar.
//!
//! Corresponds to Java's `ghidra.app.plugin.assembler.sleigh.symbol`.
//!
//! Symbols represent the terminal and non-terminal elements of the
//! assembly grammar.  Terminals match literal tokens; non-terminals
//! correspond to sub-tables and operands.

use std::collections::{BTreeMap, HashMap};
use std::fmt;

// MaskedLong is used in the symbol types for register value mapping

// ---------------------------------------------------------------------------
// AssemblySymbol (enum dispatch)
// ---------------------------------------------------------------------------

/// An assembly grammar symbol.
///
/// This is the top-level enum that represents any symbol in the
/// grammar: terminals, non-terminals, and special symbols.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum AssemblySymbol {
    /// A string literal terminal (e.g., "MOV", "ADD").
    StringTerminal(String),
    /// A numeric terminal with a fixed value.
    NumericTerminal {
        /// The name of the terminal.
        name: String,
        /// The fixed numeric value.
        value: u64,
    },
    /// A terminal that matches one of a set of numeric values.
    NumericMapTerminal {
        /// The name.
        name: String,
        /// Map from name to value.
        values: BTreeMap<String, u64>,
    },
    /// A terminal that matches a set of string values.
    StringMapTerminal {
        /// The name.
        name: String,
        /// Map from name to string.
        values: BTreeMap<String, String>,
    },
    /// A non-terminal symbol (sub-table reference).
    NonTerminal(String),
    /// An extended non-terminal for the grammar.
    ExtendedNonTerminal(String),
    /// End-of-input marker.
    EOI,
    /// A hidden node in the parse tree.
    Hidden(String),
    /// A fixed numeric terminal (always matches a specific number).
    FixedNumeric {
        /// The name.
        name: String,
        /// The fixed value.
        value: u64,
    },
}

impl AssemblySymbol {
    /// Create a string terminal.
    pub fn terminal(name: impl Into<String>) -> Self {
        Self::StringTerminal(name.into())
    }

    /// Create a non-terminal.
    pub fn non_terminal(name: impl Into<String>) -> Self {
        Self::NonTerminal(name.into())
    }

    /// Create a numeric terminal.
    pub fn numeric_terminal(name: impl Into<String>, value: u64) -> Self {
        Self::NumericTerminal {
            name: name.into(),
            value,
        }
    }

    /// Create an end-of-input marker.
    pub fn eoi() -> Self {
        Self::EOI
    }

    /// Get the name of this symbol.
    pub fn name(&self) -> &str {
        match self {
            Self::StringTerminal(s) => s,
            Self::NumericTerminal { name, .. } => name,
            Self::NumericMapTerminal { name, .. } => name,
            Self::StringMapTerminal { name, .. } => name,
            Self::NonTerminal(s) => s,
            Self::ExtendedNonTerminal(s) => s,
            Self::EOI => "$EOI",
            Self::Hidden(s) => s,
            Self::FixedNumeric { name, .. } => name,
        }
    }

    /// Check if this symbol is a non-terminal.
    pub fn is_non_terminal(&self) -> bool {
        matches!(self, Self::NonTerminal(_) | Self::ExtendedNonTerminal(_))
    }

    /// Check if this symbol is a terminal.
    pub fn is_terminal(&self) -> bool {
        !self.is_non_terminal()
    }

    /// Check if this is EOI.
    pub fn is_eoi(&self) -> bool {
        matches!(self, Self::EOI)
    }

    /// Check if this is a hidden symbol.
    pub fn is_hidden(&self) -> bool {
        matches!(self, Self::Hidden(_))
    }
}

impl fmt::Display for AssemblySymbol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StringTerminal(s) => write!(f, "'{}'", s),
            Self::NumericTerminal { name, value } => write!(f, "{}={}", name, value),
            Self::NonTerminal(s) => write!(f, "<{}>", s),
            Self::ExtendedNonTerminal(s) => write!(f, "<{}'>", s),
            Self::EOI => write!(f, "$"),
            Self::Hidden(s) => write!(f, "{{{}}}", s),
            Self::FixedNumeric { value, .. } => write!(f, "{}", value),
            Self::NumericMapTerminal { name, .. } => write!(f, "<{}:nummap>", name),
            Self::StringMapTerminal { name, .. } => write!(f, "<{}:strmap>", name),
        }
    }
}

// ---------------------------------------------------------------------------
// AssemblyNumericSymbols
// ---------------------------------------------------------------------------

/// A map from string names to numeric values, representing symbols
/// available during assembly (e.g., register names, label addresses).
///
/// Corresponds to Java's `AssemblyNumericSymbols`.
#[derive(Debug, Clone, Default)]
pub struct AssemblyNumericSymbols {
    /// Symbol name -> numeric value.
    pub symbols: HashMap<String, u64>,
}

impl AssemblyNumericSymbols {
    /// Create from a language's register set.
    pub fn from_language() -> Self {
        // In the real implementation, this would extract register
        // names and addresses from the SleighLanguage.
        Self::default()
    }

    /// Create from a program's symbol table.
    pub fn from_program() -> Self {
        // In the real implementation, this would extract symbols
        // from the program's symbol table.
        Self::default()
    }

    /// Add a symbol.
    pub fn insert(&mut self, name: impl Into<String>, value: u64) {
        self.symbols.insert(name.into(), value);
    }

    /// Look up a symbol by name.
    pub fn get(&self, name: &str) -> Option<u64> {
        self.symbols.get(name).copied()
    }

    /// Iterate over all symbols.
    pub fn iter(&self) -> impl Iterator<Item = (&String, &u64)> {
        self.symbols.iter()
    }
}

// ---------------------------------------------------------------------------
// Convenience re-exports for symbol sub-types
// ---------------------------------------------------------------------------

/// A non-terminal symbol.
#[derive(Debug, Clone)]
pub struct AssemblyNonTerminal {
    /// The name.
    pub name: String,
}

/// A string terminal.
#[derive(Debug, Clone)]
pub struct AssemblyStringTerminal {
    /// The matched text.
    pub text: String,
}

impl AssemblyStringTerminal {
    /// Create a new string terminal.
    pub fn new(text: impl Into<String>) -> Self {
        Self { text: text.into() }
    }
}

/// A terminal that matches a set of named numeric values.
pub trait AssemblyTerminal: Send + Sync + fmt::Debug {
    /// Check if this terminal matches the given text.
    fn matches(&self, text: &str) -> bool;

    /// Get the numeric value for the given text.
    fn value_for(&self, text: &str) -> Option<u64>;

    /// Get the name of this terminal.
    fn name(&self) -> &str;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_symbol_properties() {
        let nt = AssemblySymbol::non_terminal("register");
        assert!(nt.is_non_terminal());
        assert!(!nt.is_terminal());
        assert_eq!(nt.name(), "register");

        let t = AssemblySymbol::terminal("MOV");
        assert!(t.is_terminal());
        assert!(!t.is_non_terminal());
        assert_eq!(t.name(), "MOV");

        let eoi = AssemblySymbol::eoi();
        assert!(eoi.is_eoi());
        assert!(eoi.is_terminal());
    }

    #[test]
    fn test_symbol_display() {
        assert_eq!(format!("{}", AssemblySymbol::terminal("ADD")), "'ADD'");
        assert_eq!(
            format!("{}", AssemblySymbol::non_terminal("operand")),
            "<operand>"
        );
        assert_eq!(format!("{}", AssemblySymbol::eoi()), "$");
    }

    #[test]
    fn test_numeric_symbols() {
        let mut syms = AssemblyNumericSymbols::default();
        syms.insert("R0", 0);
        syms.insert("R1", 1);
        syms.insert("SP", 13);
        syms.insert("LR", 14);
        syms.insert("PC", 15);

        assert_eq!(syms.get("SP"), Some(13));
        assert_eq!(syms.get("R99"), None);
    }
}
