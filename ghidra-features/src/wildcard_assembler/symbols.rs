//! Wildcard assembly terminal and non-terminal symbols.
//!
//! Ported from Ghidra's `ghidra.asm.wild.symbol` Java package.

/// A terminal symbol in the wildcard assembly grammar.
#[derive(Debug, Clone, PartialEq)]
pub enum WildAssemblyTerminal {
    /// A fixed numeric terminal (exact value required).
    FixedNumeric(u64),
    /// A numeric terminal that can be any value.
    Numeric,
    /// A fixed string terminal.
    String(String),
    /// A numeric map terminal (value maps to a set of allowed values).
    NumericMap(Vec<u64>),
    /// A string map terminal (value maps to a set of allowed strings).
    StringMap(Vec<String>),
    /// A subtable terminal (references another parse table).
    Subtable(String),
}

impl WildAssemblyTerminal {
    pub fn is_wildcard(&self) -> bool {
        matches!(self, Self::Numeric | Self::NumericMap(_) | Self::StringMap(_))
    }
}

/// A non-terminal symbol in the wildcard assembly grammar.
#[derive(Debug, Clone)]
pub struct WildAssemblyNonTerminal {
    /// Name of the non-terminal.
    pub name: String,
    /// Index into the parse table.
    pub table_index: usize,
    /// Whether this non-terminal resolves to a wildcard.
    pub is_wildcard: bool,
}

impl WildAssemblyNonTerminal {
    pub fn new(name: String, table_index: usize) -> Self {
        Self { name, table_index, is_wildcard: false }
    }

    pub fn with_wildcard(mut self, is_wildcard: bool) -> Self {
        self.is_wildcard = is_wildcard;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fixed_numeric_terminal() {
        let t = WildAssemblyTerminal::FixedNumeric(0xFF);
        assert!(!t.is_wildcard());
    }

    #[test]
    fn test_numeric_terminal_is_wildcard() {
        let t = WildAssemblyTerminal::Numeric;
        assert!(t.is_wildcard());
    }

    #[test]
    fn test_numeric_map_is_wildcard() {
        let t = WildAssemblyTerminal::NumericMap(vec![1, 2, 3]);
        assert!(t.is_wildcard());
    }

    #[test]
    fn test_string_terminal() {
        let t = WildAssemblyTerminal::String("eax".into());
        assert!(!t.is_wildcard());
    }

    #[test]
    fn test_non_terminal() {
        let nt = WildAssemblyNonTerminal::new("operand".into(), 0).with_wildcard(true);
        assert!(nt.is_wildcard);
        assert_eq!(nt.name, "operand");
    }
}
