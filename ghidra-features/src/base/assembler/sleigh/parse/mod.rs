//! Parsing infrastructure for SLEIGH assembly.
//!
//! Corresponds to Java's `ghidra.app.plugin.assembler.sleigh.parse`.
//!
//! The parser tokenises a textual assembly instruction and attempts
//! to match it against the grammar using an LR-style automaton.
//! The result is one or more parse trees, or a syntax error.

use std::collections::{BTreeMap, BTreeSet};

use crate::base::assembler::sleigh::grammars::{AssemblyGrammar, AssemblyProduction};
use crate::base::assembler::sleigh::symbol::{AssemblyNumericSymbols, AssemblySymbol};
use crate::base::assembler::sleigh::tree::AssemblyParseTreeNode;

// ---------------------------------------------------------------------------
// AssemblyParseResult
// ---------------------------------------------------------------------------

/// The result of parsing a single textual assembly instruction.
///
/// A parse result may represent a successful parse tree, or an
/// error with diagnostic information.
///
/// Corresponds to Java's `AssemblyParseResult`.
#[derive(Debug, Clone)]
pub enum AssemblyParseResult {
    /// A successful parse with a parse tree.
    Accept(AcceptResult),
    /// A parse error.
    Error(ErrorResult),
}

impl AssemblyParseResult {
    /// Check if this result is an error.
    pub fn is_error(&self) -> bool {
        matches!(self, Self::Error(_))
    }

    /// Check if this result is an accept.
    pub fn is_accept(&self) -> bool {
        matches!(self, Self::Accept(_))
    }

    /// Get the parse tree (if accepted).
    pub fn tree(&self) -> Option<&AssemblyParseTreeNode> {
        match self {
            Self::Accept(a) => Some(&a.tree),
            _ => None,
        }
    }

    /// Get the error message (if error).
    pub fn error_message(&self) -> Option<&str> {
        match self {
            Self::Error(e) => Some(&e.message),
            _ => None,
        }
    }
}

impl PartialEq for AssemblyParseResult {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Accept(a), Self::Accept(b)) => a.production == b.production,
            (Self::Error(a), Self::Error(b)) => a.message == b.message,
            _ => false,
        }
    }
}

impl Eq for AssemblyParseResult {}

impl PartialOrd for AssemblyParseResult {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for AssemblyParseResult {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match (self, other) {
            (Self::Accept(a), Self::Accept(b)) => a.production.cmp(&b.production),
            (Self::Error(a), Self::Error(b)) => a.message.cmp(&b.message),
            (Self::Accept(_), Self::Error(_)) => std::cmp::Ordering::Less,
            (Self::Error(_), Self::Accept(_)) => std::cmp::Ordering::Greater,
        }
    }
}

/// A successful parse result.
#[derive(Debug, Clone)]
pub struct AcceptResult {
    /// The matched production rule.
    pub production: AssemblyProduction,
    /// The constructed parse tree.
    pub tree: AssemblyParseTreeNode,
}

/// A parse error result.
#[derive(Debug, Clone)]
pub struct ErrorResult {
    /// Human-readable error message.
    pub message: String,
    /// Position in the input where the error occurred.
    pub position: usize,
    /// Expected symbols at the error position.
    pub expected: BTreeSet<String>,
}

// ---------------------------------------------------------------------------
// AssemblyParser
// ---------------------------------------------------------------------------

/// The assembly parser.
///
/// This parser tokenises the input text and uses the grammar's
/// productions to construct parse trees.  It supports code
/// completion and error reporting.
///
/// Corresponds to Java's `AssemblyParser`.
#[derive(Debug)]
pub struct AssemblyParser {
    /// The grammar used for parsing.
    grammar: AssemblyGrammar,
    /// Numeric symbols available during parsing.
    numeric_symbols: AssemblyNumericSymbols,
}

impl AssemblyParser {
    /// Create a new parser with the given grammar.
    pub fn new(grammar: AssemblyGrammar) -> Self {
        Self {
            grammar,
            numeric_symbols: AssemblyNumericSymbols::default(),
        }
    }

    /// Parse a textual assembly line.
    ///
    /// Returns a collection of parse results.  If the parse is
    /// ambiguous, multiple accepted results may be returned.
    pub fn parse(&self, line: &str) -> Vec<AssemblyParseResult> {
        self.parse_with_symbols(line, &self.numeric_symbols)
    }

    /// Parse a line with explicit numeric symbols.
    pub fn parse_with_symbols(
        &self,
        line: &str,
        symbols: &AssemblyNumericSymbols,
    ) -> Vec<AssemblyParseResult> {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return vec![AssemblyParseResult::Error(ErrorResult {
                message: "Empty assembly line".to_string(),
                position: 0,
                expected: BTreeSet::new(),
            })];
        }

        let tokens = self.tokenise(trimmed, symbols);
        if tokens.is_empty() {
            return vec![AssemblyParseResult::Error(ErrorResult {
                message: format!("Could not tokenise: '{}'", trimmed),
                position: 0,
                expected: BTreeSet::new(),
            })];
        }

        // Attempt to match against grammar productions
        let mut results = Vec::new();
        let start_prods = self.grammar.get_start_productions();
        for prod in start_prods {
            if let Some(tree) = self.try_match_production(prod, &tokens) {
                results.push(AssemblyParseResult::Accept(AcceptResult {
                    production: prod.clone(),
                    tree,
                }));
            }
        }

        if results.is_empty() {
            results.push(AssemblyParseResult::Error(ErrorResult {
                message: format!("No matching production for: '{}'", trimmed),
                position: 0,
                expected: self
                    .grammar
                    .get_start_productions()
                    .iter()
                    .map(|p| p.to_string())
                    .collect(),
            }));
        }

        results
    }

    /// Tokenise the input string into assembly symbols.
    fn tokenise(&self, line: &str, symbols: &AssemblyNumericSymbols) -> Vec<Token> {
        let mut tokens = Vec::new();
        let mut chars = line.chars().peekable();

        while let Some(&ch) = chars.peek() {
            if ch.is_whitespace() {
                chars.next();
                continue;
            }

            // Check for comment
            if ch == '#' || ch == ';' {
                break;
            }

            // Check for punctuation
            if ch == ',' || ch == '(' || ch == ')' || ch == '[' || ch == ']' || ch == '+' || ch == '-'
                || ch == '*' || ch == '/' || ch == '&' || ch == '|' || ch == '^' || ch == '~'
                || ch == ':' || ch == '@'
            {
                tokens.push(Token {
                    text: ch.to_string(),
                    kind: TokenKind::Punctuation,
                });
                chars.next();
                continue;
            }

            // Check for numeric literal (hex or decimal)
            if ch == '0' {
                let mut num = String::new();
                num.push(ch);
                chars.next();
                if chars.peek() == Some(&'x') || chars.peek() == Some(&'X') {
                    num.push(chars.next().unwrap());
                    while let Some(&c) = chars.peek() {
                        if c.is_ascii_hexdigit() {
                            num.push(chars.next().unwrap());
                        } else {
                            break;
                        }
                    }
                } else {
                    while let Some(&c) = chars.peek() {
                        if c.is_ascii_digit() {
                            num.push(chars.next().unwrap());
                        } else {
                            break;
                        }
                    }
                }
                tokens.push(Token {
                    text: num,
                    kind: TokenKind::Number,
                });
                continue;
            }

            if ch.is_ascii_digit() || ch == '-' {
                let mut num = String::new();
                if ch == '-' {
                    num.push(ch);
                    chars.next();
                }
                while let Some(&c) = chars.peek() {
                    if c.is_ascii_digit() {
                        num.push(chars.next().unwrap());
                    } else {
                        break;
                    }
                }
                tokens.push(Token {
                    text: num,
                    kind: TokenKind::Number,
                });
                continue;
            }

            // Identifier / mnemonic
            if ch.is_alphanumeric() || ch == '_' || ch == '.' || ch == '$' || ch == '%' {
                let mut ident = String::new();
                while let Some(&c) = chars.peek() {
                    if c.is_alphanumeric() || c == '_' || c == '.' || c == '$' || c == '%' {
                        ident.push(chars.next().unwrap());
                    } else {
                        break;
                    }
                }

                // Check if it's a known symbol name (register etc.)
                if symbols.get(&ident).is_some() {
                    tokens.push(Token {
                        text: ident,
                        kind: TokenKind::Symbol,
                    });
                } else {
                    tokens.push(Token {
                        text: ident,
                        kind: TokenKind::Identifier,
                    });
                }
                continue;
            }

            // Skip unknown characters
            chars.next();
        }

        tokens
    }

    /// Try to match a production's RHS against the token stream.
    fn try_match_production(
        &self,
        prod: &AssemblyProduction,
        tokens: &[Token],
    ) -> Option<AssemblyParseTreeNode> {
        // Simplified matching: for a production of the form
        // "instruction -> MNEMONIC operands", check if the first
        // token matches the first terminal in the production.
        let rhs_symbols: Vec<&AssemblySymbol> = prod.rhs.symbols.iter().collect();

        if rhs_symbols.is_empty() {
            return None;
        }

        let mut token_idx = 0;
        let mut children = Vec::new();

        for sym in &rhs_symbols {
            match sym {
                AssemblySymbol::StringTerminal(text) => {
                    if token_idx >= tokens.len() {
                        return None;
                    }
                    if tokens[token_idx].text.to_uppercase() != text.to_uppercase() {
                        return None;
                    }
                    children.push(AssemblyParseTreeNode::Token {
                        text: tokens[token_idx].text.clone(),
                        symbol: (*sym).clone(),
                    });
                    token_idx += 1;
                }
                AssemblySymbol::NonTerminal(_nt) => {
                    // Non-terminals consume remaining tokens
                    let remaining: Vec<String> =
                        tokens[token_idx..].iter().map(|t| t.text.clone()).collect();
                    children.push(AssemblyParseTreeNode::Branch {
                        symbol: (*sym).clone(),
                        children: vec![AssemblyParseTreeNode::Token {
                            text: remaining.join(" "),
                            symbol: AssemblySymbol::terminal("operands"),
                        }],
                    });
                    token_idx = tokens.len();
                }
                AssemblySymbol::NumericTerminal { name: _, value } => {
                    if token_idx >= tokens.len() {
                        return None;
                    }
                    let parsed = parse_number(&tokens[token_idx].text);
                    if parsed != Some(*value) {
                        return None;
                    }
                    children.push(AssemblyParseTreeNode::NumericToken {
                        value: *value,
                        symbol: (*sym).clone(),
                    });
                    token_idx += 1;
                }
                _ => {
                    // Other symbols skip
                }
            }
        }

        // Must have consumed all tokens (or all significant tokens)
        if token_idx < tokens.len() {
            // Allow trailing tokens for non-terminal consumption
            if !rhs_symbols
                .iter()
                .any(|s| matches!(s, AssemblySymbol::NonTerminal(_)))
            {
                return None;
            }
        }

        Some(AssemblyParseTreeNode::Branch {
            symbol: AssemblySymbol::non_terminal(&prod.lhs),
            children,
        })
    }

    /// Get a reference to the grammar.
    pub fn grammar(&self) -> &AssemblyGrammar {
        &self.grammar
    }

    /// Set the numeric symbols.
    pub fn set_numeric_symbols(&mut self, symbols: AssemblyNumericSymbols) {
        self.numeric_symbols = symbols;
    }
}

/// Try to parse a string as a number.
fn parse_number(text: &str) -> Option<u64> {
    if text.starts_with("0x") || text.starts_with("0X") {
        u64::from_str_radix(&text[2..], 16).ok()
    } else if text.starts_with("0b") {
        u64::from_str_radix(&text[2..], 2).ok()
    } else if text.starts_with("0o") {
        u64::from_str_radix(&text[2..], 8).ok()
    } else {
        text.parse::<u64>().ok()
    }
}

// ---------------------------------------------------------------------------
// Token
// ---------------------------------------------------------------------------

/// A token produced by the tokeniser.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    /// The token text.
    pub text: String,
    /// The kind of token.
    pub kind: TokenKind,
}

/// The kind of a token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenKind {
    /// A mnemonic or register name.
    Identifier,
    /// A numeric literal.
    Number,
    /// A known symbol (register name, etc.).
    Symbol,
    /// Punctuation (comma, paren, etc.).
    Punctuation,
    /// A string literal.
    String,
}

// ---------------------------------------------------------------------------
// First/Follow sets
// ---------------------------------------------------------------------------

/// FIRST and FOLLOW sets for the grammar, used to build the parse table.
///
/// Corresponds to Java's `AssemblyFirstFollow`.
#[derive(Debug, Clone, Default)]
pub struct AssemblyFirstFollow {
    /// FIRST set for each non-terminal.
    pub first: BTreeMap<String, BTreeSet<String>>,
    /// FOLLOW set for each non-terminal.
    pub follow: BTreeMap<String, BTreeSet<String>>,
}

impl AssemblyFirstFollow {
    /// Compute FIRST and FOLLOW sets for the grammar.
    pub fn compute(grammar: &AssemblyGrammar) -> Self {
        let mut ff = Self::default();

        // Initialize FIRST sets for terminals
        for term in &grammar.terminals {
            ff.first
                .entry(term.clone())
                .or_default()
                .insert(term.clone());
        }

        // Compute FIRST sets iteratively
        let mut changed = true;
        while changed {
            changed = false;
            for prod in &grammar.all_productions {
                let lhs = &prod.lhs;
                for sym in &prod.rhs.symbols {
                    let sym_first = match sym {
                        AssemblySymbol::StringTerminal(t) => {
                            let mut s = BTreeSet::new();
                            s.insert(t.clone());
                            s
                        }
                        AssemblySymbol::NonTerminal(nt) => {
                            ff.first.get(nt).cloned().unwrap_or_default()
                        }
                        _ => BTreeSet::new(),
                    };

                    let first_set = ff.first.entry(lhs.clone()).or_default();
                    let before = first_set.len();
                    first_set.extend(sym_first);
                    if first_set.len() != before {
                        changed = true;
                    }

                    // If this symbol cannot derive epsilon, stop
                    if !matches!(sym, AssemblySymbol::NonTerminal(_)) {
                        break;
                    }
                }
            }
        }

        // FOLLOW set computation (simplified)
        // In a full implementation, this would properly handle
        // the start symbol and nullable non-terminals.
        for nt in &grammar.non_terminals {
            ff.follow.entry(nt.clone()).or_default();
        }

        ff
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::assembler::sleigh::grammars::AssemblySentential;

    fn make_simple_grammar() -> AssemblyGrammar {
        let mut grammar = AssemblyGrammar::new();

        // instruction -> MNEMONIC register ',' register
        let mut rhs = AssemblySentential::new();
        rhs.push(AssemblySymbol::terminal("NOP"));
        grammar.add_production(AssemblyProduction::new("instruction", rhs, 0));

        let mut rhs2 = AssemblySentential::new();
        rhs2.push(AssemblySymbol::terminal("RET"));
        grammar.add_production(AssemblyProduction::new("instruction", rhs2, 1));

        let mut rhs3 = AssemblySentential::new();
        rhs3.push(AssemblySymbol::terminal("MOV"));
        rhs3.push(AssemblySymbol::non_terminal("operands"));
        grammar.add_production(AssemblyProduction::new("instruction", rhs3, 2));

        grammar
    }

    #[test]
    fn test_parse_nop() {
        let grammar = make_simple_grammar();
        let parser = AssemblyParser::new(grammar);

        let results = parser.parse("NOP");
        assert!(!results.is_empty());
        assert!(results.iter().any(|r| r.is_accept()));
    }

    #[test]
    fn test_parse_ret() {
        let grammar = make_simple_grammar();
        let parser = AssemblyParser::new(grammar);

        let results = parser.parse("RET");
        assert!(results.iter().any(|r| r.is_accept()));
    }

    #[test]
    fn test_parse_mov() {
        let grammar = make_simple_grammar();
        let parser = AssemblyParser::new(grammar);

        let results = parser.parse("MOV R0, R1");
        assert!(results.iter().any(|r| r.is_accept()));
    }

    #[test]
    fn test_parse_error() {
        let grammar = make_simple_grammar();
        let parser = AssemblyParser::new(grammar);

        let results = parser.parse("UNKNOWN");
        assert!(results.iter().all(|r| r.is_error()));
    }

    #[test]
    fn test_parse_empty() {
        let grammar = make_simple_grammar();
        let parser = AssemblyParser::new(grammar);

        let results = parser.parse("");
        assert!(results.iter().all(|r| r.is_error()));
    }

    #[test]
    fn test_tokenise() {
        let grammar = make_simple_grammar();
        let parser = AssemblyParser::new(grammar);
        let symbols = AssemblyNumericSymbols::default();

        let tokens = parser.tokenise("MOV R0, 0x100", &symbols);
        assert_eq!(tokens.len(), 4); // MOV, R0, ,, 0x100
        assert_eq!(tokens[0].text, "MOV");
        assert_eq!(tokens[1].text, "R0");
        assert_eq!(tokens[2].kind, TokenKind::Punctuation);
        assert_eq!(tokens[3].text, "0x100");
        assert_eq!(tokens[3].kind, TokenKind::Number);
    }

    #[test]
    fn test_parse_number() {
        assert_eq!(parse_number("42"), Some(42));
        assert_eq!(parse_number("0xFF"), Some(255));
        assert_eq!(parse_number("0xff"), Some(255));
        assert_eq!(parse_number("0b1010"), Some(10));
        assert_eq!(parse_number("0o77"), Some(63));
        assert_eq!(parse_number("not_a_number"), None);
    }
}
