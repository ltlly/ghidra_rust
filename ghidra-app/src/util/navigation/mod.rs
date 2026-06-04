//! GoTo / address navigation (ported from `ghidra.app.util.navigation`).

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Error during GoTo navigation.
#[derive(Debug, Error)]
pub enum GoToError {
    #[error("address not found: {0}")]
    AddressNotFound(String),
    #[error("symbol not found: {0}")]
    SymbolNotFound(String),
    #[error("invalid address expression: {0}")]
    InvalidExpression(String),
}

/// A GoTo query that can be either an address or a symbol name.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GoToQuery {
    /// Navigate to a specific address.
    Address(u64),
    /// Navigate to a symbol by name.
    Symbol(String),
    /// Navigate to an address expression (e.g. "main+0x10").
    Expression(String),
    /// Navigate to a label with namespace (e.g. "std::string::npos").
    NamespacedLabel(String),
}

impl GoToQuery {
    /// Parse a string into a GoTo query.
    ///
    /// Tries to parse as hex address first, then falls back to symbol.
    pub fn parse(input: &str) -> Self {
        let trimmed = input.trim();
        // Try hex address
        if let Some(hex) = trimmed.strip_prefix("0x").or_else(|| trimmed.strip_prefix("0X")) {
            if let Ok(addr) = u64::from_str_radix(hex, 16) {
                return Self::Address(addr);
            }
        }
        // Try plain decimal
        if let Ok(addr) = trimmed.parse::<u64>() {
            return Self::Address(addr);
        }
        // Namespaced label
        if trimmed.contains("::") {
            return Self::NamespacedLabel(trimmed.to_string());
        }
        // Expression (contains operator)
        if trimmed.contains('+') || trimmed.contains('-') {
            return Self::Expression(trimmed.to_string());
        }
        // Default: symbol name
        Self::Symbol(trimmed.to_string())
    }
}

/// Summary of a GoTo search result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoToResult {
    /// The resolved address.
    pub address: u64,
    /// Symbol name at the address, if any.
    pub symbol: Option<String>,
    /// Function containing the address, if any.
    pub containing_function: Option<String>,
    /// Offset from the function start, if inside a function.
    pub function_offset: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn goto_query_parse_hex() {
        match GoToQuery::parse("0xDEAD") {
            GoToQuery::Address(addr) => assert_eq!(addr, 0xDEAD),
            _ => panic!("expected address"),
        }
    }

    #[test]
    fn goto_query_parse_hex_uppercase() {
        match GoToQuery::parse("0X1234") {
            GoToQuery::Address(addr) => assert_eq!(addr, 0x1234),
            _ => panic!("expected address"),
        }
    }

    #[test]
    fn goto_query_parse_decimal() {
        match GoToQuery::parse("1024") {
            GoToQuery::Address(addr) => assert_eq!(addr, 1024),
            _ => panic!("expected address"),
        }
    }

    #[test]
    fn goto_query_parse_symbol() {
        match GoToQuery::parse("main") {
            GoToQuery::Symbol(name) => assert_eq!(name, "main"),
            _ => panic!("expected symbol"),
        }
    }

    #[test]
    fn goto_query_parse_namespaced() {
        match GoToQuery::parse("std::string::npos") {
            GoToQuery::NamespacedLabel(name) => assert_eq!(name, "std::string::npos"),
            _ => panic!("expected namespaced label"),
        }
    }

    #[test]
    fn goto_query_parse_expression() {
        match GoToQuery::parse("main+0x10") {
            GoToQuery::Expression(expr) => assert_eq!(expr, "main+0x10"),
            _ => panic!("expected expression"),
        }
    }

    #[test]
    fn goto_result() {
        let r = GoToResult {
            address: 0x401000,
            symbol: Some("main".into()),
            containing_function: Some("main".into()),
            function_offset: Some(0),
        };
        assert_eq!(r.address, 0x401000);
    }
}
