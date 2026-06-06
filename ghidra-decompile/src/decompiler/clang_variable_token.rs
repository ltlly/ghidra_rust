//! ClangVariableToken: variable reference tokens.
//!
//! Ports Ghidra's `ghidra.app.decompiler.ClangVariableToken`.
//! Re-exports `ClangVariableTokenData` from `clang_node` and provides
//! convenience constructors.

pub use super::clang_node::ClangVariableTokenData;
use super::clang_node::{ClangTokenData, SyntaxType};
use ghidra_core::addr::Address;

/// Create a variable token with the given name.
pub fn variable_token(name: &str) -> ClangVariableTokenData {
    ClangVariableTokenData {
        token: ClangTokenData {
            text: Some(name.to_string()),
            syntax_type: SyntaxType::Variable,
            ..Default::default()
        },
        op_ref: None,
        var_ref: None,
        address: None,
    }
}

/// Create a parameter token with the given name.
pub fn parameter_token(name: &str) -> ClangVariableTokenData {
    ClangVariableTokenData {
        token: ClangTokenData {
            text: Some(name.to_string()),
            syntax_type: SyntaxType::Parameter,
            ..Default::default()
        },
        op_ref: None,
        var_ref: None,
        address: None,
    }
}

/// Create a global variable token with the given name.
pub fn global_token(name: &str) -> ClangVariableTokenData {
    ClangVariableTokenData {
        token: ClangTokenData {
            text: Some(name.to_string()),
            syntax_type: SyntaxType::Global,
            ..Default::default()
        },
        op_ref: None,
        var_ref: None,
        address: None,
    }
}

/// Create a variable token with p-code references.
pub fn variable_token_with_refs(
    name: &str,
    op_ref: u32,
    var_ref: u32,
    address: Address,
) -> ClangVariableTokenData {
    ClangVariableTokenData {
        token: ClangTokenData {
            text: Some(name.to_string()),
            syntax_type: SyntaxType::Variable,
            ..Default::default()
        },
        op_ref: Some(op_ref),
        var_ref: Some(var_ref),
        address: Some(address),
    }
}

/// Whether this variable token is a variable reference.
///
/// In Ghidra Java, this is `isVariableRef()` which returns true when the
/// token is inside a `ClangVariableDecl`.
pub fn is_variable_ref(tok: &ClangVariableTokenData) -> bool {
    tok.var_ref.is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_variable_token() {
        let tok = variable_token("x");
        assert_eq!(tok.token.text.as_deref(), Some("x"));
        assert_eq!(tok.token.syntax_type, SyntaxType::Variable);
    }

    #[test]
    fn test_parameter_token() {
        let tok = parameter_token("argc");
        assert_eq!(tok.token.syntax_type, SyntaxType::Parameter);
    }

    #[test]
    fn test_global_token() {
        let tok = global_token("global_var");
        assert_eq!(tok.token.syntax_type, SyntaxType::Global);
    }

    #[test]
    fn test_variable_token_with_refs() {
        let addr = Address::new(0x2000);
        let tok = variable_token_with_refs("y", 10, 20, addr);
        assert_eq!(tok.op_ref, Some(10));
        assert_eq!(tok.var_ref, Some(20));
        assert_eq!(tok.address, Some(addr));
    }

    #[test]
    fn test_is_variable_ref() {
        let tok = variable_token("x");
        assert!(!is_variable_ref(&tok));
        let tok2 = variable_token_with_refs("y", 1, 2, Address::new(0x1000));
        assert!(is_variable_ref(&tok2));
    }
}
