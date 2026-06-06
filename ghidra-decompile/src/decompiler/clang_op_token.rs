//! ClangOpToken: operator and keyword tokens.
//!
//! Ports Ghidra's `ghidra.app.decompiler.ClangOpToken`.
//! Re-exports `ClangOpTokenData` from `clang_node` and provides convenience constructors.

pub use super::clang_node::ClangOpTokenData;
use super::clang_node::{ClangTokenData, SyntaxType};
use ghidra_core::addr::Address;

/// Create an operator token (e.g., "+", "-", "*", "=", "if", "while").
pub fn op_token(text: &str, syntax_type: SyntaxType) -> ClangOpTokenData {
    ClangOpTokenData {
        text: Some(text.to_string()),
        syntax_type,
        op_ref: None,
        min_address: None,
    }
}

/// Create a keyword operator token (e.g., "if", "while", "return").
pub fn keyword_op(text: &str) -> ClangOpTokenData {
    op_token(text, SyntaxType::Keyword)
}

/// Create an arithmetic operator token (e.g., "+", "-", "*").
pub fn arithmetic_op(text: &str) -> ClangOpTokenData {
    op_token(text, SyntaxType::Default)
}

/// Create an operator token with a p-code op reference.
pub fn op_token_with_ref(text: &str, op_ref: u32, address: Address) -> ClangOpTokenData {
    ClangOpTokenData {
        text: Some(text.to_string()),
        syntax_type: SyntaxType::Default,
        op_ref: Some(op_ref),
        min_address: Some(address),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_op_token() {
        let tok = op_token("+", SyntaxType::Default);
        assert_eq!(tok.text.as_deref(), Some("+"));
        assert!(tok.op_ref.is_none());
    }

    #[test]
    fn test_keyword_op() {
        let tok = keyword_op("if");
        assert_eq!(tok.text.as_deref(), Some("if"));
        assert_eq!(tok.syntax_type, SyntaxType::Keyword);
    }

    #[test]
    fn test_arithmetic_op() {
        let tok = arithmetic_op("*");
        assert_eq!(tok.syntax_type, SyntaxType::Default);
    }

    #[test]
    fn test_op_token_with_ref() {
        let addr = Address::new(0x1000);
        let tok = op_token_with_ref("=", 42, addr);
        assert_eq!(tok.op_ref, Some(42));
        assert_eq!(tok.min_address, Some(addr));
    }
}
