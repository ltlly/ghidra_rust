//! ClangCaseToken: switch case label tokens.
//!
//! Ports Ghidra's `ghidra.app.decompiler.ClangCaseToken`.
//! Re-exports `ClangCaseTokenData` from `clang_node`.

pub use super::clang_node::ClangCaseTokenData;
use super::clang_node::{ClangTokenData, SyntaxType};
use ghidra_core::addr::Address;

/// Create a "case" label with a constant value.
pub fn case_token(value: i64) -> ClangCaseTokenData {
    ClangCaseTokenData {
        token: ClangTokenData {
            text: Some(format!("case {}", value)),
            syntax_type: SyntaxType::Keyword,
            ..Default::default()
        },
        op_ref: None,
        value,
        address: None,
    }
}

/// Create a "default" case label.
pub fn default_case_token() -> ClangCaseTokenData {
    ClangCaseTokenData {
        token: ClangTokenData {
            text: Some("default".to_string()),
            syntax_type: SyntaxType::Keyword,
            ..Default::default()
        },
        op_ref: None,
        value: 0,
        address: None,
    }
}

/// Create a case token with an op reference and address.
pub fn case_token_full(
    value: i64,
    text: &str,
    op_ref: u32,
    address: Address,
) -> ClangCaseTokenData {
    ClangCaseTokenData {
        token: ClangTokenData {
            text: Some(text.to_string()),
            syntax_type: SyntaxType::Keyword,
            ..Default::default()
        },
        op_ref: Some(op_ref),
        value,
        address: Some(address),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_case_token() {
        let tok = case_token(42);
        assert_eq!(tok.value, 42);
        assert_eq!(tok.token.text.as_deref(), Some("case 42"));
    }

    #[test]
    fn test_default_case_token() {
        let tok = default_case_token();
        assert_eq!(tok.token.text.as_deref(), Some("default"));
    }

    #[test]
    fn test_case_token_full() {
        let addr = Address::new(0x1000);
        let tok = case_token_full(10, "case 0xa:", 5, addr);
        assert_eq!(tok.value, 10);
        assert_eq!(tok.op_ref, Some(5));
        assert_eq!(tok.address, Some(addr));
    }
}
