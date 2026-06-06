//! ClangFuncNameToken: function name tokens in decompiled code.
//!
//! Ports Ghidra's `ghidra.app.decompiler.ClangFuncNameToken`.
//! Re-exports `ClangFuncNameTokenData` from `clang_node`.

pub use super::clang_node::ClangFuncNameTokenData;
use super::clang_node::{ClangTokenData, SyntaxType};
use ghidra_core::addr::Address;

/// Create a function name token.
pub fn func_name_token(name: &str) -> ClangFuncNameTokenData {
    ClangFuncNameTokenData {
        token: ClangTokenData {
            text: Some(name.to_string()),
            syntax_type: SyntaxType::Function,
            ..Default::default()
        },
        high_function_ref: None,
        op_ref: None,
        min_address: None,
    }
}

/// Create a function name token with full references.
pub fn func_name_token_full(
    name: &str,
    high_function_ref: u32,
    op_ref: u32,
    address: Address,
) -> ClangFuncNameTokenData {
    ClangFuncNameTokenData {
        token: ClangTokenData {
            text: Some(name.to_string()),
            syntax_type: SyntaxType::Function,
            ..Default::default()
        },
        high_function_ref: Some(high_function_ref),
        op_ref: Some(op_ref),
        min_address: Some(address),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_func_name_token() {
        let tok = func_name_token("main");
        assert_eq!(tok.token.text.as_deref(), Some("main"));
        assert_eq!(tok.token.syntax_type, SyntaxType::Function);
    }

    #[test]
    fn test_func_name_token_full() {
        let addr = Address::new(0x2000);
        let tok = func_name_token_full("printf", 10, 20, addr);
        assert_eq!(tok.high_function_ref, Some(10));
        assert_eq!(tok.op_ref, Some(20));
        assert_eq!(tok.min_address, Some(addr));
    }
}
