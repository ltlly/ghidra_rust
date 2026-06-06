//! ClangLabelToken: control-flow label tokens (e.g., "LAB_001000").
//!
//! Ports Ghidra's `ghidra.app.decompiler.ClangLabelToken`.
//! Re-exports `ClangLabelTokenData` from `clang_node`.

pub use super::clang_node::ClangLabelTokenData;
use super::clang_node::{ClangTokenData, SyntaxType};
use ghidra_core::addr::Address;

/// Create a label token at the given address.
pub fn label_token(label: &str, block_address: Address) -> ClangLabelTokenData {
    ClangLabelTokenData {
        token: ClangTokenData {
            text: Some(label.to_string()),
            syntax_type: SyntaxType::Default,
            ..Default::default()
        },
        block_address,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_label_token() {
        let addr = Address::new(0x1000);
        let tok = label_token("LAB_001000", addr);
        assert_eq!(tok.token.text.as_deref(), Some("LAB_001000"));
        assert_eq!(tok.block_address, addr);
    }
}
