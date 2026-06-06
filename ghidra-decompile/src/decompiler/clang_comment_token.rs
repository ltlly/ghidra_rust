//! ClangCommentToken: comment tokens.
//!
//! Ports Ghidra's `ghidra.app.decompiler.ClangCommentToken`.
//! Re-exports `ClangCommentTokenData` from `clang_node`.

pub use super::clang_node::ClangCommentTokenData;
use super::clang_node::{ClangTokenData, SyntaxType};
use ghidra_core::addr::Address;

/// Create a comment token.
pub fn comment_token(text: &str) -> ClangCommentTokenData {
    ClangCommentTokenData {
        token: ClangTokenData {
            text: Some(text.to_string()),
            syntax_type: SyntaxType::Comment,
            ..Default::default()
        },
        source_address: None,
    }
}

/// Create a comment token with a source address.
pub fn comment_token_with_address(text: &str, address: Address) -> ClangCommentTokenData {
    ClangCommentTokenData {
        token: ClangTokenData {
            text: Some(text.to_string()),
            syntax_type: SyntaxType::Comment,
            ..Default::default()
        },
        source_address: Some(address),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_comment_token() {
        let tok = comment_token("// a comment");
        assert_eq!(tok.token.text.as_deref(), Some("// a comment"));
        assert_eq!(tok.token.syntax_type, SyntaxType::Comment);
    }

    #[test]
    fn test_comment_token_with_address() {
        let addr = Address::new(0x1000);
        let tok = comment_token_with_address("/* block comment */", addr);
        assert_eq!(tok.source_address, Some(addr));
    }
}
