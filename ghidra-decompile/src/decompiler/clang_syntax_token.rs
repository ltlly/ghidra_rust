//! ClangSyntaxToken: syntax tokens like parens, braces, semicolons.
//!
//! Ports Ghidra's `ghidra.app.decompiler.ClangSyntaxToken`.
//! Re-exports `ClangSyntaxTokenData` from `clang_node` and provides
//! convenience constructors.

pub use super::clang_node::ClangSyntaxTokenData;
use super::clang_node::{ClangTokenData, SyntaxType};

/// Create a syntax token (e.g., "(", ")", "{", "}", ";", ",").
pub fn syntax_token(text: &str) -> ClangSyntaxTokenData {
    ClangSyntaxTokenData {
        token: ClangTokenData {
            text: Some(text.to_string()),
            syntax_type: SyntaxType::Default,
            ..Default::default()
        },
        open: -1,
        close: -1,
        is_variable_ref: false,
    }
}

/// Create a paired opening syntax token with a match id.
pub fn opening_token(text: &str, pair_id: i32) -> ClangSyntaxTokenData {
    ClangSyntaxTokenData {
        token: ClangTokenData {
            text: Some(text.to_string()),
            syntax_type: SyntaxType::Default,
            ..Default::default()
        },
        open: pair_id,
        close: -1,
        is_variable_ref: false,
    }
}

/// Create a paired closing syntax token with a match id.
pub fn closing_token(text: &str, pair_id: i32) -> ClangSyntaxTokenData {
    ClangSyntaxTokenData {
        token: ClangTokenData {
            text: Some(text.to_string()),
            syntax_type: SyntaxType::Default,
            ..Default::default()
        },
        open: -1,
        close: pair_id,
        is_variable_ref: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_syntax_token() {
        let tok = syntax_token(";");
        assert_eq!(tok.token.text.as_deref(), Some(";"));
        assert_eq!(tok.open, -1);
        assert_eq!(tok.close, -1);
    }

    #[test]
    fn test_opening_token() {
        let tok = opening_token("(", 1);
        assert_eq!(tok.open, 1);
        assert_eq!(tok.close, -1);
    }

    #[test]
    fn test_closing_token() {
        let tok = closing_token(")", 1);
        assert_eq!(tok.open, -1);
        assert_eq!(tok.close, 1);
    }
}
