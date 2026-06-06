//! ClangTypeToken: type name tokens.
//!
//! Ports Ghidra's `ghidra.app.decompiler.ClangTypeToken`.
//! Re-exports `ClangTypeTokenData` from `clang_node` and provides
//! convenience constructors.

pub use super::clang_node::ClangTypeTokenData;
use super::clang_node::{ClangTokenData, SyntaxType};

/// Create a type token with the given type name.
pub fn type_token(type_name: &str) -> ClangTypeTokenData {
    ClangTypeTokenData {
        token: ClangTokenData {
            text: Some(type_name.to_string()),
            syntax_type: SyntaxType::Type,
            ..Default::default()
        },
    }
}

/// Create a type token with default (non-colored) styling.
pub fn plain_type_token(type_name: &str) -> ClangTypeTokenData {
    ClangTypeTokenData {
        token: ClangTokenData {
            text: Some(type_name.to_string()),
            syntax_type: SyntaxType::Default,
            ..Default::default()
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_type_token() {
        let tok = type_token("int");
        assert_eq!(tok.token.text.as_deref(), Some("int"));
        assert_eq!(tok.token.syntax_type, SyntaxType::Type);
    }

    #[test]
    fn test_plain_type_token() {
        let tok = plain_type_token("void");
        assert_eq!(tok.token.syntax_type, SyntaxType::Default);
    }
}
