//! ClangToken: base token type for decompiler C code markup.
//!
//! Ports Ghidra's `ghidra.app.decompiler.ClangToken`.
//! In the Rust implementation, the actual data lives in `ClangTokenData`
//! (defined in `clang_node.rs`). This module provides a convenience
//! wrapper for constructing and manipulating individual tokens.

pub use super::clang_node::{
    ClangTokenData, ClangNodeId, ClangNodeKind, SyntaxType, COMMENT_COLOR, CONST_COLOR,
    DEFAULT_COLOR, ERROR_COLOR, FIELD_COLOR, FUNCTION_COLOR, GLOBAL_COLOR, KEYWORD_COLOR,
    MAX_COLOR, PARAMETER_COLOR, SPECIAL_COLOR, TYPE_COLOR, VARIABLE_COLOR,
};

/// Convenience constructor for a `ClangTokenData` with given text and syntax type.
pub fn clang_token(text: &str, syntax_type: SyntaxType) -> ClangTokenData {
    ClangTokenData {
        text: Some(text.to_string()),
        syntax_type,
        ..Default::default()
    }
}

/// Convenience constructor for a default-color token.
pub fn clang_token_default(text: &str) -> ClangTokenData {
    clang_token(text, SyntaxType::Default)
}

/// Convenience constructor for a keyword token.
pub fn clang_keyword(text: &str) -> ClangTokenData {
    clang_token(text, SyntaxType::Keyword)
}

/// Convenience constructor for a variable token.
pub fn clang_variable(text: &str) -> ClangTokenData {
    clang_token(text, SyntaxType::Variable)
}

/// Convenience constructor for a function name token.
pub fn clang_function_name(text: &str) -> ClangTokenData {
    clang_token(text, SyntaxType::Function)
}

/// Convenience constructor for a type token.
pub fn clang_type(text: &str) -> ClangTokenData {
    clang_token(text, SyntaxType::Type)
}

/// Convenience constructor for a constant token.
pub fn clang_constant(text: &str) -> ClangTokenData {
    clang_token(text, SyntaxType::Const)
}

/// Convenience constructor for a comment token.
pub fn clang_comment(text: &str) -> ClangTokenData {
    clang_token(text, SyntaxType::Comment)
}

/// Convenience constructor for a parameter token.
pub fn clang_parameter(text: &str) -> ClangTokenData {
    clang_token(text, SyntaxType::Parameter)
}

/// Convenience constructor for a global token.
pub fn clang_global(text: &str) -> ClangTokenData {
    clang_token(text, SyntaxType::Global)
}

/// Convenience constructor for a field token.
pub fn clang_field(text: &str) -> ClangTokenData {
    clang_token(text, SyntaxType::Field)
}

/// Whether a character is a letter, digit, or underscore (for token spacing).
pub fn is_ident_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clang_token_convenience() {
        let tok = clang_token_default(";");
        assert_eq!(tok.text.as_deref(), Some(";"));
        assert_eq!(tok.syntax_type, SyntaxType::Default);
    }

    #[test]
    fn test_clang_keyword() {
        let tok = clang_keyword("if");
        assert_eq!(tok.text.as_deref(), Some("if"));
        assert_eq!(tok.syntax_type, SyntaxType::Keyword);
    }

    #[test]
    fn test_clang_variable() {
        let tok = clang_variable("x");
        assert_eq!(tok.syntax_type, SyntaxType::Variable);
    }

    #[test]
    fn test_clang_function_name() {
        let tok = clang_function_name("main");
        assert_eq!(tok.syntax_type, SyntaxType::Function);
    }

    #[test]
    fn test_clang_type() {
        let tok = clang_type("int");
        assert_eq!(tok.syntax_type, SyntaxType::Type);
    }

    #[test]
    fn test_clang_constant() {
        let tok = clang_constant("42");
        assert_eq!(tok.syntax_type, SyntaxType::Const);
    }

    #[test]
    fn test_clang_comment() {
        let tok = clang_comment("// hello");
        assert_eq!(tok.syntax_type, SyntaxType::Comment);
    }

    #[test]
    fn test_is_ident_char() {
        assert!(is_ident_char('a'));
        assert!(is_ident_char('Z'));
        assert!(is_ident_char('0'));
        assert!(is_ident_char('_'));
        assert!(!is_ident_char(' '));
        assert!(!is_ident_char('('));
        assert!(!is_ident_char('+'));
    }
}
