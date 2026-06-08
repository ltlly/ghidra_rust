//! Token pairing for decompiler code comparison.
//!
//! Ported from Ghidra's `TokenPair` Java record.
//!
//! A [`TokenPair`] holds a matched pair of tokens -- one from the left
//! (source) function and one from the right (destination) function --
//! that the Pinning algorithm has identified as structurally equivalent.

use crate::codecompare::graphanalysis::DecompilerToken;

/// A matched pair of decompiler tokens from two different functions.
///
/// Ported from Ghidra's `TokenPair` Java record in the
/// `ghidra.features.codecompare.decompile` package.
///
/// When the Pinning algorithm matches tokens across two functions,
/// the resulting pair is stored as a `TokenPair`. This is used by
/// actions that operate on matched tokens (e.g., applying a variable
/// name from one function to the other).
#[derive(Debug, Clone)]
pub struct TokenPair {
    /// The token from the left (source) function.
    left_token: DecompilerToken,
    /// The token from the right (destination) function.
    right_token: DecompilerToken,
}

impl TokenPair {
    /// Create a new token pair.
    pub fn new(left_token: DecompilerToken, right_token: DecompilerToken) -> Self {
        Self {
            left_token,
            right_token,
        }
    }

    /// Get the left (source) token.
    pub fn left_token(&self) -> &DecompilerToken {
        &self.left_token
    }

    /// Get the right (destination) token.
    pub fn right_token(&self) -> &DecompilerToken {
        &self.right_token
    }

    /// Check if both tokens have the same kind.
    pub fn has_matching_kind(&self) -> bool {
        self.left_token.kind == self.right_token.kind
    }

    /// Get the text of both tokens as a pair.
    pub fn text_pair(&self) -> (&str, &str) {
        (&self.left_token.text, &self.right_token.text)
    }

    /// Check if the text of both tokens is identical.
    pub fn has_same_text(&self) -> bool {
        self.left_token.text == self.right_token.text
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codecompare::graphanalysis::{Side, TokenKind};

    fn make_token(text: &str, kind: TokenKind, side: Side) -> DecompilerToken {
        DecompilerToken {
            text: text.to_string(),
            kind,
            address: 0x1000,
            side,
        }
    }

    #[test]
    fn test_token_pair_creation() {
        let left = make_token("x", TokenKind::Variable, Side::Left);
        let right = make_token("y", TokenKind::Variable, Side::Right);
        let pair = TokenPair::new(left, right);

        assert_eq!(pair.left_token().text, "x");
        assert_eq!(pair.right_token().text, "y");
    }

    #[test]
    fn test_matching_kind() {
        let left = make_token("x", TokenKind::Variable, Side::Left);
        let right = make_token("y", TokenKind::Variable, Side::Right);
        let pair = TokenPair::new(left, right);
        assert!(pair.has_matching_kind());

        let left = make_token("x", TokenKind::Variable, Side::Left);
        let right = make_token("5", TokenKind::Constant, Side::Right);
        let pair = TokenPair::new(left, right);
        assert!(!pair.has_matching_kind());
    }

    #[test]
    fn test_text_pair() {
        let left = make_token("hello", TokenKind::Other, Side::Left);
        let right = make_token("world", TokenKind::Other, Side::Right);
        let pair = TokenPair::new(left, right);
        assert_eq!(pair.text_pair(), ("hello", "world"));
    }

    #[test]
    fn test_same_text() {
        let left = make_token("x", TokenKind::Variable, Side::Left);
        let right = make_token("x", TokenKind::Variable, Side::Right);
        let pair = TokenPair::new(left, right);
        assert!(pair.has_same_text());

        let left = make_token("x", TokenKind::Variable, Side::Left);
        let right = make_token("y", TokenKind::Variable, Side::Right);
        let pair = TokenPair::new(left, right);
        assert!(!pair.has_same_text());
    }

    #[test]
    fn test_token_pair_clone() {
        let left = make_token("a", TokenKind::Variable, Side::Left);
        let right = make_token("b", TokenKind::Variable, Side::Right);
        let pair = TokenPair::new(left, right);
        let cloned = pair.clone();
        assert_eq!(cloned.left_token().text, "a");
        assert_eq!(cloned.right_token().text, "b");
    }
}
