//! Search utilities for program analysis.
//!
//! Ported from `ghidra.util.search`.
//!
//! Re-exports the byte trie (Aho-Corasick) search data structure
//! and provides additional search helper utilities.

/// Byte-based trie with Aho-Corasick multi-pattern search.
///
/// This is re-exported from the [`crate::trie`] module for convenience.
pub use crate::trie::{ByteTrie, CaseInsensitiveByteTrie, SearchResult};

// ---------------------------------------------------------------------------
// UserSearchUtils
// ---------------------------------------------------------------------------

/// Utility functions for converting user-entered search text to regex patterns.
pub struct UserSearchUtils;

impl UserSearchUtils {
    /// Convert a user-entered literal search string into a regex pattern.
    ///
    /// Special regex characters in the input are escaped. If `include_wildcards`
    /// is true, `*` is converted to `.*` and `?` to `.`.
    pub fn convert_user_input_to_regex(input: &str, include_wildcards: bool) -> String {
        if include_wildcards {
            let mut result = String::new();
            for ch in input.chars() {
                match ch {
                    '*' => result.push_str(".*"),
                    '?' => result.push('.'),
                    c if Self::is_regex_special(c) => {
                        result.push('\\');
                        result.push(c);
                    }
                    c => result.push(c),
                }
            }
            result
        } else {
            regex::escape(input)
        }
    }

    fn is_regex_special(c: char) -> bool {
        matches!(
            c,
            '\\' | '.' | '^'
                | '$'
                | '|'
                | '?'
                | '*'
                | '+'
                | '('
                | ')'
                | '['
                | ']'
                | '{'
                | '}'
        )
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_convert_literal() {
        let pattern = UserSearchUtils::convert_user_input_to_regex("hello.world", false);
        assert_eq!(pattern, r"hello\.world");
    }

    #[test]
    fn test_convert_with_wildcards() {
        let pattern = UserSearchUtils::convert_user_input_to_regex("test*file?", true);
        assert_eq!(pattern, "test.*file.");
    }

    #[test]
    fn test_convert_special_chars() {
        let pattern = UserSearchUtils::convert_user_input_to_regex("a+b[c]", false);
        assert_eq!(pattern, r"a\+b\[c\]");
    }

    #[test]
    fn test_convert_empty() {
        let pattern = UserSearchUtils::convert_user_input_to_regex("", false);
        assert_eq!(pattern, "");
    }

    #[test]
    fn test_reexport_byte_trie() {
        let mut trie: ByteTrie<i32> = ByteTrie::new();
        trie.add(b"test", 42);
        assert_eq!(trie.size(), 1);
    }
}
