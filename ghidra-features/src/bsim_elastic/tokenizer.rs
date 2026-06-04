//! LSH Tokenizer -- tokenizes LSH vectors for Elasticsearch indexing.
//!
//! Ported from `LSHTokenizer.java` in the BSimElasticPlugin extension.
//!
//! The tokenizer converts an LSH vector into a sequence of base64-encoded
//! bin-ID strings that can be indexed by Elasticsearch's LSH-based similarity
//! search.

use super::binner::{HashEntry, LshBinner};

/// An LSH tokenizer that converts an LSH vector into a stream of
/// base64-encoded bin-ID tokens.
///
/// Each call to [`next_token()`](LshTokenizer::next_token) returns the next
/// bin-ID string for the vector, or `None` when all tokens have been
/// returned.
pub struct LshTokenizer {
    /// The LSH binner that computes bin IDs.
    binner: LshBinner,
    /// Current position in the token list.
    pos: usize,
    /// Whether the tokenizer has been initialized with a vector.
    initialized: bool,
}

impl LshTokenizer {
    /// Create a new LSH tokenizer with the given `k` (bits per bin) and `L`
    /// (number of tables).
    pub fn new(k: i32, l: i32) -> Self {
        let mut binner = LshBinner::new();
        binner.set_k_and_l(k, l);
        Self {
            binner,
            pos: 0,
            initialized: false,
        }
    }

    /// Set the LSH vector to tokenize.
    ///
    /// This computes the bin IDs via the LSH binner and prepares the
    /// tokenizer to emit tokens.
    pub fn set_vector(&mut self, vec: &[HashEntry]) {
        self.binner.generate_bin_ids(vec);
        self.pos = 0;
        self.initialized = true;
    }

    /// Get the next token (bin-ID string).
    ///
    /// Returns `Some(token_string)` or `None` when all tokens have been
    /// consumed.
    pub fn next_token(&mut self) -> Option<String> {
        if !self.initialized {
            return None;
        }
        let tokens = self.binner.token_list();
        if self.pos >= tokens.len() {
            return None;
        }
        let token = &tokens[self.pos];
        self.pos += 1;
        Some(token.buffer.iter().collect())
    }

    /// Reset the tokenizer for a new vector.
    pub fn reset(&mut self) {
        self.pos = 0;
        self.initialized = false;
    }

    /// Return the total number of tokens for the current configuration.
    pub fn num_tokens(&self) -> usize {
        self.binner.token_list().len()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bsim_elastic::binner::HashEntry;

    #[test]
    fn test_tokenizer_returns_correct_count() {
        let k = 4;
        let l = 8;
        let mut tok = LshTokenizer::new(k, l);
        assert_eq!(tok.num_tokens(), l as usize);

        let vec = vec![
            HashEntry::new(100, 1.0),
            HashEntry::new(200, -0.5),
            HashEntry::new(300, 2.0),
        ];
        tok.set_vector(&vec);

        let mut count = 0;
        while let Some(_token) = tok.next_token() {
            count += 1;
        }
        assert_eq!(count, l as usize);
    }

    #[test]
    fn test_tokenizer_returns_none_when_exhausted() {
        let mut tok = LshTokenizer::new(4, 2);
        let vec = vec![HashEntry::new(10, 1.0)];
        tok.set_vector(&vec);

        assert!(tok.next_token().is_some());
        assert!(tok.next_token().is_some());
        assert!(tok.next_token().is_none());
    }

    #[test]
    fn test_tokenizer_returns_none_before_init() {
        let mut tok = LshTokenizer::new(4, 2);
        assert!(tok.next_token().is_none());
    }

    #[test]
    fn test_tokenizer_reset() {
        let mut tok = LshTokenizer::new(4, 2);
        let vec = vec![HashEntry::new(10, 1.0)];
        tok.set_vector(&vec);

        // Consume all
        tok.next_token();
        tok.next_token();
        assert!(tok.next_token().is_none());

        // Reset and re-use
        tok.reset();
        assert!(tok.next_token().is_none()); // Not initialized yet

        tok.set_vector(&vec);
        assert!(tok.next_token().is_some());
    }

    #[test]
    fn test_tokenizer_produces_valid_base64_tokens() {
        let mut tok = LshTokenizer::new(4, 4);
        let vec = vec![
            HashEntry::new(100, 1.0),
            HashEntry::new(200, 0.5),
        ];
        tok.set_vector(&vec);

        while let Some(token) = tok.next_token() {
            assert!(!token.is_empty());
            for ch in token.chars() {
                assert!(
                    ch.is_ascii_alphanumeric() || ch == '-' || ch == '_',
                    "Invalid base64-lite character: {ch}"
                );
            }
        }
    }

    #[test]
    fn test_tokenizer_deterministic() {
        let vec = vec![
            HashEntry::new(100, 1.0),
            HashEntry::new(200, -0.5),
        ];

        let mut tok1 = LshTokenizer::new(4, 4);
        tok1.set_vector(&vec);
        let tokens1: Vec<String> = std::iter::from_fn(|| tok1.next_token()).collect();

        let mut tok2 = LshTokenizer::new(4, 4);
        tok2.set_vector(&vec);
        let tokens2: Vec<String> = std::iter::from_fn(|| tok2.next_token()).collect();

        assert_eq!(tokens1, tokens2);
    }
}
