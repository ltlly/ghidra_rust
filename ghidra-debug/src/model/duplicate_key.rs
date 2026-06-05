//! DuplicateKeyException - thrown when target object values conflict.
//!
//! Ported from Ghidra's `ghidra.trace.model.target.DuplicateKeyException`.
//! This exception is raised when attempting to add a value entry that
//! would conflict with an existing entry having the same key and
//! overlapping lifespan.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::Lifespan;

/// Exception thrown when a duplicate key conflict occurs in the target tree.
///
/// This happens when two value entries for the same key on the same parent
/// object have overlapping lifespans.
#[derive(Debug, Clone, Error, Serialize, Deserialize)]
#[error("duplicate key '{key}' on parent {parent_key}: lifespan {existing_lifespan} conflicts with {new_lifespan}")]
pub struct DuplicateKeyException {
    /// The conflicting key.
    pub key: String,
    /// The parent object's key.
    pub parent_key: i64,
    /// The lifespan of the existing entry.
    pub existing_lifespan: Lifespan,
    /// The lifespan of the new entry being added.
    pub new_lifespan: Lifespan,
}

impl DuplicateKeyException {
    /// Create a new DuplicateKeyException.
    pub fn new(
        key: impl Into<String>,
        parent_key: i64,
        existing_lifespan: Lifespan,
        new_lifespan: Lifespan,
    ) -> Self {
        Self {
            key: key.into(),
            parent_key,
            existing_lifespan,
            new_lifespan,
        }
    }

    /// Get a human-readable description of the conflict.
    pub fn description(&self) -> String {
        format!(
            "Key '{}' on parent {} already exists with lifespan [{}, {}]; \
             cannot add with lifespan [{}, {}]",
            self.key,
            self.parent_key,
            self.existing_lifespan.lmin(),
            self.existing_lifespan.lmax(),
            self.new_lifespan.lmin(),
            self.new_lifespan.lmax(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_duplicate_key_exception() {
        let e = DuplicateKeyException::new(
            "Threads",
            1,
            Lifespan::span(0, 10),
            Lifespan::span(5, 20),
        );
        assert_eq!(e.key, "Threads");
        assert_eq!(e.parent_key, 1);
        assert_eq!(e.existing_lifespan, Lifespan::span(0, 10));
        assert_eq!(e.new_lifespan, Lifespan::span(5, 20));
    }

    #[test]
    fn test_duplicate_key_description() {
        let e = DuplicateKeyException::new(
            "_display",
            42,
            Lifespan::span(0, 100),
            Lifespan::span(50, 200),
        );
        let desc = e.description();
        assert!(desc.contains("_display"));
        assert!(desc.contains("42"));
        assert!(desc.contains("0"));
        assert!(desc.contains("100"));
        assert!(desc.contains("50"));
        assert!(desc.contains("200"));
    }

    #[test]
    fn test_duplicate_key_display() {
        let e = DuplicateKeyException::new("x", 1, Lifespan::ALL, Lifespan::ALL);
        let display = format!("{}", e);
        assert!(display.contains("duplicate key"));
        assert!(display.contains("x"));
    }

    #[test]
    fn test_duplicate_key_serde() {
        let e = DuplicateKeyException::new("key", 1, Lifespan::span(0, 5), Lifespan::span(3, 10));
        let json = serde_json::to_string(&e).unwrap();
        let back: DuplicateKeyException = serde_json::from_str(&json).unwrap();
        assert_eq!(back.key, "key");
    }
}
