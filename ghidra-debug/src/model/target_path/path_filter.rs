//! PathFilter trait ported from ghidra.trace.model.target.path.PathFilter.
//!
//! Provides the trait interface for matching, filtering, and querying paths.

use std::collections::HashSet;

use super::{KeyPath, PathMatcher, PathPattern};

/// Alignment for wildcard substitution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Align {
    /// Align from the left (first wildcards substituted first).
    Left,
    /// Align from the right (last wildcards substituted first).
    Right,
}

/// A filter for matching paths against patterns.
///
/// Ported from Java's PathFilter interface. Supports matching entire paths,
/// checking successor/ancestor relationships, and collecting next/prev keys.
pub trait PathFilter: std::fmt::Debug {
    /// Combine this filter with another using OR logic.
    fn or(&self, that: &dyn PathFilter) -> Box<dyn PathFilter>;

    /// Check if the entire path passes.
    fn matches(&self, path: &KeyPath) -> bool;

    /// Check if the given path could have a matching successor.
    fn successor_could_match(&self, path: &KeyPath, strict: bool) -> bool;

    /// Check if the given path has an ancestor that matches.
    fn ancestor_matches(&self, path: &KeyPath, strict: bool) -> bool;

    /// Check if an ancestor could match starting from the right.
    fn ancestor_could_match_right(&self, path: &KeyPath, strict: bool) -> bool;

    /// Get the possible next keys after the given path.
    fn get_next_keys(&self, path: &KeyPath) -> HashSet<String>;

    /// Get the possible next name keys after the given path.
    fn get_next_names(&self, path: &KeyPath) -> HashSet<String>;

    /// Get the possible next index keys after the given path.
    fn get_next_indices(&self, path: &KeyPath) -> HashSet<String>;

    /// Get the possible previous keys before the given path.
    fn get_prev_keys(&self, path: &KeyPath) -> HashSet<String>;

    /// Get the singleton path if this filter matches exactly one path.
    fn get_singleton_path(&self) -> Option<KeyPath>;

    /// Get the singleton pattern if this filter is a single pattern.
    fn get_singleton_pattern(&self) -> Option<PathPattern>;

    /// Get the set of patterns contained in this filter.
    fn get_patterns(&self) -> HashSet<PathPattern>;

    /// Remove count elements from the right.
    fn remove_right(&self, count: usize) -> Box<dyn PathFilter>;

    /// Substitute wildcards from left to right for the given list of keys.
    fn apply_keys(&self, align: &Align, keys: &[String]) -> Box<dyn PathFilter>;

    /// Test if any patterns are contained here.
    fn is_none(&self) -> bool;
}

/// Check if a key matches a pattern key. Supports wildcards:
/// - Exact match
/// - Empty string ("") matches any name key
/// - "[]" matches any index key
pub fn key_matches(pattern: &str, key: &str) -> bool {
    if pattern == key {
        return true;
    }
    if pattern == "[]" {
        return KeyPath::is_index(key);
    }
    if pattern.is_empty() {
        return KeyPath::is_name(key);
    }
    false
}

/// Check if any pattern in the set matches the key.
pub fn any_matches(patterns: &HashSet<String>, key: &str) -> bool {
    patterns.iter().any(|p| key_matches(p, key))
}

/// Parse a string pattern into a PathPattern.
pub fn parse(pattern: &str) -> PathPattern {
    PathPattern::new(KeyPath::parse(pattern))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_matches_exact() {
        assert!(key_matches("Threads", "Threads"));
        assert!(!key_matches("Threads", "Processes"));
    }

    #[test]
    fn test_key_matches_wildcard_name() {
        assert!(key_matches("", "Threads"));
        assert!(!key_matches("", "[0]"));
    }

    #[test]
    fn test_key_matches_wildcard_index() {
        assert!(key_matches("[]", "[0]"));
        assert!(key_matches("[]", "[42]"));
        assert!(!key_matches("[]", "Threads"));
    }
}
