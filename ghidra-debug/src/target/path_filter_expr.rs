//! PathFilterExpr - composable filter expressions for target object paths.
//!
//! Ported from Ghidra's `ghidra.trace.model.target.path.PathFilter` interface.
//! Provides a richer composable filter than the pattern-based `PathMatcher`,
//! supporting boolean algebra (AND, OR, NOT) and prefix matching.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use super::key_path::KeyPath;

/// A composable filter expression that matches against key paths in the
/// target object tree.
///
/// This is the expression-oriented counterpart to `PathMatcher` (which uses
/// simple `PathPattern` instances). `PathFilterExpr` supports full boolean
/// algebra for complex matching requirements.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PathFilterExpr {
    /// Never matches any path.
    None,
    /// Matches any path.
    Any,
    /// Matches exact key paths.
    Exact(KeyPath),
    /// Matches paths where a specific segment equals a key.
    KeyAt {
        /// The position (from root) of the segment to match.
        position: usize,
        /// The key value to match.
        key: String,
    },
    /// Union of multiple filters.
    Or(Vec<PathFilterExpr>),
    /// Intersection of multiple filters.
    And(Vec<PathFilterExpr>),
    /// Negation of a filter.
    Not(Box<PathFilterExpr>),
    /// Matches paths whose prefix matches.
    Prefix(KeyPath),
}

impl PathFilterExpr {
    /// Create a filter that never matches.
    pub fn none() -> Self {
        Self::None
    }

    /// Create a filter that matches everything.
    pub fn any() -> Self {
        Self::Any
    }

    /// Create a filter for an exact key path.
    pub fn exact(path: KeyPath) -> Self {
        Self::Exact(path)
    }

    /// Create a filter matching a specific key at a position.
    pub fn key_at(position: usize, key: impl Into<String>) -> Self {
        Self::KeyAt {
            position,
            key: key.into(),
        }
    }

    /// Create a filter matching a prefix.
    pub fn prefix(path: KeyPath) -> Self {
        Self::Prefix(path)
    }

    /// Combine this filter with another using OR.
    pub fn or(self, other: PathFilterExpr) -> Self {
        match (self, other) {
            (Self::None, r) => r,
            (l, Self::None) => l,
            (Self::Or(mut a), Self::Or(b)) => {
                a.extend(b);
                Self::Or(a)
            }
            (Self::Or(mut a), r) => {
                a.push(r);
                Self::Or(a)
            }
            (l, Self::Or(mut b)) => {
                b.insert(0, l);
                Self::Or(b)
            }
            (l, r) => Self::Or(vec![l, r]),
        }
    }

    /// Combine this filter with another using AND.
    pub fn and(self, other: PathFilterExpr) -> Self {
        match (self, other) {
            (Self::None, _) => Self::None,
            (_, Self::None) => Self::None,
            (Self::Any, r) => r,
            (l, Self::Any) => l,
            (Self::And(mut a), Self::And(b)) => {
                a.extend(b);
                Self::And(a)
            }
            (Self::And(mut a), r) => {
                a.push(r);
                Self::And(a)
            }
            (l, r) => Self::And(vec![l, r]),
        }
    }

    /// Negate this filter.
    pub fn not(self) -> Self {
        match self {
            Self::None => Self::Any,
            Self::Any => Self::None,
            Self::Not(inner) => *inner,
            other => Self::Not(Box::new(other)),
        }
    }

    /// Check if this filter matches the given path.
    pub fn matches(&self, path: &KeyPath) -> bool {
        match self {
            Self::None => false,
            Self::Any => true,
            Self::Exact(expected) => path == expected,
            Self::KeyAt { position, key } => {
                path.get(*position).map_or(false, |k| k == key.as_str())
            }
            Self::Or(filters) => filters.iter().any(|f| f.matches(path)),
            Self::And(filters) => filters.iter().all(|f| f.matches(path)),
            Self::Not(inner) => !inner.matches(path),
            Self::Prefix(prefix) => prefix.is_ancestor(path),
        }
    }

    /// Check if a successor of the given path could potentially match.
    ///
    /// If `strict` is true, the successor must be strictly deeper.
    pub fn successor_could_match(&self, path: &KeyPath, strict: bool) -> bool {
        match self {
            Self::None => false,
            Self::Any => true,
            Self::Exact(expected) => {
                // path is an ancestor of expected, or equal if not strict
                if strict {
                    path.size() < expected.size() && path.is_ancestor(expected)
                } else {
                    path.size() <= expected.size() && path.is_ancestor(expected)
                }
            }
            Self::KeyAt { position, key } => {
                if *position < path.size() {
                    path.get(*position).map_or(false, |k| k == key.as_str())
                } else {
                    true // position hasn't been reached yet
                }
            }
            Self::Or(filters) => {
                filters.iter().any(|f| f.successor_could_match(path, strict))
            }
            Self::And(filters) => {
                filters.iter().all(|f| f.successor_could_match(path, strict))
            }
            Self::Not(inner) => !inner.successor_could_match(path, strict),
            Self::Prefix(prefix) => {
                // prefix is an ancestor of expected, so path can be a prefix of prefix
                if strict {
                    path.size() < prefix.size() && path.is_ancestor(prefix)
                } else {
                    path.size() <= prefix.size() && path.is_ancestor(prefix)
                }
            }
        }
    }

    /// Check if an ancestor of the given path matches.
    pub fn ancestor_matches(&self, path: &KeyPath, strict: bool) -> bool {
        let len = if strict {
            path.size().saturating_sub(1)
        } else {
            path.size()
        };
        for i in 0..=len {
            if let Some(keys) = path.keys().get(..i) {
                let prefix = KeyPath::new(keys.to_vec());
                if self.matches(&prefix) {
                    return true;
                }
            }
        }
        false
    }

    /// Get the set of possible next keys that could lead to a match.
    pub fn get_next_keys(&self, path: &KeyPath) -> BTreeSet<String> {
        match self {
            Self::Exact(expected) => {
                if expected.size() > path.size() && path.is_ancestor(expected) {
                    let mut set = BTreeSet::new();
                    if let Some(key) = expected.get(path.size()) {
                        set.insert(key.to_string());
                    }
                    set
                } else {
                    BTreeSet::new()
                }
            }
            Self::Or(filters) => {
                let mut result = BTreeSet::new();
                for f in filters {
                    result.extend(f.get_next_keys(path));
                }
                result
            }
            Self::Any => BTreeSet::new(),
            _ => BTreeSet::new(),
        }
    }

    /// Get the set of possible next names that could lead to a match.
    pub fn get_next_names(&self, path: &KeyPath) -> BTreeSet<String> {
        self.get_next_keys(path)
    }
}

impl Default for PathFilterExpr {
    fn default() -> Self {
        Self::None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_path(segments: &[&str]) -> KeyPath {
        KeyPath::new(segments.iter().map(|s| s.to_string()).collect())
    }

    #[test]
    fn test_none_filter() {
        let filter = PathFilterExpr::none();
        let path = make_path(&["a", "b"]);
        assert!(!filter.matches(&path));
    }

    #[test]
    fn test_any_filter() {
        let filter = PathFilterExpr::any();
        let path = make_path(&["a", "b"]);
        assert!(filter.matches(&path));
    }

    #[test]
    fn test_exact_filter() {
        let filter = PathFilterExpr::exact(make_path(&["a", "b"]));
        assert!(filter.matches(&make_path(&["a", "b"])));
        assert!(!filter.matches(&make_path(&["a", "c"])));
        assert!(!filter.matches(&make_path(&["a"])));
    }

    #[test]
    fn test_key_at_filter() {
        let filter = PathFilterExpr::key_at(1, "b");
        assert!(filter.matches(&make_path(&["a", "b"])));
        assert!(filter.matches(&make_path(&["x", "b"])));
        assert!(!filter.matches(&make_path(&["a", "c"])));
        assert!(!filter.matches(&make_path(&["a"])));
    }

    #[test]
    fn test_or_filter() {
        let filter = PathFilterExpr::key_at(0, "a").or(PathFilterExpr::key_at(0, "b"));
        assert!(filter.matches(&make_path(&["a"])));
        assert!(filter.matches(&make_path(&["b"])));
        assert!(!filter.matches(&make_path(&["c"])));
    }

    #[test]
    fn test_and_filter() {
        let filter = PathFilterExpr::key_at(0, "a").and(PathFilterExpr::key_at(1, "b"));
        assert!(filter.matches(&make_path(&["a", "b"])));
        assert!(!filter.matches(&make_path(&["a", "c"])));
        assert!(!filter.matches(&make_path(&["x", "b"])));
    }

    #[test]
    fn test_not_filter() {
        let filter = PathFilterExpr::key_at(0, "a").not();
        assert!(!filter.matches(&make_path(&["a", "b"])));
        assert!(filter.matches(&make_path(&["c", "b"])));
    }

    #[test]
    fn test_prefix_filter() {
        let filter = PathFilterExpr::prefix(make_path(&["Processes"]));
        assert!(filter.matches(&make_path(&["Processes"])));
        assert!(filter.matches(&make_path(&["Processes", "Threads"])));
        assert!(!filter.matches(&make_path(&["Environment"])));
    }

    #[test]
    fn test_successor_could_match() {
        let filter = PathFilterExpr::exact(make_path(&["a", "b", "c"]));
        let path = make_path(&["a", "b"]);
        assert!(filter.successor_could_match(&path, true));

        let path_full = make_path(&["a", "b", "c"]);
        assert!(!filter.successor_could_match(&path_full, true));
        assert!(filter.successor_could_match(&path_full, false));
    }

    #[test]
    fn test_get_next_keys() {
        let filter = PathFilterExpr::exact(make_path(&["a", "b", "c"]));
        let path = make_path(&["a"]);
        let next = filter.get_next_keys(&path);
        assert!(next.contains("b"));
    }

    #[test]
    fn test_or_flattening() {
        let filter = PathFilterExpr::key_at(0, "a")
            .or(PathFilterExpr::key_at(0, "b"))
            .or(PathFilterExpr::key_at(0, "c"));
        assert!(filter.matches(&make_path(&["a"])));
        assert!(filter.matches(&make_path(&["b"])));
        assert!(filter.matches(&make_path(&["c"])));
        assert!(!filter.matches(&make_path(&["d"])));
    }

    #[test]
    fn test_serialization() {
        let filter = PathFilterExpr::prefix(make_path(&["Processes"]));
        let json = serde_json::to_string(&filter).unwrap();
        let deserialized: PathFilterExpr = serde_json::from_str(&json).unwrap();
        assert!(deserialized.matches(&make_path(&["Processes", "Threads"])));
    }
}
