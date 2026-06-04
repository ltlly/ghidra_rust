//! KeyPath - an immutable path of keys leading from a root object to another.
//!
//! Ported from Ghidra's `KeyPath` class. Wraps a sequence of string keys
//! with bracketed-index support and sensible comparison.

use serde::{Deserialize, Serialize};
use std::cmp;
use std::fmt;

/// An immutable path of keys leading from one object to another.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct KeyPath {
    keys: Vec<String>,
}

impl KeyPath {
    /// The root (empty) path.
    pub const ROOT: KeyPath = KeyPath { keys: Vec::new() };

    // ── constructors ──────────────────────────────────────────────

    /// Create a path from a vector of keys.
    pub fn new(keys: Vec<String>) -> Self {
        Self { keys }
    }

    /// Create a path from string slices.
    pub fn of(keys: &[&str]) -> Self {
        Self {
            keys: keys.iter().map(|s| s.to_string()).collect(),
        }
    }

    /// Create a path from owned strings.
    pub fn of_owned(keys: Vec<String>) -> Self {
        Self { keys }
    }

    /// Parse a dot-separated path string.
    ///
    /// Supports bracketed indices, e.g. `"Process.Thread[3].name"`.
    pub fn parse(path: &str) -> Self {
        if path.is_empty() {
            return Self::ROOT;
        }
        let mut result = Vec::new();
        let mut current = String::new();
        let mut chars = path.chars().peekable();

        while let Some(c) = chars.next() {
            match c {
                '.' => {
                    if !current.is_empty() {
                        result.push(current.clone());
                        current.clear();
                    }
                }
                '[' => {
                    // Collect until ']'
                    let mut index = String::new();
                    for inner in chars.by_ref() {
                        if inner == ']' {
                            break;
                        }
                        index.push(inner);
                    }
                    if !current.is_empty() {
                        result.push(current.clone());
                        current.clear();
                    }
                    result.push(index);
                }
                _ => current.push(c),
            }
        }
        if !current.is_empty() {
            result.push(current);
        }
        Self { keys: result }
    }

    // ── accessors ─────────────────────────────────────────────────

    /// Number of keys in this path.
    pub fn size(&self) -> usize {
        self.keys.len()
    }

    /// Whether this is the root (empty) path.
    pub fn is_root(&self) -> bool {
        self.keys.is_empty()
    }

    /// Get a key by index.
    pub fn get(&self, index: usize) -> Option<&str> {
        self.keys.get(index).map(|s| s.as_str())
    }

    /// Get the last key, or None for root.
    pub fn last(&self) -> Option<&str> {
        self.keys.last().map(|s| s.as_str())
    }

    /// Whether a key is a bracketed index (e.g., "42" or "[42]").
    pub fn is_index(key: &str) -> bool {
        key.parse::<i64>().is_ok()
    }

    /// Encode an index without brackets.
    pub fn make_index(i: i64) -> String {
        i.to_string()
    }

    /// Get the parent path (everything except the last key).
    pub fn parent(&self) -> KeyPath {
        if self.keys.is_empty() {
            return Self::ROOT;
        }
        Self {
            keys: self.keys[..self.keys.len() - 1].to_vec(),
        }
    }

    /// Append a key to this path.
    pub fn extend(&self, key: &str) -> KeyPath {
        let mut new_keys = self.keys.clone();
        new_keys.push(key.to_string());
        Self { keys: new_keys }
    }

    /// Check if this path is an ancestor of the given path.
    ///
    /// A path is considered an ancestor of itself.
    pub fn is_ancestor(&self, successor: &KeyPath) -> bool {
        if self.keys.len() > successor.keys.len() {
            return false;
        }
        self.keys[..] == successor.keys[..self.keys.len()]
    }

    /// Assuming this is an ancestor, compute the relative path from here to successor.
    pub fn relativize(&self, successor: &KeyPath) -> KeyPath {
        assert!(
            self.is_ancestor(successor),
            "this is not an ancestor of successor"
        );
        Self {
            keys: successor.keys[self.keys.len()..].to_vec(),
        }
    }

    /// Iterator over keys.
    pub fn iter(&self) -> impl Iterator<Item = &str> {
        self.keys.iter().map(|s| s.as_str())
    }
}

impl fmt::Display for KeyPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, key) in self.keys.iter().enumerate() {
            if i > 0 {
                write!(f, ".")?;
            }
            write!(f, "{}", key)?;
        }
        Ok(())
    }
}

impl<'a> IntoIterator for &'a KeyPath {
    type Item = &'a str;
    type IntoIter = std::iter::Map<std::slice::Iter<'a, String>, fn(&'a String) -> &'a str>;

    fn into_iter(self) -> Self::IntoIter {
        self.keys.iter().map(|s| s.as_str())
    }
}

impl PartialOrd for KeyPath {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for KeyPath {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        // Keyed comparator: leftmost keys first, prefix is "less"
        let min_len = self.keys.len().min(other.keys.len());
        for i in 0..min_len {
            let a_is_idx = Self::is_index(&self.keys[i]);
            let b_is_idx = Self::is_index(&other.keys[i]);
            if a_is_idx && b_is_idx {
                let cmp = self.keys[i]
                    .parse::<i64>()
                    .unwrap()
                    .cmp(&other.keys[i].parse::<i64>().unwrap());
                if cmp != cmp::Ordering::Equal {
                    return cmp;
                }
            } else if a_is_idx {
                return cmp::Ordering::Less;
            } else if b_is_idx {
                return cmp::Ordering::Greater;
            } else {
                let cmp = self.keys[i].cmp(&other.keys[i]);
                if cmp != cmp::Ordering::Equal {
                    return cmp;
                }
            }
        }
        self.keys.len().cmp(&other.keys.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_root() {
        let root = KeyPath::ROOT;
        assert!(root.is_root());
        assert_eq!(root.size(), 0);
        assert_eq!(root.to_string(), "");
    }

    #[test]
    fn test_parse() {
        let p = KeyPath::parse("Process.Thread[3].name");
        assert_eq!(p.size(), 4);
        assert_eq!(p.get(0), Some("Process"));
        assert_eq!(p.get(1), Some("Thread"));
        assert_eq!(p.get(2), Some("3"));
        assert_eq!(p.get(3), Some("name"));
    }

    #[test]
    fn test_parent() {
        let p = KeyPath::parse("a.b.c");
        let parent = p.parent();
        assert_eq!(parent.to_string(), "a.b");
        assert_eq!(parent.parent().to_string(), "a");
    }

    #[test]
    fn test_extend() {
        let p = KeyPath::of(&["a", "b"]);
        let extended = p.extend("c");
        assert_eq!(extended.to_string(), "a.b.c");
    }

    #[test]
    fn test_is_ancestor() {
        let a = KeyPath::of(&["a", "b"]);
        let b = KeyPath::of(&["a", "b", "c", "d"]);
        assert!(a.is_ancestor(&b));
        assert!(a.is_ancestor(&a));
        assert!(!b.is_ancestor(&a));
    }

    #[test]
    fn test_relativize() {
        let a = KeyPath::of(&["a"]);
        let b = KeyPath::of(&["a", "b", "c"]);
        let rel = a.relativize(&b);
        assert_eq!(rel.to_string(), "b.c");
    }

    #[test]
    fn test_ord() {
        let a = KeyPath::of(&["a", "1"]);
        let b = KeyPath::of(&["a", "2"]);
        assert!(a < b);

        let c = KeyPath::of(&["a", "b"]);
        let d = KeyPath::of(&["a", "b", "c"]);
        assert!(c < d);
    }

    #[test]
    fn test_is_index() {
        assert!(KeyPath::is_index("42"));
        assert!(KeyPath::is_index("0"));
        assert!(!KeyPath::is_index("hello"));
    }
}
