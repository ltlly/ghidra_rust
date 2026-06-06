//! Immutable path of keys leading from one object to another.
//!
//! Ported from KeyPath.java. Wraps a list of string keys with convenience
//! methods, sensible comparison, and better typing.

use std::cmp::Ordering;
use std::fmt;

/// An immutable path of keys leading from one object (usually the root) to another.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KeyPath {
    keys: Vec<String>,
}

impl KeyPath {
    /// The root (empty) path.
    pub const fn root() -> Self {
        Self { keys: Vec::new() }
    }

    /// Encode the given index in decimal, without brackets.
    pub fn make_index(i: i64) -> String {
        i.to_string()
    }

    /// Check if the given key is a bracketed index (e.g. "[0]").
    pub fn is_index(key: &str) -> bool {
        key.starts_with('[') && key.ends_with(']')
    }

    /// Check if the given key is a name (not bracketed).
    pub fn is_name(key: &str) -> bool {
        !Self::is_index(key)
    }

    /// Parse an index key, stripping brackets.
    pub fn parse_index(key: &str) -> &str {
        if Self::is_index(key) {
            &key[1..key.len() - 1]
        } else {
            key
        }
    }

    /// Create a KeyPath from a list of key strings.
    pub fn of(keys: &[&str]) -> Self {
        Self {
            keys: keys.iter().map(|s| s.to_string()).collect(),
        }
    }

    /// Create a KeyPath from owned strings.
    pub fn from_vec(keys: Vec<String>) -> Self {
        Self { keys }
    }

    /// Parse a path string like "Processes[0].Threads[1]" into a KeyPath.
    pub fn parse(path: &str) -> Self {
        if path.is_empty() {
            return Self::root();
        }
        let mut keys = Vec::new();
        let mut current = String::new();
        for ch in path.chars() {
            match ch {
                '[' => {
                    if !current.is_empty() {
                        keys.push(current.clone());
                        current.clear();
                    }
                    current.push('[');
                }
                ']' => {
                    current.push(']');
                    keys.push(current.clone());
                    current.clear();
                }
                '.' => {
                    if !current.is_empty() {
                        keys.push(current.clone());
                        current.clear();
                    }
                }
                _ => current.push(ch),
            }
        }
        if !current.is_empty() {
            keys.push(current);
        }
        Self { keys }
    }

    /// Number of keys in this path.
    pub fn size(&self) -> usize {
        self.keys.len()
    }

    /// Whether this is the root (empty) path.
    pub fn is_root(&self) -> bool {
        self.keys.is_empty()
    }

    /// Get the key at the given index.
    pub fn key(&self, index: usize) -> &str {
        &self.keys[index]
    }

    /// Get the last key, or None if root.
    pub fn last_key(&self) -> Option<&str> {
        self.keys.last().map(|s| s.as_str())
    }

    /// Get the parent path, removing the last key. Returns None if root.
    pub fn parent(&self) -> Option<Self> {
        if self.keys.is_empty() {
            None
        } else {
            Some(Self {
                keys: self.keys[..self.keys.len() - 1].to_vec(),
            })
        }
    }

    /// Get the parent path removing 'count' keys from the right.
    pub fn parent_n(&self, count: usize) -> Option<Self> {
        if count > self.keys.len() {
            None
        } else if count == 0 {
            Some(self.clone())
        } else {
            Some(Self {
                keys: self.keys[..self.keys.len() - count].to_vec(),
            })
        }
    }

    /// Append a key to create a new path.
    pub fn extend(&self, key: &str) -> Self {
        let mut new_keys = self.keys.clone();
        new_keys.push(key.to_string());
        Self { keys: new_keys }
    }

    /// Append an index key to create a new path.
    pub fn extend_index(&self, index: i64) -> Self {
        self.extend(&Self::make_index(index))
    }

    /// Check if this path is an ancestor of the given path.
    pub fn is_ancestor(&self, successor: &KeyPath) -> bool {
        if self.keys.len() > successor.keys.len() {
            return false;
        }
        self.keys[..] == successor.keys[..self.keys.len()]
    }

    /// Assuming this is an ancestor, compute the relative path.
    pub fn relativize(&self, successor: &KeyPath) -> Option<Self> {
        if !self.is_ancestor(successor) {
            return None;
        }
        Some(Self {
            keys: successor.keys[self.keys.len()..].to_vec(),
        })
    }

    /// Check if this path contains any wildcards (empty or [] keys).
    pub fn contains_wildcard(&self) -> bool {
        self.keys.iter().any(|k| k.is_empty() || k == "[]")
    }

    /// Get an iterator over the keys.
    pub fn iter(&self) -> impl Iterator<Item = &str> {
        self.keys.iter().map(|s| s.as_str())
    }

    /// Get the keys as a slice.
    pub fn keys(&self) -> &[String] {
        &self.keys
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

impl PartialOrd for KeyPath {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for KeyPath {
    fn cmp(&self, other: &Self) -> Ordering {
        self.keys.cmp(&other.keys)
    }
}

impl FromIterator<String> for KeyPath {
    fn from_iter<I: IntoIterator<Item = String>>(iter: I) -> Self {
        Self {
            keys: iter.into_iter().collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_root() {
        let root = KeyPath::root();
        assert!(root.is_root());
        assert_eq!(root.size(), 0);
    }

    #[test]
    fn test_of() {
        let path = KeyPath::of(&["Processes", "[0]", "Threads"]);
        assert_eq!(path.size(), 3);
        assert_eq!(path.key(0), "Processes");
        assert_eq!(path.key(1), "[0]");
        assert_eq!(path.key(2), "Threads");
    }

    #[test]
    fn test_is_index() {
        assert!(KeyPath::is_index("[0]"));
        assert!(KeyPath::is_index("[42]"));
        assert!(!KeyPath::is_index("Threads"));
    }

    #[test]
    fn test_parent() {
        let path = KeyPath::of(&["A", "B", "C"]);
        let parent = path.parent().unwrap();
        assert_eq!(parent, KeyPath::of(&["A", "B"]));
    }

    #[test]
    fn test_is_ancestor() {
        let a = KeyPath::of(&["A", "B"]);
        let b = KeyPath::of(&["A", "B", "C"]);
        assert!(a.is_ancestor(&b));
        assert!(a.is_ancestor(&a)); // self is ancestor
        assert!(!b.is_ancestor(&a));
    }

    #[test]
    fn test_extend() {
        let base = KeyPath::of(&["A"]);
        let extended = base.extend("B");
        assert_eq!(extended, KeyPath::of(&["A", "B"]));
    }

    #[test]
    fn test_display() {
        let path = KeyPath::of(&["A", "B", "C"]);
        assert_eq!(format!("{}", path), "A.B.C");
    }

    #[test]
    fn test_parse() {
        let path = KeyPath::parse("Processes[0].Threads");
        assert_eq!(path.size(), 3);
        assert_eq!(path.key(0), "Processes");
        assert_eq!(path.key(1), "[0]");
        assert_eq!(path.key(2), "Threads");
    }

    #[test]
    fn test_contains_wildcard() {
        assert!(KeyPath::of(&["Processes", ""]).contains_wildcard());
        assert!(KeyPath::of(&["Processes", "[]"]).contains_wildcard());
        assert!(!KeyPath::of(&["Processes", "[0]"]).contains_wildcard());
    }

    #[test]
    fn test_relativize() {
        let base = KeyPath::of(&["A", "B"]);
        let child = KeyPath::of(&["A", "B", "C", "D"]);
        let rel = base.relativize(&child).unwrap();
        assert_eq!(rel, KeyPath::of(&["C", "D"]));
    }
}
