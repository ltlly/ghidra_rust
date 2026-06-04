// Port of help.PathKey

use std::fmt;
use std::path::Path;

/// A normalized path key for cross-filesystem map lookups.
///
/// Replaces backslashes with forward slashes to ensure consistent comparison
/// across platforms.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PathKey {
    path: String,
}

impl PathKey {
    pub fn from_path(p: &Path) -> Self {
        PathKey {
            path: p.to_string_lossy().replace('\\', "/"),
        }
    }

    pub fn from_string(s: &str) -> Self {
        PathKey {
            path: s.replace('\\', "/"),
        }
    }

    pub fn as_str(&self) -> &str {
        &self.path
    }
}

impl fmt::Display for PathKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn test_path_key_from_path() {
        let pk = PathKey::from_path(Path::new("help/topics/foo/bar.html"));
        assert_eq!(pk.as_str(), "help/topics/foo/bar.html");
    }

    #[test]
    fn test_path_key_backslash_normalization() {
        let pk1 = PathKey::from_path(Path::new("help/topics/foo/bar.html"));
        let pk2 = PathKey::from_string("help\\topics\\foo\\bar.html");
        assert_eq!(pk1, pk2);
        assert_eq!(pk1.to_string(), "help/topics/foo/bar.html");
    }

    #[test]
    fn test_path_key_from_string() {
        let pk = PathKey::from_string("help/topics/MyTopic/page.html");
        assert_eq!(pk.as_str(), "help/topics/MyTopic/page.html");
    }

    #[test]
    fn test_path_key_equality() {
        let pk1 = PathKey::from_string("a/b/c.html");
        let pk2 = PathKey::from_string("a/b/c.html");
        let pk3 = PathKey::from_string("a/b/d.html");
        assert_eq!(pk1, pk2);
        assert_ne!(pk1, pk3);
    }

    #[test]
    fn test_path_key_hash() {
        use std::collections::HashMap;
        let mut map = HashMap::new();
        let pk = PathKey::from_string("test/path");
        map.insert(pk.clone(), 42);
        assert_eq!(map.get(&pk), Some(&42));
    }
}
