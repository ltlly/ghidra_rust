//! PathPattern - a single pattern for matching trace object paths.
//!
//! Ported from Ghidra's `PathPattern`. Uses wildcards (`[]` for any index,
//! empty string for any name) to match against `KeyPath` values.

use std::collections::HashSet;
use std::fmt;

use super::key_path::KeyPath;

/// Alignment direction for wildcard substitution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Align {
    /// Substitute wildcards from left to right.
    Left,
    /// Substitute wildcards from right to left.
    Right,
}

/// A single pattern for matching `KeyPath` values.
///
/// Wildcards: `[]` matches any index, `""` (empty string) matches any name.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PathPattern {
    pattern: KeyPath,
}

impl PathPattern {
    /// Create a new pattern from a `KeyPath`.
    pub fn new(pattern: KeyPath) -> Self {
        Self { pattern }
    }

    /// Whether a key is a wildcard.
    pub fn is_wildcard(key: &str) -> bool {
        key == "[]" || key.is_empty()
    }

    /// The underlying pattern path.
    pub fn as_path(&self) -> &KeyPath {
        &self.pattern
    }

    /// Count the number of wildcard keys in this pattern.
    pub fn count_wildcards(&self) -> usize {
        self.pattern.iter().filter(|k| Self::is_wildcard(k)).count()
    }

    /// Check if the pattern contains wildcards.
    pub fn contains_wildcard(&self) -> bool {
        self.pattern.iter().any(|k| Self::is_wildcard(k))
    }

    /// Whether this is a singleton path (no wildcards), return it.
    pub fn singleton_path(&self) -> Option<&KeyPath> {
        if self.contains_wildcard() {
            None
        } else {
            Some(&self.pattern)
        }
    }

    /// Matches the first `length` keys of path against pattern (left to right).
    fn matches_up_to(&self, path: &KeyPath, length: usize) -> bool {
        for i in 0..length {
            let pat = self.pattern.get(i).unwrap_or("");
            let key = path.get(i).unwrap_or("");
            if !key_matches(pat, key) {
                return false;
            }
        }
        true
    }

    /// Matches the last `length` keys of path against pattern (right to left).
    fn matches_back_to(&self, path: &KeyPath, length: usize) -> bool {
        let pattern_max = self.pattern.size().saturating_sub(1);
        let path_max = path.size().saturating_sub(1);
        for i in 0..length {
            let pat = self.pattern.get(pattern_max - i).unwrap_or("");
            let key = path.get(path_max - i).unwrap_or("");
            if !key_matches(pat, key) {
                return false;
            }
        }
        true
    }

    /// Check if a path matches this pattern exactly.
    pub fn matches(&self, path: &KeyPath) -> bool {
        if path.size() != self.pattern.size() {
            return false;
        }
        self.matches_up_to(path, path.size())
    }

    /// Check if the given path could have a matching successor.
    pub fn successor_could_match(&self, path: &KeyPath, strict: bool) -> bool {
        if path.size() > self.pattern.size() {
            return false;
        }
        if strict && path.size() == self.pattern.size() {
            return false;
        }
        self.matches_up_to(path, path.size())
    }

    /// Check if the given path has an ancestor that matches.
    pub fn ancestor_matches(&self, path: &KeyPath, strict: bool) -> bool {
        if path.size() < self.pattern.size() {
            return false;
        }
        if strict && path.size() == self.pattern.size() {
            return false;
        }
        self.matches_up_to(path, self.pattern.size())
    }

    /// Check if the given path could have a matching ancestor (right to left).
    pub fn ancestor_could_match_right(&self, path: &KeyPath, strict: bool) -> bool {
        if path.size() > self.pattern.size() {
            return false;
        }
        if strict && path.size() == self.pattern.size() {
            return false;
        }
        self.matches_back_to(path, path.size())
    }

    /// Get the next possible key at the position after path.
    pub fn get_next_keys(&self, path: &KeyPath) -> HashSet<String> {
        if path.size() >= self.pattern.size() {
            return HashSet::new();
        }
        if !self.matches_up_to(path, path.size()) {
            return HashSet::new();
        }
        let mut set = HashSet::new();
        set.insert(self.pattern.get(path.size()).unwrap_or("").to_string());
        set
    }

    /// Get the next possible name at the position after path.
    pub fn get_next_names(&self, path: &KeyPath) -> HashSet<String> {
        if path.size() >= self.pattern.size() {
            return HashSet::new();
        }
        if !self.matches_up_to(path, path.size()) {
            return HashSet::new();
        }
        let pat = self.pattern.get(path.size()).unwrap_or("");
        if KeyPath::is_name(pat) {
            let mut set = HashSet::new();
            set.insert(pat.to_string());
            set
        } else {
            HashSet::new()
        }
    }

    /// Get the next possible index at the position after path.
    pub fn get_next_indices(&self, path: &KeyPath) -> HashSet<String> {
        if path.size() >= self.pattern.size() {
            return HashSet::new();
        }
        if !self.matches_up_to(path, path.size()) {
            return HashSet::new();
        }
        let pat = self.pattern.get(path.size()).unwrap_or("");
        if KeyPath::is_index_str(pat) {
            let mut set = HashSet::new();
            set.insert(KeyPath::parse_index(pat).to_string());
            set
        } else {
            HashSet::new()
        }
    }

    /// Get the previous possible key (right to left) before path.
    pub fn get_prev_keys(&self, path: &KeyPath) -> HashSet<String> {
        if path.size() >= self.pattern.size() {
            return HashSet::new();
        }
        if !self.matches_back_to(path, path.size()) {
            return HashSet::new();
        }
        let idx = self.pattern.size() - 1 - path.size();
        let mut set = HashSet::new();
        set.insert(self.pattern.get(idx).unwrap_or("").to_string());
        set
    }

    /// Apply keys to substitute wildcards.
    pub fn apply_keys(&self, align: Align, keys: &[String]) -> PathPattern {
        let size = self.pattern.size();
        let mut result: Vec<String> = Vec::with_capacity(size);

        // Build aligned iterators
        let pat_keys: Vec<&str> = (0..size)
            .map(|i| self.pattern.get(i).unwrap_or(""))
            .collect();

        match align {
            Align::Left => {
                let mut key_idx = 0;
                for i in 0..size {
                    let pat = pat_keys[i];
                    if key_idx < keys.len() && Self::is_wildcard(pat) {
                        let index = sanitize_key(&keys[key_idx]);
                        key_idx += 1;
                        if KeyPath::is_index_str(pat) {
                            result.push(format!("[{}]", index));
                        } else {
                            result.push(index);
                        }
                    } else {
                        result.push(pat.to_string());
                    }
                }
            }
            Align::Right => {
                let mut key_idx = keys.len();
                for i in (0..size).rev() {
                    let pat = pat_keys[i];
                    if key_idx > 0 && Self::is_wildcard(pat) {
                        key_idx -= 1;
                        let index = sanitize_key(&keys[key_idx]);
                        if KeyPath::is_index_str(pat) {
                            result.push(format!("[{}]", index));
                        } else {
                            result.push(index);
                        }
                    } else {
                        result.push(pat.to_string());
                    }
                }
                result.reverse();
            }
        }

        PathPattern::new(KeyPath::new(result))
    }

    /// Extract matched wildcard keys from a path.
    pub fn match_keys(&self, path: &KeyPath, match_length: bool) -> Option<Vec<String>> {
        let length = self.pattern.size();
        if match_length {
            if length != path.size() {
                return None;
            }
        } else if length > path.size() {
            return None;
        }

        let mut result = Vec::new();
        for i in 0..length {
            let pat = self.pattern.get(i).unwrap_or("");
            let key = path.get(i).unwrap_or("");
            if !key_matches(pat, key) {
                return None;
            }
            if Self::is_wildcard(pat) {
                if KeyPath::is_index_str(pat) {
                    result.push(KeyPath::parse_index(key).to_string());
                } else {
                    result.push(key.to_string());
                }
            }
        }
        Some(result)
    }

    /// Remove count elements from the right, returning a new pattern.
    pub fn remove_right(&self, count: usize) -> Option<PathPattern> {
        self.pattern.parent_n(count).map(|k| PathPattern::new(k))
    }
}

impl fmt::Display for PathPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<PathPattern {}>", self.pattern)
    }
}

/// Check if a single key matches a pattern key.
///
/// Wildcard rules:
/// - `[]` matches any index key (bracketed, e.g., `[2]`, `[42]`)
/// - `""` (empty) matches any name key (non-bracketed, non-empty)
pub fn key_matches(pat: &str, key: &str) -> bool {
    if key == pat {
        return true;
    }
    if pat == "[]" {
        return KeyPath::is_index_str(key);
    }
    if pat.is_empty() {
        return KeyPath::is_name(key);
    }
    false
}

/// Sanitize a key by replacing brackets with curly braces.
///
/// If the key is already in bracketed form `[...]`, strips the outer brackets
/// and sanitizes the inner content (matching Java's behavior).
pub fn sanitize_key(key: &str) -> String {
    let inner = if key.starts_with('[') && key.ends_with(']') {
        &key[1..key.len() - 1]
    } else {
        key
    };
    inner.replace('[', "{").replace(']', "}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_match() {
        let pat = PathPattern::new(KeyPath::of(&["Processes", "2", "Threads"]));
        assert!(pat.matches(&KeyPath::of(&["Processes", "2", "Threads"])));
        assert!(!pat.matches(&KeyPath::of(&["Processes", "3", "Threads"])));
        assert!(!pat.matches(&KeyPath::of(&["Processes", "2"])));
    }

    #[test]
    fn test_index_wildcard() {
        let pat = PathPattern::new(KeyPath::of(&["Processes", "[]", "Threads"]));
        // Bracketed index keys match the [] wildcard
        assert!(pat.matches(&KeyPath::of(&["Processes", "[2]", "Threads"])));
        assert!(pat.matches(&KeyPath::of(&["Processes", "[99]", "Threads"])));
        // Non-index keys do not match [] wildcard
        assert!(!pat.matches(&KeyPath::of(&["Processes", "name", "Threads"])));
        // Wrong length
        assert!(!pat.matches(&KeyPath::of(&["Processes", "[2]"])));
    }

    #[test]
    fn test_name_wildcard() {
        let pat = PathPattern::new(KeyPath::of(&["Processes", "", "name"]));
        assert!(pat.matches(&KeyPath::of(&["Processes", "Threads", "name"])));
        assert!(!pat.matches(&KeyPath::of(&["Processes", "[0]", "name"])));
    }

    #[test]
    fn test_successor_could_match() {
        let pat = PathPattern::new(KeyPath::of(&["a", "b", "c"]));
        assert!(pat.successor_could_match(&KeyPath::of(&["a"]), false));
        assert!(pat.successor_could_match(&KeyPath::of(&["a", "b"]), false));
        assert!(pat.successor_could_match(&KeyPath::of(&["a", "b", "c"]), false));
        assert!(!pat.successor_could_match(&KeyPath::of(&["a", "b", "c"]), true));
        assert!(!pat.successor_could_match(&KeyPath::of(&["a", "x"]), false));
    }

    #[test]
    fn test_ancestor_matches() {
        let pat = PathPattern::new(KeyPath::of(&["a", "b"]));
        assert!(pat.ancestor_matches(&KeyPath::of(&["a", "b", "c"]), false));
        assert!(pat.ancestor_matches(&KeyPath::of(&["a", "b"]), false));
        assert!(!pat.ancestor_matches(&KeyPath::of(&["a", "b"]), true));
        assert!(!pat.ancestor_matches(&KeyPath::of(&["a"]), false));
    }

    #[test]
    fn test_get_next_keys() {
        let pat = PathPattern::new(KeyPath::of(&["a", "b", "c"]));
        let keys = pat.get_next_keys(&KeyPath::of(&["a"]));
        assert_eq!(keys.len(), 1);
        assert!(keys.contains("b"));

        let empty = pat.get_next_keys(&KeyPath::of(&["x"]));
        assert!(empty.is_empty());
    }

    #[test]
    fn test_match_keys() {
        let pat = PathPattern::new(KeyPath::of(&["Processes", "[]", "name"]));
        // Key "[5]" matches index wildcard, index extracted as "5"
        let keys = pat.match_keys(&KeyPath::of(&["Processes", "[5]", "name"]), true);
        assert_eq!(keys, Some(vec!["5".to_string()]));

        // Non-matching length
        let keys = pat.match_keys(&KeyPath::of(&["Processes", "[5]"]), true);
        assert_eq!(keys, None);
    }

    #[test]
    fn test_apply_keys() {
        let pat = PathPattern::new(KeyPath::of(&["Processes", "[]", "Threads", "[]"]));
        let filled = pat.apply_keys(Align::Left, &["[5]".to_string(), "[3]".to_string()]);
        assert!(filled.matches(&KeyPath::of(&["Processes", "[5]", "Threads", "[3]"])));
    }

    #[test]
    fn test_remove_right() {
        let pat = PathPattern::new(KeyPath::of(&["a", "b", "c"]));
        let removed = pat.remove_right(1).unwrap();
        assert!(removed.matches(&KeyPath::of(&["a", "b"])));
    }

    #[test]
    fn test_sanitize_key() {
        assert_eq!(sanitize_key("foo[bar]"), "foo{bar}");
    }

    #[test]
    fn test_wildcard_detection() {
        assert!(PathPattern::is_wildcard("[]"));
        assert!(PathPattern::is_wildcard(""));
        assert!(!PathPattern::is_wildcard("name"));
    }
}
