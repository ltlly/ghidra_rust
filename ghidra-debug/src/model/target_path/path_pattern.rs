//! PathPattern ported from ghidra.trace.model.target.path.PathPattern.
//!
//! A single-path filter using a KeyPath as a pattern. Blank keys serve as
//! wildcards accepting all keys in that position.

use std::collections::HashSet;

use super::key_path::KeyPath;
use super::path_filter::{key_matches, Align, PathFilter};
use super::PathMatcher;

/// A single-path pattern filter.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PathPattern {
    pattern: KeyPath,
}

impl PathPattern {
    /// Create a new PathPattern from a KeyPath.
    pub fn new(pattern: KeyPath) -> Self {
        Self { pattern }
    }

    /// Get the underlying pattern KeyPath.
    pub fn pattern(&self) -> &KeyPath {
        &self.pattern
    }

    /// Convert to a pattern string.
    pub fn to_pattern_string(&self) -> String {
        self.pattern.to_string()
    }

    /// Check if a pattern key is a wildcard.
    pub fn is_wildcard(pat: &str) -> bool {
        pat == "[]" || pat.is_empty()
    }

    /// Match keys from the beginning up to 'length' positions.
    fn matches_up_to(&self, path: &KeyPath, length: usize) -> bool {
        for i in 0..length {
            if !key_matches(self.pattern.key(i), path.key(i)) {
                return false;
            }
        }
        true
    }

    /// Match keys from the end backwards 'length' positions.
    fn matches_back_to(&self, path: &KeyPath, length: usize) -> bool {
        let pattern_max = self.pattern.size() - 1;
        let path_max = path.size() - 1;
        for i in 0..length {
            if !key_matches(self.pattern.key(pattern_max - i), path.key(path_max - i)) {
                return false;
            }
        }
        true
    }

    /// If the path matches, extract keys matched by wildcards.
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
            let pat = self.pattern.key(i);
            let key = path.key(i);
            if !key_matches(pat, key) {
                return None;
            }
            if Self::is_wildcard(pat) {
                if KeyPath::is_index(pat) {
                    result.push(KeyPath::parse_index(key).to_string());
                } else {
                    result.push(key.to_string());
                }
            }
        }
        Some(result)
    }

    /// Add patterns with count elements removed from the right.
    pub fn do_remove_right(&self, count: usize, result: &mut HashSet<PathPattern>) {
        if let Some(parent) = self.pattern.parent_n(count) {
            result.insert(PathPattern::new(parent));
        }
    }
}

impl PathFilter for PathPattern {
    fn or(&self, that: &dyn PathFilter) -> Box<dyn PathFilter> {
        let patterns = that.get_patterns();
        if patterns.len() == 1 && patterns.contains(self) {
            return Box::new(self.clone());
        }
        let mut combined = HashSet::new();
        combined.insert(self.clone());
        combined.extend(patterns);
        Box::new(PathMatcher::from_patterns(combined))
    }

    fn matches(&self, path: &KeyPath) -> bool {
        if path.size() != self.pattern.size() {
            return false;
        }
        self.matches_up_to(path, path.size())
    }

    fn successor_could_match(&self, path: &KeyPath, strict: bool) -> bool {
        if path.size() > self.pattern.size() {
            return false;
        }
        if strict && path.size() == self.pattern.size() {
            return false;
        }
        self.matches_up_to(path, path.size())
    }

    fn ancestor_matches(&self, path: &KeyPath, strict: bool) -> bool {
        if path.size() < self.pattern.size() {
            return false;
        }
        if strict && path.size() == self.pattern.size() {
            return false;
        }
        self.matches_up_to(path, self.pattern.size())
    }

    fn ancestor_could_match_right(&self, path: &KeyPath, strict: bool) -> bool {
        if path.size() > self.pattern.size() {
            return false;
        }
        if strict && path.size() == self.pattern.size() {
            return false;
        }
        self.matches_back_to(path, path.size())
    }

    fn get_next_keys(&self, path: &KeyPath) -> HashSet<String> {
        let mut result = HashSet::new();
        if path.size() < self.pattern.size()
            && self.matches_up_to(path, path.size())
        {
            result.insert(self.pattern.key(path.size()).to_string());
        }
        result
    }

    fn get_next_names(&self, path: &KeyPath) -> HashSet<String> {
        let mut result = HashSet::new();
        if path.size() < self.pattern.size()
            && self.matches_up_to(path, path.size())
        {
            let key = self.pattern.key(path.size());
            if !KeyPath::is_index(key) {
                result.insert(key.to_string());
            }
        }
        result
    }

    fn get_next_indices(&self, path: &KeyPath) -> HashSet<String> {
        let mut result = HashSet::new();
        if path.size() < self.pattern.size()
            && self.matches_up_to(path, path.size())
        {
            let key = self.pattern.key(path.size());
            if KeyPath::is_index(key) {
                result.insert(key.to_string());
            }
        }
        result
    }

    fn get_prev_keys(&self, path: &KeyPath) -> HashSet<String> {
        let mut result = HashSet::new();
        if path.size() > self.pattern.size()
            && self.matches_up_to(path, self.pattern.size())
        {
            result.insert(self.pattern.key(self.pattern.size() - 1).to_string());
        }
        result
    }

    fn get_singleton_path(&self) -> Option<KeyPath> {
        if self.pattern.contains_wildcard() {
            None
        } else {
            Some(self.pattern.clone())
        }
    }

    fn get_singleton_pattern(&self) -> Option<PathPattern> {
        Some(self.clone())
    }

    fn get_patterns(&self) -> HashSet<PathPattern> {
        let mut s = HashSet::new();
        s.insert(self.clone());
        s
    }

    fn remove_right(&self, count: usize) -> Box<dyn PathFilter> {
        let mut patterns = HashSet::new();
        self.do_remove_right(count, &mut patterns);
        Box::new(PathMatcher::from_patterns(patterns))
    }

    fn apply_keys(&self, align: &Align, keys: &[String]) -> Box<dyn PathFilter> {
        let mut new_keys: Vec<String> = Vec::new();
        let mut key_iter = keys.iter();
        let pattern_keys = self.pattern.keys();

        match align {
            Align::Left => {
                for pat in pattern_keys {
                    if Self::is_wildcard(pat) {
                        if let Some(k) = key_iter.next() {
                            new_keys.push(k.clone());
                        } else {
                            new_keys.push(pat.clone());
                        }
                    } else {
                        new_keys.push(pat.clone());
                    }
                }
            }
            Align::Right => {
                // Count wildcards
                let wild_count = pattern_keys.iter().filter(|p| Self::is_wildcard(p)).count();
                let skip = wild_count.saturating_sub(keys.len());
                let mut wild_seen = 0;
                for pat in pattern_keys {
                    if Self::is_wildcard(pat) {
                        wild_seen += 1;
                        if wild_seen <= skip {
                            new_keys.push(pat.clone());
                        } else if let Some(k) = key_iter.next() {
                            new_keys.push(k.clone());
                        } else {
                            new_keys.push(pat.clone());
                        }
                    } else {
                        new_keys.push(pat.clone());
                    }
                }
            }
        }

        Box::new(PathPattern::new(KeyPath::from_vec(new_keys)))
    }

    fn is_none(&self) -> bool {
        false
    }
}

impl std::fmt::Display for PathPattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<PathPattern {}>", self.pattern)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_match() {
        let pat = PathPattern::new(KeyPath::of(&["Processes", "[0]"]));
        assert!(pat.matches(&KeyPath::of(&["Processes", "[0]"])));
        assert!(!pat.matches(&KeyPath::of(&["Processes", "[1]"])));
        assert!(!pat.matches(&KeyPath::of(&["Processes"])));
    }

    #[test]
    fn test_wildcard_match() {
        let pat = PathPattern::new(KeyPath::of(&["Processes", ""]));
        assert!(pat.matches(&KeyPath::of(&["Processes", "main"])));
        assert!(pat.matches(&KeyPath::of(&["Processes", "idle"])));
        assert!(!pat.matches(&KeyPath::of(&["Processes", "[0]"])));
    }

    #[test]
    fn test_index_wildcard() {
        let pat = PathPattern::new(KeyPath::of(&["Processes", "[]"]));
        assert!(pat.matches(&KeyPath::of(&["Processes", "[0]"])));
        assert!(!pat.matches(&KeyPath::of(&["Processes", "main"])));
    }

    #[test]
    fn test_successor_could_match() {
        let pat = PathPattern::new(KeyPath::of(&["Processes", "", "Threads"]));
        assert!(pat.successor_could_match(&KeyPath::of(&["Processes"]), false));
        assert!(pat.successor_could_match(&KeyPath::of(&["Processes", "main"]), false));
        assert!(!pat.successor_could_match(&KeyPath::of(&["Processes", "main", "Threads", "x"]), false));
    }

    #[test]
    fn test_ancestor_matches() {
        let pat = PathPattern::new(KeyPath::of(&["Processes", ""]));
        assert!(pat.ancestor_matches(&KeyPath::of(&["Processes", "main", "Threads"]), false));
        assert!(!pat.ancestor_matches(&KeyPath::of(&["Other"]), false));
    }

    #[test]
    fn test_get_singleton_path() {
        let pat = PathPattern::new(KeyPath::of(&["A", "B"]));
        assert_eq!(pat.get_singleton_path(), Some(KeyPath::of(&["A", "B"])));

        let wildcard = PathPattern::new(KeyPath::of(&["A", ""]));
        assert_eq!(wildcard.get_singleton_path(), None);
    }

    #[test]
    fn test_match_keys() {
        let pat = PathPattern::new(KeyPath::of(&["Processes", "", "Threads"]));
        let path = KeyPath::of(&["Processes", "main", "Threads"]);
        let keys = pat.match_keys(&path, true).unwrap();
        assert_eq!(keys, vec!["main"]);
    }
}
