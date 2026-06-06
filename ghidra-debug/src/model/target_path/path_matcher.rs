//! PathMatcher ported from ghidra.trace.model.target.path.PathMatcher.
//!
//! A union filter that matches if any of its contained patterns match.

use std::collections::HashSet;

use super::key_path::KeyPath;
use super::path_filter::{Align, PathFilter};
use super::path_pattern::PathPattern;

/// A matcher that OR-combines multiple PathPatterns.
#[derive(Debug, Clone)]
pub struct PathMatcher {
    patterns: HashSet<PathPattern>,
}

impl PathMatcher {
    /// Create a PathMatcher from a set of patterns.
    pub fn from_patterns(patterns: HashSet<PathPattern>) -> Self {
        Self { patterns }
    }

    /// Create from a list of PathFilters, collecting their patterns.
    pub fn any(filters: &[&dyn PathFilter]) -> Self {
        let mut patterns = HashSet::new();
        for f in filters {
            patterns.extend(f.get_patterns());
        }
        Self { patterns }
    }

    /// Helper: check if any pattern satisfies the predicate.
    fn any_pattern<F: Fn(&PathPattern) -> bool>(&self, pred: F) -> bool {
        self.patterns.iter().any(|p| pred(p))
    }

    /// Coalesce wildcards: if "" present, remove all names; if "[]" present, remove all indices.
    fn coalesce_wilds(result: &mut HashSet<String>) {
        if result.contains("") {
            result.retain(|k| !KeyPath::is_name(k) || k.is_empty());
            result.insert("".to_string());
        }
        if result.contains("[]") {
            result.retain(|k| !KeyPath::is_index(k) || k == "[]");
            result.insert("[]".to_string());
        }
    }
}

impl PathFilter for PathMatcher {
    fn or(&self, that: &dyn PathFilter) -> Box<dyn PathFilter> {
        let mut patterns = self.patterns.clone();
        patterns.extend(that.get_patterns());
        Box::new(PathMatcher { patterns })
    }

    fn matches(&self, path: &KeyPath) -> bool {
        self.any_pattern(|p| p.matches(path))
    }

    fn successor_could_match(&self, path: &KeyPath, strict: bool) -> bool {
        self.any_pattern(|p| p.successor_could_match(path, strict))
    }

    fn ancestor_matches(&self, path: &KeyPath, strict: bool) -> bool {
        self.any_pattern(|p| p.ancestor_matches(path, strict))
    }

    fn ancestor_could_match_right(&self, path: &KeyPath, strict: bool) -> bool {
        self.any_pattern(|p| p.ancestor_could_match_right(path, strict))
    }

    fn get_next_keys(&self, path: &KeyPath) -> HashSet<String> {
        let mut result = HashSet::new();
        for pattern in &self.patterns {
            result.extend(pattern.get_next_keys(path));
        }
        Self::coalesce_wilds(&mut result);
        result
    }

    fn get_next_names(&self, path: &KeyPath) -> HashSet<String> {
        let mut result = HashSet::new();
        for pattern in &self.patterns {
            result.extend(pattern.get_next_names(path));
            if result.contains("") {
                let mut s = HashSet::new();
                s.insert("".to_string());
                return s;
            }
        }
        result
    }

    fn get_next_indices(&self, path: &KeyPath) -> HashSet<String> {
        let mut result = HashSet::new();
        for pattern in &self.patterns {
            result.extend(pattern.get_next_indices(path));
            if result.contains("[]") {
                let mut s = HashSet::new();
                s.insert("[]".to_string());
                return s;
            }
        }
        result
    }

    fn get_prev_keys(&self, path: &KeyPath) -> HashSet<String> {
        let mut result = HashSet::new();
        for pattern in &self.patterns {
            result.extend(pattern.get_prev_keys(path));
        }
        Self::coalesce_wilds(&mut result);
        result
    }

    fn get_singleton_path(&self) -> Option<KeyPath> {
        if self.patterns.len() != 1 {
            return None;
        }
        self.patterns.iter().next().unwrap().get_singleton_path()
    }

    fn get_singleton_pattern(&self) -> Option<PathPattern> {
        if self.patterns.len() != 1 {
            return None;
        }
        self.patterns.iter().next().cloned()
    }

    fn get_patterns(&self) -> HashSet<PathPattern> {
        self.patterns.clone()
    }

    fn remove_right(&self, count: usize) -> Box<dyn PathFilter> {
        let mut patterns = HashSet::new();
        for pat in &self.patterns {
            pat.do_remove_right(count, &mut patterns);
        }
        Box::new(PathMatcher { patterns })
    }

    fn apply_keys(&self, _align: &Align, keys: &[String]) -> Box<dyn PathFilter> {
        // Collect all patterns and apply keys to each, keeping results as PathPatterns
        let mut patterns = HashSet::new();
        for pat in &self.patterns {
            // Use path_filter::apply_keys logic inline
            let new_keys = apply_keys_to_pattern(pat, _align, keys);
            patterns.insert(PathPattern::new(KeyPath::from_vec(new_keys)));
        }
        Box::new(PathMatcher { patterns })
    }

    fn is_none(&self) -> bool {
        self.patterns.is_empty()
    }
}

/// Apply keys to a pattern's keys, substituting wildcards.
fn apply_keys_to_pattern(pat: &PathPattern, align: &Align, keys: &[String]) -> Vec<String> {
    let pattern_keys = pat.pattern().keys();
    let mut new_keys = Vec::new();
    let mut key_iter = keys.iter();

    match align {
        Align::Left => {
            for pkey in pattern_keys {
                if PathPattern::is_wildcard(pkey) {
                    if let Some(k) = key_iter.next() {
                        new_keys.push(k.clone());
                    } else {
                        new_keys.push(pkey.clone());
                    }
                } else {
                    new_keys.push(pkey.clone());
                }
            }
        }
        Align::Right => {
            let wild_count = pattern_keys.iter().filter(|p| PathPattern::is_wildcard(p)).count();
            let skip = wild_count.saturating_sub(keys.len());
            let mut wild_seen = 0;
            for pkey in pattern_keys {
                if PathPattern::is_wildcard(pkey) {
                    wild_seen += 1;
                    if wild_seen <= skip {
                        new_keys.push(pkey.clone());
                    } else if let Some(k) = key_iter.next() {
                        new_keys.push(k.clone());
                    } else {
                        new_keys.push(pkey.clone());
                    }
                } else {
                    new_keys.push(pkey.clone());
                }
            }
        }
    }
    new_keys
}

impl std::fmt::Display for PathMatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "<PathMatcher")?;
        for p in &self.patterns {
            writeln!(f, "  {}", p)?;
        }
        write!(f, ">")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_matcher() {
        let m = PathMatcher::from_patterns(HashSet::new());
        assert!(m.is_none());
        assert!(!m.matches(&KeyPath::of(&["A"])));
    }

    #[test]
    fn test_multi_pattern() {
        let mut patterns = HashSet::new();
        patterns.insert(PathPattern::new(KeyPath::of(&["A", "1"])));
        patterns.insert(PathPattern::new(KeyPath::of(&["B", "2"])));
        let m = PathMatcher::from_patterns(patterns);
        assert!(m.matches(&KeyPath::of(&["A", "1"])));
        assert!(m.matches(&KeyPath::of(&["B", "2"])));
        assert!(!m.matches(&KeyPath::of(&["C", "3"])));
    }

    #[test]
    fn test_singleton_path() {
        let mut patterns = HashSet::new();
        patterns.insert(PathPattern::new(KeyPath::of(&["A", "B"])));
        let m = PathMatcher::from_patterns(patterns);
        assert_eq!(m.get_singleton_path(), Some(KeyPath::of(&["A", "B"])));
    }

    #[test]
    fn test_not_singleton_when_multiple() {
        let mut patterns = HashSet::new();
        patterns.insert(PathPattern::new(KeyPath::of(&["A"])));
        patterns.insert(PathPattern::new(KeyPath::of(&["B"])));
        let m = PathMatcher::from_patterns(patterns);
        assert_eq!(m.get_singleton_path(), None);
    }
}
