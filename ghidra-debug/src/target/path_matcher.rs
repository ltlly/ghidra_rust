//! PathMatcher - a composite filter matching multiple PathPatterns.
//!
//! Ported from Ghidra's `PathMatcher`. Aggregates multiple `PathPattern`
//! instances and tests whether any pattern matches.

use std::collections::HashSet;

use super::key_path::KeyPath;
use super::path_pattern::{Align, PathPattern};

/// A composite filter that matches a path against multiple patterns.
///
/// This is the "or" combination of `PathPattern` instances.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathMatcher {
    patterns: HashSet<PathPattern>,
}

impl PathMatcher {
    /// Create a matcher from a set of patterns.
    pub fn new(patterns: HashSet<PathPattern>) -> Self {
        Self { patterns }
    }

    /// Create a matcher from a slice of patterns.
    pub fn from_patterns(patterns: &[PathPattern]) -> Self {
        Self {
            patterns: patterns.iter().cloned().collect(),
        }
    }

    /// Combine multiple path filters into a matcher.
    pub fn any(filters: &[&dyn PathFilter]) -> Self {
        let mut patterns = HashSet::new();
        for f in filters {
            for p in f.get_patterns() {
                patterns.insert(p.clone());
            }
        }
        Self { patterns }
    }

    /// The set of patterns.
    pub fn patterns(&self) -> &HashSet<PathPattern> {
        &self.patterns
    }

    /// Check if any pattern matches.
    pub fn matches(&self, path: &KeyPath) -> bool {
        self.patterns.iter().any(|p| p.matches(path))
    }

    /// Check if any successor could match.
    pub fn successor_could_match(&self, path: &KeyPath, strict: bool) -> bool {
        self.patterns
            .iter()
            .any(|p| p.successor_could_match(path, strict))
    }

    /// Check if any ancestor matches.
    pub fn ancestor_matches(&self, path: &KeyPath, strict: bool) -> bool {
        self.patterns
            .iter()
            .any(|p| p.ancestor_matches(path, strict))
    }

    /// Check if any ancestor could match right.
    pub fn ancestor_could_match_right(&self, path: &KeyPath, strict: bool) -> bool {
        self.patterns
            .iter()
            .any(|p| p.ancestor_could_match_right(path, strict))
    }

    /// If exactly one pattern with no wildcards, return the singleton path.
    pub fn singleton_path(&self) -> Option<&KeyPath> {
        if self.patterns.len() != 1 {
            return None;
        }
        self.patterns.iter().next().unwrap().singleton_path()
    }

    /// If exactly one pattern, return it.
    pub fn singleton_pattern(&self) -> Option<&PathPattern> {
        if self.patterns.len() != 1 {
            return None;
        }
        self.patterns.iter().next()
    }

    /// Get all possible next keys.
    pub fn get_next_keys(&self, path: &KeyPath) -> HashSet<String> {
        let mut result = HashSet::new();
        for pat in &self.patterns {
            result.extend(pat.get_next_keys(path));
        }
        coalesce_wilds(&mut result);
        result
    }

    /// Get all possible next names.
    pub fn get_next_names(&self, path: &KeyPath) -> HashSet<String> {
        let mut result = HashSet::new();
        for pat in &self.patterns {
            result.extend(pat.get_next_names(path));
            if result.contains("") {
                let mut wild = HashSet::new();
                wild.insert("".to_string());
                return wild;
            }
        }
        result
    }

    /// Get all possible next indices.
    pub fn get_next_indices(&self, path: &KeyPath) -> HashSet<String> {
        let mut result = HashSet::new();
        for pat in &self.patterns {
            result.extend(pat.get_next_indices(path));
            if result.contains("") {
                let mut wild = HashSet::new();
                wild.insert("".to_string());
                return wild;
            }
        }
        result
    }

    /// Get all possible previous keys.
    pub fn get_prev_keys(&self, path: &KeyPath) -> HashSet<String> {
        let mut result = HashSet::new();
        for pat in &self.patterns {
            result.extend(pat.get_prev_keys(path));
        }
        coalesce_wilds(&mut result);
        result
    }

    /// Whether this is the "none" filter (empty).
    pub fn is_none(&self) -> bool {
        self.patterns.is_empty()
    }

    /// Apply keys to all patterns.
    pub fn apply_keys(&self, align: Align, keys: &[String]) -> PathMatcher {
        let patterns: HashSet<PathPattern> = self
            .patterns
            .iter()
            .map(|pat| pat.apply_keys(align, keys))
            .collect();
        PathMatcher { patterns }
    }

    /// Remove count elements from the right of all patterns.
    pub fn remove_right(&self, count: usize) -> PathMatcher {
        let patterns: HashSet<PathPattern> = self
            .patterns
            .iter()
            .filter_map(|pat| pat.remove_right(count))
            .collect();
        PathMatcher { patterns }
    }
}

impl std::fmt::Display for PathMatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<PathMatcher [")?;
        for (i, pat) in self.patterns.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "{}", pat)?;
        }
        write!(f, "]>")
    }
}

/// Coalesce wildcard entries in a set.
///
/// If empty-string (any-name) is present, remove all specific names.
/// If `[]` (any-index) is present, remove all specific indices.
fn coalesce_wilds(result: &mut HashSet<String>) {
    let has_name_wild = result.contains("");
    let has_index_wild = result.contains("[]");

    if has_name_wild || has_index_wild {
        let specific: Vec<String> = result
            .iter()
            .filter(|k| {
                if has_name_wild && KeyPath::is_name(k) && k.as_str() != "" {
                    return true;
                }
                if has_index_wild && KeyPath::is_index_str(k) && k.as_str() != "[]" {
                    return true;
                }
                false
            })
            .cloned()
            .collect();
        for k in specific {
            result.remove(&k);
        }
    }
}

/// Trait for path filters that can match against `KeyPath` values.
///
/// This is the Rust equivalent of Ghidra's `PathFilter` interface.
pub trait PathFilter: std::fmt::Debug {
    /// Combine with another filter (logical OR).
    fn or_filter(&self, other: &dyn PathFilter) -> PathMatcher;

    /// Check if the entire path matches.
    fn matches(&self, path: &KeyPath) -> bool;

    /// Check if a successor of the path could match.
    fn successor_could_match(&self, path: &KeyPath, strict: bool) -> bool;

    /// Check if an ancestor of the path matches.
    fn ancestor_matches(&self, path: &KeyPath, strict: bool) -> bool;

    /// Check if an ancestor could match (right to left).
    fn ancestor_could_match_right(&self, path: &KeyPath, strict: bool) -> bool;

    /// Get the next possible keys.
    fn get_next_keys(&self, path: &KeyPath) -> HashSet<String>;

    /// Get the next possible names.
    fn get_next_names(&self, path: &KeyPath) -> HashSet<String>;

    /// Get the next possible indices.
    fn get_next_indices(&self, path: &KeyPath) -> HashSet<String>;

    /// Get the previous possible keys.
    fn get_prev_keys(&self, path: &KeyPath) -> HashSet<String>;

    /// If known to match only one path, return it.
    fn singleton_path(&self) -> Option<&KeyPath>;

    /// If this consists of a single pattern, return it.
    fn singleton_pattern(&self) -> Option<&PathPattern>;

    /// Get the patterns of this filter.
    fn get_patterns(&self) -> Vec<&PathPattern>;

    /// Remove count elements from the right.
    fn remove_right(&self, count: usize) -> PathMatcher;

    /// Apply keys to substitute wildcards.
    fn apply_keys(&self, align: Align, keys: &[String]) -> PathMatcher;

    /// Whether this filter matches nothing.
    fn is_none(&self) -> bool;
}

/// A filter that matches nothing.
#[derive(Debug, Clone)]
pub struct NoneFilter;

impl PathFilter for NoneFilter {
    fn or_filter(&self, other: &dyn PathFilter) -> PathMatcher {
        PathMatcher::new(other.get_patterns().into_iter().cloned().collect())
    }
    fn matches(&self, _path: &KeyPath) -> bool {
        false
    }
    fn successor_could_match(&self, _path: &KeyPath, _strict: bool) -> bool {
        false
    }
    fn ancestor_matches(&self, _path: &KeyPath, _strict: bool) -> bool {
        false
    }
    fn ancestor_could_match_right(&self, _path: &KeyPath, _strict: bool) -> bool {
        false
    }
    fn get_next_keys(&self, _path: &KeyPath) -> HashSet<String> {
        HashSet::new()
    }
    fn get_next_names(&self, _path: &KeyPath) -> HashSet<String> {
        HashSet::new()
    }
    fn get_next_indices(&self, _path: &KeyPath) -> HashSet<String> {
        HashSet::new()
    }
    fn get_prev_keys(&self, _path: &KeyPath) -> HashSet<String> {
        HashSet::new()
    }
    fn singleton_path(&self) -> Option<&KeyPath> {
        None
    }
    fn singleton_pattern(&self) -> Option<&PathPattern> {
        None
    }
    fn get_patterns(&self) -> Vec<&PathPattern> {
        Vec::new()
    }
    fn remove_right(&self, _count: usize) -> PathMatcher {
        PathMatcher::new(HashSet::new())
    }
    fn apply_keys(&self, _align: Align, _keys: &[String]) -> PathMatcher {
        PathMatcher::new(HashSet::new())
    }
    fn is_none(&self) -> bool {
        true
    }
}

impl PathFilter for PathPattern {
    fn or_filter(&self, other: &dyn PathFilter) -> PathMatcher {
        let mut patterns: HashSet<PathPattern> = other.get_patterns().into_iter().cloned().collect();
        patterns.insert(self.clone());
        PathMatcher::new(patterns)
    }
    fn matches(&self, path: &KeyPath) -> bool {
        PathPattern::matches(self, path)
    }
    fn successor_could_match(&self, path: &KeyPath, strict: bool) -> bool {
        PathPattern::successor_could_match(self, path, strict)
    }
    fn ancestor_matches(&self, path: &KeyPath, strict: bool) -> bool {
        PathPattern::ancestor_matches(self, path, strict)
    }
    fn ancestor_could_match_right(&self, path: &KeyPath, strict: bool) -> bool {
        PathPattern::ancestor_could_match_right(self, path, strict)
    }
    fn get_next_keys(&self, path: &KeyPath) -> HashSet<String> {
        PathPattern::get_next_keys(self, path)
    }
    fn get_next_names(&self, path: &KeyPath) -> HashSet<String> {
        PathPattern::get_next_names(self, path)
    }
    fn get_next_indices(&self, path: &KeyPath) -> HashSet<String> {
        PathPattern::get_next_indices(self, path)
    }
    fn get_prev_keys(&self, path: &KeyPath) -> HashSet<String> {
        PathPattern::get_prev_keys(self, path)
    }
    fn singleton_path(&self) -> Option<&KeyPath> {
        PathPattern::singleton_path(self)
    }
    fn singleton_pattern(&self) -> Option<&PathPattern> {
        Some(self)
    }
    fn get_patterns(&self) -> Vec<&PathPattern> {
        vec![self]
    }
    fn remove_right(&self, count: usize) -> PathMatcher {
        let mut patterns = HashSet::new();
        if let Some(p) = PathPattern::remove_right(self, count) {
            patterns.insert(p);
        }
        PathMatcher::new(patterns)
    }
    fn apply_keys(&self, align: Align, keys: &[String]) -> PathMatcher {
        let mut patterns = HashSet::new();
        patterns.insert(PathPattern::apply_keys(self, align, keys));
        PathMatcher::new(patterns)
    }
    fn is_none(&self) -> bool {
        false
    }
}

impl PathFilter for PathMatcher {
    fn or_filter(&self, other: &dyn PathFilter) -> PathMatcher {
        let mut patterns = self.patterns.clone();
        for p in other.get_patterns() {
            patterns.insert(p.clone());
        }
        PathMatcher::new(patterns)
    }
    fn matches(&self, path: &KeyPath) -> bool {
        PathMatcher::matches(self, path)
    }
    fn successor_could_match(&self, path: &KeyPath, strict: bool) -> bool {
        PathMatcher::successor_could_match(self, path, strict)
    }
    fn ancestor_matches(&self, path: &KeyPath, strict: bool) -> bool {
        PathMatcher::ancestor_matches(self, path, strict)
    }
    fn ancestor_could_match_right(&self, path: &KeyPath, strict: bool) -> bool {
        PathMatcher::ancestor_could_match_right(self, path, strict)
    }
    fn get_next_keys(&self, path: &KeyPath) -> HashSet<String> {
        PathMatcher::get_next_keys(self, path)
    }
    fn get_next_names(&self, path: &KeyPath) -> HashSet<String> {
        PathMatcher::get_next_names(self, path)
    }
    fn get_next_indices(&self, path: &KeyPath) -> HashSet<String> {
        PathMatcher::get_next_indices(self, path)
    }
    fn get_prev_keys(&self, path: &KeyPath) -> HashSet<String> {
        PathMatcher::get_prev_keys(self, path)
    }
    fn singleton_path(&self) -> Option<&KeyPath> {
        PathMatcher::singleton_path(self)
    }
    fn singleton_pattern(&self) -> Option<&PathPattern> {
        PathMatcher::singleton_pattern(self)
    }
    fn get_patterns(&self) -> Vec<&PathPattern> {
        self.patterns.iter().collect()
    }
    fn remove_right(&self, count: usize) -> PathMatcher {
        PathMatcher::remove_right(self, count)
    }
    fn apply_keys(&self, align: Align, keys: &[String]) -> PathMatcher {
        PathMatcher::apply_keys(self, align, keys)
    }
    fn is_none(&self) -> bool {
        PathMatcher::is_none(self)
    }
}

/// Parse a path filter string into a `PathPattern`.
pub fn parse_pattern(pattern_str: &str) -> PathPattern {
    PathPattern::new(KeyPath::parse(pattern_str))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_path_filter_trait_with_pattern() {
        let pat = PathPattern::new(KeyPath::of(&["Processes", "[]"]));
        let filter: &dyn PathFilter = &pat;
        // "[]" matches bracketed index keys like "[5]"
        assert!(filter.matches(&KeyPath::of(&["Processes", "[5]"])));
        assert!(!filter.matches(&KeyPath::of(&["Processes", "name"])));
        assert!(!filter.matches(&KeyPath::of(&["Threads"])));
    }

    #[test]
    fn test_none_filter() {
        let f = NoneFilter;
        assert!(f.is_none());
        assert!(!f.matches(&KeyPath::ROOT));
    }

    #[test]
    fn test_or_filter() {
        let p1 = PathPattern::new(KeyPath::of(&["a"]));
        let p2 = PathPattern::new(KeyPath::of(&["b"]));
        let combined = p1.or_filter(&p2);
        assert!(combined.matches(&KeyPath::of(&["a"])));
        assert!(combined.matches(&KeyPath::of(&["b"])));
        assert!(!combined.matches(&KeyPath::of(&["c"])));
    }

    #[test]
    fn test_path_matcher_get_next_keys() {
        let p1 = PathPattern::new(KeyPath::of(&["a", "b"]));
        let p2 = PathPattern::new(KeyPath::of(&["a", "c"]));
        let matcher = PathMatcher::from_patterns(&[p1, p2]);
        let next = matcher.get_next_keys(&KeyPath::of(&["a"]));
        assert!(next.contains("b"));
        assert!(next.contains("c"));
    }

    #[test]
    fn test_coalesce_wilds() {
        let mut set = HashSet::new();
        set.insert("foo".to_string());
        set.insert("bar".to_string());
        set.insert("".to_string()); // name wildcard
        coalesce_wilds(&mut set);
        assert!(set.contains(""));
        assert!(!set.contains("foo"));
        assert!(!set.contains("bar"));
    }
}
