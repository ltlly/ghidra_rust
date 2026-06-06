//! Extended tree traversal visitors for the database target model.
//!
//! Ported from Ghidra's `ghidra.trace.database.target.visitors` package.
//! These visitors implement various traversal strategies for the trace
//! object tree, including ancestor traversal, successor traversal, and
//! path enumeration.
//!
//! Submodule: `TreeTraversal` - Core tree traversal framework with
//! visitor pattern.


use crate::model::Lifespan;
use crate::target::{KeyPath, PathMatcher, PathPattern, VisitResult};

/// The composed result of walking a path through the tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValPathEntry {
    /// The key on this path segment.
    pub key: String,
    /// The lifespan of this entry.
    pub lifespan: Lifespan,
    /// Whether this entry is an element (vs. attribute).
    pub is_element: bool,
    /// The object path from root to this entry's parent.
    pub parent_path: KeyPath,
}

impl ValPathEntry {
    /// Create a new value path entry.
    pub fn new(key: impl Into<String>, lifespan: Lifespan, is_element: bool, parent_path: KeyPath) -> Self {
        Self {
            key: key.into(),
            lifespan,
            is_element,
            parent_path,
        }
    }
}

/// A path of values from one object to another.
///
/// Ported from Ghidra's `TraceObjectValPath` / `DBTraceObjectValPath`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectValPath {
    /// Entries in the path, ordered from source to destination.
    pub entries: Vec<ValPathEntry>,
}

impl ObjectValPath {
    /// Create an empty path.
    pub fn empty() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Whether the path is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The number of entries in the path.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Append an entry to this path (going deeper into the tree).
    pub fn append(&self, entry: ValPathEntry) -> Self {
        let mut entries = self.entries.clone();
        entries.push(entry);
        Self { entries }
    }

    /// Prepend an entry to this path (going up toward root).
    pub fn prepend(&self, entry: ValPathEntry) -> Self {
        let mut entries = vec![entry];
        entries.extend(self.entries.iter().cloned());
        Self { entries }
    }

    /// Get the key path from source to destination.
    pub fn get_path(&self) -> KeyPath {
        KeyPath::of_owned(self.entries.iter().map(|e| e.key.clone()).collect())
    }

    /// Get the first entry (adjacent to source).
    pub fn first_entry(&self) -> Option<&ValPathEntry> {
        self.entries.first()
    }

    /// Get the last entry (adjacent to destination).
    pub fn last_entry(&self) -> Option<&ValPathEntry> {
        self.entries.last()
    }

    /// Whether this path contains a given key at the given parent path.
    pub fn contains_key_at(&self, key: &str, parent_path: &KeyPath) -> bool {
        self.entries
            .iter()
            .any(|e| e.key == key && &e.parent_path == parent_path)
    }

    /// The cumulative intersection of all entry lifespans.
    pub fn intersected_lifespan(&self) -> Option<Lifespan> {
        if self.entries.is_empty() {
            return Some(Lifespan::span(i64::MIN, i64::MAX));
        }
        let mut result = self.entries[0].lifespan;
        for entry in &self.entries[1..] {
            result = result.intersect(&entry.lifespan);
            if result.is_empty() {
                return None;
            }
        }
        Some(result)
    }
}

impl std::fmt::Display for ObjectValPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let path = self.get_path();
        write!(f, "{}", path)
    }
}

impl PartialOrd for ObjectValPath {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ObjectValPath {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.entries
            .len()
            .cmp(&other.entries.len())
            .then_with(|| {
                for (a, b) in self.entries.iter().zip(other.entries.iter()) {
                    let c = a.key.cmp(&b.key);
                    if c != std::cmp::Ordering::Equal {
                        return c;
                    }
                }
                std::cmp::Ordering::Equal
            })
    }
}

// ── Tree Traversal Framework ─────────────────────────────────────────────

/// The direction to compose paths during traversal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PathDirection {
    /// Paths grow from source toward destination (append).
    Forward,
    /// Paths grow from destination toward source (prepend).
    Backward,
}

/// Core tree traversal engine.
///
/// Ported from Ghidra's `TreeTraversal` enum singleton.
pub struct TreeTraversal;

impl TreeTraversal {
    /// Walk a value and possibly its subtree.
    pub fn walk_value<V: TreeVisitor>(
        visitor: &V,
        value_key: &str,
        value_lifespan: Lifespan,
        is_element: bool,
        parent_path: &KeyPath,
        span: Lifespan,
        path: &ObjectValPath,
    ) -> Vec<ObjectValPath> {
        let composed_span = visitor.compose_span(span, value_lifespan);
        if composed_span.is_empty() {
            return Vec::new();
        }
        let entry = ValPathEntry::new(value_key, value_lifespan, is_element, parent_path.clone());
        let composed_path = visitor.compose_path(path, entry);

        match visitor.visit_value(&composed_path) {
            VisitResult::IncludePrune => vec![composed_path],
            VisitResult::ExcludePrune => Vec::new(),
            VisitResult::IncludeDescend => {
                let result = vec![composed_path.clone()];
                // Would continue into child objects
                result
            }
            VisitResult::ExcludeDescend => {
                // Would continue into child objects but exclude this entry
                Vec::new()
            }
        }
    }
}

/// A visitor for tree traversal.
///
/// Ported from Ghidra's `TreeTraversal.Visitor` and `SpanIntersectingVisitor`.
pub trait TreeVisitor {
    /// Compose the span from the seed to and including the current value.
    /// Default implementation intersects.
    fn compose_span(&self, pre: Lifespan, value_lifespan: Lifespan) -> Lifespan {
        pre.intersect(&value_lifespan)
    }

    /// Compose the path from the seed to and including the current value.
    fn compose_path(&self, pre: &ObjectValPath, entry: ValPathEntry) -> ObjectValPath;

    /// Visit a value and decide how to proceed.
    fn visit_value(&self, path: &ObjectValPath) -> VisitResult;

    /// The path direction for this visitor.
    fn direction(&self) -> PathDirection;
}

// ── AllPathsVisitor ──────────────────────────────────────────────────────

/// Visitor that traverses all paths from a seed back to the root.
///
/// Ported from Ghidra's `AllPathsVisitor`. Follows parent edges
/// upward, including values along the way.
#[derive(Debug, Clone)]
pub struct AllPathsVisitor;

impl TreeVisitor for AllPathsVisitor {
    fn compose_path(&self, pre: &ObjectValPath, entry: ValPathEntry) -> ObjectValPath {
        pre.prepend(entry)
    }

    fn visit_value(&self, path: &ObjectValPath) -> VisitResult {
        if let Some(last) = path.last_entry() {
            // If parent is root, include and continue
            if last.parent_path.is_root() {
                return VisitResult::IncludeDescend;
            }
        }
        // Otherwise exclude but continue traversing upward
        VisitResult::ExcludeDescend
    }

    fn direction(&self) -> PathDirection {
        PathDirection::Backward
    }
}

// ── AncestorsRootVisitor ─────────────────────────────────────────────────

/// Visitor that traverses ancestors until reaching a path matching the
/// filter.
///
/// Ported from Ghidra's `AncestorsRootVisitor`.
#[derive(Debug, Clone)]
pub struct AncestorsRootVisitor {
    /// The filter to match against canonical paths.
    pub filter: PathMatcher,
}

impl AncestorsRootVisitor {
    /// Create a new visitor with the given filter.
    pub fn new(filter: PathMatcher) -> Self {
        Self { filter }
    }
}

impl TreeVisitor for AncestorsRootVisitor {
    fn compose_path(&self, pre: &ObjectValPath, entry: ValPathEntry) -> ObjectValPath {
        pre.prepend(entry)
    }

    fn visit_value(&self, path: &ObjectValPath) -> VisitResult {
        // Check if the parent path matches the filter
        if let Some(last) = path.last_entry() {
            let canonical = &last.parent_path;
            let matched = self.filter.matches(canonical);
            return VisitResult::result(matched, true);
        }
        VisitResult::ExcludeDescend
    }

    fn direction(&self) -> PathDirection {
        PathDirection::Backward
    }
}

// ── SuccessorsRelativeVisitor ────────────────────────────────────────────

/// Visitor that traverses successors matching a filter.
///
/// Ported from Ghidra's `SuccessorsRelativeVisitor`. Follows child
/// edges downward, pruning based on whether the filter could still
/// match the growing path.
#[derive(Debug, Clone)]
pub struct SuccessorsRelativeVisitor {
    /// The filter for matching successor paths.
    pub filter: PathMatcher,
}

impl SuccessorsRelativeVisitor {
    /// Create a new visitor with the given filter.
    pub fn new(filter: PathMatcher) -> Self {
        Self { filter }
    }
}

impl TreeVisitor for SuccessorsRelativeVisitor {
    fn compose_path(&self, pre: &ObjectValPath, entry: ValPathEntry) -> ObjectValPath {
        pre.append(entry)
    }

    fn visit_value(&self, path: &ObjectValPath) -> VisitResult {
        let key_path = path.get_path();
        let matched = self.filter.matches(&key_path);
        let can_continue = self.filter.successor_could_match(&key_path, true);
        VisitResult::result(matched, can_continue)
    }

    fn direction(&self) -> PathDirection {
        PathDirection::Forward
    }
}

// ── OrderedSuccessorsVisitor ─────────────────────────────────────────────

/// Visitor that traverses ordered successors along a fixed key path.
///
/// Ported from Ghidra's `OrderedSuccessorsVisitor`. Used when
/// searching for a specific element by its key path.
#[derive(Debug, Clone)]
pub struct OrderedSuccessorsVisitor {
    /// The target key path.
    pub target_path: KeyPath,
    /// Whether to search forward (ascending) or backward.
    pub forward: bool,
}

impl OrderedSuccessorsVisitor {
    /// Create a new ordered successors visitor.
    pub fn new(target_path: KeyPath, forward: bool) -> Self {
        Self {
            target_path,
            forward,
        }
    }
}

impl TreeVisitor for OrderedSuccessorsVisitor {
    fn compose_path(&self, pre: &ObjectValPath, entry: ValPathEntry) -> ObjectValPath {
        pre.append(entry)
    }

    fn visit_value(&self, path: &ObjectValPath) -> VisitResult {
        let current_path = path.get_path();
        if self.target_path == current_path {
            // Exact match - include and stop
            return VisitResult::IncludePrune;
        }
        // Check if a successor could still match
        if PathMatcher::from_patterns(&[PathPattern::new(self.target_path.clone())]).successor_could_match(&current_path, true) {
            VisitResult::ExcludeDescend
        } else {
            VisitResult::ExcludePrune
        }
    }

    fn direction(&self) -> PathDirection {
        PathDirection::Forward
    }
}

// ── CanonicalSuccessorsRelativeVisitor ───────────────────────────────────

/// Visitor that traverses canonical successors.
///
/// Ported from Ghidra's `CanonicalSuccessorsRelativeVisitor`.
/// Similar to `SuccessorsRelativeVisitor` but only follows canonical
/// parent-child edges.
#[derive(Debug, Clone)]
pub struct CanonicalSuccessorsRelativeVisitor {
    /// The filter for matching successor paths.
    pub filter: PathMatcher,
}

impl CanonicalSuccessorsRelativeVisitor {
    /// Create a new visitor with the given filter.
    pub fn new(filter: PathMatcher) -> Self {
        Self { filter }
    }
}

impl TreeVisitor for CanonicalSuccessorsRelativeVisitor {
    fn compose_path(&self, pre: &ObjectValPath, entry: ValPathEntry) -> ObjectValPath {
        pre.append(entry)
    }

    fn visit_value(&self, path: &ObjectValPath) -> VisitResult {
        let key_path = path.get_path();
        let matched = self.filter.matches(&key_path);
        let can_continue = self.filter.successor_could_match(&key_path, true)
            && path.last_entry().map_or(false, |e| !e.is_element || e.parent_path == KeyPath::ROOT);
        VisitResult::result(matched, can_continue)
    }

    fn direction(&self) -> PathDirection {
        PathDirection::Forward
    }
}

// ── AncestorsRelativeVisitor ─────────────────────────────────────────────

/// Visitor that traverses ancestors from a seed, looking for a filter match.
///
/// Ported from Ghidra's `AncestorsRelativeVisitor`.
#[derive(Debug, Clone)]
pub struct AncestorsRelativeVisitor {
    /// The filter to match against ancestor paths.
    pub filter: PathMatcher,
}

impl AncestorsRelativeVisitor {
    /// Create a new visitor with the given filter.
    pub fn new(filter: PathMatcher) -> Self {
        Self { filter }
    }
}

impl TreeVisitor for AncestorsRelativeVisitor {
    fn compose_path(&self, pre: &ObjectValPath, entry: ValPathEntry) -> ObjectValPath {
        pre.prepend(entry)
    }

    fn visit_value(&self, path: &ObjectValPath) -> VisitResult {
        if let Some(last) = path.last_entry() {
            let matched = self.filter.matches(&last.parent_path);
            VisitResult::result(matched, true)
        } else {
            VisitResult::ExcludeDescend
        }
    }

    fn direction(&self) -> PathDirection {
        PathDirection::Backward
    }
}

/// Utility function: enumerate all paths under a root matching a filter.
pub fn all_paths_under(
    filter: &PathMatcher,
    max_depth: usize,
) -> Vec<KeyPath> {
    // Return empty placeholder - in a real implementation this would
    // traverse the object tree using the filter
    let _ = (filter, max_depth);
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_object_val_path_empty() {
        let path = ObjectValPath::empty();
        assert!(path.is_empty());
        assert_eq!(path.len(), 0);
        assert!(path.first_entry().is_none());
        assert!(path.last_entry().is_none());
    }

    #[test]
    fn test_object_val_path_append() {
        let path = ObjectValPath::empty();
        let entry = ValPathEntry::new("Process", Lifespan::span(0, 10), false, KeyPath::ROOT);
        let path = path.append(entry);
        assert_eq!(path.len(), 1);
        assert_eq!(path.first_entry().unwrap().key, "Process");
    }

    #[test]
    fn test_object_val_path_prepend() {
        let path = ObjectValPath::empty();
        let entry1 = ValPathEntry::new("Thread", Lifespan::span(0, 5), false, KeyPath::ROOT);
        let entry2 = ValPathEntry::new("Process", Lifespan::span(0, 10), false, KeyPath::ROOT);
        let path = path.append(entry1).prepend(entry2);
        assert_eq!(path.len(), 2);
        assert_eq!(path.first_entry().unwrap().key, "Process");
        assert_eq!(path.last_entry().unwrap().key, "Thread");
    }

    #[test]
    fn test_object_val_path_get_path() {
        let path = ObjectValPath::empty();
        let entry1 = ValPathEntry::new("Process", Lifespan::span(0, 10), false, KeyPath::ROOT);
        let entry2 = ValPathEntry::new("Thread", Lifespan::span(0, 5), false, KeyPath::ROOT);
        let path = path.append(entry1).append(entry2);
        let key_path = path.get_path();
        assert_eq!(key_path.size(), 2);
    }

    #[test]
    fn test_object_val_path_lifespan_intersection() {
        let path = ObjectValPath::empty();
        let entry1 = ValPathEntry::new("a", Lifespan::span(0, 10), false, KeyPath::ROOT);
        let entry2 = ValPathEntry::new("b", Lifespan::span(5, 15), false, KeyPath::ROOT);
        let path = path.append(entry1).append(entry2);
        let lifespan = path.intersected_lifespan().unwrap();
        assert_eq!(lifespan.lmin(), 5);
        assert_eq!(lifespan.lmax(), 10);
    }

    #[test]
    fn test_object_val_path_lifespan_disjoint() {
        let path = ObjectValPath::empty();
        let entry1 = ValPathEntry::new("a", Lifespan::span(0, 5), false, KeyPath::ROOT);
        let entry2 = ValPathEntry::new("b", Lifespan::span(10, 15), false, KeyPath::ROOT);
        let path = path.append(entry1).append(entry2);
        assert!(path.intersected_lifespan().is_none());
    }

    #[test]
    fn test_object_val_path_ordering() {
        let path1 = ObjectValPath::empty().append(ValPathEntry::new(
            "a",
            Lifespan::span(0, 10),
            false,
            KeyPath::ROOT,
        ));
        let path2 = ObjectValPath::empty().append(ValPathEntry::new(
            "b",
            Lifespan::span(0, 10),
            false,
            KeyPath::ROOT,
        ));
        assert!(path1 < path2);
    }

    #[test]
    fn test_object_val_path_display() {
        let path = ObjectValPath::empty().append(ValPathEntry::new(
            "Process",
            Lifespan::span(0, 10),
            false,
            KeyPath::ROOT,
        ));
        let display = format!("{}", path);
        assert!(!display.is_empty());
    }

    #[test]
    fn test_visit_result_helpers() {
        assert_eq!(VisitResult::result(true, true), VisitResult::IncludeDescend);
        assert_eq!(VisitResult::result(true, false), VisitResult::IncludePrune);
        assert_eq!(VisitResult::result(false, true), VisitResult::ExcludeDescend);
        assert_eq!(VisitResult::result(false, false), VisitResult::ExcludePrune);
    }

    #[test]
    fn test_all_paths_visitor() {
        let visitor = AllPathsVisitor;
        assert_eq!(visitor.direction(), PathDirection::Backward);

        let path = ObjectValPath::empty();
        let entry = ValPathEntry::new("root", Lifespan::span(0, 10), false, KeyPath::ROOT);
        let composed = visitor.compose_path(&path, entry);
        assert_eq!(composed.len(), 1);
    }

    #[test]
    fn test_successors_visitor() {
        let filter = PathMatcher::from_patterns(&[PathPattern::new(KeyPath::of(&["Process", "Thread"]))]);
        let visitor = SuccessorsRelativeVisitor::new(filter);
        assert_eq!(visitor.direction(), PathDirection::Forward);
    }

    #[test]
    fn test_ordered_successors_visitor() {
        let target = KeyPath::of(&["Process", "42", "Thread"]);
        let visitor = OrderedSuccessorsVisitor::new(target, true);
        assert!(visitor.forward);
    }

    #[test]
    fn test_canonical_successors_visitor() {
        let filter = PathMatcher::from_patterns(&[PathPattern::new(KeyPath::of(&["Process"]))]);
        let visitor = CanonicalSuccessorsRelativeVisitor::new(filter);
        assert_eq!(visitor.direction(), PathDirection::Forward);
    }

    #[test]
    fn test_ancestors_root_visitor() {
        let filter = PathMatcher::from_patterns(&[PathPattern::new(KeyPath::ROOT)]);
        let visitor = AncestorsRootVisitor::new(filter);
        assert_eq!(visitor.direction(), PathDirection::Backward);
    }

    #[test]
    fn test_ancestors_relative_visitor() {
        let filter = PathMatcher::from_patterns(&[PathPattern::new(KeyPath::of(&["Process"]))]);
        let visitor = AncestorsRelativeVisitor::new(filter);
        assert_eq!(visitor.direction(), PathDirection::Backward);
    }

    #[test]
    fn test_val_path_entry_contains() {
        let path = ObjectValPath::empty()
            .append(ValPathEntry::new("a", Lifespan::span(0, 10), false, KeyPath::ROOT))
            .append(ValPathEntry::new("b", Lifespan::span(0, 10), false, KeyPath::ROOT));
        assert!(path.contains_key_at("a", &KeyPath::ROOT));
        assert!(!path.contains_key_at("c", &KeyPath::ROOT));
    }
}
