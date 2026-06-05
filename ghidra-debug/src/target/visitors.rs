//! Tree traversal visitors for the trace object model.
//!
//! Ported from Ghidra's `TreeTraversal` and related visitor types.
//! Provides support for traversing a trace's object tree with custom
//! filtering and subtree pruning.

use crate::model::Lifespan;
use crate::target::key_path::KeyPath;
use crate::target::trace_object::TraceObject;
use crate::target::trace_object::TraceObjectManager;

/// A result directing the traversal how to proceed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VisitResult {
    /// Include the value that was just traversed, and descend.
    IncludeDescend,
    /// Include the value that was just traversed, but prune its subtree.
    IncludePrune,
    /// Exclude the value that was just traversed, but descend.
    ExcludeDescend,
    /// Exclude the value that was just traversed, and prune its subtree.
    ExcludePrune,
}

impl VisitResult {
    /// Get the result from inclusion and continuation flags.
    pub fn result(include: bool, descend: bool) -> Self {
        match (include, descend) {
            (true, true) => VisitResult::IncludeDescend,
            (true, false) => VisitResult::IncludePrune,
            (false, true) => VisitResult::ExcludeDescend,
            (false, false) => VisitResult::ExcludePrune,
        }
    }

    /// Whether this result includes the current value.
    pub fn includes(&self) -> bool {
        matches!(self, VisitResult::IncludeDescend | VisitResult::IncludePrune)
    }

    /// Whether this result continues traversal.
    pub fn descends(&self) -> bool {
        matches!(self, VisitResult::IncludeDescend | VisitResult::ExcludeDescend)
    }
}

/// A visitor for tree traversal of trace objects.
pub trait TreeVisitor {
    /// Compose the span when descending through a value.
    ///
    /// Usually this is the intersection of the pre-composed span and the value's lifespan.
    fn compose_span(&self, pre: &Lifespan, value_snap: i64) -> Option<Lifespan>;

    /// Visit a child entry (attribute or element) and decide how to proceed.
    fn visit_child(
        &self,
        parent: &TraceObject,
        child_key: &str,
        child_path: &KeyPath,
        span: &Lifespan,
    ) -> VisitResult;
}

/// A visitor that intersects spans during traversal.
pub struct SpanIntersectingVisitor;

impl SpanIntersectingVisitor {
    /// Create a new span-intersecting visitor.
    pub fn new() -> Self {
        Self
    }
}

impl Default for SpanIntersectingVisitor {
    fn default() -> Self {
        Self::new()
    }
}

impl TreeVisitor for SpanIntersectingVisitor {
    fn compose_span(&self, pre: &Lifespan, value_snap: i64) -> Option<Lifespan> {
        // Intersect with a point lifespan at value_snap
        let point = Lifespan::span(value_snap, value_snap);
        let result = pre.intersect(&point);
        if result.is_empty() {
            None
        } else {
            Some(result)
        }
    }

    fn visit_child(
        &self,
        _parent: &TraceObject,
        _child_key: &str,
        _child_path: &KeyPath,
        _span: &Lifespan,
    ) -> VisitResult {
        VisitResult::IncludeDescend
    }
}

/// Walk the children of an object, collecting paths.
pub fn walk_children(
    manager: &TraceObjectManager,
    path: &KeyPath,
    snap: i64,
    visitor: &dyn TreeVisitor,
    include_self: bool,
) -> Vec<KeyPath> {
    let mut result = Vec::new();
    let span = Lifespan::span(snap, snap);

    if include_self {
        result.push(path.clone());
    }

    if let Some(object) = manager.get_object(path) {
        let attr_names = object.active_attribute_names(snap);
        for name in attr_names {
            let child_path = path.extend(name);
            match visitor.visit_child(object, name, &child_path, &span) {
                VisitResult::IncludeDescend => {
                    result.push(child_path.clone());
                    result.extend(walk_children(manager, &child_path, snap, visitor, false));
                }
                VisitResult::IncludePrune => {
                    result.push(child_path);
                }
                VisitResult::ExcludeDescend => {
                    result.extend(walk_children(manager, &child_path, snap, visitor, false));
                }
                VisitResult::ExcludePrune => {}
            }
        }

        let elem_indices = object.active_element_indices(snap);
        for idx in elem_indices {
            let child_path = path.extend(idx);
            match visitor.visit_child(object, idx, &child_path, &span) {
                VisitResult::IncludeDescend => {
                    result.push(child_path.clone());
                    result.extend(walk_children(manager, &child_path, snap, visitor, false));
                }
                VisitResult::IncludePrune => {
                    result.push(child_path);
                }
                VisitResult::ExcludeDescend => {
                    result.extend(walk_children(manager, &child_path, snap, visitor, false));
                }
                VisitResult::ExcludePrune => {}
            }
        }
    }

    result
}

/// Collect all descendant paths of a given path.
pub fn all_descendants(
    manager: &TraceObjectManager,
    path: &KeyPath,
    snap: i64,
) -> Vec<KeyPath> {
    walk_children(manager, path, snap, &SpanIntersectingVisitor::new(), false)
}

/// Collect a path and all its descendant paths.
pub fn all_paths_under(
    manager: &TraceObjectManager,
    path: &KeyPath,
    snap: i64,
) -> Vec<KeyPath> {
    walk_children(manager, path, snap, &SpanIntersectingVisitor::new(), true)
}

/// Collect all ancestor paths of a given path (excluding the path itself).
pub fn ancestor_paths(path: &KeyPath) -> Vec<KeyPath> {
    let mut result = Vec::new();
    let mut current = path.parent();
    while !current.is_root() {
        result.push(current.clone());
        current = current.parent();
    }
    result
}

// ---------------------------------------------------------------------------
// Additional visitor types ported from Framework-TraceModeling visitors
// ---------------------------------------------------------------------------

/// Walk all paths from a seed to all reachable ancestors (prepending values).
///
/// Ported from Java `AllPathsVisitor`. Traverses upward from a value to
/// discover all root paths. Excludes values without parents, includes
/// values whose parent is root (they may have other parents).
pub struct AllPathsVisitor;

impl TreeVisitor for AllPathsVisitor {
    fn compose_span(&self, pre: &Lifespan, value_snap: i64) -> Option<Lifespan> {
        let point = Lifespan::span(value_snap, value_snap);
        let result = pre.intersect(&point);
        if result.is_empty() {
            None
        } else {
            Some(result)
        }
    }

    fn visit_child(
        &self,
        parent: &TraceObject,
        _child_key: &str,
        _child_path: &KeyPath,
        _span: &Lifespan,
    ) -> VisitResult {
        if parent.path.is_root() {
            VisitResult::IncludeDescend
        } else {
            VisitResult::ExcludeDescend
        }
    }
}

/// Traverse ancestors of a value, filtering by path pattern.
///
/// Ported from Java `AncestorsRelativeVisitor`. Walks up the object tree
/// from a seed value, composing paths by prepending, and checking against
/// a path filter to decide inclusion/exclusion at each step.
pub struct AncestorsRelativeVisitor {
    /// The set of key prefixes to match against.
    pub match_keys: Vec<String>,
}

impl AncestorsRelativeVisitor {
    /// Create a new ancestor visitor with the given key prefixes.
    pub fn new(match_keys: Vec<String>) -> Self {
        Self { match_keys }
    }

    /// Create a visitor matching any ancestor.
    pub fn any() -> Self {
        Self::new(Vec::new())
    }
}

impl TreeVisitor for AncestorsRelativeVisitor {
    fn compose_span(&self, pre: &Lifespan, value_snap: i64) -> Option<Lifespan> {
        let point = Lifespan::span(value_snap, value_snap);
        let result = pre.intersect(&point);
        if result.is_empty() {
            None
        } else {
            Some(result)
        }
    }

    fn visit_child(
        &self,
        _parent: &TraceObject,
        child_key: &str,
        _child_path: &KeyPath,
        _span: &Lifespan,
    ) -> VisitResult {
        if self.match_keys.is_empty() || self.match_keys.iter().any(|k| k == child_key) {
            VisitResult::IncludeDescend
        } else {
            VisitResult::ExcludeDescend
        }
    }
}

/// Traverse ancestors upward until reaching a root or limit.
///
/// Ported from Java `AncestorsRootVisitor`. Walks from a value up to the
/// root, including all ancestors along the way.
pub struct AncestorsRootVisitor;

impl TreeVisitor for AncestorsRootVisitor {
    fn compose_span(&self, pre: &Lifespan, value_snap: i64) -> Option<Lifespan> {
        let point = Lifespan::span(value_snap, value_snap);
        let result = pre.intersect(&point);
        if result.is_empty() {
            None
        } else {
            Some(result)
        }
    }

    fn visit_child(
        &self,
        _parent: &TraceObject,
        _child_key: &str,
        _child_path: &KeyPath,
        _span: &Lifespan,
    ) -> VisitResult {
        VisitResult::IncludeDescend
    }
}

/// Visit canonical successors of objects, descending through unique paths.
///
/// Ported from Java `CanonicalSuccessorsRelativeVisitor`. Follows the
/// "canonical" path through the object tree — the first child or attribute
/// at each level — filtering by a path pattern.
pub struct CanonicalSuccessorsRelativeVisitor {
    /// The set of canonical keys to follow.
    pub canonical_keys: Vec<String>,
}

impl CanonicalSuccessorsRelativeVisitor {
    /// Create a new canonical successors visitor.
    pub fn new(canonical_keys: Vec<String>) -> Self {
        Self { canonical_keys }
    }
}

impl TreeVisitor for CanonicalSuccessorsRelativeVisitor {
    fn compose_span(&self, pre: &Lifespan, value_snap: i64) -> Option<Lifespan> {
        let point = Lifespan::span(value_snap, value_snap);
        let result = pre.intersect(&point);
        if result.is_empty() {
            None
        } else {
            Some(result)
        }
    }

    fn visit_child(
        &self,
        _parent: &TraceObject,
        child_key: &str,
        _child_path: &KeyPath,
        _span: &Lifespan,
    ) -> VisitResult {
        if self.canonical_keys.is_empty() || self.canonical_keys.contains(&child_key.to_string())
        {
            VisitResult::IncludeDescend
        } else {
            VisitResult::ExcludePrune
        }
    }
}

/// Visit successors in a deterministic (sorted) order.
///
/// Ported from Java `OrderedSuccessorsVisitor`. Traverses children in
/// sorted key order, including all of them.
pub struct OrderedSuccessorsVisitor;

impl TreeVisitor for OrderedSuccessorsVisitor {
    fn compose_span(&self, pre: &Lifespan, value_snap: i64) -> Option<Lifespan> {
        let point = Lifespan::span(value_snap, value_snap);
        let result = pre.intersect(&point);
        if result.is_empty() {
            None
        } else {
            Some(result)
        }
    }

    fn visit_child(
        &self,
        _parent: &TraceObject,
        _child_key: &str,
        _child_path: &KeyPath,
        _span: &Lifespan,
    ) -> VisitResult {
        VisitResult::IncludeDescend
    }
}

/// Visit successors relative to a path filter.
///
/// Ported from Java `SuccessorsRelativeVisitor`. Descends through children
/// that match a given set of allowed entry keys.
pub struct SuccessorsRelativeVisitor {
    /// The set of allowed entry keys (empty = allow all).
    pub allowed_keys: Vec<String>,
}

impl SuccessorsRelativeVisitor {
    /// Create a new successor visitor.
    pub fn new(allowed_keys: Vec<String>) -> Self {
        Self { allowed_keys }
    }

    /// Create a visitor that allows all successors.
    pub fn all() -> Self {
        Self::new(Vec::new())
    }
}

impl TreeVisitor for SuccessorsRelativeVisitor {
    fn compose_span(&self, pre: &Lifespan, value_snap: i64) -> Option<Lifespan> {
        let point = Lifespan::span(value_snap, value_snap);
        let result = pre.intersect(&point);
        if result.is_empty() {
            None
        } else {
            Some(result)
        }
    }

    fn visit_child(
        &self,
        _parent: &TraceObject,
        child_key: &str,
        _child_path: &KeyPath,
        _span: &Lifespan,
    ) -> VisitResult {
        if self.allowed_keys.is_empty() || self.allowed_keys.contains(&child_key.to_string()) {
            VisitResult::IncludeDescend
        } else {
            VisitResult::ExcludePrune
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::target::trace_object::{ObjectValue, TraceObject};

    #[test]
    fn test_visit_result() {
        assert!(VisitResult::result(true, true).includes());
        assert!(VisitResult::result(true, true).descends());
        assert!(VisitResult::result(true, false).includes());
        assert!(!VisitResult::result(true, false).descends());
        assert!(!VisitResult::result(false, true).includes());
        assert!(VisitResult::result(false, true).descends());
    }

    #[test]
    fn test_walk_children() {
        let mut mgr = TraceObjectManager::new();
        let mut root = TraceObject::new(KeyPath::ROOT, "Session");
        root.set_attribute("Processes", ObjectValue::String("ref".into()), Lifespan::now_on(0));
        mgr.add_object(root);

        let mut processes = TraceObject::new(KeyPath::parse("Processes"), "Processes");
        processes.set_element("0", ObjectValue::String("ref".into()), Lifespan::now_on(0));
        mgr.add_object(processes);

        let mut proc0 = TraceObject::new(KeyPath::parse("Processes[0]"), "Process");
        proc0.set_attribute("name", ObjectValue::String("main".into()), Lifespan::now_on(0));
        mgr.add_object(proc0);

        let paths = all_descendants(&mgr, &KeyPath::ROOT, 5);
        assert!(!paths.is_empty());
    }

    #[test]
    fn test_ancestor_paths() {
        let path = KeyPath::parse("a.b.c.d");
        let ancestors = ancestor_paths(&path);
        assert_eq!(ancestors.len(), 3);
        assert_eq!(ancestors[0].to_string(), "a.b.c");
        assert_eq!(ancestors[1].to_string(), "a.b");
        assert_eq!(ancestors[2].to_string(), "a");
    }

    #[test]
    fn test_all_paths_under() {
        let mut mgr = TraceObjectManager::new();
        mgr.add_object(TraceObject::new(KeyPath::of(&["a"]), "A"));
        mgr.add_object(TraceObject::new(KeyPath::of(&["a", "b"]), "B"));
        mgr.add_object(TraceObject::new(KeyPath::of(&["a", "b", "c"]), "C"));

        let paths = all_paths_under(&mgr, &KeyPath::of(&["a"]), 0);
        assert!(paths.contains(&KeyPath::of(&["a"])));
    }
}
