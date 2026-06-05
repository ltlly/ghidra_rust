//! Namespace symbol implementation for the trace database.
//!
//! Ported from Ghidra's `DBTraceNamespaceSymbol` in
//! `ghidra.trace.database.symbol`. Namespaces organize symbols into
//! hierarchies (e.g., library::module::function).

use serde::{Deserialize, Serialize};

use crate::model::Lifespan;

/// A namespace symbol entry in the trace database.
///
/// Ported from Ghidra's `DBTraceNamespaceSymbol`. Namespaces form a
/// tree structure used to organize symbols hierarchically.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbTraceNamespaceSymbol {
    /// Database row ID.
    pub id: i64,
    /// The namespace name.
    pub name: String,
    /// Parent namespace ID (-1 for global).
    pub parent_id: i64,
    /// Source type.
    pub source: u8,
}

impl DbTraceNamespaceSymbol {
    /// Create a new namespace symbol.
    pub fn new(id: i64, name: impl Into<String>, parent_id: i64, source: u8) -> Self {
        Self {
            id,
            name: name.into(),
            parent_id,
            source,
        }
    }

    /// Whether this is the global namespace.
    pub fn is_global(&self) -> bool {
        self.parent_id == -1
    }

    /// Get the depth of this namespace in the hierarchy.
    /// Global is depth 0, its children are depth 1, etc.
    pub fn depth(&self, get_parent: impl Fn(i64) -> Option<i64>) -> usize {
        if self.is_global() {
            return 0;
        }
        let mut depth = 1;
        let mut current = self.parent_id;
        while let Some(pid) = get_parent(current) {
            if pid == -1 {
                break;
            }
            depth += 1;
            current = pid;
        }
        depth
    }
}

/// A namespace view for filtering symbols by namespace.
#[derive(Debug, Clone)]
pub struct DbTraceNamespaceSymbolView {
    /// The namespace ID this view is scoped to.
    pub namespace_id: i64,
    /// Whether to include child namespaces recursively.
    pub recursive: bool,
}

impl DbTraceNamespaceSymbolView {
    /// Create a new namespace view.
    pub fn new(namespace_id: i64, recursive: bool) -> Self {
        Self {
            namespace_id,
            recursive,
        }
    }

    /// Whether a symbol with the given parent ID is in scope.
    pub fn is_in_scope(&self, parent_id: i64, is_descendant: impl Fn(i64, i64) -> bool) -> bool {
        if parent_id == self.namespace_id {
            return true;
        }
        if self.recursive {
            return is_descendant(parent_id, self.namespace_id);
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_namespace_creation() {
        let ns = DbTraceNamespaceSymbol::new(1, "mylib", 0, 0);
        assert_eq!(ns.name, "mylib");
        assert_eq!(ns.parent_id, 0);
        assert!(!ns.is_global());
    }

    #[test]
    fn test_global_namespace() {
        let global = DbTraceNamespaceSymbol::new(0, "Global", -1, 3);
        assert!(global.is_global());
    }

    #[test]
    fn test_namespace_depth() {
        let ns = DbTraceNamespaceSymbol::new(3, "leaf", 2, 0);
        // Simulate: 3 -> 2 -> 1 -> 0(global, parent=-1)
        let get_parent = |id: i64| -> Option<i64> {
            match id {
                3 => Some(2),
                2 => Some(1),
                1 => Some(0),
                0 => Some(-1),
                _ => None,
            }
        };
        assert_eq!(ns.depth(get_parent), 3);
    }

    #[test]
    fn test_namespace_view() {
        let view = DbTraceNamespaceSymbolView::new(10, false);
        assert!(view.is_in_scope(10, |_, _| false));
        assert!(!view.is_in_scope(20, |_, _| false));

        let recursive_view = DbTraceNamespaceSymbolView::new(10, true);
        assert!(recursive_view.is_in_scope(10, |_, _| false));
        assert!(recursive_view.is_in_scope(20, |child, parent| child == 20 && parent == 10));
    }
}
