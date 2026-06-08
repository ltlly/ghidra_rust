//! Function Edge Cache -- caches known function edges.
//!
//! Ported from Ghidra's `functioncalls.plugin.FunctionEdgeCache` Java class.
//!
//! Tracks all known edges between functions, even those not currently
//! shown in the graph.  Also tracks which functions have been fully
//! processed for their incoming and outgoing connections.

use std::collections::{HashMap, HashSet};

use super::function_edge::FunctionEdge;

/// A cache of known function edges.
///
/// Ported from `functioncalls.plugin.FunctionEdgeCache`.
///
/// Having a function as a key in `all_edges_by_function` is not enough
/// to know if it has been processed already (as the function can be
/// added by processing edges of other nodes).  Being in `tracked`
/// means that it has been processed for its incoming and outgoing
/// connections.
#[derive(Debug, Clone, Default)]
pub struct FunctionEdgeCache {
    /// All known edges grouped by source function address.
    all_edges_by_function: HashMap<u64, HashSet<FunctionEdge>>,
    /// Functions that have been fully processed.
    tracked: HashSet<u64>,
}

impl FunctionEdgeCache {
    /// Create a new empty cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get all edges for a function.
    ///
    /// Returns an empty set if the function has no known edges.
    pub fn get(&self, function_address: u64) -> Vec<&FunctionEdge> {
        self.all_edges_by_function
            .get(&function_address)
            .map(|set| set.iter().collect())
            .unwrap_or_default()
    }

    /// Get the number of edges for a function.
    pub fn edge_count(&self, function_address: u64) -> usize {
        self.all_edges_by_function
            .get(&function_address)
            .map(|set| set.len())
            .unwrap_or(0)
    }

    /// Add an edge to the cache.
    pub fn add_edge(&mut self, edge: FunctionEdge) {
        self.all_edges_by_function
            .entry(edge.start())
            .or_default()
            .insert(edge);
    }

    /// Check if a function has been tracked (fully processed).
    pub fn is_tracked(&self, function_address: u64) -> bool {
        self.tracked.contains(&function_address)
    }

    /// Mark a function as tracked (fully processed).
    pub fn set_tracked(&mut self, function_address: u64) {
        self.tracked.insert(function_address);
    }

    /// Get all tracked function addresses.
    pub fn tracked_functions(&self) -> &HashSet<u64> {
        &self.tracked
    }

    /// Get the total number of unique edges in the cache.
    pub fn total_edge_count(&self) -> usize {
        self.all_edges_by_function
            .values()
            .map(|set| set.len())
            .sum()
    }

    /// Get the number of functions with known edges.
    pub fn function_count(&self) -> usize {
        self.all_edges_by_function.len()
    }

    /// Check if the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.all_edges_by_function.is_empty()
    }

    /// Clear the cache.
    pub fn clear(&mut self) {
        self.all_edges_by_function.clear();
        self.tracked.clear();
    }

    /// Get all edges in the cache (deduplicated).
    pub fn all_edges(&self) -> Vec<&FunctionEdge> {
        let mut seen = HashSet::new();
        let mut result = Vec::new();
        for edges in self.all_edges_by_function.values() {
            for edge in edges {
                if seen.insert(edge) {
                    result.push(edge);
                }
            }
        }
        result
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_cache() {
        let cache = FunctionEdgeCache::new();
        assert!(cache.is_empty());
        assert_eq!(cache.total_edge_count(), 0);
        assert_eq!(cache.function_count(), 0);
    }

    #[test]
    fn test_add_edge() {
        let mut cache = FunctionEdgeCache::new();
        cache.add_edge(FunctionEdge::new(0x1000, 0x2000));

        assert!(!cache.is_empty());
        assert_eq!(cache.total_edge_count(), 1);
        assert_eq!(cache.edge_count(0x1000), 1);
    }

    #[test]
    fn test_get_edges() {
        let mut cache = FunctionEdgeCache::new();
        cache.add_edge(FunctionEdge::new(0x1000, 0x2000));
        cache.add_edge(FunctionEdge::new(0x1000, 0x3000));

        let edges = cache.get(0x1000);
        assert_eq!(edges.len(), 2);
    }

    #[test]
    fn test_get_edges_empty() {
        let cache = FunctionEdgeCache::new();
        let edges = cache.get(0x9999);
        assert!(edges.is_empty());
    }

    #[test]
    fn test_tracked() {
        let mut cache = FunctionEdgeCache::new();
        assert!(!cache.is_tracked(0x1000));

        cache.set_tracked(0x1000);
        assert!(cache.is_tracked(0x1000));
        assert!(!cache.is_tracked(0x2000));
    }

    #[test]
    fn test_tracked_functions() {
        let mut cache = FunctionEdgeCache::new();
        cache.set_tracked(0x1000);
        cache.set_tracked(0x2000);

        let tracked = cache.tracked_functions();
        assert_eq!(tracked.len(), 2);
        assert!(tracked.contains(&0x1000));
        assert!(tracked.contains(&0x2000));
    }

    #[test]
    fn test_all_edges_dedup() {
        let mut cache = FunctionEdgeCache::new();
        cache.add_edge(FunctionEdge::new(0x1000, 0x2000));
        cache.add_edge(FunctionEdge::new(0x1000, 0x3000));
        cache.add_edge(FunctionEdge::new(0x2000, 0x3000));

        let all = cache.all_edges();
        assert_eq!(all.len(), 3);
    }

    #[test]
    fn test_clear() {
        let mut cache = FunctionEdgeCache::new();
        cache.add_edge(FunctionEdge::new(0x1000, 0x2000));
        cache.set_tracked(0x1000);

        cache.clear();
        assert!(cache.is_empty());
        assert!(!cache.is_tracked(0x1000));
    }

    #[test]
    fn test_function_count() {
        let mut cache = FunctionEdgeCache::new();
        cache.add_edge(FunctionEdge::new(0x1000, 0x2000));
        cache.add_edge(FunctionEdge::new(0x1000, 0x3000));
        cache.add_edge(FunctionEdge::new(0x2000, 0x3000));

        assert_eq!(cache.function_count(), 2); // 0x1000 and 0x2000 as sources
    }

    #[test]
    fn test_clone() {
        let mut cache = FunctionEdgeCache::new();
        cache.add_edge(FunctionEdge::new(0x1000, 0x2000));
        cache.set_tracked(0x1000);

        let cloned = cache.clone();
        assert_eq!(cloned.total_edge_count(), 1);
        assert!(cloned.is_tracked(0x1000));
    }
}
