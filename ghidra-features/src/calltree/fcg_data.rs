//! Function Call Graph data abstraction.
//!
//! Ported from Ghidra's `functioncalls.plugin.FcgData` Java interface,
//! `functioncalls.plugin.ValidFcgData`, `functioncalls.plugin.EmptyFcgData`,
//! and `functioncalls.plugin.FcgDataFactory`.
//!
//! Provides a trait-based abstraction over graph data that allows clients
//! to retrieve and work on the graph and its related data, with support
//! for caching and empty/null-safe variants.

use super::fcg_edge::FcgEdge;
use super::fcg_vertex::FcgVertex;
use super::function_call_graph::FunctionCallGraph;
use super::function_edge_cache::FunctionEdgeCache;

/// Trait for Function Call Graph data.
///
/// Ported from the `FcgData` Java interface.
///
/// This trait allows clients to retrieve and work on the graph and its
/// related data.  It also makes caching the data simple.
pub trait FcgDataProvider: std::fmt::Debug {
    /// The function address of this data.
    fn function_address(&self) -> Option<u64>;

    /// The function name of this data.
    fn function_name(&self) -> Option<&str>;

    /// Get a reference to the graph.
    fn graph(&self) -> Option<&FunctionCallGraph>;

    /// Get a mutable reference to the graph.
    fn graph_mut(&mut self) -> Option<&mut FunctionCallGraph>;

    /// Get the function edge cache.
    fn function_edge_cache(&self) -> Option<&FunctionEdgeCache>;

    /// Get a mutable reference to the function edge cache.
    fn function_edge_cache_mut(&mut self) -> Option<&mut FunctionEdgeCache>;

    /// True if this data has a valid function.
    fn has_results(&self) -> bool;

    /// False if the graph in this data has not yet been loaded.
    fn is_initialized(&self) -> bool;

    /// Dispose the contents of this data.
    fn dispose(&mut self);

    /// Check if this data's function matches the given address.
    fn is_function(&self, address: u64) -> bool;

    /// Clone the graph data.
    fn clone_data(&self) -> Box<dyn FcgDataProvider>;
}

// ---------------------------------------------------------------------------
// ValidFcgData -- a valid, populated graph data
// ---------------------------------------------------------------------------

/// A valid graph data object that contains a function and its call graph.
///
/// Ported from `functioncalls.plugin.ValidFcgData`.
#[derive(Debug, Clone)]
pub struct ValidFcgData {
    /// The function address.
    function_address: u64,
    /// The function name.
    function_name: String,
    /// The function call graph.
    graph: FunctionCallGraph,
    /// Cache of all known function edges.
    edge_cache: FunctionEdgeCache,
}

impl ValidFcgData {
    /// Create a new valid FCG data.
    pub fn new(function_address: u64, function_name: impl Into<String>, graph: FunctionCallGraph) -> Self {
        Self {
            function_address,
            function_name: function_name.into(),
            graph,
            edge_cache: FunctionEdgeCache::new(),
        }
    }

    /// Get the function address.
    pub fn address(&self) -> u64 {
        self.function_address
    }

    /// Get the function name.
    pub fn name(&self) -> &str {
        &self.function_name
    }
}

impl FcgDataProvider for ValidFcgData {
    fn function_address(&self) -> Option<u64> {
        Some(self.function_address)
    }

    fn function_name(&self) -> Option<&str> {
        Some(&self.function_name)
    }

    fn graph(&self) -> Option<&FunctionCallGraph> {
        Some(&self.graph)
    }

    fn graph_mut(&mut self) -> Option<&mut FunctionCallGraph> {
        Some(&mut self.graph)
    }

    fn function_edge_cache(&self) -> Option<&FunctionEdgeCache> {
        Some(&self.edge_cache)
    }

    fn function_edge_cache_mut(&mut self) -> Option<&mut FunctionEdgeCache> {
        Some(&mut self.edge_cache)
    }

    fn has_results(&self) -> bool {
        true
    }

    fn is_initialized(&self) -> bool {
        !self.graph.is_empty()
    }

    fn dispose(&mut self) {
        self.graph.dispose();
    }

    fn is_function(&self, address: u64) -> bool {
        self.function_address == address
    }

    fn clone_data(&self) -> Box<dyn FcgDataProvider> {
        Box::new(ValidFcgData {
            function_address: self.function_address,
            function_name: self.function_name.clone(),
            graph: self.graph.clone_graph(),
            edge_cache: self.edge_cache.clone(),
        })
    }
}

// ---------------------------------------------------------------------------
// EmptyFcgData -- a null-safe empty data object
// ---------------------------------------------------------------------------

/// An empty data object used to avoid null checks.
///
/// Ported from `functioncalls.plugin.EmptyFcgData`.
#[derive(Debug, Clone)]
pub struct EmptyFcgData;

impl FcgDataProvider for EmptyFcgData {
    fn function_address(&self) -> Option<u64> {
        None
    }

    fn function_name(&self) -> Option<&str> {
        None
    }

    fn graph(&self) -> Option<&FunctionCallGraph> {
        None
    }

    fn graph_mut(&mut self) -> Option<&mut FunctionCallGraph> {
        None
    }

    fn function_edge_cache(&self) -> Option<&FunctionEdgeCache> {
        None
    }

    fn function_edge_cache_mut(&mut self) -> Option<&mut FunctionEdgeCache> {
        None
    }

    fn has_results(&self) -> bool {
        false
    }

    fn is_initialized(&self) -> bool {
        false
    }

    fn dispose(&mut self) {
        // nothing to do
    }

    fn is_function(&self, _address: u64) -> bool {
        false
    }

    fn clone_data(&self) -> Box<dyn FcgDataProvider> {
        Box::new(EmptyFcgData)
    }
}

// ---------------------------------------------------------------------------
// FcgDataFactory -- creates and caches FcgData objects
// ---------------------------------------------------------------------------

/// A factory that creates [`FcgDataProvider`] objects for functions.
///
/// Ported from `functioncalls.plugin.FcgDataFactory`.
///
/// Internally uses an MRU-style cache (limited to a configurable
/// maximum number of entries).  When the cache is full, the least
/// recently used entry is evicted and disposed.
#[derive(Debug)]
pub struct FcgDataFactory {
    /// Cache of function address -> data.
    cache: Vec<(u64, ValidFcgData)>,
    /// Maximum cache size.
    max_size: usize,
}

impl FcgDataFactory {
    /// Create a new factory with the default cache size (5).
    pub fn new() -> Self {
        Self::with_capacity(5)
    }

    /// Create a new factory with a specific cache size.
    pub fn with_capacity(max_size: usize) -> Self {
        Self {
            cache: Vec::new(),
            max_size,
        }
    }

    /// Create or retrieve graph data for a function.
    ///
    /// If the function address is `None`, returns an empty data object.
    /// If the function is already in the cache, returns the cached data.
    /// Otherwise, creates a new data object and caches it.
    pub fn create(&mut self, function_address: Option<u64>, function_name: &str) -> Box<dyn FcgDataProvider> {
        let addr = match function_address {
            Some(a) => a,
            None => return Box::new(EmptyFcgData),
        };

        // Check cache
        if let Some(idx) = self.cache.iter().position(|(a, _)| *a == addr) {
            // Move to front (MRU)
            let entry = self.cache.remove(idx);
            self.cache.insert(0, entry);
            return self.cache[0].1.clone_data();
        }

        // Evict if full
        while self.cache.len() >= self.max_size {
            if let Some((_, mut data)) = self.cache.pop() {
                data.dispose();
            }
        }

        // Create new
        let graph = FunctionCallGraph::new();
        let data = ValidFcgData::new(addr, function_name, graph);
        let result = data.clone_data();
        self.cache.insert(0, (addr, data));
        result
    }

    /// Remove a function from the cache.
    pub fn remove(&mut self, function_address: u64) {
        if let Some(idx) = self.cache.iter().position(|(a, _)| *a == function_address) {
            let (_, mut data) = self.cache.remove(idx);
            data.dispose();
        }
    }

    /// Get a reference to cached data for a function.
    pub fn get(&self, function_address: u64) -> Option<&ValidFcgData> {
        self.cache
            .iter()
            .find(|(a, _)| *a == function_address)
            .map(|(_, data)| data)
    }

    /// Get the number of cached entries.
    pub fn len(&self) -> usize {
        self.cache.len()
    }

    /// Check if the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }

    /// Dispose all cached data.
    pub fn dispose(&mut self) {
        for (_, mut data) in self.cache.drain(..) {
            data.dispose();
        }
    }
}

impl Default for FcgDataFactory {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_fcg_data() {
        let graph = FunctionCallGraph::new();
        let data = ValidFcgData::new(0x1000, "main", graph);

        assert_eq!(data.function_address(), Some(0x1000));
        assert_eq!(data.function_name(), Some("main"));
        assert!(data.has_results());
        assert!(!data.is_initialized()); // empty graph
        assert!(data.is_function(0x1000));
        assert!(!data.is_function(0x2000));
    }

    #[test]
    fn test_valid_fcg_data_initialized() {
        let mut graph = FunctionCallGraph::new();
        graph.set_source(FcgVertex::new("main", 0x1000, super::super::fcg_level::FcgLevel::source_level()));
        let data = ValidFcgData::new(0x1000, "main", graph);

        assert!(data.is_initialized());
    }

    #[test]
    fn test_valid_fcg_data_dispose() {
        let graph = FunctionCallGraph::new();
        let mut data = ValidFcgData::new(0x1000, "main", graph);

        data.dispose();
        // After dispose, graph should be empty
        assert!(data.graph().unwrap().is_empty());
    }

    #[test]
    fn test_valid_fcg_data_clone() {
        let mut graph = FunctionCallGraph::new();
        graph.set_source(FcgVertex::new("main", 0x1000, super::super::fcg_level::FcgLevel::source_level()));
        let data = ValidFcgData::new(0x1000, "main", graph);

        let cloned = data.clone_data();
        assert!(cloned.has_results());
        assert_eq!(cloned.function_address(), Some(0x1000));
    }

    #[test]
    fn test_empty_fcg_data() {
        let data = EmptyFcgData;

        assert!(data.function_address().is_none());
        assert!(data.function_name().is_none());
        assert!(data.graph().is_none());
        assert!(!data.has_results());
        assert!(!data.is_initialized());
        assert!(!data.is_function(0x1000));
    }

    #[test]
    fn test_empty_fcg_data_dispose() {
        let mut data = EmptyFcgData;
        data.dispose(); // should not panic
    }

    #[test]
    fn test_empty_fcg_data_clone() {
        let data = EmptyFcgData;
        let cloned = data.clone_data();
        assert!(!cloned.has_results());
    }

    #[test]
    fn test_factory_create_empty() {
        let mut factory = FcgDataFactory::new();
        let data = factory.create(None, "");
        assert!(!data.has_results());
        assert_eq!(factory.len(), 0);
    }

    #[test]
    fn test_factory_create_and_cache() {
        let mut factory = FcgDataFactory::new();
        let data1 = factory.create(Some(0x1000), "main");
        assert!(data1.has_results());
        assert_eq!(factory.len(), 1);

        // Same address should return cached
        let data2 = factory.create(Some(0x1000), "main");
        assert!(data2.has_results());
        assert_eq!(factory.len(), 1);
    }

    #[test]
    fn test_factory_eviction() {
        let mut factory = FcgDataFactory::with_capacity(2);

        factory.create(Some(0x1000), "a");
        factory.create(Some(0x2000), "b");
        assert_eq!(factory.len(), 2);

        factory.create(Some(0x3000), "c");
        assert_eq!(factory.len(), 2); // one was evicted

        // The oldest (0x1000) should have been evicted
        assert!(factory.get(0x1000).is_none());
    }

    #[test]
    fn test_factory_remove() {
        let mut factory = FcgDataFactory::new();
        factory.create(Some(0x1000), "main");
        assert_eq!(factory.len(), 1);

        factory.remove(0x1000);
        assert_eq!(factory.len(), 0);
    }

    #[test]
    fn test_factory_dispose() {
        let mut factory = FcgDataFactory::new();
        factory.create(Some(0x1000), "a");
        factory.create(Some(0x2000), "b");

        factory.dispose();
        assert!(factory.is_empty());
    }

    #[test]
    fn test_factory_get() {
        let mut factory = FcgDataFactory::new();
        factory.create(Some(0x1000), "main");

        assert!(factory.get(0x1000).is_some());
        assert!(factory.get(0x9999).is_none());
    }
}
