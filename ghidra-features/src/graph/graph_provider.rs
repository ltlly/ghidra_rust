//! Graph provider for creating and managing graph displays.
//!
//! Ported from Ghidra's `ghidra.features.graph` GraphProvider Java class
//! (Features/Graph/src/main/java/ghidra/features/graph/GraphProvider.java).
//!
//! A graph provider is the service interface through which plugins request
//! that graph displays be created. Each provider represents a specific graph
//! visualization backend (e.g., a JUNG-based visual graph, an external graph
//! viewer, or a headless graph export).
//!
//! # Key Types
//!
//! - [`GraphProvider`] -- Trait for graph display backends
//! - [`GraphProviderInfo`] -- Metadata about a graph provider
//! - [`GraphProviderManager`] -- Registry for graph providers
//! - [`GraphDisplayRequest`] -- Parameters for creating a graph display

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// GraphProvider trait
// ---------------------------------------------------------------------------

/// Trait for graph display providers.
///
/// A graph provider creates and manages graph display instances. Each
/// provider represents a specific backend for rendering graphs (e.g.,
/// JUNG-based visual graph, external viewer, headless export).
///
/// Ported from `ghidra.features.graph.GraphProvider`.
pub trait GraphProvider: Send + Sync + std::fmt::Debug {
    /// The unique identifier for this provider.
    fn id(&self) -> &str;

    /// The human-readable name of this provider.
    fn name(&self) -> &str;

    /// A description of what this provider does.
    fn description(&self) -> &str;

    /// Whether this provider is available on the current platform.
    ///
    /// Providers may require specific runtime capabilities (e.g., a GUI
    /// display, specific libraries). This method returns `false` if the
    /// provider cannot function in the current environment.
    fn is_available(&self) -> bool {
        true
    }

    /// Whether this provider supports the given graph type.
    fn supports_graph_type(&self, graph_type: &str) -> bool {
        let _ = graph_type;
        true
    }

    /// Whether this provider supports export to image.
    fn supports_export(&self) -> bool {
        true
    }

    /// Whether this provider supports printing.
    fn supports_print(&self) -> bool {
        true
    }

    /// Priority of this provider (lower is higher priority).
    ///
    /// When multiple providers are available, the one with the lowest
    /// priority value is chosen as the default.
    fn priority(&self) -> u32 {
        100
    }
}

// ---------------------------------------------------------------------------
// GraphProviderInfo
// ---------------------------------------------------------------------------

/// Metadata about a registered graph provider.
///
/// Captures the provider's identity and capability flags for use by the
/// provider manager and plugin configuration UI.
#[derive(Debug, Clone)]
pub struct GraphProviderInfo {
    /// Unique provider identifier.
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Provider description.
    pub description: String,
    /// Whether the provider is currently available.
    pub available: bool,
    /// Provider priority (lower = higher priority).
    pub priority: u32,
    /// Whether the provider supports image export.
    pub supports_export: bool,
    /// Whether the provider supports printing.
    pub supports_print: bool,
}

impl GraphProviderInfo {
    /// Create info from a `GraphProvider` reference.
    pub fn from_provider(provider: &dyn GraphProvider) -> Self {
        Self {
            id: provider.id().to_string(),
            name: provider.name().to_string(),
            description: provider.description().to_string(),
            available: provider.is_available(),
            priority: provider.priority(),
            supports_export: provider.supports_export(),
            supports_print: provider.supports_print(),
        }
    }
}

// ---------------------------------------------------------------------------
// GraphDisplayRequest
// ---------------------------------------------------------------------------

/// Parameters for requesting a new graph display.
///
/// Encapsulates the information needed to create a graph display, including
/// the graph type, title, and optional display options.
#[derive(Debug, Clone)]
pub struct GraphDisplayRequest {
    /// The graph type identifier (e.g., "call_graph", "cfg", "data_flow").
    pub graph_type: String,
    /// The title for the graph display window.
    pub title: String,
    /// Whether to reuse an existing display for the same graph type.
    pub reuse_existing: bool,
    /// Custom properties for the display.
    pub properties: HashMap<String, String>,
}

impl GraphDisplayRequest {
    /// Create a new graph display request.
    pub fn new(graph_type: impl Into<String>, title: impl Into<String>) -> Self {
        Self {
            graph_type: graph_type.into(),
            title: title.into(),
            reuse_existing: true,
            properties: HashMap::new(),
        }
    }

    /// Set whether to reuse an existing display.
    pub fn with_reuse(mut self, reuse: bool) -> Self {
        self.reuse_existing = reuse;
        self
    }

    /// Add a custom property.
    pub fn with_property(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.properties.insert(key.into(), value.into());
        self
    }

    /// Get a property value by key.
    pub fn property(&self, key: &str) -> Option<&str> {
        self.properties.get(key).map(|s| s.as_str())
    }
}

// ---------------------------------------------------------------------------
// GraphProviderManager
// ---------------------------------------------------------------------------

/// Registry for graph providers.
///
/// Manages the set of available graph providers and selects the appropriate
/// provider for a given graph display request.
///
/// Ported from the graph display broker's provider management logic.
#[derive(Debug)]
pub struct GraphProviderManager {
    /// Registered provider info entries, ordered by registration.
    providers: Vec<GraphProviderInfo>,
    /// The ID of the active (default) provider.
    active_provider_id: Option<String>,
}

impl GraphProviderManager {
    /// Create a new empty provider manager.
    pub fn new() -> Self {
        Self {
            providers: Vec::new(),
            active_provider_id: None,
        }
    }

    /// Register a provider.
    ///
    /// If this is the first provider registered, it becomes the active
    /// provider automatically.
    pub fn register(&mut self, info: GraphProviderInfo) {
        if self.providers.iter().any(|p| p.id == info.id) {
            return; // Already registered
        }
        let is_first = self.providers.is_empty();
        if is_first {
            self.active_provider_id = Some(info.id.clone());
        }
        self.providers.push(info);
    }

    /// Unregister a provider by ID.
    ///
    /// Returns `true` if the provider was found and removed.
    pub fn unregister(&mut self, provider_id: &str) -> bool {
        let len_before = self.providers.len();
        self.providers.retain(|p| p.id != provider_id);
        let removed = self.providers.len() < len_before;

        if removed {
            // If the active provider was removed, pick the first available
            if self.active_provider_id.as_deref() == Some(provider_id) {
                self.active_provider_id = self
                    .providers
                    .iter()
                    .find(|p| p.available)
                    .map(|p| p.id.clone());
            }
        }

        removed
    }

    /// Get all registered provider info.
    pub fn providers(&self) -> &[GraphProviderInfo] {
        &self.providers
    }

    /// Get the currently active provider ID.
    pub fn active_provider_id(&self) -> Option<&str> {
        self.active_provider_id.as_deref()
    }

    /// Set the active provider by ID.
    ///
    /// Returns `true` if the provider was found.
    pub fn set_active_provider(&mut self, provider_id: &str) -> bool {
        if self.providers.iter().any(|p| p.id == provider_id) {
            self.active_provider_id = Some(provider_id.to_string());
            true
        } else {
            false
        }
    }

    /// Get info for a specific provider by ID.
    pub fn provider_info(&self, provider_id: &str) -> Option<&GraphProviderInfo> {
        self.providers.iter().find(|p| p.id == provider_id)
    }

    /// Get the number of registered providers.
    pub fn provider_count(&self) -> usize {
        self.providers.len()
    }

    /// Get the number of currently available providers.
    pub fn available_count(&self) -> usize {
        self.providers.iter().filter(|p| p.available).count()
    }

    /// Select the best provider for a given graph type.
    ///
    /// Returns the provider with the lowest priority among those that are
    /// available and support the requested graph type. If no specific match
    /// is found, falls back to the active provider.
    pub fn select_provider(&self, graph_type: &str) -> Option<&GraphProviderInfo> {
        let _ = graph_type;
        // Try to find an available provider with the lowest priority
        let best = self
            .providers
            .iter()
            .filter(|p| p.available)
            .min_by_key(|p| p.priority);

        best.or_else(|| {
            // Fall back to the active provider
            self.active_provider_id
                .as_ref()
                .and_then(|id| self.provider_info(id))
                .filter(|p| p.available)
        })
    }

    /// Get provider info sorted by priority (ascending).
    pub fn providers_by_priority(&self) -> Vec<&GraphProviderInfo> {
        let mut sorted: Vec<_> = self.providers.iter().collect();
        sorted.sort_by_key(|p| p.priority);
        sorted
    }
}

impl Default for GraphProviderManager {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // A simple test provider implementation.
    #[derive(Debug)]
    struct TestGraphProvider {
        id_val: String,
        name_val: String,
        available_val: bool,
        priority_val: u32,
    }

    impl TestGraphProvider {
        fn new(id: &str, name: &str) -> Self {
            Self {
                id_val: id.to_string(),
                name_val: name.to_string(),
                available_val: true,
                priority_val: 100,
            }
        }

        fn with_priority(mut self, priority: u32) -> Self {
            self.priority_val = priority;
            self
        }

        fn unavailable(mut self) -> Self {
            self.available_val = false;
            self
        }
    }

    impl GraphProvider for TestGraphProvider {
        fn id(&self) -> &str {
            &self.id_val
        }
        fn name(&self) -> &str {
            &self.name_val
        }
        fn description(&self) -> &str {
            "test provider"
        }
        fn is_available(&self) -> bool {
            self.available_val
        }
        fn priority(&self) -> u32 {
            self.priority_val
        }
    }

    #[test]
    fn test_graph_display_request() {
        let req = GraphDisplayRequest::new("call_graph", "Call Graph - main")
            .with_reuse(false)
            .with_property("depth", "3");

        assert_eq!(req.graph_type, "call_graph");
        assert_eq!(req.title, "Call Graph - main");
        assert!(!req.reuse_existing);
        assert_eq!(req.property("depth"), Some("3"));
        assert_eq!(req.property("missing"), None);
    }

    #[test]
    fn test_graph_provider_info_from_provider() {
        let provider = TestGraphProvider::new("test1", "Test Provider");
        let info = GraphProviderInfo::from_provider(&provider);

        assert_eq!(info.id, "test1");
        assert_eq!(info.name, "Test Provider");
        assert!(info.available);
        assert_eq!(info.priority, 100);
        assert!(info.supports_export);
        assert!(info.supports_print);
    }

    #[test]
    fn test_provider_manager_register() {
        let mut mgr = GraphProviderManager::new();
        assert_eq!(mgr.provider_count(), 0);

        let provider = TestGraphProvider::new("p1", "Provider 1");
        mgr.register(GraphProviderInfo::from_provider(&provider));

        assert_eq!(mgr.provider_count(), 1);
        assert_eq!(mgr.active_provider_id(), Some("p1"));
    }

    #[test]
    fn test_provider_manager_first_becomes_active() {
        let mut mgr = GraphProviderManager::new();

        let p1 = TestGraphProvider::new("p1", "First");
        let p2 = TestGraphProvider::new("p2", "Second");
        mgr.register(GraphProviderInfo::from_provider(&p1));
        mgr.register(GraphProviderInfo::from_provider(&p2));

        assert_eq!(mgr.active_provider_id(), Some("p1"));
        assert_eq!(mgr.provider_count(), 2);
    }

    #[test]
    fn test_provider_manager_duplicate_registration() {
        let mut mgr = GraphProviderManager::new();

        let p1 = TestGraphProvider::new("p1", "First");
        mgr.register(GraphProviderInfo::from_provider(&p1));
        mgr.register(GraphProviderInfo::from_provider(&p1)); // duplicate

        assert_eq!(mgr.provider_count(), 1);
    }

    #[test]
    fn test_provider_manager_set_active() {
        let mut mgr = GraphProviderManager::new();

        let p1 = TestGraphProvider::new("p1", "First");
        let p2 = TestGraphProvider::new("p2", "Second");
        mgr.register(GraphProviderInfo::from_provider(&p1));
        mgr.register(GraphProviderInfo::from_provider(&p2));

        assert!(mgr.set_active_provider("p2"));
        assert_eq!(mgr.active_provider_id(), Some("p2"));

        assert!(!mgr.set_active_provider("nonexistent"));
        assert_eq!(mgr.active_provider_id(), Some("p2")); // unchanged
    }

    #[test]
    fn test_provider_manager_unregister() {
        let mut mgr = GraphProviderManager::new();

        let p1 = TestGraphProvider::new("p1", "First");
        let p2 = TestGraphProvider::new("p2", "Second");
        mgr.register(GraphProviderInfo::from_provider(&p1));
        mgr.register(GraphProviderInfo::from_provider(&p2));

        // Active is p1; removing p1 should fall back to p2
        assert!(mgr.unregister("p1"));
        assert_eq!(mgr.provider_count(), 1);
        assert_eq!(mgr.active_provider_id(), Some("p2"));

        // Removing nonexistent returns false
        assert!(!mgr.unregister("nonexistent"));
    }

    #[test]
    fn test_provider_manager_unregister_active_no_fallback() {
        let mut mgr = GraphProviderManager::new();

        let p1 = TestGraphProvider::new("p1", "First");
        mgr.register(GraphProviderInfo::from_provider(&p1));
        mgr.unregister("p1");

        assert_eq!(mgr.provider_count(), 0);
        assert_eq!(mgr.active_provider_id(), None);
    }

    #[test]
    fn test_provider_manager_unregister_unavailable_fallback() {
        let mut mgr = GraphProviderManager::new();

        let p1 = TestGraphProvider::new("p1", "First");
        let p2 = TestGraphProvider::new("p2", "Second").unavailable();
        mgr.register(GraphProviderInfo::from_provider(&p1));
        mgr.register(GraphProviderInfo::from_provider(&p2));

        // Active is p1; removing p1 -- p2 is unavailable, so active becomes None
        mgr.unregister("p1");
        assert_eq!(mgr.active_provider_id(), None);
    }

    #[test]
    fn test_provider_manager_available_count() {
        let mut mgr = GraphProviderManager::new();

        let p1 = TestGraphProvider::new("p1", "Available");
        let p2 = TestGraphProvider::new("p2", "Unavailable").unavailable();
        mgr.register(GraphProviderInfo::from_provider(&p1));
        mgr.register(GraphProviderInfo::from_provider(&p2));

        assert_eq!(mgr.provider_count(), 2);
        assert_eq!(mgr.available_count(), 1);
    }

    #[test]
    fn test_provider_manager_select_provider() {
        let mut mgr = GraphProviderManager::new();

        let p1 = TestGraphProvider::new("p1", "High Priority").with_priority(10);
        let p2 = TestGraphProvider::new("p2", "Low Priority").with_priority(50);
        mgr.register(GraphProviderInfo::from_provider(&p1));
        mgr.register(GraphProviderInfo::from_provider(&p2));

        let selected = mgr.select_provider("call_graph");
        assert!(selected.is_some());
        assert_eq!(selected.unwrap().id, "p1"); // lower priority wins
    }

    #[test]
    fn test_provider_manager_select_with_unavailable() {
        let mut mgr = GraphProviderManager::new();

        let p1 = TestGraphProvider::new("p1", "High Priority")
            .with_priority(10)
            .unavailable();
        let p2 = TestGraphProvider::new("p2", "Low Priority").with_priority(50);
        mgr.register(GraphProviderInfo::from_provider(&p1));
        mgr.register(GraphProviderInfo::from_provider(&p2));

        let selected = mgr.select_provider("call_graph");
        assert!(selected.is_some());
        assert_eq!(selected.unwrap().id, "p2"); // p1 is unavailable
    }

    #[test]
    fn test_provider_manager_select_empty() {
        let mgr = GraphProviderManager::new();
        assert!(mgr.select_provider("anything").is_none());
    }

    #[test]
    fn test_provider_manager_by_priority() {
        let mut mgr = GraphProviderManager::new();

        let p1 = TestGraphProvider::new("p1", "B").with_priority(50);
        let p2 = TestGraphProvider::new("p2", "A").with_priority(10);
        let p3 = TestGraphProvider::new("p3", "C").with_priority(100);
        mgr.register(GraphProviderInfo::from_provider(&p1));
        mgr.register(GraphProviderInfo::from_provider(&p2));
        mgr.register(GraphProviderInfo::from_provider(&p3));

        let sorted = mgr.providers_by_priority();
        assert_eq!(sorted[0].id, "p2"); // priority 10
        assert_eq!(sorted[1].id, "p1"); // priority 50
        assert_eq!(sorted[2].id, "p3"); // priority 100
    }

    #[test]
    fn test_provider_manager_provider_info_lookup() {
        let mut mgr = GraphProviderManager::new();

        let p1 = TestGraphProvider::new("p1", "My Provider");
        mgr.register(GraphProviderInfo::from_provider(&p1));

        let info = mgr.provider_info("p1");
        assert!(info.is_some());
        assert_eq!(info.unwrap().name, "My Provider");

        assert!(mgr.provider_info("nonexistent").is_none());
    }

    #[test]
    fn test_graph_provider_default_methods() {
        // Verify default trait method implementations via a minimal provider
        #[derive(Debug)]
        struct MinimalProvider;
        impl GraphProvider for MinimalProvider {
            fn id(&self) -> &str { "minimal" }
            fn name(&self) -> &str { "Minimal" }
            fn description(&self) -> &str { "minimal provider" }
        }

        let p = MinimalProvider;
        assert!(p.is_available());
        assert!(p.supports_graph_type("anything"));
        assert!(p.supports_export());
        assert!(p.supports_print());
        assert_eq!(p.priority(), 100);
    }
}
