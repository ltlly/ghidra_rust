//! Port of Ghidra's `ghidra.graph.viewer.layout.LayoutProviderExtensionPoint`.

/// Extension point for pluggable layout algorithms.
pub trait LayoutProviderExtensionPoint: Send + Sync + std::fmt::Debug {
    /// Unique name of this layout algorithm.
    fn name(&self) -> &str;
    /// Human-readable display name.
    fn display_name(&self) -> &str { self.name() }
    /// Priority for ordering in UI (lower = higher priority).
    fn priority(&self) -> i32 { 0 }
    /// Whether this layout supports the given graph type.
    fn supports_graph_type(&self, _graph_type: &str) -> bool { true }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct TestLayout;
    impl LayoutProviderExtensionPoint for TestLayout {
        fn name(&self) -> &str { "grid" }
        fn display_name(&self) -> &str { "Grid Layout" }
        fn priority(&self) -> i32 { 10 }
    }

    #[test]
    fn test_extension_point() {
        let lp = TestLayout;
        assert_eq!(lp.name(), "grid");
        assert_eq!(lp.display_name(), "Grid Layout");
        assert_eq!(lp.priority(), 10);
        assert!(lp.supports_graph_type("any"));
    }
}
