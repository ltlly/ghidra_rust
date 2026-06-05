//! Abstract layout provider.
//!
//! Ports `ghidra.graph.viewer.layout.AbstractLayoutProvider`.
//!
//! A base implementation of the LayoutProvider interface that provides
//! default stub methods. Concrete implementations override `compute_layout`.

use super::{GridPoint, LayoutLocationMap, LayoutPositions, VisualGraphLayout};
use super::super::{Point2D, Rect2D, VisualEdge, VisualGraph, VisualVertex};

/// Extension point for layout providers.
///
/// Ports `ghidra.graph.viewer.layout.LayoutProviderExtensionPoint`.
pub trait LayoutProviderExtensionPoint: Send + Sync {
    /// The name of this layout algorithm.
    fn name(&self) -> &str;

    /// Get the action icon (path or identifier).
    fn action_icon(&self) -> Option<&str> { None }

    /// Priority level (higher = preferred).
    fn priority_level(&self) -> i32 { 0 }

    /// Whether this layout provider is available.
    fn is_available(&self) -> bool { true }

    /// Get a description of this layout provider.
    fn description(&self) -> &str { "" }
}

/// Abstract base implementation of a layout provider.
///
/// Ports `ghidra.graph.viewer.layout.AbstractLayoutProvider`.
/// Provides default implementations for icon, priority, and vertex
/// location initialization.
#[derive(Debug, Clone)]
pub struct AbstractLayoutProvider {
    /// The name of this layout.
    name: String,
    /// The action icon path.
    icon: Option<String>,
    /// Priority level.
    priority: i32,
}

impl AbstractLayoutProvider {
    /// Create a new abstract layout provider.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            icon: None,
            priority: 0,
        }
    }

    /// Set the action icon.
    pub fn with_icon(mut self, icon: impl Into<String>) -> Self {
        self.icon = Some(icon.into());
        self
    }

    /// Set the priority level.
    pub fn with_priority(mut self, priority: i32) -> Self {
        self.priority = priority;
        self
    }

    /// Initialize vertex locations from a graph and layout.
    ///
    /// Gives all vertices of the graph an initial, non-null location.
    /// This only works if the graph has been built before this method
    /// is called.
    pub fn init_vertex_locations(
        &self,
        vertices: &[String],
        layout: &mut dyn VisualGraphLayout,
    ) -> LayoutLocationMap {
        let mut map = LayoutLocationMap::new();
        let positions = layout.compute_layout(vertices);
        for id in vertices {
            if let Some(pos) = positions.get_position(id) {
                map.set_position(id, pos);
            } else {
                // Default: place at origin
                map.set_position(id, Point2D::ZERO);
            }
        }
        map
    }
}

impl LayoutProviderExtensionPoint for AbstractLayoutProvider {
    fn name(&self) -> &str {
        &self.name
    }

    fn action_icon(&self) -> Option<&str> {
        self.icon.as_deref()
    }

    fn priority_level(&self) -> i32 {
        self.priority
    }
}

/// Layout provider factory using JUNG-style layout algorithms.
///
/// Ports `ghidra.graph.viewer.layout.JungLayoutProviderFactory`.
/// Provides factory methods for creating layout providers based on
/// common graph layout algorithms.
#[derive(Debug)]
pub struct JungLayoutProviderFactory;

impl JungLayoutProviderFactory {
    /// Create a grid layout provider.
    pub fn grid_layout() -> AbstractLayoutProvider {
        AbstractLayoutProvider::new("Grid Layout")
            .with_priority(10)
    }

    /// Create a hierarchical (top-down) layout provider.
    pub fn hierarchical_layout() -> AbstractLayoutProvider {
        AbstractLayoutProvider::new("Hierarchical Layout")
            .with_priority(20)
    }

    /// Create a circular layout provider.
    pub fn circular_layout() -> AbstractLayoutProvider {
        AbstractLayoutProvider::new("Circular Layout")
            .with_priority(5)
    }

    /// Create a force-directed (FR) layout provider.
    pub fn force_directed_layout() -> AbstractLayoutProvider {
        AbstractLayoutProvider::new("Force-Directed Layout")
            .with_priority(15)
    }

    /// Create a tree layout provider.
    pub fn tree_layout() -> AbstractLayoutProvider {
        AbstractLayoutProvider::new("Tree Layout")
            .with_priority(25)
    }

    /// Get all available layout providers, sorted by priority.
    pub fn all_providers() -> Vec<AbstractLayoutProvider> {
        let mut providers = vec![
            Self::grid_layout(),
            Self::hierarchical_layout(),
            Self::circular_layout(),
            Self::force_directed_layout(),
            Self::tree_layout(),
        ];
        providers.sort_by(|a, b| b.priority_level().cmp(&a.priority_level()));
        providers
    }
}

/// Jung layout wrapper.
///
/// Ports `ghidra.graph.viewer.layout.JungLayout`.
/// Wraps a layout algorithm with JUNG compatibility.
#[derive(Debug, Clone)]
pub struct JungLayout {
    /// The algorithm name.
    pub algorithm: String,
    /// Current vertex positions.
    positions: LayoutLocationMap,
}

impl JungLayout {
    /// Create a new Jung layout.
    pub fn new(algorithm: impl Into<String>) -> Self {
        Self {
            algorithm: algorithm.into(),
            positions: LayoutLocationMap::new(),
        }
    }

    /// Set a vertex position.
    pub fn set_position(&mut self, vertex_id: &str, pos: Point2D) {
        self.positions.set_position(vertex_id, pos);
    }

    /// Get a vertex position.
    pub fn get_position(&self, vertex_id: &str) -> Option<Point2D> {
        self.positions.get_position(vertex_id)
    }

    /// Get the positions map.
    pub fn positions(&self) -> &LayoutLocationMap {
        &self.positions
    }
}

impl VisualGraphLayout for JungLayout {
    fn name(&self) -> &str {
        &self.algorithm
    }

    fn compute_layout(&mut self, vertex_ids: &[String]) -> LayoutPositions {
        let mut positions = LayoutPositions::new(&self.algorithm);
        for id in vertex_ids {
            if let Some(pos) = self.positions.get_position(id) {
                positions.set_position(id, pos);
            }
        }
        positions
    }

    fn positions(&self) -> &LayoutLocationMap {
        &self.positions
    }
}

/// Layout provider extension point that uses JUNG.
///
/// Ports `ghidra.graph.viewer.layout.LayoutProviderExtensionPoint` for
/// JUNG-based layouts.
pub type LayoutProvider = dyn LayoutProviderExtensionPoint;

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::AbstractVisualGraphLayout;

    #[test]
    fn abstract_layout_provider_new() {
        let provider = AbstractLayoutProvider::new("Test Layout");
        assert_eq!(provider.name(), "Test Layout");
        assert_eq!(provider.priority_level(), 0);
        assert!(provider.action_icon().is_none());
    }

    #[test]
    fn abstract_layout_provider_with_options() {
        let provider = AbstractLayoutProvider::new("Custom")
            .with_icon("layout_icon")
            .with_priority(42);
        assert_eq!(provider.priority_level(), 42);
        assert_eq!(provider.action_icon(), Some("layout_icon"));
    }

    #[test]
    fn jung_layout_provider_factory() {
        let grid = JungLayoutProviderFactory::grid_layout();
        assert_eq!(grid.name(), "Grid Layout");
        assert_eq!(grid.priority_level(), 10);

        let hier = JungLayoutProviderFactory::hierarchical_layout();
        assert_eq!(hier.name(), "Hierarchical Layout");
        assert_eq!(hier.priority_level(), 20);
    }

    #[test]
    fn all_providers_sorted_by_priority() {
        let providers = JungLayoutProviderFactory::all_providers();
        assert_eq!(providers.len(), 5);
        // Should be sorted by priority descending
        for w in providers.windows(2) {
            assert!(w[0].priority_level() >= w[1].priority_level());
        }
    }

    #[test]
    fn jung_layout_basics() {
        let mut layout = JungLayout::new("FR");
        layout.set_position("v1", Point2D::new(10.0, 20.0));
        assert_eq!(layout.get_position("v1"), Some(Point2D::new(10.0, 20.0)));
        assert_eq!(layout.name(), "FR");
    }

    #[test]
    fn jung_layout_compute() {
        let mut layout = JungLayout::new("Grid");
        layout.set_position("a", Point2D::new(0.0, 0.0));
        layout.set_position("b", Point2D::new(100.0, 0.0));
        let ids = vec!["a".to_string(), "b".to_string()];
        let positions = layout.compute_layout(&ids);
        assert_eq!(positions.get_position("a"), Some(Point2D::new(0.0, 0.0)));
    }

    #[test]
    fn init_vertex_locations() {
        let provider = AbstractLayoutProvider::new("Test");
        let mut layout = AbstractVisualGraphLayout::new("Grid");
        let vertices = vec!["v1".to_string(), "v2".to_string()];
        let map = provider.init_vertex_locations(&vertices, &mut layout);
        assert_eq!(map.len(), 2);
    }
}
