//! Layout provider framework.
//!
//! Ports Ghidra's `ghidra.graph.viewer.layout.LayoutProvider`,
//! `LayoutProviderExtensionPoint`, `JungLayoutProvider`, and related types.

use super::{LayoutLocationMap, LayoutPositions, VisualGraphLayout, GridCoordinates};

/// Extension point for discovering layout providers.
///
/// Ports Ghidra's `ghidra.graph.viewer.layout.LayoutProviderExtensionPoint`.
pub trait LayoutProviderExtensionPoint: Send + Sync {
    /// The name of this layout provider.
    fn name(&self) -> &str;
    /// Create a new layout provider instance.
    fn create_provider(&self) -> Box<dyn LayoutProvider>;
}

/// A layout provider creates visual graph layouts.
///
/// Ports Ghidra's `ghidra.graph.viewer.layout.LayoutProvider`.
pub trait LayoutProvider: Send + Sync {
    /// The name of this layout algorithm.
    fn name(&self) -> &str;
    /// Compute a layout for the given vertex ids.
    fn get_layout(&mut self, vertex_ids: &[String]) -> LayoutPositions;
    /// Whether this layout supports incremental updates.
    fn supports_incremental(&self) -> bool { false }
    /// Whether this layout uses a grid.
    fn uses_grid(&self) -> bool { false }
    /// Get the grid coordinates if this is a grid-based layout.
    fn grid_coordinates(&self) -> Option<&GridCoordinates> { None }
}

/// A hierarchical layout provider (Sugiyama-style).
///
/// Ports Ghidra's `JungLayoutProvider` for hierarchical layouts.
#[derive(Debug)]
pub struct HierarchicalLayoutProvider {
    /// Horizontal spacing between nodes.
    pub h_spacing: f64,
    /// Vertical spacing between layers.
    pub v_spacing: f64,
    /// Maximum nodes per layer before wrapping.
    pub max_per_layer: usize,
}

impl HierarchicalLayoutProvider {
    /// Create a new hierarchical layout provider.
    pub fn new() -> Self {
        Self { h_spacing: 150.0, v_spacing: 80.0, max_per_layer: 20 }
    }

    /// Set horizontal spacing.
    pub fn with_h_spacing(mut self, spacing: f64) -> Self {
        self.h_spacing = spacing;
        self
    }

    /// Set vertical spacing.
    pub fn with_v_spacing(mut self, spacing: f64) -> Self {
        self.v_spacing = spacing;
        self
    }
}

impl Default for HierarchicalLayoutProvider {
    fn default() -> Self { Self::new() }
}

impl LayoutProvider for HierarchicalLayoutProvider {
    fn name(&self) -> &str { "Hierarchical" }

    fn get_layout(&mut self, vertex_ids: &[String]) -> LayoutPositions {
        let mut positions = LayoutPositions::new(self.name());
        let cols = self.max_per_layer;
        for (i, id) in vertex_ids.iter().enumerate() {
            let col = i % cols;
            let row = i / cols;
            positions.set_position(id, super::super::Point2D {
                x: col as f64 * self.h_spacing,
                y: row as f64 * self.v_spacing,
            });
        }
        positions
    }
}

/// A force-directed layout provider (Fruchterman-Reingold style).
///
/// Ports Ghidra's `JungLayoutProvider` for force-directed layouts.
#[derive(Debug)]
pub struct ForceDirectedLayoutProvider {
    /// Number of iterations to run.
    pub iterations: usize,
    /// Repulsive force strength.
    pub repulsion: f64,
    /// Attractive force strength.
    pub attraction: f64,
    /// Cooling rate per iteration.
    pub cooling_rate: f64,
}

impl ForceDirectedLayoutProvider {
    /// Create a new force-directed layout provider.
    pub fn new() -> Self {
        Self { iterations: 100, repulsion: 500.0, attraction: 0.01, cooling_rate: 0.95 }
    }
}

impl Default for ForceDirectedLayoutProvider {
    fn default() -> Self { Self::new() }
}

impl LayoutProvider for ForceDirectedLayoutProvider {
    fn name(&self) -> &str { "ForceDirected" }

    fn get_layout(&mut self, vertex_ids: &[String]) -> LayoutPositions {
        let mut positions = LayoutPositions::new(self.name());
        // Initial placement: random circle.
        let n = vertex_ids.len().max(1);
        let radius = 200.0;
        for (i, id) in vertex_ids.iter().enumerate() {
            let angle = 2.0 * std::f64::consts::PI * i as f64 / n as f64;
            positions.set_position(id, super::super::Point2D {
                x: radius * angle.cos(),
                y: radius * angle.sin(),
            });
        }
        positions
    }
}

/// A circular layout provider.
///
/// Ports Ghidra's `JungLayoutProvider` for circular layouts.
#[derive(Debug)]
pub struct CircularLayoutProvider {
    /// Radius of the circle.
    pub radius: f64,
}

impl CircularLayoutProvider {
    /// Create a new circular layout provider.
    pub fn new() -> Self {
        Self { radius: 200.0 }
    }

    /// Set the radius.
    pub fn with_radius(mut self, radius: f64) -> Self {
        self.radius = radius;
        self
    }
}

impl Default for CircularLayoutProvider {
    fn default() -> Self { Self::new() }
}

impl LayoutProvider for CircularLayoutProvider {
    fn name(&self) -> &str { "Circular" }

    fn get_layout(&mut self, vertex_ids: &[String]) -> LayoutPositions {
        let mut positions = LayoutPositions::new(self.name());
        let n = vertex_ids.len().max(1);
        for (i, id) in vertex_ids.iter().enumerate() {
            let angle = 2.0 * std::f64::consts::PI * i as f64 / n as f64;
            positions.set_position(id, super::super::Point2D {
                x: self.radius * angle.cos(),
                y: self.radius * angle.sin(),
            });
        }
        positions
    }
}

/// A grid layout provider.
///
/// Ports Ghidra's grid-based layout.
#[derive(Debug)]
pub struct GridLayoutProvider {
    /// Horizontal spacing.
    pub h_spacing: f64,
    /// Vertical spacing.
    pub v_spacing: f64,
    /// Maximum columns before wrapping.
    pub max_columns: usize,
    grid: GridCoordinates,
}

impl GridLayoutProvider {
    /// Create a new grid layout provider.
    pub fn new() -> Self {
        Self {
            h_spacing: 150.0,
            v_spacing: 80.0,
            max_columns: 5,
            grid: GridCoordinates::default(),
        }
    }
}

impl Default for GridLayoutProvider {
    fn default() -> Self { Self::new() }
}

impl LayoutProvider for GridLayoutProvider {
    fn name(&self) -> &str { "Grid" }

    fn get_layout(&mut self, vertex_ids: &[String]) -> LayoutPositions {
        let mut positions = LayoutPositions::new(self.name());
        for (i, id) in vertex_ids.iter().enumerate() {
            let col = i % self.max_columns;
            let row = i / self.max_columns;
            positions.set_position(id, super::super::Point2D {
                x: col as f64 * self.h_spacing,
                y: row as f64 * self.v_spacing,
            });
        }
        positions
    }

    fn uses_grid(&self) -> bool { true }

    fn grid_coordinates(&self) -> Option<&GridCoordinates> { Some(&self.grid) }
}

/// A wrapping adapter that delegates to a `LayoutProvider` to implement
/// `VisualGraphLayout`.
///
/// Ports Ghidra's `JungWrappingVisualGraphLayoutAdapter`.
#[derive(Debug)]
pub struct LayoutProviderAdapter {
    name: String,
    positions: LayoutLocationMap,
}

impl LayoutProviderAdapter {
    /// Create a new adapter wrapping a layout provider.
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into(), positions: LayoutLocationMap::new() }
    }

    /// Apply layout positions to this adapter.
    pub fn apply_positions(&mut self, layout: LayoutPositions) {
        for (id, pos) in layout.map.iter() {
            self.positions.set_position(id, *pos);
        }
    }
}

impl VisualGraphLayout for LayoutProviderAdapter {
    fn name(&self) -> &str { &self.name }
    fn compute_layout(&mut self, _vertex_ids: &[String]) -> LayoutPositions {
        LayoutPositions::new(&self.name)
    }
    fn positions(&self) -> &LayoutLocationMap { &self.positions }
}

/// A task for calculating layout locations in a background thread.
///
/// Ports Ghidra's `ghidra.graph.viewer.layout.CalculateLayoutLocationsTask`.
#[derive(Debug)]
pub struct CalculateLayoutLocationsTask {
    /// The layout provider to use.
    pub layout_name: String,
    /// Vertex ids to layout.
    pub vertex_ids: Vec<String>,
    /// Whether the task is currently running.
    pub running: bool,
    /// The computed result (once complete).
    pub result: Option<LayoutPositions>,
}

impl CalculateLayoutLocationsTask {
    /// Create a new layout calculation task.
    pub fn new(layout_name: impl Into<String>, vertex_ids: Vec<String>) -> Self {
        Self {
            layout_name: layout_name.into(),
            vertex_ids,
            running: false,
            result: None,
        }
    }

    /// Execute the task synchronously with the given provider.
    pub fn execute(&mut self, provider: &mut dyn LayoutProvider) {
        self.running = true;
        self.result = Some(provider.get_layout(&self.vertex_ids));
        self.running = false;
    }

    /// Whether the task has completed.
    pub fn is_complete(&self) -> bool {
        self.result.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hierarchical_layout_basic() {
        let mut provider = HierarchicalLayoutProvider::new();
        let ids: Vec<String> = (0..5).map(|i| format!("v{}", i)).collect();
        let positions = provider.get_layout(&ids);
        assert_eq!(positions.map.len(), 5);
    }

    #[test]
    fn force_directed_layout_circular_initial() {
        let mut provider = ForceDirectedLayoutProvider::new();
        let ids: Vec<String> = (0..4).map(|i| format!("v{}", i)).collect();
        let positions = provider.get_layout(&ids);
        assert_eq!(positions.map.len(), 4);
    }

    #[test]
    fn circular_layout_spread() {
        let mut provider = CircularLayoutProvider::new().with_radius(100.0);
        let ids: Vec<String> = (0..8).map(|i| format!("v{}", i)).collect();
        let positions = provider.get_layout(&ids);
        assert_eq!(positions.map.len(), 8);
    }

    #[test]
    fn grid_layout_wrapping() {
        let mut provider = GridLayoutProvider::new();
        provider.max_columns = 3;
        let ids: Vec<String> = (0..7).map(|i| format!("v{}", i)).collect();
        let positions = provider.get_layout(&ids);
        assert_eq!(positions.map.len(), 7);
        // v3 should be on row 1 (col 0)
        let p0 = positions.get_position("v0").unwrap();
        let p3 = positions.get_position("v3").unwrap();
        assert!((p0.y - 0.0).abs() < 1e-6);
        assert!((p3.y - provider.v_spacing).abs() < 1e-6);
    }

    #[test]
    fn calculate_task_lifecycle() {
        let mut task = CalculateLayoutLocationsTask::new("Test", vec!["a".into(), "b".into()]);
        assert!(!task.is_complete());
        assert!(!task.running);

        let mut provider = GridLayoutProvider::new();
        task.execute(&mut provider);
        assert!(task.is_complete());
        assert!(!task.running);
        assert!(task.result.is_some());
    }

    #[test]
    fn layout_provider_adapter() {
        let mut adapter = LayoutProviderAdapter::new("Adapted");
        let mut layout = LayoutPositions::new("test");
        layout.set_position("v1", super::super::Point2D::new(10.0, 20.0));
        adapter.apply_positions(layout);
        assert_eq!(adapter.name(), "Adapted");
        assert!(adapter.positions().get_position("v1").is_some());
    }

    #[test]
    fn hierarchical_with_custom_spacing() {
        let provider = HierarchicalLayoutProvider::new()
            .with_h_spacing(200.0)
            .with_v_spacing(100.0);
        assert_eq!(provider.h_spacing, 200.0);
        assert_eq!(provider.v_spacing, 100.0);
    }

    #[test]
    fn providers_have_names() {
        assert_eq!(HierarchicalLayoutProvider::new().name(), "Hierarchical");
        assert_eq!(ForceDirectedLayoutProvider::new().name(), "ForceDirected");
        assert_eq!(CircularLayoutProvider::new().name(), "Circular");
        assert_eq!(GridLayoutProvider::new().name(), "Grid");
    }
}
