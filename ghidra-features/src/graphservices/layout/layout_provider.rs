//! Layout provider infrastructure for graph services.
//!
//! Ported from Ghidra's `ghidra.graph.viewer.layout.LayoutProvider` Java
//! interface and the `ghidra.service.graph.LayoutProvider` abstract class.
//!
//! A layout provider computes vertex positions for a graph. This module
//! defines the core [`LayoutProvider`] trait, supporting types for grid
//! positions, and a registry of available layout algorithms.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

// ============================================================================
// Row / Column
// ============================================================================

/// A row index in the layout grid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Row(pub usize);

impl Row {
    /// Get the row index.
    pub fn index(&self) -> usize {
        self.0
    }
}

/// A column index in the layout grid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Column(pub usize);

impl Column {
    /// Get the column index.
    pub fn index(&self) -> usize {
        self.0
    }
}

// ============================================================================
// GridPoint
// ============================================================================

/// A point in the layout grid (column, row).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GridPoint {
    /// The column.
    pub col: Column,
    /// The row.
    pub row: Row,
}

impl GridPoint {
    /// Create a new grid point.
    pub fn new(col: usize, row: usize) -> Self {
        Self {
            col: Column(col),
            row: Row(row),
        }
    }
}

// ============================================================================
// GridLocationMap
// ============================================================================

/// Maps vertex IDs to their grid positions (column, row).
///
/// This is the primary output of a layout algorithm: each vertex is assigned
/// a (column, row) and the layout engine converts these to view-space
/// coordinates.
#[derive(Debug, Clone, Default)]
pub struct GridLocationMap {
    /// Maps vertex_id -> GridPoint.
    locations: HashMap<usize, GridPoint>,
    /// Edge articulation points: edge_key (start_id, end_id) -> list of GridPoints.
    articulations: HashMap<(usize, usize), Vec<GridPoint>>,
}

impl GridLocationMap {
    /// Create a new empty grid location map.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the grid position for a vertex.
    pub fn set(&mut self, vertex_id: usize, point: GridPoint) {
        self.locations.insert(vertex_id, point);
    }

    /// Get the grid position for a vertex.
    pub fn get(&self, vertex_id: usize) -> Option<&GridPoint> {
        self.locations.get(&vertex_id)
    }

    /// Get all vertex IDs and their positions.
    pub fn iter(&self) -> impl Iterator<Item = (usize, &GridPoint)> {
        self.locations.iter().map(|(&id, p)| (id, p))
    }

    /// Number of vertices in the map.
    pub fn len(&self) -> usize {
        self.locations.len()
    }

    /// Whether the map is empty.
    pub fn is_empty(&self) -> bool {
        self.locations.is_empty()
    }

    /// Add an articulation point for an edge.
    pub fn add_articulation(
        &mut self,
        from_id: usize,
        to_id: usize,
        point: GridPoint,
    ) {
        self.articulations
            .entry((from_id, to_id))
            .or_default()
            .push(point);
    }

    /// Get articulation points for an edge.
    pub fn get_articulations(&self, from_id: usize, to_id: usize) -> &[GridPoint] {
        self.articulations
            .get(&(from_id, to_id))
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Remove all entries.
    pub fn clear(&mut self) {
        self.locations.clear();
        self.articulations.clear();
    }
}

// ============================================================================
// GridBounds
// ============================================================================

/// The bounds of a grid in terms of rows and columns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GridBounds {
    /// Number of columns.
    pub columns: usize,
    /// Number of rows.
    pub rows: usize,
}

impl GridBounds {
    /// Create new grid bounds.
    pub fn new(columns: usize, rows: usize) -> Self {
        Self { columns, rows }
    }

    /// Total number of cells.
    pub fn cell_count(&self) -> usize {
        self.columns * self.rows
    }
}

impl Default for GridBounds {
    fn default() -> Self {
        Self {
            columns: 0,
            rows: 0,
        }
    }
}

// ============================================================================
// LayoutPositions
// ============================================================================

/// Holds the computed view-space positions for vertices and edges after a
/// layout algorithm has been applied.
#[derive(Debug, Clone, Default)]
pub struct LayoutPositions {
    /// Vertex positions: vertex_id -> (x, y).
    vertex_positions: HashMap<usize, (f64, f64)>,
    /// Edge route points: edge_key (from, to) -> list of (x, y) waypoints.
    edge_routes: HashMap<(usize, usize), Vec<(f64, f64)>>,
    /// Bounding box of the layout (x, y, width, height).
    bounds: (f64, f64, f64, f64),
}

impl LayoutPositions {
    /// Create a new empty layout positions.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the position for a vertex.
    pub fn set_vertex_position(&mut self, vertex_id: usize, x: f64, y: f64) {
        self.vertex_positions.insert(vertex_id, (x, y));
    }

    /// Get the position for a vertex.
    pub fn get_vertex_position(&self, vertex_id: usize) -> Option<(f64, f64)> {
        self.vertex_positions.get(&vertex_id).copied()
    }

    /// Set edge route waypoints.
    pub fn set_edge_route(
        &mut self,
        from_id: usize,
        to_id: usize,
        points: Vec<(f64, f64)>,
    ) {
        self.edge_routes.insert((from_id, to_id), points);
    }

    /// Get edge route waypoints.
    pub fn get_edge_route(&self, from_id: usize, to_id: usize) -> Option<&[(f64, f64)]> {
        self.edge_routes
            .get(&(from_id, to_id))
            .map(|v| v.as_slice())
    }

    /// Get all vertex positions.
    pub fn vertex_positions(&self) -> &HashMap<usize, (f64, f64)> {
        &self.vertex_positions
    }

    /// Get all edge routes.
    pub fn edge_routes(&self) -> &HashMap<(usize, usize), Vec<(f64, f64)>> {
        &self.edge_routes
    }

    /// Set the bounding box.
    pub fn set_bounds(&mut self, x: f64, y: f64, width: f64, height: f64) {
        self.bounds = (x, y, width, height);
    }

    /// Get the bounding box (x, y, width, height).
    pub fn bounds(&self) -> (f64, f64, f64, f64) {
        self.bounds
    }
}

// ============================================================================
// ViewRestoreOption
// ============================================================================

/// Options for restoring the graph view after a layout change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ViewRestoreOption {
    /// Fit the entire graph within the viewport.
    FitGraph,
    /// Center the view on the focused vertex.
    CenterOnFocus,
    /// Preserve the current view (zoom and pan).
    PreserveView,
}

impl Default for ViewRestoreOption {
    fn default() -> Self {
        Self::FitGraph
    }
}

// ============================================================================
// RelayoutOption
// ============================================================================

/// Options for how to perform a graph relayout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RelayoutOption {
    /// Perform a full layout from scratch.
    Full,
    /// Incrementally update the layout (preserve existing positions where
    /// possible).
    Incremental,
    /// Only layout newly added vertices.
    NewVerticesOnly,
}

impl Default for RelayoutOption {
    fn default() -> Self {
        Self::Full
    }
}

// ============================================================================
// LayoutProvider trait
// ============================================================================

/// A layout provider computes vertex positions for a graph.
///
/// Ported from Ghidra's `ghidra.service.graph.LayoutProvider` and
/// `ghidra.graph.viewer.layout.LayoutProvider`.
///
/// Implementations provide a layout algorithm that assigns grid positions
/// to vertices and optionally articulation points to edges.
pub trait LayoutProvider: Send + Sync {
    /// The name of this layout algorithm.
    fn layout_name(&self) -> &str;

    /// Compute grid locations for the given vertices and edges.
    ///
    /// Returns a [`GridLocationMap`] mapping each vertex ID to a grid
    /// position.
    fn compute_grid_locations(
        &self,
        vertex_ids: &[usize],
        edges: &[(usize, usize)],
    ) -> GridLocationMap;

    /// Whether this layout supports edge articulation points.
    fn uses_edge_articulations(&self) -> bool {
        false
    }

    /// Whether this layout is condensed (less whitespace between columns).
    fn is_condensed(&self) -> bool {
        false
    }

    /// The priority level (higher = more preferred when multiple layouts
    /// are available).
    fn priority_level(&self) -> i32 {
        0
    }

    /// Whether this layout can handle the given vertex/edge counts.
    ///
    /// Some layout algorithms may refuse very large graphs.
    fn supports_size(&self, vertex_count: usize, edge_count: usize) -> bool {
        let _ = (vertex_count, edge_count);
        true
    }
}

// ============================================================================
// LayoutProviderRegistry
// ============================================================================

/// A registry of available layout providers.
///
/// Layout providers can be registered by name and retrieved later for
/// applying to graphs.
pub struct LayoutProviderRegistry {
    providers: HashMap<String, Arc<dyn LayoutProvider>>,
}

impl LayoutProviderRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self {
            providers: HashMap::new(),
        }
    }

    /// Register a layout provider.
    pub fn register(&mut self, provider: Arc<dyn LayoutProvider>) {
        let name = provider.layout_name().to_string();
        self.providers.insert(name, provider);
    }

    /// Get a layout provider by name.
    pub fn get(&self, name: &str) -> Option<&Arc<dyn LayoutProvider>> {
        self.providers.get(name)
    }

    /// Get all registered layout provider names.
    pub fn names(&self) -> Vec<&str> {
        self.providers.keys().map(|s| s.as_str()).collect()
    }

    /// Get the number of registered providers.
    pub fn len(&self) -> usize {
        self.providers.len()
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.providers.is_empty()
    }

    /// Get the default (highest priority) layout provider.
    pub fn default_provider(&self) -> Option<&Arc<dyn LayoutProvider>> {
        self.providers
            .values()
            .max_by_key(|p| p.priority_level())
    }
}

impl Default for LayoutProviderRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// SimpleRowLayout
// ============================================================================

/// A simple row-based layout provider that assigns vertices to a single
/// column, one per row.
///
/// Useful as a fallback or for small graphs.
pub struct SimpleRowLayout;

impl SimpleRowLayout {
    /// Create a new simple row layout.
    pub fn new() -> Self {
        Self
    }
}

impl Default for SimpleRowLayout {
    fn default() -> Self {
        Self::new()
    }
}

impl LayoutProvider for SimpleRowLayout {
    fn layout_name(&self) -> &str {
        "SimpleRow"
    }

    fn compute_grid_locations(
        &self,
        vertex_ids: &[usize],
        _edges: &[(usize, usize)],
    ) -> GridLocationMap {
        let mut map = GridLocationMap::new();
        for (i, &id) in vertex_ids.iter().enumerate() {
            map.set(id, GridPoint::new(0, i));
        }
        map
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_grid_point() {
        let p = GridPoint::new(3, 5);
        assert_eq!(p.col.index(), 3);
        assert_eq!(p.row.index(), 5);
    }

    #[test]
    fn test_grid_location_map() {
        let mut map = GridLocationMap::new();
        assert!(map.is_empty());

        map.set(0, GridPoint::new(0, 0));
        map.set(1, GridPoint::new(1, 0));
        map.set(2, GridPoint::new(0, 1));

        assert_eq!(map.len(), 3);
        assert_eq!(map.get(0).unwrap().col.index(), 0);
        assert_eq!(map.get(1).unwrap().col.index(), 1);
        assert_eq!(map.get(2).unwrap().row.index(), 1);
    }

    #[test]
    fn test_grid_location_map_articulations() {
        let mut map = GridLocationMap::new();
        map.add_articulation(0, 1, GridPoint::new(1, 0));
        map.add_articulation(0, 1, GridPoint::new(2, 0));

        let arts = map.get_articulations(0, 1);
        assert_eq!(arts.len(), 2);
        assert_eq!(arts[0].col.index(), 1);
        assert_eq!(arts[1].col.index(), 2);

        // Non-existent edge returns empty slice
        assert!(map.get_articulations(9, 9).is_empty());
    }

    #[test]
    fn test_layout_positions() {
        let mut pos = LayoutPositions::new();
        pos.set_vertex_position(0, 10.0, 20.0);
        pos.set_vertex_position(1, 30.0, 40.0);

        assert_eq!(pos.get_vertex_position(0), Some((10.0, 20.0)));
        assert_eq!(pos.get_vertex_position(1), Some((30.0, 40.0)));
        assert_eq!(pos.get_vertex_position(2), None);

        pos.set_edge_route(0, 1, vec![(15.0, 20.0), (25.0, 30.0)]);
        let route = pos.get_edge_route(0, 1).unwrap();
        assert_eq!(route.len(), 2);
    }

    #[test]
    fn test_layout_positions_bounds() {
        let mut pos = LayoutPositions::new();
        pos.set_bounds(0.0, 0.0, 800.0, 600.0);
        assert_eq!(pos.bounds(), (0.0, 0.0, 800.0, 600.0));
    }

    #[test]
    fn test_view_restore_option_default() {
        assert_eq!(ViewRestoreOption::default(), ViewRestoreOption::FitGraph);
    }

    #[test]
    fn test_relayout_option_default() {
        assert_eq!(RelayoutOption::default(), RelayoutOption::Full);
    }

    #[test]
    fn test_simple_row_layout() {
        let layout = SimpleRowLayout::new();
        assert_eq!(layout.layout_name(), "SimpleRow");
        assert!(!layout.uses_edge_articulations());
        assert!(!layout.is_condensed());
        assert_eq!(layout.priority_level(), 0);
        assert!(layout.supports_size(1000, 5000));
    }

    #[test]
    fn test_simple_row_layout_computes_grid() {
        let layout = SimpleRowLayout::new();
        let vertex_ids = vec![0, 1, 2];
        let edges: Vec<(usize, usize)> = vec![];
        let map = layout.compute_grid_locations(&vertex_ids, &edges);
        assert_eq!(map.len(), 3);
        assert_eq!(map.get(0).unwrap().col.index(), 0);
        assert_eq!(map.get(0).unwrap().row.index(), 0);
        assert_eq!(map.get(1).unwrap().row.index(), 1);
        assert_eq!(map.get(2).unwrap().row.index(), 2);
    }

    #[test]
    fn test_layout_provider_registry() {
        let mut registry = LayoutProviderRegistry::new();
        assert!(registry.is_empty());

        registry.register(Arc::new(SimpleRowLayout::new()));
        assert_eq!(registry.len(), 1);

        let provider = registry.get("SimpleRow");
        assert!(provider.is_some()); // Registered as "SimpleRow"

        let provider = registry.get("NonExistent");
        assert!(provider.is_none());

        let names = registry.names();
        assert_eq!(names.len(), 1);

        let default = registry.default_provider();
        assert!(default.is_some());
    }
}
