//! Visual graph viewer types: visual vertices, edges, layouts, and rendering.
//!
//! Ports Ghidra's `ghidra.graph.viewer` and related packages.

pub mod layout;

use std::collections::HashMap;

/// Point in 2D space.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Point2D {
    pub x: f64,
    pub y: f64,
}

impl Point2D {
    pub fn new(x: f64, y: f64) -> Self {
        Self { x, y }
    }
}

/// Axis-aligned rectangle.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Rect2D {
    pub x: f64,
    pub y: f64,
    pub width: f64,
    pub height: f64,
}

impl Rect2D {
    pub fn new(x: f64, y: f64, width: f64, height: f64) -> Self {
        Self { x, y, width, height }
    }

    pub fn contains(&self, p: Point2D) -> bool {
        p.x >= self.x
            && p.x <= self.x + self.width
            && p.y >= self.y
            && p.y <= self.y + self.height
    }

    pub fn center(&self) -> Point2D {
        Point2D::new(self.x + self.width / 2.0, self.y + self.height / 2.0)
    }
}

/// Visual representation of a vertex in the graph viewer.
#[derive(Debug, Clone)]
pub struct VisualVertex {
    /// Unique identifier.
    pub id: String,
    /// Display label.
    pub label: String,
    /// Position of the vertex's top-left corner.
    pub position: Point2D,
    /// Size of the vertex.
    pub size: (f64, f64),
    /// Whether this vertex is currently selected.
    pub selected: bool,
    /// Whether this vertex is currently focused.
    pub focused: bool,
    /// Shape for rendering.
    pub shape: crate::graph::service::VertexShape,
}

impl VisualVertex {
    pub fn new(id: impl Into<String>, label: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            label: label.into(),
            position: Point2D::new(0.0, 0.0),
            size: (100.0, 40.0),
            selected: false,
            focused: false,
            shape: Default::default(),
        }
    }

    pub fn bounding_rect(&self) -> Rect2D {
        Rect2D::new(self.position.x, self.position.y, self.size.0, self.size.1)
    }

    pub fn center(&self) -> Point2D {
        Point2D::new(
            self.position.x + self.size.0 / 2.0,
            self.position.y + self.size.1 / 2.0,
        )
    }
}

/// Visual representation of an edge in the graph viewer.
#[derive(Debug, Clone)]
pub struct VisualEdge {
    /// Unique identifier.
    pub id: String,
    /// Source vertex id.
    pub from_id: String,
    /// Target vertex id.
    pub to_id: String,
    /// Articulation points for routing the edge.
    pub articulations: Vec<Point2D>,
    /// Whether this edge is highlighted.
    pub highlighted: bool,
    /// Whether this edge is hovered.
    pub hovered: bool,
}

impl VisualEdge {
    pub fn new(
        id: impl Into<String>,
        from_id: impl Into<String>,
        to_id: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            from_id: from_id.into(),
            to_id: to_id.into(),
            articulations: Vec::new(),
            highlighted: false,
            hovered: false,
        }
    }
}

/// A complete visual graph with positioned vertices and edges.
#[derive(Debug, Clone)]
pub struct VisualGraph {
    vertices: HashMap<String, VisualVertex>,
    edges: HashMap<String, VisualEdge>,
    out_edges: HashMap<String, Vec<String>>,
    in_edges: HashMap<String, Vec<String>>,
}

impl VisualGraph {
    pub fn new() -> Self {
        Self {
            vertices: HashMap::new(),
            edges: HashMap::new(),
            out_edges: HashMap::new(),
            in_edges: HashMap::new(),
        }
    }

    pub fn add_vertex(&mut self, v: VisualVertex) {
        let id = v.id.clone();
        self.out_edges.entry(id.clone()).or_default();
        self.in_edges.entry(id.clone()).or_default();
        self.vertices.insert(id, v);
    }

    pub fn add_edge(&mut self, e: VisualEdge) {
        let eid = e.id.clone();
        self.out_edges
            .entry(e.from_id.clone())
            .or_default()
            .push(eid.clone());
        self.in_edges
            .entry(e.to_id.clone())
            .or_default()
            .push(eid.clone());
        self.edges.insert(eid, e);
    }

    pub fn vertex(&self, id: &str) -> Option<&VisualVertex> {
        self.vertices.get(id)
    }

    pub fn vertex_mut(&mut self, id: &str) -> Option<&mut VisualVertex> {
        self.vertices.get_mut(id)
    }

    /// Iterate over all vertices mutably.
    pub fn all_vertices_mut(&mut self) -> impl Iterator<Item = &mut VisualVertex> {
        self.vertices.values_mut()
    }

    pub fn edge(&self, id: &str) -> Option<&VisualEdge> {
        self.edges.get(id)
    }

    pub fn edge_mut(&mut self, id: &str) -> Option<&mut VisualEdge> {
        self.edges.get_mut(id)
    }

    pub fn vertices(&self) -> Vec<&VisualVertex> {
        self.vertices.values().collect()
    }

    pub fn edges(&self) -> Vec<&VisualEdge> {
        self.edges.values().collect()
    }

    pub fn out_edges(&self, vertex_id: &str) -> Vec<&VisualEdge> {
        self.out_edges
            .get(vertex_id)
            .map(|ids| {
                ids.iter()
                    .filter_map(|eid| self.edges.get(eid.as_str()))
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn in_edges(&self, vertex_id: &str) -> Vec<&VisualEdge> {
        self.in_edges
            .get(vertex_id)
            .map(|ids| {
                ids.iter()
                    .filter_map(|eid| self.edges.get(eid.as_str()))
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn vertex_count(&self) -> usize {
        self.vertices.len()
    }

    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }

    pub fn is_empty(&self) -> bool {
        self.vertices.is_empty()
    }

    /// Select a vertex and deselect all others.
    pub fn select_vertex(&mut self, id: &str) {
        for v in self.vertices.values_mut() {
            v.selected = v.id == id;
        }
    }

    /// Clear all selections.
    pub fn clear_selection(&mut self) {
        for v in self.vertices.values_mut() {
            v.selected = false;
        }
    }

    /// Get the bounding rectangle of the entire graph.
    pub fn bounds(&self) -> Option<Rect2D> {
        if self.vertices.is_empty() {
            return None;
        }
        let mut min_x = f64::MAX;
        let mut min_y = f64::MAX;
        let mut max_x = f64::MIN;
        let mut max_y = f64::MIN;
        for v in self.vertices.values() {
            let r = v.bounding_rect();
            min_x = min_x.min(r.x);
            min_y = min_y.min(r.y);
            max_x = max_x.max(r.x + r.width);
            max_y = max_y.max(r.y + r.height);
        }
        Some(Rect2D::new(min_x, min_y, max_x - min_x, max_y - min_y))
    }
}

impl Default for VisualGraph {
    fn default() -> Self {
        Self::new()
    }
}

/// Layout provider trait.
pub trait LayoutProvider: Send + Sync {
    /// Compute positions for all vertices in the graph.
    fn compute_layout(&self, graph: &mut VisualGraph);
}

/// A simple grid layout.
pub struct GridLayoutProvider {
    /// Horizontal spacing between vertices.
    pub h_spacing: f64,
    /// Vertical spacing between vertices.
    pub v_spacing: f64,
    /// Maximum columns.
    pub max_columns: usize,
}

impl Default for GridLayoutProvider {
    fn default() -> Self {
        Self {
            h_spacing: 150.0,
            v_spacing: 80.0,
            max_columns: 5,
        }
    }
}

impl LayoutProvider for GridLayoutProvider {
    fn compute_layout(&self, graph: &mut VisualGraph) {
        let mut col = 0;
        let mut row = 0;
        for v in graph.vertices.values_mut() {
            v.position = Point2D::new(
                col as f64 * self.h_spacing,
                row as f64 * self.v_spacing,
            );
            col += 1;
            if col >= self.max_columns {
                col = 0;
                row += 1;
            }
        }
    }
}

/// Graph perspective info for restoring view state.
#[derive(Debug, Clone)]
pub struct GraphPerspectiveInfo {
    /// Center point of the viewport.
    pub center: Point2D,
    /// Zoom scale.
    pub scale: f64,
}

impl Default for GraphPerspectiveInfo {
    fn default() -> Self {
        Self {
            center: Point2D::new(0.0, 0.0),
            scale: 1.0,
        }
    }
}
