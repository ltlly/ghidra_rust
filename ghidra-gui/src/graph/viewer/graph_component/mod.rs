//! Graph viewer component and utilities.
//!
//! Ports Ghidra's `ghidra.graph.viewer` core types:
//! `GraphViewer`, `GraphComponent`, `GraphViewerUtils`,
//! `VisualGraphView`, `VisualGraphViewUpdater`, `SatelliteGraphViewer`,
//! and `PathHighlightMode`.

use std::collections::{HashMap, HashSet};

use super::{Point2D, Rect2D, VisualEdge, VisualGraph, VisualVertex};

// ============================================================================
// PathHighlightMode
// ============================================================================

/// Controls how edges are highlighted based on vertex hover/selection.
///
/// Ports `ghidra.graph.viewer.PathHighlightMode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathHighlightMode {
    /// No path highlighting.
    None,
    /// Highlight edges when hovering over a vertex.
    HoverOnly,
    /// Highlight edges for the focused/selected vertex only.
    FocusOnly,
    /// Highlight edges for both hover and focus.
    HoverAndFocus,
}

impl Default for PathHighlightMode {
    fn default() -> Self {
        Self::HoverAndFocus
    }
}

// ============================================================================
// GraphViewerUtils
// ============================================================================

/// Utility functions for graph viewer operations.
///
/// Ports `ghidra.graph.viewer.GraphViewerUtils`.
pub struct GraphViewerUtils;

impl GraphViewerUtils {
    /// Calculate the center of all vertices in the graph.
    pub fn graph_center(graph: &VisualGraph) -> Point2D {
        let verts = graph.vertices();
        if verts.is_empty() {
            return Point2D::ZERO;
        }
        let mut sx = 0.0;
        let mut sy = 0.0;
        for v in &verts {
            let c = v.center();
            sx += c.x;
            sy += c.y;
        }
        let n = verts.len() as f64;
        Point2D::new(sx / n, sy / n)
    }

    /// Find all vertices within a rectangular region.
    pub fn vertices_in_rect(graph: &VisualGraph, rect: &Rect2D) -> Vec<String> {
        graph
            .vertices()
            .iter()
            .filter(|v| rect.contains(v.center()))
            .map(|v| v.id.clone())
            .collect()
    }

    /// Find the vertex closest to a point.
    pub fn closest_vertex(graph: &VisualGraph, point: Point2D) -> Option<String> {
        let mut best_dist = f64::MAX;
        let mut best_id = None;
        for v in graph.vertices() {
            let c = v.center();
            let dx = c.x - point.x;
            let dy = c.y - point.y;
            let dist = dx * dx + dy * dy;
            if dist < best_dist {
                best_dist = dist;
                best_id = Some(v.id.clone());
            }
        }
        best_id
    }

    /// Compute the zoom scale needed to fit the graph into a viewport.
    pub fn compute_fit_scale(graph: &VisualGraph, viewport: Rect2D) -> f64 {
        if let Some(bounds) = graph.bounds() {
            if bounds.width <= 0.0 || bounds.height <= 0.0 {
                return 1.0;
            }
            let scale_x = viewport.width / bounds.width;
            let scale_y = viewport.height / bounds.height;
            scale_x.min(scale_y).min(2.0) // cap at 2x zoom
        } else {
            1.0
        }
    }

    /// Layout a graph using a simple force-directed algorithm.
    ///
    /// Iterates `iterations` times applying repulsive forces between all
    /// vertex pairs and attractive forces along edges.
    pub fn simple_force_layout(
        graph: &mut VisualGraph,
        iterations: usize,
        repulsion: f64,
        attraction: f64,
        damping: f64,
    ) {
        let vertex_ids: Vec<String> = graph.vertices().iter().map(|v| v.id.clone()).collect();
        let mut velocities: HashMap<String, (f64, f64)> = HashMap::new();

        for _ in 0..iterations {
            // Reset forces
            let mut forces: HashMap<String, (f64, f64)> = HashMap::new();
            for id in &vertex_ids {
                forces.insert(id.clone(), (0.0, 0.0));
            }

            // Repulsive forces between all pairs
            for i in 0..vertex_ids.len() {
                for j in (i + 1)..vertex_ids.len() {
                    let a = &vertex_ids[i];
                    let b = &vertex_ids[j];
                    let pa = graph.vertex(a).unwrap().center();
                    let pb = graph.vertex(b).unwrap().center();
                    let dx = pa.x - pb.x;
                    let dy = pa.y - pb.y;
                    let dist_sq = (dx * dx + dy * dy).max(1.0);
                    let dist = dist_sq.sqrt();
                    let force = repulsion / dist_sq;
                    let fx = force * dx / dist;
                    let fy = force * dy / dist;
                    if let Some(f) = forces.get_mut(a) {
                        f.0 += fx;
                        f.1 += fy;
                    }
                    if let Some(f) = forces.get_mut(b) {
                        f.0 -= fx;
                        f.1 -= fy;
                    }
                }
            }

            // Attractive forces along edges
            for e in graph.edges() {
                let pa = graph.vertex(&e.from_id).unwrap().center();
                let pb = graph.vertex(&e.to_id).unwrap().center();
                let dx = pb.x - pa.x;
                let dy = pb.y - pa.y;
                let dist = (dx * dx + dy * dy).sqrt().max(1.0);
                let force = attraction * dist;
                let fx = force * dx / dist;
                let fy = force * dy / dist;
                if let Some(f) = forces.get_mut(&e.from_id) {
                    f.0 += fx;
                    f.1 += fy;
                }
                if let Some(f) = forces.get_mut(&e.to_id) {
                    f.0 -= fx;
                    f.1 -= fy;
                }
            }

            // Apply forces with damping
            for id in &vertex_ids {
                let (fx, fy) = forces.get(id).copied().unwrap_or((0.0, 0.0));
                let (vx, vy) = velocities.entry(id.clone()).or_insert((0.0, 0.0));
                *vx = (*vx + fx) * damping;
                *vy = (*vy + fy) * damping;
                if let Some(v) = graph.vertex_mut(id) {
                    v.position.x += *vx;
                    v.position.y += *vy;
                }
            }
        }
    }
}

// ============================================================================
// GraphViewer
// ============================================================================

/// The top-level graph viewer that manages viewport, selection, and rendering.
///
/// Ports Ghidra's `ghidra.graph.viewer.GraphViewer` and
/// `ghidra.graph.viewer.VisualGraphView`.
#[derive(Debug, Clone)]
pub struct GraphViewer {
    /// The underlying visual graph.
    pub graph: VisualGraph,
    /// Viewport origin (top-left corner in graph-space).
    pub viewport_origin: Point2D,
    /// Viewport size in pixels.
    pub viewport_size: (f64, f64),
    /// Current zoom scale (1.0 = 100%).
    pub scale: f64,
    /// Path highlight mode.
    pub highlight_mode: PathHighlightMode,
    /// Currently hovered vertex (if any).
    pub hovered_vertex: Option<String>,
    /// Vertices in the active hover/focus path.
    path_vertices: HashSet<String>,
    /// Edges in the active hover/focus path.
    path_edges: HashSet<String>,
    /// Edge id -> articulation points.
    articulations: HashMap<String, Vec<Point2D>>,
}

impl GraphViewer {
    /// Create a new graph viewer.
    pub fn new() -> Self {
        Self {
            graph: VisualGraph::new(),
            viewport_origin: Point2D::ZERO,
            viewport_size: (800.0, 600.0),
            scale: 1.0,
            highlight_mode: PathHighlightMode::default(),
            hovered_vertex: None,
            path_vertices: HashSet::new(),
            path_edges: HashSet::new(),
            articulations: HashMap::new(),
        }
    }

    /// Set the viewport size.
    pub fn set_viewport_size(&mut self, width: f64, height: f64) {
        self.viewport_size = (width, height);
    }

    /// Pan the viewport by a delta.
    pub fn pan(&mut self, dx: f64, dy: f64) {
        self.viewport_origin.x += dx;
        self.viewport_origin.y += dy;
    }

    /// Zoom the view, keeping `center` fixed.
    pub fn zoom(&mut self, factor: f64, center: Point2D) {
        let new_scale = (self.scale * factor).clamp(0.1, 5.0);
        let ratio = new_scale / self.scale;
        // Adjust viewport origin to keep center fixed
        self.viewport_origin.x = center.x - (center.x - self.viewport_origin.x) * ratio;
        self.viewport_origin.y = center.y - (center.y - self.viewport_origin.y) * ratio;
        self.scale = new_scale;
    }

    /// Convert screen coordinates to graph coordinates.
    pub fn screen_to_graph(&self, screen: Point2D) -> Point2D {
        Point2D::new(
            screen.x / self.scale + self.viewport_origin.x,
            screen.y / self.scale + self.viewport_origin.y,
        )
    }

    /// Convert graph coordinates to screen coordinates.
    pub fn graph_to_screen(&self, graph_pt: Point2D) -> Point2D {
        Point2D::new(
            (graph_pt.x - self.viewport_origin.x) * self.scale,
            (graph_pt.y - self.viewport_origin.y) * self.scale,
        )
    }

    /// Fit the entire graph into the viewport.
    pub fn fit_graph_to_view(&mut self) {
        let viewport = Rect2D::new(0.0, 0.0, self.viewport_size.0, self.viewport_size.1);
        self.scale = GraphViewerUtils::compute_fit_scale(&self.graph, viewport);
        let center = GraphViewerUtils::graph_center(&self.graph);
        self.viewport_origin = Point2D::new(
            center.x - self.viewport_size.0 / (2.0 * self.scale),
            center.y - self.viewport_size.1 / (2.0 * self.scale),
        );
    }

    /// Update the hover state and compute the active path.
    pub fn set_hovered_vertex(&mut self, vertex_id: Option<String>) {
        self.hovered_vertex = vertex_id;
        self.update_path();
    }

    /// Update path edges based on highlight mode.
    fn update_path(&mut self) {
        self.path_vertices.clear();
        self.path_edges.clear();

        if self.highlight_mode == PathHighlightMode::None {
            return;
        }

        let should_highlight_hover = matches!(
            self.highlight_mode,
            PathHighlightMode::HoverOnly | PathHighlightMode::HoverAndFocus
        );

        if should_highlight_hover {
            if let Some(ref hovered) = self.hovered_vertex {
                self.path_vertices.insert(hovered.clone());
                for e in self.graph.out_edges(hovered) {
                    self.path_edges.insert(e.id.clone());
                    self.path_vertices.insert(e.to_id.clone());
                }
                for e in self.graph.in_edges(hovered) {
                    self.path_edges.insert(e.id.clone());
                    self.path_vertices.insert(e.from_id.clone());
                }
            }
        }
    }

    /// Get the edges in the active path.
    pub fn path_edges(&self) -> &HashSet<String> {
        &self.path_edges
    }

    /// Get the vertices in the active path.
    pub fn path_vertices(&self) -> &HashSet<String> {
        &self.path_vertices
    }

    /// Set articulation points for an edge.
    pub fn set_articulations(&mut self, edge_id: impl Into<String>, points: Vec<Point2D>) {
        self.articulations.insert(edge_id.into(), points);
    }

    /// Get articulation points for an edge.
    pub fn get_articulations(&self, edge_id: &str) -> &[Point2D] {
        self.articulations
            .get(edge_id)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }
}

impl Default for GraphViewer {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// GraphComponent
// ============================================================================

/// A component wrapper that connects a `GraphViewer` with mouse/keyboard handling.
///
/// Ports Ghidra's `ghidra.graph.viewer.GraphComponent`.
#[derive(Debug)]
pub struct GraphComponent {
    /// The underlying graph viewer.
    pub viewer: GraphViewer,
    /// Whether the component is enabled for interaction.
    pub enabled: bool,
    /// Scroll position.
    pub scroll_position: Point2D,
}

impl GraphComponent {
    /// Create a new graph component.
    pub fn new() -> Self {
        Self {
            viewer: GraphViewer::new(),
            enabled: true,
            scroll_position: Point2D::ZERO,
        }
    }

    /// Handle a mouse click at screen coordinates.
    /// Returns the id of the clicked vertex, if any.
    pub fn handle_click(&self, screen_x: f64, screen_y: f64) -> Option<String> {
        if !self.enabled {
            return None;
        }
        let graph_pt = self.viewer.screen_to_graph(Point2D::new(screen_x, screen_y));
        GraphViewerUtils::closest_vertex(&self.viewer.graph, graph_pt)
    }

    /// Handle mouse move for hover detection.
    /// Returns the id of the hovered vertex, if any.
    pub fn handle_mouse_move(&mut self, screen_x: f64, screen_y: f64) -> Option<String> {
        if !self.enabled {
            return None;
        }
        let graph_pt = self.viewer.screen_to_graph(Point2D::new(screen_x, screen_y));
        let hovered = GraphViewerUtils::closest_vertex(&self.viewer.graph, graph_pt);
        self.viewer.set_hovered_vertex(hovered.clone());
        hovered
    }

    /// Handle scroll/zoom.
    pub fn handle_scroll(&mut self, delta: f64, screen_x: f64, screen_y: f64) {
        if !self.enabled {
            return;
        }
        let factor = if delta > 0.0 { 1.1 } else { 0.9 };
        let center = Point2D::new(screen_x, screen_y);
        self.viewer.zoom(factor, center);
    }

    /// Handle a drag (pan).
    pub fn handle_drag(&mut self, dx: f64, dy: f64) {
        if !self.enabled {
            return;
        }
        self.viewer.pan(-dx / self.viewer.scale, -dy / self.viewer.scale);
    }
}

impl Default for GraphComponent {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// SatelliteGraphViewer
// ============================================================================

/// A miniature overview of the graph for navigation.
///
/// Ports Ghidra's `ghidra.graph.viewer.SatelliteGraphViewer`.
#[derive(Debug, Clone)]
pub struct SatelliteGraphViewer {
    /// Bounding rectangle of the satellite view.
    pub bounds: Rect2D,
    /// The scale factor for rendering the miniaturized graph.
    pub scale: f64,
    /// Whether the satellite view is visible.
    pub visible: bool,
    /// The viewport rectangle (shown as a draggable box).
    pub viewport_rect: Rect2D,
}

impl SatelliteGraphViewer {
    /// Create a new satellite graph viewer.
    pub fn new(width: f64, height: f64) -> Self {
        Self {
            bounds: Rect2D::new(0.0, 0.0, width, height),
            scale: 0.1,
            visible: true,
            viewport_rect: Rect2D::new(0.0, 0.0, 50.0, 50.0),
        }
    }

    /// Update the viewport rectangle to reflect the current view of the main viewer.
    pub fn update_viewport(&mut self, viewer: &GraphViewer) {
        let x = (viewer.viewport_origin.x - viewer.graph.bounds().map(|b| b.x).unwrap_or(0.0))
            * self.scale;
        let y = (viewer.viewport_origin.y - viewer.graph.bounds().map(|b| b.y).unwrap_or(0.0))
            * self.scale;
        let w = viewer.viewport_size.0 / viewer.scale * self.scale;
        let h = viewer.viewport_size.1 / viewer.scale * self.scale;
        self.viewport_rect = Rect2D::new(x, y, w, h);
    }

    /// Handle a click in the satellite view to navigate the main viewer.
    pub fn handle_click(&self, click_x: f64, click_y: f64, viewer: &mut GraphViewer) {
        let graph_x = click_x / self.scale;
        let graph_y = click_y / self.scale;
        viewer.viewport_origin.x = graph_x - viewer.viewport_size.0 / (2.0 * viewer.scale);
        viewer.viewport_origin.y = graph_y - viewer.viewport_size.1 / (2.0 * viewer.scale);
    }
}

// ============================================================================
// CachingSatelliteGraphViewer
// ============================================================================

/// A satellite viewer that caches the rendered graph image.
///
/// Ports `ghidra.graph.viewer.satellite.CachingSatelliteGraphViewer`.
#[derive(Debug, Clone)]
pub struct CachingSatelliteGraphViewer {
    /// The underlying satellite viewer.
    pub satellite: SatelliteGraphViewer,
    /// Cache generation counter - incremented when graph changes.
    pub cache_generation: u64,
    /// Last rendered generation.
    pub rendered_generation: u64,
}

impl CachingSatelliteGraphViewer {
    /// Create a new caching satellite viewer.
    pub fn new(width: f64, height: f64) -> Self {
        Self {
            satellite: SatelliteGraphViewer::new(width, height),
            cache_generation: 0,
            rendered_generation: 0,
        }
    }

    /// Invalidate the cache.
    pub fn invalidate(&mut self) {
        self.cache_generation += 1;
    }

    /// Whether the cache needs to be refreshed.
    pub fn needs_redraw(&self) -> bool {
        self.cache_generation != self.rendered_generation
    }

    /// Mark the cache as up to date.
    pub fn mark_rendered(&mut self) {
        self.rendered_generation = self.cache_generation;
    }
}

// ============================================================================
// GraphPerspectiveInfo
// ============================================================================

/// Stores and restores graph perspective data: zoom level, layout offset, and
/// view offset.  Used for persisting the user's current view state across
/// sessions or when switching tabs.
///
/// Ports `ghidra.graph.viewer.GraphPerspectiveInfo`.
#[derive(Debug, Clone)]
pub struct GraphPerspectiveInfo {
    /// Layout-space translation offset (the layout transformer's origin).
    pub layout_translate: Point2D,
    /// View-space translation offset (the view transformer's origin).
    pub view_translate: Point2D,
    /// Current zoom level (1.0 = 100%).
    pub zoom: f64,
    /// Whether to restore zoom when applying this perspective.
    pub restore_zoom: bool,
}

/// Sentinel value for an invalid coordinate.
const INVALID_COORD: f64 = f64::MAX;
/// Sentinel value for an invalid zoom level.
const INVALID_ZOOM: f64 = -1.0;

impl GraphPerspectiveInfo {
    /// Create an invalid (empty) perspective.  Applying this perspective
    /// is a no-op.
    pub fn invalid() -> Self {
        Self {
            layout_translate: Point2D::new(INVALID_COORD, INVALID_COORD),
            view_translate: Point2D::new(INVALID_COORD, INVALID_COORD),
            zoom: INVALID_ZOOM,
            restore_zoom: false,
        }
    }

    /// Create a perspective from a `GraphViewer`'s current state.
    pub fn from_viewer(viewer: &GraphViewer) -> Self {
        Self {
            layout_translate: viewer.viewport_origin,
            view_translate: Point2D::ZERO,
            zoom: viewer.scale,
            restore_zoom: true,
        }
    }

    /// Create a perspective from raw values.
    pub fn new(layout_translate: Point2D, view_translate: Point2D, zoom: f64) -> Self {
        Self {
            layout_translate,
            view_translate,
            zoom,
            restore_zoom: true,
        }
    }

    /// Whether this perspective is invalid and should not be applied.
    pub fn is_invalid(&self) -> bool {
        self.zoom == INVALID_ZOOM
            || self.layout_translate.x == INVALID_COORD
            || self.layout_translate.y == INVALID_COORD
    }

    /// Apply this perspective to a `GraphViewer`, restoring zoom and position.
    pub fn apply_to(&self, viewer: &mut GraphViewer) {
        if self.is_invalid() {
            return;
        }
        viewer.viewport_origin = self.layout_translate;
        if self.restore_zoom {
            viewer.scale = self.zoom.clamp(0.1, 5.0);
        }
    }

    /// Serialize the perspective to a JSON string for persistence.
    pub fn to_json(&self) -> String {
        format!(
            r#"{{"layout_x":{},"layout_y":{},"view_x":{},"view_y":{},"zoom":{}}}"#,
            self.layout_translate.x,
            self.layout_translate.y,
            self.view_translate.x,
            self.view_translate.y,
            self.zoom,
        )
    }

    /// Restore a perspective from a JSON-like map of key-value pairs.
    /// This mirrors Ghidra's `SaveState` approach where fields are stored
    /// by name and restored individually.
    pub fn from_save_state(
        layout_x: Option<f64>,
        layout_y: Option<f64>,
        view_x: Option<f64>,
        view_y: Option<f64>,
        zoom: Option<f64>,
    ) -> Self {
        let lx = layout_x.unwrap_or(INVALID_COORD);
        let ly = layout_y.unwrap_or(INVALID_COORD);
        let vx = view_x.unwrap_or(INVALID_COORD);
        let vy = view_y.unwrap_or(INVALID_COORD);
        let z = zoom.unwrap_or(INVALID_ZOOM);

        if lx == INVALID_COORD || ly == INVALID_COORD || z == INVALID_ZOOM {
            return Self::invalid();
        }

        Self {
            layout_translate: Point2D::new(lx, ly),
            view_translate: Point2D::new(vx, vy),
            zoom: z,
            restore_zoom: true,
        }
    }
}

// ============================================================================
// VisualGraphViewUpdater
// ============================================================================

/// Coordinates graph view mutations and animation jobs.
///
/// All view-changing operations (vertex relocation, relayout, zoom-to-fit,
/// path highlight transitions) flow through this class so that they can be
/// optionally animated and synchronised with the satellite viewer.
///
/// Ports `ghidra.graph.viewer.VisualGraphViewUpdater`.
#[derive(Debug, Clone)]
pub struct VisualGraphViewUpdater {
    /// Pending vertex relocations.
    pending_relocations: HashMap<String, Point2D>,
    /// Whether a full relayout is requested.
    relayout_requested: bool,
    /// Whether a zoom-to-fit is pending.
    zoom_to_fit_requested: bool,
    /// Current animation progress (0.0 .. 1.0).  None means no animation.
    animation_progress: Option<f64>,
    /// Animation step size per tick.
    animation_step: f64,
    /// Completed animation callbacks.
    on_complete: Vec<String>,
}

impl Default for VisualGraphViewUpdater {
    fn default() -> Self {
        Self {
            pending_relocations: HashMap::new(),
            relayout_requested: false,
            zoom_to_fit_requested: false,
            animation_progress: None,
            animation_step: 0.05,
            on_complete: Vec::new(),
        }
    }
}

impl VisualGraphViewUpdater {
    /// Create a new view updater.
    pub fn new() -> Self {
        Self::default()
    }

    /// Request a vertex be moved to a new position.
    pub fn relocate_vertex(&mut self, vertex_id: impl Into<String>, position: Point2D) {
        self.pending_relocations.insert(vertex_id.into(), position);
    }

    /// Request a full graph relayout.
    pub fn request_relayout(&mut self) {
        self.relayout_requested = true;
    }

    /// Request that the viewer zooms to fit the entire graph.
    pub fn request_zoom_to_fit(&mut self) {
        self.zoom_to_fit_requested = true;
    }

    /// Start an animation for the given duration.
    pub fn start_animation(&mut self, step: f64) {
        self.animation_progress = Some(0.0);
        self.animation_step = step.max(0.01);
    }

    /// Advance the animation by one tick.  Returns `true` if the animation
    /// completed this tick.
    pub fn tick_animation(&mut self) -> bool {
        if let Some(ref mut progress) = self.animation_progress {
            *progress += self.animation_step;
            if *progress >= 1.0 {
                self.animation_progress = None;
                return true;
            }
        }
        false
    }

    /// Whether an animation is currently running.
    pub fn is_animating(&self) -> bool {
        self.animation_progress.is_some()
    }

    /// The current animation progress (0.0 .. 1.0), or None if not animating.
    pub fn animation_progress(&self) -> Option<f64> {
        self.animation_progress
    }

    /// Register a callback name to fire when the current animation completes.
    pub fn on_animation_complete(&mut self, name: impl Into<String>) {
        self.on_complete.push(name.into());
    }

    /// Drain and return the completed-animation callback names.
    pub fn drain_completion_callbacks(&mut self) -> Vec<String> {
        std::mem::take(&mut self.on_complete)
    }

    /// Apply pending updates to the graph and viewer.
    pub fn apply_updates(&mut self, graph: &mut VisualGraph, viewer: &mut GraphViewer) {
        // Apply vertex relocations.
        for (id, pos) in self.pending_relocations.drain() {
            if let Some(v) = graph.vertex_mut(&id) {
                v.position = pos;
            }
        }

        // Apply relayout.
        if self.relayout_requested {
            self.relayout_requested = false;
            // Relayout is delegated to the layout provider; just clear the flag here.
        }

        // Apply zoom-to-fit.
        if self.zoom_to_fit_requested {
            self.zoom_to_fit_requested = false;
            viewer.fit_graph_to_view();
        }
    }

    /// Apply a weighted blend between the current viewer state and a target
    /// perspective (used during animated transitions).
    pub fn interpolate_perspective(
        &self,
        current: &GraphPerspectiveInfo,
        target: &GraphPerspectiveInfo,
        t: f64,
    ) -> GraphPerspectiveInfo {
        let t = t.clamp(0.0, 1.0);
        let one_minus_t = 1.0 - t;
        GraphPerspectiveInfo {
            layout_translate: Point2D::new(
                current.layout_translate.x * one_minus_t + target.layout_translate.x * t,
                current.layout_translate.y * one_minus_t + target.layout_translate.y * t,
            ),
            view_translate: Point2D::new(
                current.view_translate.x * one_minus_t + target.view_translate.x * t,
                current.view_translate.y * one_minus_t + target.view_translate.y * t,
            ),
            zoom: current.zoom * one_minus_t + target.zoom * t,
            restore_zoom: true,
        }
    }

    /// Whether any updates are pending.
    pub fn has_pending_updates(&self) -> bool {
        !self.pending_relocations.is_empty()
            || self.relayout_requested
            || self.zoom_to_fit_requested
    }
}

// ============================================================================
// GraphSatelliteListener
// ============================================================================

/// Trait for receiving notifications about satellite view changes.
///
/// Ports `ghidra.graph.viewer.GraphSatelliteListener`.
pub trait GraphSatelliteListener: Send + Sync + std::fmt::Debug {
    /// Called when the satellite view's viewport rectangle changes.
    fn on_viewport_changed(&self, _new_viewport: Rect2D) {}

    /// Called when the satellite view is shown.
    fn on_satellite_shown(&self) {}

    /// Called when the satellite view is hidden.
    fn on_satellite_hidden(&self) {}

    /// Called when the satellite view scale changes.
    fn on_scale_changed(&self, _new_scale: f64) {}
}

/// A no-op implementation of `GraphSatelliteListener`.
#[derive(Debug, Clone, Copy)]
pub struct NullGraphSatelliteListener;

impl GraphSatelliteListener for NullGraphSatelliteListener {}

/// Container for managing satellite view listeners.
#[derive(Debug, Default)]
pub struct SatelliteListenerRegistry {
    listeners: Vec<Box<dyn GraphSatelliteListener>>,
}

impl SatelliteListenerRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self { listeners: Vec::new() }
    }

    /// Add a listener.
    pub fn add_listener(&mut self, listener: Box<dyn GraphSatelliteListener>) {
        self.listeners.push(listener);
    }

    /// Notify all listeners that the viewport changed.
    pub fn notify_viewport_changed(&self, viewport: Rect2D) {
        for l in &self.listeners {
            l.on_viewport_changed(viewport);
        }
    }

    /// Notify all listeners that the satellite was shown.
    pub fn notify_shown(&self) {
        for l in &self.listeners {
            l.on_satellite_shown();
        }
    }

    /// Notify all listeners that the satellite was hidden.
    pub fn notify_hidden(&self) {
        for l in &self.listeners {
            l.on_satellite_hidden();
        }
    }

    /// Notify all listeners that the scale changed.
    pub fn notify_scale_changed(&self, scale: f64) {
        for l in &self.listeners {
            l.on_scale_changed(scale);
        }
    }

    /// Number of registered listeners.
    pub fn len(&self) -> usize {
        self.listeners.len()
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.listeners.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_highlight_mode_default() {
        assert_eq!(PathHighlightMode::default(), PathHighlightMode::HoverAndFocus);
    }

    #[test]
    fn graph_viewer_new() {
        let gv = GraphViewer::new();
        assert_eq!(gv.scale, 1.0);
        assert_eq!(gv.viewport_size, (800.0, 600.0));
    }

    #[test]
    fn graph_viewer_zoom() {
        let mut gv = GraphViewer::new();
        gv.zoom(2.0, Point2D::new(400.0, 300.0));
        assert!((gv.scale - 2.0).abs() < 1e-6);
    }

    #[test]
    fn graph_viewer_screen_graph_conversion() {
        let mut gv = GraphViewer::new();
        gv.scale = 2.0;
        gv.viewport_origin = Point2D::new(100.0, 100.0);
        let screen = gv.graph_to_screen(Point2D::new(200.0, 200.0));
        assert!((screen.x - 200.0).abs() < 1e-6);
        assert!((screen.y - 200.0).abs() < 1e-6);
        let back = gv.screen_to_graph(screen);
        assert!((back.x - 200.0).abs() < 1e-6);
        assert!((back.y - 200.0).abs() < 1e-6);
    }

    #[test]
    fn graph_viewer_set_hovered_vertex() {
        let mut gv = GraphViewer::new();
        gv.graph.add_vertex(VisualVertex::new("v1", "V1"));
        gv.graph.add_vertex(VisualVertex::new("v2", "V2"));
        gv.graph.add_edge(VisualEdge::new("e1", "v1", "v2"));
        gv.set_hovered_vertex(Some("v1".to_string()));
        assert!(gv.path_edges().contains("e1"));
        assert!(gv.path_vertices().contains("v2"));
    }

    #[test]
    fn graph_component_click() {
        let mut gc = GraphComponent::new();
        gc.viewer
            .graph
            .add_vertex(VisualVertex::new("v1", "V1"));
        // The vertex is at origin with size (100, 40), so center is (50, 20)
        // In screen coords at scale 1.0 with viewport at (0,0), that's (50, 20)
        let clicked = gc.handle_click(50.0, 20.0);
        assert!(clicked.is_some());
    }

    #[test]
    fn graph_component_drag() {
        let mut gc = GraphComponent::new();
        gc.handle_drag(10.0, 20.0);
        assert!((gc.viewer.viewport_origin.x + 10.0).abs() < 1e-6);
        assert!((gc.viewer.viewport_origin.y + 20.0).abs() < 1e-6);
    }

    #[test]
    fn satellite_graph_viewer() {
        let mut sat = SatelliteGraphViewer::new(200.0, 150.0);
        assert!(sat.visible);
        let mut viewer = GraphViewer::new();
        viewer.graph.add_vertex(VisualVertex::new("v1", "V1"));
        sat.update_viewport(&viewer);
    }

    #[test]
    fn caching_satellite_invalidate() {
        let mut csv = CachingSatelliteGraphViewer::new(200.0, 150.0);
        assert!(!csv.needs_redraw());
        csv.invalidate();
        assert!(csv.needs_redraw());
        csv.mark_rendered();
        assert!(!csv.needs_redraw());
    }

    #[test]
    fn graph_viewer_utils_center() {
        let mut graph = VisualGraph::new();
        graph.add_vertex(VisualVertex::new("v1", "V1"));
        graph.add_vertex(VisualVertex::new("v2", "V2"));
        let center = GraphViewerUtils::graph_center(&graph);
        assert!(center.x.is_finite());
        assert!(center.y.is_finite());
    }

    #[test]
    fn graph_viewer_utils_fit_scale() {
        let mut graph = VisualGraph::new();
        let mut v1 = VisualVertex::new("v1", "V1");
        v1.position = Point2D::new(0.0, 0.0);
        graph.add_vertex(v1);
        let mut v2 = VisualVertex::new("v2", "V2");
        v2.position = Point2D::new(400.0, 300.0);
        graph.add_vertex(v2);
        let viewport = Rect2D::new(0.0, 0.0, 800.0, 600.0);
        let scale = GraphViewerUtils::compute_fit_scale(&graph, viewport);
        assert!(scale > 0.0);
        assert!(scale <= 2.0);
    }

    #[test]
    fn view_updater_relocate() {
        let mut updater = VisualGraphViewUpdater::new();
        updater.relocate_vertex("v1", Point2D::new(10.0, 20.0));
        assert!(updater.has_pending_updates());
        let mut graph = VisualGraph::new();
        graph.add_vertex(VisualVertex::new("v1", "V1"));
        let mut viewer = GraphViewer::new();
        updater.apply_updates(&mut graph, &mut viewer);
        let v = graph.vertex("v1").unwrap();
        assert!((v.position.x - 10.0).abs() < 1e-6);
        assert!(!updater.has_pending_updates());
    }

    #[test]
    fn graph_viewer_articulations() {
        let mut gv = GraphViewer::new();
        gv.set_articulations("e1", vec![Point2D::new(10.0, 20.0), Point2D::new(30.0, 40.0)]);
        assert_eq!(gv.get_articulations("e1").len(), 2);
        assert_eq!(gv.get_articulations("unknown").len(), 0);
    }

    #[test]
    fn graph_perspective_info_invalid() {
        let info = GraphPerspectiveInfo::invalid();
        assert!(info.is_invalid());
    }

    #[test]
    fn graph_perspective_info_from_viewer() {
        let mut gv = GraphViewer::new();
        gv.scale = 1.5;
        gv.viewport_origin = Point2D::new(100.0, 200.0);
        let info = GraphPerspectiveInfo::from_viewer(&gv);
        assert!(!info.is_invalid());
        assert!((info.zoom - 1.5).abs() < 1e-6);
        assert!((info.layout_translate.x - 100.0).abs() < 1e-6);
        assert!((info.layout_translate.y - 200.0).abs() < 1e-6);
    }

    #[test]
    fn graph_perspective_info_round_trip() {
        let info = GraphPerspectiveInfo::new(
            Point2D::new(50.0, 60.0),
            Point2D::new(10.0, 20.0),
            2.0,
        );
        let json = info.to_json();
        assert!(json.contains("50"));
        assert!(json.contains("60"));
        assert!(json.contains("2"));
    }

    #[test]
    fn graph_perspective_info_apply_to_viewer() {
        let info = GraphPerspectiveInfo::new(
            Point2D::new(150.0, 250.0),
            Point2D::new(0.0, 0.0),
            3.0,
        );
        let mut gv = GraphViewer::new();
        info.apply_to(&mut gv);
        assert!((gv.viewport_origin.x - 150.0).abs() < 1e-6);
        assert!((gv.viewport_origin.y - 250.0).abs() < 1e-6);
        assert!((gv.scale - 3.0).abs() < 1e-6);
    }

    #[test]
    fn graph_perspective_info_from_save_state() {
        let info = GraphPerspectiveInfo::from_save_state(
            Some(10.0),
            Some(20.0),
            Some(0.0),
            Some(0.0),
            Some(1.5),
        );
        assert!(!info.is_invalid());
        assert!((info.zoom - 1.5).abs() < 1e-6);

        let invalid = GraphPerspectiveInfo::from_save_state(None, None, None, None, None);
        assert!(invalid.is_invalid());
    }

    #[test]
    fn visual_graph_view_updater_zoom_to_fit() {
        let mut updater = VisualGraphViewUpdater::new();
        updater.request_zoom_to_fit();
        assert!(updater.has_pending_updates());
        let mut gv = GraphViewer::new();
        let mut graph = VisualGraph::new();
        graph.add_vertex(VisualVertex::new("v1", "V1"));
        updater.apply_updates(&mut graph, &mut gv);
        assert!(!updater.has_pending_updates());
    }

    #[test]
    fn visual_graph_view_updater_animation() {
        let mut updater = VisualGraphViewUpdater::new();
        assert!(!updater.is_animating());
        updater.start_animation(0.5);
        assert!(updater.is_animating());
        assert!(updater.animation_progress().unwrap() < 0.1);
        // Tick until done
        while updater.is_animating() {
            updater.tick_animation();
        }
        let callbacks = updater.drain_completion_callbacks();
        assert!(callbacks.is_empty());
    }

    #[test]
    fn visual_graph_view_updater_interpolate() {
        let updater = VisualGraphViewUpdater::new();
        let a = GraphPerspectiveInfo::new(Point2D::new(0.0, 0.0), Point2D::ZERO, 1.0);
        let b = GraphPerspectiveInfo::new(Point2D::new(100.0, 100.0), Point2D::ZERO, 2.0);
        let mid = updater.interpolate_perspective(&a, &b, 0.5);
        assert!((mid.layout_translate.x - 50.0).abs() < 1e-6);
        assert!((mid.layout_translate.y - 50.0).abs() < 1e-6);
        assert!((mid.zoom - 1.5).abs() < 1e-6);
    }

    #[test]
    fn satellite_listener_registry() {
        let mut reg = SatelliteListenerRegistry::new();
        assert!(reg.is_empty());
        reg.add_listener(Box::new(NullGraphSatelliteListener));
        assert_eq!(reg.len(), 1);
        reg.notify_viewport_changed(Rect2D::new(0.0, 0.0, 100.0, 100.0));
        reg.notify_shown();
        reg.notify_hidden();
        reg.notify_scale_changed(2.0);
    }
}
