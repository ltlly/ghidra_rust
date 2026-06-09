//! Function Graph View -- rendering, painting, and user interaction for the
//! function graph viewer.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.functiongraph.graph`
//! (view portions).
//!
//! The [`FunctionGraphView`] handles:
//!
//! - Vertex rendering (shapes, labels, colours, selection highlights).
//! - Edge rendering (straight lines, orthogonal polylines, colour by type).
//! - Zoom and pan (affine transform from graph coordinates to screen).
//! - Hit-testing (which vertex/edge is under the cursor).
//! - Satellite (overview) viewport.
//! - Path highlighting on hover.

use super::function_graph_model::FunctionGraphModel;
use super::mvc::{EdgeColorScheme, FGVertexType, FunctionGraphOptions};
use super::{CfgEdgeType, FGEdge, FGVertex, FunctionGraph, LayoutDirection};

use ghidra_core::addr::Address;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

// ---------------------------------------------------------------------------
// VertexDisplayInfo
// ---------------------------------------------------------------------------

/// Display information for a single vertex, computed by the view.
#[derive(Debug, Clone)]
pub struct VertexDisplayInfo {
    /// Index of the vertex in the graph.
    pub index: usize,
    /// The vertex label.
    pub label: String,
    /// Background colour (RGBA u32).
    pub background_color: u32,
    /// Border colour (RGBA u32).
    pub border_color: u32,
    /// Text colour (RGBA u32).
    pub text_color: u32,
    /// Whether this vertex is currently selected.
    pub selected: bool,
    /// Whether this vertex is currently hovered.
    pub hovered: bool,
    /// Whether this vertex is on the highlighted path.
    pub on_highlighted_path: bool,
    /// The vertex type.
    pub vertex_type: FGVertexType,
}

impl VertexDisplayInfo {
    /// Create display info for a vertex.
    pub fn new(index: usize, vertex: &FGVertex, vertex_type: FGVertexType) -> Self {
        Self {
            index,
            label: vertex.label.clone(),
            background_color: 0xFFFFFFFF,
            border_color: 0x000000FF,
            text_color: 0x000000FF,
            selected: false,
            hovered: false,
            on_highlighted_path: false,
            vertex_type,
        }
    }
}

// ---------------------------------------------------------------------------
// EdgeDisplayInfo
// ---------------------------------------------------------------------------

/// Display information for a single edge.
#[derive(Debug, Clone)]
pub struct EdgeDisplayInfo {
    /// Index of the edge in the graph.
    pub index: usize,
    /// The control-flow type of this edge.
    pub edge_type: CfgEdgeType,
    /// The colour for this edge (RGBA u32).
    pub color: u32,
    /// Alpha value (0-255).
    pub alpha: u8,
    /// The polyline control points (in graph coordinates).
    pub points: Vec<(f32, f32)>,
    /// Whether this edge is on the highlighted path.
    pub on_highlighted_path: bool,
    /// Line width (pixels).
    pub line_width: f32,
}

impl EdgeDisplayInfo {
    /// Create display info for an edge.
    pub fn new(index: usize, edge: &FGEdge, color: u32, alpha: u8) -> Self {
        Self {
            index,
            edge_type: edge.edge_type,
            color,
            alpha,
            points: edge.points.clone(),
            on_highlighted_path: false,
            line_width: 1.0,
        }
    }
}

// ---------------------------------------------------------------------------
// FunctionGraphView
// ---------------------------------------------------------------------------

/// The view component for rendering and interacting with the function graph.
///
/// Manages the display state (vertex/edge display info, zoom, pan,
/// highlighted path) and provides hit-testing for user interaction.
#[derive(Debug)]
pub struct FunctionGraphView {
    /// Per-vertex display information.
    vertex_display: Vec<VertexDisplayInfo>,
    /// Per-edge display information.
    edge_display: Vec<EdgeDisplayInfo>,
    /// The highlighted path (vertex indices), if any.
    highlighted_path: Vec<usize>,
    /// Current zoom factor.
    zoom: f32,
    /// Current pan offset (screen pixels).
    pan_offset: (f32, f32),
    /// Whether the satellite (overview) view is visible.
    satellite_visible: bool,
    /// The viewport rectangle in graph coordinates (x, y, width, height).
    viewport: (f32, f32, f32, f32),
    /// Whether to merge edges with the same source and target.
    merge_edges: bool,
    /// Whether the view needs a repaint.
    needs_repaint: bool,
}

impl FunctionGraphView {
    /// Create a new view for a graph with the given number of vertices.
    pub fn new(vertex_count: usize) -> Self {
        Self {
            vertex_display: Vec::with_capacity(vertex_count),
            edge_display: Vec::new(),
            highlighted_path: Vec::new(),
            zoom: 1.0,
            pan_offset: (0.0, 0.0),
            satellite_visible: true,
            viewport: (0.0, 0.0, 800.0, 600.0),
            merge_edges: false,
            needs_repaint: true,
        }
    }

    /// Create a fully initialized view from the model.
    pub fn from_model(model: &FunctionGraphModel, options: &FunctionGraphOptions) -> Self {
        let mut view = Self::new(model.vertex_count());
        view.initialize_from_model(model, options);
        view
    }

    // -----------------------------------------------------------------------
    // Initialization
    // -----------------------------------------------------------------------

    /// Initialize (or re-initialize) the display info from the model and
    /// options.
    pub fn initialize_from_model(
        &mut self,
        model: &FunctionGraphModel,
        options: &FunctionGraphOptions,
    ) {
        let graph = model.graph();
        let edge_colors = &options.edge_colors;

        // Build vertex display info.
        self.vertex_display = graph
            .vertices
            .iter()
            .enumerate()
            .map(|(i, v)| {
                let vt = model.vertex_type(i);
                let mut info = VertexDisplayInfo::new(i, v, vt);
                info.background_color = match vt {
                    FGVertexType::Entry => 0xD4EDDAFF,
                    FGVertexType::Exit => 0xF8D7DAFF,
                    FGVertexType::Singleton => 0xFFF3CDFF,
                    FGVertexType::Group => options.default_group_background_color,
                    FGVertexType::Body => options.default_vertex_background_color,
                };
                info
            })
            .collect();

        // Build edge display info.
        self.edge_display = graph
            .edges
            .iter()
            .enumerate()
            .map(|(i, e)| {
                let color = edge_colors.color_for_edge(e.edge_type);
                let alpha = edge_colors.default_alpha;
                EdgeDisplayInfo::new(i, e, color, alpha)
            })
            .collect();

        self.satellite_visible = options.show_satellite;
        self.needs_repaint = true;
    }

    // -----------------------------------------------------------------------
    // Display info access
    // -----------------------------------------------------------------------

    /// Per-vertex display information.
    pub fn vertex_display(&self) -> &[VertexDisplayInfo] {
        &self.vertex_display
    }

    /// Per-edge display information.
    pub fn edge_display(&self) -> &[EdgeDisplayInfo] {
        &self.edge_display
    }

    /// Mutable per-vertex display information.
    pub fn vertex_display_mut(&mut self) -> &mut Vec<VertexDisplayInfo> {
        &mut self.vertex_display
    }

    /// Mutable per-edge display information.
    pub fn edge_display_mut(&mut self) -> &mut Vec<EdgeDisplayInfo> {
        &mut self.edge_display
    }

    // -----------------------------------------------------------------------
    // Selection / Hover visual state
    // -----------------------------------------------------------------------

    /// Update the visual selection state from the model.
    pub fn update_selection_state(&mut self, model: &FunctionGraphModel) {
        let selected = model.selected_vertices();
        let hovered = model.hovered_vertex();

        for info in &mut self.vertex_display {
            info.selected = selected.contains(&info.index);
            info.hovered = hovered == Some(info.index);
        }
        self.needs_repaint = true;
    }

    /// Update the highlighted path from the model.
    pub fn update_highlighted_path(&mut self, model: &FunctionGraphModel) {
        self.highlighted_path = model.highlight_path();
        let path_set: HashSet<usize> = self.highlighted_path.iter().copied().collect();

        for info in &mut self.vertex_display {
            info.on_highlighted_path = path_set.contains(&info.index);
        }
        // Mark edges on the highlighted path.
        let graph = model.graph();
        for (i, edge_info) in self.edge_display.iter_mut().enumerate() {
            if let Some(edge) = graph.edges.get(i) {
                edge_info.on_highlighted_path =
                    path_set.contains(&edge.from) && path_set.contains(&edge.to);
            }
        }
        self.needs_repaint = true;
    }

    // -----------------------------------------------------------------------
    // Layout / Model updates
    // -----------------------------------------------------------------------

    /// Called after a layout change to refresh display info.
    pub fn update_after_layout(&mut self, model: &FunctionGraphModel) {
        // Rebuild edge display info (control points changed).
        let graph = model.graph();
        self.edge_display = graph
            .edges
            .iter()
            .enumerate()
            .map(|(i, e)| {
                let color = self
                    .edge_display
                    .get(i)
                    .map(|d| d.color)
                    .unwrap_or(0x808080FF);
                let alpha = self
                    .edge_display
                    .get(i)
                    .map(|d| d.alpha)
                    .unwrap_or(128);
                EdgeDisplayInfo::new(i, e, color, alpha)
            })
            .collect();

        // Ensure vertex display count matches.
        self.sync_vertex_display_count(model);
        self.needs_repaint = true;
    }

    /// Called after a group/ungroup operation to refresh display info.
    pub fn update_after_group(&mut self, model: &FunctionGraphModel) {
        self.update_after_layout(model);
        self.update_selection_state(model);
    }

    /// Synchronize the vertex display info count with the model.
    fn sync_vertex_display_count(&mut self, model: &FunctionGraphModel) {
        let graph = model.graph();
        while self.vertex_display.len() < graph.vertices.len() {
            let i = self.vertex_display.len();
            let v = &graph.vertices[i];
            let vt = model.vertex_type(i);
            self.vertex_display
                .push(VertexDisplayInfo::new(i, v, vt));
        }
        // Truncate if model shrunk (shouldn't happen normally).
        self.vertex_display.truncate(graph.vertices.len());
    }

    // -----------------------------------------------------------------------
    // Zoom and pan
    // -----------------------------------------------------------------------

    /// The current zoom factor.
    pub fn zoom(&self) -> f32 {
        self.zoom
    }

    /// Set the zoom factor.
    pub fn set_zoom(&mut self, zoom: f32) {
        self.zoom = zoom.clamp(0.05, 10.0);
        self.needs_repaint = true;
    }

    /// The current pan offset (screen pixels).
    pub fn pan_offset(&self) -> (f32, f32) {
        self.pan_offset
    }

    /// Set the pan offset.
    pub fn set_pan_offset(&mut self, x: f32, y: f32) {
        self.pan_offset = (x, y);
        self.needs_repaint = true;
    }

    /// Pan by the given delta.
    pub fn pan_by(&mut self, dx: f32, dy: f32) {
        self.pan_offset.0 += dx;
        self.pan_offset.1 += dy;
        self.needs_repaint = true;
    }

    /// Center the viewport on the given vertex.
    pub fn center_on_vertex(&mut self, model: &FunctionGraphModel, index: usize) {
        if let Some(v) = model.vertices().get(index) {
            let (cx, cy) = v.centre();
            let view_w = self.viewport.2;
            let view_h = self.viewport.3;
            self.pan_offset = (
                view_w / 2.0 - cx * self.zoom,
                view_h / 2.0 - cy * self.zoom,
            );
            self.needs_repaint = true;
        }
    }

    // -----------------------------------------------------------------------
    // Viewport
    // -----------------------------------------------------------------------

    /// The viewport rectangle (x, y, width, height) in screen pixels.
    pub fn viewport(&self) -> (f32, f32, f32, f32) {
        self.viewport
    }

    /// Set the viewport dimensions.
    pub fn set_viewport(&mut self, x: f32, y: f32, width: f32, height: f32) {
        self.viewport = (x, y, width, height);
        self.needs_repaint = true;
    }

    /// Whether the satellite view is visible.
    pub fn is_satellite_visible(&self) -> bool {
        self.satellite_visible
    }

    /// Toggle the satellite view.
    pub fn set_satellite_visible(&mut self, visible: bool) {
        self.satellite_visible = visible;
    }

    // -----------------------------------------------------------------------
    // Hit testing
    // -----------------------------------------------------------------------

    /// Find the vertex at the given screen coordinates.
    ///
    /// Returns the vertex index, if any, accounting for zoom and pan.
    pub fn vertex_at_screen(&self, model: &FunctionGraphModel, sx: f32, sy: f32) -> Option<usize> {
        // Convert screen coordinates to graph coordinates.
        let gx = (sx - self.pan_offset.0) / self.zoom;
        let gy = (sy - self.pan_offset.1) / self.zoom;

        for (i, v) in model.vertices().iter().enumerate() {
            if gx >= v.x
                && gx <= v.x + v.width
                && gy >= v.y
                && gy <= v.y + v.height
            {
                return Some(i);
            }
        }
        None
    }

    // -----------------------------------------------------------------------
    // Repaint flag
    // -----------------------------------------------------------------------

    /// Whether the view needs to be repainted.
    pub fn needs_repaint(&self) -> bool {
        self.needs_repaint
    }

    /// Mark the view as needing a repaint.
    pub fn mark_needs_repaint(&mut self) {
        self.needs_repaint = true;
    }

    /// Clear the repaint flag (called after painting).
    pub fn clear_repaint(&mut self) {
        self.needs_repaint = false;
    }

    // -----------------------------------------------------------------------
    // Coordinate transforms
    // -----------------------------------------------------------------------

    /// Convert graph coordinates to screen coordinates.
    pub fn graph_to_screen(&self, gx: f32, gy: f32) -> (f32, f32) {
        (
            gx * self.zoom + self.pan_offset.0,
            gy * self.zoom + self.pan_offset.1,
        )
    }

    /// Convert screen coordinates to graph coordinates.
    pub fn screen_to_graph(&self, sx: f32, sy: f32) -> (f32, f32) {
        (
            (sx - self.pan_offset.0) / self.zoom,
            (sy - self.pan_offset.1) / self.zoom,
        )
    }

    /// Compute the scroll-to-fit bounds so that the entire graph is visible.
    pub fn compute_fit_bounds(&mut self, model: &FunctionGraphModel) {
        let (bx, by, bw, bh) = model.bounds();
        if bw <= 0.0 || bh <= 0.0 {
            return;
        }
        let vw = self.viewport.2;
        let vh = self.viewport.3;
        let scale_x = vw / (bw + 40.0);
        let scale_y = vh / (bh + 40.0);
        self.zoom = scale_x.min(scale_y).clamp(0.05, 2.0);
        self.pan_offset = (
            (vw - bw * self.zoom) / 2.0 - bx * self.zoom,
            (vh - bh * self.zoom) / 2.0 - by * self.zoom,
        );
        self.needs_repaint = true;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ghidra_core::addr::{Address, AddressRange};
    use ghidra_core::program::listing::Function;
    use super::super::{FGEdge, FGVertex, FunctionGraph as FG};
    use super::super::mvc::FGData;

    fn dummy_function() -> Function {
        Function::new(
            "test_fn",
            Address::new(0x1000),
            AddressRange::new(Address::new(0x1000), Address::new(0x1100)),
        )
    }

    fn make_model() -> FunctionGraphModel {
        let graph = FG::from_parts(
            dummy_function(),
            vec![
                FGVertex::new(Address::new(0x1000), "A".into(), vec![]),
                FGVertex::new(Address::new(0x1010), "B".into(), vec![]),
            ],
            vec![FGEdge::new(0, 1, CfgEdgeType::Fallthrough)],
        );
        FunctionGraphModel::from_fg_data(FGData::new(dummy_function(), graph))
    }

    #[test]
    fn view_creation() {
        let view = FunctionGraphView::new(0);
        assert_eq!(view.zoom(), 1.0);
        assert!(view.needs_repaint());
        assert!(view.is_satellite_visible());
    }

    #[test]
    fn view_from_model() {
        let model = make_model();
        let opts = FunctionGraphOptions::default();
        let view = FunctionGraphView::from_model(&model, &opts);
        assert_eq!(view.vertex_display().len(), 2);
        assert_eq!(view.edge_display().len(), 1);
    }

    #[test]
    fn vertex_display_colors() {
        let model = make_model();
        let opts = FunctionGraphOptions::default();
        let view = FunctionGraphView::from_model(&model, &opts);
        // Entry vertex (index 0) should have the entry color.
        assert_eq!(view.vertex_display()[0].background_color, 0xD4EDDAFF);
        // Exit vertex (index 1) should have the exit color.
        assert_eq!(view.vertex_display()[1].background_color, 0xF8D7DAFF);
    }

    #[test]
    fn zoom_clamp() {
        let mut view = FunctionGraphView::new(0);
        view.set_zoom(0.001);
        assert!(view.zoom() >= 0.05);
        view.set_zoom(100.0);
        assert!(view.zoom() <= 10.0);
    }

    #[test]
    fn pan_by() {
        let mut view = FunctionGraphView::new(0);
        view.pan_by(10.0, 20.0);
        assert_eq!(view.pan_offset(), (10.0, 20.0));
        view.pan_by(-5.0, -10.0);
        assert_eq!(view.pan_offset(), (5.0, 10.0));
    }

    #[test]
    fn coordinate_transform_round_trip() {
        let mut view = FunctionGraphView::new(0);
        view.set_zoom(2.0);
        view.set_pan_offset(100.0, 50.0);
        let (sx, sy) = view.graph_to_screen(10.0, 20.0);
        let (gx, gy) = view.screen_to_graph(sx, sy);
        assert!((gx - 10.0).abs() < 0.01);
        assert!((gy - 20.0).abs() < 0.01);
    }

    #[test]
    fn hit_test_vertex() {
        let model = make_model();
        let opts = FunctionGraphOptions::default();
        let mut view = FunctionGraphView::from_model(&model, &opts);
        view.set_zoom(1.0);
        view.set_pan_offset(0.0, 0.0);
        // Vertex A is at (0, 0) with default width 120, height 40.
        assert!(view.vertex_at_screen(&model, 50.0, 20.0).is_some());
        assert!(view.vertex_at_screen(&model, 500.0, 500.0).is_none());
    }

    #[test]
    fn update_selection_state() {
        let mut model = make_model();
        model.select_vertex(0);
        let opts = FunctionGraphOptions::default();
        let mut view = FunctionGraphView::from_model(&model, &opts);
        view.update_selection_state(&model);
        assert!(view.vertex_display()[0].selected);
        assert!(!view.vertex_display()[1].selected);
    }

    #[test]
    fn clear_repaint() {
        let mut view = FunctionGraphView::new(0);
        assert!(view.needs_repaint());
        view.clear_repaint();
        assert!(!view.needs_repaint());
        view.mark_needs_repaint();
        assert!(view.needs_repaint());
    }

    #[test]
    fn satellite_toggle() {
        let mut view = FunctionGraphView::new(0);
        assert!(view.is_satellite_visible());
        view.set_satellite_visible(false);
        assert!(!view.is_satellite_visible());
    }

    #[test]
    fn fit_bounds() {
        let model = make_model();
        let mut view = FunctionGraphView::new(2);
        view.set_viewport(0.0, 0.0, 800.0, 600.0);
        view.compute_fit_bounds(&model);
        assert!(view.zoom() > 0.0);
    }
}
