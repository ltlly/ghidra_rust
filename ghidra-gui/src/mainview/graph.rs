//! Function graph viewer -- interactive control-flow graph visualisation.
//!
//! Renders a [`FunctionGraph`] as an interactive node-edge diagram using egui
//! immediate-mode painting.  Features:
//!
//! * Camera with smooth pan/zoom/focus/fit-all animations.
//! * Rectangular basic-block nodes showing block label, disassembly, and
//!   addresses.
//! * Colour-coded edges: green fallthrough, blue branch, red false-branch,
//!   cyan true-branch, purple call, grey indirect.
//! * Hierarchical (Sugiyama-style) layout algorithm.
//! * Click nodes to focus in listing; double-click to expand/collapse.
//! * Drag to pan canvas or reposition nodes.
//! * Scroll-wheel zoom.
//! * Minimap / satellite view in the bottom-right corner.
//! * Node highlighting for entry point, cursor position, called functions,
//!   and externals.
//!
//! ## Public API
//!
//! | Item | Purpose |
//! |------|---------|
//! | [`FgCamera`] | Pan/zoom camera with animated transitions |
//! | [`FgTheme`] | Visual colour palette for nodes and edges |
//! | [`GraphViewerState`] | Persistent interactive state |
//! | [`GraphViewerAction`] | Actions emitted to the application |
//! | [`FunctionGraphWindow`] | Self-contained egui window widget |
//! | [`render_graph_view`] | Low-level inline render function |
//! | [`render_edge`] / [`render_edge_polyline`] | Draw a single edge |
//! | [`hit_test_nodes`] | Screen-space hit-test for node picking |
//! | [`layout_hierarchical`] | Sugiyama layered-layout algorithm |
//! | [`graph_bounds`] | Compute world-space bounding box |
//! | [`demo_function_graph`] | Build a test graph |

use egui::emath::{Pos2, Rect, Vec2};
use egui::epaint::{RectShape, Rounding, Shape, Stroke};
use egui::{Color32, FontId, Painter, Sense, Ui};
use ghidra_core::addr::Address;
use ghidra_decompile::pcode::opcodes::OpCode;
use ghidra_decompile::pcode::PcodeOperation;
use ghidra_features::functiongraph::{
    CfgEdgeType, FGEdge, FGVertex, FunctionGraph, GraphLayout, LayoutAlgorithm, LayoutDirection,
};
use std::collections::HashSet;

// ============================================================================
// Camera
// ============================================================================

/// Interactive camera that pans and zooms over the graph plane.
///
/// **World space** is the untransformed coordinate system of the graph layout.
/// **Screen space** is pixel space of the egui UI region.  The camera provides
/// the translation between the two.
#[derive(Debug, Clone)]
pub struct FgCamera {
    /// Screen-space pixel offset -- the world-space origin maps here.
    pub offset: Vec2,
    /// Current zoom factor (>0).  1.0 means 1:1.
    pub zoom: f32,
    /// Target zoom (for smooth animation).
    pub target_zoom: f32,
    /// Target offset (for smooth animation).
    pub target_offset: Vec2,
    /// Animation lerp factor per frame (0..1).  Higher = faster.
    pub lerp_speed: f32,
    /// Minimum zoom.
    pub zoom_min: f32,
    /// Maximum zoom.
    pub zoom_max: f32,
    /// Whether camera is currently animating.
    pub animating: bool,
}

impl FgCamera {
    /// Create a new camera with sensible defaults.
    pub fn new() -> Self {
        Self {
            offset: Vec2::new(50.0, 50.0),
            zoom: 1.0,
            target_zoom: 1.0,
            target_offset: Vec2::new(50.0, 50.0),
            lerp_speed: 0.15,
            zoom_min: 0.1,
            zoom_max: 5.0,
            animating: false,
        }
    }

    /// Convert a world-space point to screen-space.
    #[inline]
    pub fn world_to_screen(&self, world: Vec2) -> Pos2 {
        Pos2::new(
            world.x * self.zoom + self.offset.x,
            world.y * self.zoom + self.offset.y,
        )
    }

    /// Convert a screen-space position to world-space.
    #[inline]
    pub fn screen_to_world(&self, screen: Pos2) -> Vec2 {
        Vec2::new(
            (screen.x - self.offset.x) / self.zoom,
            (screen.y - self.offset.y) / self.zoom,
        )
    }

    /// Convert a world-space dimension to screen-space.
    #[inline]
    pub fn world_to_screen_size(&self, world: f32) -> f32 {
        world * self.zoom
    }

    /// Adjust the offset so that `world_pos` appears at `screen_pos`.
    pub fn focus_at_screen(&mut self, world_pos: Vec2, screen_pos: Pos2) {
        self.target_offset = Vec2::new(
            screen_pos.x - world_pos.x * self.target_zoom,
            screen_pos.y - world_pos.y * self.target_zoom,
        );
        self.animating = true;
    }

    /// Pan the camera by a screen-space delta.
    pub fn pan(&mut self, delta: Vec2) {
        self.target_offset += delta;
        self.animating = true;
    }

    /// Zoom by a multiplicative factor about a screen-space anchor point.
    pub fn zoom_at(&mut self, factor: f32, anchor: Pos2) {
        self.target_zoom = (self.target_zoom * factor).clamp(self.zoom_min, self.zoom_max);
        // Adjust offset so the world point under `anchor` stays fixed.
        let world = self.screen_to_world(anchor);
        self.target_offset = Vec2::new(
            anchor.x - world.x * self.target_zoom,
            anchor.y - world.y * self.target_zoom,
        );
        self.animating = true;
    }

    /// Focus on a world-space position, centring it in the given viewport.
    pub fn focus_node(&mut self, world_pos: Vec2, viewport: Rect) {
        let centre = viewport.center();
        self.target_offset = Vec2::new(
            centre.x - world_pos.x * self.target_zoom,
            centre.y - world_pos.y * self.target_zoom,
        );
        self.animating = true;
    }

    /// Zoom and pan so that all vertices are visible.
    pub fn fit_all(&mut self, bounds: Rect, viewport: Rect) {
        if !bounds.is_finite() || bounds.area() <= 0.0 {
            return;
        }

        let padding = 60.0;
        let avail_w = (viewport.width() - 2.0 * padding).max(10.0);
        let avail_h = (viewport.height() - 2.0 * padding).max(10.0);

        let zoom_w = avail_w / bounds.width();
        let zoom_h = avail_h / bounds.height();
        self.target_zoom = zoom_w.min(zoom_h).clamp(self.zoom_min, self.zoom_max);

        let bw = bounds.width() * self.target_zoom;
        let bh = bounds.height() * self.target_zoom;
        let cx = viewport.left() + (viewport.width() - bw) / 2.0;
        let cy = viewport.top() + (viewport.height() - bh) / 2.0;

        self.target_offset = Vec2::new(
            cx - bounds.left() * self.target_zoom,
            cy - bounds.top() * self.target_zoom,
        );
        self.animating = true;
    }

    /// Tick the animation: lerp current values towards targets.
    /// Returns true if the camera moved this frame.
    pub fn tick(&mut self) -> bool {
        let eps = 0.1;

        let dz = (self.target_zoom - self.zoom).abs();
        let dx = (self.target_offset.x - self.offset.x).abs();
        let dy = (self.target_offset.y - self.offset.y).abs();

        if dz < eps && dx < eps && dy < eps {
            self.zoom = self.target_zoom;
            self.offset = self.target_offset;
            self.animating = false;
            return false;
        }

        let t = self.lerp_speed;
        self.zoom += (self.target_zoom - self.zoom) * t;
        self.offset.x += (self.target_offset.x - self.offset.x) * t;
        self.offset.y += (self.target_offset.y - self.offset.y) * t;
        true
    }

    /// Snap to targets immediately (skip animation).
    pub fn snap(&mut self) {
        self.zoom = self.target_zoom;
        self.offset = self.target_offset;
        self.animating = false;
    }

    /// Compute the world-space visible rectangle for a given viewport.
    pub fn visible_world_rect(&self, viewport: Rect) -> Rect {
        let top_left = self.screen_to_world(viewport.left_top());
        let bottom_right = self.screen_to_world(viewport.right_bottom());
        Rect::from_min_max(top_left.to_pos2(), bottom_right.to_pos2())
    }
}

impl Default for FgCamera {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Theme
// ============================================================================

/// Visual theme for the graph view.
#[derive(Debug, Clone)]
pub struct FgTheme {
    /// Background colour of the canvas.
    pub bg_color: Color32,
    /// Colour of grid dots.
    pub grid_color: Color32,
    /// Default fill for basic-block nodes.
    pub block_fill: Color32,
    /// Default stroke for basic-block nodes.
    pub block_stroke: Color32,
    /// Fill for the entry-point node.
    pub entry_fill: Color32,
    /// Stroke for the entry-point node.
    pub entry_stroke: Color32,
    /// Fill for the cursor-selected / highlighted node.
    pub highlight_fill: Color32,
    /// Stroke for the cursor-selected / highlighted node.
    pub highlight_stroke: Color32,
    /// Fill for a called-function node.
    pub called_fill: Color32,
    /// Fill for an external / imported function node.
    pub external_fill: Color32,
    /// Text colour for node labels.
    pub text_color: Color32,
    /// Text colour for secondary text (addresses, disassembly).
    pub text_secondary: Color32,
    /// Font size for the main block label.
    pub label_font_size: f32,
    /// Font size for address text.
    pub addr_font_size: f32,
    /// Font size for instruction text.
    pub instr_font_size: f32,
    /// Rounding radius for node corners.
    pub rounding: f32,
    /// Width of the edge stroke.
    pub edge_width: f32,
    /// Minimap background.
    pub minimap_bg: Color32,
    /// Minimap viewport rect colour.
    pub minimap_viewport: Color32,
    /// Minimap node dot colour.
    pub minimap_node: Color32,
    /// Fill for expandable collapsed nodes.
    pub collapsed_fill: Color32,
    /// Stroke colour when node is hovered.
    pub hover_stroke: Color32,
    /// Width of node stroke when hovered.
    pub hover_stroke_width: f32,
}

impl FgTheme {
    /// Dark theme.
    pub fn dark() -> Self {
        Self {
            bg_color: Color32::from_rgb(25, 27, 32),
            grid_color: Color32::from_rgba_premultiplied(255, 255, 255, 15),
            block_fill: Color32::from_rgb(45, 48, 55),
            block_stroke: Color32::from_rgb(90, 95, 105),
            entry_fill: Color32::from_rgb(30, 60, 30),
            entry_stroke: Color32::from_rgb(80, 200, 80),
            highlight_fill: Color32::from_rgb(50, 50, 70),
            highlight_stroke: Color32::from_rgb(120, 140, 255),
            called_fill: Color32::from_rgb(50, 35, 60),
            external_fill: Color32::from_rgb(55, 50, 30),
            text_color: Color32::from_rgb(220, 225, 235),
            text_secondary: Color32::from_rgb(150, 155, 165),
            label_font_size: 12.0,
            addr_font_size: 9.0,
            instr_font_size: 10.0,
            rounding: 6.0,
            edge_width: 1.8,
            minimap_bg: Color32::from_rgba_premultiplied(20, 20, 25, 200),
            minimap_viewport: Color32::from_rgba_premultiplied(200, 200, 220, 80),
            minimap_node: Color32::from_rgba_premultiplied(180, 180, 200, 180),
            collapsed_fill: Color32::from_rgb(55, 55, 60),
            hover_stroke: Color32::from_rgb(200, 210, 255),
            hover_stroke_width: 2.5,
        }
    }

    /// Light theme.
    pub fn light() -> Self {
        Self {
            bg_color: Color32::from_rgb(245, 246, 250),
            grid_color: Color32::from_rgba_premultiplied(0, 0, 0, 20),
            block_fill: Color32::from_rgb(255, 255, 255),
            block_stroke: Color32::from_rgb(160, 165, 175),
            entry_fill: Color32::from_rgb(220, 255, 220),
            entry_stroke: Color32::from_rgb(40, 160, 40),
            highlight_fill: Color32::from_rgb(225, 230, 255),
            highlight_stroke: Color32::from_rgb(60, 80, 200),
            called_fill: Color32::from_rgb(245, 230, 255),
            external_fill: Color32::from_rgb(255, 245, 220),
            text_color: Color32::from_rgb(30, 30, 40),
            text_secondary: Color32::from_rgb(120, 120, 135),
            label_font_size: 12.0,
            addr_font_size: 9.0,
            instr_font_size: 10.0,
            rounding: 6.0,
            edge_width: 1.8,
            minimap_bg: Color32::from_rgba_premultiplied(230, 230, 235, 220),
            minimap_viewport: Color32::from_rgba_premultiplied(100, 100, 120, 100),
            minimap_node: Color32::from_rgba_premultiplied(80, 80, 100, 180),
            collapsed_fill: Color32::from_rgb(240, 240, 240),
            hover_stroke: Color32::from_rgb(60, 100, 220),
            hover_stroke_width: 2.5,
        }
    }
}

impl Default for FgTheme {
    fn default() -> Self {
        Self::dark()
    }
}

// ============================================================================
// Layout
// ============================================================================

/// Compute Sugiyama-style hierarchical positions for all vertices in `graph`.
///
/// This is a pure layout function that returns world-space positions.  It
/// does **not** mutate the graph -- callers who want to persist positions
/// should write the result back into the graph vertices themselves.
///
/// The algorithm:
/// 1. Compute layers via longest-path from sources.
/// 2. Order vertices within each layer using the barycentre heuristic to
///    minimise edge crossings.
/// 3. Map (layer, order) to Euclidean (x, y) coordinates with configurable
///    spacing.
pub fn layout_hierarchical(graph: &FunctionGraph) -> Vec<Vec2> {
    let n = graph.vertices.len();
    if n == 0 {
        return Vec::new();
    }

    let layer_spacing = graph.layout.layer_spacing;
    let node_spacing = graph.layout.node_spacing;

    // Adjacency lists.
    let mut adj: Vec<Vec<usize>> = vec![Vec::new(); n];
    let mut rev_adj: Vec<Vec<usize>> = vec![Vec::new(); n];
    for edge in &graph.edges {
        if edge.from < n && edge.to < n {
            adj[edge.from].push(edge.to);
            rev_adj[edge.to].push(edge.from);
        }
    }

    // ---- Layer assignment ----
    let mut in_degree: Vec<usize> = rev_adj.iter().map(|v| v.len()).collect();
    let mut layer: Vec<usize> = vec![0; n];
    let mut queue: std::collections::VecDeque<usize> = std::collections::VecDeque::new();

    for (i, &deg) in in_degree.iter().enumerate() {
        if deg == 0 {
            queue.push_back(i);
        }
    }
    // Cyclic graph fallback: seed with 0.
    if queue.is_empty() && n > 0 {
        queue.push_back(0);
    }

    while let Some(u) = queue.pop_front() {
        for &v in &adj[u] {
            layer[v] = layer[v].max(layer[u] + 1);
            if in_degree[v] > 0 {
                in_degree[v] -= 1;
                if in_degree[v] == 0 {
                    queue.push_back(v);
                }
            }
        }
    }

    // Handle any nodes missed by the layering pass (cycles).
    for i in 0..n {
        if in_degree[i] > 0 {
            let max_pred_layer = rev_adj[i].iter().map(|&p| layer[p]).max().unwrap_or(0);
            layer[i] = max_pred_layer + 1;
        }
    }

    let max_layer = layer.iter().copied().max().unwrap_or(0);
    let mut layers: Vec<Vec<usize>> = vec![Vec::new(); max_layer + 1];
    for (i, &l) in layer.iter().enumerate() {
        if l < layers.len() {
            layers[l].push(i);
        }
    }

    // ---- Barycentre heuristic for crossing minimisation ----
    for l in 1..=max_layer {
        layers[l].sort_by(|&a, &b| {
            let avg_pos = |v: usize| -> f32 {
                let preds: Vec<usize> = rev_adj[v]
                    .iter()
                    .filter(|&&p| p < n && layer[p] == l - 1)
                    .copied()
                    .collect();
                if preds.is_empty() {
                    return layers[l - 1].len() as f32 / 2.0;
                }
                preds
                    .iter()
                    .map(|p| layers[l - 1].iter().position(|&x| x == *p).unwrap_or(0) as f32)
                    .sum::<f32>()
                    / preds.len() as f32
            };
            avg_pos(a)
                .partial_cmp(&avg_pos(b))
                .unwrap_or(std::cmp::Ordering::Equal)
        });
    }

    // ---- Map to positions ----
    let mut positions: Vec<Vec2> = vec![Vec2::ZERO; n];

    for (l_idx, layer_nodes) in layers.iter().enumerate() {
        for (o_idx, &node_idx) in layer_nodes.iter().enumerate() {
            positions[node_idx] = match graph.layout.direction {
                LayoutDirection::TopToBottom => {
                    Vec2::new(o_idx as f32 * node_spacing, l_idx as f32 * layer_spacing)
                }
                LayoutDirection::BottomToTop => Vec2::new(
                    o_idx as f32 * node_spacing,
                    (max_layer - l_idx) as f32 * layer_spacing,
                ),
                LayoutDirection::LeftToRight => {
                    Vec2::new(l_idx as f32 * layer_spacing, o_idx as f32 * node_spacing)
                }
                LayoutDirection::RightToLeft => Vec2::new(
                    (max_layer - l_idx) as f32 * layer_spacing,
                    o_idx as f32 * node_spacing,
                ),
            };
        }
    }

    positions
}

/// Compute the world-space bounding box of all vertices given their positions.
pub fn graph_bounds(graph: &FunctionGraph, positions: &[Vec2]) -> Rect {
    if positions.is_empty() {
        return Rect::from_min_max(Pos2::new(0.0, 0.0), Pos2::new(100.0, 100.0));
    }
    let mut min_x = f32::INFINITY;
    let mut min_y = f32::INFINITY;
    let mut max_x = f32::NEG_INFINITY;
    let mut max_y = f32::NEG_INFINITY;
    for (i, pos) in positions.iter().enumerate() {
        let v = &graph.vertices[i];
        min_x = min_x.min(pos.x);
        min_y = min_y.min(pos.y);
        max_x = max_x.max(pos.x + v.width);
        max_y = max_y.max(pos.y + v.height);
    }
    Rect::from_min_max(Pos2::new(min_x, min_y), Pos2::new(max_x, max_y))
}

// ============================================================================
// Edge rendering
// ============================================================================

/// Map a [`CfgEdgeType`] to a stroke colour.
pub fn edge_color(edge_type: CfgEdgeType) -> Color32 {
    match edge_type {
        CfgEdgeType::Fallthrough => Color32::from_rgb(46, 160, 60), // green
        CfgEdgeType::Branch => Color32::from_rgb(30, 110, 210),     // blue
        CfgEdgeType::TrueBranch => Color32::from_rgb(40, 190, 210), // cyan
        CfgEdgeType::FalseBranch => Color32::from_rgb(210, 50, 50), // red
        CfgEdgeType::Call => Color32::from_rgb(160, 60, 200),       // purple
        CfgEdgeType::IndirectBranch => Color32::from_rgb(150, 150, 150), // gray
        CfgEdgeType::Return => Color32::from_rgb(180, 130, 70),     // brown
    }
}

/// Draw a single edge from `from` to `to` screen-space positions.
pub fn render_edge(painter: &Painter, from: Pos2, to: Pos2, edge_type: CfgEdgeType, width: f32) {
    let color = edge_color(edge_type);
    let stroke = Stroke::new(width, color);
    painter.line_segment([from, to], stroke);
    draw_arrowhead(painter, from, to, color, width);
}

/// Draw an edge as a polyline from source centre to target centre, with
/// orthogonal routing and an arrowhead.
pub fn render_edge_polyline(
    painter: &Painter,
    from_centre: Pos2,
    to_centre: Pos2,
    edge_type: CfgEdgeType,
    width: f32,
) {
    let dx = (to_centre.x - from_centre.x).abs();
    let dy = (to_centre.y - from_centre.y).abs();

    let color = edge_color(edge_type);
    let stroke = Stroke::new(width, color);

    if dx < 2.0 || dy < 2.0 {
        // Almost aligned -- straight line.
        painter.line_segment([from_centre, to_centre], stroke);
    } else {
        // Orthogonal: pick the midpoint on the longer axis.
        if dx > dy {
            let mid_x = (from_centre.x + to_centre.x) / 2.0;
            let mid1 = Pos2::new(mid_x, from_centre.y);
            let mid2 = Pos2::new(mid_x, to_centre.y);
            painter.line_segment([from_centre, mid1], stroke);
            painter.line_segment([mid1, mid2], stroke);
            painter.line_segment([mid2, to_centre], stroke);
        } else {
            let mid_y = (from_centre.y + to_centre.y) / 2.0;
            let mid1 = Pos2::new(from_centre.x, mid_y);
            let mid2 = Pos2::new(to_centre.x, mid_y);
            painter.line_segment([from_centre, mid1], stroke);
            painter.line_segment([mid1, mid2], stroke);
            painter.line_segment([mid2, to_centre], stroke);
        }
    }

    draw_arrowhead(painter, from_centre, to_centre, color, width);
}

/// Draw a triangular arrowhead at `to`, oriented from `from`.
fn draw_arrowhead(painter: &Painter, from: Pos2, to: Pos2, color: Color32, width: f32) {
    let dir = Vec2::new(to.x - from.x, to.y - from.y);
    let len = dir.length();
    if len < 2.0 {
        return;
    }
    let dir = dir / len;
    let perp = Vec2::new(-dir.y, dir.x);

    let size = 8.0 + width * 2.0;
    let tip = to;
    let back = Pos2::new(tip.x - dir.x * size, tip.y - dir.y * size);
    let left = Pos2::new(back.x + perp.x * size * 0.5, back.y + perp.y * size * 0.5);
    let right = Pos2::new(back.x - perp.x * size * 0.5, back.y - perp.y * size * 0.5);

    painter.add(Shape::convex_polygon(
        vec![tip, left, right],
        color,
        Stroke::new(width * 0.6, color),
    ));
}

// ============================================================================
// Node rendering
// ============================================================================

/// Return the node dimensions for a vertex.
pub fn node_size(vertex: &FGVertex, is_collapsed: bool) -> Vec2 {
    let w = 200.0;
    let h = if is_collapsed {
        40.0
    } else {
        let base = 20.0;
        let label = 12.0 + 4.0;
        let addr = 9.0 + 6.0;
        let lines = (vertex.code_units.len().min(6) as f32) * (10.0 + 2.0);
        base + label + addr + lines + 8.0
    };
    Vec2::new(w, h)
}

/// Render a single basic-block node at the given world-space position.
///
/// Draws a rounded rectangle with the block label, address, and a snippet of
/// the contained P-code operations.  Appearance varies by state flags
/// (entry, highlighted, hovered, called, external, collapsed).
pub fn render_block(
    ui: &mut Ui,
    vertex: &FGVertex,
    world_pos: Vec2,
    camera: &FgCamera,
    theme: &FgTheme,
    is_entry: bool,
    is_highlighted: bool,
    is_hovered: bool,
    is_called: bool,
    is_external: bool,
    is_collapsed: bool,
) {
    let painter = ui.painter().clone();

    let screen_pos = camera.world_to_screen(world_pos);
    let size = node_size(vertex, is_collapsed);
    let w = camera.world_to_screen_size(size.x);
    let h = camera.world_to_screen_size(size.y);
    let rounding = Rounding::same(theme.rounding);

    // -- Fill --
    let fill = if is_highlighted {
        theme.highlight_fill
    } else if is_entry {
        theme.entry_fill
    } else if is_called {
        theme.called_fill
    } else if is_external {
        theme.external_fill
    } else if is_collapsed {
        theme.collapsed_fill
    } else {
        theme.block_fill
    };

    // -- Stroke --
    let stroke_color = if is_hovered {
        theme.hover_stroke
    } else if is_highlighted {
        theme.highlight_stroke
    } else if is_entry {
        theme.entry_stroke
    } else {
        theme.block_stroke
    };
    let stroke_width = if is_hovered {
        theme.hover_stroke_width
    } else {
        1.5
    };

    // Rounded rect.
    let rect = Rect::from_min_size(screen_pos, Vec2::new(w, h));
    painter.add(Shape::Rect(RectShape {
        rect,
        rounding,
        fill,
        stroke: Stroke::new(stroke_width, stroke_color),
        ..Default::default()
    }));

    // Text: we lay out galleys using the context Fonts.
    let label = if vertex.label.is_empty() {
        format!("{:08X}", vertex.address.offset)
    } else {
        vertex.label.clone()
    };

    let label_color = if is_external {
        Color32::from_rgb(200, 180, 100)
    } else {
        theme.text_color
    };

    // Label.
    painter.text(
        Pos2::new(screen_pos.x + w / 2.0, screen_pos.y + 8.0),
        egui::Align2::CENTER_TOP,
        label,
        FontId::monospace(theme.label_font_size),
        label_color,
    );

    // Address.
    let addr_text = format!("{:08X}", vertex.address.offset);
    painter.text(
        Pos2::new(
            screen_pos.x + w / 2.0,
            screen_pos.y + 8.0 + theme.label_font_size + 4.0,
        ),
        egui::Align2::CENTER_TOP,
        addr_text,
        FontId::monospace(theme.addr_font_size),
        theme.text_secondary,
    );

    // P-code operation lines.
    let mut y_offset = screen_pos.y + 8.0 + theme.label_font_size + theme.addr_font_size + 6.0;
    let max_lines = if is_collapsed { 2 } else { 6 };
    let mut line_count = 0;

    for op in vertex.code_units.iter().take(max_lines) {
        let instr_text = format!("{}", op.opcode);
        painter.text(
            Pos2::new(screen_pos.x + 6.0, y_offset),
            egui::Align2::LEFT_TOP,
            instr_text,
            FontId::monospace(theme.instr_font_size),
            theme.text_secondary,
        );
        y_offset += theme.instr_font_size + 2.0;
        line_count += 1;
    }

    if is_collapsed && vertex.code_units.len() > max_lines {
        let more = format!("... +{} more", vertex.code_units.len() - max_lines);
        painter.text(
            Pos2::new(screen_pos.x + w / 2.0, y_offset),
            egui::Align2::CENTER_TOP,
            more,
            FontId::monospace(theme.addr_font_size),
            theme.text_secondary,
        );
    } else if !is_collapsed && line_count >= max_lines && vertex.code_units.len() > max_lines {
        painter.text(
            Pos2::new(screen_pos.x + w / 2.0, y_offset),
            egui::Align2::CENTER_TOP,
            "...",
            FontId::monospace(theme.addr_font_size),
            theme.text_secondary,
        );
    }
}

// ============================================================================
// Hit testing
// ============================================================================

/// Return the index of the vertex at the given screen-space position, or
/// `None` if no vertex is hit.
pub fn hit_test_nodes(
    screen_pos: Pos2,
    graph: &FunctionGraph,
    positions: &[Vec2],
    camera: &FgCamera,
    collapsed: &HashSet<usize>,
) -> Option<usize> {
    for i in 0..graph.vertices.len() {
        let pos = positions.get(i).copied().unwrap_or(Vec2::ZERO);
        let size = node_size(&graph.vertices[i], collapsed.contains(&i));
        let screen = camera.world_to_screen(pos);
        let w = camera.world_to_screen_size(size.x);
        let h = camera.world_to_screen_size(size.y);
        let rect = Rect::from_min_size(screen, Vec2::new(w, h));
        if rect.contains(screen_pos) {
            return Some(i);
        }
    }
    None
}

// ============================================================================
// Viewer state
// ============================================================================

/// Persistent state for the graph viewer.
#[derive(Clone)]
pub struct GraphViewerState {
    /// Camera state.
    pub camera: FgCamera,
    /// Cached layout positions (world space).
    pub positions: Vec<Vec2>,
    /// Whether positions need to be recomputed.
    pub dirty_positions: bool,
    /// Set of collapsed vertex indices.
    pub collapsed: HashSet<usize>,
    /// Index of the entry-point vertex.
    pub entry_index: Option<usize>,
    /// Index of the currently focused (clicked) vertex.
    pub focused_index: Option<usize>,
    /// Which vertex is being hovered (-1 = none).
    pub hovered_index: i32,
    /// Which vertex is being dragged (-1 = none).
    pub dragging_index: i32,
    /// Drag start position (world space).
    pub drag_start: Vec2,
    /// Whether we are panning the canvas (middle-button or right-button drag).
    pub panning: bool,
    /// Vertex indices representing called functions.
    pub called_indices: HashSet<usize>,
    /// Vertex indices representing external functions.
    pub external_indices: HashSet<usize>,
    /// Whether the minimap is visible.
    pub show_minimap: bool,
    /// Minimap size in screen pixels.
    pub minimap_size: f32,
}

impl GraphViewerState {
    pub fn new() -> Self {
        Self {
            camera: FgCamera::new(),
            positions: Vec::new(),
            dirty_positions: true,
            collapsed: HashSet::new(),
            entry_index: None,
            focused_index: None,
            hovered_index: -1,
            dragging_index: -1,
            drag_start: Vec2::ZERO,
            panning: false,
            called_indices: HashSet::new(),
            external_indices: HashSet::new(),
            show_minimap: true,
            minimap_size: 180.0,
        }
    }

    /// Recompute the hierarchical layout.
    pub fn recompute_layout(&mut self, graph: &mut FunctionGraph) {
        graph.layout.algorithm = LayoutAlgorithm::Hierarchical;
        graph.apply_layout();
        self.positions = graph.vertices.iter().map(|v| Vec2::new(v.x, v.y)).collect();
        self.dirty_positions = false;
    }

    /// Fit all vertices into view using the given viewport rect.
    pub fn fit_all(&mut self, graph: &FunctionGraph, viewport: Rect) {
        let bounds = graph_bounds(graph, &self.positions);
        self.camera.fit_all(bounds, viewport);
    }

    /// Focus on a single vertex.
    pub fn focus_on(&mut self, graph: &FunctionGraph, idx: usize, viewport: Rect) {
        if let Some(pos) = self.positions.get(idx) {
            let v = &graph.vertices[idx];
            let centre = Vec2::new(pos.x + v.width / 2.0, pos.y + v.height / 2.0);
            self.camera.focus_node(centre, viewport);
        }
    }

    /// Determine whether a vertex is a call instruction.
    fn is_call_vertex(vertex: &FGVertex) -> bool {
        vertex
            .code_units
            .iter()
            .any(|op| op.opcode == OpCode::CALL || op.opcode == OpCode::CALLIND)
    }

    /// Determine whether a vertex is external.
    fn is_external_vertex(vertex: &FGVertex) -> bool {
        vertex.code_units.is_empty() || vertex.label.to_lowercase().contains("external")
    }

    /// Refresh called/external sets from the graph.
    pub fn refresh_sets(&mut self, graph: &FunctionGraph) {
        self.called_indices.clear();
        self.external_indices.clear();
        for (i, v) in graph.vertices.iter().enumerate() {
            if Self::is_call_vertex(v) {
                self.called_indices.insert(i);
            }
            if Self::is_external_vertex(v) {
                self.external_indices.insert(i);
            }
        }
    }
}

impl Default for GraphViewerState {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Actions
// ============================================================================

/// Actions emitted by the graph viewer that the application should handle.
#[derive(Debug, Clone)]
pub enum GraphViewerAction {
    /// No action.
    None,
    /// Navigate the listing to this address.
    NavigateTo(Address),
    /// Request to focus the listing view at the given address.
    FocusListing(Address),
}

// ============================================================================
// Main interactive render
// ============================================================================

/// Render the complete interactive function graph.
///
/// Returns a [`GraphViewerAction`] that the caller should process (e.g.,
/// navigating the listing view to the focused address).
///
/// # Arguments
/// * `ui` - The egui [`Ui`] to paint into.
/// * `graph` - The function graph to render.
/// * `state` - Mutable viewer state (camera, layout, interactions).
/// * `theme` - Visual theme.
/// * `current_address` - The address currently focused in the listing (for
///   highlighting the corresponding block).
pub fn render_graph_view(
    ui: &mut Ui,
    graph: &mut FunctionGraph,
    state: &mut GraphViewerState,
    theme: &FgTheme,
    current_address: Address,
) -> GraphViewerAction {
    let mut action = GraphViewerAction::None;

    // ---- Allocate the full canvas region ----
    let (rect, mut response) = ui.allocate_exact_size(ui.available_size(), Sense::click_and_drag());

    let canvas_rect = rect;
    let painter = ui.painter_at(canvas_rect);

    // ---- Update layout if dirty ----
    if state.dirty_positions {
        state.recompute_layout(graph);
        let bounds = graph_bounds(graph, &state.positions);
        state.camera.fit_all(bounds, canvas_rect);
        state.camera.snap();
        state.refresh_sets(graph);
    }

    // ---- Tick camera animation ----
    if state.camera.tick() || state.camera.animating {
        ui.ctx().request_repaint();
    }

    // ---- Input handling ----
    let pointer_pos = ui.input(|i| i.pointer.hover_pos());

    // Pan with middle button or right button drag.
    if response.dragged_by(egui::PointerButton::Middle)
        || response.dragged_by(egui::PointerButton::Secondary)
    {
        let delta = response.drag_delta();
        state.camera.pan(delta);
        state.panning = true;
        response.mark_changed();
    } else {
        state.panning = false;
    }

    let pointer_in_canvas = pointer_pos.map_or(false, |p| canvas_rect.contains(p));

    // Zoom with scroll wheel.
    if pointer_in_canvas {
        let scroll = ui.input(|i| i.smooth_scroll_delta);
        if scroll.y != 0.0 {
            if let Some(anchor) = pointer_pos {
                let factor = 1.0 + scroll.y * 0.005;
                state.camera.zoom_at(factor, anchor);
                response.mark_changed();
            }
        }
    }

    // ---- Draw background ----
    painter.add(Shape::Rect(RectShape {
        rect: canvas_rect,
        rounding: Rounding::ZERO,
        fill: theme.bg_color,
        stroke: Stroke::NONE,
        ..Default::default()
    }));

    // ---- Grid dots (subtle dots every N world-space units) ----
    let grid_spacing = 40.0;
    let world_visible = state.camera.visible_world_rect(canvas_rect);
    let start_x = (world_visible.left() / grid_spacing).floor() * grid_spacing;
    let start_y = (world_visible.top() / grid_spacing).floor() * grid_spacing;
    let end_x = world_visible.right();
    let end_y = world_visible.bottom();

    let mut grid_x = start_x;
    while grid_x <= end_x {
        let mut grid_y = start_y;
        while grid_y <= end_y {
            let dot_screen = state.camera.world_to_screen(Vec2::new(grid_x, grid_y));
            if canvas_rect.contains(dot_screen) {
                painter.add(Shape::circle_filled(dot_screen, 1.0, theme.grid_color));
            }
            grid_y += grid_spacing;
        }
        grid_x += grid_spacing;
    }

    // ---- Draw edges (behind nodes) ----
    for edge in &graph.edges {
        if edge.from >= graph.vertices.len() || edge.to >= graph.vertices.len() {
            continue;
        }
        let from_pos = state
            .positions
            .get(edge.from)
            .copied()
            .unwrap_or(Vec2::ZERO);
        let to_pos = state.positions.get(edge.to).copied().unwrap_or(Vec2::ZERO);

        let from_size = node_size(
            &graph.vertices[edge.from],
            state.collapsed.contains(&edge.from),
        );
        let to_size = node_size(&graph.vertices[edge.to], state.collapsed.contains(&edge.to));

        let from_centre = Vec2::new(
            from_pos.x + from_size.x / 2.0,
            from_pos.y + from_size.y / 2.0,
        );
        let to_centre = Vec2::new(to_pos.x + to_size.x / 2.0, to_pos.y + to_size.y / 2.0);

        let from_border = clamp_to_node_border(from_pos, from_size, to_centre);
        let to_border = clamp_to_node_border(to_pos, to_size, from_centre);

        let from_screen = state.camera.world_to_screen(from_border);
        let to_screen = state.camera.world_to_screen(to_border);

        render_edge_polyline(
            &painter,
            from_screen,
            to_screen,
            edge.edge_type,
            theme.edge_width,
        );
    }

    // ---- Node hit testing ----
    let hovered: Option<usize> = pointer_pos
        .filter(|_| pointer_in_canvas)
        .and_then(|p| hit_test_nodes(p, graph, &state.positions, &state.camera, &state.collapsed));

    state.hovered_index = hovered.map(|h| h as i32).unwrap_or(-1);

    // ---- Drag repositioning of nodes ----
    if state.dragging_index >= 0 {
        let idx = state.dragging_index as usize;
        if let Some(p) = pointer_pos {
            let world = state.camera.screen_to_world(p);
            let v = &graph.vertices[idx];
            let offset = Vec2::new(v.width / 2.0, v.height / 2.0);
            if let Some(pos) = state.positions.get_mut(idx) {
                *pos = world - offset;
            }
            response.mark_changed();
        }
        if ui.input(|i| i.pointer.button_released(egui::PointerButton::Primary)) {
            state.dragging_index = -1;
        }
    }

    // ---- Handle clicks ----
    if response.clicked() {
        if let Some(idx) = hovered {
            let addr = graph.vertices[idx].address;
            state.focused_index = Some(idx);
            action = GraphViewerAction::NavigateTo(addr);

            let pos = state.positions[idx];
            let v = &graph.vertices[idx];
            let centre = Vec2::new(pos.x + v.width / 2.0, pos.y + v.height / 2.0);
            state.camera.focus_node(centre, canvas_rect);
        } else {
            state.focused_index = None;
        }
    }

    if response.double_clicked() {
        if let Some(idx) = hovered {
            if state.collapsed.contains(&idx) {
                state.collapsed.remove(&idx);
            } else {
                state.collapsed.insert(idx);
            }
        }
    }

    // Start dragging a node on primary-button drag.
    if state.dragging_index < 0
        && response.drag_started_by(egui::PointerButton::Primary)
        && state.hovered_index >= 0
    {
        state.dragging_index = state.hovered_index;
        state.drag_start = state
            .positions
            .get(state.hovered_index as usize)
            .copied()
            .unwrap_or(Vec2::ZERO);
    }

    // ---- Determine which vertex corresponds to the current listing address ----
    let current_listing_idx: i32 = graph
        .vertices
        .iter()
        .position(|v| {
            v.address.offset <= current_address.offset
                && v.address.offset.wrapping_add(v.code_units.len() as u64) > current_address.offset
        })
        .map(|i| i as i32)
        .unwrap_or(-1);

    // ---- Draw nodes ----
    for i in 0..graph.vertices.len() {
        let pos = state.positions.get(i).copied().unwrap_or(Vec2::ZERO);
        let is_entry = state.entry_index == Some(i);
        let is_highlighted = state.focused_index == Some(i) || current_listing_idx == i as i32;
        let is_hovered = state.hovered_index == i as i32;
        let is_called = state.called_indices.contains(&i);
        let is_external = state.external_indices.contains(&i);
        let is_collapsed = state.collapsed.contains(&i);

        render_block(
            ui,
            &graph.vertices[i],
            pos,
            &state.camera,
            theme,
            is_entry,
            is_highlighted,
            is_hovered,
            is_called,
            is_external,
            is_collapsed,
        );
    }

    // ---- Minimap ----
    if state.show_minimap {
        render_minimap(ui, graph, state, theme, canvas_rect);
    }

    // ---- Keyboard shortcuts ----
    let input = ui.input(|i| i.clone());
    if pointer_in_canvas {
        if input.key_pressed(egui::Key::F) {
            let bounds = graph_bounds(graph, &state.positions);
            state.camera.fit_all(bounds, canvas_rect);
        }
        if input.key_pressed(egui::Key::Home) {
            state
                .camera
                .zoom_at(1.0 / state.camera.target_zoom, canvas_rect.center());
        }
        let pan_amount = 50.0;
        if input.key_pressed(egui::Key::ArrowUp) {
            state.camera.pan(Vec2::new(0.0, pan_amount));
        }
        if input.key_pressed(egui::Key::ArrowDown) {
            state.camera.pan(Vec2::new(0.0, -pan_amount));
        }
        if input.key_pressed(egui::Key::ArrowLeft) {
            state.camera.pan(Vec2::new(pan_amount, 0.0));
        }
        if input.key_pressed(egui::Key::ArrowRight) {
            state.camera.pan(Vec2::new(-pan_amount, 0.0));
        }
        if input.key_pressed(egui::Key::Plus) || input.key_pressed(egui::Key::Equals) {
            state.camera.zoom_at(1.15, canvas_rect.center());
        }
        if input.key_pressed(egui::Key::Minus) {
            state.camera.zoom_at(0.85, canvas_rect.center());
        }
    }

    action
}

// ============================================================================
// Minimap
// ============================================================================

/// Render a corner minimap / satellite view showing the overview.
fn render_minimap(
    ui: &Ui,
    graph: &FunctionGraph,
    state: &GraphViewerState,
    theme: &FgTheme,
    canvas_rect: Rect,
) {
    let map_size = state.minimap_size;
    let margin = 10.0;

    let map_rect = Rect::from_min_size(
        Pos2::new(
            canvas_rect.right() - map_size - margin,
            canvas_rect.bottom() - map_size - margin,
        ),
        Vec2::new(map_size, map_size),
    );

    if map_rect.width() < 40.0 || map_rect.height() < 40.0 {
        return;
    }

    let painter = ui.painter_at(map_rect);

    // Background.
    painter.add(Shape::Rect(RectShape {
        rect: map_rect,
        rounding: Rounding::same(4.0),
        fill: theme.minimap_bg,
        stroke: Stroke::new(1.0, Color32::from_rgba_premultiplied(255, 255, 255, 40)),
        ..Default::default()
    }));

    let bounds = graph_bounds(graph, &state.positions);
    if bounds.width() <= 0.0 || bounds.height() <= 0.0 {
        return;
    }

    let pad = 8.0;
    let avail_w = map_rect.width() - 2.0 * pad;
    let avail_h = map_rect.height() - 2.0 * pad;
    let scale_x = avail_w / bounds.width();
    let scale_y = avail_h / bounds.height();
    let scale = scale_x.min(scale_y);

    let offset_x =
        map_rect.left() + pad + (avail_w - bounds.width() * scale) / 2.0 - bounds.left() * scale;
    let offset_y =
        map_rect.top() + pad + (avail_h - bounds.height() * scale) / 2.0 - bounds.top() * scale;

    // Nodes as small rectangles.
    for (i, pos) in state.positions.iter().enumerate() {
        let v = &graph.vertices[i];
        let sx = offset_x + pos.x * scale;
        let sy = offset_y + pos.y * scale;
        let sw = (v.width * scale).max(2.0);
        let sh = (v.height * scale).max(2.0);
        let node_rect = Rect::from_min_size(Pos2::new(sx, sy), Vec2::new(sw, sh));
        if map_rect.intersects(node_rect) {
            painter.add(Shape::Rect(RectShape {
                rect: node_rect,
                rounding: Rounding::same(1.0),
                fill: theme.minimap_node,
                stroke: Stroke::NONE,
                ..Default::default()
            }));
        }
    }

    // Viewport rectangle.
    let world_visible = state.camera.visible_world_rect(canvas_rect);
    let vx = offset_x + world_visible.left() * scale;
    let vy = offset_y + world_visible.top() * scale;
    let vw = (world_visible.width() * scale).max(4.0);
    let vh = (world_visible.height() * scale).max(4.0);
    let view_rect = Rect::from_min_size(Pos2::new(vx, vy), Vec2::new(vw, vh));

    painter.add(Shape::Rect(RectShape {
        rect: view_rect,
        rounding: Rounding::ZERO,
        fill: Color32::TRANSPARENT,
        stroke: Stroke::new(1.5, theme.minimap_viewport),
        ..Default::normal()
    }));
}

// ============================================================================
// Convenience helper: node-edge intersection
// ============================================================================

/// Compute the point on the border of the rect `(pos, size)` that is closest
/// to `target`.  Used to start/end edges at the border of nodes rather
/// than their centre.
fn clamp_to_node_border(pos: Vec2, size: Vec2, target: Vec2) -> Vec2 {
    let centre = Vec2::new(pos.x + size.x / 2.0, pos.y + size.y / 2.0);
    let half = Vec2::new(size.x / 2.0, size.y / 2.0);

    let dir = target - centre;
    if dir.x.abs() < 0.001 && dir.y.abs() < 0.001 {
        return centre;
    }

    let fx = if dir.x != 0.0 {
        half.x / dir.x.abs()
    } else {
        f32::INFINITY
    };
    let fy = if dir.y != 0.0 {
        half.y / dir.y.abs()
    } else {
        f32::INFINITY
    };
    let f = fx.min(fy);

    Vec2::new(centre.x + dir.x * f, centre.y + dir.y * f)
}

// ============================================================================
// Helper: Build a demo FunctionGraph
// ============================================================================

/// Build a demo function graph for testing and live preview.
pub fn demo_function_graph() -> FunctionGraph {
    use ghidra_core::addr::AddressRange;
    use ghidra_core::program::listing::Function;

    /// Helper to create a stub PcodeOperation with just an opcode.
    fn pcode_op(opcode: OpCode) -> PcodeOperation {
        PcodeOperation::new_unannotated(opcode, None, vec![])
    }

    let f = Function {
        name: "demo_function".to_string(),
        entry_point: Address::new(0x401000),
        body: AddressRange::new(Address::new(0x401000), Address::new(0x401200)),
        signature: "void demo_function(int)".to_string(),
    };

    let vertices = vec![
        FGVertex::new(
            Address::new(0x401000),
            "entry".to_string(),
            vec![
                pcode_op(OpCode::COPY),
                pcode_op(OpCode::INT_ADD),
                pcode_op(OpCode::STORE),
            ],
        ),
        FGVertex::new(
            Address::new(0x401020),
            "cmp_block".to_string(),
            vec![pcode_op(OpCode::INT_SUB), pcode_op(OpCode::CBRANCH)],
        ),
        FGVertex::new(
            Address::new(0x401040),
            "true_branch".to_string(),
            vec![
                pcode_op(OpCode::COPY),
                pcode_op(OpCode::INT_ADD),
                pcode_op(OpCode::BRANCH),
            ],
        ),
        FGVertex::new(
            Address::new(0x401060),
            "false_branch".to_string(),
            vec![pcode_op(OpCode::COPY), pcode_op(OpCode::INT_SUB)],
        ),
        FGVertex::new(
            Address::new(0x401080),
            "loop_body".to_string(),
            vec![pcode_op(OpCode::INT_SUB), pcode_op(OpCode::CBRANCH)],
        ),
        FGVertex::new(
            Address::new(0x4010a0),
            "call_block".to_string(),
            vec![pcode_op(OpCode::CALL)],
        ),
        FGVertex::new(
            Address::new(0x4010c0),
            "merge".to_string(),
            vec![
                pcode_op(OpCode::COPY),
                pcode_op(OpCode::INT_ADD),
                pcode_op(OpCode::RETURN),
            ],
        ),
    ];

    let edges = vec![
        FGEdge::new(0, 1, CfgEdgeType::Fallthrough),
        FGEdge::new(1, 2, CfgEdgeType::TrueBranch),
        FGEdge::new(1, 3, CfgEdgeType::FalseBranch),
        FGEdge::new(2, 4, CfgEdgeType::Fallthrough),
        FGEdge::new(3, 5, CfgEdgeType::Fallthrough),
        FGEdge::new(4, 1, CfgEdgeType::Branch),
        FGEdge::new(5, 6, CfgEdgeType::Fallthrough),
        FGEdge::new(4, 6, CfgEdgeType::Branch),
    ];

    FunctionGraph::from_parts(f, vertices, edges)
}

// ============================================================================
// Standalone widget: FunctionGraphWindow
// ============================================================================

/// A complete self-contained function graph viewer window.
///
/// Handles layout, rendering, and interactions.  Suitable for embedding in
/// any egui application.
pub struct FunctionGraphWindow {
    /// The function graph.
    pub graph: FunctionGraph,
    /// Viewer state.
    pub state: GraphViewerState,
    /// Theme.
    pub theme: FgTheme,
    /// Whether the window is open.
    pub open: bool,
}

impl FunctionGraphWindow {
    /// Create a new window with a demo graph.
    pub fn new() -> Self {
        let mut graph = demo_function_graph();
        graph.apply_layout();
        let mut state = GraphViewerState::new();
        state.entry_index = Some(0);
        state.positions = graph.vertices.iter().map(|v| Vec2::new(v.x, v.y)).collect();
        state.dirty_positions = false;
        state.refresh_sets(&graph);
        Self {
            graph,
            state,
            theme: FgTheme::dark(),
            open: true,
        }
    }

    /// Create a window from an existing function graph.
    pub fn from_graph(mut graph: FunctionGraph) -> Self {
        graph.apply_layout();
        let mut state = GraphViewerState::new();
        state.entry_index = Some(0);
        state.positions = graph.vertices.iter().map(|v| Vec2::new(v.x, v.y)).collect();
        state.dirty_positions = false;
        state.refresh_sets(&graph);
        Self {
            graph,
            state,
            theme: FgTheme::dark(),
            open: true,
        }
    }

    /// Show the interactive window.
    pub fn show(
        &mut self,
        ctx: &egui::Context,
        current_address: Address,
    ) -> Option<GraphViewerAction> {
        if !self.open {
            return None;
        }

        let mut action = None;

        egui::Window::new(format!("Function Graph - {}", self.graph.function.name))
            .resizable(true)
            .default_size([800.0, 600.0])
            .show(ctx, |ui| {
                action = Some(render_graph_view(
                    ui,
                    &mut self.graph,
                    &mut self.state,
                    &self.theme,
                    current_address,
                ));

                // Toolbar below the graph.
                ui.separator();
                ui.horizontal(|ui| {
                    if ui.button("Fit All").clicked() {
                        self.state
                            .fit_all(&self.graph, ui.available_rect_before_wrap());
                    }
                    if ui.button("Reset Layout").clicked() {
                        self.state.dirty_positions = true;
                    }
                    if ui.button("Collapse All").clicked() {
                        for i in 0..self.graph.vertices.len() {
                            self.state.collapsed.insert(i);
                        }
                    }
                    if ui.button("Expand All").clicked() {
                        self.state.collapsed.clear();
                    }
                    if ui.button("Tgl Minimap").clicked() {
                        self.state.show_minimap = !self.state.show_minimap;
                    }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.label(format!("Zoom: {:.1}x", self.state.camera.zoom));
                        ui.label(format!(
                            "{} nodes | {} edges",
                            self.graph.vertices.len(),
                            self.graph.edges.len()
                        ));
                    });
                });
            });

        action
    }
}

impl Default for FunctionGraphWindow {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// GraphCamera -- simplified camera matching the public API spec
// ============================================================================

/// Lightweight camera for the function graph widget.
///
/// Maps between "graph space" (world coordinates) and screen space (egui pixel
/// coordinates).  This is a simpler alternative to [`FgCamera`] without animation.
#[derive(Debug, Clone)]
pub struct GraphCamera {
    /// Screen-space pixel offset of the graph-space origin.
    pub offset: Vec2,
    /// Zoom factor (1.0 = 1:1 mapping from graph units to screen pixels).
    pub zoom: f32,
}

impl GraphCamera {
    /// Create a new camera with sensible defaults.
    pub fn new() -> Self {
        Self {
            offset: Vec2::new(50.0, 50.0),
            zoom: 1.0,
        }
    }

    /// Convert a graph-space point to screen-space.
    #[inline]
    pub fn world_to_screen(&self, world: Vec2) -> Pos2 {
        Pos2::new(
            world.x * self.zoom + self.offset.x,
            world.y * self.zoom + self.offset.y,
        )
    }

    /// Convert a screen-space position to graph-space.
    #[inline]
    pub fn screen_to_world(&self, screen: Pos2) -> Vec2 {
        Vec2::new(
            (screen.x - self.offset.x) / self.zoom,
            (screen.y - self.offset.y) / self.zoom,
        )
    }

    /// Convert a graph-space size to screen-space.
    #[inline]
    pub fn world_to_screen_size(&self, world: f32) -> f32 {
        world * self.zoom
    }

    /// Pan by a screen-space delta.
    pub fn pan(&mut self, delta: Vec2) {
        self.offset += delta;
    }

    /// Zoom by a multiplicative factor about a screen-space anchor point.
    pub fn zoom_at(&mut self, factor: f32, anchor: Pos2) {
        let new_zoom = (self.zoom * factor).clamp(0.1, 5.0);
        let world = self.screen_to_world(anchor);
        self.offset = Vec2::new(anchor.x - world.x * new_zoom, anchor.y - world.y * new_zoom);
        self.zoom = new_zoom;
    }

    /// Centre the camera on a graph-space point in the given viewport.
    pub fn focus_node(&mut self, world_pos: Vec2, viewport: Rect) {
        let centre = viewport.center();
        self.offset = Vec2::new(
            centre.x - world_pos.x * self.zoom,
            centre.y - world_pos.y * self.zoom,
        );
    }

    /// Fit all vertices into the viewport.
    pub fn fit_all(&mut self, bounds: Rect, viewport: Rect) {
        if !bounds.is_finite() || bounds.area() <= 0.0 {
            return;
        }
        let padding = 60.0;
        let avail_w = (viewport.width() - 2.0 * padding).max(10.0);
        let avail_h = (viewport.height() - 2.0 * padding).max(10.0);
        let zoom_w = avail_w / bounds.width();
        let zoom_h = avail_h / bounds.height();
        self.zoom = zoom_w.min(zoom_h).clamp(0.1, 5.0);

        let bw = bounds.width() * self.zoom;
        let bh = bounds.height() * self.zoom;
        let cx = viewport.left() + (viewport.width() - bw) / 2.0;
        let cy = viewport.top() + (viewport.height() - bh) / 2.0;
        self.offset = Vec2::new(
            cx - bounds.left() * self.zoom,
            cy - bounds.top() * self.zoom,
        );
    }

    /// Compute the graph-space visible rectangle for a given viewport.
    pub fn visible_world_rect(&self, viewport: Rect) -> Rect {
        let top_left = self.screen_to_world(viewport.left_top());
        let bottom_right = self.screen_to_world(viewport.right_bottom());
        Rect::from_min_max(top_left.to_pos2(), bottom_right.to_pos2())
    }
}

impl Default for GraphCamera {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// FunctionGraphWidget -- self-contained interactive graph widget
// ============================================================================

/// A self-contained interactive function graph widget.
///
/// This struct owns the graph data, layout positions, camera, and interaction
/// state.  Call [`render`](Self::render) each frame inside an egui region.
///
/// # Example
///
/// ```ignore
/// let mut widget = FunctionGraphWidget::from_graph(my_graph);
/// widget.layout();
/// // In your egui update loop:
/// widget.render(ui);
/// ```
pub struct FunctionGraphWidget {
    /// The function graph being displayed.
    pub graph: FunctionGraph,
    /// Layout configuration used for positioning vertices.
    pub layout: GraphLayout,
    /// Camera (pan/zoom) state.
    pub camera: GraphCamera,
    /// Cached layout positions for each vertex (graph-space).
    pub positions: Vec<Vec2>,
    /// Index of the currently selected node, if any.
    pub selected_node: Option<usize>,
    /// Index of the node under the cursor, if any.
    pub hovered_node: Option<usize>,
    /// Set of nodes that are collapsed (show only label, not full disassembly).
    pub expanded_nodes: HashSet<usize>,
    /// Whether to show the minimap overlay.
    pub show_minimap: bool,
    /// Index of the entry-point vertex.
    entry_index: Option<usize>,
    /// Which vertex is being dragged (-1 = none).
    dragging_index: i32,
    /// Theme for visual styling.
    theme: FgTheme,
    /// Set of called-function vertex indices.
    called_indices: HashSet<usize>,
    /// Set of external-function vertex indices.
    external_indices: HashSet<usize>,
    /// Whether positions need to be recomputed.
    dirty_positions: bool,
    /// Last computed bounding box of all vertices.
    cached_bounds: Option<Rect>,
    /// Whether the canvas is being panned.
    panning: bool,
    /// Current address being tracked in the listing view.
    current_address: Address,
}

impl FunctionGraphWidget {
    /// Create a new widget from a function graph.
    ///
    /// The graph's layout settings are used.  Call [`layout`](Self::layout)
    /// before first render to position all vertices.
    pub fn from_graph(mut graph: FunctionGraph) -> Self {
        let n = graph.vertices.len();
        graph.apply_layout();
        let positions: Vec<Vec2> = graph.vertices.iter().map(|v| Vec2::new(v.x, v.y)).collect();
        let mut called = HashSet::new();
        let mut external = HashSet::new();
        for (i, v) in graph.vertices.iter().enumerate() {
            let has_call = v
                .code_units
                .iter()
                .any(|op| op.opcode == OpCode::CALL || op.opcode == OpCode::CALLIND);
            if has_call {
                called.insert(i);
            }
            if v.code_units.is_empty() || v.label.to_lowercase().contains("external") {
                external.insert(i);
            }
        }
        let mut expanded = HashSet::new();
        for i in 0..n {
            expanded.insert(i);
        }
        let bounds = compute_bounds(&graph, &positions);

        Self {
            graph,
            layout: GraphLayout::default(),
            camera: GraphCamera::new(),
            positions,
            selected_node: None,
            hovered_node: None,
            expanded_nodes: expanded,
            show_minimap: true,
            entry_index: Some(0),
            dragging_index: -1,
            theme: FgTheme::dark(),
            called_indices: called,
            external_indices: external,
            dirty_positions: false,
            cached_bounds: Some(bounds),
            panning: false,
            current_address: Address::new(0),
        }
    }

    // ---- Layout ----

    /// Run the hierarchical (Sugiyama-style) layout algorithm and cache
    /// resulting vertex positions.
    pub fn layout(&mut self) {
        self.graph.layout.algorithm = LayoutAlgorithm::Hierarchical;
        self.graph.layout.layer_spacing = self.layout.layer_spacing;
        self.graph.layout.node_spacing = self.layout.node_spacing;
        self.graph.layout.direction = self.layout.direction;
        self.graph.apply_layout();
        self.positions = self
            .graph
            .vertices
            .iter()
            .map(|v| Vec2::new(v.x, v.y))
            .collect();
        self.cached_bounds = Some(compute_bounds(&self.graph, &self.positions));
        self.dirty_positions = false;
    }

    /// Run the compact layout that minimises edge crossings.
    /// Uses an enhanced Sugiyama variant with two-pass barycentre ordering.
    pub fn layout_compact(&mut self) {
        let n = self.graph.vertices.len();
        if n == 0 {
            self.positions.clear();
            self.cached_bounds = Some(Rect::from_min_max(
                Pos2::new(0.0, 0.0),
                Pos2::new(100.0, 100.0),
            ));
            return;
        }

        let layer_spacing = self.layout.layer_spacing;
        let node_spacing = self.layout.node_spacing;

        // Build adjacency
        let mut adj: Vec<Vec<usize>> = vec![Vec::new(); n];
        let mut rev_adj: Vec<Vec<usize>> = vec![Vec::new(); n];
        for edge in &self.graph.edges {
            if edge.from < n && edge.to < n {
                adj[edge.from].push(edge.to);
                rev_adj[edge.to].push(edge.from);
            }
        }

        // Layer assignment (longest-path from sources)
        let mut in_degree: Vec<usize> = rev_adj.iter().map(|v| v.len()).collect();
        let mut layer: Vec<usize> = vec![0; n];
        let mut queue: std::collections::VecDeque<usize> = std::collections::VecDeque::new();
        for (i, &deg) in in_degree.iter().enumerate() {
            if deg == 0 {
                queue.push_back(i);
            }
        }
        if queue.is_empty() && n > 0 {
            queue.push_back(0);
        }
        while let Some(u) = queue.pop_front() {
            for &v in &adj[u] {
                layer[v] = layer[v].max(layer[u] + 1);
                if in_degree[v] > 0 {
                    in_degree[v] -= 1;
                    if in_degree[v] == 0 {
                        queue.push_back(v);
                    }
                }
            }
        }
        // Handle remaining nodes (cycles)
        for i in 0..n {
            if in_degree[i] > 0 {
                let max_pred = rev_adj[i].iter().map(|&p| layer[p]).max().unwrap_or(0);
                layer[i] = max_pred + 1;
            }
        }

        let max_layer = layer.iter().copied().max().unwrap_or(0);
        let mut layers: Vec<Vec<usize>> = vec![Vec::new(); max_layer + 1];
        for (i, &l) in layer.iter().enumerate() {
            if l < layers.len() {
                layers[l].push(i);
            }
        }

        // Two-pass barycentre heuristic for crossing minimisation.
        // Forward pass: sort each layer based on predecessor positions.
        for l in 1..=max_layer {
            layers[l].sort_by(|&a, &b| {
                let avg = |v: usize| -> f32 {
                    let preds: Vec<usize> = rev_adj[v]
                        .iter()
                        .filter(|&&p| p < n && layer[p] == l - 1)
                        .copied()
                        .collect();
                    if preds.is_empty() {
                        return layers[l - 1].len() as f32 / 2.0;
                    }
                    preds
                        .iter()
                        .map(|p| layers[l - 1].iter().position(|&x| x == *p).unwrap_or(0) as f32)
                        .sum::<f32>()
                        / preds.len() as f32
                };
                avg(a)
                    .partial_cmp(&avg(b))
                    .unwrap_or(std::cmp::Ordering::Equal)
            });
        }
        // Backward pass: sort each layer based on successor positions.
        for l in (0..=max_layer).rev() {
            if l == 0 {
                break;
            }
            let layer_l_minus_1 = layers[l - 1].clone();
            layers[l - 1].sort_by(|&a, &b| {
                let avg = |v: usize| -> f32 {
                    let succs: Vec<usize> = adj[v]
                        .iter()
                        .filter(|&&s| s < n && layer[s] == l)
                        .copied()
                        .collect();
                    if succs.is_empty() {
                        return layers[l].len() as f32 / 2.0;
                    }
                    succs
                        .iter()
                        .map(|s| layers[l].iter().position(|&x| x == *s).unwrap_or(0) as f32)
                        .sum::<f32>()
                        / succs.len() as f32
                };
                avg(a)
                    .partial_cmp(&avg(b))
                    .unwrap_or(std::cmp::Ordering::Equal)
            });
        }

        // Map to positions.
        let mut positions: Vec<Vec2> = vec![Vec2::ZERO; n];
        for (l_idx, layer_nodes) in layers.iter().enumerate() {
            for (o_idx, &node_idx) in layer_nodes.iter().enumerate() {
                positions[node_idx] =
                    Vec2::new(o_idx as f32 * node_spacing, l_idx as f32 * layer_spacing);
            }
        }

        // Persist positions into graph vertices as well.
        for (i, pos) in positions.iter().enumerate() {
            self.graph.vertices[i].x = pos.x;
            self.graph.vertices[i].y = pos.y;
        }

        self.positions = positions;
        self.cached_bounds = Some(compute_bounds(&self.graph, &self.positions));
        self.dirty_positions = false;
    }

    /// Mark the layout as dirty so it is recomputed on the next render.
    pub fn invalidate_layout(&mut self) {
        self.dirty_positions = true;
    }

    // ---- Rendering ----

    /// Render the complete interactive function graph into the given egui
    /// [`Ui`].  Call this every frame when the graph is visible.
    ///
    /// Returns `Some(address)` if the user clicked a node, requesting the
    /// application to navigate the listing view to that address.
    pub fn render(&mut self, ui: &mut egui::Ui) -> Option<Address> {
        let mut target_address: Option<Address> = None;

        // Allocate canvas region.
        let (canvas_rect, mut response) =
            ui.allocate_exact_size(ui.available_size(), Sense::click_and_drag());
        let painter = ui.painter_at(canvas_rect);

        // Recompute layout if dirty.
        if self.dirty_positions {
            self.layout();
            let bounds = compute_bounds(&self.graph, &self.positions);
            self.camera.fit_all(bounds, canvas_rect);
            self.cached_bounds = Some(bounds);
            self.dirty_positions = false;
        }

        // ---- Background fill ----
        painter.add(Shape::Rect(RectShape {
            rect: canvas_rect,
            rounding: Rounding::ZERO,
            fill: self.theme.bg_color,
            stroke: Stroke::NONE,
            ..Default::default()
        }));

        // ---- Grid dots ----
        let grid_spacing = 40.0;
        let world_visible = self.camera.visible_world_rect(canvas_rect);
        let start_x = (world_visible.left() / grid_spacing).floor() * grid_spacing;
        let start_y = (world_visible.top() / grid_spacing).floor() * grid_spacing;
        let end_x = world_visible.right();
        let end_y = world_visible.bottom();

        let mut gx = start_x;
        while gx <= end_x {
            let mut gy = start_y;
            while gy <= end_y {
                let dot_screen = self.camera.world_to_screen(Vec2::new(gx, gy));
                if canvas_rect.contains(dot_screen) {
                    painter.add(Shape::circle_filled(dot_screen, 1.0, self.theme.grid_color));
                }
                gy += grid_spacing;
            }
            gx += grid_spacing;
        }

        // ---- Draw edges (behind nodes) ----
        let n_vertices = self.graph.vertices.len();
        for edge in &self.graph.edges {
            if edge.from >= n_vertices || edge.to >= n_vertices {
                continue;
            }
            let from_pos = self.positions.get(edge.from).copied().unwrap_or(Vec2::ZERO);
            let to_pos = self.positions.get(edge.to).copied().unwrap_or(Vec2::ZERO);

            let from_collapsed = !self.expanded_nodes.contains(&edge.from);
            let to_collapsed = !self.expanded_nodes.contains(&edge.to);
            let from_size = node_size(&self.graph.vertices[edge.from], from_collapsed);
            let to_size = node_size(&self.graph.vertices[edge.to], to_collapsed);

            let from_centre = Vec2::new(
                from_pos.x + from_size.x / 2.0,
                from_pos.y + from_size.y / 2.0,
            );
            let to_centre = Vec2::new(to_pos.x + to_size.x / 2.0, to_pos.y + to_size.y / 2.0);

            let from_border = clamp_to_node_border(from_pos, from_size, to_centre);
            let to_border = clamp_to_node_border(to_pos, to_size, from_centre);

            let from_screen = self.camera.world_to_screen(from_border);
            let to_screen = self.camera.world_to_screen(to_border);

            render_edge_polyline(
                &painter,
                from_screen,
                to_screen,
                edge.edge_type,
                self.theme.edge_width,
            );
        }

        // ---- Input handling ----
        let pointer_pos = ui.input(|i| i.pointer.hover_pos());
        let pointer_in_canvas = pointer_pos.map_or(false, |p| canvas_rect.contains(p));

        // Pan with middle/right button drag.
        if response.dragged_by(egui::PointerButton::Middle)
            || response.dragged_by(egui::PointerButton::Secondary)
        {
            let delta = response.drag_delta();
            self.camera.pan(delta);
            self.panning = true;
            response.mark_changed();
        } else {
            self.panning = false;
        }

        // Zoom with scroll wheel.
        if pointer_in_canvas {
            let scroll = ui.input(|i| i.smooth_scroll_delta);
            if scroll.y != 0.0 {
                if let Some(anchor) = pointer_pos {
                    let factor = 1.0 + scroll.y * 0.005;
                    self.camera.zoom_at(factor, anchor);
                    response.mark_changed();
                }
            }
        }

        // ---- Hit testing for hover ----
        let hovered = pointer_pos
            .filter(|_| pointer_in_canvas)
            .and_then(|p| self.hit_test(p));
        self.hovered_node = hovered;

        // ---- Drag repositioning of nodes ----
        if self.dragging_index >= 0 {
            let idx = self.dragging_index as usize;
            if let Some(p) = pointer_pos {
                let world = self.camera.screen_to_world(p);
                let v = &self.graph.vertices[idx];
                let offset = Vec2::new(v.width / 2.0, v.height / 2.0);
                if let Some(pos) = self.positions.get_mut(idx) {
                    *pos = world - offset;
                    self.graph.vertices[idx].x = pos.x;
                    self.graph.vertices[idx].y = pos.y;
                }
                response.mark_changed();
            }
            if ui.input(|i| i.pointer.button_released(egui::PointerButton::Primary)) {
                self.dragging_index = -1;
            }
        }

        // ---- Handle clicks ----
        if response.clicked() {
            if let Some(idx) = hovered {
                let addr = self.graph.vertices[idx].address;
                self.selected_node = Some(idx);
                target_address = Some(addr);

                let pos = self.positions[idx];
                let v = &self.graph.vertices[idx];
                let centre = Vec2::new(pos.x + v.width / 2.0, pos.y + v.height / 2.0);
                self.camera.focus_node(centre, canvas_rect);
            } else {
                self.selected_node = None;
            }
        }

        // ---- Double-click to expand/collapse ----
        if response.double_clicked() {
            if let Some(idx) = hovered {
                if self.expanded_nodes.contains(&idx) {
                    self.expanded_nodes.remove(&idx);
                } else {
                    self.expanded_nodes.insert(idx);
                }
            }
        }

        // ---- Start dragging a node on primary-button drag ----
        if self.dragging_index < 0
            && response.drag_started_by(egui::PointerButton::Primary)
            && self.hovered_node.is_some()
        {
            if let Some(h_idx) = self.hovered_node {
                self.dragging_index = h_idx as i32;
            }
        }

        // ---- Draw nodes ----
        for i in 0..n_vertices {
            let pos = self.positions.get(i).copied().unwrap_or(Vec2::ZERO);
            let is_entry = self.entry_index == Some(i);
            let is_highlighted = self.selected_node == Some(i)
                || self.current_address.offset >= self.graph.vertices[i].address.offset
                    && self.current_address.offset
                        < self.graph.vertices[i]
                            .address
                            .offset
                            .wrapping_add(self.graph.vertices[i].code_units.len() as u64);
            let is_hovered = self.hovered_node == Some(i);
            let is_called = self.called_indices.contains(&i);
            let is_external = self.external_indices.contains(&i);
            let is_collapsed = !self.expanded_nodes.contains(&i);

            render_block_widget(
                ui,
                &self.graph.vertices[i],
                pos,
                &self.camera,
                &self.theme,
                is_entry,
                is_highlighted,
                is_hovered,
                is_called,
                is_external,
                is_collapsed,
            );
        }

        // ---- Hover tooltip ----
        if self.hovered_node.is_some() && pointer_in_canvas {
            if let Some(h_idx) = self.hovered_node {
                self.render_tooltip(ui, h_idx);
            }
        }

        // ---- Minimap ----
        if self.show_minimap {
            render_minimap_widget(ui, self, canvas_rect);
        }

        // ---- Keyboard shortcuts ----
        let input = ui.input(|i| i.clone());
        if pointer_in_canvas {
            if input.key_pressed(egui::Key::F) {
                if let Some(bounds) = self.cached_bounds {
                    self.camera.fit_all(bounds, canvas_rect);
                }
            }
            let pan_amount = 50.0;
            if input.key_pressed(egui::Key::ArrowUp) {
                self.camera.pan(Vec2::new(0.0, pan_amount));
            }
            if input.key_pressed(egui::Key::ArrowDown) {
                self.camera.pan(Vec2::new(0.0, -pan_amount));
            }
            if input.key_pressed(egui::Key::ArrowLeft) {
                self.camera.pan(Vec2::new(pan_amount, 0.0));
            }
            if input.key_pressed(egui::Key::ArrowRight) {
                self.camera.pan(Vec2::new(-pan_amount, 0.0));
            }
            if input.key_pressed(egui::Key::Plus) || input.key_pressed(egui::Key::Equals) {
                self.camera.zoom_at(1.15, canvas_rect.center());
            }
            if input.key_pressed(egui::Key::Minus) {
                self.camera.zoom_at(0.85, canvas_rect.center());
            }
            if input.key_pressed(egui::Key::Home) {
                if let Some(entry) = self.entry_index {
                    self.focus_node(entry);
                    if let Some(bounds) = self.cached_bounds {
                        self.camera.focus_node(self.positions[entry], canvas_rect);
                    }
                }
            }
        }

        target_address
    }

    /// Render a hover tooltip showing the full disassembly of the node.
    fn render_tooltip(&self, ui: &mut egui::Ui, node_idx: usize) {
        let vertex = &self.graph.vertices[node_idx];
        let tooltip_text: String =
            std::iter::once(format!("{} @ {:08X}", vertex.label, vertex.address.offset))
                .chain(vertex.code_units.iter().map(|op| {
                    let addr_str = op
                        .address
                        .map_or("        ".to_string(), |a| format!("{:08X}", a.offset));
                    format!("  {}  {}", addr_str, op.opcode)
                }))
                .collect::<Vec<_>>()
                .join("\n");

        egui::show_tooltip_at_pointer(ui.ctx(), egui::Id::new("graph_tooltip"), |ui| {
            ui.label(
                egui::RichText::new(tooltip_text)
                    .font(egui::FontId::monospace(10.0))
                    .color(self.theme.text_color),
            );
        });
    }

    // ---- Spatial queries ----

    /// Return the screen-space rectangle occupied by the given node index.
    ///
    /// Returns [`Rect::NOTHING`] if the index is out of bounds.
    pub fn node_screen_rect(&self, node_idx: usize) -> Rect {
        if node_idx >= self.graph.vertices.len() {
            return Rect::NOTHING;
        }
        let pos = self.positions.get(node_idx).copied().unwrap_or(Vec2::ZERO);
        let is_collapsed = !self.expanded_nodes.contains(&node_idx);
        let size = node_size(&self.graph.vertices[node_idx], is_collapsed);
        let screen_pos = self.camera.world_to_screen(pos);
        let w = self.camera.world_to_screen_size(size.x);
        let h = self.camera.world_to_screen_size(size.y);
        Rect::from_min_size(screen_pos, Vec2::new(w, h))
    }

    /// Convert a screen-space position to graph-space.
    pub fn screen_to_graph(&self, pos: Pos2) -> Pos2 {
        let world = self.camera.screen_to_world(pos);
        Pos2::new(world.x, world.y)
    }

    /// Hit-test all vertices and return the index of the one at the given
    /// screen-space position, or `None`.
    pub fn hit_test(&self, pos: Pos2) -> Option<usize> {
        for i in (0..self.graph.vertices.len()).rev() {
            // Iterate in reverse so that top-most (last drawn) nodes are
            // picked first.
            let node_pos = self.positions.get(i).copied().unwrap_or(Vec2::ZERO);
            let is_collapsed = !self.expanded_nodes.contains(&i);
            let size = node_size(&self.graph.vertices[i], is_collapsed);
            let screen = self.camera.world_to_screen(node_pos);
            let w = self.camera.world_to_screen_size(size.x);
            let h = self.camera.world_to_screen_size(size.y);
            let rect = Rect::from_min_size(screen, Vec2::new(w, h));
            if rect.contains(pos) {
                return Some(i);
            }
        }
        None
    }

    /// Pan and zoom the camera to centre on the given vertex index.
    pub fn focus_node(&mut self, node_idx: usize) {
        if node_idx >= self.positions.len() {
            return;
        }
        self.selected_node = Some(node_idx);
        let pos = self.positions[node_idx];
        let v = &self.graph.vertices[node_idx];
        let centre = Vec2::new(pos.x + v.width / 2.0, pos.y + v.height / 2.0);
        // Set offset so the node centre appears at screen centre (the caller
        // is expected to provide viewport via render() or call this before
        // rendering).
        self.camera.offset = Vec2::new(-centre.x * self.camera.zoom, -centre.y * self.camera.zoom);
    }

    /// Set the current address (from the listing view) for cursor highlighting.
    pub fn set_current_address(&mut self, addr: Address) {
        self.current_address = addr;
    }

    /// Jump to the entry-point vertex.
    pub fn jump_to_entry(&mut self) {
        if let Some(entry) = self.entry_index {
            self.focus_node(entry);
            self.selected_node = Some(entry);
        }
    }

    /// Follow the call edges from the currently selected node.
    ///
    /// If the selected node is a call, focuses on the first called-function
    /// vertex.  Otherwise, follows the first outgoing edge.
    pub fn follow_call(&mut self) {
        let source = match self.selected_node {
            Some(idx) => idx,
            None => return,
        };
        // Find outgoing call edges.
        for edge in &self.graph.edges {
            if edge.from == source
                && (edge.edge_type == CfgEdgeType::Call || self.called_indices.contains(&edge.to))
            {
                self.focus_node(edge.to);
                return;
            }
        }
        // Fallback: follow first outgoing edge.
        for edge in &self.graph.edges {
            if edge.from == source {
                self.focus_node(edge.to);
                return;
            }
        }
    }

    // ---- Helpers ----

    /// Expand all nodes.
    pub fn expand_all(&mut self) {
        self.expanded_nodes.clear();
        for i in 0..self.graph.vertices.len() {
            self.expanded_nodes.insert(i);
        }
    }

    /// Collapse all nodes.
    pub fn collapse_all(&mut self) {
        self.expanded_nodes.clear();
    }

    /// Toggle the minimap visibility.
    pub fn toggle_minimap(&mut self) {
        self.show_minimap = !self.show_minimap;
    }

    /// Set the visual theme.
    pub fn set_theme(&mut self, theme: FgTheme) {
        self.theme = theme;
    }

    /// Get a reference to the current theme.
    pub fn theme(&self) -> &FgTheme {
        &self.theme
    }
}

// ----- Helper: render a block node using a GraphCamera -----

fn render_block_widget(
    ui: &mut egui::Ui,
    vertex: &FGVertex,
    world_pos: Vec2,
    camera: &GraphCamera,
    theme: &FgTheme,
    is_entry: bool,
    is_highlighted: bool,
    is_hovered: bool,
    is_called: bool,
    is_external: bool,
    is_collapsed: bool,
) {
    let painter = ui.painter().clone();

    let screen_pos = camera.world_to_screen(world_pos);
    let size = node_size(vertex, is_collapsed);
    let w = camera.world_to_screen_size(size.x);
    let h = camera.world_to_screen_size(size.y);
    let rounding = Rounding::same(theme.rounding);

    // -- Fill --
    let fill = if is_highlighted {
        theme.highlight_fill
    } else if is_entry {
        theme.entry_fill
    } else if is_called {
        theme.called_fill
    } else if is_external {
        theme.external_fill
    } else if is_collapsed {
        theme.collapsed_fill
    } else {
        theme.block_fill
    };

    // -- Stroke --
    let stroke_color = if is_hovered {
        theme.hover_stroke
    } else if is_highlighted {
        theme.highlight_stroke
    } else if is_entry {
        theme.entry_stroke
    } else {
        theme.block_stroke
    };
    let stroke_width = if is_hovered {
        theme.hover_stroke_width
    } else {
        1.5
    };

    // Rounded rect.
    let rect = Rect::from_min_size(screen_pos, Vec2::new(w, h));
    painter.add(Shape::Rect(RectShape {
        rect,
        rounding,
        fill,
        stroke: Stroke::new(stroke_width, stroke_color),
        ..Default::default()
    }));

    // Label.
    let label = if vertex.label.is_empty() {
        format!("{:08X}", vertex.address.offset)
    } else {
        vertex.label.clone()
    };
    let label_color = if is_external {
        Color32::from_rgb(200, 180, 100)
    } else {
        theme.text_color
    };

    painter.text(
        Pos2::new(screen_pos.x + w / 2.0, screen_pos.y + 8.0),
        egui::Align2::CENTER_TOP,
        label,
        FontId::monospace(theme.label_font_size),
        label_color,
    );

    // Address.
    let addr_text = format!("{:08X}", vertex.address.offset);
    painter.text(
        Pos2::new(
            screen_pos.x + w / 2.0,
            screen_pos.y + 8.0 + theme.label_font_size + 4.0,
        ),
        egui::Align2::CENTER_TOP,
        addr_text,
        FontId::monospace(theme.addr_font_size),
        theme.text_secondary,
    );

    // P-code operation lines.
    let mut y_offset = screen_pos.y + 8.0 + theme.label_font_size + theme.addr_font_size + 6.0;
    let max_lines = if is_collapsed { 2 } else { 6 };
    let mut line_count = 0;

    for op in vertex.code_units.iter().take(max_lines) {
        let instr_text = format!("{}", op.opcode);
        painter.text(
            Pos2::new(screen_pos.x + 6.0, y_offset),
            egui::Align2::LEFT_TOP,
            instr_text,
            FontId::monospace(theme.instr_font_size),
            theme.text_secondary,
        );
        y_offset += theme.instr_font_size + 2.0;
        line_count += 1;
    }

    if is_collapsed && vertex.code_units.len() > max_lines {
        let more = format!("... +{} more", vertex.code_units.len() - max_lines);
        painter.text(
            Pos2::new(screen_pos.x + w / 2.0, y_offset),
            egui::Align2::CENTER_TOP,
            more,
            FontId::monospace(theme.addr_font_size),
            theme.text_secondary,
        );
    } else if !is_collapsed && line_count >= max_lines && vertex.code_units.len() > max_lines {
        painter.text(
            Pos2::new(screen_pos.x + w / 2.0, y_offset),
            egui::Align2::CENTER_TOP,
            "...",
            FontId::monospace(theme.addr_font_size),
            theme.text_secondary,
        );
    }
}

// ----- Helper: render a minimap for FunctionGraphWidget -----

fn render_minimap_widget(ui: &egui::Ui, widget: &FunctionGraphWidget, canvas_rect: Rect) {
    let map_size = 180.0;
    let margin = 10.0;

    let map_rect = Rect::from_min_size(
        Pos2::new(
            canvas_rect.right() - map_size - margin,
            canvas_rect.bottom() - map_size - margin,
        ),
        Vec2::new(map_size, map_size),
    );

    if map_rect.width() < 40.0 || map_rect.height() < 40.0 {
        return;
    }

    let painter = ui.painter_at(map_rect);
    let theme = &widget.theme;

    // Background.
    painter.add(Shape::Rect(RectShape {
        rect: map_rect,
        rounding: Rounding::same(4.0),
        fill: theme.minimap_bg,
        stroke: Stroke::new(1.0, Color32::from_rgba_premultiplied(255, 255, 255, 40)),
        ..Default::default()
    }));

    let bounds = match widget.cached_bounds {
        Some(b) => b,
        None => compute_bounds(&widget.graph, &widget.positions),
    };
    if bounds.width() <= 0.0 || bounds.height() <= 0.0 {
        return;
    }

    let pad = 8.0;
    let avail_w = map_rect.width() - 2.0 * pad;
    let avail_h = map_rect.height() - 2.0 * pad;
    let scale_x = avail_w / bounds.width();
    let scale_y = avail_h / bounds.height();
    let scale = scale_x.min(scale_y);

    let offset_x =
        map_rect.left() + pad + (avail_w - bounds.width() * scale) / 2.0 - bounds.left() * scale;
    let offset_y =
        map_rect.top() + pad + (avail_h - bounds.height() * scale) / 2.0 - bounds.top() * scale;

    // Nodes as small rectangles.
    for (i, pos) in widget.positions.iter().enumerate() {
        let v = &widget.graph.vertices[i];
        let sx = offset_x + pos.x * scale;
        let sy = offset_y + pos.y * scale;
        let sw = (v.width * scale).max(2.0);
        let sh = (v.height * scale).max(2.0);
        let node_rect = Rect::from_min_size(Pos2::new(sx, sy), Vec2::new(sw, sh));
        if map_rect.intersects(node_rect) {
            painter.add(Shape::Rect(RectShape {
                rect: node_rect,
                rounding: Rounding::same(1.0),
                fill: theme.minimap_node,
                stroke: Stroke::NONE,
                ..Default::default()
            }));
        }
    }

    // Viewport rectangle.
    let world_visible = widget.camera.visible_world_rect(canvas_rect);
    let vx = offset_x + world_visible.left() * scale;
    let vy = offset_y + world_visible.top() * scale;
    let vw = (world_visible.width() * scale).max(4.0);
    let vh = (world_visible.height() * scale).max(4.0);
    let view_rect = Rect::from_min_size(Pos2::new(vx, vy), Vec2::new(vw, vh));

    painter.add(Shape::Rect(RectShape {
        rect: view_rect,
        rounding: Rounding::ZERO,
        fill: Color32::TRANSPARENT,
        stroke: Stroke::new(1.5, theme.minimap_viewport),
        ..Default::default()
    }));
}

// ----- Helper: compute bounding box -----

fn compute_bounds(graph: &FunctionGraph, positions: &[Vec2]) -> Rect {
    if positions.is_empty() {
        return Rect::from_min_max(Pos2::new(0.0, 0.0), Pos2::new(100.0, 100.0));
    }
    let mut min_x = f32::INFINITY;
    let mut min_y = f32::INFINITY;
    let mut max_x = f32::NEG_INFINITY;
    let mut max_y = f32::NEG_INFINITY;
    for (i, pos) in positions.iter().enumerate() {
        let v = &graph.vertices[i];
        min_x = min_x.min(pos.x);
        min_y = min_y.min(pos.y);
        max_x = max_x.max(pos.x + v.width);
        max_y = max_y.max(pos.y + v.height);
    }
    Rect::from_min_max(Pos2::new(min_x, min_y), Pos2::new(max_x, max_y))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_camera_world_to_screen() {
        let cam = FgCamera::new();
        let screen = cam.world_to_screen(Vec2::new(100.0, 200.0));
        assert!((screen.x - 150.0).abs() < 1.0);
        assert!((screen.y - 250.0).abs() < 1.0);
    }

    #[test]
    fn test_camera_screen_to_world_roundtrip() {
        let cam = FgCamera::new();
        let world = Vec2::new(300.0, 400.0);
        let screen = cam.world_to_screen(world);
        let back = cam.screen_to_world(screen);
        assert!((back.x - world.x).abs() < 0.01);
        assert!((back.y - world.y).abs() < 0.01);
    }

    #[test]
    fn test_camera_zoom_at() {
        let mut cam = FgCamera::new();
        cam.zoom_at(2.0, Pos2::new(100.0, 100.0));
        cam.snap();
        assert!((cam.zoom - 2.0).abs() < 0.01);
    }

    #[test]
    fn test_camera_animation() {
        let mut cam = FgCamera::new();
        cam.target_offset = Vec2::new(200.0, 200.0);
        cam.animating = true;
        assert!(cam.tick());
        assert!(cam.offset.x > 50.0);
    }

    #[test]
    fn test_layout_hierarchical() {
        let graph = demo_function_graph();
        let positions = layout_hierarchical(&graph);
        assert_eq!(positions.len(), graph.vertices.len());
    }

    #[test]
    fn test_graph_bounds() {
        let graph = demo_function_graph();
        let positions = vec![
            Vec2::new(0.0, 0.0),
            Vec2::new(100.0, 100.0),
            Vec2::new(200.0, 0.0),
            Vec2::new(0.0, 200.0),
            Vec2::new(200.0, 200.0),
            Vec2::new(300.0, 100.0),
            Vec2::new(300.0, 300.0),
        ];
        let bounds = graph_bounds(&graph, &positions);
        assert!(bounds.width() > 0.0);
        assert!(bounds.height() > 0.0);
    }

    #[test]
    fn test_hit_test_nodes() {
        let graph = demo_function_graph();
        let positions: Vec<Vec2> = vec![
            Vec2::new(0.0, 0.0),
            Vec2::new(200.0, 0.0),
            Vec2::new(400.0, 0.0),
            Vec2::new(200.0, 200.0),
            Vec2::new(400.0, 200.0),
            Vec2::new(600.0, 0.0),
            Vec2::new(400.0, 400.0),
        ];
        let cam = FgCamera::new();
        let collapsed = HashSet::new();

        let screen = cam.world_to_screen(Vec2::new(100.0, 80.0));
        let hit = hit_test_nodes(screen, &graph, &positions, &cam, &collapsed);
        assert_eq!(hit, Some(0));

        let far = cam.world_to_screen(Vec2::new(-500.0, -500.0));
        let miss = hit_test_nodes(far, &graph, &positions, &cam, &collapsed);
        assert_eq!(miss, None);
    }

    #[test]
    fn test_clamp_to_node_border() {
        let pos = Vec2::new(100.0, 100.0);
        let size = Vec2::new(200.0, 100.0);
        let target = Vec2::new(500.0, 150.0);

        let border = clamp_to_node_border(pos, size, target);
        assert!((border.x - 300.0).abs() < 1.0);
        assert!((border.y - 150.0).abs() < 1.0);
    }

    #[test]
    fn test_edge_color_mapping() {
        assert_eq!(
            edge_color(CfgEdgeType::Fallthrough),
            Color32::from_rgb(46, 160, 60)
        );
        assert_eq!(
            edge_color(CfgEdgeType::FalseBranch),
            Color32::from_rgb(210, 50, 50)
        );
    }

    #[test]
    fn test_demo_graph() {
        let graph = demo_function_graph();
        assert!(!graph.vertices.is_empty());
        assert!(!graph.edges.is_empty());
        assert_eq!(graph.function.name, "demo_function");
    }

    #[test]
    fn test_viewer_state_defaults() {
        let state = GraphViewerState::new();
        assert!(state.dirty_positions);
        assert_eq!(state.hovered_index, -1);
        assert_eq!(state.dragging_index, -1);
        assert!(state.show_minimap);
    }

    #[test]
    fn test_node_size_collapsed() {
        let vertex = FGVertex::new(Address::new(0x1000), "test".to_string(), vec![]);
        let size = node_size(&vertex, true);
        assert!(size.y < 60.0);
    }

    #[test]
    fn test_node_size_expanded() {
        fn op(code: OpCode) -> PcodeOperation {
            PcodeOperation::new_unannotated(code, None, vec![])
        }
        let vertex = FGVertex::new(
            Address::new(0x1000),
            "test".to_string(),
            vec![op(OpCode::COPY), op(OpCode::INT_ADD), op(OpCode::STORE)],
        );
        let size = node_size(&vertex, false);
        assert!(size.y > 60.0);
    }

    // ---- GraphCamera tests ----

    #[test]
    fn test_graph_camera_new() {
        let cam = GraphCamera::new();
        assert!((cam.zoom - 1.0).abs() < 0.01);
        assert!((cam.offset.x - 50.0).abs() < 0.01);
        assert!((cam.offset.y - 50.0).abs() < 0.01);
    }

    #[test]
    fn test_graph_camera_world_to_screen() {
        let cam = GraphCamera::new();
        let screen = cam.world_to_screen(Vec2::new(100.0, 200.0));
        assert!((screen.x - 150.0).abs() < 1.0);
        assert!((screen.y - 250.0).abs() < 1.0);
    }

    #[test]
    fn test_graph_camera_screen_to_world_roundtrip() {
        let cam = GraphCamera::new();
        let world = Vec2::new(300.0, 400.0);
        let screen = cam.world_to_screen(world);
        let back = cam.screen_to_world(screen);
        assert!((back.x - world.x).abs() < 0.01);
        assert!((back.y - world.y).abs() < 0.01);
    }

    #[test]
    fn test_graph_camera_zoom_at() {
        let mut cam = GraphCamera::new();
        cam.zoom_at(2.0, Pos2::new(100.0, 100.0));
        assert!((cam.zoom - 2.0).abs() < 0.01);
    }

    #[test]
    fn test_graph_camera_pan() {
        let mut cam = GraphCamera::new();
        let orig = cam.offset;
        cam.pan(Vec2::new(100.0, -50.0));
        assert!((cam.offset.x - orig.x - 100.0).abs() < 0.01);
        assert!((cam.offset.y - orig.y + 50.0).abs() < 0.01);
    }

    #[test]
    fn test_graph_camera_zoom_clamped() {
        let mut cam = GraphCamera::new();
        cam.zoom_at(100.0, Pos2::new(0.0, 0.0));
        assert!((cam.zoom - 5.0).abs() < 0.01);
    }

    // ---- FunctionGraphWidget tests ----

    #[test]
    fn test_widget_from_graph() {
        let graph = demo_function_graph();
        let widget = FunctionGraphWidget::from_graph(graph);
        assert_eq!(widget.positions.len(), widget.graph.vertices.len());
        assert_eq!(widget.entry_index, Some(0));
        assert!(widget.show_minimap);
        assert!(widget.expanded_nodes.len() > 0);
    }

    #[test]
    fn test_widget_layout() {
        let graph = demo_function_graph();
        let mut widget = FunctionGraphWidget::from_graph(graph);
        widget.layout();
        assert_eq!(widget.positions.len(), widget.graph.vertices.len());
        // After layout, positions should be non-overlapping vertically
        // for a hierarchical layout of a DAG with multiple layers.
        let mut layers: std::collections::BTreeSet<i32> = std::collections::BTreeSet::new();
        for pos in &widget.positions {
            layers.insert(pos.y as i32);
        }
        // With 7 vertices in a hierarchical DAG, we expect at least 2 distinct layers.
        assert!(layers.len() >= 2);
    }

    #[test]
    fn test_widget_layout_compact() {
        let graph = demo_function_graph();
        let mut widget = FunctionGraphWidget::from_graph(graph);
        widget.layout_compact();
        assert_eq!(widget.positions.len(), widget.graph.vertices.len());
        assert!(!widget.dirty_positions);
    }

    #[test]
    fn test_widget_hit_test() {
        let graph = demo_function_graph();
        let mut widget = FunctionGraphWidget::from_graph(graph);
        widget.layout();

        // Hit test at the position of vertex 0.
        let pos = widget.positions[0];
        let screen = widget.camera.world_to_screen(pos);
        let hit = widget.hit_test(screen);
        assert_eq!(hit, Some(0));

        // Hit test far away should return None.
        let far = widget.camera.world_to_screen(Vec2::new(-5000.0, -5000.0));
        let miss = widget.hit_test(far);
        assert_eq!(miss, None);
    }

    #[test]
    fn test_widget_node_screen_rect() {
        let graph = demo_function_graph();
        let mut widget = FunctionGraphWidget::from_graph(graph);
        widget.layout();
        let rect = widget.node_screen_rect(0);
        assert!(rect.width() > 0.0);
        assert!(rect.height() > 0.0);
    }

    #[test]
    fn test_widget_node_screen_rect_out_of_bounds() {
        let graph = demo_function_graph();
        let widget = FunctionGraphWidget::from_graph(graph);
        let rect = widget.node_screen_rect(999);
        assert_eq!(rect, Rect::NOTHING);
    }

    #[test]
    fn test_widget_screen_to_graph() {
        let graph = demo_function_graph();
        let widget = FunctionGraphWidget::from_graph(graph);
        let screen = Pos2::new(150.0, 250.0);
        let graph_pos = widget.screen_to_graph(screen);
        // At zoom 1.0 and offset (50, 50): graph = screen - offset
        assert!((graph_pos.x - 100.0).abs() < 0.01);
        assert!((graph_pos.y - 200.0).abs() < 0.01);
    }

    #[test]
    fn test_widget_focus_node() {
        let graph = demo_function_graph();
        let mut widget = FunctionGraphWidget::from_graph(graph);
        widget.layout();
        widget.focus_node(0);
        assert_eq!(widget.selected_node, Some(0));
    }

    #[test]
    fn test_widget_expand_collapse() {
        let graph = demo_function_graph();
        let mut widget = FunctionGraphWidget::from_graph(graph);
        let n = widget.graph.vertices.len();
        assert!(widget.expanded_nodes.len() > 0);

        widget.collapse_all();
        assert!(widget.expanded_nodes.is_empty());

        widget.expand_all();
        assert_eq!(widget.expanded_nodes.len(), n);
    }

    #[test]
    fn test_widget_toggle_minimap() {
        let graph = demo_function_graph();
        let mut widget = FunctionGraphWidget::from_graph(graph);
        assert!(widget.show_minimap);
        widget.toggle_minimap();
        assert!(!widget.show_minimap);
        widget.toggle_minimap();
        assert!(widget.show_minimap);
    }

    #[test]
    fn test_widget_invalidate_layout() {
        let graph = demo_function_graph();
        let mut widget = FunctionGraphWidget::from_graph(graph);
        widget.layout();
        assert!(!widget.dirty_positions);
        widget.invalidate_layout();
        assert!(widget.dirty_positions);
    }

    #[test]
    fn test_widget_set_current_address() {
        let graph = demo_function_graph();
        let mut widget = FunctionGraphWidget::from_graph(graph);
        let addr = Address::new(0x401020);
        widget.set_current_address(addr);
        assert_eq!(widget.current_address.offset, 0x401020);
    }

    #[test]
    fn test_widget_jump_to_entry() {
        let graph = demo_function_graph();
        let mut widget = FunctionGraphWidget::from_graph(graph);
        widget.focus_node(3); // select non-entry
        assert_eq!(widget.selected_node, Some(3));
        widget.jump_to_entry();
        assert_eq!(widget.selected_node, Some(0));
    }

    #[test]
    fn test_compute_bounds_empty() {
        let graph = demo_function_graph();
        let bounds = compute_bounds(&graph, &[]);
        assert!(bounds.width() > 0.0);
        assert!(bounds.height() > 0.0);
    }

    #[test]
    fn test_compute_bounds_with_positions() {
        let graph = demo_function_graph();
        let positions: Vec<Vec2> = graph.vertices.iter().map(|v| Vec2::new(v.x, v.y)).collect();
        let bounds = compute_bounds(&graph, &positions);
        assert!(bounds.width() > 0.0);
        assert!(bounds.height() > 0.0);
    }
}
