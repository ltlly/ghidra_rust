//! Vertex rendering and interaction for visual graphs.
//!
//! Ports Ghidra's `ghidra.graph.viewer.vertex` package.  Provides abstract
//! base types and traits for rendering, clicking, focusing, and shaping
//! vertices in a visual graph viewer.

use std::collections::HashMap;
use std::fmt::Debug;
use std::hash::Hash;

use super::visual_types::{Point2d, Rect2d, RgbaColor, VertexRendererConfig};

// ============================================================================
// VertexShapeProvider -- provides the shape of a vertex for rendering
// ============================================================================

/// Trait for vertices that provide their own shape for rendering.
///
/// Ports `ghidra.graph.viewer.vertex.VertexShapeProvider`.
pub trait VertexShapeProvider: Debug {
    /// Get the bounding rectangle of this vertex.
    fn bounding_rect(&self) -> Rect2d;

    /// Get the shape type used for rendering this vertex.
    fn shape_type(&self) -> VertexShapeType;
}

/// Shape types that can be used to render a vertex.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VertexShapeType {
    /// Rounded rectangle (default for function nodes).
    RoundedRectangle,
    /// Ellipse.
    Ellipse,
    /// Diamond (used for decision nodes).
    Diamond,
    /// Rectangle.
    Rectangle,
    /// Hexagon (used for special nodes).
    Hexagon,
    /// Parallelogram (used for I/O nodes).
    Parallelogram,
}

impl Default for VertexShapeType {
    fn default() -> Self {
        Self::RoundedRectangle
    }
}

// ============================================================================
// VertexClickListener -- callback when a vertex is clicked
// ============================================================================

/// Listener for vertex click events.
///
/// Ports `ghidra.graph.viewer.vertex.VertexClickListener`.
pub trait VertexClickListener<V: Clone + Debug + Eq + Hash>: Debug + Send + Sync {
    /// Called when a vertex is clicked.
    fn vertex_clicked(&self, vertex: &V, double_click: bool);
}

// ============================================================================
// VertexFocusListener -- callback when vertex focus changes
// ============================================================================

/// Listener for vertex focus changes.
///
/// Ports `ghidra.graph.viewer.vertex.VertexFocusListener`.
pub trait VertexFocusListener<V: Clone + Debug + Eq + Hash>: Debug + Send + Sync {
    /// Called when a vertex gains focus.
    fn focus_gained(&self, vertex: &V);

    /// Called when a vertex loses focus.
    fn focus_lost(&self, vertex: &V);
}

// ============================================================================
// AbstractVisualVertex -- a base implementation of a visual vertex
// ============================================================================

/// Abstract base implementation of a visual vertex with UI state.
///
/// Ports `ghidra.graph.viewer.vertex.AbstractVisualVertex`.  Provides
/// selection, focus, hover, emphasis, and position state.
#[derive(Debug, Clone)]
pub struct AbstractVisualVertex {
    /// Unique identifier for this vertex.
    pub id: usize,
    /// Display location in graph coordinates.
    location: Point2d,
    /// Whether this vertex is selected.
    selected: bool,
    /// Whether this vertex has focus.
    focused: bool,
    /// Whether the mouse is hovering over this vertex.
    hovered: bool,
    /// Whether this vertex is emphasized (e.g., in a search result).
    emphasized: bool,
    /// Opacity of this vertex (0.0 = transparent, 1.0 = opaque).
    alpha: f32,
    /// The shape type for rendering.
    shape: VertexShapeType,
    /// User-visible label.
    label: String,
}

impl AbstractVisualVertex {
    /// Create a new abstract visual vertex with the given ID and label.
    pub fn new(id: usize, label: impl Into<String>) -> Self {
        Self {
            id,
            location: Point2d::default(),
            selected: false,
            focused: false,
            hovered: false,
            emphasized: false,
            alpha: 1.0,
            shape: VertexShapeType::default(),
            label: label.into(),
        }
    }

    /// Get the display location.
    pub fn location(&self) -> Point2d {
        self.location
    }

    /// Set the display location.
    pub fn set_location(&mut self, loc: Point2d) {
        self.location = loc;
    }

    /// Whether this vertex is selected.
    pub fn is_selected(&self) -> bool {
        self.selected
    }

    /// Set the selected state.
    pub fn set_selected(&mut self, selected: bool) {
        self.selected = selected;
    }

    /// Whether this vertex has focus.
    pub fn is_focused(&self) -> bool {
        self.focused
    }

    /// Set the focused state.
    pub fn set_focused(&mut self, focused: bool) {
        self.focused = focused;
    }

    /// Whether the mouse is hovering over this vertex.
    pub fn is_hovered(&self) -> bool {
        self.hovered
    }

    /// Set the hover state.
    pub fn set_hovered(&mut self, hovered: bool) {
        self.hovered = hovered;
    }

    /// Whether this vertex is emphasized.
    pub fn is_emphasized(&self) -> bool {
        self.emphasized
    }

    /// Set the emphasis state.
    pub fn set_emphasized(&mut self, emphasized: bool) {
        self.emphasized = emphasized;
    }

    /// Get the alpha (opacity) value.
    pub fn alpha(&self) -> f32 {
        self.alpha
    }

    /// Set the alpha (opacity) value.
    pub fn set_alpha(&mut self, alpha: f32) {
        self.alpha = alpha.clamp(0.0, 1.0);
    }

    /// Get the shape type.
    pub fn shape_type(&self) -> VertexShapeType {
        self.shape
    }

    /// Set the shape type.
    pub fn set_shape_type(&mut self, shape: VertexShapeType) {
        self.shape = shape;
    }

    /// Get the label.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Set the label.
    pub fn set_label(&mut self, label: impl Into<String>) {
        self.label = label.into();
    }

    /// Get the bounding rectangle for this vertex (default 100x30).
    pub fn bounding_rect(&self) -> Rect2d {
        Rect2d::new(self.location.x, self.location.y, 100.0, 30.0)
    }

    /// Check if a point is inside this vertex's bounds.
    pub fn contains(&self, point: &Point2d) -> bool {
        self.bounding_rect().contains(point)
    }
}

impl PartialEq for AbstractVisualVertex {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}
impl Eq for AbstractVisualVertex {}

impl std::hash::Hash for AbstractVisualVertex {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}

// ============================================================================
// AbstractVisualVertexRenderer -- base renderer for vertices
// ============================================================================

/// Abstract base for vertex renderers.  Handles common rendering concerns
/// like background color selection based on state (selected, hovered, etc.).
///
/// Ports `ghidra.graph.viewer.vertex.AbstractVisualVertexRenderer`.
#[derive(Debug, Clone)]
pub struct AbstractVisualVertexRenderer {
    /// Default background color.
    pub default_color: RgbaColor,
    /// Color when selected.
    pub selected_color: RgbaColor,
    /// Color when hovered.
    pub hovered_color: RgbaColor,
    /// Color when emphasized.
    pub emphasized_color: RgbaColor,
    /// Color when focused.
    pub focused_color: RgbaColor,
    /// Default border color.
    pub border_color: RgbaColor,
    /// Selected border color.
    pub selected_border_color: RgbaColor,
    /// Border width in pixels.
    pub border_width: f32,
}

impl Default for AbstractVisualVertexRenderer {
    fn default() -> Self {
        Self {
            default_color: RgbaColor::new(60, 60, 60, 255),
            selected_color: RgbaColor::new(50, 100, 180, 255),
            hovered_color: RgbaColor::new(70, 80, 100, 255),
            emphasized_color: RgbaColor::new(255, 200, 50, 255),
            focused_color: RgbaColor::new(40, 80, 160, 255),
            border_color: RgbaColor::new(100, 100, 100, 255),
            selected_border_color: RgbaColor::new(100, 150, 255, 255),
            border_width: 1.0,
        }
    }
}

impl AbstractVisualVertexRenderer {
    /// Create a new renderer with default colors.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the appropriate background color based on vertex state.
    pub fn background_color(
        &self,
        selected: bool,
        hovered: bool,
        emphasized: bool,
        focused: bool,
    ) -> RgbaColor {
        if focused {
            return self.focused_color;
        }
        if selected {
            return self.selected_color;
        }
        if emphasized {
            return self.emphasized_color;
        }
        if hovered {
            return self.hovered_color;
        }
        self.default_color
    }

    /// Get the appropriate border color based on vertex state.
    pub fn border_color_for_state(&self, selected: bool) -> RgbaColor {
        if selected {
            self.selected_border_color
        } else {
            self.border_color
        }
    }
}

// ============================================================================
// DockingVisualVertex -- vertex that can be rendered as a dockable panel
// ============================================================================

/// A visual vertex that can be rendered as a dockable panel inside the graph.
///
/// Ports `ghidra.graph.viewer.vertex.DockingVisualVertex`.
#[derive(Debug, Clone)]
pub struct DockingVisualVertex {
    /// Base vertex data.
    pub base: AbstractVisualVertex,
    /// Whether this vertex panel is collapsible.
    pub collapsible: bool,
    /// Whether this vertex panel is currently collapsed.
    collapsed: bool,
    /// The panel title.
    pub panel_title: String,
}

impl DockingVisualVertex {
    /// Create a new docking visual vertex.
    pub fn new(id: usize, label: impl Into<String>) -> Self {
        let label_str = label.into();
        Self {
            base: AbstractVisualVertex::new(id, &label_str),
            collapsible: true,
            collapsed: false,
            panel_title: label_str,
        }
    }

    /// Whether this panel is collapsed.
    pub fn is_collapsed(&self) -> bool {
        self.collapsed
    }

    /// Toggle the collapsed state.
    pub fn toggle_collapsed(&mut self) {
        if self.collapsible {
            self.collapsed = !self.collapsed;
        }
    }

    /// Set collapsed state.
    pub fn set_collapsed(&mut self, collapsed: bool) {
        if self.collapsible || !collapsed {
            self.collapsed = collapsed;
        }
    }
}

impl PartialEq for DockingVisualVertex {
    fn eq(&self, other: &Self) -> bool {
        self.base.id == other.base.id
    }
}
impl Eq for DockingVisualVertex {}

impl std::hash::Hash for DockingVisualVertex {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.base.id.hash(state);
    }
}

// ============================================================================
// VertexShapeTransformer -- maps vertices to their shape
// ============================================================================

/// Transforms a vertex into its rendering shape.
///
/// Ports `ghidra.graph.viewer.vertex.VisualGraphVertexShapeTransformer`.
#[derive(Debug, Default)]
pub struct VertexShapeTransformer {
    /// Default shape for vertices.
    pub default_shape: VertexShapeType,
    /// Per-vertex overrides keyed by vertex ID.
    overrides: HashMap<usize, VertexShapeType>,
}

impl VertexShapeTransformer {
    /// Create a new transformer with the given default shape.
    pub fn new(default_shape: VertexShapeType) -> Self {
        Self {
            default_shape,
            overrides: HashMap::new(),
        }
    }

    /// Get the shape for a vertex by ID.
    pub fn shape_for(&self, vertex_id: usize) -> VertexShapeType {
        self.overrides.get(&vertex_id).copied().unwrap_or(self.default_shape)
    }

    /// Set a shape override for a specific vertex.
    pub fn set_override(&mut self, vertex_id: usize, shape: VertexShapeType) {
        self.overrides.insert(vertex_id, shape);
    }

    /// Remove a shape override.
    pub fn remove_override(&mut self, vertex_id: usize) {
        self.overrides.remove(&vertex_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_abstract_visual_vertex() {
        let mut v = AbstractVisualVertex::new(1, "test_vertex");
        assert_eq!(v.id, 1);
        assert_eq!(v.label(), "test_vertex");
        assert!(!v.is_selected());

        v.set_selected(true);
        assert!(v.is_selected());

        v.set_focused(true);
        assert!(v.is_focused());

        v.set_alpha(0.5);
        assert_eq!(v.alpha(), 0.5);
    }

    #[test]
    fn test_abstract_visual_vertex_contains() {
        let mut v = AbstractVisualVertex::new(1, "test");
        v.set_location(Point2d::new(10.0, 20.0));

        assert!(v.contains(&Point2d::new(50.0, 35.0)));
        assert!(!v.contains(&Point2d::new(200.0, 200.0)));
    }

    #[test]
    fn test_renderer_background_color() {
        let renderer = AbstractVisualVertexRenderer::default();

        let color = renderer.background_color(false, false, false, false);
        assert_eq!(color, renderer.default_color);

        let color = renderer.background_color(true, false, false, false);
        assert_eq!(color, renderer.selected_color);

        let color = renderer.background_color(false, true, false, false);
        assert_eq!(color, renderer.hovered_color);

        let color = renderer.background_color(false, false, false, true);
        assert_eq!(color, renderer.focused_color);
    }

    #[test]
    fn test_docking_visual_vertex() {
        let mut v = DockingVisualVertex::new(1, "panel");
        assert!(!v.is_collapsed());
        v.toggle_collapsed();
        assert!(v.is_collapsed());
        v.toggle_collapsed();
        assert!(!v.is_collapsed());
    }

    #[test]
    fn test_vertex_shape_transformer() {
        let mut transformer = VertexShapeTransformer::new(VertexShapeType::Rectangle);
        assert_eq!(transformer.shape_for(1), VertexShapeType::Rectangle);

        transformer.set_override(1, VertexShapeType::Diamond);
        assert_eq!(transformer.shape_for(1), VertexShapeType::Diamond);
        assert_eq!(transformer.shape_for(2), VertexShapeType::Rectangle);

        transformer.remove_override(1);
        assert_eq!(transformer.shape_for(1), VertexShapeType::Rectangle);
    }

    #[test]
    fn test_vertex_shape_type_default() {
        assert_eq!(VertexShapeType::default(), VertexShapeType::RoundedRectangle);
    }
}
