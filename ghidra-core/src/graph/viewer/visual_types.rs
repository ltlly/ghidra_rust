//! Visual graph types -- port of Ghidra's `ghidra.graph.viewer` interfaces.
//!
//! Provides traits for vertices, edges, layouts, and renderers that have
//! UI state (selection, hover, emphasis, alpha, articulation points).

use std::collections::HashMap;

// ============================================================================
// Point2D (lightweight 2D point, no AWT dependency)
// ============================================================================

/// A 2D point with f64 coordinates.  Replaces `java.awt.geom.Point2D`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Point2d {
    /// X coordinate.
    pub x: f64,
    /// Y coordinate.
    pub y: f64,
}

impl Point2d {
    /// Create a new point.
    pub fn new(x: f64, y: f64) -> Self {
        Self { x, y }
    }

    /// Distance to another point.
    pub fn distance(&self, other: &Point2d) -> f64 {
        ((self.x - other.x).powi(2) + (self.y - other.y).powi(2)).sqrt()
    }

    /// Translate by (dx, dy).
    pub fn translate(&self, dx: f64, dy: f64) -> Self {
        Self {
            x: self.x + dx,
            y: self.y + dy,
        }
    }
}

impl Default for Point2d {
    fn default() -> Self {
        Self { x: 0.0, y: 0.0 }
    }
}

// ============================================================================
// Rectangle
// ============================================================================

/// A 2D rectangle with f64 coordinates.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Rect2d {
    /// X coordinate of the top-left corner.
    pub x: f64,
    /// Y coordinate of the top-left corner.
    pub y: f64,
    /// Width.
    pub width: f64,
    /// Height.
    pub height: f64,
}

impl Rect2d {
    /// Create a new rectangle.
    pub fn new(x: f64, y: f64, width: f64, height: f64) -> Self {
        Self { x, y, width, height }
    }

    /// Create from center point and dimensions.
    pub fn from_center(center: Point2d, width: f64, height: f64) -> Self {
        Self {
            x: center.x - width / 2.0,
            y: center.y - height / 2.0,
            width,
            height,
        }
    }

    /// Get the center point.
    pub fn center(&self) -> Point2d {
        Point2d::new(self.x + self.width / 2.0, self.y + self.height / 2.0)
    }

    /// Check if a point is inside this rectangle.
    pub fn contains(&self, p: &Point2d) -> bool {
        p.x >= self.x
            && p.x <= self.x + self.width
            && p.y >= self.y
            && p.y <= self.y + self.height
    }

    /// Get the right edge (x + width).
    pub fn max_x(&self) -> f64 {
        self.x + self.width
    }

    /// Get the bottom edge (y + height).
    pub fn max_y(&self) -> f64 {
        self.y + self.height
    }
}

impl Default for Rect2d {
    fn default() -> Self {
        Self { x: 0.0, y: 0.0, width: 0.0, height: 0.0 }
    }
}

// ============================================================================
// VisualVertex trait
// ============================================================================

/// A vertex with UI state.
///
/// Port of Ghidra's `ghidra.graph.viewer.VisualVertex` interface.
/// Vertices can be focused, selected, hovered, emphasized, and have an
/// alpha value for animation transitions.
pub trait VisualVertex {
    /// Set focus state.  Focus differs from selection in that exactly one
    /// vertex can be focused (for keyboard navigation).
    fn set_focused(&mut self, focused: bool);

    /// Whether this vertex is focused.
    fn is_focused(&self) -> bool;

    /// Set selection state.
    fn set_selected(&mut self, selected: bool);

    /// Whether this vertex is selected.
    fn is_selected(&self) -> bool;

    /// Set hover state.
    fn set_hovered(&mut self, hovered: bool);

    /// Whether this vertex is hovered by the mouse.
    fn is_hovered(&self) -> bool;

    /// Set the location of this vertex in view space.
    fn set_location(&mut self, p: Point2d);

    /// Get the location of this vertex in view space.
    fn get_location(&self) -> Point2d;

    /// Get the bounding rectangle of this vertex.
    fn get_bounds(&self) -> Rect2d;

    /// Dispose of resources when this vertex is no longer needed.
    fn dispose(&mut self);

    // -- Rendering properties --

    /// Set the emphasis level (0.0 = no emphasis).
    fn set_emphasis(&mut self, level: f64);

    /// Get the emphasis level.
    fn get_emphasis(&self) -> f64;

    /// Set the alpha (transparency) for animation transitions.
    /// 0.0 = fully transparent, 1.0 = fully opaque.
    fn set_alpha(&mut self, alpha: f64);

    /// Get the alpha value.
    fn get_alpha(&self) -> f64;
}

// ============================================================================
// VisualEdge trait
// ============================================================================

/// An edge with UI state.
///
/// Port of Ghidra's `ghidra.graph.viewer.VisualEdge` interface.
/// Edges can be selected, emphasized, and have articulation points for
/// curved routing.
pub trait VisualEdge<V: VisualVertex> {
    /// Set selection state.
    fn set_selected(&mut self, selected: bool);

    /// Whether this edge is selected.
    fn is_selected(&self) -> bool;

    /// Set whether this edge is part of the active path.
    fn set_in_active_path(&mut self, in_path: bool);

    /// Whether this edge is part of the active path.
    fn is_in_active_path(&self) -> bool;

    /// Get the start vertex.
    fn get_start(&self) -> &V;

    /// Get the end vertex.
    fn get_end(&self) -> &V;

    // -- Rendering properties --

    /// Set the emphasis level (0.0 = no emphasis).
    fn set_emphasis(&mut self, level: f64);

    /// Get the emphasis level.
    fn get_emphasis(&self) -> f64;

    /// Set the alpha (transparency).
    fn set_alpha(&mut self, alpha: f64);

    /// Get the alpha value.
    fn get_alpha(&self) -> f64;

    /// Set articulation points for curved edge routing.
    fn set_articulation_points(&mut self, points: Vec<Point2d>);

    /// Get the articulation points.
    fn get_articulation_points(&self) -> &[Point2d];
}

// ============================================================================
// VisualEdgeRenderer trait
// ============================================================================

/// Rendering hints for edges.
///
/// Port of Ghidra's `VisualEdgeRenderer` interface.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum EdgeRenderingStyle {
    /// Default solid line.
    Solid,
    /// Dashed line (for inactive/unfocused edges).
    Dashed,
    /// Thick line (for emphasized edges).
    Thick,
    /// Custom line width.
    Custom(f64),
}

impl Default for EdgeRenderingStyle {
    fn default() -> Self {
        Self::Solid
    }
}

/// Color stored as RGBA u8 values (no AWT dependency).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RgbaColor {
    /// Red component.
    pub r: u8,
    /// Green component.
    pub g: u8,
    /// Blue component.
    pub b: u8,
    /// Alpha component.
    pub a: u8,
}

impl RgbaColor {
    /// Create a new RGBA color.
    pub const fn new(r: u8, g: u8, b: u8, a: u8) -> Self {
        Self { r, g, b, a }
    }

    /// Create from RGB with full opacity.
    pub const fn rgb(r: u8, g: u8, b: u8) -> Self {
        Self { r, g, b, a: 255 }
    }

    /// Black.
    pub const BLACK: Self = Self::new(0, 0, 0, 255);
    /// White.
    pub const WHITE: Self = Self::new(255, 255, 255, 255);
    /// Red.
    pub const RED: Self = Self::new(255, 0, 0, 255);
    /// Green.
    pub const GREEN: Self = Self::new(0, 255, 0, 255);
    /// Blue.
    pub const BLUE: Self = Self::new(0, 0, 255, 255);
    /// Gray.
    pub const GRAY: Self = Self::new(128, 128, 128, 255);
    /// Light gray.
    pub const LIGHT_GRAY: Self = Self::new(192, 192, 192, 255);
    /// Cyan.
    pub const CYAN: Self = Self::new(0, 255, 255, 255);

    /// Convert to hex string (#RRGGBB or #RRGGBBAA).
    pub fn to_hex(&self) -> String {
        if self.a == 255 {
            format!("#{:02x}{:02x}{:02x}", self.r, self.g, self.b)
        } else {
            format!(
                "#{:02x}{:02x}{:02x}{:02x}",
                self.r, self.g, self.b, self.a
            )
        }
    }

    /// Parse from hex string (#RGB, #RRGGBB, or #RRGGBBAA).
    pub fn from_hex(hex: &str) -> Option<Self> {
        let hex = hex.trim_start_matches('#');
        match hex.len() {
            3 => {
                let r = u8::from_str_radix(&hex[0..1], 16).ok()?;
                let g = u8::from_str_radix(&hex[1..2], 16).ok()?;
                let b = u8::from_str_radix(&hex[2..3], 16).ok()?;
                Some(Self::rgb(r * 17, g * 17, b * 17))
            }
            6 => {
                let r = u8::from_str_radix(&hex[0..2], 16).ok()?;
                let g = u8::from_str_radix(&hex[2..4], 16).ok()?;
                let b = u8::from_str_radix(&hex[4..6], 16).ok()?;
                Some(Self::rgb(r, g, b))
            }
            8 => {
                let r = u8::from_str_radix(&hex[0..2], 16).ok()?;
                let g = u8::from_str_radix(&hex[2..4], 16).ok()?;
                let b = u8::from_str_radix(&hex[4..6], 16).ok()?;
                let a = u8::from_str_radix(&hex[6..8], 16).ok()?;
                Some(Self::new(r, g, b, a))
            }
            _ => None,
        }
    }

    /// Interpolate between two colors.
    pub fn lerp(&self, other: &RgbaColor, t: f64) -> Self {
        let t = t.clamp(0.0, 1.0);
        Self {
            r: (self.r as f64 + (other.r as f64 - self.r as f64) * t) as u8,
            g: (self.g as f64 + (other.g as f64 - self.g as f64) * t) as u8,
            b: (self.b as f64 + (other.b as f64 - self.b as f64) * t) as u8,
            a: (self.a as f64 + (other.a as f64 - self.a as f64) * t) as u8,
        }
    }
}

impl Default for RgbaColor {
    fn default() -> Self {
        Self::BLACK
    }
}

impl std::fmt::Display for RgbaColor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// Renderer configuration for a visual edge.
#[derive(Debug, Clone, Default)]
pub struct EdgeRendererConfig {
    /// The rendering style.
    pub style: EdgeRenderingStyle,
    /// The edge color.
    pub color: RgbaColor,
    /// The selected edge color.
    pub selected_color: Option<RgbaColor>,
    /// The emphasis color.
    pub emphasis_color: Option<RgbaColor>,
}

/// Trait for edge rendering customization.
pub trait VisualEdgeRenderer {
    /// Get the renderer config.
    fn config(&self) -> &EdgeRendererConfig;

    /// Get the renderer config mutably.
    fn config_mut(&mut self) -> &mut EdgeRendererConfig;
}

// ============================================================================
// VisualVertexRenderer trait
// ============================================================================

/// Renderer configuration for a visual vertex.
#[derive(Debug, Clone, Default)]
pub struct VertexRendererConfig {
    /// The default background color.
    pub background_color: RgbaColor,
    /// The selected background color.
    pub selected_color: Option<RgbaColor>,
    /// The focused border color.
    pub focused_border_color: Option<RgbaColor>,
    /// The emphasis color.
    pub emphasis_color: Option<RgbaColor>,
    /// The border width.
    pub border_width: f64,
    /// Whether to show a shadow.
    pub show_shadow: bool,
}

/// Trait for vertex rendering customization.
pub trait VisualVertexRenderer {
    /// Get the renderer config.
    fn config(&self) -> &VertexRendererConfig;

    /// Get the renderer config mutably.
    fn config_mut(&mut self) -> &mut VertexRendererConfig;
}

// ============================================================================
// VisualGraphLayout trait
// ============================================================================

/// Type of layout change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LayoutChangeType {
    /// The layout was fully recalculated.
    FullRelayout,
    /// A single vertex was moved.
    VertexMoved,
    /// The layout was reset to default.
    Reset,
}

/// Listener for layout changes.
pub trait LayoutListener {
    /// Called when the layout changes.
    fn layout_changed(&mut self, change_type: LayoutChangeType);
}

/// A layout for a visual graph.
///
/// Port of Ghidra's `VisualGraphLayout` interface.
pub trait VisualGraphLayout<V: VisualVertex> {
    /// Set the location for a vertex.
    fn set_location(&mut self, vertex_id: usize, location: Point2d);

    /// Get the location for a vertex.
    fn get_location(&self, vertex_id: usize) -> Option<Point2d>;

    /// Get all vertex locations.
    fn get_locations(&self) -> HashMap<usize, Point2d>;

    /// Set all vertex locations at once.
    fn set_locations(&mut self, locations: HashMap<usize, Point2d>);

    /// Get the bounding rectangle of all vertices.
    fn get_bounds(&self) -> Rect2d;

    /// Perform a full layout recalculation.
    fn relayout(&mut self);

    /// Get the algorithm name.
    fn algorithm_name(&self) -> &str;

    /// Add a layout listener.
    fn add_listener(&mut self, listener: Box<dyn LayoutListener>);

    /// Remove all listeners.
    fn clear_listeners(&mut self);
}

// ============================================================================
// GraphNavigator
// ============================================================================

/// Direction for graph navigation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GraphDirection {
    /// Navigate from parents to children (downstream).
    TopDown,
    /// Navigate from children to parents (upstream).
    BottomUp,
}

impl Default for GraphDirection {
    fn default() -> Self {
        Self::TopDown
    }
}

impl GraphDirection {
    /// Whether this is top-down.
    pub fn is_top_down(&self) -> bool {
        *self == Self::TopDown
    }

    /// Flip the direction.
    pub fn flip(&self) -> Self {
        match self {
            Self::TopDown => Self::BottomUp,
            Self::BottomUp => Self::TopDown,
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_point2d_distance() {
        let a = Point2d::new(0.0, 0.0);
        let b = Point2d::new(3.0, 4.0);
        assert!((a.distance(&b) - 5.0).abs() < 1e-10);
    }

    #[test]
    fn test_point2d_translate() {
        let p = Point2d::new(1.0, 2.0);
        let q = p.translate(3.0, 4.0);
        assert_eq!(q, Point2d::new(4.0, 6.0));
    }

    #[test]
    fn test_rect2d_contains() {
        let r = Rect2d::new(0.0, 0.0, 10.0, 10.0);
        assert!(r.contains(&Point2d::new(5.0, 5.0)));
        assert!(!r.contains(&Point2d::new(15.0, 5.0)));
    }

    #[test]
    fn test_rect2d_center() {
        let r = Rect2d::new(0.0, 0.0, 10.0, 10.0);
        assert_eq!(r.center(), Point2d::new(5.0, 5.0));
    }

    #[test]
    fn test_rgba_color_hex_roundtrip() {
        let c = RgbaColor::rgb(0xAA, 0xBB, 0xCC);
        let hex = c.to_hex();
        let parsed = RgbaColor::from_hex(&hex).unwrap();
        assert_eq!(c, parsed);
    }

    #[test]
    fn test_rgba_color_from_hex_3() {
        let c = RgbaColor::from_hex("#ABC").unwrap();
        assert_eq!(c, RgbaColor::rgb(0xAA, 0xBB, 0xCC));
    }

    #[test]
    fn test_rgba_color_from_hex_6() {
        let c = RgbaColor::from_hex("#FF0000").unwrap();
        assert_eq!(c, RgbaColor::RED);
    }

    #[test]
    fn test_rgba_color_from_hex_8() {
        let c = RgbaColor::from_hex("#FF000080").unwrap();
        assert_eq!(c, RgbaColor::new(255, 0, 0, 128));
    }

    #[test]
    fn test_rgba_color_lerp() {
        let a = RgbaColor::BLACK;
        let b = RgbaColor::WHITE;
        let mid = a.lerp(&b, 0.5);
        // (0 + 255) / 2 = 127.5, truncated to 127 by as u8
        assert!(mid.r >= 126 && mid.r <= 128);
        assert!(mid.g >= 126 && mid.g <= 128);
        assert!(mid.b >= 126 && mid.b <= 128);
        assert_eq!(mid.a, 255);
    }

    #[test]
    fn test_rgba_color_constants() {
        assert_eq!(RgbaColor::BLACK.to_hex(), "#000000");
        assert_eq!(RgbaColor::WHITE.to_hex(), "#ffffff");
        assert_eq!(RgbaColor::RED.to_hex(), "#ff0000");
        assert_eq!(RgbaColor::GREEN.to_hex(), "#00ff00");
        assert_eq!(RgbaColor::BLUE.to_hex(), "#0000ff");
    }

    #[test]
    fn test_edge_rendering_style_default() {
        assert_eq!(EdgeRenderingStyle::default(), EdgeRenderingStyle::Solid);
    }

    #[test]
    fn test_graph_direction_flip() {
        assert_eq!(GraphDirection::TopDown.flip(), GraphDirection::BottomUp);
        assert_eq!(GraphDirection::BottomUp.flip(), GraphDirection::TopDown);
    }

    #[test]
    fn test_layout_change_type() {
        assert_ne!(LayoutChangeType::FullRelayout, LayoutChangeType::VertexMoved);
    }
}
