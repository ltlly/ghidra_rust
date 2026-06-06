//! Visual graph rendering helpers.
//!
//! Ports Ghidra's `ghidra.graph.viewer.renderer` package.  Provides
//! paintable shapes, grid painting, debug overlays, and renderer
//! coordination for the graph viewer.

use super::visual_types::{Point2d, Rect2d, RgbaColor};

// ============================================================================
// PaintableShape -- a shape that can be drawn on the graph canvas
// ============================================================================

/// Trait for shapes that can be rendered on the graph canvas.
///
/// Ports `ghidra.graph.viewer.renderer.PaintableShape`.
pub trait PaintableShape: std::fmt::Debug + Send + Sync {
    /// Get the bounding rectangle of this shape.
    fn bounds(&self) -> Rect2d;

    /// Get the fill color.
    fn fill_color(&self) -> Option<RgbaColor>;

    /// Get the stroke (border) color.
    fn stroke_color(&self) -> Option<RgbaColor>;

    /// Get the stroke width.
    fn stroke_width(&self) -> f32;

    /// Whether this shape is visible.
    fn is_visible(&self) -> bool {
        true
    }
}

/// A rectangle that can be painted on the graph.
///
/// Ports `ghidra.graph.viewer.renderer.MouseClickedPaintableShape`.
#[derive(Debug, Clone)]
pub struct PaintableRect {
    /// The rectangle to paint.
    pub rect: Rect2d,
    /// Fill color.
    pub fill: Option<RgbaColor>,
    /// Border color.
    pub stroke: Option<RgbaColor>,
    /// Border width.
    pub width: f32,
    /// Visibility.
    pub visible: bool,
}

impl PaintableRect {
    /// Create a new paintable rectangle.
    pub fn new(rect: Rect2d) -> Self {
        Self {
            rect,
            fill: Some(RgbaColor::new(50, 100, 200, 100)),
            stroke: Some(RgbaColor::new(50, 100, 200, 200)),
            width: 1.5,
            visible: true,
        }
    }
}

impl PaintableShape for PaintableRect {
    fn bounds(&self) -> Rect2d {
        self.rect
    }
    fn fill_color(&self) -> Option<RgbaColor> {
        self.fill
    }
    fn stroke_color(&self) -> Option<RgbaColor> {
        self.stroke
    }
    fn stroke_width(&self) -> f32 {
        self.width
    }
    fn is_visible(&self) -> bool {
        self.visible
    }
}

/// A line segment that can be painted on the graph.
///
/// Ports `ghidra.graph.viewer.renderer.MouseDraggedLinePaintableShape`.
#[derive(Debug, Clone)]
pub struct PaintableLine {
    /// Start point.
    pub start: Point2d,
    /// End point.
    pub end: Point2d,
    /// Line color.
    pub color: RgbaColor,
    /// Line width.
    pub width: f32,
    /// Visibility.
    pub visible: bool,
}

impl PaintableLine {
    /// Create a new paintable line.
    pub fn new(start: Point2d, end: Point2d) -> Self {
        Self {
            start,
            end,
            color: RgbaColor::new(200, 200, 200, 200),
            width: 1.0,
            visible: true,
        }
    }

    /// Get the bounding rectangle of this line.
    pub fn rect(&self) -> Rect2d {
        let min_x = self.start.x.min(self.end.x);
        let min_y = self.start.y.min(self.end.y);
        let w = (self.start.x - self.end.x).abs();
        let h = (self.start.y - self.end.y).abs();
        Rect2d::new(min_x, min_y, w, h)
    }
}

// ============================================================================
// GridPainter -- renders the background grid
// ============================================================================

/// Renders a background grid for the graph canvas.
///
/// Ports `ghidra.graph.viewer.renderer.GridPainter`.
#[derive(Debug, Clone)]
pub struct GridPainter {
    /// Whether the grid is visible.
    pub visible: bool,
    /// Grid spacing in pixels.
    pub spacing: f64,
    /// Grid line color.
    pub color: RgbaColor,
    /// Grid line width.
    pub line_width: f32,
    /// Whether to draw major grid lines.
    pub show_major: bool,
    /// Major grid line interval (e.g., every 5th line).
    pub major_interval: u32,
    /// Major grid line color.
    pub major_color: RgbaColor,
}

impl Default for GridPainter {
    fn default() -> Self {
        Self {
            visible: false,
            spacing: 50.0,
            color: RgbaColor::new(40, 40, 40, 100),
            line_width: 0.5,
            show_major: true,
            major_interval: 5,
            major_color: RgbaColor::new(60, 60, 60, 150),
        }
    }
}

impl GridPainter {
    /// Create a new grid painter.
    pub fn new() -> Self {
        Self::default()
    }

    /// Compute the grid lines visible within a viewport.
    pub fn visible_lines(&self, viewport: Rect2d) -> (Vec<f64>, Vec<f64>) {
        if !self.visible {
            return (Vec::new(), Vec::new());
        }

        let mut vertical = Vec::new();
        let mut horizontal = Vec::new();

        let mut x = (viewport.x / self.spacing).floor() * self.spacing;
        while x <= viewport.x + viewport.width {
            vertical.push(x);
            x += self.spacing;
        }

        let mut y = (viewport.y / self.spacing).floor() * self.spacing;
        while y <= viewport.y + viewport.height {
            horizontal.push(y);
            y += self.spacing;
        }

        (vertical, horizontal)
    }
}

// ============================================================================
// DebugShape -- debug visualization overlay
// ============================================================================

/// A shape used for debug visualization of layout and routing algorithms.
///
/// Ports `ghidra.graph.viewer.renderer.DebugShape`.
#[derive(Debug, Clone)]
pub struct DebugShape {
    /// Label for this debug shape.
    pub label: String,
    /// The rectangle to highlight.
    pub rect: Rect2d,
    /// Color of the debug shape.
    pub color: RgbaColor,
    /// Whether this debug shape is visible.
    pub visible: bool,
}

impl DebugShape {
    /// Create a new debug shape.
    pub fn new(label: impl Into<String>, rect: Rect2d, color: RgbaColor) -> Self {
        Self {
            label: label.into(),
            rect,
            color,
            visible: true,
        }
    }
}

// ============================================================================
// VisualVertexSatelliteRenderer -- renders vertices in the satellite view
// ============================================================================

/// Renderer for vertices in the satellite (overview) view.
///
/// Ports `ghidra.graph.viewer.renderer.VisualVertexSatelliteRenderer`.
#[derive(Debug, Clone)]
pub struct SatelliteVertexRenderer {
    /// Default vertex color in satellite view.
    pub color: RgbaColor,
    /// Selected vertex color.
    pub selected_color: RgbaColor,
    /// Vertex dot size in satellite view.
    pub dot_size: f64,
}

impl Default for SatelliteVertexRenderer {
    fn default() -> Self {
        Self {
            color: RgbaColor::new(100, 100, 100, 200),
            selected_color: RgbaColor::new(50, 120, 255, 255),
            dot_size: 4.0,
        }
    }
}

/// Renderer for edges in the satellite view.
///
/// Ports `ghidra.graph.viewer.renderer.VisualGraphEdgeSatelliteRenderer` and
/// `ghidra.graph.viewer.edge.VisualGraphEdgeSatelliteRenderer`.
#[derive(Debug, Clone)]
pub struct SatelliteEdgeRenderer {
    /// Edge line color.
    pub color: RgbaColor,
    /// Edge line width.
    pub width: f32,
}

impl Default for SatelliteEdgeRenderer {
    fn default() -> Self {
        Self {
            color: RgbaColor::new(80, 80, 80, 150),
            width: 0.5,
        }
    }
}

// ============================================================================
// Edge label renderer
// ============================================================================

/// Renderer for edge labels.
///
/// Ports `ghidra.graph.viewer.renderer.VisualGraphEdgeLabelRenderer`.
#[derive(Debug, Clone)]
pub struct VisualEdgeLabelRenderer {
    /// Font size in pixels.
    pub font_size: f32,
    /// Text color.
    pub text_color: RgbaColor,
    /// Background color.
    pub background_color: RgbaColor,
}

impl Default for VisualEdgeLabelRenderer {
    fn default() -> Self {
        Self {
            font_size: 10.0,
            text_color: RgbaColor::new(200, 200, 200, 255),
            background_color: RgbaColor::new(30, 30, 30, 200),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_paintable_rect() {
        let rect = PaintableRect::new(Rect2d::new(10.0, 20.0, 100.0, 50.0));
        assert!(rect.is_visible());
        assert_eq!(rect.bounds().width, 100.0);
    }

    #[test]
    fn test_paintable_line() {
        let line = PaintableLine::new(Point2d::new(0.0, 0.0), Point2d::new(100.0, 50.0));
        let r = line.rect();
        assert_eq!(r.width, 100.0);
        assert_eq!(r.height, 50.0);
    }

    #[test]
    fn test_grid_painter() {
        let mut painter = GridPainter::new();
        assert!(!painter.visible);
        painter.visible = true;

        let (vertical, horizontal) = painter.visible_lines(Rect2d::new(0.0, 0.0, 200.0, 150.0));
        assert_eq!(vertical.len(), 5); // 0, 50, 100, 150, 200
        assert_eq!(horizontal.len(), 4); // 0, 50, 100, 150
    }

    #[test]
    fn test_grid_painter_offset_viewport() {
        let mut painter = GridPainter::new();
        painter.visible = true;
        painter.spacing = 25.0;

        let (vertical, horizontal) = painter.visible_lines(Rect2d::new(10.0, 10.0, 50.0, 50.0));
        assert!(!vertical.is_empty());
        assert!(!horizontal.is_empty());
    }

    #[test]
    fn test_debug_shape() {
        let shape = DebugShape::new(
            "test",
            Rect2d::new(0.0, 0.0, 10.0, 10.0),
            RgbaColor::new(255, 0, 0, 255),
        );
        assert!(shape.visible);
        assert_eq!(shape.label, "test");
    }

    #[test]
    fn test_satellite_renderers() {
        let vr = SatelliteVertexRenderer::default();
        assert_eq!(vr.dot_size, 4.0);

        let er = SatelliteEdgeRenderer::default();
        assert_eq!(er.width, 0.5);
    }
}
