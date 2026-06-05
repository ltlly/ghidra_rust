//! Extended paintable shape types for graph viewer interaction feedback.
//!
//! Ports Ghidra's mouse feedback paintable shapes:
//! - [`MouseClickedPaintableShape`] -- visual feedback for clicks.
//! - [`MouseDraggedPaintableShape`] -- visual feedback for drags.
//! - [`MouseDraggedLinePaintableShape`] -- drag line indicator.
//! - [`MouseDebugPaintable`] -- debug overlay painting.

use super::super::{Point2D, Rect2D};
use super::RenderCommand;

/// A shape that can be painted during graph interaction.
///
/// This trait provides the abstraction for transient visual elements
/// that appear during user interactions (click indicators, drag lines,
/// selection rectangles, etc.).
pub trait PaintableShape: Send + std::fmt::Debug {
    /// Generate render commands for this shape.
    fn paint(&self) -> Vec<RenderCommand>;

    /// Whether this shape should currently be visible.
    fn is_visible(&self) -> bool;

    /// Get the bounding rectangle of this shape.
    fn bounds(&self) -> Rect2D;
}

/// Visual feedback for mouse clicks.
///
/// Ports `ghidra.graph.viewer.renderer.MouseClickedPaintableShape`.
/// Shows a brief visual indicator at the click location (e.g., a circle
/// or crosshair that fades out).
#[derive(Debug, Clone)]
pub struct MouseClickedPaintableShape {
    /// The click position.
    pub position: Point2D,
    /// Radius of the click indicator.
    pub radius: f64,
    /// Color of the indicator (CSS hex).
    pub color: String,
    /// Whether the indicator is visible.
    visible: bool,
    /// Remaining frame count for the animation.
    pub frames_remaining: u32,
}

impl MouseClickedPaintableShape {
    /// Create a new click indicator at the given position.
    pub fn new(position: Point2D) -> Self {
        Self {
            position,
            radius: 8.0,
            color: "#FF6600".to_string(),
            visible: true,
            frames_remaining: 10,
        }
    }

    /// Advance the animation by one frame.
    pub fn advance_frame(&mut self) {
        if self.frames_remaining > 0 {
            self.frames_remaining -= 1;
            if self.frames_remaining == 0 {
                self.visible = false;
            }
        }
    }
}

impl PaintableShape for MouseClickedPaintableShape {
    fn paint(&self) -> Vec<RenderCommand> {
        if !self.visible {
            return Vec::new();
        }
        vec![
            RenderCommand::FillEllipse {
                cx: self.position.x,
                cy: self.position.y,
                rx: self.radius,
                ry: self.radius,
                color: self.color.clone(),
            },
        ]
    }

    fn is_visible(&self) -> bool {
        self.visible
    }

    fn bounds(&self) -> Rect2D {
        Rect2D::new(
            self.position.x - self.radius,
            self.position.y - self.radius,
            self.radius * 2.0,
            self.radius * 2.0,
        )
    }
}

/// Visual feedback for mouse drags (rectangle).
///
/// Ports `ghidra.graph.viewer.renderer.MouseDraggedPaintableShape`.
/// Shows a selection rectangle during drag operations.
#[derive(Debug, Clone)]
pub struct MouseDraggedPaintableShape {
    /// Start point of the drag.
    pub start: Point2D,
    /// Current end point of the drag.
    pub end: Point2D,
    /// Rectangle fill color.
    pub fill_color: String,
    /// Rectangle border color.
    pub border_color: String,
    /// Whether the shape is visible.
    visible: bool,
}

impl MouseDraggedPaintableShape {
    /// Create a new drag rectangle.
    pub fn new(start: Point2D) -> Self {
        Self {
            start,
            end: start,
            fill_color: "#BBDDFF40".to_string(),
            border_color: "#4488CC".to_string(),
            visible: true,
        }
    }

    /// Update the end point.
    pub fn update(&mut self, end: Point2D) {
        self.end = end;
    }

    /// Get the computed rectangle.
    pub fn rectangle(&self) -> Rect2D {
        let x = self.start.x.min(self.end.x);
        let y = self.start.y.min(self.end.y);
        let w = (self.end.x - self.start.x).abs();
        let h = (self.end.y - self.start.y).abs();
        Rect2D::new(x, y, w, h)
    }
}

impl PaintableShape for MouseDraggedPaintableShape {
    fn paint(&self) -> Vec<RenderCommand> {
        if !self.visible {
            return Vec::new();
        }
        let rect = self.rectangle();
        vec![
            RenderCommand::FillRect {
                rect,
                color: self.fill_color.clone(),
                corner_radius: 0.0,
            },
            RenderCommand::StrokeRect {
                rect,
                color: self.border_color.clone(),
                line_width: 1.0,
            },
        ]
    }

    fn is_visible(&self) -> bool {
        self.visible
    }

    fn bounds(&self) -> Rect2D {
        self.rectangle()
    }
}

/// Visual feedback for drag line.
///
/// Ports `ghidra.graph.viewer.renderer.MouseDraggedLinePaintableShape`.
/// Draws a line from the start to the current mouse position during
/// an edge-drag interaction.
#[derive(Debug, Clone)]
pub struct MouseDraggedLinePaintableShape {
    /// Start point of the line.
    pub start: Point2D,
    /// Current end point.
    pub end: Point2D,
    /// Line color.
    pub color: String,
    /// Line width.
    pub line_width: f32,
    /// Whether the line is visible.
    visible: bool,
}

impl MouseDraggedLinePaintableShape {
    /// Create a new drag line.
    pub fn new(start: Point2D) -> Self {
        Self {
            start,
            end: start,
            color: "#888888".to_string(),
            line_width: 1.5,
            visible: true,
        }
    }

    /// Update the end point.
    pub fn update(&mut self, end: Point2D) {
        self.end = end;
    }
}

impl PaintableShape for MouseDraggedLinePaintableShape {
    fn paint(&self) -> Vec<RenderCommand> {
        if !self.visible {
            return Vec::new();
        }
        vec![RenderCommand::DrawLine {
            x1: self.start.x,
            y1: self.start.y,
            x2: self.end.x,
            y2: self.end.y,
            color: self.color.clone(),
            line_width: self.line_width,
        }]
    }

    fn is_visible(&self) -> bool {
        self.visible
    }

    fn bounds(&self) -> Rect2D {
        let x = self.start.x.min(self.end.x);
        let y = self.start.y.min(self.end.y);
        let w = (self.end.x - self.start.x).abs();
        let h = (self.end.y - self.start.y).abs();
        Rect2D::new(x, y, w, h)
    }
}

/// Debug overlay paintable for development.
///
/// Ports `ghidra.graph.viewer.renderer.MouseDebugPaintable`.
/// Provides debug visualization for graph layout and rendering.
#[derive(Debug, Clone, Default)]
pub struct MouseDebugPaintable {
    /// Debug rectangles to draw.
    pub rects: Vec<(Rect2D, String)>,
    /// Debug points to draw.
    pub points: Vec<(Point2D, String)>,
    /// Debug text labels.
    pub labels: Vec<(String, Point2D)>,
    /// Whether the debug overlay is visible.
    pub visible: bool,
}

impl MouseDebugPaintable {
    /// Create a new debug paintable.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a debug rectangle.
    pub fn add_rect(&mut self, rect: Rect2D, color: impl Into<String>) {
        self.rects.push((rect, color.into()));
    }

    /// Add a debug point.
    pub fn add_point(&mut self, point: Point2D, color: impl Into<String>) {
        self.points.push((point, color.into()));
    }

    /// Add a debug label.
    pub fn add_label(&mut self, text: impl Into<String>, position: Point2D) {
        self.labels.push((text.into(), position));
    }

    /// Clear all debug elements.
    pub fn clear(&mut self) {
        self.rects.clear();
        self.points.clear();
        self.labels.clear();
    }
}

impl PaintableShape for MouseDebugPaintable {
    fn paint(&self) -> Vec<RenderCommand> {
        if !self.visible {
            return Vec::new();
        }
        let mut commands = Vec::new();
        for (rect, color) in &self.rects {
            commands.push(RenderCommand::StrokeRect {
                rect: *rect,
                color: color.clone(),
                line_width: 1.0,
            });
        }
        for (point, color) in &self.points {
            commands.push(RenderCommand::FillEllipse {
                cx: point.x,
                cy: point.y,
                rx: 3.0,
                ry: 3.0,
                color: color.clone(),
            });
        }
        for (text, pos) in &self.labels {
            commands.push(RenderCommand::DrawText {
                text: text.clone(),
                x: pos.x,
                y: pos.y,
                font_size: 9.0,
                color: "#333333".to_string(),
            });
        }
        commands
    }

    fn is_visible(&self) -> bool {
        self.visible
    }

    fn bounds(&self) -> Rect2D {
        Rect2D::new(0.0, 0.0, 0.0, 0.0)
    }
}

/// Grid painter for debug visualization of layout grids.
///
/// Ports `ghidra.graph.viewer.renderer.GridPainter` from the renderer package.
#[derive(Debug, Clone, Default)]
pub struct DebugGridPainter {
    /// Whether the grid is visible.
    pub visible: bool,
    /// Grid line color.
    pub line_color: String,
    /// Grid cell dimensions.
    pub cell_width: f64,
    /// Grid cell height.
    pub cell_height: f64,
}

impl DebugGridPainter {
    /// Create a new debug grid painter.
    pub fn new() -> Self {
        Self {
            visible: false,
            line_color: "#DDDDDD".to_string(),
            cell_width: 100.0,
            cell_height: 50.0,
        }
    }

    /// Paint grid lines for a given viewport.
    pub fn paint(&self, viewport: Rect2D) -> Vec<RenderCommand> {
        if !self.visible {
            return Vec::new();
        }
        let mut commands = Vec::new();
        let mut x = viewport.x;
        while x <= viewport.x + viewport.width {
            commands.push(RenderCommand::DrawLine {
                x1: x,
                y1: viewport.y,
                x2: x,
                y2: viewport.y + viewport.height,
                color: self.line_color.clone(),
                line_width: 0.5,
            });
            x += self.cell_width;
        }
        let mut y = viewport.y;
        while y <= viewport.y + viewport.height {
            commands.push(RenderCommand::DrawLine {
                x1: viewport.x,
                y1: y,
                x2: viewport.x + viewport.width,
                y2: y,
                color: self.line_color.clone(),
                line_width: 0.5,
            });
            y += self.cell_height;
        }
        commands
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clicked_paintable_initial_state() {
        let shape = MouseClickedPaintableShape::new(Point2D::new(50.0, 50.0));
        assert!(shape.is_visible());
        assert_eq!(shape.frames_remaining, 10);
    }

    #[test]
    fn clicked_paintable_fade_out() {
        let mut shape = MouseClickedPaintableShape::new(Point2D::new(50.0, 50.0));
        for _ in 0..10 {
            shape.advance_frame();
        }
        assert!(!shape.is_visible());
    }

    #[test]
    fn dragged_rectangle_computed() {
        let mut shape = MouseDraggedPaintableShape::new(Point2D::new(10.0, 10.0));
        shape.update(Point2D::new(110.0, 60.0));
        let rect = shape.rectangle();
        assert_eq!(rect.x, 10.0);
        assert_eq!(rect.y, 10.0);
        assert_eq!(rect.width, 100.0);
        assert_eq!(rect.height, 50.0);
    }

    #[test]
    fn dragged_line_paintable() {
        let mut shape = MouseDraggedLinePaintableShape::new(Point2D::new(0.0, 0.0));
        shape.update(Point2D::new(100.0, 100.0));
        let commands = shape.paint();
        assert_eq!(commands.len(), 1);
    }

    #[test]
    fn debug_paintable_add_elements() {
        let mut paintable = MouseDebugPaintable::new();
        paintable.visible = true;
        paintable.add_rect(Rect2D::new(0.0, 0.0, 10.0, 10.0), "#FF0000");
        paintable.add_point(Point2D::new(5.0, 5.0), "#00FF00");
        paintable.add_label("debug", Point2D::new(0.0, 0.0));
        let commands = paintable.paint();
        assert_eq!(commands.len(), 3);
    }

    #[test]
    fn debug_paintable_invisible() {
        let mut paintable = MouseDebugPaintable::new();
        paintable.visible = false;
        paintable.add_rect(Rect2D::new(0.0, 0.0, 10.0, 10.0), "#FF0000");
        let commands = paintable.paint();
        assert!(commands.is_empty());
    }

    #[test]
    fn debug_grid_painter() {
        let mut painter = DebugGridPainter::new();
        painter.visible = true;
        painter.cell_width = 50.0;
        painter.cell_height = 50.0;
        let commands = painter.paint(Rect2D::new(0.0, 0.0, 100.0, 100.0));
        assert!(!commands.is_empty());
    }
}
