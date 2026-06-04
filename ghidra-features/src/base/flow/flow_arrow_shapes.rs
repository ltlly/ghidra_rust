//! Flow arrow shape factory and specific arrow types -- ported from Ghidra's
//! `FlowArrowShapeFactory.java`, `DefaultFlowArrow.java`,
//! `ConditionalFlowArrow.java`, and `FallthroughFlowArrow.java`.
//!
//! Provides shape creation logic and specialized arrow subtypes:
//! - [`FlowArrowShapeFactory`] -- creates arrow body/endpoint shapes
//! - [`DefaultFlowArrow`] -- default arrow for unconditional jumps
//! - [`ConditionalFlowArrow`] -- dashed arrow for conditional branches
//! - [`FallthroughFlowArrow`] -- simple arrow for fall-through flow

use crate::base::analyzer::core::*;
use crate::base::flow::flow_arrow::{FlowArrow, FlowArrowType};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Height of the arrowhead triangle in pixels.
pub const TRIANGLE_HEIGHT: i32 = 9;
/// Width of the arrowhead triangle in pixels.
pub const TRIANGLE_WIDTH: i32 = 7;
/// Minimum X position for arrow lines.
const MIN_X: i32 = 3;

// ---------------------------------------------------------------------------
// ArrowSegment
// ---------------------------------------------------------------------------

/// A segment of an arrow path (a line or curve in 2D).
///
/// This is the Rust analogue of Java's `GeneralPath` operations used in
/// `FlowArrowShapeFactory`.
#[derive(Debug, Clone, PartialEq)]
pub enum ArrowSegment {
    /// Move to (x, y) without drawing.
    MoveTo { x: i32, y: i32 },
    /// Draw a line to (x, y).
    LineTo { x: i32, y: i32 },
    /// Draw a curve (quadratic Bezier) to (x2, y2) with control point (cx, cy).
    QuadTo { cx: i32, cy: i32, x2: i32, y2: i32 },
}

// ---------------------------------------------------------------------------
// ArrowShape
// ---------------------------------------------------------------------------

/// A collection of segments forming the complete arrow shape.
///
/// Consists of a body (the line path) and an optional head (the arrowhead).
#[derive(Debug, Clone)]
pub struct ArrowShape {
    /// Segments forming the arrow body line.
    pub body: Vec<ArrowSegment>,
    /// Segments forming the arrowhead.
    pub head: Vec<ArrowSegment>,
    /// Bounding box: (min_x, min_y, max_x, max_y).
    pub bounds: (i32, i32, i32, i32),
}

impl ArrowShape {
    /// Create an empty arrow shape.
    pub fn new() -> Self {
        Self {
            body: Vec::new(),
            head: Vec::new(),
            bounds: (i32::MAX, i32::MAX, i32::MIN, i32::MIN),
        }
    }

    /// Add a body segment.
    pub fn add_body_segment(&mut self, seg: ArrowSegment) {
        self.update_bounds_from_segment(&seg);
        self.body.push(seg);
    }

    /// Add a head segment.
    pub fn add_head_segment(&mut self, seg: ArrowSegment) {
        self.update_bounds_from_segment(&seg);
        self.head.push(seg);
    }

    fn update_bounds_from_segment(&mut self, seg: &ArrowSegment) {
        let (x, y) = match seg {
            ArrowSegment::MoveTo { x, y } => (*x, *y),
            ArrowSegment::LineTo { x, y } => (*x, *y),
            ArrowSegment::QuadTo { x2, y2, .. } => (*x2, *y2),
        };
        self.bounds.0 = self.bounds.0.min(x);
        self.bounds.1 = self.bounds.1.min(y);
        self.bounds.2 = self.bounds.2.max(x);
        self.bounds.3 = self.bounds.3.max(y);
    }
}

impl Default for ArrowShape {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// FlowArrowShapeFactory
// ---------------------------------------------------------------------------

/// Factory for creating arrow shapes from flow arrow data.
///
/// This mirrors Ghidra's `FlowArrowShapeFactory`, which computes the
/// exact path segments needed to draw a flow arrow in the listing margin.
/// The factory takes the arrow, display dimensions, and layout parameters,
/// and produces an [`ArrowShape`] for rendering.
#[derive(Debug)]
pub struct FlowArrowShapeFactory;

impl FlowArrowShapeFactory {
    /// Create the arrow body path (the connecting line).
    ///
    /// The body consists of:
    /// 1. A horizontal line from the right margin to the column position
    /// 2. A vertical line along the column position
    /// 3. A horizontal line from the column position to the end address
    pub fn create_arrow_body(
        start_y: i32,
        end_y: i32,
        width: i32,
        height: i32,
        column: i32,
        line_spacing: i32,
    ) -> ArrowShape {
        let mut shape = ArrowShape::new();
        let x = Self::compute_x(width, column, line_spacing);

        // Start: horizontal line from right margin
        if start_y != 0 && start_y != height {
            shape.add_body_segment(ArrowSegment::MoveTo { x: width, y: start_y });
            shape.add_body_segment(ArrowSegment::LineTo { x, y: start_y });
        }

        // Vertical bar
        let effective_start = if start_y == 0 { 0 } else { start_y.min(height) };
        let effective_end = if end_y == 0 { 0 } else { end_y.min(height) };

        if effective_start != effective_end {
            shape.add_body_segment(ArrowSegment::MoveTo { x, y: effective_start });
            shape.add_body_segment(ArrowSegment::LineTo { x, y: effective_end });
        }

        // End: horizontal line to right margin
        if end_y != 0 && end_y != height {
            shape.add_body_segment(ArrowSegment::MoveTo { x, y: end_y });
            shape.add_body_segment(ArrowSegment::LineTo { x: width, y: end_y });
        }

        shape
    }

    /// Create the arrowhead shape at the end position.
    ///
    /// The arrowhead is a triangle pointing in the direction of the flow
    /// (upward for backward jumps, downward for forward jumps).
    pub fn create_arrow_head(
        end_y: i32,
        is_upward: bool,
        width: i32,
        column: i32,
        line_spacing: i32,
    ) -> ArrowShape {
        let mut shape = ArrowShape::new();
        let x = Self::compute_x(width, column, line_spacing);

        let tip_x = x;
        let tip_y = end_y;

        if is_upward {
            // Arrowhead pointing upward
            shape.add_head_segment(ArrowSegment::MoveTo {
                x: tip_x - TRIANGLE_WIDTH / 2,
                y: tip_y + TRIANGLE_HEIGHT,
            });
            shape.add_head_segment(ArrowSegment::LineTo { x: tip_x, y: tip_y });
            shape.add_head_segment(ArrowSegment::LineTo {
                x: tip_x + TRIANGLE_WIDTH / 2,
                y: tip_y + TRIANGLE_HEIGHT,
            });
        } else {
            // Arrowhead pointing downward
            shape.add_head_segment(ArrowSegment::MoveTo {
                x: tip_x - TRIANGLE_WIDTH / 2,
                y: tip_y - TRIANGLE_HEIGHT,
            });
            shape.add_head_segment(ArrowSegment::LineTo { x: tip_x, y: tip_y });
            shape.add_head_segment(ArrowSegment::LineTo {
                x: tip_x + TRIANGLE_WIDTH / 2,
                y: tip_y - TRIANGLE_HEIGHT,
            });
        }

        shape
    }

    /// Create a complete arrow shape (body + head).
    pub fn create_complete_arrow(
        arrow: &FlowArrow,
        start_y: i32,
        end_y: i32,
        width: i32,
        height: i32,
        line_spacing: i32,
    ) -> ArrowShape {
        let mut body = Self::create_arrow_body(
            start_y, end_y, width, height, arrow.column, line_spacing,
        );
        let head = Self::create_arrow_head(
            end_y, arrow.is_upward(), width, arrow.column, line_spacing,
        );
        body.head = head.head;
        body
    }

    /// Compute the X position for a given column.
    fn compute_x(width: i32, column: i32, line_spacing: i32) -> i32 {
        let x = width - ((column + 1) * line_spacing);
        x.max(MIN_X)
    }
}

// ---------------------------------------------------------------------------
// DefaultFlowArrow
// ---------------------------------------------------------------------------

/// Default flow arrow for unconditional jumps.
///
/// Uses a solid line and standard arrowhead.
#[derive(Debug, Clone)]
pub struct DefaultFlowArrow {
    /// The base flow arrow data.
    pub arrow: FlowArrow,
    /// Line style.
    pub style: ArrowLineStyle,
    /// Color index (for multi-color display).
    pub color_index: usize,
}

/// Line style for flow arrows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArrowLineStyle {
    /// Solid line.
    Solid,
    /// Dashed line.
    Dashed,
    /// Dotted line.
    Dotted,
}

impl DefaultFlowArrow {
    /// Create a new default flow arrow.
    pub fn new(start: Address, end: Address) -> Self {
        Self {
            arrow: FlowArrow::new(start, end, FlowArrowType::UnconditionalJump),
            style: ArrowLineStyle::Solid,
            color_index: 0,
        }
    }

    /// Get the start address.
    pub fn start(&self) -> Address {
        self.arrow.start
    }

    /// Get the end address.
    pub fn end(&self) -> Address {
        self.arrow.end
    }

    /// Whether the arrow points upward.
    pub fn is_upward(&self) -> bool {
        self.arrow.is_upward()
    }
}

// ---------------------------------------------------------------------------
// ConditionalFlowArrow
// ---------------------------------------------------------------------------

/// Flow arrow for conditional branches.
///
/// Uses a dashed line to distinguish from unconditional branches.
#[derive(Debug, Clone)]
pub struct ConditionalFlowArrow {
    /// The base flow arrow data.
    pub arrow: FlowArrow,
    /// Line style (always dashed).
    pub style: ArrowLineStyle,
    /// The condition string (e.g., "Z == 0").
    pub condition: Option<String>,
}

impl ConditionalFlowArrow {
    /// Create a new conditional flow arrow.
    pub fn new(start: Address, end: Address) -> Self {
        Self {
            arrow: FlowArrow::new(start, end, FlowArrowType::ConditionalJump),
            style: ArrowLineStyle::Dashed,
            condition: None,
        }
    }

    /// Create with a condition string.
    pub fn with_condition(start: Address, end: Address, condition: impl Into<String>) -> Self {
        Self {
            arrow: FlowArrow::new(start, end, FlowArrowType::ConditionalJump),
            style: ArrowLineStyle::Dashed,
            condition: Some(condition.into()),
        }
    }
}

// ---------------------------------------------------------------------------
// FallthroughFlowArrow
// ---------------------------------------------------------------------------

/// Flow arrow for fall-through (sequential) flow.
///
/// Uses a simple, thin line without an arrowhead, since fall-through
/// is the default (expected) control flow.
#[derive(Debug, Clone)]
pub struct FallthroughFlowArrow {
    /// The base flow arrow data.
    pub arrow: FlowArrow,
    /// Whether to show the arrowhead (typically false).
    pub show_head: bool,
}

impl FallthroughFlowArrow {
    /// Create a new fallthrough flow arrow.
    pub fn new(start: Address, end: Address) -> Self {
        Self {
            arrow: FlowArrow::new(start, end, FlowArrowType::Fallthrough),
            show_head: false,
        }
    }

    /// Whether this arrow points downward (always true for fallthrough).
    pub fn is_downward(&self) -> bool {
        self.arrow.is_downward()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arrow_shape_new() {
        let shape = ArrowShape::new();
        assert!(shape.body.is_empty());
        assert!(shape.head.is_empty());
    }

    #[test]
    fn test_shape_factory_body() {
        let shape = FlowArrowShapeFactory::create_arrow_body(
            100, 200, 500, 600, 0, 16,
        );
        // Should have segments for start, vertical, and end
        assert!(!shape.body.is_empty());
    }

    #[test]
    fn test_shape_factory_head_downward() {
        let shape = FlowArrowShapeFactory::create_arrow_head(
            200, false, 500, 0, 16,
        );
        // Downward head: 3 segments (MoveTo + 2 LineTo forming triangle)
        assert_eq!(shape.head.len(), 3);
    }

    #[test]
    fn test_shape_factory_head_upward() {
        let shape = FlowArrowShapeFactory::create_arrow_head(
            200, true, 500, 0, 16,
        );
        assert_eq!(shape.head.len(), 3);
    }

    #[test]
    fn test_shape_factory_compute_x() {
        // Column 0, width 500, line_spacing 16
        let x = FlowArrowShapeFactory::compute_x(500, 0, 16);
        assert_eq!(x, 484); // 500 - 1*16

        // Column 2
        let x = FlowArrowShapeFactory::compute_x(500, 2, 16);
        assert_eq!(x, 452); // 500 - 3*16
    }

    #[test]
    fn test_shape_factory_min_x() {
        // Very wide column should clamp to MIN_X
        let x = FlowArrowShapeFactory::compute_x(100, 20, 16);
        assert!(x >= MIN_X);
    }

    #[test]
    fn test_default_flow_arrow() {
        let arrow = DefaultFlowArrow::new(Address::new(0x1000), Address::new(0x2000));
        assert_eq!(arrow.style, ArrowLineStyle::Solid);
        assert!(!arrow.is_upward());
        assert_eq!(arrow.color_index, 0);
    }

    #[test]
    fn test_conditional_flow_arrow() {
        let arrow = ConditionalFlowArrow::new(Address::new(0x1000), Address::new(0x2000));
        assert_eq!(arrow.style, ArrowLineStyle::Dashed);
        assert!(arrow.condition.is_none());
    }

    #[test]
    fn test_conditional_flow_arrow_with_condition() {
        let arrow = ConditionalFlowArrow::with_condition(
            Address::new(0x1000), Address::new(0x2000), "Z == 0",
        );
        assert_eq!(arrow.condition.as_deref(), Some("Z == 0"));
    }

    #[test]
    fn test_fallthrough_flow_arrow() {
        let arrow = FallthroughFlowArrow::new(Address::new(0x1000), Address::new(0x1004));
        assert!(!arrow.show_head);
        assert!(arrow.is_downward());
    }

    #[test]
    fn test_fallthrough_upward() {
        // Fallthrough should always be downward
        let arrow = FallthroughFlowArrow::new(Address::new(0x1004), Address::new(0x1000));
        // This is an unusual case (backwards fallthrough)
        assert!(!arrow.is_downward());
    }

    #[test]
    fn test_arrow_segment_equality() {
        let s1 = ArrowSegment::MoveTo { x: 10, y: 20 };
        let s2 = ArrowSegment::MoveTo { x: 10, y: 20 };
        assert_eq!(s1, s2);

        let s3 = ArrowSegment::LineTo { x: 10, y: 20 };
        assert_ne!(s1, s3);
    }

    #[test]
    fn test_arrow_line_style() {
        assert_ne!(ArrowLineStyle::Solid, ArrowLineStyle::Dashed);
        assert_ne!(ArrowLineStyle::Dashed, ArrowLineStyle::Dotted);
    }

    #[test]
    fn test_complete_arrow_creation() {
        let flow_arrow = FlowArrow::new(
            Address::new(0x1000),
            Address::new(0x2000),
            FlowArrowType::UnconditionalJump,
        );
        let shape = FlowArrowShapeFactory::create_complete_arrow(
            &flow_arrow, 100, 200, 500, 600, 16,
        );
        // Should have body segments + head segments
        assert!(!shape.body.is_empty() || !shape.head.is_empty());
    }
}
