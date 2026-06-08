//! Flow Arrow -- render flow arrows in the listing margin.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.flowarrow` Java package
//! (8 source files: FlowArrow, ConditionalFlowArrow, DefaultFlowArrow,
//! FallthroughFlowArrow, FlowArrowShapeFactory, FlowArrowPlugin,
//! FlowArrowMarginProvider, FlowArrowPanel).
//!
//! # Architecture
//!
//! - [`FlowArrowType`] -- kind of control flow reference type.
//! - [`FlowArrow`] -- a single arrow with geometry, hit testing, and rendering state.
//! - [`FlowArrowShapeFactory`] -- computes arrow body path and head triangle geometry.
//! - [`FlowArrowModel`] -- manages a collection of arrows for a listing view.
//! - [`FlowArrowLayout`] -- assigns column lanes to prevent visual overlaps.
//! - [`FlowArrowPanel`] -- panel configuration and shape computation for rendering.

pub mod provider;
pub mod actions;

use std::collections::{BTreeMap, HashMap, HashSet};
use ghidra_core::Address;

// ============================================================================
// Constants (from FlowArrow.java)
// ============================================================================

/// Minimum spacing between arrow columns in pixels.
pub(crate) const MIN_LINE_SPACING: i32 = 9;

/// Default spacing between arrow columns in pixels.
pub(crate) const DEFAULT_LINE_SPACING: i32 = 16;

/// Maximum spacing between arrow columns in pixels.
pub(crate) const MAX_LINE_SPACING: i32 = 60;

/// Arrow spacing as a fraction of available width.
pub(crate) const ARROW_SPACING_RATIO: f64 = 0.18;

/// Maximum nesting depth for arrow columns (from FlowArrowMarginProvider.java).
pub(crate) const MAX_DEPTH: usize = 16;

/// Triangle arrowhead height in pixels (from FlowArrowShapeFactory.java).
pub(crate) const TRIANGLE_HEIGHT: f64 = 9.0;

/// Triangle arrowhead width in pixels (from FlowArrowShapeFactory.java).
pub(crate) const TRIANGLE_WIDTH: f64 = 7.0;

/// Pixels of left offset for the margin (from FlowArrowMarginProvider.java).
pub const LEFT_OFFSET: i32 = 3;

/// Maximum number of incoming references to show arrows for.
pub(crate) const MAX_REFS_TO_SHOW: usize = 10;

// ============================================================================
// FlowArrowType -- reference type classification
// ============================================================================

/// The type of flow arrow, mapping to Ghidra's `RefType` classification.
///
/// Each variant determines the rendering style (solid, dashed, dash-dot)
/// and the logical behavior (conditional, unconditional, fallthrough).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FlowArrowType {
    /// Unconditional forward jump.
    JumpForward,
    /// Unconditional backward jump.
    JumpBackward,
    /// Conditional forward branch.
    ConditionalForward,
    /// Conditional backward branch.
    ConditionalBackward,
    /// Function call.
    Call,
    /// Sequential fall-through.
    FallThrough,
}

impl FlowArrowType {
    /// Whether this arrow type represents a conditional branch.
    pub fn is_conditional(&self) -> bool {
        matches!(self, Self::ConditionalForward | Self::ConditionalBackward)
    }

    /// Whether this arrow type represents a call.
    pub fn is_call(&self) -> bool {
        matches!(self, Self::Call)
    }

    /// Whether this arrow type represents a jump (conditional or not).
    pub fn is_jump(&self) -> bool {
        matches!(
            self,
            Self::JumpForward
                | Self::JumpBackward
                | Self::ConditionalForward
                | Self::ConditionalBackward
        )
    }

    /// Whether this is a fall-through.
    pub fn is_fallthrough(&self) -> bool {
        matches!(self, Self::FallThrough)
    }

    /// Classify an arrow type from start/end addresses and reference properties.
    pub fn classify(start: Address, end: Address, is_conditional: bool, is_fallthrough: bool) -> Self {
        if is_fallthrough {
            return Self::FallThrough;
        }
        let forward = end >= start;
        if is_conditional {
            if forward { Self::ConditionalForward } else { Self::ConditionalBackward }
        } else if forward {
            Self::JumpForward
        } else {
            Self::JumpBackward
        }
    }
}

// ============================================================================
// Geometry types
// ============================================================================

/// A 2D point for arrow rendering.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Point {
    pub x: f64,
    pub y: f64,
}

impl Point {
    /// Create a new point.
    pub fn new(x: f64, y: f64) -> Self {
        Self { x, y }
    }
}

/// An axis-aligned rectangle for hit testing.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Rect {
    pub x: f64,
    pub y: f64,
    pub width: f64,
    pub height: f64,
}

impl Rect {
    /// Create a new rectangle.
    pub fn new(x: f64, y: f64, width: f64, height: f64) -> Self {
        Self { x, y, width, height }
    }

    /// Set the frame of this rectangle.
    pub fn set_frame(&mut self, x: f64, y: f64, width: f64, height: f64) {
        self.x = x;
        self.y = y;
        self.width = width;
        self.height = height;
    }

    /// Test intersection with another rectangle.
    pub fn intersects_rect(&self, other: &Rect) -> bool {
        self.x < other.x + other.width
            && self.x + self.width > other.x
            && self.y < other.y + other.height
            && self.y + self.height > other.y
    }
}

/// A path segment for arrow body geometry.
///
/// Maps to Java's `PathIterator` segment types.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PathSegment {
    /// Move to a point without drawing (SEG_MOVETO).
    MoveTo(f64, f64),
    /// Draw a line to a point (SEG_LINETO).
    LineTo(f64, f64),
    /// Close the path (SEG_CLOSE).
    Close,
}

/// A triangle defined by three vertices, used for arrowheads.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Triangle {
    pub p1: Point,
    pub p2: Point,
    pub p3: Point,
}

impl Triangle {
    /// Test if this triangle intersects a rectangle.
    ///
    /// Checks both vertex containment and edge-rect intersection.
    pub fn intersects_rect(&self, rect: &Rect) -> bool {
        // Check if any vertex is inside the rect
        let vertex_inside = [self.p1, self.p2, self.p3].iter().any(|p| {
            p.x >= rect.x
                && p.x <= rect.x + rect.width
                && p.y >= rect.y
                && p.y <= rect.y + rect.height
        });
        if vertex_inside {
            return true;
        }

        // Check if the rect contains the triangle's centroid
        let cx = (self.p1.x + self.p2.x + self.p3.x) / 3.0;
        let cy = (self.p1.y + self.p2.y + self.p3.y) / 3.0;
        if cx >= rect.x
            && cx <= rect.x + rect.width
            && cy >= rect.y
            && cy <= rect.y + rect.height
        {
            return true;
        }

        // Check if any triangle edge intersects any rect edge
        let edges = [
            (self.p1, self.p2),
            (self.p2, self.p3),
            (self.p3, self.p1),
        ];
        let rect_edges = [
            (Point::new(rect.x, rect.y), Point::new(rect.x + rect.width, rect.y)),
            (Point::new(rect.x + rect.width, rect.y), Point::new(rect.x + rect.width, rect.y + rect.height)),
            (Point::new(rect.x + rect.width, rect.y + rect.height), Point::new(rect.x, rect.y + rect.height)),
            (Point::new(rect.x, rect.y + rect.height), Point::new(rect.x, rect.y)),
        ];
        for (a, b) in &edges {
            for (c, d) in &rect_edges {
                if segments_intersect(*a, *b, *c, *d) {
                    return true;
                }
            }
        }

        false
    }
}

/// Check if line segment (a,b) intersects segment (c,d).
fn segments_intersect(a: Point, b: Point, c: Point, d: Point) -> bool {
    fn cross(o: Point, a: Point, b: Point) -> f64 {
        (a.x - o.x) * (b.y - o.y) - (a.y - o.y) * (b.x - o.x)
    }
    let d1 = cross(c, d, a);
    let d2 = cross(c, d, b);
    let d3 = cross(a, b, c);
    let d4 = cross(a, b, d);
    ((d1 > 0.0 && d2 < 0.0) || (d1 < 0.0 && d2 > 0.0))
        && ((d3 > 0.0 && d4 < 0.0) || (d3 < 0.0 && d4 > 0.0))
}

// ============================================================================
// StrokeStyle -- rendering stroke configuration
// ============================================================================

/// Rendering stroke style for an arrow, mapping to Java's `java.awt.Stroke`.
///
/// The style varies by arrow type and state (active, selected, inactive).
#[derive(Debug, Clone, PartialEq)]
pub enum StrokeStyle {
    /// Solid line with given width.
    Solid(f64),
    /// Dashed line with width and dash pattern (maps to ConditionalFlowArrow).
    Dashed(f64, Vec<f64>),
    /// Dash-dot line with width and pattern (maps to FallthroughFlowArrow).
    DashDot(f64, Vec<f64>),
}

// ============================================================================
// FlowArrowShape -- complete geometric representation
// ============================================================================

/// The complete geometric shape of a flow arrow including body, head,
/// and clickable hit regions.
///
/// Created by [`FlowArrowShapeFactory`] and cached in [`FlowArrow`].
#[derive(Debug, Clone)]
pub struct FlowArrowShape {
    /// Path segments forming the arrow body.
    pub body_segments: Vec<PathSegment>,
    /// The arrowhead triangle.
    pub head: Triangle,
    /// Clickable hit regions (expanded body segments for easier clicking).
    clickable_regions: Vec<Rect>,
}

impl FlowArrowShape {
    /// Test if a screen point intersects any part of this arrow.
    ///
    /// Uses an expanded hit area (5px square) for easier clicking,
    /// matching the Java `FlowArrow.intersects(Point)` behavior.
    pub fn intersects(&self, point: Point, hit_radius: f64) -> bool {
        let half = hit_radius / 2.0;
        let pick = Rect::new(point.x - half, point.y - half, hit_radius, hit_radius);

        for region in &self.clickable_regions {
            if region.intersects_rect(&pick) {
                return true;
            }
        }

        self.head.intersects_rect(&pick)
    }
}

// ============================================================================
// FlowArrow -- the main arrow struct (ported from FlowArrow.java)
// ============================================================================

/// A single flow arrow connecting two addresses in the listing.
///
/// Ported from Ghidra's abstract `FlowArrow.java`. Contains all state
/// and logic for geometry computation, hit testing, and rendering.
///
/// The three Java subclasses (`ConditionalFlowArrow`, `DefaultFlowArrow`,
/// `FallthroughFlowArrow`) are represented by the `arrow_type` field which
/// determines the stroke style. Factory functions are provided for
/// convenient construction.
#[derive(Debug, Clone)]
pub struct FlowArrow {
    /// The source address (Java: `start`).
    pub start: Address,
    /// The destination address (Java: `end`).
    pub end: Address,
    /// The column lane this arrow occupies (-1 if unassigned).
    pub column: i32,
    /// The flow arrow type determining rendering style.
    pub arrow_type: FlowArrowType,
    /// Whether the arrow points upward (toward lower addresses).
    is_up: bool,
    /// Whether the endpoint matches the current cursor address.
    pub active: bool,
    /// Whether the user has selected this arrow.
    pub selected: bool,
    /// Maximum column depth in the current view.
    max_column: i32,
    /// Cached arrow shape (body + head + hit regions).
    cached_shape: Option<FlowArrowShape>,
}

impl FlowArrow {
    /// Create a new flow arrow.
    pub fn new(start: Address, end: Address, arrow_type: FlowArrowType) -> Self {
        Self {
            start,
            end,
            column: -1,
            arrow_type,
            is_up: start.offset > end.offset,
            active: false,
            selected: false,
            max_column: 0,
            cached_shape: None,
        }
    }

    /// Set the maximum column context (for line width calculation).
    pub fn with_max_column(mut self, max_column: i32) -> Self {
        self.max_column = max_column;
        self
    }

    /// Whether this arrow points upward (toward lower addresses).
    pub fn is_up(&self) -> bool {
        self.is_up
    }

    /// Whether this arrow points forward (toward higher addresses).
    pub fn is_forward(&self) -> bool {
        self.end > self.start
    }

    /// The distance of the arrow (absolute address difference).
    pub fn distance(&self) -> u64 {
        if self.end > self.start {
            self.end.offset - self.start.offset
        } else {
            self.start.offset - self.end.offset
        }
    }

    /// Invalidate cached shapes (call when screen layout changes).
    ///
    /// Ported from `FlowArrow.resetShape()`.
    pub fn reset_shape(&mut self) {
        self.cached_shape = None;
    }

    /// Test if a screen point intersects this arrow.
    ///
    /// Ported from `FlowArrow.intersects(Point)`. Uses a 5px hit area
    /// for easier line clicking.
    pub fn intersects(&self, point: Point) -> bool {
        match &self.cached_shape {
            Some(shape) => shape.intersects(point, 5.0),
            None => false,
        }
    }

    /// Get or compute the arrow shape for the given display context.
    ///
    /// Ported from `FlowArrow.createShapes()`.
    pub fn ensure_shape(
        &mut self,
        start_y: f64,
        end_y: f64,
        display_width: f64,
        display_height: f64,
    ) {
        if self.cached_shape.is_some() {
            return;
        }
        let line_width = self.calculate_line_width(display_width as i32);
        let shape = FlowArrowShapeFactory::create_arrow_shape(
            self.column,
            start_y,
            end_y,
            display_width,
            display_height,
            line_width as f64,
            self.is_up,
        );
        self.cached_shape = Some(shape);
    }

    /// Calculate the line width (spacing) based on display width and column depth.
    ///
    /// Ported from `FlowArrow.calculateLineWidth(int)`.
    fn calculate_line_width(&self, display_width: i32) -> i32 {
        let mut line_width = DEFAULT_LINE_SPACING;
        if self.max_column >= 0 {
            let available_width = display_width - LEFT_OFFSET;
            line_width = (available_width as f64 * ARROW_SPACING_RATIO) as i32;
        }
        line_width.clamp(MIN_LINE_SPACING, MAX_LINE_SPACING)
    }

    /// Get the stroke style for rendering based on state and arrow type.
    ///
    /// Ported from `FlowArrow.doPaint()` stroke selection logic:
    /// - Selected/active: thicker stroke
    /// - Conditional: dashed
    /// - Fallthrough: dash-dot
    /// - Default: solid
    pub fn get_stroke_style(&self) -> StrokeStyle {
        let is_highlighted = self.selected || self.active;
        match self.arrow_type {
            FlowArrowType::ConditionalForward | FlowArrowType::ConditionalBackward => {
                if is_highlighted {
                    StrokeStyle::Solid(2.0)
                } else {
                    StrokeStyle::Dashed(1.0, vec![5.0, 5.0])
                }
            }
            FlowArrowType::FallThrough => {
                if is_highlighted {
                    StrokeStyle::DashDot(2.0, vec![8.0, 3.0, 2.0, 3.0])
                } else {
                    StrokeStyle::DashDot(1.0, vec![8.0, 3.0, 2.0, 3.0])
                }
            }
            _ => {
                if is_highlighted {
                    StrokeStyle::Solid(2.0)
                } else {
                    StrokeStyle::Solid(1.0)
                }
            }
        }
    }

    /// Generate an HTML display string for tooltip rendering.
    ///
    /// Ported from `FlowArrow.getDisplayString()`.
    pub fn get_display_string(&self) -> String {
        format!(
            "<html><table> \
             <tr><td>start</td><td>0x{:X}</td></tr> \
             <tr><td>end</td><td>0x{:X}</td></tr> \
             <tr><td>ref type</td><td>{:?}</td></tr> \
             </table>",
            self.start.offset, self.end.offset, self.arrow_type
        )
    }
}

impl std::fmt::Display for FlowArrow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "start=0x{:X}; end=0x{:X}; ref type={:?}",
            self.start.offset, self.end.offset, self.arrow_type
        )
    }
}

impl PartialEq for FlowArrow {
    fn eq(&self, other: &Self) -> bool {
        self.start == other.start && self.end == other.end && self.arrow_type == other.arrow_type
    }
}

impl Eq for FlowArrow {}

impl std::hash::Hash for FlowArrow {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.start.hash(state);
        self.end.hash(state);
        self.arrow_type.hash(state);
    }
}

// ============================================================================
// Arrow constructors (ported from Conditional/Default/FallthroughFlowArrow.java)
// ============================================================================

/// Create a conditional branch flow arrow.
///
/// Ported from `ConditionalFlowArrow.java`. Uses dashed stroke when
/// inactive, solid when active/selected.
pub fn conditional_flow_arrow(start: Address, end: Address) -> FlowArrow {
    FlowArrow::new(start, end, FlowArrowType::ConditionalForward)
}

/// Create an unconditional jump flow arrow.
///
/// Ported from `DefaultFlowArrow.java`. Uses thin solid stroke when
/// inactive, thick solid when active/selected.
pub fn default_flow_arrow(start: Address, end: Address) -> FlowArrow {
    FlowArrow::new(start, end, FlowArrowType::JumpForward)
}

/// Create a fallthrough flow arrow.
///
/// Ported from `FallthroughFlowArrow.java`. Uses dash-dot stroke.
pub fn fallthrough_flow_arrow(start: Address, end: Address) -> FlowArrow {
    FlowArrow::new(start, end, FlowArrowType::FallThrough)
}

// ============================================================================
// FlowArrowShapeFactory (ported from FlowArrowShapeFactory.java)
// ============================================================================

/// Factory for creating arrow body and head shapes.
///
/// Ported from `FlowArrowShapeFactory.java`. Creates the L-shaped path
/// for the arrow body and the triangle for the arrowhead.
///
/// The arrow body consists of:
/// 1. A horizontal line from the listing edge to the column position
/// 2. A vertical line along the column
/// 3. A horizontal line from the column to the arrowhead
pub struct FlowArrowShapeFactory;

impl FlowArrowShapeFactory {
    /// Create the complete arrow shape (body + head + clickable regions).
    ///
    /// This is the main entry point, called from `FlowArrow.createShapes()`.
    pub fn create_arrow_shape(
        column: i32,
        start_y: f64,
        end_y: f64,
        display_width: f64,
        display_height: f64,
        line_spacing: f64,
        is_up: bool,
    ) -> FlowArrowShape {
        let body = Self::create_arrow_body(
            column, start_y, end_y,
            display_width, display_height, line_spacing, is_up,
        );
        let head = Self::create_arrow_head(
            column, end_y, display_width, display_height, line_spacing,
        );
        let clickable = Self::create_clickable_regions(&body);
        FlowArrowShape {
            body_segments: body,
            head,
            clickable_regions: clickable,
        }
    }

    /// Create the arrow body path segments.
    ///
    /// Ported from `FlowArrowShapeFactory.createArrowBody()`.
    ///
    /// The body is an L-shaped path:
    /// ```text
    /// |  _____*|
    /// | |      |
    /// | |_____.|
    /// ```
    pub fn create_arrow_body(
        column: i32,
        start_y: f64,
        end_y: f64,
        display_width: f64,
        display_height: f64,
        line_spacing: f64,
        is_up: bool,
    ) -> Vec<PathSegment> {
        let mut segments = Vec::new();

        // Compute x position from column and spacing
        let x = display_width - ((column + 1) as f64 * line_spacing);
        let x = x.max(3.0);

        // Step 1: Horizontal line from listing edge to column position
        // (only if start is on screen)
        if start_y > 0.0 && start_y < display_height {
            segments.push(PathSegment::MoveTo(display_width, start_y));
            segments.push(PathSegment::LineTo(x, start_y));
        }

        // Step 2: Vertical line along the column
        let off_screen = end_y <= 0.0 || end_y >= display_height;
        let arrow_height = if off_screen { TRIANGLE_HEIGHT - 1.0 } else { 0.0 };
        let arrow_height = if is_up { -arrow_height } else { arrow_height };

        segments.push(PathSegment::MoveTo(x, start_y));
        segments.push(PathSegment::LineTo(x, end_y - arrow_height));

        // Step 3: Horizontal line from column to arrowhead
        // (only if end is on screen)
        if end_y > 0.0 && end_y < display_height {
            segments.push(PathSegment::MoveTo(x, end_y));
            segments.push(PathSegment::LineTo(display_width - TRIANGLE_WIDTH, end_y));
        }

        segments
    }

    /// Create the arrowhead triangle.
    ///
    /// Ported from `FlowArrowShapeFactory.createArrowHead()`.
    ///
    /// Three orientations depending on whether the endpoint is on-screen,
    /// above the screen, or below the screen:
    /// - On-screen: right-pointing triangle at the listing edge
    /// - Above screen: downward-pointing triangle at the column
    /// - Below screen: upward-pointing triangle at the column
    pub fn create_arrow_head(
        column: i32,
        end_y: f64,
        display_width: f64,
        display_height: f64,
        line_spacing: f64,
    ) -> Triangle {
        let x = display_width - ((column + 1) as f64 * line_spacing);
        let x = x.max(3.0);
        let half_height = TRIANGLE_HEIGHT / 2.0;

        if end_y > 0.0 && end_y < display_height {
            // On-screen: right-pointing arrowhead
            Triangle {
                p1: Point::new(display_width, end_y),
                p2: Point::new(display_width - TRIANGLE_WIDTH, end_y - half_height),
                p3: Point::new(display_width - TRIANGLE_WIDTH, end_y + half_height),
            }
        } else if end_y <= 0.0 {
            // Off-screen top: downward-pointing arrowhead
            Triangle {
                p1: Point::new(x, 0.0),
                p2: Point::new(x - half_height, TRIANGLE_WIDTH),
                p3: Point::new(x + half_height, TRIANGLE_WIDTH),
            }
        } else {
            // Off-screen bottom: upward-pointing arrowhead
            Triangle {
                p1: Point::new(x, display_height),
                p2: Point::new(x - half_height, display_height - TRIANGLE_WIDTH),
                p3: Point::new(x + half_height, display_height - TRIANGLE_WIDTH),
            }
        }
    }

    /// Create clickable hit regions from body path segments.
    ///
    /// Ported from `FlowArrow.createClickableShapes()`. Each `LineTo`
    /// segment is expanded into a rectangle for easier clicking.
    /// Horizontal lines get 2px height; vertical lines get 2px width.
    pub(crate) fn create_clickable_regions(segments: &[PathSegment]) -> Vec<Rect> {
        let mut regions = Vec::new();
        let mut cursor_x = 0.0_f64;
        let mut cursor_y = 0.0_f64;

        for seg in segments {
            match seg {
                PathSegment::MoveTo(x, y) => {
                    cursor_x = *x;
                    cursor_y = *y;
                }
                PathSegment::LineTo(x, y) => {
                    let rect = Self::build_clickable_rect(cursor_x, cursor_y, *x, *y);
                    regions.push(rect);
                    cursor_x = *x;
                    cursor_y = *y;
                }
                PathSegment::Close => {}
            }
        }

        regions
    }

    /// Build a clickable rectangle from a line segment.
    ///
    /// Ported from `FlowArrow.buildRectangle()`.
    /// Horizontal lines are expanded to 2px height.
    /// Vertical lines are expanded to 2px width.
    fn build_clickable_rect(
        start_x: f64, start_y: f64,
        end_x: f64, end_y: f64,
    ) -> Rect {
        let w = (start_x - end_x).abs();
        let h = (start_y - end_y).abs();

        if w > 0.0 && h > 0.0 {
            // Diagonal segment -- use bounding box as-is
            return Rect::new(start_x.min(end_x), start_y.min(end_y), w, h);
        }

        if h == 0.0 {
            // Horizontal line -- add height for clicking
            let x = start_x.min(end_x);
            Rect::new(x, start_y - 1.0, w.max(1.0), 2.0)
        } else {
            // Vertical line -- add width for clicking
            let y = start_y.min(end_y);
            Rect::new(start_x - 1.0, y, 2.0, h.max(1.0))
        }
    }
}

// ============================================================================
// FlowArrowModel -- manages arrow collections
// ============================================================================

/// Manages a collection of flow arrows for a listing view.
///
/// Supports adding, removing, querying, and sorting arrows.
#[derive(Debug, Default)]
pub struct FlowArrowModel {
    arrows: Vec<FlowArrow>,
}

impl FlowArrowModel {
    /// Create a new empty model.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a flow arrow.
    pub fn add_arrow(&mut self, arrow: FlowArrow) {
        self.arrows.push(arrow);
    }

    /// Get all arrows as a slice.
    pub fn get_arrows(&self) -> &[FlowArrow] {
        &self.arrows
    }

    /// Get mutable access to all arrows.
    pub fn get_arrows_mut(&mut self) -> &mut [FlowArrow] {
        &mut self.arrows
    }

    /// Get arrows originating from a specific address.
    pub fn get_arrows_from(&self, from: Address) -> Vec<&FlowArrow> {
        self.arrows.iter().filter(|a| a.start == from).collect()
    }

    /// Get arrows targeting a specific address.
    pub fn get_arrows_to(&self, to: Address) -> Vec<&FlowArrow> {
        self.arrows.iter().filter(|a| a.end == to).collect()
    }

    /// Get all conditional branch arrows.
    pub fn get_conditional_arrows(&self) -> Vec<&FlowArrow> {
        self.arrows.iter().filter(|a| a.arrow_type.is_conditional()).collect()
    }

    /// Get all call arrows.
    pub fn get_call_arrows(&self) -> Vec<&FlowArrow> {
        self.arrows.iter().filter(|a| a.arrow_type.is_call()).collect()
    }

    /// Get arrows sorted by end address.
    pub fn get_arrows_sorted(&self) -> Vec<&FlowArrow> {
        let mut sorted: Vec<&FlowArrow> = self.arrows.iter().collect();
        sorted.sort_by_key(|a| a.end.offset);
        sorted
    }

    /// Clear all arrows.
    pub fn clear(&mut self) {
        self.arrows.clear();
    }

    /// Return the number of arrows.
    pub fn count(&self) -> usize {
        self.arrows.len()
    }

    /// Whether the model is empty.
    pub fn is_empty(&self) -> bool {
        self.arrows.is_empty()
    }

    /// Remove arrows originating from a specific address.
    pub fn remove_arrows_from(&mut self, from: Address) {
        self.arrows.retain(|a| a.start != from);
    }

    /// Remove arrows targeting a specific address.
    pub fn remove_arrows_to(&mut self, to: Address) {
        self.arrows.retain(|a| a.end != to);
    }
}

// ============================================================================
// FlowArrowLayout -- assign columns to prevent overlaps
// ============================================================================

/// Assigns column lanes to arrows to prevent visual overlaps.
///
/// Ported from the column assignment logic in `FlowArrowMarginProvider.java`.
/// Two algorithms are provided:
///
/// - [`assign_columns`](FlowArrowLayout::assign_columns): Simple greedy
///   assignment based on address range overlap.
///
/// - [`assign_columns_grouped`](FlowArrowLayout::assign_columns_grouped):
///   Groups arrows by shared endpoints, then assigns non-overlapping columns
///   to each group. This matches the Java `ArrowGroup` behavior.
#[derive(Debug, Default)]
pub struct FlowArrowLayout;

impl FlowArrowLayout {
    /// Assign column values to arrows using simple overlap detection.
    ///
    /// Arrows are sorted by address range and assigned to the first
    /// available column where they don't overlap existing arrows.
    pub fn assign_columns(arrows: &mut [FlowArrow]) {
        if arrows.is_empty() {
            return;
        }

        arrows.sort_by_key(|a| {
            let lo = a.start.offset.min(a.end.offset);
            let hi = a.start.offset.max(a.end.offset);
            (lo, hi)
        });

        let mut column_ends: Vec<u64> = Vec::new();
        for arrow in arrows.iter_mut() {
            let lo = arrow.start.offset.min(arrow.end.offset);
            let hi = arrow.start.offset.max(arrow.end.offset);
            let mut assigned = false;

            for (col, &end) in column_ends.iter().enumerate() {
                if end < lo {
                    arrow.column = col as i32;
                    column_ends[col] = hi;
                    assigned = true;
                    break;
                }
            }

            if !assigned {
                arrow.column = column_ends.len() as i32;
                column_ends.push(hi);
            }
        }
    }

    /// Assign columns using shared-endpoint grouping.
    ///
    /// Ported from `FlowArrowMarginProvider.groupArrowsBySharedEndpoints()`
    /// and `assignArrowColumns()`. Arrows sharing a start or end address
    /// are grouped together and share the same column.
    pub fn assign_columns_grouped(arrows: &mut [FlowArrow]) {
        if arrows.is_empty() {
            return;
        }

        // Build endpoint-to-index maps
        let mut starts: HashMap<u64, Vec<usize>> = HashMap::new();
        let mut ends: HashMap<u64, Vec<usize>> = HashMap::new();

        for (i, arrow) in arrows.iter().enumerate() {
            starts.entry(arrow.start.offset).or_default().push(i);
            ends.entry(arrow.end.offset).or_default().push(i);
        }

        // Group arrows by shared endpoints using BFS
        let mut processed = HashSet::new();
        let mut groups: Vec<Vec<usize>> = Vec::new();

        for (i, _arrow) in arrows.iter().enumerate() {
            if processed.contains(&i) {
                continue;
            }

            let mut group = Vec::new();
            let mut queue = vec![i];

            while let Some(idx) = queue.pop() {
                if processed.contains(&idx) {
                    continue;
                }
                processed.insert(idx);
                group.push(idx);

                let a = &arrows[idx];
                if let Some(shared) = starts.get(&a.start.offset) {
                    for &j in shared {
                        if !processed.contains(&j) {
                            queue.push(j);
                        }
                    }
                }
                if let Some(shared) = ends.get(&a.end.offset) {
                    for &j in shared {
                        if !processed.contains(&j) {
                            queue.push(j);
                        }
                    }
                }
            }

            groups.push(group);
        }

        // Sort groups by lowest endpoint address
        groups.sort_by_key(|g| {
            g.iter()
                .map(|&idx| arrows[idx].end.offset.min(arrows[idx].start.offset))
                .min()
                .unwrap_or(0)
        });

        // Assign columns to groups, capping at MAX_DEPTH
        let mut column_ends: Vec<u64> = Vec::new();
        for group in &groups {
            let group_min = group.iter()
                .map(|&idx| arrows[idx].start.offset.min(arrows[idx].end.offset))
                .min()
                .unwrap_or(0);
            let group_max = group.iter()
                .map(|&idx| arrows[idx].start.offset.max(arrows[idx].end.offset))
                .max()
                .unwrap_or(0);

            // Find first column where this group fits
            let mut col = column_ends.len();
            for (c, &end) in column_ends.iter().enumerate() {
                if end < group_min {
                    col = c;
                    break;
                }
            }

            if col >= column_ends.len() {
                column_ends.push(group_max);
            } else {
                column_ends[col] = group_max;
            }

            let col = col.min(MAX_DEPTH);
            for &idx in group {
                arrows[idx].column = col as i32;
            }
        }
    }
}

// ============================================================================
// FlowArrowPanel -- panel configuration and shape computation
// ============================================================================

/// Configuration for a flow arrow display panel.
///
/// Ported from `FlowArrowPanel.java`. Computes arrow shapes for
/// rendering based on address-to-y-coordinate mappings.
#[derive(Debug, Clone)]
pub struct FlowArrowPanel {
    /// Panel width in pixels.
    pub width: u32,
    /// Panel height in pixels.
    pub height: u32,
    /// Column offset in pixels per lane.
    pub column_offset: f64,
    /// Maximum number of column lanes.
    pub max_columns: usize,
    /// Base x position for arrows.
    pub base_x: f64,
}

impl FlowArrowPanel {
    /// Create a new flow arrow panel.
    pub fn new(width: u32, height: u32) -> Self {
        Self {
            width,
            height,
            column_offset: 12.0,
            max_columns: 8,
            base_x: 5.0,
        }
    }

    /// Set the column offset.
    pub fn with_column_offset(mut self, offset: f64) -> Self {
        self.column_offset = offset;
        self
    }

    /// Set the maximum number of columns.
    pub fn with_max_columns(mut self, max: usize) -> Self {
        self.max_columns = max;
        self
    }

    /// Compute arrow shapes for a set of arrows given address-to-y mappings.
    pub fn compute_shapes(
        &self,
        arrows: &[FlowArrow],
        addr_to_y: &BTreeMap<u64, f64>,
    ) -> Vec<FlowArrowShape> {
        let mut shapes = Vec::new();
        for arrow in arrows {
            let from_y = addr_to_y.get(&arrow.start.offset).copied().unwrap_or(0.0);
            let to_y = addr_to_y.get(&arrow.end.offset).copied().unwrap_or(0.0);

            let shape = match arrow.arrow_type {
                FlowArrowType::FallThrough => {
                    // Fallthrough uses a simple straight line
                    let body = vec![
                        PathSegment::MoveTo(self.base_x, from_y),
                        PathSegment::LineTo(self.base_x, to_y),
                    ];
                    let head = Triangle {
                        p1: Point::new(self.base_x, to_y),
                        p2: Point::new(self.base_x - 3.0, to_y - 4.0),
                        p3: Point::new(self.base_x + 3.0, to_y - 4.0),
                    };
                    let clickable = FlowArrowShapeFactory::create_clickable_regions(&body);
                    FlowArrowShape {
                        body_segments: body,
                        head,
                        clickable_regions: clickable,
                    }
                }
                _ => {
                    FlowArrowShapeFactory::create_arrow_shape(
                        arrow.column,
                        from_y,
                        to_y,
                        self.width as f64,
                        self.height as f64,
                        self.column_offset,
                        arrow.is_up(),
                    )
                }
            };
            shapes.push(shape);
        }
        shapes
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ----------------------------------------------------------------
    // FlowArrowType tests
    // ----------------------------------------------------------------

    #[test]
    fn test_flow_arrow_type_properties() {
        assert!(FlowArrowType::ConditionalForward.is_conditional());
        assert!(FlowArrowType::ConditionalBackward.is_conditional());
        assert!(!FlowArrowType::JumpForward.is_conditional());

        assert!(FlowArrowType::Call.is_call());
        assert!(!FlowArrowType::JumpForward.is_call());

        assert!(FlowArrowType::JumpForward.is_jump());
        assert!(FlowArrowType::ConditionalForward.is_jump());
        assert!(!FlowArrowType::Call.is_jump());

        assert!(FlowArrowType::FallThrough.is_fallthrough());
        assert!(!FlowArrowType::JumpForward.is_fallthrough());
    }

    #[test]
    fn test_flow_arrow_type_classify() {
        let start = Address::new(0x1000);
        let end = Address::new(0x2000);

        let t = FlowArrowType::classify(start, end, false, false);
        assert_eq!(t, FlowArrowType::JumpForward);

        let t = FlowArrowType::classify(end, start, false, false);
        assert_eq!(t, FlowArrowType::JumpBackward);

        let t = FlowArrowType::classify(start, end, true, false);
        assert_eq!(t, FlowArrowType::ConditionalForward);

        let t = FlowArrowType::classify(start, end, false, true);
        assert_eq!(t, FlowArrowType::FallThrough);
    }

    // ----------------------------------------------------------------
    // FlowArrow tests
    // ----------------------------------------------------------------

    #[test]
    fn test_flow_arrow_direction() {
        let fwd = FlowArrow::new(Address::new(0x1000), Address::new(0x2000), FlowArrowType::JumpForward);
        assert!(fwd.is_forward());
        assert!(!fwd.is_up());

        let bwd = FlowArrow::new(Address::new(0x2000), Address::new(0x1000), FlowArrowType::JumpBackward);
        assert!(!bwd.is_forward());
        assert!(bwd.is_up());
    }

    #[test]
    fn test_flow_arrow_distance() {
        let arrow = FlowArrow::new(Address::new(0x1000), Address::new(0x2000), FlowArrowType::JumpForward);
        assert_eq!(arrow.distance(), 0x1000);
    }

    #[test]
    fn test_flow_arrow_equality() {
        let a = FlowArrow::new(Address::new(0x1000), Address::new(0x2000), FlowArrowType::JumpForward);
        let b = FlowArrow::new(Address::new(0x1000), Address::new(0x2000), FlowArrowType::JumpForward);
        let c = FlowArrow::new(Address::new(0x1000), Address::new(0x2000), FlowArrowType::ConditionalForward);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn test_flow_arrow_stroke_style() {
        let default = FlowArrow::new(Address::new(0x1000), Address::new(0x2000), FlowArrowType::JumpForward);
        assert_eq!(default.get_stroke_style(), StrokeStyle::Solid(1.0));

        let mut active = default.clone();
        active.active = true;
        assert_eq!(active.get_stroke_style(), StrokeStyle::Solid(2.0));

        let cond = FlowArrow::new(Address::new(0x1000), Address::new(0x2000), FlowArrowType::ConditionalForward);
        assert_eq!(cond.get_stroke_style(), StrokeStyle::Dashed(1.0, vec![5.0, 5.0]));

        let fall = FlowArrow::new(Address::new(0x1000), Address::new(0x2000), FlowArrowType::FallThrough);
        assert_eq!(fall.get_stroke_style(), StrokeStyle::DashDot(1.0, vec![8.0, 3.0, 2.0, 3.0]));
    }

    #[test]
    fn test_flow_arrow_display_string() {
        let arrow = FlowArrow::new(Address::new(0x1000), Address::new(0x2000), FlowArrowType::JumpForward);
        let s = arrow.get_display_string();
        assert!(s.contains("0x1000"));
        assert!(s.contains("0x2000"));
        assert!(s.contains("JumpForward"));
    }

    #[test]
    fn test_flow_arrow_display() {
        let arrow = FlowArrow::new(Address::new(0x1000), Address::new(0x2000), FlowArrowType::JumpForward);
        let s = format!("{}", arrow);
        assert!(s.contains("0x1000"));
        assert!(s.contains("0x2000"));
    }

    #[test]
    fn test_flow_arrow_reset_shape() {
        let mut arrow = FlowArrow::new(Address::new(0x1000), Address::new(0x2000), FlowArrowType::JumpForward);
        arrow.ensure_shape(10.0, 50.0, 100.0, 300.0);
        assert!(arrow.cached_shape.is_some());
        arrow.reset_shape();
        assert!(arrow.cached_shape.is_none());
    }

    #[test]
    fn test_flow_arrow_ensure_shape() {
        let mut arrow = FlowArrow::new(Address::new(0x1000), Address::new(0x2000), FlowArrowType::JumpForward);
        arrow.column = 0;
        arrow.ensure_shape(10.0, 50.0, 200.0, 300.0);
        assert!(arrow.cached_shape.is_some());

        // Calling again should be a no-op (cached)
        arrow.ensure_shape(10.0, 50.0, 200.0, 300.0);
        assert!(arrow.cached_shape.is_some());
    }

    #[test]
    fn test_flow_arrow_intersects() {
        let mut arrow = FlowArrow::new(Address::new(0x1000), Address::new(0x2000), FlowArrowType::JumpForward);
        arrow.column = 0;

        // No shape cached yet -- should not intersect
        assert!(!arrow.intersects(Point::new(50.0, 30.0)));

        // Create shape
        arrow.ensure_shape(10.0, 50.0, 200.0, 300.0);

        // Test a point near the body
        // The body goes from (200, 10) -> (188, 10) then (188, 10) -> (188, 50)
        // So a point at (194, 10) should be on the horizontal segment
        assert!(arrow.intersects(Point::new(194.0, 10.0)));
    }

    // ----------------------------------------------------------------
    // Arrow constructors
    // ----------------------------------------------------------------

    #[test]
    fn test_conditional_flow_arrow() {
        let arrow = conditional_flow_arrow(Address::new(0x1000), Address::new(0x2000));
        assert!(arrow.arrow_type.is_conditional());
        assert_eq!(arrow.arrow_type, FlowArrowType::ConditionalForward);
    }

    #[test]
    fn test_default_flow_arrow() {
        let arrow = default_flow_arrow(Address::new(0x1000), Address::new(0x2000));
        assert_eq!(arrow.arrow_type, FlowArrowType::JumpForward);
        assert!(arrow.arrow_type.is_jump());
    }

    #[test]
    fn test_fallthrough_flow_arrow() {
        let arrow = fallthrough_flow_arrow(Address::new(0x1000), Address::new(0x1004));
        assert_eq!(arrow.arrow_type, FlowArrowType::FallThrough);
        assert!(arrow.is_forward());
        assert_eq!(arrow.distance(), 4);
    }

    // ----------------------------------------------------------------
    // FlowArrowShapeFactory tests
    // ----------------------------------------------------------------

    #[test]
    fn test_shape_factory_on_screen() {
        let shape = FlowArrowShapeFactory::create_arrow_shape(
            0, 10.0, 50.0, 200.0, 300.0, 12.0, false,
        );
        assert!(!shape.body_segments.is_empty());
        // On-screen: right-pointing arrowhead
        assert_eq!(shape.head.p1.x, 200.0); // at display_width
    }

    #[test]
    fn test_shape_factory_off_screen_top() {
        let shape = FlowArrowShapeFactory::create_arrow_shape(
            0, 10.0, 0.0, 200.0, 300.0, 12.0, true,
        );
        // Off-screen top: downward-pointing arrowhead
        assert_eq!(shape.head.p1.y, 0.0);
    }

    #[test]
    fn test_shape_factory_off_screen_bottom() {
        let shape = FlowArrowShapeFactory::create_arrow_shape(
            0, 10.0, 300.0, 200.0, 300.0, 12.0, false,
        );
        // Off-screen bottom: upward-pointing arrowhead
        assert_eq!(shape.head.p1.y, 300.0);
    }

    #[test]
    fn test_shape_factory_clickable_regions() {
        let shape = FlowArrowShapeFactory::create_arrow_shape(
            0, 10.0, 50.0, 200.0, 300.0, 12.0, false,
        );
        // Should have clickable regions for each LineTo segment
        assert!(!shape.clickable_regions.is_empty());
    }

    #[test]
    fn test_shape_factory_intersects() {
        let shape = FlowArrowShapeFactory::create_arrow_shape(
            0, 100.0, 200.0, 300.0, 400.0, 12.0, false,
        );
        // A point near the horizontal body segment should intersect
        // Body: (300, 100) -> (288, 100)
        assert!(shape.intersects(Point::new(294.0, 100.0), 5.0));
    }

    #[test]
    fn test_build_clickable_rect_horizontal() {
        let rect = FlowArrowShapeFactory::build_clickable_rect(10.0, 50.0, 100.0, 50.0);
        assert_eq!(rect.y, 49.0); // expanded by 1px above
        assert_eq!(rect.height, 2.0); // 2px tall
    }

    #[test]
    fn test_build_clickable_rect_vertical() {
        let rect = FlowArrowShapeFactory::build_clickable_rect(50.0, 10.0, 50.0, 100.0);
        assert_eq!(rect.x, 49.0); // expanded by 1px left
        assert_eq!(rect.width, 2.0); // 2px wide
    }

    // ----------------------------------------------------------------
    // FlowArrowModel tests
    // ----------------------------------------------------------------

    #[test]
    fn test_flow_arrow_model_basic() {
        let mut model = FlowArrowModel::new();
        assert!(model.is_empty());
        assert_eq!(model.count(), 0);

        model.add_arrow(FlowArrow::new(
            Address::new(0x1000), Address::new(0x2000), FlowArrowType::JumpForward,
        ));
        model.add_arrow(FlowArrow::new(
            Address::new(0x3000), Address::new(0x1000), FlowArrowType::JumpBackward,
        ));
        assert_eq!(model.count(), 2);
        assert!(!model.is_empty());
    }

    #[test]
    fn test_flow_arrow_model_queries() {
        let mut model = FlowArrowModel::new();
        model.add_arrow(FlowArrow::new(
            Address::new(0x1000), Address::new(0x2000), FlowArrowType::JumpForward,
        ));
        model.add_arrow(FlowArrow::new(
            Address::new(0x1000), Address::new(0x3000), FlowArrowType::ConditionalForward,
        ));
        model.add_arrow(FlowArrow::new(
            Address::new(0x4000), Address::new(0x5000), FlowArrowType::Call,
        ));

        assert_eq!(model.get_arrows_from(Address::new(0x1000)).len(), 2);
        assert_eq!(model.get_arrows_to(Address::new(0x2000)).len(), 1);
        assert_eq!(model.get_conditional_arrows().len(), 1);
        assert_eq!(model.get_call_arrows().len(), 1);
    }

    #[test]
    fn test_flow_arrow_model_sorted() {
        let mut model = FlowArrowModel::new();
        model.add_arrow(FlowArrow::new(
            Address::new(0x1000), Address::new(0x5000), FlowArrowType::JumpForward,
        ));
        model.add_arrow(FlowArrow::new(
            Address::new(0x1000), Address::new(0x1100), FlowArrowType::JumpForward,
        ));
        let sorted = model.get_arrows_sorted();
        assert_eq!(sorted[0].end.offset, 0x1100);
        assert_eq!(sorted[1].end.offset, 0x5000);
    }

    #[test]
    fn test_flow_arrow_model_remove() {
        let mut model = FlowArrowModel::new();
        model.add_arrow(FlowArrow::new(
            Address::new(0x1000), Address::new(0x2000), FlowArrowType::JumpForward,
        ));
        model.add_arrow(FlowArrow::new(
            Address::new(0x3000), Address::new(0x1000), FlowArrowType::JumpBackward,
        ));

        model.remove_arrows_from(Address::new(0x1000));
        assert_eq!(model.count(), 1);

        model.remove_arrows_to(Address::new(0x1000));
        assert_eq!(model.count(), 0);
    }

    #[test]
    fn test_flow_arrow_model_clear() {
        let mut model = FlowArrowModel::new();
        model.add_arrow(FlowArrow::new(
            Address::new(0x1000), Address::new(0x2000), FlowArrowType::JumpForward,
        ));
        model.clear();
        assert!(model.is_empty());
    }

    // ----------------------------------------------------------------
    // FlowArrowLayout tests
    // ----------------------------------------------------------------

    #[test]
    fn test_flow_arrow_layout_simple() {
        let mut arrows = vec![
            FlowArrow::new(Address::new(0x1000), Address::new(0x3000), FlowArrowType::JumpForward),
            FlowArrow::new(Address::new(0x2000), Address::new(0x4000), FlowArrowType::JumpForward),
            FlowArrow::new(Address::new(0x1100), Address::new(0x1500), FlowArrowType::JumpForward),
        ];
        FlowArrowLayout::assign_columns(&mut arrows);
        // assign_columns sorts by (lo, hi), so [0x1100,0x1500] is now at index 1
        // It overlaps with [0x1000,0x3000] so it gets column 1
        let small_arrow = arrows.iter().find(|a| a.start.offset == 0x1100).unwrap();
        assert_eq!(small_arrow.column, 1);
    }

    #[test]
    fn test_flow_arrow_layout_grouped() {
        let mut arrows = vec![
            FlowArrow::new(Address::new(0x1000), Address::new(0x2000), FlowArrowType::JumpForward),
            FlowArrow::new(Address::new(0x1000), Address::new(0x3000), FlowArrowType::ConditionalForward),
            FlowArrow::new(Address::new(0x4000), Address::new(0x5000), FlowArrowType::JumpForward),
        ];
        FlowArrowLayout::assign_columns_grouped(&mut arrows);
        // First two share start address => same column
        assert_eq!(arrows[0].column, arrows[1].column);
    }

    #[test]
    fn test_flow_arrow_layout_empty() {
        let mut arrows: Vec<FlowArrow> = vec![];
        FlowArrowLayout::assign_columns(&mut arrows);
        assert!(arrows.is_empty());
    }

    // ----------------------------------------------------------------
    // FlowArrowPanel tests
    // ----------------------------------------------------------------

    #[test]
    fn test_flow_arrow_panel_config() {
        let panel = FlowArrowPanel::new(50, 300)
            .with_column_offset(10.0)
            .with_max_columns(4);
        assert_eq!(panel.width, 50);
        assert_eq!(panel.height, 300);
        assert_eq!(panel.column_offset, 10.0);
        assert_eq!(panel.max_columns, 4);
    }

    #[test]
    fn test_flow_arrow_panel_compute_shapes() {
        let panel = FlowArrowPanel::new(200, 300);
        let arrows = vec![
            FlowArrow::new(Address::new(0x1000), Address::new(0x2000), FlowArrowType::JumpForward),
            FlowArrow::new(Address::new(0x1000), Address::new(0x1100), FlowArrowType::FallThrough),
        ];
        let mut addr_to_y = BTreeMap::new();
        addr_to_y.insert(0x1000, 10.0);
        addr_to_y.insert(0x1100, 30.0);
        addr_to_y.insert(0x2000, 80.0);
        let shapes = panel.compute_shapes(&arrows, &addr_to_y);
        assert_eq!(shapes.len(), 2);
    }

    // ----------------------------------------------------------------
    // Geometry tests
    // ----------------------------------------------------------------

    #[test]
    fn test_point() {
        let p = Point::new(3.0, 4.0);
        assert_eq!(p.x, 3.0);
        assert_eq!(p.y, 4.0);
    }

    #[test]
    fn test_rect_intersect() {
        let r1 = Rect::new(0.0, 0.0, 10.0, 10.0);
        let r2 = Rect::new(5.0, 5.0, 10.0, 10.0);
        let r3 = Rect::new(20.0, 20.0, 5.0, 5.0);
        assert!(r1.intersects_rect(&r2));
        assert!(!r1.intersects_rect(&r3));
    }

    #[test]
    fn test_triangle_intersect() {
        let tri = Triangle {
            p1: Point::new(10.0, 5.0),
            p2: Point::new(0.0, 0.0),
            p3: Point::new(0.0, 10.0),
        };
        let rect = Rect::new(2.0, 2.0, 6.0, 6.0);
        assert!(tri.intersects_rect(&rect));

        let far_rect = Rect::new(50.0, 50.0, 5.0, 5.0);
        assert!(!tri.intersects_rect(&far_rect));
    }

    #[test]
    fn test_stroke_style_equality() {
        assert_eq!(StrokeStyle::Solid(1.0), StrokeStyle::Solid(1.0));
        assert_ne!(StrokeStyle::Solid(1.0), StrokeStyle::Solid(2.0));
        assert_eq!(
            StrokeStyle::Dashed(1.0, vec![5.0, 5.0]),
            StrokeStyle::Dashed(1.0, vec![5.0, 5.0])
        );
    }

    // ----------------------------------------------------------------
    // Integration tests
    // ----------------------------------------------------------------

    #[test]
    fn test_full_arrow_lifecycle() {
        let mut arrow = FlowArrow::new(
            Address::new(0x1000), Address::new(0x2000),
            FlowArrowType::ConditionalForward,
        );
        arrow.column = 0;

        // Create shape
        arrow.ensure_shape(50.0, 150.0, 300.0, 400.0);
        assert!(arrow.cached_shape.is_some());

        // Hit test
        assert!(arrow.intersects(Point::new(294.0, 50.0)));

        // Get display info
        let display = arrow.get_display_string();
        assert!(display.contains("0x1000"));

        // Stroke style
        assert_eq!(arrow.get_stroke_style(), StrokeStyle::Dashed(1.0, vec![5.0, 5.0]));

        // Make active
        arrow.active = true;
        assert_eq!(arrow.get_stroke_style(), StrokeStyle::Solid(2.0));

        // Reset and recreate
        arrow.reset_shape();
        assert!(arrow.cached_shape.is_none());
        arrow.ensure_shape(50.0, 150.0, 300.0, 400.0);
        assert!(arrow.cached_shape.is_some());
    }

    #[test]
    fn test_model_with_layout_and_panel() {
        let mut model = FlowArrowModel::new();
        model.add_arrow(FlowArrow::new(
            Address::new(0x1000), Address::new(0x3000), FlowArrowType::JumpForward,
        ));
        model.add_arrow(FlowArrow::new(
            Address::new(0x1000), Address::new(0x2000), FlowArrowType::ConditionalForward,
        ));
        model.add_arrow(FlowArrow::new(
            Address::new(0x1004), Address::new(0x1008), FlowArrowType::FallThrough,
        ));

        // Assign columns
        let arrows = model.get_arrows_mut();
        FlowArrowLayout::assign_columns(arrows);

        // Compute shapes
        let panel = FlowArrowPanel::new(200, 500);
        let mut addr_to_y = BTreeMap::new();
        addr_to_y.insert(0x1000, 10.0);
        addr_to_y.insert(0x1004, 20.0);
        addr_to_y.insert(0x1008, 30.0);
        addr_to_y.insert(0x2000, 80.0);
        addr_to_y.insert(0x3000, 120.0);

        let shapes = panel.compute_shapes(model.get_arrows(), &addr_to_y);
        assert_eq!(shapes.len(), 3);
    }
}
