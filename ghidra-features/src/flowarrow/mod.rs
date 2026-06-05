//! Flow Arrow -- render flow arrows in the listing.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.flowarrow` Java package.
//!
//! Provides model-level logic for computing flow arrows (jump/call lines)
//! that connect source and destination addresses in a listing view.
//!
//! # Architecture
//!
//! - [`FlowArrowType`] -- kind of control flow (jump, call, fallthrough).
//! - [`FlowArrow`] -- a single arrow from source to destination.
//! - [`FlowArrowModel`] -- manages all arrows in a listing view.
//! - [`FlowArrowShape`] -- geometric representation of an arrow.
//! - [`FlowArrowPanel`] -- renderable panel model for arrow display.
//! - [`FlowArrowLayout`] -- assigns column lanes to prevent overlaps.

use ghidra_core::Address;
use std::collections::BTreeMap;

/// The type of flow arrow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowArrowType {
    /// Forward jump arrow.
    JumpForward,
    /// Backward jump arrow.
    JumpBackward,
    /// Conditional forward jump.
    ConditionalForward,
    /// Conditional backward jump.
    ConditionalBackward,
    /// Call arrow.
    Call,
    /// Fall-through arrow.
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
    pub fn is_fall_through(&self) -> bool {
        matches!(self, Self::FallThrough)
    }
}

/// A single flow arrow in the listing.
#[derive(Debug, Clone)]
pub struct FlowArrow {
    /// The source address.
    pub from: Address,
    /// The destination address.
    pub to: Address,
    /// The type of flow.
    pub arrow_type: FlowArrowType,
    /// The column position (for overlapping arrows).
    pub column: usize,
}

impl FlowArrow {
    /// Create a new flow arrow.
    pub fn new(from: Address, to: Address, arrow_type: FlowArrowType) -> Self {
        Self {
            from,
            to,
            arrow_type,
            column: 0,
        }
    }

    /// Whether this arrow points forward (to a higher address).
    pub fn is_forward(&self) -> bool {
        self.to > self.from
    }

    /// The distance of the arrow (absolute difference in addresses).
    pub fn distance(&self) -> u64 {
        if self.to > self.from {
            self.to.offset - self.from.offset
        } else {
            self.from.offset - self.to.offset
        }
    }
}

/// Manages flow arrows for a listing view.
#[derive(Debug, Default)]
pub struct FlowArrowModel {
    arrows: Vec<FlowArrow>,
}

impl FlowArrowModel {
    /// Create a new flow arrow model.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a flow arrow.
    pub fn add_arrow(&mut self, arrow: FlowArrow) {
        self.arrows.push(arrow);
    }

    /// Get all arrows.
    pub fn get_arrows(&self) -> &[FlowArrow] {
        &self.arrows
    }

    /// Get arrows originating from a specific address.
    pub fn get_arrows_from(&self, from: Address) -> Vec<&FlowArrow> {
        self.arrows.iter().filter(|a| a.from == from).collect()
    }

    /// Get arrows targeting a specific address.
    pub fn get_arrows_to(&self, to: Address) -> Vec<&FlowArrow> {
        self.arrows.iter().filter(|a| a.to == to).collect()
    }

    /// Clear all arrows.
    pub fn clear(&mut self) {
        self.arrows.clear();
    }

    /// Return the number of arrows.
    pub fn count(&self) -> usize {
        self.arrows.len()
    }

    /// Get arrows sorted by distance (closest first).
    pub fn get_arrows_sorted(&self) -> Vec<&FlowArrow> {
        let mut sorted: Vec<&FlowArrow> = self.arrows.iter().collect();
        sorted.sort_by_key(|a| a.distance());
        sorted
    }

    /// Get all conditional branch arrows.
    pub fn get_conditional_arrows(&self) -> Vec<&FlowArrow> {
        self.arrows.iter().filter(|a| a.arrow_type.is_conditional()).collect()
    }

    /// Get all call arrows.
    pub fn get_call_arrows(&self) -> Vec<&FlowArrow> {
        self.arrows.iter().filter(|a| a.arrow_type.is_call()).collect()
    }

    /// Remove arrows originating from a specific address.
    pub fn remove_arrows_from(&mut self, from: Address) {
        self.arrows.retain(|a| a.from != from);
    }

    /// Remove arrows targeting a specific address.
    pub fn remove_arrows_to(&mut self, to: Address) {
        self.arrows.retain(|a| a.to != to);
    }
}

// ============================================================================
// FlowArrowShape -- geometric representation
// ============================================================================

/// A point in 2D space used for arrow rendering.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Point {
    /// X coordinate.
    pub x: f64,
    /// Y coordinate.
    pub y: f64,
}

impl Point {
    /// Create a new point.
    pub fn new(x: f64, y: f64) -> Self {
        Self { x, y }
    }
}

/// A geometric shape representing a flow arrow.
#[derive(Debug, Clone)]
pub struct FlowArrowShape {
    /// The path points forming the arrow line.
    pub path: Vec<Point>,
    /// The arrowhead tip point.
    pub head: Point,
    /// The arrowhead left barb.
    pub head_left: Point,
    /// The arrowhead right barb.
    pub head_right: Point,
    /// The column lane this shape occupies.
    pub column: usize,
}

impl FlowArrowShape {
    /// Create a simple straight arrow shape.
    pub fn straight(from: Point, to: Point, column: usize) -> Self {
        let dx = to.x - from.x;
        let dy = to.y - from.y;
        let len = (dx * dx + dy * dy).sqrt();
        let (ux, uy) = if len > 0.0 { (dx / len, dy / len) } else { (0.0, 1.0) };
        let head_size = 5.0;
        let head_left = Point::new(
            to.x - ux * head_size + uy * head_size * 0.5,
            to.y - uy * head_size - ux * head_size * 0.5,
        );
        let head_right = Point::new(
            to.x - ux * head_size - uy * head_size * 0.5,
            to.y - uy * head_size + ux * head_size * 0.5,
        );
        Self { path: vec![from, to], head: to, head_left, head_right, column }
    }

    /// Create a curved arrow shape that arcs to the right.
    pub fn curved_right(from_y: f64, to_y: f64, base_x: f64, column: usize, column_offset: f64) -> Self {
        let x = base_x + column_offset * (column as f64 + 1.0);
        let mid_y = (from_y + to_y) / 2.0;
        let path = vec![
            Point::new(base_x, from_y),
            Point::new(x, from_y),
            Point::new(x, mid_y),
            Point::new(base_x, mid_y),
            Point::new(base_x, to_y),
        ];
        let head = Point::new(base_x, to_y);
        let head_size = 5.0;
        let head_left = Point::new(base_x - head_size * 0.5, to_y - head_size);
        let head_right = Point::new(base_x + head_size * 0.5, to_y - head_size);
        Self { path, head, head_left, head_right, column }
    }
}

// ============================================================================
// FlowArrowPanel -- renderable panel model
// ============================================================================

/// Configuration for a flow arrow panel.
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
        Self { width, height, column_offset: 12.0, max_columns: 8, base_x: 5.0 }
    }

    /// Set the column offset.
    pub fn with_column_offset(mut self, offset: f64) -> Self { self.column_offset = offset; self }

    /// Set the maximum number of columns.
    pub fn with_max_columns(mut self, max: usize) -> Self { self.max_columns = max; self }

    /// Compute arrow shapes for a set of arrows given address-to-y mappings.
    pub fn compute_shapes(&self, arrows: &[FlowArrow], addr_to_y: &BTreeMap<u64, f64>) -> Vec<FlowArrowShape> {
        let mut shapes = Vec::new();
        for arrow in arrows {
            let from_y = addr_to_y.get(&arrow.from.offset).copied().unwrap_or(0.0);
            let to_y = addr_to_y.get(&arrow.to.offset).copied().unwrap_or(0.0);
            let shape = match arrow.arrow_type {
                FlowArrowType::FallThrough => FlowArrowShape::straight(
                    Point::new(self.base_x, from_y), Point::new(self.base_x, to_y), arrow.column,
                ),
                _ => FlowArrowShape::curved_right(from_y, to_y, self.base_x, arrow.column, self.column_offset),
            };
            shapes.push(shape);
        }
        shapes
    }
}

// ============================================================================
// FlowArrowLayout -- assign columns to prevent overlaps
// ============================================================================

/// Assigns column lanes to arrows to prevent visual overlaps.
#[derive(Debug, Default)]
pub struct FlowArrowLayout;

impl FlowArrowLayout {
    /// Assign column values to arrows.
    pub fn assign_columns(arrows: &mut [FlowArrow]) {
        if arrows.is_empty() { return; }
        arrows.sort_by_key(|a| {
            let lo = a.from.offset.min(a.to.offset);
            let hi = a.from.offset.max(a.to.offset);
            (lo, hi)
        });
        let mut column_ends: Vec<u64> = Vec::new();
        for arrow in arrows.iter_mut() {
            let lo = arrow.from.offset.min(arrow.to.offset);
            let hi = arrow.from.offset.max(arrow.to.offset);
            let mut assigned = false;
            for (col, &end) in column_ends.iter().enumerate() {
                if end < lo {
                    arrow.column = col;
                    column_ends[col] = hi;
                    assigned = true;
                    break;
                }
            }
            if !assigned {
                arrow.column = column_ends.len();
                column_ends.push(hi);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flow_arrow_direction() {
        let fwd = FlowArrow::new(Address::new(0x1000), Address::new(0x2000), FlowArrowType::JumpForward);
        assert!(fwd.is_forward());
        let bwd = FlowArrow::new(Address::new(0x2000), Address::new(0x1000), FlowArrowType::JumpBackward);
        assert!(!bwd.is_forward());
    }

    #[test]
    fn test_flow_arrow_distance() {
        let arrow = FlowArrow::new(Address::new(0x1000), Address::new(0x2000), FlowArrowType::JumpForward);
        assert_eq!(arrow.distance(), 0x1000);
    }

    #[test]
    fn test_flow_arrow_model() {
        let mut model = FlowArrowModel::new();
        model.add_arrow(FlowArrow::new(Address::new(0x1000), Address::new(0x2000), FlowArrowType::JumpForward));
        model.add_arrow(FlowArrow::new(Address::new(0x3000), Address::new(0x1000), FlowArrowType::JumpBackward));
        assert_eq!(model.count(), 2);
        assert_eq!(model.get_arrows_from(Address::new(0x1000)).len(), 1);
        assert_eq!(model.get_arrows_to(Address::new(0x1000)).len(), 1);
    }

    #[test]
    fn test_flow_arrow_type_properties() {
        assert!(FlowArrowType::ConditionalForward.is_conditional());
        assert!(!FlowArrowType::JumpForward.is_conditional());
        assert!(FlowArrowType::Call.is_call());
        assert!(FlowArrowType::JumpForward.is_jump());
        assert!(FlowArrowType::FallThrough.is_fall_through());
    }

    #[test]
    fn test_flow_arrow_model_sorted() {
        let mut model = FlowArrowModel::new();
        model.add_arrow(FlowArrow::new(Address::new(0x1000), Address::new(0x5000), FlowArrowType::JumpForward));
        model.add_arrow(FlowArrow::new(Address::new(0x1000), Address::new(0x1100), FlowArrowType::JumpForward));
        let sorted = model.get_arrows_sorted();
        assert_eq!(sorted[0].distance(), 0x100);
        assert_eq!(sorted[1].distance(), 0x4000);
    }

    #[test]
    fn test_flow_arrow_model_remove() {
        let mut model = FlowArrowModel::new();
        model.add_arrow(FlowArrow::new(Address::new(0x1000), Address::new(0x2000), FlowArrowType::JumpForward));
        model.add_arrow(FlowArrow::new(Address::new(0x3000), Address::new(0x1000), FlowArrowType::JumpBackward));
        model.remove_arrows_from(Address::new(0x1000));
        assert_eq!(model.count(), 1);
    }

    #[test]
    fn test_flow_arrow_shape_straight() {
        let shape = FlowArrowShape::straight(Point::new(10.0, 100.0), Point::new(10.0, 200.0), 0);
        assert_eq!(shape.path.len(), 2);
        assert_eq!(shape.column, 0);
    }

    #[test]
    fn test_flow_arrow_shape_curved() {
        let shape = FlowArrowShape::curved_right(100.0, 200.0, 5.0, 1, 12.0);
        assert_eq!(shape.path.len(), 5);
        assert_eq!(shape.column, 1);
    }

    #[test]
    fn test_flow_arrow_panel() {
        let panel = FlowArrowPanel::new(50, 300).with_column_offset(10.0).with_max_columns(4);
        assert_eq!(panel.width, 50);
        assert_eq!(panel.column_offset, 10.0);
    }

    #[test]
    fn test_flow_arrow_panel_compute_shapes() {
        let panel = FlowArrowPanel::new(100, 500);
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

    #[test]
    fn test_flow_arrow_layout() {
        let mut arrows = vec![
            FlowArrow::new(Address::new(0x1000), Address::new(0x3000), FlowArrowType::JumpForward),
            FlowArrow::new(Address::new(0x2000), Address::new(0x4000), FlowArrowType::JumpForward),
            FlowArrow::new(Address::new(0x1100), Address::new(0x1500), FlowArrowType::JumpForward),
        ];
        FlowArrowLayout::assign_columns(&mut arrows);
        assert_ne!(arrows[0].column, arrows[2].column);
    }

    #[test]
    fn test_point() {
        let p = Point::new(3.0, 4.0);
        assert_eq!(p.x, 3.0);
        assert_eq!(p.y, 4.0);
    }

    #[test]
    fn test_conditional_flow_arrow() {
        let arrow = ConditionalFlowArrow::new(
            Address::new(0x1000),
            Address::new(0x2000),
            true,
        );
        assert!(arrow.is_conditional);
        assert_eq!(arrow.arrow_type(), FlowArrowType::ConditionalForward);
        assert!(arrow.fallthrough_addr.is_some()); // forward => has fallthrough
    }

    #[test]
    fn test_conditional_flow_arrow_backward() {
        let arrow = ConditionalFlowArrow::new(
            Address::new(0x2000),
            Address::new(0x1000),
            false,
        );
        assert_eq!(arrow.arrow_type(), FlowArrowType::ConditionalBackward);
    }

    #[test]
    fn test_default_flow_arrow() {
        let arrow = DefaultFlowArrow::new(
            Address::new(0x1000),
            Address::new(0x2000),
        );
        assert_eq!(arrow.arrow_type(), FlowArrowType::JumpForward);
    }

    #[test]
    fn test_default_flow_arrow_backward() {
        let arrow = DefaultFlowArrow::new(
            Address::new(0x3000),
            Address::new(0x1000),
        );
        assert_eq!(arrow.arrow_type(), FlowArrowType::JumpBackward);
    }

    #[test]
    fn test_fallthrough_flow_arrow() {
        let arrow = FallthroughFlowArrow::new(
            Address::new(0x1000),
            Address::new(0x1004),
        );
        assert_eq!(arrow.arrow_type(), FlowArrowType::FallThrough);
        assert!(arrow.is_forward());
        assert_eq!(arrow.distance(), 4);
    }

    #[test]
    fn test_fallthrough_flow_arrow_create() {
        let arrow = FallthroughFlowArrow::new(
            Address::new(0x1000),
            Address::new(0x1005),
        );
        assert!(arrow.to > arrow.from);
        assert_eq!(arrow.arrow_type(), FlowArrowType::FallThrough);
    }

    #[test]
    fn test_flow_arrow_shape_factory() {
        let factory = FlowArrowShapeFactory::new(5.0, 12.0);
        let arrow = FlowArrow::new(
            Address::new(0x1000),
            Address::new(0x2000),
            FlowArrowType::FallThrough,
        );
        let mut addr_to_y = BTreeMap::new();
        addr_to_y.insert(0x1000, 10.0);
        addr_to_y.insert(0x2000, 50.0);
        let shape = factory.create_shape(&arrow, &addr_to_y);
        assert_eq!(shape.column, 0);
    }

    #[test]
    fn test_flow_arrow_shape_factory_backward() {
        let factory = FlowArrowShapeFactory::new(5.0, 12.0);
        let arrow = FlowArrow::new(
            Address::new(0x2000),
            Address::new(0x1000),
            FlowArrowType::JumpBackward,
        );
        let mut addr_to_y = BTreeMap::new();
        addr_to_y.insert(0x1000, 50.0);
        addr_to_y.insert(0x2000, 10.0);
        let shape = factory.create_shape(&arrow, &addr_to_y);
        assert_eq!(shape.path.len(), 5); // curved
    }

    #[test]
    fn test_flow_arrow_model_conditional_and_call_filters() {
        let mut model = FlowArrowModel::new();
        model.add_arrow(FlowArrow::new(Address::new(0x1000), Address::new(0x2000), FlowArrowType::ConditionalForward));
        model.add_arrow(FlowArrow::new(Address::new(0x3000), Address::new(0x4000), FlowArrowType::Call));
        model.add_arrow(FlowArrow::new(Address::new(0x5000), Address::new(0x6000), FlowArrowType::JumpForward));
        assert_eq!(model.get_conditional_arrows().len(), 1);
        assert_eq!(model.get_call_arrows().len(), 1);
    }

    #[test]
    fn test_flow_arrow_model_remove_to() {
        let mut model = FlowArrowModel::new();
        model.add_arrow(FlowArrow::new(Address::new(0x1000), Address::new(0x2000), FlowArrowType::JumpForward));
        model.add_arrow(FlowArrow::new(Address::new(0x3000), Address::new(0x2000), FlowArrowType::JumpForward));
        model.remove_arrows_to(Address::new(0x2000));
        assert_eq!(model.count(), 0);
    }
}

// ============================================================================
// ConditionalFlowArrow -- ported from ConditionalFlowArrow.java
// ============================================================================

/// A conditional branch flow arrow.
///
/// Ported from Ghidra's `ConditionalFlowArrow.java`.
#[derive(Debug, Clone)]
pub struct ConditionalFlowArrow {
    /// The source address.
    pub from: Address,
    /// The branch target address.
    pub to: Address,
    /// Whether this is a conditional branch.
    pub is_conditional: bool,
    /// The fallthrough address (if the branch is not taken).
    pub fallthrough_addr: Option<Address>,
}

impl ConditionalFlowArrow {
    /// Create a new conditional flow arrow.
    pub fn new(from: Address, to: Address, forward: bool) -> Self {
        Self {
            from,
            to,
            is_conditional: true,
            fallthrough_addr: if forward { Some(Address::new(from.offset + 1)) } else { None },
        }
    }

    /// Create with an explicit fallthrough address.
    pub fn with_fallthrough(from: Address, to: Address, fallthrough: Address) -> Self {
        Self {
            from,
            to,
            is_conditional: true,
            fallthrough_addr: Some(fallthrough),
        }
    }

    /// The arrow type for this conditional flow.
    pub fn arrow_type(&self) -> FlowArrowType {
        if self.to > self.from {
            FlowArrowType::ConditionalForward
        } else {
            FlowArrowType::ConditionalBackward
        }
    }

    /// Convert to a generic FlowArrow.
    pub fn to_flow_arrow(&self) -> FlowArrow {
        FlowArrow::new(self.from, self.to, self.arrow_type())
    }
}

// ============================================================================
// DefaultFlowArrow -- ported from DefaultFlowArrow.java
// ============================================================================

/// An unconditional jump flow arrow.
///
/// Ported from Ghidra's `DefaultFlowArrow.java`.
#[derive(Debug, Clone)]
pub struct DefaultFlowArrow {
    /// The source address.
    pub from: Address,
    /// The destination address.
    pub to: Address,
}

impl DefaultFlowArrow {
    /// Create a new default (unconditional jump) flow arrow.
    pub fn new(from: Address, to: Address) -> Self {
        Self { from, to }
    }

    /// The arrow type.
    pub fn arrow_type(&self) -> FlowArrowType {
        if self.to > self.from {
            FlowArrowType::JumpForward
        } else {
            FlowArrowType::JumpBackward
        }
    }

    /// Convert to a generic FlowArrow.
    pub fn to_flow_arrow(&self) -> FlowArrow {
        FlowArrow::new(self.from, self.to, self.arrow_type())
    }
}

// ============================================================================
// FallthroughFlowArrow -- ported from FallthroughFlowArrow.java
// ============================================================================

/// A fallthrough flow arrow (sequential execution).
///
/// Ported from Ghidra's `FallthroughFlowArrow.java`.
#[derive(Debug, Clone)]
pub struct FallthroughFlowArrow {
    /// The source address.
    pub from: Address,
    /// The fallthrough address (next instruction).
    pub to: Address,
}

impl FallthroughFlowArrow {
    /// Create a new fallthrough flow arrow.
    pub fn new(from: Address, to: Address) -> Self {
        Self { from, to }
    }

    /// The arrow type (always FallThrough).
    pub fn arrow_type(&self) -> FlowArrowType {
        FlowArrowType::FallThrough
    }

    /// Whether this arrow points forward.
    pub fn is_forward(&self) -> bool {
        self.to > self.from
    }

    /// The distance.
    pub fn distance(&self) -> u64 {
        if self.to > self.from {
            self.to.offset - self.from.offset
        } else {
            self.from.offset - self.to.offset
        }
    }

    /// Convert to a generic FlowArrow.
    pub fn to_flow_arrow(&self) -> FlowArrow {
        FlowArrow::new(self.from, self.to, FlowArrowType::FallThrough)
    }
}

// ============================================================================
// FlowArrowShapeFactory -- ported from FlowArrowShapeFactory.java
// ============================================================================

/// Factory for creating arrow shapes from flow arrows.
///
/// Ported from Ghidra's `FlowArrowShapeFactory.java`.
#[derive(Debug, Clone)]
pub struct FlowArrowShapeFactory {
    /// Base x position.
    pub base_x: f64,
    /// Column offset per lane.
    pub column_offset: f64,
}

impl FlowArrowShapeFactory {
    /// Create a new shape factory.
    pub fn new(base_x: f64, column_offset: f64) -> Self {
        Self { base_x, column_offset }
    }

    /// Create a shape for a flow arrow given address-to-y mappings.
    pub fn create_shape(
        &self,
        arrow: &FlowArrow,
        addr_to_y: &BTreeMap<u64, f64>,
    ) -> FlowArrowShape {
        let from_y = addr_to_y.get(&arrow.from.offset).copied().unwrap_or(0.0);
        let to_y = addr_to_y.get(&arrow.to.offset).copied().unwrap_or(0.0);

        match arrow.arrow_type {
            FlowArrowType::FallThrough => FlowArrowShape::straight(
                Point::new(self.base_x, from_y),
                Point::new(self.base_x, to_y),
                arrow.column,
            ),
            _ => FlowArrowShape::curved_right(
                from_y,
                to_y,
                self.base_x,
                arrow.column,
                self.column_offset,
            ),
        }
    }

    /// Create shapes for multiple arrows.
    pub fn create_shapes(
        &self,
        arrows: &[FlowArrow],
        addr_to_y: &BTreeMap<u64, f64>,
    ) -> Vec<FlowArrowShape> {
        arrows.iter().map(|a| self.create_shape(a, addr_to_y)).collect()
    }
}
