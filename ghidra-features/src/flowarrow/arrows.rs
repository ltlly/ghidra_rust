//! Flow arrow model for visualizing control flow in the listing.
//!
//! Ported from `ghidra.app.plugin.core.flowarrow` Java package.
//!
//! Provides the data model for flow arrows that show jump/call/return
//! relationships between code locations in the code browser listing.

/// The direction of a flow arrow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FlowArrowDirection {
    /// Forward arrow (jump/call to a later address).
    Forward,
    /// Backward arrow (jump to an earlier address).
    Backward,
}

/// The type of control flow the arrow represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FlowArrowKind {
    /// Unconditional jump.
    Jump,
    /// Conditional jump (branch taken/not taken).
    ConditionalJump,
    /// Function call.
    Call,
    /// Function return.
    Return,
    /// Fall-through (sequential execution).
    FallThrough,
}

impl FlowArrowKind {
    /// Whether this flow kind represents a transfer of control.
    pub fn is_transfer(&self) -> bool {
        !matches!(self, Self::FallThrough)
    }

    /// Whether this flow kind represents a call.
    pub fn is_call(&self) -> bool {
        matches!(self, Self::Call)
    }

    /// Whether this flow kind represents a return.
    pub fn is_return(&self) -> bool {
        matches!(self, Self::Return)
    }
}

/// A single flow arrow connecting two code locations.
///
/// Ported from flow arrow data structures in `ghidra.app.plugin.core.flowarrow`.
#[derive(Debug, Clone)]
pub struct FlowArrow {
    /// The source address (where the flow starts).
    pub from_address: u64,
    /// The destination address (where the flow goes).
    pub to_address: u64,
    /// The kind of control flow.
    pub kind: FlowArrowKind,
    /// The direction relative to the current view.
    pub direction: FlowArrowDirection,
    /// Whether this arrow is currently highlighted.
    pub highlighted: bool,
}

impl FlowArrow {
    /// Create a new flow arrow.
    pub fn new(from_address: u64, to_address: u64, kind: FlowArrowKind) -> Self {
        let direction = if to_address >= from_address {
            FlowArrowDirection::Forward
        } else {
            FlowArrowDirection::Backward
        };

        Self {
            from_address,
            to_address,
            kind,
            direction,
            highlighted: false,
        }
    }

    /// The span of the arrow (number of bytes between source and destination).
    pub fn span(&self) -> u64 {
        if self.to_address >= self.from_address {
            self.to_address - self.from_address
        } else {
            self.from_address - self.to_address
        }
    }
}

/// Manages a collection of flow arrows for display.
///
/// Ported from the flow arrow provider logic in the code browser plugin.
#[derive(Debug)]
pub struct FlowArrowModel {
    /// All flow arrows.
    arrows: Vec<FlowArrow>,
    /// Maximum number of arrows to display.
    max_arrows: usize,
}

impl FlowArrowModel {
    /// Create a new flow arrow model.
    pub fn new() -> Self {
        Self {
            arrows: Vec::new(),
            max_arrows: 1000,
        }
    }

    /// Add a flow arrow.
    pub fn add_arrow(&mut self, arrow: FlowArrow) {
        if self.arrows.len() < self.max_arrows {
            self.arrows.push(arrow);
        }
    }

    /// Add a batch of flow arrows.
    pub fn add_arrows(&mut self, new_arrows: Vec<FlowArrow>) {
        for arrow in new_arrows {
            self.add_arrow(arrow);
        }
    }

    /// Get all arrows.
    pub fn arrows(&self) -> &[FlowArrow] {
        &self.arrows
    }

    /// Get arrows originating from a specific address.
    pub fn arrows_from(&self, address: u64) -> Vec<&FlowArrow> {
        self.arrows.iter().filter(|a| a.from_address == address).collect()
    }

    /// Get arrows targeting a specific address.
    pub fn arrows_to(&self, address: u64) -> Vec<&FlowArrow> {
        self.arrows.iter().filter(|a| a.to_address == address).collect()
    }

    /// Get forward arrows only.
    pub fn forward_arrows(&self) -> Vec<&FlowArrow> {
        self.arrows
            .iter()
            .filter(|a| a.direction == FlowArrowDirection::Forward)
            .collect()
    }

    /// Get backward arrows only.
    pub fn backward_arrows(&self) -> Vec<&FlowArrow> {
        self.arrows
            .iter()
            .filter(|a| a.direction == FlowArrowDirection::Backward)
            .collect()
    }

    /// Get the maximum number of arrows.
    pub fn max_arrows(&self) -> usize {
        self.max_arrows
    }

    /// Set the maximum number of arrows.
    pub fn set_max_arrows(&mut self, max: usize) {
        self.max_arrows = max;
        self.arrows.truncate(max);
    }

    /// Clear all arrows.
    pub fn clear(&mut self) {
        self.arrows.clear();
    }

    /// Number of arrows.
    pub fn len(&self) -> usize {
        self.arrows.len()
    }

    /// Whether the model is empty.
    pub fn is_empty(&self) -> bool {
        self.arrows.is_empty()
    }

    /// Highlight an arrow by from/to addresses.
    pub fn highlight(&mut self, from: u64, to: u64) {
        for arrow in &mut self.arrows {
            arrow.highlighted = arrow.from_address == from && arrow.to_address == to;
        }
    }

    /// Clear all highlights.
    pub fn clear_highlights(&mut self) {
        for arrow in &mut self.arrows {
            arrow.highlighted = false;
        }
    }
}

impl Default for FlowArrowModel {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flow_arrow_new() {
        let arrow = FlowArrow::new(0x1000, 0x1100, FlowArrowKind::Jump);
        assert_eq!(arrow.direction, FlowArrowDirection::Forward);
        assert_eq!(arrow.span(), 0x100);

        let back = FlowArrow::new(0x2000, 0x1000, FlowArrowKind::ConditionalJump);
        assert_eq!(back.direction, FlowArrowDirection::Backward);
        assert_eq!(back.span(), 0x1000);
    }

    #[test]
    fn test_flow_arrow_kind() {
        assert!(FlowArrowKind::Call.is_call());
        assert!(FlowArrowKind::Return.is_return());
        assert!(FlowArrowKind::Jump.is_transfer());
        assert!(!FlowArrowKind::FallThrough.is_transfer());
    }

    #[test]
    fn test_flow_arrow_model() {
        let mut model = FlowArrowModel::new();
        assert!(model.is_empty());

        model.add_arrow(FlowArrow::new(0x1000, 0x1100, FlowArrowKind::Jump));
        model.add_arrow(FlowArrow::new(0x2000, 0x1500, FlowArrowKind::ConditionalJump));
        assert_eq!(model.len(), 2);
    }

    #[test]
    fn test_flow_arrow_model_filter() {
        let mut model = FlowArrowModel::new();
        model.add_arrow(FlowArrow::new(0x1000, 0x1100, FlowArrowKind::Jump));
        model.add_arrow(FlowArrow::new(0x2000, 0x1500, FlowArrowKind::ConditionalJump));
        model.add_arrow(FlowArrow::new(0x3000, 0x2500, FlowArrowKind::Call));

        let from_1000 = model.arrows_from(0x1000);
        assert_eq!(from_1000.len(), 1);

        let fwd = model.forward_arrows();
        assert_eq!(fwd.len(), 2); // Jump and Call are forward

        let bwd = model.backward_arrows();
        assert_eq!(bwd.len(), 1); // ConditionalJump 0x2000->0x1500 is backward
    }

    #[test]
    fn test_flow_arrow_model_max() {
        let mut model = FlowArrowModel::new();
        model.set_max_arrows(2);
        model.add_arrow(FlowArrow::new(0x1000, 0x1100, FlowArrowKind::Jump));
        model.add_arrow(FlowArrow::new(0x2000, 0x2100, FlowArrowKind::Jump));
        model.add_arrow(FlowArrow::new(0x3000, 0x3100, FlowArrowKind::Jump));
        assert_eq!(model.len(), 2);
    }

    #[test]
    fn test_flow_arrow_model_highlight() {
        let mut model = FlowArrowModel::new();
        model.add_arrow(FlowArrow::new(0x1000, 0x1100, FlowArrowKind::Jump));
        model.add_arrow(FlowArrow::new(0x2000, 0x2100, FlowArrowKind::Jump));

        model.highlight(0x1000, 0x1100);
        assert!(model.arrows()[0].highlighted);
        assert!(!model.arrows()[1].highlighted);

        model.clear_highlights();
        assert!(!model.arrows()[0].highlighted);
    }
}
