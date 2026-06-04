//! Flow Arrow -- render flow arrows in the listing.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.flowarrow` Java package.
//!
//! Provides model-level logic for computing flow arrows (jump/call lines)
//! that connect source and destination addresses in a listing view.

use ghidra_core::Address;

/// The type of flow arrow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowArrowType {
    /// Forward jump arrow.
    JumpForward,
    /// Backward jump arrow.
    JumpBackward,
    /// Call arrow.
    Call,
    /// Fall-through arrow.
    FallThrough,
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
        model.add_arrow(FlowArrow::new(
            Address::new(0x1000),
            Address::new(0x2000),
            FlowArrowType::JumpForward,
        ));
        model.add_arrow(FlowArrow::new(
            Address::new(0x3000),
            Address::new(0x1000),
            FlowArrowType::JumpBackward,
        ));
        assert_eq!(model.count(), 2);
        assert_eq!(model.get_arrows_from(Address::new(0x1000)).len(), 1);
        assert_eq!(model.get_arrows_to(Address::new(0x1000)).len(), 1);
    }
}
