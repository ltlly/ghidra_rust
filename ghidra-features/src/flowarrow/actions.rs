//! Flow arrow actions and configuration.
//!
//! Ported from Ghidra's flow arrow action classes.

use serde::{Deserialize, Serialize};

/// Types of flow arrows displayed in the listing margin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArrowType {
    /// Fall-through arrow (sequential flow).
    FallThrough,
    /// Conditional branch arrow.
    ConditionalJump,
    /// Unconditional jump arrow.
    UnconditionalJump,
    /// Call arrow.
    Call,
    /// Return arrow.
    Return,
}

impl ArrowType {
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::FallThrough => "Fall Through",
            Self::ConditionalJump => "Conditional Jump",
            Self::UnconditionalJump => "Unconditional Jump",
            Self::Call => "Call",
            Self::Return => "Return",
        }
    }
}

/// Configuration for flow arrow display.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowArrowConfig {
    /// Show fall-through arrows.
    pub show_fall_through: bool,
    /// Show conditional jump arrows.
    pub show_conditional_jump: bool,
    /// Show unconditional jump arrows.
    pub show_unconditional_jump: bool,
    /// Show call arrows.
    pub show_call: bool,
    /// Maximum arrow length (in lines).
    pub max_arrow_length: usize,
}

impl Default for FlowArrowConfig {
    fn default() -> Self {
        Self {
            show_fall_through: false,
            show_conditional_jump: true,
            show_unconditional_jump: true,
            show_call: false,
            max_arrow_length: 100,
        }
    }
}

/// A flow arrow displayed in the listing margin.
#[derive(Debug, Clone)]
pub struct FlowArrow {
    /// Source line number.
    pub from_line: usize,
    /// Destination line number.
    pub to_line: usize,
    /// Type of arrow.
    pub arrow_type: ArrowType,
}

impl FlowArrow {
    pub fn new(from_line: usize, to_line: usize, arrow_type: ArrowType) -> Self {
        Self { from_line, to_line, arrow_type }
    }
    /// Return the span (number of lines) of this arrow.
    pub fn span(&self) -> usize {
        if self.to_line >= self.from_line {
            self.to_line - self.from_line
        } else {
            self.from_line - self.to_line
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arrow_type_display() {
        assert_eq!(ArrowType::FallThrough.display_name(), "Fall Through");
        assert_eq!(ArrowType::ConditionalJump.display_name(), "Conditional Jump");
    }

    #[test]
    fn test_flow_arrow_config_default() {
        let config = FlowArrowConfig::default();
        assert!(!config.show_fall_through);
        assert!(config.show_conditional_jump);
        assert_eq!(config.max_arrow_length, 100);
    }

    #[test]
    fn test_flow_arrow() {
        let arrow = FlowArrow::new(10, 25, ArrowType::ConditionalJump);
        assert_eq!(arrow.span(), 15);
    }

    #[test]
    fn test_flow_arrow_reverse() {
        let arrow = FlowArrow::new(25, 10, ArrowType::UnconditionalJump);
        assert_eq!(arrow.span(), 15);
    }
}
