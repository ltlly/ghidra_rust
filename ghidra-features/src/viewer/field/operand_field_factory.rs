//! `OperandFieldFactory` -- generates operand fields in the listing.
//!
//! Ported from `ghidra.app.util.viewer.field.OperandFieldFactory`.

use crate::viewer::field::field_factory::{FieldFactory, BaseFieldFactory};

/// Field factory for generating operand display fields.
///
/// Ported from `OperandFieldFactory.java`.
#[derive(Debug, Clone)]
pub struct OperandFieldFactory {
    base: BaseFieldFactory,
}

impl OperandFieldFactory {
    /// Create a new operand field factory.
    pub fn new() -> Self {
        Self {
            base: BaseFieldFactory::new("Operands"),
        }
    }
}

impl Default for OperandFieldFactory {
    fn default() -> Self {
        Self::new()
    }
}

impl FieldFactory for OperandFieldFactory {
    fn name(&self) -> &str {
        "Operands"
    }

    fn clone_factory(&self) -> Box<dyn FieldFactory> {
        Box::new(self.clone())
    }

    fn is_enabled(&self) -> bool {
        self.base.is_enabled()
    }

    fn set_enabled(&mut self, enabled: bool) {
        self.base.set_enabled(enabled);
    }

    fn start_x(&self) -> i32 {
        self.base.start_x()
    }

    fn set_start_x(&mut self, x: i32) {
        self.base.set_start_x(x);
    }

    fn width(&self) -> i32 {
        self.base.width()
    }

    fn set_width(&mut self, width: i32) {
        self.base.set_width(width);
    }

    fn accepts(&self, data_type: &str) -> bool {
        data_type == "instruction" || data_type == "data"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_operand_factory() {
        let f = OperandFieldFactory::new();
        assert_eq!(f.name(), "Operands");
        assert!(f.accepts("instruction"));
    }
}
