//! `AddressFieldFactory` -- generates address fields in the listing.
//!
//! Ported from `ghidra.app.util.viewer.field.AddressFieldFactory`.

use crate::viewer::field::field_factory::{FieldFactory, BaseFieldFactory};

/// Field factory for generating address display fields in the listing.
///
/// Ported from `AddressFieldFactory.java`.
#[derive(Debug, Clone)]
pub struct AddressFieldFactory {
    base: BaseFieldFactory,
}

impl AddressFieldFactory {
    /// Create a new address field factory.
    pub fn new() -> Self {
        Self {
            base: BaseFieldFactory::new("Address"),
        }
    }
}

impl Default for AddressFieldFactory {
    fn default() -> Self {
        Self::new()
    }
}

impl FieldFactory for AddressFieldFactory {
    fn name(&self) -> &str {
        "Address"
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
        // Address fields accept any code unit
        !data_type.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_factory() {
        let f = AddressFieldFactory::new();
        assert_eq!(f.name(), "Address");
        assert!(f.is_enabled());
        assert!(f.accepts("instruction"));
    }
}
