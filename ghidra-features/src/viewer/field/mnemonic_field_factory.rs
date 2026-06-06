//! `MnemonicFieldFactory` -- generates mnemonic fields in the listing.
//!
//! Ported from `ghidra.app.util.viewer.field.MnemonicFieldFactory`.

use crate::viewer::field::field_factory::{FieldFactory, BaseFieldFactory};

/// Field factory for generating instruction mnemonic display fields.
///
/// Ported from `MnemonicFieldFactory.java`.
#[derive(Debug, Clone)]
pub struct MnemonicFieldFactory {
    base: BaseFieldFactory,
}

impl MnemonicFieldFactory {
    /// Create a new mnemonic field factory.
    pub fn new() -> Self {
        Self {
            base: BaseFieldFactory::new("Mnemonic"),
        }
    }
}

impl Default for MnemonicFieldFactory {
    fn default() -> Self {
        Self::new()
    }
}

impl FieldFactory for MnemonicFieldFactory {
    fn name(&self) -> &str {
        "Mnemonic"
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
    fn test_mnemonic_factory() {
        let f = MnemonicFieldFactory::new();
        assert_eq!(f.name(), "Mnemonic");
        assert!(f.accepts("instruction"));
        assert!(f.accepts("data"));
        assert!(!f.accepts("comment"));
    }
}
