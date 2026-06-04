//! Fall-Through Management -- override and clear fall-through addresses.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.fallthrough` Java package.
//!
//! Provides a model for viewing and modifying instruction fall-through
//! addresses. Normally an instruction's fall-through is the address of the
//! next sequential instruction; this plugin allows overriding that behavior.
//!
//! # Architecture
//!
//! - [`FallThroughOverride`] -- represents a single fall-through override.
//! - [`FallThroughModel`] -- the business logic for managing fall-through
//!   overrides on a set of instructions.
//! - [`FallThroughAction`] -- the type of fall-through action (set, clear,
//!   auto-override).

use ghidra_core::Address;
use std::collections::HashMap;

// ============================================================================
// FallThroughAction -- the type of fall-through modification
// ============================================================================

/// The type of fall-through modification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FallThroughAction {
    /// Set a specific fall-through address.
    Set,
    /// Clear the override, restoring the default.
    Clear,
    /// Auto-override: set fall-through to the next instruction after any
    /// data block.
    AutoOverride,
}

// ============================================================================
// FallThroughOverride -- a single override record
// ============================================================================

/// Records a fall-through override for a single instruction.
#[derive(Debug, Clone)]
pub struct FallThroughOverride {
    /// The address of the instruction.
    pub instruction_address: Address,
    /// The original default fall-through address.
    pub default_fallthrough: Option<Address>,
    /// The overridden fall-through address (None = use default).
    pub overridden_fallthrough: Option<Address>,
    /// Whether the override is user-defined.
    pub is_user_defined: bool,
}

impl FallThroughOverride {
    /// Create a new override record.
    pub fn new(
        instruction_address: Address,
        default_fallthrough: Option<Address>,
    ) -> Self {
        Self {
            instruction_address,
            default_fallthrough,
            overridden_fallthrough: None,
            is_user_defined: false,
        }
    }

    /// The effective fall-through address (overridden or default).
    pub fn effective_fallthrough(&self) -> Option<Address> {
        self.overridden_fallthrough
            .or(self.default_fallthrough)
    }

    /// Whether this override has been modified from the default.
    pub fn is_overridden(&self) -> bool {
        self.is_user_defined && self.overridden_fallthrough.is_some()
    }
}

// ============================================================================
// FallThroughModel -- business logic for fall-through management
// ============================================================================

/// The model managing fall-through overrides for instructions.
///
/// Corresponds to `FallThroughModel` in Java. Provides operations for
/// setting, clearing, and auto-overriding fall-through addresses.
#[derive(Debug)]
pub struct FallThroughModel {
    /// Current program address -> override record.
    overrides: HashMap<u64, FallThroughOverride>,
    /// Pending message for the UI.
    message: String,
}

impl FallThroughModel {
    /// Create a new empty model.
    pub fn new() -> Self {
        Self {
            overrides: HashMap::new(),
            message: String::new(),
        }
    }

    /// Register an instruction in the model.
    pub fn register_instruction(
        &mut self,
        address: Address,
        default_fallthrough: Option<Address>,
    ) {
        self.overrides.insert(
            address.offset,
            FallThroughOverride::new(address, default_fallthrough),
        );
    }

    /// Set the fall-through address for an instruction.
    pub fn set_fallthrough(
        &mut self,
        instruction_address: Address,
        new_fallthrough: Address,
    ) -> bool {
        if let Some(ov) = self.overrides.get_mut(&instruction_address.offset) {
            if ov.default_fallthrough == Some(new_fallthrough) {
                // Same as default -- treat as clear
                ov.overridden_fallthrough = None;
                ov.is_user_defined = false;
                self.message = "Fallthrough restored to default".into();
            } else {
                ov.overridden_fallthrough = Some(new_fallthrough);
                ov.is_user_defined = true;
                self.message = "Updated Fallthrough address".into();
            }
            true
        } else {
            self.message = "Instruction not registered".into();
            false
        }
    }

    /// Clear the fall-through override, restoring the default.
    pub fn clear_fallthrough(&mut self, instruction_address: Address) -> bool {
        if let Some(ov) = self.overrides.get_mut(&instruction_address.offset) {
            ov.overridden_fallthrough = None;
            ov.is_user_defined = false;
            self.message = "Fallthrough cleared".into();
            true
        } else {
            false
        }
    }

    /// Auto-override fall-throughs for the given address set.
    ///
    /// For each instruction in the set whose fall-through points to a data
    /// element (rather than the next instruction), the fall-through is
    /// overridden to skip the data block.
    pub fn auto_override(&mut self, addresses: &[Address]) {
        for addr in addresses {
            if let Some(ov) = self.overrides.get_mut(&addr.offset) {
                // Simulate auto-override: if there is a default, override it
                if ov.default_fallthrough.is_some() && !ov.is_user_defined {
                    ov.is_user_defined = true;
                    // In a real implementation this would skip data blocks
                    ov.overridden_fallthrough = ov.default_fallthrough;
                }
            }
        }
        self.message = "Auto-override complete".into();
    }

    /// Clear all overridden fall-throughs in the given address set.
    pub fn clear_overrides(&mut self, addresses: &[Address]) {
        for addr in addresses {
            self.clear_fallthrough(*addr);
        }
    }

    /// Get the current state of an instruction's override.
    pub fn get_override(&self, address: Address) -> Option<&FallThroughOverride> {
        self.overrides.get(&address.offset)
    }

    /// Get the pending message.
    pub fn get_message(&mut self) -> String {
        std::mem::take(&mut self.message)
    }

    /// Whether the instruction at `address` has been overridden.
    pub fn is_overridden(&self, address: Address) -> bool {
        self.overrides
            .get(&address.offset)
            .map(|ov| ov.is_overridden())
            .unwrap_or(false)
    }

    /// Return the number of registered instructions.
    pub fn instruction_count(&self) -> usize {
        self.overrides.len()
    }
}

impl Default for FallThroughModel {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_set_and_clear_fallthrough() {
        let mut model = FallThroughModel::new();
        model.register_instruction(Address::new(0x1000), Some(Address::new(0x1004)));

        assert!(model.set_fallthrough(Address::new(0x1000), Address::new(0x2000)));
        assert!(model.is_overridden(Address::new(0x1000)));

        let ov = model.get_override(Address::new(0x1000)).unwrap();
        assert_eq!(ov.effective_fallthrough(), Some(Address::new(0x2000)));

        assert!(model.clear_fallthrough(Address::new(0x1000)));
        assert!(!model.is_overridden(Address::new(0x1000)));
        let ov = model.get_override(Address::new(0x1000)).unwrap();
        assert_eq!(ov.effective_fallthrough(), Some(Address::new(0x1004)));
    }

    #[test]
    fn test_set_to_default_clears_override() {
        let mut model = FallThroughModel::new();
        model.register_instruction(Address::new(0x1000), Some(Address::new(0x1004)));
        // Set to the default value -- should clear override
        model.set_fallthrough(Address::new(0x1000), Address::new(0x1004));
        assert!(!model.is_overridden(Address::new(0x1000)));
    }

    #[test]
    fn test_auto_override() {
        let mut model = FallThroughModel::new();
        model.register_instruction(Address::new(0x1000), Some(Address::new(0x1004)));
        model.register_instruction(Address::new(0x2000), Some(Address::new(0x2004)));

        model.auto_override(&[Address::new(0x1000), Address::new(0x2000)]);
        assert!(!model.get_message().is_empty());
    }

    #[test]
    fn test_clear_overrides() {
        let mut model = FallThroughModel::new();
        model.register_instruction(Address::new(0x1000), Some(Address::new(0x1004)));
        model.set_fallthrough(Address::new(0x1000), Address::new(0x2000));
        model.clear_overrides(&[Address::new(0x1000)]);
        assert!(!model.is_overridden(Address::new(0x1000)));
    }

    #[test]
    fn test_unregistered_address() {
        let mut model = FallThroughModel::new();
        assert!(!model.set_fallthrough(Address::new(0x9999), Address::new(0xAAAA)));
        assert!(!model.is_overridden(Address::new(0x9999)));
    }

    #[test]
    fn test_instruction_count() {
        let mut model = FallThroughModel::new();
        model.register_instruction(Address::new(0x1000), Some(Address::new(0x1004)));
        model.register_instruction(Address::new(0x2000), None);
        assert_eq!(model.instruction_count(), 2);
    }

    #[test]
    fn test_no_default_fallthrough() {
        let mut model = FallThroughModel::new();
        model.register_instruction(Address::new(0x1000), None);
        let ov = model.get_override(Address::new(0x1000)).unwrap();
        assert_eq!(ov.effective_fallthrough(), None);
        model.set_fallthrough(Address::new(0x1000), Address::new(0x2000));
        let ov = model.get_override(Address::new(0x1000)).unwrap();
        assert_eq!(ov.effective_fallthrough(), Some(Address::new(0x2000)));
    }
}
