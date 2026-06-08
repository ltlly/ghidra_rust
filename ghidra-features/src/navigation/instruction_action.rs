//! Instruction navigation action -- ported from
//! `ghidra.app.plugin.core.navigation.NextPreviousInstructionAction`.
//!
//! Provides next/previous instruction navigation with support for:
//! - Finding the next/previous instruction from any code unit
//! - Inverted mode: finding next/previous non-instruction (data or undefined)
//! - Handling the "current instruction" optimization (when cursor is on
//!   an instruction, skip past non-instructions first)
//! - Integration with the AbstractNextPreviousAction pattern
//!
//! Swing UI code is omitted; only the model and business logic are ported.

use ghidra_core::Address;

use super::next_prev_plugins::NavigationDirection;

// ---------------------------------------------------------------------------
// CodeUnitType
// ---------------------------------------------------------------------------

/// The type of a code unit in the listing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CodeUnitType {
    /// A processor instruction.
    Instruction,
    /// A defined data item.
    Data,
    /// An undefined byte.
    Undefined,
}

impl CodeUnitType {
    /// Whether this is an instruction.
    pub fn is_instruction(&self) -> bool {
        matches!(self, Self::Instruction)
    }

    /// Whether this is a data item or undefined (non-instruction).
    pub fn is_non_instruction(&self) -> bool {
        !self.is_instruction()
    }
}

// ---------------------------------------------------------------------------
// CodeUnit (model)
// ---------------------------------------------------------------------------

/// A code unit in the program listing.
///
/// Ported from `ghidra.program.model.listing.CodeUnit` and its
/// subclasses (`Instruction`, `Data`).
#[derive(Debug, Clone)]
pub struct CodeUnit {
    /// The minimum (start) address of this code unit.
    pub min_address: Address,
    /// The maximum (end) address of this code unit.
    pub max_address: Address,
    /// The type of this code unit.
    pub cu_type: CodeUnitType,
}

impl CodeUnit {
    /// Create a new code unit.
    pub fn new(min_address: Address, max_address: Address, cu_type: CodeUnitType) -> Self {
        Self {
            min_address,
            max_address,
            cu_type,
        }
    }

    /// Create an instruction code unit.
    pub fn instruction(min_address: Address, length: u64) -> Self {
        Self::new(
            min_address,
            min_address + length - 1,
            CodeUnitType::Instruction,
        )
    }

    /// Create a data code unit.
    pub fn data(min_address: Address, length: u64) -> Self {
        Self::new(min_address, min_address + length - 1, CodeUnitType::Data)
    }

    /// Create an undefined code unit (single byte).
    pub fn undefined(address: Address) -> Self {
        Self::new(address, address, CodeUnitType::Undefined)
    }

    /// Get the next address after this code unit.
    pub fn next_address(&self) -> Address {
        self.max_address + 1
    }

    /// Get the previous address before this code unit.
    pub fn previous_address(&self) -> Address {
        self.min_address - 1
    }

    /// Whether this code unit contains the given address.
    pub fn contains(&self, address: Address) -> bool {
        address >= self.min_address && address <= self.max_address
    }
}

// ---------------------------------------------------------------------------
// ListingModel (instruction-aware)
// ---------------------------------------------------------------------------

/// A listing model that stores code units sorted by address.
///
/// Provides iteration for finding instructions and non-instructions.
#[derive(Debug, Clone)]
pub struct InstructionListingModel {
    /// Code units sorted by min_address.
    code_units: Vec<CodeUnit>,
}

impl InstructionListingModel {
    /// Create a new empty listing.
    pub fn new() -> Self {
        Self {
            code_units: Vec::new(),
        }
    }

    /// Add a code unit.  Units must be added in address order for
    /// binary search to work correctly.
    pub fn add_code_unit(&mut self, cu: CodeUnit) {
        let pos = self
            .code_units
            .binary_search_by_key(&cu.min_address, |c| c.min_address)
            .unwrap_or_else(|e| e);
        self.code_units.insert(pos, cu);
    }

    /// Get the instruction at the given address.
    pub fn get_instruction_at(&self, address: Address) -> Option<&CodeUnit> {
        self.code_units.iter().find(|cu| {
            cu.cu_type.is_instruction() && cu.contains(address)
        })
    }

    /// Get the instruction after the given address.
    pub fn get_instruction_after(&self, address: Address) -> Option<&CodeUnit> {
        self.code_units.iter().find(|cu| {
            cu.cu_type.is_instruction() && cu.min_address > address
        })
    }

    /// Get the instruction before the given address.
    pub fn get_instruction_before(&self, address: Address) -> Option<&CodeUnit> {
        self.code_units
            .iter()
            .rev()
            .find(|cu| cu.cu_type.is_instruction() && cu.max_address < address)
    }

    /// Get the code unit containing the given address.
    pub fn get_code_unit_containing(&self, address: Address) -> Option<&CodeUnit> {
        self.code_units.iter().find(|cu| cu.contains(address))
    }

    /// Iterate code units starting from `address` in the given direction.
    ///
    /// Returns code units whose min_address is >= (forward) or <= (backward)
    /// the given address.
    pub fn get_code_units(
        &self,
        address: Address,
        forward: bool,
    ) -> Box<dyn Iterator<Item = &CodeUnit> + '_> {
        if forward {
            let pos = self
                .code_units
                .binary_search_by_key(&address, |c| c.min_address)
                .unwrap_or_else(|e| e);
            Box::new(self.code_units[pos..].iter())
        } else {
            let pos = self
                .code_units
                .binary_search_by_key(&address, |c| c.min_address)
                .map(|p| p + 1)
                .unwrap_or_else(|e| e);
            Box::new(self.code_units[..pos].iter().rev())
        }
    }

    /// Count of code units.
    pub fn count(&self) -> usize {
        self.code_units.len()
    }
}

impl Default for InstructionListingModel {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// NextPreviousInstructionAction
// ---------------------------------------------------------------------------

/// Action that navigates to the next/previous instruction.
///
/// Ported from `ghidra.app.plugin.core.navigation.NextPreviousInstructionAction`.
///
/// This action handles the nuanced behavior of instruction navigation:
/// - When on an instruction, it first finds the next non-instruction, then
///   finds the next instruction after that (so repeated presses walk through
///   instructions rather than staying on the same one).
/// - In inverted mode, it finds the next/previous data or undefined area.
/// - Special handling for `AddressFieldLocation` (function signature cursor).
#[derive(Debug, Clone)]
pub struct NextPreviousInstructionAction {
    /// Current navigation direction.
    pub direction: NavigationDirection,
    /// Whether the action is enabled.
    pub enabled: bool,
    /// Whether the action is in inverted (non-instruction) mode.
    pub is_inverted: bool,
    /// The owner plugin name.
    pub owner: String,
}

impl NextPreviousInstructionAction {
    /// Create a new instruction navigation action.
    pub fn new(owner: impl Into<String>, direction: NavigationDirection) -> Self {
        Self {
            direction,
            enabled: true,
            is_inverted: false,
            owner: owner.into(),
        }
    }

    /// The action name.
    pub fn name(&self) -> String {
        let dir = if self.direction.is_forward() {
            "Next"
        } else {
            "Previous"
        };
        let kind = if self.is_inverted {
            "Non-Instruction"
        } else {
            "Instruction"
        };
        format!("{} {}", dir, kind)
    }

    /// Set the direction.
    pub fn set_direction(&mut self, direction: NavigationDirection) {
        self.direction = direction;
    }

    /// Set whether the action is inverted.
    pub fn set_inverted(&mut self, inverted: bool) {
        self.is_inverted = inverted;
    }

    /// Compute the next/previous address to navigate to.
    ///
    /// `current_address`: the current cursor address.
    /// `is_on_address_field`: whether the cursor is on an address field
    ///   (e.g., function signature).  When true, the action skips the
    ///   "find non-instruction first" optimization and goes directly to
    ///   the instruction at the current address.
    /// `shift_inverts`: whether shift was held (inverts direction).
    pub fn compute_address(
        &self,
        listing: &InstructionListingModel,
        current_address: Address,
        is_on_address_field: bool,
        shift_inverts: bool,
    ) -> Option<Address> {
        let forward = if shift_inverts {
            !self.direction.is_forward()
        } else {
            self.direction.is_forward()
        };

        if self.is_inverted {
            if forward {
                self.get_next_non_instruction_address(listing, current_address)
            } else {
                self.get_previous_non_instruction_address(listing, current_address)
            }
        } else if forward {
            self.get_next_instruction_address(listing, current_address, is_on_address_field)
        } else {
            self.get_previous_instruction_address(listing, current_address)
        }
    }

    /// Find the next instruction address.
    ///
    /// When on an instruction and not on an address field, the action
    /// first finds the next non-instruction, then finds the next
    /// instruction after that.  This ensures repeated presses walk
    /// through instructions rather than staying on the same one.
    fn get_next_instruction_address(
        &self,
        listing: &InstructionListingModel,
        address: Address,
        is_on_address_field: bool,
    ) -> Option<Address> {
        // Special case: if on an address field (e.g., function signature),
        // go directly to the instruction at this address.  This lets users
        // quickly jump from the signature to the entry point.
        if is_on_address_field {
            if let Some(cu) = listing.get_instruction_at(address) {
                return Some(cu.min_address);
            }
            // No instruction at this address, fall through to find next
            return self.get_address_of_next_instruction_after(listing, address);
        }

        if let Some(cu) = listing.get_code_unit_containing(address) {
            if cu.cu_type.is_instruction() {
                // On an instruction: find non-instruction first, then
                // find the next instruction after that.
                let non_instr_addr =
                    self.get_address_of_next_previous_non_instruction(listing, address, true);
                if let Some(non_addr) = non_instr_addr {
                    return self.get_address_of_next_instruction_after(listing, non_addr);
                }
                return None;
            }
        }

        // Not on an instruction: find next instruction.
        self.get_address_of_next_instruction_after(listing, address)
    }

    /// Find the previous instruction address.
    fn get_previous_instruction_address(
        &self,
        listing: &InstructionListingModel,
        address: Address,
    ) -> Option<Address> {
        if let Some(cu) = listing.get_code_unit_containing(address) {
            if cu.cu_type.is_instruction() {
                // On an instruction: find non-instruction first, then
                // find the previous instruction before that.
                let non_instr_addr =
                    self.get_address_of_next_previous_non_instruction(listing, address, false);
                if let Some(non_addr) = non_instr_addr {
                    return self.get_address_of_previous_instruction_before(listing, non_addr);
                }
                return None;
            }
        }

        // Not on an instruction: find previous instruction.
        self.get_address_of_previous_instruction_before(listing, address)
    }

    /// Find the next non-instruction address (inverted mode).
    fn get_next_non_instruction_address(
        &self,
        listing: &InstructionListingModel,
        address: Address,
    ) -> Option<Address> {
        let start = if self.is_instruction_at(listing, address) {
            // On an instruction: find non-instruction directly.
            address
        } else {
            // Not on an instruction: find next instruction first, then
            // find non-instruction after that (mimics non-inverted behavior).
            match self.get_address_of_next_instruction_after(listing, address) {
                Some(instr_addr) => instr_addr,
                None => return None,
            }
        };

        self.get_address_of_next_previous_non_instruction(listing, start, true)
    }

    /// Find the previous non-instruction address (inverted mode).
    fn get_previous_non_instruction_address(
        &self,
        listing: &InstructionListingModel,
        address: Address,
    ) -> Option<Address> {
        let start = if self.is_instruction_at(listing, address) {
            address
        } else {
            match self.get_address_of_previous_instruction_before(listing, address) {
                Some(instr_addr) => instr_addr,
                None => return None,
            }
        };

        self.get_address_of_next_previous_non_instruction(listing, start, false)
    }

    /// Check if there is an instruction at the given address.
    fn is_instruction_at(&self, listing: &InstructionListingModel, address: Address) -> bool {
        listing.get_instruction_at(address).is_some()
    }

    /// Find the address of the next instruction after `address`.
    fn get_address_of_next_instruction_after(
        &self,
        listing: &InstructionListingModel,
        address: Address,
    ) -> Option<Address> {
        listing
            .get_instruction_after(address)
            .map(|cu| cu.min_address)
    }

    /// Find the address of the previous instruction before `address`.
    fn get_address_of_previous_instruction_before(
        &self,
        listing: &InstructionListingModel,
        address: Address,
    ) -> Option<Address> {
        listing
            .get_instruction_before(address)
            .map(|cu| cu.min_address)
    }

    /// Find the next/previous code unit that is not an instruction.
    ///
    /// This walks through code units in the given direction starting from
    /// `address` and returns the address of the first Data or Undefined
    /// code unit found.
    fn get_address_of_next_previous_non_instruction(
        &self,
        listing: &InstructionListingModel,
        address: Address,
        forward: bool,
    ) -> Option<Address> {
        let start = if forward {
            address + 1
        } else {
            address - 1
        };

        for cu in listing.get_code_units(start, forward) {
            if cu.cu_type.is_non_instruction() {
                return Some(cu.min_address);
            }
        }

        None
    }

    /// The tooltip text for this action.
    pub fn tooltip_text(&self) -> String {
        let dir = if self.direction.is_forward() {
            "Next"
        } else {
            "Previous"
        };
        let kind = if self.is_inverted {
            "Non-Instruction"
        } else {
            "Instruction"
        };
        format!(
            "Go To {} {} (shift-click inverts direction)",
            dir, kind
        )
    }

    /// The keyboard shortcut description (Ctrl+Alt+I).
    pub fn key_stroke_description() -> &'static str {
        "Ctrl+Alt+I"
    }
}

impl Default for NextPreviousInstructionAction {
    fn default() -> Self {
        Self::new("Default", NavigationDirection::Forward)
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(offset: u64) -> Address {
        Address::new(offset)
    }

    fn make_listing() -> InstructionListingModel {
        let mut listing = InstructionListingModel::new();

        // Instruction at 0x1000 (4 bytes)
        listing.add_code_unit(CodeUnit::instruction(addr(0x1000), 4));
        // Instruction at 0x1004 (4 bytes)
        listing.add_code_unit(CodeUnit::instruction(addr(0x1004), 4));
        // Data at 0x1008 (4 bytes)
        listing.add_code_unit(CodeUnit::data(addr(0x1008), 4));
        // Instruction at 0x100C (4 bytes)
        listing.add_code_unit(CodeUnit::instruction(addr(0x100C), 4));
        // Data at 0x1010 (8 bytes)
        listing.add_code_unit(CodeUnit::data(addr(0x1010), 8));
        // Instruction at 0x1018 (4 bytes)
        listing.add_code_unit(CodeUnit::instruction(addr(0x1018), 4));
        // Instruction at 0x101C (4 bytes)
        listing.add_code_unit(CodeUnit::instruction(addr(0x101C), 4));
        // Undefined at 0x1020 (1 byte)
        listing.add_code_unit(CodeUnit::undefined(addr(0x1020)));
        // Instruction at 0x1021 (4 bytes)
        listing.add_code_unit(CodeUnit::instruction(addr(0x1021), 4));

        listing
    }

    #[test]
    fn test_code_unit_type() {
        assert!(CodeUnitType::Instruction.is_instruction());
        assert!(!CodeUnitType::Data.is_instruction());
        assert!(CodeUnitType::Data.is_non_instruction());
        assert!(CodeUnitType::Undefined.is_non_instruction());
    }

    #[test]
    fn test_code_unit_contains() {
        let cu = CodeUnit::instruction(addr(0x1000), 4);
        assert!(cu.contains(addr(0x1000)));
        assert!(cu.contains(addr(0x1003)));
        assert!(!cu.contains(addr(0x1004)));
        assert!(!cu.contains(addr(0x0FFF)));
    }

    #[test]
    fn test_code_unit_next_previous() {
        let cu = CodeUnit::instruction(addr(0x1000), 4);
        assert_eq!(cu.next_address(), addr(0x1004));
        assert_eq!(cu.previous_address(), addr(0x0FFF));
    }

    #[test]
    fn test_listing_get_instruction_at() {
        let listing = make_listing();
        assert!(listing.get_instruction_at(addr(0x1000)).is_some());
        assert!(listing.get_instruction_at(addr(0x1001)).is_some());
        assert!(listing.get_instruction_at(addr(0x1008)).is_none()); // data
    }

    #[test]
    fn test_listing_get_instruction_after() {
        let listing = make_listing();
        let instr = listing.get_instruction_after(addr(0x1000)).unwrap();
        assert_eq!(instr.min_address, addr(0x1004));
    }

    #[test]
    fn test_listing_get_instruction_before() {
        let listing = make_listing();
        let instr = listing.get_instruction_before(addr(0x1010)).unwrap();
        assert_eq!(instr.min_address, addr(0x100C));
    }

    #[test]
    fn test_action_name() {
        let action = NextPreviousInstructionAction::new("Test", NavigationDirection::Forward);
        assert_eq!(action.name(), "Next Instruction");
    }

    #[test]
    fn test_action_name_backward() {
        let action = NextPreviousInstructionAction::new("Test", NavigationDirection::Backward);
        assert_eq!(action.name(), "Previous Instruction");
    }

    #[test]
    fn test_action_name_inverted() {
        let mut action = NextPreviousInstructionAction::new("Test", NavigationDirection::Forward);
        action.set_inverted(true);
        assert_eq!(action.name(), "Next Non-Instruction");
    }

    #[test]
    fn test_navigate_forward_from_instruction() {
        let listing = make_listing();
        let action = NextPreviousInstructionAction::new("Test", NavigationDirection::Forward);

        // From 0x1000 (instruction), should skip to non-instruction (0x1008 data),
        // then find next instruction (0x100C).
        let result = action.compute_address(&listing, addr(0x1000), false, false);
        assert_eq!(result, Some(addr(0x100C)));
    }

    #[test]
    fn test_navigate_forward_from_instruction_chain() {
        let listing = make_listing();
        let action = NextPreviousInstructionAction::new("Test", NavigationDirection::Forward);

        // From 0x100C (instruction), should find non-instruction (0x1010 data),
        // then find next instruction (0x1018).
        let result = action.compute_address(&listing, addr(0x100C), false, false);
        assert_eq!(result, Some(addr(0x1018)));
    }

    #[test]
    fn test_navigate_forward_from_data() {
        let listing = make_listing();
        let action = NextPreviousInstructionAction::new("Test", NavigationDirection::Forward);

        // From 0x1008 (data), should find next instruction (0x100C).
        let result = action.compute_address(&listing, addr(0x1008), false, false);
        assert_eq!(result, Some(addr(0x100C)));
    }

    #[test]
    fn test_navigate_backward_from_instruction() {
        let listing = make_listing();
        let action = NextPreviousInstructionAction::new("Test", NavigationDirection::Backward);

        // From 0x100C (instruction), should find non-instruction before (0x1008 data),
        // then find previous instruction (0x1004).
        let result = action.compute_address(&listing, addr(0x100C), false, false);
        assert_eq!(result, Some(addr(0x1004)));
    }

    #[test]
    fn test_navigate_backward_from_data() {
        let listing = make_listing();
        let action = NextPreviousInstructionAction::new("Test", NavigationDirection::Backward);

        // From 0x1008 (data), should find previous instruction (0x1004).
        let result = action.compute_address(&listing, addr(0x1008), false, false);
        assert_eq!(result, Some(addr(0x1004)));
    }

    #[test]
    fn test_navigate_forward_at_end() {
        let listing = make_listing();
        let action = NextPreviousInstructionAction::new("Test", NavigationDirection::Forward);

        // From 0x1021 (last instruction), no more instructions after.
        let result = action.compute_address(&listing, addr(0x1021), false, false);
        assert_eq!(result, None);
    }

    #[test]
    fn test_navigate_backward_at_start() {
        let listing = make_listing();
        let action = NextPreviousInstructionAction::new("Test", NavigationDirection::Backward);

        // From 0x1000 (first instruction), no previous instructions.
        let result = action.compute_address(&listing, addr(0x1000), false, false);
        assert_eq!(result, None);
    }

    #[test]
    fn test_on_address_field_goes_directly() {
        let listing = make_listing();
        let action = NextPreviousInstructionAction::new("Test", NavigationDirection::Forward);

        // When on an address field (e.g., function signature), go directly
        // to the instruction at this address.
        let result = action.compute_address(&listing, addr(0x1000), true, false);
        assert_eq!(result, Some(addr(0x1000)));
    }

    #[test]
    fn test_shift_inverts_direction() {
        let listing = make_listing();
        let action = NextPreviousInstructionAction::new("Test", NavigationDirection::Forward);

        // Normally forward from 0x100C finds 0x1018.
        let result = action.compute_address(&listing, addr(0x100C), false, false);
        assert_eq!(result, Some(addr(0x1018)));

        // With shift, goes backward.
        let result = action.compute_address(&listing, addr(0x100C), false, true);
        assert_eq!(result, Some(addr(0x1004)));
    }

    #[test]
    fn test_inverted_forward() {
        let listing = make_listing();
        let mut action = NextPreviousInstructionAction::new("Test", NavigationDirection::Forward);
        action.set_inverted(true);

        // From 0x1000 (instruction), next non-instruction is 0x1008 (data).
        let result = action.compute_address(&listing, addr(0x1000), false, false);
        assert_eq!(result, Some(addr(0x1008)));
    }

    #[test]
    fn test_inverted_backward() {
        let listing = make_listing();
        let mut action = NextPreviousInstructionAction::new("Test", NavigationDirection::Backward);
        action.set_inverted(true);

        // From 0x1018 (instruction), previous non-instruction is 0x1010 (data).
        let result = action.compute_address(&listing, addr(0x1018), false, false);
        assert_eq!(result, Some(addr(0x1010)));
    }

    #[test]
    fn test_inverted_forward_from_data() {
        let listing = make_listing();
        let mut action = NextPreviousInstructionAction::new("Test", NavigationDirection::Forward);
        action.set_inverted(true);

        // From 0x1008 (data, non-instruction), inverted forward should:
        // 1. Find next instruction (0x100C)
        // 2. Find next non-instruction after that (0x1010 data)
        let result = action.compute_address(&listing, addr(0x1008), false, false);
        assert_eq!(result, Some(addr(0x1010)));
    }

    #[test]
    fn test_inverted_finds_undefined() {
        let listing = make_listing();
        let mut action = NextPreviousInstructionAction::new("Test", NavigationDirection::Forward);
        action.set_inverted(true);

        // From 0x101C (instruction), next non-instruction is 0x1020 (undefined).
        let result = action.compute_address(&listing, addr(0x101C), false, false);
        assert_eq!(result, Some(addr(0x1020)));
    }

    #[test]
    fn test_tooltip_text() {
        let action = NextPreviousInstructionAction::new("Test", NavigationDirection::Forward);
        let tooltip = action.tooltip_text();
        assert!(tooltip.contains("Next Instruction"));
        assert!(tooltip.contains("shift-click"));
    }

    #[test]
    fn test_key_stroke() {
        assert_eq!(
            NextPreviousInstructionAction::key_stroke_description(),
            "Ctrl+Alt+I"
        );
    }

    #[test]
    fn test_set_direction() {
        let mut action = NextPreviousInstructionAction::new("Test", NavigationDirection::Forward);
        assert_eq!(action.name(), "Next Instruction");
        action.set_direction(NavigationDirection::Backward);
        assert_eq!(action.name(), "Previous Instruction");
    }

    #[test]
    fn test_empty_listing() {
        let listing = InstructionListingModel::new();
        let action = NextPreviousInstructionAction::new("Test", NavigationDirection::Forward);

        let result = action.compute_address(&listing, addr(0x1000), false, false);
        assert_eq!(result, None);
    }

    #[test]
    fn test_consecutive_instructions_forward() {
        let mut listing = InstructionListingModel::new();
        // Two consecutive instructions with no data between them.
        listing.add_code_unit(CodeUnit::instruction(addr(0x1000), 4));
        listing.add_code_unit(CodeUnit::instruction(addr(0x1004), 4));
        listing.add_code_unit(CodeUnit::data(addr(0x1008), 4));
        listing.add_code_unit(CodeUnit::instruction(addr(0x100C), 4));

        let action = NextPreviousInstructionAction::new("Test", NavigationDirection::Forward);

        // From 0x1000 (instruction), find non-instruction (0x1008),
        // then find next instruction (0x100C).
        let result = action.compute_address(&listing, addr(0x1000), false, false);
        assert_eq!(result, Some(addr(0x100C)));
    }

    #[test]
    fn test_listing_code_units_forward() {
        let listing = make_listing();
        let addrs: Vec<Address> = listing
            .get_code_units(addr(0x100C), true)
            .map(|cu| cu.min_address)
            .collect();
        assert_eq!(
            addrs,
            vec![
                addr(0x100C),
                addr(0x1010),
                addr(0x1018),
                addr(0x101C),
                addr(0x1020),
                addr(0x1021),
            ]
        );
    }

    #[test]
    fn test_listing_code_units_backward() {
        let listing = make_listing();
        let addrs: Vec<Address> = listing
            .get_code_units(addr(0x100C), false)
            .map(|cu| cu.min_address)
            .collect();
        assert_eq!(
            addrs,
            vec![addr(0x100C), addr(0x1008), addr(0x1004), addr(0x1000)]
        );
    }
}
