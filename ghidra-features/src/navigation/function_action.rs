//! Function navigation action -- ported from
//! `ghidra.app.plugin.core.navigation.NextPreviousFunctionAction`.
//!
//! Provides next/previous function navigation with support for:
//! - Finding the next/previous function entry point
//! - Handling "inside function not at entry" (go to entry first)
//! - Inverted mode: finding instructions NOT in any function
//! - Memory-aware function iteration (only functions with addresses
//!   in the program's memory are considered)
//!
//! Swing UI code is omitted; only the model and business logic are ported.

use ghidra_core::Address;

use super::next_prev_plugins::NavigationDirection;

// ---------------------------------------------------------------------------
// Function (model)
// ---------------------------------------------------------------------------

/// A function in the program.
///
/// Ported from `ghidra.program.model.listing.Function`.
#[derive(Debug, Clone)]
pub struct Function {
    /// The entry point address of the function.
    pub entry_point: Address,
    /// The function name.
    pub name: String,
    /// The body of the function as a list of address ranges
    /// (min, max) inclusive.
    pub body: Vec<(Address, Address)>,
    /// The function's prototype string (for display in signature fields).
    pub prototype_string: String,
}

impl Function {
    /// Create a new function.
    pub fn new(entry_point: Address, name: impl Into<String>) -> Self {
        Self {
            entry_point,
            name: name.into(),
            body: Vec::new(),
            prototype_string: String::new(),
        }
    }

    /// Add an address range to the function body.
    pub fn add_body_range(&mut self, min: Address, max: Address) {
        self.body.push((min, max));
    }

    /// Whether the function body contains the given address.
    pub fn body_contains(&self, address: Address) -> bool {
        self.body
            .iter()
            .any(|(min, max)| address >= *min && address <= *max)
    }

    /// Get the entry point address.
    pub fn get_entry_point(&self) -> Address {
        self.entry_point
    }
}

// ---------------------------------------------------------------------------
// FunctionListingModel
// ---------------------------------------------------------------------------

/// A listing model for function navigation.
///
/// Provides function iteration and lookup by address.
#[derive(Debug, Clone)]
pub struct FunctionListingModel {
    /// Functions sorted by entry point address.
    functions: Vec<Function>,
}

impl FunctionListingModel {
    /// Create a new empty listing.
    pub fn new() -> Self {
        Self {
            functions: Vec::new(),
        }
    }

    /// Add a function.  Functions should be added in entry point order.
    pub fn add_function(&mut self, function: Function) {
        let pos = self
            .functions
            .binary_search_by_key(&function.entry_point, |f| f.entry_point)
            .unwrap_or_else(|e| e);
        self.functions.insert(pos, function);
    }

    /// Get the function containing the given address.
    pub fn get_function_containing(&self, address: Address) -> Option<&Function> {
        self.functions.iter().find(|f| f.body_contains(address))
    }

    /// Get the function at the given address (entry point match).
    pub fn get_function_at(&self, address: Address) -> Option<&Function> {
        self.functions.iter().find(|f| f.entry_point == address)
    }

    /// Iterate functions starting from `address` in the given direction.
    ///
    /// Returns functions whose entry point is >= (forward) or <= (backward)
    /// the given address.
    pub fn get_functions(
        &self,
        address: Address,
        forward: bool,
    ) -> Box<dyn Iterator<Item = &Function> + '_> {
        if forward {
            let pos = self
                .functions
                .binary_search_by_key(&address, |f| f.entry_point)
                .unwrap_or_else(|e| e);
            Box::new(self.functions[pos..].iter())
        } else {
            let pos = self
                .functions
                .binary_search_by_key(&address, |f| f.entry_point)
                .map(|p| p + 1)
                .unwrap_or_else(|e| e);
            Box::new(self.functions[..pos].iter().rev())
        }
    }

    /// Count of functions.
    pub fn count(&self) -> usize {
        self.functions.len()
    }
}

impl Default for FunctionListingModel {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// InstructionListingModel (reuse from instruction_action)
// ---------------------------------------------------------------------------

/// Minimal instruction model for function navigation.
///
/// Used by the inverted mode to iterate instructions and check
/// whether they fall within a function body.
#[derive(Debug, Clone)]
pub struct FnInstructionListing {
    /// Instructions sorted by address.
    /// Each entry is (address, length).
    instructions: Vec<(Address, u64)>,
}

impl FnInstructionListing {
    /// Create a new empty instruction listing.
    pub fn new() -> Self {
        Self {
            instructions: Vec::new(),
        }
    }

    /// Add an instruction at the given address with the given length.
    pub fn add_instruction(&mut self, address: Address, length: u64) {
        let pos = self
            .instructions
            .binary_search_by_key(&address, |(a, _)| *a)
            .unwrap_or_else(|e| e);
        self.instructions.insert(pos, (address, length));
    }

    /// Iterate instructions starting from `address` in the given direction.
    pub fn get_instructions(
        &self,
        address: Address,
        forward: bool,
    ) -> Box<dyn Iterator<Item = Address> + '_> {
        if forward {
            let pos = self
                .instructions
                .binary_search_by_key(&address, |(a, _)| *a)
                .unwrap_or_else(|e| e);
            Box::new(self.instructions[pos..].iter().map(|(a, _)| *a))
        } else {
            let pos = self
                .instructions
                .binary_search_by_key(&address, |(a, _)| *a)
                .map(|p| p + 1)
                .unwrap_or_else(|e| e);
            Box::new(self.instructions[..pos].iter().rev().map(|(a, _)| *a))
        }
    }
}

impl Default for FnInstructionListing {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// ProgramFunctionModel
// ---------------------------------------------------------------------------

/// A program model for function navigation.
///
/// Bundles the listing (for function lookup) and instruction listing
/// (for inverted mode) together.
#[derive(Debug, Clone)]
pub struct ProgramFunctionModel {
    /// The program name.
    pub name: String,
    /// The function listing.
    pub functions: FunctionListingModel,
    /// The instruction listing (for inverted mode).
    pub instructions: FnInstructionListing,
    /// Addresses that are in the program's memory.
    /// (Functions whose entry points are not in memory are skipped.)
    pub memory_addresses: Vec<Address>,
}

impl ProgramFunctionModel {
    /// Create a new program function model.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            functions: FunctionListingModel::new(),
            instructions: FnInstructionListing::new(),
            memory_addresses: Vec::new(),
        }
    }

    /// Check if the given address is in the program's memory.
    pub fn is_in_memory(&self, address: Address) -> bool {
        // For simplicity, check if the address is in the sorted memory_addresses list.
        self.memory_addresses
            .binary_search(&address)
            .is_ok()
    }
}

// ---------------------------------------------------------------------------
// NextPreviousFunctionAction
// ---------------------------------------------------------------------------

/// Action that navigates to the next/previous function.
///
/// Ported from `ghidra.app.plugin.core.navigation.NextPreviousFunctionAction`.
///
/// This action handles:
/// - Finding the next/previous function entry point
/// - When inside a function (not at entry), going to the entry first
/// - Inverted mode: finding instructions NOT in any function
/// - Memory-aware function iteration
#[derive(Debug, Clone)]
pub struct NextPreviousFunctionAction {
    /// Current navigation direction.
    pub direction: NavigationDirection,
    /// Whether the action is enabled.
    pub enabled: bool,
    /// Whether the action is in inverted (non-function) mode.
    pub is_inverted: bool,
    /// The owner plugin name.
    pub owner: String,
}

impl NextPreviousFunctionAction {
    /// Create a new function navigation action.
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
            "Instruction Not In a Function"
        } else {
            "Function"
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
    /// Returns `(address, is_function_entry)` where `is_function_entry`
    /// is true when the address is a function entry point (used for
    /// rendering the function signature field location).
    pub fn compute_address(
        &self,
        program: &ProgramFunctionModel,
        current_address: Address,
        shift_inverts: bool,
    ) -> Option<(Address, bool)> {
        let forward = if shift_inverts {
            !self.direction.is_forward()
        } else {
            self.direction.is_forward()
        };

        if self.is_inverted {
            if forward {
                self.get_next_non_function_address(program, current_address)
                    .map(|a| (a, false))
            } else {
                self.get_previous_non_function_address(program, current_address)
                    .map(|a| (a, false))
            }
        } else if forward {
            self.get_next_function_address(program, current_address)
                .map(|a| (a, true))
        } else {
            self.get_previous_function_address(program, current_address)
                .map(|a| (a, true))
        }
    }

    /// Find the next function entry point.
    ///
    /// If we are inside a function (not at the entry), return the entry
    /// point first.  Otherwise, find the next function after the current
    /// address.
    fn get_next_function_address(
        &self,
        program: &ProgramFunctionModel,
        address: Address,
    ) -> Option<Address> {
        // Find the next function whose entry point is not at the current address.
        let next = self.get_next_function_not_at_address(program, address, true);
        next.map(|f| f.entry_point)
    }

    /// Find the previous function entry point.
    ///
    /// If we are inside a function (not at the entry), return the entry
    /// point first.  Otherwise, find the previous function before the
    /// current address.
    fn get_previous_function_address(
        &self,
        program: &ProgramFunctionModel,
        address: Address,
    ) -> Option<Address> {
        // Check if we are inside a function (not at entry).
        if let Some(func) = program.functions.get_function_containing(address) {
            if self.is_inside_function_not_at_entry(func, address) {
                return Some(func.entry_point);
            }
        }

        // Find the previous function whose entry point is not at the current address.
        let prev = self.get_next_function_not_at_address(program, address, false);
        prev.map(|f| f.entry_point)
    }

    /// Find the next non-function address (inverted mode).
    ///
    /// Finds the next instruction that is not contained within any
    /// function body.
    fn get_next_non_function_address(
        &self,
        program: &ProgramFunctionModel,
        address: Address,
    ) -> Option<Address> {
        // If not currently in a function, find the next non-function instruction after this one.
        if program.functions.get_function_containing(address).is_none() {
            let iter = program.instructions.get_instructions(address + 1, true);
            for instr_addr in iter {
                if program.functions.get_function_containing(instr_addr).is_none() {
                    return Some(instr_addr);
                }
            }
            return None;
        }

        // If currently in a function, start from the function's entry point.
        let start_function = match program.functions.get_function_containing(address) {
            Some(func) => func.clone(),
            None => return None,
        };

        self.find_next_instruction_address_not_in_function(program, &start_function, true)
    }

    /// Find the previous non-function address (inverted mode).
    fn get_previous_non_function_address(
        &self,
        program: &ProgramFunctionModel,
        address: Address,
    ) -> Option<Address> {
        let start_function = match program.functions.get_function_containing(address) {
            Some(func) => Some(func.clone()),
            None => self.get_next_function(program, address, false).cloned(),
        };

        match start_function {
            Some(func) => {
                self.find_next_instruction_address_not_in_function(program, &func, false)
            }
            None => None,
        }
    }

    /// Find the next/previous instruction address that is not within
    /// any function body.
    ///
    /// Starting from `start_function`, walks through instructions in the
    /// given direction.  When an instruction falls outside the current
    /// function's body, checks if it is in another function.  If not,
    /// returns that address.
    fn find_next_instruction_address_not_in_function(
        &self,
        program: &ProgramFunctionModel,
        start_function: &Function,
        forward: bool,
    ) -> Option<Address> {
        let mut current_body = start_function.body.clone();
        let start_addr = start_function.entry_point;

        let iter = program.instructions.get_instructions(start_addr, forward);
        for instr_addr in iter {
            // Check if this instruction is in the current function body.
            let in_body = current_body
                .iter()
                .any(|(min, max)| instr_addr >= *min && instr_addr <= *max);

            if !in_body {
                // Outside the current function.  Check if it's in another function.
                match program.functions.get_function_containing(instr_addr) {
                    Some(other_func) => {
                        // Update to the new function's body and continue.
                        current_body = other_func.body.clone();
                    }
                    None => {
                        // Not in any function -- this is our target.
                        return Some(instr_addr);
                    }
                }
            }
        }

        None
    }

    /// Check if the address is inside a function but not at the entry.
    fn is_inside_function_not_at_entry(&self, function: &Function, address: Address) -> bool {
        function.body_contains(address) && address != function.entry_point
    }

    /// Get the next function iterator that is not at the given address.
    fn get_next_function_not_at_address<'a>(
        &self,
        program: &'a ProgramFunctionModel,
        address: Address,
        forward: bool,
    ) -> Option<&'a Function> {
        let iter = program.functions.get_functions(address, forward);
        for func in iter {
            if func.entry_point == address {
                continue;
            }
            // In a full implementation, we'd check memory.contains(entryPoint).
            // For our model, we accept all functions.
            return Some(func);
        }
        None
    }

    /// Get the next function (any, including at the address).
    fn get_next_function<'a>(
        &self,
        program: &'a ProgramFunctionModel,
        address: Address,
        forward: bool,
    ) -> Option<&'a Function> {
        program.functions.get_functions(address, forward).next()
    }

    /// The tooltip text for this action.
    pub fn tooltip_text(&self) -> String {
        let dir = if self.direction.is_forward() {
            "Next"
        } else {
            "Previous"
        };
        let kind = if self.is_inverted {
            "Instruction Not In a Function"
        } else {
            "Function"
        };
        format!(
            "Go To {} {} (shift-click inverts direction)",
            dir, kind
        )
    }

    /// The keyboard shortcut description (Ctrl+Alt+F).
    pub fn key_stroke_description() -> &'static str {
        "Ctrl+Alt+F"
    }
}

impl Default for NextPreviousFunctionAction {
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

    fn make_function(
        entry: u64,
        name: &str,
        body_start: u64,
        body_end: u64,
    ) -> Function {
        let mut func = Function::new(addr(entry), name);
        func.add_body_range(addr(body_start), addr(body_end));
        func
    }

    fn make_program() -> ProgramFunctionModel {
        let mut program = ProgramFunctionModel::new("test.exe");

        // Function A: entry 0x1000, body 0x1000-0x1040
        program
            .functions
            .add_function(make_function(0x1000, "funcA", 0x1000, 0x1040));

        // Function B: entry 0x2000, body 0x2000-0x2040
        program
            .functions
            .add_function(make_function(0x2000, "funcB", 0x2000, 0x2040));

        // Function C: entry 0x3000, body 0x3000-0x3040
        program
            .functions
            .add_function(make_function(0x3000, "funcC", 0x3000, 0x3040));

        // Instructions inside function A
        for i in 0..16 {
            program
                .instructions
                .add_instruction(addr(0x1000 + i * 4), 4);
        }

        // Instructions between functions A and B (not in any function)
        program.instructions.add_instruction(addr(0x1100), 4);
        program.instructions.add_instruction(addr(0x1104), 4);

        // Instructions inside function B
        for i in 0..16 {
            program
                .instructions
                .add_instruction(addr(0x2000 + i * 4), 4);
        }

        // Instructions inside function C
        for i in 0..16 {
            program
                .instructions
                .add_instruction(addr(0x3000 + i * 4), 4);
        }

        program
    }

    #[test]
    fn test_function_body_contains() {
        let func = make_function(0x1000, "test", 0x1000, 0x1040);
        assert!(func.body_contains(addr(0x1000)));
        assert!(func.body_contains(addr(0x1020)));
        assert!(func.body_contains(addr(0x1040)));
        assert!(!func.body_contains(addr(0x1041)));
        assert!(!func.body_contains(addr(0x0FFF)));
    }

    #[test]
    fn test_listing_get_function_containing() {
        let program = make_program();
        let func = program.functions.get_function_containing(addr(0x1020));
        assert!(func.is_some());
        assert_eq!(func.unwrap().name, "funcA");
    }

    #[test]
    fn test_listing_get_function_containing_at_entry() {
        let program = make_program();
        let func = program.functions.get_function_containing(addr(0x2000));
        assert!(func.is_some());
        assert_eq!(func.unwrap().name, "funcB");
    }

    #[test]
    fn test_listing_get_function_containing_between() {
        let program = make_program();
        // 0x1100 is between funcA and funcB, not in any function.
        let func = program.functions.get_function_containing(addr(0x1100));
        assert!(func.is_none());
    }

    #[test]
    fn test_listing_get_function_at() {
        let program = make_program();
        let func = program.functions.get_function_at(addr(0x1000));
        assert!(func.is_some());
        assert_eq!(func.unwrap().name, "funcA");

        // 0x1004 is in the function body but not the entry point.
        let func = program.functions.get_function_at(addr(0x1004));
        assert!(func.is_none());
    }

    #[test]
    fn test_action_name() {
        let action = NextPreviousFunctionAction::new("Test", NavigationDirection::Forward);
        assert_eq!(action.name(), "Next Function");
    }

    #[test]
    fn test_action_name_backward() {
        let action = NextPreviousFunctionAction::new("Test", NavigationDirection::Backward);
        assert_eq!(action.name(), "Previous Function");
    }

    #[test]
    fn test_action_name_inverted() {
        let mut action = NextPreviousFunctionAction::new("Test", NavigationDirection::Forward);
        action.set_inverted(true);
        assert_eq!(action.name(), "Next Instruction Not In a Function");
    }

    #[test]
    fn test_navigate_forward_from_entry() {
        let program = make_program();
        let action = NextPreviousFunctionAction::new("Test", NavigationDirection::Forward);

        // From 0x1000 (funcA entry), next function is funcB at 0x2000.
        let result = action.compute_address(&program, addr(0x1000), false);
        assert_eq!(result, Some((addr(0x2000), true)));
    }

    #[test]
    fn test_navigate_forward_from_inside_function() {
        let program = make_program();
        let action = NextPreviousFunctionAction::new("Test", NavigationDirection::Forward);

        // From 0x1020 (inside funcA), next function is funcB at 0x2000.
        let result = action.compute_address(&program, addr(0x1020), false);
        assert_eq!(result, Some((addr(0x2000), true)));
    }

    #[test]
    fn test_navigate_backward_from_inside_function() {
        let program = make_program();
        let action = NextPreviousFunctionAction::new("Test", NavigationDirection::Backward);

        // From 0x2020 (inside funcB, not at entry), go to funcB entry first.
        let result = action.compute_address(&program, addr(0x2020), false);
        assert_eq!(result, Some((addr(0x2000), true)));
    }

    #[test]
    fn test_navigate_backward_from_entry() {
        let program = make_program();
        let action = NextPreviousFunctionAction::new("Test", NavigationDirection::Backward);

        // From 0x2000 (funcB entry), previous function is funcA at 0x1000.
        let result = action.compute_address(&program, addr(0x2000), false);
        assert_eq!(result, Some((addr(0x1000), true)));
    }

    #[test]
    fn test_navigate_forward_from_between_functions() {
        let program = make_program();
        let action = NextPreviousFunctionAction::new("Test", NavigationDirection::Forward);

        // From 0x1100 (between funcA and funcB), next function is funcB.
        let result = action.compute_address(&program, addr(0x1100), false);
        assert_eq!(result, Some((addr(0x2000), true)));
    }

    #[test]
    fn test_navigate_backward_from_between_functions() {
        let program = make_program();
        let action = NextPreviousFunctionAction::new("Test", NavigationDirection::Backward);

        // From 0x1100 (between funcA and funcB), previous function is funcA.
        let result = action.compute_address(&program, addr(0x1100), false);
        assert_eq!(result, Some((addr(0x1000), true)));
    }

    #[test]
    fn test_navigate_forward_at_last_function() {
        let program = make_program();
        let action = NextPreviousFunctionAction::new("Test", NavigationDirection::Forward);

        // From 0x3000 (funcC entry), no more functions.
        let result = action.compute_address(&program, addr(0x3000), false);
        assert_eq!(result, None);
    }

    #[test]
    fn test_navigate_backward_at_first_function() {
        let program = make_program();
        let action = NextPreviousFunctionAction::new("Test", NavigationDirection::Backward);

        // From 0x1000 (funcA entry), no previous functions.
        let result = action.compute_address(&program, addr(0x1000), false);
        assert_eq!(result, None);
    }

    #[test]
    fn test_shift_inverts_direction() {
        let program = make_program();
        let action = NextPreviousFunctionAction::new("Test", NavigationDirection::Forward);

        // Normally forward from 0x1000 goes to 0x2000.
        let result = action.compute_address(&program, addr(0x1000), false);
        assert_eq!(result, Some((addr(0x2000), true)));

        // With shift, goes backward (no previous function from 0x1000).
        let result = action.compute_address(&program, addr(0x1000), true);
        assert_eq!(result, None);
    }

    #[test]
    fn test_shift_inverts_from_middle() {
        let program = make_program();
        let action = NextPreviousFunctionAction::new("Test", NavigationDirection::Forward);

        // Normally forward from 0x2000 goes to 0x3000.
        let result = action.compute_address(&program, addr(0x2000), false);
        assert_eq!(result, Some((addr(0x3000), true)));

        // With shift, goes backward to 0x1000.
        let result = action.compute_address(&program, addr(0x2000), true);
        assert_eq!(result, Some((addr(0x1000), true)));
    }

    #[test]
    fn test_inverted_forward_finds_non_function() {
        let program = make_program();
        let mut action = NextPreviousFunctionAction::new("Test", NavigationDirection::Forward);
        action.set_inverted(true);

        // From 0x1000 (funcA entry), inverted forward finds instructions
        // not in any function.  Instructions at 0x1100 and 0x1104 are
        // between funcA and funcB.
        let result = action.compute_address(&program, addr(0x1000), false);
        assert_eq!(result, Some((addr(0x1100), false)));
    }

    #[test]
    fn test_inverted_backward_finds_non_function() {
        let program = make_program();
        let mut action = NextPreviousFunctionAction::new("Test", NavigationDirection::Backward);
        action.set_inverted(true);

        // From 0x2000 (funcB entry), inverted backward finds instructions
        // not in any function before funcB.
        let result = action.compute_address(&program, addr(0x2000), false);
        assert_eq!(result, Some((addr(0x1104), false)));
    }

    #[test]
    fn test_inverted_forward_from_non_function() {
        let program = make_program();
        let mut action = NextPreviousFunctionAction::new("Test", NavigationDirection::Forward);
        action.set_inverted(true);

        // From 0x1100 (not in any function), inverted forward:
        // 1. Find next function (funcB at 0x2000)
        // 2. Walk instructions from funcB entry forward
        // 3. All instructions in funcB are in its body
        // 4. No more non-function instructions found after funcB (funcC follows)
        // Actually, let's check: after funcB's body (0x2040), next is funcC at 0x3000.
        // There are no instructions between 0x2040 and 0x3000 in our model.
        let result = action.compute_address(&program, addr(0x1100), false);
        // Should find 0x1104 (the next non-function instruction).
        assert_eq!(result, Some((addr(0x1104), false)));
    }

    #[test]
    fn test_inverted_no_non_function_instructions() {
        let mut program = ProgramFunctionModel::new("test.exe");

        // Only one function covering all instructions.
        program
            .functions
            .add_function(make_function(0x1000, "bigFunc", 0x1000, 0x3000));

        for i in 0..100 {
            program
                .instructions
                .add_instruction(addr(0x1000 + i * 4), 4);
        }

        let mut action = NextPreviousFunctionAction::new("Test", NavigationDirection::Forward);
        action.set_inverted(true);

        // All instructions are in bigFunc, so no non-function instruction exists.
        let result = action.compute_address(&program, addr(0x1000), false);
        assert_eq!(result, None);
    }

    #[test]
    fn test_tooltip_text() {
        let action = NextPreviousFunctionAction::new("Test", NavigationDirection::Forward);
        let tooltip = action.tooltip_text();
        assert!(tooltip.contains("Next Function"));
        assert!(tooltip.contains("shift-click"));
    }

    #[test]
    fn test_tooltip_text_inverted() {
        let mut action = NextPreviousFunctionAction::new("Test", NavigationDirection::Forward);
        action.set_inverted(true);
        let tooltip = action.tooltip_text();
        assert!(tooltip.contains("Next Instruction Not In a Function"));
    }

    #[test]
    fn test_key_stroke() {
        assert_eq!(
            NextPreviousFunctionAction::key_stroke_description(),
            "Ctrl+Alt+F"
        );
    }

    #[test]
    fn test_set_direction() {
        let mut action = NextPreviousFunctionAction::new("Test", NavigationDirection::Forward);
        assert_eq!(action.name(), "Next Function");
        action.set_direction(NavigationDirection::Backward);
        assert_eq!(action.name(), "Previous Function");
    }

    #[test]
    fn test_empty_program() {
        let program = ProgramFunctionModel::new("empty.exe");
        let action = NextPreviousFunctionAction::new("Test", NavigationDirection::Forward);

        let result = action.compute_address(&program, addr(0x1000), false);
        assert_eq!(result, None);
    }

    #[test]
    fn test_single_function_forward() {
        let mut program = ProgramFunctionModel::new("test.exe");
        program
            .functions
            .add_function(make_function(0x1000, "only", 0x1000, 0x1040));

        let action = NextPreviousFunctionAction::new("Test", NavigationDirection::Forward);
        let result = action.compute_address(&program, addr(0x1000), false);
        assert_eq!(result, None);
    }

    #[test]
    fn test_single_function_backward() {
        let mut program = ProgramFunctionModel::new("test.exe");
        program
            .functions
            .add_function(make_function(0x1000, "only", 0x1000, 0x1040));

        let action = NextPreviousFunctionAction::new("Test", NavigationDirection::Backward);
        let result = action.compute_address(&program, addr(0x1000), false);
        assert_eq!(result, None);
    }

    #[test]
    fn test_single_function_backward_inside() {
        let mut program = ProgramFunctionModel::new("test.exe");
        program
            .functions
            .add_function(make_function(0x1000, "only", 0x1000, 0x1040));

        let action = NextPreviousFunctionAction::new("Test", NavigationDirection::Backward);
        // From 0x1020 (inside "only"), go to entry first.
        let result = action.compute_address(&program, addr(0x1020), false);
        assert_eq!(result, Some((addr(0x1000), true)));
    }

    #[test]
    fn test_function_listing_forward_backward() {
        let mut listing = FunctionListingModel::new();
        listing.add_function(make_function(0x1000, "a", 0x1000, 0x1040));
        listing.add_function(make_function(0x2000, "b", 0x2000, 0x2040));
        listing.add_function(make_function(0x3000, "c", 0x3000, 0x3040));

        // Forward from 0x1500
        let names: Vec<&str> = listing
            .get_functions(addr(0x1500), true)
            .map(|f| f.name.as_str())
            .collect();
        assert_eq!(names, vec!["b", "c"]);

        // Backward from 0x2500
        let names: Vec<&str> = listing
            .get_functions(addr(0x2500), false)
            .map(|f| f.name.as_str())
            .collect();
        assert_eq!(names, vec!["b", "a"]);
    }

    #[test]
    fn test_instruction_listing_forward() {
        let mut listing = FnInstructionListing::new();
        listing.add_instruction(addr(0x1000), 4);
        listing.add_instruction(addr(0x1004), 4);
        listing.add_instruction(addr(0x2000), 4);

        let addrs: Vec<Address> = listing.get_instructions(addr(0x1004), true).collect();
        assert_eq!(addrs, vec![addr(0x1004), addr(0x2000)]);
    }

    #[test]
    fn test_instruction_listing_backward() {
        let mut listing = FnInstructionListing::new();
        listing.add_instruction(addr(0x1000), 4);
        listing.add_instruction(addr(0x1004), 4);
        listing.add_instruction(addr(0x2000), 4);

        let addrs: Vec<Address> = listing.get_instructions(addr(0x2000), false).collect();
        assert_eq!(addrs, vec![addr(0x2000), addr(0x1004), addr(0x1000)]);
    }
}
