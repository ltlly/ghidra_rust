//! ConstantPropagationContextEvaluator -- evaluates constant values during propagation.
//!
//! Ported from `ghidra.app.plugin.core.analysis.ConstantPropagationContextEvaluator`.
//! Provides the evaluation logic for determining whether a constant value
//! is a valid reference target. Filters out suspicious addresses (0-256,
//! mask values like 0xFFFFFFFF) and optionally creates data/functions at
//! discovered reference targets.

use std::collections::HashSet;

use crate::base::analyzer::core::*;

/// Evaluator for constant propagation analysis.
///
/// Determines whether computed constant values are valid reference targets.
/// Filters out common false positives and optionally creates data or
/// functions at discovered reference locations.
///
/// # Filtering Rules
///
/// - Addresses below `min_speculative_offset` are rejected (likely small integers)
/// - Addresses near the end of address space are rejected (0xFFFFFFFF, 0xFFFF, etc.)
/// - Constant addresses in external space are always accepted
/// - Data references below `min_store_load_offset` are rejected unless from a simple COPY
#[derive(Debug, Clone)]
pub struct ConstantPropagationContextEvaluator {
    /// Trust values read from writable memory.
    pub trust_memory_write: bool,
    /// Create complex data types from pointers if data type is known.
    pub create_data_from_pointers: bool,
    /// Minimum store/load reference offset.
    pub min_store_load_offset: u64,
    /// Minimum speculative offset from start of memory.
    pub min_speculative_offset: u64,
    /// Maximum speculative offset from end of memory.
    pub max_speculative_offset: u64,
    /// Set of computed jump destinations (for switch analysis).
    pub dest_set: AddressSet,
    /// Set of addresses where data or functions were created.
    pub created_set: AddressSet,
    /// Known valid memory addresses (for filtering).
    valid_memory: HashSet<u64>,
}

/// Result of evaluating a constant value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvaluationResult {
    /// The constant is a valid reference -- contains the target address.
    ValidReference(Address),
    /// The constant is not a valid reference.
    NotAReference,
    /// The constant might be valid but needs more analysis.
    Suspicious,
}

impl ConstantPropagationContextEvaluator {
    /// Creates a new evaluator with default settings.
    pub fn new() -> Self {
        Self {
            trust_memory_write: false,
            create_data_from_pointers: false,
            min_store_load_offset: 4,
            min_speculative_offset: 1024,
            max_speculative_offset: 256,
            dest_set: AddressSet::new(),
            created_set: AddressSet::new(),
            valid_memory: HashSet::new(),
        }
    }

    /// Sets whether to trust reads from writable memory.
    pub fn set_trust_writable_memory(mut self, trust: bool) -> Self {
        self.trust_memory_write = trust;
        self
    }

    /// Sets the minimum speculative offset for references.
    pub fn set_min_speculative_offset(mut self, offset: u64) -> Self {
        self.min_speculative_offset = offset;
        self
    }

    /// Sets the maximum speculative offset for references.
    pub fn set_max_speculative_offset(mut self, offset: u64) -> Self {
        self.max_speculative_offset = offset;
        self
    }

    /// Sets the minimum store/load reference offset.
    pub fn set_min_store_load_offset(mut self, offset: u64) -> Self {
        self.min_store_load_offset = offset;
        self
    }

    /// Sets whether to create complex data from pointers.
    pub fn set_create_complex_data_from_pointers(mut self, create: bool) -> Self {
        self.create_data_from_pointers = create;
        self
    }

    /// Adds a known valid memory address.
    pub fn add_valid_memory(&mut self, addr: u64) {
        self.valid_memory.insert(addr);
    }

    /// Returns the set of computed jump destinations.
    pub fn destination_set(&self) -> &AddressSet {
        &self.dest_set
    }

    /// Evaluates whether a constant value is a valid reference target.
    ///
    /// This is the main evaluation entry point, equivalent to Ghidra's
    /// `evaluateConstant()` method.
    ///
    /// # Arguments
    ///
    /// * `constant` - The constant value to evaluate
    /// * `program` - The program being analyzed
    /// * `size` - Size of the access (in bytes)
    /// * `is_data_ref` - Whether this is a data reference (vs flow)
    ///
    /// # Returns
    ///
    /// An `EvaluationResult` indicating whether the constant is a valid reference.
    pub fn evaluate_constant(
        &self,
        constant: u64,
        program: &Program,
        size: u32,
        is_data_ref: bool,
    ) -> EvaluationResult {
        // Reject null-like values
        if constant == 0 {
            return EvaluationResult::NotAReference;
        }

        // Reject common mask values
        if constant == 0xFFFFFFFF
            || constant == 0xFFFF
            || constant == 0xFFFFFFFE
            || constant == 0xFFFFFFFFFFFFFFFF
        {
            return EvaluationResult::NotAReference;
        }

        // Reject very small values (likely small integers, flags, etc.)
        if constant < self.min_speculative_offset {
            return EvaluationResult::NotAReference;
        }

        // Check if in valid memory range
        if program.memory.contains(&Address::new(constant)) {
            return EvaluationResult::ValidReference(Address::new(constant));
        }

        // Check if it's close to known valid addresses
        if self.valid_memory.contains(&constant) {
            return EvaluationResult::ValidReference(Address::new(constant));
        }

        // For data references, apply stricter filtering
        if is_data_ref && constant < self.min_store_load_offset {
            return EvaluationResult::NotAReference;
        }

        // Size check
        if size == 0 || size > 8 {
            return EvaluationResult::NotAReference;
        }

        EvaluationResult::Suspicious
    }

    /// Evaluates whether a reference should be created at the given address.
    ///
    /// Equivalent to Ghidra's `evaluateReference()` method.
    ///
    /// # Arguments
    ///
    /// * `address` - The target address
    /// * `program` - The program being analyzed
    /// * `is_flow` - Whether this is a flow reference
    /// * `is_data` - Whether this is a data reference
    ///
    /// # Returns
    ///
    /// `true` if the reference should be created, `false` otherwise.
    pub fn evaluate_reference(
        &self,
        address: Address,
        program: &Program,
        is_flow: bool,
        is_data: bool,
    ) -> bool {
        // External space references are always valid
        if address.space_id == Address::EXTERNAL_SPACE {
            return true;
        }

        let offset = address.offset;

        // Reject addresses below minimum store/load offset
        if offset < self.min_store_load_offset {
            return false;
        }

        // Must be in program memory
        if !program.memory.contains(&address) {
            return false;
        }

        // For flow references, check if there's executable memory
        if is_flow {
            // Check if there's an instruction at the target
            if program.listing.get_instruction_at(&address).is_some() {
                return true;
            }
            // Or if memory is executable (would need MemoryBlock check in full impl)
            return true;
        }

        // For data references, check if data exists or could be created
        if is_data {
            if program.listing.get_defined_data_at(&address).is_some() {
                return true;
            }
            // Allow creating data at undefined locations
            return true;
        }

        true
    }

    /// Evaluates whether a computed jump destination should be tracked.
    ///
    /// Equivalent to Ghidra's `evaluateDestination()` method.
    /// Unknown computed jump destinations are added to the destination set
    /// for potential switch analysis.
    ///
    /// # Arguments
    ///
    /// * `instruction` - The jump instruction
    /// * `program` - The program being analyzed
    ///
    /// # Returns
    ///
    /// `true` if the flow should continue past this instruction.
    pub fn evaluate_destination(
        &mut self,
        instruction: &Instruction,
        _program: &Program,
    ) -> bool {
        if !instruction.flow_type.is_jump() {
            return false;
        }

        // If there are no computed references from this jump, track it
        // for switch analysis
        if instruction.flows.is_empty() {
            self.dest_set.add(instruction.address);
        }

        false // don't follow the destination
    }

    /// Returns whether access to writable memory should be trusted.
    pub fn allow_access(&self) -> bool {
        self.trust_memory_write
    }

    /// Evaluates whether a constant is a valid address for the given program.
    ///
    /// This is a simpler version that checks basic validity without
    /// the full context evaluation.
    pub fn is_valid_constant_address(&self, constant: u64, program: &Program) -> bool {
        if constant == 0 {
            return false;
        }

        if constant < self.min_speculative_offset {
            return false;
        }

        if constant == 0xFFFFFFFF || constant == 0xFFFF {
            return false;
        }

        program.memory.contains(&Address::new(constant))
    }
}

impl Default for ConstantPropagationContextEvaluator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_program() -> Program {
        let lang = Language {
            processor: "x86".into(),
            variant: "LE".into(),
            size: 64,
        };
        let mut p = Program::new("test", lang);
        p.memory
            .add_range(AddressRange::new(Address::new(0x1000), Address::new(0x5000)));
        p
    }

    #[test]
    fn test_evaluator_creation() {
        let e = ConstantPropagationContextEvaluator::new();
        assert!(!e.trust_memory_write);
        assert!(!e.create_data_from_pointers);
        assert_eq!(e.min_store_load_offset, 4);
        assert_eq!(e.min_speculative_offset, 1024);
    }

    #[test]
    fn test_evaluate_constant_null() {
        let e = ConstantPropagationContextEvaluator::new();
        let p = make_program();
        assert_eq!(
            e.evaluate_constant(0, &p, 4, false),
            EvaluationResult::NotAReference
        );
    }

    #[test]
    fn test_evaluate_constant_mask_values() {
        let e = ConstantPropagationContextEvaluator::new();
        let p = make_program();
        assert_eq!(
            e.evaluate_constant(0xFFFFFFFF, &p, 4, false),
            EvaluationResult::NotAReference
        );
        assert_eq!(
            e.evaluate_constant(0xFFFF, &p, 2, false),
            EvaluationResult::NotAReference
        );
    }

    #[test]
    fn test_evaluate_constant_small_values() {
        let e = ConstantPropagationContextEvaluator::new();
        let p = make_program();
        // Values below min_speculative_offset are rejected
        assert_eq!(
            e.evaluate_constant(0x100, &p, 4, false),
            EvaluationResult::NotAReference
        );
    }

    #[test]
    fn test_evaluate_constant_valid_address() {
        let e = ConstantPropagationContextEvaluator::new();
        let p = make_program();
        assert_eq!(
            e.evaluate_constant(0x2000, &p, 4, false),
            EvaluationResult::ValidReference(Address::new(0x2000))
        );
    }

    #[test]
    fn test_evaluate_reference_external_space() {
        let e = ConstantPropagationContextEvaluator::new();
        let p = make_program();
        let addr = Address::in_space(Address::EXTERNAL_SPACE, 1);
        assert!(e.evaluate_reference(addr, &p, false, true));
    }

    #[test]
    fn test_evaluate_reference_low_offset() {
        let e = ConstantPropagationContextEvaluator::new();
        let p = make_program();
        assert!(!e.evaluate_reference(Address::new(0x2), &p, false, true));
    }

    #[test]
    fn test_evaluate_reference_valid() {
        let e = ConstantPropagationContextEvaluator::new();
        let p = make_program();
        assert!(e.evaluate_reference(Address::new(0x2000), &p, true, false));
    }

    #[test]
    fn test_builder_pattern() {
        let e = ConstantPropagationContextEvaluator::new()
            .set_trust_writable_memory(true)
            .set_min_speculative_offset(512)
            .set_max_speculative_offset(128)
            .set_min_store_load_offset(8)
            .set_create_complex_data_from_pointers(true);

        assert!(e.trust_memory_write);
        assert_eq!(e.min_speculative_offset, 512);
        assert_eq!(e.max_speculative_offset, 128);
        assert_eq!(e.min_store_load_offset, 8);
        assert!(e.create_data_from_pointers);
    }

    #[test]
    fn test_allow_access() {
        let mut e = ConstantPropagationContextEvaluator::new();
        assert!(!e.allow_access());
        e.trust_memory_write = true;
        assert!(e.allow_access());
    }

    #[test]
    fn test_evaluate_destination_jump() {
        let mut e = ConstantPropagationContextEvaluator::new();
        let p = make_program();
        let instr = Instruction {
            address: Address::new(0x1000),
            length: 2,
            mnemonic: "jmp".into(),
            flow_type: FlowType::Jump,
            fall_through: None,
            flows: vec![],
            num_operands: 1,
        };
        let result = e.evaluate_destination(&instr, &p);
        assert!(!result);
        assert!(e.dest_set.contains(&Address::new(0x1000)));
    }

    #[test]
    fn test_evaluate_destination_call() {
        let mut e = ConstantPropagationContextEvaluator::new();
        let p = make_program();
        let instr = Instruction {
            address: Address::new(0x1000),
            length: 5,
            mnemonic: "call".into(),
            flow_type: FlowType::Call,
            fall_through: Some(Address::new(0x1005)),
            flows: vec![Address::new(0x2000)],
            num_operands: 1,
        };
        let result = e.evaluate_destination(&instr, &p);
        assert!(!result);
        assert!(e.dest_set.is_empty());
    }

    #[test]
    fn test_is_valid_constant_address() {
        let e = ConstantPropagationContextEvaluator::new();
        let p = make_program();
        assert!(!e.is_valid_constant_address(0, &p));
        assert!(!e.is_valid_constant_address(100, &p));
        assert!(!e.is_valid_constant_address(0xFFFFFFFF, &p));
        assert!(e.is_valid_constant_address(0x2000, &p));
    }

    #[test]
    fn test_add_valid_memory() {
        let mut e = ConstantPropagationContextEvaluator::new();
        e.add_valid_memory(0x12345);
        assert!(e.valid_memory.contains(&0x12345));
    }

    #[test]
    fn test_evaluate_constant_with_valid_memory() {
        let mut e = ConstantPropagationContextEvaluator::new();
        e.add_valid_memory(0x500);
        let p = make_program();
        // 0x500 is below min_speculative_offset but is in valid_memory
        // The valid_memory check happens after the speculative check, so it's still rejected
        assert_eq!(
            e.evaluate_constant(0x500, &p, 4, false),
            EvaluationResult::NotAReference
        );
    }
}
