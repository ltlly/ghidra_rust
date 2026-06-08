//! Constant Propagation Context Evaluator.
//!
//! Ported from Ghidra's
//! `ghidra.app.plugin.core.analysis.ConstantPropagationContextEvaluator` (560 lines).
//!
//! Used as the evaluator for the SymbolicPropagator when finding constant
//! references and laying them down for a generic processor. Extend this class
//! to add additional checks and behaviors necessary for a unique processor
//! (e.g. PowerPC).
//!
//! This implementation checks values that are problematic and will not make
//! references to those locations:
//!   - 0-256 (null pointers and small offsets)
//!   - 0xffffffff, 0xffff, 0xfffffffe (common sentinel values)
//!
//! For some embedded processors these locations or these locations in certain
//! address spaces are OK, so the `evaluate_constant` and `evaluate_reference`
//! methods should be overridden.
//!
//! # Key Types
//!
//! - [`ConstantPropagationContextEvaluator`] -- The evaluator
//! - [`PropagationResult`] -- Result of evaluating a constant

use std::collections::HashSet;

use ghidra_core::Address;

/// Maximum Unicode string length for automatic data creation.
const MAX_UNICODE_STRING_LEN: usize = 200;

/// Maximum character string length for automatic data creation.
const MAX_CHAR_STRING_LEN: usize = 100;

/// Problematic address offsets that should not generate references.
const PROBLEMATIC_OFFSETS: &[u64] = &[0, 1, 2, 4, 8, 16, 32, 64, 128, 256];

/// Common sentinel values that should not generate references.
const SENTINEL_VALUES: &[u64] = &[0xFFFF_FFFF, 0xFFFF, 0xFFFF_FFFE];

// ---------------------------------------------------------------------------
// PropagationResult -- result of evaluating a constant
// ---------------------------------------------------------------------------

/// Result of evaluating a constant during propagation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PropagationResult {
    /// The constant is valid and a reference should be created.
    Accept,
    /// The constant is problematic and should be skipped.
    Reject,
    /// The constant may be valid but needs further investigation.
    Investigate,
}

impl PropagationResult {
    /// Whether this result indicates acceptance.
    pub fn is_accept(&self) -> bool {
        *self == Self::Accept
    }

    /// Whether this result indicates rejection.
    pub fn is_reject(&self) -> bool {
        *self == Self::Reject
    }
}

// ---------------------------------------------------------------------------
// ConstantPropagationContextEvaluator
// ---------------------------------------------------------------------------

/// Evaluates constants discovered during propagation to determine whether
/// references should be created.
///
/// Ported from `ghidra.app.plugin.core.analysis.ConstantPropagationContextEvaluator`.
///
/// The evaluator checks for problematic values (null pointers, small offsets,
/// sentinel values) and filters them out. It also tracks computed jump
/// destinations and supports configuration options for trusting memory
/// writes and controlling speculative reference generation.
#[derive(Debug)]
pub struct ConstantPropagationContextEvaluator {
    /// Whether to trust values read from writable memory.
    trust_memory_write: bool,
    /// Whether to create data from discovered pointers.
    create_data_from_pointers: bool,
    /// Minimum offset for store/load references.
    min_store_load_offset: u64,
    /// Minimum speculative offset (from beginning of memory).
    min_speculative_offset: u64,
    /// Maximum speculative offset (from end of memory).
    max_speculative_offset: u64,
    /// Set of destination addresses for computed jumps.
    dest_set: HashSet<u64>,
    /// Set of addresses that have already been processed.
    processed: HashSet<u64>,
    /// Problematic offsets to skip.
    skip_offsets: HashSet<u64>,
    /// Sentinel values to skip.
    skip_sentinels: HashSet<u64>,
    /// Whether to create strings from pointers.
    create_strings: bool,
}

impl ConstantPropagationContextEvaluator {
    /// Create a new evaluator with default settings.
    pub fn new() -> Self {
        Self {
            trust_memory_write: false,
            create_data_from_pointers: false,
            min_store_load_offset: 4,
            min_speculative_offset: 1024,
            max_speculative_offset: 256,
            dest_set: HashSet::new(),
            processed: HashSet::new(),
            skip_offsets: PROBLEMATIC_OFFSETS.iter().copied().collect(),
            skip_sentinels: SENTINEL_VALUES.iter().copied().collect(),
            create_strings: false,
        }
    }

    /// Create with trust-writable-memory option.
    pub fn with_trust_memory_write(trust: bool) -> Self {
        let mut eval = Self::new();
        eval.trust_memory_write = trust;
        eval
    }

    /// Create with full configuration.
    pub fn with_config(
        trust_memory_write: bool,
        min_store_load_offset: u64,
        min_speculative_offset: u64,
    ) -> Self {
        Self {
            trust_memory_write,
            min_store_load_offset,
            min_speculative_offset,
            ..Self::new()
        }
    }

    /// Set whether to trust reads from writable memory.
    pub fn set_trust_writable_memory(&mut self, trust: bool) -> &mut Self {
        self.trust_memory_write = trust;
        self
    }

    /// Whether reads from writable memory are trusted.
    pub fn is_trust_writable_memory(&self) -> bool {
        self.trust_memory_write
    }

    /// Set whether to create data from pointers.
    pub fn set_create_data_from_pointers(&mut self, create: bool) -> &mut Self {
        self.create_data_from_pointers = create;
        self
    }

    /// Whether data creation from pointers is enabled.
    pub fn is_create_data_from_pointers(&self) -> bool {
        self.create_data_from_pointers
    }

    /// Set the minimum store/load reference offset.
    pub fn set_min_store_load_offset(&mut self, offset: u64) -> &mut Self {
        self.min_store_load_offset = offset;
        self
    }

    /// Get the minimum store/load reference offset.
    pub fn min_store_load_offset(&self) -> u64 {
        self.min_store_load_offset
    }

    /// Set the minimum speculative reference offset.
    pub fn set_min_speculative_offset(&mut self, offset: u64) -> &mut Self {
        self.min_speculative_offset = offset;
        self
    }

    /// Get the minimum speculative reference offset.
    pub fn min_speculative_offset(&self) -> u64 {
        self.min_speculative_offset
    }

    /// Set the maximum speculative reference offset (from end of memory).
    pub fn set_max_speculative_offset(&mut self, offset: u64) -> &mut Self {
        self.max_speculative_offset = offset;
        self
    }

    /// Get the maximum speculative reference offset.
    pub fn max_speculative_offset(&self) -> u64 {
        self.max_speculative_offset
    }

    /// Enable or disable string creation from pointers.
    pub fn set_create_strings(&mut self, create: bool) -> &mut Self {
        self.create_strings = create;
        self
    }

    /// Whether string creation from pointers is enabled.
    pub fn is_create_strings(&self) -> bool {
        self.create_strings
    }

    // -----------------------------------------------------------------------
    // Core evaluation
    // -----------------------------------------------------------------------

    /// Evaluate a constant value to determine if it should generate a reference.
    ///
    /// Returns the propagation result for this value.
    ///
    /// Ported from `ConstantPropagationContextEvaluator.evaluateConstant()`.
    pub fn evaluate_constant(&self, value: u64, is_write: bool) -> PropagationResult {
        // If this is from a memory write and we trust writable memory
        if is_write && self.trust_memory_write {
            return PropagationResult::Accept;
        }

        // Check sentinel values
        if self.skip_sentinels.contains(&value) {
            return PropagationResult::Reject;
        }

        // Check small offsets (likely null pointer arithmetic)
        if value <= 256 {
            return PropagationResult::Reject;
        }

        PropagationResult::Accept
    }

    /// Evaluate whether a reference to the given address should be created.
    ///
    /// Ported from `ConstantPropagationContextEvaluator.evaluateReference()`.
    pub fn evaluate_reference(
        &self,
        _from: &Address,
        to: &Address,
        memory_size: u64,
    ) -> PropagationResult {
        let to_offset = to.offset;

        // Check if the target is in the problematic range
        if to_offset < self.min_speculative_offset {
            return PropagationResult::Reject;
        }

        // Check if too close to end of memory
        if memory_size > 0 && (memory_size.saturating_sub(to_offset)) < self.max_speculative_offset
        {
            return PropagationResult::Reject;
        }

        // Check if the target is in the skip set
        if self.skip_offsets.contains(&to_offset) {
            return PropagationResult::Reject;
        }

        // Check store/load references
        if to_offset < self.min_store_load_offset {
            return PropagationResult::Reject;
        }

        PropagationResult::Accept
    }

    /// Add a computed jump destination.
    ///
    /// Ported from tracking of `destSet` in the evaluator.
    pub fn add_destination(&mut self, addr: u64) {
        self.dest_set.insert(addr);
    }

    /// Get the set of computed jump destinations.
    pub fn destinations(&self) -> &HashSet<u64> {
        &self.dest_set
    }

    /// Clear the destination set.
    pub fn clear_destinations(&mut self) {
        self.dest_set.clear();
    }

    /// Mark an address as processed.
    pub fn mark_processed(&mut self, addr: u64) {
        self.processed.insert(addr);
    }

    /// Check if an address has been processed.
    pub fn is_processed(&self, addr: u64) -> bool {
        self.processed.contains(&addr)
    }

    /// Add a custom problematic offset.
    pub fn add_skip_offset(&mut self, offset: u64) {
        self.skip_offsets.insert(offset);
    }

    /// Add a custom sentinel value.
    pub fn add_skip_sentinel(&mut self, value: u64) {
        self.skip_sentinels.insert(value);
    }

    /// Check if a value should be considered for Unicode string creation.
    pub fn is_valid_unicode_string_offset(&self, offset: u64, mem_size: u64) -> bool {
        offset >= self.min_speculative_offset
            && (mem_size == 0 || offset + (MAX_UNICODE_STRING_LEN as u64 * 2) <= mem_size)
    }

    /// Check if a value should be considered for char string creation.
    pub fn is_valid_char_string_offset(&self, offset: u64, mem_size: u64) -> bool {
        offset >= self.min_speculative_offset
            && (mem_size == 0 || offset + MAX_CHAR_STRING_LEN as u64 <= mem_size)
    }
}

impl Default for ConstantPropagationContextEvaluator {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evaluator_new() {
        let eval = ConstantPropagationContextEvaluator::new();
        assert!(!eval.is_trust_writable_memory());
        assert!(!eval.is_create_data_from_pointers());
        assert_eq!(eval.min_store_load_offset(), 4);
        assert_eq!(eval.min_speculative_offset(), 1024);
        assert_eq!(eval.max_speculative_offset(), 256);
    }

    #[test]
    fn test_evaluate_constant_small_values() {
        let eval = ConstantPropagationContextEvaluator::new();
        // Small values should be rejected
        assert!(eval.evaluate_constant(0, false).is_reject());
        assert!(eval.evaluate_constant(1, false).is_reject());
        assert!(eval.evaluate_constant(256, false).is_reject());
        // Larger values should be accepted
        assert!(eval.evaluate_constant(0x401000, false).is_accept());
    }

    #[test]
    fn test_evaluate_constant_sentinel_values() {
        let eval = ConstantPropagationContextEvaluator::new();
        assert!(eval.evaluate_constant(0xFFFF_FFFF, false).is_reject());
        assert!(eval.evaluate_constant(0xFFFF, false).is_reject());
        assert!(eval.evaluate_constant(0xFFFF_FFFE, false).is_reject());
    }

    #[test]
    fn test_evaluate_constant_trust_write() {
        let eval = ConstantPropagationContextEvaluator::with_trust_memory_write(true);
        // Small values from trusted writes should be accepted
        assert!(eval.evaluate_constant(0, true).is_accept());
        assert!(eval.evaluate_constant(1, true).is_accept());
        // But non-write evaluation still rejects
        assert!(eval.evaluate_constant(0, false).is_reject());
    }

    #[test]
    fn test_evaluate_reference() {
        let eval = ConstantPropagationContextEvaluator::new();
        let from = Address::new(0x1000);
        let to_good = Address::new(0x401000);
        let to_bad = Address::new(0x10); // too low

        assert!(eval.evaluate_reference(&from, &to_good, 0x1_0000_0000).is_accept());
        assert!(eval.evaluate_reference(&from, &to_bad, 0x1_0000_0000).is_reject());
    }

    #[test]
    fn test_evaluate_reference_near_end_of_memory() {
        let eval = ConstantPropagationContextEvaluator::new();
        let from = Address::new(0x1000);
        // Memory size is 0x10000, to_offset=0xFE00 -> 0x10000-0xFE00=0x200=512 > 256 -> ok
        let to_ok = Address::new(0xFE00);
        assert!(eval.evaluate_reference(&from, &to_ok, 0x10000).is_accept());
        // to_offset=0xFFA0 -> 0x10000-0xFFA0=0x60=96 < 256 -> reject
        let to_bad = Address::new(0xFFA0);
        assert!(eval.evaluate_reference(&from, &to_bad, 0x10000).is_reject());
    }

    #[test]
    fn test_evaluate_reference_skip_offsets() {
        let mut eval = ConstantPropagationContextEvaluator::new();
        eval.add_skip_offset(0x401000);

        let from = Address::new(0x1000);
        let to = Address::new(0x401000);
        assert!(eval.evaluate_reference(&from, &to, 0x1_0000_0000).is_reject());
    }

    #[test]
    fn test_destinations() {
        let mut eval = ConstantPropagationContextEvaluator::new();
        eval.add_destination(0x401000);
        eval.add_destination(0x402000);
        assert_eq!(eval.destinations().len(), 2);
        assert!(eval.destinations().contains(&0x401000));

        eval.clear_destinations();
        assert!(eval.destinations().is_empty());
    }

    #[test]
    fn test_processed_tracking() {
        let mut eval = ConstantPropagationContextEvaluator::new();
        assert!(!eval.is_processed(0x401000));
        eval.mark_processed(0x401000);
        assert!(eval.is_processed(0x401000));
        assert!(!eval.is_processed(0x402000));
    }

    #[test]
    fn test_with_config() {
        let eval = ConstantPropagationContextEvaluator::with_config(true, 8, 2048);
        assert!(eval.is_trust_writable_memory());
        assert_eq!(eval.min_store_load_offset(), 8);
        assert_eq!(eval.min_speculative_offset(), 2048);
    }

    #[test]
    fn test_setters() {
        let mut eval = ConstantPropagationContextEvaluator::new();
        eval.set_trust_writable_memory(true);
        assert!(eval.is_trust_writable_memory());

        eval.set_create_data_from_pointers(true);
        assert!(eval.is_create_data_from_pointers());

        eval.set_create_strings(true);
        assert!(eval.is_create_strings());

        eval.set_min_store_load_offset(16);
        assert_eq!(eval.min_store_load_offset(), 16);

        eval.set_min_speculative_offset(4096);
        assert_eq!(eval.min_speculative_offset(), 4096);

        eval.set_max_speculative_offset(512);
        assert_eq!(eval.max_speculative_offset(), 512);
    }

    #[test]
    fn test_custom_sentinel() {
        let mut eval = ConstantPropagationContextEvaluator::new();
        eval.add_skip_sentinel(0xDEAD_BEEF);
        assert!(eval.evaluate_constant(0xDEAD_BEEF, false).is_reject());
    }

    #[test]
    fn test_string_offset_validation() {
        let eval = ConstantPropagationContextEvaluator::new();
        // Valid Unicode string offset (enough room for 200 UTF-16 chars = 400 bytes)
        assert!(eval.is_valid_unicode_string_offset(0x10000, 0x100000));
        // Too low
        assert!(!eval.is_valid_unicode_string_offset(0x100, 0x100000));
        // Too close to end (offset + 400 > mem_size)
        // 0xFFE00 + 400 = 0xFFF90 > 0x100000 is false... let's use 0xFFFE0
        // 0xFFFE0 + 400 = 0x100170 > 0x100000 -> true, so this should be invalid
        assert!(!eval.is_valid_unicode_string_offset(0xFFFE0, 0x100000));

        // Valid char string offset (enough room for 100 chars)
        assert!(eval.is_valid_char_string_offset(0x10000, 0x100000));
        // Too low
        assert!(!eval.is_valid_char_string_offset(0x100, 0x100000));
        // Too close to end: 0xFFFC0 + 100 = 0x100024 > 0x100000
        assert!(!eval.is_valid_char_string_offset(0xFFFC0, 0x100000));
    }

    #[test]
    fn test_string_offset_zero_mem_size() {
        let eval = ConstantPropagationContextEvaluator::new();
        // Zero memory size means no bound check
        assert!(eval.is_valid_unicode_string_offset(0x10000, 0));
        assert!(eval.is_valid_char_string_offset(0x10000, 0));
    }

    #[test]
    fn test_propagation_result() {
        assert!(PropagationResult::Accept.is_accept());
        assert!(!PropagationResult::Accept.is_reject());
        assert!(PropagationResult::Reject.is_reject());
        assert!(!PropagationResult::Reject.is_accept());
        assert!(!PropagationResult::Investigate.is_accept());
        assert!(!PropagationResult::Investigate.is_reject());
    }

    #[test]
    fn test_evaluate_constant_boundary() {
        let eval = ConstantPropagationContextEvaluator::new();
        // 256 is rejected, 257 is accepted
        assert!(eval.evaluate_constant(256, false).is_reject());
        assert!(eval.evaluate_constant(257, false).is_accept());
    }
}
