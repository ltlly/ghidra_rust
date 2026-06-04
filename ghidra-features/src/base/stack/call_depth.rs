//! Call depth change information -- tracks the cumulative stack depth
//! change through a function.
//!
//! Ported from Ghidra's `CallDepthChangeInfo`.

use crate::base::analyzer::core::Address;

// ============================================================================
// CallDepthChangeInfo
// ============================================================================

/// Tracks the cumulative stack depth change through a function's body.
///
/// This mirrors Ghidra's `CallDepthChangeInfo`, which is used by
/// `FunctionStackAnalysisCmd` to determine the stack offset for each
/// instruction operand by following the stack-pointer register through
/// pushes, pops, SUB/ADD instructions, and CALL/RET sequences.
///
/// The "stack purge" is the net bytes removed from the stack by the
/// function's epilogue.
#[derive(Debug, Clone)]
pub struct CallDepthChangeInfo {
    /// The entry point address of the function being analyzed.
    pub function_entry: Address,
    /// The computed stack purge (net bytes removed on return).
    /// A negative value means the function adds to the stack (e.g.,
    /// sub rsp, N).
    pub stack_purge: i32,
    /// Per-address stack depth changes recorded during analysis.
    /// Key = instruction address, value = cumulative depth at that point.
    depth_map: Vec<(Address, i32)>,
}

impl CallDepthChangeInfo {
    /// Sentinel value for unknown or invalid stack depth change.
    pub const INVALID_STACK_DEPTH_CHANGE: i32 = i32::MAX;

    /// Create a new call depth change info for the given function entry.
    pub fn new(function_entry: Address) -> Self {
        Self {
            function_entry,
            stack_purge: 0,
            depth_map: Vec::new(),
        }
    }

    /// Create with a pre-computed stack purge.
    pub fn with_purge(function_entry: Address, stack_purge: i32) -> Self {
        Self {
            function_entry,
            stack_purge,
            depth_map: Vec::new(),
        }
    }

    /// Record a stack depth at a given instruction address.
    pub fn record_depth(&mut self, addr: Address, depth: i32) {
        self.depth_map.push((addr, depth));
    }

    /// Get the cumulative stack depth at a given instruction address.
    ///
    /// Returns `None` if no depth was recorded for this address.
    pub fn get_depth_at(&self, addr: &Address) -> Option<i32> {
        self.depth_map
            .iter()
            .find(|(a, _)| *a == *addr)
            .map(|(_, d)| *d)
    }

    /// Get the stack offset for a given instruction operand.
    ///
    /// This is the cumulative depth at the instruction address plus
    /// any operand-specific offset.
    ///
    /// Returns `INVALID_STACK_DEPTH_CHANGE` if no depth was recorded.
    pub fn get_stack_offset(&self, addr: &Address, operand_offset: i32) -> i32 {
        match self.get_depth_at(addr) {
            Some(depth) => depth + operand_offset,
            None => Self::INVALID_STACK_DEPTH_CHANGE,
        }
    }

    /// The computed stack purge.
    pub fn get_stack_purge(&self) -> i32 {
        self.stack_purge
    }

    /// Set the stack purge value.
    pub fn set_stack_purge(&mut self, purge: i32) {
        self.stack_purge = purge;
    }

    /// Number of recorded depth entries.
    pub fn len(&self) -> usize {
        self.depth_map.len()
    }

    /// Whether no depths have been recorded.
    pub fn is_empty(&self) -> bool {
        self.depth_map.is_empty()
    }
}

// ============================================================================
// StackAdjustment
// ============================================================================

/// A stack adjustment event observed during instruction traversal.
///
/// When processing instructions that modify the stack pointer (e.g.,
/// `PUSH`, `POP`, `SUB ESP, N`, `ADD ESP, N`), the analyzer creates
/// one of these to track the change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StackAdjustment {
    /// Address of the instruction that caused the adjustment.
    pub address: Address,
    /// The signed delta: negative for pushes (grow stack), positive
    /// for pops (shrink stack).
    pub delta: i32,
}

impl StackAdjustment {
    /// Create a new stack adjustment.
    pub fn new(address: Address, delta: i32) -> Self {
        Self { address, delta }
    }

    /// Whether this adjustment grows the stack (push).
    pub fn is_push(&self) -> bool {
        self.delta < 0
    }

    /// Whether this adjustment shrinks the stack (pop).
    pub fn is_pop(&self) -> bool {
        self.delta > 0
    }

    /// Whether this is a no-op adjustment.
    pub fn is_noop(&self) -> bool {
        self.delta == 0
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(offset: u64) -> Address {
        Address::new(offset)
    }

    // -- CallDepthChangeInfo tests --

    #[test]
    fn test_call_depth_creation() {
        let info = CallDepthChangeInfo::new(addr(0x401000));
        assert_eq!(info.function_entry, addr(0x401000));
        assert_eq!(info.stack_purge, 0);
        assert!(info.is_empty());
    }

    #[test]
    fn test_call_depth_with_purge() {
        let info = CallDepthChangeInfo::with_purge(addr(0x401000), 8);
        assert_eq!(info.get_stack_purge(), 8);
    }

    #[test]
    fn test_record_and_get_depth() {
        let mut info = CallDepthChangeInfo::new(addr(0x401000));
        info.record_depth(addr(0x401000), -8);
        info.record_depth(addr(0x401010), -16);
        info.record_depth(addr(0x401020), -8);

        assert_eq!(info.get_depth_at(&addr(0x401000)), Some(-8));
        assert_eq!(info.get_depth_at(&addr(0x401010)), Some(-16));
        assert_eq!(info.get_depth_at(&addr(0x401020)), Some(-8));
        assert_eq!(info.get_depth_at(&addr(0x401099)), None);
        assert_eq!(info.len(), 3);
    }

    #[test]
    fn test_get_stack_offset() {
        let mut info = CallDepthChangeInfo::new(addr(0x401000));
        info.record_depth(addr(0x401000), -8);

        // At instruction 0x401000 with depth -8, offset 0 => -8
        assert_eq!(info.get_stack_offset(&addr(0x401000), 0), -8);
        // With operand offset 4 => -4
        assert_eq!(info.get_stack_offset(&addr(0x401000), 4), -4);
        // Unknown address => INVALID
        assert_eq!(
            info.get_stack_offset(&addr(0x401099), 0),
            CallDepthChangeInfo::INVALID_STACK_DEPTH_CHANGE
        );
    }

    #[test]
    fn test_set_stack_purge() {
        let mut info = CallDepthChangeInfo::new(addr(0x401000));
        assert_eq!(info.get_stack_purge(), 0);
        info.set_stack_purge(16);
        assert_eq!(info.get_stack_purge(), 16);
    }

    #[test]
    fn test_invalid_stack_depth_constant() {
        assert_eq!(CallDepthChangeInfo::INVALID_STACK_DEPTH_CHANGE, i32::MAX);
    }

    // -- StackAdjustment tests --

    #[test]
    fn test_stack_adjustment_push() {
        let adj = StackAdjustment::new(addr(0x401000), -8);
        assert!(adj.is_push());
        assert!(!adj.is_pop());
        assert!(!adj.is_noop());
    }

    #[test]
    fn test_stack_adjustment_pop() {
        let adj = StackAdjustment::new(addr(0x401000), 8);
        assert!(!adj.is_push());
        assert!(adj.is_pop());
        assert!(!adj.is_noop());
    }

    #[test]
    fn test_stack_adjustment_noop() {
        let adj = StackAdjustment::new(addr(0x401000), 0);
        assert!(!adj.is_push());
        assert!(!adj.is_pop());
        assert!(adj.is_noop());
    }

    #[test]
    fn test_clone_eq() {
        let adj1 = StackAdjustment::new(addr(0x401000), -4);
        let adj2 = adj1;
        assert_eq!(adj1, adj2);
    }
}
