//! P-code injection context for Ghidra Rust.
//!
//! Direct translation of `ghidra.program.model.lang.InjectContext`.
//!
//! Provides [`InjectContext`] which carries the context needed to perform
//! a pcode injection (e.g., for call-fixup or callee-fixup).

use crate::addr::Address;
use crate::pcode::Varnode;

/// Context for a pcode injection.
///
/// Corresponds to `ghidra.program.model.lang.InjectContext`.
///
/// When a pcode injection is triggered (e.g., a call-fixup), this context
/// carries all the information needed to execute the injected pcode:
/// - The base address of the injecting instruction
/// - The address of the next instruction
/// - For call injections, the address of the function being called
/// - Input parameters (varnodes) for the injection
/// - Output parameters (varnodes) for the injection
///
/// # Examples
///
/// ```ignore
/// use ghidra_core::pcode::inject::InjectContext;
/// use ghidra_core::addr::Address;
///
/// let mut ctx = InjectContext::new();
/// ctx.base_addr = Address::new(0x401000);
/// ctx.next_addr = Address::new(0x401005);
/// ```
#[derive(Debug, Clone, Default)]
pub struct InjectContext {
    /// Base address of the instruction causing the injection.
    pub base_addr: Address,

    /// Address of the next instruction following the injecting instruction.
    pub next_addr: Address,

    /// For a call inject, the address of the function being called.
    pub call_addr: Address,

    /// Reference address (context-dependent).
    pub ref_addr: Address,

    /// Input parameters for the injection.
    pub input_list: Vec<Varnode>,

    /// Output parameters for the injection.
    pub output: Vec<Varnode>,
}

impl InjectContext {
    /// Create a new empty inject context.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create an inject context with the given base and next addresses.
    pub fn with_addresses(base_addr: Address, next_addr: Address) -> Self {
        Self {
            base_addr,
            next_addr,
            ..Default::default()
        }
    }

    /// Create a call inject context with the given addresses.
    pub fn for_call(
        base_addr: Address,
        next_addr: Address,
        call_addr: Address,
    ) -> Self {
        Self {
            base_addr,
            next_addr,
            call_addr,
            ..Default::default()
        }
    }

    /// Add an input varnode to the injection context.
    pub fn add_input(&mut self, varnode: Varnode) {
        self.input_list.push(varnode);
    }

    /// Add an output varnode to the injection context.
    pub fn add_output(&mut self, varnode: Varnode) {
        self.output.push(varnode);
    }

    /// Returns the number of input parameters.
    pub fn num_inputs(&self) -> usize {
        self.input_list.len()
    }

    /// Returns the number of output parameters.
    pub fn num_outputs(&self) -> usize {
        self.output.len()
    }

    /// Returns true if this is a call injection (has a call address).
    pub fn is_call_inject(&self) -> bool {
        !self.call_addr.is_null()
    }

    /// Clear all input and output parameters.
    pub fn clear(&mut self) {
        self.input_list.clear();
        self.output.clear();
    }

    /// Reset the entire context to default values.
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let ctx = InjectContext::new();
        assert!(ctx.base_addr.is_null());
        assert!(ctx.input_list.is_empty());
        assert!(ctx.output.is_empty());
    }

    #[test]
    fn test_with_addresses() {
        let ctx = InjectContext::with_addresses(
            Address::new(0x401000),
            Address::new(0x401005),
        );
        assert_eq!(ctx.base_addr.offset, 0x401000);
        assert_eq!(ctx.next_addr.offset, 0x401005);
    }

    #[test]
    fn test_for_call() {
        let ctx = InjectContext::for_call(
            Address::new(0x401000),
            Address::new(0x401005),
            Address::new(0x402000),
        );
        assert_eq!(ctx.base_addr.offset, 0x401000);
        assert_eq!(ctx.next_addr.offset, 0x401005);
        assert_eq!(ctx.call_addr.offset, 0x402000);
        assert!(ctx.is_call_inject());
    }

    #[test]
    fn test_add_input() {
        let mut ctx = InjectContext::new();
        let vn = Varnode::new(Address::new(0), 4);
        ctx.add_input(vn);
        assert_eq!(ctx.num_inputs(), 1);
    }

    #[test]
    fn test_add_output() {
        let mut ctx = InjectContext::new();
        let vn = Varnode::new(Address::new(0), 4);
        ctx.add_output(vn);
        assert_eq!(ctx.num_outputs(), 1);
    }

    #[test]
    fn test_is_call_inject() {
        let mut ctx = InjectContext::new();
        assert!(!ctx.is_call_inject());

        ctx.call_addr = Address::new(0x402000);
        assert!(ctx.is_call_inject());
    }

    #[test]
    fn test_clear() {
        let mut ctx = InjectContext::new();
        ctx.add_input(Varnode::new(Address::new(0), 4));
        ctx.add_output(Varnode::new(Address::new(0), 4));
        ctx.clear();
        assert!(ctx.input_list.is_empty());
        assert!(ctx.output.is_empty());
    }

    #[test]
    fn test_reset() {
        let mut ctx = InjectContext::for_call(
            Address::new(0x401000),
            Address::new(0x401005),
            Address::new(0x402000),
        );
        ctx.add_input(Varnode::new(Address::new(0), 4));
        ctx.reset();
        assert!(ctx.base_addr.is_null());
        assert!(ctx.input_list.is_empty());
    }

    #[test]
    fn test_clone() {
        let mut ctx = InjectContext::new();
        ctx.base_addr = Address::new(0x401000);
        ctx.add_input(Varnode::new(Address::new(0), 4));

        let cloned = ctx.clone();
        assert_eq!(cloned.base_addr.offset, 0x401000);
        assert_eq!(cloned.num_inputs(), 1);
    }
}
