//! Disassembler context -- ported from Ghidra's `DisassemblerContextImpl.java`.
//!
//! Manages register context values during disassembly. Acts as a proxy
//! that overlays in-progress context changes on top of the program's
//! committed context, allowing the disassembler to track context register
//! modifications before they are committed to the program database.

use std::collections::HashMap;

use crate::base::analyzer::core::*;

/// A register value with associated mask indicating which bits are set.
#[derive(Debug, Clone)]
pub struct RegisterValue {
    /// Name of the register.
    pub register: String,
    /// The value (only bits where mask is 1 are meaningful).
    pub value: u128,
    /// Bit mask indicating which bits of `value` are valid.
    pub mask: u128,
}

impl RegisterValue {
    /// Create a new register value.
    pub fn new(register: impl Into<String>, value: u128, mask: u128) -> Self {
        Self {
            register: register.into(),
            value,
            mask,
        }
    }

    /// Create a register value where all bits are valid.
    pub fn full_value(register: impl Into<String>, value: u128, bit_size: u32) -> Self {
        let mask = if bit_size >= 128 {
            u128::MAX
        } else {
            (1u128 << bit_size) - 1
        };
        Self::new(register, value, mask)
    }

    /// Get the value with only valid bits.
    pub fn unsigned_value(&self) -> u128 {
        self.value & self.mask
    }

    /// Check if a specific bit is set (and valid).
    pub fn get_bit(&self, bit: u32) -> Option<bool> {
        if bit >= 128 {
            return None;
        }
        let bit_mask = 1u128 << bit;
        if self.mask & bit_mask == 0 {
            return None; // bit not valid
        }
        Some(self.value & bit_mask != 0)
    }

    /// Check if all bits are valid (mask is all-ones for the register width).
    pub fn is_full(&self, bit_size: u32) -> bool {
        let expected_mask = if bit_size >= 128 {
            u128::MAX
        } else {
            (1u128 << bit_size) - 1
        };
        self.mask & expected_mask == expected_mask
    }

    /// Combine this value with another, producing a value where bits from
    /// `other` take precedence where both are valid.
    pub fn combine(&self, other: &RegisterValue) -> RegisterValue {
        assert_eq!(self.register, other.register, "cannot combine different registers");
        let combined_mask = self.mask | other.mask;
        let combined_value = (self.value & !other.mask) | (other.value & other.mask);
        RegisterValue {
            register: self.register.clone(),
            value: combined_value,
            mask: combined_mask,
        }
    }
}

// ---------------------------------------------------------------------------
// DisassemblerContext
// ---------------------------------------------------------------------------

/// Context for disassembly, managing register values at addresses.
///
/// This is the disassembler's view of register context. It overlays
/// in-progress changes on top of the base program context, allowing
/// context-dependent disassembly decisions (e.g., ARM Thumb mode, MIPS
/// delay slots).
///
/// # Example
///
/// ```ignore
/// use ghidra_features::base::disassembler::context::DisassemblerContext;
/// use ghidra_features::base::disassembler::context::RegisterValue;
///
/// let mut ctx = DisassemblerContext::new();
/// let val = RegisterValue::full_value("TMode", 1, 1);
/// ctx.set_register_value(Address::new(0x1000), val);
/// ```
pub struct DisassemblerContext {
    /// Per-address register value overrides.
    context_map: HashMap<Address, HashMap<String, RegisterValue>>,
    /// Default (base) register values.
    default_values: HashMap<String, RegisterValue>,
    /// The base context register name (e.g., "CONTEXT" for x86).
    base_context_register: Option<String>,
}

impl DisassemblerContext {
    /// Create a new empty disassembler context.
    pub fn new() -> Self {
        Self {
            context_map: HashMap::new(),
            default_values: HashMap::new(),
            base_context_register: None,
        }
    }

    /// Set the base context register name.
    pub fn set_base_context_register(&mut self, name: impl Into<String>) {
        self.base_context_register = Some(name.into());
    }

    /// Get the base context register name.
    pub fn base_context_register(&self) -> Option<&str> {
        self.base_context_register.as_deref()
    }

    /// Set a default (base) register value that applies when no
    /// address-specific override exists.
    pub fn set_default_value(&mut self, value: RegisterValue) {
        self.default_values.insert(value.register.clone(), value);
    }

    /// Set a register value at a specific address.
    pub fn set_register_value(&mut self, addr: Address, value: RegisterValue) {
        self.context_map
            .entry(addr)
            .or_default()
            .insert(value.register.clone(), value);
    }

    /// Get the register value at a specific address, falling back to
    /// the default value if no override exists.
    pub fn get_register_value(&self, addr: &Address, register: &str) -> Option<&RegisterValue> {
        self.context_map
            .get(addr)
            .and_then(|m| m.get(register))
            .or_else(|| self.default_values.get(register))
    }

    /// Get the full context (all registers) at a specific address.
    pub fn get_context_at(&self, addr: &Address) -> HashMap<String, &RegisterValue> {
        let mut result = HashMap::new();
        // Start with defaults
        for (name, val) in &self.default_values {
            result.insert(name.clone(), val);
        }
        // Override with address-specific values
        if let Some(overrides) = self.context_map.get(addr) {
            for (name, val) in overrides {
                result.insert(name.clone(), val);
            }
        }
        result
    }

    /// Clear all context values at a specific address.
    pub fn clear_context_at(&mut self, addr: &Address) {
        self.context_map.remove(addr);
    }

    /// Check if context exists at a specific address.
    pub fn has_context_at(&self, addr: &Address) -> bool {
        self.context_map.contains_key(addr)
    }

    /// Get the total number of addresses with context overrides.
    pub fn num_addresses_with_context(&self) -> usize {
        self.context_map.len()
    }

    /// Copy context values from one address to another.
    pub fn copy_context(&mut self, from: &Address, to: Address) {
        if let Some(values) = self.context_map.get(from).cloned() {
            self.context_map.insert(to, values);
        }
    }

    /// Merge another context into this one, preferring values from `other`.
    pub fn merge_from(&mut self, other: &DisassemblerContext) {
        for (addr, values) in &other.context_map {
            let entry = self.context_map.entry(*addr).or_default();
            for (name, val) in values {
                entry.insert(name.clone(), val.clone());
            }
        }
        for (name, val) in &other.default_values {
            self.default_values.insert(name.clone(), val.clone());
        }
    }
}

impl Default for DisassemblerContext {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_value_basics() {
        let val = RegisterValue::full_value("TMode", 1, 1);
        assert_eq!(val.unsigned_value(), 1);
        assert_eq!(val.get_bit(0), Some(true));
        assert!(val.is_full(1));
    }

    #[test]
    fn test_register_value_partial() {
        let val = RegisterValue::new("Flags", 0b1010, 0b1100);
        assert_eq!(val.unsigned_value(), 0b1000); // only bits 2,3 valid
        assert_eq!(val.get_bit(0), None); // bit 0 not in mask
        assert_eq!(val.get_bit(2), Some(false)); // bit 2 valid but 0
        assert_eq!(val.get_bit(3), Some(true)); // bit 3 valid and 1
    }

    #[test]
    fn test_register_value_combine() {
        let base = RegisterValue::new("Ctx", 0xFF, 0xF0);
        let override_val = RegisterValue::new("Ctx", 0x05, 0x0F);
        let combined = base.combine(&override_val);
        assert_eq!(combined.mask, 0xFF);
        assert_eq!(combined.unsigned_value(), 0xF5);
    }

    #[test]
    fn test_context_set_and_get() {
        let mut ctx = DisassemblerContext::new();
        let addr = Address::new(0x1000);
        let val = RegisterValue::full_value("TMode", 1, 1);
        ctx.set_register_value(addr, val);

        let retrieved = ctx.get_register_value(&addr, "TMode").unwrap();
        assert_eq!(retrieved.unsigned_value(), 1);
    }

    #[test]
    fn test_context_default_fallback() {
        let mut ctx = DisassemblerContext::new();
        let val = RegisterValue::full_value("TMode", 0, 1);
        ctx.set_default_value(val);

        let addr = Address::new(0x5000);
        let retrieved = ctx.get_register_value(&addr, "TMode").unwrap();
        assert_eq!(retrieved.unsigned_value(), 0);
    }

    #[test]
    fn test_context_override_default() {
        let mut ctx = DisassemblerContext::new();
        ctx.set_default_value(RegisterValue::full_value("TMode", 0, 1));
        ctx.set_register_value(Address::new(0x1000), RegisterValue::full_value("TMode", 1, 1));

        // Address with override
        let val = ctx.get_register_value(&Address::new(0x1000), "TMode").unwrap();
        assert_eq!(val.unsigned_value(), 1);

        // Address without override -> falls back to default
        let val = ctx.get_register_value(&Address::new(0x2000), "TMode").unwrap();
        assert_eq!(val.unsigned_value(), 0);
    }

    #[test]
    fn test_context_copy() {
        let mut ctx = DisassemblerContext::new();
        let from = Address::new(0x1000);
        let to = Address::new(0x2000);
        ctx.set_register_value(from, RegisterValue::full_value("TMode", 1, 1));
        ctx.copy_context(&from, to);

        let val = ctx.get_register_value(&to, "TMode").unwrap();
        assert_eq!(val.unsigned_value(), 1);
    }

    #[test]
    fn test_context_merge() {
        let mut ctx1 = DisassemblerContext::new();
        ctx1.set_register_value(Address::new(0x1000), RegisterValue::full_value("TMode", 0, 1));

        let mut ctx2 = DisassemblerContext::new();
        ctx2.set_register_value(Address::new(0x1000), RegisterValue::full_value("TMode", 1, 1));
        ctx2.set_register_value(Address::new(0x2000), RegisterValue::full_value("TMode", 1, 1));

        ctx1.merge_from(&ctx2);
        let val = ctx1.get_register_value(&Address::new(0x1000), "TMode").unwrap();
        assert_eq!(val.unsigned_value(), 1);
        let val = ctx1.get_register_value(&Address::new(0x2000), "TMode").unwrap();
        assert_eq!(val.unsigned_value(), 1);
    }
}
