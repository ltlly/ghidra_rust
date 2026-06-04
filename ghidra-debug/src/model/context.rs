//! TraceRegisterContextOperations - operations on register context values.
//!
//! Ported from Ghidra's `ghidra.trace.model.context.TraceRegisterContextOperations`.
//! Defines the interface for reading and writing register context values
//! (language-defined context register settings) that affect instruction
//! decoding at specific address/snap ranges.

use serde::{Deserialize, Serialize};

use super::lifespan::Lifespan;

/// A simplified register identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RegisterId {
    /// The register name (e.g., "TMode", "opsize").
    pub name: String,
    /// Size in bytes.
    pub size: u32,
}

impl RegisterId {
    /// Create a new register identifier.
    pub fn new(name: impl Into<String>, size: u32) -> Self {
        Self {
            name: name.into(),
            size,
        }
    }
}

/// A simplified language identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LanguageId {
    /// The language ID string (e.g., "x86:LE:64:default").
    pub id: String,
}

impl LanguageId {
    /// Create a new language identifier.
    pub fn new(id: impl Into<String>) -> Self {
        Self { id: id.into() }
    }
}

/// A register value with optional mask for un/defined bits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextRegisterValue {
    /// The register this value applies to.
    pub register: RegisterId,
    /// The value bytes (little-endian).
    pub value: Vec<u8>,
    /// Optional mask indicating which bits are defined (all-ones mask = fully defined).
    pub mask: Option<Vec<u8>>,
}

impl ContextRegisterValue {
    /// Create a fully defined register value.
    pub fn new(register: RegisterId, value: Vec<u8>) -> Self {
        Self {
            register,
            value,
            mask: None,
        }
    }

    /// Create a partially defined register value with a mask.
    pub fn with_mask(mut self, mask: Vec<u8>) -> Self {
        self.mask = Some(mask);
        self
    }

    /// Check if a specific bit is defined.
    pub fn is_bit_defined(&self, bit: usize) -> bool {
        match &self.mask {
            Some(m) => {
                let byte_idx = bit / 8;
                let bit_idx = bit % 8;
                byte_idx < m.len() && (m[byte_idx] & (1 << bit_idx)) != 0
            }
            None => true,
        }
    }

    /// Get the value as a u64 (for registers up to 8 bytes).
    pub fn as_u64(&self) -> u64 {
        let mut val = 0u64;
        for (i, &b) in self.value.iter().enumerate().take(8) {
            val |= (b as u64) << (i * 8);
        }
        val
    }
}

/// An address range for context register operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextAddressRange {
    /// Start address (inclusive).
    pub min: u64,
    /// End address (inclusive).
    pub max: u64,
}

impl ContextAddressRange {
    /// Create a new address range.
    pub fn new(min: u64, max: u64) -> Self {
        Self { min, max }
    }

    /// Check if the range contains an address.
    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.min && addr <= self.max
    }
}

/// Operations for managing register context values in a trace.
///
/// Register context values are language-defined settings that affect how
/// instructions are decoded. For example, ARM's TMode register determines
/// whether to decode Thumb or ARM instructions.
pub trait TraceRegisterContextOperations {
    /// Get the language-defined default value of a register at an address.
    fn get_default_value(&self, language: &LanguageId, register: &RegisterId, address: u64)
        -> Option<ContextRegisterValue>;

    /// Set a register context value over a lifespan and address range.
    fn set_value(
        &mut self,
        language: &LanguageId,
        value: &ContextRegisterValue,
        lifespan: Lifespan,
        range: &ContextAddressRange,
    );

    /// Remove a register context value over a lifespan and address range.
    fn remove_value(
        &mut self,
        language: &LanguageId,
        register: &RegisterId,
        lifespan: Lifespan,
        range: &ContextAddressRange,
    );

    /// Get the register value at a specific snap and address.
    fn get_value(
        &self,
        language: &LanguageId,
        register: &RegisterId,
        snap: i64,
        address: u64,
    ) -> Option<ContextRegisterValue>;

    /// Get the value with language default applied if no explicit value exists.
    fn get_value_with_default(
        &self,
        language: &LanguageId,
        register: &RegisterId,
        snap: i64,
        address: u64,
    ) -> Option<ContextRegisterValue>;

    /// Check if a register has a value at the given snap and address range.
    fn has_register_value_in_range(
        &self,
        language: &LanguageId,
        register: &RegisterId,
        snap: i64,
        range: &ContextAddressRange,
    ) -> bool;

    /// Check if a register has any value at the given snap.
    fn has_register_value(
        &self,
        language: &LanguageId,
        register: &RegisterId,
        snap: i64,
    ) -> bool;

    /// Clear all context values in the given lifespan and address range.
    fn clear(&mut self, lifespan: Lifespan, range: &ContextAddressRange);
}

/// A space (address space) for register context values.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceRegisterContextSpace {
    /// The address space name.
    pub space_name: String,
    /// The language this space belongs to.
    pub language: LanguageId,
}

impl TraceRegisterContextSpace {
    /// Create a new context space.
    pub fn new(space_name: impl Into<String>, language: LanguageId) -> Self {
        Self {
            space_name: space_name.into(),
            language,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_context_register_value() {
        let reg = RegisterId::new("TMode", 1);
        let val = ContextRegisterValue::new(reg.clone(), vec![1]);
        assert_eq!(val.as_u64(), 1);
        assert!(val.is_bit_defined(0));
    }

    #[test]
    fn test_context_register_value_with_mask() {
        let reg = RegisterId::new("flags", 2);
        let val = ContextRegisterValue::new(reg, vec![0xFF, 0x00])
            .with_mask(vec![0xFF, 0x0F]);
        assert!(val.is_bit_defined(0));
        assert!(val.is_bit_defined(7));
        assert!(val.is_bit_defined(8));
        assert!(!val.is_bit_defined(12));
    }

    #[test]
    fn test_address_range() {
        let range = ContextAddressRange::new(0x1000, 0x2000);
        assert!(range.contains(0x1500));
        assert!(!range.contains(0x3000));
        assert!(range.contains(0x1000));
        assert!(range.contains(0x2000));
    }

    #[test]
    fn test_register_id() {
        let reg = RegisterId::new("opsize", 1);
        assert_eq!(reg.name, "opsize");
        assert_eq!(reg.size, 1);
    }

    #[test]
    fn test_language_id() {
        let lang = LanguageId::new("x86:LE:64:default");
        assert_eq!(lang.id, "x86:LE:64:default");
    }

    #[test]
    fn test_context_space() {
        let lang = LanguageId::new("ARM:LE:32:v8");
        let space = TraceRegisterContextSpace::new("register", lang);
        assert_eq!(space.space_name, "register");
    }
}
