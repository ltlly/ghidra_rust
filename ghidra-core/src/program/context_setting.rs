//! Context register settings for Ghidra Rust.
//!
//! Direct translation of `ghidra.program.model.lang.ContextSetting`.
//!
//! Provides [`ContextSetting`] for describing a processor context register
//! value to be applied at a specific address.

use crate::addr::Address;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Describes a context register setting at a specific address.
///
/// Corresponds to `ghidra.program.model.lang.ContextSetting`.
///
/// A context setting associates a named context register with a value and
/// a mask. The mask indicates which bits of the register are being set.
/// This is used by the disassembler to apply processor context changes
/// (e.g., switching between ARM and Thumb mode).
///
/// # Examples
///
/// ```
/// use ghidra_core::program::context_setting::ContextSetting;
/// use ghidra_core::addr::Address;
///
/// let cs = ContextSetting::new("TMode", Address::new(0x401000), 1, 1);
/// assert_eq!(cs.register_name(), "TMode");
/// assert_eq!(cs.value(), 1);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextSetting {
    /// The name of the context register.
    register_name: String,
    /// The address at which this setting takes effect.
    address: Address,
    /// The value to set.
    value: u64,
    /// The mask indicating which bits are being set.
    mask: u64,
}

impl ContextSetting {
    /// Create a new context setting.
    pub fn new(
        register_name: impl Into<String>,
        address: Address,
        value: u64,
        mask: u64,
    ) -> Self {
        Self {
            register_name: register_name.into(),
            address,
            value,
            mask,
        }
    }

    /// Create a context setting that sets all bits of the register.
    pub fn full(
        register_name: impl Into<String>,
        address: Address,
        value: u64,
    ) -> Self {
        Self {
            register_name: register_name.into(),
            address,
            value,
            mask: u64::MAX,
        }
    }

    /// Create a single-bit context setting (mask = 1, value = 0 or 1).
    pub fn single_bit(
        register_name: impl Into<String>,
        address: Address,
        bit_value: bool,
    ) -> Self {
        Self {
            register_name: register_name.into(),
            address,
            value: if bit_value { 1 } else { 0 },
            mask: 1,
        }
    }

    /// Returns the name of the context register.
    pub fn register_name(&self) -> &str {
        &self.register_name
    }

    /// Returns the address at which this setting takes effect.
    pub fn address(&self) -> Address {
        self.address
    }

    /// Returns the value to set.
    pub fn value(&self) -> u64 {
        self.value
    }

    /// Returns the mask indicating which bits are being set.
    pub fn mask(&self) -> u64 {
        self.mask
    }

    /// Returns true if this setting modifies all bits of the register.
    pub fn is_full_register(&self) -> bool {
        self.mask == u64::MAX
    }

    /// Returns true if this setting modifies a single bit.
    pub fn is_single_bit(&self) -> bool {
        self.mask.count_ones() == 1
    }

    /// Returns the number of bits being set.
    pub fn num_bits_set(&self) -> u32 {
        self.mask.count_ones()
    }

    /// Apply this setting to a current register value.
    ///
    /// Returns the new value with the masked bits replaced.
    pub fn apply(&self, current_value: u64) -> u64 {
        (current_value & !self.mask) | (self.value & self.mask)
    }

    /// Returns true if the given value already matches this setting.
    pub fn is_already_set(&self, current_value: u64) -> bool {
        (current_value & self.mask) == (self.value & self.mask)
    }
}

impl fmt::Display for ContextSetting {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} @ {} = 0x{:x} (mask: 0x{:x})",
            self.register_name, self.address, self.value, self.mask
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let cs = ContextSetting::new("TMode", Address::new(0x401000), 1, 1);
        assert_eq!(cs.register_name(), "TMode");
        assert_eq!(cs.address().offset, 0x401000);
        assert_eq!(cs.value(), 1);
        assert_eq!(cs.mask(), 1);
    }

    #[test]
    fn test_full() {
        let cs = ContextSetting::full("ContextReg", Address::new(0x1000), 0xFF);
        assert!(cs.is_full_register());
        assert!(!cs.is_single_bit());
    }

    #[test]
    fn test_single_bit() {
        let cs = ContextSetting::single_bit("TMode", Address::new(0x1000), true);
        assert!(cs.is_single_bit());
        assert!(!cs.is_full_register());
        assert_eq!(cs.num_bits_set(), 1);
        assert_eq!(cs.value(), 1);
    }

    #[test]
    fn test_apply() {
        let cs = ContextSetting::new("TMode", Address::new(0x1000), 1, 1);
        assert_eq!(cs.apply(0), 1);
        assert_eq!(cs.apply(1), 1);
        assert_eq!(cs.apply(0xFF), 0xFF); // only bit 0 is affected
    }

    #[test]
    fn test_apply_multi_bit() {
        let cs = ContextSetting::new("Mode", Address::new(0x1000), 0b110, 0b111);
        assert_eq!(cs.apply(0b000), 0b110);
        assert_eq!(cs.apply(0b111), 0b110);
        assert_eq!(cs.apply(0b1000), 0b1110); // bit 3 preserved
    }

    #[test]
    fn test_is_already_set() {
        let cs = ContextSetting::new("TMode", Address::new(0x1000), 1, 1);
        assert!(cs.is_already_set(1));
        assert!(cs.is_already_set(0xFF)); // bit 0 is set
        assert!(!cs.is_already_set(0));
        assert!(!cs.is_already_set(0xFE)); // bit 0 is clear
    }

    #[test]
    fn test_num_bits_set() {
        let cs = ContextSetting::new("R", Address::new(0), 0, 0b1111);
        assert_eq!(cs.num_bits_set(), 4);
    }

    #[test]
    fn test_display() {
        let cs = ContextSetting::new("TMode", Address::new(0x401000), 1, 1);
        let s = format!("{}", cs);
        assert!(s.contains("TMode"));
        assert!(s.contains("00401000"));
    }

    #[test]
    fn test_clone() {
        let cs = ContextSetting::new("TMode", Address::new(0x1000), 1, 1);
        let cloned = cs.clone();
        assert_eq!(cs, cloned);
    }

    #[test]
    fn test_eq() {
        let a = ContextSetting::new("TMode", Address::new(0x1000), 1, 1);
        let b = ContextSetting::new("TMode", Address::new(0x1000), 1, 1);
        let c = ContextSetting::new("TMode", Address::new(0x1000), 0, 1);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
