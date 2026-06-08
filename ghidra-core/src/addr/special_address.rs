//! Special addresses for Ghidra Rust.
//!
//! Direct translation of `ghidra.program.model.address.SpecialAddress`.
//!
//! A [`SpecialAddress`] represents well-known addresses such as `NO_ADDRESS`
//! and `EXTERNAL_ADDEDRESS`. These use their address space name as their
//! display string (the offset is always 0).

use crate::addr::{Address, AddressSpace, AddrSpaceType, GenericAddress};
use std::fmt;
use std::sync::Arc;

/// A special (non-memory) address.
///
/// Corresponds to `ghidra.program.model.address.SpecialAddress`.
///
/// Special addresses are used for sentinel values like "no address" or
/// "external address". The display string is the name of the address
/// space itself, not a numeric offset.
#[derive(Debug, Clone)]
pub struct SpecialAddress {
    inner: GenericAddress,
}

impl SpecialAddress {
    /// Create a special address from a space name.
    ///
    /// This creates a new `GenericAddressSpace` with the given name,
    /// `pointer_size=0`, `type=NONE`, `unique_id=-1`, and offset 0.
    pub fn new(name: impl Into<String>) -> Self {
        let name_str = name.into();
        let space = Arc::new(AddressSpace {
            name: name_str,
            pointer_size: 0,
            big_endian: false,
            space_type: AddrSpaceType::Other,
            space_id: u32::MAX,
            is_overlay: false,
        });
        Self {
            inner: GenericAddress::new(space, 0),
        }
    }

    /// Returns a reference to the inner `GenericAddress`.
    pub fn as_generic(&self) -> &GenericAddress {
        &self.inner
    }

    /// Returns the name of this special address (the space name).
    pub fn name(&self) -> &str {
        &self.inner.get_address_space().name
    }

    /// Convert to a plain `Address` (offset 0).
    pub fn to_address(&self) -> Address {
        Address::new(0)
    }
}

impl fmt::Display for SpecialAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.inner.get_address_space().name)
    }
}

impl PartialEq for SpecialAddress {
    fn eq(&self, other: &Self) -> bool {
        self.inner.get_address_space().name == other.inner.get_address_space().name
    }
}

impl Eq for SpecialAddress {}

impl std::hash::Hash for SpecialAddress {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.inner.get_address_space().name.hash(state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_special_address_display() {
        let no_addr = SpecialAddress::new("NO_ADDRESS");
        assert_eq!(format!("{}", no_addr), "NO_ADDRESS");
    }

    #[test]
    fn test_special_address_equality() {
        let a = SpecialAddress::new("NO_ADDRESS");
        let b = SpecialAddress::new("NO_ADDRESS");
        assert_eq!(a, b);
    }

    #[test]
    fn test_special_address_inequality() {
        let a = SpecialAddress::new("NO_ADDRESS");
        let b = SpecialAddress::new("EXTERNAL");
        assert_ne!(a, b);
    }

    #[test]
    fn test_special_address_name() {
        let s = SpecialAddress::new("MY_SPECIAL");
        assert_eq!(s.name(), "MY_SPECIAL");
    }
}
