//! Default address factory implementation.
//!
//! Direct translation of `ghidra.program.model.address.DefaultAddressFactory`.
//!
//! Provides [`DefaultAddressFactory`] -- a full address factory that manages
//! multiple address spaces, supports parsing address strings, and validates
//! that reserved spaces (stack, external, variable, join) are not duplicated.

use crate::addr::{Address, AddressSet, AddrSpaceType};
use crate::addr::address_factory::AddressFactory;
use crate::addr::generic_address_space::GenericAddressSpace;
use std::collections::HashMap;

/// Error for duplicate or invalid address space names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DuplicateSpaceError(pub String);

impl std::fmt::Display for DuplicateSpaceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Duplicate address space: {}", self.0)
    }
}

impl std::error::Error for DuplicateSpaceError {}

/// Reserved space type constants.
const TYPE_VARIABLE: u8 = 11;
const TYPE_JOIN: u8 = 6;
const TYPE_EXTERNAL: u8 = 10;
const TYPE_STACK: u8 = 5;

/// Join space name.
const JOIN_SPACE_NAME: &str = "join";

/// A full address factory managing multiple address spaces.
///
/// Corresponds to `ghidra.program.model.address.DefaultAddressFactory`.
///
/// Manages all known address spaces, provides lookup by name and ID,
/// and handles parsing of address strings with optional space-name prefixes.
///
/// # Examples
///
/// ```
/// use ghidra_core::addr::AddrSpaceType;
/// use ghidra_core::addr::default_address_factory::DefaultAddressFactory;
/// use ghidra_core::addr::generic_address_space::GenericAddressSpace;
///
/// let ram = GenericAddressSpace::new("ram", 32, 1, AddrSpaceType::Ram, 1);
/// let reg = GenericAddressSpace::new("register", 32, 1, AddrSpaceType::Register, 2);
///
/// let factory = DefaultAddressFactory::new(vec![ram, reg], Some("ram")).unwrap();
/// assert_eq!(factory.num_address_spaces(), 2);
/// assert!(factory.get_space_by_name("ram").is_some());
/// ```
#[derive(Debug, Clone)]
pub struct DefaultAddressFactory {
    /// Ordered list of all address spaces.
    spaces: Vec<GenericAddressSpace>,
    /// Lookup by name.
    by_name: HashMap<String, usize>,
    /// Lookup by space ID.
    by_id: HashMap<u32, usize>,
    /// Index of the default space.
    default_index: usize,
    /// Index of the constant space (if any).
    constant_index: Option<usize>,
    /// Index of the unique space (if any).
    unique_index: Option<usize>,
    /// Index of the register space (if any).
    register_index: Option<usize>,
    /// Address set spanning all memory spaces.
    memory_address_set: AddressSet,
}

impl DefaultAddressFactory {
    /// Create a new default address factory.
    ///
    /// The first space in the list becomes the default if `default_space_name`
    /// is `None`.
    ///
    /// # Errors
    ///
    /// Returns `Err` if:
    /// - A reserved space type (variable, join, external, stack) is specified
    /// - Duplicate space names exist
    /// - The specified default space name is not in the list
    /// - More than one register space is specified
    pub fn new(
        spaces: Vec<GenericAddressSpace>,
        default_space_name: Option<&str>,
    ) -> Result<Self, DuplicateSpaceError> {
        let mut by_name = HashMap::new();
        let mut by_id = HashMap::new();
        let mut constant_index = None;
        let mut unique_index = None;
        let mut register_index = None;
        let mut memory_address_set = AddressSet::new();

        // Validate reserved spaces
        for space in &spaces {
            Self::check_reserved_space(space)?;
        }

        // Check for duplicates and register
        for (i, space) in spaces.iter().enumerate() {
            if by_name.contains_key(space.name()) {
                return Err(DuplicateSpaceError(format!(
                    "Space named '{}' already exists",
                    space.name()
                )));
            }
            by_name.insert(space.name().to_string(), i);
            by_id.insert(space.space_id(), i);

            match space.space_type() {
                AddrSpaceType::Constant => constant_index = Some(i),
                AddrSpaceType::Unique => unique_index = Some(i),
                AddrSpaceType::Register => {
                    if register_index.is_some()
                        || !space.name().eq_ignore_ascii_case("register")
                    {
                        return Err(DuplicateSpaceError(
                            "Ghidra can only support a single Register space named 'register'"
                                .to_string(),
                        ));
                    }
                    register_index = Some(i);
                }
                _ => {}
            }

            // Build memory address set
            if space.is_memory_space() {
                memory_address_set.add_range(space.min_address(), space.max_address());
            }
        }

        // Determine default space
        let default_index = if let Some(name) = default_space_name {
            *by_name
                .get(name)
                .ok_or_else(|| DuplicateSpaceError(format!("Default space '{}' not found", name)))?
        } else {
            0
        };

        Ok(Self {
            spaces,
            by_name,
            by_id,
            default_index,
            constant_index,
            unique_index,
            register_index,
            memory_address_set,
        })
    }

    fn check_reserved_space(space: &GenericAddressSpace) -> Result<(), DuplicateSpaceError> {
        let st = space.space_type() as u8;
        if st == TYPE_VARIABLE {
            return Err(DuplicateSpaceError(
                "Variable space should not be specified".to_string(),
            ));
        }
        if st == TYPE_JOIN || space.name() == JOIN_SPACE_NAME {
            return Err(DuplicateSpaceError(
                "Join space should not be specified".to_string(),
            ));
        }
        if st == TYPE_EXTERNAL {
            return Err(DuplicateSpaceError(
                "External space should not be specified".to_string(),
            ));
        }
        if st == TYPE_STACK {
            return Err(DuplicateSpaceError(
                "Stack space should not be specified".to_string(),
            ));
        }
        Ok(())
    }

    // -- Space lookup --

    /// Look up a space by name.
    pub fn get_space_by_name(&self, name: &str) -> Option<&GenericAddressSpace> {
        self.by_name.get(name).map(|&i| &self.spaces[i])
    }

    /// Look up a space by numeric ID.
    pub fn get_space_by_id(&self, id: u32) -> Option<&GenericAddressSpace> {
        self.by_id.get(&id).map(|&i| &self.spaces[i])
    }

    /// The default address space.
    pub fn default_space(&self) -> &GenericAddressSpace {
        &self.spaces[self.default_index]
    }

    /// All registered spaces.
    pub fn all_spaces(&self) -> &[GenericAddressSpace] {
        &self.spaces
    }

    /// Number of registered spaces.
    pub fn num_address_spaces(&self) -> usize {
        self.spaces.len()
    }

    /// The constant space, if registered.
    pub fn constant_space(&self) -> Option<&GenericAddressSpace> {
        self.constant_index.map(|i| &self.spaces[i])
    }

    /// The unique space, if registered.
    pub fn unique_space(&self) -> Option<&GenericAddressSpace> {
        self.unique_index.map(|i| &self.spaces[i])
    }

    /// The register space, if registered.
    pub fn register_space(&self) -> Option<&GenericAddressSpace> {
        self.register_index.map(|i| &self.spaces[i])
    }

    /// True if there is more than one memory address space.
    pub fn has_multiple_memory_spaces(&self) -> bool {
        self.spaces.iter().filter(|s| s.is_memory_space()).count() > 1
    }

    /// The set of all memory-space addresses.
    pub fn memory_address_set(&self) -> &AddressSet {
        &self.memory_address_set
    }

    /// Returns all physical (memory) spaces.
    pub fn physical_spaces(&self) -> Vec<&GenericAddressSpace> {
        self.spaces.iter().filter(|s| s.is_memory_space()).collect()
    }

    // -- Address creation --

    /// Create an address in the default space.
    pub fn new_address(&self, offset: u64) -> Address {
        Address::new(offset)
    }

    /// Create an address in the space with the given ID.
    pub fn get_address(&self, space_id: u32, offset: u64) -> Option<Address> {
        if self.by_id.contains_key(&space_id) {
            Some(Address::new(offset))
        } else {
            None
        }
    }

    /// Parse an address string.
    ///
    /// Tries the default space first, then all others. The string may be
    /// in the form "space_name:0xoffset" or just "0xoffset".
    pub fn get_address_from_string(&self, addr_str: &str) -> Option<Address> {
        // Try default space first
        if let Some(space) = self.spaces.get(self.default_index) {
            match space.parse_address(addr_str, true) {
                Ok(Some(addr)) => return Some(addr),
                _ => {}
            }
        }

        // Try all other spaces
        for (i, space) in self.spaces.iter().enumerate() {
            if i == self.default_index {
                continue;
            }
            match space.parse_address(addr_str, true) {
                Ok(Some(addr)) => return Some(addr),
                _ => {}
            }
        }
        None
    }

    /// Get a constant address in the constant space.
    pub fn get_constant_address(&self, offset: u64) -> Address {
        Address::new(offset)
    }

    /// Build an AddressSet spanning start..end (same space only).
    pub fn get_address_set(&self, start: Address, end: Address) -> AddressSet {
        let mut set = AddressSet::new();
        set.add_range(start, end);
        set
    }

    /// Get the index encoding for an address (space_id << 48 | offset).
    pub fn get_index(&self, addr: Address) -> u64 {
        let space = self.default_space();
        ((space.space_id() as u64) << 48) + addr.offset
    }
}

impl std::fmt::Display for DefaultAddressFactory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "DefaultAddressFactory({} spaces, default={})",
            self.spaces.len(),
            self.default_space().name()
        )
    }
}

impl AddressFactory for DefaultAddressFactory {
    fn get_address(&self, addr_string: &str) -> Option<Address> {
        self.get_address_from_string(addr_string)
    }

    fn get_all_addresses(&self, addr_string: &str, case_sensitive: bool) -> Vec<Address> {
        let mut results = Vec::new();

        // Try each space
        for space in &self.spaces {
            match space.parse_address(addr_string, case_sensitive) {
                Ok(Some(addr)) => results.push(addr),
                _ => {}
            }
        }

        // If no loaded memory addresses found, try non-loaded spaces
        // (In this simplified model, we just return what we have)
        results
    }

    fn get_default_address_space(&self) -> &GenericAddressSpace {
        self.default_space()
    }

    fn get_address_spaces(&self) -> Vec<&GenericAddressSpace> {
        self.physical_spaces()
    }

    fn get_all_address_spaces(&self) -> Vec<&GenericAddressSpace> {
        self.all_spaces().iter().collect()
    }

    fn get_address_space_by_name(&self, name: &str) -> Option<&GenericAddressSpace> {
        self.get_space_by_name(name)
    }

    fn get_address_space_by_id(&self, space_id: u32) -> Option<&GenericAddressSpace> {
        self.get_space_by_id(space_id)
    }

    fn num_address_spaces(&self) -> usize {
        self.num_address_spaces()
    }

    fn is_valid_address(&self, _addr: &Address) -> bool {
        // In this simplified model, any non-null address is valid
        !_addr.is_null()
    }

    fn get_index(&self, addr: Address) -> u64 {
        self.get_index(addr)
    }

    fn get_physical_space<'a>(&'a self, space: &'a GenericAddressSpace) -> &'a GenericAddressSpace {
        space.get_physical_space()
    }

    fn get_physical_spaces(&self) -> Vec<&GenericAddressSpace> {
        self.physical_spaces()
    }

    fn get_address_in_space(&self, space_id: u32, offset: u64) -> Option<Address> {
        self.get_address(space_id, offset)
    }

    fn get_constant_space(&self) -> Option<&GenericAddressSpace> {
        self.constant_space()
    }

    fn get_unique_space(&self) -> Option<&GenericAddressSpace> {
        self.unique_space()
    }

    fn get_stack_space(&self) -> Option<&GenericAddressSpace> {
        // Stack space is reserved and not stored in DefaultAddressFactory
        None
    }

    fn get_register_space(&self) -> Option<&GenericAddressSpace> {
        self.register_space()
    }

    fn get_constant_address(&self, offset: u64) -> Address {
        self.get_constant_address(offset)
    }

    fn get_address_set(&self, min: Address, max: Address) -> AddressSet {
        self.get_address_set(min, max)
    }

    fn get_full_address_set(&self) -> AddressSet {
        self.memory_address_set().clone()
    }

    fn old_get_address_from_long(&self, value: u64) -> Option<Address> {
        // Old encoding: space_id << 48 | offset
        let _space_id = (value >> 48) as u32;
        let offset = value & 0x0000_FFFF_FFFF_FFFF;
        Some(Address::new(offset))
    }

    fn has_multiple_memory_spaces(&self) -> bool {
        self.has_multiple_memory_spaces()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn ram_32(id: u32) -> GenericAddressSpace {
        GenericAddressSpace::new("ram", 32, 1, AddrSpaceType::Ram, id)
    }

    fn register_32() -> GenericAddressSpace {
        GenericAddressSpace::new("register", 32, 1, AddrSpaceType::Register, 5)
    }

    fn const_space() -> GenericAddressSpace {
        GenericAddressSpace::new("const", 64, 1, AddrSpaceType::Constant, 6)
    }

    fn unique_space() -> GenericAddressSpace {
        GenericAddressSpace::new("unique", 64, 1, AddrSpaceType::Unique, 7)
    }

    #[test]
    fn test_basic_factory() {
        let factory = DefaultAddressFactory::new(vec![ram_32(1)], None).unwrap();
        assert_eq!(factory.num_address_spaces(), 1);
        assert_eq!(factory.default_space().name(), "ram");
    }

    #[test]
    fn test_multiple_spaces() {
        let factory =
            DefaultAddressFactory::new(vec![ram_32(1), register_32()], Some("ram")).unwrap();
        assert_eq!(factory.num_address_spaces(), 2);
        assert!(factory.get_space_by_name("ram").is_some());
        assert!(factory.get_space_by_name("register").is_some());
        assert!(factory.get_space_by_name("nonexistent").is_none());
    }

    #[test]
    fn test_default_space() {
        let factory =
            DefaultAddressFactory::new(vec![ram_32(1), register_32()], Some("register")).unwrap();
        assert_eq!(factory.default_space().name(), "register");
    }

    #[test]
    fn test_default_space_not_found() {
        let result =
            DefaultAddressFactory::new(vec![ram_32(1)], Some("nonexistent"));
        assert!(result.is_err());
    }

    #[test]
    fn test_duplicate_space() {
        let result =
            DefaultAddressFactory::new(vec![ram_32(1), ram_32(2)], None);
        assert!(result.is_err());
    }

    #[test]
    fn test_reserved_stack_space() {
        let stack = GenericAddressSpace::new("stack", 32, 1, AddrSpaceType::Stack, 3);
        let result = DefaultAddressFactory::new(vec![stack], None);
        assert!(result.is_err());
    }

    #[test]
    fn test_reserved_external_space() {
        let ext = GenericAddressSpace::new("EXTERNAL", 32, 1, AddrSpaceType::External, 4);
        let result = DefaultAddressFactory::new(vec![ext], None);
        assert!(result.is_err());
    }

    #[test]
    fn test_lookup_by_id() {
        let ram = ram_32(42);
        let ram_id = ram.space_id();
        let factory =
            DefaultAddressFactory::new(vec![ram, register_32()], None).unwrap();
        assert!(factory.get_space_by_id(ram_id).is_some());
        assert!(factory.get_space_by_id(99).is_none());
    }

    #[test]
    fn test_constant_space() {
        let factory =
            DefaultAddressFactory::new(vec![ram_32(1), const_space()], None).unwrap();
        assert!(factory.constant_space().is_some());
        assert_eq!(factory.constant_space().unwrap().name(), "const");
    }

    #[test]
    fn test_unique_space() {
        let factory =
            DefaultAddressFactory::new(vec![ram_32(1), unique_space()], None).unwrap();
        assert!(factory.unique_space().is_some());
        assert_eq!(factory.unique_space().unwrap().name(), "unique");
    }

    #[test]
    fn test_register_space() {
        let factory =
            DefaultAddressFactory::new(vec![ram_32(1), register_32()], None).unwrap();
        assert!(factory.register_space().is_some());
        assert_eq!(factory.register_space().unwrap().name(), "register");
    }

    #[test]
    fn test_memory_address_set() {
        let factory = DefaultAddressFactory::new(vec![ram_32(1)], None).unwrap();
        let set = factory.memory_address_set();
        assert!(!set.is_empty());
    }

    #[test]
    fn test_has_multiple_memory_spaces() {
        let ram2 = GenericAddressSpace::new("ram2", 32, 1, AddrSpaceType::Ram, 2);
        let factory =
            DefaultAddressFactory::new(vec![ram_32(1), ram2], None).unwrap();
        assert!(factory.has_multiple_memory_spaces());
    }

    #[test]
    fn test_single_memory_space() {
        let factory = DefaultAddressFactory::new(vec![ram_32(1)], None).unwrap();
        assert!(!factory.has_multiple_memory_spaces());
    }

    #[test]
    fn test_get_address_from_string() {
        let factory = DefaultAddressFactory::new(vec![ram_32(1)], None).unwrap();
        let addr = factory.get_address_from_string("0x1234");
        assert!(addr.is_some());
        assert_eq!(addr.unwrap().offset, 0x1234);
    }

    #[test]
    fn test_get_address_from_string_with_space() {
        let factory = DefaultAddressFactory::new(vec![ram_32(1)], None).unwrap();
        let addr = factory.get_address_from_string("ram:0x1234");
        assert!(addr.is_some());
        assert_eq!(addr.unwrap().offset, 0x1234);
    }

    #[test]
    fn test_display() {
        let factory = DefaultAddressFactory::new(vec![ram_32(1)], None).unwrap();
        let s = format!("{}", factory);
        assert!(s.contains("1 spaces"));
        assert!(s.contains("ram"));
    }
}
