//! Address factory types for traces ported from Framework-TraceModeling.
//!
//! Provides types for creating and managing address spaces in traces,
//! including space descriptors and factory methods.

use serde::{Deserialize, Serialize};

/// Types of address spaces in a trace model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ModelAddressSpaceType {
    /// General memory (RAM).
    Ram,
    /// Register space.
    Register,
    /// P-code unique space.
    Unique,
    /// Overlay space (mapped on top of another space).
    Overlay,
    /// Constant space.
    Constant,
    /// Stack space.
    Stack,
    /// Other/unknown.
    Other,
}

/// Description of an address space in a trace model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelAddressSpaceDesc {
    /// Space name (e.g., "ram", "register", "CODE").
    pub name: String,
    /// Space type (e.g., "ram", "register", "unique", "overlay").
    pub space_type: ModelAddressSpaceType,
    /// Size of the addressable space in bytes (address size).
    pub address_size: u32,
    /// Whether the space is big-endian.
    pub big_endian: bool,
    /// Unique ID for this space.
    pub space_id: u32,
    /// Physical size for overlay spaces.
    pub physical_size: Option<u64>,
}

impl ModelAddressSpaceDesc {
    /// Create a new RAM address space.
    pub fn ram(name: impl Into<String>, address_size: u32, big_endian: bool) -> Self {
        Self {
            name: name.into(),
            space_type: ModelAddressSpaceType::Ram,
            address_size,
            big_endian,
            space_id: 0,
            physical_size: None,
        }
    }

    /// Create a new register address space.
    pub fn register(name: impl Into<String>, address_size: u32) -> Self {
        Self {
            name: name.into(),
            space_type: ModelAddressSpaceType::Register,
            address_size,
            big_endian: false,
            space_id: 0,
            physical_size: None,
        }
    }

    /// Create a new unique address space.
    pub fn unique(name: impl Into<String>, address_size: u32) -> Self {
        Self {
            name: name.into(),
            space_type: ModelAddressSpaceType::Unique,
            address_size,
            big_endian: false,
            space_id: 0,
            physical_size: None,
        }
    }

    /// Create a new overlay address space.
    pub fn overlay(
        name: impl Into<String>,
        address_size: u32,
        big_endian: bool,
        physical_size: u64,
    ) -> Self {
        Self {
            name: name.into(),
            space_type: ModelAddressSpaceType::Overlay,
            address_size,
            big_endian,
            space_id: 0,
            physical_size: Some(physical_size),
        }
    }

    /// Whether this space is a memory space (RAM or overlay).
    pub fn is_memory_space(&self) -> bool {
        matches!(self.space_type, ModelAddressSpaceType::Ram | ModelAddressSpaceType::Overlay)
    }

    /// Whether this space is a register space.
    pub fn is_register_space(&self) -> bool {
        self.space_type == ModelAddressSpaceType::Register
    }

    /// Whether this space is an overlay.
    pub fn is_overlay(&self) -> bool {
        self.space_type == ModelAddressSpaceType::Overlay
    }

    /// Get the maximum address value for this space.
    pub fn max_address(&self) -> u64 {
        match self.address_size {
            1 => 0xFF,
            2 => 0xFFFF,
            4 => 0xFFFF_FFFF,
            8 => u64::MAX,
            _ => (1u64 << (self.address_size as u64 * 8)) - 1,
        }
    }
}

/// Factory for creating trace address spaces from language definitions.
///
/// Ported from Ghidra's `ModelTraceAddressFactory`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelTraceAddressFactory {
    /// Registered address spaces.
    spaces: Vec<ModelAddressSpaceDesc>,
    /// Counter for assigning space IDs.
    next_space_id: u32,
}

impl ModelTraceAddressFactory {
    /// Create a new empty address factory.
    pub fn new() -> Self {
        Self {
            spaces: Vec::new(),
            next_space_id: 0,
        }
    }

    /// Create a factory with standard x86-64 spaces.
    pub fn x86_64() -> Self {
        let mut factory = Self::new();
        factory.add_space(ModelAddressSpaceDesc::ram("ram", 8, false));
        factory.add_space(ModelAddressSpaceDesc::register("register", 8));
        factory.add_space(ModelAddressSpaceDesc::unique("unique", 8));
        factory
    }

    /// Create a factory with standard ARM64 spaces.
    pub fn aarch64() -> Self {
        let mut factory = Self::new();
        factory.add_space(ModelAddressSpaceDesc::ram("ram", 8, false));
        factory.add_space(ModelAddressSpaceDesc::register("register", 8));
        factory.add_space(ModelAddressSpaceDesc::unique("unique", 8));
        factory
    }

    /// Register an address space and assign it a unique ID.
    pub fn add_space(&mut self, mut space: ModelAddressSpaceDesc) -> u32 {
        let id = self.next_space_id;
        space.space_id = id;
        self.next_space_id += 1;
        self.spaces.push(space);
        id
    }

    /// Find a space by name.
    pub fn get_space(&self, name: &str) -> Option<&ModelAddressSpaceDesc> {
        self.spaces.iter().find(|s| s.name == name)
    }

    /// Find a space by ID.
    pub fn get_space_by_id(&self, id: u32) -> Option<&ModelAddressSpaceDesc> {
        self.spaces.iter().find(|s| s.space_id == id)
    }

    /// Get all space names.
    pub fn space_names(&self) -> Vec<&str> {
        self.spaces.iter().map(|s| s.name.as_str()).collect()
    }

    /// Get the default (first RAM) space, if any.
    pub fn default_space(&self) -> Option<&ModelAddressSpaceDesc> {
        self.spaces.iter().find(|s| s.space_type == ModelAddressSpaceType::Ram)
    }

    /// Get the register space, if any.
    pub fn register_space(&self) -> Option<&ModelAddressSpaceDesc> {
        self.spaces
            .iter()
            .find(|s| s.space_type == ModelAddressSpaceType::Register)
    }

    /// Get the number of registered spaces.
    pub fn len(&self) -> usize {
        self.spaces.len()
    }

    /// Check if no spaces are registered.
    pub fn is_empty(&self) -> bool {
        self.spaces.is_empty()
    }

    /// Get all spaces.
    pub fn spaces(&self) -> &[ModelAddressSpaceDesc] {
        &self.spaces
    }

    /// Check if a space exists.
    pub fn has_space(&self, name: &str) -> bool {
        self.spaces.iter().any(|s| s.name == name)
    }
}

impl Default for ModelTraceAddressFactory {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_space_desc_ram() {
        let desc = ModelAddressSpaceDesc::ram("ram", 8, false);
        assert_eq!(desc.name, "ram");
        assert_eq!(desc.space_type, ModelAddressSpaceType::Ram);
        assert_eq!(desc.address_size, 8);
        assert!(!desc.big_endian);
        assert!(desc.is_memory_space());
        assert!(!desc.is_register_space());
        assert!(!desc.is_overlay());
    }

    #[test]
    fn test_address_space_desc_register() {
        let desc = ModelAddressSpaceDesc::register("register", 4);
        assert!(desc.is_register_space());
        assert!(!desc.is_memory_space());
    }

    #[test]
    fn test_address_space_desc_overlay() {
        let desc = ModelAddressSpaceDesc::overlay("CODE", 8, false, 0x10000);
        assert!(desc.is_overlay());
        assert!(desc.is_memory_space());
        assert_eq!(desc.physical_size, Some(0x10000));
    }

    #[test]
    fn test_max_address() {
        let desc1 = ModelAddressSpaceDesc::ram("ram1", 1, false);
        assert_eq!(desc1.max_address(), 0xFF);
        let desc2 = ModelAddressSpaceDesc::ram("ram2", 2, false);
        assert_eq!(desc2.max_address(), 0xFFFF);
        let desc4 = ModelAddressSpaceDesc::ram("ram4", 4, false);
        assert_eq!(desc4.max_address(), 0xFFFF_FFFF);
        let desc8 = ModelAddressSpaceDesc::ram("ram8", 8, false);
        assert_eq!(desc8.max_address(), u64::MAX);
    }

    #[test]
    fn test_address_factory() {
        let mut factory = ModelTraceAddressFactory::new();
        assert!(factory.is_empty());

        let id1 = factory.add_space(ModelAddressSpaceDesc::ram("ram", 8, false));
        let id2 = factory.add_space(ModelAddressSpaceDesc::register("register", 8));
        let id3 = factory.add_space(ModelAddressSpaceDesc::unique("unique", 8));

        assert_eq!(factory.len(), 3);
        assert_ne!(id1, id2);
        assert_ne!(id2, id3);

        assert!(factory.has_space("ram"));
        assert!(factory.has_space("register"));
        assert!(!factory.has_space("nonexistent"));

        assert!(factory.default_space().is_some());
        assert!(factory.register_space().is_some());
    }

    #[test]
    fn test_factory_x86_64() {
        let factory = ModelTraceAddressFactory::x86_64();
        assert_eq!(factory.len(), 3);
        assert!(factory.has_space("ram"));
        assert!(factory.has_space("register"));
        assert!(factory.has_space("unique"));
        assert_eq!(factory.default_space().unwrap().address_size, 8);
    }

    #[test]
    fn test_factory_aarch64() {
        let factory = ModelTraceAddressFactory::aarch64();
        assert_eq!(factory.len(), 3);
        assert!(factory.has_space("ram"));
    }

    #[test]
    fn test_space_type_variants() {
        assert_ne!(ModelAddressSpaceType::Ram, ModelAddressSpaceType::Register);
        assert_ne!(ModelAddressSpaceType::Overlay, ModelAddressSpaceType::Unique);
        assert_ne!(ModelAddressSpaceType::Constant, ModelAddressSpaceType::Stack);
    }
}
