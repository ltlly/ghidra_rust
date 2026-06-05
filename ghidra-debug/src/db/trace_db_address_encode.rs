//! Address encoding for trace database field codecs.
//!
//! Ported from Ghidra's `DBTraceOverlaySpaceAdapter.AddressDBFieldCodec`
//! in `ghidra.trace.database.address`. Provides encoding/decoding of
//! `Address` values (space ID + offset) for persistent storage in the
//! trace database.

use serde::{Deserialize, Serialize};

/// Encoded address representation for database storage.
///
/// In Ghidra, addresses are encoded as 10 bytes: 2 bytes for the space ID
/// plus 8 bytes for the offset. This mirrors the `FixedField10` used in
/// Ghidra's database layer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncodedAddress {
    /// The address space ID (2 bytes).
    pub space_id: u16,
    /// The address offset (8 bytes).
    pub offset: u64,
}

impl EncodedAddress {
    /// The size of an encoded address in bytes (2 for space + 8 for offset).
    pub const ENCODED_SIZE: usize = 10;

    /// Create a new encoded address.
    pub fn new(space_id: u16, offset: u64) -> Self {
        Self { space_id, offset }
    }

    /// Encode this address into bytes (big-endian space ID + offset).
    ///
    /// Mirrors Ghidra's `AddressDBFieldCodec.encode(Address)`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(Self::ENCODED_SIZE);
        buf.extend_from_slice(&self.space_id.to_be_bytes());
        buf.extend_from_slice(&self.offset.to_be_bytes());
        buf
    }

    /// Decode an address from bytes.
    ///
    /// Mirrors Ghidra's `AddressDBFieldCodec.decode(byte[], DBTraceOverlaySpaceAdapter)`.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < Self::ENCODED_SIZE {
            return None;
        }
        let space_id = u16::from_be_bytes([data[0], data[1]]);
        let offset = u64::from_be_bytes([
            data[2], data[3], data[4], data[5], data[6], data[7], data[8], data[9],
        ]);
        Some(Self { space_id, offset })
    }

    /// Create an encoded address for a known space and offset.
    pub fn encode(space_id: u16, offset: u64) -> Vec<u8> {
        Self::new(space_id, offset).to_bytes()
    }

    /// Decode an encoded address, returning space_id and offset.
    pub fn decode(data: &[u8]) -> Option<(u16, u64)> {
        Self::from_bytes(data).map(|a| (a.space_id, a.offset))
    }
}

/// Trace address factory for managing address spaces.
///
/// Ported from Ghidra's `TraceAddressFactory` in
/// `ghidra.trace.database.address`. Extends the basic address factory
/// with overlay space support (including register-space overlays).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceAddressFactoryImpl {
    /// All registered address spaces by ID.
    spaces: Vec<AddressSpaceDescriptor>,
    /// Overlay space mappings: overlay_id -> (name, base_space_id).
    overlays: Vec<OverlayRegistration>,
    /// Next available overlay key.
    next_overlay_key: u64,
}

/// Descriptor for an address space in the trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressSpaceDescriptor {
    /// The space ID.
    pub space_id: u16,
    /// The space name.
    pub name: String,
    /// The space type (ram, register, unique, etc.).
    pub space_type: AddressSpaceType,
    /// Whether this is an overlay space.
    pub is_overlay: bool,
    /// The base space ID if this is an overlay.
    pub base_space_id: Option<u16>,
    /// Size of the addressable range.
    pub size: u64,
}

/// Types of address spaces in a trace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AddressSpaceType {
    /// General-purpose memory (RAM).
    Ram,
    /// Register space.
    Register,
    /// Unique (temporary) space.
    Unique,
    /// Constant space.
    Constant,
    /// Other/unknown.
    Other,
}

/// Registration of an overlay address space.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverlayRegistration {
    /// Database key for this overlay.
    pub key: u64,
    /// The overlay space name.
    pub name: String,
    /// The base space ID.
    pub base_space_id: u16,
}

impl TraceAddressFactoryImpl {
    /// Create a new trace address factory.
    pub fn new() -> Self {
        Self {
            spaces: Vec::new(),
            overlays: Vec::new(),
            next_overlay_key: 0x8000_0000,
        }
    }

    /// Register an address space.
    pub fn add_space(&mut self, space_id: u16, name: &str, space_type: AddressSpaceType, size: u64) {
        self.spaces.push(AddressSpaceDescriptor {
            space_id,
            name: name.to_string(),
            space_type,
            is_overlay: false,
            base_space_id: None,
            size,
        });
    }

    /// Check if a space is valid as an overlay base.
    ///
    /// In Ghidra, overlays can be based on RAM or register spaces.
    pub fn is_valid_overlay_base(&self, space_id: u16) -> bool {
        self.spaces.iter().any(|s| {
            s.space_id == space_id
                && matches!(s.space_type, AddressSpaceType::Ram | AddressSpaceType::Register)
        })
    }

    /// Create an overlay address space.
    ///
    /// Returns the new space ID, or None if the base space is invalid.
    pub fn add_overlay_space(
        &mut self,
        name: &str,
        base_space_id: u16,
    ) -> Option<u16> {
        if !self.is_valid_overlay_base(base_space_id) {
            return None;
        }
        // Check for duplicate name
        if self.spaces.iter().any(|s| s.name == name) {
            return None;
        }

        let key = self.next_overlay_key;
        self.next_overlay_key += 1;
        let overlay_id = (key & 0xFFFF) as u16;

        self.overlays.push(OverlayRegistration {
            key,
            name: name.to_string(),
            base_space_id,
        });

        self.spaces.push(AddressSpaceDescriptor {
            space_id: overlay_id,
            name: name.to_string(),
            space_type: AddressSpaceType::Ram,
            is_overlay: true,
            base_space_id: Some(base_space_id),
            size: self
                .spaces
                .iter()
                .find(|s| s.space_id == base_space_id)
                .map(|s| s.size)
                .unwrap_or(u64::MAX),
        });

        Some(overlay_id)
    }

    /// Remove an overlay space by name.
    pub fn remove_overlay_space(&mut self, name: &str) -> bool {
        let before = self.spaces.len();
        self.spaces.retain(|s| !(s.is_overlay && s.name == name));
        self.overlays.retain(|o| o.name != name);
        self.spaces.len() < before
    }

    /// Get a space by ID.
    pub fn get_space(&self, space_id: u16) -> Option<&AddressSpaceDescriptor> {
        self.spaces.iter().find(|s| s.space_id == space_id)
    }

    /// Get a space by name.
    pub fn get_space_by_name(&self, name: &str) -> Option<&AddressSpaceDescriptor> {
        self.spaces.iter().find(|s| s.name == name)
    }

    /// Get all spaces.
    pub fn all_spaces(&self) -> &[AddressSpaceDescriptor] {
        &self.spaces
    }

    /// Get all overlay spaces.
    pub fn overlay_spaces(&self) -> Vec<&AddressSpaceDescriptor> {
        self.spaces.iter().filter(|s| s.is_overlay).collect()
    }
}

impl Default for TraceAddressFactoryImpl {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encoded_address_roundtrip() {
        let addr = EncodedAddress::new(3, 0xDEADBEEF);
        let bytes = addr.to_bytes();
        assert_eq!(bytes.len(), EncodedAddress::ENCODED_SIZE);
        let decoded = EncodedAddress::from_bytes(&bytes).unwrap();
        assert_eq!(decoded, addr);
    }

    #[test]
    fn test_encoded_address_encode_decode() {
        let bytes = EncodedAddress::encode(7, 0x1000);
        let (space_id, offset) = EncodedAddress::decode(&bytes).unwrap();
        assert_eq!(space_id, 7);
        assert_eq!(offset, 0x1000);
    }

    #[test]
    fn test_encoded_address_short_data() {
        assert!(EncodedAddress::from_bytes(&[1, 2, 3]).is_none());
    }

    #[test]
    fn test_encoded_address_zero() {
        let bytes = EncodedAddress::encode(0, 0);
        assert_eq!(bytes, vec![0u8; 10]);
        let (sid, off) = EncodedAddress::decode(&bytes).unwrap();
        assert_eq!(sid, 0);
        assert_eq!(off, 0);
    }

    #[test]
    fn test_address_factory_new() {
        let factory = TraceAddressFactoryImpl::new();
        assert!(factory.all_spaces().is_empty());
        assert!(factory.overlay_spaces().is_empty());
    }

    #[test]
    fn test_address_factory_add_space() {
        let mut factory = TraceAddressFactoryImpl::new();
        factory.add_space(1, "ram", AddressSpaceType::Ram, 0x1_0000_0000);
        factory.add_space(2, "register", AddressSpaceType::Register, 0x10000);
        assert_eq!(factory.all_spaces().len(), 2);
    }

    #[test]
    fn test_address_factory_overlay() {
        let mut factory = TraceAddressFactoryImpl::new();
        factory.add_space(1, "ram", AddressSpaceType::Ram, 0x1_0000_0000);
        factory.add_space(2, "register", AddressSpaceType::Register, 0x10000);

        // RAM overlays are valid
        assert!(factory.is_valid_overlay_base(1));
        // Register overlays are also valid in Ghidra traces
        assert!(factory.is_valid_overlay_base(2));

        let overlay_id = factory.add_overlay_space("OV1", 1).unwrap();
        assert_eq!(factory.overlay_spaces().len(), 1);
        assert!(factory.get_space(overlay_id).unwrap().is_overlay);
    }

    #[test]
    fn test_address_factory_overlay_duplicate_name() {
        let mut factory = TraceAddressFactoryImpl::new();
        factory.add_space(1, "ram", AddressSpaceType::Ram, 0x1_0000_0000);
        factory.add_overlay_space("OV1", 1).unwrap();
        // Duplicate name should fail
        assert!(factory.add_overlay_space("OV1", 1).is_none());
    }

    #[test]
    fn test_address_factory_remove_overlay() {
        let mut factory = TraceAddressFactoryImpl::new();
        factory.add_space(1, "ram", AddressSpaceType::Ram, 0x1_0000_0000);
        factory.add_overlay_space("OV1", 1).unwrap();
        assert!(factory.remove_overlay_space("OV1"));
        assert!(factory.overlay_spaces().is_empty());
    }

    #[test]
    fn test_address_factory_get_by_name() {
        let mut factory = TraceAddressFactoryImpl::new();
        factory.add_space(1, "ram", AddressSpaceType::Ram, 0x1_0000_0000);
        let space = factory.get_space_by_name("ram").unwrap();
        assert_eq!(space.space_id, 1);
        assert_eq!(space.space_type, AddressSpaceType::Ram);
    }

    #[test]
    fn test_address_factory_invalid_overlay_base() {
        let mut factory = TraceAddressFactoryImpl::new();
        factory.add_space(1, "unique", AddressSpaceType::Unique, 0x10000);
        assert!(!factory.is_valid_overlay_base(1));
        assert!(factory.add_overlay_space("OV1", 1).is_none());
    }
}
