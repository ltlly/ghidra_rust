//! Database-backed memory block source information.
//!
//! Mirrors `ghidra.program.database.mem.MemoryBlockSourceInfoDB`. Provides
//! source information about a sub-block segment within a MemoryBlockDB.

use crate::addr::{Address, AddressRange};
use crate::mem::db::memory_block_db::MemoryBlockDB;
use crate::mem::db::sub_memory_block::{SubMemoryBlock, SubMemoryBlockType};
use crate::mem::ByteMappingScheme;

// ============================================================================
// MemoryBlockSourceInfoDB
// ============================================================================

/// Describes the source of bytes for a portion of a database-backed memory block.
///
/// Mirrors `ghidra.program.database.mem.MemoryBlockSourceInfoDB`. Each
/// `MemoryBlockSourceInfoDB` is associated with a specific [`SubMemoryBlock`]
/// within a [`MemoryBlockDB`] and exposes its address range, backing data
/// source, and mapping information.
#[derive(Debug)]
pub struct MemoryBlockSourceInfoDB {
    /// The owning block's name.
    block_name: String,
    /// The owning block's start address.
    block_start: Address,
    /// The owning block's ID.
    block_id: u64,
    /// Sub-block starting offset within the parent block.
    sub_offset: u64,
    /// Sub-block length in bytes.
    sub_length: u64,
    /// Whether the sub-block is initialized.
    initialized: bool,
    /// Sub-block type.
    sub_type: SubMemoryBlockType,
    /// Description string.
    description: String,
    /// Optional file bytes ID.
    file_bytes_id: Option<u64>,
    /// File bytes offset (or -1 if not applicable).
    file_bytes_offset: i64,
    /// Optional mapped address range (for bit/byte-mapped blocks).
    mapped_range: Option<AddressRange>,
    /// Optional byte mapping scheme (for byte-mapped blocks).
    byte_mapping_scheme: Option<ByteMappingScheme>,
}

impl MemoryBlockSourceInfoDB {
    /// Create a source info from a sub-block and its owning block.
    pub fn from_sub_block(
        block: &MemoryBlockDB,
        sub: &dyn SubMemoryBlock,
    ) -> Self {
        let sub_offset = sub.starting_offset();
        let sub_length = sub.length();
        let min_addr = block.start().add(sub_offset);
        let max_addr = min_addr.add(sub_length.saturating_sub(1));
        let sub_type = sub.sub_block_type();

        // Determine file bytes info
        let (file_bytes_id, file_bytes_offset) = match sub_type {
            SubMemoryBlockType::FileBytes => {
                // In the real implementation, this would come from the sub-block.
                // Here we use placeholder values.
                (None, -1i64)
            }
            _ => (None, -1i64),
        };

        // Determine mapping info
        let (mapped_range, byte_mapping_scheme) = match sub_type {
            SubMemoryBlockType::BitMapped => {
                let mapped_base = block.mapped_source_base();
                if let Some(base) = mapped_base {
                    let mapped_min = base.add(sub_offset);
                    let mapped_max = mapped_min.add(sub_length.saturating_sub(1));
                    (Some(AddressRange::new(mapped_min, mapped_max)), None)
                } else {
                    (None, None)
                }
            }
            SubMemoryBlockType::ByteMapped => {
                let mapped_base = block.mapped_source_base();
                let scheme = block.byte_mapping_scheme().cloned();
                if let (Some(base), Some(scheme)) = (mapped_base, &scheme) {
                    let mapped_min = base.add(sub_offset);
                    let mapped_max = mapped_min.add(sub_length.saturating_sub(1));
                    (
                        Some(AddressRange::new(mapped_min, mapped_max)),
                        Some(scheme.clone()),
                    )
                } else {
                    (None, None)
                }
            }
            _ => (None, None),
        };

        Self {
            block_name: block.name().to_string(),
            block_start: block.start(),
            block_id: block.id(),
            sub_offset,
            sub_length,
            initialized: sub.is_initialized(),
            sub_type,
            description: sub.description(),
            file_bytes_id,
            file_bytes_offset,
            mapped_range,
            byte_mapping_scheme,
        }
    }

    /// Create a simple source info for an initialized sub-block.
    pub fn new_initialized(
        length: u64,
        min_address: Address,
        file_bytes_id: Option<u64>,
        file_bytes_offset: i64,
    ) -> Self {
        let max_address = min_address.add(length.saturating_sub(1));
        Self {
            block_name: String::new(),
            block_start: Address::NULL,
            block_id: 0,
            sub_offset: min_address.offset,
            sub_length: length,
            initialized: true,
            sub_type: SubMemoryBlockType::Buffer,
            description: format!("init[0x{:x}]", length),
            file_bytes_id,
            file_bytes_offset,
            mapped_range: None,
            byte_mapping_scheme: None,
        }
    }

    /// Create a source info for a byte-mapped sub-block.
    pub fn new_byte_mapped(
        length: u64,
        min_address: Address,
        mapped_range: AddressRange,
        scheme: ByteMappingScheme,
    ) -> Self {
        let max_address = min_address.add(length.saturating_sub(1));
        Self {
            block_name: String::new(),
            block_start: Address::NULL,
            block_id: 0,
            sub_offset: min_address.offset,
            sub_length: length,
            initialized: false,
            sub_type: SubMemoryBlockType::ByteMapped,
            description: format!("Mapped: {}", scheme),
            file_bytes_id: None,
            file_bytes_offset: -1,
            mapped_range: Some(mapped_range),
            byte_mapping_scheme: Some(scheme),
        }
    }

    /// Create a source info for a bit-mapped sub-block.
    pub fn new_bit_mapped(
        length: u64,
        min_address: Address,
        mapped_range: AddressRange,
    ) -> Self {
        let max_address = min_address.add(length.saturating_sub(1));
        Self {
            block_name: String::new(),
            block_start: Address::NULL,
            block_id: 0,
            sub_offset: min_address.offset,
            sub_length: length,
            initialized: false,
            sub_type: SubMemoryBlockType::BitMapped,
            description: "Bit Mapped".to_string(),
            file_bytes_id: None,
            file_bytes_offset: -1,
            mapped_range: Some(mapped_range),
            byte_mapping_scheme: None,
        }
    }

    // ---- Accessors ----

    /// Returns the mapped length in bytes.
    pub fn get_length(&self) -> u64 {
        self.sub_length
    }

    /// Returns the minimum mapped address for this source.
    pub fn get_min_address(&self) -> Address {
        self.block_start.add(self.sub_offset)
    }

    /// Returns the maximum mapped address for this source.
    pub fn get_max_address(&self) -> Address {
        self.get_min_address()
            .add(self.sub_length.saturating_sub(1))
    }

    /// Returns the description string.
    pub fn get_description(&self) -> &str {
        &self.description
    }

    /// Returns the file bytes identifier, if present.
    pub fn get_file_bytes_id(&self) -> Option<u64> {
        self.file_bytes_id
    }

    /// Returns the starting offset into file bytes, if applicable.
    pub fn get_file_bytes_offset(&self) -> Option<u64> {
        (self.file_bytes_offset >= 0).then_some(self.file_bytes_offset as u64)
    }

    /// Returns the file bytes offset for the given address within this source.
    pub fn get_file_bytes_offset_for_address(&self, address: &Address) -> Option<u64> {
        if self.file_bytes_offset < 0 || !self.contains(address) {
            return None;
        }
        let sub_offset = address.offset - self.get_min_address().offset;
        Some(self.file_bytes_offset as u64 + sub_offset)
    }

    /// Returns the mapped source address range, if this source is mapped.
    pub fn get_mapped_range(&self) -> Option<AddressRange> {
        self.mapped_range
    }

    /// Returns the byte mapping scheme, if this source is byte-mapped.
    pub fn get_byte_mapping_scheme(&self) -> Option<&ByteMappingScheme> {
        self.byte_mapping_scheme.as_ref()
    }

    /// Returns true if this source is byte-mapped.
    pub fn is_byte_mapped(&self) -> bool {
        matches!(self.sub_type, SubMemoryBlockType::ByteMapped)
    }

    /// Returns true if this source is bit-mapped.
    pub fn is_bit_mapped(&self) -> bool {
        matches!(self.sub_type, SubMemoryBlockType::BitMapped)
    }

    /// Returns true if this source is any mapped source.
    pub fn is_mapped(&self) -> bool {
        self.mapped_range.is_some()
    }

    /// Returns true if this source has file bytes backing.
    pub fn has_file_bytes(&self) -> bool {
        self.file_bytes_id.is_some() && self.file_bytes_offset >= 0
    }

    /// Returns true if the source describes a single contiguous file-backed range.
    pub fn is_file_bytes_range(&self) -> bool {
        self.has_file_bytes() && !self.is_mapped()
    }

    /// Returns the address range covered by this source.
    pub fn get_address_range(&self) -> AddressRange {
        AddressRange::new(self.get_min_address(), self.get_max_address())
    }

    /// Check if the given address is within this source.
    pub fn contains(&self, address: &Address) -> bool {
        let min = self.get_min_address();
        let max = self.get_max_address();
        address.offset >= min.offset && address.offset <= max.offset
    }

    /// Check if this source contains the specified file offset.
    pub fn contains_file_offset(&self, file_offset: u64) -> bool {
        if self.file_bytes_offset < 0 {
            return false;
        }
        let start = self.file_bytes_offset as u64;
        let end = start + self.sub_length.saturating_sub(1);
        file_offset >= start && file_offset <= end
    }

    /// Get the address within this source that corresponds to the given file offset.
    pub fn locate_address_for_file_offset(&self, file_offset: u64) -> Option<Address> {
        if !self.contains_file_offset(file_offset) {
            return None;
        }
        let start = self.file_bytes_offset as u64;
        let offset = file_offset.checked_sub(start)?;
        if offset >= self.sub_length {
            return None;
        }
        Some(self.get_min_address().add(offset))
    }
}

impl std::fmt::Display for MemoryBlockSourceInfoDB {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "MemoryBlockSourceInfoDB: StartAddress = {}, length = {}",
            self.get_min_address(),
            self.get_length()
        )
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_source_info_initialized() {
        let info = MemoryBlockSourceInfoDB::new_initialized(
            256,
            Address::new(0x1000),
            Some(42),
            128,
        );
        assert_eq!(info.get_length(), 256);
        assert_eq!(info.get_min_address(), Address::new(0x1000));
        assert_eq!(info.get_max_address(), Address::new(0x10FF));
        assert!(info.contains(&Address::new(0x1080)));
        assert!(!info.contains(&Address::new(0x0FFF)));
        assert!(!info.contains(&Address::new(0x1100)));
    }

    #[test]
    fn test_source_info_file_bytes() {
        let info = MemoryBlockSourceInfoDB::new_initialized(
            100,
            Address::new(0x1000),
            Some(42),
            128,
        );
        assert!(info.has_file_bytes());
        assert!(info.is_file_bytes_range());
        assert!(!info.is_mapped());
        assert_eq!(info.get_file_bytes_id(), Some(42));
        assert_eq!(info.get_file_bytes_offset(), Some(128));
    }

    #[test]
    fn test_source_info_no_file_bytes() {
        let info = MemoryBlockSourceInfoDB::new_initialized(
            100,
            Address::new(0x1000),
            None,
            -1,
        );
        assert!(!info.has_file_bytes());
        assert!(!info.is_file_bytes_range());
    }

    #[test]
    fn test_source_info_contains_file_offset() {
        let info = MemoryBlockSourceInfoDB::new_initialized(
            100,
            Address::new(0x1000),
            Some(42),
            128,
        );
        assert!(info.contains_file_offset(128));
        assert!(info.contains_file_offset(227));
        assert!(!info.contains_file_offset(127));
        assert!(!info.contains_file_offset(228));
    }

    #[test]
    fn test_source_info_locate_address() {
        let info = MemoryBlockSourceInfoDB::new_initialized(
            100,
            Address::new(0x1000),
            Some(42),
            128,
        );
        assert_eq!(
            info.locate_address_for_file_offset(128),
            Some(Address::new(0x1000))
        );
        assert_eq!(
            info.locate_address_for_file_offset(140),
            Some(Address::new(0x100C))
        );
        assert_eq!(info.locate_address_for_file_offset(100), None);
    }

    #[test]
    fn test_source_info_byte_mapped() {
        let scheme = ByteMappingScheme::new(2, 4);
        let mapped_range = AddressRange::new(Address::new(0x2000), Address::new(0x20FF));
        let info = MemoryBlockSourceInfoDB::new_byte_mapped(
            256,
            Address::new(0x1000),
            mapped_range,
            scheme,
        );
        assert!(info.is_byte_mapped());
        assert!(info.is_mapped());
        assert!(!info.is_bit_mapped());
        assert!(info.get_byte_mapping_scheme().is_some());
        assert_eq!(info.get_mapped_range(), Some(mapped_range));
    }

    #[test]
    fn test_source_info_bit_mapped() {
        let mapped_range = AddressRange::new(Address::new(0x3000), Address::new(0x30FF));
        let info = MemoryBlockSourceInfoDB::new_bit_mapped(
            256,
            Address::new(0x1000),
            mapped_range,
        );
        assert!(info.is_bit_mapped());
        assert!(info.is_mapped());
        assert!(!info.is_byte_mapped());
        assert!(info.get_byte_mapping_scheme().is_none());
    }

    #[test]
    fn test_source_info_display() {
        let info = MemoryBlockSourceInfoDB::new_initialized(
            100,
            Address::new(0x1000),
            None,
            -1,
        );
        let s = format!("{}", info);
        assert!(s.contains("0x1000"));
        assert!(s.contains("100"));
    }

    #[test]
    fn test_source_info_address_range() {
        let info = MemoryBlockSourceInfoDB::new_initialized(
            128,
            Address::new(0x2000),
            None,
            -1,
        );
        let range = info.get_address_range();
        assert_eq!(range.start, Address::new(0x2000));
        assert_eq!(range.end, Address::new(0x207F));
    }

    #[test]
    fn test_source_info_get_file_bytes_offset_for_address() {
        let info = MemoryBlockSourceInfoDB::new_initialized(
            100,
            Address::new(0x1000),
            Some(42),
            1000,
        );
        assert_eq!(
            info.get_file_bytes_offset_for_address(&Address::new(0x1000)),
            Some(1000)
        );
        assert_eq!(
            info.get_file_bytes_offset_for_address(&Address::new(0x1010)),
            Some(1016)
        );
        // Out of range
        assert_eq!(
            info.get_file_bytes_offset_for_address(&Address::new(0x2000)),
            None
        );
    }
}
