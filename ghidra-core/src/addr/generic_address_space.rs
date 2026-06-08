//! Generic address space implementation.
//!
//! Direct translation of `ghidra.program.model.address.GenericAddressSpace`
//! and `ghidra.program.model.address.AbstractAddressSpace`.
//!
//! Provides [`GenericAddressSpace`] -- a concrete address space that handles
//! offset truncation, parsing, and arithmetic for most Ghidra address space
//! types (RAM, register, constant, unique, stack, external, etc.).

use crate::addr::{Address, AddrSpaceType};
use crate::addr::address_error::{AddressFormatException, AddressOutOfBoundsException, AddressOverflowException};

// ---------------------------------------------------------------------------
// Space ID encoding (mirrors Ghidra's ID_SIZE_SHIFT / ID_UNIQUE_SHIFT)
// ---------------------------------------------------------------------------

/// Bit shift for encoding size component in space ID.
const ID_SIZE_SHIFT: u32 = 4;
/// Bit mask for size component in space ID.
const ID_SIZE_MASK: u32 = 0x0070;
/// Bit mask for type component in space ID.
const ID_TYPE_MASK: u32 = 0x000F;
/// Bit shift for unique component in space ID.
const ID_UNIQUE_SHIFT: u32 = 7;

/// Compute the size log value used for space ID encoding.
fn size_to_log(size: u32) -> u32 {
    match size {
        8 => 0,
        16 => 1,
        32 => 2,
        64 => 3,
        _ => 7,
    }
}

/// Compute the number of bits consumed by the unit size encoding.
fn bits_consumed_by_unit_size(unit_size: u32) -> u32 {
    if unit_size < 1 || unit_size > 8 {
        panic!("Unsupported unit size: {}", unit_size);
    }
    let mut cnt = 0u32;
    let mut test = unit_size - 1;
    while test != 0 {
        test >>= 1;
        cnt += 1;
    }
    cnt
}

// ---------------------------------------------------------------------------
// GenericAddressSpace
// ---------------------------------------------------------------------------

/// A concrete implementation of an address space for standard (non-segmented)
/// memory layouts.
///
/// Corresponds to `ghidra.program.model.address.GenericAddressSpace` (which
/// extends `AbstractAddressSpace`).
///
/// This handles:
/// - Space ID encoding (unique + size + type)
/// - Offset truncation and wrapping
/// - Signed vs unsigned offset arithmetic
/// - Address string parsing ("space:0xoffset" or plain hex)
/// - Min/max address computation
///
/// # Examples
///
/// ```
/// use ghidra_core::addr::AddrSpaceType;
/// use ghidra_core::addr::generic_address_space::GenericAddressSpace;
///
/// let space = GenericAddressSpace::new("ram", 32, 1, AddrSpaceType::Ram, 1);
/// assert_eq!(space.name(), "ram");
/// assert_eq!(space.size(), 32);
/// assert_eq!(space.max_offset(), 0xFFFF_FFFF);
/// ```
#[derive(Debug, Clone)]
pub struct GenericAddressSpace {
    /// The space name.
    name: String,
    /// Number of address bits (e.g. 32, 64).
    size: u32,
    /// Number of data bytes per addressable location (word size).
    unit_size: u32,
    /// The address space type.
    space_type: AddrSpaceType,
    /// Encoded space ID.
    space_id: u32,
    /// Whether this is an overlay space.
    is_overlay: bool,
    /// Whether to show the space name in display.
    show_space_name: bool,
    /// Whether this space uses signed offsets.
    signed: bool,
    /// Minimum valid offset.
    min_offset: i64,
    /// Maximum valid offset.
    max_offset: u64,
    /// Total space size in bytes (0 means full 64-bit).
    space_size: u64,
    /// Mask for addressable word offset truncation.
    word_address_mask: u64,
    /// Minimum address in this space.
    min_address: Address,
    /// Maximum address in this space.
    max_address: Address,
    /// Whether this space has memory-mapped registers.
    has_mapped_registers: bool,
}

impl GenericAddressSpace {
    /// Create a new generic address space.
    ///
    /// # Arguments
    /// * `name` - the space name
    /// * `size` - number of address bits (e.g., 32 or 64)
    /// * `unit_size` - bytes per addressable word (typically 1)
    /// * `space_type` - the type of space
    /// * `unique` - unique id for this space (used in space ID encoding)
    pub fn new(
        name: impl Into<String>,
        size: u32,
        unit_size: u32,
        space_type: AddrSpaceType,
        unique: u32,
    ) -> Self {
        let name_str = name.into();

        // Validate
        assert!(
            unique <= i16::MAX as u32,
            "Unique space id must be between 0 and {} inclusive",
            i16::MAX
        );
        assert!(
            bits_consumed_by_unit_size(unit_size) + size <= 64,
            "Unsupported address space size (2^size * wordsize > 2^64)"
        );

        let signed = matches!(space_type, AddrSpaceType::Constant | AddrSpaceType::Stack);

        let (space_size, word_address_mask, min_offset, max_offset, min_address, max_address) =
            if size == 64 {
                let max_off = u64::MAX;
                let min_off: i64 = if signed { i64::MIN } else { 0 };
                (
                    0u64, // space_size=0 signals full 64-bit
                    u64::MAX,
                    min_off,
                    max_off,
                    Address::new(min_off as u64),
                    Address::new(max_off),
                )
            } else {
                let ss = (unit_size as u64) << size;
                let wam = (1u64 << size) - 1;
                if signed {
                    let max_o = (ss - 1) >> 1;
                    let min_o = -(max_o as i64) - 1;
                    (
                        ss,
                        wam,
                        min_o,
                        max_o,
                        Address::new(min_o as u64),
                        Address::new(max_o),
                    )
                } else {
                    let max_o = ss - 1;
                    (ss, wam, 0i64, max_o, Address::new(0), Address::new(max_o))
                }
            };

        let logsize = size_to_log(size);
        let space_id = (unique << ID_UNIQUE_SHIFT) | (logsize << ID_SIZE_SHIFT) | (space_type as u32 & ID_TYPE_MASK);

        let show_space_name = space_type != AddrSpaceType::Ram;

        Self {
            name: name_str,
            size,
            unit_size,
            space_type,
            space_id,
            is_overlay: false,
            show_space_name,
            signed,
            min_offset,
            max_offset,
            space_size,
            word_address_mask,
            min_address,
            max_address,
            has_mapped_registers: false,
        }
    }

    // -- Accessors --

    /// Returns the space name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the number of address bits.
    pub fn size(&self) -> u32 {
        self.size
    }

    /// Returns the addressable unit size in bytes.
    pub fn addressable_unit_size(&self) -> u32 {
        self.unit_size
    }

    /// Returns the pointer size in bytes.
    pub fn pointer_size(&self) -> u32 {
        let mut ptr_size = self.size / 8;
        if self.size % 8 != 0 {
            ptr_size += 1;
        }
        ptr_size
    }

    /// Returns the space type.
    pub fn space_type(&self) -> AddrSpaceType {
        self.space_type
    }

    /// Returns the encoded space ID.
    pub fn space_id(&self) -> u32 {
        self.space_id
    }

    /// Returns the unique id component of the space ID.
    pub fn unique(&self) -> u32 {
        self.space_id >> ID_UNIQUE_SHIFT
    }

    /// Returns true if this space uses signed offsets.
    pub fn has_signed_offset(&self) -> bool {
        self.signed
    }

    /// Returns true if this is an overlay space.
    pub fn is_overlay(&self) -> bool {
        self.is_overlay
    }

    /// Sets whether this is an overlay space.
    pub fn set_overlay(&mut self, overlay: bool) {
        self.is_overlay = overlay;
    }

    /// Returns whether to show the space name in display.
    pub fn show_space_name(&self) -> bool {
        self.show_space_name
    }

    /// Sets whether to show the space name.
    pub fn set_show_space_name(&mut self, show: bool) {
        self.show_space_name = show;
    }

    /// Returns whether this space has memory-mapped registers.
    pub fn has_mapped_registers(&self) -> bool {
        self.has_mapped_registers
    }

    /// Sets whether this space has memory-mapped registers.
    pub fn set_has_mapped_registers(&mut self, has: bool) {
        self.has_mapped_registers = has;
    }

    /// Returns the minimum address in this space.
    pub fn min_address(&self) -> Address {
        self.min_address
    }

    /// Returns the maximum address in this space.
    pub fn max_address(&self) -> Address {
        self.max_address
    }

    /// Returns the minimum valid offset.
    pub fn min_offset(&self) -> i64 {
        self.min_offset
    }

    /// Returns the maximum valid offset.
    pub fn max_offset(&self) -> u64 {
        self.max_offset
    }

    /// Returns the total space size (0 for 64-bit spaces).
    pub fn space_size(&self) -> u64 {
        self.space_size
    }

    // -- Type query methods --

    /// True if this space represents real memory.
    pub fn is_memory_space(&self) -> bool {
        matches!(
            self.space_type,
            AddrSpaceType::Ram | AddrSpaceType::Other
        )
    }

    /// True if this is a loaded memory space.
    pub fn is_loaded_memory_space(&self) -> bool {
        self.space_type == AddrSpaceType::Ram
    }

    /// True if this is a non-loaded memory space.
    pub fn is_non_loaded_memory_space(&self) -> bool {
        self.space_type == AddrSpaceType::Other
    }

    /// True if this is a register space.
    pub fn is_register_space(&self) -> bool {
        self.space_type == AddrSpaceType::Register
    }

    /// True if this is a stack space.
    pub fn is_stack_space(&self) -> bool {
        self.space_type == AddrSpaceType::Stack
    }

    /// True if this is a unique space.
    pub fn is_unique_space(&self) -> bool {
        self.space_type == AddrSpaceType::Unique
    }

    /// True if this is a constant space.
    pub fn is_constant_space(&self) -> bool {
        self.space_type == AddrSpaceType::Constant
    }

    /// True if this is a variable space.
    pub fn is_variable_space(&self) -> bool {
        self.space_type == AddrSpaceType::Variable
    }

    /// True if this is an external space.
    pub fn is_external_space(&self) -> bool {
        self.space_type == AddrSpaceType::External
    }

    // -- Address creation --

    /// Create an address in this space from a byte offset.
    ///
    /// Returns `Err` if the offset is out of bounds.
    pub fn get_address(&self, byte_offset: u64) -> Result<Address, AddressOutOfBoundsException> {
        self.make_valid_offset(byte_offset as i64)
            .map(Address::new)
            .map_err(|_| AddressOutOfBoundsException::for_offset(&self.name, byte_offset))
    }

    /// Create an address in this space, allowing word-offset input.
    pub fn get_address_word(
        &self,
        offset: u64,
        is_word_offset: bool,
    ) -> Result<Address, AddressOutOfBoundsException> {
        let byte_offset = if is_word_offset {
            offset * self.unit_size as u64
        } else {
            offset
        };
        self.get_address(byte_offset)
    }

    /// Create an address without bounds checking.
    pub fn get_unchecked_address(&self, offset: u64) -> Address {
        Address::new(offset)
    }

    /// Create a truncated address (never fails).
    pub fn get_truncated_address(
        &self,
        offset: u64,
        is_word_offset: bool,
    ) -> Address {
        let truncated = if is_word_offset {
            self.truncate_addressable_word_offset(offset)
        } else {
            self.truncate_offset(offset as i64) as u64
        };
        Address::new(truncated)
    }

    // -- Offset truncation and validation --

    /// Truncate an offset to fit within this space.
    ///
    /// For unsigned spaces, applies modular arithmetic. For signed spaces,
    /// handles sign extension.
    pub fn truncate_offset(&self, offset: i64) -> i64 {
        if self.space_size == 0 {
            return offset;
        }
        if offset >= self.min_offset && (offset as u64) <= self.max_offset {
            return offset;
        }
        if self.signed {
            let mut off = ((offset + self.max_offset as i64 + 1) % self.space_size as i64)
                as i64;
            if off < 0 {
                off += self.space_size as i64;
            }
            off - self.max_offset as i64 - 1
        } else {
            let mut off = (offset as u64 % self.space_size) as i64;
            if off < 0 {
                off += self.space_size as i64;
            }
            off
        }
    }

    /// Truncate an addressable word offset.
    pub fn truncate_addressable_word_offset(&self, word_offset: u64) -> u64 {
        word_offset & self.word_address_mask
    }

    /// Validate and return a valid offset, applying sign extension if needed.
    pub fn make_valid_offset(&self, offset: i64) -> Result<u64, AddressOutOfBoundsException> {
        if self.size == 64 || self.space_size == 0 {
            return Ok(offset as u64);
        }
        if offset >= self.min_offset && (offset as u64) <= self.max_offset {
            return Ok(offset as u64);
        }
        if self.signed {
            if (offset as u64) > self.max_offset && (offset as u64) < self.space_size {
                return Ok((offset - self.space_size as i64) as u64);
            }
        } else {
            if offset < 0 && offset >= -(self.max_offset as i64) - 1 {
                return Ok((offset + self.space_size as i64) as u64);
            }
        }
        Err(AddressOutOfBoundsException::new(format!(
            "Offset must be between 0x{:x} and 0x{:x}, got 0x{:x}",
            self.min_offset as u64,
            self.max_offset,
            offset as u64
        )))
    }

    // -- Addressable word offset --

    /// Convert a byte offset to an addressable word offset.
    pub fn get_addressable_word_offset(&self, byte_offset: u64) -> u64 {
        match self.unit_size {
            1 => byte_offset,
            2 => byte_offset >> 1,
            4 => byte_offset >> 2,
            8 => byte_offset >> 3,
            _ => byte_offset / self.unit_size as u64,
        }
    }

    // -- Arithmetic helpers --

    /// Add a displacement with wrapping.
    pub fn add_wrap(&self, addr: Address, displacement: i64) -> Address {
        Address::new(self.truncate_offset(addr.offset as i64 + displacement) as u64)
    }

    /// Subtract a displacement with wrapping.
    pub fn subtract_wrap(&self, addr: Address, displacement: i64) -> Address {
        self.add_wrap(addr, -displacement)
    }

    /// Add a displacement, returning Err on overflow.
    pub fn add_no_wrap(
        &self,
        addr: Address,
        displacement: i64,
    ) -> Result<Address, AddressOverflowException> {
        if displacement == 0 {
            return Ok(addr);
        }
        if displacement < 0 {
            return self.subtract_no_wrap(addr, -displacement);
        }
        if self.space_size != 0 && (displacement as u64) > self.space_size {
            return Err(AddressOverflowException::add_overflow(addr.offset, displacement as u64));
        }
        let addr_off = addr.offset;
        let result = addr_off.wrapping_add(displacement as u64);

        if self.signed {
            if result < addr_off || result > self.max_address.offset {
                return Err(AddressOverflowException::add_overflow(addr_off, displacement as u64));
            }
        } else {
            if (self.max_address.offset as u64) < result || result < addr_off {
                return Err(AddressOverflowException::add_overflow(addr_off, displacement as u64));
            }
        }
        Ok(Address::new(result))
    }

    /// Subtract a displacement, returning Err on overflow.
    pub fn subtract_no_wrap(
        &self,
        addr: Address,
        displacement: i64,
    ) -> Result<Address, AddressOverflowException> {
        if displacement < 0 {
            if displacement == i64::MIN {
                return Err(AddressOverflowException::subtract_overflow(addr.offset, displacement as u64));
            }
            return self.add_no_wrap(addr, -displacement);
        }
        if self.space_size != 0 && (displacement as u64) > self.space_size {
            return Err(AddressOverflowException::subtract_overflow(addr.offset, displacement as u64));
        }
        let addr_off = addr.offset;
        let result = addr_off.wrapping_sub(displacement as u64);

        if self.signed {
            if result < self.min_address.offset || result > addr_off {
                return Err(AddressOverflowException::subtract_overflow(addr_off, displacement as u64));
            }
        } else {
            if (addr_off as u64) < result {
                return Err(AddressOverflowException::subtract_overflow(addr_off, displacement as u64));
            }
        }
        Ok(Address::new(result))
    }

    /// Add a displacement, returning Err on out-of-bounds.
    pub fn add(
        &self,
        addr: Address,
        displacement: i64,
    ) -> Result<Address, AddressOutOfBoundsException> {
        self.add_no_wrap(addr, displacement)
            .map_err(AddressOutOfBoundsException::from)
    }

    /// Subtract a displacement, returning Err on out-of-bounds.
    pub fn subtract(
        &self,
        addr: Address,
        displacement: i64,
    ) -> Result<Address, AddressOutOfBoundsException> {
        self.subtract_no_wrap(addr, displacement)
            .map_err(AddressOutOfBoundsException::from)
    }

    /// Compute the difference between two addresses in this space.
    pub fn subtract_addrs(&self, addr1: Address, addr2: Address) -> i64 {
        addr1.offset as i64 - addr2.offset as i64
    }

    /// Check if `addr2` immediately follows `addr1`.
    pub fn is_successor(&self, addr1: Address, addr2: Address) -> bool {
        if self.max_address.offset == addr1.offset {
            return false;
        }
        addr1.offset.wrapping_add(1) == addr2.offset
    }

    /// Check if a byte range is valid within this space.
    pub fn is_valid_range(&self, byte_offset: u64, length: u64) -> bool {
        if length == 0 {
            return false;
        }
        let start = match self.get_address(byte_offset) {
            Ok(a) => a,
            Err(_) => return false,
        };
        self.add_no_wrap(start, (length - 1) as i64).is_ok()
    }

    // -- String parsing --

    /// Parse an address string in this space.
    ///
    /// Accepts:
    /// - `"space_name:0x1234"` (with space name check)
    /// - `"0x1234"` or plain `"1234"` (hex offset)
    /// - Word offset notation: `"0x1234.2"` (for unit_size > 1)
    pub fn parse_address(
        &self,
        addr_string: &str,
        case_sensitive: bool,
    ) -> Result<Option<Address>, AddressFormatException> {
        let (space_part, offset_part) = if let Some(colon_pos) = addr_string.rfind(':') {
            let sp = &addr_string[..colon_pos];
            let off = &addr_string[colon_pos + 1..];
            (Some(sp), off)
        } else {
            (None, addr_string)
        };

        // Check space name matches
        if let Some(sp) = space_part {
            let matches = if case_sensitive {
                sp == self.name
            } else {
                sp.eq_ignore_ascii_case(&self.name)
            };
            if !matches {
                return Ok(None);
            }
        }

        let offset = self.parse_offset_string(offset_part)?;
        Ok(Some(Address::new(offset)))
    }

    fn parse_offset_string(&self, s: &str) -> Result<u64, AddressFormatException> {
        let s = s.trim();
        let s = s
            .strip_prefix("0x")
            .or_else(|| s.strip_prefix("0X"))
            .unwrap_or(s);

        let mut mod_offset = 0u64;
        let hex_part = if self.unit_size > 1 {
            if let Some(dot_pos) = s.find('.') {
                let unit_str = &s[dot_pos + 1..];
                mod_offset = u64::from_str_radix(unit_str, 16)
                    .map_err(|_| AddressFormatException::new(format!("invalid address unit offset: .{}", unit_str)))?;
                if mod_offset >= self.unit_size as u64 {
                    return Err(AddressFormatException::new(format!(
                        "invalid address unit offset: .{}",
                        unit_str
                    )));
                }
                &s[..dot_pos]
            } else {
                s
            }
        } else {
            s
        };

        let base = u64::from_str_radix(hex_part, 16)
            .map_err(|_| AddressFormatException::new(format!("contains invalid address hex offset: {}", s)))?;

        Ok((self.unit_size as u64 * base) + mod_offset)
    }

    /// Create the physical space (same as self for non-overlay spaces).
    pub fn get_physical_space(&self) -> &GenericAddressSpace {
        self
    }
}

impl std::fmt::Display for GenericAddressSpace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:", self.name)
    }
}

impl PartialEq for GenericAddressSpace {
    fn eq(&self, other: &Self) -> bool {
        self.space_id == other.space_id
            && self.name == other.name
            && self.size == other.size
            && self.unit_size == other.unit_size
    }
}

impl Eq for GenericAddressSpace {}

impl std::hash::Hash for GenericAddressSpace {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.name.hash(state);
        self.space_type.hash(state);
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::addr::AddrSpaceType;

    fn ram_32() -> GenericAddressSpace {
        GenericAddressSpace::new("ram", 32, 1, AddrSpaceType::Ram, 1)
    }

    fn stack_32() -> GenericAddressSpace {
        GenericAddressSpace::new("stack", 32, 1, AddrSpaceType::Stack, 2)
    }

    fn ram_64() -> GenericAddressSpace {
        GenericAddressSpace::new("ram64", 64, 1, AddrSpaceType::Ram, 3)
    }

    fn register_32() -> GenericAddressSpace {
        GenericAddressSpace::new("register", 32, 1, AddrSpaceType::Register, 4)
    }

    #[test]
    fn test_basic_properties() {
        let space = ram_32();
        assert_eq!(space.name(), "ram");
        assert_eq!(space.size(), 32);
        assert_eq!(space.pointer_size(), 4);
        assert_eq!(space.addressable_unit_size(), 1);
        assert!(!space.has_signed_offset());
        assert!(!space.is_overlay());
        assert!(space.is_memory_space());
        assert!(!space.is_register_space());
    }

    #[test]
    fn test_stack_is_signed() {
        let space = stack_32();
        assert!(space.has_signed_offset());
        assert!(space.is_stack_space());
        assert!(!space.is_memory_space());
    }

    #[test]
    fn test_register_space() {
        let space = register_32();
        assert!(space.is_register_space());
        assert!(!space.is_memory_space());
    }

    #[test]
    fn test_max_offset_32() {
        let space = ram_32();
        assert_eq!(space.max_offset(), 0xFFFF_FFFF);
        assert_eq!(space.max_address().offset, 0xFFFF_FFFF);
        assert_eq!(space.min_address().offset, 0);
    }

    #[test]
    fn test_max_offset_64() {
        let space = ram_64();
        assert_eq!(space.max_offset(), u64::MAX);
        assert_eq!(space.max_address().offset, u64::MAX);
    }

    #[test]
    fn test_stack_offsets() {
        let space = stack_32();
        // For 32-bit stack, max_offset = (2^32 - 1) / 2 = 0x7FFF_FFFF
        assert_eq!(space.max_offset(), 0x7FFF_FFFF);
        assert_eq!(space.min_offset(), -(0x8000_0000i64));
    }

    #[test]
    fn test_space_id_encoding() {
        let space = ram_32();
        // size=32 => logsize=2, unique=1, type=Ram=1
        // ID = (1 << 7) | (2 << 4) | 1 = 128 + 32 + 1 = 161
        assert_eq!(space.space_id(), (1 << 7) | (2 << 4) | 1);
    }

    #[test]
    fn test_get_address_valid() {
        let space = ram_32();
        let addr = space.get_address(0x1000).unwrap();
        assert_eq!(addr.offset, 0x1000);
    }

    #[test]
    fn test_get_address_out_of_bounds() {
        let space = ram_32();
        let result = space.get_address(0x1_FFFF_FFFF);
        assert!(result.is_err());
    }

    #[test]
    fn test_get_unchecked_address() {
        let space = ram_32();
        let addr = space.get_unchecked_address(0x1_FFFF_FFFF);
        assert_eq!(addr.offset, 0x1_FFFF_FFFF);
    }

    #[test]
    fn test_truncate_offset() {
        let space = ram_32();
        assert_eq!(space.truncate_offset(0x100), 0x100);
        // Wraps within 32-bit space
        let truncated = space.truncate_offset(0x1_FFFF_FFFF + 1);
        assert!(truncated <= 0xFFFF_FFFF);
    }

    #[test]
    fn test_truncate_word_offset() {
        // With size=17, word_address_mask = (1 << 17) - 1 = 0x1FFFF
        let space = GenericAddressSpace::new("ram", 17, 2, AddrSpaceType::Ram, 1);
        assert_eq!(space.truncate_addressable_word_offset(0xFFFF), 0xFFFF);
        assert_eq!(space.truncate_addressable_word_offset(0x1_FFFF), 0x1_FFFF);
        assert_eq!(space.truncate_addressable_word_offset(0x3_FFFF), 0x1_FFFF);
    }

    #[test]
    fn test_add_wrap() {
        let space = ram_32();
        let addr = Address::new(0xFFFF_FFFE);
        let result = space.add_wrap(addr, 5);
        assert_eq!(result.offset, 3); // wraps around 32-bit space
    }

    #[test]
    fn test_subtract_wrap() {
        let space = ram_32();
        let addr = Address::new(2);
        let result = space.subtract_wrap(addr, 5);
        // wraps: 2 - 5 = -3 mod 2^32 = 0xFFFF_FFFD
        assert_eq!(result.offset as u32, 0xFFFF_FFFD);
    }

    #[test]
    fn test_add_no_wrap_ok() {
        let space = ram_32();
        let addr = Address::new(0x1000);
        let result = space.add_no_wrap(addr, 0x100).unwrap();
        assert_eq!(result.offset, 0x1100);
    }

    #[test]
    fn test_add_no_wrap_overflow() {
        let space = ram_32();
        let addr = Address::new(0xFFFF_FFFE);
        let result = space.add_no_wrap(addr, 5);
        assert!(result.is_err());
    }

    #[test]
    fn test_subtract_no_wrap_ok() {
        let space = ram_32();
        let addr = Address::new(0x1100);
        let result = space.subtract_no_wrap(addr, 0x100).unwrap();
        assert_eq!(result.offset, 0x1000);
    }

    #[test]
    fn test_subtract_no_wrap_underflow() {
        let space = ram_32();
        let addr = Address::new(2);
        let result = space.subtract_no_wrap(addr, 5);
        assert!(result.is_err());
    }

    #[test]
    fn test_subtract_addrs() {
        let space = ram_32();
        let a = Address::new(0x2000);
        let b = Address::new(0x1000);
        assert_eq!(space.subtract_addrs(a, b), 0x1000);
    }

    #[test]
    fn test_is_successor() {
        let space = ram_32();
        assert!(space.is_successor(Address::new(0x100), Address::new(0x101)));
        assert!(!space.is_successor(Address::new(0x100), Address::new(0x102)));
    }

    #[test]
    fn test_is_valid_range() {
        let space = ram_32();
        assert!(space.is_valid_range(0x1000, 0x100));
        assert!(!space.is_valid_range(0xFFFF_FFFF, 2));
        assert!(!space.is_valid_range(0x1000, 0));
    }

    #[test]
    fn test_parse_address_with_space() {
        let space = ram_32();
        let addr = space.parse_address("ram:0x1234", true).unwrap();
        assert!(addr.is_some());
        assert_eq!(addr.unwrap().offset, 0x1234);
    }

    #[test]
    fn test_parse_address_wrong_space() {
        let space = ram_32();
        let addr = space.parse_address("other:0x1234", true).unwrap();
        assert!(addr.is_none());
    }

    #[test]
    fn test_parse_address_no_space() {
        let space = ram_32();
        let addr = space.parse_address("0x1234", true).unwrap();
        assert!(addr.is_some());
        assert_eq!(addr.unwrap().offset, 0x1234);
    }

    #[test]
    fn test_parse_address_plain_hex() {
        let space = ram_32();
        let addr = space.parse_address("abcd", true).unwrap();
        assert_eq!(addr.unwrap().offset, 0xabcd);
    }

    #[test]
    fn test_parse_address_case_insensitive() {
        let space = ram_32();
        let addr = space.parse_address("RAM:0x100", false).unwrap();
        assert!(addr.is_some());
    }

    #[test]
    fn test_get_addressable_word_offset() {
        let space = GenericAddressSpace::new("ram", 32, 4, AddrSpaceType::Ram, 1);
        assert_eq!(space.get_addressable_word_offset(0), 0);
        assert_eq!(space.get_addressable_word_offset(4), 1);
        assert_eq!(space.get_addressable_word_offset(8), 2);
    }

    #[test]
    fn test_display() {
        let space = ram_32();
        assert_eq!(format!("{}", space), "ram:");
    }

    #[test]
    fn test_overlay_flag() {
        let mut space = ram_32();
        assert!(!space.is_overlay());
        space.set_overlay(true);
        assert!(space.is_overlay());
    }

    #[test]
    fn test_equality() {
        let a = ram_32();
        let b = ram_32();
        assert_eq!(a, b);
    }
}
