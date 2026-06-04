//! MSVC Run-Time Type Information (RTTI) data structures.
//!
//! Ported from Ghidra's `ghidra.app.cmd.data.rtti` package.
//!
//! # RTTI Chain (MSVC)
//!
//! ```text
//! vftable pointer
//!   └── RTTI4  CompleteObjectLocator
//!         ├── pTypeDescriptor  ──► RTTI0  TypeDescriptor (class name + mangled info)
//!         └── pClassDescriptor ──► RTTI3  ClassHierarchyDescriptor
//!               └── pBaseClassArray ──► RTTI2  BaseClassArray
//!                     └── [0..N] ──► RTTI1  BaseClassDescriptor (each base class)
//!                           ├── pTypeDescriptor ──► RTTI0
//!                           └── pClassHierarchyDescriptor ──► RTTI3
//! ```

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// TypeDescriptor (RTTI 0)
// ---------------------------------------------------------------------------

/// MSVC RTTI Type Descriptor (RTTI 0).
///
/// Represents the type information for a C++ class including its mangled name.
///
/// ```c
/// struct TypeDescriptor {
///     void*   pVFTable;      // vftable of type_info (class)
///     void*   spare;         // reserved
///     char    name[];        // mangled class name (e.g. ".?AVMyClass@@")
/// };
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypeDescriptor {
    /// The RTTI vftable pointer for `type_info`.
    pub vftable_ptr: u64,
    /// Reserved spare pointer.
    pub spare: u64,
    /// Mangled class name (e.g., `".?AVMyClass@@"`).
    pub name: String,
    /// The address where this structure lives.
    pub address: u64,
    /// Whether the type uses image-relative pointers (64-bit mode).
    pub is_relative: bool,
}

impl TypeDescriptor {
    /// Attempt to parse a TypeDescriptor from a byte buffer at `address`.
    ///
    /// `ptr_size` should be 4 (32-bit) or 8 (64-bit).
    pub fn parse(data: &[u8], address: u64, ptr_size: usize) -> Option<Self> {
        if data.len() < ptr_size * 2 {
            return None;
        }
        let vftable_ptr = read_ptr(data, 0, ptr_size);
        let spare = read_ptr(data, ptr_size, ptr_size);

        let name_start = ptr_size * 2;
        if name_start >= data.len() {
            return None;
        }
        let name_bytes = &data[name_start..];
        let name_end = name_bytes.iter().position(|&b| b == 0).unwrap_or(name_bytes.len());
        let name = String::from_utf8_lossy(&name_bytes[..name_end]).to_string();

        Some(Self {
            vftable_ptr,
            spare,
            name,
            address,
            is_relative: ptr_size == 8,
        })
    }

    /// Strip MSVC mangling decorations and return a readable class name.
    pub fn demangled_class_name(&self) -> &str {
        let n = &self.name;
        // Typical patterns: ".?AVName@@", ".?AUName@@", ".?AVName@ns@@"
        let trimmed = n
            .trim_start_matches(".?AV")
            .trim_start_matches(".?AU")
            .trim_start_matches(".?AV")
            .trim_end_matches("@@");
        // Remove namespace separators
        let parts: Vec<&str> = trimmed.split('@').filter(|s| !s.is_empty()).collect();
        parts.last().copied().unwrap_or(trimmed)
    }

    /// The minimum byte length of the fixed header (two pointers).
    pub fn header_len(ptr_size: usize) -> usize {
        ptr_size * 2
    }
}

// ---------------------------------------------------------------------------
// BaseClassDescriptor (RTTI 1)
// ---------------------------------------------------------------------------

/// MSVC RTTI Base Class Descriptor (RTTI 1).
///
/// Describes a single base class in the hierarchy.
///
/// ```c
/// struct RTTIBaseClassDescriptor {
///     TypeDescriptor* pTypeDescriptor;         // ref to RTTI 0
///     unsigned long   numContainedBases;       // count in BaseClassArray (RTTI 2)
///     PMD             pmdMemberDisp;           // member displacement info
///     unsigned long   attributes;              // flags
///     ClassHierarchyDescriptor* pClassHierarchyDescriptor; // ref to RTTI 3
/// };
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaseClassDescriptor {
    /// Address of the TypeDescriptor (RTTI 0) for this base class.
    pub type_descriptor_address: u64,
    /// Number of extended base classes in the BaseClassArray (RTTI 2).
    pub num_contained_bases: u32,
    /// Member displacement within the base class.
    pub member_disp: i32,
    /// Vbtable displacement.
    pub vbtable_disp: i32,
    /// Displacement within the vbtable.
    pub vdisp: i32,
    /// Attributes flags (e.g., `0x10` for multiple inheritance).
    pub attributes: u32,
    /// Address of the ClassHierarchyDescriptor (RTTI 3).
    pub class_hierarchy_address: u64,
    /// The address where this structure lives.
    pub address: u64,
    /// Whether the type uses image-relative pointers (64-bit mode).
    pub is_relative: bool,
}

impl BaseClassDescriptor {
    /// Size of this structure for 32-bit targets (4 ptr + 3 dwords = 28 bytes).
    pub const SIZE_32: usize = 28;
    /// Size of this structure for 64-bit targets (uses image-relative offsets, 4 dwords = 16 bytes).
    pub const SIZE_64: usize = 16;

    /// Parse a BaseClassDescriptor from a byte buffer.
    pub fn parse(data: &[u8], address: u64, ptr_size: usize) -> Option<Self> {
        if ptr_size == 4 {
            Self::parse_32(data, address)
        } else {
            Self::parse_64(data, address)
        }
    }

    fn parse_32(data: &[u8], address: u64) -> Option<Self> {
        if data.len() < Self::SIZE_32 {
            return None;
        }
        let type_descriptor_address = read_u32(data, 0) as u64;
        let num_contained_bases = read_u32(data, 4);
        let member_disp = read_i32(data, 8);
        let vbtable_disp = read_i32(data, 12);
        let vdisp = read_i32(data, 16);
        let attributes = read_u32(data, 20);
        let class_hierarchy_address = read_u32(data, 24) as u64;

        Some(Self {
            type_descriptor_address,
            num_contained_bases,
            member_disp,
            vbtable_disp,
            vdisp,
            attributes,
            class_hierarchy_address,
            address,
            is_relative: false,
        })
    }

    fn parse_64(data: &[u8], address: u64) -> Option<Self> {
        if data.len() < Self::SIZE_64 {
            return None;
        }
        // In 64-bit mode, all pointers are image-relative (signed 32-bit offsets).
        let type_descriptor_address =
            address.wrapping_add(read_i32(data, 0) as i64 as u64);
        let num_contained_bases = read_u32(data, 4);
        let member_disp = read_i32(data, 8);
        // vbtable_disp and vdisp are packed differently in 64-bit
        let vbtable_disp = read_i32(data, 12);
        let vdisp = 0; // not present in 64-bit layout at the same offsets
        let attributes = 0u32;
        let class_hierarchy_address = 0u64; // resolved via RTTI3 separately

        Some(Self {
            type_descriptor_address,
            num_contained_bases,
            member_disp,
            vbtable_disp,
            vdisp,
            attributes,
            class_hierarchy_address,
            address,
            is_relative: true,
        })
    }

    /// Whether this base class uses virtual inheritance.
    pub fn has_virtual_base(&self) -> bool {
        self.attributes & 0x1 != 0
    }

    /// Whether this base class is public.
    pub fn is_public(&self) -> bool {
        self.attributes & 0x2 != 0
    }
}

// ---------------------------------------------------------------------------
// ClassHierarchyDescriptor (RTTI 2 -> actually RTTI 3 in Ghidra naming)
// ---------------------------------------------------------------------------

/// MSVC RTTI Class Hierarchy Descriptor (RTTI 3).
///
/// Describes the class hierarchy (number of base classes and a pointer to the
/// base class array).
///
/// ```c
/// struct RTTIClassHierarchyDescriptor {
///     unsigned long   signature;       // always 0
///     unsigned long   attributes;      // flags
///     unsigned long   numBaseClasses;  // count of entries in RTTI 2
///     BaseClassArray* pBaseClassArray;  // ref to RTTI 2
/// };
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassHierarchyDescriptor {
    /// Signature (always 0 in practice).
    pub signature: u32,
    /// Attributes (e.g., multiple/virtual inheritance hints).
    pub attributes: u32,
    /// Number of base classes (count of RTTI 1 entries in the RTTI 2 array).
    pub num_base_classes: u32,
    /// Address of the BaseClassArray (RTTI 2).
    pub base_class_array_address: u64,
    /// The address where this structure lives.
    pub address: u64,
    /// Whether the type uses image-relative pointers (64-bit mode).
    pub is_relative: bool,
}

impl ClassHierarchyDescriptor {
    /// Size in bytes for 32-bit targets (3 dwords + pointer = 16 bytes).
    pub const SIZE_32: usize = 16;
    /// Size in bytes for 64-bit targets (3 dwords = 12 bytes, pointer is image-relative).
    pub const SIZE_64: usize = 12;

    /// Parse from byte buffer.
    pub fn parse(data: &[u8], address: u64, ptr_size: usize) -> Option<Self> {
        if data.len() < 12 {
            return None;
        }
        let signature = read_u32(data, 0);
        let attributes = read_u32(data, 4);
        let num_base_classes = read_u32(data, 8);

        let base_class_array_address = if ptr_size == 4 && data.len() >= 16 {
            read_u32(data, 12) as u64
        } else if ptr_size == 8 && data.len() >= 16 {
            address.wrapping_add(12).wrapping_add(read_i32(data, 12) as i64 as u64)
        } else {
            0
        };

        Some(Self {
            signature,
            attributes,
            num_base_classes,
            base_class_array_address,
            address,
            is_relative: ptr_size == 8,
        })
    }

    /// Maximum sanity-checked base class count.
    pub const MAX_BASE_CLASSES: u32 = 1000;
}

// ---------------------------------------------------------------------------
// BaseClassArray (RTTI 2)
// ---------------------------------------------------------------------------

/// MSVC RTTI Base Class Array (RTTI 2).
///
/// An array of pointers or image-relative offsets to BaseClassDescriptor
/// (RTTI 1) entries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaseClassArray {
    /// Addresses of each BaseClassDescriptor (RTTI 1) in the array.
    pub entries: Vec<u64>,
    /// The address where this array lives.
    pub address: u64,
}

impl BaseClassArray {
    /// Parse from byte buffer given the expected entry count and pointer size.
    pub fn parse(data: &[u8], address: u64, entry_count: u32, ptr_size: usize) -> Option<Self> {
        let count = entry_count as usize;
        let entry_size = if ptr_size == 4 { 4 } else { 4 }; // always 4 bytes (IBO32 or pointer)
        let needed = count * entry_size;
        if data.len() < needed {
            return None;
        }

        let mut entries = Vec::with_capacity(count);
        for i in 0..count {
            let offset = i * entry_size;
            if ptr_size == 4 {
                entries.push(read_u32(data, offset) as u64);
            } else {
                // 64-bit image-relative
                entries.push(
                    address
                        .wrapping_add(offset as u64)
                        .wrapping_add(read_i32(data, offset) as i64 as u64),
                );
            }
        }

        Some(Self { entries, address })
    }
}

// ---------------------------------------------------------------------------
// CompleteObjectLocator (RTTI 4)
// ---------------------------------------------------------------------------

/// MSVC RTTI Complete Object Locator (RTTI 4).
///
/// This is the top-level RTTI structure that a vtable pointer refers to.
/// It locates the full RTTI chain for a class.
///
/// ```c
/// struct RTTICompleteObjectLocator {
///     unsigned long   signature;           // 0 for x86, 1 for x64
///     unsigned long   vbTableOffset;       // offset of vbtable
///     unsigned long   constructorDispOffset; // displacement to constructor
///     TypeDescriptor* pTypeDescriptor;     // ref to RTTI 0
///     ClassHierarchyDescriptor* pClassDescriptor; // ref to RTTI 3
/// };
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompleteObjectLocator {
    /// Signature: 0 = x86 (32-bit), 1 = x64 (64-bit).
    pub signature: u32,
    /// Offset of the virtual base table in the class layout.
    pub vb_table_offset: u32,
    /// Offset to the constructor displacement.
    pub constructor_disp_offset: u32,
    /// Address of the TypeDescriptor (RTTI 0).
    pub rtti0_address: u64,
    /// Address of the ClassHierarchyDescriptor (RTTI 3).
    pub rtti3_address: u64,
    /// The address where this structure lives.
    pub address: u64,
    /// Whether the type uses image-relative pointers (64-bit mode).
    pub is_relative: bool,
}

impl CompleteObjectLocator {
    /// Size in bytes for 32-bit targets (3 dwords + 2 pointers = 20 bytes).
    pub const SIZE_32: usize = 20;
    /// Size in bytes for 64-bit targets (3 dwords + 2 IBO32 = 20 bytes).
    pub const SIZE_64: usize = 20;

    /// Offsets of each field.
    pub const OFFSET_SIGNATURE: usize = 0;
    pub const OFFSET_VB_TABLE: usize = 4;
    pub const OFFSET_CONSTRUCTOR_DISP: usize = 8;
    pub const OFFSET_RTTI0: usize = 12;
    pub const OFFSET_RTTI3: usize = 16;

    /// Parse from byte buffer.
    pub fn parse(data: &[u8], address: u64, ptr_size: usize) -> Option<Self> {
        if data.len() < Self::SIZE_32 {
            return None;
        }
        let signature = read_u32(data, Self::OFFSET_SIGNATURE);
        let vb_table_offset = read_u32(data, Self::OFFSET_VB_TABLE);
        let constructor_disp_offset = read_u32(data, Self::OFFSET_CONSTRUCTOR_DISP);

        let rtti0_address = if ptr_size == 4 {
            read_u32(data, Self::OFFSET_RTTI0) as u64
        } else {
            address
                .wrapping_add(Self::OFFSET_RTTI0 as u64)
                .wrapping_add(read_i32(data, Self::OFFSET_RTTI0) as i64 as u64)
        };

        let rtti3_address = if ptr_size == 4 {
            read_u32(data, Self::OFFSET_RTTI3) as u64
        } else {
            address
                .wrapping_add(Self::OFFSET_RTTI3 as u64)
                .wrapping_add(read_i32(data, Self::OFFSET_RTTI3) as i64 as u64)
        };

        Some(Self {
            signature,
            vb_table_offset,
            constructor_disp_offset,
            rtti0_address,
            rtti3_address,
            address,
            is_relative: ptr_size == 8,
        })
    }

    /// Is this a valid COL signature?
    pub fn is_valid_signature(&self) -> bool {
        self.signature <= 1
    }

    /// Returns true if this is a 64-bit (image-relative) locator.
    pub fn is_64bit(&self) -> bool {
        self.signature == 1
    }
}

// ---------------------------------------------------------------------------
// RttiAnalyzer: port of Ghidra's RttiAnalyzer
// ---------------------------------------------------------------------------

/// Scans a binary for RTTI structures and labels them.
///
/// The analyzer searches for known MSVC RTTI patterns in memory, creates
/// the corresponding data structures, and labels them in the program listing.
#[derive(Debug)]
pub struct RttiAnalyzer {
    /// Whether to apply type descriptors.
    pub apply_type_descriptors: bool,
    /// Whether to apply vftable labels.
    pub apply_vftable_labels: bool,
    /// The pointer size used (4 or 8).
    pub ptr_size: usize,
}

impl Default for RttiAnalyzer {
    fn default() -> Self {
        Self {
            apply_type_descriptors: true,
            apply_vftable_labels: true,
            ptr_size: 4,
        }
    }
}

impl RttiAnalyzer {
    /// Create a new RTTI analyzer.
    pub fn new(ptr_size: usize) -> Self {
        Self {
            apply_type_descriptors: true,
            apply_vftable_labels: true,
            ptr_size,
        }
    }

    /// Attempt to parse a `CompleteObjectLocator` (RTTI 4) from the given bytes.
    pub fn try_parse_col(&self, data: &[u8], address: u64) -> Option<CompleteObjectLocator> {
        CompleteObjectLocator::parse(data, address, self.ptr_size)
            .filter(|c| c.is_valid_signature())
    }

    /// Attempt to parse a `ClassHierarchyDescriptor` (RTTI 3) from the given bytes.
    pub fn try_parse_chd(&self, data: &[u8], address: u64) -> Option<ClassHierarchyDescriptor> {
        ClassHierarchyDescriptor::parse(data, address, self.ptr_size)
            .filter(|c| c.num_base_classes >= 1 && c.num_base_classes <= ClassHierarchyDescriptor::MAX_BASE_CLASSES)
    }

    /// Attempt to parse a `BaseClassDescriptor` (RTTI 1) from the given bytes.
    pub fn try_parse_bcd(&self, data: &[u8], address: u64) -> Option<BaseClassDescriptor> {
        BaseClassDescriptor::parse(data, address, self.ptr_size)
    }

    /// Attempt to parse a `TypeDescriptor` (RTTI 0) from the given bytes.
    pub fn try_parse_td(&self, data: &[u8], address: u64) -> Option<TypeDescriptor> {
        TypeDescriptor::parse(data, address, self.ptr_size)
    }

    /// Validate a full RTTI chain starting from a COL address.
    ///
    /// Returns `true` if RTTI0, RTTI3, and (optionally) RTTI2/RTTI1 can all be resolved.
    pub fn validate_rtti_chain(
        &self,
        data: &[u8],
        base_address: u64,
        col_address: u64,
    ) -> bool {
        let rel_col = (col_address - base_address) as usize;
        let col_end = rel_col + CompleteObjectLocator::SIZE_32;
        if col_end > data.len() {
            return false;
        }

        let Some(col) = self.try_parse_col(&data[rel_col..col_end], col_address) else {
            return false;
        };

        // Check RTTI 0 (TypeDescriptor) pointer validity
        if col.rtti0_address == 0 || col.rtti0_address < base_address {
            return false;
        }
        let rtti0_rel = (col.rtti0_address - base_address) as usize;
        let rtti0_end = rtti0_rel + TypeDescriptor::header_len(self.ptr_size);
        if rtti0_end > data.len() {
            return false;
        }

        // Check RTTI 3 (ClassHierarchyDescriptor) pointer validity
        if col.rtti3_address == 0 || col.rtti3_address < base_address {
            return false;
        }
        let rtti3_rel = (col.rtti3_address - base_address) as usize;
        let rtti3_end = rtti3_rel + 12; // minimum for CHD header
        if rtti3_end > data.len() {
            return false;
        }

        true
    }
}

// ---------------------------------------------------------------------------
// Utility helpers
// ---------------------------------------------------------------------------

/// Read a little-endian `u32` from `data` at the given offset.
pub fn read_u32(data: &[u8], offset: usize) -> u32 {
    if offset + 4 > data.len() {
        return 0;
    }
    u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]])
}

/// Read a little-endian `i32` from `data` at the given offset.
pub fn read_i32(data: &[u8], offset: usize) -> i32 {
    read_u32(data, offset) as i32
}

/// Read a little-endian `u16` from `data` at the given offset.
pub fn read_u16(data: &[u8], offset: usize) -> u16 {
    if offset + 2 > data.len() {
        return 0;
    }
    u16::from_le_bytes([data[offset], data[offset + 1]])
}

/// Read a pointer-sized value (little-endian) from `data`.
pub fn read_ptr(data: &[u8], offset: usize, size: usize) -> u64 {
    match size {
        8 => {
            if offset + 8 > data.len() {
                return 0;
            }
            u64::from_le_bytes(
                data[offset..offset + 8].try_into().unwrap_or([0; 8]),
            )
        }
        4 => read_u32(data, offset) as u64,
        2 => read_u16(data, offset) as u64,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_type_descriptor_parse() {
        // Build a fake TypeDescriptor with name ".?AVTestClass@@"
        let name = b".?AVTestClass@@\0";
        let mut data = vec![0u8; 16 + name.len()];
        // vftable ptr
        data[0..4].copy_from_slice(&0x1000u32.to_le_bytes());
        // spare
        data[4..8].copy_from_slice(&0u32.to_le_bytes());
        data[8..8 + name.len()].copy_from_slice(name);

        let td = TypeDescriptor::parse(&data, 0x5000, 4).unwrap();
        assert_eq!(td.name, ".?AVTestClass@@");
        assert_eq!(td.demangled_class_name(), "TestClass");
        assert_eq!(td.vftable_ptr, 0x1000);
        assert_eq!(td.address, 0x5000);
    }

    #[test]
    fn test_complete_object_locator_parse_32() {
        // signature=0, vbTableOffset=0, ctorDisp=0, pRtti0=0x2000, pRtti3=0x3000
        let mut data = [0u8; 20];
        data[0..4].copy_from_slice(&0u32.to_le_bytes());   // signature
        data[4..8].copy_from_slice(&0u32.to_le_bytes());   // vbTableOffset
        data[8..12].copy_from_slice(&0u32.to_le_bytes());  // ctorDispOffset
        data[12..16].copy_from_slice(&0x2000u32.to_le_bytes()); // pRtti0
        data[16..20].copy_from_slice(&0x3000u32.to_le_bytes()); // pRtti3

        let col = CompleteObjectLocator::parse(&data, 0x1000, 4).unwrap();
        assert_eq!(col.signature, 0);
        assert_eq!(col.rtti0_address, 0x2000);
        assert_eq!(col.rtti3_address, 0x3000);
        assert!(!col.is_64bit());
        assert!(col.is_valid_signature());
    }

    #[test]
    fn test_complete_object_locator_parse_64() {
        let base = 0x14000_0000u64;
        let rtti0_abs = 0x14000_2000u64;
        let rtti3_abs = 0x14000_3000u64;
        let rtti0_offset = (rtti0_abs - (base + CompleteObjectLocator::OFFSET_RTTI0 as u64)) as i32;
        let rtti3_offset = (rtti3_abs - (base + CompleteObjectLocator::OFFSET_RTTI3 as u64)) as i32;

        let mut data = [0u8; 20];
        data[0..4].copy_from_slice(&1u32.to_le_bytes());  // signature = 1 (x64)
        data[4..8].copy_from_slice(&0u32.to_le_bytes());
        data[8..12].copy_from_slice(&0u32.to_le_bytes());
        data[12..16].copy_from_slice(&rtti0_offset.to_le_bytes());
        data[16..20].copy_from_slice(&rtti3_offset.to_le_bytes());

        let col = CompleteObjectLocator::parse(&data, base, 8).unwrap();
        assert_eq!(col.rtti0_address, rtti0_abs);
        assert_eq!(col.rtti3_address, rtti3_abs);
        assert!(col.is_64bit());
    }

    #[test]
    fn test_class_hierarchy_descriptor_parse() {
        let mut data = [0u8; 16];
        data[0..4].copy_from_slice(&0u32.to_le_bytes());      // signature
        data[4..8].copy_from_slice(&0u32.to_le_bytes());       // attributes
        data[8..12].copy_from_slice(&5u32.to_le_bytes());      // numBaseClasses
        data[12..16].copy_from_slice(&0x4000u32.to_le_bytes()); // pBaseClassArray

        let chd = ClassHierarchyDescriptor::parse(&data, 0x5000, 4).unwrap();
        assert_eq!(chd.num_base_classes, 5);
        assert_eq!(chd.base_class_array_address, 0x4000);
    }

    #[test]
    fn test_base_class_descriptor_parse_32() {
        let mut data = [0u8; 28];
        data[0..4].copy_from_slice(&0x2000u32.to_le_bytes()); // pTypeDescriptor
        data[4..8].copy_from_slice(&3u32.to_le_bytes());      // numContainedBases
        data[8..12].copy_from_slice(&4i32.to_le_bytes());     // memberDisp
        data[12..16].copy_from_slice(&0i32.to_le_bytes());    // vbtableDisp
        data[16..20].copy_from_slice(&0i32.to_le_bytes());    // vdisp
        data[20..24].copy_from_slice(&0x10u32.to_le_bytes()); // attributes (0x10 = multiple inheritance)
        data[24..28].copy_from_slice(&0x3000u32.to_le_bytes()); // pClassHierarchyDescriptor

        let bcd = BaseClassDescriptor::parse(&data, 0x6000, 4).unwrap();
        assert_eq!(bcd.type_descriptor_address, 0x2000);
        assert_eq!(bcd.num_contained_bases, 3);
        assert_eq!(bcd.member_disp, 4);
        assert_eq!(bcd.attributes, 0x10);
        assert_eq!(bcd.class_hierarchy_address, 0x3000);
    }

    #[test]
    fn test_base_class_array_parse() {
        let mut data = [0u8; 12]; // 3 entries
        data[0..4].copy_from_slice(&0x1000u32.to_le_bytes());
        data[4..8].copy_from_slice(&0x2000u32.to_le_bytes());
        data[8..12].copy_from_slice(&0x3000u32.to_le_bytes());

        let bca = BaseClassArray::parse(&data, 0x8000, 3, 4).unwrap();
        assert_eq!(bca.entries.len(), 3);
        assert_eq!(bca.entries[0], 0x1000);
        assert_eq!(bca.entries[1], 0x2000);
        assert_eq!(bca.entries[2], 0x3000);
    }

    #[test]
    fn test_rtti_analyzer_validate_chain() {
        let analyzer = RttiAnalyzer::new(4);
        let mut data = vec![0u8; 0x6000];

        // Build COL at 0x1000: signature=0, vbOff=0, ctorDisp=0, pRtti0=0x2000, pRtti3=0x3000
        let col_offset = 0x1000;
        data[col_offset..col_offset + 4].copy_from_slice(&0u32.to_le_bytes());
        data[col_offset + 4..col_offset + 8].copy_from_slice(&0u32.to_le_bytes());
        data[col_offset + 8..col_offset + 12].copy_from_slice(&0u32.to_le_bytes());
        data[col_offset + 12..col_offset + 16].copy_from_slice(&0x2000u32.to_le_bytes());
        data[col_offset + 16..col_offset + 20].copy_from_slice(&0x3000u32.to_le_bytes());

        // Build RTTI 0 (TypeDescriptor) at 0x2000
        let td_name = b".?AVTest@@\0";
        let td_offset = 0x2000;
        data[td_offset..td_offset + 4].copy_from_slice(&0x1000u32.to_le_bytes());
        data[td_offset + 4..td_offset + 8].copy_from_slice(&0u32.to_le_bytes());
        data[td_offset + 8..td_offset + 8 + td_name.len()].copy_from_slice(td_name);

        // Build RTTI 3 (CHD) at 0x3000
        let chd_offset = 0x3000;
        data[chd_offset..chd_offset + 4].copy_from_slice(&0u32.to_le_bytes());
        data[chd_offset + 4..chd_offset + 8].copy_from_slice(&0u32.to_le_bytes());
        data[chd_offset + 8..chd_offset + 12].copy_from_slice(&2u32.to_le_bytes());
        data[chd_offset + 12..chd_offset + 16].copy_from_slice(&0x4000u32.to_le_bytes());

        assert!(analyzer.validate_rtti_chain(&data, 0, 0x1000));
    }

    #[test]
    fn test_read_u32_basic() {
        let data = [0x78, 0x56, 0x34, 0x12];
        assert_eq!(read_u32(&data, 0), 0x12345678);
    }

    #[test]
    fn test_read_u32_out_of_bounds() {
        let data = [0x01, 0x02];
        assert_eq!(read_u32(&data, 0), 0); // returns 0 on OOB
    }

    #[test]
    fn test_type_descriptor_header_len() {
        assert_eq!(TypeDescriptor::header_len(4), 8);
        assert_eq!(TypeDescriptor::header_len(8), 16);
    }
}
