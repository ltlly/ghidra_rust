//! Device Tree Blob (DTB) / Flattened Device Tree format parser.
//!
//! Ported from Ghidra's `ghidra.file.formats.dtb` package.
//! Supports both FDT (Flattened Device Tree) and DT Table (Android DTBO) formats.
//!
//! References:
//! - Devicetree Specification v0.3
//! - <https://devicetree.org/specifications/>
//! - Android DTBO: <https://source.android.com/devices/architecture/dto/partitions>

use nom::{
    bytes::complete::take,
    number::complete::{be_u32, be_u64},
    IResult,
};
use std::collections::HashMap;
use std::fmt;

// ═══════════════════════════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════════════════════════

/// FDT magic value: `0xD00DFEED`.
pub const FDT_MAGIC: u32 = 0xD00DFEED;

/// DT Table magic (Android DTBO): `0xD7B7AB1E`.
pub const DT_TABLE_MAGIC: u32 = 0xD7B7AB1E;

// FDT structure tokens
/// Begin node.
pub const FDT_BEGIN_NODE: u32 = 0x00000001;
/// End node.
pub const FDT_END_NODE: u32 = 0x00000002;
/// Property.
pub const FDT_PROP: u32 = 0x00000003;
/// No operation (nop).
pub const FDT_NOP: u32 = 0x00000004;
/// End of structure block.
pub const FDT_END: u32 = 0x00000009;

// ═══════════════════════════════════════════════════════════════════════════════════
// FDT Header
// ═══════════════════════════════════════════════════════════════════════════════════

/// FDT (Flattened Device Tree) header.
#[derive(Debug, Clone)]
pub struct FdtHeader {
    /// Magic: `0xD00DFEED`.
    pub magic: u32,
    /// Total size of the DTB in bytes.
    pub totalsize: u32,
    /// Offset to the structure block.
    pub off_dt_struct: u32,
    /// Offset to the strings block.
    pub off_dt_strings: u32,
    /// Offset to the memory reservation block.
    pub off_mem_rsvmap: u32,
    /// Version of the DTB format.
    pub version: u32,
    /// Lowest compatible version.
    pub last_comp_version: u32,
    /// Physical ID of the system's boot CPU.
    pub boot_cpuid_phys: u32,
    /// Size of the strings block.
    pub size_dt_strings: u32,
    /// Size of the structure block.
    pub size_dt_struct: u32,
}

impl FdtHeader {
    /// Header size for version >= 17.
    pub const SIZE_V17: usize = 40;

    /// Parse an FDT header from a big-endian byte slice.
    pub fn parse(data: &[u8]) -> IResult<&[u8], Self> {
        let (i, magic) = be_u32(data)?;
        let (i, totalsize) = be_u32(i)?;
        let (i, off_dt_struct) = be_u32(i)?;
        let (i, off_dt_strings) = be_u32(i)?;
        let (i, off_mem_rsvmap) = be_u32(i)?;
        let (i, version) = be_u32(i)?;
        let (i, last_comp_version) = be_u32(i)?;
        let (i, boot_cpuid_phys) = be_u32(i)?;
        let (i, size_dt_strings) = be_u32(i)?;
        let (i, size_dt_struct) = be_u32(i)?;

        Ok((
            i,
            FdtHeader {
                magic,
                totalsize,
                off_dt_struct,
                off_dt_strings,
                off_mem_rsvmap,
                version,
                last_comp_version,
                boot_cpuid_phys,
                size_dt_strings,
                size_dt_struct,
            },
        ))
    }

    /// Check if the magic is valid.
    pub fn is_valid(&self) -> bool {
        self.magic == FDT_MAGIC
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// FDT Property
// ═══════════════════════════════════════════════════════════════════════════════════

/// A property in a device tree node.
#[derive(Debug, Clone)]
pub struct FdtProperty {
    /// Property name (resolved from strings block).
    pub name: String,
    /// Property value bytes.
    pub value: Vec<u8>,
}

impl FdtProperty {
    /// Try to interpret value as a big-endian u32.
    pub fn as_u32(&self) -> Option<u32> {
        if self.value.len() >= 4 {
            Some(u32::from_be_bytes([
                self.value[0],
                self.value[1],
                self.value[2],
                self.value[3],
            ]))
        } else {
            None
        }
    }

    /// Try to interpret value as a big-endian u64.
    pub fn as_u64(&self) -> Option<u64> {
        if self.value.len() >= 8 {
            Some(u64::from_be_bytes([
                self.value[0],
                self.value[1],
                self.value[2],
                self.value[3],
                self.value[4],
                self.value[5],
                self.value[6],
                self.value[7],
            ] as [u8; 8]))
        } else {
            None
        }
    }

    /// Try to interpret value as a NUL-terminated string.
    pub fn as_str(&self) -> Option<&str> {
        // Trim trailing NUL
        let end = self.value.iter().position(|&b| b == 0).unwrap_or(self.value.len());
        std::str::from_utf8(&self.value[..end]).ok()
    }

    /// Try to interpret value as a list of NUL-terminated strings.
    pub fn as_string_list(&self) -> Vec<&str> {
        self.value
            .split(|&b| b == 0)
            .filter(|s| !s.is_empty())
            .filter_map(|s| std::str::from_utf8(s).ok())
            .collect()
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// FDT Node
// ═══════════════════════════════════════════════════════════════════════════════════

/// A node in the device tree.
#[derive(Debug, Clone)]
pub struct FdtNode {
    /// Node name.
    pub name: String,
    /// Properties of this node.
    pub properties: Vec<FdtProperty>,
    /// Child nodes.
    pub children: Vec<FdtNode>,
}

impl FdtNode {
    /// Find a property by name.
    pub fn get_property(&self, name: &str) -> Option<&FdtProperty> {
        self.properties.iter().find(|p| p.name == name)
    }

    /// Find a child node by name.
    pub fn get_child(&self, name: &str) -> Option<&FdtNode> {
        self.children.iter().find(|c| c.name == name)
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// FDT Device Tree
// ═══════════════════════════════════════════════════════════════════════════════════

/// A parsed Flattened Device Tree.
#[derive(Debug, Clone)]
pub struct FdtDeviceTree {
    /// The FDT header.
    pub header: FdtHeader,
    /// Memory reservation entries: (address, size).
    pub memory_reservations: Vec<(u64, u64)>,
    /// Root node of the device tree.
    pub root: FdtNode,
}

impl FdtDeviceTree {
    /// Parse a Flattened Device Tree from a big-endian byte slice.
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        let (_, header) = FdtHeader::parse(data)
            .map_err(|e| format!("Failed to parse FDT header: {:?}", e))?;

        if !header.is_valid() {
            return Err(format!(
                "Invalid FDT magic: expected 0x{:08X}, got 0x{:08X}",
                FDT_MAGIC, header.magic
            ));
        }

        if header.totalsize as usize > data.len() {
            return Err("FDT total size exceeds data length".to_string());
        }

        // Parse memory reservation block
        let mut mem_rsv = Vec::new();
        let mut off = header.off_mem_rsvmap as usize;
        loop {
            if off + 16 > data.len() {
                break;
            }
            let address = u64::from_be_bytes(data[off..off + 8].try_into().unwrap());
            let size = u64::from_be_bytes(data[off + 8..off + 16].try_into().unwrap());
            off += 16;
            if address == 0 && size == 0 {
                break;
            }
            mem_rsv.push((address, size));
        }

        // Parse strings block
        let strings_start = header.off_dt_strings as usize;
        let strings_end = strings_start + header.size_dt_strings as usize;
        let strings_block = if strings_end <= data.len() {
            &data[strings_start..strings_end]
        } else {
            &data[strings_start..]
        };

        // Parse structure block
        let struct_start = header.off_dt_struct as usize;
        let struct_end = struct_start + header.size_dt_struct as usize;
        let struct_block = if struct_end <= data.len() {
            &data[struct_start..struct_end]
        } else {
            &data[struct_start..]
        };

        let mut cursor = 0usize;
        let root = parse_node_recursive(struct_block, strings_block, &mut cursor)?;

        Ok(FdtDeviceTree {
            header,
            memory_reservations: mem_rsv,
            root,
        })
    }

    /// Check if a byte slice starts with FDT magic.
    pub fn is_fdt(data: &[u8]) -> bool {
        data.len() >= 4 && u32::from_be_bytes([data[0], data[1], data[2], data[3]]) == FDT_MAGIC
    }
}

/// Recursively parse FDT nodes from the structure block.
fn parse_node_recursive(
    struct_block: &[u8],
    strings_block: &[u8],
    cursor: &mut usize,
) -> Result<FdtNode, String> {
    let mut node = FdtNode {
        name: String::new(),
        properties: Vec::new(),
        children: Vec::new(),
    };

    loop {
        if *cursor + 4 > struct_block.len() {
            break;
        }

        let token = u32::from_be_bytes([
            struct_block[*cursor],
            struct_block[*cursor + 1],
            struct_block[*cursor + 2],
            struct_block[*cursor + 3],
        ]);
        *cursor += 4;

        match token {
            FDT_BEGIN_NODE => {
                // Read node name (NUL-terminated, padded to 4 bytes)
                let name_start = *cursor;
                let name_end = struct_block[name_start..]
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(0);
                node.name = String::from_utf8_lossy(&struct_block[name_start..name_start + name_end])
                    .to_string();
                *cursor = name_start + name_end + 1;
                // Align to 4 bytes
                *cursor = (*cursor + 3) & !3;
            }
            FDT_END_NODE => {
                return Ok(node);
            }
            FDT_PROP => {
                if *cursor + 8 > struct_block.len() {
                    break;
                }
                let len = u32::from_be_bytes([
                    struct_block[*cursor],
                    struct_block[*cursor + 1],
                    struct_block[*cursor + 2],
                    struct_block[*cursor + 3],
                ]) as usize;
                let nameoff = u32::from_be_bytes([
                    struct_block[*cursor + 4],
                    struct_block[*cursor + 5],
                    struct_block[*cursor + 6],
                    struct_block[*cursor + 7],
                ]) as usize;
                *cursor += 8;

                // Read property value
                let value = if *cursor + len <= struct_block.len() {
                    struct_block[*cursor..*cursor + len].to_vec()
                } else {
                    Vec::new()
                };
                *cursor += len;
                // Align to 4 bytes
                *cursor = (*cursor + 3) & !3;

                // Resolve name from strings block
                let name = if nameoff < strings_block.len() {
                    let end = strings_block[nameoff..]
                        .iter()
                        .position(|&b| b == 0)
                        .unwrap_or(strings_block.len() - nameoff);
                    String::from_utf8_lossy(&strings_block[nameoff..nameoff + end]).to_string()
                } else {
                    format!("unknown@{}", nameoff)
                };

                node.properties.push(FdtProperty { name, value });
            }
            FDT_NOP => {
                // Skip
            }
            FDT_END => {
                break;
            }
            _ => {
                // Unknown token, skip
            }
        }
    }

    Ok(node)
}

// ═══════════════════════════════════════════════════════════════════════════════════
// DT Table Header (Android DTBO)
// ═══════════════════════════════════════════════════════════════════════════════════

/// Android DTBO (Device Tree Table) header.
#[derive(Debug, Clone)]
pub struct DtTableHeader {
    /// Magic: `0xD7B7AB1E`.
    pub magic: u32,
    /// Total size.
    pub total_size: u32,
    /// Header size.
    pub header_size: u32,
    /// DT entry size.
    pub dt_entry_size: u32,
    /// Number of DT entries.
    pub dt_entry_count: u32,
    /// Offset to DT entries.
    pub dt_entries_offset: u32,
    /// Page size.
    pub page_size: u32,
    /// Version.
    pub version: u32,
}

impl DtTableHeader {
    pub const SIZE: usize = 32;

    /// Parse a DT table header (big-endian).
    pub fn parse(data: &[u8]) -> IResult<&[u8], Self> {
        let (i, magic) = be_u32(data)?;
        let (i, total_size) = be_u32(i)?;
        let (i, header_size) = be_u32(i)?;
        let (i, dt_entry_size) = be_u32(i)?;
        let (i, dt_entry_count) = be_u32(i)?;
        let (i, dt_entries_offset) = be_u32(i)?;
        let (i, page_size) = be_u32(i)?;
        let (i, version) = be_u32(i)?;

        Ok((
            i,
            DtTableHeader {
                magic,
                total_size,
                header_size,
                dt_entry_size,
                dt_entry_count,
                dt_entries_offset,
                page_size,
                version,
            },
        ))
    }

    pub fn is_valid(&self) -> bool {
        self.magic == DT_TABLE_MAGIC
    }
}

/// An entry in a DT Table.
#[derive(Debug, Clone, Copy)]
pub struct DtTableEntry {
    /// Offset to the DTB within the image.
    pub dt_offset: u32,
    /// Size of the DTB.
    pub dt_size: u32,
    /// Offset to the ID in the string table.
    pub id: u32,
    /// Custom0.
    pub custom0: u32,
    /// Custom1.
    pub custom1: u32,
    /// Custom2.
    pub custom2: u32,
    /// Custom3.
    pub custom3: u32,
}

impl DtTableEntry {
    pub const SIZE: usize = 32;

    pub fn parse(data: &[u8]) -> IResult<&[u8], Self> {
        let (i, dt_offset) = be_u32(data)?;
        let (i, dt_size) = be_u32(i)?;
        let (i, id) = be_u32(i)?;
        let (i, custom0) = be_u32(i)?;
        let (i, custom1) = be_u32(i)?;
        let (i, custom2) = be_u32(i)?;
        let (i, custom3) = be_u32(i)?;

        Ok((
            i,
            DtTableEntry {
                dt_offset,
                dt_size,
                id,
                custom0,
                custom1,
                custom2,
                custom3,
            },
        ))
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fdt_magic() {
        assert_eq!(FDT_MAGIC, 0xD00DFEED);
    }

    #[test]
    fn test_dt_table_magic() {
        assert_eq!(DT_TABLE_MAGIC, 0xD7B7AB1E);
    }

    #[test]
    fn test_is_fdt() {
        let data = FDT_MAGIC.to_be_bytes();
        assert!(FdtDeviceTree::is_fdt(&data));
        assert!(!FdtDeviceTree::is_fdt(&[0, 0, 0, 0]));
    }

    #[test]
    fn test_fdt_header_parse() {
        let mut data = Vec::new();
        data.extend_from_slice(&FDT_MAGIC.to_be_bytes());
        data.extend_from_slice(&256u32.to_be_bytes()); // totalsize
        data.extend_from_slice(&40u32.to_be_bytes());  // off_dt_struct
        data.extend_from_slice(&200u32.to_be_bytes()); // off_dt_strings
        data.extend_from_slice(&32u32.to_be_bytes());  // off_mem_rsvmap
        data.extend_from_slice(&17u32.to_be_bytes());  // version
        data.extend_from_slice(&16u32.to_be_bytes());  // last_comp_version
        data.extend_from_slice(&0u32.to_be_bytes());   // boot_cpuid_phys
        data.extend_from_slice(&56u32.to_be_bytes());  // size_dt_strings
        data.extend_from_slice(&160u32.to_be_bytes()); // size_dt_struct

        let (_, header) = FdtHeader::parse(&data).unwrap();
        assert!(header.is_valid());
        assert_eq!(header.totalsize, 256);
        assert_eq!(header.version, 17);
    }

    #[test]
    fn test_dt_table_header_parse() {
        let mut data = Vec::new();
        data.extend_from_slice(&DT_TABLE_MAGIC.to_be_bytes());
        data.extend_from_slice(&512u32.to_be_bytes()); // total_size
        data.extend_from_slice(&32u32.to_be_bytes());  // header_size
        data.extend_from_slice(&32u32.to_be_bytes());  // dt_entry_size
        data.extend_from_slice(&1u32.to_be_bytes());   // dt_entry_count
        data.extend_from_slice(&32u32.to_be_bytes());  // dt_entries_offset
        data.extend_from_slice(&4096u32.to_be_bytes()); // page_size
        data.extend_from_slice(&0u32.to_be_bytes());   // version

        let (_, header) = DtTableHeader::parse(&data).unwrap();
        assert!(header.is_valid());
        assert_eq!(header.dt_entry_count, 1);
    }

    #[test]
    fn test_dt_table_entry_parse() {
        let mut data = Vec::new();
        data.extend_from_slice(&64u32.to_be_bytes());   // dt_offset
        data.extend_from_slice(&1024u32.to_be_bytes()); // dt_size
        data.extend_from_slice(&1u32.to_be_bytes());    // id
        data.extend_from_slice(&0u32.to_be_bytes());    // custom0-3
        data.extend_from_slice(&0u32.to_be_bytes());
        data.extend_from_slice(&0u32.to_be_bytes());
        data.extend_from_slice(&0u32.to_be_bytes());

        let (_, entry) = DtTableEntry::parse(&data).unwrap();
        assert_eq!(entry.dt_offset, 64);
        assert_eq!(entry.dt_size, 1024);
    }

    #[test]
    fn test_property_as_str() {
        let prop = FdtProperty {
            name: "compatible".to_string(),
            value: b"vendor,device\0".to_vec(),
        };
        assert_eq!(prop.as_str(), Some("vendor,device"));
    }

    #[test]
    fn test_property_as_u32() {
        let prop = FdtProperty {
            name: "#address-cells".to_string(),
            value: 2u32.to_be_bytes().to_vec(),
        };
        assert_eq!(prop.as_u32(), Some(2));
    }

    #[test]
    fn test_node_get_property() {
        let node = FdtNode {
            name: "test".to_string(),
            properties: vec![
                FdtProperty {
                    name: "compatible".to_string(),
                    value: b"test\0".to_vec(),
                },
            ],
            children: vec![],
        };
        assert!(node.get_property("compatible").is_some());
        assert!(node.get_property("missing").is_none());
    }
}
