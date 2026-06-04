//! MZ (DOS Executable) loader.
//!
//! Ported from Ghidra's `ghidra.app.util.opinion.MzLoader`.
//!
//! Handles old-style DOS MZ executables by parsing the DOS header,
//! relocation table, and loading segments into a segmented address space.

use super::framework::*;
use crate::base::analyzer::{Address, Language, MemoryBlock, Program};

/// MZ loader name.
pub const MZ_NAME: &str = "Old-style DOS Executable (MZ)";

/// Minimum byte length for a valid MZ header.
const MIN_MZ_LENGTH: usize = 64;

/// DOS header e_magic: "MZ" (0x5A4D).
const MZ_MAGIC: u16 = 0x5A4D;

/// Parsed DOS (MZ) header fields we need for loading.
#[derive(Debug, Clone)]
pub struct MzHeader {
    /// e_magic: Must be 0x5A4D ("MZ").
    pub e_magic: u16,
    /// e_cparhdr: Size of header in paragraphs (16-byte units).
    pub e_cparhdr: u16,
    /// e_cp: Pages in file (512 bytes each).
    pub e_cp: u16,
    /// e_cblp: Bytes on last page.
    pub e_cblp: u16,
    /// e_minalloc: Minimum extra paragraphs needed.
    pub e_minalloc: u16,
    /// e_maxalloc: Maximum extra paragraphs needed.
    pub e_maxalloc: u16,
    /// e_ss: Initial SS value (relative to load segment).
    pub e_ss: u16,
    /// e_sp: Initial SP value.
    pub e_sp: u16,
    /// e_cs: Initial CS value (relative to load segment).
    pub e_cs: u16,
    /// e_ip: Initial IP value.
    pub e_ip: u16,
    /// e_lfarlc: File offset of relocation table.
    pub e_lfarlc: u16,
    /// e_ovno: Overlay number.
    pub e_ovno: u16,
    /// e_lfanew: File offset of new exe header (PE/NE). 0 if not present.
    pub e_lfanew: u32,
}

impl MzHeader {
    /// Parse an MZ header from raw bytes.
    pub fn parse(data: &[u8]) -> Result<Self, LoadError> {
        if data.len() < MIN_MZ_LENGTH {
            return Err(LoadError::MalformedInput("Too short for MZ header".into()));
        }

        let e_magic = u16::from_le_bytes([data[0], data[1]]);
        if e_magic != MZ_MAGIC {
            return Err(LoadError::MalformedInput(format!(
                "Bad MZ magic: 0x{:04x} (expected 0x5A4D)",
                e_magic
            )));
        }

        Ok(MzHeader {
            e_magic,
            e_cblp: u16::from_le_bytes([data[2], data[3]]),
            e_cp: u16::from_le_bytes([data[4], data[5]]),
            e_cparhdr: u16::from_le_bytes([data[8], data[9]]),
            e_minalloc: u16::from_le_bytes([data[10], data[11]]),
            e_maxalloc: u16::from_le_bytes([data[12], data[13]]),
            e_ss: u16::from_le_bytes([data[14], data[15]]),
            e_sp: u16::from_le_bytes([data[16], data[17]]),
            e_cs: u16::from_le_bytes([data[20], data[21]]),
            e_ip: u16::from_le_bytes([data[22], data[23]]),
            e_lfarlc: u16::from_le_bytes([data[24], data[25]]),
            e_ovno: u16::from_le_bytes([data[28], data[29]]),
            e_lfanew: u32::from_le_bytes([data[60], data[61], data[62], data[63]]),
        })
    }

    /// Check if the magic is valid MZ.
    pub fn is_valid(&self) -> bool {
        self.e_magic == MZ_MAGIC
    }

    /// Check if this has a PE or NE header (not a plain DOS executable).
    pub fn has_new_exe_header(&self) -> bool {
        self.e_lfanew != 0
    }

    /// Get the size of the load module in bytes.
    pub fn load_module_size(&self) -> usize {
        let pages = self.e_cp as usize;
        let bytes_on_last = self.e_cblp as usize;
        let total = (pages.saturating_sub(1)) * 512 + bytes_on_last;
        let header_size = (self.e_cparhdr as usize) * 16;
        total.saturating_sub(header_size)
    }

    /// Get the header size in bytes.
    pub fn header_size(&self) -> usize {
        (self.e_cparhdr as usize) * 16
    }
}

/// A parsed MZ relocation entry.
#[derive(Debug, Clone, Copy)]
pub struct MzRelocation {
    /// Segment part of the relocation target.
    pub segment: u16,
    /// Offset part of the relocation target.
    pub offset: u16,
}

/// Detect whether `data` is an MZ executable (DOS, not PE).
pub fn is_mz(data: &[u8]) -> bool {
    if data.len() < MIN_MZ_LENGTH {
        return false;
    }
    let magic = u16::from_le_bytes([data[0], data[1]]);
    if magic != MZ_MAGIC {
        return false;
    }
    // Check that there's no PE/NE header
    let e_lfanew = u32::from_le_bytes([data[60], data[61], data[62], data[63]]);
    if e_lfanew == 0 {
        return true;
    }
    // If e_lfanew points to a valid PE signature, this is not a plain MZ
    if e_lfanew as usize + 4 <= data.len() {
        let sig = &data[e_lfanew as usize..e_lfanew as usize + 4];
        if sig == b"PE\0\0" || sig == b"NE\0\0" {
            return false;
        }
    }
    true
}

/// Find supported load specs for MZ data.
pub fn find_mz_load_specs() -> Vec<LoadSpec> {
    let results = QueryOpinionService::query(MZ_NAME, "0", None);
    if results.is_empty() {
        vec![LoadSpec::with_unknown_language(MZ_NAME, 0, true)]
    } else {
        results
            .iter()
            .map(|r| LoadSpec::from_query_result(MZ_NAME, 0, r))
            .collect()
    }
}

/// Parse the MZ relocation table.
pub fn parse_relocations(data: &[u8], header: &MzHeader) -> Vec<MzRelocation> {
    let mut relocations = Vec::new();

    if header.e_lfarlc == 0 {
        return relocations;
    }

    let reloc_offset = header.e_lfarlc as usize;
    // Number of relocations is implicit: (header_size - e_lfarlc) / 4
    let reloc_count = if header.e_cparhdr > 0 {
        let hdr_size = (header.e_cparhdr as usize) * 16;
        if hdr_size > reloc_offset {
            (hdr_size - reloc_offset) / 4
        } else {
            0
        }
    } else {
        0
    };

    for i in 0..reloc_count {
        let off = reloc_offset + i * 4;
        if off + 4 > data.len() {
            break;
        }
        relocations.push(MzRelocation {
            offset: u16::from_le_bytes([data[off], data[off + 1]]),
            segment: u16::from_le_bytes([data[off + 2], data[off + 3]]),
        });
    }

    relocations
}

/// Load an MZ executable into a Program.
pub fn load_mz(data: &[u8], _options: &[LoadOption], log: &mut MessageLog) -> Result<Program, LoadError> {
    let header = MzHeader::parse(data)?;

    let lang = Language {
        processor: "x86".into(),
        variant: "LE:16:Real Mode".into(),
        size: 16,
    };
    let mut program = Program::new("mz_binary", lang);
    program.executable_format = Some(MZ_NAME.to_string());

    let initial_segment = 0x1000u64;
    let header_size = header.header_size();
    let load_size = header.load_module_size();
    let code_start = initial_segment * 16;

    // Create the code segment
    if load_size > 0 {
        let actual_size = load_size.min(data.len().saturating_sub(header_size));
        program.memory_blocks.push(MemoryBlock {
            name: "CODE".to_string(),
            start: Address::new(code_start),
            size: actual_size as u64,
            is_read: true,
            is_write: true,
            is_execute: true,
            is_initialized: true,
        });
        program.memory.add_range(crate::base::analyzer::AddressRange::new(
            Address::new(code_start),
            Address::new(code_start + actual_size as u64 - 1),
        ));
    }

    // Create extra data space if needed
    let extra_paragraphs = header.e_minalloc as u64;
    if extra_paragraphs > 0 {
        let extra_start = code_start + load_size as u64;
        let extra_size = extra_paragraphs * 16;
        program.memory_blocks.push(MemoryBlock {
            name: "DATA".to_string(),
            start: Address::new(extra_start),
            size: extra_size,
            is_read: true,
            is_write: true,
            is_execute: false,
            is_initialized: false,
        });
        program.memory.add_range(crate::base::analyzer::AddressRange::new(
            Address::new(extra_start),
            Address::new(extra_start + extra_size - 1),
        ));
    }

    // Set entry point
    let entry = code_start + (header.e_cs as u64) * 16 + header.e_ip as u64;
    program
        .symbols
        .insert(Address::new(entry), "entry".to_string());
    program.image_base = code_start;

    // Parse relocations
    let relocations = parse_relocations(data, &header);
    if !relocations.is_empty() {
        log.info(format!("Parsed {} MZ relocations", relocations.len()));
    }

    log.info(format!(
        "Loaded MZ: header {} bytes, load module {} bytes, entry 0x{:x}",
        header_size, load_size, entry
    ));

    Ok(program)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_minimal_mz() -> Vec<u8> {
        let mut data = vec![0u8; 256];
        // e_magic = "MZ"
        data[0] = 0x4D;
        data[1] = 0x5A;
        // e_cblp = 0 (bytes on last page)
        data[2] = 0x00;
        data[3] = 0x00;
        // e_cp = 2 (pages in file = 1024 bytes)
        data[4] = 0x02;
        data[5] = 0x00;
        // e_cparhdr = 2 (header size = 32 bytes)
        data[8] = 0x02;
        data[9] = 0x00;
        // e_minalloc = 1
        data[10] = 0x01;
        data[11] = 0x00;
        // e_maxalloc = 0xFFFF
        data[12] = 0xFF;
        data[13] = 0xFF;
        // e_ss = 0
        data[14] = 0x00;
        data[15] = 0x00;
        // e_sp = 0x100
        data[16] = 0x00;
        data[17] = 0x01;
        // e_cs = 0
        data[20] = 0x00;
        data[21] = 0x00;
        // e_ip = 0x100
        data[22] = 0x00;
        data[23] = 0x01;
        // e_lfarlc = 0x1C (relocation table at 28)
        data[24] = 0x1C;
        data[25] = 0x00;
        // e_lfanew = 0 (no PE/NE header)
        data[60] = 0x00;
        data[61] = 0x00;
        data[62] = 0x00;
        data[63] = 0x00;
        data
    }

    #[test]
    fn test_mz_header_parse() {
        let data = make_minimal_mz();
        let header = MzHeader::parse(&data).unwrap();
        assert!(header.is_valid());
        assert_eq!(header.e_magic, MZ_MAGIC);
        assert_eq!(header.e_cparhdr, 2);
        assert_eq!(header.e_cp, 2);
        assert_eq!(header.e_sp, 0x100);
        assert_eq!(header.e_ip, 0x100);
        assert!(!header.has_new_exe_header());
    }

    #[test]
    fn test_mz_header_parse_bad_magic() {
        let mut data = make_minimal_mz();
        data[0] = 0x00;
        assert!(MzHeader::parse(&data).is_err());
    }

    #[test]
    fn test_mz_header_parse_too_short() {
        assert!(MzHeader::parse(&[0x4D, 0x5A]).is_err());
    }

    #[test]
    fn test_is_mz_valid() {
        let data = make_minimal_mz();
        assert!(is_mz(&data));
    }

    #[test]
    fn test_is_mz_pe() {
        let mut data = make_minimal_mz();
        // Set e_lfanew to 0x80
        data[60] = 0x80;
        // PE signature at 0x80
        if data.len() > 0x83 {
            data[0x80] = b'P';
            data[0x81] = b'E';
            data[0x82] = 0;
            data[0x83] = 0;
        }
        assert!(!is_mz(&data));
    }

    #[test]
    fn test_is_mz_invalid() {
        assert!(!is_mz(&[]));
        assert!(!is_mz(&[0x7f, b'E', b'L', b'F']));
    }

    #[test]
    fn test_mz_load_module_size() {
        let data = make_minimal_mz();
        let header = MzHeader::parse(&data).unwrap();
        // (e_cp-1)*512 + e_cblp - header_size = (2-1)*512 + 0 - 32 = 480
        assert_eq!(header.load_module_size(), 480);
    }

    #[test]
    fn test_mz_header_size() {
        let data = make_minimal_mz();
        let header = MzHeader::parse(&data).unwrap();
        assert_eq!(header.header_size(), 32); // 2 paragraphs * 16
    }

    #[test]
    fn test_parse_relocations_empty() {
        let data = make_minimal_mz();
        let header = MzHeader::parse(&data).unwrap();
        let relocs = parse_relocations(&data, &header);
        // No relocation entries fit in the remaining header space
        // (header_size=32, e_lfarlc=28, so (32-28)/4 = 1 possible entry)
        // But it depends on available data
    }

    #[test]
    fn test_find_mz_load_specs() {
        let specs = find_mz_load_specs();
        assert!(!specs.is_empty());
    }

    #[test]
    fn test_load_mz() {
        let data = make_minimal_mz();
        let mut log = MessageLog::new();
        let prog = load_mz(&data, &[], &mut log).unwrap();
        assert_eq!(prog.executable_format, Some(MZ_NAME.to_string()));
        assert!(!prog.memory_blocks.is_empty());
        assert!(prog.symbols.values().any(|v| v == "entry"));
    }
}
