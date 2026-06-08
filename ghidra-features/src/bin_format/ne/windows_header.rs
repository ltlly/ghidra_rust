//! NE Windows Header ported from Ghidra's
//! `ghidra.app.util.bin.format.ne.WindowsHeader`.
//!
//! Orchestrates parsing of all NE header sub-structures.

use std::fmt;
use std::io;

use crate::bin_format::binary_reader::BinaryReader;

use super::entry_table::EntryTable;
use super::information_block::InformationBlock;
use super::resource_table::ResourceTable;
use super::segment::SegmentTable;
use super::{
    ImportedNameTable, InvalidWindowsHeaderError, ModuleReferenceTable, NonResidentNameTable,
    ResidentNameTable,
};

// ---------------------------------------------------------------------------
// WindowsHeader
// ---------------------------------------------------------------------------

/// The Windows NE header, which orchestrates parsing of all sub-tables.
///
/// Ported from `ghidra.app.util.bin.format.ne.WindowsHeader`.
/// This is the main entry point for parsing an NE executable's header
/// structures after the DOS header has been read.
#[derive(Debug)]
pub struct WindowsHeader {
    info_block: InformationBlock,
    seg_table: SegmentTable,
    rsrc_table: Option<ResourceTable>,
    res_name_table: ResidentNameTable,
    mod_ref_table: ModuleReferenceTable,
    imp_name_table: ImportedNameTable,
    entry_table: EntryTable,
    non_res_name_table: NonResidentNameTable,
}

impl WindowsHeader {
    /// Parse the Windows NE header from the reader.
    ///
    /// `index` is the byte offset where the NE header begins (typically
    /// the value from `DOSHeader.e_lfanew`).
    pub fn parse(
        reader: &mut BinaryReader,
        index: u64,
    ) -> Result<Self, InvalidWindowsHeaderError> {
        let info_block = InformationBlock::parse(reader, index)?;

        // Parse segment table
        let seg_table_index = info_block.segment_table_offset() as u64 + index;
        let seg_table = SegmentTable::parse(
            reader,
            seg_table_index,
            info_block.segment_count(),
            info_block.segment_alignment_shift_count(),
            0, // base segment = 0 for standalone parsing
        )
        .map_err(|_| InvalidWindowsHeaderError)?;

        // Parse resource table (only if offset differs from resident name table)
        let rsrc_table = if info_block.resource_table_offset()
            != info_block.resident_name_table_offset()
        {
            let rsrc_index = info_block.resource_table_offset() as u64 + index;
            match ResourceTable::parse(reader, rsrc_index) {
                Ok(rt) => Some(rt),
                Err(_) => None,
            }
        } else {
            None
        };

        // Parse resident name table
        let res_name_index = info_block.resident_name_table_offset() as u64 + index;
        let res_name_table = ResidentNameTable::parse(reader, res_name_index)
            .map_err(|_| InvalidWindowsHeaderError)?;

        // Parse imported name table
        let imp_name_index = info_block.imported_names_table_offset() as u64 + index;
        let imp_name_table = ImportedNameTable::new(imp_name_index);

        // Parse module reference table
        let mod_ref_index = info_block.module_reference_table_offset() as u64 + index;
        let mod_ref_table = ModuleReferenceTable::parse(
            reader,
            mod_ref_index,
            info_block.module_reference_table_count(),
            &imp_name_table,
        )
        .map_err(|_| InvalidWindowsHeaderError)?;

        // Parse entry table
        let entry_table_index = info_block.entry_table_offset() as u64 + index;
        let entry_table =
            EntryTable::parse(reader, entry_table_index, info_block.entry_table_size())
                .map_err(|_| InvalidWindowsHeaderError)?;

        // Parse non-resident name table
        let non_res_offset = info_block.non_resident_name_table_offset() as u64;
        let non_res_size = info_block.non_resident_name_table_size();
        let non_res_name_table =
            NonResidentNameTable::parse(reader, non_res_offset, non_res_size)
                .map_err(|_| InvalidWindowsHeaderError)?;

        Ok(Self {
            info_block,
            seg_table,
            rsrc_table,
            res_name_table,
            mod_ref_table,
            imp_name_table,
            entry_table,
            non_res_name_table,
        })
    }

    /// Returns the information block.
    pub fn information_block(&self) -> &InformationBlock {
        &self.info_block
    }

    /// Returns the segment table.
    pub fn segment_table(&self) -> &SegmentTable {
        &self.seg_table
    }

    /// Returns the resource table, if present.
    pub fn resource_table(&self) -> Option<&ResourceTable> {
        self.rsrc_table.as_ref()
    }

    /// Returns the resident name table.
    pub fn resident_name_table(&self) -> &ResidentNameTable {
        &self.res_name_table
    }

    /// Returns the module reference table.
    pub fn module_reference_table(&self) -> &ModuleReferenceTable {
        &self.mod_ref_table
    }

    /// Returns the imported name table.
    pub fn imported_name_table(&self) -> &ImportedNameTable {
        &self.imp_name_table
    }

    /// Returns the entry table.
    pub fn entry_table(&self) -> &EntryTable {
        &self.entry_table
    }

    /// Returns the non-resident name table.
    pub fn non_resident_name_table(&self) -> &NonResidentNameTable {
        &self.non_res_name_table
    }

    /// Returns the processor name (hardcoded to "x86" for NE files).
    pub fn processor_name(&self) -> &str {
        "x86"
    }
}

impl fmt::Display for WindowsHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "WindowsHeader {{ {}, segments={}, entries={}, modules={} }}",
            self.info_block,
            self.seg_table.segments().len(),
            self.entry_table.total_entry_count(),
            self.mod_ref_table.names().len()
        )
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ne_header_bytes() -> Vec<u8> {
        // Build a minimal NE file: DOS header + NE header
        let mut data = vec![0u8; 512];

        // DOS header
        data[0] = 0x4D;
        data[1] = 0x5A; // MZ signature
        data[24] = 0x40; // e_lfarlc
        // e_lfanew = 0x80 (NE header starts at offset 0x80)
        data[60] = 0x80;

        // NE header starts at 0x80
        let base = 0x80;

        // ne_magic = 0x454E
        data[base] = 0x4E;
        data[base + 1] = 0x45;

        // ne_ver=1, ne_rev=0
        data[base + 2] = 1;
        data[base + 3] = 0;

        // ne_enttab = 0x0000 (no entry table)
        data[base + 4] = 0x00;
        data[base + 5] = 0x00;

        // ne_cbenttab = 0
        data[base + 6] = 0x00;
        data[base + 7] = 0x00;

        // ne_crc = 0
        // ne_flags = single data
        data[base + 12] = 0x01;

        // ne_autodata = 1
        data[base + 14] = 0x01;

        // ne_cseg = 0 (no segments)
        data[base + 28] = 0x00;

        // ne_cmod = 0 (no module references)
        data[base + 30] = 0x00;

        // ne_segtab = base+64 (right after the header)
        data[base + 34] = (base + 64) as u8;

        // ne_rsrctab = 0 (no resources, same as restab)
        data[base + 36] = 0x00;

        // ne_restab = base+64 (resident name table at same place)
        data[base + 38] = (base + 64) as u8;

        // ne_modtab = base+64
        data[base + 40] = (base + 64) as u8;

        // ne_imptab = base+64
        data[base + 42] = (base + 64) as u8;

        // ne_nrestab = 0 (non-resident table at file offset 0)
        data[base + 44] = 0x00;

        // ne_align = 0
        data[base + 50] = 0x00;

        // ne_exetyp = 0x02 (Windows)
        data[base + 54] = 0x02;

        // At base+64: empty tables (terminators)
        // Resident name table terminator
        let table_start = base + 64;
        data[table_start] = 0; // empty length = terminator

        // Entry table terminator
        data[table_start] = 0;

        data
    }

    #[test]
    fn test_windows_header_parse_invalid() {
        // Test that parsing with invalid NE header returns error
        let data = vec![0u8; 256];
        let mut reader = BinaryReader::from_bytes(&data, true);
        let result = WindowsHeader::parse(&mut reader, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_windows_header_error_display() {
        let err = InvalidWindowsHeaderError;
        assert_eq!(format!("{}", err), "Invalid Windows NE header");
    }
}
