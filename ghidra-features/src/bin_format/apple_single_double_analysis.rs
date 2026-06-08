//! AppleSingle/Double binary analysis command ported from Ghidra's
//! `ghidra.app.cmd.formats.AppleSingleDoubleBinaryAnalysisCommand`.
//!
//! Provides [`AppleSingleDoubleAnalysisCommand`] which analyzes an AppleSingle or
//! AppleDouble file and produces [`ProgramMarkup`] entries for:
//! - File header (magic, version, filler, entry count)
//! - Entry descriptors (data fork, resource fork, Finder info, etc.)
//! - Entry data regions
//!
//! AppleSingle files combine data fork + resource fork + metadata into one file.
//! AppleDouble files store only the resource fork + metadata (data fork is separate).
//!
//! This implementation works on raw binary data and generates markup descriptors
//! rather than directly mutating a Ghidra Program.

use super::analysis_command::{
    BinaryAnalysisCommand, CommentType, FragmentEntry, LabelEntry, MarkupEntry, MessageLog,
    ProgramMarkup, SourceType,
};
use super::binary_reader::BinaryReader;
use super::types::DataTypeDescription;

// ---------------------------------------------------------------------------
// AppleSingle/Double Constants
// ---------------------------------------------------------------------------

/// AppleSingle magic number: 0x00051600.
pub const APPLE_SINGLE_MAGIC: u32 = 0x0005_1600;

/// AppleDouble magic number: 0x00051607.
pub const APPLE_DOUBLE_MAGIC: u32 = 0x0005_1607;

/// AppleSingle/Double header size (4 + 4 + 16 + 2 = 26 bytes).
const ASD_HEADER_SIZE: u64 = 26;

/// Entry descriptor size (4 + 4 + 4 = 12 bytes).
const ENTRY_DESCRIPTOR_SIZE: u64 = 12;

/// Filler field length (16 bytes of zeros).
const FILLER_LENGTH: usize = 16;

// Entry descriptor IDs (from EntryDescriptorID.java)
const ENTRY_DATA_FORK: u32 = 0x1;
const ENTRY_RESOURCE_FORK: u32 = 0x2;
const ENTRY_REAL_NAME: u32 = 0x3;
const ENTRY_COMMENT: u32 = 0x4;
const ENTRY_ICON_BW: u32 = 0x5;
const ENTRY_ICON_COLOR: u32 = 0x6;
const ENTRY_FILE_DATE_INFO: u32 = 0x7;
const ENTRY_FINDER_INFO: u32 = 0x8;
const ENTRY_MAC_FILE_INFO: u32 = 0x9;
const ENTRY_PRODOS_FILE_INFO: u32 = 0xa;
const ENTRY_MSDOS_FILE_INFO: u32 = 0xb;
const ENTRY_SHORT_NAME: u32 = 0xc;
const ENTRY_AFP_FILE_INFO: u32 = 0xd;
const ENTRY_DIRECTORY_ID: u32 = 0xe;

// ---------------------------------------------------------------------------
// Parsed structures
// ---------------------------------------------------------------------------

/// Parsed AppleSingle/Double header.
#[derive(Debug, Clone)]
struct AsdHeader {
    magic: u32,
    version: u32,
    filler: [u8; FILLER_LENGTH],
    entry_count: u16,
}

/// Parsed entry descriptor.
#[derive(Debug, Clone)]
struct EntryDescriptor {
    entry_id: u32,
    offset: u32,
    length: u32,
    file_offset: u64,
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Return a human-readable entry ID name.
fn entry_id_name(entry_id: u32) -> &'static str {
    match entry_id {
        ENTRY_DATA_FORK => "DATA_FORK",
        ENTRY_RESOURCE_FORK => "RESOURCE_FORK",
        ENTRY_REAL_NAME => "REAL_NAME",
        ENTRY_COMMENT => "COMMENT",
        ENTRY_ICON_BW => "ICON_BW",
        ENTRY_ICON_COLOR => "ICON_COLOR",
        ENTRY_FILE_DATE_INFO => "FILE_DATE_INFO",
        ENTRY_FINDER_INFO => "FINDER_INFO",
        ENTRY_MAC_FILE_INFO => "MAC_FILE_INFO",
        ENTRY_PRODOS_FILE_INFO => "PRODOS_FILE_INFO",
        ENTRY_MSDOS_FILE_INFO => "MSDOS_FILE_INFO",
        ENTRY_SHORT_NAME => "SHORT_NAME",
        ENTRY_AFP_FILE_INFO => "AFP_FILE_INFO",
        ENTRY_DIRECTORY_ID => "DIRECTORY_ID",
        _ => "Unknown",
    }
}

/// Return the version name for the AppleSingle/Double version.
fn version_name(version: u32) -> &'static str {
    match version {
        0x0001_0000 => "Version 1.0",
        0x0002_0000 => "Version 2.0",
        _ => "Unknown",
    }
}

// ---------------------------------------------------------------------------
// AppleSingleDoubleAnalysisCommand
// ---------------------------------------------------------------------------

/// AppleSingle/Double binary analysis command.
///
/// Ported from `ghidra.app.cmd.formats.AppleSingleDoubleBinaryAnalysisCommand`.
/// Parses the AppleSingle/Double header, entry descriptors, and entry data regions,
/// and produces a [`ProgramMarkup`].
pub struct AppleSingleDoubleAnalysisCommand {
    messages: MessageLog,
}

impl AppleSingleDoubleAnalysisCommand {
    /// Create a new AppleSingle/Double analysis command.
    pub fn new() -> Self {
        Self {
            messages: MessageLog::new(),
        }
    }

    /// Parse the AppleSingle/Double header.
    fn parse_header(&self, data: &[u8]) -> Result<AsdHeader, String> {
        if data.len() < ASD_HEADER_SIZE as usize {
            return Err("Data too short for AppleSingle/Double header".into());
        }

        let reader = BinaryReader::from_bytes(data, false); // big-endian

        let magic = reader.read_u32_at(0).map_err(|e| format!("magic: {}", e))?;
        let version = reader.read_u32_at(4).map_err(|e| format!("version: {}", e))?;

        let mut filler = [0u8; FILLER_LENGTH];
        filler.copy_from_slice(&data[8..24]);

        let entry_count = reader.read_u16_at(24).map_err(|e| format!("entry_count: {}", e))?;

        Ok(AsdHeader {
            magic,
            version,
            filler,
            entry_count,
        })
    }

    /// Parse entry descriptors.
    fn parse_entry_descriptors(
        &self,
        data: &[u8],
        offset: usize,
        count: usize,
    ) -> Result<Vec<EntryDescriptor>, String> {
        let mut entries = Vec::new();
        let reader = BinaryReader::from_bytes(&data[offset..], false); // big-endian

        for i in 0..count {
            let base = i * ENTRY_DESCRIPTOR_SIZE as usize;
            if offset + base + ENTRY_DESCRIPTOR_SIZE as usize > data.len() {
                return Err(format!("Entry descriptor {} extends beyond data", i));
            }

            let entry_id = reader.read_u32_at(base).map_err(|e| format!("entry_id[{}]: {}", i, e))?;
            let entry_offset = reader.read_u32_at(base + 4).map_err(|e| format!("offset[{}]: {}", i, e))?;
            let length = reader.read_u32_at(base + 8).map_err(|e| format!("length[{}]: {}", i, e))?;

            entries.push(EntryDescriptor {
                entry_id,
                offset: entry_offset,
                length,
                file_offset: (offset + base) as u64,
            });
        }

        Ok(entries)
    }

    /// Process AppleSingle/Double header markup.
    fn process_header(
        &self,
        markup: &mut ProgramMarkup,
        header: &AsdHeader,
    ) {
        let magic_name = if header.magic == APPLE_SINGLE_MAGIC {
            "AppleSingle"
        } else if header.magic == APPLE_DOUBLE_MAGIC {
            "AppleDouble"
        } else {
            "Unknown"
        };

        let comment = format!(
            "Magic: 0x{:08X} ({})\nVersion: 0x{:08X} ({})\nEntries: {}",
            header.magic,
            magic_name,
            header.version,
            version_name(header.version),
            header.entry_count,
        );

        markup.add_markup(
            MarkupEntry::new(0, DataTypeDescription::Struct {
                name: "AppleSingleDoubleHeader".into(),
                size: ASD_HEADER_SIZE as u32,
            })
            .with_name("AppleSingleDoubleHeader")
            .with_comment(comment, CommentType::Plate),
        );
        markup.add_fragment(FragmentEntry::new(
            "AppleSingleDoubleHeader",
            0,
            ASD_HEADER_SIZE,
        ));
    }

    /// Process entry descriptors markup.
    fn process_entry_descriptors(
        &self,
        markup: &mut ProgramMarkup,
        entries: &[EntryDescriptor],
    ) {
        for entry in entries {
            let name = entry_id_name(entry.entry_id);

            let comment = format!(
                "Entry ID: {} (0x{:04X})\nOffset: 0x{:08X}\nLength: 0x{:08X}",
                name,
                entry.entry_id,
                entry.offset,
                entry.length,
            );

            markup.add_markup(
                MarkupEntry::new(entry.file_offset, DataTypeDescription::Struct {
                    name: "EntryDescriptor".into(),
                    size: ENTRY_DESCRIPTOR_SIZE as u32,
                })
                .with_comment(comment, CommentType::Plate),
            );
            markup.add_fragment(FragmentEntry::new(
                format!("EntryDescriptor_{}", name),
                entry.file_offset,
                ENTRY_DESCRIPTOR_SIZE,
            ));

            // Create fragment for the entry data
            if entry.length > 0 {
                let data_offset = entry.offset as u64;
                let data_name = format!("EntryData_{}", name);
                markup.add_fragment(FragmentEntry::new(
                    &data_name,
                    data_offset,
                    entry.length as u64,
                ));
                markup.add_label(
                    LabelEntry::new(data_offset, &data_name)
                        .with_source(SourceType::Imported),
                );
            }
        }
    }

    /// Process resource fork data markup (if present).
    ///
    /// This marks up the resource fork structure: resource header, resource data,
    /// resource map, and resource type list.
    fn process_resource_fork(
        &self,
        markup: &mut ProgramMarkup,
        entries: &[EntryDescriptor],
        data: &[u8],
    ) -> Result<(), String> {
        // Find the resource fork entry
        let resource_entry = entries.iter().find(|e| e.entry_id == ENTRY_RESOURCE_FORK);
        let resource_entry = match resource_entry {
            Some(e) => e,
            None => return Ok(()),
        };

        if resource_entry.length == 0 {
            return Ok(());
        }

        let res_offset = resource_entry.offset as usize;
        let res_length = resource_entry.length as usize;

        if res_offset + res_length > data.len() {
            self.messages.append_warning("Resource fork extends beyond data");
            return Ok(());
        }

        // Resource fork has the same structure as a standalone resource file:
        // Resource header (16 bytes):
        //   - dataOffset: u32 (offset to resource data from start of resource fork)
        //   - mapOffset: u32 (offset to resource map from start of resource fork)
        //   - dataLength: u32
        //   - mapLength: u32

        if res_length < 16 {
            return Ok(());
        }

        let reader = BinaryReader::from_bytes(&data[res_offset..], false); // big-endian
        let data_offset = reader.read_u32_at(0).map_err(|e| format!("data_offset: {}", e))?;
        let map_offset = reader.read_u32_at(4).map_err(|e| format!("map_offset: {}", e))?;
        let data_length = reader.read_u32_at(8).map_err(|e| format!("data_length: {}", e))?;
        let map_length = reader.read_u32_at(12).map_err(|e| format!("map_length: {}", e))?;

        let header_comment = format!(
            "Resource Header\nData Offset: 0x{:08X}\nMap Offset: 0x{:08X}\nData Length: 0x{:08X}\nMap Length: 0x{:08X}",
            data_offset,
            map_offset,
            data_length,
            map_length,
        );

        markup.add_markup(
            MarkupEntry::new(res_offset as u64, DataTypeDescription::Struct {
                name: "ResourceHeader".into(),
                size: 16,
            })
            .with_comment(header_comment, CommentType::Plate),
        );
        markup.add_fragment(FragmentEntry::new(
            "ResourceHeader",
            res_offset as u64,
            16,
        ));

        // Resource data region
        if data_offset > 0 && data_length > 0 {
            let abs_data_offset = res_offset as u64 + data_offset as u64;
            if abs_data_offset + data_length as u64 <= data.len() as u64 {
                markup.add_fragment(FragmentEntry::new(
                    "ResourceData",
                    abs_data_offset,
                    data_length as u64,
                ));
            }
        }

        // Resource map region
        if map_offset > 0 && map_length > 0 {
            let abs_map_offset = res_offset as u64 + map_offset as u64;
            if abs_map_offset + map_length as u64 <= data.len() as u64 {
                markup.add_fragment(FragmentEntry::new(
                    "ResourceMap",
                    abs_map_offset,
                    map_length as u64,
                ));
            }
        }

        Ok(())
    }
}

impl Default for AppleSingleDoubleAnalysisCommand {
    fn default() -> Self {
        Self::new()
    }
}

impl BinaryAnalysisCommand for AppleSingleDoubleAnalysisCommand {
    fn name(&self) -> &str {
        "Apple Single/Double Header Annotation"
    }

    fn can_apply(&self, data: &[u8]) -> bool {
        if data.len() < 4 {
            return false;
        }
        let magic = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        magic == APPLE_SINGLE_MAGIC || magic == APPLE_DOUBLE_MAGIC
    }

    fn apply(&self, data: &[u8], _is_little_endian: bool) -> Result<ProgramMarkup, String> {
        let mut markup = ProgramMarkup::new();

        // 1. Parse header
        let header = self.parse_header(data)?;

        // Validate magic
        if header.magic != APPLE_SINGLE_MAGIC && header.magic != APPLE_DOUBLE_MAGIC {
            return Err(format!(
                "Not an AppleSingle/Double file: magic=0x{:08X}",
                header.magic
            ));
        }

        self.process_header(&mut markup, &header);

        // 2. Parse entry descriptors
        let entries_offset = ASD_HEADER_SIZE as usize;
        let entries = self.parse_entry_descriptors(data, entries_offset, header.entry_count as usize)?;
        self.process_entry_descriptors(&mut markup, &entries);

        // 3. Process resource fork if present
        self.process_resource_fork(&mut markup, &entries, data)?;

        let file_type = if header.magic == APPLE_SINGLE_MAGIC {
            "AppleSingle"
        } else {
            "AppleDouble"
        };

        self.messages.append_msg(format!(
            "{} analysis complete: {} entries",
            file_type,
            header.entry_count,
        ));

        Ok(markup)
    }

    fn messages(&self) -> &MessageLog {
        &self.messages
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_minimal_apple_single() -> Vec<u8> {
        let mut data = vec![0u8; 512];

        // Magic: AppleSingle = 0x00051600 (big-endian)
        data[0] = 0x00;
        data[1] = 0x05;
        data[2] = 0x16;
        data[3] = 0x00;

        // Version: 0x00010000 (1.0)
        data[4] = 0x00;
        data[5] = 0x01;
        data[6] = 0x00;
        data[7] = 0x00;

        // Filler: 16 bytes of zeros (already zeroed)

        // Number of entries: 2
        data[24] = 0x00;
        data[25] = 0x02;

        // Entry descriptor 0: Data Fork (ID=1, offset=0x100, length=0x80)
        let ed0 = 26;
        data[ed0 + 3] = 0x01; // entry_id = 1
        data[ed0 + 7] = 0x01; // offset = 0x100
        data[ed0 + 11] = 0x80; // length = 0x80

        // Entry descriptor 1: Resource Fork (ID=2, offset=0x200, length=0x40)
        let ed1 = 38;
        data[ed1 + 3] = 0x02; // entry_id = 2
        data[ed1 + 7] = 0x02; // offset = 0x200
        data[ed1 + 11] = 0x40; // length = 0x40

        data
    }

    fn make_minimal_apple_double() -> Vec<u8> {
        let mut data = vec![0u8; 512];

        // Magic: AppleDouble = 0x00051607 (big-endian)
        data[0] = 0x00;
        data[1] = 0x05;
        data[2] = 0x16;
        data[3] = 0x07;

        // Version: 0x00010000 (1.0)
        data[4] = 0x00;
        data[5] = 0x01;
        data[6] = 0x00;
        data[7] = 0x00;

        // Filler: 16 bytes of zeros

        // Number of entries: 1 (resource fork only)
        data[24] = 0x00;
        data[25] = 0x01;

        // Entry descriptor 0: Resource Fork (ID=2, offset=0x100, length=0x40)
        let ed0 = 26;
        data[ed0 + 3] = 0x02; // entry_id = 2
        data[ed0 + 7] = 0x01; // offset = 0x100
        data[ed0 + 11] = 0x40; // length = 0x40

        data
    }

    #[test]
    fn test_apple_single_can_apply() {
        let cmd = AppleSingleDoubleAnalysisCommand::new();
        let data = make_minimal_apple_single();
        assert!(cmd.can_apply(&data));
    }

    #[test]
    fn test_apple_double_can_apply() {
        let cmd = AppleSingleDoubleAnalysisCommand::new();
        let data = make_minimal_apple_double();
        assert!(cmd.can_apply(&data));
    }

    #[test]
    fn test_cannot_apply_elf() {
        let cmd = AppleSingleDoubleAnalysisCommand::new();
        let data = vec![0x7f, b'E', b'L', b'F', 0, 0, 0, 0];
        assert!(!cmd.can_apply(&data));
    }

    #[test]
    fn test_cannot_apply_short() {
        let cmd = AppleSingleDoubleAnalysisCommand::new();
        let data = vec![0x00, 0x05];
        assert!(!cmd.can_apply(&data));
    }

    #[test]
    fn test_parse_header_apple_single() {
        let cmd = AppleSingleDoubleAnalysisCommand::new();
        let data = make_minimal_apple_single();
        let header = cmd.parse_header(&data).unwrap();
        assert_eq!(header.magic, APPLE_SINGLE_MAGIC);
        assert_eq!(header.version, 0x00010000);
        assert_eq!(header.entry_count, 2);
    }

    #[test]
    fn test_parse_header_apple_double() {
        let cmd = AppleSingleDoubleAnalysisCommand::new();
        let data = make_minimal_apple_double();
        let header = cmd.parse_header(&data).unwrap();
        assert_eq!(header.magic, APPLE_DOUBLE_MAGIC);
        assert_eq!(header.entry_count, 1);
    }

    #[test]
    fn test_parse_entry_descriptors() {
        let cmd = AppleSingleDoubleAnalysisCommand::new();
        let data = make_minimal_apple_single();
        let entries = cmd.parse_entry_descriptors(&data, 26, 2).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].entry_id, ENTRY_DATA_FORK);
        assert_eq!(entries[0].offset, 0x100);
        assert_eq!(entries[0].length, 0x80);
        assert_eq!(entries[1].entry_id, ENTRY_RESOURCE_FORK);
        assert_eq!(entries[1].offset, 0x200);
        assert_eq!(entries[1].length, 0x40);
    }

    #[test]
    fn test_apply_apple_single() {
        let cmd = AppleSingleDoubleAnalysisCommand::new();
        let data = make_minimal_apple_single();
        let result = cmd.apply(&data, false);
        assert!(result.is_ok(), "apply failed: {:?}", result.err());

        let markup = result.unwrap();
        assert!(!markup.is_empty());
        // Should have: header + 2 entry descriptors + 2 entry data fragments + 2 labels
        assert!(markup.data_markups.len() >= 3);
        assert!(markup.fragments.len() >= 5); // header + 2 descriptors + 2 data regions
        assert!(markup.labels.len() >= 2);
    }

    #[test]
    fn test_apply_apple_double() {
        let cmd = AppleSingleDoubleAnalysisCommand::new();
        let data = make_minimal_apple_double();
        let result = cmd.apply(&data, false);
        assert!(result.is_ok(), "apply failed: {:?}", result.err());

        let markup = result.unwrap();
        assert!(!markup.is_empty());
        // Should have: header + 1 entry descriptor + 1 entry data fragment + 1 label
        assert!(markup.data_markups.len() >= 2);
        assert!(markup.fragments.len() >= 3);
    }

    #[test]
    fn test_entry_id_names() {
        assert_eq!(entry_id_name(ENTRY_DATA_FORK), "DATA_FORK");
        assert_eq!(entry_id_name(ENTRY_RESOURCE_FORK), "RESOURCE_FORK");
        assert_eq!(entry_id_name(ENTRY_REAL_NAME), "REAL_NAME");
        assert_eq!(entry_id_name(ENTRY_FINDER_INFO), "FINDER_INFO");
        assert_eq!(entry_id_name(0xFF), "Unknown");
    }

    #[test]
    fn test_version_names() {
        assert_eq!(version_name(0x00010000), "Version 1.0");
        assert_eq!(version_name(0x00020000), "Version 2.0");
        assert_eq!(version_name(0x12345678), "Unknown");
    }

    #[test]
    fn test_magic_detection() {
        let cmd = AppleSingleDoubleAnalysisCommand::new();

        // AppleSingle
        assert!(cmd.can_apply(&[0x00, 0x05, 0x16, 0x00]));
        // AppleDouble
        assert!(cmd.can_apply(&[0x00, 0x05, 0x16, 0x07]));
        // Not magic
        assert!(!cmd.can_apply(&[0x00, 0x05, 0x16, 0x01]));
    }
}
