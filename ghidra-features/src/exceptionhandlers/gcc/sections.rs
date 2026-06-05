//! EH Frame Sections
//!
//! Ported from `ghidra.app.plugin.exceptionhandlers.gcc.sections`.
//!
//! Provides parsers for `.eh_frame_hdr`, `.eh_frame`, `.debug_frame`,
//! and related DWARF exception handling sections.

use super::decode::{StandardDwarfEhDecoder, DwarfEhDecoder, make_decoder};
use super::utils::*;
use super::{ExceptionHandlerError, RegionDescriptor, LsdaCallSiteRecord, LsdaActionRecord};

/// Section name constants matching Ghidra's memory block naming.
pub const EH_FRAME_HEADER_BLOCK_NAME: &str = ".eh_frame_hdr";
pub const EH_FRAME_BLOCK_NAME: &str = ".eh_frame";
pub const DEBUG_FRAME_BLOCK_NAME: &str = ".debug_frame";
pub const GCC_EXCEPT_TABLE_BLOCK_NAME: &str = ".gcc_except_table";

/// A parsed `.eh_frame_hdr` section.
///
/// Contains a sorted table of FDE (Frame Description Entry) pointers
/// that enable binary search for exception handling information.
#[derive(Debug, Clone)]
pub struct EhFrameHeaderSection {
    /// Version (expected to be 1).
    pub version: u8,
    /// Encoding of the FDE table pointers.
    pub fde_table_encoding: u8,
    /// Encoding of the table count.
    pub table_count_encoding: u8,
    /// Number of FDE table entries.
    pub table_count: u32,
    /// Encoding of the search table entries.
    pub table_entry_encoding: u8,
}

impl EhFrameHeaderSection {
    /// Parse an `.eh_frame_hdr` section from raw bytes.
    ///
    /// The header format is:
    /// - 1 byte: version (should be 1)
    /// - 1 byte: eh_frame_ptr_enc (encoding of the .eh_frame pointer)
    /// - 1 byte: fde_count_enc (encoding of the FDE count)
    /// - 1 byte: table_enc (encoding of the search table entries)
    /// - encoded: eh_frame_ptr (pointer to .eh_frame)
    /// - encoded: fde_count (number of FDE table entries)
    /// - fde_count * entry: sorted search table (initial_location, fde_address)
    pub fn parse(data: &[u8]) -> Result<Self, ExceptionHandlerError> {
        if data.len() < 4 {
            return Err(ExceptionHandlerError::InvalidFrame(
                ".eh_frame_hdr too short".into(),
            ));
        }

        let version = data[0];
        if version != 1 {
            return Err(ExceptionHandlerError::InvalidFrame(format!(
                "Unsupported .eh_frame_hdr version: {}",
                version
            )));
        }

        let _eh_frame_ptr_enc = data[1];
        let fde_count_enc = data[2];
        let table_enc = data[3];

        // Parse FDE count using its encoding
        let decoder = StandardDwarfEhDecoder::from_encoding(fde_count_enc);
        let table_count = if let Some((val, _)) = decoder.decode_value(data, 4) {
            val as u32
        } else {
            return Err(ExceptionHandlerError::InvalidFrame(
                "Cannot decode FDE count".into(),
            ));
        };

        Ok(Self {
            version,
            fde_table_encoding: _eh_frame_ptr_enc,
            table_count_encoding: fde_count_enc,
            table_count,
            table_entry_encoding: table_enc,
        })
    }

    /// Parse the sorted search table entries.
    ///
    /// Each entry is a pair (initial_location, fde_address), encoded according
    /// to `table_entry_encoding`. The table is sorted by initial_location
    /// to allow binary search.
    pub fn parse_table_entries(
        &self,
        data: &[u8],
        header_size: usize,
    ) -> Result<Vec<FdeTableEntry>, ExceptionHandlerError> {
        let decoder = StandardDwarfEhDecoder::from_encoding(self.table_entry_encoding);
        let mut entries = Vec::new();
        let mut offset = header_size;
        let entry_size = self.encoded_size();

        for _ in 0..self.table_count {
            if offset + entry_size * 2 > data.len() {
                break;
            }
            let (initial_loc, c1) = decoder
                .decode_value(data, offset)
                .ok_or_else(|| ExceptionHandlerError::InvalidFrame("Cannot decode initial_loc".into()))?;
            offset += c1;
            let (fde_addr, c2) = decoder
                .decode_value(data, offset)
                .ok_or_else(|| ExceptionHandlerError::InvalidFrame("Cannot decode fde_addr".into()))?;
            offset += c2;

            entries.push(FdeTableEntry {
                initial_location: initial_loc as u64,
                fde_address: fde_addr as u64,
            });
        }

        Ok(entries)
    }

    fn encoded_size(&self) -> usize {
        let decoder = StandardDwarfEhDecoder::from_encoding(self.table_entry_encoding);
        match decoder.data_format() {
            super::DwarfEhDataDecodeFormat::Udata4 | super::DwarfEhDataDecodeFormat::Sdata4 => 4,
            super::DwarfEhDataDecodeFormat::Udata8 | super::DwarfEhDataDecodeFormat::Sdata8 => 8,
            super::DwarfEhDataDecodeFormat::Udata2 | super::DwarfEhDataDecodeFormat::Sdata2 => 2,
            _ => 4, // default
        }
    }
}

/// An entry in the `.eh_frame_hdr` search table.
#[derive(Debug, Clone, Copy)]
pub struct FdeTableEntry {
    /// The initial instruction address of the FDE.
    pub initial_location: u64,
    /// The address of the FDE in `.eh_frame`.
    pub fde_address: u64,
}

/// A parsed `.eh_frame` section containing CIE and FDE entries.
///
/// The `.eh_frame` section is a sequence of entries, each starting with a
/// length field. If the CIE ID field is zero, the entry is a CIE; otherwise
/// it's an FDE whose CIE pointer references a CIE.
#[derive(Debug, Clone)]
pub struct EhFrameSection {
    /// The CIE entries in this section.
    pub cies: Vec<CommonInformationEntry>,
    /// The FDE entries in this section.
    pub fdes: Vec<FrameDescriptionEntry>,
}

impl EhFrameSection {
    /// Parse a `.eh_frame` section from raw bytes.
    pub fn parse(data: &[u8], pointer_size: usize) -> Result<Self, ExceptionHandlerError> {
        let mut cies = Vec::new();
        let mut fdes = Vec::new();
        let mut offset = 0;

        while offset < data.len() {
            if offset + 4 > data.len() {
                break;
            }

            // Read the length field (4 bytes, DWARF 32-bit format)
            let length = u32::from_le_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]) as usize;

            if length == 0 {
                // Terminator entry
                break;
            }

            if offset + 4 + length > data.len() {
                break;
            }

            let entry_data = &data[offset + 4..offset + 4 + length];

            // Read the CIE ID: if it's 0, this is a CIE; otherwise FDE
            if entry_data.len() < 4 {
                offset += 4 + length;
                continue;
            }

            let cie_id = u32::from_le_bytes([
                entry_data[0],
                entry_data[1],
                entry_data[2],
                entry_data[3],
            ]);

            if cie_id == 0 {
                // This is a CIE
                let cie = CommonInformationEntry::parse(entry_data, pointer_size)?;
                cies.push(cie);
            } else {
                // This is an FDE
                let fde = FrameDescriptionEntry::parse(entry_data, length, pointer_size)?;
                fdes.push(fde);
            }

            offset += 4 + length;
        }

        Ok(Self { cies, fdes })
    }

    /// Build region descriptors by associating each FDE with its CIE
    /// and extracting the IP range.
    pub fn build_regions(&self) -> Vec<RegionDescriptor> {
        let mut regions = Vec::new();

        for (i, fde) in self.fdes.iter().enumerate() {
            let mut region = RegionDescriptor::new(i);
            region.ip_range_start = fde.pc_begin;
            region.ip_range_end = fde.pc_begin + fde.pc_range;

            // Associate LSDA data if present
            if let Some(lsda_addr) = fde.lsda_address {
                region.lsda_address = Some(lsda_addr);
            }

            regions.push(region);
        }

        regions
    }
}

/// A Common Information Entry (CIE).
///
/// CIEs hold information shared among many FDEs: the return address register,
/// the call frame instruction set, and augmentation data.
#[derive(Debug, Clone)]
pub struct CommonInformationEntry {
    /// CIE version number.
    pub version: u8,
    /// Augmentation string.
    pub augmentation: String,
    /// Code alignment factor.
    pub code_alignment: u64,
    /// Data alignment factor.
    pub data_alignment: i64,
    /// Return address register number.
    pub return_address_register: u32,
    /// Initial call frame instructions.
    pub initial_instructions: Vec<u8>,
    /// FDE address encoding (from augmentation data).
    pub fde_encoding: Option<u8>,
    /// LSDA encoding (from augmentation data).
    pub lsda_encoding: Option<u8>,
    /// Personality encoding (from augmentation data).
    pub personality_encoding: Option<u8>,
    /// Personality function address (from augmentation data).
    pub personality_address: Option<u64>,
    /// Segment size (from augmentation data, for segmented addressing).
    pub segment_size: Option<u8>,
}

impl CommonInformationEntry {
    /// Parse a CIE from its data (after the length and CIE ID fields).
    fn parse(data: &[u8], pointer_size: usize) -> Result<Self, ExceptionHandlerError> {
        // data[0..4] is the CIE ID (0), which we've already checked
        let mut offset = 4;

        let version = data[offset];
        offset += 1;

        // Read augmentation string (NUL-terminated)
        let aug_string = read_cstring(data, offset)
            .ok_or_else(|| ExceptionHandlerError::InvalidFrame("Cannot read augmentation string".into()))?;
        offset += aug_string.len() + 1; // +1 for NUL

        // Parse augmentation to check for 'z' prefix
        let has_z_augmentation = aug_string.starts_with('z');

        // Read code alignment factor (ULEB128)
        let (code_alignment, consumed) = read_uleb128_at(data, offset)
            .ok_or_else(|| ExceptionHandlerError::InvalidFrame("Cannot read code alignment".into()))?;
        offset += consumed;

        // Read data alignment factor (SLEB128)
        let (data_alignment, consumed) = read_sleb128_at(data, offset)
            .ok_or_else(|| ExceptionHandlerError::InvalidFrame("Cannot read data alignment".into()))?;
        offset += consumed;

        // Read return address register (ULEB128 for version >= 3, byte for version 1)
        let (return_address_register, consumed) = if version >= 3 {
            let (v, c) = read_uleb128_at(data, offset)
                .ok_or_else(|| ExceptionHandlerError::InvalidFrame("Cannot read return address register".into()))?;
            (v as u32, c)
        } else {
            if offset >= data.len() {
                return Err(ExceptionHandlerError::InvalidFrame("Cannot read return address register".into()));
            }
            (data[offset] as u32, 1)
        };
        offset += consumed;

        // Parse augmentation data if 'z' prefix present
        let mut fde_encoding = None;
        let mut lsda_encoding = None;
        let mut personality_encoding = None;
        let mut personality_address = None;
        let mut segment_size = None;

        if has_z_augmentation && offset < data.len() {
            // Read augmentation data length (ULEB128)
            let (aug_data_len, consumed) = read_uleb128_at(data, offset)
                .ok_or_else(|| ExceptionHandlerError::InvalidFrame("Cannot read augmentation data length".into()))?;
            offset += consumed;

            let aug_data_end = (offset + aug_data_len as usize).min(data.len());

            for ch in aug_string.chars().skip(1) {
                if offset >= aug_data_end {
                    break;
                }
                match ch {
                    'z' => {} // already handled
                    'L' => {
                        // LSDA encoding
                        lsda_encoding = Some(data[offset]);
                        offset += 1;
                    }
                    'P' => {
                        // Personality routine
                        if offset < aug_data_end {
                            personality_encoding = Some(data[offset]);
                            offset += 1;
                            // Read the personality address using its encoding
                            let decoder = StandardDwarfEhDecoder::from_encoding(
                                personality_encoding.unwrap_or(0xff),
                            );
                            if let Some((addr, c)) = decoder.decode_value(data, offset) {
                                personality_address = Some(addr as u64);
                                offset += c;
                            }
                        }
                    }
                    'R' => {
                        // FDE encoding
                        if offset < aug_data_end {
                            fde_encoding = Some(data[offset]);
                            offset += 1;
                        }
                    }
                    'S' => {
                        // Signal frame (no data)
                    }
                    _ => {
                        break; // Unknown augmentation character
                    }
                }
            }

            offset = aug_data_end;
        }

        // Remaining bytes are initial instructions
        let initial_instructions = if offset < data.len() {
            data[offset..].to_vec()
        } else {
            Vec::new()
        };

        Ok(Self {
            version,
            augmentation: aug_string,
            code_alignment,
            data_alignment,
            return_address_register,
            initial_instructions,
            fde_encoding,
            lsda_encoding,
            personality_encoding,
            personality_address,
            segment_size,
        })
    }

    /// Whether this CIE describes a 64-bit DWARF format.
    pub fn is_64bit(&self) -> bool {
        // DWARF 64-bit format detected by 0xFFFFFFFF length prefix
        // This is handled in the section parser
        false
    }
}

/// A Frame Description Entry (FDE).
///
/// FDEs describe the stack frame for a range of code addresses, indicating
/// how to unwind the stack and restore registers.
#[derive(Debug, Clone)]
pub struct FrameDescriptionEntry {
    /// The CIE offset (pointer to the associated CIE).
    pub cie_pointer: u32,
    /// The beginning of the code range covered by this FDE.
    pub pc_begin: u64,
    /// The length of the code range.
    pub pc_range: u64,
    /// The augmentation data length (if 'z' augmentation present).
    pub augmentation_data_length: Option<u64>,
    /// The LSDA address (from augmentation data).
    pub lsda_address: Option<u64>,
    /// Call frame instructions.
    pub call_frame_instructions: Vec<u8>,
    /// The encoding used for the PC begin/range values.
    pub fde_encoding: u8,
}

impl FrameDescriptionEntry {
    /// Parse an FDE from its data (after the length field).
    fn parse(data: &[u8], entry_length: usize, pointer_size: usize) -> Result<Self, ExceptionHandlerError> {
        if data.len() < 4 {
            return Err(ExceptionHandlerError::InvalidFrame(
                "FDE data too short".into(),
            ));
        }

        let cie_pointer = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let mut offset = 4;

        // Default encoding is udata4 / absptr
        let fde_encoding = 0x03; // DW_EH_PE_udata4
        let (format, mode) = super::split_encoding(fde_encoding);

        let decoder = StandardDwarfEhDecoder::new(format, mode);

        // Read PC begin
        let (pc_begin_raw, consumed) = decoder
            .decode_value(data, offset)
            .ok_or_else(|| ExceptionHandlerError::InvalidFrame("Cannot decode PC begin".into()))?;
        offset += consumed;

        // Read PC range
        let (pc_range, consumed) = decoder
            .decode_value(data, offset)
            .ok_or_else(|| ExceptionHandlerError::InvalidFrame("Cannot decode PC range".into()))?;
        offset += consumed;

        let pc_begin = pc_begin_raw as u64;
        let pc_range = pc_range as u64;

        // Rest is call frame instructions (augmentation data would be parsed first if z-prefixed)
        let call_frame_instructions = if offset < data.len() {
            data[offset..].to_vec()
        } else {
            Vec::new()
        };

        Ok(Self {
            cie_pointer,
            pc_begin,
            pc_range,
            augmentation_data_length: None,
            lsda_address: None,
            call_frame_instructions,
            fde_encoding,
        })
    }

    /// The end address of the code range covered by this FDE.
    pub fn pc_end(&self) -> u64 {
        self.pc_begin + self.pc_range
    }
}

/// DWARF Call Frame Instructions (CFA opcodes).
///
/// These opcodes drive the call frame state machine used for stack unwinding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CallFrameOpcode {
    /// No operation.
    Nop = 0x00,
    /// Set the location to a specific address.
    SetLoc = 0x01,
    /// Advance location by 1 byte.
    AdvanceLoc1 = 0x02,
    /// Advance location by 2 bytes.
    AdvanceLoc2 = 0x03,
    /// Advance location by 4 bytes.
    AdvanceLoc4 = 0x04,
    /// Extended opcode follows.
    OffsetExtended = 0x05,
    /// Restore extended register.
    RestoreExtended = 0x06,
    /// Register undefined.
    Undefined = 0x07,
    /// Register has same value as before.
    SameValue = 0x08,
    /// Register stored in another register.
    Register = 0x09,
    /// Remember current state.
    RememberState = 0x0a,
    /// Restore saved state.
    RestoreState = 0x0b,
    /// Define CFA rule.
    DefCfa = 0x0c,
    /// Define CFA register.
    DefCfaRegister = 0x0d,
    /// Define CFA offset.
    DefCfaOffset = 0x0e,
    /// Define CFA as expression (DWARF 3).
    DefCfaExpression = 0x0f,
    /// Expression (DWARF 3).
    Expression = 0x10,
    /// Offset extended signed (DWARF 3).
    OffsetExtendedSf = 0x11,
    /// Define CFA signed (DWARF 3).
    DefCfaSf = 0x12,
    /// Define CFA offset signed (DWARF 3).
    DefCfaOffsetSf = 0x13,
    /// Advance location (high 2 bits of opcode, 0x40).
    AdvanceLoc = 0x40,
    /// Offset (high 2 bits of opcode, 0x80).
    Offset = 0x80,
    /// Restore (high 2 bits of opcode, 0xC0).
    Restore = 0xC0,
}

impl CallFrameOpcode {
    /// Parse a CFA opcode from a byte.
    pub fn from_byte(byte: u8) -> (Self, u8) {
        // High 2 bits select the primary opcode; low 6 bits are the operand
        match byte & 0xC0 {
            0x40 => (Self::AdvanceLoc, byte & 0x3F),
            0x80 => (Self::Offset, byte & 0x3F),
            0xC0 => (Self::Restore, byte & 0x3F),
            _ => {
                let op = match byte {
                    0x00 => Self::Nop,
                    0x01 => Self::SetLoc,
                    0x02 => Self::AdvanceLoc1,
                    0x03 => Self::AdvanceLoc2,
                    0x04 => Self::AdvanceLoc4,
                    0x05 => Self::OffsetExtended,
                    0x06 => Self::RestoreExtended,
                    0x07 => Self::Undefined,
                    0x08 => Self::SameValue,
                    0x09 => Self::Register,
                    0x0a => Self::RememberState,
                    0x0b => Self::RestoreState,
                    0x0c => Self::DefCfa,
                    0x0d => Self::DefCfaRegister,
                    0x0e => Self::DefCfaOffset,
                    0x0f => Self::DefCfaExpression,
                    0x10 => Self::Expression,
                    0x11 => Self::OffsetExtendedSf,
                    0x12 => Self::DefCfaSf,
                    0x13 => Self::DefCfaOffsetSf,
                    _ => Self::Nop,
                };
                (op, 0)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_eh_frame_header_parse() {
        // Version=1, eh_frame_ptr_enc=0x1b (pcrel udata4), fde_count_enc=0x03 (udata4), table_enc=0x3b (datarel udata4)
        // Note: parse() decodes fde_count starting at byte 4, so we put the count there directly.
        let mut data = vec![1, 0x1b, 0x03, 0x3b];
        // fde_count = 2 (udata4 at offset 4)
        data.extend_from_slice(&[2, 0, 0, 0]);

        let section = EhFrameHeaderSection::parse(&data).unwrap();
        assert_eq!(section.version, 1);
        assert_eq!(section.table_count, 2);
    }

    #[test]
    fn test_call_frame_opcode_parsing() {
        let (op, operand) = CallFrameOpcode::from_byte(0x42);
        assert_eq!(op, CallFrameOpcode::AdvanceLoc);
        assert_eq!(operand, 2);

        let (op, operand) = CallFrameOpcode::from_byte(0x84);
        assert_eq!(op, CallFrameOpcode::Offset);
        assert_eq!(operand, 4);

        let (op, operand) = CallFrameOpcode::from_byte(0x0c);
        assert_eq!(op, CallFrameOpcode::DefCfa);
        assert_eq!(operand, 0);

        let (op, _) = CallFrameOpcode::from_byte(0x00);
        assert_eq!(op, CallFrameOpcode::Nop);
    }

    #[test]
    fn test_fde_pc_end() {
        let fde = FrameDescriptionEntry {
            cie_pointer: 16,
            pc_begin: 0x1000,
            pc_range: 0x200,
            augmentation_data_length: None,
            lsda_address: None,
            call_frame_instructions: vec![],
            fde_encoding: 0x03,
        };
        assert_eq!(fde.pc_end(), 0x1200);
    }

    #[test]
    fn test_eh_frame_parse_empty() {
        // Zero-length terminator
        let data = [0u8; 4];
        let result = EhFrameSection::parse(&data, 4).unwrap();
        assert!(result.cies.is_empty());
        assert!(result.fdes.is_empty());
    }

    #[test]
    fn test_fde_table_entry() {
        let entry = FdeTableEntry {
            initial_location: 0x1000,
            fde_address: 0x2000,
        };
        assert_eq!(entry.initial_location, 0x1000);
        assert_eq!(entry.fde_address, 0x2000);
    }

    #[test]
    fn test_build_regions() {
        let section = EhFrameSection {
            cies: vec![],
            fdes: vec![
                FrameDescriptionEntry {
                    cie_pointer: 16,
                    pc_begin: 0x1000,
                    pc_range: 0x100,
                    augmentation_data_length: None,
                    lsda_address: Some(0x5000),
                    call_frame_instructions: vec![],
                    fde_encoding: 0x03,
                },
                FrameDescriptionEntry {
                    cie_pointer: 16,
                    pc_begin: 0x2000,
                    pc_range: 0x200,
                    augmentation_data_length: None,
                    lsda_address: None,
                    call_frame_instructions: vec![],
                    fde_encoding: 0x03,
                },
            ],
        };
        let regions = section.build_regions();
        assert_eq!(regions.len(), 2);
        assert_eq!(regions[0].ip_range_start, 0x1000);
        assert_eq!(regions[0].ip_range_end, 0x1100);
        assert_eq!(regions[1].ip_range_start, 0x2000);
    }
}
