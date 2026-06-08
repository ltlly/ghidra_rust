//! GCC/DWARF Exception Handling
//!
//! Ported from `ghidra.app.plugin.exceptionhandlers.gcc`.
//!
//! Provides structures and analysis for GCC's exception handling mechanism:
//! - DWARF exception handling data encoding formats
//! - `.eh_frame` / `.debug_frame` sections (CIE, FDE)
//! - `.gcc_except_table` LSDA structures
//! - The `GccExceptionAnalyzer` that marks up try/catch regions

use thiserror::Error;

pub mod analyzer;
pub mod datatype;
pub mod decode;
pub mod sections;
pub mod structures;
pub mod utils;

/// Errors specific to GCC exception handling analysis.
#[derive(Debug, Error)]
pub enum ExceptionHandlerError {
    #[error("Memory access error at {0}")]
    MemoryAccess(String),

    #[error("Invalid frame data: {0}")]
    InvalidFrame(String),

    #[error("Analysis cancelled")]
    Cancelled,

    #[error("DWARF decode error: {0}")]
    DecodeError(String),

    #[error("Address out of bounds: {0}")]
    AddressOutOfBounds(String),
}

/// DWARF Exception Handling Data Decode Format.
///
/// See the Linux Standard Base DWARF extensions specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DwarfEhDataDecodeFormat {
    /// Absolute pointer
    Absptr = 0x00,
    /// Unsigned LEB128
    Uleb128 = 0x01,
    /// Unsigned 2-byte
    Udata2 = 0x02,
    /// Unsigned 4-byte
    Udata4 = 0x03,
    /// Unsigned 8-byte
    Udata8 = 0x04,
    /// Signed flag
    Signed = 0x08,
    /// Signed LEB128
    Sleb128 = 0x09,
    /// Signed 2-byte
    Sdata2 = 0x0a,
    /// Signed 4-byte
    Sdata4 = 0x0b,
    /// Signed 8-byte
    Sdata8 = 0x0c,
    /// Omitted
    Omit = 0x0f,
}

impl DwarfEhDataDecodeFormat {
    /// Parse a decode format from its code value.
    pub fn from_code(code: u8) -> Option<Self> {
        match code {
            0x00 => Some(Self::Absptr),
            0x01 => Some(Self::Uleb128),
            0x02 => Some(Self::Udata2),
            0x03 => Some(Self::Udata4),
            0x04 => Some(Self::Udata8),
            0x08 => Some(Self::Signed),
            0x09 => Some(Self::Sleb128),
            0x0a => Some(Self::Sdata2),
            0x0b => Some(Self::Sdata4),
            0x0c => Some(Self::Sdata8),
            0x0f => Some(Self::Omit),
            _ => None,
        }
    }

    /// Whether this format is signed.
    pub fn is_signed(&self) -> bool {
        matches!(
            self,
            Self::Signed | Self::Sleb128 | Self::Sdata2 | Self::Sdata4 | Self::Sdata8
        )
    }

    /// The byte size of the encoded data (0 for LEB128/omit).
    pub fn byte_size(&self) -> usize {
        match self {
            Self::Absptr => 0, // depends on pointer size
            Self::Uleb128 | Self::Sleb128 => 0, // variable
            Self::Udata2 | Self::Sdata2 => 2,
            Self::Udata4 | Self::Sdata4 => 4,
            Self::Udata8 | Self::Sdata8 => 8,
            Self::Signed | Self::Omit => 0,
        }
    }
}

/// DWARF Exception Handling Data Application Mode.
///
/// See the Linux Standard Base DWARF extensions specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DwarfEhDataApplicationMode {
    /// Absolute pointer
    Absptr = 0x00,
    /// PC-relative
    Pcrel = 0x10,
    /// Text-relative
    Textrel = 0x20,
    /// Data-relative
    Datarel = 0x30,
    /// Function-relative
    Funcrel = 0x40,
    /// Aligned
    Aligned = 0x50,
    /// Indirect (value is address of actual pointer)
    Indirect = 0x80,
    /// Omitted
    Omit = 0xf0,
}

impl DwarfEhDataApplicationMode {
    /// Parse an application mode from its code value.
    pub fn from_code(code: u8) -> Option<Self> {
        match code {
            0x00 => Some(Self::Absptr),
            0x10 => Some(Self::Pcrel),
            0x20 => Some(Self::Textrel),
            0x30 => Some(Self::Datarel),
            0x40 => Some(Self::Funcrel),
            0x50 => Some(Self::Aligned),
            0x80 => Some(Self::Indirect),
            0xf0 => Some(Self::Omit),
            _ => None,
        }
    }
}

/// The low 2 bits of a DWARF encoding byte select the decode format;
/// bits [4..7] select the application mode.
pub fn split_encoding(encoding: u8) -> (DwarfEhDataDecodeFormat, DwarfEhDataApplicationMode) {
    let format_code = encoding & 0x0f;
    let mode_code = encoding & 0xf0;
    let format = DwarfEhDataDecodeFormat::from_code(format_code)
        .unwrap_or(DwarfEhDataDecodeFormat::Omit);
    let mode = DwarfEhDataApplicationMode::from_code(mode_code)
        .unwrap_or(DwarfEhDataApplicationMode::Omit);
    (format, mode)
}

/// Placeholder for a decode context that carries program, address, and block info.
#[derive(Debug, Clone)]
pub struct DwarfDecodeContext {
    /// The program being analyzed.
    pub program_name: String,
    /// The current decode offset.
    pub offset: u64,
    /// Memory block name for the section being decoded.
    pub block_name: String,
}

impl DwarfDecodeContext {
    pub fn new(program_name: &str, offset: u64, block_name: &str) -> Self {
        Self {
            program_name: program_name.to_string(),
            offset,
            block_name: block_name.to_string(),
        }
    }
}

/// Region descriptor holds information about a call frame region.
///
/// Associates an FDE with its LSDA tables and the IP range it covers.
#[derive(Debug, Clone)]
pub struct RegionDescriptor {
    /// The LSDA table address (if present).
    pub lsda_address: Option<u64>,
    /// The IP (instruction pointer) range covered by this region.
    pub ip_range_start: u64,
    /// End of the IP range.
    pub ip_range_end: u64,
    /// The LSDA call site records for this region.
    pub call_site_records: Vec<LsdaCallSiteRecord>,
    /// The LSDA action records for this region.
    pub action_records: Vec<LsdaActionRecord>,
    /// The LSDA type table entries for this region.
    pub type_table: Vec<u64>,
    /// The FDE index.
    pub fde_index: usize,
}

impl RegionDescriptor {
    /// Create a new empty region descriptor.
    pub fn new(fde_index: usize) -> Self {
        Self {
            lsda_address: None,
            ip_range_start: 0,
            ip_range_end: 0,
            call_site_records: Vec::new(),
            action_records: Vec::new(),
            type_table: Vec::new(),
            fde_index,
        }
    }

    /// The IP range length.
    pub fn range_length(&self) -> u64 {
        self.ip_range_end.saturating_sub(self.ip_range_start)
    }
}

/// An LSDA call site record defines the bounds of a try-catch region.
#[derive(Debug, Clone)]
pub struct LsdaCallSiteRecord {
    /// Offset of the call site start from the LPStart.
    pub call_site_start: u64,
    /// Length of the call site range.
    pub call_site_length: u64,
    /// Offset of the landing pad from the LPStart (0 means no landing pad).
    pub landing_pad_offset: u64,
    /// Offset into the action table (0 means cleanup only).
    pub action_offset: u32,
}

impl LsdaCallSiteRecord {
    /// Whether this call site has a landing pad (i.e., is a try-catch region).
    pub fn has_landing_pad(&self) -> bool {
        self.landing_pad_offset != 0
    }

    /// The absolute call site start address given the LPStart base.
    pub fn call_site_base(&self, lp_start: u64) -> u64 {
        lp_start + self.call_site_start
    }

    /// The absolute landing pad address given the LPStart base.
    pub fn landing_pad(&self, lp_start: u64) -> u64 {
        lp_start + self.landing_pad_offset
    }
}

/// An LSDA action record associates type info with a catch action.
#[derive(Debug, Clone)]
pub struct LsdaActionRecord {
    /// The type filter value (0 = cleanup, positive = type table index).
    pub type_filter: i32,
    /// Displacement to the next action record (0 = last).
    pub next_displacement: i32,
}

impl LsdaActionRecord {
    /// Whether this is a cleanup-only action (filter == 0).
    pub fn is_cleanup(&self) -> bool {
        self.type_filter == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_format_from_code() {
        assert_eq!(
            DwarfEhDataDecodeFormat::from_code(0x00),
            Some(DwarfEhDataDecodeFormat::Absptr)
        );
        assert_eq!(
            DwarfEhDataDecodeFormat::from_code(0x03),
            Some(DwarfEhDataDecodeFormat::Udata4)
        );
        assert_eq!(
            DwarfEhDataDecodeFormat::from_code(0x0b),
            Some(DwarfEhDataDecodeFormat::Sdata4)
        );
        assert_eq!(DwarfEhDataDecodeFormat::from_code(0xff), None);
    }

    #[test]
    fn test_application_mode_from_code() {
        assert_eq!(
            DwarfEhDataApplicationMode::from_code(0x00),
            Some(DwarfEhDataApplicationMode::Absptr)
        );
        assert_eq!(
            DwarfEhDataApplicationMode::from_code(0x10),
            Some(DwarfEhDataApplicationMode::Pcrel)
        );
        assert_eq!(
            DwarfEhDataApplicationMode::from_code(0x30),
            Some(DwarfEhDataApplicationMode::Datarel)
        );
    }

    #[test]
    fn test_split_encoding() {
        // DW_EH_PE_udata4 | DW_EH_PE_pcrel = 0x13
        let (format, mode) = split_encoding(0x13);
        assert_eq!(format, DwarfEhDataDecodeFormat::Udata4);
        assert_eq!(mode, DwarfEhDataApplicationMode::Pcrel);

        // DW_EH_PE_absptr | DW_EH_PE_absptr = 0x00
        let (format, mode) = split_encoding(0x00);
        assert_eq!(format, DwarfEhDataDecodeFormat::Absptr);
        assert_eq!(mode, DwarfEhDataApplicationMode::Absptr);
    }

    #[test]
    fn test_is_signed() {
        assert!(!DwarfEhDataDecodeFormat::Udata4.is_signed());
        assert!(DwarfEhDataDecodeFormat::Sdata4.is_signed());
        assert!(DwarfEhDataDecodeFormat::Sleb128.is_signed());
    }

    #[test]
    fn test_region_descriptor() {
        let mut region = RegionDescriptor::new(0);
        region.ip_range_start = 0x1000;
        region.ip_range_end = 0x2000;
        assert_eq!(region.range_length(), 0x1000);
    }

    #[test]
    fn test_call_site_record() {
        let csr = LsdaCallSiteRecord {
            call_site_start: 0x100,
            call_site_length: 0x20,
            landing_pad_offset: 0x400,
            action_offset: 4,
        };
        assert!(csr.has_landing_pad());
        assert_eq!(csr.call_site_base(0x1000), 0x1100);
        assert_eq!(csr.landing_pad(0x1000), 0x1400);
    }

    #[test]
    fn test_action_record() {
        let cleanup = LsdaActionRecord {
            type_filter: 0,
            next_displacement: 0,
        };
        assert!(cleanup.is_cleanup());

        let catch_action = LsdaActionRecord {
            type_filter: 2,
            next_displacement: 8,
        };
        assert!(!catch_action.is_cleanup());
    }
}
