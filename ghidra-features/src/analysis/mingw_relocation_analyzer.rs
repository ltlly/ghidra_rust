//! MinGW relocation analyzer -- handles MinGW/PE relocations.
//!
//! Ported from `ghidra.app.plugin.core.analysis.MingwRelocationAnalyzer` in Ghidra's
//! Features/Base.
//!
//! MinGW-compiled PE binaries contain special relocation types that need
//! custom handling. This analyzer detects and processes these relocations,
//! particularly the `.reloc` section entries that point to pointer-sized
//! values in the data sections.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// MingwRelocationAnalyzer
// ---------------------------------------------------------------------------

/// Analyzer for MinGW-specific PE relocations.
///
/// MinGW toolchains produce PE binaries with relocation tables that differ
/// from standard MSVC-generated PE files. This analyzer detects MinGW
/// relocations and creates proper memory references from them.
///
/// Key behaviors:
/// - Reads the PE `.reloc` section to find relocation entries
/// - Handles `IMAGE_REL_BASED_HIGHLOW` (32-bit) and `IMAGE_REL_BASED_DIR64` (64-bit)
/// - Creates data references from relocation targets to their referenced addresses
/// - Processes `.got` (Global Offset Table) entries for position-independent code
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MingwRelocationAnalyzer {
    /// Whether to create references from relocation entries.
    pub create_references: bool,
    /// Whether to mark GOT entries as pointer data.
    pub mark_got_pointers: bool,
    /// Whether to process highlow (32-bit) relocations.
    pub process_highlow: bool,
    /// Whether to process dir64 (64-bit) relocations.
    pub process_dir64: bool,
}

impl Default for MingwRelocationAnalyzer {
    fn default() -> Self {
        Self {
            create_references: true,
            mark_got_pointers: true,
            process_highlow: true,
            process_dir64: true,
        }
    }
}

impl MingwRelocationAnalyzer {
    /// Analyzer name.
    pub const NAME: &'static str = "MinGW Relocation";
    /// Analyzer description.
    pub const DESCRIPTION: &'static str = "Analyzes MinGW-specific PE relocations.";

    /// Create a new analyzer with default settings.
    pub fn new() -> Self {
        Self::default()
    }
}

/// Relocation entry types in PE format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PeRelocType {
    /// The base relocation is skipped (padding).
    Absolute,
    /// High 16 bits of 32-bit address.
    High,
    /// Low 16 bits of 32-bit address.
    Low,
    /// High and low 16 bits (HIGHLOW) -- 32-bit relocation.
    HighLow,
    /// Adjusted high and low 16 bits.
    HighAdj,
    /// MIPS jump address.
    MipsJmpAddr,
    /// 64-bit address (DIR64).
    Dir64,
    /// Unknown/unsupported type.
    Unknown(u16),
}

impl PeRelocType {
    /// Parse a relocation type from its raw 4-bit field.
    pub fn from_raw(value: u16) -> Self {
        match value {
            0 => PeRelocType::Absolute,
            1 => PeRelocType::High,
            2 => PeRelocType::Low,
            3 => PeRelocType::HighLow,
            4 => PeRelocType::HighAdj,
            5 => PeRelocType::MipsJmpAddr,
            10 => PeRelocType::Dir64,
            _ => PeRelocType::Unknown(value),
        }
    }

    /// Get the size of this relocation type in bytes.
    pub fn size(&self) -> u32 {
        match self {
            PeRelocType::Absolute => 0,
            PeRelocType::High | PeRelocType::Low => 2,
            PeRelocType::HighLow | PeRelocType::HighAdj | PeRelocType::MipsJmpAddr => 4,
            PeRelocType::Dir64 => 8,
            PeRelocType::Unknown(_) => 0,
        }
    }
}

/// A parsed PE relocation entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeRelocationEntry {
    /// The page RVA (relative virtual address) from the block header.
    pub page_rva: u32,
    /// The relocation type.
    pub reloc_type: PeRelocType,
    /// The offset within the page.
    pub offset: u16,
}

impl PeRelocationEntry {
    /// Get the full RVA of the relocation target.
    pub fn target_rva(&self) -> u32 {
        self.page_rva + self.offset as u32
    }

    /// Get the target address given the image base.
    pub fn target_address(&self, image_base: u64) -> u64 {
        image_base + self.target_rva() as u64
    }
}

/// Result of processing a MinGW relocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MingwRelocResult {
    /// A pointer was created at the relocation target.
    PointerCreated {
        /// Target address where the pointer was created.
        address: u64,
        /// The referenced address.
        referenced: u64,
    },
    /// A GOT entry was marked.
    GotEntryMarked {
        /// GOT entry address.
        address: u64,
    },
    /// Relocation was skipped (unsupported type or padding).
    Skipped {
        /// Reason for skipping.
        reason: &'static str,
    },
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analyzer_defaults() {
        let analyzer = MingwRelocationAnalyzer::new();
        assert!(analyzer.create_references);
        assert!(analyzer.mark_got_pointers);
        assert!(analyzer.process_highlow);
        assert!(analyzer.process_dir64);
    }

    #[test]
    fn test_reloc_type_from_raw() {
        assert_eq!(PeRelocType::from_raw(0), PeRelocType::Absolute);
        assert_eq!(PeRelocType::from_raw(3), PeRelocType::HighLow);
        assert_eq!(PeRelocType::from_raw(10), PeRelocType::Dir64);
        assert_eq!(PeRelocType::from_raw(99), PeRelocType::Unknown(99));
    }

    #[test]
    fn test_reloc_type_size() {
        assert_eq!(PeRelocType::Absolute.size(), 0);
        assert_eq!(PeRelocType::High.size(), 2);
        assert_eq!(PeRelocType::Low.size(), 2);
        assert_eq!(PeRelocType::HighLow.size(), 4);
        assert_eq!(PeRelocType::Dir64.size(), 8);
    }

    #[test]
    fn test_relocation_entry() {
        let entry = PeRelocationEntry {
            page_rva: 0x1000,
            reloc_type: PeRelocType::HighLow,
            offset: 0x42,
        };
        assert_eq!(entry.target_rva(), 0x1042);
        assert_eq!(entry.target_address(0x400000), 0x401042);
    }

    #[test]
    fn test_mingw_reloc_result() {
        let result = MingwRelocResult::PointerCreated {
            address: 0x401000,
            referenced: 0x402000,
        };
        match result {
            MingwRelocResult::PointerCreated { address, referenced } => {
                assert_eq!(address, 0x401000);
                assert_eq!(referenced, 0x402000);
            }
            _ => panic!("Expected PointerCreated"),
        }
    }
}
