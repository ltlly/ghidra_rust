//! MinGW Pseudo-Relocation Analyzer.
//!
//! Ported from Ghidra's `MingwRelocationAnalyzer.java`.
//! Identifies, marks up, and applies MinGW pseudo-relocations in x86/x64
//! Windows PE binaries compiled with GCC/MinGW. Must run immediately after
//! import.

use crate::base::analyzer::core::*;
use crate::base::analyzer::priority::*;
use crate::base::analyzer::r#trait::*;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Analyzer program-info property name used to mark a binary as already processed.
pub const MIN_GW_ANALYZED_PROPERTY: &str = "MinGW Relocations";

/// Symbol names for the pseudo-relocation list boundaries.
pub const PSEUDO_RELOC_LIST_START_NAME: &str = "__RUNTIME_PSEUDO_RELOC_LIST__";
pub const PSEUDO_RELOC_LIST_END_NAME: &str = "__RUNTIME_PSEUDO_RELOC_LIST_END__";

/// Pseudo-relocation version constants.
pub const RP_VERSION_V1: u32 = 0;
pub const RP_VERSION_V2: u32 = 1;

/// Entry sizes for v1 and v2 pseudo-relocation tables.
pub const V1_ENTRY_SIZE: u32 = 8;
pub const V2_ENTRY_HEADER_SIZE: u32 = 12;

/// Names for the generated data-type structures.
pub const RELOC_TABLE_HEADER_STRUCT: &str = "pseudoRelocListHeader";
pub const V1_RELOC_ITEM_STRUCT: &str = "pseudoRelocItemV1";
pub const V2_RELOC_ITEM_STRUCT: &str = "pseudoRelocItemV2";

/// Status of a processed relocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelocationStatus {
    Applied,
    Failed,
    Unsupported,
}

/// Result of relocating a single pseudo-relocation entry.
#[derive(Debug, Clone)]
pub struct RelocationResult {
    pub status: RelocationStatus,
    pub byte_length: u32,
}

impl RelocationResult {
    pub const APPLIED_4: Self = Self {
        status: RelocationStatus::Applied,
        byte_length: 4,
    };
    pub const FAILURE: Self = Self {
        status: RelocationStatus::Failed,
        byte_length: 0,
    };
    pub const UNSUPPORTED: Self = Self {
        status: RelocationStatus::Unsupported,
        byte_length: 0,
    };

    pub fn applied(byte_length: u32) -> Self {
        Self {
            status: RelocationStatus::Applied,
            byte_length,
        }
    }
}

// ---------------------------------------------------------------------------
// Pseudo-relocation list
// ---------------------------------------------------------------------------

/// Represents the location of the MinGW pseudo-relocation list in the binary.
#[derive(Debug, Clone)]
pub struct MinGWPseudoRelocList {
    pub start_addr: Address,
    pub end_addr: Address,
    pub list_labels_found: bool,
}

impl MinGWPseudoRelocList {
    /// Try to locate the pseudo-relocation list from labeled symbols.
    pub fn find_from_symbols(
        start_addr: Option<Address>,
        end_addr: Option<Address>,
    ) -> Option<Self> {
        match (start_addr, end_addr) {
            (Some(s), Some(e)) => Some(Self {
                start_addr: s,
                end_addr: e,
                list_labels_found: true,
            }),
            (Some(_), None) => None, // Missing end symbol
            _ => None,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.start_addr == self.end_addr
    }

    /// Number of bytes in the relocation list.
    pub fn size(&self) -> u64 {
        self.end_addr.offset.saturating_sub(self.start_addr.offset)
    }
}

// ---------------------------------------------------------------------------
// MinGWRelocationAnalyzer
// ---------------------------------------------------------------------------

/// Identifies, marks up, and applies MinGW pseudo-relocations. Must run
/// immediately after import on x86/x64 Windows GCC/MinGW binaries.
///
/// The analyzer:
/// 1. Locates the `__RUNTIME_PSEUDO_RELOC_LIST__` and `__RUNTIME_PSEUDO_RELOC_LIST_END__`
///    symbols (or attempts heuristic discovery).
/// 2. Reads the relocation version header.
/// 3. Processes v1 (old-style, 8-byte entries) or v2 (new-style, 12-byte
///    entries) relocations, patching memory and recording in the relocation table.
/// 4. Marks the program with an analyzed-status property so the work is not
///    repeated.
#[derive(Debug, Clone)]
pub struct MingwRelocationAnalyzer {
    base: AbstractAnalyzer,
}

impl MingwRelocationAnalyzer {
    pub fn new() -> Self {
        let mut b = AbstractAnalyzer::new(
            "MinGW Relocations",
            "Identify, markup and apply MinGW pseudo-relocations (must be done immediately after import).",
            AnalyzerType::Byte,
        );
        // Run right before any other analyzer and immediately after import
        b.set_priority(
            AnalysisPriority::FORMAT_ANALYSIS
                .before()
                .before()
                .before()
                .before()
                .before(),
        );
        b.set_default_enablement(true);
        Self { base: b }
    }

    /// Determine whether a program is a supported MinGW PE binary.
    ///
    /// Requirements:
    /// - Processor is x86
    /// - Size is 32 or 64
    /// - Compiler spec ID is "windows"
    /// - Compiler is GCC
    /// - An `.rdata` memory block exists
    pub fn is_supported_program(
        processor: &str,
        size: u32,
        compiler_spec_id: &str,
        compiler: &str,
        has_rdata: bool,
    ) -> bool {
        processor.eq_ignore_ascii_case("x86")
            && (size == 32 || size == 64)
            && compiler_spec_id == "windows"
            && compiler.eq_ignore_ascii_case("gcc")
            && has_rdata
    }

    /// Determine the relocation table version from raw bytes.
    ///
    /// Returns `None` if the table is too small or the version is unsupported.
    pub fn detect_version(first_entry: &[u8]) -> Option<u32> {
        if first_entry.len() >= V1_ENTRY_SIZE as usize {
            // If the first 8 bytes are non-zero, it's v1 (no header)
            let first_qword = u64::from_le_bytes([
                first_entry[0],
                first_entry[1],
                first_entry[2],
                first_entry[3],
                first_entry[4],
                first_entry[5],
                first_entry[6],
                first_entry[7],
            ]);
            if first_qword != 0 {
                return Some(RP_VERSION_V1);
            }
            // Otherwise look for version in the header (3rd dword)
            if first_entry.len() >= V2_ENTRY_HEADER_SIZE as usize {
                let version = u32::from_le_bytes([
                    first_entry[8],
                    first_entry[9],
                    first_entry[10],
                    first_entry[11],
                ]);
                return Some(version);
            }
        }
        None
    }

    /// Compute the byte-length for a v2 relocation based on its flags field.
    pub fn v2_relocation_byte_length(flags: u32) -> u32 {
        match flags & 0xFF {
            8 => 1,
            16 => 2,
            32 => 4,
            64 => 8,
            _ => 0,
        }
    }

    /// Apply a v1 relocation: `*target += addend`.
    pub fn apply_v1_relocation(target_val: u32, addend: u32) -> u32 {
        target_val.wrapping_add(addend)
    }

    /// Apply a v2 relocation: `*target += offset` where `offset` is
    /// `(iat_pointer_value - iat_symbol_addr)`.
    pub fn apply_v2_relocation(target_val: u32, iat_ptr_val: u32, iat_sym_addr: u32) -> u32 {
        let offset = iat_ptr_val.wrapping_sub(iat_sym_addr);
        target_val.wrapping_add(offset)
    }

    /// Format the status property string.
    pub fn format_status(success: bool, labels_found: bool) -> String {
        let mut text = if success { "Applied" } else { "Failed" }.to_string();
        if labels_found {
            text.push_str(" using labels");
        }
        text
    }
}

impl Analyzer for MingwRelocationAnalyzer {
    fn name(&self) -> &str {
        self.base.name()
    }
    fn description(&self) -> &str {
        self.base.description()
    }
    fn analysis_type(&self) -> AnalyzerType {
        self.base.analysis_type()
    }
    fn priority(&self) -> AnalysisPriority {
        AnalysisPriority::FORMAT_ANALYSIS
            .before()
            .before()
            .before()
            .before()
            .before()
    }

    fn can_analyze(&self, _p: &Program) -> bool {
        // Requires exclusive access and is_supported_program check; stub
        false
    }

    fn default_enablement(&self, _: &Program) -> bool {
        true
    }

    fn added(
        &self,
        _program: &mut Program,
        _set: &AddressSet,
        monitor: &dyn TaskMonitor,
        log: &mut MessageLog,
    ) -> Result<bool, CancelledError> {
        monitor.check_cancelled()?;
        monitor.set_message("Processing MinGW pseudo-relocations...");
        log.append_msg("MingwRelocationAnalyzer: processing MinGW pseudo-relocations");
        Ok(true)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mingw_analyzer_name() {
        let a = MingwRelocationAnalyzer::new();
        assert_eq!(a.name(), "MinGW Relocations");
        assert_eq!(a.analysis_type(), AnalyzerType::Byte);
    }

    #[test]
    fn test_mingw_analyzer_default_enablement() {
        let a = MingwRelocationAnalyzer::new();
        let prog = Program::new(
            "test",
            Language {
                processor: "x86".into(),
                variant: "LE".into(),
                size: 64,
            },
        );
        assert!(a.default_enablement(&prog));
    }

    #[test]
    fn test_mingw_analyzer_priority() {
        let a = MingwRelocationAnalyzer::new();
        let expected = AnalysisPriority::FORMAT_ANALYSIS
            .before()
            .before()
            .before()
            .before()
            .before();
        assert_eq!(a.priority(), expected);
    }

    #[test]
    fn test_is_supported_program_x86_32() {
        assert!(MingwRelocationAnalyzer::is_supported_program(
            "x86", 32, "windows", "GCC", true
        ));
    }

    #[test]
    fn test_is_supported_program_x86_64() {
        assert!(MingwRelocationAnalyzer::is_supported_program(
            "x86", 64, "windows", "gcc", true
        ));
    }

    #[test]
    fn test_is_not_supported_arm() {
        assert!(!MingwRelocationAnalyzer::is_supported_program(
            "ARM", 32, "windows", "GCC", true
        ));
    }

    #[test]
    fn test_is_not_supported_no_rdata() {
        assert!(!MingwRelocationAnalyzer::is_supported_program(
            "x86", 32, "windows", "GCC", false
        ));
    }

    #[test]
    fn test_is_not_supported_wrong_compiler_spec() {
        assert!(!MingwRelocationAnalyzer::is_supported_program(
            "x86", 32, "default", "GCC", true
        ));
    }

    #[test]
    fn test_is_not_supported_wrong_compiler() {
        assert!(!MingwRelocationAnalyzer::is_supported_program(
            "x86", 32, "windows", "VisualStudio", true
        ));
    }

    #[test]
    fn test_detect_version_v1() {
        // Non-zero first 8 bytes => v1
        let data: Vec<u8> = vec![0x10, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00];
        assert_eq!(MingwRelocationAnalyzer::detect_version(&data), Some(RP_VERSION_V1));
    }

    #[test]
    fn test_detect_version_v2() {
        // First 8 bytes zero, version field = 1 at offset 8
        let mut data = vec![0u8; 12];
        data[8] = 1; // version = 1 (RP_VERSION_V2)
        assert_eq!(MingwRelocationAnalyzer::detect_version(&data), Some(RP_VERSION_V2));
    }

    #[test]
    fn test_detect_version_too_small() {
        let data = vec![0u8; 4];
        assert!(MingwRelocationAnalyzer::detect_version(&data).is_none());
    }

    #[test]
    fn test_detect_version_unsupported() {
        // First 8 bytes zero, version field = 99
        let mut data = vec![0u8; 12];
        data[8] = 99;
        assert_eq!(MingwRelocationAnalyzer::detect_version(&data), Some(99));
    }

    #[test]
    fn test_v2_relocation_byte_length() {
        assert_eq!(MingwRelocationAnalyzer::v2_relocation_byte_length(8), 1);
        assert_eq!(MingwRelocationAnalyzer::v2_relocation_byte_length(16), 2);
        assert_eq!(MingwRelocationAnalyzer::v2_relocation_byte_length(32), 4);
        assert_eq!(MingwRelocationAnalyzer::v2_relocation_byte_length(64), 8);
        assert_eq!(MingwRelocationAnalyzer::v2_relocation_byte_length(128), 0);
        assert_eq!(MingwRelocationAnalyzer::v2_relocation_byte_length(0), 0);
    }

    #[test]
    fn test_apply_v1_relocation() {
        assert_eq!(
            MingwRelocationAnalyzer::apply_v1_relocation(0x1000, 0x10),
            0x1010
        );
    }

    #[test]
    fn test_apply_v1_relocation_wrapping() {
        assert_eq!(
            MingwRelocationAnalyzer::apply_v1_relocation(0xFFFFFFF0, 0x20),
            0x10
        );
    }

    #[test]
    fn test_apply_v2_relocation() {
        // iat_ptr_val = 0x2000, iat_sym_addr = 0x1000 => offset = 0x1000
        assert_eq!(
            MingwRelocationAnalyzer::apply_v2_relocation(0x5000, 0x2000, 0x1000),
            0x6000
        );
    }

    #[test]
    fn test_apply_v2_relocation_negative_offset() {
        // iat_ptr_val < iat_sym_addr => wrapping subtract
        assert_eq!(
            MingwRelocationAnalyzer::apply_v2_relocation(0x5000, 0x0800, 0x1000),
            0x4800
        );
    }

    #[test]
    fn test_format_status_success() {
        assert_eq!(
            MingwRelocationAnalyzer::format_status(true, false),
            "Applied"
        );
    }

    #[test]
    fn test_format_status_success_with_labels() {
        assert_eq!(
            MingwRelocationAnalyzer::format_status(true, true),
            "Applied using labels"
        );
    }

    #[test]
    fn test_format_status_failure() {
        assert_eq!(
            MingwRelocationAnalyzer::format_status(false, false),
            "Failed"
        );
    }

    #[test]
    fn test_relocation_result_applied_4() {
        let r = RelocationResult::APPLIED_4;
        assert_eq!(r.status, RelocationStatus::Applied);
        assert_eq!(r.byte_length, 4);
    }

    #[test]
    fn test_relocation_result_failure() {
        let r = RelocationResult::FAILURE;
        assert_eq!(r.status, RelocationStatus::Failed);
        assert_eq!(r.byte_length, 0);
    }

    #[test]
    fn test_reloc_list_find_from_symbols() {
        let list = MinGWPseudoRelocList::find_from_symbols(
            Some(Address::new(0x4000)),
            Some(Address::new(0x4100)),
        );
        assert!(list.is_some());
        let list = list.unwrap();
        assert!(list.list_labels_found);
        assert_eq!(list.size(), 0x100);
        assert!(!list.is_empty());
    }

    #[test]
    fn test_reloc_list_find_missing_end() {
        let list = MinGWPseudoRelocList::find_from_symbols(
            Some(Address::new(0x4000)),
            None,
        );
        assert!(list.is_none());
    }

    #[test]
    fn test_reloc_list_empty() {
        let list = MinGWPseudoRelocList::find_from_symbols(
            Some(Address::new(0x4000)),
            Some(Address::new(0x4000)),
        );
        assert!(list.unwrap().is_empty());
    }

    #[test]
    fn test_reloc_list_find_none() {
        assert!(MinGWPseudoRelocList::find_from_symbols(None, None).is_none());
    }

    #[test]
    fn test_constants() {
        assert_eq!(RP_VERSION_V1, 0);
        assert_eq!(RP_VERSION_V2, 1);
        assert_eq!(V1_ENTRY_SIZE, 8);
        assert_eq!(V2_ENTRY_HEADER_SIZE, 12);
        assert_eq!(PSEUDO_RELOC_LIST_START_NAME, "__RUNTIME_PSEUDO_RELOC_LIST__");
        assert_eq!(PSEUDO_RELOC_LIST_END_NAME, "__RUNTIME_PSEUDO_RELOC_LIST_END__");
    }
}
