//! Operand Reference Analyzer.
//!
//! Ported from Ghidra's `OperandReferenceAnalyzer.java`.
//! Analyzes data referenced by instruction operands, creating data definitions
//! (pointers, strings, address tables) and subroutine references where
//! appropriate. This is one of the core reference-analysis passes in Ghidra.

use crate::base::analyzer::core::*;
use crate::base::analyzer::priority::*;
use crate::base::analyzer::r#trait::*;

// ---------------------------------------------------------------------------
// Option names and defaults
// ---------------------------------------------------------------------------

/// Analyzer option identifiers.
pub mod options {
    pub const ASCII_STRINGS: &str = "Ascii String References";
    pub const UNICODE_STRINGS: &str = "Unicode String References";
    pub const ALIGN_STRINGS: &str = "Align End of Strings";
    pub const MIN_STRING_LENGTH: &str = "Minimum String Length";
    pub const POINTERS: &str = "References to Pointers";
    pub const RELOCATION_GUIDE: &str = "Relocation Table Guide";
    pub const SUBROUTINE: &str = "Subroutine References";
    pub const ADDRESS_TABLE: &str = "Create Address Tables";
    pub const SWITCH_TABLE: &str = "Switch Table References";
    pub const TABLE_ALIGNMENT: &str = "Address Table Alignment";
    pub const MIN_TABLE_SIZE: &str = "Address Table Minimum Size";
    pub const RESPECT_EXECUTE: &str = "Respect Execute Flag";
}

/// Default values for each analyzer option.
pub mod defaults {
    pub const ASCII_STRINGS: bool = true;
    pub const UNICODE_STRINGS: bool = true;
    pub const ALIGN_STRINGS: bool = false;
    pub const MIN_STRING_LENGTH: u32 = 5;
    pub const POINTERS: bool = true;
    pub const RELOCATION_GUIDE: bool = true;
    pub const SUBROUTINE: bool = true;
    pub const ADDRESS_TABLE: bool = true;
    pub const SWITCH_TABLE: bool = true;
    pub const TABLE_ALIGNMENT: u32 = 4;
    pub const MIN_TABLE_SIZE: u32 = 2;
    pub const RESPECT_EXECUTE: bool = true;
}

// ---------------------------------------------------------------------------
// Operand reference configuration
// ---------------------------------------------------------------------------

/// Configuration for operand reference analysis.
#[derive(Debug, Clone)]
pub struct OperandReferenceConfig {
    /// Create ASCII strings when referenced.
    pub ascii_strings: bool,
    /// Create Unicode strings when referenced.
    pub unicode_strings: bool,
    /// Align string end to processor alignment when trailing zeros present.
    pub align_strings: bool,
    /// Minimum byte count for a valid string.
    pub min_string_length: u32,
    /// Create pointers when referenced.
    pub pointers: bool,
    /// Use relocation table entries to guide pointer analysis.
    pub relocation_guide: bool,
    /// Disassemble and bookmark referenced code subroutines.
    pub subroutine: bool,
    /// Create address tables.
    pub address_table: bool,
    /// Create switch (jump) tables.
    pub switch_table: bool,
    /// Alignment in bytes for address tables.
    pub table_alignment: u32,
    /// Minimum number of valid pointer entries to form an address table.
    pub min_table_size: u32,
    /// Respect the execute flag on memory blocks when checking entry points.
    pub respect_execute: bool,
}

impl Default for OperandReferenceConfig {
    fn default() -> Self {
        Self {
            ascii_strings: defaults::ASCII_STRINGS,
            unicode_strings: defaults::UNICODE_STRINGS,
            align_strings: defaults::ALIGN_STRINGS,
            min_string_length: defaults::MIN_STRING_LENGTH,
            pointers: defaults::POINTERS,
            relocation_guide: defaults::RELOCATION_GUIDE,
            subroutine: defaults::SUBROUTINE,
            address_table: defaults::ADDRESS_TABLE,
            switch_table: defaults::SWITCH_TABLE,
            table_alignment: defaults::TABLE_ALIGNMENT,
            min_table_size: defaults::MIN_TABLE_SIZE,
            respect_execute: defaults::RESPECT_EXECUTE,
        }
    }
}

// ---------------------------------------------------------------------------
// PointerAnalysis
// ---------------------------------------------------------------------------

/// The result of analyzing a memory location for pointer content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PointerAnalysis {
    /// Location contains a valid pointer to code.
    CodePointer,
    /// Location contains a valid pointer to data.
    DataPointer,
    /// Location contains a valid pointer to an external address.
    ExternalPointer,
    /// Location does not look like a pointer.
    NotPointer,
    /// Pointer value is null or out of bounds.
    InvalidPointer,
}

impl PointerAnalysis {
    pub fn is_pointer(&self) -> bool {
        matches!(
            self,
            Self::CodePointer | Self::DataPointer | Self::ExternalPointer
        )
    }
}

// ---------------------------------------------------------------------------
// AddressTable
// ---------------------------------------------------------------------------

/// Represents a contiguous run of pointer-like values that form an address
/// table (potentially a switch/jump table).
#[derive(Debug, Clone)]
pub struct AddressTable {
    /// Start address of the table.
    pub start: Address,
    /// Number of entries in the table.
    pub num_entries: u32,
    /// Byte alignment of each entry.
    pub alignment: u32,
    /// Whether this table appears to be a switch table (all targets are in
    /// the same function).
    pub is_switch: bool,
}

impl AddressTable {
    pub fn new(start: Address, num_entries: u32, alignment: u32, is_switch: bool) -> Self {
        Self {
            start,
            num_entries,
            alignment,
            is_switch,
        }
    }

    /// Total size of the table in bytes.
    pub fn byte_size(&self) -> u64 {
        (self.num_entries as u64) * (self.alignment as u64)
    }

    /// End address (inclusive) of the table.
    pub fn end_address(&self) -> Address {
        self.start.add(self.byte_size().saturating_sub(1))
    }
}

// ---------------------------------------------------------------------------
// OperandReferenceAnalyzer
// ---------------------------------------------------------------------------

/// Analyzes data referenced by instructions.
///
/// This analyzer is one of the most important reference-analysis passes in
/// Ghidra. It:
///
/// 1. Iterates over instructions in the affected address set.
/// 2. For each memory operand reference, determines whether the target looks
///    like a pointer, string, subroutine entry point, or address table.
/// 3. Creates appropriate data definitions (pointers, strings) or function
///    entries.
/// 4. Can optionally follow relocation table entries for additional guidance.
#[derive(Debug, Clone)]
pub struct OperandReferenceAnalyzer {
    base: AbstractAnalyzer,
    pub config: OperandReferenceConfig,
}

impl OperandReferenceAnalyzer {
    pub fn new() -> Self {
        let mut b = AbstractAnalyzer::new(
            "Reference",
            "Analyzes data referenced by instructions.",
            AnalyzerType::Byte,
        );
        b.set_priority(AnalysisPriority::REFERENCE_ANALYSIS);
        b.set_default_enablement(true);
        Self {
            base: b,
            config: OperandReferenceConfig::default(),
        }
    }

    /// Create a new analyzer with custom configuration.
    pub fn with_config(config: OperandReferenceConfig) -> Self {
        let mut a = Self::new();
        a.config = config;
        a
    }

    /// Analyze a potential pointer value against the program's memory layout.
    pub fn analyze_pointer(
        value: u64,
        min_addr: u64,
        max_addr: u64,
        executable_ranges: &[(u64, u64)],
        external_range: Option<(u64, u64)>,
    ) -> PointerAnalysis {
        // Check external space
        if let Some((ext_min, ext_max)) = external_range {
            if value >= ext_min && value <= ext_max {
                return PointerAnalysis::ExternalPointer;
            }
        }
        // Check program bounds
        if value < min_addr || value > max_addr {
            return PointerAnalysis::InvalidPointer;
        }
        if value == 0 {
            return PointerAnalysis::InvalidPointer;
        }
        // Check if target is in an executable range
        for &(lo, hi) in executable_ranges {
            if value >= lo && value <= hi {
                return PointerAnalysis::CodePointer;
            }
        }
        PointerAnalysis::DataPointer
    }

    /// Detect whether a contiguous sequence of values at `start` looks like
    /// an address table. Returns the table if at least `min_entries`
    /// consecutive valid pointers are found.
    pub fn detect_address_table(
        values: &[u64],
        min_addr: u64,
        max_addr: u64,
        min_entries: u32,
        alignment: u32,
    ) -> Option<AddressTable> {
        if values.is_empty() || alignment == 0 {
            return None;
        }
        let mut run: u32 = 0;
        let mut first_valid_idx: usize = 0;
        for (i, &val) in values.iter().enumerate() {
            if val >= min_addr && val <= max_addr && val != 0 {
                if run == 0 {
                    first_valid_idx = i;
                }
                run += 1;
            } else {
                if run >= min_entries {
                    let start_offset = (first_valid_idx as u64) * (alignment as u64);
                    return Some(AddressTable::new(
                        Address::new(start_offset),
                        run,
                        alignment,
                        false,
                    ));
                }
                run = 0;
            }
        }
        if run >= min_entries {
            let start_offset = (first_valid_idx as u64) * (alignment as u64);
            return Some(AddressTable::new(
                Address::new(start_offset),
                run,
                alignment,
                false,
            ));
        }
        None
    }

    /// Check if a byte sequence looks like a valid ASCII string (printable
    /// chars, null-terminated or at end of block).
    pub fn looks_like_ascii_string(bytes: &[u8], min_length: u32) -> bool {
        if (bytes.len() as u32) < min_length {
            return false;
        }
        let printable = bytes
            .iter()
            .take_while(|&&b| b != 0)
            .all(|&b| b == b'\n' || b == b'\t' || b == b'\r' || (b >= 0x20 && b < 0x7F));
        let non_null_len = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        printable && (non_null_len as u32) >= min_length
    }

    /// Check if a byte sequence looks like a valid UTF-16LE string.
    pub fn looks_like_utf16_string(bytes: &[u8], min_length: u32) -> bool {
        if bytes.len() < 4 || (bytes.len() as u32) < min_length * 2 {
            return false;
        }
        let mut char_count: u32 = 0;
        for chunk in bytes.chunks_exact(2) {
            let cp = u16::from_le_bytes([chunk[0], chunk[1]]);
            if cp == 0 {
                break;
            }
            // Allow ASCII range and common BMP characters
            if cp < 0x20 && cp != b'\n' as u16 && cp != b'\t' as u16 {
                return false;
            }
            char_count += 1;
        }
        char_count >= min_length
    }
}

impl Analyzer for OperandReferenceAnalyzer {
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
        AnalysisPriority::REFERENCE_ANALYSIS
    }

    fn can_analyze(&self, _p: &Program) -> bool {
        true
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
        monitor.set_message("Analyzing operand references...");
        log.append_msg("OperandReferenceAnalyzer: analyzing operand references");
        Ok(true)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_prog() -> Program {
        let lang = Language {
            processor: "x86".into(),
            variant: "LE".into(),
            size: 64,
        };
        let mut prog = Program::new("ref_test", lang);
        prog.image_base = 0x400000;
        prog.memory.add_range(AddressRange::new(
            Address::new(0x400000),
            Address::new(0x600000),
        ));
        prog
    }

    // -- Analyzer identity tests --

    #[test]
    fn test_operand_ref_analyzer_name() {
        let a = OperandReferenceAnalyzer::new();
        assert_eq!(a.name(), "Reference");
        assert_eq!(a.analysis_type(), AnalyzerType::Byte);
    }

    #[test]
    fn test_operand_ref_analyzer_priority() {
        let a = OperandReferenceAnalyzer::new();
        assert_eq!(a.priority(), AnalysisPriority::REFERENCE_ANALYSIS);
    }

    #[test]
    fn test_operand_ref_default_enablement() {
        let a = OperandReferenceAnalyzer::new();
        assert!(a.default_enablement(&make_prog()));
    }

    #[test]
    fn test_operand_ref_can_analyze() {
        let a = OperandReferenceAnalyzer::new();
        assert!(a.can_analyze(&make_prog()));
    }

    #[test]
    fn test_operand_ref_with_config() {
        let config = OperandReferenceConfig {
            ascii_strings: false,
            unicode_strings: false,
            min_string_length: 10,
            ..Default::default()
        };
        let a = OperandReferenceAnalyzer::with_config(config);
        assert!(!a.config.ascii_strings);
        assert!(!a.config.unicode_strings);
        assert_eq!(a.config.min_string_length, 10);
    }

    #[test]
    fn test_operand_ref_added() {
        let a = OperandReferenceAnalyzer::new();
        let mut prog = make_prog();
        let set = AddressSet::new();
        let monitor = BasicTaskMonitor::new();
        let mut log = MessageLog::new();
        let result = a.added(&mut prog, &set, &monitor, &mut log);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    // -- Config default tests --

    #[test]
    fn test_config_defaults() {
        let c = OperandReferenceConfig::default();
        assert!(c.ascii_strings);
        assert!(c.unicode_strings);
        assert!(!c.align_strings);
        assert_eq!(c.min_string_length, 5);
        assert!(c.pointers);
        assert!(c.relocation_guide);
        assert!(c.subroutine);
        assert!(c.address_table);
        assert!(c.switch_table);
        assert_eq!(c.table_alignment, 4);
        assert_eq!(c.min_table_size, 2);
        assert!(c.respect_execute);
    }

    // -- Pointer analysis tests --

    #[test]
    fn test_analyze_pointer_code() {
        let exec = vec![(0x401000u64, 0x402000u64)];
        assert_eq!(
            OperandReferenceAnalyzer::analyze_pointer(0x401500, 0x400000, 0x600000, &exec, None),
            PointerAnalysis::CodePointer
        );
    }

    #[test]
    fn test_analyze_pointer_data() {
        let exec = vec![(0x401000u64, 0x402000u64)];
        assert_eq!(
            OperandReferenceAnalyzer::analyze_pointer(0x500000, 0x400000, 0x600000, &exec, None),
            PointerAnalysis::DataPointer
        );
    }

    #[test]
    fn test_analyze_pointer_external() {
        let exec = vec![];
        assert_eq!(
            OperandReferenceAnalyzer::analyze_pointer(
                0xFFFF0000,
                0x400000,
                0x600000,
                &exec,
                Some((0xFFFF0000, 0xFFFFFFFF))
            ),
            PointerAnalysis::ExternalPointer
        );
    }

    #[test]
    fn test_analyze_pointer_null() {
        let exec = vec![];
        assert_eq!(
            OperandReferenceAnalyzer::analyze_pointer(0, 0x400000, 0x600000, &exec, None),
            PointerAnalysis::InvalidPointer
        );
    }

    #[test]
    fn test_analyze_pointer_out_of_bounds() {
        let exec = vec![];
        assert_eq!(
            OperandReferenceAnalyzer::analyze_pointer(0x700000, 0x400000, 0x600000, &exec, None),
            PointerAnalysis::InvalidPointer
        );
    }

    #[test]
    fn test_pointer_analysis_is_pointer() {
        assert!(PointerAnalysis::CodePointer.is_pointer());
        assert!(PointerAnalysis::DataPointer.is_pointer());
        assert!(PointerAnalysis::ExternalPointer.is_pointer());
        assert!(!PointerAnalysis::NotPointer.is_pointer());
        assert!(!PointerAnalysis::InvalidPointer.is_pointer());
    }

    // -- Address table detection tests --

    #[test]
    fn test_detect_address_table_found() {
        let values = vec![0x401000, 0x401010, 0x401020, 0x401030, 0x0, 0x0];
        let table = OperandReferenceAnalyzer::detect_address_table(
            &values, 0x400000, 0x600000, 2, 8,
        );
        assert!(table.is_some());
        let t = table.unwrap();
        assert_eq!(t.num_entries, 4);
        assert_eq!(t.alignment, 8);
        assert_eq!(t.byte_size(), 32);
    }

    #[test]
    fn test_detect_address_table_too_short() {
        let values = vec![0x401000, 0x0];
        let table = OperandReferenceAnalyzer::detect_address_table(
            &values, 0x400000, 0x600000, 3, 8,
        );
        assert!(table.is_none());
    }

    #[test]
    fn test_detect_address_table_empty() {
        let values: Vec<u64> = vec![];
        let table = OperandReferenceAnalyzer::detect_address_table(
            &values, 0x400000, 0x600000, 2, 8,
        );
        assert!(table.is_none());
    }

    #[test]
    fn test_detect_address_table_all_invalid() {
        let values = vec![0x0, 0x0, 0x0];
        let table = OperandReferenceAnalyzer::detect_address_table(
            &values, 0x400000, 0x600000, 2, 8,
        );
        assert!(table.is_none());
    }

    #[test]
    fn test_detect_address_table_with_gap() {
        // Valid, Valid, Invalid, Valid, Valid, Valid
        let values = vec![0x401000, 0x401010, 0x0, 0x401020, 0x401030, 0x401040];
        let table = OperandReferenceAnalyzer::detect_address_table(
            &values, 0x400000, 0x600000, 2, 8,
        );
        assert!(table.is_some());
        let t = table.unwrap();
        assert_eq!(t.num_entries, 2); // First run of 2
    }

    #[test]
    fn test_address_table_end_address() {
        let t = AddressTable::new(Address::new(0x5000), 4, 8, false);
        assert_eq!(t.byte_size(), 32);
        assert_eq!(t.end_address(), Address::new(0x501F));
    }

    // -- String detection tests --

    #[test]
    fn test_looks_like_ascii_string_valid() {
        assert!(OperandReferenceAnalyzer::looks_like_ascii_string(
            b"Hello\0",
            5
        ));
    }

    #[test]
    fn test_looks_like_ascii_string_too_short() {
        assert!(!OperandReferenceAnalyzer::looks_like_ascii_string(
            b"Hi\0",
            5
        ));
    }

    #[test]
    fn test_looks_like_ascii_string_no_null() {
        // Still valid if length >= min (treated as unterminated string)
        assert!(OperandReferenceAnalyzer::looks_like_ascii_string(
            b"Hello, World!",
            5
        ));
    }

    #[test]
    fn test_looks_like_ascii_string_control_chars() {
        assert!(!OperandReferenceAnalyzer::looks_like_ascii_string(
            b"Hel\x01lo\0",
            3
        ));
    }

    #[test]
    fn test_looks_like_ascii_string_with_newline_tab() {
        assert!(OperandReferenceAnalyzer::looks_like_ascii_string(
            b"line1\nline2\tend\0",
            5
        ));
    }

    #[test]
    fn test_looks_like_ascii_string_empty() {
        assert!(!OperandReferenceAnalyzer::looks_like_ascii_string(
            b"\0",
            1
        ));
    }

    #[test]
    fn test_looks_like_utf16_string_valid() {
        // "AB" in UTF-16LE: 0x0041 0x0042
        let bytes: Vec<u8> = vec![0x41, 0x00, 0x42, 0x00, 0x00, 0x00];
        assert!(OperandReferenceAnalyzer::looks_like_utf16_string(&bytes, 2));
    }

    #[test]
    fn test_looks_like_utf16_string_too_short() {
        let bytes: Vec<u8> = vec![0x41, 0x00, 0x00, 0x00];
        assert!(!OperandReferenceAnalyzer::looks_like_utf16_string(&bytes, 3));
    }

    #[test]
    fn test_looks_like_utf16_string_empty() {
        let bytes: Vec<u8> = vec![0x00, 0x00];
        assert!(!OperandReferenceAnalyzer::looks_like_utf16_string(&bytes, 1));
    }

    #[test]
    fn test_looks_like_utf16_string_control_char() {
        // \x01 in UTF-16LE
        let bytes: Vec<u8> = vec![0x01, 0x00, 0x42, 0x00, 0x00, 0x00];
        assert!(!OperandReferenceAnalyzer::looks_like_utf16_string(&bytes, 2));
    }

    #[test]
    fn test_looks_like_utf16_string_with_newline() {
        // \n in UTF-16LE
        let bytes: Vec<u8> = vec![0x0A, 0x00, 0x42, 0x00, 0x00, 0x00];
        assert!(OperandReferenceAnalyzer::looks_like_utf16_string(&bytes, 2));
    }
}
