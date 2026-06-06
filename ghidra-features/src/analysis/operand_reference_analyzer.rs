//! Operand reference analyzer -- checks operand references to memory locations.
//!
//! Ported from `ghidra.app.plugin.core.analysis.OperandReferenceAnalyzer` in Ghidra's
//! Features/Base.
//!
//! This analyzer iterates over instructions and examines data referenced by
//! operand values, looking for pointers, strings, address tables, and switch
//! table references. It is one of the most important post-disassembly analyzers.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// OperandReferenceAnalyzer
// ---------------------------------------------------------------------------

/// Analyzes data referenced by instruction operands.
///
/// This analyzer walks all instructions in the analysis set and for each
/// operand that references memory, it inspects the target to determine if it
/// is a pointer, string, address table, or switch table entry.
///
/// Configuration options control which types of references are created.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperandReferenceAnalyzer {
    /// Whether ASCII string references are created.
    pub ascii_enabled: bool,
    /// Whether Unicode string references are created.
    pub unicode_enabled: bool,
    /// Whether to align end of strings to processor alignment.
    pub align_strings_enabled: bool,
    /// Minimum number of bytes for a valid string.
    pub min_string_length: u32,
    /// Whether pointer references are created.
    pub pointer_enabled: bool,
    /// Whether relocation table entries guide pointer analysis.
    pub relocation_guide_enabled: bool,
    /// Whether subroutine references are created (disassemble valid code flow).
    pub subroutine_enabled: bool,
    /// Whether address tables are created.
    pub address_table_enabled: bool,
    /// Whether switch table references are created.
    pub switch_table_enabled: bool,
    /// Alignment for address tables (in bytes).
    pub address_table_alignment: u32,
    /// Minimum table size (number of entries) to be considered.
    pub minimum_table_size: u32,
    /// Whether to respect the execute flag on memory blocks.
    pub respect_execute_flag: bool,
}

impl Default for OperandReferenceAnalyzer {
    fn default() -> Self {
        Self {
            ascii_enabled: true,
            unicode_enabled: true,
            align_strings_enabled: false,
            min_string_length: 5,
            pointer_enabled: true,
            relocation_guide_enabled: true,
            subroutine_enabled: true,
            address_table_enabled: true,
            switch_table_enabled: false,
            address_table_alignment: 1,
            minimum_table_size: 3,
            respect_execute_flag: true,
        }
    }
}

impl OperandReferenceAnalyzer {
    /// Analyzer name.
    pub const NAME: &'static str = "Reference";
    /// Analyzer description.
    pub const DESCRIPTION: &'static str = "Analyzes data referenced by instructions.";

    /// Minimum potential table size for address table detection.
    pub const MINIMUM_POTENTIAL_TABLE_SIZE: u32 = 3;
    /// Maximum negative entries to check for switch tables.
    pub const MAX_NEG_ENTRIES: u32 = 32;
    /// Notification interval for progress updates.
    pub const NOTIFICATION_INTERVAL: u32 = 256;

    /// Create a new analyzer with default settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create analyzer options as a key-value list.
    pub fn option_descriptors(&self) -> Vec<AnalyzerOption> {
        vec![
            AnalyzerOption {
                name: "Ascii String References".into(),
                description: "Create an ascii string if there is a reference to it.".into(),
                value: OptionValue::Bool(self.ascii_enabled),
            },
            AnalyzerOption {
                name: "Unicode String References".into(),
                description: "Create a unicode string if there is a reference to it.".into(),
                value: OptionValue::Bool(self.unicode_enabled),
            },
            AnalyzerOption {
                name: "Align End of Strings".into(),
                description: "Align string length to the processor's alignment if trailing bytes are '0's.".into(),
                value: OptionValue::Bool(self.align_strings_enabled),
            },
            AnalyzerOption {
                name: "Minimum String Length".into(),
                description: "Minimum number of bytes for a string to be valid.".into(),
                value: OptionValue::Int(self.min_string_length as i64),
            },
            AnalyzerOption {
                name: "References to Pointers".into(),
                description: "Create pointers if there is a reference to it.".into(),
                value: OptionValue::Bool(self.pointer_enabled),
            },
            AnalyzerOption {
                name: "Relocation Table Guide".into(),
                description: "Use relocation table entries to guide pointer analysis.".into(),
                value: OptionValue::Bool(self.relocation_guide_enabled),
            },
            AnalyzerOption {
                name: "Subroutine References".into(),
                description: "Bookmark code that is a valid subroutine code flow and disassemble there.".into(),
                value: OptionValue::Bool(self.subroutine_enabled),
            },
            AnalyzerOption {
                name: "Create Address Tables".into(),
                description: "Create an address table if there is a reference to it.".into(),
                value: OptionValue::Bool(self.address_table_enabled),
            },
            AnalyzerOption {
                name: "Switch Table References".into(),
                description: "Create a switch table if there is a reference to it.".into(),
                value: OptionValue::Bool(self.switch_table_enabled),
            },
            AnalyzerOption {
                name: "Address Table Alignment".into(),
                description: "Align address tables on this number of bytes.".into(),
                value: OptionValue::Int(self.address_table_alignment as i64),
            },
            AnalyzerOption {
                name: "Address Table Minimum Size".into(),
                description: "Minimum run of valid pointers to be considered an address table.".into(),
                value: OptionValue::Int(self.minimum_table_size as i64),
            },
            AnalyzerOption {
                name: "Respect Execute Flag".into(),
                description: "Respect execute flag on memory blocks when checking entry points for code.".into(),
                value: OptionValue::Bool(self.respect_execute_flag),
            },
        ]
    }
}

// ---------------------------------------------------------------------------
// OperandAnalysisResult
// ---------------------------------------------------------------------------

/// Result of analyzing a single operand reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OperandAnalysisResult {
    /// A pointer reference was created.
    PointerCreated {
        /// Source address.
        from: u64,
        /// Target address.
        to: u64,
        /// Operand index.
        op_index: u32,
    },
    /// A string reference was created (ASCII or Unicode).
    StringCreated {
        /// Source address.
        from: u64,
        /// String data address.
        string_addr: u64,
        /// String length in bytes.
        length: u32,
        /// Whether this is a Unicode string.
        is_unicode: bool,
    },
    /// An address table was created.
    AddressTableCreated {
        /// Table start address.
        table_addr: u64,
        /// Number of entries in the table.
        entry_count: u32,
    },
    /// A switch table reference was created.
    SwitchTableCreated {
        /// Table start address.
        table_addr: u64,
        /// Number of cases.
        case_count: u32,
    },
    /// No reference was created (not applicable or already exists).
    Skipped,
    /// Analysis was cancelled.
    Cancelled,
}

// ---------------------------------------------------------------------------
// AnalyzerOption
// ---------------------------------------------------------------------------

/// Describes a configurable analyzer option.
#[derive(Debug, Clone)]
pub struct AnalyzerOption {
    /// Option name (displayed in the UI).
    pub name: String,
    /// Description of what this option controls.
    pub description: String,
    /// Current value.
    pub value: OptionValue,
}

/// Possible values for an analyzer option.
#[derive(Debug, Clone)]
pub enum OptionValue {
    /// Boolean option.
    Bool(bool),
    /// Integer option.
    Int(i64),
    /// String option.
    String(String),
}

// ---------------------------------------------------------------------------
// OperandRefAnalysisContext
// ---------------------------------------------------------------------------

/// Context for analyzing operand references during a single analysis pass.
#[derive(Debug)]
pub struct OperandRefAnalysisContext {
    /// The analyzer configuration.
    pub config: OperandReferenceAnalyzer,
    /// Count of pointer references created.
    pub pointer_count: u32,
    /// Count of string references created.
    pub string_count: u32,
    /// Count of address tables created.
    pub table_count: u32,
    /// Count of instructions processed.
    pub instructions_processed: u32,
}

impl OperandRefAnalysisContext {
    /// Create a new analysis context with the given configuration.
    pub fn new(config: OperandReferenceAnalyzer) -> Self {
        Self {
            config,
            pointer_count: 0,
            string_count: 0,
            table_count: 0,
            instructions_processed: 0,
        }
    }

    /// Process a single analysis result and update counters.
    pub fn record_result(&mut self, result: &OperandAnalysisResult) {
        match result {
            OperandAnalysisResult::PointerCreated { .. } => self.pointer_count += 1,
            OperandAnalysisResult::StringCreated { .. } => self.string_count += 1,
            OperandAnalysisResult::AddressTableCreated { .. }
            | OperandAnalysisResult::SwitchTableCreated { .. } => self.table_count += 1,
            _ => {}
        }
    }

    /// Process a single instruction and update the counter.
    pub fn record_instruction(&mut self) {
        self.instructions_processed += 1;
    }

    /// Get a summary of the analysis results.
    pub fn summary(&self) -> AnalysisSummary {
        AnalysisSummary {
            instructions_processed: self.instructions_processed,
            pointers_created: self.pointer_count,
            strings_created: self.string_count,
            tables_created: self.table_count,
        }
    }
}

/// Summary of an operand reference analysis pass.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnalysisSummary {
    /// Number of instructions processed.
    pub instructions_processed: u32,
    /// Number of pointer references created.
    pub pointers_created: u32,
    /// Number of string references created.
    pub strings_created: u32,
    /// Number of address/switch tables created.
    pub tables_created: u32,
}

// ---------------------------------------------------------------------------
// WellKnownValues
// ---------------------------------------------------------------------------

/// Common scalar values that should not be treated as addresses.
///
/// These values appear frequently in code (masks, flags, etc.) and would
/// generate false positive pointer references if not filtered.
pub struct WellKnownValues;

impl WellKnownValues {
    /// Values that should be skipped (not treated as addresses).
    pub const SKIP_VALUES: &'static [u64] = &[
        0,
        0xFF,
        0xFF00,
        0xFFFF,
        0xFFFFFF,
        0xFF_0000,
        0xFF_00FF,
        0xFFFF_FFFF,
        0xFFFF_FF00,
        0xFFFF_0000,
        0xFF00_0000,
    ];

    /// Minimum scalar value to consider as a potential address.
    pub const MIN_ADDRESS_VALUE: u64 = 4096;

    /// Check if a scalar value should be skipped as a potential address.
    pub fn should_skip(value: u64) -> bool {
        value < Self::MIN_ADDRESS_VALUE || Self::SKIP_VALUES.contains(&value)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_operand_reference_analyzer_defaults() {
        let analyzer = OperandReferenceAnalyzer::new();
        assert!(analyzer.ascii_enabled);
        assert!(analyzer.unicode_enabled);
        assert!(!analyzer.align_strings_enabled);
        assert_eq!(analyzer.min_string_length, 5);
        assert!(analyzer.pointer_enabled);
        assert!(analyzer.relocation_guide_enabled);
        assert!(analyzer.subroutine_enabled);
        assert!(analyzer.address_table_enabled);
        assert!(!analyzer.switch_table_enabled);
        assert_eq!(analyzer.address_table_alignment, 1);
        assert_eq!(analyzer.minimum_table_size, 3);
        assert!(analyzer.respect_execute_flag);
    }

    #[test]
    fn test_option_descriptors() {
        let analyzer = OperandReferenceAnalyzer::new();
        let opts = analyzer.option_descriptors();
        assert_eq!(opts.len(), 12);
        assert_eq!(opts[0].name, "Ascii String References");
        assert_eq!(opts[4].name, "References to Pointers");
    }

    #[test]
    fn test_analysis_context() {
        let config = OperandReferenceAnalyzer::new();
        let mut ctx = OperandRefAnalysisContext::new(config);

        ctx.record_result(&OperandAnalysisResult::PointerCreated {
            from: 0x400000,
            to: 0x401000,
            op_index: 0,
        });
        ctx.record_result(&OperandAnalysisResult::StringCreated {
            from: 0x400010,
            string_addr: 0x402000,
            length: 10,
            is_unicode: false,
        });
        ctx.record_instruction();
        ctx.record_instruction();

        let summary = ctx.summary();
        assert_eq!(summary.instructions_processed, 2);
        assert_eq!(summary.pointers_created, 1);
        assert_eq!(summary.strings_created, 1);
        assert_eq!(summary.tables_created, 0);
    }

    #[test]
    fn test_well_known_values() {
        assert!(WellKnownValues::should_skip(0));
        assert!(WellKnownValues::should_skip(100));
        assert!(WellKnownValues::should_skip(0xFF));
        assert!(WellKnownValues::should_skip(0xFFFF));
        assert!(!WellKnownValues::should_skip(0x400000));
        assert!(!WellKnownValues::should_skip(0x1000));
    }
}
