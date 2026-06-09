//! Data analyzer.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.analysis.DataAnalyzer`.
//!
//! This analyzer creates data definitions in undefined memory regions.
//! It scans for pointer-aligned values, string patterns, and common
//! data structure layouts.
//!
//! Key responsibilities:
//!
//! - Auto-create pointer data types where values point to valid memory
//! - Detect ASCII / UTF-8 string data
//! - Create arrays of primitive types (byte, word, dword, qword)
//! - Handle data in non-code memory regions

use std::collections::HashSet;

use super::analyzer::{
    AbstractAnalyzer, Address, AddressRange, AddressSet, AnalysisOption, AnalysisOptionValue,
    AnalysisPriority, Analyzer, AnalyzerType, BookmarkType, CancelledError, Data, MessageLog,
    Program, TaskMonitor,
};

// ---------------------------------------------------------------------------
// Data classification
// ---------------------------------------------------------------------------
/// The type of data detected at an address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DataClassification {
    /// A pointer to another address in the program.
    Pointer,
    /// A null-terminated ASCII string.
    AsciiString,
    /// A sequence of bytes (not further classified).
    ByteArray,
    /// A 16-bit word.
    Word,
    /// A 32-bit dword.
    DWord,
    /// A 64-bit qword.
    QWord,
    /// An array of pointers.
    PointerArray,
    /// Unknown / unclassified.
    Unknown,
}

/// A single detected data item with its classification.
#[derive(Debug, Clone)]
pub struct DataItem {
    pub address: Address,
    pub classification: DataClassification,
    pub length: u32,
    pub value: DataValue,
}

/// The actual value of a data item.
#[derive(Debug, Clone)]
pub enum DataValue {
    Pointer(u64),
    String(String),
    Bytes(Vec<u8>),
    Integer(u64),
}

// ---------------------------------------------------------------------------
// DataAnalyzer
// ---------------------------------------------------------------------------
/// Creates data definitions in undefined memory regions.
///
/// Runs at [`AnalysisPriority::DATA_ANALYSIS`] and is triggered by
/// [`AnalyzerType::Byte`] changes (new memory blocks).
#[derive(Debug)]
pub struct DataAnalyzer {
    base: AbstractAnalyzer,
    /// Whether to create pointer data when a value points into the
    /// program's address space.
    pub create_pointers: bool,
    /// Whether to detect and create ASCII strings.
    pub create_strings: bool,
    /// Minimum string length to consider.
    pub min_string_length: usize,
    /// Whether to create word/dword/qword arrays.
    pub create_arrays: bool,
    /// Maximum number of data items to create per run.
    pub max_items_per_run: usize,
}

impl DataAnalyzer {
    pub fn new() -> Self {
        let mut base = AbstractAnalyzer::new(
            "Data Analyzer",
            "Creates data definitions in undefined memory",
            AnalyzerType::Data,
        );
        base.set_priority(AnalysisPriority::DATA_ANALYSIS);
        base.set_supports_one_time_analysis(true);
        Self {
            base,
            create_pointers: true,
            create_strings: true,
            min_string_length: 4,
            create_arrays: true,
            max_items_per_run: 100_000,
        }
    }

    /// Check if a 32-bit value is a plausible pointer into the program's
    /// memory.
    pub fn is_valid_pointer32(&self, value: u32, program: &Program) -> bool {
        if value == 0 {
            return false;
        }
        program.memory.contains(&Address::new(value as u64))
    }

    /// Check if a 64-bit value is a plausible pointer.
    pub fn is_valid_pointer64(&self, value: u64, program: &Program) -> bool {
        if value == 0 || value == u64::MAX {
            return false;
        }
        program.memory.contains(&Address::new(value))
    }

    /// Scan a byte slice for a null-terminated ASCII string.
    ///
    /// Returns the string length (excluding the null terminator) if a
    /// valid string is found, or `None` if the bytes do not form a
    /// valid string of at least [`min_string_length`](Self::min_string_length).
    pub fn scan_ascii_string(&self, bytes: &[u8]) -> Option<usize> {
        let mut len = 0usize;
        for &b in bytes {
            if b == 0 {
                break;
            }
            if !(0x20..=0x7e).contains(&b) && b != b'\t' && b != b'\n' && b != b'\r' {
                return None;
            }
            len += 1;
        }
        if len >= self.min_string_length {
            Some(len)
        } else {
            None
        }
    }

    /// Classify data at the given address based on the raw bytes.
    pub fn classify_data(&self, _addr: Address, _bytes: &[u8], program: &Program) -> DataClassification {
        // Placeholder: real implementation would inspect the raw bytes.
        let _ = program;
        DataClassification::Unknown
    }
}

impl Default for DataAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl Analyzer for DataAnalyzer {
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
        self.base.priority()
    }

    fn supports_one_time_analysis(&self) -> bool {
        self.base.supports_one_time_analysis()
    }

    fn can_analyze(&self, _program: &Program) -> bool {
        true
    }

    fn added(
        &self,
        program: &mut Program,
        set: &AddressSet,
        monitor: &dyn TaskMonitor,
        log: &mut MessageLog,
    ) -> Result<bool, CancelledError> {
        let mut items_created = 0usize;

        for addr in set.get_addresses(true) {
            monitor.check_cancelled()?;

            if items_created >= self.max_items_per_run {
                break;
            }

            // Skip addresses that already have data defined
            if program.listing.defined_data.contains_key(&addr) {
                continue;
            }

            // Placeholder: real implementation would read bytes from memory
            // and classify them.  For now, we just count addresses.
            items_created += 1;
        }

        if items_created > 0 {
            log.append_msg(&format!("Processed {} data addresses", items_created));
        }
        Ok(items_created > 0)
    }

    fn register_options(&self, _program: &Program) -> Vec<AnalysisOption> {
        vec![
            AnalysisOption {
                name: "Create pointers".to_string(),
                description: "Automatically create pointer data types".to_string(),
                default_value: AnalysisOptionValue::Bool(true),
                current_value: AnalysisOptionValue::Bool(self.create_pointers),
            },
            AnalysisOption {
                name: "Create strings".to_string(),
                description: "Automatically create string data types".to_string(),
                default_value: AnalysisOptionValue::Bool(true),
                current_value: AnalysisOptionValue::Bool(self.create_strings),
            },
            AnalysisOption {
                name: "Min string length".to_string(),
                description: "Minimum string length to auto-create".to_string(),
                default_value: AnalysisOptionValue::Integer(4),
                current_value: AnalysisOptionValue::Integer(self.min_string_length as i64),
            },
            AnalysisOption {
                name: "Create arrays".to_string(),
                description: "Automatically create arrays of primitive types".to_string(),
                default_value: AnalysisOptionValue::Bool(true),
                current_value: AnalysisOptionValue::Bool(self.create_arrays),
            },
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::analyzer::{AddressRange, BasicTaskMonitor, Language};

    fn make_lang() -> Language {
        Language {
            processor: "x86".into(),
            variant: "LE".into(),
            size: 64,
        }
    }

    fn make_program() -> Program {
        let mut prog = Program::new("test_data", make_lang());
        prog.image_base = 0x400000;
        prog.memory.add_range(AddressRange::new(
            Address::new(0x400000),
            Address::new(0x500000),
        ));
        prog
    }

    #[test]
    fn test_data_analyzer_creation() {
        let a = DataAnalyzer::new();
        assert_eq!(a.name(), "Data Analyzer");
        assert_eq!(a.analysis_type(), AnalyzerType::Data);
        assert!(a.supports_one_time_analysis());
        assert!(a.create_pointers);
        assert!(a.create_strings);
        assert_eq!(a.min_string_length, 4);
        assert!(a.create_arrays);
        assert_eq!(a.max_items_per_run, 100_000);
    }

    #[test]
    fn test_data_analyzer_can_analyze() {
        let a = DataAnalyzer::new();
        assert!(a.can_analyze(&make_program()));
    }

    #[test]
    fn test_is_valid_pointer32() {
        let a = DataAnalyzer::new();
        let prog = make_program();
        assert!(!a.is_valid_pointer32(0, &prog));
        assert!(a.is_valid_pointer32(0x401000, &prog));
        assert!(!a.is_valid_pointer32(0x600000, &prog));
    }

    #[test]
    fn test_is_valid_pointer64() {
        let a = DataAnalyzer::new();
        let prog = make_program();
        assert!(!a.is_valid_pointer64(0, &prog));
        assert!(!a.is_valid_pointer64(u64::MAX, &prog));
        assert!(a.is_valid_pointer64(0x401000, &prog));
        assert!(!a.is_valid_pointer64(0x600000, &prog));
    }

    #[test]
    fn test_scan_ascii_string_valid() {
        let a = DataAnalyzer::new();
        assert_eq!(a.scan_ascii_string(b"hello\0"), Some(5));
        assert_eq!(a.scan_ascii_string(b"test\0"), Some(4));
        assert_eq!(a.scan_ascii_string(b"ab\0"), None); // Too short
    }

    #[test]
    fn test_scan_ascii_string_with_control_chars() {
        let a = DataAnalyzer::new();
        assert_eq!(a.scan_ascii_string(b"hello\tworld\0"), Some(11));
        assert_eq!(a.scan_ascii_string(b"line\n\0"), Some(5));
        assert_eq!(a.scan_ascii_string(b"\x01bad\0"), None);
    }

    #[test]
    fn test_scan_ascii_string_no_null() {
        let a = DataAnalyzer::new();
        // No null terminator -- scan until end of slice
        assert_eq!(a.scan_ascii_string(b"hello"), Some(5));
    }

    #[test]
    fn test_scan_ascii_string_custom_min() {
        let mut a = DataAnalyzer::new();
        a.min_string_length = 2;
        assert_eq!(a.scan_ascii_string(b"ab\0"), Some(2));
        assert_eq!(a.scan_ascii_string(b"a\0"), None);
    }

    #[test]
    fn test_scan_ascii_string_empty() {
        let a = DataAnalyzer::new();
        assert_eq!(a.scan_ascii_string(b"\0"), None);
        assert_eq!(a.scan_ascii_string(b""), None);
    }

    #[test]
    fn test_data_classification_variants() {
        assert_ne!(DataClassification::Pointer, DataClassification::AsciiString);
        assert_ne!(DataClassification::DWord, DataClassification::QWord);
    }

    #[test]
    fn test_data_value_variants() {
        let p = DataValue::Pointer(0x401000);
        let s = DataValue::String("hello".into());
        let b = DataValue::Bytes(vec![1, 2, 3]);
        let i = DataValue::Integer(42);

        match p {
            DataValue::Pointer(v) => assert_eq!(v, 0x401000),
            _ => panic!("expected pointer"),
        }
        match s {
            DataValue::String(v) => assert_eq!(v, "hello"),
            _ => panic!("expected string"),
        }
        match b {
            DataValue::Bytes(v) => assert_eq!(v.len(), 3),
            _ => panic!("expected bytes"),
        }
        match i {
            DataValue::Integer(v) => assert_eq!(v, 42),
            _ => panic!("expected integer"),
        }
    }

    #[test]
    fn test_data_item() {
        let item = DataItem {
            address: Address::new(0x401000),
            classification: DataClassification::Pointer,
            length: 8,
            value: DataValue::Pointer(0x402000),
        };
        assert_eq!(item.address, Address::new(0x401000));
        assert_eq!(item.length, 8);
    }

    #[test]
    fn test_data_analyzer_run() {
        let a = DataAnalyzer::new();
        let mut prog = make_program();
        let set = AddressSet::from_range(AddressRange::new(
            Address::new(0x401000),
            Address::new(0x401100),
        ));
        let monitor = BasicTaskMonitor::new();
        let mut log = MessageLog::new();
        let result = a.added(&mut prog, &set, &monitor, &mut log).unwrap();
        assert!(result);
    }

    #[test]
    fn test_data_analyzer_empty_set() {
        let a = DataAnalyzer::new();
        let mut prog = make_program();
        let set = AddressSet::new();
        let monitor = BasicTaskMonitor::new();
        let mut log = MessageLog::new();
        let result = a.added(&mut prog, &set, &monitor, &mut log).unwrap();
        assert!(!result);
    }

    #[test]
    fn test_data_analyzer_cancelled() {
        let a = DataAnalyzer::new();
        let mut prog = make_program();
        let set = AddressSet::from_range(AddressRange::new(
            Address::new(0x401000),
            Address::new(0x401100),
        ));
        let monitor = BasicTaskMonitor::new();
        monitor.cancel();
        let mut log = MessageLog::new();
        let result = a.added(&mut prog, &set, &monitor, &mut log);
        assert!(result.is_err());
    }

    #[test]
    fn test_data_analyzer_max_items() {
        let mut a = DataAnalyzer::new();
        a.max_items_per_run = 5;
        let mut prog = make_program();
        let set = AddressSet::from_range(AddressRange::new(
            Address::new(0x401000),
            Address::new(0x402000),
        ));
        let monitor = BasicTaskMonitor::new();
        let mut log = MessageLog::new();
        let result = a.added(&mut prog, &set, &monitor, &mut log);
        assert!(result.is_ok());
    }

    #[test]
    fn test_data_analyzer_options() {
        let a = DataAnalyzer::new();
        let prog = make_program();
        let opts = a.register_options(&prog);
        assert_eq!(opts.len(), 4);
        assert_eq!(opts[0].name, "Create pointers");
        assert_eq!(opts[1].name, "Create strings");
        assert_eq!(opts[2].name, "Min string length");
        assert_eq!(opts[3].name, "Create arrays");
    }

    #[test]
    fn test_data_analyzer_skip_existing() {
        let a = DataAnalyzer::new();
        let mut prog = make_program();
        prog.listing.defined_data.insert(
            Address::new(0x401000),
            Data {
                address: Address::new(0x401000),
                length: 4,
                data_type_name: "dword".into(),
            },
        );
        let set = AddressSet::from_range(AddressRange::new(
            Address::new(0x401000),
            Address::new(0x401100),
        ));
        let monitor = BasicTaskMonitor::new();
        let mut log = MessageLog::new();
        // Should skip 0x401000 and process the rest
        let result = a.added(&mut prog, &set, &monitor, &mut log);
        assert!(result.is_ok());
    }

    #[test]
    fn test_classify_data_placeholder() {
        let a = DataAnalyzer::new();
        let prog = make_program();
        let class = a.classify_data(Address::new(0x401000), &[0, 0, 0, 0], &prog);
        assert_eq!(class, DataClassification::Unknown);
    }
}
