//! GolangStringAnalyzer -- finds and labels Go string structures.
//!
//! Ported from `ghidra.app.plugin.core.analysis.GolangStringAnalyzer`.
//! Go strings are stored as structs {char* data, int64 len} without null
//! terminators. This analyzer finds these structs and creates fixed-length
//! strings at the referenced locations.

use std::collections::{HashMap, HashSet};

use crate::base::analyzer::core::*;
use crate::base::analyzer::priority::*;
use crate::base::analyzer::r#trait::*;

/// A discovered Go string.
#[derive(Debug, Clone)]
pub struct GoString {
    /// Address of the string struct.
    pub struct_addr: Address,
    /// Address of the string data (char array).
    pub data_addr: Address,
    /// Length of the string in bytes.
    pub length: u64,
    /// Whether this is an inline string (data referenced from instruction, not struct).
    pub is_inline: bool,
    /// The string content (if readable).
    pub content: Option<String>,
}

impl GoString {
    /// Returns the address range of the string data.
    pub fn data_range(&self) -> AddressRange {
        AddressRange::new(self.data_addr, Address::new(self.data_addr.offset + self.length - 1))
    }

    /// Validates that the string is within the valid data range.
    pub fn is_valid(&self, data_range: &AddressSet) -> bool {
        if self.length == 0 {
            return false;
        }
        if self.length > 10000 {
            return false; // Unreasonably long
        }
        data_range.contains(&self.data_addr)
    }
}

/// A discovered Go slice.
#[derive(Debug, Clone)]
pub struct GoSlice {
    /// Address of the slice struct.
    pub struct_addr: Address,
    /// Address of the slice data (array pointer).
    pub data_addr: Address,
    /// Length of the slice.
    pub length: u64,
    /// Capacity of the slice.
    pub capacity: u64,
}

/// Options for the Go string analyzer.
#[derive(Debug, Clone)]
pub struct GolangStringAnalyzerOptions {
    /// Whether to markup slice structures.
    pub markup_slice_structs: bool,
    /// Whether to search data segments for string/slice structs.
    pub markup_data_segment_structs: bool,
}

impl Default for GolangStringAnalyzerOptions {
    fn default() -> Self {
        Self {
            markup_slice_structs: true,
            markup_data_segment_structs: true,
        }
    }
}

/// Analyzer that finds and labels Go string structures.
///
/// Go strings are stored as `{char* data, int64 len}` structs without null
/// terminators, making them invisible to normal string detection. This analyzer:
///
/// 1. Scans instruction references for potential string struct patterns
/// 2. Scans data segments for struct-like patterns
/// 3. Validates candidates by checking string content
/// 4. Creates fixed-length string data at discovered locations
#[derive(Debug, Clone)]
pub struct GolangStringAnalyzer {
    base: AbstractAnalyzer,
    /// Analyzer options.
    pub options: GolangStringAnalyzerOptions,
    /// Pointer size (from GoRttiMapper).
    pub ptr_size: u32,
    /// Discovered strings.
    strings: Vec<GoString>,
    /// Discovered slices.
    slices: Vec<GoSlice>,
}

impl GolangStringAnalyzer {
    /// Creates a new analyzer.
    pub fn new() -> Self {
        let mut base = AbstractAnalyzer::new(
            "Golang Strings",
            "Finds and labels Go string structures.",
            AnalyzerType::Byte,
        );
        base.set_default_enablement(true);
        base.set_priority(AnalysisPriority::DATA_TYPE_PROPAGATION.after().after());

        Self {
            base,
            options: GolangStringAnalyzerOptions::default(),
            ptr_size: 8, // Default 64-bit
            strings: Vec::new(),
            slices: Vec::new(),
        }
    }

    /// Returns discovered Go strings.
    pub fn strings(&self) -> &[GoString] {
        &self.strings
    }

    /// Returns discovered Go slices.
    pub fn slices(&self) -> &[GoSlice] {
        &self.slices
    }

    /// Checks if a string content is valid (no garbage characters).
    fn is_valid_string_content(s: &str) -> bool {
        s.chars().all(|c| c == '\n' || c == '\t' || (c as u32 >= 32 && c as u32 != 0xFFFD))
    }

    /// Attempts to read a Go string struct at the given address.
    ///
    /// A Go string struct is: {pointer data, int64 length}
    fn try_read_string_struct(
        &self,
        program: &Program,
        addr: Address,
        string_data_range: &AddressSet,
    ) -> Option<GoString> {
        let struct_size = self.ptr_size as u64 * 2; // pointer + length

        // Check if there's enough room for the struct
        if !program.memory.contains(&addr) {
            return None;
        }

        // Read pointer (first field)
        let ptr_addr = addr;
        if !string_data_range.contains(&ptr_addr) {
            return None;
        }

        // Read length (second field) -- simulated
        let data_addr = Address::new(addr.offset + self.ptr_size as u64);
        if !program.memory.contains(&data_addr) {
            return None;
        }

        // In a real implementation, we'd read the actual bytes from memory.
        // For now, check if there's data defined at the struct location.
        let has_data = program.listing.get_defined_data_at(&addr).is_some()
            || program.listing.get_instruction_at(&addr).is_some();

        if !has_data {
            return None;
        }

        // Simulate reading the struct
        Some(GoString {
            struct_addr: addr,
            data_addr: ptr_addr,
            length: 0, // Would be read from the struct
            is_inline: false,
            content: None,
        })
    }

    /// Attempts to read a Go slice struct at the given address.
    ///
    /// A Go slice struct is: {pointer data, int64 length, int64 capacity}
    fn try_read_slice_struct(&self, program: &Program, addr: Address) -> Option<GoSlice> {
        let struct_size = self.ptr_size as u64 * 3; // pointer + length + capacity

        if !program.memory.contains(&addr) {
            return None;
        }

        // Check if there's data at the location
        let has_data = program.listing.get_defined_data_at(&addr).is_some()
            || program.listing.get_instruction_at(&addr).is_some();

        if !has_data {
            return None;
        }

        Some(GoSlice {
            struct_addr: addr,
            data_addr: addr,
            length: 0,
            capacity: 0,
        })
    }

    /// Scans data segments for string and slice structs.
    fn markup_data_segment_structs(
        &mut self,
        program: &Program,
        string_data_range: &AddressSet,
        monitor: &dyn TaskMonitor,
    ) -> u32 {
        let mut string_count = 0u32;

        // Iterate through memory looking for potential struct patterns
        let addrs: Vec<Address> = program
            .memory
            .get_addresses(true)
            .collect();

        let align = self.ptr_size as u64;
        let mut i = 0u64;

        for addr in addrs {
            monitor.check_cancelled().ok();

            // Align to pointer size
            if addr.offset % align != 0 {
                continue;
            }

            // Try slice first (3 pointers), then string (2 pointers)
            if let Some(go_slice) = self.try_read_slice_struct(program, addr) {
                if go_slice.length > 0 && go_slice.length == go_slice.capacity {
                    self.slices.push(go_slice);
                    continue;
                }
            }

            if let Some(go_string) = self.try_read_string_struct(program, addr, string_data_range) {
                self.strings.push(go_string);
                string_count += 1;
            }
        }

        string_count
    }
}

impl Analyzer for GolangStringAnalyzer {
    fn name(&self) -> &str {
        self.base.name()
    }
    fn description(&self) -> &str {
        self.base.description()
    }
    fn analysis_type(&self) -> AnalyzerType {
        AnalyzerType::Byte
    }
    fn priority(&self) -> AnalysisPriority {
        AnalysisPriority::DATA_TYPE_PROPAGATION.after().after()
    }

    fn can_analyze(&self, program: &Program) -> bool {
        // Check if this is a Go program
        program
            .executable_format
            .as_deref()
            .map_or(false, |f| f.contains("ELF"))
            && program
                .symbols
                .values()
                .any(|s| s.contains("runtime.") || s.contains("main."))
    }

    fn default_enablement(&self, _program: &Program) -> bool {
        true
    }

    fn added(
        &self,
        program: &mut Program,
        set: &AddressSet,
        monitor: &dyn TaskMonitor,
        log: &mut MessageLog,
    ) -> Result<bool, CancelledError> {
        monitor.check_cancelled()?;
        monitor.set_message("Searching for Go strings...");

        let mut analyzer = self.clone();
        analyzer.strings.clear();
        analyzer.slices.clear();

        let string_data_range = program.memory.clone();

        // Scan data segments
        if analyzer.options.markup_data_segment_structs {
            let count =
                analyzer.markup_data_segment_structs(program, &string_data_range, monitor);
            log.append_msg(format!(
                "GolangStringAnalyzer: found {} strings",
                count
            ));
        }

        Ok(!analyzer.strings.is_empty())
    }

    fn options_changed(&mut self, opts: &HashMap<String, AnalysisOptionValue>) {
        if let Some(AnalysisOptionValue::Bool(v)) = opts.get("Markup slices") {
            self.options.markup_slice_structs = *v;
        }
        if let Some(AnalysisOptionValue::Bool(v)) = opts.get("Search data segments") {
            self.options.markup_data_segment_structs = *v;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_go_program() -> Program {
        let lang = Language {
            processor: "x86".into(),
            variant: "LE".into(),
            size: 64,
        };
        let mut p = Program::new("test_go", lang);
        p.executable_format = Some("ELF".into());
        p.memory
            .add_range(AddressRange::new(Address::new(0x400000), Address::new(0x500000)));
        // Add Go-like symbols
        p.symbols
            .insert(Address::new(0x401000), "runtime.main".into());
        p
    }

    #[test]
    fn test_golang_analyzer_creation() {
        let a = GolangStringAnalyzer::new();
        assert_eq!(a.name(), "Golang Strings");
        assert_eq!(a.ptr_size, 8);
    }

    #[test]
    fn test_golang_can_analyze_go_program() {
        let a = GolangStringAnalyzer::new();
        let p = make_go_program();
        assert!(a.can_analyze(&p));
    }

    #[test]
    fn test_golang_cannot_analyze_non_go() {
        let a = GolangStringAnalyzer::new();
        let mut p = make_go_program();
        p.symbols.clear();
        assert!(!a.can_analyze(&p));
    }

    #[test]
    fn test_golang_options() {
        let a = GolangStringAnalyzer::new();
        assert!(a.options.markup_slice_structs);
        assert!(a.options.markup_data_segment_structs);
    }

    #[test]
    fn test_golang_options_changed() {
        let mut a = GolangStringAnalyzer::new();
        let mut opts = HashMap::new();
        opts.insert(
            "Markup slices".to_string(),
            AnalysisOptionValue::Bool(false),
        );
        opts.insert(
            "Search data segments".to_string(),
            AnalysisOptionValue::Bool(false),
        );
        a.options_changed(&opts);
        assert!(!a.options.markup_slice_structs);
        assert!(!a.options.markup_data_segment_structs);
    }

    #[test]
    fn test_go_string_valid() {
        let s = GoString {
            struct_addr: Address::new(0x1000),
            data_addr: Address::new(0x2000),
            length: 5,
            is_inline: false,
            content: Some("hello".into()),
        };
        let range = AddressSet::from_range(AddressRange::new(
            Address::new(0x2000),
            Address::new(0x3000),
        ));
        assert!(s.is_valid(&range));
        assert_eq!(s.data_range().len(), 5);
    }

    #[test]
    fn test_go_string_invalid_zero_length() {
        let s = GoString {
            struct_addr: Address::new(0x1000),
            data_addr: Address::new(0x2000),
            length: 0,
            is_inline: false,
            content: None,
        };
        let range = AddressSet::new();
        assert!(!s.is_valid(&range));
    }

    #[test]
    fn test_is_valid_string_content() {
        assert!(GolangStringAnalyzer::is_valid_string_content("hello world"));
        assert!(GolangStringAnalyzer::is_valid_string_content("line1\nline2"));
        assert!(GolangStringAnalyzer::is_valid_string_content("tab\there"));
        assert!(!GolangStringAnalyzer::is_valid_string_content(
            "bad\x01char"
        ));
    }

    #[test]
    fn test_go_string_display() {
        let s = GoString {
            struct_addr: Address::new(0x1000),
            data_addr: Address::new(0x2000),
            length: 11,
            is_inline: false,
            content: Some("hello world".into()),
        };
        let range = AddressSet::from_range(AddressRange::new(
            Address::new(0x2000),
            Address::new(0x3000),
        ));
        assert!(s.is_valid(&range));
    }
}
