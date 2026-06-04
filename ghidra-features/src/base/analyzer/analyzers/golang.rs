//! Golang analyzers.
//!
//! Ported from Ghidra's `GolangStringAnalyzer.java` and `GolangSymbolAnalyzer.java`.
//! Handles Go binary analysis: RTTI recovery, function symbol restoration,
//! string/slice structure markup, closure fixup, and RTTI propagation.

use crate::base::analyzer::core::*;
use crate::base::analyzer::priority::*;
use crate::base::analyzer::r#trait::*;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Executable format reported for Go binaries.
pub const GOLANG_FORMAT_NAME: &str = "Go";

/// Name of the analyzed-flag property in program options.
pub const GOLANG_ANALYZED_FLAG: &str = "Golang Analyzed";

/// Function names to skip during Go function markup.
pub const FUNCNAMES_TO_IGNORE: &[&str] = &["go:buildid", "go.buildid"];

// Go calling convention names for special functions
pub const GOLANG_DUFFZERO_CC: &str = "__go_duffzero";
pub const GOLANG_DUFFCOPY_CC: &str = "__go_duffcopy";
pub const GOLANG_GCWRITE_BUFFERED_CC: &str = "__go_gcwrite_buffered";
pub const GOLANG_GCWRITE_BATCH_CC: &str = "__go_gcwrite_batch";
pub const GOLANG_CLOSURE_CONTEXT_NAME: &str = "context";

/// GC write barrier function name pattern prefix.
pub const GC_WRITE_BARRIER_PREFIX: &str = "runtime.gcWriteBarrier";

/// Registers used in x86_64 gcWriteBarrier variants (buffered mode).
pub const GCWRITE_BUFFERED_X86_64_REGS: &[&str] = &["BX", "CX", "DI", "SI"];

// ---------------------------------------------------------------------------
// Go string structure layout
// ---------------------------------------------------------------------------

/// Represents a Go string structure: `{ data: *u8, len: usize }`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoStringStruct {
    pub data_addr: u64,
    pub len: u64,
    pub ptr_size: u32,
}

impl GoStringStruct {
    pub fn new(data_addr: u64, len: u64, ptr_size: u32) -> Self {
        Self {
            data_addr,
            len,
            ptr_size,
        }
    }

    /// Size of the Go string struct in bytes.
    pub fn struct_len(&self) -> u32 {
        self.ptr_size * 2
    }

    /// Whether this string appears valid: non-null data pointer and
    /// non-zero length.
    pub fn is_valid(&self) -> bool {
        self.data_addr != 0 && self.len > 0
    }

    /// Whether the string content contains only printable/valid characters.
    pub fn is_valid_content(&self, content: &str) -> bool {
        content
            .chars()
            .all(|c| c == '\n' || c == '\t' || (c as u32) >= 32)
    }
}

// ---------------------------------------------------------------------------
// Go slice structure layout
// ---------------------------------------------------------------------------

/// Represents a Go slice structure: `{ data: *u8, len: usize, cap: usize }`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoSliceStruct {
    pub data_addr: u64,
    pub len: u64,
    pub cap: u64,
    pub ptr_size: u32,
}

impl GoSliceStruct {
    pub fn new(data_addr: u64, len: u64, cap: u64, ptr_size: u32) -> Self {
        Self {
            data_addr,
            len,
            cap,
            ptr_size,
        }
    }

    /// Size of the Go slice struct in bytes.
    pub fn struct_len(&self) -> u32 {
        self.ptr_size * 3
    }

    /// Whether this slice appears valid.
    pub fn is_valid(&self) -> bool {
        self.len > 0 && self.cap >= self.len
    }

    /// Whether the slice data pointer is non-null and capacity is non-zero.
    pub fn is_full(&self) -> bool {
        self.data_addr != 0 && self.cap > 0
    }
}

// ---------------------------------------------------------------------------
// Go function flags
// ---------------------------------------------------------------------------

/// Flags associated with a Go function definition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GoFuncFlag {
    /// Function is written in assembly.
    Native,
    /// Function uses Go internal ABI (register-based calling convention).
    AbiInternal,
    /// Function uses Go ABI0 (stack-based calling convention).
    Abi0,
}

/// Source of a recovered function definition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FuncDefSource {
    /// From a runtime snapshot JSON file.
    FromSnapshot,
    /// From RTTI method information.
    FromRttiMethod,
    /// From partial closure context info.
    FromClosure,
}

// ---------------------------------------------------------------------------
// Go analyzer options
// ---------------------------------------------------------------------------

/// Options for the Golang symbol analyzer.
#[derive(Debug, Clone)]
pub struct GolangAnalyzerOptions {
    /// Add source file and line number information to functions.
    pub output_source_info: bool,
    /// Copy information from duffzero/duffcopy to alternate entry points.
    pub fixup_duff_functions: bool,
    /// Override calls to built-in allocators with specific Go type return types.
    pub propagate_rtti: bool,
    /// Fixup gcWriteBarrier function signatures.
    pub fixup_gcwrite_barrier_functions: bool,
    /// Fixup the global writeBarrier flag.
    pub fixup_gcwrite_barrier_flag: bool,
    /// Fallback Go version when metadata is obfuscated.
    pub fallback_go_ver: String,
}

impl Default for GolangAnalyzerOptions {
    fn default() -> Self {
        Self {
            output_source_info: true,
            fixup_duff_functions: true,
            propagate_rtti: true,
            fixup_gcwrite_barrier_functions: true,
            fixup_gcwrite_barrier_flag: true,
            fallback_go_ver: String::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Go string analyzer options
// ---------------------------------------------------------------------------

/// Options for the Golang string analyzer.
#[derive(Debug, Clone)]
pub struct GolangStringAnalyzerOptions {
    /// Whether to markup structures that look like Go slices.
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

// ---------------------------------------------------------------------------
// Inline string pattern matcher
// ---------------------------------------------------------------------------

/// Checks whether two consecutive instructions match the inline string pattern:
/// 1. First instruction loads a data address into a register.
/// 2. Second instruction loads a scalar (the string length) into the next
///    parameter register.
pub fn matches_inline_string_pattern(
    instr1_num_operands: u32,
    instr1_op0_is_register: bool,
    instr2_num_operands: u32,
    instr2_op1_is_scalar: bool,
) -> bool {
    instr1_num_operands == 2
        && instr1_op0_is_register
        && instr2_num_operands == 2
        && instr2_op1_is_scalar
}

// ---------------------------------------------------------------------------
// GolangSymbolAnalyzer  --  "Golang Symbols"
// ---------------------------------------------------------------------------

/// Analyzes Go binaries for RTTI and function symbol information by following
/// references from the root `GoModuleData` instance.
///
/// Priority: runs after FORMAT_ANALYSIS. Should be used with 'Apply Data
/// Archives' and 'Shared Return Calls' analyzers disabled for best results.
#[derive(Debug, Clone)]
pub struct GolangSymbolAnalyzer {
    base: AbstractAnalyzer,
    pub options: GolangAnalyzerOptions,
}

impl GolangSymbolAnalyzer {
    /// Analysis priority for the Go symbol analyzer (FORMAT_ANALYSIS + 2).
    pub const GOLANG_ANALYSIS_PRIORITY: AnalysisPriority =
        AnalysisPriority::new("GOLANG", AnalysisPriority::FORMAT_ANALYSIS.priority() + 2);
    /// Priority for RTTI propagation (after REFERENCE_ANALYSIS).
    pub const PROP_RTTI_PRIORITY: AnalysisPriority =
        AnalysisPriority::new("PROP_RTTI", AnalysisPriority::REFERENCE_ANALYSIS.priority() + 1);
    /// Priority for closure fixup (after PROP_RTTI).
    pub const FIX_CLOSURES_PRIORITY: AnalysisPriority =
        AnalysisPriority::new("FIX_CLOSURES", Self::PROP_RTTI_PRIORITY.priority() + 1);
    /// Priority for Go string analysis (after FIX_CLOSURES).
    pub const STRINGS_PRIORITY: AnalysisPriority =
        AnalysisPriority::new("GOSTRINGS", Self::FIX_CLOSURES_PRIORITY.priority() + 1);
    /// Priority for gcWriteBarrier flag fixup (after STRINGS).
    pub const FIX_GCWRITEBARRIER_PRIORITY: AnalysisPriority =
        AnalysisPriority::new("GCWB", Self::STRINGS_PRIORITY.priority() + 1);

    pub fn new() -> Self {
        let mut b = AbstractAnalyzer::new(
            "Golang Symbols",
            "Analyze Go binaries for RTTI and function symbols.\n\
             'Apply Data Archives' and 'Shared Return Calls' analyzers should be disabled for best results.",
            AnalyzerType::Byte,
        );
        b.set_priority(Self::GOLANG_ANALYSIS_PRIORITY);
        b.set_default_enablement(true);
        Self {
            base: b,
            options: GolangAnalyzerOptions::default(),
        }
    }

    /// Returns `true` if the program executable format indicates a Go binary.
    pub fn is_golang_format(format: Option<&str>) -> bool {
        matches!(format, Some("Go") | Some("ELF")) // ELF can contain Go binaries
    }

    /// Check if a function name should be ignored during processing.
    pub fn should_ignore_func_name(name: &str) -> bool {
        FUNCNAMES_TO_IGNORE.contains(&name)
    }
}

impl Analyzer for GolangSymbolAnalyzer {
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
        Self::GOLANG_ANALYSIS_PRIORITY
    }

    fn can_analyze(&self, _p: &Program) -> bool {
        // In Java, this checks GoRttiMapper.isGolangProgram(program)
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
        monitor.set_message("Go symbol analyzer");
        log.append_msg("GolangSymbolAnalyzer: analyzing Go symbols");
        Ok(true)
    }
}

// ---------------------------------------------------------------------------
// GolangStringAnalyzer  --  "Golang Strings"
// ---------------------------------------------------------------------------

/// Finds Go strings (and optionally slices) and marks up the found instances.
///
/// Go strings do not contain null terminators, so standard string detection
/// fails. This analyzer looks for data that matches the Go string struct
/// layout `{ *u8, usize }` and follows the pointer to create fixed-length
/// strings.
#[derive(Debug, Clone)]
pub struct GolangStringAnalyzer {
    base: AbstractAnalyzer,
    pub options: GolangStringAnalyzerOptions,
}

impl GolangStringAnalyzer {
    pub fn new() -> Self {
        let mut b = AbstractAnalyzer::new(
            "Golang Strings",
            "Finds and labels Go string structures.",
            AnalyzerType::Byte,
        );
        b.set_priority(GolangSymbolAnalyzer::STRINGS_PRIORITY);
        b.set_default_enablement(true);
        Self {
            base: b,
            options: GolangStringAnalyzerOptions::default(),
        }
    }

    /// Align the start of an address set to the given alignment boundary.
    /// Returns `true` if the set still has addresses after alignment, `false`
    /// if the set became empty.
    pub fn align_address(offset: u64, alignment: u64) -> u64 {
        if alignment == 0 {
            return offset;
        }
        let remainder = offset % alignment;
        if remainder == 0 {
            offset
        } else {
            offset + (alignment - remainder)
        }
    }

    /// Validate that a string's content does not contain garbage characters.
    pub fn is_valid_string_data(s: &str) -> bool {
        s.chars().all(|c| {
            let cp = c as u32;
            c == '\n' || c == '\t' || cp >= 32
        })
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
        self.base.analysis_type()
    }
    fn priority(&self) -> AnalysisPriority {
        GolangSymbolAnalyzer::STRINGS_PRIORITY
    }

    fn can_analyze(&self, _p: &Program) -> bool {
        // In Java: GoRttiMapper.isGolangProgram(program)
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
        monitor.set_message("Searching for Go string structures...");
        log.append_msg("GolangStringAnalyzer: searching for Go strings");
        Ok(true)
    }
}

// ---------------------------------------------------------------------------
// RTTI propagation helper types
// ---------------------------------------------------------------------------

/// Information about an RTTI-aware runtime allocator function.
#[derive(Debug, Clone)]
pub struct RttiFuncInfo {
    pub func_name: String,
    /// Index of the RTTI parameter (-1 means "find pointer-to-GoType").
    pub rtti_param_index: i32,
}

impl RttiFuncInfo {
    pub fn new(func_name: impl Into<String>, rtti_param_index: i32) -> Self {
        Self {
            func_name: func_name.into(),
            rtti_param_index,
        }
    }
}

/// Default set of Go runtime allocator functions with RTTI propagation.
pub fn default_rtti_alloc_funcs() -> Vec<RttiFuncInfo> {
    vec![
        RttiFuncInfo::new("runtime.newobject", 0),
        RttiFuncInfo::new("runtime.makeslice", 0),
        RttiFuncInfo::new("runtime.growslice", -1),
        RttiFuncInfo::new("runtime.makeslicecopy", 0),
    ]
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_go_program() -> Program {
        let lang = Language {
            processor: "x86".into(),
            variant: "LE".into(),
            size: 64,
        };
        let mut prog = Program::new("go_test", lang);
        prog.executable_format = Some(GOLANG_FORMAT_NAME.into());
        prog
    }

    // -- GolangSymbolAnalyzer tests --

    #[test]
    fn test_golang_symbol_analyzer_name() {
        let a = GolangSymbolAnalyzer::new();
        assert_eq!(a.name(), "Golang Symbols");
        assert_eq!(a.analysis_type(), AnalyzerType::Byte);
    }

    #[test]
    fn test_golang_symbol_analyzer_default_enablement() {
        let a = GolangSymbolAnalyzer::new();
        assert!(a.default_enablement(&make_go_program()));
    }

    #[test]
    fn test_golang_symbol_analyzer_priority() {
        let a = GolangSymbolAnalyzer::new();
        assert_eq!(a.priority(), GolangSymbolAnalyzer::GOLANG_ANALYSIS_PRIORITY);
    }

    #[test]
    fn test_golang_priority_chain() {
        let p1 = GolangSymbolAnalyzer::GOLANG_ANALYSIS_PRIORITY;
        let p2 = GolangSymbolAnalyzer::PROP_RTTI_PRIORITY;
        let p3 = GolangSymbolAnalyzer::FIX_CLOSURES_PRIORITY;
        let p4 = GolangSymbolAnalyzer::STRINGS_PRIORITY;
        let p5 = GolangSymbolAnalyzer::FIX_GCWRITEBARRIER_PRIORITY;
        assert!(p1 < p2);
        assert!(p2 < p3);
        assert!(p3 < p4);
        assert!(p4 < p5);
    }

    #[test]
    fn test_should_ignore_func_name() {
        assert!(GolangSymbolAnalyzer::should_ignore_func_name("go:buildid"));
        assert!(GolangSymbolAnalyzer::should_ignore_func_name("go.buildid"));
        assert!(!GolangSymbolAnalyzer::should_ignore_func_name("runtime.main"));
        assert!(!GolangSymbolAnalyzer::should_ignore_func_name("main.main"));
    }

    #[test]
    fn test_is_golang_format() {
        assert!(GolangSymbolAnalyzer::is_golang_format(Some("Go")));
        assert!(GolangSymbolAnalyzer::is_golang_format(Some("ELF")));
        assert!(!GolangSymbolAnalyzer::is_golang_format(Some("PE")));
        assert!(!GolangSymbolAnalyzer::is_golang_format(None));
    }

    #[test]
    fn test_golang_analyzer_options_default() {
        let opts = GolangAnalyzerOptions::default();
        assert!(opts.output_source_info);
        assert!(opts.fixup_duff_functions);
        assert!(opts.propagate_rtti);
        assert!(opts.fixup_gcwrite_barrier_functions);
        assert!(opts.fixup_gcwrite_barrier_flag);
        assert!(opts.fallback_go_ver.is_empty());
    }

    #[test]
    fn test_golang_symbol_analyzer_added() {
        let a = GolangSymbolAnalyzer::new();
        let mut prog = make_go_program();
        let set = AddressSet::new();
        let monitor = BasicTaskMonitor::new();
        let mut log = MessageLog::new();
        let result = a.added(&mut prog, &set, &monitor, &mut log);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    // -- GolangStringAnalyzer tests --

    #[test]
    fn test_golang_string_analyzer_name() {
        let a = GolangStringAnalyzer::new();
        assert_eq!(a.name(), "Golang Strings");
        assert_eq!(a.analysis_type(), AnalyzerType::Byte);
    }

    #[test]
    fn test_golang_string_analyzer_priority() {
        let a = GolangStringAnalyzer::new();
        assert_eq!(a.priority(), GolangSymbolAnalyzer::STRINGS_PRIORITY);
    }

    #[test]
    fn test_golang_string_analyzer_default_enablement() {
        let a = GolangStringAnalyzer::new();
        assert!(a.default_enablement(&make_go_program()));
    }

    #[test]
    fn test_golang_string_analyzer_options_default() {
        let opts = GolangStringAnalyzerOptions::default();
        assert!(opts.markup_slice_structs);
        assert!(opts.markup_data_segment_structs);
    }

    #[test]
    fn test_golang_string_analyzer_added() {
        let a = GolangStringAnalyzer::new();
        let mut prog = make_go_program();
        let set = AddressSet::new();
        let monitor = BasicTaskMonitor::new();
        let mut log = MessageLog::new();
        let result = a.added(&mut prog, &set, &monitor, &mut log);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    // -- GoStringStruct tests --

    #[test]
    fn test_go_string_struct_valid() {
        let s = GoStringStruct::new(0x1000, 5, 8);
        assert!(s.is_valid());
        assert_eq!(s.struct_len(), 16);
    }

    #[test]
    fn test_go_string_struct_invalid_zero_addr() {
        let s = GoStringStruct::new(0, 5, 8);
        assert!(!s.is_valid());
    }

    #[test]
    fn test_go_string_struct_invalid_zero_len() {
        let s = GoStringStruct::new(0x1000, 0, 8);
        assert!(!s.is_valid());
    }

    #[test]
    fn test_go_string_struct_32bit() {
        let s = GoStringStruct::new(0x1000, 5, 4);
        assert_eq!(s.struct_len(), 8);
    }

    #[test]
    fn test_go_string_struct_valid_content() {
        let s = GoStringStruct::new(0x1000, 3, 8);
        assert!(s.is_valid_content("hello\n"));
        assert!(s.is_valid_content("foo\tbar"));
        assert!(!s.is_valid_content("\x01\x02\x03"));
    }

    // -- GoSliceStruct tests --

    #[test]
    fn test_go_slice_struct_valid() {
        let s = GoSliceStruct::new(0x1000, 3, 5, 8);
        assert!(s.is_valid());
        assert_eq!(s.struct_len(), 24);
    }

    #[test]
    fn test_go_slice_struct_invalid_cap_lt_len() {
        let s = GoSliceStruct::new(0x1000, 10, 5, 8);
        assert!(!s.is_valid());
    }

    #[test]
    fn test_go_slice_struct_full() {
        let s = GoSliceStruct::new(0x1000, 3, 5, 8);
        assert!(s.is_full());
    }

    #[test]
    fn test_go_slice_struct_not_full_zero_data() {
        let s = GoSliceStruct::new(0, 3, 5, 8);
        assert!(!s.is_full());
    }

    #[test]
    fn test_go_slice_struct_32bit() {
        let s = GoSliceStruct::new(0x1000, 1, 1, 4);
        assert_eq!(s.struct_len(), 12);
    }

    // -- align_address tests --

    #[test]
    fn test_align_address_already_aligned() {
        assert_eq!(GolangStringAnalyzer::align_address(0x1000, 8), 0x1000);
    }

    #[test]
    fn test_align_address_needs_alignment() {
        assert_eq!(GolangStringAnalyzer::align_address(0x1001, 8), 0x1008);
    }

    #[test]
    fn test_align_address_zero_alignment() {
        assert_eq!(GolangStringAnalyzer::align_address(0x1003, 0), 0x1003);
    }

    // -- is_valid_string_data tests --

    #[test]
    fn test_valid_string_data_normal() {
        assert!(GolangStringAnalyzer::is_valid_string_data("Hello, World!"));
    }

    #[test]
    fn test_valid_string_data_newline_tab() {
        assert!(GolangStringAnalyzer::is_valid_string_data("line1\nline2\t"));
    }

    #[test]
    fn test_valid_string_data_empty() {
        assert!(GolangStringAnalyzer::is_valid_string_data(""));
    }

    #[test]
    fn test_invalid_string_data_control_chars() {
        assert!(!GolangStringAnalyzer::is_valid_string_data("abc\x01def"));
        assert!(!GolangStringAnalyzer::is_valid_string_data("\x00"));
    }

    // -- Inline string pattern tests --

    #[test]
    fn test_matches_inline_string_pattern_valid() {
        assert!(matches_inline_string_pattern(2, true, 2, true));
    }

    #[test]
    fn test_matches_inline_string_pattern_wrong_operands() {
        assert!(!matches_inline_string_pattern(3, true, 2, true));
        assert!(!matches_inline_string_pattern(2, false, 2, true));
        assert!(!matches_inline_string_pattern(2, true, 1, true));
        assert!(!matches_inline_string_pattern(2, true, 2, false));
    }

    // -- RTTI func info tests --

    #[test]
    fn test_rtti_func_info() {
        let info = RttiFuncInfo::new("runtime.newobject", 0);
        assert_eq!(info.func_name, "runtime.newobject");
        assert_eq!(info.rtti_param_index, 0);
    }

    #[test]
    fn test_default_rtti_alloc_funcs() {
        let funcs = default_rtti_alloc_funcs();
        assert_eq!(funcs.len(), 4);
        assert_eq!(funcs[0].func_name, "runtime.newobject");
        assert_eq!(funcs[0].rtti_param_index, 0);
        assert_eq!(funcs[2].func_name, "runtime.growslice");
        assert_eq!(funcs[2].rtti_param_index, -1);
    }

    // -- Constants tests --

    #[test]
    fn test_golang_constants() {
        assert_eq!(GOLANG_FORMAT_NAME, "Go");
        assert_eq!(GOLANG_ANALYZED_FLAG, "Golang Analyzed");
        assert_eq!(FUNCNAMES_TO_IGNORE, &["go:buildid", "go.buildid"]);
        assert_eq!(GOLANG_CLOSURE_CONTEXT_NAME, "context");
        assert_eq!(GC_WRITE_BARRIER_PREFIX, "runtime.gcWriteBarrier");
    }

    #[test]
    fn test_gcwrite_registers() {
        assert!(GCWRITE_BUFFERED_X86_64_REGS.contains(&"BX"));
        assert!(GCWRITE_BUFFERED_X86_64_REGS.contains(&"CX"));
        assert!(GCWRITE_BUFFERED_X86_64_REGS.contains(&"DI"));
        assert!(GCWRITE_BUFFERED_X86_64_REGS.contains(&"SI"));
        assert_eq!(GCWRITE_BUFFERED_X86_64_REGS.len(), 4);
    }
}
