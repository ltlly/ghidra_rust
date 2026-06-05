// ===========================================================================
// Symbol & Function Analyzers -- ported from Ghidra's
// `ghidra.app.plugin.core.analysis` package.
//
// Includes:
// - NoReturnFunctionAnalyzer          -- marks non-returning functions
// - GolangStringAnalyzer              -- discovers Go string data
// - GolangSymbolAnalyzer              -- discovers Go runtime symbols
// - ArmSymbolAnalyzer                 -- ARM-specific symbol analysis
// - DwAnalyzer                        -- DWARF debug info analysis
// - RegisterContextBuilder            -- builds register context from analysis
// ===========================================================================

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use ghidra_core::Address;

/// A discovered symbol.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DiscoveredSymbol {
    /// The address of the symbol.
    pub address: Address,
    /// The symbol name.
    pub name: String,
    /// The namespace/scope (e.g., library name).
    pub namespace: Option<String>,
    /// Whether this is a function symbol.
    pub is_function: bool,
}

// ---------------------------------------------------------------------------
// NoReturnFunctionAnalyzer
// ---------------------------------------------------------------------------

/// Identifies functions that do not return (e.g., `exit`, `abort`, `panic`)
/// and marks them accordingly in the program.
///
/// Ported from `ghidra.app.plugin.core.analysis.NoReturnFunctionAnalyzer`.
#[derive(Debug, Clone)]
pub struct NoReturnFunctionAnalyzer {
    /// Name of this analyzer.
    pub name: String,
    /// Whether the analyzer is enabled.
    pub enabled: bool,
    /// Known non-returning function names (case-insensitive).
    pub known_noreturn_names: HashSet<String>,
    /// Discovered non-returning function addresses.
    pub noreturn_functions: BTreeSet<Address>,
    /// Whether to also analyze call graph to propagate no-return.
    pub propagate_through_callgraph: bool,
}

impl NoReturnFunctionAnalyzer {
    /// Create a new analyzer with common non-returning function names.
    pub fn new() -> Self {
        let known: HashSet<String> = [
            "exit", "_exit", "abort", "_abort", "ExitProcess", "ExitThread",
            "TerminateProcess", "TerminateThread", "longjmp", "_longjmp",
            "siglongjmp", "__stack_chk_fail", "panic", "fatal", "die",
            "unreachable", "__builtin_unreachable", "Throw", "_CxxThrowException",
            "RtlExitUserThread", "NtTerminateProcess", "ZwTerminateProcess",
            "exit_group", "tkill", "tgkill",
        ]
        .iter()
        .map(|s| s.to_lowercase())
        .collect();

        Self {
            name: "No Return Function Analyzer".into(),
            enabled: true,
            known_noreturn_names: known,
            noreturn_functions: BTreeSet::new(),
            propagate_through_callgraph: true,
        }
    }

    /// Check if a function name is known to be non-returning.
    pub fn is_known_noreturn(&self, name: &str) -> bool {
        self.known_noreturn_names.contains(&name.to_lowercase())
    }

    /// Add a known non-returning function name.
    pub fn add_known_noreturn(&mut self, name: impl Into<String>) {
        self.known_noreturn_names.insert(name.into().to_lowercase());
    }

    /// Mark a function address as non-returning.
    pub fn mark_noreturn(&mut self, addr: Address) {
        self.noreturn_functions.insert(addr);
    }

    /// Check if a function address has been marked non-returning.
    pub fn is_noreturn(&self, addr: &Address) -> bool {
        self.noreturn_functions.contains(addr)
    }

    /// Analyze a list of (address, function_name) pairs and return those
    /// that should be marked as non-returning.
    pub fn analyze_functions(
        &mut self,
        functions: &[(Address, &str)],
    ) -> Vec<Address> {
        let mut result = Vec::new();
        for (addr, name) in functions {
            if self.is_known_noreturn(name) {
                self.noreturn_functions.insert(*addr);
                result.push(*addr);
            }
        }
        result
    }

    /// Propagate no-return through the call graph. If a function's only
    /// exit path calls a non-returning function, it is also non-returning.
    pub fn propagate_noreturn(
        &mut self,
        call_graph: &BTreeMap<Address, Vec<Address>>,
    ) -> Vec<Address> {
        let mut newly_marked = Vec::new();
        let mut changed = true;

        while changed {
            changed = false;
            for (caller, callees) in call_graph {
                if self.noreturn_functions.contains(caller) {
                    continue;
                }
                // If every callee is noreturn (or empty -- unreachable), mark caller.
                if !callees.is_empty()
                    && callees.iter().all(|c| self.noreturn_functions.contains(c))
                {
                    self.noreturn_functions.insert(*caller);
                    newly_marked.push(*caller);
                    changed = true;
                }
            }
        }

        newly_marked
    }

    /// Get the total number of known non-returning function names.
    pub fn known_name_count(&self) -> usize {
        self.known_noreturn_names.len()
    }
}

impl Default for NoReturnFunctionAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// GolangStringAnalyzer
// ---------------------------------------------------------------------------

/// Discovers Go string data structures in binaries.
///
/// Go strings are represented as a `(pointer, length)` pair. This analyzer
/// scans for such pairs in read-only data sections.
///
/// Ported from `ghidra.app.plugin.core.analysis.GolangStringAnalyzer`.
#[derive(Debug, Clone)]
pub struct GolangStringAnalyzer {
    /// Name of this analyzer.
    pub name: String,
    /// Whether the analyzer is enabled.
    pub enabled: bool,
    /// Minimum string length to discover.
    pub min_string_length: usize,
    /// Maximum string length to discover.
    pub max_string_length: usize,
    /// Whether the binary is 64-bit (affects pointer size).
    pub is_64bit: bool,
    /// Discovered Go strings: address -> (string_content, length).
    pub discovered: BTreeMap<Address, (String, usize)>,
}

impl GolangStringAnalyzer {
    /// Create a new analyzer.
    pub fn new() -> Self {
        Self {
            name: "Golang String Analyzer".into(),
            enabled: true,
            min_string_length: 3,
            max_string_length: 10_000,
            is_64bit: true,
            discovered: BTreeMap::new(),
        }
    }

    /// Get the pointer size based on bitness.
    pub fn pointer_size(&self) -> usize {
        if self.is_64bit { 8 } else { 4 }
    }

    /// Analyze a data region for Go string pairs.
    ///
    /// `data` is the raw bytes at `base_address`. The analyzer scans for
    /// (pointer, length) pairs where the pointer points to valid ASCII/UTF-8
    /// data of the given length.
    pub fn analyze(
        &mut self,
        base_address: Address,
        data: &[u8],
        memory_regions: &BTreeMap<u64, &[u8]>,
    ) -> Vec<Address> {
        let ptr_size = self.pointer_size();
        let pair_size = ptr_size * 2;
        let mut found = Vec::new();

        if data.len() < pair_size {
            return found;
        }

        let mut offset = 0;
        while offset + pair_size <= data.len() {
            let ptr_value = if self.is_64bit {
                u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap_or([0; 8]))
            } else {
                u32::from_le_bytes(
                    data[offset..offset + 4].try_into().unwrap_or([0; 4]),
                ) as u64
            };

            let len_value = if self.is_64bit {
                u64::from_le_bytes(
                    data[offset + ptr_size..offset + ptr_size + 8]
                        .try_into()
                        .unwrap_or([0; 8]),
                ) as usize
            } else {
                u32::from_le_bytes(
                    data[offset + ptr_size..offset + ptr_size + 4]
                        .try_into()
                        .unwrap_or([0; 4]),
                ) as usize
            };

            if len_value >= self.min_string_length
                && len_value <= self.max_string_length
                && ptr_value > 0
            {
                // Check if the pointer points to valid memory.
                if let Some(region) = memory_regions.get(&ptr_value) {
                    if region.len() >= len_value {
                        let str_bytes = &region[..len_value];
                        if is_valid_utf8(str_bytes) {
                            let s = String::from_utf8_lossy(str_bytes).to_string();
                            let addr = Address::new(base_address.offset + offset as u64);
                            self.discovered.insert(addr, (s, len_value));
                            found.push(addr);
                        }
                    }
                }
            }

            offset += ptr_size; // Advance by pointer size, not pair size.
        }

        found
    }
}

impl Default for GolangStringAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// GolangSymbolAnalyzer
// ---------------------------------------------------------------------------

/// Discovers Go runtime symbols (e.g., `runtime.main`, `runtime.mallocgc`)
/// from the Go symbol table and pclntab.
///
/// Ported from `ghidra.app.plugin.core.analysis.GolangSymbolAnalyzer`.
#[derive(Debug, Clone)]
pub struct GolangSymbolAnalyzer {
    /// Name of this analyzer.
    pub name: String,
    /// Whether the analyzer is enabled.
    pub enabled: bool,
    /// Discovered Go symbols.
    pub symbols: Vec<DiscoveredSymbol>,
    /// Whether the pclntab has been found.
    pub pclntab_found: bool,
    /// Address of the pclntab (if found).
    pub pclntab_address: Option<Address>,
    /// Go version string (if discovered).
    pub go_version: Option<String>,
}

impl GolangSymbolAnalyzer {
    /// Create a new analyzer.
    pub fn new() -> Self {
        Self {
            name: "Golang Symbol Analyzer".into(),
            enabled: true,
            symbols: Vec::new(),
            pclntab_found: false,
            pclntab_address: None,
            go_version: None,
        }
    }

    /// Search for the pclntab magic bytes in a data region.
    ///
    /// Go pclntab starts with specific magic bytes depending on version.
    pub fn find_pclntab(&mut self, data: &[u8], base_offset: u64) -> Option<Address> {
        // Common pclntab magic values for different Go versions.
        let magics: &[&[u8]] = &[
            &[0xf1, 0xff, 0xff, 0xff], // Go 1.2+
            &[0xf0, 0xff, 0xff, 0xff], // Go 1.16-1.17
            &[0xfa, 0xff, 0xff, 0xff], // Go 1.18+
            &[0xfb, 0xff, 0xff, 0xff], // Go 1.20+
        ];

        for magic in magics {
            for i in 0..data.len().saturating_sub(magic.len()) {
                if &data[i..i + magic.len()] == *magic {
                    let addr = Address::new(base_offset + i as u64);
                    self.pclntab_found = true;
                    self.pclntab_address = Some(addr);
                    return Some(addr);
                }
            }
        }

        None
    }

    /// Add a discovered symbol.
    pub fn add_symbol(&mut self, symbol: DiscoveredSymbol) {
        self.symbols.push(symbol);
    }

    /// Get the number of discovered symbols.
    pub fn symbol_count(&self) -> usize {
        self.symbols.len()
    }
}

impl Default for GolangSymbolAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// ArmSymbolAnalyzer
// ---------------------------------------------------------------------------

/// Performs ARM-specific symbol analysis, including detection of ARM/Thumb
/// mode switches and veneer (PLT) entries.
///
/// Ported from `ghidra.app.plugin.core.analysis.ArmSymbolAnalyzer`.
#[derive(Debug, Clone)]
pub struct ArmSymbolAnalyzer {
    /// Name of this analyzer.
    pub name: String,
    /// Whether the analyzer is enabled.
    pub enabled: bool,
    /// Addresses identified as Thumb-mode functions.
    pub thumb_functions: BTreeSet<Address>,
    /// Addresses identified as ARM-mode functions.
    pub arm_functions: BTreeSet<Address>,
    /// Detected veneer entries (PLT stubs).
    pub veneers: BTreeMap<Address, Address>,
}

impl ArmSymbolAnalyzer {
    /// Create a new analyzer.
    pub fn new() -> Self {
        Self {
            name: "ARM Symbol Analyzer".into(),
            enabled: true,
            thumb_functions: BTreeSet::new(),
            arm_functions: BTreeSet::new(),
            veneers: BTreeMap::new(),
        }
    }

    /// Mark a function address as Thumb mode.
    ///
    /// In ARM, the least-significant bit of the address indicates Thumb mode.
    pub fn mark_thumb(&mut self, addr: Address) {
        let aligned = Address::new(addr.offset & !1);
        self.thumb_functions.insert(aligned);
    }

    /// Mark a function address as ARM (32-bit) mode.
    pub fn mark_arm(&mut self, addr: Address) {
        let aligned = Address::new(addr.offset & !3);
        self.arm_functions.insert(aligned);
    }

    /// Detect if an address is Thumb mode (LSB = 1).
    pub fn is_thumb_entry(addr: Address) -> bool {
        addr.offset & 1 == 1
    }

    /// Add a veneer entry (ARM PLT stub).
    ///
    /// `veneer_addr` is the address of the veneer stub.
    /// `target_addr` is the actual function address it jumps to.
    pub fn add_veneer(&mut self, veneer_addr: Address, target_addr: Address) {
        self.veneers.insert(veneer_addr, target_addr);
    }

    /// Check if an address is a known veneer.
    pub fn is_veneer(&self, addr: &Address) -> bool {
        self.veneers.contains_key(addr)
    }

    /// Resolve a veneer to its target.
    pub fn resolve_veneer(&self, addr: &Address) -> Option<Address> {
        self.veneers.get(addr).copied()
    }
}

impl Default for ArmSymbolAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// DwAnalyzer (DWARF Debug Info Analyzer)
// ---------------------------------------------------------------------------

/// Analyzes DWARF debug information sections to discover function boundaries,
/// variables, types, and source line mappings.
///
/// Ported from `ghidra.app.plugin.core.analysis.DWARFAnalyzer`.
#[derive(Debug, Clone)]
pub struct DwAnalyzer {
    /// Name of this analyzer.
    pub name: String,
    /// Whether the analyzer is enabled.
    pub enabled: bool,
    /// DWARF version detected (2, 3, 4, or 5).
    pub dwarf_version: Option<u32>,
    /// Discovered function entries from DWARF.
    pub functions: BTreeMap<Address, DwFunctionEntry>,
    /// Discovered type entries.
    pub type_count: usize,
    /// Source file mappings.
    pub source_files: BTreeMap<String, Vec<(u64, u64)>>,
}

/// A function entry discovered from DWARF debug info.
#[derive(Debug, Clone)]
pub struct DwFunctionEntry {
    /// The function's low PC (start address).
    pub low_pc: Address,
    /// The function's high PC (end address, exclusive).
    pub high_pc: Address,
    /// The function name (from DW_AT_name).
    pub name: String,
    /// The source file path.
    pub source_file: Option<String>,
    /// The line number in the source file.
    pub source_line: Option<u32>,
    /// The linkage name (mangled name, from DW_AT_linkage_name).
    pub linkage_name: Option<String>,
}

impl DwAnalyzer {
    /// Create a new analyzer.
    pub fn new() -> Self {
        Self {
            name: "DWARF Analyzer".into(),
            enabled: true,
            dwarf_version: None,
            functions: BTreeMap::new(),
            type_count: 0,
            source_files: BTreeMap::new(),
        }
    }

    /// Add a discovered function entry.
    pub fn add_function(&mut self, entry: DwFunctionEntry) {
        self.functions.insert(entry.low_pc, entry);
    }

    /// Get the number of discovered functions.
    pub fn function_count(&self) -> usize {
        self.functions.len()
    }

    /// Set the DWARF version detected in the binary.
    pub fn set_dwarf_version(&mut self, version: u32) {
        self.dwarf_version = Some(version);
    }

    /// Add a source file mapping: file path -> (offset, line_number) pairs.
    pub fn add_source_file(&mut self, path: String, entries: Vec<(u64, u64)>) {
        self.source_files.insert(path, entries);
    }

    /// Get the total number of source file entries.
    pub fn total_source_entries(&self) -> usize {
        self.source_files.values().map(|v| v.len()).sum()
    }
}

impl Default for DwAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// RegisterContextBuilder
// ---------------------------------------------------------------------------

/// Builds register context information from analysis results, particularly
/// for processors with context-dependent instruction sets (e.g., ARM Thumb,
/// x86 real/protected mode).
///
/// Ported from `ghidra.app.plugin.core.analysis.RegisterContextBuilder`.
#[derive(Debug, Clone)]
pub struct RegisterContextBuilder {
    /// Register name -> current value.
    pub register_values: HashMap<String, u64>,
    /// Address ranges where specific context values apply.
    pub context_ranges: BTreeMap<(u64, u64), HashMap<String, u64>>,
    /// The current context register state at the analysis cursor.
    pub current_context: HashMap<String, u64>,
}

impl RegisterContextBuilder {
    /// Create a new context builder.
    pub fn new() -> Self {
        Self {
            register_values: HashMap::new(),
            context_ranges: BTreeMap::new(),
            current_context: HashMap::new(),
        }
    }

    /// Set a register value.
    pub fn set_register(&mut self, name: impl Into<String>, value: u64) {
        let name = name.into();
        self.register_values.insert(name.clone(), value);
        self.current_context.insert(name, value);
    }

    /// Get a register value.
    pub fn get_register(&self, name: &str) -> Option<u64> {
        self.current_context.get(name).copied()
    }

    /// Define a context range: a region of code where specific register
    /// context values apply.
    pub fn add_context_range(
        &mut self,
        start: u64,
        end: u64,
        context: HashMap<String, u64>,
    ) {
        self.context_ranges.insert((start, end), context);
    }

    /// Get the context that applies at a specific address.
    pub fn context_at(&self, addr: u64) -> Option<&HashMap<String, u64>> {
        for ((start, end), context) in &self.context_ranges {
            if addr >= *start && addr < *end {
                return Some(context);
            }
        }
        None
    }

    /// Get the number of defined context ranges.
    pub fn range_count(&self) -> usize {
        self.context_ranges.len()
    }

    /// Merge context from another builder.
    pub fn merge_from(&mut self, other: &RegisterContextBuilder) {
        for (name, &value) in &other.register_values {
            self.register_values.insert(name.clone(), value);
            self.current_context.insert(name.clone(), value);
        }
        for (range, context) in &other.context_ranges {
            self.context_ranges.insert(*range, context.clone());
        }
    }
}

impl Default for RegisterContextBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

/// Check if a byte slice is valid UTF-8.
fn is_valid_utf8(data: &[u8]) -> bool {
    std::str::from_utf8(data).is_ok()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_return_analyzer_known_names() {
        let analyzer = NoReturnFunctionAnalyzer::new();
        assert!(analyzer.is_known_noreturn("exit"));
        assert!(analyzer.is_known_noreturn("EXIT"));
        assert!(analyzer.is_known_noreturn("abort"));
        assert!(analyzer.is_known_noreturn("panic"));
        assert!(!analyzer.is_known_noreturn("printf"));
    }

    #[test]
    fn test_no_return_analyzer_mark() {
        let mut analyzer = NoReturnFunctionAnalyzer::new();
        analyzer.mark_noreturn(Address::new(0x400000));
        assert!(analyzer.is_noreturn(&Address::new(0x400000)));
        assert!(!analyzer.is_noreturn(&Address::new(0x400004)));
    }

    #[test]
    fn test_no_return_analyzer_propagate() {
        let mut analyzer = NoReturnFunctionAnalyzer::new();
        analyzer.mark_noreturn(Address::new(0x500000)); // exit

        let mut call_graph = BTreeMap::new();
        // my_exit only calls exit
        call_graph.insert(Address::new(0x400000), vec![Address::new(0x500000)]);
        // main calls my_exit and other
        call_graph.insert(
            Address::new(0x300000),
            vec![Address::new(0x400000), Address::new(0x600000)],
        );

        let newly_marked = analyzer.propagate_noreturn(&call_graph);
        assert!(newly_marked.contains(&Address::new(0x400000)));
        // main also calls 0x600000 which is not noreturn, so main should NOT be marked.
        assert!(!analyzer.is_noreturn(&Address::new(0x300000)));
    }

    #[test]
    fn test_no_return_analyzer_analyze_functions() {
        let mut analyzer = NoReturnFunctionAnalyzer::new();
        let functions = vec![
            (Address::new(0x400000), "main"),
            (Address::new(0x400100), "exit"),
            (Address::new(0x400200), "abort"),
        ];
        let result = analyzer.analyze_functions(&functions);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_golang_string_analyzer_pointer_size() {
        let analyzer32 = GolangStringAnalyzer {
            is_64bit: false,
            ..GolangStringAnalyzer::new()
        };
        assert_eq!(analyzer32.pointer_size(), 4);
        let analyzer64 = GolangStringAnalyzer {
            is_64bit: true,
            ..GolangStringAnalyzer::new()
        };
        assert_eq!(analyzer64.pointer_size(), 8);
    }

    #[test]
    fn test_golang_symbol_analyzer_pclntab() {
        let mut analyzer = GolangSymbolAnalyzer::new();
        let data = vec![0x00, 0x00, 0xf1, 0xff, 0xff, 0xff, 0x00, 0x00];
        let result = analyzer.find_pclntab(&data, 0x1000);
        assert!(result.is_some());
        assert_eq!(result.unwrap(), Address::new(0x1002));
        assert!(analyzer.pclntab_found);
    }

    #[test]
    fn test_arm_symbol_analyzer_thumb() {
        assert!(ArmSymbolAnalyzer::is_thumb_entry(Address::new(0x400001)));
        assert!(!ArmSymbolAnalyzer::is_thumb_entry(Address::new(0x400000)));
    }

    #[test]
    fn test_arm_symbol_analyzer_veneer() {
        let mut analyzer = ArmSymbolAnalyzer::new();
        analyzer.add_veneer(Address::new(0x400000), Address::new(0x500000));
        assert!(analyzer.is_veneer(&Address::new(0x400000)));
        assert_eq!(
            analyzer.resolve_veneer(&Address::new(0x400000)),
            Some(Address::new(0x500000))
        );
        assert_eq!(analyzer.resolve_veneer(&Address::new(0x400004)), None);
    }

    #[test]
    fn test_dw_analyzer_functions() {
        let mut analyzer = DwAnalyzer::new();
        analyzer.set_dwarf_version(4);
        assert_eq!(analyzer.dwarf_version, Some(4));

        analyzer.add_function(DwFunctionEntry {
            low_pc: Address::new(0x400000),
            high_pc: Address::new(0x400100),
            name: "main".into(),
            source_file: Some("main.c".into()),
            source_line: Some(10),
            linkage_name: Some("main".into()),
        });
        assert_eq!(analyzer.function_count(), 1);
    }

    #[test]
    fn test_register_context_builder() {
        let mut builder = RegisterContextBuilder::new();
        builder.set_register("TMode", 1);
        assert_eq!(builder.get_register("TMode"), Some(1));

        let mut ctx = HashMap::new();
        ctx.insert("TMode".to_string(), 0);
        builder.add_context_range(0x400000, 0x401000, ctx);
        assert_eq!(builder.range_count(), 1);

        let context = builder.context_at(0x400500);
        assert!(context.is_some());
        assert_eq!(context.unwrap().get("TMode"), Some(&0));
    }

    #[test]
    fn test_register_context_builder_merge() {
        let mut b1 = RegisterContextBuilder::new();
        b1.set_register("R1", 10);

        let mut b2 = RegisterContextBuilder::new();
        b2.set_register("R2", 20);

        b1.merge_from(&b2);
        assert_eq!(b1.get_register("R1"), Some(10));
        assert_eq!(b1.get_register("R2"), Some(20));
    }
}
