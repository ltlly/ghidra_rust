//! Entry Point Analyzer -- ported from
//! `ghidra.app.plugin.core.disassembler.EntryPointAnalyzer`.
//!
//! Disassembles entry points in newly added memory. This analyzer is
//! triggered during auto-analysis when new memory blocks are added to
//! a program.

use ghidra_core::Address;
use std::collections::HashSet;

/// Analysis priority levels for entry point analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AnalysisPriority {
    /// Block-level analysis (runs first on new memory blocks).
    BlockAnalysis,
    /// Reference-level analysis.
    ReferenceAnalysis,
    /// Disassembly-level analysis.
    Disassembly,
    /// Function-level analysis.
    FunctionAnalysis,
}

impl AnalysisPriority {
    /// Return the priority level just before this one.
    pub fn before(self) -> Self {
        match self {
            Self::BlockAnalysis => Self::BlockAnalysis,
            Self::ReferenceAnalysis => Self::BlockAnalysis,
            Self::Disassembly => Self::ReferenceAnalysis,
            Self::FunctionAnalysis => Self::Disassembly,
        }
    }

    /// Return the priority level just after this one.
    pub fn after(self) -> Self {
        match self {
            Self::BlockAnalysis => Self::ReferenceAnalysis,
            Self::ReferenceAnalysis => Self::Disassembly,
            Self::Disassembly => Self::FunctionAnalysis,
            Self::FunctionAnalysis => Self::FunctionAnalysis,
        }
    }
}

/// Analyzer type classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnalyzerType {
    /// Analyzes newly added bytes.
    ByteAnalyzer,
    /// Analyzes functions.
    FunctionAnalyzer,
    /// Analyzes instructions.
    InstructionAnalyzer,
    /// Analyzes data.
    DataAnalyzer,
}

/// Entry point analyzer for disassembling entry points in newly added memory.
///
/// Ported from `ghidra.app.plugin.core.disassembler.EntryPointAnalyzer`.
///
/// The analyzer performs several passes:
/// 1. Disassemble code-map markers from the importer.
/// 2. Find "dummy" functions (single-address placeholders) and disassemble them.
/// 3. Find external entry points and disassemble them.
/// 4. Find symbol-based entry points (from the symbol table).
/// 5. Process "do-later" entries for deferred disassembly.
/// 6. Fix up dummy function bodies after initial disassembly.
#[derive(Debug)]
pub struct EntryPointAnalyzer {
    /// Human-readable name.
    pub name: String,
    /// Description.
    pub description: String,
    /// The analyzer type.
    pub analyzer_type: AnalyzerType,
    /// Analysis priority.
    pub priority: AnalysisPriority,
    /// Whether the analyzer is enabled by default.
    pub default_enabled: bool,
    /// Whether to respect execute flags on memory blocks.
    pub respect_execute_flags: bool,
    /// Whether supports one-time analysis.
    pub supports_one_time_analysis: bool,
    /// Entry points that have been identified for disassembly.
    entry_points: HashSet<u64>,
    /// Entry points deferred to later analysis.
    do_later_set: HashSet<u64>,
    /// Dummy functions found (single-address placeholders).
    dummy_functions: HashSet<u64>,
    /// Functions whose bodies need to be re-done.
    redo_functions: HashSet<u64>,
}

impl EntryPointAnalyzer {
    /// The standard analyzer name.
    pub const NAME: &'static str = "Disassemble Entry Points";

    /// Create a new entry point analyzer.
    pub fn new() -> Self {
        Self {
            name: Self::NAME.into(),
            description: "Disassembles entry points in newly added memory.".into(),
            analyzer_type: AnalyzerType::ByteAnalyzer,
            priority: AnalysisPriority::BlockAnalysis,
            default_enabled: true,
            respect_execute_flags: true,
            supports_one_time_analysis: false,
            entry_points: HashSet::new(),
            do_later_set: HashSet::new(),
            dummy_functions: HashSet::new(),
            redo_functions: HashSet::new(),
        }
    }

    /// Create an analyzer with the given priority.
    pub fn with_priority(mut self, priority: AnalysisPriority) -> Self {
        self.priority = priority;
        self
    }

    /// Whether the analyzer should respect memory block execute flags.
    pub fn should_respect_execute_flags(&self) -> bool {
        self.respect_execute_flags
    }

    /// Set whether to respect execute flags.
    pub fn set_respect_execute_flags(&mut self, respect: bool) {
        self.respect_execute_flags = respect;
    }

    /// Add an entry point for disassembly.
    pub fn add_entry_point(&mut self, address: Address) {
        self.entry_points.insert(address.offset);
    }

    /// Add an entry point to the "do later" set.
    pub fn add_do_later(&mut self, address: Address) {
        self.do_later_set.insert(address.offset);
    }

    /// Mark a function address as a dummy (single-address placeholder).
    pub fn add_dummy_function(&mut self, address: Address) {
        self.dummy_functions.insert(address.offset);
    }

    /// Mark a function address as needing body re-do.
    pub fn add_redo_function(&mut self, address: Address) {
        self.redo_functions.insert(address.offset);
    }

    /// Get all entry points.
    pub fn entry_points(&self) -> &HashSet<u64> {
        &self.entry_points
    }

    /// Get the "do later" set.
    pub fn do_later_set(&self) -> &HashSet<u64> {
        &self.do_later_set
    }

    /// Get dummy functions.
    pub fn dummy_functions(&self) -> &HashSet<u64> {
        &self.dummy_functions
    }

    /// Get redo functions.
    pub fn redo_functions(&self) -> &HashSet<u64> {
        &self.redo_functions
    }

    /// Whether the analyzer has any work to do.
    pub fn has_work(&self) -> bool {
        !self.entry_points.is_empty()
            || !self.do_later_set.is_empty()
            || !self.dummy_functions.is_empty()
            || !self.redo_functions.is_empty()
    }

    /// Process the "do later" set.
    ///
    /// If the analyzer is at block-analysis priority, the do-later set is
    /// scheduled for later. Otherwise, disassembly is performed immediately.
    pub fn process_do_later(&mut self) -> Vec<Address> {
        let addrs: Vec<Address> = self
            .do_later_set
            .iter()
            .map(|&offset| Address::new(offset))
            .collect();
        self.do_later_set.clear();
        addrs
    }

    /// Classify entry points from a set of addresses.
    ///
    /// This models the logic from `EntryPointAnalyzer.added()`:
    /// - Addresses that are external entry points go into `entry_points`.
    /// - Single-address functions go into `dummy_functions` and `redo_functions`.
    /// - Everything else goes into `do_later_set`.
    pub fn classify_addresses(
        &mut self,
        addresses: &[Address],
        external_entry_points: &HashSet<u64>,
        function_entries: &HashSet<u64>,
        single_address_functions: &HashSet<u64>,
        has_code_at: impl Fn(Address) -> bool,
        has_data_at: impl Fn(Address) -> bool,
    ) {
        for &addr in addresses {
            let offset = addr.offset;
            // Skip if there's already defined data
            if has_data_at(addr) {
                continue;
            }
            // If it's a single-address function, mark as dummy
            if single_address_functions.contains(&offset) {
                self.dummy_functions.insert(offset);
                self.redo_functions.insert(offset);
                continue;
            }
            // If it's an external entry point, add directly
            if external_entry_points.contains(&offset) {
                self.entry_points.insert(offset);
                continue;
            }
            // If it's a function entry with no code, schedule for later
            if function_entries.contains(&offset) && !has_code_at(addr) {
                self.do_later_set.insert(offset);
                continue;
            }
            // Default: add to entry points
            self.entry_points.insert(offset);
        }
    }

    /// Clear all internal state.
    pub fn clear(&mut self) {
        self.entry_points.clear();
        self.do_later_set.clear();
        self.dummy_functions.clear();
        self.redo_functions.clear();
    }
}

impl Default for EntryPointAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entry_point_analyzer_new() {
        let analyzer = EntryPointAnalyzer::new();
        assert_eq!(analyzer.name, EntryPointAnalyzer::NAME);
        assert_eq!(analyzer.analyzer_type, AnalyzerType::ByteAnalyzer);
        assert_eq!(analyzer.priority, AnalysisPriority::BlockAnalysis);
        assert!(analyzer.default_enabled);
        assert!(analyzer.respect_execute_flags);
        assert!(!analyzer.has_work());
    }

    #[test]
    fn test_entry_point_analyzer_with_priority() {
        let analyzer = EntryPointAnalyzer::new()
            .with_priority(AnalysisPriority::ReferenceAnalysis);
        assert_eq!(analyzer.priority, AnalysisPriority::ReferenceAnalysis);
    }

    #[test]
    fn test_add_entry_point() {
        let mut analyzer = EntryPointAnalyzer::new();
        analyzer.add_entry_point(Address::new(0x400000));
        assert!(analyzer.has_work());
        assert!(analyzer.entry_points().contains(&0x400000));
    }

    #[test]
    fn test_add_dummy_function() {
        let mut analyzer = EntryPointAnalyzer::new();
        analyzer.add_dummy_function(Address::new(0x401000));
        assert!(analyzer.dummy_functions().contains(&0x401000));
    }

    #[test]
    fn test_process_do_later() {
        let mut analyzer = EntryPointAnalyzer::new();
        analyzer.add_do_later(Address::new(0x402000));
        analyzer.add_do_later(Address::new(0x403000));
        let addrs = analyzer.process_do_later();
        assert_eq!(addrs.len(), 2);
        assert!(analyzer.do_later_set().is_empty());
    }

    #[test]
    fn test_classify_addresses() {
        let mut analyzer = EntryPointAnalyzer::new();
        let addresses = vec![
            Address::new(0x1000),
            Address::new(0x2000),
            Address::new(0x3000),
            Address::new(0x4000),
        ];
        let mut external = HashSet::new();
        external.insert(0x1000);
        let mut func_entries = HashSet::new();
        func_entries.insert(0x3000);
        let mut single_addr_funcs = HashSet::new();
        single_addr_funcs.insert(0x2000);

        analyzer.classify_addresses(
            &addresses,
            &external,
            &func_entries,
            &single_addr_funcs,
            |_addr| false, // no code
            |_addr| false, // no data
        );

        assert!(analyzer.entry_points().contains(&0x1000));
        assert!(analyzer.dummy_functions().contains(&0x2000));
        assert!(analyzer.redo_functions().contains(&0x2000));
        assert!(analyzer.do_later_set().contains(&0x3000));
        assert!(analyzer.entry_points().contains(&0x4000));
    }

    #[test]
    fn test_classify_skips_data_addresses() {
        let mut analyzer = EntryPointAnalyzer::new();
        let addresses = vec![Address::new(0x5000)];
        let external = HashSet::new();
        let func_entries = HashSet::new();
        let single_addr_funcs = HashSet::new();

        analyzer.classify_addresses(
            &addresses,
            &external,
            &func_entries,
            &single_addr_funcs,
            |_addr| false,
            |_addr| true, // has data -> skip
        );

        assert!(!analyzer.entry_points().contains(&0x5000));
        assert!(!analyzer.has_work());
    }

    #[test]
    fn test_analysis_priority_ordering() {
        assert!(AnalysisPriority::BlockAnalysis < AnalysisPriority::ReferenceAnalysis);
        assert!(AnalysisPriority::ReferenceAnalysis < AnalysisPriority::Disassembly);
        assert!(AnalysisPriority::Disassembly < AnalysisPriority::FunctionAnalysis);
    }

    #[test]
    fn test_analysis_priority_before_after() {
        assert_eq!(
            AnalysisPriority::ReferenceAnalysis.before(),
            AnalysisPriority::BlockAnalysis
        );
        assert_eq!(
            AnalysisPriority::BlockAnalysis.after(),
            AnalysisPriority::ReferenceAnalysis
        );
    }

    #[test]
    fn test_set_respect_execute_flags() {
        let mut analyzer = EntryPointAnalyzer::new();
        analyzer.set_respect_execute_flags(false);
        assert!(!analyzer.should_respect_execute_flags());
    }

    #[test]
    fn test_clear() {
        let mut analyzer = EntryPointAnalyzer::new();
        analyzer.add_entry_point(Address::new(0x1000));
        analyzer.add_do_later(Address::new(0x2000));
        analyzer.add_dummy_function(Address::new(0x3000));
        analyzer.clear();
        assert!(!analyzer.has_work());
    }
}
