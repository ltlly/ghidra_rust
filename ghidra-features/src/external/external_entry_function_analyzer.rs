//! ExternalEntryFunctionAnalyzer -- analyzer for creating functions at
//! external entry points.
//!
//! Ported from
//! `ghidra.app.plugin.core.function.ExternalEntryFunctionAnalyzer`.
//!
//! This analyzer iterates over the program's external entry points and
//! creates function definitions at each address where an instruction
//! exists and the address is a good candidate for a function start.
//! An address is considered a good function start if:
//!
//! 1. An instruction exists at the address, AND
//! 2. No instruction immediately before the address falls through to it
//!    (i.e., the address is not in the middle of another function's
//!    control flow).
//!
//! # Examples
//!
//! ```rust
//! use ghidra_features::external::ExternalEntryPointManager;
//! use ghidra_features::external::external_entry_function_analyzer::{
//!     ExternalEntryFunctionAnalyzer, FunctionStartDatabase,
//! };
//! use ghidra_core::addr::Address;
//!
//! let mut entry_mgr = ExternalEntryPointManager::new();
//! entry_mgr.add_external_entry_point(Address::new(0x401000));
//! entry_mgr.add_external_entry_point(Address::new(0x402000));
//!
//! let mut func_db = FunctionStartDatabase::new();
//! func_db.add_instruction(Address::new(0x401000), 4);
//! func_db.add_instruction(Address::new(0x402000), 6);
//!
//! let mut analyzer = ExternalEntryFunctionAnalyzer::new();
//! let result = analyzer.analyze(&entry_mgr, &func_db);
//! assert_eq!(result.new_function_count(), 2);
//! ```

use std::collections::BTreeSet;
use std::fmt;

use ghidra_core::addr::Address;

use super::external_entry_cmd::ExternalEntryPointManager;

// ---------------------------------------------------------------------------
// InstructionInfo
// ---------------------------------------------------------------------------

/// Information about an instruction at a given address.
///
/// In the Java implementation this is derived from
/// `Listing.getInstructionAt()` and `Listing.getInstructionContaining()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstructionInfo {
    /// The start address of the instruction.
    pub address: Address,
    /// The length of the instruction in bytes.
    pub length: u32,
}

impl InstructionInfo {
    /// Create new instruction info.
    pub fn new(address: Address, length: u32) -> Self {
        Self { address, length }
    }

    /// Returns the fall-through address (the address of the next
    /// instruction in sequence).
    pub fn fall_through(&self) -> Address {
        Address::new(self.address.offset + self.length as u64)
    }
}

// ---------------------------------------------------------------------------
// FunctionStartDatabase
// ---------------------------------------------------------------------------

/// Simplified database of instruction and function start information.
///
/// In the Java implementation this information comes from the program's
/// `Listing` and `FunctionManager`.  This struct provides the minimum
/// API needed by the analyzer.
#[derive(Debug, Clone, Default)]
pub struct FunctionStartDatabase {
    /// All instruction start addresses (sorted).
    instruction_addrs: BTreeSet<u64>,
    /// Instruction lengths keyed by start address.
    instruction_lengths: std::collections::BTreeMap<u64, u32>,
    /// Addresses that are already function starts.
    function_starts: BTreeSet<u64>,
}

impl FunctionStartDatabase {
    /// Create a new empty database.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register an instruction at the given address.
    ///
    /// * `addr` -- the start address of the instruction.
    /// * `length` -- the instruction length in bytes.
    pub fn add_instruction(&mut self, addr: Address, length: u32) {
        self.instruction_addrs.insert(addr.offset);
        self.instruction_lengths.insert(addr.offset, length);
    }

    /// Register an address as an existing function start.
    pub fn add_function_start(&mut self, addr: Address) {
        self.function_starts.insert(addr.offset);
    }

    /// Check if an instruction exists at the given address.
    pub fn has_instruction_at(&self, addr: &Address) -> bool {
        self.instruction_addrs.contains(&addr.offset)
    }

    /// Returns the instruction info at the given address, if any.
    pub fn get_instruction_at(&self, addr: &Address) -> Option<InstructionInfo> {
        self.instruction_lengths
            .get(&addr.offset)
            .map(|&length| InstructionInfo::new(*addr, length))
    }

    /// Returns the instruction that contains the given address.
    ///
    /// This searches for an instruction whose range `[start, start+length)`
    /// includes the given address.
    pub fn get_instruction_containing(&self, addr: &Address) -> Option<InstructionInfo> {
        // Walk backwards from the address to find the instruction that
        // contains it.
        for (&start_offset, &length) in self.instruction_lengths.range(..=addr.offset).rev() {
            let end_offset = start_offset + length as u64;
            if addr.offset >= start_offset && addr.offset < end_offset {
                return Some(InstructionInfo::new(Address::new(start_offset), length));
            }
            // Once we're past the range, stop searching
            if addr.offset >= end_offset {
                break;
            }
        }
        None
    }

    /// Check if the given address is already a function start.
    pub fn is_function_start(&self, addr: &Address) -> bool {
        self.function_starts.contains(&addr.offset)
    }

    /// Returns the total number of registered instructions.
    pub fn instruction_count(&self) -> usize {
        self.instruction_addrs.len()
    }

    /// Returns the total number of registered function starts.
    pub fn function_start_count(&self) -> usize {
        self.function_starts.len()
    }
}

// ---------------------------------------------------------------------------
// AnalysisResult
// ---------------------------------------------------------------------------

/// The result of running the external entry function analyzer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnalysisResult {
    /// Addresses at which new functions were created.
    pub new_function_starts: Vec<Address>,
    /// Addresses that were skipped because they already had functions.
    pub already_functions: Vec<Address>,
    /// Addresses that were skipped because they were not good function
    /// starts (no instruction, or falls through from prior instruction).
    pub skipped: Vec<Address>,
}

impl AnalysisResult {
    /// Returns the total number of new function starts.
    pub fn new_function_count(&self) -> usize {
        self.new_function_starts.len()
    }

    /// Returns the total number of addresses processed.
    pub fn total_processed(&self) -> usize {
        self.new_function_starts.len() + self.already_functions.len() + self.skipped.len()
    }
}

// ---------------------------------------------------------------------------
// Analyzer error
// ---------------------------------------------------------------------------

/// Errors that can occur during analysis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnalyzerError {
    /// Analysis was cancelled.
    Cancelled,
    /// General error.
    Other(String),
}

impl fmt::Display for AnalyzerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AnalyzerError::Cancelled => write!(f, "Analysis cancelled"),
            AnalyzerError::Other(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for AnalyzerError {}

// ---------------------------------------------------------------------------
// ExternalEntryFunctionAnalyzer
// ---------------------------------------------------------------------------

/// Analyzer that creates function definitions for external entry points
/// where instructions already exist.
///
/// This is the Rust port of Ghidra's `ExternalEntryFunctionAnalyzer`.
/// It iterates over all external entry points, checks whether each
/// address is a valid function start, and returns the set of addresses
/// at which new functions should be created.
///
/// # Analysis criteria
///
/// An address is a good function start if:
///
/// 1. An instruction exists at the address.
/// 2. The address is not already a function start.
/// 3. No instruction immediately before the address falls through to it
///    (meaning the address is not in the middle of another function's
///    sequential flow).
///
/// # Examples
///
/// ```rust
/// use ghidra_features::external::{
///     ExternalEntryFunctionAnalyzer, ExternalEntryPointManager,
///     FunctionStartDatabase,
/// };
/// use ghidra_core::addr::Address;
///
/// let mut entry_mgr = ExternalEntryPointManager::new();
/// entry_mgr.add_external_entry_point(Address::new(0x401000));
///
/// let mut func_db = FunctionStartDatabase::new();
/// func_db.add_instruction(Address::new(0x401000), 4);
///
/// let mut analyzer = ExternalEntryFunctionAnalyzer::new();
/// let result = analyzer.analyze(&entry_mgr, &func_db);
/// assert_eq!(result.new_function_count(), 1);
/// assert_eq!(result.new_function_starts[0], Address::new(0x401000));
/// ```
#[derive(Debug, Clone)]
pub struct ExternalEntryFunctionAnalyzer {
    /// The analyzer name.
    name: String,
    /// The analyzer description.
    description: String,
    /// Whether the analyzer is enabled by default.
    enabled: bool,
}

impl ExternalEntryFunctionAnalyzer {
    /// Create a new analyzer with default settings.
    pub fn new() -> Self {
        Self {
            name: "External Entry References".to_string(),
            description: "Creates function definitions for external entry points where instructions already exist.".to_string(),
            enabled: true,
        }
    }

    /// Returns the analyzer name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the analyzer description.
    pub fn description(&self) -> &str {
        &self.description
    }

    /// Returns whether the analyzer is enabled by default.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Set whether the analyzer is enabled.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Check if an address is a good function start.
    ///
    /// An address is a good function start if:
    /// 1. An instruction exists at the address.
    /// 2. No instruction immediately before falls through to it.
    ///
    /// This is a direct port of
    /// `ExternalEntryFunctionAnalyzer.isGoodFunctionStart()`.
    pub fn is_good_function_start(
        func_db: &FunctionStartDatabase,
        addr: &Address,
    ) -> bool {
        // Must have an instruction at the location
        if !func_db.has_instruction_at(addr) {
            return false;
        }

        // Check the address before this one
        if addr.offset == 0 {
            return true;
        }

        let addr_before = Address::new(addr.offset - 1);

        // Check if the instruction before falls into this one
        if let Some(instr) = func_db.get_instruction_containing(&addr_before) {
            if *addr == instr.fall_through() {
                return false;
            }
        }

        true
    }

    /// Run the analysis on the given entry point manager and function
    /// start database.
    ///
    /// Returns an [`AnalysisResult`] describing what was found.
    pub fn analyze(
        &mut self,
        entry_mgr: &ExternalEntryPointManager,
        func_db: &FunctionStartDatabase,
    ) -> AnalysisResult {
        let mut new_function_starts = Vec::new();
        let mut already_functions = Vec::new();
        let mut skipped = Vec::new();

        for addr in entry_mgr.addresses() {
            // Skip if already a function
            if func_db.is_function_start(&addr) {
                already_functions.push(addr);
                continue;
            }

            // Check if this is a good function start
            if Self::is_good_function_start(func_db, &addr) {
                new_function_starts.push(addr);
            } else {
                skipped.push(addr);
            }
        }

        AnalysisResult {
            new_function_starts,
            already_functions,
            skipped,
        }
    }
}

impl Default for ExternalEntryFunctionAnalyzer {
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
    fn test_analyze_creates_functions() {
        let mut entry_mgr = ExternalEntryPointManager::new();
        entry_mgr.add_external_entry_point(Address::new(0x401000));
        entry_mgr.add_external_entry_point(Address::new(0x402000));

        let mut func_db = FunctionStartDatabase::new();
        func_db.add_instruction(Address::new(0x401000), 4);
        func_db.add_instruction(Address::new(0x402000), 6);

        let mut analyzer = ExternalEntryFunctionAnalyzer::new();
        let result = analyzer.analyze(&entry_mgr, &func_db);

        assert_eq!(result.new_function_count(), 2);
        assert_eq!(result.new_function_starts[0], Address::new(0x401000));
        assert_eq!(result.new_function_starts[1], Address::new(0x402000));
        assert!(result.already_functions.is_empty());
        assert!(result.skipped.is_empty());
    }

    #[test]
    fn test_analyze_skips_existing_functions() {
        let mut entry_mgr = ExternalEntryPointManager::new();
        entry_mgr.add_external_entry_point(Address::new(0x401000));
        entry_mgr.add_external_entry_point(Address::new(0x402000));

        let mut func_db = FunctionStartDatabase::new();
        func_db.add_instruction(Address::new(0x401000), 4);
        func_db.add_instruction(Address::new(0x402000), 6);
        func_db.add_function_start(Address::new(0x401000)); // already a function

        let mut analyzer = ExternalEntryFunctionAnalyzer::new();
        let result = analyzer.analyze(&entry_mgr, &func_db);

        assert_eq!(result.new_function_count(), 1);
        assert_eq!(result.new_function_starts[0], Address::new(0x402000));
        assert_eq!(result.already_functions.len(), 1);
        assert_eq!(result.already_functions[0], Address::new(0x401000));
    }

    #[test]
    fn test_analyze_skips_no_instruction() {
        let mut entry_mgr = ExternalEntryPointManager::new();
        entry_mgr.add_external_entry_point(Address::new(0x401000));

        let func_db = FunctionStartDatabase::new();
        // No instruction at 0x401000

        let mut analyzer = ExternalEntryFunctionAnalyzer::new();
        let result = analyzer.analyze(&entry_mgr, &func_db);

        assert_eq!(result.new_function_count(), 0);
        assert!(result.new_function_starts.is_empty());
        assert_eq!(result.skipped.len(), 1);
    }

    #[test]
    fn test_analyze_skips_fall_through() {
        let mut entry_mgr = ExternalEntryPointManager::new();
        entry_mgr.add_external_entry_point(Address::new(0x401004));

        let mut func_db = FunctionStartDatabase::new();
        func_db.add_instruction(Address::new(0x401000), 4);
        func_db.add_instruction(Address::new(0x401004), 8);

        let mut analyzer = ExternalEntryFunctionAnalyzer::new();
        let result = analyzer.analyze(&entry_mgr, &func_db);

        // 0x401004 falls through from 0x401000 (instruction at 0x401000
        // has length 4, so fall-through = 0x401004)
        assert_eq!(result.new_function_count(), 0);
        assert_eq!(result.skipped.len(), 1);
        assert_eq!(result.skipped[0], Address::new(0x401004));
    }

    #[test]
    fn test_analyze_empty_entry_points() {
        let entry_mgr = ExternalEntryPointManager::new();
        let func_db = FunctionStartDatabase::new();

        let mut analyzer = ExternalEntryFunctionAnalyzer::new();
        let result = analyzer.analyze(&entry_mgr, &func_db);

        assert_eq!(result.total_processed(), 0);
        assert!(result.new_function_starts.is_empty());
        assert!(result.already_functions.is_empty());
        assert!(result.skipped.is_empty());
    }

    #[test]
    fn test_is_good_function_start() {
        let mut func_db = FunctionStartDatabase::new();
        func_db.add_instruction(Address::new(0x401000), 4);

        assert!(ExternalEntryFunctionAnalyzer::is_good_function_start(
            &func_db,
            &Address::new(0x401000)
        ));
    }

    #[test]
    fn test_is_good_function_start_no_instruction() {
        let func_db = FunctionStartDatabase::new();

        assert!(!ExternalEntryFunctionAnalyzer::is_good_function_start(
            &func_db,
            &Address::new(0x401000)
        ));
    }

    #[test]
    fn test_is_good_function_start_fall_through() {
        let mut func_db = FunctionStartDatabase::new();
        func_db.add_instruction(Address::new(0x401000), 4);
        func_db.add_instruction(Address::new(0x401004), 8);

        // 0x401004 is the fall-through of the instruction at 0x401000
        assert!(!ExternalEntryFunctionAnalyzer::is_good_function_start(
            &func_db,
            &Address::new(0x401004)
        ));
    }

    #[test]
    fn test_is_good_function_start_at_zero() {
        let mut func_db = FunctionStartDatabase::new();
        func_db.add_instruction(Address::new(0x0), 4);

        // Address 0 has no previous address, so it's always a good start
        assert!(ExternalEntryFunctionAnalyzer::is_good_function_start(
            &func_db,
            &Address::new(0x0)
        ));
    }

    #[test]
    fn test_analyzer_properties() {
        let analyzer = ExternalEntryFunctionAnalyzer::new();
        assert_eq!(analyzer.name(), "External Entry References");
        assert!(analyzer.is_enabled());
        assert!(!analyzer.description().is_empty());
    }

    #[test]
    fn test_analyzer_set_enabled() {
        let mut analyzer = ExternalEntryFunctionAnalyzer::new();
        assert!(analyzer.is_enabled());
        analyzer.set_enabled(false);
        assert!(!analyzer.is_enabled());
        analyzer.set_enabled(true);
        assert!(analyzer.is_enabled());
    }

    #[test]
    fn test_instruction_info() {
        let info = InstructionInfo::new(Address::new(0x401000), 4);
        assert_eq!(info.address, Address::new(0x401000));
        assert_eq!(info.length, 4);
        assert_eq!(info.fall_through(), Address::new(0x401004));
    }

    #[test]
    fn test_function_start_database() {
        let mut db = FunctionStartDatabase::new();
        db.add_instruction(Address::new(0x401000), 4);
        db.add_instruction(Address::new(0x401004), 6);
        db.add_function_start(Address::new(0x401000));

        assert_eq!(db.instruction_count(), 2);
        assert_eq!(db.function_start_count(), 1);
        assert!(db.has_instruction_at(&Address::new(0x401000)));
        assert!(!db.has_instruction_at(&Address::new(0x402000)));
        assert!(db.is_function_start(&Address::new(0x401000)));
        assert!(!db.is_function_start(&Address::new(0x401004)));
    }

    #[test]
    fn test_function_start_database_containing() {
        let mut db = FunctionStartDatabase::new();
        db.add_instruction(Address::new(0x401000), 8);

        // Address inside the instruction
        let info = db.get_instruction_containing(&Address::new(0x401003));
        assert!(info.is_some());
        assert_eq!(info.unwrap().address, Address::new(0x401000));

        // Address at the start
        let info = db.get_instruction_containing(&Address::new(0x401000));
        assert!(info.is_some());

        // Address after the instruction
        let info = db.get_instruction_containing(&Address::new(0x401008));
        assert!(info.is_none());
    }

    #[test]
    fn test_analysis_result() {
        let result = AnalysisResult {
            new_function_starts: vec![Address::new(0x401000), Address::new(0x402000)],
            already_functions: vec![Address::new(0x403000)],
            skipped: vec![Address::new(0x404000)],
        };

        assert_eq!(result.new_function_count(), 2);
        assert_eq!(result.total_processed(), 4);
    }

    #[test]
    fn test_complex_scenario() {
        let mut entry_mgr = ExternalEntryPointManager::new();
        entry_mgr.add_external_entry_point(Address::new(0x401000)); // good start
        entry_mgr.add_external_entry_point(Address::new(0x401004)); // fall-through (skip)
        entry_mgr.add_external_entry_point(Address::new(0x402000)); // already function
        entry_mgr.add_external_entry_point(Address::new(0x403000)); // no instruction (skip)
        entry_mgr.add_external_entry_point(Address::new(0x404000)); // good start

        let mut func_db = FunctionStartDatabase::new();
        func_db.add_instruction(Address::new(0x401000), 4);
        func_db.add_instruction(Address::new(0x401004), 8);
        func_db.add_instruction(Address::new(0x402000), 12);
        func_db.add_instruction(Address::new(0x404000), 6);
        func_db.add_function_start(Address::new(0x402000));

        let mut analyzer = ExternalEntryFunctionAnalyzer::new();
        let result = analyzer.analyze(&entry_mgr, &func_db);

        assert_eq!(result.new_function_count(), 2);
        assert_eq!(result.new_function_starts[0], Address::new(0x401000));
        assert_eq!(result.new_function_starts[1], Address::new(0x404000));
        assert_eq!(result.already_functions.len(), 1);
        assert_eq!(result.already_functions[0], Address::new(0x402000));
        assert_eq!(result.skipped.len(), 2);
    }
}
