//! ExternalDebugFileSymbolImporter -- imports symbols from an external
//! debug program into the target program.
//!
//! Ported from
//! `ghidra.app.util.bin.format.dwarf.ExternalDebugFileSymbolImporter`.
//!
//! When an ELF binary is stripped of its debug information (via
//! `objcopy --strip-debug`), the debug symbols can be stored in a
//! separate file (often named `<binary>.debug` or looked up via
//! build-id).  The external debug file contains the original symbol
//! table, function boundaries, and data labels.
//!
//! This importer copies symbols from the external debug program into
//! the program that contains the executable code.  It performs a
//! memory-map compatibility check before copying, and tracks
//! statistics about the import process.
//!
//! # Examples
//!
//! ```rust
//! use ghidra_features::external::external_debug_file_symbol_importer::{
//!     ExternalDebugFileSymbolImporter, MemoryBlockInfo,
//! };
//! use ghidra_core::addr::Address;
//!
//! let mut importer = ExternalDebugFileSymbolImporter::new();
//!
//! // Add a memory block covering the test addresses
//! importer.add_program_block(MemoryBlockInfo::new(".text", Address::new(0x400000), 0x10000, true));
//!
//! // Simulate importing symbols
//! importer.import_function_symbol("main", 0x401000, true).unwrap();
//! importer.import_data_symbol("global_var", 0x402000, 4).unwrap();
//!
//! assert_eq!(importer.stats().func_symbols_copied, 1);
//! assert_eq!(importer.stats().data_symbols_copied, 1);
//! ```

use std::collections::HashMap;
use std::fmt;

use ghidra_core::addr::Address;

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

/// Errors that can occur during symbol import.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SymbolImportError {
    /// The memory maps of the two programs do not match.
    MemoryMapMismatch,
    /// The address could not be mapped to the target program.
    AddressNotMapped(String),
    /// The symbol is invalid.
    InvalidSymbol(String),
    /// A function creation failed.
    FunctionCreationFailed(String),
    /// A data creation failed.
    DataCreationFailed(String),
    /// General error.
    Other(String),
}

impl fmt::Display for SymbolImportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SymbolImportError::MemoryMapMismatch => {
                write!(
                    f,
                    "Unable to copy external symbols: memory map does not match"
                )
            }
            SymbolImportError::AddressNotMapped(addr) => {
                write!(f, "Unable to map address: {}", addr)
            }
            SymbolImportError::InvalidSymbol(name) => {
                write!(f, "Invalid symbol: {}", name)
            }
            SymbolImportError::FunctionCreationFailed(name) => {
                write!(f, "Failed to create function: {}", name)
            }
            SymbolImportError::DataCreationFailed(name) => {
                write!(f, "Failed to create data: {}", name)
            }
            SymbolImportError::Other(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for SymbolImportError {}

// ---------------------------------------------------------------------------
// Import statistics
// ---------------------------------------------------------------------------

/// Statistics about the symbol import process.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImportStats {
    /// Number of function symbols successfully copied.
    pub func_symbols_copied: usize,
    /// Number of data symbols successfully copied.
    pub data_symbols_copied: usize,
    /// Number of symbols skipped (e.g., library namespace symbols).
    pub symbols_skipped: usize,
    /// Number of symbols that failed to copy.
    pub symbol_copy_fail_count: usize,
    /// Total number of symbols processed.
    pub total_symbol_count: usize,
}

impl ImportStats {
    /// Create new empty statistics.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the total number of successfully imported symbols.
    pub fn total_copied(&self) -> usize {
        self.func_symbols_copied + self.data_symbols_copied
    }

    /// Returns a summary string of the import statistics.
    pub fn summary(&self) -> String {
        format!(
            "Copied {}/{}/{}/{}/{} func/data/skip/fail/total symbols from external debug file",
            self.func_symbols_copied,
            self.data_symbols_copied,
            self.symbols_skipped,
            self.symbol_copy_fail_count,
            self.total_symbol_count,
        )
    }
}

// ---------------------------------------------------------------------------
// Memory block info
// ---------------------------------------------------------------------------

/// Information about a memory block in a program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryBlockInfo {
    /// The name of the memory block.
    pub name: String,
    /// The start address of the block.
    pub start: Address,
    /// The size of the block in bytes.
    pub size: u64,
    /// Whether this block is executable.
    pub is_execute: bool,
}

impl MemoryBlockInfo {
    /// Create new memory block info.
    pub fn new(name: impl Into<String>, start: Address, size: u64, is_execute: bool) -> Self {
        Self {
            name: name.into(),
            start,
            size,
            is_execute,
        }
    }
}

// ---------------------------------------------------------------------------
// Symbol info for import
// ---------------------------------------------------------------------------

/// Information about an external debug file symbol to be imported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DebugFileSymbol {
    /// The symbol name.
    pub name: String,
    /// The address of the symbol in the debug file.
    pub address: Address,
    /// Whether this symbol is a function.
    pub is_function: bool,
    /// Whether this symbol is a thunk function.
    pub is_thunk: bool,
    /// Whether this symbol is a label (data symbol).
    pub is_label: bool,
    /// The size of the data (for data symbols).
    pub data_size: Option<u64>,
    /// Whether the symbol is in a library namespace (and should be skipped).
    pub in_library_namespace: bool,
}

impl DebugFileSymbol {
    /// Create a new function symbol.
    pub fn function(name: impl Into<String>, address: Address) -> Self {
        Self {
            name: name.into(),
            address,
            is_function: true,
            is_thunk: false,
            is_label: false,
            data_size: None,
            in_library_namespace: false,
        }
    }

    /// Create a new thunk function symbol.
    pub fn thunk_function(name: impl Into<String>, address: Address) -> Self {
        Self {
            name: name.into(),
            address,
            is_function: true,
            is_thunk: true,
            is_label: false,
            data_size: None,
            in_library_namespace: false,
        }
    }

    /// Create a new data (label) symbol.
    pub fn data(name: impl Into<String>, address: Address, size: u64) -> Self {
        Self {
            name: name.into(),
            address,
            is_function: false,
            is_thunk: false,
            is_label: true,
            data_size: Some(size),
            in_library_namespace: false,
        }
    }

    /// Mark this symbol as being in a library namespace (will be skipped).
    pub fn in_library_namespace(mut self) -> Self {
        self.in_library_namespace = true;
        self
    }
}

// ---------------------------------------------------------------------------
// ExternalDebugFileSymbolImporter
// ---------------------------------------------------------------------------

/// Imports symbols from an external debug program into the target program.
///
/// This is the Rust port of Ghidra's `ExternalDebugFileSymbolImporter`.
/// It processes symbols from an external debug file and creates
/// corresponding functions and labels in the target program.
///
/// The import process:
///
/// 1. Verifies that the memory maps are compatible (same executable blocks).
/// 2. Iterates over all symbols in the external debug file.
/// 3. For each symbol (that is not in a library namespace):
///    - If it is a function (not a thunk), creates or updates the function.
///    - If it is a data label, creates undefined data and a label.
/// 4. Tracks statistics about the import.
///
/// # Examples
///
/// ```rust
/// use ghidra_features::external::external_debug_file_symbol_importer::{
///     ExternalDebugFileSymbolImporter, MemoryBlockInfo,
/// };
/// use ghidra_core::addr::Address;
///
/// let mut importer = ExternalDebugFileSymbolImporter::new();
///
/// // Set up compatible memory maps
/// importer.add_program_block(MemoryBlockInfo::new(".text", Address::new(0x400000), 0x2000, true));
/// importer.add_debug_block(MemoryBlockInfo::new(".text", Address::new(0x400000), 0x2000, true));
///
/// // Import symbols
/// importer.import_function_symbol("main", 0x401000, true).unwrap();
///
/// assert_eq!(importer.stats().func_symbols_copied, 1);
/// ```
#[derive(Debug)]
pub struct ExternalDebugFileSymbolImporter {
    /// Memory blocks of the target program.
    program_blocks: Vec<MemoryBlockInfo>,
    /// Memory blocks of the external debug program.
    debug_blocks: Vec<MemoryBlockInfo>,
    /// Import statistics.
    stats: ImportStats,
    /// Labels already present in the target program (address -> names).
    existing_labels: HashMap<Address, Vec<String>>,
    /// Functions already present in the target program (address -> name).
    existing_functions: HashMap<Address, String>,
    /// Whether the memory map check has been performed.
    mem_map_checked: bool,
    /// Whether the memory maps are compatible.
    mem_map_compatible: bool,
}

impl ExternalDebugFileSymbolImporter {
    /// Create a new external debug file symbol importer.
    pub fn new() -> Self {
        Self {
            program_blocks: Vec::new(),
            debug_blocks: Vec::new(),
            stats: ImportStats::new(),
            existing_labels: HashMap::new(),
            existing_functions: HashMap::new(),
            mem_map_checked: false,
            mem_map_compatible: true,
        }
    }

    /// Add a memory block from the target program.
    pub fn add_program_block(&mut self, block: MemoryBlockInfo) {
        self.program_blocks.push(block);
        self.mem_map_checked = false;
    }

    /// Add a memory block from the external debug program.
    pub fn add_debug_block(&mut self, block: MemoryBlockInfo) {
        self.debug_blocks.push(block);
        self.mem_map_checked = false;
    }

    /// Add an existing label in the target program.
    pub fn add_existing_label(&mut self, address: Address, name: impl Into<String>) {
        self.existing_labels
            .entry(address)
            .or_default()
            .push(name.into());
    }

    /// Add an existing function in the target program.
    pub fn add_existing_function(&mut self, address: Address, name: impl Into<String>) {
        self.existing_functions.insert(address, name.into());
    }

    /// Returns the import statistics.
    pub fn stats(&self) -> &ImportStats {
        &self.stats
    }

    /// Check if the memory maps of the two programs are compatible.
    ///
    /// This checks that for every executable block in the target program,
    /// there is a matching block in the debug program with the same name,
    /// start address, and size.
    pub fn check_memory_map(&mut self) -> bool {
        if self.mem_map_checked {
            return self.mem_map_compatible;
        }

        self.mem_map_compatible = true;
        for p1_block in &self.program_blocks {
            if !p1_block.is_execute {
                continue;
            }
            let p2_block = self.debug_blocks.iter().find(|b| b.start == p1_block.start);
            match p2_block {
                None => {
                    self.mem_map_compatible = false;
                    break;
                }
                Some(b) => {
                    if b.name != p1_block.name || b.size != p1_block.size {
                        self.mem_map_compatible = false;
                        break;
                    }
                }
            }
        }

        self.mem_map_checked = true;
        self.mem_map_compatible
    }

    /// Import a function symbol from the external debug file.
    ///
    /// Returns `Ok(true)` if the function was created or updated,
    /// `Ok(false)` if it was skipped (e.g., thunk), or an error.
    pub fn import_function_symbol(
        &mut self,
        name: &str,
        address: u64,
        create_label_if_exists: bool,
    ) -> Result<bool, SymbolImportError> {
        self.stats.total_symbol_count += 1;

        let addr = Address::new(address);

        // Check if the address is in a compatible block
        if !self.is_address_mapped(addr) {
            self.stats.symbol_copy_fail_count += 1;
            return Err(SymbolImportError::AddressNotMapped(format!(
                "{}@{:#x}",
                name, address
            )));
        }

        // Check if function already exists
        if let Some(existing_name) = self.existing_functions.get(&addr) {
            if existing_name != name && create_label_if_exists {
                self.add_label_if_needed(addr, name);
            }
        } else {
            // Create the function
            self.existing_functions.insert(addr, name.to_string());
            // If labels already exist at this address, also add the function name
            if create_label_if_exists && self.existing_labels.contains_key(&addr) {
                self.add_label_if_needed(addr, name);
            }
        }

        self.stats.func_symbols_copied += 1;
        Ok(true)
    }

    /// Import a data symbol from the external debug file.
    ///
    /// Returns `Ok(true)` if the data was created or updated, or an
    /// error.
    pub fn import_data_symbol(
        &mut self,
        name: &str,
        address: u64,
        size: u64,
    ) -> Result<bool, SymbolImportError> {
        self.stats.total_symbol_count += 1;

        let addr = Address::new(address);

        // Check if the address is in a compatible block
        if !self.is_address_mapped(addr) {
            self.stats.symbol_copy_fail_count += 1;
            return Err(SymbolImportError::AddressNotMapped(format!(
                "{}@{:x}",
                name, address
            )));
        }

        self.add_label_if_needed(addr, name);
        self.stats.data_symbols_copied += 1;
        Ok(true)
    }

    /// Import a symbol from the external debug file.
    ///
    /// This is the main entry point that dispatches to the appropriate
    /// import method based on the symbol type.
    pub fn import_symbol(&mut self, symbol: &DebugFileSymbol) -> Result<(), SymbolImportError> {
        // Skip symbols in library namespaces
        if symbol.in_library_namespace {
            self.stats.total_symbol_count += 1;
            self.stats.symbols_skipped += 1;
            return Ok(());
        }

        if symbol.is_function && !symbol.is_thunk {
            self.import_function_symbol(&symbol.name, symbol.address.offset, true)?;
        } else if symbol.is_label {
            let size = symbol.data_size.unwrap_or(1);
            self.import_data_symbol(&symbol.name, symbol.address.offset, size)?;
        } else {
            self.stats.total_symbol_count += 1;
            self.stats.symbols_skipped += 1;
        }

        Ok(())
    }

    /// Import all symbols from the external debug file.
    ///
    /// This is the high-level method that performs the memory map check
    /// and then iterates over all symbols.
    pub fn import_all(
        &mut self,
        symbols: &[DebugFileSymbol],
    ) -> Result<ImportStats, SymbolImportError> {
        if !self.check_memory_map() {
            return Err(SymbolImportError::MemoryMapMismatch);
        }

        for sym in symbols {
            self.import_symbol(sym)?;
        }

        Ok(self.stats.clone())
    }

    /// Check if an address is mapped in the target program's memory.
    fn is_address_mapped(&self, addr: Address) -> bool {
        self.program_blocks
            .iter()
            .any(|b| addr.offset >= b.start.offset && addr.offset < b.start.offset + b.size)
    }

    /// Add a label at the given address if one with the same name
    /// does not already exist.
    fn add_label_if_needed(&mut self, addr: Address, name: &str) {
        let labels = self.existing_labels.entry(addr).or_default();
        if !labels.iter().any(|l| l == name) {
            labels.push(name.to_string());
        }
    }
}

impl Default for ExternalDebugFileSymbolImporter {
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
    fn test_new_importer() {
        let importer = ExternalDebugFileSymbolImporter::new();
        assert_eq!(importer.stats().total_symbol_count, 0);
        assert_eq!(importer.stats().func_symbols_copied, 0);
        assert_eq!(importer.stats().data_symbols_copied, 0);
    }

    #[test]
    fn test_memory_map_compatible() {
        let mut importer = ExternalDebugFileSymbolImporter::new();
        importer.add_program_block(MemoryBlockInfo::new(
            ".text",
            Address::new(0x400000),
            0x1000,
            true,
        ));
        importer.add_debug_block(MemoryBlockInfo::new(
            ".text",
            Address::new(0x400000),
            0x1000,
            true,
        ));
        assert!(importer.check_memory_map());
    }

    #[test]
    fn test_memory_map_incompatible_name() {
        let mut importer = ExternalDebugFileSymbolImporter::new();
        importer.add_program_block(MemoryBlockInfo::new(
            ".text",
            Address::new(0x400000),
            0x1000,
            true,
        ));
        importer.add_debug_block(MemoryBlockInfo::new(
            ".code",
            Address::new(0x400000),
            0x1000,
            true,
        ));
        assert!(!importer.check_memory_map());
    }

    #[test]
    fn test_memory_map_incompatible_size() {
        let mut importer = ExternalDebugFileSymbolImporter::new();
        importer.add_program_block(MemoryBlockInfo::new(
            ".text",
            Address::new(0x400000),
            0x1000,
            true,
        ));
        importer.add_debug_block(MemoryBlockInfo::new(
            ".text",
            Address::new(0x400000),
            0x2000,
            true,
        ));
        assert!(!importer.check_memory_map());
    }

    #[test]
    fn test_memory_map_incompatible_address() {
        let mut importer = ExternalDebugFileSymbolImporter::new();
        importer.add_program_block(MemoryBlockInfo::new(
            ".text",
            Address::new(0x400000),
            0x1000,
            true,
        ));
        importer.add_debug_block(MemoryBlockInfo::new(
            ".text",
            Address::new(0x500000),
            0x1000,
            true,
        ));
        assert!(!importer.check_memory_map());
    }

    #[test]
    fn test_memory_map_missing_debug_block() {
        let mut importer = ExternalDebugFileSymbolImporter::new();
        importer.add_program_block(MemoryBlockInfo::new(
            ".text",
            Address::new(0x400000),
            0x1000,
            true,
        ));
        assert!(!importer.check_memory_map());
    }

    #[test]
    fn test_memory_map_non_executable_ignored() {
        let mut importer = ExternalDebugFileSymbolImporter::new();
        importer.add_program_block(MemoryBlockInfo::new(
            ".data",
            Address::new(0x400000),
            0x1000,
            false,
        ));
        // No matching debug block, but .data is not executable
        assert!(importer.check_memory_map());
    }

    #[test]
    fn test_import_function_symbol() {
        let mut importer = ExternalDebugFileSymbolImporter::new();
        importer.add_program_block(MemoryBlockInfo::new(
            ".text",
            Address::new(0x400000),
            0x2000,
            true,
        ));
        importer.add_debug_block(MemoryBlockInfo::new(
            ".text",
            Address::new(0x400000),
            0x2000,
            true,
        ));
        importer.check_memory_map();

        let result = importer.import_function_symbol("main", 0x401000, true);
        assert!(result.is_ok());
        assert_eq!(importer.stats().func_symbols_copied, 1);
        assert_eq!(importer.stats().total_symbol_count, 1);
    }

    #[test]
    fn test_import_data_symbol() {
        let mut importer = ExternalDebugFileSymbolImporter::new();
        importer.add_program_block(MemoryBlockInfo::new(
            ".text",
            Address::new(0x400000),
            0x1000,
            true,
        ));
        importer.add_debug_block(MemoryBlockInfo::new(
            ".text",
            Address::new(0x400000),
            0x1000,
            true,
        ));
        importer.check_memory_map();

        let result = importer.import_data_symbol("global_var", 0x400100, 4);
        assert!(result.is_ok());
        assert_eq!(importer.stats().data_symbols_copied, 1);
        assert_eq!(importer.stats().total_symbol_count, 1);
    }

    #[test]
    fn test_import_unmapped_address() {
        let mut importer = ExternalDebugFileSymbolImporter::new();
        importer.add_program_block(MemoryBlockInfo::new(
            ".text",
            Address::new(0x400000),
            0x1000,
            true,
        ));
        importer.add_debug_block(MemoryBlockInfo::new(
            ".text",
            Address::new(0x400000),
            0x1000,
            true,
        ));
        importer.check_memory_map();

        // Address outside the mapped block
        let result = importer.import_function_symbol("main", 0x500000, true);
        assert!(result.is_err());
        assert_eq!(importer.stats().symbol_copy_fail_count, 1);
    }

    #[test]
    fn test_import_symbol_skips_library_namespace() {
        let mut importer = ExternalDebugFileSymbolImporter::new();
        importer.add_program_block(MemoryBlockInfo::new(
            ".text",
            Address::new(0x400000),
            0x1000,
            true,
        ));
        importer.add_debug_block(MemoryBlockInfo::new(
            ".text",
            Address::new(0x400000),
            0x1000,
            true,
        ));

        let sym =
            DebugFileSymbol::function("printf", Address::new(0x400100)).in_library_namespace();
        let symbols = vec![sym];
        let stats = importer.import_all(&symbols).unwrap();
        assert_eq!(stats.symbols_skipped, 1);
        assert_eq!(stats.func_symbols_copied, 0);
    }

    #[test]
    fn test_import_all_memory_map_mismatch() {
        let mut importer = ExternalDebugFileSymbolImporter::new();
        importer.add_program_block(MemoryBlockInfo::new(
            ".text",
            Address::new(0x400000),
            0x1000,
            true,
        ));
        // No matching debug block

        let symbols = vec![DebugFileSymbol::function("main", Address::new(0x400100))];
        let result = importer.import_all(&symbols);
        assert!(result.is_err());
        match result.unwrap_err() {
            SymbolImportError::MemoryMapMismatch => {}
            _ => panic!("Expected MemoryMapMismatch error"),
        }
    }

    #[test]
    fn test_import_all_success() {
        let mut importer = ExternalDebugFileSymbolImporter::new();
        importer.add_program_block(MemoryBlockInfo::new(
            ".text",
            Address::new(0x400000),
            0x1000,
            true,
        ));
        importer.add_debug_block(MemoryBlockInfo::new(
            ".text",
            Address::new(0x400000),
            0x1000,
            true,
        ));

        let symbols = vec![
            DebugFileSymbol::function("main", Address::new(0x400100)),
            DebugFileSymbol::data("global_var", Address::new(0x400200), 4),
        ];
        let stats = importer.import_all(&symbols).unwrap();
        assert_eq!(stats.func_symbols_copied, 1);
        assert_eq!(stats.data_symbols_copied, 1);
        assert_eq!(stats.total_symbol_count, 2);
    }

    #[test]
    fn test_import_thunk_function_skipped() {
        let mut importer = ExternalDebugFileSymbolImporter::new();
        importer.add_program_block(MemoryBlockInfo::new(
            ".text",
            Address::new(0x400000),
            0x1000,
            true,
        ));
        importer.add_debug_block(MemoryBlockInfo::new(
            ".text",
            Address::new(0x400000),
            0x1000,
            true,
        ));

        let sym = DebugFileSymbol::thunk_function("thunk_func", Address::new(0x400100));
        let symbols = vec![sym];
        let stats = importer.import_all(&symbols).unwrap();
        assert_eq!(stats.symbols_skipped, 1);
        assert_eq!(stats.func_symbols_copied, 0);
    }

    #[test]
    fn test_stats_summary() {
        let mut stats = ImportStats::new();
        stats.func_symbols_copied = 10;
        stats.data_symbols_copied = 5;
        stats.symbols_skipped = 3;
        stats.symbol_copy_fail_count = 1;
        stats.total_symbol_count = 19;

        let summary = stats.summary();
        assert!(summary.contains("10"));
        assert!(summary.contains("5"));
        assert!(summary.contains("3"));
        assert!(summary.contains("1"));
        assert!(summary.contains("19"));
    }

    #[test]
    fn test_stats_total_copied() {
        let mut stats = ImportStats::new();
        stats.func_symbols_copied = 10;
        stats.data_symbols_copied = 5;
        assert_eq!(stats.total_copied(), 15);
    }

    #[test]
    fn test_debug_file_symbol_function() {
        let sym = DebugFileSymbol::function("main", Address::new(0x401000));
        assert_eq!(sym.name, "main");
        assert!(sym.is_function);
        assert!(!sym.is_thunk);
        assert!(!sym.is_label);
        assert!(!sym.in_library_namespace);
    }

    #[test]
    fn test_debug_file_symbol_thunk() {
        let sym = DebugFileSymbol::thunk_function("thunk", Address::new(0x401000));
        assert!(sym.is_function);
        assert!(sym.is_thunk);
    }

    #[test]
    fn test_debug_file_symbol_data() {
        let sym = DebugFileSymbol::data("global", Address::new(0x402000), 8);
        assert!(sym.is_label);
        assert!(!sym.is_function);
        assert_eq!(sym.data_size, Some(8));
    }

    #[test]
    fn test_debug_file_symbol_library_namespace() {
        let sym =
            DebugFileSymbol::function("printf", Address::new(0x401000)).in_library_namespace();
        assert!(sym.in_library_namespace);
    }

    #[test]
    fn test_existing_labels() {
        let mut importer = ExternalDebugFileSymbolImporter::new();
        importer.add_program_block(MemoryBlockInfo::new(
            ".text",
            Address::new(0x400000),
            0x1000,
            true,
        ));
        importer.add_debug_block(MemoryBlockInfo::new(
            ".text",
            Address::new(0x400000),
            0x1000,
            true,
        ));
        importer.add_existing_label(Address::new(0x400100), "existing_label");

        // Import a function at the same address with a different name
        let result = importer.import_function_symbol("new_name", 0x400100, true);
        assert!(result.is_ok());

        // The existing label should still be there, and the new one added
        let labels = importer
            .existing_labels
            .get(&Address::new(0x400100))
            .unwrap();
        assert!(labels.contains(&"existing_label".to_string()));
        assert!(labels.contains(&"new_name".to_string()));
    }

    #[test]
    fn test_error_display() {
        let err = SymbolImportError::MemoryMapMismatch;
        assert!(err.to_string().contains("memory map"));

        let err = SymbolImportError::AddressNotMapped("foo@1000".to_string());
        assert!(err.to_string().contains("foo@1000"));

        let err = SymbolImportError::InvalidSymbol("bad".to_string());
        assert!(err.to_string().contains("bad"));

        let err = SymbolImportError::FunctionCreationFailed("f".to_string());
        assert!(err.to_string().contains("f"));

        let err = SymbolImportError::DataCreationFailed("d".to_string());
        assert!(err.to_string().contains("d"));

        let err = SymbolImportError::Other("misc".to_string());
        assert_eq!(err.to_string(), "misc");
    }

    #[test]
    fn test_memory_block_info() {
        let block = MemoryBlockInfo::new(".text", Address::new(0x400000), 0x1000, true);
        assert_eq!(block.name, ".text");
        assert_eq!(block.start, Address::new(0x400000));
        assert_eq!(block.size, 0x1000);
        assert!(block.is_execute);
    }

    #[test]
    fn test_default() {
        let importer = ExternalDebugFileSymbolImporter::default();
        assert_eq!(importer.stats().total_symbol_count, 0);
    }
}
