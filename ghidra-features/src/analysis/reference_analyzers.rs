// ===========================================================================
// Reference Analyzers -- ported from Ghidra's `ghidra.app.plugin.core.analysis`
//
// Includes:
// - DataOperandReferenceAnalyzer  -- discovers references from data operands
// - OperandReferenceAnalyzer      -- discovers references from instruction operands
// - ScalarOperandAnalyzer         -- finds scalar values that look like addresses
// - ExternalSymbolResolverAnalyzer -- resolves external library symbols
// ===========================================================================

use std::collections::{BTreeMap, HashMap};

use ghidra_core::Address;

/// A discovered reference candidate.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ReferenceCandidate {
    /// Source address of the reference.
    pub from_address: Address,
    /// Target address of the reference.
    pub to_address: Address,
    /// The type of reference.
    pub ref_type: ReferenceType,
}

/// The type of reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReferenceType {
    /// A direct (absolute) reference.
    Direct,
    /// A read reference.
    Read,
    /// A write reference.
    Write,
    /// A conditional reference.
    Conditional,
    /// A computed/indirect reference.
    Indirect,
    /// An external reference to a library function.
    External,
}

// ---------------------------------------------------------------------------
// DataOperandReferenceAnalyzer
// ---------------------------------------------------------------------------

/// Analyzes data operands in the listing for address-like values and creates
/// references to the discovered targets.
///
/// Ported from `ghidra.app.plugin.core.analysis.DataOperandReferenceAnalyzer`.
#[derive(Debug, Clone)]
pub struct DataOperandReferenceAnalyzer {
    /// Name of this analyzer.
    pub name: String,
    /// Whether the analyzer is enabled.
    pub enabled: bool,
    /// Minimum address value to consider as a valid reference target.
    pub min_address: u64,
    /// Maximum address value to consider as a valid reference target.
    pub max_address: u64,
    /// Maximum data items to analyze per invocation.
    pub max_items: usize,
}

impl DataOperandReferenceAnalyzer {
    /// Create a new analyzer with default settings.
    pub fn new() -> Self {
        Self {
            name: "Data Operand Reference Analyzer".into(),
            enabled: true,
            min_address: 0x1000,
            max_address: 0xFFFF_FFFF_FFFF_FFFF,
            max_items: 10_000,
        }
    }

    /// Set the valid address range for reference targets.
    pub fn set_address_range(&mut self, min: u64, max: u64) {
        self.min_address = min;
        self.max_address = max;
    }

    /// Analyze a set of data items and return discovered references.
    pub fn analyze(&self, data_items: &[(Address, u64)]) -> Vec<ReferenceCandidate> {
        let mut refs = Vec::new();
        for (addr, value) in data_items.iter().take(self.max_items) {
            if *value >= self.min_address && *value <= self.max_address {
                refs.push(ReferenceCandidate {
                    from_address: *addr,
                    to_address: Address::new(*value),
                    ref_type: ReferenceType::Read,
                });
            }
        }
        refs
    }
}

impl Default for DataOperandReferenceAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// OperandReferenceAnalyzer
// ---------------------------------------------------------------------------

/// Analyzes instruction operands for address references.
///
/// Ported from `ghidra.app.plugin.core.analysis.OperandReferenceAnalyzer`.
#[derive(Debug, Clone)]
pub struct OperandReferenceAnalyzer {
    /// Name of this analyzer.
    pub name: String,
    /// Whether the analyzer is enabled.
    pub enabled: bool,
    /// Processor-specific operand patterns to recognize.
    pub patterns: Vec<OperandPattern>,
    /// Number of instructions analyzed.
    pub analyzed_count: usize,
}

/// A pattern for matching operand references.
#[derive(Debug, Clone)]
pub struct OperandPattern {
    /// The pattern name.
    pub name: String,
    /// The reference type this pattern produces.
    pub ref_type: ReferenceType,
    /// Whether this pattern applies to memory operands only.
    pub memory_only: bool,
}

impl OperandReferenceAnalyzer {
    /// Create a new analyzer with default patterns.
    pub fn new() -> Self {
        Self {
            name: "Operand Reference Analyzer".into(),
            enabled: true,
            patterns: vec![
                OperandPattern {
                    name: "direct_address".into(),
                    ref_type: ReferenceType::Direct,
                    memory_only: false,
                },
                OperandPattern {
                    name: "indirect_address".into(),
                    ref_type: ReferenceType::Indirect,
                    memory_only: true,
                },
                OperandPattern {
                    name: "memory_read".into(),
                    ref_type: ReferenceType::Read,
                    memory_only: true,
                },
                OperandPattern {
                    name: "memory_write".into(),
                    ref_type: ReferenceType::Write,
                    memory_only: true,
                },
            ],
            analyzed_count: 0,
        }
    }

    /// Analyze an instruction's operands and return reference candidates.
    ///
    /// `operands` is a slice of (operand_index, operand_value) pairs.
    pub fn analyze_instruction(
        &mut self,
        addr: Address,
        operands: &[(usize, u64)],
    ) -> Vec<ReferenceCandidate> {
        self.analyzed_count += 1;
        let mut refs = Vec::new();

        for (_idx, value) in operands {
            if looks_like_address(*value) {
                refs.push(ReferenceCandidate {
                    from_address: addr,
                    to_address: Address::new(*value),
                    ref_type: ReferenceType::Direct,
                });
            }
        }

        refs
    }
}

impl Default for OperandReferenceAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// ScalarOperandAnalyzer
// ---------------------------------------------------------------------------

/// Finds scalar instruction operands that appear to be addresses and
/// creates references to them.
///
/// Ported from `ghidra.app.plugin.core.analysis.ScalarOperandAnalyzer`.
#[derive(Debug, Clone)]
pub struct ScalarOperandAnalyzer {
    /// Name of this analyzer.
    pub name: String,
    /// Whether the analyzer is enabled.
    pub enabled: bool,
    /// Minimum scalar value to consider.
    pub min_scalar: u64,
    /// Maximum scalar value to consider.
    pub max_scalar: u64,
    /// Scalar size in bits (0 = any size).
    pub scalar_bits: u32,
    /// Whether to also check for negative values interpreted as addresses.
    pub check_negative: bool,
    /// Number of scalars found.
    pub found_count: usize,
}

impl ScalarOperandAnalyzer {
    /// Create a new analyzer with default settings.
    pub fn new() -> Self {
        Self {
            name: "Scalar Operand Analyzer".into(),
            enabled: true,
            min_scalar: 0x1000,
            max_scalar: 0xFFFF_FFFF,
            scalar_bits: 0,
            check_negative: false,
            found_count: 0,
        }
    }

    /// Test whether a scalar value looks like a valid address.
    pub fn is_valid_address_scalar(&self, value: u64) -> bool {
        if self.scalar_bits > 0 {
            let mask = (1u64 << self.scalar_bits) - 1;
            let masked = value & mask;
            if masked != value {
                return false;
            }
        }
        value >= self.min_scalar && value <= self.max_scalar
    }

    /// Analyze scalar operands and return reference candidates.
    pub fn analyze_scalars(
        &mut self,
        addr: Address,
        scalars: &[u64],
    ) -> Vec<ReferenceCandidate> {
        let mut refs = Vec::new();
        for &value in scalars {
            if self.is_valid_address_scalar(value) {
                self.found_count += 1;
                refs.push(ReferenceCandidate {
                    from_address: addr,
                    to_address: Address::new(value),
                    ref_type: ReferenceType::Direct,
                });
            }
        }
        refs
    }
}

impl Default for ScalarOperandAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// ExternalSymbolResolverAnalyzer
// ---------------------------------------------------------------------------

/// Resolves external library symbols by matching unresolved imports
/// against known library signatures.
///
/// Ported from `ghidra.app.plugin.core.analysis.ExternalSymbolResolverAnalyzer`.
#[derive(Debug, Clone)]
pub struct ExternalSymbolResolverAnalyzer {
    /// Name of this analyzer.
    pub name: String,
    /// Whether the analyzer is enabled.
    pub enabled: bool,
    /// Known library name -> (symbol name -> address).
    pub library_symbols: HashMap<String, BTreeMap<String, u64>>,
    /// Resolved external references.
    pub resolved: Vec<ResolvedExternal>,
}

/// A resolved external reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedExternal {
    /// The external address in the program.
    pub external_addr: Address,
    /// The library name.
    pub library: String,
    /// The symbol name within the library.
    pub symbol: String,
    /// The resolved address in the library.
    pub library_addr: u64,
}

impl ExternalSymbolResolverAnalyzer {
    /// Create a new resolver.
    pub fn new() -> Self {
        Self {
            name: "External Symbol Resolver Analyzer".into(),
            enabled: true,
            library_symbols: HashMap::new(),
            resolved: Vec::new(),
        }
    }

    /// Register symbols from a library.
    pub fn add_library(
        &mut self,
        library: impl Into<String>,
        symbols: BTreeMap<String, u64>,
    ) {
        self.library_symbols.insert(library.into(), symbols);
    }

    /// Try to resolve an unresolved external by name.
    pub fn resolve(
        &mut self,
        external_addr: Address,
        symbol_name: &str,
    ) -> Option<&ResolvedExternal> {
        for (lib_name, symbols) in &self.library_symbols {
            if let Some(&lib_addr) = symbols.get(symbol_name) {
                let resolved = ResolvedExternal {
                    external_addr,
                    library: lib_name.clone(),
                    symbol: symbol_name.to_string(),
                    library_addr: lib_addr,
                };
                self.resolved.push(resolved);
                return self.resolved.last();
            }
        }
        None
    }

    /// Get all resolved externals.
    pub fn all_resolved(&self) -> &[ResolvedExternal] {
        &self.resolved
    }

    /// Get the number of resolved externals.
    pub fn resolved_count(&self) -> usize {
        self.resolved.len()
    }
}

impl Default for ExternalSymbolResolverAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Heuristic check: does a value look like it could be a valid address?
fn looks_like_address(value: u64) -> bool {
    // Reject obviously non-address values
    value >= 0x100 && value < 0xFFFF_FFFF_FFFF_0000
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_data_operand_analyzer_basic() {
        let analyzer = DataOperandReferenceAnalyzer::new();
        let items = vec![
            (Address::new(0x100), 0x401000),
            (Address::new(0x104), 0x0000), // too low
            (Address::new(0x108), 0x402000),
        ];
        let refs = analyzer.analyze(&items);
        assert_eq!(refs.len(), 2);
        assert_eq!(refs[0].to_address, Address::new(0x401000));
        assert_eq!(refs[1].to_address, Address::new(0x402000));
    }

    #[test]
    fn test_data_operand_analyzer_range() {
        let mut analyzer = DataOperandReferenceAnalyzer::new();
        analyzer.set_address_range(0x400000, 0x500000);
        let items = vec![
            (Address::new(0x100), 0x300000), // below range
            (Address::new(0x104), 0x400000), // at min
            (Address::new(0x108), 0x600000), // above range
        ];
        let refs = analyzer.analyze(&items);
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].to_address, Address::new(0x400000));
    }

    #[test]
    fn test_operand_reference_analyzer() {
        let mut analyzer = OperandReferenceAnalyzer::new();
        let operands = vec![(0, 0x401000), (1, 0x50), (2, 0x402000)];
        let refs = analyzer.analyze_instruction(Address::new(0x1000), &operands);
        assert_eq!(refs.len(), 2);
        assert_eq!(analyzer.analyzed_count, 1);
    }

    #[test]
    fn test_scalar_operand_analyzer() {
        let mut analyzer = ScalarOperandAnalyzer::new();
        let scalars = vec![0x401000, 0x50, 0x402000, 0x0];
        let refs = analyzer.analyze_scalars(Address::new(0x1000), &scalars);
        assert_eq!(refs.len(), 2);
        assert_eq!(analyzer.found_count, 2);
    }

    #[test]
    fn test_scalar_operand_analyzer_bits() {
        let mut analyzer = ScalarOperandAnalyzer::new();
        analyzer.scalar_bits = 16;
        assert!(analyzer.is_valid_address_scalar(0x8000));
        assert!(!analyzer.is_valid_address_scalar(0x18000)); // exceeds 16 bits
    }

    #[test]
    fn test_external_symbol_resolver() {
        let mut resolver = ExternalSymbolResolverAnalyzer::new();
        let mut symbols = BTreeMap::new();
        symbols.insert("printf".to_string(), 0x7fff1234);
        symbols.insert("malloc".to_string(), 0x7fff5678);
        resolver.add_library("libc.so", symbols);

        let result = resolver.resolve(Address::new(0x400000), "printf");
        assert!(result.is_some());
        let resolved = result.unwrap();
        assert_eq!(resolved.library, "libc.so");
        assert_eq!(resolved.symbol, "printf");
        assert_eq!(resolved.library_addr, 0x7fff1234);
        assert_eq!(resolver.resolved_count(), 1);

        // Unknown symbol
        assert!(resolver
            .resolve(Address::new(0x400004), "unknown_func")
            .is_none());
    }

    #[test]
    fn test_looks_like_address() {
        assert!(!looks_like_address(0));
        assert!(!looks_like_address(0x50));
        assert!(looks_like_address(0x100));
        assert!(looks_like_address(0x401000));
        assert!(!looks_like_address(u64::MAX));
    }
}
