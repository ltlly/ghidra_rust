//! Entry point analyzer -- ported from Ghidra's `EntryPointAnalyzer.java`.
//!
//! This analyzer disassembles from known entry points in newly added memory,
//! including:
//! - Code map markers from the importer
//! - External symbols marked as code
//! - Dummy function placeholders
//! - Exported entry points

use std::collections::{HashMap, HashSet};

use crate::base::analyzer::core::*;
use crate::base::analyzer::priority::*;
use crate::base::analyzer::r#trait::*;

// ---------------------------------------------------------------------------
// EntryPointAnalyzer
// ---------------------------------------------------------------------------

/// Analyzer that disassembles from known entry points.
///
/// When new memory is added to a program, this analyzer identifies the
/// initial disassembly points from code markers, external symbols, and
/// exported entry points, then disassembles from those points.
#[derive(Debug, Clone)]
pub struct EntryPointAnalyzer {
    base: AbstractAnalyzer,
    /// Whether to respect the execute flag on memory blocks.
    respect_execute_flags: bool,
}

impl EntryPointAnalyzer {
    /// Create a new entry point analyzer.
    pub fn new() -> Self {
        let mut base = AbstractAnalyzer::new(
            "Disassemble Entry Points",
            "Disassembles entry points in newly added memory.",
            AnalyzerType::Byte,
        );
        base.set_priority(AnalysisPriority::BLOCK_ANALYSIS);
        base.set_default_enablement(true);

        Self {
            base,
            respect_execute_flags: true,
        }
    }

    /// Get whether the analyzer respects execute flags.
    pub fn respect_execute_flags(&self) -> bool {
        self.respect_execute_flags
    }

    /// Set whether the analyzer respects execute flags.
    pub fn set_respect_execute_flags(&mut self, v: bool) {
        self.respect_execute_flags = v;
    }

    /// Collect entry point addresses from symbols in the program.
    ///
    /// Returns addresses marked as code symbols, external entry points,
    /// and exported symbols within the given address set.
    pub fn collect_entry_points(
        &self,
        program: &Program,
        address_set: &AddressSet,
    ) -> EntryPointCollection {
        let mut collection = EntryPointCollection::new();
        let mut do_now = HashSet::new();
        let mut do_later = HashSet::new();

        // Collect code symbols
        for (addr, name) in &program.symbols {
            if address_set.contains(addr) && !program.function_manager.functions.contains_key(addr) {
                do_now.insert(*addr);
                collection.code_symbols.push(SymbolEntry {
                    address: *addr,
                    name: name.clone(),
                });
            }
        }

        // Collect external references
        for (addr, name) in &program.external_references {
            if address_set.contains(addr) {
                do_now.insert(*addr);
                collection.external_entries.push(SymbolEntry {
                    address: *addr,
                    name: name.clone(),
                });
            }
        }

        collection.immediate_set = AddressSet::from_address(*do_now.iter().next().unwrap_or(&Address::ZERO));
        for addr in &do_now {
            collection.immediate_set.add(*addr);
        }
        collection.deferred_set = AddressSet::from_address(*do_later.iter().next().unwrap_or(&Address::ZERO));
        for addr in &do_later {
            collection.deferred_set.add(*addr);
        }

        collection
    }

    /// Check if the program has a single external entry point.
    pub fn is_single_external_entry_point(
        &self,
        _program: &Program,
        external_count: usize,
        immediate_set: &HashSet<Address>,
    ) -> bool {
        external_count == 1 && immediate_set.len() == 1
    }
}

impl Default for EntryPointAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

/// A collected set of entry point addresses.
#[derive(Debug, Clone, Default)]
pub struct EntryPointCollection {
    /// Code symbol entries found.
    pub code_symbols: Vec<SymbolEntry>,
    /// External entries found.
    pub external_entries: Vec<SymbolEntry>,
    /// Entry points to disassemble immediately.
    pub immediate_set: AddressSet,
    /// Entry points to disassemble later (suspect functions).
    pub deferred_set: AddressSet,
}

impl EntryPointCollection {
    /// Create a new empty collection.
    pub fn new() -> Self {
        Self::default()
    }
}

/// A named address entry.
#[derive(Debug, Clone)]
pub struct SymbolEntry {
    /// The address.
    pub address: Address,
    /// The symbol name.
    pub name: String,
}

impl Analyzer for EntryPointAnalyzer {
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

    fn default_enablement(&self, _program: &Program) -> bool {
        self.base.default_enablement(_program)
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
        monitor.check_cancelled()?;
        monitor.initialize(set.num_addresses());
        monitor.set_message("Disassembling entry points...");

        // If respecting execute flags, intersect with executable memory
        let effective_set = if self.respect_execute_flags {
            let mut exec_set = AddressSet::new();
            for block in &program.memory_blocks {
                if block.is_execute {
                    exec_set.add_range(AddressRange::new(
                        block.start,
                        block.start.add(block.size.saturating_sub(1)),
                    ));
                }
            }
            if exec_set.is_empty() {
                set.clone()
            } else {
                set.intersect(&exec_set)
            }
        } else {
            set.clone()
        };

        let collection = self.collect_entry_points(program, &effective_set);

        log.append_msg(format!(
            "Found {} code symbols, {} external entries",
            collection.code_symbols.len(),
            collection.external_entries.len()
        ));

        // In a full implementation, this would invoke the Disassembler
        // on each entry point. Here we just report what was found.
        for entry in &collection.code_symbols {
            if monitor.is_cancelled() {
                break;
            }
            log.append_msg(format!("Entry point: {} at {}", entry.name, entry.address));
        }

        Ok(true)
    }

    fn register_options(&self, _program: &Program) -> Vec<AnalysisOption> {
        vec![AnalysisOption {
            name: "Respect Execute Flag".to_string(),
            description: "Respect Execute flag on memory blocks when checking entry points for code.".to_string(),
            default_value: AnalysisOptionValue::Bool(true),
            current_value: AnalysisOptionValue::Bool(self.respect_execute_flags),
        }]
    }

    fn options_changed(&mut self, options: &HashMap<String, AnalysisOptionValue>) {
        if let Some(AnalysisOptionValue::Bool(v)) = options.get("Respect Execute Flag") {
            self.respect_execute_flags = *v;
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entry_point_analyzer_creation() {
        let analyzer = EntryPointAnalyzer::new();
        assert_eq!(analyzer.name(), "Disassemble Entry Points");
        assert!(analyzer.default_enablement(&Program::new("test", Language {
            processor: "x86".into(),
            variant: "LE".into(),
            size: 64,
        })));
        assert!(analyzer.respect_execute_flags());
    }

    #[test]
    fn test_entry_point_analyzer_can_analyze() {
        let analyzer = EntryPointAnalyzer::new();
        let prog = Program::new("test", Language {
            processor: "ARM".into(),
            variant: "LE".into(),
            size: 32,
        });
        assert!(analyzer.can_analyze(&prog));
    }

    #[test]
    fn test_entry_point_collection_defaults() {
        let collection = EntryPointCollection::default();
        assert!(collection.code_symbols.is_empty());
        assert!(collection.external_entries.is_empty());
        assert!(collection.immediate_set.is_empty());
        assert!(collection.deferred_set.is_empty());
    }

    #[test]
    fn test_collect_entry_points() {
        let analyzer = EntryPointAnalyzer::new();
        let mut prog = Program::new("test", Language {
            processor: "x86".into(),
            variant: "LE".into(),
            size: 64,
        });
        prog.symbols.insert(Address::new(0x401000), "main".to_string());
        prog.symbols.insert(Address::new(0x401100), "start".to_string());
        prog.external_references.insert(Address::new(0x402000), "printf".to_string());

        let mut set = AddressSet::new();
        set.add_range(AddressRange::new(Address::new(0x400000), Address::new(0x40FFFF)));

        let collection = analyzer.collect_entry_points(&prog, &set);
        assert_eq!(collection.code_symbols.len(), 2);
        assert_eq!(collection.external_entries.len(), 1);
    }

    #[test]
    fn test_is_single_external_entry_point() {
        let analyzer = EntryPointAnalyzer::new();
        let prog = Program::new("test", Language {
            processor: "x86".into(),
            variant: "LE".into(),
            size: 64,
        });

        let mut immediate = HashSet::new();
        immediate.insert(Address::new(0x1000));
        assert!(analyzer.is_single_external_entry_point(&prog, 1, &immediate));

        immediate.insert(Address::new(0x2000));
        assert!(!analyzer.is_single_external_entry_point(&prog, 1, &immediate));
    }

    #[test]
    fn test_register_options() {
        let analyzer = EntryPointAnalyzer::new();
        let prog = Program::new("test", Language {
            processor: "x86".into(),
            variant: "LE".into(),
            size: 64,
        });
        let opts = analyzer.register_options(&prog);
        assert_eq!(opts.len(), 1);
        assert_eq!(opts[0].name, "Respect Execute Flag");
    }
}
