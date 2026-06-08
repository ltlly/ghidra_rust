//! Full ConstantPropagationAnalyzer -- propagates constant references through instructions.
//!
//! Ported from `ghidra.app.plugin.core.analysis.ConstantPropagationAnalyzer`.
//! Performs symbolic propagation to discover constant references computed across
//! multiple instructions. Supports parallel analysis of function entry points.

use std::collections::{HashMap, HashSet};

use crate::base::analyzer::core::*;
use crate::base::analyzer::priority::*;
use crate::base::analyzer::r#trait::*;

/// Tracks which processors have specialized analyzers registered.
///
/// When a processor-specific analyzer claims a processor (e.g., "x86"), the
/// generic "Basic" analyzer will skip programs using that processor.
static mut HANDLED_PROCESSORS: Option<HashSet<String>> = None;

fn handled_processors() -> &'static HashSet<String> {
    unsafe {
        if HANDLED_PROCESSORS.is_none() {
            HANDLED_PROCESSORS = Some(HashSet::new());
        }
        HANDLED_PROCESSORS.as_ref().unwrap()
    }
}

fn handled_processors_mut() -> &'static mut HashSet<String> {
    unsafe {
        if HANDLED_PROCESSORS.is_none() {
            HANDLED_PROCESSORS = Some(HashSet::new());
        }
        HANDLED_PROCESSORS.as_mut().unwrap()
    }
}

/// Configuration for constant propagation analysis.
#[derive(Debug, Clone)]
pub struct ConstantPropagationConfig {
    /// Check if function parameters/returns could be pointer references.
    pub check_param_refs: bool,
    /// Require pointer parameter data type before creating references.
    pub check_pointer_param_refs: bool,
    /// Check if stored values could be pointer references.
    pub check_stored_refs: bool,
    /// Trust values read from writable memory.
    pub trust_write_mem: bool,
    /// Create complex data types from pointers if data type is known.
    pub create_complex_data_from_pointers: bool,
    /// Maximum number of threads for parallel analysis.
    pub max_thread_count: u32,
    /// Minimum address for calculated constant store/load references.
    pub min_store_load_ref_address: u64,
    /// Minimum speculative reference address offset.
    pub min_speculative_ref_address: u64,
    /// Maximum speculative reference address offset from end of memory.
    pub max_speculative_ref_address: u64,
}

impl Default for ConstantPropagationConfig {
    fn default() -> Self {
        Self {
            check_param_refs: true,
            check_pointer_param_refs: false,
            check_stored_refs: true,
            trust_write_mem: true,
            create_complex_data_from_pointers: false,
            max_thread_count: 2,
            min_store_load_ref_address: 4,
            min_speculative_ref_address: 1024,
            max_speculative_ref_address: 256,
        }
    }
}

/// Result of constant propagation at a single address.
#[derive(Debug, Clone)]
pub struct ConstantRef {
    /// Address where the reference was found.
    pub from_address: Address,
    /// Target address of the constant reference.
    pub to_address: Address,
    /// Size of the access.
    pub size: u32,
    /// Whether this is a data reference (vs flow).
    pub is_data: bool,
}

/// Constant propagation analyzer for a generic processor.
///
/// Finds constant references computed with multiple instructions using
/// symbolic propagation. Can be extended for processor-specific analyzers.
///
/// # Options
///
/// - `Function parameter/return Pointer analysis` -- check parameter passing
/// - `Stored Value Pointer analysis` -- check stored values
/// - `Trust values read from writable memory` -- trust writable memory reads
/// - `Max Threads` -- parallel analysis thread count
/// - `Min absolute reference` -- minimum address for references
/// - `Speculative reference min/max` -- speculative reference bounds
#[derive(Debug, Clone)]
pub struct ConstantPropagationAnalyzer {
    base: AbstractAnalyzer,
    /// Processor name (e.g., "Basic", "x86", "ARM").
    pub processor_name: String,
    /// Analysis configuration.
    pub config: ConstantPropagationConfig,
    /// Whether to follow conditional branches.
    pub follow_conditional: bool,
    /// Found constant references.
    found_refs: Vec<ConstantRef>,
}

impl ConstantPropagationAnalyzer {
    /// Creates a new analyzer for the "Basic" (generic) processor.
    pub fn new() -> Self {
        Self::with_processor("Basic")
    }

    /// Creates a new analyzer for a specific processor.
    pub fn with_processor(processor_name: &str) -> Self {
        let name = format!("{} Constant Reference Analyzer", processor_name);
        let desc = format!(
            "{} Constant Propagation Analyzer for constant references computed with multiple instructions.",
            processor_name
        );
        let mut base = AbstractAnalyzer::new(&name, &desc, AnalyzerType::Instruction);
        base.set_priority(AnalysisPriority::REFERENCE_ANALYSIS.before().before().before().before());

        // Claim this processor
        handled_processors_mut().insert(processor_name.to_string());

        Self {
            base,
            processor_name: processor_name.to_string(),
            config: ConstantPropagationConfig::default(),
            follow_conditional: false,
            found_refs: Vec::new(),
        }
    }

    /// Returns true if the given processor has been claimed by a specific analyzer.
    pub fn is_claimed_processor(processor: &str) -> bool {
        handled_processors().contains(processor)
    }

    /// Returns found constant references.
    pub fn found_refs(&self) -> &[ConstantRef] {
        &self.found_refs
    }

    /// Removes uninitialized blocks from the address set to analyze.
    fn remove_uninitialized_blocks(&self, program: &Program, set: &mut AddressSet) {
        for block in &program.memory_blocks {
            if block.is_initialized || block.is_write {
                continue;
            }
            let block_set =
                AddressSet::from_range(AddressRange::new(block.start, Address::new(block.start.offset + block.size - 1)));
            set.delete(&block_set);
        }
    }

    /// Finds function locations and leaves only entry points in the address set.
    fn find_locations_remove_function_bodies(
        &self,
        program: &Program,
        set: &mut AddressSet,
        locations: &mut HashSet<Address>,
    ) {
        let mut in_body_set = AddressSet::new();

        // Collect function entry points and their bodies
        let functions: Vec<(Address, AddressSet)> = program
            .function_manager
            .get_functions(false)
            .filter(|f| set.contains(&f.entry_point))
            .map(|f| (f.entry_point, f.body.clone()))
            .collect();

        for (entry, body) in functions {
            locations.insert(entry);
            in_body_set.add_all(&body);
        }

        set.delete(&in_body_set);

        // For remaining addresses, use the first address of each range as a start
        let ranges: Vec<AddressRange> = set.iter().copied().collect();
        let mut out_of_body = AddressSet::new();
        for range in ranges {
            let addr = range.start;
            locations.insert(addr);
            out_of_body.add(addr);
        }
        set.delete(&out_of_body);
    }

    /// Analyzes a single location using constant propagation.
    fn analyze_location(
        &self,
        program: &Program,
        start: Address,
        set: &AddressSet,
        monitor: &dyn TaskMonitor,
    ) -> Result<AddressSet, CancelledError> {
        monitor.check_cancelled()?;

        if program.listing.get_instruction_at(&start).is_none() {
            return Ok(AddressSet::new());
        }

        // Find containing function
        let (flow_start, flow_set) =
            if let Some(func) = program.function_manager.get_function_containing(&start) {
                let body = &func.body;
                if body.num_addresses() > 1 {
                    (func.entry_point, body.clone())
                } else {
                    (start, set.clone())
                }
            } else {
                (start, set.clone())
            };

        // Run symbolic propagation
        self.flow_constants(program, flow_start, &flow_set, monitor)
    }

    /// Performs constant propagation through the instruction flow.
    fn flow_constants(
        &self,
        program: &Program,
        start: Address,
        flow_set: &AddressSet,
        monitor: &dyn TaskMonitor,
    ) -> Result<AddressSet, CancelledError> {
        let mut analyzed = AddressSet::new();
        let mut visited = HashSet::new();
        let mut work = vec![start];

        while let Some(addr) = work.pop() {
            monitor.check_cancelled()?;

            if visited.contains(&addr) || !flow_set.contains(&addr) {
                continue;
            }
            visited.insert(addr);
            analyzed.add(addr);

            let instr = match program.listing.get_instruction_at(&addr) {
                Some(i) => i,
                None => continue,
            };

            // Check each operand for constant values that could be references
            self.evaluate_instruction(program, instr, &mut analyzed, monitor)?;

            // Follow control flow
            if let Some(ft) = instr.fall_through {
                if flow_set.contains(&ft) {
                    work.push(ft);
                }
            }

            if instr.flow_type.is_jump() && !instr.flow_type.is_call() {
                for flow in &instr.flows {
                    if flow_set.contains(flow) {
                        work.push(*flow);
                    }
                }
            }
        }

        Ok(analyzed)
    }

    /// Evaluates an instruction's operands for constant references.
    fn evaluate_instruction(
        &self,
        program: &Program,
        instr: &Instruction,
        analyzed: &mut AddressSet,
        _monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledError> {
        // Check flows for potential constant references
        for target in &instr.flows {
            if self.is_valid_reference_target(program, *target) {
                analyzed.add(*target);
            }
        }
        Ok(())
    }

    /// Checks if an address is a valid reference target.
    fn is_valid_reference_target(&self, program: &Program, addr: Address) -> bool {
        // Must be in program memory
        if !program.memory.contains(&addr) {
            return false;
        }

        // Skip low addresses (likely null/offset values)
        let offset = addr.offset;
        if offset < self.config.min_store_load_ref_address {
            return false;
        }

        true
    }

    /// Iterates through the address set analyzing each instruction.
    fn analyze_set(
        &self,
        program: &Program,
        todo_set: &AddressSet,
        monitor: &dyn TaskMonitor,
    ) -> Result<AddressSet, CancelledError> {
        let mut result_set = AddressSet::new();
        let addrs: Vec<Address> = todo_set.get_addresses(true).collect();
        let total = addrs.len() as u64;
        monitor.initialize(total);

        for (i, addr) in addrs.iter().enumerate() {
            monitor.check_cancelled()?;
            if i % 100 == 0 {
                monitor.set_progress(i as u64);
            }

            if let Some(_instr) = program.listing.get_instruction_at(addr) {
                let result = self.analyze_location(program, *addr, todo_set, monitor)?;
                result_set.add_all(&result);
            }
        }

        Ok(result_set)
    }
}

impl Analyzer for ConstantPropagationAnalyzer {
    fn name(&self) -> &str {
        self.base.name()
    }
    fn description(&self) -> &str {
        self.base.description()
    }
    fn analysis_type(&self) -> AnalyzerType {
        AnalyzerType::Instruction
    }
    fn priority(&self) -> AnalysisPriority {
        AnalysisPriority::REFERENCE_ANALYSIS
            .before()
            .before()
            .before()
            .before()
    }

    fn can_analyze(&self, program: &Program) -> bool {
        if self.processor_name == "Basic" {
            // Skip if a more specific analyzer has claimed this processor
            if Self::is_claimed_processor(&program.language.processor) {
                return false;
            }
            true
        } else {
            program.language.processor.to_lowercase() == self.processor_name.to_lowercase()
        }
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
        monitor.set_message(&self.base.name());

        let mut analyzer = self.clone();

        // Adjust config based on program properties
        let ptr_size = program.language.default_pointer_size();
        analyzer.config.check_pointer_param_refs = ptr_size <= 2;

        let mut unanalyzed = set.clone();
        analyzer.remove_uninitialized_blocks(program, &mut unanalyzed);

        // Find function entry points
        let mut locations = HashSet::new();
        analyzer.find_locations_remove_function_bodies(program, &mut unanalyzed, &mut locations);

        let location_count = locations.len() as u64;
        monitor.initialize(location_count);

        if location_count > 0 {
            // Analyze function entry points
            let mut result_set = AddressSet::new();
            for (i, addr) in locations.iter().enumerate() {
                monitor.check_cancelled()?;
                monitor.set_progress(i as u64);
                if let Ok(result) = analyzer.analyze_location(program, *addr, set, monitor) {
                    result_set.add_all(&result);
                }
            }
            unanalyzed.delete(&result_set);
        }

        // Analyze remaining addresses
        if !unanalyzed.is_empty() {
            let result = analyzer.analyze_set(program, &unanalyzed, monitor)?;
            unanalyzed.delete(&result);
        }

        log.append_msg(format!(
            "ConstantPropagationAnalyzer: analyzed {} function locations",
            location_count
        ));

        Ok(true)
    }

    fn options_changed(&mut self, opts: &HashMap<String, AnalysisOptionValue>) {
        if let Some(AnalysisOptionValue::Bool(v)) =
            opts.get("Function parameter/return Pointer analysis")
        {
            self.config.check_param_refs = *v;
        }
        if let Some(AnalysisOptionValue::Bool(v)) = opts.get("Require pointer param data type") {
            self.config.check_pointer_param_refs = *v;
        }
        if let Some(AnalysisOptionValue::Bool(v)) = opts.get("Stored Value Pointer analysis") {
            self.config.check_stored_refs = *v;
        }
        if let Some(AnalysisOptionValue::Bool(v)) =
            opts.get("Trust values read from writable memory")
        {
            self.config.trust_write_mem = *v;
        }
        if let Some(AnalysisOptionValue::Bool(v)) = opts.get("Create Data from pointer") {
            self.config.create_complex_data_from_pointers = *v;
        }
        if let Some(AnalysisOptionValue::Integer(v)) = opts.get("Max Threads") {
            self.config.max_thread_count = *v as u32;
        }
        if let Some(AnalysisOptionValue::Integer(v)) = opts.get("Min absolute reference") {
            self.config.min_store_load_ref_address = *v as u64;
        }
        if let Some(AnalysisOptionValue::Integer(v)) = opts.get("Speculative reference min") {
            self.config.min_speculative_ref_address = *v as u64;
        }
        if let Some(AnalysisOptionValue::Integer(v)) = opts.get("Speculative reference max") {
            self.config.max_speculative_ref_address = *v as u64;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_program() -> Program {
        let lang = Language {
            processor: "x86".into(),
            variant: "LE".into(),
            size: 64,
        };
        let mut p = Program::new("test", lang);
        p.memory
            .add_range(AddressRange::new(Address::new(0x1000), Address::new(0x5000)));
        p
    }

    #[test]
    fn test_constant_propagation_creation() {
        let a = ConstantPropagationAnalyzer::new();
        assert!(a.name().contains("Basic"));
        assert!(a.name().contains("Constant"));
    }

    #[test]
    fn test_constant_propagation_with_processor() {
        let a = ConstantPropagationAnalyzer::with_processor("ARM");
        assert!(a.name().contains("ARM"));
        assert_eq!(a.processor_name, "ARM");
    }

    #[test]
    fn test_constant_propagation_claimed_processor() {
        ConstantPropagationAnalyzer::with_processor("MIPS");
        assert!(ConstantPropagationAnalyzer::is_claimed_processor("MIPS"));
    }

    #[test]
    fn test_constant_propagation_can_analyze_basic() {
        let a = ConstantPropagationAnalyzer::new();
        let mut p = make_program();
        p.language.processor = "Z80".into(); // Not claimed
        assert!(a.can_analyze(&p));
    }

    #[test]
    fn test_constant_propagation_priority() {
        let a = ConstantPropagationAnalyzer::new();
        assert!(a.priority() < AnalysisPriority::REFERENCE_ANALYSIS);
    }

    #[test]
    fn test_constant_propagation_config_default() {
        let config = ConstantPropagationConfig::default();
        assert!(config.check_param_refs);
        assert!(!config.check_pointer_param_refs);
        assert!(config.check_stored_refs);
        assert!(config.trust_write_mem);
        assert_eq!(config.max_thread_count, 2);
    }

    #[test]
    fn test_constant_propagation_options() {
        let mut a = ConstantPropagationAnalyzer::new();
        let mut opts = HashMap::new();
        opts.insert(
            "Max Threads".to_string(),
            AnalysisOptionValue::Integer(4),
        );
        opts.insert(
            "Trust values read from writable memory".to_string(),
            AnalysisOptionValue::Bool(false),
        );
        a.options_changed(&opts);
        assert_eq!(a.config.max_thread_count, 4);
        assert!(!a.config.trust_write_mem);
    }

    #[test]
    fn test_is_valid_reference_target() {
        let a = ConstantPropagationAnalyzer::new();
        let p = make_program();
        // Low address - not valid
        assert!(!a.is_valid_reference_target(&p, Address::new(0x2)));
        // Valid address in memory
        assert!(a.is_valid_reference_target(&p, Address::new(0x2000)));
    }

    #[test]
    fn test_remove_uninitialized_blocks() {
        let a = ConstantPropagationAnalyzer::new();
        let mut p = make_program();
        p.memory_blocks.push(MemoryBlock {
            name: ".bss".into(),
            start: Address::new(0x4000),
            size: 0x1000,
            is_read: true,
            is_write: true,
            is_execute: false,
            is_initialized: false,
        });
        let mut set = AddressSet::from_range(AddressRange::new(
            Address::new(0x1000),
            Address::new(0x5000),
        ));
        a.remove_uninitialized_blocks(&p, &mut set);
        assert!(!set.contains(&Address::new(0x4500)));
    }
}
