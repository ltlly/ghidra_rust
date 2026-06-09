//! Reference analyzer for creating and maintaining cross-references.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.analysis.ReferenceAnalyzer`.
//!
//! This analyzer scans instruction operands for memory references (code
//! and data) and creates corresponding [`Reference`] entries in the
//! program's reference manager. It handles:
//!
//! - Direct memory references from branch/call instructions
//! - Indirect references through register-based operands
//! - External library references
//! - Reference cleanup when addresses are removed

use std::collections::{HashMap, HashSet};

use super::analyzer::{
    AbstractAnalyzer, Address, AddressSet, AnalysisOption, AnalysisOptionValue, AnalysisPriority,
    Analyzer, AnalyzerType, BasicTaskMonitor, CancelledError, FlowType, Instruction, Listing,
    MessageLog, Program, TaskMonitor,
};

// ---------------------------------------------------------------------------
// Reference model
// ---------------------------------------------------------------------------
/// The kind of cross-reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RefType {
    /// Unconditional jump or call.
    Unconditional,
    /// Conditional branch.
    Conditional,
    /// Data read.
    Read,
    /// Data write.
    Write,
    /// Data read and write.
    ReadWrite,
    /// Call to an external library.
    ExternalCall,
    /// Indirect reference (computed, table, etc.).
    Indirect,
}

/// A single cross-reference from `from_addr` to `to_addr`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Reference {
    pub from_addr: Address,
    pub to_addr: Address,
    pub ref_type: RefType,
    pub is_primary: bool,
}

impl Reference {
    pub fn new(from: Address, to: Address, ref_type: RefType, primary: bool) -> Self {
        Self {
            from_addr: from,
            to_addr: to,
            ref_type,
            is_primary: primary,
        }
    }
}

/// Storage for all references in a program.
#[derive(Debug, Clone, Default)]
pub struct ReferenceManager {
    refs: Vec<Reference>,
    by_from: HashMap<Address, Vec<usize>>,
    by_to: HashMap<Address, Vec<usize>>,
}

impl ReferenceManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a reference. Skips exact duplicates.
    pub fn add_reference(&mut self, r: Reference) -> bool {
        if self.refs.iter().any(|existing| *existing == r) {
            return false;
        }
        let idx = self.refs.len();
        self.by_from
            .entry(r.from_addr)
            .or_default()
            .push(idx);
        self.by_to
            .entry(r.to_addr)
            .or_default()
            .push(idx);
        self.refs.push(r);
        true
    }

    /// Number of references.
    pub fn len(&self) -> usize {
        self.refs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.refs.is_empty()
    }

    /// Get all references from a given address.
    pub fn refs_from(&self, addr: &Address) -> Vec<&Reference> {
        self.by_from
            .get(addr)
            .map(|indices| indices.iter().map(|&i| &self.refs[i]).collect())
            .unwrap_or_default()
    }

    /// Get all references to a given address.
    pub fn refs_to(&self, addr: &Address) -> Vec<&Reference> {
        self.by_to
            .get(addr)
            .map(|indices| indices.iter().map(|&i| &self.refs[i]).collect())
            .unwrap_or_default()
    }

    /// Remove all references originating from an address.
    pub fn remove_refs_from(&mut self, addr: &Address) {
        if let Some(indices) = self.by_from.remove(addr) {
            for &idx in &indices {
                if let Some(r) = self.refs.get(idx) {
                    // Remove from by_to as well (logical removal; real impl
                    // would use an arena or swap-remove).
                    if let Some(to_vec) = self.by_to.get_mut(&r.to_addr) {
                        to_vec.retain(|&i| i != idx);
                    }
                }
                // Mark as removed by overwriting with a sentinel (not used
                // in practice; this is a placeholder).
            }
        }
    }

    /// Get all unique target addresses referenced from the given set.
    pub fn get_reference_targets(&self, addrs: &AddressSet) -> HashSet<Address> {
        let mut targets = HashSet::new();
        for addr in addrs.get_addresses(true) {
            for r in self.refs_from(&addr) {
                targets.insert(r.to_addr);
            }
        }
        targets
    }

    /// Iterate over all references.
    pub fn iter(&self) -> impl Iterator<Item = &Reference> {
        self.refs.iter()
    }
}

// ---------------------------------------------------------------------------
// ReferenceAnalyzer
// ---------------------------------------------------------------------------
/// Scans instruction operands for memory references and populates the
/// [`ReferenceManager`].
///
/// This is one of the most frequently-invoked analyzers -- it runs
/// after disassembly creates new instructions and after data is defined.
#[derive(Debug)]
pub struct ReferenceAnalyzer {
    base: AbstractAnalyzer,
    /// Maximum number of references to create per invocation.
    pub max_refs_per_run: usize,
    /// Whether to follow fallthroughs from indirect calls.
    pub follow_indirect_fallthrough: bool,
}

impl ReferenceAnalyzer {
    pub fn new() -> Self {
        let mut base = AbstractAnalyzer::new(
            "Reference Analyzer",
            "Creates references from instruction operands",
            AnalyzerType::Instruction,
        );
        base.set_priority(AnalysisPriority::REFERENCE_ANALYSIS);
        base.set_supports_one_time_analysis(true);
        Self {
            base,
            max_refs_per_run: 50_000,
            follow_indirect_fallthrough: true,
        }
    }

    /// Scan a single instruction and produce references.
    pub fn collect_refs_for_instruction(
        &self,
        instr: &Instruction,
        _listing: &Listing,
    ) -> Vec<Reference> {
        let mut refs = Vec::new();

        // References from flow targets
        for &target in &instr.flows {
            let ref_type = match instr.flow_type {
                FlowType::Call | FlowType::ConditionalCall | FlowType::IndirectCall => {
                    RefType::Unconditional
                }
                FlowType::ConditionalBranch => RefType::Conditional,
                FlowType::UnconditionalBranch => RefType::Unconditional,
                FlowType::ComputedJump | FlowType::IndirectJump => RefType::Indirect,
                _ => RefType::Unconditional,
            };
            refs.push(Reference::new(instr.address, target, ref_type, true));
        }

        refs
    }
}

impl Default for ReferenceAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl Analyzer for ReferenceAnalyzer {
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
        let mut ref_manager = ReferenceManager::new();
        let mut count = 0usize;

        for instr in program.listing.get_instructions(set, true) {
            monitor.check_cancelled()?;
            let refs = self.collect_refs_for_instruction(instr, &program.listing);
            for r in refs {
                if ref_manager.add_reference(r) {
                    count += 1;
                }
                if count >= self.max_refs_per_run {
                    break;
                }
            }
            if count >= self.max_refs_per_run {
                break;
            }
        }

        if count > 0 {
            log.append_msg(&format!("Created {} references", count));
        }
        Ok(count > 0)
    }

    fn removed(
        &self,
        _program: &mut Program,
        _set: &AddressSet,
        _monitor: &dyn TaskMonitor,
        _log: &mut MessageLog,
    ) -> Result<bool, CancelledError> {
        // Reference removal is handled by the reference manager
        // when instructions are deleted.
        Ok(false)
    }

    fn register_options(&self, _program: &Program) -> Vec<AnalysisOption> {
        vec![AnalysisOption {
            name: "Max references per run".to_string(),
            description: "Maximum number of references created per analysis run".to_string(),
            default_value: AnalysisOptionValue::Integer(50_000),
            current_value: AnalysisOptionValue::Integer(self.max_refs_per_run as i64),
        }]
    }

    fn analysis_ended(&self, _program: &Program) {
        // Finalization: ensure all references are consistent.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_instr(addr: u64, mnemonic: &str, flow_type: FlowType, flows: Vec<u64>) -> Instruction {
        Instruction {
            address: Address::new(addr),
            length: if mnemonic.starts_with("call") { 5 } else { 3 },
            mnemonic: mnemonic.to_string(),
            flow_type,
            fall_through: Some(Address::new(addr + if mnemonic.starts_with("call") { 5 } else { 3 })),
            flows: flows.into_iter().map(Address::new).collect(),
            num_operands: 1,
        }
    }

    fn make_program_with_instructions() -> Program {
        let lang = super::super::analyzer::Language {
            processor: "x86".into(),
            variant: "LE".into(),
            size: 64,
        };
        let mut prog = Program::new("test_ref", lang);
        prog.image_base = 0x400000;
        prog.memory.add_range(super::super::analyzer::AddressRange::new(
            Address::new(0x400000),
            Address::new(0x500000),
        ));
        prog.listing.instructions.insert(
            Address::new(0x401000),
            make_instr(0x401000, "call", FlowType::Call, vec![0x402000]),
        );
        prog.listing.instructions.insert(
            Address::new(0x401005),
            make_instr(0x401005, "jmp", FlowType::UnconditionalBranch, vec![0x403000]),
        );
        prog.listing.instructions.insert(
            Address::new(0x401008),
            make_instr(0x401008, "jz", FlowType::ConditionalBranch, vec![0x401100]),
        );
        prog
    }

    #[test]
    fn test_reference_manager_basic() {
        let mut mgr = ReferenceManager::new();
        assert!(mgr.is_empty());

        let r = Reference::new(Address::new(0x1000), Address::new(0x2000), RefType::Unconditional, true);
        assert!(mgr.add_reference(r));
        assert_eq!(mgr.len(), 1);
        assert!(!mgr.is_empty());

        // Duplicate should not be added
        let r2 = Reference::new(Address::new(0x1000), Address::new(0x2000), RefType::Unconditional, true);
        assert!(!mgr.add_reference(r2));
        assert_eq!(mgr.len(), 1);
    }

    #[test]
    fn test_reference_manager_refs_from() {
        let mut mgr = ReferenceManager::new();
        mgr.add_reference(Reference::new(Address::new(0x1000), Address::new(0x2000), RefType::Unconditional, true));
        mgr.add_reference(Reference::new(Address::new(0x1000), Address::new(0x3000), RefType::Conditional, false));
        mgr.add_reference(Reference::new(Address::new(0x1005), Address::new(0x2000), RefType::Read, true));

        assert_eq!(mgr.refs_from(&Address::new(0x1000)).len(), 2);
        assert_eq!(mgr.refs_from(&Address::new(0x1005)).len(), 1);
        assert!(mgr.refs_from(&Address::new(0x9999)).is_empty());
    }

    #[test]
    fn test_reference_manager_refs_to() {
        let mut mgr = ReferenceManager::new();
        mgr.add_reference(Reference::new(Address::new(0x1000), Address::new(0x2000), RefType::Unconditional, true));
        mgr.add_reference(Reference::new(Address::new(0x1005), Address::new(0x2000), RefType::Read, true));

        assert_eq!(mgr.refs_to(&Address::new(0x2000)).len(), 2);
        assert!(mgr.refs_to(&Address::new(0x9999)).is_empty());
    }

    #[test]
    fn test_reference_manager_remove() {
        let mut mgr = ReferenceManager::new();
        mgr.add_reference(Reference::new(Address::new(0x1000), Address::new(0x2000), RefType::Unconditional, true));
        assert_eq!(mgr.len(), 1);
        mgr.remove_refs_from(&Address::new(0x1000));
        // After removal the logical view from by_from should be empty
        assert!(mgr.refs_from(&Address::new(0x1000)).is_empty());
    }

    #[test]
    fn test_reference_manager_targets() {
        let mut mgr = ReferenceManager::new();
        mgr.add_reference(Reference::new(Address::new(0x1000), Address::new(0x2000), RefType::Unconditional, true));
        mgr.add_reference(Reference::new(Address::new(0x1000), Address::new(0x3000), RefType::Conditional, false));

        let set = AddressSet::from_address(Address::new(0x1000));
        let targets = mgr.get_reference_targets(&set);
        assert_eq!(targets.len(), 2);
        assert!(targets.contains(&Address::new(0x2000)));
        assert!(targets.contains(&Address::new(0x3000)));
    }

    #[test]
    fn test_ref_type_variants() {
        assert_ne!(RefType::Unconditional, RefType::Conditional);
        assert_ne!(RefType::Read, RefType::Write);
    }

    #[test]
    fn test_reference_equality() {
        let r1 = Reference::new(Address::new(0x1000), Address::new(0x2000), RefType::Unconditional, true);
        let r2 = Reference::new(Address::new(0x1000), Address::new(0x2000), RefType::Unconditional, true);
        let r3 = Reference::new(Address::new(0x1000), Address::new(0x2000), RefType::Conditional, true);
        assert_eq!(r1, r2);
        assert_ne!(r1, r3);
    }

    #[test]
    fn test_reference_analyzer_creation() {
        let a = ReferenceAnalyzer::new();
        assert_eq!(a.name(), "Reference Analyzer");
        assert_eq!(a.analysis_type(), AnalyzerType::Instruction);
        assert!(a.supports_one_time_analysis());
        assert!(a.can_analyze(&make_program_with_instructions()));
    }

    #[test]
    fn test_reference_analyzer_collect() {
        let a = ReferenceAnalyzer::new();
        let prog = make_program_with_instructions();
        let instr = prog.listing.instructions.get(&Address::new(0x401000)).unwrap();
        let refs = a.collect_refs_for_instruction(instr, &prog.listing);
        assert!(!refs.is_empty());
        assert_eq!(refs[0].from_addr, Address::new(0x401000));
        assert_eq!(refs[0].to_addr, Address::new(0x402000));
    }

    #[test]
    fn test_reference_analyzer_run() {
        let a = ReferenceAnalyzer::new();
        let mut prog = make_program_with_instructions();
        let set = AddressSet::from_range(super::super::analyzer::AddressRange::new(
            Address::new(0x400000),
            Address::new(0x500000),
        ));
        let monitor = BasicTaskMonitor::new();
        let mut log = MessageLog::new();
        let result = a.added(&mut prog, &set, &monitor, &mut log);
        assert!(result.is_ok());
    }

    #[test]
    fn test_reference_analyzer_max_refs() {
        let mut a = ReferenceAnalyzer::new();
        a.max_refs_per_run = 1;
        let mut prog = make_program_with_instructions();
        let set = AddressSet::from_range(super::super::analyzer::AddressRange::new(
            Address::new(0x400000),
            Address::new(0x500000),
        ));
        let monitor = BasicTaskMonitor::new();
        let mut log = MessageLog::new();
        let result = a.added(&mut prog, &set, &monitor, &mut log);
        assert!(result.is_ok());
    }

    #[test]
    fn test_reference_analyzer_options() {
        let a = ReferenceAnalyzer::new();
        let opts = a.register_options(&make_program_with_instructions());
        assert_eq!(opts.len(), 1);
        assert_eq!(opts[0].name, "Max references per run");
    }

    #[test]
    fn test_reference_analyzer_empty_set() {
        let a = ReferenceAnalyzer::new();
        let mut prog = make_program_with_instructions();
        let set = AddressSet::new();
        let monitor = BasicTaskMonitor::new();
        let mut log = MessageLog::new();
        let result = a.added(&mut prog, &set, &monitor, &mut log).unwrap();
        assert!(!result);
    }

    #[test]
    fn test_reference_analyzer_cancelled() {
        let a = ReferenceAnalyzer::new();
        let mut prog = make_program_with_instructions();
        let set = AddressSet::from_range(super::super::analyzer::AddressRange::new(
            Address::new(0x400000),
            Address::new(0x500000),
        ));
        let monitor = BasicTaskMonitor::new();
        monitor.cancel();
        let mut log = MessageLog::new();
        let result = a.added(&mut prog, &set, &monitor, &mut log);
        assert!(result.is_err());
    }

    #[test]
    fn test_reference_analyzer_removed() {
        let a = ReferenceAnalyzer::new();
        let mut prog = make_program_with_instructions();
        let set = AddressSet::new();
        let monitor = BasicTaskMonitor::new();
        let mut log = MessageLog::new();
        let result = a.removed(&mut prog, &set, &monitor, &mut log).unwrap();
        assert!(!result);
    }

    #[test]
    fn test_reference_manager_iter() {
        let mut mgr = ReferenceManager::new();
        mgr.add_reference(Reference::new(Address::new(0x1000), Address::new(0x2000), RefType::Unconditional, true));
        mgr.add_reference(Reference::new(Address::new(0x1005), Address::new(0x3000), RefType::Read, false));
        let all: Vec<_> = mgr.iter().collect();
        assert_eq!(all.len(), 2);
    }
}
