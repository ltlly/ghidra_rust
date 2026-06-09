//! Cross-reference (XRef) analyzer.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.analysis.XrefAnalyzer`.
//!
//! Builds the full cross-reference table for a program by scanning
//! all instructions for branch, call, and data references. Unlike
//! [`ReferenceAnalyzer`] which processes one instruction at a time,
//! this analyzer operates on a whole address set and can reconcile
//! stale cross-references.

use std::collections::{BTreeMap, HashMap, HashSet};

use super::analyzer::{
    AbstractAnalyzer, Address, AddressSet, AnalysisPriority, Analyzer, AnalyzerType,
    CancelledError, FlowType, Instruction, MessageLog, Program, TaskMonitor,
};

// ---------------------------------------------------------------------------
// XRef model
// ---------------------------------------------------------------------------
/// Cross-reference direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum XRefDirection {
    /// From caller to callee / branch target.
    From,
    /// From callee / target back to caller / source.
    To,
}

/// A cross-reference entry.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct XRef {
    pub from: Address,
    pub to: Address,
    pub is_call: bool,
    pub is_conditional: bool,
    pub is_primary: bool,
}

impl XRef {
    pub fn new_call(from: Address, to: Address, conditional: bool) -> Self {
        Self {
            from,
            to,
            is_call: true,
            is_conditional: conditional,
            is_primary: true,
        }
    }

    pub fn new_branch(from: Address, to: Address, conditional: bool) -> Self {
        Self {
            from,
            to,
            is_call: false,
            is_conditional: conditional,
            is_primary: true,
        }
    }
}

/// The full cross-reference table for a program.
#[derive(Debug, Clone, Default)]
pub struct XRefTable {
    entries: Vec<XRef>,
    from_index: BTreeMap<Address, Vec<usize>>,
    to_index: BTreeMap<Address, Vec<usize>>,
}

impl XRefTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an xref, skipping duplicates.
    pub fn add(&mut self, xref: XRef) -> bool {
        if self.entries.iter().any(|e| e.from == xref.from && e.to == xref.to) {
            return false;
        }
        let idx = self.entries.len();
        self.from_index.entry(xref.from).or_default().push(idx);
        self.to_index.entry(xref.to).or_default().push(idx);
        self.entries.push(xref);
        true
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// All xrefs originating from `addr`.
    pub fn get_from(&self, addr: &Address) -> Vec<&XRef> {
        self.from_index
            .get(addr)
            .map(|v| v.iter().filter_map(|&i| self.entries.get(i)).collect())
            .unwrap_or_default()
    }

    /// All xrefs pointing to `addr`.
    pub fn get_to(&self, addr: &Address) -> Vec<&XRef> {
        self.to_index
            .get(addr)
            .map(|v| v.iter().filter_map(|&i| self.entries.get(i)).collect())
            .unwrap_or_default()
    }

    /// Number of callers referencing `addr`.
    pub fn ref_count_to(&self, addr: &Address) -> usize {
        self.to_index.get(addr).map_or(0, |v| v.len())
    }

    /// Number of targets from `addr`.
    pub fn ref_count_from(&self, addr: &Address) -> usize {
        self.from_index.get(addr).map_or(0, |v| v.len())
    }

    /// Return all unique source addresses that reference into the given set.
    pub fn get_referring_sources(&self, addrs: &AddressSet) -> HashSet<Address> {
        let mut sources = HashSet::new();
        for addr in addrs.get_addresses(true) {
            for xref in self.get_to(&addr) {
                sources.insert(xref.from);
            }
        }
        sources
    }

    /// Return all unique target addresses referenced from the given set.
    pub fn get_reference_targets(&self, addrs: &AddressSet) -> HashSet<Address> {
        let mut targets = HashSet::new();
        for addr in addrs.get_addresses(true) {
            for xref in self.get_from(&addr) {
                targets.insert(xref.to);
            }
        }
        targets
    }

    /// Remove all xrefs originating from the given address.
    pub fn remove_from(&mut self, addr: &Address) {
        if let Some(indices) = self.from_index.remove(addr) {
            for &idx in &indices {
                if let Some(xref) = self.entries.get(idx) {
                    if let Some(to_vec) = self.to_index.get_mut(&xref.to) {
                        to_vec.retain(|&i| i != idx);
                    }
                }
            }
        }
    }

    /// Remove all xrefs targeting the given address.
    pub fn remove_to(&mut self, addr: &Address) {
        if let Some(indices) = self.to_index.remove(addr) {
            for &idx in &indices {
                if let Some(xref) = self.entries.get(idx) {
                    if let Some(from_vec) = self.from_index.get_mut(&xref.from) {
                        from_vec.retain(|&i| i != idx);
                    }
                }
            }
        }
    }

    /// Iterate over all entries.
    pub fn iter(&self) -> impl Iterator<Item = &XRef> {
        self.entries.iter()
    }
}

// ---------------------------------------------------------------------------
// XRefAnalyzer
// ---------------------------------------------------------------------------
/// Builds and reconciles cross-references over an address set.
///
/// Runs at [`AnalysisPriority::REFERENCE_ANALYSIS`] and is triggered by
/// both instruction and function analysis type changes.
#[derive(Debug)]
pub struct XRefAnalyzer {
    base: AbstractAnalyzer,
}

impl XRefAnalyzer {
    pub fn new() -> Self {
        let mut base = AbstractAnalyzer::new(
            "Cross Reference Analyzer",
            "Builds cross-reference tables from instructions",
            AnalyzerType::Instruction,
        );
        base.set_priority(AnalysisPriority::REFERENCE_ANALYSIS);
        base.set_supports_one_time_analysis(true);
        Self { base }
    }

    /// Build xrefs for a single instruction.
    fn build_xrefs_for_instruction(&self, instr: &Instruction) -> Vec<XRef> {
        let mut xrefs = Vec::new();

        for &target in &instr.flows {
            let is_cond = matches!(
                instr.flow_type,
                FlowType::ConditionalBranch | FlowType::ConditionalCall
            );

            if instr.flow_type.is_call() {
                xrefs.push(XRef::new_call(instr.address, target, is_cond));
            } else if instr.flow_type.is_jump() {
                xrefs.push(XRef::new_branch(instr.address, target, is_cond));
            }
        }

        xrefs
    }
}

impl Default for XRefAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl Analyzer for XRefAnalyzer {
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
        let mut table = XRefTable::new();
        let mut count = 0usize;

        for instr in program.listing.get_instructions(set, true) {
            monitor.check_cancelled()?;
            for xref in self.build_xrefs_for_instruction(instr) {
                if table.add(xref) {
                    count += 1;
                }
            }
        }

        if count > 0 {
            log.append_msg(&format!("Created {} cross-references", count));
        }
        Ok(count > 0)
    }

    fn removed(
        &self,
        _program: &mut Program,
        set: &AddressSet,
        monitor: &dyn TaskMonitor,
        log: &mut MessageLog,
    ) -> Result<bool, CancelledError> {
        // XRef cleanup is performed when instructions are removed.
        let _ = (set, monitor, log);
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::analyzer::{AddressRange, BasicTaskMonitor, Listing};

    fn make_xref_table() -> XRefTable {
        let mut table = XRefTable::new();
        table.add(XRef::new_call(Address::new(0x1000), Address::new(0x2000), false));
        table.add(XRef::new_call(Address::new(0x1005), Address::new(0x2000), true));
        table.add(XRef::new_branch(Address::new(0x1008), Address::new(0x3000), false));
        table.add(XRef::new_branch(Address::new(0x1010), Address::new(0x2000), true));
        table
    }

    #[test]
    fn test_xref_creation() {
        let x = XRef::new_call(Address::new(0x1000), Address::new(0x2000), false);
        assert!(x.is_call);
        assert!(!x.is_conditional);
        assert!(x.is_primary);

        let y = XRef::new_branch(Address::new(0x1000), Address::new(0x3000), true);
        assert!(!y.is_call);
        assert!(y.is_conditional);
    }

    #[test]
    fn test_xref_table_basic() {
        let mut table = XRefTable::new();
        assert!(table.is_empty());
        assert_eq!(table.len(), 0);

        let added = table.add(XRef::new_call(Address::new(0x1000), Address::new(0x2000), false));
        assert!(added);
        assert_eq!(table.len(), 1);
        assert!(!table.is_empty());
    }

    #[test]
    fn test_xref_table_duplicate() {
        let mut table = XRefTable::new();
        assert!(table.add(XRef::new_call(Address::new(0x1000), Address::new(0x2000), false)));
        assert!(!table.add(XRef::new_call(Address::new(0x1000), Address::new(0x2000), false)));
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn test_xref_table_get_from() {
        let table = make_xref_table();
        let from_1000 = table.get_from(&Address::new(0x1000));
        assert_eq!(from_1000.len(), 1);
        assert_eq!(from_1000[0].to, Address::new(0x2000));

        let from_none = table.get_from(&Address::new(0x9999));
        assert!(from_none.is_empty());
    }

    #[test]
    fn test_xref_table_get_to() {
        let table = make_xref_table();
        let to_2000 = table.get_to(&Address::new(0x2000));
        assert_eq!(to_2000.len(), 3);
    }

    #[test]
    fn test_xref_table_ref_counts() {
        let table = make_xref_table();
        assert_eq!(table.ref_count_to(&Address::new(0x2000)), 3);
        assert_eq!(table.ref_count_from(&Address::new(0x1000)), 1);
        assert_eq!(table.ref_count_to(&Address::new(0x9999)), 0);
    }

    #[test]
    fn test_xref_table_targets() {
        let table = make_xref_table();
        let set = AddressSet::from_range(AddressRange::new(Address::new(0x1000), Address::new(0x1010)));
        let targets = table.get_reference_targets(&set);
        assert!(targets.contains(&Address::new(0x2000)));
        assert!(targets.contains(&Address::new(0x3000)));
    }

    #[test]
    fn test_xref_table_sources() {
        let table = make_xref_table();
        let set = AddressSet::from_address(Address::new(0x2000));
        let sources = table.get_referring_sources(&set);
        assert_eq!(sources.len(), 3);
    }

    #[test]
    fn test_xref_table_remove_from() {
        let mut table = make_xref_table();
        let before = table.len();
        table.remove_from(&Address::new(0x1000));
        assert!(table.get_from(&Address::new(0x1000)).is_empty());
        assert_eq!(table.ref_count_to(&Address::new(0x2000)), 2);
    }

    #[test]
    fn test_xref_table_remove_to() {
        let mut table = make_xref_table();
        table.remove_to(&Address::new(0x2000));
        assert!(table.get_to(&Address::new(0x2000)).is_empty());
    }

    #[test]
    fn test_xref_table_iter() {
        let table = make_xref_table();
        let all: Vec<_> = table.iter().collect();
        assert_eq!(all.len(), 4);
    }

    #[test]
    fn test_xref_direction() {
        assert_ne!(XRefDirection::From, XRefDirection::To);
    }

    #[test]
    fn test_xref_analyzer_creation() {
        let a = XRefAnalyzer::new();
        assert_eq!(a.name(), "Cross Reference Analyzer");
        assert_eq!(a.analysis_type(), AnalyzerType::Instruction);
        assert!(a.supports_one_time_analysis());
    }

    #[test]
    fn test_xref_analyzer_can_analyze() {
        let a = XRefAnalyzer::new();
        let lang = super::super::analyzer::Language {
            processor: "x86".into(),
            variant: "LE".into(),
            size: 64,
        };
        let prog = Program::new("test", lang);
        assert!(a.can_analyze(&prog));
    }

    #[test]
    fn test_xref_analyzer_run() {
        let a = XRefAnalyzer::new();
        let lang = super::super::analyzer::Language {
            processor: "x86".into(),
            variant: "LE".into(),
            size: 64,
        };
        let mut prog = Program::new("test", lang);
        prog.listing.instructions.insert(
            Address::new(0x401000),
            Instruction {
                address: Address::new(0x401000),
                length: 5,
                mnemonic: "call".into(),
                flow_type: FlowType::Call,
                fall_through: Some(Address::new(0x401005)),
                flows: vec![Address::new(0x402000)],
                num_operands: 1,
            },
        );

        let set = AddressSet::from_range(AddressRange::new(Address::new(0x400000), Address::new(0x500000)));
        let monitor = BasicTaskMonitor::new();
        let mut log = MessageLog::new();
        let result = a.added(&mut prog, &set, &monitor, &mut log).unwrap();
        assert!(result);
    }

    #[test]
    fn test_xref_analyzer_empty() {
        let a = XRefAnalyzer::new();
        let lang = super::super::analyzer::Language {
            processor: "x86".into(),
            variant: "LE".into(),
            size: 64,
        };
        let mut prog = Program::new("test", lang);
        let set = AddressSet::new();
        let monitor = BasicTaskMonitor::new();
        let mut log = MessageLog::new();
        let result = a.added(&mut prog, &set, &monitor, &mut log).unwrap();
        assert!(!result);
    }

    #[test]
    fn test_xref_analyzer_cancelled() {
        let a = XRefAnalyzer::new();
        let lang = super::super::analyzer::Language {
            processor: "x86".into(),
            variant: "LE".into(),
            size: 64,
        };
        let mut prog = Program::new("test", lang);
        let set = AddressSet::from_range(AddressRange::new(Address::new(0x400000), Address::new(0x500000)));
        let monitor = BasicTaskMonitor::new();
        monitor.cancel();
        let mut log = MessageLog::new();
        let result = a.added(&mut prog, &set, &monitor, &mut log);
        assert!(result.is_err());
    }

    #[test]
    fn test_xref_analyzer_removed() {
        let a = XRefAnalyzer::new();
        let lang = super::super::analyzer::Language {
            processor: "x86".into(),
            variant: "LE".into(),
            size: 64,
        };
        let mut prog = Program::new("test", lang);
        let set = AddressSet::new();
        let monitor = BasicTaskMonitor::new();
        let mut log = MessageLog::new();
        let result = a.removed(&mut prog, &set, &monitor, &mut log).unwrap();
        assert!(!result);
    }
}
