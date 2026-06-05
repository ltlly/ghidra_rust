//! Extended module/mapping service implementation types.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.service.modules` package.
//! Provides map entry types, mapping proposals, and per-program/per-trace info
//! for the static mapping service.

use std::collections::BTreeMap;

use crate::model::lifespan::Lifespan;

/// A mapping entry connecting a program region to a trace region.
///
/// Corresponds to Java's `MappingEntry` and `AbstractMapEntry`.
#[derive(Debug, Clone)]
pub struct MappingEntry {
    /// Program URL.
    pub program_url: String,
    /// Program address range start.
    pub program_min: u64,
    /// Program address range end.
    pub program_max: u64,
    /// Trace address range start.
    pub trace_min: u64,
    /// Trace address range end.
    pub trace_max: u64,
    /// Lifespan of this mapping.
    pub lifespan: Lifespan,
    /// Whether this mapping is currently enabled.
    pub enabled: bool,
}

impl MappingEntry {
    /// Create a new mapping entry.
    pub fn new(
        program_url: impl Into<String>,
        program_min: u64,
        program_max: u64,
        trace_min: u64,
        trace_max: u64,
        lifespan: Lifespan,
    ) -> Self {
        Self {
            program_url: program_url.into(),
            program_min,
            program_max,
            trace_min,
            trace_max,
            lifespan,
            enabled: true,
        }
    }

    /// Get the program address range size.
    pub fn program_range_size(&self) -> u64 {
        self.program_max - self.program_min + 1
    }

    /// Get the trace address range size.
    pub fn trace_range_size(&self) -> u64 {
        self.trace_max - self.trace_min + 1
    }

    /// Translate a program address to a trace address.
    pub fn program_to_trace(&self, prog_addr: u64) -> Option<u64> {
        if prog_addr >= self.program_min && prog_addr <= self.program_max {
            Some(self.trace_min + (prog_addr - self.program_min))
        } else {
            None
        }
    }

    /// Translate a trace address to a program address.
    pub fn trace_to_program(&self, trace_addr: u64) -> Option<u64> {
        if trace_addr >= self.trace_min && trace_addr <= self.trace_max {
            Some(self.program_min + (trace_addr - self.trace_min))
        } else {
            None
        }
    }
}

/// A proposed mapping from a program region to a trace region.
///
/// Corresponds to Java's `AbstractMapProposal` and related types.
#[derive(Debug, Clone)]
pub struct MapProposalEntry {
    /// Source description (module name, region name, etc.).
    pub source_name: String,
    /// Program address range start.
    pub program_min: u64,
    /// Program address range end.
    pub program_max: u64,
    /// Proposed trace address range start.
    pub trace_min: u64,
    /// Proposed trace address range end.
    pub trace_max: u64,
    /// Confidence score (0.0 to 1.0).
    pub confidence: f64,
    /// Whether the user has accepted this proposal.
    pub accepted: bool,
}

impl MapProposalEntry {
    /// Create a new map proposal entry.
    pub fn new(
        source_name: impl Into<String>,
        program_min: u64,
        program_max: u64,
        trace_min: u64,
        trace_max: u64,
        confidence: f64,
    ) -> Self {
        Self {
            source_name: source_name.into(),
            program_min,
            program_max,
            trace_min,
            trace_max,
            confidence,
            accepted: false,
        }
    }
}

/// Information tracked per open program.
///
/// Corresponds to Java's `InfoPerProgram`.
#[derive(Debug)]
pub struct InfoPerProgram {
    /// Program URL.
    pub program_url: String,
    /// Whether the program is currently open.
    pub is_open: bool,
    /// The associated trace key, if mapped.
    pub trace_key: Option<i64>,
    /// Module mappings for this program.
    pub mappings: Vec<MappingEntry>,
}

impl InfoPerProgram {
    /// Create new per-program info.
    pub fn new(program_url: impl Into<String>) -> Self {
        Self {
            program_url: program_url.into(),
            is_open: true,
            trace_key: None,
            mappings: Vec::new(),
        }
    }

    /// Add a mapping entry.
    pub fn add_mapping(&mut self, entry: MappingEntry) {
        self.mappings.push(entry);
    }

    /// Get the number of mappings.
    pub fn mapping_count(&self) -> usize {
        self.mappings.len()
    }

    /// Mark the program as closed.
    pub fn close(&mut self) {
        self.is_open = false;
        self.trace_key = None;
    }
}

/// Information tracked per trace for mapping purposes.
///
/// Corresponds to Java's `InfoPerTrace`.
#[derive(Debug)]
pub struct InfoPerTrace {
    /// Trace key.
    pub trace_key: i64,
    /// Programs mapped to this trace, indexed by URL.
    pub programs: BTreeMap<String, Vec<MappingEntry>>,
}

impl InfoPerTrace {
    /// Create new per-trace info.
    pub fn new(trace_key: i64) -> Self {
        Self {
            trace_key,
            programs: BTreeMap::new(),
        }
    }

    /// Add a mapping for a program.
    pub fn add_mapping(&mut self, program_url: impl Into<String>, entry: MappingEntry) {
        self.programs.entry(program_url.into()).or_default().push(entry);
    }

    /// Get mappings for a program.
    pub fn get_mappings(&self, program_url: &str) -> Option<&Vec<MappingEntry>> {
        self.programs.get(program_url)
    }

    /// Get all mapped program URLs.
    pub fn mapped_programs(&self) -> Vec<&str> {
        self.programs.keys().map(|s| s.as_str()).collect()
    }

    /// Get total mapping count.
    pub fn total_mappings(&self) -> usize {
        self.programs.values().map(|v| v.len()).sum()
    }
}

/// Context for a static mapping event.
///
/// Corresponds to Java's `DebuggerStaticMappingContext`.
#[derive(Debug, Clone)]
pub struct StaticMappingContext {
    /// The trace key.
    pub trace_key: i64,
    /// The program URL.
    pub program_url: String,
    /// The mapping that was changed.
    pub mapping: Option<MappingEntry>,
    /// The kind of change.
    pub change_kind: MappingChangeKind,
}

/// Kind of mapping change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MappingChangeKind {
    /// A mapping was added.
    Added,
    /// A mapping was removed.
    Removed,
    /// A mapping was modified.
    Modified,
}

/// Proposals for mapping a program to a trace.
///
/// Corresponds to Java's `DebuggerStaticMappingProposals`.
#[derive(Debug, Clone)]
pub struct StaticMappingProposals {
    /// Program URL being mapped.
    pub program_url: String,
    /// Target trace key.
    pub trace_key: i64,
    /// The proposed mapping entries.
    pub proposals: Vec<MapProposalEntry>,
}

impl StaticMappingProposals {
    /// Create new proposals.
    pub fn new(program_url: impl Into<String>, trace_key: i64) -> Self {
        Self {
            program_url: program_url.into(),
            trace_key,
            proposals: Vec::new(),
        }
    }

    /// Add a proposal.
    pub fn add(&mut self, proposal: MapProposalEntry) {
        self.proposals.push(proposal);
    }

    /// Get accepted proposals.
    pub fn accepted_proposals(&self) -> Vec<&MapProposalEntry> {
        self.proposals.iter().filter(|p| p.accepted).collect()
    }

    /// Accept all proposals.
    pub fn accept_all(&mut self) {
        for p in &mut self.proposals {
            p.accepted = true;
        }
    }

    /// Get the total number of proposals.
    pub fn len(&self) -> usize {
        self.proposals.len()
    }

    /// Check if there are no proposals.
    pub fn is_empty(&self) -> bool {
        self.proposals.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mapping_entry_translation() {
        let entry = MappingEntry::new(
            "file:///test",
            0x400000, 0x400FFF,
            0x7FFF0000, 0x7FFF0FFF,
            Lifespan::span(0, 100),
        );
        assert_eq!(entry.program_to_trace(0x400000), Some(0x7FFF0000));
        assert_eq!(entry.program_to_trace(0x400FFF), Some(0x7FFF0FFF));
        assert_eq!(entry.program_to_trace(0x500000), None);

        assert_eq!(entry.trace_to_program(0x7FFF0000), Some(0x400000));
        assert_eq!(entry.trace_to_program(0x7FFF0010), Some(0x400010));
        assert_eq!(entry.program_range_size(), 0x1000);
    }

    #[test]
    fn test_map_proposal_entry() {
        let proposal = MapProposalEntry::new(".text", 0x1000, 0x1FFF, 0x401000, 0x401FFF, 0.95);
        assert_eq!(proposal.source_name, ".text");
        assert_eq!(proposal.confidence, 0.95);
        assert!(!proposal.accepted);
    }

    #[test]
    fn test_info_per_program() {
        let mut info = InfoPerProgram::new("file:///test");
        assert!(info.is_open);
        assert_eq!(info.mapping_count(), 0);

        info.add_mapping(MappingEntry::new("file:///test", 0, 100, 0x400000, 0x400064, Lifespan::span(0, 100)));
        assert_eq!(info.mapping_count(), 1);

        info.close();
        assert!(!info.is_open);
    }

    #[test]
    fn test_info_per_trace() {
        let mut info = InfoPerTrace::new(1);
        info.add_mapping("file:///a", MappingEntry::new("a", 0, 100, 0x400000, 0x400064, Lifespan::span(0, 100)));
        info.add_mapping("file:///a", MappingEntry::new("a", 200, 300, 0x400200, 0x400264, Lifespan::span(0, 100)));
        info.add_mapping("file:///b", MappingEntry::new("b", 0, 100, 0x500000, 0x500064, Lifespan::span(0, 100)));

        assert_eq!(info.mapped_programs().len(), 2);
        assert_eq!(info.total_mappings(), 3);
        assert_eq!(info.get_mappings("file:///a").unwrap().len(), 2);
    }

    #[test]
    fn test_static_mapping_proposals() {
        let mut proposals = StaticMappingProposals::new("file:///test", 1);
        proposals.add(MapProposalEntry::new(".text", 0x1000, 0x1FFF, 0x401000, 0x401FFF, 0.95));
        proposals.add(MapProposalEntry::new(".data", 0x2000, 0x2FFF, 0x402000, 0x402FFF, 0.80));

        assert_eq!(proposals.len(), 2);
        assert_eq!(proposals.accepted_proposals().len(), 0);

        proposals.proposals[0].accepted = true;
        assert_eq!(proposals.accepted_proposals().len(), 1);
    }

    #[test]
    fn test_static_mapping_proposals_accept_all() {
        let mut proposals = StaticMappingProposals::new("test", 1);
        proposals.add(MapProposalEntry::new(".text", 0, 100, 0x400000, 0x400064, 0.9));
        proposals.add(MapProposalEntry::new(".data", 100, 200, 0x400100, 0x400164, 0.8));
        proposals.accept_all();
        assert_eq!(proposals.accepted_proposals().len(), 2);
    }

    #[test]
    fn test_static_mapping_context() {
        let ctx = StaticMappingContext {
            trace_key: 1,
            program_url: "file:///test".to_string(),
            mapping: Some(MappingEntry::new("t", 0, 100, 0x400000, 0x400064, Lifespan::span(0, 100))),
            change_kind: MappingChangeKind::Added,
        };
        assert_eq!(ctx.change_kind, MappingChangeKind::Added);
    }
}
