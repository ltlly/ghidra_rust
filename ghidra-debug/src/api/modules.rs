//! Module mapping types: MapEntry, MappedAddressRange, MapProposal, and
//! related types for static/dynamic address translation.
//!
//! Ported from Ghidra's `ghidra.debug.api.modules` package.

use serde::{Deserialize, Serialize};

use crate::model::Lifespan;

/// A mapping entry from a trace address range to a program address range.
///
/// Ported from Ghidra's `MapEntry<T, P>` interface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MapEntry {
    /// Source (trace) address range start.
    pub from_min: u64,
    /// Source (trace) address range end (inclusive).
    pub from_max: u64,
    /// Lifespan during which this mapping is valid.
    pub from_lifespan: Lifespan,
    /// Destination (program) address range start.
    pub to_min: u64,
    /// Destination (program) address range end (inclusive).
    pub to_max: u64,
    /// Length of the mapping (in bytes).
    pub length: u64,
    /// The source trace ID.
    pub trace_id: String,
    /// The destination program URL.
    pub program_url: Option<String>,
}

impl MapEntry {
    /// Create a new mapping entry.
    pub fn new(
        trace_id: impl Into<String>,
        from_min: u64,
        from_max: u64,
        to_min: u64,
        to_max: u64,
        lifespan: Lifespan,
    ) -> Self {
        let length = from_max - from_min + 1;
        Self {
            from_min,
            from_max,
            from_lifespan: lifespan,
            to_min,
            to_max,
            length,
            trace_id: trace_id.into(),
            program_url: None,
        }
    }

    /// Set the program URL.
    pub fn with_program_url(mut self, url: impl Into<String>) -> Self {
        self.program_url = Some(url.into());
        self
    }

    /// Whether this mapping overlaps another mapping's from-range and lifespan.
    pub fn overlaps_from(&self, other: &MapEntry) -> bool {
        self.from_min <= other.from_max
            && other.from_min <= self.from_max
            && self.from_lifespan.intersects(&other.from_lifespan)
    }

    /// Whether this mapping overlaps a given address at a given snap.
    pub fn contains_from(&self, addr: u64, snap: i64) -> bool {
        addr >= self.from_min && addr <= self.from_max && self.from_lifespan.contains(snap)
    }

    /// Translate a trace address to a program address.
    pub fn trace_to_program(&self, trace_addr: u64) -> Option<u64> {
        if trace_addr >= self.from_min && trace_addr <= self.from_max {
            let offset = trace_addr - self.from_min;
            Some(self.to_min + offset)
        } else {
            None
        }
    }

    /// Translate a program address to a trace address.
    pub fn program_to_trace(&self, program_addr: u64) -> Option<u64> {
        if program_addr >= self.to_min && program_addr <= self.to_max {
            let offset = program_addr - self.to_min;
            Some(self.from_min + offset)
        } else {
            None
        }
    }
}

/// A range of addresses in a trace that have been mapped.
///
/// Ported from Ghidra's `MappedAddressRange`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MappedAddressRange {
    /// The trace address range start.
    pub trace_min: u64,
    /// The trace address range end (inclusive).
    pub trace_max: u64,
    /// The snap (time).
    pub snap: i64,
    /// The trace ID.
    pub trace_id: String,
}

impl MappedAddressRange {
    /// Create a new mapped address range.
    pub fn new(trace_id: impl Into<String>, trace_min: u64, trace_max: u64, snap: i64) -> Self {
        Self {
            trace_min,
            trace_max,
            snap,
            trace_id: trace_id.into(),
        }
    }

    /// Whether this range contains the given address.
    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.trace_min && addr <= self.trace_max
    }

    /// The length of this range.
    pub fn length(&self) -> u64 {
        self.trace_max - self.trace_min + 1
    }
}

/// A proposal for mapping program regions to trace regions.
///
/// Ported from Ghidra's `MapProposal<T, P, E>` interface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MapProposal {
    /// The name of this proposal.
    pub name: String,
    /// The proposed mapping entries.
    pub entries: Vec<MapEntry>,
}

impl MapProposal {
    /// Create a new empty proposal.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            entries: Vec::new(),
        }
    }

    /// Add an entry to the proposal.
    pub fn add_entry(&mut self, entry: MapEntry) {
        self.entries.push(entry);
    }

    /// Compute the map (identity here -- all entries).
    pub fn compute_map(&self) -> &[MapEntry] {
        &self.entries
    }

    /// Flatten multiple proposals into a single collection of entries.
    pub fn flatten_proposals(proposals: &[MapProposal]) -> Vec<&MapEntry> {
        proposals.iter().flat_map(|p| p.entries.iter()).collect()
    }

    /// Remove entries that overlap existing mappings.
    pub fn remove_overlapping<'a>(
        entries: &'a [MapEntry],
        existing: &[MapEntry],
    ) -> Vec<&'a MapEntry> {
        entries
            .iter()
            .filter(|e| !existing.iter().any(|ex| ex.overlaps_from(e)))
            .collect()
    }
}

/// A change listener for static mapping changes.
///
/// Ported from Ghidra's `DebuggerStaticMappingChangeListener`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MappingChangeKind {
    /// A mapping was added.
    Added,
    /// A mapping was modified.
    Modified,
    /// A mapping was removed.
    Removed,
}

/// Event data for a mapping change.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MappingChangeEvent {
    /// The kind of change.
    pub kind: MappingChangeKind,
    /// The affected mapping entry.
    pub entry: MapEntry,
}

impl MappingChangeEvent {
    /// Create a new change event.
    pub fn new(kind: MappingChangeKind, entry: MapEntry) -> Self {
        Self { kind, entry }
    }
}

/// Scheme for a section map proposal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionMapProposal {
    /// The module/section name.
    pub section_name: String,
    /// The entries for this section.
    pub entries: Vec<MapEntry>,
}

impl SectionMapProposal {
    /// Create a new section map proposal.
    pub fn new(section_name: impl Into<String>) -> Self {
        Self {
            section_name: section_name.into(),
            entries: Vec::new(),
        }
    }

    /// Add an entry.
    pub fn add_entry(&mut self, entry: MapEntry) {
        self.entries.push(entry);
    }
}

/// Scheme for a module map proposal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleMapProposal {
    /// The module name.
    pub module_name: String,
    /// The section proposals.
    pub sections: Vec<SectionMapProposal>,
}

impl ModuleMapProposal {
    /// Create a new module map proposal.
    pub fn new(module_name: impl Into<String>) -> Self {
        Self {
            module_name: module_name.into(),
            sections: Vec::new(),
        }
    }

    /// Add a section proposal.
    pub fn add_section(&mut self, section: SectionMapProposal) {
        self.sections.push(section);
    }

    /// Flatten all entries across sections.
    pub fn all_entries(&self) -> Vec<&MapEntry> {
        self.sections.iter().flat_map(|s| s.entries.iter()).collect()
    }
}

/// A region map proposal: maps an entire region from a trace to a program.
///
/// Ported from Ghidra's `RegionMapProposal`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegionMapProposal {
    /// The region name (e.g., ".text", ".data").
    pub region_name: String,
    /// The trace start address.
    pub trace_start: u64,
    /// The trace end address (inclusive).
    pub trace_end: u64,
    /// The program start address.
    pub program_start: u64,
    /// The program end address (inclusive).
    pub program_end: u64,
    /// The lifespan for this region.
    pub lifespan: Lifespan,
}

impl RegionMapProposal {
    /// Create a new region map proposal.
    pub fn new(
        region_name: impl Into<String>,
        trace_start: u64,
        trace_end: u64,
        program_start: u64,
        program_end: u64,
        lifespan: Lifespan,
    ) -> Self {
        Self {
            region_name: region_name.into(),
            trace_start,
            trace_end,
            program_start,
            program_end,
            lifespan,
        }
    }

    /// Convert to a `MapEntry`.
    pub fn to_map_entry(&self, trace_id: &str) -> MapEntry {
        MapEntry::new(
            trace_id,
            self.trace_start,
            self.trace_end,
            self.program_start,
            self.program_end,
            self.lifespan.clone(),
        )
    }
}

/// Action context for when a module is missing from the trace.
///
/// Ported from Ghidra's `DebuggerMissingModuleActionContext`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebuggerMissingModuleActionContext {
    /// The trace ID.
    pub trace_id: String,
    /// The module name that is missing.
    pub module_name: String,
    /// The module load address, if known.
    pub load_address: Option<u64>,
}

impl DebuggerMissingModuleActionContext {
    /// Create a new missing module context.
    pub fn new(trace_id: impl Into<String>, module_name: impl Into<String>) -> Self {
        Self {
            trace_id: trace_id.into(),
            module_name: module_name.into(),
            load_address: None,
        }
    }

    /// Set the load address.
    pub fn with_load_address(mut self, addr: u64) -> Self {
        self.load_address = Some(addr);
        self
    }
}

/// Action context for opening a program from the trace module.
///
/// Ported from Ghidra's `DebuggerOpenProgramActionContext`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebuggerOpenProgramActionContext {
    /// The trace ID.
    pub trace_id: String,
    /// The program URL.
    pub program_url: String,
    /// The snap (snapshot time) to view.
    pub snap: i64,
}

impl DebuggerOpenProgramActionContext {
    /// Create a new open program context.
    pub fn new(
        trace_id: impl Into<String>,
        program_url: impl Into<String>,
        snap: i64,
    ) -> Self {
        Self {
            trace_id: trace_id.into(),
            program_url: program_url.into(),
            snap,
        }
    }
}

/// Action context for when a program mapping is missing.
///
/// Ported from Ghidra's `DebuggerMissingProgramActionContext`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebuggerMissingProgramActionContext {
    /// The trace ID.
    pub trace_id: String,
    /// The expected program URL.
    pub program_url: String,
    /// The trace address range start.
    pub trace_min: u64,
    /// The trace address range end (inclusive).
    pub trace_max: u64,
}

impl DebuggerMissingProgramActionContext {
    /// Create a new missing program context.
    pub fn new(
        trace_id: impl Into<String>,
        program_url: impl Into<String>,
        trace_min: u64,
        trace_max: u64,
    ) -> Self {
        Self {
            trace_id: trace_id.into(),
            program_url: program_url.into(),
            trace_min,
            trace_max,
        }
    }
}

/// Trait for an address translator that maps between trace and program addresses.
///
/// Ported from Ghidra's `DebuggerAddressTranslator` interface.
pub trait DebuggerAddressTranslator {
    /// Translate a trace address to a program address.
    fn trace_to_program(&self, trace_addr: u64, snap: i64) -> Option<(String, u64)>;

    /// Translate a program address back to a trace address.
    fn program_to_trace(&self, program_url: &str, program_addr: u64, snap: i64) -> Option<u64>;

    /// Get all open mapped locations for a given program location.
    fn get_open_mapped_locations(&self, program_url: &str, program_addr: u64) -> Vec<(String, u64, i64)>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_entry(from_min: u64, from_max: u64, to_min: u64) -> MapEntry {
        let to_max = to_min + (from_max - from_min);
        MapEntry::new("trace1", from_min, from_max, to_min, to_max, Lifespan::now_on(0))
    }

    #[test]
    fn test_map_entry_translation() {
        let entry = sample_entry(0x7fff0000, 0x7fff0fff, 0x400000);
        assert_eq!(entry.trace_to_program(0x7fff0000), Some(0x400000));
        assert_eq!(entry.trace_to_program(0x7fff0100), Some(0x400100));
        assert_eq!(entry.trace_to_program(0x80000000), None);

        assert_eq!(entry.program_to_trace(0x400000), Some(0x7fff0000));
        assert_eq!(entry.program_to_trace(0x500000), None);
    }

    #[test]
    fn test_map_entry_overlaps() {
        let e1 = sample_entry(0x1000, 0x2000, 0x400000);
        let e2 = sample_entry(0x1800, 0x2800, 0x500000);
        let e3 = sample_entry(0x3000, 0x4000, 0x600000);

        assert!(e1.overlaps_from(&e2));
        assert!(!e1.overlaps_from(&e3));
    }

    #[test]
    fn test_map_entry_contains() {
        let entry = sample_entry(0x1000, 0x2000, 0x400000);
        assert!(entry.contains_from(0x1500, 0));
        assert!(!entry.contains_from(0x3000, 0));
    }

    #[test]
    fn test_mapped_address_range() {
        let range = MappedAddressRange::new("t1", 0x1000, 0x2000, 5);
        assert!(range.contains(0x1500));
        assert!(!range.contains(0x3000));
        assert_eq!(range.length(), 0x1001);
    }

    #[test]
    fn test_map_proposal() {
        let mut proposal = MapProposal::new("test");
        proposal.add_entry(sample_entry(0x1000, 0x2000, 0x400000));
        proposal.add_entry(sample_entry(0x3000, 0x4000, 0x500000));
        assert_eq!(proposal.compute_map().len(), 2);
    }

    #[test]
    fn test_flatten_proposals() {
        let mut p1 = MapProposal::new("p1");
        p1.add_entry(sample_entry(0x1000, 0x2000, 0x400000));
        let mut p2 = MapProposal::new("p2");
        p2.add_entry(sample_entry(0x3000, 0x4000, 0x500000));

        let proposals = [p1, p2];
        let flat = MapProposal::flatten_proposals(&proposals);
        assert_eq!(flat.len(), 2);
    }

    #[test]
    fn test_remove_overlapping() {
        let entries = vec![
            sample_entry(0x1000, 0x2000, 0x400000),
            sample_entry(0x3000, 0x4000, 0x500000),
        ];
        let existing = vec![sample_entry(0x1800, 0x2800, 0x401800)];

        let filtered = MapProposal::remove_overlapping(&entries, &existing);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].from_min, 0x3000);
    }

    #[test]
    fn test_section_map_proposal() {
        let mut section = SectionMapProposal::new(".text");
        section.add_entry(sample_entry(0x1000, 0x2000, 0x400000));
        assert_eq!(section.entries.len(), 1);
    }

    #[test]
    fn test_module_map_proposal() {
        let mut module = ModuleMapProposal::new("libc.so");
        let mut section = SectionMapProposal::new(".text");
        section.add_entry(sample_entry(0x1000, 0x2000, 0x400000));
        module.add_section(section);

        let all = module.all_entries();
        assert_eq!(all.len(), 1);
    }

    #[test]
    fn test_mapping_change_event() {
        let entry = sample_entry(0x1000, 0x2000, 0x400000);
        let event = MappingChangeEvent::new(MappingChangeKind::Added, entry);
        assert_eq!(event.kind, MappingChangeKind::Added);
    }

    #[test]
    fn test_map_entry_serde() {
        let entry = sample_entry(0x1000, 0x2000, 0x400000);
        let json = serde_json::to_string(&entry).unwrap();
        let back: MapEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(back.from_min, 0x1000);
        assert_eq!(back.to_min, 0x400000);
    }

    #[test]
    fn test_region_map_proposal() {
        let region = RegionMapProposal::new(
            ".text",
            0x7fff0000,
            0x7fff0fff,
            0x400000,
            0x400fff,
            Lifespan::now_on(0),
        );
        assert_eq!(region.region_name, ".text");

        let entry = region.to_map_entry("trace1");
        assert_eq!(entry.from_min, 0x7fff0000);
        assert_eq!(entry.to_min, 0x400000);
    }

    #[test]
    fn test_missing_module_context() {
        let ctx = DebuggerMissingModuleActionContext::new("trace1", "libc.so.6")
            .with_load_address(0x7f0000);
        assert_eq!(ctx.module_name, "libc.so.6");
        assert_eq!(ctx.load_address, Some(0x7f0000));
    }

    #[test]
    fn test_open_program_context() {
        let ctx = DebuggerOpenProgramActionContext::new("trace1", "/usr/lib/libc.so", 5);
        assert_eq!(ctx.program_url, "/usr/lib/libc.so");
        assert_eq!(ctx.snap, 5);
    }

    #[test]
    fn test_missing_program_context() {
        let ctx = DebuggerMissingProgramActionContext::new(
            "trace1",
            "/usr/lib/libc.so",
            0x7f000000,
            0x7f001000,
        );
        assert_eq!(ctx.trace_min, 0x7f000000);
        assert_eq!(ctx.trace_max, 0x7f001000);
    }

    struct MockTranslator;
    impl DebuggerAddressTranslator for MockTranslator {
        fn trace_to_program(&self, _trace_addr: u64, _snap: i64) -> Option<(String, u64)> {
            Some(("prog.bin".into(), 0x400000))
        }
        fn program_to_trace(&self, _url: &str, _addr: u64, _snap: i64) -> Option<u64> {
            Some(0x7fff0000)
        }
        fn get_open_mapped_locations(&self, _url: &str, _addr: u64) -> Vec<(String, u64, i64)> {
            vec![("trace1".into(), 0x7fff0000, 0)]
        }
    }

    #[test]
    fn test_address_translator_trait() {
        let translator = MockTranslator;
        let result = translator.trace_to_program(0x7fff0000, 0);
        assert_eq!(result, Some(("prog.bin".into(), 0x400000)));

        let result = translator.program_to_trace("prog.bin", 0x400000, 0);
        assert_eq!(result, Some(0x7fff0000));
    }

    #[test]
    fn test_region_map_proposal_serde() {
        let region = RegionMapProposal::new(".text", 0x1000, 0x2000, 0x400000, 0x401000, Lifespan::now_on(0));
        let json = serde_json::to_string(&region).unwrap();
        let back: RegionMapProposal = serde_json::from_str(&json).unwrap();
        assert_eq!(back.region_name, ".text");
    }
}
