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
}
