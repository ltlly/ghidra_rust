//! Mapped memory bytes visitor.
//!
//! Ported from Ghidra's `AbstractMappedMemoryBytesVisitor`.
//!
//! Provides a visitor pattern for reading memory bytes from mapped programs
//! in a trace. The visitor traverses static mappings between the trace's
//! host address space and mapped program address spaces, reading bytes
//! from program memory at each mapped range.
//!
//! This is useful for operations that need to copy or compare memory
//! between the trace and statically-mapped programs (e.g., for diffing,
//! export, or synchronization).

use std::collections::BTreeMap;

/// A mapping entry from trace address range to program address range.
///
/// Ported from the static mapping service's `MapEntry`.
#[derive(Debug, Clone)]
pub struct StaticMappingEntry {
    /// Start offset in the trace address space.
    pub trace_start: u64,
    /// End offset in the trace address space.
    pub trace_end: u64,
    /// Start offset in the program address space.
    pub program_start: u64,
    /// Length of the mapping in bytes.
    pub length: u64,
    /// Identifier for the mapped program.
    pub program_id: String,
}

impl StaticMappingEntry {
    /// Create a new mapping entry.
    pub fn new(
        trace_start: u64,
        trace_end: u64,
        program_start: u64,
        length: u64,
        program_id: impl Into<String>,
    ) -> Self {
        Self {
            trace_start,
            trace_end,
            program_start,
            length,
            program_id: program_id.into(),
        }
    }

    /// Map a trace offset to a program offset.
    pub fn map_trace_to_program(&self, trace_offset: u64) -> Option<u64> {
        if trace_offset < self.trace_start || trace_offset > self.trace_end {
            return None;
        }
        let delta = trace_offset - self.trace_start;
        Some(self.program_start + delta)
    }

    /// Map a program offset to a trace offset.
    pub fn map_program_to_trace(&self, program_offset: u64) -> Option<u64> {
        if program_offset < self.program_start
            || program_offset >= self.program_start + self.length
        {
            return None;
        }
        let delta = program_offset - self.program_start;
        Some(self.trace_start + delta)
    }

    /// Check if this mapping overlaps with a given trace range.
    pub fn overlaps_trace(&self, start: u64, end: u64) -> bool {
        self.trace_start <= end && self.trace_end >= start
    }

    /// Get the intersection of this mapping with a given trace range.
    pub fn intersect_trace(&self, start: u64, end: u64) -> Option<(u64, u64)> {
        let is = self.trace_start.max(start);
        let ie = self.trace_end.min(end);
        if is <= ie {
            Some((is, ie))
        } else {
            None
        }
    }
}

/// Result of visiting a memory region.
#[derive(Debug, Clone)]
pub struct VisitResult {
    /// The trace address where bytes were read.
    pub trace_address: u64,
    /// The number of bytes read.
    pub bytes_read: usize,
    /// The program ID that was the source.
    pub program_id: String,
}

/// An abstract visitor for reading mapped memory bytes from programs.
///
/// Ported from Ghidra's `AbstractMappedMemoryBytesVisitor`. Provides
/// the framework for iterating over static mappings and reading bytes
/// from program memory into a buffer.
///
/// # Usage
///
/// ```rust
/// use ghidra_debug::plugin::mapped_memory_visitor::*;
///
/// let mut visitor = MappedMemoryBytesVisitor::new(4096);
/// visitor.add_mapping_default(StaticMappingEntry::new(0x1000, 0x1FFF, 0x400000, 0x1000, "prog1"));
///
/// // Visit trace range [0x1000, 0x100F]
/// let results = visitor.visit(0, 0x1000, 0x100F);
/// ```
pub struct MappedMemoryBytesVisitor {
    /// Known static mappings, indexed by snap.
    mappings: BTreeMap<i64, Vec<StaticMappingEntry>>,
    /// Buffer size for reading.
    buffer_size: usize,
}

impl MappedMemoryBytesVisitor {
    /// Create a new visitor with the given buffer size.
    pub fn new(buffer_size: usize) -> Self {
        Self {
            mappings: BTreeMap::new(),
            buffer_size,
        }
    }

    /// Add a mapping entry for a given snap.
    pub fn add_mapping(&mut self, snap: i64, entry: StaticMappingEntry) {
        self.mappings.entry(snap).or_default().push(entry);
    }

    /// Add a mapping entry for snap 0.
    pub fn add_mapping_default(&mut self, entry: StaticMappingEntry) {
        self.add_mapping(0, entry);
    }

    /// Get the active mappings for a given snap.
    ///
    /// Returns the mappings for the most recent snap <= the given snap.
    pub fn get_mappings(&self, snap: i64) -> Option<&Vec<StaticMappingEntry>> {
        // Find the most recent snap <= given snap
        self.mappings.range(..=snap).next_back().map(|(_, v)| v)
    }

    /// Visit a trace address range, collecting visit results.
    ///
    /// For each mapping that overlaps the given range, a `VisitResult`
    /// is produced describing what was "visited". In a full implementation,
    /// this would actually read bytes from the program memory.
    pub fn visit(&self, snap: i64, trace_start: u64, trace_end: u64) -> Vec<VisitResult> {
        let mut results = Vec::new();
        if let Some(entries) = self.get_mappings(snap) {
            for entry in entries {
                if let Some((is, ie)) = entry.intersect_trace(trace_start, trace_end) {
                    results.push(VisitResult {
                        trace_address: is,
                        bytes_read: (ie - is + 1) as usize,
                        program_id: entry.program_id.clone(),
                    });
                }
            }
        }
        results
    }

    /// Visit and collect bytes (stub - in full implementation reads from program memory).
    pub fn visit_bytes(
        &self,
        snap: i64,
        trace_start: u64,
        trace_end: u64,
    ) -> Vec<(u64, Vec<u8>, String)> {
        let mut result = Vec::new();
        if let Some(entries) = self.get_mappings(snap) {
            for entry in entries {
                if let Some((is, ie)) = entry.intersect_trace(trace_start, trace_end) {
                    let len = (ie - is + 1) as usize;
                    let bytes = vec![0u8; len.min(self.buffer_size)];
                    result.push((is, bytes, entry.program_id.clone()));
                }
            }
        }
        result
    }

    /// Get the number of mappings for a given snap.
    pub fn mapping_count(&self, snap: i64) -> usize {
        self.get_mappings(snap).map_or(0, |v| v.len())
    }

    /// Check if any mappings exist.
    pub fn has_mappings(&self) -> bool {
        !self.mappings.is_empty()
    }
}

/// A concrete implementation that collects visited bytes into a Vec.
///
/// This is the simplest usable visitor. More sophisticated visitors
/// would write to a file, compare with another trace, etc.
#[derive(Debug)]
pub struct CollectingVisitor {
    entries: Vec<VisitedEntry>,
}

/// A single visited entry from the collecting visitor.
#[derive(Debug, Clone)]
pub struct VisitedEntry {
    /// The trace address.
    pub trace_address: u64,
    /// The collected bytes.
    pub bytes: Vec<u8>,
    /// Source program ID.
    pub program_id: String,
}

impl CollectingVisitor {
    /// Create a new collecting visitor.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Visit a data chunk.
    pub fn visit_data(&mut self, trace_address: u64, bytes: &[u8], program_id: &str) {
        self.entries.push(VisitedEntry {
            trace_address,
            bytes: bytes.to_vec(),
            program_id: program_id.to_string(),
        });
    }

    /// Get all collected entries.
    pub fn entries(&self) -> &[VisitedEntry] {
        &self.entries
    }

    /// Get the total number of bytes collected.
    pub fn total_bytes(&self) -> usize {
        self.entries.iter().map(|e| e.bytes.len()).sum()
    }

    /// Clear all collected entries.
    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

impl Default for CollectingVisitor {
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
    fn test_mapping_entry_creation() {
        let entry = StaticMappingEntry::new(0x1000, 0x1FFF, 0x400000, 0x1000, "prog1");
        assert_eq!(entry.trace_start, 0x1000);
        assert_eq!(entry.trace_end, 0x1FFF);
        assert_eq!(entry.program_start, 0x400000);
        assert_eq!(entry.length, 0x1000);
        assert_eq!(entry.program_id, "prog1");
    }

    #[test]
    fn test_mapping_trace_to_program() {
        let entry = StaticMappingEntry::new(0x1000, 0x1FFF, 0x400000, 0x1000, "prog1");
        assert_eq!(entry.map_trace_to_program(0x1000), Some(0x400000));
        assert_eq!(entry.map_trace_to_program(0x1050), Some(0x400050));
        assert_eq!(entry.map_trace_to_program(0x1FFF), Some(0x400FFF));
        assert_eq!(entry.map_trace_to_program(0x2000), None);
        assert_eq!(entry.map_trace_to_program(0x0FFF), None);
    }

    #[test]
    fn test_mapping_program_to_trace() {
        let entry = StaticMappingEntry::new(0x1000, 0x1FFF, 0x400000, 0x1000, "prog1");
        assert_eq!(entry.map_program_to_trace(0x400000), Some(0x1000));
        assert_eq!(entry.map_program_to_trace(0x400050), Some(0x1050));
        assert_eq!(entry.map_program_to_trace(0x400FFF), Some(0x1FFF));
        assert_eq!(entry.map_program_to_trace(0x401000), None);
    }

    #[test]
    fn test_mapping_overlap() {
        let entry = StaticMappingEntry::new(0x1000, 0x1FFF, 0x400000, 0x1000, "prog1");
        assert!(entry.overlaps_trace(0x1000, 0x1FFF));
        assert!(entry.overlaps_trace(0x0000, 0x2000));
        assert!(entry.overlaps_trace(0x1500, 0x1800));
        assert!(!entry.overlaps_trace(0x2000, 0x3000));
        assert!(!entry.overlaps_trace(0x0000, 0x0FFF));
    }

    #[test]
    fn test_mapping_intersection() {
        let entry = StaticMappingEntry::new(0x1000, 0x1FFF, 0x400000, 0x1000, "prog1");
        assert_eq!(entry.intersect_trace(0x1000, 0x1FFF), Some((0x1000, 0x1FFF)));
        assert_eq!(entry.intersect_trace(0x1500, 0x1800), Some((0x1500, 0x1800)));
        assert_eq!(entry.intersect_trace(0x0000, 0x1050), Some((0x1000, 0x1050)));
        assert_eq!(entry.intersect_trace(0x2000, 0x3000), None);
    }

    #[test]
    fn test_visitor_basic() {
        let mut visitor = MappedMemoryBytesVisitor::new(4096);
        visitor.add_mapping_default(StaticMappingEntry::new(0x1000, 0x1FFF, 0x400000, 0x1000, "prog1"));
        assert!(visitor.has_mappings());
        assert_eq!(visitor.mapping_count(0), 1);
    }

    #[test]
    fn test_visitor_visit() {
        let mut visitor = MappedMemoryBytesVisitor::new(4096);
        visitor.add_mapping_default(StaticMappingEntry::new(0x1000, 0x1FFF, 0x400000, 0x1000, "prog1"));

        let results = visitor.visit(0, 0x1000, 0x100F);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].trace_address, 0x1000);
        assert_eq!(results[0].bytes_read, 0x10);
        assert_eq!(results[0].program_id, "prog1");
    }

    #[test]
    fn test_visitor_no_overlap() {
        let mut visitor = MappedMemoryBytesVisitor::new(4096);
        visitor.add_mapping_default(StaticMappingEntry::new(0x1000, 0x1FFF, 0x400000, 0x1000, "prog1"));

        let results = visitor.visit(0, 0x5000, 0x5FFF);
        assert!(results.is_empty());
    }

    #[test]
    fn test_visitor_multiple_mappings() {
        let mut visitor = MappedMemoryBytesVisitor::new(4096);
        visitor.add_mapping_default(StaticMappingEntry::new(0x1000, 0x1FFF, 0x400000, 0x1000, "prog1"));
        visitor.add_mapping_default(StaticMappingEntry::new(0x3000, 0x3FFF, 0x800000, 0x1000, "prog2"));

        // Range that spans both
        let results = visitor.visit(0, 0x0000, 0xFFFF);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_visitor_snap_resolution() {
        let mut visitor = MappedMemoryBytesVisitor::new(4096);
        visitor.add_mapping(0, StaticMappingEntry::new(0x1000, 0x1FFF, 0x400000, 0x1000, "old"));
        visitor.add_mapping(10, StaticMappingEntry::new(0x1000, 0x1FFF, 0x800000, 0x1000, "new"));

        // At snap 5, should get "old" mappings
        let results = visitor.visit(5, 0x1000, 0x100F);
        assert_eq!(results[0].program_id, "old");

        // At snap 10, should get "new" mappings
        let results = visitor.visit(10, 0x1000, 0x100F);
        assert_eq!(results[0].program_id, "new");
    }

    #[test]
    fn test_collecting_visitor() {
        let mut visitor = CollectingVisitor::new();
        visitor.visit_data(0x1000, &[0x48, 0x89, 0xE5], "prog1");
        visitor.visit_data(0x2000, &[0x55, 0x48, 0x89, 0xE5], "prog2");

        assert_eq!(visitor.entries().len(), 2);
        assert_eq!(visitor.total_bytes(), 7);
    }

    #[test]
    fn test_collecting_visitor_clear() {
        let mut visitor = CollectingVisitor::new();
        visitor.visit_data(0x1000, &[1, 2, 3], "prog");
        assert_eq!(visitor.total_bytes(), 3);
        visitor.clear();
        assert_eq!(visitor.total_bytes(), 0);
    }
}
