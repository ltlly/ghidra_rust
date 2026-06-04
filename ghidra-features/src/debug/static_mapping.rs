//! Static mapping model for the Debug framework.
//!
//! Ported from `ghidra.trace.model.modules` — includes [`TraceStaticMapping`]
//! and [`TraceStaticMappingManager`].

use std::collections::BTreeMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

use super::core_types::Lifespan;

// ---------------------------------------------------------------------------
// TraceStaticMapping
// ---------------------------------------------------------------------------

/// A mapping from a trace address range to a static program address range.
///
/// Ported from `ghidra.trace.model.modules.TraceStaticMapping`. This links
/// dynamic addresses in the trace to static addresses in a Ghidra Program.
#[derive(Debug, Clone)]
pub struct TraceStaticMapping {
    /// Unique key for this mapping.
    key: u64,
    /// The trace-side minimum address.
    trace_min_address: u64,
    /// The trace-side maximum address.
    trace_max_address: u64,
    /// The static program URL (string representation).
    static_program_url: String,
    /// The static-side minimum address (string form).
    static_min_address: String,
    /// The shift applied to trace addresses to get static addresses (or vice versa).
    shift: i64,
    /// The lifespan of this mapping.
    pub lifespan: Lifespan,
    /// Whether deleted.
    deleted: bool,
}

impl TraceStaticMapping {
    /// Create a new static mapping.
    pub fn new(
        key: u64,
        trace_min_address: u64,
        trace_max_address: u64,
        static_program_url: impl Into<String>,
        static_min_address: impl Into<String>,
        shift: i64,
        lifespan: Lifespan,
    ) -> Self {
        Self {
            key,
            trace_min_address,
            trace_max_address,
            static_program_url: static_program_url.into(),
            static_min_address: static_min_address.into(),
            shift,
            lifespan,
            deleted: false,
        }
    }

    /// Returns the unique key.
    pub fn key(&self) -> u64 {
        self.key
    }

    /// Returns the trace-side minimum address.
    pub fn trace_min_address(&self) -> u64 {
        self.trace_min_address
    }

    /// Returns the trace-side maximum address.
    pub fn trace_max_address(&self) -> u64 {
        self.trace_max_address
    }

    /// Returns the length of the mapped range.
    pub fn length(&self) -> u64 {
        self.trace_max_address - self.trace_min_address + 1
    }

    /// Returns the static program URL.
    pub fn static_program_url(&self) -> &str {
        &self.static_program_url
    }

    /// Returns the static-side minimum address string.
    pub fn static_min_address(&self) -> &str {
        &self.static_min_address
    }

    /// Returns the shift.
    pub fn shift(&self) -> i64 {
        self.shift
    }

    /// Check if this mapping contains the given trace address at the given snapshot.
    pub fn contains_trace_address(&self, address: u64, snap: i64) -> bool {
        !self.deleted
            && self.lifespan.contains(snap)
            && address >= self.trace_min_address
            && address <= self.trace_max_address
    }

    /// Check if this mapping conflicts with the given parameters.
    pub fn conflicts_with(
        &self,
        range_min: u64,
        range_max: u64,
        lifespan: &Lifespan,
        program_url: &str,
        static_address: &str,
    ) -> bool {
        if self.deleted {
            return false;
        }
        if self.static_program_url != program_url {
            return false;
        }
        if self.static_min_address != static_address {
            return false;
        }
        if !self.lifespan.intersects(lifespan) {
            return false;
        }
        self.trace_min_address <= range_max && range_min <= self.trace_max_address
    }

    /// Check if valid at the given snapshot.
    pub fn is_valid(&self, snap: i64) -> bool {
        !self.deleted && self.lifespan.contains(snap)
    }

    /// Delete this mapping.
    pub fn delete(&mut self) {
        self.deleted = true;
    }
}

impl fmt::Display for TraceStaticMapping {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[0x{:x}..0x{:x}] -> {}+{} {}",
            self.trace_min_address,
            self.trace_max_address,
            self.static_program_url,
            self.static_min_address,
            self.lifespan
        )
    }
}

// ---------------------------------------------------------------------------
// TraceStaticMappingManager
// ---------------------------------------------------------------------------

/// Manages static mappings within a trace.
///
/// Ported from `ghidra.trace.model.modules.TraceStaticMappingManager`.
#[derive(Debug)]
pub struct TraceStaticMappingManager {
    next_key: AtomicU64,
    mappings: BTreeMap<u64, TraceStaticMapping>,
}

impl TraceStaticMappingManager {
    /// Create a new empty static mapping manager.
    pub fn new() -> Self {
        Self {
            next_key: AtomicU64::new(1),
            mappings: BTreeMap::new(),
        }
    }

    fn alloc_key(&self) -> u64 {
        self.next_key.fetch_add(1, Ordering::Relaxed)
    }

    /// Add a static mapping.
    pub fn add_mapping(
        &mut self,
        trace_min_address: u64,
        trace_max_address: u64,
        static_program_url: impl Into<String>,
        static_min_address: impl Into<String>,
        shift: i64,
        lifespan: Lifespan,
    ) -> u64 {
        let key = self.alloc_key();
        self.mappings.insert(
            key,
            TraceStaticMapping::new(
                key,
                trace_min_address,
                trace_max_address,
                static_program_url,
                static_min_address,
                shift,
                lifespan,
            ),
        );
        key
    }

    /// Get a mapping by key.
    pub fn get_mapping(&self, key: u64) -> Option<&TraceStaticMapping> {
        self.mappings.get(&key)
    }

    /// Get a mutable mapping by key.
    pub fn get_mapping_mut(&mut self, key: u64) -> Option<&mut TraceStaticMapping> {
        self.mappings.get_mut(&key)
    }

    /// Find mappings that contain the given trace address at the given snapshot.
    pub fn get_mappings_for_address(&self, address: u64, snap: i64) -> Vec<&TraceStaticMapping> {
        self.mappings
            .values()
            .filter(|m| m.contains_trace_address(address, snap))
            .collect()
    }

    /// Find any conflicting mapping.
    pub fn find_any_conflicting(
        &self,
        range_min: u64,
        range_max: u64,
        lifespan: &Lifespan,
        program_url: &str,
        static_address: &str,
    ) -> Option<&TraceStaticMapping> {
        self.mappings.values().find(|m| {
            m.conflicts_with(range_min, range_max, lifespan, program_url, static_address)
        })
    }

    /// Iterate over all mappings.
    pub fn mappings(&self) -> impl Iterator<Item = &TraceStaticMapping> {
        self.mappings.values()
    }

    /// Remove a mapping by key.
    pub fn remove_mapping(&mut self, key: u64) -> Option<TraceStaticMapping> {
        self.mappings.remove(&key)
    }
}

impl Default for TraceStaticMappingManager {
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
    fn test_static_mapping_basic() {
        let mapping = TraceStaticMapping::new(
            1,
            0x400000,
            0x400FFF,
            "file:///path/to/program",
            "0x100000",
            0,
            Lifespan::now_on(0),
        );
        assert_eq!(mapping.key(), 1);
        assert_eq!(mapping.trace_min_address(), 0x400000);
        assert_eq!(mapping.trace_max_address(), 0x400FFF);
        assert_eq!(mapping.length(), 0x1000);
        assert_eq!(mapping.static_program_url(), "file:///path/to/program");
        assert_eq!(mapping.static_min_address(), "0x100000");
        assert_eq!(mapping.shift(), 0);
    }

    #[test]
    fn test_static_mapping_contains() {
        let mapping = TraceStaticMapping::new(
            1,
            0x400000,
            0x400FFF,
            "file:///prog",
            "0x100000",
            0,
            Lifespan::span(0, 100),
        );
        assert!(mapping.contains_trace_address(0x400500, 50));
        assert!(!mapping.contains_trace_address(0x400500, 101));
        assert!(!mapping.contains_trace_address(0x500000, 50));
    }

    #[test]
    fn test_static_mapping_conflicts() {
        let mapping = TraceStaticMapping::new(
            1,
            0x400000,
            0x400FFF,
            "file:///prog",
            "0x100000",
            0,
            Lifespan::span(0, 100),
        );

        // Same program, overlapping range, overlapping lifespan
        assert!(mapping.conflicts_with(
            0x400500,
            0x401500,
            &Lifespan::span(50, 150),
            "file:///prog",
            "0x100000",
        ));

        // Different program URL
        assert!(!mapping.conflicts_with(
            0x400500,
            0x401500,
            &Lifespan::span(50, 150),
            "file:///other_prog",
            "0x100000",
        ));

        // Non-overlapping lifespans
        assert!(!mapping.conflicts_with(
            0x400500,
            0x401500,
            &Lifespan::span(200, 300),
            "file:///prog",
            "0x100000",
        ));
    }

    #[test]
    fn test_static_mapping_delete() {
        let mut mapping = TraceStaticMapping::new(
            1,
            0x400000,
            0x400FFF,
            "file:///prog",
            "0x100000",
            0,
            Lifespan::now_on(0),
        );
        assert!(mapping.is_valid(0));
        mapping.delete();
        assert!(!mapping.is_valid(0));
    }

    #[test]
    fn test_static_mapping_manager() {
        let mut mgr = TraceStaticMappingManager::new();
        let k1 = mgr.add_mapping(
            0x400000,
            0x400FFF,
            "file:///prog",
            "0x100000",
            0,
            Lifespan::now_on(0),
        );
        let k2 = mgr.add_mapping(
            0x7F0000,
            0x7FFFFF,
            "file:///prog",
            "0x200000",
            0,
            Lifespan::now_on(0),
        );

        assert_eq!(mgr.mappings().count(), 2);

        let found = mgr.get_mappings_for_address(0x400500, 0);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].key(), k1);

        let not_found = mgr.get_mappings_for_address(0x500000, 0);
        assert!(not_found.is_empty());
    }

    #[test]
    fn test_static_mapping_manager_conflicting() {
        let mut mgr = TraceStaticMappingManager::new();
        mgr.add_mapping(
            0x400000,
            0x400FFF,
            "file:///prog",
            "0x100000",
            0,
            Lifespan::now_on(0),
        );

        let conflict = mgr.find_any_conflicting(
            0x400500,
            0x401500,
            &Lifespan::now_on(0),
            "file:///prog",
            "0x100000",
        );
        assert!(conflict.is_some());

        let no_conflict = mgr.find_any_conflicting(
            0x500000,
            0x500FFF,
            &Lifespan::now_on(0),
            "file:///prog",
            "0x100000",
        );
        assert!(no_conflict.is_none());
    }

    #[test]
    fn test_static_mapping_manager_remove() {
        let mut mgr = TraceStaticMappingManager::new();
        let k = mgr.add_mapping(
            0x400000,
            0x400FFF,
            "file:///prog",
            "0x100000",
            0,
            Lifespan::now_on(0),
        );
        assert_eq!(mgr.mappings().count(), 1);
        mgr.remove_mapping(k);
        assert_eq!(mgr.mappings().count(), 0);
    }

    #[test]
    fn test_static_mapping_display() {
        let mapping = TraceStaticMapping::new(
            1,
            0x400000,
            0x400FFF,
            "file:///prog",
            "0x100000",
            0,
            Lifespan::now_on(0),
        );
        let s = format!("{mapping}");
        assert!(s.contains("0x400000"));
        assert!(s.contains("0x400fff"));
    }
}
