//! TraceMemoryRegion -- enhanced memory region modeling for the debug trace.
//!
//! Ported from Ghidra's `ghidra.trace.model.memory.TraceMemoryRegion` and
//! `ghidra.trace.database.memory.DBTraceMemoryRegion`.
//!
//! This module provides a richer memory region type than the basic
//! `model::memory::TraceMemoryRegion`, adding permissions, address space
//! association, lifespan-based lifecycle, mapping metadata, and collection
//! management with overlap detection.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::model::Lifespan;
use crate::model::TraceMemoryState;

// ---------------------------------------------------------------------------
// MemoryRegionPermissions
// ---------------------------------------------------------------------------

/// Access permissions for a memory region.
///
/// Ported from Ghidra's region permission flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MemoryRegionPermissions {
    /// Whether the region is readable.
    pub read: bool,
    /// Whether the region is writable.
    pub write: bool,
    /// Whether the region is executable.
    pub execute: bool,
}

impl MemoryRegionPermissions {
    /// Full permissions (rwx).
    pub const RWX: Self = Self {
        read: true,
        write: true,
        execute: true,
    };

    /// Read-only.
    pub const READ_ONLY: Self = Self {
        read: true,
        write: false,
        execute: false,
    };

    /// Read + execute.
    pub const RX: Self = Self {
        read: true,
        write: false,
        execute: true,
    };

    /// Read + write.
    pub const RW: Self = Self {
        read: true,
        write: true,
        execute: false,
    };

    /// No permissions.
    pub const NONE: Self = Self {
        read: false,
        write: false,
        execute: false,
    };

    /// Create new permissions.
    pub fn new(read: bool, write: bool, execute: bool) -> Self {
        Self {
            read,
            write,
            execute,
        }
    }

    /// Whether these permissions grant any access at all.
    pub fn is_any(&self) -> bool {
        self.read || self.write || self.execute
    }

    /// Whether `self` is a superset of `other`.
    pub fn superset_of(&self, other: &Self) -> bool {
        (!other.read || self.read)
            && (!other.write || self.write)
            && (!other.execute || self.execute)
    }

    /// Intersect two permission sets.
    pub fn intersect(&self, other: &Self) -> Self {
        Self {
            read: self.read && other.read,
            write: self.write && other.write,
            execute: self.execute && other.execute,
        }
    }
}

impl Default for MemoryRegionPermissions {
    fn default() -> Self {
        Self::RWX
    }
}

impl fmt::Display for MemoryRegionPermissions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}{}{}",
            if self.read { 'r' } else { '-' },
            if self.write { 'w' } else { '-' },
            if self.execute { 'x' } else { '-' }
        )
    }
}

// ---------------------------------------------------------------------------
// TraceMemoryRegionEntry
// ---------------------------------------------------------------------------

/// An enhanced memory region entry for the debug trace.
///
/// Ported from Ghidra's `DBTraceMemoryRegion`. Each region lives in a
/// specific address space, has a bounded range of offsets, permissions,
/// a lifespan, and optional mapping metadata (e.g., file offset for
/// loaded modules).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceMemoryRegionEntry {
    /// Unique key identifying this region.
    pub key: i64,
    /// The object path (e.g., "MemoryRegions[0]").
    pub path: String,
    /// Display name (e.g., ".text", ".data", "[heap]").
    pub name: String,
    /// The address space this region belongs to (e.g., "ram", "register").
    pub space: String,
    /// Start offset within the address space.
    pub min_address: u64,
    /// End offset within the address space (inclusive).
    pub max_address: u64,
    /// Access permissions.
    pub permissions: MemoryRegionPermissions,
    /// Whether this region is volatile (e.g., memory-mapped I/O).
    pub volatile: bool,
    /// The lifespan during which this region exists.
    pub lifespan: Lifespan,
    /// The memory state of this region.
    pub state: TraceMemoryState,
    /// Optional source file path (for memory-mapped files).
    pub source_file: Option<String>,
    /// Optional file offset corresponding to `min_address`.
    pub file_offset: Option<u64>,
    /// Optional comment.
    pub comment: Option<String>,
}

impl TraceMemoryRegionEntry {
    /// Create a new memory region.
    pub fn new(
        key: i64,
        path: impl Into<String>,
        name: impl Into<String>,
        space: impl Into<String>,
        min_address: u64,
        max_address: u64,
        lifespan: Lifespan,
    ) -> Self {
        Self {
            key,
            path: path.into(),
            name: name.into(),
            space: space.into(),
            min_address,
            max_address,
            permissions: MemoryRegionPermissions::default(),
            volatile: false,
            lifespan,
            state: TraceMemoryState::Unknown,
            source_file: None,
            file_offset: None,
            comment: None,
        }
    }

    /// Set permissions.
    pub fn with_permissions(mut self, perms: MemoryRegionPermissions) -> Self {
        self.permissions = perms;
        self
    }

    /// Mark as volatile.
    pub fn with_volatile(mut self, volatile: bool) -> Self {
        self.volatile = volatile;
        self
    }

    /// Set the memory state.
    pub fn with_state(mut self, state: TraceMemoryState) -> Self {
        self.state = state;
        self
    }

    /// Set a source file mapping.
    pub fn with_source_file(mut self, path: impl Into<String>, file_offset: u64) -> Self {
        self.source_file = Some(path.into());
        self.file_offset = Some(file_offset);
        self
    }

    /// Set a comment.
    pub fn with_comment(mut self, comment: impl Into<String>) -> Self {
        self.comment = Some(comment.into());
        self
    }

    /// Size of this region in bytes.
    pub fn size(&self) -> u64 {
        self.max_address - self.min_address + 1
    }

    /// Whether this region is valid at `snap`.
    pub fn is_valid_at(&self, snap: i64) -> bool {
        self.lifespan.contains(snap)
    }

    /// Whether the region is alive for any part of the given span.
    pub fn is_alive(&self, span: &Lifespan) -> bool {
        self.lifespan.intersects(span)
    }

    /// Whether the region is currently alive (not yet removed).
    pub fn is_alive_now(&self) -> bool {
        self.lifespan.lmax() == Lifespan::MAX
    }

    /// End this region's life at the given snap.
    pub fn remove(&mut self, snap: i64) {
        self.lifespan = self.lifespan.with_max(snap);
    }

    /// Whether the given offset falls within this region.
    pub fn contains_offset(&self, offset: u64) -> bool {
        offset >= self.min_address && offset <= self.max_address
    }

    /// Whether this region overlaps with another.
    pub fn overlaps(&self, other: &Self) -> bool {
        self.space == other.space
            && self.lifespan.intersects(&other.lifespan)
            && self.min_address <= other.max_address
            && other.min_address <= self.max_address
    }

    /// Whether the given address is readable through this region.
    pub fn is_readable(&self) -> bool {
        self.permissions.read
    }

    /// Whether the given address is writable through this region.
    pub fn is_writable(&self) -> bool {
        self.permissions.write
    }

    /// Whether the given address is executable through this region.
    pub fn is_executable(&self) -> bool {
        self.permissions.execute
    }
}

// ---------------------------------------------------------------------------
// TraceMemoryRegionManager
// ---------------------------------------------------------------------------

/// Manages memory regions for a trace, supporting lifecycle, overlap
/// detection, and query-by-address.
///
/// Ported from Ghidra's `DBTraceMemoryManager` region management.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TraceMemoryRegionManager {
    /// Regions indexed by key.
    regions: BTreeMap<i64, TraceMemoryRegionEntry>,
    /// Next available key.
    next_key: i64,
}

impl TraceMemoryRegionManager {
    /// Create a new empty manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a region and return its key. The region's `key` field is
    /// overwritten with the assigned key.
    pub fn add_region(&mut self, mut region: TraceMemoryRegionEntry) -> i64 {
        let key = self.next_key;
        self.next_key += 1;
        region.key = key;
        self.regions.insert(key, region);
        key
    }

    /// Get a region by key.
    pub fn region(&self, key: i64) -> Option<&TraceMemoryRegionEntry> {
        self.regions.get(&key)
    }

    /// Get a mutable region by key.
    pub fn region_mut(&mut self, key: i64) -> Option<&mut TraceMemoryRegionEntry> {
        self.regions.get_mut(&key)
    }

    /// Remove a region by key.
    pub fn remove_region(&mut self, key: i64) -> Option<TraceMemoryRegionEntry> {
        self.regions.remove(&key)
    }

    /// All region keys.
    pub fn region_keys(&self) -> Vec<i64> {
        self.regions.keys().copied().collect()
    }

    /// The number of regions (including dead).
    pub fn region_count(&self) -> usize {
        self.regions.len()
    }

    /// All regions alive at `snap`.
    pub fn regions_at(&self, snap: i64) -> Vec<&TraceMemoryRegionEntry> {
        self.regions
            .values()
            .filter(|r| r.is_valid_at(snap))
            .collect()
    }

    /// All regions in a given address space, alive at `snap`.
    pub fn regions_in_space_at(&self, space: &str, snap: i64) -> Vec<&TraceMemoryRegionEntry> {
        self.regions
            .values()
            .filter(|r| r.space == space && r.is_valid_at(snap))
            .collect()
    }

    /// Find the region containing the given offset in a space at `snap`.
    pub fn region_containing(
        &self,
        space: &str,
        offset: u64,
        snap: i64,
    ) -> Option<&TraceMemoryRegionEntry> {
        self.regions.values().find(|r| {
            r.space == space && r.is_valid_at(snap) && r.contains_offset(offset)
        })
    }

    /// Detect overlapping regions in a given space at `snap`.
    pub fn detect_overlaps(&self, space: &str, snap: i64) -> Vec<(i64, i64)> {
        let regions: Vec<&TraceMemoryRegionEntry> = self.regions_in_space_at(space, snap);
        let mut overlaps = Vec::new();
        for i in 0..regions.len() {
            for j in (i + 1)..regions.len() {
                if regions[i].overlaps(regions[j]) {
                    overlaps.push((regions[i].key, regions[j].key));
                }
            }
        }
        overlaps
    }

    /// Get the permissions at a specific offset in a space at `snap`.
    pub fn permissions_at(
        &self,
        space: &str,
        offset: u64,
        snap: i64,
    ) -> Option<MemoryRegionPermissions> {
        self.region_containing(space, offset, snap)
            .map(|r| r.permissions)
    }

    /// Get the memory state at a specific offset in a space at `snap`.
    pub fn state_at(
        &self,
        space: &str,
        offset: u64,
        snap: i64,
    ) -> Option<TraceMemoryState> {
        self.region_containing(space, offset, snap)
            .map(|r| r.state)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_permissions_display() {
        assert_eq!(MemoryRegionPermissions::RWX.to_string(), "rwx");
        assert_eq!(MemoryRegionPermissions::READ_ONLY.to_string(), "r--");
        assert_eq!(MemoryRegionPermissions::RX.to_string(), "r-x");
        assert_eq!(MemoryRegionPermissions::NONE.to_string(), "---");
    }

    #[test]
    fn test_permissions_intersect() {
        let a = MemoryRegionPermissions::RWX;
        let b = MemoryRegionPermissions::RX;
        let c = a.intersect(&b);
        assert!(c.read);
        assert!(!c.write);
        assert!(c.execute);
    }

    #[test]
    fn test_permissions_superset() {
        assert!(MemoryRegionPermissions::RWX.superset_of(&MemoryRegionPermissions::READ_ONLY));
        assert!(!MemoryRegionPermissions::READ_ONLY.superset_of(&MemoryRegionPermissions::RWX));
    }

    #[test]
    fn test_region_creation() {
        let r = TraceMemoryRegionEntry::new(
            1,
            "Regions[0]",
            ".text",
            "ram",
            0x400000,
            0x400FFF,
            Lifespan::now_on(0),
        );
        assert_eq!(r.key, 1);
        assert_eq!(r.name, ".text");
        assert_eq!(r.space, "ram");
        assert_eq!(r.size(), 0x1000);
        assert!(r.is_valid_at(0));
        assert!(r.is_valid_at(100));
        assert!(r.is_alive_now());
    }

    #[test]
    fn test_region_builder() {
        let r = TraceMemoryRegionEntry::new(
            0,
            "R[0]",
            ".data",
            "ram",
            0x500000,
            0x500FFF,
            Lifespan::now_on(0),
        )
        .with_permissions(MemoryRegionPermissions::RW)
        .with_volatile(false)
        .with_state(TraceMemoryState::Known)
        .with_source_file("/usr/lib/libc.so", 0)
        .with_comment("data section");

        assert_eq!(r.permissions, MemoryRegionPermissions::RW);
        assert!(!r.volatile);
        assert_eq!(r.state, TraceMemoryState::Known);
        assert_eq!(r.source_file.as_deref(), Some("/usr/lib/libc.so"));
        assert_eq!(r.file_offset, Some(0));
        assert_eq!(r.comment.as_deref(), Some("data section"));
    }

    #[test]
    fn test_region_remove() {
        let mut r = TraceMemoryRegionEntry::new(
            0, "R[0]", ".text", "ram", 0x100, 0x1FF, Lifespan::now_on(0),
        );
        assert!(r.is_alive_now());
        r.remove(10);
        assert!(r.is_valid_at(10));
        assert!(!r.is_valid_at(11));
        assert!(!r.is_alive_now());
    }

    #[test]
    fn test_region_contains_offset() {
        let r = TraceMemoryRegionEntry::new(
            0, "R[0]", ".text", "ram", 0x100, 0x1FF, Lifespan::now_on(0),
        );
        assert!(r.contains_offset(0x100));
        assert!(r.contains_offset(0x180));
        assert!(r.contains_offset(0x1FF));
        assert!(!r.contains_offset(0x0FF));
        assert!(!r.contains_offset(0x200));
    }

    #[test]
    fn test_region_overlaps() {
        let a = TraceMemoryRegionEntry::new(
            0, "R[0]", "a", "ram", 0x100, 0x1FF, Lifespan::now_on(0),
        );
        let b = TraceMemoryRegionEntry::new(
            1, "R[1]", "b", "ram", 0x180, 0x280, Lifespan::now_on(0),
        );
        let c = TraceMemoryRegionEntry::new(
            2, "R[2]", "c", "ram", 0x200, 0x2FF, Lifespan::now_on(0),
        );
        // Different space
        let d = TraceMemoryRegionEntry::new(
            3, "R[3]", "d", "io", 0x100, 0x1FF, Lifespan::now_on(0),
        );

        assert!(a.overlaps(&b));
        assert!(b.overlaps(&a));
        assert!(b.overlaps(&c));
        assert!(!a.overlaps(&c));
        assert!(!a.overlaps(&d));
    }

    #[test]
    fn test_region_permissions_helpers() {
        let r = TraceMemoryRegionEntry::new(
            0, "R[0]", ".text", "ram", 0x100, 0x1FF, Lifespan::now_on(0),
        )
        .with_permissions(MemoryRegionPermissions::RX);

        assert!(r.is_readable());
        assert!(!r.is_writable());
        assert!(r.is_executable());
    }

    #[test]
    fn test_region_manager_add_and_query() {
        let mut mgr = TraceMemoryRegionManager::new();
        let k = mgr.add_region(TraceMemoryRegionEntry::new(
            0, "", ".text", "ram", 0x400000, 0x400FFF, Lifespan::now_on(0),
        ));
        assert_eq!(k, 0);
        assert_eq!(mgr.region_count(), 1);

        let r = mgr.region(k).unwrap();
        assert_eq!(r.name, ".text");
    }

    #[test]
    fn test_region_manager_remove() {
        let mut mgr = TraceMemoryRegionManager::new();
        let k = mgr.add_region(TraceMemoryRegionEntry::new(
            0, "", ".text", "ram", 0x400000, 0x400FFF, Lifespan::now_on(0),
        ));
        assert!(mgr.remove_region(k).is_some());
        assert_eq!(mgr.region_count(), 0);
        assert!(mgr.region(k).is_none());
    }

    #[test]
    fn test_region_manager_regions_at() {
        let mut mgr = TraceMemoryRegionManager::new();
        mgr.add_region(TraceMemoryRegionEntry::new(
            0, "", ".text", "ram", 0x400000, 0x400FFF, Lifespan::now_on(0),
        ));
        mgr.add_region(TraceMemoryRegionEntry::new(
            0, "", ".data", "ram", 0x500000, 0x500FFF, Lifespan::span(5, 20),
        ));

        assert_eq!(mgr.regions_at(0).len(), 1);
        assert_eq!(mgr.regions_at(5).len(), 2);
        assert_eq!(mgr.regions_at(21).len(), 1);
    }

    #[test]
    fn test_region_manager_space_filter() {
        let mut mgr = TraceMemoryRegionManager::new();
        mgr.add_region(TraceMemoryRegionEntry::new(
            0, "", ".text", "ram", 0x400000, 0x400FFF, Lifespan::now_on(0),
        ));
        mgr.add_region(TraceMemoryRegionEntry::new(
            0, "", "reg", "register", 0, 0xFF, Lifespan::now_on(0),
        ));

        assert_eq!(mgr.regions_in_space_at("ram", 0).len(), 1);
        assert_eq!(mgr.regions_in_space_at("register", 0).len(), 1);
        assert_eq!(mgr.regions_in_space_at("io", 0).len(), 0);
    }

    #[test]
    fn test_region_manager_containing() {
        let mut mgr = TraceMemoryRegionManager::new();
        mgr.add_region(TraceMemoryRegionEntry::new(
            0, "", ".text", "ram", 0x400000, 0x400FFF, Lifespan::now_on(0),
        ));

        let r = mgr.region_containing("ram", 0x400500, 0).unwrap();
        assert_eq!(r.name, ".text");
        assert!(mgr.region_containing("ram", 0x300000, 0).is_none());
        assert!(mgr.region_containing("io", 0x400500, 0).is_none());
    }

    #[test]
    fn test_region_manager_detect_overlaps() {
        let mut mgr = TraceMemoryRegionManager::new();
        let k0 = mgr.add_region(TraceMemoryRegionEntry::new(
            0, "", "a", "ram", 0x100, 0x1FF, Lifespan::now_on(0),
        ));
        let k1 = mgr.add_region(TraceMemoryRegionEntry::new(
            0, "", "b", "ram", 0x180, 0x280, Lifespan::now_on(0),
        ));
        mgr.add_region(TraceMemoryRegionEntry::new(
            0, "", "c", "ram", 0x300, 0x3FF, Lifespan::now_on(0),
        ));

        let overlaps = mgr.detect_overlaps("ram", 0);
        assert_eq!(overlaps.len(), 1);
        assert_eq!(overlaps[0], (k0, k1));
    }

    #[test]
    fn test_region_manager_permissions_at() {
        let mut mgr = TraceMemoryRegionManager::new();
        mgr.add_region(
            TraceMemoryRegionEntry::new(
                0, "", ".text", "ram", 0x400000, 0x400FFF, Lifespan::now_on(0),
            )
            .with_permissions(MemoryRegionPermissions::RX),
        );

        let p = mgr.permissions_at("ram", 0x400500, 0).unwrap();
        assert_eq!(p, MemoryRegionPermissions::RX);
        assert!(mgr.permissions_at("ram", 0x300000, 0).is_none());
    }

    #[test]
    fn test_region_manager_state_at() {
        let mut mgr = TraceMemoryRegionManager::new();
        mgr.add_region(
            TraceMemoryRegionEntry::new(
                0, "", ".text", "ram", 0x400000, 0x400FFF, Lifespan::now_on(0),
            )
            .with_state(TraceMemoryState::Known),
        );

        let s = mgr.state_at("ram", 0x400500, 0).unwrap();
        assert_eq!(s, TraceMemoryState::Known);
    }

    #[test]
    fn test_region_serde() {
        let r = TraceMemoryRegionEntry::new(
            1,
            "Regions[0]",
            ".text",
            "ram",
            0x400000,
            0x400FFF,
            Lifespan::now_on(0),
        )
        .with_permissions(MemoryRegionPermissions::RX);

        let json = serde_json::to_string(&r).unwrap();
        let back: TraceMemoryRegionEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(back.key, 1);
        assert_eq!(back.name, ".text");
        assert_eq!(back.permissions, MemoryRegionPermissions::RX);
    }

    #[test]
    fn test_permissions_is_any() {
        assert!(MemoryRegionPermissions::RWX.is_any());
        assert!(MemoryRegionPermissions::READ_ONLY.is_any());
        assert!(!MemoryRegionPermissions::NONE.is_any());
    }

    #[test]
    fn test_region_is_alive() {
        let r = TraceMemoryRegionEntry::new(
            0, "R[0]", ".text", "ram", 0x100, 0x1FF, Lifespan::span(0, 10),
        );
        assert!(r.is_alive(&Lifespan::span(5, 15)));
        assert!(!r.is_alive(&Lifespan::span(20, 30)));
    }

    #[test]
    fn test_region_manager_serde() {
        let mut mgr = TraceMemoryRegionManager::new();
        mgr.add_region(TraceMemoryRegionEntry::new(
            0, "", ".text", "ram", 0x400000, 0x400FFF, Lifespan::now_on(0),
        ));

        let json = serde_json::to_string(&mgr).unwrap();
        let back: TraceMemoryRegionManager = serde_json::from_str(&json).unwrap();
        assert_eq!(back.region_count(), 1);
    }
}
