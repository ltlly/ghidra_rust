//! TraceMemoryRegion -- enhanced memory region modeling for the debug trace.
//!
//! Ported from Ghidra's `ghidra.trace.model.memory.TraceMemoryRegion`,
//! `ghidra.trace.model.memory.TraceMemoryFlag`, and
//! `ghidra.trace.database.memory.DBTraceMemoryRegion`.
//!
//! This module provides a richer memory region type than the basic
//! `model::memory::TraceMemoryRegion`, adding permissions, address space
//! association, lifespan-based lifecycle, mapping metadata, and collection
//! management with overlap detection.
//!
//! New in this update: `TraceMemoryFlag` enum (from Java `TraceMemoryFlag`),
//! snap-based flag operations (`set_flags`, `add_flags`, `clear_flags`,
//! `get_flags`, `set_read`, `set_write`, `set_execute`, `set_volatile`),
//! snap-based range operations (`set_range`, `get_range`, `set_min_address`,
//! `set_max_address`, `set_length`, `get_length`), snap-based name
//! operations (`set_name`, `get_name`), and `delete`/`remove` lifecycle.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::model::Lifespan;
use crate::model::TraceMemoryState;

// ---------------------------------------------------------------------------
// TraceMemoryRegionChangeEvent
// ---------------------------------------------------------------------------

/// The kind of change event that occurred on a memory region.
///
/// Ported from Ghidra's `TraceEvents.REGION_ADDED`, `REGION_CHANGED`, etc.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TraceMemoryRegionChangeEvent {
    /// A new region was added.
    Added,
    /// The region's lifespan changed (creation or destruction snap moved).
    LifespanChanged,
    /// The region's properties changed (name, range, flags, etc.).
    Changed,
    /// The region was deleted.
    Deleted,
}

impl TraceMemoryRegionChangeEvent {
    /// Human-readable name.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Added => "Added",
            Self::LifespanChanged => "LifespanChanged",
            Self::Changed => "Changed",
            Self::Deleted => "Deleted",
        }
    }
}

impl fmt::Display for TraceMemoryRegionChangeEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// TraceOverlappedRegionException
// ---------------------------------------------------------------------------

/// Error returned when adding or modifying a region would cause it to
/// overlap an existing region in the same address space.
///
/// Ported from Ghidra's `TraceOverlappedRegionException`.
#[derive(Debug, Clone)]
pub struct TraceOverlappedRegionException {
    /// The keys of the conflicting regions.
    pub conflicts: Vec<i64>,
    /// Human-readable message.
    pub message: String,
}

impl TraceOverlappedRegionException {
    /// Create a new overlap exception with the given conflicting region keys.
    pub fn new(conflicts: Vec<i64>) -> Self {
        let msg = format!(
            "Region would overlap {} existing region(s): {:?}",
            conflicts.len(),
            conflicts
        );
        Self {
            conflicts,
            message: msg,
        }
    }
}

impl fmt::Display for TraceOverlappedRegionException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for TraceOverlappedRegionException {}

// ---------------------------------------------------------------------------
// AddressRange (helper for range-based operations)
// ---------------------------------------------------------------------------

/// A simple address range represented as (min, max) inclusive.
///
/// This is a lightweight stand-in for Ghidra's `AddressRange` used by
/// region operations that need to express a contiguous range of offsets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AddressRange {
    /// Minimum offset (inclusive).
    pub min: u64,
    /// Maximum offset (inclusive).
    pub max: u64,
}

impl AddressRange {
    /// Create a new address range.
    pub fn new(min: u64, max: u64) -> Self {
        Self { min, max }
    }

    /// The length of this range in bytes.
    pub fn length(&self) -> u64 {
        self.max - self.min + 1
    }

    /// Whether this range contains the given offset.
    pub fn contains(&self, offset: u64) -> bool {
        offset >= self.min && offset <= self.max
    }

    /// Whether this range overlaps with another.
    pub fn overlaps(&self, other: &Self) -> bool {
        self.min <= other.max && other.min <= self.max
    }
}

// ---------------------------------------------------------------------------
// TraceMemoryFlag
// ---------------------------------------------------------------------------

/// Flags for memory regions, ported from Ghidra's `TraceMemoryFlag`.
///
/// Each flag corresponds to a bit in the Java `MemoryBlock` constants:
/// READ, WRITE, EXECUTE, VOLATILE.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum TraceMemoryFlag {
    /// Region is readable.
    Read,
    /// Region is writable.
    Write,
    /// Region is executable.
    Execute,
    /// Region is volatile (e.g., memory-mapped I/O).
    Volatile,
}

impl TraceMemoryFlag {
    /// The bit mask for this flag (matching Java's `MemoryBlock` constants).
    pub fn bits(&self) -> u8 {
        match self {
            TraceMemoryFlag::Read => 0x01,
            TraceMemoryFlag::Write => 0x02,
            TraceMemoryFlag::Execute => 0x04,
            TraceMemoryFlag::Volatile => 0x08,
        }
    }

    /// Convert a bit mask to a set of flags.
    pub fn from_bits(mask: u8) -> BTreeSet<TraceMemoryFlag> {
        let mut flags = BTreeSet::new();
        for f in &[
            TraceMemoryFlag::Read,
            TraceMemoryFlag::Write,
            TraceMemoryFlag::Execute,
            TraceMemoryFlag::Volatile,
        ] {
            if mask & f.bits() != 0 {
                flags.insert(*f);
            }
        }
        flags
    }

    /// Convert a set of flags to a bit mask.
    pub fn to_bits(flags: &BTreeSet<TraceMemoryFlag>) -> u8 {
        flags.iter().fold(0u8, |acc, f| acc | f.bits())
    }

    /// All flag variants.
    pub fn all() -> &'static [TraceMemoryFlag] {
        &[
            TraceMemoryFlag::Read,
            TraceMemoryFlag::Write,
            TraceMemoryFlag::Execute,
            TraceMemoryFlag::Volatile,
        ]
    }
}

// ---------------------------------------------------------------------------
// MemoryRegionPermissions
// ---------------------------------------------------------------------------

/// Access permissions for a memory region.
///
/// Ported from Ghidra's region permission flags. This is a convenience
/// wrapper that maps directly to the `TraceMemoryFlag` Read/Write/Execute
/// flags; Volatile is tracked separately on the entry.
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

    /// Convert to a `BTreeSet<TraceMemoryFlag>`.
    pub fn to_flags(&self) -> BTreeSet<TraceMemoryFlag> {
        let mut flags = BTreeSet::new();
        if self.read {
            flags.insert(TraceMemoryFlag::Read);
        }
        if self.write {
            flags.insert(TraceMemoryFlag::Write);
        }
        if self.execute {
            flags.insert(TraceMemoryFlag::Execute);
        }
        flags
    }

    /// Create from a `BTreeSet<TraceMemoryFlag>`.
    pub fn from_flags(flags: &BTreeSet<TraceMemoryFlag>) -> Self {
        Self {
            read: flags.contains(&TraceMemoryFlag::Read),
            write: flags.contains(&TraceMemoryFlag::Write),
            execute: flags.contains(&TraceMemoryFlag::Execute),
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

/// A snap-indexed value entry for properties that change over time.
///
/// Ported from the object-tree model in Ghidra where attributes have
/// per-lifespan values. Each `SnapValue` associates a value with the
/// snap from which it becomes active.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapValue<T> {
    /// The snap from which this value becomes active (inclusive).
    pub snap: i64,
    /// The value.
    pub value: T,
}

/// An enhanced memory region entry for the debug trace.
///
/// Ported from Ghidra's `DBTraceMemoryRegion`. Each region lives in a
/// specific address space, has a bounded range of offsets, permissions,
/// a lifespan, and optional mapping metadata (e.g., file offset for
/// loaded modules).
///
/// Supports snap-based property history for name, range, and flags
/// (matching the Java object-tree model where these are per-lifespan
/// attributes).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceMemoryRegionEntry {
    /// Unique key identifying this region.
    pub key: i64,
    /// The object path (e.g., "MemoryRegions[0]").
    pub path: String,
    /// The current display name (e.g., ".text", ".data", "[heap]").
    pub name: String,
    /// Name history (snap -> name).
    name_history: Vec<SnapValue<String>>,
    /// The address space this region belongs to (e.g., "ram", "register").
    pub space: String,
    /// Current start offset within the address space.
    pub min_address: u64,
    /// Current end offset within the address space (inclusive).
    pub max_address: u64,
    /// Range history (snap -> (min, max)).
    range_history: Vec<SnapValue<(u64, u64)>>,
    /// Current access permissions.
    pub permissions: MemoryRegionPermissions,
    /// Current flags as a set (superset of permissions).
    flags: BTreeSet<TraceMemoryFlag>,
    /// Flag history (snap -> flags).
    flag_history: Vec<SnapValue<BTreeSet<TraceMemoryFlag>>>,
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
        let name_str = name.into();
        let perms = MemoryRegionPermissions::default();
        let mut flags = BTreeSet::new();
        flags.insert(TraceMemoryFlag::Read);
        flags.insert(TraceMemoryFlag::Write);
        flags.insert(TraceMemoryFlag::Execute);
        let snap = lifespan.lmin();
        Self {
            key,
            path: path.into(),
            name: name_str.clone(),
            name_history: vec![SnapValue {
                snap,
                value: name_str,
            }],
            space: space.into(),
            min_address,
            max_address,
            range_history: vec![SnapValue {
                snap,
                value: (min_address, max_address),
            }],
            permissions: perms,
            flags: flags.clone(),
            flag_history: vec![SnapValue {
                snap,
                value: flags,
            }],
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
        self.flags = perms.to_flags();
        // Also update the flag history entry for the initial snap.
        if let Some(last) = self.flag_history.last_mut() {
            last.value = self.flags.clone();
        }
        self
    }

    /// Mark as volatile.
    pub fn with_volatile(mut self, volatile: bool) -> Self {
        if volatile {
            self.flags.insert(TraceMemoryFlag::Volatile);
        } else {
            self.flags.remove(&TraceMemoryFlag::Volatile);
        }
        // Also update the flag history entry for the initial snap.
        if let Some(last) = self.flag_history.last_mut() {
            last.value = self.flags.clone();
        }
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

    // -----------------------------------------------------------------------
    // Snap-based name operations (ported from Java TraceMemoryRegion)
    // -----------------------------------------------------------------------

    /// Set the display name, effective for the given lifespan.
    ///
    /// Ported from `TraceMemoryRegion.setName(Lifespan, String)`.
    /// Sets the name to apply from `lifespan.lmin()` onward.
    pub fn set_name_lifespan(&mut self, lifespan: &Lifespan, name: impl Into<String>) {
        self.set_name(lifespan.lmin(), name);
    }

    /// Set the display name, effective from `snap` onward.
    ///
    /// Ported from `TraceMemoryRegion.setName(long, String)`.
    pub fn set_name(&mut self, snap: i64, name: impl Into<String>) {
        let name_str = name.into();
        self.name = name_str.clone();
        self.name_history.push(SnapValue {
            snap,
            value: name_str,
        });
    }

    /// Get the display name at the given `snap`.
    ///
    /// Returns the most recent name set at or before `snap`.
    /// Ported from `TraceMemoryRegion.getName(long)`.
    pub fn get_name(&self, snap: i64) -> &str {
        self.name_history
            .iter()
            .rev()
            .find(|sv| sv.snap <= snap)
            .map(|sv| sv.value.as_str())
            .unwrap_or(&self.name)
    }

    /// The name history.
    pub fn name_history(&self) -> &[SnapValue<String>] {
        &self.name_history
    }

    // -----------------------------------------------------------------------
    // Snap-based range operations (ported from Java TraceMemoryRegion)
    // -----------------------------------------------------------------------

    /// Set the address range, effective for the given lifespan.
    ///
    /// Ported from `TraceMemoryRegion.setRange(Lifespan, AddressRange)`.
    /// Sets the range to apply from `lifespan.lmin()` onward.
    pub fn set_range_lifespan(&mut self, lifespan: &Lifespan, min_address: u64, max_address: u64) {
        self.set_range(lifespan.lmin(), min_address, max_address);
    }

    /// Set the address range, effective from `snap` onward.
    ///
    /// Ported from `TraceMemoryRegion.setRange(long, AddressRange)`.
    pub fn set_range(&mut self, snap: i64, min_address: u64, max_address: u64) {
        self.min_address = min_address;
        self.max_address = max_address;
        self.range_history.push(SnapValue {
            snap,
            value: (min_address, max_address),
        });
    }

    /// Get the address range at the given `snap`.
    ///
    /// Returns `(min, max)` for the range effective at `snap`.
    /// Ported from `TraceMemoryRegion.getRange(long)`.
    pub fn get_range(&self, snap: i64) -> (u64, u64) {
        self.range_history
            .iter()
            .rev()
            .find(|sv| sv.snap <= snap)
            .map(|sv| sv.value)
            .unwrap_or((self.min_address, self.max_address))
    }

    /// Set the minimum address, effective from `snap` onward.
    ///
    /// Ported from `TraceMemoryRegion.setMinAddress(long, Address)`.
    pub fn set_min_address(&mut self, snap: i64, min: u64) {
        let max = self.max_address;
        self.set_range(snap, min, max);
    }

    /// Get the minimum address at the given `snap`.
    ///
    /// Ported from `TraceMemoryRegion.getMinAddress(long)`.
    pub fn get_min_address(&self, snap: i64) -> u64 {
        self.get_range(snap).0
    }

    /// Set the maximum address, effective from `snap` onward.
    ///
    /// Ported from `TraceMemoryRegion.setMaxAddress(long, Address)`.
    pub fn set_max_address(&mut self, snap: i64, max: u64) {
        let min = self.min_address;
        self.set_range(snap, min, max);
    }

    /// Get the maximum address at the given `snap`.
    ///
    /// Ported from `TraceMemoryRegion.getMaxAddress(long)`.
    pub fn get_max_address(&self, snap: i64) -> u64 {
        self.get_range(snap).1
    }

    /// Set the length of the region, adjusting the max address.
    ///
    /// Ported from `TraceMemoryRegion.setLength(long, long)`.
    pub fn set_length(&mut self, snap: i64, length: u64) {
        let (min, _) = self.get_range(snap);
        self.set_range(snap, min, min + length - 1);
    }

    /// Get the length of the region at the given `snap`.
    ///
    /// Ported from `TraceMemoryRegion.getLength(long)`.
    pub fn get_length(&self, snap: i64) -> u64 {
        let (min, max) = self.get_range(snap);
        max - min + 1
    }

    /// The range history.
    pub fn range_history(&self) -> &[SnapValue<(u64, u64)>] {
        &self.range_history
    }

    // -----------------------------------------------------------------------
    // Snap-based flag operations (ported from Java TraceMemoryRegion)
    // -----------------------------------------------------------------------

    /// Set the complete flag set, effective for the given lifespan.
    ///
    /// Ported from `TraceMemoryRegion.setFlags(Lifespan, Collection)`.
    /// Sets flags from `lifespan.lmin()` onward.
    pub fn set_flags_lifespan(&mut self, lifespan: &Lifespan, flags: BTreeSet<TraceMemoryFlag>) {
        self.set_flags(lifespan.lmin(), flags);
    }

    /// Set the complete flag set, effective from `snap` onward.
    ///
    /// Ported from `TraceMemoryRegion.setFlags(long, Collection)`.
    pub fn set_flags(&mut self, snap: i64, flags: BTreeSet<TraceMemoryFlag>) {
        self.permissions = MemoryRegionPermissions::from_flags(&flags);
        self.flags = flags.clone();
        self.flag_history.push(SnapValue { snap, value: flags });
    }

    /// Add flags to the current set, effective for the given lifespan.
    ///
    /// Ported from `TraceMemoryRegion.addFlags(Lifespan, Collection)`.
    pub fn add_flags_lifespan(&mut self, lifespan: &Lifespan, new_flags: &BTreeSet<TraceMemoryFlag>) {
        self.add_flags(lifespan.lmin(), new_flags);
    }

    /// Add flags to the current set, effective from `snap` onward.
    ///
    /// Ported from `TraceMemoryRegion.addFlags(long, Collection)`.
    pub fn add_flags(&mut self, snap: i64, new_flags: &BTreeSet<TraceMemoryFlag>) {
        for f in new_flags {
            self.flags.insert(*f);
        }
        self.permissions = MemoryRegionPermissions::from_flags(&self.flags);
        self.flag_history
            .push(SnapValue {
                snap,
                value: self.flags.clone(),
            });
    }

    /// Clear flags from the current set, effective for the given lifespan.
    ///
    /// Ported from `TraceMemoryRegion.clearFlags(Lifespan, Collection)`.
    pub fn clear_flags_lifespan(&mut self, lifespan: &Lifespan, to_clear: &BTreeSet<TraceMemoryFlag>) {
        self.clear_flags(lifespan.lmin(), to_clear);
    }

    /// Clear flags from the current set, effective from `snap` onward.
    ///
    /// Ported from `TraceMemoryRegion.clearFlags(long, Collection)`.
    pub fn clear_flags(&mut self, snap: i64, to_clear: &BTreeSet<TraceMemoryFlag>) {
        for f in to_clear {
            self.flags.remove(f);
        }
        self.permissions = MemoryRegionPermissions::from_flags(&self.flags);
        self.flag_history
            .push(SnapValue {
                snap,
                value: self.flags.clone(),
            });
    }

    /// Get the flags effective at the given `snap`.
    ///
    /// Ported from `TraceMemoryRegion.getFlags(long)`.
    pub fn get_flags(&self, snap: i64) -> &BTreeSet<TraceMemoryFlag> {
        self.flag_history
            .iter()
            .rev()
            .find(|sv| sv.snap <= snap)
            .map(|sv| &sv.value)
            .unwrap_or(&self.flags)
    }

    /// Set or clear the Read flag at `snap`.
    ///
    /// Ported from `TraceMemoryRegion.setRead(long, boolean)`.
    pub fn set_read(&mut self, snap: i64, read: bool) {
        if read {
            let mut new_flags = self.flags.clone();
            new_flags.insert(TraceMemoryFlag::Read);
            self.add_flags(snap, &BTreeSet::from([TraceMemoryFlag::Read]));
        } else {
            self.clear_flags(snap, &BTreeSet::from([TraceMemoryFlag::Read]));
        }
    }

    /// Set or clear the Write flag at `snap`.
    ///
    /// Ported from `TraceMemoryRegion.setWrite(long, boolean)`.
    pub fn set_write(&mut self, snap: i64, write: bool) {
        if write {
            self.add_flags(snap, &BTreeSet::from([TraceMemoryFlag::Write]));
        } else {
            self.clear_flags(snap, &BTreeSet::from([TraceMemoryFlag::Write]));
        }
    }

    /// Set or clear the Execute flag at `snap`.
    ///
    /// Ported from `TraceMemoryRegion.setExecute(long, boolean)`.
    pub fn set_execute(&mut self, snap: i64, execute: bool) {
        if execute {
            self.add_flags(snap, &BTreeSet::from([TraceMemoryFlag::Execute]));
        } else {
            self.clear_flags(snap, &BTreeSet::from([TraceMemoryFlag::Execute]));
        }
    }

    /// Set or clear the Volatile flag at `snap`.
    ///
    /// Ported from `TraceMemoryRegion.setVolatile(long, boolean)`.
    pub fn set_volatile(&mut self, snap: i64, volatile: bool) {
        if volatile {
            self.add_flags(snap, &BTreeSet::from([TraceMemoryFlag::Volatile]));
        } else {
            self.clear_flags(snap, &BTreeSet::from([TraceMemoryFlag::Volatile]));
        }
    }

    /// Check if the Read flag is set at `snap`.
    ///
    /// Ported from `TraceMemoryRegion.isRead(long)`.
    pub fn is_read_at(&self, snap: i64) -> bool {
        self.get_flags(snap).contains(&TraceMemoryFlag::Read)
    }

    /// Check if the Write flag is set at `snap`.
    ///
    /// Ported from `TraceMemoryRegion.isWrite(long)`.
    pub fn is_write_at(&self, snap: i64) -> bool {
        self.get_flags(snap).contains(&TraceMemoryFlag::Write)
    }

    /// Check if the Execute flag is set at `snap`.
    ///
    /// Ported from `TraceMemoryRegion.isExecute(long)`.
    pub fn is_execute_at(&self, snap: i64) -> bool {
        self.get_flags(snap).contains(&TraceMemoryFlag::Execute)
    }

    /// Check if the Volatile flag is set at `snap`.
    ///
    /// Ported from `TraceMemoryRegion.isVolatile(long)`.
    pub fn is_volatile_at(&self, snap: i64) -> bool {
        self.get_flags(snap).contains(&TraceMemoryFlag::Volatile)
    }

    /// The current flags set.
    pub fn flags(&self) -> &BTreeSet<TraceMemoryFlag> {
        &self.flags
    }

    /// The flag history.
    pub fn flag_history(&self) -> &[SnapValue<BTreeSet<TraceMemoryFlag>>] {
        &self.flag_history
    }

    // -----------------------------------------------------------------------
    // Lifecycle (ported from Java TraceMemoryRegion)
    // -----------------------------------------------------------------------

    /// Delete this region entirely (clear all history, mark lifespan as
    /// empty).
    ///
    /// Ported from `TraceMemoryRegion.delete()`.
    pub fn delete(&mut self) {
        self.lifespan = Lifespan::EMPTY;
        self.name_history.clear();
        self.range_history.clear();
        self.flag_history.clear();
    }

    /// End this region's life at the given snap.
    ///
    /// Ported from `TraceMemoryRegion.remove(long)`.
    pub fn remove(&mut self, snap: i64) {
        self.lifespan = self.lifespan.with_max(snap);
    }

    // -----------------------------------------------------------------------
    // Query helpers
    // -----------------------------------------------------------------------

    /// Size of this region in bytes (current values).
    pub fn size(&self) -> u64 {
        self.max_address - self.min_address + 1
    }

    /// Whether this region is valid at `snap`.
    ///
    /// Ported from `TraceMemoryRegion.isValid(long)`.
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

    /// Whether the given offset falls within this region (current range).
    pub fn contains_offset(&self, offset: u64) -> bool {
        offset >= self.min_address && offset <= self.max_address
    }

    /// Whether the given offset falls within this region at `snap`.
    pub fn contains_offset_at(&self, offset: u64, snap: i64) -> bool {
        let (min, max) = self.get_range(snap);
        offset >= min && offset <= max
    }

    /// Whether this region overlaps with another (current ranges).
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

    /// Delete a region by key (call `delete()` on the region before removing).
    ///
    /// Ported from `DBTraceMemoryRegion.delete()`.
    pub fn delete_region(&mut self, key: i64) -> Option<TraceMemoryRegionEntry> {
        if let Some(region) = self.regions.get_mut(&key) {
            region.delete();
        }
        self.regions.remove(&key)
    }

    /// End a region's life at `snap` (call `remove(snap)` on the region).
    ///
    /// Ported from `DBTraceMemoryRegion.remove(long)`.
    pub fn remove_region_at(&mut self, key: i64, snap: i64) -> bool {
        if let Some(region) = self.regions.get_mut(&key) {
            region.remove(snap);
            true
        } else {
            false
        }
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
    ///
    /// Uses snap-based range lookup when available.
    pub fn region_containing(
        &self,
        space: &str,
        offset: u64,
        snap: i64,
    ) -> Option<&TraceMemoryRegionEntry> {
        self.regions.values().find(|r| {
            r.space == space && r.is_valid_at(snap) && r.contains_offset_at(offset, snap)
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
            .map(|r| MemoryRegionPermissions::from_flags(r.get_flags(snap)))
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

    /// Get the flags at a specific offset in a space at `snap`.
    pub fn flags_at(
        &self,
        space: &str,
        offset: u64,
        snap: i64,
    ) -> Option<&BTreeSet<TraceMemoryFlag>> {
        self.region_containing(space, offset, snap)
            .map(|r| r.get_flags(snap))
    }

    /// Whether the manager has no regions.
    pub fn is_empty(&self) -> bool {
        self.regions.is_empty()
    }

    /// Find all regions with the given name at `snap`.
    ///
    /// Ported from region lookup by display name in `DBTraceMemoryManager`.
    pub fn find_regions_by_name(&self, name: &str, snap: i64) -> Vec<&TraceMemoryRegionEntry> {
        self.regions
            .values()
            .filter(|r| r.is_valid_at(snap) && r.get_name(snap) == name)
            .collect()
    }

    /// Find all regions in a space that overlap the given range at `snap`.
    ///
    /// Ported from `DBTraceMemoryManager.getRegionsContaining(AddressRange, long)`.
    pub fn regions_overlapping_range(
        &self,
        space: &str,
        min: u64,
        max: u64,
        snap: i64,
    ) -> Vec<&TraceMemoryRegionEntry> {
        self.regions
            .values()
            .filter(|r| {
                r.space == space
                    && r.is_valid_at(snap)
                    && {
                        let (rmin, rmax) = r.get_range(snap);
                        rmin <= max && min <= rmax
                    }
            })
            .collect()
    }

    /// Get all regions sorted by their minimum address in a space at `snap`.
    pub fn regions_sorted_by_address(
        &self,
        space: &str,
        snap: i64,
    ) -> Vec<&TraceMemoryRegionEntry> {
        let mut regions = self.regions_in_space_at(space, snap);
        regions.sort_by_key(|r| r.get_min_address(snap));
        regions
    }

    /// Find the region with the largest minimum address in a space at `snap`.
    ///
    /// Useful for determining the upper bound of mapped memory.
    pub fn highest_region_in_space(
        &self,
        space: &str,
        snap: i64,
    ) -> Option<&TraceMemoryRegionEntry> {
        self.regions
            .values()
            .filter(|r| r.space == space && r.is_valid_at(snap))
            .max_by_key(|r| r.get_min_address(snap))
    }

    /// Find all regions in a space that are marked as executable at `snap`.
    pub fn executable_regions_at(
        &self,
        space: &str,
        snap: i64,
    ) -> Vec<&TraceMemoryRegionEntry> {
        self.regions
            .values()
            .filter(|r| r.space == space && r.is_valid_at(snap) && r.is_execute_at(snap))
            .collect()
    }

    /// Find all regions in a space that are marked as writable at `snap`.
    pub fn writable_regions_at(
        &self,
        space: &str,
        snap: i64,
    ) -> Vec<&TraceMemoryRegionEntry> {
        self.regions
            .values()
            .filter(|r| r.space == space && r.is_valid_at(snap) && r.is_write_at(snap))
            .collect()
    }

    /// Find all regions across all spaces that are alive at `snap`.
    pub fn all_regions_at(&self, snap: i64) -> Vec<&TraceMemoryRegionEntry> {
        self.regions
            .values()
            .filter(|r| r.is_valid_at(snap))
            .collect()
    }

    /// Delete all regions in the manager.
    ///
    /// Ported from clearing all memory regions in `DBTraceMemoryManager`.
    pub fn clear(&mut self) {
        self.regions.clear();
    }

    // -----------------------------------------------------------------------
    // Path-based lookup (ported from TraceMemoryManager.getLiveRegionByPath)
    // -----------------------------------------------------------------------

    /// Get a region by its path at the given snap.
    ///
    /// Ported from `TraceMemoryManager.getLiveRegionByPath(long, String)`.
    /// Returns the region whose path matches and which is valid at `snap`.
    pub fn get_region_by_path(&self, snap: i64, path: &str) -> Option<&TraceMemoryRegionEntry> {
        self.regions
            .values()
            .find(|r| r.path == path && r.is_valid_at(snap))
    }

    /// Get a mutable region by its path at the given snap.
    pub fn get_region_by_path_mut(
        &mut self,
        snap: i64,
        path: &str,
    ) -> Option<&mut TraceMemoryRegionEntry> {
        self.regions
            .values_mut()
            .find(|r| r.path == path && r.is_valid_at(snap))
    }

    // -----------------------------------------------------------------------
    // Overlap-checked add (ported from TraceMemoryManager.addRegion)
    // -----------------------------------------------------------------------

    /// Add a region with overlap validation.
    ///
    /// Ported from `TraceMemoryManager.addRegion(String, Lifespan, AddressRange, Collection)`.
    /// If the new region would overlap an existing region in the same space
    /// and overlapping lifespan, returns `Err` with the conflicting keys.
    pub fn add_region_checked(
        &mut self,
        mut region: TraceMemoryRegionEntry,
    ) -> Result<i64, TraceOverlappedRegionException> {
        // Check for overlaps with existing regions in the same space
        let conflicts: Vec<i64> = self
            .regions
            .values()
            .filter(|r| {
                r.space == region.space
                    && r.lifespan.intersects(&region.lifespan)
                    && r.min_address <= region.max_address
                    && region.min_address <= r.max_address
            })
            .map(|r| r.key)
            .collect();

        if !conflicts.is_empty() {
            return Err(TraceOverlappedRegionException::new(conflicts));
        }

        let key = self.next_key;
        self.next_key += 1;
        region.key = key;
        self.regions.insert(key, region);
        Ok(key)
    }

    /// Create a new region (convenience for `add_region_checked`).
    ///
    /// Ported from `TraceMemoryManager.createRegion(String, long, AddressRange, Collection)`.
    pub fn create_region(
        &mut self,
        path: impl Into<String>,
        name: impl Into<String>,
        space: impl Into<String>,
        min_address: u64,
        max_address: u64,
        snap: i64,
        flags: BTreeSet<TraceMemoryFlag>,
    ) -> Result<i64, TraceOverlappedRegionException> {
        let lifespan = Lifespan::now_on(snap);
        let region = TraceMemoryRegionEntry::new(
            0, // will be overwritten
            path,
            name,
            space,
            min_address,
            max_address,
            lifespan,
        )
        .with_permissions(MemoryRegionPermissions::from_flags(&flags));
        self.add_region_checked(region)
    }

    // -----------------------------------------------------------------------
    // Address set (ported from TraceMemoryManager.getRegionsAddressSet)
    // -----------------------------------------------------------------------

    /// Get the union of all region address ranges at the given snap.
    ///
    /// Ported from `TraceMemoryManager.getRegionsAddressSet(long)`.
    /// Returns a sorted, merged list of `(min, max)` ranges.
    pub fn get_regions_address_set(&self, snap: i64) -> Vec<(u64, u64)> {
        let mut ranges: Vec<(u64, u64)> = self
            .regions
            .values()
            .filter(|r| r.is_valid_at(snap))
            .map(|r| r.get_range(snap))
            .collect();
        ranges.sort_by_key(|&(min, _)| min);

        // Merge overlapping/adjacent ranges
        let mut merged: Vec<(u64, u64)> = Vec::new();
        for (min, max) in ranges {
            if let Some(last) = merged.last_mut() {
                if min <= last.1 + 1 {
                    last.1 = last.1.max(max);
                    continue;
                }
            }
            merged.push((min, max));
        }
        merged
    }

    /// Get the union of all region address ranges in a given space at `snap`.
    ///
    /// Ported from `TraceMemoryManager.getRegionsAddressSet(long)` with
    /// space filtering.
    pub fn get_regions_address_set_in_space(
        &self,
        space: &str,
        snap: i64,
    ) -> Vec<(u64, u64)> {
        let mut ranges: Vec<(u64, u64)> = self
            .regions
            .values()
            .filter(|r| r.space == space && r.is_valid_at(snap))
            .map(|r| r.get_range(snap))
            .collect();
        ranges.sort_by_key(|&(min, _)| min);

        let mut merged: Vec<(u64, u64)> = Vec::new();
        for (min, max) in ranges {
            if let Some(last) = merged.last_mut() {
                if min <= last.1 + 1 {
                    last.1 = last.1.max(max);
                    continue;
                }
            }
            merged.push((min, max));
        }
        merged
    }

    /// Whether a given range is fully covered by regions in a space at `snap`.
    ///
    /// Useful for checking if a memory read would succeed entirely from
    /// mapped regions.
    pub fn is_range_covered(
        &self,
        space: &str,
        min: u64,
        max: u64,
        snap: i64,
    ) -> bool {
        let set = self.get_regions_address_set_in_space(space, snap);
        let mut covered_up_to = min;
        for (rmin, rmax) in &set {
            if *rmin > covered_up_to {
                return false;
            }
            covered_up_to = covered_up_to.max(*rmax + 1);
            if covered_up_to > max {
                return true;
            }
        }
        covered_up_to > max
    }

    /// Get all regions sorted by creation snap (lifespan min).
    pub fn regions_by_creation_order(&self) -> Vec<&TraceMemoryRegionEntry> {
        let mut regions: Vec<&TraceMemoryRegionEntry> = self.regions.values().collect();
        regions.sort_by_key(|r| r.lifespan.lmin());
        regions
    }

    /// Get the total number of bytes mapped across all regions in a space at `snap`.
    pub fn total_mapped_bytes(&self, space: &str, snap: i64) -> u64 {
        self.regions_in_space_at(space, snap)
            .iter()
            .map(|r| r.get_length(snap))
            .sum()
    }

    /// Find all regions that match a predicate at the given snap.
    pub fn find_regions_where(
        &self,
        snap: i64,
        predicate: impl Fn(&TraceMemoryRegionEntry) -> bool,
    ) -> Vec<&TraceMemoryRegionEntry> {
        self.regions
            .values()
            .filter(|r| r.is_valid_at(snap) && predicate(r))
            .collect()
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
    fn test_permissions_to_from_flags() {
        let perms = MemoryRegionPermissions::RX;
        let flags = perms.to_flags();
        assert!(flags.contains(&TraceMemoryFlag::Read));
        assert!(!flags.contains(&TraceMemoryFlag::Write));
        assert!(flags.contains(&TraceMemoryFlag::Execute));

        let back = MemoryRegionPermissions::from_flags(&flags);
        assert_eq!(back, perms);
    }

    #[test]
    fn test_memory_flag_bits() {
        assert_eq!(TraceMemoryFlag::Read.bits(), 0x01);
        assert_eq!(TraceMemoryFlag::Write.bits(), 0x02);
        assert_eq!(TraceMemoryFlag::Execute.bits(), 0x04);
        assert_eq!(TraceMemoryFlag::Volatile.bits(), 0x08);

        let mask = TraceMemoryFlag::to_bits(&BTreeSet::from([
            TraceMemoryFlag::Read,
            TraceMemoryFlag::Execute,
        ]));
        assert_eq!(mask, 0x05);

        let flags = TraceMemoryFlag::from_bits(0x05);
        assert!(flags.contains(&TraceMemoryFlag::Read));
        assert!(!flags.contains(&TraceMemoryFlag::Write));
        assert!(flags.contains(&TraceMemoryFlag::Execute));
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
        assert!(!r.is_volatile_at(0));
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
    fn test_region_delete() {
        let mut r = TraceMemoryRegionEntry::new(
            0, "R[0]", ".text", "ram", 0x100, 0x1FF, Lifespan::now_on(0),
        );
        r.delete();
        assert_eq!(r.lifespan, Lifespan::EMPTY);
        assert!(r.name_history().is_empty());
        assert!(r.range_history().is_empty());
        assert!(r.flag_history().is_empty());
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
    fn test_region_contains_offset_at() {
        let mut r = TraceMemoryRegionEntry::new(
            0, "R[0]", ".text", "ram", 0x100, 0x1FF, Lifespan::now_on(0),
        );
        // Change range at snap 10
        r.set_range(10, 0x200, 0x2FF);
        // At snap 0, range is 0x100..0x1FF
        assert!(r.contains_offset_at(0x180, 0));
        assert!(!r.contains_offset_at(0x250, 0));
        // At snap 10, range is 0x200..0x2FF
        assert!(r.contains_offset_at(0x250, 10));
        assert!(!r.contains_offset_at(0x180, 10));
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

    // -----------------------------------------------------------------------
    // Snap-based name tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_region_snap_name() {
        let mut r = TraceMemoryRegionEntry::new(
            0, "R[0]", ".text", "ram", 0x100, 0x1FF, Lifespan::now_on(0),
        );
        assert_eq!(r.get_name(0), ".text");
        r.set_name(10, ".text_v2");
        assert_eq!(r.get_name(5), ".text");
        assert_eq!(r.get_name(10), ".text_v2");
        assert_eq!(r.get_name(100), ".text_v2");
    }

    // -----------------------------------------------------------------------
    // Snap-based range tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_region_snap_range() {
        let mut r = TraceMemoryRegionEntry::new(
            0, "R[0]", ".text", "ram", 0x400000, 0x400FFF, Lifespan::now_on(0),
        );
        assert_eq!(r.get_range(0), (0x400000, 0x400FFF));
        assert_eq!(r.get_length(0), 0x1000);
        assert_eq!(r.get_min_address(0), 0x400000);
        assert_eq!(r.get_max_address(0), 0x400FFF);

        r.set_range(10, 0x500000, 0x500FFF);
        assert_eq!(r.get_range(5), (0x400000, 0x400FFF));
        assert_eq!(r.get_range(10), (0x500000, 0x500FFF));
    }

    #[test]
    fn test_region_set_length() {
        let mut r = TraceMemoryRegionEntry::new(
            0, "R[0]", ".text", "ram", 0x400000, 0x400FFF, Lifespan::now_on(0),
        );
        r.set_length(5, 0x2000);
        assert_eq!(r.get_range(5), (0x400000, 0x401FFF));
        assert_eq!(r.get_length(5), 0x2000);
    }

    // -----------------------------------------------------------------------
    // Snap-based flag tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_region_snap_flags() {
        let mut r = TraceMemoryRegionEntry::new(
            0, "R[0]", ".text", "ram", 0x100, 0x1FF, Lifespan::now_on(0),
        );
        // Default: RWX
        assert!(r.is_read_at(0));
        assert!(r.is_write_at(0));
        assert!(r.is_execute_at(0));

        // Change to RX at snap 10
        r.set_flags(
            10,
            BTreeSet::from([TraceMemoryFlag::Read, TraceMemoryFlag::Execute]),
        );
        assert!(r.is_read_at(5));
        assert!(r.is_write_at(5));
        assert!(r.is_read_at(10));
        assert!(!r.is_write_at(10));
        assert!(r.is_execute_at(10));
    }

    #[test]
    fn test_region_set_read_write_execute() {
        let mut r = TraceMemoryRegionEntry::new(
            0, "R[0]", ".text", "ram", 0x100, 0x1FF, Lifespan::now_on(0),
        );
        r.set_write(5, false);
        assert!(!r.is_write_at(5));
        assert!(r.is_read_at(5));

        r.set_execute(10, false);
        assert!(!r.is_execute_at(10));
        assert!(!r.is_write_at(10));
        assert!(r.is_read_at(10));
    }

    #[test]
    fn test_region_set_volatile() {
        let mut r = TraceMemoryRegionEntry::new(
            0, "R[0]", "mmio", "ram", 0x100, 0x1FF, Lifespan::now_on(0),
        );
        assert!(!r.is_volatile_at(0));
        r.set_volatile(5, true);
        assert!(r.is_volatile_at(5));
        r.set_volatile(10, false);
        assert!(!r.is_volatile_at(10));
    }

    // -----------------------------------------------------------------------
    // Manager lifecycle tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_region_manager_delete() {
        let mut mgr = TraceMemoryRegionManager::new();
        let k = mgr.add_region(TraceMemoryRegionEntry::new(
            0, "", ".text", "ram", 0x400000, 0x400FFF, Lifespan::now_on(0),
        ));
        assert_eq!(mgr.region_count(), 1);
        mgr.delete_region(k);
        assert_eq!(mgr.region_count(), 0);
    }

    #[test]
    fn test_region_manager_remove_at() {
        let mut mgr = TraceMemoryRegionManager::new();
        let k = mgr.add_region(TraceMemoryRegionEntry::new(
            0, "", ".text", "ram", 0x400000, 0x400FFF, Lifespan::now_on(0),
        ));
        assert!(mgr.remove_region_at(k, 10));
        let r = mgr.region(k).unwrap();
        assert!(r.is_valid_at(10));
        assert!(!r.is_valid_at(11));
    }

    #[test]
    fn test_region_manager_flags_at() {
        let mut mgr = TraceMemoryRegionManager::new();
        mgr.add_region(
            TraceMemoryRegionEntry::new(
                0, "", ".text", "ram", 0x400000, 0x400FFF, Lifespan::now_on(0),
            )
            .with_permissions(MemoryRegionPermissions::RX),
        );

        let flags = mgr.flags_at("ram", 0x400500, 0).unwrap();
        assert!(flags.contains(&TraceMemoryFlag::Read));
        assert!(!flags.contains(&TraceMemoryFlag::Write));
        assert!(flags.contains(&TraceMemoryFlag::Execute));
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

    // -----------------------------------------------------------------------
    // Lifespan-based operations tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_region_set_name_lifespan() {
        let mut r = TraceMemoryRegionEntry::new(
            0, "R[0]", ".text", "ram", 0x100, 0x1FF, Lifespan::now_on(0),
        );
        r.set_name_lifespan(&Lifespan::span(5, 20), ".text_v2");
        assert_eq!(r.get_name(0), ".text");
        assert_eq!(r.get_name(5), ".text_v2");
        assert_eq!(r.get_name(20), ".text_v2");
    }

    #[test]
    fn test_region_set_range_lifespan() {
        let mut r = TraceMemoryRegionEntry::new(
            0, "R[0]", ".text", "ram", 0x100, 0x1FF, Lifespan::now_on(0),
        );
        r.set_range_lifespan(&Lifespan::span(5, 20), 0x200, 0x2FF);
        assert_eq!(r.get_range(0), (0x100, 0x1FF));
        assert_eq!(r.get_range(5), (0x200, 0x2FF));
    }

    #[test]
    fn test_region_set_flags_lifespan() {
        let mut r = TraceMemoryRegionEntry::new(
            0, "R[0]", ".text", "ram", 0x100, 0x1FF, Lifespan::now_on(0),
        );
        let rx = BTreeSet::from([TraceMemoryFlag::Read, TraceMemoryFlag::Execute]);
        r.set_flags_lifespan(&Lifespan::span(5, 20), rx);
        assert!(r.is_write_at(0)); // before lifespan
        assert!(!r.is_write_at(5));
        assert!(r.is_read_at(5));
        assert!(r.is_execute_at(5));
    }

    #[test]
    fn test_region_add_flags_lifespan() {
        let mut r = TraceMemoryRegionEntry::new(
            0, "R[0]", "mmio", "ram", 0x100, 0x1FF, Lifespan::now_on(0),
        );
        // Default has RWX, now add volatile from snap 5
        let vol = BTreeSet::from([TraceMemoryFlag::Volatile]);
        r.add_flags_lifespan(&Lifespan::span(5, 20), &vol);
        assert!(!r.is_volatile_at(0));
        assert!(r.is_volatile_at(5));
    }

    #[test]
    fn test_region_clear_flags_lifespan() {
        let mut r = TraceMemoryRegionEntry::new(
            0, "R[0]", ".text", "ram", 0x100, 0x1FF, Lifespan::now_on(0),
        );
        let write = BTreeSet::from([TraceMemoryFlag::Write]);
        r.clear_flags_lifespan(&Lifespan::span(5, 20), &write);
        assert!(r.is_write_at(0));
        assert!(!r.is_write_at(5));
    }

    // -----------------------------------------------------------------------
    // Manager extended tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_region_manager_is_empty() {
        let mut mgr = TraceMemoryRegionManager::new();
        assert!(mgr.is_empty());
        mgr.add_region(TraceMemoryRegionEntry::new(
            0, "", ".text", "ram", 0x400000, 0x400FFF, Lifespan::now_on(0),
        ));
        assert!(!mgr.is_empty());
    }

    #[test]
    fn test_region_manager_find_by_name() {
        let mut mgr = TraceMemoryRegionManager::new();
        mgr.add_region(TraceMemoryRegionEntry::new(
            0, "", ".text", "ram", 0x400000, 0x400FFF, Lifespan::now_on(0),
        ));
        mgr.add_region(TraceMemoryRegionEntry::new(
            1, "", ".text", "ram", 0x500000, 0x500FFF, Lifespan::now_on(0),
        ));
        mgr.add_region(TraceMemoryRegionEntry::new(
            2, "", ".data", "ram", 0x600000, 0x600FFF, Lifespan::now_on(0),
        ));

        let texts = mgr.find_regions_by_name(".text", 0);
        assert_eq!(texts.len(), 2);

        let data = mgr.find_regions_by_name(".data", 0);
        assert_eq!(data.len(), 1);

        let none = mgr.find_regions_by_name(".bss", 0);
        assert_eq!(none.len(), 0);
    }

    #[test]
    fn test_region_manager_overlapping_range() {
        let mut mgr = TraceMemoryRegionManager::new();
        mgr.add_region(TraceMemoryRegionEntry::new(
            0, "", ".text", "ram", 0x400000, 0x400FFF, Lifespan::now_on(0),
        ));
        mgr.add_region(TraceMemoryRegionEntry::new(
            1, "", ".data", "ram", 0x402000, 0x402FFF, Lifespan::now_on(0),
        ));

        // Query range that overlaps .text only
        let regions = mgr.regions_overlapping_range("ram", 0x400F00, 0x401100, 0);
        assert_eq!(regions.len(), 1);
        assert_eq!(regions[0].name, ".text");

        // Query range that overlaps both
        let regions = mgr.regions_overlapping_range("ram", 0x400F00, 0x402100, 0);
        assert_eq!(regions.len(), 2);
    }

    #[test]
    fn test_region_manager_sorted_by_address() {
        let mut mgr = TraceMemoryRegionManager::new();
        mgr.add_region(TraceMemoryRegionEntry::new(
            0, "", ".data", "ram", 0x500000, 0x500FFF, Lifespan::now_on(0),
        ));
        mgr.add_region(TraceMemoryRegionEntry::new(
            1, "", ".text", "ram", 0x400000, 0x400FFF, Lifespan::now_on(0),
        ));

        let sorted = mgr.regions_sorted_by_address("ram", 0);
        assert_eq!(sorted[0].name, ".text");
        assert_eq!(sorted[1].name, ".data");
    }

    #[test]
    fn test_region_manager_highest_region() {
        let mut mgr = TraceMemoryRegionManager::new();
        mgr.add_region(TraceMemoryRegionEntry::new(
            0, "", ".text", "ram", 0x400000, 0x400FFF, Lifespan::now_on(0),
        ));
        mgr.add_region(TraceMemoryRegionEntry::new(
            1, "", ".stack", "ram", 0x7FFF0000, 0x7FFFFFFF, Lifespan::now_on(0),
        ));

        let highest = mgr.highest_region_in_space("ram", 0).unwrap();
        assert_eq!(highest.name, ".stack");
    }

    #[test]
    fn test_region_manager_executable_regions() {
        let mut mgr = TraceMemoryRegionManager::new();
        mgr.add_region(
            TraceMemoryRegionEntry::new(
                0, "", ".text", "ram", 0x400000, 0x400FFF, Lifespan::now_on(0),
            )
            .with_permissions(MemoryRegionPermissions::RX),
        );
        mgr.add_region(
            TraceMemoryRegionEntry::new(
                1, "", ".data", "ram", 0x500000, 0x500FFF, Lifespan::now_on(0),
            )
            .with_permissions(MemoryRegionPermissions::RW),
        );

        let exec = mgr.executable_regions_at("ram", 0);
        assert_eq!(exec.len(), 1);
        assert_eq!(exec[0].name, ".text");
    }

    #[test]
    fn test_region_manager_writable_regions() {
        let mut mgr = TraceMemoryRegionManager::new();
        mgr.add_region(
            TraceMemoryRegionEntry::new(
                0, "", ".text", "ram", 0x400000, 0x400FFF, Lifespan::now_on(0),
            )
            .with_permissions(MemoryRegionPermissions::RX),
        );
        mgr.add_region(
            TraceMemoryRegionEntry::new(
                1, "", ".data", "ram", 0x500000, 0x500FFF, Lifespan::now_on(0),
            )
            .with_permissions(MemoryRegionPermissions::RW),
        );

        let writable = mgr.writable_regions_at("ram", 0);
        assert_eq!(writable.len(), 1);
        assert_eq!(writable[0].name, ".data");
    }

    #[test]
    fn test_region_manager_all_regions_at() {
        let mut mgr = TraceMemoryRegionManager::new();
        mgr.add_region(TraceMemoryRegionEntry::new(
            0, "", ".text", "ram", 0x400000, 0x400FFF, Lifespan::now_on(0),
        ));
        mgr.add_region(TraceMemoryRegionEntry::new(
            1, "", "reg", "register", 0, 0xFF, Lifespan::now_on(0),
        ));

        assert_eq!(mgr.all_regions_at(0).len(), 2);
    }

    #[test]
    fn test_region_manager_clear() {
        let mut mgr = TraceMemoryRegionManager::new();
        mgr.add_region(TraceMemoryRegionEntry::new(
            0, "", ".text", "ram", 0x400000, 0x400FFF, Lifespan::now_on(0),
        ));
        mgr.add_region(TraceMemoryRegionEntry::new(
            1, "", ".data", "ram", 0x500000, 0x500FFF, Lifespan::now_on(0),
        ));
        assert_eq!(mgr.region_count(), 2);
        mgr.clear();
        assert_eq!(mgr.region_count(), 0);
        assert!(mgr.is_empty());
    }

    // -----------------------------------------------------------------------
    // Path-based lookup tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_region_manager_get_by_path() {
        let mut mgr = TraceMemoryRegionManager::new();
        mgr.add_region(TraceMemoryRegionEntry::new(
            0, "MemoryRegions[0]", ".text", "ram", 0x400000, 0x400FFF,
            Lifespan::now_on(0),
        ));
        mgr.add_region(TraceMemoryRegionEntry::new(
            1, "MemoryRegions[1]", ".data", "ram", 0x500000, 0x500FFF,
            Lifespan::now_on(0),
        ));

        let r = mgr.get_region_by_path(0, "MemoryRegions[0]").unwrap();
        assert_eq!(r.name, ".text");
        assert!(mgr.get_region_by_path(0, "MemoryRegions[99]").is_none());
    }

    // -----------------------------------------------------------------------
    // Overlap-checked add tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_region_manager_add_checked_no_overlap() {
        let mut mgr = TraceMemoryRegionManager::new();
        let k0 = mgr.add_region_checked(TraceMemoryRegionEntry::new(
            0, "", ".text", "ram", 0x400000, 0x400FFF, Lifespan::now_on(0),
        ));
        assert!(k0.is_ok());

        // Non-overlapping region should succeed
        let k1 = mgr.add_region_checked(TraceMemoryRegionEntry::new(
            0, "", ".data", "ram", 0x500000, 0x500FFF, Lifespan::now_on(0),
        ));
        assert!(k1.is_ok());
    }

    #[test]
    fn test_region_manager_add_checked_overlap() {
        let mut mgr = TraceMemoryRegionManager::new();
        mgr.add_region_checked(TraceMemoryRegionEntry::new(
            0, "", ".text", "ram", 0x400000, 0x400FFF, Lifespan::now_on(0),
        ))
        .unwrap();

        // Overlapping region should fail
        let result = mgr.add_region_checked(TraceMemoryRegionEntry::new(
            0, "", ".overlap", "ram", 0x400F00, 0x401FFF, Lifespan::now_on(0),
        ));
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.conflicts.len(), 1);
    }

    #[test]
    fn test_region_manager_add_checked_different_space() {
        let mut mgr = TraceMemoryRegionManager::new();
        mgr.add_region_checked(TraceMemoryRegionEntry::new(
            0, "", ".text", "ram", 0x400000, 0x400FFF, Lifespan::now_on(0),
        ))
        .unwrap();

        // Same address range but different space -- should succeed
        let result = mgr.add_region_checked(TraceMemoryRegionEntry::new(
            0, "", "reg", "register", 0x400000, 0x400FFF, Lifespan::now_on(0),
        ));
        assert!(result.is_ok());
    }

    #[test]
    fn test_region_manager_add_checked_different_lifespan() {
        let mut mgr = TraceMemoryRegionManager::new();
        mgr.add_region_checked(TraceMemoryRegionEntry::new(
            0, "", ".text", "ram", 0x400000, 0x400FFF, Lifespan::span(0, 10),
        ))
        .unwrap();

        // Same range but non-overlapping lifespan -- should succeed
        let result = mgr.add_region_checked(TraceMemoryRegionEntry::new(
            0, "", ".text2", "ram", 0x400000, 0x400FFF, Lifespan::span(11, 20),
        ));
        assert!(result.is_ok());
    }

    // -----------------------------------------------------------------------
    // create_region tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_region_manager_create_region() {
        let mut mgr = TraceMemoryRegionManager::new();
        let flags = BTreeSet::from([TraceMemoryFlag::Read, TraceMemoryFlag::Execute]);
        let k = mgr.create_region(
            "MemoryRegions[0]", ".text", "ram", 0x400000, 0x400FFF, 0, flags,
        );
        assert!(k.is_ok());
        let r = mgr.region(k.unwrap()).unwrap();
        assert_eq!(r.name, ".text");
        assert!(r.is_read_at(0));
        assert!(r.is_execute_at(0));
        assert!(!r.is_write_at(0));
    }

    // -----------------------------------------------------------------------
    // Address set tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_region_manager_address_set() {
        let mut mgr = TraceMemoryRegionManager::new();
        mgr.add_region(TraceMemoryRegionEntry::new(
            0, "", ".text", "ram", 0x400000, 0x400FFF, Lifespan::now_on(0),
        ));
        mgr.add_region(TraceMemoryRegionEntry::new(
            1, "", ".data", "ram", 0x500000, 0x500FFF, Lifespan::now_on(0),
        ));

        let set = mgr.get_regions_address_set(0);
        assert_eq!(set.len(), 2);
        assert_eq!(set[0], (0x400000, 0x400FFF));
        assert_eq!(set[1], (0x500000, 0x500FFF));
    }

    #[test]
    fn test_region_manager_address_set_merged() {
        let mut mgr = TraceMemoryRegionManager::new();
        // Two adjacent regions
        mgr.add_region(TraceMemoryRegionEntry::new(
            0, "", "a", "ram", 0x400000, 0x400FFF, Lifespan::now_on(0),
        ));
        mgr.add_region(TraceMemoryRegionEntry::new(
            1, "", "b", "ram", 0x401000, 0x401FFF, Lifespan::now_on(0),
        ));

        let set = mgr.get_regions_address_set(0);
        assert_eq!(set.len(), 1);
        assert_eq!(set[0], (0x400000, 0x401FFF));
    }

    #[test]
    fn test_region_manager_address_set_in_space() {
        let mut mgr = TraceMemoryRegionManager::new();
        mgr.add_region(TraceMemoryRegionEntry::new(
            0, "", ".text", "ram", 0x400000, 0x400FFF, Lifespan::now_on(0),
        ));
        mgr.add_region(TraceMemoryRegionEntry::new(
            1, "", "reg", "register", 0, 0xFF, Lifespan::now_on(0),
        ));

        let ram_set = mgr.get_regions_address_set_in_space("ram", 0);
        assert_eq!(ram_set.len(), 1);
        let reg_set = mgr.get_regions_address_set_in_space("register", 0);
        assert_eq!(reg_set.len(), 1);
    }

    #[test]
    fn test_region_manager_is_range_covered() {
        let mut mgr = TraceMemoryRegionManager::new();
        mgr.add_region(TraceMemoryRegionEntry::new(
            0, "", ".text", "ram", 0x400000, 0x400FFF, Lifespan::now_on(0),
        ));

        assert!(mgr.is_range_covered("ram", 0x400100, 0x400200, 0));
        assert!(!mgr.is_range_covered("ram", 0x400100, 0x401000, 0));
        assert!(mgr.is_range_covered("ram", 0x400000, 0x400FFF, 0));
    }

    // -----------------------------------------------------------------------
    // Extended query tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_region_manager_creation_order() {
        let mut mgr = TraceMemoryRegionManager::new();
        mgr.add_region(TraceMemoryRegionEntry::new(
            0, "", ".data", "ram", 0x500000, 0x500FFF, Lifespan::now_on(5),
        ));
        mgr.add_region(TraceMemoryRegionEntry::new(
            1, "", ".text", "ram", 0x400000, 0x400FFF, Lifespan::now_on(0),
        ));

        let ordered = mgr.regions_by_creation_order();
        assert_eq!(ordered[0].name, ".text");
        assert_eq!(ordered[1].name, ".data");
    }

    #[test]
    fn test_region_manager_total_mapped_bytes() {
        let mut mgr = TraceMemoryRegionManager::new();
        mgr.add_region(TraceMemoryRegionEntry::new(
            0, "", ".text", "ram", 0x400000, 0x400FFF, Lifespan::now_on(0),
        ));
        mgr.add_region(TraceMemoryRegionEntry::new(
            1, "", ".data", "ram", 0x500000, 0x500FFF, Lifespan::now_on(0),
        ));

        assert_eq!(mgr.total_mapped_bytes("ram", 0), 0x2000);
        assert_eq!(mgr.total_mapped_bytes("register", 0), 0);
    }

    #[test]
    fn test_region_manager_find_where() {
        let mut mgr = TraceMemoryRegionManager::new();
        mgr.add_region(
            TraceMemoryRegionEntry::new(
                0, "", ".text", "ram", 0x400000, 0x400FFF, Lifespan::now_on(0),
            )
            .with_permissions(MemoryRegionPermissions::RX),
        );
        mgr.add_region(
            TraceMemoryRegionEntry::new(
                1, "", ".data", "ram", 0x500000, 0x500FFF, Lifespan::now_on(0),
            )
            .with_permissions(MemoryRegionPermissions::RW),
        );

        let exec = mgr.find_regions_where(0, |r| r.permissions.execute);
        assert_eq!(exec.len(), 1);
        assert_eq!(exec[0].name, ".text");
    }

    // -----------------------------------------------------------------------
    // Change event tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_region_change_event_display() {
        assert_eq!(TraceMemoryRegionChangeEvent::Added.to_string(), "Added");
        assert_eq!(
            TraceMemoryRegionChangeEvent::LifespanChanged.to_string(),
            "LifespanChanged"
        );
        assert_eq!(TraceMemoryRegionChangeEvent::Changed.to_string(), "Changed");
        assert_eq!(TraceMemoryRegionChangeEvent::Deleted.to_string(), "Deleted");
    }

    // -----------------------------------------------------------------------
    // AddressRange tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_address_range_basics() {
        let r = AddressRange::new(0x100, 0x1FF);
        assert_eq!(r.length(), 0x100);
        assert!(r.contains(0x100));
        assert!(r.contains(0x180));
        assert!(r.contains(0x1FF));
        assert!(!r.contains(0x0FF));
        assert!(!r.contains(0x200));
    }

    #[test]
    fn test_address_range_overlaps() {
        let a = AddressRange::new(0x100, 0x1FF);
        let b = AddressRange::new(0x180, 0x280);
        let c = AddressRange::new(0x200, 0x2FF);
        assert!(a.overlaps(&b));
        assert!(b.overlaps(&c));
        assert!(!a.overlaps(&c));
    }

    // -----------------------------------------------------------------------
    // TraceOverlappedRegionException tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_overlap_exception_display() {
        let err = TraceOverlappedRegionException::new(vec![1, 2]);
        assert!(err.to_string().contains("2"));
        assert!(err.to_string().contains("overlap"));
        assert_eq!(err.conflicts, vec![1, 2]);
    }
}
