//! Breakpoint model for the Debug framework.
//!
//! Ported from `ghidra.trace.model.breakpoint` — includes [`TraceBreakpointKind`],
//! [`BreakpointSpec`], and [`BreakpointLocation`].

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

use super::core_types::Lifespan;

// ---------------------------------------------------------------------------
// TraceBreakpointKind
// ---------------------------------------------------------------------------

/// The kind of breakpoint.
///
/// Ported from `ghidra.trace.model.breakpoint.TraceBreakpointKind`.
/// Identifies the sort of access that would trap execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum TraceBreakpointKind {
    /// Read access breakpoint (hardware).
    Read,
    /// Write access breakpoint (hardware).
    Write,
    /// Hardware execute breakpoint.
    HwExecute,
    /// Software execute breakpoint.
    SwExecute,
}

impl TraceBreakpointKind {
    /// The flag character used for encoding (matches Ghidra's encoding).
    pub fn flag(&self) -> char {
        match self {
            TraceBreakpointKind::Read => 'R',
            TraceBreakpointKind::Write => 'W',
            TraceBreakpointKind::HwExecute => 'X',
            TraceBreakpointKind::SwExecute => 'x',
        }
    }

    /// All breakpoint kinds in declaration order.
    pub const ALL: [TraceBreakpointKind; 4] = [
        TraceBreakpointKind::Read,
        TraceBreakpointKind::Write,
        TraceBreakpointKind::HwExecute,
        TraceBreakpointKind::SwExecute,
    ];
}

impl fmt::Display for TraceBreakpointKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TraceBreakpointKind::Read => write!(f, "Read"),
            TraceBreakpointKind::Write => write!(f, "Write"),
            TraceBreakpointKind::HwExecute => write!(f, "HW_EXECUTE"),
            TraceBreakpointKind::SwExecute => write!(f, "SW_EXECUTE"),
        }
    }
}

// ---------------------------------------------------------------------------
// BreakpointKindSet
// ---------------------------------------------------------------------------

/// A set of breakpoint kinds, with encoding/decoding support.
///
/// Ported from `TraceBreakpointKind.TraceBreakpointKindSet`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BreakpointKindSet {
    kinds: BTreeSet<TraceBreakpointKind>,
}

impl BreakpointKindSet {
    /// An empty kind set.
    pub const EMPTY: BreakpointKindSet = BreakpointKindSet {
        kinds: BTreeSet::new(),
    };

    /// Create a kind set from a list of kinds.
    pub fn of(kinds: &[TraceBreakpointKind]) -> Self {
        Self {
            kinds: kinds.iter().copied().collect(),
        }
    }

    /// Create a kind set from an existing set.
    pub fn from_set(set: BTreeSet<TraceBreakpointKind>) -> Self {
        Self { kinds: set }
    }

    /// Returns `true` if the set contains the given kind.
    pub fn contains(&self, kind: &TraceBreakpointKind) -> bool {
        self.kinds.contains(kind)
    }

    /// Returns `true` if the set is empty.
    pub fn is_empty(&self) -> bool {
        self.kinds.is_empty()
    }

    /// Returns the number of kinds in the set.
    pub fn len(&self) -> usize {
        self.kinds.len()
    }

    /// Encode the kind set to a flag string (e.g., "RW", "X", "x").
    pub fn encode(&self) -> String {
        let mut s = String::new();
        for kind in &TraceBreakpointKind::ALL {
            if self.kinds.contains(kind) {
                s.push(kind.flag());
            }
        }
        s
    }

    /// Decode a flag string or comma-separated kind names into a kind set.
    ///
    /// If `strict` is `true`, unrecognized names cause an error.
    pub fn decode(encoded: &str, strict: bool) -> Result<Self, String> {
        match encoded {
            "" => Ok(Self::EMPTY),
            "x" | "SW_EXECUTE" => Ok(Self::of(&[TraceBreakpointKind::SwExecute])),
            "X" | "HW_EXECUTE" => Ok(Self::of(&[TraceBreakpointKind::HwExecute])),
            "R" | "READ" => Ok(Self::of(&[TraceBreakpointKind::Read])),
            "W" | "WRITE" => Ok(Self::of(&[TraceBreakpointKind::Write])),
            "RW" | "READ,WRITE" | "WRITE,READ" => {
                Ok(Self::of(&[TraceBreakpointKind::Read, TraceBreakpointKind::Write]))
            }
            _ => {
                if encoded.len() < 4 {
                    // Flag-based encoding
                    let mut result = BTreeSet::new();
                    for kind in &TraceBreakpointKind::ALL {
                        if encoded.contains(kind.flag()) {
                            result.insert(*kind);
                        }
                    }
                    Ok(Self::from_set(result))
                } else {
                    // Comma-separated names
                    let mut result = BTreeSet::new();
                    let mut remaining: BTreeSet<String> = encoded
                        .to_uppercase()
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .collect();
                    for kind in &TraceBreakpointKind::ALL {
                        let name = format!("{kind}");
                        if remaining.remove(&name) {
                            result.insert(*kind);
                        }
                    }
                    if strict && !remaining.is_empty() {
                        return Err(format!("Unrecognized breakpoint kinds: {remaining:?}"));
                    }
                    Ok(Self::from_set(result))
                }
            }
        }
    }

    /// Iterate over the kinds in the set.
    pub fn iter(&self) -> impl Iterator<Item = &TraceBreakpointKind> {
        self.kinds.iter()
    }

    /// Predefined: Software Execute.
    pub fn sw_execute() -> Self {
        Self::of(&[TraceBreakpointKind::SwExecute])
    }

    /// Predefined: Hardware Execute.
    pub fn hw_execute() -> Self {
        Self::of(&[TraceBreakpointKind::HwExecute])
    }

    /// Predefined: Read.
    pub fn read() -> Self {
        Self::of(&[TraceBreakpointKind::Read])
    }

    /// Predefined: Write.
    pub fn write() -> Self {
        Self::of(&[TraceBreakpointKind::Write])
    }

    /// Predefined: Read+Write (Access).
    pub fn access() -> Self {
        Self::of(&[TraceBreakpointKind::Read, TraceBreakpointKind::Write])
    }
}

impl fmt::Display for BreakpointKindSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.encode())
    }
}

// ---------------------------------------------------------------------------
// BreakpointSpec
// ---------------------------------------------------------------------------

/// A breakpoint specification — the "logical" breakpoint, possibly with
/// multiple locations.
///
/// Ported from `ghidra.trace.model.breakpoint.TraceBreakpointSpec`.
#[derive(Debug, Clone)]
pub struct BreakpointSpec {
    /// Unique key for this spec.
    key: u64,
    /// Time-varying kinds: (snap_from, kinds).
    kinds: BTreeMap<i64, BreakpointKindSet>,
    /// Time-varying enabled state: (snap_from, enabled).
    enabled: BTreeMap<i64, bool>,
    /// Time-varying names: (snap_from, name).
    names: BTreeMap<i64, String>,
    /// Time-varying comments: (snap_from, comment).
    comments: BTreeMap<i64, Option<String>>,
    /// The lifespan of this spec.
    pub lifespan: Lifespan,
    /// Whether deleted.
    deleted: bool,
}

impl BreakpointSpec {
    /// Create a new breakpoint spec.
    pub fn new(key: u64, snap: i64, kinds: BreakpointKindSet) -> Self {
        let mut kinds_map = BTreeMap::new();
        kinds_map.insert(snap, kinds);
        let mut enabled_map = BTreeMap::new();
        enabled_map.insert(snap, true);
        Self {
            key,
            kinds: kinds_map,
            enabled: enabled_map,
            names: BTreeMap::new(),
            comments: BTreeMap::new(),
            lifespan: Lifespan::now_on(snap),
            deleted: false,
        }
    }

    /// Returns the unique key.
    pub fn key(&self) -> u64 {
        self.key
    }

    /// Get the breakpoint kinds at the given snapshot.
    pub fn get_kinds(&self, snap: i64) -> Option<&BreakpointKindSet> {
        self.kinds.range(..=snap).next_back().map(|(_, k)| k)
    }

    /// Set the breakpoint kinds effective from the given snapshot.
    pub fn set_kinds(&mut self, snap: i64, kinds: BreakpointKindSet) {
        self.kinds.insert(snap, kinds);
    }

    /// Check if the breakpoint is enabled at the given snapshot.
    pub fn is_enabled(&self, snap: i64) -> bool {
        self.enabled
            .range(..=snap)
            .next_back()
            .map(|(_, e)| *e)
            .unwrap_or(true)
    }

    /// Set whether the breakpoint is enabled from the given snapshot.
    pub fn set_enabled(&mut self, snap: i64, enabled: bool) {
        self.enabled.insert(snap, enabled);
    }

    /// Get the display name at the given snapshot.
    pub fn get_name(&self, snap: i64) -> Option<&str> {
        self.names.range(..=snap).next_back().map(|(_, n)| n.as_str())
    }

    /// Set the display name effective from the given snapshot.
    pub fn set_name(&mut self, snap: i64, name: impl Into<String>) {
        self.names.insert(snap, name.into());
    }

    /// Get the comment at the given snapshot.
    pub fn get_comment(&self, snap: i64) -> Option<&str> {
        self.comments
            .range(..=snap)
            .next_back()
            .and_then(|(_, c)| c.as_deref())
    }

    /// Set the comment effective from the given snapshot.
    pub fn set_comment(&mut self, snap: i64, comment: Option<String>) {
        self.comments.insert(snap, comment);
    }

    /// Remove the spec from the given snap onward.
    pub fn remove(&mut self, snap: i64) {
        self.lifespan = self.lifespan.with_max(snap - 1);
    }

    /// Delete this spec entirely.
    pub fn delete(&mut self) {
        self.deleted = true;
    }

    /// Check if valid at the given snapshot.
    pub fn is_valid(&self, snap: i64) -> bool {
        !self.deleted && self.lifespan.contains(snap)
    }

    /// Check if alive for any of the given span.
    pub fn is_alive(&self, span: &Lifespan) -> bool {
        !self.deleted && self.lifespan.intersects(span)
    }
}

// ---------------------------------------------------------------------------
// BreakpointLocation
// ---------------------------------------------------------------------------

/// A breakpoint location — a specific address range for a breakpoint spec.
///
/// Ported from `ghidra.trace.model.breakpoint.TraceBreakpointLocation`.
#[derive(Debug, Clone)]
pub struct BreakpointLocation {
    /// Unique key for this location.
    key: u64,
    /// The owning spec key.
    pub spec_key: u64,
    /// Time-varying min address: (snap_from, address).
    min_addresses: BTreeMap<i64, u64>,
    /// Time-varying max address: (snap_from, address).
    max_addresses: BTreeMap<i64, u64>,
    /// Time-varying emu-enabled state: (snap_from, enabled).
    emu_enabled: BTreeMap<i64, bool>,
    /// Time-varying Sleigh injection: (snap_from, sleigh).
    emu_sleigh: BTreeMap<i64, String>,
    /// Time-varying enabled state: (snap_from, enabled).
    enabled: BTreeMap<i64, bool>,
    /// The lifespan of this location.
    pub lifespan: Lifespan,
    /// Whether deleted.
    deleted: bool,
}

impl BreakpointLocation {
    /// Create a new breakpoint location.
    pub fn new(
        key: u64,
        spec_key: u64,
        snap: i64,
        min_address: u64,
        max_address: u64,
    ) -> Self {
        let mut min_addrs = BTreeMap::new();
        min_addrs.insert(snap, min_address);
        let mut max_addrs = BTreeMap::new();
        max_addrs.insert(snap, max_address);
        let mut enabled_map = BTreeMap::new();
        enabled_map.insert(snap, true);
        Self {
            key,
            spec_key,
            min_addresses: min_addrs,
            max_addresses: max_addrs,
            emu_enabled: BTreeMap::new(),
            emu_sleigh: BTreeMap::new(),
            enabled: enabled_map,
            lifespan: Lifespan::now_on(snap),
            deleted: false,
        }
    }

    /// Create a single-address breakpoint location.
    pub fn at_address(key: u64, spec_key: u64, snap: i64, address: u64) -> Self {
        Self::new(key, spec_key, snap, address, address)
    }

    /// Returns the unique key.
    pub fn key(&self) -> u64 {
        self.key
    }

    /// Get the minimum address at the given snapshot.
    pub fn get_min_address(&self, snap: i64) -> Option<u64> {
        self.min_addresses.range(..=snap).next_back().map(|(_, a)| *a)
    }

    /// Get the maximum address at the given snapshot.
    pub fn get_max_address(&self, snap: i64) -> Option<u64> {
        self.max_addresses.range(..=snap).next_back().map(|(_, a)| *a)
    }

    /// Set the address range effective from the given snapshot.
    pub fn set_range(&mut self, snap: i64, min_address: u64, max_address: u64) {
        self.min_addresses.insert(snap, min_address);
        self.max_addresses.insert(snap, max_address);
    }

    /// Get the length of this breakpoint at the given snapshot.
    pub fn get_length(&self, snap: i64) -> Option<u64> {
        let min = self.get_min_address(snap)?;
        let max = self.get_max_address(snap)?;
        Some(max - min + 1)
    }

    /// Check if emulation is enabled at the given snapshot.
    pub fn is_emu_enabled(&self, snap: i64) -> bool {
        self.emu_enabled
            .range(..=snap)
            .next_back()
            .map(|(_, e)| *e)
            .unwrap_or(false)
    }

    /// Set emulation enabled state from the given snapshot.
    pub fn set_emu_enabled(&mut self, snap: i64, enabled: bool) {
        self.emu_enabled.insert(snap, enabled);
    }

    /// Get the Sleigh injection at the given snapshot.
    pub fn get_emu_sleigh(&self, snap: i64) -> Option<&str> {
        self.emu_sleigh
            .range(..=snap)
            .next_back()
            .map(|(_, s)| s.as_str())
    }

    /// Set the Sleigh injection effective from the given snapshot.
    pub fn set_emu_sleigh(&mut self, snap: i64, sleigh: impl Into<String>) {
        self.emu_sleigh.insert(snap, sleigh.into());
    }

    /// Check if enabled at the given snapshot.
    pub fn is_enabled(&self, snap: i64) -> bool {
        self.enabled
            .range(..=snap)
            .next_back()
            .map(|(_, e)| *e)
            .unwrap_or(true)
    }

    /// Set enabled state from the given snapshot.
    pub fn set_enabled(&mut self, snap: i64, enabled: bool) {
        self.enabled.insert(snap, enabled);
    }

    /// Remove this location from the given snap onward.
    pub fn remove(&mut self, snap: i64) {
        self.lifespan = self.lifespan.with_max(snap - 1);
    }

    /// Delete this location entirely.
    pub fn delete(&mut self) {
        self.deleted = true;
    }

    /// Check if valid at the given snapshot.
    pub fn is_valid(&self, snap: i64) -> bool {
        !self.deleted && self.lifespan.contains(snap)
    }

    /// Check if alive for any of the given span.
    pub fn is_alive(&self, span: &Lifespan) -> bool {
        !self.deleted && self.lifespan.intersects(span)
    }
}

// ---------------------------------------------------------------------------
// BreakpointManager
// ---------------------------------------------------------------------------

/// Manages breakpoint specs and locations within a trace.
#[derive(Debug)]
pub struct BreakpointManager {
    next_key: AtomicU64,
    specs: BTreeMap<u64, BreakpointSpec>,
    locations: BTreeMap<u64, BreakpointLocation>,
}

impl BreakpointManager {
    /// Create a new empty breakpoint manager.
    pub fn new() -> Self {
        Self {
            next_key: AtomicU64::new(1),
            specs: BTreeMap::new(),
            locations: BTreeMap::new(),
        }
    }

    fn alloc_key(&self) -> u64 {
        self.next_key.fetch_add(1, Ordering::Relaxed)
    }

    /// Add a new breakpoint spec.
    pub fn add_spec(&mut self, snap: i64, kinds: BreakpointKindSet) -> u64 {
        let key = self.alloc_key();
        self.specs.insert(key, BreakpointSpec::new(key, snap, kinds));
        key
    }

    /// Add a new breakpoint location for a spec.
    pub fn add_location(
        &mut self,
        spec_key: u64,
        snap: i64,
        min_address: u64,
        max_address: u64,
    ) -> u64 {
        let key = self.alloc_key();
        self.locations.insert(
            key,
            BreakpointLocation::new(key, spec_key, snap, min_address, max_address),
        );
        key
    }

    /// Add a single-address breakpoint location for a spec.
    pub fn add_location_at(&mut self, spec_key: u64, snap: i64, address: u64) -> u64 {
        self.add_location(spec_key, snap, address, address)
    }

    /// Get a spec by key.
    pub fn get_spec(&self, key: u64) -> Option<&BreakpointSpec> {
        self.specs.get(&key)
    }

    /// Get a mutable spec by key.
    pub fn get_spec_mut(&mut self, key: u64) -> Option<&mut BreakpointSpec> {
        self.specs.get_mut(&key)
    }

    /// Get a location by key.
    pub fn get_location(&self, key: u64) -> Option<&BreakpointLocation> {
        self.locations.get(&key)
    }

    /// Get a mutable location by key.
    pub fn get_location_mut(&mut self, key: u64) -> Option<&mut BreakpointLocation> {
        self.locations.get_mut(&key)
    }

    /// Get all locations for a given spec.
    pub fn get_locations_for_spec(&self, spec_key: u64) -> Vec<&BreakpointLocation> {
        self.locations
            .values()
            .filter(|loc| loc.spec_key == spec_key)
            .collect()
    }

    /// Get all locations valid at a given snapshot.
    pub fn get_locations_at_snap(&self, snap: i64) -> Vec<&BreakpointLocation> {
        self.locations
            .values()
            .filter(|loc| loc.is_valid(snap))
            .collect()
    }

    /// Iterate over all specs.
    pub fn specs(&self) -> impl Iterator<Item = &BreakpointSpec> {
        self.specs.values()
    }

    /// Iterate over all locations.
    pub fn locations(&self) -> impl Iterator<Item = &BreakpointLocation> {
        self.locations.values()
    }

    /// Remove a spec (and all its locations).
    pub fn remove_spec(&mut self, key: u64) -> Option<BreakpointSpec> {
        // Remove associated locations
        let loc_keys: Vec<u64> = self
            .locations
            .values()
            .filter(|l| l.spec_key == key)
            .map(|l| l.key())
            .collect();
        for lk in loc_keys {
            self.locations.remove(&lk);
        }
        self.specs.remove(&key)
    }

    /// Remove a single location.
    pub fn remove_location(&mut self, key: u64) -> Option<BreakpointLocation> {
        self.locations.remove(&key)
    }
}

impl Default for BreakpointManager {
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
    fn test_breakpoint_kind_flag() {
        assert_eq!(TraceBreakpointKind::Read.flag(), 'R');
        assert_eq!(TraceBreakpointKind::Write.flag(), 'W');
        assert_eq!(TraceBreakpointKind::HwExecute.flag(), 'X');
        assert_eq!(TraceBreakpointKind::SwExecute.flag(), 'x');
    }

    #[test]
    fn test_kind_set_encode_decode() {
        let set = BreakpointKindSet::of(&[
            TraceBreakpointKind::Read,
            TraceBreakpointKind::Write,
        ]);
        assert_eq!(set.encode(), "RW");

        let decoded = BreakpointKindSet::decode("RW", false).unwrap();
        assert!(decoded.contains(&TraceBreakpointKind::Read));
        assert!(decoded.contains(&TraceBreakpointKind::Write));

        let swx = BreakpointKindSet::decode("x", false).unwrap();
        assert!(swx.contains(&TraceBreakpointKind::SwExecute));
        assert_eq!(swx.len(), 1);

        let hwx = BreakpointKindSet::decode("HW_EXECUTE", false).unwrap();
        assert!(hwx.contains(&TraceBreakpointKind::HwExecute));

        let empty = BreakpointKindSet::decode("", false).unwrap();
        assert!(empty.is_empty());
    }

    #[test]
    fn test_kind_set_decode_multi_flag() {
        let set = BreakpointKindSet::decode("RWX", false).unwrap();
        assert!(set.contains(&TraceBreakpointKind::Read));
        assert!(set.contains(&TraceBreakpointKind::Write));
        assert!(set.contains(&TraceBreakpointKind::HwExecute));
        assert!(!set.contains(&TraceBreakpointKind::SwExecute));
    }

    #[test]
    fn test_breakpoint_spec() {
        let mut spec = BreakpointSpec::new(1, 0, BreakpointKindSet::sw_execute());
        assert_eq!(spec.key(), 1);
        assert!(spec.is_enabled(0));
        assert!(spec.is_valid(0));

        spec.set_enabled(5, false);
        assert!(spec.is_enabled(0));
        assert!(!spec.is_enabled(5));
        assert!(!spec.is_enabled(100));

        spec.set_name(0, "my_breakpoint");
        assert_eq!(spec.get_name(0), Some("my_breakpoint"));
    }

    #[test]
    fn test_breakpoint_location() {
        let loc = BreakpointLocation::new(10, 1, 0, 0x400000, 0x400FFF);
        assert_eq!(loc.key(), 10);
        assert_eq!(loc.spec_key, 1);
        assert_eq!(loc.get_min_address(0), Some(0x400000));
        assert_eq!(loc.get_max_address(0), Some(0x400FFF));
        assert_eq!(loc.get_length(0), Some(0x1000));
        assert!(loc.is_valid(0));
        assert!(!loc.is_emu_enabled(0));
    }

    #[test]
    fn test_breakpoint_location_at_address() {
        let loc = BreakpointLocation::at_address(20, 1, 0, 0x1000);
        assert_eq!(loc.get_min_address(0), Some(0x1000));
        assert_eq!(loc.get_max_address(0), Some(0x1000));
        assert_eq!(loc.get_length(0), Some(1));
    }

    #[test]
    fn test_breakpoint_location_emu() {
        let mut loc = BreakpointLocation::at_address(1, 1, 0, 0x1000);
        loc.set_emu_enabled(0, true);
        loc.set_emu_sleigh(0, "emu_swi(); emu_exec_decoded();");

        assert!(loc.is_emu_enabled(0));
        assert_eq!(
            loc.get_emu_sleigh(0),
            Some("emu_swi(); emu_exec_decoded();")
        );
    }

    #[test]
    fn test_breakpoint_manager() {
        let mut mgr = BreakpointManager::new();
        let spec_key = mgr.add_spec(0, BreakpointKindSet::sw_execute());
        let loc_key = mgr.add_location_at(spec_key, 0, 0x400000);

        let spec = mgr.get_spec(spec_key).unwrap();
        assert_eq!(spec.key(), spec_key);

        let loc = mgr.get_location(loc_key).unwrap();
        assert_eq!(loc.spec_key, spec_key);
        assert_eq!(loc.get_min_address(0), Some(0x400000));

        let locs = mgr.get_locations_for_spec(spec_key);
        assert_eq!(locs.len(), 1);

        let at_snap = mgr.get_locations_at_snap(0);
        assert_eq!(at_snap.len(), 1);
    }

    #[test]
    fn test_breakpoint_manager_remove_spec() {
        let mut mgr = BreakpointManager::new();
        let spec_key = mgr.add_spec(0, BreakpointKindSet::sw_execute());
        mgr.add_location_at(spec_key, 0, 0x400000);
        mgr.add_location_at(spec_key, 0, 0x400100);

        assert_eq!(mgr.locations().count(), 2);
        mgr.remove_spec(spec_key);
        assert_eq!(mgr.locations().count(), 0);
        assert!(mgr.get_spec(spec_key).is_none());
    }
}
