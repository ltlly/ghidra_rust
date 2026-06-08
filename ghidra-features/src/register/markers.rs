//! Register value markers -- visual markers for register value ranges.
//!
//! Ported from the marker logic in `RegisterValuesPanel.java` within
//! Ghidra's `ghidra.app.plugin.core.register`.
//!
//! The [`RegisterMarkerManager`] tracks which address ranges have
//! non-default register values and provides integration points for a
//! marker service (e.g., the Ghidra `MarkerService`).

use ghidra_core::addr::{Address, AddressSet};

/// A single marker entry representing a range of addresses with a
/// register value.
///
/// This is the data model behind the area markers that `RegisterValuesPanel`
/// places in the listing margin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterMarkerEntry {
    /// Start address of the marked range (inclusive).
    pub start: Address,
    /// End address of the marked range (inclusive).
    pub end: Address,
    /// Whether this marker represents a default (non-explicit) value.
    pub is_default: bool,
    /// The register name this marker is for.
    pub register_name: String,
}

impl RegisterMarkerEntry {
    /// Create a new marker entry.
    pub fn new(
        start: Address,
        end: Address,
        is_default: bool,
        register_name: impl Into<String>,
    ) -> Self {
        Self {
            start,
            end,
            is_default,
            register_name: register_name.into(),
        }
    }

    /// Whether the given address falls within this marker's range.
    pub fn contains(&self, addr: &Address) -> bool {
        addr.offset >= self.start.offset && addr.offset <= self.end.offset
    }

    /// The size of the marked range.
    pub fn size(&self) -> u64 {
        self.end.offset - self.start.offset + 1
    }
}

/// The color/priority of register markers.
///
/// Matches the `REGISTER_MARKER_COLOR` constant in the Java source.
pub const REGISTER_MARKER_PRIORITY: i32 = 0;

/// Marker name used in the marker service.
pub const REGISTER_MARKER_NAME: &str = "Register Values";

/// Marker tooltip description.
pub const REGISTER_MARKER_DESCRIPTION: &str =
    "Area where selected register has defined values";

/// Manages register value markers for a program.
///
/// Ported from the marker-related methods in `RegisterValuesPanel.java`:
/// - `updateMarkers()`
/// - `clearMarkers()`
/// - the `markerAddressSet` field
///
/// This type tracks the address set of non-default register values and
/// provides methods for building the marker data needed by a marker service.
#[derive(Debug, Clone)]
pub struct RegisterMarkerManager {
    /// The address set of non-default register values.
    marker_address_set: AddressSet,
    /// The entries for detailed marker information.
    entries: Vec<RegisterMarkerEntry>,
    /// Whether markers are currently visible.
    visible: bool,
    /// The program name these markers belong to.
    program_name: Option<String>,
}

impl RegisterMarkerManager {
    /// Create a new empty marker manager.
    pub fn new() -> Self {
        Self {
            marker_address_set: AddressSet::new(),
            entries: Vec::new(),
            visible: true,
            program_name: None,
        }
    }

    /// Set the program name these markers belong to.
    pub fn set_program(&mut self, program_name: Option<String>) {
        self.program_name = program_name;
        self.clear();
    }

    /// Get the program name.
    pub fn program_name(&self) -> Option<&str> {
        self.program_name.as_deref()
    }

    /// Clear all markers.
    ///
    /// Ported from `RegisterValuesPanel.clearMarkers()`.
    pub fn clear(&mut self) {
        self.marker_address_set = AddressSet::new();
        self.entries.clear();
    }

    /// Update markers from a set of address ranges.
    ///
    /// This replaces the current markers with the given entries.
    /// Ported from the marker-building logic in `RegisterValuesPanel.setRegister()`.
    pub fn set_entries(&mut self, entries: Vec<RegisterMarkerEntry>) {
        self.marker_address_set = AddressSet::new();
        for entry in &entries {
            if !entry.is_default {
                self.marker_address_set
                    .add_range(entry.start, entry.end);
            }
        }
        self.entries = entries;
    }

    /// Build marker entries from register value data.
    ///
    /// This is the ported version of the loop in `setRegister()` that
    /// iterates over address ranges and creates `RegisterValueRange`
    /// objects, also building the marker address set.
    pub fn build_from_values(
        &mut self,
        register_name: &str,
        ranges: &[(Address, Address, u64, bool)],
    ) {
        let mut entries = Vec::new();
        for &(start, end, _value, is_default) in ranges {
            entries.push(RegisterMarkerEntry::new(
                start,
                end,
                is_default,
                register_name,
            ));
        }
        self.set_entries(entries);
    }

    /// Get the address set of non-default register values.
    ///
    /// This is the set that would be passed to `MarkerSet.add()`.
    pub fn marker_address_set(&self) -> &AddressSet {
        &self.marker_address_set
    }

    /// Get all marker entries.
    pub fn entries(&self) -> &[RegisterMarkerEntry] {
        &self.entries
    }

    /// Whether markers are currently visible.
    pub fn is_visible(&self) -> bool {
        self.visible
    }

    /// Set marker visibility.
    pub fn set_visible(&mut self, visible: bool) {
        self.visible = visible;
    }

    /// Whether there are any markers.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The number of marker entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Find the marker entry containing the given address.
    pub fn find_entry(&self, addr: &Address) -> Option<&RegisterMarkerEntry> {
        self.entries.iter().find(|e| e.contains(addr))
    }

    /// Get the total number of non-default marked addresses.
    pub fn non_default_count(&self) -> usize {
        self.entries.iter().filter(|e| !e.is_default).count()
    }

    /// Get the total number of default marked addresses.
    pub fn default_count(&self) -> usize {
        self.entries.iter().filter(|e| e.is_default).count()
    }

    /// Build an address set covering all entries (both default and non-default).
    pub fn all_entries_address_set(&self) -> AddressSet {
        let mut set = AddressSet::new();
        for entry in &self.entries {
            set.add_range(entry.start, entry.end);
        }
        set
    }
}

impl Default for RegisterMarkerManager {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(offset: u64) -> Address {
        Address::new(offset)
    }

    #[test]
    fn test_marker_entry_creation() {
        let entry = RegisterMarkerEntry::new(addr(0x1000), addr(0x1fff), false, "EAX");
        assert_eq!(entry.start, addr(0x1000));
        assert_eq!(entry.end, addr(0x1fff));
        assert!(!entry.is_default);
        assert_eq!(entry.register_name, "EAX");
    }

    #[test]
    fn test_marker_entry_contains() {
        let entry = RegisterMarkerEntry::new(addr(0x1000), addr(0x1fff), false, "EAX");
        assert!(entry.contains(&addr(0x1000)));
        assert!(entry.contains(&addr(0x1500)));
        assert!(entry.contains(&addr(0x1fff)));
        assert!(!entry.contains(&addr(0x2000)));
        assert!(!entry.contains(&addr(0x0fff)));
    }

    #[test]
    fn test_marker_entry_size() {
        let entry = RegisterMarkerEntry::new(addr(0x1000), addr(0x1fff), false, "EAX");
        assert_eq!(entry.size(), 0x1000);
    }

    #[test]
    fn test_marker_manager_new() {
        let mgr = RegisterMarkerManager::new();
        assert!(mgr.is_empty());
        assert_eq!(mgr.len(), 0);
        assert!(mgr.is_visible());
        assert!(mgr.program_name().is_none());
    }

    #[test]
    fn test_marker_manager_set_program() {
        let mut mgr = RegisterMarkerManager::new();
        mgr.set_program(Some("test.exe".to_string()));
        assert_eq!(mgr.program_name(), Some("test.exe"));

        // Setting program clears markers
        mgr.set_entries(vec![RegisterMarkerEntry::new(
            addr(0x1000),
            addr(0x1fff),
            false,
            "EAX",
        )]);
        assert_eq!(mgr.len(), 1);
        mgr.set_program(Some("other.exe".to_string()));
        assert_eq!(mgr.len(), 0);
    }

    #[test]
    fn test_marker_manager_set_entries() {
        let mut mgr = RegisterMarkerManager::new();
        let entries = vec![
            RegisterMarkerEntry::new(addr(0x1000), addr(0x1fff), false, "EAX"),
            RegisterMarkerEntry::new(addr(0x2000), addr(0x2fff), true, "EAX"),
            RegisterMarkerEntry::new(addr(0x3000), addr(0x3fff), false, "EAX"),
        ];
        mgr.set_entries(entries);
        assert_eq!(mgr.len(), 3);
        assert_eq!(mgr.non_default_count(), 2);
        assert_eq!(mgr.default_count(), 1);

        // Non-default addresses should be in the marker address set
        let set = mgr.marker_address_set();
        assert!(set.contains(&addr(0x1000)));
        assert!(set.contains(&addr(0x3000)));
        // Default addresses should NOT be in the marker address set
        assert!(!set.contains(&addr(0x2000)));
    }

    #[test]
    fn test_marker_manager_build_from_values() {
        let mut mgr = RegisterMarkerManager::new();
        let ranges = vec![
            (addr(0x1000), addr(0x1fff), 5u64, false),
            (addr(0x2000), addr(0x2fff), 0u64, true),
            (addr(0x3000), addr(0x3fff), 10u64, false),
        ];
        mgr.build_from_values("EAX", &ranges);
        assert_eq!(mgr.len(), 3);
        assert_eq!(mgr.non_default_count(), 2);
    }

    #[test]
    fn test_marker_manager_clear() {
        let mut mgr = RegisterMarkerManager::new();
        mgr.set_entries(vec![RegisterMarkerEntry::new(
            addr(0x1000),
            addr(0x1fff),
            false,
            "EAX",
        )]);
        assert_eq!(mgr.len(), 1);
        mgr.clear();
        assert!(mgr.is_empty());
        assert!(mgr.marker_address_set().is_empty());
    }

    #[test]
    fn test_marker_manager_find_entry() {
        let mut mgr = RegisterMarkerManager::new();
        mgr.set_entries(vec![
            RegisterMarkerEntry::new(addr(0x1000), addr(0x1fff), false, "EAX"),
            RegisterMarkerEntry::new(addr(0x3000), addr(0x3fff), false, "EBX"),
        ]);
        assert!(mgr.find_entry(&addr(0x1500)).is_some());
        assert!(mgr.find_entry(&addr(0x3500)).is_some());
        assert!(mgr.find_entry(&addr(0x2500)).is_none());
    }

    #[test]
    fn test_marker_manager_visibility() {
        let mut mgr = RegisterMarkerManager::new();
        assert!(mgr.is_visible());
        mgr.set_visible(false);
        assert!(!mgr.is_visible());
    }

    #[test]
    fn test_marker_manager_all_entries_address_set() {
        let mut mgr = RegisterMarkerManager::new();
        mgr.set_entries(vec![
            RegisterMarkerEntry::new(addr(0x1000), addr(0x1fff), false, "EAX"),
            RegisterMarkerEntry::new(addr(0x2000), addr(0x2fff), true, "EAX"),
        ]);
        let all_set = mgr.all_entries_address_set();
        // All entries, including defaults, should be in this set
        assert!(all_set.contains(&addr(0x1000)));
        assert!(all_set.contains(&addr(0x2000)));
    }

    #[test]
    fn test_marker_constants() {
        assert_eq!(REGISTER_MARKER_NAME, "Register Values");
        assert_eq!(REGISTER_MARKER_PRIORITY, 0);
        assert!(!REGISTER_MARKER_DESCRIPTION.is_empty());
    }

    #[test]
    fn test_marker_entry_clone() {
        let entry = RegisterMarkerEntry::new(addr(0x1000), addr(0x1fff), false, "EAX");
        let cloned = entry.clone();
        assert_eq!(entry, cloned);
    }

    #[test]
    fn test_marker_manager_default() {
        let mgr = RegisterMarkerManager::default();
        assert!(mgr.is_empty());
        assert!(mgr.is_visible());
    }
}
