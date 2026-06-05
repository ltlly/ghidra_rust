//! Dynamic-static synchronization plugin.
//!
//! Ported from Ghidra's `DynamicStaticSynchronizationPlugin` (714 lines).
//!
//! Synchronizes the static and dynamic listings (and other components)
//! where the module map is known. This plugin translates locations
//! between program addresses and trace addresses using the module
//! mapping information.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// A static-to-dynamic address mapping entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncMappingEntry {
    /// The program (static) address.
    pub program_address: u64,
    /// The trace (dynamic) address.
    pub trace_address: u64,
    /// The size of the mapped region.
    pub size: u64,
    /// The program URL.
    pub program_url: String,
}

impl SyncMappingEntry {
    /// Create a new mapping entry.
    pub fn new(
        program_address: u64,
        trace_address: u64,
        size: u64,
        program_url: impl Into<String>,
    ) -> Self {
        Self {
            program_address,
            trace_address,
            size,
            program_url: program_url.into(),
        }
    }

    /// Translate a program address to a trace address.
    pub fn program_to_trace(&self, program_addr: u64) -> Option<u64> {
        if program_addr >= self.program_address && program_addr < self.program_address + self.size {
            Some(self.trace_address + (program_addr - self.program_address))
        } else {
            None
        }
    }

    /// Translate a trace address to a program address.
    pub fn trace_to_program(&self, trace_addr: u64) -> Option<u64> {
        if trace_addr >= self.trace_address && trace_addr < self.trace_address + self.size {
            Some(self.program_address + (trace_addr - self.trace_address))
        } else {
            None
        }
    }

    /// Whether a program address falls in this mapping.
    pub fn contains_program_address(&self, addr: u64) -> bool {
        addr >= self.program_address && addr < self.program_address + self.size
    }

    /// Whether a trace address falls in this mapping.
    pub fn contains_trace_address(&self, addr: u64) -> bool {
        addr >= self.trace_address && addr < self.trace_address + self.size
    }
}

/// The direction of synchronization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SyncDirection {
    /// Sync from static (program) to dynamic (trace).
    StaticToDynamic,
    /// Sync from dynamic (trace) to static (program).
    DynamicToStatic,
    /// Bidirectional synchronization.
    Bidirectional,
}

impl Default for SyncDirection {
    fn default() -> Self {
        SyncDirection::Bidirectional
    }
}

/// A location to synchronize.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncLocation {
    /// The address.
    pub address: u64,
    /// Whether this is a trace (dynamic) address, otherwise program (static).
    pub is_dynamic: bool,
}

impl SyncLocation {
    /// Create a dynamic (trace) location.
    pub fn dynamic(address: u64) -> Self {
        Self {
            address,
            is_dynamic: true,
        }
    }

    /// Create a static (program) location.
    pub fn static_addr(address: u64) -> Self {
        Self {
            address,
            is_dynamic: false,
        }
    }
}

/// The result of a synchronization translation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncResult {
    /// The translated address.
    pub address: u64,
    /// The program URL (if translated to static).
    pub program_url: Option<String>,
    /// Whether the translation was exact.
    pub exact: bool,
}

/// The dynamic-static synchronization plugin.
///
/// Ported from Ghidra's `DynamicStaticSynchronizationPlugin`.
#[derive(Debug, Default)]
pub struct DynamicStaticSyncPlugin {
    /// Active mappings indexed by trace key.
    mappings: BTreeMap<i64, Vec<SyncMappingEntry>>,
    /// Current synchronization direction.
    direction: SyncDirection,
    /// Whether location synchronization is enabled.
    sync_locations_enabled: bool,
    /// Whether selection synchronization is enabled.
    sync_selection_enabled: bool,
    /// The active trace key.
    active_trace_key: Option<i64>,
    /// The active program URL.
    active_program_url: Option<String>,
}

impl DynamicStaticSyncPlugin {
    /// Create a new synchronization plugin.
    pub fn new() -> Self {
        Self {
            direction: SyncDirection::default(),
            sync_locations_enabled: true,
            sync_selection_enabled: true,
            ..Default::default()
        }
    }

    /// Set the synchronization direction.
    pub fn set_direction(&mut self, direction: SyncDirection) {
        self.direction = direction;
    }

    /// Get the synchronization direction.
    pub fn direction(&self) -> SyncDirection {
        self.direction
    }

    /// Enable or disable location synchronization.
    pub fn set_sync_locations(&mut self, enabled: bool) {
        self.sync_locations_enabled = enabled;
    }

    /// Whether location synchronization is enabled.
    pub fn is_sync_locations_enabled(&self) -> bool {
        self.sync_locations_enabled
    }

    /// Enable or disable selection synchronization.
    pub fn set_sync_selection(&mut self, enabled: bool) {
        self.sync_selection_enabled = enabled;
    }

    /// Whether selection synchronization is enabled.
    pub fn is_sync_selection_enabled(&self) -> bool {
        self.sync_selection_enabled
    }

    /// Set the active trace.
    pub fn set_active_trace(&mut self, trace_key: Option<i64>) {
        self.active_trace_key = trace_key;
    }

    /// Set the active program URL.
    pub fn set_active_program(&mut self, program_url: Option<String>) {
        self.active_program_url = program_url;
    }

    /// Add a mapping for a trace.
    pub fn add_mapping(&mut self, trace_key: i64, entry: SyncMappingEntry) {
        self.mappings.entry(trace_key).or_default().push(entry);
    }

    /// Remove all mappings for a trace.
    pub fn remove_mappings(&mut self, trace_key: i64) {
        self.mappings.remove(&trace_key);
    }

    /// Translate a location using the active mappings.
    pub fn translate(&self, location: &SyncLocation) -> Option<SyncResult> {
        let trace_key = self.active_trace_key?;

        if location.is_dynamic {
            // Dynamic (trace) -> Static (program)
            if matches!(self.direction, SyncDirection::StaticToDynamic) {
                return None;
            }
            self.trace_to_program(trace_key, location.address)
        } else {
            // Static (program) -> Dynamic (trace)
            if matches!(self.direction, SyncDirection::DynamicToStatic) {
                return None;
            }
            self.program_to_trace(trace_key, location.address)
        }
    }

    fn trace_to_program(&self, trace_key: i64, trace_addr: u64) -> Option<SyncResult> {
        let entries = self.mappings.get(&trace_key)?;
        for entry in entries {
            if let Some(program_addr) = entry.trace_to_program(trace_addr) {
                return Some(SyncResult {
                    address: program_addr,
                    program_url: Some(entry.program_url.clone()),
                    exact: true,
                });
            }
        }
        None
    }

    fn program_to_trace(&self, trace_key: i64, program_addr: u64) -> Option<SyncResult> {
        let entries = self.mappings.get(&trace_key)?;
        for entry in entries {
            if let Some(trace_addr) = entry.program_to_trace(program_addr) {
                return Some(SyncResult {
                    address: trace_addr,
                    program_url: None,
                    exact: true,
                });
            }
        }
        None
    }

    /// Get all mappings for a trace.
    pub fn get_mappings(&self, trace_key: i64) -> &[SyncMappingEntry] {
        self.mappings
            .get(&trace_key)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Get the total number of mappings across all traces.
    pub fn total_mapping_count(&self) -> usize {
        self.mappings.values().map(|v| v.len()).sum()
    }

    /// Get the number of traces with mappings.
    pub fn trace_count(&self) -> usize {
        self.mappings.len()
    }

    /// Clear all mappings.
    pub fn clear(&mut self) {
        self.mappings.clear();
    }

    /// Get the active trace key.
    pub fn active_trace_key(&self) -> Option<i64> {
        self.active_trace_key
    }

    /// Get the active program URL.
    pub fn active_program_url(&self) -> Option<&str> {
        self.active_program_url.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mapping_entry_translation() {
        let entry = SyncMappingEntry::new(0x401000, 0x7FFF0000, 0x1000, "file:///test.exe");

        // Program -> Trace
        assert_eq!(entry.program_to_trace(0x401000), Some(0x7FFF0000));
        assert_eq!(entry.program_to_trace(0x401010), Some(0x7FFF0010));
        assert_eq!(entry.program_to_trace(0x402000), None); // out of range

        // Trace -> Program
        assert_eq!(entry.trace_to_program(0x7FFF0000), Some(0x401000));
        assert_eq!(entry.trace_to_program(0x7FFF0050), Some(0x401050));
        assert_eq!(entry.trace_to_program(0x80000000), None); // out of range
    }

    #[test]
    fn test_mapping_entry_contains() {
        let entry = SyncMappingEntry::new(0x1000, 0x8000, 0x100, "test");

        assert!(entry.contains_program_address(0x1000));
        assert!(entry.contains_program_address(0x1099));
        assert!(!entry.contains_program_address(0x1100));
        assert!(!entry.contains_program_address(0x0FFF));

        assert!(entry.contains_trace_address(0x8000));
        assert!(entry.contains_trace_address(0x8099));
        assert!(!entry.contains_trace_address(0x8100));
    }

    #[test]
    fn test_sync_plugin_basic() {
        let mut plugin = DynamicStaticSyncPlugin::new();
        plugin.set_active_trace(Some(1));

        plugin.add_mapping(
            1,
            SyncMappingEntry::new(0x401000, 0x7FFF0000, 0x1000, "file:///test.exe"),
        );

        // Program -> Trace
        let result = plugin
            .translate(&SyncLocation::static_addr(0x401050))
            .unwrap();
        assert_eq!(result.address, 0x7FFF0050);

        // Trace -> Program
        let result = plugin
            .translate(&SyncLocation::dynamic(0x7FFF0050))
            .unwrap();
        assert_eq!(result.address, 0x401050);
        assert_eq!(result.program_url, Some("file:///test.exe".into()));
    }

    #[test]
    fn test_sync_direction_filtering() {
        let mut plugin = DynamicStaticSyncPlugin::new();
        plugin.set_active_trace(Some(1));
        plugin.set_direction(SyncDirection::StaticToDynamic);
        plugin.add_mapping(
            1,
            SyncMappingEntry::new(0x401000, 0x7FFF0000, 0x1000, "test"),
        );

        // Static -> Dynamic should work
        assert!(plugin
            .translate(&SyncLocation::static_addr(0x401050))
            .is_some());

        // Dynamic -> Static should be blocked
        assert!(plugin
            .translate(&SyncLocation::dynamic(0x7FFF0050))
            .is_none());
    }

    #[test]
    fn test_sync_location_types() {
        let dyn_loc = SyncLocation::dynamic(0x1000);
        assert!(dyn_loc.is_dynamic);

        let stat_loc = SyncLocation::static_addr(0x1000);
        assert!(!stat_loc.is_dynamic);
    }

    #[test]
    fn test_sync_plugin_no_active_trace() {
        let mut plugin = DynamicStaticSyncPlugin::new();
        plugin.add_mapping(
            1,
            SyncMappingEntry::new(0x401000, 0x7FFF0000, 0x1000, "test"),
        );

        // No active trace set
        assert!(plugin
            .translate(&SyncLocation::static_addr(0x401050))
            .is_none());
    }

    #[test]
    fn test_sync_plugin_multiple_mappings() {
        let mut plugin = DynamicStaticSyncPlugin::new();
        plugin.set_active_trace(Some(1));

        plugin.add_mapping(
            1,
            SyncMappingEntry::new(0x401000, 0x7FFF0000, 0x1000, "lib1.so"),
        );
        plugin.add_mapping(
            1,
            SyncMappingEntry::new(0x402000, 0x80000000, 0x2000, "lib2.so"),
        );

        assert_eq!(plugin.total_mapping_count(), 2);
        assert_eq!(plugin.get_mappings(1).len(), 2);

        let result = plugin
            .translate(&SyncLocation::static_addr(0x402100))
            .unwrap();
        assert_eq!(result.address, 0x80000100);
    }

    #[test]
    fn test_sync_feature_toggles() {
        let mut plugin = DynamicStaticSyncPlugin::new();
        assert!(plugin.is_sync_locations_enabled());
        assert!(plugin.is_sync_selection_enabled());

        plugin.set_sync_locations(false);
        assert!(!plugin.is_sync_locations_enabled());

        plugin.set_sync_selection(false);
        assert!(!plugin.is_sync_selection_enabled());
    }

    #[test]
    fn test_sync_clear() {
        let mut plugin = DynamicStaticSyncPlugin::new();
        plugin.add_mapping(
            1,
            SyncMappingEntry::new(0, 0x1000, 0x100, "test"),
        );
        assert_eq!(plugin.total_mapping_count(), 1);

        plugin.clear();
        assert_eq!(plugin.total_mapping_count(), 0);
    }
}
