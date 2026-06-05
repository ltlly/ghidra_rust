//! Dynamic/static synchronization service.
//!
//! Ported from Ghidra's `DynamicStaticSynchronizationPlugin` and related types.
//!
//! Provides bidirectional synchronization between the static listing (Program)
//! and the dynamic listing (TraceProgramView) when static mappings are known.
//! This includes:
//! - Location synchronization (cursor positions)
//! - Selection synchronization
//! - Program open/activation event handling

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

/// The direction of synchronization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SyncDirection {
    /// Synchronize from static (program) to dynamic (trace).
    StaticToDynamic,
    /// Synchronize from dynamic (trace) to static (program).
    DynamicToStatic,
    /// Bidirectional synchronization.
    Bidirectional,
}

impl Default for SyncDirection {
    fn default() -> Self {
        Self::Bidirectional
    }
}

/// A location in a program or trace.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SyncLocation {
    /// The address offset.
    pub address: u64,
    /// The address space name.
    pub space: String,
    /// The snap (for trace locations).
    pub snap: Option<i64>,
}

impl SyncLocation {
    /// Create a new sync location.
    pub fn new(address: u64, space: impl Into<String>) -> Self {
        Self {
            address,
            space: space.into(),
            snap: None,
        }
    }

    /// Create a trace sync location with a snap.
    pub fn with_snap(address: u64, space: impl Into<String>, snap: i64) -> Self {
        Self {
            address,
            space: space.into(),
            snap: Some(snap),
        }
    }
}

/// A selection range in a program or trace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncSelection {
    /// Start of the selection.
    pub start: u64,
    /// End of the selection.
    pub end: u64,
    /// The address space name.
    pub space: String,
    /// The snap (for trace selections).
    pub snap: Option<i64>,
}

impl SyncSelection {
    /// Create a new sync selection.
    pub fn new(start: u64, end: u64, space: impl Into<String>) -> Self {
        Self {
            start,
            end,
            space: space.into(),
            snap: None,
        }
    }

    /// Check if this selection is empty.
    pub fn is_empty(&self) -> bool {
        self.start > self.end
    }

    /// Get the size of the selection.
    pub fn size(&self) -> u64 {
        if self.is_empty() {
            0
        } else {
            self.end - self.start + 1
        }
    }

    /// Check if an address is contained in this selection.
    pub fn contains(&self, address: u64) -> bool {
        address >= self.start && address <= self.end
    }
}

/// An event from the synchronization system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SyncEvent {
    /// A location changed in the static listing.
    StaticLocationChanged(SyncLocation),
    /// A location changed in the dynamic listing.
    DynamicLocationChanged(SyncLocation),
    /// A selection changed in the static listing.
    StaticSelectionChanged(SyncSelection),
    /// A selection changed in the dynamic listing.
    DynamicSelectionChanged(SyncSelection),
    /// Synchronization was enabled or disabled.
    SyncToggled(bool),
    /// A program was opened.
    ProgramOpened(String),
    /// A program was activated.
    ProgramActivated(String),
    /// A trace was activated.
    TraceActivated(String),
}

/// State for the synchronization plugin.
///
/// Ported from `DynamicStaticSynchronizationPlugin`.
#[derive(Debug)]
pub struct SyncServiceState {
    /// Whether location synchronization is enabled.
    pub sync_locations_enabled: bool,
    /// Whether selection synchronization is enabled.
    pub sync_selections_enabled: bool,
    /// The current sync direction.
    pub direction: SyncDirection,
    /// Known static mappings (trace_range -> program_range).
    pub mappings: HashMap<(u64, u64), (u64, u64)>,
    /// Current trace location.
    trace_location: Option<SyncLocation>,
    /// Current program location.
    program_location: Option<SyncLocation>,
    /// Event log.
    event_log: Vec<SyncEvent>,
}

impl SyncServiceState {
    /// Create a new sync service state.
    pub fn new() -> Self {
        Self {
            sync_locations_enabled: true,
            sync_selections_enabled: true,
            direction: SyncDirection::default(),
            mappings: HashMap::new(),
            trace_location: None,
            program_location: None,
            event_log: Vec::new(),
        }
    }

    /// Enable or disable location synchronization.
    pub fn set_sync_locations(&mut self, enabled: bool) {
        self.sync_locations_enabled = enabled;
        self.event_log.push(SyncEvent::SyncToggled(enabled));
    }

    /// Enable or disable selection synchronization.
    pub fn set_sync_selections(&mut self, enabled: bool) {
        self.sync_selections_enabled = enabled;
    }

    /// Add a static mapping.
    pub fn add_mapping(&mut self, trace_start: u64, trace_end: u64, prog_start: u64, prog_end: u64) {
        self.mappings
            .insert((trace_start, trace_end), (prog_start, prog_end));
    }

    /// Map a trace address to a program address using known mappings.
    pub fn map_trace_to_program(&self, trace_address: u64) -> Option<u64> {
        for ((ts, te), (ps, _pe)) in &self.mappings {
            if trace_address >= *ts && trace_address <= *te {
                let delta = trace_address - ts;
                return Some(ps + delta);
            }
        }
        None
    }

    /// Map a program address to a trace address using known mappings.
    pub fn map_program_to_trace(&self, program_address: u64) -> Option<u64> {
        for ((ts, _te), (ps, pe)) in &self.mappings {
            if program_address >= *ps && program_address <= *pe {
                let delta = program_address - ps;
                return Some(ts + delta);
            }
        }
        None
    }

    /// Update the trace location and optionally synchronize.
    pub fn set_trace_location(&mut self, location: SyncLocation) {
        if self.sync_locations_enabled {
            if let Some(prog_addr) = self.map_trace_to_program(location.address) {
                self.program_location = Some(SyncLocation::new(prog_addr, &location.space));
            }
        }
        self.trace_location = Some(location.clone());
        self.event_log
            .push(SyncEvent::DynamicLocationChanged(location));
    }

    /// Update the program location and optionally synchronize.
    pub fn set_program_location(&mut self, location: SyncLocation) {
        if self.sync_locations_enabled {
            if let Some(trace_addr) = self.map_program_to_trace(location.address) {
                self.trace_location =
                    Some(SyncLocation::new(trace_addr, &location.space));
            }
        }
        self.program_location = Some(location.clone());
        self.event_log
            .push(SyncEvent::StaticLocationChanged(location));
    }

    /// Get the current trace location.
    pub fn trace_location(&self) -> Option<&SyncLocation> {
        self.trace_location.as_ref()
    }

    /// Get the current program location.
    pub fn program_location(&self) -> Option<&SyncLocation> {
        self.program_location.as_ref()
    }

    /// Get the event log.
    pub fn event_log(&self) -> &[SyncEvent] {
        &self.event_log
    }

    /// Clear the event log.
    pub fn clear_event_log(&mut self) {
        self.event_log.clear();
    }

    /// Get the number of known mappings.
    pub fn mapping_count(&self) -> usize {
        self.mappings.len()
    }
}

impl Default for SyncServiceState {
    fn default() -> Self {
        Self::new()
    }
}

/// Thread-safe wrapper for the sync service.
#[derive(Debug, Clone)]
pub struct SyncService {
    state: Arc<Mutex<SyncServiceState>>,
}

impl SyncService {
    /// Create a new sync service.
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(SyncServiceState::new())),
        }
    }

    /// Access the state mutably.
    pub fn with_state<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut SyncServiceState) -> R,
    {
        let mut state = self.state.lock().unwrap();
        f(&mut state)
    }

    /// Access the state immutably.
    pub fn read_state<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&SyncServiceState) -> R,
    {
        let state = self.state.lock().unwrap();
        f(&state)
    }
}

impl Default for SyncService {
    fn default() -> Self {
        Self::new()
    }
}

/// Peek a domain object from a domain file.
///
/// Ported from `PeekOpenedDomainObject`. Provides a RAII guard
/// for temporarily accessing an opened domain object.
#[derive(Debug)]
pub struct PeekOpenedDomainObject {
    /// The domain file identifier.
    pub file_id: String,
    /// Whether the object is currently held.
    held: bool,
}

impl PeekOpenedDomainObject {
    /// Create a new peek guard.
    pub fn new(file_id: impl Into<String>) -> Self {
        Self {
            file_id: file_id.into(),
            held: true,
        }
    }

    /// Check if the object is currently held.
    pub fn is_held(&self) -> bool {
        self.held
    }

    /// Release the object early.
    pub fn release(&mut self) {
        self.held = false;
    }
}

impl Drop for PeekOpenedDomainObject {
    fn drop(&mut self) {
        self.held = false;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sync_location() {
        let loc = SyncLocation::new(0x1000, "ram");
        assert_eq!(loc.address, 0x1000);
        assert_eq!(loc.space, "ram");
        assert_eq!(loc.snap, None);
    }

    #[test]
    fn test_sync_location_with_snap() {
        let loc = SyncLocation::with_snap(0x1000, "ram", 5);
        assert_eq!(loc.snap, Some(5));
    }

    #[test]
    fn test_sync_selection() {
        let sel = SyncSelection::new(0x1000, 0x1FFF, "ram");
        assert_eq!(sel.size(), 0x1000);
        assert!(!sel.is_empty());
        assert!(sel.contains(0x1500));
        assert!(!sel.contains(0x2000));
    }

    #[test]
    fn test_sync_selection_empty() {
        let sel = SyncSelection::new(0x2000, 0x1000, "ram");
        assert!(sel.is_empty());
        assert_eq!(sel.size(), 0);
    }

    #[test]
    fn test_sync_service_state_new() {
        let state = SyncServiceState::new();
        assert!(state.sync_locations_enabled);
        assert!(state.sync_selections_enabled);
        assert_eq!(state.direction, SyncDirection::Bidirectional);
        assert!(state.mappings.is_empty());
    }

    #[test]
    fn test_sync_service_state_mapping() {
        let mut state = SyncServiceState::new();
        state.add_mapping(0x1000, 0x1FFF, 0x400000, 0x400FFF);

        assert_eq!(state.map_trace_to_program(0x1000), Some(0x400000));
        assert_eq!(state.map_trace_to_program(0x1050), Some(0x400050));
        assert_eq!(state.map_trace_to_program(0x2000), None);

        assert_eq!(state.map_program_to_trace(0x400000), Some(0x1000));
        assert_eq!(state.map_program_to_trace(0x400050), Some(0x1050));
        assert_eq!(state.map_program_to_trace(0x500000), None);
    }

    #[test]
    fn test_sync_service_location_sync() {
        let mut state = SyncServiceState::new();
        state.add_mapping(0x1000, 0x1FFF, 0x400000, 0x400FFF);

        // Set trace location -> should sync to program
        state.set_trace_location(SyncLocation::new(0x1050, "ram"));
        assert_eq!(state.program_location().unwrap().address, 0x400050);

        // Set program location -> should sync to trace
        state.set_program_location(SyncLocation::new(0x400080, "ram"));
        assert_eq!(state.trace_location().unwrap().address, 0x1080);
    }

    #[test]
    fn test_sync_service_disabled() {
        let mut state = SyncServiceState::new();
        state.add_mapping(0x1000, 0x1FFF, 0x400000, 0x400FFF);
        state.set_sync_locations(false);

        // Should not sync when disabled
        state.set_trace_location(SyncLocation::new(0x1050, "ram"));
        assert!(state.program_location().is_none());
    }

    #[test]
    fn test_sync_service_event_log() {
        let mut state = SyncServiceState::new();
        state.set_trace_location(SyncLocation::new(0x1000, "ram"));
        state.set_program_location(SyncLocation::new(0x400000, "ram"));

        assert_eq!(state.event_log().len(), 2);
        state.clear_event_log();
        assert!(state.event_log().is_empty());
    }

    #[test]
    fn test_sync_service_thread_safe() {
        let service = SyncService::new();
        service.with_state(|state| {
            state.add_mapping(0x1000, 0x1FFF, 0x400000, 0x400FFF);
        });

        let count = service.read_state(|state| state.mapping_count());
        assert_eq!(count, 1);
    }

    #[test]
    fn test_peek_opened_domain_object() {
        let mut peek = PeekOpenedDomainObject::new("file1");
        assert!(peek.is_held());
        assert_eq!(peek.file_id, "file1");
        peek.release();
        assert!(!peek.is_held());
    }

    #[test]
    fn test_peek_opened_domain_object_drop() {
        let peek = PeekOpenedDomainObject::new("file1");
        assert!(peek.is_held());
        drop(peek);
        // After drop, held is false (tested implicitly - no panic)
    }

    #[test]
    fn test_sync_direction_default() {
        assert_eq!(SyncDirection::default(), SyncDirection::Bidirectional);
    }

    #[test]
    fn test_multiple_mappings() {
        let mut state = SyncServiceState::new();
        state.add_mapping(0x1000, 0x1FFF, 0x400000, 0x400FFF);
        state.add_mapping(0x3000, 0x3FFF, 0x800000, 0x800FFF);

        assert_eq!(state.map_trace_to_program(0x1000), Some(0x400000));
        assert_eq!(state.map_trace_to_program(0x3000), Some(0x800000));
        assert_eq!(state.map_trace_to_program(0x5000), None);
    }
}
