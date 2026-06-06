//! Memory view trace event listener data model.
//!
//! Ported from Ghidra's `DebuggerMemviewTraceListener` in
//! `ghidra.app.plugin.core.debug.gui.memview`. Provides a data model
//! that listens for trace events and updates the memory view accordingly.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::plugin::gui_memview::{MemviewBoxType, MemoryBox};

/// A trace event that can update the memory view.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MemviewTraceEvent {
    /// Memory bytes changed.
    MemoryChanged {
        /// The snap at which the change occurred.
        snap: i64,
        /// The start address.
        address: u64,
        /// The number of bytes changed.
        length: usize,
    },
    /// A thread was added.
    ThreadAdded {
        /// The snap.
        snap: i64,
        /// Thread name.
        name: String,
    },
    /// A thread was removed.
    ThreadRemoved {
        /// The snap.
        snap: i64,
        /// Thread name.
        name: String,
    },
    /// A module was loaded.
    ModuleLoaded {
        /// The snap.
        snap: i64,
        /// Module name.
        name: String,
        /// Start address.
        base_address: u64,
        /// Module size.
        length: u64,
    },
    /// A module was unloaded.
    ModuleUnloaded {
        /// The snap.
        snap: i64,
        /// Module name.
        name: String,
    },
    /// A memory region was added.
    RegionAdded {
        /// The snap.
        snap: i64,
        /// Region name.
        name: String,
        /// Start address.
        start_address: u64,
        /// Region length.
        length: u64,
    },
    /// A memory region was removed.
    RegionRemoved {
        /// The snap.
        snap: i64,
        /// Region name.
        name: String,
    },
    /// A breakpoint was set.
    BreakpointSet {
        /// The snap.
        snap: i64,
        /// Address.
        address: u64,
    },
    /// A breakpoint was removed.
    BreakpointRemoved {
        /// The snap.
        snap: i64,
        /// Address.
        address: u64,
    },
    /// The trace was restored (full refresh needed).
    TraceRestored,
}

/// The listener state for the memory view.
///
/// Tracks the accumulated events and converts them into `MemoryBox`
/// entries for the memory view visualization.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MemviewTraceListener {
    /// Accumulated events.
    events: Vec<MemviewTraceEvent>,
    /// Generated memory boxes indexed by (address, snap).
    box_map: BTreeMap<(u64, i64), MemviewBoxType>,
    /// Whether a full refresh is needed.
    needs_refresh: bool,
}

impl MemviewTraceListener {
    /// Create a new listener.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a trace event.
    pub fn on_event(&mut self, event: MemviewTraceEvent) {
        match &event {
            MemviewTraceEvent::TraceRestored => {
                self.needs_refresh = true;
                self.box_map.clear();
                self.events.clear();
            }
            MemviewTraceEvent::MemoryChanged { snap, address, length } => {
                for offset in 0..*length as u64 {
                    self.box_map
                        .entry((*address + offset, *snap))
                        .or_insert(MemviewBoxType::ReadMemory);
                }
            }
            MemviewTraceEvent::ThreadAdded { snap, .. } => {
                self.box_map
                    .entry((0, *snap))
                    .or_insert(MemviewBoxType::Thread);
            }
            MemviewTraceEvent::ThreadRemoved { snap, .. } => {
                self.box_map
                    .entry((0, *snap))
                    .or_insert(MemviewBoxType::Thread);
            }
            MemviewTraceEvent::ModuleLoaded { snap, base_address, length, .. } => {
                for addr in (*base_address..*base_address + *length).step_by(0x1000) {
                    self.box_map
                        .entry((addr, *snap))
                        .or_insert(MemviewBoxType::Module);
                }
            }
            MemviewTraceEvent::ModuleUnloaded { snap, .. } => {
                self.box_map
                    .entry((0, *snap))
                    .or_insert(MemviewBoxType::Module);
            }
            MemviewTraceEvent::RegionAdded { snap, start_address, length, .. } => {
                for addr in (*start_address..*start_address + *length).step_by(0x1000) {
                    self.box_map
                        .entry((addr, *snap))
                        .or_insert(MemviewBoxType::Region);
                }
            }
            MemviewTraceEvent::RegionRemoved { snap, .. } => {
                self.box_map
                    .entry((0, *snap))
                    .or_insert(MemviewBoxType::Region);
            }
            MemviewTraceEvent::BreakpointSet { snap, address } => {
                self.box_map
                    .entry((*address, *snap))
                    .or_insert(MemviewBoxType::Breakpoint);
            }
            MemviewTraceEvent::BreakpointRemoved { snap, address } => {
                self.box_map
                    .entry((*address, *snap))
                    .or_insert(MemviewBoxType::Breakpoint);
            }
        }
        self.events.push(event);
    }

    /// Whether a full refresh is needed.
    pub fn needs_refresh(&self) -> bool {
        self.needs_refresh
    }

    /// Acknowledge the refresh.
    pub fn ack_refresh(&mut self) {
        self.needs_refresh = false;
    }

    /// Get all accumulated events.
    pub fn events(&self) -> &[MemviewTraceEvent] {
        &self.events
    }

    /// Convert the accumulated state into a list of MemoryBox entries.
    pub fn to_memory_boxes(&self) -> Vec<MemoryBox> {
        self.box_map
            .iter()
            .map(|(&(address, snap), &box_type)| MemoryBox::new(address, snap, box_type, 1))
            .collect()
    }

    /// Clear all state.
    pub fn clear(&mut self) {
        self.events.clear();
        self.box_map.clear();
        self.needs_refresh = false;
    }

    /// Get the number of tracked events.
    pub fn event_count(&self) -> usize {
        self.events.len()
    }

    /// Get the number of distinct memory boxes.
    pub fn box_count(&self) -> usize {
        self.box_map.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_listener_memory_changed() {
        let mut listener = MemviewTraceListener::new();
        listener.on_event(MemviewTraceEvent::MemoryChanged {
            snap: 0,
            address: 0x400000,
            length: 4,
        });
        assert_eq!(listener.box_count(), 4);
        let boxes = listener.to_memory_boxes();
        assert!(boxes.iter().all(|b| b.box_type == MemviewBoxType::ReadMemory));
    }

    #[test]
    fn test_listener_trace_restored() {
        let mut listener = MemviewTraceListener::new();
        listener.on_event(MemviewTraceEvent::MemoryChanged {
            snap: 0,
            address: 0x400000,
            length: 2,
        });
        assert_eq!(listener.box_count(), 2);

        listener.on_event(MemviewTraceEvent::TraceRestored);
        assert!(listener.needs_refresh());
        assert_eq!(listener.box_count(), 0);
    }

    #[test]
    fn test_listener_module_loaded() {
        let mut listener = MemviewTraceListener::new();
        listener.on_event(MemviewTraceEvent::ModuleLoaded {
            snap: 0,
            name: "libc.so".into(),
            base_address: 0x7f0000000000,
            length: 0x20000,
        });
        assert!(listener.box_count() > 0);
    }

    #[test]
    fn test_listener_breakpoint() {
        let mut listener = MemviewTraceListener::new();
        listener.on_event(MemviewTraceEvent::BreakpointSet {
            snap: 0,
            address: 0x400000,
        });
        let boxes = listener.to_memory_boxes();
        assert_eq!(boxes.len(), 1);
        assert_eq!(boxes[0].box_type, MemviewBoxType::Breakpoint);
    }

    #[test]
    fn test_listener_clear() {
        let mut listener = MemviewTraceListener::new();
        listener.on_event(MemviewTraceEvent::MemoryChanged {
            snap: 0,
            address: 0x400000,
            length: 2,
        });
        listener.clear();
        assert_eq!(listener.event_count(), 0);
        assert_eq!(listener.box_count(), 0);
    }

    #[test]
    fn test_listener_multiple_snaps() {
        let mut listener = MemviewTraceListener::new();
        listener.on_event(MemviewTraceEvent::MemoryChanged {
            snap: 0,
            address: 0x400000,
            length: 1,
        });
        listener.on_event(MemviewTraceEvent::MemoryChanged {
            snap: 1,
            address: 0x400000,
            length: 1,
        });
        assert_eq!(listener.box_count(), 2);
    }

    #[test]
    fn test_listener_region_added() {
        let mut listener = MemviewTraceListener::new();
        listener.on_event(MemviewTraceEvent::RegionAdded {
            snap: 0,
            name: "stack".into(),
            start_address: 0x7fff00000000,
            length: 0x10000,
        });
        assert!(listener.box_count() > 0);
        let boxes = listener.to_memory_boxes();
        assert!(boxes.iter().all(|b| b.box_type == MemviewBoxType::Region));
    }
}
