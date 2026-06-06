//! Trace tab panel data model.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.gui.trace` package.
//! Provides data model types for the trace tab panel that manages open
//! traces in the debugger tool.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::util::DebugCoordinates;

// ---------------------------------------------------------------------------
// Trace tab entry
// ---------------------------------------------------------------------------

/// A single tab entry in the trace tab panel.
///
/// Ported from Ghidra's `DebuggerTraceTabPanel` tab management.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceTabEntry {
    /// The trace ID.
    pub trace_id: String,
    /// The display name for the tab.
    pub display_name: String,
    /// Whether this tab is currently selected/active.
    pub is_active: bool,
    /// The current coordinates for this tab.
    pub coordinates: Option<DebugCoordinates>,
    /// Whether this trace has unsaved changes.
    pub is_modified: bool,
    /// The tooltip text for the tab.
    pub tooltip: Option<String>,
}

impl TraceTabEntry {
    /// Create a new tab entry.
    pub fn new(trace_id: impl Into<String>, display_name: impl Into<String>) -> Self {
        Self {
            trace_id: trace_id.into(),
            display_name: display_name.into(),
            is_active: false,
            coordinates: None,
            is_modified: false,
            tooltip: None,
        }
    }

    /// Mark this tab as active.
    pub fn activate(&mut self) {
        self.is_active = true;
    }

    /// Mark this tab as inactive.
    pub fn deactivate(&mut self) {
        self.is_active = false;
    }
}

// ---------------------------------------------------------------------------
// Trace tab panel model
// ---------------------------------------------------------------------------

/// The data model for the trace tab panel.
///
/// Ported from Ghidra's `DebuggerTraceTabPanel`. Manages open traces
/// and tab selection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceTabPanelModel {
    /// All open tabs indexed by trace ID.
    pub tabs: BTreeMap<String, TraceTabEntry>,
    /// The currently active trace ID.
    pub active_trace_id: Option<String>,
    /// Ordered list of trace IDs for tab display.
    pub tab_order: Vec<String>,
}

impl TraceTabPanelModel {
    /// Create a new empty tab panel model.
    pub fn new() -> Self {
        Self {
            tabs: BTreeMap::new(),
            active_trace_id: None,
            tab_order: Vec::new(),
        }
    }

    /// Open a new trace tab.
    pub fn open_tab(&mut self, entry: TraceTabEntry) {
        let id = entry.trace_id.clone();
        if !self.tabs.contains_key(&id) {
            self.tab_order.push(id.clone());
        }
        self.tabs.insert(id, entry);
    }

    /// Close a trace tab.
    pub fn close_tab(&mut self, trace_id: &str) {
        self.tabs.remove(trace_id);
        self.tab_order.retain(|id| id != trace_id);
        if self.active_trace_id.as_deref() == Some(trace_id) {
            self.active_trace_id = self.tab_order.last().cloned();
            if let Some(active_id) = &self.active_trace_id {
                if let Some(tab) = self.tabs.get_mut(active_id) {
                    tab.activate();
                }
            }
        }
    }

    /// Activate a trace tab.
    pub fn activate_tab(&mut self, trace_id: &str) {
        // Deactivate current
        if let Some(current_id) = &self.active_trace_id {
            if let Some(tab) = self.tabs.get_mut(current_id) {
                tab.deactivate();
            }
        }
        // Activate new
        if let Some(tab) = self.tabs.get_mut(trace_id) {
            tab.activate();
            self.active_trace_id = Some(trace_id.to_string());
        }
    }

    /// Get the active tab.
    pub fn active_tab(&self) -> Option<&TraceTabEntry> {
        self.active_trace_id
            .as_ref()
            .and_then(|id| self.tabs.get(id))
    }

    /// Get the number of open tabs.
    pub fn tab_count(&self) -> usize {
        self.tabs.len()
    }

    /// Get all tab entries in display order.
    pub fn ordered_tabs(&self) -> Vec<&TraceTabEntry> {
        self.tab_order
            .iter()
            .filter_map(|id| self.tabs.get(id))
            .collect()
    }

    /// Close all tabs.
    pub fn close_all(&mut self) {
        self.tabs.clear();
        self.tab_order.clear();
        self.active_trace_id = None;
    }

    /// Close all tabs except the active one.
    pub fn close_others(&mut self) {
        if let Some(active_id) = self.active_trace_id.clone() {
            let active_tab = self.tabs.get(&active_id).cloned();
            self.tabs.clear();
            self.tab_order.clear();
            if let Some(tab) = active_tab {
                self.tabs.insert(active_id.clone(), tab);
                self.tab_order.push(active_id);
            }
        }
    }

    /// Close tabs that are no longer alive.
    pub fn close_dead_tabs(&mut self, alive_ids: &[String]) {
        let alive: std::collections::HashSet<&str> =
            alive_ids.iter().map(|s| s.as_str()).collect();
        let to_close: Vec<String> = self
            .tabs
            .keys()
            .filter(|id| !alive.contains(id.as_str()))
            .cloned()
            .collect();
        for id in to_close {
            self.close_tab(&id);
        }
    }
}

// ---------------------------------------------------------------------------
// Trace tab event
// ---------------------------------------------------------------------------

/// Events emitted by the trace tab panel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TraceTabEvent {
    /// A new trace was opened.
    TabOpened {
        /// The trace ID.
        trace_id: String,
    },
    /// A trace tab was activated.
    TabActivated {
        /// The trace ID.
        trace_id: String,
    },
    /// A trace tab was closed.
    TabClosed {
        /// The trace ID.
        trace_id: String,
    },
    /// All tabs were closed.
    AllTabsClosed,
}

// ---------------------------------------------------------------------------
// Action contexts
// ---------------------------------------------------------------------------

/// Action context for the trace tab panel.
///
/// Ported from Ghidra's `DebuggerTraceFileActionContext`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceTabActionContext {
    /// The trace ID associated with the context.
    pub trace_id: Option<String>,
    /// The display name.
    pub trace_name: Option<String>,
}

impl TraceTabActionContext {
    /// Create with a specific trace.
    pub fn for_trace(trace_id: impl Into<String>, trace_name: impl Into<String>) -> Self {
        Self {
            trace_id: Some(trace_id.into()),
            trace_name: Some(trace_name.into()),
        }
    }
}

// ---------------------------------------------------------------------------
// Time radix setting
// ---------------------------------------------------------------------------

/// The radix used for displaying time/snap values.
///
/// Ported from Ghidra's `TraceSchedule.TimeRadix`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TimeRadix {
    /// Decimal display.
    Decimal,
    /// Hexadecimal display.
    Hexadecimal,
}

impl Default for TimeRadix {
    fn default() -> Self {
        TimeRadix::Decimal
    }
}

impl TimeRadix {
    /// Format a snap value using this radix.
    pub fn format_snap(&self, snap: i64) -> String {
        match self {
            TimeRadix::Decimal => format!("{}", snap),
            TimeRadix::Hexadecimal => format!("0x{:X}", snap),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trace_tab_entry() {
        let mut entry = TraceTabEntry::new("t1", "My Trace");
        assert!(!entry.is_active);
        entry.activate();
        assert!(entry.is_active);
        entry.deactivate();
        assert!(!entry.is_active);
    }

    #[test]
    fn test_trace_tab_panel_model() {
        let mut model = TraceTabPanelModel::new();
        assert_eq!(model.tab_count(), 0);

        model.open_tab(TraceTabEntry::new("t1", "Trace 1"));
        model.open_tab(TraceTabEntry::new("t2", "Trace 2"));
        assert_eq!(model.tab_count(), 2);

        model.activate_tab("t1");
        assert_eq!(model.active_trace_id.as_deref(), Some("t1"));
        assert!(model.active_tab().unwrap().is_active);

        model.close_tab("t1");
        assert_eq!(model.tab_count(), 1);
        assert_eq!(model.active_trace_id.as_deref(), Some("t2"));
    }

    #[test]
    fn test_close_others() {
        let mut model = TraceTabPanelModel::new();
        model.open_tab(TraceTabEntry::new("t1", "Trace 1"));
        model.open_tab(TraceTabEntry::new("t2", "Trace 2"));
        model.open_tab(TraceTabEntry::new("t3", "Trace 3"));
        model.activate_tab("t2");
        model.close_others();
        assert_eq!(model.tab_count(), 1);
        assert!(model.tabs.contains_key("t2"));
    }

    #[test]
    fn test_close_dead_tabs() {
        let mut model = TraceTabPanelModel::new();
        model.open_tab(TraceTabEntry::new("t1", "Trace 1"));
        model.open_tab(TraceTabEntry::new("t2", "Trace 2"));
        model.open_tab(TraceTabEntry::new("t3", "Trace 3"));
        model.close_dead_tabs(&["t1".into(), "t3".into()]);
        assert_eq!(model.tab_count(), 2);
        assert!(!model.tabs.contains_key("t2"));
    }

    #[test]
    fn test_close_all() {
        let mut model = TraceTabPanelModel::new();
        model.open_tab(TraceTabEntry::new("t1", "Trace 1"));
        model.activate_tab("t1");
        model.close_all();
        assert_eq!(model.tab_count(), 0);
        assert!(model.active_trace_id.is_none());
    }

    #[test]
    fn test_ordered_tabs() {
        let mut model = TraceTabPanelModel::new();
        model.open_tab(TraceTabEntry::new("t2", "Trace 2"));
        model.open_tab(TraceTabEntry::new("t1", "Trace 1"));
        let ordered = model.ordered_tabs();
        assert_eq!(ordered.len(), 2);
        assert_eq!(ordered[0].display_name, "Trace 2");
        assert_eq!(ordered[1].display_name, "Trace 1");
    }

    #[test]
    fn test_time_radix() {
        assert_eq!(TimeRadix::Decimal.format_snap(42), "42");
        assert_eq!(TimeRadix::Hexadecimal.format_snap(255), "0xFF");
        assert_eq!(TimeRadix::default(), TimeRadix::Decimal);
    }

    #[test]
    fn test_trace_tab_event_serialization() {
        let event = TraceTabEvent::TabActivated {
            trace_id: "test".into(),
        };
        let json = serde_json::to_string(&event).unwrap();
        let deserialized: TraceTabEvent = serde_json::from_str(&json).unwrap();
        match deserialized {
            TraceTabEvent::TabActivated { trace_id } => assert_eq!(trace_id, "test"),
            _ => panic!("Wrong variant"),
        }
    }
}
