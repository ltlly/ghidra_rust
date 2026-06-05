//! DebuggerTraceManagerService - service for managing open traces.
//!
//! Ported from Ghidra's `ghidra.app.services.DebuggerTraceManagerService`.

use serde::{Deserialize, Serialize};

/// Service interface for managing the lifecycle of open traces.
pub trait DebuggerTraceManagerServiceExt {
    /// Get the currently active trace key, if any.
    fn active_trace(&self) -> Option<i64>;

    /// Open a trace for viewing.
    fn open_trace(&mut self, trace_key: i64) -> Result<(), String>;

    /// Close a trace.
    fn close_trace(&mut self, trace_key: i64) -> Result<(), String>;

    /// Activate (bring to focus) a trace.
    fn activate_trace(&mut self, trace_key: i64) -> Result<(), String>;

    /// Get all open trace keys.
    fn open_traces(&self) -> Vec<i64>;

    /// Save a trace.
    fn save_trace(&mut self, trace_key: i64) -> Result<(), String>;

    /// Save a trace as a new file.
    fn save_trace_as(
        &mut self,
        trace_key: i64,
        path: &str,
    ) -> Result<(), String>;

    /// Export a trace.
    fn export_trace(
        &mut self,
        trace_key: i64,
        path: &str,
        format: &str,
    ) -> Result<(), String>;

    /// Import a trace from a file.
    fn import_trace(&mut self, path: &str) -> Result<i64, String>;
}

/// Information about an open trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceManagerEntry {
    /// The trace key.
    pub key: i64,
    /// The trace name.
    pub name: String,
    /// The file path, if saved.
    pub path: Option<String>,
    /// Whether this trace is active.
    pub is_active: bool,
    /// Whether this trace has unsaved changes.
    pub is_dirty: bool,
}

/// Save task kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SaveKind {
    /// Save to existing file.
    Save,
    /// Save as new file.
    SaveAs,
    /// Export to a different format.
    Export,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trace_manager_entry() {
        let entry = TraceManagerEntry {
            key: 1,
            name: "test.trace".into(),
            path: Some("/tmp/test.trace".into()),
            is_active: true,
            is_dirty: false,
        };
        assert!(entry.is_active);
        assert!(!entry.is_dirty);
    }

    #[test]
    fn test_save_kind() {
        assert_ne!(SaveKind::Save, SaveKind::SaveAs);
        assert_ne!(SaveKind::Export, SaveKind::Save);
    }
}
