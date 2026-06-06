//! Trace lifecycle management - trace open/close/save and session tracking.
//!
//! Ported from Ghidra's `DebuggerTraceManagerServicePlugin` (1392 lines)
//! and related service interfaces. This module manages the lifecycle of
//! traces: opening, activating, closing, saving, and tracking active
//! sessions.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// The state of a trace in the manager.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TraceState {
    /// The trace is closed.
    Closed,
    /// The trace is open for reading.
    OpenReadOnly,
    /// The trace is open for reading and writing.
    OpenReadWrite,
    /// The trace is being saved.
    Saving,
    /// The trace has unsaved changes.
    Dirty,
}

/// A record describing an open trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceRecord {
    /// The unique key for this trace.
    pub key: String,
    /// The display name for this trace.
    pub name: String,
    /// The file path, if saved.
    pub path: Option<String>,
    /// The current state.
    pub state: TraceState,
    /// Whether this is the active/focused trace.
    pub is_active: bool,
    /// Whether this trace has unsaved changes.
    pub is_changed: bool,
}

impl TraceRecord {
    /// Create a new trace record.
    pub fn new(key: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            name: name.into(),
            path: None,
            state: TraceState::Closed,
            is_active: false,
            is_changed: false,
        }
    }

    /// Mark the trace as having unsaved changes.
    pub fn mark_changed(&mut self) {
        self.is_changed = true;
        if self.state == TraceState::OpenReadOnly {
            self.state = TraceState::OpenReadWrite;
        }
    }

    /// Mark the trace as saved.
    pub fn mark_saved(&mut self) {
        self.is_changed = false;
    }
}

/// A save task tracks the progress of saving a trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaveTask {
    /// The trace key being saved.
    pub trace_key: String,
    /// The destination path.
    pub destination: String,
    /// Whether this is a "save as" operation.
    pub is_save_as: bool,
    /// The current progress (0.0 to 1.0).
    pub progress: f64,
    /// Whether the save completed successfully.
    pub completed: bool,
    /// Error message if save failed.
    pub error: Option<String>,
}

impl SaveTask {
    /// Create a new save task.
    pub fn new(trace_key: impl Into<String>, destination: impl Into<String>, is_save_as: bool) -> Self {
        Self {
            trace_key: trace_key.into(),
            destination: destination.into(),
            is_save_as,
            progress: 0.0,
            completed: false,
            error: None,
        }
    }

    /// Update progress.
    pub fn set_progress(&mut self, progress: f64) {
        self.progress = progress.clamp(0.0, 1.0);
    }

    /// Mark as completed.
    pub fn complete(&mut self) {
        self.progress = 1.0;
        self.completed = true;
    }

    /// Mark as failed.
    pub fn fail(&mut self, error: impl Into<String>) {
        self.error = Some(error.into());
        self.completed = true;
    }
}

/// The trace manager tracks all open traces and their lifecycle.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TraceManagerService {
    /// All trace records keyed by trace key.
    traces: BTreeMap<String, TraceRecord>,
    /// The currently active trace key.
    active_trace_key: Option<String>,
    /// Pending save tasks.
    save_tasks: Vec<SaveTask>,
    /// Counter for generating unique keys.
    next_key: u64,
}

impl TraceManagerService {
    /// Create a new trace manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Open a new trace.
    pub fn open_trace(&mut self, name: impl Into<String>) -> String {
        let key = format!("trace_{}", self.next_key);
        self.next_key += 1;
        let mut record = TraceRecord::new(&key, name);
        record.state = TraceState::OpenReadWrite;
        self.traces.insert(key.clone(), record);
        key
    }

    /// Close a trace.
    pub fn close_trace(&mut self, key: &str) -> Result<(), String> {
        if let Some(record) = self.traces.get_mut(key) {
            record.state = TraceState::Closed;
            if self.active_trace_key.as_deref() == Some(key) {
                self.active_trace_key = None;
            }
            Ok(())
        } else {
            Err(format!("Trace not found: {}", key))
        }
    }

    /// Remove a trace from the manager entirely.
    pub fn remove_trace(&mut self, key: &str) -> Option<TraceRecord> {
        if self.active_trace_key.as_deref() == Some(key) {
            self.active_trace_key = None;
        }
        self.traces.remove(key)
    }

    /// Activate a trace.
    pub fn activate_trace(&mut self, key: &str) -> Result<(), String> {
        if !self.traces.contains_key(key) {
            return Err(format!("Trace not found: {}", key));
        }
        // Deactivate the current active trace.
        if let Some(ref active) = self.active_trace_key.clone() {
            if let Some(record) = self.traces.get_mut(active) {
                record.is_active = false;
            }
        }
        if let Some(record) = self.traces.get_mut(key) {
            record.is_active = true;
        }
        self.active_trace_key = Some(key.to_string());
        Ok(())
    }

    /// Get the active trace key.
    pub fn active_trace_key(&self) -> Option<&str> {
        self.active_trace_key.as_deref()
    }

    /// Get the active trace record.
    pub fn active_trace(&self) -> Option<&TraceRecord> {
        self.active_trace_key
            .as_ref()
            .and_then(|key| self.traces.get(key))
    }

    /// Get a trace record by key.
    pub fn get_trace(&self, key: &str) -> Option<&TraceRecord> {
        self.traces.get(key)
    }

    /// Get a mutable reference to a trace record by key.
    pub fn get_trace_mut(&mut self, key: &str) -> Option<&mut TraceRecord> {
        self.traces.get_mut(key)
    }

    /// Get all trace keys.
    pub fn trace_keys(&self) -> Vec<&String> {
        self.traces.keys().collect()
    }

    /// Get all trace records.
    pub fn all_traces(&self) -> impl Iterator<Item = &TraceRecord> {
        self.traces.values()
    }

    /// The number of open traces.
    pub fn len(&self) -> usize {
        self.traces.len()
    }

    /// Whether the manager has no open traces.
    pub fn is_empty(&self) -> bool {
        self.traces.is_empty()
    }

    /// Whether any trace has unsaved changes.
    pub fn has_unsaved_changes(&self) -> bool {
        self.traces.values().any(|r| r.is_changed)
    }

    /// Save a trace.
    pub fn save_trace(&mut self, key: &str, path: &str) -> Result<(), String> {
        let record = self
            .traces
            .get_mut(key)
            .ok_or_else(|| format!("Trace not found: {}", key))?;
        record.path = Some(path.to_string());
        record.mark_saved();
        Ok(())
    }

    /// Create a save-as task.
    pub fn save_trace_as(&mut self, key: &str, destination: &str) -> SaveTask {
        let task = SaveTask::new(key, destination, true);
        self.save_tasks.push(task.clone());
        task
    }

    /// Get pending save tasks.
    pub fn save_tasks(&self) -> &[SaveTask] {
        &self.save_tasks
    }

    /// Clear completed save tasks.
    pub fn clear_completed_save_tasks(&mut self) {
        self.save_tasks.retain(|t| !t.completed);
    }

    /// Get traces with unsaved changes.
    pub fn dirty_traces(&self) -> Vec<&TraceRecord> {
        self.traces.values().filter(|r| r.is_changed).collect()
    }

    /// Mark a trace as changed.
    pub fn mark_trace_changed(&mut self, key: &str) {
        if let Some(record) = self.traces.get_mut(key) {
            record.mark_changed();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trace_record_new() {
        let record = TraceRecord::new("k1", "My Trace");
        assert_eq!(record.key, "k1");
        assert_eq!(record.name, "My Trace");
        assert!(record.path.is_none());
        assert_eq!(record.state, TraceState::Closed);
        assert!(!record.is_active);
        assert!(!record.is_changed);
    }

    #[test]
    fn test_trace_record_mark_changed() {
        let mut record = TraceRecord::new("k1", "T");
        record.state = TraceState::OpenReadOnly;
        record.mark_changed();
        assert!(record.is_changed);
        assert_eq!(record.state, TraceState::OpenReadWrite);
    }

    #[test]
    fn test_trace_record_mark_saved() {
        let mut record = TraceRecord::new("k1", "T");
        record.mark_changed();
        record.mark_saved();
        assert!(!record.is_changed);
    }

    #[test]
    fn test_save_task() {
        let mut task = SaveTask::new("trace1", "/tmp/trace.bin", false);
        assert_eq!(task.progress, 0.0);
        assert!(!task.completed);

        task.set_progress(0.5);
        assert_eq!(task.progress, 0.5);

        task.complete();
        assert!(task.completed);
        assert_eq!(task.progress, 1.0);
    }

    #[test]
    fn test_save_task_fail() {
        let mut task = SaveTask::new("trace1", "/tmp/trace.bin", false);
        task.fail("disk full");
        assert!(task.completed);
        assert_eq!(task.error.as_deref(), Some("disk full"));
    }

    #[test]
    fn test_save_task_progress_clamped() {
        let mut task = SaveTask::new("t", "p", false);
        task.set_progress(-0.5);
        assert_eq!(task.progress, 0.0);
        task.set_progress(1.5);
        assert_eq!(task.progress, 1.0);
    }

    #[test]
    fn test_trace_manager_open_close() {
        let mut mgr = TraceManagerService::new();
        let key = mgr.open_trace("Test");
        assert_eq!(mgr.len(), 1);
        assert!(!key.is_empty());

        let record = mgr.get_trace(&key).unwrap();
        assert_eq!(record.name, "Test");
        assert_eq!(record.state, TraceState::OpenReadWrite);

        mgr.close_trace(&key).unwrap();
        let record = mgr.get_trace(&key).unwrap();
        assert_eq!(record.state, TraceState::Closed);
    }

    #[test]
    fn test_trace_manager_activate() {
        let mut mgr = TraceManagerService::new();
        let k1 = mgr.open_trace("T1");
        let k2 = mgr.open_trace("T2");

        assert!(mgr.active_trace_key().is_none());

        mgr.activate_trace(&k1).unwrap();
        assert_eq!(mgr.active_trace_key(), Some(k1.as_str()));
        assert!(mgr.get_trace(&k1).unwrap().is_active);
        assert!(!mgr.get_trace(&k2).unwrap().is_active);

        mgr.activate_trace(&k2).unwrap();
        assert_eq!(mgr.active_trace_key(), Some(k2.as_str()));
        assert!(!mgr.get_trace(&k1).unwrap().is_active);
        assert!(mgr.get_trace(&k2).unwrap().is_active);
    }

    #[test]
    fn test_trace_manager_activate_nonexistent() {
        let mut mgr = TraceManagerService::new();
        assert!(mgr.activate_trace("nonexistent").is_err());
    }

    #[test]
    fn test_trace_manager_close_resets_active() {
        let mut mgr = TraceManagerService::new();
        let k = mgr.open_trace("T");
        mgr.activate_trace(&k).unwrap();
        mgr.close_trace(&k).unwrap();
        assert!(mgr.active_trace_key().is_none());
    }

    #[test]
    fn test_trace_manager_remove() {
        let mut mgr = TraceManagerService::new();
        let k = mgr.open_trace("T");
        mgr.activate_trace(&k).unwrap();
        let removed = mgr.remove_trace(&k);
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().name, "T");
        assert!(mgr.is_empty());
        assert!(mgr.active_trace_key().is_none());
    }

    #[test]
    fn test_trace_manager_save() {
        let mut mgr = TraceManagerService::new();
        let k = mgr.open_trace("T");
        mgr.mark_trace_changed(&k);
        assert!(mgr.get_trace(&k).unwrap().is_changed);
        assert!(mgr.has_unsaved_changes());

        mgr.save_trace(&k, "/tmp/trace.bin").unwrap();
        let record = mgr.get_trace(&k).unwrap();
        assert!(!record.is_changed);
        assert_eq!(record.path.as_deref(), Some("/tmp/trace.bin"));
        assert!(!mgr.has_unsaved_changes());
    }

    #[test]
    fn test_trace_manager_save_as() {
        let mut mgr = TraceManagerService::new();
        let k = mgr.open_trace("T");
        let task = mgr.save_trace_as(&k, "/tmp/new.bin");
        assert!(task.is_save_as);
        assert_eq!(task.destination, "/tmp/new.bin");
        assert_eq!(mgr.save_tasks().len(), 1);

        mgr.clear_completed_save_tasks();
        assert_eq!(mgr.save_tasks().len(), 1); // not completed yet
    }

    #[test]
    fn test_trace_manager_close_nonexistent() {
        let mut mgr = TraceManagerService::new();
        assert!(mgr.close_trace("nonexistent").is_err());
    }

    #[test]
    fn test_trace_manager_dirty_traces() {
        let mut mgr = TraceManagerService::new();
        let k1 = mgr.open_trace("T1");
        let _k2 = mgr.open_trace("T2");
        mgr.mark_trace_changed(&k1);

        let dirty = mgr.dirty_traces();
        assert_eq!(dirty.len(), 1);
        assert_eq!(dirty[0].key, k1);
    }

    #[test]
    fn test_trace_manager_trace_keys() {
        let mut mgr = TraceManagerService::new();
        mgr.open_trace("T1");
        mgr.open_trace("T2");
        let keys = mgr.trace_keys();
        assert_eq!(keys.len(), 2);
    }

    #[test]
    fn test_trace_manager_all_traces() {
        let mut mgr = TraceManagerService::new();
        mgr.open_trace("A");
        mgr.open_trace("B");
        let names: Vec<&str> = mgr.all_traces().map(|r| r.name.as_str()).collect();
        assert!(names.contains(&"A"));
        assert!(names.contains(&"B"));
    }

    #[test]
    fn test_trace_state_serialization() {
        let states = [
            TraceState::Closed,
            TraceState::OpenReadOnly,
            TraceState::OpenReadWrite,
            TraceState::Saving,
            TraceState::Dirty,
        ];
        for state in &states {
            let json = serde_json::to_string(state).unwrap();
            let back: TraceState = serde_json::from_str(&json).unwrap();
            assert_eq!(back, *state);
        }
    }

    #[test]
    fn test_trace_manager_get_mut() {
        let mut mgr = TraceManagerService::new();
        let k = mgr.open_trace("T");
        {
            let record = mgr.get_trace_mut(&k).unwrap();
            record.name = "Renamed".into();
        }
        assert_eq!(mgr.get_trace(&k).unwrap().name, "Renamed");
    }
}
