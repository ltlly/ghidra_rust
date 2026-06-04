//! Thread GUI data model types.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.gui.thread`
//! package in the Debugger module. Provides thread panel data types
//! for displaying processes and threads.

use serde::{Deserialize, Serialize};

use crate::model::thread::TraceThread;

/// A thread row in the threads panel.
///
/// Wraps thread information for display.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadRow {
    /// Thread key.
    pub key: i64,
    /// Thread ID (OS-level).
    pub tid: Option<i64>,
    /// Thread name.
    pub name: String,
    /// Parent process key.
    pub process_key: i64,
    /// Parent process name.
    pub process_name: String,
    /// Parent process ID (OS-level).
    pub pid: Option<i64>,
    /// Execution state string.
    pub execution_state: String,
    /// Whether this thread is currently selected/active.
    pub is_active: bool,
    /// Comment text.
    pub comment: String,
}

impl ThreadRow {
    /// Create a thread row from a `TraceThread`.
    pub fn from_thread(thread: &TraceThread, process_name: &str, pid: Option<i64>) -> Self {
        Self {
            key: thread.key,
            tid: thread.tid,
            name: thread.name.clone(),
            process_key: 0, // Extracted from path in real implementation
            process_name: process_name.to_string(),
            pid,
            execution_state: format!("{:?}", thread.execution_state),
            is_active: false,
            comment: thread.comment.clone().unwrap_or_default(),
        }
    }

    /// Display name including process.
    pub fn display_name(&self) -> String {
        if self.name.is_empty() {
            format!("Thread {} [{}]", self.key, self.tid.unwrap_or(0))
        } else {
            self.name.clone()
        }
    }

    /// Display name of the parent process.
    pub fn process_display_name(&self) -> String {
        if self.process_name.is_empty() {
            format!("Process {} [{}]", self.process_key, self.pid.unwrap_or(0))
        } else {
            self.process_name.clone()
        }
    }
}

/// Column definitions for the threads table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ThreadColumn {
    /// Thread name.
    Name,
    /// Thread ID.
    Tid,
    /// Process name.
    Process,
    /// Process ID.
    Pid,
    /// Execution state.
    State,
    /// Comment.
    Comment,
}

/// Model for the threads display panel.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ThreadTableModel {
    rows: Vec<ThreadRow>,
    selected_key: Option<i64>,
}

impl ThreadTableModel {
    /// Create a new thread model.
    pub fn new() -> Self {
        Self::default()
    }

    /// The number of rows.
    pub fn row_count(&self) -> usize {
        self.rows.len()
    }

    /// Get all rows.
    pub fn rows(&self) -> &[ThreadRow] {
        &self.rows
    }

    /// Add a thread row.
    pub fn add_row(&mut self, row: ThreadRow) {
        self.rows.push(row);
    }

    /// Remove a thread row by key.
    pub fn remove_row(&mut self, key: i64) -> bool {
        let before = self.rows.len();
        self.rows.retain(|r| r.key != key);
        self.rows.len() < before
    }

    /// Get a thread row by key.
    pub fn get(&self, key: i64) -> Option<&ThreadRow> {
        self.rows.iter().find(|r| r.key == key)
    }

    /// Set the selected thread.
    pub fn set_selected(&mut self, key: Option<i64>) {
        self.selected_key = key;
        for row in &mut self.rows {
            row.is_active = Some(row.key) == key;
        }
    }

    /// Get the selected thread key.
    pub fn selected_key(&self) -> Option<i64> {
        self.selected_key
    }

    /// Get the selected thread row.
    pub fn selected_row(&self) -> Option<&ThreadRow> {
        self.selected_key.and_then(|k| self.get(k))
    }

    /// Get all rows belonging to a specific process.
    pub fn rows_for_process(&self, process_key: i64) -> Vec<&ThreadRow> {
        self.rows.iter().filter(|r| r.process_key == process_key).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::execution_state::TraceExecutionState;
    use crate::model::thread::TraceThread;

    fn make_thread(key: i64, name: &str) -> TraceThread {
        TraceThread {
            key,
            path: format!("Threads[{}]", key),
            tid: Some(key * 100),
            name: name.to_string(),
            comment: None,
            execution_state: TraceExecutionState::Running,
            lifespan: crate::model::Lifespan::ALL,
        }
    }

    #[test]
    fn test_thread_row_from_thread() {
        let thread = make_thread(1, "main");
        let row = ThreadRow::from_thread(&thread, "myapp", Some(42));
        assert_eq!(row.key, 1);
        assert_eq!(row.tid, Some(100));
        assert_eq!(row.name, "main");
        assert_eq!(row.process_name, "myapp");
        assert_eq!(row.pid, Some(42));
    }

    #[test]
    fn test_thread_row_display_name() {
        let thread = make_thread(1, "main");
        let row = ThreadRow::from_thread(&thread, "myapp", Some(42));
        assert_eq!(row.display_name(), "main");

        let thread2 = TraceThread {
            key: 2,
            path: "Threads[2]".to_string(),
            tid: Some(200),
            name: String::new(),
            comment: None,
            execution_state: TraceExecutionState::Running,
            lifespan: crate::model::Lifespan::ALL,
        };
        let row2 = ThreadRow::from_thread(&thread2, "myapp", Some(42));
        assert_eq!(row2.display_name(), "Thread 2 [200]");
    }

    #[test]
    fn test_thread_table_model() {
        let mut model = ThreadTableModel::new();
        model.add_row(ThreadRow::from_thread(
            &make_thread(1, "main"),
            "myapp",
            Some(10),
        ));
        model.add_row(ThreadRow::from_thread(
            &make_thread(2, "worker"),
            "myapp",
            Some(10),
        ));

        assert_eq!(model.row_count(), 2);
        assert!(model.get(1).is_some());
        assert!(model.get(99).is_none());
    }

    #[test]
    fn test_thread_table_model_select() {
        let mut model = ThreadTableModel::new();
        model.add_row(ThreadRow::from_thread(
            &make_thread(1, "main"),
            "myapp",
            Some(10),
        ));

        model.set_selected(Some(1));
        assert_eq!(model.selected_key(), Some(1));
        assert!(model.get(1).unwrap().is_active);
    }

    #[test]
    fn test_thread_table_model_remove() {
        let mut model = ThreadTableModel::new();
        model.add_row(ThreadRow::from_thread(
            &make_thread(1, "main"),
            "myapp",
            Some(10),
        ));
        assert!(model.remove_row(1));
        assert_eq!(model.row_count(), 0);
        assert!(!model.remove_row(1));
    }
}
