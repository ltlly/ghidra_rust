//! Save trace task implementations.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.service.tracemgr` package.
//!
//! Provides background task implementations for saving traces:
//! - `SaveTraceTask` - save an existing trace
//! - `SaveTraceAsTask` - save a trace with a new name
//! - `SaveNewTraceTask` - save a new (unsaved) trace

use serde::{Deserialize, Serialize};

/// The outcome of a save trace operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SaveOutcome {
    /// The save completed successfully.
    Success,
    /// The save was cancelled by the user.
    Cancelled,
    /// The save failed with an error.
    Failed(String),
}

impl std::fmt::Display for SaveOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Success => write!(f, "Success"),
            Self::Cancelled => write!(f, "Cancelled"),
            Self::Failed(msg) => write!(f, "Failed: {}", msg),
        }
    }
}

/// A background task for saving a trace.
///
/// Ported from Ghidra's `SaveTraceTask`.
#[derive(Debug, Clone)]
pub struct SaveTraceTask {
    /// The trace identifier to save.
    pub trace_id: String,
    /// The domain file path where the trace should be saved.
    pub save_path: String,
    /// Whether to overwrite an existing file.
    pub overwrite: bool,
    /// Task progress (0.0 - 1.0).
    pub progress: f64,
    /// The outcome of the task, if completed.
    pub outcome: Option<SaveOutcome>,
}

impl SaveTraceTask {
    /// Create a new save trace task.
    pub fn new(trace_id: impl Into<String>, save_path: impl Into<String>) -> Self {
        Self {
            trace_id: trace_id.into(),
            save_path: save_path.into(),
            overwrite: false,
            progress: 0.0,
            outcome: None,
        }
    }

    /// Set whether to overwrite existing files.
    pub fn with_overwrite(mut self, overwrite: bool) -> Self {
        self.overwrite = overwrite;
        self
    }

    /// Execute the save task.
    ///
    /// In a real implementation, this would interact with the domain object
    /// store. Here, it simulates the save lifecycle.
    pub fn execute(&mut self) -> SaveOutcome {
        self.progress = 0.0;

        // Validate
        if self.save_path.is_empty() {
            self.outcome = Some(SaveOutcome::Failed("Empty save path".to_string()));
            return self.outcome.clone().unwrap();
        }

        self.progress = 0.5;

        // Simulate save
        self.progress = 1.0;
        self.outcome = Some(SaveOutcome::Success);
        SaveOutcome::Success
    }

    /// Check if the task has completed.
    pub fn is_complete(&self) -> bool {
        self.outcome.is_some()
    }

    /// Get the task progress (0.0 - 1.0).
    pub fn get_progress(&self) -> f64 {
        self.progress
    }
}

/// A background task for saving a trace with a new name/path.
///
/// Ported from Ghidra's `SaveTraceAsTask`.
#[derive(Debug, Clone)]
pub struct SaveTraceAsTask {
    /// The inner save task.
    pub inner: SaveTraceTask,
    /// The new name for the trace.
    pub new_name: String,
    /// Whether to close the original after saving.
    pub close_original: bool,
}

impl SaveTraceAsTask {
    /// Create a new "save as" task.
    pub fn new(
        trace_id: impl Into<String>,
        save_path: impl Into<String>,
        new_name: impl Into<String>,
    ) -> Self {
        let trace_id_str = trace_id.into();
        Self {
            inner: SaveTraceTask::new(trace_id_str, save_path),
            new_name: new_name.into(),
            close_original: false,
        }
    }

    /// Set whether to close the original trace after saving.
    pub fn with_close_original(mut self, close: bool) -> Self {
        self.close_original = close;
        self
    }

    /// Execute the save-as task.
    pub fn execute(&mut self) -> SaveOutcome {
        self.inner.execute()
    }

    /// Get the new name.
    pub fn new_name(&self) -> &str {
        &self.new_name
    }
}

/// A background task for saving a new (never-before-saved) trace.
///
/// Ported from Ghidra's `SaveNewTraceTask`.
#[derive(Debug, Clone)]
pub struct SaveNewTraceTask {
    /// The inner save task.
    pub inner: SaveTraceTask,
    /// The domain folder path for the new file.
    pub folder_path: String,
    /// Whether to add to the project.
    pub add_to_project: bool,
}

impl SaveNewTraceTask {
    /// Create a new "save new trace" task.
    pub fn new(
        trace_id: impl Into<String>,
        folder_path: impl Into<String>,
        file_name: impl Into<String>,
    ) -> Self {
        let fp = folder_path.into();
        let full_path = format!("{}/{}", fp, file_name.into());
        Self {
            inner: SaveTraceTask::new(trace_id, full_path),
            folder_path: fp,
            add_to_project: true,
        }
    }

    /// Set whether to add to the project after saving.
    pub fn with_add_to_project(mut self, add: bool) -> Self {
        self.add_to_project = add;
        self
    }

    /// Execute the save new trace task.
    pub fn execute(&mut self) -> SaveOutcome {
        self.inner.execute()
    }
}

/// A trace file descriptor for the trace manager.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceFileDescriptor {
    /// The domain file path.
    pub path: String,
    /// The display name.
    pub name: String,
    /// Whether the trace has unsaved changes.
    pub is_dirty: bool,
    /// Whether the trace is currently open.
    pub is_open: bool,
    /// The trace ID.
    pub trace_id: String,
}

impl TraceFileDescriptor {
    /// Create a new trace file descriptor.
    pub fn new(
        path: impl Into<String>,
        name: impl Into<String>,
        trace_id: impl Into<String>,
    ) -> Self {
        Self {
            path: path.into(),
            name: name.into(),
            is_dirty: false,
            is_open: false,
            trace_id: trace_id.into(),
        }
    }

    /// Mark as dirty (has unsaved changes).
    pub fn set_dirty(&mut self, dirty: bool) {
        self.is_dirty = dirty;
    }

    /// Mark as open.
    pub fn set_open(&mut self, open: bool) {
        self.is_open = open;
    }

    /// The file extension, if any.
    pub fn extension(&self) -> Option<&str> {
        let filename = self.path.rsplit('/').next().unwrap_or(&self.path);
        let filename = filename.rsplit('\\').next().unwrap_or(filename);
        if let Some(pos) = filename.rfind('.') {
            if pos > 0 {
                return Some(&filename[pos + 1..]);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_save_trace_task_basic() {
        let mut task = SaveTraceTask::new("trace1", "/path/to/trace.gzf");
        assert!(!task.is_complete());
        assert_eq!(task.get_progress(), 0.0);

        let outcome = task.execute();
        assert_eq!(outcome, SaveOutcome::Success);
        assert!(task.is_complete());
        assert_eq!(task.get_progress(), 1.0);
    }

    #[test]
    fn test_save_trace_task_empty_path() {
        let mut task = SaveTraceTask::new("trace1", "");
        let outcome = task.execute();
        assert_eq!(outcome, SaveOutcome::Failed("Empty save path".to_string()));
    }

    #[test]
    fn test_save_trace_task_with_overwrite() {
        let task = SaveTraceTask::new("trace1", "/path/to/trace.gzf")
            .with_overwrite(true);
        assert!(task.overwrite);
    }

    #[test]
    fn test_save_trace_as_task() {
        let mut task = SaveTraceAsTask::new("trace1", "/path/to/new.gzf", "new_trace")
            .with_close_original(true);
        assert_eq!(task.new_name(), "new_trace");
        assert!(task.close_original);

        let outcome = task.execute();
        assert_eq!(outcome, SaveOutcome::Success);
    }

    #[test]
    fn test_save_new_trace_task() {
        let mut task = SaveNewTraceTask::new("trace1", "/project/traces", "debug.gzf")
            .with_add_to_project(false);
        assert!(!task.add_to_project);

        let outcome = task.execute();
        assert_eq!(outcome, SaveOutcome::Success);
    }

    #[test]
    fn test_save_outcome_display() {
        assert_eq!(SaveOutcome::Success.to_string(), "Success");
        assert_eq!(SaveOutcome::Cancelled.to_string(), "Cancelled");
        assert_eq!(
            SaveOutcome::Failed("disk full".to_string()).to_string(),
            "Failed: disk full"
        );
    }

    #[test]
    fn test_trace_file_descriptor() {
        let mut desc = TraceFileDescriptor::new("/path/to/trace.gzf", "trace", "t1");
        assert!(!desc.is_dirty);
        assert!(!desc.is_open);

        desc.set_dirty(true);
        assert!(desc.is_dirty);

        desc.set_open(true);
        assert!(desc.is_open);

        assert_eq!(desc.extension(), Some("gzf"));
    }

    #[test]
    fn test_trace_file_descriptor_no_ext() {
        let desc = TraceFileDescriptor::new("/path/to/trace", "trace", "t1");
        assert_eq!(desc.extension(), None);
    }

    #[test]
    fn test_save_trace_task_serde() {
        let descriptor = TraceFileDescriptor::new("/path/trace.gzf", "trace", "t1");
        let json = serde_json::to_string(&descriptor).unwrap();
        let back: TraceFileDescriptor = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "trace");
        assert_eq!(back.trace_id, "t1");
    }
}
