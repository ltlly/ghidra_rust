//! Extended trace manager service implementation types.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.service.tracemgr` package.
//! Provides save task types for the trace manager service.

use std::path::PathBuf;

/// Kind of save operation for a trace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SaveKind {
    /// Save to the existing location.
    Save,
    /// Save to a new location (Save As).
    SaveAs,
    /// Save a new (unsaved) trace for the first time.
    SaveNew,
}

/// A task to save a trace.
///
/// Corresponds to Java's `AbstractSaveTraceTask`, `SaveTraceTask`,
/// `SaveTraceAsTask`, and `SaveNewTraceTask`.
#[derive(Debug, Clone)]
pub struct SaveTraceTask {
    /// The trace key to save.
    pub trace_key: i64,
    /// The kind of save operation.
    pub save_kind: SaveKind,
    /// The target path for SaveAs/SaveNew.
    pub target_path: Option<PathBuf>,
    /// Whether the save completed successfully.
    pub completed: bool,
    /// Error message if the save failed.
    pub error: Option<String>,
    /// Progress (0.0 to 1.0).
    pub progress: f64,
}

impl SaveTraceTask {
    /// Create a save task for an existing trace.
    pub fn save(trace_key: i64) -> Self {
        Self {
            trace_key,
            save_kind: SaveKind::Save,
            target_path: None,
            completed: false,
            error: None,
            progress: 0.0,
        }
    }

    /// Create a "Save As" task.
    pub fn save_as(trace_key: i64, target: PathBuf) -> Self {
        Self {
            trace_key,
            save_kind: SaveKind::SaveAs,
            target_path: Some(target),
            completed: false,
            error: None,
            progress: 0.0,
        }
    }

    /// Create a "Save New" task.
    pub fn save_new(trace_key: i64, target: PathBuf) -> Self {
        Self {
            trace_key,
            save_kind: SaveKind::SaveNew,
            target_path: Some(target),
            completed: false,
            error: None,
            progress: 0.0,
        }
    }

    /// Mark the task as completed.
    pub fn mark_completed(&mut self) {
        self.completed = true;
        self.progress = 1.0;
    }

    /// Set an error and mark as completed.
    pub fn set_error(&mut self, error: impl Into<String>) {
        self.error = Some(error.into());
        self.completed = true;
    }

    /// Update progress.
    pub fn set_progress(&mut self, progress: f64) {
        self.progress = progress.clamp(0.0, 1.0);
    }

    /// Check if the task has an error.
    pub fn has_error(&self) -> bool {
        self.error.is_some()
    }
}

/// Manager for pending save tasks.
#[derive(Debug)]
pub struct SaveTaskManager {
    /// Pending save tasks indexed by trace key.
    tasks: Vec<SaveTraceTask>,
}

impl SaveTaskManager {
    /// Create a new save task manager.
    pub fn new() -> Self {
        Self { tasks: Vec::new() }
    }

    /// Submit a save task.
    pub fn submit(&mut self, task: SaveTraceTask) {
        self.tasks.push(task);
    }

    /// Get the number of pending tasks.
    pub fn pending_count(&self) -> usize {
        self.tasks.iter().filter(|t| !t.completed).count()
    }

    /// Get all tasks for a trace.
    pub fn tasks_for_trace(&self, trace_key: i64) -> Vec<&SaveTraceTask> {
        self.tasks.iter().filter(|t| t.trace_key == trace_key).collect()
    }

    /// Complete the first pending task for a trace.
    pub fn complete_next(&mut self, trace_key: i64) -> bool {
        if let Some(task) = self.tasks.iter_mut().find(|t| t.trace_key == trace_key && !t.completed) {
            task.mark_completed();
            true
        } else {
            false
        }
    }

    /// Get all completed tasks.
    pub fn completed_tasks(&self) -> Vec<&SaveTraceTask> {
        self.tasks.iter().filter(|t| t.completed).collect()
    }

    /// Remove all completed tasks.
    pub fn clear_completed(&mut self) {
        self.tasks.retain(|t| !t.completed);
    }

    /// Check if there are any pending tasks.
    pub fn has_pending(&self) -> bool {
        self.tasks.iter().any(|t| !t.completed)
    }
}

impl Default for SaveTaskManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_save_trace_task_save() {
        let task = SaveTraceTask::save(1);
        assert_eq!(task.save_kind, SaveKind::Save);
        assert!(task.target_path.is_none());
        assert!(!task.completed);
    }

    #[test]
    fn test_save_trace_task_save_as() {
        let task = SaveTraceTask::save_as(1, PathBuf::from("/tmp/trace.db"));
        assert_eq!(task.save_kind, SaveKind::SaveAs);
        assert!(task.target_path.is_some());
    }

    #[test]
    fn test_save_trace_task_save_new() {
        let task = SaveTraceTask::save_new(1, PathBuf::from("/tmp/new.db"));
        assert_eq!(task.save_kind, SaveKind::SaveNew);
    }

    #[test]
    fn test_save_trace_task_completion() {
        let mut task = SaveTraceTask::save(1);
        task.set_progress(0.5);
        assert_eq!(task.progress, 0.5);
        task.mark_completed();
        assert!(task.completed);
        assert_eq!(task.progress, 1.0);
    }

    #[test]
    fn test_save_trace_task_error() {
        let mut task = SaveTraceTask::save(1);
        task.set_error("disk full");
        assert!(task.has_error());
        assert!(task.completed);
        assert_eq!(task.error.as_deref(), Some("disk full"));
    }

    #[test]
    fn test_save_trace_task_progress_clamp() {
        let mut task = SaveTraceTask::save(1);
        task.set_progress(1.5);
        assert_eq!(task.progress, 1.0);
        task.set_progress(-0.5);
        assert_eq!(task.progress, 0.0);
    }

    #[test]
    fn test_save_task_manager() {
        let mut mgr = SaveTaskManager::new();
        assert!(!mgr.has_pending());

        mgr.submit(SaveTraceTask::save(1));
        mgr.submit(SaveTraceTask::save_as(2, PathBuf::from("/tmp/out.db")));
        assert_eq!(mgr.pending_count(), 2);
        assert!(mgr.has_pending());
    }

    #[test]
    fn test_save_task_manager_complete() {
        let mut mgr = SaveTaskManager::new();
        mgr.submit(SaveTraceTask::save(1));
        mgr.submit(SaveTraceTask::save(1));

        mgr.complete_next(1);
        assert_eq!(mgr.pending_count(), 1);
        assert_eq!(mgr.completed_tasks().len(), 1);
    }

    #[test]
    fn test_save_task_manager_clear_completed() {
        let mut mgr = SaveTaskManager::new();
        mgr.submit(SaveTraceTask::save(1));
        mgr.complete_next(1);
        mgr.clear_completed();
        assert!(!mgr.has_pending());
    }

    #[test]
    fn test_save_task_manager_tasks_for_trace() {
        let mut mgr = SaveTaskManager::new();
        mgr.submit(SaveTraceTask::save(1));
        mgr.submit(SaveTraceTask::save(2));
        mgr.submit(SaveTraceTask::save(1));

        assert_eq!(mgr.tasks_for_trace(1).len(), 2);
        assert_eq!(mgr.tasks_for_trace(2).len(), 1);
        assert_eq!(mgr.tasks_for_trace(3).len(), 0);
    }
}
