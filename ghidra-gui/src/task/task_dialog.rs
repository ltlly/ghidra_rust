//! Port of `ghidra.util.task.TaskDialog`.
//!
//! A dialog that displays task progress with a cancel button and status message.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// State shared between the task and the dialog.
#[derive(Debug, Clone)]
struct TaskDialogState {
    message: String,
    progress: f64, // 0.0 - 1.0
    indeterminate: bool,
    cancelled: bool,
    finished: bool,
}

/// A dialog for displaying task progress.
///
/// Shows a progress bar, status message, and cancel button.
/// Mirrors `ghidra.util.task.TaskDialog`.
#[derive(Debug)]
pub struct TaskDialog {
    title: String,
    state: Arc<Mutex<TaskDialogState>>,
    start_time: Instant,
    /// Whether to show elapsed time.
    show_elapsed: bool,
}

impl TaskDialog {
    /// Create a new task dialog with the given title.
    pub fn new(title: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            state: Arc::new(Mutex::new(TaskDialogState {
                message: String::new(),
                progress: 0.0,
                indeterminate: true,
                cancelled: false,
                finished: false,
            })),
            start_time: Instant::now(),
            show_elapsed: true,
        }
    }

    /// Get the dialog title.
    pub fn title(&self) -> &str {
        &self.title
    }

    /// Set the status message.
    pub fn set_message(&self, message: impl Into<String>) {
        if let Ok(mut state) = self.state.lock() {
            state.message = message.into();
        }
    }

    /// Set the progress (0.0 to 1.0).
    pub fn set_progress(&self, progress: f64) {
        if let Ok(mut state) = self.state.lock() {
            state.progress = progress.clamp(0.0, 1.0);
            state.indeterminate = false;
        }
    }

    /// Set the progress as a value out of a maximum.
    pub fn set_progress_value(&self, value: usize, max: usize) {
        if max > 0 {
            self.set_progress(value as f64 / max as f64);
        }
    }

    /// Set indeterminate progress mode.
    pub fn set_indeterminate(&self, indeterminate: bool) {
        if let Ok(mut state) = self.state.lock() {
            state.indeterminate = indeterminate;
        }
    }

    /// Check if the user has cancelled the task.
    pub fn is_cancelled(&self) -> bool {
        self.state.lock().map(|s| s.cancelled).unwrap_or(false)
    }

    /// Signal the user pressed cancel.
    pub fn cancel(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.cancelled = true;
        }
    }

    /// Mark the task as finished.
    pub fn finish(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.finished = true;
        }
    }

    /// Check if the task is finished.
    pub fn is_finished(&self) -> bool {
        self.state.lock().map(|s| s.finished).unwrap_or(false)
    }

    /// Get the current message.
    pub fn message(&self) -> String {
        self.state.lock().map(|s| s.message.clone()).unwrap_or_default()
    }

    /// Get the current progress (0.0 to 1.0).
    pub fn progress(&self) -> f64 {
        self.state.lock().map(|s| s.progress).unwrap_or(0.0)
    }

    /// Check if progress is indeterminate.
    pub fn is_indeterminate(&self) -> bool {
        self.state.lock().map(|s| s.indeterminate).unwrap_or(true)
    }

    /// Get the elapsed time since the dialog was created.
    pub fn elapsed(&self) -> Duration {
        self.start_time.elapsed()
    }

    /// Get elapsed time as a formatted string.
    pub fn elapsed_string(&self) -> String {
        let dur = self.elapsed();
        let secs = dur.as_secs();
        if secs < 60 {
            format!("{}s", secs)
        } else {
            let mins = secs / 60;
            let secs = secs % 60;
            format!("{}m {}s", mins, secs)
        }
    }

    /// Whether to show elapsed time.
    pub fn set_show_elapsed(&mut self, show: bool) {
        self.show_elapsed = show;
    }

    /// Get a snapshot of the dialog state for rendering.
    pub fn snapshot(&self) -> TaskDialogSnapshot {
        let state = self.state.lock().unwrap();
        TaskDialogSnapshot {
            title: self.title.clone(),
            message: state.message.clone(),
            progress: state.progress,
            indeterminate: state.indeterminate,
            cancelled: state.cancelled,
            finished: state.finished,
            elapsed: self.elapsed_string(),
        }
    }
}

/// A snapshot of task dialog state for rendering.
#[derive(Debug, Clone)]
pub struct TaskDialogSnapshot {
    pub title: String,
    pub message: String,
    pub progress: f64,
    pub indeterminate: bool,
    pub cancelled: bool,
    pub finished: bool,
    pub elapsed: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_task_dialog_create() {
        let dialog = TaskDialog::new("Loading...");
        assert_eq!(dialog.title(), "Loading...");
        assert!(!dialog.is_cancelled());
        assert!(!dialog.is_finished());
    }

    #[test]
    fn test_task_dialog_message() {
        let dialog = TaskDialog::new("Test");
        dialog.set_message("Processing file 3 of 10");
        assert_eq!(dialog.message(), "Processing file 3 of 10");
    }

    #[test]
    fn test_task_dialog_progress() {
        let dialog = TaskDialog::new("Test");
        assert!(dialog.is_indeterminate());

        dialog.set_progress(0.5);
        assert!(!dialog.is_indeterminate());
        assert!((dialog.progress() - 0.5).abs() < 0.001);

        dialog.set_progress_value(75, 100);
        assert!((dialog.progress() - 0.75).abs() < 0.001);
    }

    #[test]
    fn test_task_dialog_progress_clamp() {
        let dialog = TaskDialog::new("Test");
        dialog.set_progress(-0.5);
        assert!(dialog.progress() >= 0.0);
        dialog.set_progress(1.5);
        assert!(dialog.progress() <= 1.0);
    }

    #[test]
    fn test_task_dialog_cancel() {
        let dialog = TaskDialog::new("Test");
        assert!(!dialog.is_cancelled());
        dialog.cancel();
        assert!(dialog.is_cancelled());
    }

    #[test]
    fn test_task_dialog_finish() {
        let dialog = TaskDialog::new("Test");
        assert!(!dialog.is_finished());
        dialog.finish();
        assert!(dialog.is_finished());
    }

    #[test]
    fn test_task_dialog_elapsed() {
        let dialog = TaskDialog::new("Test");
        let elapsed = dialog.elapsed();
        assert!(elapsed.as_millis() < 100); // should be very fast
    }

    #[test]
    fn test_task_dialog_snapshot() {
        let dialog = TaskDialog::new("My Task");
        dialog.set_message("Working...");
        dialog.set_progress(0.75);

        let snap = dialog.snapshot();
        assert_eq!(snap.title, "My Task");
        assert_eq!(snap.message, "Working...");
        assert!((snap.progress - 0.75).abs() < 0.001);
        assert!(!snap.cancelled);
    }

    #[test]
    fn test_task_dialog_indeterminate_toggle() {
        let dialog = TaskDialog::new("Test");
        assert!(dialog.is_indeterminate());

        dialog.set_progress(0.1);
        assert!(!dialog.is_indeterminate());

        dialog.set_indeterminate(true);
        assert!(dialog.is_indeterminate());
    }
}
