//! Task management for background operations.
//!
//! Ports Ghidra's `ghidra.util.task` and `ghidra.util.TrackedTaskListener`.
//!
//! Provides:
//! - [`TaskDialog`] -- a dialog showing task progress with cancel support
//! - [`TaskUtilities`] -- utility methods for running tasks
//! - [`TrackedTaskListener`] -- listener for tracked task lifecycle events
//! - [`SwingExceptionHandler`] -- global exception handler (Ghidra.SwingExceptionHandler)

pub mod task_dialog;
pub mod task_utilities;
pub mod tracked_task;

pub use task_dialog::TaskDialog;
pub use task_utilities::TaskUtilities;
pub use tracked_task::{TaskState, TrackedTask, TrackedTaskListener};
