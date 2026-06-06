//! Task management for background operations.
//!
//! Ports Ghidra's `ghidra.util.task` and `ghidra.util.TrackedTaskListener`.
//!
//! Provides:
//! - [`TaskDialog`] -- a dialog showing task progress with cancel support
//! - [`TaskUtilities`] -- utility methods for running tasks
//! - [`TrackedTaskListener`] -- listener for tracked task lifecycle events
//! - [`SwingExceptionHandler`] -- global exception handler (Ghidra.SwingExceptionHandler)

pub mod script_task_listener;
pub mod task_dialog;
pub mod task_types;
pub mod task_utilities;
pub mod tracked_task;

// New modules ported from Ghidra's task framework
pub mod compound_task;
pub mod task;
pub mod task_listener;
pub mod swing_runnable;
pub mod abstract_swing_update_manager;
pub mod unknown_progress_wrapping_task_monitor;
pub mod buffered_swing_runner;

pub use script_task_listener::ScriptTaskListener;
pub use task_dialog::TaskDialog;
pub use task_types::{
    BufferedSwingRunner, CompoundTask, DummyCancellableTaskMonitor, SwingRunnable,
    SwingUpdateManager, Task, TaskListener, UnknownProgressWrappingTaskMonitor,
};
pub use task_utilities::TaskUtilities;
pub use tracked_task::{TaskState, TrackedTask, TrackedTaskListener};
