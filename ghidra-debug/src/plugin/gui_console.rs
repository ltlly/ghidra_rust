//! Console provider data model.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.gui.console` package.
//! Provides data model types for the debug console, including log rows,
//! progress monitors, and action contexts.

use std::collections::VecDeque;

use serde::{Deserialize, Serialize};


// ---------------------------------------------------------------------------
// Log level
// ---------------------------------------------------------------------------

/// Log level for console messages.
///
/// Ported from Ghidra's log4j Level usage in `DebuggerConsoleProvider`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum LogLevel {
    /// Trace-level messages.
    Trace,
    /// Debug-level messages.
    Debug,
    /// Informational messages.
    Info,
    /// Warning messages.
    Warn,
    /// Error messages.
    Error,
    /// Fatal messages.
    Fatal,
}

impl LogLevel {
    /// Short display name for the level.
    pub fn short_name(&self) -> &'static str {
        match self {
            LogLevel::Trace => "TRC",
            LogLevel::Debug => "DBG",
            LogLevel::Info => "INF",
            LogLevel::Warn => "WRN",
            LogLevel::Error => "ERR",
            LogLevel::Fatal => "FTL",
        }
    }
}

// ---------------------------------------------------------------------------
// Log row
// ---------------------------------------------------------------------------

/// A single row in the console log table.
///
/// Ported from Ghidra's `LogRow`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogRow {
    /// The message level.
    pub level: LogLevel,
    /// The message text (may contain HTML).
    pub message: String,
    /// The source (class/logger name).
    pub source: String,
    /// Timestamp as epoch milliseconds.
    pub timestamp: i64,
    /// The associated exception trace (if any).
    pub exception: Option<String>,
    /// Action data for the row (e.g., clickable links).
    pub actions: Vec<ConsoleAction>,
}

impl LogRow {
    /// Create a new log row.
    pub fn new(level: LogLevel, message: impl Into<String>, source: impl Into<String>) -> Self {
        Self {
            level,
            message: message.into(),
            source: source.into(),
            timestamp: chrono::Utc::now().timestamp_millis(),
            exception: None,
            actions: Vec::new(),
        }
    }

    /// Create an error row.
    pub fn error(message: impl Into<String>, source: impl Into<String>) -> Self {
        Self::new(LogLevel::Error, message, source)
    }

    /// Create an info row.
    pub fn info(message: impl Into<String>, source: impl Into<String>) -> Self {
        Self::new(LogLevel::Info, message, source)
    }

    /// Set the exception.
    pub fn with_exception(mut self, exception: impl Into<String>) -> Self {
        self.exception = Some(exception.into());
        self
    }
}

// ---------------------------------------------------------------------------
// Console action
// ---------------------------------------------------------------------------

/// An action associated with a console row.
///
/// Ported from Ghidra's `ConsoleActionsCellRenderer`/`Editor`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsoleAction {
    /// The action label.
    pub label: String,
    /// The action identifier.
    pub action_id: String,
    /// Tooltip text.
    pub tooltip: Option<String>,
}

// ---------------------------------------------------------------------------
// Progress monitor row
// ---------------------------------------------------------------------------

/// A row representing a progress monitor in the console.
///
/// Ported from Ghidra's `MonitorRowConsoleActionContext` and
/// `MonitorCellRenderer`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorRow {
    /// The task ID.
    pub task_id: i64,
    /// The task name.
    pub task_name: String,
    /// Current progress (0.0 - 1.0).
    pub progress: f64,
    /// Whether the task is finished.
    pub finished: bool,
    /// Whether the task was cancelled.
    pub cancelled: bool,
    /// The associated message.
    pub message: Option<String>,
}

impl MonitorRow {
    /// Create a new monitor row.
    pub fn new(task_id: i64, task_name: impl Into<String>) -> Self {
        Self {
            task_id,
            task_name: task_name.into(),
            progress: 0.0,
            finished: false,
            cancelled: false,
            message: None,
        }
    }

    /// Update progress.
    pub fn update_progress(&mut self, progress: f64) {
        self.progress = progress.clamp(0.0, 1.0);
    }

    /// Mark as finished.
    pub fn finish(&mut self) {
        self.progress = 1.0;
        self.finished = true;
    }

    /// Mark as cancelled.
    pub fn cancel(&mut self) {
        self.cancelled = true;
        self.finished = true;
    }

    /// The progress as a percentage string.
    pub fn progress_pct(&self) -> String {
        format!("{:.0}%", self.progress * 100.0)
    }
}

// ---------------------------------------------------------------------------
// Console table column
// ---------------------------------------------------------------------------

/// Columns in the console log table.
///
/// Ported from Ghidra's `DebuggerConsoleProvider.LogTableColumns`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ConsoleColumn {
    /// Icon column (level indicator).
    Icon,
    /// Source column.
    Source,
    /// Message column.
    Message,
    /// Actions column.
    Actions,
}

/// Sort direction for the console table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SortDirection {
    /// Ascending.
    Ascending,
    /// Descending.
    Descending,
}

/// Sort state for the console table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsoleSortState {
    /// The column being sorted.
    pub column: ConsoleColumn,
    /// The direction.
    pub direction: SortDirection,
}

// ---------------------------------------------------------------------------
// Console model
// ---------------------------------------------------------------------------

/// The data model for the debug console.
///
/// Ported from Ghidra's `DebuggerConsoleProvider` data model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsoleModel {
    /// The log rows (most recent at the back).
    pub log_rows: VecDeque<LogRow>,
    /// Active progress monitors.
    pub monitors: Vec<MonitorRow>,
    /// Maximum number of log rows to retain.
    pub max_rows: usize,
    /// The sort state.
    pub sort: ConsoleSortState,
    /// The filter text (empty = no filter).
    pub filter_text: String,
}

impl ConsoleModel {
    /// Create a new console model.
    pub fn new() -> Self {
        Self {
            log_rows: VecDeque::new(),
            monitors: Vec::new(),
            max_rows: 10000,
            sort: ConsoleSortState {
                column: ConsoleColumn::Message,
                direction: SortDirection::Ascending,
            },
            filter_text: String::new(),
        }
    }

    /// Add a log row.
    pub fn add_log(&mut self, row: LogRow) {
        if self.log_rows.len() >= self.max_rows {
            self.log_rows.pop_front();
        }
        self.log_rows.push_back(row);
    }

    /// Clear all log rows.
    pub fn clear(&mut self) {
        self.log_rows.clear();
    }

    /// Get filtered rows matching the current filter text.
    pub fn filtered_rows(&self) -> Vec<&LogRow> {
        if self.filter_text.is_empty() {
            self.log_rows.iter().collect()
        } else {
            let filter_lower = self.filter_text.to_lowercase();
            self.log_rows
                .iter()
                .filter(|row| row.message.to_lowercase().contains(&filter_lower))
                .collect()
        }
    }

    /// Start a new progress monitor.
    pub fn start_monitor(&mut self, task_id: i64, task_name: impl Into<String>) {
        self.monitors.push(MonitorRow::new(task_id, task_name));
    }

    /// Update a progress monitor.
    pub fn update_monitor(&mut self, task_id: i64, progress: f64) {
        if let Some(m) = self.monitors.iter_mut().find(|m| m.task_id == task_id) {
            m.update_progress(progress);
        }
    }

    /// Finish a progress monitor.
    pub fn finish_monitor(&mut self, task_id: i64) {
        if let Some(m) = self.monitors.iter_mut().find(|m| m.task_id == task_id) {
            m.finish();
        }
    }

    /// Remove finished monitors.
    pub fn cleanup_monitors(&mut self) {
        self.monitors.retain(|m| !m.finished);
    }
}

// ---------------------------------------------------------------------------
// Progress listener model
// ---------------------------------------------------------------------------

/// A receiver that forwards progress events to the console model.
///
/// Ported from Ghidra's `MonitorReceiver` and `ProgressListener`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgressReceiver {
    /// The task ID.
    pub task_id: i64,
    /// The task name.
    pub task_name: String,
    /// Current maximum progress value.
    pub maximum: f64,
    /// Current progress value.
    pub current: f64,
    /// The status message.
    pub message: Option<String>,
    /// Whether indeterminate.
    pub indeterminate: bool,
    /// Whether cancelled.
    pub cancelled: bool,
}

impl ProgressReceiver {
    /// Create a new progress receiver.
    pub fn new(task_id: i64, task_name: impl Into<String>) -> Self {
        Self {
            task_id,
            task_name: task_name.into(),
            maximum: 100.0,
            current: 0.0,
            message: None,
            indeterminate: false,
            cancelled: false,
        }
    }

    /// Set the maximum progress value.
    pub fn set_maximum(&mut self, max: f64) {
        self.maximum = max;
    }

    /// Update the progress.
    pub fn set_progress(&mut self, current: f64) {
        self.current = current;
    }

    /// Set the message.
    pub fn set_message(&mut self, msg: impl Into<String>) {
        self.message = Some(msg.into());
    }

    /// The progress as a fraction (0.0 - 1.0).
    pub fn fraction(&self) -> f64 {
        if self.maximum <= 0.0 {
            0.0
        } else {
            (self.current / self.maximum).clamp(0.0, 1.0)
        }
    }
}

// ---------------------------------------------------------------------------
// Action contexts
// ---------------------------------------------------------------------------

/// Action context for log row operations.
///
/// Ported from Ghidra's `LogRowConsoleActionContext`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogRowActionContext {
    /// The selected log rows.
    pub rows: Vec<LogRow>,
}

/// Action context for monitor row operations.
///
/// Ported from Ghidra's `MonitorRowConsoleActionContext`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorRowActionContext {
    /// The selected monitor rows.
    pub rows: Vec<MonitorRow>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_level_ordering() {
        assert!(LogLevel::Trace < LogLevel::Debug);
        assert!(LogLevel::Debug < LogLevel::Info);
        assert!(LogLevel::Error < LogLevel::Fatal);
        assert_eq!(LogLevel::Warn.short_name(), "WRN");
    }

    #[test]
    fn test_log_row() {
        let row = LogRow::error("Something failed", "TestSource");
        assert_eq!(row.level, LogLevel::Error);
        assert_eq!(row.message, "Something failed");
        assert!(row.exception.is_none());

        let row = row.with_exception("java.lang.NullPointerException");
        assert!(row.exception.is_some());
    }

    #[test]
    fn test_monitor_row() {
        let mut monitor = MonitorRow::new(1, "Loading");
        assert_eq!(monitor.progress, 0.0);
        assert!(!monitor.finished);
        assert_eq!(monitor.progress_pct(), "0%");

        monitor.update_progress(0.5);
        assert_eq!(monitor.progress_pct(), "50%");

        monitor.finish();
        assert!(monitor.finished);
        assert_eq!(monitor.progress, 1.0);
    }

    #[test]
    fn test_monitor_cancel() {
        let mut monitor = MonitorRow::new(2, "Analysis");
        monitor.cancel();
        assert!(monitor.cancelled);
        assert!(monitor.finished);
    }

    #[test]
    fn test_console_model() {
        let mut model = ConsoleModel::new();
        model.add_log(LogRow::info("Hello", "Source"));
        model.add_log(LogRow::error("Oops", "Source"));
        assert_eq!(model.log_rows.len(), 2);
        assert_eq!(model.filtered_rows().len(), 2);

        model.filter_text = "Oops".into();
        assert_eq!(model.filtered_rows().len(), 1);
    }

    #[test]
    fn test_console_model_max_rows() {
        let mut model = ConsoleModel::new();
        model.max_rows = 3;
        for i in 0..5 {
            model.add_log(LogRow::info(format!("msg {}", i), "Src"));
        }
        assert_eq!(model.log_rows.len(), 3);
        assert_eq!(model.log_rows[0].message, "msg 2");
    }

    #[test]
    fn test_console_model_monitors() {
        let mut model = ConsoleModel::new();
        model.start_monitor(1, "Task");
        model.update_monitor(1, 0.5);
        assert_eq!(model.monitors.len(), 1);
        model.finish_monitor(1);
        assert!(model.monitors[0].finished);
        model.cleanup_monitors();
        assert!(model.monitors.is_empty());
    }

    #[test]
    fn test_progress_receiver() {
        let mut recv = ProgressReceiver::new(1, "Test");
        recv.set_maximum(200.0);
        recv.set_progress(100.0);
        assert!((recv.fraction() - 0.5).abs() < f64::EPSILON);
        recv.set_message("Halfway");
        assert_eq!(recv.message.as_deref(), Some("Halfway"));
    }
}
