//! Script execution task management.
//!
//! Ported from `ghidra.app.plugin.core.script.RunScriptTask`.
//!
//! Provides a task abstraction for running scripts asynchronously,
//! tracking progress, and handling cancellation.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::{ScriptInfo, ScriptRunState};

/// Output message produced by a running script.
#[derive(Debug, Clone)]
pub enum ScriptOutput {
    /// A normal informational message.
    Info(String),
    /// A warning message.
    Warning(String),
    /// An error message.
    Error(String),
    /// A print statement.
    Print(String),
}

/// Progress information from a running script.
#[derive(Debug, Clone)]
pub struct ScriptProgress {
    /// Current progress value.
    pub current: u64,
    /// Maximum progress value (0 = indeterminate).
    pub maximum: u64,
    /// Optional progress message.
    pub message: Option<String>,
}

impl ScriptProgress {
    /// Create a new progress value.
    pub fn new(current: u64, maximum: u64) -> Self {
        Self {
            current,
            maximum,
            message: None,
        }
    }

    /// Create an indeterminate progress.
    pub fn indeterminate() -> Self {
        Self {
            current: 0,
            maximum: 0,
            message: None,
        }
    }

    /// Progress fraction (0.0 to 1.0), or None if indeterminate.
    pub fn fraction(&self) -> Option<f64> {
        if self.maximum > 0 {
            Some(self.current as f64 / self.maximum as f64)
        } else {
            None
        }
    }

    /// Whether the task is complete.
    pub fn is_complete(&self) -> bool {
        self.maximum > 0 && self.current >= self.maximum
    }
}

/// Result of a script execution.
#[derive(Debug, Clone)]
pub struct ScriptResult {
    /// The script that was run.
    pub script_name: String,
    /// Final state.
    pub state: ScriptRunState,
    /// Output messages.
    pub output: Vec<ScriptOutput>,
    /// Error message (if failed).
    pub error: Option<String>,
    /// Duration of execution.
    pub duration: Duration,
    /// Exit code (0 = success).
    pub exit_code: i32,
}

impl ScriptResult {
    /// Create a successful result.
    pub fn success(script_name: impl Into<String>, duration: Duration) -> Self {
        Self {
            script_name: script_name.into(),
            state: ScriptRunState::Completed,
            output: Vec::new(),
            error: None,
            duration,
            exit_code: 0,
        }
    }

    /// Create a failed result.
    pub fn failure(
        script_name: impl Into<String>,
        error: impl Into<String>,
        duration: Duration,
    ) -> Self {
        Self {
            script_name: script_name.into(),
            state: ScriptRunState::Failed,
            output: Vec::new(),
            error: Some(error.into()),
            duration,
            exit_code: 1,
        }
    }

    /// Whether the script completed successfully.
    pub fn is_success(&self) -> bool {
        self.state == ScriptRunState::Completed && self.exit_code == 0
    }
}

/// A task that runs a script.
///
/// Ported from `ghidra.app.plugin.core.script.RunScriptTask`.
#[derive(Debug)]
pub struct RunScriptTask {
    /// The script to run.
    pub script: ScriptInfo,
    /// Current state.
    state: ScriptRunState,
    /// Cancellation flag.
    cancelled: Arc<AtomicBool>,
    /// Progress information.
    progress: ScriptProgress,
    /// Output buffer.
    output: Vec<ScriptOutput>,
    /// Start time.
    start_time: Option<Instant>,
}

impl RunScriptTask {
    /// Create a new run script task.
    pub fn new(script: ScriptInfo) -> Self {
        Self {
            script,
            state: ScriptRunState::Idle,
            cancelled: Arc::new(AtomicBool::new(false)),
            progress: ScriptProgress::indeterminate(),
            output: Vec::new(),
            start_time: None,
        }
    }

    /// Get the current state.
    pub fn state(&self) -> ScriptRunState {
        self.state
    }

    /// Get the cancellation flag.
    pub fn cancelled_flag(&self) -> Arc<AtomicBool> {
        self.cancelled.clone()
    }

    /// Request cancellation.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    /// Whether cancellation has been requested.
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }

    /// Get the current progress.
    pub fn progress(&self) -> &ScriptProgress {
        &self.progress
    }

    /// Update progress.
    pub fn set_progress(&mut self, progress: ScriptProgress) {
        self.progress = progress;
    }

    /// Get the output messages.
    pub fn output(&self) -> &[ScriptOutput] {
        &self.output
    }

    /// Add an output message.
    pub fn add_output(&mut self, msg: ScriptOutput) {
        self.output.push(msg);
    }

    /// Start the task (marks the start time and changes state).
    pub fn start(&mut self) {
        self.state = ScriptRunState::Running;
        self.start_time = Some(Instant::now());
    }

    /// Complete the task.
    pub fn complete(&mut self) -> ScriptResult {
        let duration = self
            .start_time
            .map(|t| t.elapsed())
            .unwrap_or(Duration::ZERO);
        self.state = ScriptRunState::Completed;
        ScriptResult {
            script_name: self.script.name.clone(),
            state: ScriptRunState::Completed,
            output: std::mem::take(&mut self.output),
            error: None,
            duration,
            exit_code: 0,
        }
    }

    /// Fail the task.
    pub fn fail(&mut self, error: impl Into<String>) -> ScriptResult {
        let duration = self
            .start_time
            .map(|t| t.elapsed())
            .unwrap_or(Duration::ZERO);
        self.state = ScriptRunState::Failed;
        ScriptResult {
            script_name: self.script.name.clone(),
            state: ScriptRunState::Failed,
            output: std::mem::take(&mut self.output),
            error: Some(error.into()),
            duration,
            exit_code: 1,
        }
    }

    /// Get the elapsed time since start.
    pub fn elapsed(&self) -> Option<Duration> {
        self.start_time.map(|t| t.elapsed())
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn sample_script_info(name: &str) -> ScriptInfo {
        ScriptInfo {
            name: name.to_string(),
            path: PathBuf::from(format!("/scripts/{}.py", name)),
            extension: "py".to_string(),
            category: super::super::ScriptCategory::root("Test"),
            description: String::new(),
            key_binding: None,
            has_gui: false,
            headless_supported: true,
            author: String::new(),
        }
    }

    #[test]
    fn test_script_progress() {
        let p = ScriptProgress::new(50, 100);
        assert_eq!(p.fraction(), Some(0.5));
        assert!(!p.is_complete());

        let complete = ScriptProgress::new(100, 100);
        assert!(complete.is_complete());
    }

    #[test]
    fn test_script_progress_indeterminate() {
        let p = ScriptProgress::indeterminate();
        assert!(p.fraction().is_none());
        assert!(!p.is_complete());
    }

    #[test]
    fn test_script_result_success() {
        let r = ScriptResult::success("test", Duration::from_millis(100));
        assert!(r.is_success());
        assert!(r.error.is_none());
    }

    #[test]
    fn test_script_result_failure() {
        let r = ScriptResult::failure("test", "runtime error", Duration::from_millis(50));
        assert!(!r.is_success());
        assert!(r.error.is_some());
        assert_eq!(r.exit_code, 1);
    }

    #[test]
    fn test_run_script_task_lifecycle() {
        let mut task = RunScriptTask::new(sample_script_info("test"));
        assert_eq!(task.state(), ScriptRunState::Idle);

        task.start();
        assert_eq!(task.state(), ScriptRunState::Running);
        assert!(task.elapsed().is_some());

        task.add_output(ScriptOutput::Info("hello".into()));
        assert_eq!(task.output().len(), 1);

        let result = task.complete();
        assert!(result.is_success());
        assert_eq!(task.state(), ScriptRunState::Completed);
    }

    #[test]
    fn test_run_script_task_fail() {
        let mut task = RunScriptTask::new(sample_script_info("failing"));
        task.start();
        let result = task.fail("division by zero");
        assert!(!result.is_success());
        assert_eq!(result.error.unwrap(), "division by zero");
    }

    #[test]
    fn test_run_script_task_cancel() {
        let task = RunScriptTask::new(sample_script_info("cancellable"));
        assert!(!task.is_cancelled());
        task.cancel();
        assert!(task.is_cancelled());
    }

    #[test]
    fn test_run_script_task_cancel_flag() {
        let task = RunScriptTask::new(sample_script_info("flag_test"));
        let flag = task.cancelled_flag();
        let handle = std::thread::spawn(move || {
            flag.load(Ordering::SeqCst)
        });
        // Should be false initially
        assert!(!handle.join().unwrap());
    }

    #[test]
    fn test_script_output_variants() {
        let info = ScriptOutput::Info("info".into());
        let warn = ScriptOutput::Warning("warn".into());
        let err = ScriptOutput::Error("err".into());
        let print = ScriptOutput::Print("print".into());

        assert!(matches!(info, ScriptOutput::Info(_)));
        assert!(matches!(warn, ScriptOutput::Warning(_)));
        assert!(matches!(err, ScriptOutput::Error(_)));
        assert!(matches!(print, ScriptOutput::Print(_)));
    }
}
