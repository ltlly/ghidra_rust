//! DisconnectTask - task for disconnecting from a debug target.
//!
//! Ported from Ghidra's `DisconnectTask` in `ghidra.app.plugin.core.debug.utils`.

use serde::{Deserialize, Serialize};

/// The method by which disconnection should occur.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DisconnectMode {
    /// Gracefully disconnect, leaving the target running.
    Detach,
    /// Disconnect and kill the target process.
    Kill,
    /// Kill and re-launch the target (for restarting).
    KillAndRestart,
}

/// The result of a disconnect operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisconnectResult {
    /// The mode used for disconnection.
    pub mode: DisconnectMode,
    /// Whether the disconnect was successful.
    pub success: bool,
    /// An error message if the disconnect failed.
    pub error: Option<String>,
    /// The target identifier that was disconnected.
    pub target_id: Option<String>,
}

impl DisconnectResult {
    /// Create a successful disconnect result.
    pub fn success(mode: DisconnectMode, target_id: Option<String>) -> Self {
        Self {
            mode,
            success: true,
            error: None,
            target_id,
        }
    }

    /// Create a failed disconnect result.
    pub fn failed(mode: DisconnectMode, error: impl Into<String>) -> Self {
        Self {
            mode,
            success: false,
            error: Some(error.into()),
            target_id: None,
        }
    }

    /// Whether the disconnect succeeded.
    pub fn is_success(&self) -> bool {
        self.success
    }
}

/// Configuration for a disconnect task.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisconnectTaskConfig {
    /// The disconnect mode.
    pub mode: DisconnectMode,
    /// Timeout in milliseconds for waiting on the disconnect.
    pub timeout_ms: u64,
    /// Whether to save the trace before disconnecting.
    pub save_trace: bool,
    /// Whether to close the trace after disconnecting.
    pub close_trace_after: bool,
}

impl DisconnectTaskConfig {
    /// Create a default detach config.
    pub fn detach() -> Self {
        Self {
            mode: DisconnectMode::Detach,
            timeout_ms: 5000,
            save_trace: true,
            close_trace_after: false,
        }
    }

    /// Create a kill config.
    pub fn kill() -> Self {
        Self {
            mode: DisconnectMode::Kill,
            timeout_ms: 10000,
            save_trace: false,
            close_trace_after: false,
        }
    }

    /// Create a kill-and-restart config.
    pub fn kill_and_restart() -> Self {
        Self {
            mode: DisconnectMode::KillAndRestart,
            timeout_ms: 15000,
            save_trace: true,
            close_trace_after: false,
        }
    }

    /// Set the timeout.
    pub fn with_timeout(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = timeout_ms;
        self
    }

    /// Whether to save the trace.
    pub fn with_save_trace(mut self, save: bool) -> Self {
        self.save_trace = save;
        self
    }

    /// Whether to close the trace after disconnect.
    pub fn with_close_trace(mut self, close: bool) -> Self {
        self.close_trace_after = close;
        self
    }
}

/// A task that disconnects from a debug target.
///
/// Ported from Ghidra's `DisconnectTask`. Manages the lifecycle
/// of disconnection including saving state and cleanup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisconnectTask {
    /// Configuration for this task.
    pub config: DisconnectTaskConfig,
    /// The connection ID to disconnect from.
    pub connection_id: Option<u64>,
    /// Whether this task has been cancelled.
    pub cancelled: bool,
}

impl DisconnectTask {
    /// Create a new disconnect task.
    pub fn new(config: DisconnectTaskConfig) -> Self {
        Self {
            config,
            connection_id: None,
            cancelled: false,
        }
    }

    /// Create a detach task.
    pub fn detach(connection_id: u64) -> Self {
        Self {
            config: DisconnectTaskConfig::detach(),
            connection_id: Some(connection_id),
            cancelled: false,
        }
    }

    /// Create a kill task.
    pub fn kill(connection_id: u64) -> Self {
        Self {
            config: DisconnectTaskConfig::kill(),
            connection_id: Some(connection_id),
            cancelled: false,
        }
    }

    /// Cancel this task.
    pub fn cancel(&mut self) {
        self.cancelled = true;
    }

    /// Whether this task has been cancelled.
    pub fn is_cancelled(&self) -> bool {
        self.cancelled
    }

    /// Execute the disconnect (simplified; actual I/O is async).
    pub fn execute(&self) -> DisconnectResult {
        if self.cancelled {
            return DisconnectResult::failed(self.config.mode, "Task cancelled");
        }
        DisconnectResult::success(
            self.config.mode,
            self.connection_id.map(|id| id.to_string()),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_disconnect_mode() {
        assert_ne!(DisconnectMode::Detach, DisconnectMode::Kill);
        assert_ne!(DisconnectMode::Kill, DisconnectMode::KillAndRestart);
    }

    #[test]
    fn test_disconnect_result_success() {
        let r = DisconnectResult::success(DisconnectMode::Detach, Some("target1".into()));
        assert!(r.is_success());
        assert_eq!(r.mode, DisconnectMode::Detach);
        assert_eq!(r.target_id.as_deref(), Some("target1"));
    }

    #[test]
    fn test_disconnect_result_failure() {
        let r = DisconnectResult::failed(DisconnectMode::Kill, "timeout");
        assert!(!r.is_success());
        assert_eq!(r.error.as_deref(), Some("timeout"));
    }

    #[test]
    fn test_disconnect_task_config() {
        let config = DisconnectTaskConfig::detach()
            .with_timeout(10000)
            .with_save_trace(true);
        assert_eq!(config.mode, DisconnectMode::Detach);
        assert_eq!(config.timeout_ms, 10000);
        assert!(config.save_trace);
    }

    #[test]
    fn test_disconnect_task_detach() {
        let task = DisconnectTask::detach(42);
        assert!(!task.is_cancelled());
        assert_eq!(task.connection_id, Some(42));

        let result = task.execute();
        assert!(result.is_success());
    }

    #[test]
    fn test_disconnect_task_cancelled() {
        let mut task = DisconnectTask::kill(1);
        task.cancel();
        assert!(task.is_cancelled());

        let result = task.execute();
        assert!(!result.is_success());
    }

    #[test]
    fn test_disconnect_task_kill() {
        let task = DisconnectTask::kill(99);
        let result = task.execute();
        assert!(result.is_success());
        assert_eq!(result.mode, DisconnectMode::Kill);
    }

    #[test]
    fn test_kill_config() {
        let config = DisconnectTaskConfig::kill();
        assert_eq!(config.mode, DisconnectMode::Kill);
        assert!(!config.save_trace);
    }

    #[test]
    fn test_kill_and_restart_config() {
        let config = DisconnectTaskConfig::kill_and_restart();
        assert_eq!(config.mode, DisconnectMode::KillAndRestart);
        assert!(config.save_trace);
    }

    #[test]
    fn test_disconnect_task_serde() {
        let task = DisconnectTask::detach(1);
        let json = serde_json::to_string(&task).unwrap();
        let back: DisconnectTask = serde_json::from_str(&json).unwrap();
        assert_eq!(back.connection_id, Some(1));
    }
}
