//! Command framework for the Ghidra Project framework.
//!
//! Ports the Java `ghidra.framework.cmd` package:
//! - `Command` trait -- interface for changes made to a domain object
//! - `BackgroundCommand` -- command that runs in a background thread
//! - `CompoundCmd` -- a sequence of commands executed as a unit
//! - `CompoundBackgroundCommand` -- compound background command
//! - `MergeableBackgroundCommand` -- background command that supports merging

use std::fmt;

use super::ProjectResult;

// ============================================================================
// Command trait
// ============================================================================

/// Interface to define a change made to a domain object.
///
/// In Java: `ghidra.framework.cmd.Command<T>`.
pub trait Command: Send + Sync + fmt::Debug {
    /// The type name of the domain object this command operates on.
    fn domain_object_type(&self) -> &str {
        "DomainObject"
    }

    /// Apply the command to the given domain object.
    ///
    /// Returns `true` if the command applied successfully.
    fn apply_to(&mut self, object_id: u64) -> bool;

    /// Returns the status message indicating the result of the command.
    ///
    /// Returns `None` if successful, or a description of the failure.
    fn status_msg(&self) -> Option<&str>;

    /// The name of this command.
    fn name(&self) -> &str;
}

// ============================================================================
// BackgroundCommand
// ============================================================================

/// Abstract command that runs in a background thread.
///
/// Use this for long-running commands that are cancellable.
/// In Java: `ghidra.framework.cmd.BackgroundCommand<T>`.
pub trait BackgroundCommand: Send + fmt::Debug {
    /// The name of this command.
    fn name(&self) -> &str;

    /// Whether this command provides progress information.
    fn has_progress(&self) -> bool;

    /// Whether this command can be canceled.
    fn can_cancel(&self) -> bool;

    /// Whether the command requires the monitor to be modal.
    fn is_modal(&self) -> bool;

    /// Apply the command with a task monitor for progress.
    ///
    /// Returns `true` if the command applied successfully.
    fn apply_to(&mut self, object_id: u64, monitor: &mut dyn BackgroundCommandMonitor) -> bool;

    /// Status message after execution.
    fn status_msg(&self) -> Option<&str>;

    /// Called when this command is being disposed without running.
    fn dispose(&mut self) {}

    /// Called when the task monitor is completely done.
    fn task_completed(&mut self) {}
}

/// Monitor interface for background commands.
pub trait BackgroundCommandMonitor: Send {
    /// Set the current progress value.
    fn set_progress(&mut self, value: i64);
    /// Set the maximum progress value.
    fn set_maximum(&mut self, max: i64);
    /// Set the progress message.
    fn set_message(&mut self, message: &str);
    /// Whether the operation has been cancelled.
    fn is_cancelled(&self) -> bool;
    /// Check cancellation and return an error if cancelled.
    fn check_cancelled(&self) -> ProjectResult<()> {
        if self.is_cancelled() {
            Err(super::ProjectError::NotAvailable("Operation cancelled".into()))
        } else {
            Ok(())
        }
    }
}

// ============================================================================
// CompoundCmd
// ============================================================================

/// A command that consists of multiple sub-commands executed as a unit.
///
/// In Java: `ghidra.framework.cmd.CompoundCmd<T>`.
#[derive(Debug)]
pub struct CompoundCmd {
    name: String,
    commands: Vec<Box<dyn Command>>,
    status_msg: Option<String>,
}

impl CompoundCmd {
    /// Create a new compound command.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            commands: Vec::new(),
            status_msg: None,
        }
    }

    /// Add a sub-command.
    pub fn add(&mut self, cmd: Box<dyn Command>) {
        self.commands.push(cmd);
    }

    /// Number of sub-commands.
    pub fn command_count(&self) -> usize {
        self.commands.len()
    }
}

impl Command for CompoundCmd {
    fn apply_to(&mut self, object_id: u64) -> bool {
        for cmd in &mut self.commands {
            if !cmd.apply_to(object_id) {
                self.status_msg = cmd.status_msg().map(|s| s.to_string());
                return false;
            }
        }
        true
    }

    fn status_msg(&self) -> Option<&str> {
        self.status_msg.as_deref()
    }

    fn name(&self) -> &str {
        &self.name
    }
}

// ============================================================================
// CompoundBackgroundCommand
// ============================================================================

/// A background command that consists of multiple sub-background commands.
///
/// In Java: `ghidra.framework.cmd.CompoundBackgroundCommand<T>`.
#[derive(Debug)]
pub struct CompoundBackgroundCommand {
    name: String,
    commands: Vec<Box<dyn BackgroundCommand>>,
    has_progress: bool,
    can_cancel: bool,
    is_modal: bool,
    status_msg: Option<String>,
}

impl CompoundBackgroundCommand {
    /// Create a new compound background command.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            commands: Vec::new(),
            has_progress: false,
            can_cancel: false,
            is_modal: false,
            status_msg: None,
        }
    }

    /// Add a sub-background-command.
    pub fn add(&mut self, cmd: Box<dyn BackgroundCommand>) {
        self.has_progress = self.has_progress || cmd.has_progress();
        self.can_cancel = self.can_cancel || cmd.can_cancel();
        self.is_modal = self.is_modal || cmd.is_modal();
        self.commands.push(cmd);
    }

    /// Number of sub-commands.
    pub fn command_count(&self) -> usize {
        self.commands.len()
    }
}

impl BackgroundCommand for CompoundBackgroundCommand {
    fn name(&self) -> &str {
        &self.name
    }
    fn has_progress(&self) -> bool {
        self.has_progress
    }
    fn can_cancel(&self) -> bool {
        self.can_cancel
    }
    fn is_modal(&self) -> bool {
        self.is_modal
    }
    fn apply_to(&mut self, object_id: u64, monitor: &mut dyn BackgroundCommandMonitor) -> bool {
        for cmd in &mut self.commands {
            if monitor.is_cancelled() {
                self.status_msg = Some("Cancelled".to_string());
                return false;
            }
            if !cmd.apply_to(object_id, monitor) {
                self.status_msg = cmd.status_msg().map(|s| s.to_string());
                return false;
            }
        }
        true
    }
    fn status_msg(&self) -> Option<&str> {
        self.status_msg.as_deref()
    }
}

// ============================================================================
// MergeableBackgroundCommand
// ============================================================================

/// A background command that supports merging with other commands of the
/// same type.
///
/// In Java: `ghidra.framework.cmd.MergeableBackgroundCommand<T>`.
pub trait MergeableBackgroundCommand: BackgroundCommand {
    /// Whether this command can merge with the given command.
    fn can_merge_with(&self, other: &dyn BackgroundCommand) -> bool;

    /// Merge the other command into this one.
    fn merge(&mut self, other: Box<dyn BackgroundCommand>);
}

// ============================================================================
// CommandResult
// ============================================================================

/// The result of applying a command.
#[derive(Debug, Clone)]
pub struct CommandResult {
    success: bool,
    message: Option<String>,
    command_name: String,
}

impl CommandResult {
    /// Create a successful result.
    pub fn success(command_name: impl Into<String>) -> Self {
        Self {
            success: true,
            message: None,
            command_name: command_name.into(),
        }
    }

    /// Create a failure result.
    pub fn failure(command_name: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            success: false,
            message: Some(message.into()),
            command_name: command_name.into(),
        }
    }

    /// Whether the command succeeded.
    pub fn is_success(&self) -> bool {
        self.success
    }

    /// The failure message, if any.
    pub fn message(&self) -> Option<&str> {
        self.message.as_deref()
    }

    /// The name of the command.
    pub fn command_name(&self) -> &str {
        &self.command_name
    }
}

impl fmt::Display for CommandResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.success {
            write!(f, "Command '{}' succeeded", self.command_name)
        } else {
            write!(
                f,
                "Command '{}' failed: {}",
                self.command_name,
                self.message.as_deref().unwrap_or("unknown error")
            )
        }
    }
}

// ============================================================================
// CommandManager
// ============================================================================

/// Manages command execution with undo support.
///
/// In Java: `ghidra.framework.cmd.CommandManager` (conceptual, spread across PluginTool).
#[derive(Debug, Default)]
pub struct CommandManager {
    history: Vec<CommandResult>,
    max_history: usize,
}

impl CommandManager {
    /// Create a new command manager.
    pub fn new() -> Self {
        Self {
            history: Vec::new(),
            max_history: 1000,
        }
    }

    /// Execute a command on the given object.
    pub fn execute(&mut self, cmd: &mut dyn Command, object_id: u64) -> CommandResult {
        let result = if cmd.apply_to(object_id) {
            CommandResult::success(cmd.name())
        } else {
            CommandResult::failure(
                cmd.name(),
                cmd.status_msg().unwrap_or("unknown error"),
            )
        };
        self.add_to_history(result.clone());
        result
    }

    /// Add a result to the history.
    fn add_to_history(&mut self, result: CommandResult) {
        self.history.push(result);
        while self.history.len() > self.max_history {
            self.history.remove(0);
        }
    }

    /// Get the command history.
    pub fn history(&self) -> &[CommandResult] {
        &self.history
    }

    /// Clear the command history.
    pub fn clear_history(&mut self) {
        self.history.clear();
    }

    /// Number of commands in history.
    pub fn history_count(&self) -> usize {
        self.history.len()
    }

    /// Set the maximum history size.
    pub fn set_max_history(&mut self, max: usize) {
        self.max_history = max.max(1);
        while self.history.len() > self.max_history {
            self.history.remove(0);
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct TestCommand {
        name: String,
        should_succeed: bool,
        status: Option<String>,
    }

    impl TestCommand {
        fn new(name: &str, should_succeed: bool) -> Self {
            Self {
                name: name.to_string(),
                should_succeed,
                status: None,
            }
        }
    }

    impl Command for TestCommand {
        fn apply_to(&mut self, _object_id: u64) -> bool {
            if !self.should_succeed {
                self.status = Some("command failed".to_string());
            }
            self.should_succeed
        }
        fn status_msg(&self) -> Option<&str> {
            self.status.as_deref()
        }
        fn name(&self) -> &str {
            &self.name
        }
    }

    #[derive(Debug)]
    struct TestBgCommand {
        name: String,
        has_progress: bool,
        can_cancel: bool,
    }

    impl TestBgCommand {
        fn new(name: &str) -> Self {
            Self {
                name: name.to_string(),
                has_progress: true,
                can_cancel: true,
            }
        }
    }

    impl BackgroundCommand for TestBgCommand {
        fn name(&self) -> &str {
            &self.name
        }
        fn has_progress(&self) -> bool {
            self.has_progress
        }
        fn can_cancel(&self) -> bool {
            self.can_cancel
        }
        fn is_modal(&self) -> bool {
            false
        }
        fn apply_to(
            &mut self,
            _object_id: u64,
            _monitor: &mut dyn BackgroundCommandMonitor,
        ) -> bool {
            true
        }
        fn status_msg(&self) -> Option<&str> {
            None
        }
    }

    #[test]
    fn test_command_apply() {
        let mut cmd = TestCommand::new("test", true);
        assert!(cmd.apply_to(1));
        assert!(cmd.status_msg().is_none());
        assert_eq!(cmd.name(), "test");

        let mut cmd2 = TestCommand::new("fail", false);
        assert!(!cmd2.apply_to(1));
        assert_eq!(cmd2.status_msg(), Some("command failed"));
    }

    #[test]
    fn test_compound_cmd() {
        let mut compound = CompoundCmd::new("compound");
        compound.add(Box::new(TestCommand::new("step1", true)));
        compound.add(Box::new(TestCommand::new("step2", true)));
        assert_eq!(compound.command_count(), 2);
        assert!(compound.apply_to(1));

        let mut compound2 = CompoundCmd::new("compound_fail");
        compound2.add(Box::new(TestCommand::new("step1", true)));
        compound2.add(Box::new(TestCommand::new("step2", false)));
        assert!(!compound2.apply_to(1));
        assert!(compound2.status_msg().is_some());
    }

    #[test]
    fn test_compound_background_command() {
        let mut compound = CompoundBackgroundCommand::new("bg_compound");
        compound.add(Box::new(TestBgCommand::new("bg1")));
        compound.add(Box::new(TestBgCommand::new("bg2")));
        assert_eq!(compound.command_count(), 2);
        assert!(compound.has_progress());
        assert!(compound.can_cancel());
    }

    #[test]
    fn test_command_result() {
        let success = CommandResult::success("my_cmd");
        assert!(success.is_success());
        assert!(success.message().is_none());

        let failure = CommandResult::failure("my_cmd", "something went wrong");
        assert!(!failure.is_success());
        assert_eq!(failure.message(), Some("something went wrong"));
        assert!(format!("{}", failure).contains("something went wrong"));
    }

    #[test]
    fn test_command_manager() {
        let mut mgr = CommandManager::new();
        let result = mgr.execute(&mut TestCommand::new("cmd1", true), 1);
        assert!(result.is_success());
        assert_eq!(mgr.history_count(), 1);

        let result2 = mgr.execute(&mut TestCommand::new("cmd2", false), 1);
        assert!(!result2.is_success());
        assert_eq!(mgr.history_count(), 2);

        mgr.clear_history();
        assert_eq!(mgr.history_count(), 0);
    }

    #[test]
    fn test_command_manager_max_history() {
        let mut mgr = CommandManager::new();
        mgr.set_max_history(3);
        for i in 0..5 {
            mgr.execute(&mut TestCommand::new(&format!("cmd{}", i), true), 1);
        }
        assert_eq!(mgr.history_count(), 3);
    }
}
