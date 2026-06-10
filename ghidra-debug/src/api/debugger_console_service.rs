//! DebuggerConsoleService - service for managing the debug console.
//!
//! Ported from Ghidra's `ghidra.debug.api.console.DebuggerConsoleService`.
//!
//! The debug console provides a text-based interface for sending commands
//! and receiving output from the debug target. This service manages console
//! sessions, output buffering, and command history.

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::fmt;
use std::sync::{Arc, Mutex};

/// The type of a console message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ConsoleMessageType {
    /// Normal output from the target.
    Output,
    /// Error output from the target.
    Error,
    /// Input typed by the user.
    Input,
    /// Informational message from the debugger.
    Info,
    /// Warning message.
    Warning,
}

impl fmt::Display for ConsoleMessageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Output => write!(f, "OUTPUT"),
            Self::Error => write!(f, "ERROR"),
            Self::Input => write!(f, "INPUT"),
            Self::Info => write!(f, "INFO"),
            Self::Warning => write!(f, "WARNING"),
        }
    }
}

/// A single message in the console output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsoleMessage {
    /// The type of message.
    pub msg_type: ConsoleMessageType,
    /// The text content of the message.
    pub text: String,
    /// Timestamp (epoch millis) when the message was created.
    pub timestamp: i64,
}

impl ConsoleMessage {
    /// Create a new console message with the current timestamp.
    pub fn new(msg_type: ConsoleMessageType, text: impl Into<String>) -> Self {
        Self {
            msg_type,
            text: text.into(),
            timestamp: now_millis(),
        }
    }

    /// Create an output message.
    pub fn output(text: impl Into<String>) -> Self {
        Self::new(ConsoleMessageType::Output, text)
    }

    /// Create an error message.
    pub fn error(text: impl Into<String>) -> Self {
        Self::new(ConsoleMessageType::Error, text)
    }

    /// Create an input message (user-typed command).
    pub fn input(text: impl Into<String>) -> Self {
        Self::new(ConsoleMessageType::Input, text)
    }

    /// Create an info message.
    pub fn info(text: impl Into<String>) -> Self {
        Self::new(ConsoleMessageType::Info, text)
    }

    /// Create a warning message.
    pub fn warning(text: impl Into<String>) -> Self {
        Self::new(ConsoleMessageType::Warning, text)
    }
}

/// Listener for console output events.
pub trait ConsoleListener: Send + Sync {
    /// Called when a new message is appended to the console.
    fn message_appended(&self, message: &ConsoleMessage);

    /// Called when the console output is cleared.
    fn console_cleared(&self);
}

/// Service for managing the debug console.
///
/// This service provides:
/// - Sending commands to the debug target
/// - Receiving and buffering console output
/// - Command history navigation
/// - Console output filtering
pub struct DebuggerConsoleService {
    /// Buffered console messages.
    messages: Mutex<VecDeque<ConsoleMessage>>,
    /// Command history.
    history: Mutex<VecDeque<String>>,
    /// Maximum number of messages to keep in the buffer.
    max_messages: usize,
    /// Maximum command history entries.
    max_history: usize,
    /// Registered listeners.
    listeners: Mutex<Vec<Arc<dyn ConsoleListener>>>,
}

impl DebuggerConsoleService {
    /// Create a new console service with default limits.
    pub fn new() -> Self {
        Self {
            messages: Mutex::new(VecDeque::new()),
            history: Mutex::new(VecDeque::new()),
            max_messages: 10_000,
            max_history: 500,
            listeners: Mutex::new(Vec::new()),
        }
    }

    /// Create a new console service with custom limits.
    pub fn with_limits(max_messages: usize, max_history: usize) -> Self {
        Self {
            messages: Mutex::new(VecDeque::new()),
            history: Mutex::new(VecDeque::new()),
            max_messages,
            max_history,
            listeners: Mutex::new(Vec::new()),
        }
    }

    /// Register a listener for console events.
    pub fn add_listener(&self, listener: Arc<dyn ConsoleListener>) {
        if let Ok(mut listeners) = self.listeners.lock() {
            listeners.push(listener);
        }
    }

    /// Append a message to the console.
    pub fn append(&self, message: ConsoleMessage) {
        // Notify listeners.
        if let Ok(listeners) = self.listeners.lock() {
            for listener in listeners.iter() {
                listener.message_appended(&message);
            }
        }

        // Add to buffer.
        if let Ok(mut messages) = self.messages.lock() {
            if messages.len() >= self.max_messages {
                messages.pop_front();
            }
            messages.push_back(message);
        }
    }

    /// Append output text.
    pub fn append_output(&self, text: impl Into<String>) {
        self.append(ConsoleMessage::output(text));
    }

    /// Append error text.
    pub fn append_error(&self, text: impl Into<String>) {
        self.append(ConsoleMessage::error(text));
    }

    /// Append an info message.
    pub fn append_info(&self, text: impl Into<String>) {
        self.append(ConsoleMessage::info(text));
    }

    /// Send a command to the debug target and record it in history.
    ///
    /// Returns the command string for the caller to dispatch to the actual
    /// debug target. The command is recorded in history regardless of success.
    pub fn send_command(&self, command: impl Into<String>) -> String {
        let cmd = command.into();

        // Record in input history.
        if let Ok(mut history) = self.history.lock() {
            if history.len() >= self.max_history {
                history.pop_front();
            }
            history.push_back(cmd.clone());
        }

        // Echo the command as an input message.
        self.append(ConsoleMessage::input(&cmd));

        cmd
    }

    /// Get the current console messages.
    pub fn messages(&self) -> Vec<ConsoleMessage> {
        self.messages
            .lock()
            .map(|m| m.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Get messages filtered by type.
    pub fn messages_of_type(&self, msg_type: ConsoleMessageType) -> Vec<ConsoleMessage> {
        self.messages
            .lock()
            .map(|m| m.iter().filter(|msg| msg.msg_type == msg_type).cloned().collect())
            .unwrap_or_default()
    }

    /// Get the command history.
    pub fn history(&self) -> Vec<String> {
        self.history
            .lock()
            .map(|h| h.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Clear all console output.
    pub fn clear(&self) {
        if let Ok(mut messages) = self.messages.lock() {
            messages.clear();
        }

        // Notify listeners.
        if let Ok(listeners) = self.listeners.lock() {
            for listener in listeners.iter() {
                listener.console_cleared();
            }
        }
    }

    /// Clear command history.
    pub fn clear_history(&self) {
        if let Ok(mut history) = self.history.lock() {
            history.clear();
        }
    }

    /// Get the number of buffered messages.
    pub fn message_count(&self) -> usize {
        self.messages.lock().map(|m| m.len()).unwrap_or(0)
    }

    /// Get the number of history entries.
    pub fn history_count(&self) -> usize {
        self.history.lock().map(|h| h.len()).unwrap_or(0)
    }

    /// Get all messages as a single concatenated string.
    pub fn text(&self) -> String {
        self.messages
            .lock()
            .map(|m| {
                m.iter()
                    .map(|msg| msg.text.as_str())
                    .collect::<Vec<_>>()
                    .join("\n")
            })
            .unwrap_or_default()
    }
}

impl Default for DebuggerConsoleService {
    fn default() -> Self {
        Self::new()
    }
}

/// Get current time in milliseconds (simplified for portability).
fn now_millis() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct TestListener {
        append_count: AtomicUsize,
        clear_count: AtomicUsize,
    }

    impl TestListener {
        fn new() -> Self {
            Self {
                append_count: AtomicUsize::new(0),
                clear_count: AtomicUsize::new(0),
            }
        }
    }

    impl ConsoleListener for TestListener {
        fn message_appended(&self, _message: &ConsoleMessage) {
            self.append_count.fetch_add(1, Ordering::SeqCst);
        }

        fn console_cleared(&self) {
            self.clear_count.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn test_console_service_new() {
        let svc = DebuggerConsoleService::new();
        assert_eq!(svc.message_count(), 0);
        assert_eq!(svc.history_count(), 0);
    }

    #[test]
    fn test_append_messages() {
        let svc = DebuggerConsoleService::new();
        svc.append_output("Hello");
        svc.append_error("Error occurred");
        svc.append_info("Info message");
        assert_eq!(svc.message_count(), 3);
    }

    #[test]
    fn test_messages_of_type() {
        let svc = DebuggerConsoleService::new();
        svc.append_output("out1");
        svc.append_error("err1");
        svc.append_output("out2");
        assert_eq!(svc.messages_of_type(ConsoleMessageType::Output).len(), 2);
        assert_eq!(svc.messages_of_type(ConsoleMessageType::Error).len(), 1);
    }

    #[test]
    fn test_send_command() {
        let svc = DebuggerConsoleService::new();
        let cmd = svc.send_command("break *main");
        assert_eq!(cmd, "break *main");
        assert_eq!(svc.history_count(), 1);
        assert_eq!(svc.message_count(), 1); // The echoed input
    }

    #[test]
    fn test_history_navigation() {
        let svc = DebuggerConsoleService::new();
        svc.send_command("cmd1");
        svc.send_command("cmd2");
        svc.send_command("cmd3");
        let history = svc.history();
        assert_eq!(history, vec!["cmd1", "cmd2", "cmd3"]);
    }

    #[test]
    fn test_clear() {
        let svc = DebuggerConsoleService::new();
        svc.append_output("test");
        svc.clear();
        assert_eq!(svc.message_count(), 0);
    }

    #[test]
    fn test_clear_history() {
        let svc = DebuggerConsoleService::new();
        svc.send_command("cmd1");
        svc.clear_history();
        assert_eq!(svc.history_count(), 0);
    }

    #[test]
    fn test_max_messages_limit() {
        let svc = DebuggerConsoleService::with_limits(3, 10);
        svc.append_output("a");
        svc.append_output("b");
        svc.append_output("c");
        svc.append_output("d");
        assert_eq!(svc.message_count(), 3);
        let msgs = svc.messages();
        assert_eq!(msgs[0].text, "b");
        assert_eq!(msgs[2].text, "d");
    }

    #[test]
    fn test_max_history_limit() {
        let svc = DebuggerConsoleService::with_limits(100, 2);
        svc.send_command("a");
        svc.send_command("b");
        svc.send_command("c");
        let history = svc.history();
        assert_eq!(history, vec!["b", "c"]);
    }

    #[test]
    fn test_listener_notification() {
        let listener = Arc::new(TestListener::new());
        let svc = DebuggerConsoleService::new();
        svc.add_listener(listener.clone());

        svc.append_output("test");
        svc.append_output("test2");
        svc.clear();

        assert_eq!(listener.append_count.load(Ordering::SeqCst), 2);
        assert_eq!(listener.clear_count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_text_concatenation() {
        let svc = DebuggerConsoleService::new();
        svc.append_output("line1");
        svc.append_output("line2");
        let text = svc.text();
        assert!(text.contains("line1"));
        assert!(text.contains("line2"));
    }

    #[test]
    fn test_console_message_types() {
        assert_eq!(ConsoleMessageType::Output.to_string(), "OUTPUT");
        assert_eq!(ConsoleMessageType::Error.to_string(), "ERROR");
        assert_eq!(ConsoleMessageType::Input.to_string(), "INPUT");
    }

    #[test]
    fn test_console_message_builders() {
        let msg = ConsoleMessage::output("out");
        assert_eq!(msg.msg_type, ConsoleMessageType::Output);
        assert_eq!(msg.text, "out");
        assert!(msg.timestamp > 0);

        let err = ConsoleMessage::error("err");
        assert_eq!(err.msg_type, ConsoleMessageType::Error);

        let input = ConsoleMessage::input("cmd");
        assert_eq!(input.msg_type, ConsoleMessageType::Input);
    }
}
