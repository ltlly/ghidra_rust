//! Script control mechanisms for output and monitoring.
//!
//! Ported from `ghidra.app.script.ScriptControls`.
//!
//! Encapsulates the output writers and task monitor that control a running
//! GhidraScript's feedback to the user (stdout, stderr, progress).

use std::fmt;
use std::io::{self, Write};
use std::sync::{Arc, Mutex};

// ---------------------------------------------------------------------------
// TaskMonitor trait
// ---------------------------------------------------------------------------

/// A simple cancellation/progress monitor for long-running operations.
///
/// This is a minimal port of Ghidra's `TaskMonitor` interface.
pub trait TaskMonitor: Send + Sync {
    /// Check whether the operation has been cancelled.
    fn is_cancelled(&self) -> bool;

    /// Set the maximum progress value.
    fn set_maximum(&mut self, max: u64);

    /// Set the current progress value.
    fn set_progress(&mut self, value: u64);

    /// Increment the progress by the given amount.
    fn increment_progress(&mut self, amount: u64) {
        let current = self.progress();
        self.set_progress(current + amount);
    }

    /// Get the current progress value.
    fn progress(&self) -> u64;

    /// Get the maximum progress value.
    fn maximum(&self) -> u64;

    /// Set a status message.
    fn set_message(&mut self, message: &str);

    /// Get the current status message.
    fn message(&self) -> String;

    /// Indicate whether the monitor shows progress.
    fn is_indeterminate(&self) -> bool {
        self.maximum() == 0
    }

    /// Cancel the operation.
    fn cancel(&mut self);

    /// Reset the monitor to its initial state.
    fn reset(&mut self) {
        self.set_progress(0);
        self.set_maximum(0);
        self.set_message("");
    }
}

/// A dummy monitor that never cancels and ignores progress.
#[derive(Debug, Clone, Copy)]
pub struct DummyMonitor;

impl TaskMonitor for DummyMonitor {
    fn is_cancelled(&self) -> bool {
        false
    }
    fn set_maximum(&mut self, _max: u64) {}
    fn set_progress(&mut self, _value: u64) {}
    fn progress(&self) -> u64 {
        0
    }
    fn maximum(&self) -> u64 {
        0
    }
    fn set_message(&mut self, _message: &str) {}
    fn message(&self) -> String {
        String::new()
    }
    fn cancel(&mut self) {}
}

/// A basic monitor that tracks progress and cancellation.
#[derive(Debug)]
pub struct BasicMonitor {
    maximum: u64,
    progress: u64,
    message: String,
    cancelled: bool,
}

impl BasicMonitor {
    /// Create a new basic monitor.
    pub fn new() -> Self {
        Self {
            maximum: 0,
            progress: 0,
            message: String::new(),
            cancelled: false,
        }
    }
}

impl Default for BasicMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl TaskMonitor for BasicMonitor {
    fn is_cancelled(&self) -> bool {
        self.cancelled
    }
    fn set_maximum(&mut self, max: u64) {
        self.maximum = max;
    }
    fn set_progress(&mut self, value: u64) {
        self.progress = value;
    }
    fn progress(&self) -> u64 {
        self.progress
    }
    fn maximum(&self) -> u64 {
        self.maximum
    }
    fn set_message(&mut self, message: &str) {
        self.message = message.to_string();
    }
    fn message(&self) -> String {
        self.message.clone()
    }
    fn cancel(&mut self) {
        self.cancelled = true;
    }
    fn reset(&mut self) {
        self.progress = 0;
        self.maximum = 0;
        self.message.clear();
        self.cancelled = false;
    }
}

// ---------------------------------------------------------------------------
// ScriptControls
// ---------------------------------------------------------------------------

/// Controls for a running GhidraScript.
///
/// Ported from `ghidra.app.script.ScriptControls`.
///
/// Encapsulates the stdout/stderr writers, output decoration setting, and
/// the cancellable task monitor. Scripts use this to write output and check
/// for cancellation.
pub struct ScriptControls {
    writer: Arc<Mutex<Vec<u8>>>,
    error_writer: Arc<Mutex<Vec<u8>>>,
    decorate_output: bool,
    monitor: Box<dyn TaskMonitor>,
}

impl ScriptControls {
    /// Create new controls with custom writers.
    pub fn new(
        writer: Arc<Mutex<Vec<u8>>>,
        error_writer: Arc<Mutex<Vec<u8>>>,
        decorate_output: bool,
        monitor: Box<dyn TaskMonitor>,
    ) -> Self {
        Self {
            writer,
            error_writer,
            decorate_output,
            monitor,
        }
    }

    /// Create controls with no output and a dummy monitor.
    pub fn none() -> Self {
        Self {
            writer: Arc::new(Mutex::new(Vec::new())),
            error_writer: Arc::new(Mutex::new(Vec::new())),
            decorate_output: false,
            monitor: Box::new(DummyMonitor),
        }
    }

    /// Whether output should be decorated with script name prefix.
    pub fn decorate_output(&self) -> bool {
        self.decorate_output
    }

    /// Get a reference to the task monitor.
    pub fn monitor(&self) -> &dyn TaskMonitor {
        self.monitor.as_ref()
    }

    /// Get a mutable reference to the task monitor.
    pub fn monitor_mut(&mut self) -> &mut dyn TaskMonitor {
        self.monitor.as_mut()
    }

    /// Write to the standard output writer.
    pub fn print(&self, text: &str) -> io::Result<()> {
        let mut buf = self.writer.lock().map_err(|_| {
            io::Error::new(io::ErrorKind::Other, "writer lock poisoned")
        })?;
        buf.write_all(text.as_bytes())
    }

    /// Write a line to the standard output writer.
    pub fn println(&self, text: &str) -> io::Result<()> {
        self.print(text)?;
        self.print("\n")
    }

    /// Write to the error output writer.
    pub fn printerr(&self, text: &str) -> io::Result<()> {
        let mut buf = self.error_writer.lock().map_err(|_| {
            io::Error::new(io::ErrorKind::Other, "error writer lock poisoned")
        })?;
        buf.write_all(text.as_bytes())
    }

    /// Write a line to the error output writer.
    pub fn printerrln(&self, text: &str) -> io::Result<()> {
        self.printerr(text)?;
        self.printerr("\n")
    }

    /// Get the contents written to stdout so far.
    pub fn stdout_contents(&self) -> String {
        self.writer
            .lock()
            .ok()
            .and_then(|buf| String::from_utf8(buf.clone()).ok())
            .unwrap_or_default()
    }

    /// Get the contents written to stderr so far.
    pub fn stderr_contents(&self) -> String {
        self.error_writer
            .lock()
            .ok()
            .and_then(|buf| String::from_utf8(buf.clone()).ok())
            .unwrap_or_default()
    }

    /// Decorate a message with the script name prefix (if decoration is enabled).
    pub fn decorate(&self, script_name: &str, message: &str) -> String {
        if self.decorate_output {
            format!("[{}] {}", script_name, message)
        } else {
            message.to_string()
        }
    }
}

impl fmt::Debug for ScriptControls {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScriptControls")
            .field("decorate_output", &self.decorate_output)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// DecoratingPrintWriter
// ---------------------------------------------------------------------------

/// A writer that prepends a decoration prefix to every line.
///
/// Ported from `ghidra.app.script.DecoratingPrintWriter`.
#[derive(Debug)]
pub struct DecoratingPrintWriter {
    prefix: String,
    buffer: Arc<Mutex<Vec<u8>>>,
}

impl DecoratingPrintWriter {
    /// Create a new decorating writer.
    pub fn new(prefix: impl Into<String>) -> Self {
        Self {
            prefix: prefix.into(),
            buffer: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Write a message with decoration.
    pub fn write(&self, text: &str) -> io::Result<()> {
        let decorated = format!("[{}] {}", self.prefix, text);
        let mut buf = self.buffer.lock().map_err(|_| {
            io::Error::new(io::ErrorKind::Other, "buffer lock poisoned")
        })?;
        buf.write_all(decorated.as_bytes())
    }

    /// Write a decorated line.
    pub fn writeln(&self, text: &str) -> io::Result<()> {
        let mut decorated = format!("[{}] {}", self.prefix, text);
        decorated.push('\n');
        let mut buf = self.buffer.lock().map_err(|_| {
            io::Error::new(io::ErrorKind::Other, "buffer lock poisoned")
        })?;
        buf.write_all(decorated.as_bytes())
    }

    /// Get the contents written so far.
    pub fn contents(&self) -> String {
        self.buffer
            .lock()
            .ok()
            .and_then(|buf| String::from_utf8(buf.clone()).ok())
            .unwrap_or_default()
    }

    /// Get a clone of the underlying buffer.
    pub fn buffer_clone(&self) -> Arc<Mutex<Vec<u8>>> {
        Arc::clone(&self.buffer)
    }
}

// ---------------------------------------------------------------------------
// StringTransformer
// ---------------------------------------------------------------------------

/// Trait for transforming script output strings.
///
/// Ported from `ghidra.app.script.StringTransformer`.
pub trait StringTransformer: Send + Sync + fmt::Debug {
    /// Transform a string.
    fn transform(&self, input: &str) -> String;
}

/// A transformer that wraps text in HTML tags.
#[derive(Debug)]
pub struct HtmlWrapper {
    /// The tag name to wrap with.
    pub tag: String,
    /// Optional CSS style string.
    pub style: Option<String>,
}

impl StringTransformer for HtmlWrapper {
    fn transform(&self, input: &str) -> String {
        match &self.style {
            Some(s) => format!("<{} style=\"{}\">{}</{}>", self.tag, s, input, self.tag),
            None => format!("<{}>{}</{}>", self.tag, input, self.tag),
        }
    }
}

/// A transformer that prepends a timestamp.
#[derive(Debug)]
pub struct TimestampPrefix {
    /// Whether to use UTC.
    pub utc: bool,
}

impl StringTransformer for TimestampPrefix {
    fn transform(&self, input: &str) -> String {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let prefix = if self.utc {
            format!("[UTC {}]", now)
        } else {
            format!("[{}]", now)
        };
        format!("{} {}", prefix, input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_script_controls_none() {
        let controls = ScriptControls::none();
        assert!(!controls.decorate_output());
        assert!(!controls.monitor().is_cancelled());
    }

    #[test]
    fn test_script_controls_print() {
        let controls = ScriptControls::none();
        controls.println("Hello, world!").unwrap();
        controls.printerrln("Error!").unwrap();
        assert_eq!(controls.stdout_contents(), "Hello, world!\n");
        assert_eq!(controls.stderr_contents(), "Error!\n");
    }

    #[test]
    fn test_script_controls_decorate() {
        let mut controls = ScriptControls::none();
        assert_eq!(controls.decorate("MyScript", "msg"), "msg");

        controls.decorate_output = true;
        assert_eq!(controls.decorate("MyScript", "msg"), "[MyScript] msg");
    }

    #[test]
    fn test_decorating_print_writer() {
        let writer = DecoratingPrintWriter::new("ScriptA");
        writer.writeln("line 1").unwrap();
        writer.writeln("line 2").unwrap();

        let contents = writer.contents();
        assert!(contents.contains("[ScriptA] line 1"));
        assert!(contents.contains("[ScriptA] line 2"));
    }

    #[test]
    fn test_dummy_monitor() {
        let mut monitor = DummyMonitor;
        assert!(!monitor.is_cancelled());
        monitor.set_maximum(100);
        monitor.set_progress(50);
        assert_eq!(monitor.progress(), 0); // Dummy ignores
        monitor.cancel();
        assert!(!monitor.is_cancelled()); // Dummy ignores
    }

    #[test]
    fn test_basic_monitor() {
        let mut monitor = BasicMonitor::new();
        assert!(!monitor.is_cancelled());
        assert_eq!(monitor.progress(), 0);

        monitor.set_maximum(100);
        monitor.set_progress(25);
        assert_eq!(monitor.progress(), 25);
        assert_eq!(monitor.maximum(), 100);

        monitor.increment_progress(10);
        assert_eq!(monitor.progress(), 35);

        monitor.set_message("Analyzing...");
        assert_eq!(monitor.message(), "Analyzing...");

        monitor.cancel();
        assert!(monitor.is_cancelled());

        monitor.reset();
        assert!(!monitor.is_cancelled());
        assert_eq!(monitor.progress(), 0);
    }

    #[test]
    fn test_html_wrapper_transformer() {
        let transformer = HtmlWrapper {
            tag: "b".to_string(),
            style: None,
        };
        assert_eq!(transformer.transform("text"), "<b>text</b>");

        let transformer_with_style = HtmlWrapper {
            tag: "span".to_string(),
            style: Some("color:red".to_string()),
        };
        assert_eq!(
            transformer_with_style.transform("hi"),
            "<span style=\"color:red\">hi</span>"
        );
    }

    #[test]
    fn test_timestamp_prefix_transformer() {
        let transformer = TimestampPrefix { utc: false };
        let result = transformer.transform("hello");
        assert!(result.starts_with('['));
        assert!(result.contains("hello"));
    }
}
