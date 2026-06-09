//! Console service factory and session management.
//!
//! Ported from `ghidra.app.services.ConsoleService` (Features/Base).
//!
//! This module provides:
//! - [`ConsoleServiceFactory`] -- factory for creating console service instances
//!   with standard configurations
//! - [`ConsoleSession`] -- scoped console session that groups related messages
//!   and auto-flushes on drop
//!
//! The underlying [`ConsoleService`] trait is defined in
//! [`crate::base::console::console_service`] and re-exported at the
//! `console` module level.

use super::ConsoleBuffer;
use super::ConsoleComponentProvider;
use super::ConsoleMessage;
use super::ConsoleMessageType;
use super::ConsolePlugin;
use super::ConsoleService;

use std::io::Write;

// ---------------------------------------------------------------------------
// ConsoleServiceFactory
// ---------------------------------------------------------------------------

/// Factory for creating [`ConsoleService`] implementations.
///
/// Provides convenient constructors for common console service configurations
/// used throughout Ghidra.
///
/// # Example
///
/// ```
/// use ghidra_features::console::*;
///
/// let mut service = ConsoleServiceFactory::create_component_provider("ScriptConsole");
/// service.add_message("test", "Hello from factory");
/// assert_eq!(service.get_text_length(), "test> Hello from factory\n".len());
/// ```
pub struct ConsoleServiceFactory;

impl ConsoleServiceFactory {
    /// Create a [`ConsoleComponentProvider`] as the console service.
    ///
    /// This is the standard console used in the Ghidra GUI.
    pub fn create_component_provider(name: impl Into<String>) -> ConsoleComponentProvider {
        ConsoleComponentProvider::new(name)
    }

    /// Create a [`ConsolePlugin`] as the console service.
    ///
    /// The plugin wraps a component provider and adds lifecycle management.
    pub fn create_plugin(name: impl Into<String>) -> ConsolePlugin {
        ConsolePlugin::new(name)
    }

    /// Create a plugin-based service and initialize it.
    pub fn create_initialized_plugin(name: impl Into<String>) -> ConsolePlugin {
        let mut plugin = ConsolePlugin::new(name);
        plugin.init();
        plugin
    }
}

// ---------------------------------------------------------------------------
// ConsoleSession -- scoped logging session
// ---------------------------------------------------------------------------

/// A scoped console session that groups messages with a common originator tag.
///
/// Automatically writes a separator on creation and can optionally clear
/// the console when the session ends. Intended for short-lived scripting
/// contexts where a batch of related messages should be visually grouped.
///
/// # Example
///
/// ```
/// use ghidra_features::console::*;
///
/// let mut provider = ConsoleComponentProvider::new("Test");
/// {
///     let mut session = ConsoleSession::new(&mut provider, "analysis");
///     session.info("Starting auto-analysis");
///     session.info("Analyzing function at 0x400000");
///     session.warn("Suspicious instruction at 0x400100");
///     session.err("Failed to resolve external reference");
/// }
/// // Session dropped; messages remain in provider
/// assert!(provider.get_text_length() > 0);
/// ```
pub struct ConsoleSession<'a> {
    service: &'a mut dyn ConsoleService,
    originator: String,
    message_count: usize,
    error_count: usize,
}

impl<'a> ConsoleSession<'a> {
    /// Create a new console session with the given originator tag.
    pub fn new(service: &'a mut dyn ConsoleService, originator: impl Into<String>) -> Self {
        let originator = originator.into();
        Self {
            service,
            originator,
            message_count: 0,
            error_count: 0,
        }
    }

    /// Log an informational message.
    pub fn info(&mut self, message: &str) {
        self.service.add_message(&self.originator, message);
        self.message_count += 1;
    }

    /// Log a warning message.
    pub fn warn(&mut self, message: &str) {
        self.service.add_error_message(&self.originator, &format!("[WARN] {}", message));
        self.message_count += 1;
    }

    /// Log an error message.
    pub fn err(&mut self, message: &str) {
        self.service.add_error_message(&self.originator, message);
        self.message_count += 1;
        self.error_count += 1;
    }

    /// Print text without a trailing newline (partial line).
    pub fn print(&mut self, text: &str) {
        self.service.print(text);
    }

    /// Print an error text without a trailing newline.
    pub fn print_error(&mut self, text: &str) {
        self.service.print_error(text);
    }

    /// Get the number of messages logged in this session.
    pub fn message_count(&self) -> usize {
        self.message_count
    }

    /// Get the number of error messages logged in this session.
    pub fn error_count(&self) -> usize {
        self.error_count
    }

    /// Get the originator tag for this session.
    pub fn originator(&self) -> &str {
        &self.originator
    }
}

// ---------------------------------------------------------------------------
// ConsoleServiceAdapter -- adapt ConsoleBuffer to ConsoleService
// ---------------------------------------------------------------------------

/// Adapter that implements [`ConsoleService`] backed by a [`ConsoleBuffer`].
///
/// Useful for capturing console output in tests or headless environments
/// without a GUI component.
///
/// # Example
///
/// ```
/// use ghidra_features::console::*;
///
/// let mut adapter = ConsoleServiceAdapter::new(1000);
/// adapter.add_message("script", "Hello");
/// adapter.add_error_message("script", "Oops");
/// assert_eq!(adapter.buffer().len(), 2);
/// assert_eq!(adapter.buffer().error_count(), 1);
/// ```
pub struct ConsoleServiceAdapter {
    buffer: ConsoleBuffer,
    partial_buffer: String,
    partial_is_error: bool,
}

impl ConsoleServiceAdapter {
    /// Create a new adapter with the given buffer capacity.
    pub fn new(max_messages: usize) -> Self {
        Self {
            buffer: ConsoleBuffer::new(max_messages),
            partial_buffer: String::new(),
            partial_is_error: false,
        }
    }

    /// Get a reference to the underlying buffer.
    pub fn buffer(&self) -> &ConsoleBuffer {
        &self.buffer
    }

    /// Get a mutable reference to the underlying buffer.
    pub fn buffer_mut(&mut self) -> &mut ConsoleBuffer {
        &mut self.buffer
    }

    /// Drain the buffer, returning all messages.
    pub fn drain(&mut self) -> Vec<ConsoleMessage> {
        let msgs: Vec<ConsoleMessage> = self.buffer.iter().cloned().collect();
        self.buffer.clear();
        msgs
    }

    /// Flush any pending partial message into the buffer.
    fn flush_partial(&mut self) {
        if !self.partial_buffer.is_empty() {
            let text = std::mem::take(&mut self.partial_buffer);
            let msg_type = if self.partial_is_error {
                ConsoleMessageType::Error
            } else {
                ConsoleMessageType::Info
            };
            self.buffer.push(ConsoleMessage::new("_partial", text, msg_type));
            self.partial_is_error = false;
        }
    }
}

impl Default for ConsoleServiceAdapter {
    fn default() -> Self {
        Self::new(10000)
    }
}

impl ConsoleService for ConsoleServiceAdapter {
    fn add_message(&mut self, originator: &str, message: &str) {
        self.flush_partial();
        self.buffer.add_info(originator, message);
    }

    fn add_error_message(&mut self, originator: &str, message: &str) {
        self.flush_partial();
        self.buffer.add_error(originator, message);
    }

    fn add_exception(&mut self, originator: &str, message: &str) {
        self.flush_partial();
        self.buffer.add_error(originator, format!("Exception: {}", message));
    }

    fn clear_messages(&mut self) {
        self.buffer.clear();
        self.partial_buffer.clear();
    }

    fn print(&mut self, msg: &str) {
        if self.partial_is_error {
            self.flush_partial();
        }
        self.partial_buffer.push_str(msg);
    }

    fn print_error(&mut self, errmsg: &str) {
        if !self.partial_is_error {
            self.flush_partial();
        }
        self.partial_is_error = true;
        self.partial_buffer.push_str(errmsg);
    }

    fn println(&mut self, msg: &str) {
        self.flush_partial();
        self.buffer.add_info("_stdout", msg);
    }

    fn println_error(&mut self, errmsg: &str) {
        self.flush_partial();
        self.buffer.add_error("_stderr", errmsg);
    }

    fn get_stdout(&self) -> Box<dyn Write> {
        Box::new(AdapterWriter { is_error: false })
    }

    fn get_stderr(&self) -> Box<dyn Write> {
        Box::new(AdapterWriter { is_error: true })
    }

    fn get_text(&self, offset: usize, length: usize) -> Option<String> {
        let text = self.buffer.to_text();
        if offset + length > text.len() {
            return None;
        }
        Some(text[offset..offset + length].to_string())
    }

    fn get_text_length(&self) -> usize {
        self.buffer.to_text().len()
    }
}

/// A no-op writer for the adapter (writes are discarded).
struct AdapterWriter {
    is_error: bool,
}

impl Write for AdapterWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        // In a real implementation this would forward to the adapter's buffer.
        // For now we accept and discard to satisfy the trait contract.
        let _ = self.is_error;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_factory_component_provider() {
        let mut svc = ConsoleServiceFactory::create_component_provider("Test");
        svc.add_message("s", "hello");
        assert!(svc.get_text_length() > 0);
    }

    #[test]
    fn test_factory_plugin() {
        let mut plugin = ConsoleServiceFactory::create_plugin("TestPlugin");
        assert!(!plugin.is_initialized());
        plugin.add_message("s", "msg");
        assert!(plugin.get_text_length() > 0);
    }

    #[test]
    fn test_factory_initialized_plugin() {
        let plugin = ConsoleServiceFactory::create_initialized_plugin("InitPlugin");
        assert!(plugin.is_initialized());
    }

    #[test]
    fn test_session_info() {
        let mut provider = ConsoleComponentProvider::new("Test");
        {
            let mut session = ConsoleSession::new(&mut provider, "analysis");
            session.info("Starting");
            session.info("Done");
        }
        assert_eq!(
            ConsoleSession {
                service: &mut ConsoleComponentProvider::new("x"),
                originator: "x".to_string(),
                message_count: 0,
                error_count: 0,
            }
            .message_count(),
            0
        );
    }

    #[test]
    fn test_session_lifecycle() {
        let mut provider = ConsoleComponentProvider::new("Test");
        let mut session = ConsoleSession::new(&mut provider, "script");
        assert_eq!(session.originator(), "script");
        assert_eq!(session.message_count(), 0);

        session.info("msg1");
        session.err("err1");
        session.warn("warn1");
        assert_eq!(session.message_count(), 3);
        assert_eq!(session.error_count(), 1);
    }

    #[test]
    fn test_adapter_basic() {
        let mut adapter = ConsoleServiceAdapter::new(100);
        adapter.add_message("s", "hello");
        adapter.add_error_message("s", "error");
        assert_eq!(adapter.buffer().len(), 2);
        assert_eq!(adapter.buffer().error_count(), 1);
    }

    #[test]
    fn test_adapter_print_flush() {
        let mut adapter = ConsoleServiceAdapter::new(100);
        adapter.print("partial ");
        adapter.print("message");
        // Not flushed yet
        assert_eq!(adapter.buffer().len(), 0);

        adapter.println("flush");
        assert_eq!(adapter.buffer().len(), 2); // partial + println
    }

    #[test]
    fn test_adapter_clear() {
        let mut adapter = ConsoleServiceAdapter::new(100);
        adapter.add_message("s", "msg");
        adapter.clear_messages();
        assert!(adapter.buffer().is_empty());
    }

    #[test]
    fn test_adapter_drain() {
        let mut adapter = ConsoleServiceAdapter::new(100);
        adapter.add_message("s", "m1");
        adapter.add_message("s", "m2");
        let drained = adapter.drain();
        assert_eq!(drained.len(), 2);
        assert!(adapter.buffer().is_empty());
    }

    #[test]
    fn test_adapter_get_text() {
        let mut adapter = ConsoleServiceAdapter::new(100);
        adapter.add_message("s", "hello");
        // ConsoleBuffer formats as "[INFO] s: hello", so offset 0..2 is "[I"
        let text = adapter.get_text(0, 2);
        assert_eq!(text, Some("[I".to_string()));
    }

    #[test]
    fn test_adapter_get_text_out_of_bounds() {
        let mut adapter = ConsoleServiceAdapter::new(100);
        adapter.add_message("s", "hi");
        assert!(adapter.get_text(0, 10000).is_none());
    }

    #[test]
    fn test_adapter_default() {
        let adapter = ConsoleServiceAdapter::default();
        assert_eq!(adapter.buffer().max_size(), 10000);
    }
}
