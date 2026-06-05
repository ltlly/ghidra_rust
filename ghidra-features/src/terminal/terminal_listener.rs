//! Terminal listener interface and terminal provider.
//!
//! Ported from `ghidra.app.plugin.core.terminal.TerminalListener`,
//! `DefaultTerminal`, `TerminalProvider`, and `ThreadedTerminal`.

use std::sync::{Arc, Mutex};
use std::collections::VecDeque;


// ---------------------------------------------------------------------------
// TerminalListener
// ---------------------------------------------------------------------------

/// Listener for terminal events.
///
/// Ported from Ghidra's `TerminalListener` interface.
pub trait TerminalListener: Send + Sync {
    /// The terminal was resized by the user.
    ///
    /// If applicable and possible, this information should be communicated
    /// to the connection.
    fn resized(&self, _cols: u16, _rows: u16) {}

    /// The application requested the window title changed.
    fn retitled(&self, _title: &str) {}

    /// The terminal session was terminated.
    ///
    /// `exitcode` is the exit code of the session leader, or -1 if not applicable.
    fn terminated(&self, _exitcode: i32) {}

    /// Data was written to the terminal (for logging/debugging).
    fn data_written(&self, _data: &[u8]) {}

    /// The cursor position changed.
    fn cursor_moved(&self, _col: u16, _row: u16) {}

    /// The terminal bell was triggered.
    fn bell(&self) {}
}

/// A no-op terminal listener for default usage.
#[derive(Debug, Clone, Copy)]
pub struct NoOpTerminalListener;

impl TerminalListener for NoOpTerminalListener {}

// ---------------------------------------------------------------------------
// TerminalOutput
// ---------------------------------------------------------------------------

/// Trait for objects that receive output from the terminal (user input).
///
/// When the user types into the terminal, the characters are sent to
/// the application through this trait.
pub trait TerminalOutput: Send + Sync {
    /// Send data from the terminal to the application (user keystrokes).
    fn write(&self, data: &[u8]);

    /// Send a resize notification to the application.
    fn resize(&self, cols: u16, rows: u16);

    /// Close the connection.
    fn close(&self);
}

/// A buffered terminal output that stores written data.
#[derive(Debug, Clone)]
pub struct BufferedTerminalOutput {
    buffer: Arc<Mutex<Vec<u8>>>,
    resize_events: Arc<Mutex<Vec<(u16, u16)>>>,
    closed: Arc<Mutex<bool>>,
}

impl BufferedTerminalOutput {
    /// Create a new buffered terminal output.
    pub fn new() -> Self {
        Self {
            buffer: Arc::new(Mutex::new(Vec::new())),
            resize_events: Arc::new(Mutex::new(Vec::new())),
            closed: Arc::new(Mutex::new(false)),
        }
    }

    /// Get the buffered data.
    pub fn buffered_data(&self) -> Vec<u8> {
        self.buffer.lock().unwrap().clone()
    }

    /// Get the resize events.
    pub fn resize_events(&self) -> Vec<(u16, u16)> {
        self.resize_events.lock().unwrap().clone()
    }

    /// Check if the connection was closed.
    pub fn is_closed(&self) -> bool {
        *self.closed.lock().unwrap()
    }

    /// Clear the buffer.
    pub fn clear(&self) {
        self.buffer.lock().unwrap().clear();
        self.resize_events.lock().unwrap().clear();
    }
}

impl Default for BufferedTerminalOutput {
    fn default() -> Self {
        Self::new()
    }
}

impl TerminalOutput for BufferedTerminalOutput {
    fn write(&self, data: &[u8]) {
        self.buffer.lock().unwrap().extend_from_slice(data);
    }

    fn resize(&self, cols: u16, rows: u16) {
        self.resize_events.lock().unwrap().push((cols, rows));
    }

    fn close(&self) {
        *self.closed.lock().unwrap() = true;
    }
}

// ---------------------------------------------------------------------------
// TerminalProvider
// ---------------------------------------------------------------------------

/// A terminal provider that manages a single terminal session.
///
/// Ported from Ghidra's `TerminalProvider`.  Holds the terminal state
/// and routes I/O between the terminal emulator and the application.
pub struct TerminalProvider {
    /// Name of this provider.
    name: String,
    /// The terminal's display state.
    state: super::TerminalState,
    /// Output from the terminal to the application.
    output: Box<dyn TerminalOutput>,
    /// Listeners for terminal events.
    listeners: Vec<Arc<dyn TerminalListener>>,
    /// Whether the provider is visible.
    visible: bool,
}

impl std::fmt::Debug for TerminalProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TerminalProvider")
            .field("name", &self.name)
            .field("visible", &self.visible)
            .finish()
    }
}

impl TerminalProvider {
    /// Create a new terminal provider.
    pub fn new(
        name: impl Into<String>,
        output: Box<dyn TerminalOutput>,
    ) -> Self {
        Self {
            name: name.into(),
            state: super::TerminalState::new(super::DEFAULT_WIDTH, super::DEFAULT_HEIGHT),
            output,
            listeners: Vec::new(),
            visible: false,
        }
    }

    /// Get the provider name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get a reference to the terminal state.
    pub fn state(&self) -> &super::TerminalState {
        &self.state
    }

    /// Get a mutable reference to the terminal state.
    pub fn state_mut(&mut self) -> &mut super::TerminalState {
        &mut self.state
    }

    /// Add a terminal listener.
    pub fn add_listener(&mut self, listener: Arc<dyn TerminalListener>) {
        self.listeners.push(listener);
    }

    /// Remove all listeners.
    pub fn clear_listeners(&mut self) {
        self.listeners.clear();
    }

    /// Returns the number of listeners.
    pub fn listener_count(&self) -> usize {
        self.listeners.len()
    }

    /// Inject display output (bytes from the application).
    pub fn inject_display_output(&mut self, data: &[u8]) {
        if let Ok(s) = std::str::from_utf8(data) {
            self.state.write_str(s);
        }
        for listener in &self.listeners {
            listener.data_written(data);
        }
    }

    /// Send user input to the application.
    pub fn send_input(&self, data: &[u8]) {
        self.output.write(data);
    }

    /// Notify the application of a resize.
    pub fn notify_resize(&self, cols: u16, rows: u16) {
        self.output.resize(cols, rows);
        for listener in &self.listeners {
            listener.resized(cols, rows);
        }
    }

    /// Notify the application of termination.
    pub fn terminated(&self, exitcode: i32) {
        for listener in &self.listeners {
            listener.terminated(exitcode);
        }
    }

    /// Notify the application of a title change.
    pub fn notify_retitled(&self, title: &str) {
        for listener in &self.listeners {
            listener.retitled(title);
        }
    }

    /// Notify listeners of a bell event.
    pub fn notify_bell(&self) {
        for listener in &self.listeners {
            listener.bell();
        }
    }

    /// Set visibility.
    pub fn set_visible(&mut self, visible: bool) {
        self.visible = visible;
    }

    /// Whether this provider is visible.
    pub fn is_visible(&self) -> bool {
        self.visible
    }

    /// Remove from tool (close the provider).
    pub fn remove_from_tool(&mut self) {
        self.visible = false;
        self.output.close();
    }
}

// ---------------------------------------------------------------------------
// DefaultTerminal
// ---------------------------------------------------------------------------

/// A default terminal implementation that delegates to a [`TerminalProvider`].
///
/// Ported from Ghidra's `DefaultTerminal`.
#[derive(Debug)]
pub struct DefaultTerminal {
    /// The underlying provider.
    provider: TerminalProvider,
}

impl DefaultTerminal {
    /// Create a new default terminal.
    pub fn new(provider: TerminalProvider) -> Self {
        Self { provider }
    }

    /// Close the terminal.
    pub fn close(&mut self) {
        self.provider.remove_from_tool();
    }

    /// Notify that the terminal has terminated.
    pub fn terminated(&mut self, exitcode: i32) {
        self.provider.terminated(exitcode);
    }

    /// Inject output from the application.
    pub fn inject_display_output(&mut self, data: &[u8]) {
        self.provider.inject_display_output(data);
    }

    /// Send user input.
    pub fn send_input(&self, data: &[u8]) {
        self.provider.send_input(data);
    }

    /// Get a reference to the provider.
    pub fn provider(&self) -> &TerminalProvider {
        &self.provider
    }

    /// Get a mutable reference to the provider.
    pub fn provider_mut(&mut self) -> &mut TerminalProvider {
        &mut self.provider
    }
}

// ---------------------------------------------------------------------------
// ThreadedTerminal
// ---------------------------------------------------------------------------

/// A terminal that runs I/O processing on a separate thread.
///
/// Ported from Ghidra's `ThreadedTerminal`.  Uses a message queue
/// to communicate between the I/O thread and the display thread.
#[derive(Debug)]
pub struct ThreadedTerminal {
    /// Pending input messages from the I/O thread.
    input_queue: Arc<Mutex<VecDeque<Vec<u8>>>>,
    /// Pending output messages to the I/O thread.
    output_queue: Arc<Mutex<VecDeque<Vec<u8>>>>,
    /// Whether the terminal is running.
    running: Arc<Mutex<bool>>,
    /// Terminal dimensions.
    cols: u16,
    rows: u16,
}

impl ThreadedTerminal {
    /// Create a new threaded terminal.
    pub fn new(cols: u16, rows: u16) -> Self {
        Self {
            input_queue: Arc::new(Mutex::new(VecDeque::new())),
            output_queue: Arc::new(Mutex::new(VecDeque::new())),
            running: Arc::new(Mutex::new(true)),
            cols,
            rows,
        }
    }

    /// Get the current dimensions.
    pub fn dimensions(&self) -> (u16, u16) {
        (self.cols, self.rows)
    }

    /// Resize the terminal.
    pub fn resize(&mut self, cols: u16, rows: u16) {
        self.cols = cols;
        self.rows = rows;
    }

    /// Enqueue data to be displayed (from the application).
    pub fn enqueue_display(&self, data: Vec<u8>) {
        self.input_queue.lock().unwrap().push_back(data);
    }

    /// Dequeue the next display message.
    pub fn dequeue_display(&self) -> Option<Vec<u8>> {
        self.input_queue.lock().unwrap().pop_front()
    }

    /// Enqueue data to be sent to the application (user input).
    pub fn enqueue_input(&self, data: Vec<u8>) {
        self.output_queue.lock().unwrap().push_back(data);
    }

    /// Dequeue the next input message.
    pub fn dequeue_input(&self) -> Option<Vec<u8>> {
        self.output_queue.lock().unwrap().pop_front()
    }

    /// Check if there are pending display messages.
    pub fn has_display_pending(&self) -> bool {
        !self.input_queue.lock().unwrap().is_empty()
    }

    /// Check if there are pending input messages.
    pub fn has_input_pending(&self) -> bool {
        !self.output_queue.lock().unwrap().is_empty()
    }

    /// Check if the terminal is running.
    pub fn is_running(&self) -> bool {
        *self.running.lock().unwrap()
    }

    /// Stop the terminal.
    pub fn stop(&self) {
        *self.running.lock().unwrap() = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_op_listener() {
        let listener = NoOpTerminalListener;
        // Should not panic.
        listener.resized(80, 24);
        listener.retitled("test");
        listener.terminated(0);
        listener.data_written(b"hello");
        listener.cursor_moved(0, 0);
        listener.bell();
    }

    #[test]
    fn test_buffered_terminal_output() {
        let output = BufferedTerminalOutput::new();
        assert!(output.buffered_data().is_empty());
        assert!(!output.is_closed());

        output.write(b"hello");
        assert_eq!(output.buffered_data(), b"hello");

        output.resize(120, 40);
        assert_eq!(output.resize_events(), vec![(120, 40)]);

        output.close();
        assert!(output.is_closed());

        output.clear();
        assert!(output.buffered_data().is_empty());
    }

    #[test]
    fn test_terminal_provider() {
        let output = Box::new(BufferedTerminalOutput::new());
        let mut provider = TerminalProvider::new("test-terminal", output);

        assert_eq!(provider.name(), "test-terminal");
        assert!(!provider.is_visible());
        assert_eq!(provider.listener_count(), 0);

        provider.set_visible(true);
        assert!(provider.is_visible());

        // Inject some display output.
        provider.inject_display_output(b"Hello, world!");
        // Terminal state should have cursor moved forward.
        assert!(provider.state().cursor_col > 0);

        // Send input.
        provider.send_input(b"ls\n");
    }

    #[test]
    fn test_terminal_provider_listeners() {
        use std::sync::atomic::{AtomicBool, Ordering};

        struct TestListener {
            resized_called: Arc<AtomicBool>,
        }
        impl TerminalListener for TestListener {
            fn resized(&self, _cols: u16, _rows: u16) {
                self.resized_called.store(true, Ordering::SeqCst);
            }
        }

        let resized_called = Arc::new(AtomicBool::new(false));
        let listener = Arc::new(TestListener {
            resized_called: resized_called.clone(),
        });

        let output = Box::new(BufferedTerminalOutput::new());
        let mut provider = TerminalProvider::new("test", output);
        provider.add_listener(listener);
        assert_eq!(provider.listener_count(), 1);

        provider.notify_resize(120, 40);
        assert!(resized_called.load(Ordering::SeqCst));

        provider.clear_listeners();
        assert_eq!(provider.listener_count(), 0);
    }

    #[test]
    fn test_default_terminal() {
        let output = Box::new(BufferedTerminalOutput::new());
        let provider = TerminalProvider::new("test", output);
        let mut terminal = DefaultTerminal::new(provider);

        terminal.inject_display_output(b"line1\nline2\n");
        // Terminal should have advanced the cursor row due to newlines.
        assert!(terminal.provider().state().cursor_row >= 1);

        terminal.send_input(b"echo hello\n");

        terminal.terminated(0);
    }

    #[test]
    fn test_threaded_terminal() {
        let terminal = ThreadedTerminal::new(80, 24);
        assert_eq!(terminal.dimensions(), (80, 24));
        assert!(terminal.is_running());

        terminal.enqueue_display(b"hello".to_vec());
        assert!(terminal.has_display_pending());
        assert_eq!(terminal.dequeue_display(), Some(b"hello".to_vec()));
        assert!(!terminal.has_display_pending());

        terminal.enqueue_input(b"input".to_vec());
        assert!(terminal.has_input_pending());
        assert_eq!(terminal.dequeue_input(), Some(b"input".to_vec()));

        terminal.stop();
        assert!(!terminal.is_running());
    }

    #[test]
    fn test_threaded_terminal_resize() {
        let mut terminal = ThreadedTerminal::new(80, 24);
        terminal.resize(120, 40);
        assert_eq!(terminal.dimensions(), (120, 40));
    }
}
