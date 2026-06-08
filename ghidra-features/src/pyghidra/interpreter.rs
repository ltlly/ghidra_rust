//! PyGhidra interpreter components.
//!
//! Ported from `ghidra.pyghidra.interpreter`.  Provides the interactive
//! Python interpreter console, its backing Ghidra script, task monitor,
//! and toolbar actions (Cancel / Reset).
//!
//! # Components
//!
//! - [`CodeCompletion`] -- a single code-completion suggestion.
//! - [`PyGhidraConsole`] -- trait for the Python-side console implementation.
//! - [`InterpreterGhidraScript`] -- Ghidra script that backs the interpreter.
//! - [`InterpreterTaskMonitor`] -- task monitor that prints status to the console.
//! - [`PyGhidraInterpreter`] -- manages the interpreter connection lifecycle.
//! - [`CancelAction`] -- toolbar / key-binding action to interrupt the interpreter.
//! - [`ResetAction`] -- toolbar / key-binding action to reset the interpreter.

use std::io::{self, Write};
use std::sync::{Arc, Mutex};

use super::PyGhidraPlugin;

// ---------------------------------------------------------------------------
// CodeCompletion
// ---------------------------------------------------------------------------

/// A single code-completion suggestion.
///
/// Matches Java's `ghidra.app.plugin.core.console.CodeCompletion`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeCompletion {
    /// The display name of the completion.
    name: String,
    /// The text to insert when the completion is accepted.
    insertion: String,
    /// Optional documentation or description.
    description: Option<String>,
}

impl CodeCompletion {
    /// Create a new code completion.
    pub fn new(
        name: impl Into<String>,
        insertion: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            insertion: insertion.into(),
            description: None,
        }
    }

    /// Create a new code completion with a description.
    pub fn with_description(
        name: impl Into<String>,
        insertion: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            insertion: insertion.into(),
            description: Some(description.into()),
        }
    }

    /// The display name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The text to insert.
    pub fn insertion(&self) -> &str {
        &self.insertion
    }

    /// The optional description.
    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }
}

// ---------------------------------------------------------------------------
// PyGhidraConsole (trait)
// ---------------------------------------------------------------------------

/// Console interface for the Python-side implementation.
///
/// This trait mirrors Java's `PyGhidraConsole` interface.  It defines
/// the methods that a Python-backed console must implement to integrate
/// with Ghidra's interpreter panel.
pub trait PyGhidraConsole: Send {
    /// Generate code completions for the given command.
    ///
    /// `cmd` is the current input text and `caret_pos` is the cursor
    /// position within it (`0 <= caret_pos <= cmd.len()`).
    fn get_completions(&self, cmd: &str, caret_pos: usize) -> Vec<CodeCompletion>;

    /// Restart the interpreter (clear state and re-initialise).
    fn restart(&self);

    /// Interrupt the code currently running in the interpreter.
    fn interrupt(&self);
}

impl Drop for dyn PyGhidraConsole {
    fn drop(&mut self) {
        // Default no-op; concrete implementations may override via their own Drop.
    }
}

// ---------------------------------------------------------------------------
// InterpreterGhidraScript
// ---------------------------------------------------------------------------

/// A custom [`GhidraScript`] for use with the PyGhidra interpreter console.
///
/// Matches Java's `InterpreterGhidraScript`.  Stores the current address,
/// location, selection, and highlight that mirror the interactive state of
/// the Ghidra tool.
#[derive(Debug)]
pub struct InterpreterGhidraScript {
    /// The current address in the program.
    current_address: Option<String>,
    /// The current program location (detailed address info).
    current_location: Option<String>,
    /// The current selection in the program.
    current_selection: Option<String>,
    /// The current highlight in the program.
    current_highlight: Option<String>,
    /// The current program name / identifier.
    current_program: Option<String>,
    /// Output writer for script print statements.
    output_buffer: Arc<Mutex<Vec<u8>>>,
}

impl InterpreterGhidraScript {
    /// Create a new interpreter script.
    pub fn new() -> Self {
        Self {
            current_address: None,
            current_location: None,
            current_selection: None,
            current_highlight: None,
            current_program: None,
            output_buffer: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Get the current address.
    pub fn current_address(&self) -> Option<&str> {
        self.current_address.as_deref()
    }

    /// Get the current location.
    pub fn current_location(&self) -> Option<&str> {
        self.current_location.as_deref()
    }

    /// Get the current selection.
    pub fn current_selection(&self) -> Option<&str> {
        self.current_selection.as_deref()
    }

    /// Get the current highlight.
    pub fn current_highlight(&self) -> Option<&str> {
        self.current_highlight.as_deref()
    }

    /// Get the current program name.
    pub fn current_program(&self) -> Option<&str> {
        self.current_program.as_deref()
    }

    /// Set the current program.
    pub fn set_current_program(&mut self, program: Option<String>) {
        self.current_program = program;
    }

    /// Set the current address.
    pub fn set_current_address(&mut self, address: Option<String>) {
        self.current_address = address;
    }

    /// Set the current location.  Also extracts the address from the
    /// location when available.
    pub fn set_current_location(&mut self, location: Option<String>) {
        self.current_address = location.clone();
        self.current_location = location;
    }

    /// Set the current selection.
    pub fn set_current_selection(&mut self, selection: Option<String>) {
        self.current_selection = selection;
    }

    /// Set the current highlight.
    pub fn set_current_highlight(&mut self, highlight: Option<String>) {
        self.current_highlight = highlight;
    }

    /// Get the output buffer contents as a UTF-8 string and clear it.
    pub fn take_output(&self) -> String {
        let mut buf = self.output_buffer.lock().unwrap();
        let s = String::from_utf8_lossy(&buf).to_string();
        buf.clear();
        s
    }

    /// Get a clone of the output buffer Arc (for sharing with writers).
    pub fn output_buffer(&self) -> Arc<Mutex<Vec<u8>>> {
        Arc::clone(&self.output_buffer)
    }
}

impl Default for InterpreterGhidraScript {
    fn default() -> Self {
        Self::new()
    }
}

impl Write for InterpreterGhidraScript {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut out = self.output_buffer.lock().map_err(|e| {
            io::Error::new(io::ErrorKind::Other, format!("lock poisoned: {e}"))
        })?;
        out.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// InterpreterTaskMonitor
// ---------------------------------------------------------------------------

/// A task monitor for the interactive PyGhidra console.
///
/// Matches Java's `InterpreterTaskMonitor`.  Prints status messages to
/// the provided writer, prefixed with `<pyghidra-interactive>: `.
pub struct InterpreterTaskMonitor {
    output: Arc<Mutex<dyn Write + Send>>,
}

impl InterpreterTaskMonitor {
    /// The prefix applied to every status message.
    pub const MESSAGE_PREFIX: &'static str = "<pyghidra-interactive>: ";

    /// Create a new interpreter task monitor writing to the given output.
    pub fn new(output: Arc<Mutex<dyn Write + Send>>) -> Self {
        Self { output }
    }

    /// Create a task monitor backed by the interpreter script's output buffer.
    pub fn from_script(script: &InterpreterGhidraScript) -> Self {
        Self {
            output: script.output_buffer(),
        }
    }

    /// Print a status message.
    pub fn set_message(&self, message: &str) {
        if let Ok(mut out) = self.output.lock() {
            let _ = writeln!(out, "{}{}", Self::MESSAGE_PREFIX, message);
        }
    }

    /// Check whether cancellation has been requested.
    ///
    /// The interactive monitor never cancels on its own; this is
    /// overridden by the interpreter-level cancellation logic.
    pub fn is_cancelled(&self) -> bool {
        false
    }
}

// ---------------------------------------------------------------------------
// CancelAction
// ---------------------------------------------------------------------------

/// A toolbar / key-binding action that interrupts the interpreter.
///
/// Matches Java's `CancelAction` (`Ctrl+I`).
#[derive(Debug, Clone)]
pub struct CancelAction {
    /// The action name.
    name: String,
    /// The owner (plugin class name).
    owner: String,
    /// Description shown in the UI.
    description: String,
    /// Whether the action is currently enabled.
    enabled: bool,
    /// The key binding (virtual key code + modifier mask).
    key_binding: Option<KeyBinding>,
}

impl CancelAction {
    /// Virtual key code for 'I'.
    pub const VK_I: u32 = 0x49;

    /// Create a new cancel action.
    pub fn new() -> Self {
        Self {
            name: "Cancel".to_string(),
            owner: "PyGhidraPlugin".to_string(),
            description: "Interrupt the interpreter".to_string(),
            enabled: true,
            key_binding: Some(KeyBinding::new(Self::VK_I, ModifierMask::CTRL)),
        }
    }

    /// The action name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The owner plugin class name.
    pub fn owner(&self) -> &str {
        &self.owner
    }

    /// The action description.
    pub fn description(&self) -> &str {
        &self.description
    }

    /// Whether the action is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Enable or disable the action.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Get the key binding.
    pub fn key_binding(&self) -> Option<&KeyBinding> {
        self.key_binding.as_ref()
    }

    /// Execute the action against the given console.
    pub fn execute<C: PyGhidraConsole>(&self, console: &C) {
        if self.enabled {
            console.interrupt();
        }
    }
}

impl Default for CancelAction {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// ResetAction
// ---------------------------------------------------------------------------

/// A toolbar / key-binding action that resets the interpreter.
///
/// Matches Java's `ResetAction` (`Ctrl+D`).
#[derive(Debug, Clone)]
pub struct ResetAction {
    /// The action name.
    name: String,
    /// The owner (plugin class name).
    owner: String,
    /// Description shown in the UI.
    description: String,
    /// Whether the action is currently enabled.
    enabled: bool,
    /// The key binding (virtual key code + modifier mask).
    key_binding: Option<KeyBinding>,
}

impl ResetAction {
    /// Virtual key code for 'D'.
    pub const VK_D: u32 = 0x44;

    /// Create a new reset action.
    pub fn new() -> Self {
        Self {
            name: "Reset".to_string(),
            owner: "PyGhidraPlugin".to_string(),
            description: "Reset the interpreter".to_string(),
            enabled: true,
            key_binding: Some(KeyBinding::new(Self::VK_D, ModifierMask::CTRL)),
        }
    }

    /// The action name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The owner plugin class name.
    pub fn owner(&self) -> &str {
        &self.owner
    }

    /// The action description.
    pub fn description(&self) -> &str {
        &self.description
    }

    /// Whether the action is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Enable or disable the action.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Get the key binding.
    pub fn key_binding(&self) -> Option<&KeyBinding> {
        self.key_binding.as_ref()
    }

    /// Execute the action against the given console.
    pub fn execute<C: PyGhidraConsole>(&self, console: &C) {
        if self.enabled {
            console.restart();
        }
    }
}

impl Default for ResetAction {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// KeyBinding / ModifierMask
// ---------------------------------------------------------------------------

/// Keyboard modifier mask values (matches Java AWT modifiers).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModifierMask(u32);

impl ModifierMask {
    /// Ctrl / Cmd modifier.
    pub const CTRL: ModifierMask = ModifierMask(1 << 18); // InputEvent.CTRL_DOWN_MASK
    /// Shift modifier.
    pub const SHIFT: ModifierMask = ModifierMask(1 << 17); // InputEvent.SHIFT_DOWN_MASK
    /// Alt modifier.
    pub const ALT: ModifierMask = ModifierMask(1 << 16); // InputEvent.ALT_DOWN_MASK

    /// Combine two modifier masks.
    pub fn combine(self, other: ModifierMask) -> ModifierMask {
        ModifierMask(self.0 | other.0)
    }

    /// The raw mask value.
    pub fn value(self) -> u32 {
        self.0
    }
}

/// A key binding: virtual key code + modifier mask.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyBinding {
    /// Virtual key code (matches Java `KeyEvent.VK_*`).
    key_code: u32,
    /// Modifier mask.
    modifiers: ModifierMask,
}

impl KeyBinding {
    /// Create a new key binding.
    pub fn new(key_code: u32, modifiers: ModifierMask) -> Self {
        Self { key_code, modifiers }
    }

    /// The virtual key code.
    pub fn key_code(&self) -> u32 {
        self.key_code
    }

    /// The modifier mask.
    pub fn modifiers(&self) -> ModifierMask {
        self.modifiers
    }
}

// ---------------------------------------------------------------------------
// PyGhidraInterpreter
// ---------------------------------------------------------------------------

/// The PyGhidra interpreter connection.
///
/// Matches Java's `PyGhidraInterpreter`.  Manages the lifecycle of the
/// Python-side console, registers Cancel / Reset actions, and provides
/// code-completion delegation.
pub struct PyGhidraInterpreter {
    /// The Python-side console (set during `init`).
    console: Option<Arc<Mutex<dyn PyGhidraConsole>>>,
    /// The backing Ghidra script.
    script: InterpreterGhidraScript,
    /// Whether Python is available.
    python_available: bool,
    /// Cancel action registered on the toolbar.
    cancel_action: CancelAction,
    /// Reset action registered on the toolbar.
    reset_action: ResetAction,
    /// Whether the interpreter has been initialized.
    initialized: bool,
}

impl PyGhidraInterpreter {
    /// Create a new PyGhidra interpreter.
    ///
    /// `python_available` indicates whether the Python runtime was detected.
    pub fn new(python_available: bool) -> Self {
        Self {
            console: None,
            script: InterpreterGhidraScript::new(),
            python_available,
            cancel_action: CancelAction::new(),
            reset_action: ResetAction::new(),
            initialized: false,
        }
    }

    /// Whether Python is available for this interpreter.
    pub fn is_python_available(&self) -> bool {
        self.python_available
    }

    /// Get a reference to the backing Ghidra script.
    pub fn script(&self) -> &InterpreterGhidraScript {
        &self.script
    }

    /// Get a mutable reference to the backing Ghidra script.
    pub fn script_mut(&mut self) -> &mut InterpreterGhidraScript {
        &mut self.script
    }

    /// Get the cancel action.
    pub fn cancel_action(&self) -> &CancelAction {
        &self.cancel_action
    }

    /// Get the reset action.
    pub fn reset_action(&self) -> &ResetAction {
        &self.reset_action
    }

    /// Whether the interpreter has been initialized with a console.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Initialize the interpreter with a Python-side console.
    ///
    /// This is the Rust equivalent of `PyGhidraInterpreter.init()` and
    /// is intended to be called once when the Python runtime attaches.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the interpreter has already been initialized.
    pub fn init<C: PyGhidraConsole + 'static>(
        &mut self,
        python_console: C,
    ) -> Result<(), &'static str> {
        if self.initialized {
            return Err("the interpreter has already been initialized");
        }
        self.console = Some(Arc::new(Mutex::new(python_console)));
        self.initialized = true;
        Ok(())
    }

    /// Get code completions for the given command and caret position.
    ///
    /// Returns an empty vector if the interpreter is not yet initialized.
    pub fn get_completions(&self, cmd: &str, caret_pos: usize) -> Vec<CodeCompletion> {
        match &self.console {
            Some(console) => console.lock().unwrap().get_completions(cmd, caret_pos),
            None => Vec::new(),
        }
    }

    /// Execute the cancel action (interrupt the running Python code).
    ///
    /// Returns `Err` if the console is not yet initialized.
    pub fn cancel(&self) -> Result<(), &'static str> {
        match &self.console {
            Some(console) => {
                console.lock().unwrap().interrupt();
                Ok(())
            }
            None => Err("interpreter not initialized"),
        }
    }

    /// Execute the reset action (restart the Python interpreter).
    ///
    /// Returns `Err` if the console is not yet initialized.
    pub fn reset(&self) -> Result<(), &'static str> {
        match &self.console {
            Some(console) => {
                console.lock().unwrap().restart();
                Ok(())
            }
            None => Err("interpreter not initialized"),
        }
    }

    /// The title shown in the interpreter panel.
    pub fn title(&self) -> &str {
        PyGhidraPlugin::TITLE
    }

    /// The "Python unavailable" message.
    pub fn unavailable_message(&self) -> &'static str {
        "Ghidra was not started with PyGhidra. Python is not available."
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- A mock PyGhidraConsole for testing -------------------------------

    struct MockConsole {
        interrupted: Arc<Mutex<bool>>,
        restarted: Arc<Mutex<bool>>,
        completions: Vec<CodeCompletion>,
    }

    impl MockConsole {
        fn new() -> Self {
            Self {
                interrupted: Arc::new(Mutex::new(false)),
                restarted: Arc::new(Mutex::new(false)),
                completions: Vec::new(),
            }
        }
    }

    impl PyGhidraConsole for MockConsole {
        fn get_completions(&self, _cmd: &str, _caret_pos: usize) -> Vec<CodeCompletion> {
            self.completions.clone()
        }

        fn restart(&self) {
            *self.restarted.lock().unwrap() = true;
        }

        fn interrupt(&self) {
            *self.interrupted.lock().unwrap() = true;
        }
    }

    // -- CodeCompletion tests ---------------------------------------------

    #[test]
    fn test_code_completion_basic() {
        let cc = CodeCompletion::new("print", "print(");
        assert_eq!(cc.name(), "print");
        assert_eq!(cc.insertion(), "print(");
        assert!(cc.description().is_none());
    }

    #[test]
    fn test_code_completion_with_description() {
        let cc = CodeCompletion::with_description("len", "len()", "Return the length");
        assert_eq!(cc.description(), Some("Return the length"));
    }

    // -- InterpreterGhidraScript tests ------------------------------------

    #[test]
    fn test_script_defaults() {
        let script = InterpreterGhidraScript::new();
        assert!(script.current_address().is_none());
        assert!(script.current_location().is_none());
        assert!(script.current_selection().is_none());
        assert!(script.current_highlight().is_none());
        assert!(script.current_program().is_none());
    }

    #[test]
    fn test_script_set_current_program() {
        let mut script = InterpreterGhidraScript::new();
        script.set_current_program(Some("test.exe".into()));
        assert_eq!(script.current_program(), Some("test.exe"));
    }

    #[test]
    fn test_script_set_current_address() {
        let mut script = InterpreterGhidraScript::new();
        script.set_current_address(Some("0x00400000".into()));
        assert_eq!(script.current_address(), Some("0x00400000"));
    }

    #[test]
    fn test_script_set_location_extracts_address() {
        let mut script = InterpreterGhidraScript::new();
        script.set_current_location(Some("0x00401000".into()));
        assert_eq!(script.current_location(), Some("0x00401000"));
        assert_eq!(script.current_address(), Some("0x00401000"));
    }

    #[test]
    fn test_script_write_and_take_output() {
        let script = InterpreterGhidraScript::new();
        {
            let mut w = &*script.output_buffer().lock().unwrap();
            use std::io::Write;
            write!(w, "hello ").unwrap();
            write!(w, "world").unwrap();
        }
        assert_eq!(script.take_output(), "hello world");
        assert_eq!(script.take_output(), ""); // cleared
    }

    // -- InterpreterTaskMonitor tests -------------------------------------

    #[test]
    fn test_task_monitor_message_prefix() {
        assert_eq!(InterpreterTaskMonitor::MESSAGE_PREFIX, "<pyghidra-interactive>: ");
    }

    #[test]
    fn test_task_monitor_set_message() {
        let script = InterpreterGhidraScript::new();
        let monitor = InterpreterTaskMonitor::from_script(&script);
        monitor.set_message("Loading...");
        let output = script.take_output();
        assert!(output.contains("<pyghidra-interactive>: Loading..."));
    }

    #[test]
    fn test_task_monitor_is_cancelled_default() {
        let script = InterpreterGhidraScript::new();
        let monitor = InterpreterTaskMonitor::from_script(&script);
        assert!(!monitor.is_cancelled());
    }

    // -- CancelAction tests -----------------------------------------------

    #[test]
    fn test_cancel_action_defaults() {
        let action = CancelAction::new();
        assert_eq!(action.name(), "Cancel");
        assert_eq!(action.description(), "Interrupt the interpreter");
        assert!(action.is_enabled());
        assert!(action.key_binding().is_some());
        assert_eq!(action.key_binding().unwrap().key_code(), CancelAction::VK_I);
    }

    #[test]
    fn test_cancel_action_execute() {
        let action = CancelAction::new();
        let console = MockConsole::new();
        let interrupted = Arc::clone(&console.interrupted);

        action.execute(&console);
        assert!(*interrupted.lock().unwrap());
    }

    #[test]
    fn test_cancel_action_disabled() {
        let mut action = CancelAction::new();
        action.set_enabled(false);
        let console = MockConsole::new();
        let interrupted = Arc::clone(&console.interrupted);

        action.execute(&console);
        assert!(!*interrupted.lock().unwrap());
    }

    // -- ResetAction tests ------------------------------------------------

    #[test]
    fn test_reset_action_defaults() {
        let action = ResetAction::new();
        assert_eq!(action.name(), "Reset");
        assert_eq!(action.description(), "Reset the interpreter");
        assert!(action.is_enabled());
        assert!(action.key_binding().is_some());
        assert_eq!(action.key_binding().unwrap().key_code(), ResetAction::VK_D);
    }

    #[test]
    fn test_reset_action_execute() {
        let action = ResetAction::new();
        let console = MockConsole::new();
        let restarted = Arc::clone(&console.restarted);

        action.execute(&console);
        assert!(*restarted.lock().unwrap());
    }

    #[test]
    fn test_reset_action_disabled() {
        let mut action = ResetAction::new();
        action.set_enabled(false);
        let console = MockConsole::new();
        let restarted = Arc::clone(&console.restarted);

        action.execute(&console);
        assert!(!*restarted.lock().unwrap());
    }

    // -- KeyBinding tests -------------------------------------------------

    #[test]
    fn test_key_binding() {
        let kb = KeyBinding::new(0x49, ModifierMask::CTRL);
        assert_eq!(kb.key_code(), 0x49);
        assert_eq!(kb.modifiers(), ModifierMask::CTRL);
    }

    #[test]
    fn test_modifier_mask_combine() {
        let combined = ModifierMask::CTRL.combine(ModifierMask::SHIFT);
        assert_eq!(combined.value(), ModifierMask::CTRL.value() | ModifierMask::SHIFT.value());
    }

    // -- PyGhidraInterpreter tests ----------------------------------------

    #[test]
    fn test_interpreter_new() {
        let interp = PyGhidraInterpreter::new(true);
        assert!(interp.is_python_available());
        assert!(!interp.is_initialized());
        assert_eq!(interp.title(), "PyGhidra");
    }

    #[test]
    fn test_interpreter_unavailable() {
        let interp = PyGhidraInterpreter::new(false);
        assert!(!interp.is_python_available());
        assert_eq!(
            interp.unavailable_message(),
            "Ghidra was not started with PyGhidra. Python is not available."
        );
    }

    #[test]
    fn test_interpreter_init_once() {
        let mut interp = PyGhidraInterpreter::new(true);
        let console = MockConsole::new();
        assert!(interp.init(console).is_ok());
        assert!(interp.is_initialized());
    }

    #[test]
    fn test_interpreter_init_twice_errors() {
        let mut interp = PyGhidraInterpreter::new(true);
        interp.init(MockConsole::new()).unwrap();
        let result = interp.init(MockConsole::new());
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "the interpreter has already been initialized");
    }

    #[test]
    fn test_interpreter_completions_uninitialized() {
        let interp = PyGhidraInterpreter::new(true);
        assert!(interp.get_completions("pri", 3).is_empty());
    }

    #[test]
    fn test_interpreter_cancel_uninitialized() {
        let interp = PyGhidraInterpreter::new(true);
        assert!(interp.cancel().is_err());
    }

    #[test]
    fn test_interpreter_reset_uninitialized() {
        let interp = PyGhidraInterpreter::new(true);
        assert!(interp.reset().is_err());
    }

    #[test]
    fn test_interpreter_cancel_initialized() {
        let mut interp = PyGhidraInterpreter::new(true);
        interp.init(MockConsole::new()).unwrap();
        assert!(interp.cancel().is_ok());
    }

    #[test]
    fn test_interpreter_reset_initialized() {
        let mut interp = PyGhidraInterpreter::new(true);
        interp.init(MockConsole::new()).unwrap();
        assert!(interp.reset().is_ok());
    }

    #[test]
    fn test_interpreter_script_access() {
        let interp = PyGhidraInterpreter::new(true);
        assert!(interp.script().current_address().is_none());
    }
}
