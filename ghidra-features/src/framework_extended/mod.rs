//! Extended framework types: commands, application configuration, tool state,
//! and navigatable component provider adapters.
//!
//! Ported from:
//! - `ghidra.framework.cmd.BinaryAnalysisCommand`
//! - `ghidra.framework.data.GhidraToolState`
//! - `ghidra.framework.plugintool.NavigatableComponentProviderAdapter`
//! - `ghidra.framework.GhidraApplicationConfiguration`
//! - `ghidra.framework.HeadlessGhidraApplicationConfiguration`
//! - `ghidra.framework.main.DataTreeDialog`
//! - `ghidra.framework.main.datatree.*`

use std::collections::HashMap;
use std::fmt;

// ---------------------------------------------------------------------------
// BinaryAnalysisCommand
// ---------------------------------------------------------------------------

/// Trait for binary analysis commands.
///
/// Ported from `ghidra.framework.cmd.BinaryAnalysisCommand`.
/// Extension point for commands that can be applied to a program during analysis.
///
/// All implementations should have names ending in "BinaryAnalysisCommand"
/// so the class searcher can find them.
pub trait BinaryAnalysisCommand: Send + Sync + fmt::Debug {
    /// Returns the name of this command.
    fn name(&self) -> &str;

    /// Returns true if this command can be applied to the given program.
    fn can_apply(&self, program_name: &str) -> bool;

    /// Applies the command to the given program.
    ///
    /// Returns true if the command applied successfully.
    fn apply(&mut self, program_name: &str) -> Result<bool, String>;

    /// Returns the status message indicating the status of the command.
    /// Returns None if the command was successful.
    fn messages(&self) -> Option<&str>;
}

// ---------------------------------------------------------------------------
// MessageLog
// ---------------------------------------------------------------------------

/// A log of messages produced during command execution.
///
/// Ported from `ghidra.app.util.importer.MessageLog`.
#[derive(Debug, Default)]
pub struct MessageLog {
    messages: Vec<LogEntry>,
}

/// A single log entry.
#[derive(Debug, Clone)]
pub struct LogEntry {
    /// Severity level.
    pub level: LogLevel,
    /// The message text.
    pub message: String,
    /// Optional source/origin.
    pub source: Option<String>,
}

/// Log level severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    /// Informational.
    Info,
    /// Warning.
    Warning,
    /// Error.
    Error,
}

impl MessageLog {
    /// Create a new empty message log.
    pub fn new() -> Self {
        Self::default()
    }

    /// Append an info message.
    pub fn info(&mut self, msg: impl Into<String>) {
        self.messages.push(LogEntry {
            level: LogLevel::Info,
            message: msg.into(),
            source: None,
        });
    }

    /// Append a warning message.
    pub fn warning(&mut self, msg: impl Into<String>) {
        self.messages.push(LogEntry {
            level: LogLevel::Warning,
            message: msg.into(),
            source: None,
        });
    }

    /// Append an error message.
    pub fn error(&mut self, msg: impl Into<String>) {
        self.messages.push(LogEntry {
            level: LogLevel::Error,
            message: msg.into(),
            source: None,
        });
    }

    /// Append a message with source.
    pub fn append_msg(&mut self, level: LogLevel, msg: impl Into<String>, source: impl Into<String>) {
        self.messages.push(LogEntry {
            level,
            message: msg.into(),
            source: Some(source.into()),
        });
    }

    /// Get all messages.
    pub fn messages(&self) -> &[LogEntry] {
        &self.messages
    }

    /// Get all error messages.
    pub fn errors(&self) -> Vec<&LogEntry> {
        self.messages.iter().filter(|e| e.level == LogLevel::Error).collect()
    }

    /// Get all warning messages.
    pub fn warnings(&self) -> Vec<&LogEntry> {
        self.messages.iter().filter(|e| e.level == LogLevel::Warning).collect()
    }

    /// Whether there are any errors.
    pub fn has_errors(&self) -> bool {
        self.messages.iter().any(|e| e.level == LogLevel::Error)
    }

    /// Whether the log is empty.
    pub fn is_empty(&self) -> bool {
        self.messages.is_empty()
    }

    /// Total number of entries.
    pub fn len(&self) -> usize {
        self.messages.len()
    }
}

// ---------------------------------------------------------------------------
// LocationMemento
// ---------------------------------------------------------------------------

/// A memento that captures a navigatable location for undo/redo.
///
/// Ported from `ghidra.app.nav.LocationMemento`.
#[derive(Debug, Clone)]
pub struct LocationMemento {
    /// Program name.
    pub program_name: String,
    /// Location address.
    pub address: Option<String>,
    /// Whether the memento is valid.
    pub valid: bool,
}

impl LocationMemento {
    /// Create an invalid memento.
    pub fn invalid() -> Self {
        Self {
            program_name: String::new(),
            address: None,
            valid: false,
        }
    }

    /// Create a valid memento.
    pub fn new(program: impl Into<String>, address: impl Into<String>) -> Self {
        Self {
            program_name: program.into(),
            address: Some(address.into()),
            valid: true,
        }
    }

    /// Whether the memento is valid.
    pub fn is_valid(&self) -> bool {
        self.valid
    }

    /// Get the program name.
    pub fn program_name(&self) -> &str {
        &self.program_name
    }

    /// Get the address.
    pub fn address(&self) -> Option<&str> {
        self.address.as_deref()
    }
}

// ---------------------------------------------------------------------------
// ToolState / GhidraToolState
// ---------------------------------------------------------------------------

/// State of a Ghidra tool for undo/redo operations.
///
/// Ported from `ghidra.framework.data.GhidraToolState`.
/// Captures the navigatable state before and after an operation.
#[derive(Debug, Clone)]
pub struct GhidraToolState {
    /// The "before" location memento.
    before_memento: Option<LocationMemento>,
    /// The "after" location memento.
    after_memento: Option<LocationMemento>,
    /// Whether the navigatable is still valid.
    navigatable_valid: bool,
    /// The tool name.
    pub tool_name: String,
}

impl GhidraToolState {
    /// Create a new tool state.
    pub fn new(tool_name: impl Into<String>) -> Self {
        Self {
            before_memento: None,
            after_memento: None,
            navigatable_valid: true,
            tool_name: tool_name.into(),
        }
    }

    /// Set the "before" memento.
    pub fn set_before_memento(&mut self, memento: LocationMemento) {
        if memento.is_valid() {
            self.before_memento = Some(memento);
        }
    }

    /// Set the "after" memento.
    pub fn set_after_memento(&mut self, memento: LocationMemento) {
        if memento.is_valid() {
            self.after_memento = Some(memento);
        }
    }

    /// Get the "before" memento.
    pub fn before_memento(&self) -> Option<&LocationMemento> {
        self.before_memento.as_ref()
    }

    /// Get the "after" memento.
    pub fn after_memento(&self) -> Option<&LocationMemento> {
        self.after_memento.as_ref()
    }

    /// Notification that the navigatable was removed.
    pub fn navigatable_removed(&mut self) {
        self.navigatable_valid = false;
        self.before_memento = None;
        self.after_memento = None;
    }

    /// Whether the navigatable is still valid.
    pub fn is_navigatable_valid(&self) -> bool {
        self.navigatable_valid
    }
}

// ---------------------------------------------------------------------------
// NavigatableComponentProviderAdapter
// ---------------------------------------------------------------------------

/// A component provider adapter that supports navigation.
///
/// Ported from `ghidra.framework.plugintool.NavigatableComponentProviderAdapter`.
/// Provides undo/redo location tracking and navigatable lifecycle management.
#[derive(Debug)]
pub struct NavigatableComponentProvider {
    /// Provider name.
    pub name: String,
    /// Owner identifier.
    pub owner: String,
    /// Whether the provider is connected to a live program.
    is_connected: bool,
    /// Whether the provider has been disposed.
    is_disposed: bool,
    /// Saved navigation state for serialization.
    nav_id: u64,
}

impl NavigatableComponentProvider {
    /// Create a new provider.
    pub fn new(name: impl Into<String>, owner: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            owner: owner.into(),
            is_connected: false,
            is_disposed: false,
            nav_id: 0,
        }
    }

    /// Whether the provider is connected.
    pub fn is_connected(&self) -> bool {
        self.is_connected
    }

    /// Set the connected state.
    pub fn set_connected(&mut self, connected: bool) {
        self.is_connected = connected;
    }

    /// Whether markers are supported (when connected).
    pub fn supports_markers(&self) -> bool {
        self.is_connected
    }

    /// Whether the provider is disposed.
    pub fn is_disposed(&self) -> bool {
        self.is_disposed
    }

    /// Dispose the provider.
    pub fn dispose(&mut self) {
        self.is_disposed = true;
    }

    /// Get the instance ID for serialization.
    pub fn instance_id(&self) -> u64 {
        self.nav_id
    }

    /// Read data state from a save state map.
    pub fn read_data_state(&mut self, state: &HashMap<String, SaveStateValue>) {
        if let Some(SaveStateValue::Long(id)) = state.get("NAV_ID") {
            self.nav_id = *id as u64;
        }
    }

    /// Write data state to a save state map.
    pub fn write_data_state(&self, state: &mut HashMap<String, SaveStateValue>) {
        state.insert("NAV_ID".to_string(), SaveStateValue::Long(self.nav_id as i64));
    }
}

// ---------------------------------------------------------------------------
// SaveState
// ---------------------------------------------------------------------------

/// A serializable state container for framework components.
///
/// Ported from `ghidra.framework.options.SaveState`.
#[derive(Debug, Clone, Default)]
pub struct SaveState {
    values: HashMap<String, SaveStateValue>,
}

/// Values that can be stored in a SaveState.
#[derive(Debug, Clone)]
pub enum SaveStateValue {
    /// Boolean value.
    Bool(bool),
    /// Integer value.
    Int(i32),
    /// Long value.
    Long(i64),
    /// String value.
    String(String),
    /// Byte array.
    Bytes(Vec<u8>),
}

impl SaveState {
    /// Create a new empty SaveState.
    pub fn new() -> Self {
        Self::default()
    }

    /// Put a boolean value.
    pub fn put_bool(&mut self, key: &str, value: bool) {
        self.values.insert(key.to_string(), SaveStateValue::Bool(value));
    }

    /// Get a boolean value.
    pub fn get_bool(&self, key: &str, default: bool) -> bool {
        match self.values.get(key) {
            Some(SaveStateValue::Bool(v)) => *v,
            _ => default,
        }
    }

    /// Put a long value.
    pub fn put_long(&mut self, key: &str, value: i64) {
        self.values.insert(key.to_string(), SaveStateValue::Long(value));
    }

    /// Get a long value.
    pub fn get_long(&self, key: &str, default: i64) -> i64 {
        match self.values.get(key) {
            Some(SaveStateValue::Long(v)) => *v,
            _ => default,
        }
    }

    /// Put a string value.
    pub fn put_string(&mut self, key: &str, value: &str) {
        self.values
            .insert(key.to_string(), SaveStateValue::String(value.to_string()));
    }

    /// Get a string value.
    pub fn get_string(&self, key: &str, default: &str) -> String {
        match self.values.get(key) {
            Some(SaveStateValue::String(v)) => v.clone(),
            _ => default.to_string(),
        }
    }

    /// Check if a key exists.
    fn has_value(&self, key: &str) -> bool {
        self.values.contains_key(key)
    }
}

// ---------------------------------------------------------------------------
// ApplicationConfiguration
// ---------------------------------------------------------------------------

/// Headless Ghidra application configuration.
///
/// Ported from `ghidra.framework.HeadlessGhidraApplicationConfiguration`.
#[derive(Debug)]
pub struct HeadlessApplicationConfiguration {
    /// Whether the application is ready.
    initialized: bool,
    /// Application title.
    pub title: String,
}

impl HeadlessApplicationConfiguration {
    /// Create a new headless configuration.
    pub fn new() -> Self {
        Self {
            initialized: false,
            title: "Ghidra".to_string(),
        }
    }

    /// Whether this is a headless configuration.
    pub fn is_headless(&self) -> bool {
        true
    }

    /// Initialize the application.
    pub fn initialize(&mut self) {
        self.initialized = true;
    }

    /// Whether the application is initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }
}

impl Default for HeadlessApplicationConfiguration {
    fn default() -> Self {
        Self::new()
    }
}

/// GUI Ghidra application configuration.
///
/// Ported from `ghidra.framework.GhidraApplicationConfiguration`.
#[derive(Debug)]
pub struct ApplicationConfiguration {
    headless: HeadlessApplicationConfiguration,
    /// Whether to show the splash screen.
    pub show_splash_screen: bool,
    /// Whether to show the user agreement.
    pub show_user_agreement: bool,
}

impl ApplicationConfiguration {
    /// Create a new GUI configuration.
    pub fn new() -> Self {
        Self {
            headless: HeadlessApplicationConfiguration::new(),
            show_splash_screen: true,
            show_user_agreement: true,
        }
    }

    /// Whether this is a headless configuration.
    pub fn is_headless(&self) -> bool {
        false
    }

    /// Initialize the application.
    pub fn initialize(&mut self) {
        self.headless.initialize();
    }

    /// Whether the application is initialized.
    pub fn is_initialized(&self) -> bool {
        self.headless.is_initialized()
    }
}

impl Default for ApplicationConfiguration {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// DataTreeDialog
// ---------------------------------------------------------------------------

/// Type of data tree dialog.
///
/// Ported from `ghidra.framework.main.DataTreeDialogType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataTreeDialogType {
    /// Open a file.
    OPEN,
    /// Save a file.
    SAVE,
}

/// Dialog for browsing and selecting items in the project data tree.
///
/// Ported from `ghidra.framework.main.DataTreeDialog`.
#[derive(Debug)]
pub struct DataTreeDialog {
    /// Dialog title.
    pub title: String,
    /// Dialog type.
    pub dialog_type: DataTreeDialogType,
    /// Selected project file path.
    selected_path: Option<String>,
}

impl DataTreeDialog {
    /// Create a new data tree dialog.
    pub fn new(title: impl Into<String>, dialog_type: DataTreeDialogType) -> Self {
        Self {
            title: title.into(),
            dialog_type,
            selected_path: None,
        }
    }

    /// Set the selected path.
    pub fn set_selected_path(&mut self, path: impl Into<String>) {
        self.selected_path = Some(path.into());
    }

    /// Get the selected path.
    pub fn selected_path(&self) -> Option<&str> {
        self.selected_path.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // BinaryAnalysisCommand tests
    // ========================================================================

    #[derive(Debug)]
    struct TestCommand {
        name: String,
        applicable: bool,
        applied: bool,
    }

    impl TestCommand {
        fn new(name: &str) -> Self {
            Self {
                name: name.to_string(),
                applicable: true,
                applied: false,
            }
        }
    }

    impl BinaryAnalysisCommand for TestCommand {
        fn name(&self) -> &str {
            &self.name
        }

        fn can_apply(&self, _program: &str) -> bool {
            self.applicable
        }

        fn apply(&mut self, _program: &str) -> Result<bool, String> {
            if self.applicable {
                self.applied = true;
                Ok(true)
            } else {
                Err("Not applicable".to_string())
            }
        }

        fn messages(&self) -> Option<&str> {
            None
        }
    }

    #[test]
    fn test_binary_analysis_command() {
        let mut cmd = TestCommand::new("TestBinaryAnalysisCommand");
        assert_eq!(cmd.name(), "TestBinaryAnalysisCommand");
        assert!(cmd.can_apply("test_program"));
        assert!(cmd.apply("test_program").unwrap());
        assert!(cmd.messages().is_none());
    }

    #[test]
    fn test_binary_analysis_command_failure() {
        let mut cmd = TestCommand::new("FailBinaryAnalysisCommand");
        cmd.applicable = false;
        assert!(!cmd.can_apply("test"));
        assert!(cmd.apply("test").is_err());
    }

    // ========================================================================
    // MessageLog tests
    // ========================================================================

    #[test]
    fn test_message_log() {
        let mut log = MessageLog::new();
        assert!(log.is_empty());

        log.info("info message");
        log.warning("warning message");
        log.error("error message");

        assert_eq!(log.len(), 3);
        assert!(log.has_errors());
        assert_eq!(log.errors().len(), 1);
        assert_eq!(log.warnings().len(), 1);
    }

    #[test]
    fn test_message_log_with_source() {
        let mut log = MessageLog::new();
        log.append_msg(LogLevel::Error, "bad data", "ImportPlugin");
        assert_eq!(log.messages()[0].source.as_deref(), Some("ImportPlugin"));
    }

    // ========================================================================
    // LocationMemento tests
    // ========================================================================

    #[test]
    fn test_location_memento() {
        let m = LocationMemento::new("program", "0x401000");
        assert!(m.is_valid());
        assert_eq!(m.program_name(), "program");
        assert_eq!(m.address(), Some("0x401000"));

        let invalid = LocationMemento::invalid();
        assert!(!invalid.is_valid());
    }

    // ========================================================================
    // GhidraToolState tests
    // ========================================================================

    #[test]
    fn test_tool_state() {
        let mut state = GhidraToolState::new("TestTool");
        assert!(state.is_navigatable_valid());

        state.set_before_memento(LocationMemento::new("prog", "0x1000"));
        assert!(state.before_memento().is_some());

        state.navigatable_removed();
        assert!(!state.is_navigatable_valid());
        assert!(state.before_memento().is_none());
    }

    #[test]
    fn test_tool_state_mementos() {
        let mut state = GhidraToolState::new("TestTool");
        state.set_before_memento(LocationMemento::new("prog", "0x1000"));
        state.set_after_memento(LocationMemento::new("prog", "0x2000"));

        assert_eq!(
            state.before_memento().unwrap().address(),
            Some("0x1000")
        );
        assert_eq!(
            state.after_memento().unwrap().address(),
            Some("0x2000")
        );
    }

    // ========================================================================
    // NavigatableComponentProvider tests
    // ========================================================================

    #[test]
    fn test_navigatable_provider() {
        let mut provider = NavigatableComponentProvider::new("CodeBrowser", "CorePlugin");
        assert!(!provider.is_connected());
        assert!(!provider.supports_markers());
        assert!(!provider.is_disposed());

        provider.set_connected(true);
        assert!(provider.is_connected());
        assert!(provider.supports_markers());

        provider.dispose();
        assert!(provider.is_disposed());
    }

    // ========================================================================
    // SaveState tests
    // ========================================================================

    #[test]
    fn test_save_state() {
        let mut state = SaveState::new();
        state.put_bool("flag", true);
        state.put_long("count", 42);
        state.put_string("name", "test");

        assert!(state.get_bool("flag", false));
        assert_eq!(state.get_long("count", 0), 42);
        assert_eq!(state.get_string("name", ""), "test");
        assert!(!state.get_bool("missing", false));
        assert_eq!(state.get_long("missing", -1), -1);
    }

    // ========================================================================
    // ApplicationConfiguration tests
    // ========================================================================

    #[test]
    fn test_headless_config() {
        let mut config = HeadlessApplicationConfiguration::new();
        assert!(config.is_headless());
        assert!(!config.is_initialized());
        config.initialize();
        assert!(config.is_initialized());
    }

    #[test]
    fn test_gui_config() {
        let mut config = ApplicationConfiguration::new();
        assert!(!config.is_headless());
        assert!(config.show_splash_screen);
        config.initialize();
        assert!(config.is_initialized());
    }

    // ========================================================================
    // DataTreeDialog tests
    // ========================================================================

    #[test]
    fn test_data_tree_dialog() {
        let mut dialog = DataTreeDialog::new("Open File", DataTreeDialogType::OPEN);
        assert_eq!(dialog.title, "Open File");
        assert!(dialog.selected_path().is_none());

        dialog.set_selected_path("/project/file.gzf");
        assert_eq!(dialog.selected_path(), Some("/project/file.gzf"));
    }
}
