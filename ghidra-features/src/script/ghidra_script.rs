//! GhidraScript core: the scripting API, state management, and provider system.
//!
//! Ported from Ghidra's `ghidra.app.script` Java package:
//! - `GhidraScript` -- abstract base for all scripts (4117 lines)
//! - `GhidraState` -- encapsulates current tool state
//! - `GhidraScriptProvider` -- discovers and manages script types
//! - `GhidraScriptProperties` -- script metadata from properties file
//! - `GhidraScriptLoadException` -- errors loading scripts
//! - `ScriptMessage` -- console message types
//! - `DecoratingPrintWriter` -- output writer with decoration
//!
//! # Key Types
//!
//! - [`GhidraScript`] -- The script execution API
//! - [`GhidraState`] -- Snapshots the current tool state
//! - [`GhidraScriptProvider`] -- Script type discovery
//! - [`GhidraScriptProperties`] -- Script metadata

use std::collections::HashMap;
use std::fmt;
use std::path::PathBuf;

// ---------------------------------------------------------------------------
// GhidraState -- current tool state for scripts
// ---------------------------------------------------------------------------

/// Represents the current state of a Ghidra tool.
///
/// Contains references to the active program, current location, selection,
/// highlight, and environment variables. This state is passed to scripts
/// when they execute.
///
/// Ported from `ghidra.app.script.GhidraState`.
#[derive(Debug, Clone)]
pub struct GhidraState {
    /// Name of the current program (or None if no program is open).
    pub current_program: Option<String>,
    /// Current address as a hex string (e.g., "0x00401000").
    pub current_address: Option<String>,
    /// Current program location (address + context).
    pub current_location: Option<ProgramLocation>,
    /// Current selection in the listing.
    pub current_selection: Option<AddressRange>,
    /// Current highlight in the listing.
    pub current_highlight: Option<AddressRange>,
    /// Environment variables passed to the script.
    pub env_map: HashMap<String, EnvValue>,
    /// Whether this is the global state (fires events on changes).
    pub is_global: bool,
}

/// A program location (address + context).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgramLocation {
    /// The address.
    pub address: String,
    /// Optional register name if this is a register location.
    pub register: Option<String>,
    /// Byte offset within the code unit.
    pub byte_offset: u32,
}

/// An address range (start, end).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressRange {
    /// Start address (hex string).
    pub start: String,
    /// End address (hex string).
    pub end: String,
}

/// Environment variable value types.
#[derive(Debug, Clone)]
pub enum EnvValue {
    /// Byte value.
    Byte(i8),
    /// Short value.
    Short(i16),
    /// Integer value.
    Int(i32),
    /// Long value.
    Long(i64),
    /// Float value.
    Float(f32),
    /// Double value.
    Double(f64),
    /// String value.
    String(String),
    /// Boolean value.
    Bool(bool),
}

impl GhidraState {
    /// Create a new state.
    pub fn new() -> Self {
        Self {
            current_program: None,
            current_address: None,
            current_location: None,
            current_selection: None,
            current_highlight: None,
            env_map: HashMap::new(),
            is_global: true,
        }
    }

    /// Create a copy of this state (non-global, for script-local use).
    pub fn copy(&self) -> Self {
        Self {
            current_program: self.current_program.clone(),
            current_address: self.current_address.clone(),
            current_location: self.current_location.clone(),
            current_selection: self.current_selection.clone(),
            current_highlight: self.current_highlight.clone(),
            env_map: self.env_map.clone(),
            is_global: false,
        }
    }

    /// Get the current address.
    pub fn current_address(&self) -> Option<&str> {
        self.current_address.as_deref()
    }

    /// Set the current address.
    pub fn set_current_address(&mut self, address: Option<String>) {
        self.current_address = address;
    }

    /// Get the current location.
    pub fn current_location(&self) -> Option<&ProgramLocation> {
        self.current_location.as_ref()
    }

    /// Set the current location.
    pub fn set_current_location(&mut self, location: Option<ProgramLocation>) {
        self.current_location = location;
    }

    /// Get the current selection.
    pub fn current_selection(&self) -> Option<&AddressRange> {
        self.current_selection.as_ref()
    }

    /// Set the current selection.
    pub fn set_current_selection(&mut self, selection: Option<AddressRange>) {
        self.current_selection = selection;
    }

    /// Get the current highlight.
    pub fn current_highlight(&self) -> Option<&AddressRange> {
        self.current_highlight.as_ref()
    }

    /// Set the current highlight.
    pub fn set_current_highlight(&mut self, highlight: Option<AddressRange>) {
        self.current_highlight = highlight;
    }

    /// Add an environment variable.
    pub fn add_env(&mut self, name: impl Into<String>, value: EnvValue) {
        self.env_map.insert(name.into(), value);
    }

    /// Remove an environment variable.
    pub fn remove_env(&mut self, name: &str) -> Option<EnvValue> {
        self.env_map.remove(name)
    }

    /// Get an environment variable.
    pub fn get_env(&self, name: &str) -> Option<&EnvValue> {
        self.env_map.get(name)
    }

    /// Get all environment variable names.
    pub fn env_names(&self) -> Vec<&str> {
        self.env_map.keys().map(|s| s.as_str()).collect()
    }
}

impl Default for GhidraState {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// GhidraScript -- the script execution API
// ---------------------------------------------------------------------------

/// The main scripting API.
///
/// Provides methods for interacting with the Ghidra program database,
/// printing output, asking the user for input, creating bookmarks,
/// manipulating addresses, and more.
///
/// Ported from `ghidra.app.script.GhidraScript` (4117 lines).
#[derive(Debug)]
pub struct GhidraScript {
    /// The script's state.
    pub state: GhidraState,
    /// Path to the script source file.
    pub source_file: Option<PathBuf>,
    /// Whether output should be decorated with script name.
    pub decorate_output: bool,
    /// The script's display name.
    pub script_name: String,
    /// Output buffer for captured messages.
    output_buffer: Vec<ScriptMessage>,
    /// Error output buffer.
    error_buffer: Vec<ScriptMessage>,
    /// Last values used by ask*() methods, for pre-populating dialogs.
    ask_map: HashMap<String, String>,
}

/// A console message emitted by a script.
#[derive(Debug, Clone)]
pub struct ScriptMessage {
    /// The message level.
    pub level: MessageLevel,
    /// The message text.
    pub text: String,
}

/// Console message levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum MessageLevel {
    /// Informational message.
    Info,
    /// Warning message.
    Warning,
    /// Error message.
    Error,
}

impl fmt::Display for MessageLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MessageLevel::Info => write!(f, "INFO"),
            MessageLevel::Warning => write!(f, "WARN"),
            MessageLevel::Error => write!(f, "ERROR"),
        }
    }
}

impl GhidraScript {
    /// Create a new script.
    pub fn new(script_name: impl Into<String>) -> Self {
        Self {
            state: GhidraState::new(),
            source_file: None,
            decorate_output: true,
            script_name: script_name.into(),
            output_buffer: Vec::new(),
            error_buffer: Vec::new(),
            ask_map: HashMap::new(),
        }
    }

    /// Print a message to the console.
    pub fn println(&mut self, msg: impl Into<String>) {
        let text = msg.into();
        self.output_buffer.push(ScriptMessage {
            level: MessageLevel::Info,
            text: text.clone(),
        });
    }

    /// Print an error message to the console.
    pub fn print_error(&mut self, msg: impl Into<String>) {
        let text = msg.into();
        self.error_buffer.push(ScriptMessage {
            level: MessageLevel::Error,
            text: text.clone(),
        });
    }

    /// Print a warning message to the console.
    pub fn print_warning(&mut self, msg: impl Into<String>) {
        let text = msg.into();
        self.output_buffer.push(ScriptMessage {
            level: MessageLevel::Warning,
            text: text.clone(),
        });
    }

    /// Get the current program name.
    pub fn current_program(&self) -> Option<&str> {
        self.state.current_program.as_deref()
    }

    /// Get the current address.
    pub fn current_address(&self) -> Option<&str> {
        self.state.current_address()
    }

    /// Get the current location.
    pub fn current_location(&self) -> Option<&ProgramLocation> {
        self.state.current_location()
    }

    /// Get the current selection.
    pub fn current_selection(&self) -> Option<&AddressRange> {
        self.state.current_selection()
    }

    /// Get the current highlight.
    pub fn current_highlight(&self) -> Option<&AddressRange> {
        self.state.current_highlight()
    }

    /// Ask the user for a string value.
    /// Returns a previously stored value if available.
    pub fn ask_string(&mut self, prompt: &str, default: &str) -> String {
        let key = format!("string:{prompt}");
        self.ask_map
            .get(&key)
            .cloned()
            .unwrap_or_else(|| default.to_string())
    }

    /// Ask the user for an address.
    pub fn ask_address(&mut self, prompt: &str, default: &str) -> String {
        let key = format!("address:{prompt}");
        self.ask_map
            .get(&key)
            .cloned()
            .unwrap_or_else(|| default.to_string())
    }

    /// Ask the user for an integer.
    pub fn ask_int(&mut self, prompt: &str, default: i64) -> i64 {
        let key = format!("int:{prompt}");
        self.ask_map
            .get(&key)
            .and_then(|s| s.parse().ok())
            .unwrap_or(default)
    }

    /// Ask the user for a choice from a list.
    pub fn ask_choice(&mut self, prompt: &str, options: &[String], default: &str) -> String {
        let key = format!("choice:{prompt}");
        let stored = self.ask_map.get(&key).cloned();
        if let Some(val) = stored {
            if options.contains(&val) {
                return val;
            }
        }
        default.to_string()
    }

    /// Store a value for future ask*() calls.
    pub fn store_ask_value(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.ask_map.insert(key.into(), value.into());
    }

    /// Get all output messages.
    pub fn output(&self) -> &[ScriptMessage] {
        &self.output_buffer
    }

    /// Get all error messages.
    pub fn errors(&self) -> &[ScriptMessage] {
        &self.error_buffer
    }

    /// Clear the output buffer.
    pub fn clear_output(&mut self) {
        self.output_buffer.clear();
        self.error_buffer.clear();
    }

    /// Get the script name.
    pub fn name(&self) -> &str {
        &self.script_name
    }

    /// Set the source file path.
    pub fn set_source_file(&mut self, path: PathBuf) {
        self.source_file = Some(path);
    }
}

// ---------------------------------------------------------------------------
// GhidraScriptProvider -- discovers and manages script types
// ---------------------------------------------------------------------------

/// The supported script language.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScriptLanguage {
    /// Java-based Ghidra scripts.
    Java,
    /// Python (Jython) scripts.
    Python,
    /// JavaScript scripts.
    JavaScript,
    /// Unsupported/unknown language.
    Unsupported,
}

impl fmt::Display for ScriptLanguage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScriptLanguage::Java => write!(f, "Java"),
            ScriptLanguage::Python => write!(f, "Python"),
            ScriptLanguage::JavaScript => write!(f, "JavaScript"),
            ScriptLanguage::Unsupported => write!(f, "Unsupported"),
        }
    }
}

/// A script provider discovers and manages scripts of a particular type.
///
/// Ported from `ghidra.app.script.GhidraScriptProvider`.
#[derive(Debug, Clone)]
pub struct GhidraScriptProvider {
    /// The language this provider supports.
    pub language: ScriptLanguage,
    /// File extensions this provider handles.
    pub extensions: Vec<String>,
    /// Description of this script type.
    pub description: String,
}

impl GhidraScriptProvider {
    /// Create a Java script provider.
    pub fn java() -> Self {
        Self {
            language: ScriptLanguage::Java,
            extensions: vec![".java".to_string()],
            description: "Java Ghidra Script".to_string(),
        }
    }

    /// Create a Python script provider.
    pub fn python() -> Self {
        Self {
            language: ScriptLanguage::Python,
            extensions: vec![".py".to_string()],
            description: "Python (Jython) Ghidra Script".to_string(),
        }
    }

    /// Create a JavaScript script provider.
    pub fn javascript() -> Self {
        Self {
            language: ScriptLanguage::JavaScript,
            extensions: vec![".js".to_string()],
            description: "JavaScript Ghidra Script".to_string(),
        }
    }

    /// Check if this provider can handle a file with the given name.
    pub fn can_handle(&self, filename: &str) -> bool {
        let lower = filename.to_lowercase();
        self.extensions.iter().any(|ext| lower.ends_with(ext))
    }

    /// Get the default file extension.
    pub fn default_extension(&self) -> &str {
        self.extensions.first().map(|s| s.as_str()).unwrap_or("")
    }
}

// ---------------------------------------------------------------------------
// GhidraScriptProperties -- script metadata
// ---------------------------------------------------------------------------

/// Metadata properties for a Ghidra script.
///
/// Ported from `ghidra.app.script.GhidraScriptProperties`.
#[derive(Debug, Clone, Default)]
pub struct GhidraScriptProperties {
    /// The script's @author tag.
    pub author: Option<String>,
    /// The script's @category tag.
    pub category: Option<String>,
    /// The script's @keybinding tag.
    pub key_binding: Option<String>,
    /// The script's @menupath tag.
    pub menu_path: Option<String>,
    /// The script's @toolbar tag.
    pub toolbar: Option<String>,
    /// The script's @description tag.
    pub description: Option<String>,
    /// Whether the script is visible in menus.
    pub visible: bool,
}

impl GhidraScriptProperties {
    /// Create empty properties.
    pub fn new() -> Self {
        Self {
            visible: true,
            ..Default::default()
        }
    }

    /// Parse properties from @tags in a script source file.
    ///
    /// Handles both bare `@tag value` and comment-prefixed `// @tag value` forms.
    pub fn from_source(source: &str) -> Self {
        let mut props = Self::new();
        for line in source.lines() {
            let trimmed = line.trim();
            // Find @tag anywhere on the line (handles //, #, /* prefixes)
            let tag_start = trimmed.find('@');
            if let Some(pos) = tag_start {
                let from_tag = &trimmed[pos..];
                if let Some(rest) = from_tag.strip_prefix("@author ") {
                    props.author = Some(rest.trim().to_string());
                } else if let Some(rest) = from_tag.strip_prefix("@category ") {
                    props.category = Some(rest.trim().to_string());
                } else if let Some(rest) = from_tag.strip_prefix("@keybinding ") {
                    props.key_binding = Some(rest.trim().to_string());
                } else if let Some(rest) = from_tag.strip_prefix("@menupath ") {
                    props.menu_path = Some(rest.trim().to_string());
                } else if let Some(rest) = from_tag.strip_prefix("@toolbar ") {
                    props.toolbar = Some(rest.trim().to_string());
                } else if let Some(rest) = from_tag.strip_prefix("@description ") {
                    props.description = Some(rest.trim().to_string());
                }
            }
        }
        props
    }
}

// ---------------------------------------------------------------------------
// GhidraScriptLoadException -- error loading a script
// ---------------------------------------------------------------------------

/// Error type for script loading failures.
///
/// Ported from `ghidra.app.script.GhidraScriptLoadException`.
#[derive(Debug, Clone)]
pub struct GhidraScriptLoadException {
    /// Description of the error.
    pub message: String,
    /// The script that failed to load.
    pub script_name: String,
    /// Optional underlying cause.
    pub cause: Option<String>,
}

impl fmt::Display for GhidraScriptLoadException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Failed to load script '{}': {}", self.script_name, self.message)
    }
}

impl std::error::Error for GhidraScriptLoadException {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ghidra_state_lifecycle() {
        let mut state = GhidraState::new();
        assert!(state.is_global);
        assert!(state.current_program.is_none());

        state.current_program = Some("test.exe".to_string());
        state.set_current_address(Some("0x00401000".to_string()));

        let copy = state.copy();
        assert!(!copy.is_global);
        assert_eq!(copy.current_program, Some("test.exe".to_string()));
        assert_eq!(copy.current_address(), Some("0x00401000"));
    }

    #[test]
    fn test_ghidra_state_location() {
        let mut state = GhidraState::new();
        let loc = ProgramLocation {
            address: "0x1000".to_string(),
            register: Some("RAX".to_string()),
            byte_offset: 0,
        };
        state.set_current_location(Some(loc.clone()));
        assert_eq!(state.current_location(), Some(&loc));
    }

    #[test]
    fn test_ghidra_state_selection() {
        let mut state = GhidraState::new();
        let sel = AddressRange {
            start: "0x1000".to_string(),
            end: "0x1FFF".to_string(),
        };
        state.set_current_selection(Some(sel.clone()));
        assert_eq!(state.current_selection(), Some(&sel));
    }

    #[test]
    fn test_ghidra_state_env_vars() {
        let mut state = GhidraState::new();
        state.add_env("COUNT", EnvValue::Int(42));
        state.add_env("NAME", EnvValue::String("test".to_string()));

        assert!(matches!(state.get_env("COUNT"), Some(EnvValue::Int(42))));
        assert!(state.get_env("MISSING").is_none());

        let names = state.env_names();
        assert_eq!(names.len(), 2);

        state.remove_env("COUNT");
        assert!(state.get_env("COUNT").is_none());
    }

    #[test]
    fn test_ghidra_script_basic() {
        let mut script = GhidraScript::new("TestScript");
        assert_eq!(script.name(), "TestScript");
        assert!(script.decorate_output);

        script.println("Hello, World!");
        script.print_warning("Be careful");
        script.print_error("Oops");

        assert_eq!(script.output().len(), 2);
        assert_eq!(script.errors().len(), 1);
        assert_eq!(script.output()[0].text, "Hello, World!");
        assert_eq!(script.output()[1].level, MessageLevel::Warning);
        assert_eq!(script.errors()[0].level, MessageLevel::Error);

        script.clear_output();
        assert!(script.output().is_empty());
        assert!(script.errors().is_empty());
    }

    #[test]
    fn test_ghidra_script_ask_methods() {
        let mut script = GhidraScript::new("AskTest");

        // Default values
        let s = script.ask_string("Enter name", "default");
        assert_eq!(s, "default");

        let addr = script.ask_address("Enter address", "0x0");
        assert_eq!(addr, "0x0");

        let i = script.ask_int("Enter count", 10);
        assert_eq!(i, 10);

        let choice = script.ask_choice(
            "Pick one",
            &["a".to_string(), "b".to_string()],
            "a",
        );
        assert_eq!(choice, "a");

        // With stored values
        script.store_ask_value("string:Enter name", "stored_name");
        let s = script.ask_string("Enter name", "default");
        assert_eq!(s, "stored_name");
    }

    #[test]
    fn test_ghidra_script_state_access() {
        let mut script = GhidraScript::new("StateTest");
        script.state.current_program = Some("prog.bin".to_string());
        script.state.set_current_address(Some("0x400000".to_string()));

        assert_eq!(script.current_program(), Some("prog.bin"));
        assert_eq!(script.current_address(), Some("0x400000"));
    }

    #[test]
    fn test_script_provider() {
        let java = GhidraScriptProvider::java();
        assert_eq!(java.language, ScriptLanguage::Java);
        assert!(java.can_handle("MyScript.java"));
        assert!(!java.can_handle("MyScript.py"));

        let python = GhidraScriptProvider::python();
        assert!(python.can_handle("analysis.py"));
        assert!(!python.can_handle("analysis.java"));

        let js = GhidraScriptProvider::javascript();
        assert!(js.can_handle("helper.js"));
        assert_eq!(js.default_extension(), ".js");
    }

    #[test]
    fn test_script_properties_from_source() {
        let source = r#"
// @author John Doe
// @category Analysis
// @keybinding ctrl shift A
// @menupath Analysis/My Analysis
// @toolbar analysis.png
// @description Performs custom analysis
public class MyScript extends GhidraScript {
    // ...
}
"#;
        let props = GhidraScriptProperties::from_source(source);
        assert_eq!(props.author, Some("John Doe".to_string()));
        assert_eq!(props.category, Some("Analysis".to_string()));
        assert_eq!(props.key_binding, Some("ctrl shift A".to_string()));
        assert_eq!(props.menu_path, Some("Analysis/My Analysis".to_string()));
        assert_eq!(props.toolbar, Some("analysis.png".to_string()));
        assert_eq!(props.description, Some("Performs custom analysis".to_string()));
    }

    #[test]
    fn test_script_properties_empty() {
        let props = GhidraScriptProperties::from_source("public class Empty {}");
        assert!(props.author.is_none());
        assert!(props.category.is_none());
        assert!(props.visible);
    }

    #[test]
    fn test_script_load_exception() {
        let err = GhidraScriptLoadException {
            message: "Syntax error".to_string(),
            script_name: "bad.java".to_string(),
            cause: Some("Unexpected token".to_string()),
        };
        let display = format!("{err}");
        assert!(display.contains("bad.java"));
        assert!(display.contains("Syntax error"));
    }

    #[test]
    fn test_message_level_ordering() {
        assert!(MessageLevel::Info < MessageLevel::Warning);
        assert!(MessageLevel::Warning < MessageLevel::Error);
        assert_eq!(format!("{}", MessageLevel::Info), "INFO");
        assert_eq!(format!("{}", MessageLevel::Warning), "WARN");
        assert_eq!(format!("{}", MessageLevel::Error), "ERROR");
    }
}
