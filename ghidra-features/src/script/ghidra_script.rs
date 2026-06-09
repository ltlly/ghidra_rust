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
    /// Script properties parsed from @tags.
    properties: GhidraScriptProperties,
    /// Command-line arguments passed to the script.
    script_args: Vec<String>,
    /// Whether the script is running in headless mode.
    headless: bool,
    /// Whether to reuse previous choices in ask*() dialogs.
    reuse_previous_choices: bool,
    /// Comments keyed by address: list of (type, text) pairs.
    comments: HashMap<String, Vec<(CommentType, String)>>,
    /// Bookmarks in the program.
    bookmarks: Vec<BookmarkInfo>,
    /// Memory blocks in the program.
    memory_blocks: Vec<MemoryBlockInfo>,
    /// Symbols in the program.
    symbols: Vec<SymbolInfo>,
    /// Entry points.
    entry_points: Vec<String>,
    /// Functions in the program.
    functions: Vec<FunctionInfo>,
    /// Instructions in the program.
    instructions: Vec<InstructionInfo>,
    /// Data items in the program.
    data_items: Vec<DataInfo>,
    /// References (xrefs) in the program.
    references: Vec<ReferenceInfo>,
    /// Addresses that have been disassembled.
    disassembled_addresses: Vec<String>,
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
            properties: GhidraScriptProperties::new(),
            script_args: Vec::new(),
            headless: false,
            reuse_previous_choices: true,
            comments: HashMap::new(),
            bookmarks: Vec::new(),
            memory_blocks: Vec::new(),
            symbols: Vec::new(),
            entry_points: Vec::new(),
            functions: Vec::new(),
            instructions: Vec::new(),
            data_items: Vec::new(),
            references: Vec::new(),
            disassembled_addresses: Vec::new(),
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
    /// Groovy scripts (runs on JVM).
    Groovy,
    /// Unsupported/unknown language.
    Unsupported,
}

impl fmt::Display for ScriptLanguage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScriptLanguage::Java => write!(f, "Java"),
            ScriptLanguage::Python => write!(f, "Python"),
            ScriptLanguage::JavaScript => write!(f, "JavaScript"),
            ScriptLanguage::Groovy => write!(f, "Groovy"),
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

    /// Create a Groovy script provider.
    pub fn groovy() -> Self {
        Self {
            language: ScriptLanguage::Groovy,
            extensions: vec![".groovy".to_string()],
            description: "Groovy Ghidra Script".to_string(),
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

    /// Create a new script file with a template.
    ///
    /// Ported from `GhidraScriptProvider.createNewScript(ResourceFile, String)`.
    pub fn create_new_script(&self, category: &str) -> String {
        let cat = if category.is_empty() { "_NEW_" } else { category };
        let ext = self.default_extension();
        let comment = match self.language {
            ScriptLanguage::Python => "#",
            _ => "//",
        };

        let mut out = String::new();
        out.push_str(&format!("{}TODO write a description for this script\n", comment));
        out.push_str(&format!("{}@author \n", comment));
        out.push_str(&format!("{}@category {}\n", comment, cat));
        out.push_str(&format!("{}@keybinding \n", comment));
        out.push_str(&format!("{}@menupath \n", comment));
        out.push_str(&format!("{}@toolbar \n", comment));
        out.push_str(&format!("{}@description \n", comment));
        out.push('\n');

        match self.language {
            ScriptLanguage::Java | ScriptLanguage::Groovy => {
                out.push_str("import ghidra.app.script.GhidraScript;\n");
                out.push('\n');
                out.push_str("public class NewScript extends GhidraScript {\n");
                out.push('\n');
                out.push_str("    public void run() throws Exception {\n");
                out.push_str(&format!("        {}TODO Add User Code Here\n", comment));
                out.push_str("    }\n");
                out.push('\n');
                out.push_str("}\n");
            }
            ScriptLanguage::Python => {
                out.push_str("#TODO Add User Code Here\n");
            }
            ScriptLanguage::JavaScript => {
                out.push_str("//TODO Add User Code Here\n");
            }
            ScriptLanguage::Unsupported => {
                out.push_str(&format!("{}TODO Add User Code Here\n", comment));
            }
        }

        out
    }

    /// Get a script instance from source code.
    ///
    /// Ported from `GhidraScriptProvider.getScriptInstance(ResourceFile, PrintWriter)`.
    pub fn get_script_instance(&self, source: &str) -> Result<GhidraScript, GhidraScriptLoadException> {
        let mut script = GhidraScript::new("script");
        script.set_properties_from_source(source);
        Ok(script)
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

// ---------------------------------------------------------------------------
// GhidraScriptConstants -- shared constants
// ---------------------------------------------------------------------------

/// Constants shared across the scripting subsystem.
///
/// Ported from `ghidra.app.script.GhidraScriptConstants`.
pub mod constants {
    /// System property that overrides the user scripts directory.
    pub const USER_SCRIPTS_DIR_PROPERTY: &str = "ghidra.user.scripts.dir";

    /// Default name for newly created scripts.
    pub const DEFAULT_SCRIPT_NAME: &str = "NewScript";

    /// Metadata tag keys used in script source headers.
    pub const AT_AUTHOR: &str = "@author";
    /// Category tag.
    pub const AT_CATEGORY: &str = "@category";
    /// Keybinding tag.
    pub const AT_KEYBINDING: &str = "@keybinding";
    /// Menu path tag.
    pub const AT_MENUPATH: &str = "@menupath";
    /// Toolbar tag.
    pub const AT_TOOLBAR: &str = "@toolbar";
    /// Description tag.
    pub const AT_DESCRIPTION: &str = "@description";
    /// Runtime environment tag.
    pub const AT_RUNTIME: &str = "@runtime";

    /// All metadata tags in order (matching Java `ScriptInfo.METADATA`).
    pub const METADATA: &[&str] = &[
        AT_AUTHOR,
        AT_CATEGORY,
        AT_KEYBINDING,
        AT_MENUPATH,
        AT_TOOLBAR,
        AT_DESCRIPTION,
        AT_RUNTIME,
    ];
}

// ---------------------------------------------------------------------------
// ImproperUseException -- API misuse in headless mode, etc.
// ---------------------------------------------------------------------------

/// Exception for improper API use (e.g., GUI-only methods in headless mode).
///
/// Ported from `ghidra.app.script.ImproperUseException`.
#[derive(Debug, Clone)]
pub struct ImproperUseException {
    pub message: String,
}

impl ImproperUseException {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for ImproperUseException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Improper use: {}", self.message)
    }
}

impl std::error::Error for ImproperUseException {}

// ---------------------------------------------------------------------------
// GhidraScriptUnsupportedClassVersionError
// ---------------------------------------------------------------------------

/// Error when a compiled script class file targets an unsupported JVM version.
///
/// Ported from `ghidra.app.script.GhidraScriptUnsupportedClassVersionError`.
#[derive(Debug, Clone)]
pub struct GhidraScriptUnsupportedClassVersionError {
    /// The class file that caused the error.
    pub class_file: String,
    /// The error message.
    pub message: String,
}

impl fmt::Display for GhidraScriptUnsupportedClassVersionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Unsupported class version in '{}': {}",
            self.class_file, self.message
        )
    }
}

impl std::error::Error for GhidraScriptUnsupportedClassVersionError {}

// ---------------------------------------------------------------------------
// GhidraScript -- extended with FlatProgramAPI-style methods
// ---------------------------------------------------------------------------

/// A bookmark in the program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BookmarkInfo {
    /// Bookmark type (e.g., "Info", "Warning", "Error", "Analysis").
    pub bookmark_type: String,
    /// The address.
    pub address: String,
    /// Bookmark category.
    pub category: String,
    /// Bookmark comment.
    pub comment: String,
}

/// Comment types in a program listing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CommentType {
    /// Plate comment (appears above the address).
    Plate,
    /// Pre-comment (appears before the code unit).
    Pre,
    /// Post-comment (appears after the code unit).
    Post,
    /// End-of-line comment.
    Eol,
    /// Repeatable comment (appears at all references).
    Repeatable,
}

/// Information about a memory block.
#[derive(Debug, Clone)]
pub struct MemoryBlockInfo {
    /// Block name.
    pub name: String,
    /// Start address (hex string).
    pub start: String,
    /// End address (hex string).
    pub end: String,
    /// Whether the block is readable.
    pub read: bool,
    /// Whether the block is writable.
    pub write: bool,
    /// Whether the block is executable.
    pub execute: bool,
    /// Whether the block is volatile.
    pub volatile: bool,
    /// Whether the block is initialized.
    pub initialized: bool,
}

/// A symbol in the program.
#[derive(Debug, Clone)]
pub struct SymbolInfo {
    /// Symbol name.
    pub name: String,
    /// Symbol address (hex string).
    pub address: String,
    /// Whether this is the primary symbol at its address.
    pub primary: bool,
    /// Symbol namespace path (e.g., "mylib::myns::func").
    pub namespace: String,
    /// Symbol source (e.g., "USER_DEFINED", "IMPORTED", "DEFAULT").
    pub source: String,
}

/// A function in the program.
#[derive(Debug, Clone)]
pub struct FunctionInfo {
    /// Function name.
    pub name: String,
    /// Entry point address (hex string).
    pub entry_point: String,
    /// Whether the function is a thunk.
    pub is_thunk: bool,
    /// Whether the function is external.
    pub is_external: bool,
    /// Function namespace path.
    pub namespace: String,
    /// Calling convention name.
    pub calling_convention: String,
    /// Stack frame size.
    pub stack_frame_size: i64,
    /// Whether the function has a custom storage.
    pub custom_storage: bool,
}

/// An instruction in the program.
#[derive(Debug, Clone)]
pub struct InstructionInfo {
    /// Mnemonic (e.g., "MOV", "ADD", "CALL").
    pub mnemonic: String,
    /// Address (hex string).
    pub address: String,
    /// Instruction length in bytes.
    pub length: usize,
    /// Number of operands.
    pub num_operands: usize,
    /// Flows to next instruction.
    pub flows_to_next: bool,
    /// Whether this is a call instruction.
    pub is_call: bool,
    /// Whether this is a branch instruction.
    pub is_branch: bool,
    /// Whether this is a return instruction.
    pub is_return: bool,
}

/// A data item in the program listing.
#[derive(Debug, Clone)]
pub struct DataInfo {
    /// Data type name (e.g., "dword", "ascii", "pointer").
    pub data_type_name: String,
    /// Address (hex string).
    pub address: String,
    /// Data length in bytes.
    pub length: usize,
    /// The value as a string representation.
    pub value: String,
    /// Whether this is an undefined data item.
    pub is_undefined: bool,
}

/// A reference (xref) in the program.
#[derive(Debug, Clone)]
pub struct ReferenceInfo {
    /// Source address (hex string).
    pub from_address: String,
    /// Destination address (hex string).
    pub to_address: String,
    /// Whether this is a flow reference (call/jump/fall-through).
    pub is_flow: bool,
    /// Reference type description.
    pub ref_type: String,
}

impl GhidraScript {
    // -- Script execution (ported from GhidraScript.execute/cleanup/set) --

    /// Initialize the script with state, then run.
    ///
    /// Ported from `GhidraScript.execute(GhidraState, ...)`.
    pub fn execute(&mut self, run_state: GhidraState) -> Result<(), String> {
        self.state = run_state;
        self.run()
    }

    /// The main run method to be overridden by concrete scripts.
    ///
    /// Ported from the abstract `GhidraScript.run()`.
    pub fn run(&mut self) -> Result<(), String> {
        // Default implementation does nothing; concrete scripts override.
        Ok(())
    }

    /// Cleanup after script execution.
    ///
    /// Ported from `GhidraScript.cleanup(boolean success)`.
    pub fn cleanup(&mut self, _success: bool) {
        // Default implementation does nothing; concrete scripts override.
    }

    /// Get the script category.
    ///
    /// Ported from `GhidraScript.getCategory()`.
    pub fn category(&self) -> Option<&str> {
        self.properties.category.as_deref()
    }

    /// Get the script arguments.
    ///
    /// Ported from `GhidraScript.getScriptArgs()`.
    pub fn script_args(&self) -> &[String] {
        &self.script_args
    }

    /// Set the script arguments.
    ///
    /// Ported from `GhidraScript.setScriptArgs(String[])`.
    pub fn set_script_args(&mut self, args: Vec<String>) {
        self.script_args = args;
    }

    /// Whether the script is running in headless mode.
    ///
    /// Ported from `GhidraScript.isRunningHeadless()`.
    pub fn is_running_headless(&self) -> bool {
        self.headless
    }

    /// Set the headless flag.
    pub fn set_headless(&mut self, headless: bool) {
        self.headless = headless;
    }

    // -- Console output (extended) --

    /// Print a formatted message (like printf).
    ///
    /// Ported from `GhidraScript.printf(String, Object...)`.
    pub fn printf(&mut self, format: &str, args: &[&dyn fmt::Display]) -> String {
        let mut result = format.to_string();
        for arg in args {
            result = result.replacen("{}", &arg.to_string(), 1);
        }
        self.println(result.clone());
        result
    }

    /// Print a blank line.
    ///
    /// Ported from `GhidraScript.println()`.
    pub fn println_blank(&mut self) {
        self.println("");
    }

    /// Print an error message (alias for print_error).
    ///
    /// Ported from `GhidraScript.printerr(String)`.
    pub fn printerr(&mut self, msg: impl Into<String>) {
        self.print_error(msg);
    }

    // -- Navigation (ported from GhidraScript/FlatProgramAPI) --

    /// Navigate to an address.
    ///
    /// Ported from `GhidraScript.goTo(Address)`.
    pub fn go_to(&mut self, address: &str) -> bool {
        self.state.set_current_address(Some(address.to_string()));
        true
    }

    /// Navigate to a symbol.
    ///
    /// Ported from `GhidraScript.goTo(Symbol)`.
    pub fn go_to_symbol(&mut self, symbol: &SymbolInfo) -> bool {
        self.go_to(&symbol.address)
    }

    /// Navigate to a function.
    ///
    /// Ported from `GhidraScript.goTo(Function)`.
    pub fn go_to_function(&mut self, function: &FunctionInfo) -> bool {
        self.go_to(&function.entry_point)
    }

    // -- Display control (ported from GhidraScript) --

    /// Show addresses in the listing.
    ///
    /// Ported from `GhidraScript.show(Address[])`.
    pub fn show_addresses(&mut self, addresses: &[String]) {
        if let Some(first) = addresses.first() {
            self.go_to(first);
        }
    }

    /// Show an address set in the listing.
    ///
    /// Ported from `GhidraScript.show(String, AddressSetView)`.
    pub fn show_address_set(&mut self, _title: &str, addresses: &[String]) {
        self.show_addresses(addresses);
    }

    /// Show a popup message.
    ///
    /// Ported from `GhidraScript.popup(Object)`.
    pub fn popup(&mut self, message: impl Into<String>) {
        let msg = message.into();
        self.output_buffer.push(ScriptMessage {
            level: MessageLevel::Info,
            text: format!("[POPUP] {}", msg),
        });
    }

    /// Set the tool status message.
    ///
    /// Ported from `GhidraScript.setToolStatusMessage(String, boolean)`.
    pub fn set_tool_status_message(
        &mut self,
        msg: impl Into<String>,
        _beep: bool,
    ) -> Result<(), ImproperUseException> {
        let _ = msg.into();
        // In headless mode, this throws ImproperUseException.
        if self.headless {
            return Err(ImproperUseException::new(
                "setToolStatusMessage is not available in headless mode",
            ));
        }
        Ok(())
    }

    // -- Selection and highlight (ported from GhidraScript) --

    /// Set the current selection.
    ///
    /// Ported from `GhidraScript.setCurrentSelection(AddressSetView)`.
    pub fn set_current_selection(&mut self, addresses: &[String]) {
        if addresses.is_empty() {
            self.state.set_current_selection(None);
        } else if addresses.len() >= 2 {
            self.state.set_current_selection(Some(AddressRange {
                start: addresses[0].clone(),
                end: addresses[addresses.len() - 1].clone(),
            }));
        }
    }

    /// Create a selection.
    ///
    /// Ported from `GhidraScript.createSelection(AddressSetView)`.
    pub fn create_selection(&mut self, addresses: &[String]) {
        self.set_current_selection(addresses);
    }

    /// Remove the current selection.
    ///
    /// Ported from `GhidraScript.removeSelection()`.
    pub fn remove_selection(&mut self) {
        self.state.set_current_selection(None);
    }

    /// Set the current highlight.
    ///
    /// Ported from `GhidraScript.setCurrentHighlight(AddressSetView)`.
    pub fn set_current_highlight(&mut self, addresses: &[String]) {
        if addresses.is_empty() {
            self.state.set_current_highlight(None);
        } else if addresses.len() >= 2 {
            self.state.set_current_highlight(Some(AddressRange {
                start: addresses[0].clone(),
                end: addresses[addresses.len() - 1].clone(),
            }));
        }
    }

    /// Create a highlight.
    ///
    /// Ported from `GhidraScript.createHighlight(AddressSetView)`.
    pub fn create_highlight(&mut self, addresses: &[String]) {
        self.set_current_highlight(addresses);
    }

    /// Remove the current highlight.
    ///
    /// Ported from `GhidraScript.removeHighlight()`.
    pub fn remove_highlight(&mut self) {
        self.state.set_current_highlight(None);
    }

    // -- Display background color (ported from GhidraScript) --

    /// Set background color at an address.
    ///
    /// Ported from `GhidraScript.setBackgroundColor(Address, Color)`.
    pub fn set_background_color(
        &mut self,
        _address: &str,
        _color: (u8, u8, u8),
    ) -> Result<(), ImproperUseException> {
        if self.headless {
            return Err(ImproperUseException::new(
                "setBackgroundColor is not available in headless mode",
            ));
        }
        Ok(())
    }

    /// Clear background color at an address.
    ///
    /// Ported from `GhidraScript.clearBackgroundColor(Address)`.
    pub fn clear_background_color(&mut self, _address: &str) -> Result<(), ImproperUseException> {
        if self.headless {
            return Err(ImproperUseException::new(
                "clearBackgroundColor is not available in headless mode",
            ));
        }
        Ok(())
    }

    // -- Comments (ported from FlatProgramAPI) --

    /// Set a plate comment at an address.
    ///
    /// Ported from `FlatProgramAPI.setPlateComment(Address, String)`.
    pub fn set_plate_comment(&mut self, address: &str, comment: &str) -> bool {
        self.comments
            .entry(address.to_string())
            .or_default()
            .push((CommentType::Plate, comment.to_string()));
        true
    }

    /// Set a pre-comment at an address.
    ///
    /// Ported from `FlatProgramAPI.setPreComment(Address, String)`.
    pub fn set_pre_comment(&mut self, address: &str, comment: &str) -> bool {
        self.comments
            .entry(address.to_string())
            .or_default()
            .push((CommentType::Pre, comment.to_string()));
        true
    }

    /// Set a post-comment at an address.
    ///
    /// Ported from `FlatProgramAPI.setPostComment(Address, String)`.
    pub fn set_post_comment(&mut self, address: &str, comment: &str) -> bool {
        self.comments
            .entry(address.to_string())
            .or_default()
            .push((CommentType::Post, comment.to_string()));
        true
    }

    /// Set an end-of-line comment at an address.
    ///
    /// Ported from `FlatProgramAPI.setEOLComment(Address, String)`.
    pub fn set_eol_comment(&mut self, address: &str, comment: &str) -> bool {
        self.comments
            .entry(address.to_string())
            .or_default()
            .push((CommentType::Eol, comment.to_string()));
        true
    }

    /// Set a repeatable comment at an address.
    ///
    /// Ported from `FlatProgramAPI.setRepeatableComment(Address, String)`.
    pub fn set_repeatable_comment(&mut self, address: &str, comment: &str) -> bool {
        self.comments
            .entry(address.to_string())
            .or_default()
            .push((CommentType::Repeatable, comment.to_string()));
        true
    }

    /// Get a plate comment at an address.
    ///
    /// Ported from `FlatProgramAPI.getPlateComment(Address)`.
    pub fn get_plate_comment(&self, address: &str) -> Option<String> {
        self.get_comment(address, CommentType::Plate)
    }

    /// Get a pre-comment at an address.
    ///
    /// Ported from `FlatProgramAPI.getPreComment(Address)`.
    pub fn get_pre_comment(&self, address: &str) -> Option<String> {
        self.get_comment(address, CommentType::Pre)
    }

    /// Get a post-comment at an address.
    ///
    /// Ported from `FlatProgramAPI.getPostComment(Address)`.
    pub fn get_post_comment(&self, address: &str) -> Option<String> {
        self.get_comment(address, CommentType::Post)
    }

    /// Get an end-of-line comment at an address.
    ///
    /// Ported from `FlatProgramAPI.getEOLComment(Address)`.
    pub fn get_eol_comment(&self, address: &str) -> Option<String> {
        self.get_comment(address, CommentType::Eol)
    }

    /// Get a repeatable comment at an address.
    ///
    /// Ported from `FlatProgramAPI.getRepeatableComment(Address)`.
    pub fn get_repeatable_comment(&self, address: &str) -> Option<String> {
        self.get_comment(address, CommentType::Repeatable)
    }

    /// Get a comment of the specified type at an address.
    fn get_comment(&self, address: &str, comment_type: CommentType) -> Option<String> {
        self.comments
            .get(address)
            .and_then(|comments| {
                comments
                    .iter()
                    .find(|(ct, _)| *ct == comment_type)
                    .map(|(_, text)| text.clone())
            })
    }

    // -- Rendered comments (ported from GhidraScript) --

    /// Get the plate comment as rendered (including line breaks).
    ///
    /// Ported from `GhidraScript.getPlateCommentAsRendered(Address)`.
    pub fn get_plate_comment_as_rendered(&self, address: &str) -> Option<String> {
        self.get_plate_comment(address)
    }

    /// Get the pre-comment as rendered.
    ///
    /// Ported from `GhidraScript.getPreCommentAsRendered(Address)`.
    pub fn get_pre_comment_as_rendered(&self, address: &str) -> Option<String> {
        self.get_pre_comment(address)
    }

    /// Get the post-comment as rendered.
    ///
    /// Ported from `GhidraScript.getPostCommentAsRendered(Address)`.
    pub fn get_post_comment_as_rendered(&self, address: &str) -> Option<String> {
        self.get_post_comment(address)
    }

    /// Get the EOL comment as rendered.
    ///
    /// Ported from `GhidraScript.getEOLCommentAsRendered(Address)`.
    pub fn get_eol_comment_as_rendered(&self, address: &str) -> Option<String> {
        self.get_eol_comment(address)
    }

    /// Get the repeatable comment as rendered.
    ///
    /// Ported from `GhidraScript.getRepeatableCommentAsRendered(Address)`.
    pub fn get_repeatable_comment_as_rendered(&self, address: &str) -> Option<String> {
        self.get_repeatable_comment(address)
    }

    // -- Bookmarks (ported from FlatProgramAPI) --

    /// Add a bookmark.
    ///
    /// Ported from `FlatProgramAPI.setBookmark(Address, String, String, String)`.
    pub fn set_bookmark(
        &mut self,
        address: &str,
        bookmark_type: &str,
        category: &str,
        comment: &str,
    ) {
        self.bookmarks.push(BookmarkInfo {
            bookmark_type: bookmark_type.to_string(),
            address: address.to_string(),
            category: category.to_string(),
            comment: comment.to_string(),
        });
    }

    /// Get bookmarks at an address.
    pub fn get_bookmarks_at(&self, address: &str) -> Vec<&BookmarkInfo> {
        self.bookmarks
            .iter()
            .filter(|b| b.address == address)
            .collect()
    }

    /// Get all bookmarks of a given type.
    pub fn get_bookmarks_by_type(&self, bookmark_type: &str) -> Vec<&BookmarkInfo> {
        self.bookmarks
            .iter()
            .filter(|b| b.bookmark_type == bookmark_type)
            .collect()
    }

    // -- Memory blocks (ported from FlatProgramAPI) --

    /// Get a memory block by name.
    ///
    /// Ported from `FlatProgramAPI.getMemoryBlock(String)`.
    pub fn get_memory_block(&self, name: &str) -> Option<&MemoryBlockInfo> {
        self.memory_blocks.iter().find(|b| b.name == name)
    }

    /// Get a memory block by address.
    ///
    /// Ported from `FlatProgramAPI.getMemoryBlock(Address)`.
    pub fn get_memory_block_at(&self, address: &str) -> Option<&MemoryBlockInfo> {
        self.memory_blocks
            .iter()
            .find(|b| address >= b.start.as_str() && address <= b.end.as_str())
    }

    /// Get all memory blocks.
    ///
    /// Ported from `FlatProgramAPI.getMemoryBlocks()`.
    pub fn get_memory_blocks(&self) -> &[MemoryBlockInfo] {
        &self.memory_blocks
    }

    /// Add a memory block.
    pub fn add_memory_block(&mut self, block: MemoryBlockInfo) {
        self.memory_blocks.push(block);
    }

    // -- Symbols (ported from FlatProgramAPI) --

    /// Create a label at an address.
    ///
    /// Ported from `FlatProgramAPI.createLabel(Address, String, boolean)`.
    pub fn create_label(&mut self, address: &str, name: &str, primary: bool) -> SymbolInfo {
        let symbol = SymbolInfo {
            name: name.to_string(),
            address: address.to_string(),
            primary,
            namespace: String::new(),
            source: "USER_DEFINED".to_string(),
        };
        self.symbols.push(symbol.clone());
        symbol
    }

    /// Create a symbol at an address.
    ///
    /// Ported from `FlatProgramAPI.createSymbol(Address, String, boolean)`.
    pub fn create_symbol(
        &mut self,
        address: &str,
        name: &str,
        primary: bool,
        namespace: &str,
    ) -> SymbolInfo {
        let symbol = SymbolInfo {
            name: name.to_string(),
            address: address.to_string(),
            primary,
            namespace: namespace.to_string(),
            source: "USER_DEFINED".to_string(),
        };
        self.symbols.push(symbol.clone());
        symbol
    }

    /// Get the symbol at an address.
    ///
    /// Ported from `FlatProgramAPI.getSymbolAt(Address)`.
    pub fn get_symbol_at(&self, address: &str) -> Option<&SymbolInfo> {
        self.symbols.iter().find(|s| s.address == address)
    }

    /// Get a symbol by name at an address.
    ///
    /// Ported from `FlatProgramAPI.getSymbolAt(Address, String)`.
    pub fn get_symbol_at_name(&self, address: &str, name: &str) -> Option<&SymbolInfo> {
        self.symbols
            .iter()
            .find(|s| s.address == address && s.name == name)
    }

    /// Remove a symbol by name at an address.
    ///
    /// Ported from `FlatProgramAPI.removeSymbol(Address, String)`.
    pub fn remove_symbol(&mut self, address: &str, name: &str) -> bool {
        let len_before = self.symbols.len();
        self.symbols
            .retain(|s| !(s.address == address && s.name == name));
        self.symbols.len() < len_before
    }

    /// Get all symbols with a given name.
    pub fn get_symbols_by_name(&self, name: &str) -> Vec<&SymbolInfo> {
        self.symbols.iter().filter(|s| s.name == name).collect()
    }

    // -- Entry points (ported from FlatProgramAPI) --

    /// Add an entry point.
    ///
    /// Ported from `FlatProgramAPI.addEntryPoint(Address)`.
    pub fn add_entry_point(&mut self, address: &str) {
        if !self.entry_points.contains(&address.to_string()) {
            self.entry_points.push(address.to_string());
        }
    }

    /// Remove an entry point.
    ///
    /// Ported from `FlatProgramAPI.removeEntryPoint(Address)`.
    pub fn remove_entry_point(&mut self, address: &str) {
        self.entry_points.retain(|a| a != address);
    }

    /// Get all entry points.
    pub fn entry_points(&self) -> &[String] {
        &self.entry_points
    }

    // -- Functions (ported from FlatProgramAPI) --

    /// Create a function at an entry point.
    ///
    /// Ported from `FlatProgramAPI.createFunction(Address, String)`.
    pub fn create_function(&mut self, entry_point: &str, name: &str) -> FunctionInfo {
        let func = FunctionInfo {
            name: name.to_string(),
            entry_point: entry_point.to_string(),
            is_thunk: false,
            is_external: false,
            namespace: String::new(),
            calling_convention: "default".to_string(),
            stack_frame_size: 0,
            custom_storage: false,
        };
        self.functions.push(func.clone());
        func
    }

    /// Get a function at an entry point.
    ///
    /// Ported from `FlatProgramAPI.getFunctionAt(Address)`.
    pub fn get_function_at(&self, entry_point: &str) -> Option<&FunctionInfo> {
        self.functions.iter().find(|f| f.entry_point == entry_point)
    }

    /// Get a function containing an address.
    ///
    /// Ported from `FlatProgramAPI.getFunctionContaining(Address)`.
    pub fn get_function_containing(&self, address: &str) -> Option<&FunctionInfo> {
        // In a full implementation, this would check address ranges.
        self.functions.iter().find(|f| f.entry_point == address)
    }

    /// Get a function by name.
    ///
    /// Ported from `FlatProgramAPI.getFunction(String)`.
    pub fn get_function_by_name(&self, name: &str) -> Option<&FunctionInfo> {
        self.functions.iter().find(|f| f.name == name)
    }

    /// Get all functions with a given name (global functions).
    ///
    /// Ported from `FlatProgramAPI.getGlobalFunctions(String)`.
    pub fn get_global_functions(&self, name: &str) -> Vec<&FunctionInfo> {
        self.functions.iter().filter(|f| f.name == name).collect()
    }

    /// Remove a function.
    ///
    /// Ported from `FlatProgramAPI.removeFunction(Function)`.
    pub fn remove_function(&mut self, entry_point: &str) -> bool {
        let len_before = self.functions.len();
        self.functions.retain(|f| f.entry_point != entry_point);
        self.functions.len() < len_before
    }

    /// Get all functions.
    pub fn get_all_functions(&self) -> &[FunctionInfo] {
        &self.functions
    }

    // -- Instructions (ported from FlatProgramAPI) --

    /// Get an instruction at an address.
    ///
    /// Ported from `FlatProgramAPI.getInstructionAt(Address)`.
    pub fn get_instruction_at(&self, address: &str) -> Option<&InstructionInfo> {
        self.instructions.iter().find(|i| i.address == address)
    }

    /// Get an instruction containing an address.
    ///
    /// Ported from `FlatProgramAPI.getInstructionContaining(Address)`.
    pub fn get_instruction_containing(&self, address: &str) -> Option<&InstructionInfo> {
        self.instructions.iter().find(|i| i.address == address)
    }

    /// Add an instruction.
    pub fn add_instruction(&mut self, instruction: InstructionInfo) {
        self.instructions.push(instruction);
    }

    /// Get all instructions.
    pub fn get_all_instructions(&self) -> &[InstructionInfo] {
        &self.instructions
    }

    // -- Data (ported from FlatProgramAPI) --

    /// Get a data item at an address.
    ///
    /// Ported from `FlatProgramAPI.getDataAt(Address)`.
    pub fn get_data_at(&self, address: &str) -> Option<&DataInfo> {
        self.data_items.iter().find(|d| d.address == address)
    }

    /// Get a data item containing an address.
    ///
    /// Ported from `FlatProgramAPI.getDataContaining(Address)`.
    pub fn get_data_containing(&self, address: &str) -> Option<&DataInfo> {
        self.data_items.iter().find(|d| d.address == address)
    }

    /// Add a data item.
    pub fn add_data(&mut self, data: DataInfo) {
        self.data_items.push(data);
    }

    /// Get all data items.
    pub fn get_all_data(&self) -> &[DataInfo] {
        &self.data_items
    }

    // -- References (xrefs) (ported from FlatProgramAPI) --

    /// Get references to an address.
    pub fn get_references_to(&self, address: &str) -> Vec<&ReferenceInfo> {
        self.references
            .iter()
            .filter(|r| r.to_address == address)
            .collect()
    }

    /// Get references from an address.
    pub fn get_references_from(&self, address: &str) -> Vec<&ReferenceInfo> {
        self.references
            .iter()
            .filter(|r| r.from_address == address)
            .collect()
    }

    /// Add a reference.
    pub fn add_reference(&mut self, from: &str, to: &str, is_flow: bool, ref_type: &str) {
        self.references.push(ReferenceInfo {
            from_address: from.to_string(),
            to_address: to.to_string(),
            is_flow,
            ref_type: ref_type.to_string(),
        });
    }

    // -- Disassembly (ported from FlatProgramAPI) --

    /// Disassemble at an address.
    ///
    /// Ported from `FlatProgramAPI.disassemble(Address)`.
    pub fn disassemble(&mut self, address: &str) -> bool {
        if !self.disassembled_addresses.contains(&address.to_string()) {
            self.disassembled_addresses.push(address.to_string());
        }
        true
    }

    // -- Hex conversion utilities (ported from GhidraScript) --

    /// Convert a byte to hex string.
    ///
    /// Ported from `GhidraScript.toHexString(byte, boolean, boolean)`.
    pub fn to_hex_string_byte(b: u8, zeropad: bool, header: bool) -> String {
        if zeropad {
            if header {
                format!("0x{:02X}", b)
            } else {
                format!("{:02X}", b)
            }
        } else if header {
            format!("0x{:X}", b)
        } else {
            format!("{:X}", b)
        }
    }

    /// Convert a u16 to hex string.
    ///
    /// Ported from `GhidraScript.toHexString(short, boolean, boolean)`.
    pub fn to_hex_string_short(s: u16, zeropad: bool, header: bool) -> String {
        if zeropad {
            if header {
                format!("0x{:04X}", s)
            } else {
                format!("{:04X}", s)
            }
        } else if header {
            format!("0x{:X}", s)
        } else {
            format!("{:X}", s)
        }
    }

    /// Convert a u32 to hex string.
    ///
    /// Ported from `GhidraScript.toHexString(int, boolean, boolean)`.
    pub fn to_hex_string_int(i: u32, zeropad: bool, header: bool) -> String {
        if zeropad {
            if header {
                format!("0x{:08X}", i)
            } else {
                format!("{:08X}", i)
            }
        } else if header {
            format!("0x{:X}", i)
        } else {
            format!("{:X}", i)
        }
    }

    /// Convert a u64 to hex string.
    ///
    /// Ported from `GhidraScript.toHexString(long, boolean, boolean)`.
    pub fn to_hex_string_long(l: u64, zeropad: bool, header: bool) -> String {
        if zeropad {
            if header {
                format!("0x{:016X}", l)
            } else {
                format!("{:016X}", l)
            }
        } else if header {
            format!("0x{:X}", l)
        } else {
            format!("{:X}", l)
        }
    }

    // -- Demangling (ported from GhidraScript) --

    /// Get a demangled name from a mangled name.
    ///
    /// Ported from `GhidraScript.getDemangled(String)`.
    pub fn get_demangled(&self, mangled: &str) -> Option<String> {
        // Placeholder: in a full implementation, this would use the demangler.
        if mangled.starts_with("_Z") {
            Some(mangled[2..].to_string())
        } else {
            None
        }
    }

    // -- Properties (from properties file) --

    /// Load properties from a source file path.
    ///
    /// Ported from `GhidraScript.setPropertiesFile(File)`.
    pub fn set_properties_from_source(&mut self, source: &str) {
        self.properties = GhidraScriptProperties::from_source(source);
    }

    /// Get the script properties.
    pub fn properties(&self) -> &GhidraScriptProperties {
        &self.properties
    }

    /// Get a mutable reference to the script properties.
    pub fn properties_mut(&mut self) -> &mut GhidraScriptProperties {
        &mut self.properties
    }
}

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

    #[test]
    fn test_groovy_script_language() {
        assert_eq!(format!("{}", ScriptLanguage::Groovy), "Groovy");
        let groovy = GhidraScriptProvider::groovy();
        assert_eq!(groovy.language, ScriptLanguage::Groovy);
        assert!(groovy.can_handle("test.groovy"));
    }

    #[test]
    fn test_script_execution() {
        let mut script = GhidraScript::new("ExecTest");
        let mut state = GhidraState::new();
        state.current_program = Some("test.bin".to_string());
        let result = script.execute(state);
        assert!(result.is_ok());
        assert_eq!(script.current_program(), Some("test.bin"));
    }

    #[test]
    fn test_script_args() {
        let mut script = GhidraScript::new("ArgTest");
        assert!(script.script_args().is_empty());
        script.set_script_args(vec!["--verbose".to_string(), "input.bin".to_string()]);
        assert_eq!(script.script_args().len(), 2);
    }

    #[test]
    fn test_script_headless() {
        let mut script = GhidraScript::new("HeadlessTest");
        assert!(!script.is_running_headless());
        script.set_headless(true);
        assert!(script.is_running_headless());
    }

    #[test]
    fn test_comments() {
        let mut script = GhidraScript::new("CommentTest");

        script.set_plate_comment("0x1000", "Main function");
        script.set_eol_comment("0x1000", "initialize registers");
        script.set_repeatable_comment("0x1000", "entry point");

        assert_eq!(script.get_plate_comment("0x1000"), Some("Main function".to_string()));
        assert_eq!(script.get_eol_comment("0x1000"), Some("initialize registers".to_string()));
        assert_eq!(script.get_repeatable_comment("0x1000"), Some("entry point".to_string()));
        assert!(script.get_pre_comment("0x1000").is_none());
        assert!(script.get_plate_comment("0x2000").is_none());
    }

    #[test]
    fn test_bookmarks() {
        let mut script = GhidraScript::new("BookmarkTest");
        script.set_bookmark("0x1000", "Info", "Analysis", "Interesting function");
        script.set_bookmark("0x2000", "Warning", "Security", "Potential vuln");

        assert_eq!(script.get_bookmarks_at("0x1000").len(), 1);
        assert_eq!(script.get_bookmarks_by_type("Warning").len(), 1);
        assert!(script.get_bookmarks_at("0x3000").is_empty());
    }

    #[test]
    fn test_memory_blocks() {
        let mut script = GhidraScript::new("MemoryTest");
        script.add_memory_block(MemoryBlockInfo {
            name: ".text".to_string(),
            start: "0x00400000".to_string(),
            end: "0x004FFFFF".to_string(),
            read: true,
            write: false,
            execute: true,
            volatile: false,
            initialized: true,
        });

        assert!(script.get_memory_block(".text").is_some());
        assert!(script.get_memory_block(".data").is_none());
        assert_eq!(script.get_memory_blocks().len(), 1);
    }

    #[test]
    fn test_symbols() {
        let mut script = GhidraScript::new("SymbolTest");
        script.create_label("0x1000", "main", true);
        script.create_symbol("0x2000", "helper", false, "mylib");

        assert!(script.get_symbol_at("0x1000").is_some());
        assert_eq!(script.get_symbol_at("0x1000").unwrap().name, "main");
        assert!(script.get_symbol_at_name("0x2000", "helper").is_some());
        assert!(script.remove_symbol("0x2000", "helper"));
        assert!(script.get_symbol_at("0x2000").is_none());
    }

    #[test]
    fn test_entry_points() {
        let mut script = GhidraScript::new("EntryPointTest");
        script.add_entry_point("0x1000");
        script.add_entry_point("0x2000");
        script.add_entry_point("0x1000"); // duplicate
        assert_eq!(script.entry_points().len(), 2);

        script.remove_entry_point("0x1000");
        assert_eq!(script.entry_points().len(), 1);
    }

    #[test]
    fn test_functions() {
        let mut script = GhidraScript::new("FuncTest");
        script.create_function("0x1000", "main");
        script.create_function("0x2000", "helper");

        assert!(script.get_function_at("0x1000").is_some());
        assert!(script.get_function_by_name("helper").is_some());
        assert!(script.get_function_containing("0x1000").is_some());
        assert_eq!(script.get_global_functions("main").len(), 1);
        assert!(script.remove_function("0x2000"));
        assert!(script.get_function_at("0x2000").is_none());
    }

    #[test]
    fn test_instructions() {
        let mut script = GhidraScript::new("InstrTest");
        script.add_instruction(InstructionInfo {
            mnemonic: "MOV".to_string(),
            address: "0x1000".to_string(),
            length: 3,
            num_operands: 2,
            flows_to_next: true,
            is_call: false,
            is_branch: false,
            is_return: false,
        });

        assert!(script.get_instruction_at("0x1000").is_some());
        assert_eq!(script.get_instruction_at("0x1000").unwrap().mnemonic, "MOV");
    }

    #[test]
    fn test_data_items() {
        let mut script = GhidraScript::new("DataTest");
        script.add_data(DataInfo {
            data_type_name: "dword".to_string(),
            address: "0x3000".to_string(),
            length: 4,
            value: "0x12345678".to_string(),
            is_undefined: false,
        });

        assert!(script.get_data_at("0x3000").is_some());
        assert!(script.get_data_at("0x4000").is_none());
    }

    #[test]
    fn test_references() {
        let mut script = GhidraScript::new("RefTest");
        script.add_reference("0x1000", "0x2000", true, "CALL");
        script.add_reference("0x1004", "0x2000", false, "DATA");

        assert_eq!(script.get_references_to("0x2000").len(), 2);
        assert_eq!(script.get_references_from("0x1000").len(), 1);
    }

    #[test]
    fn test_disassemble() {
        let mut script = GhidraScript::new("DisasmTest");
        assert!(script.disassemble("0x1000"));
        assert!(script.disassemble("0x1000")); // idempotent
    }

    #[test]
    fn test_hex_strings() {
        assert_eq!(GhidraScript::to_hex_string_byte(0xFF, true, true), "0xFF");
        assert_eq!(GhidraScript::to_hex_string_byte(0x0A, true, false), "0A");
        assert_eq!(GhidraScript::to_hex_string_int(0x12345678, true, true), "0x12345678");
        assert_eq!(GhidraScript::to_hex_string_long(0x123456789ABCDEF0, true, true), "0x123456789ABCDEF0");
    }

    #[test]
    fn test_navigation() {
        let mut script = GhidraScript::new("NavTest");
        assert!(script.go_to("0x401000"));
        assert_eq!(script.current_address(), Some("0x401000"));

        script.go_to_symbol(&SymbolInfo {
            name: "main".to_string(),
            address: "0x401100".to_string(),
            primary: true,
            namespace: String::new(),
            source: "USER_DEFINED".to_string(),
        });
        assert_eq!(script.current_address(), Some("0x401100"));
    }

    #[test]
    fn test_popup() {
        let mut script = GhidraScript::new("PopupTest");
        script.popup("Hello!");
        assert!(script.output().iter().any(|m| m.text.contains("[POPUP] Hello!")));
    }

    #[test]
    fn test_improper_use_exception() {
        let err = ImproperUseException::new("headless mode only");
        assert!(format!("{}", err).contains("headless"));
    }

    #[test]
    fn test_unsupported_class_version_error() {
        let err = GhidraScriptUnsupportedClassVersionError {
            class_file: "MyScript.class".to_string(),
            message: "Unsupported major.minor version 52.0".to_string(),
        };
        assert!(format!("{}", err).contains("MyScript.class"));
    }

    #[test]
    fn test_constants() {
        assert_eq!(constants::DEFAULT_SCRIPT_NAME, "NewScript");
        assert_eq!(constants::USER_SCRIPTS_DIR_PROPERTY, "ghidra.user.scripts.dir");
        assert_eq!(constants::METADATA.len(), 7);
    }

    #[test]
    fn test_provider_create_new_script() {
        let java = GhidraScriptProvider::java();
        let script = java.create_new_script("Analysis");
        assert!(script.contains("@category Analysis"));
        assert!(script.contains("extends GhidraScript"));

        let py = GhidraScriptProvider::python();
        let script = py.create_new_script("");
        assert!(script.contains("@category _NEW_"));
        assert!(script.contains("#"));
    }

    #[test]
    fn test_provider_get_script_instance() {
        let java = GhidraScriptProvider::java();
        let source = "// @author Test\n// @category Analysis\npublic class Test {}";
        let result = java.get_script_instance(source);
        assert!(result.is_ok());
        let script = result.unwrap();
        assert_eq!(script.properties().author, Some("Test".to_string()));
        assert_eq!(script.properties().category, Some("Analysis".to_string()));
    }

    #[test]
    fn test_set_properties_from_source() {
        let mut script = GhidraScript::new("PropTest");
        script.set_properties_from_source("// @author Alice\n// @category Utilities");
        assert_eq!(script.properties().author, Some("Alice".to_string()));
        assert_eq!(script.properties().category, Some("Utilities".to_string()));
    }
}
