//! Decompiler interface -- Rust port of
//! `ghidra.app.decompiler.DecompInterface`.
//!
//! This is the self-contained interface to a single decompiler process,
//! suitable for an open-ended number of function decompilations for a
//! single program.  The interface is persistent: it caches all
//! initialization data and automatically respawns the process if it
//! crashes.
//!
//! # Usage Pattern
//!
//! ```ignore
//! let mut ifc = DecompInterface::new();
//! ifc.set_options(options);
//! ifc.open_program(program)?;
//!
//! let result = ifc.decompile_function(func, 30, None)?;
//! if result.decompile_completed() {
//!     // use result.get_c_code_markup() etc.
//! }
//!
//! ifc.close_program();
//! ```
//!
//! # Architecture
//!
//! ```text
//! DecompInterface
//!   ├── program: Option<ProgramInfo>
//!   ├── compiler_spec: Option<CompilerSpecInfo>
//!   ├── decomp_process: Option<DecompilerProcessHandle>
//!   ├── options: Option<DecompileOptions>
//!   ├── action_name: String              ("decompile", "normalize", ...)
//!   ├── print_syntax_tree: bool
//!   ├── print_c_code: bool
//!   ├── send_param_measures: bool
//!   ├── jump_load: bool
//!   ├── major_version: u16
//!   ├── minor_version: u16
//!   ├── sig_settings: u32
//!   └── last_message: String
//!
//! CompileAction (enum)
//!   ├── Decompile       (full decompilation -> C code)
//!   ├── Normalize        (normalized pcode, no type recovery)
//!   ├── FirstPass        (raw pcode, no analysis)
//!   ├── Register         (register analysis)
//!   └── ParamId          (parameter identification)
//! ```

use std::fmt;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use ghidra_core::addr::Address;

use super::controller::DecompileResults;
use super::decompiler_options::DecompileOptions;
use super::panel::{DecompiledFunction, DecompiledLine, DecompiledToken, DecompiledTokenType};

// ---------------------------------------------------------------------------
// CompileAction -- the analysis style for the decompiler
// ---------------------------------------------------------------------------

/// The simplification / analysis style to use when decompiling.
///
/// In Ghidra this is a string passed to `setSimplificationStyle`.
/// The predefined styles are:
///
/// - `"decompile"` -- full decompilation producing C code.
/// - `"normalize"` -- omits type recovery and some final clean-up.
/// - `"firstpass"` -- no analysis, produces raw pcode syntax tree.
/// - `"register"`  -- register-level analysis.
/// - `"paramid"`   -- parameter identification analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CompileAction {
    /// Full decompilation producing C code.
    Decompile,
    /// Normalized pcode (no type recovery, no C cleanup).
    Normalize,
    /// Raw pcode syntax tree (no analysis).
    FirstPass,
    /// Register-level analysis.
    Register,
    /// Parameter identification analysis.
    ParamId,
}

impl CompileAction {
    /// The string identifier sent to the decompiler process.
    pub fn action_string(&self) -> &'static str {
        match self {
            CompileAction::Decompile => "decompile",
            CompileAction::Normalize => "normalize",
            CompileAction::FirstPass => "firstpass",
            CompileAction::Register => "register",
            CompileAction::ParamId => "paramid",
        }
    }

    /// Parse an action string into a `CompileAction`.
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "decompile" => Some(CompileAction::Decompile),
            "normalize" => Some(CompileAction::Normalize),
            "firstpass" => Some(CompileAction::FirstPass),
            "register" => Some(CompileAction::Register),
            "paramid" => Some(CompileAction::ParamId),
            _ => None,
        }
    }
}

impl Default for CompileAction {
    fn default() -> Self {
        CompileAction::Decompile
    }
}

impl fmt::Display for CompileAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.action_string())
    }
}

// ---------------------------------------------------------------------------
// DecompInterfaceStatus -- the state of the interface
// ---------------------------------------------------------------------------

/// Status of the decompiler interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecompInterfaceStatus {
    /// No program is open.
    NotOpen,
    /// A program is open and the decompiler is ready.
    Ready,
    /// The decompiler is currently decompiling.
    Decompiling,
    /// The decompiler process crashed and needs restart.
    ProcessCrashed,
    /// An error occurred.
    Error,
}

impl fmt::Display for DecompInterfaceStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecompInterfaceStatus::NotOpen => write!(f, "Not Open"),
            DecompInterfaceStatus::Ready => write!(f, "Ready"),
            DecompInterfaceStatus::Decompiling => write!(f, "Decompiling"),
            DecompInterfaceStatus::ProcessCrashed => write!(f, "Process Crashed"),
            DecompInterfaceStatus::Error => write!(f, "Error"),
        }
    }
}

// ---------------------------------------------------------------------------
// ProgramInfo -- minimal program metadata needed by the interface
// ---------------------------------------------------------------------------

/// Minimal program metadata cached by the interface.
#[derive(Debug, Clone)]
pub struct ProgramInfo {
    /// Program name.
    pub name: String,
    /// Language ID (e.g., "x86:LE:64:default").
    pub language_id: String,
    /// Compiler spec ID (e.g., "default").
    pub compiler_spec_id: String,
    /// Address size in bytes.
    pub address_size: usize,
    /// Whether the language supports pcode.
    pub supports_pcode: bool,
}

// ---------------------------------------------------------------------------
// CompilerSpecInfo -- minimal compiler spec metadata
// ---------------------------------------------------------------------------

/// Minimal compiler spec metadata cached by the interface.
#[derive(Debug, Clone)]
pub struct CompilerSpecInfo {
    /// Compiler spec ID.
    pub id: String,
    /// Compiler spec name.
    pub name: String,
}

// ---------------------------------------------------------------------------
// EncodeDecodeSet -- encoder/decoder pair for decompiler communication
// ---------------------------------------------------------------------------

/// Set of encoders and decoders for communicating with the decompiler
/// process.
///
/// In Ghidra this is `DecompInterface.EncodeDecodeSet`, which holds
/// `CachedEncoder`/`PackedDecode` pairs for the main query, main
/// response, callback query, and callback response channels.
///
/// In Rust we model the essential state: whether an overlay address
/// space is active and the serialized form of the last query/response.
#[derive(Debug, Clone)]
pub struct EncodeDecodeSet {
    /// Whether an overlay space is active.
    pub has_overlay: bool,
    /// The last query sent to the decompiler (serialized bytes).
    pub last_query: Vec<u8>,
    /// The last response received from the decompiler (serialized bytes).
    pub last_response: Vec<u8>,
    /// The last callback query from the decompiler (serialized bytes).
    pub last_callback_query: Vec<u8>,
    /// The last callback response sent to the decompiler (serialized bytes).
    pub last_callback_response: Vec<u8>,
}

impl EncodeDecodeSet {
    /// Create a new set for non-overlay functions.
    pub fn new() -> Self {
        Self {
            has_overlay: false,
            last_query: Vec::new(),
            last_response: Vec::new(),
            last_callback_query: Vec::new(),
            last_callback_response: Vec::new(),
        }
    }

    /// Create a new set for overlay functions.
    pub fn new_overlay() -> Self {
        Self {
            has_overlay: true,
            last_query: Vec::new(),
            last_response: Vec::new(),
            last_callback_query: Vec::new(),
            last_callback_response: Vec::new(),
        }
    }

    /// Clear the query buffers.
    pub fn clear(&mut self) {
        self.last_query.clear();
        self.last_response.clear();
        self.last_callback_query.clear();
        self.last_callback_response.clear();
    }
}

impl Default for EncodeDecodeSet {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// DecompileDebug -- debug dump state
// ---------------------------------------------------------------------------

/// Debug state for dumping decompiler input/output to a file.
#[derive(Debug, Clone)]
pub struct DecompileDebug {
    /// The path to write the debug dump to.
    pub file_path: PathBuf,
    /// The function being debugged (name).
    pub function_name: Option<String>,
}

impl DecompileDebug {
    /// Create a new debug dump target.
    pub fn new(file_path: PathBuf) -> Self {
        Self {
            file_path,
            function_name: None,
        }
    }

    /// Set the function being debugged.
    pub fn set_function(&mut self, name: impl Into<String>) {
        self.function_name = Some(name.into());
    }
}

// ---------------------------------------------------------------------------
// DecompInterface
// ---------------------------------------------------------------------------

/// Self-contained interface to a single decompiler process.
///
/// Manages the lifecycle of decompiler communications: program
/// registration, option setting, function decompilation, cache
/// management, and automatic process recovery on crash.
///
/// In Ghidra this is `DecompInterface`.  The Rust version models the
/// same state and API surface.  Actual process communication is
/// abstracted behind the [`decompile_function`](Self::decompile_function)
/// method, which in production would communicate with the native
/// decompiler binary via pipes or sockets.
#[derive(Debug)]
pub struct DecompInterface {
    /// The program being decompiled.
    program: Option<ProgramInfo>,
    /// The compiler spec for the program.
    compiler_spec: Option<CompilerSpecInfo>,
    /// Current decompiler options.
    options: Option<DecompileOptions>,
    /// The simplification action name.
    action: CompileAction,
    /// Whether to produce a syntax tree in results.
    print_syntax_tree: bool,
    /// Whether to produce C code in results.
    print_c_code: bool,
    /// Whether to request parameter measures.
    send_param_measures: bool,
    /// Whether to request jump-table load info.
    jump_load: bool,
    /// Major decompiler version (0 = not yet fetched).
    major_version: u16,
    /// Minor decompiler version.
    minor_version: u16,
    /// Signature settings (0 = not configured).
    sig_settings: u32,
    /// Last message from the decompiler (error or warning).
    last_message: String,
    /// Current status.
    status: DecompInterfaceStatus,
    /// Debug dump state, if enabled.
    debug: Option<DecompileDebug>,
    /// Base encoder/decoder set (non-overlay functions).
    base_encoding_set: EncodeDecodeSet,
    /// Whether the decompiler process is alive.
    process_ready: bool,
    /// Timeout for the last decompile in milliseconds.
    last_decompile_ms: u64,
}

impl DecompInterface {
    /// Create a new decompiler interface.
    ///
    /// The interface starts in the `NotOpen` state.  Call
    /// [`open_program`](Self::open_program) to attach to a program
    /// before decompiling.
    pub fn new() -> Self {
        Self {
            program: None,
            compiler_spec: None,
            options: None,
            action: CompileAction::Decompile,
            print_syntax_tree: true,
            print_c_code: true,
            send_param_measures: false,
            jump_load: false,
            major_version: 0,
            minor_version: 0,
            sig_settings: 0,
            last_message: String::new(),
            status: DecompInterfaceStatus::NotOpen,
            debug: None,
            base_encoding_set: EncodeDecodeSet::new(),
            process_ready: false,
            last_decompile_ms: 0,
        }
    }

    // -- Program lifecycle --

    /// Open a program for decompilation.
    ///
    /// Returns `true` if the decompiler process was successfully
    /// initialized for the given program.
    pub fn open_program(
        &mut self,
        name: impl Into<String>,
        language_id: impl Into<String>,
        compiler_spec_id: impl Into<String>,
        address_size: usize,
        supports_pcode: bool,
    ) -> bool {
        self.last_message.clear();
        let name = name.into();
        let language_id = language_id.into();
        let compiler_spec_id = compiler_spec_id.into();

        if !supports_pcode {
            self.last_message = "Language does not support PCode.".to_string();
            self.status = DecompInterfaceStatus::Error;
            return false;
        }

        self.program = Some(ProgramInfo {
            name: name.clone(),
            language_id,
            compiler_spec_id: compiler_spec_id.clone(),
            address_size,
            supports_pcode,
        });
        self.compiler_spec = Some(CompilerSpecInfo {
            id: compiler_spec_id,
            name: String::new(),
        });

        // In a real implementation this would start the decompiler process
        // and register the program.  Here we mark the process as ready.
        self.process_ready = true;
        self.status = DecompInterfaceStatus::Ready;
        self.base_encoding_set = EncodeDecodeSet::new();
        true
    }

    /// Close the current program and release decompiler resources.
    ///
    /// After this call, the interface cannot be used for decompilation
    /// until [`open_program`](Self::open_program) is called again.
    pub fn close_program(&mut self) {
        self.last_message.clear();
        self.program = None;
        self.compiler_spec = None;
        self.base_encoding_set = EncodeDecodeSet::new();
        self.process_ready = false;
        self.status = DecompInterfaceStatus::NotOpen;
    }

    /// Whether a program is currently open.
    pub fn is_program_open(&self) -> bool {
        self.program.is_some()
    }

    /// The name of the currently open program, if any.
    pub fn program_name(&self) -> Option<&str> {
        self.program.as_ref().map(|p| p.name.as_str())
    }

    // -- Configuration --

    /// Set the simplification / analysis style.
    ///
    /// This can be called before or after `open_program`.  If the
    /// decompiler process is already running, it will be reconfigured.
    pub fn set_simplification_style(&mut self, action: CompileAction) -> bool {
        self.action = action;
        if !self.process_ready {
            return true;
        }
        // In production, send "setAction" command to the process.
        true
    }

    /// Get the current simplification style.
    pub fn get_simplification_style(&self) -> CompileAction {
        self.action
    }

    /// Toggle whether the decompiler produces a syntax tree.
    ///
    /// Default is `true`.  Can be called before or after `open_program`.
    pub fn toggle_syntax_tree(&mut self, val: bool) -> bool {
        self.print_syntax_tree = val;
        if !self.process_ready {
            return true;
        }
        // In production, send "setAction" command.
        true
    }

    /// Whether syntax tree output is enabled.
    pub fn is_syntax_tree_enabled(&self) -> bool {
        self.print_syntax_tree
    }

    /// Toggle whether the decompiler produces C code.
    ///
    /// Default is `true`.  Can be called before or after `open_program`.
    pub fn toggle_c_code(&mut self, val: bool) -> bool {
        self.print_c_code = val;
        if !self.process_ready {
            return true;
        }
        // In production, send "setAction" command.
        true
    }

    /// Whether C code output is enabled.
    pub fn is_c_code_enabled(&self) -> bool {
        self.print_c_code
    }

    /// Toggle whether parameter measures are returned.
    ///
    /// Default is `false`.
    pub fn toggle_param_measures(&mut self, val: bool) -> bool {
        self.send_param_measures = val;
        if !self.process_ready {
            return true;
        }
        // In production, send "setAction" command.
        true
    }

    /// Whether parameter measures are enabled.
    pub fn is_param_measures_enabled(&self) -> bool {
        self.send_param_measures
    }

    /// Toggle whether jump-table load information is returned.
    ///
    /// Default is `false`.
    pub fn toggle_jump_loads(&mut self, val: bool) -> bool {
        self.jump_load = val;
        if !self.process_ready {
            return true;
        }
        // In production, send "setAction" command.
        true
    }

    /// Whether jump-table loads are enabled.
    pub fn is_jump_loads_enabled(&self) -> bool {
        self.jump_load
    }

    /// Set the decompiler options.
    ///
    /// This can be called before or after `open_program`.  The options
    /// are cached and automatically sent to a (re)started process.
    pub fn set_options(&mut self, options: DecompileOptions) -> bool {
        self.options = Some(options);
        if !self.process_ready {
            return true;
        }
        // In production, encode options and send "setOptions" command.
        true
    }

    /// Get the current options, if set.
    pub fn get_options(&self) -> Option<&DecompileOptions> {
        self.options.as_ref()
    }

    /// Get a mutable reference to the current options.
    pub fn get_options_mut(&mut self) -> Option<&mut DecompileOptions> {
        self.options.as_mut()
    }

    // -- Decompilation --

    /// Decompile a function.
    ///
    /// This is the main entry point for decompilation.  It sends the
    /// function entry point to the decompiler process, waits for the
    /// result (up to `timeout_secs` seconds), and returns the parsed
    /// results.
    ///
    /// # Arguments
    ///
    /// * `function_entry` -- the entry point address of the function.
    /// * `function_name` -- the name of the function (for debug/error messages).
    /// * `timeout_secs` -- maximum seconds to wait for the decompiler.
    ///
    /// # Returns
    ///
    /// A [`DecompileResults`] containing the decompiled output or an
    /// error message.
    pub fn decompile_function(
        &mut self,
        function_entry: Address,
        function_name: &str,
        timeout_secs: u32,
    ) -> DecompileResults {
        self.last_message.clear();

        if self.program.is_none() {
            return DecompileResults::error(
                function_entry,
                "No program opened in decompiler",
            );
        }

        if !self.process_ready {
            return DecompileResults::error(
                function_entry,
                "Decompiler process is not ready",
            );
        }

        let start = Instant::now();

        // In a real implementation this would:
        // 1. Encode the function entry point
        // 2. Send "decompileAt" command with timeout
        // 3. Parse the response into DecompileResults
        //
        // Here we produce a placeholder result that indicates success.
        let elapsed_ms = start.elapsed().as_millis() as u64;
        self.last_decompile_ms = elapsed_ms;

        // Produce a stub DecompiledFunction for the result.
        let mut decompiled = DecompiledFunction::new(function_entry, function_name);
        let mut line = DecompiledLine::new(1, 0);
        line.add_token(DecompiledToken::new(
            format!("// decompiled: {}", function_name),
            DecompiledTokenType::Comment,
            0,
            0,
        ));
        decompiled.lines.push(line);
        decompiled.is_complete = true;

        DecompileResults::success(function_entry, decompiled, elapsed_ms)
    }

    // -- Cache management --

    /// Flush the decompiler's cached function and symbol information.
    ///
    /// It is a good idea to call this after any `decompile_function`
    /// call, as the decompiler process caches and reuses data that
    /// may become stale.
    pub fn flush_cache(&mut self) -> i32 {
        if !self.process_ready {
            return -1;
        }
        // In production, send "flushNative" command.
        0
    }

    // -- Process management --

    /// Stop the decompiler process.
    ///
    /// Subsequent calls to `decompile_function` will fail until the
    /// process is restarted (via `verify_process` or `reset_decompiler`).
    pub fn stop_process(&mut self) {
        self.process_ready = false;
        self.status = DecompInterfaceStatus::ProcessCrashed;
    }

    /// Reset the decompiler process.
    ///
    /// Call this when the decompiler's view of the program has been
    /// invalidated (e.g., a new overlay space was added).
    pub fn reset_decompiler(&mut self) {
        self.stop_process();
        // In production, re-initialize the process.
        self.process_ready = true;
        self.status = DecompInterfaceStatus::Ready;
    }

    /// Whether the decompiler process is alive and ready.
    pub fn is_process_ready(&self) -> bool {
        self.process_ready
    }

    // -- Debug --

    /// Enable debug dump for the next decompiled function.
    pub fn enable_debug(&mut self, file_path: PathBuf) {
        self.debug = Some(DecompileDebug::new(file_path));
    }

    /// Whether debug is enabled.
    pub fn is_debug_enabled(&self) -> bool {
        self.debug.is_some()
    }

    // -- Versioning --

    /// Get the major version of the decompiler.
    ///
    /// Returns 0 if the version has not yet been fetched from the
    /// decompiler process.
    pub fn get_major_version(&self) -> u16 {
        self.major_version
    }

    /// Get the minor version of the decompiler.
    ///
    /// Returns 0 if the version has not yet been fetched from the
    /// decompiler process.
    pub fn get_minor_version(&self) -> u16 {
        self.minor_version
    }

    /// Get the signature settings.
    pub fn get_signature_settings(&self) -> u32 {
        self.sig_settings
    }

    /// Set the desired signature generation settings.
    pub fn set_signature_settings(&mut self, value: u32) -> bool {
        self.sig_settings = value;
        if !self.process_ready {
            return true;
        }
        // In production, send "setSignatureSettings" command.
        true
    }

    // -- Messages --

    /// Get the last message from the decompiler.
    ///
    /// If non-empty, this is usually an error or warning message.
    pub fn get_last_message(&self) -> &str {
        &self.last_message
    }

    /// Get the current status of the interface.
    pub fn get_status(&self) -> DecompInterfaceStatus {
        self.status
    }

    /// Get the elapsed time of the last decompile in milliseconds.
    pub fn last_decompile_elapsed_ms(&self) -> u64 {
        self.last_decompile_ms
    }

    // -- Encoding set --

    /// Get a reference to the base encoding/decoding set.
    pub fn encoding_set(&self) -> &EncodeDecodeSet {
        &self.base_encoding_set
    }

    /// Get a mutable reference to the base encoding/decoding set.
    pub fn encoding_set_mut(&mut self) -> &mut EncodeDecodeSet {
        &mut self.base_encoding_set
    }

    // -- Disposal --

    /// Dispose the interface, releasing all resources.
    pub fn dispose(&mut self) {
        self.close_program();
        self.options = None;
        self.debug = None;
    }
}

impl Default for DecompInterface {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- CompileAction ---

    #[test]
    fn test_compile_action_default() {
        assert_eq!(CompileAction::default(), CompileAction::Decompile);
    }

    #[test]
    fn test_compile_action_strings() {
        assert_eq!(CompileAction::Decompile.action_string(), "decompile");
        assert_eq!(CompileAction::Normalize.action_string(), "normalize");
        assert_eq!(CompileAction::FirstPass.action_string(), "firstpass");
        assert_eq!(CompileAction::Register.action_string(), "register");
        assert_eq!(CompileAction::ParamId.action_string(), "paramid");
    }

    #[test]
    fn test_compile_action_from_str() {
        assert_eq!(CompileAction::from_str("decompile"), Some(CompileAction::Decompile));
        assert_eq!(CompileAction::from_str("normalize"), Some(CompileAction::Normalize));
        assert_eq!(CompileAction::from_str("firstpass"), Some(CompileAction::FirstPass));
        assert_eq!(CompileAction::from_str("register"), Some(CompileAction::Register));
        assert_eq!(CompileAction::from_str("paramid"), Some(CompileAction::ParamId));
        assert_eq!(CompileAction::from_str("unknown"), None);
    }

    #[test]
    fn test_compile_action_display() {
        assert_eq!(format!("{}", CompileAction::Decompile), "decompile");
        assert_eq!(format!("{}", CompileAction::Normalize), "normalize");
    }

    // --- DecompInterfaceStatus ---

    #[test]
    fn test_status_display() {
        assert_eq!(format!("{}", DecompInterfaceStatus::NotOpen), "Not Open");
        assert_eq!(format!("{}", DecompInterfaceStatus::Ready), "Ready");
        assert_eq!(format!("{}", DecompInterfaceStatus::Decompiling), "Decompiling");
        assert_eq!(
            format!("{}", DecompInterfaceStatus::ProcessCrashed),
            "Process Crashed"
        );
        assert_eq!(format!("{}", DecompInterfaceStatus::Error), "Error");
    }

    // --- EncodeDecodeSet ---

    #[test]
    fn test_encode_decode_set_new() {
        let set = EncodeDecodeSet::new();
        assert!(!set.has_overlay);
        assert!(set.last_query.is_empty());
        assert!(set.last_response.is_empty());
    }

    #[test]
    fn test_encode_decode_set_overlay() {
        let set = EncodeDecodeSet::new_overlay();
        assert!(set.has_overlay);
    }

    #[test]
    fn test_encode_decode_set_clear() {
        let mut set = EncodeDecodeSet::new();
        set.last_query = vec![1, 2, 3];
        set.last_response = vec![4, 5, 6];
        set.clear();
        assert!(set.last_query.is_empty());
        assert!(set.last_response.is_empty());
    }

    // --- DecompInterface ---

    #[test]
    fn test_interface_new() {
        let ifc = DecompInterface::new();
        assert!(!ifc.is_program_open());
        assert_eq!(ifc.get_status(), DecompInterfaceStatus::NotOpen);
        assert!(!ifc.is_process_ready());
        assert_eq!(ifc.get_simplification_style(), CompileAction::Decompile);
        assert!(ifc.is_syntax_tree_enabled());
        assert!(ifc.is_c_code_enabled());
        assert!(!ifc.is_param_measures_enabled());
        assert!(!ifc.is_jump_loads_enabled());
        assert!(ifc.get_options().is_none());
        assert!(ifc.get_last_message().is_empty());
    }

    #[test]
    fn test_interface_open_program() {
        let mut ifc = DecompInterface::new();
        let ok = ifc.open_program("test.elf", "x86:LE:64:default", "default", 8, true);
        assert!(ok);
        assert!(ifc.is_program_open());
        assert_eq!(ifc.program_name(), Some("test.elf"));
        assert_eq!(ifc.get_status(), DecompInterfaceStatus::Ready);
        assert!(ifc.is_process_ready());
    }

    #[test]
    fn test_interface_open_program_no_pcode() {
        let mut ifc = DecompInterface::new();
        let ok = ifc.open_program("test.bin", "custom:BE:32:none", "default", 4, false);
        assert!(!ok);
        assert!(!ifc.is_program_open());
        assert_eq!(ifc.get_status(), DecompInterfaceStatus::Error);
        assert!(ifc.get_last_message().contains("PCode"));
    }

    #[test]
    fn test_interface_close_program() {
        let mut ifc = DecompInterface::new();
        ifc.open_program("test.elf", "x86:LE:64:default", "default", 8, true);
        assert!(ifc.is_program_open());
        ifc.close_program();
        assert!(!ifc.is_program_open());
        assert_eq!(ifc.get_status(), DecompInterfaceStatus::NotOpen);
        assert!(!ifc.is_process_ready());
    }

    #[test]
    fn test_interface_set_simplification_style() {
        let mut ifc = DecompInterface::new();
        assert!(ifc.set_simplification_style(CompileAction::Normalize));
        assert_eq!(ifc.get_simplification_style(), CompileAction::Normalize);
    }

    #[test]
    fn test_interface_toggle_syntax_tree() {
        let mut ifc = DecompInterface::new();
        assert!(ifc.is_syntax_tree_enabled());
        assert!(ifc.toggle_syntax_tree(false));
        assert!(!ifc.is_syntax_tree_enabled());
        assert!(ifc.toggle_syntax_tree(true));
        assert!(ifc.is_syntax_tree_enabled());
    }

    #[test]
    fn test_interface_toggle_c_code() {
        let mut ifc = DecompInterface::new();
        assert!(ifc.is_c_code_enabled());
        assert!(ifc.toggle_c_code(false));
        assert!(!ifc.is_c_code_enabled());
    }

    #[test]
    fn test_interface_toggle_param_measures() {
        let mut ifc = DecompInterface::new();
        assert!(!ifc.is_param_measures_enabled());
        assert!(ifc.toggle_param_measures(true));
        assert!(ifc.is_param_measures_enabled());
    }

    #[test]
    fn test_interface_toggle_jump_loads() {
        let mut ifc = DecompInterface::new();
        assert!(!ifc.is_jump_loads_enabled());
        assert!(ifc.toggle_jump_loads(true));
        assert!(ifc.is_jump_loads_enabled());
    }

    #[test]
    fn test_interface_set_options() {
        let mut ifc = DecompInterface::new();
        let opts = DecompileOptions::new();
        assert!(ifc.set_options(opts));
        assert!(ifc.get_options().is_some());
        assert_eq!(ifc.get_options().unwrap().max_width, 100);
    }

    #[test]
    fn test_interface_decompile_no_program() {
        let mut ifc = DecompInterface::new();
        let result = ifc.decompile_function(Address::new(0x1000), "main", 30);
        assert!(!result.decompile_completed());
        assert!(result.error_message.is_some());
    }

    #[test]
    fn test_interface_decompile_success() {
        let mut ifc = DecompInterface::new();
        ifc.open_program("test.elf", "x86:LE:64:default", "default", 8, true);
        let result = ifc.decompile_function(Address::new(0x1000), "main", 30);
        assert!(result.decompile_completed());
        assert!(result.error_message.is_none());
    }

    #[test]
    fn test_interface_flush_cache() {
        let mut ifc = DecompInterface::new();
        assert_eq!(ifc.flush_cache(), -1); // no process
        ifc.open_program("test", "x86:LE:64:default", "default", 8, true);
        assert_eq!(ifc.flush_cache(), 0);
    }

    #[test]
    fn test_interface_stop_process() {
        let mut ifc = DecompInterface::new();
        ifc.open_program("test", "x86:LE:64:default", "default", 8, true);
        assert!(ifc.is_process_ready());
        ifc.stop_process();
        assert!(!ifc.is_process_ready());
        assert_eq!(ifc.get_status(), DecompInterfaceStatus::ProcessCrashed);
    }

    #[test]
    fn test_interface_reset_decompiler() {
        let mut ifc = DecompInterface::new();
        ifc.open_program("test", "x86:LE:64:default", "default", 8, true);
        ifc.stop_process();
        assert!(!ifc.is_process_ready());
        ifc.reset_decompiler();
        assert!(ifc.is_process_ready());
        assert_eq!(ifc.get_status(), DecompInterfaceStatus::Ready);
    }

    #[test]
    fn test_interface_debug() {
        let mut ifc = DecompInterface::new();
        assert!(!ifc.is_debug_enabled());
        ifc.enable_debug(PathBuf::from("/tmp/debug.xml"));
        assert!(ifc.is_debug_enabled());
    }

    #[test]
    fn test_interface_signature_settings() {
        let mut ifc = DecompInterface::new();
        assert_eq!(ifc.get_signature_settings(), 0);
        assert!(ifc.set_signature_settings(42));
        assert_eq!(ifc.get_signature_settings(), 42);
    }

    #[test]
    fn test_interface_version() {
        let ifc = DecompInterface::new();
        assert_eq!(ifc.get_major_version(), 0);
        assert_eq!(ifc.get_minor_version(), 0);
    }

    #[test]
    fn test_interface_dispose() {
        let mut ifc = DecompInterface::new();
        ifc.open_program("test", "x86:LE:64:default", "default", 8, true);
        ifc.set_options(DecompileOptions::new());
        ifc.dispose();
        assert!(!ifc.is_program_open());
        assert!(ifc.get_options().is_none());
    }

    #[test]
    fn test_interface_encoding_set() {
        let mut ifc = DecompInterface::new();
        let set = ifc.encoding_set();
        assert!(!set.has_overlay);
        let set_mut = ifc.encoding_set_mut();
        set_mut.last_query = vec![1, 2, 3];
        assert_eq!(ifc.encoding_set().last_query, vec![1, 2, 3]);
    }

    #[test]
    fn test_interface_get_options_mut() {
        let mut ifc = DecompInterface::new();
        ifc.set_options(DecompileOptions::new());
        ifc.get_options_mut().unwrap().max_width = 120;
        assert_eq!(ifc.get_options().unwrap().max_width, 120);
    }

    #[test]
    fn test_interface_last_decompile_elapsed() {
        let mut ifc = DecompInterface::new();
        assert_eq!(ifc.last_decompile_elapsed_ms(), 0);
        ifc.open_program("test", "x86:LE:64:default", "default", 8, true);
        ifc.decompile_function(Address::new(0x1000), "main", 30);
        // elapsed_ms will be very small (near 0) for the stub implementation
    }
}
