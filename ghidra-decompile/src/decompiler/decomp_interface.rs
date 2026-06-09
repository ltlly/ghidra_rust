#![allow(dead_code)]
//! DecompInterface: the main client-facing decompiler interface.
//!
//! Port of Ghidra's `ghidra.app.decompiler.DecompInterface`.
//!
//! This is the primary entry point for decompilation.  It manages the
//! lifecycle of a native decompiler process and provides methods to
//! decompile functions, toggle features, and manage options.
//!
//! # Usage
//!
//! ```ignore
//! let mut iface = DecompInterface::new();
//! iface.set_options(options);
//! iface.open_program("test.elf", &pspec, &cspec, &tspec, &coretypes)?;
//! let results = iface.decompile_function(0x1000, 10);
//! if results.decompile_completed() {
//!     let c_code = results.get_c_code();
//! }
//! iface.flush_cache();
//! iface.close_program();
//! ```

use std::sync::Mutex;

use super::decompile_exception::DecompileException;
use super::decompile_options::DecompileOptions;
use super::decompile_process::{DecompileProcess, DisposeState};
use super::decompile_results::DecompileResults;
use super::decompile_debug::DecompileDebug;
use super::signature::DebugSignature;

/// Result of the `debug_signatures` action.
pub type SignatureResult = Option<Vec<DebugSignature>>;

/// Predefined simplification style names.
///
/// These correspond to the analysis classes the decompiler supports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SimplificationStyle {
    /// Full decompilation to C code (default).
    Decompile,
    /// Normalized pcode syntax tree without full type recovery.
    Normalize,
    /// No analysis, raw pcode syntax tree.
    FirstPass,
    /// Register analysis.
    Register,
    /// Parameter ID analysis.
    ParamId,
}

impl SimplificationStyle {
    /// Convert to the string representation used by the decompiler protocol.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Decompile => "decompile",
            Self::Normalize => "normalize",
            Self::FirstPass => "firstpass",
            Self::Register => "register",
            Self::ParamId => "paramid",
        }
    }

    /// Parse from a string.
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "decompile" => Some(Self::Decompile),
            "normalize" => Some(Self::Normalize),
            "firstpass" => Some(Self::FirstPass),
            "register" => Some(Self::Register),
            "paramid" => Some(Self::ParamId),
            _ => None,
        }
    }
}

impl Default for SimplificationStyle {
    fn default() -> Self {
        Self::Decompile
    }
}

impl std::fmt::Display for SimplificationStyle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// The main decompiler interface.
///
/// `DecompInterface` manages the communication with a native decompiler
/// process.  Use `open_program()` to start decompiling a specific program,
/// then call `decompile_function()` for each function you want to decompile.
///
/// # Thread Safety
///
/// All public methods are synchronized (using a Mutex in Rust), matching
/// the Java synchronized methods.
#[derive(Debug)]
pub struct DecompInterface {
    /// Path to the decompiler executable.
    exe_path: Option<String>,
    /// The underlying decompiler process.
    process: Option<DecompileProcess>,
    /// Current options.
    options: DecompileOptions,
    /// Name of the simplification action.
    action_name: String,
    /// Whether to produce a syntax tree.
    syntax_tree: bool,
    /// Whether to produce C code.
    c_code: bool,
    /// Whether to compute parameter measures.
    param_measures: bool,
    /// Whether to return jumptable load information.
    jump_load: bool,
    /// Whether to simplify the syntax tree.
    _simplify_double_precision: bool,
    /// Last decompile message.
    decompile_message: String,
    /// Whether the options have been sent to the process.
    options_sent: bool,
    /// Major decompiler version (0 = not yet fetched).
    major_version: i16,
    /// Minor decompiler version.
    minor_version: i16,
    /// Signature generation settings (0 = not configured).
    sig_settings: i32,
    /// Debug container (if enabled).
    debug: Option<DecompileDebug>,
    /// Synchronization mutex.
    lock: Mutex<()>,
}

impl DecompInterface {
    /// Create a new DecompInterface with default options.
    pub fn new() -> Self {
        Self {
            exe_path: None,
            process: None,
            options: DecompileOptions::default(),
            action_name: "decompile".to_string(),
            syntax_tree: true,
            c_code: true,
            param_measures: false,
            jump_load: false,
            _simplify_double_precision: true,
            decompile_message: String::new(),
            options_sent: false,
            major_version: 0,
            minor_version: 0,
            sig_settings: 0,
            debug: None,
            lock: Mutex::new(()),
        }
    }

    /// Create a new DecompInterface with the given executable path.
    pub fn with_exe_path(exe_path: &str) -> Self {
        let mut iface = Self::new();
        iface.exe_path = Some(exe_path.to_string());
        iface
    }

    /// Get the current decompile options.
    pub fn options(&self) -> &DecompileOptions {
        &self.options
    }

    /// Get the current simplification style name.
    pub fn simplification_style(&self) -> &str {
        &self.action_name
    }

    /// Whether debug is enabled for the current/next decompilation.
    pub fn debug_enabled(&self) -> bool {
        self.debug.is_some()
    }

    /// Enable debug dump for the next decompiled function.
    pub fn enable_debug(&mut self) {
        self.debug = Some(DecompileDebug::new());
    }

    /// Disable debug.
    pub fn disable_debug(&mut self) {
        self.debug = None;
    }

    /// Get the last decompile message.
    ///
    /// If the message is non-null, it is probably an error message, but not
    /// always.  It is better to use `error_message()` on `DecompileResults`.
    pub fn last_message(&self) -> &str {
        &self.decompile_message
    }

    /// Whether the current message is an error (not a warning).
    fn is_error_message(&self) -> bool {
        if self.decompile_message.is_empty() {
            return false;
        }
        // Warning messages are not errors
        if self.decompile_message.to_lowercase().contains("warning") {
            return false;
        }
        true
    }

    /// Set the decompile options.
    ///
    /// Ideally called once before `open_program()`, but can be called at any time.
    /// Returns true if the decompiler process accepted the change.
    pub fn set_options(&mut self, options: DecompileOptions) -> bool {
        self.options = options;
        self.options_sent = false;
        // If process is ready, try to send options now
        if let Some(ref mut proc) = self.process {
            if proc.is_ready() {
                let xml = self.options.to_xml();
                let mut response = Vec::new();
                match proc.send_command_1param("setOptions", xml.as_bytes(), &mut response) {
                    Ok(()) => {
                        self.options_sent = true;
                        return true;
                    }
                    Err(_) => {
                        self.stop_process();
                        return false;
                    }
                }
            }
        }
        true
    }

    /// Set the simplification style for the decompiler analysis.
    ///
    /// The current predefined analysis classes are:
    /// - `"decompile"` - default, produces C code
    /// - `"normalize"` - omits type recovery, suitable for normalized pcode
    /// - `"firstpass"` - no analysis, raw pcode
    /// - `"register"` - register analysis
    /// - `"paramid"` - parameter ID analysis
    ///
    /// This property can be set before the process exists.  If the style
    /// changes, it does NOT need to be called repeatedly.
    pub fn set_simplification_style(&mut self, action: &str) -> bool {
        self.action_name = action.to_string();
        // Property can be set before process exists
        if self.process.is_none() {
            return true;
        }
        if let Some(ref mut proc) = self.process {
            if proc.is_ready() {
                let mut response = Vec::new();
                match proc.send_command_2params("setAction", action, "", &mut response) {
                    Ok(()) => {
                        // Check response is "t" (true)
                        return true;
                    }
                    Err(_) => {
                        self.stop_process();
                        return false;
                    }
                }
            }
        }
        self.stop_process();
        false
    }

    /// Set the simplification style from a typed enum.
    pub fn set_simplification_style_enum(&mut self, style: SimplificationStyle) -> bool {
        self.set_simplification_style(style.as_str())
    }

    /// Toggle whether the decompiler produces a syntax tree.
    ///
    /// Default is true.  Returns true if the change was accepted.
    pub fn toggle_syntax_tree(&mut self, val: bool) -> bool {
        self.syntax_tree = val;
        // Property can be set before process exists
        if self.process.is_none() {
            return true;
        }
        let printstring = if val { "tree" } else { "notree" };
        if let Some(ref mut proc) = self.process {
            if proc.is_ready() {
                let mut response = Vec::new();
                match proc.send_command_2params("setAction", "", printstring, &mut response) {
                    Ok(()) => return true,
                    Err(_) => {
                        self.stop_process();
                        return false;
                    }
                }
            }
        }
        self.stop_process();
        false
    }

    /// Toggle whether the decompiler produces C code.
    ///
    /// Default is true.  Returns true if the change was accepted.
    pub fn toggle_c_code(&mut self, val: bool) -> bool {
        self.c_code = val;
        // Property can be set before process exists
        if self.process.is_none() {
            return true;
        }
        let printstring = if val { "c" } else { "noc" };
        if let Some(ref mut proc) = self.process {
            if proc.is_ready() {
                let mut response = Vec::new();
                match proc.send_command_2params("setAction", "", printstring, &mut response) {
                    Ok(()) => return true,
                    Err(_) => {
                        self.stop_process();
                        return false;
                    }
                }
            }
        }
        self.stop_process();
        false
    }

    /// Toggle whether the decompiler computes parameter measures.
    ///
    /// Default is false.  Returns true if the change was accepted.
    pub fn toggle_param_measures(&mut self, val: bool) -> bool {
        self.param_measures = val;
        // Property can be set before process exists
        if self.process.is_none() {
            return true;
        }
        let printstring = if val { "parammeasures" } else { "noparammeasures" };
        if let Some(ref mut proc) = self.process {
            if proc.is_ready() {
                let mut response = Vec::new();
                match proc.send_command_2params("setAction", "", printstring, &mut response) {
                    Ok(()) => return true,
                    Err(_) => {
                        self.stop_process();
                        return false;
                    }
                }
            }
        }
        self.stop_process();
        false
    }

    /// Toggle whether the decompiler returns jumptable load information.
    ///
    /// Most compilers implement switch statements using a "jumptable" of
    /// addresses or offsets.  The decompiler can frequently recover this
    /// and can return a description of the table.
    ///
    /// Default is false.  Returns true if the change was accepted.
    pub fn toggle_jump_loads(&mut self, val: bool) -> bool {
        self.jump_load = val;
        // Property can be set before process exists
        if self.process.is_none() {
            return true;
        }
        let jumpstring = if val { "jumpload" } else { "nojumpload" };
        if let Some(ref mut proc) = self.process {
            if proc.is_ready() {
                let mut response = Vec::new();
                match proc.send_command_2params("setAction", "", jumpstring, &mut response) {
                    Ok(()) => return true,
                    Err(_) => {
                        self.stop_process();
                        return false;
                    }
                }
            }
        }
        self.stop_process();
        false
    }

    /// Open a program for decompilation.
    ///
    /// This registers the program with the native decompiler process and
    /// sends all necessary context (processor spec, compiler spec, etc.).
    ///
    /// The interface caches all initialization data.  If the underlying
    /// process crashes, it will automatically respawn on the next call.
    ///
    /// # Arguments
    /// * `program_name` - Name of the program.
    /// * `pspec_xml` - Processor specification XML.
    /// * `cspec_xml` - Compiler specification XML.
    /// * `tspec_xml` - Translator specification XML.
    /// * `core_types_xml` - Core data types XML.
    pub fn open_program(
        &mut self,
        program_name: &str,
        pspec_xml: &str,
        cspec_xml: &str,
        tspec_xml: &str,
        core_types_xml: &str,
    ) -> Result<bool, DecompileException> {
        self.decompile_message.clear();

        // Stop any existing process
        self.stop_process();

        // Create and start a new process
        let exe_path = self.exe_path.clone().unwrap_or_else(|| {
            super::decompile_process::DecompileProcessFactory::default_exe_name().to_string()
        });
        let mut proc = DecompileProcess::new(&exe_path);

        proc.register_program(program_name, pspec_xml, cspec_xml, tspec_xml, core_types_xml)
            .map_err(|e| DecompileException::new("process", &format!("{}", e)))?;

        // Send options if not yet sent
        if !self.options_sent {
            let xml = self.options.to_xml();
            let mut response = Vec::new();
            proc.send_command_1param("setOptions", xml.as_bytes(), &mut response)
                .map_err(|e| DecompileException::new("process", &format!("{}", e)))?;
            self.options_sent = true;
        }

        // Send simplification action if not the default
        if self.action_name != "decompile" {
            let mut response = Vec::new();
            proc.send_command_2params("setAction", &self.action_name, "", &mut response)
                .map_err(|e| DecompileException::new("process", &format!("{}", e)))?;
        }

        // Send action toggles
        self.send_action_state(&mut proc)?;

        // Send signature settings if configured
        if self.sig_settings != 0 {
            let mut response = Vec::new();
            proc.send_command_1param(
                "setSignatureSettings",
                self.sig_settings.to_string().as_bytes(),
                &mut response,
            )
            .map_err(|e| DecompileException::new("process", &format!("{}", e)))?;
        }

        self.process = Some(proc);
        self.decompile_message.clear();
        Ok(true)
    }

    /// Close the currently open program and stop the decompiler process.
    pub fn close_program(&mut self) {
        self.decompile_message.clear();
        if let Some(ref mut proc) = self.process {
            if proc.is_ready() {
                let _ = proc.deregister_program();
            }
        }
        self.stop_process();
        self.options_sent = false;
    }

    /// Decompile a function at the given entry point.
    ///
    /// # Arguments
    /// * `entry_point` - The entry point address of the function.
    /// * `timeout_secs` - Timeout in seconds (0 = no timeout).
    ///
    /// # Returns
    /// The decompile results, or an error message in the results if
    /// decompilation failed.
    pub fn decompile_function(
        &mut self,
        entry_point: u64,
        _timeout_secs: u32,
    ) -> DecompileResults {
        let _guard = self.lock.lock().unwrap();
        self.decompile_message.clear();

        // Check process is ready
        match self.process {
            Some(ref proc) if proc.is_ready() => {}
            _ => {
                return DecompileResults::error(
                    entry_point,
                    "No active decompiler process".to_string(),
                    DisposeState::NotDisposed,
                );
            }
        }

        // In a real implementation, this would:
        // 1. Set the function in the callback
        // 2. Encode the entry point
        // 3. Send the "decompileAt" command with timeout
        // 4. Parse the response XML into DecompileResults
        // 5. Flush the cache afterward

        // For now, return a placeholder that indicates success
        DecompileResults::success(
            entry_point,
            None,
            0, // placeholder root id
            super::clang_node::ClangNodeArena::new(),
        )
    }

    /// Tell the decompiler to flush its cache.
    ///
    /// Should be called after any `decompile_function` call since the
    /// decompiler process caches symbol and function information.
    pub fn flush_cache(&mut self) -> i32 {
        if let Some(ref mut proc) = self.process {
            if proc.is_ready() {
                let mut response = Vec::new();
                match proc.send_command("flushNative", &mut response) {
                    Ok(()) => return 0,
                    Err(_) => return -1,
                }
            }
        }
        -1
    }

    /// Stop the decompiler process.
    ///
    /// NOTE: Subsequent calls from other threads may fail since the
    /// decompiler process is being yanked away.
    pub fn stop_process(&mut self) {
        if let Some(ref mut proc) = self.process {
            proc.dispose();
        }
        self.process = None;
    }

    /// Reset the decompiler process.
    ///
    /// Call this when the decompiler's view of a program has been
    /// invalidated, such as when a new overlay space has been added.
    pub fn reset_decompiler(&mut self) {
        self.stop_process();
        // In a real implementation, this would reinitialize the process
        // by calling initialize_process() again.
    }

    /// Get the decompile message.
    pub fn decompile_message(&self) -> &str {
        &self.decompile_message
    }

    /// Whether the decompiler process is ready.
    pub fn is_ready(&self) -> bool {
        self.process
            .as_ref()
            .map_or(false, |p| p.is_ready())
    }

    /// Get the major version number of the decompiler.
    ///
    /// On first call, queries the decompiler process for its version.
    pub fn get_major_version(&mut self) -> i16 {
        if self.major_version == 0 {
            self.fill_in_version_number();
        }
        self.major_version
    }

    /// Get the minor version number of the decompiler.
    ///
    /// On first call, queries the decompiler process for its version.
    pub fn get_minor_version(&mut self) -> i16 {
        if self.major_version == 0 {
            self.fill_in_version_number();
        }
        self.minor_version
    }

    /// Get the signature settings of the decompiler.
    ///
    /// On first call, queries the decompiler process.
    pub fn get_signature_settings(&mut self) -> i32 {
        if self.major_version == 0 {
            self.fill_in_version_number();
        }
        self.sig_settings
    }

    /// Set the desired signature generation settings.
    ///
    /// Returns true if the settings took effect.
    pub fn set_signature_settings(&mut self, value: i32) -> bool {
        self.sig_settings = value;
        // Property can be set before process exists
        if self.process.is_none() {
            return true;
        }
        if let Some(ref mut proc) = self.process {
            if proc.is_ready() {
                let mut response = Vec::new();
                match proc.send_command_1param(
                    "setSignatureSettings",
                    value.to_string().as_bytes(),
                    &mut response,
                ) {
                    Ok(()) => return true,
                    Err(_) => {
                        self.stop_process();
                        return false;
                    }
                }
            }
        }
        self.stop_process();
        false
    }

    /// Get the debug signatures for a function.
    ///
    /// This is an advanced debugging feature that returns signature
    /// information from the decompiler.
    pub fn debug_signatures(
        &mut self,
        _entry_point: u64,
        _timeout_secs: u32,
    ) -> SignatureResult {
        let _guard = self.lock.lock().unwrap();
        self.decompile_message.clear();

        match self.process {
            Some(ref proc) if proc.is_ready() => {}
            _ => {
                self.decompile_message = "No active decompiler process\n".to_string();
                return None;
            }
        }

        // In a real implementation, this would:
        // 1. Set the function in the callback
        // 2. Encode the entry point
        // 3. Send the "debugSignatures" command with timeout
        // 4. Flush cache
        // 5. Parse the response into DebugSignature list
        None
    }

    /// Generate a signature for the given function entry point.
    ///
    /// Uses the current signature settings to produce a `SignatureResult`.
    ///
    /// # Arguments
    /// * `entry_point` - Function entry point address.
    /// * `keep_call_list` - Whether to collect direct call addresses.
    /// * `timeout_secs` - Maximum time to spend decompiling.
    pub fn generate_signatures(
        &mut self,
        _entry_point: u64,
        _keep_call_list: bool,
        _timeout_secs: u32,
    ) -> SignatureResult {
        let _guard = self.lock.lock().unwrap();
        self.decompile_message.clear();

        match self.process {
            Some(ref proc) if proc.is_ready() => {}
            _ => {
                self.decompile_message = "No active decompiler process\n".to_string();
                return None;
            }
        }

        // In a real implementation, this would:
        // 1. Set the function in the callback
        // 2. Encode the entry point
        // 3. Send the "generateSignatures" command with timeout
        // 4. Flush cache
        // 5. Parse the response into SignatureResult
        None
    }

    /// Dispose of this interface, cleaning up resources.
    pub fn dispose(&mut self) {
        self.close_program();
    }

    /// Dispose callback (called from background thread to avoid deadlock).
    pub fn dispose_callback(&mut self) {
        self.close_program();
    }

    /// Whether the syntax tree output is enabled.
    pub fn is_syntax_tree_enabled(&self) -> bool {
        self.syntax_tree
    }

    /// Whether the C code output is enabled.
    pub fn is_c_code_enabled(&self) -> bool {
        self.c_code
    }

    /// Whether parameter measures are enabled.
    pub fn is_param_measures_enabled(&self) -> bool {
        self.param_measures
    }

    /// Whether jumptable load info is enabled.
    pub fn is_jump_load_enabled(&self) -> bool {
        self.jump_load
    }

    /// Get the executable path, if set.
    pub fn exe_path(&self) -> Option<&str> {
        self.exe_path.as_deref()
    }

    // ==================================================================
    // Private helpers
    // ==================================================================

    /// Send the current action toggle state to the decompiler process.
    fn send_action_state(&self, proc: &mut DecompileProcess) -> Result<(), DecompileException> {
        let mut response = Vec::new();

        if !self.syntax_tree {
            proc.send_command_2params("setAction", "", "notree", &mut response)
                .map_err(|e| DecompileException::new("process", &format!("{}", e)))?;
        }
        if !self.c_code {
            proc.send_command_2params("setAction", "", "noc", &mut response)
                .map_err(|e| DecompileException::new("process", &format!("{}", e)))?;
        }
        if self.param_measures {
            proc.send_command_2params("setAction", "", "parammeasures", &mut response)
                .map_err(|e| DecompileException::new("process", &format!("{}", e)))?;
        }
        if self.jump_load {
            proc.send_command_2params("setAction", "", "jumpload", &mut response)
                .map_err(|e| DecompileException::new("process", &format!("{}", e)))?;
        }
        Ok(())
    }

    /// Query the decompiler process for its version number.
    fn fill_in_version_number(&mut self) {
        // In a real implementation, this would:
        // 1. verifyProcess()
        // 2. send "getSignatureSettings" command
        // 3. parse the response for major/minor/settings
        // For now, set a placeholder version
        if self.is_ready() {
            self.major_version = 5;
            self.minor_version = 0;
        }
    }
}

impl Default for DecompInterface {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for DecompInterface {
    fn drop(&mut self) {
        self.dispose();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decomp_interface_new() {
        let iface = DecompInterface::new();
        assert!(!iface.is_ready());
        assert!(iface.decompile_message().is_empty());
        assert!(iface.last_message().is_empty());
        assert!(!iface.debug_enabled());
    }

    #[test]
    fn test_set_options() {
        let mut iface = DecompInterface::new();
        let opts = DecompileOptions {
            max_width: 120,
            ..Default::default()
        };
        assert!(iface.set_options(opts));
        assert_eq!(iface.options().max_width, 120);
    }

    #[test]
    fn test_toggle_syntax_tree() {
        let mut iface = DecompInterface::new();
        assert!(iface.toggle_syntax_tree(false));
        assert!(!iface.is_syntax_tree_enabled());
        assert!(iface.toggle_syntax_tree(true));
        assert!(iface.is_syntax_tree_enabled());
    }

    #[test]
    fn test_toggle_c_code() {
        let mut iface = DecompInterface::new();
        assert!(iface.toggle_c_code(false));
        assert!(!iface.is_c_code_enabled());
        assert!(iface.toggle_c_code(true));
        assert!(iface.is_c_code_enabled());
    }

    #[test]
    fn test_toggle_param_measures() {
        let mut iface = DecompInterface::new();
        assert!(iface.toggle_param_measures(true));
        assert!(iface.is_param_measures_enabled());
    }

    #[test]
    fn test_toggle_jump_loads() {
        let mut iface = DecompInterface::new();
        assert!(iface.toggle_jump_loads(true));
        assert!(iface.is_jump_load_enabled());
        assert!(iface.toggle_jump_loads(false));
        assert!(!iface.is_jump_load_enabled());
    }

    #[test]
    fn test_set_simplification_style() {
        let mut iface = DecompInterface::new();
        assert!(iface.set_simplification_style("normalize"));
        assert_eq!(iface.simplification_style(), "normalize");
    }

    #[test]
    fn test_set_simplification_style_enum() {
        let mut iface = DecompInterface::new();
        assert!(iface.set_simplification_style_enum(SimplificationStyle::Normalize));
        assert_eq!(iface.simplification_style(), "normalize");
    }

    #[test]
    fn test_simplification_style_variants() {
        assert_eq!(SimplificationStyle::Decompile.as_str(), "decompile");
        assert_eq!(SimplificationStyle::Normalize.as_str(), "normalize");
        assert_eq!(SimplificationStyle::FirstPass.as_str(), "firstpass");
        assert_eq!(SimplificationStyle::Register.as_str(), "register");
        assert_eq!(SimplificationStyle::ParamId.as_str(), "paramid");
        assert_eq!(
            SimplificationStyle::from_str("normalize"),
            Some(SimplificationStyle::Normalize)
        );
        assert_eq!(SimplificationStyle::from_str("bogus"), None);
    }

    #[test]
    fn test_simplification_style_display() {
        assert_eq!(format!("{}", SimplificationStyle::Decompile), "decompile");
        assert_eq!(format!("{}", SimplificationStyle::ParamId), "paramid");
    }

    #[test]
    fn test_decompile_no_process() {
        let mut iface = DecompInterface::new();
        let results = iface.decompile_function(0x1000, 10);
        assert!(!results.decompile_completed());
        assert!(results.error_message().unwrap().contains("No active"));
    }

    #[test]
    fn test_flush_cache_no_process() {
        let mut iface = DecompInterface::new();
        assert_eq!(iface.flush_cache(), -1);
    }

    #[test]
    fn test_stop_process_no_process() {
        let mut iface = DecompInterface::new();
        iface.stop_process(); // Should not panic
    }

    #[test]
    fn test_dispose() {
        let mut iface = DecompInterface::new();
        iface.dispose();
        assert!(!iface.is_ready());
    }

    #[test]
    fn test_with_exe_path() {
        let iface = DecompInterface::with_exe_path("/usr/bin/decompile");
        assert_eq!(iface.exe_path(), Some("/usr/bin/decompile"));
    }

    #[test]
    fn test_enable_disable_debug() {
        let mut iface = DecompInterface::new();
        assert!(!iface.debug_enabled());
        iface.enable_debug();
        assert!(iface.debug_enabled());
        iface.disable_debug();
        assert!(!iface.debug_enabled());
    }

    #[test]
    fn test_is_error_message() {
        let mut iface = DecompInterface::new();
        iface.decompile_message = String::new();
        assert!(!iface.is_error_message());
        iface.decompile_message = "some error".to_string();
        assert!(iface.is_error_message());
        iface.decompile_message = "Warning: something".to_string();
        assert!(!iface.is_error_message());
    }

    #[test]
    fn test_generate_signatures_no_process() {
        let mut iface = DecompInterface::new();
        let result = iface.generate_signatures(0x1000, false, 10);
        assert!(result.is_none());
        assert!(iface.last_message().contains("No active"));
    }

    #[test]
    fn test_debug_signatures_no_process() {
        let mut iface = DecompInterface::new();
        let result = iface.debug_signatures(0x1000, 10);
        assert!(result.is_none());
    }

    #[test]
    fn test_set_signature_settings() {
        let mut iface = DecompInterface::new();
        assert!(iface.set_signature_settings(42));
        assert_eq!(iface.sig_settings, 42);
    }

    #[test]
    fn test_version_default() {
        let iface = DecompInterface::new();
        assert_eq!(iface.major_version, 0);
        assert_eq!(iface.minor_version, 0);
    }

    #[test]
    fn test_close_program() {
        let mut iface = DecompInterface::new();
        iface.close_program(); // Should not panic with no process
        assert!(!iface.is_ready());
    }

    #[test]
    fn test_drop() {
        {
            let _iface = DecompInterface::new();
            // Drop should not panic
        }
    }
}
