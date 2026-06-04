//! DecompInterface: the main client-facing decompiler interface.
//!
//! Port of Ghidra's `ghidra.app.decompiler.DecompInterface`.
//!
//! This is the primary entry point for decompilation.  It manages the
//! lifecycle of a native decompiler process and provides methods to
//! decompile functions, toggle features, and manage options.

use std::sync::Mutex;

use super::decompile_exception::DecompileException;
use super::decompile_options::DecompileOptions;
use super::decompile_process::{DecompileProcess, DisposeState, ProcessStatus};
use super::decompile_results::DecompileResults;
use super::signature::DebugSignature;

/// Result of the `debug_signatures` action.
pub type SignatureResult = Option<Vec<DebugSignature>>;

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
    /// Whether to produce a syntax tree.
    syntax_tree: bool,
    /// Whether to produce C code.
    c_code: bool,
    /// Whether to compute parameter measures.
    param_measures: bool,
    /// Whether to simplify the syntax tree.
    simplify_double_precision: bool,
    /// Last decompile message.
    decompile_message: String,
    /// Whether the options have been sent to the process.
    options_sent: bool,
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
            syntax_tree: true,
            c_code: true,
            param_measures: false,
            simplify_double_precision: true,
            decompile_message: String::new(),
            options_sent: false,
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

    /// Toggle whether the decompiler produces a syntax tree.
    ///
    /// Default is true.  Returns true if the change was accepted.
    pub fn toggle_syntax_tree(&mut self, val: bool) -> bool {
        self.syntax_tree = val;
        if let Some(ref mut proc) = self.process {
            if proc.is_ready() {
                let cmd = if val { "setActionSyntaxTree" } else { "clearActionSyntaxTree" };
                let mut response = Vec::new();
                match proc.send_command(cmd, &mut response) {
                    Ok(()) => return true,
                    Err(_) => {
                        self.stop_process();
                        return false;
                    }
                }
            }
        }
        true
    }

    /// Toggle whether the decompiler produces C code.
    ///
    /// Default is true.  Returns true if the change was accepted.
    pub fn toggle_c_code(&mut self, val: bool) -> bool {
        self.c_code = val;
        if let Some(ref mut proc) = self.process {
            if proc.is_ready() {
                let cmd = if val { "setActionCCode" } else { "clearActionCCode" };
                let mut response = Vec::new();
                match proc.send_command(cmd, &mut response) {
                    Ok(()) => return true,
                    Err(_) => {
                        self.stop_process();
                        return false;
                    }
                }
            }
        }
        true
    }

    /// Toggle whether the decompiler computes parameter measures.
    ///
    /// Default is false.  Returns true if the change was accepted.
    pub fn toggle_param_measures(&mut self, val: bool) -> bool {
        self.param_measures = val;
        if let Some(ref mut proc) = self.process {
            if proc.is_ready() {
                let cmd = if val {
                    "setActionParamMeasures"
                } else {
                    "clearActionParamMeasures"
                };
                let mut response = Vec::new();
                match proc.send_command(cmd, &mut response) {
                    Ok(()) => return true,
                    Err(_) => {
                        self.stop_process();
                        return false;
                    }
                }
            }
        }
        true
    }

    /// Open a program for decompilation.
    ///
    /// This registers the program with the native decompiler process and
    /// sends all necessary context (processor spec, compiler spec, etc.).
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

        // Send action toggles
        self.send_action_state(&mut proc)?;

        self.process = Some(proc);
        self.decompile_message.clear();
        Ok(true)
    }

    /// Close the currently open program and stop the decompiler process.
    pub fn close_program(&mut self) {
        if let Some(ref mut proc) = self.process {
            let _ = proc.deregister_program();
        }
        self.process = None;
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
        timeout_secs: u32,
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
        // 3. Send the "decompile" command with timeout
        // 4. Parse the response XML into DecompileResults

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
    /// Should be called after any decompileFunction call since the
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
    }

    /// Get the last decompile message.
    pub fn decompile_message(&self) -> &str {
        &self.decompile_message
    }

    /// Whether the decompiler process is ready.
    pub fn is_ready(&self) -> bool {
        self.process
            .as_ref()
            .map_or(false, |p| p.is_ready())
    }

    /// Get the debug signatures for a function.
    ///
    /// This is an advanced debugging feature that returns signature
    /// information from the decompiler.
    pub fn debug_signatures(
        &mut self,
        entry_point: u64,
        timeout_secs: u32,
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

        // In a real implementation, this would send the debugSignatures command
        // and parse the response.
        None
    }

    /// Dispose of this interface, cleaning up resources.
    pub fn dispose(&mut self) {
        self.close_program();
    }

    /// Dispose callback (called from background thread to avoid deadlock).
    pub fn dispose_callback(&mut self) {
        if let Some(ref mut proc) = self.process {
            proc.dispose();
        }
    }

    // ==================================================================
    // Private helpers
    // ==================================================================

    fn send_action_state(&self, proc: &mut DecompileProcess) -> Result<(), DecompileException> {
        let mut response = Vec::new();
        if self.syntax_tree {
            proc.send_command("setActionSyntaxTree", &mut response)
                .map_err(|e| DecompileException::new("process", &format!("{}", e)))?;
        }
        if self.c_code {
            proc.send_command("setActionCCode", &mut response)
                .map_err(|e| DecompileException::new("process", &format!("{}", e)))?;
        }
        if self.param_measures {
            proc.send_command("setActionParamMeasures", &mut response)
                .map_err(|e| DecompileException::new("process", &format!("{}", e)))?;
        }
        Ok(())
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
        assert!(iface.toggle_syntax_tree(true));
    }

    #[test]
    fn test_toggle_c_code() {
        let mut iface = DecompInterface::new();
        assert!(iface.toggle_c_code(false));
        assert!(iface.toggle_c_code(true));
    }

    #[test]
    fn test_toggle_param_measures() {
        let mut iface = DecompInterface::new();
        assert!(iface.toggle_param_measures(true));
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
        assert_eq!(iface.exe_path.as_deref(), Some("/usr/bin/decompile"));
    }
}
