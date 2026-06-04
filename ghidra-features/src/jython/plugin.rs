//! Jython plugin.
//!
//! Ported from `JythonPlugin.java` in the Jython extension.
//!
//! The plugin provides a Python scripting console within Ghidra.

use super::interpreter::GhidraJythonInterpreter;
use super::script::JythonScriptProvider;

/// The Jython plugin for Ghidra.
///
/// Provides Python scripting capabilities by managing a
/// `GhidraJythonInterpreter` and a `JythonScriptProvider`.
pub struct JythonPlugin {
    /// The Python interpreter.
    interpreter: GhidraJythonInterpreter,
    /// The script provider.
    script_provider: JythonScriptProvider,
    /// Whether the plugin is enabled.
    enabled: bool,
}

impl JythonPlugin {
    /// Create a new Jython plugin.
    pub fn new() -> Self {
        let mut interpreter = GhidraJythonInterpreter::new("Ghidra");
        interpreter.initialize();
        Self {
            interpreter,
            script_provider: JythonScriptProvider::new(),
            enabled: true,
        }
    }

    /// Get a reference to the interpreter.
    pub fn interpreter(&self) -> &GhidraJythonInterpreter {
        &self.interpreter
    }

    /// Get a mutable reference to the interpreter.
    pub fn interpreter_mut(&mut self) -> &mut GhidraJythonInterpreter {
        &mut self.interpreter
    }

    /// Get a reference to the script provider.
    pub fn script_provider(&self) -> &JythonScriptProvider {
        &self.script_provider
    }

    /// Get a mutable reference to the script provider.
    pub fn script_provider_mut(&mut self) -> &mut JythonScriptProvider {
        &mut self.script_provider
    }

    /// Whether the plugin is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Enable or disable the plugin.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Execute a Python script string.
    pub fn execute_script(&mut self, script: &str) -> Result<String, String> {
        if !self.enabled {
            return Err("Plugin is disabled".to_string());
        }
        self.interpreter.execute(script)
    }

    /// Dispose of the plugin.
    pub fn dispose(&mut self) {
        self.interpreter.dispose();
        self.enabled = false;
    }
}

impl Default for JythonPlugin {
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

    #[test]
    fn test_plugin_creation() {
        let plugin = JythonPlugin::new();
        assert!(plugin.is_enabled());
        assert!(plugin.interpreter().is_initialized());
    }

    #[test]
    fn test_plugin_execute() {
        let mut plugin = JythonPlugin::new();
        let result = plugin.execute_script("print('hello')");
        assert!(result.is_ok());
    }

    #[test]
    fn test_plugin_disabled() {
        let mut plugin = JythonPlugin::new();
        plugin.set_enabled(false);
        let result = plugin.execute_script("print('hello')");
        assert!(result.is_err());
    }

    #[test]
    fn test_plugin_dispose() {
        let mut plugin = JythonPlugin::new();
        plugin.dispose();
        assert!(!plugin.is_enabled());
        assert!(!plugin.interpreter().is_initialized());
    }
}
