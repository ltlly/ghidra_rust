//! Ghidra Jython interpreter.
//!
//! Ported from `GhidraJythonInterpreter.java` in the Jython extension.
//!
//! Provides a Python interpreter for executing scripts within Ghidra.

use std::collections::HashMap;

/// The Ghidra Jython interpreter.
///
/// Manages a Python interpreter session, providing script execution,
/// variable binding, and output capture.
#[derive(Debug)]
pub struct GhidraJythonInterpreter {
    /// The interpreter name / ID.
    name: String,
    /// Whether the interpreter has been initialized.
    initialized: bool,
    /// Bound variables (name -> string representation).
    bindings: HashMap<String, String>,
    /// Captured output from script execution.
    output: Vec<String>,
    /// Execution history (scripts that have been run).
    history: Vec<String>,
}

impl GhidraJythonInterpreter {
    /// Create a new interpreter.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            initialized: false,
            bindings: HashMap::new(),
            output: Vec::new(),
            history: Vec::new(),
        }
    }

    /// Initialize the interpreter.
    ///
    /// This sets up the Python environment with Ghidra-specific
    /// modules and builtins.
    pub fn initialize(&mut self) {
        self.initialized = true;
        // Set default Ghidra bindings
        self.bind("__name__".to_string(), "__main__".to_string());
    }

    /// Whether the interpreter has been initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Get the interpreter name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Execute a Python script string.
    ///
    /// Returns `Ok(output)` on success, `Err(message)` on failure.
    pub fn execute(&mut self, script: &str) -> Result<String, String> {
        if !self.initialized {
            return Err("Interpreter not initialized".to_string());
        }

        self.history.push(script.to_string());
        // In a real implementation, this would invoke the Python runtime.
        // For this port, we provide a stub that records the script.
        let output = format!("<executed {} bytes of Python>", script.len());
        self.output.push(output.clone());
        Ok(output)
    }

    /// Bind a variable in the interpreter.
    pub fn bind(&mut self, name: String, value: String) {
        self.bindings.insert(name, value);
    }

    /// Get the value of a bound variable.
    pub fn get_binding(&self, name: &str) -> Option<&str> {
        self.bindings.get(name).map(|s| s.as_str())
    }

    /// Get all captured output.
    pub fn output(&self) -> &[String] {
        &self.output
    }

    /// Get execution history.
    pub fn history(&self) -> &[String] {
        &self.history
    }

    /// Clear the interpreter state.
    pub fn clear(&mut self) {
        self.output.clear();
        self.bindings.clear();
        self.history.clear();
    }

    /// Shut down the interpreter.
    pub fn dispose(&mut self) {
        self.clear();
        self.initialized = false;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interpreter_creation() {
        let interp = GhidraJythonInterpreter::new("test");
        assert_eq!(interp.name(), "test");
        assert!(!interp.is_initialized());
    }

    #[test]
    fn test_interpreter_initialize() {
        let mut interp = GhidraJythonInterpreter::new("test");
        interp.initialize();
        assert!(interp.is_initialized());
        assert_eq!(interp.get_binding("__name__"), Some("__main__"));
    }

    #[test]
    fn test_interpreter_execute_before_init() {
        let mut interp = GhidraJythonInterpreter::new("test");
        let result = interp.execute("print('hello')");
        assert!(result.is_err());
    }

    #[test]
    fn test_interpreter_execute() {
        let mut interp = GhidraJythonInterpreter::new("test");
        interp.initialize();
        let result = interp.execute("print('hello')");
        assert!(result.is_ok());
        assert_eq!(interp.history().len(), 1);
    }

    #[test]
    fn test_interpreter_bindings() {
        let mut interp = GhidraJythonInterpreter::new("test");
        interp.bind("x".to_string(), "42".to_string());
        assert_eq!(interp.get_binding("x"), Some("42"));
        assert!(interp.get_binding("y").is_none());
    }

    #[test]
    fn test_interpreter_dispose() {
        let mut interp = GhidraJythonInterpreter::new("test");
        interp.initialize();
        interp.execute("test").unwrap();
        interp.dispose();
        assert!(!interp.is_initialized());
        assert!(interp.output().is_empty());
    }
}
