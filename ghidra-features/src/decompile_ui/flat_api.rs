//! Flat decompiler API -- Rust port of
//! `ghidra.app.decompiler.flatapi.FlatDecompilerAPI`.
//!
//! Provides a simplified, script-friendly interface for decompiling
//! functions.  The flat API wraps a [`DecompInterface`] and a
//! [`FlatProgramAPI`] reference so that callers can decompile the
//! current function in one call without managing decompiler lifecycle.
//!
//! # Usage
//!
//! ```ignore
//! use ghidra_features::decompile_ui::flat_api::FlatDecompilerAPI;
//!
//! let mut api = FlatDecompilerAPI::new();
//! api.set_current_program(program);
//! let c_code = api.decompile(func_addr, Some(30))?;
//! println!("{}", c_code);
//! api.dispose();
//! ```

use std::fmt;

// ---------------------------------------------------------------------------
// Decompiler error
// ---------------------------------------------------------------------------

/// Error type for decompiler operations.
#[derive(Debug, Clone)]
pub struct DecompileError {
    /// The source component that produced the error.
    pub source: String,
    /// The error message.
    pub message: String,
}

impl DecompileError {
    /// Create a new decompile error.
    pub fn new(source: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            source: source.into(),
            message: message.into(),
        }
    }
}

impl fmt::Display for DecompileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.source, self.message)
    }
}

impl std::error::Error for DecompileError {}

// ---------------------------------------------------------------------------
// Decompiled function result
// ---------------------------------------------------------------------------

/// The result of a decompilation, containing the C source output.
#[derive(Debug, Clone)]
pub struct DecompiledFunctionResult {
    /// The decompiled C source code.
    pub c_code: String,
    /// The function name.
    pub function_name: String,
    /// The entry point address.
    pub entry_point: u64,
    /// Any error message from the decompiler (empty if successful).
    pub error_message: String,
    /// Whether decompilation was successful.
    pub success: bool,
}

impl DecompiledFunctionResult {
    /// Create a successful result.
    pub fn success(function_name: impl Into<String>, entry_point: u64, c_code: impl Into<String>) -> Self {
        Self {
            c_code: c_code.into(),
            function_name: function_name.into(),
            entry_point,
            error_message: String::new(),
            success: true,
        }
    }

    /// Create a failed result.
    pub fn failure(
        function_name: impl Into<String>,
        entry_point: u64,
        error: impl Into<String>,
    ) -> Self {
        Self {
            c_code: String::new(),
            function_name: function_name.into(),
            entry_point,
            error_message: error.into(),
            success: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Minimal function reference for decompilation
// ---------------------------------------------------------------------------

/// A minimal function descriptor used by [`FlatDecompilerAPI`].
#[derive(Debug, Clone)]
pub struct FunctionDescriptor {
    /// Function name.
    pub name: String,
    /// Entry point address.
    pub entry_point: u64,
    /// Whether this is an external function (cannot be decompiled).
    pub is_external: bool,
    /// Whether this is a thunk function.
    pub is_thunk: bool,
}

impl FunctionDescriptor {
    /// Create a new function descriptor.
    pub fn new(name: impl Into<String>, entry_point: u64) -> Self {
        Self {
            name: name.into(),
            entry_point,
            is_external: false,
            is_thunk: false,
        }
    }

    /// Mark as external.
    pub fn external(mut self) -> Self {
        self.is_external = true;
        self
    }

    /// Mark as thunk.
    pub fn thunk(mut self) -> Self {
        self.is_thunk = true;
        self
    }
}

// ---------------------------------------------------------------------------
// Decompile options (simplified)
// ---------------------------------------------------------------------------

/// Simplified decompiler options for the flat API.
#[derive(Debug, Clone)]
pub struct FlatDecompileOptions {
    /// Maximum decompilation timeout in seconds (0 = no timeout).
    pub timeout_secs: u32,
    /// Whether to simplify the output.
    pub simplify: bool,
    /// Whether to include namespace information.
    pub namespaces: bool,
}

impl Default for FlatDecompileOptions {
    fn default() -> Self {
        Self {
            timeout_secs: 0,
            simplify: true,
            namespaces: true,
        }
    }
}

// ---------------------------------------------------------------------------
// FlatDecompilerAPI
// ---------------------------------------------------------------------------

/// A simplified decompiler API for scripting.
///
/// Ported from `ghidra.app.decompiler.flatapi.FlatDecompilerAPI`.
///
/// The flat API manages a [`DecompInterface`] internally and exposes
/// a single [`decompile`](FlatDecompilerAPI::decompile) method that
/// returns the C source for a function.
///
/// # Lifecycle
///
/// 1. Create with [`new`](FlatDecompilerAPI::new).
/// 2. Set the current program via
///    [`set_current_program`](FlatDecompilerAPI::set_current_program).
/// 3. Call [`decompile`](FlatDecompilerAPI::decompile) one or more times.
/// 4. Call [`dispose`](FlatDecompilerAPI::dispose) when finished.
///
/// The [`Drop`] implementation calls `dispose` automatically.
#[derive(Debug)]
pub struct FlatDecompilerAPI {
    /// The current program name (set when the user opens a program).
    current_program: Option<String>,
    /// Cached decompiler interface (lazily initialized).
    decompiler_initialized: bool,
    /// Options for decompilation.
    options: FlatDecompileOptions,
    /// Function lookup cache: entry_point -> FunctionDescriptor.
    function_cache: Vec<FunctionDescriptor>,
    /// Mock decompilation results for testing / simulation.
    /// In a real implementation this would talk to the decompiler process.
    mock_results: Vec<(u64, DecompiledFunctionResult)>,
}

impl FlatDecompilerAPI {
    /// Create a new flat decompiler API without a program.
    ///
    /// You must call [`set_current_program`](FlatDecompilerAPI::set_current_program)
    /// before decompiling.
    pub fn new() -> Self {
        Self {
            current_program: None,
            decompiler_initialized: false,
            options: FlatDecompileOptions::default(),
            function_cache: Vec::new(),
            mock_results: Vec::new(),
        }
    }

    /// Create with pre-configured options.
    pub fn with_options(options: FlatDecompileOptions) -> Self {
        Self {
            current_program: None,
            decompiler_initialized: false,
            options,
            function_cache: Vec::new(),
            mock_results: Vec::new(),
        }
    }

    // -- Program management --

    /// Set the current program name.
    ///
    /// This mirrors the Java `FlatProgramAPI.getCurrentProgram()` call.
    pub fn set_current_program(&mut self, program_name: impl Into<String>) {
        self.current_program = Some(program_name.into());
        self.decompiler_initialized = false;
    }

    /// Get the current program name.
    pub fn current_program(&self) -> Option<&str> {
        self.current_program.as_deref()
    }

    // -- Decompiler lifecycle --

    /// Initialize the decompiler interface.
    ///
    /// This is called lazily by [`decompile`](FlatDecompilerAPI::decompile)
    /// but can be called explicitly to open the decompiler early.
    ///
    /// # Errors
    ///
    /// Returns an error if no program has been set.
    pub fn initialize(&mut self) -> Result<(), DecompileError> {
        if self.current_program.is_none() {
            return Err(DecompileError::new(
                "Decompiler",
                "No current program set. Call set_current_program() first.",
            ));
        }
        self.decompiler_initialized = true;
        Ok(())
    }

    /// Whether the decompiler has been initialized.
    pub fn is_initialized(&self) -> bool {
        self.decompiler_initialized
    }

    /// Dispose of the decompiler resources.
    ///
    /// After calling this, the API must be re-initialized before
    /// decompiling again.
    pub fn dispose(&mut self) {
        self.decompiler_initialized = false;
        self.mock_results.clear();
    }

    // -- Function cache --

    /// Register a function in the local cache.
    pub fn register_function(&mut self, func: FunctionDescriptor) {
        self.function_cache.push(func);
    }

    /// Register multiple functions.
    pub fn register_functions(&mut self, funcs: impl IntoIterator<Item = FunctionDescriptor>) {
        self.function_cache.extend(funcs);
    }

    /// Look up a function by entry point.
    pub fn find_function(&self, entry_point: u64) -> Option<&FunctionDescriptor> {
        self.function_cache
            .iter()
            .find(|f| f.entry_point == entry_point)
    }

    // -- Mock results (for testing) --

    /// Register a mock decompilation result.
    ///
    /// In a real implementation the decompiler process would produce
    /// these.  For testing, results can be pre-loaded.
    pub fn set_mock_result(&mut self, entry_point: u64, result: DecompiledFunctionResult) {
        self.mock_results.push((entry_point, result));
    }

    // -- Decompilation --

    /// Decompile a function by entry point address.
    ///
    /// Returns the decompiled C source code.
    ///
    /// # Parameters
    ///
    /// * `entry_point` - The function's entry point address.
    /// * `timeout_secs` - Maximum decompilation time in seconds.
    ///   Pass `None` to use the default from options.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The decompiler is not initialized (no program set).
    /// - The function is external and cannot be decompiled.
    /// - Decompilation fails.
    pub fn decompile(
        &mut self,
        entry_point: u64,
        timeout_secs: Option<u32>,
    ) -> Result<DecompiledFunctionResult, DecompileError> {
        if !self.decompiler_initialized {
            self.initialize()?;
        }

        // Check if function is external
        if let Some(func) = self.find_function(entry_point) {
            if func.is_external {
                return Err(DecompileError::new(
                    "Decompiler",
                    format!(
                        "Cannot decompile external function '{}' at 0x{:x}",
                        func.name, entry_point
                    ),
                ));
            }
        }

        // Look for mock result
        if let Some((_, result)) = self.mock_results.iter().find(|(ep, _)| *ep == entry_point) {
            if result.success {
                return Ok(result.clone());
            } else {
                return Err(DecompileError::new("Decompiler", &result.error_message));
            }
        }

        // In a real implementation, this would invoke the decompiler process.
        // For the Rust port, we return a placeholder indicating the function
        // would need a real decompiler backend.
        let func_name = self
            .find_function(entry_point)
            .map(|f| f.name.clone())
            .unwrap_or_else(|| format!("FUN_{:x}", entry_point));

        Err(DecompileError::new(
            "Decompiler",
            format!(
                "No decompiler backend available for '{}' at 0x{:x}. \
                 Register mock results or connect a real decompiler.",
                func_name, entry_point
            ),
        ))
    }

    /// Decompile a function and return just the C code string.
    ///
    /// Convenience wrapper around [`decompile`](FlatDecompilerAPI::decompile).
    pub fn decompile_to_string(
        &mut self,
        entry_point: u64,
        timeout_secs: Option<u32>,
    ) -> Result<String, DecompileError> {
        let result = self.decompile(entry_point, timeout_secs)?;
        Ok(result.c_code)
    }

    /// Get the current decompile options.
    pub fn options(&self) -> &FlatDecompileOptions {
        &self.options
    }

    /// Get mutable access to the decompile options.
    pub fn options_mut(&mut self) -> &mut FlatDecompileOptions {
        &mut self.options
    }
}

impl Default for FlatDecompilerAPI {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for FlatDecompilerAPI {
    fn drop(&mut self) {
        self.dispose();
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- DecompileError --

    #[test]
    fn test_decompile_error_display() {
        let err = DecompileError::new("Decompiler", "bad function");
        assert_eq!(format!("{}", err), "Decompiler: bad function");
    }

    #[test]
    fn test_decompile_error_is_std_error() {
        let err: Box<dyn std::error::Error> =
            Box::new(DecompileError::new("src", "msg"));
        assert!(err.to_string().contains("msg"));
    }

    // -- DecompiledFunctionResult --

    #[test]
    fn test_decompiled_function_result_success() {
        let r = DecompiledFunctionResult::success("main", 0x4000, "int main() {}");
        assert!(r.success);
        assert_eq!(r.c_code, "int main() {}");
        assert!(r.error_message.is_empty());
    }

    #[test]
    fn test_decompiled_function_result_failure() {
        let r = DecompiledFunctionResult::failure("bad", 0x5000, "crash");
        assert!(!r.success);
        assert!(r.c_code.is_empty());
        assert_eq!(r.error_message, "crash");
    }

    // -- FunctionDescriptor --

    #[test]
    fn test_function_descriptor_builder() {
        let f = FunctionDescriptor::new("printf", 0x0).external();
        assert!(f.is_external);
        assert!(!f.is_thunk);
    }

    #[test]
    fn test_function_descriptor_thunk() {
        let f = FunctionDescriptor::new("thunk_fn", 0x1000).thunk();
        assert!(f.is_thunk);
    }

    // -- FlatDecompilerAPI --

    #[test]
    fn test_flat_api_new() {
        let api = FlatDecompilerAPI::new();
        assert!(!api.is_initialized());
        assert!(api.current_program().is_none());
    }

    #[test]
    fn test_flat_api_set_program() {
        let mut api = FlatDecompilerAPI::new();
        api.set_current_program("test.elf");
        assert_eq!(api.current_program(), Some("test.elf"));
    }

    #[test]
    fn test_flat_api_initialize_requires_program() {
        let mut api = FlatDecompilerAPI::new();
        let result = api.initialize();
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("No current program"));
    }

    #[test]
    fn test_flat_api_initialize_with_program() {
        let mut api = FlatDecompilerAPI::new();
        api.set_current_program("test.elf");
        assert!(api.initialize().is_ok());
        assert!(api.is_initialized());
    }

    #[test]
    fn test_flat_api_dispose() {
        let mut api = FlatDecompilerAPI::new();
        api.set_current_program("test.elf");
        api.initialize().unwrap();
        assert!(api.is_initialized());

        api.dispose();
        assert!(!api.is_initialized());
    }

    #[test]
    fn test_flat_api_decompile_no_program() {
        let mut api = FlatDecompilerAPI::new();
        let result = api.decompile(0x4000, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_flat_api_decompile_external_function() {
        let mut api = FlatDecompilerAPI::new();
        api.set_current_program("test.elf");
        api.register_function(FunctionDescriptor::new("printf", 0x0).external());

        let result = api.decompile(0x0, None);
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("external"));
    }

    #[test]
    fn test_flat_api_decompile_with_mock() {
        let mut api = FlatDecompilerAPI::new();
        api.set_current_program("test.elf");
        api.register_function(FunctionDescriptor::new("main", 0x4000));
        api.set_mock_result(
            0x4000,
            DecompiledFunctionResult::success("main", 0x4000, "int main() { return 0; }"),
        );

        let result = api.decompile(0x4000, Some(30)).unwrap();
        assert!(result.success);
        assert_eq!(result.c_code, "int main() { return 0; }");
    }

    #[test]
    fn test_flat_api_decompile_to_string() {
        let mut api = FlatDecompilerAPI::new();
        api.set_current_program("test.elf");
        api.set_mock_result(
            0x1000,
            DecompiledFunctionResult::success("init", 0x1000, "void init() {}"),
        );

        let c = api.decompile_to_string(0x1000, None).unwrap();
        assert_eq!(c, "void init() {}");
    }

    #[test]
    fn test_flat_api_find_function() {
        let mut api = FlatDecompilerAPI::new();
        api.register_function(FunctionDescriptor::new("alpha", 0x1000));
        api.register_function(FunctionDescriptor::new("beta", 0x2000));

        let f = api.find_function(0x2000).unwrap();
        assert_eq!(f.name, "beta");

        assert!(api.find_function(0x9999).is_none());
    }

    #[test]
    fn test_flat_api_register_functions() {
        let mut api = FlatDecompilerAPI::new();
        api.register_functions(vec![
            FunctionDescriptor::new("a", 0x1000),
            FunctionDescriptor::new("b", 0x2000),
            FunctionDescriptor::new("c", 0x3000),
        ]);
        assert!(api.find_function(0x2000).is_some());
    }

    #[test]
    fn test_flat_api_options() {
        let opts = FlatDecompileOptions {
            timeout_secs: 60,
            simplify: false,
            namespaces: false,
        };
        let api = FlatDecompilerAPI::with_options(opts);
        assert_eq!(api.options().timeout_secs, 60);
        assert!(!api.options().simplify);
    }

    #[test]
    fn test_flat_api_options_mut() {
        let mut api = FlatDecompilerAPI::new();
        api.options_mut().timeout_secs = 120;
        assert_eq!(api.options().timeout_secs, 120);
    }

    #[test]
    fn test_flat_api_default() {
        let api = FlatDecompilerAPI::default();
        assert!(!api.is_initialized());
    }

    #[test]
    fn test_flat_api_mock_failure() {
        let mut api = FlatDecompilerAPI::new();
        api.set_current_program("test.elf");
        api.set_mock_result(
            0x5000,
            DecompiledFunctionResult::failure("bad", 0x5000, "decompile crash"),
        );

        let result = api.decompile(0x5000, None);
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("decompile crash"));
    }

    #[test]
    fn test_flat_api_no_backend_error() {
        let mut api = FlatDecompilerAPI::new();
        api.set_current_program("test.elf");
        api.register_function(FunctionDescriptor::new("real_func", 0x4000));

        let result = api.decompile(0x4000, None);
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("No decompiler backend"));
    }

    #[test]
    fn test_flat_api_drop_disposes() {
        {
            let mut api = FlatDecompilerAPI::new();
            api.set_current_program("test.elf");
            api.initialize().unwrap();
            // dropped here
        }
        // No panic = dispose was called
    }
}
