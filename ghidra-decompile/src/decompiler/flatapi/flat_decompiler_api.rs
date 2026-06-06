//! Port of `ghidra.app.decompiler.flatapi.FlatDecompilerAPI`.
//!
//! Provides a convenience API for decompiling functions from a program,
//! wrapping the lower-level [`DecompInterface`].
//!
//! Note: The parent `flatapi` module provides a [`super::FlatDecompilerAPI`]
//! that wraps [`DecompileEngine`]. This module provides the
//! [`DecompInterface`]-based variant matching the Java original more closely.

use crate::decompiler::decomp_interface::DecompInterface;
use crate::decompiler::decompile_exception::DecompileException;

/// A flat (convenience) API for decompilation using [`DecompInterface`].
///
/// This wraps a [`DecompInterface`] and provides simplified methods for
/// decompiling individual functions. Mirrors Ghidra's `FlatDecompilerAPI`.
#[derive(Debug)]
pub struct DecompInterfaceApi {
    /// The underlying decompiler interface.
    decompiler: Option<DecompInterface>,
    /// Current program name.
    program_name: Option<String>,
}

impl DecompInterfaceApi {
    /// Create a new `DecompInterfaceApi` without a program.
    pub fn new() -> Self {
        Self {
            decompiler: None,
            program_name: None,
        }
    }

    /// Create with a program name.
    pub fn with_program(program_name: impl Into<String>) -> Self {
        Self {
            decompiler: None,
            program_name: Some(program_name.into()),
        }
    }

    /// Gets the underlying decompiler interface, if initialized.
    pub fn decompiler(&self) -> Option<&DecompInterface> {
        self.decompiler.as_ref()
    }

    /// Gets a mutable reference to the underlying decompiler interface.
    pub fn decompiler_mut(&mut self) -> Option<&mut DecompInterface> {
        self.decompiler.as_mut()
    }

    /// Set the current program name.
    pub fn set_program_name(&mut self, name: impl Into<String>) {
        self.program_name = Some(name.into());
    }

    /// Get the current program name.
    pub fn program_name(&self) -> Option<&str> {
        self.program_name.as_deref()
    }

    /// Initialize the decompiler interface if not already initialized.
    pub fn initialize(&mut self) -> Result<(), DecompileException> {
        if self.decompiler.is_none() {
            self.decompiler = Some(DecompInterface::new());
        }
        Ok(())
    }

    /// Open a program with default specifications.
    pub fn open_program(
        &mut self,
        program_name: &str,
        pspec_xml: &str,
        cspec_xml: &str,
    ) -> Result<bool, DecompileException> {
        self.initialize()?;
        let decompiler = self.decompiler.as_mut().unwrap();
        decompiler.open_program(program_name, pspec_xml, cspec_xml, "", "")
    }

    /// Decompile the function at `entry_point` with no timeout.
    pub fn decompile(&mut self, entry_point: u64) -> Result<String, DecompileException> {
        self.decompile_with_timeout(entry_point, 0)
    }

    /// Decompile the function at `entry_point` with the given timeout in seconds.
    pub fn decompile_with_timeout(
        &mut self,
        entry_point: u64,
        timeout_secs: u32,
    ) -> Result<String, DecompileException> {
        self.initialize()?;
        let decompiler = self.decompiler.as_mut().unwrap();
        let results = decompiler.decompile_function(entry_point, timeout_secs);

        if results.decompile_completed() {
            if let Some(func) = results.get_decompiled_function() {
                Ok(func.c_code().to_string())
            } else if let Some(ref c) = results.c_code {
                Ok(c.clone())
            } else {
                Err(DecompileException::new(
                    "Decompiler",
                    "No decompiled function returned",
                ))
            }
        } else {
            Err(DecompileException::new(
                "Decompiler",
                results.error_message().unwrap_or("Unknown error"),
            ))
        }
    }

    /// Dispose of the decompiler resources.
    pub fn dispose(&mut self) {
        if let Some(ref mut decompiler) = self.decompiler {
            decompiler.dispose();
        }
        self.decompiler = None;
    }
}

impl Default for DecompInterfaceApi {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for DecompInterfaceApi {
    fn drop(&mut self) {
        self.dispose();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decomp_interface_api_new() {
        let api = DecompInterfaceApi::new();
        assert!(api.decompiler().is_none());
        assert!(api.program_name().is_none());
    }

    #[test]
    fn test_decomp_interface_api_with_program() {
        let api = DecompInterfaceApi::with_program("test.exe");
        assert_eq!(api.program_name(), Some("test.exe"));
        assert!(api.decompiler().is_none());
    }

    #[test]
    fn test_decomp_interface_api_initialize() {
        let mut api = DecompInterfaceApi::new();
        assert!(api.initialize().is_ok());
        assert!(api.decompiler().is_some());
    }

    #[test]
    fn test_decomp_interface_api_initialize_idempotent() {
        let mut api = DecompInterfaceApi::new();
        assert!(api.initialize().is_ok());
        let first_ptr = api.decompiler().map(|d| d as *const _);
        assert!(api.initialize().is_ok());
        let second_ptr = api.decompiler().map(|d| d as *const _);
        assert_eq!(first_ptr, second_ptr);
    }

    #[test]
    fn test_decomp_interface_api_set_program_name() {
        let mut api = DecompInterfaceApi::new();
        api.set_program_name("test.exe");
        assert_eq!(api.program_name(), Some("test.exe"));
    }

    #[test]
    fn test_decomp_interface_api_dispose() {
        let mut api = DecompInterfaceApi::new();
        api.initialize().unwrap();
        assert!(api.decompiler().is_some());
        api.dispose();
        assert!(api.decompiler().is_none());
    }

    #[test]
    fn test_decomp_interface_api_default() {
        let api = DecompInterfaceApi::default();
        assert!(api.decompiler().is_none());
    }

    #[test]
    fn test_decomp_interface_api_decompile_no_program() {
        let mut api = DecompInterfaceApi::new();
        let result = api.decompile(0x1000);
        // Should fail since no program is open
        assert!(result.is_err());
    }
}
