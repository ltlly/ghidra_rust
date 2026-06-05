//! Empty decompile data placeholder.
//!
//! Ports `ghidra.app.decompiler.EmptyDecompileData` from Ghidra's Java source.
//!
//! Represents a decompile result that has no data -- used as a default or
//! placeholder when no decompilation has been performed yet.

use ghidra_core::addr::Address;

use super::clang_node::ClangNodeArena;

/// Empty placeholder for decompile data when no function has been decompiled.
///
/// This is the initial state of a decompiler panel before any function
/// is loaded. It satisfies the decompile data interface with empty/null
/// values for all fields.
#[derive(Debug, Clone)]
pub struct EmptyDecompileData {
    /// Error message, if the empty state is due to an error.
    error_message: Option<String>,
    /// The function name (may be set even when data is empty).
    function_name: Option<String>,
    /// The program name.
    program_name: Option<String>,
}

impl EmptyDecompileData {
    /// Create a new empty decompile data with no error.
    pub fn new() -> Self {
        Self {
            error_message: None,
            function_name: None,
            program_name: None,
        }
    }

    /// Create an empty decompile data with an error message.
    pub fn with_error(message: impl Into<String>) -> Self {
        Self {
            error_message: Some(message.into()),
            function_name: None,
            program_name: None,
        }
    }

    /// Create an empty decompile data for a specific function.
    pub fn for_function(
        function_name: impl Into<String>,
        program_name: impl Into<String>,
    ) -> Self {
        Self {
            error_message: None,
            function_name: Some(function_name.into()),
            program_name: Some(program_name.into()),
        }
    }

    /// Whether this data represents an error condition.
    pub fn has_error(&self) -> bool {
        self.error_message.is_some()
    }

    /// Get the error message, if any.
    pub fn error_message(&self) -> Option<&str> {
        self.error_message.as_deref()
    }

    /// Get the function name, if set.
    pub fn function_name(&self) -> Option<&str> {
        self.function_name.as_deref()
    }

    /// Get the program name, if set.
    pub fn program_name(&self) -> Option<&str> {
        self.program_name.as_deref()
    }

    /// Whether there is any decompiled C code available.
    ///
    /// For empty data this is always false.
    pub fn has_decompiled_code(&self) -> bool {
        false
    }

    /// Get the decompiled C code (always empty for this type).
    pub fn c_code(&self) -> &str {
        ""
    }

    /// Get the Clang node arena (always empty for this type).
    pub fn clang_arena(&self) -> ClangNodeArena {
        ClangNodeArena::new()
    }

    /// Get the Clang node root id (always None for this type).
    pub fn clang_root(&self) -> Option<usize> {
        None
    }

    /// Get the entry point address (always None for this type).
    pub fn entry_point(&self) -> Option<Address> {
        None
    }

    /// Whether the decompile data is valid (always false for empty data).
    pub fn is_valid(&self) -> bool {
        false
    }

    /// Get the error status message for display.
    pub fn display_status(&self) -> String {
        match &self.error_message {
            Some(msg) => format!("Error: {}", msg),
            None => "No function decompiled".to_string(),
        }
    }
}

impl Default for EmptyDecompileData {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_data_default() {
        let data = EmptyDecompileData::new();
        assert!(!data.has_error());
        assert!(!data.has_decompiled_code());
        assert!(!data.is_valid());
        assert_eq!(data.c_code(), "");
        assert!(data.clang_root().is_none());
        assert!(data.entry_point().is_none());
    }

    #[test]
    fn empty_data_with_error() {
        let data = EmptyDecompileData::with_error("Decompilation failed");
        assert!(data.has_error());
        assert_eq!(
            data.error_message(),
            Some("Decompilation failed")
        );
        assert!(data.display_status().contains("Error"));
    }

    #[test]
    fn empty_data_for_function() {
        let data = EmptyDecompileData::for_function("main", "test.exe");
        assert_eq!(data.function_name(), Some("main"));
        assert_eq!(data.program_name(), Some("test.exe"));
        assert!(!data.has_error());
        assert!(data.display_status().contains("No function"));
    }

    #[test]
    fn empty_data_clang_arena_is_empty() {
        let data = EmptyDecompileData::new();
        let arena = data.clang_arena();
        assert!(arena.is_empty());
    }

    #[test]
    fn empty_data_default_trait() {
        let data = EmptyDecompileData::default();
        assert!(!data.has_error());
        assert!(data.function_name().is_none());
    }

    #[test]
    fn empty_data_display_status() {
        let no_err = EmptyDecompileData::new();
        assert_eq!(no_err.display_status(), "No function decompiled");

        let with_err = EmptyDecompileData::with_error("timeout");
        assert!(with_err.display_status().contains("timeout"));
    }
}
