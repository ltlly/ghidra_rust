//! Flat API for the decompiler.
//!
//! Ports `ghidra.app.decompiler.flatapi` package.
//!
//! Provides a simplified interface to decompiler functionality,
//! suitable for scripting and automated analysis.

use ghidra_core::addr::Address;

use crate::DecompileEngine;

/// A flat, simplified API to the decompiler.
///
/// This API provides convenience methods for common decompiler operations
/// without requiring deep knowledge of the decompiler internals.
pub struct FlatDecompilerAPI {
    /// The underlying decompile engine.
    engine: DecompileEngine,
}

impl FlatDecompilerAPI {
    /// Create a new flat decompiler API.
    pub fn new() -> Self {
        Self {
            engine: DecompileEngine::new(),
        }
    }

    /// Get a reference to the underlying engine.
    pub fn engine(&self) -> &DecompileEngine {
        &self.engine
    }

    /// Get a mutable reference to the underlying engine.
    pub fn engine_mut(&mut self) -> &mut DecompileEngine {
        &mut self.engine
    }

    /// Check if the decompiler is initialized.
    pub fn is_initialized(&self) -> bool {
        self.engine.is_initialized()
    }

    /// Get the decompiler version string.
    pub fn version(&self) -> &str {
        "Ghidra-Rust-Decompiler 0.1.0"
    }

    /// Format an address as a hex string.
    pub fn format_address(addr: Address) -> String {
        format!("0x{:x}", addr.offset)
    }

    /// Get the last decompile error as a string, if any.
    pub fn last_error_string(&self) -> Option<String> {
        // In a full implementation, this would track the last error
        None
    }

    /// Check if an address is a valid code address.
    pub fn is_code_address(addr: Address) -> bool {
        addr.offset > 0
    }

    /// Create a simple decompile request.
    pub fn create_request(
        &self,
        function_entry: Address,
        timeout_ms: u64,
    ) -> DecompileRequest {
        DecompileRequest {
            function_entry,
            timeout_ms,
            options: DecompileRequestOptions::default(),
        }
    }
}

impl Default for FlatDecompilerAPI {
    fn default() -> Self {
        Self::new()
    }
}

/// A decompile request specifying what to decompile and how.
#[derive(Debug, Clone)]
pub struct DecompileRequest {
    /// The function entry point to decompile.
    pub function_entry: Address,
    /// Timeout in milliseconds.
    pub timeout_ms: u64,
    /// Additional options.
    pub options: DecompileRequestOptions,
}

/// Options for a decompile request.
#[derive(Debug, Clone)]
pub struct DecompileRequestOptions {
    /// Whether to include debug info comments.
    pub include_debug_comments: bool,
    /// Whether to emit data-type information.
    pub emit_data_types: bool,
    /// Simplification level (0 = none, 1 = basic, 2 = full).
    pub simplification_level: u8,
}

impl Default for DecompileRequestOptions {
    fn default() -> Self {
        Self {
            include_debug_comments: false,
            emit_data_types: true,
            simplification_level: 2,
        }
    }
}

/// Result of a flat API decompile call.
#[derive(Debug, Clone)]
pub struct FlatDecompileResult {
    /// The decompiled C code.
    pub c_code: String,
    /// The function entry point.
    pub entry_point: Address,
    /// Whether decompilation succeeded.
    pub success: bool,
    /// Error message if failed.
    pub error: Option<String>,
    /// Time taken in milliseconds.
    pub elapsed_ms: u64,
}

impl FlatDecompileResult {
    /// Create a successful result.
    pub fn success(c_code: impl Into<String>, entry_point: Address) -> Self {
        Self {
            c_code: c_code.into(),
            entry_point,
            success: true,
            error: None,
            elapsed_ms: 0,
        }
    }

    /// Create an error result.
    pub fn error(error: impl Into<String>, entry_point: Address) -> Self {
        Self {
            c_code: String::new(),
            entry_point,
            success: false,
            error: Some(error.into()),
            elapsed_ms: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flat_api_creation() {
        let api = FlatDecompilerAPI::new();
        assert!(!api.is_initialized());
        assert!(api.version().contains("Decompiler"));
    }

    #[test]
    fn flat_api_format_address() {
        assert_eq!(
            FlatDecompilerAPI::format_address(Address::new(0xDEAD)),
            "0xdead"
        );
    }

    #[test]
    fn flat_api_is_code_address() {
        assert!(FlatDecompilerAPI::is_code_address(Address::new(0x1000)));
        assert!(!FlatDecompilerAPI::is_code_address(Address::new(0)));
    }

    #[test]
    fn decompile_request() {
        let api = FlatDecompilerAPI::new();
        let req = api.create_request(Address::new(0x1000), 5000);
        assert_eq!(req.function_entry, Address::new(0x1000));
        assert_eq!(req.timeout_ms, 5000);
        assert_eq!(req.options.simplification_level, 2);
    }

    #[test]
    fn flat_decompile_result_success() {
        let result = FlatDecompileResult::success("int main() {}", Address::new(0x1000));
        assert!(result.success);
        assert!(!result.c_code.is_empty());
    }

    #[test]
    fn flat_decompile_result_error() {
        let result = FlatDecompileResult::error("timeout", Address::new(0x1000));
        assert!(!result.success);
        assert!(result.error.is_some());
    }

    #[test]
    fn decompile_request_options_default() {
        let opts = DecompileRequestOptions::default();
        assert!(!opts.include_debug_comments);
        assert!(opts.emit_data_types);
        assert_eq!(opts.simplification_level, 2);
    }
}
