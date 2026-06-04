//! DecompileResults: results from a decompiler decompileFunction call.
//!
//! Port of Ghidra's `ghidra.app.decompiler.DecompileResults`.

use super::clang_node::{ClangNodeArena, ClangNodeId};
use super::decompiled_function::DecompiledFunction;
use super::decompile_process::DisposeState;

/// The results of a single decompileFunction call.
///
/// Depending on how the DecompInterface was called, you can get:
/// - C code with markup (ClangNode tree)
/// - The function's syntax tree (HighFunction)
/// - The function prototype
///
/// Check `decompile_completed()` before accessing results. If it returns
/// false, `error_message()` may contain an error message. Warning messages
/// may be present even if decompilation completed.
#[derive(Debug, Clone)]
pub struct DecompileResults {
    /// Entry point address of the function (offset).
    pub function_entry: u64,
    /// Name of the function (if known).
    pub function_name: Option<String>,
    /// C code markup as a ClangNode tree.
    pub doc_root: Option<ClangNodeId>,
    /// The ClangNode arena holding the AST.
    pub arena: Option<ClangNodeArena>,
    /// The raw C code as a string (if requested).
    pub c_code: Option<String>,
    /// The function prototype/signature as a string.
    pub signature: Option<String>,
    /// Error or warning message from the decompiler.
    pub error_message: Option<String>,
    /// How the process was disposed (if at all).
    pub process_state: DisposeState,
    /// High function XML data (opaque bytes).
    pub high_function_data: Option<Vec<u8>>,
    /// Parameter ID data (opaque bytes).
    pub param_id_data: Option<Vec<u8>>,
}

impl DecompileResults {
    /// Create a new DecompileResults indicating completion.
    pub fn success(
        function_entry: u64,
        function_name: Option<String>,
        doc_root: ClangNodeId,
        arena: ClangNodeArena,
    ) -> Self {
        Self {
            function_entry,
            function_name,
            doc_root: Some(doc_root),
            arena: Some(arena),
            c_code: None,
            signature: None,
            error_message: None,
            process_state: DisposeState::NotDisposed,
            high_function_data: None,
            param_id_data: None,
        }
    }

    /// Create a failed DecompileResults.
    pub fn error(function_entry: u64, message: String, state: DisposeState) -> Self {
        Self {
            function_entry,
            function_name: None,
            doc_root: None,
            arena: None,
            c_code: None,
            signature: None,
            error_message: Some(message),
            process_state: state,
            high_function_data: None,
            param_id_data: None,
        }
    }

    /// Whether the decompile completed successfully.
    pub fn decompile_completed(&self) -> bool {
        self.error_message.is_none()
            || self.error_message.as_deref().map_or(true, |m| m.trim().is_empty())
    }

    /// Get the error/warning message.
    pub fn error_message(&self) -> Option<&str> {
        self.error_message.as_deref()
    }

    /// Whether the results were produced by a timed-out process.
    pub fn is_timed_out(&self) -> bool {
        self.process_state == DisposeState::DisposedOnTimeout
    }

    /// Whether the results were produced by a cancelled process.
    pub fn is_cancelled(&self) -> bool {
        self.process_state == DisposeState::DisposedOnCancel
    }

    /// Whether the decompiler executable failed to start.
    pub fn failed_to_start(&self) -> bool {
        self.process_state == DisposeState::DisposedOnStartupFailure
    }

    /// Get the C code markup tree root.
    pub fn c_code_markup(&self) -> Option<ClangNodeId> {
        self.doc_root
    }

    /// Get the ClangNode arena.
    pub fn arena(&self) -> Option<&ClangNodeArena> {
        self.arena.as_ref()
    }

    /// Get the C code as an unadorned string.
    pub fn get_decompiled_function(&self) -> Option<DecompiledFunction> {
        let c = self.c_code.as_deref()?;
        Some(DecompiledFunction::new(self.signature.clone(), c.to_string()))
    }

    /// Get the raw C code string.
    pub fn get_c_code(&self) -> Option<&str> {
        self.c_code.as_deref()
    }

    /// Get the function signature string.
    pub fn get_signature(&self) -> Option<&str> {
        self.signature.as_deref()
    }

    /// Count the number of switch statements found during decompilation.
    ///
    /// Stub implementation; a real decompiler would parse the AST for switch nodes.
    pub fn count_switch_statements(&self) -> usize {
        // Look for switch keywords in the C code output
        self.c_code
            .as_deref()
            .map(|code| code.matches("switch").count())
            .unwrap_or(0)
    }

    /// Get the number of identified parameters.
    ///
    /// Stub implementation; a real decompiler would extract parameter count
    /// from the function signature.
    pub fn parameter_count(&self) -> usize {
        self.signature
            .as_deref()
            .map(|sig| {
                // Count commas in the parameter list + 1 if non-void
                if sig.contains("void)") || sig.contains("()") {
                    0
                } else {
                    sig.chars().filter(|&c| c == ',').count() + 1
                }
            })
            .unwrap_or(0)
    }

    /// Check whether calling convention information was recovered.
    ///
    /// Stub implementation; returns true if decompilation succeeded and
    /// a signature was produced.
    pub fn has_calling_convention_info(&self) -> bool {
        self.decompile_completed() && self.signature.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_success_result() {
        let arena = ClangNodeArena::new();
        let root = 0; // placeholder
        let mut arena_with_root = ClangNodeArena::new();
        let root_id = arena_with_root.alloc(super::super::clang_node::ClangNodeKind::TokenGroup(
            super::super::clang_node::ClangTokenGroupData::default(),
        ));
        let results = DecompileResults::success(0x1000, Some("main".to_string()), root_id, arena_with_root);
        assert!(results.decompile_completed());
        assert!(!results.is_timed_out());
        assert!(!results.is_cancelled());
        assert!(!results.failed_to_start());
        assert_eq!(results.function_entry, 0x1000);
        assert_eq!(results.function_name.as_deref(), Some("main"));
    }

    #[test]
    fn test_error_result() {
        let results = DecompileResults::error(
            0x2000,
            "timeout".to_string(),
            DisposeState::DisposedOnTimeout,
        );
        assert!(!results.decompile_completed());
        assert!(results.is_timed_out());
        assert_eq!(results.error_message(), Some("timeout"));
    }

    #[test]
    fn test_cancelled_result() {
        let results = DecompileResults::error(
            0x3000,
            "cancelled".to_string(),
            DisposeState::DisposedOnCancel,
        );
        assert!(results.is_cancelled());
        assert!(!results.is_timed_out());
    }

    #[test]
    fn test_startup_failure() {
        let results = DecompileResults::error(
            0x4000,
            "exe not found".to_string(),
            DisposeState::DisposedOnStartupFailure,
        );
        assert!(results.failed_to_start());
    }

    #[test]
    fn test_get_decompiled_function() {
        let mut results = DecompileResults::error(0, "".to_string(), DisposeState::NotDisposed);
        results.c_code = Some("int main() { return 0; }".to_string());
        results.signature = Some("int main()".to_string());
        let df = results.get_decompiled_function().unwrap();
        assert_eq!(df.c_code(), "int main() { return 0; }");
        assert_eq!(df.signature(), Some("int main()"));
    }
}
