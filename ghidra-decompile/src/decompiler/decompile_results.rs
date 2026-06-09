//! DecompileResults: results from a decompiler decompileFunction call.
//!
//! Port of Ghidra's `ghidra.app.decompiler.DecompileResults`.
//!
//! Depending on how the DecompInterface was called, you can get:
//! - C code with markup (ClangNode tree)
//! - The function's syntax tree (HighFunction)
//! - The function prototype
//!
//! Check `decompile_completed()` before accessing results. If it returns
//! false, `error_message()` may contain an error message. Warning messages
//! may be present even if decompilation completed.

use super::clang_node::{ClangNodeArena, ClangNodeId};
use super::decompiled_function::DecompiledFunction;
use super::decompile_process::DisposeState;
use super::pretty_printer::PrettyPrinter;

/// The results of a single decompileFunction call.
///
/// This is the main container for accessing the various structures returned
/// by the decompiler.  To check if the decompile completed normally, use
/// `decompile_completed()`.  If false, `error_message()` may have a useful
/// error message.  Warning messages may appear even on success.
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
    ///
    /// In the Java implementation, this checks `hfunc != null || hparamid != null`.
    /// Here we check that there is either a doc_root or high_function_data, and
    /// no non-warning error message.
    pub fn decompile_completed(&self) -> bool {
        if self.error_message.is_some() && self.is_error() {
            return false;
        }
        self.doc_root.is_some() || self.high_function_data.is_some() || self.param_id_data.is_some()
    }

    /// Whether the error message is a real error (not just a warning).
    fn is_error(&self) -> bool {
        match &self.error_message {
            None => false,
            Some(msg) => {
                if msg.trim().is_empty() {
                    return false;
                }
                if msg.to_lowercase().contains("warning") {
                    return false;
                }
                true
            }
        }
    }

    /// Whether the results are valid (no error message, or error is blank).
    ///
    /// Corresponds to Ghidra's `isValid()` which checks
    /// `errMsg == null || errMsg.isBlank()`.
    pub fn is_valid(&self) -> bool {
        match &self.error_message {
            None => true,
            Some(msg) => msg.trim().is_empty(),
        }
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

    /// Get the function entry point address.
    pub fn function_entry(&self) -> u64 {
        self.function_entry
    }

    /// Get the function name, if known.
    pub fn function_name(&self) -> Option<&str> {
        self.function_name.as_deref()
    }

    /// Get the C code markup tree root.
    ///
    /// Corresponds to Ghidra's `getCCodeMarkup()`.
    pub fn get_c_code_markup(&self) -> Option<ClangNodeId> {
        self.doc_root
    }

    /// Alias for `get_c_code_markup` for backward compatibility.
    pub fn c_code_markup(&self) -> Option<ClangNodeId> {
        self.doc_root
    }

    /// Get the ClangNode arena.
    pub fn arena(&self) -> Option<&ClangNodeArena> {
        self.arena.as_ref()
    }

    /// Get the mutable ClangNode arena.
    pub fn arena_mut(&mut self) -> Option<&mut ClangNodeArena> {
        self.arena.as_mut()
    }

    /// Get the raw high function data (opaque bytes).
    ///
    /// In the Java version, this returns a `HighFunction` object decoded from
    /// the response stream.  Here the raw bytes are stored for later decoding.
    pub fn get_high_function_data(&self) -> Option<&[u8]> {
        self.high_function_data.as_deref()
    }

    /// Get the raw parameter ID data (opaque bytes).
    ///
    /// In the Java version, this returns a `HighParamID` object decoded from
    /// the response stream.  Here the raw bytes are stored for later decoding.
    pub fn get_high_param_id_data(&self) -> Option<&[u8]> {
        self.param_id_data.as_deref()
    }

    /// Get the C code as an unadorned string.
    ///
    /// This uses the PrettyPrinter to convert the ClangNode tree into
    /// a `DecompiledFunction` containing both the raw C code and the
    /// function signature.
    pub fn get_decompiled_function(&self) -> Option<DecompiledFunction> {
        // If we have a doc_root and arena, use the PrettyPrinter
        if let (Some(root), Some(ref arena)) = (self.doc_root, &self.arena) {
            let printer = PrettyPrinter::new(
                self.function_name.clone(),
                root,
                arena.clone(),
                None,
            );
            return Some(printer.print());
        }
        // Fallback to stored c_code
        let c = self.c_code.as_deref()?;
        Some(DecompiledFunction::new(self.signature.clone(), c.to_string()))
    }

    /// Get the raw C code string.
    pub fn get_c_code(&self) -> Option<&str> {
        self.c_code.as_deref()
    }

    /// Set the raw C code string (used during response parsing).
    pub fn set_c_code(&mut self, code: String) {
        self.c_code = Some(code);
    }

    /// Get the function signature string.
    pub fn get_signature(&self) -> Option<&str> {
        self.signature.as_deref()
    }

    /// Set the function signature string (used during response parsing).
    pub fn set_signature(&mut self, sig: String) {
        self.signature = Some(sig);
    }

    /// Set the error message.
    pub fn set_error_message(&mut self, msg: String) {
        self.error_message = Some(msg);
    }

    /// Set the doc root and arena (used during response parsing).
    pub fn set_c_code_markup(&mut self, root: ClangNodeId, arena: ClangNodeArena) {
        self.doc_root = Some(root);
        self.arena = Some(arena);
    }

    /// Set high function data (used during response parsing).
    pub fn set_high_function_data(&mut self, data: Vec<u8>) {
        self.high_function_data = Some(data);
    }

    /// Set param ID data (used during response parsing).
    pub fn set_param_id_data(&mut self, data: Vec<u8>) {
        self.param_id_data = Some(data);
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

    /// Get the process dispose state.
    pub fn process_state(&self) -> DisposeState {
        self.process_state
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_success_result() {
        let _arena = ClangNodeArena::new();
        let _root = 0; // placeholder
        let mut arena_with_root = ClangNodeArena::new();
        let root_id = arena_with_root.alloc(super::super::clang_node::ClangNodeKind::TokenGroup(
            super::super::clang_node::ClangTokenGroupData::default(),
        ));
        let results = DecompileResults::success(0x1000, Some("main".to_string()), root_id, arena_with_root);
        assert!(results.decompile_completed());
        assert!(!results.is_timed_out());
        assert!(!results.is_cancelled());
        assert!(!results.failed_to_start());
        assert_eq!(results.function_entry(), 0x1000);
        assert_eq!(results.function_name(), Some("main"));
        assert!(results.is_valid());
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
        assert!(!results.is_valid());
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
    fn test_warning_is_valid() {
        let mut results = DecompileResults::error(
            0x5000,
            "Warning: something minor".to_string(),
            DisposeState::NotDisposed,
        );
        // In Java, isValid() returns false for any non-blank error message
        // (including warnings), matching errMsg == null || errMsg.isBlank()
        assert!(!results.is_valid());
        // But decompile_completed() still succeeds for warnings
        results.doc_root = Some(0);
        assert!(results.decompile_completed());
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

    #[test]
    fn test_setters() {
        let mut results = DecompileResults::error(0, "".to_string(), DisposeState::NotDisposed);
        results.set_c_code("void foo() {}".to_string());
        assert_eq!(results.get_c_code(), Some("void foo() {}"));
        results.set_signature("void foo()".to_string());
        assert_eq!(results.get_signature(), Some("void foo()"));
        results.set_error_message("some error".to_string());
        assert_eq!(results.error_message(), Some("some error"));
    }

    #[test]
    fn test_high_function_data() {
        let mut results = DecompileResults::error(0, "".to_string(), DisposeState::NotDisposed);
        assert!(results.get_high_function_data().is_none());
        results.set_high_function_data(vec![1, 2, 3]);
        assert_eq!(results.get_high_function_data(), Some([1u8, 2, 3].as_slice()));
    }

    #[test]
    fn test_param_id_data() {
        let mut results = DecompileResults::error(0, "".to_string(), DisposeState::NotDisposed);
        assert!(results.get_high_param_id_data().is_none());
        results.set_param_id_data(vec![4, 5, 6]);
        assert_eq!(results.get_high_param_id_data(), Some([4u8, 5, 6].as_slice()));
    }

    #[test]
    fn test_count_switch_statements() {
        let mut results = DecompileResults::error(0, "".to_string(), DisposeState::NotDisposed);
        results.c_code = Some("switch(x) { case 1: break; switch(y) {} }".to_string());
        assert_eq!(results.count_switch_statements(), 2);
    }

    #[test]
    fn test_parameter_count() {
        let mut results = DecompileResults::error(0, "".to_string(), DisposeState::NotDisposed);
        results.signature = Some("int main(int argc, char **argv)".to_string());
        assert_eq!(results.parameter_count(), 2);

        results.signature = Some("void foo(void)".to_string());
        assert_eq!(results.parameter_count(), 0);

        results.signature = Some("void bar()".to_string());
        assert_eq!(results.parameter_count(), 0);
    }

    #[test]
    fn test_has_calling_convention_info() {
        let mut results = DecompileResults::error(0, "".to_string(), DisposeState::NotDisposed);
        assert!(!results.has_calling_convention_info());
        results.doc_root = Some(0);
        results.signature = Some("int main()".to_string());
        assert!(results.has_calling_convention_info());
    }

    #[test]
    fn test_process_state() {
        let results = DecompileResults::error(0, "".to_string(), DisposeState::DisposedOnTimeout);
        assert_eq!(results.process_state(), DisposeState::DisposedOnTimeout);
    }

    #[test]
    fn test_c_code_markup_alias() {
        let mut results = DecompileResults::error(0, "".to_string(), DisposeState::NotDisposed);
        assert!(results.c_code_markup().is_none());
        results.doc_root = Some(42);
        assert_eq!(results.c_code_markup(), Some(42));
        assert_eq!(results.get_c_code_markup(), Some(42));
    }

    #[test]
    fn test_arena_mut() {
        let mut arena = ClangNodeArena::new();
        let root = arena.alloc(super::super::clang_node::ClangNodeKind::TokenGroup(
            super::super::clang_node::ClangTokenGroupData::default(),
        ));
        let mut results = DecompileResults::success(0x1000, None, root, arena);
        assert!(results.arena_mut().is_some());
    }
}
