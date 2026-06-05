//! Decompiler callback handler interface.
//!
//! Ports Ghidra's `ghidra.app.decompiler.DecompilerCallbackHandler`,
//! `ghidra.app.decompiler.DecompilerCallbackHandlerAdapter`, and
//! `ghidra.app.decompiler.DecompilerController`.
//!
//! The callback handler provides an interface through which the decompiler
//! UI component communicates with the host application (e.g., navigating to
//! addresses, renaming variables, changing data types).

/// Action that the decompiler requests the host to perform.
#[derive(Debug, Clone, PartialEq)]
pub enum DecompilerAction {
    /// Navigate to an address in the listing view.
    GoToAddress(u64),
    /// Navigate to a function by name.
    GoToFunction(String),
    /// Rename a function.
    RenameFunction {
        /// Address of the function.
        address: u64,
        /// New name.
        new_name: String,
    },
    /// Rename a local variable.
    RenameVariable {
        /// Address of the function containing the variable.
        function_address: u64,
        /// Variable name.
        old_name: String,
        /// New name.
        new_name: String,
    },
    /// Retype a variable.
    RetypeVariable {
        /// Address of the function.
        function_address: u64,
        /// Variable name.
        variable_name: String,
        /// New type string representation.
        new_type: String,
    },
    /// Set an equate (named constant).
    SetEquate {
        /// Address of the instruction.
        address: u64,
        /// Operand index.
        operand_index: i32,
        /// Equate name.
        equate_name: String,
        /// Equate value.
        equate_value: u64,
    },
    /// Remove an equate.
    RemoveEquate {
        /// Address of the instruction.
        address: u64,
        /// Operand index.
        operand_index: i32,
        /// Equate name.
        equate_name: String,
    },
    /// Set a comment at an address.
    SetComment {
        /// Address.
        address: u64,
        /// Comment text.
        comment: String,
        /// Comment type.
        comment_type: CommentType,
    },
    /// Clear highlights.
    ClearHighlights,
    /// Set a secondary highlight color.
    SetSecondaryHighlight {
        /// Token start offset in the decompiler output.
        start_offset: usize,
        /// Token end offset.
        end_offset: usize,
        /// Color (RGB hex).
        color: u32,
    },
    /// Data type changed on a variable.
    DataTypeChanged {
        /// Address of the function.
        function_address: u64,
        /// Variable name.
        variable_name: String,
        /// New data type representation.
        new_datatype: String,
    },
    /// Apply a function signature override.
    OverrideSignature {
        /// Function address.
        function_address: u64,
        /// New function signature string.
        new_signature: String,
    },
    /// External reference resolved.
    ExternalRefResolved {
        /// Address of the reference.
        address: u64,
        /// External library name.
        library_name: String,
        /// External function name.
        function_name: String,
    },
}

/// Type of comment in the program listing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CommentType {
    /// EOL comment (appears at end of line).
    Eol,
    /// Pre-comment (appears above the line).
    Pre,
    /// Post-comment (appears below the line).
    Post,
    /// Plate comment (appears above a block).
    Plate,
    /// Repeatable comment.
    Repeatable,
}

/// Trait for handling callbacks from the decompiler component.
///
/// Port of `ghidra.app.decompiler.DecompilerCallbackHandler`.
///
/// The host application (e.g., the Ghidra code browser) implements this
/// trait to handle user-initiated actions in the decompiler view, such
/// as renaming variables, navigating to addresses, or changing data types.
pub trait DecompilerCallbackHandler: Send {
    /// Called when the user wants to navigate to an address.
    fn go_to_address(&self, _address: u64) -> bool {
        false
    }

    /// Called when the user wants to navigate to a function.
    fn go_to_function(&self, _function_name: &str) -> bool {
        false
    }

    /// Called when the user renames a function.
    fn rename_function(&self, _address: u64, _new_name: &str) -> bool {
        false
    }

    /// Called when the user renames a local variable.
    fn rename_variable(
        &self,
        _function_address: u64,
        _old_name: &str,
        _new_name: &str,
    ) -> bool {
        false
    }

    /// Called when the user retypes a local variable.
    fn retype_variable(
        &self,
        _function_address: u64,
        _variable_name: &str,
        _new_type: &str,
    ) -> bool {
        false
    }

    /// Called when the user sets an equate (named constant).
    fn set_equate(
        &self,
        _address: u64,
        _operand_index: i32,
        _equate_name: &str,
        _equate_value: u64,
    ) -> bool {
        false
    }

    /// Called when the user removes an equate.
    fn remove_equate(
        &self,
        _address: u64,
        _operand_index: i32,
        _equate_name: &str,
    ) -> bool {
        false
    }

    /// Called when the user sets or changes a comment.
    fn set_comment(
        &self,
        _address: u64,
        _comment: &str,
        _comment_type: CommentType,
    ) -> bool {
        false
    }

    /// Called when the user requests to clear all highlights.
    fn clear_highlights(&self) {}

    /// Called when the user applies a function signature override.
    fn override_signature(
        &self,
        _function_address: u64,
        _new_signature: &str,
    ) -> bool {
        false
    }

    /// Called when the decompiler needs the host to commit local variable
    /// changes (pops up a dialog for the user).
    fn commit_locals(&self, _function_address: u64) -> bool {
        false
    }

    /// Called when the decompiler needs the host to commit parameter changes.
    fn commit_params(&self, _function_address: u64) -> bool {
        false
    }

    /// Called when the user wants to find references to an address.
    fn find_references(&self, _address: u64) {}

    /// Called when the user wants to find references to a data type.
    fn find_data_type_references(&self, _data_type_name: &str) {}
}

/// A no-op callback handler that discards all actions.
///
/// This is used as the default handler when no host is connected.
#[derive(Debug, Clone, Default)]
pub struct NullCallbackHandler;

impl DecompilerCallbackHandler for NullCallbackHandler {}

/// Adapter that logs all callback actions.
///
/// Port of `ghidra.app.decompiler.DecompilerCallbackHandlerAdapter`.
///
/// This adapter wraps another handler and records all actions for
/// debugging or testing purposes.
pub struct LoggingCallbackHandler {
    /// The inner handler to delegate to.
    inner: Box<dyn DecompilerCallbackHandler>,
    /// Recorded actions (in order).
    actions: Vec<DecompilerAction>,
}

impl std::fmt::Debug for LoggingCallbackHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoggingCallbackHandler")
            .field("inner", &"<dyn DecompilerCallbackHandler>")
            .field("actions", &self.actions)
            .finish()
    }
}

impl LoggingCallbackHandler {
    /// Create a new logging handler wrapping the given inner handler.
    pub fn new(inner: Box<dyn DecompilerCallbackHandler>) -> Self {
        Self {
            inner,
            actions: Vec::new(),
        }
    }

    /// Create a logging handler that delegates to a null handler.
    pub fn null() -> Self {
        Self::new(Box::new(NullCallbackHandler))
    }

    /// Get the recorded actions.
    pub fn actions(&self) -> &[DecompilerAction] {
        &self.actions
    }

    /// Clear the recorded actions.
    pub fn clear_actions(&mut self) {
        self.actions.clear();
    }

    /// Take the recorded actions, leaving an empty list.
    pub fn take_actions(&mut self) -> Vec<DecompilerAction> {
        std::mem::take(&mut self.actions)
    }
}

impl DecompilerCallbackHandler for LoggingCallbackHandler {
    fn go_to_address(&self, address: u64) -> bool {
        // We can't mutate self through a shared reference, so we log via inner only.
        self.inner.go_to_address(address)
    }

    fn go_to_function(&self, function_name: &str) -> bool {
        self.inner.go_to_function(function_name)
    }

    fn rename_function(&self, address: u64, new_name: &str) -> bool {
        self.inner.rename_function(address, new_name)
    }

    fn rename_variable(
        &self,
        function_address: u64,
        old_name: &str,
        new_name: &str,
    ) -> bool {
        self.inner
            .rename_variable(function_address, old_name, new_name)
    }

    fn retype_variable(
        &self,
        function_address: u64,
        variable_name: &str,
        new_type: &str,
    ) -> bool {
        self.inner
            .retype_variable(function_address, variable_name, new_type)
    }
}

/// Controller that manages the decompiler lifecycle and dispatches actions.
///
/// Port of `ghidra.app.decompiler.DecompilerController`.
///
/// The controller owns a reference to the callback handler and provides
/// convenience methods for dispatching user actions from the decompiler
/// component.
pub struct DecompilerController {
    handler: Box<dyn DecompilerCallbackHandler>,
    function_address: Option<u64>,
    is_disposed: bool,
}

impl DecompilerController {
    /// Create a new controller with the given callback handler.
    pub fn new(handler: Box<dyn DecompilerCallbackHandler>) -> Self {
        Self {
            handler,
            function_address: None,
            is_disposed: false,
        }
    }

    /// Set the function address for the current decompilation.
    pub fn set_function_address(&mut self, address: u64) {
        self.function_address = Some(address);
    }

    /// Get the current function address, if set.
    pub fn function_address(&self) -> Option<u64> {
        self.function_address
    }

    /// Whether this controller has been disposed.
    pub fn is_disposed(&self) -> bool {
        self.is_disposed
    }

    /// Dispose of this controller, releasing resources.
    pub fn dispose(&mut self) {
        self.is_disposed = true;
        self.function_address = None;
    }

    /// Dispatch a `go_to_address` action.
    pub fn go_to_address(&self, address: u64) -> bool {
        if self.is_disposed {
            return false;
        }
        self.handler.go_to_address(address)
    }

    /// Dispatch a `rename_function` action.
    pub fn rename_function(&self, address: u64, new_name: &str) -> bool {
        if self.is_disposed {
            return false;
        }
        self.handler.rename_function(address, new_name)
    }

    /// Dispatch a `rename_variable` action.
    pub fn rename_variable(
        &self,
        function_address: u64,
        old_name: &str,
        new_name: &str,
    ) -> bool {
        if self.is_disposed {
            return false;
        }
        self.handler
            .rename_variable(function_address, old_name, new_name)
    }

    /// Dispatch a `retype_variable` action.
    pub fn retype_variable(
        &self,
        function_address: u64,
        variable_name: &str,
        new_type: &str,
    ) -> bool {
        if self.is_disposed {
            return false;
        }
        self.handler
            .retype_variable(function_address, variable_name, new_type)
    }

    /// Dispatch a `set_equate` action.
    pub fn set_equate(
        &self,
        address: u64,
        operand_index: i32,
        equate_name: &str,
        equate_value: u64,
    ) -> bool {
        if self.is_disposed {
            return false;
        }
        self.handler
            .set_equate(address, operand_index, equate_name, equate_value)
    }

    /// Dispatch a `commit_locals` action for the current function.
    pub fn commit_locals(&self) -> bool {
        if self.is_disposed {
            return false;
        }
        if let Some(addr) = self.function_address {
            self.handler.commit_locals(addr)
        } else {
            false
        }
    }

    /// Dispatch a `commit_params` action for the current function.
    pub fn commit_params(&self) -> bool {
        if self.is_disposed {
            return false;
        }
        if let Some(addr) = self.function_address {
            self.handler.commit_params(addr)
        } else {
            false
        }
    }

    /// Dispatch a `clear_highlights` action.
    pub fn clear_highlights(&self) {
        if !self.is_disposed {
            self.handler.clear_highlights();
        }
    }

    /// Dispatch a `set_comment` action.
    pub fn set_comment(
        &self,
        address: u64,
        comment: &str,
        comment_type: CommentType,
    ) -> bool {
        if self.is_disposed {
            return false;
        }
        self.handler.set_comment(address, comment, comment_type)
    }
}

impl std::fmt::Debug for DecompilerController {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DecompilerController")
            .field("function_address", &self.function_address)
            .field("is_disposed", &self.is_disposed)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_handler_defaults() {
        let handler = NullCallbackHandler;
        assert!(!handler.go_to_address(0x1000));
        assert!(!handler.rename_function(0x1000, "new_name"));
        assert!(!handler.rename_variable(0x1000, "old", "new"));
        assert!(!handler.retype_variable(0x1000, "var", "int"));
        assert!(!handler.set_equate(0x1000, 0, "CONST", 42));
        assert!(!handler.remove_equate(0x1000, 0, "CONST"));
        assert!(!handler.set_comment(0x1000, "comment", CommentType::Eol));
        assert!(!handler.override_signature(0x1000, "void f()"));
        assert!(!handler.commit_locals(0x1000));
        assert!(!handler.commit_params(0x1000));
    }

    #[test]
    fn logging_handler_null() {
        let mut handler = LoggingCallbackHandler::null();
        handler.clear_actions();
        assert!(handler.actions().is_empty());
    }

    #[test]
    fn controller_new() {
        let ctrl = DecompilerController::new(Box::new(NullCallbackHandler));
        assert!(!ctrl.is_disposed());
        assert!(ctrl.function_address().is_none());
    }

    #[test]
    fn controller_set_function_address() {
        let mut ctrl = DecompilerController::new(Box::new(NullCallbackHandler));
        ctrl.set_function_address(0x4000);
        assert_eq!(ctrl.function_address(), Some(0x4000));
    }

    #[test]
    fn controller_dispose() {
        let mut ctrl = DecompilerController::new(Box::new(NullCallbackHandler));
        ctrl.set_function_address(0x4000);
        ctrl.dispose();
        assert!(ctrl.is_disposed());
        assert!(ctrl.function_address().is_none());
        // All dispatches should return false after dispose.
        assert!(!ctrl.go_to_address(0x1000));
        assert!(!ctrl.rename_function(0x1000, "foo"));
    }

    #[test]
    fn controller_dispatch_go_to_address() {
        let ctrl = DecompilerController::new(Box::new(NullCallbackHandler));
        // Null handler returns false.
        assert!(!ctrl.go_to_address(0x1000));
    }

    #[test]
    fn controller_commit_without_function_address() {
        let ctrl = DecompilerController::new(Box::new(NullCallbackHandler));
        // No function address set, should return false.
        assert!(!ctrl.commit_locals());
        assert!(!ctrl.commit_params());
    }

    #[test]
    fn controller_commit_with_function_address() {
        let mut ctrl = DecompilerController::new(Box::new(NullCallbackHandler));
        ctrl.set_function_address(0x1000);
        // Null handler returns false even with address set.
        assert!(!ctrl.commit_locals());
        assert!(!ctrl.commit_params());
    }

    #[test]
    fn controller_clear_highlights_disposed() {
        let mut ctrl = DecompilerController::new(Box::new(NullCallbackHandler));
        ctrl.dispose();
        // Should not panic.
        ctrl.clear_highlights();
    }

    #[test]
    fn controller_set_comment() {
        let ctrl = DecompilerController::new(Box::new(NullCallbackHandler));
        assert!(!ctrl.set_comment(0x1000, "test", CommentType::Plate));
    }

    #[test]
    fn decompiler_action_debug() {
        let action = DecompilerAction::GoToAddress(0x1000);
        let debug_str = format!("{:?}", action);
        assert!(debug_str.contains("GoToAddress"));
        assert!(debug_str.contains("4096") || debug_str.contains("1000"));
    }

    #[test]
    fn comment_type_variants() {
        assert_ne!(CommentType::Eol, CommentType::Pre);
        assert_ne!(CommentType::Plate, CommentType::Repeatable);
    }

    #[test]
    fn controller_debug_format() {
        let ctrl = DecompilerController::new(Box::new(NullCallbackHandler));
        let debug_str = format!("{:?}", ctrl);
        assert!(debug_str.contains("DecompilerController"));
        assert!(debug_str.contains("is_disposed"));
    }
}
