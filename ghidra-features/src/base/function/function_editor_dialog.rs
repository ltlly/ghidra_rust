//! Function editor dialog -- ported from `FunctionEditorDialog.java`.
//!
//! Provides the top-level dialog controller that orchestrates the editing
//! workflow for a function's properties (name, return type, calling
//! convention, parameters, inline/no-return flags, call-fixup).  This
//! module ties together:
//!
//! - The [`super::editor::FunctionEditorModel`] for data tracking
//! - The [`super::signature_dialog::AbstractEditFunctionSignatureDialog`]
//!   for signature validation
//! - Calling-convention and namespace resolution
//! - Applying changes via a command pattern
//!
//! The actual Swing / UI rendering is handled elsewhere; this module
//! contains only the non-UI business logic.
//!
//! # Types ported
//!
//! | Rust struct / enum              | Java class                            |
//! |---------------------------------|---------------------------------------|
//! | `FunctionEditorDialogController`| `FunctionEditorDialog`                |
//! | `DialogAction`                  | Button actions (OK/Apply/Cancel)      |
//! | `CallingConventionInfo`         | `GenericCallingConvention`            |
//! | `NamespaceResolver`             | `NamespaceUtils`                      |
//! | `EditFunctionCommand`           | `EditFunctionSignatureCmd`            |
//! | `ApplyResult`                   | Return value of apply logic           |

use std::fmt;

use super::editor::{
    FunctionData, FunctionEditorModel, FunctionVariableData, VarnodeInfo, VarnodeType,
};
use super::signature_dialog::{
    AbstractEditFunctionSignatureDialog, FunctionSignatureEditResult, SourceType,
};

// ---------------------------------------------------------------------------
// DialogAction -- button actions
// ---------------------------------------------------------------------------

/// Actions the user can take in the function editor dialog.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DialogAction {
    /// The user pressed OK (commit and close).
    Ok,
    /// The user pressed Apply (commit but keep open).
    Apply,
    /// The user pressed Cancel (discard and close).
    Cancel,
}

impl fmt::Display for DialogAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ok => write!(f, "OK"),
            Self::Apply => write!(f, "Apply"),
            Self::Cancel => write!(f, "Cancel"),
        }
    }
}

// ---------------------------------------------------------------------------
// CallingConventionInfo
// ---------------------------------------------------------------------------

/// Information about a calling convention.
///
/// Ported from `GenericCallingConvention.java` and related types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallingConventionInfo {
    /// The convention name (e.g., `"__cdecl"`, `"__stdcall"`).
    pub name: String,
    /// Human-readable description.
    pub description: String,
    /// Whether this is the default convention for the program.
    pub is_default: bool,
    /// Whether this convention supports varargs.
    pub supports_varargs: bool,
    /// The integer parameter registers in order.
    pub integer_params: Vec<String>,
    /// The float parameter registers in order.
    pub float_params: Vec<String>,
    /// The return register.
    pub return_register: String,
}

impl CallingConventionInfo {
    /// Creates a new calling convention info.
    pub fn new(
        name: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            is_default: false,
            supports_varargs: false,
            integer_params: Vec::new(),
            float_params: Vec::new(),
            return_register: String::new(),
        }
    }

    /// Creates the `__cdecl` convention (x86/x64).
    pub fn cdecl() -> Self {
        Self {
            name: "__cdecl".to_string(),
            description: "C calling convention (caller cleans stack)".to_string(),
            is_default: true,
            supports_varargs: true,
            integer_params: vec![],  // stack-based
            float_params: vec![],
            return_register: "EAX".to_string(),
        }
    }

    /// Creates the `__stdcall` convention (Win32 API).
    pub fn stdcall() -> Self {
        Self {
            name: "__stdcall".to_string(),
            description: "Standard call (callee cleans stack)".to_string(),
            is_default: false,
            supports_varargs: false,
            integer_params: vec![],
            float_params: vec![],
            return_register: "EAX".to_string(),
        }
    }

    /// Creates the `__fastcall` convention.
    pub fn fastcall() -> Self {
        Self {
            name: "__fastcall".to_string(),
            description: "Fast call (first two params in ECX/EDX)".to_string(),
            is_default: false,
            supports_varargs: false,
            integer_params: vec!["ECX".to_string(), "EDX".to_string()],
            float_params: vec![],
            return_register: "EAX".to_string(),
        }
    }

    /// Creates the System V AMD64 convention (Linux x64).
    pub fn sysv_amd64() -> Self {
        Self {
            name: "__sysv_amd64".to_string(),
            description: "System V AMD64 ABI".to_string(),
            is_default: true,
            supports_varargs: true,
            integer_params: vec![
                "RDI".into(), "RSI".into(), "RDX".into(),
                "RCX".into(), "R8".into(), "R9".into(),
            ],
            float_params: vec![
                "XMM0".into(), "XMM1".into(), "XMM2".into(),
                "XMM3".into(), "XMM4".into(), "XMM5".into(),
                "XMM6".into(), "XMM7".into(),
            ],
            return_register: "RAX".to_string(),
        }
    }

    /// Returns the default list of well-known calling conventions.
    pub fn well_known() -> Vec<Self> {
        vec![
            Self::cdecl(),
            Self::stdcall(),
            Self::fastcall(),
            Self::sysv_amd64(),
            Self::new("unknown", "Unknown calling convention"),
        ]
    }
}

impl fmt::Display for CallingConventionInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name)
    }
}

// ---------------------------------------------------------------------------
// NamespaceResolver -- resolves function namespaces
// ---------------------------------------------------------------------------

/// Resolves namespaces for function names.
///
/// Ported from `NamespaceUtils.java` -- determines the appropriate
/// namespace (library, class, global) for a function based on its name
/// and symbol information.
#[derive(Debug, Clone)]
pub struct NamespaceResolver {
    /// The global namespace name.
    global_name: String,
    /// Known library names.
    libraries: Vec<String>,
    /// Known class names.
    classes: Vec<String>,
}

impl NamespaceResolver {
    /// Creates a new namespace resolver.
    pub fn new() -> Self {
        Self {
            global_name: "Global".to_string(),
            libraries: Vec::new(),
            classes: Vec::new(),
        }
    }

    /// Adds a known library name.
    pub fn add_library(&mut self, name: impl Into<String>) {
        let n = name.into();
        if !self.libraries.contains(&n) {
            self.libraries.push(n);
        }
    }

    /// Adds a known class name.
    pub fn add_class(&mut self, name: impl Into<String>) {
        let n = name.into();
        if !self.classes.contains(&n) {
            self.classes.push(n);
        }
    }

    /// Returns the global namespace name.
    pub fn global_name(&self) -> &str {
        &self.global_name
    }

    /// Returns the known library names.
    pub fn libraries(&self) -> &[String] {
        &self.libraries
    }

    /// Returns the known class names.
    pub fn classes(&self) -> &[String] {
        &self.classes
    }

    /// Resolves the namespace for a function name that may contain
    /// namespace qualifiers (e.g., `"MyClass::myMethod"`).
    ///
    /// Returns `(namespace_path, simple_name)`.
    pub fn resolve(&self, qualified_name: &str) -> (Option<String>, String) {
        if let Some(pos) = qualified_name.rfind("::") {
            let ns = &qualified_name[..pos];
            let name = &qualified_name[pos + 2..];
            (Some(ns.to_string()), name.to_string())
        } else if let Some(pos) = qualified_name.rfind('.') {
            let ns = &qualified_name[..pos];
            let name = &qualified_name[pos + 1..];
            (Some(ns.to_string()), name.to_string())
        } else {
            (None, qualified_name.to_string())
        }
    }

    /// Returns whether a name qualifies as a library function.
    pub fn is_library_function(&self, name: &str) -> bool {
        if let (Some(ns), _) = self.resolve(name) {
            self.libraries.iter().any(|lib| lib == &ns)
        } else {
            false
        }
    }
}

impl Default for NamespaceResolver {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// EditFunctionCommand -- represents a change to apply
// ---------------------------------------------------------------------------

/// A command that applies a set of changes to a function.
///
/// Ported from `EditFunctionSignatureCmd.java` and related command
/// classes.  Each command captures the before/after state so it can
/// be undone.
#[derive(Debug, Clone)]
pub struct EditFunctionCommand {
    /// The function address (entry point).
    pub function_address: u64,
    /// The original function data (for undo).
    pub original: FunctionData,
    /// The new function data (to apply).
    pub new_data: FunctionData,
    /// Whether this is a signature-only change (vs. full property edit).
    pub signature_only: bool,
    /// The source of the change.
    pub source: SourceType,
}

impl EditFunctionCommand {
    /// Creates a new edit command.
    pub fn new(
        function_address: u64,
        original: FunctionData,
        new_data: FunctionData,
    ) -> Self {
        Self {
            function_address,
            original,
            new_data,
            signature_only: false,
            source: SourceType::UserDefined,
        }
    }

    /// Creates a signature-only edit command.
    pub fn signature_only(
        function_address: u64,
        original: FunctionData,
        new_data: FunctionData,
    ) -> Self {
        Self {
            function_address,
            original,
            new_data,
            signature_only: true,
            source: SourceType::UserDefined,
        }
    }

    /// Returns whether this command represents a meaningful change.
    pub fn has_changes(&self) -> bool {
        self.original.name() != self.new_data.name()
            || self.original.return_type() != self.new_data.return_type()
            || self.original.calling_convention() != self.new_data.calling_convention()
            || self.original.parameters().len() != self.new_data.parameters().len()
            || self.original.is_inline() != self.new_data.is_inline()
            || self.original.is_no_return() != self.new_data.is_no_return()
            || self.original.call_fixup() != self.new_data.call_fixup()
    }
}

// ---------------------------------------------------------------------------
// ApplyResult -- result of applying a dialog action
// ---------------------------------------------------------------------------

/// The result of applying an action in the dialog.
#[derive(Debug, Clone)]
pub enum ApplyResult {
    /// Changes were applied successfully.
    Success {
        /// The command that was applied.
        command: EditFunctionCommand,
    },
    /// Validation failed; no changes applied.
    ValidationError {
        /// The error message.
        message: String,
    },
    /// No changes to apply (dialog state matches original).
    NoChanges,
    /// The user cancelled.
    Cancelled,
}

impl ApplyResult {
    /// Returns `true` if the result is a success.
    pub fn is_success(&self) -> bool {
        matches!(self, Self::Success { .. })
    }

    /// Returns `true` if the result is a validation error.
    pub fn is_error(&self) -> bool {
        matches!(self, Self::ValidationError { .. })
    }
}

impl fmt::Display for ApplyResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Success { .. } => write!(f, "Success"),
            Self::ValidationError { message } => write!(f, "Validation error: {}", message),
            Self::NoChanges => write!(f, "No changes"),
            Self::Cancelled => write!(f, "Cancelled"),
        }
    }
}

// ---------------------------------------------------------------------------
// FunctionEditorDialogController -- top-level dialog controller
// ---------------------------------------------------------------------------

/// Controller for the function editor dialog.
///
/// Orchestrates the editing workflow: manages the editor model, handles
/// button actions (OK/Apply/Cancel), resolves calling conventions and
/// namespaces, and produces edit commands.
///
/// Ported from `FunctionEditorDialog.java`.
///
/// # Example
///
/// ```
/// use ghidra_features::base::function::function_editor_dialog::*;
/// use ghidra_features::base::function::editor::*;
///
/// let fd = FunctionData::new("main", "int", "__cdecl");
/// let mut dialog = FunctionEditorDialogController::new(
///     0x401000,
///     "test.exe",
///     fd,
/// );
/// assert!(dialog.is_open());
/// dialog.editor_model_mut().set_name("main2");
/// let result = dialog.action(DialogAction::Ok);
/// assert!(result.is_success());
/// ```
#[derive(Debug)]
pub struct FunctionEditorDialogController {
    /// The editor model holding current function data.
    editor_model: FunctionEditorModel,
    /// The signature dialog for additional validation.
    signature_dialog: AbstractEditFunctionSignatureDialog,
    /// Available calling conventions.
    calling_conventions: Vec<CallingConventionInfo>,
    /// The function entry point address.
    entry_point: u64,
    /// The program name.
    program_name: String,
    /// Whether the dialog is open.
    is_open: bool,
    /// Whether to commit full parameter details.
    commit_full_params: bool,
    /// The namespace resolver.
    namespace_resolver: NamespaceResolver,
    /// Status message.
    status_message: String,
}

impl FunctionEditorDialogController {
    /// Creates a new dialog controller.
    pub fn new(
        entry_point: u64,
        program_name: impl Into<String>,
        function_data: FunctionData,
    ) -> Self {
        let prog = program_name.into();
        let name = function_data.name().to_string();
        let sig = format!(
            "{} {}({})",
            function_data.return_type(),
            name,
            function_data
                .parameters()
                .iter()
                .filter(|p| !p.is_return())
                .map(|p| format!("{} {}", p.data_type_name(), p.display_name()))
                .collect::<Vec<_>>()
                .join(", ")
        );

        Self {
            editor_model: FunctionEditorModel::new(function_data.clone()),
            signature_dialog: AbstractEditFunctionSignatureDialog::new(
                format!("Edit Function: {}", name),
                true,
                true,
                true,
            ),
            calling_conventions: CallingConventionInfo::well_known(),
            entry_point,
            program_name: prog,
            is_open: true,
            commit_full_params: true,
            namespace_resolver: NamespaceResolver::new(),
            status_message: String::new(),
        }
    }

    /// Returns the dialog title.
    pub fn title(&self) -> String {
        format!("Edit Function at 0x{:x}", self.entry_point)
    }

    /// Returns whether the dialog is open.
    pub fn is_open(&self) -> bool {
        self.is_open
    }

    /// Returns the entry point address.
    pub fn entry_point(&self) -> u64 {
        self.entry_point
    }

    /// Returns the program name.
    pub fn program_name(&self) -> &str {
        &self.program_name
    }

    /// Returns a reference to the editor model.
    pub fn editor_model(&self) -> &FunctionEditorModel {
        &self.editor_model
    }

    /// Returns a mutable reference to the editor model.
    pub fn editor_model_mut(&mut self) -> &mut FunctionEditorModel {
        &mut self.editor_model
    }

    /// Returns a reference to the signature dialog.
    pub fn signature_dialog(&self) -> &AbstractEditFunctionSignatureDialog {
        &self.signature_dialog
    }

    /// Returns a mutable reference to the signature dialog.
    pub fn signature_dialog_mut(&mut self) -> &mut AbstractEditFunctionSignatureDialog {
        &mut self.signature_dialog
    }

    /// Returns the available calling conventions.
    pub fn calling_conventions(&self) -> &[CallingConventionInfo] {
        &self.calling_conventions
    }

    /// Sets the available calling conventions.
    pub fn set_calling_conventions(&mut self, conventions: Vec<CallingConventionInfo>) {
        self.calling_conventions = conventions;
    }

    /// Adds a calling convention.
    pub fn add_calling_convention(&mut self, cc: CallingConventionInfo) {
        if !self.calling_conventions.iter().any(|c| c.name == cc.name) {
            self.calling_conventions.push(cc);
        }
    }

    /// Returns whether to commit full parameter details.
    pub fn commit_full_params(&self) -> bool {
        self.commit_full_params
    }

    /// Sets whether to commit full parameter details.
    pub fn set_commit_full_params(&mut self, commit: bool) {
        self.commit_full_params = commit;
    }

    /// Returns a reference to the namespace resolver.
    pub fn namespace_resolver(&self) -> &NamespaceResolver {
        &self.namespace_resolver
    }

    /// Returns a mutable reference to the namespace resolver.
    pub fn namespace_resolver_mut(&mut self) -> &mut NamespaceResolver {
        &mut self.namespace_resolver
    }

    /// Returns the current status message.
    pub fn status_message(&self) -> &str {
        if self.status_message.is_empty() {
            self.editor_model.status_text()
        } else {
            &self.status_message
        }
    }

    /// Processes a dialog action.
    ///
    /// Returns the result of the action (success, validation error,
    /// no changes, or cancelled).
    pub fn action(&mut self, action: DialogAction) -> ApplyResult {
        match action {
            DialogAction::Ok | DialogAction::Apply => {
                if !self.editor_model.is_valid() {
                    return ApplyResult::ValidationError {
                        message: self.editor_model.status_text().to_string(),
                    };
                }
                if !self.editor_model.has_changes() {
                    return ApplyResult::NoChanges;
                }

                let command = EditFunctionCommand::new(
                    self.entry_point,
                    self.editor_model.function_data().clone(),
                    self.editor_model.function_data().clone(),
                );

                if action == DialogAction::Ok {
                    self.is_open = false;
                }

                ApplyResult::Success { command }
            }
            DialogAction::Cancel => {
                self.editor_model.reset();
                self.is_open = false;
                ApplyResult::Cancelled
            }
        }
    }

    /// Applies a signature edit result from the signature dialog.
    pub fn apply_signature_edit(&mut self, result: &FunctionSignatureEditResult) {
        if let Some(cc) = &result.calling_convention {
            self.editor_model.set_calling_convention(cc);
        }
        self.editor_model.set_inline(result.is_inline);
        self.editor_model.set_no_return(result.is_no_return);
        if let Some(fixup) = &result.call_fixup {
            self.editor_model.set_call_fixup(Some(fixup.clone()));
        }
    }

    /// Validates the current state and returns an error message if invalid.
    pub fn validate(&self) -> Option<String> {
        if !self.editor_model.is_valid() {
            Some(self.editor_model.status_text().to_string())
        } else {
            None
        }
    }

    /// Returns whether the dialog has unsaved changes.
    pub fn has_changes(&self) -> bool {
        self.editor_model.has_changes()
    }
}

impl fmt::Display for FunctionEditorDialogController {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.title())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::editor::VarnodeInfo;

    fn make_fd() -> FunctionData {
        let mut fd = FunctionData::new("main", "int", "__cdecl");
        fd.add_parameter(FunctionVariableData::parameter(
            Some("argc".into()), 0, "int", VarnodeInfo::register("EDI", 4),
        ));
        fd.add_parameter(FunctionVariableData::parameter(
            Some("argv".into()), 1, "char**", VarnodeInfo::register("RSI", 8),
        ));
        fd
    }

    // -- DialogAction --

    #[test]
    fn test_dialog_action_display() {
        assert_eq!(DialogAction::Ok.to_string(), "OK");
        assert_eq!(DialogAction::Apply.to_string(), "Apply");
        assert_eq!(DialogAction::Cancel.to_string(), "Cancel");
    }

    // -- CallingConventionInfo --

    #[test]
    fn test_calling_convention_cdecl() {
        let cc = CallingConventionInfo::cdecl();
        assert_eq!(cc.name, "__cdecl");
        assert!(cc.is_default);
        assert!(cc.supports_varargs);
        assert_eq!(cc.return_register, "EAX");
    }

    #[test]
    fn test_calling_convention_stdcall() {
        let cc = CallingConventionInfo::stdcall();
        assert_eq!(cc.name, "__stdcall");
        assert!(!cc.supports_varargs);
    }

    #[test]
    fn test_calling_convention_fastcall() {
        let cc = CallingConventionInfo::fastcall();
        assert_eq!(cc.integer_params, vec!["ECX", "EDX"]);
    }

    #[test]
    fn test_calling_convention_sysv_amd64() {
        let cc = CallingConventionInfo::sysv_amd64();
        assert_eq!(cc.integer_params.len(), 6);
        assert_eq!(cc.float_params.len(), 8);
        assert_eq!(cc.return_register, "RAX");
    }

    #[test]
    fn test_calling_convention_well_known() {
        let ccs = CallingConventionInfo::well_known();
        assert!(ccs.len() >= 4);
        assert!(ccs.iter().any(|c| c.name == "__cdecl"));
    }

    #[test]
    fn test_calling_convention_display() {
        let cc = CallingConventionInfo::new("custom", "Custom");
        assert_eq!(cc.to_string(), "custom");
    }

    // -- NamespaceResolver --

    #[test]
    fn test_namespace_resolver_basic() {
        let resolver = NamespaceResolver::new();
        assert_eq!(resolver.global_name(), "Global");
    }

    #[test]
    fn test_namespace_resolver_colon_colon() {
        let resolver = NamespaceResolver::new();
        let (ns, name) = resolver.resolve("MyClass::myMethod");
        assert_eq!(ns, Some("MyClass".to_string()));
        assert_eq!(name, "myMethod");
    }

    #[test]
    fn test_namespace_resolver_dot() {
        let resolver = NamespaceResolver::new();
        let (ns, name) = resolver.resolve("com.example.Main");
        assert_eq!(ns, Some("com.example".to_string()));
        assert_eq!(name, "Main");
    }

    #[test]
    fn test_namespace_resolver_no_namespace() {
        let resolver = NamespaceResolver::new();
        let (ns, name) = resolver.resolve("main");
        assert!(ns.is_none());
        assert_eq!(name, "main");
    }

    #[test]
    fn test_namespace_resolver_library() {
        let mut resolver = NamespaceResolver::new();
        resolver.add_library("kernel32");
        assert!(resolver.is_library_function("kernel32::CreateFileA"));
        assert!(!resolver.is_library_function("main"));
    }

    #[test]
    fn test_namespace_resolver_duplicate_library() {
        let mut resolver = NamespaceResolver::new();
        resolver.add_library("lib1");
        resolver.add_library("lib1");
        assert_eq!(resolver.libraries().len(), 1);
    }

    #[test]
    fn test_namespace_resolver_classes() {
        let mut resolver = NamespaceResolver::new();
        resolver.add_class("MyClass");
        assert_eq!(resolver.classes().len(), 1);
    }

    // -- EditFunctionCommand --

    #[test]
    fn test_edit_command_has_changes() {
        let original = FunctionData::new("main", "int", "__cdecl");
        let mut new_data = FunctionData::new("main", "int", "__cdecl");
        let cmd = EditFunctionCommand::new(0x401000, original.clone(), new_data.clone());
        assert!(!cmd.has_changes());

        new_data.set_name("main2");
        let cmd2 = EditFunctionCommand::new(0x401000, original, new_data);
        assert!(cmd2.has_changes());
    }

    #[test]
    fn test_edit_command_signature_only() {
        let original = FunctionData::new("main", "int", "__cdecl");
        let new_data = FunctionData::new("main", "void", "__cdecl");
        let cmd = EditFunctionCommand::signature_only(0x401000, original, new_data);
        assert!(cmd.signature_only);
        assert!(cmd.has_changes());
    }

    // -- ApplyResult --

    #[test]
    fn test_apply_result_success() {
        let original = FunctionData::new("main", "int", "__cdecl");
        let new_data = FunctionData::new("main2", "int", "__cdecl");
        let cmd = EditFunctionCommand::new(0x401000, original, new_data);
        let result = ApplyResult::Success { command: cmd };
        assert!(result.is_success());
        assert!(!result.is_error());
    }

    #[test]
    fn test_apply_result_validation_error() {
        let result = ApplyResult::ValidationError {
            message: "Name cannot be empty".to_string(),
        };
        assert!(!result.is_success());
        assert!(result.is_error());
        assert!(result.to_string().contains("Name cannot be empty"));
    }

    #[test]
    fn test_apply_result_no_changes() {
        let result = ApplyResult::NoChanges;
        assert_eq!(result.to_string(), "No changes");
    }

    #[test]
    fn test_apply_result_cancelled() {
        let result = ApplyResult::Cancelled;
        assert_eq!(result.to_string(), "Cancelled");
    }

    // -- FunctionEditorDialogController --

    #[test]
    fn test_dialog_controller_creation() {
        let fd = make_fd();
        let dialog = FunctionEditorDialogController::new(0x401000, "test.exe", fd);
        assert!(dialog.is_open());
        assert_eq!(dialog.entry_point(), 0x401000);
        assert_eq!(dialog.program_name(), "test.exe");
        assert!(dialog.title().contains("401000"));
    }

    #[test]
    fn test_dialog_controller_editor_model() {
        let fd = make_fd();
        let dialog = FunctionEditorDialogController::new(0x401000, "test.exe", fd);
        assert_eq!(dialog.editor_model().name(), "main");
        assert!(!dialog.has_changes());
    }

    #[test]
    fn test_dialog_controller_calling_conventions() {
        let fd = make_fd();
        let dialog = FunctionEditorDialogController::new(0x401000, "test.exe", fd);
        assert!(dialog.calling_conventions().len() >= 4);
    }

    #[test]
    fn test_dialog_controller_ok_no_changes() {
        let fd = make_fd();
        let mut dialog = FunctionEditorDialogController::new(0x401000, "test.exe", fd);
        let result = dialog.action(DialogAction::Ok);
        assert!(matches!(result, ApplyResult::NoChanges));
    }

    #[test]
    fn test_dialog_controller_ok_with_changes() {
        let fd = make_fd();
        let mut dialog = FunctionEditorDialogController::new(0x401000, "test.exe", fd);
        dialog.editor_model_mut().set_name("main2");
        let result = dialog.action(DialogAction::Ok);
        assert!(result.is_success());
        assert!(!dialog.is_open());
    }

    #[test]
    fn test_dialog_controller_apply_with_changes() {
        let fd = make_fd();
        let mut dialog = FunctionEditorDialogController::new(0x401000, "test.exe", fd);
        dialog.editor_model_mut().set_name("main2");
        let result = dialog.action(DialogAction::Apply);
        assert!(result.is_success());
        assert!(dialog.is_open()); // stays open
    }

    #[test]
    fn test_dialog_controller_cancel() {
        let fd = make_fd();
        let mut dialog = FunctionEditorDialogController::new(0x401000, "test.exe", fd);
        dialog.editor_model_mut().set_name("main2");
        assert!(dialog.has_changes());

        let result = dialog.action(DialogAction::Cancel);
        assert!(matches!(result, ApplyResult::Cancelled));
        assert!(!dialog.is_open());
        assert!(!dialog.has_changes()); // reset on cancel
    }

    #[test]
    fn test_dialog_controller_invalid_name() {
        let fd = make_fd();
        let mut dialog = FunctionEditorDialogController::new(0x401000, "test.exe", fd);
        dialog.editor_model_mut().set_name("");
        let result = dialog.action(DialogAction::Ok);
        assert!(result.is_error());
    }

    #[test]
    fn test_dialog_controller_apply_signature_edit() {
        let fd = make_fd();
        let mut dialog = FunctionEditorDialogController::new(0x401000, "test.exe", fd);
        let sig_result = FunctionSignatureEditResult::new("void main(int, char**)");
        dialog.apply_signature_edit(&sig_result);
        // The inline/no-return defaults from FunctionSignatureEditResult
        assert!(!dialog.editor_model().is_inline());
    }

    #[test]
    fn test_dialog_controller_add_calling_convention() {
        let fd = make_fd();
        let mut dialog = FunctionEditorDialogController::new(0x401000, "test.exe", fd);
        let count = dialog.calling_conventions().len();
        dialog.add_calling_convention(CallingConventionInfo::new("custom", "Custom"));
        assert_eq!(dialog.calling_conventions().len(), count + 1);

        // Duplicate should not be added
        dialog.add_calling_convention(CallingConventionInfo::new("custom", "Custom 2"));
        assert_eq!(dialog.calling_conventions().len(), count + 1);
    }

    #[test]
    fn test_dialog_controller_commit_full_params() {
        let fd = make_fd();
        let mut dialog = FunctionEditorDialogController::new(0x401000, "test.exe", fd);
        assert!(dialog.commit_full_params());
        dialog.set_commit_full_params(false);
        assert!(!dialog.commit_full_params());
    }

    #[test]
    fn test_dialog_controller_validate() {
        let fd = make_fd();
        let dialog = FunctionEditorDialogController::new(0x401000, "test.exe", fd);
        assert!(dialog.validate().is_none());

        let fd2 = make_fd();
        let mut dialog2 = FunctionEditorDialogController::new(0x401000, "test.exe", fd2);
        dialog2.editor_model_mut().set_name("");
        assert!(dialog2.validate().is_some());
    }

    #[test]
    fn test_dialog_controller_display() {
        let fd = make_fd();
        let dialog = FunctionEditorDialogController::new(0x401000, "test.exe", fd);
        let display = format!("{}", dialog);
        assert!(display.contains("401000"));
    }

    #[test]
    fn test_dialog_controller_namespace_resolver() {
        let fd = make_fd();
        let mut dialog = FunctionEditorDialogController::new(0x401000, "test.exe", fd);
        dialog.namespace_resolver_mut().add_library("kernel32");
        assert!(dialog.namespace_resolver().is_library_function("kernel32::CreateFileA"));
    }
}
