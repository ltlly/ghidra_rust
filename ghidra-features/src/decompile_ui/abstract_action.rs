//! Abstract decompiler action -- Rust port of
//! `ghidra.app.plugin.core.decompile.actions.AbstractDecompilerAction`.
//!
//! A base class for all decompiler actions that handles checking whether
//! the decompiler is busy.  Each action is responsible for deciding its
//! enablement via [`is_enabled_for_context`](AbstractDecompilerAction::is_enabled_for_context).
//! Each action must implement [`decompiler_action_performed`](AbstractDecompilerAction::decompiler_action_performed)
//! to complete its work.
//!
//! # Busy State Handling
//!
//! This parent class uses the [`DecompilerActionContext`](super::action_context::DecompilerActionContext)
//! to check for the decompiler's busy status.  If the decompiler is busy, the action reports that
//! it is enabled so that keybindings are consumed and not passed to the global context.
//! However, if the action is actually executed while busy, it shows an information message
//! instead of calling the child implementation.
//!
//! # Utility Methods
//!
//! This module also provides the utility methods that were static helpers in the Java
//! `AbstractDecompilerAction`:
//!
//! - [`get_composite_data_type`]: extract the struct/union from a field token.
//! - [`check_full_commit`]: compare high-function and function prototypes.
//! - [`get_symbol_for_context`]: find the symbol at the current context.

use std::fmt;

use ghidra_core::addr::Address;

use super::action_context::{ClangTokenKind, ClangTokenRef, DecompilerActionContext};

// ---------------------------------------------------------------------------
// Composite data type model (stand-in for Composite/Struct/Union)
// ---------------------------------------------------------------------------

/// The kind of composite data type (struct or union).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CompositeKind {
    /// A C struct.
    Struct,
    /// A C union.
    Union,
}

/// A field within a composite data type.
#[derive(Debug, Clone)]
pub struct FieldInfo {
    /// The field name.
    pub name: String,
    /// The offset in bytes from the start of the composite.
    pub offset: u64,
    /// The size in bytes.
    pub size: u64,
    /// The data type name (e.g., "int", "char *").
    pub type_name: String,
}

/// A reference to a composite (struct/union) data type.
///
/// In Ghidra this corresponds to `ghidra.program.model.data.Composite`.
/// Here we model just the information needed by decompiler actions.
#[derive(Debug, Clone)]
pub struct CompositeDataType {
    /// The name of the composite type.
    pub name: String,
    /// Whether this is a struct or union.
    pub kind: CompositeKind,
    /// The fields in this composite.
    pub fields: Vec<FieldInfo>,
    /// The total size in bytes.
    pub size: u64,
}

impl CompositeDataType {
    /// Create a new composite data type reference.
    pub fn new(name: impl Into<String>, kind: CompositeKind, size: u64) -> Self {
        Self {
            name: name.into(),
            kind,
            fields: Vec::new(),
            size,
        }
    }

    /// Add a field to this composite.
    pub fn add_field(&mut self, field: FieldInfo) {
        self.fields.push(field);
    }

    /// Find a field by name.
    pub fn find_field(&self, name: &str) -> Option<&FieldInfo> {
        self.fields.iter().find(|f| f.name == name)
    }

    /// Returns the number of fields.
    pub fn field_count(&self) -> usize {
        self.fields.len()
    }
}

impl fmt::Display for CompositeDataType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind_str = match self.kind {
            CompositeKind::Struct => "struct",
            CompositeKind::Union => "union",
        };
        write!(f, "{} {} ({} fields, {} bytes)", kind_str, self.name, self.fields.len(), self.size)
    }
}

// ---------------------------------------------------------------------------
// VariableStorage -- stand-in for VariableStorage
// ---------------------------------------------------------------------------

/// The storage location of a variable.
///
/// In Ghidra this is `ghidra.program.model.listing.VariableStorage`.
/// Here we model the essential information needed for prototype comparison.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VariableStorage {
    /// The register name or storage kind description.
    pub register: String,
    /// The first-use offset (for dynamic storage).
    pub first_use_offset: i32,
}

impl VariableStorage {
    /// Create a new variable storage.
    pub fn new(register: impl Into<String>, first_use_offset: i32) -> Self {
        Self {
            register: register.into(),
            first_use_offset,
        }
    }

    /// Compare storage locations for equivalence.
    ///
    /// Mirrors the Java `storage.compareTo(parameters[i].getVariableStorage())`
    /// which uses `DynamicVariableStorage` matching.
    pub fn storage_matches(&self, other: &VariableStorage) -> bool {
        self.register == other.register && self.first_use_offset == other.first_use_offset
    }
}

// ---------------------------------------------------------------------------
// ParameterInfo -- stand-in for function parameters in high-level IR
// ---------------------------------------------------------------------------

/// Information about a function parameter from the high-level representation.
///
/// In Ghidra this is extracted from `HighFunction.getLocalSymbolMap().getParamSymbol(i)`.
#[derive(Debug, Clone)]
pub struct ParameterInfo {
    /// The category index (parameter position).
    pub category_index: usize,
    /// The parameter's storage location.
    pub storage: VariableStorage,
    /// Whether this parameter is actually a parameter (vs. a local).
    pub is_parameter: bool,
}

impl ParameterInfo {
    /// Create a new parameter info.
    pub fn new(category_index: usize, storage: VariableStorage, is_parameter: bool) -> Self {
        Self {
            category_index,
            storage,
            is_parameter,
        }
    }
}

// ---------------------------------------------------------------------------
// AbstractDecompilerAction
// ---------------------------------------------------------------------------

/// A base trait for decompiler actions.
///
/// Implements the busy-state check and dispatches to the concrete action
/// via [`is_enabled_for_context`] and [`decompiler_action_performed`].
///
/// # Lifecycle
///
/// 1. The tool calls `is_valid_context` to verify the context is a
///    `DecompilerActionContext`.
/// 2. The tool calls `is_enabled_for_context` which checks:
///    - Is the decompiler busy?  If so, return `true` (consume the
///      keybinding) but do NOT call the child.
///    - Otherwise, delegate to `is_enabled_for_context`.
/// 3. The tool calls `action_performed` which checks busy state again
///    and delegates to `decompiler_action_performed`.
pub trait AbstractDecompilerAction: fmt::Debug {
    /// The action's unique name.
    fn name(&self) -> &str;

    /// Human-readable description.
    fn description(&self) -> &str;

    /// The popup menu path.
    fn menu_path(&self) -> &[&str] {
        &[]
    }

    /// The menu group for ordering.
    fn menu_group(&self) -> &str {
        ""
    }

    /// The key binding (if any).
    fn key_binding(&self) -> Option<&str> {
        None
    }

    /// Whether the action is valid for the given context.
    ///
    /// Default: valid only if the context is a decompiler context
    /// (always true here since we accept `DecompilerActionContext`).
    fn is_valid_context(&self, _ctx: &DecompilerActionContext) -> bool {
        true
    }

    /// Whether the action is enabled for the given context.
    ///
    /// This is called ONLY when the decompiler is NOT busy.  Subclasses
    /// must implement this to determine their enablement.
    fn is_enabled_for_context(&self, ctx: &DecompilerActionContext) -> bool;

    /// Check whether the action is enabled, considering busy state.
    ///
    /// If the decompiler is busy, returns `true` (to consume keybindings)
    /// but the action will not actually execute.
    fn check_enabled(&self, ctx: &DecompilerActionContext) -> bool {
        if ctx.is_decompiling() {
            return true; // consume keybinding while busy
        }
        self.is_enabled_for_context(ctx)
    }

    /// Execute the action.
    ///
    /// If the decompiler is busy, returns a "busy" result.  Otherwise
    /// delegates to [`decompiler_action_performed`].
    fn action_performed(&self, ctx: &mut DecompilerActionContext) -> ActionResult {
        if ctx.is_decompiling() {
            return ActionResult::Busy;
        }
        self.decompiler_action_performed(ctx)
    }

    /// Perform the actual action work.
    ///
    /// Subclasses must implement this.
    fn decompiler_action_performed(&self, ctx: &mut DecompilerActionContext) -> ActionResult;
}

/// The result of executing an abstract decompiler action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActionResult {
    /// The action completed successfully.
    Success,
    /// The action was not applicable to the current context.
    NotApplicable,
    /// The decompiler was busy; the action was not executed.
    Busy,
    /// The action failed with an error message.
    Error(String),
    /// The action requires a dialog (rename, retype, etc.).
    NeedsDialog {
        /// The prompt to show.
        prompt: String,
        /// Pre-filled value, if any.
        default_value: Option<String>,
    },
}

impl ActionResult {
    /// Returns `true` if the action succeeded.
    pub fn is_success(&self) -> bool {
        matches!(self, ActionResult::Success)
    }

    /// Returns `true` if the decompiler was busy.
    pub fn is_busy(&self) -> bool {
        matches!(self, ActionResult::Busy)
    }
}

impl fmt::Display for ActionResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ActionResult::Success => write!(f, "Success"),
            ActionResult::NotApplicable => write!(f, "NotApplicable"),
            ActionResult::Busy => write!(f, "Busy"),
            ActionResult::Error(msg) => write!(f, "Error: {}", msg),
            ActionResult::NeedsDialog { prompt, .. } => write!(f, "NeedsDialog: {}", prompt),
        }
    }
}

// ---------------------------------------------------------------------------
// Utility: get_composite_data_type
// ---------------------------------------------------------------------------

/// Extract the composite (struct/union) data type associated with a field token.
///
/// In Ghidra this is `AbstractDecompilerAction.getCompositeDataType(ClangToken)`.
/// The token must be a `ClangFieldToken`; the method looks up the data type
/// of the field and, if it is a `Composite` (struct/union), returns it.
/// If the data type is a `TypeDef`, it unwraps to the base type first.
///
/// # Arguments
///
/// * `token` - The token under the cursor (should be a field token).
/// * `composites` - A lookup function that resolves a type name to a composite.
///
/// # Returns
///
/// The composite data type, or `None` if the token is not a field token
/// or the type is not a struct/union.
pub fn get_composite_data_type(
    token: &ClangTokenRef,
    composites: &dyn Fn(&str) -> Option<CompositeDataType>,
) -> Option<CompositeDataType> {
    if token.kind != ClangTokenKind::Field {
        return None;
    }

    // In Ghidra, ClangFieldToken.getDataType() returns the field's type.
    // We use the token text as a proxy for the field name, and look up the
    // containing composite type.  The full implementation would consult the
    // decompiler's type hierarchy.
    let type_name = &token.text;

    // Try direct lookup.
    if let Some(dt) = composites(type_name) {
        return Some(dt);
    }

    // In the full implementation, TypeDef unwrapping would happen here.
    None
}

// ---------------------------------------------------------------------------
// Utility: check_full_commit
// ---------------------------------------------------------------------------

/// Compare the HighFunction's prototype with the Function's prototype.
///
/// Returns `true` if there is a difference requiring a full commit.
/// If a specific symbol is being changed, it can be passed to check
/// whether the prototype is being affected.
///
/// In Ghidra this is `AbstractDecompilerAction.checkFullCommit(HighSymbol, HighFunction)`.
///
/// # Arguments
///
/// * `high_symbol` - The symbol being modified (if any).  If it is not a
///   parameter, this function returns `false` immediately.
/// * `parameters` - The function's current parameters.
/// * `high_params` - The high-level parameter info from the decompiler.
///
/// # Returns
///
/// `true` if the prototypes differ and a full commit is required.
pub fn check_full_commit(
    high_symbol: Option<&ParameterInfo>,
    parameters: &[VariableStorage],
    high_params: &[ParameterInfo],
) -> bool {
    // If a specific symbol is being changed and it's not a parameter,
    // the prototype is not affected.
    if let Some(sym) = high_symbol {
        if !sym.is_parameter {
            return false;
        }
    }

    // Compare parameter counts.
    if high_params.len() != parameters.len() {
        return true;
    }

    // Compare each parameter's storage.
    for (i, high_param) in high_params.iter().enumerate() {
        if high_param.category_index != i {
            return true;
        }
        // Don't compare using exact equality; use storage_matches for
        // DynamicVariableStorage compatibility.
        if !high_param.storage.storage_matches(&parameters[i]) {
            return true;
        }
    }

    false
}

// ---------------------------------------------------------------------------
// Utility: get_symbol_for_context
// ---------------------------------------------------------------------------

/// Find the symbol at the current context.
///
/// Prefers the decompiler's function reference over the program location's
/// address.  If the token is a function-name token, returns the function's
/// symbol.  Otherwise falls back to the primary symbol at the context
/// address.
///
/// In Ghidra this is `AbstractDecompilerAction.getSymbol(DecompilerActionContext)`.
pub fn get_symbol_for_context(ctx: &DecompilerActionContext) -> Option<SymbolInfo> {
    // Prefer the decompiler's function reference.
    if let Some(token) = ctx.token_at_cursor() {
        if token.is_func_name_token() {
            return Some(SymbolInfo {
                name: token.text.clone(),
                address: token.function_entry,
                is_function: true,
                source: SymbolSource::UserDefined,
            });
        }
    }

    // Fall back to the primary symbol at the context address.
    // In the full implementation, this consults the SymbolTable.
    None
}

/// Information about a symbol.
#[derive(Debug, Clone)]
pub struct SymbolInfo {
    /// The symbol name.
    pub name: String,
    /// The symbol's address (if known).
    pub address: Option<Address>,
    /// Whether this symbol is a function.
    pub is_function: bool,
    /// The symbol source.
    pub source: SymbolSource,
}

impl SymbolInfo {
    /// Create a new symbol info.
    pub fn new(
        name: impl Into<String>,
        address: Option<Address>,
        is_function: bool,
        source: SymbolSource,
    ) -> Self {
        Self {
            name: name.into(),
            address,
            is_function,
            source,
        }
    }
}

impl fmt::Display for SymbolInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Symbol({})", self.name)
    }
}

/// The source of a symbol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SymbolSource {
    /// User-defined (the user renamed it).
    UserDefined,
    /// Imported from debug info.
    DebugInfo,
    /// Default (compiler-generated).
    Default,
    /// Analysis (discovered by auto-analysis).
    Analysis,
}

// ---------------------------------------------------------------------------
// ActionRegistry -- manages registered decompiler actions
// ---------------------------------------------------------------------------

/// A registry of decompiler actions.
///
/// Actions are registered with the provider and can be looked up by name.
/// The registry also maintains the ordering of actions in popup menus.
#[derive(Debug, Default)]
pub struct ActionRegistry {
    /// Registered action names in registration order.
    actions: Vec<ActionEntry>,
}

/// An entry in the action registry.
#[derive(Debug, Clone)]
pub struct ActionEntry {
    /// The action name (unique identifier).
    pub name: String,
    /// The menu group.
    pub group: String,
    /// The sub-group position.
    pub sub_group: u32,
    /// Whether this action is a local action.
    pub is_local: bool,
    /// Whether this action is a toggle action.
    pub is_toggle: bool,
    /// The key binding (if any).
    pub key_binding: Option<String>,
}

impl ActionRegistry {
    /// Create a new empty action registry.
    pub fn new() -> Self {
        Self {
            actions: Vec::new(),
        }
    }

    /// Register an action.
    pub fn register(
        &mut self,
        name: impl Into<String>,
        group: impl Into<String>,
        sub_group: u32,
        is_local: bool,
        is_toggle: bool,
        key_binding: Option<String>,
    ) {
        self.actions.push(ActionEntry {
            name: name.into(),
            group: group.into(),
            sub_group,
            is_local,
            is_toggle,
            key_binding,
        });
    }

    /// Find an action by name.
    pub fn find(&self, name: &str) -> Option<&ActionEntry> {
        self.actions.iter().find(|a| a.name == name)
    }

    /// Returns the number of registered actions.
    pub fn count(&self) -> usize {
        self.actions.len()
    }

    /// Iterate over all registered actions.
    pub fn iter(&self) -> impl Iterator<Item = &ActionEntry> {
        self.actions.iter()
    }

    /// Get actions sorted by group and sub-group.
    pub fn sorted_by_group(&self) -> Vec<&ActionEntry> {
        let mut sorted: Vec<&ActionEntry> = self.actions.iter().collect();
        sorted.sort_by(|a, b| {
            a.group
                .cmp(&b.group)
                .then_with(|| a.sub_group.cmp(&b.sub_group))
        });
        sorted
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ghidra_core::addr::Address;

    // --- CompositeDataType ---

    #[test]
    fn test_composite_new() {
        let dt = CompositeDataType::new("MyStruct", CompositeKind::Struct, 16);
        assert_eq!(dt.name, "MyStruct");
        assert_eq!(dt.kind, CompositeKind::Struct);
        assert_eq!(dt.size, 16);
        assert_eq!(dt.field_count(), 0);
    }

    #[test]
    fn test_composite_add_field() {
        let mut dt = CompositeDataType::new("MyStruct", CompositeKind::Struct, 8);
        dt.add_field(FieldInfo {
            name: "x".into(),
            offset: 0,
            size: 4,
            type_name: "int".into(),
        });
        dt.add_field(FieldInfo {
            name: "y".into(),
            offset: 4,
            size: 4,
            type_name: "int".into(),
        });
        assert_eq!(dt.field_count(), 2);
    }

    #[test]
    fn test_composite_find_field() {
        let mut dt = CompositeDataType::new("Point", CompositeKind::Struct, 8);
        dt.add_field(FieldInfo {
            name: "x".into(),
            offset: 0,
            size: 4,
            type_name: "int".into(),
        });
        assert!(dt.find_field("x").is_some());
        assert!(dt.find_field("z").is_none());
    }

    #[test]
    fn test_composite_display() {
        let dt = CompositeDataType::new("MyUnion", CompositeKind::Union, 4);
        let s = format!("{}", dt);
        assert!(s.contains("union"));
        assert!(s.contains("MyUnion"));
    }

    // --- VariableStorage ---

    #[test]
    fn test_storage_matches() {
        let a = VariableStorage::new("RAX", 0);
        let b = VariableStorage::new("RAX", 0);
        let c = VariableStorage::new("RBX", 0);
        assert!(a.storage_matches(&b));
        assert!(!a.storage_matches(&c));
    }

    #[test]
    fn test_storage_first_use_offset() {
        let a = VariableStorage::new("RAX", 1);
        let b = VariableStorage::new("RAX", 2);
        assert!(!a.storage_matches(&b));
    }

    // --- check_full_commit ---

    #[test]
    fn test_check_full_commit_no_symbol() {
        let params = vec![
            VariableStorage::new("RDI", 0),
            VariableStorage::new("RSI", 0),
        ];
        let high_params = vec![
            ParameterInfo::new(0, VariableStorage::new("RDI", 0), true),
            ParameterInfo::new(1, VariableStorage::new("RSI", 0), true),
        ];
        assert!(!check_full_commit(None, &params, &high_params));
    }

    #[test]
    fn test_check_full_commit_non_parameter_symbol() {
        let sym = ParameterInfo::new(0, VariableStorage::new("RAX", 0), false);
        let params = vec![VariableStorage::new("RDI", 0)];
        let high_params = vec![];
        assert!(!check_full_commit(Some(&sym), &params, &high_params));
    }

    #[test]
    fn test_check_full_commit_different_count() {
        let sym = ParameterInfo::new(0, VariableStorage::new("RDI", 0), true);
        let params = vec![VariableStorage::new("RDI", 0)];
        let high_params = vec![
            ParameterInfo::new(0, VariableStorage::new("RDI", 0), true),
            ParameterInfo::new(1, VariableStorage::new("RSI", 0), true),
        ];
        assert!(check_full_commit(Some(&sym), &params, &high_params));
    }

    #[test]
    fn test_check_full_commit_same_prototype() {
        let params = vec![
            VariableStorage::new("RDI", 0),
            VariableStorage::new("RSI", 0),
        ];
        let high_params = vec![
            ParameterInfo::new(0, VariableStorage::new("RDI", 0), true),
            ParameterInfo::new(1, VariableStorage::new("RSI", 0), true),
        ];
        assert!(!check_full_commit(None, &params, &high_params));
    }

    #[test]
    fn test_check_full_commit_different_storage() {
        let params = vec![VariableStorage::new("RDI", 0)];
        let high_params = vec![ParameterInfo::new(0, VariableStorage::new("RSI", 0), true)];
        assert!(check_full_commit(None, &params, &high_params));
    }

    #[test]
    fn test_check_full_commit_wrong_category_index() {
        let params = vec![VariableStorage::new("RDI", 0)];
        let high_params = vec![ParameterInfo::new(5, VariableStorage::new("RDI", 0), true)];
        assert!(check_full_commit(None, &params, &high_params));
    }

    // --- ActionResult ---

    #[test]
    fn test_action_result_success() {
        assert!(ActionResult::Success.is_success());
        assert!(!ActionResult::Success.is_busy());
    }

    #[test]
    fn test_action_result_busy() {
        assert!(ActionResult::Busy.is_busy());
        assert!(!ActionResult::Busy.is_success());
    }

    #[test]
    fn test_action_result_display() {
        assert_eq!(format!("{}", ActionResult::Success), "Success");
        assert_eq!(format!("{}", ActionResult::Busy), "Busy");
        assert_eq!(format!("{}", ActionResult::NotApplicable), "NotApplicable");
    }

    // --- ActionRegistry ---

    #[test]
    fn test_registry_new() {
        let registry = ActionRegistry::new();
        assert_eq!(registry.count(), 0);
    }

    #[test]
    fn test_registry_register() {
        let mut registry = ActionRegistry::new();
        registry.register("Rename Local", "2 - Variable Group", 0, true, false, None);
        registry.register("Rename Global", "2 - Variable Group", 1, true, false, None);
        assert_eq!(registry.count(), 2);
    }

    #[test]
    fn test_registry_find() {
        let mut registry = ActionRegistry::new();
        registry.register("Find", "Comment2 - Search Group", 0, true, false, Some("Ctrl+F".into()));
        let entry = registry.find("Find").unwrap();
        assert_eq!(entry.group, "Comment2 - Search Group");
        assert_eq!(entry.key_binding, Some("Ctrl+F".into()));
    }

    #[test]
    fn test_registry_find_missing() {
        let registry = ActionRegistry::new();
        assert!(registry.find("NonExistent").is_none());
    }

    #[test]
    fn test_registry_sorted_by_group() {
        let mut registry = ActionRegistry::new();
        registry.register("C", "Group B", 1, true, false, None);
        registry.register("A", "Group A", 0, true, false, None);
        registry.register("B", "Group A", 1, true, false, None);

        let sorted = registry.sorted_by_group();
        assert_eq!(sorted[0].name, "A");
        assert_eq!(sorted[1].name, "B");
        assert_eq!(sorted[2].name, "C");
    }

    // --- SymbolInfo ---

    #[test]
    fn test_symbol_info_display() {
        let sym = SymbolInfo::new("main", None, true, SymbolSource::UserDefined);
        assert_eq!(format!("{}", sym), "Symbol(main)");
    }

    #[test]
    fn test_symbol_source_variants() {
        assert_ne!(SymbolSource::UserDefined, SymbolSource::Default);
        assert_ne!(SymbolSource::DebugInfo, SymbolSource::Analysis);
    }
}
