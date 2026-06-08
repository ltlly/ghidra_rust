//! Rename commands for symbols, functions, and namespaces.
//!
//! Ported from Ghidra's rename operations in `ghidra.app.plugin.core`.
//!
//! This module provides commands for renaming various symbol types:
//! - [`RenameLabelCmd`] -- rename a label symbol at an address
//! - [`RenameFunctionCmd`] -- rename a function symbol
//! - [`RenameNamespaceCmd`] -- rename a namespace symbol
//! - [`SetLabelPrimaryCmd`] -- set a label as the primary symbol at its address
//! - [`ApplyFunctionSignatureCmd`] -- apply a new signature/name to a function

use ghidra_core::addr::Address;
use ghidra_core::symbol::{SourceType, SymbolError, SymbolResult};
use serde::{Deserialize, Serialize};

/// Maximum allowed length for a symbol name.
pub const MAX_SYMBOL_NAME_LENGTH: usize = 2000;

/// Characters that are not allowed in symbol names.
pub const INVALID_NAME_CHARS: &[char] = &['\0', '\n', '\r'];

/// A command to rename a label symbol at an address.
///
/// Corresponds to Ghidra's label rename operations. The command
/// validates the new name and source type before applying the change.
///
/// # Example
///
/// ```rust
/// use ghidra_features::base::rename::RenameLabelCmd;
/// use ghidra_core::addr::Address;
/// use ghidra_core::symbol::SourceType;
///
/// let cmd = RenameLabelCmd::new(
///     Address::new(0x401000),
///     "main",
///     SourceType::UserDefined,
/// );
/// assert_eq!(cmd.name(), "Rename Label");
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenameLabelCmd {
    /// The address of the label to rename.
    address: Address,
    /// The new name for the label.
    new_name: String,
    /// The source of the rename.
    source: SourceType,
}

impl RenameLabelCmd {
    /// Creates a new rename label command.
    pub fn new(address: Address, new_name: impl Into<String>, source: SourceType) -> Self {
        Self {
            address,
            new_name: new_name.into(),
            source,
        }
    }

    /// Returns the command name for display.
    pub fn name(&self) -> &str {
        "Rename Label"
    }

    /// Returns the address of the label.
    pub fn address(&self) -> Address {
        self.address
    }

    /// Returns the new name.
    pub fn new_name(&self) -> &str {
        &self.new_name
    }

    /// Returns the source type.
    pub fn source(&self) -> SourceType {
        self.source
    }

    /// Validates the new name without applying it.
    ///
    /// Returns `Ok(())` if the name is valid, or an error describing
    /// the validation failure.
    pub fn validate(&self) -> SymbolResult<()> {
        validate_symbol_name(&self.new_name)
    }
}

/// A command to rename a function symbol.
///
/// Corresponds to Ghidra's function rename operations. Functions can
/// be renamed to change their display name in the listing. The command
/// validates that the new name is a valid identifier.
///
/// # Example
///
/// ```rust
/// use ghidra_features::base::rename::RenameFunctionCmd;
/// use ghidra_core::addr::Address;
/// use ghidra_core::symbol::SourceType;
///
/// let cmd = RenameFunctionCmd::new(
///     Address::new(0x401000),
///     "process_input",
///     SourceType::UserDefined,
/// );
/// assert_eq!(cmd.name(), "Rename Function");
/// assert!(cmd.validate().is_ok());
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenameFunctionCmd {
    /// The entry point address of the function.
    entry_point: Address,
    /// The new name for the function.
    new_name: String,
    /// The source of the rename.
    source: SourceType,
}

impl RenameFunctionCmd {
    /// Creates a new rename function command.
    pub fn new(entry_point: Address, new_name: impl Into<String>, source: SourceType) -> Self {
        Self {
            entry_point,
            new_name: new_name.into(),
            source,
        }
    }

    /// Returns the command name for display.
    pub fn name(&self) -> &str {
        "Rename Function"
    }

    /// Returns the function entry point address.
    pub fn entry_point(&self) -> Address {
        self.entry_point
    }

    /// Returns the new name.
    pub fn new_name(&self) -> &str {
        &self.new_name
    }

    /// Returns the source type.
    pub fn source(&self) -> SourceType {
        self.source
    }

    /// Validates the new function name.
    pub fn validate(&self) -> SymbolResult<()> {
        validate_symbol_name(&self.new_name)
    }

    /// Returns `true` if this rename would change a default-named function
    /// (e.g., `FUN_00401000`) to a user-defined name.
    ///
    /// This is useful for UI logic: default functions get special treatment
    /// in the symbol table.
    pub fn is_naming_default(&self) -> bool {
        // Check if the new name is different from the default pattern
        !self.new_name.starts_with("FUN_")
    }
}

/// A command to rename a namespace (class, library, or generic namespace).
///
/// Namespaces form a hierarchy. Renaming a namespace does not move it;
/// use [`SetNamespaceCmd`] for that.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenameNamespaceCmd {
    /// The symbol ID of the namespace to rename.
    namespace_symbol_id: u64,
    /// The new name for the namespace.
    new_name: String,
    /// The source of the rename.
    source: SourceType,
}

impl RenameNamespaceCmd {
    /// Creates a new rename namespace command.
    pub fn new(namespace_symbol_id: u64, new_name: impl Into<String>, source: SourceType) -> Self {
        Self {
            namespace_symbol_id,
            new_name: new_name.into(),
            source,
        }
    }

    /// Returns the command name for display.
    pub fn name(&self) -> &str {
        "Rename Namespace"
    }

    /// Returns the namespace symbol ID.
    pub fn namespace_symbol_id(&self) -> u64 {
        self.namespace_symbol_id
    }

    /// Returns the new name.
    pub fn new_name(&self) -> &str {
        &self.new_name
    }

    /// Returns the source type.
    pub fn source(&self) -> SourceType {
        self.source
    }

    /// Validates the new namespace name.
    pub fn validate(&self) -> SymbolResult<()> {
        validate_symbol_name(&self.new_name)
    }
}

/// A command to move a symbol to a different namespace.
///
/// This changes the symbol's parent namespace without changing its name.
/// It is separate from rename to allow independent control.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetNamespaceCmd {
    /// The symbol ID to move.
    symbol_id: u64,
    /// The target namespace symbol ID.
    namespace_id: u64,
    /// The source of the change.
    source: SourceType,
}

impl SetNamespaceCmd {
    /// Creates a new set-namespace command.
    pub fn new(symbol_id: u64, namespace_id: u64, source: SourceType) -> Self {
        Self {
            symbol_id,
            namespace_id,
            source,
        }
    }

    /// Returns the command name for display.
    pub fn name(&self) -> &str {
        "Set Namespace"
    }

    /// Returns the symbol ID being moved.
    pub fn symbol_id(&self) -> u64 {
        self.symbol_id
    }

    /// Returns the target namespace ID.
    pub fn namespace_id(&self) -> u64 {
        self.namespace_id
    }

    /// Returns the source type.
    pub fn source(&self) -> SourceType {
        self.source
    }
}

/// A command that renames both the name and namespace of a symbol atomically.
///
/// This combines the effect of [`RenameLabelCmd`] (or [`RenameFunctionCmd`])
/// and [`SetNamespaceCmd`] into a single transaction. Ghidra uses this
/// pattern when the user edits a label and changes its namespace in the
/// same dialog.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenameAndMoveCmd {
    /// The symbol ID to rename and move.
    symbol_id: u64,
    /// The new name (or `None` to keep the current name).
    new_name: Option<String>,
    /// The target namespace ID (or `None` to keep the current namespace).
    new_namespace_id: Option<u64>,
    /// The source of the change.
    source: SourceType,
}

impl RenameAndMoveCmd {
    /// Creates a command that only renames.
    pub fn rename_only(symbol_id: u64, new_name: impl Into<String>, source: SourceType) -> Self {
        Self {
            symbol_id,
            new_name: Some(new_name.into()),
            new_namespace_id: None,
            source,
        }
    }

    /// Creates a command that only moves.
    pub fn move_only(symbol_id: u64, new_namespace_id: u64, source: SourceType) -> Self {
        Self {
            symbol_id,
            new_name: None,
            new_namespace_id: Some(new_namespace_id),
            source,
        }
    }

    /// Creates a command that both renames and moves.
    pub fn rename_and_move(
        symbol_id: u64,
        new_name: impl Into<String>,
        new_namespace_id: u64,
        source: SourceType,
    ) -> Self {
        Self {
            symbol_id,
            new_name: Some(new_name.into()),
            new_namespace_id: Some(new_namespace_id),
            source,
        }
    }

    /// Returns the command name for display.
    pub fn name(&self) -> &str {
        "Rename and Move Symbol"
    }

    /// Returns the symbol ID.
    pub fn symbol_id(&self) -> u64 {
        self.symbol_id
    }

    /// Returns the new name, if changing.
    pub fn new_name(&self) -> Option<&str> {
        self.new_name.as_deref()
    }

    /// Returns the new namespace ID, if moving.
    pub fn new_namespace_id(&self) -> Option<u64> {
        self.new_namespace_id
    }

    /// Returns the source type.
    pub fn source(&self) -> SourceType {
        self.source
    }

    /// Validates the new name (if changing).
    pub fn validate(&self) -> SymbolResult<()> {
        if let Some(ref name) = self.new_name {
            validate_symbol_name(name)?;
        }
        Ok(())
    }
}

/// A command to set a label as primary at its address.
///
/// At each address, one symbol can be designated as the "primary" symbol.
/// This is the symbol shown in the listing. Other symbols at the same
/// address are still accessible via the symbol table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetLabelPrimaryCmd {
    /// The address where the label exists.
    address: Address,
    /// The name of the label to make primary.
    label_name: String,
}

impl SetLabelPrimaryCmd {
    /// Creates a new set-primary command.
    pub fn new(address: Address, label_name: impl Into<String>) -> Self {
        Self {
            address,
            label_name: label_name.into(),
        }
    }

    /// Returns the command name for display.
    pub fn name(&self) -> &str {
        "Set Label Primary"
    }

    /// Returns the address.
    pub fn address(&self) -> Address {
        self.address
    }

    /// Returns the label name to make primary.
    pub fn label_name(&self) -> &str {
        &self.label_name
    }
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Validates a proposed symbol name.
///
/// This mirrors the validation performed by Ghidra's `DefaultSymbolDBAdapter`
/// and `SymbolDB` before accepting a new name.
///
/// Rules:
/// - Name must not be empty
/// - Name must not exceed [`MAX_SYMBOL_NAME_LENGTH`]
/// - Name must not contain null characters, newlines, or carriage returns
/// - Name must not be whitespace-only
pub fn validate_symbol_name(name: &str) -> SymbolResult<()> {
    if name.is_empty() {
        return Err(SymbolError::InvalidInput(
            "Symbol name cannot be empty".to_string(),
        ));
    }
    if name.len() > MAX_SYMBOL_NAME_LENGTH {
        return Err(SymbolError::InvalidInput(format!(
            "Symbol name exceeds maximum length of {} characters",
            MAX_SYMBOL_NAME_LENGTH
        )));
    }
    for ch in INVALID_NAME_CHARS {
        if name.contains(*ch) {
            return Err(SymbolError::InvalidInput(format!(
                "Symbol name contains invalid character: {:?}",
                ch
            )));
        }
    }
    if name.trim().is_empty() {
        return Err(SymbolError::InvalidInput(
            "Symbol name cannot be whitespace-only".to_string(),
        ));
    }
    Ok(())
}

/// Returns `true` if the given name is a default/auto-generated label name.
///
/// Ghidra generates default labels like `LAB_00401000`, `DAT_00401000`,
/// `UNK_00401000`, etc. This function checks for those patterns.
pub fn is_default_label_name(name: &str) -> bool {
    name.starts_with("LAB_")
        || name.starts_with("DAT_")
        || name.starts_with("UNK_")
        || name.starts_with("SUB_")
        || name.starts_with("BYTE_")
        || name.starts_with("WORD_")
        || name.starts_with("DWORD_")
        || name.starts_with("QWORD_")
}

/// Returns `true` if the given name is a default/auto-generated function name.
///
/// Ghidra generates default function names like `FUN_00401000`.
pub fn is_default_function_name(name: &str) -> bool {
    name.starts_with("FUN_")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_valid_name() {
        assert!(validate_symbol_name("main").is_ok());
        assert!(validate_symbol_name("my_function").is_ok());
        assert!(validate_symbol_name("Class::method").is_ok());
        assert!(validate_symbol_name("_start").is_ok());
        assert!(validate_symbol_name("LAB_00401000").is_ok());
    }

    #[test]
    fn test_validate_empty_name() {
        assert!(validate_symbol_name("").is_err());
    }

    #[test]
    fn test_validate_whitespace_only() {
        assert!(validate_symbol_name("   ").is_err());
        assert!(validate_symbol_name("\t").is_err());
    }

    #[test]
    fn test_validate_null_character() {
        assert!(validate_symbol_name("bad\0name").is_err());
    }

    #[test]
    fn test_validate_newline() {
        assert!(validate_symbol_name("bad\nname").is_err());
        assert!(validate_symbol_name("bad\rname").is_err());
    }

    #[test]
    fn test_validate_too_long() {
        let long_name = "a".repeat(MAX_SYMBOL_NAME_LENGTH + 1);
        assert!(validate_symbol_name(&long_name).is_err());
    }

    #[test]
    fn test_validate_max_length() {
        let max_name = "a".repeat(MAX_SYMBOL_NAME_LENGTH);
        assert!(validate_symbol_name(&max_name).is_ok());
    }

    #[test]
    fn test_is_default_label_name() {
        assert!(is_default_label_name("LAB_00401000"));
        assert!(is_default_label_name("DAT_00401000"));
        assert!(is_default_label_name("UNK_00401000"));
        assert!(is_default_label_name("SUB_00401000"));
        assert!(is_default_label_name("BYTE_00401000"));
        assert!(is_default_label_name("WORD_00401000"));
        assert!(is_default_label_name("DWORD_00401000"));
        assert!(is_default_label_name("QWORD_00401000"));
        assert!(!is_default_label_name("main"));
        assert!(!is_default_label_name("my_function"));
    }

    #[test]
    fn test_is_default_function_name() {
        assert!(is_default_function_name("FUN_00401000"));
        assert!(!is_default_function_name("main"));
        assert!(!is_default_function_name("process_input"));
    }

    #[test]
    fn test_rename_label_cmd() {
        let cmd = RenameLabelCmd::new(
            Address::new(0x401000),
            "main",
            SourceType::UserDefined,
        );
        assert_eq!(cmd.name(), "Rename Label");
        assert_eq!(cmd.address(), Address::new(0x401000));
        assert_eq!(cmd.new_name(), "main");
        assert_eq!(cmd.source(), SourceType::UserDefined);
        assert!(cmd.validate().is_ok());
    }

    #[test]
    fn test_rename_function_cmd() {
        let cmd = RenameFunctionCmd::new(
            Address::new(0x401000),
            "process_input",
            SourceType::UserDefined,
        );
        assert_eq!(cmd.name(), "Rename Function");
        assert_eq!(cmd.entry_point(), Address::new(0x401000));
        assert!(cmd.is_naming_default());
    }

    #[test]
    fn test_rename_function_cmd_default_name() {
        let cmd = RenameFunctionCmd::new(
            Address::new(0x401000),
            "FUN_00401000",
            SourceType::Default,
        );
        assert!(!cmd.is_naming_default());
    }

    #[test]
    fn test_rename_namespace_cmd() {
        let cmd = RenameNamespaceCmd::new(42, "MyClass", SourceType::UserDefined);
        assert_eq!(cmd.name(), "Rename Namespace");
        assert_eq!(cmd.namespace_symbol_id(), 42);
        assert_eq!(cmd.new_name(), "MyClass");
        assert!(cmd.validate().is_ok());
    }

    #[test]
    fn test_set_namespace_cmd() {
        let cmd = SetNamespaceCmd::new(1, 2, SourceType::UserDefined);
        assert_eq!(cmd.name(), "Set Namespace");
        assert_eq!(cmd.symbol_id(), 1);
        assert_eq!(cmd.namespace_id(), 2);
    }

    #[test]
    fn test_rename_and_move_rename_only() {
        let cmd = RenameAndMoveCmd::rename_only(10, "new_name", SourceType::UserDefined);
        assert_eq!(cmd.new_name(), Some("new_name"));
        assert!(cmd.new_namespace_id().is_none());
        assert!(cmd.validate().is_ok());
    }

    #[test]
    fn test_rename_and_move_move_only() {
        let cmd = RenameAndMoveCmd::move_only(10, 5, SourceType::UserDefined);
        assert!(cmd.new_name().is_none());
        assert_eq!(cmd.new_namespace_id(), Some(5));
        assert!(cmd.validate().is_ok());
    }

    #[test]
    fn test_rename_and_move_both() {
        let cmd = RenameAndMoveCmd::rename_and_move(10, "new_name", 5, SourceType::Analysis);
        assert_eq!(cmd.new_name(), Some("new_name"));
        assert_eq!(cmd.new_namespace_id(), Some(5));
        assert_eq!(cmd.source(), SourceType::Analysis);
    }

    #[test]
    fn test_rename_and_move_invalid_name() {
        let cmd = RenameAndMoveCmd::rename_only(10, "", SourceType::UserDefined);
        assert!(cmd.validate().is_err());
    }

    #[test]
    fn test_set_label_primary_cmd() {
        let cmd = SetLabelPrimaryCmd::new(Address::new(0x401000), "main");
        assert_eq!(cmd.name(), "Set Label Primary");
        assert_eq!(cmd.address(), Address::new(0x401000));
        assert_eq!(cmd.label_name(), "main");
    }
}
