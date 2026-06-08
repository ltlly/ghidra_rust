//! EditExternalLocationAction -- action for editing an existing external
//! location or external function.
//!
//! Ported from
//! `ghidra.app.plugin.core.symboltree.actions.EditExternalLocationAction`.
//!
//! This is a local action intended for components which supply a
//! `ProgramSymbolActionContext`.  It is enabled when exactly one
//! external symbol (label or function) is selected.  When triggered
//! it opens a dialog that allows the user to edit the selected external
//! location.
//!
//! # Examples
//!
//! ```rust
//! use ghidra_features::external::EditExternalLocationAction;
//!
//! let action = EditExternalLocationAction::new("SymbolTreePlugin");
//! assert_eq!(action.name(), "Edit External Location");
//! assert!(action.is_enabled());
//! ```

use std::fmt;

use ghidra_core::symbol::SymbolType;

use super::go_to_external_location_action::SymbolInfo;

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

/// Errors that can occur during the edit-external-location action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EditExternalLocationError {
    /// No symbol was selected.
    NoSymbol,
    /// Multiple symbols were selected (only one is allowed).
    MultipleSymbols(usize),
    /// The selected symbol is not an external location.
    NotExternal(String),
    /// The symbol type is not supported (must be label or function).
    UnsupportedSymbolType(String),
    /// The external location was not found in the external manager.
    LocationNotFound(String),
    /// General error.
    Other(String),
}

impl fmt::Display for EditExternalLocationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EditExternalLocationError::NoSymbol => write!(f, "No symbol selected"),
            EditExternalLocationError::MultipleSymbols(count) => {
                write!(f, "Expected 1 symbol, got {}", count)
            }
            EditExternalLocationError::NotExternal(name) => {
                write!(f, "Symbol '{}' is not an external location", name)
            }
            EditExternalLocationError::UnsupportedSymbolType(name) => {
                write!(
                    f,
                    "Symbol '{}' has unsupported type (must be label or function)",
                    name
                )
            }
            EditExternalLocationError::LocationNotFound(name) => {
                write!(f, "External location not found for '{}'", name)
            }
            EditExternalLocationError::Other(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for EditExternalLocationError {}

// ---------------------------------------------------------------------------
// EditExternalLocationAction
// ---------------------------------------------------------------------------

/// Action for editing an existing external location or external function.
///
/// This is the Rust port of Ghidra's `EditExternalLocationAction`.
/// It is a context-sensitive action that:
///
/// 1. Checks whether exactly one external symbol (label or function) is
///    selected.
/// 2. When triggered, resolves the symbol to an `ExternalLocation` and
///    opens the edit dialog.
///
/// # Examples
///
/// ```rust
/// use ghidra_features::external::edit_external_location_action::EditExternalLocationAction;
/// use ghidra_features::external::go_to_external_location_action::SymbolInfo;
/// use ghidra_core::symbol::SymbolType;
///
/// let action = EditExternalLocationAction::new("SymbolTreePlugin");
///
/// // Check if action is enabled for an external function
/// let sym = SymbolInfo::new(
///     "printf", true, SymbolType::Function,
///     None, Some("libc"), Some("printf"),
/// );
/// assert!(action.can_edit(&sym));
///
/// // Check if action is disabled for a non-external symbol
/// let local = SymbolInfo::new(
///     "main", false, SymbolType::Function,
///     None, None, None,
/// );
/// assert!(!action.can_edit(&local));
/// ```
#[derive(Debug, Clone)]
pub struct EditExternalLocationAction {
    /// The action name.
    name: String,
    /// The owning plugin name.
    plugin_name: String,
    /// Whether the action is enabled.
    enabled: bool,
}

impl EditExternalLocationAction {
    /// Create a new edit-external-location action.
    ///
    /// * `plugin_name` -- the name of the owning plugin (used for
    ///   menu grouping and help location).
    pub fn new(plugin_name: impl Into<String>) -> Self {
        Self {
            name: "Edit External Location".to_string(),
            plugin_name: plugin_name.into(),
            enabled: true,
        }
    }

    /// Returns the action name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the owning plugin name.
    pub fn plugin_name(&self) -> &str {
        &self.plugin_name
    }

    /// Returns whether the action is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Set whether the action is enabled.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Check if the action can edit the given symbol.
    ///
    /// Returns `true` if the symbol is external and is either a LABEL
    /// or FUNCTION type.  This is the equivalent of
    /// `getExternalSymbol()` returning non-null in the Java
    /// implementation.
    pub fn can_edit(&self, symbol: &SymbolInfo) -> bool {
        if !symbol.is_external {
            return false;
        }
        matches!(symbol.symbol_type, SymbolType::Label | SymbolType::Function)
    }

    /// Validate the action context and return the symbol info.
    ///
    /// This performs the same checks as `isEnabledForContext()` in the
    /// Java implementation: exactly one symbol, it must be external,
    /// and it must be a label or function.
    ///
    /// # Arguments
    ///
    /// * `symbols` -- the list of selected symbols (must contain exactly
    ///   one element).
    ///
    /// # Returns
    ///
    /// Returns the validated symbol info, or an error.
    pub fn validate_context<'a>(
        &self,
        symbols: &'a [SymbolInfo],
    ) -> Result<&'a SymbolInfo, EditExternalLocationError> {
        if symbols.is_empty() {
            return Err(EditExternalLocationError::NoSymbol);
        }
        if symbols.len() > 1 {
            return Err(EditExternalLocationError::MultipleSymbols(symbols.len()));
        }
        let symbol = &symbols[0];
        if !symbol.is_external {
            return Err(EditExternalLocationError::NotExternal(symbol.name.clone()));
        }
        if !matches!(symbol.symbol_type, SymbolType::Label | SymbolType::Function) {
            return Err(EditExternalLocationError::UnsupportedSymbolType(
                symbol.name.clone(),
            ));
        }
        Ok(symbol)
    }

    /// Execute the edit-external-location action.
    ///
    /// Validates the context and returns the information needed to open
    /// the edit dialog.  In the Java implementation this corresponds to
    /// `actionPerformed()`.
    ///
    /// # Arguments
    ///
    /// * `symbols` -- the list of selected symbols.
    ///
    /// # Returns
    ///
    /// Returns the validated symbol info on success.
    pub fn execute<'a>(
        &self,
        symbols: &'a [SymbolInfo],
    ) -> Result<&'a SymbolInfo, EditExternalLocationError> {
        self.validate_context(symbols)
    }
}

impl Default for EditExternalLocationAction {
    fn default() -> Self {
        Self::new("UnknownPlugin")
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ghidra_core::addr::Address;

    #[test]
    fn test_action_properties() {
        let action = EditExternalLocationAction::new("SymbolTreePlugin");
        assert_eq!(action.name(), "Edit External Location");
        assert_eq!(action.plugin_name(), "SymbolTreePlugin");
        assert!(action.is_enabled());
    }

    #[test]
    fn test_action_set_enabled() {
        let mut action = EditExternalLocationAction::new("SymbolTreePlugin");
        assert!(action.is_enabled());
        action.set_enabled(false);
        assert!(!action.is_enabled());
        action.set_enabled(true);
        assert!(action.is_enabled());
    }

    #[test]
    fn test_can_edit_external_function() {
        let action = EditExternalLocationAction::new("SymbolTreePlugin");
        let sym = SymbolInfo::new(
            "printf",
            true,
            SymbolType::Function,
            Some(Address::new(0x401000)),
            Some("libc"),
            Some("printf"),
        );
        assert!(action.can_edit(&sym));
    }

    #[test]
    fn test_can_edit_external_label() {
        let action = EditExternalLocationAction::new("SymbolTreePlugin");
        let sym = SymbolInfo::new(
            "errno",
            true,
            SymbolType::Label,
            None,
            Some("libc"),
            Some("errno"),
        );
        assert!(action.can_edit(&sym));
    }

    #[test]
    fn test_cannot_edit_non_external() {
        let action = EditExternalLocationAction::new("SymbolTreePlugin");
        let sym = SymbolInfo::new(
            "main",
            false,
            SymbolType::Function,
            Some(Address::new(0x400000)),
            None,
            None,
        );
        assert!(!action.can_edit(&sym));
    }

    #[test]
    fn test_cannot_edit_external_class() {
        let action = EditExternalLocationAction::new("SymbolTreePlugin");
        let sym = SymbolInfo::new(
            "MyClass",
            true,
            SymbolType::Class,
            None,
            Some("somelib"),
            Some("MyClass"),
        );
        assert!(!action.can_edit(&sym));
    }

    #[test]
    fn test_validate_context_empty() {
        let action = EditExternalLocationAction::new("SymbolTreePlugin");
        let symbols: Vec<SymbolInfo> = vec![];
        let result = action.validate_context(&symbols);
        assert!(result.is_err());
        match result.unwrap_err() {
            EditExternalLocationError::NoSymbol => {}
            _ => panic!("Expected NoSymbol error"),
        }
    }

    #[test]
    fn test_validate_context_multiple() {
        let action = EditExternalLocationAction::new("SymbolTreePlugin");
        let symbols = vec![
            SymbolInfo::new(
                "printf",
                true,
                SymbolType::Function,
                None,
                Some("libc"),
                Some("printf"),
            ),
            SymbolInfo::new(
                "malloc",
                true,
                SymbolType::Function,
                None,
                Some("libc"),
                Some("malloc"),
            ),
        ];
        let result = action.validate_context(&symbols);
        assert!(result.is_err());
        match result.unwrap_err() {
            EditExternalLocationError::MultipleSymbols(2) => {}
            _ => panic!("Expected MultipleSymbols error"),
        }
    }

    #[test]
    fn test_validate_context_not_external() {
        let action = EditExternalLocationAction::new("SymbolTreePlugin");
        let symbols = vec![SymbolInfo::new(
            "main",
            false,
            SymbolType::Function,
            Some(Address::new(0x400000)),
            None,
            None,
        )];
        let result = action.validate_context(&symbols);
        assert!(result.is_err());
        match result.unwrap_err() {
            EditExternalLocationError::NotExternal(_) => {}
            _ => panic!("Expected NotExternal error"),
        }
    }

    #[test]
    fn test_validate_context_unsupported_type() {
        let action = EditExternalLocationAction::new("SymbolTreePlugin");
        let symbols = vec![SymbolInfo::new(
            "MyClass",
            true,
            SymbolType::Class,
            None,
            Some("somelib"),
            Some("MyClass"),
        )];
        let result = action.validate_context(&symbols);
        assert!(result.is_err());
        match result.unwrap_err() {
            EditExternalLocationError::UnsupportedSymbolType(_) => {}
            _ => panic!("Expected UnsupportedSymbolType error"),
        }
    }

    #[test]
    fn test_validate_context_success() {
        let action = EditExternalLocationAction::new("SymbolTreePlugin");
        let symbols = vec![SymbolInfo::new(
            "printf",
            true,
            SymbolType::Function,
            Some(Address::new(0x401000)),
            Some("libc"),
            Some("printf"),
        )];
        let sym = action.validate_context(&symbols).unwrap();
        assert_eq!(sym.name, "printf");
        assert!(sym.is_external);
    }

    #[test]
    fn test_execute_success() {
        let action = EditExternalLocationAction::new("SymbolTreePlugin");
        let symbols = vec![SymbolInfo::new(
            "printf",
            true,
            SymbolType::Function,
            Some(Address::new(0x401000)),
            Some("libc"),
            Some("printf"),
        )];
        let sym = action.execute(&symbols).unwrap();
        assert_eq!(sym.name, "printf");
    }

    #[test]
    fn test_error_display() {
        let err = EditExternalLocationError::NoSymbol;
        assert_eq!(err.to_string(), "No symbol selected");

        let err = EditExternalLocationError::MultipleSymbols(3);
        assert!(err.to_string().contains("3"));

        let err = EditExternalLocationError::NotExternal("main".to_string());
        assert!(err.to_string().contains("main"));

        let err = EditExternalLocationError::UnsupportedSymbolType("MyClass".to_string());
        assert!(err.to_string().contains("MyClass"));

        let err = EditExternalLocationError::LocationNotFound("foo".to_string());
        assert!(err.to_string().contains("foo"));

        let err = EditExternalLocationError::Other("something".to_string());
        assert_eq!(err.to_string(), "something");
    }

    #[test]
    fn test_default() {
        let action = EditExternalLocationAction::default();
        assert_eq!(action.plugin_name(), "UnknownPlugin");
    }
}
