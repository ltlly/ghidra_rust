//! GoToExternalLocationAction -- action for navigating to an external
//! location in the listing.
//!
//! Ported from
//! `ghidra.app.plugin.core.symboltree.actions.GoToExternalLocationAction`.
//!
//! This action is enabled when exactly one symbol is selected in the
//! symbol tree, and that symbol is an external label or function.
//! When triggered, it navigates the listing to the external location
//! associated with the selected symbol.
//!
//! # Examples
//!
//! ```rust
//! use ghidra_features::external::{
//!     GoToExternalLocationAction, ExternalLocationDB, ExternalManagerDB,
//! };
//! use ghidra_core::symbol::SourceType;
//! use ghidra_core::addr::Address;
//!
//! let action = GoToExternalLocationAction::new("SymbolTreePlugin");
//! assert_eq!(action.name(), "Go To External Location");
//! assert!(action.is_enabled());
//! ```

use std::fmt;

use ghidra_core::addr::Address;
use ghidra_core::symbol::{ExternalLocation, ExternalManager, SourceType, SymbolType};

use super::external_location_db::ExternalLocationDB;
use super::external_manager_db::ExternalManagerDB;

// ---------------------------------------------------------------------------
// Symbol info
// ---------------------------------------------------------------------------

/// Information about a symbol in the symbol tree.
///
/// In the Java implementation this comes from the `Symbol` object.
/// This struct carries the minimum information needed to check whether
/// the action should be enabled and to perform the navigation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymbolInfo {
    /// The symbol name.
    pub name: String,
    /// Whether the symbol is external.
    pub is_external: bool,
    /// The type of the symbol (label, function, etc.).
    pub symbol_type: SymbolType,
    /// The address of the symbol (entry point for functions, or the
    /// external address for labels).
    pub address: Option<Address>,
    /// The external library name, if the symbol is external.
    pub library_name: Option<String>,
    /// The label within the external library.
    pub external_label: Option<String>,
}

impl SymbolInfo {
    /// Create a new symbol info.
    pub fn new(
        name: impl Into<String>,
        is_external: bool,
        symbol_type: SymbolType,
        address: Option<Address>,
        library_name: Option<&str>,
        external_label: Option<&str>,
    ) -> Self {
        Self {
            name: name.into(),
            is_external,
            symbol_type,
            address,
            library_name: library_name.map(|s| s.to_string()),
            external_label: external_label.map(|s| s.to_string()),
        }
    }

    /// Check if this symbol represents a navigable external location.
    ///
    /// Returns `true` if the symbol is external and is either a LABEL
    /// or FUNCTION type.
    pub fn is_navigable_external(&self) -> bool {
        self.is_external
            && matches!(
                self.symbol_type,
                SymbolType::Label | SymbolType::Function
            )
    }
}

// ---------------------------------------------------------------------------
// Navigation target
// ---------------------------------------------------------------------------

/// The result of resolving a symbol to a navigable external location.
///
/// This carries the information needed to navigate the listing to the
/// external location.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NavigationTarget {
    /// The library name containing the external location.
    pub library_name: String,
    /// The label (symbol name) within the external library.
    pub label: String,
    /// The address in the external program (if known).
    pub external_address: Option<Address>,
    /// The address in the current program that references this location.
    pub reference_address: Option<Address>,
}

impl NavigationTarget {
    /// Create a new navigation target.
    pub fn new(
        library_name: impl Into<String>,
        label: impl Into<String>,
        external_address: Option<Address>,
        reference_address: Option<Address>,
    ) -> Self {
        Self {
            library_name: library_name.into(),
            label: label.into(),
            external_address,
            reference_address,
        }
    }
}

// ---------------------------------------------------------------------------
// Action error
// ---------------------------------------------------------------------------

/// Errors that can occur during the go-to-external-location action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GoToExternalError {
    /// No symbol was selected.
    NoSymbol,
    /// The selected symbol is not an external location.
    NotExternal(String),
    /// The external location could not be resolved.
    LocationNotFound(String),
    /// General error.
    Other(String),
}

impl fmt::Display for GoToExternalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GoToExternalError::NoSymbol => write!(f, "No symbol selected"),
            GoToExternalError::NotExternal(name) => {
                write!(f, "Symbol '{}' is not an external location", name)
            }
            GoToExternalError::LocationNotFound(name) => {
                write!(f, "External location not found for '{}'", name)
            }
            GoToExternalError::Other(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for GoToExternalError {}

// ---------------------------------------------------------------------------
// GoToExternalLocationAction
// ---------------------------------------------------------------------------

/// Action for navigating to an external location in the listing.
///
/// This is the Rust port of Ghidra's `GoToExternalLocationAction`.
/// It is a context-sensitive action that:
///
/// 1. Checks whether exactly one external symbol (label or function) is
///    selected.
/// 2. When triggered, resolves the symbol to an `ExternalLocation` and
///    navigates to it.
///
/// # Examples
///
/// ```rust
/// use ghidra_features::external::go_to_external_location_action::{
///     GoToExternalLocationAction, SymbolInfo, NavigationTarget,
/// };
/// use ghidra_core::symbol::SymbolType;
/// use ghidra_core::addr::Address;
///
/// let action = GoToExternalLocationAction::new("SymbolTreePlugin");
///
/// // Check if action is enabled for an external function
/// let sym = SymbolInfo::new(
///     "printf", true, SymbolType::Function,
///     Some(Address::new(0x401000)),
///     Some("libc"), Some("printf"),
/// );
/// assert!(action.can_navigate(&sym));
///
/// // Check if action is disabled for a non-external symbol
/// let local_sym = SymbolInfo::new(
///     "main", false, SymbolType::Function,
///     Some(Address::new(0x400000)),
///     None, None,
/// );
/// assert!(!action.can_navigate(&local_sym));
/// ```
#[derive(Debug, Clone)]
pub struct GoToExternalLocationAction {
    /// The action name.
    name: String,
    /// The owning plugin name.
    plugin_name: String,
    /// Whether the action is enabled.
    enabled: bool,
}

impl GoToExternalLocationAction {
    /// Create a new go-to-external-location action.
    ///
    /// * `plugin_name` -- the name of the owning plugin (used for
    ///   menu grouping and help location).
    pub fn new(plugin_name: impl Into<String>) -> Self {
        Self {
            name: "Go To External Location".to_string(),
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

    /// Check if the action can navigate to the given symbol.
    ///
    /// Returns `true` if the symbol is an external label or function.
    /// This is the equivalent of `isEnabledForContext()` in the Java
    /// implementation.
    pub fn can_navigate(&self, symbol: &SymbolInfo) -> bool {
        symbol.is_navigable_external()
    }

    /// Resolve a symbol to a navigation target.
    ///
    /// Given a symbol and an external manager, resolves the symbol to
    /// a `NavigationTarget` that can be used to navigate the listing.
    ///
    /// # Arguments
    ///
    /// * `symbol` -- the symbol to resolve.
    /// * `ext_mgr` -- the external manager for looking up external
    ///   locations.
    ///
    /// # Returns
    ///
    /// Returns the navigation target, or an error if the symbol cannot
    /// be resolved.
    pub fn resolve_navigation(
        &self,
        symbol: &SymbolInfo,
        ext_mgr: &ExternalManagerDB,
    ) -> Result<NavigationTarget, GoToExternalError> {
        if !self.can_navigate(symbol) {
            return Err(GoToExternalError::NotExternal(symbol.name.clone()));
        }

        // Try to find the external location by library name and label
        if let (Some(lib_name), Some(label)) = (&symbol.library_name, &symbol.external_label) {
            if let Some(loc) = ext_mgr.get_external_location(lib_name, label) {
                return Ok(NavigationTarget::new(
                    lib_name,
                    label,
                    loc.external_address(),
                    symbol.address,
                ));
            }
        }

        // Try to find by symbol name through all external locations
        for loc in ext_mgr.all_locations() {
            if let Some(loc_label) = loc.label() {
                if loc_label == symbol.name {
                    return Ok(NavigationTarget::new(
                        loc.library_name(),
                        loc_label,
                        loc.external_address(),
                        symbol.address,
                    ));
                }
            }
        }

        Err(GoToExternalError::LocationNotFound(symbol.name.clone()))
    }

    /// Execute the go-to action for a single symbol.
    ///
    /// This is the high-level method that combines context checking,
    /// resolution, and navigation. In the Java implementation this
    /// corresponds to `actionPerformed()`.
    ///
    /// # Arguments
    ///
    /// * `symbol` -- the symbol to navigate to.
    /// * `ext_mgr` -- the external manager.
    ///
    /// # Returns
    ///
    /// Returns the navigation target on success.
    pub fn execute(
        &self,
        symbol: &SymbolInfo,
        ext_mgr: &ExternalManagerDB,
    ) -> Result<NavigationTarget, GoToExternalError> {
        self.resolve_navigation(symbol, ext_mgr)
    }
}

impl Default for GoToExternalLocationAction {
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

    #[test]
    fn test_action_properties() {
        let action = GoToExternalLocationAction::new("SymbolTreePlugin");
        assert_eq!(action.name(), "Go To External Location");
        assert_eq!(action.plugin_name(), "SymbolTreePlugin");
        assert!(action.is_enabled());
    }

    #[test]
    fn test_action_set_enabled() {
        let mut action = GoToExternalLocationAction::new("SymbolTreePlugin");
        assert!(action.is_enabled());
        action.set_enabled(false);
        assert!(!action.is_enabled());
        action.set_enabled(true);
        assert!(action.is_enabled());
    }

    #[test]
    fn test_can_navigate_external_function() {
        let action = GoToExternalLocationAction::new("SymbolTreePlugin");
        let sym = SymbolInfo::new(
            "printf",
            true,
            SymbolType::Function,
            Some(Address::new(0x401000)),
            Some("libc"),
            Some("printf"),
        );
        assert!(action.can_navigate(&sym));
    }

    #[test]
    fn test_can_navigate_external_label() {
        let action = GoToExternalLocationAction::new("SymbolTreePlugin");
        let sym = SymbolInfo::new(
            "errno",
            true,
            SymbolType::Label,
            None,
            Some("libc"),
            Some("errno"),
        );
        assert!(action.can_navigate(&sym));
    }

    #[test]
    fn test_cannot_navigate_non_external() {
        let action = GoToExternalLocationAction::new("SymbolTreePlugin");
        let sym = SymbolInfo::new(
            "main",
            false,
            SymbolType::Function,
            Some(Address::new(0x400000)),
            None,
            None,
        );
        assert!(!action.can_navigate(&sym));
    }

    #[test]
    fn test_cannot_navigate_external_class() {
        let action = GoToExternalLocationAction::new("SymbolTreePlugin");
        let sym = SymbolInfo::new(
            "MyClass",
            true,
            SymbolType::Class,
            None,
            Some("somelib"),
            Some("MyClass"),
        );
        assert!(!action.can_navigate(&sym));
    }

    #[test]
    fn test_resolve_navigation_success() {
        let action = GoToExternalLocationAction::new("SymbolTreePlugin");

        let mut ext_mgr = ExternalManagerDB::new();
        ext_mgr.add_library("libc", SourceType::Imported).unwrap();
        ext_mgr
            .add_ext_function("libc", "printf", Some(Address::new(0x1000)), SourceType::Imported)
            .unwrap();

        let sym = SymbolInfo::new(
            "printf",
            true,
            SymbolType::Function,
            Some(Address::new(0x401000)),
            Some("libc"),
            Some("printf"),
        );

        let target = action.resolve_navigation(&sym, &ext_mgr).unwrap();
        assert_eq!(target.library_name, "libc");
        assert_eq!(target.label, "printf");
        assert_eq!(target.external_address, Some(Address::new(0x1000)));
        assert_eq!(target.reference_address, Some(Address::new(0x401000)));
    }

    #[test]
    fn test_resolve_navigation_not_external() {
        let action = GoToExternalLocationAction::new("SymbolTreePlugin");
        let ext_mgr = ExternalManagerDB::new();

        let sym = SymbolInfo::new(
            "main",
            false,
            SymbolType::Function,
            Some(Address::new(0x400000)),
            None,
            None,
        );

        let result = action.resolve_navigation(&sym, &ext_mgr);
        assert!(result.is_err());
        match result.unwrap_err() {
            GoToExternalError::NotExternal(_) => {}
            _ => panic!("Expected NotExternal error"),
        }
    }

    #[test]
    fn test_resolve_navigation_location_not_found() {
        let action = GoToExternalLocationAction::new("SymbolTreePlugin");
        let ext_mgr = ExternalManagerDB::new();

        let sym = SymbolInfo::new(
            "printf",
            true,
            SymbolType::Function,
            Some(Address::new(0x401000)),
            Some("libc"),
            Some("printf"),
        );

        // External manager has no libraries registered
        let result = action.resolve_navigation(&sym, &ext_mgr);
        assert!(result.is_err());
        match result.unwrap_err() {
            GoToExternalError::LocationNotFound(_) => {}
            _ => panic!("Expected LocationNotFound error"),
        }
    }

    #[test]
    fn test_resolve_navigation_by_name_search() {
        let action = GoToExternalLocationAction::new("SymbolTreePlugin");

        let mut ext_mgr = ExternalManagerDB::new();
        ext_mgr.add_library("libm", SourceType::Imported).unwrap();
        ext_mgr
            .add_ext_function("libm", "sin", Some(Address::new(0x2000)), SourceType::Imported)
            .unwrap();

        // Symbol has no library hint but the name matches
        let sym = SymbolInfo::new(
            "sin",
            true,
            SymbolType::Function,
            Some(Address::new(0x401000)),
            None,
            None,
        );

        let target = action.resolve_navigation(&sym, &ext_mgr).unwrap();
        assert_eq!(target.library_name, "libm");
        assert_eq!(target.label, "sin");
    }

    #[test]
    fn test_execute() {
        let action = GoToExternalLocationAction::new("SymbolTreePlugin");

        let mut ext_mgr = ExternalManagerDB::new();
        ext_mgr.add_library("libc", SourceType::Imported).unwrap();
        ext_mgr
            .add_ext_function("libc", "malloc", Some(Address::new(0x3000)), SourceType::Imported)
            .unwrap();

        let sym = SymbolInfo::new(
            "malloc",
            true,
            SymbolType::Function,
            Some(Address::new(0x401000)),
            Some("libc"),
            Some("malloc"),
        );

        let target = action.execute(&sym, &ext_mgr).unwrap();
        assert_eq!(target.library_name, "libc");
        assert_eq!(target.label, "malloc");
    }

    #[test]
    fn test_symbol_info_navigable() {
        let ext_func = SymbolInfo::new(
            "printf",
            true,
            SymbolType::Function,
            None,
            Some("libc"),
            Some("printf"),
        );
        assert!(ext_func.is_navigable_external());

        let ext_label = SymbolInfo::new(
            "errno",
            true,
            SymbolType::Label,
            None,
            Some("libc"),
            Some("errno"),
        );
        assert!(ext_label.is_navigable_external());

        let local_func = SymbolInfo::new(
            "main",
            false,
            SymbolType::Function,
            Some(Address::new(0x400000)),
            None,
            None,
        );
        assert!(!local_func.is_navigable_external());

        let ext_class = SymbolInfo::new(
            "MyClass",
            true,
            SymbolType::Class,
            None,
            None,
            None,
        );
        assert!(!ext_class.is_navigable_external());
    }

    #[test]
    fn test_navigation_target() {
        let target = NavigationTarget::new(
            "libc",
            "printf",
            Some(Address::new(0x1000)),
            Some(Address::new(0x401000)),
        );
        assert_eq!(target.library_name, "libc");
        assert_eq!(target.label, "printf");
        assert_eq!(target.external_address, Some(Address::new(0x1000)));
        assert_eq!(target.reference_address, Some(Address::new(0x401000)));
    }

    #[test]
    fn test_go_to_external_error_display() {
        let err = GoToExternalError::NoSymbol;
        assert_eq!(err.to_string(), "No symbol selected");

        let err = GoToExternalError::NotExternal("main".to_string());
        assert!(err.to_string().contains("main"));

        let err = GoToExternalError::LocationNotFound("foo".to_string());
        assert!(err.to_string().contains("foo"));

        let err = GoToExternalError::Other("something".to_string());
        assert_eq!(err.to_string(), "something");
    }

    #[test]
    fn test_complex_scenario() {
        let action = GoToExternalLocationAction::new("SymbolTreePlugin");

        let mut ext_mgr = ExternalManagerDB::new();
        ext_mgr.add_library("libc", SourceType::Imported).unwrap();
        ext_mgr
            .add_ext_function("libc", "printf", Some(Address::new(0x1000)), SourceType::Imported)
            .unwrap();
        ext_mgr
            .add_ext_function("libc", "malloc", Some(Address::new(0x2000)), SourceType::Imported)
            .unwrap();
        ext_mgr.add_library("libm", SourceType::Imported).unwrap();
        ext_mgr
            .add_ext_function("libm", "sin", Some(Address::new(0x3000)), SourceType::Imported)
            .unwrap();

        // Navigate to printf
        let sym1 = SymbolInfo::new(
            "printf",
            true,
            SymbolType::Function,
            Some(Address::new(0x401000)),
            Some("libc"),
            Some("printf"),
        );
        let target1 = action.execute(&sym1, &ext_mgr).unwrap();
        assert_eq!(target1.library_name, "libc");

        // Navigate to sin
        let sym2 = SymbolInfo::new(
            "sin",
            true,
            SymbolType::Function,
            Some(Address::new(0x402000)),
            Some("libm"),
            Some("sin"),
        );
        let target2 = action.execute(&sym2, &ext_mgr).unwrap();
        assert_eq!(target2.library_name, "libm");

        // Cannot navigate to local symbol
        let local = SymbolInfo::new(
            "main",
            false,
            SymbolType::Function,
            Some(Address::new(0x400000)),
            None,
            None,
        );
        assert!(action.execute(&local, &ext_mgr).is_err());
    }
}
