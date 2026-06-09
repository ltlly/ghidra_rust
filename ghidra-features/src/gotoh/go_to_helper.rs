//! GoTo helper -- navigation logic for resolving addresses and
//! handling external linkages.
//!
//! Ported from Ghidra's
//! `ghidra.app.plugin.core.gotoquery.GoToHelper` Java class.
//!
//! [`GoToHelper`] is the core workhorse behind the GoTo service.
//! It resolves an address (or query string) into a
//! [`ProgramLocation`], manages external-program linkage
//! navigation, and consults [`NavigationOptions`] to decide
//! whether to follow external programs or stay in the current one.
//!
//! Swing / UI code is omitted; only model and navigation logic
//! are ported.

use std::collections::HashMap;

use ghidra_core::Address;

use super::go_to_service_plugin::{GoToServicePlugin, Navigatable};
use super::GoToQueryResultsTableModel;

// ---------------------------------------------------------------------------
// ProgramLocation
// ---------------------------------------------------------------------------

/// A location within a program, consisting of an address and optional
/// metadata (function name, symbol, etc.).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProgramLocation {
    /// The program name.
    pub program_name: String,
    /// The address within the program.
    pub address: Address,
    /// Optional symbol name at this location.
    pub symbol_name: Option<String>,
    /// Optional function entry address if this location is in a
    /// function.
    pub containing_function: Option<Address>,
    /// Character offset within the rendered field text.
    pub char_offset: usize,
}

impl ProgramLocation {
    /// Create a new program location.
    pub fn new(program_name: impl Into<String>, address: Address) -> Self {
        Self {
            program_name: program_name.into(),
            address,
            symbol_name: None,
            containing_function: None,
            char_offset: 0,
        }
    }

    /// Create a location with symbol information.
    pub fn with_symbol(
        program_name: impl Into<String>,
        address: Address,
        symbol_name: impl Into<String>,
    ) -> Self {
        Self {
            program_name: program_name.into(),
            address,
            symbol_name: Some(symbol_name.into()),
            containing_function: None,
            char_offset: 0,
        }
    }
}

impl std::fmt::Display for ProgramLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(ref sym) = self.symbol_name {
            write!(f, "{} @ {}", sym, self.address)
        } else {
            write!(f, "{}", self.address)
        }
    }
}

// ---------------------------------------------------------------------------
// LocationMemento
// ---------------------------------------------------------------------------

/// Serializable snapshot of a navigation position.
///
/// Used by the navigation history plugin to save/restore positions.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LocationMemento {
    /// The program name.
    pub program_name: String,
    /// The address.
    pub address: u64,
    /// The address space.
    pub address_space: String,
    /// The navigatable id.
    pub navigatable_id: u64,
}

impl LocationMemento {
    /// Create a new memento.
    pub fn new(
        program_name: impl Into<String>,
        address: Address,
        navigatable_id: u64,
    ) -> Self {
        Self {
            program_name: program_name.into(),
            address: address.offset,
            address_space: String::new(),
            navigatable_id,
        }
    }

    /// Whether this memento represents a valid position.
    pub fn is_valid(&self) -> bool {
        !self.program_name.is_empty()
    }
}

impl PartialEq for LocationMemento {
    fn eq(&self, other: &Self) -> bool {
        self.program_name == other.program_name
            && self.address == other.address
            && self.address_space == other.address_space
    }
}
impl Eq for LocationMemento {}

impl std::hash::Hash for LocationMemento {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.program_name.hash(state);
        self.address.hash(state);
        self.address_space.hash(state);
    }
}

// ---------------------------------------------------------------------------
// NavigationOptions
// ---------------------------------------------------------------------------

/// Navigation behavior options.
///
/// Controls how GoTo navigation responds to external symbols,
/// range navigation, indirection following, etc.
#[derive(Debug, Clone)]
pub struct NavigationOptions {
    /// Whether to navigate to the top and bottom of ranges.
    pub goto_top_and_bottom: bool,
    /// Whether to attempt opening external programs.
    pub goto_external_program: bool,
    /// Whether to follow indirect references (pointer dereference).
    pub follow_indirect_references: bool,
    /// Whether to prefer the current address space when resolving
    /// offsets.
    pub prefer_current_address_space: bool,
    /// Whether to restrict GoTo to the current program only.
    pub restrict_to_current_program: bool,
}

impl Default for NavigationOptions {
    fn default() -> Self {
        Self {
            goto_top_and_bottom: false,
            goto_external_program: false,
            follow_indirect_references: false,
            prefer_current_address_space: true,
            restrict_to_current_program: true,
        }
    }
}

// ---------------------------------------------------------------------------
// ExternalLocation
// ---------------------------------------------------------------------------

/// Describes an external library symbol that the user wants to
/// navigate to.
#[derive(Debug, Clone)]
pub struct ExternalLocation {
    /// Name of the external library (e.g. `"libc.so"`).
    pub library_name: String,
    /// Symbol label inside the library (e.g. `"malloc"`).
    pub label: String,
    /// Optional address of the external location.
    pub address: Option<Address>,
}

// ---------------------------------------------------------------------------
// GoToHelper
// ---------------------------------------------------------------------------

/// Navigation helper that resolves addresses and handles external
/// links.
///
/// Contains the core GoTo logic: resolving symbols, finding
/// programs containing an address, following external linkages, etc.
/// This is a direct port of the Java `GoToHelper` class.
pub struct GoToHelper {
    /// Navigation options.
    options: NavigationOptions,
}

impl GoToHelper {
    /// Create a new GoTo helper with default options.
    pub fn new() -> Self {
        Self {
            options: NavigationOptions::default(),
        }
    }

    /// Get the navigation options.
    pub fn options(&self) -> &NavigationOptions {
        &self.options
    }

    /// Get mutable access to navigation options.
    pub fn options_mut(&mut self) -> &mut NavigationOptions {
        &mut self.options
    }

    /// Resolve an address to a [`ProgramLocation`].
    ///
    /// If a symbol exists at the address, the location will include
    /// the symbol name.  If no symbol exists, a bare address
    /// location is returned.
    pub fn get_program_location_for_address(
        address: Address,
        symbols: &HashMap<Address, String>,
        program_name: &str,
    ) -> ProgramLocation {
        match symbols.get(&address) {
            Some(sym_name) => {
                ProgramLocation::with_symbol(program_name, address, sym_name.clone())
            }
            None => ProgramLocation::new(program_name, address),
        }
    }

    /// Determine if an address is external (conceptually, not in
    /// the program's loaded memory).
    pub fn is_external_address(address: &Address) -> bool {
        // In Ghidra, external addresses live in a special
        // "EXTERNAL" space.  In the simplified Rust model, delegate
        // to the Address helper.
        address.is_external_address()
    }

    /// Navigate to a location within the current program.
    ///
    /// This is the main entry point that mirrors the Java
    /// `GoToHelper.goTo()` method.  It resolves the program,
    /// checks for external addresses, and delegates to the
    /// appropriate handler.
    ///
    /// Returns `true` if navigation was successful.
    pub fn go_to(
        &self,
        plugin: &mut GoToServicePlugin,
        navigatable_id: u64,
        loc: &ProgramLocation,
    ) -> bool {
        if loc.address == Address::new(0) {
            return false;
        }

        let addr = loc.address;
        if Self::is_external_address(&addr) {
            // External address -- try to find the linkage location
            // in the current program.  In the Java version this
            // consults the ExternalManager; here we simplify.
            return self.go_to_external_linkage(plugin, navigatable_id, loc);
        }

        // Check that the address is in the current program's
        // memory.  In the simplified Rust model we assume it is
        // always valid.
        plugin.go_to_location(navigatable_id, loc)
    }

    /// GoTo external address linkage location within the current
    /// program.
    ///
    /// Mirrors the Java `GoToHelper.goToExternalLinkage()`.  When
    /// there are multiple linkage addresses and popups are allowed,
    /// a results table would be shown; here we return `true` to
    /// indicate the table was populated.
    pub fn go_to_external_linkage(
        &self,
        plugin: &mut GoToServicePlugin,
        navigatable_id: u64,
        loc: &ProgramLocation,
    ) -> bool {
        // In the full implementation this would consult the
        // ExternalManager for linkage addresses.  For the ported
        // model we attempt direct navigation.
        plugin.go_to_location(navigatable_id, loc)
    }

    /// Navigate to an external program.
    ///
    /// Mirrors the Java `GoToHelper.goToExternalLocation()`.
    /// If `check_navigation_option` is `true`, the
    /// [`NavigationOptions::goto_external_program`] flag is
    /// consulted before attempting external-program navigation.
    pub fn go_to_external_location(
        &self,
        plugin: &mut GoToServicePlugin,
        navigatable_id: u64,
        ext_loc: &ExternalLocation,
        check_navigation_option: bool,
    ) -> bool {
        if check_navigation_option && !self.options.goto_external_program {
            // Fall back to linkage navigation
            let loc = ProgramLocation::new(
                &ext_loc.library_name,
                ext_loc.address.unwrap_or(Address::new(0)),
            );
            return self.go_to_external_linkage(plugin, navigatable_id, &loc);
        }

        // In the full implementation this would open the external
        // program and navigate into it.  For the ported model we
        // create a location and navigate.
        if let Some(addr) = ext_loc.address {
            let loc =
                ProgramLocation::with_symbol(&ext_loc.library_name, addr, &ext_loc.label);
            return plugin.go_to_location(navigatable_id, &loc);
        }

        false
    }

    /// Resolve a location from the current address to a goto
    /// address.
    ///
    /// Mirrors `GoToHelper.getLocation()`.  Attempts to find a
    /// symbol at the goto address; falls back to variable lookups
    /// for stack/register addresses.
    pub fn get_location(
        current_address: Address,
        goto_address: Address,
        symbols: &HashMap<Address, String>,
        program_name: &str,
    ) -> ProgramLocation {
        // Try direct symbol lookup first
        if let Some(sym) = symbols.get(&goto_address) {
            return ProgramLocation::with_symbol(program_name, goto_address, sym.clone());
        }

        // Fall back to a bare address location
        ProgramLocation::new(program_name, goto_address)
    }
}

impl Default for GoToHelper {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_program_location_basic() {
        let addr = Address::new(0x401000);
        let loc = ProgramLocation::new("test.exe", addr);
        assert_eq!(loc.program_name, "test.exe");
        assert_eq!(loc.address, addr);
        assert_eq!(loc.symbol_name, None);
        assert_eq!(format!("{}", loc), "00401000");
    }

    #[test]
    fn test_program_location_with_symbol() {
        let addr = Address::new(0x401000);
        let loc = ProgramLocation::with_symbol("test.exe", addr, "main");
        assert_eq!(loc.symbol_name, Some("main".into()));
        assert_eq!(format!("{}", loc), "main @ 00401000");
    }

    #[test]
    fn test_location_memento_round_trip() {
        let addr = Address::new(0x401000);
        let m = LocationMemento::new("test.exe", addr, 42);
        assert!(m.is_valid());

        let json = serde_json::to_string(&m).unwrap();
        let restored: LocationMemento = serde_json::from_str(&json).unwrap();
        assert_eq!(m, restored);
    }

    #[test]
    fn test_location_memento_invalid() {
        let m = LocationMemento {
            program_name: String::new(),
            address: 0,
            address_space: "RAM".into(),
            navigatable_id: 0,
        };
        assert!(!m.is_valid());
    }

    #[test]
    fn test_navigation_options_default() {
        let opts = NavigationOptions::default();
        assert!(!opts.goto_top_and_bottom);
        assert!(!opts.goto_external_program);
        assert!(!opts.follow_indirect_references);
        assert!(opts.prefer_current_address_space);
        assert!(opts.restrict_to_current_program);
    }

    #[test]
    fn test_go_to_helper_location_for_address() {
        let addr = Address::new(0x401000);
        let mut symbols = HashMap::new();
        symbols.insert(addr, "main".to_string());

        let loc =
            GoToHelper::get_program_location_for_address(addr, &symbols, "test.exe");
        assert_eq!(loc.symbol_name, Some("main".into()));

        let addr2 = Address::new(0x402000);
        let loc2 =
            GoToHelper::get_program_location_for_address(addr2, &symbols, "test.exe");
        assert_eq!(loc2.symbol_name, None);
    }

    #[test]
    fn test_go_to_helper_get_location() {
        let cur = Address::new(0x401000);
        let goto_addr = Address::new(0x402000);
        let mut symbols = HashMap::new();
        symbols.insert(goto_addr, "target_func".to_string());

        let loc = GoToHelper::get_location(cur, goto_addr, &symbols, "test.exe");
        assert_eq!(loc.symbol_name, Some("target_func".into()));
    }

    #[test]
    fn test_go_to_helper_go_to() {
        let mut plugin = GoToServicePlugin::new();
        plugin.set_current_program(Some("test.exe".into()));
        let helper = GoToHelper::new();

        let addr = Address::new(0x401000);
        let loc = ProgramLocation::new("test.exe", addr);
        assert!(helper.go_to(&mut plugin, Navigatable::DEFAULT_ID, &loc));
    }

    #[test]
    fn test_go_to_helper_external_location() {
        let mut plugin = GoToServicePlugin::new();
        plugin.set_current_program(Some("test.exe".into()));
        let helper = GoToHelper::new();

        let ext = ExternalLocation {
            library_name: "libc.so".into(),
            label: "malloc".into(),
            address: Some(Address::new(0x7FF00000)),
        };

        // With check_navigation_option=false, should navigate
        assert!(helper.go_to_external_location(
            &mut plugin,
            Navigatable::DEFAULT_ID,
            &ext,
            false,
        ));
    }

    #[test]
    fn test_go_to_helper_external_location_with_option_check() {
        let mut plugin = GoToServicePlugin::new();
        plugin.set_current_program(Some("test.exe".into()));
        let mut helper = GoToHelper::new();
        // Default: goto_external_program = false
        helper.options_mut().goto_external_program = false;

        let ext = ExternalLocation {
            library_name: "libc.so".into(),
            label: "malloc".into(),
            address: Some(Address::new(0x7FF00000)),
        };

        // With check=true and goto_external_program=false, falls
        // back to linkage navigation (still succeeds in model)
        assert!(helper.go_to_external_location(
            &mut plugin,
            Navigatable::DEFAULT_ID,
            &ext,
            true,
        ));
    }

    #[test]
    fn test_go_to_helper_external_location_no_address() {
        let mut plugin = GoToServicePlugin::new();
        plugin.set_current_program(Some("test.exe".into()));
        let helper = GoToHelper::new();

        let ext = ExternalLocation {
            library_name: "libc.so".into(),
            label: "malloc".into(),
            address: None,
        };

        // No address, check=true, option disabled => linkage path
        // with zero address
        assert!(helper.go_to_external_location(
            &mut plugin,
            Navigatable::DEFAULT_ID,
            &ext,
            true,
        ));
    }
}
