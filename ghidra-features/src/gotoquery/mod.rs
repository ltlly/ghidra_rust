//! GoTo query service -- ported from Ghidra's
//! `ghidra.app.plugin.core.gotoquery` Java package.
//!
//! Provides the "Go To Address" service that other plugins use to
//! navigate the listing to an address, symbol, or external location.
//! The core pieces are:
//!
//! - [`GoToService`] -- trait that consumers call to navigate
//! - [`GoToServicePlugin`] -- plugin implementing the GoTo service
//! - [`GoToHelper`] -- navigation logic (address resolution, external linkage)
//! - [`GoToQueryResultsTableModel`] -- table model for multiple GoTo hits
//!
//! Swing UI code is omitted; only model and navigation logic are ported.

use std::collections::HashMap;

use ghidra_core::Address;


// ---------------------------------------------------------------------------
// GoToService trait
// ---------------------------------------------------------------------------

/// The GoTo service interface -- implemented by [`GoToServicePlugin`].
///
/// Other plugins obtain a reference to this trait and call
/// [`go_to`](Self::go_to) or [`go_to_address`](Self::go_to_address)
/// to navigate the listing.
pub trait GoToService: Send + Sync {
    /// Navigate the given navigatable to the specified address.
    ///
    /// Returns `true` if navigation was successful.
    fn go_to_address(&self, navigatable_id: u64, address: Address) -> bool;

    /// Navigate the given navigatable to a program location.
    fn go_to_location(&self, navigatable_id: u64, location: &ProgramLocation) -> bool;

    /// Get the default navigatable id.
    fn default_navigatable_id(&self) -> u64;
}

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
    /// Optional function entry address if this location is in a function.
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
// Navigatable
// ---------------------------------------------------------------------------

/// Represents a navigatable view in the tool.
///
/// Each code browser panel or other view that can be navigated has a
/// unique `Navigatable`.  The GoTo service dispatches navigation
/// requests to the correct navigatable.
#[derive(Debug, Clone)]
pub struct Navigatable {
    /// Unique id.
    pub id: u64,
    /// Whether this navigatable is connected (always true for default).
    pub connected: bool,
    /// Current location, if any.
    pub location: Option<ProgramLocation>,
    /// Current memento.
    pub memento: Option<LocationMemento>,
    /// Whether this navigatable has been disposed.
    pub disposed: bool,
    /// Whether it supports markers.
    pub supports_markers: bool,
}

impl Navigatable {
    /// Create a new navigatable with the given id.
    pub fn new(id: u64) -> Self {
        Self {
            id,
            connected: true,
            location: None,
            memento: None,
            disposed: false,
            supports_markers: true,
        }
    }

    /// The default navigatable id used by the primary listing.
    pub const DEFAULT_ID: u64 = 0;
}

// ---------------------------------------------------------------------------
// GoToHelper
// ---------------------------------------------------------------------------

/// Navigation helper that resolves addresses and handles external links.
///
/// Contains the core GoTo logic: resolving symbols, finding programs
/// containing an address, following external linkages, etc.
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

    /// Resolve an address to a `ProgramLocation`.
    ///
    /// If a symbol exists at the address, the location will include the
    /// symbol name.  If no symbol exists, a bare address location is returned.
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

    /// Determine if an address is external (conceptually, not in the
    /// program's loaded memory).
    pub fn is_external_address(address: &Address) -> bool {
        // In Ghidra, external addresses live in a special "EXTERNAL" space.
        // In the simplified Rust model, delegate to the Address helper.
        address.is_external_address()
    }
}

impl Default for GoToHelper {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// NavigationOptions
// ---------------------------------------------------------------------------

/// Navigation behavior options.
///
/// Controls how GoTo navigation responds to external symbols, range
/// navigation, indirection following, etc.
#[derive(Debug, Clone)]
pub struct NavigationOptions {
    /// Whether to navigate to the top and bottom of ranges.
    pub goto_top_and_bottom: bool,
    /// Whether to attempt opening external programs.
    pub goto_external_program: bool,
    /// Whether to follow indirect references (pointer dereference).
    pub follow_indirect_references: bool,
    /// Whether to prefer the current address space when resolving offsets.
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
// GoToServicePlugin
// ---------------------------------------------------------------------------

/// Plugin that implements the [`GoToService`] trait.
///
/// Registers itself as the provider of the GoTo service and delegates
/// navigation to a [`GoToHelper`].
pub struct GoToServicePlugin {
    /// Plugin name.
    name: String,
    /// The helper doing the actual navigation work.
    helper: GoToHelper,
    /// Default navigatable.
    default_navigatable: Navigatable,
    /// All registered navigatables.
    navigatables: HashMap<u64, Navigatable>,
    /// Current program name (if any).
    current_program: Option<String>,
    /// Search limit (max results for query tables).
    search_limit: usize,
    /// Event log (simulates plugin event dispatch).
    events: Vec<String>,
}

impl GoToServicePlugin {
    /// Create a new GoTo service plugin.
    pub fn new() -> Self {
        let default_nav = Navigatable::new(Navigatable::DEFAULT_ID);
        let mut navigatables = HashMap::new();
        navigatables.insert(default_nav.id, default_nav.clone());

        Self {
            name: "GoToServicePlugin".to_string(),
            helper: GoToHelper::new(),
            default_navigatable: default_nav,
            navigatables,
            current_program: None,
            search_limit: 500,
            events: Vec::new(),
        }
    }

    /// Return the plugin name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Set the current program name.
    pub fn set_current_program(&mut self, program_name: Option<String>) {
        self.current_program = program_name;
    }

    /// Get the current program name.
    pub fn current_program(&self) -> Option<&str> {
        self.current_program.as_deref()
    }

    /// Get the search limit.
    pub fn search_limit(&self) -> usize {
        self.search_limit
    }

    /// Set the search limit.
    pub fn set_search_limit(&mut self, limit: usize) {
        self.search_limit = limit;
    }

    /// Register a new navigatable.
    pub fn register_navigatable(&mut self, nav: Navigatable) {
        self.navigatables.insert(nav.id, nav);
    }

    /// Unregister a navigatable.
    pub fn unregister_navigatable(&mut self, id: u64) {
        if id != Navigatable::DEFAULT_ID {
            self.navigatables.remove(&id);
        }
    }

    /// Get a reference to the default navigatable.
    pub fn default_navigatable(&self) -> &Navigatable {
        &self.default_navigatable
    }

    /// Get the helper.
    pub fn helper(&self) -> &GoToHelper {
        &self.helper
    }

    /// Get the event log.
    pub fn events(&self) -> &[String] {
        &self.events
    }

    /// Navigate the default navigatable to an address.
    pub fn go_to_address(&mut self, address: Address) -> bool {
        let prog = match self.current_program.clone() {
            Some(p) => p,
            None => return false,
        };
        let loc = ProgramLocation::new(&prog, address);
        self.go_to_location(Navigatable::DEFAULT_ID, &loc)
    }

    /// Navigate a navigatable to a program location.
    pub fn go_to_location(&mut self, navigatable_id: u64, location: &ProgramLocation) -> bool {
        let nav = match self.navigatables.get_mut(&navigatable_id) {
            Some(n) => n,
            None => return false,
        };
        if nav.disposed {
            return false;
        }
        nav.location = Some(location.clone());
        self.events.push(format!(
            "GoTo: navigatable={} -> {}",
            navigatable_id, location
        ));
        true
    }
}

impl Default for GoToServicePlugin {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// GoToQueryResultsTableModel
// ---------------------------------------------------------------------------

/// Table model for displaying multiple GoTo query results.
///
/// When a GoTo query matches multiple symbols or addresses, the
/// results are collected in this model for display in a results table.
#[derive(Debug)]
pub struct GoToQueryResultsTableModel {
    /// Title for the table.
    title: String,
    /// The program name.
    program_name: String,
    /// All result locations.
    results: Vec<ProgramLocation>,
    /// Whether loading is complete.
    loaded: bool,
}

impl GoToQueryResultsTableModel {
    /// Create a new table model with the given results.
    pub fn new(title: impl Into<String>, program_name: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            program_name: program_name.into(),
            results: Vec::new(),
            loaded: false,
        }
    }

    /// Add a result to the model.
    pub fn add_result(&mut self, location: ProgramLocation) {
        self.results.push(location);
    }

    /// Add multiple results.
    pub fn add_results(&mut self, locations: impl IntoIterator<Item = ProgramLocation>) {
        self.results.extend(locations);
    }

    /// Get the number of results.
    pub fn row_count(&self) -> usize {
        self.results.len()
    }

    /// Get a result by row index.
    pub fn get_result(&self, row: usize) -> Option<&ProgramLocation> {
        self.results.get(row)
    }

    /// Get the address for a row.
    pub fn get_address(&self, row: usize) -> Option<Address> {
        self.results.get(row).map(|r| r.address)
    }

    /// Get all results.
    pub fn results(&self) -> &[ProgramLocation] {
        &self.results
    }

    /// Mark the model as fully loaded.
    pub fn set_loaded(&mut self) {
        self.loaded = true;
    }

    /// Whether the model has finished loading.
    pub fn is_loaded(&self) -> bool {
        self.loaded
    }

    /// Get the title.
    pub fn title(&self) -> &str {
        &self.title
    }

    /// Get the program name.
    pub fn program_name(&self) -> &str {
        &self.program_name
    }

    /// Clear all results.
    pub fn clear(&mut self) {
        self.results.clear();
        self.loaded = false;
    }
}

// ---------------------------------------------------------------------------
// DefaultNavigatableLocationMemento
// ---------------------------------------------------------------------------

/// Default memento for saving and restoring navigatable locations.
///
/// Ported from `ghidra.app.plugin.core.gotoquery.DefaultNavigatableLocationMemento`.
#[derive(Debug, Clone)]
pub struct DefaultNavigatableLocationMemento {
    /// The program name.
    pub program_name: String,
    /// The address.
    pub address: u64,
    /// The component path (for composite data).
    pub component_path: Vec<u64>,
}

impl DefaultNavigatableLocationMemento {
    /// Create a new memento.
    pub fn new(program_name: impl Into<String>, address: u64) -> Self {
        Self {
            program_name: program_name.into(),
            address,
            component_path: Vec::new(),
        }
    }

    /// Add a component path entry.
    pub fn add_component(&mut self, offset: u64) {
        self.component_path.push(offset);
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
    fn test_navigatable_default() {
        let nav = Navigatable::new(42);
        assert_eq!(nav.id, 42);
        assert!(nav.connected);
        assert!(!nav.disposed);
        assert!(nav.location.is_none());
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
    fn test_navigation_options_default() {
        let opts = NavigationOptions::default();
        assert!(!opts.goto_top_and_bottom);
        assert!(!opts.goto_external_program);
        assert!(!opts.follow_indirect_references);
        assert!(opts.prefer_current_address_space);
        assert!(opts.restrict_to_current_program);
    }

    #[test]
    fn test_goto_service_plugin_basic() {
        let mut plugin = GoToServicePlugin::new();
        assert_eq!(plugin.name(), "GoToServicePlugin");
        assert_eq!(plugin.current_program(), None);
        assert_eq!(plugin.search_limit(), 500);

        plugin.set_current_program(Some("test.exe".into()));
        assert_eq!(plugin.current_program(), Some("test.exe"));
    }

    #[test]
    fn test_goto_service_plugin_navigate() {
        let mut plugin = GoToServicePlugin::new();
        plugin.set_current_program(Some("test.exe".into()));

        let addr = Address::new(0x401000);
        assert!(plugin.go_to_address(addr));
        assert_eq!(plugin.events().len(), 1);
        assert!(plugin.events()[0].contains("00401000"));
    }

    #[test]
    fn test_goto_service_plugin_no_program() {
        let mut plugin = GoToServicePlugin::new();
        let addr = Address::new(0x401000);
        assert!(!plugin.go_to_address(addr));
    }

    #[test]
    fn test_goto_service_plugin_navigatable_management() {
        let mut plugin = GoToServicePlugin::new();

        let nav = Navigatable::new(100);
        plugin.register_navigatable(nav);
        assert!(plugin.navigatables.contains_key(&100));

        plugin.unregister_navigatable(100);
        assert!(!plugin.navigatables.contains_key(&100));

        // Cannot unregister default
        plugin.unregister_navigatable(Navigatable::DEFAULT_ID);
        assert!(plugin.navigatables.contains_key(&Navigatable::DEFAULT_ID));
    }

    #[test]
    fn test_goto_query_results_table_model() {
        let mut model = GoToQueryResultsTableModel::new("Goto", "test.exe");
        assert_eq!(model.row_count(), 0);
        assert!(!model.is_loaded());

        let addr1 = Address::new(0x401000);
        let addr2 = Address::new(0x402000);
        model.add_result(ProgramLocation::new("test.exe", addr1));
        model.add_result(ProgramLocation::with_symbol("test.exe", addr2, "func"));

        assert_eq!(model.row_count(), 2);
        assert_eq!(model.get_address(0), Some(addr1));
        assert_eq!(model.get_address(1), Some(addr2));
        assert_eq!(model.get_result(1).unwrap().symbol_name, Some("func".into()));

        model.set_loaded();
        assert!(model.is_loaded());

        model.clear();
        assert_eq!(model.row_count(), 0);
        assert!(!model.is_loaded());
    }

    #[test]
    fn test_go_to_location_specific_navigatable() {
        let mut plugin = GoToServicePlugin::new();
        plugin.set_current_program(Some("test.exe".into()));

        let nav = Navigatable::new(99);
        plugin.register_navigatable(nav);

        let addr = Address::new(0x500000);
        let loc = ProgramLocation::new("test.exe", addr);
        assert!(plugin.go_to_location(99, &loc));
        assert!(plugin.navigatables[&99].location.is_some());
    }

    #[test]
    fn test_go_to_disposed_navigatable() {
        let mut plugin = GoToServicePlugin::new();
        let mut nav = Navigatable::new(50);
        nav.disposed = true;
        plugin.register_navigatable(nav);

        let loc = ProgramLocation::new(
            "test.exe",
            Address::new(0x401000),
        );
        assert!(!plugin.go_to_location(50, &loc));
    }
}
