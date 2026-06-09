//! GoTo service plugin -- implements the GoTo navigation service.
//!
//! Ported from Ghidra's
//! `ghidra.app.plugin.core.gotoquery.GoToServicePlugin` Java class.
//!
//! [`GoToServicePlugin`] registers itself as the provider of the
//! GoTo service and delegates navigation to a
//! [`GoToHelper`](super::go_to_helper::GoToHelper).  It manages
//! [`Navigatable`] instances and tracks the current program.

use std::collections::HashMap;

use ghidra_core::Address;

use super::go_to_helper::{GoToHelper, ProgramLocation};

// ---------------------------------------------------------------------------
// Navigatable
// ---------------------------------------------------------------------------

/// Represents a navigatable view in the tool.
///
/// Each code browser panel or other view that can be navigated has
/// a unique `Navigatable`.  The GoTo service dispatches navigation
/// requests to the correct navigatable.
#[derive(Debug, Clone)]
pub struct Navigatable {
    /// Unique id.
    pub id: u64,
    /// Whether this navigatable is connected (always true for
    /// default).
    pub connected: bool,
    /// Current location, if any.
    pub location: Option<ProgramLocation>,
    /// Whether this navigatable has been disposed.
    pub disposed: bool,
    /// Whether it supports markers.
    pub supports_markers: bool,
    /// Whether it is currently visible.
    pub visible: bool,
}

impl Navigatable {
    /// Create a new navigatable with the given id.
    pub fn new(id: u64) -> Self {
        Self {
            id,
            connected: true,
            location: None,
            disposed: false,
            supports_markers: true,
            visible: true,
        }
    }

    /// The default navigatable id used by the primary listing.
    pub const DEFAULT_ID: u64 = 0;
}

// ---------------------------------------------------------------------------
// GoToServicePlugin
// ---------------------------------------------------------------------------

/// Plugin that implements the GoTo navigation service.
///
/// Registers itself as the provider of the GoTo service and
/// delegates navigation to a [`GoToHelper`].
///
/// This is a direct port of the Java `GoToServicePlugin` class,
/// with Swing UI code omitted.
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
    /// Whether the plugin has been disposed.
    disposed: bool,
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
            disposed: false,
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

    /// Get mutable access to the helper.
    pub fn helper_mut(&mut self) -> &mut GoToHelper {
        &mut self.helper
    }

    /// Get the event log.
    pub fn events(&self) -> &[String] {
        &self.events
    }

    /// Whether the plugin has been disposed.
    pub fn is_disposed(&self) -> bool {
        self.disposed
    }

    /// Dispose the plugin.
    ///
    /// Mirrors `GoToServicePlugin.dispose()`.  Unregisters the
    /// default navigatable and marks the plugin as disposed.
    pub fn dispose(&mut self) {
        self.disposed = true;
        self.default_navigatable.disposed = true;
        self.events.push("Plugin disposed".to_string());
    }

    /// Get the maximum search hits.
    ///
    /// Mirrors `GoToServicePlugin.getMaxHits()`.
    pub fn get_max_hits(&self) -> usize {
        self.search_limit
    }

    /// Update the current program.
    ///
    /// Mirrors `GoToServicePlugin.updateCurrentProgram()`.
    pub fn update_current_program(&mut self, program_name: Option<String>) {
        self.current_program = program_name;
        if let Some(ref p) = self.current_program {
            self.events
                .push(format!("Current program updated: {}", p));
        }
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
    pub fn go_to_location(
        &mut self,
        navigatable_id: u64,
        location: &ProgramLocation,
    ) -> bool {
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

    /// Get a navigatable by id.
    pub fn get_navigatable(&self, id: u64) -> Option<&Navigatable> {
        self.navigatables.get(&id)
    }

    /// Get a mutable navigatable by id.
    pub fn get_navigatable_mut(&mut self, id: u64) -> Option<&mut Navigatable> {
        self.navigatables.get_mut(&id)
    }
}

impl Default for GoToServicePlugin {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_navigatable_default() {
        let nav = Navigatable::new(42);
        assert_eq!(nav.id, 42);
        assert!(nav.connected);
        assert!(!nav.disposed);
        assert!(nav.location.is_none());
        assert!(nav.visible);
    }

    #[test]
    fn test_navigatable_default_id() {
        assert_eq!(Navigatable::DEFAULT_ID, 0);
    }

    #[test]
    fn test_goto_service_plugin_basic() {
        let mut plugin = GoToServicePlugin::new();
        assert_eq!(plugin.name(), "GoToServicePlugin");
        assert_eq!(plugin.current_program(), None);
        assert_eq!(plugin.search_limit(), 500);
        assert!(!plugin.is_disposed());

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
        assert!(
            plugin.navigatables.contains_key(&Navigatable::DEFAULT_ID)
        );
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

        let loc = ProgramLocation::new("test.exe", Address::new(0x401000));
        assert!(!plugin.go_to_location(50, &loc));
    }

    #[test]
    fn test_go_to_unknown_navigatable() {
        let mut plugin = GoToServicePlugin::new();
        let loc = ProgramLocation::new("test.exe", Address::new(0x401000));
        assert!(!plugin.go_to_location(999, &loc));
    }

    #[test]
    fn test_plugin_dispose() {
        let mut plugin = GoToServicePlugin::new();
        assert!(!plugin.is_disposed());

        plugin.dispose();
        assert!(plugin.is_disposed());
        assert!(plugin.default_navigatable().disposed);
        assert!(plugin.events().last().unwrap().contains("disposed"));
    }

    #[test]
    fn test_update_current_program() {
        let mut plugin = GoToServicePlugin::new();
        plugin.update_current_program(Some("my_program".into()));
        assert_eq!(plugin.current_program(), Some("my_program"));
        assert!(plugin.events().last().unwrap().contains("my_program"));
    }

    #[test]
    fn test_get_max_hits() {
        let mut plugin = GoToServicePlugin::new();
        assert_eq!(plugin.get_max_hits(), 500);

        plugin.set_search_limit(1000);
        assert_eq!(plugin.get_max_hits(), 1000);
    }

    #[test]
    fn test_get_navigatable() {
        let mut plugin = GoToServicePlugin::new();
        let nav = Navigatable::new(77);
        plugin.register_navigatable(nav);

        assert!(plugin.get_navigatable(77).is_some());
        assert!(plugin.get_navigatable(88).is_none());

        let nav_mut = plugin.get_navigatable_mut(77).unwrap();
        nav_mut.visible = false;
        assert!(!plugin.get_navigatable(77).unwrap().visible);
    }
}
