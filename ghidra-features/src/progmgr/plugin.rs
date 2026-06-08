//! ProgramManagerPlugin -- top-level plugin for managing open programs.
//!
//! Ported from `ghidra.app.plugin.core.progmgr.ProgramManagerPlugin`.
//!
//! Coordinates the [`MultiProgramManager`], [`ProgramCache`], and
//! [`ProgramSaveManager`] to provide the public API for opening,
//! closing, saving, and switching between programs.

use super::multi_program_manager::{MultiProgramManager, ProgramEvent};
use super::program_cache::ProgramCache;
use super::save_manager::{ProgramSaveManager, SaveState};
use super::transaction_monitor::TransactionMonitor;
use super::ProgramLocator;

/// The program manager plugin.
///
/// Manages the lifecycle of open programs in a tool, including:
/// - opening and closing programs
/// - caching recently closed programs
/// - save/save-as operations
/// - switching the active program
/// - undo/redo coordination
#[derive(Debug)]
pub struct ProgramManagerPlugin {
    /// The multi-program manager tracking open programs.
    program_mgr: MultiProgramManager,
    /// Cache for recently closed programs (using string as placeholder).
    program_cache: ProgramCache<String>,
    /// Manages save operations.
    save_mgr: ProgramSaveManager,
    /// Monitors transaction state.
    transaction_monitor: TransactionMonitor,
    /// The plugin name.
    name: String,
    /// Default cache duration in minutes.
    cache_duration_mins: u64,
    /// Default cache capacity.
    cache_capacity: usize,
}

impl ProgramManagerPlugin {
    /// Default cache duration in minutes.
    pub const DEFAULT_CACHE_DURATION_MINS: u64 = 30;
    /// Default cache capacity.
    pub const DEFAULT_CACHE_CAPACITY: usize = 50;

    /// Create a new ProgramManagerPlugin.
    pub fn new(name: impl Into<String>) -> Self {
        let n = name.into();
        let duration = std::time::Duration::from_secs(Self::DEFAULT_CACHE_DURATION_MINS * 60);
        let cache = ProgramCache::new(duration, Self::DEFAULT_CACHE_CAPACITY);

        Self {
            program_mgr: MultiProgramManager::new(),
            program_cache: cache,
            save_mgr: ProgramSaveManager::new(),
            transaction_monitor: TransactionMonitor::new(),
            name: n,
            cache_duration_mins: Self::DEFAULT_CACHE_DURATION_MINS,
            cache_capacity: Self::DEFAULT_CACHE_CAPACITY,
        }
    }

    /// Returns the plugin name.
    pub fn name(&self) -> &str {
        &self.name
    }

    // ------------------------------------------------------------------
    // Program lifecycle
    // ------------------------------------------------------------------

    /// Open a program from a locator.
    ///
    /// In the full implementation, this would load the program from the
    /// domain file or URL.  Here we track the open request.
    pub fn open_program(
        &mut self,
        locator: ProgramLocator,
        state: i32,
    ) -> Result<String, String> {
        // Check if already open
        if let Some(name) = self.program_mgr.find_by_locator(&locator) {
            let name = name.to_string();
            self.program_mgr.set_current_program(&name);
            return Ok(name);
        }

        // Check cache
        if self.program_cache.contains(&locator) {
            let name = locator.display_name();
            self.program_mgr.add_program(&name, locator, state);
            self.save_mgr.register_program(&name, SaveState::Clean);
            return Ok(name);
        }

        // Open new (in real impl, would load from disk)
        let name = locator.display_name();
        self.program_mgr.add_program(&name, locator, state);
        self.save_mgr
            .register_program(&name, SaveState::Clean);
        Ok(name)
    }

    /// Close a program.
    ///
    /// If the program has a persistent owner, it is hidden rather than
    /// removed.  Returns `true` if the program was successfully closed.
    pub fn close_program(&mut self, name: &str, ignore_changes: bool) -> bool {
        if !self.program_mgr.contains(name) {
            return false;
        }

        if !ignore_changes && self.save_mgr.is_dirty(name) {
            // In real impl, would prompt user.  Here, just proceed.
        }

        self.program_mgr.remove_program(name);
        self.save_mgr.unregister_program(name);
        !self.program_mgr.contains(name)
    }

    /// Close all programs except the current one.
    pub fn close_other_programs(&mut self, ignore_changes: bool) {
        let others = self.program_mgr.other_program_names();
        for name in others {
            self.close_program(&name, ignore_changes);
        }
    }

    /// Close all programs.
    pub fn close_all_programs(&mut self, ignore_changes: bool) {
        let all = self.program_mgr.all_program_names();
        // Close non-current first, then current
        let current = self.current_program_name().map(|s| s.to_string());
        for name in &all {
            if Some(name.as_str()) != current.as_deref() {
                self.close_program(name, ignore_changes);
            }
        }
        if let Some(current) = current {
            self.close_program(&current, ignore_changes);
        }
    }

    /// Add an already-open program to the manager.
    pub fn add_program(&mut self, name: impl Into<String>, state: i32) {
        let n = name.into();
        let locator = ProgramLocator::from_path(&n);
        self.program_mgr.add_program(&n, locator, state);
        self.save_mgr.register_program(&n, SaveState::Clean);
    }

    // ------------------------------------------------------------------
    // Current program
    // ------------------------------------------------------------------

    /// Returns the name of the current (active) program.
    pub fn current_program_name(&self) -> Option<&str> {
        self.program_mgr.current_program_name()
    }

    /// Set the current program.
    pub fn set_current_program(&mut self, name: &str) {
        self.program_mgr.set_current_program(name);
    }

    // ------------------------------------------------------------------
    // Queries
    // ------------------------------------------------------------------

    /// Returns all open program names.
    pub fn all_program_names(&self) -> Vec<String> {
        self.program_mgr.all_program_names()
    }

    /// Returns `true` if any program has unsaved changes.
    pub fn has_unsaved_programs(&self) -> bool {
        self.save_mgr.has_unsaved_programs()
    }

    /// Check if a program is open.
    pub fn is_open(&self, name: &str) -> bool {
        self.program_mgr.contains(name)
    }

    /// Check if a program is visible.
    pub fn is_visible(&self, name: &str) -> bool {
        self.program_mgr.is_visible(name)
    }

    /// Returns the number of open programs.
    pub fn program_count(&self) -> usize {
        self.program_mgr.program_count()
    }

    // ------------------------------------------------------------------
    // Save operations
    // ------------------------------------------------------------------

    /// Save the current program.
    pub fn save_current_program(&mut self) -> bool {
        if let Some(name) = self.current_program_name().map(|s| s.to_string()) {
            self.save_mgr.save_program(&name)
        } else {
            false
        }
    }

    /// Save a specific program.
    pub fn save_program(&mut self, name: &str) -> bool {
        self.save_mgr.save_program(name)
    }

    /// Save all dirty programs.
    pub fn save_all(&mut self) -> Vec<String> {
        self.save_mgr.save_all()
    }

    /// Mark a program as having unsaved changes.
    pub fn mark_dirty(&mut self, name: &str) {
        self.save_mgr.mark_dirty(name);
        if let Some(info) = self.program_mgr.get_info_mut(name) {
            info.is_changed = true;
        }
    }

    /// Mark a program as clean.
    pub fn mark_clean(&mut self, name: &str) {
        self.save_mgr.mark_clean(name);
        if let Some(info) = self.program_mgr.get_info_mut(name) {
            info.is_changed = false;
        }
    }

    // ------------------------------------------------------------------
    // Transaction
    // ------------------------------------------------------------------

    /// Returns a reference to the transaction monitor.
    pub fn transaction_monitor(&self) -> &TransactionMonitor {
        &self.transaction_monitor
    }

    /// Returns a mutable reference to the transaction monitor.
    pub fn transaction_monitor_mut(&mut self) -> &mut TransactionMonitor {
        &mut self.transaction_monitor
    }

    // ------------------------------------------------------------------
    // Cache
    // ------------------------------------------------------------------

    /// Set the cache duration in minutes.
    pub fn set_cache_duration(&mut self, minutes: u64) {
        self.cache_duration_mins = minutes;
        self.program_cache
            .set_duration(std::time::Duration::from_secs(minutes * 60));
    }

    /// Set the cache capacity.
    pub fn set_cache_capacity(&mut self, capacity: usize) {
        self.cache_capacity = capacity;
        self.program_cache.set_capacity(capacity);
    }

    // ------------------------------------------------------------------
    // Events
    // ------------------------------------------------------------------

    /// Drain and return all pending events.
    pub fn drain_events(&mut self) -> Vec<ProgramEvent> {
        self.program_mgr.drain_events()
    }

    /// Dispose of the plugin.
    pub fn dispose(&mut self) {
        self.program_cache.clear();
        self.program_mgr.dispose();
    }
}

impl Default for ProgramManagerPlugin {
    fn default() -> Self {
        Self::new("ProgramManager")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::progmgr::multi_program_manager::OPEN_CURRENT;
    use crate::progmgr::multi_program_manager::OPEN_VISIBLE;

    fn make_plugin() -> ProgramManagerPlugin {
        ProgramManagerPlugin::new("TestPlugin")
    }

    #[test]
    fn test_plugin_creation() {
        let plugin = make_plugin();
        assert_eq!(plugin.name(), "TestPlugin");
        assert_eq!(plugin.program_count(), 0);
    }

    #[test]
    fn test_open_program() {
        let mut plugin = make_plugin();
        let loc = ProgramLocator::from_path("/test/prog.exe");
        let name = plugin.open_program(loc, OPEN_CURRENT).unwrap();

        assert!(plugin.is_open(&name));
        assert_eq!(plugin.current_program_name(), Some(name.as_str()));
        assert_eq!(plugin.program_count(), 1);
    }

    #[test]
    fn test_close_program() {
        let mut plugin = make_plugin();
        plugin.add_program("prog", OPEN_CURRENT);
        assert!(plugin.is_open("prog"));

        plugin.close_program("prog", true);
        assert!(!plugin.is_open("prog"));
    }

    #[test]
    fn test_close_all() {
        let mut plugin = make_plugin();
        plugin.add_program("a", OPEN_CURRENT);
        plugin.add_program("b", OPEN_VISIBLE);

        plugin.close_all_programs(true);
        assert_eq!(plugin.program_count(), 0);
    }

    #[test]
    fn test_save_operations() {
        let mut plugin = make_plugin();
        plugin.add_program("prog", OPEN_CURRENT);

        plugin.mark_dirty("prog");
        assert!(plugin.has_unsaved_programs());
        assert!(plugin.save_current_program());
        assert!(!plugin.has_unsaved_programs());
    }

    #[test]
    fn test_save_all() {
        let mut plugin = make_plugin();
        plugin.add_program("a", OPEN_CURRENT);
        plugin.add_program("b", OPEN_VISIBLE);

        plugin.mark_dirty("a");
        plugin.mark_dirty("b");

        let saved = plugin.save_all();
        assert_eq!(saved.len(), 2);
        assert!(!plugin.has_unsaved_programs());
    }

    #[test]
    fn test_cache_settings() {
        let mut plugin = make_plugin();
        plugin.set_cache_duration(60);
        plugin.set_cache_capacity(100);
        // No assertions needed; just verifying it doesn't panic
    }

    #[test]
    fn test_set_current_program() {
        let mut plugin = make_plugin();
        plugin.add_program("a", OPEN_CURRENT);
        plugin.add_program("b", OPEN_VISIBLE);

        plugin.set_current_program("b");
        assert_eq!(plugin.current_program_name(), Some("b"));
    }

    #[test]
    fn test_events() {
        let mut plugin = make_plugin();
        plugin.add_program("prog", OPEN_CURRENT);
        let events = plugin.drain_events();
        assert!(!events.is_empty());
    }
}
