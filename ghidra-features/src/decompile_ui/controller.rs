//! Decompiler controller -- Rust port of
//! `ghidra.app.decompiler.component.DecompilerController`.
//!
//! Coordinates the interactions between the provider, the panel, and the
//! decompiler manager.  The controller holds:
//!
//! * A **cache** of `Function -> DecompileResults` so that revisiting a
//!   recently-decompiled function is instant.
//! * A reference to the [`DecompilerPanel`] (rendering surface).
//! * A reference to the [`DecompilerManager`] (background decompile tasks).
//!
//! The provider calls the controller to display a function, set options,
//! and forward user interactions.  The manager calls back into the
//! controller when a decompile finishes so the panel can be updated.

use std::collections::HashMap;

use ghidra_core::addr::Address;

use super::clipboard_provider::DecompilerClipboardProvider;
use super::panel::{DecompiledFunction, DecompiledLine, DecompiledToken, DecompilerPanel};

// ---------------------------------------------------------------------------
// DecompileResults
// ---------------------------------------------------------------------------

/// The results of a single decompilation of a function.
///
/// In Ghidra this carries the C markup (`ClangTokenGroup`), the
/// `HighFunction`, error messages, and timing information.  Here we
/// store the essential information needed by the panel and cache.
#[derive(Debug, Clone)]
pub struct DecompileResults {
    /// The function entry point this result belongs to.
    pub function_entry: Address,
    /// The decompiled function data (lines, tokens, etc.).
    pub decompiled_function: Option<DecompiledFunction>,
    /// Error message from the decompiler, if any.
    pub error_message: Option<String>,
    /// Whether the decompile completed successfully.
    pub completed: bool,
    /// Wall-clock time of the decompile in milliseconds.
    pub elapsed_ms: u64,
}

impl DecompileResults {
    /// Create a successful result.
    pub fn success(function_entry: Address, function: DecompiledFunction, elapsed_ms: u64) -> Self {
        Self {
            function_entry,
            decompiled_function: Some(function),
            error_message: None,
            completed: true,
            elapsed_ms,
        }
    }

    /// Create an error result.
    pub fn error(function_entry: Address, message: impl Into<String>) -> Self {
        Self {
            function_entry,
            decompiled_function: None,
            error_message: Some(message.into()),
            completed: false,
            elapsed_ms: 0,
        }
    }

    /// Returns `true` if the decompile completed without errors.
    pub fn decompile_completed(&self) -> bool {
        self.completed && self.error_message.is_none()
    }

    /// Returns the decompiled function, if available.
    pub fn get_function(&self) -> Option<&DecompiledFunction> {
        self.decompiled_function.as_ref()
    }
}

// ---------------------------------------------------------------------------
// DecompileData
// ---------------------------------------------------------------------------

/// The data associated with a single decompile display, bundling the
/// program context, function, results, and viewer position.
///
/// Ghidra's `DecompileData` carries the `Program`, `Function`,
/// `ProgramLocation`, `DecompileResults`, and viewer state.  Here we
/// use string-based program identifiers and address-based locations.
#[derive(Debug, Clone)]
pub struct DecompileData {
    /// The program name.
    pub program_name: String,
    /// The function entry point (0 if no function).
    pub function_entry: Address,
    /// The function name (for display).
    pub function_name: Option<String>,
    /// The current address the user is viewing.
    pub location: Option<Address>,
    /// The decompile results, if available.
    pub results: Option<DecompileResults>,
    /// Viewer scroll position (index, y_offset).
    pub viewer_position: Option<(usize, usize)>,
}

impl DecompileData {
    /// Create an "empty" placeholder data (no function).
    pub fn empty(message: &str) -> Self {
        Self {
            program_name: String::new(),
            function_entry: Address::new(0),
            function_name: None,
            location: None,
            results: None,
            viewer_position: None,
        }
    }

    /// Create decompile data from results.
    pub fn from_results(
        program_name: impl Into<String>,
        function_entry: Address,
        function_name: Option<String>,
        location: Option<Address>,
        results: DecompileResults,
    ) -> Self {
        Self {
            program_name: program_name.into(),
            function_entry,
            function_name,
            location,
            results: Some(results),
            viewer_position: None,
        }
    }

    /// Returns `true` if this data contains decompile results.
    pub fn has_decompile_results(&self) -> bool {
        self.results.as_ref().map_or(false, |r| r.decompile_completed())
    }

    /// Get the function name.
    pub fn get_function_name(&self) -> Option<&str> {
        self.function_name.as_deref()
    }
}

// ---------------------------------------------------------------------------
// DecompilerController
// ---------------------------------------------------------------------------

/// Coordinates the interactions between the provider, panel, and manager.
///
/// The controller:
/// * Manages a cache of recently-decompiled functions.
/// * Forwards display requests to the decompiler manager.
/// * Receives completed results and updates the panel.
/// * Provides accessor methods for the current program, function, and
///   high-level function.
///
/// # Cache
///
/// The cache uses a simple `HashMap` with a maximum size.  When the
/// cache is full, the oldest entries are evicted.  Ghidra uses a
/// Guava `Cache` with soft-value references; here we use a
/// bounded `HashMap` with manual eviction.
#[derive(Debug)]
pub struct DecompilerController {
    /// The currently displayed decompile data.
    current_data: Option<DecompileData>,
    /// The current program selection (address range).
    current_selection: Option<(Address, Address)>,
    /// The decompiler results cache: function_entry -> results.
    cache: HashMap<Address, DecompileResults>,
    /// Maximum number of entries in the cache.
    cache_size: usize,
    /// The decompiler panel (rendering surface).
    panel: DecompilerPanel,
    /// Whether a decompile is currently in progress.
    is_decompiling: bool,
    /// The clipboard provider.
    clipboard: DecompilerClipboardProvider,
}

impl DecompilerController {
    /// Create a new controller with the given cache size.
    pub fn new(cache_size: usize) -> Self {
        Self {
            current_data: None,
            current_selection: None,
            cache: HashMap::new(),
            cache_size,
            panel: DecompilerPanel::new(),
            is_decompiling: false,
            clipboard: DecompilerClipboardProvider::new(),
        }
    }

    // -----------------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------------

    /// Get a reference to the decompiler panel.
    pub fn get_decompiler_panel(&self) -> &DecompilerPanel {
        &self.panel
    }

    /// Get a mutable reference to the decompiler panel.
    pub fn get_decompiler_panel_mut(&mut self) -> &mut DecompilerPanel {
        &mut self.panel
    }

    /// Returns `true` if a decompile is currently in progress.
    pub fn is_decompiling(&self) -> bool {
        self.is_decompiling
    }

    /// Returns `true` if there are decompile results for the current function.
    pub fn has_decompile_results(&self) -> bool {
        self.current_data
            .as_ref()
            .map_or(false, |d| d.has_decompile_results())
    }

    /// Get the current program name.
    pub fn get_program_name(&self) -> Option<&str> {
        self.current_data.as_ref().map(|d| d.program_name.as_str())
    }

    /// Get the current function entry point.
    pub fn get_function_entry(&self) -> Option<Address> {
        self.current_data.as_ref().map(|d| d.function_entry)
    }

    /// Get the current function name.
    pub fn get_function_name(&self) -> Option<&str> {
        self.current_data
            .as_ref()
            .and_then(|d| d.function_name.as_deref())
    }

    /// Get the current location.
    pub fn get_location(&self) -> Option<Address> {
        self.current_data.as_ref().and_then(|d| d.location)
    }

    /// Get the current decompile data.
    pub fn get_decompile_data(&self) -> Option<&DecompileData> {
        self.current_data.as_ref()
    }

    /// Get the clipboard provider.
    pub fn clipboard_provider(&self) -> &DecompilerClipboardProvider {
        &self.clipboard
    }

    /// Get a mutable reference to the clipboard provider.
    pub fn clipboard_provider_mut(&mut self) -> &mut DecompilerClipboardProvider {
        &mut self.clipboard
    }

    // -----------------------------------------------------------------------
    // Methods called by the provider
    // -----------------------------------------------------------------------

    /// Dispose the controller, releasing all resources.
    pub fn dispose(&mut self) {
        self.clear_cache();
        self.panel.clear();
        self.current_data = None;
        self.current_selection = None;
    }

    /// Clear all internal state.  Called when the provider is no longer
    /// visible or the currently displayed program is closed.
    pub fn clear(&mut self) {
        self.current_selection = None;
        self.is_decompiling = false;
        self.set_decompile_data(DecompileData::empty("No Function"));
    }

    /// Display the function at the given location.
    ///
    /// If the function is already decompiled and in the cache, the
    /// cached result is used.  Otherwise a decompile is requested.
    pub fn display(
        &mut self,
        program_name: &str,
        location: Address,
        viewer_position: Option<(usize, usize)>,
    ) {
        // If we're already showing this function, just update the cursor.
        if self.is_already_decompiled(location) {
            self.panel.go_to_address(&location);
            return;
        }

        // Try the cache.
        if self.load_from_cache(program_name, location, viewer_position) {
            self.panel.go_to_address(&location);
            return;
        }

        // Request a decompile (in Ghidra this calls decompilerMgr.decompile).
        self.request_decompile(program_name, location, viewer_position);
    }

    /// Set the current program selection.
    pub fn set_selection(&mut self, selection: Option<(Address, Address)>) {
        self.current_selection = selection;
    }

    /// Update decompiler options.  Clears the cache and triggers a
    /// re-decompile if the cache size changed.
    pub fn set_options(&mut self, new_cache_size: usize) {
        self.clear_cache();
        if new_cache_size != self.cache_size {
            self.cache_size = new_cache_size;
        }
    }

    /// Force a re-decompile of the current location.
    pub fn refresh_display(
        &mut self,
        program_name: &str,
        location: Address,
    ) {
        self.clear_cache();
        self.request_decompile(program_name, location, None);
    }

    /// Set the decompile data and update the panel.
    pub fn set_decompile_data(&mut self, data: DecompileData) {
        // Update the cache if we have results.
        if let Some(ref results) = data.results {
            if results.decompile_completed() {
                self.update_cache(data.function_entry, results.clone());
            }
        }
        self.current_data = Some(data.clone());
        // Update the panel with the new function.
        if let Some(ref results) = data.results {
            if let Some(ref func) = results.decompiled_function {
                self.panel.set_function(func.clone());
            }
        }
        if let Some(sel) = self.current_selection {
            self.panel.set_selection(
                (sel.0.offset as usize, 0),
                (sel.1.offset as usize, 0),
            );
        }
    }

    /// Notify that the decompiler status changed (context update).
    pub fn decompiler_status_changed(&mut self) {
        // In Ghidra this calls callbackHandler.contextChanged().
    }

    /// Add results to the cache (called by the manager when a
    /// decompile finishes).
    pub fn add_to_cache(&mut self, entry: Address, results: DecompileResults) {
        self.update_cache(entry, results);
    }

    /// Returns the status message for the current state.
    pub fn get_status_message(&self) -> String {
        if self.is_decompiling {
            return "Decompiling...".to_string();
        }
        match &self.current_data {
            Some(data) => {
                if data.has_decompile_results() {
                    format!("Showing: {}", data.function_name.as_deref().unwrap_or("unknown"))
                } else {
                    "No decompile results".to_string()
                }
            }
            None => "No function".to_string(),
        }
    }

    /// Program was closed -- evict cache entries for that program.
    pub fn program_closed(&mut self, closed_program: &str) {
        // In the full implementation, this would check each cached
        // function's program.  Here we clear the entire cache since
        // we don't track program ownership per entry.
        if let Some(ref data) = self.current_data {
            if data.program_name == closed_program {
                self.clear_cache();
            }
        }
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Check if the given location is already in the current function.
    fn is_already_decompiled(&self, location: Address) -> bool {
        if self.is_decompiling {
            return false;
        }
        let data = match &self.current_data {
            Some(d) => d,
            None => return false,
        };
        // In a full implementation, we'd check if the location is within
        // the function body.  Here we check if it matches the entry point.
        data.function_entry == location
    }

    /// Try to load the function from the cache.
    fn load_from_cache(
        &mut self,
        _program_name: &str,
        location: Address,
        viewer_position: Option<(usize, usize)>,
    ) -> bool {
        // Look up the function entry for this address.  In a full
        // implementation we'd query the function manager.  Here we
        // use the address directly as the cache key.
        let entry = location;
        let results = match self.cache.get(&entry) {
            Some(r) => r.clone(),
            None => return false,
        };

        let data = DecompileData {
            program_name: _program_name.to_string(),
            function_entry: entry,
            function_name: results.get_function().map(|f| f.name.clone()),
            location: Some(location),
            results: Some(results),
            viewer_position,
        };

        self.set_decompile_data(data);
        true
    }

    /// Request a decompile.  In a full implementation this calls the
    /// `DecompilerManager`.  Here we mark the state as decompiling.
    fn request_decompile(
        &mut self,
        program_name: &str,
        location: Address,
        viewer_position: Option<(usize, usize)>,
    ) {
        self.is_decompiling = true;
        // The actual decompile would be triggered asynchronously.
        // For now, we just set a placeholder.
        self.current_data = Some(DecompileData {
            program_name: program_name.to_string(),
            function_entry: location,
            function_name: None,
            location: Some(location),
            results: None,
            viewer_position,
        });
    }

    /// Update the cache with new results, evicting if necessary.
    fn update_cache(&mut self, entry: Address, results: DecompileResults) {
        if self.cache.len() >= self.cache_size && !self.cache.contains_key(&entry) {
            // Evict the oldest entry.  In a HashMap we can't easily
            // determine "oldest", so we just remove one arbitrary entry.
            if let Some(key) = self.cache.keys().next().cloned() {
                self.cache.remove(&key);
            }
        }
        self.cache.insert(entry, results);
    }

    /// Clear the entire cache.
    pub fn clear_cache(&mut self) {
        self.cache.clear();
    }

    /// Complete a pending decompile (called by the manager when done).
    pub fn complete_decompile(&mut self, results: DecompileResults) {
        self.is_decompiling = false;
        let entry = results.function_entry;
        let func_name = results.get_function().map(|f| f.name.clone());
        let prog_name = self
            .current_data
            .as_ref()
            .map(|d| d.program_name.clone())
            .unwrap_or_default();
        let location = self.current_data.as_ref().and_then(|d| d.location);

        let data = DecompileData::from_results(prog_name, entry, func_name, location, results);
        self.set_decompile_data(data);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompile_ui::panel::{DecompiledLine, DecompiledToken, DecompiledTokenType};

    fn make_test_function(entry: u64, name: &str) -> DecompiledFunction {
        let mut func = DecompiledFunction::new(Address::new(entry), name);
        let mut line = DecompiledLine::new(1, 0);
        line.add_token(DecompiledToken::new(
            format!("void {}() {{", name),
            DecompiledTokenType::Syntax,
            0,
            0,
        ));
        func.lines.push(line);
        func.is_complete = true;
        func
    }

    #[test]
    fn test_controller_new() {
        let ctrl = DecompilerController::new(10);
        assert!(!ctrl.is_decompiling());
        assert!(!ctrl.has_decompile_results());
        assert!(ctrl.get_program_name().is_none());
    }

    #[test]
    fn test_controller_dispose() {
        let mut ctrl = DecompilerController::new(10);
        ctrl.dispose();
        assert!(ctrl.get_decompile_data().is_none());
    }

    #[test]
    fn test_controller_clear() {
        let mut ctrl = DecompilerController::new(10);
        ctrl.set_decompile_data(DecompileData::from_results(
            "test.elf",
            Address::new(0x1000),
            Some("main".into()),
            Some(Address::new(0x1000)),
            DecompileResults::success(Address::new(0x1000), make_test_function(0x1000, "main"), 42),
        ));
        assert!(ctrl.has_decompile_results());

        ctrl.clear();
        assert!(!ctrl.has_decompile_results());
    }

    #[test]
    fn test_controller_set_decompile_data() {
        let mut ctrl = DecompilerController::new(10);
        let results = DecompileResults::success(
            Address::new(0x2000),
            make_test_function(0x2000, "foo"),
            10,
        );
        ctrl.set_decompile_data(DecompileData::from_results(
            "prog",
            Address::new(0x2000),
            Some("foo".into()),
            Some(Address::new(0x2000)),
            results,
        ));
        assert!(ctrl.has_decompile_results());
        assert_eq!(ctrl.get_function_name(), Some("foo"));
        assert_eq!(ctrl.get_program_name(), Some("prog"));
    }

    #[test]
    fn test_controller_cache() {
        let mut ctrl = DecompilerController::new(5);
        let results = DecompileResults::success(
            Address::new(0x3000),
            make_test_function(0x3000, "bar"),
            5,
        );
        ctrl.add_to_cache(Address::new(0x3000), results);

        // Loading from cache should work.
        let loaded = ctrl.load_from_cache("prog", Address::new(0x3000), None);
        assert!(loaded);
        assert!(ctrl.has_decompile_results());
    }

    #[test]
    fn test_controller_cache_eviction() {
        let mut ctrl = DecompilerController::new(2);
        ctrl.add_to_cache(
            Address::new(0x1000),
            DecompileResults::success(Address::new(0x1000), make_test_function(0x1000, "a"), 1),
        );
        ctrl.add_to_cache(
            Address::new(0x2000),
            DecompileResults::success(Address::new(0x2000), make_test_function(0x2000, "b"), 1),
        );
        // Cache is full; adding a third should evict one.
        ctrl.add_to_cache(
            Address::new(0x3000),
            DecompileResults::success(Address::new(0x3000), make_test_function(0x3000, "c"), 1),
        );
        assert!(ctrl.cache.len() <= 2);
    }

    #[test]
    fn test_controller_clear_cache() {
        let mut ctrl = DecompilerController::new(10);
        ctrl.add_to_cache(
            Address::new(0x1000),
            DecompileResults::success(Address::new(0x1000), make_test_function(0x1000, "x"), 1),
        );
        ctrl.clear_cache();
        assert!(ctrl.cache.is_empty());
    }

    #[test]
    fn test_controller_complete_decompile() {
        let mut ctrl = DecompilerController::new(10);
        ctrl.is_decompiling = true;
        ctrl.current_data = Some(DecompileData {
            program_name: "test".into(),
            function_entry: Address::new(0x4000),
            function_name: None,
            location: Some(Address::new(0x4000)),
            results: None,
            viewer_position: None,
        });

        let results = DecompileResults::success(
            Address::new(0x4000),
            make_test_function(0x4000, "main"),
            100,
        );
        ctrl.complete_decompile(results);
        assert!(!ctrl.is_decompiling());
        assert!(ctrl.has_decompile_results());
        assert_eq!(ctrl.get_function_name(), Some("main"));
    }

    #[test]
    fn test_controller_status_message() {
        let mut ctrl = DecompilerController::new(10);
        assert_eq!(ctrl.get_status_message(), "No function");

        ctrl.is_decompiling = true;
        assert_eq!(ctrl.get_status_message(), "Decompiling...");
        ctrl.is_decompiling = false;

        ctrl.set_decompile_data(DecompileData::from_results(
            "p",
            Address::new(0x1000),
            Some("main".into()),
            None,
            DecompileResults::success(Address::new(0x1000), make_test_function(0x1000, "main"), 10),
        ));
        assert!(ctrl.get_status_message().contains("main"));
    }

    #[test]
    fn test_decompile_results_success() {
        let results = DecompileResults::success(
            Address::new(0x1000),
            make_test_function(0x1000, "test"),
            42,
        );
        assert!(results.decompile_completed());
        assert!(results.get_function().is_some());
        assert_eq!(results.elapsed_ms, 42);
    }

    #[test]
    fn test_decompile_results_error() {
        let results = DecompileResults::error(Address::new(0x2000), "timeout");
        assert!(!results.decompile_completed());
        assert!(results.get_function().is_none());
        assert_eq!(results.error_message.as_deref(), Some("timeout"));
    }

    #[test]
    fn test_decompile_data_empty() {
        let data = DecompileData::empty("No Function");
        assert!(!data.has_decompile_results());
        assert!(data.get_function_name().is_none());
    }

    #[test]
    fn test_decompile_data_from_results() {
        let results = DecompileResults::success(
            Address::new(0x1000),
            make_test_function(0x1000, "main"),
            10,
        );
        let data = DecompileData::from_results(
            "prog",
            Address::new(0x1000),
            Some("main".into()),
            Some(Address::new(0x1004)),
            results,
        );
        assert!(data.has_decompile_results());
        assert_eq!(data.get_function_name(), Some("main"));
    }

    #[test]
    fn test_controller_selection() {
        let mut ctrl = DecompilerController::new(10);
        assert!(ctrl.current_selection.is_none());
        ctrl.set_selection(Some((Address::new(0x100), Address::new(0x200))));
        assert!(ctrl.current_selection.is_some());
    }

    #[test]
    fn test_controller_display_with_cache_hit() {
        let mut ctrl = DecompilerController::new(10);
        // Pre-populate cache.
        ctrl.add_to_cache(
            Address::new(0x5000),
            DecompileResults::success(
                Address::new(0x5000),
                make_test_function(0x5000, "cached_fn"),
                5,
            ),
        );
        // Display should hit the cache.
        ctrl.display("prog", Address::new(0x5000), None);
        assert!(ctrl.has_decompile_results());
        assert_eq!(ctrl.get_function_name(), Some("cached_fn"));
    }

    #[test]
    fn test_controller_program_closed() {
        let mut ctrl = DecompilerController::new(10);
        ctrl.current_data = Some(DecompileData::from_results(
            "old_prog",
            Address::new(0x1000),
            Some("main".into()),
            None,
            DecompileResults::success(Address::new(0x1000), make_test_function(0x1000, "main"), 10),
        ));
        ctrl.add_to_cache(
            Address::new(0x1000),
            DecompileResults::success(
                Address::new(0x1000),
                make_test_function(0x1000, "main"),
                10,
            ),
        );
        ctrl.program_closed("old_prog");
        assert!(ctrl.cache.is_empty());
    }
}
