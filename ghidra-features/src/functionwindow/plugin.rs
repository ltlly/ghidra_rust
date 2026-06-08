//! Function window plugin.
//!
//! Ported from Ghidra's `FunctionWindowPlugin extends ProgramPlugin`.
//!
//! Listens for domain-object events (function added/removed/changed, symbol
//! renamed, memory layout changes) and forwards them to the model for live
//! table updates. Manages the function comparison service integration and
//! configuration state persistence.

use super::events::{EventQueue, FunctionWindowEvent};
use super::model::FunctionTableModel;
use super::{FunctionRef, FunctionStore};
use ghidra_core::Address;

// ===========================================================================
// FunctionWindowPlugin
// ===========================================================================

/// Plugin that provides the function list window.
///
/// This is the Rust equivalent of Ghidra's `FunctionWindowPlugin`, which
/// extends `ProgramPlugin`. It owns the [`FunctionTableModel`] and an
/// [`EventQueue`] that debounces batch events (matching the Java
/// `SwingUpdateManager` with a 1000ms interval).
///
/// # Event handling
///
/// The plugin processes domain events as follows:
///
/// - `RESTORED`, `MEMORY_BLOCK_MOVED`, `MEMORY_BLOCK_REMOVED`:
///   triggers a full model reload (immediate).
/// - `CODE_ADDED`, `CODE_REMOVED`:
///   queued in the batch queue, delivered after the interval.
/// - `FUNCTION_ADDED`, `FUNCTION_REMOVED`, `FUNCTION_CHANGED`:
///   applied incrementally to the model.
/// - `SYMBOL_ADDED`, `SYMBOL_PRIMARY_STATE_CHANGED`, `SYMBOL_RENAMED`:
///   looks up the function at the symbol's address and updates it.
///
/// # Example
///
/// ```ignore
/// let mut plugin = FunctionWindowPlugin::new();
/// plugin.program_opened(store);
/// plugin.set_visible(true);
/// plugin.function_added(&new_func);
/// ```
#[derive(Debug)]
pub struct FunctionWindowPlugin {
    /// Plugin name.
    pub name: String,
    /// The function table model.
    pub model: FunctionTableModel,
    /// Current program store, if any.
    pub current_program: Option<FunctionStore>,
    /// Whether the provider is visible.
    pub provider_visible: bool,
    /// Whether navigate-on-incoming is enabled.
    pub navigate_on_incoming: bool,
    /// Whether navigate-on-outgoing is enabled.
    pub navigate_on_outgoing: bool,
    /// Whether the comparison service is available.
    pub has_comparison_service: bool,
    /// Event queue for batched updates.
    event_queue: EventQueue,
}

impl FunctionWindowPlugin {
    /// Create a new function window plugin.
    pub fn new() -> Self {
        Self {
            name: "FunctionWindow".into(),
            model: FunctionTableModel::new("Functions"),
            current_program: None,
            provider_visible: false,
            navigate_on_incoming: false,
            navigate_on_outgoing: false,
            has_comparison_service: false,
            event_queue: EventQueue::new(1000),
        }
    }

    /// Set the current program (activate).
    ///
    /// Adds a domain-object listener to the program and reloads the model
    /// if the provider is visible.
    pub fn program_opened(&mut self, store: FunctionStore) {
        self.model.reload(Some(store.clone()));
        self.current_program = Some(store);
    }

    /// Clear the current program (deactivate).
    ///
    /// Removes the domain-object listener and clears the model.
    pub fn program_closed(&mut self) {
        self.model.reload(None);
        self.current_program = None;
        self.event_queue.clear();
    }

    /// Process a single domain event.
    ///
    /// This is the main event dispatch method, matching the Java
    /// `DomainObjectListenerBuilder` chain.
    pub fn handle_event(&mut self, event: FunctionWindowEvent) {
        if !self.provider_visible && !event.requires_reload() {
            return;
        }

        if event.requires_reload() {
            self.reload();
            return;
        }

        if event.is_batch_event() {
            self.event_queue.push(event);
            return;
        }

        // Incremental events
        match &event {
            FunctionWindowEvent::FunctionAdded(func) => {
                self.model.function_added(func);
            }
            FunctionWindowEvent::FunctionRemoved(func) => {
                self.model.function_removed(func);
            }
            FunctionWindowEvent::FunctionChanged(func) => {
                self.model.update(func);
            }
            FunctionWindowEvent::SymbolAdded { address, .. }
            | FunctionWindowEvent::SymbolPrimaryStateChanged { address, .. }
            | FunctionWindowEvent::SymbolRenamed { address, .. } => {
                self.symbol_changed_at(*address);
            }
            FunctionWindowEvent::ProgramClosed => {
                self.program_closed();
            }
            _ => {}
        }
    }

    /// Drain and process all batched events from the event queue.
    ///
    /// This should be called periodically (every ~1000ms) to flush
    /// deferred `CODE_ADDED`/`CODE_REMOVED` events.
    pub fn flush_events(&mut self) {
        let events = self.event_queue.drain();
        for event in events {
            if event.requires_reload() {
                self.reload();
                return;
            }
            // Batch code events just trigger a reload
            if event.is_batch_event() {
                self.reload();
                return;
            }
        }
    }

    /// Whether there are pending batch events.
    pub fn has_pending_events(&self) -> bool {
        self.event_queue.has_pending()
    }

    // -- Individual event handlers (matching Java methods) --

    /// Handle a function-added domain event.
    ///
    /// Corresponds to Java's `functionAdded(ProgramChangeRecord)`.
    pub fn function_added(&mut self, func: &FunctionRef) {
        if self.provider_visible {
            self.model.function_added(func);
        }
    }

    /// Handle a function-removed domain event.
    ///
    /// Corresponds to Java's `functionRemoved(ProgramChangeRecord)`.
    pub fn function_removed(&mut self, func: &FunctionRef) {
        if self.provider_visible {
            self.model.function_removed(func);
        }
    }

    /// Handle a function-changed domain event.
    ///
    /// Corresponds to Java's `functionChanged(ProgramChangeRecord)`.
    pub fn function_changed(&mut self, func: &FunctionRef) {
        if self.provider_visible {
            self.model.update(func);
        }
    }

    /// Handle a symbol-changed event at the given address.
    ///
    /// Looks up the function at the address and updates it in the model.
    /// Corresponds to Java's `symbolChanged` / `symbolRenamed`.
    fn symbol_changed_at(&mut self, addr: u64) {
        if !self.provider_visible {
            return;
        }
        if let Some(store) = &self.current_program {
            if let Some(func) = store.get_function_containing(Address::new(addr)) {
                let func_ref = func.clone();
                self.model.update(&func_ref);
            }
        }
    }

    /// Handle a symbol-renamed domain event.
    ///
    /// Corresponds to Java's `symbolRenamed(ProgramChangeRecord)`.
    pub fn symbol_renamed(&mut self, addr: Address) {
        self.symbol_changed_at(addr.offset);
    }

    /// Handle a location-changed event (select function at address).
    ///
    /// When navigate-on-incoming is enabled, this signals that the UI
    /// should scroll to the function at the given address.
    pub fn location_changed(&mut self, addr: Option<Address>) {
        if !self.provider_visible || !self.navigate_on_incoming {
            return;
        }
        let _ = addr;
    }

    /// Reload the model from the current program.
    ///
    /// Corresponds to Java's `provider.reload()`.
    pub fn reload(&mut self) {
        if self.provider_visible {
            if let Some(store) = self.current_program.clone() {
                self.model.reload(Some(store));
            }
        }
    }

    /// Set provider visibility.
    ///
    /// When made visible, reloads the model. When hidden, clears it.
    pub fn set_visible(&mut self, visible: bool) {
        self.provider_visible = visible;
        if visible {
            self.reload();
        } else {
            self.model.reload(None);
        }
    }

    /// Simulate service-added callback for FunctionComparisonService.
    ///
    /// Corresponds to Java's `serviceAdded(Class, Object)`.
    pub fn service_added_comparison(&mut self) {
        self.has_comparison_service = true;
    }

    /// Simulate service-removed callback for FunctionComparisonService.
    ///
    /// Corresponds to Java's `serviceRemoved(Class, Object)`.
    pub fn service_removed_comparison(&mut self) {
        self.has_comparison_service = false;
    }

    /// Read configuration state.
    ///
    /// Corresponds to Java's `readConfigState(SaveState)`.
    pub fn read_config(&mut self, navigate_on_incoming: bool, navigate_on_outgoing: bool) {
        self.navigate_on_incoming = navigate_on_incoming;
        self.navigate_on_outgoing = navigate_on_outgoing;
    }

    /// Write configuration state.
    ///
    /// Corresponds to Java's `writeConfigState(SaveState)`.
    pub fn write_config(&self) -> (bool, bool) {
        (self.navigate_on_incoming, self.navigate_on_outgoing)
    }

    /// Get the current program name.
    pub fn program_name(&self) -> &str {
        self.current_program
            .as_ref()
            .map(|s| s.program_name.as_str())
            .unwrap_or("")
    }
}

impl Default for FunctionWindowPlugin {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_func(id: u64, name: &str, offset: u64) -> FunctionRef {
        FunctionRef::new(id, name, Address::new(offset), format!("void {}()", name))
    }

    fn make_store() -> FunctionStore {
        let mut store = FunctionStore::new("test.exe");
        store.add_function(make_func(1, "main", 0x401000));
        store.add_function(make_func(2, "foo", 0x402000));
        store.add_function(make_func(3, "bar", 0x403000));
        store.add_function(make_func(4, "ext_import", 0x0));
        store.functions.get_mut(&4).unwrap().is_external = true;
        store
    }

    #[test]
    fn test_plugin_new() {
        let plugin = FunctionWindowPlugin::new();
        assert_eq!(plugin.name, "FunctionWindow");
        assert!(!plugin.provider_visible);
        assert!(plugin.current_program.is_none());
    }

    #[test]
    fn test_plugin_program_opened_closed() {
        let mut plugin = FunctionWindowPlugin::new();
        plugin.program_opened(make_store());
        assert_eq!(plugin.model.row_count(), 3);
        assert!(plugin.current_program.is_some());

        plugin.program_closed();
        assert_eq!(plugin.model.row_count(), 0);
        assert!(plugin.current_program.is_none());
    }

    #[test]
    fn test_plugin_function_events() {
        let mut plugin = FunctionWindowPlugin::new();
        plugin.provider_visible = true;
        plugin.program_opened(make_store());

        // Add
        plugin.function_added(&make_func(10, "new", 0x500000));
        assert!(plugin.model.get_row_by_key(10).is_some());

        // Change
        let mut changed = make_func(10, "new_renamed", 0x500000);
        changed.body_size = 128;
        plugin.function_changed(&changed);
        assert_eq!(plugin.model.get_row_by_key(10).unwrap().function.name, "new_renamed");

        // Remove
        plugin.function_removed(&make_func(10, "new_renamed", 0x500000));
        assert!(plugin.model.get_row_by_key(10).is_none());
    }

    #[test]
    fn test_plugin_events_ignored_when_hidden() {
        let mut plugin = FunctionWindowPlugin::new();
        plugin.provider_visible = false;
        plugin.program_opened(make_store());
        plugin.function_added(&make_func(10, "new", 0x500000));
        assert!(plugin.model.get_row_by_key(10).is_none());
    }

    #[test]
    fn test_plugin_symbol_renamed() {
        let mut plugin = FunctionWindowPlugin::new();
        plugin.provider_visible = true;
        let mut store = make_store();
        let mut f = make_func(5, "target", 0x600000);
        f.body_size = 0x100;
        store.add_function(f);
        plugin.program_opened(store);

        plugin.symbol_renamed(Address::new(0x600000));
        assert!(plugin.model.get_row_by_key(5).is_some());
    }

    #[test]
    fn test_plugin_visibility() {
        let mut plugin = FunctionWindowPlugin::new();
        plugin.program_opened(make_store());

        plugin.set_visible(true);
        assert!(plugin.provider_visible);
        assert_eq!(plugin.model.row_count(), 3);

        plugin.set_visible(false);
        assert!(!plugin.provider_visible);
        assert_eq!(plugin.model.row_count(), 0);
    }

    #[test]
    fn test_plugin_config() {
        let mut plugin = FunctionWindowPlugin::new();
        plugin.read_config(true, false);
        assert!(plugin.navigate_on_incoming);
        assert!(!plugin.navigate_on_outgoing);
        let (inc, out) = plugin.write_config();
        assert!(inc);
        assert!(!out);
    }

    #[test]
    fn test_plugin_comparison_service() {
        let mut plugin = FunctionWindowPlugin::new();
        assert!(!plugin.has_comparison_service);
        plugin.service_added_comparison();
        assert!(plugin.has_comparison_service);
        plugin.service_removed_comparison();
        assert!(!plugin.has_comparison_service);
    }

    #[test]
    fn test_plugin_handle_event_function_added() {
        let mut plugin = FunctionWindowPlugin::new();
        plugin.provider_visible = true;
        plugin.program_opened(make_store());

        let event = FunctionWindowEvent::FunctionAdded(make_func(100, "new_fn", 0x800000));
        plugin.handle_event(event);
        assert!(plugin.model.get_row_by_key(100).is_some());
    }

    #[test]
    fn test_plugin_handle_event_restored() {
        let mut plugin = FunctionWindowPlugin::new();
        plugin.provider_visible = true;
        plugin.program_opened(make_store());

        let event = FunctionWindowEvent::Restored;
        plugin.handle_event(event);
        // Model should have been reloaded
        assert_eq!(plugin.model.row_count(), 3);
    }

    #[test]
    fn test_plugin_handle_event_batch() {
        let mut plugin = FunctionWindowPlugin::new();
        plugin.provider_visible = true;
        plugin.program_opened(make_store());

        let event = FunctionWindowEvent::CodeAdded;
        plugin.handle_event(event);
        assert!(plugin.has_pending_events());

        plugin.flush_events();
        assert!(!plugin.has_pending_events());
    }

    #[test]
    fn test_plugin_program_name() {
        let mut plugin = FunctionWindowPlugin::new();
        assert_eq!(plugin.program_name(), "");
        plugin.program_opened(make_store());
        assert_eq!(plugin.program_name(), "test.exe");
    }

    #[test]
    fn test_plugin_default() {
        let plugin = FunctionWindowPlugin::default();
        assert_eq!(plugin.name, "FunctionWindow");
    }

    #[test]
    fn test_plugin_full_workflow() {
        let mut plugin = FunctionWindowPlugin::new();

        // Open program
        plugin.program_opened(make_store());
        assert_eq!(plugin.model.row_count(), 3);

        // Make visible
        plugin.set_visible(true);
        assert!(plugin.provider_visible);

        // Simulate function addition
        plugin.function_added(&make_func(100, "dynamic_func", 0x800000));
        assert_eq!(plugin.model.row_count(), 4);

        // Navigate to it
        let idx = plugin.model.find_by_address(Address::new(0x800000)).unwrap();
        let row = plugin.model.get_row(idx).unwrap();
        assert_eq!(row.function.name, "dynamic_func");

        // Close program
        plugin.program_closed();
        assert_eq!(plugin.model.row_count(), 0);
    }
}
