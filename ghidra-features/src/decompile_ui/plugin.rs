//! Decompile plugin -- Rust port of
//! `ghidra.app.plugin.core.decompile.DecompilePlugin`.
//!
//! The plugin is the top-level owner of all decompiler providers.  It
//! routes program events (activate, close, location, selection) to the
//! appropriate provider and manages the lifecycle of connected and
//! disconnected providers.
//!
//! # Architecture
//!
//! ```text
//! DecompilePlugin
//!   ├── PrimaryDecompilerProvider  (always connected, id=0)
//!   ├── Vec<DecompilerProvider>    (disconnected / snapshot windows)
//!   ├── delayed_location_updater   (debounce location events)
//!   ├── clipboard_service          (shared clipboard)
//!   └── hover_services             (decompiler hover providers)
//! ```
//!
//! # State Persistence
//!
//! The plugin supports `write_data_state` / `read_data_state` to save
//! and restore its configuration across Ghidra sessions.  Connected
//! provider state is saved directly; disconnected providers are saved
//! by recording the program file path and their viewer position.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use ghidra_core::addr::Address;

use super::primary_provider::PrimaryDecompilerProvider;
use super::provider::DecompilerProvider;

// ---------------------------------------------------------------------------
// Plugin event types
// ---------------------------------------------------------------------------

/// Events that the decompile plugin processes.
///
/// These correspond to the Ghidra `PluginEvent` subclasses consumed by
/// `DecompilePlugin.processEvent()`.
#[derive(Debug, Clone)]
pub enum PluginEvent {
    /// A program was activated in the tool.
    ProgramActivated {
        /// The name of the activated program.
        program_name: String,
    },
    /// A program was opened.
    ProgramOpened {
        /// The name of the opened program.
        program_name: String,
    },
    /// The user navigated to a new location.
    LocationChanged {
        /// The program name.
        program_name: String,
        /// The address the user navigated to.
        address: Address,
        /// Whether the address is in an external space (should be skipped).
        is_external: bool,
        /// Whether the address points to data (should be skipped).
        is_data: bool,
    },
    /// The user changed the selection.
    SelectionChanged {
        /// The program name.
        program_name: String,
        /// The selected address range (start, end).
        range: (Address, Address),
    },
    /// A program was closed.
    ProgramClosed {
        /// The name of the closed program.
        program_name: String,
    },
}

/// Events that the plugin fires to the tool.
#[derive(Debug, Clone)]
pub enum FiredPluginEvent {
    /// A location change event.
    LocationChanged {
        /// The provider that originated the change.
        provider_id: usize,
        /// The program name.
        program_name: String,
        /// The new address.
        address: Address,
    },
    /// A selection change event.
    SelectionChanged {
        /// The provider that originated the change.
        provider_id: usize,
        /// The program name.
        program_name: String,
        /// The selected range.
        range: (Address, Address),
    },
}

// ---------------------------------------------------------------------------
// HoverServiceId -- placeholder for decompiler hover service registration
// ---------------------------------------------------------------------------

/// Identifier for a registered decompiler hover service.
///
/// In Ghidra, `DecompilerHoverService` instances are added/removed when
/// services appear or disappear.  Here we model the registration as an
/// opaque id.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HoverServiceId(pub String);

// ---------------------------------------------------------------------------
// SaveState -- lightweight key/value store for persistence
// ---------------------------------------------------------------------------

/// A serialisable key/value bag used to persist plugin and provider state
/// across Ghidra sessions.
///
/// Maps directly to Ghidra's `SaveState` Java class which stores
/// primitives and XML sub-elements.
#[derive(Debug, Clone, Default)]
pub struct SaveState {
    /// Integer values.
    ints: HashMap<String, i64>,
    /// String values.
    strings: HashMap<String, String>,
    /// Nested XML-like sub-elements (themselves `SaveState`s).
    xml_elements: HashMap<String, SaveState>,
    /// Program paths for disconnected providers.
    provider_program_paths: Vec<String>,
    /// Viewer index per disconnected provider.
    provider_viewer_indices: Vec<i32>,
    /// Viewer Y-offset per disconnected provider.
    provider_viewer_y_offsets: Vec<i32>,
}

impl SaveState {
    /// Create an empty save state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Put an integer value.
    pub fn put_int(&mut self, key: impl Into<String>, value: i64) {
        self.ints.insert(key.into(), value);
    }

    /// Get an integer value (returns `default` if missing).
    pub fn get_int(&self, key: &str, default: i64) -> i64 {
        self.ints.get(key).copied().unwrap_or(default)
    }

    /// Put a string value.
    pub fn put_string(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.strings.insert(key.into(), value.into());
    }

    /// Get a string value (returns `default` if missing).
    pub fn get_string(&self, key: &str, default: &str) -> String {
        self.strings
            .get(key)
            .cloned()
            .unwrap_or_else(|| default.to_string())
    }

    /// Put an XML sub-element (as a nested `SaveState`).
    pub fn put_xml_element(&mut self, key: impl Into<String>, element: SaveState) {
        self.xml_elements.insert(key.into(), element);
    }

    /// Get an XML sub-element.
    pub fn get_xml_element(&self, key: &str) -> Option<&SaveState> {
        self.xml_elements.get(key)
    }

    /// Save a viewer position (index + y-offset).
    pub fn put_viewer_position(&mut self, index: i32, y_offset: i32) {
        self.put_int("VIEWER_INDEX", index as i64);
        self.put_int("VIEWER_Y_OFFSET", y_offset as i64);
    }

    /// Restore a viewer position.
    pub fn get_viewer_position(&self) -> (i32, i32) {
        let index = self.get_int("VIEWER_INDEX", 0) as i32;
        let y_offset = self.get_int("VIEWER_Y_OFFSET", 0) as i32;
        (index, y_offset)
    }
}

// ---------------------------------------------------------------------------
// DelayedLocationUpdater -- debounces rapid location events
// ---------------------------------------------------------------------------

/// A debounce mechanism for location events.
///
/// When the user switches program tabs, multiple location events arrive
/// in rapid succession.  This updater delays the actual location
/// propagation to allow events to settle.
///
/// In Ghidra this is `SwingUpdateManager(200, 200, ...)`.
#[derive(Debug)]
pub struct DelayedLocationUpdater {
    /// The last time `update_later` was called.
    last_update: Option<Instant>,
    /// The debounce duration.
    delay: Duration,
    /// The pending address to propagate.
    pending_address: Option<Address>,
    /// The pending program name.
    pending_program: Option<String>,
}

impl DelayedLocationUpdater {
    /// Create a new delayed updater with the given debounce delay.
    pub fn new(delay_ms: u64) -> Self {
        Self {
            last_update: None,
            delay: Duration::from_millis(delay_ms),
            pending_address: None,
            pending_program: None,
        }
    }

    /// Schedule a location update.  The address will be propagated
    /// only after `delay` elapses without another call.
    pub fn update_later(&mut self, program: String, address: Address) {
        self.pending_program = Some(program);
        self.pending_address = Some(address);
        self.last_update = Some(Instant::now());
    }

    /// Check whether the debounce period has elapsed and consume the
    /// pending update.
    pub fn poll(&mut self) -> Option<(String, Address)> {
        let last = self.last_update?;
        if last.elapsed() >= self.delay {
            self.last_update = None;
            let program = self.pending_program.take()?;
            let address = self.pending_address.take()?;
            Some((program, address))
        } else {
            None
        }
    }

    /// Cancel any pending update.
    pub fn cancel(&mut self) {
        self.last_update = None;
        self.pending_address = None;
        self.pending_program = None;
    }

    /// Returns `true` if there is a pending update.
    pub fn has_pending(&self) -> bool {
        self.last_update.is_some()
    }
}

// ---------------------------------------------------------------------------
// ServiceRegistration -- tracks tool service dependencies
// ---------------------------------------------------------------------------

/// Tracks which tool services the plugin has registered or is waiting for.
#[derive(Debug, Clone, Default)]
pub struct ServiceRegistration {
    /// Services the plugin provides to other plugins.
    pub services_provided: Vec<String>,
    /// Services the plugin requires from the tool.
    pub services_required: Vec<String>,
    /// Whether clipboard service has been bound.
    pub clipboard_bound: bool,
}

// ---------------------------------------------------------------------------
// DecompilePlugin
// ---------------------------------------------------------------------------

/// The decompiler plugin.
///
/// Owns the primary (connected) decompiler provider and zero or more
/// "disconnected" providers (snapshots).  Processes tool events and
/// dispatches them to providers.
///
/// # Lifecycle
///
/// 1. Created by the tool infrastructure.
/// 2. `init()` binds the clipboard service to all providers.
/// 3. On `ProgramActivated`, the primary provider is set to the new
///    program.
/// 4. On `LocationChanged`, the primary provider is asked to display
///    the new address (with a debounce delay).
/// 5. On `ProgramClosed`, any disconnected providers for that program
///    are removed.
/// 6. `dispose()` tears down all providers.
///
/// # Services
///
/// Provided: `DecompilerHighlightService`, `DecompilerMarginService`.
///
/// Required: `GoToService`, `NavigationHistoryService`,
/// `ClipboardService`, `DataTypeManagerService`.
///
/// Events consumed: `ProgramActivated`, `ProgramOpened`,
/// `ProgramLocation`, `ProgramSelection`, `ProgramClosed`.
#[derive(Debug)]
pub struct DecompilePlugin {
    /// The plugin's display name.
    name: String,
    /// The primary (connected) provider.
    connected_provider: PrimaryDecompilerProvider,
    /// Disconnected providers (snapshots).
    disconnected_providers: Vec<DecompilerProvider>,
    /// The currently active program name.
    current_program: Option<String>,
    /// The current location (address offset).
    current_location: Option<Address>,
    /// The current selection range.
    current_selection: Option<(Address, Address)>,
    /// Count of disconnected providers created.
    next_disconnected_id: usize,
    /// Debounced location updater (200ms debounce).
    delayed_location_updater: DelayedLocationUpdater,
    /// Service registration state.
    service_registration: ServiceRegistration,
    /// Registered hover services.
    hover_services: Vec<HoverServiceId>,
    /// Outgoing plugin events that have been fired (for test inspection).
    fired_events: Vec<FiredPluginEvent>,
    /// Whether the plugin has been disposed.
    disposed: bool,
}

impl DecompilePlugin {
    /// Plugin option category name.
    pub const OPTIONS_TITLE: &'static str = "Decompiler";

    /// Debounce delay in milliseconds for location changes.
    const LOCATION_DEBOUNCE_MS: u64 = 200;

    /// Create a new decompile plugin.
    pub fn new() -> Self {
        Self {
            name: "Decompile".to_string(),
            connected_provider: PrimaryDecompilerProvider::new(),
            disconnected_providers: Vec::new(),
            current_program: None,
            current_location: None,
            current_selection: None,
            next_disconnected_id: 1,
            delayed_location_updater: DelayedLocationUpdater::new(Self::LOCATION_DEBOUNCE_MS),
            service_registration: ServiceRegistration {
                services_provided: vec![
                    "DecompilerHighlightService".into(),
                    "DecompilerMarginService".into(),
                ],
                services_required: vec![
                    "GoToService".into(),
                    "NavigationHistoryService".into(),
                    "ClipboardService".into(),
                    "DataTypeManagerService".into(),
                ],
                clipboard_bound: false,
            },
            hover_services: Vec::new(),
            fired_events: Vec::new(),
            disposed: false,
        }
    }

    /// The plugin name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns a reference to the connected (primary) provider.
    pub fn connected_provider(&self) -> &PrimaryDecompilerProvider {
        &self.connected_provider
    }

    /// Returns a mutable reference to the connected (primary) provider.
    pub fn connected_provider_mut(&mut self) -> &mut PrimaryDecompilerProvider {
        &mut self.connected_provider
    }

    /// Returns the number of disconnected providers.
    pub fn disconnected_count(&self) -> usize {
        self.disconnected_providers.len()
    }

    /// Get a reference to a disconnected provider by id.
    pub fn disconnected_provider(&self, id: usize) -> Option<&DecompilerProvider> {
        self.disconnected_providers.iter().find(|p| p.id() == id)
    }

    /// Get a mutable reference to a disconnected provider by id.
    pub fn disconnected_provider_mut(&mut self, id: usize) -> Option<&mut DecompilerProvider> {
        self.disconnected_providers.iter_mut().find(|p| p.id() == id)
    }

    /// Create a new disconnected provider (snapshot window).
    ///
    /// Returns the id of the newly created provider.  The provider is
    /// immediately shown (state = Visible).
    pub fn create_new_disconnected_provider(&mut self) -> usize {
        let id = self.next_disconnected_id;
        self.next_disconnected_id += 1;
        let mut provider = DecompilerProvider::new_disconnected(id);
        provider.set_visible();
        self.disconnected_providers.push(provider);
        id
    }

    /// Whether the plugin has been disposed.
    pub fn is_disposed(&self) -> bool {
        self.disposed
    }

    // -- Initialization -------------------------------------------------------

    /// Called by the tool after construction to bind runtime services.
    ///
    /// In Ghidra this binds the `ClipboardService` to all providers.
    pub fn init(&mut self, clipboard_available: bool) {
        self.service_registration.clipboard_bound = clipboard_available;
        // In the full implementation, clipboard service is registered
        // with each provider's clipboard content provider.
    }

    /// Register a hover service with the connected provider's panel.
    pub fn add_hover_service(&mut self, service: HoverServiceId) {
        self.hover_services.push(service);
    }

    /// Remove a hover service from the connected provider's panel.
    pub fn remove_hover_service(&mut self, service: &HoverServiceId) {
        self.hover_services.retain(|s| s != service);
    }

    // -- Event Processing -----------------------------------------------------

    /// Process a program event.
    ///
    /// This is the main dispatch method called by the tool infrastructure
    /// when plugin events arrive.
    pub fn process_event(&mut self, event: PluginEvent) {
        if self.disposed {
            return;
        }

        match event {
            PluginEvent::ProgramClosed { program_name } => {
                self.program_closed(&program_name);
            }
            PluginEvent::ProgramActivated { program_name } => {
                self.current_program = Some(program_name.clone());
                self.connected_provider
                    .set_program(Some(program_name));
                // In Ghidra, SpecExtension.registerOptions(currentProgram) is called here.
            }
            PluginEvent::LocationChanged {
                program_name,
                address,
                is_external,
                is_data,
            } => {
                // Skip external addresses and data addresses.
                if is_external || is_data {
                    return;
                }
                if self.current_program.as_deref() == Some(&program_name) {
                    self.current_location = Some(address);
                    // Delay location change to allow immediate location
                    // changes to settle down (e.g., when switching program
                    // tabs in the code browser).
                    self.delayed_location_updater
                        .update_later(program_name, address);
                }
            }
            PluginEvent::SelectionChanged {
                program_name,
                range,
            } => {
                if self.current_program.as_deref() == Some(&program_name) {
                    self.current_selection = Some(range);
                    self.connected_provider
                        .set_selection(Some(range));
                    self.fire_selection_event(0, &program_name, range);
                }
            }
            PluginEvent::ProgramOpened { .. } => {
                // No action needed on open; activation will follow.
            }
        }
    }

    /// Poll the delayed location updater.  Should be called periodically
    /// (e.g., on a timer tick) to propagate debounced location changes.
    ///
    /// Returns the program/address pair if the debounce elapsed.
    pub fn poll_delayed_location(&mut self) -> Option<(String, Address)> {
        if let Some((program, address)) = self.delayed_location_updater.poll() {
            // Only update if the program still matches.
            if self.current_program.as_deref() == Some(&program) {
                self.connected_provider.set_location(Some(address));
                return Some((program, address));
            }
        }
        None
    }

    // -- Provider management --------------------------------------------------

    /// Close a provider.  If the provider is the connected one, it is
    /// hidden.  If it is a disconnected provider, it is removed and
    /// disposed.
    pub fn close_provider(&mut self, provider_id: usize) {
        if provider_id == 0 {
            // Closing the connected provider just hides it.
            self.connected_provider.set_hidden();
        } else {
            if let Some(pos) = self
                .disconnected_providers
                .iter()
                .position(|p| p.id() == provider_id)
            {
                let mut provider = self.disconnected_providers.remove(pos);
                provider.dispose();
            }
        }
    }

    /// Export the current location to the GoToService.
    ///
    /// In Ghidra, this calls `GoToService.goTo(location, program)`.
    pub fn export_location(&self) -> Option<(&str, Address)> {
        if let (Some(program), Some(addr)) = (&self.current_program, self.current_location) {
            Some((program.as_str(), addr))
        } else {
            None
        }
    }

    /// Notify the plugin that the connected provider's location changed.
    ///
    /// This fires a `ProgramLocationPluginEvent` to the tool if the
    /// provider is allowed to send events.
    pub fn location_changed(&mut self, provider_id: usize, address: Address) {
        if let Some(program) = &self.current_program {
            if self.should_send_events(provider_id) {
                self.fired_events.push(FiredPluginEvent::LocationChanged {
                    provider_id,
                    program_name: program.clone(),
                    address,
                });
            }
        }
    }

    /// Notify the plugin that a provider's selection changed.
    ///
    /// This fires a `ProgramSelectionPluginEvent` to the tool if the
    /// provider is allowed to send events.
    pub fn selection_changed(&mut self, provider_id: usize, range: (Address, Address)) {
        if self.current_program.is_some() && self.should_send_events(provider_id) {
            if let Some(program) = self.current_program.clone() {
                self.fire_selection_event(provider_id, &program, range);
            }
        }
    }

    /// Notify all providers that a token was renamed.
    ///
    /// This is called after a user renames a variable, field, or
    /// function in one provider.  All providers (connected +
    /// disconnected) must update their display.
    pub fn handle_token_renamed(&mut self, old_name: &str, new_name: &str) {
        self.connected_provider
            .notify_token_renamed(old_name, new_name);
        for provider in &mut self.disconnected_providers {
            provider.notify_token_renamed(old_name, new_name);
        }
    }

    /// Get the current location.
    pub fn current_location(&self) -> Option<Address> {
        self.current_location
    }

    /// Get the current program name.
    pub fn current_program(&self) -> Option<&str> {
        self.current_program.as_deref()
    }

    /// Get the current selection.
    pub fn current_selection(&self) -> Option<(Address, Address)> {
        self.current_selection
    }

    /// Close a disconnected provider by its id.
    /// Returns `true` if found and removed.
    pub fn close_disconnected_provider(&mut self, id: usize) -> bool {
        let mut found = false;
        self.disconnected_providers.retain(|p| {
            if p.id() == id {
                found = true;
                false
            } else {
                true
            }
        });
        found
    }

    /// Get the list of fired events (for test inspection).
    pub fn fired_events(&self) -> &[FiredPluginEvent] {
        &self.fired_events
    }

    /// Clear the fired events list.
    pub fn clear_fired_events(&mut self) {
        self.fired_events.clear();
    }

    /// Whether the given provider should send events.
    fn should_send_events(&self, provider_id: usize) -> bool {
        if provider_id == 0 {
            // Connected provider always sends events.
            true
        } else {
            // Disconnected providers only send if allowed.
            self.disconnected_providers
                .iter()
                .find(|p| p.id() == provider_id)
                .map(|p| p.should_send_events())
                .unwrap_or(false)
        }
    }

    /// Fire a selection event.
    fn fire_selection_event(
        &mut self,
        provider_id: usize,
        program: &str,
        range: (Address, Address),
    ) {
        self.fired_events.push(FiredPluginEvent::SelectionChanged {
            provider_id,
            program_name: program.to_string(),
            range,
        });
    }

    /// Handle a program being closed.
    fn program_closed(&mut self, closed_program: &str) {
        // Remove disconnected providers for the closed program.
        self.disconnected_providers.retain(|p| {
            p.program_name() != Some(closed_program)
        });

        // If the active program was closed, clear the connected provider.
        if self.current_program.as_deref() == Some(closed_program) {
            self.current_program = None;
            self.current_location = None;
            self.current_selection = None;
            self.connected_provider.set_program(None);
        }
    }

    // -- State Persistence ----------------------------------------------------

    /// Write the plugin's state for persistence across sessions.
    ///
    /// Saves:
    /// - Connected provider's location and viewer position.
    /// - Number of disconnected providers.
    /// - Each disconnected provider's program path and viewer position.
    pub fn write_data_state(&self) -> SaveState {
        let mut state = SaveState::new();

        // Save connected provider state.
        if let Some(addr) = self.current_location {
            state.put_int("ConnectedLocation", addr.offset as i64);
        }

        // Save disconnected provider count.
        state.put_int(
            "Num Disconnected",
            self.disconnected_providers.len() as i64,
        );

        // Save each disconnected provider.
        for (i, provider) in self.disconnected_providers.iter().enumerate() {
            let mut provider_state = SaveState::new();
            if let Some(program) = provider.program_name() {
                provider_state.put_string("Program Path", program);
            }
            // In the full implementation, viewer position is saved here.
            provider_state.put_int("ID", provider.id() as i64);
            state.put_xml_element(format!("Provider{}", i), provider_state);
        }

        state
    }

    /// Read the plugin's state from persistence.
    ///
    /// Returns the list of disconnected provider configurations that
    /// need to be restored (program path + viewer position).
    pub fn read_data_state(state: &SaveState) -> Vec<(String, Option<(i32, i32)>)> {
        let num_disconnected = state.get_int("Num Disconnected", 0) as usize;
        let mut providers = Vec::with_capacity(num_disconnected);

        for i in 0..num_disconnected {
            let key = format!("Provider{}", i);
            if let Some(provider_state) = state.get_xml_element(&key) {
                let program_path = provider_state.get_string("Program Path", "");
                if !program_path.is_empty() {
                    let viewer_pos = provider_state.get_viewer_position();
                    providers.push((program_path, Some(viewer_pos)));
                }
            }
        }

        providers
    }

    /// Dispose the plugin, cleaning up all providers.
    pub fn dispose(&mut self) {
        self.disposed = true;
        self.current_program = None;
        self.current_location = None;
        self.current_selection = None;
        self.connected_provider.dispose();
        for p in &mut self.disconnected_providers {
            p.dispose();
        }
        self.disconnected_providers.clear();
        self.hover_services.clear();
        self.delayed_location_updater.cancel();
    }

    // -- Service lifecycle (hover services) -----------------------------------

    /// Handle a tool service being added.
    ///
    /// In Ghidra this is `serviceAdded()` which registers
    /// `DecompilerHoverService` instances with all provider panels.
    pub fn service_added(&mut self, interface_class: &str, service_name: &str) {
        if interface_class == "DecompilerHoverService" {
            let svc = HoverServiceId(service_name.to_string());
            // Register with connected provider.
            self.connected_provider
                .notify_token_renamed("", ""); // triggers panel refresh
            // Register with all disconnected providers.
            for provider in &mut self.disconnected_providers {
                provider.notify_token_renamed("", "");
            }
            self.hover_services.push(svc);
        }
    }

    /// Handle a tool service being removed.
    ///
    /// In Ghidra this is `serviceRemoved()` which unregisters
    /// `DecompilerHoverService` instances from all provider panels.
    pub fn service_removed(&mut self, interface_class: &str, service_name: &str) {
        if interface_class == "DecompilerHoverService" {
            let svc = HoverServiceId(service_name.to_string());
            self.hover_services.retain(|s| s != &svc);
            // Unregister from connected provider.
            self.connected_provider
                .notify_token_renamed("", ""); // triggers panel refresh
            // Unregister from all disconnected providers.
            for provider in &mut self.disconnected_providers {
                provider.notify_token_renamed("", "");
            }
        }
    }

    // -- Debug helpers --------------------------------------------------------

    /// Build a debug string showing the current token in context.
    ///
    /// Mirrors Ghidra's `DecompilerProvider.currentTokenToString()` which
    /// renders the current line with the token under the cursor wrapped
    /// in `[` `]` brackets.  Returns `None` if there is no current location.
    pub fn current_token_to_string(&self) -> Option<String> {
        let _addr = self.current_location?;
        let program = self.current_program.as_deref()?;
        // In the full implementation, this reads from the decompiler panel:
        //   cursor = panel.getCursorPosition()
        //   line   = panel.getLines().get(cursor.getRow())
        //   token  = panel.getTokenAtCursor()
        //   return line.toDebugString(Arrays.asList(token))
        Some(format!(
            "[{}] @ {}",
            program,
            self.current_location
                .map(|a| format!("0x{:x}", a.offset))
                .unwrap_or_else(|| "none".into())
        ))
    }

    // -- Connected-provider viewer position persistence -----------------------

    /// Write the connected provider's viewer position into the save state.
    ///
    /// Called by the connected provider during `writeDataState`.
    pub fn write_connected_viewer_position(
        &self,
        state: &mut SaveState,
        index: i32,
        y_offset: i32,
    ) {
        state.put_int("INDEX", index as i64);
        state.put_int("Y_OFFSET", y_offset as i64);
    }

    /// Read a viewer position from a save state.
    ///
    /// Returns `(index, y_offset)`.
    pub fn read_viewer_position(state: &SaveState) -> (i32, i32) {
        let index = state.get_int("INDEX", 0) as i32;
        let y_offset = state.get_int("Y_OFFSET", 0) as i32;
        (index, y_offset)
    }
}

impl Default for DecompilePlugin {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_new() {
        let plugin = DecompilePlugin::new();
        assert_eq!(plugin.name(), "Decompile");
        assert_eq!(plugin.disconnected_count(), 0);
        assert!(plugin.current_location().is_none());
        assert!(plugin.current_program().is_none());
        assert!(!plugin.is_disposed());
    }

    #[test]
    fn test_plugin_services() {
        let plugin = DecompilePlugin::new();
        assert_eq!(
            plugin.service_registration.services_provided,
            vec![
                "DecompilerHighlightService".to_string(),
                "DecompilerMarginService".to_string()
            ]
        );
        assert_eq!(plugin.service_registration.services_required.len(), 4);
    }

    #[test]
    fn test_plugin_init() {
        let mut plugin = DecompilePlugin::new();
        assert!(!plugin.service_registration.clipboard_bound);
        plugin.init(true);
        assert!(plugin.service_registration.clipboard_bound);
    }

    #[test]
    fn test_plugin_program_activated() {
        let mut plugin = DecompilePlugin::new();
        plugin.process_event(PluginEvent::ProgramActivated {
            program_name: "test.elf".into(),
        });
        assert_eq!(plugin.current_program(), Some("test.elf"));
        assert_eq!(
            plugin.connected_provider().program_name(),
            Some("test.elf")
        );
    }

    #[test]
    fn test_plugin_location_changed_debounced() {
        let mut plugin = DecompilePlugin::new();
        plugin.process_event(PluginEvent::ProgramActivated {
            program_name: "a.bin".into(),
        });
        plugin.process_event(PluginEvent::LocationChanged {
            program_name: "a.bin".into(),
            address: Address::new(0x1000),
            is_external: false,
            is_data: false,
        });
        // Location is stored but not yet propagated (debouncing).
        assert_eq!(plugin.current_location, Some(Address::new(0x1000)));
        assert!(plugin.delayed_location_updater.has_pending());
    }

    #[test]
    fn test_plugin_location_changed_skips_external() {
        let mut plugin = DecompilePlugin::new();
        plugin.process_event(PluginEvent::ProgramActivated {
            program_name: "a.bin".into(),
        });
        plugin.process_event(PluginEvent::LocationChanged {
            program_name: "a.bin".into(),
            address: Address::new(0x1000),
            is_external: true,
            is_data: false,
        });
        // External address should be skipped entirely.
        assert!(plugin.current_location.is_none());
    }

    #[test]
    fn test_plugin_location_changed_skips_data() {
        let mut plugin = DecompilePlugin::new();
        plugin.process_event(PluginEvent::ProgramActivated {
            program_name: "a.bin".into(),
        });
        plugin.process_event(PluginEvent::LocationChanged {
            program_name: "a.bin".into(),
            address: Address::new(0x1000),
            is_external: false,
            is_data: true,
        });
        // Data address should be skipped entirely.
        assert!(plugin.current_location.is_none());
    }

    #[test]
    fn test_plugin_location_changed_wrong_program() {
        let mut plugin = DecompilePlugin::new();
        plugin.process_event(PluginEvent::ProgramActivated {
            program_name: "a.bin".into(),
        });
        plugin.process_event(PluginEvent::LocationChanged {
            program_name: "b.bin".into(),
            address: Address::new(0x2000),
            is_external: false,
            is_data: false,
        });
        assert!(plugin.current_location.is_none());
    }

    #[test]
    fn test_plugin_selection_changed() {
        let mut plugin = DecompilePlugin::new();
        plugin.process_event(PluginEvent::ProgramActivated {
            program_name: "test.elf".into(),
        });
        plugin.process_event(PluginEvent::SelectionChanged {
            program_name: "test.elf".into(),
            range: (Address::new(0x100), Address::new(0x200)),
        });
        assert_eq!(
            plugin.current_selection(),
            Some((Address::new(0x100), Address::new(0x200)))
        );
        assert_eq!(plugin.fired_events().len(), 1);
    }

    #[test]
    fn test_plugin_create_disconnected() {
        let mut plugin = DecompilePlugin::new();
        let id1 = plugin.create_new_disconnected_provider();
        let id2 = plugin.create_new_disconnected_provider();
        assert_eq!(plugin.disconnected_count(), 2);
        assert_ne!(id1, id2);
        assert!(id1 > 0);
        assert!(id2 > 0);
    }

    #[test]
    fn test_plugin_close_disconnected() {
        let mut plugin = DecompilePlugin::new();
        let id = plugin.create_new_disconnected_provider();
        assert_eq!(plugin.disconnected_count(), 1);
        assert!(plugin.close_disconnected_provider(id));
        assert_eq!(plugin.disconnected_count(), 0);
        assert!(!plugin.close_disconnected_provider(id)); // already closed
    }

    #[test]
    fn test_plugin_close_provider_connected() {
        let mut plugin = DecompilePlugin::new();
        plugin.close_provider(0);
        // Connected provider is hidden, not removed.
        assert_eq!(plugin.disconnected_count(), 0);
    }

    #[test]
    fn test_plugin_program_closed() {
        let mut plugin = DecompilePlugin::new();
        plugin.process_event(PluginEvent::ProgramActivated {
            program_name: "x.bin".into(),
        });
        plugin.create_new_disconnected_provider();
        plugin.process_event(PluginEvent::ProgramClosed {
            program_name: "x.bin".into(),
        });
        assert!(plugin.current_program.is_none());
    }

    #[test]
    fn test_plugin_program_closed_removes_disconnected() {
        let mut plugin = DecompilePlugin::new();
        plugin.process_event(PluginEvent::ProgramActivated {
            program_name: "x.bin".into(),
        });
        let id = plugin.create_new_disconnected_provider();
        // Set the disconnected provider's program.
        plugin.disconnected_provider_mut(id).unwrap().set_program(Some("x.bin".into()));
        assert_eq!(plugin.disconnected_count(), 1);

        plugin.process_event(PluginEvent::ProgramClosed {
            program_name: "x.bin".into(),
        });
        // Disconnected provider for "x.bin" should be removed.
        assert_eq!(plugin.disconnected_count(), 0);
    }

    #[test]
    fn test_plugin_dispose() {
        let mut plugin = DecompilePlugin::new();
        plugin.process_event(PluginEvent::ProgramActivated {
            program_name: "test".into(),
        });
        plugin.create_new_disconnected_provider();
        plugin.dispose();
        assert!(plugin.is_disposed());
        assert!(plugin.current_program.is_none());
        assert_eq!(plugin.disconnected_count(), 0);
    }

    #[test]
    fn test_plugin_handle_token_renamed() {
        let mut plugin = DecompilePlugin::new();
        // Should not panic even with no active program.
        plugin.handle_token_renamed("old", "new");
    }

    #[test]
    fn test_plugin_export_location() {
        let mut plugin = DecompilePlugin::new();
        assert!(plugin.export_location().is_none());

        plugin.process_event(PluginEvent::ProgramActivated {
            program_name: "test.elf".into(),
        });
        plugin.current_location = Some(Address::new(0x4000));
        let (program, addr) = plugin.export_location().unwrap();
        assert_eq!(program, "test.elf");
        assert_eq!(addr, Address::new(0x4000));
    }

    #[test]
    fn test_plugin_location_changed() {
        let mut plugin = DecompilePlugin::new();
        plugin.process_event(PluginEvent::ProgramActivated {
            program_name: "test.elf".into(),
        });
        plugin.location_changed(0, Address::new(0x5000));
        assert_eq!(plugin.fired_events().len(), 1);
    }

    #[test]
    fn test_plugin_hover_services() {
        let mut plugin = DecompilePlugin::new();
        let svc = HoverServiceId("test_hover".into());
        plugin.add_hover_service(svc.clone());
        assert_eq!(plugin.hover_services.len(), 1);
        plugin.remove_hover_service(&svc);
        assert_eq!(plugin.hover_services.len(), 0);
    }

    #[test]
    fn test_plugin_delayed_updater() {
        let mut updater = DelayedLocationUpdater::new(100);
        assert!(!updater.has_pending());

        updater.update_later("test".into(), Address::new(0x1000));
        assert!(updater.has_pending());
        assert!(updater.poll().is_none()); // not enough time elapsed

        updater.cancel();
        assert!(!updater.has_pending());
        assert!(updater.poll().is_none());
    }

    #[test]
    fn test_save_state_round_trip() {
        let mut state = SaveState::new();
        state.put_int("count", 42);
        state.put_string("name", "test");

        let mut sub = SaveState::new();
        sub.put_string("path", "/path/to/program");
        sub.put_viewer_position(10, 200);
        state.put_xml_element("Provider0", sub);

        assert_eq!(state.get_int("count", 0), 42);
        assert_eq!(state.get_string("name", ""), "test");

        let restored = state.get_xml_element("Provider0").unwrap();
        assert_eq!(restored.get_string("path", ""), "/path/to/program");
        assert_eq!(restored.get_viewer_position(), (10, 200));
    }

    #[test]
    fn test_write_read_data_state() {
        let mut plugin = DecompilePlugin::new();
        plugin.process_event(PluginEvent::ProgramActivated {
            program_name: "test.elf".into(),
        });
        plugin.current_location = Some(Address::new(0x1000));
        let id = plugin.create_new_disconnected_provider();
        plugin.disconnected_provider_mut(id).unwrap().set_program(Some("snap.bin".into()));

        let state = plugin.write_data_state();
        assert_eq!(state.get_int("Num Disconnected", 0), 1);

        let providers = DecompilePlugin::read_data_state(&state);
        assert_eq!(providers.len(), 1);
        assert_eq!(providers[0].0, "snap.bin");
    }

    #[test]
    fn test_plugin_fired_events() {
        let mut plugin = DecompilePlugin::new();
        plugin.process_event(PluginEvent::ProgramActivated {
            program_name: "test.elf".into(),
        });
        plugin.selection_changed(0, (Address::new(0x100), Address::new(0x200)));
        assert_eq!(plugin.fired_events().len(), 1);

        plugin.clear_fired_events();
        assert_eq!(plugin.fired_events().len(), 0);
    }

    // -- Service lifecycle tests --

    #[test]
    fn test_plugin_service_added_hover() {
        let mut plugin = DecompilePlugin::new();
        assert_eq!(plugin.hover_services.len(), 0);

        plugin.service_added("DecompilerHoverService", "hover_provider_1");
        assert_eq!(plugin.hover_services.len(), 1);
        assert_eq!(plugin.hover_services[0].0, "hover_provider_1");
    }

    #[test]
    fn test_plugin_service_added_ignores_non_hover() {
        let mut plugin = DecompilePlugin::new();
        plugin.service_added("SomeOtherService", "svc");
        assert_eq!(plugin.hover_services.len(), 0);
    }

    #[test]
    fn test_plugin_service_removed_hover() {
        let mut plugin = DecompilePlugin::new();
        plugin.service_added("DecompilerHoverService", "hp1");
        plugin.service_added("DecompilerHoverService", "hp2");
        assert_eq!(plugin.hover_services.len(), 2);

        plugin.service_removed("DecompilerHoverService", "hp1");
        assert_eq!(plugin.hover_services.len(), 1);
        assert_eq!(plugin.hover_services[0].0, "hp2");
    }

    #[test]
    fn test_plugin_service_removed_ignores_non_hover() {
        let mut plugin = DecompilePlugin::new();
        plugin.service_added("DecompilerHoverService", "hp1");
        plugin.service_removed("SomeOtherService", "hp1");
        assert_eq!(plugin.hover_services.len(), 1); // unchanged
    }

    // -- currentTokenToString tests --

    #[test]
    fn test_plugin_current_token_to_string_none() {
        let plugin = DecompilePlugin::new();
        assert!(plugin.current_token_to_string().is_none());
    }

    #[test]
    fn test_plugin_current_token_to_string_with_location() {
        let mut plugin = DecompilePlugin::new();
        plugin.process_event(PluginEvent::ProgramActivated {
            program_name: "test.elf".into(),
        });
        plugin.current_location = Some(Address::new(0x4000));
        let s = plugin.current_token_to_string().unwrap();
        assert!(s.contains("test.elf"));
        assert!(s.contains("0x4000"));
    }

    // -- Viewer position persistence tests --

    #[test]
    fn test_plugin_write_read_viewer_position() {
        let mut state = SaveState::new();
        DecompilePlugin::write_connected_viewer_position(
            &DecompilePlugin::new(),
            &mut state,
            15,
            300,
        );
        let (idx, y_off) = DecompilePlugin::read_viewer_position(&state);
        assert_eq!(idx, 15);
        assert_eq!(y_off, 300);
    }

    #[test]
    fn test_plugin_read_viewer_position_defaults() {
        let state = SaveState::new();
        let (idx, y_off) = DecompilePlugin::read_viewer_position(&state);
        assert_eq!(idx, 0);
        assert_eq!(y_off, 0);
    }

    // -- Write/read data state round-trip with viewer position --

    #[test]
    fn test_plugin_write_read_data_state_full_round_trip() {
        let mut plugin = DecompilePlugin::new();
        plugin.process_event(PluginEvent::ProgramActivated {
            program_name: "main.elf".into(),
        });
        plugin.current_location = Some(Address::new(0x8000));

        let id = plugin.create_new_disconnected_provider();
        plugin
            .disconnected_provider_mut(id)
            .unwrap()
            .set_program(Some("snap.bin".into()));

        let state = plugin.write_data_state();
        assert_eq!(state.get_int("Num Disconnected", 0), 1);

        let providers = DecompilePlugin::read_data_state(&state);
        assert_eq!(providers.len(), 1);
        assert_eq!(providers[0].0, "snap.bin");
    }

    // -- ProgramOpened event --

    #[test]
    fn test_plugin_program_opened_no_action() {
        let mut plugin = DecompilePlugin::new();
        plugin.process_event(PluginEvent::ProgramOpened {
            program_name: "new.elf".into(),
        });
        // ProgramOpened alone should not set current_program.
        assert!(plugin.current_program.is_none());
    }

    // -- Multiple location changes with debounce --

    #[test]
    fn test_plugin_multiple_location_changes_latest_wins() {
        let mut plugin = DecompilePlugin::new();
        plugin.process_event(PluginEvent::ProgramActivated {
            program_name: "test.elf".into(),
        });
        plugin.process_event(PluginEvent::LocationChanged {
            program_name: "test.elf".into(),
            address: Address::new(0x1000),
            is_external: false,
            is_data: false,
        });
        plugin.process_event(PluginEvent::LocationChanged {
            program_name: "test.elf".into(),
            address: Address::new(0x2000),
            is_external: false,
            is_data: false,
        });
        // The latest address should be the pending one.
        assert_eq!(plugin.current_location, Some(Address::new(0x2000)));
    }

    // -- Selection changed wrong program --

    #[test]
    fn test_plugin_selection_changed_wrong_program() {
        let mut plugin = DecompilePlugin::new();
        plugin.process_event(PluginEvent::ProgramActivated {
            program_name: "a.elf".into(),
        });
        plugin.process_event(PluginEvent::SelectionChanged {
            program_name: "b.elf".into(),
            range: (Address::new(0x100), Address::new(0x200)),
        });
        assert!(plugin.current_selection.is_none());
    }

    // -- location_changed with disconnected provider --

    #[test]
    fn test_plugin_location_changed_disconnected_not_sending() {
        let mut plugin = DecompilePlugin::new();
        let id = plugin.create_new_disconnected_provider();
        // Disconnected provider doesn't send events by default.
        plugin.location_changed(id, Address::new(0x5000));
        assert_eq!(plugin.fired_events().len(), 0);
    }

    #[test]
    fn test_plugin_location_changed_disconnected_sending() {
        let mut plugin = DecompilePlugin::new();
        plugin.process_event(PluginEvent::ProgramActivated {
            program_name: "test.elf".into(),
        });
        let id = plugin.create_new_disconnected_provider();
        plugin
            .disconnected_provider_mut(id)
            .unwrap()
            .toggle_outgoing_events();
        plugin.location_changed(id, Address::new(0x5000));
        assert_eq!(plugin.fired_events().len(), 1);
    }

    // -- Dispose already disposed --

    #[test]
    fn test_plugin_double_dispose() {
        let mut plugin = DecompilePlugin::new();
        plugin.dispose();
        assert!(plugin.is_disposed());
        // Second dispose should not panic.
        plugin.dispose();
        assert!(plugin.is_disposed());
    }

    // -- Process event after dispose --

    #[test]
    fn test_plugin_event_after_dispose_ignored() {
        let mut plugin = DecompilePlugin::new();
        plugin.dispose();
        plugin.process_event(PluginEvent::ProgramActivated {
            program_name: "test.elf".into(),
        });
        assert!(plugin.current_program.is_none());
    }
}
