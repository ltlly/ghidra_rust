//! Decompiler provider infrastructure -- Rust port of
//! `ghidra.app.plugin.core.decompile.DecompilerProvider` (extended).
//!
//! This module models the provider-level infrastructure that the base
//! [`super::provider::DecompilerProvider`] does not cover:
//!
//! * **OptionsChangeListener** -- reacting to tool option changes and
//!   triggering display refresh.
//! * **DecompilerCallbackHandler** -- the callback interface from the
//!   decompiler panel/controller back into the provider.
//! * **DecompilerHighlightService** -- creating and managing
//!   function-scoped token highlighters.
//! * **DecompilerMarginService** -- adding/removing margin providers
//!   that paint alongside the decompiler panel.
//! * **ServiceListener** -- reacting to `GraphDisplayBroker` service
//!   availability changes.
//! * **ComponentProviderAdapter** -- the `NavigatableComponentProvider`
//!   base-class methods (snapshot, close, window group, memento).
//!
//! # Architecture
//!
//! ```text
//! OptionsChangeListenerImpl
//!   └── optionsChanged()
//!       ├── decompilerOptions.grabFromToolAndProgram()
//!       └── doRefresh(optionsChanged=true)
//!
//! DecompilerCallbackHandlerImpl
//!   ├── setStatusMessage()
//!   ├── decompileDataChanged()
//!   ├── locationChanged()
//!   ├── selectionChanged()
//!   ├── annotationClicked()
//!   ├── goTo{Label,Scalar,Address,Function}()
//!   └── doWhenNotBusy()
//!
//! DecompilerHighlightServiceImpl
//!   └── createHighlighter()
//!
//! DecompilerMarginServiceImpl
//!   ├── addMarginProvider()
//!   └── removeMarginProvider()
//!
//! ServiceListenerImpl
//!   ├── serviceAdded(GraphDisplayBroker)
//!   └── serviceRemoved(GraphDisplayBroker)
//!
//! ComponentProviderAdapterImpl
//!   ├── isSnapshot()
//!   ├── closeComponent()
//!   ├── getWindowGroup()
//!   ├── writeDataState()
//!   └── readDataState()
//! ```

use std::collections::VecDeque;

use ghidra_core::addr::Address;

use super::provider::{DecompilerProvider, ProviderState, ViewerPosition};

// ---------------------------------------------------------------------------
// OptionCategory -- which set of options changed
// ---------------------------------------------------------------------------

/// Identifies the category of tool options that changed.
///
/// In Ghidra, `DecompilerProvider` listens to two `ToolOptions` objects:
/// the "Decompiler" options and the "Browser Fields" options.  This enum
/// distinguishes which one fired the change event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OptionCategory {
    /// The "Decompiler" options category.
    Decompiler,
    /// The "Browser Fields" options category.
    BrowserFields,
}

// ---------------------------------------------------------------------------
// OptionsChangeListener -- trait for option-change callbacks
// ---------------------------------------------------------------------------

/// Trait modelling Ghidra's `OptionsChangeListener`.
///
/// The decompiler provider implements this interface to react when
/// the user changes tool options in the "Decompiler" or "Browser
/// Fields" option panels.
pub trait OptionsChangeListener {
    /// Called when an option value changes.
    ///
    /// * `category` -- which options panel changed.
    /// * `option_name` -- the specific option that changed.
    fn options_changed(&mut self, category: OptionCategory, option_name: &str);
}

// ---------------------------------------------------------------------------
// DecompilerCallbackHandler -- trait for panel-to-provider callbacks
// ---------------------------------------------------------------------------

/// Trait modelling Ghidra's `DecompilerCallbackHandler`.
///
/// The decompiler panel and controller call back into the provider
/// through this interface.  This decouples the rendering layer from
/// the plugin infrastructure.
pub trait DecompilerCallbackHandler {
    /// Set a status message in the tool's status bar.
    fn set_status_message(&mut self, message: &str);

    /// Called when the decompile data (function/results) changed.
    ///
    /// The provider should update its title and notify the tool that
    /// the action context has changed.
    fn decompile_data_changed(&mut self);

    /// Called when the decompiler panel's location changed.
    ///
    /// The provider should update its state and fire a location event
    /// to the plugin.
    fn location_changed(&mut self, address: Address);

    /// Called when the decompiler panel's selection changed.
    ///
    /// The provider should update its state and fire a selection event
    /// to the plugin.
    fn selection_changed(&mut self, start: Address, end: Address);

    /// Called when an annotation (e.g., a type or variable reference)
    /// is clicked in the decompiler panel.
    ///
    /// If `new_window` is true, the navigation should happen in a new
    /// disconnected provider.
    fn annotation_clicked(&mut self, annotation_text: &str, new_window: bool);

    /// Navigate to a label by symbol name.
    fn go_to_label(&mut self, symbol_name: &str, new_window: bool);

    /// Navigate to a scalar value.
    fn go_to_scalar(&mut self, value: i64, new_window: bool);

    /// Navigate to an address.
    fn go_to_address(&mut self, address: Address, new_window: bool);

    /// Navigate to a function.
    fn go_to_function(&mut self, entry: Address, is_external: bool, new_window: bool);

    /// Schedule work to be done when the provider is not busy.
    fn do_when_not_busy(&mut self, work: Box<dyn FnOnce() + Send>);

    /// Export the current location to the GoToService.
    fn export_location(&self);
}

// ---------------------------------------------------------------------------
// HighlightMatcher / DecompilerHighlighter -- highlight service types
// ---------------------------------------------------------------------------

/// A matcher that determines which C tokens should be highlighted.
///
/// In Ghidra this is `CTokenHighlightMatcher`, an interface that
/// compares tokens and determines if they match a highlight criterion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HighlightMatcher {
    /// Match tokens by exact text.
    ExactText(String),
    /// Match tokens by address.
    Address(Address),
    /// Match tokens by variable name.
    VariableName(String),
    /// Match tokens by function entry.
    FunctionEntry(Address),
}

/// A handle to a decompiler highlighter.
///
/// In Ghidra, `DecompilerHighlighter` is returned by
/// `DecompilerHighlightService.createHighlighter()`.  The caller uses
/// this handle to add/remove highlights.
#[derive(Debug, Clone)]
pub struct DecompilerHighlighterHandle {
    /// Unique id for this highlighter.
    pub id: String,
    /// The function this highlighter is scoped to.
    pub function_entry: Address,
    /// The matcher used to select tokens.
    pub matcher: HighlightMatcher,
    /// Whether this highlighter is currently active.
    pub active: bool,
}

impl DecompilerHighlighterHandle {
    /// Create a new highlighter handle.
    pub fn new(id: impl Into<String>, function_entry: Address, matcher: HighlightMatcher) -> Self {
        Self {
            id: id.into(),
            function_entry,
            matcher,
            active: true,
        }
    }

    /// Deactivate this highlighter.
    pub fn deactivate(&mut self) {
        self.active = false;
    }

    /// Whether this highlighter is active.
    pub fn is_active(&self) -> bool {
        self.active
    }
}

// ---------------------------------------------------------------------------
// DecompilerHighlightService -- trait for highlight management
// ---------------------------------------------------------------------------

/// Trait modelling Ghidra's `DecompilerHighlightService`.
///
/// The plugin provides this service to other plugins.  It allows
/// external code to create highlighters that mark tokens in the
/// decompiler panel.
pub trait DecompilerHighlightService {
    /// Create a highlighter for the given function with the given
    /// matcher.
    ///
    /// Returns a handle that can be used to deactivate the highlighter.
    fn create_highlighter(
        &mut self,
        id: &str,
        function_entry: Address,
        matcher: HighlightMatcher,
    ) -> DecompilerHighlighterHandle;

    /// Remove a highlighter by its handle id.
    fn remove_highlighter(&mut self, id: &str);

    /// Get all active highlighter handles.
    fn active_highlighters(&self) -> Vec<&DecompilerHighlighterHandle>;
}

// ---------------------------------------------------------------------------
// DecompilerMarginProvider -- trait for margin painting
// ---------------------------------------------------------------------------

/// Trait modelling Ghidra's `DecompilerMarginProvider`.
///
/// A margin provider paints a vertical strip alongside the decompiler
/// panel (e.g., line numbers, markers, breakpoint indicators).
pub trait DecompilerMarginProvider: std::fmt::Debug {
    /// The name of this margin provider (for debugging).
    fn name(&self) -> &str;

    /// The width of this margin in pixels.
    fn width(&self) -> i32;

    /// Whether this margin provider is currently active.
    fn is_active(&self) -> bool;

    /// Activate or deactivate this margin provider.
    fn set_active(&mut self, active: bool);
}

// ---------------------------------------------------------------------------
// DecompilerMarginService -- trait for margin management
// ---------------------------------------------------------------------------

/// Trait modelling Ghidra's `DecompilerMarginService`.
///
/// The plugin provides this service to other plugins.  It allows
/// external code to add margin providers to the decompiler panel.
pub trait DecompilerMarginService {
    /// Add a margin provider.
    fn add_margin_provider(&mut self, provider: Box<dyn DecompilerMarginProvider>);

    /// Remove a margin provider by name.
    fn remove_margin_provider(&mut self, name: &str);

    /// Get the names of all registered margin providers.
    fn margin_provider_names(&self) -> Vec<String>;
}

// ---------------------------------------------------------------------------
// ServiceListener -- trait for tool service events
// ---------------------------------------------------------------------------

/// Trait modelling Ghidra's `ServiceListener`.
///
/// The provider uses this to react when tool services (like
/// `GraphDisplayBroker`) are added or removed.
pub trait ServiceListener {
    /// Called when a service is added to the tool.
    fn service_added(&mut self, interface_class: &str);

    /// Called when a service is removed from the tool.
    fn service_removed(&mut self, interface_class: &str);
}

// ---------------------------------------------------------------------------
// LocationMemento / DecompilerLocationMemento -- cursor state persistence
// ---------------------------------------------------------------------------

/// Trait modelling Ghidra's `LocationMemento`.
///
/// A memento captures the complete navigational state (program,
/// location, viewer position) so it can be saved and restored.
pub trait LocationMemento: std::fmt::Debug {
    /// The program name associated with this memento.
    fn program_name(&self) -> Option<&str>;

    /// The address associated with this memento.
    fn address(&self) -> Option<Address>;

    /// Restore this memento into the given provider.
    fn restore_to(&self, provider: &mut DecompilerProvider);
}

/// A concrete `LocationMemento` for the decompiler.
#[derive(Debug, Clone)]
pub struct DecompilerLocationMemento {
    /// The program name.
    pub program_name: Option<String>,
    /// The location address.
    pub address: Option<Address>,
    /// The viewer position.
    pub viewer_position: ViewerPosition,
}

impl DecompilerLocationMemento {
    /// Create a new memento.
    pub fn new(
        program_name: Option<String>,
        address: Option<Address>,
        viewer_position: ViewerPosition,
    ) -> Self {
        Self {
            program_name,
            address,
            viewer_position,
        }
    }
}

impl LocationMemento for DecompilerLocationMemento {
    fn program_name(&self) -> Option<&str> {
        self.program_name.as_deref()
    }

    fn address(&self) -> Option<Address> {
        self.address
    }

    fn restore_to(&self, provider: &mut DecompilerProvider) {
        if let Some(addr) = self.address {
            provider.set_location(Some(addr));
        }
        provider.set_viewer_position(self.viewer_position);
    }
}

// ---------------------------------------------------------------------------
// ComponentProviderAdapter -- base-class methods
// ---------------------------------------------------------------------------

/// Trait modelling Ghidra's `NavigatableComponentProviderAdapter`.
///
/// This captures the component provider base-class behaviour that
/// `DecompilerProvider` inherits.
pub trait ComponentProviderAdapter {
    /// Whether this provider is a snapshot (disconnected).
    fn is_snapshot(&self) -> bool;

    /// Called when the component is being closed.
    fn close_component(&mut self);

    /// The window group for this provider.
    fn window_group(&self) -> &str;

    /// Called when the component becomes visible.
    fn component_shown(&mut self);

    /// Write provider state for persistence.
    fn write_data_state(&self) -> ProviderSaveState;

    /// Read provider state from persistence.
    fn read_data_state(&mut self, state: &ProviderSaveState);
}

/// A serialisable save state for provider persistence.
///
/// This is a simplified version of Ghidra's `SaveState` used by
/// `ComponentProviderAdapter`.
#[derive(Debug, Clone, Default)]
pub struct ProviderSaveState {
    /// Integer values.
    pub ints: Vec<(String, i64)>,
    /// String values.
    pub strings: Vec<(String, String)>,
}

impl ProviderSaveState {
    /// Create an empty save state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Put an integer value.
    pub fn put_int(&mut self, key: impl Into<String>, value: i64) {
        self.ints.push((key.into(), value));
    }

    /// Get an integer value.
    pub fn get_int(&self, key: &str, default: i64) -> i64 {
        self.ints
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| *v)
            .unwrap_or(default)
    }

    /// Put a string value.
    pub fn put_string(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.strings.push((key.into(), value.into()));
    }

    /// Get a string value.
    pub fn get_string(&self, key: &str, default: &str) -> String {
        self.strings
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.clone())
            .unwrap_or_else(|| default.to_string())
    }
}

// ---------------------------------------------------------------------------
// FollowUpWorkQueue -- deferred work when provider is busy
// ---------------------------------------------------------------------------

/// A queue of callbacks to execute when the provider becomes idle.
///
/// In Ghidra, `SwingUpdateManager` coalesces and defers work.  Here we
/// model the queue explicitly.
pub struct FollowUpWorkQueue {
    queue: VecDeque<Box<dyn FnOnce() + Send>>,
    is_busy: bool,
}

impl std::fmt::Debug for FollowUpWorkQueue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FollowUpWorkQueue")
            .field("pending", &self.queue.len())
            .field("is_busy", &self.is_busy)
            .finish()
    }
}

impl FollowUpWorkQueue {
    /// Create an empty queue.
    pub fn new() -> Self {
        Self {
            queue: VecDeque::new(),
            is_busy: false,
        }
    }

    /// Set the busy state.
    pub fn set_busy(&mut self, busy: bool) {
        self.is_busy = busy;
    }

    /// Whether the queue is currently busy.
    pub fn is_busy(&self) -> bool {
        self.is_busy
    }

    /// Enqueue work.  If not busy, executes immediately.
    pub fn enqueue<F: FnOnce() + Send + 'static>(&mut self, work: F) {
        if !self.is_busy {
            work();
        } else {
            self.queue.push_back(Box::new(work));
        }
    }

    /// Drain and execute all pending work if not busy.
    ///
    /// Returns the number of items executed.
    pub fn drain(&mut self) -> usize {
        if self.is_busy {
            return 0;
        }
        let mut count = 0;
        while let Some(work) = self.queue.pop_front() {
            work();
            count += 1;
        }
        count
    }

    /// The number of pending work items.
    pub fn pending_count(&self) -> usize {
        self.queue.len()
    }

    /// Clear all pending work.
    pub fn clear(&mut self) {
        self.queue.clear();
    }
}

impl Default for FollowUpWorkQueue {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// ActionContextBuilder -- builds action contexts for the tool
// ---------------------------------------------------------------------------

/// Information needed to construct a `DecompilerActionContext`.
///
/// In Ghidra, `getActionContext()` builds a context object from the
/// current decompiler state.  This struct captures the input data.
#[derive(Debug, Clone)]
pub struct ActionContextRequest {
    /// The function entry point (if a function is being displayed).
    pub function_entry: Option<Address>,
    /// Whether a decompile is currently in progress.
    pub is_decompiling: bool,
    /// The line number under the mouse (0 if no event).
    pub line_number: usize,
    /// Whether the program is available.
    pub program_available: bool,
}

impl ActionContextRequest {
    /// Whether a valid action context can be built from this request.
    ///
    /// In Ghidra, `getActionContext()` returns `null` if there is no
    /// program, no function, or no decompile results.
    pub fn is_valid(&self) -> bool {
        self.program_available && self.function_entry.is_some() && !self.is_decompiling
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- OptionCategory tests --

    #[test]
    fn test_option_category_variants() {
        assert_ne!(OptionCategory::Decompiler, OptionCategory::BrowserFields);
    }

    // -- HighlightMatcher tests --

    #[test]
    fn test_highlight_matcher_exact_text() {
        let m = HighlightMatcher::ExactText("main".into());
        match &m {
            HighlightMatcher::ExactText(t) => assert_eq!(t, "main"),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_highlight_matcher_address() {
        let m = HighlightMatcher::Address(Address::new(0x1000));
        match &m {
            HighlightMatcher::Address(a) => assert_eq!(*a, Address::new(0x1000)),
            _ => panic!("wrong variant"),
        }
    }

    // -- DecompilerHighlighterHandle tests --

    #[test]
    fn test_highlighter_handle_new() {
        let h = DecompilerHighlighterHandle::new(
            "test_hl",
            Address::new(0x1000),
            HighlightMatcher::VariableName("x".into()),
        );
        assert_eq!(h.id, "test_hl");
        assert!(h.is_active());
    }

    #[test]
    fn test_highlighter_handle_deactivate() {
        let mut h = DecompilerHighlighterHandle::new(
            "test_hl",
            Address::new(0x1000),
            HighlightMatcher::VariableName("x".into()),
        );
        h.deactivate();
        assert!(!h.is_active());
    }

    // -- DecompilerLocationMemento tests --

    #[test]
    fn test_location_memento_new() {
        let m = DecompilerLocationMemento::new(
            Some("test.elf".into()),
            Some(Address::new(0x4000)),
            ViewerPosition::new(10, 0, 200),
        );
        assert_eq!(m.program_name(), Some("test.elf"));
        assert_eq!(m.address(), Some(Address::new(0x4000)));
    }

    #[test]
    fn test_location_memento_restore() {
        let m = DecompilerLocationMemento::new(
            Some("test.elf".into()),
            Some(Address::new(0x4000)),
            ViewerPosition::new(10, 0, 200),
        );

        let mut provider = DecompilerProvider::new_connected(0);
        m.restore_to(&mut provider);

        assert_eq!(provider.current_location(), Some(Address::new(0x4000)));
        assert_eq!(provider.viewer_position().index, 10);
        assert_eq!(provider.viewer_position().y_offset, 200);
    }

    #[test]
    fn test_location_memento_restore_no_address() {
        let m = DecompilerLocationMemento::new(
            Some("test.elf".into()),
            None,
            ViewerPosition::new(5, 0, 100),
        );

        let mut provider = DecompilerProvider::new_connected(0);
        m.restore_to(&mut provider);

        assert!(provider.current_location().is_none());
        assert_eq!(provider.viewer_position().index, 5);
    }

    // -- ProviderSaveState tests --

    #[test]
    fn test_provider_save_state_int() {
        let mut state = ProviderSaveState::new();
        state.put_int("count", 42);
        assert_eq!(state.get_int("count", 0), 42);
        assert_eq!(state.get_int("missing", 99), 99);
    }

    #[test]
    fn test_provider_save_state_string() {
        let mut state = ProviderSaveState::new();
        state.put_string("name", "test");
        assert_eq!(state.get_string("name", ""), "test");
        assert_eq!(state.get_string("missing", "default"), "default");
    }

    #[test]
    fn test_provider_save_state_round_trip() {
        let mut state = ProviderSaveState::new();
        state.put_int("INDEX", 10);
        state.put_int("Y_OFFSET", 200);
        state.put_string("Program Path", "/path/to/prog.elf");

        assert_eq!(state.get_int("INDEX", 0), 10);
        assert_eq!(state.get_int("Y_OFFSET", 0), 200);
        assert_eq!(state.get_string("Program Path", ""), "/path/to/prog.elf");
    }

    // -- FollowUpWorkQueue tests --

    #[test]
    fn test_follow_up_queue_immediate_execution() {
        let mut queue = FollowUpWorkQueue::new();
        let executed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let exec_clone = executed.clone();

        queue.enqueue(move || {
            exec_clone.store(true, std::sync::atomic::Ordering::SeqCst);
        });

        assert!(executed.load(std::sync::atomic::Ordering::SeqCst));
        assert_eq!(queue.pending_count(), 0);
    }

    #[test]
    fn test_follow_up_queue_deferred_execution() {
        let mut queue = FollowUpWorkQueue::new();
        queue.set_busy(true);

        let executed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let exec_clone = executed.clone();

        queue.enqueue(move || {
            exec_clone.store(true, std::sync::atomic::Ordering::SeqCst);
        });

        // Should not have executed yet.
        assert!(!executed.load(std::sync::atomic::Ordering::SeqCst));
        assert_eq!(queue.pending_count(), 1);

        // Now drain.
        queue.set_busy(false);
        let count = queue.drain();
        assert_eq!(count, 1);
        assert!(executed.load(std::sync::atomic::Ordering::SeqCst));
        assert_eq!(queue.pending_count(), 0);
    }

    #[test]
    fn test_follow_up_queue_drain_stays_queued_when_busy() {
        let mut queue = FollowUpWorkQueue::new();
        queue.set_busy(true);
        queue.enqueue(|| {});
        assert_eq!(queue.pending_count(), 1);

        let count = queue.drain();
        assert_eq!(count, 0);
        assert_eq!(queue.pending_count(), 1);
    }

    #[test]
    fn test_follow_up_queue_multiple_items() {
        let mut queue = FollowUpWorkQueue::new();
        queue.set_busy(true);

        let count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        for _ in 0..5 {
            let c = count.clone();
            queue.enqueue(move || {
                c.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            });
        }

        assert_eq!(queue.pending_count(), 5);

        queue.set_busy(false);
        let executed = queue.drain();
        assert_eq!(executed, 5);
        assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 5);
    }

    #[test]
    fn test_follow_up_queue_clear() {
        let mut queue = FollowUpWorkQueue::new();
        queue.set_busy(true);
        queue.enqueue(|| {});
        queue.enqueue(|| {});
        assert_eq!(queue.pending_count(), 2);

        queue.clear();
        assert_eq!(queue.pending_count(), 0);
    }

    // -- ActionContextRequest tests --

    #[test]
    fn test_action_context_request_valid() {
        let req = ActionContextRequest {
            function_entry: Some(Address::new(0x1000)),
            is_decompiling: false,
            line_number: 5,
            program_available: true,
        };
        assert!(req.is_valid());
    }

    #[test]
    fn test_action_context_request_no_function() {
        let req = ActionContextRequest {
            function_entry: None,
            is_decompiling: false,
            line_number: 0,
            program_available: true,
        };
        assert!(!req.is_valid());
    }

    #[test]
    fn test_action_context_request_decompiling() {
        let req = ActionContextRequest {
            function_entry: Some(Address::new(0x1000)),
            is_decompiling: true,
            line_number: 5,
            program_available: true,
        };
        assert!(!req.is_valid());
    }

    #[test]
    fn test_action_context_request_no_program() {
        let req = ActionContextRequest {
            function_entry: Some(Address::new(0x1000)),
            is_decompiling: false,
            line_number: 5,
            program_available: false,
        };
        assert!(!req.is_valid());
    }
}
