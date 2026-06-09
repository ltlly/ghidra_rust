//! ProgramPlugin -- base class for plugins that track program state.
//!
//! Ported from `ghidra.app.plugin.ProgramPlugin` (Features/Base).
//!
//! Provides a common base for plugins that need to respond to program
//! lifecycle events: open, close, activate, deactivate, location change,
//! selection change, and highlight change.
//!
//! Subclasses override the `on_*` callback methods to react to these events.
//! The struct tracks `current_program`, `current_location`, `current_selection`,
//! and `current_highlight` automatically.
//!
//! # Architecture
//!
//! ```text
//! ProgramPlugin
//!   ├── current_program:     Option<ProgramHandle>
//!   ├── current_location:    Option<ProgramLocation>
//!   ├── current_selection:   Option<ProgramSelection>
//!   └── current_highlight:   Option<ProgramSelection>
//! ```
//!
//! # Example
//!
//! ```
//! use ghidra_features::base::program::program_plugin::{ProgramPlugin, ProgramPluginEvent, ProgramHandle};
//!
//! let mut plugin = ProgramPlugin::new("MyPlugin");
//! plugin.init();
//!
//! // Simulate program activation
//! plugin.process_event(ProgramPluginEvent::Activated(ProgramHandle {
//!     name: "test.exe".into(),
//! }));
//!
//! assert_eq!(plugin.current_program_name(), Some("test.exe"));
//! ```

use std::fmt;

// ---------------------------------------------------------------------------
// Core types
// ---------------------------------------------------------------------------

/// Handle identifying a program.  A lightweight identifier; the real
/// `Program` object lives in `ghidra-core`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProgramHandle {
    /// The program name (typically the binary file name).
    pub name: String,
}

impl ProgramHandle {
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }
}

impl fmt::Display for ProgramHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name)
    }
}

/// A program address (placeholder; real definition in ghidra-core).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Address(pub u64);

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:x}", self.0)
    }
}

/// A program location -- an address within a program with context.
#[derive(Debug, Clone)]
pub struct ProgramLocation {
    pub address: Address,
}

impl ProgramLocation {
    pub fn new(address: Address) -> Self {
        Self { address }
    }
}

/// A program selection -- a set of address ranges.
#[derive(Debug, Clone, Default)]
pub struct ProgramSelection {
    pub ranges: Vec<(Address, Address)>,
}

impl ProgramSelection {
    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Plugin events consumed by ProgramPlugin
// ---------------------------------------------------------------------------

/// Events that `ProgramPlugin` knows how to process.
#[derive(Debug, Clone)]
pub enum ProgramPluginEvent {
    /// A new program was opened in the tool.
    Opened(ProgramHandle),
    /// A program was closed.
    Closed(ProgramHandle),
    /// The active program changed.
    Activated(ProgramHandle),
    /// The previous active program was deactivated.
    Deactivated(ProgramHandle),
    /// Post-activation notification (all plugins have seen the activation).
    PostActivated(ProgramHandle),
    /// The user's location within the active program changed.
    LocationChanged(Option<ProgramLocation>),
    /// The user's selection within the active program changed.
    SelectionChanged(Option<ProgramSelection>),
    /// The user's highlight within the active program changed.
    HighlightChanged(Option<ProgramSelection>),
}

// ---------------------------------------------------------------------------
// ProgramPlugin
// ---------------------------------------------------------------------------

/// Base plugin that tracks program state and dispatches lifecycle callbacks.
///
/// Ported from `ghidra.app.plugin.ProgramPlugin`.  Subclasses override the
/// `on_*` methods to handle events.  The struct automatically maintains
/// `current_program`, `current_location`, `current_selection`, and
/// `current_highlight`.
#[derive(Debug)]
pub struct ProgramPlugin {
    /// Plugin name.
    name: String,
    /// Whether the plugin has been initialized.
    initialized: bool,

    // -- Tracked state -------------------------------------------------------
    /// The currently active program.
    current_program: Option<ProgramHandle>,
    /// The current location within the active program.
    current_location: Option<ProgramLocation>,
    /// The current selection within the active program.
    current_selection: Option<ProgramSelection>,
    /// The current highlight within the active program.
    current_highlight: Option<ProgramSelection>,
}

impl ProgramPlugin {
    /// Create a new ProgramPlugin.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            initialized: false,
            current_program: None,
            current_location: None,
            current_selection: None,
            current_highlight: None,
        }
    }

    /// Initialize the plugin.
    pub fn init(&mut self) {
        self.initialized = true;
    }

    /// Dispose of the plugin, clearing all tracked state.
    pub fn dispose(&mut self) {
        self.current_program = None;
        self.current_location = None;
        self.current_selection = None;
        self.current_highlight = None;
        self.initialized = false;
    }

    /// Returns the plugin name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Whether the plugin has been initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    // -- State accessors -----------------------------------------------------

    /// Returns the currently active program handle.
    pub fn current_program(&self) -> Option<&ProgramHandle> {
        self.current_program.as_ref()
    }

    /// Returns the name of the current program, if any.
    pub fn current_program_name(&self) -> Option<&str> {
        self.current_program.as_ref().map(|p| p.name.as_str())
    }

    /// Returns the current program location.
    pub fn current_location(&self) -> Option<&ProgramLocation> {
        self.current_location.as_ref()
    }

    /// Returns the current program selection.
    pub fn current_selection(&self) -> Option<&ProgramSelection> {
        self.current_selection.as_ref()
    }

    /// Returns the current highlight selection.
    pub fn current_highlight(&self) -> Option<&ProgramSelection> {
        self.current_highlight.as_ref()
    }

    // -- Event processing ----------------------------------------------------

    /// Process a plugin event and dispatch to the appropriate callback.
    ///
    /// This is the main entry point for event handling.  It updates the
    /// tracked state fields and calls the corresponding `on_*` method.
    pub fn process_event(&mut self, event: ProgramPluginEvent) {
        match event {
            ProgramPluginEvent::Opened(program) => {
                self.on_program_opened(&program);
            }
            ProgramPluginEvent::Closed(program) => {
                self.on_program_closed(&program);
            }
            ProgramPluginEvent::Activated(program) => {
                let old_program = self.current_program.replace(program.clone());
                if let Some(old) = old_program {
                    self.on_program_deactivated(&old);
                    self.current_location = None;
                    self.current_selection = None;
                    self.current_highlight = None;
                    self.on_location_changed(None);
                    self.on_selection_changed(None);
                    self.on_highlight_changed(None);
                }
                if self.current_program.is_some() {
                    self.on_program_activated(&program);
                }
            }
            ProgramPluginEvent::Deactivated(program) => {
                self.on_program_deactivated(&program);
            }
            ProgramPluginEvent::PostActivated(program) => {
                self.on_post_program_activated(&program);
            }
            ProgramPluginEvent::LocationChanged(loc) => {
                if self.current_program.is_none() {
                    return;
                }
                self.current_location = loc.clone();
                self.on_location_changed(loc.as_ref());
            }
            ProgramPluginEvent::SelectionChanged(sel) => {
                let empty = sel.as_ref().map_or(true, |s| s.is_empty());
                self.current_selection = if empty { None } else { sel };
                let current = self.current_selection.clone();
                self.on_selection_changed(current.as_ref());
            }
            ProgramPluginEvent::HighlightChanged(hl) => {
                let empty = hl.as_ref().map_or(true, |s| s.is_empty());
                self.current_highlight = if empty { None } else { hl };
                let current = self.current_highlight.clone();
                self.on_highlight_changed(current.as_ref());
            }
        }
    }

    // -- Callbacks for subclasses to override --------------------------------
    // The default implementations are no-ops.

    /// Called when a program is opened.
    fn on_program_opened(&mut self, _program: &ProgramHandle) {}

    /// Called when a program is closed.
    fn on_program_closed(&mut self, _program: &ProgramHandle) {}

    /// Called when a program becomes the active program.
    fn on_program_activated(&mut self, _program: &ProgramHandle) {}

    /// Called when a program is deactivated (a new program is becoming active).
    fn on_program_deactivated(&mut self, _program: &ProgramHandle) {}

    /// Called after all plugins have processed the activation event.
    fn on_post_program_activated(&mut self, _program: &ProgramHandle) {}

    /// Called when the user's location within the active program changes.
    fn on_location_changed(&mut self, _loc: Option<&ProgramLocation>) {}

    /// Called when the user's selection within the active program changes.
    fn on_selection_changed(&mut self, _sel: Option<&ProgramSelection>) {}

    /// Called when the user's highlight within the active program changes.
    fn on_highlight_changed(&mut self, _hl: Option<&ProgramSelection>) {}

    // -- Convenience methods -------------------------------------------------

    /// Set the current program directly (without processing an event).
    pub fn set_current_program(&mut self, program: Option<ProgramHandle>) {
        self.current_program = program;
    }

    /// Set the current location directly.
    pub fn set_current_location(&mut self, loc: Option<ProgramLocation>) {
        self.current_location = loc;
    }

    /// Set the current selection directly.
    pub fn set_current_selection(&mut self, sel: Option<ProgramSelection>) {
        self.current_selection = sel;
    }

    /// Set the current highlight directly.
    pub fn set_current_highlight(&mut self, hl: Option<ProgramSelection>) {
        self.current_highlight = hl;
    }
}

impl Default for ProgramPlugin {
    fn default() -> Self {
        Self::new("ProgramPlugin")
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_creation() {
        let plugin = ProgramPlugin::new("TestPlugin");
        assert_eq!(plugin.name(), "TestPlugin");
        assert!(!plugin.is_initialized());
        assert!(plugin.current_program().is_none());
    }

    #[test]
    fn test_plugin_init_dispose() {
        let mut plugin = ProgramPlugin::new("Test");
        plugin.init();
        assert!(plugin.is_initialized());

        plugin.dispose();
        assert!(!plugin.is_initialized());
        assert!(plugin.current_program().is_none());
    }

    #[test]
    fn test_program_activated() {
        let mut plugin = ProgramPlugin::new("Test");
        plugin.init();

        plugin.process_event(ProgramPluginEvent::Activated(ProgramHandle::new("test.exe")));
        assert_eq!(plugin.current_program_name(), Some("test.exe"));
    }

    #[test]
    fn test_program_switch() {
        let mut plugin = ProgramPlugin::new("Test");
        plugin.init();

        plugin.process_event(ProgramPluginEvent::Activated(ProgramHandle::new("a.exe")));
        assert_eq!(plugin.current_program_name(), Some("a.exe"));

        plugin.process_event(ProgramPluginEvent::Activated(ProgramHandle::new("b.exe")));
        assert_eq!(plugin.current_program_name(), Some("b.exe"));
    }

    #[test]
    fn test_location_changed() {
        let mut plugin = ProgramPlugin::new("Test");
        plugin.init();

        // Without a program, location events are ignored
        plugin.process_event(ProgramPluginEvent::LocationChanged(Some(
            ProgramLocation::new(Address(0x401000)),
        )));
        assert!(plugin.current_location().is_none());

        // With a program, location is tracked
        plugin.process_event(ProgramPluginEvent::Activated(ProgramHandle::new("test.exe")));
        plugin.process_event(ProgramPluginEvent::LocationChanged(Some(
            ProgramLocation::new(Address(0x401000)),
        )));
        assert!(plugin.current_location().is_some());
        assert_eq!(plugin.current_location().unwrap().address, Address(0x401000));
    }

    #[test]
    fn test_selection_changed() {
        let mut plugin = ProgramPlugin::new("Test");
        plugin.init();

        plugin.process_event(ProgramPluginEvent::SelectionChanged(Some(
            ProgramSelection {
                ranges: vec![(Address(0x1000), Address(0x2000))],
            },
        )));
        assert!(plugin.current_selection().is_some());

        // Empty selection clears it
        plugin.process_event(ProgramPluginEvent::SelectionChanged(Some(
            ProgramSelection { ranges: vec![] },
        )));
        assert!(plugin.current_selection().is_none());
    }

    #[test]
    fn test_highlight_changed() {
        let mut plugin = ProgramPlugin::new("Test");
        plugin.init();

        plugin.process_event(ProgramPluginEvent::HighlightChanged(Some(
            ProgramSelection {
                ranges: vec![(Address(0x3000), Address(0x4000))],
            },
        )));
        assert!(plugin.current_highlight().is_some());
    }

    #[test]
    fn test_program_handle_display() {
        let handle = ProgramHandle::new("test.exe");
        assert_eq!(format!("{}", handle), "test.exe");
    }

    #[test]
    fn test_address_display() {
        let addr = Address(0x401000);
        assert_eq!(format!("{}", addr), "0x401000");
    }

    #[test]
    fn test_program_selection_empty() {
        let sel = ProgramSelection { ranges: vec![] };
        assert!(sel.is_empty());

        let sel2 = ProgramSelection {
            ranges: vec![(Address(0), Address(1))],
        };
        assert!(!sel2.is_empty());
    }

    #[test]
    fn test_default_plugin() {
        let plugin = ProgramPlugin::default();
        assert_eq!(plugin.name(), "ProgramPlugin");
    }
}
