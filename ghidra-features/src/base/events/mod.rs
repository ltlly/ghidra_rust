//! Plugin events for program lifecycle, location, selection, and highlighting.
//!
//! Ported from Ghidra's `ghidra.app.events` Java package. These event types
//! are fired by the plugin framework to notify listeners about changes to
//! program state, user selections, and navigation.
//!
//! # Event hierarchy
//!
//! - [`PluginEvent`] -- base event with source name and event name
//! - [`AbstractLocationPluginEvent`] -- events carrying a [`ProgramLocation`]
//! - [`AbstractSelectionPluginEvent`] -- events carrying a [`ProgramSelection`]
//! - [`AbstractHighlightPluginEvent`] -- events carrying a highlight selection
//!
//! Concrete events include [`ProgramActivatedPluginEvent`],
//! [`ProgramSelectionPluginEvent`], [`ProgramLocationPluginEvent`], etc.

use std::fmt;
use std::sync::{Arc, Weak};

// ---------------------------------------------------------------------------
// Placeholder types for Program, ProgramLocation, ProgramSelection, Address
// These are forward-compatible stubs; real definitions live in ghidra-core.
// ---------------------------------------------------------------------------

/// Placeholder for a Ghidra Program.
#[derive(Debug, Clone)]
pub struct Program {
    pub name: String,
}

/// Placeholder for a program address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Address(pub u64);

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:x}", self.0)
    }
}

/// Placeholder for a program location (address + context).
#[derive(Debug, Clone)]
pub struct ProgramLocation {
    pub address: Address,
    pub program: Option<Weak<Program>>,
}

impl ProgramLocation {
    pub fn get_address(&self) -> Address {
        self.address
    }

    pub fn get_program(&self) -> Option<Arc<Program>> {
        self.program.as_ref().and_then(|w| w.upgrade())
    }
}

/// Placeholder for a program selection (set of addresses).
#[derive(Debug, Clone, Default)]
pub struct ProgramSelection {
    pub ranges: Vec<(Address, Address)>,
}

// ---------------------------------------------------------------------------
// PluginEvent base
// ---------------------------------------------------------------------------

/// Base type for all plugin events.
#[derive(Debug, Clone)]
pub struct PluginEvent {
    source_name: String,
    event_name: String,
}

impl PluginEvent {
    pub fn new(source_name: impl Into<String>, event_name: impl Into<String>) -> Self {
        Self {
            source_name: source_name.into(),
            event_name: event_name.into(),
        }
    }

    pub fn source_name(&self) -> &str {
        &self.source_name
    }

    pub fn event_name(&self) -> &str {
        &self.event_name
    }

    pub fn get_details(&self) -> String {
        format!("{}: {}", self.source_name, self.event_name)
    }
}

impl fmt::Display for PluginEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.source_name, self.event_name)
    }
}

// ---------------------------------------------------------------------------
// Abstract base events
// ---------------------------------------------------------------------------

/// Base event carrying a [`ProgramLocation`].
#[derive(Debug)]
pub struct AbstractLocationPluginEvent {
    base: PluginEvent,
    location: ProgramLocation,
    program: Weak<Program>,
}

impl AbstractLocationPluginEvent {
    pub fn new(
        source_name: impl Into<String>,
        event_name: impl Into<String>,
        location: ProgramLocation,
        program: Arc<Program>,
    ) -> Self {
        Self {
            base: PluginEvent::new(source_name, event_name),
            location,
            program: Arc::downgrade(&program),
        }
    }

    pub fn get_location(&self) -> &ProgramLocation {
        &self.location
    }

    pub fn get_program(&self) -> Option<Arc<Program>> {
        self.program.upgrade()
    }

    pub fn get_details(&self) -> String {
        format!(
            "{} addr==> {}",
            std::any::type_name::<ProgramLocation>(),
            self.location.get_address()
        )
    }
}

/// Base event carrying a [`ProgramSelection`].
#[derive(Debug)]
pub struct AbstractSelectionPluginEvent {
    base: PluginEvent,
    selection: ProgramSelection,
    program: Weak<Program>,
}

impl AbstractSelectionPluginEvent {
    pub fn new(
        source_name: impl Into<String>,
        event_name: impl Into<String>,
        selection: ProgramSelection,
        program: Arc<Program>,
    ) -> Self {
        Self {
            base: PluginEvent::new(source_name, event_name),
            selection,
            program: Arc::downgrade(&program),
        }
    }

    pub fn get_selection(&self) -> &ProgramSelection {
        &self.selection
    }

    pub fn get_program(&self) -> Option<Arc<Program>> {
        self.program.upgrade()
    }
}

/// Base event carrying a highlight [`ProgramSelection`].
#[derive(Debug)]
pub struct AbstractHighlightPluginEvent {
    base: PluginEvent,
    highlight: ProgramSelection,
    program: Weak<Program>,
}

impl AbstractHighlightPluginEvent {
    pub fn new(
        source_name: impl Into<String>,
        event_name: impl Into<String>,
        highlight: ProgramSelection,
        program: Arc<Program>,
    ) -> Self {
        Self {
            base: PluginEvent::new(source_name, event_name),
            highlight,
            program: Arc::downgrade(&program),
        }
    }

    pub fn get_highlight(&self) -> &ProgramSelection {
        &self.highlight
    }

    pub fn get_program(&self) -> Option<Arc<Program>> {
        self.program.upgrade()
    }
}

// ---------------------------------------------------------------------------
// Concrete program lifecycle events
// ---------------------------------------------------------------------------

/// Fired when a program becomes the active program in the tool.
#[derive(Debug)]
pub struct ProgramActivatedPluginEvent {
    program_ref: Weak<Program>,
}

impl ProgramActivatedPluginEvent {
    pub const NAME: &'static str = "Program Activated";

    pub fn new(source: impl Into<String>, active_program: Arc<Program>) -> (PluginEvent, Self) {
        let event = PluginEvent::new(source, Self::NAME);
        let payload = Self {
            program_ref: Arc::downgrade(&active_program),
        };
        (event, payload)
    }

    pub fn get_active_program(&self) -> Option<Arc<Program>> {
        self.program_ref.upgrade()
    }
}

/// Fired when a program is opened in the tool.
#[derive(Debug)]
pub struct ProgramOpenedPluginEvent {
    program_ref: Weak<Program>,
}

impl ProgramOpenedPluginEvent {
    pub const NAME: &'static str = "ProgramOpened";

    pub fn new(source: impl Into<String>, program: Arc<Program>) -> (PluginEvent, Self) {
        let event = PluginEvent::new(source, Self::NAME);
        let payload = Self {
            program_ref: Arc::downgrade(&program),
        };
        (event, payload)
    }

    pub fn get_program(&self) -> Option<Arc<Program>> {
        self.program_ref.upgrade()
    }
}

/// Fired when a program is closed.
#[derive(Debug)]
pub struct ProgramClosedPluginEvent {
    program_ref: Weak<Program>,
}

impl ProgramClosedPluginEvent {
    pub const NAME: &'static str = "ProgramClosed";

    pub fn new(source: impl Into<String>, program: Arc<Program>) -> (PluginEvent, Self) {
        let event = PluginEvent::new(source, Self::NAME);
        let payload = Self {
            program_ref: Arc::downgrade(&program),
        };
        (event, payload)
    }

    pub fn get_program(&self) -> Option<Arc<Program>> {
        self.program_ref.upgrade()
    }
}

/// Fired when a program is about to be closed.
#[derive(Debug)]
pub struct CloseProgramPluginEvent {
    program_ref: Weak<Program>,
}

impl CloseProgramPluginEvent {
    pub const NAME: &'static str = "CloseProgram";

    pub fn new(source: impl Into<String>, program: Arc<Program>) -> (PluginEvent, Self) {
        let event = PluginEvent::new(source, Self::NAME);
        let payload = Self {
            program_ref: Arc::downgrade(&program),
        };
        (event, payload)
    }

    pub fn get_program(&self) -> Option<Arc<Program>> {
        self.program_ref.upgrade()
    }
}

/// Fired after a program has been fully analyzed for the first time.
#[derive(Debug)]
pub struct FirstTimeAnalyzedPluginEvent {
    program_ref: Weak<Program>,
}

impl FirstTimeAnalyzedPluginEvent {
    pub const NAME: &'static str = "FirstTimeAnalyzed";

    pub fn new(source: impl Into<String>, program: Arc<Program>) -> (PluginEvent, Self) {
        let event = PluginEvent::new(source, Self::NAME);
        let payload = Self {
            program_ref: Arc::downgrade(&program),
        };
        (event, payload)
    }

    pub fn get_program(&self) -> Option<Arc<Program>> {
        self.program_ref.upgrade()
    }
}

/// Fired when a program's visibility changes.
#[derive(Debug)]
pub struct ProgramVisibilityChangePluginEvent {
    program_ref: Weak<Program>,
    visible: bool,
}

impl ProgramVisibilityChangePluginEvent {
    pub const NAME: &'static str = "ProgramVisibilityChange";

    pub fn new(
        source: impl Into<String>,
        program: Arc<Program>,
        visible: bool,
    ) -> (PluginEvent, Self) {
        let event = PluginEvent::new(source, Self::NAME);
        let payload = Self {
            program_ref: Arc::downgrade(&program),
            visible,
        };
        (event, payload)
    }

    pub fn get_program(&self) -> Option<Arc<Program>> {
        self.program_ref.upgrade()
    }

    pub fn is_visible(&self) -> bool {
        self.visible
    }
}

// ---------------------------------------------------------------------------
// Location events
// ---------------------------------------------------------------------------

/// Fired when the user navigates to a new location in a program.
#[derive(Debug)]
pub struct ProgramLocationPluginEvent {
    inner: AbstractLocationPluginEvent,
}

impl ProgramLocationPluginEvent {
    pub const NAME: &'static str = "ProgramLocation";

    pub fn new(
        source: impl Into<String>,
        location: ProgramLocation,
        program: Arc<Program>,
    ) -> Self {
        Self {
            inner: AbstractLocationPluginEvent::new(source, Self::NAME, location, program),
        }
    }

    pub fn get_location(&self) -> &ProgramLocation {
        self.inner.get_location()
    }

    pub fn get_program(&self) -> Option<Arc<Program>> {
        self.inner.get_program()
    }
}

/// Fired after a program has been activated.
#[derive(Debug)]
pub struct ProgramPostActivatedPluginEvent {
    inner: AbstractLocationPluginEvent,
}

impl ProgramPostActivatedPluginEvent {
    pub const NAME: &'static str = "ProgramPostActivated";

    pub fn new(
        source: impl Into<String>,
        location: ProgramLocation,
        program: Arc<Program>,
    ) -> Self {
        Self {
            inner: AbstractLocationPluginEvent::new(source, Self::NAME, location, program),
        }
    }

    pub fn get_location(&self) -> &ProgramLocation {
        self.inner.get_location()
    }

    pub fn get_program(&self) -> Option<Arc<Program>> {
        self.inner.get_program()
    }
}

/// Fired for an external program location.
#[derive(Debug)]
pub struct ExternalProgramLocationPluginEvent {
    inner: AbstractLocationPluginEvent,
}

impl ExternalProgramLocationPluginEvent {
    pub const NAME: &'static str = "ExternalProgramLocation";

    pub fn new(
        source: impl Into<String>,
        location: ProgramLocation,
        program: Arc<Program>,
    ) -> Self {
        Self {
            inner: AbstractLocationPluginEvent::new(source, Self::NAME, location, program),
        }
    }

    pub fn get_location(&self) -> &ProgramLocation {
        self.inner.get_location()
    }

    pub fn get_program(&self) -> Option<Arc<Program>> {
        self.inner.get_program()
    }
}

/// Fired for an external reference event.
#[derive(Debug)]
pub struct ExternalReferencePluginEvent {
    inner: AbstractLocationPluginEvent,
}

impl ExternalReferencePluginEvent {
    pub const NAME: &'static str = "ExternalReference";

    pub fn new(
        source: impl Into<String>,
        location: ProgramLocation,
        program: Arc<Program>,
    ) -> Self {
        Self {
            inner: AbstractLocationPluginEvent::new(source, Self::NAME, location, program),
        }
    }

    pub fn get_location(&self) -> &ProgramLocation {
        self.inner.get_location()
    }

    pub fn get_program(&self) -> Option<Arc<Program>> {
        self.inner.get_program()
    }
}

// ---------------------------------------------------------------------------
// Selection events
// ---------------------------------------------------------------------------

/// Fired when the selection in a program changes.
#[derive(Debug)]
pub struct ProgramSelectionPluginEvent {
    inner: AbstractSelectionPluginEvent,
}

impl ProgramSelectionPluginEvent {
    pub const NAME: &'static str = "ProgramSelection";

    pub fn new(
        source: impl Into<String>,
        selection: ProgramSelection,
        program: Arc<Program>,
    ) -> Self {
        Self {
            inner: AbstractSelectionPluginEvent::new(source, Self::NAME, selection, program),
        }
    }

    pub fn get_selection(&self) -> &ProgramSelection {
        self.inner.get_selection()
    }

    pub fn get_program(&self) -> Option<Arc<Program>> {
        self.inner.get_program()
    }
}

/// Fired for an external program selection.
#[derive(Debug)]
pub struct ExternalProgramSelectionPluginEvent {
    inner: AbstractSelectionPluginEvent,
}

impl ExternalProgramSelectionPluginEvent {
    pub const NAME: &'static str = "ExternalProgramSelection";

    pub fn new(
        source: impl Into<String>,
        selection: ProgramSelection,
        program: Arc<Program>,
    ) -> Self {
        Self {
            inner: AbstractSelectionPluginEvent::new(source, Self::NAME, selection, program),
        }
    }

    pub fn get_selection(&self) -> &ProgramSelection {
        self.inner.get_selection()
    }

    pub fn get_program(&self) -> Option<Arc<Program>> {
        self.inner.get_program()
    }
}

/// Fired when a tree selection changes.
#[derive(Debug)]
pub struct TreeSelectionPluginEvent {
    inner: AbstractSelectionPluginEvent,
}

impl TreeSelectionPluginEvent {
    pub const NAME: &'static str = "TreeSelection";

    pub fn new(
        source: impl Into<String>,
        selection: ProgramSelection,
        program: Arc<Program>,
    ) -> Self {
        Self {
            inner: AbstractSelectionPluginEvent::new(source, Self::NAME, selection, program),
        }
    }

    pub fn get_selection(&self) -> &ProgramSelection {
        self.inner.get_selection()
    }

    pub fn get_program(&self) -> Option<Arc<Program>> {
        self.inner.get_program()
    }
}

// ---------------------------------------------------------------------------
// Highlight events
// ---------------------------------------------------------------------------

/// Fired when the highlight in a program changes.
#[derive(Debug)]
pub struct ProgramHighlightPluginEvent {
    inner: AbstractHighlightPluginEvent,
}

impl ProgramHighlightPluginEvent {
    pub const NAME: &'static str = "ProgramHighlight";

    pub fn new(
        source: impl Into<String>,
        highlight: ProgramSelection,
        program: Arc<Program>,
    ) -> Self {
        Self {
            inner: AbstractHighlightPluginEvent::new(source, Self::NAME, highlight, program),
        }
    }

    pub fn get_highlight(&self) -> &ProgramSelection {
        self.inner.get_highlight()
    }

    pub fn get_program(&self) -> Option<Arc<Program>> {
        self.inner.get_program()
    }
}

// ---------------------------------------------------------------------------
// View events
// ---------------------------------------------------------------------------

/// Fired when a view changes (e.g., switching between code browser and decompiler).
#[derive(Debug, Clone)]
pub struct ViewChangedPluginEvent {
    base: PluginEvent,
}

impl ViewChangedPluginEvent {
    pub const NAME: &'static str = "ViewChanged";

    pub fn new(source: impl Into<String>) -> Self {
        Self {
            base: PluginEvent::new(source, Self::NAME),
        }
    }

    pub fn event_name(&self) -> &str {
        self.base.event_name()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_program_activated_event() {
        let program = Arc::new(Program {
            name: "test.exe".into(),
        });
        let (event, payload) = ProgramActivatedPluginEvent::new("TestPlugin", program.clone());
        assert_eq!(event.event_name(), "Program Activated");
        assert!(payload.get_active_program().is_some());
    }

    #[test]
    fn test_program_opened_event() {
        let program = Arc::new(Program {
            name: "test.bin".into(),
        });
        let program_clone = Arc::clone(&program);
        let (event, payload) = ProgramOpenedPluginEvent::new("TestPlugin", program);
        assert_eq!(event.event_name(), "ProgramOpened");
        // Keep a strong ref alive so the Weak can upgrade
        assert!(payload.get_program().is_some());
        let _keep_alive = program_clone;
    }

    #[test]
    fn test_program_closed_event() {
        let program = Arc::new(Program {
            name: "test.bin".into(),
        });
        let program_clone = Arc::clone(&program);
        let (event, _payload) = ProgramClosedPluginEvent::new("TestPlugin", program);
        assert_eq!(event.event_name(), "ProgramClosed");
        let _keep_alive = program_clone;
    }

    #[test]
    fn test_program_location_event() {
        let program = Arc::new(Program {
            name: "test.bin".into(),
        });
        let loc = ProgramLocation {
            address: Address(0x401000),
            program: Some(Arc::downgrade(&program)),
        };
        let event = ProgramLocationPluginEvent::new("TestPlugin", loc, program.clone());
        assert_eq!(event.get_location().get_address(), Address(0x401000));
        assert!(event.get_program().is_some());
    }

    #[test]
    fn test_program_selection_event() {
        let program = Arc::new(Program {
            name: "test.bin".into(),
        });
        let sel = ProgramSelection {
            ranges: vec![(Address(0x1000), Address(0x2000))],
        };
        let event = ProgramSelectionPluginEvent::new("TestPlugin", sel, program);
        assert_eq!(event.get_selection().ranges.len(), 1);
    }

    #[test]
    fn test_program_highlight_event() {
        let program = Arc::new(Program {
            name: "test.bin".into(),
        });
        let hl = ProgramSelection::default();
        let event = ProgramHighlightPluginEvent::new("TestPlugin", hl, program);
        assert!(event.get_highlight().ranges.is_empty());
    }

    #[test]
    fn test_first_time_analyzed() {
        let program = Arc::new(Program {
            name: "test.bin".into(),
        });
        let program_clone = Arc::clone(&program);
        let (event, _) = FirstTimeAnalyzedPluginEvent::new("Analyzer", program);
        assert_eq!(event.event_name(), "FirstTimeAnalyzed");
        let _keep_alive = program_clone;
    }

    #[test]
    fn test_visibility_change() {
        let program = Arc::new(Program {
            name: "test.bin".into(),
        });
        let program_clone = Arc::clone(&program);
        let (_, payload) = ProgramVisibilityChangePluginEvent::new("PM", program, true);
        assert!(payload.is_visible());
        let _keep_alive = program_clone;
    }

    #[test]
    fn test_view_changed() {
        let event = ViewChangedPluginEvent::new("CodeBrowser");
        assert_eq!(event.event_name(), "ViewChanged");
    }

    #[test]
    fn test_plugin_event_display() {
        let event = PluginEvent::new("Test", "TestEvent");
        let s = format!("{}", event);
        assert!(s.contains("Test"));
        assert!(s.contains("TestEvent"));
    }

    #[test]
    fn test_weak_ref_drop() {
        let program = Arc::new(Program {
            name: "test.bin".into(),
        });
        let (_, payload) = ProgramActivatedPluginEvent::new("TestPlugin", program);
        // Drop the only Arc
        assert!(payload.get_active_program().is_none());
    }

    #[test]
    fn test_address_display() {
        let addr = Address(0xDEADBEEF);
        assert_eq!(format!("{}", addr), "0xdeadbeef");
    }
}
