//! Decompiler provider -- Rust port of
//! `ghidra.app.plugin.core.decompile.DecompilerProvider`.
//!
//! Each provider manages one decompiler panel.  A "connected" provider
//! is linked to the main tool and receives program/location/selection
//! events automatically.  A "disconnected" provider is a snapshot that
//! only works with a fixed program.

use ghidra_core::addr::Address;

use super::overlay_painter::OverlayMessagePainter;

// ---------------------------------------------------------------------------
// ProviderState
// ---------------------------------------------------------------------------

/// The lifecycle state of a decompiler provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderState {
    /// The provider has been created but not yet displayed.
    Created,
    /// The provider is visible and active.
    Visible,
    /// The provider is hidden (minimised or behind other tabs).
    Hidden,
    /// The provider has been disposed.
    Disposed,
}

// ---------------------------------------------------------------------------
// Display lock state
// ---------------------------------------------------------------------------

/// Whether the decompiler display is "locked" (not auto-refreshing).
///
/// When locked, program changes cause an overlay message ("Press F5 to
/// refresh") instead of an automatic re-decompile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisplayLockState {
    /// Normal mode: auto-refresh on changes.
    Unlocked,
    /// Locked mode: manual refresh only.
    Locked,
}

// ---------------------------------------------------------------------------
// ToggleButtonState
// ---------------------------------------------------------------------------

/// The state of a toolbar toggle button in the provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ToggleButtonState {
    /// Whether the button is currently selected (active).
    pub selected: bool,
}

impl Default for ToggleButtonState {
    fn default() -> Self {
        Self { selected: false }
    }
}

// ---------------------------------------------------------------------------
// DecompilerProvider
// ---------------------------------------------------------------------------

/// A decompiler view provider.
///
/// Manages the lifecycle of a single decompiler panel -- program binding,
/// location tracking, selection, display lock, and overlay messages.
///
/// Connected providers are created with `new_connected()` and receive
/// events from the plugin.  Disconnected providers (snapshots) are
/// created with `new_disconnected()` and work only with their fixed
/// program.
#[derive(Debug)]
pub struct DecompilerProvider {
    /// Unique identifier (0 = connected, >0 = disconnected).
    id: usize,
    /// Whether this provider is connected to the main tool.
    is_connected: bool,
    /// Current state.
    state: ProviderState,
    /// The program name bound to this provider.
    program_name: Option<String>,
    /// The current location (address offset).
    current_location: Option<Address>,
    /// The current selection range (start, end).
    current_selection: Option<(Address, Address)>,
    /// Display lock state.
    display_lock: DisplayLockState,
    /// Whether outgoing events are allowed (only meaningful for
    /// disconnected providers).
    allow_outgoing_events: bool,
    /// The overlay message painter.
    overlay_painter: OverlayMessagePainter,
    /// Toggle: show unreachable code.
    toggle_unreachable: ToggleButtonState,
    /// Toggle: respect read-only flags.
    toggle_read_only: ToggleButtonState,
    /// Title of the provider window.
    title: String,
    /// Subtitle (e.g., program name).
    subtitle: String,
    /// Tab text.
    tab_text: String,
}

impl DecompilerProvider {
    /// Create a new connected provider.
    pub fn new_connected(id: usize) -> Self {
        Self {
            id,
            is_connected: true,
            state: ProviderState::Created,
            program_name: None,
            current_location: None,
            current_selection: None,
            display_lock: DisplayLockState::Unlocked,
            allow_outgoing_events: false,
            overlay_painter: OverlayMessagePainter::new(),
            toggle_unreachable: ToggleButtonState { selected: false },
            toggle_read_only: ToggleButtonState { selected: false },
            title: "Decompile".into(),
            subtitle: String::new(),
            tab_text: "Decompiler".into(),
        }
    }

    /// Create a new disconnected (snapshot) provider.
    pub fn new_disconnected(id: usize) -> Self {
        Self {
            id,
            is_connected: false,
            state: ProviderState::Created,
            program_name: None,
            current_location: None,
            current_selection: None,
            display_lock: DisplayLockState::Unlocked,
            allow_outgoing_events: false,
            overlay_painter: OverlayMessagePainter::new(),
            toggle_unreachable: ToggleButtonState { selected: false },
            toggle_read_only: ToggleButtonState { selected: false },
            title: "[Decompile]".into(),
            subtitle: String::new(),
            tab_text: "[Decompiler]".into(),
        }
    }

    /// The provider's unique id.
    pub fn id(&self) -> usize {
        self.id
    }

    /// Returns `true` if this is a connected provider.
    pub fn is_connected(&self) -> bool {
        self.is_connected
    }

    /// Returns `true` if this is a snapshot (disconnected) provider.
    pub fn is_snapshot(&self) -> bool {
        !self.is_connected
    }

    /// Get the current state.
    pub fn state(&self) -> ProviderState {
        self.state
    }

    /// Set the provider to visible.
    pub fn set_visible(&mut self) {
        if self.state != ProviderState::Disposed {
            self.state = ProviderState::Visible;
        }
    }

    /// Set the provider to hidden.
    pub fn set_hidden(&mut self) {
        if self.state != ProviderState::Disposed {
            self.state = ProviderState::Hidden;
        }
    }

    /// Get the bound program name.
    pub fn program_name(&self) -> Option<&str> {
        self.program_name.as_deref()
    }

    /// Set the program for this provider.
    pub fn set_program(&mut self, name: Option<String>) {
        self.program_name = name;
        self.current_location = None;
        self.current_selection = None;
        self.update_title();
    }

    /// Set the current location.
    pub fn set_location(&mut self, location: Option<Address>) {
        self.current_location = location;
    }

    /// Get the current location.
    pub fn current_location(&self) -> Option<Address> {
        self.current_location
    }

    /// Set the current selection.
    pub fn set_selection(&mut self, selection: Option<(Address, Address)>) {
        self.current_selection = selection;
    }

    /// Get the current selection.
    pub fn current_selection(&self) -> Option<(Address, Address)> {
        self.current_selection
    }

    /// Toggle the display lock.
    pub fn toggle_display_lock(&mut self) {
        self.display_lock = match self.display_lock {
            DisplayLockState::Unlocked => DisplayLockState::Locked,
            DisplayLockState::Locked => {
                self.overlay_painter.clear();
                DisplayLockState::Unlocked
            }
        };
    }

    /// Returns the display lock state.
    pub fn display_lock(&self) -> DisplayLockState {
        self.display_lock
    }

    /// Toggle whether outgoing events are allowed (disconnected providers).
    pub fn toggle_outgoing_events(&mut self) {
        self.allow_outgoing_events = !self.allow_outgoing_events;
    }

    /// Whether this provider should send events to the tool.
    pub fn should_send_events(&self) -> bool {
        self.is_connected || self.allow_outgoing_events
    }

    /// Get the overlay painter.
    pub fn overlay_painter(&self) -> &OverlayMessagePainter {
        &self.overlay_painter
    }

    /// Get a mutable reference to the overlay painter.
    pub fn overlay_painter_mut(&mut self) -> &mut OverlayMessagePainter {
        &mut self.overlay_painter
    }

    /// Toggle the unreachable code display.
    pub fn toggle_unreachable_code(&mut self) {
        self.toggle_unreachable.selected = !self.toggle_unreachable.selected;
    }

    /// Returns whether unreachable code display is enabled.
    pub fn is_showing_unreachable_code(&self) -> bool {
        self.toggle_unreachable.selected
    }

    /// Toggle respect for read-only flags.
    pub fn toggle_respect_read_only(&mut self) {
        self.toggle_read_only.selected = !self.toggle_read_only.selected;
    }

    /// Returns whether read-only flags are being respected.
    pub fn is_respecting_read_only(&self) -> bool {
        self.toggle_read_only.selected
    }

    /// Notify this provider that a token was renamed.
    pub fn notify_token_renamed(&mut self, _old_name: &str, _new_name: &str) {
        // In the full implementation, this updates the decompiler panel's
        // token text.  Here we just mark a refresh as needed.
        if self.display_lock == DisplayLockState::Locked {
            self.overlay_painter.set_message("F5 to refresh");
        }
    }

    /// Request a refresh of the decompile display.
    pub fn refresh(&mut self) {
        self.overlay_painter.clear();
        // In the full implementation, this triggers a re-decompile.
    }

    /// Returns the window title.
    pub fn title(&self) -> &str {
        &self.title
    }

    /// Returns the window subtitle.
    pub fn subtitle(&self) -> &str {
        &self.subtitle
    }

    /// Returns the tab text.
    pub fn tab_text(&self) -> &str {
        &self.tab_text
    }

    /// Dispose this provider.
    pub fn dispose(&mut self) {
        self.state = ProviderState::Disposed;
        self.program_name = None;
        self.current_location = None;
        self.current_selection = None;
    }

    // -- Private helpers --

    fn update_title(&mut self) {
        let prog_display = self
            .program_name
            .as_deref()
            .unwrap_or("No Program");

        if self.is_connected {
            self.title = format!("Decompile: {}", prog_display);
            self.subtitle = format!(" ({})", prog_display);
            self.tab_text = "Decompiler".into();
        } else {
            self.title = format!("[Decompile: {}]", prog_display);
            self.subtitle = format!(" ({})", prog_display);
            self.tab_text = format!("[{}]", prog_display);
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_connected() {
        let p = DecompilerProvider::new_connected(0);
        assert!(p.is_connected());
        assert!(!p.is_snapshot());
        assert_eq!(p.state(), ProviderState::Created);
    }

    #[test]
    fn test_provider_disconnected() {
        let p = DecompilerProvider::new_disconnected(1);
        assert!(!p.is_connected());
        assert!(p.is_snapshot());
    }

    #[test]
    fn test_provider_set_program() {
        let mut p = DecompilerProvider::new_connected(0);
        p.set_program(Some("test.elf".into()));
        assert_eq!(p.program_name(), Some("test.elf"));
        assert!(p.title().contains("test.elf"));
    }

    #[test]
    fn test_provider_set_location() {
        let mut p = DecompilerProvider::new_connected(0);
        p.set_location(Some(Address::new(0x1000)));
        assert_eq!(p.current_location(), Some(Address::new(0x1000)));
    }

    #[test]
    fn test_provider_selection() {
        let mut p = DecompilerProvider::new_connected(0);
        p.set_selection(Some((Address::new(0x100), Address::new(0x200))));
        assert_eq!(
            p.current_selection(),
            Some((Address::new(0x100), Address::new(0x200)))
        );
    }

    #[test]
    fn test_provider_display_lock() {
        let mut p = DecompilerProvider::new_connected(0);
        assert_eq!(p.display_lock(), DisplayLockState::Unlocked);
        p.toggle_display_lock();
        assert_eq!(p.display_lock(), DisplayLockState::Locked);
        p.toggle_display_lock();
        assert_eq!(p.display_lock(), DisplayLockState::Unlocked);
    }

    #[test]
    fn test_provider_outgoing_events() {
        let mut p = DecompilerProvider::new_disconnected(1);
        assert!(!p.should_send_events()); // disconnected, no outgoing
        p.toggle_outgoing_events();
        assert!(p.should_send_events());
    }

    #[test]
    fn test_provider_connected_always_sends() {
        let p = DecompilerProvider::new_connected(0);
        assert!(p.should_send_events());
    }

    #[test]
    fn test_provider_unreachable_toggle() {
        let mut p = DecompilerProvider::new_connected(0);
        assert!(!p.is_showing_unreachable_code());
        p.toggle_unreachable_code();
        assert!(p.is_showing_unreachable_code());
    }

    #[test]
    fn test_provider_read_only_toggle() {
        let mut p = DecompilerProvider::new_connected(0);
        assert!(!p.is_respecting_read_only());
        p.toggle_respect_read_only();
        assert!(p.is_respecting_read_only());
    }

    #[test]
    fn test_provider_dispose() {
        let mut p = DecompilerProvider::new_connected(0);
        p.set_program(Some("x.bin".into()));
        p.dispose();
        assert_eq!(p.state(), ProviderState::Disposed);
        assert!(p.program_name().is_none());
    }

    #[test]
    fn test_provider_title_update() {
        let mut p = DecompilerProvider::new_connected(0);
        p.set_program(Some("prog.elf".into()));
        assert!(p.title().contains("prog.elf"));

        let mut dp = DecompilerProvider::new_disconnected(1);
        dp.set_program(Some("snap.bin".into()));
        assert!(dp.title().starts_with('['));
        assert!(dp.tab_text().starts_with('['));
    }

    #[test]
    fn test_provider_notify_token_renamed_locked() {
        let mut p = DecompilerProvider::new_connected(0);
        p.toggle_display_lock(); // now locked
        p.notify_token_renamed("old", "new");
        assert!(p.overlay_painter().is_active());
    }

    #[test]
    fn test_provider_refresh_clears_overlay() {
        let mut p = DecompilerProvider::new_connected(0);
        p.overlay_painter_mut().set_message("test");
        p.refresh();
        assert!(!p.overlay_painter().is_active());
    }

    #[test]
    fn test_provider_state_transitions() {
        let mut p = DecompilerProvider::new_connected(0);
        assert_eq!(p.state(), ProviderState::Created);

        p.set_visible();
        assert_eq!(p.state(), ProviderState::Visible);

        p.set_hidden();
        assert_eq!(p.state(), ProviderState::Hidden);

        p.dispose();
        assert_eq!(p.state(), ProviderState::Disposed);

        // Disposed providers cannot be made visible again.
        p.set_visible();
        assert_eq!(p.state(), ProviderState::Disposed);
    }
}
