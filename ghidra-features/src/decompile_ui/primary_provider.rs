//! Primary decompiler provider -- Rust port of
//! `ghidra.app.plugin.core.decompile.PrimaryDecompilerProvider`.
//!
//! The primary provider is always connected to the tool and serves as
//! the main decompiler view.  It is a thin specialization of
//! [`DecompilerProvider`] that enforces `is_connected() == true`.

use super::provider::DecompilerProvider;

// ---------------------------------------------------------------------------
// PrimaryDecompilerProvider
// ---------------------------------------------------------------------------

/// The primary (connected) decompiler provider.
///
/// This is always the first provider created by the plugin and is
/// permanently connected to the tool.  It cannot be made disconnected.
///
/// In Ghidra this is a simple subclass that overrides `isConnected()`
/// to always return `true`.  In Rust we compose over the base
/// `DecompilerProvider` and enforce the invariant at construction.
#[derive(Debug)]
pub struct PrimaryDecompilerProvider {
    /// The underlying connected provider.
    inner: DecompilerProvider,
}

impl PrimaryDecompilerProvider {
    /// Create a new primary provider.
    ///
    /// The provider is always connected (id = 0).
    pub fn new() -> Self {
        Self {
            inner: DecompilerProvider::new_connected(0),
        }
    }

    /// Returns `true` (the primary provider is always connected).
    pub fn is_connected(&self) -> bool {
        true
    }

    /// Returns `false` (the primary provider is never a snapshot).
    pub fn is_snapshot(&self) -> bool {
        false
    }

    /// Get a reference to the underlying provider.
    pub fn as_provider(&self) -> &DecompilerProvider {
        &self.inner
    }

    /// Get a mutable reference to the underlying provider.
    pub fn as_provider_mut(&mut self) -> &mut DecompilerProvider {
        &mut self.inner
    }

    /// The provider's unique id (always 0 for the primary).
    pub fn id(&self) -> usize {
        self.inner.id()
    }

    /// Get the current state.
    pub fn state(&self) -> super::provider::ProviderState {
        self.inner.state()
    }

    /// Set the provider to visible.
    pub fn set_visible(&mut self) {
        self.inner.set_visible();
    }

    /// Set the provider to hidden.
    pub fn set_hidden(&mut self) {
        self.inner.set_hidden();
    }

    /// Get the bound program name.
    pub fn program_name(&self) -> Option<&str> {
        self.inner.program_name()
    }

    /// Set the program for this provider.
    pub fn set_program(&mut self, name: Option<String>) {
        self.inner.set_program(name);
    }

    /// Get the current location.
    pub fn current_location(&self) -> Option<ghidra_core::addr::Address> {
        self.inner.current_location()
    }

    /// Set the current location.
    pub fn set_location(&mut self, location: Option<ghidra_core::addr::Address>) {
        self.inner.set_location(location);
    }

    /// Get the current selection.
    pub fn current_selection(&self) -> Option<(ghidra_core::addr::Address, ghidra_core::addr::Address)> {
        self.inner.current_selection()
    }

    /// Set the current selection.
    pub fn set_selection(&mut self, sel: Option<(ghidra_core::addr::Address, ghidra_core::addr::Address)>) {
        self.inner.set_selection(sel);
    }

    /// Returns the window title.
    pub fn title(&self) -> &str {
        self.inner.title()
    }

    /// Returns the window subtitle.
    pub fn subtitle(&self) -> &str {
        self.inner.subtitle()
    }

    /// Returns the tab text.
    pub fn tab_text(&self) -> &str {
        self.inner.tab_text()
    }

    /// Toggle the display lock.
    pub fn toggle_display_lock(&mut self) {
        self.inner.toggle_display_lock();
    }

    /// Returns the display lock state.
    pub fn display_lock(&self) -> super::provider::DisplayLockState {
        self.inner.display_lock()
    }

    /// Whether this provider should send events to the tool (always true).
    pub fn should_send_events(&self) -> bool {
        true
    }

    /// Toggle the unreachable code display.
    pub fn toggle_unreachable_code(&mut self) {
        self.inner.toggle_unreachable_code();
    }

    /// Returns whether unreachable code display is enabled.
    pub fn is_showing_unreachable_code(&self) -> bool {
        self.inner.is_showing_unreachable_code()
    }

    /// Toggle respect for read-only flags.
    pub fn toggle_respect_read_only(&mut self) {
        self.inner.toggle_respect_read_only();
    }

    /// Returns whether read-only flags are being respected.
    pub fn is_respecting_read_only(&self) -> bool {
        self.inner.is_respecting_read_only()
    }

    /// Request a refresh of the decompile display.
    pub fn refresh(&mut self) {
        self.inner.refresh();
    }

    /// Notify this provider that a token was renamed.
    pub fn notify_token_renamed(&mut self, old_name: &str, new_name: &str) {
        self.inner.notify_token_renamed(old_name, new_name);
    }

    /// Dispose this provider.
    pub fn dispose(&mut self) {
        self.inner.dispose();
    }
}

impl Default for PrimaryDecompilerProvider {
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
    fn test_primary_provider_is_always_connected() {
        let p = PrimaryDecompilerProvider::new();
        assert!(p.is_connected());
        assert!(!p.is_snapshot());
    }

    #[test]
    fn test_primary_provider_id_is_zero() {
        let p = PrimaryDecompilerProvider::new();
        assert_eq!(p.id(), 0);
    }

    #[test]
    fn test_primary_provider_should_always_send_events() {
        let p = PrimaryDecompilerProvider::new();
        assert!(p.should_send_events());
    }

    #[test]
    fn test_primary_provider_state() {
        let mut p = PrimaryDecompilerProvider::new();
        assert_eq!(p.state(), super::super::provider::ProviderState::Created);

        p.set_visible();
        assert_eq!(p.state(), super::super::provider::ProviderState::Visible);

        p.set_hidden();
        assert_eq!(p.state(), super::super::provider::ProviderState::Hidden);
    }

    #[test]
    fn test_primary_provider_program() {
        let mut p = PrimaryDecompilerProvider::new();
        assert!(p.program_name().is_none());

        p.set_program(Some("test.elf".into()));
        assert_eq!(p.program_name(), Some("test.elf"));
        assert!(p.title().contains("test.elf"));
    }

    #[test]
    fn test_primary_provider_location() {
        use ghidra_core::addr::Address;

        let mut p = PrimaryDecompilerProvider::new();
        assert!(p.current_location().is_none());

        p.set_location(Some(Address::new(0x1000)));
        assert_eq!(p.current_location(), Some(Address::new(0x1000)));
    }

    #[test]
    fn test_primary_provider_selection() {
        use ghidra_core::addr::Address;

        let mut p = PrimaryDecompilerProvider::new();
        assert!(p.current_selection().is_none());

        p.set_selection(Some((Address::new(0x100), Address::new(0x200))));
        assert_eq!(
            p.current_selection(),
            Some((Address::new(0x100), Address::new(0x200)))
        );
    }

    #[test]
    fn test_primary_provider_display_lock() {
        let mut p = PrimaryDecompilerProvider::new();
        assert_eq!(
            p.display_lock(),
            super::super::provider::DisplayLockState::Unlocked
        );

        p.toggle_display_lock();
        assert_eq!(
            p.display_lock(),
            super::super::provider::DisplayLockState::Locked
        );
    }

    #[test]
    fn test_primary_provider_unreachable_toggle() {
        let mut p = PrimaryDecompilerProvider::new();
        assert!(!p.is_showing_unreachable_code());

        p.toggle_unreachable_code();
        assert!(p.is_showing_unreachable_code());
    }

    #[test]
    fn test_primary_provider_read_only_toggle() {
        let mut p = PrimaryDecompilerProvider::new();
        assert!(!p.is_respecting_read_only());

        p.toggle_respect_read_only();
        assert!(p.is_respecting_read_only());
    }

    #[test]
    fn test_primary_provider_dispose() {
        let mut p = PrimaryDecompilerProvider::new();
        p.set_program(Some("prog.bin".into()));
        p.dispose();
        assert_eq!(p.state(), super::super::provider::ProviderState::Disposed);
    }

    #[test]
    fn test_primary_provider_title_format() {
        let mut p = PrimaryDecompilerProvider::new();
        p.set_program(Some("my_prog".into()));
        // The primary provider title should NOT have brackets.
        assert!(!p.title().starts_with('['));
        assert!(p.title().contains("my_prog"));
    }

    #[test]
    fn test_primary_provider_as_provider() {
        let mut p = PrimaryDecompilerProvider::new();
        p.set_program(Some("test".into()));

        // Access through as_provider.
        assert_eq!(p.as_provider().program_name(), Some("test"));

        // Access through as_provider_mut.
        p.as_provider_mut().set_location(Some(ghidra_core::addr::Address::new(0x500)));
        assert_eq!(p.current_location(), Some(ghidra_core::addr::Address::new(0x500)));
    }
}
