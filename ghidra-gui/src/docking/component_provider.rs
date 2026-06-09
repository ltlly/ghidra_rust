//! The `ComponentProvider` trait for the docking framework.
//!
//! Port of Ghidra's `docking.ComponentProvider` interface.  In Java,
//! `ComponentProvider` is the base class that every dockable view extends.
//! It carries the tool reference, the component name, and the methods
//! the framework uses to manage window lifecycle, context, and
//! actions.
//!
//! The existing [`super::component::ComponentProvider`] enum identifies
//! well-known provider *types*; this trait describes the behaviour of a
//! provider *instance*.

use std::fmt;

use super::action::DockingAction;
use super::action_context::DockingActionContext;
use super::component::WindowPosition;

// ---------------------------------------------------------------------------
// ComponentProvider trait
// ---------------------------------------------------------------------------

/// The trait that every dockable component provider implements.
///
/// This mirrors Ghidra's `ComponentProvider` abstract class.  A provider
/// is responsible for:
/// - Supplying the component's title and icon.
/// - Reporting its preferred docking position and size.
/// - Contributing actions to the tool's action system.
/// - Receiving focus and context change notifications.
/// - Painting its UI (delegated to the egui layer in this Rust port).
pub trait ComponentProvider: fmt::Debug + Send + Sync {
    /// The programmatic name of the component provider.
    fn name(&self) -> &str;

    /// The window title displayed in the title bar / tab.
    fn window_title(&self) -> &str;

    /// Optional sub-title (e.g. the program name for a listing view).
    fn sub_title(&self) -> &str {
        ""
    }

    /// The full window title including sub-title.
    fn full_title(&self) -> String {
        let base = self.window_title().to_owned();
        let sub = self.sub_title();
        if sub.is_empty() {
            base
        } else {
            format!("{} - {}", base, sub)
        }
    }

    /// Icon identifier (resource name or path).
    fn icon(&self) -> Option<&str> {
        None
    }

    /// The preferred default docking position.
    fn default_position(&self) -> WindowPosition {
        WindowPosition::Center
    }

    /// The preferred default size (width, height).
    fn default_size(&self) -> (f32, f32) {
        (400.0, 300.0)
    }

    /// The tool name this provider belongs to (e.g. "CodeBrowser").
    fn tool_name(&self) -> &str {
        ""
    }

    /// An optional owner (e.g. the plugin that created this provider).
    fn owner(&self) -> &str {
        ""
    }

    /// The menu group used when this provider's items appear in the
    /// Window menu.
    fn window_menu_group(&self) -> &str {
        "Views"
    }

    /// Priority for the Window menu ordering (lower = earlier).
    fn window_menu_priority(&self) -> u32 {
        100
    }

    /// Whether the provider is currently visible.
    fn is_visible(&self) -> bool;

    /// Show the provider.
    fn show(&mut self);

    /// Hide the provider.
    fn hide(&mut self);

    /// Set visibility (convenience: show or hide).
    fn set_visible(&mut self, visible: bool) {
        if visible {
            self.show();
        } else {
            self.hide();
        }
    }

    /// Toggle visibility.
    fn toggle(&mut self) {
        if self.is_visible() {
            self.hide();
        } else {
            self.show();
        }
    }

    /// Actions contributed by this provider to the tool.
    fn actions(&self) -> Vec<DockingAction> {
        Vec::new()
    }

    /// Add a local action to this provider.
    ///
    /// Port of Ghidra's `ComponentProvider.addLocalAction`.
    fn add_local_action(&mut self, _action: DockingAction) {}

    /// Remove a local action from this provider.
    ///
    /// Port of Ghidra's `ComponentProvider.removeLocalAction`.
    fn remove_local_action(&mut self, _action_name: &str) {}

    /// Remove all local actions from this provider.
    ///
    /// Port of Ghidra's `ComponentProvider.removeAllLocalActions`.
    fn remove_all_local_actions(&mut self) {}

    /// Called when this provider gains focus.
    fn focus_gained(&self) {}

    /// Called when this provider loses focus.
    fn focus_lost(&self) {}

    /// Called when this provider becomes the active component.
    ///
    /// Port of Ghidra's `ComponentProvider.componentActivated`.
    fn component_activated(&self) {}

    /// Called when this provider is no longer the active component.
    ///
    /// Port of Ghidra's `ComponentProvider.componentDeactivated`.
    fn component_deactivated(&self) {}

    /// Called when the provider's component is being shown.
    ///
    /// Port of Ghidra's `ComponentProvider.componentShown`.
    fn component_shown(&self) {}

    /// Called when the provider's component is being hidden.
    ///
    /// Port of Ghidra's `ComponentProvider.componentHidden`.
    fn component_hidden(&self) {}

    /// Called when the action context changes.
    fn context_changed(&self, _context: &DockingActionContext) {}

    /// Whether this provider is a transient (temporary) provider.
    ///
    /// Transient providers are removed from the tool when closed,
    /// rather than merely hidden.
    ///
    /// Port of Ghidra's `ComponentProvider.isTransient`.
    fn is_transient(&self) -> bool {
        false
    }

    /// Whether this provider supports temporary (transient) windows.
    fn supports_temporary_window(&self) -> bool {
        true
    }

    /// Whether this provider handles its own focus management.
    fn manages_own_focus(&self) -> bool {
        false
    }

    /// Whether this provider has a custom context menu.
    fn has_context_menu(&self) -> bool {
        false
    }

    /// Whether this provider should be shown by default in new tools.
    fn is_default_provider(&self) -> bool {
        false
    }

    /// The window group this provider belongs to.
    ///
    /// Providers in the same group are stacked together when first shown.
    /// The default group is `"Default"`.
    ///
    /// Port of Ghidra's `ComponentProvider.getWindowGroup`.
    fn window_group(&self) -> &str {
        "Default"
    }

    /// The sub-menu group for the Window menu.
    ///
    /// If non-null, the provider's "Show" action appears in a sub-menu
    /// of the Window menu named by this value.
    ///
    /// Port of Ghidra's `ComponentProvider.getWindowSubMenuName`.
    fn window_sub_menu_name(&self) -> Option<&str> {
        None
    }

    /// Help location identifier for the help system.
    fn help_location(&self) -> Option<&str> {
        None
    }

    /// Whether this provider can be closed by the user.
    fn closeable(&self) -> bool {
        true
    }

    /// Whether this provider's window can be used as a parent for
    /// system dialogs.
    ///
    /// Port of Ghidra's `ComponentProvider.canBeParent`.
    fn can_be_parent(&self) -> bool {
        true
    }

    /// Whether this provider is a snapshot of a primary provider.
    ///
    /// Port of Ghidra's `ComponentProvider.isSnapshot`.
    fn is_snapshot(&self) -> bool {
        false
    }

    /// The tab text shown when stacked with other providers.
    ///
    /// Defaults to `window_title()` if not overridden.
    fn tab_text(&self) -> &str {
        self.window_title()
    }

    /// Clean up resources when the provider is disposed.
    fn dispose(&self) {}

    /// A unique instance key (used for layout persistence).
    fn instance_key(&self) -> (super::component::ComponentProvider, String);

    /// The component provider enum value for this provider.
    fn provider_type(&self) -> super::component::ComponentProvider;

    // -- Tool integration --

    /// Whether this provider is currently in (registered with) a tool.
    ///
    /// Port of Ghidra's `ComponentProvider.isInTool()`.
    fn is_in_tool(&self) -> bool {
        false
    }

    /// Add this provider to the tool.
    ///
    /// Port of Ghidra's `ComponentProvider.addToTool()`.
    fn add_to_tool(&mut self) {}

    /// Remove this provider from the tool.
    ///
    /// Port of Ghidra's `ComponentProvider.removeFromTool()`.
    fn remove_from_tool(&mut self) {}

    /// Close this component.
    ///
    /// Port of Ghidra's `ComponentProvider.closeComponent()`.  Transient
    /// providers are removed from the tool; non-transient providers are
    /// merely hidden.
    fn close_component(&mut self) {
        if self.is_transient() {
            self.remove_from_tool();
        } else {
            self.set_visible(false);
        }
    }

    /// Notify the tool that this provider's own context has changed (no args).
    ///
    /// Port of Ghidra's `ComponentProvider.contextChanged()`.
    fn notify_context_changed(&self) {}

    // -- Title management --

    /// Set the window title.
    ///
    /// Port of Ghidra's `ComponentProvider.setTitle(String)`.
    fn set_window_title(&mut self, _title: &str) {}

    /// Set the sub-title.
    ///
    /// Port of Ghidra's `ComponentProvider.setSubTitle(String)`.
    fn set_sub_title(&mut self, _sub_title: &str) {}

    /// Set the tab text.
    ///
    /// Port of Ghidra's `ComponentProvider.setTabText(String)`.
    fn set_tab_text(&mut self, _tab_text: &str) {}

    // -- Transient / toolbar --

    /// Mark this provider as transient.
    ///
    /// Port of Ghidra's `ComponentProvider.setTransient()`.
    fn set_transient(&mut self) {}

    /// Signal that this provider's show action should appear in the toolbar.
    ///
    /// Port of Ghidra's `ComponentProvider.addToToolbar()`.
    fn add_to_toolbar(&mut self) {}

    // -- Position --

    /// The intra-group position (how this provider is placed relative to
    /// other members of the same window group).
    ///
    /// Port of Ghidra's `ComponentProvider.getIntraGroupPosition()`.
    fn intra_group_position(&self) -> WindowPosition {
        WindowPosition::Center
    }

    /// Set the intra-group position.
    fn set_intra_group_position(&mut self, _position: WindowPosition) {}

    /// Set the window group.
    ///
    /// Port of Ghidra's `ComponentProvider.setWindowGroup(String)`.
    fn set_window_group(&mut self, _group: &str) {}

    /// Set the window menu group.
    ///
    /// Port of Ghidra's `ComponentProvider.setWindowMenuGroup(String)`.
    fn set_window_menu_group(&mut self, _group: &str) {}

    /// The context type class name this provider supports.
    ///
    /// Port of Ghidra's `ComponentProvider.getContextType()`.
    fn context_type(&self) -> Option<&str> {
        None
    }

    // -- Focus --

    /// Whether this provider is the currently focused provider.
    ///
    /// Port of Ghidra's `ComponentProvider.isFocusedProvider()`.
    fn is_focused_provider(&self) -> bool {
        false
    }

    /// Request focus for this provider.
    ///
    /// Port of Ghidra's `ComponentProvider.requestFocus()`.
    fn request_focus(&self) {}

    /// Whether the provider is currently showing (visible and displayable).
    ///
    /// Port of Ghidra's `ComponentProvider.isShowing()`.
    fn is_showing(&self) -> bool {
        self.is_visible()
    }

    /// Whether this provider is the active provider.
    ///
    /// Port of Ghidra's `ComponentProvider.isActive()`.
    fn is_active(&self) -> bool {
        false
    }

    /// Notify the provider that its component has been made displayable.
    ///
    /// Port of Ghidra's `ComponentProvider.componentMadeDisplayable()`.
    fn component_made_displayable(&self) {}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::component::{ComponentProvider as ProviderType, SimpleComponent};

    // Test that SimpleComponent (from component.rs) doesn't conflict
    // with the new trait name.  The trait is in this module; the enum
    // is in component.rs.

    #[test]
    fn test_component_provider_trait_object() {
        // SimpleComponent implements DockingComponent and ComponentProviderInfo
        // but not the new ComponentProvider trait.  We test that the trait
        // compiles and can be used as a trait object.
        let _: Option<Box<dyn ComponentProvider>> = None;
    }

    #[test]
    fn test_full_title() {
        // Verify the default full_title logic.
        // We can't easily construct a concrete impl here without a
        // struct, so test the logic via a mock.
        #[derive(Debug)]
        struct MockProvider {
            title: String,
            sub: String,
        }
        impl ComponentProvider for MockProvider {
            fn name(&self) -> &str { "mock" }
            fn window_title(&self) -> &str { &self.title }
            fn sub_title(&self) -> &str { &self.sub }
            fn is_visible(&self) -> bool { true }
            fn show(&mut self) {}
            fn hide(&mut self) {}
            fn instance_key(&self) -> (ProviderType, String) {
                (ProviderType::Console, "mock".to_owned())
            }
            fn provider_type(&self) -> ProviderType { ProviderType::Console }
        }

        let p = MockProvider { title: "Console".into(), sub: "".into() };
        assert_eq!(p.full_title(), "Console");

        let p = MockProvider { title: "Console".into(), sub: "test.exe".into() };
        assert_eq!(p.full_title(), "Console - test.exe");
    }

    #[test]
    fn test_provider_trait_defaults() {
        #[derive(Debug)]
        struct MockProvider;
        impl ComponentProvider for MockProvider {
            fn name(&self) -> &str { "mock" }
            fn window_title(&self) -> &str { "Mock" }
            fn is_visible(&self) -> bool { false }
            fn show(&mut self) {}
            fn hide(&mut self) {}
            fn instance_key(&self) -> (ProviderType, String) {
                (ProviderType::Console, "mock".to_owned())
            }
            fn provider_type(&self) -> ProviderType { ProviderType::Console }
        }

        let p = MockProvider;
        assert_eq!(p.default_position(), WindowPosition::Center);
        assert_eq!(p.default_size(), (400.0, 300.0));
        assert_eq!(p.window_menu_group(), "Views");
        assert_eq!(p.window_menu_priority(), 100);
        assert!(p.supports_temporary_window());
        assert!(!p.manages_own_focus());
        assert!(!p.has_context_menu());
        assert!(!p.is_default_provider());
        assert!(p.help_location().is_none());
        assert!(p.closeable());
    }

    #[test]
    fn test_provider_toggle() {
        #[derive(Debug)]
        struct MockProvider { visible: bool }
        impl ComponentProvider for MockProvider {
            fn name(&self) -> &str { "mock" }
            fn window_title(&self) -> &str { "Mock" }
            fn is_visible(&self) -> bool { self.visible }
            fn show(&mut self) { self.visible = true; }
            fn hide(&mut self) { self.visible = false; }
            fn instance_key(&self) -> (ProviderType, String) {
                (ProviderType::Console, "mock".to_owned())
            }
            fn provider_type(&self) -> ProviderType { ProviderType::Console }
        }

        let mut p = MockProvider { visible: false };
        assert!(!p.is_visible());
        p.toggle();
        assert!(p.is_visible());
        p.toggle();
        assert!(!p.is_visible());
    }

    #[test]
    fn test_provider_new_defaults() {
        #[derive(Debug)]
        struct MockProvider;
        impl ComponentProvider for MockProvider {
            fn name(&self) -> &str { "mock" }
            fn window_title(&self) -> &str { "Mock" }
            fn is_visible(&self) -> bool { false }
            fn show(&mut self) {}
            fn hide(&mut self) {}
            fn instance_key(&self) -> (ProviderType, String) {
                (ProviderType::Console, "mock".to_owned())
            }
            fn provider_type(&self) -> ProviderType { ProviderType::Console }
        }

        let p = MockProvider;
        // New defaults for the Java-migrated methods.
        assert!(!p.is_transient());
        assert_eq!(p.window_group(), "Default");
        assert!(p.window_sub_menu_name().is_none());
        assert!(p.can_be_parent());
        assert!(!p.is_snapshot());
        assert!(p.sub_title().is_empty());
        assert_eq!(p.tab_text(), "Mock");
    }

    #[test]
    fn test_provider_set_visible() {
        #[derive(Debug)]
        struct MockProvider { visible: bool }
        impl ComponentProvider for MockProvider {
            fn name(&self) -> &str { "mock" }
            fn window_title(&self) -> &str { "Mock" }
            fn is_visible(&self) -> bool { self.visible }
            fn show(&mut self) { self.visible = true; }
            fn hide(&mut self) { self.visible = false; }
            fn instance_key(&self) -> (ProviderType, String) {
                (ProviderType::Console, "mock".to_owned())
            }
            fn provider_type(&self) -> ProviderType { ProviderType::Console }
        }

        let mut p = MockProvider { visible: false };
        p.set_visible(true);
        assert!(p.is_visible());
        p.set_visible(false);
        assert!(!p.is_visible());
    }
}
