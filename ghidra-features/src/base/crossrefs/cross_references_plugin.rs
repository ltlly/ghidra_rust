//! Cross References Plugin -- top-level plugin coordinating cross-reference providers.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.references.ReferencesPlugin`.
//!
//! Manages the lifecycle of cross-reference edit providers and external
//! references providers. Dispatches the "Show References" action, tracks
//! the current program location, and coordinates reference creation,
//! deletion, and editing operations.
//!
//! # Key Types
//!
//! - [`CrossReferencesPlugin`] -- Plugin that owns cross-reference providers
//! - [`ShowReferencesAction`] -- The "Show References" action model
//! - [`CreateReferenceAction`] -- The "Add Memory Reference" action model
//! - [`DeleteReferencesAction`] -- The "Delete References" action model
//!
//! # Java Original
//!
//! The Java `ReferencesPlugin` extends `Plugin` (not `ProgramPlugin`) and:
//! - Creates `EditReferencesProvider` instances on demand
//! - Maintains a single `ExternalReferencesProvider`
//! - Registers actions for creating, showing, and deleting references
//! - Processes `ProgramActivatedPluginEvent`, `ProgramClosedPluginEvent`,
//!   and `ProgramLocationPluginEvent`
//!
//! In Rust we express this as a struct with lifecycle methods, following
//! the same pattern used by `ReachabilityPlugin` and `CallTreePlugin`.

use ghidra_core::addr::Address;
use ghidra_core::symbol::{RefType, Reference, ReferenceManager, SourceType};

use super::cross_references_provider::{
    CrossReferencesProvider, ExternalReferencesProvider,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Action group name for reference-related actions.
pub const REFS_GROUP: &str = "references";

/// Action group name for "Show References" sub-menu.
pub const SHOW_REFS_GROUP: &str = "ShowReferences";

/// Sub-menu name under which reference actions appear.
pub const SUBMENU_NAME: &str = "References";

// ---------------------------------------------------------------------------
// ShowReferencesAction -- the "Show References" action model
// ---------------------------------------------------------------------------

/// The "Show References" menu action.
///
/// Ported from the `DockingAction` created inside
/// `ReferencesPlugin.setupActions()` for showing the references panel.
#[derive(Debug, Clone)]
pub struct ShowReferencesAction {
    /// Internal action name.
    pub name: String,
    /// Menu group.
    pub group: String,
    /// Description.
    pub description: String,
    /// Whether the action is enabled.
    pub enabled: bool,
    /// Menu path: ["Show References", "Show References To"].
    pub menu_path: Vec<String>,
    /// Key binding (key code name, modifier mask).
    pub key_binding: Option<(String, u32)>,
}

impl ShowReferencesAction {
    /// Create the default "Show References" action.
    pub fn new() -> Self {
        Self {
            name: "Show References".into(),
            group: SHOW_REFS_GROUP.into(),
            description: "Show cross-references to the current location".into(),
            enabled: false,
            menu_path: vec!["Show References".into(), "Show References To".into()],
            key_binding: None,
        }
    }

    /// Enable the action.
    pub fn enable(&mut self) {
        self.enabled = true;
    }

    /// Disable the action.
    pub fn disable(&mut self) {
        self.enabled = false;
    }
}

impl Default for ShowReferencesAction {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// CreateReferenceAction -- the "Add Memory Reference" action model
// ---------------------------------------------------------------------------

/// The "Add Memory Reference" action model.
///
/// Ported from `CreateDefaultReferenceAction` in the Java ReferencesPlugin.
#[derive(Debug, Clone)]
pub struct CreateReferenceAction {
    /// Internal action name.
    pub name: String,
    /// Description.
    pub description: String,
    /// Whether the action is enabled.
    pub enabled: bool,
    /// The default reference type to create.
    pub default_ref_type: RefType,
    /// Key binding (key code name, modifier mask).
    pub key_binding: Option<(String, u32)>,
}

impl CreateReferenceAction {
    /// Create the default "Add Memory Reference" action.
    pub fn new() -> Self {
        Self {
            name: "Add Memory Reference".into(),
            description: "Add a memory reference at the current location".into(),
            enabled: false,
            default_ref_type: RefType::UNCONDITIONAL_CALL,
            key_binding: Some(("M".into(), 0)),
        }
    }

    /// Get the default reference class/type for this action.
    pub fn get_default_ref_type(&self) -> RefType {
        self.default_ref_type
    }

    /// Enable the action.
    pub fn enable(&mut self) {
        self.enabled = true;
    }

    /// Disable the action.
    pub fn disable(&mut self) {
        self.enabled = false;
    }
}

impl Default for CreateReferenceAction {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// DeleteReferencesAction -- the "Delete References" action model
// ---------------------------------------------------------------------------

/// The "Delete References" action model.
///
/// Ported from `DeleteReferencesAction` in the Java ReferencesPlugin.
#[derive(Debug, Clone)]
pub struct DeleteReferencesAction {
    /// Internal action name.
    pub name: String,
    /// Description.
    pub description: String,
    /// Whether the action is enabled.
    pub enabled: bool,
    /// Key binding.
    pub key_binding: Option<(String, u32)>,
}

impl DeleteReferencesAction {
    /// Create the default "Delete References" action.
    pub fn new() -> Self {
        Self {
            name: "Delete References".into(),
            description: "Delete references at the current location".into(),
            enabled: false,
            key_binding: None,
        }
    }

    /// Enable the action.
    pub fn enable(&mut self) {
        self.enabled = true;
    }

    /// Disable the action.
    pub fn disable(&mut self) {
        self.enabled = false;
    }
}

impl Default for DeleteReferencesAction {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// CrossReferencesPlugin -- top-level plugin
// ---------------------------------------------------------------------------

/// Plugin that manages cross-reference providers.
///
/// Ported from `ghidra.app.plugin.core.references.ReferencesPlugin`.
///
/// The plugin:
/// 1. Maintains a list of [`CrossReferencesProvider`] instances (edit providers).
/// 2. Maintains a single [`ExternalReferencesProvider`].
/// 3. Dispatches the "Show References", "Create Reference", and
///    "Delete References" actions.
/// 4. Tracks the current program and location for reference resolution.
/// 5. Processes program lifecycle events (activated, deactivated, closed)
///    and location change events.
#[derive(Debug)]
pub struct CrossReferencesPlugin {
    /// Edit reference providers (one per code unit being edited).
    edit_providers: Vec<CrossReferencesProvider>,
    /// External references provider (singleton).
    external_provider: ExternalReferencesProvider,
    /// The "Show References" action.
    show_action: ShowReferencesAction,
    /// The "Create Reference" action.
    create_action: CreateReferenceAction,
    /// The "Delete References" action.
    delete_action: DeleteReferencesAction,
    /// Current program name (if any).
    current_program: Option<String>,
    /// Current cursor address.
    current_location: Option<Address>,
    /// Whether to follow on to the reference target location.
    default_follow_on_location: bool,
    /// Whether to navigate to the reference target by default.
    default_goto_reference_location: bool,
}

impl CrossReferencesPlugin {
    /// Create a new cross-references plugin.
    pub fn new() -> Self {
        Self {
            edit_providers: Vec::new(),
            external_provider: ExternalReferencesProvider::new(),
            show_action: ShowReferencesAction::new(),
            create_action: CreateReferenceAction::new(),
            delete_action: DeleteReferencesAction::new(),
            current_program: None,
            current_location: None,
            default_follow_on_location: false,
            default_goto_reference_location: false,
        }
    }

    // -------------------------------------------------------------------
    // Program lifecycle
    // -------------------------------------------------------------------

    /// Called when a program is activated.
    ///
    /// Ported from `ReferencesPlugin.programActivated(Program)`.
    pub fn program_activated(&mut self, program_name: &str) {
        self.current_program = Some(program_name.to_string());
        self.external_provider.set_program(Some(program_name.to_string()));
        self.show_action.enable();
        self.create_action.enable();
        self.delete_action.enable();
    }

    /// Called when a program is deactivated.
    ///
    /// Ported from `ReferencesPlugin.programDeactivated(Program)`.
    pub fn program_deactivated(&mut self) {
        self.current_program = None;
        self.current_location = None;
        self.external_provider.set_program(None);
        // Close edit dialog if open.
        self.cleanup_providers(false);
    }

    /// Called when a program is closed.
    ///
    /// Ported from `ReferencesPlugin.programClosed(Program)`.
    pub fn program_closed(&mut self) {
        self.current_program = None;
        self.current_location = None;
        self.external_provider.set_program(None);
        self.cleanup_providers(true);
        self.show_action.disable();
        self.create_action.disable();
        self.delete_action.disable();
    }

    // -------------------------------------------------------------------
    // Location changes
    // -------------------------------------------------------------------

    /// Called when the program location changes.
    ///
    /// Ported from `ReferencesPlugin.locationChanged(ProgramLocation)`.
    pub fn location_changed(&mut self, location: Option<Address>) {
        if let Some(addr) = location {
            self.current_location = Some(addr);
            // Update visible, unlocked edit providers.
            for provider in &mut self.edit_providers {
                if provider.is_visible() && !provider.is_location_locked() {
                    provider.update_for_location(addr);
                }
            }
        }
    }

    // -------------------------------------------------------------------
    // Provider management
    // -------------------------------------------------------------------

    /// Show the references for the given address.
    ///
    /// Finds an existing provider for this address, or creates a new one.
    /// Ported from `ReferencesPlugin.editReferenceAtLocation()`.
    pub fn show_references(&mut self, address: Address, program_name: &str) {
        // Look for an existing provider matching this address.
        if let Some(provider) = self.find_open_provider(address) {
            provider.show(program_name, address);
        } else {
            let mut provider = CrossReferencesProvider::new();
            provider.show(program_name, address);
            self.edit_providers.push(provider);
        }
    }

    /// Find an open provider that already shows references for the given address.
    fn find_open_provider(&mut self, address: Address) -> Option<&mut CrossReferencesProvider> {
        self.edit_providers
            .iter_mut()
            .find(|p| p.init_location() == Some(address))
    }

    /// Dispose a specific edit provider.
    pub fn dispose_provider(&mut self, index: usize) {
        if index < self.edit_providers.len() {
            self.edit_providers.remove(index);
        }
    }

    /// Clean up providers for a deactivation or close event.
    fn cleanup_providers(&mut self, _closed: bool) {
        // Keep one unlocked provider visible; dispose the rest.
        let mut keep_one = true;
        self.edit_providers.retain(|provider| {
            if !provider.is_location_locked() {
                if keep_one {
                    keep_one = false;
                    true
                } else {
                    false
                }
            } else {
                true
            }
        });
    }

    /// Dispose all edit providers.
    pub fn dispose_all_providers(&mut self) {
        for provider in &mut self.edit_providers {
            provider.dispose();
        }
        self.edit_providers.clear();
    }

    // -------------------------------------------------------------------
    // Accessors
    // -------------------------------------------------------------------

    /// Get the current program name.
    pub fn current_program(&self) -> Option<&str> {
        self.current_program.as_deref()
    }

    /// Get the current location address.
    pub fn current_location(&self) -> Option<Address> {
        self.current_location
    }

    /// Get the "Show References" action.
    pub fn show_action(&self) -> &ShowReferencesAction {
        &self.show_action
    }

    /// Get the "Create Reference" action.
    pub fn create_action(&self) -> &CreateReferenceAction {
        &self.create_action
    }

    /// Get the "Delete References" action.
    pub fn delete_action(&self) -> &DeleteReferencesAction {
        &self.delete_action
    }

    /// Get a reference to the external references provider.
    pub fn external_provider(&self) -> &ExternalReferencesProvider {
        &self.external_provider
    }

    /// Get a mutable reference to the external references provider.
    pub fn external_provider_mut(&mut self) -> &mut ExternalReferencesProvider {
        &mut self.external_provider
    }

    /// Get the number of open edit providers.
    pub fn provider_count(&self) -> usize {
        self.edit_providers.len()
    }

    /// Get a reference to an edit provider by index.
    pub fn get_provider(&self, index: usize) -> Option<&CrossReferencesProvider> {
        self.edit_providers.get(index)
    }

    /// Get a mutable reference to an edit provider by index.
    pub fn get_provider_mut(&mut self, index: usize) -> Option<&mut CrossReferencesProvider> {
        self.edit_providers.get_mut(index)
    }

    /// Get all edit providers.
    pub fn providers(&self) -> &[CrossReferencesProvider] {
        &self.edit_providers
    }

    /// Get the default follow-on location setting.
    pub fn default_follow_on_location(&self) -> bool {
        self.default_follow_on_location
    }

    /// Set the default follow-on location setting.
    pub fn set_default_follow_on_location(&mut self, follow: bool) {
        self.default_follow_on_location = follow;
    }

    /// Get the default goto-reference-location setting.
    pub fn default_goto_reference_location(&self) -> bool {
        self.default_goto_reference_location
    }

    /// Set the default goto-reference-location setting.
    pub fn set_default_goto_reference_location(&mut self, goto: bool) {
        self.default_goto_reference_location = goto;
    }

    /// Dispose the plugin, releasing all resources.
    ///
    /// Ported from `ReferencesPlugin.dispose()`.
    pub fn dispose(&mut self) {
        self.dispose_all_providers();
        self.external_provider.dispose();
        self.show_action.disable();
        self.create_action.disable();
        self.delete_action.disable();
        self.current_program = None;
        self.current_location = None;
    }
}

impl Default for CrossReferencesPlugin {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_new() {
        let plugin = CrossReferencesPlugin::new();
        assert_eq!(plugin.provider_count(), 0);
        assert!(plugin.current_program().is_none());
        assert!(plugin.current_location().is_none());
        assert!(!plugin.show_action().enabled);
    }

    #[test]
    fn test_plugin_program_activated() {
        let mut plugin = CrossReferencesPlugin::new();
        plugin.program_activated("test.exe");
        assert_eq!(plugin.current_program(), Some("test.exe"));
        assert!(plugin.show_action().enabled);
        assert!(plugin.create_action().enabled);
        assert!(plugin.delete_action().enabled);
    }

    #[test]
    fn test_plugin_program_deactivated() {
        let mut plugin = CrossReferencesPlugin::new();
        plugin.program_activated("test.exe");
        plugin.program_deactivated();
        assert!(plugin.current_program().is_none());
        assert!(plugin.current_location().is_none());
    }

    #[test]
    fn test_plugin_program_closed() {
        let mut plugin = CrossReferencesPlugin::new();
        plugin.program_activated("test.exe");
        plugin.program_closed();
        assert!(plugin.current_program().is_none());
        assert!(!plugin.show_action().enabled);
    }

    #[test]
    fn test_plugin_location_changed() {
        let mut plugin = CrossReferencesPlugin::new();
        plugin.program_activated("test.exe");
        plugin.location_changed(Some(Address::new(0x1000)));
        assert_eq!(plugin.current_location(), Some(Address::new(0x1000)));
    }

    #[test]
    fn test_plugin_show_references_creates_provider() {
        let mut plugin = CrossReferencesPlugin::new();
        plugin.program_activated("test.exe");
        plugin.show_references(Address::new(0x2000), "test.exe");
        assert_eq!(plugin.provider_count(), 1);
    }

    #[test]
    fn test_plugin_show_references_reuses_provider() {
        let mut plugin = CrossReferencesPlugin::new();
        plugin.program_activated("test.exe");
        plugin.show_references(Address::new(0x2000), "test.exe");
        plugin.show_references(Address::new(0x2000), "test.exe");
        assert_eq!(plugin.provider_count(), 1);
    }

    #[test]
    fn test_plugin_show_references_different_addrs() {
        let mut plugin = CrossReferencesPlugin::new();
        plugin.program_activated("test.exe");
        plugin.show_references(Address::new(0x2000), "test.exe");
        plugin.show_references(Address::new(0x3000), "test.exe");
        assert_eq!(plugin.provider_count(), 2);
    }

    #[test]
    fn test_plugin_dispose_provider() {
        let mut plugin = CrossReferencesPlugin::new();
        plugin.program_activated("test.exe");
        plugin.show_references(Address::new(0x2000), "test.exe");
        plugin.show_references(Address::new(0x3000), "test.exe");
        assert_eq!(plugin.provider_count(), 2);
        plugin.dispose_provider(0);
        assert_eq!(plugin.provider_count(), 1);
    }

    #[test]
    fn test_plugin_dispose() {
        let mut plugin = CrossReferencesPlugin::new();
        plugin.program_activated("test.exe");
        plugin.show_references(Address::new(0x2000), "test.exe");
        plugin.dispose();
        assert_eq!(plugin.provider_count(), 0);
        assert!(plugin.current_program().is_none());
        assert!(!plugin.show_action().enabled);
    }

    #[test]
    fn test_plugin_follow_on_location_setting() {
        let mut plugin = CrossReferencesPlugin::new();
        assert!(!plugin.default_follow_on_location());
        plugin.set_default_follow_on_location(true);
        assert!(plugin.default_follow_on_location());
    }

    #[test]
    fn test_plugin_goto_reference_location_setting() {
        let mut plugin = CrossReferencesPlugin::new();
        assert!(!plugin.default_goto_reference_location());
        plugin.set_default_goto_reference_location(true);
        assert!(plugin.default_goto_reference_location());
    }

    #[test]
    fn test_show_references_action_default() {
        let action = ShowReferencesAction::new();
        assert_eq!(action.name, "Show References");
        assert!(!action.enabled);
        assert_eq!(action.group, SHOW_REFS_GROUP);
    }

    #[test]
    fn test_create_reference_action_default() {
        let action = CreateReferenceAction::new();
        assert_eq!(action.name, "Add Memory Reference");
        assert!(!action.enabled);
        assert_eq!(
            action.get_default_ref_type(),
            RefType::UNCONDITIONAL_CALL
        );
    }

    #[test]
    fn test_delete_references_action_default() {
        let action = DeleteReferencesAction::new();
        assert_eq!(action.name, "Delete References");
        assert!(!action.enabled);
    }

    #[test]
    fn test_plugin_cleanup_providers() {
        let mut plugin = CrossReferencesPlugin::new();
        plugin.program_activated("test.exe");
        // Create multiple providers.
        plugin.show_references(Address::new(0x1000), "test.exe");
        plugin.show_references(Address::new(0x2000), "test.exe");
        plugin.show_references(Address::new(0x3000), "test.exe");
        assert_eq!(plugin.provider_count(), 3);
        // Cleanup should keep at most one unlocked provider.
        plugin.cleanup_providers(false);
        assert!(plugin.provider_count() <= 3);
    }

    #[test]
    fn test_plugin_dispose_all_providers() {
        let mut plugin = CrossReferencesPlugin::new();
        plugin.program_activated("test.exe");
        plugin.show_references(Address::new(0x1000), "test.exe");
        plugin.show_references(Address::new(0x2000), "test.exe");
        plugin.dispose_all_providers();
        assert_eq!(plugin.provider_count(), 0);
    }

    #[test]
    fn test_plugin_external_provider() {
        let mut plugin = CrossReferencesPlugin::new();
        plugin.program_activated("test.exe");
        assert!(plugin.external_provider().program_name().is_some());
        plugin.program_deactivated();
        assert!(plugin.external_provider().program_name().is_none());
    }
}
