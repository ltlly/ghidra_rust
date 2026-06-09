//! Clipboard Plugin -- main plugin struct and lifecycle.
//!
//! Ported from `ghidra.app.plugin.core.clipboard.ClipboardPlugin`.
//!
//! The `ClipboardPlugin` is the central orchestrator for the clipboard subsystem.
//! It manages content provider registration, action creation (copy, paste,
//! copy special, copy special again), the `remove_quotes` option, and
//! clipboard ownership tracking.
//!
//! # Architecture
//!
//! ```text
//! ClipboardPlugin
//!   |-- providers              (registered ClipboardContentProviderService instances)
//!   |-- service_action_map     (provider -> actions mapping)
//!   |-- last_copy_special_type (per-provider last used ClipboardType)
//!   |-- clipboard_owner        (which provider currently owns the clipboard)
//!   |-- remove_quotes          (option: strip quotes from copied strings)
//!   |-- copy()                 (default copy via active provider)
//!   |-- paste()                (default paste via active provider)
//!   `-- copy_special()         (copy with a specific ClipboardType)
//! ```

use std::collections::HashMap;

use super::{ClipboardEntry, ClipboardFormat};
use super::clipboard_service::ClipboardContentProviderService;
use super::service::ClipboardType;

// ---------------------------------------------------------------------------
// ActionKind -- the kinds of clipboard actions
// ---------------------------------------------------------------------------

/// The kind of clipboard action that can be registered.
///
/// Ported from the inner action classes in `ClipboardPlugin.java`:
/// `CopyAction`, `PasteAction`, `CopySpecialAction`, `CopySpecialAgainAction`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ActionKind {
    /// Default copy action (Ctrl+C).
    Copy,
    /// Default paste action (Ctrl+V).
    Paste,
    /// Copy special -- prompts for a format.
    CopySpecial,
    /// Copy special again -- repeats last used format.
    CopySpecialAgain,
}

impl ActionKind {
    /// Display name for this action.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Copy => "Copy",
            Self::Paste => "Paste",
            Self::CopySpecial => "Copy Special...",
            Self::CopySpecialAgain => "Copy Special Again",
        }
    }

    /// The menu group for clipboard actions.
    pub const MENU_GROUP: &'static str = "Clipboard";

    /// The default key binding description (platform-independent).
    pub fn key_binding_hint(&self) -> &'static str {
        match self {
            Self::Copy => "Ctrl+C",
            Self::Paste => "Ctrl+V",
            Self::CopySpecial => "",
            Self::CopySpecialAgain => "",
        }
    }
}

// ---------------------------------------------------------------------------
// ClipboardAction -- a registered clipboard action
// ---------------------------------------------------------------------------

/// A clipboard action bound to a content provider.
///
/// Ported from the `DockingAction` subclasses in `ClipboardPlugin.java`.
#[derive(Debug, Clone)]
pub struct ClipboardAction {
    /// The kind of action.
    pub kind: ActionKind,
    /// The provider this action is associated with.
    pub provider_id: String,
    /// Whether this action is currently enabled.
    pub enabled: bool,
    /// The menu path for popup menus.
    pub menu_path: Vec<String>,
    /// Optional owner override (for custom keybinding groups).
    pub action_owner: Option<String>,
}

impl ClipboardAction {
    /// Create a new clipboard action.
    pub fn new(kind: ActionKind, provider_id: impl Into<String>) -> Self {
        let provider_id = provider_id.into();
        let menu_path = vec![
            ActionKind::MENU_GROUP.to_string(),
            kind.display_name().to_string(),
        ];
        Self {
            kind,
            provider_id,
            enabled: false,
            menu_path,
            action_owner: None,
        }
    }

    /// Create a copy special again action with a dynamic menu label.
    pub fn copy_special_again(provider_id: impl Into<String>, last_type_name: &str) -> Self {
        let provider_id = provider_id.into();
        let menu_path = vec![
            ActionKind::MENU_GROUP.to_string(),
            format!("Copy \"{}\"", last_type_name),
        ];
        Self {
            kind: ActionKind::CopySpecialAgain,
            provider_id,
            enabled: false,
            menu_path,
            action_owner: None,
        }
    }
}

// ---------------------------------------------------------------------------
// ClipboardPluginOptions -- plugin-level configuration
// ---------------------------------------------------------------------------

/// Plugin-level options for the clipboard subsystem.
///
/// Ported from the options management in `ClipboardPlugin.java`.
#[derive(Debug, Clone)]
pub struct ClipboardPluginOptions {
    /// Whether copying strings should remove outer quotes.
    ///
    /// Ported from `ClipboardPlugin.REMOVE_QUOTES_OPTION`.
    pub remove_quotes: bool,
}

impl Default for ClipboardPluginOptions {
    fn default() -> Self {
        Self {
            remove_quotes: false,
        }
    }
}

impl ClipboardPluginOptions {
    /// Create new clipboard plugin options.
    pub fn new() -> Self {
        Self::default()
    }
}

// ---------------------------------------------------------------------------
// ProviderState -- internal state for a registered provider
// ---------------------------------------------------------------------------

/// Internal state for a registered clipboard content provider.
#[derive(Debug)]
struct ProviderState {
    /// The actions created for this provider.
    actions: Vec<ClipboardAction>,
    /// The last copy-special type used for this provider.
    last_copy_special_type: Option<ClipboardType>,
    /// Whether this provider can copy.
    can_copy: bool,
    /// Whether this provider can paste.
    can_paste: bool,
}

// ---------------------------------------------------------------------------
// ClipboardPlugin -- the main plugin struct
// ---------------------------------------------------------------------------

/// The clipboard plugin manages copy/paste operations across multiple
/// content providers.
///
/// Ported from `ghidra.app.plugin.core.clipboard.ClipboardPlugin`.
///
/// # Lifecycle
///
/// 1. [`ClipboardPlugin::new`] -- creates the plugin with default options.
/// 2. Register content providers via [`register_provider`](ClipboardPlugin::register_provider).
/// 3. Use [`copy`](ClipboardPlugin::copy), [`paste`](ClipboardPlugin::paste),
///    [`copy_special`](ClipboardPlugin::copy_special) to perform operations.
/// 4. [`dispose`](ClipboardPlugin::dispose) cleans up resources.
///
/// # Actions
///
/// - **Copy** -- copies from the active provider (Ctrl+C).
/// - **Paste** -- pastes into the active provider (Ctrl+V).
/// - **Copy Special** -- copies with a selected format, prompting for format.
/// - **Copy Special Again** -- repeats the last copy-special format.
///
/// # Options
///
/// - `remove_quotes` -- when true, outer quotes are stripped from copied strings.
#[derive(Debug)]
pub struct ClipboardPlugin {
    /// The plugin name.
    name: String,
    /// Registered provider states, keyed by provider ID.
    providers: HashMap<String, ProviderState>,
    /// The provider ID that currently owns the clipboard content.
    clipboard_owner: Option<String>,
    /// Plugin options.
    options: ClipboardPluginOptions,
    /// Clipboard history (most recent last).
    history: Vec<ClipboardEntry>,
    /// Maximum history size.
    max_history: usize,
    /// Whether the plugin has been disposed.
    disposed: bool,
}

impl ClipboardPlugin {
    /// The default plugin name.
    pub const PLUGIN_NAME: &'static str = "ClipboardPlugin";

    /// The option key for remove-quotes.
    pub const REMOVE_QUOTES_OPTION: &'static str = "Copy Strings Without Quotes";

    /// Create a new clipboard plugin.
    pub fn new() -> Self {
        Self {
            name: Self::PLUGIN_NAME.to_string(),
            providers: HashMap::new(),
            clipboard_owner: None,
            options: ClipboardPluginOptions::default(),
            history: Vec::new(),
            max_history: 32,
            disposed: false,
        }
    }

    /// Get the plugin name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Whether the plugin has been disposed.
    pub fn is_disposed(&self) -> bool {
        self.disposed
    }

    /// Dispose the plugin, releasing all resources.
    ///
    /// Ported from `ClipboardPlugin.dispose()`.
    pub fn dispose(&mut self) {
        self.providers.clear();
        self.clipboard_owner = None;
        self.history.clear();
        self.disposed = true;
    }

    // -- Options --

    /// Get the current plugin options.
    pub fn options(&self) -> &ClipboardPluginOptions {
        &self.options
    }

    /// Get a mutable reference to the plugin options.
    pub fn options_mut(&mut self) -> &mut ClipboardPluginOptions {
        &mut self.options
    }

    /// Whether the remove-quotes option is enabled.
    pub fn remove_quotes(&self) -> bool {
        self.options.remove_quotes
    }

    /// Set the remove-quotes option.
    pub fn set_remove_quotes(&mut self, remove: bool) {
        self.options.remove_quotes = remove;
    }

    /// Handle an options change event.
    ///
    /// Ported from `ClipboardPlugin.optionsChanged()`.
    pub fn options_changed(&mut self, option_name: &str, value: bool) {
        if option_name == Self::REMOVE_QUOTES_OPTION {
            self.set_remove_quotes(value);
        }
    }

    // -- Provider Registration --

    /// Register a clipboard content provider.
    ///
    /// Ported from `ClipboardPlugin.registerClipboardContentProvider()`.
    ///
    /// Creates the standard set of clipboard actions for the provider.
    pub fn register_provider(&mut self, provider: &dyn ClipboardContentProviderService) {
        let id = provider.provider_name().to_string();

        if self.providers.contains_key(&id) {
            return; // don't add actions twice
        }

        let can_copy = provider.can_copy();
        let can_paste = provider.can_paste();
        let actions = self.create_actions(provider);
        self.providers.insert(
            id,
            ProviderState {
                actions,
                last_copy_special_type: None,
                can_copy,
                can_paste,
            },
        );
    }

    /// Register a provider by ID with explicit capabilities.
    ///
    /// A simplified registration when the full provider object is not available.
    pub fn register_provider_by_id(
        &mut self,
        provider_id: impl Into<String>,
        can_copy: bool,
        can_copy_special: bool,
        can_paste: bool,
        _copy_types: Vec<ClipboardType>,
    ) {
        let id = provider_id.into();
        if self.providers.contains_key(&id) {
            return;
        }

        let mut actions = Vec::new();
        if can_copy {
            actions.push(ClipboardAction::new(ActionKind::Copy, &id));
        }
        if can_copy_special {
            actions.push(ClipboardAction::new(ActionKind::CopySpecial, &id));
            actions.push(ClipboardAction::copy_special_again(&id, "Last Format"));
        }
        if can_paste {
            actions.push(ClipboardAction::new(ActionKind::Paste, &id));
        }

        self.providers.insert(
            id,
            ProviderState {
                actions,
                last_copy_special_type: None,
                can_copy,
                can_paste,
            },
        );
    }

    /// De-register a clipboard content provider.
    ///
    /// Ported from `ClipboardPlugin.deRegisterClipboardContentProvider()`.
    pub fn deregister_provider(&mut self, provider_id: &str) {
        self.providers.remove(provider_id);

        if self.clipboard_owner.as_deref() == Some(provider_id) {
            self.clipboard_owner = None;
        }
    }

    /// Get the list of registered provider IDs.
    pub fn provider_ids(&self) -> Vec<&str> {
        self.providers.keys().map(|s| s.as_str()).collect()
    }

    /// Whether a provider is registered.
    pub fn has_provider(&self, provider_id: &str) -> bool {
        self.providers.contains_key(provider_id)
    }

    // -- Action Management --

    /// Create the standard clipboard actions for a provider.
    ///
    /// Ported from `ClipboardPlugin.createActions()`.
    fn create_actions(&self, provider: &dyn ClipboardContentProviderService) -> Vec<ClipboardAction> {
        let id = provider.provider_name();
        let mut actions = Vec::with_capacity(4);

        if provider.enable_copy() {
            actions.push(ClipboardAction::new(ActionKind::Copy, id));
        }
        if provider.enable_copy_special() {
            actions.push(ClipboardAction::new(ActionKind::CopySpecial, id));
            actions.push(ClipboardAction::copy_special_again(id, "Last Format"));
        }
        if provider.enable_paste() {
            actions.push(ClipboardAction::new(ActionKind::Paste, id));
        }

        actions
    }

    /// Get all actions for a given provider.
    pub fn actions_for_provider(&self, provider_id: &str) -> Option<&[ClipboardAction]> {
        self.providers
            .get(provider_id)
            .map(|state| state.actions.as_slice())
    }

    /// Get all registered actions across all providers.
    pub fn all_actions(&self) -> Vec<&ClipboardAction> {
        self.providers
            .values()
            .flat_map(|state| state.actions.iter())
            .collect()
    }

    /// Update the enabled state of copy actions based on provider capabilities.
    ///
    /// Ported from `ClipboardPlugin.updateCopyState()`.
    pub fn update_copy_state(&mut self, provider_id: &str, can_copy: bool) {
        if let Some(state) = self.providers.get_mut(provider_id) {
            state.can_copy = can_copy;
            for action in &mut state.actions {
                if matches!(action.kind, ActionKind::Copy | ActionKind::CopySpecial | ActionKind::CopySpecialAgain) {
                    action.enabled = can_copy;
                }
            }
        }
    }

    /// Update the enabled state of paste actions based on provider capabilities.
    ///
    /// Ported from `ClipboardPlugin.updatePasteState()`.
    pub fn update_paste_state(&mut self, provider_id: &str, can_paste: bool) {
        if let Some(state) = self.providers.get_mut(provider_id) {
            state.can_paste = can_paste;
            for action in &mut state.actions {
                if action.kind == ActionKind::Paste {
                    action.enabled = can_paste;
                }
            }
        }
    }

    // -- Core Operations --

    /// Perform a default copy from the given provider.
    ///
    /// Ported from `ClipboardPlugin.copy()`.
    ///
    /// Returns the entry that was copied, or `None` if the provider cannot copy.
    pub fn copy(
        &mut self,
        provider_id: &str,
        entry: ClipboardEntry,
    ) -> Option<ClipboardEntry> {
        let can_copy = self
            .providers
            .get(provider_id)
            .map(|s| s.can_copy)
            .unwrap_or(false);

        if !can_copy {
            return None;
        }

        // Notify previous owner of lost ownership
        if let Some(prev_owner) = self.clipboard_owner.take() {
            if prev_owner != provider_id {
                // Previous owner lost ownership -- no callback needed in Rust model
            }
        }

        self.clipboard_owner = Some(provider_id.to_string());

        // Apply remove_quotes option if applicable
        let mut entry = entry;
        if self.options.remove_quotes && entry.format == ClipboardFormat::Text {
            entry.text = remove_outer_quotes(&entry.text);
        }

        self.push_history(entry.clone());
        Some(entry)
    }

    /// Perform a paste into the given provider.
    ///
    /// Ported from `ClipboardPlugin.paste()`.
    ///
    /// Returns the entry that was pasted, or `None` if no content is available.
    pub fn paste(&self, provider_id: &str) -> Option<&ClipboardEntry> {
        let can_paste = self
            .providers
            .get(provider_id)
            .map(|s| s.can_paste)
            .unwrap_or(false);

        if !can_paste {
            return None;
        }
        self.history.last()
    }

    /// Perform a copy-special with a specific clipboard type.
    ///
    /// Ported from `ClipboardPlugin.copySpecial()`.
    ///
    /// Returns the entry that was copied, or `None` if unavailable.
    pub fn copy_special(
        &mut self,
        provider_id: &str,
        clipboard_type: ClipboardType,
        entry: ClipboardEntry,
    ) -> Option<ClipboardEntry> {
        let result = self.copy(provider_id, entry)?;

        // Record the last copy-special type for this provider
        if let Some(state) = self.providers.get_mut(provider_id) {
            state.last_copy_special_type = Some(clipboard_type);
        }

        Some(result)
    }

    /// Repeat the last copy-special operation for the given provider.
    ///
    /// Ported from `ClipboardPlugin.CopySpecialAgainAction`.
    ///
    /// Returns the last used `ClipboardType`, or `None` if none was recorded.
    pub fn last_copy_special_type(&self, provider_id: &str) -> Option<&ClipboardType> {
        self.providers
            .get(provider_id)
            .and_then(|state| state.last_copy_special_type.as_ref())
    }

    /// Update the copy special again action menu label with the last type name.
    ///
    /// Ported from `CopySpecialAgainAction.updateMenuName()`.
    pub fn update_copy_special_again_label(&mut self, provider_id: &str) {
        let type_name = self
            .providers
            .get(provider_id)
            .and_then(|state| state.last_copy_special_type.as_ref())
            .map(|ct| ct.display_name().to_string());

        if let Some(name) = type_name {
            if let Some(state) = self.providers.get_mut(provider_id) {
                for action in &mut state.actions {
                    if action.kind == ActionKind::CopySpecialAgain {
                        action.menu_path = vec![
                            ActionKind::MENU_GROUP.to_string(),
                            format!("Copy \"{}\"", name),
                        ];
                    }
                }
            }
        }
    }

    // -- Clipboard Ownership --

    /// Get the ID of the provider that currently owns the clipboard.
    pub fn clipboard_owner(&self) -> Option<&str> {
        self.clipboard_owner.as_deref()
    }

    /// Called when the plugin loses clipboard ownership.
    ///
    /// Ported from `ClipboardPlugin.lostOwnership()`.
    pub fn lost_ownership(&mut self) {
        self.clipboard_owner = None;
    }

    /// Clear the clipboard contents.
    ///
    /// Ported from `ClipboardPlugin.clearClipboardContents()`.
    pub fn clear_clipboard(&mut self) {
        self.history.clear();
        self.clipboard_owner = None;
    }

    // -- Provider Deactivation --

    /// Called when the current program is deactivated.
    ///
    /// Ported from `ClipboardPlugin.programDeactivated()`.
    pub fn program_deactivated(&mut self) {
        self.clipboard_owner = None;
    }

    // -- History --

    /// Get the clipboard history.
    pub fn history(&self) -> &[ClipboardEntry] {
        &self.history
    }

    /// Get the most recent clipboard entry.
    pub fn peek(&self) -> Option<&ClipboardEntry> {
        self.history.last()
    }

    /// Pop the most recent clipboard entry.
    pub fn pop(&mut self) -> Option<ClipboardEntry> {
        self.history.pop()
    }

    /// The number of entries in history.
    pub fn history_count(&self) -> usize {
        self.history.len()
    }

    /// The maximum history size.
    pub fn max_history(&self) -> usize {
        self.max_history
    }

    /// Push an entry to the history, evicting the oldest if at capacity.
    fn push_history(&mut self, entry: ClipboardEntry) {
        if self.history.len() >= self.max_history {
            self.history.remove(0);
        }
        self.history.push(entry);
    }
}

impl Default for ClipboardPlugin {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Remove outer quotes and standard string prefixes from text.
///
/// Ported from `StringTransferable.removeOuterQuotesAndStandardStringPrefix()`.
fn remove_outer_quotes(s: &str) -> String {
    let trimmed = s.trim();

    // Check for common string prefixes (which consume the opening quote)
    let (inner, prefix_consumed_quote) = if let Some(rest) = trimmed.strip_prefix("L\"") {
        (rest, true)
    } else if let Some(rest) = trimmed.strip_prefix("u\"") {
        (rest, true)
    } else if let Some(rest) = trimmed.strip_prefix("U\"") {
        (rest, true)
    } else if let Some(rest) = trimmed.strip_prefix("u8\"") {
        (rest, true)
    } else {
        (trimmed, false)
    };

    if prefix_consumed_quote {
        // Prefix consumed the opening quote; strip trailing quote
        inner.strip_suffix('"').unwrap_or(inner).to_string()
    } else if inner.starts_with('"') && inner.ends_with('"') && inner.len() >= 2 {
        inner[1..inner.len() - 1].to_string()
    } else if inner.starts_with('\'') && inner.ends_with('\'') && inner.len() >= 2 {
        inner[1..inner.len() - 1].to_string()
    } else {
        inner.to_string()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ghidra_core::Address;

    #[test]
    fn test_plugin_creation() {
        let plugin = ClipboardPlugin::new();
        assert_eq!(plugin.name(), "ClipboardPlugin");
        assert!(!plugin.is_disposed());
        assert!(!plugin.remove_quotes());
    }

    #[test]
    fn test_plugin_dispose() {
        let mut plugin = ClipboardPlugin::new();
        plugin.register_provider_by_id("test", true, true, true, vec![]);
        assert!(!plugin.provider_ids().is_empty());

        plugin.dispose();
        assert!(plugin.is_disposed());
        assert!(plugin.provider_ids().is_empty());
    }

    #[test]
    fn test_options() {
        let mut plugin = ClipboardPlugin::new();
        assert!(!plugin.options().remove_quotes);

        plugin.set_remove_quotes(true);
        assert!(plugin.remove_quotes());
    }

    #[test]
    fn test_options_changed() {
        let mut plugin = ClipboardPlugin::new();
        plugin.options_changed(ClipboardPlugin::REMOVE_QUOTES_OPTION, true);
        assert!(plugin.remove_quotes());

        // Unrelated option should not change
        plugin.options_changed("Other Option", false);
        assert!(plugin.remove_quotes());
    }

    #[test]
    fn test_register_and_deregister_provider() {
        let mut plugin = ClipboardPlugin::new();
        plugin.register_provider_by_id("Listing", true, true, true, vec![]);
        plugin.register_provider_by_id("Decompiler", true, false, true, vec![]);

        assert_eq!(plugin.provider_ids().len(), 2);
        assert!(plugin.has_provider("Listing"));
        assert!(plugin.has_provider("Decompiler"));

        plugin.deregister_provider("Listing");
        assert_eq!(plugin.provider_ids().len(), 1);
        assert!(!plugin.has_provider("Listing"));
        assert!(plugin.has_provider("Decompiler"));
    }

    #[test]
    fn test_duplicate_registration_ignored() {
        let mut plugin = ClipboardPlugin::new();
        plugin.register_provider_by_id("A", true, true, true, vec![]);
        plugin.register_provider_by_id("A", true, true, true, vec![]);
        assert_eq!(plugin.provider_ids().len(), 1);
    }

    #[test]
    fn test_actions_created() {
        let mut plugin = ClipboardPlugin::new();
        plugin.register_provider_by_id("Listing", true, true, true, vec![]);

        let actions = plugin.actions_for_provider("Listing").unwrap();
        assert_eq!(actions.len(), 4); // Copy, CopySpecial, CopySpecialAgain, Paste

        let kinds: Vec<ActionKind> = actions.iter().map(|a| a.kind).collect();
        assert!(kinds.contains(&ActionKind::Copy));
        assert!(kinds.contains(&ActionKind::Paste));
        assert!(kinds.contains(&ActionKind::CopySpecial));
        assert!(kinds.contains(&ActionKind::CopySpecialAgain));
    }

    #[test]
    fn test_actions_no_copy_special() {
        let mut plugin = ClipboardPlugin::new();
        plugin.register_provider_by_id("Simple", true, false, true, vec![]);

        let actions = plugin.actions_for_provider("Simple").unwrap();
        assert_eq!(actions.len(), 2); // Copy, Paste only

        let kinds: Vec<ActionKind> = actions.iter().map(|a| a.kind).collect();
        assert!(kinds.contains(&ActionKind::Copy));
        assert!(kinds.contains(&ActionKind::Paste));
        assert!(!kinds.contains(&ActionKind::CopySpecial));
    }

    #[test]
    fn test_copy() {
        let mut plugin = ClipboardPlugin::new();
        plugin.register_provider_by_id("test", true, true, true, vec![]);

        let entry = ClipboardEntry::from_bytes(
            Address::new(0x1000),
            Address::new(0x1003),
            vec![0x48, 0x89, 0xD8],
        );

        let result = plugin.copy("test", entry);
        assert!(result.is_some());
        assert_eq!(plugin.clipboard_owner(), Some("test"));
    }

    #[test]
    fn test_copy_disabled_provider() {
        let mut plugin = ClipboardPlugin::new();
        plugin.register_provider_by_id("test", false, false, false, vec![]);

        let entry = ClipboardEntry::from_bytes(
            Address::new(0x1000),
            Address::new(0x1003),
            vec![0x48, 0x89, 0xD8],
        );

        let result = plugin.copy("test", entry);
        assert!(result.is_none());
        assert!(plugin.clipboard_owner().is_none());
    }

    #[test]
    fn test_copy_unknown_provider() {
        let mut plugin = ClipboardPlugin::new();
        let entry = ClipboardEntry::from_bytes(
            Address::new(0x1000),
            Address::new(0x1003),
            vec![0x48],
        );

        let result = plugin.copy("nonexistent", entry);
        assert!(result.is_none());
    }

    #[test]
    fn test_copy_removes_quotes() {
        let mut plugin = ClipboardPlugin::new();
        plugin.set_remove_quotes(true);
        plugin.register_provider_by_id("test", true, true, true, vec![]);

        let entry = ClipboardEntry::from_text(
            Address::new(0x1000),
            Address::new(0x1000),
            "\"hello\"".to_string(),
        );

        let result = plugin.copy("test", entry).unwrap();
        assert_eq!(result.text, "hello");
    }

    #[test]
    fn test_paste() {
        let mut plugin = ClipboardPlugin::new();
        plugin.register_provider_by_id("test", true, true, true, vec![]);

        // Copy first
        let entry = ClipboardEntry::from_bytes(
            Address::new(0x1000),
            Address::new(0x1003),
            vec![0x48, 0x89, 0xD8],
        );
        plugin.copy("test", entry);

        // Now paste
        let pasted = plugin.paste("test");
        assert!(pasted.is_some());
        assert_eq!(pasted.unwrap().data, vec![0x48, 0x89, 0xD8]);
    }

    #[test]
    fn test_paste_no_content() {
        let mut plugin = ClipboardPlugin::new();
        plugin.register_provider_by_id("test", true, true, true, vec![]);
        // No content copied yet
        let pasted = plugin.paste("test");
        assert!(pasted.is_none());
    }

    #[test]
    fn test_copy_special() {
        let mut plugin = ClipboardPlugin::new();
        plugin.register_provider_by_id("test", true, true, true, vec![]);

        let entry = ClipboardEntry::from_bytes(
            Address::new(0x1000),
            Address::new(0x1003),
            vec![0x48, 0x89, 0xD8],
        );

        let byte_type = ClipboardType::Bytes;
        let result = plugin.copy_special("test", byte_type, entry);
        assert!(result.is_some());
        assert_eq!(plugin.clipboard_owner(), Some("test"));

        let last_type = plugin.last_copy_special_type("test");
        assert!(last_type.is_some());
        assert_eq!(last_type.unwrap().display_name(), "Bytes");
    }

    #[test]
    fn test_copy_special_again_label() {
        let mut plugin = ClipboardPlugin::new();
        plugin.register_provider_by_id("test", true, true, true, vec![]);

        let entry = ClipboardEntry::from_bytes(
            Address::new(0x1000),
            Address::new(0x1003),
            vec![0x48],
        );

        let hex_type = ClipboardType::ByteString;
        plugin.copy_special("test", hex_type, entry);
        plugin.update_copy_special_again_label("test");

        let actions = plugin.actions_for_provider("test").unwrap();
        let again_action = actions.iter().find(|a| a.kind == ActionKind::CopySpecialAgain).unwrap();
        assert_eq!(again_action.menu_path[1], "Copy \"Byte String\"");
    }

    #[test]
    fn test_update_copy_state() {
        let mut plugin = ClipboardPlugin::new();
        plugin.register_provider_by_id("test", true, true, true, vec![]);

        plugin.update_copy_state("test", false);
        let actions = plugin.actions_for_provider("test").unwrap();
        for action in actions {
            if matches!(action.kind, ActionKind::Copy | ActionKind::CopySpecial | ActionKind::CopySpecialAgain) {
                assert!(!action.enabled);
            }
        }
    }

    #[test]
    fn test_update_paste_state() {
        let mut plugin = ClipboardPlugin::new();
        plugin.register_provider_by_id("test", true, true, true, vec![]);

        plugin.update_paste_state("test", true);
        let actions = plugin.actions_for_provider("test").unwrap();
        let paste_action = actions.iter().find(|a| a.kind == ActionKind::Paste).unwrap();
        assert!(paste_action.enabled);

        plugin.update_paste_state("test", false);
        let actions = plugin.actions_for_provider("test").unwrap();
        let paste_action = actions.iter().find(|a| a.kind == ActionKind::Paste).unwrap();
        assert!(!paste_action.enabled);
    }

    #[test]
    fn test_lost_ownership() {
        let mut plugin = ClipboardPlugin::new();
        plugin.register_provider_by_id("p", true, true, true, vec![]);

        let entry = ClipboardEntry::from_bytes(
            Address::new(0x1000),
            Address::new(0x1003),
            vec![0x48],
        );
        plugin.copy("p", entry);
        assert_eq!(plugin.clipboard_owner(), Some("p"));

        plugin.lost_ownership();
        assert!(plugin.clipboard_owner().is_none());
    }

    #[test]
    fn test_clear_clipboard() {
        let mut plugin = ClipboardPlugin::new();
        plugin.register_provider_by_id("p", true, true, true, vec![]);

        let entry = ClipboardEntry::from_bytes(
            Address::new(0x1000),
            Address::new(0x1003),
            vec![0x48],
        );
        plugin.copy("p", entry);
        assert!(plugin.peek().is_some());

        plugin.clear_clipboard();
        assert!(plugin.peek().is_none());
        assert!(plugin.clipboard_owner().is_none());
    }

    #[test]
    fn test_program_deactivated() {
        let mut plugin = ClipboardPlugin::new();
        plugin.register_provider_by_id("p", true, true, true, vec![]);

        let entry = ClipboardEntry::from_bytes(
            Address::new(0x1000),
            Address::new(0x1003),
            vec![0x48],
        );
        plugin.copy("p", entry);

        plugin.program_deactivated();
        assert!(plugin.clipboard_owner().is_none());
    }

    #[test]
    fn test_deregister_clears_owner() {
        let mut plugin = ClipboardPlugin::new();
        plugin.register_provider_by_id("p", true, true, true, vec![]);

        let entry = ClipboardEntry::from_bytes(
            Address::new(0x1000),
            Address::new(0x1003),
            vec![0x48],
        );
        plugin.copy("p", entry);
        assert_eq!(plugin.clipboard_owner(), Some("p"));

        plugin.deregister_provider("p");
        assert!(plugin.clipboard_owner().is_none());
    }

    #[test]
    fn test_all_actions() {
        let mut plugin = ClipboardPlugin::new();
        plugin.register_provider_by_id("A", true, true, true, vec![]);
        plugin.register_provider_by_id("B", true, false, true, vec![]);

        let all = plugin.all_actions();
        // A: 4 actions, B: 2 actions
        assert_eq!(all.len(), 6);
    }

    #[test]
    fn test_action_kind_display() {
        assert_eq!(ActionKind::Copy.display_name(), "Copy");
        assert_eq!(ActionKind::Paste.display_name(), "Paste");
        assert_eq!(ActionKind::CopySpecial.display_name(), "Copy Special...");
        assert_eq!(
            ActionKind::CopySpecialAgain.display_name(),
            "Copy Special Again"
        );
    }

    #[test]
    fn test_action_kind_key_binding() {
        assert_eq!(ActionKind::Copy.key_binding_hint(), "Ctrl+C");
        assert_eq!(ActionKind::Paste.key_binding_hint(), "Ctrl+V");
        assert_eq!(ActionKind::CopySpecial.key_binding_hint(), "");
    }

    #[test]
    fn test_clipboard_action_new() {
        let action = ClipboardAction::new(ActionKind::Copy, "Listing");
        assert_eq!(action.kind, ActionKind::Copy);
        assert_eq!(action.provider_id, "Listing");
        assert!(!action.enabled);
        assert_eq!(action.menu_path, vec!["Clipboard", "Copy"]);
    }

    #[test]
    fn test_clipboard_action_copy_special_again() {
        let action = ClipboardAction::copy_special_again("Listing", "Hex String");
        assert_eq!(action.kind, ActionKind::CopySpecialAgain);
        assert_eq!(action.menu_path[1], "Copy \"Hex String\"");
    }

    #[test]
    fn test_remove_outer_quotes_double() {
        assert_eq!(remove_outer_quotes("\"hello\""), "hello");
    }

    #[test]
    fn test_remove_outer_quotes_single() {
        assert_eq!(remove_outer_quotes("'x'"), "x");
    }

    #[test]
    fn test_remove_outer_quotes_with_prefix() {
        assert_eq!(remove_outer_quotes("L\"wide\""), "wide");
        assert_eq!(remove_outer_quotes("u8\"utf8\""), "utf8");
        assert_eq!(remove_outer_quotes("u\"unicode\""), "unicode");
        assert_eq!(remove_outer_quotes("U\"unicode32\""), "unicode32");
    }

    #[test]
    fn test_remove_outer_quotes_no_quotes() {
        assert_eq!(remove_outer_quotes("no quotes"), "no quotes");
    }

    #[test]
    fn test_remove_outer_quotes_trimmed() {
        assert_eq!(remove_outer_quotes("  \"hello\"  "), "hello");
    }
}
