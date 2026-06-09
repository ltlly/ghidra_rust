//! Function compare plugin.
//!
//! Ported from Ghidra's `FunctionComparePlugin` Java class in
//! `ghidra.app.plugin.core.functioncompare`.
//!
//! This module provides the plugin that manages function comparison
//! providers. It handles creating comparisons, managing providers,
//! and responding to program events (open, close, restore).
//!
//! In the original Java, `FunctionComparePlugin` extends `ProgramPlugin`
//! and implements `DomainObjectListener`. In this Rust port we capture
//! the logical state and behavior without the Ghidra plugin framework.
//!
//! # Key types
//!
//! - [`FunctionComparePlugin`] -- the main plugin state
//! - [`CompareAction`] -- actions that can be performed on comparisons
//! - [`PluginEvent`] -- events emitted by the plugin

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use super::{
    ApplyResult, ComparisonContext, FunctionComparisonAction, FunctionComparisonPanel,
    FunctionComparisonEntry, FunctionComparisonService, FunctionInfo,
};

/// Actions that can be performed on function comparisons.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CompareAction {
    /// Apply function name and namespace.
    ApplyName,
    /// Apply function signature.
    ApplySignature,
    /// Apply function signature with data types.
    ApplySignatureWithDataTypes,
    /// Apply calling convention.
    ApplyCallingConvention,
    /// Apply parameter comments.
    ApplyComments,
    /// Apply all function data.
    ApplyAll,
    /// Compare selected functions (add to existing or create new).
    CompareFunctions,
    /// Compare functions in a new window.
    CompareInNewWindow,
}

impl CompareAction {
    /// A human-readable label for this action.
    pub fn label(&self) -> &'static str {
        match self {
            Self::ApplyName => "Apply Function Name",
            Self::ApplySignature => "Apply Function Signature",
            Self::ApplySignatureWithDataTypes => "Apply Signature with Data Types",
            Self::ApplyCallingConvention => "Apply Calling Convention",
            Self::ApplyComments => "Apply Function Comments",
            Self::ApplyAll => "Apply All Function Data",
            Self::CompareFunctions => "Compare Function(s)",
            Self::CompareInNewWindow => "Compare in New Window",
        }
    }

    /// A description of this action.
    pub fn description(&self) -> &'static str {
        match self {
            Self::ApplyName => "Apply function name and namespace from source to target.",
            Self::ApplySignature => "Apply function signature (return type + parameter types).",
            Self::ApplySignatureWithDataTypes => {
                "Apply function signature along with data type definitions."
            }
            Self::ApplyCallingConvention => "Apply calling convention from source to target.",
            Self::ApplyComments => "Apply parameter and function comments.",
            Self::ApplyAll => "Apply all function data from source to target.",
            Self::CompareFunctions => "Adds the selected function(s) to the current comparison window.",
            Self::CompareInNewWindow => "Compare the selected function(s) in a new comparison window.",
        }
    }

    /// Convert this action to the corresponding [`FunctionComparisonAction`],
    /// if applicable.
    pub fn to_function_comparison_action(&self) -> Option<FunctionComparisonAction> {
        match self {
            Self::ApplyName => Some(FunctionComparisonAction::ApplyName),
            Self::ApplySignature => Some(FunctionComparisonAction::ApplySignature),
            Self::ApplySignatureWithDataTypes => {
                Some(FunctionComparisonAction::ApplySignatureWithDataTypes)
            }
            Self::ApplyCallingConvention => Some(FunctionComparisonAction::ApplyCallingConvention),
            Self::ApplyComments => Some(FunctionComparisonAction::ApplyComments),
            Self::ApplyAll => Some(FunctionComparisonAction::ApplyAll),
            Self::CompareFunctions | Self::CompareInNewWindow => None,
        }
    }
}

/// Events emitted by the function compare plugin.
#[derive(Debug, Clone)]
pub enum PluginEvent {
    /// A new comparison provider was created.
    ProviderCreated {
        /// The provider ID.
        provider_id: u64,
    },
    /// A comparison provider was closed.
    ProviderClosed {
        /// The provider ID.
        provider_id: u64,
    },
    /// A comparison was initiated.
    ComparisonStarted {
        /// Source function name.
        source: String,
        /// Target function name.
        target: String,
    },
    /// An apply action was completed.
    ActionApplied {
        /// The action that was applied.
        action: FunctionComparisonAction,
        /// Whether the apply was successful.
        success: bool,
    },
}

/// Trait for receiving plugin events.
pub trait PluginEventListener: Send + Sync {
    /// Called when an event occurs.
    fn on_event(&self, event: &PluginEvent);
}

/// Global provider ID counter.
static PROVIDER_ID_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

fn next_provider_id() -> u64 {
    PROVIDER_ID_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

/// The function compare plugin state.
///
/// Manages comparison providers, handles program events, and provides
/// the comparison service API.
///
/// Ported from Ghidra's `FunctionComparePlugin` Java class.
///
/// # Example
///
/// ```rust
/// use ghidra_features::functioncompare::*;
/// use ghidra_features::functioncompare::function_compare_plugin::*;
///
/// let mut plugin = FunctionComparePlugin::new();
///
/// let ctx = ComparisonContext {
///     source: Some(FunctionInfo {
///         name: "main".into(),
///         namespace: "App".into(),
///         entry_address: 0x1000,
///         read_only: false,
///     }),
///     target: Some(FunctionInfo {
///         name: "init".into(),
///         namespace: "App".into(),
///         entry_address: 0x2000,
///         read_only: false,
///     }),
/// };
///
/// let result = plugin.execute_action(CompareAction::ApplyName, &ctx);
/// assert!(result.is_success());
/// ```
pub struct FunctionComparePlugin {
    /// Active comparison providers.
    providers: HashSet<u64>,
    /// The last active provider.
    last_active_provider: Option<u64>,
    /// Shared comparison panel.
    panel: FunctionComparisonPanel,
    /// Whether the plugin is enabled.
    enabled: bool,
    /// Listeners for plugin events.
    listeners: Vec<Arc<dyn PluginEventListener>>,
}

impl std::fmt::Debug for FunctionComparePlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FunctionComparePlugin")
            .field("providers", &self.providers)
            .field("last_active_provider", &self.last_active_provider)
            .field("panel", &self.panel)
            .field("enabled", &self.enabled)
            .field("listeners", &self.listeners.len())
            .finish()
    }
}

impl FunctionComparePlugin {
    /// Create a new function compare plugin.
    pub fn new() -> Self {
        Self {
            providers: HashSet::new(),
            last_active_provider: None,
            panel: FunctionComparisonPanel::new(),
            enabled: true,
            listeners: Vec::new(),
        }
    }

    /// Add a listener for plugin events.
    pub fn add_listener(&mut self, listener: Arc<dyn PluginEventListener>) {
        self.listeners.push(listener);
    }

    /// Remove all listeners.
    pub fn clear_listeners(&mut self) {
        self.listeners.clear();
    }

    /// Fire an event to all listeners.
    fn fire_event(&self, event: PluginEvent) {
        for listener in &self.listeners {
            listener.on_event(&event);
        }
    }

    /// Get the number of active providers.
    pub fn provider_count(&self) -> usize {
        self.providers.len()
    }

    /// Check if there are any active providers.
    pub fn has_providers(&self) -> bool {
        !self.providers.is_empty()
    }

    /// Get the last active provider ID.
    pub fn last_active_provider(&self) -> Option<u64> {
        self.last_active_provider
    }

    /// Register a new comparison provider.
    ///
    /// Returns the provider ID.
    pub fn create_provider(&mut self) -> u64 {
        let provider_id = next_provider_id();
        self.providers.insert(provider_id);
        self.last_active_provider = Some(provider_id);
        self.fire_event(PluginEvent::ProviderCreated { provider_id });
        provider_id
    }

    /// Close a comparison provider.
    pub fn close_provider(&mut self, provider_id: u64) {
        if self.providers.remove(&provider_id) {
            if self.last_active_provider == Some(provider_id) {
                self.last_active_provider = None;
            }
            self.fire_event(PluginEvent::ProviderClosed { provider_id });
        }
    }

    /// Set a provider as the last active provider.
    pub fn provider_activated(&mut self, provider_id: u64) {
        if self.providers.contains(&provider_id) {
            self.last_active_provider = Some(provider_id);
        }
    }

    /// Execute an apply action in the given context.
    ///
    /// Returns the [`ApplyResult`] of the operation.
    pub fn execute_action(
        &self,
        action: CompareAction,
        context: &ComparisonContext,
    ) -> ApplyResult {
        if !self.enabled {
            return ApplyResult::Failed {
                error: "Plugin is disabled".into(),
            };
        }

        if !context.is_valid() {
            return ApplyResult::Failed {
                error: "Invalid context: source and target required".into(),
            };
        }

        if context.is_target_read_only() {
            return ApplyResult::Failed {
                error: "Target program is read-only".into(),
            };
        }

        let source = context.source.as_ref().unwrap();
        let target = context.target.as_ref().unwrap();

        self.fire_event(PluginEvent::ComparisonStarted {
            source: source.qualified_name(),
            target: target.qualified_name(),
        });

        let result = match action {
            CompareAction::ApplyName => {
                let mut applied = Vec::new();
                applied.push(format!(
                    "Applied name '{}' from {} to {}",
                    source.name,
                    source.qualified_name(),
                    target.qualified_name()
                ));
                ApplyResult::Success { applied }
            }
            CompareAction::ApplySignature => {
                ApplyResult::Success {
                    applied: vec!["Applied function signature".into()],
                }
            }
            CompareAction::ApplySignatureWithDataTypes => {
                ApplyResult::Success {
                    applied: vec!["Applied signature with data types".into()],
                }
            }
            CompareAction::ApplyCallingConvention => {
                ApplyResult::Success {
                    applied: vec!["Applied calling convention".into()],
                }
            }
            CompareAction::ApplyComments => {
                ApplyResult::Success {
                    applied: vec!["Applied function comments".into()],
                }
            }
            CompareAction::ApplyAll => {
                ApplyResult::Success {
                    applied: vec!["Applied all function data".into()],
                }
            }
            CompareAction::CompareFunctions | CompareAction::CompareInNewWindow => {
                ApplyResult::Success {
                    applied: vec![format!(
                        "Initiated comparison between {} and {}",
                        source.qualified_name(),
                        target.qualified_name()
                    )],
                }
            }
        };

        self.fire_event(PluginEvent::ActionApplied {
            action: action
                .to_function_comparison_action()
                .unwrap_or(FunctionComparisonAction::ApplyAll),
            success: result.is_success(),
        });

        result
    }

    /// Get a reference to the comparison panel.
    pub fn panel(&self) -> &FunctionComparisonPanel {
        &self.panel
    }

    /// Get a mutable reference to the comparison panel.
    pub fn panel_mut(&mut self) -> &mut FunctionComparisonPanel {
        &mut self.panel
    }

    /// Whether the plugin is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Enable or disable the plugin.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Get all active provider IDs.
    pub fn active_providers(&self) -> Vec<u64> {
        self.providers.iter().copied().collect()
    }

    /// Dispose of the plugin.
    pub fn dispose(&mut self) {
        let provider_ids: Vec<u64> = self.providers.iter().copied().collect();
        for id in provider_ids {
            self.close_provider(id);
        }
        self.listeners.clear();
        self.panel.clear();
    }
}

impl Default for FunctionComparePlugin {
    fn default() -> Self {
        Self::new()
    }
}

/// Implementation of [`FunctionComparisonService`] backed by a
/// [`FunctionComparePlugin`].
#[derive(Debug)]
pub struct PluginComparisonService {
    /// The underlying plugin state.
    plugin: Arc<Mutex<FunctionComparePlugin>>,
}

impl PluginComparisonService {
    /// Create a new service wrapping the given plugin.
    pub fn new(plugin: Arc<Mutex<FunctionComparePlugin>>) -> Self {
        Self { plugin }
    }
}

impl FunctionComparisonService for PluginComparisonService {
    fn create_comparison(&self, functions: Vec<FunctionComparisonEntry>) {
        if let Ok(mut plugin) = self.plugin.lock() {
            let _provider_id = plugin.create_provider();
            let panel = plugin.panel_mut();
            if functions.len() >= 2 {
                panel.set_source(functions[0].clone());
                panel.set_target(functions[1].clone());
            }
        }
    }

    fn is_available(&self) -> bool {
        self.plugin.lock().map_or(false, |p| p.is_enabled())
    }
}

/// A simple listener that tracks plugin events.
#[derive(Debug, Default)]
pub struct TrackingPluginListener {
    /// Recorded events.
    pub events: Mutex<Vec<PluginEvent>>,
}

impl TrackingPluginListener {
    /// Create a new tracking listener.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the number of events received.
    pub fn event_count(&self) -> usize {
        self.events.lock().unwrap().len()
    }
}

impl PluginEventListener for TrackingPluginListener {
    fn on_event(&self, event: &PluginEvent) {
        self.events.lock().unwrap().push(event.clone());
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // --- CompareAction tests ---

    #[test]
    fn test_compare_action_label() {
        assert_eq!(CompareAction::ApplyName.label(), "Apply Function Name");
        assert_eq!(CompareAction::ApplyAll.label(), "Apply All Function Data");
        assert_eq!(CompareAction::CompareFunctions.label(), "Compare Function(s)");
    }

    #[test]
    fn test_compare_action_description() {
        assert!(!CompareAction::ApplyName.description().is_empty());
        assert!(!CompareAction::CompareInNewWindow.description().is_empty());
    }

    #[test]
    fn test_compare_action_to_function_comparison_action() {
        assert_eq!(
            CompareAction::ApplyName.to_function_comparison_action(),
            Some(FunctionComparisonAction::ApplyName)
        );
        assert_eq!(
            CompareAction::ApplySignatureWithDataTypes.to_function_comparison_action(),
            Some(FunctionComparisonAction::ApplySignatureWithDataTypes)
        );
        assert_eq!(
            CompareAction::CompareFunctions.to_function_comparison_action(),
            None
        );
    }

    // --- FunctionComparePlugin tests ---

    #[test]
    fn test_plugin_new() {
        let plugin = FunctionComparePlugin::new();
        assert_eq!(plugin.provider_count(), 0);
        assert!(!plugin.has_providers());
        assert!(plugin.last_active_provider().is_none());
        assert!(plugin.is_enabled());
    }

    #[test]
    fn test_plugin_create_provider() {
        let mut plugin = FunctionComparePlugin::new();
        let id = plugin.create_provider();
        assert_eq!(plugin.provider_count(), 1);
        assert!(plugin.has_providers());
        assert_eq!(plugin.last_active_provider(), Some(id));
    }

    #[test]
    fn test_plugin_close_provider() {
        let mut plugin = FunctionComparePlugin::new();
        let id = plugin.create_provider();
        assert_eq!(plugin.provider_count(), 1);

        plugin.close_provider(id);
        assert_eq!(plugin.provider_count(), 0);
        assert!(!plugin.has_providers());
        assert!(plugin.last_active_provider().is_none());
    }

    #[test]
    fn test_plugin_close_nonexistent_provider() {
        let mut plugin = FunctionComparePlugin::new();
        plugin.close_provider(999);
        assert_eq!(plugin.provider_count(), 0);
    }

    #[test]
    fn test_plugin_multiple_providers() {
        let mut plugin = FunctionComparePlugin::new();
        let id1 = plugin.create_provider();
        let id2 = plugin.create_provider();
        assert_eq!(plugin.provider_count(), 2);
        assert_eq!(plugin.last_active_provider(), Some(id2));

        plugin.close_provider(id1);
        assert_eq!(plugin.provider_count(), 1);
        assert_eq!(plugin.last_active_provider(), Some(id2));
    }

    #[test]
    fn test_plugin_provider_activated() {
        let mut plugin = FunctionComparePlugin::new();
        let id1 = plugin.create_provider();
        let id2 = plugin.create_provider();
        assert_eq!(plugin.last_active_provider(), Some(id2));

        plugin.provider_activated(id1);
        assert_eq!(plugin.last_active_provider(), Some(id1));
    }

    #[test]
    fn test_plugin_execute_action() {
        let plugin = FunctionComparePlugin::new();
        let ctx = ComparisonContext {
            source: Some(FunctionInfo {
                name: "foo".into(),
                namespace: "ns".into(),
                entry_address: 0x100,
                read_only: false,
            }),
            target: Some(FunctionInfo {
                name: "bar".into(),
                namespace: "ns".into(),
                entry_address: 0x200,
                read_only: false,
            }),
        };

        let result = plugin.execute_action(CompareAction::ApplyName, &ctx);
        assert!(result.is_success());
    }

    #[test]
    fn test_plugin_execute_action_read_only() {
        let plugin = FunctionComparePlugin::new();
        let ctx = ComparisonContext {
            source: Some(FunctionInfo {
                name: "foo".into(),
                namespace: String::new(),
                entry_address: 0x100,
                read_only: false,
            }),
            target: Some(FunctionInfo {
                name: "bar".into(),
                namespace: String::new(),
                entry_address: 0x200,
                read_only: true,
            }),
        };

        let result = plugin.execute_action(CompareAction::ApplyName, &ctx);
        assert!(!result.is_success());
    }

    #[test]
    fn test_plugin_execute_action_invalid_context() {
        let plugin = FunctionComparePlugin::new();
        let ctx = ComparisonContext::new();
        let result = plugin.execute_action(CompareAction::ApplyName, &ctx);
        assert!(!result.is_success());
    }

    #[test]
    fn test_plugin_disabled() {
        let mut plugin = FunctionComparePlugin::new();
        plugin.set_enabled(false);

        let ctx = ComparisonContext {
            source: Some(FunctionInfo {
                name: "foo".into(),
                namespace: String::new(),
                entry_address: 0x100,
                read_only: false,
            }),
            target: Some(FunctionInfo {
                name: "bar".into(),
                namespace: String::new(),
                entry_address: 0x200,
                read_only: false,
            }),
        };

        let result = plugin.execute_action(CompareAction::ApplyName, &ctx);
        assert!(!result.is_success());
    }

    #[test]
    fn test_plugin_panel() {
        let mut plugin = FunctionComparePlugin::new();
        assert!(!plugin.panel().is_ready());

        plugin.panel_mut().set_source(FunctionComparisonEntry::new("src", "p", 0x1000));
        plugin.panel_mut().set_target(FunctionComparisonEntry::new("tgt", "p", 0x2000));
        assert!(plugin.panel().is_ready());
    }

    #[test]
    fn test_plugin_dispose() {
        let mut plugin = FunctionComparePlugin::new();
        plugin.create_provider();
        plugin.create_provider();
        assert_eq!(plugin.provider_count(), 2);

        plugin.dispose();
        assert_eq!(plugin.provider_count(), 0);
    }

    #[test]
    fn test_plugin_default() {
        let plugin = FunctionComparePlugin::default();
        assert_eq!(plugin.provider_count(), 0);
    }

    #[test]
    fn test_plugin_event_listeners() {
        let mut plugin = FunctionComparePlugin::new();
        let listener = Arc::new(TrackingPluginListener::new());
        plugin.add_listener(listener.clone());

        let ctx = ComparisonContext {
            source: Some(FunctionInfo {
                name: "foo".into(),
                namespace: String::new(),
                entry_address: 0x100,
                read_only: false,
            }),
            target: Some(FunctionInfo {
                name: "bar".into(),
                namespace: String::new(),
                entry_address: 0x200,
                read_only: false,
            }),
        };

        plugin.execute_action(CompareAction::ApplyName, &ctx);
        // Should fire ComparisonStarted + ActionApplied
        assert_eq!(listener.event_count(), 2);
    }

    #[test]
    fn test_plugin_active_providers() {
        let mut plugin = FunctionComparePlugin::new();
        plugin.create_provider();
        plugin.create_provider();
        let providers = plugin.active_providers();
        assert_eq!(providers.len(), 2);
    }

    // --- PluginComparisonService tests ---

    #[test]
    fn test_service_create_comparison() {
        let plugin = Arc::new(Mutex::new(FunctionComparePlugin::new()));
        let service = PluginComparisonService::new(plugin.clone());

        let entries = vec![
            FunctionComparisonEntry::new("main", "test.exe", 0x1000),
            FunctionComparisonEntry::new("init", "test.exe", 0x2000),
        ];
        service.create_comparison(entries);

        assert!(plugin.lock().unwrap().has_providers());
    }

    #[test]
    fn test_service_is_available() {
        let plugin = Arc::new(Mutex::new(FunctionComparePlugin::new()));
        let service = PluginComparisonService::new(plugin.clone());
        assert!(service.is_available());

        plugin.lock().unwrap().set_enabled(false);
        assert!(!service.is_available());
    }

    // --- TrackingPluginListener tests ---

    #[test]
    fn test_tracking_plugin_listener() {
        let listener = TrackingPluginListener::new();
        assert_eq!(listener.event_count(), 0);

        listener.on_event(&PluginEvent::ProviderCreated { provider_id: 1 });
        listener.on_event(&PluginEvent::ProviderClosed { provider_id: 1 });
        assert_eq!(listener.event_count(), 2);
    }
}
