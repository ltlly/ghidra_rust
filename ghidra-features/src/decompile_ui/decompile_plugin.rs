//! Decompile plugin infrastructure -- Rust port of
//! `ghidra.app.plugin.core.decompile.DecompilePlugin` (extended).
//!
//! This module models the plugin-level infrastructure that the base
//! [`super::plugin::DecompilePlugin`] does not cover:
//!
//! * **Plugin annotations** -- `@PluginInfo` metadata (status, package,
//!   category, services required/provided, events consumed).
//! * **Service registration** -- the `registerServices()` pattern that
//!   binds `DecompilerHighlightService` and `DecompilerMarginService`.
//! * **SpecExtension integration** -- registering decompiler-specific
//!   options with the program's language specification on activation.
//! * **Plugin base class lifecycle** -- `init()`, `dispose()`, and
//!   `processEvent()` extension points modelled as traits.
//! * **Tool event wiring** -- mapping Ghidra's `PluginEvent` subclasses
//!   to the decompiler's internal dispatch.
//!
//! # Architecture
//!
//! ```text
//! PluginMetadata
//!   ├── status: PluginStatus
//!   ├── packageName: String
//!   ├── category: String
//!   ├── shortDescription: String
//!   ├── description: String
//!   ├── servicesRequired: Vec<String>
//!   ├── servicesProvided: Vec<String>
//!   └── eventsConsumed: Vec<String>
//!
//! PluginLifecycle
//!   ├── init()
//!   ├── dispose()
//!   └── processEvent()
//!
//! SpecExtensionOptions
//!   └── registerOptions(program)
//! ```

use std::collections::HashMap;

use super::plugin::DecompilePlugin;

// ---------------------------------------------------------------------------
// PluginStatus -- mirrors Ghidra's PluginStatus enum
// ---------------------------------------------------------------------------

/// The release status of a plugin.
///
/// Maps to Ghidra's `PluginStatus` enum which is used by the plugin
/// infrastructure to filter and sort plugins.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PluginStatus {
    /// The plugin is released and stable.
    Released,
    /// The plugin is in a stable but not yet fully released state.
    Stable,
    /// The plugin is under active development.
    Development,
    /// The plugin is no longer maintained.
    Unstable,
}

impl PluginStatus {
    /// Human-readable label.
    pub fn label(&self) -> &'static str {
        match self {
            PluginStatus::Released => "Released",
            PluginStatus::Stable => "Stable",
            PluginStatus::Development => "Development",
            PluginStatus::Unstable => "Unstable",
        }
    }
}

impl Default for PluginStatus {
    fn default() -> Self {
        PluginStatus::Released
    }
}

// ---------------------------------------------------------------------------
// PluginCategory -- mirrors Ghidra's PluginCategoryNames
// ---------------------------------------------------------------------------

/// Plugin category names used to organise the plugin list.
///
/// Maps to Ghidra's `PluginCategoryNames`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PluginCategory {
    /// Analysis plugins.
    Analysis,
    /// Code comparison plugins.
    CodeComparison,
    /// Data type management plugins.
    DataTypes,
    /// Decompiler plugins.
    Decompiler,
    /// Processor specification plugins.
    Processor,
    /// A custom category.
    Custom(String),
}

impl PluginCategory {
    /// The string used in Ghidra's plugin registry.
    pub fn as_str(&self) -> &str {
        match self {
            PluginCategory::Analysis => "Analysis",
            PluginCategory::CodeComparison => "Code Comparison",
            PluginCategory::DataTypes => "Data Types",
            PluginCategory::Decompiler => "Decompiler",
            PluginCategory::Processor => "Processor",
            PluginCategory::Custom(s) => s.as_str(),
        }
    }
}

// ---------------------------------------------------------------------------
// PluginMetadata -- the @PluginInfo annotation
// ---------------------------------------------------------------------------

/// Metadata for the decompile plugin, corresponding to Ghidra's
/// `@PluginInfo` annotation.
///
/// This is used by the tool infrastructure to determine:
/// * Which services the plugin requires and provides.
/// * Which events the plugin consumes.
/// * The plugin's category, status, and description.
#[derive(Debug, Clone)]
pub struct PluginMetadata {
    /// The release status.
    pub status: PluginStatus,
    /// The package name (e.g., `"Core"`).
    pub package_name: String,
    /// The category (e.g., `"Analysis"`).
    pub category: PluginCategory,
    /// Short description shown in the plugin list.
    pub short_description: String,
    /// Longer description shown in the plugin detail view.
    pub description: String,
    /// Service interfaces the plugin requires from the tool.
    pub services_required: Vec<String>,
    /// Service interfaces the plugin provides to the tool.
    pub services_provided: Vec<String>,
    /// Event class names the plugin consumes.
    pub events_consumed: Vec<String>,
}

impl PluginMetadata {
    /// Create the default metadata for the decompile plugin.
    ///
    /// This mirrors the `@PluginInfo` annotation on `DecompilePlugin`.
    pub fn decompile_plugin() -> Self {
        Self {
            status: PluginStatus::Released,
            package_name: "Core".into(),
            category: PluginCategory::Analysis,
            short_description: "Decompiler".into(),
            description: "Plugin for producing high-level decompilation".into(),
            services_required: vec![
                "GoToService".into(),
                "NavigationHistoryService".into(),
                "ClipboardService".into(),
                "DataTypeManagerService".into(),
            ],
            services_provided: vec![
                "DecompilerHighlightService".into(),
                "DecompilerMarginService".into(),
            ],
            events_consumed: vec![
                "ProgramActivatedPluginEvent".into(),
                "ProgramOpenedPluginEvent".into(),
                "ProgramLocationPluginEvent".into(),
                "ProgramSelectionPluginEvent".into(),
                "ProgramClosedPluginEvent".into(),
            ],
        }
    }

    /// Whether this plugin provides the given service interface.
    pub fn provides_service(&self, interface_name: &str) -> bool {
        self.services_provided
            .iter()
            .any(|s| s == interface_name)
    }

    /// Whether this plugin requires the given service interface.
    pub fn requires_service(&self, interface_name: &str) -> bool {
        self.services_required
            .iter()
            .any(|s| s == interface_name)
    }

    /// Whether this plugin consumes the given event class.
    pub fn consumes_event(&self, event_class: &str) -> bool {
        self.events_consumed
            .iter()
            .any(|s| s == event_class)
    }
}

// ---------------------------------------------------------------------------
// PluginLifecycle -- the init/dispose/processEvent extension points
// ---------------------------------------------------------------------------

/// Trait modelling the Ghidra `Plugin` lifecycle methods.
///
/// In Ghidra, `DecompilePlugin` extends `Plugin` and overrides:
/// * `init()` -- bind clipboard service after construction.
/// * `dispose()` -- tear down all providers.
/// * `processEvent()` -- dispatch tool events.
///
/// This trait captures that pattern for use in integration tests and
/// alternative plugin host implementations.
pub trait PluginLifecycle {
    /// Called after construction to bind runtime services.
    fn init(&mut self);

    /// Called to tear down the plugin and release all resources.
    fn dispose(&mut self);

    /// Process a tool event.
    fn process_event(&mut self, event: PluginEventKind);
}

/// High-level event categories consumed by the decompile plugin.
///
/// These correspond to the Ghidra `PluginEvent` subclasses listed in
/// the `eventsConsumed` annotation field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PluginEventKind {
    /// A program was activated in the tool.
    ProgramActivated,
    /// A program was opened.
    ProgramOpened,
    /// A program location changed.
    ProgramLocation,
    /// A program selection changed.
    ProgramSelection,
    /// A program was closed.
    ProgramClosed,
}

impl PluginEventKind {
    /// The Ghidra event class name.
    pub fn class_name(&self) -> &'static str {
        match self {
            PluginEventKind::ProgramActivated => "ProgramActivatedPluginEvent",
            PluginEventKind::ProgramOpened => "ProgramOpenedPluginEvent",
            PluginEventKind::ProgramLocation => "ProgramLocationPluginEvent",
            PluginEventKind::ProgramSelection => "ProgramSelectionPluginEvent",
            PluginEventKind::ProgramClosed => "ProgramClosedPluginEvent",
        }
    }
}

// ---------------------------------------------------------------------------
// SpecExtension -- registerOptions integration
// ---------------------------------------------------------------------------

/// Integration with Ghidra's `SpecExtension.registerOptions()`.
///
/// When a program is activated, the decompile plugin registers its
/// decompiler-specific options with the program's language
/// specification.  This ensures that processor-specific display
/// preferences (e.g., instruction set syntax) are available.
///
/// In Ghidra this is `SpecExtension.registerOptions(currentProgram)`.
/// Here we model the registration as a mapping from program id to the
/// set of registered option keys.
#[derive(Debug, Clone, Default)]
pub struct SpecExtensionRegistry {
    /// Maps program identifier to the set of option keys that have been
    /// registered for that program.
    registered: HashMap<String, Vec<String>>,
}

impl SpecExtensionRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register decompiler options for the given program.
    ///
    /// This mirrors `SpecExtension.registerOptions(program)`.
    pub fn register_options(&mut self, program_id: &str) {
        let options = self.registered.entry(program_id.to_string()).or_default();
        // These are the option keys that SpecExtension registers:
        let default_keys = [
            "Decompiler.Analysis.PreserveInlineNamespaces",
            "Decompiler.Analysis.EliminateUnreachable",
            "Decompiler.Analysis.RespectReadOnly",
            "Decompiler.Display.BraceStyle",
            "Decompiler.Display.MaxWidth",
            "Decompiler.Display.CommentStyle",
        ];
        for key in &default_keys {
            if !options.contains(&key.to_string()) {
                options.push(key.to_string());
            }
        }
    }

    /// Unregister options for the given program.
    pub fn unregister_options(&mut self, program_id: &str) {
        self.registered.remove(program_id);
    }

    /// Whether options have been registered for the given program.
    pub fn is_registered(&self, program_id: &str) -> bool {
        self.registered.contains_key(program_id)
    }

    /// Get the registered option keys for a program.
    pub fn option_keys(&self, program_id: &str) -> Option<&[String]> {
        self.registered.get(program_id).map(|v| v.as_slice())
    }
}

// ---------------------------------------------------------------------------
// ServiceRegistrationManager -- tracks provided/required services
// ---------------------------------------------------------------------------

/// Manages the plugin's service registration lifecycle.
///
/// In Ghidra, `registerServiceProvided()` and `registerServiceRequired()`
/// are called during plugin construction.  The tool uses this information
/// to wire up service dependencies.  This struct captures that state.
#[derive(Debug, Clone, Default)]
pub struct ServiceRegistrationManager {
    /// Services this plugin provides (interface name -> provider).
    provided: Vec<ServiceBinding>,
    /// Services this plugin requires (interface name).
    required: Vec<String>,
    /// Whether registration is complete.
    registered: bool,
}

/// A binding of a service interface to its provider.
#[derive(Debug, Clone)]
pub struct ServiceBinding {
    /// The service interface name.
    pub interface_name: String,
    /// A description of the provider (e.g., the provider's type name).
    pub provider_description: String,
}

impl ServiceRegistrationManager {
    /// Create a new manager with the standard decompile plugin services.
    pub fn decompile_defaults() -> Self {
        Self {
            provided: vec![
                ServiceBinding {
                    interface_name: "DecompilerHighlightService".into(),
                    provider_description: "DecompilerProvider".into(),
                },
                ServiceBinding {
                    interface_name: "DecompilerMarginService".into(),
                    provider_description: "DecompilerProvider".into(),
                },
            ],
            required: vec![
                "GoToService".into(),
                "NavigationHistoryService".into(),
                "ClipboardService".into(),
                "DataTypeManagerService".into(),
            ],
            registered: false,
        }
    }

    /// Mark registration as complete.
    pub fn mark_registered(&mut self) {
        self.registered = true;
    }

    /// Whether registration is complete.
    pub fn is_registered(&self) -> bool {
        self.registered
    }

    /// The number of provided services.
    pub fn provided_count(&self) -> usize {
        self.provided.len()
    }

    /// The number of required services.
    pub fn required_count(&self) -> usize {
        self.required.len()
    }

    /// Whether the plugin provides the given service.
    pub fn provides(&self, interface_name: &str) -> bool {
        self.provided
            .iter()
            .any(|b| b.interface_name == interface_name)
    }

    /// Whether the plugin requires the given service.
    pub fn requires(&self, interface_name: &str) -> bool {
        self.required.iter().any(|s| s == interface_name)
    }

    /// Get all provided service bindings.
    pub fn provided_services(&self) -> &[ServiceBinding] {
        &self.provided
    }

    /// Get all required service names.
    pub fn required_services(&self) -> &[String] {
        &self.required
    }
}

// ---------------------------------------------------------------------------
// DecompilePluginExtension -- helper methods for plugin setup
// ---------------------------------------------------------------------------

/// Extension trait that adds the Java-side `registerServices()` and
/// `SpecExtension` integration to the core `DecompilePlugin`.
///
/// In Ghidra, `DecompilePlugin`'s constructor calls `registerServices()`
/// and `processEvent` calls `SpecExtension.registerOptions()`.  This
/// trait captures those patterns.
pub trait DecompilePluginExtension {
    /// Register the services this plugin provides with the tool.
    ///
    /// Mirrors `DecompilePlugin.registerServices()` in Java.
    fn register_services(&self, registry: &mut ServiceRegistrationManager);

    /// Called when a program is activated to register SpecExtension
    /// options.
    ///
    /// Mirrors `SpecExtension.registerOptions(currentProgram)` in Java.
    fn on_program_activated(&self, spec_registry: &mut SpecExtensionRegistry, program_id: &str);

    /// Called when a program is closed to unregister SpecExtension
    /// options.
    fn on_program_closed(&self, spec_registry: &mut SpecExtensionRegistry, program_id: &str);
}

impl DecompilePluginExtension for DecompilePlugin {
    fn register_services(&self, registry: &mut ServiceRegistrationManager) {
        // In the full implementation, this would call:
        //   registerServiceProvided(DecompilerHighlightService.class, connectedProvider)
        //   registerServiceProvided(DecompilerMarginService.class, connectedProvider)
        registry.mark_registered();
    }

    fn on_program_activated(&self, spec_registry: &mut SpecExtensionRegistry, program_id: &str) {
        spec_registry.register_options(program_id);
    }

    fn on_program_closed(&self, spec_registry: &mut SpecExtensionRegistry, program_id: &str) {
        spec_registry.unregister_options(program_id);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- PluginMetadata tests --

    #[test]
    fn test_metadata_decompile_plugin() {
        let meta = PluginMetadata::decompile_plugin();
        assert_eq!(meta.status, PluginStatus::Released);
        assert_eq!(meta.package_name, "Core");
        assert_eq!(meta.category, PluginCategory::Analysis);
        assert_eq!(meta.short_description, "Decompiler");
        assert_eq!(meta.services_required.len(), 4);
        assert_eq!(meta.services_provided.len(), 2);
        assert_eq!(meta.events_consumed.len(), 5);
    }

    #[test]
    fn test_metadata_provides_service() {
        let meta = PluginMetadata::decompile_plugin();
        assert!(meta.provides_service("DecompilerHighlightService"));
        assert!(meta.provides_service("DecompilerMarginService"));
        assert!(!meta.provides_service("GoToService"));
    }

    #[test]
    fn test_metadata_requires_service() {
        let meta = PluginMetadata::decompile_plugin();
        assert!(meta.requires_service("GoToService"));
        assert!(meta.requires_service("ClipboardService"));
        assert!(!meta.requires_service("DecompilerHighlightService"));
    }

    #[test]
    fn test_metadata_consumes_event() {
        let meta = PluginMetadata::decompile_plugin();
        assert!(meta.consumes_event("ProgramActivatedPluginEvent"));
        assert!(meta.consumes_event("ProgramClosedPluginEvent"));
        assert!(!meta.consumes_event("SomeOtherEvent"));
    }

    // -- PluginStatus tests --

    #[test]
    fn test_plugin_status_labels() {
        assert_eq!(PluginStatus::Released.label(), "Released");
        assert_eq!(PluginStatus::Stable.label(), "Stable");
        assert_eq!(PluginStatus::Development.label(), "Development");
        assert_eq!(PluginStatus::Unstable.label(), "Unstable");
    }

    #[test]
    fn test_plugin_status_default() {
        assert_eq!(PluginStatus::default(), PluginStatus::Released);
    }

    // -- PluginCategory tests --

    #[test]
    fn test_plugin_category_as_str() {
        assert_eq!(PluginCategory::Analysis.as_str(), "Analysis");
        assert_eq!(PluginCategory::Decompiler.as_str(), "Decompiler");
        assert_eq!(
            PluginCategory::Custom("MyCategory".into()).as_str(),
            "MyCategory"
        );
    }

    // -- PluginEventKind tests --

    #[test]
    fn test_event_kind_class_name() {
        assert_eq!(
            PluginEventKind::ProgramActivated.class_name(),
            "ProgramActivatedPluginEvent"
        );
        assert_eq!(
            PluginEventKind::ProgramClosed.class_name(),
            "ProgramClosedPluginEvent"
        );
    }

    // -- SpecExtensionRegistry tests --

    #[test]
    fn test_spec_extension_register() {
        let mut registry = SpecExtensionRegistry::new();
        assert!(!registry.is_registered("prog1"));

        registry.register_options("prog1");
        assert!(registry.is_registered("prog1"));

        let keys = registry.option_keys("prog1").unwrap();
        assert!(!keys.is_empty());
        assert!(keys.iter().any(|k| k.contains("EliminateUnreachable")));
    }

    #[test]
    fn test_spec_extension_unregister() {
        let mut registry = SpecExtensionRegistry::new();
        registry.register_options("prog1");
        assert!(registry.is_registered("prog1"));

        registry.unregister_options("prog1");
        assert!(!registry.is_registered("prog1"));
    }

    #[test]
    fn test_spec_extension_multiple_programs() {
        let mut registry = SpecExtensionRegistry::new();
        registry.register_options("prog1");
        registry.register_options("prog2");
        assert!(registry.is_registered("prog1"));
        assert!(registry.is_registered("prog2"));

        registry.unregister_options("prog1");
        assert!(!registry.is_registered("prog1"));
        assert!(registry.is_registered("prog2"));
    }

    #[test]
    fn test_spec_extension_option_keys_none() {
        let registry = SpecExtensionRegistry::new();
        assert!(registry.option_keys("nonexistent").is_none());
    }

    // -- ServiceRegistrationManager tests --

    #[test]
    fn test_service_registration_defaults() {
        let manager = ServiceRegistrationManager::decompile_defaults();
        assert_eq!(manager.provided_count(), 2);
        assert_eq!(manager.required_count(), 4);
        assert!(!manager.is_registered());
    }

    #[test]
    fn test_service_registration_mark_registered() {
        let mut manager = ServiceRegistrationManager::decompile_defaults();
        manager.mark_registered();
        assert!(manager.is_registered());
    }

    #[test]
    fn test_service_registration_provides() {
        let manager = ServiceRegistrationManager::decompile_defaults();
        assert!(manager.provides("DecompilerHighlightService"));
        assert!(manager.provides("DecompilerMarginService"));
        assert!(!manager.provides("GoToService"));
    }

    #[test]
    fn test_service_registration_requires() {
        let manager = ServiceRegistrationManager::decompile_defaults();
        assert!(manager.requires("GoToService"));
        assert!(manager.requires("ClipboardService"));
        assert!(!manager.requires("DecompilerHighlightService"));
    }

    #[test]
    fn test_service_registration_provided_services() {
        let manager = ServiceRegistrationManager::decompile_defaults();
        let services = manager.provided_services();
        assert_eq!(services.len(), 2);
        assert_eq!(services[0].interface_name, "DecompilerHighlightService");
        assert_eq!(services[1].interface_name, "DecompilerMarginService");
    }

    #[test]
    fn test_service_registration_required_services() {
        let manager = ServiceRegistrationManager::decompile_defaults();
        let services = manager.required_services();
        assert_eq!(services.len(), 4);
        assert!(services.contains(&"GoToService".to_string()));
        assert!(services.contains(&"NavigationHistoryService".to_string()));
        assert!(services.contains(&"ClipboardService".to_string()));
        assert!(services.contains(&"DataTypeManagerService".to_string()));
    }

    // -- DecompilePluginExtension trait tests --

    #[test]
    fn test_plugin_extension_register_services() {
        let plugin = DecompilePlugin::new();
        let mut registry = ServiceRegistrationManager::decompile_defaults();
        assert!(!registry.is_registered());
        plugin.register_services(&mut registry);
        assert!(registry.is_registered());
    }

    #[test]
    fn test_plugin_extension_on_program_activated() {
        let plugin = DecompilePlugin::new();
        let mut spec_registry = SpecExtensionRegistry::new();

        plugin.on_program_activated(&mut spec_registry, "test.elf");
        assert!(spec_registry.is_registered("test.elf"));
        assert!(spec_registry
            .option_keys("test.elf")
            .unwrap()
            .iter()
            .any(|k| k.contains("EliminateUnreachable")));
    }

    #[test]
    fn test_plugin_extension_on_program_closed() {
        let plugin = DecompilePlugin::new();
        let mut spec_registry = SpecExtensionRegistry::new();

        plugin.on_program_activated(&mut spec_registry, "test.elf");
        assert!(spec_registry.is_registered("test.elf"));

        plugin.on_program_closed(&mut spec_registry, "test.elf");
        assert!(!spec_registry.is_registered("test.elf"));
    }
}
