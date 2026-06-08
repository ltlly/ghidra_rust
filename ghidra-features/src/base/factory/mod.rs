//! Plugin component factories.
//!
//! Ported from Ghidra's `ghidra.app.factory` and
//! `ghidra.formats.gfilesystem.factory` Java packages.
//!
//! This module provides the factory interfaces and implementations
//! for creating component providers within Ghidra's docking framework,
//! tool state factories, and the GFileSystem factory/probe system.
//! Plugins register factories with the tool, which uses them to
//! instantiate new component providers on demand.
//!
//! # Key Types
//!
//! - [`ComponentFactory`] -- trait for creating component providers
//! - [`DefaultComponentFactory`] -- default factory implementation
//! - [`FormatType`] -- describes the visual format of a component
//! - [`ComponentProviderDescription`] -- metadata about a provider
//! - [`FactoryError`] -- errors during component creation
//!
//! # Sub-modules
//!
//! - [`tool_state_factory`] -- `ToolStateFactory` / `GhidraToolStateFactory`
//! - [`gfilesystem_factory`] -- GFileSystem factory and probe interfaces
//! - [`filesystem_info`] -- `FileSystemInfoRec` registry and dependency exceptions

pub mod tool_state_factory;
pub mod gfilesystem_factory;
pub mod filesystem_info;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

// ---------------------------------------------------------------------------
// FormatType -- visual format of a component provider
// ---------------------------------------------------------------------------

/// The visual format in which a component provider can render.
///
/// Ported from `ghidra.app.factory.FormatType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FormatType {
    /// A table/list view.
    Table,
    /// A tree view.
    Tree,
    /// A text/code listing view.
    Listing,
    /// A graph/diagram view.
    Graph,
    /// An image/bitmap view.
    Image,
    /// A custom/other format.
    Other,
}

impl fmt::Display for FormatType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FormatType::Table => write!(f, "Table"),
            FormatType::Tree => write!(f, "Tree"),
            FormatType::Listing => write!(f, "Listing"),
            FormatType::Graph => write!(f, "Graph"),
            FormatType::Image => write!(f, "Image"),
            FormatType::Other => write!(f, "Other"),
        }
    }
}

// ---------------------------------------------------------------------------
// ComponentProviderDescription
// ---------------------------------------------------------------------------

/// Metadata describing a component provider.
///
/// Ported from the description fields of `ComponentProviderAdapter`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentProviderDescription {
    /// The unique name of this provider.
    pub name: String,
    /// The owning plugin name.
    pub owner: String,
    /// The visual format type.
    pub format_type: FormatType,
    /// Whether this provider supports multiple instances.
    pub supports_multiple_instances: bool,
    /// Whether the provider is transient (not saved in tool config).
    pub transient: bool,
    /// Associated help topic.
    pub help_topic: Option<String>,
    /// Window menu group for ordering.
    pub window_menu_group: Option<String>,
}

impl ComponentProviderDescription {
    /// Creates a new provider description.
    pub fn new(
        name: impl Into<String>,
        owner: impl Into<String>,
        format_type: FormatType,
    ) -> Self {
        Self {
            name: name.into(),
            owner: owner.into(),
            format_type,
            supports_multiple_instances: false,
            transient: false,
            help_topic: None,
            window_menu_group: None,
        }
    }

    /// Sets whether multiple instances are supported.
    pub fn with_multiple_instances(mut self, supports: bool) -> Self {
        self.supports_multiple_instances = supports;
        self
    }

    /// Sets the provider as transient.
    pub fn with_transient(mut self, transient: bool) -> Self {
        self.transient = transient;
        self
    }

    /// Sets the help topic.
    pub fn with_help_topic(mut self, topic: impl Into<String>) -> Self {
        self.help_topic = Some(topic.into());
        self
    }

    /// Sets the window menu group.
    pub fn with_window_menu_group(mut self, group: impl Into<String>) -> Self {
        self.window_menu_group = Some(group.into());
        self
    }
}

impl fmt::Display for ComponentProviderDescription {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} [{}] ({})", self.name, self.owner, self.format_type)
    }
}

// ---------------------------------------------------------------------------
// FactoryError
// ---------------------------------------------------------------------------

/// Errors that can occur during component provider creation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FactoryError {
    /// The factory name was not recognized.
    UnknownFactory(String),
    /// The requested provider is not supported by this factory.
    UnsupportedProvider(String),
    /// The plugin tool is not available.
    ToolNotAvailable,
    /// A required service is missing.
    MissingService(String),
    /// The component creation failed for another reason.
    CreationFailed(String),
}

impl fmt::Display for FactoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FactoryError::UnknownFactory(name) => {
                write!(f, "Unknown factory: {}", name)
            }
            FactoryError::UnsupportedProvider(name) => {
                write!(f, "Unsupported provider: {}", name)
            }
            FactoryError::ToolNotAvailable => {
                write!(f, "Plugin tool not available")
            }
            FactoryError::MissingService(name) => {
                write!(f, "Missing required service: {}", name)
            }
            FactoryError::CreationFailed(msg) => {
                write!(f, "Component creation failed: {}", msg)
            }
        }
    }
}

impl std::error::Error for FactoryError {}

// ---------------------------------------------------------------------------
// ComponentFactory trait
// ---------------------------------------------------------------------------

/// Trait for creating component providers.
///
/// A component factory is registered with the tool and used to create
/// new instances of component providers when needed.
///
/// Ported from `ghidra.app.factory.ComponentFactory`.
pub trait ComponentFactory: std::fmt::Debug + Send + Sync {
    /// The name of this factory.
    fn name(&self) -> &str;

    /// Returns the set of provider names this factory can create.
    fn supported_providers(&self) -> Vec<String>;

    /// Create a new component provider instance.
    ///
    /// # Parameters
    ///
    /// * `provider_name` -- the name of the provider to create
    /// * `tool_name` -- the name of the tool requesting the provider
    ///
    /// # Returns
    ///
    /// A description of the newly created provider, or an error.
    fn create_provider(
        &self,
        provider_name: &str,
        tool_name: &str,
    ) -> Result<ComponentProviderDescription, FactoryError>;

    /// Returns the format type for a given provider.
    fn format_type_for(&self, provider_name: &str) -> Option<FormatType> {
        let _ = provider_name;
        None
    }
}

// ---------------------------------------------------------------------------
// DefaultComponentFactory
// ---------------------------------------------------------------------------

/// Default factory implementation that creates component providers
/// from a registered set of provider descriptions.
///
/// Ported from `ghidra.app.factory.DefaultComponentFactory`.
#[derive(Debug)]
pub struct DefaultComponentFactory {
    factory_name: String,
    providers: HashMap<String, ComponentProviderDescription>,
}

impl DefaultComponentFactory {
    /// Creates a new factory with the given name.
    pub fn new(factory_name: impl Into<String>) -> Self {
        Self {
            factory_name: factory_name.into(),
            providers: HashMap::new(),
        }
    }

    /// Registers a provider with this factory.
    pub fn register_provider(&mut self, description: ComponentProviderDescription) {
        self.providers.insert(description.name.clone(), description);
    }

    /// Returns the number of registered providers.
    pub fn provider_count(&self) -> usize {
        self.providers.len()
    }
}

impl ComponentFactory for DefaultComponentFactory {
    fn name(&self) -> &str {
        &self.factory_name
    }

    fn supported_providers(&self) -> Vec<String> {
        self.providers.keys().cloned().collect()
    }

    fn create_provider(
        &self,
        provider_name: &str,
        tool_name: &str,
    ) -> Result<ComponentProviderDescription, FactoryError> {
        match self.providers.get(provider_name) {
            Some(desc) => {
                let mut result = desc.clone();
                result.name = format!("{} for {}", desc.name, tool_name);
                Ok(result)
            }
            None => Err(FactoryError::UnsupportedProvider(
                provider_name.to_string(),
            )),
        }
    }

    fn format_type_for(&self, provider_name: &str) -> Option<FormatType> {
        self.providers.get(provider_name).map(|d| d.format_type)
    }
}

// ---------------------------------------------------------------------------
// FactoryManager
// ---------------------------------------------------------------------------

/// Manages registered component factories.
///
/// This corresponds to the factory management logic in Ghidra's
/// `PluginTool`.
#[derive(Debug)]
pub struct FactoryManager {
    factories: HashMap<String, Box<dyn ComponentFactory>>,
}

impl FactoryManager {
    /// Creates a new empty factory manager.
    pub fn new() -> Self {
        Self {
            factories: HashMap::new(),
        }
    }

    /// Registers a factory.
    pub fn register(&mut self, factory: Box<dyn ComponentFactory>) {
        let name = factory.name().to_string();
        self.factories.insert(name, factory);
    }

    /// Returns whether a factory with the given name exists.
    pub fn has_factory(&self, name: &str) -> bool {
        self.factories.contains_key(name)
    }

    /// Returns the number of registered factories.
    pub fn count(&self) -> usize {
        self.factories.len()
    }

    /// Creates a provider using the named factory.
    pub fn create_provider(
        &self,
        factory_name: &str,
        provider_name: &str,
        tool_name: &str,
    ) -> Result<ComponentProviderDescription, FactoryError> {
        match self.factories.get(factory_name) {
            Some(factory) => factory.create_provider(provider_name, tool_name),
            None => Err(FactoryError::UnknownFactory(factory_name.to_string())),
        }
    }

    /// Lists all registered factory names.
    pub fn factory_names(&self) -> Vec<&str> {
        self.factories.keys().map(|s| s.as_str()).collect()
    }

    /// Lists all provider names across all factories.
    pub fn all_provider_names(&self) -> Vec<String> {
        self.factories
            .values()
            .flat_map(|f| f.supported_providers())
            .collect()
    }
}

impl Default for FactoryManager {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // --- FormatType ---

    #[test]
    fn test_format_type_display() {
        assert_eq!(format!("{}", FormatType::Table), "Table");
        assert_eq!(format!("{}", FormatType::Tree), "Tree");
        assert_eq!(format!("{}", FormatType::Listing), "Listing");
        assert_eq!(format!("{}", FormatType::Graph), "Graph");
        assert_eq!(format!("{}", FormatType::Image), "Image");
        assert_eq!(format!("{}", FormatType::Other), "Other");
    }

    #[test]
    fn test_format_type_equality() {
        assert_eq!(FormatType::Table, FormatType::Table);
        assert_ne!(FormatType::Table, FormatType::Tree);
    }

    // --- ComponentProviderDescription ---

    #[test]
    fn test_provider_description_basic() {
        let desc = ComponentProviderDescription::new("CodeBrowser", "CodeBrowserPlugin", FormatType::Listing);
        assert_eq!(desc.name, "CodeBrowser");
        assert_eq!(desc.owner, "CodeBrowserPlugin");
        assert_eq!(desc.format_type, FormatType::Listing);
        assert!(!desc.supports_multiple_instances);
        assert!(!desc.transient);
    }

    #[test]
    fn test_provider_description_builder() {
        let desc = ComponentProviderDescription::new("SymTable", "SymTablePlugin", FormatType::Table)
            .with_multiple_instances(true)
            .with_transient(true)
            .with_help_topic("SymbolTable")
            .with_window_menu_group("Symbol");

        assert!(desc.supports_multiple_instances);
        assert!(desc.transient);
        assert_eq!(desc.help_topic.as_deref(), Some("SymbolTable"));
        assert_eq!(desc.window_menu_group.as_deref(), Some("Symbol"));
    }

    #[test]
    fn test_provider_description_display() {
        let desc = ComponentProviderDescription::new("Test", "Plugin", FormatType::Graph);
        let s = format!("{}", desc);
        assert!(s.contains("Test"));
        assert!(s.contains("Graph"));
    }

    // --- FactoryError ---

    #[test]
    fn test_factory_error_display() {
        let err = FactoryError::UnknownFactory("FooFactory".to_string());
        assert!(format!("{}", err).contains("FooFactory"));

        let err = FactoryError::MissingService("GoToService".to_string());
        assert!(format!("{}", err).contains("GoToService"));

        let err = FactoryError::ToolNotAvailable;
        assert!(format!("{}", err).contains("not available"));
    }

    #[test]
    fn test_factory_error_is_std_error() {
        let err: Box<dyn std::error::Error> =
            Box::new(FactoryError::CreationFailed("test".to_string()));
        assert!(err.to_string().contains("test"));
    }

    // --- DefaultComponentFactory ---

    #[test]
    fn test_default_factory_create() {
        let mut factory = DefaultComponentFactory::new("CodeBrowserFactory");
        factory.register_provider(
            ComponentProviderDescription::new("CodeViewer", "CodeBrowserPlugin", FormatType::Listing),
        );
        factory.register_provider(
            ComponentProviderDescription::new("Minimap", "OverviewPlugin", FormatType::Image),
        );

        assert_eq!(factory.provider_count(), 2);
        assert_eq!(factory.name(), "CodeBrowserFactory");

        let providers = factory.supported_providers();
        assert_eq!(providers.len(), 2);
    }

    #[test]
    fn test_default_factory_create_provider() {
        let mut factory = DefaultComponentFactory::new("TestFactory");
        factory.register_provider(
            ComponentProviderDescription::new("TableView", "TablePlugin", FormatType::Table),
        );

        let result = factory.create_provider("TableView", "MyTool");
        assert!(result.is_ok());
        let desc = result.unwrap();
        assert!(desc.name.contains("TableView"));
        assert!(desc.name.contains("MyTool"));
    }

    #[test]
    fn test_default_factory_unsupported_provider() {
        let factory = DefaultComponentFactory::new("EmptyFactory");
        let result = factory.create_provider("NonExistent", "Tool");
        assert!(result.is_err());
        match result.unwrap_err() {
            FactoryError::UnsupportedProvider(name) => assert_eq!(name, "NonExistent"),
            _ => panic!("Expected UnsupportedProvider"),
        }
    }

    #[test]
    fn test_default_factory_format_type() {
        let mut factory = DefaultComponentFactory::new("TestFactory");
        factory.register_provider(
            ComponentProviderDescription::new("GraphView", "GraphPlugin", FormatType::Graph),
        );

        assert_eq!(factory.format_type_for("GraphView"), Some(FormatType::Graph));
        assert_eq!(factory.format_type_for("Unknown"), None);
    }

    // --- FactoryManager ---

    #[test]
    fn test_factory_manager_register_and_lookup() {
        let mut mgr = FactoryManager::new();
        assert_eq!(mgr.count(), 0);

        let mut f1 = DefaultComponentFactory::new("CodeBrowserFactory");
        f1.register_provider(
            ComponentProviderDescription::new("CodeViewer", "CBPlugin", FormatType::Listing),
        );
        mgr.register(Box::new(f1));

        assert_eq!(mgr.count(), 1);
        assert!(mgr.has_factory("CodeBrowserFactory"));
        assert!(!mgr.has_factory("NonExistent"));
    }

    #[test]
    fn test_factory_manager_create_provider() {
        let mut mgr = FactoryManager::new();
        let mut f = DefaultComponentFactory::new("TableFactory");
        f.register_provider(
            ComponentProviderDescription::new("SymbolTable", "SymTablePlugin", FormatType::Table),
        );
        mgr.register(Box::new(f));

        let result = mgr.create_provider("TableFactory", "SymbolTable", "TestTool");
        assert!(result.is_ok());
        let desc = result.unwrap();
        assert!(desc.name.contains("TestTool"));
    }

    #[test]
    fn test_factory_manager_unknown_factory() {
        let mgr = FactoryManager::new();
        let result = mgr.create_provider("NoSuchFactory", "provider", "tool");
        assert!(result.is_err());
    }

    #[test]
    fn test_factory_manager_list_names() {
        let mut mgr = FactoryManager::new();
        let mut f1 = DefaultComponentFactory::new("Factory1");
        f1.register_provider(
            ComponentProviderDescription::new("Provider1", "Plugin1", FormatType::Table),
        );
        let mut f2 = DefaultComponentFactory::new("Factory2");
        f2.register_provider(
            ComponentProviderDescription::new("Provider2", "Plugin2", FormatType::Tree),
        );
        mgr.register(Box::new(f1));
        mgr.register(Box::new(f2));

        let names = mgr.factory_names();
        assert_eq!(names.len(), 2);

        let providers = mgr.all_provider_names();
        assert_eq!(providers.len(), 2);
    }

    // --- Integration ---

    #[test]
    fn test_integration_factory_lifecycle() {
        let mut mgr = FactoryManager::new();

        // Register a factory with multiple providers
        let mut factory = DefaultComponentFactory::new("AnalysisFactory");
        factory.register_provider(
            ComponentProviderDescription::new("ByteViewer", "ByteViewerPlugin", FormatType::Listing)
                .with_help_topic("ByteViewer"),
        );
        factory.register_provider(
            ComponentProviderDescription::new("EntropyPlot", "EntropyPlugin", FormatType::Graph)
                .with_transient(true),
        );
        factory.register_provider(
            ComponentProviderDescription::new("StringsTable", "StringsPlugin", FormatType::Table)
                .with_multiple_instances(true),
        );
        mgr.register(Box::new(factory));

        // Create providers
        let bv = mgr.create_provider("AnalysisFactory", "ByteViewer", "MainTool").unwrap();
        assert_eq!(bv.format_type, FormatType::Listing);

        let entropy = mgr.create_provider("AnalysisFactory", "EntropyPlot", "MainTool").unwrap();
        assert_eq!(entropy.format_type, FormatType::Graph);
        assert!(entropy.transient);

        let strings = mgr.create_provider("AnalysisFactory", "StringsTable", "MainTool").unwrap();
        assert!(strings.supports_multiple_instances);

        // Unknown factory
        assert!(mgr.create_provider("NoFactory", "x", "t").is_err());

        // All providers listed
        assert_eq!(mgr.all_provider_names().len(), 3);
    }
}
