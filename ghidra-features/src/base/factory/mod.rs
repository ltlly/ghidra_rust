//! Plugin component factories.
//!
//! Ported from Ghidra's `ghidra.app.factory` Java package.

/// Trait for creating component providers.
///
/// A component factory is registered with the tool and used to create
/// new instances of component providers when needed.
pub trait ComponentFactory: std::fmt::Debug + Send + Sync {
    /// The name of this factory.
    fn name(&self) -> &str;

    /// Create a new component provider instance.
    fn create_provider(&self, tool_name: &str) -> String;
}

/// Default factory implementation.
#[derive(Debug)]
pub struct DefaultComponentFactory {
    factory_name: String,
    provider_class: String,
}

impl DefaultComponentFactory {
    pub fn new(factory_name: impl Into<String>, provider_class: impl Into<String>) -> Self {
        Self {
            factory_name: factory_name.into(),
            provider_class: provider_class.into(),
        }
    }
}

impl ComponentFactory for DefaultComponentFactory {
    fn name(&self) -> &str {
        &self.factory_name
    }

    fn create_provider(&self, tool_name: &str) -> String {
        format!("{} for {}", self.provider_class, tool_name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_factory() {
        let factory = DefaultComponentFactory::new("CodeBrowser", "CodeBrowserProvider");
        assert_eq!(factory.name(), "CodeBrowser");
        let provider = factory.create_provider("TestTool");
        assert!(provider.contains("CodeBrowserProvider"));
        assert!(provider.contains("TestTool"));
    }
}
