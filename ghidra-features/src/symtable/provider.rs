//! Symbol Table Provider and Panel -- ported from `SymbolProvider` and
//! `SymbolPanel`.
//!
//! The provider wraps the table model and handles display configuration.

/// Configuration for the symbol table display.
///
/// Ported from Ghidra's `SymbolPanel` configuration.
#[derive(Debug, Clone)]
pub struct SymbolTableConfig {
    /// Show addresses in hex format.
    pub show_address_hex: bool,
    /// Show the namespace column.
    pub show_namespace: bool,
    /// Show the source column.
    pub show_source: bool,
    /// Show the primary column.
    pub show_primary: bool,
    /// Auto-size columns.
    pub auto_size_columns: bool,
    /// Row height in pixels.
    pub row_height: i32,
}

impl Default for SymbolTableConfig {
    fn default() -> Self {
        Self {
            show_address_hex: true,
            show_namespace: true,
            show_source: true,
            show_primary: true,
            auto_size_columns: true,
            row_height: 20,
        }
    }
}

/// The symbol table provider.
///
/// Ported from Ghidra's `SymbolProvider`.  Manages the lifecycle of
/// the symbol table panel and coordinates with the plugin.
#[derive(Debug)]
pub struct SymbolTableProvider {
    /// The provider name.
    name: String,
    /// The configuration.
    config: SymbolTableConfig,
    /// Whether the provider is visible.
    visible: bool,
    /// The associated program name.
    program_name: Option<String>,
}

impl SymbolTableProvider {
    /// Creates a new symbol table provider.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            config: SymbolTableConfig::default(),
            visible: false,
            program_name: None,
        }
    }

    /// Returns the provider name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the configuration.
    pub fn config(&self) -> &SymbolTableConfig {
        &self.config
    }

    /// Returns a mutable reference to the configuration.
    pub fn config_mut(&mut self) -> &mut SymbolTableConfig {
        &mut self.config
    }

    /// Returns whether the provider is visible.
    pub fn is_visible(&self) -> bool {
        self.visible
    }

    /// Sets the visibility.
    pub fn set_visible(&mut self, visible: bool) {
        self.visible = visible;
    }

    /// Sets the program name.
    pub fn set_program_name(&mut self, name: Option<String>) {
        self.program_name = name;
    }

    /// Returns the program name.
    pub fn program_name(&self) -> Option<&str> {
        self.program_name.as_deref()
    }

    /// Disposes the provider.
    pub fn dispose(&mut self) {
        self.visible = false;
        self.program_name = None;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_creation() {
        let provider = SymbolTableProvider::new("TestProvider");
        assert_eq!(provider.name(), "TestProvider");
        assert!(!provider.is_visible());
        assert!(provider.program_name().is_none());
    }

    #[test]
    fn test_provider_visibility() {
        let mut provider = SymbolTableProvider::new("Test");
        provider.set_visible(true);
        assert!(provider.is_visible());
        provider.dispose();
        assert!(!provider.is_visible());
    }

    #[test]
    fn test_provider_config() {
        let mut provider = SymbolTableProvider::new("Test");
        assert!(provider.config().show_address_hex);
        provider.config_mut().show_address_hex = false;
        assert!(!provider.config().show_address_hex);
    }

    #[test]
    fn test_provider_program() {
        let mut provider = SymbolTableProvider::new("Test");
        provider.set_program_name(Some("test.exe".to_string()));
        assert_eq!(provider.program_name(), Some("test.exe"));
    }

    #[test]
    fn test_config_default() {
        let config = SymbolTableConfig::default();
        assert!(config.show_address_hex);
        assert!(config.show_namespace);
        assert!(config.auto_size_columns);
        assert_eq!(config.row_height, 20);
    }
}
