#![allow(dead_code)]
//! Extended decompiler hover providers.
//!
//! Ports Ghidra's concrete decompiler hover service implementations:
//! - [`DecompilerHoverProvider`] -- the main hover provider that dispatches
//!   to registered hover services.
//! - [`DecompilerCallbackHandlerAdapter`] -- adapter for callback handlers.
//! - [`DecompilerHoverService`] trait -- already ported in hover/mod.rs.

use ghidra_core::addr::Address;
use super::{DecompilerHoverService, HoverResult};

/// The main decompiler hover provider that manages and dispatches to
/// multiple hover services.
///
/// Ports `ghidra.app.decompiler.component.DecompilerHoverProvider`.
/// When the user hovers over a token in the decompiler view, this provider
/// queries all registered hover services and returns the highest-priority result.
pub struct DecompilerHoverProviderManager {
    /// Name of this provider.
    name: String,
    /// Registered hover services.
    services: Vec<Box<dyn DecompilerHoverService>>,
    /// Whether hover is enabled.
    enabled: bool,
}

impl std::fmt::Debug for DecompilerHoverProviderManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DecompilerHoverProviderManager")
            .field("name", &self.name)
            .field("services_count", &self.services.len())
            .field("enabled", &self.enabled)
            .finish()
    }
}

impl DecompilerHoverProviderManager {
    /// Create a new hover provider manager.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            services: Vec::new(),
            enabled: true,
        }
    }

    /// Register a hover service.
    pub fn add_hover_service(&mut self, service: Box<dyn DecompilerHoverService>) {
        self.services.push(service);
        // Sort by priority (highest first)
        self.services.sort_by(|a, b| b.priority().cmp(&a.priority()));
    }

    /// Remove a hover service by name.
    pub fn remove_hover_service(&mut self, name: &str) {
        self.services.retain(|s| s.name() != name);
    }

    /// Get the hover result for a token.
    ///
    /// Queries all registered hover services and returns the result with
    /// the highest priority.
    pub fn get_hover(&self, token_text: &str, address: Address) -> Option<HoverResult> {
        if !self.enabled {
            return None;
        }
        self.services
            .iter()
            .filter_map(|s| s.get_hover(token_text, address))
            .max_by_key(|r| r.priority)
    }

    /// Enable or disable hover.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Whether hover is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Get the number of registered services.
    pub fn service_count(&self) -> usize {
        self.services.len()
    }

    /// Get names of registered services.
    pub fn service_names(&self) -> Vec<&str> {
        self.services.iter().map(|s| s.name()).collect()
    }
}

/// Adapter for decompiler callback handlers.
///
/// Ports `ghidra.app.decompiler.component.DecompilerCallbackHandlerAdapter`.
/// Adapts the decompiler callback interface to the hover service interface.
#[derive(Debug, Clone, Default)]
pub struct DecompilerCallbackHandlerAdapter {
    /// The callback handler name.
    _name: String,
    /// Whether the adapter is active.
    active: bool,
}

impl DecompilerCallbackHandlerAdapter {
    /// Create a new adapter.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            _name: name.into(),
            active: true,
        }
    }

    /// Whether the adapter is active.
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Set the adapter active state.
    pub fn set_active(&mut self, active: bool) {
        self.active = active;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompiler::component::hover::{DataTypeHoverProvider, ScalarValueHoverProvider, ReferenceHoverProvider};

    #[test]
    fn hover_provider_manager_new() {
        let mgr = DecompilerHoverProviderManager::new("TestProvider");
        assert_eq!(mgr.service_count(), 0);
        assert!(mgr.is_enabled());
    }

    #[test]
    fn hover_provider_manager_add_services() {
        let mut mgr = DecompilerHoverProviderManager::new("Test");
        mgr.add_hover_service(Box::new(DataTypeHoverProvider));
        mgr.add_hover_service(Box::new(ScalarValueHoverProvider));
        mgr.add_hover_service(Box::new(ReferenceHoverProvider));
        assert_eq!(mgr.service_count(), 3);
    }

    #[test]
    fn hover_provider_manager_dispatches() {
        let mut mgr = DecompilerHoverProviderManager::new("Test");
        mgr.add_hover_service(Box::new(DataTypeHoverProvider));
        mgr.add_hover_service(Box::new(ScalarValueHoverProvider));

        // Should get the highest-priority result
        let result = mgr.get_hover("int", Address::new(0x1000));
        assert!(result.is_some());
    }

    #[test]
    fn hover_provider_manager_disabled() {
        let mut mgr = DecompilerHoverProviderManager::new("Test");
        mgr.add_hover_service(Box::new(DataTypeHoverProvider));
        mgr.set_enabled(false);
        assert!(!mgr.is_enabled());
        let result = mgr.get_hover("int", Address::new(0));
        assert!(result.is_none());
    }

    #[test]
    fn hover_provider_manager_remove_service() {
        let mut mgr = DecompilerHoverProviderManager::new("Test");
        mgr.add_hover_service(Box::new(DataTypeHoverProvider));
        mgr.add_hover_service(Box::new(ScalarValueHoverProvider));
        assert_eq!(mgr.service_count(), 2);
        mgr.remove_hover_service("DataType Hover");
        assert_eq!(mgr.service_count(), 1);
    }

    #[test]
    fn callback_handler_adapter() {
        let mut adapter = DecompilerCallbackHandlerAdapter::new("test");
        assert!(adapter.is_active());
        adapter.set_active(false);
        assert!(!adapter.is_active());
    }
}
