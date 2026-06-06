//! Service provider and pluggable service registry.
//!
//! Port of `ghidra.framework.plugintool`: ServiceProvider, ServiceProviderDecorator,
//! ServiceProviderStub, ServiceListener, and PluggableServiceRegistry.

use std::any::{Any, TypeId};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// A type-erased service provider that stores and retrieves services by type.
///
/// Port of `ghidra.framework.plugintool.ServiceProvider`.
///
/// In Java, `ServiceProvider` is an interface with generic methods. In Rust,
/// we use a concrete struct with `TypeId`-based lookups for dyn compatibility.
#[derive(Debug)]
pub struct ServiceProvider {
    services: RwLock<HashMap<TypeId, Arc<dyn Any + Send + Sync>>>,
}

impl ServiceProvider {
    /// Create a new service provider.
    pub fn new() -> Self {
        Self {
            services: RwLock::new(HashMap::new()),
        }
    }

    /// Register a service.
    pub fn add_service<T: 'static + Send + Sync>(&self, service: T) {
        if let Ok(mut map) = self.services.write() {
            map.insert(TypeId::of::<T>(), Arc::new(service));
        }
    }

    /// Get a service by type.
    pub fn get_service<T: 'static + Send + Sync>(&self) -> Option<Arc<T>> {
        if let Ok(map) = self.services.read() {
            if let Some(service) = map.get(&TypeId::of::<T>()) {
                return service.clone().downcast::<T>().ok();
            }
        }
        None
    }

    /// Check if a service of the given type is available.
    pub fn has_service<T: 'static + Send + Sync>(&self) -> bool {
        if let Ok(map) = self.services.read() {
            map.contains_key(&TypeId::of::<T>())
        } else {
            false
        }
    }

    /// Remove a service by type.
    pub fn remove_service<T: 'static + Send + Sync>(&self) -> bool {
        if let Ok(mut map) = self.services.write() {
            map.remove(&TypeId::of::<T>()).is_some()
        } else {
            false
        }
    }
}

impl Default for ServiceProvider {
    fn default() -> Self {
        Self::new()
    }
}

/// A decorator that wraps a service provider and can add/override services.
///
/// Port of `ghidra.framework.plugintool.ServiceProviderDecorator`.
pub struct ServiceProviderDecorator {
    /// The wrapped service provider.
    inner: Arc<ServiceProvider>,
    /// Additional or overridden services.
    overrides: HashMap<TypeId, Arc<dyn Any + Send + Sync>>,
}

impl ServiceProviderDecorator {
    /// Create a new decorator wrapping the given provider.
    pub fn new(inner: Arc<ServiceProvider>) -> Self {
        Self {
            inner,
            overrides: HashMap::new(),
        }
    }

    /// Add or override a service.
    pub fn set_service<T: 'static + Send + Sync>(&mut self, service: T) {
        self.overrides.insert(TypeId::of::<T>(), Arc::new(service));
    }

    /// Get a service, checking overrides first, then the inner provider.
    pub fn get_service<T: 'static + Send + Sync>(&self) -> Option<Arc<T>> {
        if let Some(service) = self.overrides.get(&TypeId::of::<T>()) {
            return service.clone().downcast::<T>().ok();
        }
        self.inner.get_service::<T>()
    }

    /// Check if a service is available (in overrides or inner).
    pub fn has_service<T: 'static + Send + Sync>(&self) -> bool {
        self.overrides.contains_key(&TypeId::of::<T>()) || self.inner.has_service::<T>()
    }
}

/// A stub service provider for testing (alias for ServiceProvider).
///
/// Port of `ghidra.framework.plugintool.ServiceProviderStub`.
pub type ServiceProviderStub = ServiceProvider;

/// Listener for service registration/deregistration events.
///
/// Port of `ghidra.framework.plugintool.util.ServiceListener`.
pub trait ServiceListener: Send + Sync {
    /// Called when a service is added.
    fn service_added(&self, service_type_name: &str);

    /// Called when a service is removed.
    fn service_removed(&self, service_type_name: &str);
}

/// Global registry for pluggable service implementations.
///
/// Port of `ghidra.framework.PluggableServiceRegistry`.
#[derive(Debug)]
pub struct PluggableServiceRegistry {
    /// Registered service implementations by type name.
    services: RwLock<HashMap<String, Vec<String>>>,
}

impl PluggableServiceRegistry {
    /// Create a new registry.
    pub fn new() -> Self {
        Self {
            services: RwLock::new(HashMap::new()),
        }
    }

    /// Register a service implementation.
    pub fn register(&self, service_type: &str, implementation: &str) {
        if let Ok(mut map) = self.services.write() {
            map.entry(service_type.to_string())
                .or_default()
                .push(implementation.to_string());
        }
    }

    /// Get all implementations for a service type.
    pub fn get_implementations(&self, service_type: &str) -> Vec<String> {
        if let Ok(map) = self.services.read() {
            map.get(service_type).cloned().unwrap_or_default()
        } else {
            Vec::new()
        }
    }

    /// Check if any implementations are registered for a service type.
    pub fn has_implementations(&self, service_type: &str) -> bool {
        if let Ok(map) = self.services.read() {
            map.get(service_type)
                .map(|v| !v.is_empty())
                .unwrap_or(false)
        } else {
            false
        }
    }
}

impl Default for PluggableServiceRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, PartialEq)]
    struct TestService {
        value: String,
    }

    #[test]
    fn test_service_provider_stub() {
        let stub = ServiceProviderStub::new();
        assert!(!stub.has_service::<TestService>());

        stub.add_service(TestService {
            value: "hello".to_string(),
        });
        assert!(stub.has_service::<TestService>());

        let service = stub.get_service::<TestService>().unwrap();
        assert_eq!(service.value, "hello");
    }

    #[test]
    fn test_service_provider_decorator() {
        let stub = Arc::new(ServiceProviderStub::new());
        stub.add_service(TestService {
            value: "original".to_string(),
        });

        let mut decorator = ServiceProviderDecorator::new(stub);
        assert!(decorator.has_service::<TestService>());

        let s = decorator.get_service::<TestService>().unwrap();
        assert_eq!(s.value, "original");

        // Override
        decorator.set_service(TestService {
            value: "overridden".to_string(),
        });
        let s = decorator.get_service::<TestService>().unwrap();
        assert_eq!(s.value, "overridden");
    }

    #[test]
    fn test_pluggable_service_registry() {
        let registry = PluggableServiceRegistry::new();
        registry.register("DataTypeManager", "DefaultDataTypeManager");
        registry.register("DataTypeManager", "ArchiveDataTypeManager");

        let impls = registry.get_implementations("DataTypeManager");
        assert_eq!(impls.len(), 2);
        assert!(registry.has_implementations("DataTypeManager"));
        assert!(!registry.has_implementations("NonExistent"));
    }
}
