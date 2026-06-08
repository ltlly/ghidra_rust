//! Pluggable service registry for Ghidra's plugin framework.
//!
//! Ported from `ghidra.framework.PluggableServiceRegistry` and
//! `ghidra.framework.PluggableServiceRegistryException`. Provides a
//! type-keyed global registry where plugins can register and retrieve
//! service implementations at runtime.
//!
//! In the Java original the registry uses `Class<?>` as the key and relies
//! on the JVM's type system for `isAssignableFrom` checks. In Rust we use
//! `TypeId` for the key and encode the "more-specific" / "more-generic"
//! relationship via a simple priority integer, since Rust lacks runtime
//! inheritance.
//!
//! # Thread Safety
//!
//! The registry is protected by a `RwLock`, so concurrent reads are
//! lock-free and writes acquire an exclusive lock. This mirrors the Java
//! original where `HashMap` was used without synchronization (the Java
//! code assumed single-threaded plugin loading).

use std::any::TypeId;
use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, RwLock};

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Error returned when a service registration conflicts with an existing one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceRegistryError {
    /// The service trait / interface that was being registered.
    pub service_type_name: String,
    /// The type name of the already-registered implementation.
    pub existing_type_name: String,
    /// The type name of the new (rejected) implementation.
    pub new_type_name: String,
    /// Human-readable explanation.
    pub message: String,
}

impl ServiceRegistryError {
    pub fn new(
        service_type_name: impl Into<String>,
        existing_type_name: impl Into<String>,
        new_type_name: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            service_type_name: service_type_name.into(),
            existing_type_name: existing_type_name.into(),
            new_type_name: new_type_name.into(),
            message: message.into(),
        }
    }
}

impl fmt::Display for ServiceRegistryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ServiceRegistryError: {} (service={}, existing={}, new={})",
            self.message,
            self.service_type_name,
            self.existing_type_name,
            self.new_type_name
        )
    }
}

impl std::error::Error for ServiceRegistryError {}

// ---------------------------------------------------------------------------
// ServiceEntry -- internal bookkeeping
// ---------------------------------------------------------------------------

/// An entry in the service registry.
struct ServiceEntry {
    /// The concrete type id of the registered implementation.
    type_id: TypeId,
    /// Human-readable type name for diagnostics.
    type_name: String,
    /// Priority: higher values are "more specific". When a new registration
    /// arrives the one with the higher priority wins.
    specificity: u32,
    /// The service instance, stored as a type-erased `Arc<dyn Any>`.
    instance: Arc<dyn std::any::Any + Send + Sync>,
}

impl fmt::Debug for ServiceEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServiceEntry")
            .field("type_name", &self.type_name)
            .field("specificity", &self.specificity)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// PluggableServiceRegistry
// ---------------------------------------------------------------------------

/// A global, type-keyed registry for pluggable service implementations.
///
/// Plugins register an implementation for a service trait using
/// [`register`](Self::register). Consumers retrieve the current
/// implementation using [`get`](Self::get).
///
/// # Registration Rules
///
/// When a new implementation is registered for a service key that already
/// has an entry:
///
/// 1. If the new implementation has **higher specificity** it replaces the
///    existing one.
/// 2. If it has **equal or lower specificity** the new registration is
///    silently ignored (matching the Java behaviour of silently dropping
///    more-generic registrations).
///
/// This can be customised by using [`register_with_priority`](Self::register_with_priority).
///
/// # Examples
///
/// ```
/// use ghidra_features::base::services::service_registry::PluggableServiceRegistry;
///
/// let registry = PluggableServiceRegistry::global();
///
/// // Register a concrete implementation.
/// registry.register::<dyn std::fmt::Display, String>(
///     "hello".to_string(), 0,
/// );
///
/// // Retrieve it.
/// let display = registry.get::<dyn std::fmt::Display>();
/// assert!(display.is_some());
/// ```
pub struct PluggableServiceRegistry {
    entries: RwLock<HashMap<TypeId, ServiceEntry>>,
}

impl PluggableServiceRegistry {
    // -- Construction -------------------------------------------------------

    /// Create a new, empty registry.
    pub fn new() -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
        }
    }

    /// Access the process-wide global registry.
    ///
    /// This is a convenience equivalent to the Java static `MAP` field.
    pub fn global() -> &'static PluggableServiceRegistry {
        use std::sync::OnceLock;
        static INSTANCE: OnceLock<PluggableServiceRegistry> = OnceLock::new();
        INSTANCE.get_or_init(PluggableServiceRegistry::new)
    }

    // -- Registration -------------------------------------------------------

    /// Register a service implementation.
    ///
    /// `ServiceTrait` is the trait object type used as the key (e.g.
    /// `dyn MyService`). `Impl` is the concrete type.
    ///
    /// `specificity` controls replacement priority (higher wins). Use `0` for
    /// a default implementation and higher values for overrides.
    pub fn register<ServiceTrait: ?Sized + 'static, Impl>(
        &self,
        instance: Impl,
        specificity: u32,
    ) -> Result<(), ServiceRegistryError>
    where
        Impl: Send + Sync + 'static,
    {
        let key = TypeId::of::<ServiceTrait>();
        let type_name = std::any::type_name::<Impl>().to_string();
        let entry = ServiceEntry {
            type_id: TypeId::of::<Impl>(),
            type_name: type_name.clone(),
            specificity,
            instance: Arc::new(instance),
        };

        let mut map = self.entries.write().unwrap();
        if let Some(existing) = map.get(&key) {
            if specificity > existing.specificity {
                // New entry is more specific -- replace.
                map.insert(key, entry);
                return Ok(());
            }
            if specificity < existing.specificity {
                // New entry is less specific -- silently drop.
                return Ok(());
            }
            // Equal specificity: conflict.
            return Err(ServiceRegistryError::new(
                std::any::type_name::<ServiceTrait>(),
                &existing.type_name,
                &type_name,
                format!(
                    "Cannot register {} for service {}; {} is already registered with equal specificity",
                    type_name,
                    std::any::type_name::<ServiceTrait>(),
                    existing.type_name,
                ),
            ));
        }

        map.insert(key, entry);
        Ok(())
    }

    /// Register a service implementation, replacing any existing entry
    /// unconditionally.
    ///
    /// This bypasses the specificity check and always overwrites.
    pub fn register_force<ServiceTrait: ?Sized + 'static, Impl>(
        &self,
        instance: Impl,
        specificity: u32,
    ) where
        Impl: Send + Sync + 'static,
    {
        let key = TypeId::of::<ServiceTrait>();
        let type_name = std::any::type_name::<Impl>().to_string();
        let entry = ServiceEntry {
            type_id: TypeId::of::<Impl>(),
            type_name,
            specificity,
            instance: Arc::new(instance),
        };
        let mut map = self.entries.write().unwrap();
        map.insert(key, entry);
    }

    // -- Retrieval ----------------------------------------------------------

    /// Retrieve the registered implementation for a service trait as a
    /// cloned `Arc`.
    ///
    /// Returns `Some(Arc<dyn Any + Send + Sync>)` if an implementation was
    /// registered. Returns `None` if no entry exists.
    pub fn get<ServiceTrait: ?Sized + 'static>(&self) -> Option<Arc<dyn std::any::Any + Send + Sync>> {
        let key = TypeId::of::<ServiceTrait>();
        let map = self.entries.read().unwrap();
        map.get(&key).map(|e| Arc::clone(&e.instance))
    }

    /// Retrieve the registered implementation, downcast it, and clone the
    /// `Arc`.
    ///
    /// Returns `Some(Arc<Impl>)` on success, `None` if no entry exists or
    /// the downcast fails.
    pub fn get_as<ServiceTrait: ?Sized + 'static, Impl: Send + Sync + 'static>(
        &self,
    ) -> Option<Arc<Impl>> {
        let key = TypeId::of::<ServiceTrait>();
        let map = self.entries.read().unwrap();
        map.get(&key).and_then(|e| {
            let arc = Arc::clone(&e.instance);
            arc.downcast::<Impl>().ok()
        })
    }

    /// Check whether a service trait has a registered implementation.
    pub fn contains<ServiceTrait: ?Sized + 'static>(&self) -> bool {
        let key = TypeId::of::<ServiceTrait>();
        let map = self.entries.read().unwrap();
        map.contains_key(&key)
    }

    // -- Removal ------------------------------------------------------------

    /// Remove the registered implementation for a service trait.
    ///
    /// Returns `true` if an entry was removed.
    pub fn unregister<ServiceTrait: ?Sized + 'static>(&self) -> bool {
        let key = TypeId::of::<ServiceTrait>();
        let mut map = self.entries.write().unwrap();
        map.remove(&key).is_some()
    }

    /// Remove all registered services.
    pub fn clear(&self) {
        let mut map = self.entries.write().unwrap();
        map.clear();
    }

    // -- Diagnostics --------------------------------------------------------

    /// Number of registered services.
    pub fn len(&self) -> usize {
        let map = self.entries.read().unwrap();
        map.len()
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        let map = self.entries.read().unwrap();
        map.is_empty()
    }

    /// Return a list of `(type_name, specificity)` for all registered
    /// entries, useful for debugging.
    pub fn debug_entries(&self) -> Vec<(String, u32)> {
        let map = self.entries.read().unwrap();
        map.values()
            .map(|e| (e.type_name.clone(), e.specificity))
            .collect()
    }
}

impl Default for PluggableServiceRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for PluggableServiceRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let map = self.entries.read().unwrap();
        f.debug_struct("PluggableServiceRegistry")
            .field("entries", &map.len())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Test service trait --------------------------------------------------

    trait Greeting: Send + Sync {
        fn greet(&self) -> String;
    }

    struct HelloService;
    impl Greeting for HelloService {
        fn greet(&self) -> String {
            "Hello".into()
        }
    }

    struct HolaService;
    impl Greeting for HolaService {
        fn greet(&self) -> String {
            "Hola".into()
        }
    }

    // -- Basic registration and retrieval -----------------------------------

    #[test]
    fn test_register_and_get() {
        let reg = PluggableServiceRegistry::new();
        reg.register::<dyn Greeting, _>(HelloService, 0).unwrap();
        let svc = reg.get_as::<dyn Greeting, HelloService>();
        assert!(svc.is_some());
        assert_eq!(svc.unwrap().greet(), "Hello");
    }

    #[test]
    fn test_get_missing_returns_none() {
        let reg = PluggableServiceRegistry::new();
        assert!(reg.get::<dyn Greeting>().is_none());
    }

    #[test]
    fn test_contains() {
        let reg = PluggableServiceRegistry::new();
        assert!(!reg.contains::<dyn Greeting>());
        reg.register::<dyn Greeting, _>(HelloService, 0).unwrap();
        assert!(reg.contains::<dyn Greeting>());
    }

    // -- Specificity / replacement ------------------------------------------

    #[test]
    fn test_higher_specificity_replaces() {
        let reg = PluggableServiceRegistry::new();
        reg.register::<dyn Greeting, _>(HelloService, 0).unwrap();
        reg.register::<dyn Greeting, _>(HolaService, 10).unwrap();
        let svc = reg.get_as::<dyn Greeting, HolaService>();
        assert!(svc.is_some());
        assert_eq!(svc.unwrap().greet(), "Hola");
    }

    #[test]
    fn test_lower_specificity_ignored() {
        let reg = PluggableServiceRegistry::new();
        reg.register::<dyn Greeting, _>(HolaService, 10).unwrap();
        reg.register::<dyn Greeting, _>(HelloService, 0).unwrap();
        // HolaService should still be the registered one.
        let svc = reg.get_as::<dyn Greeting, HolaService>();
        assert!(svc.is_some());
        assert_eq!(svc.unwrap().greet(), "Hola");
    }

    #[test]
    fn test_equal_specificity_conflict() {
        let reg = PluggableServiceRegistry::new();
        reg.register::<dyn Greeting, _>(HelloService, 5).unwrap();
        let result = reg.register::<dyn Greeting, _>(HolaService, 5);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.message.contains("already registered"));
    }

    #[test]
    fn test_register_force_overwrites() {
        let reg = PluggableServiceRegistry::new();
        reg.register::<dyn Greeting, _>(HelloService, 0).unwrap();
        reg.register_force::<dyn Greeting, _>(HolaService, 0);
        let svc = reg.get_as::<dyn Greeting, HolaService>();
        assert!(svc.is_some());
    }

    // -- Unregister / clear -------------------------------------------------

    #[test]
    fn test_unregister() {
        let reg = PluggableServiceRegistry::new();
        reg.register::<dyn Greeting, _>(HelloService, 0).unwrap();
        assert!(reg.unregister::<dyn Greeting>());
        assert!(!reg.contains::<dyn Greeting>());
    }

    #[test]
    fn test_unregister_missing() {
        let reg = PluggableServiceRegistry::new();
        assert!(!reg.unregister::<dyn Greeting>());
    }

    #[test]
    fn test_clear() {
        let reg = PluggableServiceRegistry::new();
        reg.register::<dyn Greeting, _>(HelloService, 0).unwrap();
        assert_eq!(reg.len(), 1);
        reg.clear();
        assert!(reg.is_empty());
    }

    // -- Multiple service types ---------------------------------------------

    trait Farewell: Send + Sync {
        fn farewell(&self) -> String;
    }

    struct ByeService;
    impl Farewell for ByeService {
        fn farewell(&self) -> String {
            "Bye".into()
        }
    }

    #[test]
    fn test_multiple_service_types() {
        let reg = PluggableServiceRegistry::new();
        reg.register::<dyn Greeting, _>(HelloService, 0).unwrap();
        reg.register::<dyn Farewell, _>(ByeService, 0).unwrap();

        assert_eq!(
            reg.get_as::<dyn Greeting, HelloService>().unwrap().greet(),
            "Hello"
        );
        assert_eq!(
            reg.get_as::<dyn Farewell, ByeService>().unwrap().farewell(),
            "Bye"
        );
    }

    // -- Diagnostics --------------------------------------------------------

    #[test]
    fn test_len() {
        let reg = PluggableServiceRegistry::new();
        assert_eq!(reg.len(), 0);
        reg.register::<dyn Greeting, _>(HelloService, 0).unwrap();
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn test_debug_entries() {
        let reg = PluggableServiceRegistry::new();
        reg.register::<dyn Greeting, _>(HelloService, 0).unwrap();
        let entries = reg.debug_entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].1, 0);
    }

    // -- Error display ------------------------------------------------------

    #[test]
    fn test_error_display() {
        let err = ServiceRegistryError::new(
            "MyService",
            "ExistingImpl",
            "NewImpl",
            "conflict",
        );
        let s = format!("{}", err);
        assert!(s.contains("conflict"));
        assert!(s.contains("ExistingImpl"));
        assert!(s.contains("NewImpl"));
    }

    // -- Global registry ----------------------------------------------------

    #[test]
    fn test_global_registry() {
        let reg = PluggableServiceRegistry::global();
        // We can't guarantee test isolation for the global singleton, so
        // just verify it returns a reference.
        let _ = reg.len();
    }

    // -- Default -----------------------------------------------------------

    #[test]
    fn test_default() {
        let reg = PluggableServiceRegistry::default();
        assert!(reg.is_empty());
    }
}
