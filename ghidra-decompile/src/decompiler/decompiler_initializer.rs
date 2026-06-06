//! Module initializer for the decompiler plugin.
//!
//! Port of `decompiler/DecompilerInitializer.java`.
//!
//! In Ghidra's Java world this is a `ModuleInitializer` that runs at startup
//! and registers the `DecompilerCommentsActionFactory` as a pluggable service
//! so that the comments subsystem knows about the decompiler's special
//! comment handling.
//!
//! In Rust we provide the same capability via a `lazy_static` registry
//! that other crates can consult at runtime.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

// ---------------------------------------------------------------------------
// Pluggable service registry (Rust equivalent of Java's PluggableServiceRegistry)
// ---------------------------------------------------------------------------

/// A type-erased pluggable service entry.
type BoxedService = Box<dyn std::any::Any + Send + Sync>;

/// Global registry of pluggable services, keyed by service name.
fn registry() -> &'static Mutex<HashMap<String, BoxedService>> {
    static INSTANCE: OnceLock<Mutex<HashMap<String, BoxedService>>> = OnceLock::new();
    INSTANCE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Register a pluggable service by name.
///
/// Equivalent to `PluggableServiceRegistry.registerPluggableService(...)` in Java.
pub fn register_pluggable_service(name: impl Into<String>, service: BoxedService) {
    let mut map = registry().lock().unwrap();
    map.insert(name.into(), service);
}

/// Look up a previously registered pluggable service by name, returning
/// a guard that holds the registry lock for the duration of the borrow.
///
/// Because `dyn Any + Send + Sync` is not `Clone`, callers obtain a
/// reference through the returned guard rather than an owned value.
pub fn with_pluggable_service<R>(
    name: &str,
    f: impl FnOnce(Option<&BoxedService>) -> R,
) -> R {
    let map = registry().lock().unwrap();
    f(map.get(name))
}

/// Look up a previously registered pluggable service by name.
///
/// Returns `true` if the service was found; `false` otherwise.  Because
/// `dyn Any + Send + Sync` is not `Clone`, callers should prefer
/// [`with_pluggable_service`] for inspecting the value.
pub fn get_pluggable_service(name: &str) -> Option<()> {
    let map = registry().lock().unwrap();
    if map.contains_key(name) { Some(()) } else { None }
}

/// Attempt to downcast a registered service to a concrete type.
///
/// Returns `Some(T)` if the service exists and is of type `T`, `None` otherwise.
pub fn get_pluggable_service_as<T: std::any::Any + Clone>(
    name: &str,
) -> Option<T> {
    let map = registry().lock().unwrap();
    map.get(name).and_then(|s| s.downcast_ref::<T>()).cloned()
}

/// Returns true if a service with the given name is registered.
pub fn has_pluggable_service(name: &str) -> bool {
    let map = registry().lock().unwrap();
    map.contains_key(name)
}

// ---------------------------------------------------------------------------
// DecompilerCommentsActionFactory (stub)
// ---------------------------------------------------------------------------

/// The decompiler's comments action factory.
///
/// In Ghidra Java this creates decompiler-specific "set comment" actions
/// that interact with the decompiler's internal representation of comments.
/// We provide a stub that records the registration.
#[derive(Debug, Clone)]
pub struct DecompilerCommentsActionFactory {
    /// The action name prefix for decompiler comments.
    pub action_prefix: String,
    /// Whether this factory is currently active.
    pub active: bool,
}

impl DecompilerCommentsActionFactory {
    /// Create a new factory.
    pub fn new() -> Self {
        Self {
            action_prefix: "Decompiler.SetComment".to_string(),
            active: true,
        }
    }
}

impl Default for DecompilerCommentsActionFactory {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// DecompilerInitializer
// ---------------------------------------------------------------------------

/// The module initializer for the Decompiler feature.
///
/// In Java this implements `ModuleInitializer.run()` and registers the
/// decompiler's comments action factory. In Rust we provide the same
/// capability through a `run()` function.
#[derive(Debug)]
pub struct DecompilerInitializer {
    /// Whether the initializer has already run.
    initialized: bool,
}

impl DecompilerInitializer {
    /// Create a new initializer.
    pub fn new() -> Self {
        Self { initialized: false }
    }

    /// Run the initializer.  Registers the decompiler's comments action factory
    /// into the pluggable service registry.
    ///
    /// Calling `run()` more than once is a no-op.
    pub fn run(&mut self) {
        if self.initialized {
            return;
        }
        let factory = DecompilerCommentsActionFactory::new();
        register_pluggable_service(
            "CommentsActionFactory",
            Box::new(factory),
        );
        self.initialized = true;
    }

    /// Whether the initializer has been run.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// The name of this module, matching `getName()` in Java.
    pub fn name(&self) -> &str {
        "Decompiler Module"
    }
}

impl Default for DecompilerInitializer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initializer_starts_uninitialized() {
        let init = DecompilerInitializer::new();
        assert!(!init.is_initialized());
        assert_eq!(init.name(), "Decompiler Module");
    }

    #[test]
    fn initializer_run_sets_initialized() {
        let mut init = DecompilerInitializer::new();
        init.run();
        assert!(init.is_initialized());
    }

    #[test]
    fn initializer_run_twice_is_noop() {
        let mut init = DecompilerInitializer::new();
        init.run();
        init.run(); // should not panic
        assert!(init.is_initialized());
    }

    #[test]
    fn register_and_check_service() {
        // Use a unique name to avoid collisions with other tests
        let name = format!("TestService_{}", std::process::id());
        assert!(!has_pluggable_service(&name));
        register_pluggable_service(name.clone(), Box::new(42i32));
        assert!(has_pluggable_service(&name));
    }

    #[test]
    fn comments_action_factory_default() {
        let factory = DecompilerCommentsActionFactory::default();
        assert_eq!(factory.action_prefix, "Decompiler.SetComment");
        assert!(factory.active);
    }

    #[test]
    fn comments_action_factory_new() {
        let factory = DecompilerCommentsActionFactory::new();
        assert!(factory.active);
    }

    #[test]
    fn get_pluggable_service_returns_none_for_missing() {
        assert!(get_pluggable_service("nonexistent_service_xyz").is_none());
    }

    #[test]
    fn get_pluggable_service_returns_some_for_existing() {
        let name = format!("ExistingSvc_{}", std::process::id());
        register_pluggable_service(name.clone(), Box::new(99u64));
        assert!(get_pluggable_service(&name).is_some());
    }

    #[test]
    fn with_pluggable_service_borrows_value() {
        let name = format!("BorrowSvc_{}", std::process::id());
        register_pluggable_service(name.clone(), Box::new(String::from("hello")));
        let result = with_pluggable_service(&name, |opt| {
            opt.map(|s| s.downcast_ref::<String>().cloned().unwrap_or_default())
        });
        assert_eq!(result, Some("hello".to_string()));
    }

    #[test]
    fn with_pluggable_service_none_for_missing() {
        let result = with_pluggable_service("absent_key_abc", |opt| opt.is_some());
        assert!(!result);
    }

    #[test]
    fn get_pluggable_service_as_downcasts_correctly() {
        let name = format!("DowncastSvc_{}", std::process::id());
        register_pluggable_service(name.clone(), Box::new(42u32));
        let val: Option<u32> = get_pluggable_service_as(&name);
        assert_eq!(val, Some(42u32));
    }

    #[test]
    fn get_pluggable_service_as_wrong_type_returns_none() {
        let name = format!("WrongTypeSvc_{}", std::process::id());
        register_pluggable_service(name.clone(), Box::new(42u32));
        let val: Option<String> = get_pluggable_service_as(&name);
        assert!(val.is_none());
    }

    #[test]
    fn initializer_run_registers_factory() {
        let mut init = DecompilerInitializer::new();
        init.run();
        // The factory is registered under "CommentsActionFactory"
        // Note: this may collide with other tests using the same key,
        // but the test verifies the registration flow works.
        assert!(has_pluggable_service("CommentsActionFactory"));
    }
}
