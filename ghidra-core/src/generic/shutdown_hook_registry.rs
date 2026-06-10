//! Priority-ordered shutdown hook manager.
//!
//! Ports Ghidra's shutdown hook infrastructure. Allows components to register
//! cleanup callbacks that are invoked in a deterministic priority order when
//! the application shuts down.
//!
//! Hooks are executed from highest priority to lowest. Hooks with the same
//! priority are executed in registration order. A hook that panics or returns
//! an error does not prevent subsequent hooks from running.

use std::fmt;
use std::sync::{Arc, Mutex, OnceLock};

// ============================================================================
// Types
// ============================================================================

/// Priority level for shutdown hooks.
///
/// Higher values execute first. The built-in levels provide conventional
/// ordering:
///
/// | Level | Value | Purpose |
/// |-------|-------|---------|
/// | `First` | 1000 | Critical cleanup that must happen before anything else |
/// | `High` | 750 | High-priority teardown (database connections, locks) |
/// | `Normal` | 500 | Default priority for most hooks |
/// | `Low` | 250 | Low-priority cleanup (caches, temp files) |
/// | `Last` | 0 | Final cleanup that must happen after everything else |
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ShutdownPriority {
    /// Last hooks to execute (value 0).
    Last,
    /// Low priority (value 250).
    Low,
    /// Normal / default priority (value 500).
    Normal,
    /// High priority (value 750).
    High,
    /// First hooks to execute (value 1000).
    First,
    /// Custom priority with an arbitrary value.
    Custom(u32),
}

impl ShutdownPriority {
    /// Return the numeric value of this priority.
    ///
    /// Higher values execute first.
    pub fn value(&self) -> u32 {
        match self {
            ShutdownPriority::First => 1000,
            ShutdownPriority::High => 750,
            ShutdownPriority::Normal => 500,
            ShutdownPriority::Low => 250,
            ShutdownPriority::Last => 0,
            ShutdownPriority::Custom(v) => *v,
        }
    }
}

impl Default for ShutdownPriority {
    fn default() -> Self {
        ShutdownPriority::Normal
    }
}

impl fmt::Display for ShutdownPriority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ShutdownPriority::First => write!(f, "First(1000)"),
            ShutdownPriority::High => write!(f, "High(750)"),
            ShutdownPriority::Normal => write!(f, "Normal(500)"),
            ShutdownPriority::Low => write!(f, "Low(250)"),
            ShutdownPriority::Last => write!(f, "Last(0)"),
            ShutdownPriority::Custom(v) => write!(f, "Custom({})", v),
        }
    }
}

/// A function that can be registered as a shutdown hook.
///
/// The function takes no arguments and returns a `Result`. If the function
/// returns `Err`, the error is logged but does not prevent subsequent hooks
/// from executing.
pub type ShutdownHookFn = Box<dyn Fn() -> Result<(), String> + Send + Sync>;

/// Result of executing all shutdown hooks.
#[derive(Debug, Clone)]
pub struct ShutdownResult {
    /// Number of hooks that executed successfully.
    pub success_count: usize,
    /// Number of hooks that returned an error.
    pub error_count: usize,
    /// Number of hooks that panicked.
    pub panic_count: usize,
    /// Collected error messages from hooks that failed.
    pub errors: Vec<ShutdownError>,
}

impl ShutdownResult {
    /// Returns `true` if all hooks executed without errors or panics.
    pub fn is_success(&self) -> bool {
        self.error_count == 0 && self.panic_count == 0
    }

    /// Total number of hooks that were executed.
    pub fn total_executed(&self) -> usize {
        self.success_count + self.error_count + self.panic_count
    }
}

impl fmt::Display for ShutdownResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ShutdownResult: {} succeeded, {} errors, {} panics ({} total)",
            self.success_count,
            self.error_count,
            self.panic_count,
            self.total_executed()
        )
    }
}

/// Information about a hook that failed during shutdown.
#[derive(Debug, Clone)]
pub struct ShutdownError {
    /// The hook's description, if one was provided.
    pub hook_description: String,
    /// The priority at which the hook was registered.
    pub priority: ShutdownPriority,
    /// The error message, if the hook returned an error.
    pub error_message: Option<String>,
    /// Whether the hook panicked (rather than returning an error).
    pub panicked: bool,
}

impl fmt::Display for ShutdownError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.panicked {
            write!(
                f,
                "[{}] Hook '{}' panicked",
                self.priority, self.hook_description
            )
        } else {
            write!(
                f,
                "[{}] Hook '{}' failed: {}",
                self.priority,
                self.hook_description,
                self.error_message.as_deref().unwrap_or("unknown error")
            )
        }
    }
}

// ============================================================================
// Registry internals
// ============================================================================

/// A single registered hook with its metadata.
struct RegisteredHook {
    /// The hook function.
    hook: ShutdownHookFn,
    /// The priority of this hook.
    priority: ShutdownPriority,
    /// Registration order (monotonically increasing counter).
    order: u64,
    /// Human-readable description for diagnostics.
    description: String,
}

// ============================================================================
// ShutdownHookRegistry
// ============================================================================

/// A priority-ordered registry of shutdown hooks.
///
/// Components register callbacks via [`register`](Self::register). When
/// [`shutdown`](Self::shutdown) is called, hooks execute from highest priority
/// to lowest, with ties broken by registration order (first-registered first).
///
/// The registry is thread-safe.
///
/// # Examples
///
/// ```
/// use ghidra_core::generic::shutdown_hook_registry::{
///     ShutdownHookRegistry, ShutdownPriority,
/// };
///
/// let registry = ShutdownHookRegistry::new();
///
/// registry.register(
///     ShutdownPriority::Normal,
///     "save preferences",
///     Box::new(|| {
///         // save preferences to disk
///         Ok(())
///     }),
/// );
///
/// registry.register(
///     ShutdownPriority::High,
///     "close database",
///     Box::new(|| {
///         // close database connections
///         Ok(())
///     }),
/// );
///
/// let result = registry.shutdown();
/// assert!(result.is_success());
/// ```
pub struct ShutdownHookRegistry {
    hooks: Arc<Mutex<Vec<RegisteredHook>>>,
    counter: Arc<Mutex<u64>>,
    /// Whether `shutdown()` has been called.
    shut_down: Arc<Mutex<bool>>,
}

impl ShutdownHookRegistry {
    /// Create a new, empty registry.
    pub fn new() -> Self {
        Self {
            hooks: Arc::new(Mutex::new(Vec::new())),
            counter: Arc::new(Mutex::new(0)),
            shut_down: Arc::new(Mutex::new(false)),
        }
    }

    /// Get the global singleton registry.
    pub fn global() -> &'static ShutdownHookRegistry {
        static GLOBAL: OnceLock<ShutdownHookRegistry> = OnceLock::new();
        GLOBAL.get_or_init(ShutdownHookRegistry::new)
    }

    /// Register a shutdown hook.
    ///
    /// The `priority` determines execution order (higher values execute first).
    /// Hooks with the same priority execute in registration order.
    ///
    /// Returns `false` if the registry has already been shut down (the hook
    /// will not be executed).
    pub fn register(
        &self,
        priority: ShutdownPriority,
        description: impl Into<String>,
        hook: ShutdownHookFn,
    ) -> bool {
        let shut_down = self.shut_down.lock().unwrap();
        if *shut_down {
            return false;
        }

        let mut counter = self.counter.lock().unwrap();
        let order = *counter;
        *counter += 1;

        let entry = RegisteredHook {
            hook,
            priority,
            order,
            description: description.into(),
        };

        let mut hooks = self.hooks.lock().unwrap();
        hooks.push(entry);
        true
    }

    /// Execute all registered shutdown hooks.
    ///
    /// Hooks are executed from highest priority to lowest, with ties broken by
    /// registration order. After execution, the registry is marked as shut down
    /// and no further hooks can be registered.
    ///
    /// Returns a [`ShutdownResult`] summarizing the outcome.
    pub fn shutdown(&self) -> ShutdownResult {
        // Mark as shut down first to prevent new registrations
        {
            let mut shut_down = self.shut_down.lock().unwrap();
            if *shut_down {
                return ShutdownResult {
                    success_count: 0,
                    error_count: 0,
                    panic_count: 0,
                    errors: Vec::new(),
                };
            }
            *shut_down = true;
        }

        // Take ownership of all hooks
        let hooks = {
            let mut guard = self.hooks.lock().unwrap();
            std::mem::take(&mut *guard)
        };

        // Sort by priority (descending) then by registration order (ascending)
        let mut sorted: Vec<RegisteredHook> = hooks;
        sorted.sort_by(|a, b| {
            b.priority
                .value()
                .cmp(&a.priority.value())
                .then(a.order.cmp(&b.order))
        });

        let mut result = ShutdownResult {
            success_count: 0,
            error_count: 0,
            panic_count: 0,
            errors: Vec::new(),
        };

        for entry in sorted {
            let hook_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                (entry.hook)()
            }));

            match hook_result {
                Ok(Ok(())) => {
                    result.success_count += 1;
                }
                Ok(Err(err_msg)) => {
                    result.error_count += 1;
                    result.errors.push(ShutdownError {
                        hook_description: entry.description.clone(),
                        priority: entry.priority,
                        error_message: Some(err_msg),
                        panicked: false,
                    });
                    log::error!(
                        "Shutdown hook '{}' [{}] failed: {}",
                        entry.description,
                        entry.priority,
                        result.errors.last().unwrap()
                    );
                }
                Err(panic_payload) => {
                    result.panic_count += 1;
                    let panic_msg = if let Some(s) = panic_payload.downcast_ref::<&str>() {
                        s.to_string()
                    } else if let Some(s) = panic_payload.downcast_ref::<String>() {
                        s.clone()
                    } else {
                        "unknown panic".to_string()
                    };
                    result.errors.push(ShutdownError {
                        hook_description: entry.description.clone(),
                        priority: entry.priority,
                        error_message: Some(panic_msg),
                        panicked: true,
                    });
                    log::error!(
                        "Shutdown hook '{}' [{}] panicked",
                        entry.description,
                        entry.priority
                    );
                }
            }
        }

        result
    }

    /// Returns the number of hooks currently registered.
    pub fn hook_count(&self) -> usize {
        self.hooks.lock().unwrap().len()
    }

    /// Returns `true` if `shutdown()` has been called.
    pub fn is_shut_down(&self) -> bool {
        *self.shut_down.lock().unwrap()
    }

    /// Remove all registered hooks (without executing them).
    ///
    /// Returns `false` if the registry has already been shut down.
    pub fn clear(&self) -> bool {
        let shut_down = self.shut_down.lock().unwrap();
        if *shut_down {
            return false;
        }
        let mut hooks = self.hooks.lock().unwrap();
        hooks.clear();
        true
    }

    /// Remove a hook by its description.
    ///
    /// If multiple hooks share the same description, only the first one
    /// (by registration order) is removed. Returns `true` if a hook was
    /// removed.
    pub fn unregister(&self, description: &str) -> bool {
        let mut hooks = self.hooks.lock().unwrap();
        if let Some(pos) = hooks.iter().position(|h| h.description == description) {
            hooks.remove(pos);
            true
        } else {
            false
        }
    }

    /// List the descriptions of all registered hooks, in priority order
    /// (highest first).
    pub fn list_hooks(&self) -> Vec<(ShutdownPriority, String)> {
        let hooks = self.hooks.lock().unwrap();
        let mut entries: Vec<_> = hooks
            .iter()
            .map(|h| (h.priority, h.description.clone()))
            .collect();
        entries.sort_by(|a, b| b.0.value().cmp(&a.0.value()));
        entries
    }
}

impl Default for ShutdownHookRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for ShutdownHookRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let count = self.hook_count();
        let shut_down = self.is_shut_down();
        f.debug_struct("ShutdownHookRegistry")
            .field("hook_count", &count)
            .field("is_shut_down", &shut_down)
            .finish()
    }
}

// ============================================================================
// Convenience functions (module-level)
// ============================================================================

/// Register a hook on the global registry with [`ShutdownPriority::Normal`].
pub fn register_hook(description: impl Into<String>, hook: ShutdownHookFn) -> bool {
    ShutdownHookRegistry::global().register(ShutdownPriority::Normal, description, hook)
}

/// Register a hook on the global registry with a specific priority.
pub fn register_hook_with_priority(
    priority: ShutdownPriority,
    description: impl Into<String>,
    hook: ShutdownHookFn,
) -> bool {
    ShutdownHookRegistry::global().register(priority, description, hook)
}

/// Execute all hooks on the global registry and return the result.
pub fn shutdown() -> ShutdownResult {
    ShutdownHookRegistry::global().shutdown()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    #[test]
    fn test_priority_ordering() {
        assert!(ShutdownPriority::First.value() > ShutdownPriority::High.value());
        assert!(ShutdownPriority::High.value() > ShutdownPriority::Normal.value());
        assert!(ShutdownPriority::Normal.value() > ShutdownPriority::Low.value());
        assert!(ShutdownPriority::Low.value() > ShutdownPriority::Last.value());
    }

    #[test]
    fn test_priority_default() {
        assert_eq!(ShutdownPriority::default(), ShutdownPriority::Normal);
        assert_eq!(ShutdownPriority::default().value(), 500);
    }

    #[test]
    fn test_priority_display() {
        assert_eq!(format!("{}", ShutdownPriority::First), "First(1000)");
        assert_eq!(format!("{}", ShutdownPriority::Custom(42)), "Custom(42)");
    }

    #[test]
    fn test_register_and_shutdown() {
        let registry = ShutdownHookRegistry::new();
        let counter = Arc::new(AtomicU32::new(0));

        let counter_clone = counter.clone();
        registry.register(
            ShutdownPriority::Normal,
            "increment counter",
            Box::new(move || {
                counter_clone.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }),
        );

        assert_eq!(registry.hook_count(), 1);

        let result = registry.shutdown();
        assert!(result.is_success());
        assert_eq!(result.success_count, 1);
        assert_eq!(result.error_count, 0);
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_priority_execution_order() {
        let registry = ShutdownHookRegistry::new();
        let order = Arc::new(Mutex::new(Vec::new()));

        let order_clone = order.clone();
        registry.register(
            ShutdownPriority::Low,
            "low hook",
            Box::new(move || {
                order_clone.lock().unwrap().push("low");
                Ok(())
            }),
        );

        let order_clone = order.clone();
        registry.register(
            ShutdownPriority::First,
            "first hook",
            Box::new(move || {
                order_clone.lock().unwrap().push("first");
                Ok(())
            }),
        );

        let order_clone = order.clone();
        registry.register(
            ShutdownPriority::High,
            "high hook",
            Box::new(move || {
                order_clone.lock().unwrap().push("high");
                Ok(())
            }),
        );

        registry.shutdown();

        let recorded = order.lock().unwrap().clone();
        assert_eq!(recorded, vec!["first", "high", "low"]);
    }

    #[test]
    fn test_same_priority_registration_order() {
        let registry = ShutdownHookRegistry::new();
        let order = Arc::new(Mutex::new(Vec::new()));

        for i in 0..5 {
            let order_clone = order.clone();
            registry.register(
                ShutdownPriority::Normal,
                format!("hook_{}", i),
                Box::new(move || {
                    order_clone.lock().unwrap().push(i);
                    Ok(())
                }),
            );
        }

        registry.shutdown();

        let recorded = order.lock().unwrap().clone();
        assert_eq!(recorded, vec![0, 1, 2, 3, 4]);
    }

    #[test]
    fn test_hook_error_does_not_stop_others() {
        let registry = ShutdownHookRegistry::new();
        let counter = Arc::new(AtomicU32::new(0));

        let counter_clone = counter.clone();
        registry.register(
            ShutdownPriority::High,
            "failing hook",
            Box::new(move || {
                counter_clone.fetch_add(1, Ordering::SeqCst);
                Err("intentional error".to_string())
            }),
        );

        let counter_clone = counter.clone();
        registry.register(
            ShutdownPriority::Low,
            "succeeding hook",
            Box::new(move || {
                counter_clone.fetch_add(10, Ordering::SeqCst);
                Ok(())
            }),
        );

        let result = registry.shutdown();
        assert!(!result.is_success());
        assert_eq!(result.error_count, 1);
        assert_eq!(result.success_count, 1);
        // Both hooks ran
        assert_eq!(counter.load(Ordering::SeqCst), 11);
    }

    #[test]
    fn test_hook_panic_does_not_stop_others() {
        let registry = ShutdownHookRegistry::new();
        let counter = Arc::new(AtomicU32::new(0));

        let counter_clone = counter.clone();
        registry.register(
            ShutdownPriority::High,
            "panicking hook",
            Box::new(move || {
                counter_clone.fetch_add(1, Ordering::SeqCst);
                panic!("intentional panic");
            }),
        );

        let counter_clone = counter.clone();
        registry.register(
            ShutdownPriority::Low,
            "after panic hook",
            Box::new(move || {
                counter_clone.fetch_add(10, Ordering::SeqCst);
                Ok(())
            }),
        );

        let result = registry.shutdown();
        assert_eq!(result.panic_count, 1);
        assert_eq!(result.success_count, 1);
        assert_eq!(counter.load(Ordering::SeqCst), 11);
    }

    #[test]
    fn test_shutdown_prevents_new_registration() {
        let registry = ShutdownHookRegistry::new();
        registry.shutdown();

        let result = registry.register(
            ShutdownPriority::Normal,
            "too late",
            Box::new(|| Ok(())),
        );
        assert!(!result);
    }

    #[test]
    fn test_double_shutdown_returns_empty() {
        let registry = ShutdownHookRegistry::new();
        let result1 = registry.shutdown();
        assert_eq!(result1.success_count, 0); // no hooks

        let result2 = registry.shutdown();
        assert_eq!(result2.success_count, 0); // already shut down
    }

    #[test]
    fn test_hook_count() {
        let registry = ShutdownHookRegistry::new();
        assert_eq!(registry.hook_count(), 0);

        registry.register(ShutdownPriority::Normal, "h1", Box::new(|| Ok(())));
        assert_eq!(registry.hook_count(), 1);

        registry.register(ShutdownPriority::High, "h2", Box::new(|| Ok(())));
        assert_eq!(registry.hook_count(), 2);
    }

    #[test]
    fn test_is_shut_down() {
        let registry = ShutdownHookRegistry::new();
        assert!(!registry.is_shut_down());

        registry.shutdown();
        assert!(registry.is_shut_down());
    }

    #[test]
    fn test_clear() {
        let registry = ShutdownHookRegistry::new();
        registry.register(ShutdownPriority::Normal, "h1", Box::new(|| Ok(())));
        registry.register(ShutdownPriority::High, "h2", Box::new(|| Ok(())));
        assert_eq!(registry.hook_count(), 2);

        assert!(registry.clear());
        assert_eq!(registry.hook_count(), 0);
    }

    #[test]
    fn test_clear_after_shutdown() {
        let registry = ShutdownHookRegistry::new();
        registry.shutdown();

        assert!(!registry.clear());
    }

    #[test]
    fn test_unregister() {
        let registry = ShutdownHookRegistry::new();
        registry.register(ShutdownPriority::Normal, "keep", Box::new(|| Ok(())));
        registry.register(ShutdownPriority::High, "remove me", Box::new(|| Ok(())));
        assert_eq!(registry.hook_count(), 2);

        assert!(registry.unregister("remove me"));
        assert_eq!(registry.hook_count(), 1);

        // Already removed
        assert!(!registry.unregister("remove me"));
        // Never existed
        assert!(!registry.unregister("nonexistent"));
    }

    #[test]
    fn test_list_hooks() {
        let registry = ShutdownHookRegistry::new();
        registry.register(ShutdownPriority::Low, "cleanup", Box::new(|| Ok(())));
        registry.register(ShutdownPriority::High, "db close", Box::new(|| Ok(())));
        registry.register(ShutdownPriority::Normal, "save", Box::new(|| Ok(())));

        let list = registry.list_hooks();
        assert_eq!(list.len(), 3);
        // Should be in priority order (highest first)
        assert_eq!(list[0].0, ShutdownPriority::High);
        assert_eq!(list[1].0, ShutdownPriority::Normal);
        assert_eq!(list[2].0, ShutdownPriority::Low);
    }

    #[test]
    fn test_shutdown_result_display() {
        let result = ShutdownResult {
            success_count: 5,
            error_count: 1,
            panic_count: 0,
            errors: vec![],
        };
        let s = format!("{}", result);
        assert!(s.contains("5 succeeded"));
        assert!(s.contains("1 errors"));
    }

    #[test]
    fn test_shutdown_result_total() {
        let result = ShutdownResult {
            success_count: 3,
            error_count: 2,
            panic_count: 1,
            errors: vec![],
        };
        assert_eq!(result.total_executed(), 6);
        assert!(!result.is_success());
    }

    #[test]
    fn test_shutdown_error_display() {
        let err = ShutdownError {
            hook_description: "test hook".to_string(),
            priority: ShutdownPriority::High,
            error_message: Some("oops".to_string()),
            panicked: false,
        };
        assert!(format!("{}", err).contains("test hook"));
        assert!(format!("{}", err).contains("oops"));

        let panic_err = ShutdownError {
            hook_description: "panic hook".to_string(),
            priority: ShutdownPriority::Normal,
            error_message: None,
            panicked: true,
        };
        assert!(format!("{}", panic_err).contains("panicked"));
    }

    #[test]
    fn test_convenience_register() {
        // Test the module-level convenience function on the global registry
        let ok = register_hook("test convenience", Box::new(|| Ok(())));
        assert!(ok);
    }

    #[test]
    fn test_empty_shutdown() {
        let registry = ShutdownHookRegistry::new();
        let result = registry.shutdown();
        assert!(result.is_success());
        assert_eq!(result.success_count, 0);
        assert_eq!(result.error_count, 0);
        assert_eq!(result.panic_count, 0);
    }

    #[test]
    fn test_custom_priority() {
        let p = ShutdownPriority::Custom(42);
        assert_eq!(p.value(), 42);
        assert_eq!(format!("{}", p), "Custom(42)");
    }

    #[test]
    fn test_hook_with_state() {
        let registry = ShutdownHookRegistry::new();
        let data = Arc::new(Mutex::new(Vec::<i32>::new()));

        for i in 0..3 {
            let data_clone = data.clone();
            registry.register(
                ShutdownPriority::Normal,
                format!("push_{}", i),
                Box::new(move || {
                    data_clone.lock().unwrap().push(i);
                    Ok(())
                }),
            );
        }

        registry.shutdown();

        let result = data.lock().unwrap().clone();
        assert_eq!(result, vec![0, 1, 2]);
    }
}
