//! Function comparison service API.
//!
//! Ported from Ghidra's `FunctionComparisonService` Java interface, which
//! is implemented by `FunctionComparisonPlugin`.
//!
//! The comparison service provides the public API for creating and managing
//! function comparisons. External components (like the code browser or
//! decompiler) use this service to request comparisons without needing
//! direct access to the plugin internals.
//!
//! In the original Java, `FunctionComparisonService` is a service interface
//! registered with the tool. Here we define the trait and provide a
//! wrapper that delegates to the plugin.
//!
//! # Key types
//!
//! - [`ComparisonRequest`] -- a request to create a comparison
//! - [`ComparisonResult`] -- the result of a comparison request
//! - [`FunctionComparisonService`] -- trait for the comparison service API
//! - [`ComparisonServiceProxy`] -- a proxy that delegates to the plugin

use std::sync::{Arc, Mutex};

use super::super::model::{ComparisonSide, FunctionInfo};
use super::super::panel::ProgramInfo;
use super::FunctionComparisonPlugin;

/// A request to create a function comparison.
#[derive(Debug, Clone)]
pub struct ComparisonRequest {
    /// The functions to compare.
    pub functions: Vec<FunctionInfo>,
    /// Whether to create a new comparison window even if one exists.
    pub force_new_window: bool,
    /// The preferred initial view (Listing, Decompiler, FunctionGraph).
    pub preferred_view: Option<String>,
}

impl ComparisonRequest {
    /// Create a new comparison request.
    pub fn new(functions: Vec<FunctionInfo>) -> Self {
        Self {
            functions,
            force_new_window: false,
            preferred_view: None,
        }
    }

    /// Create a request that forces a new comparison window.
    pub fn new_window(functions: Vec<FunctionInfo>) -> Self {
        Self {
            functions,
            force_new_window: true,
            preferred_view: None,
        }
    }

    /// Set the preferred initial view.
    pub fn with_preferred_view(mut self, view: impl Into<String>) -> Self {
        self.preferred_view = Some(view.into());
        self
    }

    /// Get the number of functions in the request.
    pub fn function_count(&self) -> usize {
        self.functions.len()
    }

    /// Check if the request has enough functions for a comparison.
    pub fn is_valid(&self) -> bool {
        self.functions.len() >= 1
    }
}

/// The result of a comparison request.
#[derive(Debug, Clone)]
pub enum ComparisonResult {
    /// A new comparison was created.
    Created {
        /// The provider ID of the new comparison.
        provider_id: u64,
        /// A description of the comparison.
        description: String,
    },
    /// Functions were added to an existing comparison.
    AddedToExisting {
        /// The provider ID of the existing comparison.
        provider_id: u64,
        /// The updated description.
        description: String,
    },
    /// The request failed.
    Failed {
        /// The reason for the failure.
        reason: String,
    },
}

impl ComparisonResult {
    /// Check if the request was successful.
    pub fn is_success(&self) -> bool {
        !matches!(self, Self::Failed { .. })
    }

    /// Get the provider ID, if available.
    pub fn provider_id(&self) -> Option<u64> {
        match self {
            Self::Created { provider_id, .. }
            | Self::AddedToExisting { provider_id, .. } => Some(*provider_id),
            Self::Failed { .. } => None,
        }
    }

    /// Get the description, if available.
    pub fn description(&self) -> Option<&str> {
        match self {
            Self::Created { description, .. }
            | Self::AddedToExisting { description, .. } => Some(description),
            Self::Failed { .. } => None,
        }
    }
}

/// Trait for the function comparison service API.
///
/// External components use this trait to create and manage comparisons
/// without needing direct access to the plugin internals.
///
/// Ported from Ghidra's `FunctionComparisonService` Java interface.
///
/// # Example
///
/// ```rust
/// use ghidra_features::codecompare::plugin::comparison_service::*;
/// use ghidra_features::codecompare::model::FunctionInfo;
///
/// // In a real implementation, this would be provided by the plugin/tool
/// let f1 = FunctionInfo::new(1, "main", "/prog", 0x1000);
/// let f2 = FunctionInfo::new(2, "init", "/prog", 0x2000);
/// let request = ComparisonRequest::new(vec![f1, f2]);
///
/// assert!(request.is_valid());
/// assert_eq!(request.function_count(), 2);
/// ```
pub trait FunctionComparisonService: Send + Sync {
    /// Create a new comparison with the given functions.
    ///
    /// If there is an existing comparison that supports adding functions
    /// and `force_new_window` is false, the functions will be added to
    /// the existing comparison.
    fn compare_functions(&self, request: &ComparisonRequest) -> ComparisonResult;

    /// Create a new comparison window with the given functions.
    ///
    /// Always creates a new window, even if one already exists.
    fn compare_in_new_window(&self, functions: Vec<FunctionInfo>) -> ComparisonResult {
        self.compare_functions(&ComparisonRequest::new_window(functions))
    }

    /// Add functions to the last active comparison.
    ///
    /// Returns true if the functions were added.
    fn add_to_comparison(&self, functions: Vec<FunctionInfo>) -> bool;

    /// Get the number of active comparison providers.
    fn provider_count(&self) -> usize;

    /// Check if there are any active comparisons.
    fn has_comparisons(&self) -> bool {
        self.provider_count() > 0
    }

    /// Close all comparison providers.
    fn close_all(&self);

    /// Get a description of the last active comparison.
    fn last_active_description(&self) -> Option<String>;
}

/// A proxy that implements [`FunctionComparisonService`] by delegating
/// to a [`FunctionComparisonPlugin`].
///
/// This is useful for providing the service API to external components
/// while keeping the plugin as the source of truth.
///
/// # Example
///
/// ```rust
/// use ghidra_features::codecompare::plugin::comparison_service::*;
/// use ghidra_features::codecompare::plugin::*;
/// use ghidra_features::codecompare::model::*;
/// use std::sync::{Arc, Mutex};
///
/// let plugin = Arc::new(Mutex::new(FunctionComparisonPlugin::new()));
/// let proxy = ComparisonServiceProxy::new(plugin.clone());
///
/// assert!(!proxy.has_comparisons());
/// assert_eq!(proxy.provider_count(), 0);
/// ```
pub struct ComparisonServiceProxy {
    /// The plugin that owns the comparisons.
    plugin: Arc<Mutex<FunctionComparisonPlugin>>,
}

impl ComparisonServiceProxy {
    /// Create a new comparison service proxy.
    pub fn new(plugin: Arc<Mutex<FunctionComparisonPlugin>>) -> Self {
        Self { plugin }
    }
}

impl FunctionComparisonService for ComparisonServiceProxy {
    fn compare_functions(&self, request: &ComparisonRequest) -> ComparisonResult {
        if !request.is_valid() {
            return ComparisonResult::Failed {
                reason: "Not enough functions for a comparison".to_string(),
            };
        }

        let mut plugin = self.plugin.lock().unwrap();

        if request.force_new_window {
            match plugin.create_comparison(request.functions.clone()) {
                Some(provider_id) => ComparisonResult::Created {
                    provider_id,
                    description: format!("{} function(s)", request.function_count()),
                },
                None => ComparisonResult::Failed {
                    reason: "Failed to create comparison".to_string(),
                },
            }
        } else {
            // Try to add to existing, or create new
            match plugin.add_to_comparison(request.functions.clone()) {
                Some(provider_id) => ComparisonResult::Created {
                    provider_id,
                    description: format!("{} function(s)", request.function_count()),
                },
                None => ComparisonResult::Failed {
                    reason: "Failed to create comparison".to_string(),
                },
            }
        }
    }

    fn add_to_comparison(&self, functions: Vec<FunctionInfo>) -> bool {
        let mut plugin = self.plugin.lock().unwrap();
        plugin.add_to_comparison(functions).is_some()
    }

    fn provider_count(&self) -> usize {
        let plugin = self.plugin.lock().unwrap();
        plugin.provider_count()
    }

    fn close_all(&self) {
        let mut plugin = self.plugin.lock().unwrap();
        plugin.dispose();
    }

    fn last_active_description(&self) -> Option<String> {
        let plugin = self.plugin.lock().unwrap();
        plugin.last_active_provider().map(|id| {
            format!("Provider {}", id)
        })
    }
}

/// A no-op comparison service that does nothing.
///
/// Useful as a default or placeholder when no real service is available.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoOpComparisonService;

impl FunctionComparisonService for NoOpComparisonService {
    fn compare_functions(&self, _request: &ComparisonRequest) -> ComparisonResult {
        ComparisonResult::Failed {
            reason: "No comparison service available".to_string(),
        }
    }

    fn add_to_comparison(&self, _functions: Vec<FunctionInfo>) -> bool {
        false
    }

    fn provider_count(&self) -> usize {
        0
    }

    fn close_all(&self) {}

    fn last_active_description(&self) -> Option<String> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::FunctionComparisonPlugin;
    use std::sync::{Arc, Mutex};

    fn make_func(id: u64, name: &str, program: &str, entry: u64) -> FunctionInfo {
        FunctionInfo::new(id, name, program, entry)
    }

    // --- ComparisonRequest tests ---

    #[test]
    fn test_request_new() {
        let f1 = make_func(1, "main", "/prog", 0x1000);
        let f2 = make_func(2, "init", "/prog", 0x2000);
        let request = ComparisonRequest::new(vec![f1, f2]);

        assert!(request.is_valid());
        assert_eq!(request.function_count(), 2);
        assert!(!request.force_new_window);
        assert!(request.preferred_view.is_none());
    }

    #[test]
    fn test_request_new_window() {
        let f1 = make_func(1, "main", "/prog", 0x1000);
        let request = ComparisonRequest::new_window(vec![f1]);

        assert!(request.force_new_window);
    }

    #[test]
    fn test_request_with_preferred_view() {
        let f1 = make_func(1, "main", "/prog", 0x1000);
        let request = ComparisonRequest::new(vec![f1])
            .with_preferred_view("Listing");

        assert_eq!(request.preferred_view.as_deref(), Some("Listing"));
    }

    #[test]
    fn test_request_empty() {
        let request = ComparisonRequest::new(vec![]);
        assert!(!request.is_valid());
        assert_eq!(request.function_count(), 0);
    }

    #[test]
    fn test_request_single_function() {
        let f1 = make_func(1, "main", "/prog", 0x1000);
        let request = ComparisonRequest::new(vec![f1]);
        assert!(request.is_valid());
    }

    // --- ComparisonResult tests ---

    #[test]
    fn test_result_created() {
        let result = ComparisonResult::Created {
            provider_id: 1,
            description: "main() vs init()".to_string(),
        };

        assert!(result.is_success());
        assert_eq!(result.provider_id(), Some(1));
        assert_eq!(result.description(), Some("main() vs init()"));
    }

    #[test]
    fn test_result_added_to_existing() {
        let result = ComparisonResult::AddedToExisting {
            provider_id: 2,
            description: "updated".to_string(),
        };

        assert!(result.is_success());
        assert_eq!(result.provider_id(), Some(2));
    }

    #[test]
    fn test_result_failed() {
        let result = ComparisonResult::Failed {
            reason: "not enough functions".to_string(),
        };

        assert!(!result.is_success());
        assert!(result.provider_id().is_none());
        assert!(result.description().is_none());
    }

    // --- ComparisonServiceProxy tests ---

    #[test]
    fn test_proxy_new() {
        let plugin = Arc::new(Mutex::new(FunctionComparisonPlugin::new()));
        let proxy = ComparisonServiceProxy::new(plugin);

        assert!(!proxy.has_comparisons());
        assert_eq!(proxy.provider_count(), 0);
    }

    #[test]
    fn test_proxy_compare_functions() {
        let plugin = Arc::new(Mutex::new(FunctionComparisonPlugin::new()));
        let proxy = ComparisonServiceProxy::new(plugin.clone());

        let f1 = make_func(1, "main", "/prog", 0x1000);
        let f2 = make_func(2, "init", "/prog", 0x2000);
        let request = ComparisonRequest::new(vec![f1, f2]);

        let result = proxy.compare_functions(&request);
        assert!(result.is_success());
        assert!(result.provider_id().is_some());
        assert!(proxy.has_comparisons());
        assert_eq!(proxy.provider_count(), 1);
    }

    #[test]
    fn test_proxy_compare_empty() {
        let plugin = Arc::new(Mutex::new(FunctionComparisonPlugin::new()));
        let proxy = ComparisonServiceProxy::new(plugin);

        let request = ComparisonRequest::new(vec![]);
        let result = proxy.compare_functions(&request);
        assert!(!result.is_success());
    }

    #[test]
    fn test_proxy_compare_in_new_window() {
        let plugin = Arc::new(Mutex::new(FunctionComparisonPlugin::new()));
        let proxy = ComparisonServiceProxy::new(plugin.clone());

        let f1 = make_func(1, "main", "/prog", 0x1000);
        let f2 = make_func(2, "init", "/prog", 0x2000);

        let result = proxy.compare_in_new_window(vec![f1, f2]);
        assert!(result.is_success());
        assert_eq!(proxy.provider_count(), 1);
    }

    #[test]
    fn test_proxy_add_to_comparison() {
        let plugin = Arc::new(Mutex::new(FunctionComparisonPlugin::new()));
        let proxy = ComparisonServiceProxy::new(plugin.clone());

        let f1 = make_func(1, "main", "/prog", 0x1000);
        assert!(proxy.add_to_comparison(vec![f1]));
        assert_eq!(proxy.provider_count(), 1);
    }

    #[test]
    fn test_proxy_close_all() {
        let plugin = Arc::new(Mutex::new(FunctionComparisonPlugin::new()));
        let proxy = ComparisonServiceProxy::new(plugin.clone());

        let f1 = make_func(1, "main", "/prog", 0x1000);
        let f2 = make_func(2, "init", "/prog", 0x2000);
        proxy.compare_in_new_window(vec![f1, f2]);

        assert!(proxy.has_comparisons());

        proxy.close_all();
        assert!(!proxy.has_comparisons());
        assert_eq!(proxy.provider_count(), 0);
    }

    #[test]
    fn test_proxy_last_active_description() {
        let plugin = Arc::new(Mutex::new(FunctionComparisonPlugin::new()));
        let proxy = ComparisonServiceProxy::new(plugin.clone());

        // No active comparison
        assert!(proxy.last_active_description().is_none());

        // Create a comparison
        let f1 = make_func(1, "main", "/prog", 0x1000);
        let f2 = make_func(2, "init", "/prog", 0x2000);
        proxy.compare_in_new_window(vec![f1, f2]);

        let desc = proxy.last_active_description();
        assert!(desc.is_some());
    }

    // --- NoOpComparisonService tests ---

    #[test]
    fn test_noop_service() {
        let service = NoOpComparisonService;

        assert!(!service.has_comparisons());
        assert_eq!(service.provider_count(), 0);
        assert!(service.last_active_description().is_none());

        let f1 = make_func(1, "main", "/prog", 0x1000);
        let request = ComparisonRequest::new(vec![f1]);
        let result = service.compare_functions(&request);
        assert!(!result.is_success());

        assert!(!service.add_to_comparison(vec![f1]));

        // close_all should not panic
        service.close_all();
    }

    // --- ComparisonResult clone tests ---

    #[test]
    fn test_result_clone() {
        let result = ComparisonResult::Created {
            provider_id: 1,
            description: "test".to_string(),
        };
        let cloned = result.clone();
        assert!(cloned.is_success());
        assert_eq!(cloned.provider_id(), Some(1));
    }

    #[test]
    fn test_result_debug() {
        let result = ComparisonResult::Failed {
            reason: "test".to_string(),
        };
        let debug_str = format!("{:?}", result);
        assert!(debug_str.contains("Failed"));
        assert!(debug_str.contains("test"));
    }
}
