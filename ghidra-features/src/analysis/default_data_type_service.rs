//! DefaultDataTypeManagerService -- headless data type manager service.
//!
//! Ported from `ghidra.app.plugin.core.analysis.DefaultDataTypeManagerService`.
//!
//! Provides a default data type manager service for headless analysis
//! environments where no tool-based service is available.

use std::collections::{HashMap, HashSet};

/// Default data type manager service for headless analysis.
///
/// Ported from Ghidra's `DefaultDataTypeManagerService`. This service
/// provides data type management capabilities when running in headless
/// mode (without a GUI tool). It manages built-in data type archives
/// and program-specific data types.
///
/// # Usage
///
/// In headless mode, this service is used instead of the tool-based
/// `DataTypeManagerService`. It provides the same interface but without
/// GUI dependencies.
///
/// ```ignore
/// use ghidra_features::analysis::DefaultDataTypeManagerService;
///
/// let service = DefaultDataTypeManagerService::new();
/// // Use service for data type resolution during analysis
/// ```
#[derive(Debug)]
pub struct DefaultDataTypeManagerService {
    /// Built-in data type archive names.
    builtin_archives: HashSet<String>,
    /// Mapping of data type names to category paths.
    type_catalog: HashMap<String, String>,
    /// Whether the service has been initialized.
    initialized: bool,
}

impl DefaultDataTypeManagerService {
    /// Create a new default data type manager service.
    pub fn new() -> Self {
        Self {
            builtin_archives: HashSet::new(),
            type_catalog: HashMap::new(),
            initialized: false,
        }
    }

    /// Initialize the service by loading built-in data type archives.
    ///
    /// In the full implementation, this would scan for built-in archive
    /// files and populate the type catalog.
    pub fn initialize(&mut self) {
        if self.initialized {
            return;
        }
        self.load_builtin_archives();
        self.initialized = true;
    }

    /// Load built-in data type archives.
    fn load_builtin_archives(&mut self) {
        // Register well-known built-in archive names
        self.builtin_archives.insert("generic_C".to_string());
        self.builtin_archives.insert("generic_clib".to_string());
    }

    /// Check if the service is initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Get the set of built-in archive names.
    pub fn builtin_archives(&self) -> &HashSet<String> {
        &self.builtin_archives
    }

    /// Add a data type to the catalog.
    pub fn add_type(&mut self, name: String, category_path: String) {
        self.type_catalog.insert(name, category_path);
    }

    /// Look up the category path for a data type name.
    pub fn find_type_category(&self, name: &str) -> Option<&str> {
        self.type_catalog.get(name).map(|s| s.as_str())
    }

    /// Get the total number of types in the catalog.
    pub fn type_count(&self) -> usize {
        self.type_catalog.len()
    }
}

impl Default for DefaultDataTypeManagerService {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_creation() {
        let service = DefaultDataTypeManagerService::new();
        assert!(!service.is_initialized());
        assert_eq!(service.type_count(), 0);
    }

    #[test]
    fn test_service_initialize() {
        let mut service = DefaultDataTypeManagerService::new();
        service.initialize();
        assert!(service.is_initialized());
        assert!(service.builtin_archives().contains("generic_C"));
        assert!(service.builtin_archives().contains("generic_clib"));
    }

    #[test]
    fn test_service_double_initialize() {
        let mut service = DefaultDataTypeManagerService::new();
        service.initialize();
        service.initialize(); // Should be idempotent
        assert!(service.is_initialized());
    }

    #[test]
    fn test_service_add_and_find_type() {
        let mut service = DefaultDataTypeManagerService::new();
        service.initialize();
        service.add_type("my_struct".to_string(), "/my/structs".to_string());
        assert_eq!(service.type_count(), 1);
        assert_eq!(service.find_type_category("my_struct"), Some("/my/structs"));
        assert!(service.find_type_category("nonexistent").is_none());
    }
}
