//! GoTo Address/Label Service -- service interface for address and label navigation.
//!
//! Ported from Ghidra's `ghidra.app.services.GoToService` and
//! `ghidra.app.plugin.core.navigation.GoToAddressLabelPlugin`.
//!
//! Provides the service interface that other plugins use to navigate the
//! listing to an address, symbol, or external location. The service
//! supports both address-based and label-based navigation.
//!
//! # Key Types
//!
//! - [`GotoAddressLabelService`] -- trait for navigating to addresses/labels
//! - [`GotoAddressLabelServiceImpl`] -- Default implementation of the service
//! - [`GotoQuery`] -- A pending GoTo query with address/label resolution
//! - [`GotoQueryResult`] -- Result of a GoTo query
//! - [`GotoAddressLabelServiceFactory`] -- Factory for creating service instances
//!
//! # Java Original
//!
//! The Java `GoToService` interface defines:
//! - `goTo(Address)` / `goTo(ProgramLocation)` for direct navigation
//! - `goToQuery(Address, String, Navigatable)` for query-based navigation
//! - `getDefaultNavigatable()` for getting the active navigatable
//!
//! The `GoToAddressLabelPlugin` provides the dialog-based GoTo functionality
//! where users type an address or label name into a text field.

use ghidra_core::Address;

// ---------------------------------------------------------------------------
// GotoAddressLabelService trait
// ---------------------------------------------------------------------------

/// Service interface for navigating to addresses and labels.
///
/// Ported from `ghidra.app.services.GoToService`.
///
/// This service is used by various plugins and actions to navigate the
/// code browser listing to a specific address or named label/symbol.
///
/// # Example
///
/// ```
/// use ghidra_features::navigation::goto_address_label_service::*;
/// use ghidra_core::Address;
///
/// let mut service = GotoAddressLabelServiceImpl::new("MyService");
/// service.go_to(Address::new(0x401000));
/// assert_eq!(service.current_address(), Some(Address::new(0x401000)));
/// ```
pub trait GotoAddressLabelService: Send + Sync {
    /// Navigate to the given address.
    ///
    /// Returns `true` if navigation was successful.
    fn go_to(&mut self, address: Address) -> bool;

    /// Navigate to an address resolved from a text query.
    ///
    /// The query can be a hex address (e.g. "0x401000") or a label name
    /// (e.g. "main"). Returns `true` if navigation was successful.
    fn go_to_query(&mut self, query: &str) -> bool;

    /// Get the current address in the listing.
    fn current_address(&self) -> Option<Address>;

    /// Get the name of the current program.
    fn current_program(&self) -> Option<&str>;

    /// Check if the service can navigate to the given address.
    fn can_go_to(&self, address: Address) -> bool;

    /// Check if the service can resolve the given query string.
    fn can_resolve_query(&self, query: &str) -> bool;

    /// Get the history of navigated addresses.
    fn history(&self) -> &[Address];

    /// Check if there is a previous location in history.
    fn has_previous(&self) -> bool;

    /// Check if there is a next location in history.
    fn has_next(&self) -> bool;

    /// Navigate to the previous location in history.
    fn go_back(&mut self) -> bool;

    /// Navigate to the next location in history.
    fn go_forward(&mut self) -> bool;

    /// Clear the navigation history.
    fn clear_history(&mut self);
}

// ---------------------------------------------------------------------------
// GotoQuery
// ---------------------------------------------------------------------------

/// A pending GoTo query that can be an address or label.
///
/// Ported from the query handling in `GoToAddressLabelPlugin`.
///
/// Represents a user-entered navigation target that needs to be resolved
/// before navigation can occur.
#[derive(Debug, Clone)]
pub struct GotoQuery {
    /// The raw query string entered by the user.
    pub raw_query: String,
    /// Whether the query has been resolved.
    pub resolved: bool,
    /// The resolved address (if resolution succeeded).
    pub resolved_address: Option<Address>,
    /// Error message (if resolution failed).
    pub error: Option<String>,
}

impl GotoQuery {
    /// Create a new GoTo query from a raw string.
    pub fn new(query: impl Into<String>) -> Self {
        Self {
            raw_query: query.into(),
            resolved: false,
            resolved_address: None,
            error: None,
        }
    }

    /// Attempt to resolve the query as a hex address.
    ///
    /// Returns `true` if resolution succeeded.
    pub fn resolve_as_address(&mut self) -> bool {
        let trimmed = self.raw_query.trim();
        let hex_str = trimmed
            .strip_prefix("0x")
            .or_else(|| trimmed.strip_prefix("0X"))
            .or_else(|| trimmed.strip_prefix("$"))
            .unwrap_or(trimmed);

        match u64::from_str_radix(hex_str, 16) {
            Ok(addr) => {
                self.resolved_address = Some(Address::new(addr));
                self.resolved = true;
                self.error = None;
                true
            }
            Err(_) => {
                self.error = Some(format!("Cannot parse '{}' as address", self.raw_query));
                self.resolved = false;
                false
            }
        }
    }

    /// Mark the query as resolved with the given address.
    pub fn set_resolved(&mut self, address: Address) {
        self.resolved_address = Some(address);
        self.resolved = true;
        self.error = None;
    }

    /// Mark the query as failed with the given error.
    pub fn set_error(&mut self, error: impl Into<String>) {
        self.error = Some(error.into());
        self.resolved = false;
        self.resolved_address = None;
    }

    /// Check if the query looks like a hex address (vs. a label name).
    pub fn looks_like_address(&self) -> bool {
        let trimmed = self.raw_query.trim();
        trimmed.starts_with("0x")
            || trimmed.starts_with("0X")
            || trimmed.starts_with("$")
            || trimmed.chars().all(|c| c.is_ascii_hexdigit())
    }
}

impl std::fmt::Display for GotoQuery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.resolved {
            if let Some(addr) = self.resolved_address {
                write!(f, "{} -> {:#x}", self.raw_query, addr.offset)
            } else {
                write!(f, "{} -> (resolved)", self.raw_query)
            }
        } else if let Some(err) = &self.error {
            write!(f, "{} -> error: {}", self.raw_query, err)
        } else {
            write!(f, "{} (pending)", self.raw_query)
        }
    }
}

// ---------------------------------------------------------------------------
// GotoQueryResult
// ---------------------------------------------------------------------------

/// Result of resolving a GoTo query.
///
/// Represents the outcome of attempting to navigate to a user-specified
/// address or label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GotoQueryResult {
    /// Navigation succeeded.
    Success {
        /// The address that was navigated to.
        address: Address,
    },
    /// Navigation failed with an error.
    Error {
        /// The error message.
        message: String,
    },
    /// Multiple matches found; navigation ambiguous.
    MultipleMatches {
        /// The number of matches found.
        count: usize,
    },
}

impl GotoQueryResult {
    /// Returns `true` if the result is a success.
    pub fn is_success(&self) -> bool {
        matches!(self, GotoQueryResult::Success { .. })
    }

    /// Returns `true` if the result is an error.
    pub fn is_error(&self) -> bool {
        matches!(self, GotoQueryResult::Error { .. })
    }

    /// Returns `true` if there are multiple matches.
    pub fn is_multiple_matches(&self) -> bool {
        matches!(self, GotoQueryResult::MultipleMatches { .. })
    }

    /// Get the address if the result is a success.
    pub fn address(&self) -> Option<Address> {
        match self {
            GotoQueryResult::Success { address } => Some(*address),
            _ => None,
        }
    }

    /// Get the error message if the result is an error.
    pub fn error_message(&self) -> Option<&str> {
        match self {
            GotoQueryResult::Error { message } => Some(message),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// GotoAddressLabelServiceImpl
// ---------------------------------------------------------------------------

/// Default implementation of [`GotoAddressLabelService`].
///
/// Maintains navigation state including the current address, program name,
/// and navigation history. Supports both address-based and label-based
/// navigation queries.
///
/// # Example
///
/// ```
/// use ghidra_features::navigation::goto_address_label_service::*;
/// use ghidra_core::Address;
///
/// let mut service = GotoAddressLabelServiceImpl::new("MainService");
/// service.set_program("test.exe");
///
/// // Navigate by address
/// let result = service.go_to(Address::new(0x401000));
/// assert!(result);
/// assert_eq!(service.current_address(), Some(Address::new(0x401000)));
///
/// // Navigate by query string
/// let result = service.go_to_query("0x402000");
/// assert!(result);
/// assert_eq!(service.current_address(), Some(Address::new(0x402000)));
///
/// // History navigation
/// assert!(service.has_previous());
/// service.go_back();
/// assert_eq!(service.current_address(), Some(Address::new(0x401000)));
/// ```
#[derive(Debug)]
pub struct GotoAddressLabelServiceImpl {
    /// Service name.
    name: String,
    /// Current address in the listing.
    current_addr: Option<Address>,
    /// Current program name.
    current_program: Option<String>,
    /// Navigation history (back/forward).
    history: Vec<Address>,
    /// Current position in history.
    history_index: Option<usize>,
    /// Maximum history size.
    max_history: usize,
    /// Known label-to-address mappings (label name -> address).
    label_map: std::collections::HashMap<String, Address>,
}

impl GotoAddressLabelServiceImpl {
    /// Create a new service with the given name.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            current_addr: None,
            current_program: None,
            history: Vec::new(),
            history_index: None,
            max_history: 100,
            label_map: std::collections::HashMap::new(),
        }
    }

    /// Get the service name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Set the current program name.
    pub fn set_program(&mut self, program: impl Into<String>) {
        self.current_program = Some(program.into());
    }

    /// Register a label-to-address mapping.
    ///
    /// This allows `go_to_query("main")` to resolve to an address.
    pub fn register_label(&mut self, label: impl Into<String>, address: Address) {
        self.label_map.insert(label.into(), address);
    }

    /// Remove a label mapping.
    pub fn unregister_label(&mut self, label: &str) -> Option<Address> {
        self.label_map.remove(label)
    }

    /// Check if a label is registered.
    pub fn has_label(&self, label: &str) -> bool {
        self.label_map.contains_key(label)
    }

    /// Get the address for a registered label.
    pub fn label_address(&self, label: &str) -> Option<Address> {
        self.label_map.get(label).copied()
    }

    /// Get the number of registered labels.
    pub fn label_count(&self) -> usize {
        self.label_map.len()
    }

    /// Get the maximum history size.
    pub fn max_history(&self) -> usize {
        self.max_history
    }

    /// Set the maximum history size.
    pub fn set_max_history(&mut self, max: usize) {
        self.max_history = max.max(10);
        self.truncate_history();
    }

    /// Get the current history length.
    pub fn history_len(&self) -> usize {
        self.history.len()
    }

    /// Push an address onto the history, truncating forward history.
    fn push_history(&mut self, address: Address) {
        // If we're not at the end of history, truncate forward entries
        if let Some(idx) = self.history_index {
            self.history.truncate(idx + 1);
        }
        self.history.push(address);
        self.history_index = Some(self.history.len() - 1);
        self.truncate_history();
    }

    /// Truncate history to max size, removing oldest entries.
    fn truncate_history(&mut self) {
        if self.history.len() > self.max_history {
            let excess = self.history.len() - self.max_history;
            self.history.drain(..excess);
            self.history_index = self.history_index.map(|i| i.saturating_sub(excess));
        }
    }

    /// Resolve a query string to an address.
    pub fn resolve_query(&self, query: &str) -> GotoQueryResult {
        let trimmed = query.trim();

        // Try as hex address first
        let hex_str = trimmed
            .strip_prefix("0x")
            .or_else(|| trimmed.strip_prefix("0X"))
            .or_else(|| trimmed.strip_prefix("$"))
            .unwrap_or(trimmed);

        if let Ok(addr) = u64::from_str_radix(hex_str, 16) {
            return GotoQueryResult::Success {
                address: Address::new(addr),
            };
        }

        // Try as label
        if let Some(addr) = self.label_map.get(trimmed) {
            return GotoQueryResult::Success { address: *addr };
        }

        GotoQueryResult::Error {
            message: format!("Cannot resolve '{}' as address or label", query),
        }
    }
}

impl GotoAddressLabelService for GotoAddressLabelServiceImpl {
    fn go_to(&mut self, address: Address) -> bool {
        self.push_history(address);
        self.current_addr = Some(address);
        true
    }

    fn go_to_query(&mut self, query: &str) -> bool {
        match self.resolve_query(query) {
            GotoQueryResult::Success { address } => self.go_to(address),
            GotoQueryResult::Error { message } => {
                log::warn!("GoTo query failed: {}", message);
                false
            }
            GotoQueryResult::MultipleMatches { .. } => {
                // In a real implementation, this would show a dialog
                // For now, just fail
                false
            }
        }
    }

    fn current_address(&self) -> Option<Address> {
        self.current_addr
    }

    fn current_program(&self) -> Option<&str> {
        self.current_program.as_deref()
    }

    fn can_go_to(&self, _address: Address) -> bool {
        true // All addresses are valid targets
    }

    fn can_resolve_query(&self, query: &str) -> bool {
        self.resolve_query(query).is_success()
    }

    fn history(&self) -> &[Address] {
        &self.history
    }

    fn has_previous(&self) -> bool {
        self.history_index.map_or(false, |i| i > 0)
    }

    fn has_next(&self) -> bool {
        self.history_index.map_or(false, |i| i + 1 < self.history.len())
    }

    fn go_back(&mut self) -> bool {
        if let Some(idx) = self.history_index {
            if idx > 0 {
                let new_idx = idx - 1;
                self.history_index = Some(new_idx);
                self.current_addr = Some(self.history[new_idx]);
                return true;
            }
        }
        false
    }

    fn go_forward(&mut self) -> bool {
        if let Some(idx) = self.history_index {
            if idx + 1 < self.history.len() {
                let new_idx = idx + 1;
                self.history_index = Some(new_idx);
                self.current_addr = Some(self.history[new_idx]);
                return true;
            }
        }
        false
    }

    fn clear_history(&mut self) {
        self.history.clear();
        self.history_index = None;
    }
}

// ---------------------------------------------------------------------------
// GotoAddressLabelServiceFactory
// ---------------------------------------------------------------------------

/// Factory for creating [`GotoAddressLabelService`] instances.
///
/// Provides convenient constructors for common service configurations
/// used throughout Ghidra.
///
/// # Example
///
/// ```
/// use ghidra_features::navigation::goto_address_label_service::*;
///
/// let service = GotoAddressLabelServiceFactory::create("MyService");
/// assert_eq!(service.name(), "MyService");
///
/// let service = GotoAddressLabelServiceFactory::create_default();
/// assert_eq!(service.name(), "GotoAddressLabelService");
/// ```
pub struct GotoAddressLabelServiceFactory;

impl GotoAddressLabelServiceFactory {
    /// Create a new service with the given name.
    pub fn create(name: impl Into<String>) -> GotoAddressLabelServiceImpl {
        GotoAddressLabelServiceImpl::new(name)
    }

    /// Create a service with the default name.
    pub fn create_default() -> GotoAddressLabelServiceImpl {
        GotoAddressLabelServiceImpl::new("GotoAddressLabelService")
    }

    /// Create a service with a pre-registered label map.
    pub fn create_with_labels(
        name: impl Into<String>,
        labels: impl IntoIterator<Item = (String, Address)>,
    ) -> GotoAddressLabelServiceImpl {
        let mut service = GotoAddressLabelServiceImpl::new(name);
        for (label, addr) in labels {
            service.register_label(label, addr);
        }
        service
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_goto_query_new() {
        let query = GotoQuery::new("0x401000");
        assert_eq!(query.raw_query, "0x401000");
        assert!(!query.resolved);
        assert!(query.resolved_address.is_none());
        assert!(query.error.is_none());
    }

    #[test]
    fn test_goto_query_resolve_hex() {
        let mut query = GotoQuery::new("0x401000");
        assert!(query.resolve_as_address());
        assert!(query.resolved);
        assert_eq!(query.resolved_address, Some(Address::new(0x401000)));
    }

    #[test]
    fn test_goto_query_resolve_hex_no_prefix() {
        let mut query = GotoQuery::new("401000");
        assert!(query.resolve_as_address());
        assert_eq!(query.resolved_address, Some(Address::new(0x401000)));
    }

    #[test]
    fn test_goto_query_resolve_dollar_prefix() {
        let mut query = GotoQuery::new("$401000");
        assert!(query.resolve_as_address());
        assert_eq!(query.resolved_address, Some(Address::new(0x401000)));
    }

    #[test]
    fn test_goto_query_resolve_invalid() {
        let mut query = GotoQuery::new("not_an_address");
        assert!(!query.resolve_as_address());
        assert!(!query.resolved);
        assert!(query.error.is_some());
    }

    #[test]
    fn test_goto_query_set_resolved() {
        let mut query = GotoQuery::new("main");
        query.set_resolved(Address::new(0x401000));
        assert!(query.resolved);
        assert_eq!(query.resolved_address, Some(Address::new(0x401000)));
        assert!(query.error.is_none());
    }

    #[test]
    fn test_goto_query_set_error() {
        let mut query = GotoQuery::new("main");
        query.set_error("Label not found");
        assert!(!query.resolved);
        assert!(query.resolved_address.is_none());
        assert_eq!(query.error.as_deref(), Some("Label not found"));
    }

    #[test]
    fn test_goto_query_looks_like_address() {
        assert!(GotoQuery::new("0x401000").looks_like_address());
        assert!(GotoQuery::new("0X401000").looks_like_address());
        assert!(GotoQuery::new("$401000").looks_like_address());
        assert!(GotoQuery::new("401000").looks_like_address());
        assert!(!GotoQuery::new("main").looks_like_address());
        assert!(!GotoQuery::new("_start").looks_like_address());
    }

    #[test]
    fn test_goto_query_display() {
        let query = GotoQuery::new("0x401000");
        assert_eq!(format!("{}", query), "0x401000 (pending)");

        let mut query = GotoQuery::new("0x401000");
        query.resolve_as_address();
        assert_eq!(format!("{}", query), "0x401000 -> 0x401000");

        let mut query = GotoQuery::new("bad");
        query.resolve_as_address();
        assert!(format!("{}", query).contains("error:"));
    }

    #[test]
    fn test_goto_query_result() {
        let success = GotoQueryResult::Success {
            address: Address::new(0x401000),
        };
        assert!(success.is_success());
        assert!(!success.is_error());
        assert_eq!(success.address(), Some(Address::new(0x401000)));

        let error = GotoQueryResult::Error {
            message: "Not found".to_string(),
        };
        assert!(!error.is_success());
        assert!(error.is_error());
        assert_eq!(error.error_message(), Some("Not found"));

        let multi = GotoQueryResult::MultipleMatches { count: 5 };
        assert!(multi.is_multiple_matches());
    }

    #[test]
    fn test_service_new() {
        let service = GotoAddressLabelServiceImpl::new("Test");
        assert_eq!(service.name(), "Test");
        assert!(service.current_address().is_none());
        assert!(service.current_program().is_none());
        assert!(service.history().is_empty());
    }

    #[test]
    fn test_service_go_to() {
        let mut service = GotoAddressLabelServiceImpl::new("Test");
        assert!(service.go_to(Address::new(0x401000)));
        assert_eq!(service.current_address(), Some(Address::new(0x401000)));
        assert_eq!(service.history().len(), 1);
    }

    #[test]
    fn test_service_go_to_query_hex() {
        let mut service = GotoAddressLabelServiceImpl::new("Test");
        assert!(service.go_to_query("0x401000"));
        assert_eq!(service.current_address(), Some(Address::new(0x401000)));
    }

    #[test]
    fn test_service_go_to_query_label() {
        let mut service = GotoAddressLabelServiceImpl::new("Test");
        service.register_label("main", Address::new(0x401000));
        assert!(service.go_to_query("main"));
        assert_eq!(service.current_address(), Some(Address::new(0x401000)));
    }

    #[test]
    fn test_service_go_to_query_unresolved() {
        let mut service = GotoAddressLabelServiceImpl::new("Test");
        assert!(!service.go_to_query("nonexistent_label"));
    }

    #[test]
    fn test_service_history_navigation() {
        let mut service = GotoAddressLabelServiceImpl::new("Test");

        service.go_to(Address::new(0x1000));
        service.go_to(Address::new(0x2000));
        service.go_to(Address::new(0x3000));

        assert_eq!(service.current_address(), Some(Address::new(0x3000)));
        assert!(service.has_previous());
        assert!(!service.has_next());

        assert!(service.go_back());
        assert_eq!(service.current_address(), Some(Address::new(0x2000)));
        assert!(service.has_previous());
        assert!(service.has_next());

        assert!(service.go_back());
        assert_eq!(service.current_address(), Some(Address::new(0x1000)));
        assert!(!service.has_previous());

        assert!(service.go_forward());
        assert_eq!(service.current_address(), Some(Address::new(0x2000)));
    }

    #[test]
    fn test_service_history_truncation_on_new_nav() {
        let mut service = GotoAddressLabelServiceImpl::new("Test");

        service.go_to(Address::new(0x1000));
        service.go_to(Address::new(0x2000));
        service.go_to(Address::new(0x3000));

        // Go back to 0x2000
        service.go_back();
        assert_eq!(service.current_address(), Some(Address::new(0x2000)));

        // Navigate to new address -- should truncate 0x3000 from history
        service.go_to(Address::new(0x4000));
        assert_eq!(service.current_address(), Some(Address::new(0x4000)));
        assert!(!service.has_next());
        assert!(service.has_previous());
    }

    #[test]
    fn test_service_clear_history() {
        let mut service = GotoAddressLabelServiceImpl::new("Test");
        service.go_to(Address::new(0x1000));
        service.go_to(Address::new(0x2000));

        service.clear_history();
        assert!(service.history().is_empty());
        assert!(!service.has_previous());
        assert!(!service.has_next());
    }

    #[test]
    fn test_service_labels() {
        let mut service = GotoAddressLabelServiceImpl::new("Test");

        service.register_label("main", Address::new(0x401000));
        service.register_label("_start", Address::new(0x400000));

        assert!(service.has_label("main"));
        assert!(service.has_label("_start"));
        assert!(!service.has_label("nonexistent"));
        assert_eq!(service.label_count(), 2);
        assert_eq!(service.label_address("main"), Some(Address::new(0x401000)));

        service.unregister_label("main");
        assert!(!service.has_label("main"));
        assert_eq!(service.label_count(), 1);
    }

    #[test]
    fn test_service_resolve_query() {
        let mut service = GotoAddressLabelServiceImpl::new("Test");
        service.register_label("main", Address::new(0x401000));

        // Hex address
        let result = service.resolve_query("0x401000");
        assert!(result.is_success());
        assert_eq!(result.address(), Some(Address::new(0x401000)));

        // Label
        let result = service.resolve_query("main");
        assert!(result.is_success());
        assert_eq!(result.address(), Some(Address::new(0x401000)));

        // Unknown
        let result = service.resolve_query("nonexistent");
        assert!(result.is_error());
    }

    #[test]
    fn test_service_can_go_to() {
        let service = GotoAddressLabelServiceImpl::new("Test");
        assert!(service.can_go_to(Address::new(0x1000)));
        assert!(service.can_go_to(Address::new(0xFFFFFFFF)));
    }

    #[test]
    fn test_service_can_resolve_query() {
        let mut service = GotoAddressLabelServiceImpl::new("Test");
        service.register_label("main", Address::new(0x401000));

        assert!(service.can_resolve_query("0x401000"));
        assert!(service.can_resolve_query("main"));
        assert!(!service.can_resolve_query("nonexistent"));
    }

    #[test]
    fn test_service_max_history() {
        let mut service = GotoAddressLabelServiceImpl::new("Test");
        service.set_max_history(5);

        for i in 0..10 {
            service.go_to(Address::new(i * 0x1000));
        }

        assert!(service.history_len() <= 5);
    }

    #[test]
    fn test_service_set_program() {
        let mut service = GotoAddressLabelServiceImpl::new("Test");
        assert!(service.current_program().is_none());

        service.set_program("test.exe");
        assert_eq!(service.current_program(), Some("test.exe"));
    }

    #[test]
    fn test_service_factory() {
        let service = GotoAddressLabelServiceFactory::create("MyService");
        assert_eq!(service.name(), "MyService");

        let service = GotoAddressLabelServiceFactory::create_default();
        assert_eq!(service.name(), "GotoAddressLabelService");

        let service = GotoAddressLabelServiceFactory::create_with_labels(
            "Test",
            vec![
                ("main".to_string(), Address::new(0x401000)),
                ("_start".to_string(), Address::new(0x400000)),
            ],
        );
        assert_eq!(service.label_count(), 2);
        assert!(service.has_label("main"));
    }
}
