//! GoTo navigation service trait.
//!
//! Ported from Ghidra's `ghidra.app.services.GoToService`.
//!
//! The [`GoToService`] trait defines the contract for navigation within
//! a Ghidra program. Plugins implement this trait to provide address
//! lookup, label resolution, and query-based navigation.

use std::fmt;
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Supporting types
// ---------------------------------------------------------------------------

/// A program address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Address(pub u64);

impl Address {
    pub fn new(val: u64) -> Self {
        Self(val)
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:08x}", self.0)
    }
}

/// A Ghidra program (minimal).
#[derive(Debug, Clone)]
pub struct Program {
    pub name: String,
}

impl Program {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
        }
    }
}

/// A location within a program (address + context).
#[derive(Debug, Clone)]
pub struct ProgramLocation {
    pub address: Address,
    pub label: Option<String>,
}

impl ProgramLocation {
    pub fn new(address: Address) -> Self {
        Self {
            address,
            label: None,
        }
    }

    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }
}

/// An external library location.
#[derive(Debug, Clone)]
pub struct ExternalLocation {
    pub library_name: String,
    pub label: String,
    pub address: Option<Address>,
}

/// Query data for GoTo operations.
#[derive(Debug, Clone)]
pub struct QueryData {
    pub query: String,
    pub is_case_sensitive: bool,
    pub use_qualified_search: bool,
}

impl QueryData {
    pub fn new(query: impl Into<String>) -> Self {
        Self {
            query: query.into(),
            is_case_sensitive: false,
            use_qualified_search: true,
        }
    }

    pub fn with_case_sensitive(mut self, yes: bool) -> Self {
        self.is_case_sensitive = yes;
        self
    }

    pub fn with_qualified_search(mut self, yes: bool) -> Self {
        self.use_qualified_search = yes;
        self
    }
}

/// A Navigatable is a view that can display program locations.
pub trait Navigatable: fmt::Debug + Send + Sync {
    /// Get the program displayed in this navigatable.
    fn get_program(&self) -> Option<Arc<Program>>;

    /// Navigate to a location. Returns `true` if navigation succeeded.
    fn go_to(&self, program: &Program, location: &ProgramLocation) -> bool;
}

/// Task monitor for long-running queries.
pub trait TaskMonitor: fmt::Debug + Send + Sync {
    fn is_cancelled(&self) -> bool;
    fn set_progress(&self, value: u64);
    fn set_message(&self, msg: &str);
}

/// A basic, no-op task monitor.
#[derive(Debug)]
pub struct BasicTaskMonitor;

impl TaskMonitor for BasicTaskMonitor {
    fn is_cancelled(&self) -> bool {
        false
    }
    fn set_progress(&self, _value: u64) {}
    fn set_message(&self, _msg: &str) {}
}

// ---------------------------------------------------------------------------
// GoToService trait
// ---------------------------------------------------------------------------

/// Trait for the GoTo navigation service.
///
/// Provides methods for navigating to addresses, locations, and
/// performing queries that resolve to locations. Plugins register
/// implementations of this trait with the service registry.
///
/// # Valid query characters
///
/// GoTo queries may contain delimiters like `.`, `:`, and `*` for
/// namespace-qualified lookups and wildcards. These are defined in
/// [`GoToService::VALID_GOTO_CHARS`].
pub trait GoToService: fmt::Debug + Send + Sync {
    /// Characters that are valid in GoTo queries (namespace delimiters, wildcards).
    const VALID_GOTO_CHARS: &'static [char] = &['.', ':', '*'];

    /// Navigate to a program location.
    fn go_to_location(&self, loc: &ProgramLocation) -> bool;

    /// Navigate to a program location within a specific program.
    fn go_to_location_in_program(&self, loc: &ProgramLocation, program: &Program) -> bool;

    /// Navigate to a location using a specific navigatable.
    fn go_to_navigatable(
        &self,
        navigatable: &dyn Navigatable,
        loc: &ProgramLocation,
        program: &Program,
    ) -> bool;

    /// Navigate from one address to another.
    fn go_to_address(&self, from: Address, to: Address) -> bool;

    /// Navigate to an address using a navigatable.
    fn go_to_address_navigatable(&self, navigatable: &dyn Navigatable, to: Address) -> bool;

    /// Navigate to an address within a program.
    fn go_to_address_in_program(&self, to: Address, program: &Program) -> bool;

    /// Navigate to an external location.
    fn go_to_external_location(
        &self,
        ext_loc: &ExternalLocation,
        check_navigation_option: bool,
    ) -> bool;

    /// Perform a GoTo query (resolves a string to a location).
    fn go_to_query(&self, from_addr: Address, query: &QueryData, monitor: &dyn TaskMonitor)
        -> bool;

    /// Get the default navigatable.
    fn get_default_navigatable(&self) -> &dyn Navigatable;
}

// ---------------------------------------------------------------------------
// GoToServiceListener
// ---------------------------------------------------------------------------

/// Listener for GoTo query completion events.
pub trait GoToServiceListener: fmt::Debug + Send + Sync {
    /// Called when the query completes.
    fn query_completed(&self, success: bool, result_count: usize);
}

// ---------------------------------------------------------------------------
// Default / no-op implementation
// ---------------------------------------------------------------------------

/// A no-op GoTo service that always returns `false`.
///
/// Useful as a placeholder when no real navigation service is available.
#[derive(Debug)]
pub struct NoOpGoToService {
    default_nav: NoOpNavigatable,
}

impl NoOpGoToService {
    pub fn new() -> Self {
        Self {
            default_nav: NoOpNavigatable,
        }
    }
}

impl Default for NoOpGoToService {
    fn default() -> Self {
        Self::new()
    }
}

impl GoToService for NoOpGoToService {
    fn go_to_location(&self, _loc: &ProgramLocation) -> bool {
        false
    }

    fn go_to_location_in_program(&self, _loc: &ProgramLocation, _program: &Program) -> bool {
        false
    }

    fn go_to_navigatable(
        &self,
        _navigatable: &dyn Navigatable,
        _loc: &ProgramLocation,
        _program: &Program,
    ) -> bool {
        false
    }

    fn go_to_address(&self, _from: Address, _to: Address) -> bool {
        false
    }

    fn go_to_address_navigatable(&self, _navigatable: &dyn Navigatable, _to: Address) -> bool {
        false
    }

    fn go_to_address_in_program(&self, _to: Address, _program: &Program) -> bool {
        false
    }

    fn go_to_external_location(
        &self,
        _ext_loc: &ExternalLocation,
        _check_navigation_option: bool,
    ) -> bool {
        false
    }

    fn go_to_query(
        &self,
        _from_addr: Address,
        _query: &QueryData,
        _monitor: &dyn TaskMonitor,
    ) -> bool {
        false
    }

    fn get_default_navigatable(&self) -> &dyn Navigatable {
        &self.default_nav
    }
}

/// A no-op navigatable.
#[derive(Debug)]
pub struct NoOpNavigatable;

impl Navigatable for NoOpNavigatable {
    fn get_program(&self) -> Option<Arc<Program>> {
        None
    }

    fn go_to(&self, _program: &Program, _location: &ProgramLocation) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_display() {
        assert_eq!(Address::new(0xDEADBEEF).to_string(), "0xdeadbeef");
    }

    #[test]
    fn test_program_location() {
        let loc = ProgramLocation::new(Address::new(0x401000));
        assert_eq!(loc.address, Address::new(0x401000));
        assert!(loc.label.is_none());

        let loc = ProgramLocation::new(Address::new(0x401000)).with_label("main");
        assert_eq!(loc.label.as_deref(), Some("main"));
    }

    #[test]
    fn test_external_location() {
        let ext = ExternalLocation {
            library_name: "kernel32.dll".into(),
            label: "CreateFileW".into(),
            address: Some(Address::new(0x7FF00000)),
        };
        assert_eq!(ext.library_name, "kernel32.dll");
        assert_eq!(ext.label, "CreateFileW");
    }

    #[test]
    fn test_query_data() {
        let q = QueryData::new("main").with_case_sensitive(true);
        assert_eq!(q.query, "main");
        assert!(q.is_case_sensitive);
        assert!(q.use_qualified_search); // default
    }

    #[test]
    fn test_query_data_qualified() {
        let q = QueryData::new("std::string").with_qualified_search(false);
        assert!(!q.use_qualified_search);
    }

    #[test]
    fn test_goto_service_valid_chars() {
        assert_eq!(NoOpGoToService::VALID_GOTO_CHARS, &['.', ':', '*']);
    }

    #[test]
    fn test_noop_goto_service() {
        let svc = NoOpGoToService::new();
        let program = Program::new("test");
        let loc = ProgramLocation::new(Address::new(0x401000));

        assert!(!svc.go_to_location(&loc));
        assert!(!svc.go_to_location_in_program(&loc, &program));
        assert!(!svc.go_to_address(Address::new(0), Address::new(0x401000)));
        assert!(!svc.go_to_address_in_program(Address::new(0x401000), &program));
        assert!(!svc.go_to_query(Address::new(0), &QueryData::new("main"), &BasicTaskMonitor,));
    }

    #[test]
    fn test_noop_navigatable() {
        let nav = NoOpNavigatable;
        assert!(nav.get_program().is_none());
        assert!(!nav.go_to(
            &Program::new("test"),
            &ProgramLocation::new(Address::new(0))
        ));
    }

    #[test]
    fn test_noop_external_location() {
        let svc = NoOpGoToService::new();
        let ext = ExternalLocation {
            library_name: "libc.so".into(),
            label: "malloc".into(),
            address: None,
        };
        assert!(!svc.go_to_external_location(&ext, true));
        assert!(!svc.go_to_external_location(&ext, false));
    }

    #[test]
    fn test_navigatable_dyn_dispatch() {
        let svc = NoOpGoToService::new();
        let nav = svc.get_default_navigatable();
        assert!(!nav.go_to(
            &Program::new("test"),
            &ProgramLocation::new(Address::new(0))
        ));
    }

    #[test]
    fn test_address_equality() {
        assert_eq!(Address::new(0x1000), Address::new(0x1000));
        assert_ne!(Address::new(0x1000), Address::new(0x2000));
    }
}
