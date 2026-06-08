//! GoTo service for listing code comparison displays.
//!
//! Ported from Ghidra's `ListingDisplayGoToService` Java class in
//! `ghidra.features.base.codecompare.listing`.
//!
//! In Ghidra, a `GoToService` allows users to navigate to addresses,
//! labels, and queries. The listing code comparison view provides a
//! specialized GoToService for each side that validates addresses
//! against the listing's current address range before navigating.
//!
//! In this Rust port, we capture the logical navigation behavior
//! without the Swing/docking framework dependency.
//!
//! # Key types
//!
//! - [`GoToServiceState`] -- the state of a GoTo service for a listing
//! - [`GoToResult`] -- the result of a GoTo operation
//! - [`QueryResult`] -- the result of a label/address query

use super::super::panel::{AddressSet, ProgramInfo};
use super::navigator::{NavigationResult, NavigatorState};
use crate::codecompare::model::ComparisonSide;

/// The result of a GoTo operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GoToResult {
    /// Navigation was successful.
    Success { address: u64 },
    /// The address is outside the listing's current view.
    OutsideView { address: u64 },
    /// There is no program loaded in the listing.
    NoProgram,
    /// The program does not match the listing's program.
    ProgramMismatch {
        expected: u64,
        actual: u64,
    },
    /// Navigation to external locations is not supported.
    ExternalNotSupported,
    /// The service has been disposed.
    Disposed,
}

impl GoToResult {
    /// Check if the operation was successful.
    pub fn is_success(&self) -> bool {
        matches!(self, Self::Success { .. })
    }

    /// Get the target address, if available.
    pub fn address(&self) -> Option<u64> {
        match self {
            Self::Success { address } | Self::OutsideView { address } => Some(*address),
            _ => None,
        }
    }
}

/// The result of a label/address query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueryResult {
    /// Query resolved to an address.
    Resolved { address: u64 },
    /// The query string was not found.
    NotFound { query: String },
    /// Queries are not supported in the comparison view.
    NotSupported,
}

/// The state of a GoTo service for a listing display.
///
/// Ported from Ghidra's `ListingDisplayGoToService` Java class.
///
/// Each side of a dual listing comparison has its own GoToService.
/// The service validates addresses against the listing's current
/// address range before navigating, and prevents navigation to
/// external locations.
///
/// # Example
///
/// ```rust
/// use ghidra_features::codecompare::listing::go_to_service::*;
/// use ghidra_features::codecompare::listing::navigator::*;
/// use ghidra_features::codecompare::panel::*;
/// use ghidra_features::codecompare::model::ComparisonSide;
///
/// let prog = ProgramInfo::new(1, "/project/test", "test");
/// let addresses = AddressSet::single(0x1000, 0x2000);
/// let nav = NavigatorState::new(ComparisonSide::Left, prog, addresses);
/// let mut service = GoToServiceState::new(nav);
///
/// let result = service.go_to_address(0x1500);
/// assert!(result.is_success());
/// ```
#[derive(Debug)]
pub struct GoToServiceState {
    /// The underlying navigator.
    navigator: NavigatorState,
    /// Status message from the last operation.
    last_status: Option<String>,
}

impl GoToServiceState {
    /// Create a new GoTo service state.
    pub fn new(navigator: NavigatorState) -> Self {
        Self {
            navigator,
            last_status: None,
        }
    }

    /// Get a reference to the underlying navigator.
    pub fn navigator(&self) -> &NavigatorState {
        &self.navigator
    }

    /// Get a mutable reference to the underlying navigator.
    pub fn navigator_mut(&mut self) -> &mut NavigatorState {
        &mut self.navigator
    }

    /// Get the last status message.
    pub fn last_status(&self) -> Option<&str> {
        self.last_status.as_deref()
    }

    /// Clear the status message.
    pub fn clear_status(&mut self) {
        self.last_status = None;
    }

    /// Navigate to an address.
    ///
    /// Validates that the address is within the listing's current
    /// address range before navigating.
    pub fn go_to_address(&mut self, address: u64) -> GoToResult {
        if self.navigator.is_disposed() {
            return GoToResult::Disposed;
        }

        if !self.navigator.has_program() {
            self.last_status = Some("No program loaded".to_string());
            return GoToResult::NoProgram;
        }

        if !self.navigator.validate_address(address) {
            self.last_status = Some(format!(
                "\"0x{:x}\" is outside the current listing's view",
                address
            ));
            return GoToResult::OutsideView { address };
        }

        match self.navigator.go_to(address) {
            NavigationResult::Success { address } => {
                self.last_status = None;
                GoToResult::Success { address }
            }
            NavigationResult::OutOfRange { address } => {
                self.last_status = Some(format!(
                    "\"0x{:x}\" is outside the current listing's view",
                    address
                ));
                GoToResult::OutsideView { address }
            }
            NavigationResult::NoProgram => GoToResult::NoProgram,
            NavigationResult::ProgramMismatch { expected, actual } => {
                GoToResult::ProgramMismatch { expected, actual }
            }
            NavigationResult::Rejected => GoToResult::Disposed,
        }
    }

    /// Navigate to a program location (program ID + address).
    pub fn go_to_location(
        &mut self,
        program_id: u64,
        address: u64,
    ) -> GoToResult {
        if self.navigator.is_disposed() {
            return GoToResult::Disposed;
        }

        if !self.navigator.has_program() {
            return GoToResult::NoProgram;
        }

        match self.navigator.go_to_location(program_id, address) {
            NavigationResult::Success { address } => {
                self.last_status = None;
                GoToResult::Success { address }
            }
            NavigationResult::OutOfRange { address } => {
                self.last_status = Some(format!(
                    "\"0x{:x}\" is outside the current listing's view",
                    address
                ));
                GoToResult::OutsideView { address }
            }
            NavigationResult::NoProgram => GoToResult::NoProgram,
            NavigationResult::ProgramMismatch { expected, actual } => {
                GoToResult::ProgramMismatch { expected, actual }
            }
            NavigationResult::Rejected => GoToResult::Disposed,
        }
    }

    /// Attempt to navigate to an external location.
    ///
    /// External locations are not supported in the comparison view.
    pub fn go_to_external(&mut self) -> GoToResult {
        self.last_status =
            Some("Can't navigate to an external function from here".to_string());
        GoToResult::ExternalNotSupported
    }

    /// Query for an address by label or address string.
    ///
    /// In the comparison view, queries are not supported because
    /// the view only shows a fixed set of addresses.
    pub fn go_to_query(&mut self, query: &str) -> QueryResult {
        // Try to parse as a hex address
        let cleaned = query.trim().trim_start_matches("0x").trim_start_matches("0X");
        if let Ok(addr) = u64::from_str_radix(cleaned, 16) {
            match self.go_to_address(addr) {
                GoToResult::Success { address } => QueryResult::Resolved { address },
                _ => QueryResult::NotFound {
                    query: query.to_string(),
                },
            }
        } else {
            QueryResult::NotSupported
        }
    }

    /// Get the current address from the navigator.
    pub fn current_address(&self) -> Option<u64> {
        self.navigator.current_address()
    }

    /// Get the side this service operates on.
    pub fn side(&self) -> ComparisonSide {
        self.navigator.side()
    }

    /// Check if the service has a program.
    pub fn has_program(&self) -> bool {
        self.navigator.has_program()
    }

    /// Dispose of this service.
    pub fn dispose(&mut self) {
        self.navigator.dispose();
        self.last_status = None;
    }
}

/// A pair of GoTo services for left and right sides.
#[derive(Debug)]
pub struct GoToServicePair {
    /// The left-side GoTo service.
    pub left: GoToServiceState,
    /// The right-side GoTo service.
    pub right: GoToServiceState,
}

impl GoToServicePair {
    /// Create a new GoTo service pair from navigator pair.
    pub fn new(
        left_program: ProgramInfo,
        left_addresses: AddressSet,
        right_program: ProgramInfo,
        right_addresses: AddressSet,
    ) -> Self {
        Self {
            left: GoToServiceState::new(NavigatorState::new(
                ComparisonSide::Left,
                left_program,
                left_addresses,
            )),
            right: GoToServiceState::new(NavigatorState::new(
                ComparisonSide::Right,
                right_program,
                right_addresses,
            )),
        }
    }

    /// Create an empty GoTo service pair.
    pub fn empty() -> Self {
        Self {
            left: GoToServiceState::new(NavigatorState::empty(ComparisonSide::Left)),
            right: GoToServiceState::new(NavigatorState::empty(ComparisonSide::Right)),
        }
    }

    /// Get the service for the given side.
    pub fn get(&self, side: ComparisonSide) -> &GoToServiceState {
        match side {
            ComparisonSide::Left => &self.left,
            ComparisonSide::Right => &self.right,
        }
    }

    /// Get a mutable reference to the service for the given side.
    pub fn get_mut(&mut self, side: ComparisonSide) -> &mut GoToServiceState {
        match side {
            ComparisonSide::Left => &mut self.left,
            ComparisonSide::Right => &mut self.right,
        }
    }

    /// Dispose of both services.
    pub fn dispose(&mut self) {
        self.left.dispose();
        self.right.dispose();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_program(id: u64, path: &str, name: &str) -> ProgramInfo {
        ProgramInfo::new(id, path, name)
    }

    fn make_service(side: ComparisonSide) -> GoToServiceState {
        let prog = make_program(1, "/project/test", "test");
        let addrs = AddressSet::single(0x1000, 0x2000);
        let nav = NavigatorState::new(side, prog, addrs);
        GoToServiceState::new(nav)
    }

    fn make_empty_service(side: ComparisonSide) -> GoToServiceState {
        let nav = NavigatorState::empty(side);
        GoToServiceState::new(nav)
    }

    // --- GoToResult tests ---

    #[test]
    fn test_go_to_result_success() {
        let result = GoToResult::Success { address: 0x1000 };
        assert!(result.is_success());
        assert_eq!(result.address(), Some(0x1000));
    }

    #[test]
    fn test_go_to_result_outside_view() {
        let result = GoToResult::OutsideView { address: 0x5000 };
        assert!(!result.is_success());
        assert_eq!(result.address(), Some(0x5000));
    }

    #[test]
    fn test_go_to_result_no_program() {
        let result = GoToResult::NoProgram;
        assert!(!result.is_success());
        assert_eq!(result.address(), None);
    }

    #[test]
    fn test_go_to_result_disposed() {
        let result = GoToResult::Disposed;
        assert!(!result.is_success());
    }

    #[test]
    fn test_go_to_result_external() {
        let result = GoToResult::ExternalNotSupported;
        assert!(!result.is_success());
    }

    // --- GoToServiceState tests ---

    #[test]
    fn test_go_to_service_new() {
        let service = make_service(ComparisonSide::Left);
        assert!(service.has_program());
        assert_eq!(service.side(), ComparisonSide::Left);
        assert!(service.last_status().is_none());
    }

    #[test]
    fn test_go_to_service_go_to_address_success() {
        let mut service = make_service(ComparisonSide::Left);
        let result = service.go_to_address(0x1500);
        assert!(result.is_success());
        assert_eq!(service.current_address(), Some(0x1500));
        assert!(service.last_status().is_none());
    }

    #[test]
    fn test_go_to_service_go_to_address_outside() {
        let mut service = make_service(ComparisonSide::Left);
        let result = service.go_to_address(0x5000);
        assert!(!result.is_success());
        assert_eq!(service.current_address(), None);
        assert!(service.last_status().is_some());
        assert!(service.last_status().unwrap().contains("outside"));
    }

    #[test]
    fn test_go_to_service_go_to_address_no_program() {
        let mut service = make_empty_service(ComparisonSide::Left);
        let result = service.go_to_address(0x1000);
        assert!(!result.is_success());
    }

    #[test]
    fn test_go_to_service_go_to_address_boundary() {
        let mut service = make_service(ComparisonSide::Left);

        // At start
        let result = service.go_to_address(0x1000);
        assert!(result.is_success());

        // At end
        let result = service.go_to_address(0x2000);
        assert!(result.is_success());

        // Just outside
        let result = service.go_to_address(0x2001);
        assert!(!result.is_success());
    }

    #[test]
    fn test_go_to_service_go_to_location() {
        let mut service = make_service(ComparisonSide::Left);

        // Correct program
        let result = service.go_to_location(1, 0x1500);
        assert!(result.is_success());

        // Wrong program
        let result = service.go_to_location(2, 0x1500);
        assert!(!result.is_success());
    }

    #[test]
    fn test_go_to_service_go_to_location_no_program() {
        let mut service = make_empty_service(ComparisonSide::Left);
        let result = service.go_to_location(1, 0x1000);
        assert!(!result.is_success());
    }

    #[test]
    fn test_go_to_service_go_to_external() {
        let mut service = make_service(ComparisonSide::Left);
        let result = service.go_to_external();
        assert!(!result.is_success());
        assert!(service.last_status().is_some());
        assert!(service.last_status().unwrap().contains("external"));
    }

    #[test]
    fn test_go_to_service_go_to_query_hex() {
        let mut service = make_service(ComparisonSide::Left);
        let result = service.go_to_query("0x1500");
        assert!(matches!(result, QueryResult::Resolved { address: 0x1500 }));
        assert_eq!(service.current_address(), Some(0x1500));
    }

    #[test]
    fn test_go_to_service_go_to_query_hex_no_prefix() {
        let mut service = make_service(ComparisonSide::Left);
        let result = service.go_to_query("1500");
        assert!(matches!(result, QueryResult::Resolved { address: 0x1500 }));
    }

    #[test]
    fn test_go_to_service_go_to_query_outside() {
        let mut service = make_service(ComparisonSide::Left);
        let result = service.go_to_query("0x5000");
        assert!(matches!(result, QueryResult::NotFound { .. }));
    }

    #[test]
    fn test_go_to_service_go_to_query_label() {
        let mut service = make_service(ComparisonSide::Left);
        let result = service.go_to_query("main");
        assert!(matches!(result, QueryResult::NotSupported));
    }

    #[test]
    fn test_go_to_service_clear_status() {
        let mut service = make_service(ComparisonSide::Left);
        service.go_to_address(0x5000);
        assert!(service.last_status().is_some());

        service.clear_status();
        assert!(service.last_status().is_none());
    }

    #[test]
    fn test_go_to_service_dispose() {
        let mut service = make_service(ComparisonSide::Left);
        service.go_to_address(0x1500);

        service.dispose();
        assert!(!service.has_program());
        assert!(service.current_address().is_none());
        assert!(service.last_status().is_none());
    }

    #[test]
    fn test_go_to_service_disposed_rejects() {
        let mut service = make_service(ComparisonSide::Left);
        service.dispose();

        let result = service.go_to_address(0x1500);
        assert!(!result.is_success());
    }

    // --- GoToServicePair tests ---

    #[test]
    fn test_go_to_service_pair_new() {
        let prog1 = make_program(1, "/left", "left");
        let prog2 = make_program(2, "/right", "right");
        let addrs1 = AddressSet::single(0x1000, 0x2000);
        let addrs2 = AddressSet::single(0x3000, 0x4000);

        let pair = GoToServicePair::new(prog1, addrs1, prog2, addrs2);
        assert!(pair.left.has_program());
        assert!(pair.right.has_program());
    }

    #[test]
    fn test_go_to_service_pair_empty() {
        let pair = GoToServicePair::empty();
        assert!(!pair.left.has_program());
        assert!(!pair.right.has_program());
    }

    #[test]
    fn test_go_to_service_pair_get() {
        let pair = GoToServicePair::empty();
        assert_eq!(pair.get(ComparisonSide::Left).side(), ComparisonSide::Left);
        assert_eq!(
            pair.get(ComparisonSide::Right).side(),
            ComparisonSide::Right
        );
    }

    #[test]
    fn test_go_to_service_pair_get_mut() {
        let prog = make_program(1, "/test", "test");
        let addrs = AddressSet::single(0x1000, 0x2000);
        let mut pair = GoToServicePair::new(
            prog.clone(),
            addrs.clone(),
            prog,
            addrs,
        );

        let result = pair.get_mut(ComparisonSide::Left).go_to_address(0x1500);
        assert!(result.is_success());
    }

    #[test]
    fn test_go_to_service_pair_dispose() {
        let prog = make_program(1, "/test", "test");
        let addrs = AddressSet::single(0x1000, 0x2000);
        let mut pair = GoToServicePair::new(
            prog.clone(),
            addrs.clone(),
            prog,
            addrs,
        );

        pair.dispose();
        assert!(!pair.left.has_program());
        assert!(!pair.right.has_program());
    }

    // --- QueryResult tests ---

    #[test]
    fn test_query_result_resolved() {
        let result = QueryResult::Resolved { address: 0x1000 };
        match result {
            QueryResult::Resolved { address } => assert_eq!(address, 0x1000),
            _ => panic!("Expected Resolved"),
        }
    }

    #[test]
    fn test_query_result_not_found() {
        let result = QueryResult::NotFound {
            query: "main".to_string(),
        };
        match result {
            QueryResult::NotFound { query } => assert_eq!(query, "main"),
            _ => panic!("Expected NotFound"),
        }
    }

    #[test]
    fn test_query_result_not_supported() {
        let result = QueryResult::NotSupported;
        assert!(matches!(result, QueryResult::NotSupported));
    }
}
