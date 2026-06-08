//! GoTo service and navigator for listing code comparison.
//!
//! Ported from Ghidra's `ListingDisplayGoToService` and
//! `ListingDisplayNavigator` Java classes in
//! `ghidra.features.base.codecompare.listing`.
//!
//! When comparing two listings side by side, each side can display a
//! completely different address range. A standard GoTo service would
//! navigate globally, but the comparison view needs a GoTo service
//! that navigates relative to a specific listing panel. Similarly,
//! each listing panel needs its own `Navigatable` so that external
//! components (like the symbol tree) can navigate to the correct side.
//!
//! In this Rust port we capture the logical state and navigation behavior
//! without the Swing/docking framework dependency.
//!
//! # Key types
//!
//! - [`NavigationTarget`] -- a target address or location for navigation
//! - [`GoToResult`] -- the result of a GoTo operation
//! - [`ListingGoToService`] -- GoTo service scoped to a single listing panel
//! - [`ListingNavigator`] -- navigator for a listing in a comparison view

use super::super::panel::AddressSet;

/// A target address or location for navigation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NavigationTarget {
    /// Navigate to a specific address.
    Address(u64),
    /// Navigate to a specific address with label context.
    LabeledAddress {
        address: u64,
        label: String,
    },
    /// Navigate to the entry point of a function.
    FunctionEntry {
        name: String,
        address: u64,
    },
}

impl NavigationTarget {
    /// Get the address of this navigation target.
    pub fn address(&self) -> u64 {
        match self {
            Self::Address(addr) => *addr,
            Self::LabeledAddress { address, .. } => *address,
            Self::FunctionEntry { address, .. } => *address,
        }
    }

    /// Get the label, if any.
    pub fn label(&self) -> Option<&str> {
        match self {
            Self::Address(_) => None,
            Self::LabeledAddress { label, .. } => Some(label),
            Self::FunctionEntry { name, .. } => Some(name),
        }
    }
}

/// The result of a GoTo operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GoToResult {
    /// Navigation succeeded.
    Success {
        /// The address that was navigated to.
        address: u64,
    },
    /// Navigation failed because the address is outside the current view.
    AddressOutOfRange {
        /// The address that was requested.
        requested: u64,
    },
    /// Navigation failed because the target is null/invalid.
    InvalidTarget,
    /// Navigation is not supported for this operation.
    NotSupported {
        reason: String,
    },
}

impl GoToResult {
    /// Check if the navigation succeeded.
    pub fn is_success(&self) -> bool {
        matches!(self, Self::Success { .. })
    }

    /// Get the resulting address, if successful.
    pub fn address(&self) -> Option<u64> {
        match self {
            Self::Success { address } => Some(*address),
            _ => None,
        }
    }
}

/// Trait for GoTo service implementations.
///
/// A GoTo service handles navigation requests within a code comparison view.
/// Each listing panel has its own GoTo service that navigates relative to
/// that panel's address range.
///
/// Ported from Ghidra's `GoToService` interface as used by
/// `ListingDisplayGoToService`.
pub trait GoToService: Send + Sync {
    /// Navigate to a specific address.
    fn go_to_address(&self, address: u64) -> GoToResult;

    /// Navigate to a navigation target.
    fn go_to_target(&self, target: &NavigationTarget) -> GoToResult;

    /// Navigate to an external location (not supported in listing comparison).
    fn go_to_external(&self) -> GoToResult {
        GoToResult::NotSupported {
            reason: "Cannot navigate to external location from a comparison view".to_string(),
        }
    }

    /// Validate that an address is within the current view's address set.
    fn validate_address(&self, address: u64) -> bool;

    /// Get the address set for this service's listing.
    fn address_set(&self) -> &AddressSet;
}

/// GoTo service scoped to a single listing panel in a comparison view.
///
/// This is the Rust equivalent of Ghidra's `ListingDisplayGoToService` Java
/// class. It ensures that navigation requests are handled relative to the
/// specific listing panel, not globally.
///
/// # Example
///
/// ```rust
/// use ghidra_features::codecompare::listing::goto_service::*;
/// use ghidra_features::codecompare::panel::AddressSet;
///
/// let addresses = AddressSet::single(0x1000, 0x2000);
/// let service = ListingGoToService::new(addresses, "left");
///
/// // Valid address
/// let result = service.go_to_address(0x1500);
/// assert!(result.is_success());
///
/// // Out of range
/// let result = service.go_to_address(0x5000);
/// assert!(!result.is_success());
/// ```
#[derive(Debug)]
pub struct ListingGoToService {
    /// The address set for this listing panel.
    addresses: AddressSet,
    /// Identifier for this listing (e.g., "left", "right").
    listing_id: String,
    /// The current cursor address.
    current_address: Option<u64>,
    /// Status message from the last failed navigation.
    last_status: Option<String>,
}

impl ListingGoToService {
    /// Create a new GoTo service for a listing panel.
    pub fn new(addresses: AddressSet, listing_id: impl Into<String>) -> Self {
        Self {
            addresses,
            listing_id: listing_id.into(),
            current_address: None,
            last_status: None,
        }
    }

    /// Get the listing identifier.
    pub fn listing_id(&self) -> &str {
        &self.listing_id
    }

    /// Get the current cursor address.
    pub fn current_address(&self) -> Option<u64> {
        self.current_address
    }

    /// Get the last status message (from a failed navigation).
    pub fn last_status(&self) -> Option<&str> {
        self.last_status.as_deref()
    }

    /// Clear the status message.
    pub fn clear_status(&mut self) {
        self.last_status = None;
    }

    /// Update the address set (e.g., when the view is reloaded).
    pub fn set_addresses(&mut self, addresses: AddressSet) {
        self.addresses = addresses;
    }

    /// Validate an address against the current address set.
    fn validate_and_navigate(&mut self, address: u64) -> GoToResult {
        if !self.addresses.contains(address) {
            self.last_status = Some(format!(
                "\"0x{:x}\" is outside the current listing's view",
                address
            ));
            return GoToResult::AddressOutOfRange {
                requested: address,
            };
        }

        self.current_address = Some(address);
        self.last_status = None;
        GoToResult::Success { address }
    }
}

impl GoToService for ListingGoToService {
    fn go_to_address(&self, address: u64) -> GoToResult {
        // Note: we need interior mutability here in a real implementation,
        // but for the trait we'll validate only. The mutable operations
        // happen through the concrete type's methods.
        if !self.addresses.contains(address) {
            return GoToResult::AddressOutOfRange {
                requested: address,
            };
        }
        GoToResult::Success { address }
    }

    fn go_to_target(&self, target: &NavigationTarget) -> GoToResult {
        let address = target.address();
        self.go_to_address(address)
    }

    fn go_to_external(&self) -> GoToResult {
        GoToResult::NotSupported {
            reason: format!(
                "Can't navigate to an external function from the {} listing",
                self.listing_id
            ),
        }
    }

    fn validate_address(&self, address: u64) -> bool {
        self.addresses.contains(address)
    }

    fn address_set(&self) -> &AddressSet {
        &self.addresses
    }
}

/// The kind of navigatable entity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NavigatableKind {
    /// A listing panel in a comparison view.
    ListingComparison,
    /// A decompiler panel in a comparison view.
    DecompilerComparison,
    /// A function graph panel.
    FunctionGraph,
}

/// Navigator for a listing in a code comparison view.
///
/// This is the Rust equivalent of Ghidra's `ListingDisplayNavigator` Java
/// class. It implements the `Navigatable` interface so that external
/// components can navigate to a specific listing side in the comparison.
///
/// # Example
///
/// ```rust
/// use ghidra_features::codecompare::listing::goto_service::*;
/// use ghidra_features::codecompare::panel::AddressSet;
///
/// let addresses = AddressSet::single(0x1000, 0x2000);
/// let mut nav = ListingNavigator::new(
///     "left_listing",
///     NavigatableKind::ListingComparison,
///     addresses,
/// );
///
/// nav.set_location(Some(0x1500));
/// assert_eq!(nav.location(), Some(0x1500));
///
/// let sel = nav.get_selection();
/// assert!(sel.is_none());
/// ```
#[derive(Debug)]
pub struct ListingNavigator {
    /// Unique identifier for this navigator.
    id: String,
    /// The kind of navigatable entity.
    kind: NavigatableKind,
    /// The address set for this listing.
    addresses: AddressSet,
    /// Current location (cursor address).
    location: Option<u64>,
    /// Current selection (address range).
    selection: Option<(u64, u64)>,
    /// Current highlight (address range).
    highlight: Option<(u64, u64)>,
    /// Whether this navigator is disposed.
    disposed: bool,
    /// Whether this navigator is visible.
    visible: bool,
    /// Whether this navigator supports markers.
    supports_markers: bool,
}

impl ListingNavigator {
    /// Create a new listing navigator.
    pub fn new(
        id: impl Into<String>,
        kind: NavigatableKind,
        addresses: AddressSet,
    ) -> Self {
        Self {
            id: id.into(),
            kind,
            addresses,
            location: None,
            selection: None,
            highlight: None,
            disposed: false,
            visible: true,
            supports_markers: false,
        }
    }

    /// Get the navigator ID.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Get the navigatable kind.
    pub fn kind(&self) -> NavigatableKind {
        self.kind
    }

    /// Get the current location (cursor address).
    pub fn location(&self) -> Option<u64> {
        self.location
    }

    /// Set the current location.
    pub fn set_location(&mut self, address: Option<u64>) {
        self.location = address;
    }

    /// Get the current selection.
    pub fn get_selection(&self) -> Option<(u64, u64)> {
        self.selection
    }

    /// Set the current selection.
    pub fn set_selection(&mut self, selection: Option<(u64, u64)>) {
        self.selection = selection;
    }

    /// Get the current highlight.
    pub fn get_highlight(&self) -> Option<(u64, u64)> {
        self.highlight
    }

    /// Set the current highlight.
    pub fn set_highlight(&mut self, highlight: Option<(u64, u64)>) {
        self.highlight = highlight;
    }

    /// Get the address set for this navigator.
    pub fn addresses(&self) -> &AddressSet {
        &self.addresses
    }

    /// Update the address set.
    pub fn set_addresses(&mut self, addresses: AddressSet) {
        self.addresses = addresses;
    }

    /// Navigate to a specific address.
    ///
    /// Returns true if the address is within the navigator's address set.
    pub fn go_to(&mut self, address: u64) -> bool {
        if !self.addresses.contains(address) {
            return false;
        }
        self.location = Some(address);
        true
    }

    /// Check if this navigator is disposed.
    pub fn is_disposed(&self) -> bool {
        self.disposed
    }

    /// Dispose of this navigator.
    pub fn dispose(&mut self) {
        self.disposed = true;
        self.location = None;
        self.selection = None;
        self.highlight = None;
    }

    /// Check if this navigator is visible.
    pub fn is_visible(&self) -> bool {
        self.visible && !self.disposed
    }

    /// Set the visibility.
    pub fn set_visible(&mut self, visible: bool) {
        self.visible = visible;
    }

    /// Check if this navigator supports markers.
    pub fn supports_markers(&self) -> bool {
        self.supports_markers
    }

    /// Set whether this navigator supports markers.
    pub fn set_supports_markers(&mut self, supports: bool) {
        self.supports_markers = supports;
    }

    /// Check if this navigator supports highlight.
    pub fn supports_highlight(&self) -> bool {
        true
    }
}

/// State tracking for a GoTo service in a comparison view.
///
/// Manages a pair of GoTo services (one per listing side) and coordinates
/// navigation between them.
pub struct ComparisonGoToManager {
    /// The GoTo service for the left listing.
    left_service: ListingGoToService,
    /// The GoTo service for the right listing.
    right_service: ListingGoToService,
    /// The navigator for the left listing.
    left_navigator: ListingNavigator,
    /// The navigator for the right listing.
    right_navigator: ListingNavigator,
}

impl ComparisonGoToManager {
    /// Create a new comparison GoTo manager.
    pub fn new(
        left_addresses: AddressSet,
        right_addresses: AddressSet,
    ) -> Self {
        let left_nav = ListingNavigator::new(
            "left_listing",
            NavigatableKind::ListingComparison,
            left_addresses.clone(),
        );
        let right_nav = ListingNavigator::new(
            "right_listing",
            NavigatableKind::ListingComparison,
            right_addresses.clone(),
        );

        Self {
            left_service: ListingGoToService::new(left_addresses, "left"),
            right_service: ListingGoToService::new(right_addresses, "right"),
            left_navigator: left_nav,
            right_navigator: right_nav,
        }
    }

    /// Get the left GoTo service.
    pub fn left_service(&self) -> &ListingGoToService {
        &self.left_service
    }

    /// Get the right GoTo service.
    pub fn right_service(&self) -> &ListingGoToService {
        &self.right_service
    }

    /// Get the left navigator.
    pub fn left_navigator(&self) -> &ListingNavigator {
        &self.left_navigator
    }

    /// Get a mutable reference to the left navigator.
    pub fn left_navigator_mut(&mut self) -> &mut ListingNavigator {
        &mut self.left_navigator
    }

    /// Get the right navigator.
    pub fn right_navigator(&self) -> &ListingNavigator {
        &self.right_navigator
    }

    /// Get a mutable reference to the right navigator.
    pub fn right_navigator_mut(&mut self) -> &mut ListingNavigator {
        &mut self.right_navigator
    }

    /// Navigate on the left listing.
    pub fn go_to_left(&mut self, address: u64) -> GoToResult {
        let result = self.left_service.go_to_address(address);
        if result.is_success() {
            self.left_navigator.set_location(Some(address));
        }
        result
    }

    /// Navigate on the right listing.
    pub fn go_to_right(&mut self, address: u64) -> GoToResult {
        let result = self.right_service.go_to_address(address);
        if result.is_success() {
            self.right_navigator.set_location(Some(address));
        }
        result
    }

    /// Update the address sets for both listings.
    pub fn update_addresses(&mut self, left: AddressSet, right: AddressSet) {
        self.left_service.set_addresses(left.clone());
        self.right_service.set_addresses(right.clone());
        self.left_navigator.set_addresses(left);
        self.right_navigator.set_addresses(right);
    }

    /// Dispose of both navigators.
    pub fn dispose(&mut self) {
        self.left_navigator.dispose();
        self.right_navigator.dispose();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codecompare::panel::AddressSet;

    // --- NavigationTarget tests ---

    #[test]
    fn test_navigation_target_address() {
        let target = NavigationTarget::Address(0x1000);
        assert_eq!(target.address(), 0x1000);
        assert!(target.label().is_none());
    }

    #[test]
    fn test_navigation_target_labeled() {
        let target = NavigationTarget::LabeledAddress {
            address: 0x2000,
            label: "main".to_string(),
        };
        assert_eq!(target.address(), 0x2000);
        assert_eq!(target.label(), Some("main"));
    }

    #[test]
    fn test_navigation_target_function_entry() {
        let target = NavigationTarget::FunctionEntry {
            name: "init".to_string(),
            address: 0x3000,
        };
        assert_eq!(target.address(), 0x3000);
        assert_eq!(target.label(), Some("init"));
    }

    // --- GoToResult tests ---

    #[test]
    fn test_goto_result_success() {
        let result = GoToResult::Success { address: 0x1000 };
        assert!(result.is_success());
        assert_eq!(result.address(), Some(0x1000));
    }

    #[test]
    fn test_goto_result_out_of_range() {
        let result = GoToResult::AddressOutOfRange { requested: 0x5000 };
        assert!(!result.is_success());
        assert!(result.address().is_none());
    }

    #[test]
    fn test_goto_result_invalid_target() {
        let result = GoToResult::InvalidTarget;
        assert!(!result.is_success());
    }

    #[test]
    fn test_goto_result_not_supported() {
        let result = GoToResult::NotSupported {
            reason: "test".to_string(),
        };
        assert!(!result.is_success());
    }

    // --- ListingGoToService tests ---

    #[test]
    fn test_goto_service_new() {
        let addresses = AddressSet::single(0x1000, 0x2000);
        let service = ListingGoToService::new(addresses, "left");
        assert_eq!(service.listing_id(), "left");
        assert!(service.current_address().is_none());
        assert!(service.last_status().is_none());
    }

    #[test]
    fn test_goto_service_valid_address() {
        let addresses = AddressSet::single(0x1000, 0x2000);
        let service = ListingGoToService::new(addresses, "left");
        let result = service.go_to_address(0x1500);
        assert!(result.is_success());
        assert_eq!(result.address(), Some(0x1500));
    }

    #[test]
    fn test_goto_service_out_of_range() {
        let addresses = AddressSet::single(0x1000, 0x2000);
        let service = ListingGoToService::new(addresses, "left");
        let result = service.go_to_address(0x5000);
        assert!(!result.is_success());
    }

    #[test]
    fn test_goto_service_validate() {
        let addresses = AddressSet::single(0x1000, 0x2000);
        let service = ListingGoToService::new(addresses, "left");
        assert!(service.validate_address(0x1500));
        assert!(!service.validate_address(0x5000));
    }

    #[test]
    fn test_goto_service_go_to_target() {
        let addresses = AddressSet::single(0x1000, 0x2000);
        let service = ListingGoToService::new(addresses, "left");

        let target = NavigationTarget::FunctionEntry {
            name: "main".to_string(),
            address: 0x1500,
        };
        let result = service.go_to_target(&target);
        assert!(result.is_success());
    }

    #[test]
    fn test_goto_service_external() {
        let addresses = AddressSet::single(0x1000, 0x2000);
        let service = ListingGoToService::new(addresses, "left");
        let result = service.go_to_external();
        assert!(!result.is_success());
    }

    // --- ListingNavigator tests ---

    #[test]
    fn test_navigator_new() {
        let addresses = AddressSet::single(0x1000, 0x2000);
        let nav = ListingNavigator::new("nav1", NavigatableKind::ListingComparison, addresses);
        assert_eq!(nav.id(), "nav1");
        assert_eq!(nav.kind(), NavigatableKind::ListingComparison);
        assert!(nav.location().is_none());
        assert!(!nav.is_disposed());
        assert!(nav.is_visible());
    }

    #[test]
    fn test_navigator_go_to() {
        let addresses = AddressSet::single(0x1000, 0x2000);
        let mut nav = ListingNavigator::new("nav1", NavigatableKind::ListingComparison, addresses);

        assert!(nav.go_to(0x1500));
        assert_eq!(nav.location(), Some(0x1500));
    }

    #[test]
    fn test_navigator_go_to_out_of_range() {
        let addresses = AddressSet::single(0x1000, 0x2000);
        let mut nav = ListingNavigator::new("nav1", NavigatableKind::ListingComparison, addresses);

        assert!(!nav.go_to(0x5000));
        assert!(nav.location().is_none());
    }

    #[test]
    fn test_navigator_selection() {
        let addresses = AddressSet::single(0x1000, 0x2000);
        let mut nav = ListingNavigator::new("nav1", NavigatableKind::ListingComparison, addresses);

        assert!(nav.get_selection().is_none());
        nav.set_selection(Some((0x1000, 0x1500)));
        assert_eq!(nav.get_selection(), Some((0x1000, 0x1500)));
    }

    #[test]
    fn test_navigator_highlight() {
        let addresses = AddressSet::single(0x1000, 0x2000);
        let mut nav = ListingNavigator::new("nav1", NavigatableKind::ListingComparison, addresses);

        assert!(nav.get_highlight().is_none());
        nav.set_highlight(Some((0x1000, 0x1100)));
        assert_eq!(nav.get_highlight(), Some((0x1000, 0x1100)));
    }

    #[test]
    fn test_navigator_dispose() {
        let addresses = AddressSet::single(0x1000, 0x2000);
        let mut nav = ListingNavigator::new("nav1", NavigatableKind::ListingComparison, addresses);

        nav.go_to(0x1500);
        nav.set_selection(Some((0x1000, 0x1500)));
        nav.dispose();

        assert!(nav.is_disposed());
        assert!(!nav.is_visible());
        assert!(nav.location().is_none());
        assert!(nav.get_selection().is_none());
    }

    #[test]
    fn test_navigator_visibility() {
        let addresses = AddressSet::single(0x1000, 0x2000);
        let mut nav = ListingNavigator::new("nav1", NavigatableKind::ListingComparison, addresses);

        assert!(nav.is_visible());
        nav.set_visible(false);
        assert!(!nav.is_visible());
        nav.set_visible(true);
        assert!(nav.is_visible());
    }

    #[test]
    fn test_navigator_markers() {
        let addresses = AddressSet::single(0x1000, 0x2000);
        let mut nav = ListingNavigator::new("nav1", NavigatableKind::ListingComparison, addresses);

        assert!(!nav.supports_markers());
        nav.set_supports_markers(true);
        assert!(nav.supports_markers());
    }

    #[test]
    fn test_navigator_highlight_support() {
        let addresses = AddressSet::single(0x1000, 0x2000);
        let nav = ListingNavigator::new("nav1", NavigatableKind::ListingComparison, addresses);
        assert!(nav.supports_highlight());
    }

    // --- ComparisonGoToManager tests ---

    #[test]
    fn test_goto_manager_new() {
        let left = AddressSet::single(0x1000, 0x2000);
        let right = AddressSet::single(0x3000, 0x4000);
        let manager = ComparisonGoToManager::new(left, right);

        assert_eq!(manager.left_service().listing_id(), "left");
        assert_eq!(manager.right_service().listing_id(), "right");
    }

    #[test]
    fn test_goto_manager_go_to_left() {
        let left = AddressSet::single(0x1000, 0x2000);
        let right = AddressSet::single(0x3000, 0x4000);
        let mut manager = ComparisonGoToManager::new(left, right);

        let result = manager.go_to_left(0x1500);
        assert!(result.is_success());
        assert_eq!(manager.left_navigator().location(), Some(0x1500));
    }

    #[test]
    fn test_goto_manager_go_to_right() {
        let left = AddressSet::single(0x1000, 0x2000);
        let right = AddressSet::single(0x3000, 0x4000);
        let mut manager = ComparisonGoToManager::new(left, right);

        let result = manager.go_to_right(0x3500);
        assert!(result.is_success());
        assert_eq!(manager.right_navigator().location(), Some(0x3500));
    }

    #[test]
    fn test_goto_manager_out_of_range() {
        let left = AddressSet::single(0x1000, 0x2000);
        let right = AddressSet::single(0x3000, 0x4000);
        let mut manager = ComparisonGoToManager::new(left, right);

        let result = manager.go_to_left(0x5000);
        assert!(!result.is_success());
        assert!(manager.left_navigator().location().is_none());
    }

    #[test]
    fn test_goto_manager_update_addresses() {
        let left = AddressSet::single(0x1000, 0x2000);
        let right = AddressSet::single(0x3000, 0x4000);
        let mut manager = ComparisonGoToManager::new(left, right);

        let new_left = AddressSet::single(0x5000, 0x6000);
        let new_right = AddressSet::single(0x7000, 0x8000);
        manager.update_addresses(new_left, new_right);

        assert!(manager.left_service().validate_address(0x5500));
        assert!(!manager.left_service().validate_address(0x1500));
    }

    #[test]
    fn test_goto_manager_dispose() {
        let left = AddressSet::single(0x1000, 0x2000);
        let right = AddressSet::single(0x3000, 0x4000);
        let mut manager = ComparisonGoToManager::new(left, right);

        manager.go_to_left(0x1500);
        manager.dispose();

        assert!(manager.left_navigator().is_disposed());
        assert!(manager.right_navigator().is_disposed());
    }

    // --- NavigatableKind tests ---

    #[test]
    fn test_navigatable_kind() {
        assert_eq!(NavigatableKind::ListingComparison, NavigatableKind::ListingComparison);
        assert_ne!(NavigatableKind::ListingComparison, NavigatableKind::DecompilerComparison);
    }
}
