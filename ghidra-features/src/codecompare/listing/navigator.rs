//! Navigator for listing code comparison displays.
//!
//! Ported from Ghidra's `ListingDisplayNavigator` Java class in
//! `ghidra.features.base.codecompare.listing`.
//!
//! In Ghidra, a `Navigatable` is an object that can be the target of
//! GoTo operations and can have selections and highlights. The listing
//! code comparison view creates a navigator for each side (left and right)
//! so that GoTo operations are directed to the correct listing panel.
//!
//! In this Rust port, we capture the logical state and navigation behavior
//! without the Swing/docking framework dependency.
//!
//! # Key types
//!
//! - [`NavigatorState`] -- the state of a listing display navigator
//! - [`NavigationResult`] -- the result of a navigation operation
//! - [`SelectionInfo`] -- information about a program selection

use super::super::panel::{AddressSet, ProgramInfo};
use crate::codecompare::model::ComparisonSide;

/// Information about a program selection.
///
/// In Ghidra, a `ProgramSelection` is a set of addresses that the user
/// has selected in the listing. Here we capture the essential state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectionInfo {
    /// The selected address ranges.
    pub addresses: AddressSet,
    /// Whether the selection is empty.
    pub is_empty: bool,
}

impl SelectionInfo {
    /// Create a new empty selection.
    pub fn empty() -> Self {
        Self {
            addresses: AddressSet::new(),
            is_empty: true,
        }
    }

    /// Create a new selection from an address set.
    pub fn new(addresses: AddressSet) -> Self {
        let is_empty = addresses.is_empty();
        Self { addresses, is_empty }
    }

    /// Get the number of selected address ranges.
    pub fn range_count(&self) -> usize {
        self.addresses.range_count()
    }

    /// Get the total number of selected addresses.
    pub fn total_size(&self) -> u64 {
        self.addresses.total_size()
    }
}

impl Default for SelectionInfo {
    fn default() -> Self {
        Self::empty()
    }
}

/// The result of a navigation operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NavigationResult {
    /// Navigation was successful; the listing moved to the given address.
    Success { address: u64 },
    /// Navigation failed because the target address is outside the listing's
    /// current address range.
    OutOfRange { address: u64 },
    /// Navigation failed because the listing has no program loaded.
    NoProgram,
    /// Navigation failed because the target program does not match the
    /// listing's program.
    ProgramMismatch {
        /// The expected program ID.
        expected: u64,
        /// The actual program ID provided.
        actual: u64,
    },
    /// Navigation was rejected (e.g., the navigator is disposed).
    Rejected,
}

impl NavigationResult {
    /// Check if the navigation was successful.
    pub fn is_success(&self) -> bool {
        matches!(self, Self::Success { .. })
    }

    /// Get the target address, if available.
    pub fn address(&self) -> Option<u64> {
        match self {
            Self::Success { address } => Some(*address),
            Self::OutOfRange { address } => Some(*address),
            _ => None,
        }
    }
}

/// The state of a listing display navigator.
///
/// Ported from Ghidra's `ListingDisplayNavigator` Java class.
///
/// Each side of a dual listing comparison has its own navigator. The
/// navigator tracks the current location, selection, and highlight
/// state, and validates that navigation targets are within the listing's
/// current address range.
///
/// # Example
///
/// ```rust
/// use ghidra_features::codecompare::listing::navigator::*;
/// use ghidra_features::codecompare::panel::*;
/// use ghidra_features::codecompare::model::ComparisonSide;
///
/// let prog = ProgramInfo::new(1, "/project/test", "test");
/// let addresses = AddressSet::single(0x1000, 0x2000);
/// let mut nav = NavigatorState::new(ComparisonSide::Left, prog, addresses);
///
/// let result = nav.go_to(0x1500);
/// assert!(result.is_success());
/// assert_eq!(nav.current_address(), Some(0x1500));
///
/// let result = nav.go_to(0x5000);
/// assert!(!result.is_success());
/// ```
#[derive(Debug, Clone)]
pub struct NavigatorState {
    /// Which side this navigator controls.
    side: ComparisonSide,
    /// The program being displayed.
    program: Option<ProgramInfo>,
    /// The address range currently loaded in the listing.
    loaded_addresses: AddressSet,
    /// The current cursor address.
    current_address: Option<u64>,
    /// The current selection.
    selection: SelectionInfo,
    /// The current highlight.
    highlight: SelectionInfo,
    /// A unique identifier for this navigator instance.
    instance_id: u64,
    /// Whether this navigator has been disposed.
    disposed: bool,
}

impl NavigatorState {
    /// Create a new navigator state.
    pub fn new(
        side: ComparisonSide,
        program: ProgramInfo,
        loaded_addresses: AddressSet,
    ) -> Self {
        Self {
            side,
            program: Some(program),
            loaded_addresses,
            current_address: None,
            selection: SelectionInfo::empty(),
            highlight: SelectionInfo::empty(),
            instance_id: next_navigator_id(),
            disposed: false,
        }
    }

    /// Create a navigator without a program (empty state).
    pub fn empty(side: ComparisonSide) -> Self {
        Self {
            side,
            program: None,
            loaded_addresses: AddressSet::new(),
            current_address: None,
            selection: SelectionInfo::empty(),
            highlight: SelectionInfo::empty(),
            instance_id: next_navigator_id(),
            disposed: false,
        }
    }

    /// Get the side this navigator controls.
    pub fn side(&self) -> ComparisonSide {
        self.side
    }

    /// Get the unique instance ID.
    pub fn instance_id(&self) -> u64 {
        self.instance_id
    }

    /// Check if this navigator has a program loaded.
    pub fn has_program(&self) -> bool {
        self.program.is_some() && !self.disposed
    }

    /// Get the program info, if available.
    pub fn program(&self) -> Option<&ProgramInfo> {
        self.program.as_ref()
    }

    /// Get the loaded address range.
    pub fn loaded_addresses(&self) -> &AddressSet {
        &self.loaded_addresses
    }

    /// Set the program and loaded addresses.
    pub fn set_program_view(
        &mut self,
        program: ProgramInfo,
        addresses: AddressSet,
    ) {
        self.program = Some(program);
        self.loaded_addresses = addresses;
        self.current_address = None;
        self.selection = SelectionInfo::empty();
        self.highlight = SelectionInfo::empty();
    }

    /// Navigate to the given address.
    ///
    /// Returns a `NavigationResult` indicating success or failure.
    pub fn go_to(&mut self, address: u64) -> NavigationResult {
        if self.disposed {
            return NavigationResult::Rejected;
        }

        if self.program.is_none() {
            return NavigationResult::NoProgram;
        }

        if !self.loaded_addresses.is_empty() && !self.loaded_addresses.contains(address) {
            return NavigationResult::OutOfRange { address };
        }

        self.current_address = Some(address);
        NavigationResult::Success { address }
    }

    /// Navigate to a program location (address + optional program check).
    pub fn go_to_location(
        &mut self,
        program_id: u64,
        address: u64,
    ) -> NavigationResult {
        if self.disposed {
            return NavigationResult::Rejected;
        }

        if let Some(ref prog) = self.program {
            if prog.id != program_id {
                return NavigationResult::ProgramMismatch {
                    expected: prog.id,
                    actual: program_id,
                };
            }
        } else {
            return NavigationResult::NoProgram;
        }

        self.go_to(address)
    }

    /// Get the current cursor address.
    pub fn current_address(&self) -> Option<u64> {
        self.current_address
    }

    /// Get the current selection.
    pub fn selection(&self) -> &SelectionInfo {
        &self.selection
    }

    /// Set the current selection.
    pub fn set_selection(&mut self, selection: SelectionInfo) {
        self.selection = selection;
    }

    /// Get the current highlight.
    pub fn highlight(&self) -> &SelectionInfo {
        &self.highlight
    }

    /// Set the current highlight.
    pub fn set_highlight(&mut self, highlight: SelectionInfo) {
        self.highlight = highlight;
    }

    /// Clear the selection.
    pub fn clear_selection(&mut self) {
        self.selection = SelectionInfo::empty();
    }

    /// Clear the highlight.
    pub fn clear_highlight(&mut self) {
        self.highlight = SelectionInfo::empty();
    }

    /// Check if the navigator supports markers.
    ///
    /// In the listing comparison view, markers are supported.
    pub fn supports_markers(&self) -> bool {
        true
    }

    /// Check if the navigator supports highlighting.
    pub fn supports_highlight(&self) -> bool {
        true
    }

    /// Check if the navigator is connected (always false for comparison views).
    ///
    /// In Ghidra, "connected" means the navigator is linked to the main
    /// listing. Comparison view navigators are never connected.
    pub fn is_connected(&self) -> bool {
        false
    }

    /// Check if this navigator is visible.
    pub fn is_visible(&self) -> bool {
        !self.disposed
    }

    /// Check if this navigator has been disposed.
    pub fn is_disposed(&self) -> bool {
        self.disposed
    }

    /// Validate that an address is within the loaded address range.
    pub fn validate_address(&self, address: u64) -> bool {
        self.loaded_addresses.is_empty() || self.loaded_addresses.contains(address)
    }

    /// Dispose of this navigator.
    pub fn dispose(&mut self) {
        self.disposed = true;
        self.program = None;
        self.loaded_addresses = AddressSet::new();
        self.current_address = None;
        self.selection = SelectionInfo::empty();
        self.highlight = SelectionInfo::empty();
    }
}

/// Global navigator ID counter.
static NAVIGATOR_ID_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

fn next_navigator_id() -> u64 {
    NAVIGATOR_ID_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

/// A pair of navigators for left and right sides of a comparison.
#[derive(Debug)]
pub struct NavigatorPair {
    /// The left-side navigator.
    pub left: NavigatorState,
    /// The right-side navigator.
    pub right: NavigatorState,
}

impl NavigatorPair {
    /// Create a new navigator pair.
    pub fn new(
        left_program: ProgramInfo,
        left_addresses: AddressSet,
        right_program: ProgramInfo,
        right_addresses: AddressSet,
    ) -> Self {
        Self {
            left: NavigatorState::new(ComparisonSide::Left, left_program, left_addresses),
            right: NavigatorState::new(ComparisonSide::Right, right_program, right_addresses),
        }
    }

    /// Create an empty navigator pair.
    pub fn empty() -> Self {
        Self {
            left: NavigatorState::empty(ComparisonSide::Left),
            right: NavigatorState::empty(ComparisonSide::Right),
        }
    }

    /// Get the navigator for the given side.
    pub fn get(&self, side: ComparisonSide) -> &NavigatorState {
        match side {
            ComparisonSide::Left => &self.left,
            ComparisonSide::Right => &self.right,
        }
    }

    /// Get a mutable reference to the navigator for the given side.
    pub fn get_mut(&mut self, side: ComparisonSide) -> &mut NavigatorState {
        match side {
            ComparisonSide::Left => &mut self.left,
            ComparisonSide::Right => &mut self.right,
        }
    }

    /// Dispose of both navigators.
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

    // --- SelectionInfo tests ---

    #[test]
    fn test_selection_info_empty() {
        let sel = SelectionInfo::empty();
        assert!(sel.is_empty);
        assert_eq!(sel.range_count(), 0);
        assert_eq!(sel.total_size(), 0);
    }

    #[test]
    fn test_selection_info_with_addresses() {
        let mut addrs = AddressSet::new();
        addrs.add(0x1000, 0x100f);
        addrs.add(0x2000, 0x200f);
        let sel = SelectionInfo::new(addrs);
        assert!(!sel.is_empty);
        assert_eq!(sel.range_count(), 2);
        assert_eq!(sel.total_size(), 0x20);
    }

    #[test]
    fn test_selection_info_default() {
        let sel = SelectionInfo::default();
        assert!(sel.is_empty);
    }

    // --- NavigationResult tests ---

    #[test]
    fn test_navigation_result_success() {
        let result = NavigationResult::Success { address: 0x1000 };
        assert!(result.is_success());
        assert_eq!(result.address(), Some(0x1000));
    }

    #[test]
    fn test_navigation_result_out_of_range() {
        let result = NavigationResult::OutOfRange { address: 0x5000 };
        assert!(!result.is_success());
        assert_eq!(result.address(), Some(0x5000));
    }

    #[test]
    fn test_navigation_result_no_program() {
        let result = NavigationResult::NoProgram;
        assert!(!result.is_success());
        assert_eq!(result.address(), None);
    }

    #[test]
    fn test_navigation_result_program_mismatch() {
        let result = NavigationResult::ProgramMismatch {
            expected: 1,
            actual: 2,
        };
        assert!(!result.is_success());
        assert_eq!(result.address(), None);
    }

    #[test]
    fn test_navigation_result_rejected() {
        let result = NavigationResult::Rejected;
        assert!(!result.is_success());
        assert_eq!(result.address(), None);
    }

    // --- NavigatorState tests ---

    #[test]
    fn test_navigator_new() {
        let prog = make_program(1, "/project/test", "test");
        let addrs = AddressSet::single(0x1000, 0x2000);
        let nav = NavigatorState::new(ComparisonSide::Left, prog, addrs);

        assert_eq!(nav.side(), ComparisonSide::Left);
        assert!(nav.has_program());
        assert!(nav.program().is_some());
        assert_eq!(nav.current_address(), None);
        assert!(!nav.is_disposed());
    }

    #[test]
    fn test_navigator_empty() {
        let nav = NavigatorState::empty(ComparisonSide::Right);
        assert_eq!(nav.side(), ComparisonSide::Right);
        assert!(!nav.has_program());
        assert!(nav.program().is_none());
    }

    #[test]
    fn test_navigator_go_to_success() {
        let prog = make_program(1, "/project/test", "test");
        let addrs = AddressSet::single(0x1000, 0x2000);
        let mut nav = NavigatorState::new(ComparisonSide::Left, prog, addrs);

        let result = nav.go_to(0x1500);
        assert!(result.is_success());
        assert_eq!(nav.current_address(), Some(0x1500));
    }

    #[test]
    fn test_navigator_go_to_out_of_range() {
        let prog = make_program(1, "/project/test", "test");
        let addrs = AddressSet::single(0x1000, 0x2000);
        let mut nav = NavigatorState::new(ComparisonSide::Left, prog, addrs);

        let result = nav.go_to(0x5000);
        assert!(!result.is_success());
        assert_eq!(nav.current_address(), None);
    }

    #[test]
    fn test_navigator_go_to_no_program() {
        let mut nav = NavigatorState::empty(ComparisonSide::Left);
        let result = nav.go_to(0x1000);
        assert!(!result.is_success());
    }

    #[test]
    fn test_navigator_go_to_boundary() {
        let prog = make_program(1, "/project/test", "test");
        let addrs = AddressSet::single(0x1000, 0x2000);
        let mut nav = NavigatorState::new(ComparisonSide::Left, prog, addrs);

        // At start boundary
        let result = nav.go_to(0x1000);
        assert!(result.is_success());

        // At end boundary
        let result = nav.go_to(0x2000);
        assert!(result.is_success());

        // Just outside
        let result = nav.go_to(0x2001);
        assert!(!result.is_success());
    }

    #[test]
    fn test_navigator_go_to_location() {
        let prog = make_program(1, "/project/test", "test");
        let addrs = AddressSet::single(0x1000, 0x2000);
        let mut nav = NavigatorState::new(ComparisonSide::Left, prog, addrs);

        // Correct program
        let result = nav.go_to_location(1, 0x1500);
        assert!(result.is_success());

        // Wrong program
        let result = nav.go_to_location(2, 0x1500);
        assert!(!result.is_success());
    }

    #[test]
    fn test_navigator_go_to_location_no_program() {
        let mut nav = NavigatorState::empty(ComparisonSide::Left);
        let result = nav.go_to_location(1, 0x1000);
        assert!(!result.is_success());
    }

    #[test]
    fn test_navigator_selection() {
        let prog = make_program(1, "/project/test", "test");
        let addrs = AddressSet::single(0x1000, 0x2000);
        let mut nav = NavigatorState::new(ComparisonSide::Left, prog, addrs);

        assert!(nav.selection().is_empty);

        let mut sel_addrs = AddressSet::new();
        sel_addrs.add(0x1000, 0x100f);
        nav.set_selection(SelectionInfo::new(sel_addrs));
        assert!(!nav.selection().is_empty);
        assert_eq!(nav.selection().range_count(), 1);

        nav.clear_selection();
        assert!(nav.selection().is_empty);
    }

    #[test]
    fn test_navigator_highlight() {
        let prog = make_program(1, "/project/test", "test");
        let addrs = AddressSet::single(0x1000, 0x2000);
        let mut nav = NavigatorState::new(ComparisonSide::Left, prog, addrs);

        assert!(nav.highlight().is_empty);

        let mut hl_addrs = AddressSet::new();
        hl_addrs.add(0x1500, 0x150f);
        nav.set_highlight(SelectionInfo::new(hl_addrs));
        assert!(!nav.highlight().is_empty);

        nav.clear_highlight();
        assert!(nav.highlight().is_empty);
    }

    #[test]
    fn test_navigator_set_program_view() {
        let prog1 = make_program(1, "/old", "old");
        let addrs1 = AddressSet::single(0x1000, 0x2000);
        let mut nav = NavigatorState::new(ComparisonSide::Left, prog1, addrs1);
        assert!(nav.go_to(0x1500).is_success());

        let prog2 = make_program(2, "/new", "new");
        let addrs2 = AddressSet::single(0x3000, 0x4000);
        nav.set_program_view(prog2, addrs2);

        assert_eq!(nav.program().unwrap().id, 2);
        assert_eq!(nav.current_address(), None);
        assert!(nav.selection().is_empty);
    }

    #[test]
    fn test_navigator_dispose() {
        let prog = make_program(1, "/project/test", "test");
        let addrs = AddressSet::single(0x1000, 0x2000);
        let mut nav = NavigatorState::new(ComparisonSide::Left, prog, addrs);
        assert!(nav.go_to(0x1500).is_success());

        nav.dispose();
        assert!(nav.is_disposed());
        assert!(!nav.has_program());
        assert!(nav.program().is_none());
        assert_eq!(nav.current_address(), None);
        assert!(!nav.is_visible());
    }

    #[test]
    fn test_navigator_disposed_rejects_navigation() {
        let prog = make_program(1, "/project/test", "test");
        let addrs = AddressSet::single(0x1000, 0x2000);
        let mut nav = NavigatorState::new(ComparisonSide::Left, prog, addrs);
        nav.dispose();

        let result = nav.go_to(0x1500);
        assert!(!result.is_success());
    }

    #[test]
    fn test_navigator_properties() {
        let prog = make_program(1, "/project/test", "test");
        let addrs = AddressSet::single(0x1000, 0x2000);
        let nav = NavigatorState::new(ComparisonSide::Left, prog, addrs);

        assert!(nav.supports_markers());
        assert!(nav.supports_highlight());
        assert!(!nav.is_connected());
        assert!(nav.is_visible());
    }

    #[test]
    fn test_navigator_validate_address() {
        let prog = make_program(1, "/project/test", "test");
        let addrs = AddressSet::single(0x1000, 0x2000);
        let nav = NavigatorState::new(ComparisonSide::Left, prog, addrs);

        assert!(nav.validate_address(0x1000));
        assert!(nav.validate_address(0x1500));
        assert!(nav.validate_address(0x2000));
        assert!(!nav.validate_address(0x2001));
        assert!(!nav.validate_address(0x0fff));
    }

    #[test]
    fn test_navigator_validate_address_empty() {
        let prog = make_program(1, "/project/test", "test");
        let nav = NavigatorState::new(
            ComparisonSide::Left,
            prog,
            AddressSet::new(),
        );

        // Empty address set means all addresses are valid
        assert!(nav.validate_address(0x1000));
        assert!(nav.validate_address(0x5000));
    }

    #[test]
    fn test_navigator_instance_id_unique() {
        let nav1 = NavigatorState::empty(ComparisonSide::Left);
        let nav2 = NavigatorState::empty(ComparisonSide::Right);
        assert_ne!(nav1.instance_id(), nav2.instance_id());
    }

    // --- NavigatorPair tests ---

    #[test]
    fn test_navigator_pair_new() {
        let prog1 = make_program(1, "/left", "left_prog");
        let prog2 = make_program(2, "/right", "right_prog");
        let addrs1 = AddressSet::single(0x1000, 0x2000);
        let addrs2 = AddressSet::single(0x3000, 0x4000);

        let pair = NavigatorPair::new(prog1, addrs1, prog2, addrs2);
        assert!(pair.left.has_program());
        assert!(pair.right.has_program());
        assert_eq!(pair.left.program().unwrap().id, 1);
        assert_eq!(pair.right.program().unwrap().id, 2);
    }

    #[test]
    fn test_navigator_pair_empty() {
        let pair = NavigatorPair::empty();
        assert!(!pair.left.has_program());
        assert!(!pair.right.has_program());
    }

    #[test]
    fn test_navigator_pair_get() {
        let pair = NavigatorPair::empty();
        assert_eq!(pair.get(ComparisonSide::Left).side(), ComparisonSide::Left);
        assert_eq!(
            pair.get(ComparisonSide::Right).side(),
            ComparisonSide::Right
        );
    }

    #[test]
    fn test_navigator_pair_get_mut() {
        let prog = make_program(1, "/test", "test");
        let addrs = AddressSet::single(0x1000, 0x2000);
        let mut pair = NavigatorPair::new(
            prog.clone(),
            addrs.clone(),
            prog,
            addrs,
        );

        assert!(pair.get_mut(ComparisonSide::Left).go_to(0x1500).is_success());
        assert_eq!(
            pair.get(ComparisonSide::Left).current_address(),
            Some(0x1500)
        );
    }

    #[test]
    fn test_navigator_pair_dispose() {
        let prog = make_program(1, "/test", "test");
        let addrs = AddressSet::single(0x1000, 0x2000);
        let mut pair = NavigatorPair::new(
            prog.clone(),
            addrs.clone(),
            prog,
            addrs,
        );

        pair.dispose();
        assert!(pair.left.is_disposed());
        assert!(pair.right.is_disposed());
    }
}
