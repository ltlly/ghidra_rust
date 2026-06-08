//! Bookmark navigation action -- ported from
//! `ghidra.app.plugin.core.navigation.NextPreviousBookmarkAction`.
//!
//! Provides next/previous bookmark navigation with support for:
//! - Bookmark type filtering (all, analysis, error, info, note, warning, custom)
//! - Inverted (non-bookmark) navigation
//! - Multi-state bookmark type selection
//! - Direction toggling via shift-click
//!
//! Swing UI and toolbar icon code is omitted; only the model and
//! business logic are ported.

use ghidra_core::Address;

use super::next_prev_plugins::NavigationDirection;

// ---------------------------------------------------------------------------
// BookmarkType
// ---------------------------------------------------------------------------

/// Known Ghidra bookmark types.
///
/// Ported from `ghidra.program.model.listing.BookmarkType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BookmarkType {
    /// Analysis bookmarks.
    Analysis,
    /// Error bookmarks.
    Error,
    /// Informational bookmarks.
    Info,
    /// Note bookmarks.
    Note,
    /// Warning bookmarks.
    Warning,
    /// Custom (user-defined) bookmarks.
    Custom,
}

impl BookmarkType {
    /// The Ghidra string identifier for this bookmark type.
    pub fn type_string(&self) -> &'static str {
        match self {
            Self::Analysis => "Analysis",
            Self::Error => "Error",
            Self::Info => "Info",
            Self::Note => "Note",
            Self::Warning => "Warning",
            Self::Custom => "Custom",
        }
    }

    /// All built-in bookmark types (excluding Custom).
    pub fn built_in_types() -> &'static [BookmarkType] {
        &[
            BookmarkType::Analysis,
            BookmarkType::Error,
            BookmarkType::Info,
            BookmarkType::Note,
            BookmarkType::Warning,
        ]
    }

    /// Whether this is a built-in (non-custom) type.
    pub fn is_built_in(&self) -> bool {
        Self::built_in_types().iter().any(|t| t == self)
    }
}

impl std::fmt::Display for BookmarkType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.type_string())
    }
}

// ---------------------------------------------------------------------------
// Bookmark (model)
// ---------------------------------------------------------------------------

/// A bookmark in a program's listing.
///
/// Ported from `ghidra.program.model.listing.Bookmark`.
#[derive(Debug, Clone)]
pub struct Bookmark {
    /// The address of the bookmark.
    pub address: Address,
    /// The bookmark type string (e.g., "Analysis", "Error").
    pub type_string: String,
    /// Optional category within the type.
    pub category: Option<String>,
    /// The bookmark comment.
    pub comment: Option<String>,
}

impl Bookmark {
    /// Create a new bookmark.
    pub fn new(address: Address, type_string: impl Into<String>) -> Self {
        Self {
            address,
            type_string: type_string.into(),
            category: None,
            comment: None,
        }
    }

    /// The type string identifier.
    pub fn get_type_string(&self) -> &str {
        &self.type_string
    }

    /// Whether this is a built-in bookmark type.
    pub fn is_built_in_type(&self) -> bool {
        matches!(
            self.type_string.as_str(),
            "Analysis" | "Error" | "Info" | "Note" | "Warning"
        )
    }

    /// Whether this bookmark is at an external address.
    pub fn is_external_address(&self) -> bool {
        // External addresses are represented by a special convention.
        // In a full implementation this would check Address::is_external_address().
        false
    }
}

// ---------------------------------------------------------------------------
// BookmarkManager (model)
// ---------------------------------------------------------------------------

/// Manages bookmarks for a program.
///
/// Ported from `ghidra.program.model.listing.BookmarkManager`.
/// This is a simplified model that stores bookmarks in a sorted vector.
#[derive(Debug, Clone)]
pub struct BookmarkManager {
    /// Bookmarks sorted by address.
    bookmarks: Vec<Bookmark>,
}

impl BookmarkManager {
    /// Create a new empty bookmark manager.
    pub fn new() -> Self {
        Self {
            bookmarks: Vec::new(),
        }
    }

    /// Add a bookmark.
    pub fn add_bookmark(&mut self, bookmark: Bookmark) {
        let pos = self
            .bookmarks
            .binary_search_by_key(&bookmark.address, |b| b.address)
            .unwrap_or_else(|e| e);
        self.bookmarks.insert(pos, bookmark);
    }

    /// Get all bookmarks at the given address.
    pub fn get_bookmarks(&self, address: Address) -> Vec<&Bookmark> {
        self.bookmarks
            .iter()
            .filter(|b| b.address == address)
            .collect()
    }

    /// Iterate bookmarks starting from `address` in the given direction.
    ///
    /// If `forward` is true, returns bookmarks at addresses >= `address`.
    /// If `forward` is false, returns bookmarks at addresses <= `address`
    /// in reverse order.
    pub fn get_bookmarks_iterator(
        &self,
        address: Address,
        forward: bool,
    ) -> Box<dyn Iterator<Item = &Bookmark> + '_> {
        if forward {
            let pos = self
                .bookmarks
                .binary_search_by_key(&address, |b| b.address)
                .unwrap_or_else(|e| e);
            Box::new(self.bookmarks[pos..].iter())
        } else {
            // Find the first bookmark with address > given address, then iterate backwards.
            let pos = self
                .bookmarks
                .binary_search_by_key(&address, |b| b.address)
                .map(|p| p + 1)
                .unwrap_or_else(|e| e);
            Box::new(self.bookmarks[..pos].iter().rev())
        }
    }

    /// Count of all bookmarks.
    pub fn count(&self) -> usize {
        self.bookmarks.len()
    }
}

impl Default for BookmarkManager {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Listing (minimal model for bookmark navigation)
// ---------------------------------------------------------------------------

/// Minimal listing model used by bookmark navigation.
///
/// Provides code unit iteration for finding non-bookmark code units.
#[derive(Debug, Clone)]
pub struct ListingModel {
    /// Known code unit addresses (instructions + defined data).
    code_units: Vec<Address>,
}

impl ListingModel {
    /// Create a new listing model.
    pub fn new() -> Self {
        Self {
            code_units: Vec::new(),
        }
    }

    /// Add a code unit address.
    pub fn add_code_unit(&mut self, address: Address) {
        let pos = self
            .code_units
            .binary_search(&address)
            .unwrap_or_else(|e| e);
        if pos >= self.code_units.len() || self.code_units[pos] != address {
            self.code_units.insert(pos, address);
        }
    }

    /// Get code units starting from `address` in the given direction.
    pub fn get_code_units(
        &self,
        address: Address,
        forward: bool,
    ) -> Box<dyn Iterator<Item = Address> + '_> {
        if forward {
            let pos = self
                .code_units
                .binary_search(&address)
                .unwrap_or_else(|e| e);
            Box::new(self.code_units[pos..].iter().copied())
        } else {
            let pos = self
                .code_units
                .binary_search(&address)
                .map(|p| p + 1)
                .unwrap_or_else(|e| e);
            Box::new(self.code_units[..pos].iter().rev().copied())
        }
    }
}

impl Default for ListingModel {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// ProgramBookmarkModel
// ---------------------------------------------------------------------------

/// A minimal program model for bookmark navigation.
///
/// In a full Ghidra implementation, these would be methods on `Program`,
/// `Listing`, and `BookmarkManager`.  This struct bundles them for
/// self-contained bookmark navigation logic.
#[derive(Debug, Clone)]
pub struct ProgramBookmarkModel {
    /// The program name.
    pub name: String,
    /// The bookmark manager.
    pub bookmark_manager: BookmarkManager,
    /// The listing (for code unit iteration).
    pub listing: ListingModel,
}

impl ProgramBookmarkModel {
    /// Create a new program bookmark model.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            bookmark_manager: BookmarkManager::new(),
            listing: ListingModel::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// NextPreviousBookmarkAction
// ---------------------------------------------------------------------------

/// The "all bookmark types" sentinel value used in Ghidra.
pub const ALL_BOOKMARK_TYPES: &str = "All Bookmark Types";

/// Action that navigates to the next/previous bookmark.
///
/// Ported from `ghidra.app.plugin.core.navigation.NextPreviousBookmarkAction`.
///
/// Supports:
/// - Bookmark type filtering (all types, or a specific type)
/// - Inverted navigation (skip to next code unit without a bookmark)
/// - Direction toggling (forward/backward)
/// - Shift-click to invert direction for a single invocation
/// - Multi-state bookmark type selection
#[derive(Debug, Clone)]
pub struct NextPreviousBookmarkAction {
    /// Current navigation direction.
    pub direction: NavigationDirection,
    /// Whether the action is enabled.
    pub enabled: bool,
    /// Whether the action is in inverted (non-bookmark) mode.
    pub is_inverted: bool,
    /// The bookmark type filter.  `None` means all types.
    pub bookmark_type: Option<BookmarkType>,
    /// The owner plugin name.
    pub owner: String,
}

impl NextPreviousBookmarkAction {
    /// Create a new bookmark navigation action.
    pub fn new(owner: impl Into<String>, direction: NavigationDirection) -> Self {
        Self {
            direction,
            enabled: true,
            is_inverted: false,
            bookmark_type: None,
            owner: owner.into(),
        }
    }

    /// The action name.
    pub fn name(&self) -> String {
        let dir = if self.direction.is_forward() {
            "Next"
        } else {
            "Previous"
        };
        let kind = if self.is_inverted {
            "Non-Bookmark"
        } else {
            "Bookmark"
        };
        format!("{} {}", dir, kind)
    }

    /// Set the direction.
    pub fn set_direction(&mut self, direction: NavigationDirection) {
        self.direction = direction;
    }

    /// Set whether the action is inverted.
    pub fn set_inverted(&mut self, inverted: bool) {
        self.is_inverted = inverted;
    }

    /// Set the bookmark type filter.
    pub fn set_bookmark_type(&mut self, bookmark_type: Option<BookmarkType>) {
        self.bookmark_type = bookmark_type;
    }

    /// Get the type string used for filtering.
    fn filter_type_string(&self) -> &str {
        match &self.bookmark_type {
            Some(bt) => bt.type_string(),
            None => ALL_BOOKMARK_TYPES,
        }
    }

    /// Compute the next/previous address to navigate to.
    ///
    /// This is the main entry point.  `shift_inverts` should be true
    /// when the user is holding shift (inverts direction for this call).
    pub fn compute_address(
        &self,
        program: &ProgramBookmarkModel,
        current_address: Address,
        shift_inverts: bool,
    ) -> Option<Address> {
        let forward = if shift_inverts {
            !self.direction.is_forward()
        } else {
            self.direction.is_forward()
        };

        if self.is_inverted {
            if forward {
                self.get_next_non_bookmark_address(program, current_address)
            } else {
                self.get_previous_non_bookmark_address(program, current_address)
            }
        } else if forward {
            self.get_address_of_next_bookmark_after(program, current_address)
        } else {
            self.get_address_of_previous_bookmark_before(program, current_address)
        }
    }

    /// Find the address of the next bookmark after `address`.
    fn get_address_of_next_bookmark_after(
        &self,
        program: &ProgramBookmarkModel,
        address: Address,
    ) -> Option<Address> {
        let start = self.get_next_address_to_begin_searching_forward(program, address);
        self.get_next_previous_bookmark(program, start, true)
            .map(|b| b.address)
    }

    /// Find the address of the previous bookmark before `address`.
    fn get_address_of_previous_bookmark_before(
        &self,
        program: &ProgramBookmarkModel,
        address: Address,
    ) -> Option<Address> {
        let start = self.get_next_address_to_begin_searching_backward(program, address);
        self.get_next_previous_bookmark(program, start, false)
            .map(|b| b.address)
    }

    /// Find the next address to begin searching forward.
    ///
    /// If the current address is within a code unit, start after that
    /// code unit.  Otherwise start at the current address.
    fn get_next_address_to_begin_searching_forward(
        &self,
        program: &ProgramBookmarkModel,
        address: Address,
    ) -> Address {
        // In a full implementation, this would get the max address of the
        // code unit containing `address` and return address.next().
        // For our model, we just use the next address.
        address + 1
    }

    /// Find the next address to begin searching backward.
    fn get_next_address_to_begin_searching_backward(
        &self,
        program: &ProgramBookmarkModel,
        address: Address,
    ) -> Address {
        // In a full implementation, this would get the min address of the
        // code unit containing `address` and return address.previous().
        // For our model, we just use the previous address.
        address - 1
    }

    /// Get the next/previous bookmark matching the type filter.
    fn get_next_previous_bookmark<'a>(
        &self,
        program: &'a ProgramBookmarkModel,
        address: Address,
        forward: bool,
    ) -> Option<&'a Bookmark> {
        let filter = self.filter_type_string();
        let iter = program
            .bookmark_manager
            .get_bookmarks_iterator(address, forward);

        for bookmark in iter {
            if bookmark.is_external_address() {
                continue;
            }

            if filter == ALL_BOOKMARK_TYPES {
                return Some(bookmark);
            } else if filter == "Custom" && !bookmark.is_built_in_type() {
                return Some(bookmark);
            } else if bookmark.get_type_string() == filter {
                return Some(bookmark);
            }
        }

        None
    }

    /// Get the next non-bookmark address (inverted mode).
    ///
    /// When the filter is "all types", this finds the next bookmark first
    /// (to skip over bookmark runs), then finds the next code unit
    /// without a bookmark.
    fn get_next_non_bookmark_address(
        &self,
        program: &ProgramBookmarkModel,
        address: Address,
    ) -> Option<Address> {
        self.get_address_of_next_previous_non_bookmark(program, address, true)
    }

    /// Get the previous non-bookmark address (inverted mode).
    fn get_previous_non_bookmark_address(
        &self,
        program: &ProgramBookmarkModel,
        address: Address,
    ) -> Option<Address> {
        self.get_address_of_next_previous_non_bookmark(program, address, false)
    }

    /// Find the next/previous code unit without a bookmark of the given type.
    ///
    /// For "all types", finds a code unit with no bookmarks at all.
    /// For a specific type, finds a code unit with a bookmark of a
    /// *different* type.
    fn get_address_of_next_previous_non_bookmark(
        &self,
        program: &ProgramBookmarkModel,
        address: Address,
        forward: bool,
    ) -> Option<Address> {
        let filter = self.filter_type_string();
        let start = if forward { address + 1 } else { address - 1 };

        if filter == ALL_BOOKMARK_TYPES {
            // Find the next code unit with no bookmarks at all.
            return self.get_next_previous_code_unit_without_bookmark(program, start, forward);
        }

        // For a specific type, iterate bookmarks and find one of a different type.
        let iter = program
            .bookmark_manager
            .get_bookmarks_iterator(start, forward);
        for bookmark in iter {
            let addr = bookmark.address;
            if bookmark.is_external_address() {
                continue;
            }

            if bookmark.get_type_string() != filter {
                return Some(addr);
            }
        }

        None
    }

    /// Find the next/previous code unit that has no bookmarks at all.
    fn get_next_previous_code_unit_without_bookmark(
        &self,
        program: &ProgramBookmarkModel,
        address: Address,
        forward: bool,
    ) -> Option<Address> {
        let iter = program.listing.get_code_units(address, forward);
        for cu_address in iter {
            let bookmarks = program.bookmark_manager.get_bookmarks(cu_address);
            if bookmarks.is_empty() {
                return Some(cu_address);
            }
        }
        None
    }

    /// The tooltip text for this action.
    pub fn tooltip_text(&self) -> String {
        let mut desc = format!(
            "Go To {} {}",
            if self.direction.is_forward() {
                "Next"
            } else {
                "Previous"
            },
            if self.is_inverted {
                "Non-Bookmark"
            } else {
                "Bookmark"
            }
        );

        let state_name = match &self.bookmark_type {
            Some(bt) => bt.type_string().to_string(),
            None => "All Types".to_string(),
        };
        desc.push_str(": ");
        desc.push_str(&state_name);
        desc.push_str(" (shift-click inverts direction)");
        desc
    }

    /// The keyboard shortcut for this action (Ctrl+Alt+B).
    pub fn key_stroke_description() -> &'static str {
        "Ctrl+Alt+B"
    }
}

impl Default for NextPreviousBookmarkAction {
    fn default() -> Self {
        Self::new("Default", NavigationDirection::Forward)
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(offset: u64) -> Address {
        Address::new(offset)
    }

    fn make_program_with_bookmarks() -> ProgramBookmarkModel {
        let mut program = ProgramBookmarkModel::new("test.exe");

        // Add some code units.
        program.listing.add_code_unit(addr(0x1000));
        program.listing.add_code_unit(addr(0x1004));
        program.listing.add_code_unit(addr(0x1008));
        program.listing.add_code_unit(addr(0x2000));
        program.listing.add_code_unit(addr(0x2004));
        program.listing.add_code_unit(addr(0x3000));
        program.listing.add_code_unit(addr(0x3004));

        // Add bookmarks.
        program.bookmark_manager.add_bookmark(Bookmark::new(
            addr(0x1000),
            BookmarkType::Error.type_string(),
        ));
        program.bookmark_manager.add_bookmark(Bookmark::new(
            addr(0x2000),
            BookmarkType::Warning.type_string(),
        ));
        program.bookmark_manager.add_bookmark(Bookmark::new(
            addr(0x3000),
            BookmarkType::Info.type_string(),
        ));

        program
    }

    #[test]
    fn test_bookmark_type_display() {
        assert_eq!(BookmarkType::Analysis.type_string(), "Analysis");
        assert_eq!(BookmarkType::Error.to_string(), "Error");
    }

    #[test]
    fn test_bookmark_type_is_built_in() {
        assert!(BookmarkType::Analysis.is_built_in());
        assert!(BookmarkType::Error.is_built_in());
        assert!(!BookmarkType::Custom.is_built_in());
    }

    #[test]
    fn test_bookmark_creation() {
        let bm = Bookmark::new(addr(0x1000), "Error");
        assert_eq!(bm.address, addr(0x1000));
        assert_eq!(bm.get_type_string(), "Error");
        assert!(bm.is_built_in_type());
    }

    #[test]
    fn test_bookmark_manager_add_and_get() {
        let mut mgr = BookmarkManager::new();
        mgr.add_bookmark(Bookmark::new(addr(0x1000), "Error"));
        mgr.add_bookmark(Bookmark::new(addr(0x2000), "Warning"));
        mgr.add_bookmark(Bookmark::new(addr(0x1000), "Info"));

        assert_eq!(mgr.count(), 3);
        let at_1000 = mgr.get_bookmarks(addr(0x1000));
        assert_eq!(at_1000.len(), 2);
    }

    #[test]
    fn test_bookmark_manager_iterator_forward() {
        let mut mgr = BookmarkManager::new();
        mgr.add_bookmark(Bookmark::new(addr(0x1000), "Error"));
        mgr.add_bookmark(Bookmark::new(addr(0x2000), "Warning"));
        mgr.add_bookmark(Bookmark::new(addr(0x3000), "Info"));

        let addrs: Vec<Address> = mgr
            .get_bookmarks_iterator(addr(0x1500), true)
            .map(|b| b.address)
            .collect();
        assert_eq!(addrs, vec![addr(0x2000), addr(0x3000)]);
    }

    #[test]
    fn test_bookmark_manager_iterator_backward() {
        let mut mgr = BookmarkManager::new();
        mgr.add_bookmark(Bookmark::new(addr(0x1000), "Error"));
        mgr.add_bookmark(Bookmark::new(addr(0x2000), "Warning"));
        mgr.add_bookmark(Bookmark::new(addr(0x3000), "Info"));

        let addrs: Vec<Address> = mgr
            .get_bookmarks_iterator(addr(0x2500), false)
            .map(|b| b.address)
            .collect();
        assert_eq!(addrs, vec![addr(0x2000), addr(0x1000)]);
    }

    #[test]
    fn test_action_name_forward() {
        let action = NextPreviousBookmarkAction::new("Test", NavigationDirection::Forward);
        assert_eq!(action.name(), "Next Bookmark");
    }

    #[test]
    fn test_action_name_backward() {
        let action = NextPreviousBookmarkAction::new("Test", NavigationDirection::Backward);
        assert_eq!(action.name(), "Previous Bookmark");
    }

    #[test]
    fn test_action_name_inverted() {
        let mut action = NextPreviousBookmarkAction::new("Test", NavigationDirection::Forward);
        action.set_inverted(true);
        assert_eq!(action.name(), "Next Non-Bookmark");
    }

    #[test]
    fn test_navigate_forward_all_types() {
        let program = make_program_with_bookmarks();
        let action = NextPreviousBookmarkAction::new("Test", NavigationDirection::Forward);

        // From 0x1000, next bookmark is at 0x2000.
        let result = action.compute_address(&program, addr(0x1000), false);
        assert_eq!(result, Some(addr(0x2000)));
    }

    #[test]
    fn test_navigate_forward_from_between() {
        let program = make_program_with_bookmarks();
        let action = NextPreviousBookmarkAction::new("Test", NavigationDirection::Forward);

        // From 0x1500, next bookmark is at 0x2000.
        let result = action.compute_address(&program, addr(0x1500), false);
        assert_eq!(result, Some(addr(0x2000)));
    }

    #[test]
    fn test_navigate_backward_all_types() {
        let program = make_program_with_bookmarks();
        let action = NextPreviousBookmarkAction::new("Test", NavigationDirection::Backward);

        // From 0x3000, previous bookmark is at 0x2000.
        let result = action.compute_address(&program, addr(0x3000), false);
        assert_eq!(result, Some(addr(0x2000)));
    }

    #[test]
    fn test_navigate_forward_specific_type() {
        let program = make_program_with_bookmarks();
        let mut action = NextPreviousBookmarkAction::new("Test", NavigationDirection::Forward);
        action.set_bookmark_type(Some(BookmarkType::Warning));

        // From 0x1000, next Warning bookmark is at 0x2000.
        let result = action.compute_address(&program, addr(0x1000), false);
        assert_eq!(result, Some(addr(0x2000)));
    }

    #[test]
    fn test_navigate_forward_specific_type_no_match() {
        let program = make_program_with_bookmarks();
        let mut action = NextPreviousBookmarkAction::new("Test", NavigationDirection::Forward);
        action.set_bookmark_type(Some(BookmarkType::Analysis));

        // No Analysis bookmarks exist.
        let result = action.compute_address(&program, addr(0x1000), false);
        assert_eq!(result, None);
    }

    #[test]
    fn test_navigate_forward_at_end() {
        let program = make_program_with_bookmarks();
        let action = NextPreviousBookmarkAction::new("Test", NavigationDirection::Forward);

        // From 0x3000 (last bookmark), no more bookmarks.
        let result = action.compute_address(&program, addr(0x3000), false);
        assert_eq!(result, None);
    }

    #[test]
    fn test_navigate_backward_at_start() {
        let program = make_program_with_bookmarks();
        let action = NextPreviousBookmarkAction::new("Test", NavigationDirection::Backward);

        // From 0x1000 (first bookmark), no previous bookmarks.
        let result = action.compute_address(&program, addr(0x1000), false);
        assert_eq!(result, None);
    }

    #[test]
    fn test_shift_inverts_direction() {
        let program = make_program_with_bookmarks();
        let action = NextPreviousBookmarkAction::new("Test", NavigationDirection::Forward);

        // Normally forward from 0x2000 goes to 0x3000.
        let result = action.compute_address(&program, addr(0x2000), false);
        assert_eq!(result, Some(addr(0x3000)));

        // With shift, goes backward to 0x1000.
        let result = action.compute_address(&program, addr(0x2000), true);
        assert_eq!(result, Some(addr(0x1000)));
    }

    #[test]
    fn test_inverted_mode_finds_non_bookmark() {
        let program = make_program_with_bookmarks();
        let mut action = NextPreviousBookmarkAction::new("Test", NavigationDirection::Forward);
        action.set_inverted(true);

        // From 0x1000 (has a bookmark), next non-bookmark code unit.
        // Code units are at 0x1004, 0x1008, etc. 0x1004 has no bookmark.
        let result = action.compute_address(&program, addr(0x1000), false);
        assert_eq!(result, Some(addr(0x1004)));
    }

    #[test]
    fn test_inverted_backward() {
        let program = make_program_with_bookmarks();
        let mut action = NextPreviousBookmarkAction::new("Test", NavigationDirection::Backward);
        action.set_inverted(true);

        // From 0x3000 (has a bookmark), previous non-bookmark code unit.
        let result = action.compute_address(&program, addr(0x3000), false);
        assert_eq!(result, Some(addr(0x2004)));
    }

    #[test]
    fn test_tooltip_text() {
        let action = NextPreviousBookmarkAction::new("Test", NavigationDirection::Forward);
        let tooltip = action.tooltip_text();
        assert!(tooltip.contains("Next Bookmark"));
        assert!(tooltip.contains("All Types"));
        assert!(tooltip.contains("shift-click"));
    }

    #[test]
    fn test_tooltip_text_with_type() {
        let mut action = NextPreviousBookmarkAction::new("Test", NavigationDirection::Backward);
        action.set_bookmark_type(Some(BookmarkType::Error));
        let tooltip = action.tooltip_text();
        assert!(tooltip.contains("Previous Bookmark"));
        assert!(tooltip.contains("Error"));
    }

    #[test]
    fn test_key_stroke_description() {
        assert_eq!(
            NextPreviousBookmarkAction::key_stroke_description(),
            "Ctrl+Alt+B"
        );
    }

    #[test]
    fn test_set_direction() {
        let mut action = NextPreviousBookmarkAction::new("Test", NavigationDirection::Forward);
        assert_eq!(action.name(), "Next Bookmark");

        action.set_direction(NavigationDirection::Backward);
        assert_eq!(action.name(), "Previous Bookmark");
    }

    #[test]
    fn test_set_inverted() {
        let mut action = NextPreviousBookmarkAction::new("Test", NavigationDirection::Forward);
        assert_eq!(action.name(), "Next Bookmark");

        action.set_inverted(true);
        assert_eq!(action.name(), "Next Non-Bookmark");
    }

    #[test]
    fn test_empty_bookmark_manager() {
        let program = ProgramBookmarkModel::new("empty.exe");
        let action = NextPreviousBookmarkAction::new("Test", NavigationDirection::Forward);

        let result = action.compute_address(&program, addr(0x1000), false);
        assert_eq!(result, None);
    }

    #[test]
    fn test_bookmark_manager_at_exact_address_forward() {
        let mut program = ProgramBookmarkModel::new("test.exe");
        program
            .bookmark_manager
            .add_bookmark(Bookmark::new(addr(0x1000), "Error"));
        program
            .bookmark_manager
            .add_bookmark(Bookmark::new(addr(0x2000), "Warning"));

        let action = NextPreviousBookmarkAction::new("Test", NavigationDirection::Forward);
        // When at the exact bookmark address, forward search should find the next one
        // (because get_next_address_to_begin_searching_forward advances past current).
        let result = action.compute_address(&program, addr(0x1000), false);
        assert_eq!(result, Some(addr(0x2000)));
    }

    #[test]
    fn test_listing_model_code_units() {
        let mut listing = ListingModel::new();
        listing.add_code_unit(addr(0x1000));
        listing.add_code_unit(addr(0x2000));
        listing.add_code_unit(addr(0x3000));

        // Forward from 0x1500
        let addrs: Vec<Address> = listing.get_code_units(addr(0x1500), true).collect();
        assert_eq!(addrs, vec![addr(0x2000), addr(0x3000)]);

        // Backward from 0x2500
        let addrs: Vec<Address> = listing.get_code_units(addr(0x2500), false).collect();
        assert_eq!(addrs, vec![addr(0x2000), addr(0x1000)]);
    }
}
