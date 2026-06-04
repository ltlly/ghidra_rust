//! Navigation actions for the code browser.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.navigation` package.
//!
//! Provides the framework for next/previous navigation actions that allow
//! users to jump between code elements (labels, functions, instructions,
//! defined data, undefined data, etc.) in the listing view.
//!
//! # Architecture
//!
//! - [`NavigationDirection`] -- Forward or backward direction.
//! - [`NavigationType`] -- The type of code element to navigate to.
//! - [`NavigationOptions`] -- User-configurable navigation settings.
//! - [`NextPreviousNavigator`] -- Core algorithm for finding the next/previous
//!   occurrence of a given type.
//!
//! # Usage
//!
//! ```rust
//! use ghidra_features::base::navigation::*;
//!
//! let addresses = vec![0x1000, 0x2000, 0x3000, 0x4000];
//! let nav = NextPreviousNavigator::new(NavigationType::Label, addresses);
//!
//! // From 0x2000 forward -> 0x3000
//! assert_eq!(nav.find_next(0x2000, NavigationDirection::Forward), Some(0x3000));
//!
//! // From 0x2000 backward -> 0x1000
//! assert_eq!(nav.find_next(0x2000, NavigationDirection::Backward), Some(0x1000));
//!
//! // From last address forward -> wraps to first
//! assert_eq!(nav.find_next(0x4000, NavigationDirection::Forward), Some(0x1000));
//! ```

/// Direction of navigation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NavigationDirection {
    /// Navigate to the next (higher address) item.
    Forward,
    /// Navigate to the previous (lower address) item.
    Backward,
}

impl NavigationDirection {
    /// Invert the direction.
    pub fn invert(&self) -> Self {
        match self {
            Self::Forward => Self::Backward,
            Self::Backward => Self::Forward,
        }
    }
}

/// The type of code element to navigate to.
///
/// Each value corresponds to a specific Next/Previous action in Ghidra's
/// navigation plugin suite.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NavigationType {
    /// Navigate to a label (symbol name).
    Label,
    /// Navigate to a function entry point.
    Function,
    /// Navigate to an instruction.
    Instruction,
    /// Navigate to defined data.
    DefinedData,
    /// Navigate to undefined data.
    UndefinedData,
    /// Navigate to a highlighted range.
    HighlightedRange,
    /// Navigate to the same byte pattern.
    SameBytes,
    /// Navigate to a selected range.
    SelectedRange,
}

impl NavigationType {
    /// Human-readable name for this navigation type.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Label => "Label",
            Self::Function => "Function",
            Self::Instruction => "Instruction",
            Self::DefinedData => "Defined Data",
            Self::UndefinedData => "Undefined Data",
            Self::HighlightedRange => "Highlighted Range",
            Self::SameBytes => "Same Bytes",
            Self::SelectedRange => "Selected Range",
        }
    }

    /// Display name with navigation prefix.
    pub fn next_name(&self) -> String {
        format!("Next {}", self.display_name())
    }

    /// Display name with navigation prefix.
    pub fn previous_name(&self) -> String {
        format!("Previous {}", self.display_name())
    }
}

/// Options that control navigation behavior.
///
/// Ported from `ghidra.app.plugin.core.navigation.NavigationOptions`.
#[derive(Debug, Clone)]
pub struct NavigationOptions {
    /// Whether to wrap around when reaching the end/beginning of the address space.
    pub wrap_around: bool,
    /// Whether shift-click inverts the direction.
    pub shift_inverts: bool,
    /// The default navigation direction.
    pub default_direction: NavigationDirection,
}

impl Default for NavigationOptions {
    fn default() -> Self {
        Self {
            wrap_around: true,
            shift_inverts: true,
            default_direction: NavigationDirection::Forward,
        }
    }
}

/// Core navigator for finding next/previous occurrences of a code element type.
///
/// This struct holds a sorted list of addresses and provides efficient
/// next/previous search. It corresponds to the core algorithm used by
/// Ghidra's `AbstractNextPreviousAction`.
#[derive(Debug, Clone)]
pub struct NextPreviousNavigator {
    /// The type of element being navigated.
    nav_type: NavigationType,
    /// Sorted list of addresses.
    addresses: Vec<u64>,
    /// Whether to wrap around at boundaries.
    wrap_around: bool,
}

impl NextPreviousNavigator {
    /// Create a new navigator with the given addresses.
    ///
    /// The addresses do not need to be sorted; they will be sorted
    /// and deduplicated internally.
    pub fn new(nav_type: NavigationType, addresses: Vec<u64>) -> Self {
        let mut addresses = addresses;
        addresses.sort_unstable();
        addresses.dedup();
        Self {
            nav_type,
            addresses,
            wrap_around: true,
        }
    }

    /// Set whether the navigator wraps around at boundaries.
    pub fn set_wrap_around(&mut self, wrap: bool) {
        self.wrap_around = wrap;
    }

    /// Get the navigation type.
    pub fn nav_type(&self) -> NavigationType {
        self.nav_type
    }

    /// Get the number of navigable addresses.
    pub fn len(&self) -> usize {
        self.addresses.len()
    }

    /// Whether the navigator has no addresses.
    pub fn is_empty(&self) -> bool {
        self.addresses.is_empty()
    }

    /// Find the next address from the given current address.
    ///
    /// If `current_addr` is in the list, the search starts from there.
    /// If not, finds the first address greater (forward) or less (backward).
    ///
    /// Returns `None` if no suitable address is found (only when wrap_around
    /// is false and at a boundary).
    pub fn find_next(&self, current_addr: u64, direction: NavigationDirection) -> Option<u64> {
        if self.addresses.is_empty() {
            return None;
        }

        match direction {
            NavigationDirection::Forward => self.find_forward(current_addr),
            NavigationDirection::Backward => self.find_backward(current_addr),
        }
    }

    fn find_forward(&self, current_addr: u64) -> Option<u64> {
        // Find the first address strictly greater than current_addr.
        let idx = self
            .addresses
            .partition_point(|&a| a <= current_addr);

        if idx < self.addresses.len() {
            Some(self.addresses[idx])
        } else if self.wrap_around {
            Some(self.addresses[0])
        } else {
            None
        }
    }

    fn find_backward(&self, current_addr: u64) -> Option<u64> {
        // Find the last address strictly less than current_addr.
        let idx = self
            .addresses
            .partition_point(|&a| a < current_addr);

        if idx > 0 {
            Some(self.addresses[idx - 1])
        } else if self.wrap_around {
            Some(self.addresses[self.addresses.len() - 1])
        } else {
            None
        }
    }

    /// Find the address at an exact position.
    pub fn get_address(&self, index: usize) -> Option<u64> {
        self.addresses.get(index).copied()
    }

    /// Get a reference to the sorted addresses.
    pub fn addresses(&self) -> &[u64] {
        &self.addresses
    }

    /// Create a navigator from options.
    pub fn with_options(
        nav_type: NavigationType,
        addresses: Vec<u64>,
        options: &NavigationOptions,
    ) -> Self {
        let mut nav = Self::new(nav_type, addresses);
        nav.set_wrap_around(options.wrap_around);
        nav
    }
}

// ---------------------------------------------------------------------------
// Navigation action descriptor
// ---------------------------------------------------------------------------

/// Describes a navigation action (name, icon, key binding).
///
/// This corresponds to the metadata set up in Ghidra's
/// `AbstractNextPreviousAction` constructor.
#[derive(Debug, Clone)]
pub struct NavigationActionDescriptor {
    /// The navigation type.
    pub nav_type: NavigationType,
    /// The display name of the action.
    pub name: String,
    /// Description shown in the toolbar tooltip.
    pub description: String,
    /// Whether the direction is inverted (non- prefix).
    pub is_inverted: bool,
    /// The current direction.
    pub direction: NavigationDirection,
}

impl NavigationActionDescriptor {
    /// Create a forward action descriptor.
    pub fn forward(nav_type: NavigationType) -> Self {
        Self {
            name: nav_type.next_name(),
            description: format!(
                "Go To Next {} (shift-click inverts direction)",
                nav_type.display_name()
            ),
            nav_type,
            is_inverted: false,
            direction: NavigationDirection::Forward,
        }
    }

    /// Create a backward action descriptor.
    pub fn backward(nav_type: NavigationType) -> Self {
        Self {
            name: nav_type.previous_name(),
            description: format!(
                "Go To Previous {} (shift-click inverts direction)",
                nav_type.display_name()
            ),
            nav_type,
            is_inverted: false,
            direction: NavigationDirection::Backward,
        }
    }

    /// Invert the navigation direction.
    pub fn invert(&mut self) {
        self.direction = self.direction.invert();
        self.is_inverted = !self.is_inverted;
        self.description = if self.direction == NavigationDirection::Forward {
            format!(
                "Go To Next {} (shift-click inverts direction)",
                self.nav_type.display_name()
            )
        } else {
            format!(
                "Go To Previous {} (shift-click inverts direction)",
                self.nav_type.display_name()
            )
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_direction_invert() {
        assert_eq!(
            NavigationDirection::Forward.invert(),
            NavigationDirection::Backward
        );
        assert_eq!(
            NavigationDirection::Backward.invert(),
            NavigationDirection::Forward
        );
    }

    #[test]
    fn test_navigation_type_display() {
        assert_eq!(NavigationType::Label.display_name(), "Label");
        assert_eq!(NavigationType::Function.display_name(), "Function");
        assert_eq!(NavigationType::UndefinedData.display_name(), "Undefined Data");
    }

    #[test]
    fn test_navigation_type_names() {
        assert_eq!(NavigationType::Label.next_name(), "Next Label");
        assert_eq!(NavigationType::Function.previous_name(), "Previous Function");
    }

    #[test]
    fn test_navigator_empty() {
        let nav = NextPreviousNavigator::new(NavigationType::Label, vec![]);
        assert!(nav.is_empty());
        assert_eq!(nav.find_next(0x400000, NavigationDirection::Forward), None);
    }

    #[test]
    fn test_navigator_forward() {
        let nav = NextPreviousNavigator::new(
            NavigationType::Label,
            vec![0x1000, 0x2000, 0x3000, 0x4000],
        );

        assert_eq!(
            nav.find_next(0x1000, NavigationDirection::Forward),
            Some(0x2000)
        );
        assert_eq!(
            nav.find_next(0x2000, NavigationDirection::Forward),
            Some(0x3000)
        );
        // Address not in list, should find next greater.
        assert_eq!(
            nav.find_next(0x1500, NavigationDirection::Forward),
            Some(0x2000)
        );
    }

    #[test]
    fn test_navigator_backward() {
        let nav = NextPreviousNavigator::new(
            NavigationType::Label,
            vec![0x1000, 0x2000, 0x3000, 0x4000],
        );

        assert_eq!(
            nav.find_next(0x3000, NavigationDirection::Backward),
            Some(0x2000)
        );
        assert_eq!(
            nav.find_next(0x4000, NavigationDirection::Backward),
            Some(0x3000)
        );
    }

    #[test]
    fn test_navigator_wrap_around_forward() {
        let nav = NextPreviousNavigator::new(
            NavigationType::Label,
            vec![0x1000, 0x2000, 0x3000],
        );

        // From last element forward -> wraps to first.
        assert_eq!(
            nav.find_next(0x3000, NavigationDirection::Forward),
            Some(0x1000)
        );
    }

    #[test]
    fn test_navigator_wrap_around_backward() {
        let nav = NextPreviousNavigator::new(
            NavigationType::Label,
            vec![0x1000, 0x2000, 0x3000],
        );

        // From first element backward -> wraps to last.
        assert_eq!(
            nav.find_next(0x1000, NavigationDirection::Backward),
            Some(0x3000)
        );
    }

    #[test]
    fn test_navigator_no_wrap() {
        let mut nav = NextPreviousNavigator::new(
            NavigationType::Label,
            vec![0x1000, 0x2000, 0x3000],
        );
        nav.set_wrap_around(false);

        assert_eq!(
            nav.find_next(0x3000, NavigationDirection::Forward),
            None
        );
        assert_eq!(
            nav.find_next(0x1000, NavigationDirection::Backward),
            None
        );
    }

    #[test]
    fn test_navigator_sorts_and_deduplicates() {
        let nav = NextPreviousNavigator::new(
            NavigationType::Label,
            vec![0x3000, 0x1000, 0x2000, 0x1000, 0x3000],
        );
        assert_eq!(nav.len(), 3);
        assert_eq!(nav.addresses(), &[0x1000, 0x2000, 0x3000]);
    }

    #[test]
    fn test_navigator_from_unsorted_addresses() {
        let nav = NextPreviousNavigator::new(
            NavigationType::Function,
            vec![0x5000, 0x1000, 0x3000],
        );
        assert_eq!(nav.nav_type(), NavigationType::Function);
        assert_eq!(
            nav.find_next(0x1000, NavigationDirection::Forward),
            Some(0x3000)
        );
    }

    #[test]
    fn test_navigation_action_descriptor_forward() {
        let desc = NavigationActionDescriptor::forward(NavigationType::Label);
        assert_eq!(desc.name, "Next Label");
        assert!(!desc.is_inverted);
        assert_eq!(desc.direction, NavigationDirection::Forward);
    }

    #[test]
    fn test_navigation_action_descriptor_backward() {
        let desc = NavigationActionDescriptor::backward(NavigationType::Function);
        assert_eq!(desc.name, "Previous Function");
        assert!(!desc.is_inverted);
        assert_eq!(desc.direction, NavigationDirection::Backward);
    }

    #[test]
    fn test_navigation_action_descriptor_invert() {
        let mut desc = NavigationActionDescriptor::forward(NavigationType::Instruction);
        desc.invert();
        assert_eq!(desc.direction, NavigationDirection::Backward);
        assert!(desc.is_inverted);
        assert_eq!(desc.name, "Next Instruction"); // Name doesn't change
        assert!(desc.description.contains("Previous"));
    }

    #[test]
    fn test_navigation_options_default() {
        let opts = NavigationOptions::default();
        assert!(opts.wrap_around);
        assert!(opts.shift_inverts);
        assert_eq!(opts.default_direction, NavigationDirection::Forward);
    }

    #[test]
    fn test_navigator_with_options() {
        let opts = NavigationOptions {
            wrap_around: false,
            ..Default::default()
        };
        let nav = NextPreviousNavigator::with_options(
            NavigationType::Label,
            vec![0x1000],
            &opts,
        );
        assert!(!nav.wrap_around);
        assert_eq!(
            nav.find_next(0x1000, NavigationDirection::Forward),
            None
        );
    }

    #[test]
    fn test_navigator_get_address() {
        let nav = NextPreviousNavigator::new(
            NavigationType::Label,
            vec![0x1000, 0x2000, 0x3000],
        );
        assert_eq!(nav.get_address(0), Some(0x1000));
        assert_eq!(nav.get_address(1), Some(0x2000));
        assert_eq!(nav.get_address(2), Some(0x3000));
        assert_eq!(nav.get_address(3), None);
    }

    #[test]
    fn test_navigator_before_all() {
        let nav = NextPreviousNavigator::new(
            NavigationType::Label,
            vec![0x1000, 0x2000],
        );
        // Address before all entries.
        assert_eq!(
            nav.find_next(0x0500, NavigationDirection::Forward),
            Some(0x1000)
        );
        assert_eq!(
            nav.find_next(0x0500, NavigationDirection::Backward),
            Some(0x2000) // wraps
        );
    }

    #[test]
    fn test_navigator_after_all() {
        let nav = NextPreviousNavigator::new(
            NavigationType::Label,
            vec![0x1000, 0x2000],
        );
        // Address after all entries.
        assert_eq!(
            nav.find_next(0x5000, NavigationDirection::Forward),
            Some(0x1000) // wraps
        );
        assert_eq!(
            nav.find_next(0x5000, NavigationDirection::Backward),
            Some(0x2000)
        );
    }
}
