//! Navigation settings -- ported from `NavigationOptions.java` and
//! `ProgramStartingLocationOptions.java`.
//!
//! Extended navigation settings that supplement the base
//! [`NavigationOptions`](super::NavigationOptions) in mod.rs.
//! Provides range-navigation policy and program starting location
//! configuration.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// RangeNavigationOption
// ---------------------------------------------------------------------------

/// How to handle navigation when the target is inside a range (e.g., a
/// memory block or highlighted region).
///
/// Ported from Ghidra's `RangeNavigationOption`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RangeNavigationOption {
    /// Navigate to the top of the range only.
    TopOfRangeOnly,
    /// Navigate to any address within the range.
    AnyInRange,
    /// Navigate to the nearest defined data or instruction.
    NearestDefined,
}

impl Default for RangeNavigationOption {
    fn default() -> Self {
        Self::AnyInRange
    }
}

impl RangeNavigationOption {
    /// Display name for this option.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::TopOfRangeOnly => "Top of Range Only",
            Self::AnyInRange => "Any Address in Range",
            Self::NearestDefined => "Nearest Defined Location",
        }
    }
}

// ---------------------------------------------------------------------------
// ProgramStartingLocationOptions
// ---------------------------------------------------------------------------

/// Options for controlling the starting location when opening a program.
///
/// Ported from `ProgramStartingLocationOptions.java`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramStartingLocationOptions {
    /// Whether to restore the last viewed location on program open.
    pub restore_last_location: bool,
    /// Whether to start at the program entry point.
    pub start_at_entry: bool,
    /// A fixed starting address (used when `start_at_entry` is false
    /// and `restore_last_location` is false).
    pub fixed_start_address: Option<u64>,
}

impl ProgramStartingLocationOptions {
    /// Create default options.
    pub fn new() -> Self {
        Self {
            restore_last_location: true,
            start_at_entry: false,
            fixed_start_address: None,
        }
    }
}

impl Default for ProgramStartingLocationOptions {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_range_navigation_option() {
        assert_eq!(
            RangeNavigationOption::TopOfRangeOnly.display_name(),
            "Top of Range Only"
        );
        assert_eq!(RangeNavigationOption::default(), RangeNavigationOption::AnyInRange);
    }

    #[test]
    fn test_program_starting_location_options() {
        let opts = ProgramStartingLocationOptions::default();
        assert!(opts.restore_last_location);
        assert!(!opts.start_at_entry);
        assert!(opts.fixed_start_address.is_none());
    }

    #[test]
    fn test_range_navigation_variants() {
        assert_ne!(RangeNavigationOption::TopOfRangeOnly, RangeNavigationOption::AnyInRange);
        assert_eq!(RangeNavigationOption::NearestDefined.display_name(), "Nearest Defined Location");
    }

    #[test]
    fn test_program_starting_location_fixed() {
        let mut opts = ProgramStartingLocationOptions::new();
        opts.fixed_start_address = Some(0x400000);
        assert_eq!(opts.fixed_start_address, Some(0x400000));
    }
}
