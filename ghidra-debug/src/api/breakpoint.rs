//! LogicalBreakpoint - the high-level breakpoint abstraction.
//!
//! A logical breakpoint ties together bookmarks (from programs) and
//! trace breakpoint locations (from traces). It has a mode (enabled/disabled)
//! and a consistency state.

use serde::{Deserialize, Serialize};

/// The mode of a logical breakpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum BreakpointMode {
    /// Breakpoint is enabled.
    Enabled,
    /// Breakpoint is disabled.
    Disabled,
}

impl BreakpointMode {
    /// Compose two modes at the same address.
    pub fn same_address(&self, other: Self) -> Self {
        if *self == Self::Enabled || other == Self::Enabled {
            Self::Enabled
        } else {
            Self::Disabled
        }
    }
}

/// The consistency of a logical breakpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum BreakpointConsistency {
    /// The bookmark and locations all agree.
    Normal,
    /// Has a bookmark but one or more trace locations is missing.
    Ineffective,
    /// Has a trace location but is not bookmarked, or the bookmark disagrees.
    Inconsistent,
}

impl BreakpointConsistency {
    /// Compose two consistency values at the same address.
    pub fn same_address(&self, other: Self) -> Self {
        let max = (*self as u8).max(other as u8);
        match max {
            0 => Self::Normal,
            1 => Self::Ineffective,
            _ => Self::Inconsistent,
        }
    }
}

/// The composite state of a logical breakpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BreakpointState {
    /// The mode (enabled/disabled).
    pub mode: Option<BreakpointMode>,
    /// The consistency.
    pub consistency: Option<BreakpointConsistency>,
}

impl BreakpointState {
    /// No state (both mode and consistency are None).
    pub const NONE: BreakpointState = BreakpointState {
        mode: None,
        consistency: None,
    };

    /// Enabled and normal.
    pub const ENABLED: BreakpointState = BreakpointState {
        mode: Some(BreakpointMode::Enabled),
        consistency: Some(BreakpointConsistency::Normal),
    };

    /// Disabled and normal.
    pub const DISABLED: BreakpointState = BreakpointState {
        mode: Some(BreakpointMode::Disabled),
        consistency: Some(BreakpointConsistency::Normal),
    };

    /// Create from fields.
    pub fn from_fields(
        mode: Option<BreakpointMode>,
        consistency: Option<BreakpointConsistency>,
    ) -> Self {
        if mode.is_none() && consistency.is_none() {
            return Self::NONE;
        }
        Self { mode, consistency }
    }

    /// Compose two states at the same address.
    pub fn same_address(&self, other: Self) -> Self {
        if *self == Self::NONE {
            return other;
        }
        if other == Self::NONE {
            return *self;
        }
        let mode = match (self.mode, other.mode) {
            (Some(a), Some(b)) => Some(a.same_address(b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        };
        let consistency = match (self.consistency, other.consistency) {
            (Some(a), Some(b)) => Some(a.same_address(b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        };
        Self { mode, consistency }
    }
}

/// A logical breakpoint tying together program bookmarks and trace locations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogicalBreakpoint {
    /// Address offset of this breakpoint.
    pub offset: u64,
    /// Expression (e.g. "0x400000").
    pub expression: String,
    /// Kinds of breakpoint.
    pub kinds: Vec<String>,
    /// Whether the breakpoint is togglable by the user.
    pub togglable: bool,
    /// The current composite state.
    pub state: BreakpointState,
    /// Comment text.
    pub comment: Option<String>,
}

impl LogicalBreakpoint {
    /// Bookmark type string for enabled breakpoints.
    pub const ENABLED_BOOKMARK_TYPE: &'static str = "BreakpointEnabled";
    /// Bookmark type string for disabled breakpoints.
    pub const DISABLED_BOOKMARK_TYPE: &'static str = "BreakpointDisabled";

    /// Marker name for enabled breakpoints.
    pub const NAME_MARKER_ENABLED: &'static str = "Enabled Breakpoint";
    /// Marker name for disabled breakpoints.
    pub const NAME_MARKER_DISABLED: &'static str = "Disabled Breakpoint";
    /// Marker name for mixed breakpoints.
    pub const NAME_MARKER_MIXED: &'static str = "Mixed Breakpoint";

    /// Create a new logical breakpoint.
    pub fn new(offset: u64, expression: impl Into<String>) -> Self {
        Self {
            offset,
            expression: expression.into(),
            kinds: Vec::new(),
            togglable: false,
            state: BreakpointState::ENABLED,
            comment: None,
        }
    }

    /// Set the kinds.
    pub fn with_kinds(mut self, kinds: Vec<String>) -> Self {
        self.kinds = kinds;
        self
    }

    /// Whether this breakpoint is currently enabled.
    pub fn is_enabled(&self) -> bool {
        self.state.mode == Some(BreakpointMode::Enabled)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_breakpoint_mode_same_address() {
        assert_eq!(
            BreakpointMode::Enabled.same_address(BreakpointMode::Disabled),
            BreakpointMode::Enabled
        );
        assert_eq!(
            BreakpointMode::Disabled.same_address(BreakpointMode::Disabled),
            BreakpointMode::Disabled
        );
    }

    #[test]
    fn test_breakpoint_consistency_same_address() {
        assert_eq!(
            BreakpointConsistency::Normal.same_address(BreakpointConsistency::Inconsistent),
            BreakpointConsistency::Inconsistent
        );
        assert_eq!(
            BreakpointConsistency::Normal.same_address(BreakpointConsistency::Normal),
            BreakpointConsistency::Normal
        );
    }

    #[test]
    fn test_breakpoint_state() {
        assert_eq!(BreakpointState::NONE, BreakpointState::from_fields(None, None));

        let composed =
            BreakpointState::ENABLED.same_address(BreakpointState::from_fields(
                Some(BreakpointMode::Enabled),
                Some(BreakpointConsistency::Inconsistent),
            ));
        assert_eq!(composed.mode, Some(BreakpointMode::Enabled));
        assert_eq!(
            composed.consistency,
            Some(BreakpointConsistency::Inconsistent)
        );
    }

    #[test]
    fn test_logical_breakpoint() {
        let bp = LogicalBreakpoint::new(0x400000, "0x400000")
            .with_kinds(vec!["SW_EXECUTE".into()]);
        assert!(bp.is_enabled());
        assert_eq!(bp.offset, 0x400000);
    }

    #[test]
    fn test_breakpoint_state_none_identity() {
        let state = BreakpointState::ENABLED;
        assert_eq!(state.same_address(BreakpointState::NONE), state);
        assert_eq!(BreakpointState::NONE.same_address(state), state);
    }
}
