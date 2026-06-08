//! Function Call Graph level -- a row in the bow-tie layout.
//!
//! Ported from Ghidra's `functioncalls.graph.FcgLevel` Java class.
//!
//! A level is both the row of the vertex (the number of hops from the
//! source vertex) and the direction.  Levels use a 1-based row system
//! internally, with negative rows for outgoing directions.

use super::fcg_direction::FcgDirection;

/// A container representing a Function Call Graph level (row + direction).
///
/// Ported from `functioncalls.graph.FcgLevel`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FcgLevel {
    /// 1-based row number.  Negative for outgoing direction.
    row: i32,
    /// The direction of this level.
    direction: FcgDirection,
}

impl FcgLevel {
    /// Create the source level (row 1, direction InAndOut).
    pub fn source_level() -> Self {
        // Manually construct to avoid the validation in `new` which rejects row==1
        // for non-InAndOut.  The source is special: distance=0, direction=InAndOut.
        Self {
            row: 1,
            direction: FcgDirection::InAndOut,
        }
    }

    /// Create a new level.
    ///
    /// # Arguments
    ///
    /// * `distance` -- the number of hops from the source vertex (must be >= 1).
    /// * `direction` -- the direction of this level (must not be `InAndOut` for distance > 0).
    ///
    /// # Panics
    ///
    /// Panics if `distance == 0` (use [`source_level()`](Self::source_level) instead)
    /// or if `distance == 1` and `direction != InAndOut`.
    pub fn new(distance: u32, direction: FcgDirection) -> Self {
        let row = Self::to_row(distance, direction);

        if row == 0 {
            panic!("The FcgLevel uses a 1-based row system");
        }

        if row == 1 && direction != FcgDirection::InAndOut {
            panic!("Row 1 must be FcgDirection::InAndOut");
        }

        Self { row, direction }
    }

    fn to_row(distance: u32, direction: FcgDirection) -> i32 {
        let one_based = (distance as i32) + 1;
        if direction == FcgDirection::Out {
            -one_based
        } else {
            one_based
        }
    }

    /// Get the raw row value (negative for outgoing).
    pub fn row(&self) -> i32 {
        self.row
    }

    /// Get the distance from the source (absolute hops).
    pub fn distance(&self) -> u32 {
        (self.row.abs() - 1) as u32
    }

    /// Get the direction of this level.
    pub fn direction(&self) -> FcgDirection {
        self.direction
    }

    /// Returns `true` if this level represents the source level (row 1).
    pub fn is_source(&self) -> bool {
        self.direction.is_source()
    }

    /// Get the parent level (one hop closer to source).
    ///
    /// # Panics
    ///
    /// Panics if this is the source level.
    pub fn parent(&self) -> FcgLevel {
        if self.direction == FcgDirection::InAndOut {
            panic!(
                "To get the parent of the source level you must use the constructor directly"
            );
        }

        let new_distance = self.distance() - 1;
        let new_direction = if new_distance == 0 {
            FcgDirection::InAndOut
        } else {
            self.direction
        };
        FcgLevel::new(new_distance, new_direction)
    }

    /// Get the child level (one hop further from source).
    ///
    /// # Panics
    ///
    /// Panics if this is the source level.
    pub fn child(&self) -> FcgLevel {
        if self.direction == FcgDirection::InAndOut {
            panic!(
                "To get the child of the source level you must use the constructor directly"
            );
        }
        self.child_with_direction(self.direction)
    }

    /// Get the child level with a specific direction.
    ///
    /// # Panics
    ///
    /// Panics if `new_direction` is `InAndOut`.
    pub fn child_with_direction(&self, new_direction: FcgDirection) -> FcgLevel {
        if new_direction == FcgDirection::InAndOut {
            panic!("Direction cannot be InAndOut");
        }
        let new_distance = self.distance() + 1;
        FcgLevel::new(new_distance, new_direction)
    }

    /// Returns `true` if this level is the immediate predecessor of `other`.
    ///
    /// The source level is the parent of the first level in either direction.
    pub fn is_parent_of(&self, other: &FcgLevel) -> bool {
        if self.is_source() {
            return other.distance() == 1;
        }

        if self.direction != other.direction {
            return false;
        }

        other.distance().saturating_sub(self.distance()) == 1
    }

    /// Returns `true` if this level is the immediate successor of `other`.
    pub fn is_child_of(&self, other: &FcgLevel) -> bool {
        other.is_parent_of(self)
    }

    /// Get the relative row (positive for incoming, negative for outgoing).
    fn relative_row(&self) -> i32 {
        if self.direction == FcgDirection::Out {
            -self.row
        } else {
            self.row
        }
    }
}

impl PartialOrd for FcgLevel {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for FcgLevel {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Compare by direction first: In on top; Out on bottom
        match self.direction.cmp(&other.direction) {
            std::cmp::Ordering::Equal => {
                // Same direction: compare by relative row (negated to match Java's ordering)
                other.relative_row().cmp(&self.relative_row())
            }
            ord => ord,
        }
    }
}

impl std::fmt::Display for FcgLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} - row {}", self.direction, self.relative_row())
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_source_level() {
        let level = FcgLevel::source_level();
        assert!(level.is_source());
        assert_eq!(level.direction(), FcgDirection::InAndOut);
        assert_eq!(level.row(), 1);
        assert_eq!(level.distance(), 0);
    }

    #[test]
    fn test_incoming_level_distance_1() {
        let level = FcgLevel::new(1, FcgDirection::In);
        assert_eq!(level.distance(), 1);
        assert_eq!(level.direction(), FcgDirection::In);
        assert!(!level.is_source());
    }

    #[test]
    fn test_outgoing_level_distance_1() {
        let level = FcgLevel::new(1, FcgDirection::Out);
        assert_eq!(level.distance(), 1);
        assert_eq!(level.direction(), FcgDirection::Out);
        assert_eq!(level.row(), -2);
    }

    #[test]
    fn test_parent() {
        let level = FcgLevel::new(2, FcgDirection::In);
        let parent = level.parent();
        assert_eq!(parent.distance(), 1);
        assert_eq!(parent.direction(), FcgDirection::In);
    }

    #[test]
    fn test_parent_to_source() {
        let level = FcgLevel::new(1, FcgDirection::In);
        let parent = level.parent();
        assert!(parent.is_source());
    }

    #[test]
    fn test_child() {
        let level = FcgLevel::new(1, FcgDirection::In);
        let child = level.child();
        assert_eq!(child.distance(), 2);
        assert_eq!(child.direction(), FcgDirection::In);
    }

    #[test]
    fn test_child_with_direction() {
        let level = FcgLevel::new(1, FcgDirection::In);
        let child = level.child_with_direction(FcgDirection::Out);
        assert_eq!(child.distance(), 2);
        assert_eq!(child.direction(), FcgDirection::Out);
    }

    #[test]
    fn test_is_parent_of() {
        let source = FcgLevel::source_level();
        let in1 = FcgLevel::new(1, FcgDirection::In);
        let in2 = FcgLevel::new(2, FcgDirection::In);

        assert!(source.is_parent_of(&in1));
        assert!(!source.is_parent_of(&in2));
        assert!(in1.is_parent_of(&in2));
        assert!(!in2.is_parent_of(&in1));
    }

    #[test]
    fn test_is_child_of() {
        let in1 = FcgLevel::new(1, FcgDirection::In);
        let in2 = FcgLevel::new(2, FcgDirection::In);
        assert!(in2.is_child_of(&in1));
        assert!(!in1.is_child_of(&in2));
    }

    #[test]
    fn test_ordering() {
        let source = FcgLevel::source_level();
        let in1 = FcgLevel::new(1, FcgDirection::In);
        let out1 = FcgLevel::new(1, FcgDirection::Out);

        // In < InAndOut < Out
        assert!(in1 < source);
        assert!(source < out1);
    }

    #[test]
    fn test_display() {
        let source = FcgLevel::source_level();
        assert_eq!(source.to_string(), "In/Out - row 1");

        let in1 = FcgLevel::new(1, FcgDirection::In);
        assert_eq!(in1.to_string(), "In - row 2");
    }

    #[test]
    fn test_equality() {
        let a = FcgLevel::new(2, FcgDirection::In);
        let b = FcgLevel::new(2, FcgDirection::In);
        let c = FcgLevel::new(2, FcgDirection::Out);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    #[should_panic(expected = "Row 1 must be FcgDirection::InAndOut")]
    fn test_invalid_distance_zero() {
        FcgLevel::new(0, FcgDirection::In);
    }

    #[test]
    fn test_outgoing_parent_to_source() {
        let level = FcgLevel::new(1, FcgDirection::Out);
        let parent = level.parent();
        assert!(parent.is_source());
    }
}
