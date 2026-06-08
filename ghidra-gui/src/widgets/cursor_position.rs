//! Cursor position tracker.
//!
//! Port of Ghidra's `CursorPosition` class. A simple tracker of position in an
//! object that allows more specialized users to extend and add functionality.

/// A simple position tracker used by search and navigation subsystems.
///
/// In Ghidra this was used by `SearchLocation` and other cursor-tracking
/// contexts. In the Rust port it serves the same purpose: wrapping an integer
/// offset with convenience methods.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CursorPosition {
    position: usize,
}

impl CursorPosition {
    /// Create a new cursor position at the given offset.
    pub fn new(position: usize) -> Self {
        Self { position }
    }

    /// Get the current position.
    pub fn position(&self) -> usize {
        self.position
    }

    /// Advance the position by `offset`.
    pub fn set_offset(&mut self, offset: usize) {
        self.position += offset;
    }

    /// Decrement the position by `offset`, saturating at zero.
    pub fn decrement_offset(&mut self, offset: usize) {
        self.position = self.position.saturating_sub(offset);
    }
}

impl Default for CursorPosition {
    fn default() -> Self {
        Self::new(0)
    }
}

impl std::fmt::Display for CursorPosition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CursorPosition - {}", self.position)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let pos = CursorPosition::new(42);
        assert_eq!(pos.position(), 42);
    }

    #[test]
    fn test_default() {
        let pos = CursorPosition::default();
        assert_eq!(pos.position(), 0);
    }

    #[test]
    fn test_set_offset() {
        let mut pos = CursorPosition::new(10);
        pos.set_offset(5);
        assert_eq!(pos.position(), 15);
    }

    #[test]
    fn test_decrement_offset() {
        let mut pos = CursorPosition::new(10);
        pos.decrement_offset(3);
        assert_eq!(pos.position(), 7);
    }

    #[test]
    fn test_decrement_saturates_at_zero() {
        let mut pos = CursorPosition::new(2);
        pos.decrement_offset(10);
        assert_eq!(pos.position(), 0);
    }

    #[test]
    fn test_display() {
        let pos = CursorPosition::new(7);
        assert_eq!(format!("{}", pos), "CursorPosition - 7");
    }

    #[test]
    fn test_clone_copy() {
        let pos = CursorPosition::new(5);
        let pos2 = pos;
        assert_eq!(pos, pos2);
    }
}
