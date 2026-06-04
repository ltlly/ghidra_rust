//! Repeat pattern tracker -- ported from Ghidra's `RepeatInstructionByteTracker.java`.
//!
//! Detects and flags sequences of repeated byte values in instructions.
//! When a disassembly follows a region of bytes that all produce the same
//! instruction (e.g., a NOP sled or padding), the tracker flags this as
//! potentially erroneous to prevent infinite disassembly loops.

use crate::base::analyzer::core::*;
use crate::base::disassembler::core::MAX_REPEAT_PATTERN_LENGTH;

// ---------------------------------------------------------------------------
// RepeatPatternTracker
// ---------------------------------------------------------------------------

/// Tracks consecutive instructions with identical byte patterns.
///
/// When the number of consecutive identical instructions exceeds the
/// configured limit, the tracker indicates that disassembly should stop
/// to prevent runaway disassembly of padding or data regions.
///
/// # Example
///
/// ```ignore
/// use ghidra_features::base::disassembler::RepeatPatternTracker;
///
/// let mut tracker = RepeatPatternTracker::new(16);
/// tracker.feed_instruction(&[0x90, 0x90, 0x90, 0x90], 0x1000);
/// tracker.feed_instruction(&[0x90, 0x90, 0x90, 0x90], 0x1004);
/// // After 16 consecutive NOPs, is_limit_exceeded() returns true
/// ```
#[derive(Debug, Clone)]
pub struct RepeatPatternTracker {
    /// Maximum number of consecutive identical instructions before flagging.
    limit: usize,
    /// Byte pattern of the most recent instruction.
    current_pattern: Vec<u8>,
    /// Number of consecutive instructions with the current pattern.
    current_count: usize,
    /// Address of the first instruction in the current repeated sequence.
    sequence_start: Option<Address>,
    /// Region where the repeat limit is ignored.
    ignored_region: Option<AddressSet>,
}

impl RepeatPatternTracker {
    /// Create a new tracker with the given limit.
    pub fn new(limit: usize) -> Self {
        Self {
            limit,
            current_pattern: Vec::new(),
            current_count: 0,
            sequence_start: None,
            ignored_region: None,
        }
    }

    /// Set the repeat pattern limit. Use `usize::MAX` to disable.
    pub fn set_limit(&mut self, limit: usize) {
        self.limit = limit;
    }

    /// Get the current limit.
    pub fn limit(&self) -> usize {
        self.limit
    }

    /// Set a region where the repeat limit is ignored.
    ///
    /// This is used to allow explicitly disassembled areas to be free
    /// of false-positive repeat-pattern bookmarks.
    pub fn set_ignored_region(&mut self, region: AddressSet) {
        self.ignored_region = Some(region);
    }

    /// Clear the ignored region.
    pub fn clear_ignored_region(&mut self) {
        self.ignored_region = None;
    }

    /// Feed an instruction's bytes into the tracker.
    ///
    /// Returns `true` if the repeat limit has been exceeded.
    pub fn feed_instruction(&mut self, bytes: &[u8], addr: Address) -> bool {
        // Check if this address is in the ignored region
        if let Some(ref ignored) = self.ignored_region {
            if ignored.contains(&addr) {
                return false;
            }
        }

        if bytes == self.current_pattern.as_slice() {
            self.current_count += 1;
        } else {
            self.current_pattern = bytes.to_vec();
            self.current_count = 1;
            self.sequence_start = Some(addr);
        }

        self.current_count > self.limit
    }

    /// Check if the repeat limit is currently exceeded.
    pub fn is_limit_exceeded(&self) -> bool {
        self.current_count > self.limit
    }

    /// Get the number of consecutive identical instructions seen so far.
    pub fn current_count(&self) -> usize {
        self.current_count
    }

    /// Get the start address of the current repeated sequence.
    pub fn sequence_start(&self) -> Option<Address> {
        self.sequence_start
    }

    /// Get the current repeated byte pattern.
    pub fn current_pattern(&self) -> &[u8] {
        &self.current_pattern
    }

    /// Reset the tracker state.
    pub fn reset(&mut self) {
        self.current_pattern.clear();
        self.current_count = 0;
        self.sequence_start = None;
    }
}

impl Default for RepeatPatternTracker {
    fn default() -> Self {
        Self::new(MAX_REPEAT_PATTERN_LENGTH)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tracker_creation() {
        let tracker = RepeatPatternTracker::new(16);
        assert_eq!(tracker.limit(), 16);
        assert_eq!(tracker.current_count(), 0);
        assert!(!tracker.is_limit_exceeded());
    }

    #[test]
    fn test_tracker_detects_repeated_pattern() {
        let mut tracker = RepeatPatternTracker::new(3);
        let pattern = &[0x90u8, 0x90, 0x90, 0x90];

        assert!(!tracker.feed_instruction(pattern, Address::new(0x1000)));
        assert!(!tracker.feed_instruction(pattern, Address::new(0x1004)));
        assert!(!tracker.feed_instruction(pattern, Address::new(0x1008)));
        assert!(tracker.feed_instruction(pattern, Address::new(0x100C))); // 4th exceeds limit of 3

        assert!(tracker.is_limit_exceeded());
        assert_eq!(tracker.current_count(), 4);
        assert_eq!(tracker.sequence_start(), Some(Address::new(0x1000)));
    }

    #[test]
    fn test_tracker_resets_on_new_pattern() {
        let mut tracker = RepeatPatternTracker::new(3);

        tracker.feed_instruction(&[0x90, 0x90], Address::new(0x1000));
        tracker.feed_instruction(&[0x90, 0x90], Address::new(0x1004));
        assert_eq!(tracker.current_count(), 2);

        // Different pattern resets the count
        tracker.feed_instruction(&[0xCC, 0xCC], Address::new(0x1008));
        assert_eq!(tracker.current_count(), 1);
        assert!(!tracker.is_limit_exceeded());
    }

    #[test]
    fn test_tracker_ignored_region() {
        let mut tracker = RepeatPatternTracker::new(2);
        let mut ignored = AddressSet::new();
        ignored.add_range(AddressRange::new(Address::new(0x1000), Address::new(0x2000)));
        tracker.set_ignored_region(ignored);

        let pattern = &[0x90u8, 0x90];
        // These are in the ignored region, should never trigger
        assert!(!tracker.feed_instruction(pattern, Address::new(0x1000)));
        assert!(!tracker.feed_instruction(pattern, Address::new(0x1004)));
        assert!(!tracker.feed_instruction(pattern, Address::new(0x1008)));
        assert!(!tracker.is_limit_exceeded());
    }

    #[test]
    fn test_tracker_reset() {
        let mut tracker = RepeatPatternTracker::new(3);
        let pattern = &[0x90u8, 0x90];
        tracker.feed_instruction(pattern, Address::new(0x1000));
        tracker.feed_instruction(pattern, Address::new(0x1004));
        assert_eq!(tracker.current_count(), 2);

        tracker.reset();
        assert_eq!(tracker.current_count(), 0);
        assert!(tracker.current_pattern().is_empty());
        assert!(!tracker.is_limit_exceeded());
    }

    #[test]
    fn test_tracker_default() {
        let tracker = RepeatPatternTracker::default();
        assert_eq!(tracker.limit(), MAX_REPEAT_PATTERN_LENGTH);
    }

    #[test]
    fn test_tracker_disable() {
        let mut tracker = RepeatPatternTracker::new(2);
        tracker.set_limit(usize::MAX);

        let pattern = &[0x90u8];
        for i in 0..100 {
            tracker.feed_instruction(pattern, Address::new(0x1000 + i));
        }
        assert!(!tracker.is_limit_exceeded());
    }
}
