//! SkipStep - a step that skips N ticks on a thread without executing.
//!
//! Ported from Ghidra's `SkipStep` class.

use serde::{Deserialize, Serialize};

use super::compare_result::CompareResult;
use super::tick_step::StepType;
use super::trace_schedule_full::TimeRadix;

/// A step that skips N ticks without executing.
///
/// Ported from Ghidra's `SkipStep`. Like `TickStep`, but the
/// stepping action is a skip rather than a tick.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SkipStep {
    /// The key of the thread in the trace, or -1 for the "last thread".
    pub thread_key: i64,
    /// The number of ticks to skip.
    pub tick_count: u64,
}

impl SkipStep {
    /// Create a new skip step for the given thread.
    pub fn new(thread_key: i64, tick_count: u64) -> Self {
        Self { thread_key, tick_count }
    }

    /// Create a skip step for the "last thread".
    pub fn last_thread(tick_count: u64) -> Self {
        Self::new(-1, tick_count)
    }

    /// Parse a skip step from a string specification.
    pub fn parse(thread_key: i64, spec: &str, radix: &TimeRadix) -> Result<Self, String> {
        if !spec.starts_with('s') {
            return Err(format!("Cannot parse skip step: '{}'", spec));
        }
        let count = radix.decode(&spec[1..])
            .map_err(|_| format!("Cannot parse skip step: '{}'", spec))?;
        Ok(Self::new(thread_key, count as u64))
    }

    /// The step type.
    pub fn step_type(&self) -> StepType {
        StepType::Skip
    }

    /// Whether this is a no-op.
    pub fn is_nop(&self) -> bool {
        self.tick_count == 0
    }

    /// Get the thread key.
    pub fn thread_key(&self) -> i64 {
        self.thread_key
    }

    /// Whether this step applies to the event thread.
    pub fn is_event_thread(&self) -> bool {
        self.thread_key == -1
    }

    /// Get the tick count.
    pub fn tick_count(&self) -> u64 {
        self.tick_count
    }

    /// Get the skip count.
    pub fn skip_count(&self) -> u64 {
        self.tick_count
    }

    /// Get the patch count (always 0 for skip steps).
    pub fn patch_count(&self) -> u64 {
        0
    }

    /// Check if the given step can be combined with this one.
    pub fn is_compatible(&self, other: &SkipStep) -> bool {
        self.thread_key == other.thread_key || other.thread_key == -1
    }

    /// Add the count from another compatible step.
    pub fn add_to(&mut self, other: &SkipStep) {
        debug_assert!(self.is_compatible(other));
        self.tick_count = self.tick_count.checked_add(other.tick_count)
            .expect("Total step count exceeds u64::MAX");
    }

    /// Compute this minus another compatible step.
    pub fn subtract(&self, other: &SkipStep) -> Self {
        debug_assert!(self.is_compatible(other));
        Self::new(self.thread_key, self.tick_count - other.tick_count)
    }

    /// Rewind by the given count.
    ///
    /// Returns -diff: negative if still has remaining, 0 if consumed, positive if over-consumed.
    pub fn rewind(&mut self, count: u64) -> i64 {
        let diff = self.tick_count as i64 - count as i64;
        self.tick_count = std::cmp::max(0, diff) as u64;
        -diff
    }

    /// Format the step with optional thread prefix.
    pub fn to_string_with_radix(&self, radix: &TimeRadix) -> String {
        let step_part = format!("s{}", radix.format(self.tick_count as i64));
        if self.thread_key == -1 {
            step_part
        } else {
            format!("t{}-{}", self.thread_key, step_part)
        }
    }

    /// Richly compare this skip step to another.
    pub fn compare_step(&self, other: &SkipStep) -> CompareResult {
        let type_cmp = self.step_type().cmp(&other.step_type());
        if type_cmp != std::cmp::Ordering::Equal {
            return CompareResult::unrelated(type_cmp);
        }
        let thread_cmp = self.thread_key.cmp(&other.thread_key);
        if thread_cmp != std::cmp::Ordering::Equal {
            return CompareResult::unrelated(thread_cmp);
        }
        CompareResult::related(self.tick_count.cmp(&other.tick_count))
    }
}

impl std::fmt::Display for SkipStep {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_string_with_radix(&TimeRadix::default()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_skip_step_new() {
        let step = SkipStep::new(1, 5);
        assert_eq!(step.thread_key, 1);
        assert_eq!(step.tick_count, 5);
        assert_eq!(step.skip_count(), 5);
    }

    #[test]
    fn test_skip_step_last_thread() {
        let step = SkipStep::last_thread(10);
        assert!(step.is_event_thread());
        assert_eq!(step.skip_count(), 10);
    }

    #[test]
    fn test_skip_step_nop() {
        let step = SkipStep::new(1, 0);
        assert!(step.is_nop());
    }

    #[test]
    fn test_skip_step_compatible() {
        let a = SkipStep::new(1, 5);
        let b = SkipStep::new(1, 3);
        let c = SkipStep::last_thread(3);
        let d = SkipStep::new(2, 3);
        assert!(a.is_compatible(&b));
        assert!(a.is_compatible(&c));
        assert!(!a.is_compatible(&d));
    }

    #[test]
    fn test_skip_step_advance() {
        let mut a = SkipStep::new(1, 5);
        let b = SkipStep::new(1, 3);
        a.add_to(&b);
        assert_eq!(a.tick_count, 8);
    }

    #[test]
    fn test_skip_step_subtract() {
        let a = SkipStep::new(1, 10);
        let b = SkipStep::new(1, 3);
        let result = a.subtract(&b);
        assert_eq!(result.tick_count, 7);
    }

    #[test]
    fn test_skip_step_rewind() {
        // Returns -diff: negative means step still has remaining ticks
        let mut step = SkipStep::new(1, 10);
        let result = step.rewind(3);
        assert_eq!(result, -7); // step has 7 remaining
        assert_eq!(step.tick_count, 7);
    }

    #[test]
    fn test_skip_step_display() {
        let step = SkipStep::new(1, 5);
        assert_eq!(step.to_string(), "t1-s5");

        let step = SkipStep::last_thread(10);
        assert_eq!(step.to_string(), "s10");
    }

    #[test]
    fn test_skip_step_parse() {
        let radix = TimeRadix::dec();
        let step = SkipStep::parse(1, "s5", &radix).unwrap();
        assert_eq!(step.thread_key, 1);
        assert_eq!(step.tick_count, 5);

        assert!(SkipStep::parse(1, "5", &radix).is_err());
    }

    #[test]
    fn test_skip_step_compare() {
        let a = SkipStep::new(1, 5);
        let b = SkipStep::new(1, 10);
        assert_eq!(a.compare_step(&b), CompareResult::REL_LT);
        assert_eq!(b.compare_step(&a), CompareResult::REL_GT);
    }
}
