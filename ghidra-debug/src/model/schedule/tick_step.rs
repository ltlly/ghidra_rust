//! TickStep - a step that advances a thread by N ticks.
//!
//! Ported from Ghidra's `TickStep` class.

use serde::{Deserialize, Serialize};

use super::compare_result::CompareResult;
use super::trace_schedule_full::TimeRadix;

/// The type of a step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum StepType {
    /// Execute one instruction.
    Tick,
    /// Skip one instruction.
    Skip,
    /// Apply a patch (sleigh modification).
    Patch,
}

/// A step of a given thread in a schedule: repeating some number of ticks.
///
/// Ported from Ghidra's `TickStep`. Represents advancing a thread by
/// a specified count of instruction ticks (or pcode ticks, depending on context).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TickStep {
    /// The key of the thread in the trace, or -1 for the "last thread".
    pub thread_key: i64,
    /// The number of ticks to advance.
    pub tick_count: u64,
}

impl TickStep {
    /// Create a new tick step for the given thread.
    pub fn new(thread_key: i64, tick_count: u64) -> Self {
        Self { thread_key, tick_count }
    }

    /// Create a tick step for the "last thread" (event thread).
    pub fn last_thread(tick_count: u64) -> Self {
        Self::new(-1, tick_count)
    }

    /// Parse a tick step from a string specification.
    pub fn parse(thread_key: i64, spec: &str, radix: &TimeRadix) -> Result<Self, String> {
        let count = radix.decode(spec)
            .map_err(|_| format!("Cannot parse tick step: '{}'", spec))?;
        Ok(Self::new(thread_key, count as u64))
    }

    /// The step type.
    pub fn step_type(&self) -> StepType {
        StepType::Tick
    }

    /// Whether this is a no-op.
    pub fn is_nop(&self) -> bool {
        self.tick_count == 0
    }

    /// Get the thread key. -1 means "last thread" or "event thread".
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

    /// Get the skip count (always 0 for tick steps).
    pub fn skip_count(&self) -> u64 {
        0
    }

    /// Get the patch count (always 0 for tick steps).
    pub fn patch_count(&self) -> u64 {
        0
    }

    /// Check if the given step can be combined with this one.
    ///
    /// Two steps applied to the same thread can just be summed.
    pub fn is_compatible(&self, other: &TickStep) -> bool {
        self.thread_key == other.thread_key || other.thread_key == -1
    }

    /// Add the count from another compatible step.
    pub fn advance(&mut self, count: u64) {
        self.tick_count = self.tick_count.checked_add(count)
            .expect("Total step count exceeds u64::MAX");
    }

    /// Add from another compatible step.
    pub fn add_to(&mut self, other: &TickStep) {
        debug_assert!(self.is_compatible(other));
        self.advance(other.tick_count);
    }

    /// Compute this minus another compatible step.
    pub fn subtract(&self, other: &TickStep) -> Self {
        debug_assert!(self.is_compatible(other));
        Self::new(self.thread_key, self.tick_count - other.tick_count)
    }

    /// Rewind by the given count.
    ///
    /// Returns -diff: negative if the step still has remaining ticks,
    /// 0 if exactly consumed, positive if over-consumed (excess to continue rewinding).
    pub fn rewind(&mut self, count: u64) -> i64 {
        let diff = self.tick_count as i64 - count as i64;
        self.tick_count = std::cmp::max(0, diff) as u64;
        -diff
    }

    /// Format the step part (without thread prefix).
    pub fn to_step_string(&self, radix: &TimeRadix) -> String {
        radix.format(self.tick_count as i64)
    }

    /// Format the step with optional thread prefix.
    pub fn to_string_with_radix(&self, radix: &TimeRadix) -> String {
        if self.thread_key == -1 {
            self.to_step_string(radix)
        } else {
            format!("t{}-{}", self.thread_key, self.to_step_string(radix))
        }
    }

    /// Richly compare this tick step to another.
    pub fn compare_step(&self, other: &TickStep) -> CompareResult {
        // Compare by type first (Tick is always type 0)
        let type_cmp = self.step_type().cmp(&other.step_type());
        if type_cmp != std::cmp::Ordering::Equal {
            return CompareResult::unrelated(type_cmp);
        }

        // Compare by thread key
        let thread_cmp = self.thread_key.cmp(&other.thread_key);
        if thread_cmp != std::cmp::Ordering::Equal {
            return CompareResult::unrelated(thread_cmp);
        }

        // Compare by tick count
        CompareResult::related(self.tick_count.cmp(&other.tick_count))
    }
}

impl std::fmt::Display for TickStep {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_string_with_radix(&TimeRadix::default()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tick_step_new() {
        let step = TickStep::new(1, 10);
        assert_eq!(step.thread_key, 1);
        assert_eq!(step.tick_count, 10);
        assert!(!step.is_nop());
    }

    #[test]
    fn test_tick_step_last_thread() {
        let step = TickStep::last_thread(5);
        assert_eq!(step.thread_key, -1);
        assert!(step.is_event_thread());
    }

    #[test]
    fn test_tick_step_nop() {
        let step = TickStep::new(1, 0);
        assert!(step.is_nop());
    }

    #[test]
    fn test_tick_step_compatible() {
        let a = TickStep::new(1, 5);
        let b = TickStep::new(1, 3);
        let c = TickStep::last_thread(3);
        let d = TickStep::new(2, 3);
        assert!(a.is_compatible(&b));
        assert!(a.is_compatible(&c)); // c has thread_key -1
        assert!(!a.is_compatible(&d));
    }

    #[test]
    fn test_tick_step_advance() {
        let mut step = TickStep::new(1, 5);
        step.advance(3);
        assert_eq!(step.tick_count, 8);
    }

    #[test]
    fn test_tick_step_add_to() {
        let mut a = TickStep::new(1, 5);
        let b = TickStep::new(1, 3);
        a.add_to(&b);
        assert_eq!(a.tick_count, 8);
    }

    #[test]
    fn test_tick_step_subtract() {
        let a = TickStep::new(1, 10);
        let b = TickStep::new(1, 3);
        let result = a.subtract(&b);
        assert_eq!(result.tick_count, 7);
    }

    #[test]
    fn test_tick_step_rewind() {
        // Returns -diff: negative means step still has remaining ticks
        let mut step = TickStep::new(1, 10);
        let result = step.rewind(3);
        assert_eq!(result, -7); // step has 7 remaining
        assert_eq!(step.tick_count, 7);

        // Returns -diff: positive means over-consumed, excess to continue rewinding
        let mut step2 = TickStep::new(1, 5);
        let result2 = step2.rewind(10);
        assert_eq!(result2, 5); // 5 excess to continue rewinding
        assert_eq!(step2.tick_count, 0);
    }

    #[test]
    fn test_tick_step_display() {
        let step = TickStep::new(1, 5);
        assert_eq!(step.to_string(), "t1-5");

        let step = TickStep::last_thread(10);
        assert_eq!(step.to_string(), "10");
    }

    #[test]
    fn test_tick_step_parse() {
        let radix = TimeRadix::dec();
        let step = TickStep::parse(1, "5", &radix).unwrap();
        assert_eq!(step.thread_key, 1);
        assert_eq!(step.tick_count, 5);

        let step = TickStep::parse(-1, "0xa", &radix).unwrap();
        assert_eq!(step.tick_count, 10);
    }

    #[test]
    fn test_tick_step_compare() {
        let a = TickStep::new(1, 5);
        let b = TickStep::new(1, 10);
        let c = TickStep::new(2, 5);

        assert_eq!(a.compare_step(&b), CompareResult::REL_LT);
        assert_eq!(b.compare_step(&a), CompareResult::REL_GT);
        assert_eq!(a.compare_step(&a), CompareResult::EQUALS);
        assert!(!a.compare_step(&c).related);
    }
}
