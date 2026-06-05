//! Sequence - an ordered list of steps with normalization and comparison.
//!
//! Ported from Ghidra's `Sequence` class.

use serde::{Deserialize, Serialize};
use std::cmp::Ordering;

use super::compare_result::CompareResult;
use super::patch_step::PatchStep;
use super::skip_step::SkipStep;
use super::tick_step::TickStep;
use super::trace_schedule_full::TimeRadix;

/// An enum representing any kind of step.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StepEnum {
    /// A tick step (advance N ticks).
    Tick(TickStep),
    /// A skip step (skip N ticks without executing).
    Skip(SkipStep),
    /// A patch step (apply a Sleigh patch).
    Patch(PatchStep),
}

impl StepEnum {
    /// Whether this is a no-op.
    pub fn is_nop(&self) -> bool {
        match self {
            Self::Tick(s) => s.is_nop(),
            Self::Skip(s) => s.is_nop(),
            Self::Patch(s) => s.is_nop(),
        }
    }

    /// Get the thread key.
    pub fn thread_key(&self) -> i64 {
        match self {
            Self::Tick(s) => s.thread_key(),
            Self::Skip(s) => s.thread_key(),
            Self::Patch(s) => s.thread_key(),
        }
    }

    /// Get the tick count.
    pub fn tick_count(&self) -> u64 {
        match self {
            Self::Tick(s) => s.tick_count(),
            Self::Skip(s) => 0,
            Self::Patch(s) => 0,
        }
    }

    /// Get the skip count.
    pub fn skip_count(&self) -> u64 {
        match self {
            Self::Tick(s) => 0,
            Self::Skip(s) => s.skip_count(),
            Self::Patch(s) => 0,
        }
    }

    /// Get the patch count.
    pub fn patch_count(&self) -> u64 {
        match self {
            Self::Tick(s) => 0,
            Self::Skip(s) => 0,
            Self::Patch(s) => 1,
        }
    }

    /// Format with the given radix.
    pub fn to_string_with_radix(&self, radix: &TimeRadix) -> String {
        match self {
            Self::Tick(s) => s.to_string_with_radix(radix),
            Self::Skip(s) => s.to_string_with_radix(radix),
            Self::Patch(s) => s.to_string_with_radix(radix),
        }
    }

    /// Parse a step from a string.
    pub fn parse(spec: &str, radix: &TimeRadix) -> Result<Self, String> {
        if spec.is_empty() {
            return Ok(Self::Tick(TickStep::new(-1, 0)));
        }
        let parts: Vec<&str> = spec.splitn(2, '-').collect();
        if parts.len() == 1 {
            return Self::parse_for_thread(-1, parts[0].trim(), radix);
        }
        if parts.len() == 2 {
            let t_part = parts[0].trim();
            if let Some(t_key) = t_part.strip_prefix('t') {
                let thread_key: i64 = t_key.parse()
                    .map_err(|_| format!("Cannot parse step: '{}'", spec))?;
                return Self::parse_for_thread(thread_key, parts[1].trim(), radix);
            }
        }
        Err(format!("Cannot parse step: '{}'", spec))
    }

    fn parse_for_thread(thread_key: i64, spec: &str, radix: &TimeRadix) -> Result<Self, String> {
        if spec.starts_with('s') {
            return Ok(Self::Skip(SkipStep::parse(thread_key, spec, radix)?));
        }
        if spec.starts_with('{') {
            return Ok(Self::Patch(PatchStep::parse(thread_key, spec)?));
        }
        Ok(Self::Tick(TickStep::parse(thread_key, spec, radix)?))
    }

    /// Check if this step is compatible with another (same type, combinable thread).
    pub fn is_compatible(&self, other: &StepEnum) -> bool {
        match (self, other) {
            (Self::Tick(a), Self::Tick(b)) => a.is_compatible(b),
            (Self::Skip(a), Self::Skip(b)) => a.is_compatible(b),
            (Self::Patch(_), Self::Patch(_)) => false, // Never combine patches
            _ => false,
        }
    }

    /// Add to this step from another compatible step.
    pub fn add_to(&mut self, other: &StepEnum) {
        debug_assert!(self.is_compatible(other));
        match (self, other) {
            (Self::Tick(a), Self::Tick(b)) => a.add_to(b),
            (Self::Skip(a), Self::Skip(b)) => a.add_to(b),
            _ => unreachable!(),
        }
    }

    /// Subtract another step from this one (they must be compatible).
    pub fn subtract(&self, other: &StepEnum) -> StepEnum {
        debug_assert!(self.is_compatible(other));
        match (self, other) {
            (Self::Tick(a), Self::Tick(b)) => Self::Tick(a.subtract(b)),
            (Self::Skip(a), Self::Skip(b)) => Self::Skip(a.subtract(b)),
            _ => unreachable!(),
        }
    }

    /// Rewind this step by the given count. Returns remaining excess.
    pub fn rewind(&mut self, count: u64) -> i64 {
        match self {
            Self::Tick(s) => s.rewind(count),
            Self::Skip(s) => s.rewind(count),
            Self::Patch(s) => s.rewind(count),
        }
    }

    /// Richly compare this step to another.
    pub fn compare_step(&self, other: &StepEnum) -> CompareResult {
        let type_ord = self.type_order().cmp(&other.type_order());
        if type_ord != Ordering::Equal {
            return CompareResult::unrelated(type_ord);
        }
        match (self, other) {
            (Self::Tick(a), Self::Tick(b)) => a.compare_step(b),
            (Self::Skip(a), Self::Skip(b)) => a.compare_step(b),
            (Self::Patch(a), Self::Patch(b)) => a.compare_step(b),
            _ => unreachable!(),
        }
    }

    fn type_order(&self) -> u8 {
        match self {
            Self::Tick(_) => 0,
            Self::Skip(_) => 1,
            Self::Patch(_) => 2,
        }
    }
}

impl std::fmt::Display for StepEnum {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_string_with_radix(&TimeRadix::default()))
    }
}

/// A sequence of thread steps, each repeated some number of times.
///
/// Ported from Ghidra's `Sequence`. Normalized as steps are appended,
/// combining compatible steps.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Sequence {
    steps: Vec<StepEnum>,
}

impl Sequence {
    /// An empty sequence (no-op).
    pub const EMPTY: Self = Self { steps: Vec::new() };

    /// Create an empty sequence.
    pub fn empty() -> Self {
        Self { steps: Vec::new() }
    }

    /// Create a sequence from a list of steps.
    pub fn from_steps(steps: Vec<StepEnum>) -> Self {
        let mut seq = Self::empty();
        for step in steps {
            seq.advance_step(step);
        }
        seq
    }

    /// Parse a sequence from a semicolon-separated string.
    pub fn parse(spec: &str, radix: TimeRadix) -> Result<Self, String> {
        let mut seq = Self::empty();
        for step_spec in spec.split(';') {
            let step = StepEnum::parse(step_spec, &radix)?;
            seq.advance_step(step);
        }
        Ok(seq)
    }

    /// Check if this sequence represents any actions.
    pub fn is_nop(&self) -> bool {
        self.steps.is_empty()
    }

    /// Get the steps (as references).
    pub fn steps(&self) -> &[StepEnum] {
        &self.steps
    }

    /// Get the number of steps.
    pub fn count(&self) -> usize {
        self.steps.len()
    }

    /// Append a step to this sequence.
    ///
    /// Compatible steps are combined. Nop steps are ignored.
    pub fn advance_step(&mut self, step: StepEnum) {
        if step.is_nop() {
            return;
        }
        if let Some(last) = self.steps.last_mut() {
            if last.is_compatible(&step) {
                last.add_to(&step);
                return;
            }
        }
        self.steps.push(step);
    }

    /// Append another sequence to this one.
    pub fn advance_seq(&mut self, other: &Sequence) {
        let cloned: Vec<StepEnum> = other.steps.iter().cloned().collect();
        if cloned.is_empty() {
            return;
        }
        self.advance_step(cloned[0].clone());
        if cloned.len() >= 2 {
            self.advance_step(cloned[1].clone());
            self.steps.extend_from_slice(&cloned[2..]);
        }
    }

    /// Rewind this sequence by the given step count.
    ///
    /// Returns the remaining excess if count exceeds total steps.
    pub fn rewind(&mut self, count: u64) -> u64 {
        if count == 0 {
            return 0;
        }
        let mut remaining = count as i64;
        while !self.steps.is_empty() {
            let last_idx = self.steps.len() - 1;
            let diff = self.steps[last_idx].rewind(remaining as u64);
            if diff >= 0 {
                self.steps.pop();
            }
            remaining = diff;
            if remaining <= 0 {
                break;
            }
        }
        std::cmp::max(0, remaining) as u64
    }

    /// Drop the last step from this sequence.
    pub fn drop_last(&self) -> Result<Self, String> {
        if self.steps.is_empty() {
            return Err("Cannot drop from empty sequence".to_string());
        }
        Ok(Self {
            steps: self.steps[..self.steps.len() - 1].to_vec(),
        })
    }

    /// Get the last step.
    pub fn last(&self) -> Option<&StepEnum> {
        self.steps.last()
    }

    /// Truncate to the first `count` steps.
    pub fn truncate(&self, count: usize) -> Self {
        Self {
            steps: self.steps[..std::cmp::min(count, self.steps.len())].to_vec(),
        }
    }

    /// Get a clone of the steps.
    pub fn get_steps(&self) -> Vec<StepEnum> {
        self.steps.clone()
    }

    /// Compute the total tick count.
    pub fn total_tick_count(&self) -> u64 {
        self.steps.iter().map(|s| s.tick_count()).sum()
    }

    /// Compute the total skip count.
    pub fn total_skip_count(&self) -> u64 {
        self.steps.iter().map(|s| s.skip_count()).sum()
    }

    /// Compute the total patch count.
    pub fn total_patch_count(&self) -> u64 {
        self.steps.iter().map(|s| s.patch_count()).sum()
    }

    /// Get the key of the last thread stepped.
    pub fn last_thread_key(&self) -> i64 {
        self.steps.last().map(|s| s.thread_key()).unwrap_or(-1)
    }

    /// Check if the first instruction step is actually to finish an incomplete instruction.
    pub fn check_finish(&self, _has_incomplete_instruction: bool) -> Self {
        // In the real implementation, this would check the pcode machine
        // for an incomplete instruction and finish it.
        self.clone()
    }

    /// Richly compare two sequences.
    ///
    /// The result indicates not only which is "less" or "greater" but also
    /// whether they are "related" (one is a prefix of the other).
    pub fn compare_seq(&self, that: &Sequence) -> CompareResult {
        let min = std::cmp::min(self.steps.len(), that.steps.len());
        for i in 0..min {
            let result = self.steps[i].compare_step(&that.steps[i]);
            match result {
                CompareResult::UNREL_LT | CompareResult::UNREL_GT => return result,
                CompareResult::REL_LT => {
                    return if i + 1 == self.steps.len() {
                        CompareResult::REL_LT
                    } else {
                        CompareResult::UNREL_LT
                    };
                }
                CompareResult::REL_GT => {
                    return if i + 1 == that.steps.len() {
                        CompareResult::REL_GT
                    } else {
                        CompareResult::UNREL_GT
                    };
                }
                _ => {} // EQUALS, check next step
            }
        }
        if that.steps.len() > min {
            return CompareResult::REL_LT;
        }
        if self.steps.len() > min {
            return CompareResult::REL_GT;
        }
        CompareResult::EQUALS
    }

    /// Compute the relative sequence from a prefix to this.
    ///
    /// Returns the sequence that, when appended to `prefix`, yields `self`.
    pub fn relativize(&self, prefix: &Sequence) -> Result<Self, String> {
        if prefix.is_nop() {
            return Ok(self.clone());
        }
        let comp = self.compare_seq(prefix);
        if comp == CompareResult::EQUALS {
            return Ok(Self::empty());
        }
        if comp != CompareResult::REL_GT {
            return Err(format!(
                "The given prefix ({}) is not actually a prefix of this ({}).",
                prefix, self
            ));
        }

        let last_step_index = prefix.steps.len() - 1;
        let continuation = &self.steps[last_step_index];
        let ancestor_last = &prefix.steps[last_step_index];
        let mut result = Self::empty();
        result.advance_step(continuation.subtract(ancestor_last));
        result.steps.extend_from_slice(&self.steps[prefix.steps.len()..]);
        Ok(result)
    }

    /// Check if two sequences differ only by patch steps.
    pub fn differs_only_by_patch(&self, that: &Sequence) -> bool {
        let size = self.steps.len();
        if size == that.steps.len() {
            if size == 0 {
                return true;
            }
            if self.steps[..size - 1] != that.steps[..size - 1] {
                return false;
            }
            let this_last = &self.steps[size - 1];
            let that_last = &that.steps[size - 1];
            return this_last == that_last ||
                (matches!(this_last, StepEnum::Patch(_)) && matches!(that_last, StepEnum::Patch(_)));
        }
        if size == that.steps.len() - 1 {
            return matches!(that.steps.last(), Some(StepEnum::Patch(_)));
        }
        false
    }

    /// Format with the given radix.
    pub fn to_string_with_radix(&self, radix: &TimeRadix) -> String {
        self.steps
            .iter()
            .map(|s| s.to_string_with_radix(radix))
            .collect::<Vec<_>>()
            .join(";")
    }
}

impl PartialOrd for Sequence {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.compare_seq(other).compare_to())
    }
}

impl Ord for Sequence {
    fn cmp(&self, other: &Self) -> Ordering {
        self.compare_seq(other).compare_to()
    }
}

impl std::fmt::Display for Sequence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_string_with_radix(&TimeRadix::default()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sequence_empty() {
        let seq = Sequence::empty();
        assert!(seq.is_nop());
        assert_eq!(seq.count(), 0);
        assert_eq!(seq.to_string(), "");
    }

    #[test]
    fn test_sequence_advance_step() {
        let mut seq = Sequence::empty();
        seq.advance_step(StepEnum::Tick(TickStep::new(-1, 5)));
        assert_eq!(seq.count(), 1);
        assert_eq!(seq.total_tick_count(), 5);
    }

    #[test]
    fn test_sequence_combine_compatible() {
        let mut seq = Sequence::empty();
        seq.advance_step(StepEnum::Tick(TickStep::new(1, 5)));
        seq.advance_step(StepEnum::Tick(TickStep::new(1, 3)));
        assert_eq!(seq.count(), 1); // Combined
        assert_eq!(seq.total_tick_count(), 8);
    }

    #[test]
    fn test_sequence_no_combine_different_thread() {
        let mut seq = Sequence::empty();
        seq.advance_step(StepEnum::Tick(TickStep::new(1, 5)));
        seq.advance_step(StepEnum::Tick(TickStep::new(2, 3)));
        assert_eq!(seq.count(), 2); // Not combined
    }

    #[test]
    fn test_sequence_parse() {
        let seq = Sequence::parse("5;t1-3", TimeRadix::dec()).unwrap();
        assert_eq!(seq.count(), 2);
        assert_eq!(seq.total_tick_count(), 8);
    }

    #[test]
    fn test_sequence_display() {
        let mut seq = Sequence::empty();
        seq.advance_step(StepEnum::Tick(TickStep::last_thread(5)));
        seq.advance_step(StepEnum::Tick(TickStep::new(1, 3)));
        assert_eq!(seq.to_string(), "5;t1-3");
    }

    #[test]
    fn test_sequence_rewind() {
        let mut seq = Sequence::empty();
        seq.advance_step(StepEnum::Tick(TickStep::last_thread(10)));
        let remaining = seq.rewind(3);
        assert_eq!(remaining, 0);
        assert_eq!(seq.total_tick_count(), 7);
    }

    #[test]
    fn test_sequence_rewind_exceed() {
        let mut seq = Sequence::empty();
        seq.advance_step(StepEnum::Tick(TickStep::last_thread(5)));
        let remaining = seq.rewind(10);
        assert_eq!(remaining, 5);
        assert!(seq.is_nop());
    }

    #[test]
    fn test_sequence_drop_last() {
        let mut seq = Sequence::empty();
        seq.advance_step(StepEnum::Tick(TickStep::new(1, 5)));
        seq.advance_step(StepEnum::Tick(TickStep::new(2, 3)));
        let seq2 = seq.drop_last().unwrap();
        assert_eq!(seq2.count(), 1);
        assert_eq!(seq2.total_tick_count(), 5);
    }

    #[test]
    fn test_sequence_truncate() {
        let mut seq = Sequence::empty();
        seq.advance_step(StepEnum::Tick(TickStep::new(1, 5)));
        seq.advance_step(StepEnum::Tick(TickStep::new(2, 3)));
        seq.advance_step(StepEnum::Tick(TickStep::new(3, 1)));
        let truncated = seq.truncate(2);
        assert_eq!(truncated.count(), 2);
    }

    #[test]
    fn test_sequence_compare_equal() {
        let a = Sequence::parse("5", TimeRadix::dec()).unwrap();
        let b = Sequence::parse("5", TimeRadix::dec()).unwrap();
        assert_eq!(a.compare_seq(&b), CompareResult::EQUALS);
    }

    #[test]
    fn test_sequence_compare_prefix() {
        let a = Sequence::parse("5", TimeRadix::dec()).unwrap();
        let b = Sequence::parse("5;t1-3", TimeRadix::dec()).unwrap();
        assert_eq!(a.compare_seq(&b), CompareResult::REL_LT);
        assert_eq!(b.compare_seq(&a), CompareResult::REL_GT);
    }

    #[test]
    fn test_sequence_compare_unrelated() {
        let a = Sequence::parse("5", TimeRadix::dec()).unwrap();
        let b = Sequence::parse("3;t1-5", TimeRadix::dec()).unwrap();
        let cmp = a.compare_seq(&b);
        assert!(!cmp.related);
    }

    #[test]
    fn test_sequence_relativize() {
        let prefix = Sequence::parse("5", TimeRadix::dec()).unwrap();
        let full = Sequence::parse("5;t1-3", TimeRadix::dec()).unwrap();
        let relative = full.relativize(&prefix).unwrap();
        assert_eq!(relative.total_tick_count(), 3);
    }

    #[test]
    fn test_sequence_relativize_equal() {
        let a = Sequence::parse("5", TimeRadix::dec()).unwrap();
        let relative = a.relativize(&a).unwrap();
        assert!(relative.is_nop());
    }

    #[test]
    fn test_sequence_advance_seq() {
        let a = Sequence::parse("5", TimeRadix::dec()).unwrap();
        let b = Sequence::parse("3", TimeRadix::dec()).unwrap();
        let mut result = Sequence::empty();
        result.advance_seq(&a);
        result.advance_seq(&b);
        assert_eq!(result.total_tick_count(), 8);
    }

    #[test]
    fn test_sequence_ordering() {
        let a = Sequence::parse("3", TimeRadix::dec()).unwrap();
        let b = Sequence::parse("5", TimeRadix::dec()).unwrap();
        assert!(a < b);
    }

    #[test]
    fn test_sequence_differs_only_by_patch() {
        let a = Sequence::parse("5", TimeRadix::dec()).unwrap();
        let b = Sequence::parse("5", TimeRadix::dec()).unwrap();
        assert!(a.differs_only_by_patch(&b));
    }

    #[test]
    fn test_sequence_empty_display() {
        let seq = Sequence::empty();
        assert_eq!(seq.to_string(), "");
    }

    #[test]
    fn test_step_enum_parse_empty() {
        let step = StepEnum::parse("", &TimeRadix::dec()).unwrap();
        assert!(step.is_nop());
    }

    #[test]
    fn test_step_enum_parse_with_thread() {
        let step = StepEnum::parse("t1-10", &TimeRadix::dec()).unwrap();
        assert_eq!(step.thread_key(), 1);
        assert_eq!(step.tick_count(), 10);
    }
}
