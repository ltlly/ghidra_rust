//! Step types for emulation scheduling.
//!
//! Ported from Ghidra's `ghidra.trace.model.time.schedule` package:
//! StepType, StepKind, TickStep, SkipStep, PatchStep, and the ScheduleStep
//! enum that unifies them.
//!
//! These types model individual actions in a schedule -- tick (advance),
//! skip (fast-forward), and patch (modify memory) -- with thread affinity
//! and comparison support.

use serde::{Deserialize, Serialize};
use std::fmt;

use super::time_schedule::CompareResult;

// ---------------------------------------------------------------------------
// StepKind – maps to the Java enum that implements Stepper
// ---------------------------------------------------------------------------

/// The kind of stepping performed (instruction-level or pcode-level).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StepKind {
    /// Execute one native instruction.
    Instruction,
    /// Execute one pcode operation.
    PcodeOp,
}

impl StepKind {
    /// Get the step kind name.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Instruction => "instruction",
            Self::PcodeOp => "pcode",
        }
    }
}

impl fmt::Display for StepKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

// ---------------------------------------------------------------------------
// StepType – discriminant for the ScheduleStep enum (Tick, Skip, Patch)
// ---------------------------------------------------------------------------

/// Discriminant for the three concrete step types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StepType {
    /// Execute ticks (instructions or pcode ops).
    Tick,
    /// Skip ticks without executing.
    Skip,
    /// Patch memory with a sequence of bytes.
    Patch,
}

impl fmt::Display for StepType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tick => write!(f, "tick"),
            Self::Skip => write!(f, "skip"),
            Self::Patch => write!(f, "patch"),
        }
    }
}

// ---------------------------------------------------------------------------
// TickStep – execute N instructions/pcode ops
// ---------------------------------------------------------------------------

/// A step that advances a thread by `tick_count` ticks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TickStep {
    /// The thread key in the trace (-1 for last thread).
    pub thread_key: i64,
    /// Number of ticks to advance.
    pub tick_count: i64,
}

impl TickStep {
    /// Create a new tick step.
    pub fn new(thread_key: i64, tick_count: i64) -> Self {
        assert!(tick_count >= 0, "Cannot step a negative number");
        Self {
            thread_key,
            tick_count,
        }
    }

    /// Parse from a schedule string fragment (just the number, no prefix).
    pub fn parse(thread_key: i64, step_spec: &str, radix: u32) -> Result<Self, String> {
        let count = i64::from_str_radix(step_spec, radix)
            .map_err(|_| format!("Cannot parse tick step: '{step_spec}'"))?;
        Ok(Self::new(thread_key, count))
    }

    /// Advance the tick count.
    pub fn advance(&mut self, steps: i64) {
        assert!(steps >= 0, "Cannot advance a negative number");
        self.tick_count += steps;
    }
}

impl fmt::Display for TickStep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.thread_key >= 0 {
            write!(f, "{}.{}", self.thread_key, self.tick_count)
        } else {
            write!(f, "{}", self.tick_count)
        }
    }
}

// ---------------------------------------------------------------------------
// SkipStep – skip N instructions without executing
// ---------------------------------------------------------------------------

/// A step that skips (fast-forwards) a thread by `tick_count` ticks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkipStep {
    /// The thread key in the trace (-1 for last thread).
    pub thread_key: i64,
    /// Number of ticks to skip.
    pub tick_count: i64,
}

impl SkipStep {
    /// Create a new skip step.
    pub fn new(thread_key: i64, tick_count: i64) -> Self {
        assert!(tick_count >= 0, "Cannot skip a negative number");
        Self {
            thread_key,
            tick_count,
        }
    }

    /// Parse from a schedule string fragment (must start with 's').
    pub fn parse(thread_key: i64, step_spec: &str, radix: u32) -> Result<Self, String> {
        if !step_spec.starts_with('s') {
            return Err(format!("Cannot parse skip step: '{step_spec}'"));
        }
        let count = i64::from_str_radix(&step_spec[1..], radix)
            .map_err(|_| format!("Cannot parse skip step: '{step_spec}'"))?;
        Ok(Self::new(thread_key, count))
    }
}

impl fmt::Display for SkipStep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.thread_key >= 0 {
            write!(f, "{}.s{}", self.thread_key, self.tick_count)
        } else {
            write!(f, "s{}", self.tick_count)
        }
    }
}

// ---------------------------------------------------------------------------
// PatchStep – apply N byte patches at a given address
// ---------------------------------------------------------------------------

/// A step that applies memory patches during emulation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchStep {
    /// The thread key in the trace (-1 for last thread).
    pub thread_key: i64,
    /// Number of patches to apply.
    pub patch_count: i64,
    /// The address at which patches begin.
    pub address: u64,
    /// The bytes to write.
    pub data: Vec<u8>,
}

impl PatchStep {
    /// Create a new patch step.
    pub fn new(thread_key: i64, patch_count: i64, address: u64, data: Vec<u8>) -> Self {
        Self {
            thread_key,
            patch_count,
            address,
            data,
        }
    }
}

impl fmt::Display for PatchStep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.thread_key >= 0 {
            write!(f, "{}.p{}", self.thread_key, self.patch_count)
        } else {
            write!(f, "p{}", self.patch_count)
        }
    }
}

// ---------------------------------------------------------------------------
// ScheduleStep – enum unifying all step types
// ---------------------------------------------------------------------------

/// A unified step enum that can represent any of the three step types.
///
/// This replaces the Java `Step` interface and `AbstractStep` class with a
/// Rust-idiomatic sum type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ScheduleStep {
    /// Execute N ticks.
    Tick(TickStep),
    /// Skip N ticks.
    Skip(SkipStep),
    /// Apply N patches.
    Patch(PatchStep),
}

impl ScheduleStep {
    /// The type discriminator.
    pub fn step_type(&self) -> StepType {
        match self {
            Self::Tick(_) => StepType::Tick,
            Self::Skip(_) => StepType::Skip,
            Self::Patch(_) => StepType::Patch,
        }
    }

    /// The thread key this step is bound to (-1 = last/any thread).
    pub fn thread_key(&self) -> i64 {
        match self {
            Self::Tick(s) => s.thread_key,
            Self::Skip(s) => s.thread_key,
            Self::Patch(s) => s.thread_key,
        }
    }

    /// The number of ticks (instructions or pcode ops) in this step.
    pub fn tick_count(&self) -> i64 {
        match self {
            Self::Tick(s) => s.tick_count,
            _ => 0,
        }
    }

    /// The number of patches in this step (0 for non-patch steps).
    pub fn patch_count(&self) -> i64 {
        match self {
            Self::Patch(s) => s.patch_count,
            _ => 0,
        }
    }

    /// The number of ticks to skip (0 for non-skip steps).
    pub fn skip_count(&self) -> i64 {
        match self {
            Self::Skip(s) => s.tick_count,
            _ => 0,
        }
    }

    /// Whether this step is a no-op (zero tick/patch count).
    pub fn is_nop(&self) -> bool {
        self.tick_count() == 0 && self.patch_count() == 0 && self.skip_count() == 0
    }

    /// Whether this step is compatible with another (same type, same or
    /// wildcard thread key).
    pub fn is_compatible(&self, other: &ScheduleStep) -> bool {
        if self.step_type() != other.step_type() {
            return false;
        }
        self.thread_key() == other.thread_key() || other.thread_key() == -1
    }

    /// Rich comparison: compare step types, then thread keys, then counts.
    pub fn compare_step(&self, other: &ScheduleStep) -> CompareResult {
        let type_cmp = (self.step_type() as u8).cmp(&(other.step_type() as u8));
        if type_cmp != std::cmp::Ordering::Equal {
            return CompareResult::from_ordering(type_cmp);
        }
        let tk_cmp = self.thread_key().cmp(&other.thread_key());
        if tk_cmp != std::cmp::Ordering::Equal {
            return CompareResult::from_ordering(tk_cmp);
        }
        CompareResult::from_ordering(self.tick_count().cmp(&other.tick_count()))
    }

    /// Add the counts of another compatible step into self.
    pub fn add_to(&mut self, other: &ScheduleStep) {
        match (self, other) {
            (ScheduleStep::Tick(a), ScheduleStep::Tick(b)) => a.tick_count += b.tick_count,
            (ScheduleStep::Skip(a), ScheduleStep::Skip(b)) => a.tick_count += b.tick_count,
            (ScheduleStep::Patch(a), ScheduleStep::Patch(b)) => a.patch_count += b.patch_count,
            _ => panic!("Cannot add incompatible step types"),
        }
    }

    /// Subtract another compatible step from self, returning the result.
    pub fn subtract(&self, other: &ScheduleStep) -> ScheduleStep {
        match (self, other) {
            (ScheduleStep::Tick(a), ScheduleStep::Tick(b)) => {
                ScheduleStep::Tick(TickStep::new(a.thread_key, a.tick_count - b.tick_count))
            }
            (ScheduleStep::Skip(a), ScheduleStep::Skip(b)) => {
                ScheduleStep::Skip(SkipStep::new(a.thread_key, a.tick_count - b.tick_count))
            }
            (ScheduleStep::Patch(a), ScheduleStep::Patch(b)) => ScheduleStep::Patch(PatchStep::new(
                a.thread_key,
                a.patch_count - b.patch_count,
                a.address,
                a.data.clone(),
            )),
            _ => panic!("Cannot subtract incompatible step types"),
        }
    }

    /// Format the step portion for a schedule string (without thread key).
    pub fn to_string_step(&self) -> String {
        match self {
            Self::Tick(s) => s.tick_count.to_string(),
            Self::Skip(s) => format!("s{}", s.tick_count),
            Self::Patch(s) => format!("p{}", s.patch_count),
        }
    }

    /// Coalesce patches in a list of steps; returns total patch count.
    pub fn coalesce_patches(steps: &[ScheduleStep]) -> i64 {
        steps.iter().map(|s| s.patch_count()).sum()
    }

    /// Create a new tick step.
    pub fn tick(thread_key: i64, tick_count: i64) -> Self {
        Self::Tick(TickStep::new(thread_key, tick_count))
    }

    /// Create a new skip step.
    pub fn skip(thread_key: i64, tick_count: i64) -> Self {
        Self::Skip(SkipStep::new(thread_key, tick_count))
    }

    /// Create a new patch step.
    pub fn patch(thread_key: i64, patch_count: i64, address: u64, data: Vec<u8>) -> Self {
        Self::Patch(PatchStep::new(thread_key, patch_count, address, data))
    }
}

impl fmt::Display for ScheduleStep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tick(s) => write!(f, "{}", s),
            Self::Skip(s) => write!(f, "{}", s),
            Self::Patch(s) => write!(f, "{}", s),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tick_step_basics() {
        let step = TickStep::new(1, 5);
        assert_eq!(step.thread_key, 1);
        assert_eq!(step.tick_count, 5);
        assert_eq!(step.to_string(), "1.5");
    }

    #[test]
    fn test_tick_step_wildcard() {
        let step = TickStep::new(-1, 3);
        assert_eq!(step.to_string(), "3");
    }

    #[test]
    fn test_skip_step_basics() {
        let step = SkipStep::new(2, 10);
        assert_eq!(step.thread_key, 2);
        assert_eq!(step.tick_count, 10);
        assert_eq!(step.to_string(), "2.s10");
    }

    #[test]
    fn test_patch_step_basics() {
        let step = PatchStep::new(-1, 2, 0x400000, vec![0x90, 0x90]);
        assert_eq!(step.patch_count, 2);
        assert_eq!(step.address, 0x400000);
        assert_eq!(step.to_string(), "p2");
    }

    #[test]
    fn test_schedule_step_tick() {
        let step = ScheduleStep::tick(1, 5);
        assert_eq!(step.step_type(), StepType::Tick);
        assert_eq!(step.thread_key(), 1);
        assert_eq!(step.tick_count(), 5);
        assert_eq!(step.skip_count(), 0);
        assert_eq!(step.patch_count(), 0);
        assert!(!step.is_nop());
    }

    #[test]
    fn test_schedule_step_skip() {
        let step = ScheduleStep::skip(2, 10);
        assert_eq!(step.step_type(), StepType::Skip);
        assert_eq!(step.skip_count(), 10);
        assert_eq!(step.tick_count(), 0);
    }

    #[test]
    fn test_schedule_step_patch() {
        let step = ScheduleStep::patch(-1, 2, 0x400000, vec![0x90]);
        assert_eq!(step.step_type(), StepType::Patch);
        assert_eq!(step.patch_count(), 2);
        assert_eq!(step.tick_count(), 0);
    }

    #[test]
    fn test_schedule_step_nop() {
        let step = ScheduleStep::tick(-1, 0);
        assert!(step.is_nop());
    }

    #[test]
    fn test_compatibility() {
        let a = ScheduleStep::tick(1, 5);
        let b = ScheduleStep::tick(1, 3);
        let c = ScheduleStep::tick(2, 3);
        let d = ScheduleStep::tick(-1, 3);

        assert!(a.is_compatible(&b));
        assert!(!a.is_compatible(&c));
        assert!(a.is_compatible(&d));
    }

    #[test]
    fn test_cross_type_incompatible() {
        let tick = ScheduleStep::tick(1, 5);
        let skip = ScheduleStep::skip(1, 5);
        assert!(!tick.is_compatible(&skip));
    }

    #[test]
    fn test_compare_step() {
        let a = ScheduleStep::tick(1, 5);
        let b = ScheduleStep::tick(1, 10);
        assert_eq!(a.compare_step(&b), CompareResult::REL_LT);
        assert_eq!(b.compare_step(&a), CompareResult::REL_GT);

        let c = ScheduleStep::tick(1, 5);
        assert_eq!(a.compare_step(&c), CompareResult::EQUALS);
    }

    #[test]
    fn test_add_to() {
        let mut a = ScheduleStep::tick(1, 5);
        let b = ScheduleStep::tick(1, 3);
        a.add_to(&b);
        assert_eq!(a.tick_count(), 8);
    }

    #[test]
    fn test_subtract() {
        let a = ScheduleStep::tick(1, 10);
        let b = ScheduleStep::tick(1, 3);
        let result = a.subtract(&b);
        assert_eq!(result.tick_count(), 7);
    }

    #[test]
    fn test_step_type_display() {
        assert_eq!(StepType::Tick.to_string(), "tick");
        assert_eq!(StepType::Skip.to_string(), "skip");
        assert_eq!(StepType::Patch.to_string(), "patch");
    }

    #[test]
    fn test_step_kind_display() {
        assert_eq!(StepKind::Instruction.to_string(), "instruction");
        assert_eq!(StepKind::PcodeOp.to_string(), "pcode");
    }

    #[test]
    fn test_parse_tick_step() {
        let step = TickStep::parse(1, "10", 10).unwrap();
        assert_eq!(step.thread_key, 1);
        assert_eq!(step.tick_count, 10);
    }

    #[test]
    fn test_parse_skip_step() {
        let step = SkipStep::parse(-1, "s5", 10).unwrap();
        assert_eq!(step.thread_key, -1);
        assert_eq!(step.tick_count, 5);
    }

    #[test]
    fn test_parse_skip_step_bad_prefix() {
        assert!(SkipStep::parse(-1, "x5", 10).is_err());
    }

    #[test]
    fn test_coalesce_patches() {
        let steps = vec![
            ScheduleStep::tick(1, 5),
            ScheduleStep::patch(-1, 2, 0, vec![]),
            ScheduleStep::skip(1, 3),
            ScheduleStep::patch(-1, 3, 0, vec![]),
        ];
        assert_eq!(ScheduleStep::coalesce_patches(&steps), 5);
    }

    #[test]
    fn test_display() {
        assert_eq!(ScheduleStep::tick(1, 5).to_string(), "1.5");
        assert_eq!(ScheduleStep::skip(-1, 3).to_string(), "s3");
        assert_eq!(ScheduleStep::patch(-1, 2, 0, vec![]).to_string(), "p2");
    }

    #[test]
    fn test_advance() {
        let mut step = TickStep::new(1, 5);
        step.advance(3);
        assert_eq!(step.tick_count, 8);
    }
}
