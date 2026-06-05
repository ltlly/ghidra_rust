//! TraceSchedule - a complete emulation schedule with snap, steps, and pcode steps.
//!
//! Ported from Ghidra's `TraceSchedule` class. This is the core scheduling
//! type that represents a "point in time" within a trace by combining a
//! snapshot key with a sequence of instruction-level steps and pcode-level steps.

use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::HashSet;

use super::compare_result::CompareResult;
use super::sequence::Sequence;
use super::tick_step::TickStep;

/// Radix for formatting and parsing time values in schedules.
///
/// Ported from Ghidra's `TraceSchedule.TimeRadix`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TimeRadix {
    /// Decimal (default).
    Dec,
    /// Upper-case hexadecimal.
    HexUpper,
    /// Lower-case hexadecimal.
    HexLower,
}

impl Default for TimeRadix {
    fn default() -> Self {
        Self::Dec
    }
}

impl TimeRadix {
    /// The default radix (decimal).
    pub const DEFAULT: Self = Self::Dec;

    /// Create a decimal radix.
    pub fn dec() -> Self {
        Self::Dec
    }

    /// Create an upper-case hex radix.
    pub fn hex_upper() -> Self {
        Self::HexUpper
    }

    /// Create a lower-case hex radix.
    pub fn hex_lower() -> Self {
        Self::HexLower
    }

    /// Get the numeric radix.
    pub fn radix(&self) -> u32 {
        match self {
            Self::Dec => 10,
            Self::HexUpper | Self::HexLower => 16,
        }
    }

    /// Parse from a string name.
    pub fn from_str(s: &str) -> Self {
        match s {
            "dec" => Self::Dec,
            "HEX" => Self::HexUpper,
            "hex" => Self::HexLower,
            _ => Self::DEFAULT,
        }
    }

    /// Format a time value.
    pub fn format(&self, time: i64) -> String {
        match self {
            Self::Dec => format!("{}", time),
            Self::HexUpper => format!("{:X}", time),
            Self::HexLower => format!("{:x}", time),
        }
    }

    /// Decode a time value from string.
    pub fn decode(&self, nm: &str) -> Result<i64, String> {
        if nm.starts_with("0x") || nm.starts_with("0X") ||
           nm.starts_with("-0x") || nm.starts_with("-0X") {
            let hex = nm.trim_start_matches('-').trim_start_matches("0x").trim_start_matches("0X");
            let value = i64::from_str_radix(hex, 16)
                .map_err(|e| e.to_string())?;
            return if nm.starts_with('-') { Ok(-value) } else { Ok(value) };
        }
        if nm.starts_with("0n") || nm.starts_with("0N") ||
           nm.starts_with("-0n") || nm.starts_with("-0N") {
            let dec = nm.trim_start_matches('-').trim_start_matches("0n").trim_start_matches("0N");
            let value = dec.parse::<i64>().map_err(|e| e.to_string())?;
            return if nm.starts_with('-') { Ok(-value) } else { Ok(value) };
        }
        i64::from_str_radix(nm, self.radix()).map_err(|e| e.to_string())
    }
}

/// The source of a schedule.
///
/// Indicates whether the schedule came from recording actual emulation
/// (where p-code steps are known not to exceed one instruction) or from
/// user input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScheduleSource {
    /// The schedule comes from the user or some source other than recorded emulation.
    Input,
    /// The schedule comes from recording actual emulation.
    Record,
}

impl ScheduleSource {
    /// Adjust the source based on pcode step counts.
    pub fn adjust(&self, p_tick_count: u64, p_patch_count: u64, p_skip_count: u64) -> Self {
        match self {
            Self::Input => {
                if p_tick_count <= 1 && p_patch_count == 0 && p_skip_count == 0 {
                    Self::Record
                } else {
                    Self::Input
                }
            }
            Self::Record => {
                if p_patch_count == 0 && p_skip_count == 0 {
                    Self::Record
                } else {
                    Self::Input
                }
            }
        }
    }
}

/// Specifies the form (restriction level) of a stepping schedule.
///
/// Ported from Ghidra's `TraceSchedule.ScheduleForm`. Each form defines
/// a set of stepping schedules, with more restrictive forms being subsets
/// of less restrictive forms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ScheduleForm {
    /// Only a snapshot, no stepping.
    SnapOnly,
    /// A snapshot and instruction steps on the event thread only.
    SnapEvtSteps,
    /// A snapshot and instruction steps on any thread(s).
    SnapAnySteps,
    /// A snapshot, instruction steps, and pcode steps on any thread(s).
    SnapAnyStepsOps,
}

impl ScheduleForm {
    /// Get all schedule forms in order of increasing capability.
    pub fn all() -> &'static [ScheduleForm] {
        &[
            ScheduleForm::SnapOnly,
            ScheduleForm::SnapEvtSteps,
            ScheduleForm::SnapAnySteps,
            ScheduleForm::SnapAnyStepsOps,
        ]
    }

    /// Get the more restrictive of this and the given form.
    pub fn intersect(&self, other: &ScheduleForm) -> ScheduleForm {
        let ord = (*self as usize).min(*other as usize);
        Self::all()[ord]
    }

    /// Check if the given schedule conforms to this form.
    ///
    /// Note: full validation requires a trace context to resolve thread keys.
    /// This implementation does a basic structural check.
    pub fn contains_basic(&self, schedule: &TraceSchedule) -> bool {
        match self {
            Self::SnapOnly => schedule.steps().is_nop() && schedule.p_steps().is_nop(),
            Self::SnapEvtSteps => {
                if !schedule.p_steps().is_nop() {
                    return false;
                }
                let steps = schedule.steps();
                if steps.is_nop() {
                    return true;
                }
                let step_list = steps.steps();
                if step_list.len() != 1 {
                    return false;
                }
                // Check that the only step is a tick on the event thread
                matches!(step_list.first(),
                    Some(super::sequence::StepEnum::Tick(t)) if t.thread_key == -1
                        || t.thread_key == schedule.last_thread_key())
            }
            Self::SnapAnySteps => schedule.p_steps().is_nop(),
            Self::SnapAnyStepsOps => true,
        }
    }
}

/// A complete emulation schedule consisting of a snap, instruction steps, and pcode steps.
///
/// Ported from Ghidra's `TraceSchedule`. This is the primary scheduling type
/// that represents a "point in time" within a trace.
///
/// A schedule is formatted as: `snap[:steps[.pSteps]]`
///
/// - `snap` is the initial trace snapshot key
/// - `steps` is a `Sequence` of thread instruction-level steps
/// - `pSteps` is a `Sequence` of pcode-level steps
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceSchedule {
    snap: i64,
    steps: Sequence,
    p_steps: Sequence,
    source: ScheduleSource,
}

impl TraceSchedule {
    /// The initial schedule at snap 0 with no steps.
    pub const ZERO: Self = Self {
        snap: 0,
        steps: Sequence::EMPTY,
        p_steps: Sequence::EMPTY,
        source: ScheduleSource::Record,
    };

    /// Create a schedule that consists solely of a snapshot.
    pub fn snap(snap: i64) -> Self {
        Self::new(snap, Sequence::empty(), Sequence::empty(), ScheduleSource::Record)
    }

    /// Construct a schedule.
    pub fn new(snap: i64, steps: Sequence, p_steps: Sequence, source: ScheduleSource) -> Self {
        let adjusted = source.adjust(
            p_steps.total_tick_count(),
            p_steps.total_patch_count(),
            p_steps.total_skip_count(),
        );
        Self { snap, steps, p_steps, source: adjusted }
    }

    /// Construct a schedule with Input source.
    pub fn with_input(snap: i64, steps: Sequence, p_steps: Sequence) -> Self {
        Self::new(snap, steps, p_steps, ScheduleSource::Input)
    }

    /// Parse a schedule from a string in the form `snap[:steps[.pSteps]]`.
    pub fn parse(spec: &str) -> Result<Self, String> {
        Self::parse_with_source(spec, ScheduleSource::Input, TimeRadix::default())
    }

    /// Parse a schedule with the given source and radix.
    pub fn parse_with_source(
        spec: &str,
        source: ScheduleSource,
        radix: TimeRadix,
    ) -> Result<Self, String> {
        let err = "Time specification must have form 'snap[:steps[.pSteps]]'";
        let parts: Vec<&str> = spec.splitn(2, ':').collect();

        let snap = radix.decode(parts[0])
            .map_err(|_| err)?;

        let (steps, p_steps) = if parts.len() > 1 {
            let subs: Vec<&str> = parts[1].splitn(2, '.').collect();
            let steps = Sequence::parse(subs[0], radix)?;
            let p_steps = if subs.len() > 1 {
                Sequence::parse(subs[1], radix)?
            } else {
                Sequence::empty()
            };
            (steps, p_steps)
        } else {
            (Sequence::empty(), Sequence::empty())
        };

        Ok(Self::new(snap, steps, p_steps, source))
    }

    /// Get the snap key.
    pub fn get_snap(&self) -> i64 {
        self.snap
    }

    /// Get the instruction step sequence.
    pub fn steps(&self) -> &Sequence {
        &self.steps
    }

    /// Get the pcode step sequence.
    pub fn p_steps(&self) -> &Sequence {
        &self.p_steps
    }

    /// Get the source.
    pub fn source(&self) -> ScheduleSource {
        self.source
    }

    /// Check if this schedule requires any stepping.
    pub fn is_snap_only(&self) -> bool {
        ScheduleForm::SnapOnly.contains_basic(self)
    }

    /// Check if this schedule has instruction steps.
    pub fn has_steps(&self) -> bool {
        !self.steps.is_nop()
    }

    /// Check if this schedule has pcode steps.
    pub fn has_p_steps(&self) -> bool {
        !self.p_steps.is_nop()
    }

    /// Get the last thread key stepped by this schedule.
    pub fn last_thread_key(&self) -> i64 {
        let last = self.p_steps.last_thread_key();
        if last != -1 {
            return last;
        }
        self.steps.last_thread_key()
    }

    /// Compute the total number of ticks (including pcode ticks).
    pub fn total_tick_count(&self) -> u64 {
        self.steps.total_tick_count() + self.p_steps.total_tick_count()
    }

    /// Compute the total number of patches.
    pub fn total_patch_count(&self) -> u64 {
        self.steps.total_patch_count() + self.p_steps.total_patch_count()
    }

    /// Get the instruction tick count (excluding pcode).
    pub fn tick_count(&self) -> u64 {
        self.steps.total_tick_count()
    }

    /// Get the step count (excluding pcode).
    pub fn step_count(&self) -> usize {
        self.steps.count()
    }

    /// Get the patch count (excluding pcode).
    pub fn patch_count(&self) -> u64 {
        self.steps.total_patch_count()
    }

    /// Get the pcode tick count.
    pub fn p_tick_count(&self) -> u64 {
        self.p_steps.total_tick_count()
    }

    /// Get the pcode patch count.
    pub fn p_patch_count(&self) -> u64 {
        self.p_steps.total_patch_count()
    }

    /// Richly compare two schedules.
    ///
    /// Schedules starting at different snapshots are never related.
    pub fn compare_schedule(&self, that: &TraceSchedule) -> CompareResult {
        // Compare snaps
        let snap_cmp = CompareResult::unrelated(self.snap.cmp(&that.snap));
        if snap_cmp != CompareResult::EQUALS {
            return snap_cmp;
        }

        // Compare instruction step sequences
        let steps_cmp = self.steps.compare_seq(&that.steps);
        match steps_cmp {
            CompareResult::UNREL_LT | CompareResult::UNREL_GT => steps_cmp,
            CompareResult::REL_LT => {
                if self.p_steps.is_nop() || self.source == ScheduleSource::Record {
                    CompareResult::REL_LT
                } else {
                    CompareResult::UNREL_LT
                }
            }
            CompareResult::REL_GT => {
                if that.p_steps.is_nop() || that.source == ScheduleSource::Record {
                    CompareResult::REL_GT
                } else {
                    CompareResult::UNREL_GT
                }
            }
            _ => self.p_steps.compare_seq(&that.p_steps),
        }
    }

    /// Returns the equivalent of stepping the given thread count more instructions.
    ///
    /// This schedule is left unmodified. Any pcode steps are dropped.
    pub fn stepped_forward(&self, thread_key: i64, tick_count: u64) -> Self {
        let mut steps = self.steps.clone();
        steps.advance_step(super::sequence::StepEnum::Tick(TickStep::new(thread_key, tick_count)));
        Self::new(self.snap, steps, Sequence::empty(), ScheduleSource::Record)
    }

    /// Returns the equivalent of skipping the given thread count more instructions.
    pub fn skipped_forward(&self, thread_key: i64, tick_count: u64) -> Self {
        let mut steps = self.steps.clone();
        steps.advance_step(super::sequence::StepEnum::Skip(
            super::skip_step::SkipStep::new(thread_key, tick_count),
        ));
        Self::new(self.snap, steps, Sequence::empty(), ScheduleSource::Record)
    }

    /// Returns the equivalent of stepping N pcode operations forward.
    pub fn stepped_pcode_forward(&self, thread_key: i64, p_tick_count: u64) -> Self {
        let mut p_steps = self.p_steps.clone();
        p_steps.advance_step(super::sequence::StepEnum::Tick(TickStep::new(thread_key, p_tick_count)));
        Self::new(self.snap, self.steps.clone(), p_steps, ScheduleSource::Input)
    }

    /// Returns the equivalent of skipping N pcode operations forward.
    pub fn skipped_pcode_forward(&self, thread_key: i64, p_tick_count: u64) -> Self {
        let mut p_steps = self.p_steps.clone();
        p_steps.advance_step(super::sequence::StepEnum::Skip(
            super::skip_step::SkipStep::new(thread_key, p_tick_count),
        ));
        Self::new(self.snap, self.steps.clone(), p_steps, ScheduleSource::Input)
    }

    /// Step backward by the given number of instruction steps.
    ///
    /// Returns `None` if the count exceeds the schedule's steps and cannot
    /// be resolved (would need to look up source snapshot in the trace).
    pub fn stepped_backward(&self, step_count: u64) -> Option<Self> {
        let total = self.total_tick_count() + self.total_patch_count();
        if step_count > total {
            return None;
        }
        let mut steps = self.steps.clone();
        let remaining = steps.rewind(step_count);
        if remaining > 0 {
            return None;
        }
        Some(Self::new(self.snap, steps, Sequence::empty(), ScheduleSource::Record))
    }

    /// Step backward by pcode steps.
    ///
    /// Returns `None` if the count exceeds pcode steps.
    pub fn stepped_pcode_backward(&self, p_step_count: u64) -> Option<Self> {
        let total = self.p_steps.total_tick_count();
        if p_step_count > total {
            return None;
        }
        let mut p_steps = self.p_steps.clone();
        let remaining = p_steps.rewind(p_step_count);
        if remaining > 0 {
            return None;
        }
        Some(Self::new(self.snap, self.steps.clone(), p_steps, ScheduleSource::Input))
    }

    /// Compute the schedule resulting from this schedule advanced by the given schedule.
    ///
    /// The given schedule's snap is ignored.
    pub fn advanced(&self, next: &TraceSchedule) -> Result<Self, String> {
        if self.p_steps.is_nop() {
            let mut steps = self.steps.clone();
            steps.advance_seq(&next.steps);
            Ok(Self::new(self.snap, steps, next.p_steps.clone(), next.source))
        } else if next.steps.is_nop() {
            let mut p_steps = self.p_steps.clone();
            p_steps.advance_seq(&next.p_steps);
            Ok(Self::new(self.snap, self.steps.clone(), p_steps, ScheduleSource::Input))
        } else {
            Err("Cannot have instruction steps following pcode steps".to_string())
        }
    }

    /// Drop the pcode steps.
    pub fn drop_p_steps(&self) -> Self {
        Self::new(self.snap, self.steps.clone(), Sequence::empty(), self.source)
    }

    /// Drop the last step.
    pub fn drop_last_step(&self) -> Result<Self, String> {
        if !self.p_steps.is_nop() {
            Ok(Self::new(
                self.snap,
                self.steps.clone(),
                self.p_steps.drop_last()?,
                self.source,
            ))
        } else {
            Ok(Self::new(
                self.snap,
                self.steps.drop_last()?,
                Sequence::empty(),
                self.source,
            ))
        }
    }

    /// Truncate the schedule to the given step count, dropping pcode steps.
    pub fn truncate_to_steps(&self, count: usize) -> Self {
        Self::new(self.snap, self.steps.truncate(count), Sequence::empty(), self.source)
    }

    /// Assume this schedule is from a recorded source.
    pub fn assume_recorded(&self) -> Self {
        Self::new(self.snap, self.steps.clone(), self.p_steps.clone(), ScheduleSource::Record)
    }

    /// Check if two schedules differ only by patch steps.
    pub fn differs_only_by_patch(&self, that: &TraceSchedule) -> bool {
        if self.snap != that.snap {
            return false;
        }
        if self.p_steps.is_nop() != that.p_steps.is_nop() {
            return false;
        }
        if self.p_steps.is_nop() {
            return self.steps.differs_only_by_patch(&that.steps);
        }
        if self.steps != that.steps {
            return false;
        }
        self.p_steps.differs_only_by_patch(&that.p_steps)
    }
}

impl PartialOrd for TraceSchedule {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.compare_schedule(other).compare_to())
    }
}

impl Ord for TraceSchedule {
    fn cmp(&self, other: &Self) -> Ordering {
        self.compare_schedule(other).compare_to()
    }
}

impl std::fmt::Display for TraceSchedule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let radix = TimeRadix::default();
        self.fmt_with_radix(f, &radix)
    }
}

impl TraceSchedule {
    /// Format with the given radix.
    pub fn fmt_with_radix(&self, f: &mut std::fmt::Formatter<'_>, radix: &TimeRadix) -> std::fmt::Result {
        if self.p_steps.is_nop() {
            if self.steps.is_nop() {
                write!(f, "{}", radix.format(self.snap))
            } else {
                write!(f, "{}:{}", radix.format(self.snap), self.steps.to_string_with_radix(radix))
            }
        } else {
            write!(f, "{}:{}.{}", radix.format(self.snap),
                self.steps.to_string_with_radix(radix),
                self.p_steps.to_string_with_radix(radix))
        }
    }

    /// Format with the given radix (string version).
    pub fn to_string_with_radix(&self, radix: &TimeRadix) -> String {
        if self.p_steps.is_nop() {
            if self.steps.is_nop() {
                radix.format(self.snap)
            } else {
                format!("{}:{}", radix.format(self.snap), self.steps.to_string_with_radix(radix))
            }
        } else {
            format!("{}:{}.{}", radix.format(self.snap),
                self.steps.to_string_with_radix(radix),
                self.p_steps.to_string_with_radix(radix))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trace_schedule_snap() {
        let s = TraceSchedule::snap(5);
        assert_eq!(s.get_snap(), 5);
        assert!(s.is_snap_only());
        assert!(!s.has_steps());
        assert!(!s.has_p_steps());
        assert_eq!(s.to_string(), "5");
    }

    #[test]
    fn test_trace_schedule_zero() {
        assert_eq!(TraceSchedule::ZERO.get_snap(), 0);
        assert!(TraceSchedule::ZERO.is_snap_only());
    }

    #[test]
    fn test_trace_schedule_parse() {
        let s = TraceSchedule::parse("5").unwrap();
        assert_eq!(s.get_snap(), 5);
        assert!(s.is_snap_only());

        let s = TraceSchedule::parse("5:t1-10").unwrap();
        assert_eq!(s.get_snap(), 5);
        assert!(s.has_steps());
        assert_eq!(s.tick_count(), 10);
        assert_eq!(s.to_string(), "5:t1-10");
    }

    #[test]
    fn test_trace_schedule_parse_with_pcode() {
        let s = TraceSchedule::parse("5:10.3").unwrap();
        assert_eq!(s.get_snap(), 5);
        assert_eq!(s.tick_count(), 10);
        assert_eq!(s.p_tick_count(), 3);
        assert!(s.has_p_steps());
    }

    #[test]
    fn test_trace_schedule_display() {
        let s = TraceSchedule::snap(0);
        assert_eq!(s.to_string(), "0");

        let s = TraceSchedule::parse("5:3").unwrap();
        assert_eq!(s.to_string(), "5:3");
    }

    #[test]
    fn test_compare_same_snap() {
        let a = TraceSchedule::snap(5);
        let b = TraceSchedule::snap(5);
        assert_eq!(a.compare_schedule(&b), CompareResult::EQUALS);
    }

    #[test]
    fn test_compare_different_snap() {
        let a = TraceSchedule::snap(5);
        let b = TraceSchedule::snap(10);
        let cmp = a.compare_schedule(&b);
        assert_eq!(cmp, CompareResult::UNREL_LT);
        assert!(!cmp.related);
    }

    #[test]
    fn test_compare_steps() {
        let a = TraceSchedule::parse("0:3").unwrap();
        let b = TraceSchedule::parse("0:5").unwrap();
        assert_eq!(a.compare_schedule(&b), CompareResult::REL_LT);
        assert_eq!(b.compare_schedule(&a), CompareResult::REL_GT);
    }

    #[test]
    fn test_stepped_forward() {
        let s = TraceSchedule::snap(0);
        let s2 = s.stepped_forward(-1, 5);
        assert_eq!(s2.get_snap(), 0);
        assert_eq!(s2.tick_count(), 5);
        assert!(!s2.is_snap_only());
    }

    #[test]
    fn test_advanced() {
        let a = TraceSchedule::snap(0);
        let b = TraceSchedule::parse("0:3").unwrap();
        let result = a.advanced(&b).unwrap();
        assert_eq!(result.get_snap(), 0);
        assert_eq!(result.tick_count(), 3);
    }

    #[test]
    fn test_drop_p_steps() {
        let s = TraceSchedule::parse("5:3.2").unwrap();
        assert!(s.has_p_steps());
        let s2 = s.drop_p_steps();
        assert!(!s2.has_p_steps());
        assert_eq!(s2.tick_count(), 3);
    }

    #[test]
    fn test_truncate_to_steps() {
        let s = TraceSchedule::parse("5:3").unwrap();
        let s2 = s.truncate_to_steps(1);
        assert_eq!(s2.step_count(), 1);
    }

    #[test]
    fn test_total_tick_count() {
        let s = TraceSchedule::parse("0:3.2").unwrap();
        assert_eq!(s.total_tick_count(), 5);
    }

    #[test]
    fn test_differs_only_by_patch() {
        let a = TraceSchedule::parse("0:3").unwrap();
        let b = TraceSchedule::parse("0:3").unwrap();
        assert!(a.differs_only_by_patch(&b));
    }

    #[test]
    fn test_schedule_form() {
        let snap_only = TraceSchedule::snap(5);
        assert!(ScheduleForm::SnapOnly.contains_basic(&snap_only));
        assert!(ScheduleForm::SnapEvtSteps.contains_basic(&snap_only));
        assert!(ScheduleForm::SnapAnySteps.contains_basic(&snap_only));
        assert!(ScheduleForm::SnapAnyStepsOps.contains_basic(&snap_only));
    }

    #[test]
    fn test_schedule_form_intersect() {
        assert_eq!(
            ScheduleForm::SnapOnly.intersect(&ScheduleForm::SnapAnySteps),
            ScheduleForm::SnapOnly
        );
        assert_eq!(
            ScheduleForm::SnapAnySteps.intersect(&ScheduleForm::SnapEvtSteps),
            ScheduleForm::SnapEvtSteps
        );
    }

    #[test]
    fn test_time_radix() {
        let radix = TimeRadix::dec();
        assert_eq!(radix.format(42), "42");
        assert_eq!(radix.decode("42").unwrap(), 42);

        let hex = TimeRadix::hex_lower();
        assert_eq!(hex.format(255), "ff");
        assert_eq!(hex.decode("0xff").unwrap(), 255);
    }

    #[test]
    fn test_time_radix_from_str() {
        assert_eq!(TimeRadix::from_str("dec"), TimeRadix::Dec);
        assert_eq!(TimeRadix::from_str("HEX"), TimeRadix::HexUpper);
        assert_eq!(TimeRadix::from_str("hex"), TimeRadix::HexLower);
        assert_eq!(TimeRadix::from_str("unknown"), TimeRadix::Dec);
    }

    #[test]
    fn test_schedule_source_adjust() {
        assert_eq!(ScheduleSource::Input.adjust(0, 0, 0), ScheduleSource::Record);
        assert_eq!(ScheduleSource::Input.adjust(2, 0, 0), ScheduleSource::Input);
        assert_eq!(ScheduleSource::Record.adjust(0, 1, 0), ScheduleSource::Input);
    }

    #[test]
    fn test_stepped_backward() {
        let s = TraceSchedule::parse("0:5").unwrap();
        let s2 = s.stepped_backward(2).unwrap();
        assert_eq!(s2.tick_count(), 3);
    }

    #[test]
    fn test_stepped_backward_exceed() {
        let s = TraceSchedule::snap(0);
        assert!(s.stepped_backward(1).is_none());
    }

    #[test]
    fn test_stepped_pcode_forward() {
        let s = TraceSchedule::snap(0);
        let s2 = s.stepped_pcode_forward(-1, 3);
        assert_eq!(s2.p_tick_count(), 3);
    }

    #[test]
    fn test_stepped_pcode_backward() {
        let s = TraceSchedule::parse("0:0.5").unwrap();
        let s2 = s.stepped_pcode_backward(2).unwrap();
        assert_eq!(s2.p_tick_count(), 3);
    }

    #[test]
    fn test_ordering() {
        let a = TraceSchedule::snap(0);
        let b = TraceSchedule::snap(1);
        assert!(a < b);

        let c = TraceSchedule::parse("0:3").unwrap();
        let d = TraceSchedule::parse("0:5").unwrap();
        assert!(c < d);
    }

    #[test]
    fn test_assume_recorded() {
        // Use p_steps with >1 tick so source stays Input (adjust keeps Input when p_tick > 1)
        let s = TraceSchedule::parse_with_source("0:0.5", ScheduleSource::Input, TimeRadix::dec()).unwrap();
        assert_eq!(s.source(), ScheduleSource::Input);
        let s2 = s.assume_recorded();
        assert_eq!(s2.source(), ScheduleSource::Record);
    }
}
