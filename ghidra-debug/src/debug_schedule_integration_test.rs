//! Integration tests for the full schedule system.
//!
//! Tests the comprehensive time scheduling model ported from Ghidra's
//! `ghidra.trace.model.time.schedule` package.

#[cfg(test)]
mod tests {
    use crate::model::schedule::{
        CompareResult, PatchStep, RunResult, Scheduler, OneThreadScheduler,
        RoundRobinScheduler, TraceScheduler, Sequence, SkipStep, StepKind,
        Stepper, TickStep, TimeRadix, TraceSchedule, ScheduleForm, ScheduleSource,
    };
    use crate::model::schedule::sequence::StepEnum;
    use crate::model::schedule::tick_step::StepType;
    use crate::model::schedule::stepper::{InstructionStepper, PcodeStepper};

    // === TraceSchedule integration tests ===

    #[test]
    fn test_schedule_snap_only_lifecycle() {
        let s = TraceSchedule::snap(0);
        assert_eq!(s.get_snap(), 0);
        assert!(s.is_snap_only());
        assert_eq!(s.tick_count(), 0);
        assert_eq!(s.step_count(), 0);
        assert_eq!(s.total_tick_count(), 0);
        assert_eq!(s.to_string(), "0");
    }

    #[test]
    fn test_schedule_with_instruction_steps() {
        let s = TraceSchedule::parse("5:10").unwrap();
        assert_eq!(s.get_snap(), 5);
        assert_eq!(s.tick_count(), 10);
        assert!(s.has_steps());
        assert!(!s.has_p_steps());
        assert!(s.is_snap_only() || s.has_steps());
    }

    #[test]
    fn test_schedule_with_pcode_steps() {
        let s = TraceSchedule::parse("5:3.2").unwrap();
        assert_eq!(s.get_snap(), 5);
        assert_eq!(s.tick_count(), 3);
        assert_eq!(s.p_tick_count(), 2);
        assert!(s.has_p_steps());
        assert_eq!(s.total_tick_count(), 5);
    }

    #[test]
    fn test_schedule_stepped_forward() {
        let base = TraceSchedule::snap(0);
        let s1 = base.stepped_forward(-1, 5);
        assert_eq!(s1.get_snap(), 0);
        assert_eq!(s1.tick_count(), 5);

        let s2 = s1.stepped_forward(1, 3);
        assert_eq!(s2.tick_count(), 8);
    }

    #[test]
    fn test_schedule_stepped_backward_basic() {
        let s = TraceSchedule::parse("0:10").unwrap();
        let s2 = s.stepped_backward(3).unwrap();
        assert_eq!(s2.tick_count(), 7);
    }

    #[test]
    fn test_schedule_stepped_backward_exceed() {
        let s = TraceSchedule::snap(0);
        assert!(s.stepped_backward(1).is_none());
    }

    #[test]
    fn test_schedule_stepped_pcode_forward() {
        let base = TraceSchedule::snap(0);
        let s = base.stepped_pcode_forward(-1, 5);
        assert_eq!(s.p_tick_count(), 5);
    }

    #[test]
    fn test_schedule_stepped_pcode_backward() {
        let s = TraceSchedule::parse("0:0.5").unwrap();
        let s2 = s.stepped_pcode_backward(2).unwrap();
        assert_eq!(s2.p_tick_count(), 3);
    }

    #[test]
    fn test_schedule_stepped_pcode_backward_exceed() {
        let s = TraceSchedule::snap(0);
        assert!(s.stepped_pcode_backward(1).is_none());
    }

    #[test]
    fn test_schedule_advanced() {
        let a = TraceSchedule::snap(0);
        let b = TraceSchedule::parse("0:3").unwrap();
        let result = a.advanced(&b).unwrap();
        assert_eq!(result.get_snap(), 0);
        assert_eq!(result.tick_count(), 3);
    }

    #[test]
    fn test_schedule_advanced_pcode_to_instruction_error() {
        let a = TraceSchedule::parse("0:0.2").unwrap();
        let b = TraceSchedule::parse("0:3").unwrap();
        assert!(a.advanced(&b).is_err());
    }

    #[test]
    fn test_schedule_drop_p_steps() {
        let s = TraceSchedule::parse("5:3.2").unwrap();
        let s2 = s.drop_p_steps();
        assert!(!s2.has_p_steps());
        assert_eq!(s2.tick_count(), 3);
    }

    #[test]
    fn test_schedule_truncate() {
        // "5:10" has 1 step (10 ticks), truncate to 3 steps keeps all 1
        let s = TraceSchedule::parse("5:10").unwrap();
        let s2 = s.truncate_to_steps(3);
        assert_eq!(s2.step_count(), 1);
        // Multi-step: truncate to 2
        let s3 = TraceSchedule::parse("5:t1-3;t2-5;t3-1").unwrap();
        assert_eq!(s3.step_count(), 3);
        let s4 = s3.truncate_to_steps(2);
        assert_eq!(s4.step_count(), 2);
    }

    #[test]
    fn test_schedule_display_roundtrip() {
        for spec in &["0", "0:5", "5:3", "5:t1-10", "0:3.2"] {
            let s = TraceSchedule::parse(spec).unwrap();
            let display = s.to_string();
            let s2 = TraceSchedule::parse(&display).unwrap();
            assert_eq!(s.get_snap(), s2.get_snap());
            assert_eq!(s.tick_count(), s2.tick_count());
        }
    }

    #[test]
    fn test_schedule_hex_radix() {
        let radix = TimeRadix::hex_lower();
        let s = TraceSchedule::parse_with_source("ff:10", ScheduleSource::Input, radix).unwrap();
        assert_eq!(s.get_snap(), 255);
        assert_eq!(s.tick_count(), 16);
    }

    // === Sequence integration tests ===

    #[test]
    fn test_sequence_multi_thread() {
        let mut seq = Sequence::empty();
        seq.advance_step(StepEnum::Tick(TickStep::new(1, 5)));
        seq.advance_step(StepEnum::Tick(TickStep::new(2, 3)));
        seq.advance_step(StepEnum::Tick(TickStep::new(1, 2)));

        // Steps for thread 1 should be combined (5 + 2 = 7), then thread 2
        assert_eq!(seq.count(), 3); // t1-5, t2-3, t1-2
        assert_eq!(seq.total_tick_count(), 10);
    }

    #[test]
    fn test_sequence_compatible_combine() {
        let mut seq = Sequence::empty();
        seq.advance_step(StepEnum::Tick(TickStep::new(1, 5)));
        // Same thread, should combine
        seq.advance_step(StepEnum::Tick(TickStep::new(1, 3)));
        assert_eq!(seq.count(), 1);
        assert_eq!(seq.total_tick_count(), 8);
    }

    #[test]
    fn test_sequence_last_thread_compatible() {
        let mut seq = Sequence::empty();
        seq.advance_step(StepEnum::Tick(TickStep::new(1, 5)));
        // Thread -1 (last thread) is compatible with any
        seq.advance_step(StepEnum::Tick(TickStep::new(-1, 3)));
        assert_eq!(seq.count(), 1);
        assert_eq!(seq.total_tick_count(), 8);
    }

    #[test]
    fn test_sequence_mixed_step_types() {
        let mut seq = Sequence::empty();
        seq.advance_step(StepEnum::Tick(TickStep::new(1, 5)));
        seq.advance_step(StepEnum::Skip(SkipStep::new(2, 3)));
        seq.advance_step(StepEnum::Patch(PatchStep::new(1, "r0=0x1234")));

        assert_eq!(seq.count(), 3);
        assert_eq!(seq.total_tick_count(), 5);
        assert_eq!(seq.total_skip_count(), 3);
        assert_eq!(seq.total_patch_count(), 1);
    }

    #[test]
    fn test_sequence_compare_prefix() {
        let a = Sequence::parse("5", TimeRadix::dec()).unwrap();
        let b = Sequence::parse("5;t1-3", TimeRadix::dec()).unwrap();
        assert_eq!(a.compare_seq(&b), CompareResult::REL_LT);
        assert_eq!(b.compare_seq(&a), CompareResult::REL_GT);
    }

    #[test]
    fn test_sequence_relativize() {
        let prefix = Sequence::parse("5", TimeRadix::dec()).unwrap();
        let full = Sequence::parse("5;t1-3", TimeRadix::dec()).unwrap();
        let relative = full.relativize(&prefix).unwrap();
        assert_eq!(relative.total_tick_count(), 3);
    }

    // === Step comparison tests ===

    #[test]
    fn test_step_type_ordering() {
        assert!(StepType::Tick < StepType::Skip);
        assert!(StepType::Skip < StepType::Patch);
    }

    #[test]
    fn test_step_compare_same_thread() {
        let a = TickStep::new(1, 5);
        let b = TickStep::new(1, 10);
        assert_eq!(a.compare_step(&b), CompareResult::REL_LT);
        assert_eq!(b.compare_step(&a), CompareResult::REL_GT);
        assert_eq!(a.compare_step(&a), CompareResult::EQUALS);
    }

    #[test]
    fn test_step_compare_different_thread() {
        let a = TickStep::new(1, 5);
        let b = TickStep::new(2, 5);
        let cmp = a.compare_step(&b);
        assert!(!cmp.related);
    }

    // === Scheduler tests ===

    #[test]
    fn test_one_thread_scheduler_repeated() {
        let mut sched = OneThreadScheduler::new(42, 100);
        for _ in 0..10 {
            let step = sched.next_slice();
            assert_eq!(step.thread_key, 42);
            assert_eq!(step.tick_count, 100);
        }
    }

    #[test]
    fn test_round_robin_cycle() {
        let mut sched = RoundRobinScheduler::new(vec![1, 2, 3, 4], 50);
        for expected in [1, 2, 3, 4, 1, 2, 3, 4] {
            assert_eq!(sched.next_slice().thread_key, expected);
        }
    }

    #[test]
    fn test_trace_scheduler_config() {
        let mut sched = TraceScheduler::new(5)
            .with_thread(10)
            .with_slice_size(200);
        let step = sched.next_slice();
        assert_eq!(step.thread_key, 10);
        assert_eq!(step.tick_count, 200);
    }

    // === Stepper tests ===

    #[test]
    fn test_instruction_stepper_type() {
        let s = InstructionStepper;
        assert_eq!(s.kind(), StepKind::Instruction);
        s.tick(0);
        s.skip(0);
    }

    #[test]
    fn test_pcode_stepper_type() {
        let s = PcodeStepper;
        assert_eq!(s.kind(), StepKind::PcodeOp);
        s.tick(0);
        s.skip(0);
    }

    // === RunResult tests ===

    #[test]
    fn test_run_result_success() {
        let result = RunResult::success(TraceSchedule::snap(0));
        assert!(result.is_success());
        assert!(!result.is_cancelled());
        assert!(result.error.is_none());
    }

    #[test]
    fn test_run_result_error() {
        let result = RunResult::with_error(TraceSchedule::snap(0), "breakpoint hit");
        assert!(!result.is_success());
        assert_eq!(result.error.as_deref(), Some("breakpoint hit"));
    }

    #[test]
    fn test_run_result_cancelled() {
        let result = RunResult::with_error(TraceSchedule::snap(0), "cancelled");
        assert!(result.is_cancelled());
    }

    // === CompareResult tests ===

    #[test]
    fn test_compare_result_semantics() {
        let eq = CompareResult::EQUALS;
        assert!(eq.related);
        assert_eq!(eq.compare_to, 0);

        let unrel = CompareResult::UNREL_LT;
        assert!(!unrel.related);
        assert_eq!(unrel.compare_to, -1);
    }

    #[test]
    fn test_compare_result_related_factory() {
        assert_eq!(
            CompareResult::related(std::cmp::Ordering::Less),
            CompareResult::REL_LT
        );
        assert_eq!(
            CompareResult::related(std::cmp::Ordering::Equal),
            CompareResult::EQUALS
        );
        assert_eq!(
            CompareResult::related(std::cmp::Ordering::Greater),
            CompareResult::REL_GT
        );
    }

    // === TimeRadix tests ===

    #[test]
    fn test_time_radix_dec() {
        let radix = TimeRadix::dec();
        assert_eq!(radix.format(42), "42");
        assert_eq!(radix.decode("42").unwrap(), 42);
        assert_eq!(radix.decode("0xff").unwrap(), 255);
    }

    #[test]
    fn test_time_radix_hex() {
        let radix = TimeRadix::hex_lower();
        assert_eq!(radix.format(255), "ff");
        assert_eq!(radix.decode("ff").unwrap(), 255);
    }

    #[test]
    fn test_time_radix_hex_prefix() {
        let radix = TimeRadix::dec();
        assert_eq!(radix.decode("0x10").unwrap(), 16);
        assert_eq!(radix.decode("0n10").unwrap(), 10);
        assert_eq!(radix.decode("-0x10").unwrap(), -16);
    }

    // === ScheduleForm tests ===

    #[test]
    fn test_schedule_form_hierarchy() {
        let snap_only = TraceSchedule::snap(0);
        assert!(ScheduleForm::SnapOnly.contains_basic(&snap_only));
        assert!(ScheduleForm::SnapEvtSteps.contains_basic(&snap_only));
        assert!(ScheduleForm::SnapAnySteps.contains_basic(&snap_only));
        assert!(ScheduleForm::SnapAnyStepsOps.contains_basic(&snap_only));
    }

    #[test]
    fn test_schedule_form_with_steps() {
        let s = TraceSchedule::parse("0:5").unwrap();
        assert!(!ScheduleForm::SnapOnly.contains_basic(&s));
        assert!(ScheduleForm::SnapAnySteps.contains_basic(&s));
        assert!(ScheduleForm::SnapAnyStepsOps.contains_basic(&s));
    }

    #[test]
    fn test_schedule_form_with_pcode() {
        let s = TraceSchedule::parse("0:3.2").unwrap();
        assert!(!ScheduleForm::SnapOnly.contains_basic(&s));
        assert!(!ScheduleForm::SnapEvtSteps.contains_basic(&s));
        assert!(!ScheduleForm::SnapAnySteps.contains_basic(&s));
        assert!(ScheduleForm::SnapAnyStepsOps.contains_basic(&s));
    }

    // === PatchStep tests ===

    #[test]
    fn test_patch_step_generate_sleigh() {
        let reg = PatchStep::generate_register_sleigh("r0", &[0x12, 0x34], true);
        assert_eq!(reg, "r0=0x1234");

        let mem = PatchStep::generate_memory_sleigh(0x400000, 4, &[0xde, 0xad, 0xbe, 0xef], true);
        assert_eq!(mem, "*0x400000:4=0xdeadbeef");

        let goto = PatchStep::generate_goto_sleigh(0x401000);
        assert_eq!(goto, "goto 0x401000");
    }

    #[test]
    fn test_patch_step_parse_display_roundtrip() {
        let step = PatchStep::new(-1, "r0=0x1234");
        let display = step.to_string();
        assert_eq!(display, "{r0=0x1234}");

        let step = PatchStep::new(1, "r0=0x1234");
        let display = step.to_string();
        assert_eq!(display, "t1-{r0=0x1234}");
    }

    // === ScheduleSource tests ===

    #[test]
    fn test_schedule_source_adjust_record() {
        // Record with no patches/skips stays Record
        assert_eq!(ScheduleSource::Record.adjust(0, 0, 0), ScheduleSource::Record);
        // Record with pcode ticks stays Record
        assert_eq!(ScheduleSource::Record.adjust(5, 0, 0), ScheduleSource::Record);
        // Record with patches becomes Input
        assert_eq!(ScheduleSource::Record.adjust(0, 1, 0), ScheduleSource::Input);
    }

    #[test]
    fn test_schedule_source_adjust_input() {
        // Input with no pcode steps becomes Record
        assert_eq!(ScheduleSource::Input.adjust(0, 0, 0), ScheduleSource::Record);
        // Input with 1 pcode tick becomes Record
        assert_eq!(ScheduleSource::Input.adjust(1, 0, 0), ScheduleSource::Record);
        // Input with >1 pcode ticks stays Input
        assert_eq!(ScheduleSource::Input.adjust(2, 0, 0), ScheduleSource::Input);
    }

    // === Differs-only-by-patch tests ===

    #[test]
    fn test_differs_only_by_patch_same() {
        let a = TraceSchedule::parse("0:3").unwrap();
        let b = TraceSchedule::parse("0:3").unwrap();
        assert!(a.differs_only_by_patch(&b));
    }

    #[test]
    fn test_differs_only_by_patch_different_snap() {
        let a = TraceSchedule::snap(0);
        let b = TraceSchedule::snap(1);
        assert!(!a.differs_only_by_patch(&b));
    }

    #[test]
    fn test_sequence_differs_only_by_patch() {
        let a = Sequence::parse("5", TimeRadix::dec()).unwrap();
        let b = Sequence::parse("5", TimeRadix::dec()).unwrap();
        assert!(a.differs_only_by_patch(&b));
    }

    // === Complex schedule construction tests ===

    #[test]
    fn test_complex_schedule_construction() {
        // Build a schedule: snap=5, 3 instruction ticks on thread 1,
        // then 2 pcode ticks on thread 2
        let mut steps = Sequence::empty();
        steps.advance_step(StepEnum::Tick(TickStep::new(1, 3)));

        let mut p_steps = Sequence::empty();
        p_steps.advance_step(StepEnum::Tick(TickStep::new(2, 2)));

        let sched = TraceSchedule::new(5, steps, p_steps, ScheduleSource::Record);
        assert_eq!(sched.get_snap(), 5);
        assert_eq!(sched.tick_count(), 3);
        assert_eq!(sched.p_tick_count(), 2);
        assert_eq!(sched.total_tick_count(), 5);
    }

    #[test]
    fn test_schedule_ordering() {
        let a = TraceSchedule::snap(0);
        let b = TraceSchedule::snap(1);
        let c = TraceSchedule::parse("0:5").unwrap();
        let d = TraceSchedule::parse("0:10").unwrap();

        assert!(a < b);
        assert!(a < c);
        assert!(c < d);
    }

    #[test]
    fn test_schedule_compare_unrelated_different_snaps() {
        let a = TraceSchedule::snap(5);
        let b = TraceSchedule::snap(10);
        let cmp = a.compare_schedule(&b);
        assert!(!cmp.related);
        assert_eq!(cmp.compare_to, -1);
    }

    #[test]
    fn test_schedule_last_thread_key() {
        let s = TraceSchedule::parse("0:t1-5").unwrap();
        assert_eq!(s.last_thread_key(), 1);

        let s2 = TraceSchedule::parse("0:5.3").unwrap();
        assert_eq!(s2.last_thread_key(), -1);
    }

    // === Sequence advanced operations ===

    #[test]
    fn test_sequence_advance_seq_combines() {
        let a = Sequence::parse("5", TimeRadix::dec()).unwrap();
        let b = Sequence::parse("3", TimeRadix::dec()).unwrap();
        let mut result = Sequence::empty();
        result.advance_seq(&a);
        result.advance_seq(&b);
        assert_eq!(result.count(), 1);
        assert_eq!(result.total_tick_count(), 8);
    }

    #[test]
    fn test_sequence_last_thread_key() {
        let seq = Sequence::parse("5;t1-3", TimeRadix::dec()).unwrap();
        assert_eq!(seq.last_thread_key(), 1);

        let seq2 = Sequence::parse("5", TimeRadix::dec()).unwrap();
        assert_eq!(seq2.last_thread_key(), -1);
    }
}
