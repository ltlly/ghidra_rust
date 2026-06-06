//! Comprehensive tests for the Debug module port from Java to Rust.
//!
//! Tests cover all three Java source directories:
//! - Framework-TraceModeling (model, database, target, pcode, util)
//! - Debugger-api (api, services)
//! - Debugger (plugin, service implementations)

#[cfg(test)]
mod model_tests {
    use crate::model::*;

    #[test]
    fn test_execution_state_inactive() {
        let state = TraceExecutionState::Inactive;
        assert!(!state.is_active());
        assert!(!state.is_alive());
        assert!(state.is_inactive());
        assert!(!state.is_terminal());
        assert_eq!(state.ghidra_name(), "INACTIVE");
    }

    #[test]
    fn test_execution_state_alive() {
        let state = TraceExecutionState::Alive;
        assert!(!state.is_active());
        assert!(state.is_alive());
        assert!(state.can_resume());
        assert!(!state.is_terminal());
        assert_eq!(state.ghidra_name(), "ALIVE");
    }

    #[test]
    fn test_execution_state_running() {
        let state = TraceExecutionState::Running;
        assert!(state.is_active());
        assert!(state.is_alive());
        assert!(!state.can_resume());
        assert_eq!(state.ghidra_name(), "RUNNING");
    }

    #[test]
    fn test_execution_state_stopped() {
        let state = TraceExecutionState::Stopped;
        assert!(!state.is_active());
        assert!(state.is_alive());
        assert!(state.can_resume());
        assert_eq!(state.ghidra_name(), "STOPPED");
    }

    #[test]
    fn test_execution_state_terminated() {
        let state = TraceExecutionState::Terminated;
        assert!(!state.is_active());
        assert!(state.is_terminal());
        assert_eq!(state.ghidra_name(), "TERMINATED");
    }

    #[test]
    fn test_execution_state_detached() {
        let state = TraceExecutionState::Detached;
        assert!(!state.is_active());
        assert!(state.is_terminal());
        assert_eq!(state.ghidra_name(), "DETACHED");
    }

    #[test]
    fn test_execution_state_serde_roundtrip() {
        let states = vec![
            TraceExecutionState::Inactive,
            TraceExecutionState::Alive,
            TraceExecutionState::Running,
            TraceExecutionState::Stopped,
            TraceExecutionState::Terminated,
            TraceExecutionState::Unknown,
            TraceExecutionState::Attaching,
            TraceExecutionState::Detached,
        ];
        for state in &states {
            let json = serde_json::to_string(state).unwrap();
            let back: TraceExecutionState = serde_json::from_str(&json).unwrap();
            assert_eq!(*state, back);
        }
    }

    #[test]
    fn test_immutable_range_centered() {
        let range = crate::model::trace_address_snap_range::ImmutableTraceAddressSnapRange::centered(
            0x1000, 5, 0x100, 2, "ram",
        );
        assert_eq!(range.min_address, 0xF00);
        assert_eq!(range.max_address, 0x1100);
        assert!(range.lifespan.contains(3));
        assert!(!range.lifespan.contains(8));
    }

    #[test]
    fn test_immutable_range_at_point() {
        let range = crate::model::trace_address_snap_range::ImmutableTraceAddressSnapRange::at_point(
            0x400000, 0, "ram",
        );
        assert_eq!(range.min_address, 0x400000);
        assert_eq!(range.max_address, 0x400000);
    }

    #[test]
    fn test_immutable_range_address_breadth() {
        let range = crate::model::trace_address_snap_range::ImmutableTraceAddressSnapRange::new(
            0x100, 0x1FF, Lifespan::at(0), "ram",
        );
        assert_eq!(range.address_breadth(), 0x100);
    }

    #[test]
    fn test_immutable_range_encloses() {
        let outer = crate::model::trace_address_snap_range::ImmutableTraceAddressSnapRange::new(
            0x0, 0x1000, Lifespan::span(0, 100), "ram",
        );
        let inner = crate::model::trace_address_snap_range::ImmutableTraceAddressSnapRange::new(
            0x100, 0x200, Lifespan::span(10, 20), "ram",
        );
        assert!(outer.encloses(&inner));
        assert!(!inner.encloses(&outer));
    }

    #[test]
    fn test_static_mapping_lifespan() {
        let m = TraceStaticMapping::with_lifespan(
            1, 0x400000, 0x400FFF, 0x0, "file:///tmp/prog",
            Lifespan::span(0, 100),
        );
        assert_eq!(m.start_snap(), 0);
        assert_eq!(m.end_snap(), 100);
        assert!(m.is_active_at(50));
        assert!(!m.is_active_at(101));
    }

    #[test]
    fn test_static_mapping_length_and_shift() {
        let m = TraceStaticMapping::new(1, 0x400000, 0x400FFF, 0x100000, "file:///tmp/prog");
        assert_eq!(m.length(), 0x1000);
        assert_eq!(m.shift(), 0x300000);
    }

    #[test]
    fn test_static_mapping_conflicts_different_program() {
        let m = TraceStaticMapping::with_lifespan(
            1, 0x400000, 0x400FFF, 0x0, "file:///tmp/prog1",
            Lifespan::now_on(0),
        );
        assert!(m.conflicts_with(0x400000, 0x400FFF, &Lifespan::now_on(0), "file:///tmp/prog2", 0x0));
    }

    #[test]
    fn test_conflicted_mapping_exception() {
        let exc = TraceConflictedMappingException::new("overlapping range", vec![]);
        assert!(exc.conflicts.is_empty());
        assert!(exc.message.contains("overlapping"));
    }

    #[test]
    fn test_domain_object_listener_dispatch() {
        use crate::model::domain_object_listener::*;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        let counter = Arc::new(AtomicUsize::new(0));
        let c = counter.clone();
        let mut listener = TraceDomainObjectListener::new();
        listener.add_handler(
            DomainObjectEvent::PropertyChanged,
            Box::new(move |_| { c.fetch_add(1, Ordering::SeqCst); }),
        );
        let event = DomainObjectChangedEvent::new(vec![DomainObjectChangeRecord::new(
            DomainObjectEvent::PropertyChanged, 1,
        )]);
        listener.domain_object_changed(&event);
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_options_manager_language_id() {
        let lang = TraceLanguageId::new("x86:LE:64:default");
        assert_eq!(lang.architecture(), "x86");
        assert_eq!(lang.endianness(), Some("LE"));
        assert_eq!(lang.bits(), Some("64"));
    }

    #[test]
    fn test_options_manager_set_all_fields() {
        let mut opts = TraceOptionsManagerExt::new();
        opts.set_name("My Trace");
        opts.set_base_language_id(TraceLanguageId::new("ARM:LE:32:v8"));
        opts.set_compiler_spec_id(CompilerSpecId::new("default"));
        opts.set_platform("linux-arm");
        assert_eq!(opts.name(), "My Trace");
        assert_eq!(opts.platform(), Some("linux-arm"));
    }

    #[test]
    fn test_lifespan_intersect() {
        let a = Lifespan::span(0, 10);
        let b = Lifespan::span(5, 15);
        let i = a.intersect(&b);
        assert_eq!(i.lmin(), 5);
        assert_eq!(i.lmax(), 10);
    }

    #[test]
    fn test_lifespan_bound() {
        let a = Lifespan::span(0, 10);
        let b = Lifespan::span(5, 20);
        let u = a.bound(&b);
        assert_eq!(u.lmin(), 0);
        assert_eq!(u.lmax(), 20);
    }

    #[test]
    fn test_step_kind_variants() {
        use crate::model::time_schedule::StepKind;
        assert_eq!(StepKind::Instruction, StepKind::Instruction);
        assert_ne!(StepKind::Instruction, StepKind::PcodeOp);
    }

    #[test]
    fn test_memory_state_variants() {
        let state = TraceMemoryState::Known;
        assert_eq!(state, TraceMemoryState::Known);
        assert_ne!(state, TraceMemoryState::Unknown);
    }

    #[test]
    fn test_trace_platform_new() {
        let p = TracePlatform::new(1, "x86:LE:64:default", "gcc");
        assert_eq!(p.key, 1);
        assert!(p.is_64_bit());
        assert!(!p.is_big_endian());
        assert_eq!(p.processor(), "x86");
    }

    #[test]
    fn test_guest_platform_mapped_range() {
        let r = TraceGuestPlatformMappedRange {
            guest_platform_key: 1,
            guest_min: 0x0,
            guest_max: 0xFFFF,
            host_min: 0x7F00000000,
            lifespan: Lifespan::now_on(0),
        };
        assert_eq!(r.guest_platform_key, 1);
    }
}

#[cfg(test)]
mod db_tests {
    use crate::db::*;

    #[test]
    fn test_trace_database_config() {
        let config = TraceDatabaseConfig::new("test_trace", "x86:LE:64:default");
        assert_eq!(config.language_id, "x86:LE:64:default");
        assert_eq!(config.name, "test_trace");
    }

    #[test]
    fn test_trace_db_error() {
        let err = TraceDbError::NotFound("test entity".into());
        assert!(format!("{}", err).contains("Not found"));
    }

    #[test]
    fn test_transaction_creation() {
        let tx = TraceTransaction {
            id: 1,
            description: "test op".into(),
            committed: false,
            operation_count: 0,
        };
        assert_eq!(tx.description, "test op");
        assert!(!tx.committed);
    }

    #[test]
    fn test_snapshot_new() {
        let snap = DbTraceSnapshot {
            key: 0,
            timestamp: 0,
            scratch: false,
            description: "Initial".into(),
            thread_key: None,
        };
        assert_eq!(snap.key, 0);
        assert!(!snap.scratch);
    }

    #[test]
    fn test_static_mapping_manager_new() {
        let mgr = DbTraceStaticMappingManager::new();
        assert!(mgr.is_empty());
        assert_eq!(mgr.len(), 0);
    }

    #[test]
    fn test_module_manager_new() {
        let _mgr = DbTraceModuleManager::new();
    }

    #[test]
    fn test_bookmark_type() {
        let bt = DbTraceBookmarkType::new(1, "Note");
        assert_eq!(bt.type_string, "Note");
        assert_eq!(bt.type_id, 1);
    }

    #[test]
    fn test_value_box() {
        let vb = ValueBox::new(vec![0x48u8, 0x89, 0xE5]);
        assert_eq!(vb.get(), &[0x48, 0x89, 0xE5]);
    }
}

#[cfg(test)]
mod api_tests {
    use crate::api::*;

    #[test]
    fn test_action_name_variants() {
        let name = ActionName::Step;
        let json = serde_json::to_string(&name).unwrap();
        let back: ActionName = serde_json::from_str(&json).unwrap();
        assert_eq!(name, back);
    }

    #[test]
    fn test_action_name_all_variants() {
        let variants = vec![
            ActionName::Continue, ActionName::Step, ActionName::StepInto,
            ActionName::StepOver, ActionName::StepOut, ActionName::Kill,
            ActionName::Attach, ActionName::Detach, ActionName::Launch,
            ActionName::Connect,
        ];
        for v in variants {
            let json = serde_json::to_string(&v).unwrap();
            let back: ActionName = serde_json::from_str(&json).unwrap();
            assert_eq!(v, back);
        }
    }

    #[test]
    fn test_logical_breakpoint() {
        let bp = LogicalBreakpoint::new(0x400000, "0x400000");
        assert_eq!(bp.offset, 0x400000);
        assert!(bp.is_enabled());
    }

    #[test]
    fn test_control_mode() {
        assert_ne!(ControlMode::RoTarget, ControlMode::RwTarget);
        assert_ne!(ControlMode::RoTrace, ControlMode::RwTrace);
    }

    #[test]
    fn test_flat_api_error() {
        let err = FlatApiError::NoActiveTrace;
        assert_eq!(format!("{}", err), "No active trace");
    }

    #[test]
    fn test_val_str() {
        let vs = ValStr::new(42u64);
        assert_eq!(vs.value, 42);
        assert_eq!(vs.display, "42");
    }

    #[test]
    fn test_val_str_with_display() {
        let vs = ValStr::with_display(42u64, "0x2A");
        assert_eq!(vs.value, 42);
        assert_eq!(vs.display, "0x2A");
    }

    #[test]
    fn test_debugger_coordinates() {
        let coords = DebuggerCoordinates::none();
        assert!(!coords.has_trace());
        assert!(!coords.has_thread());
    }

    #[test]
    fn test_debugger_coordinates_for_trace() {
        let coords = DebuggerCoordinates::trace(1).with_snap(5).with_thread(1);
        assert!(coords.has_trace());
        assert!(coords.has_thread());
    }
}

#[cfg(test)]
mod services_tests {
    use crate::services::*;

    #[test]
    fn test_mapping_proposal() {
        let p = MappingProposal {
            program_min: 0,
            program_max: 0x1000,
            trace_min: 0x400000,
            trace_max: 0x401000,
            confidence: 0.95,
        };
        assert!((p.confidence - 0.95).abs() < f64::EPSILON);
    }

    #[test]
    fn test_target_info() {
        let ti = TargetInfo {
            target_type: "gdb".into(),
            display_name: "GDB Remote".into(),
            supports_launch: true,
            supports_attach: true,
        };
        assert!(ti.supports_launch);
    }
}

#[cfg(test)]
mod plugin_tests {
    use crate::plugin::*;

    #[test]
    fn test_plugin_phase() {
        assert_eq!(PluginPhase::Initializing, PluginPhase::Initializing);
        assert_ne!(PluginPhase::Initializing, PluginPhase::Active);
    }

    #[test]
    fn test_extension_point_id() {
        let id = ExtensionPointId::new("com.example.MyPlugin");
        assert_eq!(id.class_name, "com.example.MyPlugin");
    }

    #[test]
    fn test_breakpoint_action_kind() {
        use crate::services::BreakpointActionKind;
        assert_ne!(BreakpointActionKind::Place, BreakpointActionKind::Delete);
    }
}

#[cfg(test)]
mod target_tests {
    use crate::target::*;

    #[test]
    fn test_key_path() {
        let path = KeyPath::new(vec!["Threads".into(), "0".into()]);
        assert_eq!(path.size(), 2);
        assert!(!path.is_root());
    }

    #[test]
    fn test_key_path_parent() {
        let path = KeyPath::new(vec!["Threads".into(), "0".into(), "Registers".into()]);
        let parent = path.parent();
        assert_eq!(parent.size(), 2);
    }

    #[test]
    fn test_path_pattern() {
        let pattern = PathPattern::new(KeyPath::of(&["Threads", "0"]));
        assert!(pattern.matches(&KeyPath::of(&["Threads", "0"])));
        assert!(!pattern.matches(&KeyPath::of(&["Threads", "1"])));
    }
}

#[cfg(test)]
mod schedule_tests {
    use crate::model::time_schedule::*;

    #[test]
    fn test_schedule_step() {
        let step = ScheduleStep::instruction(1);
        assert_eq!(step.count, 1);
    }

    #[test]
    fn test_schedule_sequence() {
        let mut seq = ScheduleSequence::new(0);
        seq.push(ScheduleStep::instruction(1));
        seq.push(ScheduleStep::pcode(2));
        assert_eq!(seq.total_steps(), 3);
    }

    #[test]
    fn test_scheduler() {
        let seq = ScheduleSequence::new(0);
        let scheduler = Scheduler::new(seq);
        assert!(scheduler.is_done());
    }
}

#[cfg(test)]
mod pcode_tests {
    #[test]
    fn test_trace_byte_state() {
        use crate::model::trace_emulation_state::TraceByteState;
        assert_eq!(TraceByteState::Known(0x42), TraceByteState::Known(0x42));
        assert_ne!(TraceByteState::Known(0x42), TraceByteState::Unknown);
    }
}
