//! Comprehensive integration tests for the new remaining Debug modules.
//!
//! These tests exercise the new modules created to fill gaps in the
//! ghidra-debug crate: enhanced coordinates, target lifecycle, breakpoint
//! management, trace lifecycle, emulation sessions, static mapping, and
//! control service.

#[cfg(test)]
mod new_comprehensive_tests {
    mod coordinates_enhanced_tests {
        use crate::api::tracemgr::DebuggerCoordinates;
        use crate::api::coordinates_enhanced::*;

        #[test]
        fn viewport_navigation_flow() {
            let mut vp = TimeViewport::at(0);
            assert_eq!(vp.span_length(), 1);
            for i in 1..=10 {
                vp.expand_to(i);
            }
            assert_eq!(vp.min_snap, 0);
            assert_eq!(vp.max_snap, 10);
            assert_eq!(vp.span_length(), 11);
            vp.shift(5);
            assert_eq!(vp.min_snap, 5);
            assert_eq!(vp.max_snap, 15);
        }

        #[test]
        fn coordinate_filter_workflow() {
            let coords_list = vec![
                DebuggerCoordinates::trace(1).with_snap(0),
                DebuggerCoordinates::trace(1).with_snap(5),
                DebuggerCoordinates::trace(2).with_snap(0),
            ];
            let filter = CoordinateFilter::for_trace(1);
            let filtered: Vec<_> = coords_list.iter().filter(|c| filter.matches(c)).collect();
            assert_eq!(filtered.len(), 2);

            let filter = CoordinateFilter::for_trace(1).with_snap(0);
            let filtered: Vec<_> = coords_list.iter().filter(|c| filter.matches(c)).collect();
            assert_eq!(filtered.len(), 1);
        }

        #[test]
        fn coordinate_set_multi_trace() {
            let mut set = CoordinateSet::new();
            for i in 0..5 {
                let coords =
                    DebuggerCoordinates::trace(i as i64).with_snap(i * 10);
                set.focus(coords);
            }
            assert_eq!(set.len(), 5);
            assert!(set.get_focused().is_some());
        }

        #[test]
        fn coordinates_ext_navigation_chain() {
            let base = DebuggerCoordinates::trace(1);
            let nav = base.go_snap(10).go_thread(42).go_innermost_frame();
            assert!(nav.is_complete());
            assert_eq!(nav.snap, Some(10));
            assert_eq!(nav.thread_key, Some(42));
            let summary = nav.display_summary();
            assert!(summary.contains("trace=1"));
        }

        #[test]
        fn coordinate_filter_snap_range() {
            let filter = CoordinateFilter::new().with_snap_range(0, 100);
            assert!(filter.matches(&DebuggerCoordinates::trace(99).with_snap(50)));
            assert!(!filter.matches(&DebuggerCoordinates::trace(99).with_snap(200)));
            assert!(!filter.matches(&DebuggerCoordinates::trace(99)));
        }
    }

    mod target_enhanced_tests {
        use crate::api::target_enhanced::*;
        use crate::model::TraceExecutionState;

        struct SimpleTarget {
            threads: Vec<ThreadInfo>,
        }

        impl SimpleTarget {
            fn new() -> Self {
                Self {
                    threads: vec![
                        ThreadInfo {
                            key: 1,
                            name: "main".into(),
                            tid: Some(100),
                            is_focused: true,
                            state: TraceExecutionState::Running,
                        },
                        ThreadInfo {
                            key: 2,
                            name: "bg".into(),
                            tid: Some(101),
                            is_focused: false,
                            state: TraceExecutionState::Stopped,
                        },
                    ],
                }
            }
        }

        impl TargetExtended for SimpleTarget {
            fn interrupt(&mut self) -> Result<(), String> {
                for t in &mut self.threads {
                    t.state = TraceExecutionState::Stopped;
                }
                Ok(())
            }
            fn kill(&mut self) -> Result<(), String> {
                self.threads.clear();
                Ok(())
            }
            fn attach(&mut self, pid: u64) -> Result<AttachResult, String> {
                Ok(AttachResult { process_key: pid as i64, message: None })
            }
            fn launch(&mut self, _: &str, _: &[String], _: Option<&str>) -> Result<LaunchResult, String> {
                Ok(LaunchResult { process_key: 1, main_thread_key: Some(1), message: None })
            }
            fn connect(&mut self, _: &str, _: u16) -> Result<ConnectResult, String> {
                Ok(ConnectResult { connection_id: "c1".into(), message: None })
            }
            fn activate_thread(&mut self, key: i64) -> Result<(), String> {
                for t in &mut self.threads { t.is_focused = t.key == key; }
                Ok(())
            }
            fn activate_process(&mut self, _: i64) -> Result<(), String> { Ok(()) }
            fn get_threads(&self) -> Result<Vec<ThreadInfo>, String> { Ok(self.threads.clone()) }
            fn get_processes(&self) -> Result<Vec<ProcessInfo>, String> { Ok(vec![]) }
            fn get_stack_frames(&self, _: i64) -> Result<Vec<StackFrameInfo>, String> { Ok(vec![]) }
            fn get_memory_regions(&self) -> Result<Vec<MemoryRegionInfo>, String> { Ok(vec![]) }
            fn get_registers(&self, _: i64) -> Result<Vec<RegisterInfo>, String> { Ok(vec![]) }
            fn step_back(&mut self, _: Option<i64>) -> Result<(), String> { Err("No".into()) }
            fn skip_over(&mut self, _: Option<i64>) -> Result<(), String> { Ok(()) }
            fn execute_command(&mut self, cmd: &str, _: &[String]) -> Result<String, String> { Ok(cmd.into()) }
            fn capabilities(&self) -> TargetCapabilities { TargetCapabilities::default() }
        }

        #[test]
        fn thread_query_and_activation() {
            let mut target = SimpleTarget::new();
            assert_eq!(target.get_threads().unwrap().len(), 2);
            target.activate_thread(2).unwrap();
            assert!(target.get_threads().unwrap().iter().find(|t| t.key == 2).unwrap().is_focused);
        }

        #[test]
        fn interrupt_and_kill() {
            let mut target = SimpleTarget::new();
            target.interrupt().unwrap();
            assert!(target.get_threads().unwrap().iter().all(|t| t.state == TraceExecutionState::Stopped));
            target.kill().unwrap();
            assert!(target.get_threads().unwrap().is_empty());
        }
    }

    mod breakpoint_lifecycle_tests {
        use crate::api::breakpoint::LogicalBreakpoint;
        use crate::model::breakpoint::TraceBreakpointKind;
        use crate::services::breakpoint_lifecycle::*;

        #[test]
        fn manager_full_lifecycle() {
            let mut mgr = LogicalBreakpointManager::new();
            mgr.add_program_breakpoint("prog1", 0x400000, "0x400000", vec![TraceBreakpointKind::HwExecute]);
            mgr.add_program_breakpoint("prog1", 0x400100, "0x400100", vec![]);
            mgr.add_program_breakpoint("prog2", 0x500000, "0x500000", vec![]);
            assert_eq!(mgr.total_program_breakpoints(), 3);

            mgr.toggle_breakpoint("prog1", 0x400000);
            assert!(!mgr.program_breakpoints().get(&("prog1".into(), 0x400000)).unwrap().is_enabled());

            {
                let set = mgr.trace_set_mut("trace1");
                set.insert(LogicalBreakpoint::new(0x400000, "0x400000"));
            }
            assert_eq!(mgr.trace_set("trace1").unwrap().len(), 1);

            mgr.begin_synchronize();
            assert!(mgr.is_synchronizing());
            mgr.end_synchronize();
        }

        #[test]
        fn trace_breakpoint_set_sync() {
            let mut set = TraceBreakpointSet::new("trace1");
            set.insert(LogicalBreakpoint::new(0x1000, "0x1000"));
            set.insert(LogicalBreakpoint::new(0x2000, "0x2000"));

            let actions = set.compute_sync_actions(true);
            assert_eq!(actions.len(), 2);

            set.disable_all();
            let actions = set.compute_sync_actions(true);
            assert!(actions.iter().all(|(_, s)| s.contains(&BreakpointActionItem::DisableTarget)));
        }
    }

    mod trace_lifecycle_tests {
        use crate::services::trace_lifecycle::*;

        #[test]
        fn full_workflow() {
            let mut mgr = TraceManagerService::new();
            let k1 = mgr.open_trace("First");
            let k2 = mgr.open_trace("Second");
            assert_eq!(mgr.len(), 2);

            mgr.activate_trace(&k1).unwrap();
            assert_eq!(mgr.active_trace_key(), Some(k1.as_str()));

            mgr.mark_trace_changed(&k1);
            assert!(mgr.has_unsaved_changes());
            mgr.save_trace(&k1, "/tmp/f.bin").unwrap();
            assert!(!mgr.has_unsaved_changes());

            mgr.activate_trace(&k2).unwrap();
            mgr.close_trace(&k1).unwrap();
            mgr.remove_trace(&k1);
            mgr.remove_trace(&k2);
            assert!(mgr.is_empty());
        }

        #[test]
        fn save_task_progress() {
            let mut task = SaveTask::new("t", "/tmp/o.bin", true);
            assert!(task.is_save_as);
            task.set_progress(0.5);
            task.complete();
            assert!(task.completed);
            assert_eq!(task.progress, 1.0);
        }
    }

    mod emulation_lifecycle_tests {
        use crate::services::emulation_lifecycle::*;

        #[test]
        fn session_bidirectional() {
            let mut session = EmulationSession::new("t1", EmulationMode::Bidirectional).with_max_steps(100);
            session.start(0x400000);
            for i in 1..=5 { session.step(0x400000 + i * 4).unwrap(); }
            assert_eq!(session.steps_taken, 5);
            assert_eq!(session.snapshot_count(), 6);

            session.step_back().unwrap();
            assert_eq!(session.current_snap, 4);

            session.pause();
            session.resume();
            session.stop();
            assert!(session.is_finished());
        }

        #[test]
        fn manager_multiple_sessions() {
            let mut mgr = EmulationManager::new();
            { let s = mgr.start_session("t1", EmulationMode::Forward); s.start(0x100); }
            { let s = mgr.start_session("t2", EmulationMode::Bidirectional); s.start(0x200); }
            assert_eq!(mgr.active_count(), 2);

            if let Some(s) = mgr.active_session_for_mut("t1") { s.stop(); }
            assert_eq!(mgr.active_count(), 1);
        }

        #[test]
        fn error_handling() {
            let mut session = EmulationSession::new("t1", EmulationMode::Forward);
            session.start(0x100);
            session.error("segfault");
            assert_eq!(session.state, EmulationSessionState::Error);
            assert!(session.is_finished());
        }
    }

    mod static_mapping_tests {
        use crate::services::static_mapping_service::*;

        #[test]
        fn full_mapping_workflow() {
            let mut svc = StaticMappingService::new();
            svc.add_mapping(StaticMappingEntry::new("trace1", 0x1000, 0x100, "prog://main", 0x400000, 0x100));
            svc.add_mapping(StaticMappingEntry::new("trace1", 0x2000, 0x100, "prog://main", 0x400100, 0x100));
            assert_eq!(svc.len(), 2);

            assert_eq!(svc.translate_trace_to_program("trace1", 0x1050), Some(0x400050));
            assert_eq!(svc.translate_program_to_trace("prog://main", 0x400150), Some(0x2050));
            assert_eq!(svc.mappings_for_trace("trace1").len(), 2);
            assert_eq!(svc.events().len(), 2);
        }

        #[test]
        fn overlap_detection() {
            let mut svc = StaticMappingService::new();
            svc.add_mapping(StaticMappingEntry::new("t1", 0x1000, 0x200, "p1", 0, 0x200));
            svc.add_mapping(StaticMappingEntry::new("t1", 0x0F00, 0x200, "p2", 0, 0x200));
            svc.add_mapping(StaticMappingEntry::new("t1", 0x5000, 0x100, "p3", 0, 0x100));
            assert_eq!(svc.find_overlapping().len(), 1);
        }
    }

    mod control_service_tests {
        use crate::api::control_mode::ControlMode;
        use crate::services::control_service::*;

        #[test]
        fn mode_switching() {
            let mut svc = ControlService::new(ControlMode::RwTarget);
            assert!(svc.is_live());
            assert!(svc.can_edit_state());
            assert!(svc.can_step());

            svc.set_mode(ControlMode::RoTrace);
            assert!(!svc.is_live());
            assert!(!svc.can_edit_state());
            assert!(!svc.can_step());
        }

        #[test]
        fn action_queue() {
            let mut svc = ControlService::new(ControlMode::RwTarget);
            for i in 0..5 {
                svc.enqueue_action(PendingControlAction {
                    action: format!("step_{}", i),
                    thread_key: Some(i),
                    args: vec![],
                    queued_at: None,
                });
            }
            assert_eq!(svc.pending_action_count(), 5);
            svc.dequeue_action().unwrap();
            assert_eq!(svc.pending_action_count(), 4);
            svc.clear_pending_actions();
            assert_eq!(svc.pending_action_count(), 0);
        }

        #[test]
        fn edit_permission_all_modes() {
            let modes = [
                (ControlMode::RoTarget, StateEditPermission::ReadOnly),
                (ControlMode::RwTarget, StateEditPermission::LiveEdit),
                (ControlMode::RoTrace, StateEditPermission::ReadOnly),
                (ControlMode::RwTrace, StateEditPermission::TraceEdit),
                (ControlMode::RoEmulator, StateEditPermission::ReadOnly),
                (ControlMode::RwEmulator, StateEditPermission::EmulatorEdit),
            ];
            for (mode, expected) in &modes {
                let svc = ControlService::new(*mode);
                assert_eq!(svc.edit_permission(), *expected, "mode={:?}", mode);
            }
        }
    }

    mod cross_module_integration {
        use crate::api::breakpoint::LogicalBreakpoint;
        use crate::api::control_mode::ControlMode;
        use crate::api::tracemgr::DebuggerCoordinates;
        use crate::api::coordinates_enhanced::*;
        use crate::model::breakpoint::TraceBreakpointKind;
        use crate::services::breakpoint_lifecycle::*;
        use crate::services::control_service::*;
        use crate::services::emulation_lifecycle::*;
        use crate::services::static_mapping_service::*;
        use crate::services::trace_lifecycle::*;

        #[test]
        fn full_debug_session_workflow() {
            let mut trace_mgr = TraceManagerService::new();
            let trace_name = trace_mgr.open_trace("Debug Session 1");
            trace_mgr.activate_trace(&trace_name).unwrap();

            // Use a numeric trace key for the tracemgr::DebuggerCoordinates
            let coords = DebuggerCoordinates::trace(1)
                .with_snap(0)
                .with_thread(1);
            assert!(coords.is_complete());

            let mut ctrl = ControlService::new(ControlMode::RwTarget);
            assert!(ctrl.can_step());

            let mut bp_mgr = LogicalBreakpointManager::new();
            bp_mgr.add_program_breakpoint("prog1", 0x400000, "0x400000", vec![TraceBreakpointKind::HwExecute]);
            assert_eq!(bp_mgr.total_program_breakpoints(), 1);

            let mut mapping = StaticMappingService::new();
            mapping.add_mapping(StaticMappingEntry::new(
                &trace_name, 0x1000, 0x10000, "prog://main", 0x400000, 0x10000,
            ));
            assert_eq!(mapping.translate_trace_to_program(&trace_name, 0x1500), Some(0x400500));

            ctrl.enqueue_action(PendingControlAction {
                action: "step_into".into(),
                thread_key: Some(1),
                args: vec![],
                queued_at: None,
            });

            let mut emu_mgr = EmulationManager::new();
            {
                let session = emu_mgr.start_session(&trace_name, EmulationMode::Forward);
                session.start(0x400000);
                session.step(0x400004).unwrap();
            }
            assert_eq!(emu_mgr.active_count(), 1);

            trace_mgr.mark_trace_changed(&trace_name);
            assert!(trace_mgr.has_unsaved_changes());
            trace_mgr.save_trace(&trace_name, "/tmp/debug_session.bin").unwrap();
            assert!(!trace_mgr.has_unsaved_changes());

            ctrl.clear_pending_actions();
            emu_mgr.remove_session(&trace_name);
            trace_mgr.close_trace(&trace_name).unwrap();

            assert_eq!(ctrl.pending_action_count(), 0);
            assert!(emu_mgr.is_empty());
        }

        #[test]
        fn serialization_roundtrip() {
            let coords = DebuggerCoordinates::trace(1).with_snap(5).with_thread(1);
            let json = serde_json::to_string(&coords).unwrap();
            let back: DebuggerCoordinates = serde_json::from_str(&json).unwrap();
            assert_eq!(back.trace_key, Some(1));

            let entry = StaticMappingEntry::new("t1", 0x1000, 0x100, "p1", 0x400000, 0x100);
            let json = serde_json::to_string(&entry).unwrap();
            let back: StaticMappingEntry = serde_json::from_str(&json).unwrap();
            assert_eq!(back.trace_start, 0x1000);

            let mut session = EmulationSession::new("t1", EmulationMode::Forward);
            session.start(0x100);
            let json = serde_json::to_string(&session).unwrap();
            let back: EmulationSession = serde_json::from_str(&json).unwrap();
            assert_eq!(back.trace_key, "t1");
        }
    }
}
