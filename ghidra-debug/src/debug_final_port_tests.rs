//! Tests for the final batch of Debug modules ported from Java to Rust.
//!
//! Covers:
//! - SymPcodeExecutor (symbolic p-code execution for stack analysis)
//! - UnwindStackCommand (high-level stack unwind command)
//! - DynamicStaticSync (dynamic-static synchronization)
//! - EmulationDataAccess (pcode debugger data access layer)
//! - EmulationIntegration (emulator-target integration)

#[cfg(test)]
mod final_port_tests {
    // === SymPcodeExecutor tests ===
    mod sym_pcode_executor_tests {
        use crate::stack::sym::Sym;
        use crate::stack::sym_pcode_executor::{PcodeOpSymbolic, SymPcodeExecutor, VarnodeId};

        #[test]
        fn test_create_executor() {
            let exec = SymPcodeExecutor::new("RSP", false);
            assert_eq!(exec.ops_count(), 0);
        }

        #[test]
        fn test_create_executor_big_endian() {
            let exec = SymPcodeExecutor::new("SP", true);
            assert_eq!(exec.ops_count(), 0);
        }

        #[test]
        fn test_default_executor() {
            let exec = SymPcodeExecutor::default();
            assert_eq!(exec.ops_count(), 0);
        }

        #[test]
        fn test_execute_copy_constants() {
            let mut exec = SymPcodeExecutor::new("RSP", false);
            let result = exec.execute_op(&PcodeOpSymbolic::Copy {
                input: VarnodeId::Constant(0xABCD),
                output: VarnodeId::Register("rax".into()),
            });
            assert_eq!(result.as_const_value(), Some(0xABCD));
            assert_eq!(exec.ops_count(), 1);
        }

        #[test]
        fn test_execute_add_constants() {
            let mut exec = SymPcodeExecutor::new("RSP", false);
            let result = exec.execute_op(&PcodeOpSymbolic::IntAdd {
                a: VarnodeId::Constant(100),
                b: VarnodeId::Constant(200),
                output: VarnodeId::Register("sum".into()),
            });
            assert_eq!(result.as_const_value(), Some(300));
        }

        #[test]
        fn test_execute_sub_sp_produces_stack_offset() {
            let mut exec = SymPcodeExecutor::new("RSP", false);
            let sp_addr = crate::stack::sym_pcode_executor::register_name_to_addr("RSP");
            exec.state
                .write_sym("register", sp_addr, Sym::register("RSP", 8));
            let result = exec.execute_op(&PcodeOpSymbolic::IntSub {
                a: VarnodeId::Register("RSP".into()),
                b: VarnodeId::Constant(0x30),
                output: VarnodeId::Register("RSP".into()),
            });
            assert!(matches!(result, Sym::StackOffset(_)));
        }

        #[test]
        fn test_execute_int2comp() {
            let mut exec = SymPcodeExecutor::new("RSP", false);
            let result = exec.execute_op(&PcodeOpSymbolic::Int2Comp {
                input: VarnodeId::Constant(50),
                output: VarnodeId::Register("neg".into()),
            });
            assert_eq!(result.as_const_value(), Some(-50));
        }

        #[test]
        fn test_compute_map_using_stack() {
            let mut exec = SymPcodeExecutor::new("RSP", false);
            exec.state
                .write_sym("stack", -8, Sym::register("LR", 8));
            exec.state
                .write_sym("stack", -16, Sym::register("R29", 8));
            let map = exec.compute_map_using_stack();
            assert_eq!(map.len(), 2);
        }

        #[test]
        fn test_fork_regs() {
            let mut exec = SymPcodeExecutor::new("RSP", false);
            exec.state.write_sym("register", 1, Sym::constant(42));
            let forked = exec.fork_regs();
            assert_eq!(
                forked.read_sym("register", 1, 8).as_const_value(),
                Some(42)
            );
            assert!(forked.stack.is_empty());
        }

        #[test]
        fn test_varnode_id_serde_roundtrip() {
            let ids = vec![
                VarnodeId::Register("rsp".into()),
                VarnodeId::StackOffset(-16),
                VarnodeId::Constant(0xDEAD),
                VarnodeId::Unique(42),
            ];
            for id in ids {
                let json = serde_json::to_string(&id).unwrap();
                let back: VarnodeId = serde_json::from_str(&json).unwrap();
                assert_eq!(id, back);
            }
        }
    }

    // === UnwindStackCommand tests ===
    mod unwind_command_tests {
        use crate::stack::sym::Sym;
        use crate::stack::sym_pcode_executor::{PcodeOpSymbolic, SymPcodeExecutor, VarnodeId};
        use crate::stack::unwind_command::{build_unwind_info, UnwindStackCommand, UnwindStackCommandResult};
        use crate::stack::unwound_frame::{UnwindAnalysis, UnwoundFrame};

        #[test]
        fn test_command_creation() {
            let cmd = UnwindStackCommand::new(1, 42, 100);
            assert_eq!(cmd.trace_key, 1);
            assert_eq!(cmd.thread_key, 42);
            assert_eq!(cmd.snap, 100);
        }

        #[test]
        fn test_command_builder_chain() {
            let cmd = UnwindStackCommand::new(1, 2, 3)
                .with_max_frames(100)
                .with_start_frame(5)
                .with_apply_to_trace(false);
            assert_eq!(cmd.max_frames, 100);
            assert_eq!(cmd.start_frame, 5);
            assert!(!cmd.apply_to_trace);
        }

        #[test]
        fn test_command_serde() {
            let cmd = UnwindStackCommand::new(10, 20, 30);
            let json = serde_json::to_string(&cmd).unwrap();
            let back: UnwindStackCommand = serde_json::from_str(&json).unwrap();
            assert_eq!(back.trace_key, 10);
        }

        #[test]
        fn test_result_success() {
            let result = UnwindStackCommandResult::new();
            assert!(result.is_success());
            assert_eq!(result.frame_count(), 0);
        }

        #[test]
        fn test_result_failed() {
            let result = UnwindStackCommandResult::failed("timeout");
            assert!(!result.is_success());
            if let UnwindAnalysis::Failed(msg) = &result.analysis {
                assert_eq!(msg, "timeout");
            }
        }

        #[test]
        fn test_result_frame_navigation() {
            let mut result = UnwindStackCommandResult::new();
            for i in 0..5 {
                result
                    .frames
                    .push(UnwoundFrame::new(i, 0x400000 + i as u64 * 0x100, 0x7fff00));
            }
            assert_eq!(result.frame_count(), 5);
            assert_eq!(result.innermost_frame().unwrap().level, 0);
            assert_eq!(result.outermost_frame().unwrap().level, 4);
            assert!(result.frame_at_level(2).is_some());
            assert!(result.frame_at_level(10).is_none());
        }

        #[test]
        fn test_build_unwind_info_no_ops() {
            let mut exec = SymPcodeExecutor::new("RSP", false);
            let info = build_unwind_info(&mut exec, &[], &[]);
            // With no ops and no RSP register set, depth and adjust are None
            assert!(info.depth.is_none() || info.depth == Some(0));
            assert!(info.adjust.is_none() || info.adjust == Some(0));
            assert!(info.saved_registers.is_empty());
            assert!(!info.has_error());
        }

        #[test]
        fn test_build_unwind_info_with_adjust() {
            let mut exec = SymPcodeExecutor::new("RSP", false);
            let sp_addr = crate::stack::sym_pcode_executor::register_name_to_addr("RSP");
            exec.state
                .write_sym("register", sp_addr, Sym::register("RSP", 8));

            let entry_ops = vec![PcodeOpSymbolic::IntSub {
                a: VarnodeId::Register("RSP".into()),
                b: VarnodeId::Constant(32),
                output: VarnodeId::Register("RSP".into()),
            }];
            let return_ops = vec![PcodeOpSymbolic::IntAdd {
                a: VarnodeId::Register("RSP".into()),
                b: VarnodeId::Constant(32),
                output: VarnodeId::Register("RSP".into()),
            }];

            let info = build_unwind_info(&mut exec, &entry_ops, &return_ops);
            assert!(info.depth.is_some());
            assert!(info.adjust.is_some());
        }
    }

    // === DynamicStaticSync tests ===
    mod dynamic_static_sync_tests {
        use crate::plugin::dynamic_static_sync::*;

        #[test]
        fn test_sync_config_default() {
            let config = DynamicStaticSyncConfig::default();
            assert!(config.sync_locations);
            assert!(config.sync_selections);
            assert!(config.auto_open_programs);
        }

        #[test]
        fn test_location_event_serde() {
            let evt = SyncLocationEvent {
                source: SyncDirection::DynamicToStatic,
                trace_key: Some(1),
                snap: 100,
                thread_key: Some(42),
                address: 0x400000,
                mapped_address: Some(0x100000),
            };
            let json = serde_json::to_string(&evt).unwrap();
            let back: SyncLocationEvent = serde_json::from_str(&json).unwrap();
            assert_eq!(back.address, 0x400000);
        }

        #[test]
        fn test_map_commands() {
            let cmd1 = MapModulesBackgroundCommand::new(1, 100);
            assert_eq!(cmd1.trace_key, 1);
            assert!(cmd1.auto_open);
        }

        #[test]
        fn test_program_indexer_matching() {
            let indexer = ProgramModuleIndexer::new("/lib/libc.so.6", "libc.so.6");
            assert!(indexer.matches_module_name("libc.so.6"));
            assert!(indexer.matches_module_name("libc.so"));
            assert!(!indexer.matches_module_name("libm.so.6"));
        }

        #[test]
        fn test_map_command_result() {
            let result = MapCommandResult {
                mapped: vec![MappedModule {
                    module_name: "libc".into(),
                    program_url: "ghidra:///proj/libc".into(),
                    mapped_ranges: vec![(0, 0x1000)],
                    confidence: 0.99,
                }],
                missing: vec![],
                errors: vec![],
            };
            assert_eq!(result.mapped.len(), 1);
            assert!(result.missing.is_empty());
        }
    }

    // === EmulationDataAccess tests ===
    mod emulation_data_access_tests {
        use crate::services::emulation_data_access::*;

        #[test]
        fn test_config_for_shared() {
            let config = PcodeDebuggerAccessConfig::for_shared_state(1, 100);
            assert_eq!(config.trace_key, 1);
            assert_eq!(config.snap, 100);
        }

        #[test]
        fn test_config_derive_write() {
            let config = PcodeDebuggerAccessConfig::for_shared_state(1, 100)
                .with_live(true)
                .with_scope(AccessScope::TargetFirst);
            let write = config.derive_for_write(200);
            assert_eq!(write.snap, 200);
            assert_eq!(write.scope, AccessScope::TraceOnly);
        }

        #[test]
        fn test_memory_read_write() {
            let config = PcodeDebuggerAccessConfig::for_shared_state(1, 100);
            let mut mem = PcodeDebuggerMemoryAccess::new(config);
            mem.write_bytes(0x1000, &[0x55, 0x48, 0x89]);
            assert_eq!(mem.read_bytes(0x1000, 3), Some(vec![0x55, 0x48, 0x89]));
            assert!(mem.read_bytes(0x2000, 1).is_none());
        }

        #[test]
        fn test_register_access() {
            let config = PcodeDebuggerAccessConfig::for_local_state(1, 100, 1, 0);
            let mut regs = PcodeDebuggerRegistersAccess::new(config);
            regs.write_register("rip", 0x400000);
            assert_eq!(regs.read_register("rip"), Some(0x400000));
        }

        #[test]
        fn test_default_access_combined() {
            let access = DefaultPcodeDebuggerAccess::for_shared(1, 100);
            assert!(!access.is_live());
        }

        #[test]
        fn test_property_access() {
            let config = PcodeDebuggerAccessConfig::for_shared_state(1, 100);
            let mut props = PcodeDebuggerPropertyAccess::new(config);
            props.write_property("Taint", 0x400000, vec![1, 2, 3]);
            assert!(props.read_property("Taint", 0x400000).is_some());
        }
    }

    // === EmulationIntegration tests ===
    mod emulation_integration_tests {
        use crate::services::emulation_integration_ext::*;

        #[test]
        fn test_writer_configs() {
            let delayed = EmulationWriterConfig::delayed_write_trace();
            assert_eq!(delayed.mode, TargetWriteMode::Ro);

            let immediate = EmulationWriterConfig::immediate_write_target();
            assert_eq!(immediate.mode, TargetWriteMode::Rw);
        }

        #[test]
        fn test_piece_handler_write() {
            let mut handler = TargetBytesPieceHandler::new(TargetWriteMode::Rw, 1);
            let result = handler.handle_write(0x400000, &[0xCC], true);
            assert!(matches!(result, TargetOperationResult::Success));
            assert_eq!(handler.stats.target_memory_writes, 1);
        }

        #[test]
        fn test_piece_handler_read_only() {
            let mut handler = TargetBytesPieceHandler::new(TargetWriteMode::Ro, 1);
            let result = handler.handle_write(0x400000, &[0xCC], true);
            assert!(matches!(result, TargetOperationResult::Skipped));
        }

        #[test]
        fn test_integration_stats() {
            let mut stats = EmulationIntegrationStats::default();
            stats.target_memory_reads = 100;
            stats.target_register_reads = 50;
            stats.read_timeouts = 3;
            assert_eq!(stats.total_target_ops(), 150);
            assert_eq!(stats.total_timeouts(), 3);
        }
    }
}
