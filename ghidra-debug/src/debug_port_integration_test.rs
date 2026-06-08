//! Integration tests for newly ported Debug modules.
//!
//! These tests verify the new modules ported from Ghidra's Debugger,
//! Debugger-api, and Framework-TraceModeling.

#[cfg(test)]
mod tests {
    use crate::db::DbTraceTimeManager;
    
    use crate::rmi::tracermi_service::{
        ConnectMode, TraceRmiServiceEvent, TraceRmiServiceState,
    };
    use crate::pcode::trace_data_access::{
        DefaultPcodeTraceMemoryAccess, DefaultPcodeTraceRegistersAccess,
        PcodeTraceMemoryAccess, PcodeTraceRegistersAccess,
    };
    use crate::model::trace_data_ops::{
        CommentType, DataTypeConflictHandler, ReferenceInfo, ReferenceType, SettingsValue,
        TraceDataSettings,
    };
    use crate::model::TraceMemoryState;

    // === DbTraceTimeManager ===

    #[test]
    fn test_time_manager_sequential_adds() {
        let mut mgr = DbTraceTimeManager::new();
        let keys: Vec<i64> = (0..100).map(|i| mgr.add_snapshot(i * 100)).collect();
        assert_eq!(keys.len(), 100);
        assert_eq!(mgr.snapshot_count(), 100);
        assert_eq!(mgr.max_snap(), Some(99));
    }

    #[test]
    fn test_time_manager_scratch_and_regular() {
        let mut mgr = DbTraceTimeManager::new();
        mgr.add_snapshot(100); // key 0
        mgr.add_scratch_snapshot(150, Some(1)); // key 1 (scratch)
        mgr.add_snapshot(200); // key 2
        mgr.add_scratch_snapshot(250, Some(2)); // key 3 (scratch)

        assert_eq!(mgr.snapshot_count(), 4);

        let all = mgr.get_all_snapshots();
        let scratch_count = all.iter().filter(|s| s.is_scratch()).count();
        let regular_count = all.iter().filter(|s| !s.is_scratch()).count();
        assert_eq!(scratch_count, 2);
        assert_eq!(regular_count, 2);
    }

    #[test]
    fn test_time_manager_concurrent_access_pattern() {
        let mut mgr = DbTraceTimeManager::new();
        // Simulate alternating add/remove pattern
        for i in 0..50 {
            mgr.add_snapshot(i);
        }
        assert_eq!(mgr.snapshot_count(), 50);

        // Remove every other one
        for i in (0..50).step_by(2) {
            mgr.remove_snapshot(i);
        }
        assert_eq!(mgr.snapshot_count(), 25);
    }

    // === TraceRmiServiceState ===

    #[test]
    fn test_rmi_state_full_lifecycle() {
        let mut state = TraceRmiServiceState::new();

        // Start server
        state.set_server_running(true);

        // Add connections
        let c1 = state.add_connection(ConnectMode::Connect, None, None);
        let c2 = state.add_connection(ConnectMode::Server, None, None);

        // Register targets
        state.register_target("gdb-target-1", &c1);
        state.register_target("lldb-target-1", &c2);

        assert_eq!(state.target_keys().len(), 2);

        // Transaction lifecycle
        state.begin_transaction("gdb-target-1").unwrap();
        assert!(state.begin_transaction("gdb-target-1").is_err()); // Already open
        state.end_transaction("gdb-target-1", false).unwrap();

        // Disconnect c1 - should remove its targets
        state.remove_connection(&c1);
        assert_eq!(state.target_keys().len(), 1);
        assert!(state.target_connection("gdb-target-1").is_none());
        assert!(state.target_connection("lldb-target-1").is_some());
    }

    #[test]
    fn test_rmi_service_event_creation() {
        let addr: std::net::SocketAddr = "127.0.0.1:23946".parse().unwrap();

        let events = vec![
            TraceRmiServiceEvent::ServerStarted { address: addr },
            TraceRmiServiceEvent::Connected {
                connection_id: "c1".into(),
                mode: ConnectMode::Connect,
                acceptor_id: None,
            },
            TraceRmiServiceEvent::TargetPublished {
                connection_id: "c1".into(),
                target_key: "t1".into(),
            },
            TraceRmiServiceEvent::TransactionOpened {
                connection_id: "c1".into(),
                target_key: "t1".into(),
            },
            TraceRmiServiceEvent::TransactionClosed {
                connection_id: "c1".into(),
                target_key: "t1".into(),
                aborted: false,
            },
            TraceRmiServiceEvent::TargetWithdrawn {
                connection_id: "c1".into(),
                target_key: "t1".into(),
            },
            TraceRmiServiceEvent::Disconnected {
                connection_id: "c1".into(),
            },
            TraceRmiServiceEvent::ServerStopped,
        ];

        assert_eq!(events.len(), 8);
    }

    // === PcodeTraceMemoryAccess ===

    #[test]
    fn test_pcode_memory_read_write_multiple_spaces() {
        let mut ram = DefaultPcodeTraceMemoryAccess::new("ram");
        let mut reg = DefaultPcodeTraceMemoryAccess::new("register");

        ram.write_memory(0x400000, &[0x55, 0x48, 0x89]).unwrap();
        reg.write_memory(0, &[0x00, 0x10, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00]).unwrap();

        let mut ram_buf = [0u8; 3];
        ram.read_memory(0x400000, &mut ram_buf).unwrap();
        assert_eq!(ram_buf, [0x55, 0x48, 0x89]);

        let mut reg_buf = [0u8; 8];
        reg.read_memory(0, &mut reg_buf).unwrap();
        assert_eq!(u64::from_le_bytes(reg_buf), 0x00401000);
    }

    #[test]
    fn test_pcode_memory_state_tracking() {
        let mut mem = DefaultPcodeTraceMemoryAccess::new("ram");

        // Initially all unknown
        assert_eq!(mem.get_memory_state(0x1000), TraceMemoryState::Unknown);

        // Write makes it known
        mem.write_memory(0x1000, &[0xAA, 0xBB]).unwrap();
        assert_eq!(mem.get_memory_state(0x1000), TraceMemoryState::Known);
        assert_eq!(mem.get_memory_state(0x1001), TraceMemoryState::Known);
        assert_eq!(mem.get_memory_state(0x1002), TraceMemoryState::Unknown);

        // Can set error state
        mem.set_memory_state(0x1000, TraceMemoryState::Error).unwrap();
        assert_eq!(mem.get_memory_state(0x1000), TraceMemoryState::Error);
    }

    // === PcodeTraceRegistersAccess ===

    #[test]
    fn test_pcode_registers_x64() {
        let mut regs = DefaultPcodeTraceRegistersAccess::new("RIP");

        // Set up registers
        regs.write_register_u64("RAX", 0x1234567890ABCDEF, 8).unwrap();
        regs.write_register_u64("RBX", 0xDEADBEEFCAFEBABE, 8).unwrap();
        regs.write_register_u64("RIP", 0x00401000, 8).unwrap();

        assert_eq!(regs.read_register_u64("RAX"), Some(0x1234567890ABCDEF));
        assert_eq!(regs.read_register_u64("RBX"), Some(0xDEADBEEFCAFEBABE));
        assert_eq!(regs.get_program_counter(), Some(0x00401000));
        assert_eq!(regs.register_names().len(), 3);
    }

    #[test]
    fn test_pcode_registers_partial_write() {
        let mut regs = DefaultPcodeTraceRegistersAccess::new("PC");

        // Write 4 bytes of an 8-byte register
        regs.write_register("EAX", &[0xEF, 0xBE, 0xAD, 0xDE]).unwrap();
        let val = regs.read_register("EAX").unwrap();
        assert_eq!(val, [0xEF, 0xBE, 0xAD, 0xDE]);

        // Read as u64 - only 4 bytes
        let u64_val = regs.read_register_u64("EAX").unwrap();
        assert_eq!(u64_val, 0xDEADBEEF);
    }

    // === TraceDataSettings ===

    #[test]
    fn test_data_settings_default() {
        let settings = TraceDataSettings::default();
        assert!(settings.data_type_id.is_none());
        assert!(!settings.has_comment);
        assert!(settings.primary_ref.is_none());
        assert!(settings.memory_refs.is_empty());
        assert!(!settings.is_equate);
        assert!(settings.equate_value.is_none());
        assert!(settings.properties.is_empty());
    }

    #[test]
    fn test_reference_info_creation() {
        let ri = ReferenceInfo {
            from_address: 0x400000,
            to_address: 0x400100,
            ref_type: ReferenceType::Flow,
            operand_index: -1,
        };
        assert_eq!(ri.from_address, 0x400000);
        assert_eq!(ri.to_address, 0x400100);
        assert_eq!(ri.ref_type, ReferenceType::Flow);
    }

    #[test]
    fn test_reference_type_equality() {
        assert_eq!(ReferenceType::Data, ReferenceType::Data);
        assert_ne!(ReferenceType::Read, ReferenceType::Write);
        assert_ne!(ReferenceType::Flow, ReferenceType::Indirect);
    }

    #[test]
    fn test_settings_value_types() {
        let bool_val = SettingsValue::Bool(false);
        assert_eq!(bool_val.as_bool(), Some(false));

        let int_val = SettingsValue::Int(-42);
        assert_eq!(int_val.as_i64(), Some(-42));

        let str_val = SettingsValue::String("test".into());
        assert_eq!(str_val.as_str(), Some("test"));

        let float_val = SettingsValue::Float(1.5);
        assert!((float_val.as_f64().unwrap() - 1.5).abs() < f64::EPSILON);

        let long_val = SettingsValue::Long(i64::MIN);
        assert_eq!(long_val.as_i64(), Some(i64::MIN));

        let double_val = SettingsValue::Double(std::f64::consts::PI);
        assert!((double_val.as_f64().unwrap() - std::f64::consts::PI).abs() < f64::EPSILON);
    }

    #[test]
    fn test_data_type_conflict_handler_variants() {
        let variants = [
            DataTypeConflictHandler::Replace,
            DataTypeConflictHandler::Keep,
            DataTypeConflictHandler::RenameNew,
            DataTypeConflictHandler::RenameExisting,
        ];
        assert_eq!(variants.len(), 4);
        // All are distinct
        for i in 0..variants.len() {
            for j in i + 1..variants.len() {
                assert_ne!(variants[i], variants[j]);
            }
        }
    }

    #[test]
    fn test_comment_type_variants() {
        let types = [
            CommentType::Pre,
            CommentType::Eol,
            CommentType::Post,
            CommentType::Plate,
            CommentType::Repeatable,
        ];
        assert_eq!(types.len(), 5);
        assert_ne!(CommentType::Pre, CommentType::Repeatable);
    }

    // === ConnectMode ===

    #[test]
    fn test_connect_mode_variants() {
        assert_ne!(ConnectMode::Connect, ConnectMode::AcceptOne);
        assert_ne!(ConnectMode::AcceptOne, ConnectMode::Server);
        assert_eq!(ConnectMode::Connect, ConnectMode::Connect);
    }

    // === Combined scenario tests ===

    #[test]
    fn test_debug_session_lifecycle() {
        // Simulate a debug session
        let mut time_mgr = DbTraceTimeManager::new();

        // Initial state
        let snap0 = time_mgr.add_snapshot(1000);
        assert_eq!(snap0, 0);

        // Set up RMI
        let mut rmi_state = TraceRmiServiceState::new();
        rmi_state.set_server_running(true);
        let conn = rmi_state.add_connection(ConnectMode::Connect, None, None);
        rmi_state.register_target("gdb-session", &conn);

        // Set up memory and registers
        let mut mem = DefaultPcodeTraceMemoryAccess::new("ram");
        let mut regs = DefaultPcodeTraceRegistersAccess::new("RIP");

        // Load program
        mem.write_memory(0x400000, &[0x55, 0x48, 0x89, 0xE5]).unwrap();

        // Set registers
        regs.write_register_u64("RIP", 0x400000, 8).unwrap();
        regs.write_register_u64("RSP", 0x7FFFFFFFE000, 8).unwrap();

        // Step - advance
        let snap1 = time_mgr.add_snapshot(1100);
        assert_eq!(snap1, 1);

        // Transaction
        rmi_state.begin_transaction("gdb-session").unwrap();

        // Write new state
        mem.write_memory(0x400004, &[0x48, 0x89, 0x5D, 0xF8]).unwrap();
        regs.write_register_u64("RIP", 0x400004, 8).unwrap();

        rmi_state.end_transaction("gdb-session", false).unwrap();

        // Verify state
        let snap = time_mgr.get_snapshot(snap1).unwrap();
        assert_eq!(snap.key, 1);

        let mut buf = [0u8; 4];
        mem.read_memory(0x400004, &mut buf).unwrap();
        assert_eq!(buf, [0x48, 0x89, 0x5D, 0xF8]);

        assert_eq!(regs.get_program_counter(), Some(0x400004));
    }

    #[test]
    fn test_multi_thread_trace() {
        let mut time_mgr = DbTraceTimeManager::new();
        time_mgr.add_snapshot(1000);

        // Two threads, each with their own scratch snapshot
        let scratch1 = time_mgr.add_scratch_snapshot(1050, Some(1));
        let scratch2 = time_mgr.add_scratch_snapshot(1060, Some(2));

        assert!(time_mgr.get_snapshot(scratch1).unwrap().is_scratch());
        assert!(time_mgr.get_snapshot(scratch2).unwrap().is_scratch());
        assert_eq!(
            time_mgr.get_snapshot(scratch1).unwrap().thread_key,
            Some(1)
        );
        assert_eq!(
            time_mgr.get_snapshot(scratch2).unwrap().thread_key,
            Some(2)
        );
    }
}
