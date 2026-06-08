//! Comprehensive final tests for the remaining Debug modules.
//!
//! These tests exercise the full breadth of the Debug framework port,
//! covering stack unwinding, platform mapping, TraceRmi, pcode data access,
//! framework event queues, service interfaces, and integration scenarios.

#[cfg(test)]
mod stack_unwind_comprehensive_tests {
    use std::collections::HashMap;
    
    use crate::stack::{
        ConstSym, OpaqueSym, SavedRegisterMap, StackDerefSym, StackOffsetSym,
        StackUnwinder, Sym, SymArithmetic, SymState, UnwindInfo, UnwindWarning,
        UnwindWarningKind, UnwindWarningSet,
    };
    use crate::stack::unwind_info::ReturnLocation;

    // -----------------------------------------------------------------------
    // Sym enum variant tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_sym_opaque_is_tuple_variant() {
        let a = Sym::opaque();
        assert!(a.is_opaque());
        let b = Sym::Opaque(OpaqueSym);
        assert!(b.is_opaque());
        assert_eq!(a, b);
    }

    #[test]
    fn test_sym_const_add_const() {
        let a = Sym::constant(10);
        let b = Sym::constant(20);
        let result = a.add("SP", &b);
        assert_eq!(result, Sym::Const(ConstSym { value: 30, size: 8 }));
    }

    #[test]
    fn test_sym_const_add_const_wrapping() {
        let a = Sym::constant(i64::MAX - 5);
        let b = Sym::constant(10);
        let result = a.add("SP", &b);
        match result {
            Sym::Const(c) => assert_eq!(c.value, (i64::MAX - 5).wrapping_add(10)),
            _ => panic!("Expected Const"),
        }
    }

    #[test]
    fn test_sym_const_add_register_sp() {
        let c = Sym::constant(0x100);
        let sp = Sym::register("SP", 8);
        let result = c.add("SP", &sp);
        assert_eq!(result, Sym::StackOffset(StackOffsetSym { offset: 0x100 }));
    }

    #[test]
    fn test_sym_sp_register_add_const() {
        let sp = Sym::register("SP", 8);
        let c = Sym::constant(-8);
        let result = sp.add("SP", &c);
        assert_eq!(result, Sym::StackOffset(StackOffsetSym { offset: -8 }));
    }

    #[test]
    fn test_sym_const_add_register_non_sp() {
        let c = Sym::constant(0x100);
        let rax = Sym::register("RAX", 8);
        let result = c.add("SP", &rax);
        assert!(result.is_opaque());
    }

    #[test]
    fn test_sym_stack_offset_add_const() {
        let so = Sym::stack_offset(0x100);
        let c = Sym::constant(8);
        let result = so.add("SP", &c);
        assert_eq!(result, Sym::StackOffset(StackOffsetSym { offset: 0x108 }));
    }

    #[test]
    fn test_sym_stack_offset_sub_const() {
        let so = Sym::stack_offset(0x200);
        let c = Sym::constant(0x10);
        let result = so.sub("SP", &c);
        assert_eq!(result.as_const_value(), None); // StackOffset, not Const
        match result {
            Sym::StackOffset(s) => assert_eq!(s.offset, 0x1f0),
            _ => panic!("Expected StackOffset"),
        }
    }

    #[test]
    fn test_sym_const_sub() {
        let a = Sym::constant(50);
        let b = Sym::constant(20);
        let result = a.sub("SP", &b);
        assert_eq!(result.as_const_value(), Some(30));
    }

    #[test]
    fn test_sym_const_and_const() {
        let a = Sym::constant(0xFF);
        let b = Sym::constant(0x0F);
        let result = a.and("SP", &b);
        assert_eq!(result.as_const_value(), Some(0x0F));
    }

    #[test]
    fn test_sym_const_and_register() {
        let mask = Sym::constant_sized(-2i64, 8); // 0xFFFF...FFFE
        let sp = Sym::register("SP", 8);
        let result = mask.and("SP", &sp);
        match result {
            Sym::Register(r) => {
                assert_eq!(r.register_name, "SP");
                assert_eq!(r.mask, 0xFFFF_FFFF_FFFF_FFFEu64);
            }
            _ => panic!("Expected Register, got {:?}", result),
        }
    }

    #[test]
    fn test_sym_deref_stack_offset() {
        let so = Sym::stack_offset(-8);
        let result = so.deref("SP");
        assert_eq!(
            result,
            Sym::StackDeref(StackDerefSym {
                offset: -8,
                mask: u64::MAX,
                size: 8,
            })
        );
    }

    #[test]
    fn test_sym_deref_sp_register() {
        let sp = Sym::register("SP", 8);
        let result = sp.deref("SP");
        assert_eq!(
            result,
            Sym::StackDeref(StackDerefSym {
                offset: 0,
                mask: u64::MAX,
                size: 8,
            })
        );
    }

    #[test]
    fn test_sym_deref_non_stack() {
        let rax = Sym::register("RAX", 8);
        let result = rax.deref("SP");
        assert!(result.is_opaque());
    }

    #[test]
    fn test_sym_twos_comp_const() {
        let c = Sym::constant(42);
        let result = c.twos_comp();
        assert_eq!(result.as_const_value(), Some(-42));
    }

    #[test]
    fn test_sym_twos_comp_opaque() {
        let o = Sym::opaque();
        let result = o.twos_comp();
        assert!(result.is_opaque());
    }

    #[test]
    fn test_sym_size() {
        assert_eq!(Sym::constant(0).size(), Some(8));
        assert_eq!(Sym::constant_sized(0, 4).size(), Some(4));
        assert_eq!(Sym::register("RAX", 8).size(), Some(8));
        assert_eq!(Sym::opaque().size(), None);
        assert_eq!(Sym::stack_offset(0).size(), None);
    }

    #[test]
    fn test_sym_display() {
        assert_eq!(Sym::opaque().to_string(), "Opaque");
        assert_eq!(Sym::constant(42).to_string(), "Const(0x2a, 8B)");
        assert_eq!(Sym::stack_offset(-8).to_string(), "SP-8");
        assert_eq!(Sym::stack_deref(-16, 8).to_string(), "*(SP-16)");
    }

    #[test]
    fn test_sym_serde_roundtrip() {
        let s = Sym::StackOffset(StackOffsetSym { offset: -32 });
        let json = serde_json::to_string(&s).unwrap();
        let back: Sym = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }

    // -----------------------------------------------------------------------
    // SymArithmetic tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_sym_arithmetic_unary_copy() {
        let arith = SymArithmetic::new("SP", false);
        let c = Sym::constant(42);
        let result = arith.unary_op(crate::stack::sym_arithmetic::PcodeOp::Copy, &c);
        assert_eq!(result.as_const_value(), Some(42));
    }

    #[test]
    fn test_sym_arithmetic_binary_add() {
        let arith = SymArithmetic::new("SP", false);
        let a = Sym::constant(10);
        let b = Sym::constant(20);
        let result = arith.binary_op(crate::stack::sym_arithmetic::PcodeOp::IntAdd, &a, &b);
        assert_eq!(result.as_const_value(), Some(30));
    }

    #[test]
    fn test_sym_arithmetic_binary_sub() {
        let arith = SymArithmetic::new("SP", false);
        let a = Sym::constant(50);
        let b = Sym::constant(20);
        let result = arith.binary_op(crate::stack::sym_arithmetic::PcodeOp::IntSub, &a, &b);
        assert_eq!(result.as_const_value(), Some(30));
    }

    #[test]
    fn test_sym_arithmetic_load() {
        let arith = SymArithmetic::new("SP", false);
        let offset = Sym::stack_offset(0x100);
        let result = arith.load_op("ram", &offset, 8);
        assert!(result.is_stack_deref());
        match result {
            Sym::StackDeref(sd) => assert_eq!(sd.offset, 0x100),
            _ => panic!("Expected StackDeref"),
        }
    }

    #[test]
    fn test_sym_arithmetic_unary_other_is_opaque() {
        let arith = SymArithmetic::new("SP", false);
        let c = Sym::constant(42);
        let result = arith.unary_op(crate::stack::sym_arithmetic::PcodeOp::IntOr, &c);
        assert!(result.is_opaque());
    }

    #[test]
    fn test_sym_arithmetic_default() {
        let arith = SymArithmetic::default();
        assert_eq!(arith.sp_name, "SP");
        assert!(!arith.big_endian);
    }

    // -----------------------------------------------------------------------
    // SavedRegisterMap tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_saved_register_map_empty() {
        let map = SavedRegisterMap::new();
        assert!(map.is_empty());
        assert_eq!(map.len(), 0);
    }

    #[test]
    fn test_saved_register_map_put_and_lookup() {
        let mut map = SavedRegisterMap::new();
        map.put_register(0x1000, 8, 0x7fff0000);
        assert!(!map.is_empty());
        let entry = map.lookup(0x1000);
        assert!(entry.is_some());
        let e = entry.unwrap();
        assert_eq!(e.from.min, 0x1000);
        assert_eq!(e.from.max, 0x1007);
        assert_eq!(e.to_addr, 0x7fff0000);
    }

    #[test]
    fn test_saved_register_map_no_match() {
        let mut map = SavedRegisterMap::new();
        map.put_register(0x1000, 8, 0x7fff0000);
        assert!(map.lookup(0x2000).is_none());
    }

    #[test]
    fn test_saved_register_map_fork() {
        let mut map = SavedRegisterMap::new();
        map.put_register(0x1000, 8, 0x7fff0000);
        let forked = map.fork();
        assert!(!forked.is_empty());
        let entry = forked.lookup(0x1000);
        assert!(entry.is_some());
    }

    #[test]
    fn test_saved_register_map_multiple_entries() {
        let mut map = SavedRegisterMap::new();
        map.put_register(0x1000, 8, 0x7fff0000);
        map.put_register(0x2000, 8, 0x7fff0008);
        map.put_register(0x3000, 4, 0x7fff0010);
        assert!(!map.is_empty());
        assert_eq!(map.len(), 3);
        assert!(map.lookup(0x1000).is_some());
        assert!(map.lookup(0x2000).is_some());
        assert!(map.lookup(0x3000).is_some());
        assert!(map.lookup(0x4000).is_none());
    }

    #[test]
    fn test_saved_register_map_redirect() {
        let mut map = SavedRegisterMap::new();
        map.put_register(0x1000, 8, 0x7fff0000);
        // Redirecting 0x1000 should return 0x7fff0000
        assert_eq!(map.redirect(0x1000), 0x7fff0000);
        // Redirecting 0x1001 should return 0x7fff0001 (offset within range)
        assert_eq!(map.redirect(0x1001), 0x7fff0001);
        // Non-mapped address returns itself
        assert_eq!(map.redirect(0x2000), 0x2000);
    }

    #[test]
    fn test_saved_register_map_register_name() {
        let mut map = SavedRegisterMap::new();
        map.insert_register_save("RBP".into(), -8);
        // register_name_to_addr may produce a non-negative hash
        // If so, the entry is stored; otherwise it's a no-op
        // Either way, the API should not panic
        let _name_map = map.to_name_map();
    }

    // -----------------------------------------------------------------------
    // UnwindInfo tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_unwind_info_creation() {
        let mut saved = HashMap::new();
        saved.insert("R30".to_string(), -8i64);
        saved.insert("R29".to_string(), -16i64);

        let info = UnwindInfo::new(
            Some("main".into()),
            Some(32),
            Some(40),
            ReturnLocation::Stack { offset: -8, size: 8 },
            u64::MAX,
            saved,
            UnwindWarningSet::new(),
        );

        assert_eq!(info.function_name, Some("main".into()));
        assert_eq!(info.depth, Some(32));
        assert_eq!(info.adjust, Some(40));
        assert_eq!(info.saved_registers.len(), 2);
        assert!(info.error.is_none());
        assert!(!info.has_error());
    }

    #[test]
    fn test_unwind_info_error_only() {
        let info = UnwindInfo::error_only("analysis failed");
        assert!(info.has_error());
        assert!(info.depth.is_none());
        assert!(info.adjust.is_none());
        assert!(info.saved_registers.is_empty());
    }

    #[test]
    fn test_unwind_info_compute_base() {
        let info = UnwindInfo::new(
            Some("func".into()),
            Some(64),
            Some(72),
            ReturnLocation::Stack { offset: -8, size: 8 },
            u64::MAX,
            HashMap::new(),
            UnwindWarningSet::new(),
        );
        // base = sp - depth = 0x7fff0040 - 64
        let base = info.compute_base(0x7fff0040i64);
        assert_eq!(base, Some(0x7fff0000i64));
    }

    #[test]
    fn test_unwind_info_compute_base_none_when_no_depth() {
        let info = UnwindInfo::error_only("test");
        let base = info.compute_base(0x7fff0040i64);
        assert!(base.is_none());
    }

    #[test]
    fn test_unwind_info_compute_next_sp() {
        let info = UnwindInfo::new(
            Some("func".into()),
            Some(32),
            Some(40),
            ReturnLocation::Stack { offset: -8, size: 8 },
            u64::MAX,
            HashMap::new(),
            UnwindWarningSet::new(),
        );
        let base: i64 = 0x7fff0000;
        let next_sp = info.compute_next_sp(base);
        assert_eq!(next_sp, Some(0x7fff0028)); // base + adjust = 0x7fff0000 + 40
    }

    #[test]
    fn test_unwind_info_return_location_known() {
        let info_stack = UnwindInfo::new(
            None, Some(16), Some(24),
            ReturnLocation::Stack { offset: -8, size: 8 },
            u64::MAX, HashMap::new(), UnwindWarningSet::new(),
        );
        assert!(info_stack.return_location_known());

        let info_unknown = UnwindInfo::new(
            None, Some(16), Some(24),
            ReturnLocation::Unknown,
            u64::MAX, HashMap::new(), UnwindWarningSet::new(),
        );
        assert!(!info_unknown.return_location_known());
    }

    #[test]
    fn test_unwind_info_return_offset_from_base() {
        let info = UnwindInfo::new(
            None, Some(16), Some(24),
            ReturnLocation::Stack { offset: -8, size: 8 },
            u64::MAX, HashMap::new(), UnwindWarningSet::new(),
        );
        assert_eq!(info.return_offset_from_base(), Some(-8));

        let info_reg = UnwindInfo::new(
            None, Some(16), Some(24),
            ReturnLocation::Register { name: "LR".into(), mask: u64::MAX },
            u64::MAX, HashMap::new(), UnwindWarningSet::new(),
        );
        assert_eq!(info_reg.return_offset_from_base(), None);
    }

    #[test]
    fn test_unwind_info_serde() {
        let info = UnwindInfo::new(
            Some("test_func".into()),
            Some(16),
            Some(24),
            ReturnLocation::Stack { offset: -8, size: 8 },
            u64::MAX,
            HashMap::new(),
            UnwindWarningSet::new(),
        );
        let json = serde_json::to_string(&info).unwrap();
        let back: UnwindInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(back.function_name, Some("test_func".into()));
        assert_eq!(back.depth, Some(16));
        assert_eq!(back.adjust, Some(24));
    }

    // -----------------------------------------------------------------------
    // UnwindWarning tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_unwind_warning_set_empty() {
        let set = UnwindWarningSet::new();
        assert!(set.is_empty());
        assert_eq!(set.len(), 0);
        assert!(!set.has_warnings());
    }

    #[test]
    fn test_unwind_warning_set_add_and_collect() {
        let mut set = UnwindWarningSet::new();
        set.add(UnwindWarning {
            kind: UnwindWarningKind::NoReturnPath,
            message: "no return path at 0x400000".into(),
        });
        set.add(UnwindWarning {
            kind: UnwindWarningKind::AnalysisError,
            message: "analysis error".into(),
        });
        assert_eq!(set.len(), 2);
        assert!(!set.is_empty());
        assert!(set.has_warnings());

        let messages: Vec<&str> = set.iter().map(|w| w.message.as_str()).collect();
        assert!(messages.iter().any(|m| m.contains("no return path")));
        assert!(messages.iter().any(|m| m.contains("analysis error")));
    }

    #[test]
    fn test_unwind_warning_set_dedup() {
        let mut set = UnwindWarningSet::new();
        set.add(UnwindWarning {
            kind: UnwindWarningKind::NoReturnPath,
            message: "test".into(),
        });
        set.add(UnwindWarning {
            kind: UnwindWarningKind::NoReturnPath,
            message: "test".into(),
        });
        assert_eq!(set.len(), 1); // deduped
    }

    #[test]
    fn test_unwind_warning_has_kind() {
        let mut set = UnwindWarningSet::new();
        assert!(!set.has_kind(UnwindWarningKind::NoReturnPath));
        set.add(UnwindWarning {
            kind: UnwindWarningKind::NoReturnPath,
            message: "test".into(),
        });
        assert!(set.has_kind(UnwindWarningKind::NoReturnPath));
        assert!(!set.has_kind(UnwindWarningKind::OpaqueReturnPath));
    }

    #[test]
    fn test_unwind_warning_serde() {
        let warning = UnwindWarning {
            kind: UnwindWarningKind::OpaqueReturnPath,
            message: "could not analyze path".into(),
        };
        let json = serde_json::to_string(&warning).unwrap();
        let back: UnwindWarning = serde_json::from_str(&json).unwrap();
        assert_eq!(back.kind, UnwindWarningKind::OpaqueReturnPath);
        assert!(back.message.contains("could not analyze"));
    }

    #[test]
    fn test_unwind_warning_kind_variants() {
        assert_ne!(UnwindWarningKind::NoReturnPath, UnwindWarningKind::OpaqueReturnPath);
        assert_ne!(UnwindWarningKind::Custom, UnwindWarningKind::Cancelled);
        assert_ne!(UnwindWarningKind::AnalysisError, UnwindWarningKind::NoReturnPath);
    }

    // -----------------------------------------------------------------------
    // StackUnwinder tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_stack_unwinder_creation() {
        let unwinder = StackUnwinder::new("SP", false);
        assert_eq!(unwinder.sp_name, "SP");
        assert!(!unwinder.big_endian);
    }

    #[test]
    fn test_stack_unwinder_simple_frame() {
        let mut unwinder = StackUnwinder::new("SP", false);
        let mut saved = HashMap::new();
        saved.insert("R30".to_string(), -8i64);
        saved.insert("R29".to_string(), -16i64);

        let info = UnwindInfo::new(
            Some("main".into()),
            Some(32),
            Some(40),
            ReturnLocation::Stack { offset: -8, size: 8 },
            u64::MAX,
            saved,
            UnwindWarningSet::new(),
        );

        let coords = crate::stack::stack_unwinder::UnwindCoordinates::new("trace1", 1, 0, 0);
        let unwind_info_fn = |pc: u64| -> Option<UnwindInfo> {
            match pc {
                0x400000 => Some(info.clone()),
                _ => None,
            }
        };

        let frames = unwinder.unwind_from(&coords, 0x400000, 0x7fff0000, 10, &unwind_info_fn);
        assert!(!frames.is_empty());
        let frame0 = &frames[0];
        assert_eq!(frame0.level, 0);
        assert_eq!(frame0.pc, 0x400000);
        assert_eq!(frame0.function_name, Some("main".into()));
        assert!(frame0.base_pointer.is_some());
    }

    #[test]
    fn test_stack_unwinder_no_info() {
        let mut unwinder = StackUnwinder::new("SP", false);
        let coords = crate::stack::stack_unwinder::UnwindCoordinates::new("trace1", 1, 0, 0);
        let unwind_info_fn = |_pc: u64| -> Option<UnwindInfo> { None };

        let frames = unwinder.unwind_from(&coords, 0x400000, 0x7fff0000, 10, &unwind_info_fn);
        assert_eq!(frames.len(), 1);
        assert!(frames[0].has_error());
    }

    #[test]
    fn test_stack_unwinder_max_depth_zero() {
        let mut unwinder = StackUnwinder::new("SP", false);
        let coords = crate::stack::stack_unwinder::UnwindCoordinates::new("t", 1, 0, 0);
        let unwind_info_fn = |_pc: u64| -> Option<UnwindInfo> { None };
        let frames = unwinder.unwind_from(&coords, 0x400000, 0x7fff0000, 0, &unwind_info_fn);
        assert!(frames.is_empty());
    }

    #[test]
    fn test_stack_unwinder_cache() {
        let mut unwinder = StackUnwinder::new("SP", false);
        assert_eq!(unwinder.cache_size(), 0);

        let info = UnwindInfo::error_only("test");
        unwinder.cache_unwind_info(0x400000, info);
        assert_eq!(unwinder.cache_size(), 1);

        unwinder.invalidate_cache();
        assert_eq!(unwinder.cache_size(), 0);
    }

    #[test]
    fn test_stack_unwinder_multi_frame() {
        let mut unwinder = StackUnwinder::new("RSP", true);

        let saved1 = HashMap::from([("RBP".to_string(), -8i64)]);
        let saved2 = HashMap::from([("RBX".to_string(), -16i64), ("R12".to_string(), -24i64)]);

        let info1 = UnwindInfo::new(
            Some("leaf_func".into()), Some(32), Some(32),
            ReturnLocation::Stack { offset: -8, size: 8 },
            u64::MAX, saved1, UnwindWarningSet::new(),
        );
        let info2 = UnwindInfo::new(
            Some("caller_func".into()), Some(64), Some(72),
            ReturnLocation::Stack { offset: -8, size: 8 },
            u64::MAX, saved2, UnwindWarningSet::new(),
        );

        let coords = crate::stack::stack_unwinder::UnwindCoordinates::new("trace1", 1, 0, 0);
        let unwind_info_fn = |pc: u64| -> Option<UnwindInfo> {
            match pc {
                0x400000 => Some(info1.clone()),
                0x500000 => Some(info2.clone()),
                _ => None,
            }
        };

        let frames = unwinder.unwind_from(&coords, 0x400000, 0x7fff0000, 5, &unwind_info_fn);
        assert!(frames.len() >= 1);
        assert_eq!(frames[0].pc, 0x400000);
        assert_eq!(frames[0].function_name, Some("leaf_func".into()));
    }

    #[test]
    fn test_coordinates() {
        let coords = crate::stack::stack_unwinder::UnwindCoordinates::new("trace1", 1, 0, 3);
        assert_eq!(coords.trace_key, "trace1");
        assert_eq!(coords.thread_key, 1);
        assert_eq!(coords.snap, 0);
        assert_eq!(coords.frame_level, 3);
    }

    #[test]
    fn test_stack_unwinder_arithmetic() {
        let unwinder = StackUnwinder::new("SP", false);
        let arith = unwinder.arithmetic();
        assert_eq!(arith.sp_name, "SP");
        assert!(!arith.big_endian);
    }

    #[test]
    fn test_serde_unwound_frame() {
        let frame = crate::stack::stack_unwinder::UnwoundFrame::new(0, 0x400080, 0x7fff0000);
        let json = serde_json::to_string(&frame).unwrap();
        let back: crate::stack::stack_unwinder::UnwoundFrame = serde_json::from_str(&json).unwrap();
        assert_eq!(back.pc, 0x400080);
        assert_eq!(back.sp, 0x7fff0000);
    }

    // -----------------------------------------------------------------------
    // SymState tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_sym_state_creation() {
        let arith = SymArithmetic::new("SP", false);
        let _state = SymState::new(arith);
        // Should create without panic
    }

    #[test]
    fn test_sym_state_read_write() {
        let arith = SymArithmetic::new("SP", false);
        let mut state = SymState::new(arith);
        state.write_sym("register", 0x1000, Sym::constant(0xDEAD));
        let val = state.read_sym("register", 0x1000, 8);
        assert_eq!(val.as_const_value(), Some(0xDEAD));
    }

    #[test]
    fn test_sym_state_read_unwritten() {
        let arith = SymArithmetic::new("SP", false);
        let state = SymState::new(arith);
        let val = state.read_sym("register", 0x9999, 8);
        // Unwritten addresses return register syms
        assert!(matches!(val, Sym::Register(_)));
    }

    #[test]
    fn test_return_location_variants() {
        let stack_rl = ReturnLocation::Stack { offset: -8, size: 8 };
        let reg_rl = ReturnLocation::Register { name: "LR".into(), mask: u64::MAX };
        let unknown_rl = ReturnLocation::Unknown;

        assert_ne!(stack_rl, reg_rl);
        assert_ne!(stack_rl, unknown_rl);
        assert_ne!(reg_rl, unknown_rl);
    }

    #[test]
    fn test_unwind_info_saved_register_count() {
        let saved = HashMap::from([
            ("RBP".to_string(), -8i64),
            ("RBX".to_string(), -16i64),
        ]);
        let info = UnwindInfo::new(
            None, Some(32), Some(40),
            ReturnLocation::Unknown, u64::MAX,
            saved, UnwindWarningSet::new(),
        );
        assert_eq!(info.saved_register_count(), 2);
    }
}

#[cfg(test)]
mod framework_event_comprehensive_tests {
    use crate::framework::domain_object_event_queues::{
        DomainChangeEvent, DomainObjectEventQueues, EventQueueId, FnListener,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    #[test]
    fn test_event_queue_creation() {
        let queues = DomainObjectEventQueues::new(Duration::from_millis(100));
        assert_eq!(queues.private_queue_count(), 0);
        assert_eq!(queues.listener_count(), 0);
    }

    #[test]
    fn test_event_queue_enable_disable() {
        let queues = DomainObjectEventQueues::new(Duration::from_millis(100));
        assert!(queues.is_sending_events());

        queues.set_events_enabled(false);
        assert!(!queues.is_sending_events());

        queues.set_events_enabled(true);
        assert!(queues.is_sending_events());
    }

    #[test]
    fn test_event_queue_fire_basic() {
        let queues = DomainObjectEventQueues::new(Duration::from_millis(100));
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();

        queues.add_listener(Arc::new(FnListener::new(move |_evt| {
            counter_clone.fetch_add(1, Ordering::SeqCst);
        })));

        let event = DomainChangeEvent::new("TEST", "test event");
        queues.fire_event(event);
        assert_eq!(counter.load(Ordering::SeqCst), 1);

        let event2 = DomainChangeEvent::new("TEST", "test event 2");
        queues.fire_event(event2);
        assert_eq!(counter.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn test_event_queue_fire_disabled() {
        let queues = DomainObjectEventQueues::new(Duration::from_millis(100));
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();

        queues.add_listener(Arc::new(FnListener::new(move |_evt| {
            counter_clone.fetch_add(1, Ordering::SeqCst);
        })));

        queues.set_events_enabled(false);
        let event = DomainChangeEvent::new("TEST", "test event");
        queues.fire_event(event);
        assert_eq!(counter.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn test_event_queue_private_queue() {
        let queues = DomainObjectEventQueues::new(Duration::from_millis(100));
        assert_eq!(queues.private_queue_count(), 0);

        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();
        let listener = Arc::new(FnListener::new(move |_evt| {
            counter_clone.fetch_add(1, Ordering::SeqCst);
        }));

        let qid = queues.create_private_queue(listener);
        assert_eq!(queues.private_queue_count(), 1);

        assert!(queues.remove_private_queue(qid));
        assert_eq!(queues.private_queue_count(), 0);
    }

    #[test]
    fn test_event_queue_flush_private() {
        let queues = DomainObjectEventQueues::new(Duration::from_millis(100));
        let listener = Arc::new(FnListener::new(|_evt| {}));

        let qid = queues.create_private_queue(listener);
        let result = queues.flush_private_queue(qid);
        assert!(result.is_ok());
    }

    #[test]
    fn test_event_queue_flush_nonexistent() {
        let queues = DomainObjectEventQueues::new(Duration::from_millis(100));
        let result = queues.flush_private_queue(EventQueueId::new(999));
        assert!(result.is_err());
    }

    #[test]
    fn test_domain_change_event_new() {
        let evt = DomainChangeEvent::new("TYPE", "desc");
        assert_eq!(evt.event_type, "TYPE");
        assert_eq!(evt.description, "desc");
        assert!(evt.payload.is_none());
    }

    #[test]
    fn test_domain_change_event_restored() {
        let evt = DomainChangeEvent::restored();
        assert_eq!(evt.event_type, "RESTORED");
    }

    #[test]
    fn test_domain_change_event_with_payload() {
        let evt = DomainChangeEvent::new("DATA", "data event")
            .with_payload(vec![1, 2, 3, 4]);
        assert!(evt.payload.is_some());
        assert_eq!(evt.payload.unwrap(), vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_event_queue_id_display() {
        let qid = EventQueueId::new(42);
        let display = format!("{}", qid);
        assert!(display.contains("42"));
    }

    #[test]
    fn test_event_queue_id_equality() {
        let a = EventQueueId::new(1);
        let b = EventQueueId::new(1);
        let c = EventQueueId::new(2);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn test_multiple_listeners() {
        let queues = DomainObjectEventQueues::new(Duration::from_millis(100));
        let counter1 = Arc::new(AtomicUsize::new(0));
        let counter2 = Arc::new(AtomicUsize::new(0));
        let c1 = counter1.clone();
        let c2 = counter2.clone();

        queues.add_listener(Arc::new(FnListener::new(move |_| {
            c1.fetch_add(1, Ordering::SeqCst);
        })));
        queues.add_listener(Arc::new(FnListener::new(move |_| {
            c2.fetch_add(10, Ordering::SeqCst);
        })));

        assert_eq!(queues.listener_count(), 2);
        let event = DomainChangeEvent::new("TEST", "multi-listener");
        queues.fire_event(event);
        assert_eq!(counter1.load(Ordering::SeqCst), 1);
        assert_eq!(counter2.load(Ordering::SeqCst), 10);
    }
}

#[cfg(test)]
mod rmi_connection_comprehensive_tests {
    use crate::rmi::tracermi_service::{ConnectMode, TraceRmiServiceEvent};

    #[test]
    fn test_connect_mode_variants() {
        assert_ne!(ConnectMode::Connect, ConnectMode::AcceptOne);
        assert_ne!(ConnectMode::Connect, ConnectMode::Server);
        assert_ne!(ConnectMode::AcceptOne, ConnectMode::Server);
    }

    #[test]
    fn test_connect_mode_clone() {
        let mode = ConnectMode::Connect;
        let cloned = mode.clone();
        assert_eq!(mode, cloned);
    }

    #[test]
    fn test_rmi_service_event_server_started() {
        let event = TraceRmiServiceEvent::ServerStarted {
            address: "127.0.0.1:8080".parse().unwrap(),
        };
        match event {
            TraceRmiServiceEvent::ServerStarted { address } => {
                assert_eq!(address.port(), 8080);
            }
            _ => panic!("Expected ServerStarted"),
        }
    }

    #[test]
    fn test_rmi_service_event_connected() {
        let event = TraceRmiServiceEvent::Connected {
            connection_id: "conn-1".into(),
            mode: ConnectMode::AcceptOne,
            acceptor_id: Some("acc-1".into()),
        };
        match event {
            TraceRmiServiceEvent::Connected { connection_id, mode, acceptor_id } => {
                assert_eq!(connection_id, "conn-1");
                assert_eq!(mode, ConnectMode::AcceptOne);
                assert_eq!(acceptor_id, Some("acc-1".into()));
            }
            _ => panic!("Expected Connected"),
        }
    }

    #[test]
    fn test_rmi_service_event_target_lifecycle() {
        let pub_event = TraceRmiServiceEvent::TargetPublished {
            connection_id: "c1".into(),
            target_key: "t1".into(),
        };
        match pub_event {
            TraceRmiServiceEvent::TargetPublished { target_key, .. } => {
                assert_eq!(target_key, "t1");
            }
            _ => panic!("Expected TargetPublished"),
        }
    }

    #[test]
    fn test_rmi_service_event_transaction() {
        let event = TraceRmiServiceEvent::TransactionClosed {
            connection_id: "c1".into(),
            target_key: "t1".into(),
            aborted: false,
        };
        match event {
            TraceRmiServiceEvent::TransactionClosed { aborted, .. } => {
                assert!(!aborted);
            }
            _ => panic!("Expected TransactionClosed"),
        }
    }

    #[test]
    fn test_rmi_service_event_debug() {
        let event = TraceRmiServiceEvent::Disconnected {
            connection_id: "c1".into(),
        };
        let debug_str = format!("{:?}", event);
        assert!(debug_str.contains("Disconnected"));
    }
}

#[cfg(test)]
mod platform_opinion_comprehensive_tests {
    use crate::plugin::platform_opinion::{
        PlatformOpinion, PlatformOpinionRegistry, OpinionContext,
        create_default_registry,
    };
    
    
    

    #[test]
    fn test_platform_opinion_creation() {
        let opinion = PlatformOpinion::new(
            "gdb",
            "x86:LE:64:default",
            "default",
            "x86",
            0.9,
        );
        assert_eq!(opinion.language_id, "x86:LE:64:default");
        assert_eq!(opinion.compiler_spec_id, "default");
        assert_eq!(opinion.architecture, "x86");
        assert_eq!(opinion.debugger_type, "gdb");
        assert!((opinion.confidence - 0.9).abs() < f64::EPSILON);
    }

    #[test]
    fn test_platform_opinion_registry() {
        let registry = PlatformOpinionRegistry::new();
        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);
    }

    #[test]
    fn test_opinion_context_builder() {
        let ctx = OpinionContext::new()
            .with_debugger_type("gdb")
            .with_architecture("x86")
            .with_os("linux")
            .with_pointer_size(8)
            .with_big_endian(false);
        assert_eq!(ctx.debugger_type, "gdb");
        assert_eq!(ctx.architecture, "x86");
        assert_eq!(ctx.os, "linux");
        assert_eq!(ctx.pointer_size, 8);
        assert!(!ctx.big_endian);
    }

    #[test]
    fn test_default_registry() {
        let registry = create_default_registry();
        assert!(!registry.is_empty());
    }

    #[test]
    fn test_platform_opinion_clone() {
        let opinion = PlatformOpinion::new(
            "gdb", "ARM:LE:32:v8", "default", "ARM", 0.8
        );
        let cloned = opinion.clone();
        assert_eq!(opinion.language_id, cloned.language_id);
        assert!((opinion.confidence - cloned.confidence).abs() < f64::EPSILON);
    }
}

#[cfg(test)]
mod services_integration_comprehensive_tests {
    use crate::services::{
        ConsoleService, EmulationService,
        MappingProposal, ProgressService, TraceManagerService, WatchService,
    };
    

    struct TestTraceInfo {
        key: i64,
        name: String,
        active: bool,
    }

    impl crate::services::TraceInfo for TestTraceInfo {
        fn key(&self) -> i64 { self.key }
        fn name(&self) -> &str { &self.name }
        fn is_active(&self) -> bool { self.active }
    }

    #[test]
    fn test_trace_manager_full_workflow() {
        struct TestTraceManager {
            traces: Vec<TestTraceInfo>,
        }
        impl TestTraceManager {
            fn new() -> Self { Self { traces: vec![] } }
        }
        impl TraceManagerService for TestTraceManager {
            fn active_trace(&self) -> Option<&dyn crate::services::TraceInfo> {
                self.traces.iter().find(|t| t.active).map(|t| t as &dyn crate::services::TraceInfo)
            }
            fn open_trace(&mut self, key: i64) -> Result<(), String> {
                self.traces.push(TestTraceInfo { key, name: format!("trace-{}", key), active: false });
                Ok(())
            }
            fn close_trace(&mut self, key: i64) -> Result<(), String> {
                self.traces.retain(|t| t.key != key);
                Ok(())
            }
            fn activate_trace(&mut self, key: i64) -> Result<(), String> {
                for t in &mut self.traces { t.active = t.key == key; }
                Ok(())
            }
            fn open_traces(&self) -> Vec<&dyn crate::services::TraceInfo> {
                self.traces.iter().map(|t| t as &dyn crate::services::TraceInfo).collect()
            }
        }

        let mut mgr = TestTraceManager::new();
        assert!(mgr.active_trace().is_none());

        mgr.open_trace(1).unwrap();
        mgr.open_trace(2).unwrap();
        assert_eq!(mgr.open_traces().len(), 2);

        mgr.activate_trace(1).unwrap();
        assert!(mgr.active_trace().is_some());
        assert_eq!(mgr.active_trace().unwrap().key(), 1);

        mgr.close_trace(1).unwrap();
        assert_eq!(mgr.open_traces().len(), 1);
    }

    #[test]
    fn test_emulation_service_full_lifecycle() {
        struct TestEmuService { running: bool }
        impl TestEmuService { fn new() -> Self { Self { running: false } } }
        impl EmulationService for TestEmuService {
            fn start_emulation(&mut self, _: i64) -> Result<(), String> { self.running = true; Ok(()) }
            fn stop_emulation(&mut self, _: i64) -> Result<(), String> { self.running = false; Ok(()) }
            fn is_emulating(&self, _: i64) -> bool { self.running }
            fn step_emulation(&mut self, _: i64, n: u64) -> Result<(), String> {
                if !self.running { return Err("Not running".into()); }
                let _ = n; Ok(())
            }
        }

        let mut svc = TestEmuService::new();
        assert!(!svc.is_emulating(0));
        svc.start_emulation(0).unwrap();
        assert!(svc.is_emulating(0));
        svc.step_emulation(0, 100).unwrap();
        svc.stop_emulation(0).unwrap();
        assert!(!svc.is_emulating(0));
        assert!(svc.step_emulation(0, 1).is_err());
    }

    #[test]
    fn test_console_service() {
        struct TestConsole { messages: Vec<String> }
        impl TestConsole { fn new() -> Self { Self { messages: vec![] } } }
        impl ConsoleService for TestConsole {
            fn print(&mut self, msg: &str) { self.messages.push(msg.to_string()); }
            fn print_error(&mut self, msg: &str) { self.messages.push(format!("ERROR: {}", msg)); }
        }

        let mut svc = TestConsole::new();
        svc.print("hello");
        svc.print_error("bad");
        assert_eq!(svc.messages.len(), 2);
        assert_eq!(svc.messages[0], "hello");
        assert_eq!(svc.messages[1], "ERROR: bad");
    }

    #[test]
    fn test_progress_service() {
        struct TestProgress { tasks: Vec<(i64, f64)> }
        impl TestProgress { fn new() -> Self { Self { tasks: vec![] } } }
        impl ProgressService for TestProgress {
            fn start_task(&mut self, _: &str) -> i64 { self.tasks.push((1, 0.0)); 1 }
            fn update_progress(&mut self, id: i64, p: f64) { self.tasks.push((id, p)); }
            fn finish_task(&mut self, id: i64) { self.tasks.push((id, 1.0)); }
        }

        let mut svc = TestProgress::new();
        let task_id = svc.start_task("analysis");
        assert_eq!(task_id, 1);
        svc.update_progress(task_id, 0.5);
        svc.finish_task(task_id);
        assert_eq!(svc.tasks.len(), 3);
    }

    #[test]
    fn test_watch_service() {
        struct TestWatch { exprs: Vec<String> }
        impl TestWatch { fn new() -> Self { Self { exprs: vec![] } } }
        impl WatchService for TestWatch {
            fn add_watch(&mut self, expr: String) { self.exprs.push(expr); }
            fn remove_watch(&mut self, idx: usize) { if idx < self.exprs.len() { self.exprs.remove(idx); } }
            fn watches(&self) -> &[String] { &self.exprs }
        }

        let mut svc = TestWatch::new();
        svc.add_watch("RAX".into());
        svc.add_watch("[RSP]".into());
        assert_eq!(svc.watches().len(), 2);
        svc.remove_watch(0);
        assert_eq!(svc.watches().len(), 1);
        assert_eq!(svc.watches()[0], "[RSP]");
    }

    #[test]
    fn test_mapping_proposal() {
        let proposal = MappingProposal {
            program_min: 0x400000,
            program_max: 0x401000,
            trace_min: 0x7fff0000,
            trace_max: 0x7fff1000,
            confidence: 0.95,
        };
        assert_eq!(proposal.program_max - proposal.program_min, 0x1000);
        assert_eq!(proposal.trace_max - proposal.trace_min, 0x1000);
        assert!(proposal.confidence > 0.9);
    }
}

#[cfg(test)]
mod model_comprehensive_tests {
    use crate::model::{
        Lifespan, TraceBreakpointKind, TraceExecutionState,
        TraceMemoryState, TraceSchedule,
    };

    #[test]
    fn test_lifespan_at() {
        let span = Lifespan::at(42);
        assert!(span.contains(42));
        assert!(!span.contains(41));
        assert!(!span.contains(43));
    }

    #[test]
    fn test_lifespan_since() {
        let span = Lifespan::since(100);
        assert!(span.contains(0));
        assert!(span.contains(50));
        assert!(span.contains(100));
        assert!(!span.contains(101));
    }

    #[test]
    fn test_lifespan_now_on() {
        let span = Lifespan::now_on(100);
        assert!(span.contains(100));
        assert!(span.contains(i64::MAX));
        assert!(!span.contains(99));
    }

    #[test]
    fn test_lifespan_span() {
        let span = Lifespan::span(10, 20);
        assert!(span.contains(10));
        assert!(span.contains(15));
        assert!(span.contains(20));
        assert!(!span.contains(9));
        assert!(!span.contains(21));
    }

    #[test]
    fn test_lifespan_intersect() {
        let a = Lifespan::span(10, 20);
        let b = Lifespan::span(15, 25);
        let c = a.intersect(&b);
        assert!(c.contains(15));
        assert!(c.contains(20));
        assert!(!c.contains(14));
        assert!(!c.contains(21));
    }

    #[test]
    fn test_lifespan_no_intersection() {
        let a = Lifespan::span(10, 20);
        let b = Lifespan::span(30, 40);
        let c = a.intersect(&b);
        assert!(c.is_empty());
    }

    #[test]
    fn test_lifespan_encloses() {
        let outer = Lifespan::span(5, 25);
        let inner = Lifespan::span(10, 20);
        assert!(outer.encloses(&inner));
        assert!(!inner.encloses(&outer));
    }

    #[test]
    fn test_lifespan_is_empty() {
        let empty = Lifespan::span(10, 5);
        assert!(empty.is_empty());
        let non_empty = Lifespan::span(5, 10);
        assert!(!non_empty.is_empty());
    }

    #[test]
    fn test_lifespan_serde() {
        let span = Lifespan::span(5, 15);
        let json = serde_json::to_string(&span).unwrap();
        let back: Lifespan = serde_json::from_str(&json).unwrap();
        assert!(back.contains(5));
        assert!(back.contains(15));
        assert!(!back.contains(4));
    }

    #[test]
    fn test_lifespan_with_min_max() {
        let span = Lifespan::span(10, 20);
        let widened = span.with_min(5);
        assert!(widened.contains(5));
        assert!(widened.contains(20));

        let widened2 = span.with_max(30);
        assert!(widened2.contains(10));
        assert!(widened2.contains(30));
    }

    #[test]
    fn test_memory_state_variants() {
        assert_ne!(TraceMemoryState::Known, TraceMemoryState::Unknown);
        assert_ne!(TraceMemoryState::Known, TraceMemoryState::Error);
        assert_ne!(TraceMemoryState::Unknown, TraceMemoryState::Error);
    }

    #[test]
    fn test_memory_state_implied() {
        assert_eq!(TraceMemoryState::or_implied(None), TraceMemoryState::Unknown);
        assert_eq!(TraceMemoryState::or_implied(Some(TraceMemoryState::Known)), TraceMemoryState::Known);
        assert!(TraceMemoryState::Unknown.implied_by_null());
        assert!(!TraceMemoryState::Known.implied_by_null());
    }

    #[test]
    fn test_breakpoint_kind_variants() {
        assert_ne!(TraceBreakpointKind::Read, TraceBreakpointKind::Write);
        assert_ne!(TraceBreakpointKind::Read, TraceBreakpointKind::HwExecute);
        assert_ne!(TraceBreakpointKind::SwExecute, TraceBreakpointKind::HwExecute);
    }

    #[test]
    fn test_breakpoint_kind_encoding() {
        assert_eq!(TraceBreakpointKind::Read.encoding_char(), 'R');
        assert_eq!(TraceBreakpointKind::Write.encoding_char(), 'W');
        assert_eq!(TraceBreakpointKind::HwExecute.encoding_char(), 'X');
        assert_eq!(TraceBreakpointKind::SwExecute.encoding_char(), 'x');
    }

    #[test]
    fn test_breakpoint_kind_from_char() {
        assert_eq!(TraceBreakpointKind::from_char('R'), Some(TraceBreakpointKind::Read));
        assert_eq!(TraceBreakpointKind::from_char('W'), Some(TraceBreakpointKind::Write));
        assert_eq!(TraceBreakpointKind::from_char('Z'), None);
    }

    #[test]
    fn test_execution_state_variants() {
        assert_ne!(TraceExecutionState::Running, TraceExecutionState::Stopped);
        assert_ne!(TraceExecutionState::Running, TraceExecutionState::Terminated);
        assert_ne!(TraceExecutionState::Stopped, TraceExecutionState::Inactive);
        assert_ne!(TraceExecutionState::Alive, TraceExecutionState::Running);
    }

    #[test]
    fn test_schedule_creation() {
        let s = TraceSchedule::new(10, 5);
        assert_eq!(s.initial_snap, 10);
        assert_eq!(s.steps, 5);
    }

    #[test]
    fn test_schedule_parse() {
        let s = TraceSchedule::parse("10:5").unwrap();
        assert_eq!(s.initial_snap, 10);
        assert_eq!(s.steps, 5);
    }

    #[test]
    fn test_schedule_display() {
        let s = TraceSchedule::new(10, 5);
        assert_eq!(s.to_string(), "10:5");
    }
}

#[cfg(test)]
mod util_comprehensive_tests {
    use crate::util::byte_array_utils::{compute_diffs_address_set, hash_bytes, DiffRange};
    use crate::util::trace_register_utils::{compute_mask_offset, is_byte_bound};
    use crate::util::iterator_adapters::EnumeratingIterator;

    #[test]
    fn test_hash_bytes_deterministic() {
        let data = vec![0x01, 0x02, 0x03, 0x04];
        let h1 = hash_bytes(&data);
        let h2 = hash_bytes(&data);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_hash_bytes_different_data() {
        let h1 = hash_bytes(&[1, 2, 3]);
        let h2 = hash_bytes(&[1, 2, 4]);
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_compute_diffs_no_change() {
        let data = vec![0u8; 256];
        let diffs = compute_diffs_address_set(0x1000, &data, &data);
        assert!(diffs.is_empty());
    }

    #[test]
    fn test_compute_diffs_full_change() {
        let old = vec![0u8; 16];
        let new = vec![0xFFu8; 16];
        let diffs = compute_diffs_address_set(0x1000, &old, &new);
        assert!(!diffs.is_empty());
    }

    #[test]
    fn test_compute_diffs_partial_change() {
        let old = vec![0u8; 16];
        let mut new = vec![0u8; 16];
        new[5] = 0xFF;
        new[6] = 0xFF;
        let diffs = compute_diffs_address_set(0x1000, &old, &new);
        assert!(!diffs.is_empty());
    }

    #[test]
    fn test_is_byte_bound() {
        assert!(is_byte_bound(0, 8));
        assert!(is_byte_bound(0, 16));
        assert!(is_byte_bound(8, 8));
        assert!(!is_byte_bound(3, 8));
        assert!(!is_byte_bound(7, 8));
    }

    #[test]
    fn test_compute_mask_offset() {
        // compute_mask_offset(register_offset, base_register_offset) -> u32
        let offset = compute_mask_offset(0, 0);
        assert_eq!(offset, 0);
        let offset = compute_mask_offset(8, 0);
        assert_eq!(offset, 8);
        let offset = compute_mask_offset(16, 8);
        assert_eq!(offset, 8);
    }

    #[test]
    fn test_diff_range_len() {
        let diff = DiffRange::new(0x1000, 0x100F);
        assert_eq!(diff.len(), 16);
        assert!(!diff.is_empty());
    }

    #[test]
    fn test_diff_range_single_byte() {
        // DiffRange is inclusive: start=0x1000, end=0x1000 => len = 1
        let diff = DiffRange::new(0x1000, 0x1000);
        assert_eq!(diff.len(), 1);
        assert!(!diff.is_empty());
        // Empty range: start > end
        let empty = DiffRange::new(0x1001, 0x1000);
        assert!(empty.is_empty());
    }

    #[test]
    fn test_enumerating_iterator() {
        let items = vec!["a", "b", "c"];
        let iter = EnumeratingIterator::new(items.into_iter());
        let collected: Vec<(usize, &str)> = iter.collect();
        assert_eq!(collected.len(), 3);
        assert_eq!(collected[0].0, 0);
        assert_eq!(collected[1].0, 1);
        assert_eq!(collected[2].0, 2);
    }
}
