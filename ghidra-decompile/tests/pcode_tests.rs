//! Tests for P-code operations: creation, OpCode classification, and P-code sequence building.
//!
//! Covers the `ghidra_decompile::pcode` module:
//! - [`PcodeOp`] creation and properties
//! - [`OpCode`] enumeration and classification (control flow, boolean, arithmetic)
//! - [`Varnode`] constructors and space management
//! - [`SpaceType`] index and round-trip mappings

use ghidra_decompile::pcode::{OpCode, PcodeOp, SpaceType, Varnode};

// ---------------------------------------------------------------------------
// SpaceType tests
// ---------------------------------------------------------------------------

#[test]
fn test_space_type_indices() {
    assert_eq!(SpaceType::Register.index(), 0);
    assert_eq!(SpaceType::Ram.index(), 1);
    assert_eq!(SpaceType::Constant.index(), 2);
    assert_eq!(SpaceType::Unique.index(), 3);
    assert_eq!(SpaceType::Other(42).index(), 42);
}

#[test]
fn test_space_type_from_index() {
    assert_eq!(SpaceType::from_index(0), SpaceType::Register);
    assert_eq!(SpaceType::from_index(1), SpaceType::Ram);
    assert_eq!(SpaceType::from_index(2), SpaceType::Constant);
    assert_eq!(SpaceType::from_index(3), SpaceType::Unique);
    assert_eq!(SpaceType::from_index(42), SpaceType::Other(42));
}

#[test]
fn test_space_type_roundtrip() {
    for idx in 0..20u32 {
        let st = SpaceType::from_index(idx);
        assert_eq!(st.index(), idx, "Roundtrip failed for index {}", idx);
    }
}

#[test]
fn test_space_type_classification() {
    assert!(SpaceType::Register.is_register());
    assert!(SpaceType::Ram.is_ram());
    assert!(SpaceType::Constant.is_constant());
    assert!(SpaceType::Unique.is_unique());

    assert!(!SpaceType::Other(5).is_register());
    assert!(!SpaceType::Other(5).is_ram());
    assert!(!SpaceType::Other(5).is_constant());
    assert!(!SpaceType::Other(5).is_unique());
}

#[test]
fn test_space_type_names() {
    assert_eq!(SpaceType::Register.name(), "register");
    assert_eq!(SpaceType::Ram.name(), "ram");
    assert_eq!(SpaceType::Constant.name(), "constant");
    assert_eq!(SpaceType::Unique.name(), "unique");
    assert_eq!(SpaceType::Other(99).name(), "other");
}

#[test]
fn test_space_type_display() {
    assert_eq!(format!("{}", SpaceType::Register), "register");
    assert_eq!(format!("{}", SpaceType::Ram), "ram");
    assert_eq!(format!("{}", SpaceType::Constant), "const");
    assert_eq!(format!("{}", SpaceType::Unique), "unique");
    assert_eq!(format!("{}", SpaceType::Other(7)), "space_7");
}

// ---------------------------------------------------------------------------
// Varnode tests
// ---------------------------------------------------------------------------

#[test]
fn test_varnode_register_creation() {
    let reg = Varnode::register(0, 4);
    assert_eq!(reg.space, SpaceType::Register);
    assert_eq!(reg.offset, 0);
    assert_eq!(reg.size, 4);
    assert!(reg.is_register());
    assert!(!reg.is_constant());
    assert!(!reg.is_ram());
}

#[test]
fn test_varnode_ram_creation() {
    let ram = Varnode::ram(0x7FFF_1234, 8);
    assert_eq!(reg.space, SpaceType::Ram);
    assert!(!ram.is_register());
    assert!(ram.is_ram());
    assert!(ram.is_address()); // RAM varnodes represent addresses
}

#[test]
fn test_varnode_constant_creation() {
    let cnst = Varnode::constant(42, 4);
    assert_eq!(cnst.space, SpaceType::Constant);
    assert_eq!(cnst.offset, 42);
    assert_eq!(cnst.size, 4);
    assert!(cnst.is_constant());
}

#[test]
fn test_varnode_unique_creation() {
    let uniq = Varnode::unique(100, 4);
    assert_eq!(uniq.space, SpaceType::Unique);
    assert_eq!(uniq.offset, 100);
    assert!(uniq.is_unique());
    assert!(!uniq.is_address());
}

#[test]
fn test_varnode_free() {
    let free = Varnode::free();
    assert!(free.is_free());
    assert_eq!(free.space, SpaceType::Unique);
    assert_eq!(free.offset, u64::MAX);
}

#[test]
fn test_varnode_not_free() {
    let reg = Varnode::register(0, 8);
    assert!(!reg.is_free());

    let uniq = Varnode::unique(42, 4);
    assert!(!uniq.is_free());
}

#[test]
fn test_varnode_display() {
    let reg = Varnode::register(0, 4);
    let s = format!("{}", reg);
    assert!(s.contains("register"));
    assert!(s.contains("0x0"));
    assert!(s.contains("4"));
}

#[test]
fn test_varnode_equality() {
    let a = Varnode::register(4, 4);
    let b = Varnode::register(4, 4);
    let c = Varnode::register(8, 4);
    assert_eq!(a, b);
    assert_ne!(a, c);
}

#[test]
fn test_varnode_endian_flip_offset() {
    let reg = Varnode::register(4, 2); // little-endian access at offset 4 within a register

    // Little-endian with wordsize 8:
    // offset % 8 = 4, sub_off = 4
    // new offset = 4 - 4 + (8 - 4 - 2) = 0 + 2 = 2
    let flipped = reg.flip_offset_endian(8, false);
    assert_eq!(flipped, 2);

    // Big-endian: no flip
    let same = reg.flip_offset_endian(8, true);
    assert_eq!(same, 4);
}

#[test]
fn test_varnode_constant_is_not_address() {
    let cnst = Varnode::constant(0x400000, 8);
    assert!(!cnst.is_address());
}

// ---------------------------------------------------------------------------
// OpCode roundtrip tests
// ---------------------------------------------------------------------------

#[test]
fn test_opcode_to_u32() {
    // Data movement
    assert_eq!(OpCode::Copy.to_u32(), 1);
    assert_eq!(OpCode::Load.to_u32(), 2);
    assert_eq!(OpCode::Store.to_u32(), 3);

    // Control flow
    assert_eq!(OpCode::Branch.to_u32(), 4);
    assert_eq!(OpCode::Cbranch.to_u32(), 5);
    assert_eq!(OpCode::Branchind.to_u32(), 6);
    assert_eq!(OpCode::Call.to_u32(), 7);
    assert_eq!(OpCode::Callind.to_u32(), 8);
    assert_eq!(OpCode::Callother.to_u32(), 9);
    assert_eq!(OpCode::Return.to_u32(), 10);
}

#[test]
fn test_opcode_from_u32() {
    assert_eq!(OpCode::from_u32(1), OpCode::Copy);
    assert_eq!(OpCode::from_u32(2), OpCode::Load);
    assert_eq!(OpCode::from_u32(7), OpCode::Call);
    assert_eq!(OpCode::from_u32(10), OpCode::Return);
}

#[test]
fn test_opcode_roundtrip_all_defined() {
    // All opcodes 1-63 should round-trip
    for n in 1..=63u32 {
        let op = OpCode::from_u32(n);
        let back = op.to_u32();
        assert_eq!(back, n, "OpCode roundtrip failed for {}", n);
    }
}

#[test]
fn test_opcode_user_defined() {
    let ud = OpCode::from_u32(1000);
    assert_eq!(ud, OpCode::UserDefined(1000));
    assert_eq!(ud.to_u32(), 1000);
}

// ---------------------------------------------------------------------------
// OpCode classification tests
// ---------------------------------------------------------------------------

#[test]
fn test_is_control_flow() {
    let control_flow_ops = [
        OpCode::Branch,
        OpCode::Cbranch,
        OpCode::Branchind,
        OpCode::Call,
        OpCode::Callind,
        OpCode::Callother,
        OpCode::Return,
    ];

    for op in &control_flow_ops {
        assert!(op.is_control_flow(), "{:?} should be control flow", op);
    }

    let non_cf_ops = [
        OpCode::Copy,
        OpCode::IntAdd,
        OpCode::IntSub,
        OpCode::IntAnd,
        OpCode::IntOr,
    ];

    for op in &non_cf_ops {
        assert!(!op.is_control_flow(), "{:?} should NOT be control flow", op);
    }
}

#[test]
fn test_is_boolean_op() {
    let boolean_ops = [
        OpCode::IntEqual,
        OpCode::IntNotEqual,
        OpCode::IntLess,
        OpCode::IntLessEqual,
        OpCode::IntSless,
        OpCode::IntSlessEqual,
        OpCode::BoolAnd,
        OpCode::BoolOr,
        OpCode::BoolXor,
        OpCode::BoolNeg,
        OpCode::FloatEqual,
        OpCode::FloatNotEqual,
        OpCode::FloatLess,
        OpCode::FloatLessEqual,
        OpCode::FloatNan,
    ];

    for op in &boolean_ops {
        assert!(op.is_boolean_op(), "{:?} should be boolean", op);
    }

    assert!(!OpCode::IntAdd.is_boolean_op());
    assert!(!OpCode::Copy.is_boolean_op());
}

// ---------------------------------------------------------------------------
// OpCode arithmetic classification
// ---------------------------------------------------------------------------

#[test]
fn test_integer_arithmetic_ops() {
    let arith_ops = [
        OpCode::IntAdd,
        OpCode::IntSub,
        OpCode::IntMult,
        OpCode::IntDiv,
        OpCode::IntSdiv,
        OpCode::IntRem,
        OpCode::IntSrem,
        OpCode::IntNeg,
    ];

    for op in &arith_ops {
        assert!(!op.is_control_flow());
        assert!(!op.is_boolean_op());
    }
}

#[test]
fn test_float_ops() {
    let float_ops = [
        OpCode::FloatAdd,
        OpCode::FloatSub,
        OpCode::FloatMult,
        OpCode::FloatDiv,
        OpCode::FloatNeg,
    ];

    for op in &float_ops {
        assert!(!op.is_control_flow());
    }
}

// ---------------------------------------------------------------------------
// OpCode display tests
// ---------------------------------------------------------------------------

#[test]
fn test_opcode_display() {
    assert_eq!(format!("{}", OpCode::Copy), "COPY");
    assert_eq!(format!("{}", OpCode::Load), "LOAD");
    assert_eq!(format!("{}", OpCode::Store), "STORE");
    assert_eq!(format!("{}", OpCode::Branch), "BRANCH");
    assert_eq!(format!("{}", OpCode::Call), "CALL");
    assert_eq!(format!("{}", OpCode::Return), "RETURN");
    assert_eq!(format!("{}", OpCode::IntAdd), "INT_ADD");
    assert_eq!(format!("{}", OpCode::IntSub), "INT_SUB");
    assert_eq!(format!("{}", OpCode::IntEqual), "INT_EQUAL");
    assert_eq!(format!("{}", OpCode::IntNotEqual), "INT_NOTEQUAL");
    assert_eq!(format!("{}", OpCode::UserDefined(42)), "USERDEF_42");
}

// ---------------------------------------------------------------------------
// PcodeOp creation tests
// ---------------------------------------------------------------------------

#[test]
fn test_pcode_op_creation() {
    let op = PcodeOp::new(
        OpCode::IntAdd,
        Some(Varnode::register(0, 4)),              // output: reg0
        vec![Varnode::register(4, 4), Varnode::constant(1, 4)], // inputs: reg4, const 1
    );

    assert_eq!(op.opcode, OpCode::IntAdd);
    assert!(op.output.is_some());
    assert_eq!(op.output.as_ref().unwrap().offset, 0);
    assert_eq!(op.inputs.len(), 2);
    assert_eq!(op.inputs[0].offset, 4);
    assert_eq!(op.inputs[1].offset, 1);
    assert_eq!(op.sequence, 0); // default
}

#[test]
fn test_pcode_op_with_sequence() {
    let op = PcodeOp::with_sequence(
        OpCode::Store,
        Some(Varnode::ram(0x400000, 4)),
        vec![Varnode::register(0, 4)],
        42,
    );
    assert_eq!(op.sequence, 42);
}

#[test]
fn test_pcode_op_num_inputs() {
    let op = PcodeOp::new(
        OpCode::Copy,
        Some(Varnode::unique(5, 4)),
        vec![Varnode::register(0, 4)],
    );
    assert_eq!(op.num_inputs(), 1);

    let op2 = PcodeOp::new(
        OpCode::IntAdd,
        Some(Varnode::unique(6, 4)),
        vec![Varnode::register(0, 4), Varnode::register(4, 4)],
    );
    assert_eq!(op2.num_inputs(), 2);

    let op3 = PcodeOp::new(OpCode::Return, None, vec![Varnode::register(0, 4)]);
    assert_eq!(op3.num_inputs(), 1);
}

#[test]
fn test_pcode_op_is_noop_copy() {
    // A copy from a varnode to itself is a no-op
    let v = Varnode::register(0, 4);
    let op = PcodeOp::new(OpCode::Copy, Some(v.clone()), vec![v.clone()]);
    assert!(op.is_noop_copy());

    // A copy to a different destination is NOT a no-op
    let op2 = PcodeOp::new(
        OpCode::Copy,
        Some(Varnode::register(0, 4)),
        vec![Varnode::register(4, 4)],
    );
    assert!(!op2.is_noop_copy());

    // A non-copy operation is never a no-op copy
    let op3 = PcodeOp::new(OpCode::IntAdd, Some(v.clone()), vec![]);
    assert!(!op3.is_noop_copy());
}

#[test]
fn test_pcode_op_is_dead() {
    // Operation without output and without control flow = dead
    let op = PcodeOp::new(OpCode::IntAdd, None, vec![Varnode::register(0, 4)]);
    assert!(op.is_dead());

    // Operation with output = not dead
    let op2 = PcodeOp::new(
        OpCode::IntAdd,
        Some(Varnode::register(0, 4)),
        vec![Varnode::register(4, 4)],
    );
    assert!(!op2.is_dead());

    // Control flow without output = not dead
    let op3 = PcodeOp::new(
        OpCode::Branch,
        None,
        vec![Varnode::constant(0x401000, 8)],
    );
    assert!(!op3.is_dead());
}

// ---------------------------------------------------------------------------
// PcodeOp display tests
// ---------------------------------------------------------------------------

#[test]
fn test_pcode_op_display_with_output() {
    let op = PcodeOp::new(
        OpCode::IntAdd,
        Some(Varnode::register(0, 4)),
        vec![Varnode::register(4, 4), Varnode::constant(1, 4)],
    );
    let s = format!("{}", op);
    assert!(s.contains("INT_ADD"));
    assert!(s.contains("register"));
}

#[test]
fn test_pcode_op_display_without_output() {
    let op = PcodeOp::new(
        OpCode::Return,
        None,
        vec![Varnode::register(0, 4)],
    );
    let s = format!("{}", op);
    assert!(s.contains("RETURN"));
}

// ---------------------------------------------------------------------------
// P-code sequence building
// ---------------------------------------------------------------------------

#[test]
fn test_build_add_sequence() {
    // RAX = RAX + 1
    let mut ops = Vec::new();

    ops.push(PcodeOp::new(
        OpCode::IntAdd,
        Some(Varnode::register(0, 8)),   // output: RAX (offset 0, 8 bytes)
        vec![
            Varnode::register(0, 8),      // input 1: RAX
            Varnode::constant(1, 8),       // input 2: constant 1
        ],
    ));

    assert_eq!(ops.len(), 1);
    assert_eq!(ops[0].num_inputs(), 2);
}

#[test]
fn test_build_load_store_sequence() {
    // Push RAX onto the stack: sub RSP, 8; store [RSP], RAX
    let mut ops = Vec::new();

    // RSP = RSP - 8
    ops.push(PcodeOp::new(
        OpCode::IntSub,
        Some(Varnode::register(0x20, 8)),     // output: RSP
        vec![Varnode::register(0x20, 8), Varnode::constant(8, 8)],
    ));

    // *RSP = RAX
    ops.push(PcodeOp::new(
        OpCode::Store,
        None,
        vec![Varnode::register(0x20, 8), Varnode::register(0, 8)], // [RSP], RAX
    ));

    assert_eq!(ops.len(), 2);
    assert_eq!(ops[0].opcode, OpCode::IntSub);
    assert_eq!(ops[1].opcode, OpCode::Store);
}

#[test]
fn test_build_call_sequence() {
    // CALL 0x401000:
    // 1. *(RSP - 8) = return_address  (implicit push)
    // 2. RSP = RSP - 8
    // 3. goto 0x401000

    let mut ops = Vec::new();

    ops.push(PcodeOp::new(
        OpCode::Call,
        None,
        vec![Varnode::constant(0x401000, 8)],
    ));

    ops.push(PcodeOp::new(
        OpCode::Return,
        None,
        vec![],
    ));

    assert_eq!(ops.len(), 2);
    assert!(ops[0].opcode.is_control_flow());
    assert!(ops[1].opcode.is_control_flow());
}

#[test]
fn test_build_conditional_branch() {
    // CMP RAX, RBX; JZ label
    let mut ops = Vec::new();

    // tmp = RAX == RBX
    ops.push(PcodeOp::new(
        OpCode::IntEqual,
        Some(Varnode::unique(0, 1)),
        vec![Varnode::register(0, 8), Varnode::register(0x18, 8)],
    ));

    // if tmp goto label
    ops.push(PcodeOp::new(
        OpCode::Cbranch,
        None,
        vec![
            Varnode::unique(0, 1),
            Varnode::constant(0x1050, 8),
        ],
    ));

    assert_eq!(ops.len(), 2);
    assert!(ops[0].opcode.is_boolean_op());
    assert!(ops[1].opcode.is_control_flow());
}

#[test]
fn test_build_variable_assignment() {
    // int x = 42 (in decompiled output)
    let op = PcodeOp::new(
        OpCode::Copy,
        Some(Varnode::unique(1, 4)),
        vec![Varnode::constant(42, 4)],
    );

    assert_eq!(op.opcode, OpCode::Copy);
    assert_eq!(op.inputs[0].offset, 42);
    assert!(op.inputs[0].is_constant());
}

// ---------------------------------------------------------------------------
// OpCode semantic group tests
// ---------------------------------------------------------------------------

#[test]
fn test_data_movement_ops() {
    let data_ops = [OpCode::Copy, OpCode::Load, OpCode::Store];
    for op in &data_ops {
        assert!(!op.is_control_flow());
        assert!(!op.is_boolean_op());
    }
}

#[test]
fn test_shift_ops() {
    let shift_ops = [OpCode::IntLeft, OpCode::IntRight, OpCode::IntSright];
    for op in &shift_ops {
        assert!(!op.is_control_flow());
        assert!(!op.is_boolean_op());
    }
}

#[test]
fn test_extension_ops() {
    let ext_ops = [
        OpCode::SegmentOp,
        OpCode::CpoolRef,
        OpCode::New,
        OpCode::Insert,
        OpCode::Extract,
        OpCode::Popcount,
        OpCode::Lzcount,
    ];
    for op in &ext_ops {
        assert!(!op.is_control_flow());
        assert!(!op.is_boolean_op());
    }
}
