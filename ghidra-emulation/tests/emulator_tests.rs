//! Integration tests for P-code emulation.
//!
//! Covers:
//! - Emulator creation and configuration
//! - Register read/write and state inspection
//! - Memory read/write via segmented memory
//! - Breakpoint management
//! - Single P-code operation execution
//! - Instruction-level stepping
//! - Full emulation runs (loops, branches, breakpoints)
//! - Trace capture and inspection

use ghidra_core::addr::{Address, AddressSpace};
use ghidra_core::program::lang::{Language, LanguageID};
use ghidra_core::program::program::MemoryPermissions;
use ghidra_decompile::pcode::{OpCode, PcodeOperation, Varnode};
use ghidra_emulation::{
    BreakpointKind, BreakpointManager, EmulatedMemory, EmulationResult, Emulator, EmulatorState,
    MemorySegment, StopReason,
};
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn test_language() -> Language {
    Language {
        id: LanguageID::new("x86", "LE", 64),
        name: "x86:LE:64:default".into(),
        version: "1.0".into(),
    }
}

fn make_reg_vn(offset: u64, size: u32) -> Varnode {
    Varnode::new(
        AddressSpace::new("register", size as usize, false),
        offset,
        size,
    )
}

fn make_const_vn(value: u64, size: u32) -> Varnode {
    Varnode::constant(value, size)
}

fn make_ram_vn(offset: u64, size: u32) -> Varnode {
    Varnode::ram(offset, size)
}

fn make_op(opcode: OpCode, out: Option<Varnode>, inputs: Vec<Varnode>) -> PcodeOperation {
    PcodeOperation::new_unannotated(opcode, out, inputs)
}

fn setup_emulator() -> Emulator {
    let lang = test_language();
    let mut emu = Emulator::new(&lang);

    // Add memory segments
    emu.memory
        .add_segment(MemorySegment::new(0x0, 0x10000, MemoryPermissions::RW));
    emu.memory
        .add_segment(MemorySegment::new(0x1000, 0x1000, MemoryPermissions::RX));

    emu
}

// ---------------------------------------------------------------------------
// Emulator creation tests
// ---------------------------------------------------------------------------

#[test]
fn test_emulator_creation() {
    let lang = test_language();
    let emu = Emulator::new(&lang);
    assert_eq!(emu.pc, Address::new(0));
    assert!(emu.trace.is_empty());
    assert_eq!(emu.step_limit, 1_000_000);
    assert!(!emu.is_running());
}

#[test]
fn test_emulator_default() {
    let emu = Emulator::default();
    assert_eq!(emu.step_limit, 1_000_000);
    assert_eq!(emu.pc, Address::new(0));
}

// ---------------------------------------------------------------------------
// Register state tests
// ---------------------------------------------------------------------------

#[test]
fn test_register_read_write() {
    let mut emu = setup_emulator();

    // Set RAX to 0xDEADBEEF
    emu.set_register("RAX", &[0xEF, 0xBE, 0xAD, 0xDE, 0, 0, 0, 0]);
    let val = emu.get_register("RAX").unwrap();
    assert_eq!(val, &[0xEF, 0xBE, 0xAD, 0xDE, 0, 0, 0, 0]);

    // Set RBX to 0xCAFE
    emu.set_register("RBX", &[0xFE, 0xCA, 0, 0, 0, 0, 0, 0]);
    assert_eq!(
        emu.get_register("RBX").unwrap(),
        &[0xFE, 0xCA, 0, 0, 0, 0, 0, 0]
    );
}

#[test]
fn test_register_update() {
    let mut emu = setup_emulator();

    emu.set_register("RAX", &[0x00, 0x01, 0, 0, 0, 0, 0, 0]);
    assert_eq!(
        emu.get_register("RAX").unwrap(),
        &[0x00, 0x01, 0, 0, 0, 0, 0, 0]
    );

    emu.set_register("RAX", &[0x00, 0x02, 0, 0, 0, 0, 0, 0]);
    assert_eq!(
        emu.get_register("RAX").unwrap(),
        &[0x00, 0x02, 0, 0, 0, 0, 0, 0]
    );
}

#[test]
fn test_register_read_unset() {
    let emu = setup_emulator();
    assert!(emu.get_register("NONEXISTENT").is_none());
}

#[test]
fn test_multiple_registers_independence() {
    let mut emu = setup_emulator();

    emu.set_register("RAX", &[0x11, 0x11, 0, 0, 0, 0, 0, 0]);
    emu.set_register("RCX", &[0x22, 0x22, 0, 0, 0, 0, 0, 0]);
    emu.set_register("RDX", &[0x33, 0x33, 0, 0, 0, 0, 0, 0]);

    assert_eq!(
        emu.get_register("RAX").unwrap(),
        &[0x11, 0x11, 0, 0, 0, 0, 0, 0]
    );
    assert_eq!(
        emu.get_register("RCX").unwrap(),
        &[0x22, 0x22, 0, 0, 0, 0, 0, 0]
    );
    assert_eq!(
        emu.get_register("RDX").unwrap(),
        &[0x33, 0x33, 0, 0, 0, 0, 0, 0]
    );
}

// ---------------------------------------------------------------------------
// Memory access tests
// ---------------------------------------------------------------------------

#[test]
fn test_memory_write_read() {
    let mut emu = setup_emulator();

    let addr = Address::new(0x500);
    let data = vec![0x41, 0x42, 0x43, 0x44];
    emu.write_memory(addr, &data).unwrap();

    let read = emu.read_memory(addr, 4).unwrap();
    assert_eq!(read, data);
}

#[test]
fn test_memory_unwritten_fails_or_zeros() {
    let emu = setup_emulator();
    // Address 0x1000 is in the RX segment (readable)
    let data = emu.read_memory(Address::new(0x1000), 8).unwrap();
    assert_eq!(data, vec![0u8; 8]);
}

#[test]
fn test_memory_unmapped_fails() {
    let emu = setup_emulator();
    let result = emu.read_memory(Address::new(0xFFFF0000), 4);
    assert!(result.is_err());
}

#[test]
fn test_memory_overwrite() {
    let mut emu = setup_emulator();

    let addr = Address::new(0x200);
    emu.write_memory(addr, &[0x11, 0x22, 0x33, 0x44]).unwrap();
    emu.write_memory(addr, &[0xAA, 0xBB]).unwrap();

    let read = emu.read_memory(addr, 4).unwrap();
    assert_eq!(read[0], 0xAA);
    assert_eq!(read[1], 0xBB);
    assert_eq!(read[2], 0x33);
    assert_eq!(read[3], 0x44);
}

// ---------------------------------------------------------------------------
// Emulator reset test
// ---------------------------------------------------------------------------

#[test]
fn test_emulator_reset() {
    let mut emu = setup_emulator();
    emu.set_register("RAX", &[0x34, 0x12]);
    emu.write_memory(Address::new(0x100), &[0x41, 0x42])
        .unwrap();
    emu.pc = Address::new(0x4000);
    emu.set_breakpoint(Address::new(0x4000), BreakpointKind::Execution);

    emu.reset();

    assert_eq!(emu.pc, Address::new(0));
    assert!(emu.get_register("RAX").is_none());
    assert!(emu.breakpoints.is_empty());
    assert!(emu.trace.is_empty());
    assert!(!emu.is_running());
}

// ---------------------------------------------------------------------------
// Breakpoint manager tests
// ---------------------------------------------------------------------------

#[test]
fn test_breakpoint_manager() {
    let mut mgr = BreakpointManager::new();
    assert!(mgr.is_empty());
    assert_eq!(mgr.len(), 0);

    mgr.set(Address::new(0x400000), BreakpointKind::Execution);
    mgr.set(Address::new(0x401000), BreakpointKind::Read);
    mgr.set(Address::new(0x402000), BreakpointKind::Write);

    assert_eq!(mgr.len(), 3);
    assert!(!mgr.is_empty());

    assert!(mgr.is_set(&Address::new(0x400000)));
    assert!(mgr.is_set(&Address::new(0x401000)));
    assert!(!mgr.is_set(&Address::new(0x500000)));

    assert!(mgr.check_execution(&Address::new(0x400000)));
    assert!(!mgr.check_execution(&Address::new(0x401000))); // read, not exec

    mgr.clear(Address::new(0x401000));
    assert_eq!(mgr.len(), 2);

    mgr.clear_all();
    assert!(mgr.is_empty());
}

#[test]
fn test_breakpoint_hit_count() {
    let mut mgr = BreakpointManager::new();
    mgr.set(Address::new(0x401000), BreakpointKind::Execution);

    assert!(mgr.check_execution(&Address::new(0x401000)));
    assert!(mgr.check_execution(&Address::new(0x401000)));

    let bp = mgr.get(&Address::new(0x401000)).unwrap();
    assert_eq!(bp.hit_count, 2);
}

#[test]
fn test_breakpoint_enable_disable() {
    let mut mgr = BreakpointManager::new();
    mgr.set(Address::new(0x401000), BreakpointKind::Execution);

    assert!(mgr.is_set(&Address::new(0x401000)));

    mgr.disable(&Address::new(0x401000));
    assert!(!mgr.is_set(&Address::new(0x401000)));

    mgr.enable(&Address::new(0x401000));
    assert!(mgr.is_set(&Address::new(0x401000)));
}

#[test]
fn test_read_write_access_breakpoints() {
    let mut mgr = BreakpointManager::new();

    let addr_r = Address::new(0x1000);
    let addr_w = Address::new(0x2000);
    let addr_a = Address::new(0x3000);

    // Read breakpoint
    mgr.set(addr_r, BreakpointKind::Read);
    assert!(!mgr.check_execution(&addr_r));
    assert!(mgr.check_read(&addr_r));
    assert!(!mgr.check_write(&addr_r));

    // Write breakpoint
    mgr.set(addr_w, BreakpointKind::Write);
    assert!(!mgr.check_read(&addr_w));
    assert!(mgr.check_write(&addr_w));

    // Access breakpoint (both read and write)
    mgr.set(addr_a, BreakpointKind::Access);
    assert!(mgr.check_read(&addr_a));
    assert!(mgr.check_write(&addr_a));
}

#[test]
fn test_emulator_set_clear_breakpoint() {
    let mut emu = setup_emulator();
    let addr = Address::new(0x401000);

    assert!(!emu.breakpoints.is_set(&addr));

    emu.set_breakpoint(addr, BreakpointKind::Execution);
    assert!(emu.breakpoints.is_set(&addr));

    emu.clear_breakpoint(addr);
    assert!(!emu.breakpoints.is_set(&addr));
}

// ---------------------------------------------------------------------------
// P-code execution: single operations
// ---------------------------------------------------------------------------

#[test]
fn test_execute_copy_constant_to_register() {
    let mut emu = setup_emulator();

    let op = make_op(
        OpCode::COPY,
        Some(make_reg_vn(0, 8)),
        vec![make_const_vn(42, 8)],
    );

    emu.step_pcode(&op).unwrap();

    let val = emu.get_register("register:0x0").unwrap();
    assert_eq!(val, &[42, 0, 0, 0, 0, 0, 0, 0]);
}

#[test]
fn test_execute_int_add() {
    let mut emu = setup_emulator();
    emu.set_register("register:0x0", &[10, 0, 0, 0, 0, 0, 0, 0]); // RAX = 10
    emu.set_register("register:0x18", &[20, 0, 0, 0, 0, 0, 0, 0]); // RBX = 20

    let op = make_op(
        OpCode::INT_ADD,
        Some(make_reg_vn(0, 8)),
        vec![make_reg_vn(0, 8), make_reg_vn(0x18, 8)],
    );

    emu.step_pcode(&op).unwrap();
    let val = emu.get_register("register:0x0").unwrap();
    assert_eq!(val, &[30, 0, 0, 0, 0, 0, 0, 0]); // 10 + 20
}

#[test]
fn test_execute_int_add_constant() {
    let mut emu = setup_emulator();
    emu.set_register("register:0x0", &[100, 0, 0, 0, 0, 0, 0, 0]);

    let op = make_op(
        OpCode::INT_ADD,
        Some(make_reg_vn(0, 8)),
        vec![make_reg_vn(0, 8), make_const_vn(50, 8)],
    );

    emu.step_pcode(&op).unwrap();
    let val = emu.get_register("register:0x0").unwrap();
    assert_eq!(val, &[150, 0, 0, 0, 0, 0, 0, 0]);
}

#[test]
fn test_execute_int_sub() {
    let mut emu = setup_emulator();
    emu.set_register("register:0x0", &[100, 0, 0, 0, 0, 0, 0, 0]);

    let op = make_op(
        OpCode::INT_SUB,
        Some(make_reg_vn(0, 8)),
        vec![make_reg_vn(0, 8), make_const_vn(30, 8)],
    );

    emu.step_pcode(&op).unwrap();
    let val = emu.get_register("register:0x0").unwrap();
    assert_eq!(val, &[70, 0, 0, 0, 0, 0, 0, 0]);
}

#[test]
fn test_execute_int_add_overflow_wraps() {
    let mut emu = setup_emulator();
    emu.set_register(
        "register:0x0",
        &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
    );

    let op = make_op(
        OpCode::INT_ADD,
        Some(make_reg_vn(0, 8)),
        vec![make_reg_vn(0, 8), make_const_vn(1, 8)],
    );

    emu.step_pcode(&op).unwrap();
    let val = emu.get_register("register:0x0").unwrap();
    assert_eq!(val, &[0, 0, 0, 0, 0, 0, 0, 0]); // wrapped to 0
}

#[test]
fn test_execute_store_and_load() {
    let mut emu = setup_emulator();
    emu.set_register("register:0x0", &[0xEF, 0xBE, 0xAD, 0xDE, 0, 0, 0, 0]);

    // STORE *0x500, RAX
    let store_op = make_op(
        OpCode::STORE,
        None,
        vec![
            make_const_vn(0, 4),     // space-id
            make_const_vn(0x500, 8), // pointer: address 0x500
            make_reg_vn(0, 8),       // value: RAX
        ],
    );
    emu.step_pcode(&store_op).unwrap();

    // LOAD RBX = *0x500
    let load_op = make_op(
        OpCode::LOAD,
        Some(make_reg_vn(0x18, 8)), // output: RBX
        vec![
            make_const_vn(0, 4),     // space-id
            make_const_vn(0x500, 8), // pointer
        ],
    );
    emu.step_pcode(&load_op).unwrap();

    let val = emu.get_register("register:0x18").unwrap();
    assert_eq!(val[0], 0xEF);
    assert_eq!(val[1], 0xBE);
    assert_eq!(val[2], 0xAD);
    assert_eq!(val[3], 0xDE);
}

#[test]
fn test_execute_branch() {
    let mut emu = setup_emulator();

    let op = make_op(OpCode::BRANCH, None, vec![make_const_vn(0x401000, 8)]);

    emu.step_pcode(&op).unwrap();
    assert_eq!(emu.pc, Address::new(0x401000));
}

#[test]
fn test_execute_return() {
    let mut emu = setup_emulator();
    assert!(!emu.is_running());

    // Set a return address and run state
    emu.set_register(
        "emulator:return_address",
        &Address::new(0x2000).offset.to_le_bytes(),
    );

    let op = make_op(OpCode::RETURN, None, vec![]);
    emu.step_pcode(&op).unwrap();

    // RETURN should restore PC from the saved return address
    assert_eq!(emu.pc, Address::new(0x2000));
}

#[test]
fn test_execute_multiple_ops_sequence() {
    let mut emu = setup_emulator();

    let ops = vec![
        // RAX = 1
        make_op(
            OpCode::COPY,
            Some(make_reg_vn(0, 8)),
            vec![make_const_vn(1, 8)],
        ),
        // RBX = 2
        make_op(
            OpCode::COPY,
            Some(make_reg_vn(0x18, 8)),
            vec![make_const_vn(2, 8)],
        ),
        // RAX = RAX + RBX  (1 + 2 = 3)
        make_op(
            OpCode::INT_ADD,
            Some(make_reg_vn(0, 8)),
            vec![make_reg_vn(0, 8), make_reg_vn(0x18, 8)],
        ),
        // RAX = RAX + 5  (3 + 5 = 8)
        make_op(
            OpCode::INT_ADD,
            Some(make_reg_vn(0, 8)),
            vec![make_reg_vn(0, 8), make_const_vn(5, 8)],
        ),
    ];

    for op in &ops {
        emu.step_pcode(op).unwrap();
    }

    let val = emu.get_register("register:0x0").unwrap();
    assert_eq!(val, &[8, 0, 0, 0, 0, 0, 0, 0]); // 1 + 2 + 5 = 8
    assert_eq!(emu.trace.len(), 4);
}

// ---------------------------------------------------------------------------
// Instruction-level stepping
// ---------------------------------------------------------------------------

#[test]
fn test_step_instruction() {
    let mut emu = setup_emulator();
    emu.pc = Address::new(0x1000);

    emu.load_pcode(
        Address::new(0x1000),
        vec![
            make_op(
                OpCode::COPY,
                Some(make_reg_vn(0, 8)),
                vec![make_const_vn(10, 8)],
            ),
            make_op(
                OpCode::INT_ADD,
                Some(make_reg_vn(0, 8)),
                vec![make_reg_vn(0, 8), make_const_vn(20, 8)],
            ),
            make_op(
                OpCode::INT_MUL,
                Some(make_reg_vn(0, 8)),
                vec![make_reg_vn(0, 8), make_const_vn(3, 8)],
            ),
        ],
    );

    emu.step_instruction().unwrap();

    let val = emu.get_register("register:0x0").unwrap();
    // (10 + 20) * 3 = 90
    assert_eq!(val, &[90, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(emu.trace.len(), 3);
}

#[test]
fn test_step_instruction_no_pcode_fails() {
    let mut emu = setup_emulator();
    emu.pc = Address::new(0x9999);
    let result = emu.step_instruction();
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// Full emulation runs
// ---------------------------------------------------------------------------

#[test]
fn test_simple_addition_program() {
    let mut emu = setup_emulator();
    emu.pc = Address::new(0x1000);

    // A program that computes: result = a + b + c
    // a = 10, b = 20, c = 30

    // Instruction at 0x1000: R0 = 10
    emu.load_pcode(
        Address::new(0x1000),
        vec![make_op(
            OpCode::COPY,
            Some(make_reg_vn(0x00, 8)),
            vec![make_const_vn(10, 8)],
        )],
    );
    // Instruction at 0x1001: R1 = 20
    emu.load_pcode(
        Address::new(0x1001),
        vec![make_op(
            OpCode::COPY,
            Some(make_reg_vn(0x08, 8)),
            vec![make_const_vn(20, 8)],
        )],
    );
    // Instruction at 0x1002: R2 = 30
    emu.load_pcode(
        Address::new(0x1002),
        vec![make_op(
            OpCode::COPY,
            Some(make_reg_vn(0x10, 8)),
            vec![make_const_vn(30, 8)],
        )],
    );
    // Instruction at 0x1003: R3 = R0 + R1
    emu.load_pcode(
        Address::new(0x1003),
        vec![make_op(
            OpCode::INT_ADD,
            Some(make_reg_vn(0x18, 8)),
            vec![make_reg_vn(0x00, 8), make_reg_vn(0x08, 8)],
        )],
    );
    // Instruction at 0x1004: R3 = R3 + R2
    emu.load_pcode(
        Address::new(0x1004),
        vec![make_op(
            OpCode::INT_ADD,
            Some(make_reg_vn(0x18, 8)),
            vec![make_reg_vn(0x18, 8), make_reg_vn(0x10, 8)],
        )],
    );

    let result = emu.run(100).unwrap();

    assert!(matches!(result.reason, StopReason::Halt));
    let val = emu.get_register("register:0x18").unwrap();
    assert_eq!(val, &[60, 0, 0, 0, 0, 0, 0, 0]); // 10 + 20 + 30 = 60
    assert_eq!(emu.trace.len(), 5);
}

#[test]
fn test_run_with_branch_sequence() {
    let mut emu = setup_emulator();
    emu.pc = Address::new(0x1000);

    // 0x1000: RAX = 1, then BRANCH to 0x2000
    emu.load_pcode(
        Address::new(0x1000),
        vec![
            make_op(
                OpCode::COPY,
                Some(make_reg_vn(0, 8)),
                vec![make_const_vn(1, 8)],
            ),
            make_op(OpCode::BRANCH, None, vec![make_const_vn(0x2000, 8)]),
        ],
    );
    // 0x2000: RBX = 2
    emu.load_pcode(
        Address::new(0x2000),
        vec![make_op(
            OpCode::COPY,
            Some(make_reg_vn(0x18, 8)),
            vec![make_const_vn(2, 8)],
        )],
    );

    let result = emu.run(100).unwrap();

    assert!(matches!(result.reason, StopReason::Halt));
    assert_eq!(
        emu.get_register("register:0x0").unwrap(),
        &[1, 0, 0, 0, 0, 0, 0, 0]
    );
    assert_eq!(
        emu.get_register("register:0x18").unwrap(),
        &[2, 0, 0, 0, 0, 0, 0, 0]
    );
}

#[test]
fn test_run_stops_on_breakpoint() {
    let mut emu = setup_emulator();
    emu.pc = Address::new(0x1000);

    emu.load_pcode(
        Address::new(0x1000),
        vec![make_op(
            OpCode::COPY,
            Some(make_reg_vn(0, 8)),
            vec![make_const_vn(1, 8)],
        )],
    );
    emu.load_pcode(
        Address::new(0x1001),
        vec![make_op(
            OpCode::COPY,
            Some(make_reg_vn(0x8, 8)),
            vec![make_const_vn(2, 8)],
        )],
    );
    emu.load_pcode(
        Address::new(0x1002),
        vec![make_op(
            OpCode::COPY,
            Some(make_reg_vn(0x10, 8)),
            vec![make_const_vn(3, 8)],
        )],
    );

    // Set breakpoint at 0x1001
    emu.set_breakpoint(Address::new(0x1001), BreakpointKind::Execution);

    let result = emu.run(100).unwrap();

    match &result.reason {
        StopReason::Breakpoint(addr) => assert_eq!(*addr, Address::new(0x1001)),
        other => panic!("expected Breakpoint, got {:?}", other),
    }

    // Only instruction at 0x1000 should have executed
    // (breakpoint at 0x1001 fires before that instruction runs)
    assert_eq!(emu.trace.len(), 0); // no steps traced because breakpoint fires before step
}

#[test]
fn test_run_stops_on_max_steps() {
    let mut emu = setup_emulator();
    emu.pc = Address::new(0x1000);

    for i in 0..10 {
        emu.load_pcode(
            Address::new(0x1000 + i),
            vec![make_op(
                OpCode::COPY,
                Some(make_reg_vn(i, 8)),
                vec![make_const_vn(i, 8)],
            )],
        );
    }

    let result = emu.run(5).unwrap();

    assert!(matches!(result.reason, StopReason::MaxSteps));
    assert!(result.steps_executed <= 5);
}

// ---------------------------------------------------------------------------
// Trace tests
// ---------------------------------------------------------------------------

#[test]
fn test_trace_captures_register_changes() {
    let mut emu = setup_emulator();
    emu.pc = Address::new(0x1000);

    emu.load_pcode(
        Address::new(0x1000),
        vec![
            make_op(
                OpCode::COPY,
                Some(make_reg_vn(0, 8)),
                vec![make_const_vn(100, 8)],
            ),
            make_op(
                OpCode::INT_ADD,
                Some(make_reg_vn(0, 8)),
                vec![make_reg_vn(0, 8), make_const_vn(50, 8)],
            ),
        ],
    );

    emu.step_instruction().unwrap();

    assert_eq!(emu.trace.len(), 2);
    assert_eq!(emu.trace[0].operation.opcode, OpCode::COPY);
    assert_eq!(emu.trace[1].operation.opcode, OpCode::INT_ADD);

    // First step: register:0x0 was set to 100
    let changes0 = &emu.trace[0].register_changes;
    assert!(changes0.contains_key("register:0x0"));

    // Second step: register:0x0 was updated from 100 to 150
    let changes1 = &emu.trace[1].register_changes;
    assert!(changes1.contains_key("register:0x0"));
}

// ---------------------------------------------------------------------------
// Conditional branch test
// ---------------------------------------------------------------------------

#[test]
fn test_cbranch_taken() {
    let mut emu = setup_emulator();
    emu.pc = Address::new(0x1000);

    // Set condition register to non-zero (true)
    emu.set_register("register:0x0", &[1, 0, 0, 0, 0, 0, 0, 0]);

    emu.load_pcode(
        Address::new(0x1000),
        vec![make_op(
            OpCode::CBRANCH,
            None,
            vec![
                make_const_vn(0x3000, 8), // target
                make_reg_vn(0, 8),        // condition
            ],
        )],
    );

    // After stepping, PC should be at 0x3000
    emu.step_instruction().unwrap();
    assert_eq!(emu.pc, Address::new(0x3000));
}

#[test]
fn test_cbranch_not_taken() {
    let mut emu = setup_emulator();
    emu.pc = Address::new(0x1000);

    // Set condition register to zero (false)
    emu.set_register("register:0x0", &[0, 0, 0, 0, 0, 0, 0, 0]);

    emu.load_pcode(
        Address::new(0x1000),
        vec![make_op(
            OpCode::CBRANCH,
            None,
            vec![
                make_const_vn(0x3000, 8), // target
                make_reg_vn(0, 8),        // condition
            ],
        )],
    );

    emu.step_instruction().unwrap();
    // PC should advance past this instruction (0x1000 -> 0x1001)
    assert_eq!(emu.pc, Address::new(0x1001));
}

// ---------------------------------------------------------------------------
// Divide by zero test
// ---------------------------------------------------------------------------

#[test]
fn test_divide_by_zero() {
    let mut emu = setup_emulator();
    emu.set_register("register:0x0", &[10, 0, 0, 0, 0, 0, 0, 0]);

    let op = make_op(
        OpCode::INT_DIV,
        Some(make_reg_vn(0, 8)),
        vec![make_reg_vn(0, 8), make_const_vn(0, 8)],
    );

    let result = emu.step_pcode(&op);
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// EmulatorState standalone tests
// ---------------------------------------------------------------------------

#[test]
fn test_emulator_state() {
    let mut state = EmulatorState::new();

    state.set_register("R0", &[0x10, 0x20]);
    assert_eq!(state.get_register("R0").unwrap(), &[0x10, 0x20]);

    state.set_flag("ZF", true);
    state.set_flag("CF", false);
    assert_eq!(state.get_flag("ZF"), Some(true));
    assert_eq!(state.get_flag("CF"), Some(false));
    assert_eq!(state.get_flag("OF"), None);

    state.clear();
    assert!(state.get_register("R0").is_none());
    assert!(state.get_flag("ZF").is_none());
}
