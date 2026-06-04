//! Tests for P-code operations: creation, OpCode classification, and P-code sequence building.
//!
//! Covers the `ghidra_decompile::pcode` module:
//! - [`PcodeOperation`] creation and properties
//! - [`OpCode`] enumeration and classification (control flow, boolean, arithmetic)
//! - [`Varnode`] constructors and space management

use ghidra_decompile::pcode::{OpCode, PcodeOperation, Varnode};

// ---------------------------------------------------------------------------
// Varnode tests
// ---------------------------------------------------------------------------

#[test]
fn test_varnode_register_creation() {
    let reg = Varnode::register("register", 0, 4);
    assert_eq!(reg.offset, 0);
    assert_eq!(reg.size, 4);
    assert!(reg.is_register());
    assert!(!reg.is_constant());
    assert!(!reg.is_ram());
}

#[test]
fn test_varnode_constant_creation() {
    let cnst = Varnode::constant(42, 4);
    assert_eq!(cnst.offset, 42);
    assert_eq!(cnst.size, 4);
    assert!(cnst.is_constant());
}

#[test]
fn test_varnode_unique_creation() {
    let uniq = Varnode::unique(100, 4);
    assert_eq!(uniq.offset, 100);
    assert!(uniq.is_unique());
}

#[test]
fn test_varnode_ram_creation() {
    let ram = Varnode::ram(0x7FFF_1234, 8);
    assert!(!ram.is_register());
    assert!(ram.is_ram());
}

#[test]
fn test_varnode_equality() {
    let a = Varnode::register("r", 4, 4);
    let b = Varnode::register("r", 4, 4);
    let c = Varnode::register("r", 8, 4);
    assert_eq!(a, b);
    assert_ne!(a, c);
}

// ---------------------------------------------------------------------------
// OpCode classification tests
// ---------------------------------------------------------------------------

#[test]
fn test_opcode_branch_classification() {
    assert!(OpCode::BRANCH.is_branch());
    assert!(OpCode::CBRANCH.is_branch());
    assert!(OpCode::BRANCHIND.is_branch());
    assert!(!OpCode::COPY.is_branch());
    assert!(!OpCode::INT_ADD.is_branch());
}

#[test]
fn test_opcode_call_classification() {
    assert!(OpCode::CALL.is_call());
    assert!(OpCode::CALLIND.is_call());
    assert!(!OpCode::COPY.is_call());
}

#[test]
fn test_opcode_return_classification() {
    assert!(OpCode::RETURN.is_return());
    assert!(!OpCode::COPY.is_return());
}

#[test]
fn test_opcode_flow_classification() {
    assert!(OpCode::BRANCH.is_flow());
    assert!(OpCode::CBRANCH.is_flow());
    assert!(OpCode::CALL.is_flow());
    assert!(OpCode::RETURN.is_flow());
    assert!(!OpCode::COPY.is_flow());
    assert!(!OpCode::INT_ADD.is_flow());
}

#[test]
fn test_opcode_arithmetic_classification() {
    assert!(OpCode::INT_ADD.is_arithmetic());
    assert!(OpCode::INT_SUB.is_arithmetic());
    assert!(OpCode::INT_MUL.is_arithmetic());
    assert!(OpCode::INT_DIV.is_arithmetic());
    assert!(!OpCode::COPY.is_arithmetic());
    assert!(!OpCode::BRANCH.is_arithmetic());
}

#[test]
fn test_opcode_comparison_classification() {
    assert!(OpCode::INT_EQUAL.is_comparison());
    assert!(OpCode::INT_NOTEQUAL.is_comparison());
    assert!(OpCode::INT_LESS.is_comparison());
    assert!(OpCode::INT_SLESS.is_comparison());
    assert!(!OpCode::INT_ADD.is_comparison());
}

#[test]
fn test_opcode_logical_classification() {
    assert!(OpCode::BOOL_AND.is_logical());
    assert!(OpCode::BOOL_OR.is_logical());
    assert!(OpCode::BOOL_NEGATE.is_logical());
    assert!(!OpCode::INT_ADD.is_logical());
}

#[test]
fn test_opcode_shift_classification() {
    assert!(OpCode::INT_LEFT.is_shift());
    assert!(OpCode::INT_RIGHT.is_shift());
    assert!(OpCode::INT_SRIGHT.is_shift());
    assert!(!OpCode::INT_ADD.is_shift());
}

#[test]
fn test_opcode_float_classification() {
    assert!(OpCode::FLOAT_ADD.is_float());
    assert!(OpCode::FLOAT_SUB.is_float());
    assert!(OpCode::FLOAT_MUL.is_float());
    assert!(OpCode::FLOAT_DIV.is_float());
    assert!(!OpCode::INT_ADD.is_float());
}

#[test]
fn test_opcode_display() {
    assert_eq!(OpCode::COPY.name(), "COPY");
    assert_eq!(OpCode::LOAD.name(), "LOAD");
    assert_eq!(OpCode::STORE.name(), "STORE");
    assert_eq!(OpCode::BRANCH.name(), "BRANCH");
    assert_eq!(OpCode::CALL.name(), "CALL");
    assert_eq!(OpCode::RETURN.name(), "RETURN");
    assert_eq!(OpCode::INT_ADD.name(), "INT_ADD");
    assert_eq!(OpCode::INT_SUB.name(), "INT_SUB");
}

// ---------------------------------------------------------------------------
// PcodeOperation creation tests
// ---------------------------------------------------------------------------

#[test]
fn test_pcode_op_creation() {
    let op = PcodeOperation::new_unannotated(
        OpCode::INT_ADD,
        Some(Varnode::register("r", 0, 4)),
        vec![Varnode::register("r", 4, 4), Varnode::constant(1, 4)],
    );

    assert_eq!(op.opcode, OpCode::INT_ADD);
    assert!(op.output.is_some());
    assert_eq!(op.output.as_ref().unwrap().offset, 0);
    assert_eq!(op.inputs.len(), 2);
    assert_eq!(op.inputs[0].offset, 4);
    assert_eq!(op.inputs[1].offset, 1);
}

// ---------------------------------------------------------------------------
// P-code sequence building
// ---------------------------------------------------------------------------

#[test]
fn test_build_add_sequence() {
    let mut ops = Vec::new();

    ops.push(PcodeOperation::new_unannotated(
        OpCode::INT_ADD,
        Some(Varnode::register("r", 0, 8)),
        vec![
            Varnode::register("r", 0, 8),
            Varnode::constant(1, 8),
        ],
    ));

    assert_eq!(ops.len(), 1);
    assert_eq!(ops[0].inputs.len(), 2);
}

#[test]
fn test_build_load_store_sequence() {
    let mut ops = Vec::new();

    ops.push(PcodeOperation::new_unannotated(
        OpCode::INT_SUB,
        Some(Varnode::register("r", 0x20, 8)),
        vec![Varnode::register("r", 0x20, 8), Varnode::constant(8, 8)],
    ));

    ops.push(PcodeOperation::new_unannotated(
        OpCode::STORE,
        None,
        vec![Varnode::register("r", 0x20, 8), Varnode::register("r", 0, 8)],
    ));

    assert_eq!(ops.len(), 2);
    assert_eq!(ops[0].opcode, OpCode::INT_SUB);
    assert_eq!(ops[1].opcode, OpCode::STORE);
}

#[test]
fn test_build_call_sequence() {
    let mut ops = Vec::new();

    ops.push(PcodeOperation::new_unannotated(
        OpCode::CALL,
        None,
        vec![Varnode::constant(0x401000, 8)],
    ));

    ops.push(PcodeOperation::new_unannotated(
        OpCode::RETURN,
        None,
        vec![],
    ));

    assert_eq!(ops.len(), 2);
    assert!(ops[0].opcode.is_flow());
    assert!(ops[1].opcode.is_flow());
}

#[test]
fn test_build_conditional_branch() {
    let mut ops = Vec::new();

    ops.push(PcodeOperation::new_unannotated(
        OpCode::INT_EQUAL,
        Some(Varnode::unique(0, 1)),
        vec![Varnode::register("r", 0, 8), Varnode::register("r", 0x18, 8)],
    ));

    ops.push(PcodeOperation::new_unannotated(
        OpCode::CBRANCH,
        None,
        vec![
            Varnode::unique(0, 1),
            Varnode::constant(0x1050, 8),
        ],
    ));

    assert_eq!(ops.len(), 2);
    assert!(ops[0].opcode.is_comparison());
    assert!(ops[1].opcode.is_flow());
}

#[test]
fn test_build_variable_assignment() {
    let op = PcodeOperation::new_unannotated(
        OpCode::COPY,
        Some(Varnode::unique(1, 4)),
        vec![Varnode::constant(42, 4)],
    );

    assert_eq!(op.opcode, OpCode::COPY);
    assert_eq!(op.inputs[0].offset, 42);
    assert!(op.inputs[0].is_constant());
}

#[test]
fn test_data_movement_ops() {
    let data_ops = [OpCode::COPY, OpCode::LOAD, OpCode::STORE];
    for op in &data_ops {
        assert!(!op.is_flow());
        assert!(!op.is_comparison());
    }
}

#[test]
fn test_shift_ops() {
    let shift_ops = [OpCode::INT_LEFT, OpCode::INT_RIGHT, OpCode::INT_SRIGHT];
    for op in &shift_ops {
        assert!(!op.is_flow());
        assert!(!op.is_comparison());
    }
}

#[test]
fn test_extension_ops() {
    let ext_ops = [
        OpCode::SEGMENTOP,
        OpCode::CPOOLREF,
        OpCode::NEW,
        OpCode::INSERT,
        OpCode::EXTRACT,
        OpCode::POPCOUNT,
        OpCode::LZCOUNT,
    ];
    for op in &ext_ops {
        assert!(!op.is_flow());
        assert!(!op.is_comparison());
    }
}
