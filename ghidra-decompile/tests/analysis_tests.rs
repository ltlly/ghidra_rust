//! Tests for decompiler analysis: BasicBlock, CfgEdge, P-code operations,
//! control flow patterns, and varnode space classification.
//!
//! Ports key analysis test patterns from Ghidra's Java decompiler test suite.

use ghidra_decompile::pcode::{OpCode, PcodeOperation, Varnode};
use ghidra_decompile::analysis::cfg::{BasicBlock, CfgEdge};
use ghidra_core::addr::Address;

// ============================================================================
// BasicBlock construction and properties
// ============================================================================

#[test]
fn test_basic_block_empty() {
    let block = BasicBlock::new(0);
    assert!(block.is_empty());
    assert_eq!(block.len(), 0);
    assert!(!block.has_terminator());
    assert!(block.terminator().is_none());
}

#[test]
fn test_basic_block_with_ops() {
    let ops = vec![
        PcodeOperation::new_unannotated(
            OpCode::COPY,
            Some(Varnode::register("RAX", 0, 8)),
            vec![Varnode::constant(42, 8)],
        ),
        PcodeOperation::new_unannotated(
            OpCode::INT_ADD,
            Some(Varnode::register("RAX", 0, 8)),
            vec![Varnode::register("RAX", 0, 8), Varnode::constant(1, 8)],
        ),
    ];

    let block = BasicBlock::with_ops(1, ops, Address::new(0x1000), Address::new(0x100F));
    assert_eq!(block.len(), 2);
    assert!(!block.is_empty());
    assert!(!block.has_terminator()); // no control-flow op
}

#[test]
fn test_basic_block_with_terminator() {
    let ops = vec![
        PcodeOperation::new_unannotated(
            OpCode::INT_EQUAL,
            Some(Varnode::unique(0, 1)),
            vec![Varnode::register("RAX", 0, 8), Varnode::constant(0, 8)],
        ),
        PcodeOperation::new_unannotated(
            OpCode::CBRANCH,
            None,
            vec![Varnode::ram(0x2000, 8), Varnode::unique(0, 1)],
        ),
    ];

    let block = BasicBlock::with_ops(2, ops, Address::new(0x2000), Address::new(0x200F));
    assert!(block.has_terminator());
    assert_eq!(block.terminator().unwrap().opcode, OpCode::CBRANCH);
}

#[test]
fn test_basic_block_direct_branch_target() {
    let ops = vec![
        PcodeOperation::new_unannotated(OpCode::BRANCH, None, vec![Varnode::constant(0x3000, 8)]),
    ];

    let block = BasicBlock::with_ops(3, ops, Address::new(0x2000), Address::new(0x200F));
    let target = block.direct_branch_target();
    assert!(target.is_some());
    assert_eq!(target.unwrap(), Address::new(0x3000));
}

#[test]
fn test_basic_block_varnodes() {
    let ops = vec![
        PcodeOperation::new_unannotated(
            OpCode::COPY,
            Some(Varnode::register("RAX", 0, 8)),
            vec![Varnode::constant(10, 8)],
        ),
        PcodeOperation::new_unannotated(
            OpCode::INT_ADD,
            Some(Varnode::register("RBX", 8, 8)),
            vec![Varnode::register("RAX", 0, 8), Varnode::register("RCX", 16, 8)],
        ),
    ];

    let block = BasicBlock::with_ops(4, ops, Address::new(0x4000), Address::new(0x400F));

    let defined = block.defined_varnodes();
    assert_eq!(defined.len(), 2); // RAX and RBX

    let used = block.used_varnodes();
    assert_eq!(used.len(), 3); // 10, RAX, RCX
}

#[test]
fn test_basic_block_terminator_returns_none_for_non_flow() {
    let ops = vec![
        PcodeOperation::new_unannotated(
            OpCode::INT_ADD,
            Some(Varnode::register("RAX", 0, 8)),
            vec![Varnode::register("RAX", 0, 8), Varnode::constant(1, 8)],
        ),
    ];
    let block = BasicBlock::with_ops(5, ops, Address::new(0x5000), Address::new(0x500F));
    assert!(block.terminator().is_none());
}

// ============================================================================
// CfgEdge types
// ============================================================================

#[test]
fn test_cfg_edge_fallthrough() {
    let edge = CfgEdge::FallThrough;
    assert!(edge.is_fallthrough());
    assert!(!edge.is_conditional());
    assert!(!edge.is_unconditional());
}

#[test]
fn test_cfg_edge_branch_taken() {
    let edge = CfgEdge::Branch(true);
    assert!(!edge.is_fallthrough());
    assert!(!edge.is_conditional());
    assert!(edge.is_unconditional());
}

#[test]
fn test_cfg_edge_branch_not_taken() {
    let edge = CfgEdge::Branch(false);
    assert!(!edge.is_fallthrough());
    assert!(edge.is_conditional());
    assert!(!edge.is_unconditional());
}

#[test]
fn test_cfg_edge_call() {
    let edge = CfgEdge::Call;
    assert!(!edge.is_fallthrough());
    assert!(!edge.is_conditional());
    assert!(!edge.is_unconditional());
}

#[test]
fn test_cfg_edge_return() {
    let edge = CfgEdge::Return;
    assert!(!edge.is_fallthrough());
}

#[test]
fn test_cfg_edge_equality() {
    assert_eq!(CfgEdge::FallThrough, CfgEdge::FallThrough);
    assert_eq!(CfgEdge::Branch(true), CfgEdge::Branch(true));
    assert_ne!(CfgEdge::Branch(true), CfgEdge::Branch(false));
    assert_ne!(CfgEdge::Call, CfgEdge::Return);
}

// ============================================================================
// PcodeOperation basic operations
// ============================================================================

#[test]
fn test_copy_op() {
    let op = PcodeOperation::new_unannotated(
        OpCode::COPY,
        Some(Varnode::register("EAX", 0, 4)),
        vec![Varnode::constant(42, 4)],
    );
    assert_eq!(op.opcode, OpCode::COPY);
    assert!(op.output.is_some());
    assert_eq!(op.inputs.len(), 1);
}

#[test]
fn test_int_add_op() {
    let op = PcodeOperation::new_unannotated(
        OpCode::INT_ADD,
        Some(Varnode::register("RAX", 0, 8)),
        vec![Varnode::register("RAX", 0, 8), Varnode::register("RBX", 8, 8)],
    );
    assert_eq!(op.opcode, OpCode::INT_ADD);
    assert!(op.opcode.is_arithmetic());
    assert!(!op.opcode.is_flow());
}

#[test]
fn test_branch_op() {
    let op = PcodeOperation::new_unannotated(
        OpCode::BRANCH,
        None,
        vec![Varnode::ram(0x401000, 8)],
    );
    assert!(op.output.is_none());
    assert!(op.opcode.is_branch());
    assert!(op.opcode.is_flow());
}

#[test]
fn test_cbranch_op() {
    let op = PcodeOperation::new_unannotated(
        OpCode::CBRANCH,
        None,
        vec![Varnode::ram(0x402000, 8), Varnode::unique(0, 1)],
    );
    assert!(op.opcode.is_branch());
    assert!(op.opcode.is_flow());
}

#[test]
fn test_call_op() {
    let op = PcodeOperation::new_unannotated(
        OpCode::CALL,
        None,
        vec![Varnode::ram(0x402000, 8)],
    );
    assert!(op.opcode.is_call());
    assert!(op.opcode.is_flow());
}

#[test]
fn test_return_op() {
    let op = PcodeOperation::new_unannotated(OpCode::RETURN, None, vec![]);
    assert!(op.opcode.is_return());
    assert!(op.opcode.is_flow());
}

#[test]
fn test_store_load_pair() {
    let store = PcodeOperation::new_unannotated(
        OpCode::STORE,
        None,
        vec![
            Varnode::constant(0, 4),
            Varnode::ram(0x600000, 8),
            Varnode::register("RAX", 0, 8),
        ],
    );
    assert_eq!(store.opcode, OpCode::STORE);

    let load = PcodeOperation::new_unannotated(
        OpCode::LOAD,
        Some(Varnode::register("RBX", 8, 8)),
        vec![Varnode::constant(0, 4), Varnode::ram(0x600000, 8)],
    );
    assert_eq!(load.opcode, OpCode::LOAD);
}

// ============================================================================
// Varnode space types in analysis context
// ============================================================================

#[test]
fn test_varnode_register_space() {
    let vn = Varnode::register("RAX", 0, 8);
    assert!(vn.is_register());
    assert!(!vn.is_constant());
    assert!(!vn.is_ram());
}

#[test]
fn test_varnode_constant_space() {
    let vn = Varnode::constant(0xDEAD, 4);
    assert!(vn.is_constant());
    assert_eq!(vn.offset, 0xDEAD);
}

#[test]
fn test_varnode_ram_space() {
    let vn = Varnode::ram(0x401000, 1);
    assert!(vn.is_ram());
    assert!(!vn.is_register());
}

#[test]
fn test_varnode_unique_space() {
    let vn = Varnode::unique(42, 4);
    assert!(vn.is_unique());
    assert!(!vn.is_ram());
    assert!(!vn.is_register());
    assert!(!vn.is_constant());
}

// ============================================================================
// Multi-operation sequences (control flow patterns)
// ============================================================================

#[test]
fn test_function_call_sequence() {
    let ops = vec![
        PcodeOperation::new_unannotated(OpCode::COPY, Some(Varnode::register("EDI", 0x38, 4)), vec![Varnode::constant(0x600000, 4)]),
        PcodeOperation::new_unannotated(OpCode::COPY, Some(Varnode::register("ESI", 0x30, 4)), vec![Varnode::constant(42, 4)]),
        PcodeOperation::new_unannotated(OpCode::CALL, None, vec![Varnode::ram(0x7000, 8)]),
    ];
    assert_eq!(ops.len(), 3);
    assert_eq!(ops[2].opcode, OpCode::CALL);
}

#[test]
fn test_while_loop_pcode() {
    let ops = vec![
        PcodeOperation::new_unannotated(OpCode::COPY, Some(Varnode::unique(0, 4)), vec![Varnode::constant(0, 4)]),
        PcodeOperation::new_unannotated(OpCode::INT_LESS, Some(Varnode::unique(1, 1)), vec![Varnode::unique(0, 4), Varnode::constant(10, 4)]),
        PcodeOperation::new_unannotated(OpCode::CBRANCH, None, vec![Varnode::ram(0x1100, 8), Varnode::unique(1, 1)]),
        PcodeOperation::new_unannotated(OpCode::INT_ADD, Some(Varnode::unique(0, 4)), vec![Varnode::unique(0, 4), Varnode::constant(1, 4)]),
        PcodeOperation::new_unannotated(OpCode::BRANCH, None, vec![Varnode::ram(0x1008, 8)]),
    ];

    assert_eq!(ops.len(), 5);
    assert!(ops[1].opcode.is_comparison());
    assert!(ops[2].opcode.is_branch());
    assert!(ops[3].opcode.is_arithmetic());
    assert!(ops[4].opcode.is_branch());
}

#[test]
fn test_switch_case_pcode() {
    let ops = vec![
        PcodeOperation::new_unannotated(OpCode::COPY, Some(Varnode::unique(0, 4)), vec![Varnode::register("EAX", 0, 4)]),
        PcodeOperation::new_unannotated(OpCode::INT_EQUAL, Some(Varnode::unique(1, 1)), vec![Varnode::unique(0, 4), Varnode::constant(0, 4)]),
        PcodeOperation::new_unannotated(OpCode::CBRANCH, None, vec![Varnode::ram(0x2000, 8), Varnode::unique(1, 1)]),
        PcodeOperation::new_unannotated(OpCode::INT_EQUAL, Some(Varnode::unique(2, 1)), vec![Varnode::unique(0, 4), Varnode::constant(1, 4)]),
        PcodeOperation::new_unannotated(OpCode::CBRANCH, None, vec![Varnode::ram(0x3000, 8), Varnode::unique(2, 1)]),
        PcodeOperation::new_unannotated(OpCode::INT_EQUAL, Some(Varnode::unique(3, 1)), vec![Varnode::unique(0, 4), Varnode::constant(2, 4)]),
        PcodeOperation::new_unannotated(OpCode::CBRANCH, None, vec![Varnode::ram(0x4000, 8), Varnode::unique(3, 1)]),
        PcodeOperation::new_unannotated(OpCode::BRANCH, None, vec![Varnode::ram(0x5000, 8)]),
    ];

    let flow_ops: Vec<_> = ops.iter().filter(|op| op.opcode.is_flow()).collect();
    assert_eq!(flow_ops.len(), 4); // 3 CB branches + 1 default branch
}

#[test]
fn test_if_else_pcode() {
    let ops = vec![
        PcodeOperation::new_unannotated(OpCode::INT_EQUAL, Some(Varnode::unique(0, 1)), vec![Varnode::register("EAX", 0, 4), Varnode::constant(0, 4)]),
        PcodeOperation::new_unannotated(OpCode::CBRANCH, None, vec![Varnode::ram(0x2000, 8), Varnode::unique(0, 1)]),
        PcodeOperation::new_unannotated(OpCode::COPY, Some(Varnode::register("ECX", 4, 4)), vec![Varnode::constant(1, 4)]),
        PcodeOperation::new_unannotated(OpCode::BRANCH, None, vec![Varnode::ram(0x3000, 8)]),
        PcodeOperation::new_unannotated(OpCode::COPY, Some(Varnode::register("ECX", 4, 4)), vec![Varnode::constant(0, 4)]),
    ];

    let comparisons: Vec<_> = ops.iter().filter(|op| op.opcode.is_comparison()).collect();
    assert_eq!(comparisons.len(), 1);

    let branches: Vec<_> = ops.iter().filter(|op| op.opcode.is_branch()).collect();
    assert_eq!(branches.len(), 2); // CBRANCH + BRANCH
}

// ============================================================================
// OpCode classification comprehensive tests
// ============================================================================

#[test]
fn test_all_flow_opcodes() {
    let flow_ops = [
        OpCode::BRANCH, OpCode::CBRANCH, OpCode::BRANCHIND,
        OpCode::CALL, OpCode::CALLIND,
        OpCode::RETURN,
    ];
    for op in &flow_ops {
        assert!(op.is_flow(), "{:?} should be flow", op);
    }
}

#[test]
fn test_non_flow_opcodes() {
    let non_flow = [
        OpCode::COPY, OpCode::LOAD, OpCode::STORE,
        OpCode::INT_ADD, OpCode::INT_SUB,
        OpCode::INT_EQUAL, OpCode::INT_LESS,
        OpCode::BOOL_AND, OpCode::BOOL_OR,
    ];
    for op in &non_flow {
        assert!(!op.is_flow(), "{:?} should not be flow", op);
    }
}

#[test]
fn test_all_arithmetic_opcodes() {
    let arith = [
        OpCode::INT_ADD, OpCode::INT_SUB, OpCode::INT_MUL,
        OpCode::INT_DIV, OpCode::INT_SDIV,
    ];
    for op in &arith {
        assert!(op.is_arithmetic(), "{:?} should be arithmetic", op);
    }
}

#[test]
fn test_all_comparison_opcodes() {
    let cmp = [
        OpCode::INT_EQUAL, OpCode::INT_NOTEQUAL,
        OpCode::INT_LESS, OpCode::INT_SLESS,
        OpCode::INT_LESSEQUAL, OpCode::INT_SLESSEQUAL,
    ];
    for op in &cmp {
        assert!(op.is_comparison(), "{:?} should be comparison", op);
    }
}

#[test]
fn test_all_logical_opcodes() {
    let log = [OpCode::BOOL_AND, OpCode::BOOL_OR, OpCode::BOOL_NEGATE];
    for op in &log {
        assert!(op.is_logical(), "{:?} should be logical", op);
    }
}

#[test]
fn test_all_shift_opcodes() {
    let shift = [OpCode::INT_LEFT, OpCode::INT_RIGHT, OpCode::INT_SRIGHT];
    for op in &shift {
        assert!(op.is_shift(), "{:?} should be shift", op);
    }
}

#[test]
fn test_all_float_opcodes() {
    let float = [
        OpCode::FLOAT_ADD, OpCode::FLOAT_SUB,
        OpCode::FLOAT_MUL, OpCode::FLOAT_DIV,
    ];
    for op in &float {
        assert!(op.is_float(), "{:?} should be float", op);
    }
}
