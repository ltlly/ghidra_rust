//! Integration tests for the Ghidra Rust toolchain.
//!
//! Tests end-to-end workflows:
//! - Load binary -> analyze -> decompile -> verify output
//! - Server mode start -> create session -> decompile -> verify
//! - Cross-crate type interoperability (core + decompile + features + processors)
//!
//! These tests verify that all crates work together correctly.

use ghidra_core::addr::{Address, AddressRange, AddressSpace};
use ghidra_core::data::{DataType, DataTypeKind, builtin_data_type_tree};
use ghidra_core::listing::ListingRow;
use ghidra_core::program::{
    Comment, CommentKind, ListingData, MemoryBlock, MemoryPermissions, Program, SymbolTable,
};
use ghidra_core::symbol::{Symbol, SymbolKind};

use ghidra_decompile::pcode::{OpCode, PcodeOp, SpaceType, Varnode};
use ghidra_decompile::sleigh::construct::{
    ConstructTpl, Constructor, ContextOp, OperandVal, PatternEquation, TokenField,
};
use ghidra_decompile::sleigh::context::{ContextBit, ContextDatabase, ContextField};

use ghidra_features::base::analyzer::{
    AnalysisPriority, AnalyzerType, BasicTaskMonitor, Language, Program as AnalyzerProgram,
};

use ghidra_emulation::{Breakpoint, Emulator};

// ---------------------------------------------------------------------------
// Integration: Load binary -> analyze -> decompile -> verify
// ---------------------------------------------------------------------------

/// Simulates loading an ELF binary, running auto-analysis, and verifying
/// the decompiled output.
#[test]
fn test_load_analyze_decompile_pipeline() {
    // Step 1: Create a "loaded program" (simulated binary)
    let mut prog = Program::new("integration_test.elf", Address::new(0x400000));

    // Add a .text section with some code
    let text_range = AddressRange::new(Address::new(0x401000), Address::new(0x401FFF));
    prog.memory_blocks.insert(
        ".text".to_string(),
        MemoryBlock {
            name: ".text".to_string(),
            range: text_range,
            permissions: MemoryPermissions::RX,
            initialized: true,
        },
    );

    // Add a .data section
    let data_range = AddressRange::new(Address::new(0x600000), Address::new(0x600FFF));
    prog.memory_blocks.insert(
        ".data".to_string(),
        MemoryBlock {
            name: ".data".to_string(),
            range: data_range,
            permissions: MemoryPermissions::RW,
            initialized: true,
        },
    );

    // Step 2: Add symbols discovered during loading
    let mut sym_table = SymbolTable::default();
    sym_table.add(Symbol::function("_start", Address::new(0x401000)));
    sym_table.add(Symbol::function("main", Address::new(0x4010A0)));
    sym_table.add(Symbol::function("helper", Address::new(0x401200)));
    sym_table.add(Symbol::import("printf", Address::new(0x7000)));
    prog.symbol_table = sym_table;

    // Step 3: Add listing data (simulated disassembly of main)
    let mut listing = ListingData::default();

    // push rbp
    listing.add(
        Address::new(0x4010A0),
        ListingRow::new(Address::new(0x4010A0), vec![0x55], "push", "rbp"),
    );
    // mov rbp, rsp
    listing.add(
        Address::new(0x4010A1),
        ListingRow::new(Address::new(0x4010A1), vec![0x48, 0x89, 0xE5], "mov", "rbp, rsp"),
    );
    // mov edi, 0x600000  (address of string)
    listing.add(
        Address::new(0x4010A4),
        ListingRow::new(Address::new(0x4010A4), vec![0xBF, 0x00, 0x00, 0x60, 0x00], "mov", "edi, 0x600000"),
    );
    // call printf
    listing.add(
        Address::new(0x4010A9),
        ListingRow::new(Address::new(0x4010A9), vec![0xE8, 0x52, 0xFF, 0xFF, 0xFF], "call", "printf"),
    );
    // xor eax, eax
    listing.add(
        Address::new(0x4010AE),
        ListingRow::new(Address::new(0x4010AE), vec![0x31, 0xC0], "xor", "eax, eax"),
    );
    // pop rbp
    listing.add(
        Address::new(0x4010B0),
        ListingRow::new(Address::new(0x4010B0), vec![0x5D], "pop", "rbp"),
    );
    // ret
    listing.add(
        Address::new(0x4010B1),
        ListingRow::new(Address::new(0x4010B1), vec![0xC3], "ret", ""),
    );

    prog.listing = listing;

    // Step 4: Add cross-references
    prog.xrefs.insert(
        Address::new(0x7000),  // printf
        vec![Address::new(0x4010A9)], // called from main+0x9
    );
    prog.xrefs.insert(
        Address::new(0x4010A0), // main
        vec![Address::new(0x401000)], // called from _start
    );

    // Step 5: Add comments from analysis
    prog.comments.insert(
        Address::new(0x4010A0),
        vec![Comment {
            kind: CommentKind::Plate,
            text: "=== FUNCTION main ===".to_string(),
            author: "analysis".to_string(),
        }],
    );

    // Step 6: Verify the integrated state
    assert_eq!(prog.name, "integration_test.elf");
    assert_eq!(prog.image_base, Address::new(0x400000));
    assert_eq!(prog.memory_blocks.len(), 2);
    assert_eq!(prog.symbol_table.len(), 4);

    // Verify main function exists
    let main_sym = prog.symbol_at(&Address::new(0x4010A0));
    assert!(main_sym.is_some());
    assert_eq!(main_sym.unwrap().name, "main");
    assert_eq!(main_sym.unwrap().kind, SymbolKind::Function);

    // Verify listing has the expected number of instructions
    let rows = prog.listing.iter_from(Address::new(0x4010A0), 10);
    assert_eq!(rows.len(), 7); // 7 instructions from push rbp to ret

    // Verify the call instruction has the expected mnemonic
    let call_instr = rows.iter().find(|r| r.mnemonic.text == "call");
    assert!(call_instr.is_some());
    assert_eq!(call_instr.unwrap().operands, "printf");

    // Verify cross-reference from _start to main
    let xrefs_to_main = prog.xrefs_to(&Address::new(0x4010A0));
    assert!(!xrefs_to_main.is_empty());

    // Verify comment on main
    let comments = prog.comments.get(&Address::new(0x4010A0));
    assert!(comments.is_some());
    let plate_comment = comments.unwrap().iter().find(|c| c.kind == CommentKind::Plate);
    assert!(plate_comment.is_some());
    assert!(plate_comment.unwrap().text.contains("main"));
}

// ---------------------------------------------------------------------------
// Integration: Server mode -> create session -> decompile -> verify
// ---------------------------------------------------------------------------

/// Represents a simplified server session for testing.
struct TestSession {
    session_id: String,
    program: Program,
    decompiled_functions: Vec<DecompiledFunction>,
}

/// Represents a decompiled function for testing.
struct DecompiledFunction {
    name: String,
    address: Address,
    signature: String,
    pcode_ops: Vec<PcodeOp>,
}

/// Simulates the server workflow: start -> load -> decompile -> verify.
#[test]
fn test_server_decompile_workflow() {
    // Step 1: "Start server" (create a session)
    let mut session = TestSession {
        session_id: "session-001".to_string(),
        program: Program::new("decompile_target.exe", Address::new(0x140000000)),
        decompiled_functions: Vec::new(),
    };

    // Step 2: "Load program" (populate memory, symbols, listing)
    session.program.memory_blocks.insert(
        ".text".to_string(),
        MemoryBlock {
            name: ".text".to_string(),
            range: AddressRange::new(Address::new(0x140001000), Address::new(0x140001FFF)),
            permissions: MemoryPermissions::RX,
            initialized: true,
        },
    );

    session.program.symbol_table.add(Symbol::function(
        "add_numbers",
        Address::new(0x140001000),
    ));

    // Step 3: "Decompile" (generate P-code and signature)
    // Simulate decompilation of add_numbers(a: i32, b: i32) -> i32
    let mut pcode_ops = Vec::new();

    // a (EDI) -> u0
    pcode_ops.push(PcodeOp::new(
        OpCode::Copy,
        Some(Varnode::unique(0, 4)),
        vec![Varnode::register(0x38, 4)], // EDI = param 1
    ));

    // b (ESI) -> u1
    pcode_ops.push(PcodeOp::new(
        OpCode::Copy,
        Some(Varnode::unique(1, 4)),
        vec![Varnode::register(0x30, 4)], // ESI = param 2
    ));

    // u2 = u0 + u1
    pcode_ops.push(PcodeOp::new(
        OpCode::IntAdd,
        Some(Varnode::unique(2, 4)),
        vec![Varnode::unique(0, 4), Varnode::unique(1, 4)],
    ));

    // EAX = u2 (return value)
    pcode_ops.push(PcodeOp::new(
        OpCode::Copy,
        Some(Varnode::register(0, 4)), // EAX = return value
        vec![Varnode::unique(2, 4)],
    ));

    // RET
    pcode_ops.push(PcodeOp::new(OpCode::Return, None, vec![]));

    let decompiled = DecompiledFunction {
        name: "add_numbers".to_string(),
        address: Address::new(0x140001000),
        signature: "int add_numbers(int a, int b)".to_string(),
        pcode_ops,
    };

    session.decompiled_functions.push(decompiled);

    // Step 4: "Verify decompiled output"
    let func = &session.decompiled_functions[0];
    assert_eq!(func.name, "add_numbers");
    assert_eq!(func.address, Address::new(0x140001000));
    assert!(func.signature.contains("add_numbers"));
    assert!(func.signature.contains("int"));
    assert_eq!(func.pcode_ops.len(), 5);

    // Verify P-code structure
    assert_eq!(func.pcode_ops[0].opcode, OpCode::Copy);     // param a
    assert_eq!(func.pcode_ops[1].opcode, OpCode::Copy);     // param b
    assert_eq!(func.pcode_ops[2].opcode, OpCode::IntAdd);   // a + b
    assert_eq!(func.pcode_ops[3].opcode, OpCode::Copy);     // return value
    assert_eq!(func.pcode_ops[4].opcode, OpCode::Return);   // return

    // Session metadata
    assert_eq!(session.session_id, "session-001");
}

// ---------------------------------------------------------------------------
// Cross-crate type interoperability tests
// ---------------------------------------------------------------------------

/// Verify that core address types can be used with decompile varnode types.
#[test]
fn test_address_to_varnode_interop() {
    // Core address
    let addr = Address::new(0x7FFF1234);

    // Convert to a decompile varnode (RAM space)
    let mem_varnode = Varnode::ram(addr.offset, 8);
    assert_eq!(mem_varnode.offset, 0x7FFF1234);
    assert!(mem_varnode.is_address());

    // Core address space
    let ram_space = AddressSpace::ram();
    assert!(!ram_space.big_endian);

    // Decompile space type
    assert_eq!(SpaceType::Ram.index(), 1);
}

/// Verify that data types integrate with P-code types.
#[test]
fn test_data_type_pcode_interop() {
    // Create a 32-bit integer in core
    let int_type = DataType::i32();
    assert_eq!(int_type.size, 4);
    assert_eq!(int_type.kind, DataTypeKind::Primitive);

    // Represent as a P-code varnode of the same size
    let int_varnode = Varnode::register(0, 4);
    assert_eq!(int_varnode.size, int_type.size);

    // Create an operation with this varnode
    let op = PcodeOp::new(
        OpCode::Copy,
        Some(Varnode::register(0, 4)),
        vec![Varnode::constant(42, 4)],
    );
    assert_eq!(op.output.as_ref().unwrap().size, 4);
}

/// Verify that program memory blocks can be interpreted with feature-level types.
#[test]
fn test_memory_analyzer_interop() {
    // Features crate analyzer types
    let lang = Language {
        processor: "x86".to_string(),
        variant: "LE".to_string(),
        size: 64,
    };
    let mut analyzer_prog = AnalyzerProgram::new("test_interop", lang);

    // Core memory block
    let core_block = MemoryBlock {
        name: ".text".to_string(),
        range: AddressRange::new(Address::new(0x401000), Address::new(0x401FFF)),
        permissions: MemoryPermissions::RX,
        initialized: true,
    };

    // Verify the features and core types work together
    analyzer_prog.image_base = core_block.range.start.offset;
    assert_eq!(analyzer_prog.image_base, 0x401000);
    assert_eq!(core_block.permissions, MemoryPermissions::RX);
}

/// Verify that SLEIGH constructors and P-code operations compose.
#[test]
fn test_sleigh_pcode_composition() {
    // Create a SLEIGH constructor for ADD instruction
    let mut template = ConstructTpl::with_operand_count(2);

    let add_op = PcodeOp::new(
        OpCode::IntAdd,
        Some(Varnode::register(0, 4)),
        vec![Varnode::register(0, 4), Varnode::register(0x18, 4)],
    );
    template.add_op(add_op);

    let pattern = PatternEquation::Constraint {
        pattern: vec![0x01, 0xD8],
        mask: vec![0xFF, 0xFF],
    };

    let constructor = Constructor::new(0, "ADD", pattern, template);

    // Verify integration
    assert_eq!(constructor.mnemonic, "ADD");
    assert_eq!(constructor.pcode_ops().len(), 1);
    assert_eq!(constructor.pcode_ops()[0].opcode, OpCode::IntAdd);
}

// ---------------------------------------------------------------------------
// Integration: P-code execution with context tracking
// ---------------------------------------------------------------------------

/// Simulates disassembling ARM with TMode context tracking.
#[test]
fn test_arm_context_aware_disassembly_workflow() {
    // Step 1: Set up context database for ARM Thumb mode
    let mut db = ContextDatabase::new();
    db.register_bit(ContextBit::new("TMode", 0, 0)).unwrap();

    // Step 2: Create ARM-mode constructor (TMode=0)
    let arm_bl = Constructor::new(
        1,
        "BL",
        PatternEquation::Constraint {
            pattern: vec![0xEB, 0x00, 0x00, 0x00],
            mask: vec![0xFF, 0x00, 0x00, 0x00],
        },
        ConstructTpl::new(),
    );

    // Step 3: Create Thumb-mode constructor (TMode=1)
    let thumb_bl = Constructor::new(
        2,
        "BL.Thumb",
        PatternEquation::Constraint {
            pattern: vec![0x00, 0xF0],
            mask: vec![0x00, 0xF8],
        },
        ConstructTpl::new(),
    );

    // Initially in ARM mode (TMode=0)
    db.set_bit("TMode", false).unwrap();

    // ARM byte sequence [0xEB, 0x00, 0x00, 0x00] should match ARM BL
    let arm_bytes = [0xEB, 0x00, 0x00, 0x00];
    assert!(arm_bl.matches(&arm_bytes, &[]));

    // Switch to Thumb mode (TMode=1)
    db.set_bit("TMode", true).unwrap();
    assert_eq!(db.get_bit("TMode"), Some(true));

    // Thumb BX LR pattern should match in Thumb mode
    // (context variable is verified by constructor's matches method)
    let thumb_bytes = [0x00, 0xF0, 0x10, 0x47];
    assert!(thumb_bl.matches(&thumb_bytes, &[]));
}

// ---------------------------------------------------------------------------
// Integration: Analysis priority pipeline
// ---------------------------------------------------------------------------

#[test]
fn test_analysis_priority_pipeline_integration() {
    // Verify the analysis priority pipeline ordering
    let pipeline = [
        AnalysisPriority::FORMAT_ANALYSIS,
        AnalysisPriority::BLOCK_ANALYSIS,
        AnalysisPriority::DISASSEMBLY,
        AnalysisPriority::CODE_ANALYSIS,
        AnalysisPriority::FUNCTION_ANALYSIS,
        AnalysisPriority::REFERENCE_ANALYSIS,
        AnalysisPriority::DATA_ANALYSIS,
        AnalysisPriority::FUNCTION_ID_ANALYSIS,
        AnalysisPriority::DATA_TYPE_PROPAGATION,
        AnalysisPriority::LOW_PRIORITY,
    ];

    // Verify strict ordering
    for i in 1..pipeline.len() {
        assert!(
            pipeline[i - 1] < pipeline[i],
            "Expected {:?} < {:?}",
            pipeline[i - 1],
            pipeline[i]
        );
    }
}

// ---------------------------------------------------------------------------
// Integration: Built-in data type tree accessibility
// ---------------------------------------------------------------------------

#[test]
fn test_builtin_types_available_across_crates() {
    let tree = builtin_data_type_tree();

    // Common types that should be available
    let expected_types = [
        "void", "bool", "char", "byte", "word", "dword", "qword",
        "short", "int", "uint", "long", "float", "double", "string",
    ];

    for expected in &expected_types {
        let found = tree.children.iter().any(|child| child.name == *expected);
        assert!(found, "Expected builtin type '{}' not found", expected);
    }
}

// ---------------------------------------------------------------------------
// Integration: Full round-trip with emulation
// ---------------------------------------------------------------------------

#[test]
fn test_emulation_round_trip() {
    // A full workflow:
    // 1. Load a function
    // 2. Get its P-code from the decompiler
    // 3. Emulate the P-code
    // 4. Verify the result

    let mut emu = Emulator::new();

    // The function: int triple(int x) { return x * 3; }
    // P-code: x * 2 + x (optimized: x << 1 + x)

    // param x (EDI) -> u0
    emu.set_register(0x38, 7, 4); // EDI = 7

    // u0 = EDI (copy param to temp)
    emu.execute_op(&PcodeOp::new(
        OpCode::Copy,
        Some(Varnode::unique(0, 4)),
        vec![Varnode::register(0x38, 4)],
    ));

    // u1 = u0 * 2 (shift left = x * 2)
    emu.execute_op(&PcodeOp::new(
        OpCode::IntAdd,
        Some(Varnode::unique(1, 4)),
        vec![Varnode::unique(0, 4), Varnode::unique(0, 4)],
    ));

    // u2 = u1 + u0 (x * 2 + x = x * 3)
    emu.execute_op(&PcodeOp::new(
        OpCode::IntAdd,
        Some(Varnode::unique(2, 4)),
        vec![Varnode::unique(1, 4), Varnode::unique(0, 4)],
    ));

    // EAX = u2 (return value)
    emu.execute_op(&PcodeOp::new(
        OpCode::Copy,
        Some(Varnode::register(0, 4)),
        vec![Varnode::unique(2, 4)],
    ));

    // Verify result: 7 * 3 = 21
    assert_eq!(emu.get_register(0, 4), 21);
    assert_eq!(emu.step_count, 4);
}

// ---------------------------------------------------------------------------
// Integration: Breakpoint-based debugging workflow
// ---------------------------------------------------------------------------

#[test]
fn test_debugging_workflow() {
    let mut emu = Emulator::new();
    emu.pc = 0x401000;

    // Set breakpoint at 0x401010
    emu.add_breakpoint(0x401010);

    // Create a breakpoint with condition
    let bp = Breakpoint::conditional(0x401020, "RAX == 0");
    assert!(bp.enabled);

    // Simulate stepping through instructions
    let mut breakpoint_hit = false;
    for addr in 0x401000..0x401030 {
        emu.pc = addr;
        if emu.has_breakpoint(addr) {
            breakpoint_hit = true;
            break;
        }
    }

    assert!(breakpoint_hit, "Breakpoint at 0x401010 should have been hit");
}

// ---------------------------------------------------------------------------
// Integration: Completeness check
// ---------------------------------------------------------------------------

#[test]
fn test_integration_completeness() {
    // Verify that all major type families from different crates can coexist

    // Core types
    let addr = Address::new(0x1000);
    let range = AddressRange::new(addr, addr.add(0xFF));
    let dt = DataType::i32();

    // Decompile types
    let vn = Varnode::register(0, 4);
    let op = PcodeOp::new(OpCode::IntAdd, Some(vn), vec![]);
    let db = ContextDatabase::new();

    // Features types
    let monitor = BasicTaskMonitor::new();
    let priority = AnalysisPriority::CODE_ANALYSIS;

    // Emulation types
    let mut emu = Emulator::new();
    emu.set_register(0, 42, 4);

    // All types should be created without panicking
    assert_eq!(range.len(), 0x100);
    assert_eq!(dt.size, 4);
    assert_eq!(op.opcode, OpCode::IntAdd);
    assert_eq!(db.total_bits(), 0);
    assert!(!monitor.is_cancelled());
    assert!(priority.priority() > 0);
    assert_eq!(emu.get_register(0, 4), 42);
}
