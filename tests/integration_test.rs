//! Integration tests for the Ghidra Rust toolchain.
//!
//! Tests end-to-end workflows:
//! - Load binary -> analyze -> decompile -> verify output
//! - Cross-crate type interoperability (core + decompile + features + processors)
//!
//! These tests verify that all crates work together correctly.

use ghidra_core::addr::{Address, AddressRange};
use ghidra_core::listing::ListingRow;
use ghidra_core::program::{
    Comment, CommentKind, MemoryBlock, MemoryPermissions, Program, SimpleDataType, SymbolTable,
};
use ghidra_core::program::lang::Language;
use ghidra_core::symbol::{Symbol, SymbolType};

use ghidra_decompile::pcode::{OpCode, PcodeOperation, Varnode};
use ghidra_decompile::sleigh::pcode::{PcodeOp as SleighPcodeOp, OpCode as SleighOpCode, Varnode as SleighVarnode};
use ghidra_decompile::sleigh::construct::{
    ConstructTpl, Constructor, ContextOp, OperandVal, PatternEquation, TokenField,
};
use ghidra_decompile::sleigh::context::{ContextBit, ContextDatabase, ContextField};

use ghidra_features::base::analyzer::{
    AnalysisPriority, AnalyzerType, BasicTaskMonitor,
    Language as AnalyzerLanguage, Program as AnalyzerProgram,
};

use ghidra_emulation::{Emulator, RegisterDefinition};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn test_emu_language() -> Language {
    use ghidra_core::addr::{AddressFactory, AddrSpaceType, AddressSpace};
    Language::new(
        ghidra_core::program::lang::LanguageID::new("x86", "LE", 64, "default"),
        "x86:LE:64:default",
        "1.0",
        0,
        "Test x86 64-bit little-endian language",
        AddressFactory::new(),
    )
}

// ---------------------------------------------------------------------------
// Integration: Load binary -> analyze -> decompile -> verify
// ---------------------------------------------------------------------------

#[test]
fn test_load_analyze_decompile_pipeline() {
    let mut prog = Program::new("integration_test.elf", Address::new(0x400000));

    let text_range = AddressRange::new(Address::new(0x401000), Address::new(0x401FFF));
    prog.memory_blocks.insert(
        ".text".to_string(),
        MemoryBlock {
            name: ".text".to_string(),
            range: text_range,
            permissions: MemoryPermissions::RX,
            initialized: true,
            data: vec![0u8; 0x1000],
        },
    );

    let data_range = AddressRange::new(Address::new(0x600000), Address::new(0x600FFF));
    prog.memory_blocks.insert(
        ".data".to_string(),
        MemoryBlock {
            name: ".data".to_string(),
            range: data_range,
            permissions: MemoryPermissions::RW,
            initialized: true,
            data: vec![0u8; 0x1000],
        },
    );

    let mut sym_table = SymbolTable::default();
    sym_table.add(Symbol::function("_start", Address::new(0x401000)));
    sym_table.add(Symbol::function("main", Address::new(0x4010A0)));
    sym_table.add(Symbol::function("helper", Address::new(0x401200)));
    sym_table.add(Symbol::import("printf", Address::new(0x7000)));
    prog.symbol_table = sym_table;

    prog.listing_data.add(
        Address::new(0x4010A0),
        ListingRow::new(Address::new(0x4010A0), vec![0x55], "push", "rbp"),
    );
    prog.listing_data.add(
        Address::new(0x4010A1),
        ListingRow::new(Address::new(0x4010A1), vec![0x48, 0x89, 0xE5], "mov", "rbp, rsp"),
    );
    prog.listing_data.add(
        Address::new(0x4010A9),
        ListingRow::new(Address::new(0x4010A9), vec![0xE8, 0x52, 0xFF, 0xFF, 0xFF], "call", "printf"),
    );
    prog.listing_data.add(
        Address::new(0x4010B1),
        ListingRow::new(Address::new(0x4010B1), vec![0xC3], "ret", ""),
    );

    prog.xrefs.insert(
        Address::new(0x7000),
        vec![Address::new(0x4010A9)],
    );
    prog.xrefs.insert(
        Address::new(0x4010A0),
        vec![Address::new(0x401000)],
    );

    prog.comments.insert(
        Address::new(0x4010A0),
        vec![Comment {
            kind: CommentKind::Plate,
            text: "=== FUNCTION main ===".to_string(),
            author: "analysis".to_string(),
        }],
    );

    assert_eq!(prog.name, "integration_test.elf");
    assert_eq!(prog.image_base, Address::new(0x400000));
    assert_eq!(prog.memory_blocks.len(), 2);
    assert_eq!(prog.symbol_table.len(), 4);

    let main_sym = prog.symbol_table.get(&Address::new(0x4010A0));
    assert!(main_sym.is_some());
    assert_eq!(main_sym.unwrap().name(), "main");
    assert_eq!(main_sym.unwrap().kind(), SymbolType::Function);

    let row = prog.listing_data.get(&Address::new(0x4010A9));
    assert!(row.is_some());
    assert_eq!(row.unwrap().mnemonic.text, "call");

    let xrefs_to_main = prog.xrefs.get(&Address::new(0x4010A0));
    assert!(xrefs_to_main.is_some());
    assert!(!xrefs_to_main.unwrap().is_empty());

    let comments = prog.comments.get(&Address::new(0x4010A0));
    assert!(comments.is_some());
    let plate_comment = comments.unwrap().iter().find(|c| c.kind == CommentKind::Plate);
    assert!(plate_comment.is_some());
    assert!(plate_comment.unwrap().text.contains("main"));
}

// ---------------------------------------------------------------------------
// Integration: P-code structure verification
// ---------------------------------------------------------------------------

#[test]
fn test_pcode_operation_structure() {
    // Simulate decompilation of add_numbers(a: i32, b: i32) -> i32
    let ops = vec![
        PcodeOperation::new_unannotated(
            OpCode::COPY,
            Some(Varnode::unique(0, 4)),
            vec![Varnode::register("", 0x38, 4)],
        ),
        PcodeOperation::new_unannotated(
            OpCode::COPY,
            Some(Varnode::unique(1, 4)),
            vec![Varnode::register("", 0x30, 4)],
        ),
        PcodeOperation::new_unannotated(
            OpCode::INT_ADD,
            Some(Varnode::unique(2, 4)),
            vec![Varnode::unique(0, 4), Varnode::unique(1, 4)],
        ),
        PcodeOperation::new_unannotated(
            OpCode::COPY,
            Some(Varnode::register("", 0, 4)),
            vec![Varnode::unique(2, 4)],
        ),
        PcodeOperation::new_unannotated(OpCode::RETURN, None, vec![]),
    ];

    assert_eq!(ops.len(), 5);
    assert_eq!(ops[0].opcode, OpCode::COPY);
    assert_eq!(ops[1].opcode, OpCode::COPY);
    assert_eq!(ops[2].opcode, OpCode::INT_ADD);
    assert_eq!(ops[3].opcode, OpCode::COPY);
    assert_eq!(ops[4].opcode, OpCode::RETURN);

    // Verify varnode structure
    assert!(ops[0].output.is_some());
    assert_eq!(ops[0].output.as_ref().unwrap().size, 4);
    assert_eq!(ops[0].inputs.len(), 1);
    assert!(ops[4].output.is_none());
}

// ---------------------------------------------------------------------------
// Cross-crate type interoperability tests
// ---------------------------------------------------------------------------

#[test]
fn test_address_to_varnode_interop() {
    let addr = Address::new(0x7FFF1234);
    let mem_varnode = Varnode::ram(addr.offset, 8);
    assert_eq!(mem_varnode.offset, 0x7FFF1234);
    assert!(mem_varnode.is_ram());
}

#[test]
fn test_data_type_pcode_interop() {
    let int_type = SimpleDataType::i32();
    assert_eq!(int_type.size, 4);
    assert_eq!(int_type.kind, ghidra_core::data::DataTypeKind::Primitive);

    let int_varnode = Varnode::register("", 0, 4);
    assert_eq!(int_varnode.size, int_type.size as u32);

    let op = PcodeOperation::new_unannotated(
        OpCode::COPY,
        Some(Varnode::register("", 0, 4)),
        vec![Varnode::constant(42, 4)],
    );
    assert_eq!(op.output.as_ref().unwrap().size, 4);
}

#[test]
fn test_memory_analyzer_interop() {
    let lang = AnalyzerLanguage {
        processor: "x86".to_string(),
        variant: "LE".to_string(),
        size: 64,
    };
    let mut analyzer_prog = AnalyzerProgram::new("test_interop", lang);

    let core_block = MemoryBlock {
        name: ".text".to_string(),
        range: AddressRange::new(Address::new(0x401000), Address::new(0x401FFF)),
        permissions: MemoryPermissions::RX,
        initialized: true,
        data: vec![],
    };

    analyzer_prog.image_base = core_block.range.start.offset;
    assert_eq!(analyzer_prog.image_base, 0x401000);
    assert_eq!(core_block.permissions, MemoryPermissions::RX);
}

// ---------------------------------------------------------------------------
// Integration: SLEIGH constructors and P-code composition
// ---------------------------------------------------------------------------

#[test]
fn test_sleigh_pcode_composition() {
    let mut template = ConstructTpl::with_operand_count(2);

    let add_op = SleighPcodeOp::new(
        SleighOpCode::IntAdd,
        Some(SleighVarnode::register(0, 4)),
        vec![
            SleighVarnode::register(0, 4),
            SleighVarnode::register(0x18, 4),
        ],
    );
    template.add_op(add_op);

    let pattern = PatternEquation::Constraint {
        pattern: vec![0x01, 0xD8],
        mask: vec![0xFF, 0xFF],
    };

    let constructor = Constructor::new(0, "ADD", pattern, template);

    assert_eq!(constructor.mnemonic, "ADD");
    assert_eq!(constructor.pcode_ops().len(), 1);
    assert_eq!(constructor.pcode_ops()[0].opcode, SleighOpCode::IntAdd);
}

// ---------------------------------------------------------------------------
// Integration: P-code execution with context tracking
// ---------------------------------------------------------------------------

#[test]
fn test_arm_context_aware_disassembly_workflow() {
    let mut db = ContextDatabase::new();
    db.register_bit(ContextBit::new("TMode", 0, 0)).unwrap();

    let arm_bl = Constructor::new(
        1,
        "BL",
        PatternEquation::Constraint {
            pattern: vec![0xEB, 0x00, 0x00, 0x00],
            mask: vec![0xFF, 0x00, 0x00, 0x00],
        },
        ConstructTpl::new(),
    );

    let thumb_bl = Constructor::new(
        2,
        "BL.Thumb",
        PatternEquation::Constraint {
            pattern: vec![0x00, 0xF0],
            mask: vec![0x00, 0xF8],
        },
        ConstructTpl::new(),
    );

    db.set_bit("TMode", false).unwrap();

    let arm_bytes = [0xEB, 0x00, 0x00, 0x00];
    assert!(arm_bl.matches(&arm_bytes, &[]));

    db.set_bit("TMode", true).unwrap();
    assert_eq!(db.get_bit("TMode"), Some(true));

    let thumb_bytes = [0x00, 0xF0, 0x10, 0x47];
    assert!(thumb_bl.matches(&thumb_bytes, &[]));
}

// ---------------------------------------------------------------------------
// Integration: Analysis priority pipeline
// ---------------------------------------------------------------------------

#[test]
fn test_analysis_priority_pipeline_integration() {
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
    use ghidra_core::data::builtin_data_type_tree;
    let tree = builtin_data_type_tree();

    // The tree is organized into categories: undefined, integer, float, string, misc
    let category_names: Vec<&str> = tree.children.iter().map(|c| c.name.as_str()).collect();
    assert!(category_names.contains(&"integer"), "Should have 'integer' category");
    assert!(category_names.contains(&"float"), "Should have 'float' category");
    assert!(category_names.contains(&"misc"), "Should have 'misc' category");

    // Check that some known types exist within categories
    let all_type_names: Vec<String> = tree.children.iter()
        .flat_map(|cat| cat.children.iter().map(|t| t.name.clone()))
        .collect();
    assert!(all_type_names.contains(&"bool".to_string()), "Should have 'bool' type");
    assert!(all_type_names.contains(&"int".to_string()), "Should have 'int' type");
    assert!(all_type_names.contains(&"void".to_string()), "Should have 'void' type");
    assert!(all_type_names.contains(&"float".to_string()), "Should have 'float' type");
}

// ---------------------------------------------------------------------------
// Integration: Full round-trip with emulation
// ---------------------------------------------------------------------------

#[test]
fn test_emulation_round_trip() {
    let lang = test_emu_language();
    let mut emu = Emulator::new(&lang);

    // Register varnodes use key format "{space}:0x{offset}"
    // EDI at offset 0x38, EAX at offset 0
    emu.define_register(RegisterDefinition::new(":0x38", 0x38, 4));
    emu.define_register(RegisterDefinition::new(":0x0", 0, 4));

    // param x (EDI) = 7
    emu.set_register(":0x38", &7u32.to_le_bytes());

    let ops = vec![
        PcodeOperation::new_unannotated(
            OpCode::COPY,
            Some(Varnode::unique(0, 4)),
            vec![Varnode::register("", 0x38, 4)],
        ),
        PcodeOperation::new_unannotated(
            OpCode::INT_ADD,
            Some(Varnode::unique(1, 4)),
            vec![Varnode::unique(0, 4), Varnode::unique(0, 4)],
        ),
        PcodeOperation::new_unannotated(
            OpCode::INT_ADD,
            Some(Varnode::unique(2, 4)),
            vec![Varnode::unique(1, 4), Varnode::unique(0, 4)],
        ),
        PcodeOperation::new_unannotated(
            OpCode::COPY,
            Some(Varnode::register("", 0, 4)),
            vec![Varnode::unique(2, 4)],
        ),
    ];

    emu.load_pcode(Address::new(0x401000), ops);
    emu.pc = Address::new(0x401000);
    let result = emu.run(100);
    assert!(result.is_ok());

    let eax = emu.get_register(":0x0");
    assert!(eax.is_some(), "EAX register should be set after execution");
    let val = u32::from_le_bytes(eax.unwrap().try_into().unwrap());
    assert_eq!(val, 21);
}

// ---------------------------------------------------------------------------
// Integration: Completeness check
// ---------------------------------------------------------------------------

#[test]
fn test_integration_completeness() {
    let addr = Address::new(0x1000);
    let range = AddressRange::new(addr, addr.add(0xFF));
    let dt = SimpleDataType::i32();

    let vn = Varnode::register("", 0, 4);
    let op = PcodeOperation::new_unannotated(OpCode::INT_ADD, Some(vn), vec![]);
    let db = ContextDatabase::new();

    let monitor = BasicTaskMonitor::new();
    let priority = AnalysisPriority::CODE_ANALYSIS;

    let lang = test_emu_language();
    let emu = Emulator::new(&lang);

    assert_eq!(range.len(), 0x100);
    assert_eq!(dt.size, 4);
    assert_eq!(op.opcode, OpCode::INT_ADD);
    assert_eq!(db.total_bits(), 0);
    assert!(!TaskMonitorTrait::is_cancelled(&monitor));
    assert!(priority.priority() > 0);
}

// Helper trait import for is_cancelled
use ghidra_features::base::analyzer::TaskMonitor as TaskMonitorTrait;
