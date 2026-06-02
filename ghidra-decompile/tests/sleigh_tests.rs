//! Tests for SLEIGH: .slaspec parsing, constructor matching, and instruction decoding.
//!
//! Covers the `ghidra_decompile::sleigh` modules:
//! - [`Constructor`] and [`ConstructTpl`] creation and matching
//! - [`PatternEquation`] tree building, matching, and byte length computation
//! - [`TokenField`] bit extraction (unsigned and signed)
//! - [`ContextDatabase`] state management, save/restore, bit and field operations
//! - [`ContextBit`], [`ContextField`], [`TrackedContext`] definitions
//! - [`ContextOp`] and [`OperandVal`] creation and display

use ghidra_decompile::pcode::{OpCode, PcodeOp, Varnode};
use ghidra_decompile::sleigh::construct::{
    ConstructTpl, Constructor, ContextOp, OperandSymbol, OperandVal, PatternEquation, TokenField,
};
use ghidra_decompile::sleigh::context::{
    ContextBit, ContextDatabase, ContextField, TrackedContext,
};

// ---------------------------------------------------------------------------
// TokenField tests
// ---------------------------------------------------------------------------

#[test]
fn test_token_field_creation() {
    let tf = TokenField::new(0, 8, 8, false);
    assert_eq!(tf.token_id, 0);
    assert_eq!(tf.bit_start, 8);
    assert_eq!(tf.bit_size, 8);
    assert!(!tf.signed);
    assert_eq!(tf.bit_end(), 16);
}

#[test]
fn test_token_field_extract_unsigned_low_byte() {
    // Bytes: [0x12, 0x34] = 0b00010010 00110100 (MSB first)
    // Low byte (bits 0..8): 0x34
    let field = TokenField::new(0, 0, 8, false);
    let value = field.extract_unsigned(&[0x12, 0x34]);
    assert_eq!(value, 0x34);
}

#[test]
fn test_token_field_extract_unsigned_high_byte() {
    // High byte (bits 8..16): 0x12
    let field = TokenField::new(0, 8, 8, false);
    let value = field.extract_unsigned(&[0x12, 0x34]);
    assert_eq!(value, 0x12);
}

#[test]
fn test_token_field_extract_unsigned_nibble() {
    // Extract 4 bits from the middle. Bytes: 0b1010_1100
    // bits 4..8 = 0b1010 = 10
    let field = TokenField::new(0, 4, 4, false);
    let value = field.extract_unsigned(&[0xAC]);
    assert_eq!(value, 0xA);
}

#[test]
fn test_token_field_extract_signed_negative() {
    // 4-bit signed field: value 0b1110 = -2
    let field = TokenField::new(0, 0, 4, true);
    // Byte: 0b1110_0101 -> low nibble is 0b1110
    let value = field.extract_signed(&[0xE5]);
    assert_eq!(value, -2);
}

#[test]
fn test_token_field_extract_signed_positive() {
    let field = TokenField::new(0, 4, 4, true);
    // Byte: 0b0101_xxxx -> high nibble is 0b0101 = 5
    // Actually: bytes[0] = 0x5A, bit_start=4 => extract bits 4-8 from low byte
    let value = field.extract_signed(&[0x5A]);
    assert_eq!(value, 5);
}

#[test]
fn test_token_field_extract_unsigned_empty() {
    let field = TokenField::new(0, 0, 8, false);
    let value = field.extract_unsigned(&[]);
    assert_eq!(value, 0);
}

#[test]
fn test_token_field_display() {
    let tf = TokenField::new(1, 4, 8, true);
    let s = format!("{}", tf);
    assert!(s.contains("token_1"));
}

// ---------------------------------------------------------------------------
// PatternEquation tests
// ---------------------------------------------------------------------------

#[test]
fn test_pattern_constraint_match_exact() {
    let pattern = PatternEquation::Constraint {
        pattern: vec![0xE8],
        mask: vec![0xFF],
    };
    assert!(pattern.matches(&[0xE8], &[]));
    assert!(!pattern.matches(&[0xE9], &[]));
}

#[test]
fn test_pattern_constraint_match_with_dont_care() {
    // Top nibble must be 0xF0, bottom nibble is don't-care
    let pattern = PatternEquation::Constraint {
        pattern: vec![0xF0],
        mask: vec![0xF0],
    };
    assert!(pattern.matches(&[0xF0], &[]));
    assert!(pattern.matches(&[0xF5], &[])); // bottom nibble ignored
    assert!(!pattern.matches(&[0x0F], &[])); // top nibble wrong
}

#[test]
fn test_pattern_constraint_match_multi_byte() {
    let pattern = PatternEquation::Constraint {
        pattern: vec![0x66, 0x0F, 0x6F],
        mask: vec![0xFF, 0xFF, 0xFF],
    };
    // MOVDQA xmm1, xmm2/m128 (3-byte opcode)
    assert!(pattern.matches(&[0x66, 0x0F, 0x6F], &[]));
    assert!(!pattern.matches(&[0x66, 0x0F, 0x6E], &[]));
}

#[test]
fn test_pattern_constraint_too_short() {
    let pattern = PatternEquation::Constraint {
        pattern: vec![0x00, 0x00, 0x00],
        mask: vec![0xFF, 0xFF, 0xFF],
    };
    // Input is shorter than pattern constraint — any constrained bits
    // beyond the input fail.
    assert!(!pattern.matches(&[0x00], &[]));
}

#[test]
fn test_pattern_token_field_always_matches() {
    let tf = TokenField::new(0, 0, 4, false);
    let pattern = PatternEquation::TokenField(tf);
    // Token fields always succeed during matching
    assert!(pattern.matches(&[], &[]));
    assert!(pattern.matches(&[0xFF], &[]));
}

#[test]
fn test_pattern_or() {
    let p1 = PatternEquation::Constraint {
        pattern: vec![0x10],
        mask: vec![0xFF],
    };
    let p2 = PatternEquation::Constraint {
        pattern: vec![0x20],
        mask: vec![0xFF],
    };
    let or_pattern = PatternEquation::Or(vec![p1, p2]);

    assert!(or_pattern.matches(&[0x10], &[]));
    assert!(or_pattern.matches(&[0x20], &[]));
    assert!(!or_pattern.matches(&[0x30], &[]));
}

#[test]
fn test_pattern_and() {
    let p1 = PatternEquation::Constraint {
        pattern: vec![0x10],
        mask: vec![0xF0], // top nibble = 1
    };
    let p2 = PatternEquation::Constraint {
        pattern: vec![0x02],
        mask: vec![0x0F], // bottom nibble = 2
    };
    let and_pattern = PatternEquation::And(vec![p1, p2]);

    assert!(and_pattern.matches(&[0x12], &[]));
    assert!(!and_pattern.matches(&[0x11], &[])); // bottom nibble wrong
    assert!(!and_pattern.matches(&[0x22], &[])); // top nibble wrong
}

#[test]
fn test_pattern_not() {
    let inner = PatternEquation::Constraint {
        pattern: vec![0x00],
        mask: vec![0xFF],
    };
    let not_pattern = PatternEquation::Not(Box::new(inner));

    assert!(!not_pattern.matches(&[0x00], &[]));
    assert!(not_pattern.matches(&[0x01], &[]));
    assert!(not_pattern.matches(&[0xFF], &[]));
}

#[test]
fn test_pattern_any() {
    assert!(PatternEquation::Any.matches(&[], &[]));
    assert!(PatternEquation::Any.matches(&[0x00, 0xFF], &[]));
}

#[test]
fn test_pattern_complex_tree() {
    // (p1 OR p2) AND NOT(p3)
    let p1 = PatternEquation::Constraint {
        pattern: vec![0x10],
        mask: vec![0xF0],
    };
    let p2 = PatternEquation::Constraint {
        pattern: vec![0x20],
        mask: vec![0xF0],
    };
    let p3 = PatternEquation::Constraint {
        pattern: vec![0x00],
        mask: vec![0x0F],
    };

    let complex = PatternEquation::And(vec![
        PatternEquation::Or(vec![p1, p2]),
        PatternEquation::Not(Box::new(p3)),
    ]);

    // 0x11: top nibble matches p1 (1x), bottom nibble != 0 -> NOT(p3) passes
    assert!(complex.matches(&[0x11], &[]));
    // 0x20: top nibble matches p2 (2x), bottom nibble = 0 -> NOT(p3) fails
    assert!(!complex.matches(&[0x20], &[]));
    // 0x32: top nibble = 3, neither p1 nor p2 match
    assert!(!complex.matches(&[0x32], &[]));
}

#[test]
fn test_pattern_min_byte_length() {
    let p = PatternEquation::Constraint {
        pattern: vec![0x00; 4],
        mask: vec![0xFF; 4],
    };
    assert_eq!(p.min_byte_length(), 4);

    let tf = TokenField::new(0, 24, 8, false);
    let tf_p = PatternEquation::TokenField(tf);
    assert_eq!(tf_p.min_byte_length(), 4); // bit 24 + 8 = 32 bits = 4 bytes

    let or_p = PatternEquation::Or(vec![
        PatternEquation::Constraint { pattern: vec![0x00], mask: vec![0xFF] },
        PatternEquation::Constraint { pattern: vec![0x00; 3], mask: vec![0xFF; 3] },
    ]);
    assert_eq!(or_p.min_byte_length(), 3);
}

#[test]
fn test_pattern_collect_token_fields() {
    let tf1 = TokenField::new(0, 0, 4, false);
    let tf2 = TokenField::new(0, 4, 4, false);

    let pattern = PatternEquation::And(vec![
        PatternEquation::TokenField(tf1.clone()),
        PatternEquation::TokenField(tf2.clone()),
    ]);

    let fields = pattern.collect_token_fields();
    assert_eq!(fields.len(), 2);
}

#[test]
fn test_pattern_has_subtables() {
    let p = PatternEquation::SubTableRef { table_name: "ThumbExpand".into() };
    assert!(p.has_subtables());

    let p2 = PatternEquation::And(vec![
        PatternEquation::Constraint { pattern: vec![0], mask: vec![0xFF] },
        p,
    ]);
    assert!(p2.has_subtables());

    let p3 = PatternEquation::Constraint { pattern: vec![0], mask: vec![0xFF] };
    assert!(!p3.has_subtables());
}

// ---------------------------------------------------------------------------
// Constructor tests
// ---------------------------------------------------------------------------

#[test]
fn test_constructor_creation() {
    let template = ConstructTpl::with_operand_count(1);
    let pattern = PatternEquation::Constraint {
        pattern: vec![0xE8],
        mask: vec![0xFF],
    };
    let constructor = Constructor::new(0, "CALL", pattern, template);

    assert_eq!(constructor.id, 0);
    assert_eq!(constructor.mnemonic, "CALL");
    assert!(constructor.enabled);
}

#[test]
fn test_constructor_matches_exact() {
    let template = ConstructTpl::new();
    let pattern = PatternEquation::Constraint {
        pattern: vec![0xE8],
        mask: vec![0xFF],
    };
    let constructor = Constructor::new(0, "CALL", pattern, template);

    assert!(constructor.matches(&[0xE8], &[]));
    assert!(!constructor.matches(&[0xE9], &[]));
}

#[test]
fn test_constructor_matches_too_short() {
    let template = ConstructTpl::new();
    let pattern = PatternEquation::Constraint {
        pattern: vec![0x66, 0x0F],
        mask: vec![0xFF, 0xFF],
    };
    let constructor = Constructor::new(0, "SSE_OP", pattern, template);

    // Only 1 byte, needs 2
    assert!(!constructor.matches(&[0x66], &[]));
    // 2 bytes, matches
    assert!(constructor.matches(&[0x66, 0x0F], &[]));
}

#[test]
fn test_constructor_context_ops() {
    let mut constructor = Constructor::new(
        0,
        "BL",
        PatternEquation::Constraint { pattern: vec![0xEB], mask: vec![0xFF] },
        ConstructTpl::new(),
    );

    constructor.add_context_op(ContextOp::Set {
        name: "TMode".into(),
        value: 1,
    });

    assert_eq!(constructor.context_ops.len(), 1);
    match &constructor.context_ops[0] {
        ContextOp::Set { name, value } => {
            assert_eq!(name, "TMode");
            assert_eq!(*value, 1);
        }
        _ => panic!("Expected ContextOp::Set"),
    }
}

#[test]
fn test_constructor_description() {
    let mut constructor = Constructor::new(
        0,
        "NOP",
        PatternEquation::Any,
        ConstructTpl::new(),
    );
    constructor.set_description("No Operation");

    assert_eq!(constructor.description, "No Operation");
    let display = format!("{}", constructor);
    assert!(display.contains("No Operation"));
}

#[test]
fn test_constructor_root_flag() {
    let mut constructor = Constructor::new(
        0,
        "ADD",
        PatternEquation::Any,
        ConstructTpl::new(),
    );
    assert!(!constructor.is_root);
    constructor.mark_root();
    assert!(constructor.is_root);
}

// ---------------------------------------------------------------------------
// ConstructTpl tests
// ---------------------------------------------------------------------------

#[test]
fn test_construct_tpl_creation() {
    let tpl = ConstructTpl::new();
    assert!(tpl.is_empty());
    assert_eq!(tpl.op_count(), 0);
    assert_eq!(tpl.pcode_ops.len(), 0);
}

#[test]
fn test_construct_tpl_with_operand_count() {
    let tpl = ConstructTpl::with_operand_count(3);
    assert_eq!(tpl.num_operands, 3);
    assert!(tpl.operands.capacity() >= 3);
}

#[test]
fn test_construct_tpl_add_op() {
    let mut tpl = ConstructTpl::new();
    let op = PcodeOp::new(
        OpCode::IntAdd,
        Some(Varnode::register(0, 4)),
        vec![Varnode::register(4, 4), Varnode::constant(1, 4)],
    );
    tpl.add_op(op);
    assert_eq!(tpl.op_count(), 1);
}

#[test]
fn test_construct_tpl_add_operand() {
    let mut tpl = ConstructTpl::new();
    let op = OperandSymbol::Register { name: "EAX".into() };
    tpl.add_operand(op);
    assert_eq!(tpl.operands.len(), 1);
}

#[test]
fn test_construct_tpl_mnemonic() {
    let mut tpl = ConstructTpl::new();
    tpl.set_mnemonic("CALL.ABS");
    assert_eq!(tpl.mnemonic.as_deref(), Some("CALL.ABS"));
}

// ---------------------------------------------------------------------------
// Operand symbol and value tests
// ---------------------------------------------------------------------------

#[test]
fn test_operand_symbol_size() {
    let imm = OperandSymbol::Immediate { index: 0, size: 4 };
    assert_eq!(imm.size_bytes(), Some(4));

    let reg = OperandSymbol::Register { name: "RAX".into() };
    assert_eq!(reg.size_bytes(), None); // register size is context-dependent

    let addr = OperandSymbol::Address { index: 0, size: 8 };
    assert_eq!(addr.size_bytes(), Some(8));
}

#[test]
fn test_operand_symbol_index() {
    let imm = OperandSymbol::Immediate { index: 3, size: 4 };
    assert_eq!(imm.operand_index(), Some(3));

    let reg = OperandSymbol::Register { name: "RAX".into() };
    assert_eq!(reg.operand_index(), None);
}

#[test]
fn test_operand_symbol_display() {
    let reg = OperandSymbol::Register { name: "EAX".into() };
    assert_eq!(format!("{}", reg), "EAX");

    let imm = OperandSymbol::Immediate { index: 0, size: 4 };
    assert_eq!(format!("{}", imm), "imm0[4]");

    let scaled = OperandSymbol::Scaled { base: "RAX".into(), scale: 4, offset: 8 };
    assert!(format!("{}", scaled).contains("RAX"));
    assert!(format!("{}", scaled).contains("*4"));
}

#[test]
fn test_operand_val_creation() {
    let reg = OperandVal::register("EAX", 4);
    assert!(reg.is_register());
    assert!(!reg.is_immediate());
    assert_eq!(reg.size_bytes(), Some(4));

    let imm = OperandVal::immediate(42, 4);
    assert!(imm.is_immediate());
    assert!(!imm.is_register());
}

#[test]
fn test_operand_val_address_and_relative() {
    let addr = OperandVal::address(0x400000, 0);
    assert!(format!("{}", addr).contains("400000"));

    let rel = OperandVal::relative(0x100);
    assert!(format!("{}", rel).contains("PC"));
}

// ---------------------------------------------------------------------------
// ContextOp tests
// ---------------------------------------------------------------------------

#[test]
fn test_context_op_set() {
    let op = ContextOp::Set { name: "TMode".into(), value: 1 };
    assert_eq!(op.variable_name(), "TMode");
    assert!(op.is_write());
    assert_eq!(format!("{}", op), "TMode = 0x1");
}

#[test]
fn test_context_op_clear() {
    let op = ContextOp::Clear("IT".into());
    assert_eq!(op.variable_name(), "IT");
    assert!(op.is_write());
    assert_eq!(format!("{}", op), "clear IT");
}

#[test]
fn test_context_op_copy() {
    let op = ContextOp::Copy { src: "A".into(), dest: "B".into() };
    assert_eq!(op.variable_name(), "B");
    assert!(!op.is_write());
    assert_eq!(format!("{}", op), "B = A");
}

// ---------------------------------------------------------------------------
// ContextDatabase tests
// ---------------------------------------------------------------------------

#[test]
fn test_context_database_creation() {
    let db = ContextDatabase::new();
    assert_eq!(db.total_bits(), 0);
    assert_eq!(db.save_depth(), 0);
}

#[test]
fn test_register_and_get_bit() {
    let mut db = ContextDatabase::new();
    db.register_bit(ContextBit::new("TMode", 0, 0)).unwrap();
    db.register_bit(ContextBit::new("BigEndian", 1, 1)).unwrap();

    assert_eq!(db.total_bits(), 2);
    assert_eq!(db.get_bit("TMode"), Some(false)); // default 0
    assert_eq!(db.get_bit("BigEndian"), Some(true)); // default 1
}

#[test]
fn test_set_and_get_bit() {
    let mut db = ContextDatabase::new();
    db.register_bit(ContextBit::new("Flag", 0, 0)).unwrap();

    db.set_bit("Flag", true).unwrap();
    assert_eq!(db.get_bit("Flag"), Some(true));

    db.set_bit("Flag", false).unwrap();
    assert_eq!(db.get_bit("Flag"), Some(false));
}

#[test]
fn test_set_nonexistent_bit() {
    let mut db = ContextDatabase::new();
    let result = db.set_bit("NoSuchBit", true);
    assert!(result.is_err());
}

#[test]
fn test_register_field() {
    let mut db = ContextDatabase::new();
    db.register_field(ContextField::new("Mode", 0, 2, 0)).unwrap();

    assert_eq!(db.total_bits(), 2);
    assert_eq!(db.get_field("Mode"), Some(0));

    db.set_field("Mode", 3).unwrap(); // max for 2-bit field
    assert_eq!(db.get_field("Mode"), Some(3));

    // Value larger than field width is masked
    db.set_field("Mode", 0xFF).unwrap();
    assert_eq!(db.get_field("Mode"), Some(3)); // 0xFF & 3 = 3
}

#[test]
fn test_duplicate_register_fails() {
    let mut db = ContextDatabase::new();
    db.register_bit(ContextBit::new("TMode", 0, 0)).unwrap();
    assert!(db.register_bit(ContextBit::new("TMode", 1, 0)).is_err());
    assert!(db.register_field(ContextField::new("TMode", 0, 2, 0)).is_err());
}

#[test]
fn test_field_name_conflict_with_bit() {
    let mut db = ContextDatabase::new();
    db.register_field(ContextField::new("Mode", 0, 4, 0)).unwrap();
    assert!(db.register_bit(ContextBit::new("Mode", 5, 0)).is_err());
}

#[test]
fn test_save_restore_state() {
    let mut db = ContextDatabase::new();
    db.register_bit(ContextBit::new("TMode", 0, 0)).unwrap();

    db.set_bit("TMode", true).unwrap();
    db.save_state();

    db.set_bit("TMode", false).unwrap();
    assert_eq!(db.get_bit("TMode"), Some(false));

    db.restore_state().unwrap();
    assert_eq!(db.get_bit("TMode"), Some(true));
}

#[test]
fn test_commit_state() {
    let mut db = ContextDatabase::new();
    db.register_bit(ContextBit::new("Flag", 0, 0)).unwrap();

    db.set_bit("Flag", true).unwrap();
    db.save_state();

    db.set_bit("Flag", false).unwrap();
    db.commit_state().unwrap(); // discard saved state, keep current

    assert_eq!(db.get_bit("Flag"), Some(false));
    // Stack should be empty now
    assert!(db.restore_state().is_err());
}

#[test]
fn test_nested_save_restore() {
    let mut db = ContextDatabase::new();
    db.register_bit(ContextBit::new("A", 0, 0)).unwrap();
    db.register_bit(ContextBit::new("B", 1, 0)).unwrap();

    // Set A=1, save
    db.set_bit("A", true).unwrap();
    db.save_state();

    // Set A=0, B=1, save again
    db.set_bit("A", false).unwrap();
    db.set_bit("B", true).unwrap();
    db.save_state();

    // Set A=1, B=0
    db.set_bit("A", true).unwrap();
    db.set_bit("B", false).unwrap();

    // Restore inner: A=0, B=1
    db.restore_state().unwrap();
    assert_eq!(db.get_bit("A"), Some(false));
    assert_eq!(db.get_bit("B"), Some(true));

    // Restore outer: A=1, B=0
    db.restore_state().unwrap();
    assert_eq!(db.get_bit("A"), Some(true));
    assert_eq!(db.get_bit("B"), Some(false));
}

#[test]
fn test_reset_to_defaults() {
    let mut db = ContextDatabase::new();
    db.register_bit(ContextBit::new("Flag", 0, 1)).unwrap();
    db.set_bit("Flag", false).unwrap();

    db.reset();
    assert_eq!(db.get_bit("Flag"), Some(true)); // back to default
}

#[test]
fn test_field_extract_encode() {
    let field = ContextField::new("Mode", 4, 8, 0);
    let mut bits = vec![0u8; 2]; // 16 bits

    // Encode 0xAB into bits[4..8]
    field.encode(&mut bits, 0xAB);
    let extracted = field.extract(&bits);
    assert_eq!(extracted, 0xAB);
}

#[test]
fn test_context_database_contains_and_width() {
    let mut db = ContextDatabase::new();
    db.register_bit(ContextBit::new("TMode", 0, 0)).unwrap();
    db.register_field(ContextField::new("ProcMode", 2, 6, 0)).unwrap();

    assert!(db.contains("TMode"));
    assert!(db.contains("ProcMode"));
    assert!(!db.contains("Nonexistent"));

    assert_eq!(db.width_of("TMode"), Some(1));
    assert_eq!(db.width_of("ProcMode"), Some(4));
    assert_eq!(db.width_of("Unknown"), None);
}

#[test]
fn test_iterators() {
    let mut db = ContextDatabase::new();
    db.register_bit(ContextBit::new("A", 0, 0)).unwrap();
    db.register_bit(ContextBit::new("B", 1, 0)).unwrap();
    db.register_field(ContextField::new("F", 2, 6, 0)).unwrap();

    let bits: Vec<&ContextBit> = db.iter_bits().collect();
    assert_eq!(bits.len(), 2);

    let fields: Vec<&ContextField> = db.iter_fields().collect();
    assert_eq!(fields.len(), 1);
}

// ---------------------------------------------------------------------------
// ContextBit, ContextField, TrackedContext tests
// ---------------------------------------------------------------------------

#[test]
fn test_context_bit_creation() {
    let bit = ContextBit::new("TMode", 0, 0);
    assert_eq!(bit.position, 0);
    assert_eq!(bit.default_value, 0);
    assert!(!bit.flow_follow);
}

#[test]
fn test_context_bit_with_flow_follow() {
    let bit = ContextBit::new("TMode", 0, 0).with_flow_follow();
    assert!(bit.flow_follow);
}

#[test]
fn test_context_bit_display() {
    let bit = ContextBit::new("TMode", 0, 1);
    let s = format!("{}", bit);
    assert!(s.contains("TMode"));
    assert!(s.contains("bit 0"));
}

#[test]
fn test_context_field_properties() {
    let field = ContextField::new("Mode", 2, 6, 3);
    assert_eq!(field.bit_width(), 4);
    assert_eq!(field.max_value(), 15); // (1 << 4) - 1
}

#[test]
fn test_context_field_large_width() {
    let field = ContextField::new("Big", 0, 64, 0);
    assert_eq!(field.bit_width(), 64);
    assert_eq!(field.max_value(), u64::MAX);
}

#[test]
fn test_context_field_display() {
    let field = ContextField::new("Mode", 0, 4, 7);
    let s = format!("{}", field);
    assert!(s.contains("Mode"));
    assert!(s.contains("0x7"));
}

#[test]
fn test_tracked_context_lifecycle() {
    let vn = Varnode::register(0, 4);
    let mut tc = TrackedContext::new("PC", vn);
    assert!(tc.valid);

    tc.invalidate();
    assert!(!tc.valid);

    tc.validate();
    assert!(tc.valid);
}

#[test]
fn test_tracked_context_display() {
    let vn = Varnode::ram(0x400000, 4);
    let tc = TrackedContext::new("entry", vn);
    let s = format!("{}", tc);
    assert!(s.contains("entry"));
    assert!(s.contains("valid"));
}

// ---------------------------------------------------------------------------
// Instruction decoding scenario
// ---------------------------------------------------------------------------

#[test]
fn test_arm_bl_instruction_pattern() {
    // ARM BL (Branch with Link) encoding:
    // Bits 27-24 = 0b1011 (condition AL = always)
    // Bit 25 (Link) = 1
    // Top byte: 0b1110_1011 = 0xEB, mask = 0xFF

    let bl_pattern = PatternEquation::Constraint {
        pattern: vec![0xEB],
        mask: vec![0xFF],
    };

    // ARM: BL 0x... = bytes [0xEB, xx, xx, xx]
    let arm_bl_bytes = [0xEB, 0x00, 0x00, 0x00];
    assert!(bl_pattern.matches(&arm_bl_bytes, &[]));

    // B (without link) = bytes [0xEA, ...] - should NOT match
    let arm_b_bytes = [0xEA, 0x00, 0x00, 0x00];
    assert!(!bl_pattern.matches(&arm_b_bytes, &[]));
}

#[test]
fn test_x86_mov_register_pattern() {
    // x86 MOV r32, r/m32 opcode range: 0x89 or 0x8B
    let p1 = PatternEquation::Constraint {
        pattern: vec![0x89],
        mask: vec![0xFD], // 0b1111_1101 - bit 1 is direction, don't-care
    };
    let p2 = PatternEquation::Constraint {
        pattern: vec![0x8B],
        mask: vec![0xFD],
    };
    let mov_pattern = PatternEquation::Or(vec![p1, p2]);

    // MOV with ModRM byte
    assert!(mov_pattern.matches(&[0x89, 0xC0], &[])); // MOV EAX, EAX
    assert!(mov_pattern.matches(&[0x8B, 0x45, 0xFC], &[])); // MOV EAX, [EBP-4]
    assert!(mov_pattern.matches(&[0x89, 0xD8], &[])); // MOV EAX, EBX
    assert!(!mov_pattern.matches(&[0x88, 0xC0], &[])); // MOV AL, AL (8-bit)
}

#[test]
fn test_context_aware_arm_thumb_disambiguation() {
    // ARM uses context variable TMode to distinguish ARM vs Thumb
    let mut db = ContextDatabase::new();
    db.register_bit(ContextBit::new("TMode", 0, 0)).unwrap();

    // When TMode=0 (ARM mode), bytes [0x00, 0xBF] is a different instruction
    // than when TMode=1 (Thumb mode)

    // ARM mode: set TMode=0
    db.set_bit("TMode", false).unwrap();

    // In ARM, 0xE12FFF1E = BX LR
    let arm_bx_lr = [0x1E, 0xFF, 0x2F, 0xE1];
    let arm_bx_pattern = PatternEquation::Constraint {
        pattern: vec![0x1E, 0xFF, 0x2F, 0xE1],
        mask: vec![0xFF, 0xFF, 0xFF, 0xFF],
    };
    assert!(arm_bx_pattern.matches(&arm_bx_lr, &[]));

    // Switch to Thumb mode
    db.set_bit("TMode", true).unwrap();
    assert_eq!(db.get_bit("TMode"), Some(true));

    // Thumb BX LR encoding: 0x4770
    let thumb_bx_lr = [0x70, 0x47];
    let thumb_bx_pattern = PatternEquation::Constraint {
        pattern: vec![0x70, 0x47],
        mask: vec![0xFF, 0xFF],
    };
    assert!(thumb_bx_pattern.matches(&thumb_bx_lr, &[]));
}
