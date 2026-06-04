//! Tests for symbolic P-code emulation (SymZ3 framework).
//!
//! Covers SymValueZ3 creation/arithmetic/comparison/boolean ops,
//! SymZ3RegisterMap, SymZ3MemoryMap, SymZ3Preconditions, and serialization.

use ghidra_emulation::symz3::{
    SymValueZ3, SymZ3RegisterMap, SymZ3MemoryMap, RegisterDescriptor,
    MemoryRegion, SymZ3Precondition, SymZ3Preconditions, SymZ3State,
    SpaceKind,
};

// ============================================================================
// SymValueZ3 creation and properties
// ============================================================================

#[test]
fn test_from_bitvec() {
    let v = SymValueZ3::from_bitvec("bv42");
    assert!(v.has_bitvec_expr());
    assert!(!v.has_bool_expr());
    assert_eq!(v.bitvec_expr_string.as_deref(), Some("bv42"));
}

#[test]
fn test_from_bool() {
    let v = SymValueZ3::from_bool("true");
    assert!(!v.has_bitvec_expr());
    assert!(v.has_bool_expr());
    assert_eq!(v.bool_expr_string.as_deref(), Some("true"));
}

#[test]
fn test_from_bitvec_and_bool() {
    let v = SymValueZ3::from_bitvec_and_bool("bv1", "(> x 0)");
    assert!(v.has_bitvec_expr());
    assert!(v.has_bool_expr());
}

#[test]
fn test_display() {
    let v = SymValueZ3::from_bitvec("x + y");
    let s = format!("{}", v);
    assert!(s.contains("x + y"));
}

// ============================================================================
// Serialization round-trip
// ============================================================================

#[test]
fn test_serialize_bitvec_only() {
    let v = SymValueZ3::from_bitvec("bv42");
    let serialized = v.serialize();
    assert!(serialized.contains(":::::"));
    let parsed = SymValueZ3::parse(&serialized).unwrap();
    assert_eq!(v, parsed);
}

#[test]
fn test_serialize_bool_only() {
    let v = SymValueZ3::from_bool("true");
    let serialized = v.serialize();
    let parsed = SymValueZ3::parse(&serialized).unwrap();
    assert_eq!(parsed.bool_expr_string, Some("true".to_string()));
}

#[test]
fn test_serialize_bool_priority() {
    // When both present, bool takes priority in serialization
    let v = SymValueZ3::from_bitvec_and_bool("bv1", "true");
    let serialized = v.serialize();
    let parsed = SymValueZ3::parse(&serialized).unwrap();
    assert!(!parsed.has_bitvec_expr()); // bitvec is NOT serialized
    assert_eq!(parsed.bool_expr_string, Some("true".to_string()));
}

#[test]
fn test_parse_invalid() {
    assert!(SymValueZ3::parse("no_delimiter").is_none());
}

// ============================================================================
// SymValueZ3 arithmetic operations
// ============================================================================

#[test]
fn test_int_add() {
    let a = SymValueZ3::from_bitvec("a");
    let b = SymValueZ3::from_bitvec("b");
    let result = a.int_add(&b);
    let expr = result.bitvec_expr_string.unwrap();
    assert!(expr.contains("bvadd"));
    assert!(expr.contains("a"));
    assert!(expr.contains("b"));
}

#[test]
fn test_int_sub() {
    let a = SymValueZ3::from_bitvec("a");
    let b = SymValueZ3::from_bitvec("b");
    let result = a.int_sub(&b);
    assert!(result.bitvec_expr_string.unwrap().contains("bvsub"));
}

#[test]
fn test_int_mult() {
    let a = SymValueZ3::from_bitvec("a");
    let b = SymValueZ3::from_bitvec("b");
    let result = a.int_mult(&b);
    assert!(result.bitvec_expr_string.unwrap().contains("bvmul"));
}

#[test]
fn test_int_div() {
    let a = SymValueZ3::from_bitvec("a");
    let b = SymValueZ3::from_bitvec("b");
    let result = a.int_div(&b);
    assert!(result.bitvec_expr_string.unwrap().contains("bvudiv"));
}

#[test]
fn test_int_sdiv() {
    let a = SymValueZ3::from_bitvec("a");
    let b = SymValueZ3::from_bitvec("b");
    let result = a.int_sdiv(&b);
    assert!(result.bitvec_expr_string.unwrap().contains("bvsdiv"));
}

// ============================================================================
// SymValueZ3 bitwise operations
// ============================================================================

#[test]
fn test_int_and_or_xor() {
    let a = SymValueZ3::from_bitvec("a");
    let b = SymValueZ3::from_bitvec("b");
    assert!(a.int_and(&b).bitvec_expr_string.unwrap().contains("bvand"));
    assert!(a.int_or(&b).bitvec_expr_string.unwrap().contains("bvor"));
    assert!(a.int_xor(&b).bitvec_expr_string.unwrap().contains("bvxor"));
}

#[test]
fn test_shift_operations() {
    let a = SymValueZ3::from_bitvec("a");
    let b = SymValueZ3::from_bitvec("b");
    assert!(a.int_left(&b).bitvec_expr_string.unwrap().contains("bvshl"));
    assert!(a.int_right(&b).bitvec_expr_string.unwrap().contains("bvlshr"));
    assert!(a.int_sright(&b).bitvec_expr_string.unwrap().contains("bvashr"));
}

// ============================================================================
// SymValueZ3 comparison operations
// ============================================================================

#[test]
fn test_int_equal() {
    let a = SymValueZ3::from_bitvec("a");
    let b = SymValueZ3::from_bitvec("b");
    let result = a.int_equal(&b);
    let expr = result.bitvec_expr_string.unwrap();
    assert!(expr.contains("ite"));
    assert!(expr.contains("="));
}

#[test]
fn test_int_not_equal() {
    let a = SymValueZ3::from_bitvec("a");
    let b = SymValueZ3::from_bitvec("b");
    let result = a.int_not_equal(&b);
    let expr = result.bitvec_expr_string.unwrap();
    assert!(expr.contains("not"));
}

#[test]
fn test_int_sless() {
    let a = SymValueZ3::from_bitvec("a");
    let b = SymValueZ3::from_bitvec("b");
    assert!(a.int_sless(&b).bitvec_expr_string.unwrap().contains("bvslt"));
}

#[test]
fn test_int_less() {
    let a = SymValueZ3::from_bitvec("a");
    let b = SymValueZ3::from_bitvec("b");
    assert!(a.int_less(&b).bitvec_expr_string.unwrap().contains("bvult"));
}

#[test]
fn test_int_sless_equal() {
    let a = SymValueZ3::from_bitvec("a");
    let b = SymValueZ3::from_bitvec("b");
    assert!(a.int_sless_equal(&b).bitvec_expr_string.unwrap().contains("bvsle"));
}

#[test]
fn test_int_less_equal() {
    let a = SymValueZ3::from_bitvec("a");
    let b = SymValueZ3::from_bitvec("b");
    assert!(a.int_less_equal(&b).bitvec_expr_string.unwrap().contains("bvule"));
}

// ============================================================================
// SymValueZ3 boolean operations
// ============================================================================

#[test]
fn test_bool_negate() {
    let a = SymValueZ3::from_bool("p");
    let neg = a.bool_negate();
    assert!(neg.bitvec_expr_string.unwrap().contains("not"));
}

#[test]
fn test_bool_and() {
    let a = SymValueZ3::from_bool("p");
    let b = SymValueZ3::from_bool("q");
    let result = a.bool_and(&b);
    assert!(result.bitvec_expr_string.unwrap().contains("and"));
}

#[test]
fn test_bool_or() {
    let a = SymValueZ3::from_bool("p");
    let b = SymValueZ3::from_bool("q");
    let result = a.bool_or(&b);
    assert!(result.bitvec_expr_string.unwrap().contains("or"));
}

#[test]
fn test_bool_xor() {
    let a = SymValueZ3::from_bool("p");
    let b = SymValueZ3::from_bool("q");
    let result = a.bool_xor(&b);
    assert!(result.bitvec_expr_string.unwrap().contains("xor"));
}

// ============================================================================
// SymValueZ3 extension operations
// ============================================================================

#[test]
fn test_int_zext() {
    let a = SymValueZ3::from_bitvec("a");
    let result = a.int_zext(8);
    assert!(result.bitvec_expr_string.unwrap().contains("zero_extend"));
}

#[test]
fn test_int_sext() {
    let a = SymValueZ3::from_bitvec("a");
    let result = a.int_sext(8);
    assert!(result.bitvec_expr_string.unwrap().contains("sign_extend"));
}

#[test]
fn test_piece() {
    let a = SymValueZ3::from_bitvec("a");
    let b = SymValueZ3::from_bitvec("b");
    let result = a.piece(&b);
    assert!(result.bitvec_expr_string.unwrap().contains("concat"));
}

#[test]
fn test_subpiece() {
    let a = SymValueZ3::from_bitvec("a");
    let result = a.subpiece(4, 0);
    assert!(result.bitvec_expr_string.unwrap().contains("extract"));
}

#[test]
fn test_int_carry() {
    let a = SymValueZ3::from_bitvec("a");
    let b = SymValueZ3::from_bitvec("b");
    let result = a.int_carry(&b);
    let expr = result.bitvec_expr_string.unwrap();
    assert!(expr.contains("bvadd"));
}

#[test]
fn test_popcount() {
    let a = SymValueZ3::from_bitvec("a");
    let result = a.popcount(4);
    assert!(result.bitvec_expr_string.unwrap().contains("popcount"));
}

#[test]
fn test_ite_from_predicate() {
    let result = SymValueZ3::ite_from_predicate("(= x 0)", 32);
    let expr = result.bitvec_expr_string.unwrap();
    assert!(expr.contains("ite"));
}

// ============================================================================
// SymZ3RegisterMap tests
// ============================================================================

#[test]
fn test_register_map_empty() {
    let map = SymZ3RegisterMap::new();
    assert!(map.get("RAX").is_none());
}

#[test]
fn test_register_map_add_and_lookup() {
    let mut map = SymZ3RegisterMap::new();
    map.add(RegisterDescriptor::new("RAX", 0, 8));
    map.add(RegisterDescriptor::new("RBX", 8, 8));
    map.add(RegisterDescriptor::new("EAX", 0, 4));

    assert!(map.get("RAX").is_some());
    assert!(map.get("RBX").is_some());
    assert!(map.get("EAX").is_some());
    assert!(map.get("RCX").is_none());
}

#[test]
fn test_register_descriptor_properties() {
    let desc = RegisterDescriptor::new("RAX", 0, 8);
    assert_eq!(desc.name, "RAX");
    assert_eq!(desc.offset, 0);
    assert_eq!(desc.size, 8);
}

#[test]
fn test_register_map_name_at() {
    let mut map = SymZ3RegisterMap::new();
    map.add(RegisterDescriptor::new("RAX", 0, 8));
    map.add(RegisterDescriptor::new("EAX", 0, 4));

    assert_eq!(map.name_at(0, 8), Some("RAX"));
    assert_eq!(map.name_at(0, 4), Some("EAX"));
    assert_eq!(map.name_at(99, 8), None);
}

#[test]
fn test_register_map_with_state() {
    let mut map = SymZ3RegisterMap::new();
    map.add(RegisterDescriptor::new("RAX", 0, 8));

    let mut state = SymZ3State::new();
    state.set_value(SpaceKind::Register, 0, 8, SymValueZ3::from_bitvec("init_rax"));

    let val = map.get_value("RAX", &state);
    assert!(val.is_some());
    assert_eq!(val.unwrap().bitvec_expr_string.as_deref(), Some("init_rax"));
}

// ============================================================================
// SymZ3MemoryMap tests
// ============================================================================

#[test]
fn test_memory_map_empty() {
    let map = SymZ3MemoryMap::new();
    assert_eq!(map.num_regions(), 0);
    assert!(map.find_region(0x1000).is_none());
}

#[test]
fn test_memory_region_properties() {
    let region = MemoryRegion::new(0x400000, 0x1000, ".text");
    assert_eq!(region.start, 0x400000);
    assert_eq!(region.size, 0x1000);
    assert_eq!(region.name, ".text");
    assert!(region.readable);
    assert!(region.writable);
    assert_eq!(region.end(), 0x401000);
    assert!(region.contains(0x400000));
    assert!(region.contains(0x400FFF));
    assert!(!region.contains(0x401000));
    assert!(!region.contains(0x3FFFFF));
}

#[test]
fn test_memory_map_add_and_find() {
    let mut map = SymZ3MemoryMap::new();
    map.add_region(MemoryRegion::new(0x400000, 0x1000, ".text"));
    map.add_region(MemoryRegion::new(0x600000, 0x2000, ".data"));

    assert_eq!(map.num_regions(), 2);

    let r = map.find_region(0x400500).unwrap();
    assert_eq!(r.name, ".text");

    let r = map.find_region(0x601000).unwrap();
    assert_eq!(r.name, ".data");

    assert!(map.find_region(0x500000).is_none());
}

#[test]
fn test_memory_map_init_concrete() {
    let map = SymZ3MemoryMap::new();
    let mut state = SymZ3State::new();
    map.init_concrete(&mut state, 0x1000, &[0x48, 0x89, 0xE5]);
    assert_eq!(state.total_entries(), 3);
}

#[test]
fn test_memory_map_init_symbolic() {
    let map = SymZ3MemoryMap::new();
    let mut state = SymZ3State::new();
    map.init_symbolic(&mut state, 0x1000, 4, "mem");
    assert_eq!(state.total_entries(), 4);
}

// ============================================================================
// SymZ3Preconditions tests
// ============================================================================

#[test]
fn test_preconditions_empty() {
    let pre = SymZ3Preconditions::new();
    assert!(pre.is_empty());
    assert_eq!(pre.len(), 0);
}

#[test]
fn test_preconditions_add_register() {
    let mut pre = SymZ3Preconditions::new();
    pre.add_register(0, 8, SymValueZ3::from_bitvec("RAX_init"));
    pre.add_register(8, 8, SymValueZ3::from_bitvec("RBX_init"));
    assert_eq!(pre.len(), 2);
}

#[test]
fn test_preconditions_add_memory() {
    let mut pre = SymZ3Preconditions::new();
    pre.add_memory(0x600000, 4, SymValueZ3::from_bitvec("mem_init"));
    assert_eq!(pre.len(), 1);
}

#[test]
fn test_preconditions_apply_to_state() {
    let mut pre = SymZ3Preconditions::new();
    pre.add_register(0, 8, SymValueZ3::from_bitvec("init_rax"));

    let mut state = SymZ3State::new();
    pre.apply_to_state(&mut state);

    let val = state.get_value(SpaceKind::Register, 0, 8).unwrap();
    assert_eq!(val.bitvec_expr_string.as_deref(), Some("init_rax"));
}

#[test]
fn test_precondition_register_constructor() {
    let pre = SymZ3Precondition::register(0, 8, SymValueZ3::from_bitvec("x"));
    assert_eq!(pre.space, SpaceKind::Register);
    assert_eq!(pre.offset, 0);
    assert_eq!(pre.size, 8);
}

#[test]
fn test_precondition_memory_constructor() {
    let pre = SymZ3Precondition::memory(0x1000, 4, SymValueZ3::from_bitvec("y"));
    assert_eq!(pre.space, SpaceKind::Memory);
    assert_eq!(pre.offset, 0x1000);
    assert_eq!(pre.size, 4);
}

// ============================================================================
// SymZ3State tests
// ============================================================================

#[test]
fn test_state_set_and_get() {
    let mut state = SymZ3State::new();
    state.set_value(SpaceKind::Register, 0, 8, SymValueZ3::from_bitvec("RAX"));
    state.set_value(SpaceKind::Register, 8, 8, SymValueZ3::from_bitvec("RBX"));

    assert_eq!(state.total_entries(), 2);

    let rax = state.get_value(SpaceKind::Register, 0, 8).unwrap();
    assert_eq!(rax.bitvec_expr_string.as_deref(), Some("RAX"));

    let rbx = state.get_value(SpaceKind::Register, 8, 8).unwrap();
    assert_eq!(rbx.bitvec_expr_string.as_deref(), Some("RBX"));
}

#[test]
fn test_state_empty() {
    let state = SymZ3State::new();
    assert_eq!(state.total_entries(), 0);
    assert!(state.get_value(SpaceKind::Register, 0, 8).is_none());
}

#[test]
fn test_state_overwrite() {
    let mut state = SymZ3State::new();
    state.set_value(SpaceKind::Register, 0, 8, SymValueZ3::from_bitvec("old"));
    state.set_value(SpaceKind::Register, 0, 8, SymValueZ3::from_bitvec("new"));

    let val = state.get_value(SpaceKind::Register, 0, 8).unwrap();
    assert_eq!(val.bitvec_expr_string.as_deref(), Some("new"));
}
