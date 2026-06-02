//! Tests for data types: creation, classification, type hierarchy, and composite types.
//!
//! Covers the `ghidra_core::data` module:
//! - [`DataType`] construction and primitive factories
//! - [`DataTypeKind`] enumeration and display
//! - [`DataTypePath`] and [`DataTypeTreeNode`] hierarchy
//! - Pointer, Structure, and Enum representation patterns

use ghidra_core::data::{
    builtin_data_type_tree, DataType, DataTypeKind, DataTypePath, DataTypeTreeNode,
};

// ---------------------------------------------------------------------------
// DataTypeKind tests
// ---------------------------------------------------------------------------

#[test]
fn test_data_type_kind_enum_values() {
    let kinds = [
        (DataTypeKind::Undefined, "undefined"),
        (DataTypeKind::Primitive, "primitive"),
        (DataTypeKind::Pointer, "pointer"),
        (DataTypeKind::Array, "array"),
        (DataTypeKind::Structure, "structure"),
        (DataTypeKind::Union, "union"),
        (DataTypeKind::Enum, "enum"),
        (DataTypeKind::Typedef, "typedef"),
        (DataTypeKind::FunctionSignature, "function"),
    ];

    for (kind, expected) in &kinds {
        assert_eq!(format!("{}", kind), *expected);
    }
}

#[test]
fn test_data_type_kind_equality() {
    assert_eq!(DataTypeKind::Primitive, DataTypeKind::Primitive);
    assert_ne!(DataTypeKind::Structure, DataTypeKind::Union);
    assert_ne!(DataTypeKind::Pointer, DataTypeKind::Array);
}

// ---------------------------------------------------------------------------
// DataType tests — primitive types
// ---------------------------------------------------------------------------

#[test]
fn test_data_type_construction() {
    let dt = DataType::new("my_type", 8, DataTypeKind::Structure);
    assert_eq!(dt.name, "my_type");
    assert_eq!(dt.size, 8);
    assert_eq!(dt.kind, DataTypeKind::Structure);
    assert!(dt.category.is_none());
    assert!(dt.description.is_empty());
}

#[test]
fn test_void_type() {
    let void = DataType::void();
    assert_eq!(void.name, "void");
    assert_eq!(void.size, 0);
    assert_eq!(void.kind, DataTypeKind::Primitive);
}

#[test]
fn test_bool_type() {
    let b = DataType::bool();
    assert_eq!(b.name, "bool");
    assert_eq!(b.size, 1);
    assert_eq!(b.kind, DataTypeKind::Primitive);
}

#[test]
fn test_char_type() {
    let c = DataType::char();
    assert_eq!(c.name, "char");
    assert_eq!(c.size, 1);
}

#[test]
fn test_integer_types() {
    let u8_ = DataType::u8();
    assert_eq!(u8_.name, "u8");
    assert_eq!(u8_.size, 1);

    let i8_ = DataType::i8();
    assert_eq!(i8_.name, "i8");
    assert_eq!(i8_.size, 1);

    let u16_ = DataType::u16();
    assert_eq!(u16_.name, "u16");
    assert_eq!(u16_.size, 2);

    let i16_ = DataType::i16();
    assert_eq!(i16_.name, "i16");
    assert_eq!(i16_.size, 2);

    let u32_ = DataType::u32();
    assert_eq!(u32_.name, "u32");
    assert_eq!(u32_.size, 4);

    let i32_ = DataType::i32();
    assert_eq!(i32_.name, "i32");
    assert_eq!(i32_.size, 4);

    let u64_ = DataType::u64();
    assert_eq!(u64_.name, "u64");
    assert_eq!(u64_.size, 8);

    let i64_ = DataType::i64();
    assert_eq!(i64_.name, "i64");
    assert_eq!(i64_.size, 8);
}

#[test]
fn test_floating_point_types() {
    let f = DataType::float();
    assert_eq!(f.name, "float");
    assert_eq!(f.size, 4);

    let d = DataType::double();
    assert_eq!(d.name, "double");
    assert_eq!(d.size, 8);
}

#[test]
fn test_string_type() {
    let s = DataType::string();
    assert_eq!(s.name, "string");
    assert_eq!(s.size, 0); // strings are variable-length
}

#[test]
fn test_data_type_display() {
    let dt = DataType::new("MyStruct", 16, DataTypeKind::Structure);
    let s = format!("{}", dt);
    assert!(s.contains("MyStruct"));
    assert!(s.contains("16 bytes"));
    assert!(s.contains("structure"));
}

#[test]
fn test_data_type_equality() {
    let a = DataType::i32();
    let b = DataType::i32();
    let c = DataType::i64();
    assert_eq!(a, b);
    assert_ne!(a, c);
}

// ---------------------------------------------------------------------------
// Pointer type tests
// ---------------------------------------------------------------------------

#[test]
fn test_pointer_type() {
    let base = DataType::i32();
    let ptr = DataType::pointer(&base);
    assert_eq!(ptr.name, "i32*");
    assert_eq!(ptr.size, 8); // 64-bit pointer
    assert_eq!(ptr.kind, DataTypeKind::Pointer);
    assert_eq!(ptr.description, "i32"); // stores base type name
}

#[test]
fn test_pointer_to_pointer() {
    let base = DataType::char();
    let ptr = DataType::pointer(&base);
    let ptr_ptr = DataType::pointer(&ptr);
    assert_eq!(ptr_ptr.name, "char**");
    assert_eq!(ptr_ptr.kind, DataTypeKind::Pointer);
}

#[test]
fn test_pointer_to_void() {
    let void = DataType::void();
    let void_ptr = DataType::pointer(&void);
    assert_eq!(void_ptr.name, "void*");
    assert_eq!(void_ptr.size, 8);
}

// ---------------------------------------------------------------------------
// Structure/Union tests
// ---------------------------------------------------------------------------

#[test]
fn test_structure_like_type() {
    // Represent a struct { int a; char b; float c; }
    let mut struct_dt = DataType::new("Point", 12, DataTypeKind::Structure);
    struct_dt.description = "A 3D point { x: i32, y: i32, z: i32 }".to_string();

    assert_eq!(struct_dt.name, "Point");
    assert_eq!(struct_dt.size, 12);
    assert_eq!(struct_dt.kind, DataTypeKind::Structure);
    assert!(!struct_dt.description.is_empty());

    // Fields would be tracked via a field manager in a full implementation
}

#[test]
fn test_union_type() {
    let union_dt = DataType::new("Variant", 8, DataTypeKind::Union);
    assert_eq!(union_dt.kind, DataTypeKind::Union);
}

#[test]
fn test_enum_type() {
    let enum_dt = DataType::new("Colors", 4, DataTypeKind::Enum);
    assert_eq!(enum_dt.kind, DataTypeKind::Enum);
    // Enum values (RED=0, GREEN=1, BLUE=2) would be stored in an enum member list
}

#[test]
fn test_array_type() {
    // Represent int[10]
    let array_dt = DataType::new("int[10]", 40, DataTypeKind::Array);
    assert_eq!(array_dt.name, "int[10]");
    assert_eq!(array_dt.size, 40); // 10 * 4 bytes
    assert_eq!(array_dt.kind, DataTypeKind::Array);
}

#[test]
fn test_typedef_type() {
    let td = DataType::new("size_t", 8, DataTypeKind::Typedef);
    assert_eq!(td.kind, DataTypeKind::Typedef);
}

#[test]
fn test_function_signature_type() {
    let fs = DataType::new("int(int, char*)", 0, DataTypeKind::FunctionSignature);
    assert_eq!(fs.kind, DataTypeKind::FunctionSignature);
}

// ---------------------------------------------------------------------------
// DataTypePath tests
// ---------------------------------------------------------------------------

#[test]
fn test_data_type_path_construction() {
    let path = DataTypePath::new("root");
    assert_eq!(path.segments.len(), 1);
    assert_eq!(path.segments[0], "root");
}

#[test]
fn test_data_type_path_from_segments() {
    let path = DataTypePath::from_segments(vec![
        "root".into(),
        "std".into(),
        "string".into(),
    ]);
    assert_eq!(path.segments.len(), 3);
    assert_eq!(path.display_name(), "root/std/string");
}

#[test]
fn test_data_type_path_display() {
    let path = DataTypePath::from_segments(vec!["base".into(), "ptr".into()]);
    assert_eq!(path.display_name(), "base/ptr");
}

#[test]
fn test_data_type_path_equality() {
    let a = DataTypePath::from_segments(vec!["a".into(), "b".into()]);
    let b = DataTypePath::from_segments(vec!["a".into(), "b".into()]);
    let c = DataTypePath::from_segments(vec!["a".into(), "c".into()]);
    assert_eq!(a, b);
    assert_ne!(a, c);
}

// ---------------------------------------------------------------------------
// DataTypeTreeNode tests
// ---------------------------------------------------------------------------

#[test]
fn test_tree_node_leaf() {
    let node = DataTypeTreeNode::leaf("int", DataType::i32());
    assert_eq!(node.name, "int");
    assert!(node.data_type.is_some());
    assert!(node.is_leaf());
}

#[test]
fn test_tree_node_category() {
    let children = vec![
        DataTypeTreeNode::leaf("int", DataType::i32()),
        DataTypeTreeNode::leaf("long", DataType::i64()),
    ];
    let cat = DataTypeTreeNode::category("primitives", children);
    assert_eq!(cat.name, "primitives");
    assert!(cat.data_type.is_none());
    assert!(!cat.is_leaf());
    assert_eq!(cat.children.len(), 2);
}

#[test]
fn test_tree_node_new() {
    let node = DataTypeTreeNode::new("MyCategory");
    assert_eq!(node.name, "MyCategory");
    assert!(node.data_type.is_none());
    assert!(node.is_leaf());
}

// ---------------------------------------------------------------------------
// Built-in data type tree tests
// ---------------------------------------------------------------------------

#[test]
fn test_builtin_tree_not_empty() {
    let tree = builtin_data_type_tree();
    assert!(!tree.is_leaf());
    assert!(!tree.children.is_empty());
}

#[test]
fn test_builtin_tree_contains_primitives() {
    let tree = builtin_data_type_tree();

    // Search for common primitive types
    let mut found_void = false;
    let mut found_bool = false;
    let mut found_int = false;
    let mut found_float = false;
    let mut found_double = false;

    for child in &tree.children {
        if child.name == "void" {
            found_void = true;
            assert!(child.data_type.is_some());
        }
        if child.name == "bool" {
            found_bool = true;
        }
        if child.name == "int" {
            found_int = true;
        }
        if child.name == "float" {
            found_float = true;
        }
        if child.name == "double" {
            found_double = true;
        }
    }

    assert!(found_void, "void type not found in builtin tree");
    assert!(found_bool, "bool type not found in builtin tree");
    assert!(found_int, "int type not found in builtin tree");
    assert!(found_float, "float type not found in builtin tree");
    assert!(found_double, "double type not found in builtin tree");
}

#[test]
fn test_builtin_tree_leaf_types() {
    let tree = builtin_data_type_tree();
    for child in &tree.children {
        assert!(child.is_leaf(), "Expected leaf node, got category: {}", child.name);
        assert!(child.data_type.is_some(), "Expected data type for leaf: {}", child.name);
        let dt = child.data_type.as_ref().unwrap();
        assert_eq!(dt.kind, DataTypeKind::Primitive);
    }
}

// ---------------------------------------------------------------------------
// Combined scenario tests
// ---------------------------------------------------------------------------

#[test]
fn test_hierarchical_type_system() {
    // Build a two-level type hierarchy
    let mut root = DataTypeTreeNode::new("/");

    let mut primitives = DataTypeTreeNode::category(
        "primitives",
        vec![
            DataTypeTreeNode::leaf("int", DataType::i32()),
            DataTypeTreeNode::leaf("float", DataType::float()),
        ],
    );

    let mut composites = DataTypeTreeNode::category(
        "composites",
        vec![
            DataTypeTreeNode::leaf("string", DataType::string()),
            DataTypeTreeNode::leaf("char*", DataType::pointer(&DataType::char())),
        ],
    );

    root.children.push(primitives);
    root.children.push(composites);

    assert_eq!(root.children.len(), 2);
    assert_eq!(root.children[0].children.len(), 2);
    assert_eq!(root.children[1].children.len(), 2);
}

#[test]
fn test_pointer_chain() {
    // int -> int* -> int** -> int***
    let base = DataType::i32();
    let p1 = DataType::pointer(&base);
    let p2 = DataType::pointer(&p1);
    let p3 = DataType::pointer(&p2);

    assert_eq!(p1.name, "i32*");
    assert_eq!(p2.name, "i32**");
    assert_eq!(p3.name, "i32***");

    // All pointers are 8 bytes on 64-bit
    assert_eq!(p1.size, 8);
    assert_eq!(p2.size, 8);
    assert_eq!(p3.size, 8);
}

#[test]
fn test_varied_sizes() {
    // Verify common C type sizes
    let sizes = [
        ("void", 0),
        ("bool", 1),
        ("char", 1),
        ("u8", 1),
        ("i8", 1),
        ("u16", 2),
        ("i16", 2),
        ("u32", 4),
        ("i32", 4),
        ("u64", 8),
        ("i64", 8),
        ("float", 4),
        ("double", 8),
    ];

    for (name, expected_size) in &sizes {
        let dt = match *name {
            "void" => DataType::void(),
            "bool" => DataType::bool(),
            "char" => DataType::char(),
            "u8" => DataType::u8(),
            "i8" => DataType::i8(),
            "u16" => DataType::u16(),
            "i16" => DataType::i16(),
            "u32" => DataType::u32(),
            "i32" => DataType::i32(),
            "u64" => DataType::u64(),
            "i64" => DataType::i64(),
            "float" => DataType::float(),
            "double" => DataType::double(),
            _ => continue,
        };
        assert_eq!(
            dt.size, *expected_size,
            "Expected {} to have size {}, got {}",
            name, expected_size, dt.size
        );
    }
}

#[test]
fn test_kind_classification() {
    // Verify that each kind maps to its expected semantic category
    assert_eq!(DataTypeKind::Primitive, DataType::i32().kind);
    assert_eq!(DataTypeKind::Pointer, DataType::pointer(&DataType::i32()).kind);
    assert_eq!(DataTypeKind::Array, DataType::new("arr", 40, DataTypeKind::Array).kind);
    assert_eq!(DataTypeKind::Structure, DataType::new("s", 16, DataTypeKind::Structure).kind);
    assert_eq!(DataTypeKind::Enum, DataType::new("e", 4, DataTypeKind::Enum).kind);
    assert_eq!(DataTypeKind::Union, DataType::new("u", 8, DataTypeKind::Union).kind);
}
