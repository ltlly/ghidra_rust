//! Tests for data types: creation, classification, and composite types.
//!
//! Covers the `ghidra_core::data` module using concrete DataType implementations.

use ghidra_core::data::{
    builtin_data_type_tree, DataType, DataTypeKind, DataTypePath, DataTypeTreeNode,
    types::{StructureDataType, EnumDataType, UnionDataType, ArrayDataType, PointerDataType,
            TypedefDataType, FunctionDefinitionDataType, StringDataType, UndefinedDataType},
    builtin_types::{BooleanDataType, ByteDataType, IntegerDataType, FloatDataType, DoubleDataType,
                     CharDataType, ShortDataType, LongDataType, LongLongDataType,
                     VoidDataType, SignedByteDataType, SignedWordDataType, SignedDWordDataType,
                     SignedQWordDataType, WordDataType, DWordDataType, QWordDataType},
};

// ---------------------------------------------------------------------------
// Builtin type tests
// ---------------------------------------------------------------------------

#[test]
fn test_void_type() {
    let void = VoidDataType::new();
    assert_eq!(void.name(), "void");
    assert_eq!(void.get_size(), 0);
}

#[test]
fn test_boolean_type() {
    let b = BooleanDataType::new();
    assert_eq!(b.name(), "bool");
    assert_eq!(b.get_size(), 1);
}

#[test]
fn test_char_type() {
    let c = CharDataType::new();
    assert_eq!(c.name(), "char");
    assert_eq!(c.get_size(), 1);
}

#[test]
fn test_integer_types() {
    let u8_ = ByteDataType::new();
    assert_eq!(u8_.name(), "byte");
    assert_eq!(u8_.get_size(), 1);

    let i8_ = SignedByteDataType::new();
    assert_eq!(i8_.name(), "sbyte");
    assert_eq!(i8_.get_size(), 1);

    let u16_ = WordDataType::new();
    assert_eq!(u16_.name(), "word");
    assert_eq!(u16_.get_size(), 2);

    let i16_ = SignedWordDataType::new();
    assert_eq!(i16_.name(), "sword");
    assert_eq!(i16_.get_size(), 2);

    let u32_ = DWordDataType::new();
    assert_eq!(u32_.name(), "dword");
    assert_eq!(u32_.get_size(), 4);

    let i32_ = SignedDWordDataType::new();
    assert_eq!(i32_.name(), "sdword");
    assert_eq!(i32_.get_size(), 4);

    let u64_ = QWordDataType::new();
    assert_eq!(u64_.name(), "qword");
    assert_eq!(u64_.get_size(), 8);

    let i64_ = SignedQWordDataType::new();
    assert_eq!(i64_.name(), "sqword");
    assert_eq!(i64_.get_size(), 8);
}

#[test]
fn test_long_types() {
    let short = ShortDataType::new();
    assert_eq!(short.name(), "short");
    assert_eq!(short.get_size(), 2);

    let int = IntegerDataType::new(4);
    assert_eq!(int.name(), "int");
    assert_eq!(int.get_size(), 4);

    let long = LongDataType::new();
    assert_eq!(long.name(), "long");
    assert_eq!(long.get_size(), 4);

    let long_long = LongLongDataType::new();
    assert_eq!(long_long.name(), "longlong");
    assert_eq!(long_long.get_size(), 8);
}

#[test]
fn test_floating_point_types() {
    let f = FloatDataType::new();
    assert_eq!(f.name(), "float");
    assert_eq!(f.get_size(), 4);

    let d = DoubleDataType::new();
    assert_eq!(d.name(), "double");
    assert_eq!(d.get_size(), 8);
}

#[test]
fn test_string_type() {
    let s = StringDataType::new();
    assert_eq!(s.name(), "string");
    assert_eq!(s.get_size(), 0); // strings are variable-length
}

// ---------------------------------------------------------------------------
// Composite type tests
// ---------------------------------------------------------------------------

#[test]
fn test_structure_construction() {
    let dt = StructureDataType::new("my_type");
    assert_eq!(dt.name, "my_type");
    assert_eq!(dt.size, 0); // empty structure
}

#[test]
fn test_structure_display() {
    let dt = StructureDataType::new("MyStruct");
    let s = format!("{}", dt);
    assert!(s.contains("MyStruct"));
}

#[test]
fn test_structure_like_type() {
    let mut struct_dt = StructureDataType::new("Point");
    struct_dt.description = "A 3D point".to_string();
    assert_eq!(struct_dt.name, "Point");
    assert!(!struct_dt.description.is_empty());
}

#[test]
fn test_union_type() {
    let union_dt = UnionDataType::new("Variant");
    assert_eq!(union_dt.name, "Variant");
}

#[test]
fn test_enum_type() {
    let enum_dt = EnumDataType::new("Colors");
    assert_eq!(enum_dt.name, "Colors");
}

#[test]
fn test_array_type() {
    let base = IntegerDataType::new(4); // 32-bit int
    let array_dt = ArrayDataType::new(&base, 10);
    assert_eq!(array_dt.name, "int[10]");
    assert_eq!(array_dt.num_elements, 10);
}

#[test]
fn test_pointer_type() {
    let base = IntegerDataType::new(4);
    let ptr = PointerDataType::new(&base);
    assert_eq!(ptr.name, "int*");
    assert_eq!(ptr.size, 8); // 64-bit pointer
}

#[test]
fn test_typedef_type() {
    let base = IntegerDataType::new(8);
    let td = TypedefDataType::new("size_t", &base);
    assert_eq!(td.name, "size_t");
}

#[test]
fn test_function_signature_type() {
    let fs = FunctionDefinitionDataType::new("my_func");
    assert_eq!(fs.name, "my_func");
}

#[test]
fn test_undefined_type() {
    let ud = UndefinedDataType::new(4);
    assert_eq!(ud.name(), "undefined4");
    assert_eq!(ud.get_size(), 4);
    assert!(!ud.is_defined());
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
    let dt = IntegerDataType::new(4);
    let node = DataTypeTreeNode::leaf("int", dt);
    assert_eq!(node.name, "int");
    assert!(node.data_type.is_some());
    assert!(node.is_leaf());
}

#[test]
fn test_tree_node_category() {
    let children = vec![
        DataTypeTreeNode::leaf("byte", ByteDataType::new()),
        DataTypeTreeNode::leaf("word", WordDataType::new()),
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

    let mut found_void = false;
    let mut found_bool = false;
    let mut found_byte = false;
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
        if child.name == "byte" {
            found_byte = true;
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
    assert!(found_byte, "byte type not found in builtin tree");
    assert!(found_float, "float type not found in builtin tree");
    assert!(found_double, "double type not found in builtin tree");
}

#[test]
fn test_builtin_tree_leaf_types() {
    let tree = builtin_data_type_tree();
    for child in &tree.children {
        assert!(child.is_leaf(), "Expected leaf node, got category: {}", child.name);
        assert!(child.data_type.is_some(), "Expected data type for leaf: {}", child.name);
    }
}

// ---------------------------------------------------------------------------
// Combined scenario tests
// ---------------------------------------------------------------------------

#[test]
fn test_hierarchical_type_system() {
    let mut root = DataTypeTreeNode::new("/");

    let mut primitives = DataTypeTreeNode::category(
        "primitives",
        vec![
            DataTypeTreeNode::leaf("int", IntegerDataType::new(4)),
            DataTypeTreeNode::leaf("float", FloatDataType::new()),
        ],
    );

    let mut composites = DataTypeTreeNode::category(
        "composites",
        vec![
            DataTypeTreeNode::leaf("string", StringDataType::new()),
            DataTypeTreeNode::leaf("char*", PointerDataType::new(&CharDataType::new())),
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
    let base = IntegerDataType::new(4);
    let p1 = PointerDataType::new(&base);
    let p2 = PointerDataType::new(&p1);
    let p3 = PointerDataType::new(&p2);

    assert_eq!(p1.name, "int*");
    assert_eq!(p2.name, "int**");
    assert_eq!(p3.name, "int***");

    // All pointers are 8 bytes on 64-bit
    assert_eq!(p1.size, 8);
    assert_eq!(p2.size, 8);
    assert_eq!(p3.size, 8);
}

#[test]
fn test_varied_sizes() {
    let sizes = [
        (VoidDataType::new().get_size(), 0),
        (BooleanDataType::new().get_size(), 1),
        (CharDataType::new().get_size(), 1),
        (ByteDataType::new().get_size(), 1),
        (SignedByteDataType::new().get_size(), 1),
        (WordDataType::new().get_size(), 2),
        (SignedWordDataType::new().get_size(), 2),
        (DWordDataType::new().get_size(), 4),
        (SignedDWordDataType::new().get_size(), 4),
        (QWordDataType::new().get_size(), 8),
        (SignedQWordDataType::new().get_size(), 8),
        (FloatDataType::new().get_size(), 4),
        (DoubleDataType::new().get_size(), 8),
    ];

    for (actual, expected) in &sizes {
        assert_eq!(
            actual, expected,
            "Expected size {}, got {}",
            expected, actual
        );
    }
}
