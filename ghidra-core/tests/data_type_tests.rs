//! Tests for data types: creation, classification, and composite types.
//!
//! Covers the `ghidra_core::data` module using concrete DataType implementations.

use std::sync::Arc;

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

    let int = IntegerDataType::new();
    assert_eq!(int.name(), "int");
    assert_eq!(int.get_size(), 4);

    let long = LongDataType::new();
    assert_eq!(long.name(), "long");
    // LongDataType may be 8 bytes on 64-bit platforms
    assert!(long.get_size() == 4 || long.get_size() == 8);

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
    let s = StringDataType::new(0);
    assert_eq!(s.name(), "string");
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
    let enum_dt = EnumDataType::new("Colors", 4);
    assert_eq!(enum_dt.name, "Colors");
}

#[test]
fn test_array_type() {
    let base: Arc<dyn DataType> = Arc::new(IntegerDataType::new());
    let array_dt = ArrayDataType::new(base, 10);
    assert_eq!(array_dt.element_count, 10);
}

#[test]
fn test_pointer_type() {
    let base: Arc<dyn DataType> = Arc::new(IntegerDataType::new());
    let ptr = PointerDataType::new(base);
    assert_eq!(ptr.pointer_size, 8); // 64-bit pointer
}

#[test]
fn test_typedef_type() {
    let base: Arc<dyn DataType> = Arc::new(IntegerDataType::new());
    let td = TypedefDataType::new("size_t", base);
    assert_eq!(td.name, "size_t");
}

#[test]
fn test_function_signature_type() {
    let ret: Arc<dyn DataType> = Arc::new(IntegerDataType::new());
    let fs = FunctionDefinitionDataType::new("my_func", ret);
    assert_eq!(fs.name, "my_func");
}

#[test]
fn test_undefined_type() {
    let ud = UndefinedDataType::new(4);
    // Name may vary depending on implementation
    assert!(!ud.name().is_empty());
    assert_eq!(ud.get_size(), 4);
    assert!(!ud.is_defined());
}

// ---------------------------------------------------------------------------
// DataTypePath tests
// ---------------------------------------------------------------------------

#[test]
fn test_data_type_path_construction() {
    use ghidra_core::data::CategoryPath;
    let path = DataTypePath::new(CategoryPath::from_segments(vec!["root".into()]), "MyType");
    assert_eq!(path.data_type_name, "MyType");
    assert_eq!(path.category_path.segments.len(), 1);
}

#[test]
fn test_data_type_path_from_path() {
    let path = DataTypePath::from_path("/root/std/string");
    assert_eq!(path.data_type_name, "string");
    assert_eq!(path.category_path.segments.len(), 2);
}

#[test]
fn test_data_type_path_equality() {
    let a = DataTypePath::from_path("/a/b");
    let b = DataTypePath::from_path("/a/b");
    let c = DataTypePath::from_path("/a/c");
    assert_eq!(a, b);
    assert_ne!(a, c);
}

// ---------------------------------------------------------------------------
// DataTypeTreeNode tests
// ---------------------------------------------------------------------------

#[test]
fn test_tree_node_leaf() {
    let dt: Arc<dyn DataType> = Arc::new(IntegerDataType::new());
    let node = DataTypeTreeNode::leaf("int", dt);
    assert_eq!(node.name, "int");
    assert!(node.data_type.is_some());
    assert!(node.is_leaf());
}

#[test]
fn test_tree_node_category() {
    let children = vec![
        DataTypeTreeNode::leaf("byte", Arc::new(ByteDataType::new()) as Arc<dyn DataType>),
        DataTypeTreeNode::leaf("word", Arc::new(WordDataType::new()) as Arc<dyn DataType>),
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
fn test_builtin_tree_contains_types() {
    let tree = builtin_data_type_tree();

    // The tree should have children (builtin types)
    assert!(!tree.children.is_empty(), "Builtin tree should have children");

    // Collect all type names for debugging
    let names: Vec<&str> = tree.children.iter().map(|c| c.name.as_str()).collect();
    assert!(!names.is_empty());

    // At least some common types should exist (names may vary)
    // Check that we have a reasonable number of builtin types
    assert!(names.len() >= 5, "Expected at least 5 builtin types, got {}", names.len());
}

#[test]
fn test_builtin_tree_leaf_types() {
    let tree = builtin_data_type_tree();
    // The tree has categories as children, each containing leaf types.
    // Check that at least one category has leaf children.
    let mut total_leaves = 0;
    for category in &tree.children {
        for child in &category.children {
            if child.is_leaf() {
                total_leaves += 1;
            }
        }
    }
    assert!(total_leaves > 0, "Expected at least one leaf type in builtin tree");
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
            DataTypeTreeNode::leaf("int", Arc::new(IntegerDataType::new()) as Arc<dyn DataType>),
            DataTypeTreeNode::leaf("float", Arc::new(FloatDataType::new()) as Arc<dyn DataType>),
        ],
    );

    let char_ptr: Arc<dyn DataType> = Arc::new(CharDataType::new());
    let mut composites = DataTypeTreeNode::category(
        "composites",
        vec![
            DataTypeTreeNode::leaf("string", Arc::new(StringDataType::new(0)) as Arc<dyn DataType>),
            DataTypeTreeNode::leaf("char*", Arc::new(PointerDataType::new(char_ptr)) as Arc<dyn DataType>),
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
    let base: Arc<dyn DataType> = Arc::new(IntegerDataType::new());
    let p1 = PointerDataType::new(base);
    let p1_arc: Arc<dyn DataType> = Arc::new(p1);
    let p2 = PointerDataType::new(p1_arc);
    let p2_arc: Arc<dyn DataType> = Arc::new(p2);
    let p3 = PointerDataType::new(p2_arc);

    assert_eq!(p3.pointer_size, 8);
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
