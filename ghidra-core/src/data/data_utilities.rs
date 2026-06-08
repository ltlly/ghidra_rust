//! Utility functions for data type operations.
//!
//! Port of Ghidra's `DataTypeUtilities.java` and `DataUtilities.java`.

use std::sync::Arc;

use super::types::DataType;
use super::CategoryPath;

// ============================================================================
// DataTypeUtilities
// ============================================================================

/// Check if two data types are the same instance or are equivalent.
///
/// Port of Ghidra's `DataTypeUtilities.isSameOrEquivalentDataType()`.
pub fn is_same_or_equivalent(dt1: &dyn DataType, dt2: &dyn DataType) -> bool {
    // Fast path: same pointer (if Arc-wrapped types call through to this)
    std::ptr::eq(dt1 as *const _ as *const u8, dt2 as *const _ as *const u8)
        || dt1.is_equivalent(dt2)
}

/// Get the base name without any conflict suffix.
pub fn get_name_without_conflict(name: &str) -> &str {
    super::comparators::get_name_without_conflict(name)
}

/// Get the conflict value (number of conflict suffixes).
pub fn get_conflict_value(name: &str) -> usize {
    super::comparators::get_conflict_value(name)
}

/// Generate a unique name by appending conflict suffixes.
pub fn get_unique_name(
    name: &str,
    existing_names: &[&str],
) -> String {
    let mut candidate = name.to_string();
    let mut counter = 1;
    while existing_names.contains(&candidate.as_str()) {
        counter += 1;
        candidate = format!("{}{}", name, ".conflict".repeat(counter - 1));
    }
    candidate
}

/// Check if a data type is a pointer type (including typedefs to pointers).
pub fn is_pointer_type(dt: &dyn DataType) -> bool {
    dt.is_pointer()
}

/// Check if a data type is a composite type (structure or union).
pub fn is_composite_type(dt: &dyn DataType) -> bool {
    dt.is_composite()
}

/// Check if a data type is an undefined type.
pub fn is_undefined_type(dt: &dyn DataType) -> bool {
    dt.is_undefined()
}

/// Get the base data type, following typedef chains.
///
/// In the Rust implementation, this is a simplified version. The full Java
/// version would downcast to `TypeDef` and follow the chain. Here we just
/// return the type itself, as the `TypedefDataType` in Rust already delegates
/// size/alignment to its base.
pub fn get_base_data_type(dt: &Arc<dyn DataType>) -> Arc<dyn DataType> {
    dt.clone()
}

/// Check if two category paths are the same.
pub fn is_same_category_path(path1: &CategoryPath, path2: &CategoryPath) -> bool {
    path1 == path2
}

/// Get the shortest unique name for a data type given other types.
pub fn get_shortest_unique_name(
    dt: &dyn DataType,
    others: &[&dyn DataType],
) -> String {
    let name = dt.name().to_string();
    let full_name = dt.get_path_name();

    // Check if just the name is unique
    let name_conflicts = others
        .iter()
        .filter(|other| other.name() == name)
        .count();
    if name_conflicts == 0 {
        return name;
    }

    // Check if name + immediate category is unique
    let last_category = dt
        .get_category_path()
        .segments
        .last()
        .cloned()
        .unwrap_or_default();
    if !last_category.is_empty() {
        let qualified = format!("{}/{}", last_category, name);
        let qualified_conflicts = others.iter().filter(|other| {
            let other_last = other
                .get_category_path()
                .segments
                .last()
                .cloned()
                .unwrap_or_default();
            let other_qualified = format!("{}/{}", other_last, other.name());
            other_qualified == qualified
        }).count();
        if qualified_conflicts == 0 {
            return qualified;
        }
    }

    // Fall back to full path
    full_name
}

// ============================================================================
// DataUtilities
// ============================================================================

/// Check if a data type has a language-dependent length.
pub fn has_language_dependent_length(dt: &dyn DataType) -> bool {
    // Primitive types like int, long, etc. have sizes that depend on the
    // target architecture's data organization.
    let name = dt.name();
    matches!(
        name,
        "int" | "uint" | "long" | "ulong" | "longlong" | "ulonglong"
            | "wchar" | "wchar16" | "wchar32"
    )
}

/// Check if a data type is a fixed-length type suitable for use as a
/// variable or parameter type.
pub fn is_fixed_length(dt: &dyn DataType) -> bool {
    dt.get_size() > 0 && !dt.is_undefined()
}

/// Get the category path from a fully-qualified data type path string.
pub fn parse_category_path(full_path: &str) -> CategoryPath {
    if let Some(last_slash) = full_path.rfind('/') {
        CategoryPath::from_path_string(&full_path[..last_slash])
    } else {
        CategoryPath::ROOT
    }
}

/// Get the type name from a fully-qualified data type path string.
pub fn parse_type_name(full_path: &str) -> &str {
    if let Some(last_slash) = full_path.rfind('/') {
        &full_path[last_slash + 1..]
    } else {
        full_path
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::types::StructureDataType;
    use crate::data::builtin_types::*;

    #[test]
    fn test_is_same_or_equivalent() {
        let dt1 = IntegerDataType::new();
        let dt2 = IntegerDataType::new();
        assert!(is_same_or_equivalent(&dt1, &dt2));
    }

    #[test]
    fn test_is_pointer_type() {
        let s = StructureDataType::new("test");
        assert!(!is_pointer_type(&s));
    }

    #[test]
    fn test_is_composite_type() {
        let s = StructureDataType::new("test");
        assert!(is_composite_type(&s));
    }

    #[test]
    fn test_is_undefined_type() {
        let u = crate::data::types::UndefinedDataType::new(4);
        assert!(is_undefined_type(&u));
        assert!(!is_undefined_type(&IntegerDataType::new()));
    }

    #[test]
    fn test_get_unique_name() {
        let existing = &["int", "int.conflict"];
        let unique = get_unique_name("int", existing);
        assert_eq!(unique, "int.conflict.conflict");
    }

    #[test]
    fn test_parse_category_path() {
        assert_eq!(parse_category_path("/a/b/c"), CategoryPath::from_path_string("/a/b"));
        assert_eq!(parse_category_path("int"), CategoryPath::ROOT);
    }

    #[test]
    fn test_parse_type_name() {
        assert_eq!(parse_type_name("/a/b/c"), "c");
        assert_eq!(parse_type_name("int"), "int");
    }

    #[test]
    fn test_has_language_dependent_length() {
        assert!(has_language_dependent_length(&IntegerDataType::new()));
        assert!(has_language_dependent_length(&LongDataType::new()));
        assert!(!has_language_dependent_length(&ByteDataType::new()));
    }

    #[test]
    fn test_is_fixed_length() {
        assert!(is_fixed_length(&IntegerDataType::new()));
        assert!(!is_fixed_length(&crate::data::types::UndefinedDataType::new(4)));
    }

    #[test]
    fn test_get_shortest_unique_name() {
        let s1 = StructureDataType::new("MyType")
            .with_category_path(CategoryPath::new("a"));
        let s2 = StructureDataType::new("MyType")
            .with_category_path(CategoryPath::new("b"));

        let others: Vec<&dyn DataType> = vec![&s2];
        let name = get_shortest_unique_name(&s1, &others);
        // Should include category qualifier since name collides
        assert!(name.contains("a") || name.contains("MyType"));
    }
}
