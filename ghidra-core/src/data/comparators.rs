//! Comparators for data type sorting and ordering.
//!
//! Ports of:
//! - `DataTypeComparator.java` - name-based comparison with sub-ordering
//! - `DataTypeNameComparator.java` - case-insensitive name comparison
//! - `DataTypeObjectComparator.java` - mixed DataType/String comparison

use std::cmp::Ordering;
use std::sync::Arc;

use super::types::DataType;

/// The conflict suffix appended to conflicting data type names.
pub const CONFLICT_SUFFIX: &str = ".conflict";

// ============================================================================
// Utility functions (port of DataTypeUtilities helpers)
// ============================================================================

/// Get the base name without any conflict suffix.
///
/// For example, `"int.conflict"` becomes `"int"`.
pub fn get_name_without_conflict(name: &str) -> &str {
    if let Some(idx) = name.rfind(CONFLICT_SUFFIX) {
        &name[..idx]
    } else {
        name
    }
}

/// Get the conflict number from a name.
///
/// Returns 0 for a base name, 1 for `".conflict"`, 2 for `".conflict.conflict"`, etc.
pub fn get_conflict_value(name: &str) -> usize {
    let mut count = 0;
    let mut remaining = name;
    while let Some(idx) = remaining.rfind(CONFLICT_SUFFIX) {
        count += 1;
        remaining = &remaining[..idx];
    }
    count
}

/// Generate a conflict name by appending the conflict suffix.
pub fn get_conflict_name(name: &str) -> String {
    format!("{}{}", name, CONFLICT_SUFFIX)
}

// ============================================================================
// DataTypeNameComparator
// ============================================================================

/// Provides a preferred name-based comparison of data type names.
///
/// Port of Ghidra's `DataTypeNameComparator.java`. Handles case-insensitive
/// comparison and proper ordering of conflict datatypes.
#[derive(Debug, Clone, Copy)]
pub struct DataTypeNameComparator;

impl DataTypeNameComparator {
    /// The singleton instance.
    pub const INSTANCE: DataTypeNameComparator = DataTypeNameComparator;

    /// Compare two data type names.
    ///
    /// Uses case-insensitive comparison for the base name, then sub-orders
    /// by conflict value.
    pub fn compare(&self, dt1_name: &str, dt2_name: &str) -> Ordering {
        let name1 = get_name_without_conflict(dt1_name);
        let name2 = get_name_without_conflict(dt2_name);

        let chars1: Vec<char> = name1.chars().collect();
        let chars2: Vec<char> = name2.chars().collect();
        let len1 = chars1.len();
        let len2 = chars2.len();
        let overlap_len = len1.min(len2);
        let mut base_name_len = overlap_len;

        // Case-insensitive compare of significant overlapping portion
        let mut base_case_compare: i32 = 0;
        for i in 0..overlap_len {
            let lc1 = chars1[i].to_lowercase().next().unwrap_or(chars1[i]);
            let lc2 = chars2[i].to_lowercase().next().unwrap_or(chars2[i]);
            // First space treated as end of base-name
            if lc1 == ' ' {
                if lc2 == ' ' {
                    base_name_len = i;
                    break;
                }
                return Ordering::Less;
            }
            if lc2 == ' ' {
                return Ordering::Greater;
            }
            if lc1 != lc2 {
                return (lc1 as i32).cmp(&(lc2 as i32));
            }
            if base_case_compare == 0 {
                base_case_compare = (chars1[i] as i32) - (chars2[i] as i32);
            }
        }

        if len1 > base_name_len
            && base_name_len < chars1.len()
            && chars1[base_name_len] != ' '
        {
            return Ordering::Greater; // first name has longer base-name
        }
        if len2 > base_name_len
            && base_name_len < chars2.len()
            && chars2[base_name_len] != ' '
        {
            return Ordering::Less; // second name has longer base-name
        }

        if base_case_compare != 0 {
            return base_case_compare.cmp(&0);
        }

        // Same base-name, order by conflict
        let conflict1 = get_conflict_value(dt1_name);
        let conflict2 = get_conflict_value(dt2_name);
        if conflict1 != conflict2 {
            return conflict1.cmp(&conflict2);
        }

        dt1_name.cmp(dt2_name)
    }
}

impl PartialEq for DataTypeNameComparator {
    fn eq(&self, _other: &Self) -> bool {
        true // All instances are equivalent
    }
}

impl Eq for DataTypeNameComparator {}

// ============================================================================
// DataTypeComparator
// ============================================================================

/// Provides the preferred name-based comparison of `DataType` values.
///
/// Port of Ghidra's `DataTypeComparator.java`. Uses `DataTypeNameComparator`
/// for primary name comparison followed by sub-ordering on category path.
#[derive(Debug, Clone, Copy)]
pub struct DataTypeComparator;

impl DataTypeComparator {
    /// The singleton instance.
    pub const INSTANCE: DataTypeComparator = DataTypeComparator;

    /// Compare two data types by name, then by category path.
    pub fn compare(&self, dt1: &dyn DataType, dt2: &dyn DataType) -> Ordering {
        let name_compare = DataTypeNameComparator::INSTANCE.compare(dt1.name(), dt2.name());
        if name_compare == Ordering::Equal {
            // Compare category paths
            let cat1 = dt1.get_category_path().display_name();
            let cat2 = dt2.get_category_path().display_name();
            cat1.cmp(&cat2)
        } else {
            name_compare
        }
    }
}

/// A `std::cmp::Comparator`-style function for comparing `Arc<dyn DataType>`.
pub fn compare_data_types(dt1: &Arc<dyn DataType>, dt2: &Arc<dyn DataType>) -> Ordering {
    DataTypeComparator::INSTANCE.compare(dt1.as_ref(), dt2.as_ref())
}

/// A comparator that sorts data types by name (case-insensitive).
pub fn compare_data_type_names(name1: &str, name2: &str) -> Ordering {
    DataTypeNameComparator::INSTANCE.compare(name1, name2)
}

// ============================================================================
// DataTypeObjectComparator
// ============================================================================

/// An enum wrapper that allows comparing either `DataType` trait objects or name strings.
///
/// Port of Ghidra's `DataTypeObjectComparator.java`.
#[derive(Debug)]
pub enum DataTypeOrName<'a> {
    /// A reference to a DataType.
    Type(&'a dyn DataType),
    /// A bare name string.
    Name(&'a str),
}

impl<'a> DataTypeOrName<'a> {
    /// Get the name from either variant.
    pub fn name(&self) -> &str {
        match self {
            Self::Type(dt) => dt.name(),
            Self::Name(n) => n,
        }
    }

    /// Compare two `DataTypeOrName` values using the name comparator.
    pub fn compare(a: &Self, b: &Self) -> Ordering {
        DataTypeNameComparator::INSTANCE.compare(a.name(), b.name())
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::types::StructureDataType;
    use crate::data::CategoryPath;

    #[test]
    fn test_get_name_without_conflict() {
        assert_eq!(get_name_without_conflict("int"), "int");
        assert_eq!(get_name_without_conflict("int.conflict"), "int");
        assert_eq!(get_name_without_conflict("int.conflict.conflict"), "int.conflict");
    }

    #[test]
    fn test_get_conflict_value() {
        assert_eq!(get_conflict_value("int"), 0);
        assert_eq!(get_conflict_value("int.conflict"), 1);
        assert_eq!(get_conflict_value("int.conflict.conflict"), 2);
    }

    #[test]
    fn test_get_conflict_name() {
        assert_eq!(get_conflict_name("int"), "int.conflict");
        assert_eq!(get_conflict_name("int.conflict"), "int.conflict.conflict");
    }

    #[test]
    fn test_name_comparator_case_insensitive() {
        let cmp = DataTypeNameComparator::INSTANCE;
        assert_eq!(cmp.compare("int", "int"), Ordering::Equal);
        // When lowercase names are equal, case-sensitive comparison applies:
        // 'i' (105) > 'I' (73), so "int" > "Int"
        assert_eq!(cmp.compare("int", "Int"), Ordering::Greater);
        assert_eq!(cmp.compare("byte", "word"), Ordering::Less);
    }

    #[test]
    fn test_name_comparator_conflict_ordering() {
        let cmp = DataTypeNameComparator::INSTANCE;
        assert_eq!(cmp.compare("int", "int.conflict"), Ordering::Less);
        assert_eq!(cmp.compare("int.conflict", "int.conflict.conflict"), Ordering::Less);
    }

    #[test]
    fn test_data_type_comparator() {
        let cmp = DataTypeComparator::INSTANCE;

        let s1 = StructureDataType::new("Alpha");
        let s2 = StructureDataType::new("Beta");

        assert_eq!(cmp.compare(&s1, &s2), Ordering::Less);
        assert_eq!(cmp.compare(&s1, &s1), Ordering::Equal);
    }

    #[test]
    fn test_data_type_comparator_with_category() {
        let cmp = DataTypeComparator::INSTANCE;

        let s1 = StructureDataType::new("MyStruct")
            .with_category_path(CategoryPath::new("a"));
        let s2 = StructureDataType::new("MyStruct")
            .with_category_path(CategoryPath::new("b"));

        assert_eq!(cmp.compare(&s1, &s2), Ordering::Less);
    }

    #[test]
    fn test_data_type_or_name_compare() {
        let a = DataTypeOrName::Name("alpha");
        let b = DataTypeOrName::Name("beta");
        assert_eq!(DataTypeOrName::compare(&a, &b), Ordering::Less);
    }
}
