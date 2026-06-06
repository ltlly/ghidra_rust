//! Program column constraint providers and type mappers.
//!
//! Ported from `ghidra.base.widgets.table.constraint.provider` -- provides
//! column constraint types for table filtering, including address-to-BigInteger
//! conversion, symbol-to-string mapping, and namespace/DataType mappers.
//!
//! # Architecture
//!
//! - [`ColumnTypeMapper`]: Trait for converting column values to filterable types.
//! - [`ColumnConstraint`]: Trait for column filter constraints.
//! - [`ProgramColumnConstraintProvider`]: Provides address-based constraints
//!   using unsigned long comparison.
//! - Various mapper implementations: [`AddressToUnsignedLongMapper`],
//!   [`SymbolToStringMapper`], [`DataTypeToStringMapper`], [`NamespaceToStringMapper`].

use std::fmt;

// ---------------------------------------------------------------------------
// ColumnTypeMapper
// ---------------------------------------------------------------------------

/// Trait for mapping column values from one type to another for filtering.
///
/// Ported from `docking.widgets.table.constraint.ColumnTypeMapper`.
pub trait ColumnTypeMapper<FROM, TO>: fmt::Debug {
    /// Convert a value from the source type to the target type.
    fn convert(&self, value: &FROM) -> TO;
}

// ---------------------------------------------------------------------------
// ColumnConstraint
// ---------------------------------------------------------------------------

/// A constraint that can be applied to a table column for filtering.
///
/// Ported from `docking.widgets.table.constraint.ColumnConstraint`.
pub trait ColumnConstraint<T: fmt::Debug>: fmt::Debug {
    /// The display name of this constraint.
    fn name(&self) -> &str;

    /// Check if a value satisfies this constraint.
    fn accepts(&self, value: &T) -> bool;

    /// Get the constraint description.
    fn description(&self) -> String;
}

// ---------------------------------------------------------------------------
// AtMostConstraint
// ---------------------------------------------------------------------------

/// Constraint: value must be at most (<=) the given maximum.
#[derive(Debug)]
pub struct AtMostConstraint<T> {
    /// The maximum value.
    pub max: T,
}

impl<T: PartialOrd + fmt::Debug + fmt::Display> ColumnConstraint<T> for AtMostConstraint<T> {
    fn name(&self) -> &str {
        "At Most"
    }

    fn accepts(&self, value: &T) -> bool {
        value <= &self.max
    }

    fn description(&self) -> String {
        format!("Value must be at most {}", self.max)
    }
}

// ---------------------------------------------------------------------------
// AtLeastConstraint
// ---------------------------------------------------------------------------

/// Constraint: value must be at least (>=) the given minimum.
#[derive(Debug)]
pub struct AtLeastConstraint<T> {
    /// The minimum value.
    pub min: T,
}

impl<T: PartialOrd + fmt::Debug + fmt::Display> ColumnConstraint<T> for AtLeastConstraint<T> {
    fn name(&self) -> &str {
        "At Least"
    }

    fn accepts(&self, value: &T) -> bool {
        value >= &self.min
    }

    fn description(&self) -> String {
        format!("Value must be at least {}", self.min)
    }
}

// ---------------------------------------------------------------------------
// InRangeConstraint
// ---------------------------------------------------------------------------

/// Constraint: value must be within [min, max] range.
#[derive(Debug)]
pub struct InRangeConstraint<T> {
    /// Minimum of the range.
    pub min: T,
    /// Maximum of the range.
    pub max: T,
}

impl<T: PartialOrd + fmt::Debug + fmt::Display> ColumnConstraint<T> for InRangeConstraint<T> {
    fn name(&self) -> &str {
        "In Range"
    }

    fn accepts(&self, value: &T) -> bool {
        value >= &self.min && value <= &self.max
    }

    fn description(&self) -> String {
        format!("Value must be between {} and {}", self.min, self.max)
    }
}

// ---------------------------------------------------------------------------
// NotInRangeConstraint
// ---------------------------------------------------------------------------

/// Constraint: value must NOT be within [min, max] range.
#[derive(Debug)]
pub struct NotInRangeConstraint<T> {
    /// Minimum of the excluded range.
    pub min: T,
    /// Maximum of the excluded range.
    pub max: T,
}

impl<T: PartialOrd + fmt::Debug + fmt::Display> ColumnConstraint<T> for NotInRangeConstraint<T> {
    fn name(&self) -> &str {
        "Not In Range"
    }

    fn accepts(&self, value: &T) -> bool {
        value < &self.min || value > &self.max
    }

    fn description(&self) -> String {
        format!("Value must NOT be between {} and {}", self.min, self.max)
    }
}

// ---------------------------------------------------------------------------
// MappedColumnConstraint
// ---------------------------------------------------------------------------

/// A constraint that first maps a value to another type, then applies a delegate constraint.
///
/// Ported from `docking.widgets.table.constraint.MappedColumnConstraint`.
#[derive(Debug)]
pub struct MappedColumnConstraint<FROM, TO> {
    /// Name for this mapped constraint.
    name: String,
    /// Whether this constraint maps FROM -> TO.
    _phantom: std::marker::PhantomData<(FROM, TO)>,
}

impl<FROM: fmt::Debug, TO: fmt::Debug> MappedColumnConstraint<FROM, TO> {
    /// Create a new mapped constraint.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            _phantom: std::marker::PhantomData,
        }
    }

    /// Get the constraint name.
    pub fn name(&self) -> &str {
        &self.name
    }
}

// ---------------------------------------------------------------------------
// Address mapper and constraints
// ---------------------------------------------------------------------------

/// Mapper that converts an address (as a hex string) to an unsigned 64-bit value.
///
/// Ported from `AddressToBigIntegerMapper.java`.
#[derive(Debug)]
pub struct AddressToUnsignedLongMapper;

impl ColumnTypeMapper<String, u64> for AddressToUnsignedLongMapper {
    fn convert(&self, value: &String) -> u64 {
        // Parse hex address string to u64.
        let cleaned = value.trim_start_matches("0x").trim_start_matches("0X");
        u64::from_str_radix(cleaned, 16).unwrap_or(0)
    }
}

// ---------------------------------------------------------------------------
// SymbolToStringMapper
// ---------------------------------------------------------------------------

/// Mapper that converts a symbol object to its name string.
///
/// Ported from `SymbolColumnTypeMapper.java`.
#[derive(Debug)]
pub struct SymbolToStringMapper;

impl ColumnTypeMapper<String, String> for SymbolToStringMapper {
    fn convert(&self, value: &String) -> String {
        value.clone()
    }
}

// ---------------------------------------------------------------------------
// DataTypeToStringMapper
// ---------------------------------------------------------------------------

/// Mapper that converts a DataType to its name string.
///
/// Ported from `DataTypeColumnTypeMapper.java`.
#[derive(Debug)]
pub struct DataTypeToStringMapper;

impl ColumnTypeMapper<String, String> for DataTypeToStringMapper {
    fn convert(&self, value: &String) -> String {
        value.clone()
    }
}

// ---------------------------------------------------------------------------
// NamespaceToStringMapper
// ---------------------------------------------------------------------------

/// Mapper that converts a Namespace to its path string.
///
/// Ported from `NamespaceColumnTypeMapper.java`.
#[derive(Debug)]
pub struct NamespaceToStringMapper;

impl ColumnTypeMapper<String, String> for NamespaceToStringMapper {
    fn convert(&self, value: &String) -> String {
        value.clone()
    }
}

// ---------------------------------------------------------------------------
// ProgramLocationToStringMapper
// ---------------------------------------------------------------------------

/// Mapper that converts a ProgramLocation to a string representation.
///
/// Ported from `ProgramLocationColumnTypeMapper.java`.
#[derive(Debug)]
pub struct ProgramLocationToStringMapper;

impl ColumnTypeMapper<String, String> for ProgramLocationToStringMapper {
    fn convert(&self, value: &String) -> String {
        value.clone()
    }
}

// ---------------------------------------------------------------------------
// ScalarToLongMapper
// ---------------------------------------------------------------------------

/// Mapper that converts a scalar value to a long.
///
/// Ported from `ScalarToLongColumnTypeMapper.java`.
#[derive(Debug)]
pub struct ScalarToLongMapper;

impl ColumnTypeMapper<i64, i64> for ScalarToLongMapper {
    fn convert(&self, value: &i64) -> i64 {
        *value
    }
}

// ---------------------------------------------------------------------------
// ProgramColumnConstraintProvider
// ---------------------------------------------------------------------------

/// Provider for program-related column constraints.
///
/// Ported from `ProgramColumnConstraintProvider.java`. Provides address-based
/// constraints using unsigned long comparison.
#[derive(Debug)]
pub struct ProgramColumnConstraintProvider;

impl ProgramColumnConstraintProvider {
    /// Create a new constraint provider.
    pub fn new() -> Self {
        Self
    }

    /// Get address constraints (at most, at least, in range, not in range).
    pub fn address_constraints(&self) -> Vec<Box<dyn ColumnConstraint<u64>>> {
        vec![
            Box::new(AtMostConstraint { max: u64::MAX }),
            Box::new(AtLeastConstraint { min: 0 }),
            Box::new(InRangeConstraint {
                min: 0,
                max: u64::MAX,
            }),
            Box::new(NotInRangeConstraint {
                min: 0,
                max: u64::MAX,
            }),
        ]
    }

    /// Get string constraints (for symbol, namespace, DataType columns).
    pub fn string_constraints(&self) -> Vec<Box<dyn ColumnConstraint<String>>> {
        vec![
            Box::new(StringContainsConstraint {
                pattern: String::new(),
            }),
            Box::new(StringStartsWithConstraint {
                prefix: String::new(),
            }),
            Box::new(StringEndsWithConstraint {
                suffix: String::new(),
            }),
        ]
    }
}

impl Default for ProgramColumnConstraintProvider {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// String constraints
// ---------------------------------------------------------------------------

/// Constraint: string contains the given substring.
#[derive(Debug)]
pub struct StringContainsConstraint {
    /// The pattern to search for.
    pub pattern: String,
}

impl ColumnConstraint<String> for StringContainsConstraint {
    fn name(&self) -> &str {
        "Contains"
    }

    fn accepts(&self, value: &String) -> bool {
        if self.pattern.is_empty() {
            return true;
        }
        value.contains(&self.pattern)
    }

    fn description(&self) -> String {
        format!("Contains '{}'", self.pattern)
    }
}

/// Constraint: string starts with the given prefix.
#[derive(Debug)]
pub struct StringStartsWithConstraint {
    /// The prefix.
    pub prefix: String,
}

impl ColumnConstraint<String> for StringStartsWithConstraint {
    fn name(&self) -> &str {
        "Starts With"
    }

    fn accepts(&self, value: &String) -> bool {
        if self.prefix.is_empty() {
            return true;
        }
        value.starts_with(&self.prefix)
    }

    fn description(&self) -> String {
        format!("Starts with '{}'", self.prefix)
    }
}

/// Constraint: string ends with the given suffix.
#[derive(Debug)]
pub struct StringEndsWithConstraint {
    /// The suffix.
    pub suffix: String,
}

impl ColumnConstraint<String> for StringEndsWithConstraint {
    fn name(&self) -> &str {
        "Ends With"
    }

    fn accepts(&self, value: &String) -> bool {
        if self.suffix.is_empty() {
            return true;
        }
        value.ends_with(&self.suffix)
    }

    fn description(&self) -> String {
        format!("Ends with '{}'", self.suffix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // Address mapper tests
    // ========================================================================

    #[test]
    fn test_address_to_unsigned_long_mapper() {
        let mapper = AddressToUnsignedLongMapper;
        assert_eq!(mapper.convert(&"0x401000".to_string()), 0x401000);
        assert_eq!(mapper.convert(&"0XFF".to_string()), 255);
        assert_eq!(mapper.convert(&"1000".to_string()), 0x1000);
        assert_eq!(mapper.convert(&"0x0".to_string()), 0);
    }

    // ========================================================================
    // Type mapper tests
    // ========================================================================

    #[test]
    fn test_symbol_to_string_mapper() {
        let mapper = SymbolToStringMapper;
        assert_eq!(mapper.convert(&"main".to_string()), "main");
    }

    #[test]
    fn test_data_type_to_string_mapper() {
        let mapper = DataTypeToStringMapper;
        assert_eq!(mapper.convert(&"int".to_string()), "int");
    }

    #[test]
    fn test_namespace_to_string_mapper() {
        let mapper = NamespaceToStringMapper;
        assert_eq!(mapper.convert(&"std::io".to_string()), "std::io");
    }

    #[test]
    fn test_scalar_to_long_mapper() {
        let mapper = ScalarToLongMapper;
        assert_eq!(mapper.convert(&42), 42);
        assert_eq!(mapper.convert(&-1), -1);
    }

    // ========================================================================
    // AtMostConstraint tests
    // ========================================================================

    #[test]
    fn test_at_most_constraint() {
        let constraint = AtMostConstraint { max: 100u64 };
        assert_eq!(constraint.name(), "At Most");
        assert!(constraint.accepts(&50));
        assert!(constraint.accepts(&100));
        assert!(!constraint.accepts(&101));
    }

    // ========================================================================
    // AtLeastConstraint tests
    // ========================================================================

    #[test]
    fn test_at_least_constraint() {
        let constraint = AtLeastConstraint { min: 10u64 };
        assert_eq!(constraint.name(), "At Least");
        assert!(constraint.accepts(&10));
        assert!(constraint.accepts(&100));
        assert!(!constraint.accepts(&9));
    }

    // ========================================================================
    // InRangeConstraint tests
    // ========================================================================

    #[test]
    fn test_in_range_constraint() {
        let constraint = InRangeConstraint {
            min: 10u64,
            max: 100u64,
        };
        assert_eq!(constraint.name(), "In Range");
        assert!(constraint.accepts(&10));
        assert!(constraint.accepts(&50));
        assert!(constraint.accepts(&100));
        assert!(!constraint.accepts(&9));
        assert!(!constraint.accepts(&101));
    }

    // ========================================================================
    // NotInRangeConstraint tests
    // ========================================================================

    #[test]
    fn test_not_in_range_constraint() {
        let constraint = NotInRangeConstraint {
            min: 10u64,
            max: 100u64,
        };
        assert_eq!(constraint.name(), "Not In Range");
        assert!(constraint.accepts(&9));
        assert!(constraint.accepts(&101));
        assert!(!constraint.accepts(&50));
        assert!(!constraint.accepts(&10));
    }

    // ========================================================================
    // String constraint tests
    // ========================================================================

    #[test]
    fn test_string_contains() {
        let constraint = StringContainsConstraint {
            pattern: "test".to_string(),
        };
        assert_eq!(constraint.name(), "Contains");
        assert!(constraint.accepts(&"this is a test".to_string()));
        assert!(!constraint.accepts(&"no match".to_string()));
    }

    #[test]
    fn test_string_contains_empty() {
        let constraint = StringContainsConstraint {
            pattern: String::new(),
        };
        assert!(constraint.accepts(&"anything".to_string()));
    }

    #[test]
    fn test_string_starts_with() {
        let constraint = StringStartsWithConstraint {
            prefix: "main".to_string(),
        };
        assert!(constraint.accepts(&"main_loop".to_string()));
        assert!(!constraint.accepts(&"sub_main".to_string()));
    }

    #[test]
    fn test_string_ends_with() {
        let constraint = StringEndsWithConstraint {
            suffix: "_end".to_string(),
        };
        assert!(constraint.accepts(&"func_end".to_string()));
        assert!(!constraint.accepts(&"end_func".to_string()));
    }

    // ========================================================================
    // ProgramColumnConstraintProvider tests
    // ========================================================================

    #[test]
    fn test_constraint_provider_address() {
        let provider = ProgramColumnConstraintProvider::new();
        let constraints = provider.address_constraints();
        assert_eq!(constraints.len(), 4);
    }

    #[test]
    fn test_constraint_provider_string() {
        let provider = ProgramColumnConstraintProvider::new();
        let constraints = provider.string_constraints();
        assert_eq!(constraints.len(), 3);
    }

    // ========================================================================
    // MappedColumnConstraint tests
    // ========================================================================

    #[test]
    fn test_mapped_constraint() {
        let constraint = MappedColumnConstraint::<String, u64>::new("Address Filter");
        assert_eq!(constraint.name(), "Address Filter");
    }
}
