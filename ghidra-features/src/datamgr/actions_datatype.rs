//! Data type specific actions for the data type manager.
//!
//! Ported from individual action classes in
//! `ghidra.app.plugin.core.datamgr.actions`:
//!
//! - [`ApplyEnumsAsLabelsAction`] -- apply enum values as labels at addresses
//! - [`CaptureFunctionDataTypesAction`] -- capture data types from function
//!   signatures into the data type manager
//! - [`CreateEnumFromSelectionAction`] -- create an enum from selected values
//! - [`FindEnumsByValueAction`] -- find enums that contain a specific value

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// ApplyEnumsAsLabelsAction
// ---------------------------------------------------------------------------

/// Action to apply enum constant values as labels at addresses in the
/// program listing.
///
/// When an enum is applied to a data location, the value at that
/// location determines which enum constant matches.  This action
/// creates a label at each address where an enum constant value is
/// used, using the constant name as the label text.
///
/// Ported from `ghidra.app.plugin.core.datamgr.actions.ApplyEnumsAsLabelsAction`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplyEnumsAsLabelsAction {
    /// The data type path of the enum to apply.
    pub enum_path: String,
    /// The namespace to place labels in (empty = default).
    pub namespace: String,
    /// Whether to overwrite existing labels.
    pub overwrite_existing: bool,
    /// The addresses where the enum values appear.
    pub addresses: Vec<u64>,
}

impl ApplyEnumsAsLabelsAction {
    /// Create a new action for applying enum values as labels.
    pub fn new(enum_path: impl Into<String>) -> Self {
        Self {
            enum_path: enum_path.into(),
            namespace: String::new(),
            overwrite_existing: false,
            addresses: Vec::new(),
        }
    }

    /// Set the namespace for the labels.
    pub fn with_namespace(mut self, namespace: impl Into<String>) -> Self {
        self.namespace = namespace.into();
        self
    }

    /// Whether to overwrite existing labels.
    pub fn set_overwrite_existing(&mut self, overwrite: bool) {
        self.overwrite_existing = overwrite;
    }

    /// Add an address where an enum value appears.
    pub fn add_address(&mut self, address: u64) {
        self.addresses.push(address);
    }

    /// Add multiple addresses.
    pub fn add_addresses(&mut self, addresses: &[u64]) {
        self.addresses.extend_from_slice(addresses);
    }

    /// Whether this action has work to do.
    pub fn has_work(&self) -> bool {
        !self.addresses.is_empty()
    }
}

// ---------------------------------------------------------------------------
// CaptureFunctionDataTypesAction
// ---------------------------------------------------------------------------

/// Action to capture data types from function signatures into the
/// data type manager.
///
/// When analyzing a program, functions may have parameter and return
/// types that are not yet tracked in the data type manager.  This
/// action extracts those types and creates corresponding entries in
/// the appropriate data type category.
///
/// Ported from `ghidra.app.plugin.core.datamgr.actions.CaptureFunctionDataTypesAction`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureFunctionDataTypesAction {
    /// The category path to store captured types in.
    pub target_category: String,
    /// The function entry points to capture types from.
    pub function_addresses: Vec<u64>,
    /// Whether to also capture parameter types.
    pub capture_parameters: bool,
    /// Whether to also capture return types.
    pub capture_return_types: bool,
    /// Whether to overwrite existing types with the same name.
    pub overwrite_existing: bool,
}

impl CaptureFunctionDataTypesAction {
    /// Create a new capture action.
    pub fn new(target_category: impl Into<String>) -> Self {
        Self {
            target_category: target_category.into(),
            function_addresses: Vec::new(),
            capture_parameters: true,
            capture_return_types: true,
            overwrite_existing: false,
        }
    }

    /// Add a function address to capture types from.
    pub fn add_function(&mut self, address: u64) {
        self.function_addresses.push(address);
    }

    /// Whether to capture parameter types.
    pub fn set_capture_parameters(&mut self, capture: bool) {
        self.capture_parameters = capture;
    }

    /// Whether to capture return types.
    pub fn set_capture_return_types(&mut self, capture: bool) {
        self.capture_return_types = capture;
    }

    /// Whether there are functions to process.
    pub fn has_functions(&self) -> bool {
        !self.function_addresses.is_empty()
    }
}

// ---------------------------------------------------------------------------
// CreateEnumFromSelectionAction
// ---------------------------------------------------------------------------

/// Action to create a new enum data type from a selection of values.
///
/// This is typically invoked when the user selects a range of values
/// (e.g., in a table or listing) and wants to define an enum whose
/// constants correspond to those values.
///
/// Ported from `ghidra.app.plugin.core.datamgr.actions.CreateEnumFromSelectionAction`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateEnumFromSelectionAction {
    /// The name for the new enum.
    pub enum_name: String,
    /// The category path for the new enum.
    pub category_path: String,
    /// The selected values (value, optional name pairs).
    pub values: Vec<EnumValueEntry>,
    /// The bit width of the enum (8, 16, 32, 64).
    pub bit_width: u32,
}

/// A single value entry for enum creation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnumValueEntry {
    /// The numeric value.
    pub value: i64,
    /// An optional name for this constant.
    pub name: Option<String>,
}

impl EnumValueEntry {
    /// Create a new entry with just a value.
    pub fn new(value: i64) -> Self {
        Self { value, name: None }
    }

    /// Create a new entry with a value and name.
    pub fn with_name(value: i64, name: impl Into<String>) -> Self {
        Self {
            value,
            name: Some(name.into()),
        }
    }
}

impl CreateEnumFromSelectionAction {
    /// Create a new action for creating an enum from selected values.
    pub fn new(
        enum_name: impl Into<String>,
        category_path: impl Into<String>,
    ) -> Self {
        Self {
            enum_name: enum_name.into(),
            category_path: category_path.into(),
            values: Vec::new(),
            bit_width: 32,
        }
    }

    /// Add a value to the enum.
    pub fn add_value(&mut self, value: i64) {
        self.values.push(EnumValueEntry::new(value));
    }

    /// Add a named value to the enum.
    pub fn add_named_value(&mut self, value: i64, name: impl Into<String>) {
        self.values.push(EnumValueEntry::with_name(value, name));
    }

    /// Set the bit width for the enum.
    pub fn set_bit_width(&mut self, width: u32) {
        self.bit_width = width;
    }

    /// Whether there are values to create the enum from.
    pub fn has_values(&self) -> bool {
        !self.values.is_empty()
    }

    /// Get the minimum value in the selection.
    pub fn min_value(&self) -> Option<i64> {
        self.values.iter().map(|e| e.value).min()
    }

    /// Get the maximum value in the selection.
    pub fn max_value(&self) -> Option<i64> {
        self.values.iter().map(|e| e.value).max()
    }
}

// ---------------------------------------------------------------------------
// FindEnumsByValueAction
// ---------------------------------------------------------------------------

/// Action to find all enums in the data type manager that contain a
/// constant with a specific numeric value.
///
/// Ported from `ghidra.app.plugin.core.datamgr.actions.FindEnumsByValueAction`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindEnumsByValueAction {
    /// The value to search for.
    pub search_value: i64,
    /// Whether to search only in the program's data type manager.
    pub program_only: bool,
    /// Whether to also search loaded archives.
    pub include_archives: bool,
}

impl FindEnumsByValueAction {
    /// Create a new find-by-value action.
    pub fn new(search_value: i64) -> Self {
        Self {
            search_value,
            program_only: false,
            include_archives: true,
        }
    }

    /// Restrict search to the program's data type manager only.
    pub fn set_program_only(&mut self, program_only: bool) {
        self.program_only = program_only;
    }

    /// Whether to include archives in the search.
    pub fn set_include_archives(&mut self, include: bool) {
        self.include_archives = include;
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_apply_enums_as_labels_action() {
        let mut action = ApplyEnumsAsLabelsAction::new("/MyEnum");
        assert!(!action.has_work());
        assert_eq!(action.enum_path, "/MyEnum");

        action.add_address(0x400000);
        action.add_address(0x400004);
        assert!(action.has_work());
        assert_eq!(action.addresses.len(), 2);
    }

    #[test]
    fn test_apply_enums_with_namespace() {
        let action = ApplyEnumsAsLabelsAction::new("/MyEnum")
            .with_namespace("MyNamespace");
        assert_eq!(action.namespace, "MyNamespace");
    }

    #[test]
    fn test_apply_enums_overwrite() {
        let mut action = ApplyEnumsAsLabelsAction::new("/MyEnum");
        assert!(!action.overwrite_existing);
        action.set_overwrite_existing(true);
        assert!(action.overwrite_existing);
    }

    #[test]
    fn test_apply_enums_add_addresses() {
        let mut action = ApplyEnumsAsLabelsAction::new("/MyEnum");
        action.add_addresses(&[0x1000, 0x2000, 0x3000]);
        assert_eq!(action.addresses.len(), 3);
    }

    #[test]
    fn test_capture_function_data_types_action() {
        let mut action = CaptureFunctionDataTypesAction::new("/Functions");
        assert!(!action.has_functions());
        action.add_function(0x400000);
        action.add_function(0x400100);
        assert!(action.has_functions());
        assert_eq!(action.function_addresses.len(), 2);
    }

    #[test]
    fn test_capture_function_setters() {
        let mut action = CaptureFunctionDataTypesAction::new("/Functions");
        assert!(action.capture_parameters);
        assert!(action.capture_return_types);

        action.set_capture_parameters(false);
        assert!(!action.capture_parameters);

        action.set_capture_return_types(false);
        assert!(!action.capture_return_types);
    }

    #[test]
    fn test_create_enum_from_selection_action() {
        let mut action = CreateEnumFromSelectionAction::new("MyEnum", "/Custom");
        assert!(!action.has_values());

        action.add_value(0);
        action.add_value(1);
        action.add_named_value(2, "VALUE_THREE");
        assert!(action.has_values());
        assert_eq!(action.values.len(), 3);
    }

    #[test]
    fn test_create_enum_min_max() {
        let mut action = CreateEnumFromSelectionAction::new("MyEnum", "/Custom");
        action.add_value(10);
        action.add_value(5);
        action.add_value(20);
        assert_eq!(action.min_value(), Some(5));
        assert_eq!(action.max_value(), Some(20));
    }

    #[test]
    fn test_create_enum_bit_width() {
        let mut action = CreateEnumFromSelectionAction::new("MyEnum", "/Custom");
        assert_eq!(action.bit_width, 32);
        action.set_bit_width(16);
        assert_eq!(action.bit_width, 16);
    }

    #[test]
    fn test_enum_value_entry() {
        let entry = EnumValueEntry::new(42);
        assert_eq!(entry.value, 42);
        assert!(entry.name.is_none());

        let named = EnumValueEntry::with_name(42, "ANSWER");
        assert_eq!(named.value, 42);
        assert_eq!(named.name.as_deref(), Some("ANSWER"));
    }

    #[test]
    fn test_find_enums_by_value_action() {
        let action = FindEnumsByValueAction::new(0xFF);
        assert_eq!(action.search_value, 0xFF);
        assert!(!action.program_only);
        assert!(action.include_archives);
    }

    #[test]
    fn test_find_enums_setters() {
        let mut action = FindEnumsByValueAction::new(0);
        action.set_program_only(true);
        assert!(action.program_only);
        action.set_include_archives(false);
        assert!(!action.include_archives);
    }

    #[test]
    fn test_create_enum_empty_min_max() {
        let action = CreateEnumFromSelectionAction::new("empty", "/Custom");
        assert!(action.min_value().is_none());
        assert!(action.max_value().is_none());
    }
}
