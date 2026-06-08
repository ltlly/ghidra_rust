//! Additional data-type find actions -- ported from
//! `ghidra.app.plugin.core.datamgr.actions`.
//!
//! These actions search the data type manager for structures by
//! offset/size, enums by value, and data types by various criteria.
//! They are invoked from the Data Type Manager's search menu and
//! produce filtered results in a secondary tree view.
//!
//! # Actions ported
//!
//! | Rust struct | Java class |
//! |---|---|
//! | `FindStructuresByOffsetAction` | `FindStructuresByOffsetAction` |
//! | `FindStructuresBySizeAction` | `FindStructuresBySizeAction` |
//! | `FindEnumsByValueAction` | `FindEnumsByValueAction` |
//! | `FindBaseDataTypeAction` | `FindBaseDataTypeAction` |
//! | `ApplyFunctionDataTypesAction` | `ApplyFunctionDataTypesAction` |
//! | `ApplyEnumsAsLabelsAction` | `ApplyEnumsAsLabelsAction` |


// ---------------------------------------------------------------------------
// Structure offset match
// ---------------------------------------------------------------------------

/// Result of matching a structure against a set of offsets.
///
/// Ported from the inner `OffsetGTreeFilter` logic in
/// `FindStructuresByOffsetAction`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructureOffsetMatch {
    /// Name of the structure type.
    pub structure_name: String,
    /// The offsets within the structure that matched the query.
    pub matched_offsets: Vec<u32>,
}

impl StructureOffsetMatch {
    /// Create a new match result.
    pub fn new(structure_name: impl Into<String>, matched_offsets: Vec<u32>) -> Self {
        Self {
            structure_name: structure_name.into(),
            matched_offsets,
        }
    }

    /// Number of matched offsets.
    pub fn match_count(&self) -> usize {
        self.matched_offsets.len()
    }
}

/// Describes a single component in a structure for offset matching.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructureComponentInfo {
    /// The component offset within the structure.
    pub offset: u32,
    /// The component's data type name.
    pub type_name: String,
    /// The component field name, if any.
    pub field_name: Option<String>,
}

/// A simplified structure representation for searching.
#[derive(Debug, Clone)]
pub struct StructureInfo {
    /// The structure name.
    pub name: String,
    /// The structure's components, ordered by offset.
    pub components: Vec<StructureComponentInfo>,
}

impl StructureInfo {
    /// Create a new structure info.
    pub fn new(name: impl Into<String>, components: Vec<StructureComponentInfo>) -> Self {
        Self {
            name: name.into(),
            components,
        }
    }

    /// Returns all offsets within this structure.
    pub fn offsets(&self) -> Vec<u32> {
        self.components.iter().map(|c| c.offset).collect()
    }

    /// Check whether any component offset falls within the given ranges.
    ///
    /// `ranges` is a sorted list of `(min, max)` inclusive ranges.
    pub fn has_offset_in_ranges(&self, ranges: &[(u32, u32)]) -> Option<StructureOffsetMatch> {
        let mut matched = Vec::new();
        for comp in &self.components {
            let mut found = false;
            for &(lo, hi) in ranges {
                if comp.offset < lo {
                    // Component is before this range. Since ranges are
                    // sorted, skip to next range.
                    continue;
                }
                if comp.offset > hi {
                    // Component is past this range, but a later range
                    // might still match. Continue checking.
                    continue;
                }
                // comp.offset is in [lo, hi]
                found = true;
                break;
            }
            if found {
                matched.push(comp.offset);
            }
        }
        if matched.is_empty() {
            None
        } else {
            Some(StructureOffsetMatch::new(&self.name, matched))
        }
    }
}

// ---------------------------------------------------------------------------
// FindStructuresByOffset
// ---------------------------------------------------------------------------

/// Search for structures that contain components at the given offsets.
///
/// Ported from `FindStructuresByOffsetAction`.
pub struct FindStructuresByOffset;

impl FindStructuresByOffset {
    /// Search for structures matching any of the given offsets.
    ///
    /// `structures` is the set of structures to search.
    /// `offsets` is a sorted list of `(min, max)` inclusive ranges.
    pub fn search(
        structures: &[StructureInfo],
        offsets: &[(u32, u32)],
    ) -> Vec<StructureOffsetMatch> {
        structures
            .iter()
            .filter_map(|s| s.has_offset_in_ranges(offsets))
            .collect()
    }
}

// ---------------------------------------------------------------------------
// FindStructuresBySize
// ---------------------------------------------------------------------------

/// Result of matching a structure by its total size.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructureSizeMatch {
    /// Name of the structure.
    pub structure_name: String,
    /// The total byte size.
    pub total_size: u32,
}

/// Search for structures matching the given size(s).
///
/// Ported from `FindStructuresBySizeAction`.
pub struct FindStructuresBySize;

impl FindStructuresBySize {
    /// Search for structures whose total size is in the given range(s).
    pub fn search(
        structures: &[StructureInfo],
        size_ranges: &[(u32, u32)],
    ) -> Vec<StructureSizeMatch> {
        structures
            .iter()
            .filter_map(|s| {
                let total = s.components.iter().map(|c| c.offset).max().unwrap_or(0);
                for &(lo, hi) in size_ranges {
                    if total >= lo && total <= hi {
                        return Some(StructureSizeMatch {
                            structure_name: s.name.clone(),
                            total_size: total,
                        });
                    }
                }
                None
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Enum value matching
// ---------------------------------------------------------------------------

/// Describes an entry in an enum type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnumEntry {
    /// The entry name.
    pub name: String,
    /// The entry value.
    pub value: i64,
}

/// A simplified enum representation for searching.
#[derive(Debug, Clone)]
pub struct EnumInfo {
    /// The enum name.
    pub name: String,
    /// The enum entries.
    pub entries: Vec<EnumEntry>,
}

impl EnumInfo {
    /// Create a new enum info.
    pub fn new(name: impl Into<String>, entries: Vec<EnumEntry>) -> Self {
        Self {
            name: name.into(),
            entries,
        }
    }

    /// Check whether this enum has an entry with the given value.
    pub fn has_value(&self, value: i64) -> bool {
        self.entries.iter().any(|e| e.value == value)
    }

    /// Get entry names matching a value.
    pub fn entries_with_value(&self, value: i64) -> Vec<&str> {
        self.entries
            .iter()
            .filter(|e| e.value == value)
            .map(|e| e.name.as_str())
            .collect()
    }
}

/// Result of matching an enum by value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnumValueMatch {
    /// The enum name.
    pub enum_name: String,
    /// Entry names that matched.
    pub entry_names: Vec<String>,
}

/// Search for enums containing a specific value.
///
/// Ported from `FindEnumsByValueAction`.
pub struct FindEnumsByValue;

impl FindEnumsByValue {
    /// Search for enums that contain entries with any of the given
    /// values.
    pub fn search(enums: &[EnumInfo], values: &[i64]) -> Vec<EnumValueMatch> {
        enums
            .iter()
            .filter_map(|e| {
                let matched_names: Vec<String> = values
                    .iter()
                    .flat_map(|v| e.entries_with_value(*v))
                    .map(|s| s.to_string())
                    .collect();
                if matched_names.is_empty() {
                    None
                } else {
                    Some(EnumValueMatch {
                        enum_name: e.name.clone(),
                        entry_names: matched_names,
                    })
                }
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// FindBaseDataType
// ---------------------------------------------------------------------------

/// Result of searching for a data type by name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataTypeMatch {
    /// The data type name.
    pub name: String,
    /// The category path (e.g., "/structs").
    pub category_path: String,
    /// The data type manager name.
    pub manager_name: String,
}

/// Search for data types by name across all open managers.
///
/// Ported from `FindBaseDataTypeAction`.
pub struct FindBaseDataType;

impl FindBaseDataType {
    /// Search for data types whose name contains the given substring.
    ///
    /// `data_types` is a list of `(name, category_path, manager_name)`
    /// tuples from all open data type managers.
    pub fn search(
        data_types: &[(String, String, String)],
        name_substring: &str,
        case_sensitive: bool,
    ) -> Vec<DataTypeMatch> {
        let needle = if case_sensitive {
            name_substring.to_string()
        } else {
            name_substring.to_lowercase()
        };

        data_types
            .iter()
            .filter(|(name, _, _)| {
                let haystack = if case_sensitive {
                    name.clone()
                } else {
                    name.to_lowercase()
                };
                haystack.contains(&needle)
            })
            .map(|(name, cat, mgr)| DataTypeMatch {
                name: name.clone(),
                category_path: cat.clone(),
                manager_name: mgr.clone(),
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// ApplyFunctionDataTypes
// ---------------------------------------------------------------------------

/// A data type application from a library archive to a program.
///
/// Ported from `ApplyFunctionDataTypesAction`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataTypeApplication {
    /// The function address in the target program.
    pub function_address: u64,
    /// The data type path being applied.
    pub data_type_path: String,
    /// The source archive name.
    pub source_archive: String,
    /// Whether the application was successful.
    pub applied: bool,
    /// Error message if application failed.
    pub error: Option<String>,
}

/// Applies function data types from an archive to the current program.
///
/// Ported from `ApplyFunctionDataTypesAction`.
pub struct ApplyFunctionDataTypes;

impl ApplyFunctionDataTypes {
    /// Generate applications for the given function address/type pairs.
    ///
    /// Returns a list of [`DataTypeApplication`] records indicating
    /// what would be applied.
    pub fn plan_applications(
        functions: &[(u64, String)],
        source_archive: &str,
    ) -> Vec<DataTypeApplication> {
        functions
            .iter()
            .map(|(addr, dt_path)| DataTypeApplication {
                function_address: *addr,
                data_type_path: dt_path.clone(),
                source_archive: source_archive.to_string(),
                applied: false,
                error: None,
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// ApplyEnumsAsLabels
// ---------------------------------------------------------------------------

/// An enum-label application -- converting enum entry values into
/// named labels at the corresponding addresses.
///
/// Ported from `ApplyEnumsAsLabelsAction`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnumLabelApplication {
    /// The target address (typically the enum value interpreted as an
    /// address offset).
    pub address: u64,
    /// The label name (from the enum entry name).
    pub label_name: String,
    /// The enum name this came from.
    pub enum_name: String,
    /// Whether the application was successful.
    pub applied: bool,
}

/// Applies enum entry values as address labels.
///
/// Ported from `ApplyEnumsAsLabelsAction`.
pub struct ApplyEnumsAsLabels;

impl ApplyEnumsAsLabels {
    /// Plan label applications from enum entries.
    pub fn plan_applications(
        enum_info: &EnumInfo,
        base_address: u64,
    ) -> Vec<EnumLabelApplication> {
        enum_info
            .entries
            .iter()
            .map(|entry| EnumLabelApplication {
                address: base_address.wrapping_add(entry.value as u64),
                label_name: entry.name.clone(),
                enum_name: enum_info.name.clone(),
                applied: false,
            })
            .collect()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -- Structure offset matching --

    fn sample_struct() -> StructureInfo {
        StructureInfo::new(
            "MyStruct",
            vec![
                StructureComponentInfo {
                    offset: 0,
                    type_name: "int".into(),
                    field_name: Some("x".into()),
                },
                StructureComponentInfo {
                    offset: 4,
                    type_name: "char".into(),
                    field_name: Some("c".into()),
                },
                StructureComponentInfo {
                    offset: 8,
                    type_name: "float".into(),
                    field_name: Some("f".into()),
                },
                StructureComponentInfo {
                    offset: 16,
                    type_name: "double".into(),
                    field_name: Some("d".into()),
                },
            ],
        )
    }

    #[test]
    fn test_structure_info_offsets() {
        let s = sample_struct();
        assert_eq!(s.offsets(), vec![0, 4, 8, 16]);
    }

    #[test]
    fn test_find_structures_by_offset_match() {
        let s = sample_struct();
        let ranges = vec![(4, 4), (16, 16)];
        let result = s.has_offset_in_ranges(&ranges);
        assert!(result.is_some());
        let m = result.unwrap();
        assert_eq!(m.matched_offsets, vec![4, 16]);
    }

    #[test]
    fn test_find_structures_by_offset_no_match() {
        let s = sample_struct();
        let ranges = vec![(100, 200)];
        let result = s.has_offset_in_ranges(&ranges);
        assert!(result.is_none());
    }

    #[test]
    fn test_find_structures_by_offset_search() {
        let structs = vec![sample_struct()];
        let ranges = vec![(0, 0), (8, 8)];
        let results = FindStructuresByOffset::search(&structs, &ranges);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].structure_name, "MyStruct");
        assert_eq!(results[0].match_count(), 2);
    }

    #[test]
    fn test_find_structures_by_offset_search_empty() {
        let structs = vec![sample_struct()];
        let ranges = vec![(100, 200)];
        let results = FindStructuresByOffset::search(&structs, &ranges);
        assert!(results.is_empty());
    }

    // -- Structure size matching --

    #[test]
    fn test_find_structures_by_size() {
        let s = sample_struct();
        let structs = vec![s];
        let results = FindStructuresBySize::search(&structs, &[(16, 16)]);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].total_size, 16);
    }

    #[test]
    fn test_find_structures_by_size_no_match() {
        let structs = vec![sample_struct()];
        let results = FindStructuresBySize::search(&structs, &[(100, 200)]);
        assert!(results.is_empty());
    }

    // -- Enum value matching --

    fn sample_enum() -> EnumInfo {
        EnumInfo::new(
            "Color",
            vec![
                EnumEntry {
                    name: "RED".into(),
                    value: 0,
                },
                EnumEntry {
                    name: "GREEN".into(),
                    value: 1,
                },
                EnumEntry {
                    name: "BLUE".into(),
                    value: 2,
                },
                EnumEntry {
                    name: "ALSO_RED".into(),
                    value: 0,
                },
            ],
        )
    }

    #[test]
    fn test_enum_info_has_value() {
        let e = sample_enum();
        assert!(e.has_value(0));
        assert!(e.has_value(2));
        assert!(!e.has_value(99));
    }

    #[test]
    fn test_enum_info_entries_with_value() {
        let e = sample_enum();
        let entries = e.entries_with_value(0);
        assert_eq!(entries, vec!["RED", "ALSO_RED"]);
    }

    #[test]
    fn test_find_enums_by_value() {
        let enums = vec![sample_enum()];
        let results = FindEnumsByValue::search(&enums, &[0]);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].enum_name, "Color");
        assert_eq!(results[0].entry_names, vec!["RED", "ALSO_RED"]);
    }

    #[test]
    fn test_find_enums_by_value_no_match() {
        let enums = vec![sample_enum()];
        let results = FindEnumsByValue::search(&enums, &[999]);
        assert!(results.is_empty());
    }

    // -- FindBaseDataType --

    #[test]
    fn test_find_base_data_type_case_sensitive() {
        let types = vec![
            ("MyStruct".into(), "/structs".into(), "Program".into()),
            ("mystruct".into(), "/other".into(), "Archive".into()),
            ("OtherType".into(), "/".into(), "Program".into()),
        ];
        let results = FindBaseDataType::search(&types, "MyStruct", true);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "MyStruct");
    }

    #[test]
    fn test_find_base_data_type_case_insensitive() {
        let types = vec![
            ("MyStruct".into(), "/structs".into(), "Program".into()),
            ("mystruct".into(), "/other".into(), "Archive".into()),
            ("OtherType".into(), "/".into(), "Program".into()),
        ];
        let results = FindBaseDataType::search(&types, "mystruct", false);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_find_base_data_type_no_match() {
        let types = vec![("Foo".into(), "/".into(), "P".into())];
        let results = FindBaseDataType::search(&types, "Bar", true);
        assert!(results.is_empty());
    }

    // -- ApplyFunctionDataTypes --

    #[test]
    fn test_apply_function_data_types_plan() {
        let funcs = vec![
            (0x401000, "/structs/MyStruct".into()),
            (0x402000, "/other/OtherType".into()),
        ];
        let apps = ApplyFunctionDataTypes::plan_applications(&funcs, "MyArchive");
        assert_eq!(apps.len(), 2);
        assert_eq!(apps[0].function_address, 0x401000);
        assert_eq!(apps[0].source_archive, "MyArchive");
        assert!(!apps[0].applied);
    }

    // -- ApplyEnumsAsLabels --

    #[test]
    fn test_apply_enums_as_labels_plan() {
        let e = EnumInfo::new(
            "Flags",
            vec![
                EnumEntry {
                    name: "FLAG_A".into(),
                    value: 0x10,
                },
                EnumEntry {
                    name: "FLAG_B".into(),
                    value: 0x20,
                },
            ],
        );
        let apps = ApplyEnumsAsLabels::plan_applications(&e, 0x10000);
        assert_eq!(apps.len(), 2);
        assert_eq!(apps[0].address, 0x10010);
        assert_eq!(apps[0].label_name, "FLAG_A");
        assert_eq!(apps[1].address, 0x10020);
        assert_eq!(apps[1].label_name, "FLAG_B");
        assert!(!apps[0].applied);
    }

    #[test]
    fn test_apply_enums_as_labels_empty() {
        let e = EnumInfo::new("Empty", vec![]);
        let apps = ApplyEnumsAsLabels::plan_applications(&e, 0);
        assert!(apps.is_empty());
    }

    // -- StructureOffsetMatch --

    #[test]
    fn test_structure_offset_match_count() {
        let m = StructureOffsetMatch::new("S", vec![0, 4, 8]);
        assert_eq!(m.match_count(), 3);
    }
}
