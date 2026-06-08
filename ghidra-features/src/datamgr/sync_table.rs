// ===========================================================================
// Data Type Sync Table Model -- ported from Ghidra's
// `ghidra.app.plugin.core.datamgr` package.
//
// Additional types that complement the existing `sync` module:
// - DataTypeSyncTableModel      -- table model for sync status display
// - DerivativeDataTypeInfo      -- info about derived data types
// - DuplicateIdException        -- error for duplicate type IDs
// - ArchiveUtils                -- utility functions for archives
//
// Uses `super::sync::DataTypeSyncState` and `super::sync::DataTypeSyncInfo`.
// ===========================================================================


use ghidra_core::Address;
use super::sync::DataTypeSyncState;

// ---------------------------------------------------------------------------
// DataTypeKind
// ---------------------------------------------------------------------------

/// The kind of data type for display in the sync table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DataTypeKind {
    /// Built-in type (int, float, etc.),
    BuiltIn,
    /// Structure type.
    Structure,
    /// Union type.
    Union,
    /// Enum type.
    Enum,
    /// Pointer type.
    Pointer,
    /// Array type.
    Array,
    /// Typedef.
    TypeDef,
    /// Function definition.
    FunctionDefinition,
}

// ---------------------------------------------------------------------------
// DataTypeSyncTableModel
// ---------------------------------------------------------------------------

/// Table model that displays data type synchronization status.
///
/// Ported from `ghidra.app.plugin.core.datamgr.DataTypeSyncTableModel`.
#[derive(Debug, Clone)]
pub struct DataTypeSyncTableModel {
    /// The sync info entries.
    pub entries: Vec<SyncTableEntry>,
    /// Column names.
    pub columns: Vec<String>,
}

/// An entry in the sync table.
#[derive(Debug, Clone)]
pub struct SyncTableEntry {
    /// The data type name.
    pub name: String,
    /// The category path.
    pub category_path: String,
    /// The source archive name.
    pub source_archive: String,
    /// Current sync state.
    pub state: DataTypeSyncState,
    /// The data type kind.
    pub kind: DataTypeKind,
    /// Size in bytes.
    pub size: usize,
}

impl SyncTableEntry {
    /// Create a new sync table entry.
    pub fn new(
        name: impl Into<String>,
        category_path: impl Into<String>,
        source_archive: impl Into<String>,
        state: DataTypeSyncState,
        kind: DataTypeKind,
        size: usize,
    ) -> Self {
        Self {
            name: name.into(),
            category_path: category_path.into(),
            source_archive: source_archive.into(),
            state,
            kind,
            size,
        }
    }

    /// Whether this entry needs user action.
    pub fn needs_action(&self) -> bool {
        !matches!(self.state, DataTypeSyncState::InSync)
    }
}

impl DataTypeSyncTableModel {
    /// Create a new model.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            columns: vec![
                "Name".into(),
                "Category".into(),
                "Source".into(),
                "Status".into(),
                "Kind".into(),
                "Size".into(),
            ],
        }
    }

    /// Add an entry.
    pub fn add_entry(&mut self, entry: SyncTableEntry) {
        self.entries.push(entry);
    }

    /// Get the number of entries.
    pub fn row_count(&self) -> usize {
        self.entries.len()
    }

    /// Get entries that need action.
    pub fn needs_action(&self) -> Vec<&SyncTableEntry> {
        self.entries.iter().filter(|e| e.needs_action()).collect()
    }

    /// Get the cell text for a specific row and column.
    pub fn cell_text(&self, row: usize, col: usize) -> Option<String> {
        self.entries.get(row).map(|entry| match col {
            0 => entry.name.clone(),
            1 => entry.category_path.clone(),
            2 => entry.source_archive.clone(),
            3 => format!("{:?}", entry.state),
            4 => format!("{:?}", entry.kind),
            5 => entry.size.to_string(),
            _ => String::new(),
        })
    }

    /// Clear all entries.
    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

impl Default for DataTypeSyncTableModel {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// DerivativeDataTypeInfo
// ---------------------------------------------------------------------------

/// Information about a data type derived from another type.
///
/// Ported from `ghidra.app.plugin.core.datamgr.DerivativeDataTypeInfo`.
#[derive(Debug, Clone)]
pub struct DerivativeDataTypeInfo {
    /// The derived type name.
    pub name: String,
    /// The base type it was derived from.
    pub base_type_name: String,
    /// The derivation method.
    pub derivation: DerivationMethod,
    /// The address where the derivation is applied.
    pub address: Address,
}

/// How a type was derived.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DerivationMethod {
    /// Pointer to the base type.
    Pointer,
    /// Array of the base type.
    Array,
    /// Typedef of the base type.
    TypeDef,
    /// Subtype/field of a structure.
    SubType,
}

impl DerivativeDataTypeInfo {
    /// Create a new derivative info.
    pub fn new(
        name: impl Into<String>,
        base_type_name: impl Into<String>,
        derivation: DerivationMethod,
        address: Address,
    ) -> Self {
        Self {
            name: name.into(),
            base_type_name: base_type_name.into(),
            derivation,
            address,
        }
    }
}

// ---------------------------------------------------------------------------
// DuplicateIdException
// ---------------------------------------------------------------------------

/// Error for when a data type ID is not unique within a manager.
///
/// Ported from `ghidra.app.plugin.core.datamgr.DuplicateIdException`.
#[derive(Debug, Clone)]
pub struct DuplicateIdException {
    /// The duplicate type ID.
    pub type_id: String,
    /// The existing type name using this ID.
    pub existing_name: String,
    /// The new type name trying to use this ID.
    pub new_name: String,
}

impl DuplicateIdException {
    /// Create a new exception.
    pub fn new(
        type_id: impl Into<String>,
        existing_name: impl Into<String>,
        new_name: impl Into<String>,
    ) -> Self {
        Self {
            type_id: type_id.into(),
            existing_name: existing_name.into(),
            new_name: new_name.into(),
        }
    }

    /// Error message.
    pub fn message(&self) -> String {
        format!(
            "Duplicate data type ID '{}': already used by '{}', cannot add '{}'",
            self.type_id, self.existing_name, self.new_name
        )
    }
}

impl std::fmt::Display for DuplicateIdException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message())
    }
}

impl std::error::Error for DuplicateIdException {}

// ---------------------------------------------------------------------------
// ArchiveUtils
// ---------------------------------------------------------------------------

/// Utility functions for working with data type archives.
///
/// Ported from `ghidra.app.plugin.core.datamgr.ArchiveUtils`.
pub struct ArchiveUtils;

impl ArchiveUtils {
    /// Normalize a category path (ensure leading `/`, no trailing `/`).
    pub fn normalize_category_path(path: &str) -> String {
        let trimmed = path.trim_end_matches('/');
        if trimmed.starts_with('/') {
            trimmed.to_string()
        } else {
            format!("/{}", trimmed)
        }
    }

    /// Split a qualified name into category path and type name.
    pub fn split_qualified_name(qualified: &str) -> (String, String) {
        match qualified.rfind('/') {
            Some(pos) => (
                Self::normalize_category_path(&qualified[..pos]),
                qualified[pos + 1..].to_string(),
            ),
            None => ("/".to_string(), qualified.to_string()),
        }
    }

    /// Check if a category path is a subpath of another.
    pub fn is_subcategory(sub: &str, parent: &str) -> bool {
        let sub_norm = Self::normalize_category_path(sub);
        let parent_norm = Self::normalize_category_path(parent);
        sub_norm.starts_with(&parent_norm)
            && (sub_norm.len() == parent_norm.len()
                || sub_norm.as_bytes().get(parent_norm.len()) == Some(&b'/'))
    }

    /// Generate a unique type ID.
    pub fn generate_type_id() -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        format!("dt_{:x}", ts)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sync_table_model() {
        let mut model = DataTypeSyncTableModel::new();
        model.add_entry(SyncTableEntry::new(
            "MyStruct",
            "/",
            "archive1",
            DataTypeSyncState::InSync,
            DataTypeKind::Structure,
            16,
        ));
        model.add_entry(SyncTableEntry::new(
            "ConflictType",
            "/Types",
            "archive1",
            DataTypeSyncState::Conflict,
            DataTypeKind::Enum,
            4,
        ));
        assert_eq!(model.row_count(), 2);
        assert_eq!(model.needs_action().len(), 1);
        assert_eq!(model.cell_text(1, 0).unwrap(), "ConflictType");
        assert_eq!(model.cell_text(1, 1).unwrap(), "/Types");
    }

    #[test]
    fn test_sync_table_entry_needs_action() {
        let entry = SyncTableEntry::new(
            "A",
            "/",
            "arch",
            DataTypeSyncState::InSync,
            DataTypeKind::BuiltIn,
            4,
        );
        assert!(!entry.needs_action());

        let entry2 = SyncTableEntry::new(
            "B",
            "/",
            "arch",
            DataTypeSyncState::Conflict,
            DataTypeKind::Structure,
            8,
        );
        assert!(entry2.needs_action());
    }

    #[test]
    fn test_duplicate_id_exception() {
        let err = DuplicateIdException::new("dt1", "Existing", "New");
        assert!(err.message().contains("dt1"));
        assert!(err.message().contains("Existing"));
        assert!(err.message().contains("New"));
    }

    #[test]
    fn test_archive_utils_normalize() {
        assert_eq!(ArchiveUtils::normalize_category_path("/Types"), "/Types");
        assert_eq!(ArchiveUtils::normalize_category_path("Types"), "/Types");
        assert_eq!(ArchiveUtils::normalize_category_path("/Types/"), "/Types");
    }

    #[test]
    fn test_archive_utils_split() {
        let (cat, name) = ArchiveUtils::split_qualified_name("/Types/Data/MyStruct");
        assert_eq!(cat, "/Types/Data");
        assert_eq!(name, "MyStruct");

        let (cat2, name2) = ArchiveUtils::split_qualified_name("SimpleType");
        assert_eq!(cat2, "/");
        assert_eq!(name2, "SimpleType");
    }

    #[test]
    fn test_archive_utils_is_subcategory() {
        assert!(ArchiveUtils::is_subcategory("/Types/Data", "/Types"));
        assert!(ArchiveUtils::is_subcategory("/Types", "/Types"));
        assert!(!ArchiveUtils::is_subcategory("/Other", "/Types"));
        assert!(!ArchiveUtils::is_subcategory("/TypesData", "/Types"));
    }

    #[test]
    fn test_generate_type_id() {
        let id = ArchiveUtils::generate_type_id();
        assert!(id.starts_with("dt_"));
    }
}
