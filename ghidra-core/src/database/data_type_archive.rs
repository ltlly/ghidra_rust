//! Data type archive database ported from Java's `DataTypeArchiveDB`,
//! `DataTypeManagerDB`, `ProgramDataTypeManager`, and `ProjectDataTypeManager`.
//!
//! Provides the data type manager hierarchy that stores, resolves, and
//! manages data types in the Ghidra database.

use crate::database::db::{Database, DbResult};
use crate::database::manager_db::{ManagerDB, OpenMode, ProgramContext};
use crate::database::program_change_set::DataTypeArchiveDBChangeSet;
use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, RwLock};

// ============================================================================
// DataTypeId — unique data type identifier
// ============================================================================

/// A unique identifier for a data type within a manager.
pub type DataTypeId = i64;

// ============================================================================
// DataTypeEntry (port of Java DataTypeDB entry)
// ============================================================================

/// A stored data type entry in the archive.
#[derive(Debug, Clone)]
pub struct DataTypeEntry {
    /// Unique ID.
    pub id: DataTypeId,
    /// Category path (e.g., "/Pointer", "/MyStructs").
    pub category_path: String,
    /// The data type name.
    pub name: String,
    /// Source archive UUID (empty for local types).
    pub source_archive_id: String,
    /// The data type's universal ID (UUID-like).
    pub universal_id: String,
    /// Whether this type was last modified in this archive.
    pub last_changed_timestamp: u64,
    /// Serialized data type definition.
    pub data: Vec<u8>,
}

impl DataTypeEntry {
    /// Create a new data type entry.
    pub fn new(
        id: DataTypeId,
        category_path: &str,
        name: &str,
    ) -> Self {
        Self {
            id,
            category_path: category_path.to_string(),
            name: name.to_string(),
            source_archive_id: String::new(),
            universal_id: String::new(),
            last_changed_timestamp: 0,
            data: Vec::new(),
        }
    }

    /// Full path including category and name.
    pub fn full_path(&self) -> String {
        if self.category_path.ends_with('/') {
            format!("{}{}", self.category_path, self.name)
        } else {
            format!("{}/{}", self.category_path, self.name)
        }
    }
}

// ============================================================================
// CategoryEntry
// ============================================================================

/// A stored category (folder) in the data type archive.
#[derive(Debug, Clone)]
pub struct CategoryEntry {
    /// Unique ID.
    pub id: DataTypeId,
    /// Parent category ID (0 for root).
    pub parent_id: DataTypeId,
    /// Category name.
    pub name: String,
}

impl CategoryEntry {
    /// Create a new category entry.
    pub fn new(id: DataTypeId, parent_id: DataTypeId, name: &str) -> Self {
        Self {
            id,
            parent_id,
            name: name.to_string(),
        }
    }
}

// ============================================================================
// SourceArchiveEntry
// ============================================================================

/// Information about a source archive linked to this data type manager.
#[derive(Debug, Clone)]
pub struct SourceArchiveEntry {
    /// Unique ID in this manager.
    pub id: DataTypeId,
    /// The archive's universal ID.
    pub archive_id: String,
    /// File path or URL to the archive.
    pub domain_file_path: String,
    /// Timestamp of last sync.
    pub last_sync_timestamp: u64,
}

// ============================================================================
// DataTypeManagerDB (port of Java DataTypeManagerDB)
// ============================================================================

/// Database-backed data type manager.
///
/// Port of Java `ghidra.program.database.data.DataTypeManagerDB`.
///
/// Manages the complete lifecycle of data types: creation, modification,
/// deletion, category organization, and source archive tracking.
#[derive(Debug)]
pub struct DataTypeManagerDB {
    /// Unique manager ID.
    manager_id: u64,
    /// Data types keyed by ID.
    data_types: HashMap<DataTypeId, DataTypeEntry>,
    /// Categories keyed by ID.
    categories: HashMap<DataTypeId, CategoryEntry>,
    /// Source archives keyed by ID.
    source_archives: HashMap<DataTypeId, SourceArchiveEntry>,
    /// Monotonic ID counter.
    next_id: AtomicI64,
    /// Name of the data type manager (e.g., program name).
    name: String,
    /// Change set for tracking modifications.
    change_set: DataTypeArchiveDBChangeSet,
    /// Whether a transaction is currently active.
    in_transaction: bool,
}

impl DataTypeManagerDB {
    /// Create a new empty data type manager.
    pub fn new(manager_id: u64, name: &str) -> Self {
        let mut categories = HashMap::new();
        // Create root category.
        categories.insert(
            0,
            CategoryEntry {
                id: 0,
                parent_id: -1,
                name: "/".to_string(),
            },
        );
        Self {
            manager_id,
            data_types: HashMap::new(),
            categories,
            source_archives: HashMap::new(),
            next_id: AtomicI64::new(1),
            name: name.to_string(),
            change_set: DataTypeArchiveDBChangeSet::new(4),
            in_transaction: false,
        }
    }

    /// Get the manager ID.
    pub fn manager_id(&self) -> u64 {
        self.manager_id
    }

    /// Get the manager name.
    pub fn name(&self) -> &str {
        &self.name
    }

    // ---- Data type CRUD ----

    /// Add a new data type. Returns the assigned ID.
    pub fn add_data_type(
        &mut self,
        category_path: &str,
        name: &str,
        data: Vec<u8>,
    ) -> DataTypeId {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let mut entry = DataTypeEntry::new(id, category_path, name);
        entry.data = data;
        self.data_types.insert(id, entry);
        if self.in_transaction {
            self.change_set.data_type_added(id);
        }
        id
    }

    /// Get a data type by ID.
    pub fn get_data_type(&self, id: DataTypeId) -> Option<&DataTypeEntry> {
        self.data_types.get(&id)
    }

    /// Get a data type by full path (category + name).
    pub fn get_data_type_by_path(&self, category_path: &str, name: &str) -> Option<&DataTypeEntry> {
        self.data_types.values().find(|dt| {
            dt.category_path == category_path && dt.name == name
        })
    }

    /// Remove a data type. Returns the removed entry if present.
    pub fn remove_data_type(&mut self, id: DataTypeId) -> Option<DataTypeEntry> {
        let result = self.data_types.remove(&id);
        if result.is_some() && self.in_transaction {
            self.change_set.data_type_changed(id);
        }
        result
    }

    /// Replace the data bytes of an existing data type.
    pub fn replace_data_type(&mut self, id: DataTypeId, data: Vec<u8>) -> bool {
        if let Some(entry) = self.data_types.get_mut(&id) {
            entry.data = data;
            entry.last_changed_timestamp += 1;
            if self.in_transaction {
                self.change_set.data_type_changed(id);
            }
            true
        } else {
            false
        }
    }

    /// Return the total number of data types.
    pub fn data_type_count(&self) -> usize {
        self.data_types.len()
    }

    /// Iterate over all data types.
    pub fn iter_data_types(&self) -> impl Iterator<Item = &DataTypeEntry> {
        self.data_types.values()
    }

    /// Find data types whose name matches the given string.
    pub fn find_data_types(&self, name: &str) -> Vec<&DataTypeEntry> {
        self.data_types.values().filter(|dt| dt.name == name).collect()
    }

    // ---- Category management ----

    /// Create a new category. Returns the assigned ID.
    pub fn create_category(&mut self, parent_id: DataTypeId, name: &str) -> DataTypeId {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.categories
            .insert(id, CategoryEntry::new(id, parent_id, name));
        if self.in_transaction {
            self.change_set.category_added(id);
        }
        id
    }

    /// Get a category by ID.
    pub fn get_category(&self, id: DataTypeId) -> Option<&CategoryEntry> {
        self.categories.get(&id)
    }

    /// Return the total number of categories (including root).
    pub fn category_count(&self) -> usize {
        self.categories.len()
    }

    /// Iterate over all categories.
    pub fn iter_categories(&self) -> impl Iterator<Item = &CategoryEntry> {
        self.categories.values()
    }

    // ---- Source archive management ----

    /// Add a source archive reference.
    pub fn add_source_archive(&mut self, entry: SourceArchiveEntry) -> DataTypeId {
        let id = entry.id;
        self.source_archives.insert(id, entry);
        if self.in_transaction {
            self.change_set.source_archive_added(id);
        }
        id
    }

    /// Get a source archive by ID.
    pub fn get_source_archive(&self, id: DataTypeId) -> Option<&SourceArchiveEntry> {
        self.source_archives.get(&id)
    }

    /// Return the number of source archives.
    pub fn source_archive_count(&self) -> usize {
        self.source_archives.len()
    }

    // ---- Transaction support ----

    /// Start a data type transaction.
    pub fn start_transaction(&mut self) {
        self.change_set.start_transaction();
        self.in_transaction = true;
    }

    /// End the current transaction.
    pub fn end_transaction(&mut self, commit: bool) {
        self.in_transaction = false;
        self.change_set.end_transaction(commit);
    }

    /// Get the change set.
    pub fn change_set(&self) -> &DataTypeArchiveDBChangeSet {
        &self.change_set
    }

    /// Get the change set (mutable).
    pub fn change_set_mut(&mut self) -> &mut DataTypeArchiveDBChangeSet {
        &mut self.change_set
    }
}

// ============================================================================
// ProgramDataTypeManager (port of Java ProgramDataTypeManager)
// ============================================================================

/// A data type manager that is bound to a specific program.
///
/// Port of Java `ghidra.program.database.data.ProgramDataTypeManager`.
///
/// Adds program-specific features: unique archive ID, source archive
/// tracking, and the ability to associate types with the program's address
/// space.
#[derive(Debug)]
pub struct ProgramDataTypeManager {
    inner: DataTypeManagerDB,
    /// Unique archive UUID for this program.
    archive_uuid: String,
}

impl ProgramDataTypeManager {
    /// Create a new program data type manager.
    pub fn new(manager_id: u64, name: &str, archive_uuid: &str) -> Self {
        Self {
            inner: DataTypeManagerDB::new(manager_id, name),
            archive_uuid: archive_uuid.to_string(),
        }
    }

    /// Get the archive UUID.
    pub fn archive_uuid(&self) -> &str {
        &self.archive_uuid
    }

    /// Get the inner data type manager.
    pub fn inner(&self) -> &DataTypeManagerDB {
        &self.inner
    }

    /// Get the inner data type manager (mutable).
    pub fn inner_mut(&mut self) -> &mut DataTypeManagerDB {
        &mut self.inner
    }
}

impl fmt::Display for ProgramDataTypeManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ProgramDataTypeManager(name={}, types={}, uuid={})",
            self.inner.name(),
            self.inner.data_type_count(),
            self.archive_uuid,
        )
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_data_type_manager_basics() {
        let mut mgr = DataTypeManagerDB::new(1, "test");
        assert_eq!(mgr.data_type_count(), 0);
        assert_eq!(mgr.category_count(), 1); // root category

        let id = mgr.add_data_type("/MyTypes", "int", vec![0x01, 0x02]);
        assert_eq!(mgr.data_type_count(), 1);

        let dt = mgr.get_data_type(id).unwrap();
        assert_eq!(dt.name, "int");
        assert_eq!(dt.category_path, "/MyTypes");
        assert_eq!(dt.data, vec![0x01, 0x02]);
    }

    #[test]
    fn test_find_data_type_by_path() {
        let mut mgr = DataTypeManagerDB::new(1, "test");
        mgr.add_data_type("/Path", "MyType", vec![]);

        let dt = mgr.get_data_type_by_path("/Path", "MyType");
        assert!(dt.is_some());
        assert_eq!(dt.unwrap().name, "MyType");

        assert!(mgr.get_data_type_by_path("/Path", "Nope").is_none());
    }

    #[test]
    fn test_find_data_types_by_name() {
        let mut mgr = DataTypeManagerDB::new(1, "test");
        mgr.add_data_type("/A", "int", vec![]);
        mgr.add_data_type("/B", "int", vec![]);
        mgr.add_data_type("/C", "float", vec![]);

        let ints = mgr.find_data_types("int");
        assert_eq!(ints.len(), 2);
    }

    #[test]
    fn test_remove_data_type() {
        let mut mgr = DataTypeManagerDB::new(1, "test");
        let id = mgr.add_data_type("/", "temp", vec![]);
        assert_eq!(mgr.data_type_count(), 1);
        mgr.remove_data_type(id);
        assert_eq!(mgr.data_type_count(), 0);
    }

    #[test]
    fn test_category_management() {
        let mut mgr = DataTypeManagerDB::new(1, "test");
        let cat_id = mgr.create_category(0, "SubCat");
        assert_eq!(mgr.category_count(), 2); // root + SubCat

        let cat = mgr.get_category(cat_id).unwrap();
        assert_eq!(cat.name, "SubCat");
        assert_eq!(cat.parent_id, 0);
    }

    #[test]
    fn test_source_archive() {
        let mut mgr = DataTypeManagerDB::new(1, "test");
        let entry = SourceArchiveEntry {
            id: 100,
            archive_id: "uuid-1234".to_string(),
            domain_file_path: "/path/to/archive.gdt".to_string(),
            last_sync_timestamp: 12345,
        };
        mgr.add_source_archive(entry);
        assert_eq!(mgr.source_archive_count(), 1);

        let archive = mgr.get_source_archive(100).unwrap();
        assert_eq!(archive.archive_id, "uuid-1234");
    }

    #[test]
    fn test_transaction_change_tracking() {
        let mut mgr = DataTypeManagerDB::new(1, "test");
        mgr.start_transaction();
        mgr.add_data_type("/", "new_type", vec![]);
        mgr.end_transaction(true);

        assert!(mgr.change_set().has_changes());
        assert_eq!(mgr.change_set().get_data_type_additions().len(), 1);
    }

    #[test]
    fn test_replace_data_type() {
        let mut mgr = DataTypeManagerDB::new(1, "test");
        let id = mgr.add_data_type("/", "mod", vec![1, 2]);
        mgr.replace_data_type(id, vec![3, 4, 5]);

        let dt = mgr.get_data_type(id).unwrap();
        assert_eq!(dt.data, vec![3, 4, 5]);
    }

    #[test]
    fn test_program_data_type_manager() {
        let mut mgr = ProgramDataTypeManager::new(1, "MyProgram", "uuid-5678");
        assert_eq!(mgr.archive_uuid(), "uuid-5678");

        mgr.inner_mut().add_data_type("/", "byte", vec![]);
        assert_eq!(mgr.inner().data_type_count(), 1);
    }
}
