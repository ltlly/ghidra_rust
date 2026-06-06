//! Database-backed data type manager for traces.
//!
//! Ported from Ghidra's `ghidra.trace.database.data.DBTraceDataTypeManager`.
//! Manages data type definitions and categories for a trace, with per-platform
//! support (host vs guest prefix).


use rusqlite::{params, Connection, Result as SqlResult};
use serde::{Deserialize, Serialize};


/// The conflict resolution strategy when adding a data type with an existing path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DataTypeConflictHandler {
    /// Keep the existing type, discard the new one.
    KeepExisting,
    /// Replace the existing type with the new one.
    ReplaceExisting,
    /// Rename the new type to avoid conflict.
    RenameNew,
}

impl Default for DataTypeConflictHandler {
    fn default() -> Self {
        Self::KeepExisting
    }
}

/// A data type category (folder in the type hierarchy).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataTypeCategory {
    /// Category ID.
    pub id: i64,
    /// Parent category ID (None for root).
    pub parent_id: Option<i64>,
    /// Category name.
    pub name: String,
    /// Full category path.
    pub path: String,
}

/// A data type entry stored in the database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataTypeEntry {
    /// Data type ID.
    pub id: i64,
    /// Category ID.
    pub category_id: i64,
    /// The data type name.
    pub name: String,
    /// The full path (category/name).
    pub path: String,
    /// Size in bytes (0 for variable-length types).
    pub size: u32,
    /// Whether this type is a built-in.
    pub is_builtin: bool,
}

/// Database-backed data type manager for a trace.
///
/// Ported from Ghidra's `DBTraceDataTypeManager`. Provides data type
/// and category management, with optional per-platform prefix support
/// for guest platforms.
#[derive(Debug)]
pub struct TraceDataTypeManager<'a> {
    conn: &'a Connection,
    /// The platform prefix for this manager (None for host, Some("GuestN_") for guests).
    prefix: Option<String>,
}

impl<'a> TraceDataTypeManager<'a> {
    /// Create a new data type manager for the host platform.
    pub fn new(conn: &'a Connection) -> SqlResult<Self> {
        let mgr = Self {
            conn,
            prefix: None,
        };
        mgr.create_tables()?;
        Ok(mgr)
    }

    /// Create a new data type manager for a guest platform with the given key.
    pub fn new_for_guest(conn: &'a Connection, guest_key: i64) -> SqlResult<Self> {
        let mgr = Self {
            conn,
            prefix: Some(format!("Guest{}_", guest_key)),
        };
        mgr.create_tables()?;
        Ok(mgr)
    }

    fn table_prefix(&self) -> &str {
        self.prefix.as_deref().unwrap_or("")
    }

    fn create_tables(&self) -> SqlResult<()> {
        let prefix = self.table_prefix();
        self.conn.execute_batch(&format!(
            "
            CREATE TABLE IF NOT EXISTS {prefix}data_type_categories (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                parent_id INTEGER,
                name TEXT NOT NULL,
                path TEXT NOT NULL UNIQUE
            );

            CREATE TABLE IF NOT EXISTS {prefix}data_types (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                category_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                path TEXT NOT NULL UNIQUE,
                size INTEGER NOT NULL DEFAULT 0,
                is_builtin INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY (category_id) REFERENCES {prefix}data_type_categories(id)
            );

            CREATE INDEX IF NOT EXISTS {prefix}idx_dt_path ON {prefix}data_types(path);
            CREATE INDEX IF NOT EXISTS {prefix}idx_cat_path ON {prefix}data_type_categories(path);
            ",
        ))?;

        // Ensure root category exists
        let root_path = "/";
        let count: i64 = self.conn.query_row(
            &format!(
                "SELECT COUNT(*) FROM {prefix}data_type_categories WHERE path = ?1"
            ),
            params![root_path],
            |row| row.get(0),
        )?;
        if count == 0 {
            self.conn.execute(
                &format!(
                    "INSERT INTO {prefix}data_type_categories (parent_id, name, path) VALUES (NULL, '', ?1)"
                ),
                params![root_path],
            )?;
        }

        Ok(())
    }

    /// Get the root category ID.
    pub fn root_category_id(&self) -> SqlResult<i64> {
        let prefix = self.table_prefix();
        self.conn.query_row(
            &format!(
                "SELECT id FROM {prefix}data_type_categories WHERE path = '/'"
            ),
            [],
            |row| row.get(0),
        )
    }

    /// Create a category under a parent.
    pub fn create_category(&self, parent_id: i64, name: &str) -> SqlResult<i64> {
        let prefix = self.table_prefix();
        // Get parent path
        let parent_path: String = self.conn.query_row(
            &format!(
                "SELECT path FROM {prefix}data_type_categories WHERE id = ?1"
            ),
            params![parent_id],
            |row| row.get(0),
        )?;
        let path = if parent_path == "/" {
            format!("/{}", name)
        } else {
            format!("{}/{}", parent_path, name)
        };

        self.conn.execute(
            &format!(
                "INSERT INTO {prefix}data_type_categories (parent_id, name, path) VALUES (?1, ?2, ?3)"
            ),
            params![parent_id, name, path],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Get a category by path.
    pub fn get_category_by_path(&self, path: &str) -> SqlResult<Option<DataTypeCategory>> {
        let prefix = self.table_prefix();
        let mut stmt = self.conn.prepare(&format!(
            "SELECT id, parent_id, name, path FROM {prefix}data_type_categories WHERE path = ?1"
        ))?;
        let mut rows = stmt.query_map(params![path], |row| {
            Ok(DataTypeCategory {
                id: row.get(0)?,
                parent_id: row.get(1)?,
                name: row.get(2)?,
                path: row.get(3)?,
            })
        })?;
        match rows.next() {
            Some(Ok(cat)) => Ok(Some(cat)),
            Some(Err(e)) => Err(e),
            None => Ok(None),
        }
    }

    /// List all categories.
    pub fn list_categories(&self) -> SqlResult<Vec<DataTypeCategory>> {
        let prefix = self.table_prefix();
        let mut stmt = self.conn.prepare(&format!(
            "SELECT id, parent_id, name, path FROM {prefix}data_type_categories ORDER BY path"
        ))?;
        let cats = stmt
            .query_map([], |row| {
                Ok(DataTypeCategory {
                    id: row.get(0)?,
                    parent_id: row.get(1)?,
                    name: row.get(2)?,
                    path: row.get(3)?,
                })
            })?
            .collect::<SqlResult<Vec<_>>>()?;
        Ok(cats)
    }

    /// Add a data type to a category.
    pub fn add_data_type(
        &self,
        category_id: i64,
        name: &str,
        size: u32,
        is_builtin: bool,
        handler: DataTypeConflictHandler,
    ) -> SqlResult<i64> {
        let prefix = self.table_prefix();
        // Get category path
        let cat_path: String = self.conn.query_row(
            &format!(
                "SELECT path FROM {prefix}data_type_categories WHERE id = ?1"
            ),
            params![category_id],
            |row| row.get(0),
        )?;
        let full_path = if cat_path == "/" {
            format!("/{}", name)
        } else {
            format!("{}/{}", cat_path, name)
        };

        // Check for existing
        let existing: Result<i64, _> = self.conn.query_row(
            &format!(
                "SELECT id FROM {prefix}data_types WHERE path = ?1"
            ),
            params![full_path],
            |row| row.get(0),
        );

        if let Ok(existing_id) = existing {
            match handler {
                DataTypeConflictHandler::KeepExisting => return Ok(existing_id),
                DataTypeConflictHandler::ReplaceExisting => {
                    self.conn.execute(
                        &format!("DELETE FROM {prefix}data_types WHERE id = ?1"),
                        params![existing_id],
                    )?;
                }
                DataTypeConflictHandler::RenameNew => {
                    let mut suffix = 1;
                    let mut new_path = format!("{}_{}", full_path, suffix);
                    while self
                        .conn
                        .query_row(
                            &format!(
                                "SELECT COUNT(*) FROM {prefix}data_types WHERE path = ?1"
                            ),
                            params![new_path],
                            |row| row.get::<_, i64>(0),
                        )
                        .unwrap_or(0)
                        > 0
                    {
                        suffix += 1;
                        new_path = format!("{}_{}", full_path, suffix);
                    }
                    // Use the renamed path
                    self.conn.execute(
                        &format!(
                            "INSERT INTO {prefix}data_types (category_id, name, path, size, is_builtin)
                             VALUES (?1, ?2, ?3, ?4, ?5)"
                        ),
                        params![category_id, name, new_path, size, is_builtin as i32],
                    )?;
                    return Ok(self.conn.last_insert_rowid());
                }
            }
        }

        self.conn.execute(
            &format!(
                "INSERT INTO {prefix}data_types (category_id, name, path, size, is_builtin)
                 VALUES (?1, ?2, ?3, ?4, ?5)"
            ),
            params![category_id, name, full_path, size, is_builtin as i32],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Get a data type by path.
    pub fn get_data_type_by_path(&self, path: &str) -> SqlResult<Option<DataTypeEntry>> {
        let prefix = self.table_prefix();
        let mut stmt = self.conn.prepare(&format!(
            "SELECT id, category_id, name, path, size, is_builtin FROM {prefix}data_types WHERE path = ?1"
        ))?;
        let mut rows = stmt.query_map(params![path], |row| {
            Ok(DataTypeEntry {
                id: row.get(0)?,
                category_id: row.get(1)?,
                name: row.get(2)?,
                path: row.get(3)?,
                size: row.get(4)?,
                is_builtin: row.get::<_, i32>(5)? != 0,
            })
        })?;
        match rows.next() {
            Some(Ok(dt)) => Ok(Some(dt)),
            Some(Err(e)) => Err(e),
            None => Ok(None),
        }
    }

    /// List all data types in a category.
    pub fn list_data_types_in_category(
        &self,
        category_id: i64,
    ) -> SqlResult<Vec<DataTypeEntry>> {
        let prefix = self.table_prefix();
        let mut stmt = self.conn.prepare(&format!(
            "SELECT id, category_id, name, path, size, is_builtin FROM {prefix}data_types WHERE category_id = ?1 ORDER BY name"
        ))?;
        let dts = stmt
            .query_map(params![category_id], |row| {
                Ok(DataTypeEntry {
                    id: row.get(0)?,
                    category_id: row.get(1)?,
                    name: row.get(2)?,
                    path: row.get(3)?,
                    size: row.get(4)?,
                    is_builtin: row.get::<_, i32>(5)? != 0,
                })
            })?
            .collect::<SqlResult<Vec<_>>>()?;
        Ok(dts)
    }

    /// Delete a data type by ID.
    pub fn delete_data_type(&self, id: i64) -> SqlResult<bool> {
        let prefix = self.table_prefix();
        let count = self.conn.execute(
            &format!("DELETE FROM {prefix}data_types WHERE id = ?1"),
            params![id],
        )?;
        Ok(count > 0)
    }

    /// Delete a category by ID (must be empty).
    pub fn delete_category(&self, id: i64) -> SqlResult<bool> {
        let prefix = self.table_prefix();
        // Check for child categories
        let child_count: i64 = self.conn.query_row(
            &format!(
                "SELECT COUNT(*) FROM {prefix}data_type_categories WHERE parent_id = ?1"
            ),
            params![id],
            |row| row.get(0),
        )?;
        if child_count > 0 {
            return Ok(false);
        }
        // Check for data types in this category
        let dt_count: i64 = self.conn.query_row(
            &format!(
                "SELECT COUNT(*) FROM {prefix}data_types WHERE category_id = ?1"
            ),
            params![id],
            |row| row.get(0),
        )?;
        if dt_count > 0 {
            return Ok(false);
        }
        let count = self.conn.execute(
            &format!("DELETE FROM {prefix}data_type_categories WHERE id = ?1"),
            params![id],
        )?;
        Ok(count > 0)
    }

    /// Count all data types.
    pub fn data_type_count(&self) -> SqlResult<usize> {
        let prefix = self.table_prefix();
        self.conn.query_row(
            &format!("SELECT COUNT(*) FROM {prefix}data_types"),
            [],
            |row| row.get(0),
        )
    }

    /// Count all categories.
    pub fn category_count(&self) -> SqlResult<usize> {
        let prefix = self.table_prefix();
        self.conn.query_row(
            &format!("SELECT COUNT(*) FROM {prefix}data_type_categories"),
            [],
            |row| row.get(0),
        )
    }

    /// Get the platform prefix for this manager.
    pub fn platform_prefix(&self) -> Option<&str> {
        self.prefix.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    fn setup() -> Connection {
        Connection::open_in_memory().unwrap()
    }

    #[test]
    fn test_create_manager() {
        let conn = setup();
        let mgr = TraceDataTypeManager::new(&conn).unwrap();
        assert!(mgr.platform_prefix().is_none());
        // Should have root category
        assert_eq!(mgr.category_count().unwrap(), 1);
    }

    #[test]
    fn test_create_guest_manager() {
        let conn = setup();
        let mgr = TraceDataTypeManager::new_for_guest(&conn, 42).unwrap();
        assert_eq!(mgr.platform_prefix(), Some("Guest42_"));
    }

    #[test]
    fn test_create_category() {
        let conn = setup();
        let mgr = TraceDataTypeManager::new(&conn).unwrap();
        let root_id = mgr.root_category_id().unwrap();

        let cat_id = mgr.create_category(root_id, "builtin").unwrap();
        let cat = mgr.get_category_by_path("/builtin").unwrap().unwrap();
        assert_eq!(cat.id, cat_id);
        assert_eq!(cat.name, "builtin");
        assert_eq!(cat.path, "/builtin");
    }

    #[test]
    fn test_nested_categories() {
        let conn = setup();
        let mgr = TraceDataTypeManager::new(&conn).unwrap();
        let root_id = mgr.root_category_id().unwrap();

        let c1 = mgr.create_category(root_id, "structs").unwrap();
        let c2 = mgr.create_category(c1, "network").unwrap();
        let cat = mgr.get_category_by_path("/structs/network").unwrap().unwrap();
        assert_eq!(cat.id, c2);
        assert_eq!(cat.parent_id, Some(c1));
    }

    #[test]
    fn test_add_data_type() {
        let conn = setup();
        let mgr = TraceDataTypeManager::new(&conn).unwrap();
        let root_id = mgr.root_category_id().unwrap();

        let dt_id = mgr
            .add_data_type(root_id, "int", 4, true, DataTypeConflictHandler::KeepExisting)
            .unwrap();
        let dt = mgr.get_data_type_by_path("/int").unwrap().unwrap();
        assert_eq!(dt.id, dt_id);
        assert_eq!(dt.name, "int");
        assert_eq!(dt.size, 4);
        assert!(dt.is_builtin);
    }

    #[test]
    fn test_conflict_keep_existing() {
        let conn = setup();
        let mgr = TraceDataTypeManager::new(&conn).unwrap();
        let root_id = mgr.root_category_id().unwrap();

        let id1 = mgr
            .add_data_type(root_id, "mytype", 4, false, DataTypeConflictHandler::KeepExisting)
            .unwrap();
        let id2 = mgr
            .add_data_type(root_id, "mytype", 8, false, DataTypeConflictHandler::KeepExisting)
            .unwrap();
        assert_eq!(id1, id2); // Same ID kept

        let dt = mgr.get_data_type_by_path("/mytype").unwrap().unwrap();
        assert_eq!(dt.size, 4); // Original size preserved
    }

    #[test]
    fn test_conflict_replace_existing() {
        let conn = setup();
        let mgr = TraceDataTypeManager::new(&conn).unwrap();
        let root_id = mgr.root_category_id().unwrap();

        let _id1 = mgr
            .add_data_type(root_id, "mytype", 4, false, DataTypeConflictHandler::ReplaceExisting)
            .unwrap();
        let id2 = mgr
            .add_data_type(root_id, "mytype", 8, false, DataTypeConflictHandler::ReplaceExisting)
            .unwrap();

        let dt = mgr.get_data_type_by_path("/mytype").unwrap().unwrap();
        assert_eq!(dt.id, id2);
        assert_eq!(dt.size, 8); // New size
    }

    #[test]
    fn test_conflict_rename_new() {
        let conn = setup();
        let mgr = TraceDataTypeManager::new(&conn).unwrap();
        let root_id = mgr.root_category_id().unwrap();

        let id1 = mgr
            .add_data_type(root_id, "mytype", 4, false, DataTypeConflictHandler::RenameNew)
            .unwrap();
        let id2 = mgr
            .add_data_type(root_id, "mytype", 8, false, DataTypeConflictHandler::RenameNew)
            .unwrap();
        assert_ne!(id1, id2); // Different IDs

        let dt = mgr.get_data_type_by_path("/mytype_1").unwrap().unwrap();
        assert_eq!(dt.size, 8);
    }

    #[test]
    fn test_list_data_types_in_category() {
        let conn = setup();
        let mgr = TraceDataTypeManager::new(&conn).unwrap();
        let root_id = mgr.root_category_id().unwrap();
        let cat_id = mgr.create_category(root_id, "test").unwrap();

        mgr.add_data_type(cat_id, "alpha", 1, false, DataTypeConflictHandler::default())
            .unwrap();
        mgr.add_data_type(cat_id, "beta", 2, false, DataTypeConflictHandler::default())
            .unwrap();

        let types = mgr.list_data_types_in_category(cat_id).unwrap();
        assert_eq!(types.len(), 2);
        assert_eq!(types[0].name, "alpha");
        assert_eq!(types[1].name, "beta");
    }

    #[test]
    fn test_delete_data_type() {
        let conn = setup();
        let mgr = TraceDataTypeManager::new(&conn).unwrap();
        let root_id = mgr.root_category_id().unwrap();

        let id = mgr
            .add_data_type(root_id, "temp", 4, false, DataTypeConflictHandler::default())
            .unwrap();
        assert_eq!(mgr.data_type_count().unwrap(), 1);

        assert!(mgr.delete_data_type(id).unwrap());
        assert_eq!(mgr.data_type_count().unwrap(), 0);
    }

    #[test]
    fn test_delete_empty_category() {
        let conn = setup();
        let mgr = TraceDataTypeManager::new(&conn).unwrap();
        let root_id = mgr.root_category_id().unwrap();

        let cat_id = mgr.create_category(root_id, "empty").unwrap();
        assert!(mgr.delete_category(cat_id).unwrap());
        assert_eq!(mgr.category_count().unwrap(), 1); // Only root remains
    }

    #[test]
    fn test_delete_nonempty_category_fails() {
        let conn = setup();
        let mgr = TraceDataTypeManager::new(&conn).unwrap();
        let root_id = mgr.root_category_id().unwrap();

        let cat_id = mgr.create_category(root_id, "notempty").unwrap();
        mgr.add_data_type(cat_id, "mytype", 4, false, DataTypeConflictHandler::default())
            .unwrap();

        assert!(!mgr.delete_category(cat_id).unwrap());
    }

    #[test]
    fn test_list_categories() {
        let conn = setup();
        let mgr = TraceDataTypeManager::new(&conn).unwrap();
        let root_id = mgr.root_category_id().unwrap();

        mgr.create_category(root_id, "a").unwrap();
        mgr.create_category(root_id, "b").unwrap();

        let cats = mgr.list_categories().unwrap();
        // Root + a + b = 3
        assert_eq!(cats.len(), 3);
    }

    #[test]
    fn test_guest_manager_isolation() {
        let conn = setup();
        let host_mgr = TraceDataTypeManager::new(&conn).unwrap();
        let guest_mgr = TraceDataTypeManager::new_for_guest(&conn, 1).unwrap();

        let host_root = host_mgr.root_category_id().unwrap();
        let guest_root = guest_mgr.root_category_id().unwrap();

        host_mgr
            .add_data_type(host_root, "host_type", 4, false, DataTypeConflictHandler::default())
            .unwrap();
        guest_mgr
            .add_data_type(guest_root, "guest_type", 2, false, DataTypeConflictHandler::default())
            .unwrap();

        // Host sees only its type
        assert!(host_mgr.get_data_type_by_path("/host_type").unwrap().is_some());
        assert!(host_mgr.get_data_type_by_path("/guest_type").unwrap().is_none());

        // Guest sees only its type
        assert!(guest_mgr.get_data_type_by_path("/guest_type").unwrap().is_some());
        assert!(guest_mgr.get_data_type_by_path("/host_type").unwrap().is_none());
    }
}
