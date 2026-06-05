//! Database-backed address property manager for traces.
//!
//! Ported from Ghidra's `DBTraceAddressPropertyManager` and
//! `DBTraceAddressPropertyManagerApiView`.
//!
//! Provides SQLite-backed storage for address-based boolean properties
//! (e.g., instruction starts, code unit boundaries) across snaps and
//! address spaces.

use rusqlite::{params, Connection, Result as SqlResult};
use std::collections::HashMap;

use crate::model::Lifespan;

/// An entry in an address property map.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressPropertyEntry {
    /// The address offset.
    pub address: u64,
    /// The address space name.
    pub space: String,
    /// The snap range.
    pub lifespan: Lifespan,
    /// The property value.
    pub value: bool,
}

/// Database-backed address property manager.
///
/// Manages boolean properties associated with (snap, space, address) triples.
/// Used for instruction starts, plate addresses, and other address-based
/// boolean metadata in the trace database.
#[derive(Debug)]
pub struct DBTraceAddressPropertyManager {
    /// The property name.
    pub name: String,
    conn: std::sync::Arc<Connection>,
}

impl DBTraceAddressPropertyManager {
    /// Create a new address property manager.
    pub fn new(name: impl Into<String>, conn: std::sync::Arc<Connection>) -> Self {
        Self {
            name: name.into(),
            conn,
        }
    }

    fn safe_table_name(&self) -> String {
        let prefix = "trace_addr_prop_";
        let safe_name: String = self
            .name
            .chars()
            .map(|c| if c.is_alphanumeric() || c == '_' { c } else { '_' })
            .collect();
        format!("{}{}", prefix, safe_name)
    }

    /// Create the database table.
    pub fn create_table(&self) -> SqlResult<()> {
        self.conn.execute_batch(&format!(
            "
            CREATE TABLE IF NOT EXISTS {table} (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                space TEXT NOT NULL,
                address INTEGER NOT NULL,
                min_snap INTEGER NOT NULL,
                max_snap INTEGER NOT NULL,
                value INTEGER NOT NULL DEFAULT 1
            );
            CREATE INDEX IF NOT EXISTS idx_{table}_addr
                ON {table}(space, address, min_snap, max_snap);
            CREATE INDEX IF NOT EXISTS idx_{table}_snap
                ON {table}(min_snap, max_snap);
            ",
            table = self.safe_table_name()
        ))
    }

    /// Set a property value for an address over a lifespan.
    pub fn set(
        &self,
        space: &str,
        address: u64,
        lifespan: &Lifespan,
        value: bool,
    ) -> SqlResult<()> {
        self.conn.execute(
            &format!(
                "INSERT INTO {table} (space, address, min_snap, max_snap, value)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                table = self.safe_table_name()
            ),
            params![
                space,
                address as i64,
                lifespan.lmin(),
                lifespan.lmax(),
                value as i32
            ],
        )
        .map(|_| ())
    }

    /// Get the property value at a specific address and snap.
    pub fn get(&self, space: &str, address: u64, snap: i64) -> SqlResult<Option<bool>> {
        let table = self.safe_table_name();
        let mut stmt = self.conn.prepare(&format!(
            "SELECT value FROM {table}
             WHERE space = ?1 AND address = ?2 AND min_snap <= ?3 AND max_snap >= ?3
             ORDER BY min_snap DESC LIMIT 1"
        ))?;
        let mut rows = stmt.query_map(params![space, address as i64, snap], |row| {
            Ok(row.get::<_, i32>(0)? != 0)
        })?;
        match rows.next() {
            Some(r) => Ok(Some(r?)),
            None => Ok(None),
        }
    }

    /// Get all entries in the given lifespan and address range.
    pub fn get_intersecting(
        &self,
        space: &str,
        span: &Lifespan,
        min_address: u64,
        max_address: u64,
    ) -> SqlResult<Vec<AddressPropertyEntry>> {
        let table = self.safe_table_name();
        let mut stmt = self.conn.prepare(&format!(
            "SELECT space, address, min_snap, max_snap, value FROM {table}
             WHERE space = ?1
             AND min_snap <= ?2 AND max_snap >= ?3
             AND address >= ?4 AND address <= ?5"
        ))?;
        let rows = stmt.query_map(
            params![
                space,
                span.lmax(),
                span.lmin(),
                min_address as i64,
                max_address as i64
            ],
            |row| {
                Ok(AddressPropertyEntry {
                    space: row.get(0)?,
                    address: row.get::<_, i64>(1)? as u64,
                    lifespan: Lifespan::span(row.get(2)?, row.get(3)?),
                    value: row.get::<_, i32>(4)? != 0,
                })
            },
        )?;
        rows.collect()
    }

    /// Clear properties in the given lifespan and address range.
    pub fn clear(
        &self,
        space: &str,
        span: &Lifespan,
        min_address: u64,
        max_address: u64,
    ) -> SqlResult<usize> {
        let table = self.safe_table_name();
        self.conn.execute(
            &format!(
                "DELETE FROM {table}
                 WHERE space = ?1
                 AND min_snap <= ?2 AND max_snap >= ?3
                 AND address >= ?4 AND address <= ?5"
            ),
            params![
                space,
                span.lmax(),
                span.lmin(),
                min_address as i64,
                max_address as i64
            ],
        )
    }

    /// Count all entries.
    pub fn count(&self) -> SqlResult<usize> {
        let table = self.safe_table_name();
        let count: i64 = self
            .conn
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })?;
        Ok(count as usize)
    }
}

/// An API view over address properties that supports batch queries.
///
/// Ported from Ghidra's `DBTraceAddressPropertyManagerApiView`.
#[derive(Debug)]
pub struct DBTraceAddressPropertyApiView {
    /// The underlying property managers.
    pub managers: HashMap<String, DBTraceAddressPropertyManager>,
}

impl DBTraceAddressPropertyApiView {
    /// Create a new API view.
    pub fn new() -> Self {
        Self {
            managers: HashMap::new(),
        }
    }

    /// Add a property manager.
    pub fn add_manager(&mut self, manager: DBTraceAddressPropertyManager) {
        let name = manager.name.clone();
        self.managers.insert(name, manager);
    }

    /// Get a property manager by name.
    pub fn get_manager(&self, name: &str) -> Option<&DBTraceAddressPropertyManager> {
        self.managers.get(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn make_db() -> Arc<Connection> {
        Arc::new(Connection::open_in_memory().unwrap())
    }

    #[test]
    fn test_property_manager_create() {
        let conn = make_db();
        let mgr = DBTraceAddressPropertyManager::new("instruction_starts", conn);
        mgr.create_table().unwrap();
    }

    #[test]
    fn test_property_set_get() {
        let conn = make_db();
        let mgr = DBTraceAddressPropertyManager::new("test_props", Arc::clone(&conn));
        mgr.create_table().unwrap();

        mgr.set("ram", 0x1000, &Lifespan::span(0, 10), true).unwrap();

        let val = mgr.get("ram", 0x1000, 5).unwrap();
        assert_eq!(val, Some(true));

        let missing = mgr.get("ram", 0x2000, 5).unwrap();
        assert_eq!(missing, None);

        let expired = mgr.get("ram", 0x1000, 15).unwrap();
        assert_eq!(expired, None);
    }

    #[test]
    fn test_property_intersecting() {
        let conn = make_db();
        let mgr = DBTraceAddressPropertyManager::new("test_props", Arc::clone(&conn));
        mgr.create_table().unwrap();

        mgr.set("ram", 0x1000, &Lifespan::span(0, 10), true).unwrap();
        mgr.set("ram", 0x2000, &Lifespan::span(0, 10), true).unwrap();
        mgr.set("ram", 0x3000, &Lifespan::span(5, 15), true).unwrap();

        let entries = mgr
            .get_intersecting("ram", &Lifespan::span(3, 12), 0x500, 0x2500)
            .unwrap();
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn test_property_clear() {
        let conn = make_db();
        let mgr = DBTraceAddressPropertyManager::new("test_props", Arc::clone(&conn));
        mgr.create_table().unwrap();

        mgr.set("ram", 0x1000, &Lifespan::span(0, 10), true).unwrap();
        mgr.set("ram", 0x2000, &Lifespan::span(0, 10), true).unwrap();

        let cleared = mgr
            .clear("ram", &Lifespan::span(5, 8), 0x500, 0x1500)
            .unwrap();
        assert_eq!(cleared, 1);
        assert_eq!(mgr.count().unwrap(), 1);
    }

    #[test]
    fn test_property_count() {
        let conn = make_db();
        let mgr = DBTraceAddressPropertyManager::new("test_props", Arc::clone(&conn));
        mgr.create_table().unwrap();

        assert_eq!(mgr.count().unwrap(), 0);
        mgr.set("ram", 0x1000, &Lifespan::span(0, 10), true).unwrap();
        assert_eq!(mgr.count().unwrap(), 1);
    }

    #[test]
    fn test_safe_table_name() {
        let mgr = DBTraceAddressPropertyManager::new("instruction starts!", make_db());
        assert_eq!(mgr.safe_table_name(), "trace_addr_prop_instruction_starts_");
    }

    #[test]
    fn test_api_view() {
        let conn = make_db();
        let mgr = DBTraceAddressPropertyManager::new("test", Arc::clone(&conn));
        let mut view = DBTraceAddressPropertyApiView::new();
        view.add_manager(mgr);
        assert!(view.get_manager("test").is_some());
        assert!(view.get_manager("other").is_none());
    }
}
