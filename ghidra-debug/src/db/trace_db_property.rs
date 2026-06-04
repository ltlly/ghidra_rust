//! Database-backed property storage.
//!
//! Ported from Ghidra's `ghidra.trace.database.property` package.
//! Provides SQLite-backed persistence for trace properties (key-value
//! pairs that are snap-scoped).

use rusqlite::{params, Connection, Result as SqlResult};
use serde::{Deserialize, Serialize};

use crate::model::lifespan::Lifespan;

/// A property value type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PropertyValue {
    /// A boolean value.
    Bool(bool),
    /// An integer value.
    Int(i64),
    /// A string value.
    String(String),
}

impl PropertyValue {
    /// Get the type tag for database storage.
    pub fn type_tag(&self) -> &'static str {
        match self {
            Self::Bool(_) => "bool",
            Self::Int(_) => "int",
            Self::String(_) => "string",
        }
    }

    /// Serialize the value to a string for storage.
    pub fn to_stored(&self) -> String {
        match self {
            Self::Bool(v) => v.to_string(),
            Self::Int(v) => v.to_string(),
            Self::String(v) => v.clone(),
        }
    }
}

/// A property entry stored in the database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PropertyEntry {
    /// Row ID.
    pub id: i64,
    /// The property name/key.
    pub name: String,
    /// The property value.
    pub value: PropertyValue,
    /// Minimum snap (inclusive).
    pub min_snap: i64,
    /// Maximum snap (inclusive).
    pub max_snap: i64,
}

/// Database-backed property manager.
#[derive(Debug)]
pub struct TraceDbPropertyManager<'a> {
    conn: &'a Connection,
}

impl<'a> TraceDbPropertyManager<'a> {
    /// Create a new property manager.
    pub fn new(conn: &'a Connection) -> SqlResult<Self> {
        let mgr = Self { conn };
        mgr.create_tables()?;
        Ok(mgr)
    }

    fn create_tables(&self) -> SqlResult<()> {
        self.conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS properties (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                value_type TEXT NOT NULL,
                value TEXT NOT NULL,
                min_snap INTEGER NOT NULL,
                max_snap INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_prop_name ON properties(name, min_snap);
            ",
        )?;
        Ok(())
    }

    /// Set a property value over a lifespan.
    pub fn set(&self, name: &str, value: &PropertyValue, lifespan: Lifespan) -> SqlResult<i64> {
        self.conn.execute(
            "INSERT INTO properties (name, value_type, value, min_snap, max_snap)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                name,
                value.type_tag(),
                value.to_stored(),
                lifespan.lmin(),
                lifespan.lmax(),
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Get a property value at a specific snap.
    pub fn get(&self, name: &str, snap: i64) -> SqlResult<Option<PropertyEntry>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, name, value_type, value, min_snap, max_snap
             FROM properties
             WHERE name = ?1 AND min_snap <= ?2 AND max_snap >= ?2
             ORDER BY min_snap DESC LIMIT 1",
        )?;
        let mut rows = stmt.query_map(params![name, snap], |row| {
            let value_type: String = row.get(2)?;
            let value_str: String = row.get(3)?;
            let value = match value_type.as_str() {
                "bool" => PropertyValue::Bool(value_str == "true"),
                "int" => PropertyValue::Int(value_str.parse().unwrap_or(0)),
                _ => PropertyValue::String(value_str),
            };
            Ok(PropertyEntry {
                id: row.get(0)?,
                name: row.get(1)?,
                value,
                min_snap: row.get(4)?,
                max_snap: row.get(5)?,
            })
        })?;
        match rows.next() {
            Some(Ok(entry)) => Ok(Some(entry)),
            Some(Err(e)) => Err(e),
            None => Ok(None),
        }
    }

    /// Remove a property.
    pub fn remove(&self, name: &str, lifespan: Lifespan) -> SqlResult<usize> {
        self.conn.execute(
            "DELETE FROM properties
             WHERE name = ?1 AND min_snap <= ?2 AND max_snap >= ?3",
            params![name, lifespan.lmax(), lifespan.lmin()],
        )
    }

    /// Get the count of stored properties.
    pub fn count(&self) -> SqlResult<usize> {
        self.conn
            .query_row("SELECT COUNT(*) FROM properties", [], |row| row.get(0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    #[test]
    fn test_set_and_get_bool() {
        let conn = Connection::open_in_memory().unwrap();
        let mgr = TraceDbPropertyManager::new(&conn).unwrap();
        let lifespan = Lifespan::span(0, 100);
        mgr.set("is_running", &PropertyValue::Bool(true), lifespan)
            .unwrap();
        let entry = mgr.get("is_running", 50).unwrap().unwrap();
        assert_eq!(entry.value, PropertyValue::Bool(true));
    }

    #[test]
    fn test_set_and_get_int() {
        let conn = Connection::open_in_memory().unwrap();
        let mgr = TraceDbPropertyManager::new(&conn).unwrap();
        let lifespan = Lifespan::span(0, 100);
        mgr.set("exit_code", &PropertyValue::Int(42), lifespan)
            .unwrap();
        let entry = mgr.get("exit_code", 50).unwrap().unwrap();
        assert_eq!(entry.value, PropertyValue::Int(42));
    }

    #[test]
    fn test_set_and_get_string() {
        let conn = Connection::open_in_memory().unwrap();
        let mgr = TraceDbPropertyManager::new(&conn).unwrap();
        let lifespan = Lifespan::span(0, 100);
        mgr.set("arch", &PropertyValue::String("x86_64".into()), lifespan)
            .unwrap();
        let entry = mgr.get("arch", 50).unwrap().unwrap();
        assert_eq!(entry.value, PropertyValue::String("x86_64".into()));
    }

    #[test]
    fn test_get_outside_lifespan() {
        let conn = Connection::open_in_memory().unwrap();
        let mgr = TraceDbPropertyManager::new(&conn).unwrap();
        let lifespan = Lifespan::span(0, 10);
        mgr.set("key", &PropertyValue::Int(1), lifespan).unwrap();
        assert!(mgr.get("key", 50).unwrap().is_none());
    }

    #[test]
    fn test_remove_property() {
        let conn = Connection::open_in_memory().unwrap();
        let mgr = TraceDbPropertyManager::new(&conn).unwrap();
        let lifespan = Lifespan::span(0, 100);
        mgr.set("key", &PropertyValue::Int(1), lifespan).unwrap();
        assert_eq!(mgr.count().unwrap(), 1);
        mgr.remove("key", lifespan).unwrap();
        assert_eq!(mgr.count().unwrap(), 0);
    }
}
