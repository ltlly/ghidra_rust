//! Database-backed data settings storage for traces.
//!
//! Ported from Ghidra's `ghidra.trace.database.data.DBTraceDataSettingsAdapter`
//! and `DBTraceDataSettingsOperations`. Manages per-address settings (long,
//! string, or byte values) that are snap-range scoped within an address space.

use std::collections::HashMap;

use rusqlite::{params, Connection, Result as SqlResult};
use serde::{Deserialize, Serialize};

use crate::model::Lifespan;

/// The type of value stored in a data settings entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SettingsValue {
    /// An integer value.
    Long(i64),
    /// A string value.
    String(String),
    /// A raw bytes value.
    Bytes(Vec<u8>),
}

impl SettingsValue {
    /// Get the long value, if this is a Long variant.
    pub fn as_long(&self) -> Option<i64> {
        match self {
            Self::Long(v) => Some(*v),
            _ => None,
        }
    }

    /// Get the string value, if this is a String variant.
    pub fn as_string(&self) -> Option<&str> {
        match self {
            Self::String(v) => Some(v.as_str()),
            _ => None,
        }
    }

    /// Get the bytes value, if this is a Bytes variant.
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Bytes(v) => Some(v.as_slice()),
            _ => None,
        }
    }
}

/// A single data settings entry in the database.
///
/// Ported from Ghidra's `DBTraceSettingsEntry`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataSettingsEntry {
    /// Row ID.
    pub id: i64,
    /// The address offset within the space.
    pub address: u64,
    /// The address space name.
    pub space: String,
    /// The settings key.
    pub key: String,
    /// The stored value.
    pub value: SettingsValue,
    /// The snap range this setting is valid for.
    pub lifespan: Lifespan,
}

/// Operations trait for data settings.
///
/// Ported from Ghidra's `DBTraceDataSettingsOperations`.
pub trait DataSettingsOperations {
    /// Set a long value for a key at an address.
    fn set_long(
        &self,
        space: &str,
        address: u64,
        key: &str,
        value: i64,
        lifespan: Lifespan,
    ) -> SqlResult<()>;

    /// Set a string value for a key at an address.
    fn set_string(
        &self,
        space: &str,
        address: u64,
        key: &str,
        value: &str,
        lifespan: Lifespan,
    ) -> SqlResult<()>;

    /// Set a bytes value for a key at an address.
    fn set_bytes(
        &self,
        space: &str,
        address: u64,
        key: &str,
        value: &[u8],
        lifespan: Lifespan,
    ) -> SqlResult<()>;

    /// Get the value for a key at an address at a given snap.
    fn get_value(
        &self,
        space: &str,
        address: u64,
        key: &str,
        snap: i64,
    ) -> SqlResult<Option<SettingsValue>>;

    /// Delete the setting for a key at an address.
    fn delete_value(
        &self,
        space: &str,
        address: u64,
        key: &str,
    ) -> SqlResult<bool>;
}

/// Database-backed data settings adapter.
///
/// Ported from Ghidra's `DBTraceDataSettingsAdapter`. Manages address-
/// snap-property entries backed by SQLite, with per-space (including
/// register space) organization.
#[derive(Debug)]
pub struct DataSettingsAdapter<'a> {
    conn: &'a Connection,
}

impl<'a> DataSettingsAdapter<'a> {
    /// The table name for data settings.
    pub const TABLE_NAME: &'static str = "data_settings";

    /// Create a new data settings adapter.
    pub fn new(conn: &'a Connection) -> SqlResult<Self> {
        let adapter = Self { conn };
        adapter.create_tables()?;
        Ok(adapter)
    }

    fn create_tables(&self) -> SqlResult<()> {
        self.conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS data_settings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                address INTEGER NOT NULL,
                space TEXT NOT NULL,
                key TEXT NOT NULL,
                value_type TEXT NOT NULL,
                long_value INTEGER,
                string_value TEXT,
                bytes_value BLOB,
                min_snap INTEGER NOT NULL,
                max_snap INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_settings_addr
                ON data_settings(space, address, key, min_snap);
            CREATE UNIQUE INDEX IF NOT EXISTS idx_settings_unique
                ON data_settings(space, address, key, min_snap, max_snap);
            ",
        )?;
        Ok(())
    }

    /// Internal: insert or replace a settings entry.
    fn insert_entry(
        &self,
        space: &str,
        address: u64,
        key: &str,
        value: &SettingsValue,
        lifespan: Lifespan,
    ) -> SqlResult<()> {
        let (value_type, long_val, str_val, bytes_val) = match value {
            SettingsValue::Long(v) => ("long", Some(*v), None, None),
            SettingsValue::String(v) => ("string", None, Some(v.clone()), None),
            SettingsValue::Bytes(v) => ("bytes", None, None, Some(v.clone())),
        };

        // Remove any existing entry at this exact location
        self.conn.execute(
            "DELETE FROM data_settings WHERE space = ?1 AND address = ?2 AND key = ?3
             AND min_snap = ?4 AND max_snap = ?5",
            params![space, address as i64, key, lifespan.lmin(), lifespan.lmax()],
        )?;

        self.conn.execute(
            "INSERT INTO data_settings (address, space, key, value_type, long_value, string_value, bytes_value, min_snap, max_snap)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                address as i64,
                space,
                key,
                value_type,
                long_val,
                str_val,
                bytes_val,
                lifespan.lmin(),
                lifespan.lmax(),
            ],
        )?;
        Ok(())
    }

    /// Get all settings at a given address and snap.
    pub fn get_all_at(
        &self,
        space: &str,
        address: u64,
        snap: i64,
    ) -> SqlResult<HashMap<String, SettingsValue>> {
        let mut stmt = self.conn.prepare(
            "SELECT key, value_type, long_value, string_value, bytes_value
             FROM data_settings
             WHERE space = ?1 AND address = ?2
             AND min_snap <= ?3 AND max_snap >= ?3",
        )?;
        let entries = stmt.query_map(params![space, address as i64, snap], |row| {
            let key: String = row.get(0)?;
            let value_type: String = row.get(1)?;
            let value = match value_type.as_str() {
                "long" => SettingsValue::Long(row.get::<_, Option<i64>>(2)?.unwrap_or(0)),
                "string" => {
                    SettingsValue::String(row.get::<_, Option<String>>(3)?.unwrap_or_default())
                }
                "bytes" => {
                    SettingsValue::Bytes(row.get::<_, Option<Vec<u8>>>(4)?.unwrap_or_default())
                }
                _ => SettingsValue::Long(0),
            };
            Ok((key, value))
        })?;
        let mut result = HashMap::new();
        for entry in entries {
            let (key, value) = entry?;
            result.insert(key, value);
        }
        Ok(result)
    }

    /// Count all settings entries.
    pub fn count(&self) -> SqlResult<usize> {
        self.conn
            .query_row("SELECT COUNT(*) FROM data_settings", [], |row| row.get(0))
    }

    /// Clear all settings in a space.
    pub fn clear_space(&self, space: &str) -> SqlResult<usize> {
        self.conn.execute(
            "DELETE FROM data_settings WHERE space = ?1",
            params![space],
        )
    }

    /// Clear all settings.
    pub fn clear_all(&self) -> SqlResult<usize> {
        self.conn.execute("DELETE FROM data_settings", [])
    }
}

impl<'a> DataSettingsOperations for DataSettingsAdapter<'a> {
    fn set_long(
        &self,
        space: &str,
        address: u64,
        key: &str,
        value: i64,
        lifespan: Lifespan,
    ) -> SqlResult<()> {
        self.insert_entry(space, address, key, &SettingsValue::Long(value), lifespan)
    }

    fn set_string(
        &self,
        space: &str,
        address: u64,
        key: &str,
        value: &str,
        lifespan: Lifespan,
    ) -> SqlResult<()> {
        self.insert_entry(
            space,
            address,
            key,
            &SettingsValue::String(value.to_string()),
            lifespan,
        )
    }

    fn set_bytes(
        &self,
        space: &str,
        address: u64,
        key: &str,
        value: &[u8],
        lifespan: Lifespan,
    ) -> SqlResult<()> {
        self.insert_entry(
            space,
            address,
            key,
            &SettingsValue::Bytes(value.to_vec()),
            lifespan,
        )
    }

    fn get_value(
        &self,
        space: &str,
        address: u64,
        key: &str,
        snap: i64,
    ) -> SqlResult<Option<SettingsValue>> {
        let mut stmt = self.conn.prepare(
            "SELECT value_type, long_value, string_value, bytes_value
             FROM data_settings
             WHERE space = ?1 AND address = ?2 AND key = ?3
             AND min_snap <= ?4 AND max_snap >= ?4
             LIMIT 1",
        )?;
        let mut rows = stmt.query_map(params![space, address as i64, key, snap], |row| {
            let value_type: String = row.get(0)?;
            Ok(match value_type.as_str() {
                "long" => SettingsValue::Long(row.get::<_, Option<i64>>(1)?.unwrap_or(0)),
                "string" => {
                    SettingsValue::String(row.get::<_, Option<String>>(2)?.unwrap_or_default())
                }
                "bytes" => {
                    SettingsValue::Bytes(row.get::<_, Option<Vec<u8>>>(3)?.unwrap_or_default())
                }
                _ => SettingsValue::Long(0),
            })
        })?;
        match rows.next() {
            Some(Ok(v)) => Ok(Some(v)),
            Some(Err(e)) => Err(e),
            None => Ok(None),
        }
    }

    fn delete_value(
        &self,
        space: &str,
        address: u64,
        key: &str,
    ) -> SqlResult<bool> {
        let count = self.conn.execute(
            "DELETE FROM data_settings WHERE space = ?1 AND address = ?2 AND key = ?3",
            params![space, address as i64, key],
        )?;
        Ok(count > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    fn setup() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        // Tables are auto-created by DataSettingsAdapter::new
        conn
    }

    #[test]
    fn test_create_adapter() {
        let conn = setup();
        let _adapter = DataSettingsAdapter::new(&conn).unwrap();
    }

    #[test]
    fn test_set_and_get_long() {
        let conn = setup();
        let adapter = DataSettingsAdapter::new(&conn).unwrap();
        let lifespan = Lifespan::span(0, 100);

        adapter.set_long("ram", 0x400000, "width", 4, lifespan).unwrap();

        let val = adapter.get_value("ram", 0x400000, "width", 50).unwrap();
        assert_eq!(val, Some(SettingsValue::Long(4)));
    }

    #[test]
    fn test_set_and_get_string() {
        let conn = setup();
        let adapter = DataSettingsAdapter::new(&conn).unwrap();
        let lifespan = Lifespan::span(0, 100);

        adapter
            .set_string("ram", 0x400000, "label", "my_label", lifespan)
            .unwrap();

        let val = adapter.get_value("ram", 0x400000, "label", 50).unwrap();
        assert_eq!(val, Some(SettingsValue::String("my_label".into())));
    }

    #[test]
    fn test_set_and_get_bytes() {
        let conn = setup();
        let adapter = DataSettingsAdapter::new(&conn).unwrap();
        let lifespan = Lifespan::span(0, 100);

        adapter
            .set_bytes("ram", 0x400000, "data", &[0xDE, 0xAD, 0xBE, 0xEF], lifespan)
            .unwrap();

        let val = adapter.get_value("ram", 0x400000, "data", 50).unwrap();
        assert_eq!(
            val,
            Some(SettingsValue::Bytes(vec![0xDE, 0xAD, 0xBE, 0xEF]))
        );
    }

    #[test]
    fn test_get_outside_snap_range() {
        let conn = setup();
        let adapter = DataSettingsAdapter::new(&conn).unwrap();
        let lifespan = Lifespan::span(0, 10);

        adapter.set_long("ram", 0x400000, "width", 4, lifespan).unwrap();

        let val = adapter.get_value("ram", 0x400000, "width", 50).unwrap();
        assert_eq!(val, None);
    }

    #[test]
    fn test_delete_value() {
        let conn = setup();
        let adapter = DataSettingsAdapter::new(&conn).unwrap();
        let lifespan = Lifespan::span(0, 100);

        adapter.set_long("ram", 0x400000, "width", 4, lifespan).unwrap();
        assert!(adapter.delete_value("ram", 0x400000, "width").unwrap());

        let val = adapter.get_value("ram", 0x400000, "width", 50).unwrap();
        assert_eq!(val, None);
    }

    #[test]
    fn test_get_all_at() {
        let conn = setup();
        let adapter = DataSettingsAdapter::new(&conn).unwrap();
        let lifespan = Lifespan::span(0, 100);

        adapter.set_long("ram", 0x400000, "width", 4, lifespan).unwrap();
        adapter
            .set_string("ram", 0x400000, "label", "entry", lifespan)
            .unwrap();

        let all = adapter.get_all_at("ram", 0x400000, 50).unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all.get("width"), Some(&SettingsValue::Long(4)));
        assert_eq!(
            all.get("label"),
            Some(&SettingsValue::String("entry".into()))
        );
    }

    #[test]
    fn test_count() {
        let conn = setup();
        let adapter = DataSettingsAdapter::new(&conn).unwrap();
        let lifespan = Lifespan::span(0, 100);

        assert_eq!(adapter.count().unwrap(), 0);

        adapter.set_long("ram", 0x100, "a", 1, lifespan).unwrap();
        adapter.set_long("ram", 0x200, "b", 2, lifespan).unwrap();
        assert_eq!(adapter.count().unwrap(), 2);
    }

    #[test]
    fn test_clear_space() {
        let conn = setup();
        let adapter = DataSettingsAdapter::new(&conn).unwrap();
        let lifespan = Lifespan::span(0, 100);

        adapter.set_long("ram", 0x100, "a", 1, lifespan).unwrap();
        adapter.set_long("stack", 0x100, "b", 2, lifespan).unwrap();

        adapter.clear_space("ram").unwrap();
        assert_eq!(adapter.count().unwrap(), 1);

        // Stack entry should still exist
        let val = adapter.get_value("stack", 0x100, "b", 50).unwrap();
        assert_eq!(val, Some(SettingsValue::Long(2)));
    }

    #[test]
    fn test_clear_all() {
        let conn = setup();
        let adapter = DataSettingsAdapter::new(&conn).unwrap();
        let lifespan = Lifespan::span(0, 100);

        adapter.set_long("ram", 0x100, "a", 1, lifespan).unwrap();
        adapter.set_long("stack", 0x100, "b", 2, lifespan).unwrap();

        adapter.clear_all().unwrap();
        assert_eq!(adapter.count().unwrap(), 0);
    }

    #[test]
    fn test_settings_value_as_long() {
        let v = SettingsValue::Long(42);
        assert_eq!(v.as_long(), Some(42));
        assert!(v.as_string().is_none());
        assert!(v.as_bytes().is_none());
    }

    #[test]
    fn test_settings_value_as_string() {
        let v = SettingsValue::String("hello".into());
        assert_eq!(v.as_string(), Some("hello"));
        assert!(v.as_long().is_none());
    }

    #[test]
    fn test_settings_value_as_bytes() {
        let v = SettingsValue::Bytes(vec![1, 2, 3]);
        assert_eq!(v.as_bytes(), Some(&[1u8, 2, 3][..]));
        assert!(v.as_long().is_none());
    }

    #[test]
    fn test_multiple_keys_same_address() {
        let conn = setup();
        let adapter = DataSettingsAdapter::new(&conn).unwrap();
        let lifespan = Lifespan::span(0, 100);

        adapter.set_long("ram", 0x400000, "key1", 10, lifespan).unwrap();
        adapter.set_long("ram", 0x400000, "key2", 20, lifespan).unwrap();

        let v1 = adapter.get_value("ram", 0x400000, "key1", 50).unwrap();
        let v2 = adapter.get_value("ram", 0x400000, "key2", 50).unwrap();
        assert_eq!(v1, Some(SettingsValue::Long(10)));
        assert_eq!(v2, Some(SettingsValue::Long(20)));
    }

    #[test]
    fn test_different_spaces_same_address() {
        let conn = setup();
        let adapter = DataSettingsAdapter::new(&conn).unwrap();
        let lifespan = Lifespan::span(0, 100);

        adapter.set_long("ram", 0x100, "key", 1, lifespan).unwrap();
        adapter.set_long("stack", 0x100, "key", 2, lifespan).unwrap();

        let v_ram = adapter.get_value("ram", 0x100, "key", 50).unwrap();
        let v_stack = adapter.get_value("stack", 0x100, "key", 50).unwrap();
        assert_eq!(v_ram, Some(SettingsValue::Long(1)));
        assert_eq!(v_stack, Some(SettingsValue::Long(2)));
    }

    #[test]
    fn test_settings_entry_serde() {
        let entry = DataSettingsEntry {
            id: 1,
            address: 0x400000,
            space: "ram".into(),
            key: "width".into(),
            value: SettingsValue::Long(4),
            lifespan: Lifespan::span(0, 100),
        };
        let json = serde_json::to_string(&entry).unwrap();
        let back: DataSettingsEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(back.value, SettingsValue::Long(4));
        assert_eq!(back.space, "ram");
    }
}
