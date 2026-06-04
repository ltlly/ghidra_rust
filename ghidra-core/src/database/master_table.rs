//! Master table management ported from Java's `db.MasterTable`.

use crate::database::db::{Database, DbResult};
use crate::database::record::TableRecord;
use std::collections::BTreeMap;
use rusqlite::params;

const MASTER_TABLE_NAME: &str = "GHIDRA_MASTER";

/// Manages the master table that tracks all tables in a Ghidra database.
///
/// Port of Java `db.MasterTable`.
pub struct GhidraMasterTable {
    records: BTreeMap<i64, TableRecord>,
    next_table_num: i64,
}

impl GhidraMasterTable {
    pub fn new() -> Self {
        Self { records: BTreeMap::new(), next_table_num: 0 }
    }

    /// Ensure the master metadata table exists.
    pub fn ensure_table(db: &Database) -> DbResult<()> {
        let conn = db.read()?;
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
            params![MASTER_TABLE_NAME],
            |row| row.get(0),
        ).unwrap_or(0);
        if count == 0 {
            drop(conn);
            let conn = db.write()?;
            conn.execute_batch(&format!(
                "CREATE TABLE IF NOT EXISTS {} (\
                    table_num INTEGER PRIMARY KEY, \
                    name TEXT NOT NULL, \
                    key_field_type INTEGER NOT NULL, \
                    field_types BLOB, \
                    field_names TEXT, \
                    root_buffer_id INTEGER NOT NULL DEFAULT -1, \
                    record_count INTEGER NOT NULL DEFAULT 0, \
                    max_key INTEGER NOT NULL DEFAULT 0, \
                    indexed_column INTEGER NOT NULL DEFAULT -1\
                )",
                MASTER_TABLE_NAME
            ))?;
        }
        Ok(())
    }

    /// Load table records from the database.
    pub fn load_from_db(db: &Database) -> DbResult<Self> {
        Self::ensure_table(db)?;
        let conn = db.read()?;
        let mut stmt = conn.prepare(&format!(
            "SELECT table_num, name, key_field_type, field_types, field_names, \
                    root_buffer_id, record_count, max_key, indexed_column \
             FROM {} ORDER BY table_num ASC",
            MASTER_TABLE_NAME
        ))?;

        let mut records = BTreeMap::new();
        let mut max_num = 0i64;

        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i32>(2)?,
                row.get::<_, Option<Vec<u8>>>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, i32>(5)?,
                row.get::<_, i32>(6)?,
                row.get::<_, i64>(7)?,
                row.get::<_, i32>(8)?,
            ))
        })?;

        for row in rows {
            let (table_num, name, key_field_type, field_types_blob, field_names_str,
                 root_buffer_id, record_count, max_key, indexed_column) = row?;

            let field_types = field_types_blob.unwrap_or_default();
            let field_names: Vec<String> = field_names_str
                .unwrap_or_default()
                .split(';')
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
                .collect();

            let mut tr = TableRecord::new(
                table_num,
                name,
                key_field_type as u8,
                field_types,
                field_names,
                indexed_column,
            );
            tr.set_root_buffer_id(root_buffer_id);
            tr.set_record_count(record_count);
            tr.set_max_key(max_key);
            tr.mark_clean();

            if table_num > max_num {
                max_num = table_num;
            }
            records.insert(table_num, tr);
        }

        Ok(Self { records, next_table_num: max_num + 1 })
    }

    /// Create a new table record.
    pub fn create_table_record(
        &mut self,
        db: &Database,
        name: &str,
        key_field_type: u8,
        field_types: Vec<u8>,
        field_names: Vec<String>,
        indexed_column: i32,
    ) -> DbResult<TableRecord> {
        Self::ensure_table(db)?;
        let table_num = self.next_table_num;
        self.next_table_num += 1;

        let field_names_str = field_names.join(";");
        let conn = db.write()?;
        conn.execute(
            &format!(
                "INSERT INTO {} (table_num, name, key_field_type, field_types, field_names, \
                 root_buffer_id, record_count, max_key, indexed_column) \
                 VALUES (?1, ?2, ?3, ?4, ?5, -1, 0, 0, ?6)",
                MASTER_TABLE_NAME
            ),
            params![table_num, name, key_field_type as i32, field_types, field_names_str, indexed_column],
        )?;

        let tr = TableRecord::new(table_num, name, key_field_type, field_types, field_names, indexed_column);
        let result = tr.clone();
        self.records.insert(table_num, tr);
        Ok(result)
    }

    /// Delete a table record by table number.
    pub fn delete_table_record(&mut self, db: &Database, table_num: i64) -> DbResult<()> {
        if let Some(tr) = self.records.get(&table_num) {
            if tr.get_root_buffer_id() >= 0 {
                return Err(crate::database::db::DbError::Schema(
                    "Cannot delete non-empty table".to_string(),
                ));
            }
        }
        let conn = db.write()?;
        conn.execute(
            &format!("DELETE FROM {} WHERE table_num=?1", MASTER_TABLE_NAME),
            params![table_num],
        )?;
        self.records.remove(&table_num);
        Ok(())
    }

    pub fn get_table_records(&self) -> Vec<&TableRecord> {
        self.records.values().collect()
    }

    pub fn get_table_record_mut(&mut self, table_num: i64) -> Option<&mut TableRecord> {
        self.records.get_mut(&table_num)
    }

    /// Change the name of a table record.
    pub fn change_table_name(&mut self, db: &Database, old_name: &str, new_name: &str) -> DbResult<()> {
        for tr in self.records.values_mut() {
            if tr.get_name() == old_name {
                tr.set_name(new_name);
                let conn = db.write()?;
                conn.execute(
                    &format!("UPDATE {} SET name=?1 WHERE table_num=?2", MASTER_TABLE_NAME),
                    params![new_name, tr.get_table_num()],
                )?;
            }
        }
        Ok(())
    }

    /// Flush all dirty table records to the database.
    pub fn flush(&self, db: &Database) -> DbResult<()> {
        let conn = db.write()?;
        for tr in self.records.values() {
            if tr.is_dirty() {
                let field_names_str = tr.get_field_names().join(";");
                conn.execute(
                    &format!(
                        "UPDATE {} SET root_buffer_id=?1, record_count=?2, max_key=?3, \
                         field_types=?4, field_names=?5 WHERE table_num=?6",
                        MASTER_TABLE_NAME
                    ),
                    params![
                        tr.get_root_buffer_id(),
                        tr.get_record_count(),
                        tr.get_max_key(),
                        tr.get_field_types(),
                        field_names_str,
                        tr.get_table_num(),
                    ],
                )?;
            }
        }
        Ok(())
    }

    /// Refresh table records from the database.
    pub fn refresh(&mut self, db: &Database) -> DbResult<()> {
        *self = Self::load_from_db(db)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_master_table_create_and_list() {
        let db = Database::in_memory().unwrap();
        let mut master = GhidraMasterTable::new();

        let tr = master.create_table_record(&db, "users", 3, vec![3, 4], vec!["id".into(), "name".into()], -1).unwrap();
        assert_eq!(tr.get_table_num(), 0);
        assert_eq!(tr.get_name(), "users");

        let records: Vec<_> = master.get_table_records().iter().map(|r| r.get_name().to_string()).collect();
        assert_eq!(records, vec!["users"]);
    }

    #[test]
    fn test_master_table_delete() {
        let db = Database::in_memory().unwrap();
        let mut master = GhidraMasterTable::new();

        let tr = master.create_table_record(&db, "tmp", 3, vec![], vec![], -1).unwrap();
        master.delete_table_record(&db, tr.get_table_num()).unwrap();
        assert_eq!(master.get_table_records().len(), 0);
    }

    #[test]
    fn test_master_table_rename() {
        let db = Database::in_memory().unwrap();
        let mut master = GhidraMasterTable::new();

        master.create_table_record(&db, "old_name", 3, vec![], vec![], -1).unwrap();
        master.change_table_name(&db, "old_name", "new_name").unwrap();

        let names: Vec<_> = master.get_table_records().iter().map(|r| r.get_name().to_string()).collect();
        assert_eq!(names, vec!["new_name"]);
    }

    #[test]
    fn test_master_table_persistence() {
        let db = Database::in_memory().unwrap();
        let mut master = GhidraMasterTable::new();

        master.create_table_record(&db, "persist", 3, vec![3], vec!["id".into()], -1).unwrap();
        master.flush(&db).unwrap();

        let master2 = GhidraMasterTable::load_from_db(&db).unwrap();
        assert_eq!(master2.get_table_records().len(), 1);
        assert_eq!(master2.get_table_records()[0].get_name(), "persist");
    }

    #[test]
    fn test_master_table_multiple_tables() {
        let db = Database::in_memory().unwrap();
        let mut master = GhidraMasterTable::new();

        master.create_table_record(&db, "a", 3, vec![], vec![], -1).unwrap();
        master.create_table_record(&db, "b", 2, vec![], vec![], -1).unwrap();
        master.create_table_record(&db, "c", 3, vec![], vec![], -1).unwrap();

        assert_eq!(master.get_table_records().len(), 3);
    }
}
