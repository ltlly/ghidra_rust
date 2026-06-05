//! Database-backed equate space for traces.
//!
//! Ported from Ghidra's `DBTraceEquateSpace`.
//!
//! Provides SQLite-backed storage and management of equates within
//! a specific address space in the trace database.

use rusqlite::{params, Connection, Result as SqlResult};

use crate::model::Lifespan;

use super::trace_db_equate::{EquateId, TraceEquate, TraceEquateReference};

/// Database-backed equate space.
///
/// Manages equates and their references for a single address space
/// within the trace database.
#[derive(Debug)]
pub struct DBTraceEquateSpace {
    /// The address space name.
    pub address_space: String,
    conn: std::sync::Arc<Connection>,
}

impl DBTraceEquateSpace {
    /// Create a new DB-backed equate space.
    pub fn new(address_space: impl Into<String>, conn: std::sync::Arc<Connection>) -> Self {
        Self {
            address_space: address_space.into(),
            conn,
        }
    }

    /// Create the database tables for this equate space.
    pub fn create_tables(&self) -> SqlResult<()> {
        self.conn.execute_batch(&format!(
            "
            CREATE TABLE IF NOT EXISTS trace_equates_{space} (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                value INTEGER NOT NULL,
                ref_count INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS trace_equate_refs_{space} (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                equate_id INTEGER NOT NULL,
                address INTEGER NOT NULL,
                operand_index INTEGER NOT NULL DEFAULT 0,
                sub_operand_index INTEGER NOT NULL DEFAULT 0,
                min_snap INTEGER NOT NULL,
                max_snap INTEGER NOT NULL,
                FOREIGN KEY(equate_id) REFERENCES trace_equates_{space}(id)
            );
            CREATE INDEX IF NOT EXISTS idx_equate_refs_addr_{space}
                ON trace_equate_refs_{space}(address, min_snap, max_snap);
            CREATE INDEX IF NOT EXISTS idx_equate_refs_equate_{space}
                ON trace_equate_refs_{space}(equate_id);
            ",
            space = self.safe_table_name()
        ))
    }

    fn safe_table_name(&self) -> String {
        self.address_space
            .chars()
            .map(|c| if c.is_alphanumeric() || c == '_' { c } else { '_' })
            .collect()
    }

    /// Add an equate to the database.
    pub fn add_equate(&self, name: &str, value: i64) -> SqlResult<EquateId> {
        self.conn.execute(
            &format!(
                "INSERT INTO trace_equates_{space} (name, value, ref_count) VALUES (?1, ?2, 0)",
                space = self.safe_table_name()
            ),
            params![name, value],
        )?;
        Ok(self.conn.last_insert_rowid() as EquateId)
    }

    /// Get an equate by ID.
    pub fn get_equate(&self, id: EquateId) -> SqlResult<Option<TraceEquate>> {
        let mut stmt = self.conn.prepare(&format!(
            "SELECT id, name, value, ref_count FROM trace_equates_{space} WHERE id = ?1",
            space = self.safe_table_name()
        ))?;
        let mut rows = stmt.query_map(params![id], |row| {
            Ok(TraceEquate {
                id: row.get(0)?,
                name: row.get(1)?,
                value: row.get(2)?,
                ref_count: row.get(3)?,
            })
        })?;
        match rows.next() {
            Some(r) => Ok(Some(r?)),
            None => Ok(None),
        }
    }

    /// Get an equate by name.
    pub fn get_equate_by_name(&self, name: &str) -> SqlResult<Option<TraceEquate>> {
        let mut stmt = self.conn.prepare(&format!(
            "SELECT id, name, value, ref_count FROM trace_equates_{space} WHERE name = ?1",
            space = self.safe_table_name()
        ))?;
        let mut rows = stmt.query_map(params![name], |row| {
            Ok(TraceEquate {
                id: row.get(0)?,
                name: row.get(1)?,
                value: row.get(2)?,
                ref_count: row.get(3)?,
            })
        })?;
        match rows.next() {
            Some(r) => Ok(Some(r?)),
            None => Ok(None),
        }
    }

    /// Get all equates.
    pub fn get_all_equates(&self) -> SqlResult<Vec<TraceEquate>> {
        let mut stmt = self.conn.prepare(&format!(
            "SELECT id, name, value, ref_count FROM trace_equates_{space} ORDER BY name",
            space = self.safe_table_name()
        ))?;
        let rows = stmt.query_map([], |row| {
            Ok(TraceEquate {
                id: row.get(0)?,
                name: row.get(1)?,
                value: row.get(2)?,
                ref_count: row.get(3)?,
            })
        })?;
        rows.collect()
    }

    /// Delete an equate and its references.
    pub fn delete_equate(&self, id: EquateId) -> SqlResult<bool> {
        let space = self.safe_table_name();
        self.conn.execute(
            &format!("DELETE FROM trace_equate_refs_{space} WHERE equate_id = ?1"),
            params![id],
        )?;
        let affected = self.conn.execute(
            &format!("DELETE FROM trace_equates_{space} WHERE id = ?1"),
            params![id],
        )?;
        Ok(affected > 0)
    }

    /// Add a reference to an equate.
    pub fn add_reference(
        &self,
        equate_id: EquateId,
        address: u64,
        operand_index: i32,
        sub_operand_index: i32,
        lifespan: &Lifespan,
    ) -> SqlResult<()> {
        let space = self.safe_table_name();
        self.conn.execute(
            &format!(
                "INSERT INTO trace_equate_refs_{space}
                (equate_id, address, operand_index, sub_operand_index, min_snap, max_snap)
                VALUES (?1, ?2, ?3, ?4, ?5, ?6)"
            ),
            params![
                equate_id,
                address as i64,
                operand_index,
                sub_operand_index,
                lifespan.lmin(),
                lifespan.lmax()
            ],
        )?;
        self.conn.execute(
            &format!(
                "UPDATE trace_equates_{space} SET ref_count = ref_count + 1 WHERE id = ?1"
            ),
            params![equate_id],
        )?;
        Ok(())
    }

    /// Get references for an equate.
    pub fn get_references(&self, equate_id: EquateId) -> SqlResult<Vec<TraceEquateReference>> {
        let mut stmt = self.conn.prepare(&format!(
            "SELECT equate_id, address, operand_index, sub_operand_index, min_snap, max_snap
             FROM trace_equate_refs_{space} WHERE equate_id = ?1",
            space = self.safe_table_name()
        ))?;
        let rows = stmt.query_map(params![equate_id], |row| {
            Ok(TraceEquateReference {
                equate_id: row.get(0)?,
                address: row.get::<_, i64>(1)? as u64,
                space: String::new(),
                operand_index: row.get(2)?,
                sub_operand_index: row.get(3)?,
                lifespan: Lifespan::span(row.get(4)?, row.get(5)?),
            })
        })?;
        rows.collect()
    }

    /// Get references at a specific address.
    pub fn get_references_at(&self, address: u64) -> SqlResult<Vec<TraceEquateReference>> {
        let mut stmt = self.conn.prepare(&format!(
            "SELECT equate_id, address, operand_index, sub_operand_index, min_snap, max_snap
             FROM trace_equate_refs_{space} WHERE address = ?1",
            space = self.safe_table_name()
        ))?;
        let rows = stmt.query_map(params![address as i64], |row| {
            Ok(TraceEquateReference {
                equate_id: row.get(0)?,
                address: row.get::<_, i64>(1)? as u64,
                space: String::new(),
                operand_index: row.get(2)?,
                sub_operand_index: row.get(3)?,
                lifespan: Lifespan::span(row.get(4)?, row.get(5)?),
            })
        })?;
        rows.collect()
    }

    /// Clear references in the given lifespan and address range.
    pub fn clear_references(
        &self,
        lifespan: &Lifespan,
        min_address: u64,
        max_address: u64,
    ) -> SqlResult<usize> {
        let space = self.safe_table_name();
        let affected = self.conn.execute(
            &format!(
                "DELETE FROM trace_equate_refs_{space}
                 WHERE min_snap <= ?1 AND max_snap >= ?2
                 AND address >= ?3 AND address <= ?4"
            ),
            params![
                lifespan.lmax(),
                lifespan.lmin(),
                min_address as i64,
                max_address as i64
            ],
        )?;
        Ok(affected)
    }

    /// Get the equate count.
    pub fn equate_count(&self) -> SqlResult<usize> {
        let count: i64 = self.conn.query_row(
            &format!(
                "SELECT COUNT(*) FROM trace_equates_{space}",
                space = self.safe_table_name()
            ),
            [],
            |row| row.get(0),
        )?;
        Ok(count as usize)
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
    fn test_equate_space_create_tables() {
        let conn = make_db();
        let space = DBTraceEquateSpace::new("ram", conn);
        space.create_tables().unwrap();
    }

    #[test]
    fn test_equate_space_add_get() {
        let conn = make_db();
        let space = DBTraceEquateSpace::new("ram", Arc::clone(&conn));
        space.create_tables().unwrap();

        let id = space.add_equate("MY_CONST", 42).unwrap();
        assert!(id > 0);

        let equate = space.get_equate(id).unwrap().unwrap();
        assert_eq!(equate.name, "MY_CONST");
        assert_eq!(equate.value, 42);
    }

    #[test]
    fn test_equate_space_by_name() {
        let conn = make_db();
        let space = DBTraceEquateSpace::new("ram", Arc::clone(&conn));
        space.create_tables().unwrap();

        space.add_equate("MY_CONST", 42).unwrap();

        let equate = space.get_equate_by_name("MY_CONST").unwrap().unwrap();
        assert_eq!(equate.value, 42);

        let missing = space.get_equate_by_name("NONEXISTENT").unwrap();
        assert!(missing.is_none());
    }

    #[test]
    fn test_equate_space_delete() {
        let conn = make_db();
        let space = DBTraceEquateSpace::new("ram", Arc::clone(&conn));
        space.create_tables().unwrap();

        let id = space.add_equate("MY_CONST", 42).unwrap();
        assert!(space.delete_equate(id).unwrap());
        assert!(space.get_equate(id).unwrap().is_none());
    }

    #[test]
    fn test_equate_space_references() {
        let conn = make_db();
        let space = DBTraceEquateSpace::new("ram", Arc::clone(&conn));
        space.create_tables().unwrap();

        let id = space.add_equate("MY_CONST", 42).unwrap();
        space
            .add_reference(id, 0x1000, 0, 0, &Lifespan::span(0, 10))
            .unwrap();

        let refs = space.get_references(id).unwrap();
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].address, 0x1000);

        let refs_at = space.get_references_at(0x1000).unwrap();
        assert_eq!(refs_at.len(), 1);
    }

    #[test]
    fn test_equate_space_all_equates() {
        let conn = make_db();
        let space = DBTraceEquateSpace::new("ram", Arc::clone(&conn));
        space.create_tables().unwrap();

        space.add_equate("B", 2).unwrap();
        space.add_equate("A", 1).unwrap();
        space.add_equate("C", 3).unwrap();

        let all = space.get_all_equates().unwrap();
        assert_eq!(all.len(), 3);
        // Should be sorted by name
        assert_eq!(all[0].name, "A");
        assert_eq!(all[1].name, "B");
        assert_eq!(all[2].name, "C");
    }

    #[test]
    fn test_equate_space_clear_references() {
        let conn = make_db();
        let space = DBTraceEquateSpace::new("ram", Arc::clone(&conn));
        space.create_tables().unwrap();

        let id = space.add_equate("MY_CONST", 42).unwrap();
        space
            .add_reference(id, 0x1000, 0, 0, &Lifespan::span(0, 10))
            .unwrap();
        space
            .add_reference(id, 0x2000, 0, 0, &Lifespan::span(0, 10))
            .unwrap();

        let cleared = space
            .clear_references(&Lifespan::span(5, 8), 0x500, 0x1500)
            .unwrap();
        assert_eq!(cleared, 1);

        let remaining = space.get_references(id).unwrap();
        assert_eq!(remaining.len(), 1);
    }

    #[test]
    fn test_equate_space_count() {
        let conn = make_db();
        let space = DBTraceEquateSpace::new("ram", Arc::clone(&conn));
        space.create_tables().unwrap();

        assert_eq!(space.equate_count().unwrap(), 0);
        space.add_equate("A", 1).unwrap();
        space.add_equate("B", 2).unwrap();
        assert_eq!(space.equate_count().unwrap(), 2);
    }

    #[test]
    fn test_safe_table_name() {
        let space = DBTraceEquateSpace::new("ram", make_db());
        assert_eq!(space.safe_table_name(), "ram");

        let space2 = DBTraceEquateSpace::new("register:V850", make_db());
        assert_eq!(space2.safe_table_name(), "register_V850");
    }
}
