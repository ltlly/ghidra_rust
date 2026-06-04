//! Database-backed module storage.
//!
//! Ported from Ghidra's `ghidra.trace.database.module.DBTraceModuleManager`.
//! Provides SQLite-backed persistence for loaded modules and their sections.

use rusqlite::{params, Connection, Result as SqlResult};
use serde::{Deserialize, Serialize};

use crate::model::lifespan::Lifespan;
use crate::model::module::{TraceModule, TraceSection};

/// A module entry stored in the database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleEntry {
    /// Row ID.
    pub id: i64,
    /// Module name (e.g., "libc.so").
    pub name: String,
    /// Base address where the module is loaded.
    pub base_address: u64,
    /// Module length in bytes.
    pub length: u64,
    /// The snap range.
    pub min_snap: i64,
    pub max_snap: i64,
}

/// A section entry stored in the database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionEntry {
    /// Row ID.
    pub id: i64,
    /// The parent module ID.
    pub module_id: i64,
    /// Section name (e.g., ".text").
    pub name: String,
    /// Start address.
    pub start_addr: u64,
    /// End address.
    pub end_addr: u64,
    /// The snap range.
    pub min_snap: i64,
    pub max_snap: i64,
}

/// Database-backed module manager.
#[derive(Debug)]
pub struct TraceDbModuleManager<'a> {
    conn: &'a Connection,
}

impl<'a> TraceDbModuleManager<'a> {
    /// Create a new module manager.
    pub fn new(conn: &'a Connection) -> SqlResult<Self> {
        let mgr = Self { conn };
        mgr.create_tables()?;
        Ok(mgr)
    }

    fn create_tables(&self) -> SqlResult<()> {
        self.conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS modules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                base_address INTEGER NOT NULL,
                length INTEGER NOT NULL DEFAULT 0,
                min_snap INTEGER NOT NULL,
                max_snap INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                module_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                start_addr INTEGER NOT NULL,
                end_addr INTEGER NOT NULL,
                min_snap INTEGER NOT NULL,
                max_snap INTEGER NOT NULL,
                FOREIGN KEY (module_id) REFERENCES modules(id)
            );
            CREATE INDEX IF NOT EXISTS idx_mod_snap ON modules(min_snap, max_snap);
            CREATE INDEX IF NOT EXISTS idx_sec_mod ON sections(module_id);
            ",
        )?;
        Ok(())
    }

    /// Add a module.
    pub fn add_module(
        &self,
        name: &str,
        base_address: u64,
        length: u64,
        lifespan: Lifespan,
    ) -> SqlResult<i64> {
        self.conn.execute(
            "INSERT INTO modules (name, base_address, length, min_snap, max_snap)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![name, base_address as i64, length as i64, lifespan.lmin(), lifespan.lmax()],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Add a section to a module.
    pub fn add_section(
        &self,
        module_id: i64,
        name: &str,
        start_addr: u64,
        end_addr: u64,
        lifespan: Lifespan,
    ) -> SqlResult<i64> {
        self.conn.execute(
            "INSERT INTO sections (module_id, name, start_addr, end_addr, min_snap, max_snap)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![module_id, name, start_addr as i64, end_addr as i64, lifespan.lmin(), lifespan.lmax()],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Get all modules at a given snap.
    pub fn get_modules(&self, snap: i64) -> SqlResult<Vec<ModuleEntry>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, name, base_address, length, min_snap, max_snap
             FROM modules WHERE min_snap <= ?1 AND max_snap >= ?1",
        )?;
        let rows = stmt.query_map(params![snap], |row| {
            Ok(ModuleEntry {
                id: row.get(0)?,
                name: row.get(1)?,
                base_address: row.get::<_, i64>(2)? as u64,
                length: row.get::<_, i64>(3)? as u64,
                min_snap: row.get(4)?,
                max_snap: row.get(5)?,
            })
        })?;
        rows.collect()
    }

    /// Get sections for a module at a given snap.
    pub fn get_sections(&self, module_id: i64, snap: i64) -> SqlResult<Vec<SectionEntry>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, module_id, name, start_addr, end_addr, min_snap, max_snap
             FROM sections WHERE module_id = ?1 AND min_snap <= ?2 AND max_snap >= ?2",
        )?;
        let rows = stmt.query_map(params![module_id, snap], |row| {
            Ok(SectionEntry {
                id: row.get(0)?,
                module_id: row.get(1)?,
                name: row.get(2)?,
                start_addr: row.get::<_, i64>(3)? as u64,
                end_addr: row.get::<_, i64>(4)? as u64,
                min_snap: row.get(5)?,
                max_snap: row.get(6)?,
            })
        })?;
        rows.collect()
    }

    /// Count modules.
    pub fn count_modules(&self) -> SqlResult<usize> {
        self.conn
            .query_row("SELECT COUNT(*) FROM modules", [], |row| row.get(0))
    }

    /// Count sections.
    pub fn count_sections(&self) -> SqlResult<usize> {
        self.conn
            .query_row("SELECT COUNT(*) FROM sections", [], |row| row.get(0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    #[test]
    fn test_add_module() {
        let conn = Connection::open_in_memory().unwrap();
        let mgr = TraceDbModuleManager::new(&conn).unwrap();
        let lifespan = Lifespan::span(0, 100);
        let id = mgr.add_module("libc.so", 0x7F000000, 0x1A0000, lifespan).unwrap();
        assert_eq!(id, 1);
        assert_eq!(mgr.count_modules().unwrap(), 1);
    }

    #[test]
    fn test_add_section() {
        let conn = Connection::open_in_memory().unwrap();
        let mgr = TraceDbModuleManager::new(&conn).unwrap();
        let lifespan = Lifespan::span(0, 100);
        let mod_id = mgr.add_module("libc.so", 0x7F000000, 0x1A0000, lifespan).unwrap();
        mgr.add_section(mod_id, ".text", 0x7F001000, 0x7F0A0000, lifespan)
            .unwrap();
        assert_eq!(mgr.count_sections().unwrap(), 1);
    }

    #[test]
    fn test_get_modules_at_snap() {
        let conn = Connection::open_in_memory().unwrap();
        let mgr = TraceDbModuleManager::new(&conn).unwrap();
        let lifespan = Lifespan::span(0, 100);
        mgr.add_module("libc.so", 0x7F000000, 0x1A0000, lifespan).unwrap();
        let modules = mgr.get_modules(50).unwrap();
        assert_eq!(modules.len(), 1);
        assert_eq!(modules[0].name, "libc.so");
    }

    #[test]
    fn test_get_sections() {
        let conn = Connection::open_in_memory().unwrap();
        let mgr = TraceDbModuleManager::new(&conn).unwrap();
        let lifespan = Lifespan::span(0, 100);
        let mod_id = mgr.add_module("libc.so", 0x7F000000, 0x1A0000, lifespan).unwrap();
        mgr.add_section(mod_id, ".text", 0x7F001000, 0x7F0A0000, lifespan).unwrap();
        mgr.add_section(mod_id, ".data", 0x7F0A0000, 0x7F0B0000, lifespan).unwrap();

        let sections = mgr.get_sections(mod_id, 50).unwrap();
        assert_eq!(sections.len(), 2);
    }
}
