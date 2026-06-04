//! TraceDatabase - SQLite-backed trace storage.
//!
//! Ported from Ghidra's `DBTrace`. This provides persistent storage
//! for all trace data: snapshots, threads, modules, breakpoints, and objects.

use rusqlite::{params, Connection, Result as SqlResult};
use std::path::Path;

use crate::model::{
    Lifespan, TraceExecutionState, TraceModule,
    TraceSnapshot, TraceThread, TraceTimeManager,
};
use crate::target::{KeyPath, TraceObject, TraceObjectManager};

/// A SQLite-backed trace database.
pub struct TraceDatabase {
    conn: Connection,
    time_manager: TraceTimeManager,
    object_manager: TraceObjectManager,
}

impl TraceDatabase {
    /// Open or create a trace database at the given path.
    pub fn open(path: &Path) -> SqlResult<Self> {
        let conn = Connection::open(path)?;
        let mut db = Self {
            conn,
            time_manager: TraceTimeManager::new(),
            object_manager: TraceObjectManager::new(),
        };
        db.create_tables()?;
        db.load_from_db()?;
        Ok(db)
    }

    /// Create an in-memory trace database.
    pub fn open_in_memory() -> SqlResult<Self> {
        let conn = Connection::open_in_memory()?;
        let db = Self {
            conn,
            time_manager: TraceTimeManager::new(),
            object_manager: TraceObjectManager::new(),
        };
        db.create_tables()?;
        Ok(db)
    }

    fn create_tables(&self) -> SqlResult<()> {
        self.conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS trace_info (
                key TEXT PRIMARY KEY,
                value TEXT
            );

            CREATE TABLE IF NOT EXISTS snapshots (
                key INTEGER PRIMARY KEY,
                description TEXT NOT NULL DEFAULT '',
                real_time INTEGER,
                event_thread_key INTEGER,
                schedule_string TEXT,
                version INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS threads (
                key INTEGER PRIMARY KEY,
                path TEXT NOT NULL,
                tid INTEGER,
                name TEXT NOT NULL DEFAULT '',
                comment TEXT,
                min_snap INTEGER NOT NULL,
                max_snap INTEGER NOT NULL,
                execution_state TEXT NOT NULL DEFAULT 'Unknown'
            );

            CREATE TABLE IF NOT EXISTS processes (
                key INTEGER PRIMARY KEY,
                path TEXT NOT NULL,
                pid INTEGER,
                name TEXT NOT NULL DEFAULT '',
                min_snap INTEGER NOT NULL,
                max_snap INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS modules (
                key INTEGER PRIMARY KEY,
                path TEXT NOT NULL,
                module_name TEXT NOT NULL,
                min_address INTEGER NOT NULL,
                max_address INTEGER NOT NULL,
                min_snap INTEGER NOT NULL,
                max_snap INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS sections (
                key INTEGER PRIMARY KEY,
                module_key INTEGER NOT NULL,
                path TEXT NOT NULL,
                name TEXT NOT NULL,
                min_address INTEGER NOT NULL,
                max_address INTEGER NOT NULL,
                FOREIGN KEY (module_key) REFERENCES modules(key)
            );

            CREATE TABLE IF NOT EXISTS breakpoints (
                path TEXT NOT NULL,
                min_snap INTEGER NOT NULL,
                max_snap INTEGER NOT NULL,
                min_address INTEGER NOT NULL,
                max_address INTEGER NOT NULL,
                kinds INTEGER NOT NULL DEFAULT 0,
                enabled INTEGER NOT NULL DEFAULT 1,
                comment TEXT,
                PRIMARY KEY (path, min_snap)
            );

            CREATE TABLE IF NOT EXISTS memory_blocks (
                space_name TEXT NOT NULL,
                min_address INTEGER NOT NULL,
                max_address INTEGER NOT NULL,
                name TEXT NOT NULL,
                permissions INTEGER NOT NULL DEFAULT 0,
                initialized INTEGER NOT NULL DEFAULT 1
            );

            CREATE TABLE IF NOT EXISTS objects (
                path TEXT PRIMARY KEY,
                schema_name TEXT NOT NULL DEFAULT '',
                interfaces TEXT NOT NULL DEFAULT '[]'
            );

            CREATE TABLE IF NOT EXISTS object_attributes (
                object_path TEXT NOT NULL,
                name TEXT NOT NULL,
                value_type TEXT NOT NULL,
                value TEXT NOT NULL,
                min_snap INTEGER NOT NULL,
                max_snap INTEGER NOT NULL,
                FOREIGN KEY (object_path) REFERENCES objects(path),
                PRIMARY KEY (object_path, name, min_snap)
            );

            CREATE TABLE IF NOT EXISTS object_elements (
                object_path TEXT NOT NULL,
                idx TEXT NOT NULL,
                value_type TEXT NOT NULL,
                value TEXT NOT NULL,
                min_snap INTEGER NOT NULL,
                max_snap INTEGER NOT NULL,
                FOREIGN KEY (object_path) REFERENCES objects(path),
                PRIMARY KEY (object_path, idx, min_snap)
            );
            ",
        )?;
        Ok(())
    }

    fn load_from_db(&mut self) -> SqlResult<()> {
        self.load_snapshots()?;
        self.load_threads()?;
        self.load_objects()?;
        Ok(())
    }

    fn load_snapshots(&mut self) -> SqlResult<()> {
        let mut stmt = self
            .conn
            .prepare("SELECT key, description, real_time, event_thread_key, schedule_string, version FROM snapshots")?;
        let rows = stmt.query_map([], |row| {
            Ok(TraceSnapshot {
                key: row.get(0)?,
                description: row.get::<_, String>(1)?,
                real_time: row.get(2)?,
                event_thread_key: row.get(3)?,
                schedule_string: row.get(4)?,
                version: row.get(5)?,
            })
        })?;
        for row in rows {
            let snap = row?;
            if snap.key >= self.time_manager.snapshots().len() as i64 {
                self.time_manager.create_snapshot_at(snap.key);
            }
            if let Some(s) = self.time_manager.get_snapshot_mut(snap.key) {
                s.description = snap.description;
                s.real_time = snap.real_time;
                s.event_thread_key = snap.event_thread_key;
                s.schedule_string = snap.schedule_string;
                s.version = snap.version;
            }
        }
        Ok(())
    }

    fn load_threads(&mut self) -> SqlResult<()> {
        // Threads are loaded through the object manager
        Ok(())
    }

    fn load_objects(&mut self) -> SqlResult<()> {
        let mut stmt = self
            .conn
            .prepare("SELECT path, schema_name, interfaces FROM objects")?;
        let rows = stmt.query_map([], |row| {
            let path_str: String = row.get(0)?;
            let schema_name: String = row.get(1)?;
            let interfaces_json: String = row.get(2)?;
            Ok((path_str, schema_name, interfaces_json))
        })?;
        for row in rows {
            let (path_str, schema_name, interfaces_json) = row?;
            let path = KeyPath::parse(&path_str);
            let mut obj = TraceObject::new(path.clone(), schema_name);
            if let Ok(interfaces) = serde_json::from_str::<Vec<String>>(&interfaces_json) {
                for iface in interfaces {
                    obj.add_interface(iface);
                }
            }
            self.object_manager.add_object(obj);
        }
        Ok(())
    }

    // ── Snapshot operations ───────────────────────────────────────

    /// Create a new snapshot.
    pub fn create_snapshot(&mut self) -> SqlResult<i64> {
        self.time_manager.create_snapshot();
        let snap = self.time_manager.snapshots().last().unwrap();
        let key = snap.key;
        self.conn.execute(
            "INSERT INTO snapshots (key, description, version) VALUES (?1, '', 0)",
            params![key],
        )?;
        Ok(key)
    }

    /// Create a snapshot with a description.
    pub fn create_snapshot_with_desc(&mut self, desc: &str) -> SqlResult<i64> {
        self.time_manager.create_snapshot();
        let snap = self.time_manager.snapshots().last().unwrap();
        let key = snap.key;
        self.conn.execute(
            "INSERT INTO snapshots (key, description, version) VALUES (?1, ?2, 0)",
            params![key, desc],
        )?;
        if let Some(s) = self.time_manager.get_snapshot_mut(key) {
            s.description = desc.to_string();
        }
        Ok(key)
    }

    /// Get the time manager.
    pub fn time_manager(&self) -> &TraceTimeManager {
        &self.time_manager
    }

    /// Get the object manager.
    pub fn object_manager(&self) -> &TraceObjectManager {
        &self.object_manager
    }

    /// Get a mutable reference to the object manager.
    pub fn object_manager_mut(&mut self) -> &mut TraceObjectManager {
        &mut self.object_manager
    }

    /// Delete a snapshot by key.
    pub fn delete_snapshot(&mut self, key: i64) -> SqlResult<bool> {
        if self.time_manager.delete_snapshot(key) {
            self.conn
                .execute("DELETE FROM snapshots WHERE key = ?1", params![key])?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Set the description of a snapshot.
    pub fn set_snapshot_description(&mut self, key: i64, desc: &str) -> SqlResult<()> {
        if let Some(s) = self.time_manager.get_snapshot_mut(key) {
            s.description = desc.to_string();
        }
        self.conn.execute(
            "UPDATE snapshots SET description = ?1 WHERE key = ?2",
            params![desc, key],
        )?;
        Ok(())
    }

    // ── Thread operations ─────────────────────────────────────────

    /// Add a thread to the database.
    pub fn add_thread(
        &mut self,
        key: i64,
        path: &str,
        name: &str,
        tid: Option<i64>,
        snap: i64,
    ) -> SqlResult<()> {
        self.conn.execute(
            "INSERT INTO threads (key, path, tid, name, min_snap, max_snap, execution_state) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![key, path, tid, name, snap, i64::MAX, "Unknown"],
        )?;
        Ok(())
    }

    /// Get all threads.
    pub fn get_threads(&self) -> SqlResult<Vec<TraceThread>> {
        let mut stmt = self.conn.prepare(
            "SELECT key, path, tid, name, comment, min_snap, max_snap, execution_state FROM threads",
        )?;
        let threads = stmt
            .query_map([], |row| {
                let min_snap: i64 = row.get(5)?;
                let max_snap: i64 = row.get(6)?;
                let state_str: String = row.get(7)?;
                Ok(TraceThread {
                    key: row.get(0)?,
                    path: row.get(1)?,
                    tid: row.get(2)?,
                    name: row.get(3)?,
                    comment: row.get(4)?,
                    lifespan: Lifespan::span(min_snap, max_snap),
                    execution_state: match state_str.as_str() {
                        "Running" => TraceExecutionState::Running,
                        "Stopped" => TraceExecutionState::Stopped,
                        "Terminated" => TraceExecutionState::Terminated,
                        _ => TraceExecutionState::Unknown,
                    },
                })
            })?
            .collect::<SqlResult<Vec<_>>>()?;
        Ok(threads)
    }

    // ── Module operations ─────────────────────────────────────────

    /// Add a module to the database.
    pub fn add_module(
        &mut self,
        key: i64,
        path: &str,
        module_name: &str,
        min_address: u64,
        max_address: u64,
        min_snap: i64,
        max_snap: i64,
    ) -> SqlResult<()> {
        self.conn.execute(
            "INSERT INTO modules (key, path, module_name, min_address, max_address, min_snap, max_snap) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![key, path, module_name, min_address as i64, max_address as i64, min_snap, max_snap],
        )?;
        Ok(())
    }

    /// Get all modules.
    pub fn get_modules(&self) -> SqlResult<Vec<TraceModule>> {
        let mut stmt = self.conn.prepare(
            "SELECT key, path, module_name, min_address, max_address, min_snap, max_snap FROM modules",
        )?;
        let modules = stmt
            .query_map([], |row| {
                Ok(TraceModule {
                    key: row.get(0)?,
                    path: row.get(1)?,
                    module_name: row.get(2)?,
                    min_address: row.get::<_, i64>(3)? as u64,
                    max_address: row.get::<_, i64>(4)? as u64,
                    lifespan: Lifespan::span(row.get(5)?, row.get(6)?),
                })
            })?
            .collect::<SqlResult<Vec<_>>>()?;
        Ok(modules)
    }

    // ── Breakpoint operations ─────────────────────────────────────

    /// Add a breakpoint to the database.
    pub fn add_breakpoint(
        &mut self,
        path: &str,
        lifespan: Lifespan,
        min_address: u64,
        max_address: u64,
        kinds: u8,
        enabled: bool,
        comment: Option<&str>,
    ) -> SqlResult<()> {
        self.conn.execute(
            "INSERT INTO breakpoints (path, min_snap, max_snap, min_address, max_address, kinds, enabled, comment) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                path,
                lifespan.lmin(),
                lifespan.lmax(),
                min_address as i64,
                max_address as i64,
                kinds,
                enabled as i32,
                comment,
            ],
        )?;
        Ok(())
    }

    /// Get breakpoints at a given snap.
    pub fn get_breakpoints_at(&self, snap: i64) -> SqlResult<Vec<(String, u64, u64, u8, bool)>> {
        let mut stmt = self.conn.prepare(
            "SELECT path, min_address, max_address, kinds, enabled FROM breakpoints WHERE min_snap <= ?1 AND max_snap >= ?1",
        )?;
        let bps = stmt
            .query_map(params![snap], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)? as u64,
                    row.get::<_, i64>(2)? as u64,
                    row.get::<_, u8>(3)?,
                    row.get::<_, i32>(4)? != 0,
                ))
            })?
            .collect::<SqlResult<Vec<_>>>()?;
        Ok(bps)
    }

    // ── Object operations ─────────────────────────────────────────

    /// Insert an object into the database.
    pub fn insert_object(&mut self, obj: &TraceObject) -> SqlResult<()> {
        let interfaces_json = serde_json::to_string(&obj.interfaces).unwrap_or_default();
        self.conn.execute(
            "INSERT OR REPLACE INTO objects (path, schema_name, interfaces) VALUES (?1, ?2, ?3)",
            params![obj.path.to_string(), obj.schema_name, interfaces_json],
        )?;
        Ok(())
    }

    /// The underlying SQLite connection.
    pub fn connection(&self) -> &Connection {
        &self.conn
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_open_in_memory() {
        let db = TraceDatabase::open_in_memory().unwrap();
        assert!(db.time_manager().is_empty());
    }

    #[test]
    fn test_create_snapshot() {
        let mut db = TraceDatabase::open_in_memory().unwrap();
        let key = db.create_snapshot().unwrap();
        assert_eq!(key, 0);
        let key2 = db.create_snapshot_with_desc("step 1").unwrap();
        assert_eq!(key2, 1);
        assert_eq!(db.time_manager().len(), 2);
    }

    #[test]
    fn test_delete_snapshot() {
        let mut db = TraceDatabase::open_in_memory().unwrap();
        db.create_snapshot().unwrap();
        assert!(db.delete_snapshot(0).unwrap());
        assert!(db.time_manager().is_empty());
    }

    #[test]
    fn test_thread_operations() {
        let mut db = TraceDatabase::open_in_memory().unwrap();
        db.add_thread(1, "Threads[100]", "main", Some(100), 0)
            .unwrap();
        let threads = db.get_threads().unwrap();
        assert_eq!(threads.len(), 1);
        assert_eq!(threads[0].name, "main");
        assert_eq!(threads[0].tid, Some(100));
    }

    #[test]
    fn test_module_operations() {
        let mut db = TraceDatabase::open_in_memory().unwrap();
        db.add_module(1, "Modules[1]", "libc.so", 0x7f0000, 0x7fffff, 0, i64::MAX)
            .unwrap();
        let modules = db.get_modules().unwrap();
        assert_eq!(modules.len(), 1);
        assert_eq!(modules[0].module_name, "libc.so");
        assert!(modules[0].is_loaded_at(5));
    }

    #[test]
    fn test_breakpoint_operations() {
        let mut db = TraceDatabase::open_in_memory().unwrap();
        db.add_breakpoint(
            "bp1",
            Lifespan::now_on(0),
            0x400000,
            0x400000,
            4, // HW_EXECUTE
            true,
            Some("test bp"),
        )
        .unwrap();

        let bps = db.get_breakpoints_at(0).unwrap();
        assert_eq!(bps.len(), 1);
        assert_eq!(bps[0].0, "bp1");
        assert!(bps[0].4); // enabled

        let bps_empty = db.get_breakpoints_at(100).unwrap();
        assert_eq!(bps_empty.len(), 1); // still alive (now_on)
    }

    #[test]
    fn test_object_operations() {
        let mut db = TraceDatabase::open_in_memory().unwrap();
        let obj = TraceObject::new(KeyPath::parse("Session"), "Session");
        db.insert_object(&obj).unwrap();
        db.object_manager_mut().add_object(obj);

        let loaded = db.object_manager().get_object(&KeyPath::parse("Session"));
        assert!(loaded.is_some());
        assert_eq!(loaded.unwrap().schema_name, "Session");
    }

    #[test]
    fn test_snapshot_description() {
        let mut db = TraceDatabase::open_in_memory().unwrap();
        db.create_snapshot().unwrap();
        db.set_snapshot_description(0, "Initial state").unwrap();
        let snap = db.time_manager().get_snapshot(0).unwrap();
        assert_eq!(snap.description, "Initial state");
    }

    #[test]
    fn test_persistence() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test_trace.db");

        {
            let mut db = TraceDatabase::open(&path).unwrap();
            db.create_snapshot_with_desc("first").unwrap();
            db.add_thread(1, "Threads[1]", "main", Some(42), 0)
                .unwrap();
        }

        {
            let db = TraceDatabase::open(&path).unwrap();
            assert_eq!(db.time_manager().len(), 1);
            let snap = db.time_manager().get_snapshot(0).unwrap();
            assert_eq!(snap.description, "first");
            let threads = db.get_threads().unwrap();
            assert_eq!(threads.len(), 1);
            assert_eq!(threads[0].tid, Some(42));
        }
    }
}
