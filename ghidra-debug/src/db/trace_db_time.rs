//! Database-backed time/snap management.
//!
//! Ported from Ghidra's `ghidra.trace.database.time.DBTraceTimeManager`.
//! Provides SQLite-backed persistence for snapshots within a trace,
//! extending the in-memory TraceTimeManager with durable storage.

use rusqlite::{params, Connection, Result as SqlResult};
use serde::{Deserialize, Serialize};

use crate::model::time::TraceSnapshot;

/// A snapshot entry stored in the database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotEntry {
    /// Row ID (the snap key).
    pub key: i64,
    /// Description.
    pub description: String,
    /// Real time in millis.
    pub real_time: Option<i64>,
    /// Event thread key.
    pub event_thread_key: Option<i64>,
    /// Schedule string.
    pub schedule_string: Option<String>,
    /// Emulator cache version.
    pub version: Option<i64>,
}

/// Database-backed time manager.
#[derive(Debug)]
pub struct TraceDbTimeManager<'a> {
    conn: &'a Connection,
}

impl<'a> TraceDbTimeManager<'a> {
    /// Create a new time manager.
    pub fn new(conn: &'a Connection) -> SqlResult<Self> {
        let mgr = Self { conn };
        mgr.create_tables()?;
        Ok(mgr)
    }

    fn create_tables(&self) -> SqlResult<()> {
        self.conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS snapshots (
                key INTEGER PRIMARY KEY,
                description TEXT NOT NULL DEFAULT '',
                real_time INTEGER,
                event_thread_key INTEGER,
                schedule_string TEXT,
                version INTEGER
            );
            ",
        )?;
        Ok(())
    }

    /// Insert or replace a snapshot.
    pub fn put_snapshot(&self, snap: &TraceSnapshot) -> SqlResult<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO snapshots (key, description, real_time, event_thread_key, schedule_string, version)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                snap.key,
                snap.description,
                snap.real_time,
                snap.event_thread_key,
                snap.schedule_string,
                snap.version,
            ],
        )?;
        Ok(())
    }

    /// Get a snapshot by key.
    pub fn get_snapshot(&self, key: i64) -> SqlResult<Option<SnapshotEntry>> {
        let mut stmt = self.conn.prepare(
            "SELECT key, description, real_time, event_thread_key, schedule_string, version
             FROM snapshots WHERE key = ?1",
        )?;
        let mut rows = stmt.query_map(params![key], |row| {
            Ok(SnapshotEntry {
                key: row.get(0)?,
                description: row.get(1)?,
                real_time: row.get(2)?,
                event_thread_key: row.get(3)?,
                schedule_string: row.get(4)?,
                version: row.get(5)?,
            })
        })?;
        match rows.next() {
            Some(Ok(e)) => Ok(Some(e)),
            Some(Err(e)) => Err(e),
            None => Ok(None),
        }
    }

    /// Get all snapshots, ordered by key.
    pub fn get_all_snapshots(&self) -> SqlResult<Vec<SnapshotEntry>> {
        let mut stmt = self.conn.prepare(
            "SELECT key, description, real_time, event_thread_key, schedule_string, version
             FROM snapshots ORDER BY key ASC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(SnapshotEntry {
                key: row.get(0)?,
                description: row.get(1)?,
                real_time: row.get(2)?,
                event_thread_key: row.get(3)?,
                schedule_string: row.get(4)?,
                version: row.get(5)?,
            })
        })?;
        rows.collect()
    }

    /// Delete a snapshot by key.
    pub fn delete_snapshot(&self, key: i64) -> SqlResult<usize> {
        self.conn
            .execute("DELETE FROM snapshots WHERE key = ?1", params![key])
    }

    /// Count snapshots.
    pub fn count(&self) -> SqlResult<usize> {
        self.conn
            .query_row("SELECT COUNT(*) FROM snapshots", [], |row| row.get(0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    #[test]
    fn test_put_and_get() {
        let conn = Connection::open_in_memory().unwrap();
        let mgr = TraceDbTimeManager::new(&conn).unwrap();
        let snap = TraceSnapshot::new(0).with_description("initial");
        mgr.put_snapshot(&snap).unwrap();
        assert_eq!(mgr.count().unwrap(), 1);

        let entry = mgr.get_snapshot(0).unwrap().unwrap();
        assert_eq!(entry.description, "initial");
        assert_eq!(entry.key, 0);
    }

    #[test]
    fn test_get_all() {
        let conn = Connection::open_in_memory().unwrap();
        let mgr = TraceDbTimeManager::new(&conn).unwrap();
        mgr.put_snapshot(&TraceSnapshot::new(0)).unwrap();
        mgr.put_snapshot(&TraceSnapshot::new(1)).unwrap();
        mgr.put_snapshot(&TraceSnapshot::new(5)).unwrap();
        let all = mgr.get_all_snapshots().unwrap();
        assert_eq!(all.len(), 3);
        assert_eq!(all[0].key, 0);
        assert_eq!(all[1].key, 1);
        assert_eq!(all[2].key, 5);
    }

    #[test]
    fn test_delete() {
        let conn = Connection::open_in_memory().unwrap();
        let mgr = TraceDbTimeManager::new(&conn).unwrap();
        mgr.put_snapshot(&TraceSnapshot::new(0)).unwrap();
        mgr.delete_snapshot(0).unwrap();
        assert_eq!(mgr.count().unwrap(), 0);
    }

    #[test]
    fn test_snapshot_with_real_time() {
        let conn = Connection::open_in_memory().unwrap();
        let mgr = TraceDbTimeManager::new(&conn).unwrap();
        let snap = TraceSnapshot::new(1).with_real_time(1234567890);
        mgr.put_snapshot(&snap).unwrap();
        let entry = mgr.get_snapshot(1).unwrap().unwrap();
        assert_eq!(entry.real_time, Some(1234567890));
    }
}
