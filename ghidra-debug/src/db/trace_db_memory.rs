//! Database-backed memory storage for traces.
//!
//! Provides SQLite-backed memory region and state operations for the trace database.

use rusqlite::{params, Connection, Result as SqlResult};

use crate::model::{Lifespan, TraceMemoryState};

/// A memory region record with lifespan information.
#[derive(Debug, Clone)]
pub struct TraceMemoryRegionRecord {
    /// Region path (unique name).
    pub path: String,
    /// The address space.
    pub space: String,
    /// Start offset.
    pub min_offset: u64,
    /// End offset.
    pub max_offset: u64,
    /// The lifespan.
    pub lifespan: Lifespan,
    /// Whether readable.
    pub readable: bool,
    /// Whether writable.
    pub writable: bool,
    /// Whether executable.
    pub executable: bool,
    /// Whether volatile.
    pub volatile: bool,
    /// The display name.
    pub name: String,
}

/// Extension trait for memory table operations.
pub trait TraceMemoryDbExt {
    /// Create the memory tables.
    fn create_memory_tables(&self) -> SqlResult<()>;

    /// Insert a memory region.
    fn insert_memory_region(&self, region: &TraceMemoryRegionRecord) -> SqlResult<()>;

    /// Load all memory regions.
    fn load_memory_regions(&self) -> SqlResult<Vec<TraceMemoryRegionRecord>>;

    /// Delete a memory region by path.
    fn delete_memory_region(&self, path: &str) -> SqlResult<bool>;

    /// Get memory regions active at a given snap.
    fn get_regions_at(&self, snap: i64) -> SqlResult<Vec<TraceMemoryRegionRecord>>;

    /// Insert a memory state entry.
    fn insert_memory_state(
        &self,
        space: &str,
        min_addr: u64,
        max_addr: u64,
        min_snap: i64,
        max_snap: i64,
        state: &str,
        data: Option<&[u8]>,
    ) -> SqlResult<()>;

    /// Get memory state at a specific address and snap.
    fn get_memory_state(
        &self,
        space: &str,
        address: u64,
        snap: i64,
    ) -> SqlResult<Option<(TraceMemoryState, Option<Vec<u8>>)>>;

    /// Read memory bytes at a given address range and snap.
    fn read_memory(
        &self,
        space: &str,
        min_addr: u64,
        max_addr: u64,
        snap: i64,
    ) -> SqlResult<Vec<Option<u8>>>;
}

impl TraceMemoryDbExt for Connection {
    fn create_memory_tables(&self) -> SqlResult<()> {
        self.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS trace_memory_regions (
                path TEXT PRIMARY KEY,
                space TEXT NOT NULL,
                min_offset INTEGER NOT NULL,
                max_offset INTEGER NOT NULL,
                min_snap INTEGER NOT NULL,
                max_snap INTEGER NOT NULL,
                readable INTEGER NOT NULL DEFAULT 1,
                writable INTEGER NOT NULL DEFAULT 0,
                executable INTEGER NOT NULL DEFAULT 0,
                volatile INTEGER NOT NULL DEFAULT 0,
                name TEXT NOT NULL DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS idx_mem_regions_snap ON trace_memory_regions(min_snap, max_snap);
            CREATE INDEX IF NOT EXISTS idx_mem_regions_space ON trace_memory_regions(space);

            CREATE TABLE IF NOT EXISTS trace_memory_state (
                space TEXT NOT NULL,
                min_address INTEGER NOT NULL,
                max_address INTEGER NOT NULL,
                min_snap INTEGER NOT NULL,
                max_snap INTEGER NOT NULL,
                state TEXT NOT NULL,
                data BLOB,
                PRIMARY KEY (space, min_address, min_snap)
            );
            CREATE INDEX IF NOT EXISTS idx_mem_state_snap ON trace_memory_state(min_snap, max_snap);
            ",
        )?;
        Ok(())
    }

    fn insert_memory_region(&self, region: &TraceMemoryRegionRecord) -> SqlResult<()> {
        self.execute(
            "INSERT OR REPLACE INTO trace_memory_regions (path, space, min_offset, max_offset, min_snap, max_snap, readable, writable, executable, volatile, name) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                region.path,
                region.space,
                region.min_offset as i64,
                region.max_offset as i64,
                region.lifespan.lmin(),
                region.lifespan.lmax(),
                region.readable as i32,
                region.writable as i32,
                region.executable as i32,
                region.volatile as i32,
                region.name,
            ],
        )?;
        Ok(())
    }

    fn load_memory_regions(&self) -> SqlResult<Vec<TraceMemoryRegionRecord>> {
        let mut stmt = self.prepare(
            "SELECT path, space, min_offset, max_offset, min_snap, max_snap, readable, writable, executable, volatile, name FROM trace_memory_regions",
        )?;
        let regions = stmt
            .query_map([], |row| {
                Ok(TraceMemoryRegionRecord {
                    path: row.get(0)?,
                    space: row.get(1)?,
                    min_offset: row.get::<_, i64>(2)? as u64,
                    max_offset: row.get::<_, i64>(3)? as u64,
                    lifespan: Lifespan::span(row.get(4)?, row.get(5)?),
                    readable: row.get::<_, i32>(6)? != 0,
                    writable: row.get::<_, i32>(7)? != 0,
                    executable: row.get::<_, i32>(8)? != 0,
                    volatile: row.get::<_, i32>(9)? != 0,
                    name: row.get(10)?,
                })
            })?
            .collect::<SqlResult<Vec<_>>>()?;
        Ok(regions)
    }

    fn delete_memory_region(&self, path: &str) -> SqlResult<bool> {
        let count = self.execute(
            "DELETE FROM trace_memory_regions WHERE path = ?1",
            params![path],
        )?;
        Ok(count > 0)
    }

    fn get_regions_at(&self, snap: i64) -> SqlResult<Vec<TraceMemoryRegionRecord>> {
        let mut stmt = self.prepare(
            "SELECT path, space, min_offset, max_offset, min_snap, max_snap, readable, writable, executable, volatile, name FROM trace_memory_regions WHERE min_snap <= ?1 AND max_snap >= ?1",
        )?;
        let regions = stmt
            .query_map(params![snap], |row| {
                Ok(TraceMemoryRegionRecord {
                    path: row.get(0)?,
                    space: row.get(1)?,
                    min_offset: row.get::<_, i64>(2)? as u64,
                    max_offset: row.get::<_, i64>(3)? as u64,
                    lifespan: Lifespan::span(row.get(4)?, row.get(5)?),
                    readable: row.get::<_, i32>(6)? != 0,
                    writable: row.get::<_, i32>(7)? != 0,
                    executable: row.get::<_, i32>(8)? != 0,
                    volatile: row.get::<_, i32>(9)? != 0,
                    name: row.get(10)?,
                })
            })?
            .collect::<SqlResult<Vec<_>>>()?;
        Ok(regions)
    }

    fn insert_memory_state(
        &self,
        space: &str,
        min_addr: u64,
        max_addr: u64,
        min_snap: i64,
        max_snap: i64,
        state: &str,
        data: Option<&[u8]>,
    ) -> SqlResult<()> {
        self.execute(
            "INSERT OR REPLACE INTO trace_memory_state (space, min_address, max_address, min_snap, max_snap, state, data) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                space,
                min_addr as i64,
                max_addr as i64,
                min_snap,
                max_snap,
                state,
                data,
            ],
        )?;
        Ok(())
    }

    fn get_memory_state(
        &self,
        space: &str,
        address: u64,
        snap: i64,
    ) -> SqlResult<Option<(TraceMemoryState, Option<Vec<u8>>)>> {
        let mut stmt = self.prepare(
            "SELECT state, data FROM trace_memory_state WHERE space = ?1 AND min_address <= ?2 AND max_address >= ?2 AND min_snap <= ?3 AND max_snap >= ?3 ORDER BY min_snap DESC LIMIT 1",
        )?;
        let mut rows = stmt.query_map(params![space, address as i64, snap], |row| {
            let state_str: String = row.get(0)?;
            let data: Option<Vec<u8>> = row.get(1)?;
            let state = match state_str.as_str() {
                "Known" => TraceMemoryState::Known,
                "Error" => TraceMemoryState::Error,
                _ => TraceMemoryState::Unknown,
            };
            Ok((state, data))
        })?;

        match rows.next() {
            Some(row) => Ok(Some(row?)),
            None => Ok(None),
        }
    }

    fn read_memory(
        &self,
        space: &str,
        min_addr: u64,
        max_addr: u64,
        snap: i64,
    ) -> SqlResult<Vec<Option<u8>>> {
        let size = (max_addr - min_addr + 1) as usize;
        let mut result = vec![None; size];
        let mut stmt = self.prepare(
            "SELECT min_address, max_address, data FROM trace_memory_state WHERE space = ?1 AND min_address <= ?3 AND max_address >= ?2 AND min_snap <= ?4 AND max_snap >= ?4 AND state = 'Known'",
        )?;
        let rows = stmt.query_map(params![space, min_addr as i64, max_addr as i64, snap], |row| {
            let min: i64 = row.get(0)?;
            let max: i64 = row.get(1)?;
            let data: Option<Vec<u8>> = row.get(2)?;
            Ok((min as u64, max as u64, data))
        })?;

        for row in rows {
            let (entry_min, _entry_max, data) = row?;
            if let Some(bytes) = data {
                let start = if entry_min > min_addr {
                    (entry_min - min_addr) as usize
                } else {
                    0
                };
                let src_start = if min_addr > entry_min {
                    (min_addr - entry_min) as usize
                } else {
                    0
                };
                let copy_len = bytes.len().saturating_sub(src_start).min(size - start);
                if copy_len > 0 && start < size {
                    result[start..start + copy_len].copy_from_slice(
                        &bytes[src_start..src_start + copy_len]
                            .iter()
                            .map(|b| Some(*b))
                            .collect::<Vec<_>>(),
                    );
                }
            }
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    fn setup_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.create_memory_tables().unwrap();
        conn
    }

    #[test]
    fn test_create_tables() {
        setup_db();
    }

    #[test]
    fn test_insert_and_load_region() {
        let conn = setup_db();
        let region = TraceMemoryRegionRecord {
            path: "ram[0x400000]".into(),
            space: "ram".into(),
            min_offset: 0x400000,
            max_offset: 0x400fff,
            lifespan: Lifespan::now_on(0),
            readable: true,
            writable: true,
            executable: true,
            volatile: false,
            name: ".text".into(),
        };
        conn.insert_memory_region(&region).unwrap();

        let regions = conn.load_memory_regions().unwrap();
        assert_eq!(regions.len(), 1);
        assert_eq!(regions[0].name, ".text");
        assert!(regions[0].readable);
        assert!(regions[0].executable);
    }

    #[test]
    fn test_regions_at_snap() {
        let conn = setup_db();
        let region = TraceMemoryRegionRecord {
            path: "stack".into(),
            space: "ram".into(),
            min_offset: 0x7fff0000,
            max_offset: 0x7fffffff,
            lifespan: Lifespan::span(0, 10),
            readable: true,
            writable: true,
            executable: false,
            volatile: false,
            name: "stack".into(),
        };
        conn.insert_memory_region(&region).unwrap();

        let at_5 = conn.get_regions_at(5).unwrap();
        assert_eq!(at_5.len(), 1);

        let at_15 = conn.get_regions_at(15).unwrap();
        assert_eq!(at_15.len(), 0);
    }

    #[test]
    fn test_delete_region() {
        let conn = setup_db();
        let region = TraceMemoryRegionRecord {
            path: "test".into(),
            space: "ram".into(),
            min_offset: 0,
            max_offset: 0xff,
            lifespan: Lifespan::ALL,
            readable: true,
            writable: false,
            executable: false,
            volatile: false,
            name: "test".into(),
        };
        conn.insert_memory_region(&region).unwrap();
        assert!(conn.delete_memory_region("test").unwrap());
        assert!(conn.load_memory_regions().unwrap().is_empty());
    }

    #[test]
    fn test_memory_state() {
        let conn = setup_db();
        conn.insert_memory_state("ram", 0x400000, 0x40000f, 0, i64::MAX, "Known", Some(&[0x90; 16]))
            .unwrap();

        let (state, data) = conn.get_memory_state("ram", 0x400005, 0).unwrap().unwrap();
        assert_eq!(state, TraceMemoryState::Known);
        assert_eq!(data.unwrap().len(), 16);

        let no_state = conn.get_memory_state("ram", 0x500000, 0).unwrap();
        assert!(no_state.is_none());
    }

    #[test]
    fn test_read_memory() {
        let conn = setup_db();
        conn.insert_memory_state("ram", 0x400000, 0x40000f, 0, i64::MAX, "Known", Some(&[0x90; 16]))
            .unwrap();

        let bytes = conn.read_memory("ram", 0x400000, 0x40000f, 0).unwrap();
        assert_eq!(bytes.len(), 16);
        assert_eq!(bytes[0], Some(0x90));
    }
}
