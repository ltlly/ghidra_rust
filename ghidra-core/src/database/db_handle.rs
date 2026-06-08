//! Thread-safe SQLite connection pool ported from Java's `db.DBHandle`.
//!
//! Provides [`DBHandle`] (connection pool with round-robin distribution)
//! and [`PooledConnection`] (a checked-out connection handle).

use rusqlite::{
    backup,
    params,
    Connection as SqliteConnection,
    Result as SqlResult,
};
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use super::db::{DbError, DbResult, FieldValue, Index, Schema};
use super::db::execute_values;
use super::db::params_to_slice;

// ============================================================================
// PooledConnection — a connection checked out from the pool
// ============================================================================

/// A connection checked out from the pool.
pub struct PooledConnection {
    pub(crate) conn: Arc<Mutex<SqliteConnection>>,
    pub(crate) id: usize,
}

impl PooledConnection {
    /// Execute a read-only closure with the locked connection.
    pub fn with_conn<F, T>(&self, f: F) -> T
    where
        F: FnOnce(&SqliteConnection) -> T,
    {
        let guard = self.conn.lock().expect("Poisoned mutex");
        f(&*guard)
    }

    /// Execute a mutating closure with the locked connection.
    pub fn with_conn_mut<F, T>(&self, f: F) -> T
    where
        F: FnOnce(&SqliteConnection) -> T,
    {
        let guard = self.conn.lock().expect("Poisoned mutex");
        f(&*guard)
    }

    /// The pool-internal ID of this connection.
    pub fn id(&self) -> usize {
        self.id
    }
}

// ============================================================================
// DBHandle — connection pool manager (port of Java DBHandle)
// ============================================================================

/// A thread-safe connection pool for SQLite.
///
/// Each connection in the pool is wrapped in `Arc<Mutex<Connection>>`.
/// Connections are distributed round-robin to spread load.
pub struct DBHandle {
    path: PathBuf,
    pool: Vec<Arc<Mutex<SqliteConnection>>>,
    pool_size: usize,
    next: AtomicUsize,
}

impl DBHandle {
    /// Open a database and create a pool of `pool_size` connections (minimum 1).
    pub fn open<P: AsRef<Path>>(path: P, pool_size: usize) -> SqlResult<Self> {
        let pool_size = pool_size.max(1);
        let mut pool = Vec::with_capacity(pool_size);
        let pragmas = "PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA foreign_keys=ON;";
        for _ in 0..pool_size {
            let conn = SqliteConnection::open(path.as_ref())?;
            conn.execute_batch(pragmas)?;
            pool.push(Arc::new(Mutex::new(conn)));
        }
        Ok(Self {
            path: path.as_ref().to_path_buf(),
            pool,
            pool_size,
            next: AtomicUsize::new(0),
        })
    }

    /// Create an in-memory database with a connection pool.
    ///
    /// Uses SQLite's shared-cache mode so all connections in the pool
    /// operate on the same in-memory database.
    pub fn in_memory(pool_size: usize) -> SqlResult<Self> {
        // Use a unique shared-cache URI so all connections see the same database.
        let uri = "file::memdb?mode=memory&cache=shared";
        Self::open(uri, pool_size)
    }

    /// Get a connection from the pool (round-robin).
    pub fn get_conn(&self) -> PooledConnection {
        let idx = self.next.fetch_add(1, Ordering::Relaxed) % self.pool_size;
        PooledConnection {
            conn: Arc::clone(&self.pool[idx]),
            id: idx,
        }
    }

    /// Execute a read operation on any pooled connection.
    pub fn read<F, T>(&self, f: F) -> DbResult<T>
    where
        F: FnOnce(&SqliteConnection) -> DbResult<T>,
    {
        let pooled = self.get_conn();
        let guard = pooled
            .conn
            .lock()
            .map_err(|e| DbError::Lock(format!("Mutex poisoned: {}", e)))?;
        f(&*guard)
    }

    /// Execute a write operation on any pooled connection.
    pub fn write<F, T>(&self, f: F) -> DbResult<T>
    where
        F: FnOnce(&SqliteConnection) -> DbResult<T>,
    {
        let pooled = self.get_conn();
        let guard = pooled
            .conn
            .lock()
            .map_err(|e| DbError::Lock(format!("Mutex poisoned: {}", e)))?;
        f(&*guard)
    }

    /// Execute a parameterised SQL statement. Returns rows modified.
    pub fn execute(&self, sql: &str, params: &[FieldValue]) -> DbResult<usize> {
        self.write(|conn| Ok(execute_values(conn, sql, params)?))
    }

    /// Execute a batch of SQL (no params).
    pub fn execute_batch(&self, sql: &str) -> DbResult<()> {
        self.write(|conn| {
            conn.execute_batch(sql)?;
            Ok(())
        })
    }

    /// Query with a custom row mapper.
    pub fn query<T, F>(&self, sql: &str, params: &[FieldValue], mapper: F) -> DbResult<Vec<T>>
    where
        F: Fn(&rusqlite::Row) -> SqlResult<T>,
    {
        self.read(|conn| {
            let mut stmt = conn.prepare(sql)?;
            let results: Vec<T> = stmt
                .query_map(params_to_slice(params).as_slice(), |row| mapper(row))?
                .filter_map(|r| r.ok())
                .collect();
            Ok(results)
        })
    }

    /// Create a table from a schema.
    pub fn create_table(&self, schema: &Schema) -> DbResult<()> {
        let sql = schema.to_create_table_sql();
        self.execute_batch(&sql)
    }

    /// Delete a table.
    pub fn delete_table(&self, table_name: &str) -> DbResult<()> {
        let sql = format!("DROP TABLE IF EXISTS {}", table_name);
        self.execute_batch(&sql)
    }

    /// Check whether a table exists.
    pub fn table_exists(&self, table_name: &str) -> DbResult<bool> {
        self.read(|conn| {
            let mut stmt = conn.prepare(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
            )?;
            let count: i64 = stmt.query_row(params![table_name], |row| row.get(0))?;
            Ok(count > 0)
        })
    }

    /// Return the names of all user tables.
    pub fn table_names(&self) -> DbResult<Vec<String>> {
        self.read(|conn| {
            let mut stmt = conn.prepare(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
            )?;
            let names: Vec<String> = stmt
                .query_map([], |row| row.get::<_, String>(0))?
                .filter_map(|r| r.ok())
                .collect();
            Ok(names)
        })
    }

    /// Create an index.
    pub fn create_index(&self, index: &Index) -> DbResult<()> {
        let sql = index.to_create_sql();
        self.execute_batch(&sql)
    }

    /// Drop an index.
    pub fn drop_index(&self, index: &Index) -> DbResult<()> {
        let sql = index.to_drop_sql();
        self.execute_batch(&sql)
    }

    /// Vacuum.
    pub fn vacuum(&self) -> DbResult<()> {
        self.execute_batch("VACUUM")
    }

    /// Backup to a file.
    pub fn backup_to<P: AsRef<Path>>(&self, dst_path: P) -> DbResult<()> {
        let mut dst = SqliteConnection::open(dst_path)?;
        self.read(|conn| {
            let backup = backup::Backup::new(conn, &mut dst)
                .map_err(|e| DbError::Backup(format!("{}", e)))?;
            backup
                .step(-1)
                .map_err(|e| DbError::Backup(format!("{}", e)))?;
            Ok(())
        })
    }

    /// Get the filesystem path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Number of connections in the pool.
    pub fn pool_size(&self) -> usize {
        self.pool_size
    }

    /// Close all connections.
    pub fn close(self) -> DbResult<()> {
        for conn_arc in self.pool {
            if let Ok(conn) = Arc::try_unwrap(conn_arc) {
                let conn = conn
                    .into_inner()
                    .map_err(|_| DbError::Lock("Mutex poisoned".into()))?;
                conn.close()
                    .map_err(|(_, e)| DbError::Sqlite(e))?;
            }
        }
        Ok(())
    }
}

impl fmt::Debug for DBHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DBHandle")
            .field("path", &self.path)
            .field("pool_size", &self.pool_size)
            .finish()
    }
}
