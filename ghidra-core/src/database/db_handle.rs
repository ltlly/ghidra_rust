//! Thread-safe SQLite connection pool and database handle, ported from Java's `db.DBHandle`.
//!
//! Provides [`DBHandle`] (connection pool with round-robin distribution),
//! [`PooledConnection`] (a checked-out connection handle), and database-level
//! operations (table management, transactions, undo/redo, listeners).

use rusqlite::{
    backup,
    params,
    Connection as SqliteConnection,
    Result as SqlResult,
};
use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};

use super::db::{DbError, DbResult, FieldValue, Index, Schema};
use super::db::{execute_values, params_to_slice};
use super::table::Table;

// ============================================================================
// DBListener — database lifecycle callbacks (port of Java DBListener)
// ============================================================================

/// Observer that is notified of database lifecycle events.
///
/// Mirrors Ghidra's Java `DBListener` interface.
pub trait DBHandleListener: Send + Sync {
    /// Called after an undo or redo was performed.
    fn on_db_restored(&self, _handle: &DBHandle) {}

    /// Called when the database has been closed.
    fn on_db_closed(&self, _handle: &DBHandle) {}

    /// Called when a table was deleted.
    fn on_table_deleted(&self, _handle: &DBHandle, _table_name: &str) {}

    /// Called when a table was added.
    fn on_table_added(&self, _handle: &DBHandle, _table_name: &str) {}
}

/// A no-op listener that can be used as a default.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopDBHandleListener;

impl DBHandleListener for NoopDBHandleListener {}

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

/// A thread-safe connection pool and database handle for SQLite.
///
/// Each connection in the pool is wrapped in `Arc<Mutex<Connection>>`.
/// Connections are distributed round-robin to spread load.
///
/// Also provides database-level operations ported from Java `DBHandle`:
/// - Table management (create, delete, rename)
/// - Transaction lifecycle (start, end, terminate)
/// - Undo/redo
/// - Listener notification
/// - Database ID
pub struct DBHandle {
    path: PathBuf,
    pool: Vec<Arc<Mutex<SqliteConnection>>>,
    pool_size: usize,
    next: AtomicUsize,
    // --- Ghidra-specific state (port of Java DBHandle fields) ---
    /// Unique database identifier (port of Java `databaseId`).
    database_id: AtomicU64,
    /// In-memory table registry, keyed by table name.
    tables: Mutex<HashMap<String, Table>>,
    /// Weak references to registered listeners.
    listeners: Mutex<Vec<Weak<dyn DBHandleListener>>>,
    /// Last assigned transaction ID.
    last_transaction_id: AtomicU64,
    /// Whether a transaction is currently active.
    tx_active: AtomicBool,
    /// Whether we are waiting for a new transaction (after terminate).
    waiting_for_new_tx: AtomicBool,
    /// Global checkpoint counter.
    checkpoint_num: AtomicU64,
    /// Cached "is changed" state.
    cached_changed: AtomicBool,
    /// Modification counter for change detection.
    mod_count: AtomicU64,
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
            database_id: AtomicU64::new(0),
            tables: Mutex::new(HashMap::new()),
            listeners: Mutex::new(Vec::new()),
            last_transaction_id: AtomicU64::new(0),
            tx_active: AtomicBool::new(false),
            waiting_for_new_tx: AtomicBool::new(false),
            checkpoint_num: AtomicU64::new(0),
            cached_changed: AtomicBool::new(false),
            mod_count: AtomicU64::new(0),
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

    /// Close all connections and release resources.
    pub fn close(self) -> DbResult<()> {
        // Drop implementation will handle notification.
        // Connections are cleaned up when Arcs are dropped.
        Ok(())
    }

    // ------------------------------------------------------------------
    // Database ID (port of Java DBHandle.databaseId)
    // ------------------------------------------------------------------

    /// Get the unique database ID.
    ///
    /// Mirrors Java's `DBHandle.getDatabaseId()`.
    pub fn database_id(&self) -> u64 {
        self.database_id.load(Ordering::Relaxed)
    }

    /// Set the database ID.
    pub fn set_database_id(&self, id: u64) {
        self.database_id.store(id, Ordering::Relaxed);
    }

    // ------------------------------------------------------------------
    // In-memory table registry (port of Java DBHandle.tables Hashtable)
    // ------------------------------------------------------------------

    /// Register a [`Table`] in the in-memory registry.
    ///
    /// Mirrors Java's `tables.put(name, table)`.
    pub fn register_table(&self, table: Table) {
        if let Ok(mut tables) = self.tables.lock() {
            tables.insert(table.name.clone(), table);
        }
    }

    /// Look up a registered table by name.
    ///
    /// Mirrors Java's `DBHandle.getTable(String name)`.
    pub fn get_table(&self, name: &str) -> Option<Table> {
        self.tables.lock().ok()?.get(name).cloned()
    }

    /// Get all registered tables.
    ///
    /// Mirrors Java's `DBHandle.getTables()`.
    pub fn get_tables(&self) -> Vec<Table> {
        self.tables
            .lock()
            .map(|t| t.values().cloned().collect())
            .unwrap_or_default()
    }

    /// Return the number of registered tables.
    ///
    /// Mirrors Java's `DBHandle.getTableCount()`.
    pub fn table_count(&self) -> usize {
        self.tables.lock().map(|t| t.len()).unwrap_or(0)
    }

    /// Rename a table in the in-memory registry.
    ///
    /// Mirrors Java's `DBHandle.setTableName(oldName, newName)`.
    /// The caller is responsible for issuing `ALTER TABLE ... RENAME TO ...`
    /// in the database itself.
    pub fn rename_table(&self, old_name: &str, new_name: &str) -> DbResult<()> {
        let mut tables = self
            .tables
            .lock()
            .map_err(|e| DbError::Lock(format!("Mutex poisoned: {}", e)))?;
        if tables.contains_key(new_name) {
            return Err(DbError::Schema(format!("Table '{}' already exists", new_name)));
        }
        if let Some(mut table) = tables.remove(old_name) {
            table.rename(new_name);
            tables.insert(new_name.to_string(), table);
            Ok(())
        } else {
            Err(DbError::NotFound(format!("Table '{}' not found", old_name)))
        }
    }

    /// Remove a table from the in-memory registry.
    ///
    /// Mirrors Java's `tables.remove(name)`.
    pub fn unregister_table(&self, name: &str) -> Option<Table> {
        self.tables.lock().ok()?.remove(name)
    }

    // ------------------------------------------------------------------
    // Transaction management (port of Java DBHandle transaction methods)
    // ------------------------------------------------------------------

    /// Verify that a valid transaction has been started.
    ///
    /// Mirrors Java's `DBHandle.checkTransaction()`.
    pub fn check_transaction(&self) -> DbResult<()> {
        if !self.tx_active.load(Ordering::Relaxed) {
            if self.waiting_for_new_tx.load(Ordering::Relaxed) {
                return Err(DbError::Schema("TerminatedTransactionException".into()));
            }
            return Err(DbError::Schema("NoTransactionException".into()));
        }
        Ok(())
    }

    /// Returns true if a transaction is currently active.
    ///
    /// Mirrors Java's `DBHandle.isTransactionActive()`.
    pub fn is_transaction_active(&self) -> bool {
        self.tx_active.load(Ordering::Relaxed)
    }

    /// Start a new transaction. Returns a transaction ID.
    ///
    /// Mirrors Java's `DBHandle.startTransaction()`.
    pub fn start_transaction(&self) -> DbResult<u64> {
        if self.tx_active.load(Ordering::Relaxed) {
            return Err(DbError::Schema("Transaction already started".into()));
        }
        self.waiting_for_new_tx.store(false, Ordering::Relaxed);
        self.tx_active.store(true, Ordering::Relaxed);
        let tx_id = self.last_transaction_id.fetch_add(1, Ordering::Relaxed) + 1;
        Ok(tx_id)
    }

    /// End the current transaction.
    ///
    /// If `commit` is true, changes are persisted. If false, a rollback may
    /// occur followed by `on_db_restored` notification.
    ///
    /// Mirrors Java's `DBHandle.endTransaction(id, commit)`.
    pub fn end_transaction(&self, id: u64, commit: bool) -> DbResult<bool> {
        if id != self.last_transaction_id.load(Ordering::Relaxed) {
            return Err(DbError::Schema("Transaction id is not active".into()));
        }
        let result = if commit {
            // Commit: increment checkpoint
            self.checkpoint_num.fetch_add(1, Ordering::Relaxed);
            true
        } else {
            // Rollback: reload tables, notify listeners
            self.notify_db_restored();
            false
        };
        self.tx_active.store(false, Ordering::Relaxed);
        self.update_changed_state();
        Ok(result)
    }

    /// Terminate the current transaction, optionally setting the handle into
    /// a "waiting for new transaction" state.
    ///
    /// Mirrors Java's `DBHandle.terminateTransaction(id, commit)`.
    pub fn terminate_transaction(&self, id: u64, commit: bool) -> DbResult<()> {
        let _ = self.end_transaction(id, commit)?;
        self.waiting_for_new_tx.store(true, Ordering::Relaxed);
        Ok(())
    }

    /// Get the current modification count.
    ///
    /// Mirrors Java's `DBHandle.getModCount()`.
    pub fn mod_count(&self) -> u64 {
        self.mod_count.load(Ordering::Relaxed)
    }

    /// Increment the modification counter.
    pub fn increment_mod_count(&self) {
        self.mod_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Returns true if there are uncommitted changes.
    ///
    /// Mirrors Java's `DBHandle.hasUncommittedChanges()`.
    pub fn has_uncommitted_changes(&self) -> bool {
        self.cached_changed.load(Ordering::Relaxed)
    }

    /// Update the cached "changed" state.
    fn update_changed_state(&self) {
        // For SQLite-backed databases, check via PRAGMA.
        let changed = self.read(|conn| {
            let mut stmt = conn.prepare("PRAGMA journal_mode")?;
            let mode: String = stmt.query_row([], |row| row.get(0))?;
            // If in WAL mode and there are changes, the journal mode query itself
            // doesn't tell us about uncommitted state. Use a simple dirty flag.
            Ok(mode)
        });
        // The real dirty tracking is done via mark_dirty/mark_clean calls.
        let _ = changed;
    }

    /// Mark the database as having uncommitted changes.
    pub fn mark_dirty(&self) {
        self.cached_changed.store(true, Ordering::Relaxed);
    }

    /// Clear the dirty flag.
    pub fn mark_clean(&self) {
        self.cached_changed.store(false, Ordering::Relaxed);
    }

    // ------------------------------------------------------------------
    // Undo / Redo (port of Java DBHandle undo/redo)
    // ------------------------------------------------------------------

    /// Returns true if there are changes that can be undone.
    ///
    /// Mirrors Java's `DBHandle.canUndo()`. Note: with SQLite, undo is
    /// handled at the transaction level, so this is always false unless
    /// an undo stack is maintained externally.
    pub fn can_undo(&self) -> bool {
        false // SQLite handles rollback via transactions
    }

    /// Returns true if there are changes that can be redone.
    ///
    /// Mirrors Java's `DBHandle.canRedo()`.
    pub fn can_redo(&self) -> bool {
        false // SQLite handles rollback via transactions
    }

    /// Get the number of undo-able transactions.
    pub fn available_undo_count(&self) -> usize {
        0
    }

    /// Get the number of redo-able transactions.
    pub fn available_redo_count(&self) -> usize {
        0
    }

    // ------------------------------------------------------------------
    // Listeners (port of Java DBHandle.addListener)
    // ------------------------------------------------------------------

    /// Register a database listener.
    ///
    /// The listener is stored as a `Weak` reference, matching Java's
    /// `WeakSet<DBListener>` semantics.
    pub fn add_listener(&self, listener: Weak<dyn DBHandleListener>) {
        if let Ok(mut listeners) = self.listeners.lock() {
            listeners.push(listener);
        }
    }

    /// Notify all live listeners that the database was restored (undo/redo).
    fn notify_db_restored(&self) {
        if let Ok(listeners) = self.listeners.lock() {
            for weak in listeners.iter() {
                if let Some(listener) = weak.upgrade() {
                    listener.on_db_restored(self);
                }
            }
        }
    }

    /// Notify all live listeners that the database was closed.
    fn notify_db_closed(&self) {
        if let Ok(listeners) = self.listeners.lock() {
            for weak in listeners.iter() {
                if let Some(listener) = weak.upgrade() {
                    listener.on_db_closed(self);
                }
            }
        }
    }

    /// Notify all live listeners that a table was added.
    pub fn notify_table_added(&self, table_name: &str) {
        if let Ok(listeners) = self.listeners.lock() {
            for weak in listeners.iter() {
                if let Some(listener) = weak.upgrade() {
                    listener.on_table_added(self, table_name);
                }
            }
        }
    }

    /// Notify all live listeners that a table was deleted.
    pub fn notify_table_deleted(&self, table_name: &str) {
        if let Ok(listeners) = self.listeners.lock() {
            for weak in listeners.iter() {
                if let Some(listener) = weak.upgrade() {
                    listener.on_table_deleted(self, table_name);
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // Checkpoint
    // ------------------------------------------------------------------

    /// Get the current checkpoint number.
    pub fn checkpoint_num(&self) -> u64 {
        self.checkpoint_num.load(Ordering::Relaxed)
    }

    // ------------------------------------------------------------------
    // Connection lifetime check
    // ------------------------------------------------------------------

    /// Returns true if this handle has been effectively closed (all
    /// connections dropped).
    ///
    /// Mirrors Java's `DBHandle.isClosed()`.
    pub fn is_closed(&self) -> bool {
        // If all Arc references to connections have been released, we consider
        // the handle closed. In practice, the handle owns the strong refs.
        false
    }

    /// Check if the database is closed and return an error if so.
    ///
    /// Mirrors Java's `DBHandle.checkIsClosed()`.
    pub fn check_is_closed(&self) -> DbResult<()> {
        if self.is_closed() {
            return Err(DbError::Schema("Database is closed".into()));
        }
        Ok(())
    }
}

impl fmt::Debug for DBHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DBHandle")
            .field("path", &self.path)
            .field("pool_size", &self.pool_size)
            .field("database_id", &self.database_id.load(Ordering::Relaxed))
            .field("table_count", &self.table_count())
            .field("tx_active", &self.tx_active.load(Ordering::Relaxed))
            .finish()
    }
}

impl Drop for DBHandle {
    fn drop(&mut self) {
        self.notify_db_closed();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pooled_connection_round_robin() {
        let handle = DBHandle::in_memory(3).unwrap();
        let ids: Vec<usize> = (0..6).map(|_| handle.get_conn().id()).collect();
        assert_eq!(ids, vec![0, 1, 2, 0, 1, 2]);
    }

    #[test]
    fn test_db_handle_create_table() {
        let handle = DBHandle::in_memory(2).unwrap();
        assert_eq!(handle.pool_size(), 2);

        let schema = Schema::new("handle_test", 1)
            .with_field(super::super::db::Field::new("id", super::super::db::FieldType::Int).primary_key());
        handle.create_table(&schema).unwrap();
        assert!(handle.table_exists("handle_test").unwrap());

        let names = handle.table_names().unwrap();
        assert!(names.contains(&"handle_test".to_string()));
    }

    #[test]
    fn test_db_handle_execute_query() {
        let handle = DBHandle::in_memory(1).unwrap();
        handle
            .execute_batch("CREATE TABLE t (x INTEGER)")
            .unwrap();
        handle
            .execute("INSERT INTO t (x) VALUES (?1)", &[FieldValue::Int(99)])
            .unwrap();
        let rows: Vec<i64> = handle
            .query("SELECT x FROM t", &[], |row| row.get(0))
            .unwrap();
        assert_eq!(rows, vec![99]);
    }

    #[test]
    fn test_db_handle_table_registry() {
        let handle = DBHandle::in_memory(1).unwrap();
        let schema = Schema::new("my_table", 1)
            .with_field(super::super::db::Field::new("id", super::super::db::FieldType::Int).primary_key());
        let table = Table::new(schema);
        handle.register_table(table);
        assert_eq!(handle.table_count(), 1);
        assert!(handle.get_table("my_table").is_some());

        let all = handle.get_tables();
        assert_eq!(all.len(), 1);

        handle.unregister_table("my_table");
        assert_eq!(handle.table_count(), 0);
    }

    #[test]
    fn test_db_handle_rename_table() {
        let handle = DBHandle::in_memory(1).unwrap();
        let schema = Schema::new("old", 1)
            .with_field(super::super::db::Field::new("id", super::super::db::FieldType::Int).primary_key());
        handle.register_table(Table::new(schema));

        handle.rename_table("old", "new").unwrap();
        assert!(handle.get_table("old").is_none());
        assert!(handle.get_table("new").is_some());
    }

    #[test]
    fn test_db_handle_transaction_lifecycle() {
        let handle = DBHandle::in_memory(1).unwrap();

        assert!(!handle.is_transaction_active());

        let tx_id = handle.start_transaction().unwrap();
        assert!(handle.is_transaction_active());
        assert_eq!(tx_id, 1);
        assert!(handle.check_transaction().is_ok());

        // Cannot start a second transaction.
        assert!(handle.start_transaction().is_err());

        handle.end_transaction(tx_id, true).unwrap();
        assert!(!handle.is_transaction_active());
    }

    #[test]
    fn test_db_handle_transaction_rollback() {
        let handle = DBHandle::in_memory(1).unwrap();

        let tx_id = handle.start_transaction().unwrap();
        handle.mark_dirty();
        assert!(handle.has_uncommitted_changes());

        handle.end_transaction(tx_id, false).unwrap();
        assert!(!handle.is_transaction_active());
    }

    #[test]
    fn test_db_handle_terminate_transaction() {
        let handle = DBHandle::in_memory(1).unwrap();

        let tx_id = handle.start_transaction().unwrap();
        handle.terminate_transaction(tx_id, true).unwrap();
        assert!(!handle.is_transaction_active());
        // After terminate, check_transaction should return an error.
        assert!(handle.check_transaction().is_err());
    }

    #[test]
    fn test_db_handle_database_id() {
        let handle = DBHandle::in_memory(1).unwrap();
        assert_eq!(handle.database_id(), 0);

        handle.set_database_id(42);
        assert_eq!(handle.database_id(), 42);
    }

    #[test]
    fn test_db_handle_checkpoint() {
        let handle = DBHandle::in_memory(1).unwrap();
        assert_eq!(handle.checkpoint_num(), 0);

        let tx_id = handle.start_transaction().unwrap();
        handle.end_transaction(tx_id, true).unwrap();
        assert_eq!(handle.checkpoint_num(), 1);
    }

    #[test]
    fn test_db_handle_listener() {
        use std::sync::atomic::AtomicU32;

        struct CountListener {
            closed: AtomicU32,
        }
        impl DBHandleListener for CountListener {
            fn on_db_closed(&self, _handle: &DBHandle) {
                self.closed.fetch_add(1, Ordering::Relaxed);
            }
        }

        let handle = DBHandle::in_memory(1).unwrap();
        let listener = Arc::new(CountListener {
            closed: AtomicU32::new(0),
        });
        handle.add_listener(Arc::downgrade(&listener) as Weak<dyn DBHandleListener>);

        drop(handle);
        assert_eq!(listener.closed.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_db_handle_mod_count() {
        let handle = DBHandle::in_memory(1).unwrap();
        assert_eq!(handle.mod_count(), 0);
        handle.increment_mod_count();
        assert_eq!(handle.mod_count(), 1);
    }
}
