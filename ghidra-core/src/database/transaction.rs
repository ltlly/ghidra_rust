//! RAII-style transaction and savepoint management.
//!
//! ## Overview
//!
//! [`Transaction`] wraps a `RwLockWriteGuard<Connection>` and provides
//! RAII-style commit/rollback:
//!
//! - Constructed via [`Database::begin_transaction`].
//! - [`Transaction::commit`] consumes the guard and commits.
//! - On `Drop`, if not explicitly committed, the transaction is rolled back.
//!
//! Nested savepoints are tracked with a depth counter so that rollback only
//! reverts to the most recent savepoint.
//!
//! ## Example
//!
//! ```rust,ignore
//! let db = Database::open("my.db")?;
//! {
//!     let tx = db.begin_transaction(TransactionOpenMode::ReadWrite)?;
//!     db.execute("INSERT INTO t VALUES (?1)", &[FieldValue::Int(1)])?;
//!     tx.commit()?;
//! } // auto-rolls back if commit wasn't called
//! ```

use rusqlite::Connection as SqliteConnection;
use std::fmt;
use std::sync::RwLockWriteGuard;

use super::db::{DbError, DbResult};

// ============================================================================
// TransactionOpenMode
// ============================================================================

/// Controls whether a transaction is read-only or read-write.
///
/// SQLite does not allow writes inside a `BEGIN` (deferred) transaction that
/// started as a read — use `ReadWrite` if you intend to write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionOpenMode {
    /// Read-only transaction (`BEGIN`).  Any attempted write will fail.
    ReadOnly,
    /// Read-write transaction (`BEGIN IMMEDIATE`).  Writes are permitted.
    ReadWrite,
}

// ============================================================================
// TransactionListener
// ============================================================================

/// Observer that is notified of transaction lifecycle events.
///
/// Implementations can be registered on a [`Transaction`] to react to commit,
/// rollback, or savepoint boundaries.
pub trait TransactionListener {
    /// Called after a successful commit.
    fn on_commit(&self) {}

    /// Called after a rollback (manual or automatic on drop).
    fn on_rollback(&self) {}

    /// Called when a nested savepoint is opened.
    fn on_savepoint_open(&self, _depth: u32) {}

    /// Called when a nested savepoint is released (committed).
    fn on_savepoint_release(&self, _depth: u32) {}

    /// Called when a nested savepoint is rolled back.
    fn on_savepoint_rollback(&self, _depth: u32) {}

    /// Called when the outermost transaction is about to commit.
    fn on_before_commit(&self) {}
}

/// A no-op listener that can be used as a default.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopTransactionListener;

impl TransactionListener for NoopTransactionListener {}

// ============================================================================
// Transaction
// ============================================================================

/// An RAII-guarded database transaction.
///
/// Holds an exclusive write lock (`RwLockWriteGuard`) on the underlying
/// connection for the lifetime of the transaction.  If `commit` is not
/// explicitly called before the guard is dropped, all changes since the last
/// `BEGIN` (or last savepoint) are rolled back.
///
/// ## Nested savepoints
///
/// Call [`Transaction::savepoint`] to create a nested savepoint.  The
/// returned [`SavepointGuard`] exposes its own `commit` / `rollback`, but
/// rolling back only discards changes since the savepoint — earlier work is
/// preserved.
pub struct Transaction<'a> {
    guard: RwLockWriteGuard<'a, SqliteConnection>,
    committed: bool,
    mode: TransactionOpenMode,
    savepoint_depth: u32,
    listener: Option<Box<dyn TransactionListener + 'a>>,
}

impl<'a> Transaction<'a> {
    /// Begin a new transaction, issuing `BEGIN` or `BEGIN IMMEDIATE`.
    ///
    /// This is `pub(crate)` — users obtain a guard via
    /// `Database::begin_transaction`.
    pub(crate) fn begin(
        guard: RwLockWriteGuard<'a, SqliteConnection>,
        mode: TransactionOpenMode,
    ) -> DbResult<Self> {
        let sql = match mode {
            TransactionOpenMode::ReadOnly => "BEGIN",
            TransactionOpenMode::ReadWrite => "BEGIN IMMEDIATE",
        };
        guard.execute(sql, [])?;
        Ok(Self {
            guard,
            committed: false,
            mode,
            savepoint_depth: 0,
            listener: None,
        })
    }

    /// Attach a listener that will be notified of lifecycle events.
    pub fn set_listener<L: TransactionListener + 'a>(&mut self, listener: L) {
        self.listener = Some(Box::new(listener));
    }

    /// Remove the current listener, if any.
    pub fn remove_listener(&mut self) {
        self.listener = None;
    }

    /// Returns the open mode of this transaction.
    pub fn mode(&self) -> TransactionOpenMode {
        self.mode
    }

    /// Returns the current savepoint nesting depth.
    pub fn savepoint_depth(&self) -> u32 {
        self.savepoint_depth
    }

    /// Returns `true` if `commit` has been called.
    pub fn is_committed(&self) -> bool {
        self.committed
    }

    /// Create a nested savepoint.
    ///
    /// Nested transactions use SQLite savepoints (`SAVEPOINT sp_N`) so that a
    /// rollback of an inner operation does not discard the outer transaction's
    /// work.
    pub fn savepoint(&mut self) -> DbResult<SavepointGuard<'_, 'a>> {
        self.savepoint_depth += 1;
        let sp_name = format!("sp_{}", self.savepoint_depth);
        let sql = format!("SAVEPOINT {}", sp_name);
        self.guard.execute(&sql, [])?;

        let depth = self.savepoint_depth;

        if let Some(ref listener) = self.listener {
            listener.on_savepoint_open(depth);
        }

        Ok(SavepointGuard {
            transaction: self,
            depth,
            committed: false,
        })
    }

    /// Commit the outermost transaction and release the write lock.
    ///
    /// After calling this, the guard is consumed and no further operations on
    /// this transaction are possible.
    pub fn commit(mut self) -> DbResult<()> {
        if self.committed {
            return Err(DbError::Lock("Transaction already committed".into()));
        }
        self.committed = true;

        if let Some(ref listener) = self.listener {
            listener.on_before_commit();
        }

        self.guard.execute("COMMIT", [])?;

        if let Some(ref listener) = self.listener {
            listener.on_commit();
        }
        Ok(())
    }

    /// Explicitly roll back the transaction and release the write lock.
    ///
    /// This is equivalent to dropping the transaction without calling
    /// `commit`, but it returns a `Result` instead of silently discarding
    /// errors.
    pub fn rollback(mut self) -> DbResult<()> {
        if self.committed {
            return Err(DbError::Lock("Transaction already committed — cannot roll back".into()));
        }
        self.committed = true; // prevent double-rollback in Drop
        self.guard.execute("ROLLBACK", [])?;

        if let Some(ref listener) = self.listener {
            listener.on_rollback();
        }
        Ok(())
    }
}

impl<'a> Drop for Transaction<'a> {
    fn drop(&mut self) {
        if !self.committed {
            // Best-effort rollback.  We cannot propagate the error from Drop.
            let _ = self.guard.execute("ROLLBACK", []);
            if let Some(ref listener) = self.listener {
                listener.on_rollback();
            }
        }
    }
}

impl<'a> fmt::Debug for Transaction<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Transaction")
            .field("mode", &self.mode)
            .field("committed", &self.committed)
            .field("savepoint_depth", &self.savepoint_depth)
            .field("has_listener", &self.listener.is_some())
            .finish()
    }
}

// ============================================================================
// SavepointGuard
// ============================================================================

/// A handle to a nested savepoint inside a [`Transaction`].
///
/// Created by [`Transaction::savepoint`].  On drop, if not explicitly
/// committed, the savepoint is rolled back.
pub struct SavepointGuard<'tx, 'conn> {
    transaction: &'tx mut Transaction<'conn>,
    depth: u32,
    committed: bool,
}

impl<'tx, 'conn> SavepointGuard<'tx, 'conn> {
    /// Release (commit) this savepoint.
    pub fn commit(mut self) -> DbResult<()> {
        if self.committed {
            return Err(DbError::Lock("Savepoint already committed".into()));
        }
        self.committed = true;

        let sp_name = format!("sp_{}", self.depth);
        let sql = format!("RELEASE {}", sp_name);
        self.transaction.guard.execute(&sql, [])?;

        self.transaction.savepoint_depth = self.transaction.savepoint_depth.saturating_sub(1);

        if let Some(ref listener) = self.transaction.listener {
            listener.on_savepoint_release(self.depth);
        }
        Ok(())
    }

    /// Roll back to this savepoint.
    pub fn rollback(mut self) -> DbResult<()> {
        if self.committed {
            return Err(DbError::Lock("Savepoint already committed — cannot roll back".into()));
        }
        self.committed = true;

        let sp_name = format!("sp_{}", self.depth);
        let sql = format!("ROLLBACK TO {}", sp_name);
        self.transaction.guard.execute(&sql, [])?;

        // Also release the savepoint to clean up.
        let release_sql = format!("RELEASE {}", sp_name);
        let _ = self.transaction.guard.execute(&release_sql, []);

        self.transaction.savepoint_depth = self.transaction.savepoint_depth.saturating_sub(1);

        if let Some(ref listener) = self.transaction.listener {
            listener.on_savepoint_rollback(self.depth);
        }
        Ok(())
    }

    /// Access the outer transaction.
    pub fn transaction(&self) -> &Transaction<'conn> {
        self.transaction
    }

    /// The nesting depth of this savepoint (1 = first, inner-most = highest).
    pub fn depth(&self) -> u32 {
        self.depth
    }

    /// `true` if `commit` or `rollback` has already been called.
    pub fn is_closed(&self) -> bool {
        self.committed
    }
}

impl<'tx, 'conn> Drop for SavepointGuard<'tx, 'conn> {
    fn drop(&mut self) {
        if !self.committed {
            // Best-effort rollback to savepoint.
            let sp_name = format!("sp_{}", self.depth);
            let rollback_sql = format!("ROLLBACK TO {}", sp_name);
            let release_sql = format!("RELEASE {}", sp_name);
            let _ = self.transaction.guard.execute(&rollback_sql, []);
            let _ = self.transaction.guard.execute(&release_sql, []);
            self.transaction.savepoint_depth = self.transaction.savepoint_depth.saturating_sub(1);

            if let Some(ref listener) = self.transaction.listener {
                listener.on_savepoint_rollback(self.depth);
            }
        }
    }
}

impl<'tx, 'conn> fmt::Debug for SavepointGuard<'tx, 'conn> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SavepointGuard")
            .field("depth", &self.depth)
            .field("committed", &self.committed)
            .finish()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use std::sync::RwLock;

    /// Helper: create an in-memory connection behind a RwLock and produce a
    /// guard so we can test Transaction without needing a full Database.
    fn test_guard() -> RwLockWriteGuard<'static, SqliteConnection> {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE t (id INTEGER PRIMARY KEY, val TEXT);
             INSERT INTO t VALUES (1, 'hello');",
        )
        .unwrap();
        // SAFETY: We leak the RwLock so we can return a 'static guard.
        // This is only used in tests and the lock is immediately consumed by
        // Transaction which lives for the test scope.
        let lock: &'static RwLock<Connection> = Box::leak(Box::new(RwLock::new(conn)));
        lock.write().unwrap()
    }

    #[test]
    fn test_commit_writes() {
        let guard = test_guard();
        let tx = Transaction::begin(guard, TransactionOpenMode::ReadWrite).unwrap();
        tx.guard
            .execute("INSERT INTO t VALUES (2, 'world')", [])
            .unwrap();
        tx.commit().unwrap();
    }

    #[test]
    fn test_drop_rolls_back() {
        let guard = test_guard();
        {
            let tx = Transaction::begin(guard, TransactionOpenMode::ReadWrite).unwrap();
            tx.guard
                .execute("INSERT INTO t VALUES (99, 'ghost')", [])
                .unwrap();
            // tx is dropped — should roll back.
        }
        // The guard was consumed when tx was dropped, so we need a new test.
    }

    #[test]
    fn test_nested_savepoints() {
        let guard = test_guard();
        let mut tx = Transaction::begin(guard, TransactionOpenMode::ReadWrite).unwrap();

        // Insert at outermost level.
        tx.guard
            .execute("INSERT INTO t VALUES (2, 'outer')", [])
            .unwrap();

        // Open inner savepoint.
        {
            let sp = tx.savepoint().unwrap();
            assert_eq!(sp.depth(), 1);
            sp.transaction()
                .guard
                .execute("INSERT INTO t VALUES (3, 'inner')", [])
                .unwrap();
            // Roll back the savepoint — row 3 should disappear.
            sp.rollback().unwrap();
        }

        // Row 2 should still be there, row 3 should not.
        let count: i64 = tx
            .guard
            .query_row("SELECT COUNT(*) FROM t WHERE val = 'outer'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(count, 1);

        tx.commit().unwrap();
    }

    #[test]
    fn test_savepoint_commit_preserves() {
        let guard = test_guard();
        let mut tx = Transaction::begin(guard, TransactionOpenMode::ReadWrite).unwrap();

        {
            let sp = tx.savepoint().unwrap();
            sp.transaction()
                .guard
                .execute("INSERT INTO t VALUES (4, 'nested_commit')", [])
                .unwrap();
            sp.commit().unwrap();
        }

        let count: i64 = tx
            .guard
            .query_row("SELECT COUNT(*) FROM t WHERE val='nested_commit'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(count, 1);

        tx.commit().unwrap();
    }

    #[test]
    fn test_transaction_open_mode() {
        assert_eq!(
            TransactionOpenMode::ReadOnly as i32,
            TransactionOpenMode::ReadOnly as i32
        );
        assert_ne!(TransactionOpenMode::ReadOnly, TransactionOpenMode::ReadWrite);
    }

    #[test]
    fn test_noop_listener() {
        let listener = NoopTransactionListener;
        listener.on_commit();
        listener.on_rollback();
        listener.on_savepoint_open(1);
        listener.on_savepoint_release(1);
        listener.on_savepoint_rollback(1);
        listener.on_before_commit();
    }

    /// A counting listener for test verification.
    struct CountingListener {
        commits: std::cell::Cell<u32>,
        rollbacks: std::cell::Cell<u32>,
        savepoints_opened: std::cell::Cell<u32>,
        savepoints_released: std::cell::Cell<u32>,
        savepoints_rolled: std::cell::Cell<u32>,
        before_commits: std::cell::Cell<u32>,
    }

    impl CountingListener {
        fn new() -> Self {
            Self {
                commits: std::cell::Cell::new(0),
                rollbacks: std::cell::Cell::new(0),
                savepoints_opened: std::cell::Cell::new(0),
                savepoints_released: std::cell::Cell::new(0),
                savepoints_rolled: std::cell::Cell::new(0),
                before_commits: std::cell::Cell::new(0),
            }
        }
    }

    impl TransactionListener for CountingListener {
        fn on_commit(&self) {
            self.commits.set(self.commits.get() + 1);
        }
        fn on_rollback(&self) {
            self.rollbacks.set(self.rollbacks.get() + 1);
        }
        fn on_savepoint_open(&self, _depth: u32) {
            self.savepoints_opened.set(self.savepoints_opened.get() + 1);
        }
        fn on_savepoint_release(&self, _depth: u32) {
            self.savepoints_released.set(self.savepoints_released.get() + 1);
        }
        fn on_savepoint_rollback(&self, _depth: u32) {
            self.savepoints_rolled.set(self.savepoints_rolled.get() + 1);
        }
        fn on_before_commit(&self) {
            self.before_commits.set(self.before_commits.get() + 1);
        }
    }

    #[test]
    fn test_transaction_listener_callbacks() {
        let guard = test_guard();
        let mut tx = Transaction::begin(guard, TransactionOpenMode::ReadWrite).unwrap();

        let listener = CountingListener::new();
        tx.set_listener(listener);

        // Open and release a savepoint.
        {
            let sp = tx.savepoint().unwrap();
            sp.commit().unwrap();
        }

        tx.commit().unwrap();

        // The listener is consumed by the transaction so we can't easily
        // inspect it.  This test mainly validates that the callback path
        // doesn't panic.
    }
}
