//! Database-backed bookmark storage.
//!
//! Provides SQLite-backed bookmark operations for the trace database.

use rusqlite::{params, Connection, Result as SqlResult};

use crate::model::{
    bookmark::{TraceBookmark, TraceBookmarkManager, TraceBookmarkType},
    Lifespan,
};

/// Extension trait for adding bookmark table operations to a SQLite connection.
pub trait TraceBookmarkDbExt {
    /// Create the bookmarks table.
    fn create_bookmark_tables(&self) -> SqlResult<()>;

    /// Insert a bookmark.
    fn insert_bookmark(&self, bookmark: &TraceBookmark) -> SqlResult<()>;

    /// Load all bookmarks into the given manager.
    fn load_bookmarks(&self, manager: &mut TraceBookmarkManager) -> SqlResult<()>;

    /// Delete a bookmark by key.
    fn delete_bookmark(&self, key: i64) -> SqlResult<bool>;

    /// Update a bookmark's lifespan.
    fn update_bookmark_lifespan(&self, key: i64, lifespan: &Lifespan) -> SqlResult<()>;

    /// Update a bookmark's comment.
    fn update_bookmark_comment(&self, key: i64, comment: &str) -> SqlResult<()>;
}

impl TraceBookmarkDbExt for Connection {
    fn create_bookmark_tables(&self) -> SqlResult<()> {
        self.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS trace_bookmarks (
                key INTEGER PRIMARY KEY,
                address INTEGER NOT NULL,
                min_snap INTEGER NOT NULL,
                max_snap INTEGER NOT NULL,
                bookmark_type TEXT NOT NULL,
                category TEXT NOT NULL DEFAULT '',
                comment TEXT NOT NULL DEFAULT '',
                thread_key INTEGER
            );
            CREATE INDEX IF NOT EXISTS idx_bookmarks_snap ON trace_bookmarks(min_snap, max_snap);
            CREATE INDEX IF NOT EXISTS idx_bookmarks_address ON trace_bookmarks(address);
            ",
        )?;
        Ok(())
    }

    fn insert_bookmark(&self, bookmark: &TraceBookmark) -> SqlResult<()> {
        self.execute(
            "INSERT INTO trace_bookmarks (key, address, min_snap, max_snap, bookmark_type, category, comment, thread_key) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                bookmark.key,
                bookmark.address as i64,
                bookmark.lifespan.lmin(),
                bookmark.lifespan.lmax(),
                format!("{:?}", bookmark.bookmark_type),
                bookmark.category,
                bookmark.comment,
                bookmark.thread_key,
            ],
        )?;
        Ok(())
    }

    fn load_bookmarks(&self, manager: &mut TraceBookmarkManager) -> SqlResult<()> {
        let mut stmt = self.prepare(
            "SELECT key, address, min_snap, max_snap, bookmark_type, category, comment, thread_key FROM trace_bookmarks",
        )?;
        let rows = stmt.query_map([], |row| {
            let key: i64 = row.get(0)?;
            let address: i64 = row.get(1)?;
            let min_snap: i64 = row.get(2)?;
            let max_snap: i64 = row.get(3)?;
            let type_str: String = row.get(4)?;
            let category: String = row.get(5)?;
            let comment: String = row.get(6)?;
            let thread_key: Option<i64> = row.get(7)?;

            let bookmark_type = match type_str.as_str() {
                "Note" => TraceBookmarkType::Note,
                "Warning" => TraceBookmarkType::Warning,
                "Error" => TraceBookmarkType::Error,
                "Analysis" => TraceBookmarkType::Analysis,
                "Type" => TraceBookmarkType::Type,
                _ => TraceBookmarkType::Note,
            };

            Ok(TraceBookmark {
                key,
                address: address as u64,
                lifespan: Lifespan::span(min_snap, max_snap),
                bookmark_type,
                category,
                comment,
                thread_key,
            })
        })?;

        for row in rows {
            let bookmark = row?;
            manager.add_bookmark_with_key(bookmark);
        }
        Ok(())
    }

    fn delete_bookmark(&self, key: i64) -> SqlResult<bool> {
        let count = self.execute(
            "DELETE FROM trace_bookmarks WHERE key = ?1",
            params![key],
        )?;
        Ok(count > 0)
    }

    fn update_bookmark_lifespan(&self, key: i64, lifespan: &Lifespan) -> SqlResult<()> {
        self.execute(
            "UPDATE trace_bookmarks SET min_snap = ?1, max_snap = ?2 WHERE key = ?3",
            params![lifespan.lmin(), lifespan.lmax(), key],
        )?;
        Ok(())
    }

    fn update_bookmark_comment(&self, key: i64, comment: &str) -> SqlResult<()> {
        self.execute(
            "UPDATE trace_bookmarks SET comment = ?1 WHERE key = ?2",
            params![comment, key],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    #[test]
    fn test_create_tables() {
        let conn = Connection::open_in_memory().unwrap();
        conn.create_bookmark_tables().unwrap();
    }

    #[test]
    fn test_insert_and_load() {
        let conn = Connection::open_in_memory().unwrap();
        conn.create_bookmark_tables().unwrap();

        let bookmark = TraceBookmark::new(
            1,
            0x400000,
            Lifespan::at(0),
            TraceBookmarkType::Note,
            "test",
            "a note",
        );
        conn.insert_bookmark(&bookmark).unwrap();

        let mut mgr = TraceBookmarkManager::new();
        conn.load_bookmarks(&mut mgr).unwrap();

        assert_eq!(mgr.len(), 1);
        let loaded = mgr.get(1).unwrap();
        assert_eq!(loaded.address, 0x400000);
        assert_eq!(loaded.bookmark_type, TraceBookmarkType::Note);
    }

    #[test]
    fn test_delete_bookmark() {
        let conn = Connection::open_in_memory().unwrap();
        conn.create_bookmark_tables().unwrap();

        let bookmark = TraceBookmark::new(
            1,
            0x400000,
            Lifespan::at(0),
            TraceBookmarkType::Error,
            "",
            "error msg",
        );
        conn.insert_bookmark(&bookmark).unwrap();
        assert!(conn.delete_bookmark(1).unwrap());
        assert!(!conn.delete_bookmark(999).unwrap());
    }

    #[test]
    fn test_update_comment() {
        let conn = Connection::open_in_memory().unwrap();
        conn.create_bookmark_tables().unwrap();

        let bookmark = TraceBookmark::new(
            1,
            0x400000,
            Lifespan::at(0),
            TraceBookmarkType::Warning,
            "",
            "old comment",
        );
        conn.insert_bookmark(&bookmark).unwrap();
        conn.update_bookmark_comment(1, "new comment").unwrap();

        let mut mgr = TraceBookmarkManager::new();
        conn.load_bookmarks(&mut mgr).unwrap();
        assert_eq!(mgr.get(1).unwrap().comment, "new comment");
    }

    #[test]
    fn test_update_lifespan() {
        let conn = Connection::open_in_memory().unwrap();
        conn.create_bookmark_tables().unwrap();

        let bookmark = TraceBookmark::new(
            1,
            0x400000,
            Lifespan::span(0, 5),
            TraceBookmarkType::Note,
            "",
            "",
        );
        conn.insert_bookmark(&bookmark).unwrap();
        conn.update_bookmark_lifespan(1, &Lifespan::span(0, 10)).unwrap();

        let mut mgr = TraceBookmarkManager::new();
        conn.load_bookmarks(&mut mgr).unwrap();
        assert_eq!(mgr.get(1).unwrap().lifespan, Lifespan::span(0, 10));
    }
}
