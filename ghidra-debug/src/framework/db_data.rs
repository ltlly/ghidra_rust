//! Database domain data types ported from ghidra.framework.data.
//!
//! Provides data manager types for trace databases.

/// Marker trait for database-managed objects.
pub trait DBTraceManager: std::fmt::Debug {
    /// Called when a database error occurs.
    fn db_error(&self, _error: &std::io::Error) {}

    /// Invalidate cached data.
    fn invalidate_cache(&mut self, _all: bool) {}
}

/// Configuration for opening a trace database.
#[derive(Debug, Clone)]
pub struct OpenMode {
    /// Whether the database is read-only.
    pub read_only: bool,
    /// Whether to upgrade if needed.
    pub upgrade: bool,
}

impl Default for OpenMode {
    fn default() -> Self {
        Self {
            read_only: false,
            upgrade: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_open_mode() {
        let mode = OpenMode::default();
        assert!(!mode.read_only);
        assert!(mode.upgrade);
    }
}
