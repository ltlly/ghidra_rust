//! Table statistics ported from Java's `db.TableStatistics`.

use std::fmt;

/// Diagnostic statistics for a database table.
///
/// Port of Java `db.TableStatistics`.
#[derive(Debug, Clone, Default)]
pub struct TableStatistics {
    /// Table name.
    pub name: String,
    /// Number of data buffers.
    pub buffer_count: usize,
    /// Number of interior (non-leaf) B-tree nodes.
    pub interior_node_cnt: usize,
    /// Number of record (leaf) B-tree nodes.
    pub record_node_cnt: usize,
    /// Number of chained buffer nodes.
    pub chained_buffer_cnt: usize,
    /// Total size in bytes.
    pub size: usize,
}

impl TableStatistics {
    /// Create empty statistics.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            ..Default::default()
        }
    }
}

impl fmt::Display for TableStatistics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Table '{}': {} bytes, {} buffers ({} interior, {} record, {} chained)",
            self.name,
            self.size,
            self.buffer_count,
            self.interior_node_cnt,
            self.record_node_cnt,
            self.chained_buffer_cnt,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_table_statistics_display() {
        let mut stats = TableStatistics::new("users");
        stats.buffer_count = 10;
        stats.interior_node_cnt = 2;
        stats.record_node_cnt = 5;
        stats.chained_buffer_cnt = 3;
        stats.size = 40960;

        let display = format!("{}", stats);
        assert!(display.contains("users"));
        assert!(display.contains("40960"));
        assert!(display.contains("10 buffers"));
    }

    #[test]
    fn test_table_statistics_default() {
        let stats = TableStatistics::default();
        assert_eq!(stats.buffer_count, 0);
        assert_eq!(stats.size, 0);
    }
}
