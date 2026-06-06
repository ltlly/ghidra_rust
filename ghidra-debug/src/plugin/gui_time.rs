//! Time/snapshot GUI data model types.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.gui.time` package
//! in the Debugger module. Provides `SnapshotRow` and `SnapshotTableModel`
//! for the time navigation panel.

use serde::{Deserialize, Serialize};

use crate::model::TraceSnapshot;

/// A row in the snapshot table.
///
/// Ported from Ghidra's `SnapshotRow`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotRow {
    /// The snapshot key.
    pub key: i64,
    /// The display label for this snapshot.
    pub label: String,
    /// Description text.
    pub description: String,
    /// Real-world timestamp (epoch millis), if available.
    pub timestamp: Option<i64>,
    /// The event thread key, if any.
    pub event_thread_key: Option<i64>,
    /// The schedule string for this snapshot.
    pub schedule: String,
    /// Version counter for change tracking.
    pub version: u32,
}

impl SnapshotRow {
    /// Create a snapshot row from a `TraceSnapshot`.
    pub fn from_snapshot(snap: &TraceSnapshot) -> Self {
        Self {
            key: snap.key,
            label: format!("Snap {}", snap.key),
            description: snap.description.clone(),
            timestamp: snap.real_time,
            event_thread_key: snap.event_thread_key,
            schedule: snap.schedule_string.clone().unwrap_or_default(),
            version: snap.version as u32,
        }
    }

    /// Create a scratch snapshot row.
    pub fn scratch() -> Self {
        Self {
            key: -1,
            label: "Scratch".to_string(),
            description: String::new(),
            timestamp: None,
            event_thread_key: None,
            schedule: String::new(),
            version: 0,
        }
    }

    /// Whether this is the scratch snapshot.
    pub fn is_scratch(&self) -> bool {
        self.key < 0
    }
}

/// Table model for the snapshot list.
///
/// Ported from Ghidra's `SnapshotTableModel`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SnapshotTableModel {
    rows: Vec<SnapshotRow>,
    selected_index: Option<usize>,
}

impl SnapshotTableModel {
    /// Create a new empty model.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a model populated from snapshots.
    pub fn from_snapshots(snapshots: &[TraceSnapshot]) -> Self {
        let mut rows: Vec<SnapshotRow> = snapshots.iter().map(SnapshotRow::from_snapshot).collect();
        rows.sort_by_key(|r| r.key);
        Self {
            rows,
            selected_index: None,
        }
    }

    /// The number of rows.
    pub fn row_count(&self) -> usize {
        self.rows.len()
    }

    /// Get a row by index.
    pub fn row(&self, index: usize) -> Option<&SnapshotRow> {
        self.rows.get(index)
    }

    /// Get a row by snapshot key.
    pub fn row_by_key(&self, key: i64) -> Option<&SnapshotRow> {
        self.rows.iter().find(|r| r.key == key)
    }

    /// Add a row.
    pub fn add_row(&mut self, row: SnapshotRow) {
        self.rows.push(row);
        self.rows.sort_by_key(|r| r.key);
    }

    /// Remove a row by key.
    pub fn remove_row(&mut self, key: i64) -> bool {
        let before = self.rows.len();
        self.rows.retain(|r| r.key != key);
        self.rows.len() < before
    }

    /// Get all rows.
    pub fn rows(&self) -> &[SnapshotRow] {
        &self.rows
    }

    /// Set the selected index.
    pub fn set_selected(&mut self, index: Option<usize>) {
        self.selected_index = index;
    }

    /// Get the selected index.
    pub fn selected_index(&self) -> Option<usize> {
        self.selected_index
    }

    /// Get the selected row.
    pub fn selected_row(&self) -> Option<&SnapshotRow> {
        self.selected_index.and_then(|i| self.rows.get(i))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::TraceSnapshot;

    #[test]
    fn test_snapshot_row_from_snapshot() {
        let snap = TraceSnapshot::new(5).with_description("test snapshot");
        let row = SnapshotRow::from_snapshot(&snap);
        assert_eq!(row.key, 5);
        assert_eq!(row.description, "test snapshot");
        assert_eq!(row.label, "Snap 5");
        assert!(!row.is_scratch());
    }

    #[test]
    fn test_snapshot_row_scratch() {
        let row = SnapshotRow::scratch();
        assert!(row.is_scratch());
        assert_eq!(row.key, -1);
        assert_eq!(row.label, "Scratch");
    }

    #[test]
    fn test_snapshot_table_model() {
        let snapshots = vec![
            TraceSnapshot::new(2).with_description("second"),
            TraceSnapshot::new(0).with_description("initial"),
            TraceSnapshot::new(1).with_description("first"),
        ];
        let model = SnapshotTableModel::from_snapshots(&snapshots);
        assert_eq!(model.row_count(), 3);
        // Should be sorted by key
        assert_eq!(model.row(0).unwrap().key, 0);
        assert_eq!(model.row(1).unwrap().key, 1);
        assert_eq!(model.row(2).unwrap().key, 2);
    }

    #[test]
    fn test_snapshot_table_model_select() {
        let snapshots = vec![TraceSnapshot::new(0).with_description("init"), TraceSnapshot::new(1).with_description("step1")];
        let mut model = SnapshotTableModel::from_snapshots(&snapshots);
        assert!(model.selected_row().is_none());

        model.set_selected(Some(1));
        assert_eq!(model.selected_row().unwrap().key, 1);
    }

    #[test]
    fn test_snapshot_table_model_add_remove() {
        let mut model = SnapshotTableModel::new();
        model.add_row(SnapshotRow::from_snapshot(&TraceSnapshot::new(1).with_description("first")));
        model.add_row(SnapshotRow::from_snapshot(&TraceSnapshot::new(0).with_description("zero")));
        assert_eq!(model.row_count(), 2);
        assert_eq!(model.row(0).unwrap().key, 0);

        assert!(model.remove_row(0));
        assert_eq!(model.row_count(), 1);
        assert!(!model.remove_row(999));
    }

    #[test]
    fn test_snapshot_table_model_by_key() {
        let snapshots = vec![TraceSnapshot::new(42).with_description("answer")];
        let model = SnapshotTableModel::from_snapshots(&snapshots);
        assert!(model.row_by_key(42).is_some());
        assert!(model.row_by_key(0).is_none());
    }
}
