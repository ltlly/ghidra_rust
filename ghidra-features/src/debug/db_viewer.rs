//! Database viewer diagnostic utility for Ghidra databases.
//!
//! Ported from `db.DbViewer` (Features/DebugUtils) -- a diagnostic
//! application for inspecting Ghidra database files (.gbf and packed
//! databases).  The Java original is a Swing GUI (`JFrame`) that opens
//! buffer files, enumerates tables, and displays records with statistics.
//!
//! This Rust module provides the **core data model and logic** without
//! the Swing UI layer: database handle management, table enumeration,
//! record representation, table statistics aggregation, and the viewer
//! state machine.

use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Preference key used to remember the last-visited directory (mirrors the
/// Java constant `LAST_BUFFER_FILE_DIRECTORY`).
pub const LAST_BUFFER_FILE_DIRECTORY: &str = "LastBufferFileDirectory";

/// The file extension for Ghidra buffer files.
pub const GBF_EXTENSION: &str = "gbf";

/// The file extension for packed (compressed) Ghidra databases.
pub const PDB_EXTENSION: &str = "gpd";

// ---------------------------------------------------------------------------
// DatabaseRecord
// ---------------------------------------------------------------------------

/// A single record within a database table.
///
/// Each record is identified by a key and contains a list of typed fields.
/// This mirrors the `DBRecord` type in Ghidra's internal `db` package.
#[derive(Debug, Clone)]
pub struct DatabaseRecord {
    /// The record key (unique within its table).
    pub key: u32,
    /// The record's field values, stored as raw byte slices.
    pub fields: Vec<Vec<u8>>,
}

impl DatabaseRecord {
    /// Create a new record with the given key and fields.
    pub fn new(key: u32, fields: Vec<Vec<u8>>) -> Self {
        Self { key, fields }
    }

    /// Return the number of fields in this record.
    pub fn field_count(&self) -> usize {
        self.fields.len()
    }

    /// Return a reference to the field at the given index.
    pub fn field(&self, index: usize) -> Option<&[u8]> {
        self.fields.get(index).map(|v| v.as_slice())
    }
}

impl fmt::Display for DatabaseRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Record(key={}, fields={})", self.key, self.fields.len())
    }
}

// ---------------------------------------------------------------------------
// TableStatistics
// ---------------------------------------------------------------------------

/// Statistics for a single database table (or its index).
///
/// Mirrors the `TableStatistics` class in Ghidra's `db` package.
/// Element 0 of a statistics array is for the primary table; element 1
/// aggregates all index tables.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct TableStatistics {
    /// Total number of buffers used by this table.
    pub buffer_count: u32,
    /// Number of chained (linked) buffers.
    pub chained_buffer_cnt: u32,
    /// Number of interior (non-leaf) B-tree nodes.
    pub interior_node_cnt: u32,
    /// Number of record (leaf) B-tree nodes.
    pub record_node_cnt: u32,
    /// Total size in bytes.
    pub size: u64,
}

impl TableStatistics {
    /// Create statistics with the given values.
    pub fn new(
        buffer_count: u32,
        chained_buffer_cnt: u32,
        interior_node_cnt: u32,
        record_node_cnt: u32,
        size: u64,
    ) -> Self {
        Self {
            buffer_count,
            chained_buffer_cnt,
            interior_node_cnt,
            record_node_cnt,
            size,
        }
    }

    /// Add the values from another `TableStatistics` into this one
    /// (in-place accumulation).  Used to combine index statistics.
    pub fn accumulate(&mut self, other: &TableStatistics) {
        self.buffer_count += other.buffer_count;
        self.chained_buffer_cnt += other.chained_buffer_cnt;
        self.interior_node_cnt += other.interior_node_cnt;
        self.record_node_cnt += other.record_node_cnt;
        self.size += other.size;
    }

    /// Return the size in whole kilobytes.
    pub fn size_kb(&self) -> u64 {
        self.size / 1024
    }
}

impl fmt::Display for TableStatistics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Buffers={} Chained={} Interior={} Records={} Size={}KB",
            self.buffer_count,
            self.chained_buffer_cnt,
            self.interior_node_cnt,
            self.record_node_cnt,
            self.size_kb()
        )
    }
}

// ---------------------------------------------------------------------------
// DbTable
// ---------------------------------------------------------------------------

/// A single table within a Ghidra database.
///
/// Mirrors the `Table` type from Ghidra's `db` package.  A table has a
/// name, a schema (list of column definitions), and a set of records.
#[derive(Debug, Clone)]
pub struct DbTable {
    /// The table's name.
    name: String,
    /// Column names / schema description.
    columns: Vec<String>,
    /// Records in this table (key -> record).
    records: Vec<DatabaseRecord>,
    /// Cached statistics (computed lazily).
    stats: Option<Vec<TableStatistics>>,
}

impl DbTable {
    /// Create a new empty table.
    pub fn new(name: impl Into<String>, columns: Vec<String>) -> Self {
        Self {
            name: name.into(),
            columns,
            records: Vec::new(),
            stats: None,
        }
    }

    /// Return the table name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Return the column definitions.
    pub fn columns(&self) -> &[String] {
        &self.columns
    }

    /// Return the number of records in this table.
    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    /// Return a reference to all records.
    pub fn records(&self) -> &[DatabaseRecord] {
        &self.records
    }

    /// Add a record to this table.
    pub fn add_record(&mut self, record: DatabaseRecord) {
        self.records.push(record);
        // Invalidate cached stats when records change.
        self.stats = None;
    }

    /// Return (or compute) the statistics for this table.
    ///
    /// The returned vector has at least two elements when index tables
    /// exist: `[0]` = primary, `[1]` = combined index stats.  If no
    /// index tables are present, only `[0]` is returned.
    pub fn statistics(&mut self) -> &[TableStatistics] {
        if self.stats.is_none() {
            self.stats = Some(self.compute_statistics());
        }
        self.stats.as_ref().unwrap()
    }

    /// Compute statistics from scratch.
    fn compute_statistics(&self) -> Vec<TableStatistics> {
        // Placeholder: in a full implementation this would parse the
        // buffer file's B-tree structure.  Here we produce a single
        // entry summarizing the in-memory table.
        vec![TableStatistics::new(
            0, // buffer_count
            0, // chained_buffer_cnt
            0, // interior_node_cnt
            self.records.len() as u32, // record_node_cnt (leaf-level)
            0, // size
        )]
    }

    /// Invalidate cached statistics (e.g., after modifying the table).
    pub fn invalidate_stats(&mut self) {
        self.stats = None;
    }
}

impl fmt::Display for DbTable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.name, self.records.len())
    }
}

// ---------------------------------------------------------------------------
// DatabaseHandle
// ---------------------------------------------------------------------------

/// The type of database file that was opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DatabaseKind {
    /// A Ghidra buffer file (.gbf).
    BufferFile,
    /// A packed (compressed) database.
    PackedDatabase,
}

impl fmt::Display for DatabaseKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DatabaseKind::BufferFile => write!(f, "Buffer File"),
            DatabaseKind::PackedDatabase => write!(f, "Packed Database"),
        }
    }
}

/// A handle to an opened Ghidra database.
///
/// Mirrors `DBHandle` from Ghidra's `db` package.  Holds the file path,
/// database type, and the collection of tables.
#[derive(Debug)]
pub struct DatabaseHandle {
    /// Path to the database file on disk.
    file: PathBuf,
    /// Whether this is a buffer file or packed database.
    kind: DatabaseKind,
    /// The tables contained in this database.
    tables: Vec<DbTable>,
    /// Whether this handle is currently open.
    open: bool,
}

impl DatabaseHandle {
    /// Open a Ghidra buffer file at the given path.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the file cannot be read.
    pub fn open_buffer_file(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        if !path.exists() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("File not found: {}", path.display()),
            ));
        }
        Ok(Self {
            file: path,
            kind: DatabaseKind::BufferFile,
            tables: Vec::new(),
            open: true,
        })
    }

    /// Open a packed database at the given path.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the file cannot be read.
    pub fn open_packed_database(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        if !path.exists() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("File not found: {}", path.display()),
            ));
        }
        Ok(Self {
            file: path,
            kind: DatabaseKind::PackedDatabase,
            tables: Vec::new(),
            open: true,
        })
    }

    /// Try to open a Ghidra database, auto-detecting the format.
    ///
    /// Attempts a buffer file first; falls back to packed database.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the file cannot be opened in either format.
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref();
        if !path.exists() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("File not found: {}", path.display()),
            ));
        }
        // Try buffer file first, fall back to packed database.
        match Self::open_buffer_file(path) {
            Ok(h) => Ok(h),
            Err(_) => Self::open_packed_database(path),
        }
    }

    /// Return the path to the database file.
    pub fn file(&self) -> &Path {
        &self.file
    }

    /// Return the name of the database file (without path).
    pub fn file_name(&self) -> &str {
        self.file
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("<unknown>")
    }

    /// Return the kind of database that was opened.
    pub fn kind(&self) -> DatabaseKind {
        self.kind
    }

    /// Return whether this handle is still open.
    pub fn is_open(&self) -> bool {
        self.open
    }

    /// Return a reference to all tables.
    pub fn tables(&self) -> &[DbTable] {
        &self.tables
    }

    /// Return a mutable reference to all tables.
    pub fn tables_mut(&mut self) -> &mut Vec<DbTable> {
        &mut self.tables
    }

    /// Add a table to this database handle.
    pub fn add_table(&mut self, table: DbTable) {
        self.tables.push(table);
        self.tables.sort_by(|a, b| a.name().cmp(b.name()));
    }

    /// Find a table by name.
    pub fn find_table(&self, name: &str) -> Option<&DbTable> {
        self.tables.iter().find(|t| t.name() == name)
    }

    /// Find a table by name (mutable).
    pub fn find_table_mut(&mut self, name: &str) -> Option<&mut DbTable> {
        self.tables.iter_mut().find(|t| t.name() == name)
    }

    /// Return table names with record counts (for combo-box display).
    pub fn table_names_with_counts(&self) -> Vec<String> {
        self.tables
            .iter()
            .map(|t| format!("{} ({})", t.name(), t.record_count()))
            .collect()
    }

    /// Close this database handle, releasing resources.
    pub fn close(&mut self) {
        self.tables.clear();
        self.open = false;
    }
}

impl Drop for DatabaseHandle {
    fn drop(&mut self) {
        if self.open {
            self.close();
        }
    }
}

impl fmt::Display for DatabaseHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DatabaseHandle({}, {}, tables={}, open={})",
            self.file.display(),
            self.kind,
            self.tables.len(),
            self.open
        )
    }
}

// ---------------------------------------------------------------------------
// TableStatisticsCache
// ---------------------------------------------------------------------------

/// Caches table statistics to avoid recomputing them on every selection
/// change.  Mirrors the `Hashtable<String, TableStatistics[]>` field in
/// the Java `DbViewer`.
#[derive(Debug, Default)]
pub struct TableStatisticsCache {
    cache: HashMap<String, Vec<TableStatistics>>,
}

impl TableStatisticsCache {
    /// Create an empty cache.
    pub fn new() -> Self {
        Self {
            cache: HashMap::new(),
        }
    }

    /// Look up cached statistics for the given table name.
    pub fn get(&self, table_name: &str) -> Option<&[TableStatistics]> {
        self.cache.get(table_name).map(|v| v.as_slice())
    }

    /// Store statistics for the given table name.
    pub fn put(&mut self, table_name: impl Into<String>, stats: Vec<TableStatistics>) {
        self.cache.insert(table_name.into(), stats);
    }

    /// Compute (or return cached) statistics for the given table.
    ///
    /// If the stats are not yet cached, this invokes `table.statistics()`,
    /// combines index statistics (elements 2..N are folded into element 1),
    /// and caches the result.
    pub fn get_or_compute(&mut self, table: &mut DbTable) -> Vec<TableStatistics> {
        let name = table.name().to_string();
        if let Some(cached) = self.get(&name) {
            return cached.to_vec();
        }
        let mut stats: Vec<TableStatistics> = table.statistics().to_vec();
        // Combine index statistics (elements 2..N into element 1).
        if stats.len() > 2 {
            let (head, tail) = stats.split_at_mut(2);
            for s in tail {
                head[1].accumulate(s);
            }
            stats.truncate(2);
        }
        self.put(&name, stats.clone());
        stats
    }

    /// Remove all cached entries.
    pub fn clear(&mut self) {
        self.cache.clear();
    }

    /// Return the number of cached entries.
    pub fn len(&self) -> usize {
        self.cache.len()
    }

    /// Return whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }
}

// ---------------------------------------------------------------------------
// StatsLabel
// ---------------------------------------------------------------------------

/// Formats a statistics summary label for display.
///
/// Mirrors the `statsLabel` construction in `DbViewer.createSouthPanel()`.
pub fn format_stats_label(
    record_count: usize,
    stats: Option<&[TableStatistics]>,
) -> String {
    let mut parts = vec![format!("Records: {}", record_count)];

    if let Some(stats) = stats {
        let primary = &stats[0];
        let mut int_node = format!("{}", primary.interior_node_cnt);
        let mut rec_node = format!("{}", primary.record_node_cnt);
        let mut chain_buf = format!("{}", primary.chained_buffer_cnt);
        let mut size = format!("{}", primary.size_kb());

        if stats.len() > 1 {
            let combined = &stats[1];
            int_node += &format!(" / {}", combined.interior_node_cnt);
            rec_node += &format!(" / {}", combined.record_node_cnt);
            chain_buf += &format!(" / {}", combined.chained_buffer_cnt);
            size += &format!(" / {}", combined.size_kb());
        }

        parts.push(format!("Interior Nodes: {}", int_node));
        parts.push(format!("Record Nodes: {}", rec_node));
        parts.push(format!("Chained Buffers: {}", chain_buf));
        parts.push(format!("Size (KB): {}", size));
    }

    parts.join("   ")
}

// ---------------------------------------------------------------------------
// DbViewerState
// ---------------------------------------------------------------------------

/// The state of the database viewer.
///
/// Mirrors the state machine in `DbViewer`: the viewer can be empty
/// (no database open), or it can have a database open with a currently
/// selected table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DbViewerState {
    /// No database is currently open.
    Empty,
    /// A database is open and a table is selected.
    ViewingTable,
}

impl fmt::Display for DbViewerState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DbViewerState::Empty => write!(f, "Empty"),
            DbViewerState::ViewingTable => write!(f, "Viewing Table"),
        }
    }
}

// ---------------------------------------------------------------------------
// DbViewer
// ---------------------------------------------------------------------------

/// The database viewer, ported from the Java `DbViewer` class.
///
/// In the Java version this is a `JFrame` with Swing menus, combo boxes,
/// and table views.  Here it holds the **domain model** -- the open
/// database handle, the selected table index, and the statistics cache --
/// so that a UI layer (egui, iced, terminal, etc.) can drive it.
///
/// # Example
///
/// ```ignore
/// use ghidra_features::debug::db_viewer::DbViewer;
///
/// let mut viewer = DbViewer::new();
/// viewer.open_database("/path/to/my.db")?;
/// let table_names = viewer.table_names();
/// viewer.select_table(0);
/// let label = viewer.stats_label();
/// viewer.close_database();
/// ```
#[derive(Debug)]
pub struct DbViewer {
    /// The currently open database handle (if any).
    db_handle: Option<DatabaseHandle>,
    /// Index of the currently selected table (into `db_handle.tables()`).
    selected_table_index: usize,
    /// Statistics cache.
    stats_cache: TableStatisticsCache,
    /// The last directory the user browsed to.
    last_directory: Option<PathBuf>,
}

impl DbViewer {
    /// Create a new viewer with no database open.
    pub fn new() -> Self {
        Self {
            db_handle: None,
            selected_table_index: 0,
            stats_cache: TableStatisticsCache::new(),
            last_directory: None,
        }
    }

    /// Return the current viewer state.
    pub fn state(&self) -> DbViewerState {
        if self.db_handle.as_ref().map_or(false, |h| h.is_open()) {
            DbViewerState::ViewingTable
        } else {
            DbViewerState::Empty
        }
    }

    /// Open a database file, auto-detecting the format.
    ///
    /// If a database is already open it is closed first.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the file cannot be opened.
    pub fn open_database(&mut self, path: impl AsRef<Path>) -> io::Result<()> {
        if self.db_handle.is_some() {
            self.close_database();
        }
        let path = path.as_ref();
        self.last_directory = path.parent().map(|p| p.to_path_buf());

        let handle = DatabaseHandle::open(path)?;
        self.db_handle = Some(handle);
        self.selected_table_index = 0;
        self.stats_cache.clear();
        Ok(())
    }

    /// Open a Ghidra buffer file (.gbf).
    ///
    /// If a database is already open it is closed first.
    pub fn open_buffer_file(&mut self, path: impl AsRef<Path>) -> io::Result<()> {
        if self.db_handle.is_some() {
            self.close_database();
        }
        let path = path.as_ref();
        self.last_directory = path.parent().map(|p| p.to_path_buf());

        let handle = DatabaseHandle::open_buffer_file(path)?;
        self.db_handle = Some(handle);
        self.selected_table_index = 0;
        self.stats_cache.clear();
        Ok(())
    }

    /// Open a packed database.
    ///
    /// If a database is already open it is closed first.
    pub fn open_packed_database(&mut self, path: impl AsRef<Path>) -> io::Result<()> {
        if self.db_handle.is_some() {
            self.close_database();
        }
        let path = path.as_ref();
        self.last_directory = path.parent().map(|p| p.to_path_buf());

        let handle = DatabaseHandle::open_packed_database(path)?;
        self.db_handle = Some(handle);
        self.selected_table_index = 0;
        self.stats_cache.clear();
        Ok(())
    }

    /// Close the currently open database.
    pub fn close_database(&mut self) {
        if let Some(ref mut handle) = self.db_handle {
            handle.close();
        }
        self.db_handle = None;
        self.selected_table_index = 0;
        self.stats_cache.clear();
    }

    /// Return whether a database is currently open.
    pub fn is_open(&self) -> bool {
        self.db_handle.as_ref().map_or(false, |h| h.is_open())
    }

    /// Return a reference to the open database handle.
    pub fn database_handle(&self) -> Option<&DatabaseHandle> {
        self.db_handle.as_ref().filter(|h| h.is_open())
    }

    /// Return the name of the currently open database file.
    pub fn database_name(&self) -> Option<&str> {
        self.database_handle().map(|h| h.file_name())
    }

    /// Return the number of tables in the open database.
    pub fn table_count(&self) -> usize {
        self.database_handle().map_or(0, |h| h.tables().len())
    }

    /// Return table names with record counts (for display in a combo box).
    pub fn table_names(&self) -> Vec<String> {
        self.database_handle()
            .map_or_else(Vec::new, |h| h.table_names_with_counts())
    }

    /// Return the currently selected table index.
    pub fn selected_table_index(&self) -> usize {
        self.selected_table_index
    }

    /// Select a table by index.
    ///
    /// Clamps the index to the valid range.
    pub fn select_table(&mut self, index: usize) {
        let count = self.table_count();
        if count == 0 {
            self.selected_table_index = 0;
        } else {
            self.selected_table_index = index.min(count - 1);
        }
    }

    /// Return a reference to the currently selected table.
    pub fn selected_table(&self) -> Option<&DbTable> {
        self.database_handle()
            .and_then(|h| h.tables().get(self.selected_table_index))
    }

    /// Return a mutable reference to the currently selected table.
    pub fn selected_table_mut(&mut self) -> Option<&mut DbTable> {
        let idx = self.selected_table_index;
        self.db_handle
            .as_mut()
            .and_then(|h| h.tables_mut().get_mut(idx))
    }

    /// Compute (or retrieve from cache) the statistics for the
    /// currently selected table.  Returns a formatted label string.
    pub fn stats_label(&mut self) -> String {
        let record_count = self
            .selected_table()
            .map_or(0, |t| t.record_count());
        let idx = self.selected_table_index;
        let stats = if let Some(handle) = self.db_handle.as_mut() {
            if let Some(table) = handle.tables_mut().get_mut(idx) {
                let s = self.stats_cache.get_or_compute(table);
                Some(s)
            } else {
                None
            }
        } else {
            None
        };
        format_stats_label(record_count, stats.as_deref())
    }

    /// Return the last browsed directory (used for file chooser persistence).
    pub fn last_directory(&self) -> Option<&Path> {
        self.last_directory.as_deref()
    }

    /// Set the last browsed directory.
    pub fn set_last_directory(&mut self, dir: impl Into<PathBuf>) {
        self.last_directory = Some(dir.into());
    }

    /// Enumerate `.gbf` and `.gpd` files in the given directory.
    ///
    /// This is a convenience method for building file filters.
    pub fn list_database_files(dir: impl AsRef<Path>) -> io::Result<Vec<PathBuf>> {
        let dir = dir.as_ref();
        if !dir.exists() {
            return Err(io::Error::new(io::ErrorKind::NotFound, format!("Directory not found: {}", dir.display())));
        }
        let mut result = Vec::new();
        if dir.is_dir() {
            for entry in fs::read_dir(dir)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_file() {
                    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                        if ext.eq_ignore_ascii_case(GBF_EXTENSION)
                            || ext.eq_ignore_ascii_case(PDB_EXTENSION)
                        {
                            result.push(path);
                        }
                    }
                }
            }
        }
        result.sort();
        Ok(result)
    }
}

impl Default for DbViewer {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for DbViewer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.db_handle {
            Some(h) => write!(f, "DbViewer({})", h),
            None => write!(f, "DbViewer(no database open)"),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- DatabaseRecord --

    #[test]
    fn test_record_new() {
        let r = DatabaseRecord::new(42, vec![vec![1, 2], vec![3, 4, 5]]);
        assert_eq!(r.key, 42);
        assert_eq!(r.field_count(), 2);
        assert_eq!(r.field(0), Some(&[1, 2][..]));
        assert_eq!(r.field(1), Some(&[3, 4, 5][..]));
        assert_eq!(r.field(2), None);
    }

    #[test]
    fn test_record_display() {
        let r = DatabaseRecord::new(1, vec![vec![0]]);
        assert_eq!(format!("{}", r), "Record(key=1, fields=1)");
    }

    // -- TableStatistics --

    #[test]
    fn test_statistics_default() {
        let s = TableStatistics::default();
        assert_eq!(s.buffer_count, 0);
        assert_eq!(s.size_kb(), 0);
    }

    #[test]
    fn test_statistics_accumulate() {
        let mut a = TableStatistics::new(10, 2, 3, 4, 2048);
        let b = TableStatistics::new(5, 1, 2, 3, 1024);
        a.accumulate(&b);
        assert_eq!(a.buffer_count, 15);
        assert_eq!(a.chained_buffer_cnt, 3);
        assert_eq!(a.interior_node_cnt, 5);
        assert_eq!(a.record_node_cnt, 7);
        assert_eq!(a.size, 3072);
    }

    #[test]
    fn test_statistics_size_kb() {
        let s = TableStatistics::new(0, 0, 0, 0, 2048);
        assert_eq!(s.size_kb(), 2);
    }

    #[test]
    fn test_statistics_display() {
        let s = TableStatistics::new(1, 2, 3, 4, 4096);
        let d = format!("{}", s);
        assert!(d.contains("Buffers=1"));
        assert!(d.contains("Chained=2"));
        assert!(d.contains("Interior=3"));
        assert!(d.contains("Records=4"));
        assert!(d.contains("Size=4KB"));
    }

    // -- DbTable --

    #[test]
    fn test_table_new() {
        let t = DbTable::new("my_table", vec!["col_a".into(), "col_b".into()]);
        assert_eq!(t.name(), "my_table");
        assert_eq!(t.columns().len(), 2);
        assert_eq!(t.record_count(), 0);
    }

    #[test]
    fn test_table_add_record() {
        let mut t = DbTable::new("t", vec![]);
        assert_eq!(t.record_count(), 0);
        t.add_record(DatabaseRecord::new(1, vec![]));
        t.add_record(DatabaseRecord::new(2, vec![vec![10]]));
        assert_eq!(t.record_count(), 2);
        assert_eq!(t.records()[0].key, 1);
        assert_eq!(t.records()[1].key, 2);
    }

    #[test]
    fn test_table_statistics_computed() {
        let mut t = DbTable::new("t", vec![]);
        t.add_record(DatabaseRecord::new(1, vec![]));
        t.add_record(DatabaseRecord::new(2, vec![]));
        let stats = t.statistics();
        assert_eq!(stats.len(), 1);
        assert_eq!(stats[0].record_node_cnt, 2);
    }

    #[test]
    fn test_table_display() {
        let mut t = DbTable::new("foo", vec![]);
        t.add_record(DatabaseRecord::new(1, vec![]));
        assert_eq!(format!("{}", t), "foo (1)");
    }

    // -- DatabaseHandle --

    #[test]
    fn test_handle_table_names_with_counts() {
        let mut h = DatabaseHandle {
            file: PathBuf::from("/tmp/test.db"),
            kind: DatabaseKind::BufferFile,
            tables: Vec::new(),
            open: true,
        };
        let mut t1 = DbTable::new("alpha", vec![]);
        t1.add_record(DatabaseRecord::new(1, vec![]));
        t1.add_record(DatabaseRecord::new(2, vec![]));
        let t2 = DbTable::new("beta", vec![]);
        h.add_table(t1);
        h.add_table(t2);

        let names = h.table_names_with_counts();
        assert_eq!(names.len(), 2);
        // Tables are sorted by name.
        assert_eq!(names[0], "alpha (2)");
        assert_eq!(names[1], "beta (0)");
    }

    #[test]
    fn test_handle_find_table() {
        let mut h = DatabaseHandle {
            file: PathBuf::from("/tmp/test.db"),
            kind: DatabaseKind::PackedDatabase,
            tables: Vec::new(),
            open: true,
        };
        h.add_table(DbTable::new("users", vec!["name".into()]));
        assert!(h.find_table("users").is_some());
        assert!(h.find_table("nonexistent").is_none());
    }

    #[test]
    fn test_handle_close() {
        let mut h = DatabaseHandle {
            file: PathBuf::from("/tmp/test.db"),
            kind: DatabaseKind::BufferFile,
            tables: vec![DbTable::new("t", vec![])],
            open: true,
        };
        assert!(h.is_open());
        h.close();
        assert!(!h.is_open());
        assert!(h.tables().is_empty());
    }

    #[test]
    fn test_handle_display() {
        let h = DatabaseHandle {
            file: PathBuf::from("/tmp/mydb.gbf"),
            kind: DatabaseKind::BufferFile,
            tables: Vec::new(),
            open: true,
        };
        let s = format!("{}", h);
        assert!(s.contains("mydb.gbf"));
        assert!(s.contains("Buffer File"));
        assert!(s.contains("open=true"));
    }

    #[test]
    fn test_handle_file_name() {
        let h = DatabaseHandle {
            file: PathBuf::from("/home/user/data/test.gbf"),
            kind: DatabaseKind::BufferFile,
            tables: Vec::new(),
            open: true,
        };
        assert_eq!(h.file_name(), "test.gbf");
    }

    // -- TableStatisticsCache --

    #[test]
    fn test_cache_put_get() {
        let mut cache = TableStatisticsCache::new();
        assert!(cache.is_empty());

        let stats = vec![TableStatistics::new(1, 2, 3, 4, 5)];
        cache.put("my_table", stats);
        assert_eq!(cache.len(), 1);

        let cached = cache.get("my_table").unwrap();
        assert_eq!(cached[0].buffer_count, 1);
        assert!(cache.get("other").is_none());
    }

    #[test]
    fn test_cache_clear() {
        let mut cache = TableStatisticsCache::new();
        cache.put("t1", vec![TableStatistics::default()]);
        cache.put("t2", vec![TableStatistics::default()]);
        assert_eq!(cache.len(), 2);
        cache.clear();
        assert!(cache.is_empty());
    }

    #[test]
    fn test_cache_get_or_compute() {
        let mut cache = TableStatisticsCache::new();
        let mut table = DbTable::new("t", vec![]);
        table.add_record(DatabaseRecord::new(1, vec![]));

        // First call computes.
        let stats = cache.get_or_compute(&mut table);
        assert_eq!(stats.len(), 1);
        assert_eq!(stats[0].record_node_cnt, 1);

        // Second call uses cache.
        let stats2 = cache.get_or_compute(&mut table);
        assert_eq!(stats, stats2);
    }

    // -- format_stats_label --

    #[test]
    fn test_format_stats_label_no_stats() {
        let label = format_stats_label(42, None);
        assert_eq!(label, "Records: 42");
    }

    #[test]
    fn test_format_stats_label_primary_only() {
        let stats = vec![TableStatistics::new(10, 2, 3, 4, 4096)];
        let label = format_stats_label(100, Some(&stats));
        assert!(label.contains("Records: 100"));
        assert!(label.contains("Interior Nodes: 3"));
        assert!(label.contains("Record Nodes: 4"));
        assert!(label.contains("Chained Buffers: 2"));
        assert!(label.contains("Size (KB): 4"));
    }

    #[test]
    fn test_format_stats_label_with_combined_index() {
        let stats = vec![
            TableStatistics::new(10, 2, 3, 4, 4096),
            TableStatistics::new(5, 1, 2, 3, 2048),
        ];
        let label = format_stats_label(50, Some(&stats));
        assert!(label.contains("Interior Nodes: 3 / 2"));
        assert!(label.contains("Record Nodes: 4 / 3"));
        assert!(label.contains("Chained Buffers: 2 / 1"));
        assert!(label.contains("Size (KB): 4 / 2"));
    }

    // -- DbViewerState --

    #[test]
    fn test_viewer_state_display() {
        assert_eq!(format!("{}", DbViewerState::Empty), "Empty");
        assert_eq!(
            format!("{}", DbViewerState::ViewingTable),
            "Viewing Table"
        );
    }

    // -- DbViewer --

    #[test]
    fn test_viewer_new() {
        let viewer = DbViewer::new();
        assert_eq!(viewer.state(), DbViewerState::Empty);
        assert!(!viewer.is_open());
        assert!(viewer.database_handle().is_none());
        assert!(viewer.database_name().is_none());
        assert_eq!(viewer.table_count(), 0);
        assert!(viewer.table_names().is_empty());
        assert_eq!(viewer.selected_table_index(), 0);
        assert!(viewer.selected_table().is_none());
        assert!(viewer.last_directory().is_none());
    }

    #[test]
    fn test_viewer_default() {
        let viewer = DbViewer::default();
        assert_eq!(viewer.state(), DbViewerState::Empty);
    }

    #[test]
    fn test_viewer_close_empty() {
        let mut viewer = DbViewer::new();
        // Closing when nothing is open should be a no-op.
        viewer.close_database();
        assert_eq!(viewer.state(), DbViewerState::Empty);
    }

    #[test]
    fn test_viewer_select_table_clamped() {
        let mut viewer = DbViewer::new();
        // No tables -- selecting anything should stay at 0.
        viewer.select_table(5);
        assert_eq!(viewer.selected_table_index(), 0);
    }

    #[test]
    fn test_viewer_set_last_directory() {
        let mut viewer = DbViewer::new();
        assert!(viewer.last_directory().is_none());
        viewer.set_last_directory("/home/user/databases");
        assert_eq!(
            viewer.last_directory().unwrap(),
            Path::new("/home/user/databases")
        );
    }

    #[test]
    fn test_viewer_display_no_db() {
        let viewer = DbViewer::new();
        let s = format!("{}", viewer);
        assert!(s.contains("no database open"));
    }

    #[test]
    fn test_viewer_stats_label_empty() {
        let mut viewer = DbViewer::new();
        let label = viewer.stats_label();
        assert_eq!(label, "Records: 0");
    }

    #[test]
    fn test_list_database_files_nonexistent_dir() {
        let result = DbViewer::list_database_files("/nonexistent/path");
        assert!(result.is_err());
    }

    // -- DatabaseKind --

    #[test]
    fn test_database_kind_display() {
        assert_eq!(format!("{}", DatabaseKind::BufferFile), "Buffer File");
        assert_eq!(
            format!("{}", DatabaseKind::PackedDatabase),
            "Packed Database"
        );
    }

    #[test]
    fn test_database_kind_equality() {
        assert_eq!(DatabaseKind::BufferFile, DatabaseKind::BufferFile);
        assert_ne!(DatabaseKind::BufferFile, DatabaseKind::PackedDatabase);
    }
}
