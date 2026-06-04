//! Data type synchronization between programs and archives.
//!
//! Ported from Ghidra's `DataTypeSyncState`, `DataTypeSyncInfo`,
//! `DataTypeSynchronizer`, and `DataTypeSyncListener` Java classes.
//!
//! The key concepts are:
//!
//! - [`DataTypeSyncState`] -- a five-state machine describing whether a
//!   data type in a program is in sync with its source archive, needs
//!   an update (from archive), a commit (to archive), or has a conflict.
//!
//! - [`DataTypeSyncInfo`] -- per-type sync metadata, computed from
//!   timestamps and equivalence checks.
//!
//! - [`DataTypeSynchronizer`] -- batch operations over all data types
//!   sourced from a particular archive.

use ghidra_core::data::{DataTypePath, UniversalID};
use std::fmt;

// ---------------------------------------------------------------------------
// DataTypeSyncState
// ---------------------------------------------------------------------------

/// The synchronization state of a data type relative to its source archive.
///
/// Ported from Ghidra's `DataTypeSyncState` Java enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DataTypeSyncState {
    /// The data type matches its source and its timestamps agree.
    InSync,
    /// The source archive has changed and the local copy should be updated.
    Update,
    /// The local copy has changed and should be committed to the archive.
    Commit,
    /// Both the local copy and the source have changed independently.
    Conflict,
    /// The source data type no longer exists in the archive.
    Orphan,
    /// The source archive is not open, so the state cannot be determined.
    Unknown,
}

impl DataTypeSyncState {
    /// Returns `true` if the user can push local changes to the archive.
    ///
    /// For [`Orphan`] types (source deleted from archive), a commit is
    /// allowed because the local copy can be pushed to recreate the type.
    pub fn can_commit(&self) -> bool {
        matches!(self, Self::Commit | Self::Conflict | Self::Orphan)
    }

    /// Returns `true` if the user can pull archive changes into the program.
    pub fn can_update(&self) -> bool {
        matches!(self, Self::Update | Self::Conflict)
    }

    /// Returns `true` if the data type is already in sync.
    pub fn is_in_sync(&self) -> bool {
        *self == Self::InSync
    }

    /// Returns `true` if the source data type is missing.
    pub fn is_orphan(&self) -> bool {
        *self == Self::Orphan
    }

    /// Returns `true` if the state is unknown (source archive not open).
    pub fn is_unknown(&self) -> bool {
        *self == Self::Unknown
    }

    /// Human-readable label for this state.
    pub fn label(&self) -> &'static str {
        match self {
            Self::InSync => "In Sync",
            Self::Update => "Update",
            Self::Commit => "Commit",
            Self::Conflict => "Conflict",
            Self::Orphan => "Orphan",
            Self::Unknown => "Unknown",
        }
    }
}

impl fmt::Display for DataTypeSyncState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label())
    }
}

// ---------------------------------------------------------------------------
// DataTypeSyncInfo
// ---------------------------------------------------------------------------

/// Per-data-type synchronization metadata.
///
/// Wraps a reference (local) data type and the corresponding source
/// data type from the archive and computes the current sync state.
///
/// Ported from Ghidra's `DataTypeSyncInfo` Java class.
#[derive(Debug, Clone)]
pub struct DataTypeSyncInfo {
    /// The data type in the program (reference).
    ref_dt_path: DataTypePath,
    /// The name of the reference data type.
    ref_name: String,
    /// The last change time of the reference data type.
    ref_last_change_time: u64,
    /// The last change time in the source archive as recorded by the reference.
    ref_last_change_time_in_source: u64,
    /// Description of the reference data type.
    ref_description: String,
    /// The source data type's path (empty if orphan).
    source_dt_path: DataTypePath,
    /// The last change time of the source data type.
    source_last_change_time: u64,
    /// Description of the source data type.
    source_description: String,
    /// Whether the source data type exists.
    source_exists: bool,
    /// Whether the reference data type is a pointer or array type.
    is_pointer_or_array: bool,
    /// Computed sync state.
    sync_state: DataTypeSyncState,
    /// Whether the reference data type has real structural changes vs the source.
    has_real_change: bool,
}

impl DataTypeSyncInfo {
    /// Create sync info from raw field values.
    ///
    /// This factory method computes the sync state from the timestamps
    /// and existence flags.  In the full implementation the actual data
    /// types would be inspected.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        ref_dt_path: DataTypePath,
        ref_name: impl Into<String>,
        ref_last_change_time: u64,
        ref_last_change_time_in_source: u64,
        ref_description: impl Into<String>,
        source_dt_path: DataTypePath,
        source_last_change_time: u64,
        source_description: impl Into<String>,
        source_exists: bool,
        is_pointer_or_array: bool,
        has_real_change: bool,
    ) -> Self {
        let sync_state = Self::compute_sync_state(
            source_exists,
            ref_last_change_time,
            ref_last_change_time_in_source,
            source_last_change_time,
            has_real_change,
        );
        Self {
            ref_dt_path,
            ref_name: ref_name.into(),
            ref_last_change_time,
            ref_last_change_time_in_source,
            ref_description: ref_description.into(),
            source_dt_path,
            source_last_change_time,
            source_description: source_description.into(),
            source_exists,
            is_pointer_or_array,
            sync_state,
            has_real_change,
        }
    }

    /// Compute the sync state from timestamps and existence.
    fn compute_sync_state(
        source_exists: bool,
        ref_change: u64,
        ref_source_time: u64,
        source_change: u64,
        has_real_change: bool,
    ) -> DataTypeSyncState {
        if !source_exists {
            return DataTypeSyncState::Orphan;
        }
        let can_update = source_change != ref_source_time && ref_source_time <= source_change;
        let can_commit = ref_change != ref_source_time;
        // Special case: user committed but archive wasn't saved.
        let commit_unsaved = ref_source_time > source_change;

        if can_update && (can_commit || commit_unsaved) {
            DataTypeSyncState::Conflict
        } else if can_update {
            DataTypeSyncState::Update
        } else if can_commit || commit_unsaved {
            DataTypeSyncState::Commit
        } else if has_real_change {
            // Timestamps match but content differs -- force out of sync.
            DataTypeSyncState::Conflict
        } else {
            DataTypeSyncState::InSync
        }
    }

    /// The current sync state.
    pub fn sync_state(&self) -> DataTypeSyncState {
        self.sync_state
    }

    /// Returns `true` if the program data type can be committed to the archive.
    pub fn can_commit(&self) -> bool {
        self.sync_state.can_commit()
    }

    /// Returns `true` if the program data type can be updated from the archive.
    pub fn can_update(&self) -> bool {
        self.sync_state.can_update()
    }

    /// Returns `true` if the data type can be reverted to the source version.
    pub fn can_revert(&self) -> bool {
        self.source_exists && self.can_commit()
    }

    /// Returns `true` if the data type has changed (name, description, or
    /// structural content) relative to the source.
    pub fn has_change(&self) -> bool {
        self.has_real_change
    }

    /// Returns the path of the reference data type.
    pub fn ref_dt_path(&self) -> &DataTypePath {
        &self.ref_dt_path
    }

    /// Returns the path of the source data type (in the archive).
    pub fn source_dt_path(&self) -> &DataTypePath {
        &self.source_dt_path
    }

    /// Returns the name of the reference data type.
    pub fn name(&self) -> &str {
        &self.ref_name
    }

    /// Returns the last change time of the reference data type.
    pub fn ref_last_change_time(&self) -> u64 {
        self.ref_last_change_time
    }

    /// Returns the last change time of the source data type.
    pub fn source_last_change_time(&self) -> u64 {
        self.source_last_change_time
    }

    /// Returns the last change time recorded in the source archive.
    pub fn last_sync_time(&self) -> u64 {
        self.ref_last_change_time_in_source
    }

    /// Returns `true` if the source data type exists in the archive.
    pub fn source_exists(&self) -> bool {
        self.source_exists
    }

    /// Returns `true` if the reference data type is a pointer or array.
    pub fn is_pointer_or_array(&self) -> bool {
        self.is_pointer_or_array
    }

    /// Returns the description of the reference data type.
    pub fn ref_description(&self) -> &str {
        &self.ref_description
    }

    /// Returns the description of the source data type.
    pub fn source_description(&self) -> &str {
        &self.source_description
    }

    /// Format a human-readable change timestamp string.
    pub fn last_change_time_string(&self, use_source: bool) -> String {
        let ts = if use_source {
            self.source_last_change_time
        } else {
            self.ref_last_change_time
        };
        if ts == 0 {
            String::new()
        } else {
            format!("{}", ts)
        }
    }

    /// Format a human-readable sync time string.
    pub fn last_sync_time_string(&self) -> String {
        let ts = self.ref_last_change_time_in_source;
        if ts == 0 {
            String::new()
        } else {
            format!("{}", ts)
        }
    }
}

impl fmt::Display for DataTypeSyncInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} [{}] {}",
            self.ref_name,
            self.sync_state.label(),
            self.ref_dt_path
        )
    }
}

// ---------------------------------------------------------------------------
// DataTypeSynchronizer
// ---------------------------------------------------------------------------

/// Batch-synchronizes data types between a program's [`DataTypeManager`]
/// and a source archive.
///
/// Ported from Ghidra's `DataTypeSynchronizer` Java class.
#[derive(Debug)]
pub struct DataTypeSynchronizer {
    /// The data type manager of the program (client).
    client_name: String,
    /// The source archive name.
    source_name: String,
    /// Whether the client is a program manager (vs. a project/archive manager).
    client_is_program: bool,
}

impl DataTypeSynchronizer {
    /// Create a new synchronizer.
    pub fn new(
        client_name: impl Into<String>,
        source_name: impl Into<String>,
        client_is_program: bool,
    ) -> Self {
        Self {
            client_name: client_name.into(),
            source_name: source_name.into(),
            client_is_program,
        }
    }

    /// The name of the client (program) data type manager.
    pub fn client_name(&self) -> &str {
        &self.client_name
    }

    /// The name of the source archive.
    pub fn source_name(&self) -> &str {
        &self.source_name
    }

    /// Returns a label for the client type ("Program" or "Archive").
    pub fn client_type(&self) -> &str {
        if self.client_is_program {
            "Program"
        } else {
            "Archive"
        }
    }

    /// Check whether two data type names are "equivalent" for sync purposes.
    ///
    /// Auto-named typedefs are considered equivalent to each other.
    pub fn names_are_equivalent(
        name1: &str,
        is_auto_named1: bool,
        name2: &str,
        is_auto_named2: bool,
    ) -> bool {
        if is_auto_named1 {
            return is_auto_named2;
        }
        if is_auto_named2 {
            return false;
        }
        name1 == name2
    }

    /// Returns `true` if a data type is a pointer or array (these have
    /// special sync rules: name/description are not synced).
    pub fn is_pointer_or_array(type_name: &str) -> bool {
        type_name == "pointer" || type_name == "array"
    }

    /// Compute the sync status for a data type.
    ///
    /// Returns [`DataTypeSyncState::Unknown`] if the source archive
    /// is not open or the data type has no universal ID.
    pub fn get_sync_status(
        source_archive_id: Option<UniversalID>,
        client_manager_id: Option<UniversalID>,
        source_manager_exists: bool,
        ref_change_time: u64,
        ref_source_time: u64,
        source_change_time: u64,
        source_exists: bool,
    ) -> DataTypeSyncState {
        if let (Some(src_id), Some(client_id)) = (source_archive_id, client_manager_id) {
            if src_id == client_id {
                return DataTypeSyncState::Unknown;
            }
        } else {
            return DataTypeSyncState::Unknown;
        }

        let has_changed_locally = ref_change_time != ref_source_time;
        if !source_manager_exists {
            return if has_changed_locally {
                DataTypeSyncState::Commit
            } else {
                DataTypeSyncState::InSync
            };
        }

        DataTypeSyncInfo::compute_sync_state(
            source_exists,
            ref_change_time,
            ref_source_time,
            source_change_time,
            false,
        )
    }

    /// Prepare sync metadata for a list of data types, returning those
    /// that are out of sync.
    pub fn filter_out_of_sync(infos: &[DataTypeSyncInfo]) -> Vec<&DataTypeSyncInfo> {
        infos
            .iter()
            .filter(|info| info.can_commit() || info.can_update())
            .collect()
    }
}

// ---------------------------------------------------------------------------
// DataTypeSyncListener
// ---------------------------------------------------------------------------

/// Listener for bulk sync-progress events.
pub trait DataTypeSyncListener: fmt::Debug + Send + Sync {
    /// Called when a single data type has been synced.
    fn on_type_synced(&self, _info: &DataTypeSyncInfo) {}

    /// Called when sync is complete.
    fn on_sync_complete(&self, _total: usize, _updated: usize, _committed: usize) {}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ghidra_core::data::CategoryPath;

    fn make_ref_path(name: &str) -> DataTypePath {
        DataTypePath::new(CategoryPath::ROOT, name)
    }

    #[test]
    fn test_sync_state_display() {
        assert_eq!(format!("{}", DataTypeSyncState::InSync), "In Sync");
        assert_eq!(format!("{}", DataTypeSyncState::Update), "Update");
        assert_eq!(format!("{}", DataTypeSyncState::Commit), "Commit");
        assert_eq!(format!("{}", DataTypeSyncState::Conflict), "Conflict");
        assert_eq!(format!("{}", DataTypeSyncState::Orphan), "Orphan");
        assert_eq!(format!("{}", DataTypeSyncState::Unknown), "Unknown");
    }

    #[test]
    fn test_sync_state_predicates() {
        assert!(DataTypeSyncState::InSync.is_in_sync());
        assert!(!DataTypeSyncState::Update.is_in_sync());

        assert!(DataTypeSyncState::Orphan.is_orphan());
        assert!(!DataTypeSyncState::InSync.is_orphan());

        assert!(DataTypeSyncState::Unknown.is_unknown());

        assert!(DataTypeSyncState::Commit.can_commit());
        assert!(DataTypeSyncState::Conflict.can_commit());
        assert!(!DataTypeSyncState::Update.can_commit());

        assert!(DataTypeSyncState::Update.can_update());
        assert!(DataTypeSyncState::Conflict.can_update());
        assert!(!DataTypeSyncState::Commit.can_update());
    }

    #[test]
    fn test_sync_info_in_sync() {
        let info = DataTypeSyncInfo::new(
            make_ref_path("int"),
            "int",
            100, // ref change time
            100, // ref source time (matches ref change)
            "",
            make_ref_path("int"),
            100, // source change time (matches ref source)
            "",
            true,  // source exists
            false, // not pointer/array
            false, // no real change
        );
        assert_eq!(info.sync_state(), DataTypeSyncState::InSync);
        assert!(!info.can_commit());
        assert!(!info.can_update());
    }

    #[test]
    fn test_sync_info_commit() {
        let info = DataTypeSyncInfo::new(
            make_ref_path("my_struct"),
            "my_struct",
            200, // ref changed at 200
            100, // last synced at 100
            "modified struct",
            make_ref_path("my_struct"),
            100, // source hasn't changed since sync
            "original struct",
            true, false, true,
        );
        assert_eq!(info.sync_state(), DataTypeSyncState::Commit);
        assert!(info.can_commit());
        assert!(!info.can_update());
    }

    #[test]
    fn test_sync_info_update() {
        let info = DataTypeSyncInfo::new(
            make_ref_path("my_struct"),
            "my_struct",
            100, // ref hasn't changed
            100, // synced at 100
            "old desc",
            make_ref_path("my_struct"),
            200, // source changed at 200
            "new desc",
            true, false, true,
        );
        assert_eq!(info.sync_state(), DataTypeSyncState::Update);
        assert!(!info.can_commit());
        assert!(info.can_update());
    }

    #[test]
    fn test_sync_info_conflict() {
        let info = DataTypeSyncInfo::new(
            make_ref_path("my_struct"),
            "my_struct",
            200, // ref changed at 200
            100, // synced at 100
            "local change",
            make_ref_path("my_struct"),
            300, // source changed at 300
            "remote change",
            true, false, true,
        );
        assert_eq!(info.sync_state(), DataTypeSyncState::Conflict);
        assert!(info.can_commit());
        assert!(info.can_update());
    }

    #[test]
    fn test_sync_info_orphan() {
        let info = DataTypeSyncInfo::new(
            make_ref_path("deleted_type"),
            "deleted_type",
            100, 100, "",
            make_ref_path("deleted_type"),
            0, "",
            false, // source does NOT exist
            false, false,
        );
        assert_eq!(info.sync_state(), DataTypeSyncState::Orphan);
        assert!(info.can_commit()); // can commit (source deleted, so this is new)
        assert!(!info.can_update()); // can't update -- nothing to pull
        assert!(info.is_pointer_or_array() == false);
    }

    #[test]
    fn test_synchronizer_names_equivalent() {
        assert!(DataTypeSynchronizer::names_are_equivalent("foo", false, "foo", false));
        assert!(!DataTypeSynchronizer::names_are_equivalent("foo", false, "bar", false));
        // Auto-named typedefs are equivalent to each other
        assert!(DataTypeSynchronizer::names_are_equivalent("td1", true, "td2", true));
        // Auto-named is NOT equivalent to explicitly named
        assert!(!DataTypeSynchronizer::names_are_equivalent("td1", true, "td2", false));
        assert!(!DataTypeSynchronizer::names_are_equivalent("td1", false, "td2", true));
    }

    #[test]
    fn test_synchronizer_is_pointer_or_array() {
        assert!(DataTypeSynchronizer::is_pointer_or_array("pointer"));
        assert!(DataTypeSynchronizer::is_pointer_or_array("array"));
        assert!(!DataTypeSynchronizer::is_pointer_or_array("struct"));
        assert!(!DataTypeSynchronizer::is_pointer_or_array("int"));
    }

    #[test]
    fn test_synchronizer_client_type() {
        let sync_prog = DataTypeSynchronizer::new("Prog", "Archive", true);
        assert_eq!(sync_prog.client_type(), "Program");
        let sync_arch = DataTypeSynchronizer::new("Prog", "Archive", false);
        assert_eq!(sync_arch.client_type(), "Archive");
    }

    #[test]
    fn test_filter_out_of_sync() {
        let in_sync = DataTypeSyncInfo::new(
            make_ref_path("a"), "a", 100, 100, "",
            make_ref_path("a"), 100, "", true, false, false,
        );
        let commit = DataTypeSyncInfo::new(
            make_ref_path("b"), "b", 200, 100, "",
            make_ref_path("b"), 100, "", true, false, true,
        );
        let orphan = DataTypeSyncInfo::new(
            make_ref_path("c"), "c", 50, 50, "",
            make_ref_path("c"), 0, "", false, false, false,
        );

        let infos = vec![in_sync, commit, orphan];
        let out_of_sync = DataTypeSynchronizer::filter_out_of_sync(&infos);
        assert_eq!(out_of_sync.len(), 2);
        assert_eq!(out_of_sync[0].name(), "b");
        assert_eq!(out_of_sync[1].name(), "c");
    }

    #[test]
    fn test_get_sync_status() {
        // Same manager -> Unknown
        let status = DataTypeSynchronizer::get_sync_status(
            Some(UniversalID::new(1)),
            Some(UniversalID::new(1)),
            true, 100, 100, 100, true,
        );
        assert_eq!(status, DataTypeSyncState::Unknown);

        // Source not open, local changes -> Commit
        let status = DataTypeSynchronizer::get_sync_status(
            Some(UniversalID::new(2)),
            Some(UniversalID::new(1)),
            false, // source not open
            200, 100, 0, true,
        );
        assert_eq!(status, DataTypeSyncState::Commit);
    }

    #[test]
    fn test_sync_info_display() {
        let info = DataTypeSyncInfo::new(
            make_ref_path("my_struct"), "my_struct", 200, 100, "",
            make_ref_path("my_struct"), 100, "", true, false, true,
        );
        let s = format!("{}", info);
        assert!(s.contains("my_struct"));
        assert!(s.contains("Commit"));
    }

    #[test]
    fn test_sync_info_timestamps() {
        let info = DataTypeSyncInfo::new(
            make_ref_path("x"), "x", 500, 300, "desc ref",
            make_ref_path("x"), 400, "desc src", true, false, true,
        );
        assert_eq!(info.ref_last_change_time(), 500);
        assert_eq!(info.source_last_change_time(), 400);
        assert_eq!(info.last_sync_time(), 300);
        assert_eq!(info.ref_description(), "desc ref");
        assert_eq!(info.source_description(), "desc src");
    }
}
