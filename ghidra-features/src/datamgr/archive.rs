//! Archive types for data type management.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.datamgr.archive` package.
//!
//! The [`Archive`] trait is the core abstraction; concrete implementations
//! cover the built-in type library, file-backed archives, program-embedded
//! archives, project-stored archives, and placeholder nodes for archives
//! that could not be opened.

use ghidra_core::data::{
    DataTypeManager, StandaloneDataTypeManager, BuiltInDataTypeManager,
    SourceArchive, UniversalID,
};
use std::fmt;
use std::path::PathBuf;

// ---------------------------------------------------------------------------
// ArchiveKind
// ---------------------------------------------------------------------------

/// Discriminator for the different concrete archive types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ArchiveKind {
    /// The built-in (global) data type library.
    BuiltIn,
    /// An archive file on disk (e.g., `Ghidra/Features/Base/gdt/*.gdt`).
    File,
    /// The data type manager embedded in a program.
    Program,
    /// A project-stored data type archive.
    Project,
    /// A placeholder for an archive whose file could not be found / opened.
    Invalid,
}

impl fmt::Display for ArchiveKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BuiltIn => write!(f, "BuiltIn"),
            Self::File => write!(f, "File"),
            Self::Program => write!(f, "Program"),
            Self::Project => write!(f, "Project"),
            Self::Invalid => write!(f, "Invalid"),
        }
    }
}

// ---------------------------------------------------------------------------
// Archive trait
// ---------------------------------------------------------------------------

/// Trait for data type archives.
///
/// This is the Rust equivalent of Ghidra's `Archive` Java interface.
/// Every concrete archive type wraps a [`DataTypeManager`] and adds
/// lifecycle (open / close / save) and state queries (modifiable,
/// changed, savable).
pub trait Archive: fmt::Debug + Send + Sync {
    /// The kind of this archive.
    fn kind(&self) -> ArchiveKind;

    /// The user-visible name of this archive, or `None` if closed.
    fn name(&self) -> Option<&str>;

    /// Close this archive.  Some archives (built-in) cannot be closed.
    fn close(&mut self);

    /// Returns `true` if the archive can be modified.
    ///
    /// A modifiable archive is one whose contents can be changed --
    /// e.g., a program archive, a non-versioned project archive, a
    /// checked-out versioned project archive, or a locked file archive.
    fn is_modifiable(&self) -> bool;

    /// Returns `true` if the archive supports saving.
    fn is_savable(&self) -> bool;

    /// Returns `true` if the archive contains unsaved changes.
    fn is_changed(&self) -> bool;

    /// Save the archive to its current backing location.
    ///
    /// # Errors
    ///
    /// Returns an error string if the save fails.
    fn save(&mut self) -> Result<(), String>;

    /// Save the archive to a new path / name.
    ///
    /// # Errors
    ///
    /// Returns an error string if the save fails.
    fn save_as(&mut self, _new_path: &str) -> Result<(), String> {
        Err("save_as not supported for this archive type".into())
    }

    /// A reference to the underlying data type manager.
    fn data_type_manager(&self) -> &dyn DataTypeManager;

    /// A mutable reference to the underlying data type manager.
    fn data_type_manager_mut(&mut self) -> Option<&mut dyn DataTypeManager>;

    /// The universal ID of this archive's data type manager.
    fn universal_id(&self) -> Option<UniversalID>;
}

// ---------------------------------------------------------------------------
// ArchiveManagerListener
// ---------------------------------------------------------------------------

/// Listener for archive open/close/state-change events.
///
/// This is the Rust equivalent of Ghidra's `ArchiveManagerListener`.
pub trait ArchiveManagerListener: fmt::Debug + Send + Sync {
    /// Called when an archive has been opened.
    fn archive_opened(&self, _archive: &dyn Archive) {}

    /// Called when an archive has been closed.
    fn archive_closed(&self, _archive: &dyn Archive) {}

    /// Called when the data type manager of a file archive changes
    /// (e.g., on save-as with a new name).
    fn archive_data_type_manager_changed(&self, _archive: &dyn Archive) {}

    /// Called when an archive's state (modifiable, changed, etc.) changes.
    fn archive_state_changed(&self, _archive: &dyn Archive) {}
}

// ---------------------------------------------------------------------------
// BuiltInArchive
// ---------------------------------------------------------------------------

/// The built-in data type archive.
///
/// This archive wraps Ghidra's global [`BuiltInDataTypeManager`] and
/// cannot be closed, saved, or modified by the user.
#[derive(Debug)]
pub struct BuiltInArchive {
    name: String,
    dtm: BuiltInDataTypeManager,
}

impl BuiltInArchive {
    /// Create a new built-in archive.
    pub fn new(dtm: BuiltInDataTypeManager) -> Self {
        Self {
            name: "BuiltInTypes".into(),
            dtm,
        }
    }
}

impl Archive for BuiltInArchive {
    fn kind(&self) -> ArchiveKind { ArchiveKind::BuiltIn }
    fn name(&self) -> Option<&str> { Some(&self.name) }
    fn close(&mut self) { /* built-in cannot be closed */ }
    fn is_modifiable(&self) -> bool { false }
    fn is_savable(&self) -> bool { false }
    fn is_changed(&self) -> bool { false }
    fn save(&mut self) -> Result<(), String> { Ok(()) }
    fn data_type_manager(&self) -> &dyn DataTypeManager { &self.dtm }
    fn data_type_manager_mut(&mut self) -> Option<&mut dyn DataTypeManager> { Some(&mut self.dtm) }
    fn universal_id(&self) -> Option<UniversalID> { Some(UniversalID::new(1)) }
}

// ---------------------------------------------------------------------------
// FileArchive
// ---------------------------------------------------------------------------

/// A file-backed data type archive.
///
/// Wraps a [`StandaloneDataTypeManager`] whose contents are persisted
/// to a `.gdt` file on disk.
#[derive(Debug)]
pub struct FileArchive {
    name: String,
    file_path: PathBuf,
    dtm: StandaloneDataTypeManager,
    modifiable: bool,
    changed: bool,
    closed: bool,
}

impl FileArchive {
    /// Create a new file archive at the given path.
    pub fn new(
        name: impl Into<String>,
        file_path: PathBuf,
        dtm: StandaloneDataTypeManager,
        modifiable: bool,
    ) -> Self {
        Self {
            name: name.into(),
            file_path,
            dtm,
            modifiable,
            changed: false,
            closed: false,
        }
    }

    /// The absolute path of the backing file.
    pub fn file_path(&self) -> &PathBuf {
        &self.file_path
    }

    /// Returns `true` if this archive has been closed.
    pub fn is_closed(&self) -> bool {
        self.closed
    }
}

impl Archive for FileArchive {
    fn kind(&self) -> ArchiveKind { ArchiveKind::File }
    fn name(&self) -> Option<&str> {
        if self.closed { None } else { Some(&self.name) }
    }

    fn close(&mut self) {
        self.closed = true;
    }

    fn is_modifiable(&self) -> bool { self.modifiable && !self.closed }
    fn is_savable(&self) -> bool { !self.closed }
    fn is_changed(&self) -> bool { self.changed }

    fn save(&mut self) -> Result<(), String> {
        if self.closed {
            return Err("Archive is closed".into());
        }
        // In a full implementation this would serialize to disk.
        self.changed = false;
        Ok(())
    }

    fn save_as(&mut self, new_path: &str) -> Result<(), String> {
        self.file_path = PathBuf::from(new_path);
        self.changed = false;
        Ok(())
    }

    fn data_type_manager(&self) -> &dyn DataTypeManager { &self.dtm }
    fn data_type_manager_mut(&mut self) -> Option<&mut dyn DataTypeManager> {
        if self.modifiable { Some(&mut self.dtm) } else { None }
    }
    fn universal_id(&self) -> Option<UniversalID> { None }
}

// ---------------------------------------------------------------------------
// ProgramArchive
// ---------------------------------------------------------------------------

/// An archive embedded within a program.
///
/// The program's [`DataTypeManager`] is the source of truth.
#[derive(Debug)]
pub struct ProgramArchive {
    name: String,
    dtm: StandaloneDataTypeManager,
}

impl ProgramArchive {
    /// Create a new program archive.
    pub fn new(name: impl Into<String>, dtm: StandaloneDataTypeManager) -> Self {
        Self { name: name.into(), dtm }
    }
}

impl Archive for ProgramArchive {
    fn kind(&self) -> ArchiveKind { ArchiveKind::Program }
    fn name(&self) -> Option<&str> { Some(&self.name) }
    fn close(&mut self) { /* program archive lifecycle is managed by the program */ }
    fn is_modifiable(&self) -> bool { true }
    fn is_savable(&self) -> bool { true }
    fn is_changed(&self) -> bool { false }
    fn save(&mut self) -> Result<(), String> { Ok(()) }
    fn data_type_manager(&self) -> &dyn DataTypeManager { &self.dtm }
    fn data_type_manager_mut(&mut self) -> Option<&mut dyn DataTypeManager> { Some(&mut self.dtm) }
    fn universal_id(&self) -> Option<UniversalID> { None }
}

// ---------------------------------------------------------------------------
// ProjectArchive
// ---------------------------------------------------------------------------

/// A project-stored data type archive.
#[derive(Debug)]
pub struct ProjectArchive {
    name: String,
    domain_file_path: String,
    dtm: StandaloneDataTypeManager,
    changed: bool,
}

impl ProjectArchive {
    /// Create a new project archive.
    pub fn new(
        name: impl Into<String>,
        domain_file_path: impl Into<String>,
        dtm: StandaloneDataTypeManager,
    ) -> Self {
        Self {
            name: name.into(),
            domain_file_path: domain_file_path.into(),
            dtm,
            changed: false,
        }
    }

    /// The project-relative path of the domain file.
    pub fn domain_file_path(&self) -> &str {
        &self.domain_file_path
    }
}

impl Archive for ProjectArchive {
    fn kind(&self) -> ArchiveKind { ArchiveKind::Project }
    fn name(&self) -> Option<&str> { Some(&self.name) }
    fn close(&mut self) {}
    fn is_modifiable(&self) -> bool { true }
    fn is_savable(&self) -> bool { true }
    fn is_changed(&self) -> bool { self.changed }
    fn save(&mut self) -> Result<(), String> {
        self.changed = false;
        Ok(())
    }
    fn data_type_manager(&self) -> &dyn DataTypeManager { &self.dtm }
    fn data_type_manager_mut(&mut self) -> Option<&mut dyn DataTypeManager> { Some(&mut self.dtm) }
    fn universal_id(&self) -> Option<UniversalID> { None }
}

// ---------------------------------------------------------------------------
// InvalidFileArchive
// ---------------------------------------------------------------------------

/// A placeholder for an archive whose backing file was not found.
///
/// Shown in the tree so the user can see which source archives a
/// program references even when the archive files are missing.
#[derive(Debug)]
pub struct InvalidFileArchive {
    name: String,
    source_archive: SourceArchive,
    closed: bool,
}

impl InvalidFileArchive {
    /// Create a new invalid-archive placeholder.
    pub fn new(source_archive: SourceArchive) -> Self {
        let name = source_archive.name.clone();
        Self {
            name,
            source_archive,
            closed: false,
        }
    }

    /// The source archive metadata for the missing file.
    pub fn source_archive(&self) -> &SourceArchive {
        &self.source_archive
    }

    /// The universal ID of the missing archive.
    pub fn get_universal_id(&self) -> UniversalID {
        self.source_archive.source_id
    }
}

impl Archive for InvalidFileArchive {
    fn kind(&self) -> ArchiveKind { ArchiveKind::Invalid }
    fn name(&self) -> Option<&str> {
        if self.closed { None } else { Some(&self.name) }
    }
    fn close(&mut self) { self.closed = true; }
    fn is_modifiable(&self) -> bool { false }
    fn is_savable(&self) -> bool { false }
    fn is_changed(&self) -> bool { false }
    fn save(&mut self) -> Result<(), String> {
        Err("Cannot save an invalid archive".into())
    }
    // Invalid archives have no real data type manager; return a static default.
    fn data_type_manager(&self) -> &dyn DataTypeManager {
        // We need a static fallback. Use a OnceLock instance.
        use std::sync::OnceLock;
        static FALLBACK: OnceLock<StandaloneDataTypeManager> = OnceLock::new();
        FALLBACK.get_or_init(StandaloneDataTypeManager::new)
    }
    fn data_type_manager_mut(&mut self) -> Option<&mut dyn DataTypeManager> { None }
    fn universal_id(&self) -> Option<UniversalID> {
        Some(self.source_archive.source_id)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_built_in_archive() {
        let dtm = BuiltInDataTypeManager::new();
        let mut archive = BuiltInArchive::new(dtm);
        assert_eq!(archive.kind(), ArchiveKind::BuiltIn);
        assert_eq!(archive.name(), Some("BuiltInTypes"));
        assert!(!archive.is_modifiable());
        assert!(!archive.is_savable());
        assert!(!archive.is_changed());
        assert!(archive.save().is_ok());
        assert!(archive.universal_id().is_some());
        // close is a no-op
        archive.close();
        assert_eq!(archive.name(), Some("BuiltInTypes"));
    }

    #[test]
    fn test_file_archive() {
        let dtm = StandaloneDataTypeManager::new();
        let mut archive = FileArchive::new("test.gdt", PathBuf::from("/tmp/test.gdt"), dtm, true);
        assert_eq!(archive.kind(), ArchiveKind::File);
        assert!(archive.is_modifiable());
        assert!(archive.is_savable());
        assert!(!archive.is_changed());
        assert!(archive.save().is_ok());
        assert_eq!(archive.file_path(), &PathBuf::from("/tmp/test.gdt"));
        archive.close();
        assert!(archive.name().is_none());
        assert!(!archive.is_modifiable());
    }

    #[test]
    fn test_file_archive_readonly() {
        let dtm = StandaloneDataTypeManager::new();
        let mut archive = FileArchive::new("ro.gdt", PathBuf::from("/tmp/ro.gdt"), dtm, false);
        assert!(!archive.is_modifiable());
        assert!(archive.data_type_manager_mut().is_none());
    }

    #[test]
    fn test_program_archive() {
        let dtm = StandaloneDataTypeManager::new();
        let archive = ProgramArchive::new("my_program", dtm);
        assert_eq!(archive.kind(), ArchiveKind::Program);
        assert!(archive.is_modifiable());
        assert!(archive.is_savable());
        assert!(archive.name().is_some());
    }

    #[test]
    fn test_project_archive() {
        let dtm = StandaloneDataTypeManager::new();
        let mut archive = ProjectArchive::new("my_project", "/project/archive.gdt", dtm);
        assert_eq!(archive.kind(), ArchiveKind::Project);
        assert!(archive.is_modifiable());
        assert_eq!(archive.domain_file_path(), "/project/archive.gdt");
        assert!(archive.save().is_ok());
    }

    #[test]
    fn test_invalid_file_archive() {
        let source = SourceArchive::new(UniversalID::new(99), "file123", "MissingLib");
        let mut archive = InvalidFileArchive::new(source);
        assert_eq!(archive.kind(), ArchiveKind::Invalid);
        assert!(!archive.is_modifiable());
        assert!(!archive.is_savable());
        assert!(archive.save().is_err());
        assert_eq!(archive.name(), Some("MissingLib"));
        assert_eq!(archive.get_universal_id(), UniversalID::new(99));
        archive.close();
        assert!(archive.name().is_none());
    }

    #[test]
    fn test_archive_kind_display() {
        assert_eq!(format!("{}", ArchiveKind::BuiltIn), "BuiltIn");
        assert_eq!(format!("{}", ArchiveKind::File), "File");
        assert_eq!(format!("{}", ArchiveKind::Program), "Program");
        assert_eq!(format!("{}", ArchiveKind::Project), "Project");
        assert_eq!(format!("{}", ArchiveKind::Invalid), "Invalid");
    }
}
