//! Project filesystem store framework.
//!
//! Provides the types and traits for Ghidra's project-level file storage:
//! versioned and non-versioned items, checkout management, local and remote
//! filesystem implementations, and supporting infrastructure.
//!
//! Corresponds to `ghidra.framework.store.*`.

pub mod db;
pub mod listener;
pub mod local;
pub mod remote;

use std::collections::HashMap;
use std::fmt;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::error::GhidraError;
use crate::generic::task::TaskMonitor;

// ============================================================================
// Trait alias for Read+Write (required for trait objects)
// ============================================================================

// ============================================================================
// Result alias
// ============================================================================

/// Result type for store operations.
pub type StoreResult<T> = Result<T, GhidraError>;

// ============================================================================
// Constants
// ============================================================================

/// Path separator character for store paths.
pub const SEPARATOR_CHAR: char = '/';
/// Path separator string.
pub const SEPARATOR: &str = "/";

/// Underlying file is an unknown/unsupported type.
pub const UNKNOWN_FILE_TYPE: i32 = -1;
/// Underlying file is a Database.
pub const DATABASE_FILE_TYPE: i32 = 0;
/// String representation of the database file type.
pub const DATABASE_FILE_TYPE_STR: &str = "0";
/// Underlying file is a serialized data file.
pub const DATAFILE_FILE_TYPE: i32 = 1;
/// Underlying file is a link file.
pub const LINK_FILE_TYPE: i32 = 2;

/// Value used to indicate the latest version.
pub const LATEST_VERSION: i32 = -1;

/// Default checkout ID (indicating no checkout).
pub const DEFAULT_CHECKOUT_ID: i64 = -1;

// ============================================================================
// ReadWrite trait alias
// ============================================================================

/// A combined `Read + Write + Send` trait for objects that support both
/// reading and writing (e.g., database handles opened for update).
pub trait ReadWrite: Read + Write + Send {}
impl<T: Read + Write + Send> ReadWrite for T {}

// ============================================================================
// CheckoutType
// ============================================================================

/// Identifies the type of checkout.
///
/// Corresponds to `ghidra.framework.store.CheckoutType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CheckoutType {
    /// Normal non-exclusive checkout.
    Normal,
    /// Persistent exclusive checkout that prevents any other checkout.
    Exclusive,
    /// Similar to Exclusive but only persists while the client connection
    /// is alive. Only for remote versioned file systems.
    Transient,
}

impl CheckoutType {
    /// Get the abbreviated ID for serialization (first character of the name).
    pub fn id(&self) -> i32 {
        match self {
            CheckoutType::Normal => 'N' as i32,
            CheckoutType::Exclusive => 'E' as i32,
            CheckoutType::Transient => 'T' as i32,
        }
    }

    /// Look up a CheckoutType by its serialization ID.
    pub fn from_id(type_id: i32) -> Option<CheckoutType> {
        match type_id as u8 as char {
            'N' => Some(CheckoutType::Normal),
            'E' => Some(CheckoutType::Exclusive),
            'T' => Some(CheckoutType::Transient),
            _ => None,
        }
    }

    /// Return all variants.
    pub fn values() -> &'static [CheckoutType] {
        &[
            CheckoutType::Normal,
            CheckoutType::Exclusive,
            CheckoutType::Transient,
        ]
    }
}

impl fmt::Display for CheckoutType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CheckoutType::Normal => write!(f, "Normal"),
            CheckoutType::Exclusive => write!(f, "Exclusive"),
            CheckoutType::Transient => write!(f, "Transient"),
        }
    }
}

// ============================================================================
// Version
// ============================================================================

/// Immutable information about a specific version of an item.
///
/// Corresponds to `ghidra.framework.store.Version`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version {
    /// Version number.
    version: i32,
    /// Time at which version was created (millis since epoch).
    create_time: i64,
    /// Name of user who created version.
    user: String,
    /// Version comment.
    comment: String,
}

impl Version {
    /// Create a new version info.
    pub fn new(version: i32, create_time: i64, user: impl Into<String>, comment: impl Into<String>) -> Self {
        Self {
            version,
            create_time,
            user: user.into(),
            comment: comment.into(),
        }
    }

    /// Returns version number.
    pub fn version(&self) -> i32 {
        self.version
    }

    /// Returns time at which version was created (millis since epoch).
    pub fn create_time(&self) -> i64 {
        self.create_time
    }

    /// Returns version comment.
    pub fn comment(&self) -> &str {
        &self.comment
    }

    /// Returns name of user who created version.
    pub fn user(&self) -> &str {
        &self.user
    }
}

// ============================================================================
// ItemCheckoutStatus
// ============================================================================

/// Immutable status information for a checked-out item.
///
/// Corresponds to `ghidra.framework.store.ItemCheckoutStatus`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemCheckoutStatus {
    /// Unique checkout ID.
    checkout_id: i64,
    /// Type of checkout.
    checkout_type: CheckoutType,
    /// User name.
    user: String,
    /// Version of the file that was checked out.
    version: i32,
    /// Time when checkout was completed (millis since epoch).
    time: i64,
    /// User's local project path (host::path format).
    project_path: Option<String>,
}

impl ItemCheckoutStatus {
    /// Create a new checkout status.
    pub fn new(
        checkout_id: i64,
        checkout_type: CheckoutType,
        user: impl Into<String>,
        version: i32,
        time: i64,
        project_path: Option<String>,
    ) -> Self {
        let path = project_path.map(|p| p.replace('\\', "/"));
        Self {
            checkout_id,
            checkout_type,
            user: user.into(),
            version,
            time,
            project_path: path,
        }
    }

    /// Returns the unique checkout ID.
    pub fn checkout_id(&self) -> i64 {
        self.checkout_id
    }

    /// Returns the checkout type.
    pub fn checkout_type(&self) -> CheckoutType {
        self.checkout_type
    }

    /// Returns the user name.
    pub fn user(&self) -> &str {
        &self.user
    }

    /// Returns the checkout version.
    pub fn checkout_version(&self) -> i32 {
        self.version
    }

    /// Returns the checkout time.
    pub fn checkout_time(&self) -> i64 {
        self.time
    }

    /// Returns the user's project path if known.
    pub fn project_path(&self) -> Option<&str> {
        self.project_path.as_deref()
    }

    /// Returns the project name (last path component).
    pub fn project_name(&self) -> Option<&str> {
        let path = self.project_path.as_ref()?;
        let after_host = match path.find("::") {
            Some(idx) => &path[idx + 2..],
            None => path,
        };
        after_host.rsplit('/').next()
    }

    /// Returns the project location (everything except the last path component).
    pub fn project_location(&self) -> Option<&str> {
        let path = self.project_path.as_ref()?;
        let after_host = match path.find("::") {
            Some(idx) => &path[idx + 2..],
            None => path,
        };
        match after_host.rfind('/') {
            Some(idx) => Some(&after_host[..idx]),
            None => None,
        }
    }

    /// Returns the hostname from the project path.
    pub fn user_host_name(&self) -> Option<&str> {
        let path = self.project_path.as_ref()?;
        match path.find("::") {
            Some(idx) => Some(&path[..idx]),
            None => None,
        }
    }

    /// Build a project path string suitable for checkout requests.
    pub fn make_project_path(project_path: &str, is_transient: bool) -> String {
        let hostname = whoami::fallible::hostname().unwrap_or_default();
        let prefix = format!("{}::", hostname);
        if is_transient {
            format!("{}<Transient>", prefix)
        } else {
            format!("{}{}", prefix, project_path)
        }
    }
}

impl std::hash::Hash for ItemCheckoutStatus {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.checkout_id.hash(state);
        self.user.hash(state);
        self.version.hash(state);
        self.time.hash(state);
    }
}

// ============================================================================
// DataFileHandle trait
// ============================================================================

/// Random-access handle to a file.
///
/// Corresponds to `ghidra.framework.store.DataFileHandle`.
pub trait DataFileHandle: Send {
    /// Returns true if this handle is open read-only.
    fn is_read_only(&self) -> StoreResult<bool>;

    /// Read bytes into the buffer.
    fn read_bytes(&mut self, buf: &mut [u8]) -> StoreResult<usize>;

    /// Read bytes at a specific offset.
    fn read_at(&mut self, buf: &mut [u8], offset: u64) -> StoreResult<usize>;

    /// Write bytes from the buffer.
    fn write_bytes(&mut self, buf: &[u8]) -> StoreResult<usize>;

    /// Write bytes at a specific offset.
    fn write_at(&mut self, buf: &[u8], offset: u64) -> StoreResult<usize>;

    /// Skip forward by `n` bytes. Returns actual bytes skipped.
    fn skip_bytes(&mut self, n: u64) -> StoreResult<u64>;

    /// Set the file pointer position.
    fn seek(&mut self, pos: u64) -> StoreResult<()>;

    /// Returns the length of this file.
    fn length(&self) -> StoreResult<u64>;

    /// Set the length of this file.
    fn set_length(&mut self, new_length: u64) -> StoreResult<()>;

    /// Close this handle.
    fn close(&mut self) -> StoreResult<()>;
}

// ============================================================================
// FolderItem trait
// ============================================================================

/// Represents an individual file contained within a FileSystem store,
/// uniquely identified by a path string.
///
/// Corresponds to `ghidra.framework.store.FolderItem`.
pub trait FolderItem: Send + Sync {
    /// Return the display name for this item.
    fn name(&self) -> &str;

    /// Return the file ID if one has been established, or None.
    fn file_id(&self) -> Option<&str>;

    /// Assign a new file-ID to this local non-versioned file.
    fn reset_file_id(&mut self) -> StoreResult<String>;

    /// Returns the length of this domain file.
    fn length(&self) -> StoreResult<i64>;

    /// Returns the content type.
    fn content_type(&self) -> &str;

    /// Returns the current version number.
    fn current_version(&self) -> i32;

    /// Returns the minimum version number.
    fn minimum_version(&self) -> StoreResult<i32>;

    /// Returns true if this item is a checked-out copy.
    fn is_checked_out(&self) -> bool;

    /// Returns true if this item has exclusive checkout.
    fn is_checked_out_exclusive(&self) -> bool;

    /// Returns true if this is a versioned item.
    fn is_versioned(&self) -> StoreResult<bool>;

    /// Returns the checkout ID (-1 for private items).
    fn checkout_id(&self) -> StoreResult<i64>;

    /// Returns the item version that was checked out (-1 for private items).
    fn checkout_version(&self) -> StoreResult<i32>;

    /// Returns the local item version at the time the checkout was completed.
    fn local_checkout_version(&self) -> i32;

    /// Set the checkout data associated with this non-shared file.
    fn set_checkout(
        &mut self,
        checkout_id: i64,
        exclusive: bool,
        checkout_version: i32,
        local_version: i32,
    ) -> StoreResult<()>;

    /// Clear the checkout data.
    fn clear_checkout(&mut self) -> StoreResult<()>;

    /// Delete the item or a specific version.
    fn delete(&mut self, version: i32, user: &str) -> StoreResult<()>;

    /// Returns list of all available versions, or None if not versioned.
    fn get_versions(&self) -> StoreResult<Option<Vec<Version>>>;

    /// Checkout this item.
    fn checkout(
        &self,
        checkout_type: CheckoutType,
        user: &str,
        project_path: &str,
    ) -> StoreResult<Option<ItemCheckoutStatus>>;

    /// Terminate a checkout.
    fn terminate_checkout(&self, checkout_id: i64, notify: bool) -> StoreResult<()>;

    /// Get the checkout status for a given checkout ID.
    fn get_checkout(&self, checkout_id: i64) -> StoreResult<Option<ItemCheckoutStatus>>;

    /// Get all current checkouts for this item.
    fn get_checkouts(&self) -> StoreResult<Vec<ItemCheckoutStatus>>;

    /// Returns true if a checkin is currently in progress.
    fn is_checkin_active(&self) -> StoreResult<bool>;

    /// Update the checkout version.
    fn update_checkout_version(
        &self,
        checkout_id: i64,
        checkout_version: i32,
        user: &str,
    ) -> StoreResult<()>;

    /// Serialize (pack) this item to an output file.
    fn output(
        &self,
        output_file: &Path,
        version: i32,
        monitor: &TaskMonitor,
    ) -> StoreResult<()>;

    /// Refresh this item, returning itself or None if it no longer exists.
    fn refresh(&mut self) -> StoreResult<bool>;

    /// Returns true if this item can be recovered.
    fn can_recover(&self) -> bool;
}

// ============================================================================
// DatabaseItem trait
// ============================================================================

/// Represents a database item (private or versioned) within a FileSystem.
///
/// Corresponds to `ghidra.framework.store.DatabaseItem`.
pub trait DatabaseItem: FolderItem {
    /// Open the current version of the stored database for non-update use.
    fn open(&self) -> StoreResult<Box<dyn Read + Send>>;

    /// Open the current version for update use (initiates checkin on shared FS).
    fn open_for_update(
        &mut self,
        checkout_id: i64,
        user: &str,
    ) -> StoreResult<Box<dyn ReadWrite>>;

    /// Open a specific version for non-update use.
    fn open_version(&self, version: i32) -> StoreResult<Box<dyn Read + Send>>;

    /// Copy the current database to a buffer file.
    fn copy_to(
        &self,
        dest: &mut dyn Write,
        monitor: &TaskMonitor,
    ) -> StoreResult<()>;

    /// Delete all items associated with this database.
    fn delete_database(&mut self, user: &str) -> StoreResult<()>;

    /// Set the content type.
    fn set_content_type(&mut self, content_type: &str) -> StoreResult<()>;
}

// ============================================================================
// DataFileItem trait
// ============================================================================

/// Represents a private serialized data file within a FileSystem.
///
/// Corresponds to `ghidra.framework.store.DataFileItem`.
pub trait DataFileItem: FolderItem {
    /// Open the current version for reading.
    fn get_input_stream(&self) -> StoreResult<Box<dyn Read + Send>>;

    /// Open a new version for writing.
    fn get_output_stream(&self) -> StoreResult<Box<dyn Write + Send>>;

    /// Open a specific version for reading.
    fn get_input_stream_version(&self, version: i32) -> StoreResult<Box<dyn Read + Send>>;
}

// ============================================================================
// TextDataItem trait
// ============================================================================

/// Represents a file that contains only text data and relies on property-file
/// storage (no separate database or data file).
///
/// Corresponds to `ghidra.framework.store.TextDataItem`.
pub trait TextDataItem: FolderItem {
    /// Get the text data stored with this item.
    fn text_data(&self) -> &str;
}

// ============================================================================
// UnknownFolderItem trait
// ============================================================================

/// A folder item with an unknown or unsupported storage type.
///
/// Corresponds to `ghidra.framework.store.UnknownFolderItem`.
pub trait UnknownFolderItem: FolderItem {
    /// The content type string for unknown items.
    const UNKNOWN_CONTENT_TYPE: &'static str = "Unknown-File";

    /// Get the underlying file type (DATABASE_FILE_TYPE, DATAFILE_FILE_TYPE,
    /// LINK_FILE_TYPE, or UNKNOWN_FILE_TYPE).
    fn file_type(&self) -> i32;
}

// ============================================================================
// FileSystem (store) trait
// ============================================================================

/// Hierarchical view and management of a set of files and folders
/// at the project store level.
///
/// This is the *store*-level `FileSystem` (corresponding to
/// `ghidra.framework.store.FileSystem`), distinct from the
/// binary-analysis `GFileSystem` trait in the parent module.
pub trait FileSystemStore: Send + Sync {
    /// Get the user name associated with this filesystem.
    fn user_name(&self) -> &str;

    /// Returns the number of items in the filesystem.
    fn item_count(&self) -> StoreResult<i32>;

    /// Returns the names of items in the given folder.
    fn item_names(
        &self,
        folder_path: &str,
        include_hidden: bool,
    ) -> StoreResult<Vec<String>>;

    /// Returns the names of sub-folders in the given folder.
    fn folder_names(&self, folder_path: &str) -> StoreResult<Vec<String>>;

    /// Returns the folder items in the given folder.
    fn get_items(&self, folder_path: &str) -> StoreResult<Vec<Arc<Mutex<dyn FolderItem>>>>;

    /// Get a specific folder item by path and name.
    fn get_item(
        &self,
        folder_path: &str,
        name: &str,
    ) -> StoreResult<Option<Arc<Mutex<dyn FolderItem>>>>;

    /// Get a folder item by its file ID.
    fn get_item_by_id(&self, file_id: &str) -> StoreResult<Option<Arc<Mutex<dyn FolderItem>>>>;

    /// Maximum allowed item name length.
    fn max_name_length(&self) -> usize;

    /// Create a new folder.
    fn create_folder(&self, parent_path: &str, folder_name: &str) -> StoreResult<()>;

    /// Delete a folder.
    fn delete_folder(&self, folder_path: &str) -> StoreResult<()>;

    /// Move a folder.
    fn move_folder(
        &self,
        parent_path: &str,
        folder_name: &str,
        new_parent_path: &str,
    ) -> StoreResult<()>;

    /// Rename a folder.
    fn rename_folder(
        &self,
        parent_path: &str,
        folder_name: &str,
        new_folder_name: &str,
    ) -> StoreResult<()>;

    /// Move an item.
    fn move_item(
        &self,
        parent_path: &str,
        name: &str,
        new_parent_path: &str,
        new_name: &str,
    ) -> StoreResult<()>;

    /// Returns true if the specified folder exists.
    fn folder_exists(&self, folder_path: &str) -> StoreResult<bool>;

    /// Returns true if the specified file exists.
    fn file_exists(&self, folder_path: &str, item_name: &str) -> StoreResult<bool>;

    /// Returns true if this filesystem is read-only.
    fn is_read_only(&self) -> bool;

    /// Returns true if this filesystem supports versioning.
    fn is_versioned(&self) -> bool;

    /// Create a new data file.
    fn create_data_file(
        &self,
        parent_path: &str,
        name: &str,
        data: &[u8],
        comment: &str,
        content_type: &str,
        monitor: &TaskMonitor,
    ) -> StoreResult<Arc<Mutex<dyn DataFileItem>>>;

    /// Create a new text data item.
    fn create_text_data_item(
        &self,
        parent_path: &str,
        name: &str,
        file_id: Option<&str>,
        content_type: &str,
        text_data: &str,
        comment: &str,
        user: &str,
    ) -> StoreResult<Arc<Mutex<dyn TextDataItem>>>;

    /// Returns true if the specified folder item type is supported.
    fn is_supported_item_type(&self, file_type: i32) -> bool;

    /// Dispose of this filesystem, releasing all resources.
    fn dispose(&mut self) -> StoreResult<()>;

    /// Returns true if a migration is currently in progress.
    fn migration_in_progress(&self) -> bool;
}

// ============================================================================
// LocalFileSystem trait (extends FileSystemStore)
// ============================================================================

/// Extension of FileSystemStore for local filesystem-specific operations.
pub trait LocalFileSystemStore: FileSystemStore {
    /// Get the root directory path.
    fn root_path(&self) -> &Path;

    /// Find an existing storage location for the given item.
    fn find_item_storage(
        &self,
        folder_path: &str,
        item_name: &str,
    ) -> StoreResult<Option<PathBuf>>;

    /// Allocate storage for a new item.
    fn allocate_item_storage(
        &self,
        parent_path: &str,
        name: &str,
    ) -> StoreResult<PathBuf>;

    /// Deallocate storage for an item that failed to create.
    fn deallocate_item_storage(&self, parent_path: &str, name: &str) -> StoreResult<()>;

    /// Get the local database item for the given path/name.
    fn get_database_item(
        &self,
        folder_path: &str,
        name: &str,
    ) -> StoreResult<Option<Arc<Mutex<dyn DatabaseItem>>>>;

    /// Create a new empty database item.
    fn create_empty_database(
        &self,
        parent_path: &str,
        name: &str,
        file_id: Option<&str>,
        content_type: &str,
        buffer_size: i32,
        user: &str,
        project_path: &str,
    ) -> StoreResult<Arc<Mutex<dyn DatabaseItem>>>;

    /// Create a database from an existing buffer.
    fn create_database_from_buffer(
        &self,
        parent_path: &str,
        name: &str,
        file_id: Option<&str>,
        data: &[u8],
        comment: &str,
        content_type: &str,
        reset_database_id: bool,
        monitor: &TaskMonitor,
        user: &str,
    ) -> StoreResult<Arc<Mutex<dyn DatabaseItem>>>;
}

// ============================================================================
// ItemStorage
// ============================================================================

/// Storage location for an item in a local filesystem.
///
/// Corresponds to `ghidra.framework.store.local.ItemStorage`.
#[derive(Debug, Clone)]
pub struct ItemStorage {
    /// Storage directory.
    pub dir: PathBuf,
    /// Mangled storage name (without extension).
    pub storage_name: String,
    /// Logical parent path.
    pub folder_path: String,
    /// Logical item name.
    pub item_name: String,
}

impl ItemStorage {
    /// Create a new ItemStorage.
    pub fn new(
        dir: PathBuf,
        storage_name: String,
        folder_path: String,
        item_name: String,
    ) -> Self {
        Self {
            dir,
            storage_name,
            folder_path,
            item_name,
        }
    }

    /// Get the property file path.
    pub fn property_file_path(&self) -> PathBuf {
        self.dir.join(format!("{}.prp", self.storage_name))
    }
}

// ============================================================================
// PropertyFile
// ============================================================================

/// A file that stores key-value properties.
///
/// Corresponds to the Java `PropertyFile` / `ItemPropertyFile`.
#[derive(Debug, Clone)]
pub struct PropertyFile {
    /// Path to the property file on disk.
    file_path: PathBuf,
    /// The name of the item.
    name: String,
    /// The logical parent path.
    parent_path: String,
    /// Key-value storage.
    properties: HashMap<String, String>,
    /// Whether the file needs to be written.
    dirty: bool,
}

impl PropertyFile {
    /// Property file extension.
    pub const PROPERTY_EXT: &'static str = ".prp";

    /// Create a new PropertyFile at the given path.
    pub fn new(dir: &Path, storage_name: &str, parent_path: &str, name: &str) -> Self {
        let file_path = dir.join(format!("{}{}", storage_name, Self::PROPERTY_EXT));
        let mut pf = Self {
            file_path,
            name: name.to_string(),
            parent_path: parent_path.to_string(),
            properties: HashMap::new(),
            dirty: false,
        };
        // Try to load existing properties
        let _ = pf.read_state();
        pf
    }

    /// Get the item name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the logical parent path.
    pub fn parent_path(&self) -> &str {
        &self.parent_path
    }

    /// Get the storage directory.
    pub fn parent_storage_directory(&self) -> &Path {
        self.file_path.parent().unwrap_or(Path::new("/"))
    }

    /// Check if this file exists on disk.
    pub fn exists(&self) -> bool {
        self.file_path.exists()
    }

    /// Get the last modified time.
    pub fn last_modified(&self) -> u64 {
        std::fs::metadata(&self.file_path)
            .ok()
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }

    /// Get a string property.
    pub fn get_string(&self, key: &str, default: &str) -> String {
        self.properties
            .get(key)
            .cloned()
            .unwrap_or_else(|| default.to_string())
    }

    /// Set a string property.
    pub fn put_string(&mut self, key: &str, value: &str) {
        self.properties.insert(key.to_string(), value.to_string());
        self.dirty = true;
    }

    /// Get an integer property.
    pub fn get_int(&self, key: &str, default: i32) -> i32 {
        self.properties
            .get(key)
            .and_then(|v| v.parse().ok())
            .unwrap_or(default)
    }

    /// Set an integer property.
    pub fn put_int(&mut self, key: &str, value: i32) {
        self.properties.insert(key.to_string(), value.to_string());
        self.dirty = true;
    }

    /// Get a long property.
    pub fn get_long(&self, key: &str, default: i64) -> i64 {
        self.properties
            .get(key)
            .and_then(|v| v.parse().ok())
            .unwrap_or(default)
    }

    /// Set a long property.
    pub fn put_long(&mut self, key: &str, value: i64) {
        self.properties.insert(key.to_string(), value.to_string());
        self.dirty = true;
    }

    /// Get a boolean property.
    pub fn get_boolean(&self, key: &str, default: bool) -> bool {
        self.properties
            .get(key)
            .and_then(|v| v.parse().ok())
            .unwrap_or(default)
    }

    /// Set a boolean property.
    pub fn put_boolean(&mut self, key: &str, value: bool) {
        self.properties
            .insert(key.to_string(), value.to_string());
        self.dirty = true;
    }

    /// Read properties from disk.
    pub fn read_state(&mut self) -> StoreResult<()> {
        if !self.file_path.exists() {
            return Ok(());
        }
        let content = std::fs::read_to_string(&self.file_path)?;
        self.properties.clear();
        for line in content.lines() {
            if let Some((key, value)) = line.split_once('=') {
                self.properties
                    .insert(key.trim().to_string(), value.trim().to_string());
            }
        }
        // Update name and parent_path from stored values if present
        if let Some(stored_name) = self.properties.get("NAME") {
            // Keep the logical name from the constructor, don't overwrite
            let _ = stored_name;
        }
        self.dirty = false;
        Ok(())
    }

    /// Write properties to disk.
    pub fn write_state(&mut self) -> StoreResult<()> {
        if !self.dirty {
            return Ok(());
        }
        // Ensure parent directory exists
        if let Some(parent) = self.file_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut content = String::new();
        for (key, value) in &self.properties {
            content.push_str(&format!("{}={}\n", key, value));
        }
        // Write atomically via temp file
        let tmp_path = self.file_path.with_extension("prp.tmp");
        std::fs::write(&tmp_path, &content)?;
        std::fs::rename(&tmp_path, &self.file_path)?;
        self.dirty = false;
        Ok(())
    }

    /// Move this property file to a new location.
    pub fn move_to(
        &mut self,
        new_dir: &Path,
        new_storage_name: &str,
        new_parent_path: &str,
        new_name: &str,
    ) -> StoreResult<()> {
        let new_path = new_dir.join(format!("{}{}", new_storage_name, Self::PROPERTY_EXT));
        // Check destination doesn't exist
        if new_path.exists() {
            return Err(GhidraError::InvalidData(format!(
                "Destination already exists: {}",
                new_path.display()
            )));
        }
        // Ensure destination directory exists
        if let Some(parent) = new_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::rename(&self.file_path, &new_path)?;
        self.file_path = new_path;
        self.name = new_name.to_string();
        self.parent_path = new_parent_path.to_string();
        self.dirty = true;
        Ok(())
    }

    /// Delete this property file from disk.
    pub fn delete(&self) -> StoreResult<()> {
        if self.file_path.exists() {
            std::fs::remove_file(&self.file_path)?;
        }
        Ok(())
    }

    /// Get the file path.
    pub fn file_path(&self) -> &Path {
        &self.file_path
    }

    /// Get all properties.
    pub fn properties(&self) -> &HashMap<String, String> {
        &self.properties
    }
}

// ============================================================================
// FileIDFactory
// ============================================================================

/// Factory for generating unique file IDs.
///
/// Corresponds to `ghidra.framework.store.FileIDFactory`.
pub struct FileIDFactory;

impl FileIDFactory {
    /// Generate a unique file ID.
    pub fn create_file_id() -> String {
        use std::time::SystemTime;

        // Use a combination of timestamp and random bytes for uniqueness
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default();
        let nanos = now.as_nanos();

        // Get some uniqueness from hostname + PID
        let pid = std::process::id();
        let host = whoami::fallible::hostname().unwrap_or_default();

        // Try to get a socket port for uniqueness (like the Java version)
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .ok()
            .and_then(|l| l.local_addr().ok())
            .map(|a| a.port())
            .unwrap_or(0);

        format!("{:x}{:x}{:x}{:x}", nanos, pid, port, Self::hash_string(&host))
    }

    fn hash_string(s: &str) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut h = DefaultHasher::new();
        s.hash(&mut h);
        h.finish()
    }
}

// ============================================================================
// FileSystemSynchronizer
// ============================================================================

/// Global flag tracking long-running filesystem synchronization.
///
/// Corresponds to `ghidra.framework.store.FileSystemSynchronizer`.
pub struct FileSystemSynchronizer;

static IS_SYNCHRONIZING: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

impl FileSystemSynchronizer {
    /// Set whether a synchronization operation is running.
    pub fn set_synchronizing(b: bool) {
        IS_SYNCHRONIZING.store(b, std::sync::atomic::Ordering::Relaxed);
    }

    /// Returns true if a synchronization is in progress.
    pub fn is_synchronizing() -> bool {
        IS_SYNCHRONIZING.load(std::sync::atomic::Ordering::Relaxed)
    }
}

// ============================================================================
// Exceptions (as error variants)
// ============================================================================

// These are represented as GhidraError variants. We add convenience constructors.

/// Create a lock error.
pub fn lock_error(msg: impl Into<String>) -> GhidraError {
    GhidraError::InvalidState(format!("Lock error: {}", msg.into()))
}

/// Create an exclusive checkout error.
pub fn exclusive_checkout_error(msg: impl Into<String>) -> GhidraError {
    GhidraError::InvalidState(format!("Exclusive checkout: {}", msg.into()))
}

/// Create a folder-not-empty error.
pub fn folder_not_empty_error(msg: impl Into<String>) -> GhidraError {
    GhidraError::InvalidData(format!("Folder not empty: {}", msg.into()))
}

/// Create a duplicate file error.
pub fn duplicate_file_error(msg: impl Into<String>) -> GhidraError {
    GhidraError::InvalidData(format!("Duplicate file: {}", msg.into()))
}

/// Create an invalid name error.
pub fn invalid_name_error(msg: impl Into<String>) -> GhidraError {
    GhidraError::InvalidData(format!("Invalid name: {}", msg.into()))
}

/// Create a read-only error.
pub fn read_only_error() -> GhidraError {
    GhidraError::InvalidState("File system is read-only".to_string())
}

/// Create a file-in-use error.
pub fn file_in_use_error(msg: impl Into<String>) -> GhidraError {
    GhidraError::InvalidState(format!("File in use: {}", msg.into()))
}

/// Create a not-found error for store operations.
pub fn not_found_error(msg: impl Into<String>) -> GhidraError {
    GhidraError::NotFound(msg.into())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_checkout_type_id_roundtrip() {
        for ct in CheckoutType::values() {
            let id = ct.id();
            let recovered = CheckoutType::from_id(id);
            assert_eq!(recovered, Some(*ct));
        }
    }

    #[test]
    fn test_checkout_type_from_invalid_id() {
        assert_eq!(CheckoutType::from_id(999), None);
    }

    #[test]
    fn test_version_fields() {
        let v = Version::new(5, 12345, "alice", "initial commit");
        assert_eq!(v.version(), 5);
        assert_eq!(v.create_time(), 12345);
        assert_eq!(v.user(), "alice");
        assert_eq!(v.comment(), "initial commit");
    }

    #[test]
    fn test_item_checkout_status() {
        let status = ItemCheckoutStatus::new(
            42,
            CheckoutType::Exclusive,
            "bob",
            3,
            100000,
            Some("myhost::/projects/test".to_string()),
        );
        assert_eq!(status.checkout_id(), 42);
        assert_eq!(status.checkout_type(), CheckoutType::Exclusive);
        assert_eq!(status.user(), "bob");
        assert_eq!(status.checkout_version(), 3);
        assert_eq!(status.checkout_time(), 100000);
        assert_eq!(status.user_host_name(), Some("myhost"));
        assert_eq!(status.project_name(), Some("test"));
        assert_eq!(status.project_location(), Some("/projects"));
    }

    #[test]
    fn test_item_checkout_status_no_path() {
        let status = ItemCheckoutStatus::new(
            1,
            CheckoutType::Normal,
            "alice",
            1,
            0,
            None,
        );
        assert_eq!(status.project_path(), None);
        assert_eq!(status.project_name(), None);
        assert_eq!(status.user_host_name(), None);
    }

    #[test]
    fn test_item_checkout_status_backslash_normalize() {
        let status = ItemCheckoutStatus::new(
            1,
            CheckoutType::Normal,
            "alice",
            1,
            0,
            Some(r"host::C:\Users\test".to_string()),
        );
        assert_eq!(status.project_path(), Some("host::C:/Users/test"));
    }

    #[test]
    fn test_property_file_basic() {
        let dir = std::env::temp_dir().join("ghidra_test_propfile");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let mut pf = PropertyFile::new(&dir, "test_item", "/my/path", "item_name");
        assert_eq!(pf.name(), "item_name");
        assert_eq!(pf.parent_path(), "/my/path");

        pf.put_string("key1", "value1");
        pf.put_int("key2", 42);
        pf.put_boolean("key3", true);
        pf.write_state().unwrap();

        // Re-read
        let mut pf2 = PropertyFile::new(&dir, "test_item", "/my/path", "item_name");
        pf2.read_state().unwrap();
        assert_eq!(pf2.get_string("key1", ""), "value1");
        assert_eq!(pf2.get_int("key2", 0), 42);
        assert_eq!(pf2.get_boolean("key3", false), true);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_file_id_factory() {
        let id1 = FileIDFactory::create_file_id();
        let id2 = FileIDFactory::create_file_id();
        // They should be different (very high probability)
        assert_ne!(id1, id2);
        assert!(!id1.is_empty());
    }

    #[test]
    fn test_filesystem_synchronizer() {
        assert!(!FileSystemSynchronizer::is_synchronizing());
        FileSystemSynchronizer::set_synchronizing(true);
        assert!(FileSystemSynchronizer::is_synchronizing());
        FileSystemSynchronizer::set_synchronizing(false);
        assert!(!FileSystemSynchronizer::is_synchronizing());
    }

    #[test]
    fn test_separator_constants() {
        assert_eq!(SEPARATOR_CHAR, '/');
        assert_eq!(SEPARATOR, "/");
        assert_eq!(LATEST_VERSION, -1);
        assert_eq!(DEFAULT_CHECKOUT_ID, -1);
    }

    #[test]
    fn test_error_constructors() {
        let e = lock_error("test lock");
        assert!(format!("{}", e).contains("Lock error"));

        let e = folder_not_empty_error("/my/folder");
        assert!(format!("{}", e).contains("Folder not empty"));

        let e = duplicate_file_error("test.txt");
        assert!(format!("{}", e).contains("Duplicate file"));

        let e = read_only_error();
        assert!(format!("{}", e).contains("read-only"));
    }

    #[test]
    fn test_item_storage() {
        let storage = ItemStorage::new(
            PathBuf::from("/tmp/test"),
            "a1b2c3".to_string(),
            "/parent".to_string(),
            "item.db".to_string(),
        );
        assert_eq!(storage.dir, PathBuf::from("/tmp/test"));
        assert_eq!(storage.storage_name, "a1b2c3");
        assert_eq!(storage.property_file_path(), PathBuf::from("/tmp/test/a1b2c3.prp"));
    }
}
