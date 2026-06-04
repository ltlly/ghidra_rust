//! Local filesystem store implementations.
//!
//! Provides [`LocalFileSystemStoreImpl`] (the local file-system),
//! [`LocalFolderItemBase`] (abstract base for items), and concrete item types:
//! [`LocalDatabaseItem`], [`LocalDataFileItem`], [`LocalTextDataItem`],
//! [`LocalUnknownFolderItem`], plus [`CheckoutManager`], [`HistoryManager`],
//! and [`LockFile`].
//!
//! Corresponds to `ghidra.framework.store.local.*`.

use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::error::GhidraError;
use crate::generic::task::TaskMonitor;
use crate::filesystem::store::{
    self, CheckoutType, DataFileItem, DatabaseItem, FolderItem, ItemCheckoutStatus,
    PropertyFile, TextDataItem, UnknownFolderItem, Version,
    DEFAULT_CHECKOUT_ID, DATAFILE_FILE_TYPE, DATABASE_FILE_TYPE, LATEST_VERSION,
    LINK_FILE_TYPE, SEPARATOR, UNKNOWN_FILE_TYPE,
    FileIDFactory, FileSystemStore, StoreResult,
};
use crate::filesystem::store::listener::FileSystemEventManager;

// ============================================================================
// Constants
// ============================================================================

/// Hidden directory name prefix.
pub const HIDDEN_DIR_PREFIX_CHAR: char = '~';
/// Hidden directory name prefix (string).
pub const HIDDEN_DIR_PREFIX: &str = "~";

/// Hidden item name prefix.
pub const HIDDEN_ITEM_PREFIX: &str = "~";

/// Data directory extension.
pub const DATA_DIR_EXTENSION: &str = ".db";

/// Maximum delete retries.
pub const MAX_DELETE_TRIES: i32 = 5;

/// Maximum lock lease period in seconds.
pub const MAX_LOCK_LEASE_PERIOD: i32 = 300;

/// Invalid filename characters.
pub const INVALID_FILENAME_CHARS: &str = "/\\:*?\"<>|";

/// Maximum pathname length.
pub const MAX_PATHNAME_LENGTH: usize = 200;

/// Property file extension.
pub const PROPERTY_EXT: &str = ".prp";

/// IO buffer size.
pub const IO_BUFFER_SIZE: usize = 32 * 1024;

// ============================================================================
// CheckoutManager
// ============================================================================

/// Manages checkout data for a versioned [`LocalFolderItem`].
///
/// Corresponds to `ghidra.framework.store.local.CheckoutManager`.
pub struct CheckoutManager {
    next_checkout_id: i64,
    checkouts: HashMap<i64, ItemCheckoutStatus>,
}

impl CheckoutManager {
    /// Create a new CheckoutManager.
    pub fn new() -> Self {
        Self {
            next_checkout_id: 1,
            checkouts: HashMap::new(),
        }
    }

    /// Create a checkout, returning the assigned checkout ID.
    pub fn create_checkout(
        &mut self,
        checkout_type: CheckoutType,
        user: &str,
        checkout_version: i32,
        time: i64,
        project_path: Option<String>,
    ) -> i64 {
        let checkout_id = self.next_checkout_id;
        self.next_checkout_id += 1;

        let status = ItemCheckoutStatus::new(
            checkout_id,
            checkout_type,
            user,
            checkout_version,
            time,
            project_path,
        );
        self.checkouts.insert(checkout_id, status);
        checkout_id
    }

    /// Remove a checkout by ID. Returns the removed status.
    pub fn remove_checkout(&mut self, checkout_id: i64) -> Option<ItemCheckoutStatus> {
        self.checkouts.remove(&checkout_id)
    }

    /// Get a checkout by ID.
    pub fn get_checkout(&self, checkout_id: i64) -> Option<&ItemCheckoutStatus> {
        self.checkouts.get(&checkout_id)
    }

    /// Get all checkouts.
    pub fn get_all_checkouts(&self) -> Vec<ItemCheckoutStatus> {
        self.checkouts.values().cloned().collect()
    }

    /// Update the checkout version for a given checkout ID.
    pub fn update_checkout(&mut self, checkout_id: i64, checkout_version: i32) {
        if let Some(status) = self.checkouts.get_mut(&checkout_id) {
            // Create a new status with updated version
            let new_status = ItemCheckoutStatus::new(
                status.checkout_id(),
                status.checkout_type(),
                status.user(),
                checkout_version,
                status.checkout_time(),
                status.project_path().map(|s| s.to_string()),
            );
            self.checkouts.insert(checkout_id, new_status);
        }
    }

    /// Returns true if there are any exclusive checkouts.
    pub fn has_exclusive_checkout(&self) -> bool {
        self.checkouts
            .values()
            .any(|s| s.checkout_type() == CheckoutType::Exclusive)
    }

    /// Returns true if the given checkout is exclusive.
    pub fn is_exclusive(&self, checkout_id: i64) -> bool {
        self.checkouts
            .get(&checkout_id)
            .map(|s| s.checkout_type() == CheckoutType::Exclusive)
            .unwrap_or(false)
    }

    /// Returns the number of active checkouts.
    pub fn checkout_count(&self) -> usize {
        self.checkouts.len()
    }

    /// Check if a specific user has a checkout.
    pub fn user_has_checkout(&self, user: &str) -> bool {
        self.checkouts.values().any(|s| s.user() == user)
    }

    /// Check if a specific user has an exclusive checkout.
    pub fn user_has_exclusive_checkout(&self, user: &str) -> bool {
        self.checkouts.values().any(|s| {
            s.user() == user && s.checkout_type() == CheckoutType::Exclusive
        })
    }
}

impl fmt::Debug for CheckoutManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CheckoutManager")
            .field("next_checkout_id", &self.next_checkout_id)
            .field("checkout_count", &self.checkouts.len())
            .finish()
    }
}

// ============================================================================
// HistoryManager
// ============================================================================

/// Manages version history for a versioned [`LocalFolderItem`].
///
/// Corresponds to `ghidra.framework.store.local.HistoryManager`.
pub struct HistoryManager {
    versions: Vec<Version>,
}

impl HistoryManager {
    /// Create a new HistoryManager.
    pub fn new() -> Self {
        Self {
            versions: Vec::new(),
        }
    }

    /// Add a new version entry.
    pub fn add_version(&mut self, version: Version) {
        self.versions.push(version);
    }

    /// Get all versions.
    pub fn get_versions(&self) -> &[Version] {
        &self.versions
    }

    /// Get the latest version number.
    pub fn latest_version(&self) -> i32 {
        self.versions.last().map(|v| v.version()).unwrap_or(0)
    }

    /// Get the minimum version number.
    pub fn minimum_version(&self) -> i32 {
        self.versions.first().map(|v| v.version()).unwrap_or(0)
    }

    /// Get a specific version by number.
    pub fn get_version(&self, version: i32) -> Option<&Version> {
        self.versions.iter().find(|v| v.version() == version)
    }

    /// Delete a version by number.
    pub fn delete_version(&mut self, version: i32) -> bool {
        let before = self.versions.len();
        self.versions.retain(|v| v.version() != version);
        self.versions.len() < before
    }

    /// The number of versions.
    pub fn version_count(&self) -> usize {
        self.versions.len()
    }
}

impl fmt::Debug for HistoryManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HistoryManager")
            .field("version_count", &self.versions.len())
            .finish()
    }
}

// ============================================================================
// LockFile
// ============================================================================

/// Provides file-based locking with lease management.
///
/// Corresponds to `ghidra.framework.store.local.LockFile`.
pub struct LockFile {
    lock_path: PathBuf,
    lock_count: i32,
    max_lock_lease_period_ms: u64,
    lock_timeout_ms: u64,
}

impl LockFile {
    /// Default maximum lock lease period (seconds).
    pub const MAX_LOCK_LEASE_PERIOD: i32 = MAX_LOCK_LEASE_PERIOD;

    /// Lock file suffix.
    pub const LOCK_SUFFIX: &'static str = ".lock";

    /// Create a new LockFile in the given directory for the given name.
    pub fn new(dir: &Path, name: &str) -> Self {
        let lock_path = dir.join(format!("{}{}", name, Self::LOCK_SUFFIX));
        Self {
            lock_path,
            lock_count: 0,
            max_lock_lease_period_ms: (MAX_LOCK_LEASE_PERIOD as u64) * 1000,
            lock_timeout_ms: 30_000, // 30 second default timeout
        }
    }

    /// Create a LockFile for testing with custom timeouts.
    pub fn for_testing(
        dir: &Path,
        name: &str,
        max_lease_secs: u64,
        timeout_ms: u64,
    ) -> Self {
        let lock_path = dir.join(format!("{}{}", name, Self::LOCK_SUFFIX));
        Self {
            lock_path,
            lock_count: 0,
            max_lock_lease_period_ms: max_lease_secs * 1000,
            lock_timeout_ms: timeout_ms,
        }
    }

    /// Returns the path of the lock file.
    pub fn lock_path(&self) -> &Path {
        &self.lock_path
    }

    /// Attempt to acquire the lock (non-blocking).
    ///
    /// Returns true if the lock was acquired.
    pub fn try_lock(&mut self) -> io::Result<bool> {
        if self.lock_count > 0 {
            self.lock_count += 1;
            return Ok(true);
        }

        // Try to create the lock file atomically
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&self.lock_path)
        {
            Ok(mut file) => {
                // Write lock owner info
                let owner_info = format!(
                    "{}@{}",
                    whoami::username(),
                    whoami::hostname()
                );
                let _ = file.write_all(owner_info.as_bytes());
                self.lock_count = 1;
                Ok(true)
            }
            Err(ref e) if e.kind() == io::ErrorKind::AlreadyExists => {
                // Check for expired lock
                if self.is_lock_expired()? {
                    self.force_remove_lock()?;
                    // Try again
                    match fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(&self.lock_path)
                    {
                        Ok(mut file) => {
                            let owner_info = format!("{}@{}", whoami::username(), "localhost");
                            let _ = file.write_all(owner_info.as_bytes());
                            self.lock_count = 1;
                            Ok(true)
                        }
                        Err(_) => Ok(false),
                    }
                } else {
                    Ok(false)
                }
            }
            Err(e) => Err(e),
        }
    }

    /// Acquire the lock, waiting up to the configured timeout.
    ///
    /// Returns true if the lock was acquired within the timeout.
    pub fn lock(&mut self) -> io::Result<bool> {
        if self.try_lock()? {
            return Ok(true);
        }

        let start = std::time::Instant::now();
        let timeout = std::time::Duration::from_millis(self.lock_timeout_ms);

        while start.elapsed() < timeout {
            std::thread::sleep(std::time::Duration::from_millis(500));
            if self.try_lock()? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Release the lock.
    pub fn unlock(&mut self) {
        if self.lock_count > 0 {
            self.lock_count -= 1;
            if self.lock_count == 0 {
                let _ = self.remove_lock();
            }
        }
    }

    /// Check if the current lock has expired.
    fn is_lock_expired(&self) -> io::Result<bool> {
        match fs::metadata(&self.lock_path) {
            Ok(meta) => {
                let modified = meta
                    .modified()
                    .ok()
                    .and_then(|t| t.elapsed().ok())
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or(u64::MAX);
                Ok(modified > self.max_lock_lease_period_ms)
            }
            Err(_) => Ok(true), // Lock file gone, consider it expired
        }
    }

    /// Remove the lock file.
    fn remove_lock(&self) -> io::Result<()> {
        if self.lock_path.exists() {
            fs::remove_file(&self.lock_path)?;
        }
        Ok(())
    }

    /// Forcefully remove a stale lock file.
    fn force_remove_lock(&self) -> io::Result<()> {
        log::warn!(
            "Forcefully removing lock file: {}",
            self.lock_path.display()
        );
        self.remove_lock()
    }

    /// Returns true if the lock is currently held.
    pub fn is_locked(&self) -> bool {
        self.lock_count > 0
    }

    /// Returns the lock owner info, if available.
    pub fn get_lock_owner(&self) -> Option<String> {
        if self.lock_path.exists() {
            fs::read_to_string(&self.lock_path).ok()
        } else {
            None
        }
    }
}

impl Drop for LockFile {
    fn drop(&mut self) {
        if self.lock_count > 0 {
            self.lock_count = 0;
            let _ = self.remove_lock();
        }
    }
}

impl fmt::Debug for LockFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LockFile")
            .field("path", &self.lock_path)
            .field("lock_count", &self.lock_count)
            .finish()
    }
}

// ============================================================================
// LocalFolderItemBase
// ============================================================================

/// Base fields for all local folder items.
///
/// This is not a standalone type but is embedded in concrete item types.
pub struct LocalFolderItemBase {
    /// Property file storing item metadata.
    pub property_file: PropertyFile,
    /// Checkout manager (if versioned).
    pub checkout_mgr: Option<CheckoutManager>,
    /// History manager (if versioned).
    pub history_mgr: Option<HistoryManager>,
    /// Whether this item is on a versioned filesystem.
    pub is_versioned: bool,
    /// Whether this item uses a data directory.
    pub use_data_dir: bool,
    /// Repository name.
    pub repository_name: Option<String>,
    /// Last modified time.
    pub last_modified: u64,
    /// Checkin ID.
    pub checkin_id: i64,
    /// Whether read-only.
    pub read_only: bool,
    /// Content type.
    pub content_type: String,
    /// File ID.
    pub file_id: Option<String>,
    /// Name.
    pub name: String,
    /// Parent path.
    pub parent_path: String,
    /// Data directory path.
    pub data_dir: PathBuf,
}

impl LocalFolderItemBase {
    /// Property key constants.
    pub const FILE_TYPE: &'static str = "FILE_TYPE";
    pub const READ_ONLY: &'static str = "READ_ONLY";
    pub const CONTENT_TYPE: &'static str = "CONTENT_TYPE";
    pub const CHECKOUT_ID: &'static str = "CHECKOUT_ID";
    pub const EXCLUSIVE_CHECKOUT: &'static str = "EXCLUSIVE";
    pub const CHECKOUT_VERSION: &'static str = "CHECKOUT_VERSION";
    pub const LOCAL_CHECKOUT_VERSION: &'static str = "LOCAL_CHECKOUT_VERSION";

    /// Create a new LocalFolderItemBase for an existing item.
    pub fn new(
        property_file: PropertyFile,
        is_versioned: bool,
        use_data_dir: bool,
    ) -> Self {
        let name = property_file.name().to_string();
        let parent_path = property_file.parent_path().to_string();
        let content_type = property_file.get_string(Self::CONTENT_TYPE, "");
        let file_id: String = property_file
            .get_string("FILE_ID", "");
        let read_only = property_file.get_boolean(Self::READ_ONLY, false);
        let last_modified = property_file.last_modified();

        let file_id_opt = if file_id.as_str().is_empty() {
            None
        } else {
            Some(file_id)
        };

        let data_dir = property_file
            .parent_storage_directory()
            .join(format!(
                "{}{}{}",
                HIDDEN_DIR_PREFIX,
                property_file
                    .file_path()
                    .file_stem()
                    .unwrap_or_default()
                    .to_string_lossy(),
                DATA_DIR_EXTENSION
            ));

        let checkout_mgr = if is_versioned {
            Some(CheckoutManager::new())
        } else {
            None
        };

        let history_mgr = if is_versioned {
            Some(HistoryManager::new())
        } else {
            None
        };

        Self {
            property_file,
            checkout_mgr,
            history_mgr,
            is_versioned,
            use_data_dir,
            repository_name: None,
            last_modified,
            checkin_id: DEFAULT_CHECKOUT_ID,
            read_only,
            content_type,
            file_id: file_id_opt,
            name,
            parent_path,
            data_dir,
        }
    }

    /// Create a new LocalFolderItemBase for a new item.
    pub fn create(
        mut property_file: PropertyFile,
        is_versioned: bool,
        use_data_dir: bool,
        content_type: &str,
        file_id: Option<&str>,
    ) -> StoreResult<Self> {
        property_file.put_string(Self::CONTENT_TYPE, content_type);
        if let Some(fid) = file_id {
            property_file.put_string("FILE_ID", fid);
        }
        property_file.put_boolean(Self::READ_ONLY, false);
        property_file.write_state()?;

        if use_data_dir {
            let data_dir = property_file
                .parent_storage_directory()
                .join(format!(
                    "{}{}{}",
                    HIDDEN_DIR_PREFIX,
                    property_file
                        .file_path()
                        .file_stem()
                        .unwrap_or_default()
                        .to_string_lossy(),
                    DATA_DIR_EXTENSION
                ));
            fs::create_dir_all(&data_dir)?;
        }

        let mut base = Self::new(property_file, is_versioned, use_data_dir);
        base.content_type = content_type.to_string();
        base.file_id = file_id.map(|s| s.to_string());
        Ok(base)
    }

    /// Abort item creation (clean up data directory).
    pub fn abort_create(&self) {
        if self.use_data_dir && self.data_dir.exists() {
            let _ = fs::remove_dir_all(&self.data_dir);
        }
        let _ = self.property_file.file_path().exists()
            .then(|| fs::remove_file(self.property_file.file_path()));
    }

    /// Save state to the property file.
    pub fn save_state(&mut self) -> StoreResult<()> {
        self.property_file.put_string(Self::CONTENT_TYPE, &self.content_type);
        self.property_file.put_boolean(Self::READ_ONLY, self.read_only);
        if let Some(ref fid) = self.file_id {
            self.property_file.put_string("FILE_ID", fid);
        }
        // Save checkout state
        if let Some(ref mgr) = self.checkout_mgr {
            if let Some(status) = mgr.get_checkout(self.checkin_id) {
                self.property_file
                    .put_long(Self::CHECKOUT_ID, status.checkout_id());
                self.property_file
                    .put_boolean(Self::EXCLUSIVE_CHECKOUT, status.checkout_type() == CheckoutType::Exclusive);
                self.property_file
                    .put_int(Self::CHECKOUT_VERSION, status.checkout_version());
            }
        }
        self.property_file.write_state()
    }
}

// ============================================================================
// LocalDatabaseItem
// ============================================================================

/// A [`FolderItem`] implementation for a local database.
///
/// Corresponds to `ghidra.framework.store.local.LocalDatabaseItem`.
pub struct LocalDatabaseItem {
    base: LocalFolderItemBase,
    /// The underlying data directory containing database files.
    buffer_size: i32,
}

impl LocalDatabaseItem {
    /// Create a new LocalDatabaseItem for an existing item.
    pub fn new(property_file: PropertyFile, is_versioned: bool) -> StoreResult<Self> {
        let base = LocalFolderItemBase::new(property_file, is_versioned, true);
        Ok(Self {
            base,
            buffer_size: 0,
        })
    }

    /// Create a new database item.
    pub fn create(
        property_file: PropertyFile,
        is_versioned: bool,
        content_type: &str,
        file_id: Option<&str>,
        buffer_size: i32,
    ) -> StoreResult<Self> {
        let base = LocalFolderItemBase::create(
            property_file,
            is_versioned,
            true,
            content_type,
            file_id,
        )?;
        Ok(Self { base, buffer_size })
    }

    /// The buffer size for this database.
    pub fn buffer_size(&self) -> i32 {
        self.buffer_size
    }

    /// The data directory for this database.
    pub fn data_dir(&self) -> &Path {
        &self.base.data_dir
    }
}

impl FolderItem for LocalDatabaseItem {
    fn name(&self) -> &str {
        &self.base.name
    }

    fn file_id(&self) -> Option<&str> {
        self.base.file_id.as_deref()
    }

    fn reset_file_id(&mut self) -> StoreResult<String> {
        let new_id = FileIDFactory::create_file_id();
        self.base.file_id = Some(new_id.clone());
        self.base.save_state()?;
        Ok(new_id)
    }

    fn length(&self) -> StoreResult<i64> {
        // Sum up file sizes in the data directory
        let mut total: i64 = 0;
        if self.base.data_dir.exists() {
            if let Ok(entries) = fs::read_dir(&self.base.data_dir) {
                for entry in entries.flatten() {
                    if let Ok(meta) = entry.metadata() {
                        total += meta.len() as i64;
                    }
                }
            }
        }
        Ok(total)
    }

    fn content_type(&self) -> &str {
        &self.base.content_type
    }

    fn current_version(&self) -> i32 {
        self.base
            .history_mgr
            .as_ref()
            .map(|h| h.latest_version())
            .unwrap_or(0)
    }

    fn minimum_version(&self) -> StoreResult<i32> {
        Ok(self
            .base
            .history_mgr
            .as_ref()
            .map(|h| h.minimum_version())
            .unwrap_or(0))
    }

    fn is_checked_out(&self) -> bool {
        self.base.checkin_id != DEFAULT_CHECKOUT_ID
    }

    fn is_checked_out_exclusive(&self) -> bool {
        self.base
            .checkout_mgr
            .as_ref()
            .and_then(|mgr| mgr.get_checkout(self.base.checkin_id))
            .map(|s| s.checkout_type() == CheckoutType::Exclusive)
            .unwrap_or(false)
    }

    fn is_versioned(&self) -> StoreResult<bool> {
        Ok(self.base.is_versioned)
    }

    fn checkout_id(&self) -> StoreResult<i64> {
        Ok(self.base.checkin_id)
    }

    fn checkout_version(&self) -> StoreResult<i32> {
        Ok(self
            .base
            .property_file
            .get_int(LocalFolderItemBase::CHECKOUT_VERSION, -1))
    }

    fn local_checkout_version(&self) -> i32 {
        self.base
            .property_file
            .get_int(LocalFolderItemBase::LOCAL_CHECKOUT_VERSION, -1)
    }

    fn set_checkout(
        &mut self,
        checkout_id: i64,
        exclusive: bool,
        checkout_version: i32,
        local_version: i32,
    ) -> StoreResult<()> {
        self.base.checkin_id = checkout_id;
        self.base
            .property_file
            .put_long(LocalFolderItemBase::CHECKOUT_ID, checkout_id);
        self.base.property_file.put_boolean(
            LocalFolderItemBase::EXCLUSIVE_CHECKOUT,
            exclusive,
        );
        self.base
            .property_file
            .put_int(LocalFolderItemBase::CHECKOUT_VERSION, checkout_version);
        self.base
            .property_file
            .put_int(LocalFolderItemBase::LOCAL_CHECKOUT_VERSION, local_version);
        self.base.save_state()
    }

    fn clear_checkout(&mut self) -> StoreResult<()> {
        self.base.checkin_id = DEFAULT_CHECKOUT_ID;
        self.base
            .property_file
            .put_long(LocalFolderItemBase::CHECKOUT_ID, DEFAULT_CHECKOUT_ID);
        self.base
            .property_file
            .put_boolean(LocalFolderItemBase::EXCLUSIVE_CHECKOUT, false);
        self.base.save_state()
    }

    fn delete(&mut self, version: i32, _user: &str) -> StoreResult<()> {
        if version == LATEST_VERSION {
            // Delete all versions - remove the entire item
            if self.base.use_data_dir && self.base.data_dir.exists() {
                fs::remove_dir_all(&self.base.data_dir)?;
            }
            self.base.property_file.delete()?;
        }
        Ok(())
    }

    fn get_versions(&self) -> StoreResult<Option<Vec<Version>>> {
        if !self.base.is_versioned {
            return Ok(None);
        }
        Ok(self
            .base
            .history_mgr
            .as_ref()
            .map(|h| h.get_versions().to_vec()))
    }

    fn checkout(
        &self,
        _checkout_type: CheckoutType,
        _user: &str,
        _project_path: &str,
    ) -> StoreResult<Option<ItemCheckoutStatus>> {
        Err(GhidraError::NotSupported(
            "Checkout not yet implemented for LocalDatabaseItem".into(),
        ))
    }

    fn terminate_checkout(&self, _checkout_id: i64, _notify: bool) -> StoreResult<()> {
        Err(GhidraError::NotSupported(
            "terminateCheckout not yet implemented".into(),
        ))
    }

    fn get_checkout(&self, checkout_id: i64) -> StoreResult<Option<ItemCheckoutStatus>> {
        Ok(self
            .base
            .checkout_mgr
            .as_ref()
            .and_then(|mgr| mgr.get_checkout(checkout_id).cloned()))
    }

    fn get_checkouts(&self) -> StoreResult<Vec<ItemCheckoutStatus>> {
        Ok(self
            .base
            .checkout_mgr
            .as_ref()
            .map(|mgr| mgr.get_all_checkouts())
            .unwrap_or_default())
    }

    fn is_checkin_active(&self) -> StoreResult<bool> {
        Ok(self.base.checkin_id != DEFAULT_CHECKOUT_ID)
    }

    fn update_checkout_version(
        &self,
        _checkout_id: i64,
        _checkout_version: i32,
        _user: &str,
    ) -> StoreResult<()> {
        Err(GhidraError::NotSupported(
            "updateCheckoutVersion not yet implemented".into(),
        ))
    }

    fn output(
        &self,
        _output_file: &Path,
        _version: i32,
        _monitor: &TaskMonitor,
    ) -> StoreResult<()> {
        Err(GhidraError::NotSupported(
            "Output not yet implemented for LocalDatabaseItem".into(),
        ))
    }

    fn refresh(&mut self) -> StoreResult<bool> {
        if !self.base.property_file.exists() {
            return Ok(false);
        }
        self.base.property_file.read_state()?;
        self.base.last_modified = self.base.property_file.last_modified();
        Ok(true)
    }

    fn can_recover(&self) -> bool {
        false
    }
}

impl DatabaseItem for LocalDatabaseItem {
    fn open(&self) -> StoreResult<Box<dyn Read + Send>> {
        Err(GhidraError::NotSupported(
            "Database open requires buffer file subsystem".into(),
        ))
    }

    fn open_for_update(
        &mut self,
        _checkout_id: i64,
        _user: &str,
    ) -> StoreResult<Box<dyn super::ReadWrite>> {
        Err(GhidraError::NotSupported(
            "Database open_for_update requires buffer file subsystem".into(),
        ))
    }

    fn open_version(&self, _version: i32) -> StoreResult<Box<dyn Read + Send>> {
        Err(GhidraError::NotSupported(
            "Database open_version requires buffer file subsystem".into(),
        ))
    }

    fn copy_to(
        &self,
        _dest: &mut dyn Write,
        _monitor: &TaskMonitor,
    ) -> StoreResult<()> {
        Err(GhidraError::NotSupported(
            "Database copy requires buffer file subsystem".into(),
        ))
    }

    fn delete_database(&mut self, user: &str) -> StoreResult<()> {
        self.delete(LATEST_VERSION, user)
    }

    fn set_content_type(&mut self, content_type: &str) -> StoreResult<()> {
        self.base.content_type = content_type.to_string();
        self.base.save_state()
    }
}

impl fmt::Debug for LocalDatabaseItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalDatabaseItem")
            .field("name", &self.base.name)
            .field("content_type", &self.base.content_type)
            .field("is_versioned", &self.base.is_versioned)
            .field("data_dir", &self.base.data_dir)
            .finish()
    }
}

// ============================================================================
// LocalDataFileItem
// ============================================================================

/// A [`FolderItem`] implementation for a local serialized data file.
///
/// Supports non-versioned filesystems only.
///
/// Corresponds to `ghidra.framework.store.local.LocalDataFileItem`.
pub struct LocalDataFileItem {
    base: LocalFolderItemBase,
}

impl LocalDataFileItem {
    /// Data file name within the data directory.
    pub const DATA_FILE: &'static str = "data.1.gdf";

    /// Create a new LocalDataFileItem for an existing item.
    pub fn new(property_file: PropertyFile) -> StoreResult<Self> {
        let base = LocalFolderItemBase::new(property_file, false, true);
        if !base.data_dir.join(Self::DATA_FILE).exists() {
            return Err(GhidraError::NotFound(format!(
                "Data file missing for: {}",
                base.name
            )));
        }
        Ok(Self { base })
    }

    /// Create a new LocalDataFileItem with initial data.
    pub fn create(
        property_file: PropertyFile,
        content_type: &str,
        data: &[u8],
    ) -> StoreResult<Self> {
        let base = LocalFolderItemBase::create(
            property_file,
            false,
            true,
            content_type,
            None,
        )?;
        let data_file = base.data_dir.join(Self::DATA_FILE);
        fs::write(&data_file, data)?;
        Ok(Self { base })
    }

    /// Get the path to the data file.
    pub fn data_file_path(&self) -> PathBuf {
        self.base.data_dir.join(Self::DATA_FILE)
    }
}

impl FolderItem for LocalDataFileItem {
    fn name(&self) -> &str {
        &self.base.name
    }

    fn file_id(&self) -> Option<&str> {
        self.base.file_id.as_deref()
    }

    fn reset_file_id(&mut self) -> StoreResult<String> {
        let new_id = FileIDFactory::create_file_id();
        self.base.file_id = Some(new_id.clone());
        self.base.save_state()?;
        Ok(new_id)
    }

    fn length(&self) -> StoreResult<i64> {
        let path = self.data_file_path();
        if path.exists() {
            Ok(fs::metadata(&path)?.len() as i64)
        } else {
            Ok(-1)
        }
    }

    fn content_type(&self) -> &str {
        &self.base.content_type
    }

    fn current_version(&self) -> i32 {
        -1
    }

    fn minimum_version(&self) -> StoreResult<i32> {
        Ok(-1)
    }

    fn is_checked_out(&self) -> bool {
        false
    }

    fn is_checked_out_exclusive(&self) -> bool {
        false
    }

    fn is_versioned(&self) -> StoreResult<bool> {
        Ok(false)
    }

    fn checkout_id(&self) -> StoreResult<i64> {
        Ok(DEFAULT_CHECKOUT_ID)
    }

    fn checkout_version(&self) -> StoreResult<i32> {
        Ok(-1)
    }

    fn local_checkout_version(&self) -> i32 {
        -1
    }

    fn set_checkout(
        &mut self,
        _checkout_id: i64,
        _exclusive: bool,
        _checkout_version: i32,
        _local_version: i32,
    ) -> StoreResult<()> {
        Err(GhidraError::NotSupported(
            "Data files do not support checkout".into(),
        ))
    }

    fn clear_checkout(&mut self) -> StoreResult<()> {
        Err(GhidraError::NotSupported(
            "Data files do not support checkout".into(),
        ))
    }

    fn delete(&mut self, _version: i32, _user: &str) -> StoreResult<()> {
        if self.base.use_data_dir && self.base.data_dir.exists() {
            fs::remove_dir_all(&self.base.data_dir)?;
        }
        self.base.property_file.delete()?;
        Ok(())
    }

    fn get_versions(&self) -> StoreResult<Option<Vec<Version>>> {
        Ok(None)
    }

    fn checkout(
        &self,
        _checkout_type: CheckoutType,
        _user: &str,
        _project_path: &str,
    ) -> StoreResult<Option<ItemCheckoutStatus>> {
        Err(GhidraError::NotSupported(
            "Data files do not support checkout".into(),
        ))
    }

    fn terminate_checkout(&self, _checkout_id: i64, _notify: bool) -> StoreResult<()> {
        Err(GhidraError::NotSupported(
            "Data files do not support checkout".into(),
        ))
    }

    fn get_checkout(&self, _checkout_id: i64) -> StoreResult<Option<ItemCheckoutStatus>> {
        Ok(None)
    }

    fn get_checkouts(&self) -> StoreResult<Vec<ItemCheckoutStatus>> {
        Ok(Vec::new())
    }

    fn is_checkin_active(&self) -> StoreResult<bool> {
        Ok(false)
    }

    fn update_checkout_version(
        &self,
        _checkout_id: i64,
        _checkout_version: i32,
        _user: &str,
    ) -> StoreResult<()> {
        Err(GhidraError::NotSupported(
            "Data files do not support checkout".into(),
        ))
    }

    fn output(
        &self,
        _output_file: &Path,
        _version: i32,
        _monitor: &TaskMonitor,
    ) -> StoreResult<()> {
        Err(GhidraError::NotSupported(
            "Output not yet supported for DataFiles".into(),
        ))
    }

    fn refresh(&mut self) -> StoreResult<bool> {
        if !self.base.property_file.exists() {
            return Ok(false);
        }
        self.base.property_file.read_state()?;
        Ok(true)
    }

    fn can_recover(&self) -> bool {
        false
    }
}

impl DataFileItem for LocalDataFileItem {
    fn get_input_stream(&self) -> StoreResult<Box<dyn Read + Send>> {
        let file = fs::File::open(self.data_file_path())?;
        Ok(Box::new(file))
    }

    fn get_output_stream(&self) -> StoreResult<Box<dyn Write + Send>> {
        let file = fs::File::create(self.data_file_path())?;
        Ok(Box::new(file))
    }

    fn get_input_stream_version(&self, _version: i32) -> StoreResult<Box<dyn Read + Send>> {
        self.get_input_stream()
    }
}

impl fmt::Debug for LocalDataFileItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalDataFileItem")
            .field("name", &self.base.name)
            .field("content_type", &self.base.content_type)
            .finish()
    }
}

// ============================================================================
// LocalTextDataItem
// ============================================================================

/// A [`FolderItem`] implementation that stores text data within the property file.
///
/// Corresponds to `ghidra.framework.store.local.LocalTextDataItem`.
pub struct LocalTextDataItem {
    base: LocalFolderItemBase,
    text_data: String,
}

impl LocalTextDataItem {
    const TEXT_PROPERTY: &'static str = "TEXT";
    const VERSION_CREATE_USER: &'static str = "CREATE_USER";
    const VERSION_CREATE_TIME: &'static str = "CREATE_TIME";
    const VERSION_CREATE_COMMENT: &'static str = "CREATE_COMMENT";

    /// Create a new LocalTextDataItem for an existing item.
    pub fn new(property_file: PropertyFile, is_versioned: bool) -> StoreResult<Self> {
        let base = LocalFolderItemBase::new(property_file, is_versioned, false);
        let text_data = base.property_file.get_string(Self::TEXT_PROPERTY, "");
        Ok(Self { base, text_data })
    }

    /// Create a new LocalTextDataItem with initial text data.
    pub fn create(
        property_file: PropertyFile,
        is_versioned: bool,
        content_type: &str,
        file_id: Option<&str>,
        text_data: &str,
    ) -> StoreResult<Self> {
        if content_type.is_empty() {
            return Err(GhidraError::InvalidData(
                "Content type must not be blank".into(),
            ));
        }
        let mut base = LocalFolderItemBase::create(
            property_file,
            is_versioned,
            false,
            content_type,
            file_id,
        )?;
        base.property_file
            .put_string(Self::TEXT_PROPERTY, text_data);
        base.property_file.put_int(
            LocalFolderItemBase::FILE_TYPE,
            LINK_FILE_TYPE,
        );
        base.save_state()?;

        Ok(Self {
            base,
            text_data: text_data.to_string(),
        })
    }

    /// Set the version info for a versioned text item.
    pub fn set_version_info(&mut self, version: &Version) -> StoreResult<()> {
        if !self.base.is_versioned {
            return Err(GhidraError::NotSupported(
                "Versioning not supported".into(),
            ));
        }
        self.base.property_file.put_string(
            Self::VERSION_CREATE_USER,
            version.user(),
        );
        self.base.property_file.put_long(
            Self::VERSION_CREATE_TIME,
            version.create_time(),
        );
        self.base.property_file.put_string(
            Self::VERSION_CREATE_COMMENT,
            version.comment(),
        );
        self.base.save_state()
    }
}

impl FolderItem for LocalTextDataItem {
    fn name(&self) -> &str {
        &self.base.name
    }

    fn file_id(&self) -> Option<&str> {
        self.base.file_id.as_deref()
    }

    fn reset_file_id(&mut self) -> StoreResult<String> {
        let new_id = FileIDFactory::create_file_id();
        self.base.file_id = Some(new_id.clone());
        self.base.save_state()?;
        Ok(new_id)
    }

    fn length(&self) -> StoreResult<i64> {
        Ok(self.text_data.len() as i64)
    }

    fn content_type(&self) -> &str {
        &self.base.content_type
    }

    fn current_version(&self) -> i32 {
        1
    }

    fn minimum_version(&self) -> StoreResult<i32> {
        Ok(1)
    }

    fn is_checked_out(&self) -> bool {
        false
    }

    fn is_checked_out_exclusive(&self) -> bool {
        false
    }

    fn is_versioned(&self) -> StoreResult<bool> {
        Ok(self.base.is_versioned)
    }

    fn checkout_id(&self) -> StoreResult<i64> {
        Ok(DEFAULT_CHECKOUT_ID)
    }

    fn checkout_version(&self) -> StoreResult<i32> {
        Ok(-1)
    }

    fn local_checkout_version(&self) -> i32 {
        -1
    }

    fn set_checkout(
        &mut self,
        _checkout_id: i64,
        _exclusive: bool,
        _checkout_version: i32,
        _local_version: i32,
    ) -> StoreResult<()> {
        Err(GhidraError::NotSupported(
            "Text items do not support checkout".into(),
        ))
    }

    fn clear_checkout(&mut self) -> StoreResult<()> {
        Err(GhidraError::NotSupported(
            "Text items do not support checkout".into(),
        ))
    }

    fn delete(&mut self, _version: i32, _user: &str) -> StoreResult<()> {
        self.base.property_file.delete()?;
        Ok(())
    }

    fn get_versions(&self) -> StoreResult<Option<Vec<Version>>> {
        if !self.base.is_versioned {
            return Err(GhidraError::NotSupported(
                "Non-versioned item does not support getVersions".into(),
            ));
        }
        let user = self
            .base
            .property_file
            .get_string(Self::VERSION_CREATE_USER, "");
        let time = self
            .base
            .property_file
            .get_long(Self::VERSION_CREATE_TIME, 0);
        let comment = self
            .base
            .property_file
            .get_string(Self::VERSION_CREATE_COMMENT, "");
        Ok(Some(vec![Version::new(1, time, user, comment)]))
    }

    fn checkout(
        &self,
        _checkout_type: CheckoutType,
        _user: &str,
        _project_path: &str,
    ) -> StoreResult<Option<ItemCheckoutStatus>> {
        Err(GhidraError::NotSupported(
            "Text items do not support checkout".into(),
        ))
    }

    fn terminate_checkout(&self, _checkout_id: i64, _notify: bool) -> StoreResult<()> {
        Err(GhidraError::NotSupported(
            "Text items do not support checkout".into(),
        ))
    }

    fn get_checkout(&self, _checkout_id: i64) -> StoreResult<Option<ItemCheckoutStatus>> {
        Ok(None)
    }

    fn get_checkouts(&self) -> StoreResult<Vec<ItemCheckoutStatus>> {
        Ok(Vec::new())
    }

    fn is_checkin_active(&self) -> StoreResult<bool> {
        Ok(false)
    }

    fn update_checkout_version(
        &self,
        _checkout_id: i64,
        _checkout_version: i32,
        _user: &str,
    ) -> StoreResult<()> {
        Err(GhidraError::NotSupported(
            "Text items do not support checkout".into(),
        ))
    }

    fn output(
        &self,
        _output_file: &Path,
        _version: i32,
        _monitor: &TaskMonitor,
    ) -> StoreResult<()> {
        Err(GhidraError::NotSupported(
            "Output not supported for TextDataItem".into(),
        ))
    }

    fn refresh(&mut self) -> StoreResult<bool> {
        if !self.base.property_file.exists() {
            return Ok(false);
        }
        self.base.property_file.read_state()?;
        self.text_data = self
            .base
            .property_file
            .get_string(Self::TEXT_PROPERTY, "");
        Ok(true)
    }

    fn can_recover(&self) -> bool {
        false
    }
}

impl TextDataItem for LocalTextDataItem {
    fn text_data(&self) -> &str {
        &self.text_data
    }
}

impl fmt::Debug for LocalTextDataItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalTextDataItem")
            .field("name", &self.base.name)
            .field("text_len", &self.text_data.len())
            .finish()
    }
}

// ============================================================================
// LocalUnknownFolderItem
// ============================================================================

/// A [`FolderItem`] for an unknown or unsupported storage type.
///
/// Corresponds to `ghidra.framework.store.local.LocalUnknownFolderItem`.
pub struct LocalUnknownFolderItem {
    base: LocalFolderItemBase,
    file_type: i32,
}

impl LocalUnknownFolderItem {
    /// Create a new unknown item.
    pub fn new(property_file: PropertyFile) -> StoreResult<Self> {
        let base = LocalFolderItemBase::new(property_file, false, false);
        let file_type = base
            .property_file
            .get_int(LocalFolderItemBase::FILE_TYPE, UNKNOWN_FILE_TYPE);
        Ok(Self { base, file_type })
    }
}

impl FolderItem for LocalUnknownFolderItem {
    fn name(&self) -> &str {
        &self.base.name
    }

    fn file_id(&self) -> Option<&str> {
        self.base.file_id.as_deref()
    }

    fn reset_file_id(&mut self) -> StoreResult<String> {
        Err(GhidraError::NotSupported(
            "Cannot reset file ID on unknown item".into(),
        ))
    }

    fn length(&self) -> StoreResult<i64> {
        Ok(-1)
    }

    fn content_type(&self) -> &str {
        &self.base.content_type
    }

    fn current_version(&self) -> i32 {
        -1
    }

    fn minimum_version(&self) -> StoreResult<i32> {
        Ok(-1)
    }

    fn is_checked_out(&self) -> bool {
        false
    }

    fn is_checked_out_exclusive(&self) -> bool {
        false
    }

    fn is_versioned(&self) -> StoreResult<bool> {
        Ok(false)
    }

    fn checkout_id(&self) -> StoreResult<i64> {
        Ok(DEFAULT_CHECKOUT_ID)
    }

    fn checkout_version(&self) -> StoreResult<i32> {
        Ok(-1)
    }

    fn local_checkout_version(&self) -> i32 {
        -1
    }

    fn set_checkout(
        &mut self,
        _checkout_id: i64,
        _exclusive: bool,
        _checkout_version: i32,
        _local_version: i32,
    ) -> StoreResult<()> {
        Err(GhidraError::NotSupported(
            "Unknown item does not support operations".into(),
        ))
    }

    fn clear_checkout(&mut self) -> StoreResult<()> {
        Err(GhidraError::NotSupported(
            "Unknown item does not support operations".into(),
        ))
    }

    fn delete(&mut self, _version: i32, _user: &str) -> StoreResult<()> {
        self.base.property_file.delete()?;
        Ok(())
    }

    fn get_versions(&self) -> StoreResult<Option<Vec<Version>>> {
        Ok(None)
    }

    fn checkout(
        &self,
        _checkout_type: CheckoutType,
        _user: &str,
        _project_path: &str,
    ) -> StoreResult<Option<ItemCheckoutStatus>> {
        Err(GhidraError::NotSupported(
            "Unknown item does not support checkout".into(),
        ))
    }

    fn terminate_checkout(&self, _checkout_id: i64, _notify: bool) -> StoreResult<()> {
        Err(GhidraError::NotSupported(
            "Unknown item does not support checkout".into(),
        ))
    }

    fn get_checkout(&self, _checkout_id: i64) -> StoreResult<Option<ItemCheckoutStatus>> {
        Ok(None)
    }

    fn get_checkouts(&self) -> StoreResult<Vec<ItemCheckoutStatus>> {
        Ok(Vec::new())
    }

    fn is_checkin_active(&self) -> StoreResult<bool> {
        Ok(false)
    }

    fn update_checkout_version(
        &self,
        _checkout_id: i64,
        _checkout_version: i32,
        _user: &str,
    ) -> StoreResult<()> {
        Err(GhidraError::NotSupported(
            "Unknown item does not support operations".into(),
        ))
    }

    fn output(
        &self,
        _output_file: &Path,
        _version: i32,
        _monitor: &TaskMonitor,
    ) -> StoreResult<()> {
        Err(GhidraError::NotSupported(
            "Unknown item does not support output".into(),
        ))
    }

    fn refresh(&mut self) -> StoreResult<bool> {
        if !self.base.property_file.exists() {
            return Ok(false);
        }
        self.base.property_file.read_state()?;
        Ok(true)
    }

    fn can_recover(&self) -> bool {
        false
    }
}

impl UnknownFolderItem for LocalUnknownFolderItem {
    fn file_type(&self) -> i32 {
        self.file_type
    }
}

impl fmt::Debug for LocalUnknownFolderItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalUnknownFolderItem")
            .field("name", &self.base.name)
            .field("file_type", &self.file_type)
            .finish()
    }
}

// ============================================================================
// LocalFileSystemStoreImpl
// ============================================================================

/// Local filesystem that stores project items in a directory hierarchy.
///
/// Corresponds to `ghidra.framework.store.local.LocalFileSystem` (the abstract
/// class) combined with the `MangledLocalFileSystem` (legacy storage scheme).
/// For simplicity, this Rust implementation uses direct name mapping (not
/// mangled names).
pub struct LocalFileSystemStoreImpl {
    /// Root directory of this filesystem.
    root: PathBuf,
    /// Whether this filesystem is versioned.
    is_versioned: bool,
    /// Whether this filesystem is read-only.
    read_only: bool,
    /// Event manager for file system events.
    event_manager: FileSystemEventManager,
    /// Item cache: (folder_path, name) -> item.
    items: HashMap<(String, String), Arc<Mutex<Box<dyn FolderItem>>>>,
}

impl LocalFileSystemStoreImpl {
    /// Create a new local filesystem store.
    pub fn new(
        root_path: &str,
        is_versioned: bool,
        read_only: bool,
        async_dispatch: bool,
    ) -> StoreResult<Self> {
        let root = PathBuf::from(root_path);
        if !root.exists() {
            fs::create_dir_all(&root)?;
        }
        if !root.is_dir() {
            return Err(GhidraError::NotFound(format!(
                "Not a directory: {}",
                root_path
            )));
        }

        let event_manager = FileSystemEventManager::new(async_dispatch);

        let mut fs = Self {
            root,
            is_versioned,
            read_only,
            event_manager,
            items: HashMap::new(),
        };

        if !read_only {
            fs.cleanup_temporary_files(SEPARATOR)?;
        }

        Ok(fs)
    }

    /// Create a read-only empty local filesystem.
    pub fn empty() -> Self {
        Self {
            root: PathBuf::new(),
            is_versioned: false,
            read_only: true,
            event_manager: FileSystemEventManager::new(false),
            items: HashMap::new(),
        }
    }

    /// Get the root path.
    pub fn root_path(&self) -> &Path {
        &self.root
    }

    /// Check if a name is a hidden item.
    pub fn is_hidden_item_name(name: &str) -> bool {
        name.starts_with(HIDDEN_ITEM_PREFIX)
    }

    /// Check if a name is a hidden directory.
    pub fn is_hidden_dir_name(name: &str) -> bool {
        name.starts_with(HIDDEN_DIR_PREFIX)
    }

    /// Test if a name character is valid.
    pub fn is_valid_name_character(c: char) -> bool {
        !((c < ' ') || INVALID_FILENAME_CHARS.contains(c) || (c > '\u{00FF}'))
    }

    /// Validate an item name.
    pub fn test_valid_name(name: &str, is_folder_path: bool) -> StoreResult<()> {
        if name.is_empty() {
            return Err(store::invalid_name_error("Name must not be empty"));
        }
        if is_folder_path && name == SEPARATOR {
            return Ok(());
        }
        for c in name.chars() {
            // For folder paths, '/' is allowed as a path separator
            if c == '/' && is_folder_path {
                continue;
            }
            if !Self::is_valid_name_character(c) {
                return Err(store::invalid_name_error(format!(
                    "Invalid character '{}' in name: {}",
                    c, name
                )));
            }
        }
        if name.len() > MAX_PATHNAME_LENGTH {
            return Err(store::invalid_name_error(format!(
                "Name too long ({} chars): {}",
                name.len(),
                name
            )));
        }
        Ok(())
    }

    /// Get the filesystem path for a folder.
    fn get_folder_path(&self, folder_path: &str) -> PathBuf {
        if folder_path == SEPARATOR || folder_path.is_empty() {
            return self.root.clone();
        }
        // Strip leading separator and join
        let relative = folder_path.trim_start_matches('/');
        self.root.join(relative)
    }

    /// Get the filesystem path for an item's property file.
    fn get_item_property_path(&self, folder_path: &str, name: &str) -> PathBuf {
        let dir = self.get_folder_path(folder_path);
        dir.join(format!("{}{}", name, PROPERTY_EXT))
    }

    /// Clean up temporary files.
    fn cleanup_temporary_files(&self, folder_path: &str) -> StoreResult<()> {
        let dir = self.get_folder_path(folder_path);
        if !dir.exists() {
            return Ok(());
        }
        for entry in fs::read_dir(&dir)?.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with(HIDDEN_ITEM_PREFIX) {
                // Check if it's a temp file
                let path = entry.path();
                if path.is_file() && name.ends_with(".tmp") {
                    let _ = fs::remove_file(&path);
                }
            }
        }
        Ok(())
    }

    /// Get the event manager.
    pub fn event_manager(&self) -> &FileSystemEventManager {
        &self.event_manager
    }

    /// Get a mutable reference to the event manager.
    pub fn event_manager_mut(&mut self) -> &mut FileSystemEventManager {
        &mut self.event_manager
    }

    /// Log a message for an item operation.
    pub fn log_item(&self, item: &dyn FolderItem, msg: &str, user: &str) {
        log::info!(
            "[{}] {} (user={}, item={})",
            self.root.display(),
            msg,
            user,
            item.name()
        );
    }
}

impl FileSystemStore for LocalFileSystemStoreImpl {
    fn user_name(&self) -> &str {
        "local"
    }

    fn item_count(&self) -> StoreResult<i32> {
        let mut count = 0i32;
        fn count_items(dir: &Path) -> io::Result<i32> {
            let mut c = 0i32;
            if dir.exists() {
                for entry in fs::read_dir(dir)?.flatten() {
                    let name = entry.file_name().to_string_lossy().to_string();
                    let path = entry.path();
                    if path.is_dir()
                        && !LocalFileSystemStoreImpl::is_hidden_dir_name(&name)
                    {
                        c += count_items(&path)?;
                    } else if path.is_file() && name.ends_with(PROPERTY_EXT) {
                        c += 1;
                    }
                }
            }
            Ok(c)
        }
        count = count_items(&self.root)?;
        Ok(count)
    }

    fn item_names(
        &self,
        folder_path: &str,
        include_hidden: bool,
    ) -> StoreResult<Vec<String>> {
        let dir = self.get_folder_path(folder_path);
        if !dir.exists() {
            return Err(GhidraError::NotFound(format!(
                "Folder not found: {}",
                folder_path
            )));
        }
        let mut names = Vec::new();
        for entry in fs::read_dir(&dir)?.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            let path = entry.path();
            if path.is_file() && name.ends_with(PROPERTY_EXT) {
                let item_name = &name[..name.len() - PROPERTY_EXT.len()];
                if include_hidden || !Self::is_hidden_item_name(item_name) {
                    names.push(item_name.to_string());
                }
            }
        }
        names.sort();
        Ok(names)
    }

    fn folder_names(&self, folder_path: &str) -> StoreResult<Vec<String>> {
        let dir = self.get_folder_path(folder_path);
        if !dir.exists() {
            return Err(GhidraError::NotFound(format!(
                "Folder not found: {}",
                folder_path
            )));
        }
        let mut names = Vec::new();
        for entry in fs::read_dir(&dir)?.flatten() {
            let path = entry.path();
            if path.is_dir() {
                let name = entry.file_name().to_string_lossy().to_string();
                if !Self::is_hidden_dir_name(&name) {
                    names.push(name);
                }
            }
        }
        names.sort();
        Ok(names)
    }

    fn get_items(&self, folder_path: &str) -> StoreResult<Vec<Arc<Mutex<dyn FolderItem>>>> {
        let names = self.item_names(folder_path, false)?;
        let mut items = Vec::new();
        for name in names {
            if let Ok(item) = self.get_item(folder_path, &name) {
                if let Some(item) = item {
                    items.push(item);
                }
            }
        }
        Ok(items)
    }

    fn get_item(
        &self,
        folder_path: &str,
        name: &str,
    ) -> StoreResult<Option<Arc<Mutex<dyn FolderItem>>>> {
        let prop_path = self.get_item_property_path(folder_path, name);
        if !prop_path.exists() {
            return Ok(None);
        }

        let dir = self.get_folder_path(folder_path);
        let pf = PropertyFile::new(&dir, name, folder_path, name);

        let file_type = pf.get_int(LocalFolderItemBase::FILE_TYPE, UNKNOWN_FILE_TYPE);

        let item: Arc<Mutex<dyn FolderItem>> = match file_type {
            DATABASE_FILE_TYPE => {
                Arc::new(Mutex::new(LocalDatabaseItem::new(pf, self.is_versioned)?))
            }
            DATAFILE_FILE_TYPE => {
                Arc::new(Mutex::new(LocalDataFileItem::new(pf)?))
            }
            LINK_FILE_TYPE => {
                Arc::new(Mutex::new(LocalTextDataItem::new(pf, self.is_versioned)?))
            }
            _ => Arc::new(Mutex::new(LocalUnknownFolderItem::new(pf)?)),
        };

        Ok(Some(item))
    }

    fn get_item_by_id(&self, _file_id: &str) -> StoreResult<Option<Arc<Mutex<dyn FolderItem>>>> {
        // Would need to scan all items; not implemented for efficiency
        Ok(None)
    }

    fn max_name_length(&self) -> usize {
        MAX_PATHNAME_LENGTH
    }

    fn create_folder(&self, parent_path: &str, folder_name: &str) -> StoreResult<()> {
        if self.read_only {
            return Err(store::read_only_error());
        }
        Self::test_valid_name(parent_path, true)?;
        Self::test_valid_name(folder_name, false)?;

        let path = self.get_folder_path(&format!(
            "{}/{}",
            parent_path.trim_end_matches('/'),
            folder_name
        ));
        if path.exists() {
            return Ok(());
        }
        fs::create_dir_all(&path)?;
        self.event_manager.folder_created(parent_path, folder_name);
        Ok(())
    }

    fn delete_folder(&self, folder_path: &str) -> StoreResult<()> {
        if self.read_only {
            return Err(store::read_only_error());
        }
        if folder_path == SEPARATOR {
            return Err(GhidraError::InvalidData(
                "Root folder may not be deleted".into(),
            ));
        }
        let dir = self.get_folder_path(folder_path);
        if !dir.exists() {
            return Err(GhidraError::NotFound(format!(
                "Folder not found: {}",
                folder_path
            )));
        }
        // Check if empty (only hidden dirs allowed)
        let has_items = fs::read_dir(&dir)?
            .flatten()
            .any(|e| {
                let n = e.file_name().to_string_lossy().to_string();
                !Self::is_hidden_dir_name(&n)
            });
        if has_items {
            return Err(store::folder_not_empty_error(folder_path));
        }
        fs::remove_dir_all(&dir)?;

        // Extract parent path and folder name
        let (parent, name) = match folder_path.rfind('/') {
            Some(idx) => (&folder_path[..idx], &folder_path[idx + 1..]),
            None => ("/", folder_path),
        };
        self.event_manager.folder_deleted(
            if parent.is_empty() { "/" } else { parent },
            name,
        );
        Ok(())
    }

    fn move_folder(
        &self,
        parent_path: &str,
        folder_name: &str,
        new_parent_path: &str,
    ) -> StoreResult<()> {
        if self.read_only {
            return Err(store::read_only_error());
        }
        let src = self.get_folder_path(&format!(
            "{}/{}",
            parent_path.trim_end_matches('/'),
            folder_name
        ));
        let dst = self.get_folder_path(&format!(
            "{}/{}",
            new_parent_path.trim_end_matches('/'),
            folder_name
        ));
        if !src.exists() {
            return Err(GhidraError::NotFound(format!(
                "Source folder not found: {}",
                src.display()
            )));
        }
        if dst.exists() {
            return Err(store::duplicate_file_error(format!(
                "Destination already exists: {}",
                dst.display()
            )));
        }
        fs::rename(&src, &dst)?;
        self.event_manager
            .folder_moved(parent_path, folder_name, new_parent_path);
        Ok(())
    }

    fn rename_folder(
        &self,
        parent_path: &str,
        folder_name: &str,
        new_folder_name: &str,
    ) -> StoreResult<()> {
        if self.read_only {
            return Err(store::read_only_error());
        }
        Self::test_valid_name(new_folder_name, false)?;

        let src = self.get_folder_path(&format!(
            "{}/{}",
            parent_path.trim_end_matches('/'),
            folder_name
        ));
        let dst = self.get_folder_path(&format!(
            "{}/{}",
            parent_path.trim_end_matches('/'),
            new_folder_name
        ));
        if !src.exists() {
            return Err(GhidraError::NotFound(format!(
                "Folder not found: {}",
                src.display()
            )));
        }
        if dst.exists() {
            return Err(store::duplicate_file_error(format!(
                "Destination already exists: {}",
                dst.display()
            )));
        }
        fs::rename(&src, &dst)?;
        self.event_manager
            .folder_renamed(parent_path, folder_name, new_folder_name);
        Ok(())
    }

    fn move_item(
        &self,
        parent_path: &str,
        name: &str,
        new_parent_path: &str,
        new_name: &str,
    ) -> StoreResult<()> {
        if self.read_only {
            return Err(store::read_only_error());
        }
        Self::test_valid_name(new_name, false)?;

        let src_dir = self.get_folder_path(parent_path);
        let dst_dir = self.get_folder_path(new_parent_path);

        let src_prop = src_dir.join(format!("{}{}", name, PROPERTY_EXT));
        let dst_prop = dst_dir.join(format!("{}{}", new_name, PROPERTY_EXT));

        if !src_prop.exists() {
            return Err(GhidraError::NotFound(format!(
                "Item not found: {}/{}",
                parent_path, name
            )));
        }
        if dst_prop.exists() {
            return Err(store::duplicate_file_error(format!(
                "Destination already exists: {}/{}",
                new_parent_path, new_name
            )));
        }

        // Ensure destination directory exists
        fs::create_dir_all(&dst_dir)?;

        // Move the property file
        fs::rename(&src_prop, &dst_prop)?;

        // Move the data directory if it exists
        let src_data_dir = src_dir.join(format!("~{}{}", name, DATA_DIR_EXTENSION));
        let dst_data_dir = dst_dir.join(format!("~{}{}", new_name, DATA_DIR_EXTENSION));
        if src_data_dir.exists() {
            fs::rename(&src_data_dir, &dst_data_dir)?;
        }

        self.event_manager
            .item_moved(parent_path, name, new_parent_path, new_name);
        Ok(())
    }

    fn folder_exists(&self, folder_path: &str) -> StoreResult<bool> {
        let dir = self.get_folder_path(folder_path);
        Ok(dir.exists() && dir.is_dir())
    }

    fn file_exists(&self, folder_path: &str, item_name: &str) -> StoreResult<bool> {
        let prop_path = self.get_item_property_path(folder_path, item_name);
        Ok(prop_path.exists())
    }

    fn is_read_only(&self) -> bool {
        self.read_only
    }

    fn is_versioned(&self) -> bool {
        self.is_versioned
    }

    fn create_data_file(
        &self,
        parent_path: &str,
        name: &str,
        data: &[u8],
        _comment: &str,
        content_type: &str,
        _monitor: &TaskMonitor,
    ) -> StoreResult<Arc<Mutex<dyn DataFileItem>>> {
        if self.read_only {
            return Err(store::read_only_error());
        }
        Self::test_valid_name(parent_path, true)?;
        Self::test_valid_name(name, false)?;

        let dir = self.get_folder_path(parent_path);
        fs::create_dir_all(&dir)?;

        let prop_path = dir.join(format!("{}{}", name, PROPERTY_EXT));
        if prop_path.exists() {
            return Err(store::duplicate_file_error(format!(
                "Item already exists: {}/{}",
                parent_path, name
            )));
        }

        let pf = PropertyFile::new(&dir, name, parent_path, name);
        let item = LocalDataFileItem::create(pf, content_type, data)?;

        self.event_manager.item_created(parent_path, name);
        Ok(Arc::new(Mutex::new(item)))
    }

    fn create_text_data_item(
        &self,
        parent_path: &str,
        name: &str,
        file_id: Option<&str>,
        content_type: &str,
        text_data: &str,
        _comment: &str,
        _user: &str,
    ) -> StoreResult<Arc<Mutex<dyn TextDataItem>>> {
        if self.read_only {
            return Err(store::read_only_error());
        }
        Self::test_valid_name(parent_path, true)?;
        Self::test_valid_name(name, false)?;

        let dir = self.get_folder_path(parent_path);
        fs::create_dir_all(&dir)?;

        let prop_path = dir.join(format!("{}{}", name, PROPERTY_EXT));
        if prop_path.exists() {
            return Err(store::duplicate_file_error(format!(
                "Item already exists: {}/{}",
                parent_path, name
            )));
        }

        let pf = PropertyFile::new(&dir, name, parent_path, name);
        let item = LocalTextDataItem::create(
            pf,
            self.is_versioned,
            content_type,
            file_id,
            text_data,
        )?;

        self.event_manager.item_created(parent_path, name);
        Ok(Arc::new(Mutex::new(item)))
    }

    fn is_supported_item_type(&self, file_type: i32) -> bool {
        matches!(file_type, DATABASE_FILE_TYPE | DATAFILE_FILE_TYPE | LINK_FILE_TYPE)
    }

    fn dispose(&mut self) -> StoreResult<()> {
        self.items.clear();
        self.event_manager.dispose();
        Ok(())
    }

    fn migration_in_progress(&self) -> bool {
        false
    }
}

impl fmt::Debug for LocalFileSystemStoreImpl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalFileSystemStoreImpl")
            .field("root", &self.root)
            .field("is_versioned", &self.is_versioned)
            .field("read_only", &self.read_only)
            .field("items_cached", &self.items.len())
            .finish()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_temp_fs(dir_name: &str) -> (PathBuf, LocalFileSystemStoreImpl) {
        let dir = std::env::temp_dir().join(format!("ghidra_test_{}", dir_name));
        let _ = fs::remove_dir_all(&dir);
        let fs = LocalFileSystemStoreImpl::new(
            dir.to_str().unwrap(),
            false,
            false,
            false,
        )
        .unwrap();
        (dir, fs)
    }

    #[test]
    fn test_create_folder() {
        let (dir, fs) = make_temp_fs("create_folder");
        fs.create_folder("/", "my_folder").unwrap();
        assert!(dir.join("my_folder").exists());
        assert!(fs.folder_exists("/my_folder").unwrap());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_create_nested_folders() {
        let (dir, fs) = make_temp_fs("nested_folders");
        fs.create_folder("/", "a").unwrap();
        fs.create_folder("/a", "b").unwrap();
        fs.create_folder("/a/b", "c").unwrap();
        assert!(dir.join("a/b/c").exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_folder_names() {
        let (dir, fs) = make_temp_fs("folder_names");
        fs.create_folder("/", "alpha").unwrap();
        fs.create_folder("/", "beta").unwrap();
        fs.create_folder("/", "gamma").unwrap();
        let names = fs.folder_names("/").unwrap();
        assert_eq!(names, vec!["alpha", "beta", "gamma"]);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_create_data_file() {
        let (dir, fs) = make_temp_fs("data_file");
        fs.create_folder("/", "test").unwrap();
        let monitor = TaskMonitor::new();
        let item = fs
            .create_data_file("/test", "myfile.bin", b"hello world", "", "binary", &monitor)
            .unwrap();
        let item = item.lock().unwrap();
        assert_eq!(item.name(), "myfile.bin");
        assert_eq!(item.length().unwrap(), 11);
        assert_eq!(item.content_type(), "binary");
        drop(item);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_create_text_data_item() {
        let (dir, fs) = make_temp_fs("text_data");
        let item = fs
            .create_text_data_item(
                "/",
                "link.txt",
                None,
                "text/plain",
                "some text content",
                "comment",
                "testuser",
            )
            .unwrap();
        let item = item.lock().unwrap();
        assert_eq!(item.name(), "link.txt");
        assert_eq!(item.text_data(), "some text content");
        drop(item);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_item_names() {
        let (dir, fs) = make_temp_fs("item_names");
        let monitor = TaskMonitor::new();
        fs.create_data_file("/", "file_a.txt", b"a", "", "text", &monitor)
            .unwrap();
        fs.create_data_file("/", "file_b.txt", b"b", "", "text", &monitor)
            .unwrap();
        fs.create_data_file("/", "file_c.txt", b"c", "", "text", &monitor)
            .unwrap();
        let names = fs.item_names("/", false).unwrap();
        assert_eq!(names, vec!["file_a.txt", "file_b.txt", "file_c.txt"]);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_get_item() {
        let (dir, fs) = make_temp_fs("get_item");
        let monitor = TaskMonitor::new();
        fs.create_data_file("/", "test_item", b"data", "", "application/octet-stream", &monitor)
            .unwrap();
        let item = fs.get_item("/", "test_item").unwrap();
        assert!(item.is_some());
        let item = item.unwrap();
        let item = item.lock().unwrap();
        assert_eq!(item.name(), "test_item");
        drop(item);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_read_only_fs() {
        let dir = std::env::temp_dir().join("ghidra_test_readonly");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let fs = LocalFileSystemStoreImpl::new(
            dir.to_str().unwrap(),
            false,
            true, // read-only
            false,
        )
        .unwrap();

        assert!(fs.create_folder("/", "test").is_err());
        assert!(fs.is_read_only());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_delete_folder() {
        let (dir, fs) = make_temp_fs("delete_folder");
        fs.create_folder("/", "to_delete").unwrap();
        assert!(fs.folder_exists("/to_delete").unwrap());
        fs.delete_folder("/to_delete").unwrap();
        assert!(!fs.folder_exists("/to_delete").unwrap());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_move_item() {
        let (dir, fs) = make_temp_fs("move_item");
        fs.create_folder("/", "src").unwrap();
        fs.create_folder("/", "dst").unwrap();
        let monitor = TaskMonitor::new();
        fs.create_data_file("/src", "moveme.txt", b"data", "", "text", &monitor)
            .unwrap();
        fs.move_item("/src", "moveme.txt", "/dst", "moveme.txt")
            .unwrap();
        assert!(!fs.file_exists("/src", "moveme.txt").unwrap());
        assert!(fs.file_exists("/dst", "moveme.txt").unwrap());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_rename_folder() {
        let (dir, fs) = make_temp_fs("rename_folder");
        fs.create_folder("/", "old_name").unwrap();
        fs.rename_folder("/", "old_name", "new_name").unwrap();
        assert!(!fs.folder_exists("/old_name").unwrap());
        assert!(fs.folder_exists("/new_name").unwrap());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_duplicate_item_error() {
        let (dir, fs) = make_temp_fs("dup_error");
        let monitor = TaskMonitor::new();
        fs.create_data_file("/", "dup", b"data", "", "text", &monitor)
            .unwrap();
        let result = fs.create_data_file("/", "dup", b"data", "", "text", &monitor);
        assert!(result.is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_versioned_fs() {
        let dir = std::env::temp_dir().join("ghidra_test_versioned");
        let _ = fs::remove_dir_all(&dir);
        let fs = LocalFileSystemStoreImpl::new(
            dir.to_str().unwrap(),
            true, // versioned
            false,
            false,
        )
        .unwrap();
        assert!(fs.is_versioned());
        let _ = fs::remove_dir_all(&dir);
    }

    // CheckoutManager tests
    #[test]
    fn test_checkout_manager_basic() {
        let mut mgr = CheckoutManager::new();
        let id = mgr.create_checkout(
            CheckoutType::Normal,
            "alice",
            1,
            1000,
            Some("host::/proj".to_string()),
        );
        assert_eq!(id, 1);
        assert_eq!(mgr.checkout_count(), 1);

        let status = mgr.get_checkout(id).unwrap();
        assert_eq!(status.user(), "alice");
        assert_eq!(status.checkout_type(), CheckoutType::Normal);

        mgr.remove_checkout(id);
        assert_eq!(mgr.checkout_count(), 0);
        assert!(mgr.get_checkout(id).is_none());
    }

    #[test]
    fn test_checkout_manager_exclusive() {
        let mut mgr = CheckoutManager::new();
        let id = mgr.create_checkout(
            CheckoutType::Exclusive,
            "bob",
            1,
            0,
            None,
        );
        assert!(mgr.has_exclusive_checkout());
        assert!(mgr.is_exclusive(id));
        assert!(mgr.user_has_exclusive_checkout("bob"));
        assert!(!mgr.user_has_exclusive_checkout("alice"));
    }

    // HistoryManager tests
    #[test]
    fn test_history_manager() {
        let mut mgr = HistoryManager::new();
        assert_eq!(mgr.version_count(), 0);

        mgr.add_version(Version::new(1, 100, "alice", "v1"));
        mgr.add_version(Version::new(2, 200, "alice", "v2"));
        mgr.add_version(Version::new(3, 300, "bob", "v3"));

        assert_eq!(mgr.version_count(), 3);
        assert_eq!(mgr.latest_version(), 3);
        assert_eq!(mgr.minimum_version(), 1);

        let v2 = mgr.get_version(2).unwrap();
        assert_eq!(v2.user(), "alice");
        assert_eq!(v2.comment(), "v2");

        mgr.delete_version(2);
        assert_eq!(mgr.version_count(), 2);
        assert!(mgr.get_version(2).is_none());
    }

    // LockFile tests
    #[test]
    fn test_lock_file_basic() {
        let dir = std::env::temp_dir().join("ghidra_test_lock");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let mut lock = LockFile::new(&dir, "test_item");
        assert!(!lock.is_locked());

        let acquired = lock.try_lock().unwrap();
        assert!(acquired);
        assert!(lock.is_locked());

        // Should fail since lock is held
        let mut lock2 = LockFile::for_testing(&dir, "test_item", 60, 100);
        let acquired2 = lock2.try_lock().unwrap();
        assert!(!acquired2);

        lock.unlock();
        assert!(!lock.is_locked());

        // Now should succeed
        let acquired3 = lock2.try_lock().unwrap();
        assert!(acquired3);
        lock2.unlock();

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_lock_file_owner_info() {
        let dir = std::env::temp_dir().join("ghidra_test_lock_owner");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let mut lock = LockFile::new(&dir, "test_item");
        lock.try_lock().unwrap();

        let owner = lock.get_lock_owner();
        assert!(owner.is_some());
        assert!(!owner.unwrap().is_empty());

        lock.unlock();
        let _ = fs::remove_dir_all(&dir);
    }

    // PropertyFile tests
    #[test]
    fn test_property_file_move() {
        let dir = std::env::temp_dir().join("ghidra_test_prop_move");
        let _ = fs::remove_dir_all(&dir);
        let src_dir = dir.join("src");
        let dst_dir = dir.join("dst");
        fs::create_dir_all(&src_dir).unwrap();
        fs::create_dir_all(&dst_dir).unwrap();

        let mut pf = PropertyFile::new(&src_dir, "item", "/old", "item_name");
        pf.put_string("key", "value");
        pf.write_state().unwrap();

        assert!(pf.exists());
        pf.move_to(&dst_dir, "item", "/new", "item_name")
            .unwrap();

        assert!(!src_dir.join("item.prp").exists());
        assert!(dst_dir.join("item.prp").exists());
        assert_eq!(pf.name(), "item_name");
        assert_eq!(pf.parent_path(), "/new");

        let _ = fs::remove_dir_all(&dir);
    }
}
