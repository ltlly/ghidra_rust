//! Remote filesystem store implementations.
//!
//! Provides [`RemoteFileSystemStore`], [`RemoteFolderItemBase`], and concrete
//! item types for accessing versioned items stored on a remote repository.
//!
//! These are stub implementations that define the full API surface but delegate
//! actual network operations to a `RepositoryAdapter` trait.
//!
//! Corresponds to `ghidra.framework.store.remote.*`.

use std::fmt;
use std::io::{Read, Write};
use std::path::Path;

use crate::error::GhidraError;
use crate::generic::task::TaskMonitor;
use crate::filesystem::store::{
    CheckoutType, DatabaseItem, FolderItem, ItemCheckoutStatus,
    TextDataItem, UnknownFolderItem, Version, UNKNOWN_FILE_TYPE,
};
use crate::filesystem::store::listener::FileSystemEventManager;
use super::StoreResult;

// ============================================================================
// RepositoryAdapter trait
// ============================================================================

/// Trait abstracting a remote repository connection.
///
/// This replaces the Java `RepositoryAdapter` class. Implementations will
/// handle the actual network calls to a Ghidra server.
pub trait RepositoryAdapter: Send + Sync {
    /// Get the user name.
    fn user_name(&self) -> &str;

    /// List items in a folder.
    fn item_list(&self, folder_path: &str) -> StoreResult<Vec<RepositoryItemInfo>>;

    /// Get a specific item by path and name.
    fn get_item(&self, folder_path: &str, name: &str) -> StoreResult<Option<RepositoryItemInfo>>;

    /// Get a specific item by file ID.
    fn get_item_by_id(&self, file_id: &str) -> StoreResult<Option<RepositoryItemInfo>>;

    /// List subfolders.
    fn subfolder_list(&self, folder_path: &str) -> StoreResult<Vec<String>>;

    /// Check if a folder exists.
    fn folder_exists(&self, folder_path: &str) -> StoreResult<bool>;

    /// Check if a file exists.
    fn file_exists(&self, folder_path: &str, item_name: &str) -> StoreResult<bool>;

    /// Checkout an item.
    fn checkout(
        &self,
        parent_path: &str,
        item_name: &str,
        checkout_type: CheckoutType,
        project_path: &str,
    ) -> StoreResult<ItemCheckoutStatus>;

    /// Terminate a checkout.
    fn terminate_checkout(
        &self,
        parent_path: &str,
        item_name: &str,
        checkout_id: i64,
        notify: bool,
    ) -> StoreResult<()>;

    /// Get checkout status.
    fn get_checkout(
        &self,
        parent_path: &str,
        item_name: &str,
        checkout_id: i64,
    ) -> StoreResult<Option<ItemCheckoutStatus>>;

    /// Get all checkouts for an item.
    fn get_checkouts(
        &self,
        parent_path: &str,
        item_name: &str,
    ) -> StoreResult<Vec<ItemCheckoutStatus>>;

    /// Create a text data file.
    fn create_text_data_file(
        &self,
        parent_path: &str,
        name: &str,
        file_id: Option<&str>,
        content_type: &str,
        text_data: &str,
        comment: &str,
    ) -> StoreResult<()>;

    /// Move a folder.
    fn move_folder(
        &self,
        parent_path: &str,
        new_parent_path: &str,
        folder_name: &str,
        new_folder_name: &str,
    ) -> StoreResult<()>;

    /// Move an item.
    fn move_item(
        &self,
        parent_path: &str,
        new_parent_path: &str,
        name: &str,
        new_name: &str,
    ) -> StoreResult<()>;
}

/// Information about a repository item (replaces Java's `RepositoryItem`).
#[derive(Debug, Clone)]
pub struct RepositoryItemInfo {
    /// Item name.
    pub name: String,
    /// Parent path.
    pub parent_path: String,
    /// Content type.
    pub content_type: String,
    /// File ID.
    pub file_id: Option<String>,
    /// Item type (DATABASE, TEXT_DATA_FILE, etc.).
    pub item_type: i32,
    /// Current version.
    pub version: i32,
    /// Version time.
    pub version_time: i64,
    /// Text data (for text items).
    pub text_data: Option<String>,
}

impl RepositoryItemInfo {
    /// Item type constants (matching Java's RepositoryItem).
    pub const DATABASE: i32 = 0;
    pub const TEXT_DATA_FILE: i32 = 2;
    pub const UNKNOWN: i32 = -1;
}

// ============================================================================
// RemoteFolderItemBase
// ============================================================================

/// Base fields for all remote folder items.
pub struct RemoteFolderItemBase {
    pub parent_path: String,
    pub item_name: String,
    pub content_type: String,
    pub file_id: Option<String>,
    pub version: i32,
    pub version_time: i64,
    pub text_data: Option<String>,
}

impl RemoteFolderItemBase {
    /// Create from a RepositoryItemInfo.
    pub fn from_info(info: &RepositoryItemInfo) -> Self {
        let content_type = if info.content_type.is_empty() {
            "Unknown-File".to_string()
        } else {
            info.content_type.clone()
        };

        Self {
            parent_path: info.parent_path.clone(),
            item_name: info.name.clone(),
            content_type,
            file_id: info.file_id.clone(),
            version: info.version,
            version_time: info.version_time,
            text_data: info.text_data.clone(),
        }
    }
}

// ============================================================================
// RemoteDatabaseItem
// ============================================================================

/// A remote database item.
///
/// Corresponds to `ghidra.framework.store.remote.RemoteDatabaseItem`.
pub struct RemoteDatabaseItem {
    base: RemoteFolderItemBase,
}

impl RemoteDatabaseItem {
    /// Create a new RemoteDatabaseItem.
    pub fn new(info: &RepositoryItemInfo) -> Self {
        Self {
            base: RemoteFolderItemBase::from_info(info),
        }
    }

    /// The version time.
    pub fn version_time(&self) -> i64 {
        self.base.version_time
    }
}

impl FolderItem for RemoteDatabaseItem {
    fn name(&self) -> &str {
        &self.base.item_name
    }

    fn file_id(&self) -> Option<&str> {
        self.base.file_id.as_deref()
    }

    fn reset_file_id(&mut self) -> StoreResult<String> {
        Err(GhidraError::NotSupported(
            "resetFileID not applicable to versioned item".into(),
        ))
    }

    fn length(&self) -> StoreResult<i64> {
        Ok(-1) // Unknown for remote items without fetching
    }

    fn content_type(&self) -> &str {
        &self.base.content_type
    }

    fn current_version(&self) -> i32 {
        self.base.version
    }

    fn minimum_version(&self) -> StoreResult<i32> {
        Err(GhidraError::NotSupported(
            "minimumVersion not available for remote items".into(),
        ))
    }

    fn is_checked_out(&self) -> bool {
        false
    }

    fn is_checked_out_exclusive(&self) -> bool {
        false
    }

    fn is_versioned(&self) -> StoreResult<bool> {
        Ok(true)
    }

    fn checkout_id(&self) -> StoreResult<i64> {
        Err(GhidraError::NotSupported(
            "checkoutId not applicable to versioned item".into(),
        ))
    }

    fn checkout_version(&self) -> StoreResult<i32> {
        Err(GhidraError::NotSupported(
            "checkoutVersion not applicable to versioned item".into(),
        ))
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
            "setCheckout not applicable to versioned item".into(),
        ))
    }

    fn clear_checkout(&mut self) -> StoreResult<()> {
        Err(GhidraError::NotSupported(
            "clearCheckout not applicable to versioned item".into(),
        ))
    }

    fn delete(&mut self, _version: i32, _user: &str) -> StoreResult<()> {
        Err(GhidraError::NotSupported(
            "delete not implemented for remote items".into(),
        ))
    }

    fn get_versions(&self) -> StoreResult<Option<Vec<Version>>> {
        Err(GhidraError::NotSupported(
            "getVersions requires repository connection".into(),
        ))
    }

    fn checkout(
        &self,
        _checkout_type: CheckoutType,
        _user: &str,
        _project_path: &str,
    ) -> StoreResult<Option<ItemCheckoutStatus>> {
        Err(GhidraError::NotSupported(
            "checkout requires repository connection".into(),
        ))
    }

    fn terminate_checkout(&self, _checkout_id: i64, _notify: bool) -> StoreResult<()> {
        Err(GhidraError::NotSupported(
            "terminateCheckout requires repository connection".into(),
        ))
    }

    fn get_checkout(&self, _checkout_id: i64) -> StoreResult<Option<ItemCheckoutStatus>> {
        Err(GhidraError::NotSupported(
            "getCheckout requires repository connection".into(),
        ))
    }

    fn get_checkouts(&self) -> StoreResult<Vec<ItemCheckoutStatus>> {
        Err(GhidraError::NotSupported(
            "getCheckouts requires repository connection".into(),
        ))
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
            "updateCheckoutVersion requires repository connection".into(),
        ))
    }

    fn output(
        &self,
        _output_file: &Path,
        _version: i32,
        _monitor: &TaskMonitor,
    ) -> StoreResult<()> {
        Err(GhidraError::NotSupported(
            "output requires repository connection".into(),
        ))
    }

    fn refresh(&mut self) -> StoreResult<bool> {
        Ok(true) // Assume still exists
    }

    fn can_recover(&self) -> bool {
        false
    }
}

impl DatabaseItem for RemoteDatabaseItem {
    fn open(&self) -> StoreResult<Box<dyn Read + Send>> {
        Err(GhidraError::NotSupported(
            "Database open requires repository connection".into(),
        ))
    }

    fn open_for_update(
        &mut self,
        _checkout_id: i64,
        _user: &str,
    ) -> StoreResult<Box<dyn super::ReadWrite>> {
        Err(GhidraError::NotSupported(
            "Database open_for_update requires repository connection".into(),
        ))
    }

    fn open_version(&self, _version: i32) -> StoreResult<Box<dyn Read + Send>> {
        Err(GhidraError::NotSupported(
            "Database open_version requires repository connection".into(),
        ))
    }

    fn copy_to(&self, _dest: &mut dyn Write, _monitor: &TaskMonitor) -> StoreResult<()> {
        Err(GhidraError::NotSupported(
            "Database copy_to requires repository connection".into(),
        ))
    }

    fn delete_database(&mut self, _user: &str) -> StoreResult<()> {
        Err(GhidraError::NotSupported(
            "deleteDatabase requires repository connection".into(),
        ))
    }

    fn set_content_type(&mut self, _content_type: &str) -> StoreResult<()> {
        Err(GhidraError::NotSupported(
            "setContentType requires repository connection".into(),
        ))
    }
}

impl fmt::Debug for RemoteDatabaseItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RemoteDatabaseItem")
            .field("name", &self.base.item_name)
            .field("version", &self.base.version)
            .finish()
    }
}

// ============================================================================
// RemoteTextDataItem
// ============================================================================

/// A remote text data item.
///
/// Corresponds to `ghidra.framework.store.remote.RemoteTextDataItem`.
pub struct RemoteTextDataItem {
    base: RemoteFolderItemBase,
}

impl RemoteTextDataItem {
    /// Create a new RemoteTextDataItem.
    pub fn new(info: &RepositoryItemInfo) -> Self {
        Self {
            base: RemoteFolderItemBase::from_info(info),
        }
    }
}

impl FolderItem for RemoteTextDataItem {
    fn name(&self) -> &str {
        &self.base.item_name
    }

    fn file_id(&self) -> Option<&str> {
        self.base.file_id.as_deref()
    }

    fn reset_file_id(&mut self) -> StoreResult<String> {
        Err(GhidraError::NotSupported(
            "resetFileID not applicable to versioned item".into(),
        ))
    }

    fn length(&self) -> StoreResult<i64> {
        Ok(self
            .base
            .text_data
            .as_ref()
            .map(|s| s.len() as i64)
            .unwrap_or(-1))
    }

    fn content_type(&self) -> &str {
        &self.base.content_type
    }

    fn current_version(&self) -> i32 {
        self.base.version
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
        Ok(true)
    }

    fn checkout_id(&self) -> StoreResult<i64> {
        Err(GhidraError::NotSupported(
            "checkoutId not applicable to versioned item".into(),
        ))
    }

    fn checkout_version(&self) -> StoreResult<i32> {
        Err(GhidraError::NotSupported(
            "checkoutVersion not applicable to versioned item".into(),
        ))
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
            "setCheckout not applicable to versioned item".into(),
        ))
    }

    fn clear_checkout(&mut self) -> StoreResult<()> {
        Err(GhidraError::NotSupported(
            "clearCheckout not applicable to versioned item".into(),
        ))
    }

    fn delete(&mut self, _version: i32, _user: &str) -> StoreResult<()> {
        Err(GhidraError::NotSupported(
            "delete not implemented for remote items".into(),
        ))
    }

    fn get_versions(&self) -> StoreResult<Option<Vec<Version>>> {
        Ok(Some(vec![Version::new(
            self.base.version,
            self.base.version_time,
            "",
            "",
        )]))
    }

    fn checkout(
        &self,
        _checkout_type: CheckoutType,
        _user: &str,
        _project_path: &str,
    ) -> StoreResult<Option<ItemCheckoutStatus>> {
        Err(GhidraError::NotSupported(
            "checkout requires repository connection".into(),
        ))
    }

    fn terminate_checkout(&self, _checkout_id: i64, _notify: bool) -> StoreResult<()> {
        Err(GhidraError::NotSupported(
            "terminateCheckout requires repository connection".into(),
        ))
    }

    fn get_checkout(&self, _checkout_id: i64) -> StoreResult<Option<ItemCheckoutStatus>> {
        Err(GhidraError::NotSupported(
            "getCheckout requires repository connection".into(),
        ))
    }

    fn get_checkouts(&self) -> StoreResult<Vec<ItemCheckoutStatus>> {
        Err(GhidraError::NotSupported(
            "getCheckouts requires repository connection".into(),
        ))
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
            "updateCheckoutVersion requires repository connection".into(),
        ))
    }

    fn output(
        &self,
        _output_file: &Path,
        _version: i32,
        _monitor: &TaskMonitor,
    ) -> StoreResult<()> {
        Err(GhidraError::NotSupported(
            "output requires repository connection".into(),
        ))
    }

    fn refresh(&mut self) -> StoreResult<bool> {
        Ok(true)
    }

    fn can_recover(&self) -> bool {
        false
    }
}

impl TextDataItem for RemoteTextDataItem {
    fn text_data(&self) -> &str {
        self.base.text_data.as_deref().unwrap_or("")
    }
}

impl fmt::Debug for RemoteTextDataItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RemoteTextDataItem")
            .field("name", &self.base.item_name)
            .field("version", &self.base.version)
            .finish()
    }
}

// ============================================================================
// RemoteUnknownFolderItem
// ============================================================================

/// A remote item with unknown or unsupported type.
///
/// Corresponds to `ghidra.framework.store.remote.RemoteUnknownFolderItem`.
pub struct RemoteUnknownFolderItem {
    base: RemoteFolderItemBase,
    file_type: i32,
}

impl RemoteUnknownFolderItem {
    /// Create a new RemoteUnknownFolderItem.
    pub fn new(info: &RepositoryItemInfo) -> Self {
        Self {
            base: RemoteFolderItemBase::from_info(info),
            file_type: UNKNOWN_FILE_TYPE,
        }
    }
}

impl FolderItem for RemoteUnknownFolderItem {
    fn name(&self) -> &str {
        &self.base.item_name
    }

    fn file_id(&self) -> Option<&str> {
        self.base.file_id.as_deref()
    }

    fn reset_file_id(&mut self) -> StoreResult<String> {
        Err(GhidraError::NotSupported(
            "Unknown item does not support operations".into(),
        ))
    }

    fn length(&self) -> StoreResult<i64> {
        Ok(-1)
    }

    fn content_type(&self) -> &str {
        "Unknown-File"
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
        Ok(true)
    }

    fn checkout_id(&self) -> StoreResult<i64> {
        Err(GhidraError::NotSupported("Unknown item".into()))
    }

    fn checkout_version(&self) -> StoreResult<i32> {
        Err(GhidraError::NotSupported("Unknown item".into()))
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
        Err(GhidraError::NotSupported("Unknown item".into()))
    }

    fn clear_checkout(&mut self) -> StoreResult<()> {
        Err(GhidraError::NotSupported("Unknown item".into()))
    }

    fn delete(&mut self, _version: i32, _user: &str) -> StoreResult<()> {
        Err(GhidraError::NotSupported("Unknown item".into()))
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
        Err(GhidraError::NotSupported("Unknown item".into()))
    }

    fn terminate_checkout(&self, _checkout_id: i64, _notify: bool) -> StoreResult<()> {
        Err(GhidraError::NotSupported("Unknown item".into()))
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
        Err(GhidraError::NotSupported("Unknown item".into()))
    }

    fn output(
        &self,
        _output_file: &Path,
        _version: i32,
        _monitor: &TaskMonitor,
    ) -> StoreResult<()> {
        Err(GhidraError::NotSupported("Unknown item".into()))
    }

    fn refresh(&mut self) -> StoreResult<bool> {
        Ok(true)
    }

    fn can_recover(&self) -> bool {
        false
    }
}

impl UnknownFolderItem for RemoteUnknownFolderItem {
    fn file_type(&self) -> i32 {
        self.file_type
    }
}

impl fmt::Debug for RemoteUnknownFolderItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RemoteUnknownFolderItem")
            .field("name", &self.base.item_name)
            .finish()
    }
}

// ============================================================================
// RemoteFileSystemStore
// ============================================================================

/// Remote filesystem backed by a repository adapter.
///
/// Corresponds to `ghidra.framework.store.remote.RemoteFileSystem`.
pub struct RemoteFileSystemStore {
    /// Event manager.
    event_manager: FileSystemEventManager,
}

impl RemoteFileSystemStore {
    /// Create a new RemoteFileSystemStore.
    pub fn new() -> Self {
        Self {
            event_manager: FileSystemEventManager::new(true),
        }
    }

    /// Get the event manager.
    pub fn event_manager(&self) -> &FileSystemEventManager {
        &self.event_manager
    }

    /// Get a mutable reference to the event manager.
    pub fn event_manager_mut(&mut self) -> &mut FileSystemEventManager {
        &mut self.event_manager
    }

    /// Create a FolderItem from a RepositoryItemInfo.
    pub fn create_item_from_info(info: &RepositoryItemInfo) -> Box<dyn FolderItem> {
        match info.item_type {
            RepositoryItemInfo::DATABASE => Box::new(RemoteDatabaseItem::new(info)),
            RepositoryItemInfo::TEXT_DATA_FILE => Box::new(RemoteTextDataItem::new(info)),
            _ => Box::new(RemoteUnknownFolderItem::new(info)),
        }
    }
}

impl Default for RemoteFileSystemStore {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for RemoteFileSystemStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RemoteFileSystemStore").finish()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_remote_database_item_from_info() {
        let info = RepositoryItemInfo {
            name: "my_db".to_string(),
            parent_path: "/projects".to_string(),
            content_type: "Program".to_string(),
            file_id: Some("abc123".to_string()),
            item_type: RepositoryItemInfo::DATABASE,
            version: 5,
            version_time: 1234567890,
            text_data: None,
        };

        let item = RemoteDatabaseItem::new(&info);
        assert_eq!(item.name(), "my_db");
        assert_eq!(item.content_type(), "Program");
        assert_eq!(item.current_version(), 5);
        assert!(item.is_versioned().unwrap());
        assert_eq!(item.file_id(), Some("abc123"));
    }

    #[test]
    fn test_remote_text_data_item() {
        let info = RepositoryItemInfo {
            name: "link".to_string(),
            parent_path: "/".to_string(),
            content_type: "Link".to_string(),
            file_id: None,
            item_type: RepositoryItemInfo::TEXT_DATA_FILE,
            version: 1,
            version_time: 0,
            text_data: Some("some text data".to_string()),
        };

        let item = RemoteTextDataItem::new(&info);
        assert_eq!(item.text_data(), "some text data");
        assert_eq!(item.length().unwrap(), 14);
    }

    #[test]
    fn test_remote_unknown_item() {
        let info = RepositoryItemInfo {
            name: "mystery".to_string(),
            parent_path: "/".to_string(),
            content_type: "".to_string(),
            file_id: None,
            item_type: 999,
            version: -1,
            version_time: 0,
            text_data: None,
        };

        let item = RemoteUnknownFolderItem::new(&info);
        assert_eq!(item.content_type(), "Unknown-File");
        assert_eq!(item.file_type(), UNKNOWN_FILE_TYPE);
    }

    #[test]
    fn test_create_item_from_info() {
        let db_info = RepositoryItemInfo {
            name: "db".to_string(),
            parent_path: "/".to_string(),
            content_type: "Program".to_string(),
            file_id: None,
            item_type: RepositoryItemInfo::DATABASE,
            version: 1,
            version_time: 0,
            text_data: None,
        };
        let item = RemoteFileSystemStore::create_item_from_info(&db_info);
        assert!(item.is_versioned().unwrap());

        let text_info = RepositoryItemInfo {
            name: "txt".to_string(),
            parent_path: "/".to_string(),
            content_type: "Text".to_string(),
            file_id: None,
            item_type: RepositoryItemInfo::TEXT_DATA_FILE,
            version: 1,
            version_time: 0,
            text_data: Some("hello".to_string()),
        };
        let item = RemoteFileSystemStore::create_item_from_info(&text_info);
        assert!(item.is_versioned().unwrap());
    }
}
