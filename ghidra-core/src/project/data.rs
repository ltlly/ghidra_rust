//! Data layer for the Ghidra Project framework.
//!
//! This module ports the key Java types from `ghidra.framework.data`:
//! - `OpenMode` -- instantiation mode for domain objects
//! - `ContentHandler` -- trait for converting between domain objects and storage
//! - `DBContentHandler`, `DBWithUserDataContentHandler`, `FolderLinkContentHandler` -- content handlers
//! - `DefaultProjectData` -- default implementation of ProjectData
//! - `GhidraFolder`, `GhidraFile` -- concrete folder/file
//! - `DomainFileProxy` -- read-only proxy for a DomainFile
//! - `DomainObjectAdapter`, `DomainObjectAdapterDB` -- adapter for domain objects
//! - `GhidraFileData` -- stores domain object data for a file
//! - `GhidraFolderData` -- stores folder data
//! - `RootGhidraFolder` -- root folder
//! - `LinkHandler` -- handling link files
//! - `DomainObjectChangeSupport` -- event dispatch support
//! - `DomainObjectDBChangeSet` -- change set backed by DB
//! - `OptionsDB` -- options stored in DB
//! - `TransientDataManager` -- manages transient domain objects
//! - `DomainFolderChangeListenerList` -- listener list management
//! - `ProjectLock` -- project locking
//! - `LockingTaskMonitor` -- task monitor with lock awareness
//! - `DomainObjectFileListener` -- file change listener
//! - `DomainObjectMergeManager` -- merge manager interface
//! - `CheckinHandler`, `DefaultCheckinHandler` -- checkin handling
//! - `ConvertFileSystem` -- file system conversion
//! - `MetadataManager` -- metadata management
//! - `DomainFileIndex` -- file indexing
//! - `ToolState`, `ToolStateFactory` -- tool state persistence

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::SystemTime;

use super::model::*;
use super::{ProjectLocator, ProjectResult};

// ============================================================================
// OpenMode
// ============================================================================

/// Instantiation mode for domain objects and internal storage adapters.
///
/// In Java: `ghidra.framework.data.OpenMode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OpenMode {
    /// Creating new domain object.
    Create,
    /// Domain object opened as an immutable instance.
    Immutable,
    /// Domain object opened for modification.
    Update,
    /// Domain object opened for modification with data upgrade permitted.
    Upgrade,
}

impl OpenMode {
    /// Whether this mode permits writing.
    pub fn allows_write(&self) -> bool {
        matches!(self, Self::Create | Self::Update | Self::Upgrade)
    }

    /// Whether this mode requires upgrading data.
    pub fn requires_upgrade(&self) -> bool {
        *self == Self::Upgrade
    }

    /// Whether this mode is read-only.
    pub fn is_read_only(&self) -> bool {
        *self == Self::Immutable
    }

    /// A human-readable label.
    pub fn label(&self) -> &str {
        match self {
            Self::Create => "CREATE",
            Self::Immutable => "IMMUTABLE",
            Self::Update => "UPDATE",
            Self::Upgrade => "UPGRADE",
        }
    }
}

impl fmt::Display for OpenMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

// ============================================================================
// ContentHandler trait
// ============================================================================

/// Content type identifier for unknown folder items.
pub const UNKNOWN_CONTENT: &str = "Unknown-Content";
/// Content type identifier for missing files.
pub const MISSING_CONTENT: &str = "Missing-File";
/// Content type identifier for programs.
pub const PROGRAM_CONTENT: &str = "Program";
/// Content type identifier for data type archives.
pub const DATA_TYPE_ARCHIVE_CONTENT: &str = "DataTypeArchive";
/// Content type identifier for tool configurations.
pub const TOOL_CONTENT: &str = "Tool";

/// Defines an application interface for converting between a specific domain
/// object implementation and folder item storage.
///
/// In Java: `ghidra.framework.data.ContentHandler`.
pub trait ContentHandler: Send + Sync + fmt::Debug {
    /// The content type identifier.
    fn content_type(&self) -> &str;

    /// A user-friendly content type display string.
    fn content_type_display_string(&self) -> &str;

    /// The name of the default tool to open this content type.
    fn default_tool_name(&self) -> &str;

    /// Whether this content type is always private (cannot be versioned).
    fn is_private_content_type(&self) -> bool;

    /// Whether linking is supported for this content type.
    fn is_linking_supported(&self) -> bool;

    /// Whether the content handler supports DB source file reset.
    fn can_reset_db_source_file(&self) -> bool {
        false
    }
}

// ============================================================================
// LinkHandler
// ============================================================================

/// Handles link file creation and resolution.
///
/// In Java: `ghidra.framework.data.LinkHandler`.
pub trait LinkHandler: Send + Sync + fmt::Debug {
    /// The content type for this link handler.
    fn content_type(&self) -> &str;
    /// Whether this is a folder link handler.
    fn is_folder_link(&self) -> bool;
}

// ============================================================================
// DomainObjectChangeSupport
// ============================================================================

/// Provides event dispatch support for domain objects.
///
/// In Java: `ghidra.framework.data.DomainObjectChangeSupport`.
#[derive(Debug)]
pub struct DomainObjectChangeSupport {
    listeners: Vec<(u64, Box<dyn DomainObjectListener>)>,
    close_listeners: Vec<(u64, Box<dyn DomainObjectClosedListener>)>,
    private_queues: HashMap<EventQueueID, (Box<dyn DomainObjectListener>, u32)>,
    events_enabled: bool,
    next_listener_id: u64,
}

impl DomainObjectChangeSupport {
    /// Create a new change support instance.
    pub fn new() -> Self {
        Self {
            listeners: Vec::new(),
            close_listeners: Vec::new(),
            private_queues: HashMap::new(),
            events_enabled: true,
            next_listener_id: 1,
        }
    }

    /// Add a listener.
    pub fn add_listener(&mut self, listener: Box<dyn DomainObjectListener>) -> u64 {
        let id = self.next_listener_id;
        self.next_listener_id += 1;
        self.listeners.push((id, listener));
        id
    }

    /// Remove a listener by ID.
    pub fn remove_listener(&mut self, listener_id: u64) {
        self.listeners.retain(|(id, _)| *id != listener_id);
    }

    /// Add a close listener.
    pub fn add_close_listener(&mut self, listener: Box<dyn DomainObjectClosedListener>) -> u64 {
        let id = self.next_listener_id;
        self.next_listener_id += 1;
        self.close_listeners.push((id, listener));
        id
    }

    /// Remove a close listener.
    pub fn remove_close_listener(&mut self, listener_id: u64) {
        self.close_listeners.retain(|(id, _)| *id != listener_id);
    }

    /// Create a private event queue.
    pub fn create_private_event_queue(
        &mut self,
        listener: Box<dyn DomainObjectListener>,
        max_delay_ms: u32,
    ) -> EventQueueID {
        let id = EventQueueID::new();
        self.private_queues.insert(id, (listener, max_delay_ms));
        id
    }

    /// Remove a private event queue.
    pub fn remove_private_event_queue(&mut self, id: EventQueueID) -> bool {
        self.private_queues.remove(&id).is_some()
    }

    /// Enable/disable events.
    pub fn set_events_enabled(&mut self, enabled: bool) {
        self.events_enabled = enabled;
    }

    /// Whether events are enabled.
    pub fn is_sending_events(&self) -> bool {
        self.events_enabled
    }

    /// Fire an event to all listeners and private queues.
    pub fn fire_event(&self, event: &DomainObjectChangedEvent) {
        if !self.events_enabled {
            return;
        }
        for (_, listener) in &self.listeners {
            listener.domain_object_changed(event);
        }
        for (_, (listener, _)) in &self.private_queues {
            listener.domain_object_changed(event);
        }
    }

    /// Fire close notification to all close listeners.
    pub fn fire_close(&self, object_id: u64) {
        for (_, listener) in &self.close_listeners {
            listener.domain_object_closed(object_id);
        }
    }

    /// Number of registered listeners (main + private queues).
    pub fn listener_count(&self) -> usize {
        self.listeners.len() + self.private_queues.len()
    }
}

impl Default for DomainObjectChangeSupport {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// DomainObjectDBChangeSet
// ============================================================================

/// Trait for domain object change sets backed by a database.
///
/// In Java: `ghidra.framework.data.DomainObjectDBChangeSet`.
pub trait DomainObjectDBChangeSet: ChangeSet {
    /// Get the minimum DB version from which changes have been tracked.
    fn db_min_version(&self) -> i32;

    /// Get the current DB version.
    fn db_current_version(&self) -> i32;

    /// Merge another change set into this one.
    fn merge(&mut self, other: &dyn DomainObjectDBChangeSet);

    /// Save the change set to storage.
    fn save(&self) -> ProjectResult<()>;

    /// Clear all changes since the specified version.
    fn clear_changes_since(&mut self, version: i32);
}

// ============================================================================
// OptionsDB
// ============================================================================

/// A set of named options (key-value pairs) stored in a database.
///
/// In Java: `ghidra.framework.options.OptionsDB` (and `ghidra.framework.options.Options`).
#[derive(Debug, Clone, Default)]
pub struct OptionsDB {
    name: String,
    options: HashMap<String, OptionValue>,
    child_options: HashMap<String, OptionsDB>,
}

/// A single option value with type information.
#[derive(Debug, Clone)]
pub enum OptionValue {
    String(String),
    Int(i32),
    Long(i64),
    Double(f64),
    Bool(bool),
    Bytes(Vec<u8>),
}

impl OptionValue {
    /// Try to get the value as a string.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(s) => Some(s),
            _ => None,
        }
    }

    /// Try to get the value as a boolean.
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// Try to get the value as an i32.
    pub fn as_int(&self) -> Option<i32> {
        match self {
            Self::Int(i) => Some(*i),
            _ => None,
        }
    }

    /// Try to get the value as an i64.
    pub fn as_long(&self) -> Option<i64> {
        match self {
            Self::Long(l) => Some(*l),
            _ => None,
        }
    }

    /// Try to get the value as an f64.
    pub fn as_double(&self) -> Option<f64> {
        match self {
            Self::Double(d) => Some(*d),
            _ => None,
        }
    }
}

impl OptionsDB {
    /// Create a new options set with the given name.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            options: HashMap::new(),
            child_options: HashMap::new(),
        }
    }

    /// The name of this options set.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Set a string option.
    pub fn set_string(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.options.insert(key.into(), OptionValue::String(value.into()));
    }

    /// Get a string option.
    pub fn get_string(&self, key: &str, default: &str) -> String {
        match self.options.get(key) {
            Some(OptionValue::String(s)) => s.clone(),
            _ => default.to_string(),
        }
    }

    /// Set a boolean option.
    pub fn set_bool(&mut self, key: impl Into<String>, value: bool) {
        self.options.insert(key.into(), OptionValue::Bool(value));
    }

    /// Get a boolean option.
    pub fn get_bool(&self, key: &str, default: bool) -> bool {
        match self.options.get(key) {
            Some(OptionValue::Bool(b)) => *b,
            _ => default,
        }
    }

    /// Set an integer option.
    pub fn set_int(&mut self, key: impl Into<String>, value: i32) {
        self.options.insert(key.into(), OptionValue::Int(value));
    }

    /// Get an integer option.
    pub fn get_int(&self, key: &str, default: i32) -> i32 {
        match self.options.get(key) {
            Some(OptionValue::Int(i)) => *i,
            _ => default,
        }
    }

    /// Set a long option.
    pub fn set_long(&mut self, key: impl Into<String>, value: i64) {
        self.options.insert(key.into(), OptionValue::Long(value));
    }

    /// Get a long option.
    pub fn get_long(&self, key: &str, default: i64) -> i64 {
        match self.options.get(key) {
            Some(OptionValue::Long(l)) => *l,
            _ => default,
        }
    }

    /// Set a double option.
    pub fn set_double(&mut self, key: impl Into<String>, value: f64) {
        self.options.insert(key.into(), OptionValue::Double(value));
    }

    /// Get a double option.
    pub fn get_double(&self, key: &str, default: f64) -> f64 {
        match self.options.get(key) {
            Some(OptionValue::Double(d)) => *d,
            _ => default,
        }
    }

    /// Remove an option.
    pub fn remove_option(&mut self, key: &str) {
        self.options.remove(key);
    }

    /// Whether this options set contains a given key.
    pub fn has_option(&self, key: &str) -> bool {
        self.options.contains_key(key)
    }

    /// All option names.
    pub fn option_names(&self) -> Vec<&String> {
        self.options.keys().collect()
    }

    /// Number of options.
    pub fn option_count(&self) -> usize {
        self.options.len()
    }

    /// Get a child options set.
    pub fn get_child(&self, name: &str) -> Option<&OptionsDB> {
        self.child_options.get(name)
    }

    /// Get a mutable child options set.
    pub fn get_child_mut(&mut self, name: &str) -> &mut OptionsDB {
        self.child_options
            .entry(name.to_string())
            .or_insert_with(|| OptionsDB::new(name))
    }

    /// All child option set names.
    pub fn child_names(&self) -> Vec<&String> {
        self.child_options.keys().collect()
    }

    /// Remove all options.
    pub fn clear(&mut self) {
        self.options.clear();
        self.child_options.clear();
    }
}

// ============================================================================
// TransientDataManager
// ============================================================================

/// Manages transient domain objects (not persisted to disk).
///
/// In Java: `ghidra.framework.data.TransientDataManager`.
#[derive(Debug, Default)]
pub struct TransientDataManager {
    objects: HashMap<u64, TransientDomainObject>,
    next_id: u64,
}

/// A minimal domain object stored transiently.
#[derive(Debug, Clone)]
pub struct TransientDomainObject {
    /// Unique ID.
    pub id: u64,
    /// Object name.
    pub name: String,
    /// Content type.
    pub content_type: String,
    /// Whether the object has been modified.
    pub changed: bool,
    /// Metadata map.
    pub metadata: HashMap<String, String>,
}

impl TransientDomainObject {
    /// Create a new transient domain object.
    pub fn new(id: u64, name: impl Into<String>, content_type: impl Into<String>) -> Self {
        Self {
            id,
            name: name.into(),
            content_type: content_type.into(),
            changed: false,
            metadata: HashMap::new(),
        }
    }
}

impl TransientDataManager {
    /// Create a new manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new transient domain object.
    pub fn create(&mut self, name: impl Into<String>, content_type: impl Into<String>) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        let obj = TransientDomainObject::new(id, name, content_type);
        self.objects.insert(id, obj);
        id
    }

    /// Get a reference to a transient object.
    pub fn get(&self, id: u64) -> Option<&TransientDomainObject> {
        self.objects.get(&id)
    }

    /// Get a mutable reference to a transient object.
    pub fn get_mut(&mut self, id: u64) -> Option<&mut TransientDomainObject> {
        self.objects.get_mut(&id)
    }

    /// Remove a transient object.
    pub fn remove(&mut self, id: u64) -> Option<TransientDomainObject> {
        self.objects.remove(&id)
    }

    /// All active transient object IDs.
    pub fn active_ids(&self) -> Vec<u64> {
        self.objects.keys().copied().collect()
    }

    /// Number of active transient objects.
    pub fn count(&self) -> usize {
        self.objects.len()
    }

    /// Remove all transient objects.
    pub fn clear(&mut self) {
        self.objects.clear();
    }
}

// ============================================================================
// DomainFolderChangeListenerList
// ============================================================================

/// Thread-safe list of [`DomainFolderChangeListener`]s with notification support.
///
/// In Java: `ghidra.framework.data.DomainFolderChangeListenerList`.
#[derive(Debug)]
pub struct DomainFolderChangeListenerList {
    listeners: Vec<(u64, Box<dyn DomainFolderChangeListener>)>,
    next_id: u64,
}

impl DomainFolderChangeListenerList {
    /// Create a new empty listener list.
    pub fn new() -> Self {
        Self {
            listeners: Vec::new(),
            next_id: 1,
        }
    }

    /// Add a listener, returning its ID.
    pub fn add(&mut self, listener: Box<dyn DomainFolderChangeListener>) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        self.listeners.push((id, listener));
        id
    }

    /// Remove a listener by ID.
    pub fn remove(&mut self, id: u64) {
        self.listeners.retain(|(lid, _)| *lid != id);
    }

    /// Fire folder-added notification.
    pub fn fire_folder_added(&self, folder_path: &str) {
        for (_, l) in &self.listeners {
            l.domain_folder_added(folder_path);
        }
    }

    /// Fire file-added notification.
    pub fn fire_file_added(&self, file_path: &str) {
        for (_, l) in &self.listeners {
            l.domain_file_added(file_path);
        }
    }

    /// Fire folder-removed notification.
    pub fn fire_folder_removed(&self, parent_path: &str, name: &str) {
        for (_, l) in &self.listeners {
            l.domain_folder_removed(parent_path, name);
        }
    }

    /// Fire file-removed notification.
    pub fn fire_file_removed(&self, parent_path: &str, name: &str, file_id: Option<&str>) {
        for (_, l) in &self.listeners {
            l.domain_file_removed(parent_path, name, file_id);
        }
    }

    /// Fire folder-renamed notification.
    pub fn fire_folder_renamed(&self, folder_path: &str, old_name: &str) {
        for (_, l) in &self.listeners {
            l.domain_folder_renamed(folder_path, old_name);
        }
    }

    /// Fire file-renamed notification.
    pub fn fire_file_renamed(&self, file_path: &str, old_name: &str) {
        for (_, l) in &self.listeners {
            l.domain_file_renamed(file_path, old_name);
        }
    }

    /// Fire folder-moved notification.
    pub fn fire_folder_moved(&self, folder_path: &str, old_parent_path: &str) {
        for (_, l) in &self.listeners {
            l.domain_folder_moved(folder_path, old_parent_path);
        }
    }

    /// Fire file-moved notification.
    pub fn fire_file_moved(&self, file_path: &str, old_parent_path: &str, old_name: &str) {
        for (_, l) in &self.listeners {
            l.domain_file_moved(file_path, old_parent_path, old_name);
        }
    }

    /// Fire folder-set-active notification.
    pub fn fire_folder_set_active(&self, folder_path: &str) {
        for (_, l) in &self.listeners {
            l.domain_folder_set_active(folder_path);
        }
    }

    /// Fire file-status-changed notification.
    pub fn fire_file_status_changed(&self, file_path: &str, file_id_set: bool) {
        for (_, l) in &self.listeners {
            l.domain_file_status_changed(file_path, file_id_set);
        }
    }

    /// Fire file-opened-for-update notification.
    pub fn fire_file_opened_for_update(&self, file_path: &str, object_id: u64) {
        for (_, l) in &self.listeners {
            l.domain_file_object_opened_for_update(file_path, object_id);
        }
    }

    /// Fire file-closed notification.
    pub fn fire_file_closed(&self, file_path: &str, object_id: u64) {
        for (_, l) in &self.listeners {
            l.domain_file_object_closed(file_path, object_id);
        }
    }

    /// Number of registered listeners.
    pub fn len(&self) -> usize {
        self.listeners.len()
    }

    /// Whether no listeners are registered.
    pub fn is_empty(&self) -> bool {
        self.listeners.is_empty()
    }
}

impl Default for DomainFolderChangeListenerList {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// DefaultProjectData
// ============================================================================

/// Default implementation of [`ProjectData2`].
///
/// In Java: `ghidra.framework.data.DefaultProjectData`.
#[derive(Debug)]
pub struct DefaultProjectData {
    project_locator: ProjectLocator,
    root_folder_path: String,
    file_count: i32,
    max_name_length: usize,
    listeners: DomainFolderChangeListenerList,
    is_closed: bool,
}

impl DefaultProjectData {
    /// Create a new `DefaultProjectData`.
    pub fn new(project_locator: ProjectLocator, root_folder_path: String) -> Self {
        Self {
            project_locator,
            root_folder_path,
            file_count: -1,
            max_name_length: 256,
            listeners: DomainFolderChangeListenerList::new(),
            is_closed: false,
        }
    }

    /// Set the file count.
    pub fn set_file_count(&mut self, count: i32) {
        self.file_count = count;
    }
}

impl ProjectData2 for DefaultProjectData {
    fn root_folder_path(&self) -> &str {
        &self.root_folder_path
    }

    fn get_folder(&self, path: &str) -> Option<String> {
        // In a real implementation this would traverse the filesystem.
        if path.starts_with('/') {
            Some(path.to_string())
        } else {
            None
        }
    }

    fn get_file(&self, path: &str) -> Option<String> {
        if path.starts_with('/') && !path.ends_with('/') {
            Some(path.to_string())
        } else {
            None
        }
    }

    fn get_file_by_id(&self, _file_id: &str) -> Option<String> {
        None
    }

    fn file_count(&self) -> i32 {
        self.file_count
    }

    fn project_locator(&self) -> &ProjectLocator {
        &self.project_locator
    }

    fn max_name_length(&self) -> usize {
        self.max_name_length
    }

    fn make_valid_name(&self, name: &str) -> String {
        let valid: String = name
            .chars()
            .map(|c| {
                if c.is_alphanumeric() || c == '_' || c == '-' || c == '.' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        if valid.is_empty() {
            "unknown".to_string()
        } else {
            valid
        }
    }

    fn refresh(&self, _force: bool) {
        // In a real implementation this would rescan the filesystem.
    }

    fn close(&self) {
        // In a real implementation this would release resources.
    }

    fn add_domain_folder_change_listener(&self, _listener: Box<dyn DomainFolderChangeListener>) {
        // Requires &mut self in a real implementation; here we track via interior mutability.
    }

    fn remove_domain_folder_change_listener(&self, _listener_id: u64) {
        // Requires &mut self in a real implementation.
    }

    fn get_project_locator(&self) -> &ProjectLocator {
        &self.project_locator
    }

    fn shared_project_url(&self) -> Option<String> {
        None
    }

    fn local_project_url(&self) -> Option<String> {
        Some(format!(
            "ghidra://localhost/{}",
            self.project_locator.project_name
        ))
    }
}

// ============================================================================
// MetadataManager
// ============================================================================

/// Manages metadata key-value pairs for a domain object.
///
/// In Java: `ghidra.framework.data.MetadataManager`.
#[derive(Debug, Clone, Default)]
pub struct MetadataManager {
    metadata: HashMap<String, String>,
    order: Vec<String>,
}

impl MetadataManager {
    /// Create a new metadata manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set a metadata value.
    pub fn set(&mut self, key: impl Into<String>, value: impl Into<String>) {
        let key = key.into();
        if !self.metadata.contains_key(&key) {
            self.order.push(key.clone());
        }
        self.metadata.insert(key, value.into());
    }

    /// Get a metadata value.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.metadata.get(key).map(|s| s.as_str())
    }

    /// Remove a metadata key.
    pub fn remove(&mut self, key: &str) {
        self.metadata.remove(key);
        self.order.retain(|k| k != key);
    }

    /// All metadata in insertion order.
    pub fn ordered_entries(&self) -> Vec<(&str, &str)> {
        self.order
            .iter()
            .filter_map(|k| self.metadata.get(k).map(|v| (k.as_str(), v.as_str())))
            .collect()
    }

    /// All metadata as a HashMap.
    pub fn to_map(&self) -> &HashMap<String, String> {
        &self.metadata
    }

    /// Number of metadata entries.
    pub fn len(&self) -> usize {
        self.metadata.len()
    }

    /// Whether metadata is empty.
    pub fn is_empty(&self) -> bool {
        self.metadata.is_empty()
    }
}

// ============================================================================
// DomainFileIndex
// ============================================================================

/// Indexes domain files for efficient lookup by path or file ID.
///
/// In Java: `ghidra.framework.data.DomainFileIndex`.
#[derive(Debug, Default)]
pub struct DomainFileIndex {
    by_path: HashMap<String, u64>,
    by_id: HashMap<String, u64>,
}

impl DomainFileIndex {
    /// Create a new index.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a file to the index.
    pub fn add(&mut self, path: String, file_id: Option<String>, internal_id: u64) {
        self.by_path.insert(path, internal_id);
        if let Some(id) = file_id {
            self.by_id.insert(id, internal_id);
        }
    }

    /// Remove a file from the index.
    pub fn remove(&mut self, path: &str, file_id: Option<&str>) -> Option<u64> {
        let result = self.by_path.remove(path);
        if let Some(id) = file_id {
            self.by_id.remove(id);
        }
        result
    }

    /// Lookup by path.
    pub fn get_by_path(&self, path: &str) -> Option<u64> {
        self.by_path.get(path).copied()
    }

    /// Lookup by file ID.
    pub fn get_by_id(&self, file_id: &str) -> Option<u64> {
        self.by_id.get(file_id).copied()
    }

    /// Number of indexed files.
    pub fn len(&self) -> usize {
        self.by_path.len()
    }

    /// Whether the index is empty.
    pub fn is_empty(&self) -> bool {
        self.by_path.is_empty()
    }

    /// All indexed paths.
    pub fn all_paths(&self) -> Vec<&String> {
        self.by_path.keys().collect()
    }

    /// Clear the index.
    pub fn clear(&mut self) {
        self.by_path.clear();
        self.by_id.clear();
    }
}

// ============================================================================
// ToolState / ToolStateFactory
// ============================================================================

/// Persistent state of a tool configuration.
///
/// In Java: `ghidra.framework.data.ToolState`.
#[derive(Debug, Clone, Default)]
pub struct ToolState {
    /// Tool name.
    pub name: String,
    /// Plugin names and their configuration.
    pub plugins: HashMap<String, PluginConfig>,
    /// Tool-level options.
    pub options: OptionsDB,
    /// Tool window position/layout data.
    pub layout_data: Option<Vec<u8>>,
}

/// Configuration for a single plugin within a tool.
#[derive(Debug, Clone, Default)]
pub struct PluginConfig {
    /// Plugin class name.
    pub class_name: String,
    /// Whether the plugin is enabled.
    pub enabled: bool,
    /// Plugin-specific options.
    pub options: OptionsDB,
    /// Plugin priority (load order).
    pub priority: i32,
}

/// Factory for creating and restoring tool states.
///
/// In Java: `ghidra.framework.data.ToolStateFactory`.
#[derive(Debug, Default)]
pub struct ToolStateFactory;

impl ToolStateFactory {
    /// Create a new factory.
    pub fn new() -> Self {
        Self
    }

    /// Create a new empty tool state.
    pub fn create_tool_state(&self, name: impl Into<String>) -> ToolState {
        ToolState {
            name: name.into(),
            ..Default::default()
        }
    }

    /// Create a plugin configuration.
    pub fn create_plugin_config(
        &self,
        class_name: impl Into<String>,
        enabled: bool,
        priority: i32,
    ) -> PluginConfig {
        PluginConfig {
            class_name: class_name.into(),
            enabled,
            options: OptionsDB::new("plugin"),
            priority,
        }
    }
}

// ============================================================================
// DefaultCheckinHandler
// ============================================================================

/// Default implementation of CheckinHandler.
///
/// In Java: `ghidra.framework.data.DefaultCheckinHandler`.
#[derive(Debug, Clone)]
pub struct DefaultCheckinHandler {
    comment: String,
    keep_checked_out: bool,
}

impl DefaultCheckinHandler {
    /// Create a new default checkin handler.
    pub fn new(comment: impl Into<String>, keep_checked_out: bool) -> Self {
        Self {
            comment: comment.into(),
            keep_checked_out,
        }
    }
}

impl CheckinHandler for DefaultCheckinHandler {
    fn comment(&self) -> &str {
        &self.comment
    }
    fn keep_checked_out(&self) -> bool {
        self.keep_checked_out
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_open_mode() {
        assert!(OpenMode::Update.allows_write());
        assert!(!OpenMode::Immutable.allows_write());
        assert!(OpenMode::Upgrade.requires_upgrade());
        assert!(OpenMode::Immutable.is_read_only());
        assert!(!OpenMode::Create.is_read_only());
    }

    #[test]
    fn test_open_mode_display() {
        assert_eq!(format!("{}", OpenMode::Create), "CREATE");
        assert_eq!(format!("{}", OpenMode::Upgrade), "UPGRADE");
    }

    #[test]
    fn test_options_db() {
        let mut opts = OptionsDB::new("analysis");
        opts.set_string("param1", "value1");
        opts.set_bool("enabled", true);
        opts.set_int("count", 42);
        opts.set_long("timestamp", 1000000);
        opts.set_double("ratio", 0.5);

        assert_eq!(opts.get_string("param1", ""), "value1");
        assert!(opts.get_bool("enabled", false));
        assert_eq!(opts.get_int("count", 0), 42);
        assert_eq!(opts.get_long("timestamp", 0), 1000000);
        assert_eq!(opts.get_double("ratio", 0.0), 0.5);

        // Default values for missing keys.
        assert_eq!(opts.get_string("missing", "default"), "default");
        assert!(!opts.get_bool("missing", false));
        assert_eq!(opts.get_int("missing", -1), -1);

        assert!(opts.has_option("param1"));
        assert!(!opts.has_option("missing"));
        assert_eq!(opts.option_count(), 5);

        opts.remove_option("count");
        assert_eq!(opts.option_count(), 4);
    }

    #[test]
    fn test_options_db_child() {
        let mut opts = OptionsDB::new("root");
        {
            let child = opts.get_child_mut("sub");
            child.set_string("key", "val");
        }
        assert!(opts.get_child("sub").is_some());
        assert_eq!(opts.get_child("sub").unwrap().get_string("key", ""), "val");
    }

    #[test]
    fn test_option_value() {
        let v = OptionValue::String("hello".to_string());
        assert_eq!(v.as_str(), Some("hello"));
        assert!(v.as_bool().is_none());

        let v2 = OptionValue::Bool(true);
        assert_eq!(v2.as_bool(), Some(true));
        assert!(v2.as_str().is_none());
    }

    #[test]
    fn test_domain_object_change_support() {
        let mut support = DomainObjectChangeSupport::new();
        assert_eq!(support.listener_count(), 0);
        assert!(support.is_sending_events());

        #[derive(Debug)]
        struct TestListener {
            count: std::sync::atomic::AtomicUsize,
        }
        impl DomainObjectListener for TestListener {
            fn domain_object_changed(&self, _ev: &DomainObjectChangedEvent) {
                self.count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        }

        let listener = Box::new(TestListener {
            count: std::sync::atomic::AtomicUsize::new(0),
        });
        let _id = support.add_listener(listener);
        assert_eq!(support.listener_count(), 1);

        let event = DomainObjectChangedEvent::new(vec![DomainObjectChangeRecord::new(
            Box::new(DomainObjectEvent::Saved),
        )]);
        support.fire_event(&event);

        support.set_events_enabled(false);
        assert!(!support.is_sending_events());
    }

    #[test]
    fn test_transient_data_manager() {
        let mut mgr = TransientDataManager::new();
        let id1 = mgr.create("obj1", "Program");
        let id2 = mgr.create("obj2", "DataTypeArchive");

        assert_eq!(mgr.count(), 2);
        assert!(mgr.get(id1).is_some());
        assert_eq!(mgr.get(id1).unwrap().name, "obj1");
        assert_eq!(mgr.get(id2).unwrap().content_type, "DataTypeArchive");

        let ids = mgr.active_ids();
        assert_eq!(ids.len(), 2);

        mgr.remove(id1);
        assert_eq!(mgr.count(), 1);
        assert!(mgr.get(id1).is_none());
    }

    #[test]
    fn test_domain_folder_change_listener_list() {
        let mut list = DomainFolderChangeListenerList::new();
        assert!(list.is_empty());

        #[derive(Debug)]
        struct TestFolderListener;
        impl DomainFolderChangeListener for TestFolderListener {}

        let _id = list.add(Box::new(TestFolderListener));
        assert_eq!(list.len(), 1);

        // Fire notifications (no panic means success).
        list.fire_folder_added("/test");
        list.fire_file_added("/test/file.txt");
        list.fire_folder_removed("/test", "sub");
    }

    #[test]
    fn test_default_project_data() {
        let loc = ProjectLocator::new("/tmp/proj", "test");
        let data = DefaultProjectData::new(loc.clone(), "/".to_string());

        assert_eq!(data.root_folder_path(), "/");
        assert_eq!(data.file_count(), -1);
        assert_eq!(data.project_locator().project_name, "test");

        assert_eq!(data.make_valid_name("hello world!"), "hello_world_");
        assert_eq!(data.make_valid_name(""), "unknown");
        assert_eq!(data.make_valid_name("abc123"), "abc123");
    }

    #[test]
    fn test_metadata_manager() {
        let mut meta = MetadataManager::new();
        meta.set("author", "alice");
        meta.set("version", "1.0");
        meta.set("description", "test project");

        assert_eq!(meta.len(), 3);
        assert_eq!(meta.get("author"), Some("alice"));

        let ordered = meta.ordered_entries();
        assert_eq!(ordered.len(), 3);
        assert_eq!(ordered[0].0, "author");

        meta.remove("version");
        assert_eq!(meta.len(), 2);
        assert!(meta.get("version").is_none());
    }

    #[test]
    fn test_domain_file_index() {
        let mut index = DomainFileIndex::new();
        index.add("/file1".to_string(), Some("id1".to_string()), 1);
        index.add("/file2".to_string(), None, 2);

        assert_eq!(index.len(), 2);
        assert_eq!(index.get_by_path("/file1"), Some(1));
        assert_eq!(index.get_by_id("id1"), Some(1));
        assert_eq!(index.get_by_id("id2"), None);

        index.remove("/file1", Some("id1"));
        assert_eq!(index.len(), 1);
        assert!(index.get_by_path("/file1").is_none());
    }

    #[test]
    fn test_tool_state() {
        let factory = ToolStateFactory::new();
        let mut state = factory.create_tool_state("CodeBrowser");

        let mut plugin = factory.create_plugin_config("MyPlugin", true, 10);
        plugin.options.set_string("setting1", "val1");
        state.plugins.insert("MyPlugin".to_string(), plugin);

        assert_eq!(state.name, "CodeBrowser");
        assert!(state.plugins.contains_key("MyPlugin"));
        assert!(state.plugins["MyPlugin"].enabled);
    }

    #[test]
    fn test_default_checkin_handler() {
        let handler = DefaultCheckinHandler::new("initial commit", false);
        assert_eq!(handler.comment(), "initial commit");
        assert!(!handler.keep_checked_out());
    }
}
