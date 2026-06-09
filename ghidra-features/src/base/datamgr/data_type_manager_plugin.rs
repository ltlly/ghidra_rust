//! DataTypeManager Plugin -- top-level plugin for the Data Type Manager feature.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin`.
//!
//! This module provides [`DataTypeManagerPlugin`], which manages the lifecycle
//! of a connected [`DataTypeManagerProvider`] (tied to the active program) and
//! zero or more archive providers (external type libraries). It dispatches
//! actions for creating, editing, deleting, and searching data types, and
//! handles program open/close/activate events.
//!
//! # Architecture
//!
//! ```text
//! DataTypeManagerPlugin
//!   ├── provider: DataTypeManagerProvider  (connected to active program)
//!   ├── archive_providers: Vec<ArchiveInfo>  (external type archives)
//!   ├── actions: DtMgrAction  (new, edit, delete, rename, cut/copy/paste)
//!   └── state tracking (current_program, initialized, disposed)
//! ```

use std::fmt;

use super::data_type_manager_provider::DataTypeManagerProvider;

// ---------------------------------------------------------------------------
// DtMgrConfigValue -- configuration values stored by the plugin
// ---------------------------------------------------------------------------

/// A configuration value stored by the DataTypeManager plugin.
#[derive(Debug, Clone)]
pub enum DtMgrConfigValue {
    /// Boolean value.
    Bool(bool),
    /// Integer value.
    Int(i32),
    /// String value.
    String(String),
}

impl fmt::Display for DtMgrConfigValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bool(v) => write!(f, "{}", v),
            Self::Int(v) => write!(f, "{}", v),
            Self::String(v) => write!(f, "{}", v),
        }
    }
}

// ---------------------------------------------------------------------------
// DtMgrAction -- action models for the DataTypeManager plugin
// ---------------------------------------------------------------------------

/// Represents the set of actions available in the Data Type Manager.
///
/// Each field corresponds to a menu/toolbar action ported from the Java
/// `DataTypeManagerPlugin.setupActions()` method.
#[derive(Debug, Clone)]
pub struct DtMgrAction {
    /// "New" actions grouped by category (structure, union, enum, typedef, etc.).
    pub new_structure_enabled: bool,
    pub new_union_enabled: bool,
    pub new_enum_enabled: bool,
    pub new_typedef_enabled: bool,
    pub new_function_def_enabled: bool,
    /// Edit / Delete / Rename actions.
    pub edit_enabled: bool,
    pub delete_enabled: bool,
    pub rename_enabled: bool,
    /// Clipboard actions.
    pub cut_enabled: bool,
    pub copy_enabled: bool,
    pub paste_enabled: bool,
    /// Search action.
    pub search_enabled: bool,
    /// "Apply" data type to listing.
    pub apply_enabled: bool,
    /// "Set as default" pointer size.
    pub set_default_pointer_enabled: bool,
    /// "Replace" data type.
    pub replace_enabled: bool,
    /// "Refresh" from archive.
    pub refresh_enabled: bool,
    /// "Open archive" action.
    pub open_archive_enabled: bool,
    /// "Close archive" action.
    pub close_archive_enabled: bool,
}

impl DtMgrAction {
    /// Create a new action set with all actions disabled.
    pub fn new() -> Self {
        Self {
            new_structure_enabled: false,
            new_union_enabled: false,
            new_enum_enabled: false,
            new_typedef_enabled: false,
            new_function_def_enabled: false,
            edit_enabled: false,
            delete_enabled: false,
            rename_enabled: false,
            cut_enabled: false,
            copy_enabled: false,
            paste_enabled: false,
            search_enabled: false,
            apply_enabled: false,
            set_default_pointer_enabled: false,
            replace_enabled: false,
            refresh_enabled: false,
            open_archive_enabled: false,
            close_archive_enabled: false,
        }
    }

    /// Enable all create/edit actions (typically called when a program is active).
    pub fn enable_all(&mut self) {
        self.new_structure_enabled = true;
        self.new_union_enabled = true;
        self.new_enum_enabled = true;
        self.new_typedef_enabled = true;
        self.new_function_def_enabled = true;
        self.edit_enabled = true;
        self.delete_enabled = true;
        self.rename_enabled = true;
        self.cut_enabled = true;
        self.copy_enabled = true;
        self.paste_enabled = true;
        self.search_enabled = true;
        self.apply_enabled = true;
        self.set_default_pointer_enabled = true;
        self.replace_enabled = true;
        self.refresh_enabled = true;
        self.open_archive_enabled = true;
        self.close_archive_enabled = true;
    }

    /// Disable all actions (typically called when no program is active).
    pub fn disable_all(&mut self) {
        *self = Self::new();
    }

    /// Returns `true` if the "new structure" action is enabled.
    pub fn can_new_structure(&self) -> bool {
        self.new_structure_enabled
    }

    /// Returns `true` if the "edit" action is enabled.
    pub fn can_edit(&self) -> bool {
        self.edit_enabled
    }

    /// Returns `true` if the "delete" action is enabled.
    pub fn can_delete(&self) -> bool {
        self.delete_enabled
    }

    /// Returns `true` if the "search" action is enabled.
    pub fn can_search(&self) -> bool {
        self.search_enabled
    }
}

impl Default for DtMgrAction {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// ArchiveInfo -- metadata about an external type archive
// ---------------------------------------------------------------------------

/// Metadata about an external type archive (GDT file or built-in types).
///
/// Ported from the archive management logic in `DataTypeManagerPlugin`.
#[derive(Debug, Clone)]
pub struct ArchiveInfo {
    /// The display name of the archive (e.g., "generic_C_lib", "BuiltInTypes").
    name: String,
    /// The file path (if a file-based archive).
    file_path: Option<String>,
    /// Whether the archive is the built-in types archive.
    is_builtin: bool,
    /// Whether the archive is currently open/loaded.
    is_open: bool,
    /// Whether the archive has been modified since last save.
    is_dirty: bool,
    /// The number of data types in this archive.
    type_count: usize,
}

impl ArchiveInfo {
    /// Create a new archive info entry.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            file_path: None,
            is_builtin: false,
            is_open: false,
            is_dirty: false,
            type_count: 0,
        }
    }

    /// Create info for the built-in types archive.
    pub fn builtin() -> Self {
        Self {
            name: "BuiltInTypes".into(),
            file_path: None,
            is_builtin: true,
            is_open: true,
            is_dirty: false,
            type_count: 0,
        }
    }

    /// Create info for a file-based archive.
    pub fn from_file(name: impl Into<String>, path: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            file_path: Some(path.into()),
            is_builtin: false,
            is_open: false,
            is_dirty: false,
            type_count: 0,
        }
    }

    /// The display name of this archive.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The file path, if file-based.
    pub fn file_path(&self) -> Option<&str> {
        self.file_path.as_deref()
    }

    /// Whether this is the built-in types archive.
    pub fn is_builtin(&self) -> bool {
        self.is_builtin
    }

    /// Whether this archive is currently open.
    pub fn is_open(&self) -> bool {
        self.is_open
    }

    /// Set the open state.
    pub fn set_open(&mut self, open: bool) {
        self.is_open = open;
    }

    /// Whether this archive has unsaved changes.
    pub fn is_dirty(&self) -> bool {
        self.is_dirty
    }

    /// Set the dirty state.
    pub fn set_dirty(&mut self, dirty: bool) {
        self.is_dirty = dirty;
    }

    /// The number of data types in this archive.
    pub fn type_count(&self) -> usize {
        self.type_count
    }

    /// Set the type count.
    pub fn set_type_count(&mut self, count: usize) {
        self.type_count = count;
    }
}

impl fmt::Display for ArchiveInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({} types", self.name, self.type_count)?;
        if self.is_dirty {
            write!(f, ", dirty")?;
        }
        if self.is_builtin {
            write!(f, ", builtin")?;
        }
        write!(f, ")")
    }
}

// ---------------------------------------------------------------------------
// DataTypeManagerPlugin -- the main plugin
// ---------------------------------------------------------------------------

/// The Data Type Manager plugin.
///
/// Manages the connected [`DataTypeManagerProvider`] tied to the active
/// program, external archive providers, and the set of available actions.
///
/// Ported from `ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin`.
#[derive(Debug)]
pub struct DataTypeManagerPlugin {
    /// Plugin name.
    name: String,
    /// The connected (primary) provider for the active program's type manager.
    provider: DataTypeManagerProvider,
    /// External archive providers (GDT files, built-in types, etc.).
    archive_infos: Vec<ArchiveInfo>,
    /// The action models.
    actions: DtMgrAction,
    /// Name of the currently active program (if any).
    current_program: Option<String>,
    /// Whether the plugin has been initialized.
    initialized: bool,
    /// Whether the plugin has been disposed.
    disposed: bool,
    /// Stored configuration (key-value pairs).
    config: std::collections::HashMap<String, DtMgrConfigValue>,
    /// Whether to show the data type manager on startup.
    show_on_startup: bool,
    /// The default category path for newly created types.
    default_category_path: String,
}

impl DataTypeManagerPlugin {
    /// Creates a new DataTypeManager plugin.
    pub fn new(name: impl Into<String>) -> Self {
        let name = name.into();
        Self {
            provider: DataTypeManagerProvider::new("Data Type Manager", true),
            name,
            archive_infos: Vec::new(),
            actions: DtMgrAction::new(),
            current_program: None,
            initialized: false,
            disposed: false,
            config: std::collections::HashMap::new(),
            show_on_startup: true,
            default_category_path: "/".into(),
        }
    }

    /// Returns the plugin name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Initializes the plugin.
    pub fn init(&mut self) {
        if self.initialized {
            return;
        }
        self.initialized = true;
        // Register the built-in types archive.
        self.archive_infos.push(ArchiveInfo::builtin());
    }

    /// Disposes the plugin and all providers.
    pub fn dispose(&mut self) {
        if self.disposed {
            return;
        }
        self.disposed = true;
        self.provider.dispose();
        self.actions.disable_all();
        self.current_program = None;
        self.archive_infos.clear();
    }

    /// Whether the plugin is initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Whether the plugin is disposed.
    pub fn is_disposed(&self) -> bool {
        self.disposed
    }

    // ---- Provider access ----

    /// Returns a reference to the connected provider.
    pub fn provider(&self) -> &DataTypeManagerProvider {
        &self.provider
    }

    /// Returns a mutable reference to the connected provider.
    pub fn provider_mut(&mut self) -> &mut DataTypeManagerProvider {
        &mut self.provider
    }

    // ---- Archive management ----

    /// Returns a reference to the archive info list.
    pub fn archive_infos(&self) -> &[ArchiveInfo] {
        &self.archive_infos
    }

    /// Returns a mutable reference to the archive info list.
    pub fn archive_infos_mut(&mut self) -> &mut Vec<ArchiveInfo> {
        &mut self.archive_infos
    }

    /// Opens an external archive by file path.
    ///
    /// Returns the index of the new archive entry, or the index of the
    /// existing entry if already open.
    pub fn open_archive(
        &mut self,
        name: impl Into<String>,
        path: impl Into<String>,
    ) -> usize {
        let path_str = path.into();
        // Check if already open.
        if let Some(idx) = self
            .archive_infos
            .iter()
            .position(|a| a.file_path.as_deref() == Some(&path_str))
        {
            return idx;
        }
        let mut info = ArchiveInfo::from_file(name, &path_str);
        info.set_open(true);
        let idx = self.archive_infos.len();
        self.archive_infos.push(info);
        idx
    }

    /// Closes an archive by index.
    pub fn close_archive(&mut self, index: usize) -> bool {
        if let Some(info) = self.archive_infos.get_mut(index) {
            if info.is_builtin {
                return false; // Cannot close the built-in types archive.
            }
            info.set_open(false);
            true
        } else {
            false
        }
    }

    /// Removes a closed archive entry by index.
    pub fn remove_archive(&mut self, index: usize) -> Option<ArchiveInfo> {
        if let Some(info) = self.archive_infos.get(index) {
            if info.is_builtin {
                return None; // Cannot remove the built-in types archive.
            }
        }
        if index < self.archive_infos.len() {
            Some(self.archive_infos.remove(index))
        } else {
            None
        }
    }

    /// Returns the number of open archives.
    pub fn open_archive_count(&self) -> usize {
        self.archive_infos.iter().filter(|a| a.is_open).count()
    }

    // ---- Program lifecycle ----

    /// Called when a program is opened.
    pub fn program_opened(&mut self, program_name: impl Into<String>) {
        let name = program_name.into();
        self.current_program = Some(name.clone());
        self.provider.program_opened(name);
        self.actions.enable_all();
    }

    /// Called when the active program changes.
    pub fn program_activated(&mut self, program_name: impl Into<String>) {
        let name = program_name.into();
        self.current_program = Some(name.clone());
        self.provider.program_opened(name);
        self.actions.enable_all();
    }

    /// Called when a program is closed.
    pub fn program_closed(&mut self, program_name: &str) {
        if self.current_program.as_deref() == Some(program_name) {
            self.current_program = None;
            self.provider.program_closed();
            self.actions.disable_all();
        }
    }

    /// The name of the currently active program, if any.
    pub fn current_program(&self) -> Option<&str> {
        self.current_program.as_deref()
    }

    // ---- Actions ----

    /// Returns a reference to the action models.
    pub fn actions(&self) -> &DtMgrAction {
        &self.actions
    }

    /// Returns a mutable reference to the action models.
    pub fn actions_mut(&mut self) -> &mut DtMgrAction {
        &mut self.actions
    }

    // ---- Configuration persistence ----

    /// Writes configuration state to the given key-value store.
    pub fn write_config_state(
        &self,
        store: &mut std::collections::HashMap<String, DtMgrConfigValue>,
    ) {
        store.insert(
            "show_on_startup".into(),
            DtMgrConfigValue::Bool(self.show_on_startup),
        );
        store.insert(
            "default_category_path".into(),
            DtMgrConfigValue::String(self.default_category_path.clone()),
        );
    }

    /// Reads configuration state from the given key-value store.
    pub fn read_config_state(
        &mut self,
        store: &std::collections::HashMap<String, DtMgrConfigValue>,
    ) {
        if let Some(DtMgrConfigValue::Bool(show)) = store.get("show_on_startup") {
            self.show_on_startup = *show;
        }
        if let Some(DtMgrConfigValue::String(path)) = store.get("default_category_path") {
            self.default_category_path = path.clone();
        }
    }

    /// Whether to show the data type manager on startup.
    pub fn show_on_startup(&self) -> bool {
        self.show_on_startup
    }

    /// Set whether to show the data type manager on startup.
    pub fn set_show_on_startup(&mut self, show: bool) {
        self.show_on_startup = show;
    }

    /// Returns the default category path for newly created types.
    pub fn default_category_path(&self) -> &str {
        &self.default_category_path
    }

    /// Sets the default category path for newly created types.
    pub fn set_default_category_path(&mut self, path: impl Into<String>) {
        self.default_category_path = path.into();
    }

    /// Sets a config value.
    pub fn set_config(&mut self, key: impl Into<String>, value: DtMgrConfigValue) {
        self.config.insert(key.into(), value);
    }

    /// Gets a config value.
    pub fn get_config(&self, key: &str) -> Option<&DtMgrConfigValue> {
        self.config.get(key)
    }
}

impl Default for DataTypeManagerPlugin {
    fn default() -> Self {
        Self::new("DataTypeManagerPlugin")
    }
}

impl fmt::Display for DataTypeManagerPlugin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DataTypeManagerPlugin({}, program={:?}, archives={})",
            self.name,
            self.current_program,
            self.archive_infos.len()
        )
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_creation() {
        let plugin = DataTypeManagerPlugin::new("TestDTM");
        assert_eq!(plugin.name(), "TestDTM");
        assert!(!plugin.is_initialized());
        assert!(!plugin.is_disposed());
        assert!(plugin.current_program().is_none());
        assert!(plugin.archive_infos().is_empty());
    }

    #[test]
    fn test_plugin_init_dispose() {
        let mut plugin = DataTypeManagerPlugin::new("TestDTM");
        plugin.init();
        assert!(plugin.is_initialized());
        // Init should add the built-in types archive.
        assert_eq!(plugin.archive_infos().len(), 1);
        assert!(plugin.archive_infos()[0].is_builtin());
        plugin.dispose();
        assert!(plugin.is_disposed());
    }

    #[test]
    fn test_plugin_double_init() {
        let mut plugin = DataTypeManagerPlugin::new("TestDTM");
        plugin.init();
        plugin.init(); // second call should be a no-op
        assert!(plugin.is_initialized());
    }

    #[test]
    fn test_plugin_double_dispose() {
        let mut plugin = DataTypeManagerPlugin::new("TestDTM");
        plugin.init();
        plugin.dispose();
        plugin.dispose(); // second call should be a no-op
        assert!(plugin.is_disposed());
    }

    #[test]
    fn test_program_lifecycle() {
        let mut plugin = DataTypeManagerPlugin::new("TestDTM");
        plugin.init();
        plugin.program_opened("test.exe");
        assert_eq!(plugin.current_program(), Some("test.exe"));
        assert!(plugin.actions().can_edit());

        plugin.program_closed("test.exe");
        assert!(plugin.current_program().is_none());
        assert!(!plugin.actions().can_edit());
    }

    #[test]
    fn test_program_activated() {
        let mut plugin = DataTypeManagerPlugin::new("TestDTM");
        plugin.init();
        plugin.program_activated("test.exe");
        assert_eq!(plugin.current_program(), Some("test.exe"));
        assert!(plugin.actions().can_new_structure());
        assert!(plugin.actions().can_search());
    }

    #[test]
    fn test_program_closed_wrong_name() {
        let mut plugin = DataTypeManagerPlugin::new("TestDTM");
        plugin.init();
        plugin.program_opened("test.exe");
        plugin.program_closed("other.exe"); // wrong name
        assert_eq!(plugin.current_program(), Some("test.exe"));
    }

    #[test]
    fn test_archive_open_close() {
        let mut plugin = DataTypeManagerPlugin::new("TestDTM");
        plugin.init();
        assert_eq!(plugin.archive_infos().len(), 1); // builtin

        let idx = plugin.open_archive("my_types", "/path/to/my_types.gdt");
        assert_eq!(idx, 1);
        assert_eq!(plugin.archive_infos().len(), 2);
        assert!(plugin.archive_infos()[1].is_open());

        // Opening the same path again should return the same index.
        let idx2 = plugin.open_archive("my_types", "/path/to/my_types.gdt");
        assert_eq!(idx2, 1);

        // Close the archive.
        assert!(plugin.close_archive(1));
        assert!(!plugin.archive_infos()[1].is_open());
    }

    #[test]
    fn test_close_builtin_archive_fails() {
        let mut plugin = DataTypeManagerPlugin::new("TestDTM");
        plugin.init();
        // Index 0 is the built-in types archive.
        assert!(!plugin.close_archive(0));
    }

    #[test]
    fn test_remove_archive() {
        let mut plugin = DataTypeManagerPlugin::new("TestDTM");
        plugin.init();
        plugin.open_archive("my_types", "/path/to/my_types.gdt");
        assert_eq!(plugin.archive_infos().len(), 2);

        let removed = plugin.remove_archive(1);
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().name(), "my_types");
        assert_eq!(plugin.archive_infos().len(), 1);
    }

    #[test]
    fn test_remove_builtin_archive_fails() {
        let mut plugin = DataTypeManagerPlugin::new("TestDTM");
        plugin.init();
        assert!(plugin.remove_archive(0).is_none());
    }

    #[test]
    fn test_open_archive_count() {
        let mut plugin = DataTypeManagerPlugin::new("TestDTM");
        plugin.init();
        assert_eq!(plugin.open_archive_count(), 1); // builtin

        plugin.open_archive("my_types", "/path/to/my_types.gdt");
        assert_eq!(plugin.open_archive_count(), 2);

        plugin.close_archive(1);
        assert_eq!(plugin.open_archive_count(), 1);
    }

    #[test]
    fn test_actions_default() {
        let actions = DtMgrAction::new();
        assert!(!actions.can_new_structure());
        assert!(!actions.can_edit());
        assert!(!actions.can_delete());
        assert!(!actions.can_search());
    }

    #[test]
    fn test_actions_enable_all() {
        let mut actions = DtMgrAction::new();
        actions.enable_all();
        assert!(actions.can_new_structure());
        assert!(actions.can_edit());
        assert!(actions.can_delete());
        assert!(actions.can_search());
    }

    #[test]
    fn test_actions_disable_all() {
        let mut actions = DtMgrAction::new();
        actions.enable_all();
        actions.disable_all();
        assert!(!actions.can_new_structure());
        assert!(!actions.can_edit());
    }

    #[test]
    fn test_config() {
        let mut plugin = DataTypeManagerPlugin::new("TestDTM");
        plugin.set_config("max_results", DtMgrConfigValue::Int(500));
        assert!(matches!(
            plugin.get_config("max_results"),
            Some(DtMgrConfigValue::Int(500))
        ));
    }

    #[test]
    fn test_config_persistence() {
        let mut plugin = DataTypeManagerPlugin::new("TestDTM");
        plugin.set_show_on_startup(false);
        plugin.set_default_category_path("/MyTypes");

        let mut store = std::collections::HashMap::new();
        plugin.write_config_state(&mut store);

        let mut plugin2 = DataTypeManagerPlugin::new("TestDTM2");
        plugin2.read_config_state(&store);
        assert!(!plugin2.show_on_startup());
        assert_eq!(plugin2.default_category_path(), "/MyTypes");
    }

    #[test]
    fn test_default() {
        let plugin = DataTypeManagerPlugin::default();
        assert_eq!(plugin.name(), "DataTypeManagerPlugin");
    }

    #[test]
    fn test_display() {
        let plugin = DataTypeManagerPlugin::new("Test");
        let s = format!("{}", plugin);
        assert!(s.contains("Test"));
        assert!(s.contains("archives="));
    }

    #[test]
    fn test_archive_info_display() {
        let mut info = ArchiveInfo::new("my_types");
        info.set_type_count(42);
        info.set_dirty(true);
        let s = format!("{}", info);
        assert!(s.contains("my_types"));
        assert!(s.contains("42"));
        assert!(s.contains("dirty"));
    }

    #[test]
    fn test_archive_info_builtin() {
        let info = ArchiveInfo::builtin();
        assert_eq!(info.name(), "BuiltInTypes");
        assert!(info.is_builtin());
        assert!(info.is_open());
    }

    #[test]
    fn test_archive_info_from_file() {
        let info = ArchiveInfo::from_file("my_types", "/path/to/file.gdt");
        assert_eq!(info.name(), "my_types");
        assert_eq!(info.file_path(), Some("/path/to/file.gdt"));
        assert!(!info.is_builtin());
        assert!(!info.is_open());
    }

    #[test]
    fn test_config_value_display() {
        assert_eq!(format!("{}", DtMgrConfigValue::Bool(true)), "true");
        assert_eq!(format!("{}", DtMgrConfigValue::Int(42)), "42");
        assert_eq!(
            format!("{}", DtMgrConfigValue::String("hello".into())),
            "hello"
        );
    }
}
