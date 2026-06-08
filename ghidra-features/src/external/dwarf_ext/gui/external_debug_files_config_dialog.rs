//! ExternalDebugFilesConfigDialog -- main configuration dialog for DWARF
//! external debug file providers.
//!
//! Ported from `ghidra.app.util.bin.format.dwarf.external.gui.ExternalDebugFilesConfigDialog`.
//!
//! In the Java version this is a Swing `DialogComponentProvider` that
//! displays a table of debug info providers, buttons to add/remove/reorder
//! them, and a storage location selector.  In Rust we provide:
//!
//! - [`ConfigDialogState`] -- the logical state of the configuration dialog
//! - [`ConfigDialogAction`] -- actions the user can perform
//! - [`ConfigDialogHandler`] -- trait for UI-framework-specific rendering
//!
//! The actual dialog rendering is delegated to a [`ConfigDialogHandler`]
//! implementation.

use std::path::PathBuf;
use std::sync::Arc;

use super::super::build_id_debug_file_provider::BuildIdDebugFileProvider;
use super::super::debug_info_provider::DebugInfoProvider;
use super::super::debug_info_provider_registry::DebugInfoProviderCreatorContext;
use super::super::http_debuginfo_d_provider::HttpDebugInfoDProvider;
use super::super::local_dir_debug_info_d_provider::LocalDirDebugInfoDProvider;
use super::super::local_dir_debug_link_provider::LocalDirDebugLinkProvider;
use super::super::same_dir_debug_info_provider::SameDirDebugInfoProvider;
use super::external_debug_info_provider_table_model::ExternalDebugInfoProviderTableModel;
use super::well_known_debug_provider::WellKnownDebugProvider;

/// The type of location the user wants to add.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddLocationType {
    /// Same directory as the program being analysed.
    SameDir,
    /// Build-id hash-based directory (e.g. `/usr/lib/debug/.build-id`).
    BuildIdDir,
    /// Debug link recursive directory search.
    DebugLinkDir,
    /// Debuginfod cache directory.
    DebugInfoDDir,
    /// HTTP(S) debuginfod server URL.
    DebuginfodUrl,
    /// Import from DEBUGINFOD_URLS environment variable.
    ImportDebuginfodUrls,
}

/// Actions that can be performed on the configuration dialog.
#[derive(Debug, Clone)]
pub enum ConfigDialogAction {
    /// Add a location of the given type with a path/URL.
    AddLocation(AddLocationType, Option<String>),
    /// Delete the provider at the given row index.
    DeleteLocation(usize),
    /// Move the provider at the given row index up or down.
    MoveLocation(usize, isize),
    /// Toggle the enabled state of the provider at the given row index.
    ToggleEnabled(usize),
    /// Refresh the status of all providers.
    RefreshStatus,
    /// Set the storage location.
    SetStorageLocation(PathBuf),
    /// Use the Ghidra cache as the storage location.
    UseGhidraCache,
    /// Save the current configuration.
    Save,
    /// Cancel the dialog.
    Cancel,
    /// Confirm/OK the dialog.
    Ok,
}

/// The logical state of the external debug files configuration dialog.
///
/// This struct holds all the data needed to render the dialog and
/// process user interactions.  It is UI-framework-agnostic.
#[derive(Debug)]
pub struct ConfigDialogState {
    /// The table model holding the list of providers.
    table_model: ExternalDebugInfoProviderTableModel,
    /// The well-known debug providers (loaded from configuration files).
    known_providers: Vec<WellKnownDebugProvider>,
    /// The creator context for instantiating new providers.
    creator_context: DebugInfoProviderCreatorContext,
    /// Path to the local storage directory, if set.
    storage_path: Option<PathBuf>,
    /// Whether the configuration has been changed since last save.
    config_changed: bool,
    /// Whether the dialog was confirmed (OK) vs cancelled.
    confirmed: bool,
}

impl ConfigDialogState {
    /// Creates a new configuration dialog state with default settings.
    pub fn new() -> Self {
        Self {
            table_model: ExternalDebugInfoProviderTableModel::new(),
            known_providers: Vec::new(),
            creator_context: DebugInfoProviderCreatorContext::new(),
            storage_path: None,
            config_changed: false,
            confirmed: false,
        }
    }

    /// Creates a new state with the given creator context.
    pub fn with_context(creator_context: DebugInfoProviderCreatorContext) -> Self {
        Self {
            creator_context,
            ..Self::new()
        }
    }

    /// Loads well-known providers from the given search directories.
    pub fn load_known_providers(&mut self, search_dirs: &[&std::path::Path], file_ext: &str) {
        self.known_providers =
            WellKnownDebugProvider::load_all_from_dirs(search_dirs, file_ext);
    }

    /// Returns a reference to the table model.
    pub fn table_model(&self) -> &ExternalDebugInfoProviderTableModel {
        &self.table_model
    }

    /// Returns a mutable reference to the table model.
    pub fn table_model_mut(&mut self) -> &mut ExternalDebugInfoProviderTableModel {
        &mut self.table_model
    }

    /// Returns the list of well-known providers.
    pub fn known_providers(&self) -> &[WellKnownDebugProvider] {
        &self.known_providers
    }

    /// Returns the storage path.
    pub fn storage_path(&self) -> Option<&std::path::Path> {
        self.storage_path.as_deref()
    }

    /// Returns whether the configuration has changed.
    pub fn is_config_changed(&self) -> bool {
        self.config_changed || self.table_model.is_data_changed()
    }

    /// Sets the config changed flag.
    pub fn set_config_changed(&mut self, changed: bool) {
        self.config_changed = changed;
        self.table_model.set_data_changed(changed);
    }

    /// Returns whether the dialog was confirmed.
    pub fn is_confirmed(&self) -> bool {
        self.confirmed
    }

    /// Sets the storage location path.
    pub fn set_storage_path(&mut self, path: PathBuf) {
        self.storage_path = Some(path);
        self.config_changed = true;
    }

    /// Processes a user action.
    ///
    /// Returns `true` if the dialog should close (Ok or Cancel).
    pub fn handle_action(&mut self, action: ConfigDialogAction) -> bool {
        match action {
            ConfigDialogAction::AddLocation(location_type, value) => {
                self.add_location(location_type, value.as_deref());
                false
            }
            ConfigDialogAction::DeleteLocation(index) => {
                self.table_model.delete_rows(&[index]);
                self.config_changed = true;
                false
            }
            ConfigDialogAction::MoveLocation(index, delta) => {
                self.table_model.move_row(index, delta);
                self.config_changed = true;
                false
            }
            ConfigDialogAction::ToggleEnabled(index) => {
                if let Some(row) = self.table_model.row(index) {
                    let currently_enabled = row.is_enabled();
                    self.table_model.set_row_enabled(index, !currently_enabled);
                }
                false
            }
            ConfigDialogAction::RefreshStatus => {
                // Status refresh is async in the Java version;
                // here we just mark it as a no-op placeholder.
                false
            }
            ConfigDialogAction::SetStorageLocation(path) => {
                self.set_storage_path(path);
                false
            }
            ConfigDialogAction::UseGhidraCache => {
                let provider = LocalDirDebugInfoDProvider::ghidra_cache_instance();
                let cache_path = provider.root_dir().to_path_buf();
                self.set_storage_path(cache_path);
                false
            }
            ConfigDialogAction::Save => {
                self.set_config_changed(false);
                false
            }
            ConfigDialogAction::Cancel => true,
            ConfigDialogAction::Ok => {
                self.confirmed = true;
                true
            }
        }
    }

    /// Adds a new provider of the given type.
    fn add_location(&mut self, location_type: AddLocationType, value: Option<&str>) {
        let provider: Option<Arc<dyn DebugInfoProvider>> = match location_type {
            AddLocationType::SameDir => {
                let dir = self.creator_context.program_dir().map(PathBuf::from);
                Some(Arc::new(SameDirDebugInfoProvider::new(dir)))
            }
            AddLocationType::BuildIdDir => {
                value.and_then(|v| {
                    let path = PathBuf::from(v);
                    if path.is_dir() {
                        Some(Arc::new(BuildIdDebugFileProvider::new(path)) as Arc<dyn DebugInfoProvider>)
                    } else {
                        None
                    }
                })
            }
            AddLocationType::DebugLinkDir => {
                value.and_then(|v| {
                    let path = PathBuf::from(v);
                    if path.is_dir() {
                        Some(Arc::new(LocalDirDebugLinkProvider::new(path)) as Arc<dyn DebugInfoProvider>)
                    } else {
                        None
                    }
                })
            }
            AddLocationType::DebugInfoDDir => {
                value.and_then(|v| {
                    let path = PathBuf::from(v);
                    if path.is_dir() {
                        let provider = LocalDirDebugInfoDProvider::new(path);
                        Some(Arc::new(provider) as Arc<dyn DebugInfoProvider>)
                    } else {
                        None
                    }
                })
            }
            AddLocationType::DebuginfodUrl => {
                value.and_then(|v| {
                    let url = v.trim().to_lowercase();
                    if url.starts_with("http://") || url.starts_with("https://") {
                        HttpDebugInfoDProvider::new(&url)
                            .ok()
                            .map(|p| Arc::new(p) as Arc<dyn DebugInfoProvider>)
                    } else {
                        None
                    }
                })
            }
            AddLocationType::ImportDebuginfodUrls => {
                if let Some(env_str) = value {
                    let urls = parse_debuginfod_urls(env_str);
                    for url in urls {
                        if let Ok(provider) = HttpDebugInfoDProvider::new(&url) {
                            let provider = Arc::new(provider) as Arc<dyn DebugInfoProvider>;
                            self.table_model.add_item(provider);
                        }
                    }
                    return;
                }
                None
            }
        };

        if let Some(p) = provider {
            self.table_model.add_item(p);
        }
    }

    /// Returns the list of available "add location" menu options.
    pub fn add_location_menu_options(&self) -> Vec<AddLocationMenuEntry> {
        let mut options = vec![
            AddLocationMenuEntry {
                label: "Same as Program Directory".to_string(),
                tooltip: Some(
                    "Directory that the program was originally imported from.".to_string(),
                ),
                location_type: AddLocationType::SameDir,
                needs_input: false,
            },
            AddLocationMenuEntry {
                label: "Build-id Directory".to_string(),
                tooltip: Some(
                    "Directory where debug files identified by a build-id hash are stored.\n\
                     e.g. /usr/lib/debug/.build-id"
                        .to_string(),
                ),
                location_type: AddLocationType::BuildIdDir,
                needs_input: true,
            },
            AddLocationMenuEntry {
                label: "Debug Link Directory".to_string(),
                tooltip: Some(
                    "Directory where debug files identified by a debug filename and crc hash \
                     are stored. Searched recursively."
                        .to_string(),
                ),
                location_type: AddLocationType::DebugLinkDir,
                needs_input: true,
            },
            AddLocationMenuEntry {
                label: "Debuginfod Directory".to_string(),
                tooltip: Some("Directory where debuginfod has stored files.".to_string()),
                location_type: AddLocationType::DebugInfoDDir,
                needs_input: true,
            },
            AddLocationMenuEntry {
                label: "Debuginfod URL".to_string(),
                tooltip: Some("HTTP(s) URL that points to a debuginfod server.".to_string()),
                location_type: AddLocationType::DebuginfodUrl,
                needs_input: true,
            },
            AddLocationMenuEntry {
                label: "Import DEBUGINFOD_URLS Env Var".to_string(),
                tooltip: Some(
                    "Adds debuginfod URLs found in the system environment variable.".to_string(),
                ),
                location_type: AddLocationType::ImportDebuginfodUrls,
                needs_input: false,
            },
        ];

        // Add well-known providers
        for provider in &self.known_providers {
            options.push(AddLocationMenuEntry {
                label: provider.location().to_string(),
                tooltip: provider
                    .warning()
                    .map(|w| format!("[from {}] {}", provider.file_origin(), w))
                    .or_else(|| Some(format!("[from {}]", provider.file_origin()))),
                location_type: AddLocationType::DebuginfodUrl,
                needs_input: false,
            });
        }

        options
    }
}

impl Default for ConfigDialogState {
    fn default() -> Self {
        Self::new()
    }
}

/// An entry in the "Add Location" popup menu.
#[derive(Debug, Clone)]
pub struct AddLocationMenuEntry {
    /// The display label.
    pub label: String,
    /// Optional tooltip text.
    pub tooltip: Option<String>,
    /// The type of location to add.
    pub location_type: AddLocationType,
    /// Whether the user needs to provide additional input (path or URL).
    pub needs_input: bool,
}

/// Trait for UI-framework-specific configuration dialog rendering.
///
/// Implementors provide the actual dialog display logic.
pub trait ConfigDialogHandler {
    /// Shows the configuration dialog.
    ///
    /// Returns `true` if the user confirmed (OK), `false` if cancelled.
    fn show(&self, state: &mut ConfigDialogState) -> bool;
}

/// A mock handler for testing.
#[derive(Debug, Clone)]
pub struct MockConfigDialogHandler {
    /// The value to return from `show`.
    result: bool,
}

impl MockConfigDialogHandler {
    /// Creates a handler that simulates OK.
    pub fn confirmed() -> Self {
        Self { result: true }
    }

    /// Creates a handler that simulates Cancel.
    pub fn cancelled() -> Self {
        Self { result: false }
    }
}

impl ConfigDialogHandler for MockConfigDialogHandler {
    fn show(&self, state: &mut ConfigDialogState) -> bool {
        state.confirmed = self.result;
        self.result
    }
}

/// Parses a DEBUGINFOD_URLS environment variable string into individual URLs.
///
/// The string is split on spaces and semicolons.
fn parse_debuginfod_urls(env_string: &str) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut results = Vec::new();

    for part in env_string.split(|c: char| c == ' ' || c == ';') {
        let trimmed = part.trim();
        if !trimmed.is_empty() && seen.insert(trimmed.to_string()) {
            results.push(trimmed.to_string());
        }
    }

    results
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_dialog_state_new() {
        let state = ConfigDialogState::new();
        assert!(state.table_model().is_empty());
        assert!(state.known_providers().is_empty());
        assert!(state.storage_path().is_none());
        assert!(!state.is_config_changed());
        assert!(!state.is_confirmed());
    }

    #[test]
    fn test_config_dialog_state_with_context() {
        let ctx = DebugInfoProviderCreatorContext::with_program_dir(PathBuf::from("/usr/bin"));
        let state = ConfigDialogState::with_context(ctx);
        assert_eq!(
            state.creator_context.program_dir(),
            Some(std::path::Path::new("/usr/bin"))
        );
    }

    #[test]
    fn test_handle_action_cancel() {
        let mut state = ConfigDialogState::new();
        let should_close = state.handle_action(ConfigDialogAction::Cancel);
        assert!(should_close);
        assert!(!state.is_confirmed());
    }

    #[test]
    fn test_handle_action_ok() {
        let mut state = ConfigDialogState::new();
        let should_close = state.handle_action(ConfigDialogAction::Ok);
        assert!(should_close);
        assert!(state.is_confirmed());
    }

    #[test]
    fn test_handle_action_add_same_dir() {
        let ctx = DebugInfoProviderCreatorContext::with_program_dir(PathBuf::from("/usr/bin"));
        let mut state = ConfigDialogState::with_context(ctx);
        let should_close = state.handle_action(ConfigDialogAction::AddLocation(
            AddLocationType::SameDir,
            None,
        ));
        assert!(!should_close);
        assert_eq!(state.table_model().row_count(), 1);
    }

    #[test]
    fn test_handle_action_add_build_id_dir() {
        let mut state = ConfigDialogState::new();
        // Use a real directory that exists on the system
        let should_close = state.handle_action(ConfigDialogAction::AddLocation(
            AddLocationType::BuildIdDir,
            Some("/tmp".to_string()),
        ));
        assert!(!should_close);
        // /tmp exists, so should add
        assert_eq!(state.table_model().row_count(), 1);
    }

    #[test]
    fn test_handle_action_add_build_id_dir_invalid() {
        let mut state = ConfigDialogState::new();
        let should_close = state.handle_action(ConfigDialogAction::AddLocation(
            AddLocationType::BuildIdDir,
            Some("/nonexistent/path".to_string()),
        ));
        assert!(!should_close);
        // Invalid path, should not add
        assert_eq!(state.table_model().row_count(), 0);
    }

    #[test]
    fn test_handle_action_add_debug_link_dir() {
        let mut state = ConfigDialogState::new();
        let should_close = state.handle_action(ConfigDialogAction::AddLocation(
            AddLocationType::DebugLinkDir,
            Some("/tmp".to_string()),
        ));
        assert!(!should_close);
        assert_eq!(state.table_model().row_count(), 1);
    }

    #[test]
    fn test_handle_action_add_url() {
        let mut state = ConfigDialogState::new();
        let should_close = state.handle_action(ConfigDialogAction::AddLocation(
            AddLocationType::DebuginfodUrl,
            Some("https://debuginfod.example.com/".to_string()),
        ));
        assert!(!should_close);
        assert_eq!(state.table_model().row_count(), 1);
    }

    #[test]
    fn test_handle_action_add_url_invalid() {
        let mut state = ConfigDialogState::new();
        let should_close = state.handle_action(ConfigDialogAction::AddLocation(
            AddLocationType::DebuginfodUrl,
            Some("not-a-url".to_string()),
        ));
        assert!(!should_close);
        assert_eq!(state.table_model().row_count(), 0);
    }

    #[test]
    fn test_handle_action_delete() {
        let ctx = DebugInfoProviderCreatorContext::with_program_dir(PathBuf::from("/usr/bin"));
        let mut state = ConfigDialogState::with_context(ctx);
        state.handle_action(ConfigDialogAction::AddLocation(
            AddLocationType::SameDir,
            None,
        ));
        assert_eq!(state.table_model().row_count(), 1);

        state.handle_action(ConfigDialogAction::DeleteLocation(0));
        assert_eq!(state.table_model().row_count(), 0);
    }

    #[test]
    fn test_handle_action_move() {
        let ctx = DebugInfoProviderCreatorContext::with_program_dir(PathBuf::from("/usr/bin"));
        let mut state = ConfigDialogState::with_context(ctx);
        state.handle_action(ConfigDialogAction::AddLocation(
            AddLocationType::SameDir,
            None,
        ));
        state.handle_action(ConfigDialogAction::AddLocation(
            AddLocationType::BuildIdDir,
            Some("/tmp".to_string()),
        ));
        assert_eq!(state.table_model().row_count(), 2);

        // Move first row down
        state.handle_action(ConfigDialogAction::MoveLocation(0, 1));
        // Rows should be swapped
        assert_eq!(state.table_model().row_count(), 2);
    }

    #[test]
    fn test_handle_action_save() {
        let mut state = ConfigDialogState::new();
        state.config_changed = true;
        state.table_model.set_data_changed(true);

        state.handle_action(ConfigDialogAction::Save);
        assert!(!state.is_config_changed());
    }

    #[test]
    fn test_handle_action_set_storage() {
        let mut state = ConfigDialogState::new();
        state.handle_action(ConfigDialogAction::SetStorageLocation(PathBuf::from(
            "/tmp/debug",
        )));
        assert_eq!(
            state.storage_path(),
            Some(std::path::Path::new("/tmp/debug"))
        );
        assert!(state.is_config_changed());
    }

    #[test]
    fn test_add_location_menu_options() {
        let state = ConfigDialogState::new();
        let options = state.add_location_menu_options();
        assert!(!options.is_empty());

        // Should have at least the 6 built-in options
        assert!(options.len() >= 6);

        // Check first option
        assert_eq!(options[0].label, "Same as Program Directory");
        assert!(!options[0].needs_input);

        // Check build-id option
        assert_eq!(options[1].label, "Build-id Directory");
        assert!(options[1].needs_input);
    }

    #[test]
    fn test_add_location_menu_with_known_providers() {
        let mut state = ConfigDialogState::new();
        state.known_providers.push(WellKnownDebugProvider::new(
            "https://debuginfod.example.com/".to_string(),
            "Internet".to_string(),
            None,
            "test.debuginfod_urls".to_string(),
        ));

        let options = state.add_location_menu_options();
        // Should have 6 built-in + 1 well-known
        assert_eq!(options.len(), 7);
        assert_eq!(options[6].label, "https://debuginfod.example.com/");
    }

    #[test]
    fn test_parse_debuginfod_urls() {
        let urls = parse_debuginfod_urls("https://a.com https://b.com;https://c.com");
        assert_eq!(urls.len(), 3);
        assert_eq!(urls[0], "https://a.com");
        assert_eq!(urls[1], "https://b.com");
        assert_eq!(urls[2], "https://c.com");
    }

    #[test]
    fn test_parse_debuginfod_urls_dedup() {
        let urls = parse_debuginfod_urls("https://a.com https://a.com");
        assert_eq!(urls.len(), 1);
    }

    #[test]
    fn test_parse_debuginfod_urls_empty() {
        let urls = parse_debuginfod_urls("");
        assert!(urls.is_empty());
    }

    #[test]
    fn test_parse_debuginfod_urls_whitespace() {
        let urls = parse_debuginfod_urls("  https://a.com   https://b.com  ");
        assert_eq!(urls.len(), 2);
    }

    #[test]
    fn test_mock_handler_confirmed() {
        let handler = MockConfigDialogHandler::confirmed();
        let mut state = ConfigDialogState::new();
        let result = handler.show(&mut state);
        assert!(result);
        assert!(state.is_confirmed());
    }

    #[test]
    fn test_mock_handler_cancelled() {
        let handler = MockConfigDialogHandler::cancelled();
        let mut state = ConfigDialogState::new();
        let result = handler.show(&mut state);
        assert!(!result);
        assert!(!state.is_confirmed());
    }

    #[test]
    fn test_config_dialog_state_default() {
        let state = ConfigDialogState::default();
        assert!(state.table_model().is_empty());
    }
}
