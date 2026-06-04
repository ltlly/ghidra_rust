//! Decompiler plugin core types.
//!
//! Port of Ghidra's `ghidra.app.plugin.core.decompile` package.
//!
//! Provides the plugin-level types for the decompiler integration,
//! including the decompiler plugin, its provider, action context, and
//! the clipboard/overlay support types.

use super::component::{
    ClangHighlightController, ClangLayoutController, ClangTextField,
    DecompileData, DecompilerController, TokenHighlightColors,
};
use super::location::DecompilerLocation;

/// The main decompiler plugin type.
///
/// Manages decompiler providers (connected and disconnected instances),
/// registers actions, and coordinates with the Ghidra tool system.
///
/// In Ghidra, this is a `Plugin` that lives in the tool's plugin registry.
/// In the Rust port, it serves as the central coordinator for decompiler
/// functionality without a Swing dependency.
#[derive(Debug)]
pub struct DecompilerPlugin {
    /// The primary (connected) decompiler provider.
    pub provider: Option<DecompilerProvider>,
    /// Additional disconnected / snapshot providers.
    pub disconnected_providers: Vec<DecompilerProvider>,
    /// Whether the plugin has been disposed.
    pub disposed: bool,
    /// The name of this plugin.
    pub name: String,
}

impl DecompilerPlugin {
    /// Create a new DecompilerPlugin.
    pub fn new() -> Self {
        Self {
            provider: None,
            disconnected_providers: Vec::new(),
            disposed: false,
            name: "Decompiler".to_string(),
        }
    }

    /// Set the primary (connected) provider.
    pub fn set_provider(&mut self, provider: DecompilerProvider) {
        self.provider = Some(provider);
    }

    /// Get a reference to the primary provider.
    pub fn get_provider(&self) -> Option<&DecompilerProvider> {
        self.provider.as_ref()
    }

    /// Create a disconnected (snapshot) decompiler provider.
    pub fn create_disconnected_provider(&mut self) -> &mut DecompilerProvider {
        let provider = DecompilerProvider::new_disconnected();
        self.disconnected_providers.push(provider);
        self.disconnected_providers.last_mut().unwrap()
    }

    /// Get the number of active providers (connected + disconnected).
    pub fn provider_count(&self) -> usize {
        let connected = if self.provider.is_some() { 1 } else { 0 };
        connected + self.disconnected_providers.len()
    }

    /// Dispose of the plugin and all providers.
    pub fn dispose(&mut self) {
        self.disposed = true;
        if let Some(ref mut p) = self.provider {
            p.dispose();
        }
        for p in &mut self.disconnected_providers {
            p.dispose();
        }
    }
}

impl Default for DecompilerPlugin {
    fn default() -> Self {
        Self::new()
    }
}

/// A decompiler provider manages a single decompiler view instance.
///
/// Contains the decompiler controller, panel data, and display state.
/// Connected providers are linked to the tool; disconnected providers
/// are snapshots that don't receive program changes.
#[derive(Debug)]
pub struct DecompilerProvider {
    /// The decompiler controller.
    pub controller: DecompilerController,
    /// The highlight controller.
    pub highlights: ClangHighlightController,
    /// The layout controller.
    pub layout: ClangLayoutController,
    /// The text field (for rename/retype operations).
    pub text_field: Option<ClangTextField>,
    /// The highlight colors.
    pub colors: TokenHighlightColors,
    /// Whether this is a disconnected provider.
    pub disconnected: bool,
    /// Whether the provider has been disposed.
    pub disposed: bool,
    /// The display name for this provider.
    pub display_name: String,
}

impl DecompilerProvider {
    /// Create a new connected decompiler provider.
    pub fn new() -> Self {
        Self {
            controller: DecompilerController::new(),
            highlights: ClangHighlightController::new(),
            layout: ClangLayoutController::new(),
            text_field: None,
            colors: TokenHighlightColors::default(),
            disconnected: false,
            disposed: false,
            display_name: "Decompiler".to_string(),
        }
    }

    /// Create a new disconnected (snapshot) decompiler provider.
    pub fn new_disconnected() -> Self {
        Self {
            controller: DecompilerController::new(),
            highlights: ClangHighlightController::new(),
            layout: ClangLayoutController::new(),
            text_field: None,
            colors: TokenHighlightColors::default(),
            disconnected: true,
            disposed: false,
            display_name: "Decompiler (snapshot)".to_string(),
        }
    }

    /// Whether this provider is connected to the tool.
    pub fn is_connected(&self) -> bool {
        !self.disconnected
    }

    /// Set the decompile data.
    pub fn set_decompile_data(&mut self, data: DecompileData) {
        self.controller.set_data(data);
    }

    /// Get the current function entry.
    pub fn current_function(&self) -> Option<u64> {
        self.controller.current_function()
    }

    /// Activate a text field for editing.
    pub fn activate_text_field(&mut self, node_id: super::clang_node::ClangNodeId, text: String) {
        let mut tf = ClangTextField::new(node_id, text);
        tf.activate();
        self.text_field = Some(tf);
    }

    /// Deactivate the text field.
    pub fn deactivate_text_field(&mut self) {
        if let Some(ref mut tf) = self.text_field {
            tf.deactivate();
        }
        self.text_field = None;
    }

    /// Dispose of this provider.
    pub fn dispose(&mut self) {
        self.disposed = true;
        self.controller.dispose();
        self.highlights.clear_all();
        self.text_field = None;
    }
}

impl Default for DecompilerProvider {
    fn default() -> Self {
        Self::new()
    }
}

/// Action context for decompiler actions.
///
/// Provides the context that decompiler actions (rename, retype, etc.)
/// need to perform their operations. Contains references to the current
/// token, its location, and the surrounding context.
#[derive(Debug, Clone)]
pub struct DecompilerActionContext {
    /// The token text at the cursor.
    pub token_text: String,
    /// The syntax type of the token.
    pub syntax_type: i32,
    /// The address of the token.
    pub address: u64,
    /// The function entry point.
    pub function_entry: u64,
    /// The function name.
    pub function_name: Option<String>,
    /// The ClangNodeId of the token.
    pub node_id: super::clang_node::ClangNodeId,
    /// The decompiler location (if known).
    pub location: Option<DecompilerLocation>,
    /// Whether the context represents a valid selection.
    pub valid: bool,
}

impl DecompilerActionContext {
    /// Create a new action context.
    pub fn new(
        token_text: String,
        syntax_type: i32,
        address: u64,
        function_entry: u64,
        node_id: super::clang_node::ClangNodeId,
    ) -> Self {
        Self {
            token_text,
            syntax_type,
            address,
            function_entry,
            function_name: None,
            node_id,
            location: None,
            valid: true,
        }
    }

    /// Whether this context has a valid token selected.
    pub fn has_valid_token(&self) -> bool {
        self.valid && !self.token_text.is_empty()
    }

    /// Get the function entry address.
    pub fn get_function_entry(&self) -> u64 {
        self.function_entry
    }

    /// Set the function name.
    pub fn set_function_name(&mut self, name: Option<String>) {
        self.function_name = name;
    }
}

/// The cursor position in the decompiler display.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecompilerCursorPosition {
    /// The line number (0-based).
    pub line: usize,
    /// The column number (0-based).
    pub column: usize,
    /// The character offset from the start of the line.
    pub char_offset: usize,
}

impl DecompilerCursorPosition {
    /// Create a new cursor position.
    pub fn new(line: usize, column: usize, char_offset: usize) -> Self {
        Self {
            line,
            column,
            char_offset,
        }
    }

    /// Create a position at the origin.
    pub fn origin() -> Self {
        Self::new(0, 0, 0)
    }
}

impl Default for DecompilerCursorPosition {
    fn default() -> Self {
        Self::origin()
    }
}

/// Search location in the decompiler display.
#[derive(Debug, Clone)]
pub struct DecompilerSearchLocation {
    /// The text being searched for.
    pub search_text: String,
    /// The line where the match was found.
    pub line: usize,
    /// The column where the match starts.
    pub column: usize,
    /// The length of the match.
    pub match_length: usize,
    /// Whether the search was case-sensitive.
    pub case_sensitive: bool,
}

impl DecompilerSearchLocation {
    /// Create a new search location.
    pub fn new(
        search_text: String,
        line: usize,
        column: usize,
        match_length: usize,
        case_sensitive: bool,
    ) -> Self {
        Self {
            search_text,
            line,
            column,
            match_length,
            case_sensitive,
        }
    }

    /// Get the end column of the match.
    pub fn end_column(&self) -> usize {
        self.column + self.match_length
    }
}

/// Results from a decompiler search operation.
#[derive(Debug, Clone, Default)]
pub struct DecompilerSearchResults {
    /// All search locations found.
    pub locations: Vec<DecompilerSearchLocation>,
    /// The index of the current (focused) result.
    pub current_index: usize,
    /// The search text.
    pub search_text: String,
}

impl DecompilerSearchResults {
    /// Create a new empty search results.
    pub fn new(search_text: String) -> Self {
        Self {
            locations: Vec::new(),
            current_index: 0,
            search_text,
        }
    }

    /// Add a result location.
    pub fn add_location(&mut self, location: DecompilerSearchLocation) {
        self.locations.push(location);
    }

    /// Get the number of results.
    pub fn count(&self) -> usize {
        self.locations.len()
    }

    /// Get the current result.
    pub fn current(&self) -> Option<&DecompilerSearchLocation> {
        self.locations.get(self.current_index)
    }

    /// Move to the next result.
    pub fn next(&mut self) -> Option<&DecompilerSearchLocation> {
        if self.locations.is_empty() {
            return None;
        }
        self.current_index = (self.current_index + 1) % self.locations.len();
        self.current()
    }

    /// Move to the previous result.
    pub fn previous(&mut self) -> Option<&DecompilerSearchLocation> {
        if self.locations.is_empty() {
            return None;
        }
        self.current_index = if self.current_index == 0 {
            self.locations.len() - 1
        } else {
            self.current_index - 1
        };
        self.current()
    }

    /// Whether there are any results.
    pub fn is_empty(&self) -> bool {
        self.locations.is_empty()
    }
}

/// Metadata about a decompiler action.
#[derive(Debug, Clone)]
pub struct ActionMetadata {
    /// The action name.
    pub name: String,
    /// The action description.
    pub description: String,
    /// The key binding (if any).
    pub key_binding: Option<String>,
    /// The menu path.
    pub menu_path: Option<String>,
    /// The action group.
    pub group: String,
}

impl ActionMetadata {
    /// Create new action metadata.
    pub fn new(name: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            key_binding: None,
            menu_path: None,
            group: "Decompiler".to_string(),
        }
    }

    /// Set the key binding.
    pub fn with_key_binding(mut self, binding: impl Into<String>) -> Self {
        self.key_binding = Some(binding.into());
        self
    }

    /// Set the menu path.
    pub fn with_menu_path(mut self, path: impl Into<String>) -> Self {
        self.menu_path = Some(path.into());
        self
    }

    /// Set the action group.
    pub fn with_group(mut self, group: impl Into<String>) -> Self {
        self.group = group.into();
        self
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decompiler_plugin_new() {
        let plugin = DecompilerPlugin::new();
        assert!(!plugin.disposed);
        assert_eq!(plugin.provider_count(), 0);
    }

    #[test]
    fn test_decompiler_plugin_set_provider() {
        let mut plugin = DecompilerPlugin::new();
        let provider = DecompilerProvider::new();
        plugin.set_provider(provider);
        assert_eq!(plugin.provider_count(), 1);
        assert!(plugin.get_provider().is_some());
    }

    #[test]
    fn test_decompiler_plugin_disconnected_provider() {
        let mut plugin = DecompilerPlugin::new();
        plugin.create_disconnected_provider();
        assert_eq!(plugin.provider_count(), 1);
    }

    #[test]
    fn test_decompiler_plugin_dispose() {
        let mut plugin = DecompilerPlugin::new();
        plugin.set_provider(DecompilerProvider::new());
        plugin.dispose();
        assert!(plugin.disposed);
    }

    #[test]
    fn test_decompiler_provider_new() {
        let provider = DecompilerProvider::new();
        assert!(provider.is_connected());
        assert!(!provider.disposed);
    }

    #[test]
    fn test_decompiler_provider_disconnected() {
        let provider = DecompilerProvider::new_disconnected();
        assert!(!provider.is_connected());
    }

    #[test]
    fn test_decompiler_provider_set_data() {
        let mut provider = DecompilerProvider::new();
        let data = DecompileData::new(0x1000);
        provider.set_decompile_data(data);
        assert_eq!(provider.current_function(), Some(0x1000));
    }

    #[test]
    fn test_decompiler_provider_text_field() {
        let mut provider = DecompilerProvider::new();
        provider.activate_text_field(1, "old_name".to_string());
        assert!(provider.text_field.is_some());
        provider.deactivate_text_field();
        assert!(provider.text_field.is_none());
    }

    #[test]
    fn test_action_context() {
        let ctx = DecompilerActionContext::new(
            "main".to_string(),
            0,
            0x1000,
            0x1000,
            1,
        );
        assert!(ctx.has_valid_token());
        assert_eq!(ctx.get_function_entry(), 0x1000);
    }

    #[test]
    fn test_action_context_empty_token() {
        let ctx = DecompilerActionContext::new(
            String::new(),
            0,
            0x1000,
            0x1000,
            1,
        );
        assert!(!ctx.has_valid_token());
    }

    #[test]
    fn test_cursor_position() {
        let pos = DecompilerCursorPosition::new(5, 10, 42);
        assert_eq!(pos.line, 5);
        assert_eq!(pos.column, 10);
        assert_eq!(pos.char_offset, 42);
    }

    #[test]
    fn test_cursor_position_origin() {
        let pos = DecompilerCursorPosition::origin();
        assert_eq!(pos.line, 0);
        assert_eq!(pos.column, 0);
    }

    #[test]
    fn test_search_location() {
        let loc = DecompilerSearchLocation::new(
            "foo".to_string(),
            5,
            10,
            3,
            true,
        );
        assert_eq!(loc.end_column(), 13);
    }

    #[test]
    fn test_search_results_navigation() {
        let mut results = DecompilerSearchResults::new("test".to_string());
        results.add_location(DecompilerSearchLocation::new("test".to_string(), 0, 0, 4, true));
        results.add_location(DecompilerSearchLocation::new("test".to_string(), 1, 5, 4, true));
        results.add_location(DecompilerSearchLocation::new("test".to_string(), 2, 10, 4, true));
        assert_eq!(results.count(), 3);

        // Navigate forward
        let cur = results.next().unwrap();
        assert_eq!(cur.line, 1);

        let cur = results.next().unwrap();
        assert_eq!(cur.line, 2);

        // Wrap around
        let cur = results.next().unwrap();
        assert_eq!(cur.line, 0);

        // Navigate backward
        let cur = results.previous().unwrap();
        assert_eq!(cur.line, 2);
    }

    #[test]
    fn test_search_results_empty() {
        let mut results = DecompilerSearchResults::new("foo".to_string());
        assert!(results.is_empty());
        assert!(results.next().is_none());
        assert!(results.previous().is_none());
        assert!(results.current().is_none());
    }

    #[test]
    fn test_action_metadata() {
        let meta = ActionMetadata::new("Rename", "Rename a function or variable")
            .with_key_binding("Ctrl+R")
            .with_menu_path("Edit/Rename")
            .with_group("Editing");
        assert_eq!(meta.name, "Rename");
        assert_eq!(meta.key_binding, Some("Ctrl+R".to_string()));
        assert_eq!(meta.menu_path, Some("Edit/Rename".to_string()));
        assert_eq!(meta.group, "Editing");
    }
}
