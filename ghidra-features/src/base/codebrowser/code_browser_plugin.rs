//! Code Browser Plugin -- the main program listing display window.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin`
//! and `ghidra.app.plugin.core.codebrowser.AbstractCodeBrowserPlugin`.
//!
//! This is the primary plugin that provides the code listing view where users
//! interact with disassembly, data, and other program information. It manages
//! the connected (primary) and disconnected (cloned) providers, handles
//! navigation, selection, highlighting, service registration, and plugin
//! event dispatch.
//!
//! # Architecture
//!
//! ```text
//! CodeBrowserPlugin
//!   ├── CodeBrowserProvider (connected / primary)
//!   ├── Vec<CodeBrowserProvider> (disconnected / clones)
//!   ├── EventDispatcher (plugin event bus)
//!   ├── NavigationManager (back/forward/go-to)
//!   └── SelectionManager (address range selection)
//! ```
//!
//! # Example
//!
//! ```
//! use ghidra_features::base::codebrowser::code_browser_plugin::CodeBrowserPlugin;
//!
//! let mut plugin = CodeBrowserPlugin::new("CodeBrowser");
//! plugin.init();
//! assert_eq!(plugin.name(), "CodeBrowser");
//!
//! // Navigate to an address
//! plugin.go_to("0x401000");
//! assert_eq!(plugin.connected_provider().current_address(), Some("0x401000"));
//! ```

use std::collections::HashMap;
use std::fmt;

// ---------------------------------------------------------------------------
// Plugin status and metadata
// ---------------------------------------------------------------------------

/// Plugin lifecycle status.
///
/// Ported from Ghidra's `PluginStatus`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginStatus {
    /// Plugin is released and stable.
    Released,
    /// Plugin is in beta.
    Beta,
    /// Plugin is unstable/experimental.
    Unstable,
}

/// Metadata about a plugin.
///
/// Ported from Ghidra's `@PluginInfo` annotation.
#[derive(Debug, Clone)]
pub struct PluginInfo {
    /// Plugin status.
    pub status: PluginStatus,
    /// Package name.
    pub package_name: String,
    /// Category.
    pub category: String,
    /// Short description.
    pub short_description: String,
    /// Full description.
    pub description: String,
}

impl Default for PluginInfo {
    fn default() -> Self {
        Self {
            status: PluginStatus::Released,
            package_name: "Core".to_string(),
            category: "Code Viewer".to_string(),
            short_description: "Code Viewer".to_string(),
            description: "This plugin provides the main program listing display window. \
                It also includes the header component which allows the various \
                program fields to be arranged as desired.  In addition, this plugin \
                provides the CodeViewerService which allows other plugins to extend \
                the basic functionality to include such features as flow arrows, \
                margin markers and difference tracking."
                .to_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// Plugin events
// ---------------------------------------------------------------------------

/// Events that the code browser plugin can produce or consume.
///
/// Ported from Ghidra's plugin event types
/// (`ProgramLocationPluginEvent`, `ProgramSelectionPluginEvent`,
/// `ProgramHighlightPluginEvent`, `ProgramActivatedPluginEvent`,
/// `ProgramClosedPluginEvent`, `ViewChangedPluginEvent`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PluginEvent {
    /// A program was activated (opened and made current).
    ProgramActivated {
        /// Name of the activated program.
        program_name: String,
    },
    /// A program was closed.
    ProgramClosed {
        /// Name of the closed program.
        program_name: String,
    },
    /// The cursor location changed.
    ProgramLocation {
        /// The address (hex string).
        address: String,
        /// Row in the listing.
        row: usize,
        /// Column in the listing.
        col: usize,
    },
    /// The address selection changed.
    ProgramSelection {
        /// Selected address ranges as (start, end) hex string pairs.
        ranges: Vec<(String, String)>,
    },
    /// The highlight range changed.
    ProgramHighlight {
        /// Highlighted address range (start, end) as hex strings.
        range: Option<(String, String)>,
    },
    /// The view address set changed.
    ViewChanged {
        /// Number of address ranges in the new view.
        range_count: usize,
    },
}

// ---------------------------------------------------------------------------
// CodeBrowserProvider -- a single listing view
// ---------------------------------------------------------------------------

/// A provider for the code browser listing view.
///
/// Each provider represents a single listing window (either connected/primary
/// or disconnected/clone).  Manages navigation history, cursor position,
/// and the current program.
///
/// Ported from Ghidra's `CodeViewerProvider`.
#[derive(Debug)]
pub struct CodeBrowserProvider {
    /// Provider name.
    name: String,
    /// Current address as a hex string.
    current_address: Option<String>,
    /// Whether this is the connected (primary) provider.
    connected: bool,
    /// Current program name.
    program: Option<String>,
    /// Address history for back/forward navigation.
    history: Vec<String>,
    /// Current position in history.
    history_index: usize,
    /// Selection ranges as (start, end) hex string pairs.
    selection: Vec<(String, String)>,
    /// Highlight range as (start, end) hex string pair.
    highlight: Option<(String, String)>,
    /// Pending events to be dispatched.
    pending_events: Vec<PluginEvent>,
}

impl CodeBrowserProvider {
    /// Creates a new provider.
    pub fn new(name: impl Into<String>, connected: bool) -> Self {
        Self {
            name: name.into(),
            current_address: None,
            connected,
            program: None,
            history: Vec::new(),
            history_index: 0,
            selection: Vec::new(),
            highlight: None,
            pending_events: Vec::new(),
        }
    }

    /// Returns the provider name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the current address.
    pub fn current_address(&self) -> Option<&str> {
        self.current_address.as_deref()
    }

    /// Navigates to the given address.
    ///
    /// Truncates any forward history and pushes the new address.
    /// Emits a `ProgramLocation` event if connected.
    pub fn go_to(&mut self, address: impl Into<String>) {
        let addr = address.into();
        // Truncate forward history
        self.history.truncate(self.history_index);
        self.history.push(addr.clone());
        self.history_index = self.history.len();
        self.current_address = Some(addr.clone());

        if self.connected {
            self.pending_events.push(PluginEvent::ProgramLocation {
                address: addr,
                row: 0,
                col: 0,
            });
        }
    }

    /// Navigates back in history.
    pub fn go_back(&mut self) -> bool {
        if self.history_index > 1 {
            self.history_index -= 1;
            let addr = self.history.get(self.history_index - 1).cloned();
            self.current_address = addr;
            true
        } else {
            false
        }
    }

    /// Navigates forward in history.
    pub fn go_forward(&mut self) -> bool {
        if self.history_index < self.history.len() {
            let addr = self.history.get(self.history_index).cloned();
            self.current_address = addr;
            self.history_index += 1;
            true
        } else {
            false
        }
    }

    /// Returns whether this is the connected (primary) provider.
    pub fn is_connected(&self) -> bool {
        self.connected
    }

    /// Sets the current program.
    pub fn set_program(&mut self, program: Option<String>) {
        self.program = program;
    }

    /// Returns the current program name.
    pub fn program(&self) -> Option<&str> {
        self.program.as_deref()
    }

    /// Sets the selection ranges.
    pub fn set_selection(&mut self, ranges: Vec<(String, String)>) {
        self.selection = ranges;
    }

    /// Returns the selection ranges.
    pub fn selection(&self) -> &[(String, String)] {
        &self.selection
    }

    /// Returns whether there is an active selection.
    pub fn has_selection(&self) -> bool {
        !self.selection.is_empty()
    }

    /// Sets the highlight range.
    pub fn set_highlight(&mut self, range: Option<(String, String)>) {
        self.highlight = range;
        if self.connected {
            self.pending_events.push(PluginEvent::ProgramHighlight {
                range: self.highlight.clone(),
            });
        }
    }

    /// Returns the highlight range.
    pub fn highlight(&self) -> Option<&(String, String)> {
        self.highlight.as_ref()
    }

    /// Drains and returns all pending events.
    pub fn drain_events(&mut self) -> Vec<PluginEvent> {
        std::mem::take(&mut self.pending_events)
    }

    /// Clears the provider state.
    pub fn clear(&mut self) {
        self.current_address = None;
        self.history.clear();
        self.history_index = 0;
        self.selection.clear();
        self.highlight = None;
    }
}

// ---------------------------------------------------------------------------
// CodeBrowserPlugin -- the main plugin
// ---------------------------------------------------------------------------

/// A plugin option value.
#[derive(Debug, Clone)]
pub enum PluginOptionValue {
    /// Boolean option.
    Bool(bool),
    /// Integer option.
    Int(i32),
    /// String option.
    String(String),
    /// Color option (ARGB as u32).
    Color(u32),
}

impl fmt::Display for PluginOptionValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bool(v) => write!(f, "{}", v),
            Self::Int(v) => write!(f, "{}", v),
            Self::String(v) => write!(f, "{}", v),
            Self::Color(v) => write!(f, "#{:08X}", v),
        }
    }
}

/// The code browser plugin.
///
/// Manages the connected (primary) and disconnected (cloned) providers,
/// navigation, selection, highlighting, event dispatch, and plugin options.
///
/// This is the Rust port of Ghidra's `AbstractCodeBrowserPlugin` and
/// `CodeBrowserPlugin` Java classes.
#[derive(Debug)]
pub struct CodeBrowserPlugin {
    /// The plugin name.
    name: String,
    /// The primary (connected) provider.
    connected_provider: CodeBrowserProvider,
    /// Disconnected (cloned) providers.
    disconnected_providers: Vec<CodeBrowserProvider>,
    /// The current program name.
    current_program: Option<String>,
    /// Whether the plugin is initialized.
    initialized: bool,
    /// Whether the plugin is disposed.
    disposed: bool,
    /// Plugin options.
    options: HashMap<String, PluginOptionValue>,
    /// Plugin info.
    info: PluginInfo,
    /// Accumulated events from all providers.
    event_log: Vec<PluginEvent>,
}

impl CodeBrowserPlugin {
    /// Creates a new code browser plugin.
    pub fn new(name: impl Into<String>) -> Self {
        let name = name.into();
        Self {
            connected_provider: CodeBrowserProvider::new(
                format!("{}_Primary", name),
                true,
            ),
            name,
            disconnected_providers: Vec::new(),
            current_program: None,
            initialized: false,
            disposed: false,
            options: HashMap::new(),
            info: PluginInfo::default(),
            event_log: Vec::new(),
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
    }

    /// Disposes the plugin and releases resources.
    pub fn dispose(&mut self) {
        if self.disposed {
            return;
        }
        self.disposed = true;
        self.connected_provider.clear();
        self.disconnected_providers.clear();
    }

    /// Returns whether the plugin is initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Returns whether the plugin is disposed.
    pub fn is_disposed(&self) -> bool {
        self.disposed
    }

    /// Returns a reference to the connected (primary) provider.
    pub fn connected_provider(&self) -> &CodeBrowserProvider {
        &self.connected_provider
    }

    /// Returns a mutable reference to the connected (primary) provider.
    pub fn connected_provider_mut(&mut self) -> &mut CodeBrowserProvider {
        &mut self.connected_provider
    }

    /// Returns the number of disconnected providers.
    pub fn disconnected_provider_count(&self) -> usize {
        self.disconnected_providers.len()
    }

    /// Returns a reference to a disconnected provider by index.
    pub fn disconnected_provider(&self, index: usize) -> Option<&CodeBrowserProvider> {
        self.disconnected_providers.get(index)
    }

    /// Creates a new disconnected (cloned) provider.
    ///
    /// The new provider inherits the current program from the plugin.
    pub fn clone_provider(&mut self) -> usize {
        let index = self.disconnected_providers.len();
        let name = format!("{}_Clone_{}", self.name, index);
        let mut provider = CodeBrowserProvider::new(name, false);
        provider.set_program(self.current_program.clone());
        self.disconnected_providers.push(provider);
        index
    }

    /// Removes a disconnected provider by index.
    pub fn remove_disconnected_provider(&mut self, index: usize) -> Option<CodeBrowserProvider> {
        if index < self.disconnected_providers.len() {
            Some(self.disconnected_providers.remove(index))
        } else {
            None
        }
    }

    /// Sets the current program for all providers.
    ///
    /// Emits a `ProgramActivated` event.
    pub fn set_program(&mut self, program: Option<String>) {
        let old = self.current_program.replace(program.clone().unwrap_or_default());
        let new_name = program.clone().unwrap_or_default();

        // Emit program closed for the old program
        if let Some(ref old_name) = old {
            if old_name != &new_name {
                self.event_log.push(PluginEvent::ProgramClosed {
                    program_name: old_name.clone(),
                });
            }
        }

        // Emit program activated for the new program
        if let Some(ref p) = program {
            self.event_log.push(PluginEvent::ProgramActivated {
                program_name: p.clone(),
            });
        }

        self.current_program = program.clone();
        self.connected_provider.set_program(program.clone());
        for provider in &mut self.disconnected_providers {
            provider.set_program(program.clone());
        }
    }

    /// Returns the current program name.
    pub fn current_program(&self) -> Option<&str> {
        self.current_program.as_deref()
    }

    /// Navigates the connected provider to the given address.
    pub fn go_to(&mut self, address: impl Into<String>) {
        self.connected_provider.go_to(address);
    }

    /// Navigates the connected provider back.
    pub fn go_back(&mut self) -> bool {
        self.connected_provider.go_back()
    }

    /// Navigates the connected provider forward.
    pub fn go_forward(&mut self) -> bool {
        self.connected_provider.go_forward()
    }

    /// Sets the selection on the connected provider.
    ///
    /// Emits a `ProgramSelection` event.
    pub fn set_selection(&mut self, ranges: Vec<(String, String)>) {
        self.connected_provider.set_selection(ranges.clone());
        self.event_log.push(PluginEvent::ProgramSelection { ranges });
    }

    /// Sets the highlight on the connected provider.
    pub fn set_highlight(&mut self, range: Option<(String, String)>) {
        self.connected_provider.set_highlight(range);
    }

    /// Processes a plugin event.
    ///
    /// Ported from `CodeBrowserPlugin.processEvent()`.
    pub fn process_event(&mut self, event: PluginEvent) {
        match &event {
            PluginEvent::ProgramActivated { program_name } => {
                self.set_program(Some(program_name.clone()));
            }
            PluginEvent::ProgramClosed { program_name } => {
                // Remove disconnected providers that had this program
                self.disconnected_providers.retain(|p| {
                    p.program().map_or(true, |p_name| p_name != program_name)
                });
            }
            PluginEvent::ProgramLocation { address, row, col } => {
                self.connected_provider.go_to(address.clone());
            }
            PluginEvent::ProgramSelection { ranges } => {
                self.connected_provider.set_selection(ranges.clone());
            }
            PluginEvent::ProgramHighlight { range } => {
                self.connected_provider.set_highlight(range.clone());
            }
            PluginEvent::ViewChanged { .. } => {
                // View changes are handled by the view manager
            }
        }
        self.event_log.push(event);
    }

    /// Drains and returns all pending events from all providers.
    pub fn drain_events(&mut self) -> Vec<PluginEvent> {
        let mut events = std::mem::take(&mut self.event_log);
        events.append(&mut self.connected_provider.drain_events());
        for provider in &mut self.disconnected_providers {
            events.append(&mut provider.drain_events());
        }
        events
    }

    /// Returns a reference to the plugin info.
    pub fn info(&self) -> &PluginInfo {
        &self.info
    }

    /// Sets a plugin option.
    pub fn set_option(&mut self, key: impl Into<String>, value: PluginOptionValue) {
        self.options.insert(key.into(), value);
    }

    /// Gets a plugin option.
    pub fn get_option(&self, key: &str) -> Option<&PluginOptionValue> {
        self.options.get(key)
    }

    /// Gets a boolean option with a default value.
    pub fn get_bool_option(&self, key: &str, default: bool) -> bool {
        match self.options.get(key) {
            Some(PluginOptionValue::Bool(v)) => *v,
            _ => default,
        }
    }

    /// Gets an integer option with a default value.
    pub fn get_int_option(&self, key: &str, default: i32) -> i32 {
        match self.options.get(key) {
            Some(PluginOptionValue::Int(v)) => *v,
            _ => default,
        }
    }

    /// Gets a string option with a default value.
    pub fn get_string_option<'a>(&'a self, key: &str, default: &'a str) -> &'a str {
        match self.options.get(key) {
            Some(PluginOptionValue::String(v)) => v,
            _ => default,
        }
    }

    /// Returns the number of plugin options.
    pub fn option_count(&self) -> usize {
        self.options.len()
    }

    /// Closes the given program, removing any disconnected providers that
    /// had it open.
    ///
    /// Ported from `CodeBrowserPlugin.programClosed()`.
    pub fn program_closed(&mut self, program_name: &str) {
        self.disconnected_providers.retain(|p| {
            p.program().map_or(true, |p_name| p_name != program_name)
        });
        if self.current_program.as_deref() == Some(program_name) {
            self.current_program = None;
            self.connected_provider.clear();
        }
    }
}

impl Default for CodeBrowserPlugin {
    fn default() -> Self {
        Self::new("CodeBrowserPlugin")
    }
}

impl fmt::Display for CodeBrowserPlugin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CodeBrowserPlugin({}, program={:?})",
            self.name, self.current_program
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_creation() {
        let plugin = CodeBrowserPlugin::new("TestPlugin");
        assert_eq!(plugin.name(), "TestPlugin");
        assert!(!plugin.is_initialized());
        assert!(!plugin.is_disposed());
    }

    #[test]
    fn test_plugin_init_dispose() {
        let mut plugin = CodeBrowserPlugin::new("TestPlugin");
        plugin.init();
        assert!(plugin.is_initialized());
        plugin.dispose();
        assert!(plugin.is_disposed());
    }

    #[test]
    fn test_navigation() {
        let mut plugin = CodeBrowserPlugin::new("TestPlugin");
        plugin.init();
        plugin.go_to("0x401000");
        assert_eq!(plugin.connected_provider().current_address(), Some("0x401000"));
        plugin.go_to("0x402000");
        assert_eq!(plugin.connected_provider().current_address(), Some("0x402000"));
        plugin.go_back();
        assert_eq!(plugin.connected_provider().current_address(), Some("0x401000"));
        plugin.go_forward();
        assert_eq!(plugin.connected_provider().current_address(), Some("0x402000"));
    }

    #[test]
    fn test_clone_provider() {
        let mut plugin = CodeBrowserPlugin::new("TestPlugin");
        let idx = plugin.clone_provider();
        assert_eq!(plugin.disconnected_provider_count(), 1);
        assert!(plugin.disconnected_provider(idx).is_some());
    }

    #[test]
    fn test_program_management() {
        let mut plugin = CodeBrowserPlugin::new("TestPlugin");
        plugin.set_program(Some("test.exe".to_string()));
        assert_eq!(plugin.current_program(), Some("test.exe"));
    }

    #[test]
    fn test_selection_and_highlight() {
        let mut plugin = CodeBrowserPlugin::new("TestPlugin");
        plugin.set_selection(vec![
            ("0x401000".into(), "0x4010FF".into()),
        ]);
        assert!(plugin.connected_provider().has_selection());

        plugin.set_highlight(Some(("0x401020".into(), "0x401030".into())));
        assert!(plugin.connected_provider().highlight().is_some());
    }

    #[test]
    fn test_process_event() {
        let mut plugin = CodeBrowserPlugin::new("TestPlugin");
        plugin.init();

        plugin.process_event(PluginEvent::ProgramActivated {
            program_name: "test.exe".into(),
        });
        assert_eq!(plugin.current_program(), Some("test.exe"));

        plugin.process_event(PluginEvent::ProgramLocation {
            address: "0x401000".into(),
            row: 0,
            col: 0,
        });
        assert_eq!(plugin.connected_provider().current_address(), Some("0x401000"));
    }

    #[test]
    fn test_program_closed() {
        let mut plugin = CodeBrowserPlugin::new("TestPlugin");
        plugin.set_program(Some("test.exe".to_string()));
        let _ = plugin.clone_provider();
        assert_eq!(plugin.disconnected_provider_count(), 1);

        plugin.program_closed("test.exe");
        assert_eq!(plugin.disconnected_provider_count(), 0);
        assert!(plugin.current_program().is_none());
    }

    #[test]
    fn test_options() {
        let mut plugin = CodeBrowserPlugin::new("TestPlugin");
        plugin.set_option("highlight_cursor_line", PluginOptionValue::Bool(true));
        plugin.set_option("font_size", PluginOptionValue::Int(14));
        plugin.set_option("theme", PluginOptionValue::String("dark".into()));

        assert!(plugin.get_bool_option("highlight_cursor_line", false));
        assert_eq!(plugin.get_int_option("font_size", 12), 14);
        assert_eq!(plugin.get_string_option("theme", "light"), "dark");
        assert!(!plugin.get_bool_option("nonexistent", false));
        assert_eq!(plugin.option_count(), 3);
    }

    #[test]
    fn test_event_log() {
        let mut plugin = CodeBrowserPlugin::new("TestPlugin");
        plugin.set_program(Some("test.exe".to_string()));
        let events = plugin.drain_events();
        // Should have at least ProgramActivated event
        assert!(!events.is_empty());
    }

    #[test]
    fn test_display() {
        let plugin = CodeBrowserPlugin::new("TestPlugin");
        let display = format!("{}", plugin);
        assert!(display.contains("TestPlugin"));
    }
}
