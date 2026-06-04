//! The code viewer provider.
//!
//! Ports `ghidra.app.plugin.core.codebrowser.CodeViewerProvider`,
//! which is the main component provider that hosts the listing panel,
//! handles drag-and-drop, manages hover services, and coordinates
//! with the code browser plugin.

use std::collections::HashMap;
use std::fmt;

use super::location_memento::CodeViewerLocationMemento;

/// Provider identifier counter for unique IDs.
static PROVIDER_ID_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

/// The code viewer provider -- the main listing window.
///
/// This corresponds to Ghidra's `CodeViewerProvider`, which is a
/// `ComponentProvider` that hosts a `ListingPanel` and coordinates
/// navigation, selection, highlighting, and the dual-listing feature.
///
/// Ported from Ghidra's `CodeViewerProvider`.
#[derive(Debug)]
pub struct CodeViewerProvider {
    /// Unique instance identifier.
    id: u64,
    /// Whether this is the connected (primary) or a disconnected (cloned) provider.
    is_connected: bool,
    /// The plugin that owns this provider (name for identification).
    plugin_name: String,
    /// The current program name (if any).
    program: Option<String>,
    /// The current cursor location address.
    current_address: Option<String>,
    /// The current selection range.
    current_selection: Option<(String, String)>,
    /// The current highlight range.
    current_highlight: Option<(String, String)>,
    /// Cursor offset within the listing field.
    cursor_offset: i32,
    /// Whether the header is showing.
    header_visible: bool,
    /// Whether hover popups are enabled.
    hover_enabled: bool,
    /// Registered hover service names.
    hover_services: Vec<String>,
    /// Registered margin provider service names.
    margin_services: Vec<String>,
    /// Registered overview provider service names.
    overview_services: Vec<String>,
    /// Per-address program highlights (external highlighters).
    program_highlights: HashMap<String, Vec<(u64, u64)>>,
    /// Whether this provider has been disposed.
    disposed: bool,
}

impl CodeViewerProvider {
    /// Create a new code viewer provider.
    ///
    /// # Parameters
    ///
    /// * `plugin_name` - The name of the owning plugin.
    /// * `is_connected` - `true` for the primary provider, `false` for clones.
    pub fn new(plugin_name: impl Into<String>, is_connected: bool) -> Self {
        let id = PROVIDER_ID_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Self {
            id,
            is_connected,
            plugin_name: plugin_name.into(),
            program: None,
            current_address: None,
            current_selection: None,
            current_highlight: None,
            cursor_offset: 0,
            header_visible: true,
            hover_enabled: true,
            hover_services: Vec::new(),
            margin_services: Vec::new(),
            overview_services: Vec::new(),
            program_highlights: HashMap::new(),
            disposed: false,
        }
    }

    /// Get the unique provider ID.
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Whether this is the connected (primary) provider.
    pub fn is_connected(&self) -> bool {
        self.is_connected
    }

    /// Get the owning plugin name.
    pub fn plugin_name(&self) -> &str {
        &self.plugin_name
    }

    // ---------------------------------------------------------------
    // Program management
    // ---------------------------------------------------------------

    /// Get the current program name.
    pub fn program(&self) -> Option<&str> {
        self.program.as_deref()
    }

    /// Set the current program.
    pub fn set_program(&mut self, program: Option<String>) {
        self.program = program;
    }

    // ---------------------------------------------------------------
    // Navigation
    // ---------------------------------------------------------------

    /// Get the current address.
    pub fn current_address(&self) -> Option<&str> {
        self.current_address.as_deref()
    }

    /// Navigate to a specific address.
    ///
    /// Ports `CodeViewerProvider.goTo(Program, ProgramLocation)`.
    ///
    /// Returns `true` if navigation succeeded.
    pub fn go_to(&mut self, address: impl Into<String>) -> bool {
        self.current_address = Some(address.into());
        self.cursor_offset = 0;
        true
    }

    // ---------------------------------------------------------------
    // Selection
    // ---------------------------------------------------------------

    /// Get the current selection range.
    pub fn current_selection(&self) -> Option<&(String, String)> {
        self.current_selection.as_ref()
    }

    /// Whether a selection is currently active.
    pub fn has_selection(&self) -> bool {
        self.current_selection.is_some()
    }

    /// Set the current selection range.
    pub fn set_selection(&mut self, start: Option<String>, end: Option<String>) {
        match (start, end) {
            (Some(s), Some(e)) => self.current_selection = Some((s, e)),
            _ => self.current_selection = None,
        }
    }

    /// Clear the current selection.
    pub fn clear_selection(&mut self) {
        self.current_selection = None;
    }

    // ---------------------------------------------------------------
    // Highlight
    // ---------------------------------------------------------------

    /// Get the current highlight range.
    pub fn current_highlight(&self) -> Option<&(String, String)> {
        self.current_highlight.as_ref()
    }

    /// Set the current highlight.
    pub fn set_highlight(&mut self, start: Option<String>, end: Option<String>) {
        match (start, end) {
            (Some(s), Some(e)) => self.current_highlight = Some((s, e)),
            _ => self.current_highlight = None,
        }
    }

    /// Clear the current highlight.
    pub fn clear_highlight(&mut self) {
        self.current_highlight = None;
    }

    // ---------------------------------------------------------------
    // Cursor
    // ---------------------------------------------------------------

    /// Get the cursor offset within the listing field.
    pub fn cursor_offset(&self) -> i32 {
        self.cursor_offset
    }

    /// Set the cursor offset within the listing field.
    pub fn set_cursor_offset(&mut self, offset: i32) {
        self.cursor_offset = offset;
    }

    // ---------------------------------------------------------------
    // Header / Hover
    // ---------------------------------------------------------------

    /// Whether the listing header is currently visible.
    pub fn is_header_showing(&self) -> bool {
        self.header_visible
    }

    /// Toggle the header visibility.
    pub fn show_header(&mut self, show: bool) {
        self.header_visible = show;
    }

    /// Whether hover popups are enabled.
    pub fn is_hover_enabled(&self) -> bool {
        self.hover_enabled
    }

    /// Enable or disable hover popups.
    pub fn set_hover_enabled(&mut self, enabled: bool) {
        self.hover_enabled = enabled;
    }

    // ---------------------------------------------------------------
    // Service registration
    // ---------------------------------------------------------------

    /// Add a hover service.
    pub fn add_hover_service(&mut self, service_name: impl Into<String>) {
        let name = service_name.into();
        if !self.hover_services.contains(&name) {
            self.hover_services.push(name);
        }
    }

    /// Remove a hover service.
    pub fn remove_hover_service(&mut self, service_name: &str) {
        self.hover_services.retain(|s| s != service_name);
    }

    /// Get all registered hover service names.
    pub fn hover_services(&self) -> &[String] {
        &self.hover_services
    }

    /// Add a margin provider service.
    pub fn add_margin_service(&mut self, service_name: impl Into<String>) {
        let name = service_name.into();
        if !self.margin_services.contains(&name) {
            self.margin_services.push(name);
        }
    }

    /// Remove a margin provider service.
    pub fn remove_margin_service(&mut self, service_name: &str) {
        self.margin_services.retain(|s| s != service_name);
    }

    /// Add an overview provider service.
    pub fn add_overview_service(&mut self, service_name: impl Into<String>) {
        let name = service_name.into();
        if !self.overview_services.contains(&name) {
            self.overview_services.push(name);
        }
    }

    /// Remove an overview provider service.
    pub fn remove_overview_service(&mut self, service_name: &str) {
        self.overview_services.retain(|s| s != service_name);
    }

    // ---------------------------------------------------------------
    // Program highlights
    // ---------------------------------------------------------------

    /// Set an external program highlight for the given program name.
    pub fn set_program_highlight(
        &mut self,
        program_name: impl Into<String>,
        ranges: Vec<(u64, u64)>,
    ) {
        self.program_highlights.insert(program_name.into(), ranges);
    }

    /// Get the program highlights for a given program name.
    pub fn get_program_highlights(&self, program_name: &str) -> Option<&Vec<(u64, u64)>> {
        self.program_highlights.get(program_name)
    }

    /// Clear the program highlights for a specific program.
    pub fn clear_program_highlights(&mut self, program_name: &str) {
        self.program_highlights.remove(program_name);
    }

    // ---------------------------------------------------------------
    // Memento
    // ---------------------------------------------------------------

    /// Create a memento capturing the current position.
    ///
    /// Ports `CodeViewerProvider.getMemento()`.
    pub fn get_memento(&self) -> CodeViewerLocationMemento {
        CodeViewerLocationMemento::new(
            self.program.clone(),
            self.current_address.clone(),
            0, 0, 0, 0, 0, 0,
            self.cursor_offset,
        )
    }

    /// Restore the position from a memento.
    ///
    /// Ports `CodeViewerProvider.setMemento(LocationMemento)`.
    pub fn set_memento(&mut self, memento: &CodeViewerLocationMemento) {
        self.cursor_offset = memento.cursor_offset();
        if let Some(ref addr) = memento.address {
            self.current_address = Some(addr.clone());
        }
    }

    // ---------------------------------------------------------------
    // State persistence
    // ---------------------------------------------------------------

    /// Save the provider's data state to a key-value store.
    pub fn save_data_state(&self) -> HashMap<String, String> {
        let mut state = HashMap::new();
        if let Some(ref addr) = self.current_address {
            state.insert("ADDRESS".to_string(), addr.clone());
        }
        state.insert("CURSOR_OFFSET".to_string(), self.cursor_offset.to_string());
        state.insert(
            "HEADER_VISIBLE".to_string(),
            self.header_visible.to_string(),
        );
        state.insert(
            "HOVER_ENABLED".to_string(),
            self.hover_enabled.to_string(),
        );
        state
    }

    /// Restore the provider's data state from a key-value store.
    pub fn read_data_state(&mut self, state: &HashMap<String, String>) {
        if let Some(addr) = state.get("ADDRESS") {
            self.current_address = Some(addr.clone());
        }
        if let Some(offset) = state.get("CURSOR_OFFSET") {
            if let Ok(v) = offset.parse() {
                self.cursor_offset = v;
            }
        }
        if let Some(visible) = state.get("HEADER_VISIBLE") {
            self.header_visible = visible.parse().unwrap_or(true);
        }
        if let Some(enabled) = state.get("HOVER_ENABLED") {
            self.hover_enabled = enabled.parse().unwrap_or(true);
        }
    }

    // ---------------------------------------------------------------
    // Lifecycle
    // ---------------------------------------------------------------

    /// Dispose of this provider.
    pub fn dispose(&mut self) {
        self.disposed = true;
        self.hover_services.clear();
        self.margin_services.clear();
        self.overview_services.clear();
        self.program_highlights.clear();
    }

    /// Whether this provider has been disposed.
    pub fn is_disposed(&self) -> bool {
        self.disposed
    }
}

impl fmt::Display for CodeViewerProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CodeViewerProvider(id={}, plugin={}, connected={}, program={:?})",
            self.id, self.plugin_name, self.is_connected, self.program
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_creation() {
        let provider = CodeViewerProvider::new("CodeBrowserPlugin", true);
        assert!(provider.is_connected());
        assert_eq!(provider.plugin_name(), "CodeBrowserPlugin");
        assert!(!provider.is_disposed());
    }

    #[test]
    fn test_provider_unique_ids() {
        let p1 = CodeViewerProvider::new("Plugin1", true);
        let p2 = CodeViewerProvider::new("Plugin2", false);
        assert_ne!(p1.id(), p2.id());
    }

    #[test]
    fn test_program_management() {
        let mut provider = CodeViewerProvider::new("Plugin", true);
        assert!(provider.program().is_none());
        provider.set_program(Some("test.exe".into()));
        assert_eq!(provider.program(), Some("test.exe"));
    }

    #[test]
    fn test_navigation() {
        let mut provider = CodeViewerProvider::new("Plugin", true);
        assert!(provider.current_address().is_none());
        assert!(provider.go_to("0x100000"));
        assert_eq!(provider.current_address(), Some("0x100000"));
        assert_eq!(provider.cursor_offset(), 0);
    }

    #[test]
    fn test_selection() {
        let mut provider = CodeViewerProvider::new("Plugin", true);
        assert!(provider.current_selection().is_none());
        provider.set_selection(Some("0x1000".into()), Some("0x10FF".into()));
        let sel = provider.current_selection().unwrap();
        assert_eq!(sel.0, "0x1000");
        assert_eq!(sel.1, "0x10FF");
        provider.clear_selection();
        assert!(provider.current_selection().is_none());
    }

    #[test]
    fn test_highlight() {
        let mut provider = CodeViewerProvider::new("Plugin", true);
        provider.set_highlight(Some("0x2000".into()), Some("0x20FF".into()));
        let hl = provider.current_highlight().unwrap();
        assert_eq!(hl.0, "0x2000");
        provider.clear_highlight();
        assert!(provider.current_highlight().is_none());
    }

    #[test]
    fn test_header_and_hover() {
        let mut provider = CodeViewerProvider::new("Plugin", true);
        assert!(provider.is_header_showing());
        provider.show_header(false);
        assert!(!provider.is_header_showing());

        assert!(provider.is_hover_enabled());
        provider.set_hover_enabled(false);
        assert!(!provider.is_hover_enabled());
    }

    #[test]
    fn test_hover_services() {
        let mut provider = CodeViewerProvider::new("Plugin", true);
        provider.add_hover_service("ServiceA");
        provider.add_hover_service("ServiceB");
        provider.add_hover_service("ServiceA"); // duplicate ignored
        assert_eq!(provider.hover_services().len(), 2);

        provider.remove_hover_service("ServiceA");
        assert_eq!(provider.hover_services().len(), 1);
        assert_eq!(provider.hover_services()[0], "ServiceB");
    }

    #[test]
    fn test_memento_roundtrip() {
        let mut provider = CodeViewerProvider::new("Plugin", true);
        provider.go_to("0x400000");
        provider.set_cursor_offset(42);

        let memento = provider.get_memento();
        assert_eq!(memento.cursor_offset(), 42);

        let mut provider2 = CodeViewerProvider::new("Plugin", false);
        provider2.set_memento(&memento);
        assert_eq!(provider2.current_address(), Some("0x400000"));
        assert_eq!(provider2.cursor_offset(), 42);
    }

    #[test]
    fn test_state_save_restore() {
        let mut provider = CodeViewerProvider::new("Plugin", true);
        provider.go_to("0xDEAD");
        provider.set_cursor_offset(7);
        provider.show_header(false);

        let state = provider.save_data_state();
        assert_eq!(state.get("ADDRESS").unwrap(), "0xDEAD");
        assert_eq!(state.get("CURSOR_OFFSET").unwrap(), "7");
        assert_eq!(state.get("HEADER_VISIBLE").unwrap(), "false");

        let mut provider2 = CodeViewerProvider::new("Plugin", false);
        provider2.read_data_state(&state);
        assert_eq!(provider2.current_address(), Some("0xDEAD"));
        assert_eq!(provider2.cursor_offset(), 7);
        assert!(!provider2.is_header_showing());
    }

    #[test]
    fn test_program_highlights() {
        let mut provider = CodeViewerProvider::new("Plugin", true);
        provider.set_program_highlight("test.exe", vec![(0x1000, 0x10FF)]);
        let hl = provider.get_program_highlights("test.exe").unwrap();
        assert_eq!(hl.len(), 1);
        assert_eq!(hl[0], (0x1000, 0x10FF));

        provider.clear_program_highlights("test.exe");
        assert!(provider.get_program_highlights("test.exe").is_none());
    }

    #[test]
    fn test_dispose() {
        let mut provider = CodeViewerProvider::new("Plugin", true);
        provider.add_hover_service("svc");
        provider.dispose();
        assert!(provider.is_disposed());
        assert!(provider.hover_services().is_empty());
    }

    #[test]
    fn test_display() {
        let provider = CodeViewerProvider::new("CodeBrowserPlugin", true);
        let display = format!("{}", provider);
        assert!(display.contains("CodeBrowserPlugin"));
        assert!(display.contains("connected=true"));
    }
}
