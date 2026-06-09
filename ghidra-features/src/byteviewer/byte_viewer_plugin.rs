//! Byte Viewer Plugin implementation.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.byteviewer.ByteViewerPlugin`,
//! `AbstractByteViewerPlugin`, `ProgramByteViewerComponentProvider`,
//! `ByteViewerComponentProvider`, `ByteViewerActionContext`,
//! `ByteViewerClipboardProvider`, and `ByteBlockChangePluginEvent`.
//!
//! This is the top-level plugin that integrates the byte viewer into the
//! Ghidra framework. It manages provider lifecycle, coordinates navigation
//! events, and wires the byte viewer component to the current program and
//! address set.
//!
//! # Key types
//!
//! - [`ByteViewerPlugin`] -- the main plugin struct
//! - [`ByteViewerProvider`] -- the provider that owns the component and
//!   manages its visibility within the tool
//! - [`ProgramByteViewerProvider`] -- provider specialised for program-backed
//!   byte viewing (transaction support, undo/redo state)
//! - [`ByteViewerActionContext`] -- action context carrying the active column
//! - [`ByteViewerClipboardProvider`] -- clipboard copy/paste support
//! - [`ByteBlockChangePluginEvent`] -- plugin event for byte-edit propagation

use num_bigint::BigInt;
use std::collections::BTreeMap;

use super::{
    ByteBlockInfo, ByteBlockSet, ByteBlockSelection, ByteViewerConfigOptions,
    ByteEditInfo,
};
use super::byte_viewer_component::ByteViewerComponent;

// ---------------------------------------------------------------------------
// ByteViewerProvider
// ---------------------------------------------------------------------------

/// Provider that hosts the [`ByteViewerComponent`] within the tool.
///
/// Ported from Ghidra's `ByteViewerPlugin$ByteViewerProvider` inner class.
///
/// The provider is responsible for creating the component, managing its
/// connection to the active program, and forwarding navigation/address
/// change events.
#[derive(Debug)]
pub struct ByteViewerProvider {
    /// Display name for this provider.
    name: String,
    /// The owned byte viewer component.
    component: ByteViewerComponent,
    /// Whether this provider is currently visible.
    visible: bool,
    /// The currently connected program (opaque name reference).
    program_name: Option<String>,
    /// Whether the provider has been disposed.
    disposed: bool,
}

impl ByteViewerProvider {
    /// Create a new provider with the given name.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            component: ByteViewerComponent::new(),
            visible: false,
            program_name: None,
            disposed: false,
        }
    }

    /// The provider name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Whether the provider is visible.
    pub fn is_visible(&self) -> bool {
        self.visible
    }

    /// Set visibility.
    pub fn set_visible(&mut self, visible: bool) {
        self.visible = visible;
    }

    /// Whether the provider has been disposed.
    pub fn is_disposed(&self) -> bool {
        self.disposed
    }

    /// Connect this provider to a program.
    pub fn program_opened(&mut self, program_name: impl Into<String>) {
        self.program_name = Some(program_name.into());
        self.component.clear();
    }

    /// Disconnect from the current program.
    pub fn program_closed(&mut self) {
        self.program_name = None;
        self.component.clear();
    }

    /// Get a reference to the component.
    pub fn component(&self) -> &ByteViewerComponent {
        &self.component
    }

    /// Get a mutable reference to the component.
    pub fn component_mut(&mut self) -> &mut ByteViewerComponent {
        &mut self.component
    }

    /// Dispose of this provider, releasing resources.
    pub fn dispose(&mut self) {
        self.disposed = true;
        self.visible = false;
        self.program_name = None;
        self.component.clear();
    }
}

// ---------------------------------------------------------------------------
// ByteViewerPlugin
// ---------------------------------------------------------------------------

/// The main plugin that manages byte viewer instances.
///
/// Ported from Ghidra's `ByteViewerPlugin`.
///
/// This plugin:
/// - Creates and manages a [`ByteViewerProvider`] for each open program
/// - Listens for program open/close events and navigates the viewer
/// - Provides programmatic access to the byte viewer component
/// - Manages configuration options that are shared across providers
#[derive(Debug)]
pub struct ByteViewerPlugin {
    /// Providers keyed by program name.
    providers: BTreeMap<String, ByteViewerProvider>,
    /// Global configuration options.
    config: ByteViewerConfigOptions,
    /// Whether the plugin has been disposed.
    disposed: bool,
    /// The name of the currently active program.
    active_program: Option<String>,
}

impl ByteViewerPlugin {
    /// Create a new byte viewer plugin.
    pub fn new() -> Self {
        Self {
            providers: BTreeMap::new(),
            config: ByteViewerConfigOptions::new(),
            disposed: false,
            active_program: None,
        }
    }

    /// Create with custom configuration options.
    pub fn with_config(config: ByteViewerConfigOptions) -> Self {
        Self {
            providers: BTreeMap::new(),
            config,
            disposed: false,
            active_program: None,
        }
    }

    /// Handle a program being opened.
    ///
    /// Creates a new provider for the program and makes it the active viewer.
    pub fn program_opened(&mut self, program_name: impl Into<String>) {
        let name = program_name.into();
        let mut provider = ByteViewerProvider::new(&name);
        provider.program_opened(&name);
        provider.component_mut().set_config(self.config.clone());
        self.providers.insert(name.clone(), provider);
        self.active_program = Some(name);
    }

    /// Handle a program being closed.
    ///
    /// Disposes the provider associated with the program.
    pub fn program_closed(&mut self, program_name: &str) {
        if let Some(mut provider) = self.providers.remove(program_name) {
            provider.dispose();
        }
        if self.active_program.as_deref() == Some(program_name) {
            self.active_program = self.providers.keys().next().cloned();
        }
    }

    /// Set the active program.
    pub fn set_active_program(&mut self, program_name: Option<String>) {
        self.active_program = program_name;
    }

    /// Get the active program name.
    pub fn active_program(&self) -> Option<&str> {
        self.active_program.as_deref()
    }

    /// Get the provider for the given program.
    pub fn provider(&self, program_name: &str) -> Option<&ByteViewerProvider> {
        self.providers.get(program_name)
    }

    /// Get the mutable provider for the given program.
    pub fn provider_mut(&mut self, program_name: &str) -> Option<&mut ByteViewerProvider> {
        self.providers.get_mut(program_name)
    }

    /// Get the active provider.
    pub fn active_provider(&self) -> Option<&ByteViewerProvider> {
        self.active_program
            .as_ref()
            .and_then(|name| self.providers.get(name))
    }

    /// Get the active provider (mutable).
    pub fn active_provider_mut(&mut self) -> Option<&mut ByteViewerProvider> {
        self.active_program
            .clone()
            .and_then(move |name| self.providers.get_mut(&name))
    }

    /// Get the configuration options.
    pub fn config(&self) -> &ByteViewerConfigOptions {
        &self.config
    }

    /// Get mutable configuration options.
    pub fn config_mut(&mut self) -> &mut ByteViewerConfigOptions {
        &mut self.config
    }

    /// Set configuration options and propagate to all providers.
    pub fn set_config(&mut self, config: ByteViewerConfigOptions) {
        self.config = config.clone();
        for provider in self.providers.values_mut() {
            provider.component_mut().set_config(config.clone());
        }
    }

    /// Navigate the active viewer to the given address.
    pub fn go_to(&mut self, address: u64) {
        if let Some(provider) = self.active_provider_mut() {
            provider.component_mut().go_to_address(address);
        }
    }

    /// Set the byte block set for the active viewer.
    pub fn set_byte_block_set(&mut self, block_set: ByteBlockSet) {
        if let Some(provider) = self.active_provider_mut() {
            provider.component_mut().set_block_set(block_set);
        }
    }

    /// Get all open program names.
    pub fn open_programs(&self) -> Vec<&str> {
        self.providers.keys().map(|s| s.as_str()).collect()
    }

    /// Number of active providers.
    pub fn provider_count(&self) -> usize {
        self.providers.len()
    }

    /// Whether the plugin has been disposed.
    pub fn is_disposed(&self) -> bool {
        self.disposed
    }

    /// Dispose of the plugin and all providers.
    pub fn dispose(&mut self) {
        let providers = std::mem::take(&mut self.providers);
        for (_, mut provider) in providers.into_iter() {
            provider.dispose();
        }
        self.disposed = true;
        self.active_program = None;
    }
}

impl Default for ByteViewerPlugin {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// ByteBlockChangePluginEvent
// ---------------------------------------------------------------------------

/// Plugin event for notification of byte block changes produced by the
/// Byte Viewer.
///
/// Ported from Ghidra's `ByteBlockChangePluginEvent`.
///
/// Carries a [`ByteEditInfo`] describing the change and a weak reference to
/// the program it applies to.
#[derive(Debug, Clone)]
pub struct ByteBlockChangePluginEvent {
    /// Name of the source plugin that generated this event.
    source: String,
    /// The byte edit description.
    edit: ByteEditInfo,
    /// Opaque program handle (name).
    program_name: Option<String>,
}

impl ByteBlockChangePluginEvent {
    /// Event name constant.
    pub const NAME: &'static str = "ByteBlockChange";

    /// Create a new byte block change plugin event.
    pub fn new(
        source: impl Into<String>,
        edit: ByteEditInfo,
        program_name: Option<String>,
    ) -> Self {
        Self {
            source: source.into(),
            edit,
            program_name,
        }
    }

    /// The source plugin name.
    pub fn source(&self) -> &str {
        &self.source
    }

    /// The event name.
    pub fn event_name(&self) -> &str {
        Self::NAME
    }

    /// Get the program name this event relates to.
    pub fn program_name(&self) -> Option<&str> {
        self.program_name.as_deref()
    }

    /// Get the byte edit info.
    pub fn byte_edit_info(&self) -> &ByteEditInfo {
        &self.edit
    }

    /// Human-readable detail string.
    pub fn details(&self) -> String {
        format!(
            "Address of Block Change==> {}, offset ==> {}",
            self.edit.block_address(),
            self.edit.offset()
        )
    }
}

// ---------------------------------------------------------------------------
// ByteViewerActionContext
// ---------------------------------------------------------------------------

/// Action context for the byte viewer.
///
/// Ported from Ghidra's `ByteViewerActionContext`.
///
/// Carries a reference to the currently active byte viewer column so that
/// actions can operate on the correct format view.
#[derive(Debug)]
pub struct ByteViewerActionContext {
    /// The provider this context belongs to.
    provider_name: String,
    /// The active column index (None means no specific column).
    active_column: Option<usize>,
}

impl ByteViewerActionContext {
    /// Create a new action context.
    pub fn new(provider_name: impl Into<String>) -> Self {
        Self {
            provider_name: provider_name.into(),
            active_column: None,
        }
    }

    /// Create with a specific active column.
    pub fn with_column(provider_name: impl Into<String>, column: usize) -> Self {
        Self {
            provider_name: provider_name.into(),
            active_column: Some(column),
        }
    }

    /// The provider name.
    pub fn provider_name(&self) -> &str {
        &self.provider_name
    }

    /// The active column, if any.
    pub fn active_column(&self) -> Option<usize> {
        self.active_column
    }

    /// Whether the byte viewer works on functions (it does not).
    pub fn has_functions(&self) -> bool {
        false
    }
}

// ---------------------------------------------------------------------------
// ByteViewerClipboardProvider
// ---------------------------------------------------------------------------

/// Clipboard copy/paste support for the byte viewer.
///
/// Ported from Ghidra's `ByteViewerClipboardProvider`.
///
/// Manages the available clipboard copy types, tracks whether copy/paste
/// is enabled, and provides the byte string conversion.
#[derive(Debug, Clone)]
pub struct ByteViewerClipboardProvider {
    /// Whether copy is currently enabled (selection is non-empty).
    copy_enabled: bool,
    /// Whether paste is currently enabled.
    paste_enabled: bool,
    /// The currently selected address range (as a start/end address pair).
    selection_range: Option<(u64, u64)>,
    /// The program name for the current context.
    program_name: Option<String>,
}

impl ByteViewerClipboardProvider {
    /// Create a new clipboard provider.
    pub fn new() -> Self {
        Self {
            copy_enabled: false,
            paste_enabled: false,
            selection_range: None,
            program_name: None,
        }
    }

    /// Whether copy is currently available.
    pub fn can_copy(&self) -> bool {
        self.copy_enabled
    }

    /// Whether paste is currently available.
    pub fn can_paste(&self) -> bool {
        self.paste_enabled && self.program_name.is_some()
    }

    /// Whether copy is enabled (always true for byte viewer).
    pub fn enable_copy(&self) -> bool {
        true
    }

    /// Whether paste is enabled.
    pub fn is_paste_enabled(&self) -> bool {
        self.paste_enabled
    }

    /// Set paste enabled.
    pub fn set_paste_enabled(&mut self, enabled: bool) {
        self.paste_enabled = enabled;
    }

    /// Set the current selection range.
    pub fn set_selection_range(&mut self, range: Option<(u64, u64)>) {
        self.selection_range = range;
        self.copy_enabled = range.is_some();
    }

    /// Get the current selection range.
    pub fn selection_range(&self) -> Option<(u64, u64)> {
        self.selection_range
    }

    /// Set the current program.
    pub fn set_program(&mut self, program_name: Option<String>) {
        self.program_name = program_name;
    }

    /// Format the current selection as a hex byte string.
    pub fn copy_bytes_as_hex_string(&self, bytes: &[u8], with_spaces: bool) -> String {
        if with_spaces {
            bytes
                .iter()
                .map(|b| format!("{:02X}", b))
                .collect::<Vec<_>>()
                .join(" ")
        } else {
            bytes
                .iter()
                .map(|b| format!("{:02X}", b))
                .collect::<Vec<_>>()
                .join("")
        }
    }

    /// Format bytes as a Python byte string literal.
    pub fn copy_as_python_bytes(&self, bytes: &[u8]) -> String {
        let inner: String = bytes
            .iter()
            .map(|b| format!("\\x{:02x}", b))
            .collect();
        format!("b\"{}\"", inner)
    }

    /// Format bytes as a Python list of ints.
    pub fn copy_as_python_list(&self, bytes: &[u8]) -> String {
        let inner: String = bytes
            .iter()
            .map(|b| format!("{}", b))
            .collect::<Vec<_>>()
            .join(", ");
        format!("[{}]", inner)
    }

    /// Format bytes as a C byte array.
    pub fn copy_as_c_array(&self, bytes: &[u8]) -> String {
        let inner: String = bytes
            .iter()
            .map(|b| format!("0x{:02x}", b))
            .collect::<Vec<_>>()
            .join(", ");
        format!("{{{}}}", inner)
    }
}

impl Default for ByteViewerClipboardProvider {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// ProgramByteViewerProvider
// ---------------------------------------------------------------------------

/// A [`ByteViewerProvider`] specialisation for program-backed viewing.
///
/// Ported from Ghidra's `ProgramByteViewerComponentProvider`.
///
/// Adds transaction management for byte edits, undo/redo state
/// serialisation, and program-location-aware navigation.
#[derive(Debug)]
pub struct ProgramByteViewerProvider {
    /// The base provider.
    base: ByteViewerProvider,
    /// The program handle (opaque name).
    program_name: Option<String>,
    /// Clipboard support.
    clipboard: ByteViewerClipboardProvider,
    /// Whether byte editing is allowed.
    editable: bool,
}

impl ProgramByteViewerProvider {
    /// Create a new program byte viewer provider.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            base: ByteViewerProvider::new(name),
            program_name: None,
            clipboard: ByteViewerClipboardProvider::new(),
            editable: true,
        }
    }

    /// The provider name.
    pub fn name(&self) -> &str {
        self.base.name()
    }

    /// Whether the provider is visible.
    pub fn is_visible(&self) -> bool {
        self.base.is_visible()
    }

    /// Set visibility.
    pub fn set_visible(&mut self, visible: bool) {
        self.base.set_visible(visible);
    }

    /// Whether the provider has been disposed.
    pub fn is_disposed(&self) -> bool {
        self.base.is_disposed()
    }

    /// Connect to a program.
    pub fn program_opened(&mut self, program_name: impl Into<String>) {
        let name = program_name.into();
        self.program_name = Some(name.clone());
        self.clipboard.set_program(Some(name.clone()));
        self.base.program_opened(name);
    }

    /// Disconnect from the program.
    pub fn program_closed(&mut self) {
        self.program_name = None;
        self.clipboard.set_program(None);
        self.base.program_closed();
    }

    /// Get a reference to the component.
    pub fn component(&self) -> &ByteViewerComponent {
        self.base.component()
    }

    /// Get a mutable reference to the component.
    pub fn component_mut(&mut self) -> &mut ByteViewerComponent {
        self.base.component_mut()
    }

    /// Get the program name.
    pub fn program_name(&self) -> Option<&str> {
        self.program_name.as_deref()
    }

    /// Whether byte editing is allowed.
    pub fn is_editable(&self) -> bool {
        self.editable
    }

    /// Set whether byte editing is allowed.
    pub fn set_editable(&mut self, editable: bool) {
        self.editable = editable;
    }

    /// Get the clipboard provider.
    pub fn clipboard(&self) -> &ByteViewerClipboardProvider {
        &self.clipboard
    }

    /// Get a mutable reference to the clipboard provider.
    pub fn clipboard_mut(&mut self) -> &mut ByteViewerClipboardProvider {
        &mut self.clipboard
    }

    /// Notify the provider of a byte edit.
    ///
    /// Returns a [`ByteBlockChangePluginEvent`] to be broadcast.
    pub fn notify_edit(&self, edit: ByteEditInfo) -> ByteBlockChangePluginEvent {
        ByteBlockChangePluginEvent::new("ByteViewer", edit, self.program_name.clone())
    }

    /// Dispose of this provider.
    pub fn dispose(&mut self) {
        self.base.dispose();
        self.program_name = None;
        self.clipboard.set_program(None);
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_create() {
        let plugin = ByteViewerPlugin::new();
        assert!(!plugin.is_disposed());
        assert_eq!(plugin.provider_count(), 0);
        assert!(plugin.active_program().is_none());
    }

    #[test]
    fn test_plugin_program_lifecycle() {
        let mut plugin = ByteViewerPlugin::new();
        plugin.program_opened("test.exe");
        assert_eq!(plugin.provider_count(), 1);
        assert_eq!(plugin.active_program(), Some("test.exe"));

        let provider = plugin.provider("test.exe").unwrap();
        assert_eq!(provider.name(), "test.exe");
        assert!(provider.is_disposed() == false);

        plugin.program_closed("test.exe");
        assert_eq!(plugin.provider_count(), 0);
        assert!(plugin.active_program().is_none());
    }

    #[test]
    fn test_plugin_multiple_programs() {
        let mut plugin = ByteViewerPlugin::new();
        plugin.program_opened("prog1.exe");
        plugin.program_opened("prog2.exe");
        assert_eq!(plugin.provider_count(), 2);
        assert_eq!(plugin.active_program(), Some("prog2.exe"));

        plugin.program_closed("prog2.exe");
        assert_eq!(plugin.active_program(), Some("prog1.exe"));
    }

    #[test]
    fn test_plugin_config_propagation() {
        let mut plugin = ByteViewerPlugin::new();
        plugin.program_opened("test.exe");

        let mut config = ByteViewerConfigOptions::new();
        config.set_bytes_per_line(32);
        plugin.set_config(config);

        let provider = plugin.provider("test.exe").unwrap();
        assert_eq!(
            provider.component().config().bytes_per_line(),
            32
        );
    }

    #[test]
    fn test_plugin_go_to() {
        let mut plugin = ByteViewerPlugin::new();
        plugin.program_opened("test.exe");

        let mut block_set = ByteBlockSet::new("test.exe");
        block_set.add_block(super::super::ByteBlock::new(".text", 0x1000, vec![0; 256]));
        plugin.set_byte_block_set(block_set);

        plugin.go_to(0x1000);
        let provider = plugin.provider("test.exe").unwrap();
        assert!(provider.component().current_address().is_some());
    }

    #[test]
    fn test_plugin_dispose() {
        let mut plugin = ByteViewerPlugin::new();
        plugin.program_opened("test.exe");
        plugin.dispose();

        assert!(plugin.is_disposed());
        assert_eq!(plugin.provider_count(), 0);
    }

    #[test]
    fn test_provider_visibility() {
        let mut provider = ByteViewerProvider::new("test");
        assert!(!provider.is_visible());
        provider.set_visible(true);
        assert!(provider.is_visible());
    }

    #[test]
    fn test_provider_program_connection() {
        let mut provider = ByteViewerProvider::new("test");
        provider.program_opened("prog.exe");
        assert!(!provider.is_disposed());

        provider.program_closed();
        provider.dispose();
        assert!(provider.is_disposed());
    }

    #[test]
    fn test_plugin_open_programs() {
        let mut plugin = ByteViewerPlugin::new();
        plugin.program_opened("a.exe");
        plugin.program_opened("b.exe");
        let names = plugin.open_programs();
        assert_eq!(names, vec!["a.exe", "b.exe"]);
    }

    #[test]
    fn test_plugin_with_config() {
        let mut config = ByteViewerConfigOptions::new();
        config.set_bytes_per_line(32);
        let plugin = ByteViewerPlugin::with_config(config);
        assert_eq!(plugin.config().bytes_per_line(), 32);
    }

    // ---- ByteBlockChangePluginEvent tests ----

    #[test]
    fn test_change_event_create() {
        let edit = ByteEditInfo::new(0x1000, BigInt::from(5), vec![0x00], vec![0xFF]);
        let event = ByteBlockChangePluginEvent::new("TestPlugin", edit, Some("test.exe".into()));
        assert_eq!(event.source(), "TestPlugin");
        assert_eq!(event.event_name(), "ByteBlockChange");
        assert_eq!(event.program_name(), Some("test.exe"));
        assert_eq!(event.byte_edit_info().block_address(), 0x1000);
    }

    #[test]
    fn test_change_event_details() {
        let edit = ByteEditInfo::new(0x1000, BigInt::from(0), vec![0x00], vec![0xFF]);
        let event = ByteBlockChangePluginEvent::new("P", edit, None);
        let details = event.details();
        assert!(details.contains("4096")); // 0x1000 = 4096 decimal
        assert!(details.contains("offset"));
    }

    // ---- ByteViewerActionContext tests ----

    #[test]
    fn test_action_context_create() {
        let ctx = ByteViewerActionContext::new("TestProvider");
        assert_eq!(ctx.provider_name(), "TestProvider");
        assert!(ctx.active_column().is_none());
        assert!(!ctx.has_functions());
    }

    #[test]
    fn test_action_context_with_column() {
        let ctx = ByteViewerActionContext::with_column("TestProvider", 3);
        assert_eq!(ctx.active_column(), Some(3));
    }

    // ---- ByteViewerClipboardProvider tests ----

    #[test]
    fn test_clipboard_create() {
        let cb = ByteViewerClipboardProvider::new();
        assert!(!cb.can_copy());
        assert!(!cb.can_paste());
        assert!(cb.enable_copy());
    }

    #[test]
    fn test_clipboard_selection() {
        let mut cb = ByteViewerClipboardProvider::new();
        cb.set_program(Some("test.exe".into()));
        cb.set_selection_range(Some((0x1000, 0x100F)));
        assert!(cb.can_copy());
        assert_eq!(cb.selection_range(), Some((0x1000, 0x100F)));
    }

    #[test]
    fn test_clipboard_paste() {
        let mut cb = ByteViewerClipboardProvider::new();
        assert!(!cb.can_paste());
        cb.set_paste_enabled(true);
        assert!(!cb.can_paste()); // no program
        cb.set_program(Some("test.exe".into()));
        assert!(cb.can_paste());
    }

    #[test]
    fn test_clipboard_hex_format() {
        let cb = ByteViewerClipboardProvider::new();
        let bytes = [0xDE, 0xAD, 0xBE, 0xEF];
        assert_eq!(cb.copy_bytes_as_hex_string(&bytes, true), "DE AD BE EF");
        assert_eq!(cb.copy_bytes_as_hex_string(&bytes, false), "DEADBEEF");
    }

    #[test]
    fn test_clipboard_python_format() {
        let cb = ByteViewerClipboardProvider::new();
        let bytes = [0xCA, 0xFE];
        assert_eq!(cb.copy_as_python_bytes(&bytes), "b\"\\xca\\xfe\"");
        assert_eq!(cb.copy_as_python_list(&bytes), "[202, 254]");
    }

    #[test]
    fn test_clipboard_c_format() {
        let cb = ByteViewerClipboardProvider::new();
        let bytes = [0x90, 0xC3];
        assert_eq!(cb.copy_as_c_array(&bytes), "{0x90, 0xc3}");
    }

    // ---- ProgramByteViewerProvider tests ----

    #[test]
    fn test_program_provider_create() {
        let provider = ProgramByteViewerProvider::new("test");
        assert_eq!(provider.name(), "test");
        assert!(!provider.is_disposed());
        assert!(provider.program_name().is_none());
        assert!(provider.is_editable());
    }

    #[test]
    fn test_program_provider_lifecycle() {
        let mut provider = ProgramByteViewerProvider::new("test");
        provider.program_opened("prog.exe");
        assert_eq!(provider.program_name(), Some("prog.exe"));

        provider.program_closed();
        assert!(provider.program_name().is_none());
    }

    #[test]
    fn test_program_provider_notify_edit() {
        let mut provider = ProgramByteViewerProvider::new("test");
        provider.program_opened("prog.exe");
        let edit = ByteEditInfo::new(0x1000, BigInt::from(0), vec![0x00], vec![0xFF]);
        let event = provider.notify_edit(edit);
        assert_eq!(event.event_name(), "ByteBlockChange");
        assert_eq!(event.program_name(), Some("prog.exe"));
    }

    #[test]
    fn test_program_provider_editable() {
        let mut provider = ProgramByteViewerProvider::new("test");
        assert!(provider.is_editable());
        provider.set_editable(false);
        assert!(!provider.is_editable());
    }

    #[test]
    fn test_program_provider_dispose() {
        let mut provider = ProgramByteViewerProvider::new("test");
        provider.program_opened("prog.exe");
        provider.dispose();
        assert!(provider.is_disposed());
        assert!(provider.program_name().is_none());
    }
}
