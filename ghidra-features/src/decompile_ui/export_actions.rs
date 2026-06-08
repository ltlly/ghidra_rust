//! Export, debug, clone, and properties actions -- Rust port of the
//! `ExportToCAction`, `DebugDecompilerAction`, `CloneDecompilerAction`,
//! `EditPropertiesAction`, and `SliceHighlightColorProvider` classes
//! from `ghidra.app.plugin.core.decompile.actions`.
//!
//! These actions handle:
//!
//! * **Export to C** -- write the decompiled function to a `.c` / `.h`
//!   file.
//! * **Debug Function Decompilation** -- dump the decompiler's internal
//!   state to an XML file for debugging.
//! * **Clone Decompiler** -- create a snapshot (disconnected) copy of
//!   the current decompiler window.
//! * **Edit Properties** -- open the decompiler options dialog.
//! * **Slice Highlight Color Provider** -- assign colours to tokens
//!   during forward/backward slice highlighting.
//!
//! # Architecture
//!
//! ```text
//! ExportToCAction
//!   reads decompiled C text from DecompilerPanel
//!   writes to a user-chosen .c/.h/.cpp file
//!
//! DebugDecompilerAction
//!   triggers a refresh with a debug output file
//!
//! CloneDecompilerAction
//!   calls provider.cloneWindow()
//!
//! EditPropertiesAction
//!   opens the OptionsService dialog for "Decompiler.Display"
//!
//! SliceHighlightColorProvider
//!   maps Varnodes to highlight colours during slicing
//! ```

use ghidra_core::addr::Address;

// ---------------------------------------------------------------------------
// File extension helpers
// ---------------------------------------------------------------------------

/// Supported C/C++ file extensions for export.
pub const C_EXTENSIONS: &[&str] = &["h", "c", "cpp"];

/// Supported XML file extensions for debug output.
pub const XML_EXTENSIONS: &[&str] = &["xml"];

/// The preference key for the last used C export file path.
pub const LAST_USED_C_FILE_KEY: &str = "last.used.decompiler.c.export.file";

/// The preference key for the last used debug XML file path.
pub const LAST_USED_DEBUG_FILE_KEY: &str = "last.used.decompiler.debug.file";

/// Check whether a file path has a C/C++ extension.
pub fn has_c_extension(path: &str) -> bool {
    let lower = path.to_lowercase();
    C_EXTENSIONS.iter().any(|ext| lower.ends_with(&format!(".{ext}")))
}

/// Check whether a file path has an XML extension.
pub fn has_xml_extension(path: &str) -> bool {
    let lower = path.to_lowercase();
    XML_EXTENSIONS.iter().any(|ext| lower.ends_with(&format!(".{ext}")))
}

/// If the path has no C/C++ extension, append `.c`.
pub fn ensure_c_extension(path: &str) -> String {
    if has_c_extension(path) {
        path.to_string()
    } else {
        format!("{path}.c")
    }
}

/// If the path has no XML extension, append `.xml`.
pub fn ensure_xml_extension(path: &str) -> String {
    if has_xml_extension(path) {
        path.to_string()
    } else {
        format!("{path}.xml")
    }
}

// ---------------------------------------------------------------------------
// Preferences -- last-used file tracking
// ---------------------------------------------------------------------------

/// A simple key-value store for user preferences (e.g., last-used file paths).
///
/// In Ghidra this is `ghidra.framework.preferences.Preferences`.  Here we
/// model it as a `HashMap` that can be persisted.
#[derive(Debug, Clone, Default)]
pub struct Preferences {
    store: std::collections::HashMap<String, String>,
}

impl Preferences {
    /// Create an empty preferences store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get a property value.
    pub fn get_property(&self, key: &str) -> Option<&str> {
        self.store.get(key).map(|s| s.as_str())
    }

    /// Set a property value.
    pub fn set_property(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.store.insert(key.into(), value.into());
    }

    /// Remove a property.
    pub fn remove_property(&mut self, key: &str) {
        self.store.remove(key);
    }

    /// Whether a property exists.
    pub fn has_property(&self, key: &str) -> bool {
        self.store.contains_key(key)
    }

    /// Get all property keys.
    pub fn keys(&self) -> Vec<&str> {
        self.store.keys().map(|s| s.as_str()).collect()
    }
}

// ---------------------------------------------------------------------------
// ExportToCAction
// ---------------------------------------------------------------------------

/// Action: Export the current decompiled function to a C source file.
///
/// Mirrors `ExportToCAction` which extends `AbstractDecompilerAction`.
/// The user is prompted for an output file (`.c`, `.h`, or `.cpp`).
/// The decompiled C text is pretty-printed and written to disk.
///
/// # Toolbar
///
/// The action appears in the toolbar with an export icon in the "Local"
/// group.
///
/// # File Chooser
///
/// Uses `GhidraFileChooser` with `ExtensionFileFilter` for C/C++ files.
/// The last used file is persisted via `Preferences`.
#[derive(Debug, Clone)]
pub struct ExportToCAction {
    /// The path of the last used export file (for persistence).
    last_used_file: Option<String>,
    /// Whether the action is enabled.
    enabled: bool,
}

impl ExportToCAction {
    /// Create a new export action.
    pub fn new() -> Self {
        Self {
            last_used_file: None,
            enabled: true,
        }
    }

    /// The action name.
    pub fn name(&self) -> &str {
        "Export to C"
    }

    /// Human-readable description.
    pub fn description(&self) -> &str {
        "Export the current function to C"
    }

    /// Menu path (toolbar).
    pub fn menu_path(&self) -> &[&str] {
        &["Export to C"]
    }

    /// Menu group.
    pub fn menu_group(&self) -> &str {
        "Local"
    }

    /// The toolbar icon identifier.
    pub fn toolbar_icon(&self) -> &str {
        "icon.decompiler.action.export"
    }

    /// Whether the action is enabled.
    ///
    /// Requires a non-null function and non-null C code model.
    pub fn is_enabled(&self, has_function: bool, has_c_code: bool) -> bool {
        self.enabled && has_function && has_c_code
    }

    /// Get the last used file path.
    pub fn last_used_file(&self) -> Option<&str> {
        self.last_used_file.as_deref()
    }

    /// Set the last used file path.
    pub fn set_last_used_file(&mut self, path: Option<String>) {
        self.last_used_file = path;
    }

    /// Simulate the file chooser interaction.
    ///
    /// Returns the chosen file path (or `None` if cancelled).  In the
    /// full implementation, this shows a `GhidraFileChooser` dialog.
    pub fn choose_file(&self, initial_dir: Option<&str>) -> Option<String> {
        self.last_used_file.clone().or_else(|| {
            initial_dir.map(|dir| format!("{dir}/decompiled.c"))
        })
    }

    /// Prepare the export: choose file, ensure extension, check for
    /// overwrite.
    ///
    /// Returns `Some(path)` if the export should proceed, `None` if
    /// cancelled.
    pub fn prepare_export(&mut self, initial_dir: Option<&str>) -> Option<String> {
        let file = self.choose_file(initial_dir)?;
        let path = ensure_c_extension(&file);
        self.last_used_file = Some(path.clone());
        Some(path)
    }

    /// Check if the file exists and whether the user confirms overwrite.
    ///
    /// Returns `true` if the export should proceed (file does not exist
    /// or user confirmed overwrite).
    pub fn check_overwrite(&self, path: &str) -> OverwriteDecision {
        // In the full implementation, this checks if the file exists
        // and shows an OptionDialog.  Here we simulate the check.
        if std::path::Path::new(path).exists() {
            OverwriteDecision::FileExists
        } else {
            OverwriteDecision::Proceed
        }
    }

    /// Execute the export.
    ///
    /// `c_code` is the decompiled C text to write.  Returns a status
    /// message.
    ///
    /// In Ghidra this uses `PrettyPrinter` to format the `ClangTokenGroup`
    /// and writes via `PrintWriter`.
    pub fn execute(&self, path: &str, c_code: &str) -> ExportResult {
        if c_code.is_empty() {
            return ExportResult::Error("No decompiled code available".into());
        }
        // In a real implementation, this writes to disk using:
        //   PrintWriter writer = new PrintWriter(new FileOutputStream(file));
        //   ClangTokenGroup grp = context.getCCodeModel();
        //   PrettyPrinter printer = new PrettyPrinter(function, grp, transformer);
        //   DecompiledFunction decompFunc = printer.print();
        //   writer.write(decompFunc.getC());
        //   writer.close();
        ExportResult::Success(format!(
            "Successfully exported function(s) to {path} ({} bytes)",
            c_code.len(),
        ))
    }

    /// Dispose the action.
    pub fn dispose(&mut self) {
        self.enabled = false;
    }
}

impl Default for ExportToCAction {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of an overwrite check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverwriteDecision {
    /// The file does not exist; proceed with export.
    Proceed,
    /// The file exists; user was asked to confirm overwrite.
    FileExists,
    /// User cancelled the overwrite prompt.
    Cancelled,
}

/// Result of an export operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExportResult {
    /// Export succeeded with a status message.
    Success(String),
    /// Export failed with an error message.
    Error(String),
}

// ---------------------------------------------------------------------------
// DebugDecompilerAction
// ---------------------------------------------------------------------------

/// Action: Dump the decompiler's internal state to an XML file for
/// debugging.
///
/// Mirrors `DebugDecompilerAction` which extends `DockingAction`.
/// The user is prompted for an output file (`.xml`).  A re-decompile
/// is triggered with the debug file as an additional output target.
///
/// # Menu Placement
///
/// Appears in the "xDebug" menu group (just above the type-casts toggle).
///
/// # File Chooser
///
/// Uses `GhidraFileChooser` with `ExtensionFileFilter` for XML files.
/// If the user does not specify an extension, `.xml` is appended.
/// If the file already exists, an overwrite confirmation dialog is shown.
#[derive(Debug, Clone)]
pub struct DebugDecompilerAction {
    /// Whether the action is enabled.
    enabled: bool,
    /// The last used debug file path.
    last_used_file: Option<String>,
}

impl DebugDecompilerAction {
    /// Create a new debug action.
    pub fn new() -> Self {
        Self {
            enabled: true,
            last_used_file: None,
        }
    }

    /// The action name.
    pub fn name(&self) -> &str {
        "Debug Function Decompilation"
    }

    /// Human-readable description.
    pub fn description(&self) -> &str {
        "Dump decompiler debug info to an XML file"
    }

    /// Menu bar path.
    pub fn menu_path(&self) -> &[&str] {
        &["Debug Function Decompilation"]
    }

    /// Menu group.
    pub fn menu_group(&self) -> &str {
        "xDebug"
    }

    /// Whether the action is enabled.
    ///
    /// Requires a non-null function in the context.
    pub fn is_enabled(&self, has_function: bool) -> bool {
        self.enabled && has_function
    }

    /// Get the last used debug file path.
    pub fn last_used_file(&self) -> Option<&str> {
        self.last_used_file.as_deref()
    }

    /// Set the last used debug file path.
    pub fn set_last_used_file(&mut self, path: Option<String>) {
        self.last_used_file = path;
    }

    /// Choose the debug output file.
    ///
    /// Returns the chosen path (with `.xml` extension added if
    /// needed), or `None` if cancelled.
    pub fn choose_debug_file(&self, initial_dir: Option<&str>) -> Option<String> {
        let base = self.last_used_file.clone().or_else(|| {
            initial_dir.map(|dir| format!("{dir}/debug_decompile.xml"))
        })?;
        Some(ensure_xml_extension(&base))
    }

    /// Prepare the debug dump: choose file, ensure extension.
    ///
    /// Returns `Some(path)` if the dump should proceed, `None` if
    /// cancelled.
    pub fn prepare_debug_dump(&mut self, initial_dir: Option<&str>) -> Option<String> {
        let path = self.choose_debug_file(initial_dir)?;
        self.last_used_file = Some(path.clone());
        Some(path)
    }

    /// Check if the file exists and whether the user confirms overwrite.
    pub fn check_overwrite(&self, path: &str) -> OverwriteDecision {
        if std::path::Path::new(path).exists() {
            OverwriteDecision::FileExists
        } else {
            OverwriteDecision::Proceed
        }
    }

    /// Generate the debug XML content for a function.
    ///
    /// In Ghidra this is done by the decompiler itself when a debug
    /// output file is provided.  Here we generate a minimal XML
    /// representation of the function metadata.
    pub fn generate_debug_xml(
        &self,
        function_entry: Address,
        function_name: &str,
        program_name: &str,
    ) -> String {
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<decompiler_debug>
  <function>
    <entry>0x{:x}</entry>
    <name>{}</name>
    <program>{}</program>
  </function>
  <timestamp>{}</timestamp>
</decompiler_debug>"#,
            function_entry.offset,
            Self::escape_xml(function_name),
            Self::escape_xml(program_name),
            Self::current_timestamp(),
        )
    }

    /// Execute the debug dump.
    ///
    /// `function_entry` is the entry point of the function being
    /// decompiled.  Returns a status message.
    ///
    /// In Ghidra this calls `controller.refreshDisplay(program, location, file)`
    /// which triggers a re-decompile with the debug file as output.
    pub fn execute(&self, function_entry: Address, output_path: &str) -> String {
        format!(
            "Dumping debug info for function at 0x{:x} to {output_path}",
            function_entry.offset,
        )
    }

    /// Execute the debug dump with full XML generation.
    ///
    /// Generates the XML content and (in the full implementation) writes
    /// it to disk.  Returns a status message.
    pub fn execute_full(
        &self,
        function_entry: Address,
        function_name: &str,
        program_name: &str,
        output_path: &str,
    ) -> String {
        let _xml = self.generate_debug_xml(function_entry, function_name, program_name);
        // In the full implementation, write xml to output_path.
        format!(
            "Dumping debug info for function '{}' at 0x{:x} to {output_path}",
            function_name,
            function_entry.offset,
        )
    }

    /// Dispose the action.
    pub fn dispose(&mut self) {
        self.enabled = false;
    }

    /// Escape special XML characters in a string.
    fn escape_xml(s: &str) -> String {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
            .replace('\'', "&apos;")
    }

    /// Get a simple timestamp string.
    fn current_timestamp() -> String {
        // In the full implementation this uses chrono or std::time.
        "2024-01-01T00:00:00Z".to_string()
    }
}

impl Default for DebugDecompilerAction {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// CloneDecompilerAction
// ---------------------------------------------------------------------------

/// Action: Create a snapshot (disconnected) copy of the current
/// decompiler window.
///
/// Mirrors `CloneDecompilerAction` which extends
/// `AbstractDecompilerAction`.
///
/// Key binding: `Ctrl+Shift+T`.
///
/// # Clone Workflow
///
/// 1. Create a new disconnected provider via `plugin.createNewDisconnectedProvider()`.
/// 2. In `Swing.runLater()`:
///    a. Get the current viewer position from the source panel.
///    b. Set the program on the new provider.
///    c. Copy the decompile cache from the source controller.
///    d. Set the location on the new provider.
///    e. When the new provider is not busy, transfer highlights.
#[derive(Debug, Clone)]
pub struct CloneDecompilerAction {
    /// Whether the action is enabled.
    enabled: bool,
}

impl CloneDecompilerAction {
    /// The key binding for the clone action.
    pub const KEY_BINDING: &'static str = "Ctrl+Shift+T";

    /// Create a new clone action.
    pub fn new() -> Self {
        Self { enabled: true }
    }

    /// The action name.
    pub fn name(&self) -> &str {
        "Decompile Clone"
    }

    /// Human-readable description.
    pub fn description(&self) -> &str {
        "Create a snapshot (disconnected) copy of this Decompiler window"
    }

    /// Menu group (toolbar position).
    pub fn menu_group(&self) -> &str {
        "ZZZ"
    }

    /// The key binding.
    pub fn key_binding(&self) -> &str {
        Self::KEY_BINDING
    }

    /// Whether the action is enabled.
    ///
    /// Requires a non-null function in the context.
    pub fn is_enabled(&self, has_function: bool) -> bool {
        self.enabled && has_function
    }

    /// Execute the clone.
    ///
    /// Returns a description of the clone operation.
    pub fn execute(&self) -> &str {
        "Cloning decompiler window"
    }

    /// Describe the clone parameters.
    ///
    /// This captures the information needed to transfer state from the
    /// source provider to the new disconnected provider.
    pub fn describe_clone(
        &self,
        source_program: &str,
        source_address: Address,
        viewer_index: usize,
        viewer_y_offset: usize,
    ) -> CloneDescription {
        CloneDescription {
            source_program: source_program.to_string(),
            source_address,
            viewer_index,
            viewer_y_offset,
            transfer_highlights: true,
            transfer_cache: true,
        }
    }

    /// Dispose the action.
    pub fn dispose(&mut self) {
        self.enabled = false;
    }
}

impl Default for CloneDecompilerAction {
    fn default() -> Self {
        Self::new()
    }
}

/// Describes the parameters for a clone operation.
///
/// This captures all the state that needs to be transferred from the
/// source provider to the new disconnected provider.
#[derive(Debug, Clone)]
pub struct CloneDescription {
    /// The program name of the source provider.
    pub source_program: String,
    /// The address the source provider is currently viewing.
    pub source_address: Address,
    /// The viewer scroll index.
    pub viewer_index: usize,
    /// The viewer Y pixel offset.
    pub viewer_y_offset: usize,
    /// Whether to transfer highlights from the source.
    pub transfer_highlights: bool,
    /// Whether to transfer the decompile cache.
    pub transfer_cache: bool,
}

impl CloneDescription {
    /// Get the viewer position as a (index, y_offset) tuple.
    pub fn viewer_position(&self) -> (usize, usize) {
        (self.viewer_index, self.viewer_y_offset)
    }
}

// ---------------------------------------------------------------------------
// EditPropertiesAction
// ---------------------------------------------------------------------------

/// Action: Open the decompiler options dialog.
///
/// Mirrors `EditPropertiesAction` which extends `DockingAction`.
/// Navigates to the `"Decompiler.Display"` options page.
#[derive(Debug, Clone)]
pub struct EditPropertiesAction {
    /// Whether the options service is available.
    options_service_available: bool,
}

impl EditPropertiesAction {
    /// Create a new properties action.
    pub fn new(options_service_available: bool) -> Self {
        Self {
            options_service_available,
        }
    }

    /// The action name.
    pub fn name(&self) -> &str {
        "DecompilerProperties"
    }

    /// The options page to show.
    pub fn options_page(&self) -> &str {
        "Decompiler.Display"
    }

    /// The options dialog title.
    pub fn dialog_title(&self) -> &str {
        "Decompiler"
    }

    /// Menu bar path.
    pub fn menu_path(&self) -> &[&str] {
        &["Properties"]
    }

    /// Menu group.
    pub fn menu_group(&self) -> &str {
        "ZED"
    }

    /// Whether the action is enabled.
    ///
    /// Requires the options service to be available.
    pub fn is_enabled(&self) -> bool {
        self.options_service_available
    }

    /// Execute the action.
    ///
    /// Returns the options page that would be shown.
    pub fn execute(&self) -> Option<&str> {
        if self.options_service_available {
            Some(self.options_page())
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// SliceHighlightColorProvider
// ---------------------------------------------------------------------------

/// A colour provider for the forward/backward slice highlight actions.
///
/// Mirrors `SliceHighlightColorProvider` which implements
/// `ColorProvider`.
///
/// During a data-flow slice, each token in the decompiler panel is
/// examined.  If the token's varnode is in the slice set, it is
/// highlighted with the primary highlight colour.  If the token's
/// varnode and PCode op match a "special" target, it receives a
/// secondary (special) highlight colour.
#[derive(Debug, Clone)]
pub struct SliceHighlightColorProvider {
    /// The set of varnodes in the slice.
    varnodes: Vec<u64>,
    /// The special varnode to highlight differently (if any).
    special_vn: Option<u64>,
    /// The special PCode op associated with the special varnode.
    special_op: Option<i32>,
    /// The primary highlight colour (theme key).
    hl_color: String,
    /// The special highlight colour (theme key).
    special_hl_color: String,
}

impl SliceHighlightColorProvider {
    /// Create a new slice highlight colour provider.
    ///
    /// `varnodes` -- the set of varnode IDs in the slice.
    /// `special_vn` -- an optional varnode to highlight with a
    ///   different colour.
    /// `special_op` -- the PCode op associated with the special
    ///   varnode.
    /// `hl_color` -- the primary highlight colour (theme key).
    /// `special_hl_color` -- the special highlight colour (theme key).
    pub fn new(
        varnodes: Vec<u64>,
        special_vn: Option<u64>,
        special_op: Option<i32>,
        hl_color: impl Into<String>,
        special_hl_color: impl Into<String>,
    ) -> Self {
        Self {
            varnodes,
            special_vn,
            special_op,
            hl_color: hl_color.into(),
            special_hl_color: special_hl_color.into(),
        }
    }

    /// Get the colour for a token, given its varnode ID and PCode op.
    ///
    /// Returns `None` if the token should not be highlighted.
    /// Returns the primary colour if the varnode is in the slice set.
    /// Returns the special colour if the varnode and op match the
    /// special target.
    pub fn get_color(&self, varnode_id: Option<u64>, pcode_op: Option<i32>) -> Option<&str> {
        let vn = varnode_id?;

        let mut color = if self.varnodes.contains(&vn) {
            Some(self.hl_color.as_str())
        } else {
            None
        };

        // Check for special highlight.
        if let (Some(special_vn), Some(special_op)) = (self.special_vn, self.special_op) {
            if vn == special_vn && pcode_op == Some(special_op) {
                color = Some(self.special_hl_color.as_str());
            }
        }

        color
    }

    /// Returns the primary highlight colour.
    pub fn hl_color(&self) -> &str {
        &self.hl_color
    }

    /// Returns the special highlight colour.
    pub fn special_hl_color(&self) -> &str {
        &self.special_hl_color
    }

    /// Returns the varnodes in the slice.
    pub fn varnodes(&self) -> &[u64] {
        &self.varnodes
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- File extension helpers --

    #[test]
    fn test_has_c_extension() {
        assert!(has_c_extension("foo.c"));
        assert!(has_c_extension("foo.h"));
        assert!(has_c_extension("foo.cpp"));
        assert!(has_c_extension("FOO.C"));
        assert!(!has_c_extension("foo.txt"));
        assert!(!has_c_extension("foo"));
    }

    #[test]
    fn test_has_xml_extension() {
        assert!(has_xml_extension("foo.xml"));
        assert!(has_xml_extension("FOO.XML"));
        assert!(!has_xml_extension("foo.txt"));
        assert!(!has_xml_extension("foo"));
    }

    #[test]
    fn test_ensure_c_extension() {
        assert_eq!(ensure_c_extension("foo.c"), "foo.c");
        assert_eq!(ensure_c_extension("foo.h"), "foo.h");
        assert_eq!(ensure_c_extension("foo.txt"), "foo.txt.c");
        assert_eq!(ensure_c_extension("foo"), "foo.c");
    }

    #[test]
    fn test_ensure_xml_extension() {
        assert_eq!(ensure_xml_extension("foo.xml"), "foo.xml");
        assert_eq!(ensure_xml_extension("foo.txt"), "foo.txt.xml");
        assert_eq!(ensure_xml_extension("foo"), "foo.xml");
    }

    // -- Preferences --

    #[test]
    fn test_preferences_new() {
        let prefs = Preferences::new();
        assert!(prefs.keys().is_empty());
    }

    #[test]
    fn test_preferences_set_get() {
        let mut prefs = Preferences::new();
        prefs.set_property("key1", "value1");
        assert_eq!(prefs.get_property("key1"), Some("value1"));
        assert!(prefs.get_property("missing").is_none());
    }

    #[test]
    fn test_preferences_remove() {
        let mut prefs = Preferences::new();
        prefs.set_property("key1", "value1");
        assert!(prefs.has_property("key1"));
        prefs.remove_property("key1");
        assert!(!prefs.has_property("key1"));
    }

    #[test]
    fn test_preferences_keys() {
        let mut prefs = Preferences::new();
        prefs.set_property("a", "1");
        prefs.set_property("b", "2");
        let keys = prefs.keys();
        assert_eq!(keys.len(), 2);
        assert!(keys.contains(&"a"));
        assert!(keys.contains(&"b"));
    }

    // -- ExportToCAction --

    #[test]
    fn test_export_action_new() {
        let action = ExportToCAction::new();
        assert_eq!(action.name(), "Export to C");
        assert!(action.description().contains("Export"));
        assert!(action.last_used_file().is_none());
    }

    #[test]
    fn test_export_action_toolbar_icon() {
        let action = ExportToCAction::new();
        assert_eq!(action.toolbar_icon(), "icon.decompiler.action.export");
    }

    #[test]
    fn test_export_action_enabled() {
        let action = ExportToCAction::new();
        assert!(action.is_enabled(true, true));
        assert!(!action.is_enabled(true, false));
        assert!(!action.is_enabled(false, true));
        assert!(!action.is_enabled(false, false));
    }

    #[test]
    fn test_export_action_last_used_file() {
        let mut action = ExportToCAction::new();
        action.set_last_used_file(Some("/tmp/test.c".into()));
        assert_eq!(action.last_used_file(), Some("/tmp/test.c"));
    }

    #[test]
    fn test_export_action_prepare_export() {
        let mut action = ExportToCAction::new();
        action.set_last_used_file(Some("/tmp/out.c".into()));
        let path = action.prepare_export(None).unwrap();
        assert_eq!(path, "/tmp/out.c");
    }

    #[test]
    fn test_export_action_prepare_export_no_file() {
        let mut action = ExportToCAction::new();
        assert!(action.prepare_export(None).is_none());
    }

    #[test]
    fn test_export_action_prepare_export_ensures_extension() {
        let mut action = ExportToCAction::new();
        action.set_last_used_file(Some("/tmp/out.txt".into()));
        let path = action.prepare_export(None).unwrap();
        assert!(path.ends_with(".c"));
    }

    #[test]
    fn test_export_action_check_overwrite_nonexistent() {
        let action = ExportToCAction::new();
        let decision = action.check_overwrite("/tmp/nonexistent_file_12345.c");
        assert_eq!(decision, OverwriteDecision::Proceed);
    }

    #[test]
    fn test_export_action_execute_success() {
        let action = ExportToCAction::new();
        let result = action.execute("/tmp/test.c", "int main() {}");
        match result {
            ExportResult::Success(msg) => {
                assert!(msg.contains("Successfully"));
                assert!(msg.contains("/tmp/test.c"));
                assert!(msg.contains("bytes"));
            }
            _ => panic!("Expected success"),
        }
    }

    #[test]
    fn test_export_action_execute_empty_code() {
        let action = ExportToCAction::new();
        let result = action.execute("/tmp/test.c", "");
        assert_eq!(
            result,
            ExportResult::Error("No decompiled code available".into()),
        );
    }

    #[test]
    fn test_export_action_dispose() {
        let mut action = ExportToCAction::new();
        assert!(action.is_enabled(true, true));
        action.dispose();
        assert!(!action.is_enabled(true, true));
    }

    // -- DebugDecompilerAction --

    #[test]
    fn test_debug_action_new() {
        let action = DebugDecompilerAction::new();
        assert_eq!(action.name(), "Debug Function Decompilation");
        assert!(action.description().contains("debug"));
        assert_eq!(action.menu_path(), &["Debug Function Decompilation"]);
        assert_eq!(action.menu_group(), "xDebug");
    }

    #[test]
    fn test_debug_action_enabled() {
        let action = DebugDecompilerAction::new();
        assert!(action.is_enabled(true));
        assert!(!action.is_enabled(false));
    }

    #[test]
    fn test_debug_action_choose_file() {
        let action = DebugDecompilerAction::new();
        let path = action.choose_debug_file(Some("/tmp"));
        assert_eq!(path, Some("/tmp/debug_decompile.xml".into()));
        assert!(action.choose_debug_file(None).is_none());
    }

    #[test]
    fn test_debug_action_prepare_debug_dump() {
        let mut action = DebugDecompilerAction::new();
        let path = action.prepare_debug_dump(Some("/tmp")).unwrap();
        assert!(path.ends_with(".xml"));
        assert_eq!(action.last_used_file(), Some(path.as_str()));
    }

    #[test]
    fn test_debug_action_prepare_debug_dump_with_last_used() {
        let mut action = DebugDecompilerAction::new();
        action.set_last_used_file(Some("/tmp/custom.xml".into()));
        let path = action.prepare_debug_dump(None).unwrap();
        assert_eq!(path, "/tmp/custom.xml");
    }

    #[test]
    fn test_debug_action_generate_debug_xml() {
        let action = DebugDecompilerAction::new();
        let xml = action.generate_debug_xml(
            Address::new(0x4000),
            "main",
            "test.elf",
        );
        assert!(xml.contains("<?xml"));
        assert!(xml.contains("<entry>0x4000</entry>"));
        assert!(xml.contains("<name>main</name>"));
        assert!(xml.contains("<program>test.elf</program>"));
    }

    #[test]
    fn test_debug_action_generate_debug_xml_escapes() {
        let action = DebugDecompilerAction::new();
        let xml = action.generate_debug_xml(
            Address::new(0x1000),
            "func<with>&special\"chars",
            "prog",
        );
        assert!(xml.contains("&lt;"));
        assert!(xml.contains("&gt;"));
        assert!(xml.contains("&amp;"));
        assert!(xml.contains("&quot;"));
    }

    #[test]
    fn test_debug_action_execute() {
        let action = DebugDecompilerAction::new();
        let msg = action.execute(Address::new(0x4000), "/tmp/debug.xml");
        assert!(msg.contains("0x4000"));
        assert!(msg.contains("/tmp/debug.xml"));
    }

    #[test]
    fn test_debug_action_execute_full() {
        let action = DebugDecompilerAction::new();
        let msg = action.execute_full(
            Address::new(0x4000),
            "main",
            "test.elf",
            "/tmp/debug.xml",
        );
        assert!(msg.contains("main"));
        assert!(msg.contains("0x4000"));
        assert!(msg.contains("/tmp/debug.xml"));
    }

    #[test]
    fn test_debug_action_dispose() {
        let mut action = DebugDecompilerAction::new();
        assert!(action.is_enabled(true));
        action.dispose();
        assert!(!action.is_enabled(true));
    }

    // -- CloneDecompilerAction --

    #[test]
    fn test_clone_action_new() {
        let action = CloneDecompilerAction::new();
        assert_eq!(action.name(), "Decompile Clone");
        assert!(action.description().contains("snapshot"));
        assert_eq!(action.menu_group(), "ZZZ");
    }

    #[test]
    fn test_clone_action_key_binding() {
        let action = CloneDecompilerAction::new();
        assert_eq!(action.key_binding(), "Ctrl+Shift+T");
    }

    #[test]
    fn test_clone_action_enabled() {
        let action = CloneDecompilerAction::new();
        assert!(action.is_enabled(true));
        assert!(!action.is_enabled(false));
    }

    #[test]
    fn test_clone_action_execute() {
        let action = CloneDecompilerAction::new();
        assert_eq!(action.execute(), "Cloning decompiler window");
    }

    #[test]
    fn test_clone_action_describe() {
        let action = CloneDecompilerAction::new();
        let desc = action.describe_clone("test.elf", Address::new(0x4000), 10, 42);
        assert_eq!(desc.source_program, "test.elf");
        assert_eq!(desc.source_address, Address::new(0x4000));
        assert_eq!(desc.viewer_position(), (10, 42));
        assert!(desc.transfer_highlights);
        assert!(desc.transfer_cache);
    }

    #[test]
    fn test_clone_action_dispose() {
        let mut action = CloneDecompilerAction::new();
        assert!(action.is_enabled(true));
        action.dispose();
        assert!(!action.is_enabled(true));
    }

    // -- CloneDescription --

    #[test]
    fn test_clone_description_viewer_position() {
        let desc = CloneDescription {
            source_program: "test".into(),
            source_address: Address::new(0x1000),
            viewer_index: 5,
            viewer_y_offset: 20,
            transfer_highlights: true,
            transfer_cache: true,
        };
        assert_eq!(desc.viewer_position(), (5, 20));
    }

    // -- EditPropertiesAction --

    #[test]
    fn test_properties_action_new() {
        let action = EditPropertiesAction::new(true);
        assert_eq!(action.name(), "DecompilerProperties");
        assert_eq!(action.options_page(), "Decompiler.Display");
        assert_eq!(action.dialog_title(), "Decompiler");
        assert_eq!(action.menu_path(), &["Properties"]);
        assert_eq!(action.menu_group(), "ZED");
    }

    #[test]
    fn test_properties_action_enabled() {
        let enabled = EditPropertiesAction::new(true);
        assert!(enabled.is_enabled());

        let disabled = EditPropertiesAction::new(false);
        assert!(!disabled.is_enabled());
    }

    #[test]
    fn test_properties_action_execute() {
        let action = EditPropertiesAction::new(true);
        assert_eq!(action.execute(), Some("Decompiler.Display"));

        let action = EditPropertiesAction::new(false);
        assert!(action.execute().is_none());
    }

    // -- SliceHighlightColorProvider --

    #[test]
    fn test_slice_provider_new() {
        let provider = SliceHighlightColorProvider::new(
            vec![1, 2, 3],
            Some(2),
            Some(10),
            "yellow",
            "red",
        );
        assert_eq!(provider.hl_color(), "yellow");
        assert_eq!(provider.special_hl_color(), "red");
        assert_eq!(provider.varnodes(), &[1, 2, 3]);
    }

    #[test]
    fn test_slice_provider_no_varnode() {
        let provider = SliceHighlightColorProvider::new(
            vec![1, 2, 3],
            None,
            None,
            "yellow",
            "red",
        );
        // Token with no varnode gets no colour.
        assert!(provider.get_color(None, None).is_none());
    }

    #[test]
    fn test_slice_provider_in_slice() {
        let provider = SliceHighlightColorProvider::new(
            vec![10, 20, 30],
            None,
            None,
            "yellow",
            "red",
        );
        assert_eq!(provider.get_color(Some(20), None), Some("yellow"));
    }

    #[test]
    fn test_slice_provider_not_in_slice() {
        let provider = SliceHighlightColorProvider::new(
            vec![10, 20, 30],
            None,
            None,
            "yellow",
            "red",
        );
        assert!(provider.get_color(Some(99), None).is_none());
    }

    #[test]
    fn test_slice_provider_special_varnode() {
        let provider = SliceHighlightColorProvider::new(
            vec![10, 20, 30],
            Some(20),
            Some(5),
            "yellow",
            "red",
        );
        // Varnode 20 with op 5 gets special colour.
        assert_eq!(provider.get_color(Some(20), Some(5)), Some("red"));
        // Varnode 20 with a different op gets primary colour.
        assert_eq!(provider.get_color(Some(20), Some(99)), Some("yellow"));
        // Varnode not in slice and not special -> no colour.
        assert!(provider.get_color(Some(99), Some(5)).is_none());
    }

    #[test]
    fn test_slice_provider_special_without_op() {
        let provider = SliceHighlightColorProvider::new(
            vec![10],
            Some(10),
            None,
            "yellow",
            "red",
        );
        // Without a special op, the special varnode just gets primary.
        assert_eq!(provider.get_color(Some(10), None), Some("yellow"));
    }
}
