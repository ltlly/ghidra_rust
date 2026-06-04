//! Additional sample plugins.
//!
//! Ported from `HelloWorldComponentPlugin.java`, `HelloProgramPlugin.java`,
//! `ShowInfoPlugin.java`, `KitchenSinkPlugin.java`, `SampleProgramTreePlugin.java`,
//! and `SampleStringTranslationPlugin.java` in the sample extension.
//!
//! These plugins demonstrate various Ghidra extension patterns including
//! component-based UI plugins, program-aware plugins, and translation plugins.

/// A plugin that demonstrates adding a dockable GUI component to a tool.
///
/// Ported from `HelloWorldComponentPlugin.java`.
///
/// This plugin creates and manages a `HelloWorldComponentProvider` that
/// provides a dockable panel in the Ghidra tool.
#[derive(Debug)]
pub struct HelloWorldComponentPlugin {
    /// Plugin name.
    pub name: String,
    /// Whether the component provider is visible.
    pub provider_visible: bool,
}

impl HelloWorldComponentPlugin {
    /// Create a new component plugin.
    pub fn new() -> Self {
        Self {
            name: "HelloWorldComponent".to_string(),
            provider_visible: true,
        }
    }

    /// Toggle the visibility of the component provider.
    pub fn toggle_visibility(&mut self) {
        self.provider_visible = !self.provider_visible;
    }

    /// Dispose the plugin.
    pub fn dispose(&mut self) {
        self.provider_visible = false;
    }
}

impl Default for HelloWorldComponentPlugin {
    fn default() -> Self {
        Self::new()
    }
}

/// A plugin that demonstrates program-awareness.
///
/// Ported from `HelloProgramPlugin.java`.
///
/// This plugin reacts to program open/close events and provides
/// actions that operate on the current program.
#[derive(Debug)]
pub struct HelloProgramPlugin {
    /// Plugin name.
    pub name: String,
    /// Name of the currently open program, if any.
    pub current_program: Option<String>,
}

impl HelloProgramPlugin {
    /// Create a new program-aware plugin.
    pub fn new() -> Self {
        Self {
            name: "HelloProgram".to_string(),
            current_program: None,
        }
    }

    /// Called when a program is opened.
    pub fn program_opened(&mut self, program_name: impl Into<String>) {
        self.current_program = Some(program_name.into());
    }

    /// Called when a program is closed.
    pub fn program_closed(&mut self) {
        self.current_program = None;
    }

    /// Whether a program is currently open.
    pub fn has_program(&self) -> bool {
        self.current_program.is_some()
    }
}

impl Default for HelloProgramPlugin {
    fn default() -> Self {
        Self::new()
    }
}

/// A plugin that displays information about the current program.
///
/// Ported from `ShowInfoPlugin.java`.
///
/// Provides a dialog that shows metadata about the loaded program
/// including architecture, language, and address space information.
#[derive(Debug)]
pub struct ShowInfoPlugin {
    /// Plugin name.
    pub name: String,
}

impl ShowInfoPlugin {
    /// Create a new show-info plugin.
    pub fn new() -> Self {
        Self {
            name: "ShowInfo".to_string(),
        }
    }

    /// Generate an info string about a program.
    ///
    /// In a real implementation, this would query the program model.
    pub fn format_program_info(
        &self,
        name: &str,
        processor: &str,
        address_size: u32,
        language: &str,
    ) -> String {
        format!(
            "Program: {name}\nProcessor: {processor}\nAddress Size: {address_size} bits\nLanguage: {language}"
        )
    }
}

impl Default for ShowInfoPlugin {
    fn default() -> Self {
        Self::new()
    }
}

/// A "kitchen sink" plugin demonstrating many Ghidra plugin features.
///
/// Ported from `KitchenSinkPlugin.java`.
///
/// This plugin demonstrates options, actions, menus, dialogs, and
/// tool integration patterns.
#[derive(Debug)]
pub struct KitchenSinkPlugin {
    /// Plugin name.
    pub name: String,
    /// Registered options (name -> value).
    pub options: std::collections::HashMap<String, String>,
    /// Registered action names.
    pub actions: Vec<String>,
}

impl KitchenSinkPlugin {
    /// Create a new kitchen sink plugin.
    pub fn new() -> Self {
        Self {
            name: "KitchenSink".to_string(),
            options: std::collections::HashMap::new(),
            actions: Vec::new(),
        }
    }

    /// Set an option value.
    pub fn set_option(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.options.insert(name.into(), value.into());
    }

    /// Get an option value.
    pub fn get_option(&self, name: &str) -> Option<&str> {
        self.options.get(name).map(|s| s.as_str())
    }

    /// Register an action.
    pub fn register_action(&mut self, name: impl Into<String>) {
        self.actions.push(name.into());
    }

    /// Check if an action is registered.
    pub fn has_action(&self, name: &str) -> bool {
        self.actions.iter().any(|a| a == name)
    }
}

impl Default for KitchenSinkPlugin {
    fn default() -> Self {
        Self::new()
    }
}

/// A plugin for program tree manipulation.
///
/// Ported from `SampleProgramTreePlugin.java`.
///
/// Demonstrates how to interact with the program tree (the hierarchical
/// view of address groups and modules).
#[derive(Debug)]
pub struct SampleProgramTreePlugin {
    /// Plugin name.
    pub name: String,
    /// Registered tree groups.
    pub groups: Vec<String>,
}

impl SampleProgramTreePlugin {
    /// Create a new program tree plugin.
    pub fn new() -> Self {
        Self {
            name: "SampleProgramTree".to_string(),
            groups: Vec::new(),
        }
    }

    /// Add a group to the program tree.
    pub fn add_group(&mut self, name: impl Into<String>) {
        self.groups.push(name.into());
    }

    /// Get the number of groups.
    pub fn num_groups(&self) -> usize {
        self.groups.len()
    }
}

impl Default for SampleProgramTreePlugin {
    fn default() -> Self {
        Self::new()
    }
}

/// A plugin for string translation.
///
/// Ported from `SampleStringTranslationPlugin.java`.
///
/// Demonstrates how to register a string translation provider that
/// Ghidra can use to translate strings found in binaries.
#[derive(Debug)]
pub struct SampleStringTranslationPlugin {
    /// Plugin name.
    pub name: String,
    /// Registered translation entries (original -> translated).
    pub translations: std::collections::HashMap<String, String>,
}

impl SampleStringTranslationPlugin {
    /// Create a new string translation plugin.
    pub fn new() -> Self {
        Self {
            name: "SampleStringTranslation".to_string(),
            translations: std::collections::HashMap::new(),
        }
    }

    /// Add a translation entry.
    pub fn add_translation(
        &mut self,
        original: impl Into<String>,
        translated: impl Into<String>,
    ) {
        self.translations.insert(original.into(), translated.into());
    }

    /// Look up a translation.
    pub fn translate(&self, original: &str) -> Option<&str> {
        self.translations.get(original).map(|s| s.as_str())
    }
}

impl Default for SampleStringTranslationPlugin {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_component_plugin() {
        let mut plugin = HelloWorldComponentPlugin::new();
        assert!(plugin.provider_visible);
        plugin.dispose();
        assert!(!plugin.provider_visible);
    }

    #[test]
    fn test_component_plugin_toggle() {
        let mut plugin = HelloWorldComponentPlugin::new();
        assert!(plugin.provider_visible);
        plugin.toggle_visibility();
        assert!(!plugin.provider_visible);
        plugin.toggle_visibility();
        assert!(plugin.provider_visible);
    }

    #[test]
    fn test_program_plugin() {
        let mut plugin = HelloProgramPlugin::new();
        assert!(!plugin.has_program());
        plugin.program_opened("test.exe");
        assert!(plugin.has_program());
        assert_eq!(plugin.current_program.as_deref(), Some("test.exe"));
        plugin.program_closed();
        assert!(!plugin.has_program());
    }

    #[test]
    fn test_show_info_format() {
        let plugin = ShowInfoPlugin::new();
        let info = plugin.format_program_info("test.exe", "x86", 64, "x86:LE:64:default");
        assert!(info.contains("test.exe"));
        assert!(info.contains("x86"));
        assert!(info.contains("64"));
    }

    #[test]
    fn test_kitchen_sink_options() {
        let mut plugin = KitchenSinkPlugin::new();
        plugin.set_option("theme", "dark");
        assert_eq!(plugin.get_option("theme"), Some("dark"));
        assert_eq!(plugin.get_option("missing"), None);
    }

    #[test]
    fn test_kitchen_sink_actions() {
        let mut plugin = KitchenSinkPlugin::new();
        plugin.register_action("MyAction");
        assert!(plugin.has_action("MyAction"));
        assert!(!plugin.has_action("OtherAction"));
    }

    #[test]
    fn test_program_tree_plugin() {
        let mut plugin = SampleProgramTreePlugin::new();
        assert_eq!(plugin.num_groups(), 0);
        plugin.add_group("Group1");
        plugin.add_group("Group2");
        assert_eq!(plugin.num_groups(), 2);
    }

    #[test]
    fn test_string_translation_plugin() {
        let mut plugin = SampleStringTranslationPlugin::new();
        plugin.add_translation("hello", "hola");
        plugin.add_translation("goodbye", "adios");
        assert_eq!(plugin.translate("hello"), Some("hola"));
        assert_eq!(plugin.translate("goodbye"), Some("adios"));
        assert_eq!(plugin.translate("missing"), None);
    }
}
