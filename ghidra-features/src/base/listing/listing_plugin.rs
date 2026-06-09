//! Listing Plugin -- manages the program listing display.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.listing` package.
//!
//! This module provides the listing plugin that manages how program data
//! (instructions, data, comments, labels) is displayed in the code browser.
//! It handles field layout, formatting, rendering, and provider management.
//!
//! # Architecture
//!
//! ```text
//! ListingPlugin
//!   ├── ListingLayoutManager (field layout)
//!   ├── ListingFormatService (formatting rules)
//!   ├── FieldFactory (creates display fields)
//!   ├── ListingModel (data model)
//!   └── ListingProvider[] (connected providers)
//! ```
//!
//! # Example
//!
//! ```
//! use ghidra_features::base::listing::listing_plugin::ListingPlugin;
//!
//! let mut plugin = ListingPlugin::new("Listing");
//! plugin.init();
//! assert_eq!(plugin.name(), "Listing");
//! ```

use std::collections::HashMap;
use std::fmt;

use super::listing_provider::ListingProvider;

// ---------------------------------------------------------------------------
// ListingFieldLayout -- field positioning in a listing row
// ---------------------------------------------------------------------------

/// The alignment of a field within its column.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldAlignment {
    /// Left-aligned.
    Left,
    /// Center-aligned.
    Center,
    /// Right-aligned.
    Right,
}

/// Defines how a field is positioned in a listing row.
#[derive(Debug, Clone)]
pub struct FieldLayout {
    /// The field name.
    pub name: String,
    /// The column index.
    pub column: usize,
    /// The width in characters.
    pub width: usize,
    /// The alignment.
    pub alignment: FieldAlignment,
    /// Whether the field is visible.
    pub visible: bool,
    /// The field priority (lower = rendered first).
    pub priority: u32,
}

impl FieldLayout {
    /// Creates a new field layout.
    pub fn new(name: impl Into<String>, column: usize, width: usize) -> Self {
        Self {
            name: name.into(),
            column,
            width,
            alignment: FieldAlignment::Left,
            visible: true,
            priority: 100,
        }
    }

    /// Sets the alignment.
    pub fn with_alignment(mut self, alignment: FieldAlignment) -> Self {
        self.alignment = alignment;
        self
    }

    /// Sets the visibility.
    pub fn with_visible(mut self, visible: bool) -> Self {
        self.visible = visible;
        self
    }

    /// Sets the priority.
    pub fn with_priority(mut self, priority: u32) -> Self {
        self.priority = priority;
        self
    }
}

// ---------------------------------------------------------------------------
// ListingFormat -- formatting rules for listing display
// ---------------------------------------------------------------------------

/// The type of code unit being displayed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CodeUnitType {
    /// An instruction.
    Instruction,
    /// Defined data.
    DefinedData,
    /// Undefined data.
    UndefinedData,
    /// A function entry point.
    FunctionEntry,
    /// A label.
    Label,
    /// A comment.
    Comment,
}

/// Formatting rules for a specific code unit type.
#[derive(Debug, Clone)]
pub struct CodeUnitFormat {
    /// The code unit type.
    pub code_unit_type: CodeUnitType,
    /// Whether to show the address.
    pub show_address: bool,
    /// Whether to show bytes.
    pub show_bytes: bool,
    /// Whether to show comments.
    pub show_comments: bool,
    /// Whether to show labels.
    pub show_labels: bool,
    /// Maximum line width.
    pub max_line_width: usize,
}

impl CodeUnitFormat {
    /// Creates a new code unit format with default settings.
    pub fn new(code_unit_type: CodeUnitType) -> Self {
        Self {
            code_unit_type,
            show_address: true,
            show_bytes: true,
            show_comments: true,
            show_labels: true,
            max_line_width: 120,
        }
    }
}

impl Default for CodeUnitFormat {
    fn default() -> Self {
        Self::new(CodeUnitType::Instruction)
    }
}

// ---------------------------------------------------------------------------
// ListingPlugin -- the main plugin
// ---------------------------------------------------------------------------

/// The listing plugin.
///
/// Manages how program data is displayed in the code browser. Handles
/// field layout, formatting, rendering rules, and provider management.
///
/// Ported from Ghidra's listing plugin Java classes.
#[derive(Debug)]
pub struct ListingPlugin {
    /// The plugin name.
    name: String,
    /// Field layouts by name.
    field_layouts: HashMap<String, FieldLayout>,
    /// Code unit formats by type.
    formats: HashMap<CodeUnitType, CodeUnitFormat>,
    /// Connected providers.
    providers: Vec<ListingProvider>,
    /// Whether the plugin is initialized.
    initialized: bool,
    /// Whether the plugin is disposed.
    disposed: bool,
    /// Plugin options.
    options: HashMap<String, ListingOption>,
}

/// A listing plugin option.
#[derive(Debug, Clone)]
pub enum ListingOption {
    /// Boolean option.
    Bool(bool),
    /// Integer option.
    Int(i32),
    /// String option.
    String(String),
}

impl fmt::Display for ListingOption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bool(v) => write!(f, "{}", v),
            Self::Int(v) => write!(f, "{}", v),
            Self::String(v) => write!(f, "{}", v),
        }
    }
}

impl ListingPlugin {
    /// Creates a new listing plugin.
    pub fn new(name: impl Into<String>) -> Self {
        let mut plugin = Self {
            name: name.into(),
            field_layouts: HashMap::new(),
            formats: HashMap::new(),
            providers: Vec::new(),
            initialized: false,
            disposed: false,
            options: HashMap::new(),
        };
        plugin.init_default_layouts();
        plugin.init_default_formats();
        plugin
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

    /// Disposes the plugin.
    pub fn dispose(&mut self) {
        if self.disposed {
            return;
        }
        self.disposed = true;
        self.providers.clear();
        self.field_layouts.clear();
        self.formats.clear();
    }

    /// Returns whether the plugin is initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Returns whether the plugin is disposed.
    pub fn is_disposed(&self) -> bool {
        self.disposed
    }

    // ---- Provider management ----

    /// Adds a provider to the plugin.
    pub fn add_provider(&mut self, provider: ListingProvider) {
        self.providers.push(provider);
    }

    /// Returns the number of providers.
    pub fn provider_count(&self) -> usize {
        self.providers.len()
    }

    /// Returns a reference to a provider by index.
    pub fn provider(&self, index: usize) -> Option<&ListingProvider> {
        self.providers.get(index)
    }

    /// Returns a mutable reference to a provider by index.
    pub fn provider_mut(&mut self, index: usize) -> Option<&mut ListingProvider> {
        self.providers.get_mut(index)
    }

    /// Returns a reference to all providers.
    pub fn providers(&self) -> &[ListingProvider] {
        &self.providers
    }

    /// Returns a mutable reference to all providers.
    pub fn providers_mut(&mut self) -> &mut Vec<ListingProvider> {
        &mut self.providers
    }

    // ---- Field layout management ----

    /// Adds a field layout.
    pub fn add_field_layout(&mut self, layout: FieldLayout) {
        self.field_layouts.insert(layout.name.clone(), layout);
    }

    /// Returns a reference to a field layout by name.
    pub fn field_layout(&self, name: &str) -> Option<&FieldLayout> {
        self.field_layouts.get(name)
    }

    /// Returns a mutable reference to a field layout by name.
    pub fn field_layout_mut(&mut self, name: &str) -> Option<&mut FieldLayout> {
        self.field_layouts.get_mut(name)
    }

    /// Returns the number of field layouts.
    pub fn field_layout_count(&self) -> usize {
        self.field_layouts.len()
    }

    /// Returns all visible field layouts, sorted by priority.
    pub fn visible_field_layouts(&self) -> Vec<&FieldLayout> {
        let mut layouts: Vec<_> = self.field_layouts.values().filter(|l| l.visible).collect();
        layouts.sort_by_key(|l| l.priority);
        layouts
    }

    // ---- Format management ----

    /// Sets the format for a code unit type.
    pub fn set_format(&mut self, code_unit_type: CodeUnitType, format: CodeUnitFormat) {
        self.formats.insert(code_unit_type, format);
    }

    /// Returns the format for a code unit type.
    pub fn format(&self, code_unit_type: &CodeUnitType) -> Option<&CodeUnitFormat> {
        self.formats.get(code_unit_type)
    }

    // ---- Option management ----

    /// Sets a plugin option.
    pub fn set_option(&mut self, key: impl Into<String>, value: ListingOption) {
        self.options.insert(key.into(), value);
    }

    /// Gets a plugin option.
    pub fn get_option(&self, key: &str) -> Option<&ListingOption> {
        self.options.get(key)
    }

    // ---- Initialization helpers ----

    /// Initializes default field layouts.
    fn init_default_layouts(&mut self) {
        self.field_layouts.insert(
            "address".to_string(),
            FieldLayout::new("address", 0, 16)
                .with_alignment(FieldAlignment::Left)
                .with_priority(10),
        );
        self.field_layouts.insert(
            "bytes".to_string(),
            FieldLayout::new("bytes", 1, 24)
                .with_alignment(FieldAlignment::Left)
                .with_priority(20),
        );
        self.field_layouts.insert(
            "mnemonic".to_string(),
            FieldLayout::new("mnemonic", 2, 12)
                .with_alignment(FieldAlignment::Left)
                .with_priority(30),
        );
        self.field_layouts.insert(
            "operand".to_string(),
            FieldLayout::new("operand", 3, 30)
                .with_alignment(FieldAlignment::Left)
                .with_priority(40),
        );
        self.field_layouts.insert(
            "comment".to_string(),
            FieldLayout::new("comment", 4, 40)
                .with_alignment(FieldAlignment::Left)
                .with_priority(50),
        );
    }

    /// Initializes default code unit formats.
    fn init_default_formats(&mut self) {
        self.formats.insert(
            CodeUnitType::Instruction,
            CodeUnitFormat::new(CodeUnitType::Instruction),
        );
        self.formats.insert(
            CodeUnitType::DefinedData,
            CodeUnitFormat::new(CodeUnitType::DefinedData),
        );
        self.formats.insert(
            CodeUnitType::UndefinedData,
            CodeUnitFormat {
                code_unit_type: CodeUnitType::UndefinedData,
                show_address: true,
                show_bytes: true,
                show_comments: false,
                show_labels: true,
                max_line_width: 120,
            },
        );
        self.formats.insert(
            CodeUnitType::FunctionEntry,
            CodeUnitFormat::new(CodeUnitType::FunctionEntry),
        );
        self.formats.insert(
            CodeUnitType::Label,
            CodeUnitFormat {
                code_unit_type: CodeUnitType::Label,
                show_address: true,
                show_bytes: false,
                show_comments: false,
                show_labels: true,
                max_line_width: 120,
            },
        );
        self.formats.insert(
            CodeUnitType::Comment,
            CodeUnitFormat {
                code_unit_type: CodeUnitType::Comment,
                show_address: false,
                show_bytes: false,
                show_comments: true,
                show_labels: false,
                max_line_width: 120,
            },
        );
    }
}

impl Default for ListingPlugin {
    fn default() -> Self {
        Self::new("ListingPlugin")
    }
}

impl fmt::Display for ListingPlugin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ListingPlugin({})", self.name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_creation() {
        let plugin = ListingPlugin::new("TestPlugin");
        assert_eq!(plugin.name(), "TestPlugin");
        assert!(!plugin.is_initialized());
        assert!(plugin.field_layout_count() > 0);
        assert_eq!(plugin.provider_count(), 0);
    }

    #[test]
    fn test_field_layouts() {
        let plugin = ListingPlugin::new("TestPlugin");
        assert!(plugin.field_layout("address").is_some());
        assert!(plugin.field_layout("bytes").is_some());
        assert!(plugin.field_layout("mnemonic").is_some());
        assert!(plugin.field_layout("nonexistent").is_none());
    }

    #[test]
    fn test_formats() {
        let plugin = ListingPlugin::new("TestPlugin");
        assert!(plugin.format(&CodeUnitType::Instruction).is_some());
        assert!(plugin.format(&CodeUnitType::DefinedData).is_some());
        assert!(plugin.format(&CodeUnitType::UndefinedData).is_some());
    }

    #[test]
    fn test_visible_field_layouts() {
        let plugin = ListingPlugin::new("TestPlugin");
        let visible = plugin.visible_field_layouts();
        assert!(!visible.is_empty());
        // Should be sorted by priority
        for i in 1..visible.len() {
            assert!(visible[i - 1].priority <= visible[i].priority);
        }
    }

    #[test]
    fn test_init_dispose() {
        let mut plugin = ListingPlugin::new("TestPlugin");
        plugin.init();
        assert!(plugin.is_initialized());
        plugin.dispose();
        assert!(plugin.is_disposed());
    }

    #[test]
    fn test_provider_management() {
        let mut plugin = ListingPlugin::new("TestPlugin");
        let provider = ListingProvider::new("Provider1", true);
        plugin.add_provider(provider);
        assert_eq!(plugin.provider_count(), 1);
        assert!(plugin.provider(0).is_some());
        assert!(plugin.provider(1).is_none());
    }

    #[test]
    fn test_options() {
        let mut plugin = ListingPlugin::new("TestPlugin");
        plugin.set_option("show_line_numbers", ListingOption::Bool(true));
        plugin.set_option("tab_size", ListingOption::Int(4));
        assert!(matches!(plugin.get_option("show_line_numbers"), Some(ListingOption::Bool(true))));
        assert!(matches!(plugin.get_option("tab_size"), Some(ListingOption::Int(4))));
        assert!(plugin.get_option("nonexistent").is_none());
    }
}
