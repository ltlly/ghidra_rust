//! AbstractOptions: base implementation for the Options trait.
//!
//! Port of `ghidra.framework.options.AbstractOptions`.
//!
//! Provides a concrete base for options implementations that stores options
//! in a hierarchical tree structure and implements most of the [`Options`] trait
//! automatically.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use crate::gui_util::help_location::HelpLocation;
use crate::gui_util::web_colors::RgbaColor;
use super::action_trigger::ActionTrigger;
use super::option_type::OptionType;
use super::option_value::{FontDescriptor, KeyStroke, OptionValue};
use super::options_trait::{Options, OptionsChangeListener, DELIMITER};

// ============================================================================
// OptionDefinition
// ============================================================================

/// Metadata about a registered option.
#[derive(Debug, Clone)]
pub struct OptionDefinition {
    /// The option name.
    pub name: String,
    /// The type of this option.
    pub option_type: OptionType,
    /// The default value.
    pub default_value: OptionValue,
    /// A human-readable description.
    pub description: String,
    /// Help location for this option.
    pub help_location: Option<HelpLocation>,
    /// The current value.
    pub value: OptionValue,
}

impl OptionDefinition {
    /// Create a new option definition.
    pub fn new(
        name: impl Into<String>,
        option_type: OptionType,
        default_value: OptionValue,
        description: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            option_type,
            default_value: default_value.clone(),
            description: description.into(),
            help_location: None,
            value: default_value,
        }
    }

    /// Set the help location.
    pub fn with_help_location(mut self, help: HelpLocation) -> Self {
        self.help_location = Some(help);
        self
    }

    /// Whether the current value equals the default.
    pub fn is_default(&self) -> bool {
        self.value == self.default_value
    }

    /// Restore the default value.
    pub fn restore_default(&mut self) {
        self.value = self.default_value.clone();
    }
}

// ============================================================================
// AbstractOptions
// ============================================================================

/// Base implementation for the [`Options`] trait.
///
/// Stores options in a flat map keyed by name, with support for
/// child options (sub-options groups).
///
/// Port of `ghidra.framework.options.AbstractOptions`.
pub struct AbstractOptions {
    /// Name of this options group.
    name: String,
    /// Registered option definitions.
    options: BTreeMap<String, OptionDefinition>,
    /// Child options groups.
    children: BTreeMap<String, Box<AbstractOptions>>,
    /// Change listeners.
    listeners: Vec<Arc<dyn OptionsChangeListener>>,
}

impl std::fmt::Debug for AbstractOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AbstractOptions")
            .field("name", &self.name)
            .field("options_count", &self.options.len())
            .field("children_count", &self.children.len())
            .field("listeners_count", &self.listeners.len())
            .finish()
    }
}

impl AbstractOptions {
    /// Create a new abstract options group.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            options: BTreeMap::new(),
            children: BTreeMap::new(),
            listeners: Vec::new(),
        }
    }

    /// Register a new option.
    pub fn register(
        &mut self,
        name: impl Into<String>,
        option_type: OptionType,
        default_value: OptionValue,
        description: impl Into<String>,
    ) {
        let name = name.into();
        let def = OptionDefinition::new(name.clone(), option_type, default_value, description);
        self.options.insert(name, def);
    }

    /// Register an option with help location.
    pub fn register_with_help(
        &mut self,
        name: impl Into<String>,
        option_type: OptionType,
        default_value: OptionValue,
        description: impl Into<String>,
        help: HelpLocation,
    ) {
        let name = name.into();
        let def = OptionDefinition::new(name.clone(), option_type, default_value, description)
            .with_help_location(help);
        self.options.insert(name, def);
    }

    /// Add a child options group.
    pub fn add_child(&mut self, child: AbstractOptions) {
        let name = child.name.clone();
        self.children.insert(name, Box::new(child));
    }

    /// Get a child options group by name.
    pub fn get_child(&self, name: &str) -> Option<&AbstractOptions> {
        self.children.get(name).map(|b| b.as_ref())
    }

    /// Get a mutable reference to a child options group by name.
    pub fn get_child_mut(&mut self, name: &str) -> Option<&mut AbstractOptions> {
        self.children.get_mut(name).map(|b| b.as_mut())
    }

    /// Add a change listener.
    pub fn add_listener(&mut self, listener: Arc<dyn OptionsChangeListener>) {
        self.listeners.push(listener);
    }

    /// Get the underlying option definitions.
    pub fn definitions(&self) -> &BTreeMap<String, OptionDefinition> {
        &self.options
    }

    /// Get a mutable reference to the underlying option definitions.
    pub fn definitions_mut(&mut self) -> &mut BTreeMap<String, OptionDefinition> {
        &mut self.options
    }

    /// Get the number of registered options.
    pub fn option_count(&self) -> usize {
        self.options.len()
    }

    /// Whether this options group has any registered options.
    pub fn has_options(&self) -> bool {
        !self.options.is_empty()
    }
}

impl Options for AbstractOptions {
    fn name(&self) -> &str {
        &self.name
    }

    fn get_id(&self, option_name: &str) -> String {
        format!("{}{}{}", self.name, DELIMITER, option_name)
    }

    fn get_type(&self, option_name: &str) -> OptionType {
        self.options
            .get(option_name)
            .map(|d| d.option_type)
            .unwrap_or(OptionType::NoType)
    }

    fn contains(&self, option_name: &str) -> bool {
        self.options.contains_key(option_name)
    }

    fn get_description(&self, option_name: &str) -> Option<String> {
        self.options.get(option_name).map(|d| d.description.clone())
    }

    fn get_help_location(&self, option_name: &str) -> Option<HelpLocation> {
        self.options.get(option_name).and_then(|d| d.help_location.clone())
    }

    fn is_registered(&self, option_name: &str) -> bool {
        self.options.contains_key(option_name)
    }

    fn is_default_value(&self, option_name: &str) -> bool {
        self.options.get(option_name).map_or(false, |d| d.is_default())
    }

    fn get_default_value(&self, option_name: &str) -> OptionValue {
        self.options
            .get(option_name)
            .map(|d| d.default_value.clone())
            .unwrap_or(OptionValue::None)
    }

    fn restore_default_value(&mut self, option_name: &str) {
        if let Some(def) = self.options.get_mut(option_name) {
            def.restore_default();
        }
    }

    fn restore_default_values(&mut self) {
        for def in self.options.values_mut() {
            def.restore_default();
        }
    }

    fn get_child_options(&self) -> Vec<String> {
        self.children.keys().cloned().collect()
    }

    fn get_option_names(&self) -> Vec<String> {
        self.options.keys().cloned().collect()
    }

    fn get_boolean(&self, option_name: &str, default: bool) -> bool {
        match self.options.get(option_name) {
            Some(def) => match &def.value {
                OptionValue::Boolean(b) => *b,
                _ => default,
            },
            None => default,
        }
    }

    fn get_int(&self, option_name: &str, default: i32) -> i32 {
        match self.options.get(option_name) {
            Some(def) => match &def.value {
                OptionValue::Int(n) => *n,
                _ => default,
            },
            None => default,
        }
    }

    fn get_long(&self, option_name: &str, default: i64) -> i64 {
        match self.options.get(option_name) {
            Some(def) => match &def.value {
                OptionValue::Long(n) => *n,
                _ => default,
            },
            None => default,
        }
    }

    fn get_float(&self, option_name: &str, default: f32) -> f32 {
        match self.options.get(option_name) {
            Some(def) => match &def.value {
                OptionValue::Float(n) => *n,
                _ => default,
            },
            None => default,
        }
    }

    fn get_double(&self, option_name: &str, default: f64) -> f64 {
        match self.options.get(option_name) {
            Some(def) => match &def.value {
                OptionValue::Double(n) => *n,
                _ => default,
            },
            None => default,
        }
    }

    fn get_string(&self, option_name: &str, default: &str) -> String {
        match self.options.get(option_name) {
            Some(def) => match &def.value {
                OptionValue::String(s) => s.clone(),
                _ => default.to_string(),
            },
            None => default.to_string(),
        }
    }

    fn get_byte_array(&self, option_name: &str, default: &[u8]) -> Vec<u8> {
        match self.options.get(option_name) {
            Some(def) => match &def.value {
                OptionValue::ByteArray(v) => v.clone(),
                _ => default.to_vec(),
            },
            None => default.to_vec(),
        }
    }

    fn get_color(&self, option_name: &str, default: RgbaColor) -> RgbaColor {
        match self.options.get(option_name) {
            Some(def) => match &def.value {
                OptionValue::Color(c) => *c,
                _ => default,
            },
            None => default,
        }
    }

    fn get_font(&self, option_name: &str, default: &FontDescriptor) -> FontDescriptor {
        match self.options.get(option_name) {
            Some(def) => match &def.value {
                OptionValue::Font(f) => f.clone(),
                _ => default.clone(),
            },
            None => default.clone(),
        }
    }

    fn get_key_stroke(&self, option_name: &str, _default: &KeyStroke) -> Option<KeyStroke> {
        match self.options.get(option_name) {
            Some(def) => match &def.value {
                OptionValue::KeyStroke(ks) => Some(ks.clone()),
                _ => None,
            },
            None => None,
        }
    }

    fn get_action_trigger(&self, option_name: &str, _default: &ActionTrigger) -> Option<ActionTrigger> {
        // ActionTrigger is a complex type; for now return None if not stored.
        let _ = option_name;
        None
    }

    fn get_file(&self, option_name: &str, default: &PathBuf) -> PathBuf {
        match self.options.get(option_name) {
            Some(def) => match &def.value {
                OptionValue::File(f) => f.clone(),
                _ => default.clone(),
            },
            None => default.clone(),
        }
    }

    fn set_boolean(&mut self, option_name: &str, value: bool) {
        if let Some(def) = self.options.get_mut(option_name) {
            def.value = OptionValue::Boolean(value);
        }
    }

    fn set_int(&mut self, option_name: &str, value: i32) {
        if let Some(def) = self.options.get_mut(option_name) {
            def.value = OptionValue::Int(value);
        }
    }

    fn set_long(&mut self, option_name: &str, value: i64) {
        if let Some(def) = self.options.get_mut(option_name) {
            def.value = OptionValue::Long(value);
        }
    }

    fn set_float(&mut self, option_name: &str, value: f32) {
        if let Some(def) = self.options.get_mut(option_name) {
            def.value = OptionValue::Float(value);
        }
    }

    fn set_double(&mut self, option_name: &str, value: f64) {
        if let Some(def) = self.options.get_mut(option_name) {
            def.value = OptionValue::Double(value);
        }
    }

    fn set_string(&mut self, option_name: &str, value: &str) {
        if let Some(def) = self.options.get_mut(option_name) {
            def.value = OptionValue::String(value.to_string());
        }
    }

    fn set_byte_array(&mut self, option_name: &str, value: &[u8]) {
        if let Some(def) = self.options.get_mut(option_name) {
            def.value = OptionValue::ByteArray(value.to_vec());
        }
    }

    fn set_color(&mut self, option_name: &str, value: RgbaColor) {
        if let Some(def) = self.options.get_mut(option_name) {
            def.value = OptionValue::Color(value);
        }
    }

    fn set_font(&mut self, option_name: &str, value: &FontDescriptor) {
        if let Some(def) = self.options.get_mut(option_name) {
            def.value = OptionValue::Font(value.clone());
        }
    }

    fn set_key_stroke(&mut self, option_name: &str, value: &KeyStroke) {
        if let Some(def) = self.options.get_mut(option_name) {
            def.value = OptionValue::KeyStroke(value.clone());
        }
    }

    fn set_action_trigger(&mut self, _option_name: &str, _value: &ActionTrigger) {
        // ActionTrigger storage not yet fully implemented.
    }

    fn set_file(&mut self, option_name: &str, value: &PathBuf) {
        if let Some(def) = self.options.get_mut(option_name) {
            def.value = OptionValue::File(value.clone());
        }
    }

    fn register_option(
        &mut self,
        option_name: &str,
        option_type: OptionType,
        default_value: OptionValue,
        help: Option<&HelpLocation>,
        description: &str,
    ) {
        let mut def = OptionDefinition::new(option_name, option_type, default_value, description);
        if let Some(h) = help {
            def.help_location = Some(h.clone());
        }
        self.options.insert(option_name.to_string(), def);
    }

    fn register_theme_color_binding(
        &mut self,
        option_name: &str,
        color_id: &str,
        help: Option<&HelpLocation>,
        description: &str,
    ) {
        let mut def = OptionDefinition::new(
            option_name,
            OptionType::ColorType,
            OptionValue::Color(RgbaColor::new(0, 0, 0)),
            description,
        );
        if let Some(h) = help {
            def.help_location = Some(h.clone());
        }
        let _ = color_id; // color_id is used in the theme system
        self.options.insert(option_name.to_string(), def);
    }

    fn register_theme_font_binding(
        &mut self,
        option_name: &str,
        font_id: &str,
        help: Option<&HelpLocation>,
        description: &str,
    ) {
        let mut def = OptionDefinition::new(
            option_name,
            OptionType::FontType,
            OptionValue::Font(FontDescriptor::plain("Monospaced", 12.0)),
            description,
        );
        if let Some(h) = help {
            def.help_location = Some(h.clone());
        }
        let _ = font_id; // font_id is used in the theme system
        self.options.insert(option_name.to_string(), def);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn abstract_options_basics() {
        let mut opts = AbstractOptions::new("Test");
        assert_eq!(opts.name(), "Test");
        assert_eq!(opts.option_count(), 0);
        opts.register("key1", OptionType::StringType, OptionValue::String("default".into()), "A string option");
        assert_eq!(opts.option_count(), 1);
        assert!(opts.contains("key1"));
    }

    #[test]
    fn abstract_options_get_set() {
        let mut opts = AbstractOptions::new("Test");
        opts.register("count", OptionType::IntType, OptionValue::Int(42), "A count");
        assert_eq!(opts.get_int("count", 0), 42);
        opts.set_int("count", 100);
        assert_eq!(opts.get_int("count", 0), 100);
        assert!(!opts.is_default_value("count"));
    }

    #[test]
    fn abstract_options_boolean() {
        let mut opts = AbstractOptions::new("Test");
        opts.register("flag", OptionType::BooleanType, OptionValue::Boolean(false), "A flag");
        assert!(!opts.get_boolean("flag", true));
        opts.set_boolean("flag", true);
        assert!(opts.get_boolean("flag", false));
    }

    #[test]
    fn abstract_options_double() {
        let mut opts = AbstractOptions::new("Test");
        opts.register("ratio", OptionType::DoubleType, OptionValue::Double(0.5), "A ratio");
        assert!((opts.get_double("ratio", 0.0) - 0.5).abs() < 1e-9);
        opts.set_double("ratio", 0.75);
        assert!((opts.get_double("ratio", 0.0) - 0.75).abs() < 1e-9);
    }

    #[test]
    fn abstract_options_float() {
        let mut opts = AbstractOptions::new("Test");
        opts.register("f", OptionType::FloatType, OptionValue::Float(1.5f32), "A float");
        assert!((opts.get_float("f", 0.0) - 1.5).abs() < 1e-5);
        opts.set_float("f", 2.5);
        assert!((opts.get_float("f", 0.0) - 2.5).abs() < 1e-5);
    }

    #[test]
    fn abstract_options_long() {
        let mut opts = AbstractOptions::new("Test");
        opts.register("big", OptionType::LongType, OptionValue::Long(1_000_000i64), "A long");
        assert_eq!(opts.get_long("big", 0), 1_000_000);
        opts.set_long("big", 2_000_000);
        assert_eq!(opts.get_long("big", 0), 2_000_000);
    }

    #[test]
    fn abstract_options_restore_default() {
        let mut opts = AbstractOptions::new("Test");
        opts.register("val", OptionType::IntType, OptionValue::Int(10), "A value");
        opts.set_int("val", 99);
        assert!(!opts.is_default_value("val"));
        opts.restore_default_value("val");
        assert!(opts.is_default_value("val"));
        assert_eq!(opts.get_int("val", 0), 10);
    }

    #[test]
    fn abstract_options_restore_all() {
        let mut opts = AbstractOptions::new("Test");
        opts.register("a", OptionType::IntType, OptionValue::Int(1), "");
        opts.register("b", OptionType::IntType, OptionValue::Int(2), "");
        opts.set_int("a", 100);
        opts.set_int("b", 200);
        opts.restore_default_values();
        assert_eq!(opts.get_int("a", 0), 1);
        assert_eq!(opts.get_int("b", 0), 2);
    }

    #[test]
    fn abstract_options_child() {
        let mut parent = AbstractOptions::new("Parent");
        let child = AbstractOptions::new("Child");
        parent.add_child(child);
        assert!(parent.get_child("Child").is_some());
        assert!(parent.get_child("Missing").is_none());
    }

    #[test]
    fn abstract_options_help_location() {
        let mut opts = AbstractOptions::new("Test");
        opts.register_with_help(
            "help_opt",
            OptionType::StringType,
            OptionValue::String("v".into()),
            "Has help",
            HelpLocation::new("HelpTopic", "anchor"),
        );
        let help = opts.get_help_location("help_opt").unwrap();
        assert_eq!(help.topic(), "HelpTopic");
    }

    #[test]
    fn abstract_options_default_value() {
        let mut opts = AbstractOptions::new("Test");
        opts.register("val", OptionType::IntType, OptionValue::Int(5), "");
        let default = opts.get_default_value("val");
        assert_eq!(default, OptionValue::Int(5));
    }

    #[test]
    fn abstract_options_option_type() {
        let mut opts = AbstractOptions::new("Test");
        opts.register("s", OptionType::StringType, OptionValue::String("".into()), "");
        opts.register("i", OptionType::IntType, OptionValue::Int(0), "");
        assert_eq!(opts.get_type("s"), OptionType::StringType);
        assert_eq!(opts.get_type("i"), OptionType::IntType);
        assert_eq!(opts.get_type("nonexistent"), OptionType::NoType);
    }

    #[test]
    fn abstract_options_value_missing() {
        let opts = AbstractOptions::new("Test");
        assert_eq!(opts.get_string("missing", "fallback"), "fallback");
        assert_eq!(opts.get_int("missing", 42), 42);
        assert!(opts.get_boolean("missing", true));
    }

    #[test]
    fn abstract_options_restore_default_noop() {
        let mut opts = AbstractOptions::new("Test");
        // Restore on non-existent option should be a no-op
        opts.restore_default_value("nonexistent");
    }

    #[test]
    fn abstract_options_byte_array() {
        let mut opts = AbstractOptions::new("Test");
        opts.register("data", OptionType::ByteArrayType, OptionValue::ByteArray(vec![1, 2, 3]), "");
        let v = opts.get_byte_array("data", &[]);
        assert_eq!(v, vec![1, 2, 3]);
        opts.set_byte_array("data", &[4, 5]);
        assert_eq!(opts.get_byte_array("data", &[]), vec![4, 5]);
    }

    #[test]
    fn abstract_options_color() {
        let mut opts = AbstractOptions::new("Test");
        let color = RgbaColor::new(255, 0, 0);
        opts.register("c", OptionType::ColorType, OptionValue::Color(color), "");
        let c = opts.get_color("c", RgbaColor::new(0, 0, 0));
        assert_eq!(c, color);
    }

    #[test]
    fn abstract_options_font() {
        let mut opts = AbstractOptions::new("Test");
        let font = FontDescriptor::bold("Arial", 14.0);
        opts.register("f", OptionType::FontType, OptionValue::Font(font.clone()), "");
        let f = opts.get_font("f", &FontDescriptor::plain("Mono", 10.0));
        assert_eq!(f.family, "Arial");
        assert!(f.is_bold());
    }

    #[test]
    fn abstract_options_register_option_trait() {
        let mut opts = AbstractOptions::new("Test");
        opts.register_option("x", OptionType::IntType, OptionValue::Int(5), None, "desc");
        assert!(opts.contains("x"));
        assert_eq!(opts.get_int("x", 0), 5);
        assert_eq!(opts.get_description("x").as_deref(), Some("desc"));
    }

    #[test]
    fn abstract_options_register_option_with_help() {
        let mut opts = AbstractOptions::new("Test");
        let help = HelpLocation::new("Topic", "anchor");
        opts.register_option("h", OptionType::StringType, OptionValue::String("v".into()), Some(&help), "has help");
        let h = opts.get_help_location("h").unwrap();
        assert_eq!(h.topic(), "Topic");
    }

    #[test]
    fn abstract_options_theme_color_binding() {
        let mut opts = AbstractOptions::new("Test");
        opts.register_theme_color_binding("bg", "color.bg", None, "Background color");
        assert!(opts.contains("bg"));
    }

    #[test]
    fn abstract_options_theme_font_binding() {
        let mut opts = AbstractOptions::new("Test");
        opts.register_theme_font_binding("code", "font.code", None, "Code font");
        assert!(opts.contains("code"));
    }

    #[test]
    fn abstract_options_is_registered() {
        let mut opts = AbstractOptions::new("Test");
        opts.register("a", OptionType::IntType, OptionValue::Int(1), "");
        assert!(opts.is_registered("a"));
        assert!(!opts.is_registered("b"));
    }

    #[test]
    fn abstract_options_option_names() {
        let mut opts = AbstractOptions::new("Test");
        opts.register("a", OptionType::IntType, OptionValue::Int(1), "");
        opts.register("b", OptionType::IntType, OptionValue::Int(2), "");
        let names = opts.get_option_names();
        assert_eq!(names.len(), 2);
        assert!(names.contains(&"a".to_string()));
        assert!(names.contains(&"b".to_string()));
    }

    #[test]
    fn abstract_options_child_options() {
        let mut parent = AbstractOptions::new("Parent");
        let child = AbstractOptions::new("Sub");
        parent.add_child(child);
        let children = parent.get_child_options();
        assert_eq!(children, vec!["Sub".to_string()]);
    }

    #[test]
    fn abstract_options_file() {
        let mut opts = AbstractOptions::new("Test");
        let path = PathBuf::from("/tmp/test.txt");
        opts.register("path", OptionType::FileType, OptionValue::File(path.clone()), "");
        assert_eq!(opts.get_file("path", &PathBuf::new()), path);
        let new_path = PathBuf::from("/tmp/other.txt");
        opts.set_file("path", &new_path);
        assert_eq!(opts.get_file("path", &PathBuf::new()), new_path);
    }

    #[test]
    fn abstract_options_key_stroke() {
        let mut opts = AbstractOptions::new("Test");
        let ks = KeyStroke::new("Ctrl+S");
        opts.register("shortcut", OptionType::KeyStrokeType, OptionValue::KeyStroke(ks.clone()), "");
        let result = opts.get_key_stroke("shortcut", &KeyStroke::new("F1"));
        assert!(result.is_some());
        assert_eq!(result.unwrap().representation, "Ctrl+S");
    }

    #[test]
    fn option_definition_is_default() {
        let mut def = OptionDefinition::new("x", OptionType::IntType, OptionValue::Int(5), "");
        assert!(def.is_default());
        def.value = OptionValue::Int(10);
        assert!(!def.is_default());
    }

    #[test]
    fn option_definition_restore_default() {
        let mut def = OptionDefinition::new("x", OptionType::IntType, OptionValue::Int(5), "");
        def.value = OptionValue::Int(10);
        def.restore_default();
        assert!(def.is_default());
        assert_eq!(def.value, OptionValue::Int(5));
    }

    #[test]
    fn option_definition_with_help() {
        let def = OptionDefinition::new("x", OptionType::IntType, OptionValue::Int(5), "desc")
            .with_help_location(HelpLocation::new("Topic", "anchor"));
        assert!(def.help_location.is_some());
        assert_eq!(def.help_location.unwrap().topic(), "Topic");
    }
}
