//! Concrete options store used by tools.
//!
//! Ports `ghidra.framework.options.ToolOptions` and
//! `ghidra.framework.options.AbstractOptions`.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use crate::gui_util::help_location::HelpLocation;
use crate::gui_util::web_colors::RgbaColor;
use super::action_trigger::ActionTrigger;
use super::option::OptionEntry;
use super::option_type::OptionType;
use super::option_value::{FontDescriptor, KeyStroke, OptionValue};
use super::options_trait::{Options, OptionsChangeListener, DELIMITER, DELIMITER_STR};

/// A concrete hierarchical options store.
///
/// Ported from Ghidra's `ToolOptions` / `AbstractOptions`.
pub struct ToolOptions {
    /// Display name for this options node.
    name: String,
    /// Prefix for all option names (for sub-options).
    prefix: String,
    /// Stored options keyed by their full (prefixed) name.
    value_map: HashMap<String, OptionEntry>,
    /// Alias map for renamed options.
    alias_map: HashMap<String, String>,
    /// Help locations for categories.
    category_help_map: HashMap<String, HelpLocation>,
    /// Registered change listeners.
    listeners: Vec<Arc<dyn OptionsChangeListener>>,
}

impl std::fmt::Debug for ToolOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ToolOptions")
            .field("name", &self.name)
            .field("prefix", &self.prefix)
            .field("options_count", &self.value_map.len())
            .finish()
    }
}

impl ToolOptions {
    /// Create a new root options object.
    pub fn new(name: impl Into<String>) -> Self {
        let name = name.into();
        Self {
            name: name.clone(),
            prefix: String::new(),
            value_map: HashMap::new(),
            alias_map: HashMap::new(),
            category_help_map: HashMap::new(),
            listeners: Vec::new(),
        }
    }

    /// Get the option entry (or `None` if not found).
    pub fn get_option(&self, name: &str) -> Option<&OptionEntry> {
        let full = self.full_name(name);
        self.value_map.get(&full)
    }

    /// Get a mutable reference to the option entry.
    pub fn get_option_mut(&mut self, name: &str) -> Option<&mut OptionEntry> {
        let full = self.full_name(name);
        self.value_map.get_mut(&full)
    }

    /// Add a change listener.
    pub fn add_options_change_listener(&mut self, listener: Arc<dyn OptionsChangeListener>) {
        self.listeners.push(listener);
    }

    /// Remove a change listener. Returns true if found and removed.
    pub fn remove_options_change_listener(&mut self, listener_id: usize) -> bool {
        // Simple removal by index for now.
        if listener_id < self.listeners.len() {
            self.listeners.remove(listener_id);
            true
        } else {
            false
        }
    }

    /// Set the help location for a category.
    pub fn set_category_help_location(&mut self, prefix: &str, help: HelpLocation) {
        self.category_help_map.insert(prefix.to_string(), help);
    }

    /// Get the help location for a category.
    pub fn get_category_help_location(&self, prefix: &str) -> Option<&HelpLocation> {
        self.category_help_map.get(prefix)
    }

    /// Put a raw value into the map, creating the option if needed.
    pub fn put_object(&mut self, name: &str, value: OptionValue, option_type: OptionType) {
        let full = self.full_name(name);
        if let Some(opt) = self.value_map.get_mut(&full) {
            let old_value = opt.current_value().clone();
            opt.set_current_value(value.clone());
            self.notify_changed(name, &old_value, &value);
        } else {
            let opt = OptionEntry::new_unregistered(&full, option_type, value);
            self.value_map.insert(full, opt);
        }
    }

    /// Register an option.
    fn do_register(
        &mut self,
        name: &str,
        option_type: OptionType,
        default_value: OptionValue,
        help: Option<&HelpLocation>,
        description: &str,
    ) {
        let full = self.full_name(name);
        let mut opt = OptionEntry::new(&full, option_type, default_value)
            .with_description(description);
        if let Some(h) = help {
            opt = opt.with_help_location(h.clone());
        }
        self.value_map.insert(full, opt);
    }

    /// Full name with prefix.
    fn full_name(&self, name: &str) -> String {
        if self.prefix.is_empty() {
            name.to_string()
        } else {
            format!("{}{}", self.prefix, name)
        }
    }

    /// Notify listeners of a change.
    fn notify_changed(&self, name: &str, old_value: &OptionValue, new_value: &OptionValue) {
        for listener in &self.listeners {
            // A veto (return false) would revert, but we don't store a back-pointer
            // to self for reverting here; the caller can handle it.
            listener.options_changed(self, name, old_value, new_value);
        }
    }

    /// Extract child category names from a list of option paths.
    pub fn get_child_categories(option_names: &[String]) -> Vec<String> {
        let mut categories = std::collections::BTreeSet::new();
        for name in option_names {
            if let Some(pos) = name.find(DELIMITER) {
                categories.insert(name[..pos].to_string());
            }
        }
        categories.into_iter().collect()
    }

    /// Get only the leaf option names (no further dots).
    pub fn get_leaves(option_names: &[String]) -> Vec<String> {
        option_names
            .iter()
            .filter(|n| !n.contains(DELIMITER))
            .cloned()
            .collect()
    }
}

impl Options for ToolOptions {
    fn name(&self) -> &str {
        &self.name
    }

    fn get_id(&self, option_name: &str) -> String {
        self.full_name(option_name)
    }

    fn get_type(&self, option_name: &str) -> OptionType {
        self.get_option(option_name)
            .map(|o| o.option_type())
            .unwrap_or(OptionType::NoType)
    }

    fn contains(&self, option_name: &str) -> bool {
        let full = self.full_name(option_name);
        self.value_map.contains_key(&full) || self.alias_map.contains_key(&full)
    }

    fn get_description(&self, option_name: &str) -> Option<String> {
        self.get_option(option_name).and_then(|o| o.description().map(|s| s.to_string()))
    }

    fn get_help_location(&self, option_name: &str) -> Option<HelpLocation> {
        self.get_option(option_name).and_then(|o| o.help_location().cloned())
    }

    fn is_registered(&self, option_name: &str) -> bool {
        self.get_option(option_name).map(|o| o.is_registered()).unwrap_or(false)
    }

    fn is_default_value(&self, option_name: &str) -> bool {
        self.get_option(option_name).map(|o| o.is_default()).unwrap_or(true)
    }

    fn get_default_value(&self, option_name: &str) -> OptionValue {
        self.get_option(option_name)
            .map(|o| o.default_value().clone())
            .unwrap_or(OptionValue::None)
    }

    fn restore_default_value(&mut self, option_name: &str) {
        let full = self.full_name(option_name);
        if let Some(opt) = self.value_map.get_mut(&full) {
            if !opt.is_default() {
                let old = opt.current_value().clone();
                opt.restore_default();
                let new = opt.current_value().clone();
                self.notify_changed(option_name, &old, &new);
            }
        }
    }

    fn restore_default_values(&mut self) {
        let names: Vec<String> = self.value_map.keys().cloned().collect();
        for full_name in names {
            let short = full_name.strip_prefix(&self.prefix).unwrap_or(&full_name);
            let short_owned = short.to_string();
            if let Some(opt) = self.value_map.get_mut(&full_name) {
                if !opt.is_default() {
                    let old = opt.current_value().clone();
                    opt.restore_default();
                    let new = opt.current_value().clone();
                    drop(opt); // release borrow
                    self.notify_changed(&short_owned, &old, &new);
                }
            }
        }
    }

    fn get_child_options(&self) -> Vec<String> {
        let names: Vec<String> = self.value_map.keys().cloned().collect();
        Self::get_child_categories(&names)
    }

    fn get_option_names(&self) -> Vec<String> {
        self.value_map.keys().cloned().collect()
    }

    fn get_boolean(&self, option_name: &str, default: bool) -> bool {
        match self.get_option(option_name).map(|o| o.current_value()) {
            Some(OptionValue::Boolean(v)) => *v,
            _ => default,
        }
    }

    fn get_int(&self, option_name: &str, default: i32) -> i32 {
        match self.get_option(option_name).map(|o| o.current_value()) {
            Some(OptionValue::Int(v)) => *v,
            _ => default,
        }
    }

    fn get_long(&self, option_name: &str, default: i64) -> i64 {
        match self.get_option(option_name).map(|o| o.current_value()) {
            Some(OptionValue::Long(v)) => *v,
            _ => default,
        }
    }

    fn get_float(&self, option_name: &str, default: f32) -> f32 {
        match self.get_option(option_name).map(|o| o.current_value()) {
            Some(OptionValue::Float(v)) => *v,
            _ => default,
        }
    }

    fn get_double(&self, option_name: &str, default: f64) -> f64 {
        match self.get_option(option_name).map(|o| o.current_value()) {
            Some(OptionValue::Double(v)) => *v,
            _ => default,
        }
    }

    fn get_string(&self, option_name: &str, default: &str) -> String {
        match self.get_option(option_name).map(|o| o.current_value()) {
            Some(OptionValue::String(v)) => v.clone(),
            _ => default.to_string(),
        }
    }

    fn get_byte_array(&self, option_name: &str, default: &[u8]) -> Vec<u8> {
        match self.get_option(option_name).map(|o| o.current_value()) {
            Some(OptionValue::ByteArray(v)) => v.clone(),
            _ => default.to_vec(),
        }
    }

    fn get_color(&self, option_name: &str, default: RgbaColor) -> RgbaColor {
        match self.get_option(option_name).map(|o| o.current_value()) {
            Some(OptionValue::Color(v)) => *v,
            _ => default,
        }
    }

    fn get_font(&self, option_name: &str, default: &FontDescriptor) -> FontDescriptor {
        match self.get_option(option_name).map(|o| o.current_value()) {
            Some(OptionValue::Font(v)) => v.clone(),
            _ => default.clone(),
        }
    }

    fn get_key_stroke(&self, option_name: &str, default: &KeyStroke) -> Option<KeyStroke> {
        match self.get_option(option_name).map(|o| o.current_value()) {
            Some(OptionValue::KeyStroke(v)) => Some(v.clone()),
            _ => Some(default.clone()),
        }
    }

    fn get_action_trigger(&self, option_name: &str, default: &ActionTrigger) -> Option<ActionTrigger> {
        match self.get_option(option_name).map(|o| o.current_value()) {
            Some(OptionValue::Custom(v)) => ActionTrigger::parse(v),
            _ => Some(default.clone()),
        }
    }

    fn get_file(&self, option_name: &str, default: &PathBuf) -> PathBuf {
        match self.get_option(option_name).map(|o| o.current_value()) {
            Some(OptionValue::File(v)) => v.clone(),
            _ => default.clone(),
        }
    }

    fn set_boolean(&mut self, option_name: &str, value: bool) {
        self.put_object(option_name, OptionValue::Boolean(value), OptionType::BooleanType);
    }

    fn set_int(&mut self, option_name: &str, value: i32) {
        self.put_object(option_name, OptionValue::Int(value), OptionType::IntType);
    }

    fn set_long(&mut self, option_name: &str, value: i64) {
        self.put_object(option_name, OptionValue::Long(value), OptionType::LongType);
    }

    fn set_float(&mut self, option_name: &str, value: f32) {
        self.put_object(option_name, OptionValue::Float(value), OptionType::FloatType);
    }

    fn set_double(&mut self, option_name: &str, value: f64) {
        self.put_object(option_name, OptionValue::Double(value), OptionType::DoubleType);
    }

    fn set_string(&mut self, option_name: &str, value: &str) {
        self.put_object(option_name, OptionValue::String(value.to_string()), OptionType::StringType);
    }

    fn set_byte_array(&mut self, option_name: &str, value: &[u8]) {
        self.put_object(option_name, OptionValue::ByteArray(value.to_vec()), OptionType::ByteArrayType);
    }

    fn set_color(&mut self, option_name: &str, value: RgbaColor) {
        self.put_object(option_name, OptionValue::Color(value), OptionType::ColorType);
    }

    fn set_font(&mut self, option_name: &str, value: &FontDescriptor) {
        self.put_object(option_name, OptionValue::Font(value.clone()), OptionType::FontType);
    }

    fn set_key_stroke(&mut self, option_name: &str, value: &KeyStroke) {
        self.put_object(option_name, OptionValue::KeyStroke(value.clone()), OptionType::KeyStrokeType);
    }

    fn set_action_trigger(&mut self, option_name: &str, value: &ActionTrigger) {
        self.put_object(option_name, OptionValue::Custom(value.to_string()), OptionType::ActionTrigger);
    }

    fn set_file(&mut self, option_name: &str, value: &PathBuf) {
        self.put_object(option_name, OptionValue::File(value.clone()), OptionType::FileType);
    }

    fn register_option(
        &mut self,
        option_name: &str,
        option_type: OptionType,
        default_value: OptionValue,
        help: Option<&HelpLocation>,
        description: &str,
    ) {
        self.do_register(option_name, option_type, default_value, help, description);
    }

    fn register_theme_color_binding(
        &mut self,
        option_name: &str,
        color_id: &str,
        help: Option<&HelpLocation>,
        description: &str,
    ) {
        // Store the color ID as a string; resolution happens at theme level.
        self.do_register(
            option_name,
            OptionType::ColorType,
            OptionValue::String(color_id.to_string()),
            help,
            description,
        );
    }

    fn register_theme_font_binding(
        &mut self,
        option_name: &str,
        font_id: &str,
        help: Option<&HelpLocation>,
        description: &str,
    ) {
        self.do_register(
            option_name,
            OptionType::FontType,
            OptionValue::String(font_id.to_string()),
            help,
            description,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tool_options_basics() {
        let mut opts = ToolOptions::new("Test");
        assert_eq!(opts.name(), "Test");
        opts.set_int("count", 42);
        assert_eq!(opts.get_int("count", 0), 42);
    }

    #[test]
    fn test_tool_options_all_types() {
        let mut opts = ToolOptions::new("Types");

        opts.set_boolean("b", true);
        assert!(opts.get_boolean("b", false));

        opts.set_long("l", 123456789i64);
        assert_eq!(opts.get_long("l", 0), 123456789);

        opts.set_float("f", 3.14);
        assert!((opts.get_float("f", 0.0) - 3.14).abs() < 0.001);

        opts.set_double("d", 2.718);
        assert!((opts.get_double("d", 0.0) - 2.718).abs() < 0.001);

        opts.set_string("s", "hello");
        assert_eq!(opts.get_string("s", ""), "hello");

        opts.set_color("c", RgbaColor::new(255, 0, 0));
        assert_eq!(opts.get_color("c", RgbaColor::new(0, 0, 0)), RgbaColor::new(255, 0, 0));

        opts.set_byte_array("ba", &[1, 2, 3]);
        assert_eq!(opts.get_byte_array("ba", &[]), vec![1, 2, 3]);
    }

    #[test]
    fn test_tool_options_register() {
        let mut opts = ToolOptions::new("Reg");
        let help = HelpLocation::new("Plugin", "option");
        opts.register_option(
            "test",
            OptionType::IntType,
            OptionValue::Int(10),
            Some(&help),
            "A test option",
        );
        assert!(opts.contains("test"));
        assert!(opts.is_registered("test"));
        assert!(opts.is_default_value("test"));
        assert_eq!(opts.get_description("test"), Some("A test option".to_string()));
        assert_eq!(opts.get_int("test", 0), 10);
    }

    #[test]
    fn test_tool_options_restore_default() {
        let mut opts = ToolOptions::new("Restore");
        opts.register_option("val", OptionType::IntType, OptionValue::Int(5), None, "");
        opts.set_int("val", 99);
        assert!(!opts.is_default_value("val"));
        opts.restore_default_value("val");
        assert!(opts.is_default_value("val"));
        assert_eq!(opts.get_int("val", 0), 5);
    }

    #[test]
    fn test_tool_options_restore_all() {
        let mut opts = ToolOptions::new("All");
        opts.register_option("a", OptionType::IntType, OptionValue::Int(1), None, "");
        opts.register_option("b", OptionType::BooleanType, OptionValue::Boolean(false), None, "");
        opts.set_int("a", 100);
        opts.set_boolean("b", true);
        opts.restore_default_values();
        assert_eq!(opts.get_int("a", 0), 1);
        assert!(!opts.get_boolean("b", true));
    }

    #[test]
    fn test_tool_options_contains() {
        let mut opts = ToolOptions::new("Contains");
        assert!(!opts.contains("missing"));
        opts.set_int("present", 1);
        assert!(opts.contains("present"));
    }

    #[test]
    fn test_child_categories() {
        let names = vec![
            "display.font".to_string(),
            "display.color".to_string(),
            "general.name".to_string(),
        ];
        let cats = ToolOptions::get_child_categories(&names);
        assert_eq!(cats, vec!["display", "general"]);
    }

    #[test]
    fn test_file_get_set() {
        let mut opts = ToolOptions::new("File");
        let path = PathBuf::from("/tmp/test.txt");
        opts.set_file("path", &path);
        assert_eq!(opts.get_file("path", &PathBuf::new()), path);
    }

    #[test]
    fn test_font_get_set() {
        let mut opts = ToolOptions::new("Font");
        let fd = FontDescriptor::bold("Arial", 14.0);
        opts.set_font("code_font", &fd);
        let got = opts.get_font("code_font", &FontDescriptor::plain("Courier", 12.0));
        assert_eq!(got.family, "Arial");
        assert!(got.is_bold());
    }

    #[test]
    fn test_key_stroke_get_set() {
        let mut opts = ToolOptions::new("KS");
        let ks = KeyStroke::new("Ctrl+S");
        opts.set_key_stroke("save", &ks);
        let got = opts.get_key_stroke("save", &KeyStroke::new("F1")).unwrap();
        assert_eq!(got.representation, "Ctrl+S");
    }
}
