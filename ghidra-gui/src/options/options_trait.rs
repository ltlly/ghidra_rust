//! The `Options` trait and change listener.
//!
//! Ports `ghidra.framework.options.Options` (the interface) and
//! `ghidra.framework.options.OptionsChangeListener`.

use std::path::PathBuf;

use crate::gui_util::help_location::HelpLocation;
use crate::gui_util::web_colors::RgbaColor;
use super::action_trigger::ActionTrigger;
use super::option_type::OptionType;
use super::option_value::{FontDescriptor, KeyStroke, OptionValue};
use super::tool_options::ToolOptions;

/// Delimiter for option path hierarchies.
pub const DELIMITER: char = '.';
/// Delimiter as a string.
pub const DELIMITER_STR: &str = ".";

/// Trait for change listeners that are notified when options change.
///
/// Ported from Ghidra's `ghidra.framework.options.OptionsChangeListener`.
pub trait OptionsChangeListener: Send + Sync {
    /// Called when an option value changes.
    ///
    /// Return `false` to reject (veto) the change.
    fn options_changed(
        &self,
        options: &ToolOptions,
        option_name: &str,
        old_value: &OptionValue,
        new_value: &OptionValue,
    ) -> bool {
        // Default: accept all changes.
        let _ = (options, option_name, old_value, new_value);
        true
    }
}

/// The `Options` trait -- the core interface for the options system.
///
/// Ported from Ghidra's `ghidra.framework.options.Options`.
pub trait Options: Send + Sync {
    /// Get the name of this options object.
    fn name(&self) -> &str;

    /// Get a unique ID for the option with the given name.
    fn get_id(&self, option_name: &str) -> String;

    /// Get the `OptionType` of the given option.
    fn get_type(&self, option_name: &str) -> OptionType;

    /// Check whether the named option exists.
    fn contains(&self, option_name: &str) -> bool;

    /// Get the description of the named option.
    fn get_description(&self, option_name: &str) -> Option<String>;

    /// Get the help location for the named option.
    fn get_help_location(&self, option_name: &str) -> Option<HelpLocation>;

    /// Whether the option was explicitly registered.
    fn is_registered(&self, option_name: &str) -> bool;

    /// Whether the option's current value equals its default.
    fn is_default_value(&self, option_name: &str) -> bool;

    /// Get the default value of the named option.
    fn get_default_value(&self, option_name: &str) -> OptionValue;

    /// Restore the default value for the named option.
    fn restore_default_value(&mut self, option_name: &str);

    /// Restore all option values to their defaults.
    fn restore_default_values(&mut self);

    /// Get a list of child options (one level down).
    fn get_child_options(&self) -> Vec<String>;

    /// Get a list of leaf option names.
    fn get_option_names(&self) -> Vec<String>;

    // -- Typed getters --

    fn get_boolean(&self, option_name: &str, default: bool) -> bool;
    fn get_int(&self, option_name: &str, default: i32) -> i32;
    fn get_long(&self, option_name: &str, default: i64) -> i64;
    fn get_float(&self, option_name: &str, default: f32) -> f32;
    fn get_double(&self, option_name: &str, default: f64) -> f64;
    fn get_string(&self, option_name: &str, default: &str) -> String;
    fn get_byte_array(&self, option_name: &str, default: &[u8]) -> Vec<u8>;
    fn get_color(&self, option_name: &str, default: RgbaColor) -> RgbaColor;
    fn get_font(&self, option_name: &str, default: &FontDescriptor) -> FontDescriptor;
    fn get_key_stroke(&self, option_name: &str, default: &KeyStroke) -> Option<KeyStroke>;
    fn get_action_trigger(&self, option_name: &str, default: &ActionTrigger) -> Option<ActionTrigger>;
    fn get_file(&self, option_name: &str, default: &PathBuf) -> PathBuf;

    // -- Typed setters --

    fn set_boolean(&mut self, option_name: &str, value: bool);
    fn set_int(&mut self, option_name: &str, value: i32);
    fn set_long(&mut self, option_name: &str, value: i64);
    fn set_float(&mut self, option_name: &str, value: f32);
    fn set_double(&mut self, option_name: &str, value: f64);
    fn set_string(&mut self, option_name: &str, value: &str);
    fn set_byte_array(&mut self, option_name: &str, value: &[u8]);
    fn set_color(&mut self, option_name: &str, value: RgbaColor);
    fn set_font(&mut self, option_name: &str, value: &FontDescriptor);
    fn set_key_stroke(&mut self, option_name: &str, value: &KeyStroke);
    fn set_action_trigger(&mut self, option_name: &str, value: &ActionTrigger);
    fn set_file(&mut self, option_name: &str, value: &PathBuf);

    // -- Registration --

    /// Register a new option with a default value, help location, and description.
    fn register_option(
        &mut self,
        option_name: &str,
        option_type: OptionType,
        default_value: OptionValue,
        help: Option<&HelpLocation>,
        description: &str,
    );

    /// Register a theme color binding.
    fn register_theme_color_binding(
        &mut self,
        option_name: &str,
        color_id: &str,
        help: Option<&HelpLocation>,
        description: &str,
    );

    /// Register a theme font binding.
    fn register_theme_font_binding(
        &mut self,
        option_name: &str,
        font_id: &str,
        help: Option<&HelpLocation>,
        description: &str,
    );
}

#[cfg(test)]
mod tests {
    

    // The trait is not directly testable without a concrete implementation;
    // tests are in tool_options/tests.
}
