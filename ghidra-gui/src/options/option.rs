//! Single option entry with current and default values.
//!
//! Ports `ghidra.framework.options.Option`.

use super::option_type::OptionType;
use super::option_value::OptionValue;
use crate::gui_util::help_location::HelpLocation;

/// A single registered option with its current value, default value,
/// description, and help location.
///
/// Ported from Ghidra's `ghidra.framework.options.Option`.
/// Named `OptionEntry` to avoid collision with `std::Option`.
#[derive(Debug, Clone)]
pub struct OptionEntry {
    /// Unique name within the options tree.
    name: String,
    /// The option type.
    option_type: OptionType,
    /// The current value.
    current_value: OptionValue,
    /// The default value.
    default_value: OptionValue,
    /// Human-readable description.
    description: Option<String>,
    /// Help location for this option.
    help_location: Option<HelpLocation>,
    /// Whether this option has been registered (vs. loaded from file).
    registered: bool,
}

impl OptionEntry {
    /// Create a new registered option.
    pub fn new(
        name: impl Into<String>,
        option_type: OptionType,
        default_value: OptionValue,
    ) -> Self {
        Self {
            name: name.into(),
            option_type,
            current_value: default_value.clone(),
            default_value,
            description: None,
            help_location: None,
            registered: true,
        }
    }

    /// Create an unregistered option (loaded from file).
    pub fn new_unregistered(
        name: impl Into<String>,
        option_type: OptionType,
        value: OptionValue,
    ) -> Self {
        Self {
            name: name.into(),
            option_type,
            current_value: value.clone(),
            default_value: value,
            description: None,
            help_location: None,
            registered: false,
        }
    }

    /// Set the description.
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }

    /// Set the help location.
    pub fn with_help_location(mut self, help: HelpLocation) -> Self {
        self.help_location = Some(help);
        self
    }

    /// Get the option name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the option type.
    pub fn option_type(&self) -> OptionType {
        self.option_type
    }

    /// Get the current value.
    pub fn current_value(&self) -> &OptionValue {
        &self.current_value
    }

    /// Set the current value.
    pub fn set_current_value(&mut self, value: OptionValue) {
        self.current_value = value;
    }

    /// Get the default value.
    pub fn default_value(&self) -> &OptionValue {
        &self.default_value
    }

    /// Get the description.
    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    /// Get the help location.
    pub fn help_location(&self) -> Option<&HelpLocation> {
        self.help_location.as_ref()
    }

    /// Whether this option was explicitly registered.
    pub fn is_registered(&self) -> bool {
        self.registered
    }

    /// Whether the current value equals the default.
    pub fn is_default(&self) -> bool {
        self.current_value == self.default_value
    }

    /// Restore the current value to the default.
    pub fn restore_default(&mut self) {
        self.current_value = self.default_value.clone();
    }

    /// Get the value with a fallback to the provided default if the
    /// current value is `None`.
    pub fn get_value(&self, fallback: &OptionValue) -> OptionValue {
        match &self.current_value {
            OptionValue::None => fallback.clone(),
            other => other.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_option_new() {
        let opt = OptionEntry::new("test.int", OptionType::IntType, OptionValue::Int(42));
        assert_eq!(opt.name(), "test.int");
        assert_eq!(opt.option_type(), OptionType::IntType);
        assert_eq!(*opt.current_value(), OptionValue::Int(42));
        assert!(opt.is_default());
    }

    #[test]
    fn test_option_set_value() {
        let mut opt = OptionEntry::new("test.str", OptionType::StringType, OptionValue::String("default".into()));
        opt.set_current_value(OptionValue::String("changed".into()));
        assert!(!opt.is_default());
        assert_eq!(*opt.current_value(), OptionValue::String("changed".into()));
    }

    #[test]
    fn test_option_restore_default() {
        let mut opt = OptionEntry::new("test.bool", OptionType::BooleanType, OptionValue::Boolean(false));
        opt.set_current_value(OptionValue::Boolean(true));
        assert!(!opt.is_default());
        opt.restore_default();
        assert!(opt.is_default());
    }

    #[test]
    fn test_option_with_description() {
        let opt = OptionEntry::new("test", OptionType::IntType, OptionValue::Int(0))
            .with_description("A test option");
        assert_eq!(opt.description(), Some("A test option"));
    }

    #[test]
    fn test_option_with_help() {
        let opt = OptionEntry::new("test", OptionType::IntType, OptionValue::Int(0))
            .with_help_location(HelpLocation::new("MyPlugin", "option_help"));
        assert!(opt.help_location().is_some());
    }

    #[test]
    fn test_option_unregistered() {
        let opt = OptionEntry::new_unregistered("loaded", OptionType::StringType, OptionValue::String("val".into()));
        assert!(!opt.is_registered());
    }

    #[test]
    fn test_option_get_value_with_fallback() {
        let opt = OptionEntry::new("test", OptionType::IntType, OptionValue::None);
        let fallback = OptionValue::Int(99);
        assert_eq!(opt.get_value(&fallback), OptionValue::Int(99));
    }
}
