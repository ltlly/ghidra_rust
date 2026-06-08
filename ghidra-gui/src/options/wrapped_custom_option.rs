//! Port of `ghidra.framework.options.WrappedCustomOption`.
//!
//! A wrapper for persisting custom option values as options. Stores a class
//! name and serialized state that can be written/read to/from a key/value map.

use super::option_type::OptionType;
use super::option_value::OptionValue;
use super::wrapped_option::WrappedOption;

/// Trait for custom option values that can be serialized to/from key/value state.
///
/// Ported from Ghidra's `ghidra.framework.options.CustomOption`.
pub trait CustomOption: std::fmt::Debug + Send + Sync {
    /// Read state from a key/value map.
    fn read_state(&mut self, state: &[(String, OptionValue)]);

    /// Write state into a key/value map.
    fn write_state(&self) -> Vec<(String, OptionValue)>;

    /// Get the class name of this custom option implementation.
    fn class_name(&self) -> &str;
}

/// Wrapper for a [`CustomOption`] that can be persisted as an option value.
///
/// Ported from Ghidra's `ghidra.framework.options.WrappedCustomOption`.
#[derive(Debug)]
pub struct WrappedCustomOption {
    /// The class name of the custom option implementation.
    class_name: String,
    /// The serialized state of the custom option.
    state: Vec<(String, OptionValue)>,
    /// Whether the custom option was deserialized successfully.
    valid: bool,
}

impl WrappedCustomOption {
    /// Create a new wrapper for a custom option.
    pub fn new(class_name: impl Into<String>) -> Self {
        Self {
            class_name: class_name.into(),
            state: Vec::new(),
            valid: true,
        }
    }

    /// Create a wrapper from a `CustomOption` trait object.
    pub fn from_custom_option(option: &dyn CustomOption) -> Self {
        Self {
            class_name: option.class_name().to_string(),
            state: option.write_state(),
            valid: true,
        }
    }

    /// Get the class name of the custom option.
    pub fn class_name(&self) -> &str {
        &self.class_name
    }

    /// Whether the custom option was deserialized successfully.
    pub fn is_valid(&self) -> bool {
        self.valid
    }

    /// Get the stored state.
    pub fn state(&self) -> &[(String, OptionValue)] {
        &self.state
    }

    /// Set the stored state.
    pub fn set_state(&mut self, state: Vec<(String, OptionValue)>) {
        self.state = state;
    }

    /// Set the valid flag.
    pub fn set_valid(&mut self, valid: bool) {
        self.valid = valid;
    }

    /// Attempt to apply this wrapped state to a `CustomOption` implementation.
    pub fn apply_to(&self, option: &mut dyn CustomOption) {
        option.read_state(&self.state);
    }
}

impl Clone for WrappedCustomOption {
    fn clone(&self) -> Self {
        Self {
            class_name: self.class_name.clone(),
            state: self.state.clone(),
            valid: self.valid,
        }
    }
}

impl WrappedOption for WrappedCustomOption {
    fn get_object(&self) -> OptionValue {
        OptionValue::String(self.class_name.clone())
    }

    fn read_state(&mut self, state: &[(String, OptionValue)]) {
        let mut class_name_found = false;
        let mut new_class = String::new();
        let mut data_state = Vec::new();

        for (key, val) in state {
            if key == "CUSTOM OPTION CLASS" {
                if let OptionValue::String(s) = val {
                    new_class = s.clone();
                    class_name_found = true;
                }
            } else {
                data_state.push((key.clone(), val.clone()));
            }
        }

        if class_name_found {
            self.class_name = new_class;
        }
        self.state = data_state;
        self.valid = true;
    }

    fn write_state(&self) -> Vec<(String, OptionValue)> {
        let mut result = vec![(
            "CUSTOM OPTION CLASS".to_string(),
            OptionValue::String(self.class_name.clone()),
        )];
        result.extend(self.state.clone());
        result
    }

    fn option_type(&self) -> OptionType {
        OptionType::CustomType
    }
}

impl std::fmt::Display for WrappedCustomOption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "WrappedCustomOption: class={}, valid={}, fields={}",
            self.class_name,
            self.valid,
            self.state.len()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wrapped_custom_option_new() {
        let co = WrappedCustomOption::new("com.example.MyOption");
        assert!(co.is_valid());
        assert_eq!(co.class_name(), "com.example.MyOption");
    }

    #[test]
    fn test_wrapped_custom_option_option_type() {
        let co = WrappedCustomOption::new("test");
        assert_eq!(co.option_type(), OptionType::CustomType);
    }

    #[test]
    fn test_wrapped_custom_option_roundtrip() {
        let mut co = WrappedCustomOption::new("com.example.MyOption");
        co.set_state(vec![
            ("width".to_string(), OptionValue::Int(800)),
            ("height".to_string(), OptionValue::Int(600)),
        ]);

        let state = co.write_state();
        // State should have "CUSTOM OPTION CLASS" + 2 data fields.
        assert_eq!(state.len(), 3);

        let mut co2 = WrappedCustomOption::new("");
        co2.read_state(&state);
        assert_eq!(co2.class_name(), "com.example.MyOption");
        assert_eq!(co2.state().len(), 2);
    }

    #[test]
    fn test_wrapped_custom_option_get_object() {
        let co = WrappedCustomOption::new("my.class");
        match co.get_object() {
            OptionValue::String(s) => assert_eq!(s, "my.class"),
            _ => panic!("Expected String option value"),
        }
    }

    #[test]
    fn test_wrapped_custom_option_valid() {
        let mut co = WrappedCustomOption::new("test");
        assert!(co.is_valid());
        co.set_valid(false);
        assert!(!co.is_valid());
    }

    #[test]
    fn test_wrapped_custom_option_display() {
        let co = WrappedCustomOption::new("com.example.Foo");
        let s = format!("{}", co);
        assert!(s.contains("com.example.Foo"));
        assert!(s.contains("valid=true"));
    }

    #[test]
    fn test_wrapped_custom_option_clone() {
        let co = WrappedCustomOption::new("test.class");
        let co2 = co.clone();
        assert_eq!(co2.class_name(), "test.class");
    }
}
