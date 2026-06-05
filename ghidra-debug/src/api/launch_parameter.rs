//! LaunchParameter - parameters for launching a debug target.
//!
//! Ported from Ghidra's `ghidra.debug.api.LaunchParameter`.

use serde::{Deserialize, Serialize};

/// A parameter definition for launching a debug target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LaunchParameter {
    /// The parameter name/key.
    pub name: String,
    /// Human-readable display name.
    pub display_name: String,
    /// Description of what this parameter does.
    pub description: String,
    /// The parameter type (e.g., "string", "integer", "boolean", "path").
    pub param_type: LaunchParameterType,
    /// Whether this parameter is required.
    pub required: bool,
    /// Default value if not specified.
    pub default_value: Option<String>,
    /// Possible values for enum-style parameters.
    pub choices: Vec<String>,
}

/// The type of a launch parameter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LaunchParameterType {
    /// A string value.
    String,
    /// An integer value.
    Integer,
    /// A boolean flag.
    Boolean,
    /// A file system path.
    Path,
    /// A choice from a predefined set.
    Choice,
    /// An address value.
    Address,
    /// A connection string (host:port).
    Connection,
}

impl LaunchParameter {
    /// Create a new string parameter.
    pub fn string(name: impl Into<String>) -> Self {
        let name = name.into();
        Self {
            display_name: name.clone(),
            name,
            description: String::new(),
            param_type: LaunchParameterType::String,
            required: false,
            default_value: None,
            choices: Vec::new(),
        }
    }

    /// Create a new boolean parameter.
    pub fn boolean(name: impl Into<String>) -> Self {
        let name = name.into();
        Self {
            display_name: name.clone(),
            name,
            description: String::new(),
            param_type: LaunchParameterType::Boolean,
            required: false,
            default_value: Some("false".into()),
            choices: Vec::new(),
        }
    }

    /// Create a new connection parameter.
    pub fn connection(name: impl Into<String>) -> Self {
        let name = name.into();
        Self {
            display_name: name.clone(),
            name,
            description: String::new(),
            param_type: LaunchParameterType::Connection,
            required: true,
            default_value: None,
            choices: Vec::new(),
        }
    }

    /// Set the display name.
    pub fn with_display_name(mut self, name: impl Into<String>) -> Self {
        self.display_name = name.into();
        self
    }

    /// Set the description.
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    /// Mark as required.
    pub fn required(mut self) -> Self {
        self.required = true;
        self
    }

    /// Set the default value.
    pub fn with_default(mut self, val: impl Into<String>) -> Self {
        self.default_value = Some(val.into());
        self
    }

    /// Set possible choices.
    pub fn with_choices(mut self, choices: Vec<String>) -> Self {
        self.choices = choices;
        self.param_type = LaunchParameterType::Choice;
        self
    }
}

/// A collection of launch parameters.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LaunchParameterSet {
    parameters: Vec<LaunchParameter>,
}

impl LaunchParameterSet {
    /// Create an empty parameter set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a parameter.
    pub fn push(&mut self, param: LaunchParameter) {
        self.parameters.push(param);
    }

    /// Get all parameters.
    pub fn parameters(&self) -> &[LaunchParameter] {
        &self.parameters
    }

    /// Find a parameter by name.
    pub fn find(&self, name: &str) -> Option<&LaunchParameter> {
        self.parameters.iter().find(|p| p.name == name)
    }

    /// Get all required parameters.
    pub fn required_parameters(&self) -> Vec<&LaunchParameter> {
        self.parameters.iter().filter(|p| p.required).collect()
    }

    /// Validate a set of values against required parameters.
    pub fn validate(&self, values: &std::collections::HashMap<String, String>) -> Vec<String> {
        let mut errors = Vec::new();
        for param in &self.parameters {
            if param.required && !values.contains_key(&param.name) {
                errors.push(format!("Missing required parameter: {}", param.name));
            }
            if !param.choices.is_empty() {
                if let Some(val) = values.get(&param.name) {
                    if !param.choices.contains(val) {
                        errors.push(format!(
                            "Invalid value '{}' for parameter '{}'. Valid choices: {:?}",
                            val, param.name, param.choices
                        ));
                    }
                }
            }
        }
        errors
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_string_parameter() {
        let p = LaunchParameter::string("host")
            .with_display_name("Host Address")
            .required();
        assert_eq!(p.name, "host");
        assert!(p.required);
        assert_eq!(p.param_type, LaunchParameterType::String);
    }

    #[test]
    fn test_boolean_parameter() {
        let p = LaunchParameter::boolean("verbose");
        assert_eq!(p.default_value, Some("false".into()));
        assert!(!p.required);
    }

    #[test]
    fn test_connection_parameter() {
        let p = LaunchParameter::connection("gdb");
        assert!(p.required);
        assert_eq!(p.param_type, LaunchParameterType::Connection);
    }

    #[test]
    fn test_parameter_set() {
        let mut set = LaunchParameterSet::new();
        set.push(LaunchParameter::string("host").required());
        set.push(LaunchParameter::boolean("verbose"));
        assert_eq!(set.parameters().len(), 2);
        assert_eq!(set.required_parameters().len(), 1);
    }

    #[test]
    fn test_validate() {
        let mut set = LaunchParameterSet::new();
        set.push(LaunchParameter::string("host").required());
        set.push(
            LaunchParameter::string("mode").with_choices(vec!["fast".into(), "slow".into()]),
        );

        let mut values = HashMap::new();
        values.insert("host".into(), "localhost".into());
        let errors = set.validate(&values);
        assert!(errors.is_empty());

        let mut values = HashMap::new();
        values.insert("mode".into(), "invalid".into());
        let errors = set.validate(&values);
        assert_eq!(errors.len(), 2); // missing host + invalid mode
    }

    #[test]
    fn test_find_parameter() {
        let mut set = LaunchParameterSet::new();
        set.push(LaunchParameter::string("port").with_default("22"));
        assert!(set.find("port").is_some());
        assert!(set.find("missing").is_none());
    }

    #[test]
    fn test_serde() {
        let p = LaunchParameter::string("test").required();
        let json = serde_json::to_string(&p).unwrap();
        let back: LaunchParameter = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "test");
        assert!(back.required);
    }
}
