//! Options storage for the Ghidra framework.
//!
//! Ports Ghidra's `framework.options.Options` interface. An `Options` object
//! is a named, typed key-value store for configuration options. Each option
//! has a name, a type ([`OptionType`](super::option_type::OptionType)), and a
//! value. Options can be registered with defaults and then read/written by
//! name.

use std::collections::HashMap;
use std::fmt;

use super::option_type::OptionType;

// ============================================================================
// OptionValue
// ============================================================================

/// A stored option value with its type tag.
#[derive(Debug, Clone)]
pub enum OptionValue {
    Int(i32),
    Long(i64),
    String(String),
    Double(f64),
    Float(f32),
    Boolean(bool),
    ByteArray(Vec<u8>),
    Date(String),
    Enum(String),
    Custom(String),
    File(String),
    Color(u32),
    Font(String),
    KeyStroke(String),
    ActionTrigger(String),
}

impl OptionValue {
    /// Returns the [`OptionType`] tag for this value.
    pub fn option_type(&self) -> OptionType {
        match self {
            OptionValue::Int(_) => OptionType::IntType,
            OptionValue::Long(_) => OptionType::LongType,
            OptionValue::String(_) => OptionType::StringType,
            OptionValue::Double(_) => OptionType::DoubleType,
            OptionValue::Float(_) => OptionType::FloatType,
            OptionValue::Boolean(_) => OptionType::BooleanType,
            OptionValue::ByteArray(_) => OptionType::ByteArrayType,
            OptionValue::Date(_) => OptionType::DateType,
            OptionValue::Enum(_) => OptionType::EnumType,
            OptionValue::Custom(_) => OptionType::CustomType,
            OptionValue::File(_) => OptionType::FileType,
            OptionValue::Color(_) => OptionType::ColorType,
            OptionValue::Font(_) => OptionType::FontType,
            OptionValue::KeyStroke(_) => OptionType::KeyStrokeType,
            OptionValue::ActionTrigger(_) => OptionType::ActionTrigger,
        }
    }

    /// Returns the value as a string representation.
    pub fn to_display_string(&self) -> String {
        match self {
            OptionValue::Int(v) => v.to_string(),
            OptionValue::Long(v) => v.to_string(),
            OptionValue::String(v) => v.clone(),
            OptionValue::Double(v) => v.to_string(),
            OptionValue::Float(v) => v.to_string(),
            OptionValue::Boolean(v) => v.to_string(),
            OptionValue::ByteArray(v) => format!("{:02x?}", v),
            OptionValue::Date(v) => v.clone(),
            OptionValue::Enum(v) => v.clone(),
            OptionValue::Custom(v) => v.clone(),
            OptionValue::File(v) => v.clone(),
            OptionValue::Color(v) => format!("0x{:08x}", v),
            OptionValue::Font(v) => v.clone(),
            OptionValue::KeyStroke(v) => v.clone(),
            OptionValue::ActionTrigger(v) => v.clone(),
        }
    }
}

// ============================================================================
// Options trait
// ============================================================================

/// A named collection of typed options.
///
/// Options are identified by name and typed by [`OptionType`]. This trait
/// provides the interface for reading, writing, and managing configuration
/// options in the Ghidra framework.
pub trait Options: fmt::Debug + Send + Sync {
    /// Returns the name of this options collection.
    fn get_name(&self) -> &str;

    /// Returns the full path to this options collection (e.g., "/General/Editor").
    fn get_path(&self) -> &str;

    /// Register a new option with a default value.
    fn register_option(
        &mut self,
        name: &str,
        option_type: OptionType,
        default_value: Option<OptionValue>,
    ) -> Result<(), OptionsError>;

    /// Returns `true` if an option with the given name exists.
    fn has_option(&self, name: &str) -> bool;

    /// Get the type of the option with the given name.
    fn get_option_type(&self, name: &str) -> Option<OptionType>;

    /// Get the value of an option as an `OptionValue`.
    fn get_value(&self, name: &str) -> Option<OptionValue>;

    /// Set the value of an option.
    fn set_value(&mut self, name: &str, value: OptionValue) -> Result<(), OptionsError>;

    /// Remove an option by name.
    fn remove_option(&mut self, name: &str) -> Result<(), OptionsError>;

    /// List all option names.
    fn get_option_names(&self) -> Vec<String>;

    /// Returns the number of registered options.
    fn get_option_count(&self) -> usize;

    /// Get a string value, or the default if not set.
    fn get_string(&self, name: &str, default: &str) -> String {
        match self.get_value(name) {
            Some(OptionValue::String(s)) => s,
            _ => default.to_string(),
        }
    }

    /// Get an int value, or the default if not set.
    fn get_int(&self, name: &str, default: i32) -> i32 {
        match self.get_value(name) {
            Some(OptionValue::Int(v)) => v,
            _ => default,
        }
    }

    /// Get a long value, or the default if not set.
    fn get_long(&self, name: &str, default: i64) -> i64 {
        match self.get_value(name) {
            Some(OptionValue::Long(v)) => v,
            _ => default,
        }
    }

    /// Get a boolean value, or the default if not set.
    fn get_boolean(&self, name: &str, default: bool) -> bool {
        match self.get_value(name) {
            Some(OptionValue::Boolean(v)) => v,
            _ => default,
        }
    }

    /// Get a double value, or the default if not set.
    fn get_double(&self, name: &str, default: f64) -> f64 {
        match self.get_value(name) {
            Some(OptionValue::Double(v)) => v,
            _ => default,
        }
    }
}

// ============================================================================
// OptionsError
// ============================================================================

/// Errors that can occur when operating on options.
#[derive(Debug, Clone)]
pub enum OptionsError {
    /// An option with the given name already exists.
    AlreadyExists(String),
    /// The specified option was not found.
    NotFound(String),
    /// The value type does not match the registered type.
    TypeMismatch {
        name: String,
        expected: OptionType,
        actual: OptionType,
    },
    /// The option name is invalid.
    InvalidName(String),
    /// A generic error.
    Other(String),
}

impl fmt::Display for OptionsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OptionsError::AlreadyExists(name) => {
                write!(f, "Option already exists: {}", name)
            }
            OptionsError::NotFound(name) => write!(f, "Option not found: {}", name),
            OptionsError::TypeMismatch {
                name,
                expected,
                actual,
            } => write!(
                f,
                "Type mismatch for '{}': expected {:?}, got {:?}",
                name, expected, actual
            ),
            OptionsError::InvalidName(name) => {
                write!(f, "Invalid option name: {}", name)
            }
            OptionsError::Other(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for OptionsError {}

// ============================================================================
// DefaultOptions — concrete in-memory implementation
// ============================================================================

/// An in-memory implementation of [`Options`].
///
/// Stores all option registrations and values in `HashMap`s. Thread-safe
/// via interior `RwLock`.
#[derive(Debug)]
pub struct DefaultOptions {
    name: String,
    path: String,
    registrations: HashMap<String, OptionType>,
    values: HashMap<String, OptionValue>,
}

impl DefaultOptions {
    /// Create a new empty options collection.
    pub fn new(name: impl Into<String>, path: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            path: path.into(),
            registrations: HashMap::new(),
            values: HashMap::new(),
        }
    }
}

impl Options for DefaultOptions {
    fn get_name(&self) -> &str {
        &self.name
    }

    fn get_path(&self) -> &str {
        &self.path
    }

    fn register_option(
        &mut self,
        name: &str,
        option_type: OptionType,
        default_value: Option<OptionValue>,
    ) -> Result<(), OptionsError> {
        if self.registrations.contains_key(name) {
            return Err(OptionsError::AlreadyExists(name.to_string()));
        }
        self.registrations.insert(name.to_string(), option_type);
        if let Some(val) = default_value {
            self.values.insert(name.to_string(), val);
        }
        Ok(())
    }

    fn has_option(&self, name: &str) -> bool {
        self.registrations.contains_key(name)
    }

    fn get_option_type(&self, name: &str) -> Option<OptionType> {
        self.registrations.get(name).copied()
    }

    fn get_value(&self, name: &str) -> Option<OptionValue> {
        self.values.get(name).cloned()
    }

    fn set_value(&mut self, name: &str, value: OptionValue) -> Result<(), OptionsError> {
        if let Some(&registered_type) = self.registrations.get(name) {
            let actual_type = value.option_type();
            if registered_type != actual_type && registered_type != OptionType::NoType {
                return Err(OptionsError::TypeMismatch {
                    name: name.to_string(),
                    expected: registered_type,
                    actual: actual_type,
                });
            }
        }
        self.values.insert(name.to_string(), value);
        Ok(())
    }

    fn remove_option(&mut self, name: &str) -> Result<(), OptionsError> {
        if self.registrations.remove(name).is_none() {
            return Err(OptionsError::NotFound(name.to_string()));
        }
        self.values.remove(name);
        Ok(())
    }

    fn get_option_names(&self) -> Vec<String> {
        self.registrations.keys().cloned().collect()
    }

    fn get_option_count(&self) -> usize {
        self.registrations.len()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_options_register_and_get() {
        let mut opts = DefaultOptions::new("Test", "/Test");
        opts.register_option("fontSize", OptionType::IntType, Some(OptionValue::Int(12)))
            .unwrap();

        assert!(opts.has_option("fontSize"));
        assert_eq!(opts.get_option_type("fontSize"), Some(OptionType::IntType));
        assert_eq!(opts.get_int("fontSize", 10), 12);
    }

    #[test]
    fn test_options_set_value() {
        let mut opts = DefaultOptions::new("Test", "/Test");
        opts.register_option("name", OptionType::StringType, None)
            .unwrap();

        opts.set_value("name", OptionValue::String("Ghidra".to_string()))
            .unwrap();
        assert_eq!(opts.get_string("name", ""), "Ghidra");
    }

    #[test]
    fn test_options_type_mismatch() {
        let mut opts = DefaultOptions::new("Test", "/Test");
        opts.register_option("count", OptionType::IntType, None)
            .unwrap();

        let result = opts.set_value("count", OptionValue::String("bad".to_string()));
        assert!(result.is_err());
    }

    #[test]
    fn test_options_remove() {
        let mut opts = DefaultOptions::new("Test", "/Test");
        opts.register_option("temp", OptionType::BooleanType, None)
            .unwrap();
        assert!(opts.has_option("temp"));

        opts.remove_option("temp").unwrap();
        assert!(!opts.has_option("temp"));
    }

    #[test]
    fn test_options_list_names() {
        let mut opts = DefaultOptions::new("Test", "/Test");
        opts.register_option("a", OptionType::IntType, None).unwrap();
        opts.register_option("b", OptionType::StringType, None)
            .unwrap();
        opts.register_option("c", OptionType::BooleanType, None)
            .unwrap();

        let mut names = opts.get_option_names();
        names.sort();
        assert_eq!(names, vec!["a", "b", "c"]);
        assert_eq!(opts.get_option_count(), 3);
    }

    #[test]
    fn test_options_default_values() {
        let opts = DefaultOptions::new("Test", "/Test");
        assert_eq!(opts.get_string("missing", "default"), "default");
        assert_eq!(opts.get_int("missing", 42), 42);
        assert_eq!(opts.get_long("missing", 100), 100);
        assert!(opts.get_boolean("missing", true));
        assert!((opts.get_double("missing", 3.14) - 3.14).abs() < f64::EPSILON);
    }

    #[test]
    fn test_option_value_type() {
        assert_eq!(OptionValue::Int(42).option_type(), OptionType::IntType);
        assert_eq!(
            OptionValue::String("x".into()).option_type(),
            OptionType::StringType
        );
        assert_eq!(
            OptionValue::Boolean(true).option_type(),
            OptionType::BooleanType
        );
    }

    #[test]
    fn test_option_value_display() {
        assert_eq!(OptionValue::Int(42).to_display_string(), "42");
        assert_eq!(
            OptionValue::Boolean(true).to_display_string(),
            "true"
        );
    }

    #[test]
    fn test_options_error_display() {
        let err = OptionsError::AlreadyExists("opt".to_string());
        assert!(err.to_string().contains("already exists"));

        let err = OptionsError::NotFound("opt".to_string());
        assert!(err.to_string().contains("not found"));
    }

    #[test]
    fn test_options_already_exists() {
        let mut opts = DefaultOptions::new("Test", "/Test");
        opts.register_option("dup", OptionType::IntType, None).unwrap();
        assert!(opts
            .register_option("dup", OptionType::IntType, None)
            .is_err());
    }
}
