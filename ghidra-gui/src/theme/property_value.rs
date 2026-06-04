//! Port of `generic.theme.*PropertyValue` types.
//!
//! Typed wrappers for theme property values: `JavaPropertyValue`, `StringPropertyValue`,
//! `BooleanPropertyValue`.

/// A Java-compatible property value (string representation of any value).
///
/// Mirrors `generic.theme.JavaPropertyValue`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct JavaPropertyValue {
    /// The string representation of the value.
    pub value: String,
    /// The Java class name of the value type.
    pub class_name: String,
}

impl JavaPropertyValue {
    /// Create a new Java property value.
    pub fn new(value: impl Into<String>, class_name: impl Into<String>) -> Self {
        Self {
            value: value.into(),
            class_name: class_name.into(),
        }
    }

    /// Create a string property value.
    pub fn string(value: impl Into<String>) -> Self {
        Self::new(value, "java.lang.String")
    }

    /// Create an integer property value.
    pub fn integer(value: i64) -> Self {
        Self::new(value.to_string(), "java.lang.Integer")
    }

    /// Create a boolean property value.
    pub fn boolean(value: bool) -> Self {
        Self::new(value.to_string(), "java.lang.Boolean")
    }
}

impl std::fmt::Display for JavaPropertyValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.value)
    }
}

/// A string property value.
///
/// Mirrors `generic.theme.StringPropertyValue`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StringPropertyValue {
    /// The string value.
    pub value: String,
}

impl StringPropertyValue {
    /// Create a new string property value.
    pub fn new(value: impl Into<String>) -> Self {
        Self { value: value.into() }
    }

    /// Get the value.
    pub fn get(&self) -> &str {
        &self.value
    }
}

impl std::fmt::Display for StringPropertyValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.value)
    }
}

/// A boolean property value.
///
/// Mirrors `generic.theme.BooleanPropertyValue`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BooleanPropertyValue {
    /// The boolean value.
    pub value: bool,
}

impl BooleanPropertyValue {
    /// Create a new boolean property value.
    pub fn new(value: bool) -> Self {
        Self { value }
    }

    /// Get the value.
    pub fn get(&self) -> bool {
        self.value
    }
}

impl std::fmt::Display for BooleanPropertyValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_java_property_value_string() {
        let v = JavaPropertyValue::string("hello");
        assert_eq!(v.value, "hello");
        assert_eq!(v.class_name, "java.lang.String");
    }

    #[test]
    fn test_java_property_value_integer() {
        let v = JavaPropertyValue::integer(42);
        assert_eq!(v.value, "42");
        assert_eq!(v.class_name, "java.lang.Integer");
    }

    #[test]
    fn test_java_property_value_boolean() {
        let v = JavaPropertyValue::boolean(true);
        assert_eq!(v.value, "true");
    }

    #[test]
    fn test_java_property_value_display() {
        let v = JavaPropertyValue::string("test");
        assert_eq!(v.to_string(), "test");
    }

    #[test]
    fn test_string_property_value() {
        let v = StringPropertyValue::new("hello");
        assert_eq!(v.get(), "hello");
        assert_eq!(v.to_string(), "hello");
    }

    #[test]
    fn test_boolean_property_value() {
        let t = BooleanPropertyValue::new(true);
        let f = BooleanPropertyValue::new(false);
        assert!(t.get());
        assert!(!f.get());
        assert_eq!(t.to_string(), "true");
        assert_eq!(f.to_string(), "false");
    }
}
