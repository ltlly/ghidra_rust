//! TraceMethod - Method invocation interface for trace target objects.
//!
//! Ported from Ghidra's `ghidra.trace.model.target.iface.TraceMethod`.
//! Represents an object in the target tree that can be invoked as a method.
//! Methods have typed parameters and return values, and can be called
//! through the RMI framework.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A value specification for a method parameter, indicating whether the
/// value was explicitly specified and what its value is.
///
/// This corresponds to Ghidra's `TraceMethod.Value<T>`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MethodValue<T> {
    /// Whether this value was explicitly specified by the caller.
    pub specified: bool,
    /// The value itself, if specified.
    pub value: Option<T>,
}

impl<T> MethodValue<T> {
    /// Create a specified value.
    pub fn of(value: T) -> Self {
        Self {
            specified: true,
            value: Some(value),
    }
    }

    /// Create an unspecified value.
    pub fn unspecified() -> Self {
        Self {
            specified: false,
            value: None,
        }
    }

    /// Whether this value was specified.
    pub fn is_specified(&self) -> bool {
        self.specified
    }

    /// Get the value, if specified.
    pub fn get(&self) -> Option<&T> {
        self.value.as_ref()
    }

    /// Get the value or a default.
    pub fn get_or<'a>(&'a self, default: &'a T) -> &'a T {
        self.value.as_ref().unwrap_or(default)
    }
}

/// A boolean method value parameter.
pub type BoolValue = MethodValue<bool>;

/// An integer method value parameter.
pub type IntValue = MethodValue<i32>;

/// A long method value parameter.
pub type LongValue = MethodValue<i64>;

/// A string method value parameter.
pub type StringValue = MethodValue<String>;

/// Describes a single parameter of a trace method.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MethodParameter {
    /// The name of the parameter.
    pub name: String,
    /// The type name of the parameter (e.g., "long", "string", "boolean").
    pub type_name: String,
    /// Whether this parameter is required.
    pub required: bool,
    /// Default value as a string, if any.
    pub default_value: Option<String>,
}

impl MethodParameter {
    /// Create a new required parameter.
    pub fn required(name: impl Into<String>, type_name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            type_name: type_name.into(),
            required: true,
            default_value: None,
        }
    }

    /// Create an optional parameter with a default.
    pub fn optional(
        name: impl Into<String>,
        type_name: impl Into<String>,
        default: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            type_name: type_name.into(),
            required: false,
            default_value: Some(default.into()),
        }
    }
}

/// Describes a method that can be invoked on a trace target object.
///
/// This corresponds to Ghidra's `TraceMethod` interface. Methods are
/// discovered through the object schema and invoked via the RMI protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceMethodDescriptor {
    /// The schema name of the method (e.g., "Method").
    pub schema_name: String,
    /// The short display name.
    pub short_name: String,
    /// The parameters of this method.
    pub parameters: Vec<MethodParameter>,
    /// The return type name, if any.
    pub return_type: Option<String>,
}

impl TraceMethodDescriptor {
    /// Create a new method descriptor.
    pub fn new(
        schema_name: impl Into<String>,
        short_name: impl Into<String>,
        parameters: Vec<MethodParameter>,
    ) -> Self {
        Self {
            schema_name: schema_name.into(),
            short_name: short_name.into(),
            parameters,
            return_type: None,
        }
    }

    /// Set the return type.
    pub fn with_return_type(mut self, return_type: impl Into<String>) -> Self {
        self.return_type = Some(return_type.into());
        self
    }

    /// Get the number of required parameters.
    pub fn required_param_count(&self) -> usize {
        self.parameters.iter().filter(|p| p.required).count()
    }

    /// Get the total number of parameters.
    pub fn param_count(&self) -> usize {
        self.parameters.len()
    }
}

/// A method invocation argument map.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MethodArguments {
    args: HashMap<String, ArgValue>,
}

/// A boxed argument value for method invocations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ArgValue {
    /// A boolean argument.
    Bool(bool),
    /// A 32-bit integer argument.
    Int(i32),
    /// A 64-bit integer argument.
    Long(i64),
    /// A string argument.
    String(String),
    /// A list of bytes.
    Bytes(Vec<u8>),
    /// A null argument.
    Null,
}

impl MethodArguments {
    /// Create empty arguments.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set a boolean argument.
    pub fn set_bool(&mut self, name: impl Into<String>, value: bool) {
        self.args.insert(name.into(), ArgValue::Bool(value));
    }

    /// Set an integer argument.
    pub fn set_int(&mut self, name: impl Into<String>, value: i32) {
        self.args.insert(name.into(), ArgValue::Int(value));
    }

    /// Set a long argument.
    pub fn set_long(&mut self, name: impl Into<String>, value: i64) {
        self.args.insert(name.into(), ArgValue::Long(value));
    }

    /// Set a string argument.
    pub fn set_string(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.args.insert(name.into(), ArgValue::String(value.into()));
    }

    /// Set a bytes argument.
    pub fn set_bytes(&mut self, name: impl Into<String>, value: Vec<u8>) {
        self.args.insert(name.into(), ArgValue::Bytes(value));
    }

    /// Get an argument by name.
    pub fn get(&self, name: &str) -> Option<&ArgValue> {
        self.args.get(name)
    }

    /// Get the number of arguments.
    pub fn len(&self) -> usize {
        self.args.len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.args.is_empty()
    }

    /// Iterate over arguments.
    pub fn iter(&self) -> impl Iterator<Item = (&String, &ArgValue)> {
        self.args.iter()
    }
}

/// The result of a method invocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MethodResult {
    /// Whether the invocation succeeded.
    pub success: bool,
    /// The return value, if any.
    pub return_value: Option<ArgValue>,
    /// An error message, if the invocation failed.
    pub error: Option<String>,
}

impl MethodResult {
    /// Create a successful result with no return value.
    pub fn success() -> Self {
        Self {
            success: true,
            return_value: None,
            error: None,
        }
    }

    /// Create a successful result with a return value.
    pub fn with_value(value: ArgValue) -> Self {
        Self {
            success: true,
            return_value: Some(value),
            error: None,
        }
    }

    /// Create an error result.
    pub fn error(message: impl Into<String>) -> Self {
        Self {
            success: false,
            return_value: None,
            error: Some(message.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_method_value_specified() {
        let v = MethodValue::of(42i32);
        assert!(v.is_specified());
        assert_eq!(v.get(), Some(&42));
    }

    #[test]
    fn test_method_value_unspecified() {
        let v: MethodValue<i32> = MethodValue::unspecified();
        assert!(!v.is_specified());
        assert_eq!(v.get(), None);
    }

    #[test]
    fn test_method_value_get_or() {
        let v: MethodValue<i32> = MethodValue::unspecified();
        assert_eq!(v.get_or(&99), &99);

        let v = MethodValue::of(42i32);
        assert_eq!(v.get_or(&99), &42);
    }

    #[test]
    fn test_method_parameter_required() {
        let p = MethodParameter::required("address", "long");
        assert_eq!(p.name, "address");
        assert_eq!(p.type_name, "long");
        assert!(p.required);
        assert!(p.default_value.is_none());
    }

    #[test]
    fn test_method_parameter_optional() {
        let p = MethodParameter::optional("count", "int", "1");
        assert!(!p.required);
        assert_eq!(p.default_value.as_deref(), Some("1"));
    }

    #[test]
    fn test_method_descriptor() {
        let d = TraceMethodDescriptor::new("Method", "resume", vec![
            MethodParameter::optional("count", "long", "0"),
        ])
        .with_return_type("boolean");
        assert_eq!(d.schema_name, "Method");
        assert_eq!(d.short_name, "resume");
        assert_eq!(d.param_count(), 1);
        assert_eq!(d.required_param_count(), 0);
        assert_eq!(d.return_type.as_deref(), Some("boolean"));
    }

    #[test]
    fn test_method_arguments() {
        let mut args = MethodArguments::new();
        args.set_long("address", 0x1000);
        args.set_bool("force", true);
        args.set_string("name", "test");

        assert_eq!(args.len(), 3);
        assert!(!args.is_empty());

        match args.get("address") {
            Some(ArgValue::Long(v)) => assert_eq!(*v, 0x1000),
            _ => panic!("Expected Long"),
        }
        match args.get("force") {
            Some(ArgValue::Bool(v)) => assert!(*v),
            _ => panic!("Expected Bool"),
        }
    }

    #[test]
    fn test_method_result() {
        let r = MethodResult::success();
        assert!(r.success);
        assert!(r.return_value.is_none());

        let r = MethodResult::with_value(ArgValue::Bool(true));
        assert!(r.success);
        match r.return_value {
            Some(ArgValue::Bool(v)) => assert!(v),
            _ => panic!("Expected Bool"),
        }

        let r = MethodResult::error("not found");
        assert!(!r.success);
        assert_eq!(r.error.as_deref(), Some("not found"));
    }

    #[test]
    fn test_method_descriptor_required_count() {
        let d = TraceMethodDescriptor::new("Method", "read", vec![
            MethodParameter::required("address", "long"),
            MethodParameter::required("size", "int"),
            MethodParameter::optional("offset", "long", "0"),
        ]);
        assert_eq!(d.required_param_count(), 2);
        assert_eq!(d.param_count(), 3);
    }
}
