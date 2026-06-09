//! TargetMethod -- invocable methods on target objects.
//!
//! Ported from Ghidra's `Debugger/target/iface/TargetMethod.java`.
//!
//! A `TargetMethod` represents a callable action on a target object
//! (e.g., resume, step, read-memory). Methods have typed parameters,
//! return values, and can be invoked through the RMI framework.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use super::key_path::KeyPath;

// ---------------------------------------------------------------------------
// Parameter definition
// ---------------------------------------------------------------------------

/// Describes a single parameter of a target method.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetMethodParameter {
    /// The parameter name.
    pub name: String,
    /// The type name (e.g., "long", "string", "boolean", "byte[]").
    pub type_name: String,
    /// Whether this parameter is required.
    pub required: bool,
    /// A human-readable description.
    pub description: Option<String>,
    /// Default value serialized as a string, if optional.
    pub default_value: Option<String>,
}

impl TargetMethodParameter {
    /// Create a required parameter.
    pub fn required(name: impl Into<String>, type_name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            type_name: type_name.into(),
            required: true,
            description: None,
            default_value: None,
        }
    }

    /// Create an optional parameter with a default value.
    pub fn optional(
        name: impl Into<String>,
        type_name: impl Into<String>,
        default: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            type_name: type_name.into(),
            required: false,
            description: None,
            default_value: Some(default.into()),
        }
    }

    /// Attach a description.
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }
}

// ---------------------------------------------------------------------------
// Invocation argument / result values
// ---------------------------------------------------------------------------

/// A boxed argument or return value for a method invocation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum InvokeValue {
    /// Boolean value.
    Bool(bool),
    /// 32-bit signed integer.
    Int(i32),
    /// 64-bit signed integer.
    Long(i64),
    /// 64-bit floating-point.
    Double(f64),
    /// String value.
    String(String),
    /// Raw bytes.
    Bytes(Vec<u8>),
    /// An object reference by key.
    ObjectRef(i64),
    /// Null / absent.
    Null,
}

impl fmt::Display for InvokeValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bool(v) => write!(f, "{v}"),
            Self::Int(v) => write!(f, "{v}"),
            Self::Long(v) => write!(f, "{v}"),
            Self::Double(v) => write!(f, "{v}"),
            Self::String(v) => write!(f, "{v}"),
            Self::Bytes(v) => write!(f, "<{} bytes>", v.len()),
            Self::ObjectRef(k) => write!(f, "ObjectRef({k})"),
            Self::Null => write!(f, "null"),
        }
    }
}

// ---------------------------------------------------------------------------
// Invocation arguments
// ---------------------------------------------------------------------------

/// A map of named arguments for a method invocation.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct InvokeArguments {
    args: BTreeMap<String, InvokeValue>,
}

impl InvokeArguments {
    /// Create an empty argument map.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set a boolean argument.
    pub fn set_bool(&mut self, name: impl Into<String>, value: bool) {
        self.args.insert(name.into(), InvokeValue::Bool(value));
    }

    /// Set an int argument.
    pub fn set_int(&mut self, name: impl Into<String>, value: i32) {
        self.args.insert(name.into(), InvokeValue::Int(value));
    }

    /// Set a long argument.
    pub fn set_long(&mut self, name: impl Into<String>, value: i64) {
        self.args.insert(name.into(), InvokeValue::Long(value));
    }

    /// Set a double argument.
    pub fn set_double(&mut self, name: impl Into<String>, value: f64) {
        self.args.insert(name.into(), InvokeValue::Double(value));
    }

    /// Set a string argument.
    pub fn set_string(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.args.insert(name.into(), InvokeValue::String(value.into()));
    }

    /// Set a bytes argument.
    pub fn set_bytes(&mut self, name: impl Into<String>, value: Vec<u8>) {
        self.args.insert(name.into(), InvokeValue::Bytes(value));
    }

    /// Set an object-reference argument.
    pub fn set_object_ref(&mut self, name: impl Into<String>, key: i64) {
        self.args.insert(name.into(), InvokeValue::ObjectRef(key));
    }

    /// Set a null argument.
    pub fn set_null(&mut self, name: impl Into<String>) {
        self.args.insert(name.into(), InvokeValue::Null);
    }

    /// Get an argument by name.
    pub fn get(&self, name: &str) -> Option<&InvokeValue> {
        self.args.get(name)
    }

    /// Number of arguments.
    pub fn len(&self) -> usize {
        self.args.len()
    }

    /// Whether the argument map is empty.
    pub fn is_empty(&self) -> bool {
        self.args.is_empty()
    }

    /// Iterate over (name, value) pairs.
    pub fn iter(&self) -> impl Iterator<Item = (&String, &InvokeValue)> {
        self.args.iter()
    }

    /// Consume self and return the inner map.
    pub fn into_inner(self) -> BTreeMap<String, InvokeValue> {
        self.args
    }
}

// ---------------------------------------------------------------------------
// Invocation result
// ---------------------------------------------------------------------------

/// The result of a target method invocation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InvokeResult {
    /// Whether the invocation succeeded.
    pub success: bool,
    /// The return value, if any.
    pub return_value: Option<InvokeValue>,
    /// An error message on failure.
    pub error: Option<String>,
}

impl InvokeResult {
    /// A successful result with no return value.
    pub fn ok() -> Self {
        Self {
            success: true,
            return_value: None,
            error: None,
        }
    }

    /// A successful result with a return value.
    pub fn with_value(value: InvokeValue) -> Self {
        Self {
            success: true,
            return_value: Some(value),
            error: None,
        }
    }

    /// A failed result.
    pub fn error(message: impl Into<String>) -> Self {
        Self {
            success: false,
            return_value: None,
            error: Some(message.into()),
        }
    }

    /// Whether this result is an error.
    pub fn is_error(&self) -> bool {
        !self.success
    }
}

// ---------------------------------------------------------------------------
// TargetMethod
// ---------------------------------------------------------------------------

/// Describes an invocable method on a target object.
///
/// Ported from Ghidra's `TargetMethod` interface. A method has a name,
/// a set of typed parameters, and an optional return type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetMethod {
    /// The path to the object owning this method.
    pub path: KeyPath,
    /// The method name (e.g., "resume", "step", "read-memory").
    pub name: String,
    /// A human-readable description of what this method does.
    pub description: Option<String>,
    /// The method parameters.
    pub parameters: Vec<TargetMethodParameter>,
    /// The return type name, if the method returns a value.
    pub return_type: Option<String>,
    /// Whether this method can be invoked remotely via RMI.
    pub rmi_enabled: bool,
}

impl TargetMethod {
    /// Create a new method descriptor.
    pub fn new(
        path: KeyPath,
        name: impl Into<String>,
        parameters: Vec<TargetMethodParameter>,
    ) -> Self {
        Self {
            path,
            name: name.into(),
            description: None,
            parameters,
            return_type: None,
            rmi_enabled: true,
        }
    }

    /// Attach a description.
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }

    /// Set the return type.
    pub fn with_return_type(mut self, return_type: impl Into<String>) -> Self {
        self.return_type = Some(return_type.into());
        self
    }

    /// Set whether RMI is enabled.
    pub fn with_rmi_enabled(mut self, enabled: bool) -> Self {
        self.rmi_enabled = enabled;
        self
    }

    /// The number of required parameters.
    pub fn required_param_count(&self) -> usize {
        self.parameters.iter().filter(|p| p.required).count()
    }

    /// The total number of parameters.
    pub fn param_count(&self) -> usize {
        self.parameters.len()
    }

    /// Find a parameter by name.
    pub fn param(&self, name: &str) -> Option<&TargetMethodParameter> {
        self.parameters.iter().find(|p| p.name == name)
    }

    /// Validate that the given arguments satisfy this method's required parameters.
    pub fn validate_args(&self, args: &InvokeArguments) -> Result<(), String> {
        for param in &self.parameters {
            if param.required && args.get(&param.name).is_none() {
                return Err(format!("missing required parameter: {}", param.name));
            }
        }
        Ok(())
    }
}

impl fmt::Display for TargetMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}({})",
            self.name,
            self.parameters
                .iter()
                .map(|p| p.name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )
    }
}

// ---------------------------------------------------------------------------
// Well-known method names
// ---------------------------------------------------------------------------

/// Common target method names used by Ghidra debuggers.
pub mod method_names {
    /// Resume execution.
    pub const RESUME: &str = "resume";
    /// Resume for a given number of steps.
    pub const STEP: &str = "step";
    /// Step into a function call.
    pub const STEP_INTO: &str = "step-into";
    /// Step out of the current function.
    pub const STEP_OUT: &str = "step-out";
    /// Step over a function call.
    pub const STEP_OVER: &str = "step-over";
    /// Interrupt execution.
    pub const INTERRUPT: &str = "interrupt";
    /// Kill the target process.
    pub const KILL: &str = "kill";
    /// Read memory from the target.
    pub const READ_MEMORY: &str = "read-memory";
    /// Write memory to the target.
    pub const WRITE_MEMORY: &str = "write-memory";
    /// Read registers.
    pub const READ_REGISTERS: &str = "read-registers";
    /// Write registers.
    pub const WRITE_REGISTERS: &str = "write-registers";
    /// Set a breakpoint.
    pub const SET_BREAKPOINT: &str = "set-breakpoint";
    /// Delete a breakpoint.
    pub const DELETE_BREAKPOINT: &str = "delete-breakpoint";
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parameter_required() {
        let p = TargetMethodParameter::required("address", "long");
        assert!(p.required);
        assert!(p.default_value.is_none());
        assert_eq!(p.name, "address");
    }

    #[test]
    fn test_parameter_optional() {
        let p = TargetMethodParameter::optional("count", "int", "1")
            .with_description("Number of steps");
        assert!(!p.required);
        assert_eq!(p.default_value.as_deref(), Some("1"));
        assert_eq!(p.description.as_deref(), Some("Number of steps"));
    }

    #[test]
    fn test_invoke_value_display() {
        assert_eq!(InvokeValue::Bool(true).to_string(), "true");
        assert_eq!(InvokeValue::Int(42).to_string(), "42");
        assert_eq!(InvokeValue::String("hi".into()).to_string(), "hi");
        assert_eq!(InvokeValue::Null.to_string(), "null");
        assert_eq!(InvokeValue::Bytes(vec![0; 5]).to_string(), "<5 bytes>");
    }

    #[test]
    fn test_invoke_arguments() {
        let mut args = InvokeArguments::new();
        args.set_long("address", 0x1000);
        args.set_bool("force", true);
        args.set_string("name", "test");
        args.set_bytes("data", vec![1, 2, 3]);
        args.set_object_ref("thread", 42);
        args.set_null("opt");

        assert_eq!(args.len(), 6);
        assert!(!args.is_empty());

        match args.get("address") {
            Some(InvokeValue::Long(v)) => assert_eq!(*v, 0x1000),
            _ => panic!("expected Long"),
        }
        assert!(args.get("missing").is_none());
    }

    #[test]
    fn test_invoke_result() {
        let r = InvokeResult::ok();
        assert!(r.success);
        assert!(!r.is_error());
        assert!(r.return_value.is_none());

        let r = InvokeResult::with_value(InvokeValue::Bool(true));
        assert!(r.success);
        match r.return_value {
            Some(InvokeValue::Bool(v)) => assert!(v),
            _ => panic!("expected Bool"),
        }

        let r = InvokeResult::error("not found");
        assert!(!r.success);
        assert!(r.is_error());
        assert_eq!(r.error.as_deref(), Some("not found"));
    }

    #[test]
    fn test_target_method_creation() {
        let m = TargetMethod::new(
            KeyPath::parse("Threads[0]"),
            "resume",
            vec![
                TargetMethodParameter::optional("count", "long", "0"),
            ],
        )
        .with_description("Resume execution")
        .with_return_type("boolean");

        assert_eq!(m.name, "resume");
        assert_eq!(m.param_count(), 1);
        assert_eq!(m.required_param_count(), 0);
        assert_eq!(m.return_type.as_deref(), Some("boolean"));
        assert!(m.rmi_enabled);
    }

    #[test]
    fn test_method_display() {
        let m = TargetMethod::new(
            KeyPath::parse("T"),
            "read-memory",
            vec![
                TargetMethodParameter::required("address", "long"),
                TargetMethodParameter::required("size", "int"),
            ],
        );
        let s = format!("{m}");
        assert!(s.contains("read-memory"));
        assert!(s.contains("address"));
        assert!(s.contains("size"));
    }

    #[test]
    fn test_method_param_lookup() {
        let m = TargetMethod::new(
            KeyPath::parse("T"),
            "step",
            vec![
                TargetMethodParameter::optional("count", "long", "1"),
            ],
        );
        assert!(m.param("count").is_some());
        assert!(m.param("missing").is_none());
    }

    #[test]
    fn test_method_validate_args() {
        let m = TargetMethod::new(
            KeyPath::parse("T"),
            "read",
            vec![
                TargetMethodParameter::required("address", "long"),
                TargetMethodParameter::required("size", "int"),
                TargetMethodParameter::optional("offset", "long", "0"),
            ],
        );

        // Missing required param
        let mut args = InvokeArguments::new();
        args.set_long("address", 0x1000);
        assert!(m.validate_args(&args).is_err());

        // All required params present
        args.set_int("size", 256);
        assert!(m.validate_args(&args).is_ok());

        // With optional param also
        args.set_long("offset", 10);
        assert!(m.validate_args(&args).is_ok());
    }

    #[test]
    fn test_well_known_methods() {
        assert_eq!(method_names::RESUME, "resume");
        assert_eq!(method_names::STEP_INTO, "step-into");
        assert_eq!(method_names::READ_MEMORY, "read-memory");
    }

    #[test]
    fn test_method_serde() {
        let m = TargetMethod::new(
            KeyPath::parse("T"),
            "step",
            vec![TargetMethodParameter::required("count", "long")],
        )
        .with_return_type("boolean");
        let json = serde_json::to_string(&m).unwrap();
        let back: TargetMethod = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "step");
        assert_eq!(back.required_param_count(), 1);
    }

    #[test]
    fn test_invoke_arguments_serde() {
        let mut args = InvokeArguments::new();
        args.set_long("addr", 0x4000);
        args.set_string("name", "main");
        let json = serde_json::to_string(&args).unwrap();
        let back: InvokeArguments = serde_json::from_str(&json).unwrap();
        assert_eq!(back.len(), 2);
    }

    #[test]
    fn test_invoke_value_equality() {
        assert_eq!(InvokeValue::Int(1), InvokeValue::Int(1));
        assert_ne!(InvokeValue::Int(1), InvokeValue::Int(2));
        assert_ne!(InvokeValue::Bool(true), InvokeValue::Null);
    }

    #[test]
    fn test_rmi_toggle() {
        let m = TargetMethod::new(
            KeyPath::parse("T"),
            "local-only",
            vec![],
        )
        .with_rmi_enabled(false);
        assert!(!m.rmi_enabled);
    }
}
