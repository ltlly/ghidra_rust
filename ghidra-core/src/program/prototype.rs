//! Prototype model for function calling conventions in Ghidra Rust.
//!
//! Provides [`PrototypeModel`] which describes how a function's parameters
//! are passed and return values are produced for a specific calling convention.

use crate::program::lang::CompilerSpecID;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

/// How a parameter is passed to a function.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ParameterPassing {
    /// Parameter is passed in a register.
    Register(String),
    /// Parameter is passed on the stack at the given offset.
    Stack(i64),
    /// Parameter is passed in a register, then overflow goes to stack.
    RegisterThenStack(String, i64),
    /// Parameter is passed in a specific memory address.
    Memory(u64),
}

/// Describes a single parameter in a function prototype.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrototypeParameter {
    /// Parameter name (if known).
    pub name: Option<String>,
    /// How the parameter is passed.
    pub passing: ParameterPassing,
    /// Size of the parameter in bytes.
    pub size: usize,
    /// Ordinal position (0-based).
    pub ordinal: usize,
}

/// How a return value is produced by a function.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReturnPassing {
    /// Return value is in a register.
    Register(String),
    /// Return value is in a register pair (for large values).
    RegisterPair(String, String),
    /// Return value is on the stack.
    Stack(i64),
    /// No return value (void).
    Void,
}

/// A prototype model describing how a function's parameters and return value
/// are passed according to a specific calling convention.
///
/// Corresponds to a prototype model in `ghidra.program.model.lang.CompilerSpec`.
///
/// A prototype model defines:
/// - Which registers are used for parameter passing (in order)
/// - How the return value is produced
/// - Stack alignment and growth direction
/// - Whether the caller or callee cleans up stack arguments
/// - How many stack bytes are used for the return address
///
/// # Examples
///
/// ```ignore
/// use ghidra_core::program::prototype::*;
///
/// let model = PrototypeModelBuilder::new("__stdcall")
///     .with_parameter_register("ECX")
///     .with_parameter_register("EDX")
///     .with_return_register("EAX")
///     .with_stack_grows_negative(true)
///     .with_callee_cleanup(true)
///     .build();
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrototypeModel {
    /// The name of this prototype model (e.g., "__stdcall", "__cdecl").
    pub name: String,

    /// The compiler spec ID this model belongs to.
    pub compiler_spec_id: Option<CompilerSpecID>,

    /// Ordered list of registers used for parameter passing.
    pub parameter_registers: Vec<String>,

    /// The register used to return scalar values.
    pub return_register: Option<String>,

    /// Secondary return register for values too large for one register.
    pub return_register_pair: Option<(String, String)>,

    /// Stack pointer register name.
    pub stack_pointer: Option<String>,

    /// Whether the stack grows toward lower addresses.
    pub stack_grows_negative: bool,

    /// Stack alignment in bytes (e.g., 4, 8, 16).
    pub stack_alignment: usize,

    /// Number of bytes reserved on the stack for the return address.
    pub return_address_size: usize,

    /// Whether the callee cleans up stack arguments.
    pub callee_cleanup: bool,

    /// Whether this model performs C data-type conversions (array-to-pointer decay).
    pub does_c_data_type_conversions: bool,

    /// Extra space reserved on the stack for parameter passing (shadow space).
    pub extra_stack_space: i64,

    /// Properties attached to this model.
    pub properties: HashMap<String, String>,
}

impl PrototypeModel {
    /// Create a new prototype model with the given name.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            compiler_spec_id: None,
            parameter_registers: Vec::new(),
            return_register: None,
            return_register_pair: None,
            stack_pointer: None,
            stack_grows_negative: true,
            stack_alignment: 4,
            return_address_size: 4,
            callee_cleanup: false,
            does_c_data_type_conversions: false,
            extra_stack_space: 0,
            properties: HashMap::new(),
        }
    }

    /// Returns the model name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the number of register-passed parameters.
    pub fn num_register_params(&self) -> usize {
        self.parameter_registers.len()
    }

    /// Returns the register name for the given parameter ordinal, if it fits
    /// in the register-passing window.
    pub fn get_register_for_param(&self, ordinal: usize) -> Option<&str> {
        self.parameter_registers.get(ordinal).map(|s| s.as_str())
    }

    /// Returns true if this model has a return register defined.
    pub fn has_return_register(&self) -> bool {
        self.return_register.is_some()
    }

    /// Returns the return register name, if any.
    pub fn get_return_register(&self) -> Option<&str> {
        self.return_register.as_deref()
    }

    /// Returns true if the callee cleans up the stack.
    pub fn is_callee_cleanup(&self) -> bool {
        self.callee_cleanup
    }

    /// Returns true if the caller cleans up the stack (not callee cleanup).
    pub fn is_caller_cleanup(&self) -> bool {
        !self.callee_cleanup
    }

    /// Returns the stack alignment in bytes.
    pub fn stack_alignment(&self) -> usize {
        self.stack_alignment
    }

    /// Returns the number of bytes reserved for the return address.
    pub fn return_address_size(&self) -> usize {
        self.return_address_size
    }
}

impl fmt::Display for PrototypeModel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PrototypeModel({}, {} reg params, stack {})",
            self.name,
            self.parameter_registers.len(),
            if self.stack_grows_negative { "-" } else { "+" }
        )
    }
}

/// Builder for constructing a [`PrototypeModel`].
pub struct PrototypeModelBuilder {
    model: PrototypeModel,
}

impl PrototypeModelBuilder {
    /// Create a new builder with the given model name.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            model: PrototypeModel::new(name),
        }
    }

    /// Add a register used for parameter passing.
    pub fn with_parameter_register(mut self, reg: impl Into<String>) -> Self {
        self.model.parameter_registers.push(reg.into());
        self
    }

    /// Set the return register.
    pub fn with_return_register(mut self, reg: impl Into<String>) -> Self {
        self.model.return_register = Some(reg.into());
        self
    }

    /// Set the return register pair.
    pub fn with_return_register_pair(
        mut self,
        reg1: impl Into<String>,
        reg2: impl Into<String>,
    ) -> Self {
        self.model.return_register_pair = Some((reg1.into(), reg2.into()));
        self
    }

    /// Set the stack pointer register name.
    pub fn with_stack_pointer(mut self, reg: impl Into<String>) -> Self {
        self.model.stack_pointer = Some(reg.into());
        self
    }

    /// Set whether the stack grows toward lower addresses.
    pub fn with_stack_grows_negative(mut self, val: bool) -> Self {
        self.model.stack_grows_negative = val;
        self
    }

    /// Set the stack alignment.
    pub fn with_stack_alignment(mut self, alignment: usize) -> Self {
        self.model.stack_alignment = alignment;
        self
    }

    /// Set the return address size.
    pub fn with_return_address_size(mut self, size: usize) -> Self {
        self.model.return_address_size = size;
        self
    }

    /// Set whether the callee cleans up the stack.
    pub fn with_callee_cleanup(mut self, val: bool) -> Self {
        self.model.callee_cleanup = val;
        self
    }

    /// Set whether C data type conversions are performed.
    pub fn with_c_data_type_conversions(mut self, val: bool) -> Self {
        self.model.does_c_data_type_conversions = val;
        self
    }

    /// Set extra stack space (shadow space).
    pub fn with_extra_stack_space(mut self, bytes: i64) -> Self {
        self.model.extra_stack_space = bytes;
        self
    }

    /// Build the prototype model.
    pub fn build(self) -> PrototypeModel {
        self.model
    }
}

/// Pre-built prototype models for common calling conventions.
impl PrototypeModel {
    /// Create a default x86-32 __cdecl prototype model.
    pub fn x86_cdecl() -> Self {
        PrototypeModelBuilder::new("__cdecl")
            .with_parameter_register("Stack")
            .with_return_register("EAX")
            .with_stack_pointer("ESP")
            .with_stack_grows_negative(true)
            .with_stack_alignment(4)
            .with_return_address_size(4)
            .with_callee_cleanup(false) // caller cleanup
            .with_c_data_type_conversions(true)
            .build()
    }

    /// Create a default x86-32 __stdcall prototype model.
    pub fn x86_stdcall() -> Self {
        PrototypeModelBuilder::new("__stdcall")
            .with_parameter_register("Stack")
            .with_return_register("EAX")
            .with_stack_pointer("ESP")
            .with_stack_grows_negative(true)
            .with_stack_alignment(4)
            .with_return_address_size(4)
            .with_callee_cleanup(true) // callee cleanup
            .with_c_data_type_conversions(true)
            .build()
    }

    /// Create a default x86-64 System V AMD64 prototype model.
    pub fn x86_64_sysv() -> Self {
        PrototypeModelBuilder::new("__fastcall")
            .with_parameter_register("RDI")
            .with_parameter_register("RSI")
            .with_parameter_register("RDX")
            .with_parameter_register("RCX")
            .with_parameter_register("R8")
            .with_parameter_register("R9")
            .with_return_register("RAX")
            .with_return_register_pair("RAX", "RDX")
            .with_stack_pointer("RSP")
            .with_stack_grows_negative(true)
            .with_stack_alignment(16)
            .with_return_address_size(8)
            .with_callee_cleanup(false)
            .with_c_data_type_conversions(true)
            .build()
    }

    /// Create a default x86-64 Windows x64 prototype model.
    pub fn x86_64_windows() -> Self {
        PrototypeModelBuilder::new("__fastcall")
            .with_parameter_register("RCX")
            .with_parameter_register("RDX")
            .with_parameter_register("R8")
            .with_parameter_register("R9")
            .with_return_register("RAX")
            .with_stack_pointer("RSP")
            .with_stack_grows_negative(true)
            .with_stack_alignment(16)
            .with_return_address_size(8)
            .with_callee_cleanup(false)
            .with_c_data_type_conversions(true)
            .with_extra_stack_space(32) // shadow space
            .build()
    }

    /// Create a default ARM AAPCS prototype model.
    pub fn arm_aapcs() -> Self {
        PrototypeModelBuilder::new("default")
            .with_parameter_register("r0")
            .with_parameter_register("r1")
            .with_parameter_register("r2")
            .with_parameter_register("r3")
            .with_return_register("r0")
            .with_return_register_pair("r0", "r1")
            .with_stack_pointer("sp")
            .with_stack_grows_negative(true)
            .with_stack_alignment(4)
            .with_return_address_size(0)
            .with_callee_cleanup(false)
            .build()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_model() {
        let model = PrototypeModel::new("__cdecl");
        assert_eq!(model.name(), "__cdecl");
        assert_eq!(model.num_register_params(), 0);
        assert!(!model.has_return_register());
        assert!(model.is_caller_cleanup());
    }

    #[test]
    fn test_builder() {
        let model = PrototypeModelBuilder::new("__stdcall")
            .with_parameter_register("ECX")
            .with_parameter_register("EDX")
            .with_return_register("EAX")
            .with_stack_pointer("ESP")
            .with_callee_cleanup(true)
            .build();

        assert_eq!(model.name(), "__stdcall");
        assert_eq!(model.num_register_params(), 2);
        assert_eq!(model.get_register_for_param(0), Some("ECX"));
        assert_eq!(model.get_register_for_param(1), Some("EDX"));
        assert_eq!(model.get_return_register(), Some("EAX"));
        assert!(model.has_return_register());
        assert!(model.is_callee_cleanup());
        assert!(!model.is_caller_cleanup());
    }

    #[test]
    fn test_x86_cdecl() {
        let model = PrototypeModel::x86_cdecl();
        assert_eq!(model.name(), "__cdecl");
        assert!(model.is_caller_cleanup());
        assert_eq!(model.get_return_register(), Some("EAX"));
        assert_eq!(model.stack_alignment(), 4);
    }

    #[test]
    fn test_x86_stdcall() {
        let model = PrototypeModel::x86_stdcall();
        assert_eq!(model.name(), "__stdcall");
        assert!(model.is_callee_cleanup());
        assert_eq!(model.get_return_register(), Some("EAX"));
    }

    #[test]
    fn test_x86_64_sysv() {
        let model = PrototypeModel::x86_64_sysv();
        assert_eq!(model.num_register_params(), 6);
        assert_eq!(model.get_register_for_param(0), Some("RDI"));
        assert_eq!(model.get_register_for_param(5), Some("R9"));
        assert_eq!(model.get_return_register(), Some("RAX"));
        assert!(model.return_register_pair.is_some());
        assert_eq!(model.stack_alignment(), 16);
    }

    #[test]
    fn test_x86_64_windows() {
        let model = PrototypeModel::x86_64_windows();
        assert_eq!(model.num_register_params(), 4);
        assert_eq!(model.get_register_for_param(0), Some("RCX"));
        assert_eq!(model.extra_stack_space, 32); // shadow space
    }

    #[test]
    fn test_arm_aapcs() {
        let model = PrototypeModel::arm_aapcs();
        assert_eq!(model.num_register_params(), 4);
        assert_eq!(model.get_register_for_param(0), Some("r0"));
        assert_eq!(model.get_return_register(), Some("r0"));
    }

    #[test]
    fn test_display() {
        let model = PrototypeModel::x86_cdecl();
        let s = format!("{}", model);
        assert!(s.contains("__cdecl"));
        assert!(s.contains("reg params"));
    }

    #[test]
    fn test_return_register_pair() {
        let model = PrototypeModelBuilder::new("test")
            .with_return_register_pair("RAX", "RDX")
            .build();
        assert!(model.return_register_pair.is_some());
        let (r1, r2) = model.return_register_pair.as_ref().unwrap();
        assert_eq!(r1, "RAX");
        assert_eq!(r2, "RDX");
    }
}
