//! Function types for Ghidra Rust.
//!
//! Direct translation of `ghidra.program.model.listing.Function`.
//!
//! A function has an entry point, body, stack frame, parameters, local
//! variables, return type, calling convention, and tags. Thunk functions
//! reference another function.

use crate::addr::{Address, AddressRange};
use crate::data::DataType;
use crate::listing::parameter::Parameter;
use crate::listing::stack_frame::StackFrameData;
use crate::listing::FunctionTag;
use crate::symbol::SourceType;
use std::collections::HashMap;
use std::sync::Arc;

/// The common interface for a function in the program.
///
/// Corresponds to `ghidra.program.model.listing.Function`. This trait defines
/// the query methods that all function implementations must provide.
pub trait FunctionApi: Send + Sync {
    /// Returns the function name.
    fn get_name(&self) -> &str;

    /// Returns the entry point address.
    fn get_entry_point(&self) -> Address;

    /// Returns the function body as an address range.
    fn get_body(&self) -> &AddressRange;

    /// Returns true if the given address is within the function body.
    fn contains_address(&self, addr: &Address) -> bool;

    /// Returns the return type, if known.
    fn get_return_type(&self) -> Option<&Arc<dyn DataType>>;

    /// Returns the number of parameters (excluding return).
    fn get_parameter_count(&self) -> usize;

    /// Returns the calling convention name.
    fn get_calling_convention_name(&self) -> &str;

    /// Returns true if this function is a thunk.
    fn is_thunk(&self) -> bool;

    /// Returns true if this function has variable arguments.
    fn has_varargs(&self) -> bool;

    /// Returns true if this function is marked as inline.
    fn is_inline(&self) -> bool;

    /// Returns true if this function is marked as noreturn.
    fn is_no_return(&self) -> bool;

    /// Returns true if this function is external.
    fn is_external(&self) -> bool;

    /// Returns the stack frame layout.
    fn get_stack_frame(&self) -> &StackFrameData;

    /// Returns true if a tag with the given name is applied.
    fn has_tag_named(&self, tag_name: &str) -> bool;

    /// Returns the function signature as a display string.
    fn signature_string(&self) -> String;
}

/// A function in the program.
///
/// Corresponds to Ghidra's `Function` Java class. Functions have an entry
/// point, a body, a stack frame, parameters, local variables, return type,
/// calling convention, and tags.
#[derive(Debug, Clone)]
pub struct Function {
    /// The function name.
    pub name: String,
    /// The entry-point address.
    pub entry_point: Address,
    /// The body range (all addresses covered by the function).
    pub body: AddressRange,
    /// The return type, if known.
    pub return_type: Option<Arc<dyn DataType>>,
    /// The return parameter (ordinal = -1).
    pub return_param: Parameter,
    /// The function parameters (ordered).
    pub parameters: Vec<Parameter>,
    /// The calling convention name.
    pub calling_convention: String,
    /// Stack frame layout.
    pub stack_frame: StackFrameData,
    /// Stack purge size (bytes popped by callee on x86 stdcall).
    pub stack_purge_size: i32,
    /// Whether the stack purge size has been determined/valid.
    pub stack_purge_size_valid: bool,
    /// Overall signature source.
    pub signature_source: SourceType,
    /// Whether this function has custom variable storage.
    pub custom_storage: bool,
    /// Whether this function is a thunk (wrapper/forwarder).
    pub is_thunk: bool,
    /// If this is a thunk, the address of the thunked function.
    pub thunked_function: Option<Address>,
    /// Whether this function has a variable argument list.
    pub has_varargs: bool,
    /// Whether this function is marked as inline.
    pub inline: bool,
    /// Whether this function is marked as noreturn.
    pub no_return: bool,
    /// Call-fixup name (compiler-spec specific).
    pub call_fixup: Option<String>,
    /// Function comment.
    pub comment: Option<String>,
    /// Repeatable comment (shown at call sites).
    pub repeatable_comment: Option<String>,
    /// Tags applied to this function (keyed by tag name).
    pub tags: HashMap<String, FunctionTag>,
    /// Whether this function is external (EXTERNAL address space).
    pub is_external: bool,
    /// Whether this function has been deleted.
    pub deleted: bool,
}

impl Function {
    /// Default parameter prefix.
    pub const DEFAULT_PARAM_PREFIX: &'static str = "param_";
    /// Default local variable prefix.
    pub const DEFAULT_LOCAL_PREFIX: &'static str = "local_";
    /// Default local temp prefix.
    pub const DEFAULT_LOCAL_TEMP_PREFIX: &'static str = "temp_";
    /// Reserved local prefix.
    pub const DEFAULT_LOCAL_RESERVED_PREFIX: &'static str = "local_res";
    /// The `this` parameter name for __thiscall.
    pub const THIS_PARAM_NAME: &'static str = "this";
    /// The return storage pointer parameter name.
    pub const RETURN_PTR_PARAM_NAME: &'static str = "__return_storage_ptr__";
    /// Unknown calling convention string.
    pub const UNKNOWN_CALLING_CONVENTION: &'static str = "unknown";
    /// Default calling convention string.
    pub const DEFAULT_CALLING_CONVENTION: &'static str = "default";
    /// Unknown stack depth constant.
    pub const UNKNOWN_STACK_DEPTH_CHANGE: i32 = i32::MAX;
    /// Invalid stack depth constant.
    pub const INVALID_STACK_DEPTH_CHANGE: i32 = i32::MAX - 1;
    /// Inline tag name.
    pub const INLINE_TAG: &'static str = "inline";
    /// Noreturn tag name.
    pub const NORETURN_TAG: &'static str = "noreturn";
    /// Thunk tag name.
    pub const THUNK_TAG: &'static str = "thunk";

    /// Create a new function.
    pub fn new(name: impl Into<String>, entry_point: Address, body: AddressRange) -> Self {
        Self {
            name: name.into(),
            entry_point,
            body,
            return_type: None,
            return_param: Parameter::return_param(None),
            parameters: Vec::new(),
            calling_convention: Self::DEFAULT_CALLING_CONVENTION.to_string(),
            stack_frame: StackFrameData::empty(true),
            stack_purge_size: 0,
            stack_purge_size_valid: false,
            signature_source: SourceType::Default,
            custom_storage: false,
            is_thunk: false,
            thunked_function: None,
            has_varargs: false,
            inline: false,
            no_return: false,
            call_fixup: None,
            comment: None,
            repeatable_comment: None,
            tags: HashMap::new(),
            is_external: false,
            deleted: false,
        }
    }

    /// Builder: set return type.
    pub fn with_return_type(mut self, dt: Arc<dyn DataType>) -> Self {
        self.return_param = Parameter::return_param(Some(dt.clone()));
        self.return_type = Some(dt);
        self
    }

    /// Builder: add a parameter.
    pub fn with_parameter(mut self, param: Parameter) -> Self {
        self.parameters.push(param);
        self
    }

    /// Builder: set calling convention.
    pub fn with_calling_convention(mut self, cc: impl Into<String>) -> Self {
        self.calling_convention = cc.into();
        self
    }

    /// Builder: set as thunk.
    pub fn with_thunk(mut self, target: Address) -> Self {
        self.is_thunk = true;
        self.thunked_function = Some(target);
        self.tags.insert(Self::THUNK_TAG.to_string(), FunctionTag::new(0, Self::THUNK_TAG));
        self
    }

    /// Builder: set as inline.
    pub fn with_inline(mut self) -> Self {
        self.inline = true;
        self.tags.insert(Self::INLINE_TAG.to_string(), FunctionTag::new(0, Self::INLINE_TAG));
        self
    }

    /// Builder: set as no-return.
    pub fn with_noreturn(mut self) -> Self {
        self.no_return = true;
        self.tags.insert(Self::NORETURN_TAG.to_string(), FunctionTag::new(0, Self::NORETURN_TAG));
        self
    }

    /// Builder: set varargs.
    pub fn with_varargs(mut self) -> Self {
        self.has_varargs = true;
        self
    }

    /// Builder: set comment.
    pub fn with_comment(mut self, comment: impl Into<String>) -> Self {
        self.comment = Some(comment.into());
        self
    }

    /// Builder: set repeatable comment.
    pub fn with_repeatable_comment(mut self, comment: impl Into<String>) -> Self {
        self.repeatable_comment = Some(comment.into());
        self
    }

    /// Builder: add a tag.
    pub fn with_tag(mut self, tag: FunctionTag) -> Self {
        self.tags.insert(tag.get_name().to_string(), tag);
        self
    }

    /// Get a parameter by ordinal.
    pub fn get_parameter(&self, ordinal: i32) -> Option<&Parameter> {
        if ordinal == Parameter::RETURN_ORDINAL {
            Some(&self.return_param)
        } else {
            self.parameters.get(ordinal as usize)
        }
    }

    /// Number of parameters (excluding return).
    pub fn get_parameter_count(&self) -> usize {
        self.parameters.len()
    }

    /// Auto-parameter count (parameters injected by calling convention).
    pub fn get_auto_parameter_count(&self) -> usize {
        self.parameters
            .iter()
            .filter(|p| p.auto_parameter)
            .count()
    }

    /// Find a parameter by name.
    pub fn get_parameter_by_name(&self, name: &str) -> Option<&Parameter> {
        self.parameters.iter().find(|param| param.name() == Some(name))
    }

    /// Number of local variables.
    pub fn get_local_variable_count(&self) -> usize {
        0 // Placeholder -- local variables stored separately in a full implementation
    }

    /// Returns true if the given tag name is applied to the function.
    pub fn has_tag_named(&self, tag_name: &str) -> bool {
        self.tags.contains_key(tag_name)
    }

    /// End address of the function body.
    pub fn get_body_end(&self) -> Address {
        self.body.end
    }

    /// Returns true if the given address is contained in this function's body.
    pub fn contains_address(&self, addr: &Address) -> bool {
        self.body.contains(addr)
    }

    /// Returns true if this function has a valid stack purge size.
    pub fn is_stack_purge_size_valid(&self) -> bool {
        self.stack_purge_size_valid
    }

    /// Get the effective calling convention name.
    pub fn get_calling_convention_name(&self) -> String {
        if self.calling_convention.is_empty() {
            Self::UNKNOWN_CALLING_CONVENTION.to_string()
        } else {
            self.calling_convention.clone()
        }
    }

    /// Check if the calling convention is unknown.
    pub fn has_unknown_calling_convention_name(&self) -> bool {
        self.calling_convention.is_empty()
            || self.calling_convention == Self::UNKNOWN_CALLING_CONVENTION
    }

    /// Get the signature string for display.
    pub fn signature_string(&self) -> String {
        let mut result = String::new();
        if let Some(ref rt) = self.return_type {
            result.push_str(rt.name());
        } else {
            result.push_str("void");
        }
        result.push(' ');
        result.push_str(&self.name);
        result.push('(');
        let param_strs: Vec<String> = self
            .parameters
            .iter()
            .map(|p| {
                let type_name = p
                    .formal_data_type()
                    .map(|dt| dt.name().to_string())
                    .unwrap_or_else(|| "undefined".to_string());
                let pname = p.name().unwrap_or("").to_string();
                let name = if pname.is_empty() {
                    format!("{}", p.ordinal)
                } else {
                    pname
                };
                format!("{} {}", type_name, name)
            })
            .collect();
        result.push_str(&param_strs.join(", "));
        if self.has_varargs {
            if param_strs.is_empty() {
                result.push_str("...");
            } else {
                result.push_str(", ...");
            }
        }
        result.push(')');
        result
    }

    /// Get the prototype string (optionally including calling convention).
    pub fn prototype_string(&self, include_calling_convention: bool) -> String {
        let mut result = String::new();
        if include_calling_convention
            && !self.calling_convention.is_empty()
            && self.calling_convention != Self::DEFAULT_CALLING_CONVENTION
        {
            result.push_str(&self.calling_convention);
            result.push(' ');
        }
        result.push_str(&self.signature_string());
        result
    }
}

impl PartialEq for Function {
    fn eq(&self, other: &Self) -> bool {
        self.entry_point == other.entry_point && self.name == other.name
    }
}

impl Eq for Function {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_function_creation() {
        let body = AddressRange::new(Address::new(0x1000), Address::new(0x1021));
        let func = Function::new("main", Address::new(0x1000), body);
        assert_eq!(func.name, "main");
        assert_eq!(func.entry_point, Address::new(0x1000));
        assert!(!func.is_thunk);
        assert!(func.contains_address(&Address::new(0x1010)));
    }

    #[test]
    fn test_function_signature() {
        let body = AddressRange::new(Address::new(0x1000), Address::new(0x1021));
        let func = Function::new("main", Address::new(0x1000), body)
            .with_parameter(Parameter::new("argc", None, 0, SourceType::UserDefined))
            .with_parameter(Parameter::new("argv", None, 1, SourceType::UserDefined));
        let sig = func.signature_string();
        assert!(sig.contains("main"));
        assert!(sig.contains("argc"));
        assert!(sig.contains("argv"));
    }

    #[test]
    fn test_function_thunk() {
        let body = AddressRange::new(Address::new(0x1000), Address::new(0x1005));
        let func = Function::new("thunk_func", Address::new(0x1000), body)
            .with_thunk(Address::new(0x2000));
        assert!(func.is_thunk);
        assert_eq!(func.thunked_function, Some(Address::new(0x2000)));
        assert!(func.has_tag_named(Function::THUNK_TAG));
    }

    #[test]
    fn test_function_convenience_helpers() {
        let body = AddressRange::new(Address::new(0x1000), Address::new(0x1021));
        let func = Function::new("main", Address::new(0x1000), body)
            .with_parameter(Parameter::new("argc", None, 0, SourceType::UserDefined))
            .with_tag(FunctionTag::new(0, "entry"));

        assert_eq!(func.get_parameter_by_name("argc").map(|p| p.ordinal), Some(0));
        assert!(func.has_tag_named("entry"));
        assert_eq!(func.get_body_end(), Address::new(0x1021));
    }

    #[test]
    fn test_function_noreturn() {
        let body = AddressRange::new(Address::new(0x2000), Address::new(0x2010));
        let func = Function::new("abort", Address::new(0x2000), body).with_noreturn();
        assert!(func.no_return);
        assert!(func.has_tag_named(Function::NORETURN_TAG));
    }

    #[test]
    fn test_function_calling_convention() {
        let body = AddressRange::new(Address::new(0x3000), Address::new(0x3010));
        let func = Function::new("test", Address::new(0x3000), body)
            .with_calling_convention("__stdcall");
        assert_eq!(func.get_calling_convention_name(), "__stdcall");
        assert!(!func.has_unknown_calling_convention_name());
    }
}
