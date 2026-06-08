//! Variable filter types for Ghidra Rust.
//!
//! Direct translation of `ghidra.program.model.listing.VariableFilter`.
//!
//! Provides predefined filters for selecting variables based on their
//! storage type (stack, register, memory, etc.) and role (parameter, local).

/// A filter that determines if a variable matches certain criteria.
///
/// Corresponds to `ghidra.program.model.listing.VariableFilter`.
pub trait VariableFilter {
    /// Returns `true` if the variable matches this filter.
    fn matches(&self, is_parameter: bool, is_auto_param: bool, is_stack: bool,
               has_stack_storage: bool, is_register: bool, is_memory: bool,
               is_unique: bool) -> bool;
}

/// Matches all parameters, including auto-parameters.
#[derive(Debug, Clone, Copy)]
pub struct ParameterFilter {
    /// Whether to include auto-parameters.
    pub allow_auto_params: bool,
}

impl VariableFilter for ParameterFilter {
    fn matches(&self, is_parameter: bool, is_auto_param: bool, _is_stack: bool,
               _has_stack_storage: bool, _is_register: bool, _is_memory: bool,
               _is_unique: bool) -> bool {
        is_parameter && (!is_auto_param || self.allow_auto_params)
    }
}

/// Matches all parameters that are not auto-parameters.
#[derive(Debug, Clone, Copy)]
pub struct NonAutoParameterFilter;

impl VariableFilter for NonAutoParameterFilter {
    fn matches(&self, is_parameter: bool, is_auto_param: bool, _is_stack: bool,
               _has_stack_storage: bool, _is_register: bool, _is_memory: bool,
               _is_unique: bool) -> bool {
        is_parameter && !is_auto_param
    }
}

/// Matches all local variables (non-parameters).
#[derive(Debug, Clone, Copy)]
pub struct LocalVariableFilter;

impl VariableFilter for LocalVariableFilter {
    fn matches(&self, is_parameter: bool, _is_auto_param: bool, _is_stack: bool,
               _has_stack_storage: bool, _is_register: bool, _is_memory: bool,
               _is_unique: bool) -> bool {
        !is_parameter
    }
}

/// Matches all simple stack variables.
#[derive(Debug, Clone, Copy)]
pub struct StackVariableFilter;

impl VariableFilter for StackVariableFilter {
    fn matches(&self, _is_parameter: bool, _is_auto_param: bool, is_stack: bool,
               _has_stack_storage: bool, _is_register: bool, _is_memory: bool,
               _is_unique: bool) -> bool {
        is_stack
    }
}

/// Matches all simple or compound variables that use stack storage.
#[derive(Debug, Clone, Copy)]
pub struct CompoundStackVariableFilter;

impl VariableFilter for CompoundStackVariableFilter {
    fn matches(&self, _is_parameter: bool, _is_auto_param: bool, _is_stack: bool,
               has_stack_storage: bool, _is_register: bool, _is_memory: bool,
               _is_unique: bool) -> bool {
        has_stack_storage
    }
}

/// Matches all simple register variables.
#[derive(Debug, Clone, Copy)]
pub struct RegisterVariableFilter;

impl VariableFilter for RegisterVariableFilter {
    fn matches(&self, _is_parameter: bool, _is_auto_param: bool, _is_stack: bool,
               _has_stack_storage: bool, is_register: bool, _is_memory: bool,
               _is_unique: bool) -> bool {
        is_register
    }
}

/// Matches all simple memory variables.
#[derive(Debug, Clone, Copy)]
pub struct MemoryVariableFilter;

impl VariableFilter for MemoryVariableFilter {
    fn matches(&self, _is_parameter: bool, _is_auto_param: bool, _is_stack: bool,
               _has_stack_storage: bool, _is_register: bool, is_memory: bool,
               _is_unique: bool) -> bool {
        is_memory
    }
}

/// Matches all simple unique variables (identified by hash).
#[derive(Debug, Clone, Copy)]
pub struct UniqueVariableFilter;

impl VariableFilter for UniqueVariableFilter {
    fn matches(&self, _is_parameter: bool, _is_auto_param: bool, _is_stack: bool,
               _has_stack_storage: bool, _is_register: bool, _is_memory: bool,
               is_unique: bool) -> bool {
        is_unique
    }
}

/// Predefined variable filters as constants.
pub mod filters {
    use super::*;

    /// Matches all parameters (includes auto-params).
    pub const PARAMETER_FILTER: ParameterFilter = ParameterFilter {
        allow_auto_params: true,
    };

    /// Matches all parameters which are not auto-params.
    pub const NONAUTO_PARAMETER_FILTER: NonAutoParameterFilter = NonAutoParameterFilter;

    /// Matches all local variables (non-parameters).
    pub const LOCAL_VARIABLE_FILTER: LocalVariableFilter = LocalVariableFilter;

    /// Matches all simple stack variables.
    pub const STACK_VARIABLE_FILTER: StackVariableFilter = StackVariableFilter;

    /// Matches all simple or compound variables using stack storage.
    pub const COMPOUND_STACK_VARIABLE_FILTER: CompoundStackVariableFilter =
        CompoundStackVariableFilter;

    /// Matches all simple register variables.
    pub const REGISTER_VARIABLE_FILTER: RegisterVariableFilter = RegisterVariableFilter;

    /// Matches all simple memory variables.
    pub const MEMORY_VARIABLE_FILTER: MemoryVariableFilter = MemoryVariableFilter;

    /// Matches all simple unique variables.
    pub const UNIQUE_VARIABLE_FILTER: UniqueVariableFilter = UniqueVariableFilter;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parameter_filter() {
        let f = filters::PARAMETER_FILTER;
        assert!(f.matches(true, false, false, false, false, false, false));
        assert!(f.matches(true, true, false, false, false, false, false));
        assert!(!f.matches(false, false, false, false, false, false, false));
    }

    #[test]
    fn test_nonautto_parameter_filter() {
        let f = filters::NONAUTO_PARAMETER_FILTER;
        assert!(f.matches(true, false, false, false, false, false, false));
        assert!(!f.matches(true, true, false, false, false, false, false));
        assert!(!f.matches(false, false, false, false, false, false, false));
    }

    #[test]
    fn test_local_variable_filter() {
        let f = filters::LOCAL_VARIABLE_FILTER;
        assert!(!f.matches(true, false, false, false, false, false, false));
        assert!(f.matches(false, false, true, false, false, false, false));
    }

    #[test]
    fn test_stack_variable_filter() {
        let f = filters::STACK_VARIABLE_FILTER;
        assert!(f.matches(false, false, true, false, false, false, false));
        assert!(!f.matches(false, false, false, false, true, false, false));
    }

    #[test]
    fn test_register_variable_filter() {
        let f = filters::REGISTER_VARIABLE_FILTER;
        assert!(f.matches(false, false, false, false, true, false, false));
        assert!(!f.matches(false, false, true, false, false, false, false));
    }

    #[test]
    fn test_memory_variable_filter() {
        let f = filters::MEMORY_VARIABLE_FILTER;
        assert!(f.matches(false, false, false, false, false, true, false));
        assert!(!f.matches(false, false, false, false, true, false, false));
    }

    #[test]
    fn test_unique_variable_filter() {
        let f = filters::UNIQUE_VARIABLE_FILTER;
        assert!(f.matches(false, false, false, false, false, false, true));
        assert!(!f.matches(false, false, true, false, false, false, false));
    }
}
