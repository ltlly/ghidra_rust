//! Port of `DecompilerParameterIDValidator`.
use std::collections::HashMap;
/// Struct porting `DecompilerParameterIDValidator`.
#[derive(Debug, Clone)]
pub struct DecompilerParameterIDValidator {
    /// MIN_NUM_FUNCS
    pub min_num_funcs: String,
    /// MIN_NUM_FUNCS_DEFAULT
    pub min_num_funcs_default: i32,
}
impl DecompilerParameterIDValidator {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for DecompilerParameterIDValidator {
    fn default() -> Self {
        Self {
            min_num_funcs: String::new(),
            min_num_funcs_default: 0
        }


}}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_decompiler_parameter_id_validator_new() { let _ = DecompilerParameterIDValidator::new(); }
}
