//! Port of `CompilerBSimFilterType`.
use std::collections::HashMap;
/// Struct porting `CompilerBSimFilterType`.
#[derive(Debug, Clone)]
pub struct CompilerBSimFilterType {
    /// xml_value.
    pub xml_value: String,
}

impl CompilerBSimFilterType {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for CompilerBSimFilterType {
    fn default() -> Self {
        Self {
            xml_value: String::new(),
}
    }
}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_compiler_b_sim_filter_type_new() { let _ = CompilerBSimFilterType::new(); }
}
