//! Port of `NotCompilerBSimFilterType`.
use std::collections::HashMap;
/// Struct porting `NotCompilerBSimFilterType`.
#[derive(Debug, Clone)]
pub struct NotCompilerBSimFilterType {
    /// xml_value.
    pub xml_value: String,
}

impl NotCompilerBSimFilterType {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for NotCompilerBSimFilterType {
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
    fn test_not_compiler_b_sim_filter_type_new() { let _ = NotCompilerBSimFilterType::new(); }
}
