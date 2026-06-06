//! Port of `ExecutableNameBSimFilterType`.
use std::collections::HashMap;
/// Struct porting `ExecutableNameBSimFilterType`.
#[derive(Debug, Clone)]
pub struct ExecutableNameBSimFilterType {
    /// xml_value.
    pub xml_value: String,
}

impl ExecutableNameBSimFilterType {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for ExecutableNameBSimFilterType {
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
    fn test_executable_name_b_sim_filter_type_new() { let _ = ExecutableNameBSimFilterType::new(); }
}
