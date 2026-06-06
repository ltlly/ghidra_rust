//! Port of `ExecutableCategoryBSimFilterType`.
use std::collections::HashMap;
/// Struct porting `ExecutableCategoryBSimFilterType`.
#[derive(Debug, Clone)]
pub struct ExecutableCategoryBSimFilterType {
    /// xml_value.
    pub xml_value: String,
}

impl ExecutableCategoryBSimFilterType {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for ExecutableCategoryBSimFilterType {
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
    fn test_executable_category_b_sim_filter_type_new() { let _ = ExecutableCategoryBSimFilterType::new(); }
}
