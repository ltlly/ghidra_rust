//! Port of `NotExecutableCategoryBSimFilterType`.
use std::collections::HashMap;
/// Struct porting `NotExecutableCategoryBSimFilterType`.
#[derive(Debug, Clone)]
pub struct NotExecutableCategoryBSimFilterType {
    /// xml_value.
    pub xml_value: String,
}

impl NotExecutableCategoryBSimFilterType {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for NotExecutableCategoryBSimFilterType {
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
    fn test_not_executable_category_b_sim_filter_type_new() { let _ = NotExecutableCategoryBSimFilterType::new(); }
}
