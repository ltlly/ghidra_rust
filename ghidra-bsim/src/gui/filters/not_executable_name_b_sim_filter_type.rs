//! Port of `NotExecutableNameBSimFilterType`.
use std::collections::HashMap;
/// Struct porting `NotExecutableNameBSimFilterType`.
#[derive(Debug, Clone)]
pub struct NotExecutableNameBSimFilterType {
    /// xml_value.
    pub xml_value: String,
}

impl NotExecutableNameBSimFilterType {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for NotExecutableNameBSimFilterType {
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
    fn test_not_executable_name_b_sim_filter_type_new() { let _ = NotExecutableNameBSimFilterType::new(); }
}
