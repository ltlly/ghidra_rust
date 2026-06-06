//! Port of `NotArchitectureBSimFilterType`.
use std::collections::HashMap;
/// Struct porting `NotArchitectureBSimFilterType`.
#[derive(Debug, Clone)]
pub struct NotArchitectureBSimFilterType {
    /// xml_value.
    pub xml_value: String,
}

impl NotArchitectureBSimFilterType {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for NotArchitectureBSimFilterType {
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
    fn test_not_architecture_b_sim_filter_type_new() { let _ = NotArchitectureBSimFilterType::new(); }
}
