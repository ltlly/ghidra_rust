//! Port of `ArchitectureBSimFilterType`.
use std::collections::HashMap;
/// Struct porting `ArchitectureBSimFilterType`.
#[derive(Debug, Clone)]
pub struct ArchitectureBSimFilterType {
    /// xml_value.
    pub xml_value: String,
}

impl ArchitectureBSimFilterType {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for ArchitectureBSimFilterType {
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
    fn test_architecture_b_sim_filter_type_new() { let _ = ArchitectureBSimFilterType::new(); }
}
