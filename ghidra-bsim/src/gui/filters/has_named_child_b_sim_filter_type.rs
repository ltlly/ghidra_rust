//! Port of `HasNamedChildBSimFilterType`.
use std::collections::HashMap;
/// Struct porting `HasNamedChildBSimFilterType`.
#[derive(Debug, Clone)]
pub struct HasNamedChildBSimFilterType {
    /// xml_value.
    pub xml_value: String,
}

impl HasNamedChildBSimFilterType {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for HasNamedChildBSimFilterType {
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
    fn test_has_named_child_b_sim_filter_type_new() { let _ = HasNamedChildBSimFilterType::new(); }
}
