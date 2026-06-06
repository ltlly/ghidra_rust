//! Port of `BlankBSimFilterType`.
use std::collections::HashMap;
/// Struct porting `BlankBSimFilterType`.
#[derive(Debug, Clone)]
pub struct BlankBSimFilterType {
    /// xml_value.
    pub xml_value: String,
}

impl BlankBSimFilterType {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for BlankBSimFilterType {
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
    fn test_blank_b_sim_filter_type_new() { let _ = BlankBSimFilterType::new(); }
}
