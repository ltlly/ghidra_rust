//! Port of `FunctionTagBSimFilterType`.
use std::collections::HashMap;
/// Struct porting `FunctionTagBSimFilterType`.
#[derive(Debug, Clone)]
pub struct FunctionTagBSimFilterType {
    /// xml_value.
    pub xml_value: String,
    /// reserved_bits.
    pub reserved_bits: i32,
    /// max_tag_count.
    pub max_tag_count: i32,
    /// known_library_mask.
    pub known_library_mask: i32,
    /// has_unimplemented_mask.
    pub has_unimplemented_mask: i32,
    /// has_baddata_mask.
    pub has_baddata_mask: i32,
}

impl FunctionTagBSimFilterType {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for FunctionTagBSimFilterType {
    fn default() -> Self {
        Self {
            xml_value: String::new(),
            reserved_bits: 0,
            max_tag_count: 0,
            known_library_mask: 0,
            has_unimplemented_mask: 0,
            has_baddata_mask: 0,
}
    }
}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_function_tag_b_sim_filter_type_new() { let _ = FunctionTagBSimFilterType::new(); }
}
