//! Port of `NotMd5BSimFilterType`.
use std::collections::HashMap;
/// Struct porting `NotMd5BSimFilterType`.
#[derive(Debug, Clone)]
pub struct NotMd5BSimFilterType {
    /// xml_value.
    pub xml_value: String,
}

impl NotMd5BSimFilterType {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for NotMd5BSimFilterType {
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
    fn test_not_md5_b_sim_filter_type_new() { let _ = NotMd5BSimFilterType::new(); }
}
