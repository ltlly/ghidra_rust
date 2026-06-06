//! Port of `Md5BSimFilterType`.
use std::collections::HashMap;
/// Struct porting `Md5BSimFilterType`.
#[derive(Debug, Clone)]
pub struct Md5BSimFilterType {
    /// xml_value.
    pub xml_value: String,
    /// md5_regex.
    pub md5_regex: String,
}

impl Md5BSimFilterType {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for Md5BSimFilterType {
    fn default() -> Self {
        Self {
            xml_value: String::new(),
            md5_regex: String::new(),
}
    }
}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_md5_b_sim_filter_type_new() { let _ = Md5BSimFilterType::new(); }
}
