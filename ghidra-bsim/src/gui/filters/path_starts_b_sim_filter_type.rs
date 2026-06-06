//! Port of `PathStartsBSimFilterType`.
use std::collections::HashMap;
/// Struct porting `PathStartsBSimFilterType`.
#[derive(Debug, Clone)]
pub struct PathStartsBSimFilterType {
    /// xml_value.
    pub xml_value: String,
}

impl PathStartsBSimFilterType {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for PathStartsBSimFilterType {
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
    fn test_path_starts_b_sim_filter_type_new() { let _ = PathStartsBSimFilterType::new(); }
}
