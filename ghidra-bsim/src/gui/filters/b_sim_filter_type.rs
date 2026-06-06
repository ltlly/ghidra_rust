//! Port of `BSimFilterType`.
use std::collections::HashMap;
/// Struct porting `BSimFilterType`.
#[derive(Debug, Clone)]
pub struct BSimFilterType {
    /// blank.
    pub blank: String,
    /// label.
    pub label: String,
    /// xmlval.
    pub xmlval: String,
    /// hint.
    pub hint: String,
}

impl BSimFilterType {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for BSimFilterType {
    fn default() -> Self {
        Self {
            blank: String::new(),
            label: String::new(),
            xmlval: String::new(),
            hint: String::new(),
}
    }
}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_b_sim_filter_type_new() { let _ = BSimFilterType::new(); }
}
