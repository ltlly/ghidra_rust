//! Port of `DateLaterBSimFilterType`.
use std::collections::HashMap;
/// Struct porting `DateLaterBSimFilterType`.
#[derive(Debug, Clone)]
pub struct DateLaterBSimFilterType {
    /// xml_value.
    pub xml_value: String,
}

impl DateLaterBSimFilterType {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for DateLaterBSimFilterType {
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
    fn test_date_later_b_sim_filter_type_new() { let _ = DateLaterBSimFilterType::new(); }
}
