//! Port of `DateEarlierBSimFilterType`.
use std::collections::HashMap;
/// Struct porting `DateEarlierBSimFilterType`.
#[derive(Debug, Clone)]
pub struct DateEarlierBSimFilterType {
    /// xml_value.
    pub xml_value: String,
}

impl DateEarlierBSimFilterType {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for DateEarlierBSimFilterType {
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
    fn test_date_earlier_b_sim_filter_type_new() { let _ = DateEarlierBSimFilterType::new(); }
}
