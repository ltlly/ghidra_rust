//! Port of `DateBSimFilterType`.
use std::collections::HashMap;
/// Struct porting `DateBSimFilterType`.
#[derive(Debug, Clone)]
pub struct DateBSimFilterType {
    /// formatters.
    pub formatters: String,
}

impl DateBSimFilterType {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for DateBSimFilterType {
    fn default() -> Self {
        Self {
            formatters: String::new(),
}
    }
}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_date_b_sim_filter_type_new() { let _ = DateBSimFilterType::new(); }
}
