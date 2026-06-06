//! Port of `BooleanPropertyValue`.
use std::collections::HashMap;
/// Struct porting `BooleanPropertyValue`.
#[derive(Debug, Clone)]
pub struct BooleanPropertyValue {
    _phantom: std::marker::PhantomData<()>,
}
impl BooleanPropertyValue {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for BooleanPropertyValue {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_boolean_property_value_new() { let _ = BooleanPropertyValue::new(); }
}
