//! Port of `StringPropertyValue`.
use std::collections::HashMap;
/// Struct porting `StringPropertyValue`.
#[derive(Debug, Clone)]
pub struct StringPropertyValue {
    _phantom: std::marker::PhantomData<()>,
}
impl StringPropertyValue {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for StringPropertyValue {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_string_property_value_new() { let _ = StringPropertyValue::new(); }
}
