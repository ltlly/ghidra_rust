//! Port of `JavaPropertyValue`.
use std::collections::HashMap;
/// Struct porting `JavaPropertyValue`.
#[derive(Debug, Clone)]
pub struct JavaPropertyValue {
    _phantom: std::marker::PhantomData<()>,
}
impl JavaPropertyValue {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for JavaPropertyValue {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_java_property_value_new() { let _ = JavaPropertyValue::new(); }
}
