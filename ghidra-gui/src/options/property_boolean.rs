//! Port of `PropertyBoolean`.
use std::collections::HashMap;
/// Struct porting `PropertyBoolean`.
#[derive(Debug, Clone)]
pub struct PropertyBoolean {
    _phantom: std::marker::PhantomData<()>,
}
impl PropertyBoolean {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for PropertyBoolean {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_property_boolean_new() { let _ = PropertyBoolean::new(); }
}
