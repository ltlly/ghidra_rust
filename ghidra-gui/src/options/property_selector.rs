//! Port of `PropertySelector`.
use std::collections::HashMap;
/// Struct porting `PropertySelector`.
#[derive(Debug, Clone)]
pub struct PropertySelector {
    _phantom: std::marker::PhantomData<()>,
}
impl PropertySelector {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for PropertySelector {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_property_selector_new() { let _ = PropertySelector::new(); }
}
