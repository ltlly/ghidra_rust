//! Port of `PropertyText`.
use std::collections::HashMap;
/// Struct porting `PropertyText`.
#[derive(Debug, Clone)]
pub struct PropertyText {
    _phantom: std::marker::PhantomData<()>,
}
impl PropertyText {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for PropertyText {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_property_text_new() { let _ = PropertyText::new(); }
}
