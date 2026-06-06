//! Port of `WrappedCustomOption`.
use std::collections::HashMap;
/// Struct porting `WrappedCustomOption`.
#[derive(Debug, Clone)]
pub struct WrappedCustomOption {
    _phantom: std::marker::PhantomData<()>,
}
impl WrappedCustomOption {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for WrappedCustomOption {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_wrapped_custom_option_new() { let _ = WrappedCustomOption::new(); }
}
