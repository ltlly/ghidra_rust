//! Port of `IconWrapper`.
use std::collections::HashMap;
/// Struct porting `IconWrapper`.
#[derive(Debug, Clone)]
pub struct IconWrapper {
    _phantom: std::marker::PhantomData<()>,
}
impl IconWrapper {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for IconWrapper {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_icon_wrapper_new() { let _ = IconWrapper::new(); }
}
