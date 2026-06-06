//! Port of `OptionsVetoException`.
use std::collections::HashMap;
/// Struct porting `OptionsVetoException`.
#[derive(Debug, Clone)]
pub struct OptionsVetoException {
    _phantom: std::marker::PhantomData<()>,
}
impl OptionsVetoException {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for OptionsVetoException {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_options_veto_exception_new() { let _ = OptionsVetoException::new(); }
}
