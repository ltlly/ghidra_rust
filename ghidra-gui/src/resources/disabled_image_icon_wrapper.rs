//! Port of `DisabledImageIconWrapper`.
use std::collections::HashMap;
/// Struct porting `DisabledImageIconWrapper`.
#[derive(Debug, Clone)]
pub struct DisabledImageIconWrapper {
    _phantom: std::marker::PhantomData<()>,
}
impl DisabledImageIconWrapper {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for DisabledImageIconWrapper {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_disabled_image_icon_wrapper_new() { let _ = DisabledImageIconWrapper::new(); }
}
