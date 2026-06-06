//! Port of `ScaledImageIconWrapper`.
use std::collections::HashMap;
/// Struct porting `ScaledImageIconWrapper`.
#[derive(Debug, Clone)]
pub struct ScaledImageIconWrapper {
    _phantom: std::marker::PhantomData<()>,
}
impl ScaledImageIconWrapper {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for ScaledImageIconWrapper {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_scaled_image_icon_wrapper_new() { let _ = ScaledImageIconWrapper::new(); }
}
