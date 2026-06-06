//! Port of `ScaledImageIcon`.
use std::collections::HashMap;
/// Struct porting `ScaledImageIcon`.
#[derive(Debug, Clone)]
pub struct ScaledImageIcon {
    _phantom: std::marker::PhantomData<()>,
}
impl ScaledImageIcon {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for ScaledImageIcon {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_scaled_image_icon_new() { let _ = ScaledImageIcon::new(); }
}
