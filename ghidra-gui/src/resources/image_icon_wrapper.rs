//! Port of `ImageIconWrapper`.
use std::collections::HashMap;
/// Struct porting `ImageIconWrapper`.
#[derive(Debug, Clone)]
pub struct ImageIconWrapper {
    _phantom: std::marker::PhantomData<()>,
}
impl ImageIconWrapper {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for ImageIconWrapper {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_image_icon_wrapper_new() { let _ = ImageIconWrapper::new(); }
}
