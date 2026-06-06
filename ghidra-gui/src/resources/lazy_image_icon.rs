//! Port of `LazyImageIcon`.
use std::collections::HashMap;
/// Struct porting `LazyImageIcon`.
#[derive(Debug, Clone)]
pub struct LazyImageIcon {
    _phantom: std::marker::PhantomData<()>,
}
impl LazyImageIcon {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for LazyImageIcon {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_lazy_image_icon_new() { let _ = LazyImageIcon::new(); }
}
