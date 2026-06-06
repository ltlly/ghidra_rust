//! Port of `ColorIcon`.
use std::collections::HashMap;
/// Struct porting `ColorIcon`.
#[derive(Debug, Clone)]
pub struct ColorIcon {
    _phantom: std::marker::PhantomData<()>,
}
impl ColorIcon {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for ColorIcon {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_color_icon_new() { let _ = ColorIcon::new(); }
}
