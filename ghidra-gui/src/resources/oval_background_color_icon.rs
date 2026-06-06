//! Port of `OvalBackgroundColorIcon`.
use std::collections::HashMap;
/// Struct porting `OvalBackgroundColorIcon`.
#[derive(Debug, Clone)]
pub struct OvalBackgroundColorIcon {
    _phantom: std::marker::PhantomData<()>,
}
impl OvalBackgroundColorIcon {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for OvalBackgroundColorIcon {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_oval_background_color_icon_new() { let _ = OvalBackgroundColorIcon::new(); }
}
