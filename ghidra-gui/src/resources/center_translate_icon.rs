//! Port of `CenterTranslateIcon`.
use std::collections::HashMap;
/// Struct porting `CenterTranslateIcon`.
#[derive(Debug, Clone)]
pub struct CenterTranslateIcon {
    _phantom: std::marker::PhantomData<()>,
}
impl CenterTranslateIcon {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for CenterTranslateIcon {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_center_translate_icon_new() { let _ = CenterTranslateIcon::new(); }
}
