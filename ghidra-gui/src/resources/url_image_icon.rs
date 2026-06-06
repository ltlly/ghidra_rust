//! Port of `UrlImageIcon`.
use std::collections::HashMap;
/// Struct porting `UrlImageIcon`.
#[derive(Debug, Clone)]
pub struct UrlImageIcon {
    _phantom: std::marker::PhantomData<()>,
}
impl UrlImageIcon {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for UrlImageIcon {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_url_image_icon_new() { let _ = UrlImageIcon::new(); }
}
