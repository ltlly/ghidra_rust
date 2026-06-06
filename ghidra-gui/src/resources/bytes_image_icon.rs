//! Port of `BytesImageIcon`.
use std::collections::HashMap;
/// Struct porting `BytesImageIcon`.
#[derive(Debug, Clone)]
pub struct BytesImageIcon {
    _phantom: std::marker::PhantomData<()>,
}
impl BytesImageIcon {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for BytesImageIcon {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_bytes_image_icon_new() { let _ = BytesImageIcon::new(); }
}
