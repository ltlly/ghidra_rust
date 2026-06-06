//! Port of `DerivedImageIcon`.
use std::collections::HashMap;
/// Struct porting `DerivedImageIcon`.
#[derive(Debug, Clone)]
pub struct DerivedImageIcon {
    _phantom: std::marker::PhantomData<()>,
}
impl DerivedImageIcon {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for DerivedImageIcon {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_derived_image_icon_new() { let _ = DerivedImageIcon::new(); }
}
