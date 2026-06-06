//! Port of `DisabledImageIcon`.
use std::collections::HashMap;
/// Struct porting `DisabledImageIcon`.
#[derive(Debug, Clone)]
pub struct DisabledImageIcon {
    _phantom: std::marker::PhantomData<()>,
}
impl DisabledImageIcon {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for DisabledImageIcon {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_disabled_image_icon_new() { let _ = DisabledImageIcon::new(); }
}
