//! Port of `RotateIcon`.
use std::collections::HashMap;
/// Struct porting `RotateIcon`.
#[derive(Debug, Clone)]
pub struct RotateIcon {
    _phantom: std::marker::PhantomData<()>,
}
impl RotateIcon {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for RotateIcon {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_rotate_icon_new() { let _ = RotateIcon::new(); }
}
