//! Port of `OvalColorIcon`.
use std::collections::HashMap;
/// Struct porting `OvalColorIcon`.
#[derive(Debug, Clone)]
pub struct OvalColorIcon {
    _phantom: std::marker::PhantomData<()>,
}
impl OvalColorIcon {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for OvalColorIcon {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_oval_color_icon_new() { let _ = OvalColorIcon::new(); }
}
