//! Port of `MouseDebugPaintable`.
use std::collections::HashMap;
/// Struct porting `MouseDebugPaintable`.
#[derive(Debug, Clone)]
pub struct MouseDebugPaintable {
    _phantom: std::marker::PhantomData<()>,
}
impl MouseDebugPaintable {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for MouseDebugPaintable {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_mouse_debug_paintable_new() { let _ = MouseDebugPaintable::new(); }
}
