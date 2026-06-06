//! Port of `MouseBinding`.
use std::collections::HashMap;
/// Struct porting `MouseBinding`.
#[derive(Debug, Clone)]
pub struct MouseBinding {
    _phantom: std::marker::PhantomData<()>,
}
impl MouseBinding {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for MouseBinding {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_mouse_binding_new() { let _ = MouseBinding::new(); }
}
