//! Port of `TwinkleVertexAnimator`.
use std::collections::HashMap;
/// Struct porting `TwinkleVertexAnimator`.
#[derive(Debug, Clone)]
pub struct TwinkleVertexAnimator {
    _phantom: std::marker::PhantomData<()>,
}
impl TwinkleVertexAnimator {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for TwinkleVertexAnimator {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_twinkle_vertex_animator_new() { let _ = TwinkleVertexAnimator::new(); }
}
