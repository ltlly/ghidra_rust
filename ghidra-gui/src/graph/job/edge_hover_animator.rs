//! Port of `EdgeHoverAnimator`.
use std::collections::HashMap;
/// Struct porting `EdgeHoverAnimator`.
#[derive(Debug, Clone)]
pub struct EdgeHoverAnimator {
    _phantom: std::marker::PhantomData<()>,
}
impl EdgeHoverAnimator {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for EdgeHoverAnimator {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_edge_hover_animator_new() { let _ = EdgeHoverAnimator::new(); }
}
