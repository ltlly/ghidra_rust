//! Port of `LayoutPositions`.
use std::collections::HashMap;
/// Struct porting `LayoutPositions`.
#[derive(Debug, Clone)]
pub struct LayoutPositions {
    _phantom: std::marker::PhantomData<()>,
}
impl LayoutPositions {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for LayoutPositions {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_layout_positions_new() { let _ = LayoutPositions::new(); }
}
