//! Port of `DockingVisualVertex`.
use std::collections::HashMap;
/// Struct porting `DockingVisualVertex`.
#[derive(Debug, Clone)]
pub struct DockingVisualVertex {
    _phantom: std::marker::PhantomData<()>,
}
impl DockingVisualVertex {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for DockingVisualVertex {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_docking_visual_vertex_new() { let _ = DockingVisualVertex::new(); }
}
