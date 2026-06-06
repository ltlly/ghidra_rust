//! Port of `VisualGraphScalingGraphMousePlugin`.
use std::collections::HashMap;
/// Struct porting `VisualGraphScalingGraphMousePlugin`.
#[derive(Debug, Clone)]
pub struct VisualGraphScalingGraphMousePlugin {
    _phantom: std::marker::PhantomData<()>,
}
impl VisualGraphScalingGraphMousePlugin {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for VisualGraphScalingGraphMousePlugin {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_visual_graph_scaling_graph_mouse_plugin_new() { let _ = VisualGraphScalingGraphMousePlugin::new(); }
}
