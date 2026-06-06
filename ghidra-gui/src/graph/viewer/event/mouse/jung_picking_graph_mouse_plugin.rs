//! Port of `JungPickingGraphMousePlugin`.
use std::collections::HashMap;
/// Struct porting `JungPickingGraphMousePlugin`.
#[derive(Debug, Clone)]
pub struct JungPickingGraphMousePlugin {
    /// vertex.
    pub vertex: String,
    /// edge.
    pub edge: String,
    /// offsetx.
    pub offsetx: f64,
    /// offsety.
    pub offsety: f64,
    /// locked.
    pub locked: bool,
    /// add_to_selection_modifiers.
    pub add_to_selection_modifiers: i32,
}

impl JungPickingGraphMousePlugin {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for JungPickingGraphMousePlugin {
    fn default() -> Self {
        Self {
            vertex: String::new(),
            edge: String::new(),
            offsetx: 0,
            offsety: 0,
            locked: false,
            add_to_selection_modifiers: 0,
}
    }
}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_jung_picking_graph_mouse_plugin_new() { let _ = JungPickingGraphMousePlugin::new(); }
}
