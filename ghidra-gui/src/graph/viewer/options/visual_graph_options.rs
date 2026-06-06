//! Port of `VisualGraphOptions`.
use std::collections::HashMap;
/// Struct porting `VisualGraphOptions`.
#[derive(Debug, Clone)]
pub struct VisualGraphOptions {
    /// graph_background_color_key.
    pub graph_background_color_key: String,
    /// graph_background_color_descrption.
    pub graph_background_color_descrption: String,
    /// show_animation_options_key.
    pub show_animation_options_key: String,
    /// show_animation_description.
    pub show_animation_description: String,
    /// use_mouse_relative_zoom_key.
    pub use_mouse_relative_zoom_key: String,
    /// use_mouse_relative_zoom_description.
    pub use_mouse_relative_zoom_description: String,
}

impl VisualGraphOptions {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for VisualGraphOptions {
    fn default() -> Self {
        Self {
            graph_background_color_key: String::new(),
            graph_background_color_descrption: String::new(),
            show_animation_options_key: String::new(),
            show_animation_description: String::new(),
            use_mouse_relative_zoom_key: String::new(),
            use_mouse_relative_zoom_description: String::new(),
}
    }
}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_visual_graph_options_new() { let _ = VisualGraphOptions::new(); }
}
