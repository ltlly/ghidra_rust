//! Port of `GGlassPane`.
use std::collections::HashMap;
/// Struct porting `GGlassPane`.
#[derive(Debug, Clone)]
pub struct GGlassPane {
    _phantom: std::marker::PhantomData<()>,
}
impl GGlassPane {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for GGlassPane {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_g_glass_pane_new() { let _ = GGlassPane::new(); }
}
