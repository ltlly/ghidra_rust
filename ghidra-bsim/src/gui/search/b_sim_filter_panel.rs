//! Port of `BSimFilterPanel`.
use std::collections::HashMap;
/// Struct porting `BSimFilterPanel`.
#[derive(Debug, Clone)]
pub struct BSimFilterPanel {
    _phantom: std::marker::PhantomData<()>,
}
impl BSimFilterPanel {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for BSimFilterPanel {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_b_sim_filter_panel_new() { let _ = BSimFilterPanel::new(); }
}
