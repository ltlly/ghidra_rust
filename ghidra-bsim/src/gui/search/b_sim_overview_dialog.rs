//! Port of `BSimOverviewDialog`.
use std::collections::HashMap;
/// Struct porting `BSimOverviewDialog`.
#[derive(Debug, Clone)]
pub struct BSimOverviewDialog {
    _phantom: std::marker::PhantomData<()>,
}
impl BSimOverviewDialog {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for BSimOverviewDialog {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_b_sim_overview_dialog_new() { let _ = BSimOverviewDialog::new(); }
}
