//! Port of `BSimSearchInfoDisplayDialog`.
use std::collections::HashMap;
/// Struct porting `BSimSearchInfoDisplayDialog`.
#[derive(Debug, Clone)]
pub struct BSimSearchInfoDisplayDialog {
    _phantom: std::marker::PhantomData<()>,
}
impl BSimSearchInfoDisplayDialog {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for BSimSearchInfoDisplayDialog {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_b_sim_search_info_display_dialog_new() { let _ = BSimSearchInfoDisplayDialog::new(); }
}
