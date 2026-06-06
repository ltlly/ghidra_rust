//! Port of `BSimServerDialog`.
use std::collections::HashMap;
/// Struct porting `BSimServerDialog`.
#[derive(Debug, Clone)]
pub struct BSimServerDialog {
    _phantom: std::marker::PhantomData<()>,
}
impl BSimServerDialog {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for BSimServerDialog {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_b_sim_server_dialog_new() { let _ = BSimServerDialog::new(); }
}
