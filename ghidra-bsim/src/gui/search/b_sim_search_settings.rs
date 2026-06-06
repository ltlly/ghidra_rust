//! Port of `BSimSearchSettings`.
use std::collections::HashMap;
/// Struct porting `BSimSearchSettings`.
#[derive(Debug, Clone)]
pub struct BSimSearchSettings {
    _phantom: std::marker::PhantomData<()>,
}
impl BSimSearchSettings {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for BSimSearchSettings {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_b_sim_search_settings_new() { let _ = BSimSearchSettings::new(); }
}
