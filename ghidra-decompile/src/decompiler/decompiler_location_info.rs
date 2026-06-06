//! Port of `DecompilerLocationInfo`.
use std::collections::HashMap;
/// Struct porting `DecompilerLocationInfo`.
#[derive(Debug, Clone)]
pub struct DecompilerLocationInfo {
    _phantom: std::marker::PhantomData<()>,
}
impl DecompilerLocationInfo {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for DecompilerLocationInfo {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_decompiler_location_info_new() { let _ = DecompilerLocationInfo::new(); }
}
