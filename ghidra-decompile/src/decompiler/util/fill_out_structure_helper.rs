//! Port of `FillOutStructureHelper`.
use std::collections::HashMap;
/// Struct porting `FillOutStructureHelper`.
#[derive(Debug, Clone)]
pub struct FillOutStructureHelper {
    _phantom: std::marker::PhantomData<()>,
}
impl FillOutStructureHelper {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for FillOutStructureHelper {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_fill_out_structure_helper_new() { let _ = FillOutStructureHelper::new(); }
}
