//! Port of `FillOutStructureCmd`.
use std::collections::HashMap;
/// Struct porting `FillOutStructureCmd`.
#[derive(Debug, Clone)]
pub struct FillOutStructureCmd {
    _phantom: std::marker::PhantomData<()>,
}
impl FillOutStructureCmd {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for FillOutStructureCmd {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_fill_out_structure_cmd_new() { let _ = FillOutStructureCmd::new(); }
}
