//! Port of `Decompiler`.
use std::collections::HashMap;
/// Struct porting `Decompiler`.
#[derive(Debug, Clone)]
pub struct Decompiler {
    _phantom: std::marker::PhantomData<()>,
}
impl Decompiler {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for Decompiler {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_decompiler_new() { let _ = Decompiler::new(); }
}
