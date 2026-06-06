//! Port of `ParallelDecompiler`.
use std::collections::HashMap;
/// Struct porting `ParallelDecompiler`.
#[derive(Debug, Clone)]
pub struct ParallelDecompiler {
    _phantom: std::marker::PhantomData<()>,
}
impl ParallelDecompiler {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for ParallelDecompiler {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_parallel_decompiler_new() { let _ = ParallelDecompiler::new(); }
}
