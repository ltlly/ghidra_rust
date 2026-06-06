//! Port of `ChunkingParallelDecompiler`.
use std::collections::HashMap;
/// Struct porting `ChunkingParallelDecompiler`.
#[derive(Debug, Clone)]
pub struct ChunkingParallelDecompiler {
    _phantom: std::marker::PhantomData<()>,
}
impl ChunkingParallelDecompiler {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for ChunkingParallelDecompiler {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_chunking_parallel_decompiler_new() { let _ = ChunkingParallelDecompiler::new(); }
}
