//! Port of `PrimaryDecompilerProvider`.
use std::collections::HashMap;
/// Struct porting `PrimaryDecompilerProvider`.
#[derive(Debug, Clone)]
pub struct PrimaryDecompilerProvider {
    _phantom: std::marker::PhantomData<()>,
}
impl PrimaryDecompilerProvider {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for PrimaryDecompilerProvider {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_primary_decompiler_provider_new() { let _ = PrimaryDecompilerProvider::new(); }
}
