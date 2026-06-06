//! Port of `FlatDecompilerAPI`.
use std::collections::HashMap;
/// Struct porting `FlatDecompilerAPI`.
#[derive(Debug, Clone)]
pub struct FlatDecompilerAPI {
    /// flatProgramAPI
    pub flat_program_api: String,
    /// decompiler
    pub decompiler: String,
}
impl FlatDecompilerAPI {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for FlatDecompilerAPI {
    fn default() -> Self {
        Self {
            flat_program_api: String::new(),
            decompiler: String::new()
        }


}}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_flat_decompiler_api_new() { let _ = FlatDecompilerAPI::new(); }
}
