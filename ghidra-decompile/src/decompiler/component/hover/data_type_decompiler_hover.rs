//! Port of `DataTypeDecompilerHover`.
use std::collections::HashMap;
/// Struct porting `DataTypeDecompilerHover`.
#[derive(Debug, Clone)]
pub struct DataTypeDecompilerHover {
    _phantom: std::marker::PhantomData<()>,
}
impl DataTypeDecompilerHover {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for DataTypeDecompilerHover {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_data_type_decompiler_hover_new() { let _ = DataTypeDecompilerHover::new(); }
}
