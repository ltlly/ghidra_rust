//! Port of `FunctionSymbolIterator`.
use std::collections::HashMap;
/// Struct porting `FunctionSymbolIterator`.
#[derive(Debug, Clone)]
pub struct FunctionSymbolIterator {
    _phantom: std::marker::PhantomData<()>,
}
impl FunctionSymbolIterator {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for FunctionSymbolIterator {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_function_symbol_iterator_new() { let _ = FunctionSymbolIterator::new(); }
}
