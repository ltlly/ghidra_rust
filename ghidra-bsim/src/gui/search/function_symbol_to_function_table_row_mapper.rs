//! Port of `FunctionSymbolToFunctionTableRowMapper`.
use std::collections::HashMap;
/// Struct porting `FunctionSymbolToFunctionTableRowMapper`.
#[derive(Debug, Clone)]
pub struct FunctionSymbolToFunctionTableRowMapper {
    _phantom: std::marker::PhantomData<()>,
}
impl FunctionSymbolToFunctionTableRowMapper {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for FunctionSymbolToFunctionTableRowMapper {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_function_symbol_to_function_table_row_mapper_new() { let _ = FunctionSymbolToFunctionTableRowMapper::new(); }
}
