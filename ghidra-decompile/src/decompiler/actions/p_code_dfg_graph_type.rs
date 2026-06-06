//! Port of `PCodeDfgGraphType`.
use std::collections::HashMap;
/// Struct porting `PCodeDfgGraphType`.
#[derive(Debug, Clone)]
pub struct PCodeDfgGraphType {
    /// DEFAULT_VERTEX
    pub default_vertex: String,
    /// CONSTANT
    pub constant: String,
    /// REGISTER
    pub register: String,
    /// UNIQUE
    pub unique: String,
    /// PERSISTENT
    pub persistent: String,
    /// ADDRESS_TIED
    pub address_tied: String,
}
impl PCodeDfgGraphType {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for PCodeDfgGraphType {
    fn default() -> Self {
        Self {
            default_vertex: String::new(),
            constant: String::new(),
            register: String::new(),
            unique: String::new(),
            persistent: String::new(),
            address_tied: String::new()
        }
    }


}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_p_code_dfg_graph_type_new() { let _ = PCodeDfgGraphType::new(); }
}
