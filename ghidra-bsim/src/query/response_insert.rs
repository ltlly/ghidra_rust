//! Port of `ResponseInsert`.
use std::collections::HashMap;
/// Struct porting `ResponseInsert`.
#[derive(Debug, Clone)]
pub struct ResponseInsert {
    /// numexe.
    pub numexe: i32,
    /// numfunc.
    pub numfunc: i32,
}

impl ResponseInsert {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for ResponseInsert {
    fn default() -> Self {
        Self {
            numexe: 0,
            numfunc: 0,
}
    }
}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_response_insert_new() { let _ = ResponseInsert::new(); }
}
