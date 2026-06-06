//! Port of `ResponseUpdate`.
use std::collections::HashMap;
/// Struct porting `ResponseUpdate`.
#[derive(Debug, Clone)]
pub struct ResponseUpdate {
    /// badexe.
    pub badexe: String,
    /// badfunc.
    pub badfunc: String,
    /// exeupdate.
    pub exeupdate: i32,
    /// funcupdate.
    pub funcupdate: i32,
    /// qupdate.
    pub qupdate: String,
}

impl ResponseUpdate {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for ResponseUpdate {
    fn default() -> Self {
        Self {
            badexe: String::new(),
            badfunc: String::new(),
            exeupdate: 0,
            funcupdate: 0,
            qupdate: String::new(),
}
    }
}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_response_update_new() { let _ = ResponseUpdate::new(); }
}
