//! Port of `ResponseExe`.
use std::collections::HashMap;
/// Struct porting `ResponseExe`.
#[derive(Debug, Clone)]
pub struct ResponseExe {
    /// records.
    pub records: String,
    /// manage.
    pub manage: String,
    /// record_count.
    pub record_count: i32,
}

impl ResponseExe {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for ResponseExe {
    fn default() -> Self {
        Self {
            records: String::new(),
            manage: String::new(),
            record_count: 0,
}
    }
}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_response_exe_new() { let _ = ResponseExe::new(); }
}
