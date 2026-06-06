//! Port of `ExecutableRecord`.
use std::collections::HashMap;
/// Struct porting `ExecutableRecord`.
#[derive(Debug, Clone)]
pub struct ExecutableRecord {
    /// empty_date.
    pub empty_date: String,
    /// already_stored.
    pub already_stored: i32,
    /// library.
    pub library: i32,
    /// categories_set.
    pub categories_set: i32,
    /// metadata_name.
    pub metadata_name: i32,
    /// metadata_arch.
    pub metadata_arch: i32,
}

impl ExecutableRecord {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for ExecutableRecord {
    fn default() -> Self {
        Self {
            empty_date: String::new(),
            already_stored: 0,
            library: 0,
            categories_set: 0,
            metadata_name: 0,
            metadata_arch: 0,
}
    }
}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_executable_record_new() { let _ = ExecutableRecord::new(); }
}
