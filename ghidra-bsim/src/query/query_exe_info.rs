//! Port of `QueryExeInfo`.
use std::collections::HashMap;
/// Struct porting `QueryExeInfo`.
#[derive(Debug, Clone)]
pub struct QueryExeInfo {
    /// exeresponse.
    pub exeresponse: String,
    /// limit.
    pub limit: i32,
    /// filter_md5.
    pub filter_md5: String,
    /// filter_exe_name.
    pub filter_exe_name: String,
    /// filter_arch.
    pub filter_arch: String,
    /// filter_compiler_name.
    pub filter_compiler_name: String,
}

impl QueryExeInfo {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for QueryExeInfo {
    fn default() -> Self {
        Self {
            exeresponse: String::new(),
            limit: 0,
            filter_md5: String::new(),
            filter_exe_name: String::new(),
            filter_arch: String::new(),
            filter_compiler_name: String::new(),
}
    }
}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_query_exe_info_new() { let _ = QueryExeInfo::new(); }
}
