//! Port of `QueryExeCount`.
use std::collections::HashMap;
/// Struct porting `QueryExeCount`.
#[derive(Debug, Clone)]
pub struct QueryExeCount {
    /// exeresponse.
    pub exeresponse: String,
    /// filter_md5.
    pub filter_md5: String,
    /// filter_exe_name.
    pub filter_exe_name: String,
    /// filter_arch.
    pub filter_arch: String,
    /// filter_compiler_name.
    pub filter_compiler_name: String,
    /// include_fakes.
    pub include_fakes: bool,
}

impl QueryExeCount {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for QueryExeCount {
    fn default() -> Self {
        Self {
            exeresponse: String::new(),
            filter_md5: String::new(),
            filter_exe_name: String::new(),
            filter_arch: String::new(),
            filter_compiler_name: String::new(),
            include_fakes: false,
}
    }
}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_query_exe_count_new() { let _ = QueryExeCount::new(); }
}
