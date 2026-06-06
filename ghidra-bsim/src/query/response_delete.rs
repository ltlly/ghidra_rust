//! Port of `ResponseDelete`.
use std::collections::HashMap;
/// Struct porting `ResponseDelete`.
#[derive(Debug, Clone)]
pub struct ResponseDelete {
    /// md5.
    pub md5: String,
    /// name.
    pub name: String,
    /// funccount.
    pub funccount: i32,
    /// reslist.
    pub reslist: String,
    /// missedlist.
    pub missedlist: String,
}

impl ResponseDelete {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for ResponseDelete {
    fn default() -> Self {
        Self {
            md5: String::new(),
            name: String::new(),
            funccount: 0,
            reslist: String::new(),
            missedlist: String::new(),
}
    }
}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_response_delete_new() { let _ = ResponseDelete::new(); }
}
