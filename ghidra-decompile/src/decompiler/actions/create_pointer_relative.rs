//! Port of `CreatePointerRelative`.
use std::collections::HashMap;
/// Struct porting `CreatePointerRelative`.
#[derive(Debug, Clone)]
pub struct CreatePointerRelative {
    /// op
    pub op: String,
    /// slot
    pub slot: i32,
    /// offset
    pub offset: i32,
    /// iterForward
    pub iter_forward: String,
    /// dataType
    pub data_type: String,
}
impl CreatePointerRelative {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for CreatePointerRelative {
    fn default() -> Self {
        Self {
            op: String::new(),
            slot: 0,
            offset: 0,
            iter_forward: String::new(),
            data_type: String::new()
        }
    }


}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_create_pointer_relative_new() { let _ = CreatePointerRelative::new(); }
}
