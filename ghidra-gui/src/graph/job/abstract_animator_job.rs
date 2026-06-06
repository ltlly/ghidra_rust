//! Port of `AbstractAnimatorJob`.
use std::collections::HashMap;
/// Struct porting `AbstractAnimatorJob`.
#[derive(Debug, Clone)]
pub struct AbstractAnimatorJob {
    /// too_big_to_animate.
    pub too_big_to_animate: i32,
    /// log.
    pub log: String,
    /// animator.
    pub animator: String,
    /// is_shortcut.
    pub is_shortcut: bool,
}

impl AbstractAnimatorJob {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for AbstractAnimatorJob {
    fn default() -> Self {
        Self {
            too_big_to_animate: 0,
            log: String::new(),
            animator: String::new(),
            is_shortcut: false,
}
    }
}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_abstract_animator_job_new() { let _ = AbstractAnimatorJob::new(); }
}
