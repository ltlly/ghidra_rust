//! Port of `AbstractAnimator`.
use std::collections::HashMap;
/// Struct porting `AbstractAnimator`.
#[derive(Debug, Clone)]
pub struct AbstractAnimator {
    /// animator.
    pub animator: String,
}

impl AbstractAnimator {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for AbstractAnimator {
    fn default() -> Self {
        Self {
            animator: String::new(),
}
    }
}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_abstract_animator_new() { let _ = AbstractAnimator::new(); }
}
