//! Port of `AbstractGraphVisibilityTransitionJob`.
use std::collections::HashMap;
/// Struct porting `AbstractGraphVisibilityTransitionJob`.
#[derive(Debug, Clone)]
pub struct AbstractGraphVisibilityTransitionJob {
    /// normal_duration.
    pub normal_duration: i32,
    /// fast_duration.
    pub fast_duration: i32,
    /// duration.
    pub duration: i32,
    /// use_animation.
    pub use_animation: bool,
}

impl AbstractGraphVisibilityTransitionJob {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for AbstractGraphVisibilityTransitionJob {
    fn default() -> Self {
        Self {
            normal_duration: 0,
            fast_duration: 0,
            duration: 0,
            use_animation: false,
}
    }
}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_abstract_graph_visibility_transition_job_new() { let _ = AbstractGraphVisibilityTransitionJob::new(); }
}
