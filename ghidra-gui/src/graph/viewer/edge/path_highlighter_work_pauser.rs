//! Port of Ghidra's `ghidra.graph.viewer.edge.PathHighlighterWorkPauser`.
//!
//! Controls when path highlighting should be paused (e.g., during layout animations).

/// Trait for controlling when path highlight computation should be paused.
pub trait PathHighlighterWorkPauser: Send + Sync {
    /// Return true if path highlighting should be paused right now.
    fn is_paused(&self) -> bool;
    /// Notify that a layout animation has started.
    fn layout_animation_started(&self) {}
    /// Notify that a layout animation has finished.
    fn layout_animation_finished(&self) {}
}

/// Default implementation: never paused.
#[derive(Debug, Default)]
pub struct NeverPaused;
impl PathHighlighterWorkPauser for NeverPaused {
    fn is_paused(&self) -> bool { false }
}

/// Implementation that pauses during layout animations.
#[derive(Debug, Default)]
pub struct AnimationPauser {
    animating: std::sync::atomic::AtomicBool,
}
impl PathHighlighterWorkPauser for AnimationPauser {
    fn is_paused(&self) -> bool {
        self.animating.load(std::sync::atomic::Ordering::Relaxed)
    }
    fn layout_animation_started(&self) {
        self.animating.store(true, std::sync::atomic::Ordering::Relaxed);
    }
    fn layout_animation_finished(&self) {
        self.animating.store(false, std::sync::atomic::Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_never_paused() {
        let p = NeverPaused;
        assert!(!p.is_paused());
    }

    #[test]
    fn test_animation_pauser() {
        let p = AnimationPauser::default();
        assert!(!p.is_paused());
        p.layout_animation_started();
        assert!(p.is_paused());
        p.layout_animation_finished();
        assert!(!p.is_paused());
    }
}
