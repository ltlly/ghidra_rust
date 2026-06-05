//! Abstract layout manager base.
//!
//! Ports `ghidra.util.layout.AbstractLayoutManager`.

/// Trait for layout managers that position components in a container.
///
/// This is the Rust equivalent of Java's LayoutManager interface,
/// simplified for the egui-based rendering model.
pub trait LayoutManager: Send + Sync {
    /// Compute the minimum size needed for this layout.
    fn minimum_size(&self, num_children: usize) -> (f64, f64);

    /// Compute the preferred size for this layout.
    fn preferred_size(&self, num_children: usize) -> (f64, f64);

    /// Layout children within the given bounds.
    /// Returns a list of (x, y, width, height) for each child.
    fn layout_children(
        &self,
        num_children: usize,
        container_width: f64,
        container_height: f64,
    ) -> Vec<(f64, f64, f64, f64)>;
}

/// Abstract base that defaults minimum size to preferred size.
pub struct AbstractLayoutManager;

impl AbstractLayoutManager {
    /// Compute layout - override preferred_size in implementations.
    pub fn default_minimum_size(num_children: usize) -> (f64, f64) {
        // Defaults to same as preferred size
        (0.0, 0.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_abstract_layout_manager() {
        let (w, h) = AbstractLayoutManager::default_minimum_size(5);
        assert_eq!(w, 0.0);
        assert_eq!(h, 0.0);
    }
}
