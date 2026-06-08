//! Layout algorithm for the data exploration graph.
//!
//! Ported from Ghidra's `datagraph.data.graph.DegLayout` Java class.

use std::collections::HashMap;

/// A 2D coordinate for graph layout.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Coord {
    pub x: f64,
    pub y: f64,
}

impl Coord {
    pub fn new(x: f64, y: f64) -> Self { Self { x, y } }
}

/// Layout configuration for the data exploration graph.
#[derive(Debug, Clone)]
pub struct DegLayoutConfig {
    /// Horizontal spacing between vertices.
    pub horizontal_spacing: f64,
    /// Vertical spacing between vertices.
    pub vertical_spacing: f64,
    /// Maximum vertices per row.
    pub max_per_row: usize,
    /// Layout direction (left-to-right or top-to-bottom).
    pub direction: LayoutDirection,
}

/// Direction of graph layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LayoutDirection {
    LeftToRight,
    TopToBottom,
}

impl Default for DegLayoutConfig {
    fn default() -> Self {
        Self {
            horizontal_spacing: 150.0,
            vertical_spacing: 100.0,
            max_per_row: 8,
            direction: LayoutDirection::TopToBottom,
        }
    }
}

/// Computes vertex positions for the data exploration graph.
#[derive(Debug)]
pub struct DegLayout {
    /// Layout configuration.
    pub config: DegLayoutConfig,
    /// Computed positions: vertex ID -> coordinate.
    pub positions: HashMap<u64, Coord>,
}

impl DegLayout {
    pub fn new(config: DegLayoutConfig) -> Self {
        Self {
            config,
            positions: HashMap::new(),
        }
    }

    /// Compute layout for the given vertex IDs.
    pub fn compute_layout(&mut self, vertex_ids: &[u64]) {
        self.positions.clear();
        let max = self.config.max_per_row.max(1);
        for (i, &vid) in vertex_ids.iter().enumerate() {
            let col = i % max;
            let row = i / max;
            let x = col as f64 * self.config.horizontal_spacing;
            let y = row as f64 * self.config.vertical_spacing;
            self.positions.insert(vid, Coord::new(x, y));
        }
    }

    pub fn get_position(&self, vertex_id: u64) -> Option<&Coord> {
        self.positions.get(&vertex_id)
    }
}

impl Default for DegLayout {
    fn default() -> Self {
        Self::new(DegLayoutConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_layout_config_default() {
        let c = DegLayoutConfig::default();
        assert_eq!(c.horizontal_spacing, 150.0);
        assert_eq!(c.vertical_spacing, 100.0);
        assert_eq!(c.max_per_row, 8);
    }

    #[test]
    fn test_compute_layout() {
        let mut layout = DegLayout::default();
        layout.compute_layout(&[1, 2, 3, 4, 5]);
        assert_eq!(layout.positions.len(), 5);
        assert_eq!(layout.get_position(1), Some(&Coord::new(0.0, 0.0)));
        assert_eq!(layout.get_position(2), Some(&Coord::new(150.0, 0.0)));
        assert_eq!(layout.get_position(9), None);
    }
}
