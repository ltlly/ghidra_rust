//! Time overview panel.

/// Time overview panel.
#[derive(Debug, Clone)]
pub struct TimeOverviewPanel {
    /// snap_range_min
    pub snap_range_min: i64,
    /// snap_range_max
    pub snap_range_max: i64,
    /// marker_size
    pub marker_size: usize,
}

impl TimeOverviewPanel {
    /// Create a new TimeOverviewPanel.
    pub fn new(snap_range_min: i64, snap_range_max: i64, marker_size: usize) -> Self {
        Self { snap_range_min, snap_range_max, marker_size }
    }

    /// snap_range_min
    pub fn snap_range_min(&self) -> &i64 {
        &self.snap_range_min
    }

    /// snap_range_max
    pub fn snap_range_max(&self) -> &i64 {
        &self.snap_range_max
    }

    /// marker_size
    pub fn marker_size(&self) -> &usize {
        &self.marker_size
    }
}

impl Default for TimeOverviewPanel {
    fn default() -> Self {
        Self::new(Default::default(), Default::default(), Default::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_creation() {
        let obj = TimeOverviewPanel::new(0, 0, 4);
        assert!(true);
    }

    #[test]
    fn test_default() {
        let _obj = TimeOverviewPanel::default();
    }
}
