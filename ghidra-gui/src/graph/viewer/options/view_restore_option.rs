//! Port of Ghidra's `ghidra.graph.viewer.options.ViewRestoreOption`.

/// Options for controlling view state restoration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ViewRestoreOption {
    /// Do not restore the previous view state.
    NoRestore,
    /// Restore the previous pan position.
    RestorePosition,
    /// Restore both pan position and zoom level.
    RestorePositionAndZoom,
    /// Restore pan, zoom, and vertex selection state.
    RestoreAll,
}

impl Default for ViewRestoreOption {
    fn default() -> Self { Self::RestorePositionAndZoom }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default() { assert_eq!(ViewRestoreOption::default(), ViewRestoreOption::RestorePositionAndZoom); }

    #[test]
    fn test_variants() { assert_ne!(ViewRestoreOption::NoRestore, ViewRestoreOption::RestoreAll); }
}
