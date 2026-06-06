//! Memory view zoom and navigation actions.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.gui.memview.actions` package.
//!
//! Provides action types for zooming in and out of the memory view widget,
//! as well as address navigation and format selection.

use serde::{Deserialize, Serialize};

/// The kind of zoom action to perform on the memory view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MemviewZoomActionKind {
    /// Zoom in (increase cell size, show more detail).
    ZoomIn,
    /// Zoom out (decrease cell size, show more area).
    ZoomOut,
    /// Zoom to fit the current selection.
    ZoomToFit,
    /// Reset to default zoom level.
    ZoomReset,
}

impl MemviewZoomActionKind {
    /// Return the display name.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::ZoomIn => "Zoom In (Address)",
            Self::ZoomOut => "Zoom Out (Address)",
            Self::ZoomToFit => "Zoom to Fit",
            Self::ZoomReset => "Reset Zoom",
        }
    }

    /// Return the action key name.
    pub fn action_key(&self) -> &'static str {
        match self {
            Self::ZoomIn => "ZoomIn",
            Self::ZoomOut => "ZoomOut",
            Self::ZoomToFit => "ZoomToFit",
            Self::ZoomReset => "ZoomReset",
        }
    }

    /// Return the icon name.
    pub fn icon_name(&self) -> &'static str {
        match self {
            Self::ZoomIn => "icon.widget.imagepanel.zoom.in",
            Self::ZoomOut => "icon.widget.imagepanel.zoom.out",
            Self::ZoomToFit => "icon.widget.imagepanel.zoom.fit",
            Self::ZoomReset => "icon.widget.imagepanel.zoom.reset",
        }
    }
}

/// A zoom action for the memory view panel.
///
/// Ported from `ZoomInAAction` / `ZoomOutAAction`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemviewZoomAction {
    /// The kind of zoom action.
    pub kind: MemviewZoomActionKind,
    /// Whether the action is currently enabled.
    pub enabled: bool,
    /// The action group for toolbar ordering.
    pub group: String,
    /// The sub-group for ordering within the group.
    pub sub_group: u32,
}

impl MemviewZoomAction {
    /// Create a new zoom action.
    pub fn new(kind: MemviewZoomActionKind) -> Self {
        Self {
            kind,
            enabled: true,
            group: "Zoom".into(),
            sub_group: 0,
        }
    }

    /// Create a zoom-in action.
    pub fn zoom_in() -> Self {
        Self::new(MemviewZoomActionKind::ZoomIn)
    }

    /// Create a zoom-out action.
    pub fn zoom_out() -> Self {
        Self::new(MemviewZoomActionKind::ZoomOut)
    }

    /// Create a zoom-to-fit action.
    pub fn zoom_to_fit() -> Self {
        Self::new(MemviewZoomActionKind::ZoomToFit)
    }

    /// Create a reset-zoom action.
    pub fn zoom_reset() -> Self {
        Self::new(MemviewZoomActionKind::ZoomReset)
    }
}

/// The navigation action kind for the memory view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MemviewNavActionKind {
    /// Go to a specific address.
    GoToAddress,
    /// Go to the next highlighted cell.
    GoToNextHighlight,
    /// Go to the previous highlighted cell.
    GoToPrevHighlight,
    /// Go to the start of the address range.
    GoToStart,
    /// Go to the end of the address range.
    GoToEnd,
}

impl MemviewNavActionKind {
    /// Return the display name.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::GoToAddress => "Go To Address",
            Self::GoToNextHighlight => "Go To Next Highlight",
            Self::GoToPrevHighlight => "Go To Previous Highlight",
            Self::GoToStart => "Go To Start",
            Self::GoToEnd => "Go To End",
        }
    }
}

/// A navigation action for the memory view panel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemviewNavAction {
    /// The kind of navigation action.
    pub kind: MemviewNavActionKind,
    /// Whether the action is currently enabled.
    pub enabled: bool,
}

impl MemviewNavAction {
    /// Create a new navigation action.
    pub fn new(kind: MemviewNavActionKind) -> Self {
        Self { kind, enabled: true }
    }
}

/// The format for displaying memory cells.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub enum MemviewCellFormat {
    /// Display as hex bytes.
    #[default]
    Hex,
    /// Display as decimal bytes.
    Decimal,
    /// Display as ASCII.
    Ascii,
    /// Display as binary.
    Binary,
}

impl MemviewCellFormat {
    /// Return the display name.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Hex => "Hex",
            Self::Decimal => "Decimal",
            Self::Ascii => "ASCII",
            Self::Binary => "Binary",
        }
    }
}

/// Configuration for all memory view actions.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MemviewActionConfig {
    /// The current zoom level (1.0 = 100%).
    pub zoom_level: f64,
    /// The minimum zoom level.
    pub min_zoom: f64,
    /// The maximum zoom level.
    pub max_zoom: f64,
    /// The zoom step per action.
    pub zoom_step: f64,
    /// The current cell format.
    pub cell_format: MemviewCellFormat,
    /// Whether to show address annotations.
    pub show_addresses: bool,
}

impl MemviewActionConfig {
    /// Create a default configuration.
    pub fn new() -> Self {
        Self {
            zoom_level: 1.0,
            min_zoom: 0.1,
            max_zoom: 16.0,
            zoom_step: 2.0,
            cell_format: MemviewCellFormat::Hex,
            show_addresses: true,
        }
    }

    /// Apply a zoom-in action.
    pub fn zoom_in(&mut self) {
        self.zoom_level = (self.zoom_level * self.zoom_step).min(self.max_zoom);
    }

    /// Apply a zoom-out action.
    pub fn zoom_out(&mut self) {
        self.zoom_level = (self.zoom_level / self.zoom_step).max(self.min_zoom);
    }

    /// Reset zoom to default.
    pub fn zoom_reset(&mut self) {
        self.zoom_level = 1.0;
    }

    /// Set zoom to a specific level.
    pub fn set_zoom(&mut self, level: f64) {
        self.zoom_level = level.clamp(self.min_zoom, self.max_zoom);
    }
}

/// Returns the complete set of zoom actions for the memory view panel.
pub fn all_zoom_actions() -> Vec<MemviewZoomAction> {
    vec![
        MemviewZoomAction::zoom_in(),
        MemviewZoomAction::zoom_out(),
        MemviewZoomAction::zoom_to_fit(),
        MemviewZoomAction::zoom_reset(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zoom_action_kind_names() {
        assert_eq!(
            MemviewZoomActionKind::ZoomIn.display_name(),
            "Zoom In (Address)"
        );
        assert_eq!(
            MemviewZoomActionKind::ZoomOut.action_key(),
            "ZoomOut"
        );
    }

    #[test]
    fn test_zoom_action_constructors() {
        let za = MemviewZoomAction::zoom_in();
        assert_eq!(za.kind, MemviewZoomActionKind::ZoomIn);
        assert!(za.enabled);

        let zo = MemviewZoomAction::zoom_out();
        assert_eq!(zo.kind, MemviewZoomActionKind::ZoomOut);

        let zt = MemviewZoomAction::zoom_to_fit();
        assert_eq!(zt.kind, MemviewZoomActionKind::ZoomToFit);

        let zr = MemviewZoomAction::zoom_reset();
        assert_eq!(zr.kind, MemviewZoomActionKind::ZoomReset);
    }

    #[test]
    fn test_zoom_action_icons() {
        assert!(MemviewZoomActionKind::ZoomIn.icon_name().contains("zoom.in"));
        assert!(MemviewZoomActionKind::ZoomOut.icon_name().contains("zoom.out"));
    }

    #[test]
    fn test_nav_action_kind_names() {
        assert_eq!(
            MemviewNavActionKind::GoToAddress.display_name(),
            "Go To Address"
        );
    }

    #[test]
    fn test_cell_format_names() {
        assert_eq!(MemviewCellFormat::Hex.display_name(), "Hex");
        assert_eq!(MemviewCellFormat::Ascii.display_name(), "ASCII");
    }

    #[test]
    fn test_action_config_new() {
        let cfg = MemviewActionConfig::new();
        assert!((cfg.zoom_level - 1.0).abs() < f64::EPSILON);
        assert_eq!(cfg.cell_format, MemviewCellFormat::Hex);
        assert!(cfg.show_addresses);
    }

    #[test]
    fn test_action_config_zoom_in() {
        let mut cfg = MemviewActionConfig::new();
        cfg.zoom_in();
        assert!((cfg.zoom_level - 2.0).abs() < f64::EPSILON);
        cfg.zoom_in();
        assert!((cfg.zoom_level - 4.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_action_config_zoom_out() {
        let mut cfg = MemviewActionConfig::new();
        cfg.zoom_level = 4.0;
        cfg.zoom_out();
        assert!((cfg.zoom_level - 2.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_action_config_zoom_clamp() {
        let mut cfg = MemviewActionConfig::new();
        cfg.set_zoom(100.0);
        assert!((cfg.zoom_level - 16.0).abs() < f64::EPSILON);
        cfg.set_zoom(0.001);
        assert!((cfg.zoom_level - 0.1).abs() < f64::EPSILON);
    }

    #[test]
    fn test_action_config_zoom_reset() {
        let mut cfg = MemviewActionConfig::new();
        cfg.zoom_level = 8.0;
        cfg.zoom_reset();
        assert!((cfg.zoom_level - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_all_zoom_actions() {
        let actions = all_zoom_actions();
        assert_eq!(actions.len(), 4);
    }

    #[test]
    fn test_nav_action() {
        let na = MemviewNavAction::new(MemviewNavActionKind::GoToNextHighlight);
        assert!(na.enabled);
        assert_eq!(
            na.kind,
            MemviewNavActionKind::GoToNextHighlight
        );
    }
}
