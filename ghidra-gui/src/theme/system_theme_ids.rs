//! System theme IDs that work regardless of the active look-and-feel.
//!
//! Ports `generic.theme.SystemThemeIds`. These IDs are used by the
//! application for common UI concepts (control, view, menu, tooltip).
//! Each category has background, foreground, selected-bg/fg, disabled,
//! focus, and border variants.

/// Standard control widget IDs (buttons, checkboxes, etc.).
pub mod control {
    /// Background color for control widgets.
    pub const BG: &str = "color.bg.control";
    /// Foreground color for control widgets.
    pub const FG: &str = "color.fg.control";
    /// Background color when selected.
    pub const BG_SELECTED: &str = "color.bg.control.selected";
    /// Foreground color when selected.
    pub const FG_SELECTED: &str = "color.fg.control.selected";
    /// Foreground color when disabled.
    pub const FG_DISABLED: &str = "color.fg.control.disabled";
    /// Background color when focused.
    pub const BG_FOCUS: &str = "color.bg.control.focus";
    /// Border color.
    pub const BORDER: &str = "color.border.control";
    /// Font for control widgets.
    pub const FONT: &str = "font.control";
}

/// Standard view widget IDs (trees, tables, text fields, lists).
pub mod view {
    /// Background color for view widgets.
    pub const BG: &str = "color.bg.view";
    /// Foreground color for view widgets.
    pub const FG: &str = "color.fg.view";
    /// Background color when selected.
    pub const BG_SELECTED: &str = "color.bg.view.selected";
    /// Foreground color when selected.
    pub const FG_SELECTED: &str = "color.fg.view.selected";
    /// Foreground color when disabled.
    pub const FG_DISABLED: &str = "color.fg.view.disabled";
    /// Background color for alternating rows.
    pub const BG_ALTERNATE: &str = "color.bg.view.alternate";
    /// Border color.
    pub const BORDER: &str = "color.border.view";
    /// Font for view widgets.
    pub const FONT: &str = "font.view";
}

/// Standard menu widget IDs.
pub mod menu {
    /// Background color for menu widgets.
    pub const BG: &str = "color.bg.menu";
    /// Foreground color for menu widgets.
    pub const FG: &str = "color.fg.menu";
    /// Background color when selected.
    pub const BG_SELECTED: &str = "color.bg.menu.selected";
    /// Foreground color when selected.
    pub const FG_SELECTED: &str = "color.fg.menu.selected";
    /// Foreground color when disabled.
    pub const FG_DISABLED: &str = "color.fg.menu.disabled";
    /// Font for menu widgets.
    pub const FONT: &str = "font.menu";
}

/// Standard tooltip widget IDs.
pub mod tooltip {
    /// Background color for tooltips.
    pub const BG: &str = "color.bg.tooltip";
    /// Foreground color for tooltips.
    pub const FG: &str = "color.fg.tooltip";
    /// Font for tooltips.
    pub const FONT: &str = "font.tooltip";
    /// Border color for tooltips.
    pub const BORDER: &str = "color.border.tooltip";
}

/// Standard separator IDs.
pub mod separator {
    /// Separator color.
    pub const COLOR: &str = "color.separator";
}

/// Standard window/widget IDs.
pub mod window {
    /// Active caption background.
    pub const ACTIVE_CAPTION_BG: &str = "color.bg.window.active.caption";
    /// Active caption foreground.
    pub const ACTIVE_CAPTION_FG: &str = "color.fg.window.active.caption";
    /// Inactive caption background.
    pub const INACTIVE_CAPTION_BG: &str = "color.bg.window.inactive.caption";
    /// Inactive caption foreground.
    pub const INACTIVE_CAPTION_FG: &str = "color.fg.window.inactive.caption";
}

/// Standard highlight IDs.
pub mod highlight {
    /// Visual graph highlight background.
    pub const VISUAL_GRAPH_BG: &str = "color.bg.highlight.visualgraph";
    /// Drop shadow dark color.
    pub const DROP_SHADOW_DARK: &str = "color.bg.visualgraph.drop.shadow.dark";
    /// Drop shadow light color.
    pub const DROP_SHADOW_LIGHT: &str = "color.bg.visualgraph.drop.shadow.light";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_control_ids_are_strings() {
        assert!(!control::BG.is_empty());
        assert!(!control::FG.is_empty());
        assert!(!control::FONT.is_empty());
    }

    #[test]
    fn test_view_ids() {
        assert!(view::BG.contains("view"));
        assert!(view::BG_ALTERNATE.contains("alternate"));
    }

    #[test]
    fn test_menu_ids() {
        assert!(menu::BG.contains("menu"));
    }

    #[test]
    fn test_tooltip_ids() {
        assert!(tooltip::BG.contains("tooltip"));
    }

    #[test]
    fn test_highlight_ids() {
        assert!(highlight::VISUAL_GRAPH_BG.contains("visualgraph"));
    }
}
