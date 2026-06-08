//! Flow Arrow panel interactions and configuration.
//!
//! Ported from `ghidra.app.plugin.core.flowarrow.FlowArrowPanel` (401 lines).
//!
//! Provides the interaction model for the flow arrow panel including
//! mouse click handling, cursor management, tooltip generation,
//! layered paint logic, and animated navigation.
//!
//! Also includes [`FlowArrowConfig`] for display options.

use super::{
    FlowArrow, FlowArrowShape, FlowArrowShapeFactory, FlowArrowType,
    Point, StrokeStyle,
};
use ghidra_core::Address;
use std::collections::BTreeMap;

// ============================================================================
// FlowArrowConfig -- display configuration
// ============================================================================

/// Configuration for which flow arrow types to display.
///
/// Ported from the options registered in `FlowArrowPlugin.getOptions()`.
#[derive(Debug, Clone)]
pub struct FlowArrowConfig {
    /// Show fall-through arrows.
    pub show_fall_through: bool,
    /// Show conditional jump arrows.
    pub show_conditional_jump: bool,
    /// Show unconditional jump arrows.
    pub show_unconditional_jump: bool,
    /// Show call arrows.
    pub show_call: bool,
    /// Maximum arrow span (number of addresses) before clipping.
    pub max_arrow_span: u64,
    /// Non-active arrow color (R, G, B).
    pub color_non_active: (u8, u8, u8),
    /// Active arrow color (R, G, B).
    pub color_active: (u8, u8, u8),
    /// Selected arrow color (R, G, B).
    pub color_selected: (u8, u8, u8),
}

impl Default for FlowArrowConfig {
    fn default() -> Self {
        Self {
            show_fall_through: false,
            show_conditional_jump: true,
            show_unconditional_jump: true,
            show_call: false,
            max_arrow_span: 0x10000,
            color_non_active: (128, 128, 128),
            color_active: (0, 128, 255),
            color_selected: (255, 128, 0),
        }
    }
}

impl FlowArrowConfig {
    /// Whether an arrow should be displayed based on this configuration.
    pub fn should_show(&self, arrow: &FlowArrow) -> bool {
        match arrow.arrow_type {
            FlowArrowType::FallThrough => self.show_fall_through,
            FlowArrowType::ConditionalForward | FlowArrowType::ConditionalBackward => {
                self.show_conditional_jump
            }
            FlowArrowType::JumpForward | FlowArrowType::JumpBackward => {
                self.show_unconditional_jump
            }
            FlowArrowType::Call => self.show_call,
        }
    }

    /// Get the color for an arrow based on its state.
    pub fn get_color(&self, arrow: &FlowArrow) -> (u8, u8, u8) {
        if arrow.selected {
            self.color_selected
        } else if arrow.active {
            self.color_active
        } else {
            self.color_non_active
        }
    }
}

// ============================================================================
// FlowArrowPanelState -- panel interaction model
// ============================================================================

/// State and interaction model for the flow arrow panel.
///
/// Ported from `FlowArrowPanel.java`. Manages:
/// - Mouse click handling (single click = toggle select, double click = navigate)
/// - Cursor style changes (default vs hand cursor)
/// - Tooltip text generation
/// - Layered paint ordering (inactive -> active -> selected)
/// - Animated scroll navigation to arrow endpoints
#[derive(Debug)]
pub struct FlowArrowPanelState {
    /// Panel width in pixels.
    pub width: u32,
    /// Panel height in pixels.
    pub height: u32,
    /// Current cursor style.
    cursor_style: CursorStyle,
    /// Configuration for display options.
    pub config: FlowArrowConfig,
    /// Pending single click point (debounced).
    pending_click: Option<Point>,
    /// Click debounce delay in milliseconds.
    pub click_debounce_ms: u32,
}

/// Cursor style for the flow arrow panel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CursorStyle {
    /// Default arrow cursor.
    Default,
    /// Hand cursor (when hovering over an arrow).
    Hand,
}

/// The result of processing a mouse event.
#[derive(Debug, Clone, PartialEq)]
pub enum MouseEventResult {
    /// No action taken.
    None,
    /// An arrow was selected or deselected.
    ArrowToggled {
        /// The address of the toggled arrow's start.
        start: Address,
        /// The address of the toggled arrow's end.
        end: Address,
        /// Whether the arrow is now selected.
        selected: bool,
    },
    /// Navigation to an arrow endpoint was triggered.
    NavigateTo {
        /// The target address to navigate to.
        target: Address,
        /// The source address (for animation start).
        source: Address,
        /// Whether the target is on screen.
        on_screen: bool,
    },
    /// Cursor style changed.
    CursorChanged(CursorStyle),
}

impl FlowArrowPanelState {
    /// Create a new panel state.
    pub fn new(width: u32, height: u32) -> Self {
        Self {
            width,
            height,
            cursor_style: CursorStyle::Default,
            config: FlowArrowConfig::default(),
            pending_click: None,
            click_debounce_ms: 350,
        }
    }

    /// Get the current cursor style.
    pub fn cursor_style(&self) -> CursorStyle {
        self.cursor_style
    }

    /// Process a mouse move event.
    ///
    /// Ported from `FlowArrowPanel.FlowArrowCursorMouseListener.mouseMoved()`.
    /// Updates the cursor to a hand cursor when hovering over an arrow.
    pub fn on_mouse_move(
        &mut self,
        point: Point,
        arrows: &[FlowArrow],
        shapes: &[FlowArrowShape],
    ) -> MouseEventResult {
        let hovering = Self::find_arrow_at_point(point, arrows, shapes);
        let new_style = if hovering.is_some() {
            CursorStyle::Hand
        } else {
            CursorStyle::Default
        };

        if new_style != self.cursor_style {
            self.cursor_style = new_style;
            return MouseEventResult::CursorChanged(new_style);
        }

        MouseEventResult::None
    }

    /// Process a mouse click event.
    ///
    /// Ported from `FlowArrowPanel.processSingleClick()`.
    /// Toggles the selection state of the clicked arrow.
    pub fn on_single_click(
        &mut self,
        point: Point,
        arrows: &[FlowArrow],
        shapes: &[FlowArrowShape],
    ) -> MouseEventResult {
        if let Some(arrow) = Self::find_arrow_at_point(point, arrows, shapes) {
            return MouseEventResult::ArrowToggled {
                start: arrow.start,
                end: arrow.end,
                selected: !arrow.selected,
            };
        }
        MouseEventResult::None
    }

    /// Process a double-click event.
    ///
    /// Ported from `FlowArrowPanel.processDoubleClick()` and
    /// `navigateArrow()`. Triggers navigation to the arrow's endpoint.
    pub fn on_double_click(
        &mut self,
        point: Point,
        current_addr: Option<Address>,
        arrows: &[FlowArrow],
        shapes: &[FlowArrowShape],
        is_on_screen: impl Fn(Address) -> bool,
    ) -> MouseEventResult {
        if let Some(arrow) = Self::find_arrow_at_point(point, arrows, shapes) {
            let mut target = arrow.end;
            if Some(target) == current_addr {
                // Navigate back to start if we're already at the end
                target = arrow.start;
            }

            let on_screen = is_on_screen(target);
            return MouseEventResult::NavigateTo {
                target,
                source: arrow.start,
                on_screen,
            };
        }
        MouseEventResult::None
    }

    /// Process a mouse exit event.
    ///
    /// Ported from `FlowArrowPanel.FlowArrowCursorMouseListener.mouseExited()`.
    pub fn on_mouse_exit(&mut self) -> MouseEventResult {
        if self.cursor_style != CursorStyle::Default {
            self.cursor_style = CursorStyle::Default;
            return MouseEventResult::CursorChanged(CursorStyle::Default);
        }
        MouseEventResult::None
    }

    /// Generate tooltip text for a point.
    ///
    /// Ported from `FlowArrowPanel.getToolTipText(MouseEvent)`.
    pub fn get_tooltip_text(
        &self,
        point: Point,
        arrows: &[FlowArrow],
        shapes: &[FlowArrowShape],
    ) -> Option<String> {
        let arrow = Self::find_arrow_at_point(point, arrows, shapes)?;
        Some(arrow.get_display_string())
    }

    /// Compute the layered paint order.
    ///
    /// Ported from `FlowArrowPanel.paintComponent(Graphics)`.
    /// Returns arrows grouped by paint layer:
    /// 1. Inactive arrows (painted first, at the back)
    /// 2. Active arrows (painted on top of inactive)
    /// 3. Selected arrows (painted on top of everything)
    pub fn compute_paint_layers<'a>(
        &self,
        arrows: &'a [FlowArrow],
    ) -> PaintLayers<'a> {
        let mut inactive = Vec::new();
        let mut active = Vec::new();
        let mut selected = Vec::new();

        for arrow in arrows {
            if arrow.selected {
                selected.push(arrow);
            } else if arrow.active {
                active.push(arrow);
            } else {
                inactive.push(arrow);
            }
        }

        PaintLayers { inactive, active, selected }
    }

    /// Find an arrow at the given screen point.
    ///
    /// Ported from `FlowArrowPanel.getArrow(Point)`. Checks all arrows
    /// in order: regular, then selected, then active.
    fn find_arrow_at_point<'a>(
        point: Point,
        arrows: &'a [FlowArrow],
        shapes: &[FlowArrowShape],
    ) -> Option<&'a FlowArrow> {
        for (arrow, shape) in arrows.iter().zip(shapes.iter()) {
            if shape.intersects(point, 5.0) {
                return Some(arrow);
            }
        }
        None
    }
}

/// Arrows grouped by paint layer.
///
/// Used by [`FlowArrowPanelState::compute_paint_layers`] to determine
/// the rendering order: inactive first, then active, then selected.
#[derive(Debug)]
pub struct PaintLayers<'a> {
    /// Inactive arrows (painted first, at the back).
    pub inactive: Vec<&'a FlowArrow>,
    /// Active arrows (painted on top of inactive).
    pub active: Vec<&'a FlowArrow>,
    /// Selected arrows (painted on top of everything).
    pub selected: Vec<&'a FlowArrow>,
}

// ============================================================================
// ScrollingCallback -- animated navigation model
// ============================================================================

/// Callback for animated scrolling between addresses.
///
/// Ported from `FlowArrowPanel.ScrollingCallback`. Models the
/// animation progress from a start address to an end address.
#[derive(Debug)]
pub struct ScrollingCallback {
    /// The start address of the scroll.
    pub start: Address,
    /// The end address of the scroll.
    pub end: Address,
    /// Current progress (0.0 to 1.0).
    progress: f64,
    /// Whether the animation is complete.
    done: bool,
    /// Whether the scroll direction is backward (start > end).
    pub is_backward: bool,
}

impl ScrollingCallback {
    /// Create a new scrolling callback.
    ///
    /// Ported from `ScrollingCallback(Address start, Address end)`.
    pub fn new(start: Address, end: Address) -> Self {
        Self {
            start,
            end,
            progress: 0.0,
            done: false,
            is_backward: start > end,
        }
    }

    /// Get the address at the current progress.
    ///
    /// Ported from `ScrollingCallback.progress(double)`.
    pub fn current_address(&self) -> Address {
        let length = if self.is_backward {
            self.start.offset - self.end.offset
        } else {
            self.end.offset - self.start.offset
        };

        let offset = (length as f64 * self.progress).round() as u64;

        if self.is_backward {
            self.start.sub(offset)
        } else {
            self.start.add(offset)
        }
    }

    /// Advance the animation by a step.
    ///
    /// Returns the current address, or `None` if the animation is done.
    pub fn advance(&mut self, step: f64) -> Option<Address> {
        if self.done {
            return None;
        }

        self.progress = (self.progress + step).min(1.0);

        if self.progress >= 1.0 {
            self.done = true;
            return Some(self.end);
        }

        Some(self.current_address())
    }

    /// Mark the animation as done and return the final address.
    ///
    /// Ported from `ScrollingCallback.done()`.
    pub fn finish(&mut self) -> Address {
        self.done = true;
        self.progress = 1.0;
        self.end
    }

    /// Whether the animation is complete.
    pub fn is_done(&self) -> bool {
        self.done
    }

    /// Get the current progress (0.0 to 1.0).
    pub fn progress(&self) -> f64 {
        self.progress
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::{FlowArrowShapeFactory, FlowArrowPanel, FlowArrowLayout};

    fn make_test_arrows() -> (Vec<FlowArrow>, Vec<FlowArrowShape>) {
        let mut arrows = vec![
            FlowArrow::new(Address::new(0x1000), Address::new(0x2000), FlowArrowType::JumpForward),
            FlowArrow::new(Address::new(0x1000), Address::new(0x3000), FlowArrowType::ConditionalForward),
            FlowArrow::new(Address::new(0x1000), Address::new(0x1004), FlowArrowType::FallThrough),
        ];

        // Assign columns so arrows have valid geometry
        FlowArrowLayout::assign_columns(&mut arrows);

        let mut addr_to_y = BTreeMap::new();
        addr_to_y.insert(0x1000, 50.0);
        addr_to_y.insert(0x1004, 60.0);
        addr_to_y.insert(0x2000, 150.0);
        addr_to_y.insert(0x3000, 200.0);

        let panel = FlowArrowPanel::new(200, 300);
        let shapes = panel.compute_shapes(&arrows, &addr_to_y);

        (arrows, shapes)
    }

    // ----------------------------------------------------------------
    // FlowArrowConfig tests
    // ----------------------------------------------------------------

    #[test]
    fn test_config_default() {
        let config = FlowArrowConfig::default();
        assert!(!config.show_fall_through);
        assert!(config.show_conditional_jump);
        assert!(config.show_unconditional_jump);
        assert!(!config.show_call);
    }

    #[test]
    fn test_config_should_show() {
        let config = FlowArrowConfig::default();

        let jump = FlowArrow::new(Address::new(0x1000), Address::new(0x2000), FlowArrowType::JumpForward);
        assert!(config.should_show(&jump));

        let cond = FlowArrow::new(Address::new(0x1000), Address::new(0x2000), FlowArrowType::ConditionalForward);
        assert!(config.should_show(&cond));

        let fall = FlowArrow::new(Address::new(0x1000), Address::new(0x2000), FlowArrowType::FallThrough);
        assert!(!config.should_show(&fall));

        let call = FlowArrow::new(Address::new(0x1000), Address::new(0x2000), FlowArrowType::Call);
        assert!(!config.should_show(&call));
    }

    #[test]
    fn test_config_get_color() {
        let config = FlowArrowConfig::default();

        let normal = FlowArrow::new(Address::new(0x1000), Address::new(0x2000), FlowArrowType::JumpForward);
        assert_eq!(config.get_color(&normal), (128, 128, 128));

        let mut active = normal.clone();
        active.active = true;
        assert_eq!(config.get_color(&active), (0, 128, 255));

        let mut selected = normal.clone();
        selected.selected = true;
        assert_eq!(config.get_color(&selected), (255, 128, 0));
    }

    // ----------------------------------------------------------------
    // FlowArrowPanelState tests
    // ----------------------------------------------------------------

    #[test]
    fn test_panel_state_new() {
        let state = FlowArrowPanelState::new(200, 300);
        assert_eq!(state.width, 200);
        assert_eq!(state.height, 300);
        assert_eq!(state.cursor_style(), CursorStyle::Default);
    }

    #[test]
    fn test_panel_mouse_move_on_arrow() {
        let (arrows, shapes) = make_test_arrows();
        let mut state = FlowArrowPanelState::new(200, 300);

        // The first arrow body goes from (200, 50) -> (188, 50) horizontally
        // So (194, 50) should be on the arrow
        let result = state.on_mouse_move(Point::new(194.0, 50.0), &arrows, &shapes);
        assert_eq!(result, MouseEventResult::CursorChanged(CursorStyle::Hand));
        assert_eq!(state.cursor_style(), CursorStyle::Hand);
    }

    #[test]
    fn test_panel_mouse_move_off_arrow() {
        let (arrows, shapes) = make_test_arrows();
        let mut state = FlowArrowPanelState::new(200, 300);

        // First move onto arrow
        state.on_mouse_move(Point::new(194.0, 50.0), &arrows, &shapes);
        assert_eq!(state.cursor_style(), CursorStyle::Hand);

        // Then move off
        let result = state.on_mouse_move(Point::new(10.0, 10.0), &arrows, &shapes);
        assert_eq!(result, MouseEventResult::CursorChanged(CursorStyle::Default));
        assert_eq!(state.cursor_style(), CursorStyle::Default);
    }

    #[test]
    fn test_panel_single_click_toggle() {
        let (arrows, shapes) = make_test_arrows();
        let mut state = FlowArrowPanelState::new(200, 300);

        let result = state.on_single_click(Point::new(194.0, 50.0), &arrows, &shapes);
        match result {
            MouseEventResult::ArrowToggled { start, end, selected } => {
                assert_eq!(start, Address::new(0x1000));
                assert_eq!(end, Address::new(0x2000));
                assert!(selected); // toggled to selected
            }
            _ => panic!("Expected ArrowToggled"),
        }
    }

    #[test]
    fn test_panel_single_click_empty() {
        let (arrows, shapes) = make_test_arrows();
        let mut state = FlowArrowPanelState::new(200, 300);

        let result = state.on_single_click(Point::new(10.0, 10.0), &arrows, &shapes);
        assert_eq!(result, MouseEventResult::None);
    }

    #[test]
    fn test_panel_double_click_navigate() {
        let (arrows, shapes) = make_test_arrows();
        let mut state = FlowArrowPanelState::new(200, 300);

        let result = state.on_double_click(
            Point::new(194.0, 50.0),
            Some(Address::new(0x1000)),
            &arrows,
            &shapes,
            |addr| addr.offset >= 0x1000 && addr.offset <= 0x5000,
        );

        match result {
            MouseEventResult::NavigateTo { target, on_screen, .. } => {
                assert_eq!(target, Address::new(0x2000));
                assert!(on_screen);
            }
            _ => panic!("Expected NavigateTo"),
        }
    }

    #[test]
    fn test_panel_double_click_reverse() {
        let (arrows, shapes) = make_test_arrows();
        let mut state = FlowArrowPanelState::new(200, 300);

        // If current address is the end, navigate back to start
        let result = state.on_double_click(
            Point::new(194.0, 50.0),
            Some(Address::new(0x2000)), // at the end
            &arrows,
            &shapes,
            |addr| true,
        );

        match result {
            MouseEventResult::NavigateTo { target, .. } => {
                assert_eq!(target, Address::new(0x1000)); // back to start
            }
            _ => panic!("Expected NavigateTo"),
        }
    }

    #[test]
    fn test_panel_mouse_exit() {
        let (arrows, shapes) = make_test_arrows();
        let mut state = FlowArrowPanelState::new(200, 300);

        // Move onto arrow first
        state.on_mouse_move(Point::new(194.0, 50.0), &arrows, &shapes);
        assert_eq!(state.cursor_style(), CursorStyle::Hand);

        // Exit
        let result = state.on_mouse_exit();
        assert_eq!(result, MouseEventResult::CursorChanged(CursorStyle::Default));
        assert_eq!(state.cursor_style(), CursorStyle::Default);
    }

    #[test]
    fn test_panel_mouse_exit_already_default() {
        let mut state = FlowArrowPanelState::new(200, 300);
        let result = state.on_mouse_exit();
        assert_eq!(result, MouseEventResult::None);
    }

    #[test]
    fn test_panel_tooltip() {
        let (arrows, shapes) = make_test_arrows();
        let state = FlowArrowPanelState::new(200, 300);

        let tooltip = state.get_tooltip_text(Point::new(194.0, 50.0), &arrows, &shapes);
        assert!(tooltip.is_some());
        let text = tooltip.unwrap();
        assert!(text.contains("0x1000"));
        assert!(text.contains("0x2000"));
    }

    #[test]
    fn test_panel_tooltip_empty() {
        let (arrows, shapes) = make_test_arrows();
        let state = FlowArrowPanelState::new(200, 300);

        let tooltip = state.get_tooltip_text(Point::new(10.0, 10.0), &arrows, &shapes);
        assert!(tooltip.is_none());
    }

    #[test]
    fn test_panel_paint_layers() {
        let mut arrows = vec![
            FlowArrow::new(Address::new(0x1000), Address::new(0x2000), FlowArrowType::JumpForward),
            FlowArrow::new(Address::new(0x3000), Address::new(0x4000), FlowArrowType::ConditionalForward),
            FlowArrow::new(Address::new(0x5000), Address::new(0x6000), FlowArrowType::FallThrough),
        ];
        arrows[0].active = true;
        arrows[1].selected = true;

        let state = FlowArrowPanelState::new(200, 300);
        let layers = state.compute_paint_layers(&arrows);

        assert_eq!(layers.inactive.len(), 1); // fallthrough
        assert_eq!(layers.active.len(), 1); // jump
        assert_eq!(layers.selected.len(), 1); // conditional
    }

    // ----------------------------------------------------------------
    // ScrollingCallback tests
    // ----------------------------------------------------------------

    #[test]
    fn test_scrolling_callback_forward() {
        let mut cb = ScrollingCallback::new(Address::new(0x1000), Address::new(0x2000));
        assert!(!cb.is_backward);
        assert!(!cb.is_done());
        assert_eq!(cb.progress(), 0.0);

        // At 50% progress, should be at 0x1800
        let addr = cb.advance(0.5);
        assert!(addr.is_some());
        assert_eq!(addr.unwrap(), Address::new(0x1800));
        assert_eq!(cb.progress(), 0.5);
    }

    #[test]
    fn test_scrolling_callback_backward() {
        let mut cb = ScrollingCallback::new(Address::new(0x2000), Address::new(0x1000));
        assert!(cb.is_backward);

        // At 50% progress, should be at 0x1800
        let addr = cb.advance(0.5);
        assert!(addr.is_some());
        assert_eq!(addr.unwrap(), Address::new(0x1800));
    }

    #[test]
    fn test_scrolling_callback_finish() {
        let mut cb = ScrollingCallback::new(Address::new(0x1000), Address::new(0x2000));
        let addr = cb.advance(1.0);
        assert_eq!(addr, Some(Address::new(0x2000)));
        assert!(cb.is_done());

        // Further advances should return None
        assert!(cb.advance(0.1).is_none());
    }

    #[test]
    fn test_scrolling_callback_finish_method() {
        let mut cb = ScrollingCallback::new(Address::new(0x1000), Address::new(0x2000));
        let addr = cb.finish();
        assert_eq!(addr, Address::new(0x2000));
        assert!(cb.is_done());
    }

    #[test]
    fn test_scrolling_callback_current_address() {
        let cb = ScrollingCallback::new(Address::new(0x1000), Address::new(0x2000));
        assert_eq!(cb.current_address(), Address::new(0x1000)); // 0% = start
    }

    #[test]
    fn test_scrolling_callback_progress_clamped() {
        let mut cb = ScrollingCallback::new(Address::new(0x1000), Address::new(0x2000));
        cb.advance(2.0); // overshoot
        assert_eq!(cb.progress(), 1.0);
        assert!(cb.is_done());
    }

    // ----------------------------------------------------------------
    // PaintLayers tests
    // ----------------------------------------------------------------

    #[test]
    fn test_paint_layers_empty() {
        let arrows: Vec<FlowArrow> = vec![];
        let state = FlowArrowPanelState::new(200, 300);
        let layers = state.compute_paint_layers(&arrows);
        assert!(layers.inactive.is_empty());
        assert!(layers.active.is_empty());
        assert!(layers.selected.is_empty());
    }

    #[test]
    fn test_paint_layers_all_inactive() {
        let arrows = vec![
            FlowArrow::new(Address::new(0x1000), Address::new(0x2000), FlowArrowType::JumpForward),
        ];
        let state = FlowArrowPanelState::new(200, 300);
        let layers = state.compute_paint_layers(&arrows);
        assert_eq!(layers.inactive.len(), 1);
        assert!(layers.active.is_empty());
        assert!(layers.selected.is_empty());
    }

    // ----------------------------------------------------------------
    // Integration tests
    // ----------------------------------------------------------------

    #[test]
    fn test_full_panel_interaction() {
        let (arrows, shapes) = make_test_arrows();
        let mut state = FlowArrowPanelState::new(200, 300);

        // 1. Move mouse onto arrow -> hand cursor
        let r = state.on_mouse_move(Point::new(194.0, 50.0), &arrows, &shapes);
        assert_eq!(r, MouseEventResult::CursorChanged(CursorStyle::Hand));

        // 2. Get tooltip
        let tip = state.get_tooltip_text(Point::new(194.0, 50.0), &arrows, &shapes);
        assert!(tip.is_some());

        // 3. Single click -> toggle selection
        let r = state.on_single_click(Point::new(194.0, 50.0), &arrows, &shapes);
        assert!(matches!(r, MouseEventResult::ArrowToggled { selected: true, .. }));

        // 4. Double click -> navigate
        let r = state.on_double_click(
            Point::new(194.0, 50.0),
            Some(Address::new(0x1000)),
            &arrows,
            &shapes,
            |_| true,
        );
        assert!(matches!(r, MouseEventResult::NavigateTo { .. }));

        // 5. Mouse exit -> default cursor
        let r = state.on_mouse_exit();
        assert_eq!(r, MouseEventResult::CursorChanged(CursorStyle::Default));
    }

    #[test]
    fn test_config_filter_and_paint() {
        let config = FlowArrowConfig {
            show_fall_through: false,
            show_conditional_jump: true,
            show_unconditional_jump: true,
            show_call: false,
            ..Default::default()
        };

        let arrows = vec![
            FlowArrow::new(Address::new(0x1000), Address::new(0x2000), FlowArrowType::JumpForward),
            FlowArrow::new(Address::new(0x1000), Address::new(0x3000), FlowArrowType::ConditionalForward),
            FlowArrow::new(Address::new(0x1000), Address::new(0x1004), FlowArrowType::FallThrough),
            FlowArrow::new(Address::new(0x4000), Address::new(0x5000), FlowArrowType::Call),
        ];

        let visible: Vec<_> = arrows.iter().filter(|a| config.should_show(a)).collect();
        assert_eq!(visible.len(), 2); // jump + conditional
    }
}
