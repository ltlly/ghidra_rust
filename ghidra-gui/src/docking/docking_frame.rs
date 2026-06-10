//! Main application window frame for the docking framework.
//!
//! Port of Ghidra's `DockingFrame`.  Manages the top-level window that
//! contains the docking layout, menu bar, tool bars, status bar, and all
//! dockable components.  In the egui-based architecture the frame wraps
//! an [`eframe::App`] implementation that drives the UI loop.

use super::action::GuiActionManager;
use super::component::ComponentProvider;
use super::layout::DockingLayout;
use super::menu::MenuModel;
use super::statusbar::StatusBar;
use super::tool::{DockingTool, ToolEvent, ToolEventCallback};
use super::window_manager::DockingWindowManager;

// ---------------------------------------------------------------------------
// FrameConfig — configuration for the docking frame
// ---------------------------------------------------------------------------

/// Configuration options for a [`DockingFrame`].
#[derive(Debug, Clone)]
pub struct FrameConfig {
    /// Window title.
    pub title: String,
    /// Initial window width in logical pixels.
    pub width: f32,
    /// Initial window height in logical pixels.
    pub height: f32,
    /// Whether the window is resizable.
    pub resizable: bool,
    /// Whether to show the menu bar.
    pub show_menu_bar: bool,
    /// Whether to show the status bar.
    pub show_status_bar: bool,
    /// Whether to show tool bars.
    pub show_toolbars: bool,
    /// Minimum window width.
    pub min_width: Option<f32>,
    /// Minimum window height.
    pub min_height: Option<f32>,
}

impl Default for FrameConfig {
    fn default() -> Self {
        Self {
            title: "Ghidra".to_string(),
            width: 1280.0,
            height: 800.0,
            resizable: true,
            show_menu_bar: true,
            show_status_bar: true,
            show_toolbars: true,
            min_width: Some(640.0),
            min_height: Some(480.0),
        }
    }
}

// ---------------------------------------------------------------------------
// FrameState — the mutable state of the docking frame
// ---------------------------------------------------------------------------

/// Runtime state of the docking frame.
#[derive(Debug)]
pub struct FrameState {
    /// Whether the frame is currently active (has focus).
    pub active: bool,
    /// Current window position (x, y).
    pub position: Option<(f32, f32)>,
    /// Current window size (width, height).
    pub size: (f32, f32),
    /// Whether the window is maximized.
    pub maximized: bool,
    /// Whether the window is minimized (iconified).
    pub minimized: bool,
}

impl Default for FrameState {
    fn default() -> Self {
        Self {
            active: false,
            position: None,
            size: (1280.0, 800.0),
            maximized: false,
            minimized: false,
        }
    }
}

// ---------------------------------------------------------------------------
// DockingFrame — the main application window
// ---------------------------------------------------------------------------

/// The main application window frame for the docking framework.
///
/// In Ghidra's Java implementation `DockingFrame` extends `JFrame` and owns
/// the root pane.  In the egui port it holds the layout, window manager,
/// action manager, status bar, and menu model, and provides the top-level
/// rendering and event dispatch logic.
///
/// # Lifecycle
///
/// 1. Create with [`DockingFrame::new`].
/// 2. Optionally configure via [`DockingFrame::with_config`].
/// 3. Attach to a [`DockingTool`] via [`DockingFrame::set_tool`].
/// 4. Call [`DockingFrame::update`] once per frame from the egui render loop.
pub struct DockingFrame {
    /// Configuration.
    config: FrameConfig,
    /// Runtime state.
    state: FrameState,
    /// The docking layout.
    layout: DockingLayout,
    /// The window manager.
    window_manager: DockingWindowManager,
    /// The action manager.
    action_manager: GuiActionManager,
    /// The status bar.
    status_bar: StatusBar,
    /// The top-level menu models (one per top-level menu).
    menus: Vec<MenuModel>,
    /// Registered tool event callbacks.
    event_callbacks: Vec<ToolEventCallback>,
    /// Whether the frame has been initialized.
    initialized: bool,
}

impl std::fmt::Debug for DockingFrame {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DockingFrame")
            .field("config", &self.config)
            .field("state", &self.state)
            .field("layout", &self.layout)
            .field("window_manager", &self.window_manager)
            .field("action_manager", &self.action_manager)
            .field("status_bar", &self.status_bar)
            .field("menus", &self.menus)
            .field("event_callbacks", &self.event_callbacks.len())
            .field("initialized", &self.initialized)
            .finish()
    }
}

impl DockingFrame {
    /// Create a new docking frame with default configuration.
    pub fn new() -> Self {
        Self {
            config: FrameConfig::default(),
            state: FrameState::default(),
            layout: DockingLayout::default_layout(),
            window_manager: DockingWindowManager::new(DockingLayout::default_layout()),
            action_manager: GuiActionManager::new(),
            status_bar: StatusBar::new(),
            menus: Vec::new(),
            event_callbacks: Vec::new(),
            initialized: false,
        }
    }

    /// Create a new docking frame with the given configuration.
    pub fn with_config(config: FrameConfig) -> Self {
        let size = (config.width, config.height);
        Self {
            state: FrameState {
                size,
                ..FrameState::default()
            },
            config,
            ..Self::new()
        }
    }

    // -- Configuration -------------------------------------------------------

    /// Returns the current frame configuration.
    pub fn config(&self) -> &FrameConfig {
        &self.config
    }

    /// Update the frame configuration.
    pub fn set_config(&mut self, config: FrameConfig) {
        self.config = config;
    }

    /// Set the window title.
    pub fn set_title(&mut self, title: impl Into<String>) {
        self.config.title = title.into();
    }

    /// Returns the current window title.
    pub fn title(&self) -> &str {
        &self.config.title
    }

    // -- State ---------------------------------------------------------------

    /// Returns the current frame state.
    pub fn state(&self) -> &FrameState {
        &self.state
    }

    /// Returns whether the frame is active (focused).
    pub fn is_active(&self) -> bool {
        self.state.active
    }

    /// Set the active state.
    pub fn set_active(&mut self, active: bool) {
        self.state.active = active;
    }

    /// Returns the current window size.
    pub fn size(&self) -> (f32, f32) {
        self.state.size
    }

    /// Set the window size.
    pub fn set_size(&mut self, width: f32, height: f32) {
        self.state.size = (width, height);
    }

    // -- Layout --------------------------------------------------------------

    /// Returns a reference to the docking layout.
    pub fn layout(&self) -> &DockingLayout {
        &self.layout
    }

    /// Returns a mutable reference to the docking layout.
    pub fn layout_mut(&mut self) -> &mut DockingLayout {
        &mut self.layout
    }

    /// Replace the entire layout.
    pub fn set_layout(&mut self, layout: DockingLayout) {
        self.layout = layout;
        self.fire_event(ToolEvent::LayoutChanged);
    }

    /// Load a layout from a JSON string.
    pub fn load_layout(&mut self, json: &str) -> Result<(), serde_json::Error> {
        self.layout = serde_json::from_str(json)?;
        self.fire_event(ToolEvent::LayoutLoaded);
        Ok(())
    }

    /// Serialize the current layout to a JSON string.
    pub fn save_layout(&self) -> String {
        serde_json::to_string(&self.layout).unwrap_or_default()
    }

    // -- Window Manager ------------------------------------------------------

    /// Returns a reference to the window manager.
    pub fn window_manager(&self) -> &DockingWindowManager {
        &self.window_manager
    }

    /// Returns a mutable reference to the window manager.
    pub fn window_manager_mut(&mut self) -> &mut DockingWindowManager {
        &mut self.window_manager
    }

    // -- Action Manager ------------------------------------------------------

    /// Returns a reference to the action manager.
    pub fn action_manager(&self) -> &GuiActionManager {
        &self.action_manager
    }

    /// Returns a mutable reference to the action manager.
    pub fn action_manager_mut(&mut self) -> &mut GuiActionManager {
        &mut self.action_manager
    }

    // -- Status Bar ----------------------------------------------------------

    /// Returns a reference to the status bar.
    pub fn status_bar(&self) -> &StatusBar {
        &self.status_bar
    }

    /// Returns a mutable reference to the status bar.
    pub fn status_bar_mut(&mut self) -> &mut StatusBar {
        &mut self.status_bar
    }

    // -- Menu Model ----------------------------------------------------------

    /// Returns a reference to the top-level menu models.
    pub fn menus(&self) -> &[MenuModel] {
        &self.menus
    }

    /// Returns a mutable reference to the top-level menu models.
    pub fn menus_mut(&mut self) -> &mut Vec<MenuModel> {
        &mut self.menus
    }

    /// Add a top-level menu.
    pub fn add_menu(&mut self, menu: MenuModel) {
        self.menus.push(menu);
    }

    // -- Tool Integration ----------------------------------------------------

    /// Attach a docking tool to this frame.
    ///
    /// Copies the tool's layout, actions, and window manager into the frame
    /// so the frame can render them.
    pub fn set_tool(&mut self, tool: &DockingTool) {
        self.layout = tool.layout.clone();
        // Additional integration would be wired here in a full implementation.
    }

    // -- Event System --------------------------------------------------------

    /// Register a callback to receive tool events.
    pub fn add_event_callback(&mut self, callback: ToolEventCallback) {
        self.event_callbacks.push(callback);
    }

    /// Fire a tool event to all registered callbacks.
    fn fire_event(&self, event: ToolEvent) {
        for cb in &self.event_callbacks {
            cb(&event);
        }
    }

    // -- Component Management ------------------------------------------------

    /// Add a component provider to the frame.
    pub fn add_component(&mut self, provider: ComponentProvider) {
        self.fire_event(ToolEvent::ComponentAdded {
            provider,
            name: provider.display_name().to_string(),
        });
    }

    /// Remove a component provider from the frame.
    pub fn remove_component(&mut self, provider: ComponentProvider) {
        self.fire_event(ToolEvent::ComponentRemoved {
            provider,
            name: provider.display_name().to_string(),
        });
    }

    // -- Rendering -----------------------------------------------------------

    /// Update the frame for the current egui frame.
    ///
    /// This is the main entry point called once per frame from the egui
    /// render loop.  It renders the menu bar, toolbars, docking layout,
    /// and status bar.
    pub fn update(&mut self, ctx: &egui::Context) {
        if !self.initialized {
            self.initialize();
        }

        // Render the menu bar.
        if self.config.show_menu_bar {
            egui::TopBottomPanel::top("docking_frame_menu_bar").show(ctx, |ui| {
                self.render_menu_bar(ui);
            });
        }

        // Render the status bar.
        if self.config.show_status_bar {
            egui::TopBottomPanel::bottom("docking_frame_status_bar").show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label(self.status_bar.status_text());
                });
            });
        }

        // Render the central docking area.
        egui::CentralPanel::default().show(ctx, |ui| {
            self.render_docking_area(ui);
        });
    }

    /// One-time initialization when the frame is first shown.
    fn initialize(&mut self) {
        self.initialized = true;
    }

    /// Render the menu bar.
    fn render_menu_bar(&self, ui: &mut egui::Ui) {
        egui::menu::bar(ui, |ui| {
            for menu in &self.menus {
                ui.menu_button(&menu.title, |ui| {
                    for item in &menu.items {
                        if item.is_separator() {
                            ui.separator();
                        } else if ui.button(&item.text).clicked() {
                            // Item click handling would go here.
                        }
                    }
                });
            }
        });
    }

    /// Render the docking area.
    fn render_docking_area(&self, ui: &mut egui::Ui) {
        // The docking area renders the layout's split tree.
        // In a full implementation this would walk the SplitNode tree
        // and render each component in its dock area.
        let _ = ui;
    }
}

impl Default for DockingFrame {
    fn default() -> Self {
        Self::new()
    }
}
