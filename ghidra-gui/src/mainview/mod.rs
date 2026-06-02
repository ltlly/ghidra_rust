//! Main view components for the Ghidra GUI.
//!
//! Contains the menu bar, toolbar, and status bar rendering logic.

pub mod graph;
pub mod menu;

use egui::{Align, Color32, Layout, RichText, Ui};

/// Toolbar state.
pub struct ToolbarState {
    /// The current text in the address bar.
    pub address_text: String,
    /// The current text in the search box.
    pub search_text: String,
    /// Whether the search box has focus.
    pub search_focused: bool,
    /// Whether to show search results.
    pub show_search_results: bool,
}

impl ToolbarState {
    pub fn new() -> Self {
        Self {
            address_text: String::new(),
            search_text: String::new(),
            search_focused: false,
            show_search_results: false,
        }
    }
}

impl Default for ToolbarState {
    fn default() -> Self {
        Self::new()
    }
}

/// Render the toolbar with navigation buttons and address bar.
pub fn render_toolbar(
    toolbar: &mut ToolbarState,
    can_go_back: bool,
    can_go_forward: bool,
    current_address: &str,
    ui: &mut Ui,
) -> ToolbarAction {
    let mut action = ToolbarAction::None;

    ui.horizontal(|ui| {
        // Navigation buttons
        if ui
            .add_enabled(can_go_back, egui::Button::new("\u{25C0} Back"))
            .clicked()
        {
            action = ToolbarAction::GoBack;
        }
        if ui
            .add_enabled(can_go_forward, egui::Button::new("Forward \u{25B6}"))
            .clicked()
        {
            action = ToolbarAction::GoForward;
        }
        if ui.button("\u{2302} Home").clicked() {
            action = ToolbarAction::GoHome;
        }

        ui.separator();

        // Address label and bar
        ui.label("Addr:");
        let addr_response = ui.text_edit_singleline(&mut toolbar.address_text);
        if addr_response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
            action = ToolbarAction::GoTo(toolbar.address_text.clone());
        }

        ui.separator();

        // Search box
        ui.label("Search:");
        let search_response = ui.text_edit_singleline(&mut toolbar.search_text);
        if search_response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
            if !toolbar.search_text.is_empty() {
                action = ToolbarAction::Search(toolbar.search_text.clone());
            }
        }

        if toolbar.search_focused {
            search_response.request_focus();
            toolbar.search_focused = false;
        }

        // Search navigation
        if ui.button("Next").clicked() {
            action = ToolbarAction::SearchNext;
        }
        if ui.button("Prev").clicked() {
            action = ToolbarAction::SearchPrev;
        }
    });

    action
}

/// Render the status bar at the bottom of the window.
pub fn render_status_bar(status_message: &str, ui: &mut Ui) {
    ui.horizontal(|ui| {
        ui.label(
            RichText::new(status_message)
                .color(Color32::from_rgb(180, 180, 180))
                .font_size(11.0),
        );
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            ui.label(
                RichText::new("Ghidra Rust")
                    .color(Color32::from_rgb(140, 140, 140))
                    .font_size(11.0),
            );
        });
    });
}

/// Actions triggered from the toolbar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolbarAction {
    None,
    GoBack,
    GoForward,
    GoHome,
    GoTo(String),
    Search(String),
    SearchNext,
    SearchPrev,
}
