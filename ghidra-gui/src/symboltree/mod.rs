//! Symbol tree panel for the Ghidra GUI.
//!
//! Provides a tree view of program symbols organized by category
//! (Functions, Labels, Classes, Namespaces, Exports, Imports) with
//! search/filter, click-to-navigate, multi-select, drag-and-drop, and
//! right-click context menu support.

use ghidra_core::addr::Address;
use ghidra_core::symbol::{Symbol, SymbolPath, SymbolTreeNode, SymbolType};
use std::collections::HashSet;

// ============================================================================
// Constants
// ============================================================================

/// Height of a single tree row in pixels.
const ROW_HEIGHT: f32 = 20.0;

/// Indentation per nesting level in pixels.
const INDENT_WIDTH: f32 = 16.0;

/// Width of the expand/collapse triangle area.
const TRIANGLE_WIDTH: f32 = 16.0;

/// Icon width for symbol type indicators.
const _ICON_WIDTH: f32 = 24.0;

/// Padding around tree rows.
const _ROW_PAD: f32 = 2.0;

// ============================================================================
// Drag-and-drop payload types
// ============================================================================

/// Payload for drag-and-drop operations in the symbol tree.
#[derive(Debug, Clone)]
pub enum SymbolTreeDragPayload {
    /// A leaf symbol is being dragged.
    Symbol(Symbol),
    /// A category/group node is being dragged.
    Group(SymbolPath),
}

// ============================================================================
// Symbol Tree Panel
// ============================================================================

/// The symbol tree panel state.
pub struct SymbolTreePanel {
    /// The root of the symbol tree.
    pub tree: SymbolTreeNode,

    /// Filter text for searching symbols (real-time).
    pub filter: String,

    /// Set of expanded paths in the tree.
    pub expanded: HashSet<SymbolPath>,

    /// Currently selected symbol paths (multi-select with Ctrl/Shift).
    pub selected: HashSet<SymbolPath>,

    /// The last-clicked symbol path (for shift+click range selection).
    pub last_clicked: Option<SymbolPath>,

    /// The last clicked symbol address for navigation.
    pub navigate_to: Option<Address>,

    /// Whether to show all symbols or only filtered ones.
    pub show_all: bool,

    /// The collapsed/expanded state of a drag-and-drop hover target for pending drop.
    pub drop_target: Option<SymbolPath>,

    /// Whether the drop target hover is currently over the upper half (to drop above).
    pub drop_above: bool,

    /// Scroll offset (used to persist scroll state).
    pub scroll_offset: f32,
}

impl SymbolTreePanel {
    /// Create a new empty symbol tree panel.
    pub fn new() -> Self {
        Self {
            tree: SymbolTreeNode::root(),
            filter: String::new(),
            expanded: HashSet::new(),
            selected: HashSet::new(),
            last_clicked: None,
            navigate_to: None,
            show_all: true,
            drop_target: None,
            drop_above: false,
            scroll_offset: 0.0,
        }
    }

    /// Load symbols from a program's symbol table into the tree.
    pub fn load_symbols(&mut self, tree: SymbolTreeNode) {
        self.tree = tree;
        // Auto-expand root categories
        for child in &self.tree.children {
            self.expanded.insert(child.path.clone());
        }
    }

    /// Set the filter text and update the view.
    pub fn set_filter(&mut self, filter: impl Into<String>) {
        self.filter = filter.into();
        // Auto-expand all nodes when filtering so results are visible
        if !self.filter.is_empty() {
            self.expand_all_matching(&self.tree.clone());
        }
    }

    /// Toggle expansion of a tree node.
    pub fn toggle_expanded(&mut self, path: &SymbolPath) {
        if self.expanded.contains(path) {
            self.expanded.remove(path);
        } else {
            self.expanded.insert(path.clone());
        }
    }

    /// Expand a specific path.
    pub fn expand(&mut self, path: &SymbolPath) {
        self.expanded.insert(path.clone());
    }

    /// Collapse a specific path.
    pub fn collapse(&mut self, path: &SymbolPath) {
        self.expanded.remove(path);
    }

    /// Expand all nodes that have descendants matching the current filter.
    fn expand_all_matching(&mut self, node: &SymbolTreeNode) {
        if self.node_matches_filter(node) {
            self.expanded.insert(node.path.clone());
            for child in &node.children {
                self.expand_all_matching(child);
            }
        }
    }

    /// Check whether any descendant of this node matches the current filter.
    fn any_descendant_matches_filter(&self, node: &SymbolTreeNode) -> bool {
        if self.filter.is_empty() {
            return true;
        }
        let filter_lower = self.filter.to_lowercase();
        if node.name.to_lowercase().contains(&filter_lower) {
            return true;
        }
        for child in &node.children {
            if self.any_descendant_matches_filter(child) {
                return true;
            }
        }
        false
    }

    /// Check whether this specific node matches the current filter.
    fn node_matches_filter(&self, node: &SymbolTreeNode) -> bool {
        if self.filter.is_empty() {
            return true;
        }
        let filter_lower = self.filter.to_lowercase();
        node.name.to_lowercase().contains(&filter_lower)
    }

    /// Check if a symbol matches the current filter.
    pub fn matches_filter(&self, symbol: &Symbol) -> bool {
        if self.filter.is_empty() {
            return true;
        }
        let filter_lower = self.filter.to_lowercase();
        symbol.name().to_lowercase().contains(&filter_lower)
    }

    /// Find symbols matching the given query.
    pub fn search(&self, query: &str) -> Vec<&Symbol> {
        let query_lower = query.to_lowercase();
        self.collect_symbols()
            .into_iter()
            .filter(|s| s.name().to_lowercase().contains(&query_lower))
            .collect()
    }

    /// Collect all symbols from the tree into a flat list.
    fn collect_symbols(&self) -> Vec<&Symbol> {
        let mut result = Vec::new();
        self.collect_from_node(&self.tree, &mut result);
        result
    }

    fn collect_from_node<'a>(&self, node: &'a SymbolTreeNode, result: &mut Vec<&'a Symbol>) {
        if let Some(ref sym) = node.symbol {
            result.push(sym);
        }
        for child in &node.children {
            self.collect_from_node(child, result);
        }
    }

    /// Count the total number of leaf symbols beneath a node.
    fn count_leaves(&self, node: &SymbolTreeNode) -> usize {
        if node.children.is_empty() {
            if node.symbol.is_some() {
                1
            } else {
                0
            }
        } else {
            node.children.iter().map(|c| self.count_leaves(c)).sum()
        }
    }

    /// Set the selected symbol by clicking on it.
    /// With Ctrl modifies multi-select, with Shift extends range.
    pub fn select(&mut self, path: &SymbolPath, symbol: Symbol, ctrl: bool, shift: bool) {
        if ctrl {
            // Toggle selection
            if self.selected.contains(path) {
                self.selected.remove(path);
            } else {
                self.selected.insert(path.clone());
            }
            self.navigate_to = None;
        } else if shift {
            // Range select not fully implemented yet; just add to selection
            self.selected.insert(path.clone());
            self.navigate_to = Some(*symbol.address());
        } else {
            // Single select
            self.selected.clear();
            self.selected.insert(path.clone());
            self.navigate_to = Some(*symbol.address());
        }
        self.last_clicked = Some(path.clone());
    }

    /// Select a category/group node (no navigation).
    pub fn select_group(&mut self, path: &SymbolPath, ctrl: bool, shift: bool) {
        if ctrl {
            if self.selected.contains(path) {
                self.selected.remove(path);
            } else {
                self.selected.insert(path.clone());
            }
        } else if shift {
            self.selected.insert(path.clone());
        } else {
            self.selected.clear();
            self.selected.insert(path.clone());
        }
        self.last_clicked = Some(path.clone());
    }

    /// Clear all selection.
    pub fn clear_selection(&mut self) {
        self.selected.clear();
        self.last_clicked = None;
    }

    /// Select all visible symbols.
    pub fn select_all(&mut self) {
        self.selected.clear();
        let tree = self.tree.clone();
        self.select_all_recursive(&tree);
    }

    fn select_all_recursive(&mut self, node: &SymbolTreeNode) {
        if node.symbol.is_some() {
            self.selected.insert(node.path.clone());
        }
        for child in &node.children {
            self.select_all_recursive(child);
        }
    }

    /// Clear the navigation request (call after consuming).
    pub fn take_navigate_to(&mut self) -> Option<Address> {
        self.navigate_to.take()
    }

    /// Expand all categories.
    pub fn expand_all(&mut self) {
        let tree = self.tree.clone();
        self.expand_all_recursive(&tree);
    }

    fn expand_all_recursive(&mut self, node: &SymbolTreeNode) {
        if !node.children.is_empty() {
            self.expanded.insert(node.path.clone());
            for child in &node.children {
                self.expand_all_recursive(child);
            }
        }
    }

    /// Collapse all categories.
    pub fn collapse_all(&mut self) {
        self.expanded.clear();
    }

    // ========================================================================
    // Main Render Entry Point
    // ========================================================================

    /// Render the symbol tree using egui.
    ///
    /// This is the main entry point. It renders the filter bar, then
    /// the scrollable tree area with full interaction support.
    pub fn render(&mut self, ui: &mut egui::Ui) {
        // --- Filter Bar ---
        self.render_filter_bar(ui);
        ui.separator();

        // --- Tree Body ---
        let available = ui.available_size_before_wrap();
        let tree_rect = egui::Rect::from_min_size(ui.next_widget_position(), available);

        // Allocate the tree area for drag-and-drop interaction
        let tree_response = ui.allocate_rect(tree_rect, egui::Sense::hover());

        // Detect drop on empty area
        self.detect_drop_on_empty(&tree_response, ui);

        // --- Scrollable Tree ---
        egui::ScrollArea::vertical()
            .auto_shrink([false; 2])
            .show(ui, |ui| {
                // Render categories
                let children = self.tree.children.clone();
                for (cat_idx, child) in children.iter().enumerate() {
                    // Check if this child (or any descendant) matches the filter
                    if !self.any_descendant_matches_filter(child) {
                        continue;
                    }

                    self.render_tree_node(ui, child, 0, cat_idx);
                }

                if children.is_empty() {
                    ui.centered_and_justified(|ui| {
                        ui.label(
                            egui::RichText::new("No symbols loaded")
                                .color(egui::Color32::from_rgb(128, 128, 128))
                                .italics(),
                        );
                    });
                }

                // Provide enough space for the scrollbar
                ui.allocate_space(egui::Vec2::new(ui.available_width(), 0.0));
            });

        // --- Keyboard Navigation ---
        self.handle_keyboard(ui);

        // --- Consume drag/drop ---
        self.process_drop(ui);
    }

    // ========================================================================
    // Filter Bar
    // ========================================================================

    /// Render the filter/search bar at the top of the panel.
    fn render_filter_bar(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            // Filter icon/label
            ui.label(egui::RichText::new("\u{1F50D}").size(14.0));
            // OR use a unicode char: ui.label("🔍");

            // Filter text input
            let filter_response = ui.add(
                egui::TextEdit::singleline(&mut self.filter)
                    .hint_text("Search symbols...")
                    .desired_width(ui.available_width() - 60.0),
            );

            // Auto-focus the filter when typing
            if filter_response.changed() && !self.filter.is_empty() {
                // Expand all matching nodes
                let tree = self.tree.clone();
                self.expand_all_matching(&tree);
            }

            // Clear button
            if ui
                .add_enabled(!self.filter.is_empty(), egui::Button::new("\u{2715}"))
                .clicked()
            {
                self.filter.clear();
            }

            // Total symbol count badge
            let total = self.count_leaves(&self.tree);
            let matching = if self.filter.is_empty() {
                total
            } else {
                self.collect_symbols()
                    .iter()
                    .filter(|s| self.matches_filter(s))
                    .count()
            };
            let badge = if !self.filter.is_empty() {
                format!("{}/{}", matching, total)
            } else {
                format!("{}", total)
            };
            ui.label(
                egui::RichText::new(badge)
                    .monospace()
                    .size(11.0)
                    .color(egui::Color32::from_rgb(150, 150, 150)),
            );
        });

        // Quick-toggle buttons
        if self.filter.is_empty() {
            ui.horizontal(|ui| {
                if ui.small_button("Expand All").clicked() {
                    self.expand_all();
                }
                if ui.small_button("Collapse All").clicked() {
                    self.collapse_all();
                }
                if ui.small_button("Select All").clicked() {
                    self.select_all();
                }
            });
        }
    }

    // ========================================================================
    // Tree Node Rendering
    // ========================================================================

    /// Render a single tree node and its children recursively.
    ///
    /// Returns the `egui::Response` for the row, which can be used for
    /// drag-and-drop source and target detection.
    fn render_tree_node(
        &mut self,
        ui: &mut egui::Ui,
        node: &SymbolTreeNode,
        depth: usize,
        flat_index: usize,
    ) {
        let has_children = !node.children.is_empty();
        let is_expanded = self.expanded.contains(&node.path);
        let is_selected = self.selected.contains(&node.path);
        let has_symbol = node.symbol.is_some();

        // Determine filter state for this node
        let node_matches = if self.filter.is_empty() {
            true
        } else {
            self.node_matches_filter(node) || self.any_descendant_matches_filter(node)
        };

        if !node_matches {
            return;
        }

        // --- Row Layout ---
        let indent = depth as f32 * INDENT_WIDTH;
        let available_w = ui.available_width();

        let row_height = ROW_HEIGHT;
        let _row_rect = egui::Rect::from_min_size(
            ui.next_widget_position(),
            egui::Vec2::new(available_w, row_height),
        );

        // Determine the row id for unique identification
        let _row_id = egui::Id::new(("symtree_row", node.path.clone()));
        let (row_rect_sense, row_response) = ui.allocate_at_least(
            egui::Vec2::new(available_w, row_height),
            egui::Sense::click_and_drag(),
        );

        // --- Row Background ---
        if is_selected {
            ui.painter().rect_filled(
                row_rect_sense,
                0.0,
                egui::Color32::from_rgb(40, 80, 140), // selection blue
            );
        } else if row_response.hovered() {
            ui.painter().rect_filled(
                row_rect_sense,
                0.0,
                egui::Color32::from_rgb(55, 55, 65), // hover highlight
            );
        }

        // --- Row Content ---
        let mut child_ui = ui.new_child(
            egui::UiBuilder::new()
                .max_rect(row_rect_sense)
                .layout(egui::Layout::left_to_right(egui::Align::Center)),
        );

        // 1. Indent
        child_ui.add_space(indent);

        // 2. Expand/collapse triangle (or placeholder for leaf nodes)
        if has_children {
            let triangle_text = if is_expanded { "\u{25BC}" } else { "\u{25B6}" }; // ▼ or ▶
            let triangle_rect = egui::Rect::from_min_size(
                child_ui.next_widget_position(),
                egui::Vec2::new(TRIANGLE_WIDTH, row_height),
            );

            let mut tri_ui = child_ui.new_child(
                egui::UiBuilder::new()
                    .max_rect(triangle_rect)
                    .layout(egui::Layout::centered_and_justified(egui::Direction::LeftToRight)),
            );

            let tri_response = tri_ui.add(
                egui::Button::new(
                    egui::RichText::new(triangle_text)
                        .size(10.0)
                        .color(egui::Color32::from_rgb(180, 180, 180)),
                )
                .fill(egui::Color32::TRANSPARENT)
                .frame(false)
                .min_size(egui::Vec2::new(TRIANGLE_WIDTH, row_height)),
            );

            if tri_response.clicked() {
                self.toggle_expanded(&node.path);
            }
        } else {
            child_ui.add_space(TRIANGLE_WIDTH);
        }

        // 3. Icon
        let icon_text = self.icon_for_node(node);
        child_ui.label(
            egui::RichText::new(icon_text)
                .size(12.0)
                .monospace()
                .color(self.color_for_node(node)),
        );
        child_ui.add_space(2.0);

        // 4. Symbol name label
        let name_text = if has_symbol {
            let sym = node.symbol.as_ref().unwrap();
            format!("{}  @ {}", node.name, sym.address())
        } else if has_children {
            let count = self.count_leaves(node);
            format!("{}  ({})", node.name, count)
        } else {
            node.name.clone()
        };

        let label_color = if is_selected {
            egui::Color32::WHITE
        } else {
            self.color_for_label(node)
        };

        let label = egui::RichText::new(&name_text)
            .size(12.0)
            .color(label_color);

        child_ui.label(label);

        // --- Row Click Handling ---
        if row_response.clicked() {
            // Get modifier keys
            let modifiers = ui.input(|i| i.modifiers);
            let ctrl = modifiers.ctrl;
            let shift = modifiers.shift;

            if has_symbol {
                self.select(&node.path, node.symbol.clone().unwrap(), ctrl, shift);
            } else {
                self.select_group(&node.path, ctrl, shift);
            }
            if !ctrl && !shift && !has_symbol {
                self.toggle_expanded(&node.path);
            }
        }

        if row_response.double_clicked() {
            if !has_symbol && has_children {
                self.toggle_expanded(&node.path);
            }
        }

        // --- Context Menu ---
        self.render_context_menu(node, &row_response, ui);

        // --- Drag Source ---
        self.handle_drag_source(node, &row_response, ui);

        // --- Drop Target ---
        self.handle_drop_target(node, &row_response, ui);

        // --- Render Children ---
        if is_expanded && has_children {
            let children = node.children.clone();
            for (child_idx, child) in children.iter().enumerate() {
                let child_idx_flat = flat_index * 1000 + child_idx + 1; // rough unique index
                self.render_tree_node(ui, child, depth + 1, child_idx_flat);
            }
        }
    }

    // ========================================================================
    // Icon & Color Helpers
    // ========================================================================

    /// Return a unicode icon character for a tree node.
    fn icon_for_node(&self, node: &SymbolTreeNode) -> &'static str {
        if let Some(ref sym) = node.symbol {
            match sym.kind() {
                SymbolType::Function => "F ",
                SymbolType::Label => "L ",
                SymbolType::Import => "\u{2193}", // ↓ down arrow
                SymbolType::Export => "\u{2191}", // ↑ up arrow
                SymbolType::Class => "C ",
                SymbolType::Namespace => "N ",
                SymbolType::Library => "B ", // library Book
                SymbolType::Parameter => "p ",
                SymbolType::LocalVar => "v ",
                SymbolType::GlobalVar => "V ",
                SymbolType::Global => "G ",
                SymbolType::Unknown => "? ",
            }
        } else if !node.children.is_empty() {
            // Check the node name to decide category icon
            let name_lower = node.name.to_lowercase();
            if name_lower.contains("function") {
                "F "
            } else if name_lower.contains("label") {
                "L "
            } else if name_lower.contains("import") {
                "\u{2193}"
            } else if name_lower.contains("export") {
                "\u{2191}"
            } else if name_lower.contains("class") {
                "C "
            } else if name_lower.contains("namespace") {
                "N "
            } else if name_lower.contains("external") {
                "E "
            } else {
                "\u{1F4C1} " // 📁 folder
            }
        } else {
            "  "
        }
    }

    /// Return the color for the icon of a tree node.
    fn color_for_node(&self, node: &SymbolTreeNode) -> egui::Color32 {
        if let Some(ref sym) = node.symbol {
            match sym.kind() {
                SymbolType::Function => egui::Color32::from_rgb(220, 200, 120), // gold
                SymbolType::Label => egui::Color32::from_rgb(180, 200, 220),    // light blue
                SymbolType::Import => egui::Color32::from_rgb(100, 180, 220),   // cyan-blue
                SymbolType::Export => egui::Color32::from_rgb(100, 220, 100),   // green
                SymbolType::Class => egui::Color32::from_rgb(200, 160, 220),    // lavender
                SymbolType::Namespace => egui::Color32::from_rgb(160, 200, 160), // mint
                SymbolType::Library => egui::Color32::from_rgb(220, 180, 140),  // tan
                SymbolType::Parameter => egui::Color32::from_rgb(160, 160, 200), // periwinkle
                SymbolType::LocalVar => egui::Color32::from_rgb(200, 200, 160), // pale yellow
                SymbolType::GlobalVar => egui::Color32::from_rgb(220, 160, 160), // salmon
                _ => egui::Color32::from_rgb(180, 180, 180),                    // grey
            }
        } else if !node.children.is_empty() {
            let name_lower = node.name.to_lowercase();
            if name_lower.contains("function") {
                egui::Color32::from_rgb(220, 200, 120)
            } else if name_lower.contains("import") {
                egui::Color32::from_rgb(100, 180, 220)
            } else if name_lower.contains("export") {
                egui::Color32::from_rgb(100, 220, 100)
            } else if name_lower.contains("class") {
                egui::Color32::from_rgb(200, 160, 220)
            } else if name_lower.contains("namespace") {
                egui::Color32::from_rgb(160, 200, 160)
            } else {
                egui::Color32::from_rgb(200, 200, 200)
            }
        } else {
            egui::Color32::from_rgb(180, 180, 180)
        }
    }

    /// Return the color for the text label of a tree node.
    fn color_for_label(&self, node: &SymbolTreeNode) -> egui::Color32 {
        if node.symbol.is_some() {
            if self.selected.contains(&node.path) {
                egui::Color32::WHITE
            } else {
                egui::Color32::from_rgb(220, 220, 220)
            }
        } else if !node.children.is_empty() {
            egui::Color32::from_rgb(180, 180, 200)
        } else {
            egui::Color32::from_rgb(180, 180, 180)
        }
    }

    // ========================================================================
    // Context Menu
    // ========================================================================

    /// Render the right-click context menu for a tree node.
    fn render_context_menu(
        &mut self,
        node: &SymbolTreeNode,
        response: &egui::Response,
        _ui: &mut egui::Ui,
    ) {
        let path = node.path.clone();
        let has_sym = node.symbol.is_some();
        let has_children = !node.children.is_empty();
        let sym_addr = node.symbol.as_ref().map(|s| *s.address());
        let sym_name = node.name.clone();
        let is_function = node
            .symbol
            .as_ref()
            .map(|s| s.kind() == SymbolType::Function)
            .unwrap_or(false);

        response.clone().context_menu(|ui| {
            // --- Navigation ---
            if has_sym {
                if let Some(addr) = sym_addr {
                    if ui.button("Go To  [Enter]").clicked() {
                        self.navigate_to = Some(addr);
                        self.selected.clear();
                        self.selected.insert(path.clone());
                        ui.close_menu();
                    }
                    if ui.button("Go To In New Window").clicked() {
                        self.navigate_to = Some(addr);
                        ui.close_menu();
                    }
                }
            }

            ui.separator();

            // --- Symbol Operations ---
            if has_sym {
                if ui.button(format!("Rename {}  [F2]", sym_name)).clicked() {
                    // In a real implementation, this would open a rename dialog
                    self.navigate_to = sym_addr;
                    ui.close_menu();
                }

                if ui.button("Delete  [Delete]").clicked() {
                    ui.close_menu();
                }

                ui.separator();

                if ui.button("Set As Primary").clicked() {
                    ui.close_menu();
                }

                ui.separator();

                if ui.button("Copy Name").clicked() {
                    ui.output_mut(|o| o.copied_text = sym_name.clone());
                    ui.close_menu();
                }

                if let Some(addr) = sym_addr {
                    if ui.button("Copy Address").clicked() {
                        ui.output_mut(|o| o.copied_text = format!("{}", addr));
                        ui.close_menu();
                    }
                }
            }

            // --- Category Operations ---
            if has_children {
                ui.separator();
                if ui.button("Expand All").clicked() {
                    self.expand_all_recursive(node);
                    ui.close_menu();
                }
                if ui.button("Collapse All").clicked() {
                    self.collapse_recursive(node);
                    ui.close_menu();
                }
                ui.separator();
            }

            if has_children && !has_sym {
                if ui.button("Create Category...").clicked() {
                    ui.close_menu();
                }
            }

            // --- References ---
            if has_sym {
                ui.separator();

                ui.menu_button("References", |ui| {
                    if ui.button("Show References To").clicked() {
                        self.navigate_to = sym_addr;
                        ui.close_menu();
                    }
                    if ui.button("Show References From").clicked() {
                        self.navigate_to = sym_addr;
                        ui.close_menu();
                    }
                    ui.separator();
                    if ui.button("Show XRefs").clicked() {
                        self.navigate_to = sym_addr;
                        ui.close_menu();
                    }
                });

                if is_function {
                    if ui.button("Edit Function Signature...").clicked() {
                        ui.close_menu();
                    }
                    if ui.button("Delete Function").clicked() {
                        ui.close_menu();
                    }
                }
            }

            // --- Data Type ---
            if has_sym {
                ui.separator();
                ui.menu_button("Data Type", |ui| {
                    for dt in &[
                        "byte", "word", "dword", "qword", "float", "double", "string", "pointer",
                        "unicode",
                    ] {
                        if ui.button(*dt).clicked() {
                            ui.close_menu();
                        }
                    }
                });
            }

            // --- Colors ---
            if has_sym {
                ui.separator();
                ui.menu_button("Colors", |ui| {
                    if ui.button("Set Background Color...").clicked() {
                        ui.close_menu();
                    }
                    if ui.button("Set Text Color...").clicked() {
                        ui.close_menu();
                    }
                    ui.separator();
                    if ui.button("Clear Colors").clicked() {
                        ui.close_menu();
                    }
                });
            }

            // --- Bookmarks ---
            if has_sym {
                ui.separator();
                if ui.button("Add Bookmark...").clicked() {
                    ui.close_menu();
                }
                if ui
                    .add_enabled(false, egui::Button::new("Remove Bookmark"))
                    .clicked()
                {
                    ui.close_menu();
                }
            }

            // --- Move / Reorganize ---
            if has_sym {
                ui.separator();
                if ui.button("Move To Category...").clicked() {
                    ui.close_menu();
                }
                if ui.button("Move To Namespace...").clicked() {
                    ui.close_menu();
                }
            }

            // --- Global Tree Actions ---
            ui.separator();
            ui.menu_button("Export", |ui| {
                if ui.button("Export Symbols As Text...").clicked() {
                    ui.close_menu();
                }
                if ui.button("Export Symbols As CSV...").clicked() {
                    ui.close_menu();
                }
            });
            if ui.button("Import Symbols...").clicked() {
                ui.close_menu();
            }
        });
    }

    /// Recursively collapse a node and all descendants.
    fn collapse_recursive(&mut self, node: &SymbolTreeNode) {
        self.expanded.remove(&node.path);
        for child in &node.children {
            self.collapse_recursive(child);
        }
    }

    // ========================================================================
    // Drag-and-Drop
    // ========================================================================

    /// Set up the node as a drag source.
    fn handle_drag_source(
        &mut self,
        node: &SymbolTreeNode,
        response: &egui::Response,
        _ui: &mut egui::Ui,
    ) {
        if response.drag_started() {
            if let Some(ref sym) = node.symbol {
                _ui.ctx().memory_mut(|mem| {
                    mem.data.insert_temp(
                        egui::Id::new("symtree_drag"),
                        SymbolTreeDragPayload::Symbol(sym.clone()),
                    );
                });
                // Also note that we're dragging
                _ui.output_mut(|o| o.cursor_icon = egui::CursorIcon::Grabbing);
            } else if !node.children.is_empty() {
                _ui.ctx().memory_mut(|mem| {
                    mem.data.insert_temp(
                        egui::Id::new("symtree_drag"),
                        SymbolTreeDragPayload::Group(node.path.clone()),
                    );
                });
                _ui.output_mut(|o| o.cursor_icon = egui::CursorIcon::Grabbing);
            }
        }

        // Change cursor on hover for draggable items
        if response.hovered() && !response.dragged() {
            if node.symbol.is_some() || !node.children.is_empty() {
                _ui.output_mut(|o| o.cursor_icon = egui::CursorIcon::Grab);
            }
        }
    }

    /// Set up the node as a drop target.
    fn handle_drop_target(
        &mut self,
        node: &SymbolTreeNode,
        response: &egui::Response,
        _ui: &mut egui::Ui,
    ) {
        // Check if something is being dragged
        let is_dragging = _ui.ctx().memory(|mem| {
            mem.data
                .get_temp::<SymbolTreeDragPayload>(egui::Id::new("symtree_drag"))
                .is_some()
        });

        if !is_dragging {
            return;
        }

        if response.hovered() {
            // Determine if we're hovering the upper or lower half of the row
            let hover_pos = response.hover_pos().unwrap_or(egui::Pos2::ZERO);
            let rect = response.rect;
            let is_upper = (hover_pos.y - rect.top()) < rect.height() * 0.5;

            self.drop_target = Some(node.path.clone());
            self.drop_above = is_upper;

            // Draw a drop indicator line
            let indicator_y = if is_upper { rect.top() } else { rect.bottom() };
            let indicator_rect = egui::Rect::from_min_max(
                egui::Pos2::new(rect.left(), indicator_y - 1.0),
                egui::Pos2::new(rect.right(), indicator_y + 1.0),
            );
            _ui.painter()
                .rect_filled(indicator_rect, 0.0, egui::Color32::from_rgb(100, 200, 255));

            _ui.output_mut(|o| o.cursor_icon = egui::CursorIcon::Grabbing);
        }
    }

    /// Detect a drop on empty area (below all rows).
    fn detect_drop_on_empty(&mut self, response: &egui::Response, _ui: &mut egui::Ui) {
        let is_dragging = _ui.ctx().memory(|mem| {
            mem.data
                .get_temp::<SymbolTreeDragPayload>(egui::Id::new("symtree_drag"))
                .is_some()
        });

        if !is_dragging {
            return;
        }

        if response.hovered() {
            // Dropping on empty area = drop as last child of root
            self.drop_target = Some(self.tree.path.clone());
            self.drop_above = false;
        }
    }

    /// Process a completed drag-and-drop operation.
    fn process_drop(&mut self, _ui: &mut egui::Ui) {
        let drag_data = _ui.ctx().memory(|mem| {
            mem.data
                .get_temp::<SymbolTreeDragPayload>(egui::Id::new("symtree_drag"))
        });

        // The drag data is consumed when the drag ends with a release, or
        // when the mouse is released. In egui, we check if the pointer was released
        // and there was a drag in progress.
        let drag_released = _ui.input(|i| i.pointer.any_released());

        if drag_released {
            if let Some(_target) = self.drop_target.take() {
                if let Some(_payload) = drag_data {
                    // In a full implementation, this would:
                    // 1. Re-parent the dragged symbol under the target
                    // 2. Use self.drop_above to decide whether to insert
                    //    before/after the target node
                    // 3. Update the symbol's namespace
                    // 4. Refresh the tree

                    let _above = self.drop_above; // used for drop positioning

                    // For now we just clear the state
                    _ui.ctx().memory_mut(|mem| {
                        mem.data
                            .remove::<SymbolTreeDragPayload>(egui::Id::new("symtree_drag"));
                    });
                }
            } else {
                // Drop was released outside any target — clear drag state
                _ui.ctx().memory_mut(|mem| {
                    mem.data
                        .remove::<SymbolTreeDragPayload>(egui::Id::new("symtree_drag"));
                });
            }
        }
    }

    // ========================================================================
    // Keyboard Handling
    // ========================================================================

    /// Handle keyboard shortcuts.
    fn handle_keyboard(&mut self, ui: &mut egui::Ui) {
        let input = ui.input(|i| i.clone());

        // Escape: clear selection
        if input.key_pressed(egui::Key::Escape) {
            self.clear_selection();
        }

        // Delete: placeholder for removing selected
        if input.key_pressed(egui::Key::Delete) {
            // Would confirm and remove selected symbols
        }

        // Ctrl+A: select all
        if input.modifiers.ctrl && input.key_pressed(egui::Key::A) {
            self.select_all();
        }

        // F2: rename
        if input.key_pressed(egui::Key::F2) {
            // Would open rename dialog for selected symbol
        }

        // Enter: navigate to selected
        if input.key_pressed(egui::Key::Enter) {
            if let Some(path) = self.selected.iter().next() {
                // Find the symbol and navigate
                if let Some(sym) = self.find_symbol_at_path(path) {
                    self.navigate_to = Some(*sym.address());
                }
            }
        }

        // Ctrl+F: focus filter
        if input.modifiers.ctrl && input.key_pressed(egui::Key::F) {
            // Focus the filter text input (handled implicitly via UI order)
        }

        // Left arrow: collapse
        if input.key_pressed(egui::Key::ArrowLeft) {
            let paths: Vec<_> = self.selected.iter().cloned().collect();
            for path in &paths {
                self.collapse(path);
            }
        }

        // Right arrow: expand
        if input.key_pressed(egui::Key::ArrowRight) {
            let paths: Vec<_> = self.selected.iter().cloned().collect();
            for path in &paths {
                self.expand(path);
            }
        }
    }

    /// Find a symbol at a given path in the tree.
    fn find_symbol_at_path(&self, path: &SymbolPath) -> Option<&Symbol> {
        self.find_in_node(path, &self.tree)
    }

    fn find_in_node<'a>(&self, path: &SymbolPath, node: &'a SymbolTreeNode) -> Option<&'a Symbol> {
        if &node.path == path {
            return node.symbol.as_ref();
        }
        for child in &node.children {
            if let Some(sym) = self.find_in_node(path, child) {
                return Some(sym);
            }
        }
        None
    }
}

impl Default for SymbolTreePanel {
    fn default() -> Self {
        Self::new()
    }
}
