//! Renderer for the disassembly listing view.
//!
//! Renders each listing row with address, bytes, label, mnemonic,
//! operands, and cross-references. Supports syntax highlighting,
//! clickable addresses, virtual scrolling, column resize, and
//! right-click context menus.

use super::{
    first_target_address, has_address_reference, is_flow_instruction, ColumnId, ColumnLayout,
    ListingAction, ListingRow, ListingView, OperandRenderType, RowType, SyntaxTheme,
};
use egui::{
    Align, Color32, CursorIcon, FontId, Id, Key, Modifiers, Pos2, Rect, Response, RichText,
    ScrollArea, Sense, Stroke, TextStyle, Ui, Vec2,
};
use ghidra_core::addr::Address;

// ============================================================================
// Constants
// ============================================================================

/// Height of a single listing row in pixels.
const ROW_HEIGHT: f32 = 18.0;

/// Height of the column header bar.
const HEADER_HEIGHT: f32 = 22.0;

/// Padding inside each cell.
const CELL_PADDING: f32 = 2.0;

/// Extra spacing for the separator area.
const SEPARATOR_PADDING: f32 = 3.0;

// ============================================================================
// Public Entry Point
// ============================================================================

/// Render the complete listing view into the given egui UI.
///
/// This is the main entry point called from the application. It renders
/// column headers, virtual-scrolled rows, and handles all interaction.
pub fn render_listing_view(
    view: &mut ListingView,
    rows: &[ListingRow],
    prog_name: &str,
    ui: &mut Ui,
) {
    // Sync column visibility from settings
    view.sync_column_visibility();

    // Render the header bar
    render_header_bar(view, prog_name, ui);

    // Render column headers with resize handles
    render_column_headers(view, ui, rows.is_empty());

    // Render the main listing area with virtual scrolling
    render_listing_body(view, rows, ui);

    // Render any open dialogs
    render_dialogs(view, ui);
}

// ============================================================================
// Header Bar
// ============================================================================

/// Render the listing header bar showing program name and toggles.
fn render_header_bar(view: &mut ListingView, prog_name: &str, ui: &mut Ui) {
    ui.horizontal(|ui| {
        ui.label(
            RichText::new(format!("Listing: {}", prog_name))
                .strong()
                .size(13.0)
                .color(view.syntax_theme.header_text),
        );

        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            // Column visibility toggles
            ui.checkbox(&mut view.columns.show_address, "Addr");
            ui.checkbox(&mut view.columns.show_bytes, "Bytes");
            ui.checkbox(&mut view.columns.show_label, "Label");
            ui.checkbox(&mut view.show_xrefs, "XRefs");

            ui.separator();

            // Theme toggle
            if ui.button("Theme").clicked() {
                // Toggle between dark and light
                // (simplified: just reset to default)
                view.syntax_theme = super::dark_theme();
            }

            // Goto button
            if ui.button("Goto...").clicked() {
                view.show_goto_dialog = true;
                view.goto_text = format!("{:08X}", view.cursor_position.offset);
            }
        });
    });
    ui.separator();
}

// ============================================================================
// Column Headers
// ============================================================================

/// Render column headers with labels and draggable resize handles.
fn render_column_headers(view: &mut ListingView, ui: &mut Ui, is_empty: bool) {
    let theme = &view.syntax_theme;
    let available = ui.available_size_before_wrap();

    // Background for header row
    let header_rect = Rect::from_min_size(
        ui.next_widget_position(),
        Vec2::new(available.x, HEADER_HEIGHT),
    );
    ui.painter().rect_filled(header_rect, 0.0, theme.header_bg);
    ui.painter().line_segment(
        [header_rect.left_bottom(), header_rect.right_bottom()],
        Stroke::new(1.0, theme.separator),
    );

    // Allocate the header row
    let (rect, _) = ui.allocate_exact_size(Vec2::new(available.x, HEADER_HEIGHT), Sense::hover());

    let mut child_ui = ui.child_ui(rect, *ui.layout(), None);

    let visible_cols: Vec<usize> = view
        .column_layout
        .columns
        .iter()
        .enumerate()
        .filter(|(_, c)| c.visible)
        .map(|(i, _)| i)
        .collect();

    let col_count = visible_cols.len();
    if col_count == 0 {
        return;
    }

    for (vis_idx, &col_idx) in visible_cols.iter().enumerate() {
        let col = &view.column_layout.columns[col_idx];
        let width = col.current_width;

        // Column header text
        let cell_rect = Rect::from_min_size(
            child_ui.next_widget_position(),
            Vec2::new(width - SEPARATOR_PADDING, HEADER_HEIGHT),
        );
        child_ui.allocate_ui_at_rect(cell_rect, |ui| {
            ui.set_min_size(Vec2::new(width - SEPARATOR_PADDING, HEADER_HEIGHT));
            ui.with_layout(
                egui::Layout::from_main_dir_and_cross_align(
                    egui::Direction::LeftToRight,
                    col.align,
                ),
                |ui| {
                    let label = RichText::new(&col.label)
                        .color(theme.header_text)
                        .monospace()
                        .font_size(11.0)
                        .strong();
                    ui.label(label);
                },
            );
        });

        // Resize handle (except after last column)
        if vis_idx < col_count - 1 {
            let sep_x = child_ui.next_widget_position().x;
            let sep_rect = Rect::from_min_size(
                Pos2::new(sep_x, header_rect.top()),
                Vec2::new(SEPARATOR_PADDING * 2.0, HEADER_HEIGHT),
            );

            let sep_response =
                child_ui.interact(sep_rect, Id::new(("col_resize", col_idx)), Sense::drag());

            // Change cursor on hover
            if sep_response.hovered() || view.column_layout.resizing == Some(col_idx) {
                child_ui.ctx().set_cursor_icon(CursorIcon::ResizeColumn);
            }

            // Draw resize handle
            if sep_response.hovered() || sep_response.dragged() {
                child_ui.painter().rect_filled(
                    sep_rect.shrink(1.0),
                    0.0,
                    theme.resize_handle_hover,
                );
            } else {
                child_ui
                    .painter()
                    .rect_filled(sep_rect.shrink(1.5), 0.0, theme.resize_handle);
            }
            child_ui.advance_cursor_after_rect(sep_rect);

            // Handle drag for resize
            if sep_response.dragged() {
                let delta = sep_response.drag_delta().x;
                if delta.abs() > 0.5 {
                    let col = &mut view.column_layout.columns[col_idx];
                    col.current_width =
                        (col.current_width + delta).clamp(col.min_width, col.max_width);
                    // Adjust next visible column too
                    if let Some(&next_idx) = visible_cols.get(vis_idx + 1) {
                        let next = &mut view.column_layout.columns[next_idx];
                        next.current_width =
                            (next.current_width - delta).clamp(next.min_width, next.max_width);
                    }
                    view.column_layout.resizing = Some(col_idx);
                }
            } else if view.column_layout.resizing == Some(col_idx) {
                view.column_layout.resizing = None;
            }
        }
    }
}

// ============================================================================
// Listing Body (Virtual Scrolling)
// ============================================================================

/// Render the listing rows using virtual scrolling.
fn render_listing_body(view: &mut ListingView, rows: &[ListingRow], ui: &mut Ui) {
    if rows.is_empty() {
        ui.centered_and_justified(|ui| {
            ui.label(
                RichText::new("No disassembly data available")
                    .color(view.syntax_theme.comment)
                    .monospace(),
            );
        });
        return;
    }

    let total_rows = rows.len();
    let row_height = ROW_HEIGHT;

    // Use egui's virtual scroll area
    egui::ScrollArea::vertical()
        .auto_shrink([false; 2])
        .show_rows(ui, row_height, total_rows, |ui, visible_range| {
            // Update scroll offset for keyboard navigation sync
            view.scroll_offset = visible_range.start;
            view.rows_visible = visible_range.end - visible_range.start;

            // Handle keyboard events
            let input = ui.input(|i| i.clone());
            handle_keyboard_navigation(view, rows, &input);

            // Allocate the total content area (for correct scrollbar)
            let total_height = total_rows as f32 * row_height;
            let available_width = ui.available_width();
            let desired_size = Vec2::new(available_width, total_height);
            ui.allocate_space(desired_size);

            // Render each visible row
            for row_idx in visible_range {
                if row_idx >= rows.len() {
                    break;
                }
                let row = &rows[row_idx];
                let is_cursor = row.address == view.cursor_position;
                let is_selected = view.is_selected(&row.address);
                let is_alternating = row_idx % 2 == 1;

                let y_pos = row_idx as f32 * row_height;
                let row_rect = Rect::from_min_size(
                    Pos2::new(ui.min_rect().left(), ui.min_rect().top() + y_pos),
                    Vec2::new(available_width, row_height),
                );

                // Row background
                paint_row_background(
                    ui,
                    row_rect,
                    is_cursor,
                    is_selected,
                    is_alternating,
                    &view.syntax_theme,
                );

                // Render the row content
                render_single_row(view, row, row_idx, row_rect, ui);

                // Handle click interactions
                let response = ui.interact(
                    row_rect,
                    Id::new(("listing_row", row.address.offset)),
                    Sense::click(),
                );
                handle_row_click(view, row, &response, ui);
                handle_row_context_menu(view, row, &response);
            }
        });
}

// ============================================================================
// Row Background Painting
// ============================================================================

/// Paint the background for a listing row.
fn paint_row_background(
    ui: &mut Ui,
    rect: Rect,
    is_cursor: bool,
    is_selected: bool,
    is_alternating: bool,
    theme: &SyntaxTheme,
) {
    if is_cursor {
        ui.painter().rect_filled(rect, 0.0, theme.cursor_bg);
    } else if is_selected {
        ui.painter().rect_filled(rect, 0.0, theme.selection_bg);
    } else if is_alternating {
        ui.painter().rect_filled(rect, 0.0, theme.alternating_bg);
    }
}

// ============================================================================
// Single Row Rendering
// ============================================================================

/// Render the content of a single listing row.
fn render_single_row(
    view: &ListingView,
    row: &ListingRow,
    row_idx: usize,
    row_rect: Rect,
    ui: &mut Ui,
) {
    let theme = &view.syntax_theme;
    let mut child_ui = ui.child_ui(row_rect, *ui.layout(), None);
    child_ui.set_min_size(Vec2::new(row_rect.width(), ROW_HEIGHT));

    let visible_cols: Vec<&super::ColumnDef> = view
        .column_layout
        .columns
        .iter()
        .filter(|c| c.visible)
        .collect();

    for (vis_idx, col) in visible_cols.iter().enumerate() {
        let width = col.current_width;
        let cell_width = if vis_idx < visible_cols.len() - 1 {
            width - SEPARATOR_PADDING
        } else {
            width
        };

        let cell_rect = Rect::from_min_size(
            child_ui.next_widget_position(),
            Vec2::new(cell_width, ROW_HEIGHT),
        );
        child_ui.allocate_ui_at_rect(cell_rect, |ui| {
            ui.set_min_size(Vec2::new(cell_width - CELL_PADDING * 2.0, ROW_HEIGHT));
            render_cell_content(view, row, col.id, theme, ui);
        });

        // Separator gap
        if vis_idx < visible_cols.len() - 1 {
            child_ui.add_space(SEPARATOR_PADDING);
        }
    }
}

/// Render the content of a specific cell based on column type.
fn render_cell_content(
    view: &ListingView,
    row: &ListingRow,
    col_id: ColumnId,
    theme: &SyntaxTheme,
    ui: &mut Ui,
) {
    match col_id {
        ColumnId::Address => render_address_cell(row, theme, ui),
        ColumnId::Bytes => render_bytes_cell(row, theme, ui),
        ColumnId::Label => render_label_cell(row, theme, ui),
        ColumnId::Mnemonic => render_mnemonic_cell(row, theme, ui),
        ColumnId::Operands => render_operands_cell(row, theme, ui),
        ColumnId::XRefs => render_xrefs_cell(view, row, theme, ui),
        ColumnId::Comment => render_comment_cell(view, row, theme, ui),
    }
}

// ============================================================================
// Individual Cell Renderers
// ============================================================================

/// Render the address cell.
fn render_address_cell(row: &ListingRow, theme: &SyntaxTheme, ui: &mut Ui) {
    let addr_text = format!("{:08X}", row.address.offset);
    match row.row_type {
        RowType::Separator => {
            ui.label(
                RichText::new("\u{2500}".repeat(10))
                    .color(theme.separator)
                    .monospace()
                    .font_size(10.0),
            );
        }
        RowType::Empty => {
            // Nothing
        }
        _ => {
            ui.label(
                RichText::new(&addr_text)
                    .color(theme.address)
                    .monospace()
                    .font_size(12.0),
            );
        }
    }
}

/// Render the bytes cell.
fn render_bytes_cell(row: &ListingRow, theme: &SyntaxTheme, ui: &mut Ui) {
    if row.bytes.is_empty() {
        return;
    }
    let bytes_text: String = row
        .bytes
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(" ");

    ui.label(
        RichText::new(&bytes_text)
            .color(theme.bytes)
            .monospace()
            .font_size(11.0),
    );
}

/// Render the label cell.
fn render_label_cell(row: &ListingRow, theme: &SyntaxTheme, ui: &mut Ui) {
    if let Some(ref label) = row.label {
        let (text, color) = if row.row_type == RowType::Instruction
            || is_flow_instruction(&row.mnemonic, &row.operands)
        {
            // Function labels get special color
            (label.as_str(), theme.label)
        } else {
            (label.as_str(), theme.address_ref)
        };
        ui.label(RichText::new(text).color(color).monospace().font_size(12.0));
    }
}

/// Render the mnemonic cell.
fn render_mnemonic_cell(row: &ListingRow, theme: &SyntaxTheme, ui: &mut Ui) {
    if row.mnemonic.is_empty() {
        match row.row_type {
            RowType::Data => {
                ui.label(
                    RichText::new("db")
                        .color(theme.mnemonic)
                        .monospace()
                        .font_size(12.0),
                );
            }
            RowType::Label => {
                ui.label(
                    RichText::new("lab")
                        .color(theme.mnemonic)
                        .monospace()
                        .font_size(12.0),
                );
            }
            _ => {}
        }
        return;
    }

    // Color conditional jumps differently
    let color = if row.mnemonic.starts_with('j') && row.mnemonic.len() >= 2 {
        let third = row.mnemonic.chars().nth(2);
        if third == Some('e')
            || third == Some('n')
            || third == Some('l')
            || third == Some('g')
            || third == Some('a')
            || third == Some('b')
            || third == Some('s')
            || third == Some('o')
            || third == Some('p')
            || third == Some('c')
            || third == Some('z')
        {
            Color32::from_rgb(200, 150, 255) // Purple for conditional jumps
        } else {
            theme.mnemonic
        }
    } else if row.mnemonic == "call" {
        Color32::from_rgb(255, 180, 100) // Orange for calls
    } else if row.mnemonic == "ret" || row.mnemonic == "iret" {
        Color32::from_rgb(255, 150, 130) // Red-ish for returns
    } else {
        theme.mnemonic
    };

    ui.label(
        RichText::new(&row.mnemonic)
            .color(color)
            .monospace()
            .font_size(12.0)
            .strong(),
    );
}

/// Render the operands cell with syntax coloring.
fn render_operands_cell(row: &ListingRow, theme: &SyntaxTheme, ui: &mut Ui) {
    if row.operands.is_empty() {
        return;
    }

    // Use a horizontal layout for inline operands
    ui.horizontal(|ui| {
        for (i, operand) in row.operands.iter().enumerate() {
            let color = operand_color(operand.op_type, theme);

            // Address operands are rendered as clickable links
            if operand.op_type == OperandRenderType::Address
                || operand.op_type == OperandRenderType::Label
            {
                let link_text = RichText::new(&operand.text)
                    .color(color)
                    .monospace()
                    .font_size(12.0)
                    .underline();
                let response = ui.selectable_label(false, link_text);
                if response.clicked() {
                    // Navigation will be handled by the caller via pending actions
                    // We set up the click target here
                    if let Some(target) = operand.target_address {
                        ui.ctx().data_mut(|d| {
                            d.insert_temp(Id::new("navigate_to"), target);
                        });
                    }
                }
            } else {
                ui.label(
                    RichText::new(&operand.text)
                        .color(color)
                        .monospace()
                        .font_size(12.0),
                );
            }

            // Add a small space after each operand for readability
            if i < row.operands.len() - 1 {
                // Check if the next token is a separator (comma etc) or if we just need space
                let next = &row.operands[i + 1];
                let this_text = &operand.text;
                let next_text = &next.text;
                if next_text != ","
                    && next_text != "]"
                    && next_text != ")"
                    && !this_text.ends_with('[')
                    && !this_text.ends_with('(')
                {
                    ui.add_space(2.0);
                }
            }
        }
    });
}

/// Render the cross-references cell.
fn render_xrefs_cell(view: &ListingView, row: &ListingRow, theme: &SyntaxTheme, ui: &mut Ui) {
    let xrefs = view.xrefs_to(&row.address);
    if xrefs.is_empty() && row.xrefs_to.is_empty() {
        return;
    }

    ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
        if !row.xrefs_to.is_empty() {
            let text = row.xrefs_to.join(", ");
            ui.label(
                RichText::new(text)
                    .color(theme.xref)
                    .monospace()
                    .font_size(10.0),
            );
        } else if !xrefs.is_empty() {
            let text: String = xrefs
                .iter()
                .map(|a| format!("{:08X}", a.offset))
                .collect::<Vec<_>>()
                .join(", ");
            ui.label(
                RichText::new(text)
                    .color(theme.xref)
                    .monospace()
                    .font_size(10.0),
            );
        }
    });
}

/// Render the comment cell.
fn render_comment_cell(view: &ListingView, row: &ListingRow, theme: &SyntaxTheme, ui: &mut Ui) {
    let comment = row
        .comment
        .as_deref()
        .or_else(|| view.comment_at(&row.address));
    if let Some(comment) = comment {
        ui.label(
            RichText::new(format!("; {}", comment))
                .color(theme.comment)
                .monospace()
                .font_size(11.0)
                .italics(),
        );
    }
}

// ============================================================================
// Operand Color Mapping
// ============================================================================

/// Map an [`OperandRenderType`] to a display color from the theme.
fn operand_color(op_type: OperandRenderType, theme: &SyntaxTheme) -> Color32 {
    match op_type {
        OperandRenderType::Register => theme.register,
        OperandRenderType::Immediate => theme.immediate,
        OperandRenderType::Address => theme.address_ref,
        OperandRenderType::Scalar => theme.scalar,
        OperandRenderType::Label => theme.label,
        OperandRenderType::String => theme.string,
        OperandRenderType::Constant => theme.constant,
    }
}

// ============================================================================
// Click Handling
// ============================================================================

/// Handle click interactions on a listing row.
fn handle_row_click(view: &mut ListingView, row: &ListingRow, response: &Response, ui: &Ui) {
    let modifiers = ui.input(|i| i.modifiers);

    if response.clicked() {
        if modifiers.ctrl {
            // Ctrl+click: toggle multi-select
            view.toggle_select(row.address);
        } else if modifiers.shift {
            // Shift+click: range select
            view.extend_selection(row.address);
        } else {
            // Single click: set cursor
            view.select(row.address);
        }
    }

    if response.double_clicked() {
        // Double-click: navigate to referenced address
        if has_address_reference(&row.operands) {
            if let Some(target) = first_target_address(&row.operands) {
                view.goto(target);
            }
        } else if is_flow_instruction(&row.mnemonic, &row.operands) {
            if let Some(target) = first_target_address(&row.operands) {
                view.goto(target);
            }
        }
    }
}

// ============================================================================
// Context Menu
// ============================================================================

/// Render the right-click context menu for a listing row.
///
/// Uses the structured context menu from [`crate::menus`] with nested submenus
/// for Data Type, References, Copy Special, Color, and External Program.
fn handle_row_context_menu(view: &mut ListingView, row: &ListingRow, response: &Response) {
    if row.address.offset == u64::MAX {
        return; // Skip null addresses
    }

    let row_addr = row.address;
    let row_mnemonic = row.mnemonic.clone();
    let row_full_instruction = format!(
        "{} {}",
        row.mnemonic,
        row.operands
            .iter()
            .map(|o| o.text.as_str())
            .collect::<Vec<_>>()
            .join(""),
    );
    let has_label = row.label.is_some();
    let has_comment = row.comment.is_some() || view.comment_at(&row_addr).is_some();
    let is_instruction = row.is_instruction;
    let has_function = is_instruction && !row_mnemonic.is_empty();
    let has_bookmark = false; // Could track bookmarks in the view

    let xrefs_to: Vec<Address> = view.xrefs_to(&row_addr).to_vec();

    response.clone().context_menu(|ui| {
        // -- Label Operations --
        if ui.button(format!("Rename Label...  [L]")).clicked() {
            view.show_rename_dialog = true;
            view.rename_address = Some(row_addr);
            view.rename_text = row.label.clone().unwrap_or_default();
            ui.close_menu();
        }
        ui.add_enabled(has_label, egui::Button::new("Remove Label"))
            .clicked()
            .then(|| {
                view.queue_action(ListingAction::RemoveLabel(row_addr));
                ui.close_menu();
            });

        ui.separator();

        // -- Comment Operations --
        if ui.button(format!("Set Comment...  [;]")).clicked() {
            view.show_comment_dialog = true;
            view.comment_address = Some(row_addr);
            view.comment_text = row.comment.clone().unwrap_or_default();
            ui.close_menu();
        }
        ui.add_enabled(has_comment, egui::Button::new("Edit Comment"))
            .clicked()
            .then(|| {
                view.show_comment_dialog = true;
                view.comment_address = Some(row_addr);
                view.comment_text = row.comment.clone().unwrap_or_default();
                ui.close_menu();
            });
        ui.add_enabled(has_comment, egui::Button::new("Delete Comment"))
            .clicked()
            .then(|| {
                view.queue_action(ListingAction::DeleteComment(row_addr));
                ui.close_menu();
            });

        ui.separator();

        // -- Disassembly Operations --
        if ui.button(format!("Disassemble  [D]")).clicked() {
            view.queue_action(ListingAction::Disassemble(row_addr));
            ui.close_menu();
        }
        if ui.button(format!("Clear Code Bytes  [C]")).clicked() {
            view.queue_action(ListingAction::Clear(row_addr));
            ui.close_menu();
        }

        ui.separator();

        // -- Function Operations --
        if ui.button(format!("Create Function  [F]")).clicked() {
            view.queue_action(ListingAction::CreateFunction(row_addr));
            ui.close_menu();
        }
        ui.add_enabled(false, egui::Button::new("Delete Function"))
            .clicked()
            .then(|| {
                view.queue_action(ListingAction::DeleteFunction(row_addr));
                ui.close_menu();
            });
        ui.add_enabled(false, egui::Button::new("Edit Function Signature..."))
            .clicked()
            .then(|| {
                view.queue_action(ListingAction::EditFunctionSignature(row_addr));
                ui.close_menu();
            });

        ui.separator();

        // -- Create / Data --
        if ui.button("Create Data").clicked() {
            view.queue_action(ListingAction::SetDataType(row_addr, "byte".to_string()));
            ui.close_menu();
        }

        // -- Data Type submenu --
        ui.menu_button("Define Data Type", |ui| {
            for (label, dt_name) in &[
                ("byte  [B]", "byte"),
                ("word", "word"),
                ("dword", "dword"),
                ("qword", "qword"),
                ("float", "float"),
                ("double", "double"),
                ("string", "string"),
                ("unicode", "unicode"),
                ("pointer  [P]", "pointer"),
                ("array...  [[]", "array"),
                ("struct...", "struct"),
            ] {
                if ui.button(*label).clicked() {
                    view.queue_action(ListingAction::SetDataType(row_addr, dt_name.to_string()));
                    ui.close_menu();
                }
            }
        });

        if ui.button("Create Array...").clicked() {
            view.queue_action(ListingAction::CreateArray(row_addr));
            ui.close_menu();
        }
        if ui.button("Create Pointer").clicked() {
            view.queue_action(ListingAction::CreatePointer(row_addr));
            ui.close_menu();
        }
        if ui.button("Create Structure...").clicked() {
            view.queue_action(ListingAction::CreateStructure(row_addr));
            ui.close_menu();
        }
        if ui.button("Apply Structure...").clicked() {
            view.queue_action(ListingAction::ApplyStructure(row_addr));
            ui.close_menu();
        }

        ui.separator();

        // -- Register / Flow --
        if ui.button("Set Register Value...").clicked() {
            view.queue_action(ListingAction::SetRegisterValue(row_addr));
            ui.close_menu();
        }
        if ui.button("Set Flow Override...").clicked() {
            view.queue_action(ListingAction::SetFlowOverride(row_addr));
            ui.close_menu();
        }

        ui.separator();

        // -- Bookmarks --
        if ui.button("Add Bookmark...").clicked() {
            view.queue_action(ListingAction::AddBookmark(row_addr));
            ui.close_menu();
        }
        ui.add_enabled(has_bookmark, egui::Button::new("Remove Bookmark"))
            .clicked()
            .then(|| {
                view.queue_action(ListingAction::RemoveBookmark(row_addr));
                ui.close_menu();
            });

        ui.separator();

        // -- Analysis --
        if ui.button("Analyze From Here").clicked() {
            view.queue_action(ListingAction::AnalyzeFromHere(row_addr));
            ui.close_menu();
        }

        ui.separator();

        // -- Patch --
        ui.add_enabled(is_instruction, egui::Button::new("Patch Instruction..."))
            .clicked()
            .then(|| {
                view.queue_action(ListingAction::PatchInstruction(row_addr));
                ui.close_menu();
            });
        ui.add_enabled(!is_instruction, egui::Button::new("Patch Data..."))
            .clicked()
            .then(|| {
                view.queue_action(ListingAction::PatchData(row_addr));
                ui.close_menu();
            });

        ui.separator();

        // -- References submenu --
        ui.menu_button("References", |ui| {
            if ui.button("Show References To").clicked() {
                view.queue_action(ListingAction::ShowXRefs(row_addr));
                ui.close_menu();
            }
            if ui.button("Show References From").clicked() {
                view.queue_action(ListingAction::ShowReferences(row_addr));
                ui.close_menu();
            }
            ui.separator();
            if ui.button("Show XRefs").clicked() {
                view.queue_action(ListingAction::ShowXRefs(row_addr));
                ui.close_menu();
            }
            // Show individual xref targets for navigation
            if !xrefs_to.is_empty() {
                ui.separator();
                ui.label(format!("XRefs To ({})", xrefs_to.len()));
                for xref in &xrefs_to {
                    let xref_text = format!("{:08X}", xref.offset);
                    if ui.button(&xref_text).clicked() {
                        view.goto(*xref);
                        ui.close_menu();
                    }
                }
            }
        });

        ui.separator();

        // -- Copy / Copy Special submenu --
        if ui.button("Copy").clicked() {
            let instr = row_full_instruction.clone();
            ui.output_mut(|o| o.copied_text = instr.clone());
            view.queue_action(ListingAction::CopyInstruction(instr));
            ui.close_menu();
        }
        ui.menu_button("Copy Special", |ui| {
            if ui.button("Copy Address").clicked() {
                let addr_str = format!("{:08X}", row_addr.offset);
                ui.output_mut(|o| o.copied_text = addr_str.clone());
                view.queue_action(ListingAction::CopyAddress(row_addr));
                ui.close_menu();
            }
            if ui.button("Copy Bytes").clicked() {
                let bytes_str: String = row
                    .bytes
                    .iter()
                    .map(|b| format!("{:02X}", b))
                    .collect::<Vec<_>>()
                    .join(" ");
                ui.output_mut(|o| o.copied_text = bytes_str.clone());
                view.queue_action(ListingAction::CopyBytes(row_addr));
                ui.close_menu();
            }
            ui.separator();
            if ui.button("Copy As String").clicked() {
                let s: String = row
                    .bytes
                    .iter()
                    .filter_map(|&b| {
                        if b.is_ascii_graphic() || b == b' ' {
                            Some(b as char)
                        } else {
                            None
                        }
                    })
                    .collect();
                ui.output_mut(|o| o.copied_text = s.clone());
                view.queue_action(ListingAction::CopyAsString(row_addr));
                ui.close_menu();
            }
            if ui.button("Copy As C Array").clicked() {
                let c_arr = format!(
                    "unsigned char data[] = {{ {} }};",
                    row.bytes
                        .iter()
                        .map(|b| format!("0x{:02X}", b))
                        .collect::<Vec<_>>()
                        .join(", ")
                );
                ui.output_mut(|o| o.copied_text = c_arr.clone());
                view.queue_action(ListingAction::CopyAsCArray(row_addr));
                ui.close_menu();
            }
            if ui.button("Copy As Python List").clicked() {
                let py_list = format!(
                    "[{}]",
                    row.bytes
                        .iter()
                        .map(|b| format!("0x{:02X}", b))
                        .collect::<Vec<_>>()
                        .join(", ")
                );
                ui.output_mut(|o| o.copied_text = py_list.clone());
                view.queue_action(ListingAction::CopyAsPythonList(row_addr));
                ui.close_menu();
            }
        });

        ui.separator();

        // -- Color submenu --
        ui.menu_button("Color", |ui| {
            if ui.button("Set Background Color...").clicked() {
                view.queue_action(ListingAction::SetBackgroundColor(row_addr));
                ui.close_menu();
            }
            if ui.button("Set Text Color...").clicked() {
                view.queue_action(ListingAction::SetTextColor(row_addr));
                ui.close_menu();
            }
            ui.separator();
            if ui.button("Clear Colors").clicked() {
                view.queue_action(ListingAction::ClearColors(row_addr));
                ui.close_menu();
            }
        });

        ui.separator();

        // -- External Program submenu --
        ui.menu_button("External Program", |ui| {
            if ui.button("Open In New Window").clicked() {
                view.queue_action(ListingAction::OpenInNewWindow(row_addr));
                ui.close_menu();
            }
            if ui.button("Edit With External Tool...").clicked() {
                view.queue_action(ListingAction::EditWithExternalTool(row_addr));
                ui.close_menu();
            }
        });
    });
}

// ============================================================================
// Keyboard Navigation
// ============================================================================

/// Handle keyboard events for navigation and actions.
fn handle_keyboard_navigation(
    view: &mut ListingView,
    rows: &[ListingRow],
    input: &egui::InputState,
) {
    // Arrow key navigation
    if input.key_pressed(Key::ArrowDown) {
        if let Some(current_idx) = view.address_to_row_index(rows, &view.cursor_position) {
            let next_idx = (current_idx + 1).min(rows.len().saturating_sub(1));
            if next_idx < rows.len() {
                let next_addr = rows[next_idx].address;
                if input.modifiers.shift {
                    view.extend_selection(next_addr);
                } else {
                    view.select(next_addr);
                }
                // Auto-scroll to keep cursor visible
                if next_idx >= view.scroll_offset + view.rows_visible.saturating_sub(1) {
                    view.scroll_down();
                }
            }
        }
    }

    if input.key_pressed(Key::ArrowUp) {
        if let Some(current_idx) = view.address_to_row_index(rows, &view.cursor_position) {
            let next_idx = current_idx.saturating_sub(1);
            if next_idx < rows.len() {
                let next_addr = rows[next_idx].address;
                if input.modifiers.shift {
                    view.extend_selection(next_addr);
                } else {
                    view.select(next_addr);
                }
                if next_idx <= view.scroll_offset {
                    view.scroll_up();
                }
            }
        }
    }

    // Page up/down
    if input.key_pressed(Key::PageDown) {
        view.page_down();
        if let Some(current_idx) = view.address_to_row_index(rows, &view.cursor_position) {
            let new_idx = (current_idx + view.rows_visible).min(rows.len().saturating_sub(1));
            if new_idx < rows.len() {
                view.cursor_position = rows[new_idx].address;
            }
        }
    }

    if input.key_pressed(Key::PageUp) {
        view.page_up();
        if let Some(current_idx) = view.address_to_row_index(rows, &view.cursor_position) {
            let new_idx = current_idx.saturating_sub(view.rows_visible);
            if new_idx < rows.len() {
                view.cursor_position = rows[new_idx].address;
            }
        }
    }

    // Home / End
    if input.key_pressed(Key::Home) {
        if let Some(row) = rows.first() {
            view.select(row.address);
            view.scroll_offset = 0;
        }
    }

    if input.key_pressed(Key::End) {
        if let Some(row) = rows.last() {
            view.select(row.address);
            view.scroll_offset = rows.len().saturating_sub(view.rows_visible);
        }
    }

    // Escape: clear selection
    if input.key_pressed(Key::Escape) {
        view.clear_selection();
    }

    // Ctrl+G: goto dialog
    if input.modifiers.ctrl && input.key_pressed(Key::G) {
        view.show_goto_dialog = true;
        view.goto_text = format!("{:08X}", view.cursor_position.offset);
    }

    // Ctrl+N: rename label
    if input.modifiers.ctrl && input.key_pressed(Key::N) {
        view.show_rename_dialog = true;
        view.rename_address = Some(view.cursor_position);
        view.rename_text = view
            .label_at(&view.cursor_position)
            .unwrap_or("")
            .to_string();
    }

    // Ctrl+;: set comment
    if input.modifiers.ctrl && input.key_pressed(Key::Semicolon) {
        view.show_comment_dialog = true;
        view.comment_address = Some(view.cursor_position);
        view.comment_text = view
            .comment_at(&view.cursor_position)
            .unwrap_or("")
            .to_string();
    }
}

// ============================================================================
// Dialogs
// ============================================================================

/// Render popup dialogs (goto, rename, comment).
fn render_dialogs(view: &mut ListingView, ui: &mut Ui) {
    render_goto_dialog(view, ui);
    render_rename_dialog(view, ui);
    render_comment_dialog(view, ui);
}

/// Render the "Go To Address" dialog.
fn render_goto_dialog(view: &mut ListingView, ui: &mut Ui) {
    if !view.show_goto_dialog {
        return;
    }

    egui::Window::new("Go To Address")
        .collapsible(false)
        .resizable(false)
        .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
        .show(ui.ctx(), |ui| {
            ui.horizontal(|ui| {
                ui.label("Address (hex):");
                ui.text_edit_singleline(&mut view.goto_text);
            });

            ui.horizontal(|ui| {
                if ui.button("Go").clicked() || ui.input(|i| i.key_pressed(Key::Enter)) {
                    let trimmed = view.goto_text.trim();
                    let addr = if trimmed.starts_with("0x") || trimmed.starts_with("0X") {
                        u64::from_str_radix(&trimmed[2..], 16).ok()
                    } else {
                        u64::from_str_radix(trimmed, 16).ok()
                    };

                    if let Some(offset) = addr {
                        let addr = Address::new(offset);
                        view.goto(addr);
                        view.scroll_to_address(&[], &addr);
                    }
                    view.show_goto_dialog = false;
                }
                if ui.button("Cancel").clicked() {
                    view.show_goto_dialog = false;
                }
            });
        });
}

/// Render the "Rename Label" dialog.
fn render_rename_dialog(view: &mut ListingView, ui: &mut Ui) {
    if !view.show_rename_dialog {
        return;
    }

    let addr = view.rename_address.unwrap_or(Address::new(0));

    egui::Window::new("Rename Label")
        .collapsible(false)
        .resizable(false)
        .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
        .show(ui.ctx(), |ui| {
            ui.label(format!("Address: {:08X}", addr.offset));
            ui.horizontal(|ui| {
                ui.label("Name:");
                ui.text_edit_singleline(&mut view.rename_text);
            });

            ui.horizontal(|ui| {
                if ui.button("OK").clicked() || ui.input(|i| i.key_pressed(Key::Enter)) {
                    view.queue_action(ListingAction::RenameLabel(addr));
                    view.show_rename_dialog = false;
                }
                if ui.button("Cancel").clicked() {
                    view.show_rename_dialog = false;
                }
            });

            // Quick suggestions
            ui.separator();
            ui.label("Suggestions:");
            ui.horizontal(|ui| {
                for prefix in &["FUN_", "DAT_", "LAB_", "sub_", "loc_"] {
                    if ui
                        .button(format!("{}{:08X}", prefix, addr.offset))
                        .clicked()
                    {
                        view.rename_text = format!("{}{:08X}", prefix, addr.offset);
                    }
                }
            });

            if let Some(ref label) = view.label_at(&addr).map(|s| s.to_string()) {
                if !label.is_empty() {
                    ui.horizontal(|ui| {
                        ui.label("Current:");
                        ui.label(
                            RichText::new(label)
                                .monospace()
                                .color(view.syntax_theme.label),
                        );
                    });
                }
            }
        });
}

/// Render the "Set Comment" dialog.
fn render_comment_dialog(view: &mut ListingView, ui: &mut Ui) {
    if !view.show_comment_dialog {
        return;
    }

    let addr = view.comment_address.unwrap_or(Address::new(0));

    egui::Window::new("Set Comment")
        .collapsible(false)
        .resizable(true)
        .default_size([400.0, 200.0])
        .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
        .show(ui.ctx(), |ui| {
            ui.label(format!("Address: {:08X}", addr.offset));

            ui.horizontal(|ui| {
                ui.label("Comment type:");
                egui::ComboBox::from_id_salt("comment_type")
                    .selected_text("EOL")
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut String::from("EOL"), "EOL".to_string(), "EOL");
                        ui.selectable_value(&mut String::from("PRE"), "PRE".to_string(), "Pre");
                        ui.selectable_value(&mut String::from("POST"), "POST".to_string(), "Post");
                        ui.selectable_value(
                            &mut String::from("PLATE"),
                            "PLATE".to_string(),
                            "Plate",
                        );
                        ui.selectable_value(
                            &mut String::from("REPEATABLE"),
                            "REPEATABLE".to_string(),
                            "Repeatable",
                        );
                    });
            });

            ui.label("Comment:");
            ui.text_edit_multiline(&mut view.comment_text);

            ui.horizontal(|ui| {
                if ui.button("OK").clicked() {
                    view.queue_action(ListingAction::SetComment(addr, view.comment_text.clone()));
                    view.show_comment_dialog = false;
                }
                if ui.button("Cancel").clicked() {
                    view.show_comment_dialog = false;
                }
                if ui.button("Clear").clicked() {
                    view.comment_text.clear();
                }
            });

            // Show existing comment if any
            if let Some(existing) = view.comment_at(&addr) {
                ui.separator();
                ui.label("Existing comment:");
                ui.label(
                    RichText::new(existing)
                        .color(view.syntax_theme.comment)
                        .monospace(),
                );
            }
        });
}
