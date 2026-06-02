//! Renderer for the bytes/hex view.
//!
//! Renders a classic hex-dump layout with an address column, a hex-byte
//! column (with configurable grouping), and an ASCII representation column.
//! Supports inline hex editing, range selection (click + shift-click, drag),
//! keyboard navigation, search with highlighting, and clipboard export.

use super::BytesView;
use egui::{Color32, Key, Layout, RichText, Ui, Vec2};

// =============================================================================
// Colour constants
// =============================================================================

const BG_DEFAULT: Color32 = Color32::from_rgb(30, 30, 30);
const BG_SELECTED: Color32 = Color32::from_rgb(55, 85, 140);
const BG_CURSOR: Color32 = Color32::from_rgb(80, 80, 80);
const BG_EDIT: Color32 = Color32::from_rgb(100, 40, 40);
const BG_SEARCH_HIT: Color32 = Color32::from_rgb(60, 90, 30);
const BG_CHANGED: Color32 = Color32::from_rgb(80, 40, 0);

const COLOR_ADDRESS: Color32 = Color32::from_rgb(120, 160, 200);
const COLOR_HEX: Color32 = Color32::from_rgb(200, 200, 200);
const COLOR_ASCII: Color32 = Color32::from_rgb(150, 200, 150);
const COLOR_DOT: Color32 = Color32::from_rgb(100, 100, 100);
const COLOR_CHANGED_TEXT: Color32 = Color32::from_rgb(255, 180, 100);
const COLOR_SEARCH_TEXT: Color32 = Color32::from_rgb(200, 255, 180);

const GUTTER_WIDTH: f32 = 8.0; // pixels between columns

// =============================================================================
// Public entry-point
// =============================================================================

/// Render the complete bytes-view (toolbar + hex dump + dialogs).
pub fn render_bytes_view(view: &mut BytesView, ui: &mut Ui) {
    // ---- toolbar ------------------------------------------------------------
    render_toolbar(view, ui);
    ui.separator();

    // ---- search bar ---------------------------------------------------------
    if view.show_search {
        render_search_bar(view, ui);
        ui.separator();
    }

    // ---- hex dump area ------------------------------------------------------
    if !view.has_data {
        ui.centered_and_justified(|ui| {
            ui.label(RichText::new("No data loaded").color(COLOR_DOT).monospace());
        });
    } else {
        view.line_height = ui.text_style_height(&egui::TextStyle::Monospace);
        let glyph_w = char_width(ui, &view.font);
        render_hex_dump(view, ui, glyph_w, view.line_height);
    }

    // ---- goto dialog --------------------------------------------------------
    if view.show_goto {
        render_goto_dialog(view, ui);
    }

    // ---- keyboard handling --------------------------------------------------
    if !view.show_goto {
        handle_keyboard(view, ui);
    }
}

// =============================================================================
// Toolbar
// =============================================================================

fn render_toolbar(view: &mut BytesView, ui: &mut Ui) {
    ui.horizontal(|ui| {
        ui.label(RichText::new("Bytes:").monospace().small());

        // Group size toggle
        ui.menu_button("Group", |ui| {
            for &gs in &[1, 2, 4, 8] {
                if ui
                    .selectable_label(
                        view.group_size == gs,
                        format!("{} byte{}", gs, if gs == 1 { "" } else { "s" }),
                    )
                    .clicked()
                {
                    view.group_size = gs;
                    ui.close_menu();
                }
            }
        });

        // Bytes per row
        ui.separator();
        ui.label("Row:");
        egui::ComboBox::from_id_salt("bpr_combo")
            .width(48.0)
            .selected_text(format!("{}", view.bytes_per_row))
            .show_ui(ui, |ui| {
                for &n in &[8, 16, 32, 64] {
                    ui.selectable_value(&mut view.bytes_per_row, n, format!("{}", n));
                }
            });

        ui.separator();

        // Visibility toggles
        ui.toggle_value(&mut view.show_address, "Addr");
        ui.toggle_value(&mut view.show_ascii, "ASCII");

        ui.separator();

        // Copy menu
        let copy_resp = ui.button("Copy");
        copy_resp.context_menu(|ui| {
            if ui.button("Copy as hex string").clicked() {
                let s = view.copy_as_hex();
                ui.ctx().output_mut(|o| o.copied_text = s.clone());
                view.last_copy = "Copied hex".into();
                ui.close_menu();
            }
            if ui.button("Copy as C array").clicked() {
                let s = view.copy_as_c_array();
                ui.ctx().output_mut(|o| o.copied_text = s.clone());
                view.last_copy = "Copied C array".into();
                ui.close_menu();
            }
            if ui.button("Copy as Python bytes").clicked() {
                let s = view.copy_as_python_bytes();
                ui.ctx().output_mut(|o| o.copied_text = s.clone());
                view.last_copy = "Copied Python bytes".into();
                ui.close_menu();
            }
            if ui.button("Copy as Python bytearray").clicked() {
                let s = view.copy_as_python_bytearray();
                ui.ctx().output_mut(|o| o.copied_text = s.clone());
                view.last_copy = "Copied Python bytearray".into();
                ui.close_menu();
            }
        });

        // Search toggle
        if ui
            .button("\u{1F50D}")
            .on_hover_text("Search hex pattern (Ctrl+F)")
            .clicked()
        {
            view.show_search = !view.show_search;
            if !view.show_search {
                view.search_results.clear();
                view.search_current = 0;
            }
        }

        // Goto button
        if ui
            .button("GoTo")
            .on_hover_text("Go to address (Ctrl+G)")
            .clicked()
        {
            view.show_goto = true;
            view.goto_buffer = format!("{:08X}", view.cursor_offset);
        }

        ui.separator();

        // Revert
        if ui
            .button("Revert")
            .on_hover_text("Revert all changes")
            .clicked()
        {
            view.revert_all();
        }

        // Changed count
        let changed = view.original_bytes.len();
        if changed > 0 {
            ui.label(
                RichText::new(format!("{} changed", changed))
                    .color(COLOR_CHANGED_TEXT)
                    .small(),
            );
        }

        // Status / last copy
        if !view.last_copy.is_empty() {
            ui.with_layout(Layout::right_to_left(egui::Align::Center), |ui| {
                ui.label(RichText::new(&view.last_copy).color(COLOR_ASCII).small());
            });
        }
    });
}

// =============================================================================
// Search bar
// =============================================================================

fn render_search_bar(view: &mut BytesView, ui: &mut Ui) {
    ui.horizontal(|ui| {
        ui.label("Hex pattern:");
        let resp = ui.add_sized(
            [160.0, 20.0],
            egui::TextEdit::singleline(&mut view.search_pattern)
                .font(view.font.clone())
                .hint_text("e.g. 48 65 6C"),
        );

        if ui.button("Find").clicked()
            || (resp.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter)))
        {
            view.search();
        }

        if !view.search_results.is_empty() {
            ui.label(format!(
                "{}/{}",
                view.search_current + 1,
                view.search_results.len()
            ));

            if ui
                .button("\u{25C0}")
                .on_hover_text("Previous match (Shift+F3)")
                .clicked()
            {
                view.search_prev();
            }
            if ui
                .button("\u{25B6}")
                .on_hover_text("Next match (F3)")
                .clicked()
            {
                view.search_next();
            }
        } else if !view.search_pattern.is_empty() && view.search_results.is_empty() {
            ui.label(RichText::new("No matches").color(COLOR_DOT).small());
        }

        if ui.button("\u{2715}").on_hover_text("Close search").clicked() {
            view.show_search = false;
            view.search_results.clear();
            view.search_current = 0;
            view.search_pattern.clear();
        }
    });
}

// =============================================================================
// Goto dialog
// =============================================================================

fn render_goto_dialog(view: &mut BytesView, ui: &mut Ui) {
    egui::Window::new("Go to address")
        .collapsible(false)
        .resizable(false)
        .anchor(egui::Align2::CENTER_TOP, [0.0, 40.0])
        .show(ui.ctx(), |ui| {
            ui.horizontal(|ui| {
                ui.label("Address (hex):");
                let resp = ui.add_sized(
                    [140.0, 20.0],
                    egui::TextEdit::singleline(&mut view.goto_buffer)
                        .font(view.font.clone())
                        .hint_text("00001000"),
                );
                resp.request_focus();

                if ui.button("Go").clicked()
                    || (resp.lost_focus()
                        && ui.input(|i| i.key_pressed(Key::Enter)))
                {
                    view.submit_goto();
                }
                if ui.button("Cancel").clicked() {
                    view.show_goto = false;
                    view.goto_buffer.clear();
                }
            });
        });
}

// =============================================================================
// Hex dump
// =============================================================================

fn render_hex_dump(view: &mut BytesView, ui: &mut Ui, glyph_w: f32, line_h: f32) {
    let avail_h = ui.available_height();
    let vis = (avail_h / line_h).floor() as usize;
    view.visible_rows = vis.max(4);

    let total = view.total_rows();
    let max_scroll = total.saturating_sub(view.visible_rows);
    if view.scroll_offset > max_scroll {
        view.scroll_offset = max_scroll;
    }

    // Collect search hit offsets into a Set for O(1) lookup during rendering.
    let search_hits = if view.show_search {
        view.search_hit_offsets()
    } else {
        std::collections::HashSet::new()
    };

    let current_search_hit_base = view.current_search_hit_offset();

    // Pre-compute column widths.
    let addr_w = if view.show_address {
        8.0 * glyph_w
    } else {
        0.0
    };
    let hex_w = hex_column_width(view, glyph_w);
    let ascii_w = if view.show_ascii {
        (view.bytes_per_row as f32) * glyph_w
    } else {
        0.0
    };

    // ---- column header ------------------------------------------------------
    ui.horizontal(|ui| {
        ui.set_height(line_h);
        if view.show_address {
            ui.add_sized(
                [addr_w, line_h],
                egui::Label::new(
                    RichText::new("Offset  ").color(COLOR_ADDRESS).monospace(),
                ),
            );
            ui.add_space(GUTTER_WIDTH);
        }

        let hex_label = match view.bytes_per_row {
            8 => "00 01 02 03 04 05 06 07",
            16 => "00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F",
            32 => "00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F  \
                    10 11 12 13 14 15 16 17  18 19 1A 1B 1C 1D 1E 1F",
            _ => "",
        };
        ui.add_sized(
            [hex_w, line_h],
            egui::Label::new(RichText::new(hex_label).color(COLOR_DOT).monospace()),
        );

        if view.show_ascii {
            ui.add_space(GUTTER_WIDTH);
            ui.add_sized(
                [ascii_w, line_h],
                egui::Label::new(
                    RichText::new("ASCII").color(COLOR_ADDRESS).monospace(),
                ),
            );
        }
    });
    ui.separator();

    // ---- scrollable body ----------------------------------------------------
    egui::ScrollArea::vertical()
        .id_salt("hex_scroll")
        .auto_shrink([false; 2])
        .show_rows(ui, line_h, view.visible_rows, |ui, row_range| {
            view.scroll_offset = row_range.start;

            for row_idx in row_range {
                if row_idx >= total {
                    break;
                }
                render_hex_row(
                    view,
                    ui,
                    row_idx,
                    glyph_w,
                    line_h,
                    addr_w,
                    hex_w,
                    ascii_w,
                    &search_hits,
                    current_search_hit_base,
                );
            }

            // Detect drag release that happened outside the row loop
            if view.dragging {
                let released =
                    ui.input(|i| !i.pointer.button_down(egui::PointerButton::Primary));
                if released {
                    view.end_drag();
                }
            }
        });
}

// =============================================================================
// Single hex row
// =============================================================================

fn render_hex_row(
    view: &mut BytesView,
    ui: &mut Ui,
    row_idx: usize,
    glyph_w: f32,
    line_h: f32,
    addr_w: f32,
    hex_w: f32,
    ascii_w: f32,
    search_hits: &std::collections::HashSet<u64>,
    current_search_hit_base: Option<u64>,
) {
    let row = view.get_row(row_idx);
    if row.is_empty() {
        return;
    }

    let row_addr = view.row_start_offset(row_idx);
    let row_len = row.len();

    ui.horizontal(|ui| {
        ui.set_height(line_h);

        // -- address column ---------------------------------------------------
        if view.show_address {
            let addr_text = format!("{:08X}", row_addr);
            ui.add_sized(
                [addr_w, line_h],
                egui::Label::new(
                    RichText::new(&addr_text)
                        .color(COLOR_ADDRESS)
                        .monospace(),
                ),
            );
            ui.add_space(GUTTER_WIDTH);
        }

        // -- hex bytes column -------------------------------------------------
        render_hex_bytes_column(
            view,
            ui,
            &row,
            glyph_w,
            line_h,
            search_hits,
            current_search_hit_base,
        );

        // Compute exactly how much hex-column pixel-width was consumed and
        // add the remaining slack so that every row fills the same `hex_w`.
        let consumed = used_hex_width(row_len, view.group_size, glyph_w);
        let slack = hex_w - consumed;
        if slack > 0.0 {
            ui.add_space(slack);
        }

        // -- ascii column -----------------------------------------------------
        if view.show_ascii {
            ui.add_space(GUTTER_WIDTH);
            render_ascii_column(view, ui, &row, glyph_w, line_h);

            // Pad ascii column to consistent width
            let ascii_slack = ascii_w - row_len as f32 * glyph_w;
            if ascii_slack > 0.0 {
                ui.add_space(ascii_slack);
            }
        }

        // Consume remaining width to prevent row from stretching
        let remaining = ui.available_width();
        if remaining > 0.0 {
            ui.add_space(remaining);
        }
    });
}

// =============================================================================
// Hex bytes column — one interactive cell per byte
// =============================================================================

fn render_hex_bytes_column(
    view: &mut BytesView,
    ui: &mut Ui,
    row: &[(u64, u8)],
    glyph_w: f32,
    line_h: f32,
    search_hits: &std::collections::HashSet<u64>,
    _current_search_hit_base: Option<u64>,
) {
    for (col, &(offset, byte)) in row.iter().enumerate() {
        // Extra space before each group boundary (except first)
        if col > 0 && col % view.group_size == 0 {
            ui.add_space(glyph_w);
        }

        let is_cursor = !view.edit_mode && view.cursor_offset == offset;
        let is_selected = view.is_selected(offset);
        let is_changed = view.is_changed(offset);
        let is_search_hit = search_hits.contains(&offset);

        let bg = if view.edit_mode && view.cursor_offset == offset {
            BG_EDIT
        } else if is_search_hit {
            BG_SEARCH_HIT
        } else if is_selected {
            BG_SELECTED
        } else if is_cursor {
            BG_CURSOR
        } else if is_changed {
            BG_CHANGED
        } else {
            BG_DEFAULT
        };

        let text_color = if is_changed {
            COLOR_CHANGED_TEXT
        } else if is_search_hit {
            COLOR_SEARCH_TEXT
        } else {
            COLOR_HEX
        };

        let byte_text = format!("{:02X}", byte);
        let cell_w = 2.0 * glyph_w;

        if view.edit_mode && view.cursor_offset == offset {
            // ---- inline text edit -------------------------------------------
            let resp = ui.add_sized(
                [cell_w, line_h],
                egui::TextEdit::singleline(&mut view.edit_buffer)
                    .font(view.font.clone())
                    .text_color(Color32::WHITE)
                    .desired_width(cell_w),
            );

            if resp.lost_focus() {
                let ctx = ui.ctx();
                if ctx.input(|i| i.key_pressed(Key::Enter))
                    || ctx.input(|i| i.key_pressed(Key::Tab))
                {
                    view.commit_edit();
                    if ctx.input(|i| i.key_pressed(Key::Tab)) {
                        view.set_cursor(view.cursor_offset.saturating_add(1));
                    }
                } else if ctx.input(|i| i.key_pressed(Key::Escape)) {
                    view.cancel_edit();
                } else {
                    // Focus lost due to clicking elsewhere; commit what we have
                    view.commit_edit();
                }
            }

            // Auto-commit when 2 hex digits typed
            if view.edit_buffer.len() >= 2 {
                view.commit_edit();
                view.set_cursor(view.cursor_offset.saturating_add(1));
            }

            resp.request_focus();
        } else {
            // ---- normal byte cell with manual painting -----------------------
            let (rect, resp) = ui.allocate_exact_size(
                Vec2::new(cell_w, line_h),
                egui::Sense::click_and_drag(),
            );

            if ui.is_rect_visible(rect) {
                // Background
                ui.painter().rect_filled(rect, egui::Rounding::ZERO, bg);

                // Text centred in cell
                ui.painter().text(
                    rect.center(),
                    egui::Align2::CENTER_CENTER,
                    &byte_text,
                    view.font.clone(),
                    text_color,
                );

                // Cursor underline
                if is_cursor {
                    let y = rect.bottom() - 1.0;
                    ui.painter().line_segment(
                        [egui::pos2(rect.left(), y), egui::pos2(rect.right(), y)],
                        egui::Stroke::new(1.5, Color32::WHITE),
                    );
                }
            }

            // Interaction
            if resp.clicked() {
                if ui.input(|i| i.modifiers.shift) {
                    view.extend_selection_to(offset);
                } else {
                    view.set_cursor(offset);
                }
            }
            if resp.double_clicked() {
                view.set_cursor(offset);
                view.enter_edit_mode();
            }
            if resp.drag_started() {
                view.start_drag(offset);
            }
            if resp.dragged() {
                view.continue_drag(offset);
            }
        }

        // Inter-byte spacing (single space, except after the last byte)
        if col < row.len() - 1 {
            ui.add_space(glyph_w);
        }
    }
}

// =============================================================================
// ASCII column — one interactive character per byte
// =============================================================================

fn render_ascii_column(
    view: &mut BytesView,
    ui: &mut Ui,
    row: &[(u64, u8)],
    glyph_w: f32,
    line_h: f32,
) {
    for (col, &(offset, byte)) in row.iter().enumerate() {
        let is_cursor = !view.edit_mode && view.cursor_offset == offset;
        let is_selected = view.is_selected(offset);
        let is_changed = view.is_changed(offset);

        let ch = if byte.is_ascii_graphic() || byte == b' ' {
            byte as char
        } else {
            '.'
        };

        let text_color = if ch == '.' {
            COLOR_DOT
        } else if is_changed {
            COLOR_CHANGED_TEXT
        } else {
            COLOR_ASCII
        };

        let bg = if is_selected {
            BG_SELECTED
        } else if is_cursor {
            BG_CURSOR
        } else if is_changed {
            BG_CHANGED
        } else {
            BG_DEFAULT
        };

        let cell_w = glyph_w;
        let (rect, resp) = ui.allocate_exact_size(
            Vec2::new(cell_w, line_h),
            egui::Sense::click_and_drag(),
        );

        if ui.is_rect_visible(rect) {
            ui.painter().rect_filled(rect, egui::Rounding::ZERO, bg);
            ui.painter().text(
                rect.center(),
                egui::Align2::CENTER_CENTER,
                &ch.to_string(),
                view.font.clone(),
                text_color,
            );
            if is_cursor {
                let y = rect.bottom() - 1.0;
                ui.painter().line_segment(
                    [egui::pos2(rect.left(), y), egui::pos2(rect.right(), y)],
                    egui::Stroke::new(1.5, Color32::WHITE),
                );
            }
        }

        if resp.clicked() {
            if ui.input(|i| i.modifiers.shift) {
                view.extend_selection_to(offset);
            } else {
                view.set_cursor(offset);
            }
        }
        if resp.double_clicked() {
            view.set_cursor(offset);
            view.enter_edit_mode();
        }
        if resp.drag_started() {
            view.start_drag(offset);
        }
        if resp.dragged() {
            view.continue_drag(offset);
        }

        // Type an ASCII character to overwrite the byte
        if is_cursor && !view.edit_mode {
            let events = ui.ctx().input(|i| i.events.clone());
            if !events.is_empty() {
                for event in &events {
                    if let egui::Event::Text(t) = event {
                        if t.len() == 1 {
                            let c = t.chars().next().unwrap();
                            if c.is_ascii() && !c.is_control() {
                                let b = c as u8;
                                let start = view.start_address.offset;
                                let idx = (offset - start) as usize;
                                if idx < view.bytes.len() {
                                    if !view.original_bytes.contains_key(&offset) {
                                        view.original_bytes
                                            .insert(offset, view.bytes[idx]);
                                    }
                                    view.bytes[idx] = b;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

// =============================================================================
// Keyboard navigation
// =============================================================================

fn handle_keyboard(view: &mut BytesView, ui: &mut Ui) {
    // Guard: don't handle raw view keys while goto dialog or edit is active.
    if view.show_goto {
        return;
    }

    // Let edit-mode keys be processed by the inline TextEdit, except Escape
    // which we handle globally to cancel edit.
    if view.edit_mode {
        if ui.input(|i| i.key_pressed(Key::Escape)) {
            view.cancel_edit();
        }
        return;
    }

    let input = ui.input(|i| i.clone());

    // ---- arrow navigation ---------------------------------------------------
    if input.key_pressed(Key::ArrowUp) {
        view.cursor_up();
    }
    if input.key_pressed(Key::ArrowDown) {
        view.cursor_down();
    }
    if input.key_pressed(Key::ArrowLeft) {
        view.cursor_left();
    }
    if input.key_pressed(Key::ArrowRight) {
        view.cursor_right();
    }

    // ---- page up / down -----------------------------------------------------
    if input.key_pressed(Key::PageUp) {
        let rows = view.visible_rows as u64;
        let dec = rows * view.bytes_per_row as u64;
        let lo = view.start_address.offset;
        view.cursor_offset = if view.cursor_offset > lo + dec {
            view.cursor_offset - dec
        } else {
            lo
        };
        view.set_cursor(view.cursor_offset);
        view.page_up();
    }
    if input.key_pressed(Key::PageDown) {
        let rows = view.visible_rows as u64;
        let inc = rows * view.bytes_per_row as u64;
        let hi = view.end_offset();
        view.cursor_offset = (view.cursor_offset + inc).min(hi.saturating_sub(1));
        view.set_cursor(view.cursor_offset);
        view.page_down();
    }

    // ---- home / end ---------------------------------------------------------
    if input.key_pressed(Key::Home) {
        view.cursor_offset = view.start_address.offset;
        view.set_cursor(view.cursor_offset);
        view.scroll_offset = 0;
    }
    if input.key_pressed(Key::End) {
        view.cursor_offset = view.end_offset().saturating_sub(1);
        view.set_cursor(view.cursor_offset);
        view.scroll_into_view();
    }

    // ---- Enter -> edit mode -------------------------------------------------
    if input.key_pressed(Key::Enter) && !input.modifiers.ctrl {
        view.enter_edit_mode();
    }

    // ---- Delete / Backspace -> zero the byte --------------------------------
    if input.key_pressed(Key::Delete) || input.key_pressed(Key::Backspace) {
        let off = view.cursor_offset;
        let start = view.start_address.offset;
        if off >= start {
            let idx = (off - start) as usize;
            if idx < view.bytes.len() {
                if !view.original_bytes.contains_key(&off) {
                    view.original_bytes.insert(off, view.bytes[idx]);
                }
                view.bytes[idx] = 0;
            }
        }
    }

    // ---- Ctrl+G -> goto dialog ----------------------------------------------
    if input.key_pressed(Key::G) && input.modifiers.ctrl {
        view.show_goto = !view.show_goto;
        if view.show_goto {
            view.goto_buffer = format!("{:08X}", view.cursor_offset);
        }
    }

    // ---- Ctrl+F -> search ---------------------------------------------------
    if input.key_pressed(Key::F) && input.modifiers.ctrl {
        view.show_search = !view.show_search;
        if !view.show_search {
            view.search_results.clear();
            view.search_current = 0;
            view.search_pattern.clear();
        }
    }

    // ---- Ctrl+C -> copy hex -------------------------------------------------
    if input.key_pressed(Key::C) && input.modifiers.ctrl && !input.modifiers.shift
    {
        let s = view.copy_as_hex();
        ui.ctx().output_mut(|o| o.copied_text = s.clone());
        view.last_copy = "Copied hex (Ctrl+C)".into();
    }

    // ---- Ctrl+Shift+C -> copy C array ---------------------------------------
    if input.key_pressed(Key::C) && input.modifiers.ctrl && input.modifiers.shift
    {
        let s = view.copy_as_c_array();
        ui.ctx().output_mut(|o| o.copied_text = s.clone());
        view.last_copy = "Copied C array".into();
    }

    // ---- Hex digit typing -> inline edit ------------------------------------
    let hex_digit = input.events.iter().find_map(|ev| {
        if let egui::Event::Text(t) = ev {
            if t.len() == 1 {
                let c = t.chars().next().unwrap();
                if c.is_ascii_hexdigit() && !input.modifiers.ctrl {
                    return Some(c.to_ascii_uppercase());
                }
            }
        }
        None
    });

    if let Some(c) = hex_digit {
        view.enter_edit_mode();
        view.edit_buffer = format!("{}", c);
    }

    // ---- F3 -> search next/prev ---------------------------------------------
    if input.key_pressed(Key::F3) {
        if view.show_search && !view.search_results.is_empty() {
            if input.modifiers.shift {
                view.search_prev();
            } else {
                view.search_next();
            }
        }
    }

    // ---- Escape -> clear selection / close search ---------------------------
    if input.key_pressed(Key::Escape) {
        if view.show_search {
            view.show_search = false;
            view.search_results.clear();
            view.search_current = 0;
            view.search_pattern.clear();
        } else {
            view.selection = None;
            view.set_cursor(view.cursor_offset);
        }
    }
}

// =============================================================================
// Helpers
// =============================================================================

/// Compute the total pixel width of the hex column.
///
/// Layout per byte: 2 glyphs (hex digits) + 1 glyph (inter-byte space).
/// Between groups one extra glyph is added.  The last byte has no trailing
/// space, so the formulas subtract 1 glyph for that case.
///
/// Full-row width formula (n bytes, g = group_size):
///   - cells:        n * 2
///   - inter-byte:   (n - 1) * 1
///   - group-sep:    ((n - 1) / g) * 1       (group boundaries *inside* the row)
///   Total glyphs  = 3*n - 1 + (n - 1) / g
fn hex_column_width(view: &BytesView, glyph_w: f32) -> f32 {
    if view.column_widths.1 > 0.0 {
        return view.column_widths.1;
    }
    let n = view.bytes_per_row;
    if n == 0 {
        return 0.0;
    }
    let g = view.group_size.max(1);
    // group boundaries among n bytes = indices 1..n-1 that are multiples of g
    let group_seps = (n.saturating_sub(1)) / g;
    let glyphs = 3 * n - 1 + group_seps;
    glyphs as f32 * glyph_w
}

/// Compute the actual pixel width consumed by `m` rendered bytes in a
/// horizontal layout.  Uses the same arithmetic as [`hex_column_width`].
fn used_hex_width(m: usize, group_size: usize, glyph_w: f32) -> f32 {
    if m == 0 {
        return 0.0;
    }
    let g = group_size.max(1);
    let group_seps = (m.saturating_sub(1)) / g;
    let glyphs = 3 * m - 1 + group_seps;
    glyphs as f32 * glyph_w
}

/// Approximate monospace character width for a given font.
fn char_width(ui: &Ui, font: &egui::FontId) -> f32 {
    ui.fonts(|f| f.glyph_width(font, '0'))
        .max(6.0)
}
