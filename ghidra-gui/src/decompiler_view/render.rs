//! Renderer for the decompiler view.
//!
//! Renders C pseudocode with syntax highlighting, line numbers, code folding,
//! bracket matching, selection, hover tooltips, click navigation, and
//! scroll synchronization with the listing view.
//!
//! ## Layout
//!
//! The decompiler view is laid out in three horizontal bands:
//! 1. **Gutter** (left): line numbers, fold `[+]/[-]` toggles
//! 2. **Code area** (center): token-based syntax-highlighted text
//! 3. **Address comments** (right, optional): address annotations
//!
//! Each line is rendered as a row with a fixed height. Only visible
//! (non-folded) lines are rendered.

use super::{
    token_color, token_is_bold, token_is_italic, token_is_underline, CTokenKind,
    DecompilerNavigation, DecompilerViewState, SyntaxTheme, TextPosition, TextRange,
    TokenNavigation,
};
use egui::{
    Align2, Color32, CursorIcon, FontId, Id, Key, Modifiers, Pos2, Rect, RichText,
    ScrollArea, Sense, Stroke, Ui, Vec2,
};
use ghidra_core::addr::Address;

// ============================================================================
// Layout Constants
// ============================================================================

/// Height of a single code line in pixels.
const ROW_HEIGHT: f32 = 18.0;

/// Width of the gutter area (line numbers + fold indicators).
const GUTTER_WIDTH: f32 = 64.0;

/// Width of the line number sub-area within the gutter.
const LINE_NUMBER_WIDTH: f32 = 40.0;

/// Width of the fold indicator sub-area within the gutter.
const FOLD_INDICATOR_WIDTH: f32 = 20.0;

/// Horizontal padding inside the code area.
const CODE_PADDING_X: f32 = 8.0;

/// Height of the header bar.
const HEADER_HEIGHT: f32 = 26.0;

/// Maximum number of lines to render in a single frame.
/// Used for performance when dealing with very large files.
const MAX_VISIBLE_LINES: usize = 5000;

// ============================================================================
// Public Entry Point
// ============================================================================

/// Render the complete decompiler view into the given egui UI.
///
/// This is the main entry point called from the application. It renders
/// the header bar, the code area with gutter and syntax highlighting,
/// and handles all interaction (clicks, keyboard, hover, selection).
pub fn render_decompiler_view(state: &mut DecompilerViewState, ui: &mut Ui) {
    // Reset pending navigation each frame
    state.pending_navigation = None;

    // Render the header bar
    render_header(state, ui);

    // Render the main code area
    render_code_area(state, ui);

    // Handle keyboard shortcuts
    handle_keyboard(state, ui);
}

// ============================================================================
// Header Bar
// ============================================================================

/// Render the decompiler view header showing the function name, theme
/// toggle, font size control, and other options.
fn render_header(state: &mut DecompilerViewState, ui: &mut Ui) {
    let theme = state.syntax_theme.clone();
    let available = ui.available_size_before_wrap();

    // Header background
    let header_rect = Rect::from_min_size(
        ui.next_widget_position(),
        Vec2::new(available.x, HEADER_HEIGHT),
    );
    ui.painter().rect_filled(header_rect, 0.0, theme.header_bg);
    ui.painter().line_segment(
        [header_rect.left_bottom(), header_rect.right_bottom()],
        Stroke::new(1.0, theme.gutter_bg),
    );

    let (rect, _) = ui.allocate_exact_size(Vec2::new(available.x, HEADER_HEIGHT), Sense::hover());
    let mut header_ui = ui.new_child(egui::UiBuilder::new().max_rect(rect).layout(*ui.layout()));

    header_ui.horizontal(|ui| {
        // Function name
        if let Some(ref func_name) = state.current_function {
            ui.label(
                RichText::new(format!("Decompiler: {}", func_name))
                    .color(theme.header_text)
                    .strong()
                    .size(13.0)
                    .monospace(),
            );
        } else {
            ui.label(
                RichText::new("Decompiler View")
                    .color(theme.header_text)
                    .strong()
                    .size(13.0)
                    .monospace(),
            );
        }

        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            // Font size
            ui.label(RichText::new("Font:").color(theme.header_text).size(11.0));
            if ui
                .add(
                    egui::DragValue::new(&mut state.font_size)
                        .range(8.0..=24.0)
                        .speed(0.5)
                        .fixed_decimals(0),
                )
                .changed()
            {
                // Clamp font size
                state.font_size = state.font_size.clamp(8.0, 24.0);
            }

            ui.separator();

            // Address comments toggle
            ui.checkbox(&mut state.show_address_comments, "Addrs");

            // Line numbers toggle
            ui.checkbox(&mut state.show_line_numbers, "Lines");

            ui.separator();

            // Theme toggle button
            if ui
                .add_sized(
                    [60.0, 18.0],
                    egui::Button::new(RichText::new("Theme").size(11.0)),
                )
                .clicked()
            {
                // Toggle between dark and light
                let bg = state.syntax_theme.background;
                if bg.r() < 128 {
                    state.syntax_theme = SyntaxTheme::light();
                } else {
                    state.syntax_theme = SyntaxTheme::dark();
                }
            }

            // Fold controls
            if ui
                .add_sized(
                    [50.0, 18.0],
                    egui::Button::new(RichText::new("Fold").size(11.0)),
                )
                .clicked()
            {
                state.fold_all();
            }

            if ui
                .add_sized(
                    [60.0, 18.0],
                    egui::Button::new(RichText::new("Unfold").size(11.0)),
                )
                .clicked()
            {
                state.unfold_all();
            }
        });
    });
}

// ============================================================================
// Code Area (Main Body)
// ============================================================================

/// Render the main code display area with gutter and tokenized lines.
fn render_code_area(state: &mut DecompilerViewState, ui: &mut Ui) {
    let theme = state.syntax_theme.clone();

    // Paint background
    let available = ui.available_size_before_wrap();
    let bg_rect = Rect::from_min_size(
        ui.next_widget_position(),
        Vec2::new(available.x, available.y),
    );
    ui.painter().rect_filled(bg_rect, 0.0, theme.background);

    if state.tokens.is_empty() {
        ui.centered_and_justified(|ui| {
            ui.label(
                RichText::new("No decompiled code available")
                    .color(theme.comment_color)
                    .monospace()
                    .size(state.font_size),
            );
        });
        return;
    }

    // Compute visible lines (accounting for folding)
    let visible_lines: Vec<usize> = (0..state.tokens.len())
        .filter(|&line| state.is_line_visible(line))
        .collect();

    let total_visible = visible_lines.len().min(MAX_VISIBLE_LINES);
    let total_height = total_visible as f32 * ROW_HEIGHT;

    // Allocate the scroll area
    let scroll_id = ui.make_persistent_id("decompiler_scroll");
    let scroll_area = ScrollArea::vertical()
        .id_salt(scroll_id)
        .auto_shrink([false; 2])
        .drag_to_scroll(true);

    // Apply stored scroll offset if not user-scrolled
    let scroll_output = scroll_area.show(ui, |ui| {
        // Allocate total content height
        let desired = Vec2::new(
            ui.available_width(),
            total_height.max(ui.available_height()),
        );
        let (_content_rect, _) = ui.allocate_exact_size(desired, Sense::click());

        // Track scroll state
        let clip_rect = ui.clip_rect();
        let scroll_offset_y = clip_rect.top() - ui.min_rect().top();
        state.scroll_offset = scroll_offset_y.max(0.0);

        // Determine visible range
        let first_visible_line = (scroll_offset_y / ROW_HEIGHT) as usize;
        let visible_line_count = (ui.available_height() / ROW_HEIGHT) as usize + 2;
        let last_visible_line = (first_visible_line + visible_line_count).min(total_visible);

        // Render each visible line
        for vis_idx in first_visible_line..last_visible_line {
            if vis_idx >= visible_lines.len() {
                break;
            }
            let line_idx = visible_lines[vis_idx];
            if line_idx >= state.tokens.len() {
                break;
            }

            let y_pos = vis_idx as f32 * ROW_HEIGHT;
            render_code_line(state, line_idx, vis_idx, y_pos, ui);
        }

        // Handle mouse wheel for scroll detection
        state.user_scrolled = ui.input(|i| i.smooth_scroll_delta.y != 0.0);
    });

    // Track whether the user is actively scrolling vs programmatic
    if scroll_output.state.velocity().y.abs() > 0.1 {
        state.user_scrolled = true;
    }
}

// ============================================================================
// Single Line Rendering
// ============================================================================

/// Render a single line of decompiled code with gutter, tokens, and
/// optional address comment.
fn render_code_line(
    state: &mut DecompilerViewState,
    line_idx: usize,
    _vis_idx: usize,
    y_pos: f32,
    ui: &mut Ui,
) {
    let theme = state.syntax_theme.clone();
    let tokens = state.tokens[line_idx].clone();
    let is_cursor_line = line_idx == state.cursor_line;

    // Line rect for background and interaction
    let x_start = ui.min_rect().left();
    let line_width = ui.available_width();
    let line_rect = Rect::from_min_size(
        Pos2::new(x_start, ui.min_rect().top() + y_pos),
        Vec2::new(line_width, ROW_HEIGHT),
    );

    // --- Background painting ---
    // Cursor line highlight
    if is_cursor_line {
        ui.painter()
            .rect_filled(line_rect, 0.0, theme.cursor_line_bg);
    }

    // Selection highlight (per-token granularity)
    paint_selection_background(state, line_idx, line_rect, ui);

    // Highlighted variable background
    paint_variable_highlights(state, &tokens, line_rect, ui);

    // --- Gutter (line numbers + fold indicators) ---
    let gutter_rect = Rect::from_min_size(
        Pos2::new(x_start, line_rect.top()),
        Vec2::new(GUTTER_WIDTH, ROW_HEIGHT),
    );
    ui.painter().rect_filled(gutter_rect, 0.0, theme.gutter_bg);

    // Vertical separator between gutter and code
    ui.painter().line_segment(
        [
            Pos2::new(x_start + GUTTER_WIDTH, line_rect.top()),
            Pos2::new(x_start + GUTTER_WIDTH, line_rect.bottom()),
        ],
        Stroke::new(1.0, Color32::from_rgb(60, 60, 70)),
    );

    // Line number
    if state.show_line_numbers {
        let ln_text = format!("{:>4}", line_idx + 1);
        let ln_pos = Pos2::new(
            x_start + 4.0,
            line_rect.top() + (ROW_HEIGHT - state.font_size) / 2.0,
        );
        ui.painter().text(
            ln_pos,
            Align2::LEFT_TOP,
            ln_text,
            FontId::monospace(state.font_size),
            theme.line_number_color,
        );
    }

    // Fold indicator
    render_fold_indicator(state, line_idx, x_start, line_rect.top(), ui);

    // --- Code area ---
    let code_x = x_start + GUTTER_WIDTH + CODE_PADDING_X;
    let code_width = line_width - GUTTER_WIDTH - CODE_PADDING_X;

    // Check for address comment column
    let addr_col_width = if state.show_address_comments {
        120.0
    } else {
        0.0
    };
    let actual_code_width = code_width - addr_col_width;

    // Render tokens with syntax coloring
    render_tokens(
        state,
        &tokens,
        line_idx,
        code_x,
        line_rect.top(),
        actual_code_width,
        ui,
    );

    // Address comment
    if state.show_address_comments {
        if let Some(Some(addr)) = state.line_addresses.get(line_idx) {
            let addr_text = format!("// @ {:08X}", addr.offset);
            let addr_pos = Pos2::new(
                code_x + actual_code_width + 8.0,
                line_rect.top() + (ROW_HEIGHT - state.font_size) / 2.0,
            );
            ui.painter().text(
                addr_pos,
                Align2::LEFT_TOP,
                addr_text,
                FontId::monospace(state.font_size * 0.85),
                theme.comment_color,
            );
        }
    }

    // --- Bracket matching highlight ---
    paint_bracket_highlights(state, line_idx, line_rect, ui);

    // --- Line-level interaction ---
    let line_response = ui.interact(
        line_rect,
        Id::new(("decomp_line", line_idx)),
        Sense::click(),
    );

    // Click on line background: set cursor
    if line_response.clicked() {
        let click_pos = line_response.interact_pointer_pos();
        if let Some(pos) = click_pos {
            let col = col_from_x(pos.x - code_x, &tokens, state.font_size);
            state.set_cursor(line_idx, col);
        } else {
            state.set_cursor(line_idx, 0);
        }
    }

    // Double click on line: navigate to its address
    if line_response.double_clicked() {
        if let Some(nav) = state.handle_double_click(line_idx) {
            state.pending_navigation = Some(nav);
        }
    }
}

// ============================================================================
// Gutter Fold Indicator
// ============================================================================

/// Render the `[-]` or `[+]` fold toggle in the gutter for foldable lines.
fn render_fold_indicator(
    state: &mut DecompilerViewState,
    line_idx: usize,
    x_start: f32,
    y_top: f32,
    ui: &mut Ui,
) {
    let theme = &state.syntax_theme;

    // Check if this line starts a foldable region
    let is_fold_start = state.fold_regions.iter().any(|r| r.start_line == line_idx);
    let is_folded = state.folded_regions.contains(&line_idx);

    if !is_fold_start {
        // Check if this is a closing-brace line — show a subtle indicator
        let has_closing = state.tokens.get(line_idx).map_or(false, |tokens| {
            tokens
                .iter()
                .any(|t| t.bracket_is_close && t.bracket_char == Some('}'))
        });
        if has_closing {
            let indicator = "\u{2514}"; // box-drawing: L-shape
            let fold_x = x_start + LINE_NUMBER_WIDTH + 4.0;
            let pos = Pos2::new(fold_x, y_top + (ROW_HEIGHT - state.font_size) / 2.0);
            ui.painter().text(
                pos,
                Align2::LEFT_TOP,
                indicator,
                FontId::monospace(state.font_size * 0.7),
                theme.line_number_color,
            );
        }
        return;
    }

    let fold_x = x_start + LINE_NUMBER_WIDTH + 2.0;
    let fold_rect = Rect::from_min_size(
        Pos2::new(fold_x, y_top),
        Vec2::new(FOLD_INDICATOR_WIDTH, ROW_HEIGHT),
    );

    let fold_text = if is_folded { "[+]" } else { "[-]" };
    let fold_color = if is_folded {
        Color32::from_rgb(100, 180, 255)
    } else {
        theme.line_number_color
    };

    // Paint the indicator text
    let pos = Pos2::new(fold_x, y_top + (ROW_HEIGHT - state.font_size) / 2.0);
    ui.painter().text(
        pos,
        Align2::LEFT_TOP,
        fold_text,
        FontId::monospace(state.font_size * 0.75),
        fold_color,
    );

    // Make clickable
    let fold_response = ui.interact(
        fold_rect,
        Id::new(("fold_toggle", line_idx)),
        Sense::click(),
    );
    if fold_response.clicked() {
        state.toggle_fold(line_idx);
    }
    if fold_response.hovered() {
        ui.ctx().set_cursor_icon(CursorIcon::PointingHand);
    }
}

// ============================================================================
// Token Rendering
// ============================================================================

/// Render all tokens on a line with syntax coloring and interaction.
fn render_tokens(
    state: &mut DecompilerViewState,
    tokens: &[super::CToken],
    line_idx: usize,
    code_x: f32,
    y_top: f32,
    _max_width: f32,
    ui: &mut Ui,
) {
    let theme = state.syntax_theme.clone();
    let font_size = state.font_size;
    let font_id = FontId::monospace(font_size);
    let char_width = estimate_char_width(font_size);

    let mut x = code_x;
    let y_text = y_top + (ROW_HEIGHT - font_size) / 2.0;

    for token in tokens {
        if token.kind == CTokenKind::Whitespace {
            // Advance cursor by the whitespace width
            let ws_width = token.text.len() as f32 * char_width;
            x += ws_width;
            continue;
        }

        let text = &token.text;
        let text_width = text.len() as f32 * char_width;

        // Skip if token is entirely off-screen to the left
        if x + text_width < ui.min_rect().left() {
            x += text_width;
            continue;
        }

        // Skip if token is entirely off-screen to the right
        if x > ui.min_rect().right() {
            break;
        }

        // Get display color
        let color = token_color(token.kind, &theme);
        let is_bold = token_is_bold(token.kind);
        let is_italic = token_is_italic(token.kind);
        let is_underline = token_is_underline(token.kind);

        // Check if this token is a bracket match
        let is_bracket_match = is_bracket_at_match(state, line_idx, token);

        // Build the display style
        let display_color = if is_bracket_match {
            theme.bracket_match_border
        } else {
            color
        };

        // For clickable tokens, draw underline
        let draw_underline = is_underline || token.navigation != TokenNavigation::None;

        // Paint the token text
        let pos = Pos2::new(x, y_text);
        let token_font = if is_bold && is_italic {
            FontId::monospace(font_size)
        } else if is_bold {
            FontId::monospace(font_size)
        } else if is_italic {
            FontId::monospace(font_size)
        } else {
            font_id.clone()
        };

        ui.painter()
            .text(pos, Align2::LEFT_TOP, text, token_font.clone(), display_color);

        // Draw underline for clickable tokens
        if draw_underline {
            let underline_y = y_text + font_size + 1.0;
            ui.painter().line_segment(
                [
                    Pos2::new(x, underline_y),
                    Pos2::new(x + text_width, underline_y),
                ],
                Stroke::new(1.0, display_color),
            );
        }

        // Create an interaction rect for this token
        let token_rect =
            Rect::from_min_size(Pos2::new(x, y_top), Vec2::new(text_width, ROW_HEIGHT));

        let token_id = Id::new(("decomp_token", line_idx, token.col, token.text.clone()));
        let sense = if token.navigation != TokenNavigation::None
            || token.kind == CTokenKind::FunctionName
            || token.kind == CTokenKind::Identifier
            || token.kind == CTokenKind::LabelDef
            || token.kind == CTokenKind::AddressRef
        {
            Sense::click()
        } else {
            Sense::hover()
        };

        let token_response = ui.interact(token_rect, token_id, sense);

        // Click handler
        if token_response.clicked() {
            let col = token.col;
            let nav = state.handle_click(line_idx, col);
            if let Some(nav) = nav {
                state.pending_navigation = Some(nav);
            }
        }

        // Cursor change on hover for clickable tokens
        if token_response.hovered()
            && (token.navigation != TokenNavigation::None
                || token.kind == CTokenKind::AddressRef
                || token.kind == CTokenKind::FunctionName
                || token.kind == CTokenKind::LabelDef)
        {
            ui.ctx().set_cursor_icon(CursorIcon::PointingHand);
        }

        // Hover tooltip
        if token_response.hovered() {
            show_token_tooltip(state, token, ui);
        }

        // Drag for selection
        if token_response.drag_started() {
            let drag_col = token.col;
            state.selection = Some(TextRange::single(TextPosition::new(line_idx, drag_col)));
        }
        if token_response.dragged() {
            if let Some(pointer_pos) = ui.ctx().pointer_interact_pos() {
                let col = col_from_x(pointer_pos.x - code_x, tokens, font_size);
                let drag_line = line_idx; // approximate — could compute from y
                state.extend_selection(drag_line, col);
            }
        }

        x += text_width;
    }
}

// ============================================================================
// Background Painting Helpers
// ============================================================================

/// Paint the selection background for tokens on a line that fall within
/// the current text selection range.
fn paint_selection_background(
    state: &DecompilerViewState,
    line_idx: usize,
    line_rect: Rect,
    ui: &mut Ui,
) {
    let selection = match &state.selection {
        Some(sel) if sel.intersects_line(line_idx) => sel,
        _ => return,
    };

    let theme = &state.syntax_theme;
    let font_size = state.font_size;
    let char_width = estimate_char_width(font_size);

    let tokens = state.tokens[line_idx].clone();
    let code_x = line_rect.left() + GUTTER_WIDTH + CODE_PADDING_X;

    for token in tokens {
        if token.kind == CTokenKind::Whitespace {
            continue;
        }

        let tok_start = TextPosition::new(line_idx, token.col);
        let tok_end = TextPosition::new(line_idx, token.col + token.text.len());

        // Check if this token intersects the selection
        if tok_end <= selection.start || tok_start >= selection.end {
            continue;
        }

        // Compute the selection highlight rect for this token
        let sel_start_col = if selection.start.line == line_idx && selection.start.col > token.col {
            selection.start.col
        } else {
            token.col
        };
        let sel_end_col =
            if selection.end.line == line_idx && selection.end.col < token.col + token.text.len() {
                selection.end.col
            } else {
                token.col + token.text.len()
            };

        let x_start = code_x + (sel_start_col - token.col) as f32 * char_width;
        let highlight_width = (sel_end_col - sel_start_col) as f32 * char_width;
        let highlight_rect = Rect::from_min_size(
            Pos2::new(x_start, line_rect.top()),
            Vec2::new(highlight_width, ROW_HEIGHT),
        );

        ui.painter()
            .rect_filled(highlight_rect, 0.0, theme.selection_bg);
    }
}

/// Paint background highlights for all occurrences of the currently
/// highlighted variable name.
fn paint_variable_highlights(
    state: &DecompilerViewState,
    tokens: &[super::CToken],
    line_rect: Rect,
    ui: &mut Ui,
) {
    let var_name = match &state.highlighted_variable {
        Some(name) => name,
        None => return,
    };
    let theme = &state.syntax_theme;
    let code_x = line_rect.left() + GUTTER_WIDTH + CODE_PADDING_X;
    let font_size = state.font_size;
    let char_width = estimate_char_width(font_size);

    for token in tokens {
        if token.kind == CTokenKind::Whitespace {
            continue;
        }
        if &token.text != var_name {
            continue;
        }
        if token.kind != CTokenKind::Identifier && token.kind != CTokenKind::FunctionName {
            continue;
        }

        // Highlight this occurrence
        let x_start = code_x + token.col as f32 * char_width;
        let width = token.text.len() as f32 * char_width;
        let hl_rect = Rect::from_min_size(
            Pos2::new(x_start, line_rect.top()),
            Vec2::new(width, ROW_HEIGHT),
        );
        ui.painter().rect_filled(hl_rect, 0.0, theme.highlight_bg);
    }
}

// ============================================================================
// Bracket Matching Highlight
// ============================================================================

/// Check if the token at the given position is one end of a bracket pair
/// that contains the cursor.
fn is_bracket_at_match(state: &DecompilerViewState, line: usize, token: &super::CToken) -> bool {
    if !token.is_bracket {
        return false;
    }
    let pos = TextPosition::new(line, token.col);
    let cursor_pos = TextPosition::new(state.cursor_line, state.cursor_col);

    // Check if cursor is on this bracket or its pair
    for pair in &state.bracket_pairs {
        if (pair.open == cursor_pos || pair.close == cursor_pos)
            && (pair.open == pos || pair.close == pos)
        {
            return true;
        }
    }
    false
}

/// Paint bracket match highlights for both ends of a bracket pair when
/// the cursor is at one end.
fn paint_bracket_highlights(
    state: &DecompilerViewState,
    line_idx: usize,
    line_rect: Rect,
    ui: &mut Ui,
) {
    let theme = &state.syntax_theme;
    let font_size = state.font_size;
    let char_width = estimate_char_width(font_size);
    let code_x = line_rect.left() + GUTTER_WIDTH + CODE_PADDING_X;

    let cursor_pos = TextPosition::new(state.cursor_line, state.cursor_col);

    for pair in &state.bracket_pairs {
        if pair.open != cursor_pos && pair.close != cursor_pos {
            continue;
        }

        // Highlight both brackets
        for bracket_pos in &[pair.open, pair.close] {
            if bracket_pos.line != line_idx {
                continue;
            }

            let x_pos = code_x + bracket_pos.col as f32 * char_width;
            let bracket_rect = Rect::from_min_size(
                Pos2::new(x_pos, line_rect.top()),
                Vec2::new(char_width, ROW_HEIGHT),
            );

            // Filled background
            ui.painter()
                .rect_filled(bracket_rect, 0.0, theme.bracket_match_bg);

            // Border outline
            ui.painter().rect_stroke(
                bracket_rect,
                0.0,
                Stroke::new(1.5, theme.bracket_match_border),
            );
        }
    }
}

// ============================================================================
// Hover Tooltips
// ============================================================================

/// Show a hover tooltip for a token with relevant information.
fn show_token_tooltip(state: &DecompilerViewState, token: &super::CToken, ui: &mut Ui) {
    let tooltip_text = match &token.navigation {
        TokenNavigation::Address(addr) => {
            format!(
                "Address: {:08X}\nClick to navigate to this address",
                addr.offset
            )
        }
        TokenNavigation::Function(name) => {
            format!("Function: {}\nClick to navigate to definition", name)
        }
        TokenNavigation::Label(name) => {
            format!("Label: {}\nClick to jump to label definition", name)
        }
        TokenNavigation::Variable(name) => {
            if state.variables.contains_key(name) {
                let count = state.variables[name].occurrences.len();
                format!(
                    "Variable: {}\n{} occurrence{}\nClick to highlight all uses",
                    name,
                    count,
                    if count == 1 { "" } else { "s" }
                )
            } else {
                format!("Identifier: {}", name)
            }
        }
        TokenNavigation::None => match token.kind {
            CTokenKind::FunctionName => {
                format!("Function: {}\nClick to navigate", token.text)
            }
            CTokenKind::Identifier => {
                if state.variables.contains_key(&token.text) {
                    let count = state.variables[&token.text].occurrences.len();
                    format!(
                        "Variable: {}\n{} occurrence{}\nClick to highlight all uses",
                        token.text,
                        count,
                        if count == 1 { "" } else { "s" }
                    )
                } else {
                    format!("Identifier: {}", token.text)
                }
            }
            CTokenKind::LabelDef => {
                format!("Label: {}\nClick to navigate", token.text)
            }
            CTokenKind::Number | CTokenKind::AddressRef => {
                format!(
                    "Constant: {}\nDecimal: {}",
                    token.text,
                    parse_decimal_if_hex(&token.text)
                )
            }
            CTokenKind::StringLiteral => {
                format!(
                    "String literal ({} chars)",
                    token.text.len().saturating_sub(2)
                )
            }
            CTokenKind::CharLiteral => {
                format!("Character literal")
            }
            CTokenKind::TypeName => {
                format!("Type: {}", token.text)
            }
            CTokenKind::Keyword => {
                format!("Keyword: {}", token.text)
            }
            _ => {
                format!("{}", token.text)
            }
        },
    };

    // Show address for this line if available
    let address_info = if let Some(Some(addr)) = state.line_addresses.get(token.line) {
        format!("\nLine address: {:08X}", addr.offset)
    } else {
        String::new()
    };

    let full_tooltip = format!("{}{}", tooltip_text, address_info);

    egui::show_tooltip_at_pointer(
        ui.ctx(),
        ui.layer_id(),
        Id::new(("token_tooltip", token.line, token.col)),
        |ui: &mut Ui| {
            ui.label(
                RichText::new(&full_tooltip)
                    .monospace()
                    .size(11.0)
                    .color(Color32::from_rgb(220, 220, 220)),
            );
        },
    );
}

/// Try to parse a hex number and show its decimal equivalent.
fn parse_decimal_if_hex(text: &str) -> String {
    if text.starts_with("0x") || text.starts_with("0X") {
        if let Ok(val) = u64::from_str_radix(&text[2..], 16) {
            return format!("{}", val);
        }
    }
    text.to_string()
}

// ============================================================================
// Keyboard Handling
// ============================================================================

/// Handle keyboard shortcuts and navigation within the decompiler view.
fn handle_keyboard(state: &mut DecompilerViewState, ui: &mut Ui) {
    let input = ui.input(|i| i.clone());
    let modifiers = input.modifiers;

    // --- Copy ---
    if modifiers.ctrl && input.key_pressed(Key::C) {
        state.copy_selection(ui);
    }

    // --- Select All ---
    if modifiers.ctrl && input.key_pressed(Key::A) {
        state.select_all();
    }

    // --- Arrow key navigation ---
    if input.key_pressed(Key::ArrowDown) {
        move_cursor_down(state, modifiers);
    }
    if input.key_pressed(Key::ArrowUp) {
        move_cursor_up(state, modifiers);
    }
    if input.key_pressed(Key::ArrowRight) {
        move_cursor_right(state, modifiers);
    }
    if input.key_pressed(Key::ArrowLeft) {
        move_cursor_left(state, modifiers);
    }

    // --- Page Up/Down ---
    if input.key_pressed(Key::PageDown) {
        let page_lines = 20;
        let new_line = (state.cursor_line + page_lines).min(state.tokens.len().saturating_sub(1));
        if modifiers.shift {
            state.extend_selection(new_line, state.cursor_col);
        } else {
            state.set_cursor(new_line, 0);
        }
    }
    if input.key_pressed(Key::PageUp) {
        let page_lines = 20;
        let new_line = state.cursor_line.saturating_sub(page_lines);
        if modifiers.shift {
            state.extend_selection(new_line, state.cursor_col);
        } else {
            state.set_cursor(new_line, 0);
        }
    }

    // --- Home / End ---
    if input.key_pressed(Key::Home) {
        if modifiers.ctrl {
            // Ctrl+Home: go to first line
            if modifiers.shift {
                state.extend_selection(0, 0);
            } else {
                state.set_cursor(0, 0);
            }
        } else {
            // Home: go to start of line (first non-whitespace)
            let line_tokens = state
                .tokens
                .get(state.cursor_line)
                .map(|t| t.as_slice())
                .unwrap_or(&[]);
            let first_col = line_tokens
                .iter()
                .find(|t| t.kind != CTokenKind::Whitespace)
                .map(|t| t.col)
                .unwrap_or(0);
            if modifiers.shift {
                state.extend_selection(state.cursor_line, first_col);
            } else {
                state.set_cursor(state.cursor_line, first_col);
            }
        }
    }
    if input.key_pressed(Key::End) {
        if modifiers.ctrl {
            // Ctrl+End: go to last line
            let last_line = state.tokens.len().saturating_sub(1);
            if modifiers.shift {
                state.extend_selection(last_line, 0);
            } else {
                state.set_cursor(last_line, 0);
            }
        } else {
            // End: go to end of line
            let line_tokens = state
                .tokens
                .get(state.cursor_line)
                .map(|t| t.as_slice())
                .unwrap_or(&[]);
            let last_col = line_tokens
                .last()
                .map(|t| t.col + t.text.len())
                .unwrap_or(0);
            if modifiers.shift {
                state.extend_selection(state.cursor_line, last_col);
            } else {
                state.set_cursor(state.cursor_line, last_col);
            }
        }
    }

    // --- Escape: clear selection ---
    if input.key_pressed(Key::Escape) {
        if state.selection.is_some() {
            state.clear_selection();
        } else if state.highlighted_variable.is_some() {
            state.highlighted_variable = None;
        }
    }

    // --- Enter: navigate to function/label/address at cursor ---
    if input.key_pressed(Key::Enter) {
        if let Some(token) = state.token_at_cursor() {
            if let Some(nav) = match &token.navigation {
                TokenNavigation::Address(addr) => {
                    Some(DecompilerNavigation::NavigateToAddress(*addr))
                }
                TokenNavigation::Function(name) => {
                    Some(DecompilerNavigation::NavigateToFunction(name.clone()))
                }
                TokenNavigation::Label(name) => {
                    Some(DecompilerNavigation::NavigateToLabel(name.clone()))
                }
                _ => None,
            } {
                state.pending_navigation = Some(nav);
            }
        }
    }

    // --- F: fold/unfold at cursor ---
    if modifiers.ctrl && input.key_pressed(Key::F) {
        state.toggle_fold(state.cursor_line);
    }

    // --- Ctrl+Shift+F: fold all ---
    if modifiers.ctrl && modifiers.shift && input.key_pressed(Key::F) {
        state.fold_all();
    }

    // --- Ctrl+Shift+U: unfold all ---
    if modifiers.ctrl && modifiers.shift && input.key_pressed(Key::U) {
        state.unfold_all();
    }
}

/// Move cursor down one visible line.
fn move_cursor_down(state: &mut DecompilerViewState, modifiers: Modifiers) {
    let visible: Vec<usize> = (0..state.tokens.len())
        .filter(|&l| state.is_line_visible(l))
        .collect();

    if let Some(pos) = visible.iter().position(|&l| l == state.cursor_line) {
        if pos + 1 < visible.len() {
            let new_line = visible[pos + 1];
            if modifiers.shift {
                state.extend_selection(new_line, state.cursor_col);
            } else {
                state.set_cursor(new_line, state.cursor_col);
            }
        }
    } else if !visible.is_empty() {
        // Cursor is on a hidden line; move to first visible
        if modifiers.shift {
            state.extend_selection(visible[0], 0);
        } else {
            state.set_cursor(visible[0], 0);
        }
    }
}

/// Move cursor up one visible line.
fn move_cursor_up(state: &mut DecompilerViewState, modifiers: Modifiers) {
    let visible: Vec<usize> = (0..state.tokens.len())
        .filter(|&l| state.is_line_visible(l))
        .collect();

    if let Some(pos) = visible.iter().position(|&l| l == state.cursor_line) {
        if pos > 0 {
            let new_line = visible[pos - 1];
            if modifiers.shift {
                state.extend_selection(new_line, state.cursor_col);
            } else {
                state.set_cursor(new_line, state.cursor_col);
            }
        }
    }
}

/// Move cursor one character to the right.
fn move_cursor_right(state: &mut DecompilerViewState, modifiers: Modifiers) {
    if state.cursor_line >= state.tokens.len() {
        return;
    }
    let line_tokens = &state.tokens[state.cursor_line];
    let max_col = line_tokens
        .last()
        .map(|t| t.col + t.text.len())
        .unwrap_or(0);

    if state.cursor_col < max_col {
        let new_col = state.cursor_col + 1;
        if modifiers.shift {
            state.extend_selection(state.cursor_line, new_col);
        } else {
            state.set_cursor(state.cursor_line, new_col);
        }
    } else if state.cursor_line + 1 < state.tokens.len() {
        // Move to start of next line
        if modifiers.shift {
            state.extend_selection(state.cursor_line + 1, 0);
        } else {
            state.set_cursor(state.cursor_line + 1, 0);
        }
    }
}

/// Move cursor one character to the left.
fn move_cursor_left(state: &mut DecompilerViewState, modifiers: Modifiers) {
    if state.cursor_col > 0 {
        let new_col = state.cursor_col - 1;
        if modifiers.shift {
            state.extend_selection(state.cursor_line, new_col);
        } else {
            state.set_cursor(state.cursor_line, new_col);
        }
    } else if state.cursor_line > 0 {
        // Move to end of previous line
        let prev_tokens = &state.tokens[state.cursor_line - 1];
        let last_col = prev_tokens
            .last()
            .map(|t| t.col + t.text.len())
            .unwrap_or(0);
        if modifiers.shift {
            state.extend_selection(state.cursor_line - 1, last_col);
        } else {
            state.set_cursor(state.cursor_line - 1, last_col);
        }
    }
}

// ============================================================================
// Utility Functions
// ============================================================================

/// Estimate the pixel width of a single monospace character at the given
/// font size. This is approximate but works well for the default egui
/// monospace fonts.
fn estimate_char_width(font_size: f32) -> f32 {
    // For typical monospace fonts, char width is ~0.6 * font_size
    font_size * 0.6
}

/// Convert an x-offset from the code area start to a column index within
/// the tokens on a line. Used for click-to-column resolution.
fn col_from_x(x: f32, tokens: &[super::CToken], font_size: f32) -> usize {
    let char_width = estimate_char_width(font_size);

    // Walk through tokens to find which column the x position maps to
    let mut current_x = 0.0f32;
    for token in tokens {
        let token_width = token.text.len() as f32 * char_width;
        if x >= current_x && x < current_x + token_width {
            // Click is within this token
            let char_offset = ((x - current_x) / char_width) as usize;
            return token.col + char_offset.min(token.text.len());
        }
        current_x += token_width;
    }

    // Click is past the end of the line
    if let Some(last) = tokens.last() {
        last.col + last.text.len()
    } else {
        0
    }
}

/// Get the width of a rendered token in pixels.
fn _token_pixel_width(token: &super::CToken, font_size: f32) -> f32 {
    let char_width = estimate_char_width(font_size);
    token.text.len() as f32 * char_width
}

/// Compute the total width of a line in pixels.
fn _line_pixel_width(tokens: &[super::CToken], font_size: f32) -> f32 {
    tokens.iter().map(|t| _token_pixel_width(t, font_size)).sum()
}

// ============================================================================
// Public Helper: Compute Visible Addresses
// ============================================================================

/// Return sorted list of (source_line, address) for all currently visible
/// lines.  Used by the application for scroll synchronization with the
/// listing view.
pub fn _visible_line_addresses(state: &DecompilerViewState) -> Vec<(usize, Address)> {
    let mut results = Vec::new();
    for line in 0..state.tokens.len() {
        if state.is_line_visible(line) {
            if let Some(Some(addr)) = state.line_addresses.get(line) {
                results.push((line, *addr));
            }
        }
    }
    results
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_estimate_char_width() {
        let w12 = estimate_char_width(12.0);
        let w16 = estimate_char_width(16.0);
        assert!(w12 > 0.0);
        assert!(w16 > w12);
    }

    #[test]
    fn test_line_pixel_width() {
        use super::super::{CToken, CTokenKind};
        let tokens = vec![
            CToken::new(CTokenKind::Keyword, "if", 0, 0),
            CToken::whitespace(" ", 0, 2),
            CToken::new(CTokenKind::Punctuation, "(", 0, 3),
            CToken::new(CTokenKind::Identifier, "x", 0, 4),
            CToken::new(CTokenKind::Punctuation, ")", 0, 5),
        ];
        let width = _line_pixel_width(&tokens, 12.0);
        assert!(width > 0.0);
    }
}
