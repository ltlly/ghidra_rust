//! Detailed C pseudocode renderer with syntax highlighting, bracket matching,
//! code folding, and navigation from C constructs to assembly addresses.
//!
//! Provides [`CDecompilerRenderer`], a full-featured decompiled-code view that
//! renders tokenized C pseudocode with per-token coloring, line-number gutters,
//! foldable brace blocks, highlighted bracket pairs, variable-use highlights,
//! and clickable cross-references to the listing view.
//!
//! ## Usage
//!
//! ```ignore
//! let mut renderer = CDecompilerRenderer::default();
//! let tokens: Vec<Vec<CToken>> = ...;
//! let fold_regions: Vec<FoldRegion> = ...;
//! renderer.render(ui, &tokens, &fold_regions);
//! ```

use super::{BracketKind, BracketPair, CToken, CTokenKind, FoldRegion, TokenNavigation};

use egui::{
    pos2, vec2, Align2, Color32, CursorIcon, FontId, Id, Key, Modifiers, Painter, Pos2, Rect,
    Response, RichText, Sense, Stroke, Ui, Vec2,
};
use ghidra_core::addr::Address;
use std::collections::HashSet;

// ============================================================================
// Constants
// ============================================================================

/// Default line height.
const LINE_HEIGHT: f32 = 18.0;

/// Gutter width for the fold indicators.
const FOLD_GUTTER_WIDTH: f32 = 24.0;

/// Gutter width for line numbers.
const LINE_NUMBER_GUTTER_WIDTH: f32 = 48.0;

/// Padding within the code area.
const CODE_PADDING_X: f32 = 6.0;

/// Padding inside the gutter.
const GUTTER_PADDING_X: f32 = 3.0;

/// Space character width estimate (monospace).
const CHAR_WIDTH: f32 = 8.4;

// ============================================================================
// CFonts
// ============================================================================

/// Font configuration for the decompiler renderer.
#[derive(Debug, Clone)]
pub struct CFonts {
    /// Default font for identifiers and general code.
    pub default: FontId,
    /// Bold font for keywords.
    pub bold: FontId,
    /// Italic font for comments.
    pub italic: FontId,
}

impl Default for CFonts {
    fn default() -> Self {
        Self {
            default: FontId::monospace(12.0),
            bold: FontId::new(12.0, egui::FontFamily::Monospace),
            italic: FontId::new(12.0, egui::FontFamily::Monospace),
        }
    }
}

impl CFonts {
    /// Create fonts at the given base size.
    pub fn with_size(size: f32) -> Self {
        Self {
            default: FontId::monospace(size),
            bold: FontId::new(size, egui::FontFamily::Monospace),
            italic: FontId::new(size, egui::FontFamily::Monospace),
        }
    }
}

// ============================================================================
// CColors
// ============================================================================

/// Color configuration for C pseudocode syntax highlighting.
///
/// Each field controls the color of a different syntactic category in the
/// decompiler output.
#[derive(Debug, Clone, Copy)]
pub struct CColors {
    /// C keywords: `if`, `else`, `while`, `for`, `return`, etc.
    pub keyword: Color32,
    /// Type names: `int`, `char`, `void`, `uint32_t`, etc.
    pub datatype: Color32,
    /// Identifiers: variable names, parameter names.
    pub identifier: Color32,
    /// Numeric literals: hex, decimal, octal.
    pub number: Color32,
    /// String literals: `"hello"`.
    pub string: Color32,
    /// Comments: `// ...`, `/* ... */`.
    pub comment: Color32,
    /// Operators: `+`, `-`, `*`, `&`, `->`, `<<=`, etc.
    pub operator: Color32,
    /// Punctuation delimiters: `;`, `,`, `(`, `)`, `{`, `}`, `[`, `]`.
    pub punctuation: Color32,
    /// Preprocessor directives: `#define`, `#include`, `#ifdef`, etc.
    pub preprocessor: Color32,
    /// Function names in call expressions and definitions.
    pub function: Color32,
    /// Variable names for highlight-on-click.
    pub variable: Color32,
    /// Function parameter names.
    pub parameter: Color32,
    /// Global variable names.
    pub global: Color32,
    /// Local variable names.
    pub local: Color32,
    /// Label definitions: `LAB_...:`.
    pub label: Color32,
    /// Goto label references.
    pub goto_label: Color32,

    // Background and UI colors
    /// Background color of the code area.
    pub background: Color32,
    /// Background color of the gutter (line numbers + fold indicators).
    pub gutter_background: Color32,
    /// Color for line-number text.
    pub line_number: Color32,
    /// Background for the current cursor line.
    pub cursor_line: Color32,
    /// Background for selected text.
    pub selection: Color32,
    /// Background for bracket match highlights.
    pub bracket_match_bg: Color32,
    /// Border for bracket match highlights.
    pub bracket_match_border: Color32,
    /// Background for variable-use highlights.
    pub highlight_bg: Color32,
}

impl Default for CColors {
    fn default() -> Self {
        Self::dark()
    }
}

impl CColors {
    /// Ghidra-inspired dark theme.
    pub fn dark() -> Self {
        Self {
            keyword: Color32::from_rgb(200, 120, 255),
            datatype: Color32::from_rgb(100, 200, 180),
            identifier: Color32::from_rgb(220, 220, 220),
            number: Color32::from_rgb(150, 220, 150),
            string: Color32::from_rgb(255, 180, 100),
            comment: Color32::from_rgb(100, 170, 100),
            operator: Color32::from_rgb(200, 200, 210),
            punctuation: Color32::from_rgb(210, 210, 220),
            preprocessor: Color32::from_rgb(180, 150, 120),
            function: Color32::from_rgb(220, 220, 100),
            variable: Color32::from_rgb(180, 220, 255),
            parameter: Color32::from_rgb(255, 200, 150),
            global: Color32::from_rgb(255, 220, 120),
            local: Color32::from_rgb(160, 220, 255),
            label: Color32::from_rgb(255, 200, 100),
            goto_label: Color32::from_rgb(255, 180, 80),

            background: Color32::from_rgb(30, 30, 35),
            gutter_background: Color32::from_rgb(40, 40, 46),
            line_number: Color32::from_rgb(120, 120, 130),
            cursor_line: Color32::from_rgba_premultiplied(255, 255, 100, 25),
            selection: Color32::from_rgba_premultiplied(80, 140, 255, 45),
            bracket_match_bg: Color32::from_rgba_premultiplied(255, 255, 100, 60),
            bracket_match_border: Color32::from_rgb(255, 255, 100),
            highlight_bg: Color32::from_rgba_premultiplied(100, 100, 255, 40),
        }
    }

    /// Light theme variant.
    pub fn light() -> Self {
        Self {
            keyword: Color32::from_rgb(140, 40, 180),
            datatype: Color32::from_rgb(0, 130, 130),
            identifier: Color32::from_rgb(30, 30, 30),
            number: Color32::from_rgb(0, 140, 0),
            string: Color32::from_rgb(160, 80, 0),
            comment: Color32::from_rgb(0, 130, 0),
            operator: Color32::from_rgb(80, 80, 90),
            punctuation: Color32::from_rgb(60, 60, 65),
            preprocessor: Color32::from_rgb(140, 100, 60),
            function: Color32::from_rgb(0, 0, 180),
            variable: Color32::from_rgb(20, 80, 160),
            parameter: Color32::from_rgb(140, 80, 0),
            global: Color32::from_rgb(160, 120, 0),
            local: Color32::from_rgb(0, 90, 150),
            label: Color32::from_rgb(180, 120, 0),
            goto_label: Color32::from_rgb(160, 100, 0),

            background: Color32::from_rgb(250, 250, 252),
            gutter_background: Color32::from_rgb(235, 235, 238),
            line_number: Color32::from_rgb(140, 140, 150),
            cursor_line: Color32::from_rgba_premultiplied(255, 255, 200, 60),
            selection: Color32::from_rgba_premultiplied(100, 160, 255, 50),
            bracket_match_bg: Color32::from_rgba_premultiplied(255, 255, 100, 80),
            bracket_match_border: Color32::from_rgb(200, 180, 0),
            highlight_bg: Color32::from_rgba_premultiplied(100, 100, 255, 35),
        }
    }

    /// Get the text color for a given token kind.
    pub fn token_color(&self, kind: CTokenKind) -> Color32 {
        match kind {
            CTokenKind::Keyword => self.keyword,
            CTokenKind::TypeName => self.datatype,
            CTokenKind::Identifier => self.identifier,
            CTokenKind::FunctionName => self.function,
            CTokenKind::Number => self.number,
            CTokenKind::StringLiteral => self.string,
            CTokenKind::CharLiteral => self.string,
            CTokenKind::Comment => self.comment,
            CTokenKind::Preprocessor => self.preprocessor,
            CTokenKind::Operator => self.operator,
            CTokenKind::Punctuation => self.punctuation,
            CTokenKind::AddressRef => self.keyword, // address refs treated like keywords (blue/purple links)
            CTokenKind::LabelDef => self.label,
            CTokenKind::Whitespace => self.identifier,
            CTokenKind::Unknown => self.identifier,
        }
    }

    /// Get the background color for a BracketKind.
    pub fn bracket_color(&self, _kind: BracketKind) -> Color32 {
        self.bracket_match_bg
    }
}

// ============================================================================
// Render state helpers
// ============================================================================

/// A literal position in pixel coordinates, used internally during rendering.
#[derive(Debug, Clone, Copy, Default)]
struct PixelPos {
    x: f32,
    y: f32,
}

/// Internal state tracking whether the user is performing a text selection drag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SelectionMode {
    None,
    /// Dragging to extend a text selection.
    Extending,
}

/// Internal line-render data computed once per frame.
struct LineLayout {
    line_index: usize,
    y_pos: f32,
    is_visible: bool,
    is_folded: bool,
    fold_depth: usize,
}

// ============================================================================
// CDecompilerRenderer
// ============================================================================

/// Full C pseudocode renderer with syntax highlighting, bracket matching,
/// code folding, and C-to-assembly navigation.
///
/// The renderer takes tokenized lines of C code and renders them into an
/// egui [`Ui`].  It paints:
///
/// - A **fold gutter** showing `[-]`/`[+]` toggle buttons for each foldable
///   brace block.
/// - A **line-number gutter** with configurable width.
/// - The **code area** with per-token syntax coloring, bracket-pair highlights,
///   variable-use underlines, and clickable address/function/label tokens.
///
/// ## Navigation
///
/// Clicking on a token with a [`TokenNavigation`] target produces a
/// [`DecompilerAction`] that the application should consume.
#[derive(Debug, Clone)]
pub struct CDecompilerRenderer {
    /// Font configuration.
    pub fonts: CFonts,
    /// Color configuration.
    pub colors: CColors,
    /// Width of the fold gutter in pixels.
    pub fold_gutter_width: f32,
    /// Width of the line-number gutter in pixels.
    pub line_number_gutter: f32,

    // Interaction state
    /// Cursor line (0-based).
    cursor_line: usize,
    /// Cursor column (0-based).
    cursor_col: usize,
    /// Whether the renderer has a text selection.
    has_selection: bool,
    /// Start of the selection (line, col).
    sel_start_line: usize,
    sel_start_col: usize,
    /// End of the selection (line, col).
    sel_end_line: usize,
    sel_end_col: usize,
    /// Set of folded region start lines.
    folded_regions: HashSet<usize>,
    /// Currently hovered token for tooltips.
    hovered_token_info: Option<String>,
    /// Variable name whose occurrences should be highlighted.
    highlighted_variable: Option<String>,
    /// The matching bracket position if cursor is on a bracket.
    matching_bracket_pos: Option<(usize, usize)>,
    /// Scroll position.
    scroll_offset: f32,
    /// Whether the user manually scrolled.
    user_scrolled: bool,
    /// Pending action produced by the last render.
    pending_action: Option<DecompilerAction>,
}

impl Default for CDecompilerRenderer {
    fn default() -> Self {
        Self {
            fonts: CFonts::default(),
            colors: CColors::default(),
            fold_gutter_width: FOLD_GUTTER_WIDTH,
            line_number_gutter: LINE_NUMBER_GUTTER_WIDTH,

            cursor_line: 0,
            cursor_col: 0,
            has_selection: false,
            sel_start_line: 0,
            sel_start_col: 0,
            sel_end_line: 0,
            sel_end_col: 0,
            folded_regions: HashSet::new(),
            hovered_token_info: None,
            highlighted_variable: None,
            matching_bracket_pos: None,
            scroll_offset: 0.0,
            user_scrolled: true,
            pending_action: None,
        }
    }
}

// ============================================================================
// DecompilerAction
// ============================================================================

/// Actions emitted by the decompiler renderer in response to user interaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecompilerAction {
    /// No action.
    None,
    /// Navigate the listing view to an address.
    NavigateToAddress(Address),
    /// Navigate to a function definition (by name).
    NavigateToFunction(String),
    /// Navigate to a label definition (by name).
    NavigateToLabel(String),
    /// Highlight all usages of a variable.
    HighlightVariable(String),
    /// Clear variable highlights.
    ClearHighlight,
    /// Fold toggle at a specific line.
    ToggleFold(usize),
    /// Selection was copied to clipboard (text provided).
    Copied(String),
}

// ============================================================================
// Implementation
// ============================================================================

impl CDecompilerRenderer {
    // ------------------------------------------------------------------
    // Constructor
    // ------------------------------------------------------------------

    /// Create a new renderer with default dark theme.
    pub fn new() -> Self {
        Self::default()
    }

    /// Builder: set the font size for all fonts.
    pub fn with_font_size(mut self, size: f32) -> Self {
        self.fonts = CFonts::with_size(size);
        self
    }

    /// Builder: use the light color theme.
    pub fn with_light_theme(mut self) -> Self {
        self.colors = CColors::light();
        self
    }

    /// Builder: set fold gutter width.
    pub fn with_fold_gutter(mut self, width: f32) -> Self {
        self.fold_gutter_width = width;
        self
    }

    /// Builder: set line-number gutter width.
    pub fn with_line_number_gutter(mut self, width: f32) -> Self {
        self.line_number_gutter = width;
        self
    }

    /// Take the pending action, if any.
    pub fn take_action(&mut self) -> DecompilerAction {
        self.pending_action.take().unwrap_or(DecompilerAction::None)
    }

    // ------------------------------------------------------------------
    // Cursor and selection
    // ------------------------------------------------------------------

    /// Set the cursor position.
    pub fn set_cursor(&mut self, line: usize, col: usize) {
        self.cursor_line = line;
        self.cursor_col = col;
    }

    /// Get the cursor line.
    pub fn cursor_line(&self) -> usize {
        self.cursor_line
    }

    /// Get the cursor column.
    pub fn cursor_col(&self) -> usize {
        self.cursor_col
    }

    /// Set the selection.
    pub fn set_selection(
        &mut self,
        start_line: usize,
        start_col: usize,
        end_line: usize,
        end_col: usize,
    ) {
        self.has_selection = true;
        self.sel_start_line = start_line;
        self.sel_start_col = start_col;
        self.sel_end_line = end_line;
        self.sel_end_col = end_col;
    }

    /// Clear the selection.
    pub fn clear_selection(&mut self) {
        self.has_selection = false;
    }

    /// Check if a position is within the selection.
    fn is_position_selected(&self, line: usize, col: usize) -> bool {
        if !self.has_selection {
            return false;
        }
        let (sl, sc) = self.normalized_selection_start();
        let (el, ec) = self.normalized_selection_end();
        if line < sl || line > el {
            return false;
        }
        if line == sl && line == el {
            col >= sc && col < ec
        } else if line == sl {
            col >= sc
        } else if line == el {
            col < ec
        } else {
            true
        }
    }

    /// Get the normalized (earlier) selection start.
    fn normalized_selection_start(&self) -> (usize, usize) {
        if self.sel_start_line < self.sel_end_line {
            (self.sel_start_line, self.sel_start_col)
        } else if self.sel_start_line > self.sel_end_line {
            (self.sel_end_line, self.sel_end_col)
        } else if self.sel_start_col <= self.sel_end_col {
            (self.sel_start_line, self.sel_start_col)
        } else {
            (self.sel_end_line, self.sel_end_col)
        }
    }

    /// Get the normalized (later) selection end.
    fn normalized_selection_end(&self) -> (usize, usize) {
        if self.sel_start_line < self.sel_end_line {
            (self.sel_end_line, self.sel_end_col)
        } else if self.sel_start_line > self.sel_end_line {
            (self.sel_start_line, self.sel_start_col)
        } else if self.sel_start_col <= self.sel_end_col {
            (self.sel_end_line, self.sel_end_col)
        } else {
            (self.sel_start_line, self.sel_start_col)
        }
    }

    // ------------------------------------------------------------------
    // Folding
    // ------------------------------------------------------------------

    /// Check if a fold region is currently folded.
    pub fn is_folded(&self, start_line: usize) -> bool {
        self.folded_regions.contains(&start_line)
    }

    /// Toggle folding at a fold region start line.
    pub fn toggle_fold(&mut self, start_line: usize) {
        if self.folded_regions.contains(&start_line) {
            self.folded_regions.remove(&start_line);
        } else {
            self.folded_regions.insert(start_line);
        }
    }

    /// Fold all regions.
    pub fn fold_all(&mut self, fold_regions: &[FoldRegion]) {
        for region in fold_regions {
            self.folded_regions.insert(region.start_line);
        }
    }

    /// Unfold all regions.
    pub fn unfold_all(&mut self) {
        self.folded_regions.clear();
    }

    /// Check whether a line is visible (not hidden by a folded ancestor).
    pub fn is_line_visible(&self, line: usize, fold_regions: &[FoldRegion]) -> bool {
        for region in fold_regions {
            if self.folded_regions.contains(&region.start_line) {
                if line > region.start_line && line <= region.end_line {
                    return false;
                }
            }
        }
        true
    }

    // ------------------------------------------------------------------
    // Bracket matching
    // ------------------------------------------------------------------

    /// Find the matching bracket for the cursor position.
    pub fn find_matching_bracket(&self, bracket_pairs: &[BracketPair]) -> Option<(usize, usize)> {
        for pair in bracket_pairs {
            if pair.open.line == self.cursor_line
                && (pair.open.col as i32 - self.cursor_col as i32).abs() <= 1
            {
                return Some((pair.close.line, pair.close.col));
            }
            if pair.close.line == self.cursor_line
                && (pair.close.col as i32 - self.cursor_col as i32).abs() <= 1
            {
                return Some((pair.open.line, pair.open.col));
            }
        }
        None
    }

    // ------------------------------------------------------------------
    // Variable highlighting
    // ------------------------------------------------------------------

    /// Set the variable to highlight.
    pub fn highlight_variable(&mut self, name: Option<String>) {
        self.highlighted_variable = name;
    }

    /// Check if a token is a highlighted variable occurrence.
    fn is_variable_highlighted(&self, token: &CToken) -> bool {
        if let Some(ref var) = self.highlighted_variable {
            if token.kind == CTokenKind::Identifier {
                return token.text == *var;
            }
        }
        false
    }

    // ------------------------------------------------------------------
    // Render
    // ------------------------------------------------------------------

    /// Render the decompiled C code into the given egui Ui.
    ///
    /// # Arguments
    ///
    /// * `ui` — the egui Ui to render into.
    /// * `tokens` — tokenized lines of C pseudocode.
    /// * `fold_regions` — computed foldable regions.
    /// * `bracket_pairs` — computed bracket pairs, for bracket matching.
    /// * `line_addresses` — optional per-line assembly address mapping.
    pub fn render(
        &mut self,
        ui: &mut Ui,
        tokens: &[Vec<CToken>],
        fold_regions: &[FoldRegion],
        bracket_pairs: &[BracketPair],
        line_addresses: &[Option<Address>],
    ) {
        let total_gutter = self.fold_gutter_width + self.line_number_gutter;
        let code_area_start_x = ui.available_rect_before_wrap().left() + total_gutter;

        // Refresh bracket match
        self.matching_bracket_pos = self.find_matching_bracket(bracket_pairs);

        // Determine which lines are visible
        let total_lines = tokens.len();
        let line_count = total_lines as f32 * LINE_HEIGHT;

        // Receive keyboard input before we start painting
        let input = ui.input(|i| i.clone());
        self.handle_keyboard(&input, tokens, fold_regions, line_addresses);

        // Build the list of visible line layouts
        let layouts: Vec<LineLayout> = (0..total_lines)
            .map(|line_idx| {
                let is_visible = self.is_line_visible(line_idx, fold_regions);
                let is_folded = self.is_folded(line_idx);
                LineLayout {
                    line_index: line_idx,
                    y_pos: 0.0, // computed during rendering
                    is_visible,
                    is_folded,
                    fold_depth: fold_regions
                        .iter()
                        .filter(|r| r.start_line == line_idx)
                        .map(|r| r.depth)
                        .next()
                        .unwrap_or(0),
                }
            })
            .collect();

        // Count visible lines to compute total height
        let visible_count = layouts.iter().filter(|l| l.is_visible).count();
        let total_content_height = visible_count as f32 * LINE_HEIGHT;

        // Scroll area
        let scroll_id = ui.make_persistent_id("decompiler_scroll");
        let available = ui.available_rect_before_wrap();
        let content_size = vec2(
            available.width(),
            total_content_height.max(available.height()),
        );

        let (_rect, _response) = ui.allocate_exact_size(content_size, Sense::click_and_drag());

        // Determine which visible lines fall within the viewport
        let clip = ui.clip_rect();
        let first_visible_y = (clip.top() - available.top()).max(0.0);
        let first_line_idx = (first_visible_y / LINE_HEIGHT) as usize;
        let last_line_idx = ((first_visible_y + clip.height()) / LINE_HEIGHT) as usize + 2;

        // Paint background
        ui.painter().rect_filled(
            Rect::from_min_size(
                pos2(available.left(), available.top()),
                vec2(available.width(), total_content_height),
            ),
            0.0,
            self.colors.background,
        );

        // Paint gutter background
        ui.painter().rect_filled(
            Rect::from_min_size(
                pos2(available.left(), available.top()),
                vec2(total_gutter, total_content_height),
            ),
            0.0,
            self.colors.gutter_background,
        );

        // Paint vertical separator between gutter and code
        ui.painter().line_segment(
            [
                pos2(code_area_start_x, available.top()),
                pos2(code_area_start_x, available.top() + total_content_height),
            ],
            Stroke::new(1.0, Color32::from_rgb(60, 60, 66)),
        );

        // Render lines
        let mut visible_y = 0.0f32;
        for layout in &layouts {
            if !layout.is_visible {
                continue;
            }
            if visible_y + LINE_HEIGHT < first_visible_y {
                visible_y += LINE_HEIGHT;
                continue;
            }
            if visible_y > first_visible_y + clip.height() {
                break;
            }

            let mut abs_y = available.top() + visible_y;
            let line = layout.line_index;

            let tokens_line = if line < tokens.len() {
                &tokens[line]
            } else {
                continue;
            };

            // --- Line background ---
            let is_cursor = line == self.cursor_line;
            let line_rect = Rect::from_min_size(
                pos2(available.left(), abs_y),
                vec2(available.width(), LINE_HEIGHT),
            );

            if is_cursor {
                ui.painter()
                    .rect_filled(line_rect, 0.0, self.colors.cursor_line);
            }

            // --- Fold gutter ---
            let fold_is_foldable = fold_regions.iter().any(|r| r.start_line == line);
            let is_folded = self.is_folded(line);

            if fold_is_foldable {
                let fold_rect = Rect::from_min_size(
                    pos2(available.left() + 2.0, abs_y + 2.0),
                    vec2(self.fold_gutter_width - 4.0, LINE_HEIGHT - 4.0),
                );
                let icon = if is_folded { "[+]" } else { "[-]" };
                let fold_color = Color32::from_rgb(140, 140, 150);

                let fold_resp =
                    ui.interact(fold_rect, Id::new(("fold_toggle", line)), Sense::click());
                if fold_resp.clicked() {
                    self.toggle_fold(line);
                    self.pending_action = Some(DecompilerAction::ToggleFold(line));
                }
                if fold_resp.hovered() {
                    ui.ctx().set_cursor_icon(CursorIcon::PointingHand);
                }

                let galley = ui.painter().layout_no_wrap(
                    icon.to_string(),
                    self.fonts.default.clone(),
                    fold_color,
                );
                ui.painter()
                    .galley(pos2(fold_rect.left(), abs_y + 2.0), galley, fold_color);
            }

            // --- Line number ---
            let ln_text = format!("{:>4}", line + 1);
            let ln_color = if is_cursor {
                self.colors.keyword
            } else {
                self.colors.line_number
            };
            let ln_galley =
                ui.painter()
                    .layout_no_wrap(ln_text.clone(), self.fonts.default.clone(), ln_color);
            ui.painter().galley(
                pos2(available.left() + self.fold_gutter_width + 2.0, abs_y + 1.0),
                ln_galley,
                ln_color,
            );

            // --- Code tokens ---
            let mut x = code_area_start_x + CODE_PADDING_X;

            for token in tokens_line {
                let token_text = &token.text;
                if token_text.is_empty() {
                    continue;
                }

                let color = self.resolve_token_color(token);
                let mut bg = None;

                // Selection background
                if self.has_selection {
                    let token_end_col = token.col + token_text.len();
                    let sel_start = self.normalized_selection_start();
                    let sel_end = self.normalized_selection_end();

                    let is_in_sel = if line < sel_start.0 || line > sel_end.0 {
                        false
                    } else if line == sel_start.0 && line == sel_end.0 {
                        token.col < sel_end.1 && token_end_col > sel_start.1
                    } else if line == sel_start.0 {
                        token_end_col > sel_start.1
                    } else if line == sel_end.0 {
                        token.col < sel_end.1
                    } else {
                        true
                    };
                    if is_in_sel {
                        bg = Some(self.colors.selection);
                    }
                }

                // Bracket match highlight
                if let Some((ml, mc)) = self.matching_bracket_pos {
                    if line == ml && token.col == mc {
                        bg = Some(self.colors.bracket_match_bg);
                    }
                }

                // Variable highlight
                if self.is_variable_highlighted(token) {
                    bg = Some(self.colors.highlight_bg);
                }

                // Render each line within a multi-line token (e.g., a "\n" in a string)
                for (sub_idx, sub_line) in token_text.lines().enumerate() {
                    if sub_idx > 0 {
                        // Start new line for multi-line tokens
                        visible_y += LINE_HEIGHT;
                        abs_y = available.top() + visible_y;
                        x = code_area_start_x + CODE_PADDING_X;
                    }

                    let token_width = sub_line.len() as f32 * CHAR_WIDTH;
                    let token_rect = Rect::from_min_size(
                        pos2(x, abs_y),
                        vec2(token_width.max(10.0), LINE_HEIGHT),
                    );

                    // Paint background if needed
                    if let Some(bg_color) = bg {
                        ui.painter().rect_filled(token_rect, 0.0, bg_color);
                    }

                    // Paint the text
                    if !sub_line.is_empty() {
                        let galley = ui.painter().layout_no_wrap(
                            sub_line.to_string(),
                            self.fonts.default.clone(),
                            color,
                        );
                        ui.painter().galley(pos2(x, abs_y + 1.0), galley, color);

                        // Underline for clickable navigation tokens
                        if matches!(
                            token.navigation,
                            TokenNavigation::Address(_)
                                | TokenNavigation::Function(_)
                                | TokenNavigation::Label(_)
                        ) {
                            ui.painter().line_segment(
                                [
                                    pos2(x, abs_y + LINE_HEIGHT - 1.0),
                                    pos2(x + token_width, abs_y + LINE_HEIGHT - 1.0),
                                ],
                                Stroke::new(1.0, color),
                            );
                        }
                    }

                    // Interaction: detect click on token
                    let token_resp = ui.interact(
                        token_rect,
                        Id::new(("decomp_token", line, token.col, sub_idx)),
                        Sense::click(),
                    );

                    if token_resp.clicked() {
                        self.cursor_line = line;
                        self.cursor_col = token.col;
                        self.handle_token_click(token);
                    }
                    if token_resp.hovered() {
                        self.hovered_token_info =
                            Some(format!("{:?}: {}", token.kind, token.text));
                    }

                    x += token_width;
                }
            }

            visible_y += LINE_HEIGHT;

            if visible_y > first_visible_y + clip.height() + LINE_HEIGHT {
                break;
            }
        }
    }

    // ------------------------------------------------------------------
    // Token interaction
    // ------------------------------------------------------------------

    /// Handle a click on a token.
    fn handle_token_click(&mut self, token: &CToken) {
        match &token.navigation {
            TokenNavigation::Address(addr) => {
                self.pending_action = Some(DecompilerAction::NavigateToAddress(*addr));
            }
            TokenNavigation::Function(name) => {
                self.pending_action = Some(DecompilerAction::NavigateToFunction(name.clone()));
            }
            TokenNavigation::Label(name) => {
                self.pending_action = Some(DecompilerAction::NavigateToLabel(name.clone()));
            }
            TokenNavigation::Variable(name) => {
                if self.highlighted_variable.as_deref() == Some(name.as_str()) {
                    self.pending_action = Some(DecompilerAction::ClearHighlight);
                } else {
                    self.pending_action = Some(DecompilerAction::HighlightVariable(name.clone()));
                }
            }
            TokenNavigation::None => {
                // Plain identifier: still allow variable hover/highlight
                if token.kind == CTokenKind::Identifier || token.kind == CTokenKind::FunctionName {
                    let name = &token.text;
                    if self.highlighted_variable.as_deref() == Some(name) {
                        self.pending_action = Some(DecompilerAction::ClearHighlight);
                    } else {
                        self.pending_action =
                            Some(DecompilerAction::HighlightVariable(name.clone()));
                    }
                }
            }
        }
    }

    /// Resolve the display color for a token.
    fn resolve_token_color(&self, token: &CToken) -> Color32 {
        // Override for highlighted variable
        if self.is_variable_highlighted(token) {
            return self.colors.variable;
        }

        // Override for bracket match
        if let Some((ml, mc)) = self.matching_bracket_pos {
            if token.line == ml && token.col == mc && token.is_bracket {
                return self.colors.bracket_match_border;
            }
        }

        self.colors.token_color(token.kind)
    }

    // ------------------------------------------------------------------
    // Keyboard handling
    // ------------------------------------------------------------------

    /// Handle keyboard input.
    fn handle_keyboard(
        &mut self,
        input: &egui::InputState,
        tokens: &[Vec<CToken>],
        fold_regions: &[FoldRegion],
        line_addresses: &[Option<Address>],
    ) {
        let modifiers = input.modifiers;

        // Arrow down
        if input.key_pressed(Key::ArrowDown) {
            let next = (self.cursor_line + 1).min(tokens.len().saturating_sub(1));
            self.cursor_line = next;
            self.cursor_col = 0;
            if modifiers.shift {
                self.has_selection = true;
                self.sel_end_line = next;
                self.sel_end_col = 0;
            } else {
                self.clear_selection();
            }
        }

        // Arrow up
        if input.key_pressed(Key::ArrowUp) {
            let prev = self.cursor_line.saturating_sub(1);
            self.cursor_line = prev;
            self.cursor_col = 0;
            if modifiers.shift {
                self.has_selection = true;
                self.sel_end_line = prev;
                self.sel_end_col = 0;
            } else {
                self.clear_selection();
            }
        }

        // Arrow right
        if input.key_pressed(Key::ArrowRight) {
            if let Some(line) = tokens.get(self.cursor_line) {
                let max_col = line.last().map(|t| t.col + t.text.len()).unwrap_or(0);
                self.cursor_col = (self.cursor_col + 1).min(max_col);
            }
        }

        // Arrow left
        if input.key_pressed(Key::ArrowLeft) {
            self.cursor_col = self.cursor_col.saturating_sub(1);
        }

        // Page down
        if input.key_pressed(Key::PageDown) {
            let skip = 20usize;
            self.cursor_line = (self.cursor_line + skip).min(tokens.len().saturating_sub(1));
        }

        // Page up
        if input.key_pressed(Key::PageUp) {
            self.cursor_line = self.cursor_line.saturating_sub(20);
        }

        // Home
        if input.key_pressed(Key::Home) {
            self.cursor_line = 0;
            self.cursor_col = 0;
            self.clear_selection();
        }

        // End
        if input.key_pressed(Key::End) {
            self.cursor_line = tokens.len().saturating_sub(1);
            self.cursor_col = 0;
            self.clear_selection();
        }

        // Escape: clear selection
        if input.key_pressed(Key::Escape) {
            self.clear_selection();
            self.highlighted_variable = None;
        }

        // Ctrl+G: navigate line
        if modifiers.ctrl && input.key_pressed(Key::G) {
            // Would open a "go to line" dialog — not implemented here,
            // but the caller can detect this via input state.
        }

        // Ctrl+A: select all
        if modifiers.ctrl && input.key_pressed(Key::A) {
            self.has_selection = true;
            self.sel_start_line = 0;
            self.sel_start_col = 0;
            if let Some(last_line) = tokens.last() {
                self.sel_end_line = tokens.len().saturating_sub(1);
                self.sel_end_col = last_line.last().map(|t| t.col + t.text.len()).unwrap_or(0);
            }
        }

        // Ctrl+C: copy selection
        if modifiers.ctrl && input.key_pressed(Key::C) {
            let text = self.selected_text(tokens);
            if !text.is_empty() {
                self.pending_action = Some(DecompilerAction::Copied(text));
            }
        }

        // Enter: navigate to address on current line
        if input.key_pressed(Key::Enter) && !modifiers.ctrl {
            if let Some(Some(addr)) = line_addresses.get(self.cursor_line) {
                self.pending_action = Some(DecompilerAction::NavigateToAddress(*addr));
            }
        }
    }

    /// Get the text of the current selection.
    fn selected_text(&self, tokens: &[Vec<CToken>]) -> String {
        if !self.has_selection {
            return String::new();
        }
        let (sl, sc) = self.normalized_selection_start();
        let (el, ec) = self.normalized_selection_end();

        let mut result = String::new();
        for (line_idx, line_tokens) in tokens.iter().enumerate() {
            if line_idx < sl || line_idx > el {
                continue;
            }
            for token in line_tokens {
                let tok_end = token.col + token.text.len();
                if line_idx == sl && line_idx == el {
                    if token.col < ec && tok_end > sc {
                        let s = &token.text[(sc.saturating_sub(token.col))
                            ..((ec).min(tok_end).saturating_sub(token.col))];
                        result.push_str(s);
                    }
                } else if line_idx == sl {
                    if tok_end > sc {
                        result.push_str(&token.text[(sc.saturating_sub(token.col))..]);
                    }
                } else if line_idx == el {
                    if token.col < ec {
                        result.push_str(&token.text[..(ec.saturating_sub(token.col))]);
                    }
                } else {
                    result.push_str(&token.text);
                }
            }
            if line_idx < el && !result.ends_with('\n') {
                result.push('\n');
            }
        }
        result
    }

    // ------------------------------------------------------------------
    // Scrolling
    // ------------------------------------------------------------------

    /// Set the scroll offset (pixels from top).
    pub fn set_scroll_offset(&mut self, offset: f32) {
        self.scroll_offset = offset;
    }

    /// Get the current scroll offset.
    pub fn scroll_offset(&self) -> f32 {
        self.scroll_offset
    }

    /// Scroll to make a given line visible.
    pub fn scroll_to_line(&mut self, line: usize, visible_lines: usize) {
        // Estimate: place the line in the middle of the viewport
        let half = (visible_lines / 2) as f32;
        self.scroll_offset = (line as f32 - half).max(0.0) * LINE_HEIGHT;
    }
}

// ============================================================================
// Helper: CTokenKind display name
// ============================================================================

impl CTokenKind {
    /// A human-readable name for this token kind (used in hover tooltips).
    pub fn kind_name(&self) -> &'static str {
        match self {
            CTokenKind::Keyword => "keyword",
            CTokenKind::TypeName => "type",
            CTokenKind::Identifier => "identifier",
            CTokenKind::FunctionName => "function",
            CTokenKind::Number => "number",
            CTokenKind::StringLiteral => "string",
            CTokenKind::CharLiteral => "char",
            CTokenKind::Comment => "comment",
            CTokenKind::Preprocessor => "preprocessor",
            CTokenKind::Operator => "operator",
            CTokenKind::Punctuation => "punctuation",
            CTokenKind::AddressRef => "address",
            CTokenKind::Whitespace => "whitespace",
            CTokenKind::LabelDef => "label",
            CTokenKind::Unknown => "unknown",
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_renderer() -> CDecompilerRenderer {
        CDecompilerRenderer::default()
    }

    #[test]
    fn test_default_renderer() {
        let r = make_renderer();
        assert_eq!(r.cursor_line(), 0);
        assert_eq!(r.cursor_col(), 0);
        assert!(!r.has_selection);
    }

    #[test]
    fn test_cursor_operations() {
        let mut r = make_renderer();
        r.set_cursor(5, 10);
        assert_eq!(r.cursor_line(), 5);
        assert_eq!(r.cursor_col(), 10);
    }

    #[test]
    fn test_selection_operations() {
        let mut r = make_renderer();
        r.set_selection(0, 5, 2, 10);
        assert!(r.has_selection);
        assert_eq!(r.normalized_selection_start(), (0, 5));
        assert_eq!(r.normalized_selection_end(), (2, 10));

        r.clear_selection();
        assert!(!r.has_selection);
    }

    #[test]
    fn test_folding() {
        let mut r = make_renderer();
        assert!(!r.is_folded(0));

        r.toggle_fold(0);
        assert!(r.is_folded(0));

        r.toggle_fold(0);
        assert!(!r.is_folded(0));
    }

    #[test]
    fn test_fold_all_unfold_all() {
        let mut r = make_renderer();
        let regions = vec![
            FoldRegion {
                start_line: 0,
                end_line: 10,
                depth: 0,
                kind: super::super::FoldKind::BraceBlock,
            },
            FoldRegion {
                start_line: 3,
                end_line: 7,
                depth: 1,
                kind: super::super::FoldKind::BraceBlock,
            },
        ];

        r.fold_all(&regions);
        assert!(r.is_folded(0));
        assert!(r.is_folded(3));

        r.unfold_all();
        assert!(!r.is_folded(0));
        assert!(!r.is_folded(3));
    }

    #[test]
    fn test_is_line_visible() {
        let mut r = make_renderer();
        let regions = vec![FoldRegion {
            start_line: 1,
            end_line: 5,
            depth: 0,
            kind: super::super::FoldKind::BraceBlock,
        }];

        // Before folding: all lines visible
        assert!(r.is_line_visible(0, &regions));
        assert!(r.is_line_visible(2, &regions));
        assert!(r.is_line_visible(6, &regions));

        // Fold the region
        r.toggle_fold(1);
        assert!(r.is_line_visible(0, &regions));
        assert!(r.is_line_visible(1, &regions)); // start line visible
        assert!(!r.is_line_visible(3, &regions)); // hidden
        assert!(r.is_line_visible(6, &regions)); // after region
    }

    #[test]
    fn test_colors_dark() {
        let colors = CColors::dark();
        assert_ne!(colors.keyword, colors.comment);
        assert_ne!(colors.string, colors.number);
        assert_ne!(colors.identifier, colors.function);
        assert_ne!(colors.background, colors.gutter_background);
    }

    #[test]
    fn test_colors_light() {
        let colors = CColors::light();
        assert_ne!(colors.keyword, colors.comment);
        // Light theme should have light background
        assert!(colors.background.r() > 200);
    }

    #[test]
    fn test_fonts_with_size() {
        let fonts = CFonts::with_size(14.0);
        assert_eq!(fonts.default.size, 14.0);
    }

    #[test]
    fn test_selected_text() {
        let mut r = make_renderer();
        let tokens: Vec<Vec<CToken>> = vec![
            vec![CToken::new(CTokenKind::Identifier, "hello", 0, 0)],
            vec![CToken::new(CTokenKind::Identifier, "world", 1, 0)],
        ];

        // No selection
        assert_eq!(r.selected_text(&tokens), "");

        // Select "hello"
        r.set_selection(0, 0, 0, 5);
        assert_eq!(r.selected_text(&tokens), "hello");

        // Select all
        r.set_selection(0, 0, 1, 5);
        let text = r.selected_text(&tokens);
        assert!(text.contains("hello"));
        assert!(text.contains("world"));
    }

    #[test]
    fn test_token_color_mapping() {
        let colors = CColors::default();
        assert_eq!(colors.token_color(CTokenKind::Comment), colors.comment);
        assert_eq!(colors.token_color(CTokenKind::StringLiteral), colors.string);
        assert_eq!(colors.token_color(CTokenKind::Number), colors.number);
        assert_eq!(
            colors.token_color(CTokenKind::FunctionName),
            colors.function
        );
    }

    #[test]
    fn test_variable_highlight() {
        let mut r = make_renderer();
        let token = CToken::new(CTokenKind::Identifier, "counter", 5, 10);

        assert!(!r.is_variable_highlighted(&token));

        r.highlight_variable(Some("counter".to_string()));
        assert!(r.is_variable_highlighted(&token));

        r.highlight_variable(None);
        assert!(!r.is_variable_highlighted(&token));

        let other = CToken::new(CTokenKind::Identifier, "other", 6, 4);
        r.highlight_variable(Some("counter".to_string()));
        assert!(!r.is_variable_highlighted(&other));
    }

    #[test]
    fn test_decompiler_action_take() {
        let mut r = make_renderer();
        assert_eq!(r.take_action(), DecompilerAction::None);

        r.pending_action = Some(DecompilerAction::NavigateToAddress(Address::new(0x401000)));
        assert_eq!(
            r.take_action(),
            DecompilerAction::NavigateToAddress(Address::new(0x401000))
        );
        assert_eq!(r.take_action(), DecompilerAction::None);
    }
}
