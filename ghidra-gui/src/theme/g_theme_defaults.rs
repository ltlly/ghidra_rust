//! Default theme values for commonly used Ghidra concepts.
//!
//! Port of `generic.theme.GThemeDefaults`. Provides standard color,
//! font, and icon constants that applications should use instead of
//! hard-coding values, so they adapt to the active theme.
//!
//! # Usage
//!
//! ```ignore
//! use ghidra_gui::theme::g_theme_defaults::{Colors, Fonts, Icons};
//!
//! let fg = Colors::foreground();       // GColor resolving to the current theme
//! let mono = Fonts::MONOSPACED;        // a &str key
//! let icon = Icons::DECOMPILER;        // a &str key
//! ```

use super::g_color::GColor;

// ---------------------------------------------------------------------------
// Colors
// ---------------------------------------------------------------------------

/// Standard color constants that follow the active theme.
///
/// Instead of hard-coding `Color::BLACK` for a label foreground, use
/// `Colors::foreground()` so it adapts when the user switches themes.
///
/// Each method returns a new [`GColor`] keyed to a stable theme-id string.
/// Because `GColor` holds an `Arc`, repeated calls are cheap once the
/// theme manager resolves the actual RGBA value.
pub struct Colors;

impl Colors {
    /// The standard foreground (text) color.
    pub fn foreground() -> GColor { GColor::new("foreground") }
    /// The standard background color.
    pub fn background() -> GColor { GColor::new("background") }
    /// Color for informational / muted text.
    pub fn info() -> GColor { GColor::new("color.info") }
    /// Color for warning text or indicators.
    pub fn warn() -> GColor { GColor::new("color.warn") }
    /// Color for error text or indicators.
    pub fn error() -> GColor { GColor::new("color.error") }
    /// Color for success / positive indicators.
    pub fn success() -> GColor { GColor::new("color.success") }
    /// Color for hyperlink text.
    pub fn link() -> GColor { GColor::new("color.link") }
    /// Color for visited hyperlink text.
    pub fn link_visited() -> GColor { GColor::new("color.link.visited") }
    /// Color for disabled / greyed-out text.
    pub fn disabled() -> GColor { GColor::new("color.disabled") }
    /// Color for highlighted / selected text background.
    pub fn selection_background() -> GColor { GColor::new("color.selection.background") }
    /// Color for highlighted / selected text foreground.
    pub fn selection_foreground() -> GColor { GColor::new("color.selection.foreground") }
    /// Color for borders and dividers.
    pub fn border() -> GColor { GColor::new("color.border") }
    /// Color for alternating row backgrounds in tables.
    pub fn table_alt_row() -> GColor { GColor::new("color.table.alt.row") }

    // ---- Listing-specific colors ----

    /// Color for address fields in the listing.
    pub fn listing_address() -> GColor { GColor::new("color.listing.address") }
    /// Color for bytes display in the listing.
    pub fn listing_bytes() -> GColor { GColor::new("color.listing.bytes") }
    /// Color for comments in the listing.
    pub fn listing_comment() -> GColor { GColor::new("color.listing.comment") }
    /// Color for keywords (if, return, etc.) in the listing.
    pub fn listing_keyword() -> GColor { GColor::new("color.listing.keyword") }
    /// Color for register names in the listing.
    pub fn listing_register() -> GColor { GColor::new("color.listing.register") }
    /// Color for function names in the listing.
    pub fn listing_function() -> GColor { GColor::new("color.listing.function") }
    /// Color for variables in the listing.
    pub fn listing_variable() -> GColor { GColor::new("color.listing.variable") }
    /// Color for type names in the listing.
    pub fn listing_type() -> GColor { GColor::new("color.listing.type") }
    /// Color for constants/numbers in the listing.
    pub fn listing_constant() -> GColor { GColor::new("color.listing.constant") }
    /// Color for mnemonics/opcode names in the listing.
    pub fn listing_mnemonic() -> GColor { GColor::new("color.listing.mnemonic") }

    // ---- Decompiler-specific colors ----

    /// Default decompiler C code foreground color.
    pub fn decompiler_default() -> GColor { GColor::new("color.decompiler.default") }
    /// Decompiler keyword color.
    pub fn decompiler_keyword() -> GColor { GColor::new("color.decompiler.keyword") }
    /// Decompiler type name color.
    pub fn decompiler_type() -> GColor { GColor::new("color.decompiler.type") }
    /// Decompiler function name color.
    pub fn decompiler_function() -> GColor { GColor::new("color.decompiler.function") }
    /// Decompiler variable color.
    pub fn decompiler_variable() -> GColor { GColor::new("color.decompiler.variable") }
    /// Decompiler constant color.
    pub fn decompiler_constant() -> GColor { GColor::new("color.decompiler.constant") }
    /// Decompiler parameter color.
    pub fn decompiler_parameter() -> GColor { GColor::new("color.decompiler.parameter") }
    /// Decompiler comment color.
    pub fn decompiler_comment() -> GColor { GColor::new("color.decompiler.comment") }

    // ---- Graph-specific colors ----

    /// Default vertex fill color in graph views.
    pub fn graph_vertex_fill() -> GColor { GColor::new("color.graph.vertex.fill") }
    /// Default vertex border color in graph views.
    pub fn graph_vertex_border() -> GColor { GColor::new("color.graph.vertex.border") }
    /// Default edge color in graph views.
    pub fn graph_edge() -> GColor { GColor::new("color.graph.edge") }
    /// Color for highlighted edges in graph views.
    pub fn graph_edge_highlight() -> GColor { GColor::new("color.graph.edge.highlight") }
    /// Background color for the graph view.
    pub fn graph_background() -> GColor { GColor::new("color.graph.background") }
}

// ---------------------------------------------------------------------------
// Fonts
// ---------------------------------------------------------------------------

/// Standard font identifiers that follow the active theme.
///
/// Use these constants instead of hard-coding font names and sizes.
/// The values are stable theme-key strings; the theme manager resolves
/// them to actual fonts at runtime.
pub struct Fonts;

impl Fonts {
    /// Default proportional font (e.g., for labels, menus).
    pub const DEFAULT: &'static str = "font.default";
    /// Monospaced / fixed-width font (e.g., for code, listing, decompiler).
    pub const MONOSPACED: &'static str = "font.monospaced";
    /// Small font for compact displays.
    pub const SMALL: &'static str = "font.small";
    /// Large font for headings or emphasis.
    pub const LARGE: &'static str = "font.large";
    /// Bold variant of the default font.
    pub const BOLD: &'static str = "font.bold";
    /// Italic variant of the default font.
    pub const ITALIC: &'static str = "font.italic";

    // Listing-specific fonts
    /// Monospaced font used in the code listing view.
    pub const LISTING: &'static str = "font.listing";
    /// Monospaced font used in the decompiler view.
    pub const DECOMPILER: &'static str = "font.decompiler";

    // Component fonts
    /// Font for table headers.
    pub const TABLE_HEADER: &'static str = "font.table.header";
    /// Font for table cells.
    pub const TABLE_CELL: &'static str = "font.table.cell";
    /// Font for tooltips.
    pub const TOOLTIP: &'static str = "font.tooltip";
    /// Font for status bar.
    pub const STATUS_BAR: &'static str = "font.status.bar";
}

// ---------------------------------------------------------------------------
// Icons
// ---------------------------------------------------------------------------

/// Standard icon identifiers that follow the active theme.
///
/// These are stable key strings. The resource manager / icon factory
/// resolves them to actual icon images at runtime based on the active
/// theme (light, dark, etc.).
pub struct Icons;

impl Icons {
    // ---- Navigation icons ----
    /// Navigate back icon.
    pub const NAVIGATE_BACK: &'static str = "icon.navigate.back";
    /// Navigate forward icon.
    pub const NAVIGATE_FORWARD: &'static str = "icon.navigate.forward";
    /// Navigate home icon.
    pub const NAVIGATE_HOME: &'static str = "icon.navigate.home";
    /// Navigate up icon.
    pub const NAVIGATE_UP: &'static str = "icon.navigate.up";

    // ---- Action icons ----
    /// New / create icon.
    pub const NEW: &'static str = "icon.new";
    /// Open / load icon.
    pub const OPEN: &'static str = "icon.open";
    /// Save icon.
    pub const SAVE: &'static str = "icon.save";
    /// Save all icon.
    pub const SAVE_ALL: &'static str = "icon.save.all";
    /// Close icon.
    pub const CLOSE: &'static str = "icon.close";
    /// Cut icon.
    pub const CUT: &'static str = "icon.cut";
    /// Copy icon.
    pub const COPY: &'static str = "icon.copy";
    /// Paste icon.
    pub const PASTE: &'static str = "icon.paste";
    /// Delete icon.
    pub const DELETE: &'static str = "icon.delete";
    /// Undo icon.
    pub const UNDO: &'static str = "icon.undo";
    /// Redo icon.
    pub const REDO: &'static str = "icon.redo";
    /// Search icon.
    pub const SEARCH: &'static str = "icon.search";
    /// Filter icon.
    pub const FILTER: &'static str = "icon.filter";
    /// Refresh icon.
    pub const REFRESH: &'static str = "icon.refresh";
    /// Settings / properties icon.
    pub const SETTINGS: &'static str = "icon.settings";
    /// Help icon.
    pub const HELP: &'static str = "icon.help";
    /// Info icon.
    pub const INFO: &'static str = "icon.info";
    /// Warning icon.
    pub const WARNING: &'static str = "icon.warning";
    /// Error icon.
    pub const ERROR: &'static str = "icon.error";
    /// Success / OK icon.
    pub const OK: &'static str = "icon.ok";

    // ---- Tree / list icons ----
    /// Expand / plus icon.
    pub const EXPAND: &'static str = "icon.expand";
    /// Collapse / minus icon.
    pub const COLLAPSE: &'static str = "icon.collapse";
    /// Folder icon.
    pub const FOLDER: &'static str = "icon.folder";
    /// File icon.
    pub const FILE: &'static str = "icon.file";
    /// Checkbox checked icon.
    pub const CHECKBOX_CHECKED: &'static str = "icon.checkbox.checked";
    /// Checkbox unchecked icon.
    pub const CHECKBOX_UNCHECKED: &'static str = "icon.checkbox.unchecked";
    /// Radio selected icon.
    pub const RADIO_SELECTED: &'static str = "icon.radio.selected";
    /// Radio unselected icon.
    pub const RADIO_UNSELECTED: &'static str = "icon.radio.unselected";

    // ---- Ghidra-specific icons ----
    /// Decompiler icon.
    pub const DECOMPILER: &'static str = "icon.decompiler";
    /// Listing icon.
    pub const LISTING: &'static str = "icon.listing";
    /// Graph view icon.
    pub const GRAPH: &'static str = "icon.graph";
    /// Function icon.
    pub const FUNCTION: &'static str = "icon.function";
    /// Symbol icon.
    pub const SYMBOL: &'static str = "icon.symbol";
    /// Bookmark icon.
    pub const BOOKMARK: &'static str = "icon.bookmark";
    /// Breakpoint icon.
    pub const BREAKPOINT: &'static str = "icon.breakpoint";
    /// Memory icon.
    pub const MEMORY: &'static str = "icon.memory";
    /// Register icon.
    pub const REGISTER: &'static str = "icon.register";
    /// Program icon.
    pub const PROGRAM: &'static str = "icon.program";
    /// Binary icon.
    pub const BINARY: &'static str = "icon.binary";
    /// Analysis icon.
    pub const ANALYSIS: &'static str = "icon.analysis";

    // ---- Status / overlay icons ----
    /// Overlay: locked / read-only.
    pub const OVERLAY_LOCKED: &'static str = "icon.overlay.locked";
    /// Overlay: modified / dirty.
    pub const OVERLAY_MODIFIED: &'static str = "icon.overlay.modified";
    /// Overlay: error.
    pub const OVERLAY_ERROR: &'static str = "icon.overlay.error";
    /// Overlay: warning.
    pub const OVERLAY_WARNING: &'static str = "icon.overlay.warning";
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn color_factory_returns_gcolors() {
        let fg = Colors::foreground();
        let bg = Colors::background();
        // IDs must differ
        assert_ne!(fg.id(), bg.id());
        assert_eq!(fg.id(), "foreground");
        assert_eq!(bg.id(), "background");
    }

    #[test]
    fn listing_colors_have_distinct_ids() {
        let ids: Vec<String> = vec![
            Colors::listing_address().id(),
            Colors::listing_bytes().id(),
            Colors::listing_comment().id(),
            Colors::listing_keyword().id(),
            Colors::listing_register().id(),
            Colors::listing_function().id(),
            Colors::listing_variable().id(),
            Colors::listing_type().id(),
            Colors::listing_constant().id(),
            Colors::listing_mnemonic().id(),
        ];
        let original_len = ids.len();
        let mut deduped = ids.clone();
        deduped.sort();
        deduped.dedup();
        assert_eq!(deduped.len(), original_len, "listing color IDs should be unique");
    }

    #[test]
    fn decompiler_colors_have_distinct_ids() {
        let ids: Vec<String> = vec![
            Colors::decompiler_default().id(),
            Colors::decompiler_keyword().id(),
            Colors::decompiler_type().id(),
            Colors::decompiler_function().id(),
            Colors::decompiler_variable().id(),
            Colors::decompiler_constant().id(),
            Colors::decompiler_parameter().id(),
            Colors::decompiler_comment().id(),
        ];
        let original_len = ids.len();
        let mut deduped = ids.clone();
        deduped.sort();
        deduped.dedup();
        assert_eq!(deduped.len(), original_len, "decompiler color IDs should be unique");
    }

    #[test]
    fn graph_colors_have_distinct_ids() {
        let ids: Vec<String> = vec![
            Colors::graph_vertex_fill().id(),
            Colors::graph_vertex_border().id(),
            Colors::graph_edge().id(),
            Colors::graph_edge_highlight().id(),
            Colors::graph_background().id(),
        ];
        let original_len = ids.len();
        let mut deduped = ids.clone();
        deduped.sort();
        deduped.dedup();
        assert_eq!(deduped.len(), original_len, "graph color IDs should be unique");
    }

    #[test]
    fn font_constants_non_empty() {
        assert!(!Fonts::DEFAULT.is_empty());
        assert!(!Fonts::MONOSPACED.is_empty());
        assert!(!Fonts::LISTING.is_empty());
        assert!(!Fonts::DECOMPILER.is_empty());
        assert!(!Fonts::SMALL.is_empty());
        assert!(!Fonts::LARGE.is_empty());
        assert!(!Fonts::BOLD.is_empty());
        assert!(!Fonts::ITALIC.is_empty());
        assert!(!Fonts::TABLE_HEADER.is_empty());
        assert!(!Fonts::TABLE_CELL.is_empty());
        assert!(!Fonts::TOOLTIP.is_empty());
        assert!(!Fonts::STATUS_BAR.is_empty());
    }

    #[test]
    fn font_constants_unique() {
        let fonts = [
            Fonts::DEFAULT, Fonts::MONOSPACED, Fonts::SMALL, Fonts::LARGE,
            Fonts::BOLD, Fonts::ITALIC, Fonts::LISTING, Fonts::DECOMPILER,
            Fonts::TABLE_HEADER, Fonts::TABLE_CELL, Fonts::TOOLTIP, Fonts::STATUS_BAR,
        ];
        for i in 0..fonts.len() {
            for j in (i + 1)..fonts.len() {
                assert_ne!(fonts[i], fonts[j], "Font {} and {} should be unique", i, j);
            }
        }
    }

    #[test]
    fn icon_constants_non_empty() {
        assert!(!Icons::NAVIGATE_BACK.is_empty());
        assert!(!Icons::NEW.is_empty());
        assert!(!Icons::DECOMPILER.is_empty());
        assert!(!Icons::LISTING.is_empty());
        assert!(!Icons::GRAPH.is_empty());
        assert!(!Icons::FUNCTION.is_empty());
        assert!(!Icons::SAVE.is_empty());
        assert!(!Icons::SEARCH.is_empty());
        assert!(!Icons::FOLDER.is_empty());
        assert!(!Icons::FILE.is_empty());
    }

    #[test]
    fn icon_constants_unique() {
        let icons = [
            Icons::NAVIGATE_BACK, Icons::NAVIGATE_FORWARD, Icons::NEW, Icons::OPEN,
            Icons::SAVE, Icons::CLOSE, Icons::CUT, Icons::COPY, Icons::PASTE,
            Icons::DELETE, Icons::UNDO, Icons::REDO, Icons::SEARCH, Icons::FILTER,
            Icons::REFRESH, Icons::SETTINGS, Icons::HELP, Icons::INFO, Icons::WARNING,
            Icons::ERROR, Icons::OK, Icons::EXPAND, Icons::COLLAPSE, Icons::FOLDER,
            Icons::FILE, Icons::DECOMPILER, Icons::LISTING, Icons::GRAPH,
            Icons::FUNCTION, Icons::SYMBOL, Icons::BOOKMARK, Icons::BREAKPOINT,
            Icons::MEMORY, Icons::REGISTER, Icons::PROGRAM, Icons::BINARY,
            Icons::ANALYSIS,
        ];
        for i in 0..icons.len() {
            for j in (i + 1)..icons.len() {
                assert_ne!(icons[i], icons[j], "Icon {} and {} should be unique", i, j);
            }
        }
    }

    #[test]
    fn color_ids_follow_naming_convention() {
        // All listing colors should start with "color.listing."
        let listing_colors = vec![
            Colors::listing_address(), Colors::listing_bytes(),
            Colors::listing_comment(), Colors::listing_keyword(),
        ];
        for c in &listing_colors {
            assert!(c.id().starts_with("color.listing."), "Expected prefix 'color.listing.' in '{}'", c.id());
        }
        // All decompiler colors should start with "color.decompiler."
        let decompiler_colors = vec![
            Colors::decompiler_default(), Colors::decompiler_keyword(),
            Colors::decompiler_type(), Colors::decompiler_function(),
        ];
        for c in &decompiler_colors {
            assert!(c.id().starts_with("color.decompiler."), "Expected prefix 'color.decompiler.' in '{}'", c.id());
        }
    }
}
