//! Slice highlight color provider -- Rust port of
//! `ghidra.app.plugin.core.decompile.actions.SliceHighlightColorProvider`.
//!
//! Provides the coloring logic for the forward-slice and backward-slice
//! highlight actions.  When the user invokes a slice action, the
//! decompiler panel highlights all tokens whose underlying varnodes are
//! in the slice set.  A "special" varnode/op pair receives a distinct
//! highlight color (typically the seed varnode of the slice).
//!
//! # Architecture
//!
//! ```text
//! SliceHighlightColorProvider
//!   ├── varnodes: HashSet<Varnode>   (the full slice set)
//!   ├── special_vn: Option<Varnode>  (the seed varnode)
//!   ├── special_op: Option<PcodeOp>  (the seed p-code op)
//!   ├── hl_color: Color              (normal slice highlight)
//!   └── special_hl_color: Color      (seed highlight)
//! ```
//!
//! The provider implements [`ColorProvider`], which the decompiler panel
//! queries on each token to decide its background color.

use std::collections::HashSet;
use std::fmt;

// ---------------------------------------------------------------------------
// Varnode -- lightweight stand-in for P-code varnodes
// ---------------------------------------------------------------------------

/// A P-code varnode reference.
///
/// In Ghidra this is `ghidra.program.model.pcode.Varnode`, which
/// identifies a contiguous range of bytes in an address space.  Here we
/// store the address offset and size, which is sufficient for identity
/// comparisons within a single function's decompilation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Varnode {
    /// The address offset of this varnode.
    pub offset: u64,
    /// The size in bytes.
    pub size: u16,
    /// The address space id (0 = default/physical).
    pub space_id: u32,
}

impl Varnode {
    /// Create a new varnode reference.
    pub fn new(offset: u64, size: u16, space_id: u32) -> Self {
        Self { offset, size, space_id }
    }

    /// Create a varnode in the default address space.
    pub fn default_space(offset: u64, size: u16) -> Self {
        Self::new(offset, size, 0)
    }
}

impl fmt::Display for Varnode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "vn({:#x}, {}b, sp={})", self.offset, self.size, self.space_id)
    }
}

// ---------------------------------------------------------------------------
// PcodeOp -- lightweight stand-in for P-code operations
// ---------------------------------------------------------------------------

/// A P-code operation reference.
///
/// In Ghidra this is `ghidra.program.model.pcode.PcodeOp`.  Here we
/// store just enough to identify the op within a function's P-code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PcodeOp {
    /// The sequence number of this op within the function.
    pub seq_num: u64,
    /// The P-code opcode.
    pub opcode: u16,
}

impl PcodeOp {
    /// Create a new P-code op reference.
    pub fn new(seq_num: u64, opcode: u16) -> Self {
        Self { seq_num, opcode }
    }
}

// ---------------------------------------------------------------------------
// Color -- RGBA color
// ---------------------------------------------------------------------------

/// An RGBA color value.
///
/// Mirrors the `java.awt.Color` usage in the Java implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Color {
    /// Red component (0-255).
    pub r: u8,
    /// Green component (0-255).
    pub g: u8,
    /// Blue component (0-255).
    pub b: u8,
    /// Alpha component (0-255, 255 = opaque).
    pub a: u8,
}

impl Color {
    /// Create a new color.
    pub const fn new(r: u8, g: u8, b: u8, a: u8) -> Self {
        Self { r, g, b, a }
    }

    /// Create an opaque color.
    pub const fn rgb(r: u8, g: u8, b: u8) -> Self {
        Self::new(r, g, b, 255)
    }

    /// Yellow (commonly used for highlight).
    pub const YELLOW: Self = Self::rgb(255, 255, 0);

    /// Cyan (commonly used for special highlight).
    pub const CYAN: Self = Self::rgb(0, 255, 255);

    /// Light green.
    pub const LIGHT_GREEN: Self = Self::rgb(144, 238, 144);

    /// Light blue.
    pub const LIGHT_BLUE: Self = Self::rgb(173, 216, 230);

    /// Convert to a CSS-style hex string (e.g., `"#FFFF00"`).
    pub fn to_hex(&self) -> String {
        format!("#{:02X}{:02X}{:02X}", self.r, self.g, self.b)
    }
}

impl fmt::Display for Color {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Color({}, {}, {}, {})", self.r, self.g, self.b, self.a)
    }
}

// ---------------------------------------------------------------------------
// TokenInfo -- minimal token info needed for coloring
// ---------------------------------------------------------------------------

/// Minimal token information needed by the color provider.
///
/// This is a simplified version of [`ClangTokenRef`](super::action_context::ClangTokenRef)
/// containing only the fields required for varnode-based coloring.
#[derive(Debug, Clone)]
pub struct TokenInfo {
    /// The displayed text of the token.
    pub text: String,
    /// The underlying varnode reference (if this token maps to a varnode).
    pub varnode: Option<Varnode>,
    /// The P-code op this token belongs to (if any).
    pub pcode_op: Option<PcodeOp>,
}

impl TokenInfo {
    /// Create a new token info.
    pub fn new(text: impl Into<String>, varnode: Option<Varnode>, pcode_op: Option<PcodeOp>) -> Self {
        Self {
            text: text.into(),
            varnode,
            pcode_op,
        }
    }

    /// Create a token info with no varnode mapping.
    pub fn syntax(text: impl Into<String>) -> Self {
        Self::new(text, None, None)
    }
}

// ---------------------------------------------------------------------------
// ColorProvider trait
// ---------------------------------------------------------------------------

/// A provider that supplies highlight colors for tokens.
///
/// The decompiler panel calls `get_color` for each visible token to
/// determine its background highlight color.  Returning `None` means
/// "no highlight for this token".
pub trait ColorProvider: fmt::Debug + Send + Sync {
    /// Returns the highlight color for the given token, or `None` if the
    /// token should not be highlighted.
    fn get_color(&self, token: &TokenInfo) -> Option<Color>;
}

// ---------------------------------------------------------------------------
// SliceHighlightColorProvider
// ---------------------------------------------------------------------------

/// Provides highlight colors for slice-based highlighting.
///
/// When a forward or backward slice is computed, the set of varnodes in
/// the slice is passed to this provider.  Each token in the decompiler
/// panel is then colored:
///
/// - **Normal highlight**: any token whose varnode is in the slice set.
/// - **Special highlight**: the specific varnode/pcode-op pair that
///   seeded the slice (e.g., the variable the user right-clicked).
///
/// # Example
///
/// ```
/// use ghidra_features::decompile_ui::slice_color_provider::*;
///
/// let varnodes = vec![
///     Varnode::default_space(0x1000, 4),
///     Varnode::default_space(0x1004, 4),
/// ];
/// let special_vn = Varnode::default_space(0x1000, 4);
/// let special_op = PcodeOp::new(42, 1);
///
/// let provider = SliceHighlightColorProvider::new(
///     &varnodes,
///     Some(special_vn),
///     Some(special_op),
///     Color::YELLOW,
///     Color::CYAN,
/// );
///
/// // A token whose varnode is in the slice set.
/// let slice_token = TokenInfo::new("x", Some(Varnode::default_space(0x1000, 4)), Some(PcodeOp::new(42, 1)));
/// assert_eq!(provider.get_color(&slice_token), Some(Color::CYAN));
///
/// // A token whose varnode is NOT in the slice set.
/// let other_token = TokenInfo::new("y", Some(Varnode::default_space(0x2000, 4)), None);
/// assert_eq!(provider.get_color(&other_token), None);
/// ```
#[derive(Debug)]
pub struct SliceHighlightColorProvider {
    /// The set of varnodes in the slice.
    varnodes: HashSet<Varnode>,
    /// The special (seed) varnode, if any.
    special_vn: Option<Varnode>,
    /// The special (seed) p-code op, if any.
    special_op: Option<PcodeOp>,
    /// The normal slice highlight color.
    hl_color: Color,
    /// The special (seed) highlight color.
    special_hl_color: Color,
}

impl SliceHighlightColorProvider {
    /// Create a new slice highlight color provider.
    ///
    /// # Arguments
    ///
    /// * `varnodes` - The set of varnodes in the slice.
    /// * `special_vn` - The seed varnode (receives the special color).
    /// * `special_op` - The seed p-code op (used to match the special varnode).
    /// * `hl_color` - The normal highlight color.
    /// * `special_hl_color` - The special highlight color for the seed.
    pub fn new(
        varnodes: &[Varnode],
        special_vn: Option<Varnode>,
        special_op: Option<PcodeOp>,
        hl_color: Color,
        special_hl_color: Color,
    ) -> Self {
        Self {
            varnodes: varnodes.iter().copied().collect(),
            special_vn,
            special_op,
            hl_color,
            special_hl_color,
        }
    }

    /// Create a provider with default colors (yellow for normal, cyan for special).
    pub fn with_default_colors(
        varnodes: &[Varnode],
        special_vn: Option<Varnode>,
        special_op: Option<PcodeOp>,
    ) -> Self {
        Self::new(varnodes, special_vn, special_op, Color::YELLOW, Color::CYAN)
    }

    /// Returns the number of varnodes in the slice set.
    pub fn varnode_count(&self) -> usize {
        self.varnodes.len()
    }

    /// Returns `true` if the given varnode is in the slice set.
    pub fn contains_varnode(&self, vn: &Varnode) -> bool {
        self.varnodes.contains(vn)
    }

    /// Returns the normal highlight color.
    pub fn highlight_color(&self) -> Color {
        self.hl_color
    }

    /// Returns the special highlight color.
    pub fn special_highlight_color(&self) -> Color {
        self.special_hl_color
    }

    /// Returns the special varnode, if any.
    pub fn special_varnode(&self) -> Option<Varnode> {
        self.special_vn
    }

    /// Returns the special p-code op, if any.
    pub fn special_pcode_op(&self) -> Option<PcodeOp> {
        self.special_op
    }
}

impl ColorProvider for SliceHighlightColorProvider {
    /// Returns the highlight color for the given token.
    ///
    /// The logic mirrors Ghidra's `SliceHighlightColorProvider.getColor()`:
    ///
    /// 1. If the token has no varnode, return `None`.
    /// 2. If the token's varnode is in the slice set, return `hl_color`.
    /// 3. If the token's varnode matches the special varnode AND the
    ///    token's pcode op matches the special op, return
    ///    `special_hl_color` (overriding the normal color).
    fn get_color(&self, token: &TokenInfo) -> Option<Color> {
        let vn = token.varnode?;

        let mut color = if self.varnodes.contains(&vn) {
            Some(self.hl_color)
        } else {
            None
        };

        // Check for the special varnode/op pair.
        if let (Some(special_vn), Some(special_op)) = (self.special_vn, self.special_op) {
            if vn == special_vn && token.pcode_op == Some(special_op) {
                color = Some(self.special_hl_color);
            }
        }

        color
    }
}

impl fmt::Display for SliceHighlightColorProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Slice Color Provider {} ({} varnodes)",
            self.hl_color,
            self.varnodes.len()
        )
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- Varnode ---

    #[test]
    fn test_varnode_new() {
        let vn = Varnode::new(0x1000, 4, 0);
        assert_eq!(vn.offset, 0x1000);
        assert_eq!(vn.size, 4);
        assert_eq!(vn.space_id, 0);
    }

    #[test]
    fn test_varnode_default_space() {
        let vn = Varnode::default_space(0x2000, 8);
        assert_eq!(vn.space_id, 0);
        assert_eq!(vn.size, 8);
    }

    #[test]
    fn test_varnode_equality() {
        let a = Varnode::default_space(0x1000, 4);
        let b = Varnode::default_space(0x1000, 4);
        let c = Varnode::default_space(0x1000, 8);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn test_varnode_display() {
        let vn = Varnode::default_space(0x1000, 4);
        let s = format!("{}", vn);
        assert!(s.contains("0x1000"));
        assert!(s.contains("4b"));
    }

    #[test]
    fn test_varnode_hash_set() {
        let mut set = HashSet::new();
        set.insert(Varnode::default_space(0x1000, 4));
        set.insert(Varnode::default_space(0x1000, 4)); // duplicate
        set.insert(Varnode::default_space(0x2000, 4));
        assert_eq!(set.len(), 2);
    }

    // --- PcodeOp ---

    #[test]
    fn test_pcode_op_new() {
        let op = PcodeOp::new(42, 1);
        assert_eq!(op.seq_num, 42);
        assert_eq!(op.opcode, 1);
    }

    #[test]
    fn test_pcode_op_equality() {
        let a = PcodeOp::new(1, 2);
        let b = PcodeOp::new(1, 2);
        let c = PcodeOp::new(1, 3);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    // --- Color ---

    #[test]
    fn test_color_rgb() {
        let c = Color::rgb(255, 128, 0);
        assert_eq!(c.r, 255);
        assert_eq!(c.g, 128);
        assert_eq!(c.b, 0);
        assert_eq!(c.a, 255);
    }

    #[test]
    fn test_color_new_with_alpha() {
        let c = Color::new(100, 200, 50, 128);
        assert_eq!(c.a, 128);
    }

    #[test]
    fn test_color_to_hex() {
        assert_eq!(Color::YELLOW.to_hex(), "#FFFF00");
        assert_eq!(Color::CYAN.to_hex(), "#00FFFF");
    }

    #[test]
    fn test_color_display() {
        let s = format!("{}", Color::YELLOW);
        assert!(s.contains("255"));
    }

    #[test]
    fn test_color_constants() {
        assert_eq!(Color::YELLOW, Color::rgb(255, 255, 0));
        assert_eq!(Color::CYAN, Color::rgb(0, 255, 255));
    }

    // --- TokenInfo ---

    #[test]
    fn test_token_info_syntax() {
        let t = TokenInfo::syntax("if");
        assert_eq!(t.text, "if");
        assert!(t.varnode.is_none());
        assert!(t.pcode_op.is_none());
    }

    #[test]
    fn test_token_info_with_varnode() {
        let vn = Varnode::default_space(0x1000, 4);
        let t = TokenInfo::new("x", Some(vn), None);
        assert_eq!(t.varnode.unwrap().offset, 0x1000);
    }

    // --- SliceHighlightColorProvider ---

    fn make_varnodes() -> Vec<Varnode> {
        vec![
            Varnode::default_space(0x1000, 4),
            Varnode::default_space(0x1004, 4),
            Varnode::default_space(0x1008, 4),
        ]
    }

    #[test]
    fn test_provider_new() {
        let vns = make_varnodes();
        let provider = SliceHighlightColorProvider::new(
            &vns,
            None,
            None,
            Color::YELLOW,
            Color::CYAN,
        );
        assert_eq!(provider.varnode_count(), 3);
        assert_eq!(provider.highlight_color(), Color::YELLOW);
        assert_eq!(provider.special_highlight_color(), Color::CYAN);
    }

    #[test]
    fn test_provider_with_default_colors() {
        let vns = make_varnodes();
        let provider = SliceHighlightColorProvider::with_default_colors(&vns, None, None);
        assert_eq!(provider.highlight_color(), Color::YELLOW);
        assert_eq!(provider.special_highlight_color(), Color::CYAN);
    }

    #[test]
    fn test_provider_contains_varnode() {
        let vns = make_varnodes();
        let provider = SliceHighlightColorProvider::with_default_colors(&vns, None, None);

        assert!(provider.contains_varnode(&Varnode::default_space(0x1000, 4)));
        assert!(!provider.contains_varnode(&Varnode::default_space(0x2000, 4)));
    }

    #[test]
    fn test_provider_get_color_no_varnode() {
        let vns = make_varnodes();
        let provider = SliceHighlightColorProvider::with_default_colors(&vns, None, None);

        // Token with no varnode mapping.
        let token = TokenInfo::syntax("if");
        assert_eq!(provider.get_color(&token), None);
    }

    #[test]
    fn test_provider_get_color_in_slice() {
        let vns = make_varnodes();
        let provider = SliceHighlightColorProvider::with_default_colors(&vns, None, None);

        // Token whose varnode is in the slice set.
        let token = TokenInfo::new("x", Some(Varnode::default_space(0x1000, 4)), None);
        assert_eq!(provider.get_color(&token), Some(Color::YELLOW));
    }

    #[test]
    fn test_provider_get_color_not_in_slice() {
        let vns = make_varnodes();
        let provider = SliceHighlightColorProvider::with_default_colors(&vns, None, None);

        // Token whose varnode is NOT in the slice set.
        let token = TokenInfo::new("y", Some(Varnode::default_space(0x2000, 4)), None);
        assert_eq!(provider.get_color(&token), None);
    }

    #[test]
    fn test_provider_get_color_special_varnode() {
        let vns = make_varnodes();
        let special_vn = Varnode::default_space(0x1000, 4);
        let special_op = PcodeOp::new(42, 1);
        let provider = SliceHighlightColorProvider::new(
            &vns,
            Some(special_vn),
            Some(special_op),
            Color::YELLOW,
            Color::CYAN,
        );

        // Token matching the special varnode AND special op.
        let token = TokenInfo::new(
            "x",
            Some(Varnode::default_space(0x1000, 4)),
            Some(PcodeOp::new(42, 1)),
        );
        assert_eq!(provider.get_color(&token), Some(Color::CYAN));
    }

    #[test]
    fn test_provider_get_color_special_varnode_wrong_op() {
        let vns = make_varnodes();
        let special_vn = Varnode::default_space(0x1000, 4);
        let special_op = PcodeOp::new(42, 1);
        let provider = SliceHighlightColorProvider::new(
            &vns,
            Some(special_vn),
            Some(special_op),
            Color::YELLOW,
            Color::CYAN,
        );

        // Token matching the special varnode but with a DIFFERENT op.
        let token = TokenInfo::new(
            "x",
            Some(Varnode::default_space(0x1000, 4)),
            Some(PcodeOp::new(99, 1)),
        );
        // Should get the normal highlight color, not the special one.
        assert_eq!(provider.get_color(&token), Some(Color::YELLOW));
    }

    #[test]
    fn test_provider_get_color_special_varnode_no_op() {
        let vns = make_varnodes();
        let special_vn = Varnode::default_space(0x1000, 4);
        let special_op = PcodeOp::new(42, 1);
        let provider = SliceHighlightColorProvider::new(
            &vns,
            Some(special_vn),
            Some(special_op),
            Color::YELLOW,
            Color::CYAN,
        );

        // Token matching the special varnode but with no op at all.
        let token = TokenInfo::new("x", Some(Varnode::default_space(0x1000, 4)), None);
        // Should get the normal highlight color.
        assert_eq!(provider.get_color(&token), Some(Color::YELLOW));
    }

    #[test]
    fn test_provider_no_special() {
        let vns = make_varnodes();
        let provider = SliceHighlightColorProvider::new(
            &vns,
            None, // no special varnode
            None,
            Color::YELLOW,
            Color::CYAN,
        );

        let token = TokenInfo::new(
            "x",
            Some(Varnode::default_space(0x1000, 4)),
            Some(PcodeOp::new(42, 1)),
        );
        // Without a special varnode, should get the normal color.
        assert_eq!(provider.get_color(&token), Some(Color::YELLOW));
    }

    #[test]
    fn test_provider_special_only_special_op() {
        let vns = make_varnodes();
        // special_vn is set but special_op is None.
        let provider = SliceHighlightColorProvider::new(
            &vns,
            Some(Varnode::default_space(0x1000, 4)),
            None, // no special op
            Color::YELLOW,
            Color::CYAN,
        );

        let token = TokenInfo::new(
            "x",
            Some(Varnode::default_space(0x1000, 4)),
            Some(PcodeOp::new(42, 1)),
        );
        // Without a special op, the special color is never applied.
        assert_eq!(provider.get_color(&token), Some(Color::YELLOW));
    }

    #[test]
    fn test_provider_empty_varnodes() {
        let provider = SliceHighlightColorProvider::with_default_colors(&[], None, None);

        let token = TokenInfo::new("x", Some(Varnode::default_space(0x1000, 4)), None);
        assert_eq!(provider.get_color(&token), None);
    }

    #[test]
    fn test_provider_display() {
        let vns = make_varnodes();
        let provider = SliceHighlightColorProvider::with_default_colors(&vns, None, None);
        let s = format!("{}", provider);
        assert!(s.contains("Slice Color Provider"));
        assert!(s.contains("3 varnodes"));
    }

    #[test]
    fn test_provider_special_accessors() {
        let vns = make_varnodes();
        let special_vn = Varnode::default_space(0x1000, 4);
        let special_op = PcodeOp::new(42, 1);
        let provider = SliceHighlightColorProvider::new(
            &vns,
            Some(special_vn),
            Some(special_op),
            Color::YELLOW,
            Color::CYAN,
        );

        assert_eq!(provider.special_varnode(), Some(special_vn));
        assert_eq!(provider.special_pcode_op(), Some(special_op));
    }

    #[test]
    fn test_provider_duplicate_varnodes() {
        // Adding the same varnode twice should not increase the count.
        let vns = vec![
            Varnode::default_space(0x1000, 4),
            Varnode::default_space(0x1000, 4),
            Varnode::default_space(0x1004, 4),
        ];
        let provider = SliceHighlightColorProvider::with_default_colors(&vns, None, None);
        assert_eq!(provider.varnode_count(), 2);
    }
}
