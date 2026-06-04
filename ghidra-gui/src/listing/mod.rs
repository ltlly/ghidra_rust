//! Disassembly listing view for the Ghidra GUI.
//!
//! The main code browser view showing the disassembly listing with
//! address, bytes, labels, mnemonics, operands, and cross-references.
//! Supports syntax highlighting, clickable addresses for navigation,
//! right-click context menus, and virtual scrolling.
//!
//! ## Architecture
//!
//! The listing view is composed of:
//! - **Rich data types** ([`ListingRow`], [`RenderedOperand`], [`RowType`]) that
//!   model each row in the disassembly.
//! - **Column layout** ([`ColumnLayout`]) managing column widths and resize.
//! - **Syntax theme** ([`SyntaxTheme`]) for configurable coloring.
//! - **View state** ([`ListingView`]) tracking cursor, selection, navigation.
//! - **Renderer** ([`render_listing_view`]) that paints the view into an egui [`Ui`].

pub mod disassembly;
pub mod field_formatter;
mod render;

pub use render::render_listing_view;

use ghidra_core::addr::{Address, AddressRange};
use ghidra_core::listing::ListingColumns;
use std::collections::{HashMap, HashSet};

// ============================================================================
// Rich Listing Row Types
// ============================================================================

/// The type of a rendered operand for syntax coloring.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OperandRenderType {
    /// A CPU register (e.g., "rax", "eip").
    Register,
    /// An immediate value — hex or decimal constant.
    Immediate,
    /// An address reference (e.g., "0x401000").
    Address,
    /// A scalar displacement or offset.
    Scalar,
    /// A label / symbol name.
    Label,
    /// A string literal.
    String,
    /// A named constant / enum value.
    Constant,
}

/// A single operand rendered with typing information for syntax coloring
/// and navigation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderedOperand {
    /// The display text of this operand.
    pub text: String,
    /// The type of operand (register, immediate, address, etc.).
    pub op_type: OperandRenderType,
    /// If this operand references another address, the target.
    pub target_address: Option<Address>,
}

impl RenderedOperand {
    /// Create a register operand.
    pub fn register(name: impl Into<String>) -> Self {
        Self {
            text: name.into(),
            op_type: OperandRenderType::Register,
            target_address: None,
        }
    }

    /// Create an immediate operand.
    pub fn immediate(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            op_type: OperandRenderType::Immediate,
            target_address: None,
        }
    }

    /// Create an address reference operand.
    pub fn address(text: impl Into<String>, target: Address) -> Self {
        Self {
            text: text.into(),
            op_type: OperandRenderType::Address,
            target_address: Some(target),
        }
    }

    /// Create a scalar operand.
    pub fn scalar(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            op_type: OperandRenderType::Scalar,
            target_address: None,
        }
    }

    /// Create a label operand.
    pub fn label(text: impl Into<String>, target: Option<Address>) -> Self {
        Self {
            text: text.into(),
            op_type: OperandRenderType::Label,
            target_address: target,
        }
    }

    /// Create a string operand.
    pub fn string(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            op_type: OperandRenderType::String,
            target_address: None,
        }
    }

    /// Create a constant operand.
    pub fn constant(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            op_type: OperandRenderType::Constant,
            target_address: None,
        }
    }
}

/// The semantic type of a listing row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RowType {
    /// A decoded processor instruction.
    Instruction,
    /// A data item (bytes, words, strings, etc.).
    Data,
    /// A label-only line (no instruction/data at this address).
    Label,
    /// A comment-only line.
    Comment,
    /// A visual separator line.
    Separator,
    /// An empty/padding row.
    Empty,
}

/// A single row in the disassembly listing view.
///
/// This is the rich GUI-level representation, converted from the core
/// [`ghidra_core::listing::ListingRow`].
#[derive(Debug, Clone)]
pub struct ListingRow {
    /// The address of this row.
    pub address: Address,
    /// The raw bytes at this address.
    pub bytes: Vec<u8>,
    /// Optional label at this address (function name, symbol label).
    pub label: Option<String>,
    /// The instruction mnemonic (e.g., "mov", "call", "push").
    pub mnemonic: String,
    /// The parsed operands with type information.
    pub operands: Vec<RenderedOperand>,
    /// Cross-references TO this address (as display strings).
    pub xrefs_to: Vec<String>,
    /// Optional comment on this row.
    pub comment: Option<String>,
    /// Whether this row contains an instruction.
    pub is_instruction: bool,
    /// The semantic row type.
    pub row_type: RowType,
}

impl ListingRow {
    /// Create an empty row for the given address.
    pub fn empty(address: Address) -> Self {
        Self {
            address,
            bytes: Vec::new(),
            label: None,
            mnemonic: String::new(),
            operands: Vec::new(),
            xrefs_to: Vec::new(),
            comment: None,
            is_instruction: false,
            row_type: RowType::Empty,
        }
    }

    /// Create an instruction row.
    pub fn instruction(
        address: Address,
        bytes: Vec<u8>,
        mnemonic: impl Into<String>,
        operands: Vec<RenderedOperand>,
    ) -> Self {
        Self {
            address,
            bytes,
            label: None,
            mnemonic: mnemonic.into(),
            operands,
            xrefs_to: Vec::new(),
            comment: None,
            is_instruction: true,
            row_type: RowType::Instruction,
        }
    }

    /// Create a data row.
    pub fn data(address: Address, bytes: Vec<u8>, label: Option<String>) -> Self {
        Self {
            address,
            bytes,
            label,
            mnemonic: String::new(),
            operands: Vec::new(),
            xrefs_to: Vec::new(),
            comment: None,
            is_instruction: false,
            row_type: RowType::Data,
        }
    }

    /// Create a label row.
    pub fn label_row(address: Address, label: impl Into<String>) -> Self {
        Self {
            address,
            bytes: Vec::new(),
            label: Some(label.into()),
            mnemonic: String::new(),
            operands: Vec::new(),
            xrefs_to: Vec::new(),
            comment: None,
            is_instruction: false,
            row_type: RowType::Label,
        }
    }

    /// Create a separator row.
    pub fn separator(address: Address) -> Self {
        Self {
            address,
            bytes: Vec::new(),
            label: None,
            mnemonic: String::new(),
            operands: Vec::new(),
            xrefs_to: Vec::new(),
            comment: None,
            is_instruction: false,
            row_type: RowType::Separator,
        }
    }

    /// Create a comment row.
    pub fn comment_row(address: Address, comment: impl Into<String>) -> Self {
        Self {
            address,
            bytes: Vec::new(),
            label: None,
            mnemonic: String::new(),
            operands: Vec::new(),
            xrefs_to: Vec::new(),
            comment: Some(comment.into()),
            is_instruction: false,
            row_type: RowType::Comment,
        }
    }

    /// Convert from a core [`ghidra_core::listing::ListingRow`] into this rich type.
    ///
    /// Operands are parsed and classified, labels and comments are set from
    /// the provided lookup maps.
    pub fn from_core(
        row: &ghidra_core::listing::ListingRow,
        labels: &HashMap<Address, String>,
        comments: &HashMap<Address, String>,
        xrefs: &HashMap<Address, Vec<Address>>,
    ) -> Self {
        let label = row
            .label
            .clone()
            .or_else(|| labels.get(&row.address).cloned());
        let comment = row
            .comment
            .clone()
            .or_else(|| comments.get(&row.address).cloned());
        let xrefs_to: Vec<String> = xrefs
            .get(&row.address)
            .map(|refs| refs.iter().map(|a| format!("{:08X}", a.offset)).collect())
            .unwrap_or_default();

        // Classify each operand token
        let operands = classify_operands(&row.operands);

        Self {
            address: row.address,
            bytes: row.bytes.clone(),
            label,
            mnemonic: row.mnemonic.text.clone(),
            operands,
            xrefs_to,
            comment,
            is_instruction: !row.mnemonic.text.is_empty(),
            row_type: if row.mnemonic.text.is_empty() {
                RowType::Data
            } else {
                RowType::Instruction
            },
        }
    }
}

/// Helper: classify operand tokens from a raw operand string into
/// [`RenderedOperand`] instances with type information.
fn classify_operands(operands: &str) -> Vec<RenderedOperand> {
    if operands.is_empty() {
        return Vec::new();
    }

    let mut result = Vec::new();
    let tokens = tokenize_operand_string(operands);

    for token in tokens {
        let rendered = classify_single_token(&token);
        result.push(rendered);
    }

    result
}

/// A raw token from splitting an operand string.
#[derive(Debug, Clone)]
struct RawOperandToken {
    text: String,
    is_separator: bool,
}

/// Split an operand string into meaningful tokens.
fn tokenize_operand_string(s: &str) -> Vec<RawOperandToken> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let separators: &[char] = &[
        '[', ']', ',', '<', '>', '+', '-', '*', '(', ')', ':', '{', '}',
    ];

    let mut chars = s.chars().peekable();
    while let Some(&ch) = chars.peek() {
        if ch.is_whitespace() {
            chars.next();
            if !current.is_empty() {
                tokens.push(RawOperandToken {
                    text: std::mem::take(&mut current),
                    is_separator: false,
                });
            }
            continue;
        }

        if separators.contains(&ch) {
            if !current.is_empty() {
                tokens.push(RawOperandToken {
                    text: std::mem::take(&mut current),
                    is_separator: false,
                });
            }
            tokens.push(RawOperandToken {
                text: ch.to_string(),
                is_separator: true,
            });
            chars.next();
            continue;
        }

        // Collect word characters
        current.push(ch);
        chars.next();
    }

    if !current.is_empty() {
        tokens.push(RawOperandToken {
            text: current,
            is_separator: false,
        });
    }

    tokens
}

/// Known x86/x86-64 register names for classification.
static KNOWN_REGISTERS: &[&str] = &[
    // General purpose 64-bit
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12", "r13",
    "r14", "r15", // General purpose 32-bit
    "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "r8d", "r9d", "r10d", "r11d", "r12d",
    "r13d", "r14d", "r15d", // General purpose 16-bit
    "ax", "bx", "cx", "dx", "si", "di", "bp", "sp", "r8w", "r9w", "r10w", "r11w", "r12w", "r13w",
    "r14w", "r15w", // General purpose 8-bit
    "al", "ah", "bl", "bh", "cl", "ch", "dl", "dh", "sil", "dil", "bpl", "spl", "r8b", "r9b",
    "r10b", "r11b", "r12b", "r13b", "r14b", "r15b", // Instruction pointer
    "rip", "eip", "ip", // Segment registers
    "cs", "ds", "es", "fs", "gs", "ss", // XMM registers
    "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7", "xmm8", "xmm9", "xmm10",
    "xmm11", "xmm12", "xmm13", "xmm14", "xmm15", // YMM registers
    "ymm0", "ymm1", "ymm2", "ymm3", "ymm4", "ymm5", "ymm6", "ymm7", "ymm8", "ymm9", "ymm10",
    "ymm11", "ymm12", "ymm13", "ymm14", "ymm15", // Other
    "st0", "st1", "st2", "st3", "st4", "st5", "st6", "st7", "mm0", "mm1", "mm2", "mm3", "mm4",
    "mm5", "mm6", "mm7", "cr0", "cr2", "cr3", "cr4", "cr8", "dr0", "dr1", "dr2", "dr3", "dr6",
    "dr7", "eflags", "rflags",
];

/// Size qualifier keywords found in operand strings.
static SIZE_KEYWORDS: &[&str] = &[
    "byte", "word", "dword", "qword", "xword", "yword", "zword", "oword", "ptr", "PTR", "BYTE",
    "WORD", "DWORD", "QWORD",
];

/// Classify a single operand token into a [`RenderedOperand`].
fn classify_single_token(token: &RawOperandToken) -> RenderedOperand {
    if token.is_separator {
        return RenderedOperand {
            text: token.text.clone(),
            op_type: OperandRenderType::Scalar,
            target_address: None,
        };
    }

    let text = &token.text;
    let lower = text.to_lowercase();

    // Register check
    if KNOWN_REGISTERS.contains(&lower.as_str()) {
        return RenderedOperand::register(text);
    }

    // Size keyword check
    if SIZE_KEYWORDS.iter().any(|kw| text == *kw) {
        return RenderedOperand::scalar(text);
    }

    // Hex number / address
    if text.starts_with("0x") || text.starts_with("0X") {
        let hex_part = &text[2..];
        if hex_part.chars().all(|c| c.is_ascii_hexdigit()) {
            if let Ok(addr_val) = u64::from_str_radix(hex_part, 16) {
                if hex_part.len() >= 4 {
                    return RenderedOperand::address(text, Address::new(addr_val));
                }
                return RenderedOperand::immediate(text);
            }
        }
        return RenderedOperand::immediate(text);
    }

    // Decimal number
    if text.chars().all(|c| c.is_ascii_digit() || c == '-') && text.len() > 1 {
        return RenderedOperand::immediate(text);
    }
    if text.len() == 1 && text.chars().all(|c| c.is_ascii_digit()) {
        return RenderedOperand::immediate(text);
    }

    // Negative hex with minus sign
    if text.starts_with("-0x") || text.starts_with("-0X") {
        let hex_part = &text[3..];
        if hex_part.chars().all(|c| c.is_ascii_hexdigit()) {
            if let Ok(addr_val) = u64::from_str_radix(hex_part, 16) {
                if hex_part.len() >= 4 {
                    return RenderedOperand::address(text, Address::new(addr_val));
                }
            }
            return RenderedOperand::immediate(text);
        }
    }

    // Otherwise, could be a label reference (symbol name)
    if text
        .chars()
        .all(|c| c.is_alphanumeric() || c == '_' || c == '.' || c == '$' || c == '@')
    {
        return RenderedOperand::label(text, None);
    }

    // Fallback: plain text / scalar
    RenderedOperand::scalar(text)
}

// ============================================================================
// Column Management
// ============================================================================

/// Pre-defined column identifiers for the listing view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ColumnId {
    /// Address column.
    Address,
    /// Raw bytes column.
    Bytes,
    /// Label column.
    Label,
    /// Mnemonic column.
    Mnemonic,
    /// Operands column.
    Operands,
    /// Cross-references column.
    XRefs,
    /// Comment column.
    Comment,
}

impl ColumnId {
    /// Human-readable header label.
    pub fn label(&self) -> &'static str {
        match self {
            ColumnId::Address => "Address",
            ColumnId::Bytes => "Bytes",
            ColumnId::Label => "Label",
            ColumnId::Mnemonic => "Mnemonic",
            ColumnId::Operands => "Operands",
            ColumnId::XRefs => "XRef",
            ColumnId::Comment => "Comment",
        }
    }

    /// Default width for this column.
    pub fn default_width(&self) -> f32 {
        match self {
            ColumnId::Address => 90.0,
            ColumnId::Bytes => 130.0,
            ColumnId::Label => 100.0,
            ColumnId::Mnemonic => 80.0,
            ColumnId::Operands => 220.0,
            ColumnId::XRefs => 150.0,
            ColumnId::Comment => 200.0,
        }
    }

    /// Minimum allowed width.
    pub fn min_width(&self) -> f32 {
        match self {
            ColumnId::Address => 50.0,
            ColumnId::Bytes => 40.0,
            ColumnId::Label => 30.0,
            ColumnId::Mnemonic => 40.0,
            ColumnId::Operands => 60.0,
            ColumnId::XRefs => 40.0,
            ColumnId::Comment => 40.0,
        }
    }

    /// Maximum allowed width.
    pub fn max_width(&self) -> f32 {
        match self {
            ColumnId::Address => 150.0,
            ColumnId::Bytes => 250.0,
            ColumnId::Label => 300.0,
            ColumnId::Mnemonic => 150.0,
            ColumnId::Operands => 500.0,
            ColumnId::XRefs => 400.0,
            ColumnId::Comment => 500.0,
        }
    }

    /// All columns in display order.
    pub fn all() -> &'static [ColumnId] {
        &[
            ColumnId::Address,
            ColumnId::Bytes,
            ColumnId::Label,
            ColumnId::Mnemonic,
            ColumnId::Operands,
            ColumnId::XRefs,
            ColumnId::Comment,
        ]
    }
}

/// Defines the layout and sizing of a single column in the listing view.
#[derive(Debug, Clone)]
pub struct ColumnDef {
    /// The column identifier.
    pub id: ColumnId,
    /// Header label for display.
    pub label: String,
    /// Text alignment within the column.
    pub align: egui::Align,
    /// Minimum width in pixels.
    pub min_width: f32,
    /// Maximum width in pixels.
    pub max_width: f32,
    /// Current width in pixels.
    pub current_width: f32,
    /// Whether this column is visible.
    pub visible: bool,
}

impl ColumnDef {
    /// Create a new column definition with defaults.
    pub fn new(id: ColumnId) -> Self {
        Self {
            id,
            label: id.label().to_string(),
            align: match id {
                ColumnId::Address | ColumnId::Bytes => egui::Align::Min,
                ColumnId::XRefs => egui::Align::Max,
                _ => egui::Align::Min,
            },
            min_width: id.min_width(),
            max_width: id.max_width(),
            current_width: id.default_width(),
            visible: true,
        }
    }

    /// Clamp width to min/max bounds.
    pub fn clamp_width(&mut self) {
        self.current_width = self.current_width.clamp(self.min_width, self.max_width);
    }
}

/// Tracks column layout and resize state for the listing view.
#[derive(Debug, Clone)]
pub struct ColumnLayout {
    /// All column definitions in display order.
    pub columns: Vec<ColumnDef>,
    /// Whether the user is currently dragging a resize handle.
    pub resizing: Option<usize>,
    /// The separator strip width.
    pub separator_width: f32,
}

impl ColumnLayout {
    /// Create the default column layout.
    pub fn default_layout() -> Self {
        let columns = ColumnId::all()
            .iter()
            .map(|id| ColumnDef::new(*id))
            .collect();
        Self {
            columns,
            resizing: None,
            separator_width: 6.0,
        }
    }

    /// Get the total width of all visible columns including separators.
    pub fn total_width(&self) -> f32 {
        let visible: Vec<&ColumnDef> = self.columns.iter().filter(|c| c.visible).collect();
        if visible.is_empty() {
            return 0.0;
        }
        let col_width: f32 = visible.iter().map(|c| c.current_width).sum();
        let sep_width: f32 = self.separator_width * (visible.len().saturating_sub(1)) as f32;
        col_width + sep_width
    }

    /// Get a mutable reference to a column by its id.
    pub fn column_mut(&mut self, id: ColumnId) -> Option<&mut ColumnDef> {
        self.columns.iter_mut().find(|c| c.id == id)
    }

    /// Get a reference to a column by its id.
    pub fn column(&self, id: ColumnId) -> Option<&ColumnDef> {
        self.columns.iter().find(|c| c.id == id)
    }

    /// Toggle visibility of a column.
    pub fn toggle_visibility(&mut self, id: ColumnId) {
        if let Some(col) = self.column_mut(id) {
            col.visible = !col.visible;
        }
    }
}

impl Default for ColumnLayout {
    fn default() -> Self {
        Self::default_layout()
    }
}

// ============================================================================
// Syntax Theme
// ============================================================================

/// Syntax highlighting colors for disassembly tokens.
///
/// Each field controls the color of a different syntactic element in the
/// listing view. Colors use [`egui::Color32`].
#[derive(Debug, Clone)]
pub struct SyntaxTheme {
    /// Color for instruction mnemonics (e.g., "mov", "call").
    pub mnemonic: egui::Color32,
    /// Color for register names.
    pub register: egui::Color32,
    /// Color for immediate values (constants).
    pub immediate: egui::Color32,
    /// Color for hexadecimal immediate values.
    pub immediate_hex: egui::Color32,
    /// Color for decimal immediate values.
    pub immediate_dec: egui::Color32,
    /// Color for address references (clickable).
    pub address_ref: egui::Color32,
    /// Color for labels and symbol names.
    pub label: egui::Color32,
    /// Color for string literals.
    pub string: egui::Color32,
    /// Color for comments.
    pub comment: egui::Color32,
    /// Color for the raw bytes display.
    pub bytes: egui::Color32,
    /// Color for the address column.
    pub address: egui::Color32,
    /// Color for separators and punctuation.
    pub separator: egui::Color32,
    /// Color for cross-reference lists.
    pub xref: egui::Color32,
    /// Color for scalar/plain operands.
    pub scalar: egui::Color32,
    /// Color for named constants.
    pub constant: egui::Color32,
    /// Background color for the currently focused row.
    pub cursor_bg: egui::Color32,
    /// Background color for selected rows.
    pub selection_bg: egui::Color32,
    /// Background color for alternating rows (odd rows).
    pub alternating_bg: egui::Color32,
    /// Background color for the listing area.
    pub background: egui::Color32,
    /// Color for column header text.
    pub header_text: egui::Color32,
    /// Background color for column headers.
    pub header_bg: egui::Color32,
    /// Color for the resize handle.
    pub resize_handle: egui::Color32,
    /// Color for the resize handle on hover.
    pub resize_handle_hover: egui::Color32,
}

impl Default for SyntaxTheme {
    fn default() -> Self {
        Self {
            mnemonic: egui::Color32::from_rgb(130, 190, 255), // Blue
            register: egui::Color32::from_rgb(180, 210, 255), // Light blue
            immediate: egui::Color32::from_rgb(100, 255, 130), // Green
            immediate_hex: egui::Color32::from_rgb(100, 255, 130), // Green
            immediate_dec: egui::Color32::from_rgb(100, 230, 255), // Cyan
            address_ref: egui::Color32::from_rgb(255, 220, 120), // Yellow/gold
            label: egui::Color32::from_rgb(255, 200, 100),    // Orange
            string: egui::Color32::from_rgb(255, 180, 100),   // Orange
            comment: egui::Color32::from_rgb(100, 200, 100),  // Green
            bytes: egui::Color32::from_rgb(150, 150, 160),    // Dim gray
            address: egui::Color32::from_rgb(160, 160, 160),  // Gray
            separator: egui::Color32::from_rgb(120, 120, 120), // Dark gray
            xref: egui::Color32::from_rgb(100, 170, 170),     // Dim teal
            scalar: egui::Color32::from_rgb(200, 200, 200),   // Light gray
            constant: egui::Color32::from_rgb(180, 230, 180), // Pale green
            cursor_bg: egui::Color32::from_rgba_premultiplied(255, 255, 100, 35),
            selection_bg: egui::Color32::from_rgba_premultiplied(80, 140, 255, 45),
            alternating_bg: egui::Color32::from_rgba_premultiplied(255, 255, 255, 8),
            background: egui::Color32::from_rgb(30, 30, 35),
            header_text: egui::Color32::from_rgb(180, 200, 220),
            header_bg: egui::Color32::from_rgb(45, 45, 55),
            resize_handle: egui::Color32::from_rgb(60, 60, 70),
            resize_handle_hover: egui::Color32::from_rgb(120, 160, 220),
        }
    }
}

/// Pre-defined dark theme.
pub fn dark_theme() -> SyntaxTheme {
    SyntaxTheme::default()
}

/// Pre-defined light theme.
pub fn light_theme() -> SyntaxTheme {
    SyntaxTheme {
        mnemonic: egui::Color32::from_rgb(0, 0, 180),
        register: egui::Color32::from_rgb(0, 80, 160),
        immediate: egui::Color32::from_rgb(0, 140, 0),
        immediate_hex: egui::Color32::from_rgb(0, 140, 0),
        immediate_dec: egui::Color32::from_rgb(0, 120, 140),
        address_ref: egui::Color32::from_rgb(180, 120, 0),
        label: egui::Color32::from_rgb(180, 100, 0),
        string: egui::Color32::from_rgb(160, 80, 0),
        comment: egui::Color32::from_rgb(0, 130, 0),
        bytes: egui::Color32::from_rgb(100, 100, 110),
        address: egui::Color32::from_rgb(80, 80, 90),
        separator: egui::Color32::from_rgb(150, 150, 150),
        xref: egui::Color32::from_rgb(60, 120, 120),
        scalar: egui::Color32::from_rgb(60, 60, 60),
        constant: egui::Color32::from_rgb(60, 140, 60),
        cursor_bg: egui::Color32::from_rgba_premultiplied(255, 255, 200, 60),
        selection_bg: egui::Color32::from_rgba_premultiplied(100, 160, 255, 50),
        alternating_bg: egui::Color32::from_rgba_premultiplied(0, 0, 0, 12),
        background: egui::Color32::from_rgb(250, 250, 250),
        header_text: egui::Color32::from_rgb(40, 40, 50),
        header_bg: egui::Color32::from_rgb(220, 225, 235),
        resize_handle: egui::Color32::from_rgb(180, 185, 190),
        resize_handle_hover: egui::Color32::from_rgb(80, 140, 220),
    }
}

// ============================================================================
// Actions Emitted by the Listing View
// ============================================================================

/// Actions that the listing renderer can request from the application.
///
/// Actions are queued in [`ListingView::pending_actions`] and consumed
/// by the application each frame.
#[derive(Debug, Clone)]
pub enum ListingAction {
    /// No action.
    None,
    /// Navigate to an address.
    NavigateTo(Address),
    /// Rename the label at an address.
    RenameLabel(Address),
    /// Remove the label at an address.
    RemoveLabel(Address),
    /// Set or edit a comment at an address.
    SetComment(Address, String),
    /// Delete all comments at an address.
    DeleteComment(Address),
    /// Create a function at an address.
    CreateFunction(Address),
    /// Delete the function at an address.
    DeleteFunction(Address),
    /// Edit function signature at an address.
    EditFunctionSignature(Address),
    /// Disassemble starting at an address.
    Disassemble(Address),
    /// Clear the code unit at an address.
    Clear(Address),
    /// Set data type at an address.
    SetDataType(Address, String),
    /// Create an array at the selection/address.
    CreateArray(Address),
    /// Create a pointer at the selection/address.
    CreatePointer(Address),
    /// Create a structure from the selection/address.
    CreateStructure(Address),
    /// Apply an existing structure type.
    ApplyStructure(Address),
    /// Set register value at an address.
    SetRegisterValue(Address),
    /// Set flow override at an address.
    SetFlowOverride(Address),
    /// Add a bookmark at an address.
    AddBookmark(Address),
    /// Remove bookmarks at an address.
    RemoveBookmark(Address),
    /// Run analysis starting at an address.
    AnalyzeFromHere(Address),
    /// Patch/modify instruction bytes at an address.
    PatchInstruction(Address),
    /// Patch data bytes at an address.
    PatchData(Address),
    /// Show all references FROM an address.
    ShowReferences(Address),
    /// Show all cross-references TO an address.
    ShowXRefs(Address),
    /// Copy address to clipboard.
    CopyAddress(Address),
    /// Copy raw bytes (hex) to clipboard.
    CopyBytes(Address),
    /// Copy as a printable string.
    CopyAsString(Address),
    /// Copy as a C array declaration.
    CopyAsCArray(Address),
    /// Copy as a Python list.
    CopyAsPythonList(Address),
    /// Copy full instruction to clipboard.
    CopyInstruction(String),
    /// Copy label to clipboard.
    CopyLabel(Address),
    /// Set background color at an address.
    SetBackgroundColor(Address),
    /// Set text color at an address.
    SetTextColor(Address),
    /// Clear custom colors at an address.
    ClearColors(Address),
    /// Open selection in a new listing window.
    OpenInNewWindow(Address),
    /// Edit with an external tool.
    EditWithExternalTool(Address),
}

// ============================================================================
// Listing View State
// ============================================================================

/// The disassembly listing view state.
///
/// Holds cursor position, selection, scroll state, navigation history,
/// column layout, and pending actions.
pub struct ListingView {
    /// Column visibility and layout configuration.
    pub columns: ListingColumns,
    /// Column width and resize state.
    pub column_layout: ColumnLayout,
    /// Current cursor position (address).
    pub cursor_position: Address,
    /// Range selection (shift+click), if any.
    pub selection: Option<AddressRange>,
    /// Multi-select set (ctrl+click addresses).
    pub multi_selection: HashSet<Address>,
    /// The visible address range (computed from scroll position).
    pub visible_rows: Vec<Address>,
    /// Syntax highlighting theme.
    pub syntax_theme: SyntaxTheme,
    /// Whether to show raw bytes.
    pub show_bytes: bool,
    /// Whether to show xrefs as a separate column.
    pub show_xrefs: bool,
    /// Scroll offset (row index from top).
    pub scroll_offset: usize,
    /// Number of rows visible.
    pub rows_visible: usize,
    /// Navigation history for back/forward.
    pub nav_history: Vec<Address>,
    /// Current position in navigation history.
    pub nav_index: usize,
    /// Tracked labels for display.
    pub labels: HashMap<Address, String>,
    /// Tracked xrefs for display.
    pub xrefs: HashMap<Address, Vec<Address>>,
    /// Tracked comments for display.
    pub comments: HashMap<Address, String>,
    /// Pending actions to be handled by the application.
    pub pending_actions: Vec<ListingAction>,
    /// Whether the address input popup is visible.
    pub show_goto_dialog: bool,
    /// Text in the goto dialog.
    pub goto_text: String,
    /// Whether the rename dialog is visible.
    pub show_rename_dialog: bool,
    /// Address for the rename dialog.
    pub rename_address: Option<Address>,
    /// Text in the rename dialog.
    pub rename_text: String,
    /// Whether the comment dialog is visible.
    pub show_comment_dialog: bool,
    /// Address for the comment dialog.
    pub comment_address: Option<Address>,
    /// Text in the comment dialog.
    pub comment_text: String,
}

impl ListingView {
    /// Create a new listing view with default configuration.
    pub fn new() -> Self {
        Self {
            columns: ListingColumns::default(),
            column_layout: ColumnLayout::default(),
            cursor_position: Address::new(0x1000),
            selection: None,
            multi_selection: HashSet::new(),
            visible_rows: Vec::new(),
            syntax_theme: SyntaxTheme::default(),
            show_bytes: true,
            show_xrefs: true,
            scroll_offset: 0,
            rows_visible: 50,
            nav_history: vec![Address::new(0x1000)],
            nav_index: 0,
            labels: HashMap::new(),
            xrefs: HashMap::new(),
            comments: HashMap::new(),
            pending_actions: Vec::new(),
            show_goto_dialog: false,
            goto_text: String::new(),
            show_rename_dialog: false,
            rename_address: None,
            rename_text: String::new(),
            show_comment_dialog: false,
            comment_address: None,
            comment_text: String::new(),
        }
    }

    /// Navigate to a specific address.
    pub fn goto(&mut self, addr: Address) {
        if self.nav_index + 1 < self.nav_history.len() {
            self.nav_history.truncate(self.nav_index + 1);
        }
        self.nav_history.push(addr);
        self.nav_index = self.nav_history.len() - 1;
        self.cursor_position = addr;
    }

    /// Go back in navigation history.
    pub fn go_back(&mut self) {
        if self.nav_index > 0 {
            self.nav_index -= 1;
            self.cursor_position = self.nav_history[self.nav_index];
        }
    }

    /// Go forward in navigation history.
    pub fn go_forward(&mut self) {
        if self.nav_index + 1 < self.nav_history.len() {
            self.nav_index += 1;
            self.cursor_position = self.nav_history[self.nav_index];
        }
    }

    /// Check if we can go back.
    pub fn can_go_back(&self) -> bool {
        self.nav_index > 0
    }

    /// Check if we can go forward.
    pub fn can_go_forward(&self) -> bool {
        self.nav_index + 1 < self.nav_history.len()
    }

    /// Scroll up one line.
    pub fn scroll_up(&mut self) {
        self.scroll_offset = self.scroll_offset.saturating_sub(1);
    }

    /// Scroll down one line.
    pub fn scroll_down(&mut self) {
        self.scroll_offset += 1;
    }

    /// Page up.
    pub fn page_up(&mut self) {
        self.scroll_offset = self.scroll_offset.saturating_sub(self.rows_visible);
    }

    /// Page down.
    pub fn page_down(&mut self) {
        self.scroll_offset += self.rows_visible;
    }

    /// Select an address (single click — sets cursor, clears selection).
    pub fn select(&mut self, addr: Address) {
        self.cursor_position = addr;
        self.selection = None;
        self.multi_selection.clear();
    }

    /// Toggle multi-select for an address (ctrl+click).
    pub fn toggle_select(&mut self, addr: Address) {
        if self.multi_selection.contains(&addr) {
            self.multi_selection.remove(&addr);
        } else {
            self.multi_selection.insert(addr);
        }
    }

    /// Extend selection to an address (shift+click — range select).
    pub fn extend_selection(&mut self, addr: Address) {
        self.selection = Some(match self.selection {
            Some(ref range) => {
                let start = std::cmp::min(range.start, addr);
                let end = std::cmp::max(range.end, addr);
                AddressRange::new(start, end)
            }
            None => {
                let start = std::cmp::min(self.cursor_position, addr);
                let end = std::cmp::max(self.cursor_position, addr);
                AddressRange::new(start, end)
            }
        });
    }

    /// Clear selection.
    pub fn clear_selection(&mut self) {
        self.selection = None;
        self.multi_selection.clear();
    }

    /// Check if an address is selected.
    pub fn is_selected(&self, addr: &Address) -> bool {
        if self.multi_selection.contains(addr) {
            return true;
        }
        self.selection
            .as_ref()
            .map(|r| r.contains(addr))
            .unwrap_or(false)
    }

    /// Set labels from a program.
    pub fn set_labels(&mut self, labels: HashMap<Address, String>) {
        self.labels = labels;
    }

    /// Set xrefs from a program.
    pub fn set_xrefs(&mut self, xrefs: HashMap<Address, Vec<Address>>) {
        self.xrefs = xrefs;
    }

    /// Set comments from a program.
    pub fn set_comments(&mut self, comments: HashMap<Address, String>) {
        self.comments = comments;
    }

    /// Compute visible rows based on current position and scroll offset.
    pub fn update_visible_rows(&mut self, available_rows: &[Address]) {
        let start = self
            .scroll_offset
            .min(available_rows.len().saturating_sub(1));
        let end = (start + self.rows_visible).min(available_rows.len());
        self.visible_rows = available_rows[start..end].to_vec();
    }

    /// Get the label at an address.
    pub fn label_at(&self, addr: &Address) -> Option<&str> {
        self.labels.get(addr).map(|s| s.as_str())
    }

    /// Get the comment at an address.
    pub fn comment_at(&self, addr: &Address) -> Option<&str> {
        self.comments.get(addr).map(|s| s.as_str())
    }

    /// Get the xrefs TO an address.
    pub fn xrefs_to(&self, addr: &Address) -> &[Address] {
        self.xrefs.get(addr).map(|v| v.as_slice()).unwrap_or(&[])
    }

    /// Queue an action for the application to handle.
    pub fn queue_action(&mut self, action: ListingAction) {
        self.pending_actions.push(action);
    }

    /// Take all pending actions, clearing the queue.
    pub fn take_actions(&mut self) -> Vec<ListingAction> {
        std::mem::take(&mut self.pending_actions)
    }

    /// Convert a row index to an address, given sorted rows.
    pub fn row_index_to_address(&self, rows: &[ListingRow], index: usize) -> Option<Address> {
        rows.get(index).map(|r| r.address)
    }

    /// Convert an address to a row index via binary search.
    pub fn address_to_row_index(&self, rows: &[ListingRow], addr: &Address) -> Option<usize> {
        rows.binary_search_by_key(&addr.offset, |r| r.address.offset)
            .ok()
    }

    /// Scroll to make the given address visible.
    pub fn scroll_to_address(&mut self, rows: &[ListingRow], addr: &Address) {
        if let Some(idx) = self.address_to_row_index(rows, addr) {
            // Center the address in the view
            let half = self.rows_visible / 2;
            self.scroll_offset = idx.saturating_sub(half);
        }
    }

    /// Apply column visibility settings from `ListingColumns` to `ColumnLayout`.
    pub fn sync_column_visibility(&mut self) {
        let mapping: &[(ColumnId, bool)] = &[
            (ColumnId::Address, self.columns.show_address),
            (ColumnId::Bytes, self.columns.show_bytes && self.show_bytes),
            (ColumnId::Label, self.columns.show_label),
            (ColumnId::Mnemonic, self.columns.show_mnemonic),
            (ColumnId::Operands, self.columns.show_operands),
            (ColumnId::XRefs, self.columns.show_xrefs && self.show_xrefs),
            (ColumnId::Comment, self.columns.show_comment),
        ];
        for (id, visible) in mapping {
            if let Some(col) = self.column_layout.column_mut(*id) {
                col.visible = *visible;
            }
        }
    }
}

impl Default for ListingView {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Listing Row Conversion Utilities
// ============================================================================

/// Convert a slice of core [`ghidra_core::listing::ListingRow`] to the rich
/// GUI [`ListingRow`] type, using the provided label/comment/xref maps.
pub fn convert_core_rows(
    core_rows: &[ghidra_core::listing::ListingRow],
    labels: &HashMap<Address, String>,
    comments: &HashMap<Address, String>,
    xrefs: &HashMap<Address, Vec<Address>>,
) -> Vec<ListingRow> {
    let mut rows: Vec<ListingRow> = core_rows
        .iter()
        .map(|r| ListingRow::from_core(r, labels, comments, xrefs))
        .collect();
    rows.sort_by_key(|r| r.address.offset);
    rows
}

/// Check if an operand string likely contains an address reference.
pub fn has_address_reference(operands: &[RenderedOperand]) -> bool {
    operands.iter().any(|op| op.target_address.is_some())
}

/// Extract the first target address from a list of operands.
pub fn first_target_address(operands: &[RenderedOperand]) -> Option<Address> {
    operands.iter().find_map(|op| op.target_address)
}

/// Determine if the operands indicate a flow control instruction.
pub fn is_flow_instruction(mnemonic: &str, operands: &[RenderedOperand]) -> bool {
    let flow_mnemonics: &[&str] = &[
        "jmp", "je", "jne", "jz", "jnz", "jg", "jl", "jge", "jle", "ja", "jb", "jae", "jbe", "jo",
        "jno", "js", "jns", "jcxz", "jecxz", "jrcxz", "call", "ret", "iret", "syscall", "sysenter",
        "int", "loop", "loope", "loopne", "loopnz", "loopz",
    ];
    flow_mnemonics.contains(&mnemonic.to_lowercase().as_str()) || has_address_reference(operands)
}

// ============================================================================
// Row Display Formatting
// ============================================================================

/// Format a slice of bytes as a hex dump string.
///
/// Example: `[0x48, 0x89, 0xE5]` -> `"48 89 E5"`
pub fn format_hex_bytes(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Format a list of operands as a single display string.
///
/// Joins operand text with appropriate spacing.
pub fn format_operands(operands: &[RenderedOperand]) -> String {
    let mut result = String::new();
    for (i, op) in operands.iter().enumerate() {
        if i > 0 {
            let prev = &operands[i - 1];
            // Don't add space before/after separators
            let prev_end = prev.text.chars().last().unwrap_or(' ');
            let this_start = op.text.chars().next().unwrap_or(' ');
            if prev_end != '['
                && prev_end != '('
                && this_start != ','
                && this_start != ']'
                && this_start != ')'
                && this_start != ':'
                && prev_end != ':'
            {
                result.push(' ');
            }
        }
        result.push_str(&op.text);
    }
    result
}

/// Format the full instruction string for a listing row (mnemonic + operands).
pub fn format_full_instruction(row: &ListingRow) -> String {
    if row.mnemonic.is_empty() {
        return String::new();
    }
    let ops = format_operands(&row.operands);
    if ops.is_empty() {
        row.mnemonic.clone()
    } else {
        format!("{} {}", row.mnemonic, ops)
    }
}

/// Format the address as a hex string with a leading "0x" prefix.
pub fn format_address_hex(addr: &Address) -> String {
    format!("0x{:08X}", addr.offset)
}

/// Format the address as a compact hex string (no prefix).
pub fn format_address_compact(addr: &Address) -> String {
    format!("{:08X}", addr.offset)
}

// ============================================================================
// Row Iteration and Query Utilities
// ============================================================================

/// Iterator adapter that yields only instruction rows.
pub fn filter_instructions<'a>(rows: &'a [ListingRow]) -> impl Iterator<Item = &'a ListingRow> {
    rows.iter().filter(|r| r.is_instruction)
}

/// Iterator adapter that yields only data rows.
pub fn filter_data<'a>(rows: &'a [ListingRow]) -> impl Iterator<Item = &'a ListingRow> {
    rows.iter()
        .filter(|r| !r.is_instruction && r.row_type == RowType::Data)
}

/// Iterator adapter that yields rows with labels.
pub fn filter_labelled<'a>(rows: &'a [ListingRow]) -> impl Iterator<Item = &'a ListingRow> {
    rows.iter().filter(|r| r.label.is_some())
}

/// Iterator adapter that yields rows with comments.
pub fn filter_commented<'a>(rows: &'a [ListingRow]) -> impl Iterator<Item = &'a ListingRow> {
    rows.iter().filter(|r| r.comment.is_some())
}

/// Find the row at the given address using binary search on a sorted slice.
pub fn find_row_at_address<'a>(rows: &'a [ListingRow], addr: &Address) -> Option<&'a ListingRow> {
    rows.binary_search_by_key(&addr.offset, |r| r.address.offset)
        .ok()
        .map(|i| &rows[i])
}

/// Find all rows within an address range.
pub fn rows_in_range<'a>(rows: &'a [ListingRow], range: &AddressRange) -> Vec<&'a ListingRow> {
    rows.iter().filter(|r| range.contains(&r.address)).collect()
}

/// Get the next instruction row after the given address.
pub fn next_instruction_after<'a>(
    rows: &'a [ListingRow],
    addr: &Address,
) -> Option<&'a ListingRow> {
    rows.iter()
        .filter(|r| r.is_instruction && r.address.offset > addr.offset)
        .min_by_key(|r| r.address.offset)
}

/// Get the previous instruction row before the given address.
pub fn prev_instruction_before<'a>(
    rows: &'a [ListingRow],
    addr: &Address,
) -> Option<&'a ListingRow> {
    rows.iter()
        .filter(|r| r.is_instruction && r.address.offset < addr.offset)
        .max_by_key(|r| r.address.offset)
}

/// Convert a sorted slice of rows into a vector of addresses only.
pub fn rows_to_addresses(rows: &[ListingRow]) -> Vec<Address> {
    rows.iter().map(|r| r.address).collect()
}

/// Group rows by their label (for building label-to-address maps).
pub fn group_by_label(rows: &[ListingRow]) -> HashMap<String, Vec<Address>> {
    let mut map: HashMap<String, Vec<Address>> = HashMap::new();
    for row in rows {
        if let Some(ref label) = row.label {
            map.entry(label.clone()).or_default().push(row.address);
        }
    }
    map
}

// ============================================================================
// Selection Utilities
// ============================================================================

/// Returns the sorted, deduplicated set of selected addresses from the view.
pub fn selected_addresses(view: &ListingView, rows: &[ListingRow]) -> Vec<Address> {
    if let Some(ref range) = view.selection {
        let mut addrs: Vec<Address> = rows
            .iter()
            .filter(|r| range.contains(&r.address))
            .map(|r| r.address)
            .collect();
        for addr in &view.multi_selection {
            if !addrs.contains(addr) {
                addrs.push(*addr);
            }
        }
        addrs.sort();
        addrs
    } else if !view.multi_selection.is_empty() {
        let mut addrs: Vec<Address> = view.multi_selection.iter().copied().collect();
        addrs.sort();
        addrs
    } else {
        vec![view.cursor_position]
    }
}

/// Select all rows in the listing.
pub fn select_all(view: &mut ListingView, rows: &[ListingRow]) {
    if let (Some(first), Some(last)) = (rows.first(), rows.last()) {
        view.selection = Some(AddressRange::new(first.address, last.address));
    }
}

/// Deselect all rows.
pub fn deselect_all(view: &mut ListingView) {
    view.clear_selection();
}

/// Select all rows that match the given function (predicate).
pub fn select_matching(
    view: &mut ListingView,
    rows: &[ListingRow],
    predicate: impl Fn(&ListingRow) -> bool,
) {
    for row in rows {
        if predicate(row) {
            view.multi_selection.insert(row.address);
        }
    }
}

/// Compute the minimum and maximum selected addresses for range operations.
pub fn selected_range(view: &ListingView) -> Option<AddressRange> {
    if let Some(ref range) = view.selection {
        return Some(*range);
    }
    if view.multi_selection.is_empty() {
        return None;
    }
    let min = view.multi_selection.iter().min().copied()?;
    let max = view.multi_selection.iter().max().copied()?;
    Some(AddressRange::new(min, max))
}

// ============================================================================
// Instruction Classification Utilities
// ============================================================================

/// Known unconditional jump mnemonics (x86/x86-64).
static UNCONDITIONAL_JUMPS: &[&str] = &["jmp", "ljmp"];

/// Known conditional jump mnemonics (x86/x86-64).
static CONDITIONAL_JUMPS: &[&str] = &[
    "je", "jne", "jz", "jnz", "jg", "jge", "jl", "jle", "ja", "jae", "jb", "jbe", "jo", "jno",
    "js", "jns", "jp", "jnp", "jpe", "jpo", "jcxz", "jecxz", "jrcxz",
];

/// Known call mnemonics.
static CALL_MNEMONICS: &[&str] = &[
    "call", "lcall", "syscall", "sysenter", "int", "int3", "into",
];

/// Known return mnemonics.
static RETURN_MNEMONICS: &[&str] = &["ret", "retn", "retf", "iret", "iretd", "iretq", "sysexit"];

/// Known stack operation mnemonics.
static STACK_MNEMONICS: &[&str] = &[
    "push", "pusha", "pushad", "pushf", "pushfd", "pushfq", "pop", "popa", "popad", "popf",
    "popfd", "popfq", "enter", "leave",
];

/// Known arithmetic/logic mnemonics.
static ARITHMETIC_MNEMONICS: &[&str] = &[
    "add", "sub", "mul", "imul", "div", "idiv", "inc", "dec", "neg", "adc", "sbb", "and", "or",
    "xor", "not", "test", "cmp",
];

/// Known data movement mnemonics.
static DATA_MOVE_MNEMONICS: &[&str] = &[
    "mov", "movsx", "movzx", "movsb", "movsw", "movsd", "movsq", "lea", "xchg", "cmpxchg", "xadd",
    "bswap", "lahf", "sahf",
];

/// Known string operation mnemonics.
static STRING_MNEMONICS: &[&str] = &[
    "movs", "cmps", "scas", "lods", "stos", "rep", "repe", "repne", "repnz", "repz",
];

/// Returns the flow type of a given mnemonic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstructionFlowType {
    /// Non-flow instruction (arithmetic, data movement, etc.).
    Normal,
    /// Unconditional jump (always transfers control).
    UnconditionalJump,
    /// Conditional jump (may or may not transfer control).
    ConditionalJump,
    /// Call (transfers control and expects to return).
    Call,
    /// Return (returns control to caller).
    Return,
    /// Stack operation.
    Stack,
    /// System instruction (privileged or special).
    System,
}

/// Classify an instruction mnemonic into its flow type.
pub fn classify_instruction_flow(mnemonic: &str) -> InstructionFlowType {
    let lower = mnemonic.to_lowercase();
    if CALL_MNEMONICS.contains(&lower.as_str()) {
        InstructionFlowType::Call
    } else if RETURN_MNEMONICS.contains(&lower.as_str()) {
        InstructionFlowType::Return
    } else if UNCONDITIONAL_JUMPS.contains(&lower.as_str()) {
        InstructionFlowType::UnconditionalJump
    } else if CONDITIONAL_JUMPS.contains(&lower.as_str()) {
        InstructionFlowType::ConditionalJump
    } else if STACK_MNEMONICS.contains(&lower.as_str()) {
        InstructionFlowType::Stack
    } else if lower == "syscall"
        || lower == "sysenter"
        || lower == "sysexit"
        || lower == "int"
        || lower == "int3"
        || lower == "hlt"
        || lower == "cpuid"
        || lower == "rdtsc"
        || lower == "rdmsr"
        || lower == "wrmsr"
    {
        InstructionFlowType::System
    } else {
        InstructionFlowType::Normal
    }
}

/// Check if a mnemonic is an unconditional jump.
pub fn is_unconditional_jump(mnemonic: &str) -> bool {
    UNCONDITIONAL_JUMPS.contains(&mnemonic.to_lowercase().as_str())
}

/// Check if a mnemonic is a conditional jump.
pub fn is_conditional_jump(mnemonic: &str) -> bool {
    CONDITIONAL_JUMPS.contains(&mnemonic.to_lowercase().as_str())
}

/// Check if a mnemonic is a call instruction.
pub fn is_call(mnemonic: &str) -> bool {
    CALL_MNEMONICS.contains(&mnemonic.to_lowercase().as_str())
}

/// Check if a mnemonic is a return instruction.
pub fn is_return(mnemonic: &str) -> bool {
    RETURN_MNEMONICS.contains(&mnemonic.to_lowercase().as_str())
}

/// Check if a mnemonic is a stack operation.
pub fn is_stack_operation(mnemonic: &str) -> bool {
    STACK_MNEMONICS.contains(&mnemonic.to_lowercase().as_str())
}

/// Check if a mnemonic is an arithmetic/logic instruction.
pub fn is_arithmetic(mnemonic: &str) -> bool {
    ARITHMETIC_MNEMONICS.contains(&mnemonic.to_lowercase().as_str())
}

/// Check if a mnemonic is a data movement instruction.
pub fn is_data_move(mnemonic: &str) -> bool {
    DATA_MOVE_MNEMONICS.contains(&mnemonic.to_lowercase().as_str())
}

/// Check if a mnemonic is a string operation.
pub fn is_string_operation(mnemonic: &str) -> bool {
    STRING_MNEMONICS.contains(&mnemonic.to_lowercase().as_str())
}

/// Check if a mnemonic terminates a basic block.
pub fn is_basic_block_terminator(mnemonic: &str) -> bool {
    is_unconditional_jump(mnemonic)
        || is_conditional_jump(mnemonic)
        || is_return(mnemonic)
        || is_call(mnemonic)
}

/// Get the default color for an instruction based on its flow type.
pub fn instruction_flow_color(mnemonic: &str, theme: &SyntaxTheme) -> egui::Color32 {
    match classify_instruction_flow(mnemonic) {
        InstructionFlowType::Call => egui::Color32::from_rgb(255, 180, 100),
        InstructionFlowType::Return => egui::Color32::from_rgb(255, 150, 130),
        InstructionFlowType::UnconditionalJump => egui::Color32::from_rgb(255, 130, 180),
        InstructionFlowType::ConditionalJump => egui::Color32::from_rgb(200, 150, 255),
        InstructionFlowType::Stack => egui::Color32::from_rgb(180, 200, 220),
        InstructionFlowType::System => egui::Color32::from_rgb(255, 100, 100),
        InstructionFlowType::Normal => theme.mnemonic,
    }
}

// ============================================================================
// Row Caching & Management Utilities
// ============================================================================

/// A cache of listing rows with sorted access.
#[derive(Debug, Clone, Default)]
pub struct ListingRowCache {
    /// Sorted rows.
    rows: Vec<ListingRow>,
    /// Address-to-index lookup for O(1) access.
    addr_to_index: HashMap<Address, usize>,
    /// Whether the cache needs re-sorting.
    dirty: bool,
}

impl ListingRowCache {
    /// Create an empty cache.
    pub fn new() -> Self {
        Self {
            rows: Vec::new(),
            addr_to_index: HashMap::new(),
            dirty: false,
        }
    }

    /// Create a cache from a vector of rows, sorted by address.
    pub fn from_rows(rows: Vec<ListingRow>) -> Self {
        let mut cache = Self {
            rows,
            addr_to_index: HashMap::new(),
            dirty: true,
        };
        cache.rebuild();
        cache
    }

    /// Get a row by address.
    pub fn get(&self, addr: &Address) -> Option<&ListingRow> {
        self.addr_to_index.get(addr).and_then(|&i| self.rows.get(i))
    }

    /// Get a row by index.
    pub fn get_by_index(&self, index: usize) -> Option<&ListingRow> {
        self.rows.get(index)
    }

    /// Get the index of a row by address.
    pub fn index_of(&self, addr: &Address) -> Option<usize> {
        self.addr_to_index.get(addr).copied()
    }

    /// Number of rows.
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    /// Whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Add or update a row.
    pub fn insert(&mut self, row: ListingRow) {
        if let Some(&idx) = self.addr_to_index.get(&row.address) {
            self.rows[idx] = row;
        } else {
            self.rows.push(row);
            self.dirty = true;
        }
    }

    /// Remove a row by address.
    pub fn remove(&mut self, addr: &Address) -> Option<ListingRow> {
        if let Some(&idx) = self.addr_to_index.get(addr) {
            let row = self.rows.remove(idx);
            self.dirty = true;
            Some(row)
        } else {
            None
        }
    }

    /// Iterate over rows in order.
    pub fn iter(&self) -> impl Iterator<Item = &ListingRow> {
        self.rows.iter()
    }

    /// Get a slice of all rows.
    pub fn as_slice(&self) -> &[ListingRow] {
        &self.rows
    }

    /// Get rows in a range of indices.
    pub fn range(&self, start: usize, end: usize) -> &[ListingRow] {
        let end = end.min(self.rows.len());
        let start = start.min(end);
        &self.rows[start..end]
    }

    /// Find all rows whose addresses fall within the given range.
    pub fn rows_in_addr_range(&self, range: &AddressRange) -> Vec<&ListingRow> {
        self.rows
            .iter()
            .filter(|r| range.contains(&r.address))
            .collect()
    }

    /// Rebuild the internal lookup index.
    pub fn rebuild(&mut self) {
        if self.dirty {
            self.rows.sort_by_key(|r| r.address.offset);
            self.addr_to_index.clear();
            for (i, row) in self.rows.iter().enumerate() {
                self.addr_to_index.insert(row.address, i);
            }
            self.dirty = false;
        }
    }

    /// Clear all rows.
    pub fn clear(&mut self) {
        self.rows.clear();
        self.addr_to_index.clear();
        self.dirty = false;
    }

    /// Count rows matching a predicate.
    pub fn count_matching(&self, predicate: impl Fn(&ListingRow) -> bool) -> usize {
        self.rows.iter().filter(|r| predicate(r)).count()
    }

    /// Find the first row matching a predicate.
    pub fn find(&self, predicate: impl Fn(&ListingRow) -> bool) -> Option<&ListingRow> {
        self.rows.iter().find(|r| predicate(r))
    }

    /// Find all rows matching a predicate.
    pub fn find_all(&self, predicate: impl Fn(&ListingRow) -> bool) -> Vec<&ListingRow> {
        self.rows.iter().filter(|r| predicate(r)).collect()
    }

    /// Get the address range covered by this cache.
    pub fn address_range(&self) -> Option<AddressRange> {
        let first = self.rows.first()?;
        let last = self.rows.last()?;
        Some(AddressRange::new(first.address, last.address))
    }
}

// ============================================================================
// Row Builder Pattern
// ============================================================================

/// Builder for constructing [`ListingRow`] instances fluently.
#[derive(Debug, Clone)]
pub struct ListingRowBuilder {
    row: ListingRow,
}

impl ListingRowBuilder {
    /// Start building an instruction row at the given address.
    pub fn instruction(address: Address, mnemonic: impl Into<String>) -> Self {
        Self {
            row: ListingRow::instruction(address, Vec::new(), mnemonic, Vec::new()),
        }
    }

    /// Start building a data row at the given address.
    pub fn data(address: Address) -> Self {
        Self {
            row: ListingRow::data(address, Vec::new(), None),
        }
    }

    /// Set the raw bytes.
    pub fn bytes(mut self, bytes: Vec<u8>) -> Self {
        self.row.bytes = bytes;
        self
    }

    /// Set the label.
    pub fn label(mut self, label: impl Into<String>) -> Self {
        self.row.label = Some(label.into());
        self
    }

    /// Set the comment.
    pub fn comment(mut self, comment: impl Into<String>) -> Self {
        self.row.comment = Some(comment.into());
        self
    }

    /// Add an operand.
    pub fn operand(mut self, operand: RenderedOperand) -> Self {
        self.row.operands.push(operand);
        self
    }

    /// Add a register operand.
    pub fn reg(mut self, name: impl Into<String>) -> Self {
        self.row.operands.push(RenderedOperand::register(name));
        self
    }

    /// Add an immediate operand.
    pub fn imm(mut self, value: impl Into<String>) -> Self {
        self.row.operands.push(RenderedOperand::immediate(value));
        self
    }

    /// Add an address operand.
    pub fn addr_ref(mut self, text: impl Into<String>, target: Address) -> Self {
        self.row
            .operands
            .push(RenderedOperand::address(text, target));
        self
    }

    /// Add a scalar operand (separator, bracket, etc.).
    pub fn scalar(mut self, text: impl Into<String>) -> Self {
        self.row.operands.push(RenderedOperand::scalar(text));
        self
    }

    /// Add a label reference operand.
    pub fn label_ref(mut self, text: impl Into<String>, target: Option<Address>) -> Self {
        self.row.operands.push(RenderedOperand::label(text, target));
        self
    }

    /// Add a cross-reference TO this address.
    pub fn xref_to(mut self, xref_text: impl Into<String>) -> Self {
        self.row.xrefs_to.push(xref_text.into());
        self
    }

    /// Set the row type.
    pub fn row_type(mut self, rtype: RowType) -> Self {
        self.row.row_type = rtype;
        self
    }

    /// Build the row.
    pub fn build(self) -> ListingRow {
        self.row
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_hex_bytes() {
        assert_eq!(format_hex_bytes(&[0x48, 0x89, 0xE5]), "48 89 E5");
        assert_eq!(format_hex_bytes(&[]), "");
        assert_eq!(format_hex_bytes(&[0xFF]), "FF");
    }

    #[test]
    fn test_format_operands() {
        let ops = vec![
            RenderedOperand::register("rax"),
            RenderedOperand::scalar(","),
            RenderedOperand::immediate("0x42"),
        ];
        assert_eq!(format_operands(&ops), "rax, 0x42");
    }

    #[test]
    fn test_format_full_instruction() {
        let row = ListingRow::instruction(
            Address::new(0x1000),
            vec![0x48, 0x89, 0xE5],
            "mov",
            vec![
                RenderedOperand::register("rbp"),
                RenderedOperand::scalar(","),
                RenderedOperand::register("rsp"),
            ],
        );
        assert_eq!(format_full_instruction(&row), "mov rbp, rsp");
    }

    #[test]
    fn test_format_address() {
        assert_eq!(format_address_hex(&Address::new(0x1000)), "0x00001000");
        assert_eq!(format_address_compact(&Address::new(0x1000)), "00001000");
    }

    #[test]
    fn test_classify_instruction_flow() {
        assert_eq!(classify_instruction_flow("call"), InstructionFlowType::Call);
        assert_eq!(
            classify_instruction_flow("ret"),
            InstructionFlowType::Return
        );
        assert_eq!(
            classify_instruction_flow("jmp"),
            InstructionFlowType::UnconditionalJump
        );
        assert_eq!(
            classify_instruction_flow("je"),
            InstructionFlowType::ConditionalJump
        );
        assert_eq!(
            classify_instruction_flow("push"),
            InstructionFlowType::Stack
        );
        assert_eq!(
            classify_instruction_flow("mov"),
            InstructionFlowType::Normal
        );
    }

    #[test]
    fn test_is_basic_block_terminator() {
        assert!(is_basic_block_terminator("jmp"));
        assert!(is_basic_block_terminator("je"));
        assert!(is_basic_block_terminator("ret"));
        assert!(is_basic_block_terminator("call"));
        assert!(!is_basic_block_terminator("mov"));
        assert!(!is_basic_block_terminator("add"));
    }

    #[test]
    fn test_listing_row_cache() {
        let rows = vec![
            ListingRow::instruction(Address::new(0x1000), vec![], "nop", vec![]),
            ListingRow::instruction(Address::new(0x1001), vec![], "ret", vec![]),
        ];
        let cache = ListingRowCache::from_rows(rows);
        assert_eq!(cache.len(), 2);
        assert!(cache.get(&Address::new(0x1000)).is_some());
        assert_eq!(cache.get(&Address::new(0x1000)).unwrap().mnemonic, "nop");
        assert!(cache.get(&Address::new(0x9999)).is_none());
    }

    #[test]
    fn test_listing_row_builder() {
        let row = ListingRowBuilder::instruction(Address::new(0x1000), "mov")
            .bytes(vec![0x48, 0x89, 0xE5])
            .label("main")
            .comment("entry point")
            .reg("rbp")
            .scalar(",")
            .reg("rsp")
            .build();

        assert_eq!(row.address.offset, 0x1000);
        assert_eq!(row.mnemonic, "mov");
        assert_eq!(row.label.unwrap(), "main");
        assert_eq!(row.comment.unwrap(), "entry point");
        assert_eq!(row.operands.len(), 3);
    }

    #[test]
    fn test_rendered_operand_constructors() {
        let reg = RenderedOperand::register("rax");
        assert_eq!(reg.op_type, OperandRenderType::Register);

        let addr = RenderedOperand::address("0x401000", Address::new(0x401000));
        assert_eq!(addr.op_type, OperandRenderType::Address);
        assert_eq!(addr.target_address, Some(Address::new(0x401000)));

        let imm = RenderedOperand::immediate("42");
        assert_eq!(imm.op_type, OperandRenderType::Immediate);
    }

    #[test]
    fn test_find_row_at_address() {
        let rows = vec![
            ListingRow::empty(Address::new(0x1000)),
            ListingRow::empty(Address::new(0x1005)),
            ListingRow::empty(Address::new(0x1010)),
        ];
        assert!(find_row_at_address(&rows, &Address::new(0x1005)).is_some());
        assert!(find_row_at_address(&rows, &Address::new(0x9999)).is_none());
    }

    #[test]
    fn test_selected_addresses() {
        let mut view = ListingView::new();
        view.cursor_position = Address::new(0x1000);
        let rows = vec![
            ListingRow::empty(Address::new(0x1000)),
            ListingRow::empty(Address::new(0x1005)),
        ];
        let selected = selected_addresses(&view, &rows);
        assert_eq!(selected, vec![Address::new(0x1000)]);

        view.select(Address::new(0x1005));
        let selected = selected_addresses(&view, &rows);
        assert_eq!(selected, vec![Address::new(0x1005)]);
    }
}
