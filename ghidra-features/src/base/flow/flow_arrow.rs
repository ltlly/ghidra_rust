//! Flow arrow visualization -- ported from Ghidra's
//! `FlowArrow.java` and `FlowArrowPlugin.java`.
//!
//! This module provides flow arrow types for visualizing control flow
//! in the listing margin. Flow arrows show the direction of jumps,
//! calls, and fall-throughs in the code browser.

use crate::base::analyzer::core::*;

// ---------------------------------------------------------------------------
// FlowArrowType
// ---------------------------------------------------------------------------

/// Types of flow arrows displayed in the listing margin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FlowArrowType {
    /// Unconditional jump (up or down).
    UnconditionalJump,
    /// Conditional jump.
    ConditionalJump,
    /// Call arrow.
    Call,
    /// Fall-through arrow (always downward).
    Fallthrough,
    /// Computed/indirect flow.
    Computed,
    /// Return from function.
    Return,
}

impl FlowArrowType {
    /// Check if this is a jump type arrow.
    pub fn is_jump(&self) -> bool {
        matches!(
            self,
            FlowArrowType::UnconditionalJump | FlowArrowType::ConditionalJump
        )
    }

    /// Check if this is a call type arrow.
    pub fn is_call(&self) -> bool {
        *self == FlowArrowType::Call
    }

    /// Get the display name.
    pub fn display_name(&self) -> &'static str {
        match self {
            FlowArrowType::UnconditionalJump => "Unconditional Jump",
            FlowArrowType::ConditionalJump => "Conditional Jump",
            FlowArrowType::Call => "Call",
            FlowArrowType::Fallthrough => "Fallthrough",
            FlowArrowType::Computed => "Computed",
            FlowArrowType::Return => "Return",
        }
    }

    /// Determine the arrow type from a flow type and addresses.
    pub fn from_flow(flow_type: &FlowType, start: Address, end: Address) -> Self {
        match flow_type {
            FlowType::Call | FlowType::ConditionalCall => FlowArrowType::Call,
            FlowType::Jump => FlowArrowType::UnconditionalJump,
            FlowType::ConditionalJump => FlowArrowType::ConditionalJump,
            FlowType::Return | FlowType::Terminator => FlowArrowType::Return,
            FlowType::Fallthrough => {
                if start.offset > end.offset {
                    FlowArrowType::UnconditionalJump // upward fallthrough is unusual
                } else {
                    FlowArrowType::Fallthrough
                }
            }
            _ => FlowArrowType::Computed,
        }
    }
}

impl std::fmt::Display for FlowArrowType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

// ---------------------------------------------------------------------------
// FlowArrow
// ---------------------------------------------------------------------------

/// Represents a flow arrow in the listing margin.
///
/// A flow arrow connects two addresses in the listing, showing the
/// control flow relationship between them. Arrows can point upward
/// (backward jumps) or downward (forward jumps, fall-throughs).
///
/// # Example
///
/// ```ignore
/// use ghidra_features::base::flow::{FlowArrow, FlowArrowType};
///
/// let arrow = FlowArrow::new(
///     Address::new(0x1000),
///     Address::new(0x2000),
///     FlowArrowType::ConditionalJump,
/// );
/// assert!(!arrow.is_upward());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FlowArrow {
    /// Source address of the flow.
    pub start: Address,
    /// Destination address of the flow.
    pub end: Address,
    /// The type of flow arrow.
    pub arrow_type: FlowArrowType,
    /// The column position (for overlapping arrows).
    pub column: i32,
    /// Whether this arrow is currently active (mouse hover).
    pub active: bool,
    /// Whether this arrow is currently selected.
    pub selected: bool,
}

impl FlowArrow {
    /// Create a new flow arrow.
    pub fn new(start: Address, end: Address, arrow_type: FlowArrowType) -> Self {
        Self {
            start,
            end,
            arrow_type,
            column: -1,
            active: false,
            selected: false,
        }
    }

    /// Check if this arrow points upward (start > end).
    pub fn is_upward(&self) -> bool {
        self.start.offset > self.end.offset
    }

    /// Check if this arrow points downward (start <= end).
    pub fn is_downward(&self) -> bool {
        self.start.offset <= self.end.offset
    }

    /// Get the address range spanned by this arrow.
    pub fn address_range(&self) -> AddressRange {
        let (min_addr, max_addr) = if self.start.offset <= self.end.offset {
            (self.start, self.end)
        } else {
            (self.end, self.start)
        };
        AddressRange::new(min_addr, max_addr)
    }

    /// Get the number of addresses spanned by this arrow.
    pub fn span(&self) -> u64 {
        if self.start.offset >= self.end.offset {
            self.start.offset - self.end.offset + 1
        } else {
            self.end.offset - self.start.offset + 1
        }
    }

    /// Check if this arrow contains the given address in its range.
    pub fn contains_address(&self, addr: &Address) -> bool {
        let range = self.address_range();
        range.contains(addr)
    }

    /// Get the display string for this arrow.
    pub fn display_string(&self) -> String {
        format!(
            "start={}; end={}; type={}",
            self.start, self.end, self.arrow_type
        )
    }

    /// Get the max column depth (for layout calculations).
    pub fn max_column(&self) -> i32 {
        self.column.max(0)
    }
}

impl std::fmt::Display for FlowArrow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} -> {} ({})",
            self.start, self.end, self.arrow_type
        )
    }
}

// ---------------------------------------------------------------------------
// FlowArrowLayout
// ---------------------------------------------------------------------------

/// Configuration for flow arrow layout in the margin.
#[derive(Debug, Clone)]
pub struct FlowArrowLayout {
    /// Minimum spacing between arrow lines in pixels.
    pub min_line_spacing: i32,
    /// Default spacing between arrow lines in pixels.
    pub default_line_spacing: i32,
    /// Maximum spacing between arrow lines in pixels.
    pub max_line_spacing: i32,
    /// Arrow spacing as a ratio of available width.
    pub arrow_spacing_ratio: f64,
    /// Left margin offset for arrows.
    pub left_offset: i32,
}

impl FlowArrowLayout {
    /// Create a layout with default Ghidra settings.
    pub fn new() -> Self {
        Self {
            min_line_spacing: 9,
            default_line_spacing: 16,
            max_line_spacing: 60,
            arrow_spacing_ratio: 0.18,
            left_offset: 0,
        }
    }

    /// Calculate the line width for a given display width and max column depth.
    pub fn calculate_line_width(&self, display_width: i32, max_column: i32) -> i32 {
        let mut width = self.default_line_spacing;
        if max_column >= 0 {
            let available = display_width - self.left_offset;
            width = (available as f64 * self.arrow_spacing_ratio) as i32;
        }
        width.clamp(self.min_line_spacing, self.max_line_spacing)
    }
}

impl Default for FlowArrowLayout {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// FlowArrowPlugin
// ---------------------------------------------------------------------------

/// Plugin for displaying flow arrows in the listing margin.
///
/// This plugin manages the creation and display of flow arrows that
/// visualize control flow relationships in the code browser.
#[derive(Debug, Clone)]
pub struct FlowArrowPlugin {
    /// Plugin name.
    name: String,
    /// Currently displayed arrows.
    arrows: Vec<FlowArrow>,
    /// Layout configuration.
    layout: FlowArrowLayout,
    /// Maximum column depth across all arrows.
    max_column: i32,
}

impl FlowArrowPlugin {
    /// Create a new flow arrow plugin.
    pub fn new() -> Self {
        Self {
            name: "Flow Arrows".to_string(),
            arrows: Vec::new(),
            layout: FlowArrowLayout::new(),
            max_column: -1,
        }
    }

    /// Get the plugin name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get a reference to the displayed arrows.
    pub fn arrows(&self) -> &[FlowArrow] {
        &self.arrows
    }

    /// Get a mutable reference to the displayed arrows.
    pub fn arrows_mut(&mut self) -> &mut Vec<FlowArrow> {
        &mut self.arrows
    }

    /// Add a flow arrow.
    pub fn add_arrow(&mut self, arrow: FlowArrow) {
        self.max_column = self.max_column.max(arrow.column);
        self.arrows.push(arrow);
    }

    /// Remove all arrows.
    pub fn clear_arrows(&mut self) {
        self.arrows.clear();
        self.max_column = -1;
    }

    /// Get the layout configuration.
    pub fn layout(&self) -> &FlowArrowLayout {
        &self.layout
    }

    /// Get the maximum column depth.
    pub fn max_column(&self) -> i32 {
        self.max_column
    }

    /// Find an arrow that intersects the given address.
    pub fn find_arrow_at(&self, addr: &Address) -> Option<&FlowArrow> {
        self.arrows.iter().find(|a| a.contains_address(addr))
    }

    /// Build flow arrows from a program's instructions within an address set.
    pub fn build_arrows(&mut self, program: &Program, addr_set: &AddressSet) {
        self.clear_arrows();

        for range in addr_set.iter() {
            let mut addr = range.start;
            while addr.offset <= range.end.offset {
                if let Some(instr) = program.listing.get_instruction_at(&addr) {
                    // Create arrows for branch targets
                    for target in &instr.flows {
                        let arrow_type =
                            FlowArrowType::from_flow(&instr.flow_type, addr, *target);
                        self.add_arrow(FlowArrow::new(addr, *target, arrow_type));
                    }
                }
                addr = addr.add(1);
            }
        }

        // Assign columns to avoid overlaps
        self.assign_columns();
    }

    /// Assign column positions to arrows to prevent overlapping.
    fn assign_columns(&mut self) {
        // Simple greedy column assignment
        let mut columns: Vec<(u64, u64)> = Vec::new(); // (start_offset, end_offset)
        for arrow in &mut self.arrows {
            let range = arrow.address_range();
            let start_off = range.start.offset;
            let end_off = range.end.offset;

            // Find first available column
            let mut col = 0i32;
            loop {
                if col as usize >= columns.len() {
                    columns.push((start_off, end_off));
                    arrow.column = col;
                    break;
                }
                let (c_start, c_end) = columns[col as usize];
                // Check overlap
                if start_off > c_end || end_off < c_start {
                    // No overlap, reuse this column
                    columns[col as usize] = (
                        start_off.min(c_start),
                        end_off.max(c_end),
                    );
                    arrow.column = col;
                    break;
                }
                col += 1;
            }
        }
        self.max_column = columns.len() as i32 - 1;
    }
}

impl Default for FlowArrowPlugin {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flow_arrow_creation() {
        let arrow = FlowArrow::new(
            Address::new(0x1000),
            Address::new(0x2000),
            FlowArrowType::ConditionalJump,
        );
        assert!(!arrow.is_upward());
        assert!(arrow.is_downward());
        assert_eq!(arrow.span(), 0x1001);
    }

    #[test]
    fn test_flow_arrow_upward() {
        let arrow = FlowArrow::new(
            Address::new(0x2000),
            Address::new(0x1000),
            FlowArrowType::UnconditionalJump,
        );
        assert!(arrow.is_upward());
        assert!(!arrow.is_downward());
    }

    #[test]
    fn test_flow_arrow_contains_address() {
        let arrow = FlowArrow::new(
            Address::new(0x1000),
            Address::new(0x2000),
            FlowArrowType::Call,
        );
        assert!(arrow.contains_address(&Address::new(0x1500)));
        assert!(arrow.contains_address(&Address::new(0x1000)));
        assert!(arrow.contains_address(&Address::new(0x2000)));
        assert!(!arrow.contains_address(&Address::new(0x3000)));
    }

    #[test]
    fn test_flow_arrow_type_from_flow() {
        let arrow_type = FlowArrowType::from_flow(
            &FlowType::Jump,
            Address::new(0x1000),
            Address::new(0x2000),
        );
        assert_eq!(arrow_type, FlowArrowType::UnconditionalJump);

        let arrow_type = FlowArrowType::from_flow(
            &FlowType::ConditionalJump,
            Address::new(0x1000),
            Address::new(0x2000),
        );
        assert_eq!(arrow_type, FlowArrowType::ConditionalJump);

        let arrow_type = FlowArrowType::from_flow(
            &FlowType::Call,
            Address::new(0x1000),
            Address::new(0x3000),
        );
        assert_eq!(arrow_type, FlowArrowType::Call);

        let arrow_type = FlowArrowType::from_flow(
            &FlowType::Return,
            Address::new(0x1000),
            Address::new(0x0),
        );
        assert_eq!(arrow_type, FlowArrowType::Return);
    }

    #[test]
    fn test_flow_arrow_type_properties() {
        assert!(FlowArrowType::UnconditionalJump.is_jump());
        assert!(FlowArrowType::ConditionalJump.is_jump());
        assert!(!FlowArrowType::Call.is_jump());
        assert!(FlowArrowType::Call.is_call());
    }

    #[test]
    fn test_flow_arrow_type_display() {
        assert_eq!(FlowArrowType::UnconditionalJump.to_string(), "Unconditional Jump");
        assert_eq!(FlowArrowType::Call.to_string(), "Call");
        assert_eq!(FlowArrowType::Fallthrough.to_string(), "Fallthrough");
    }

    #[test]
    fn test_flow_arrow_display() {
        let arrow = FlowArrow::new(
            Address::new(0x1000),
            Address::new(0x2000),
            FlowArrowType::ConditionalJump,
        );
        let display = arrow.display_string();
        assert!(display.contains("0x00001000"));
        assert!(display.contains("0x00002000"));
        assert!(display.contains("Conditional Jump"));
    }

    #[test]
    fn test_flow_arrow_layout() {
        let layout = FlowArrowLayout::new();
        assert_eq!(layout.min_line_spacing, 9);
        assert_eq!(layout.default_line_spacing, 16);
        assert_eq!(layout.max_line_spacing, 60);
        assert!((layout.arrow_spacing_ratio - 0.18).abs() < f64::EPSILON);
    }

    #[test]
    fn test_flow_arrow_layout_line_width() {
        let layout = FlowArrowLayout::new();
        let width = layout.calculate_line_width(1000, 0);
        assert!(width >= layout.min_line_spacing);
        assert!(width <= layout.max_line_spacing);
    }

    #[test]
    fn test_flow_arrow_plugin() {
        let mut plugin = FlowArrowPlugin::new();
        assert_eq!(plugin.name(), "Flow Arrows");
        assert!(plugin.arrows().is_empty());

        let arrow = FlowArrow::new(
            Address::new(0x1000),
            Address::new(0x2000),
            FlowArrowType::UnconditionalJump,
        );
        plugin.add_arrow(arrow);
        assert_eq!(plugin.arrows().len(), 1);

        plugin.clear_arrows();
        assert!(plugin.arrows().is_empty());
    }

    #[test]
    fn test_flow_arrow_plugin_build_arrows() {
        let mut prog = Program::new("test", Language {
            processor: "x86".into(),
            variant: "LE".into(),
            size: 64,
        });
        prog.listing.instructions.insert(
            Address::new(0x1000),
            Instruction {
                address: Address::new(0x1000),
                length: 4,
                mnemonic: "jz".to_string(),
                flow_type: FlowType::ConditionalJump,
                fall_through: Some(Address::new(0x1004)),
                flows: vec![Address::new(0x2000)],
                num_operands: 1,
            },
        );

        let mut plugin = FlowArrowPlugin::new();
        let mut set = AddressSet::new();
        set.add_range(AddressRange::new(Address::new(0x1000), Address::new(0x1004)));
        plugin.build_arrows(&prog, &set);

        assert!(!plugin.arrows().is_empty());
    }

    #[test]
    fn test_flow_arrow_plugin_find_at() {
        let mut plugin = FlowArrowPlugin::new();
        plugin.add_arrow(FlowArrow::new(
            Address::new(0x1000),
            Address::new(0x2000),
            FlowArrowType::UnconditionalJump,
        ));

        assert!(plugin.find_arrow_at(&Address::new(0x1500)).is_some());
        assert!(plugin.find_arrow_at(&Address::new(0x3000)).is_none());
    }
}
