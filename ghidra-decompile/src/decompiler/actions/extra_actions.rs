//! Additional decompiler actions not covered by edit_actions.
//!
//! Ports the remaining Ghidra `ghidra.app.plugin.core.decompile.actions` classes:
//! - Slice actions (BackwardsSlice, ForwardSlice, to PCodeOps variants)
//! - Highlight actions (SetSecondaryHighlight, RemoveSecondaryHighlight, etc.)
//! - PCode graph tasks (PCodeCfgGraphTask, PCodeDfgGraphTask, etc.)
//! - Navigation actions (GoToNextBrace, GoToPreviousBrace, Find, FindReferences)
//! - Prototype override actions
//! - Display/copy/export actions
//! - Select/commit actions
//! - Rename/structure tasks

use ghidra_core::addr::Address;
use serde::{Deserialize, Serialize};

use super::{ActionCategory, ActionMetadata, DecompilerActionContext};

// ============================================================================
// Slice actions
// ============================================================================

/// Direction of a data-flow slice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SliceDirection {
    /// Backwards (def-to-use) slice.
    Backward,
    /// Forward (use-to-def) slice.
    Forward,
}

/// Data for a slice action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SliceAction {
    /// Direction of the slice.
    pub direction: SliceDirection,
    /// The target address.
    pub address: Address,
    /// The variable name being sliced (if any).
    pub variable_name: Option<String>,
    /// Whether to show P-code operations in the slice.
    pub show_pcode_ops: bool,
    /// Maximum depth for the slice.
    pub max_depth: Option<usize>,
}

impl SliceAction {
    /// Create a backwards slice action.
    pub fn backward(address: Address) -> Self {
        Self {
            direction: SliceDirection::Backward,
            address,
            variable_name: None,
            show_pcode_ops: false,
            max_depth: None,
        }
    }

    /// Create a forward slice action.
    pub fn forward(address: Address) -> Self {
        Self {
            direction: SliceDirection::Forward,
            address,
            variable_name: None,
            show_pcode_ops: false,
            max_depth: None,
        }
    }

    /// Convert to a P-code ops slice action.
    pub fn to_pcode_ops(mut self) -> Self {
        self.show_pcode_ops = true;
        self
    }

    /// Get the metadata for this action.
    pub fn metadata(&self) -> ActionMetadata {
        let name = match (&self.direction, self.show_pcode_ops) {
            (SliceDirection::Backward, false) => "BackwardsSliceAction",
            (SliceDirection::Backward, true) => "BackwardsSliceToPCodeOpsAction",
            (SliceDirection::Forward, false) => "ForwardSliceAction",
            (SliceDirection::Forward, true) => "ForwardSliceToPCodeOpsAction",
        };
        ActionMetadata::new(name, name, ActionCategory::Analysis)
    }
}

// ============================================================================
// Highlight actions
// ============================================================================

/// Action to set a secondary highlight on a token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetSecondaryHighlightAction {
    /// The address to highlight.
    pub address: Address,
    /// The highlight color (CSS hex string).
    pub color: String,
    /// The highlight name/id for management.
    pub highlight_id: String,
}

impl SetSecondaryHighlightAction {
    /// Create a new set-secondary-highlight action.
    pub fn new(address: Address, color: impl Into<String>, highlight_id: impl Into<String>) -> Self {
        Self {
            address,
            color: color.into(),
            highlight_id: highlight_id.into(),
        }
    }

    /// Get the action metadata.
    pub fn metadata(&self) -> ActionMetadata {
        ActionMetadata::new(
            "SetSecondaryHighlightAction",
            "Set Secondary Highlight",
            ActionCategory::Display,
        )
    }
}

/// Action to remove a specific secondary highlight.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoveSecondaryHighlightAction {
    /// The highlight name/id to remove.
    pub highlight_id: String,
}

impl RemoveSecondaryHighlightAction {
    /// Create a new remove action.
    pub fn new(highlight_id: impl Into<String>) -> Self {
        Self { highlight_id: highlight_id.into() }
    }

    /// Get the action metadata.
    pub fn metadata(&self) -> ActionMetadata {
        ActionMetadata::new(
            "RemoveSecondaryHighlightAction",
            "Remove Secondary Highlight",
            ActionCategory::Display,
        )
    }
}

/// Action to remove all secondary highlights.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RemoveAllSecondaryHighlightsAction;

impl RemoveAllSecondaryHighlightsAction {
    /// Get the action metadata.
    pub fn metadata(&self) -> ActionMetadata {
        ActionMetadata::new(
            "RemoveAllSecondaryHighlightsAction",
            "Remove All Secondary Highlights",
            ActionCategory::Display,
        )
    }
}

/// Action to set the secondary highlight color via a chooser.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetSecondaryHighlightColorChooserAction {
    /// The current color (pre-populated).
    pub current_color: String,
}

impl SetSecondaryHighlightColorChooserAction {
    /// Create a new color chooser action.
    pub fn new(current_color: impl Into<String>) -> Self {
        Self { current_color: current_color.into() }
    }

    /// Get the action metadata.
    pub fn metadata(&self) -> ActionMetadata {
        ActionMetadata::new(
            "SetSecondaryHighlightColorChooserAction",
            "Choose Highlight Color",
            ActionCategory::Display,
        )
    }
}

/// Action to highlight all definitions and uses of a symbol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HighlightDefinedUseAction {
    /// The symbol name.
    pub symbol_name: String,
    /// Whether to highlight definitions (true) or uses (false).
    pub highlight_definitions: bool,
}

impl HighlightDefinedUseAction {
    /// Create a new action.
    pub fn new(symbol_name: impl Into<String>, highlight_definitions: bool) -> Self {
        Self {
            symbol_name: symbol_name.into(),
            highlight_definitions,
        }
    }

    /// Get the action metadata.
    pub fn metadata(&self) -> ActionMetadata {
        ActionMetadata::new(
            "HighlightDefinedUseAction",
            "Highlight Definitions/Uses",
            ActionCategory::Display,
        )
    }
}

/// Action to navigate to the next highlighted token.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NextHighlightedTokenAction;

impl NextHighlightedTokenAction {
    pub fn metadata() -> ActionMetadata {
        ActionMetadata::new("NextHighlightedTokenAction", "Next Highlighted Token", ActionCategory::Navigation)
            .with_shortcut("Ctrl+Shift+Down")
    }
}

/// Action to navigate to the previous highlighted token.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PreviousHighlightedTokenAction;

impl PreviousHighlightedTokenAction {
    pub fn metadata() -> ActionMetadata {
        ActionMetadata::new("PreviousHighlightedTokenAction", "Previous Highlighted Token", ActionCategory::Navigation)
            .with_shortcut("Ctrl+Shift+Up")
    }
}

// ============================================================================
// PCode graph tasks
// ============================================================================

/// Task to display the P-code control-flow graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PCodeCfgGraphTask {
    /// The function address.
    pub function_address: Address,
    /// The graph type to display.
    pub graph_type: PCodeCfgGraphType,
    /// Whether to use simplified form.
    pub simplified: bool,
}

/// P-code CFG graph type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PCodeCfgGraphType {
    /// Basic block level.
    BasicBlock,
    /// Instruction level.
    Instruction,
}

impl PCodeCfgGraphTask {
    /// Create a new PCode CFG task.
    pub fn new(function_address: Address, graph_type: PCodeCfgGraphType) -> Self {
        Self { function_address, graph_type, simplified: true }
    }

    pub fn metadata() -> ActionMetadata {
        ActionMetadata::new("PCodeCfgGraphTask", "P-Code CFG", ActionCategory::Pcode)
    }
}

/// Task to display the P-code data-flow graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PCodeDfgGraphTask {
    /// The function address.
    pub function_address: Address,
    /// The graph type to display.
    pub graph_type: PCodeDfgGraphType,
    /// Display options.
    pub options: PCodeDfgDisplayOpts,
}

/// P-code DFG graph type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PCodeDfgGraphType {
    /// Full data-flow graph.
    Full,
    /// Selected operations only.
    Selected,
}

/// Display options for P-code DFG.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PCodeDfgDisplayOpts {
    /// Show constant propagation edges.
    pub show_constants: bool,
    /// Show register dependencies.
    pub show_registers: bool,
    /// Show memory dependencies.
    pub show_memory: bool,
}

impl PCodeDfgGraphTask {
    /// Create a new PCode DFG task.
    pub fn new(function_address: Address, graph_type: PCodeDfgGraphType) -> Self {
        Self {
            function_address,
            graph_type,
            options: PCodeDfgDisplayOpts::default(),
        }
    }

    pub fn metadata() -> ActionMetadata {
        ActionMetadata::new("PCodeDfgGraphTask", "P-Code DFG", ActionCategory::Pcode)
    }
}

/// Combined CFG+DFG graph task.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PCodeCombinedGraphTask {
    /// The function address.
    pub function_address: Address,
    /// Whether to show the CFG.
    pub show_cfg: bool,
    /// Whether to show the DFG.
    pub show_dfg: bool,
}

impl PCodeCombinedGraphTask {
    /// Create a new combined task.
    pub fn new(function_address: Address) -> Self {
        Self { function_address, show_cfg: true, show_dfg: true }
    }

    pub fn metadata() -> ActionMetadata {
        ActionMetadata::new("PCodeCombinedGraphTask", "P-Code Combined Graph", ActionCategory::Pcode)
    }
}

/// Selected-only P-code DFG graph task.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelectedPCodeDfgGraphTask {
    /// The function address.
    pub function_address: Address,
    /// Selected token addresses.
    pub selected_addresses: Vec<Address>,
}

impl SelectedPCodeDfgGraphTask {
    /// Create a new selected DFG task.
    pub fn new(function_address: Address) -> Self {
        Self { function_address, selected_addresses: Vec::new() }
    }

    pub fn metadata() -> ActionMetadata {
        ActionMetadata::new("SelectedPCodeDfgGraphTask", "Selected P-Code DFG", ActionCategory::Pcode)
    }
}

// ============================================================================
// Navigation actions
// ============================================================================

/// Action to go to the next brace.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GoToNextBraceAction;

impl GoToNextBraceAction {
    pub fn metadata() -> ActionMetadata {
        ActionMetadata::new("GoToNextBraceAction", "Go to Next Brace", ActionCategory::Navigation)
            .with_shortcut("Ctrl+]")
    }
}

/// Action to go to the previous brace.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GoToPreviousBraceAction;

impl GoToPreviousBraceAction {
    pub fn metadata() -> ActionMetadata {
        ActionMetadata::new("GoToPreviousBraceAction", "Go to Previous Brace", ActionCategory::Navigation)
            .with_shortcut("Ctrl+[")
    }
}

/// Action to open a find dialog.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FindAction;

impl FindAction {
    pub fn metadata() -> ActionMetadata {
        ActionMetadata::new("FindAction", "Find...", ActionCategory::Navigation)
            .with_shortcut("Ctrl+F")
    }
}

/// Action to find references to an address.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindReferencesToAddressAction {
    /// The address to find references to.
    pub address: Address,
}

impl FindReferencesToAddressAction {
    pub fn new(address: Address) -> Self {
        Self { address }
    }

    pub fn metadata() -> ActionMetadata {
        ActionMetadata::new("FindReferencesToAddressAction", "Find References to Address", ActionCategory::Analysis)
    }
}

/// Action to find references to a data type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindReferencesToDataTypeAction {
    /// The data type name.
    pub data_type_name: String,
}

impl FindReferencesToDataTypeAction {
    pub fn new(data_type_name: impl Into<String>) -> Self {
        Self { data_type_name: data_type_name.into() }
    }

    pub fn metadata() -> ActionMetadata {
        ActionMetadata::new("FindReferencesToDataTypeAction", "Find References to Data Type", ActionCategory::Analysis)
    }
}

/// Action to find references to a high symbol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindReferencesToHighSymbolAction {
    /// The symbol name.
    pub symbol_name: String,
}

impl FindReferencesToHighSymbolAction {
    pub fn new(symbol_name: impl Into<String>) -> Self {
        Self { symbol_name: symbol_name.into() }
    }

    pub fn metadata() -> ActionMetadata {
        ActionMetadata::new("FindReferencesToHighSymbolAction", "Find References to Symbol", ActionCategory::Analysis)
    }
}

// ============================================================================
// Prototype override actions
// ============================================================================

/// Action to override the function prototype.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverridePrototypeAction {
    /// The function address.
    pub function_address: Address,
    /// The new calling convention (if changing).
    pub calling_convention: Option<String>,
    /// The new return type (if changing).
    pub return_type: Option<String>,
    /// New parameter types (if changing).
    pub parameters: Vec<ParameterOverride>,
}

/// Override for a single parameter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParameterOverride {
    /// Parameter index.
    pub index: usize,
    /// New name (if changing).
    pub name: Option<String>,
    /// New type (if changing).
    pub type_name: Option<String>,
}

impl OverridePrototypeAction {
    /// Create a new override action.
    pub fn new(function_address: Address) -> Self {
        Self {
            function_address,
            calling_convention: None,
            return_type: None,
            parameters: Vec::new(),
        }
    }

    pub fn metadata() -> ActionMetadata {
        ActionMetadata::new("OverridePrototypeAction", "Override Function Prototype", ActionCategory::Editing)
    }
}

/// Action to edit the function prototype.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EditPrototypeOverrideAction {
    /// The function address.
    pub function_address: Address,
}

impl EditPrototypeOverrideAction {
    pub fn new(function_address: Address) -> Self {
        Self { function_address }
    }

    pub fn metadata() -> ActionMetadata {
        ActionMetadata::new("EditPrototypeOverrideAction", "Edit Prototype Override", ActionCategory::Editing)
    }
}

/// Action to delete the function prototype override.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeletePrototypeOverrideAction {
    /// The function address.
    pub function_address: Address,
}

impl DeletePrototypeOverrideAction {
    pub fn new(function_address: Address) -> Self {
        Self { function_address }
    }

    pub fn metadata() -> ActionMetadata {
        ActionMetadata::new("DeletePrototypeOverrideAction", "Delete Prototype Override", ActionCategory::Editing)
    }
}

/// Action to specify a C prototype.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpecifyCPrototypeAction {
    /// The function address.
    pub function_address: Address,
    /// The C prototype string.
    pub prototype: String,
}

impl SpecifyCPrototypeAction {
    pub fn new(function_address: Address, prototype: impl Into<String>) -> Self {
        Self { function_address, prototype: prototype.into() }
    }

    pub fn metadata() -> ActionMetadata {
        ActionMetadata::new("SpecifyCPrototypeAction", "Specify C Prototype", ActionCategory::Editing)
    }
}

// ============================================================================
// Display / clipboard actions
// ============================================================================

/// Action to toggle display of type casts.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DisplayTypeCastsAction {
    /// Whether type casts are currently shown.
    pub show_type_casts: bool,
}

impl DisplayTypeCastsAction {
    pub fn new(show_type_casts: bool) -> Self {
        Self { show_type_casts }
    }

    pub fn metadata() -> ActionMetadata {
        ActionMetadata::new("DisplayTypeCastsAction", "Display Type Casts", ActionCategory::Display)
    }
}

/// Action to select all decompiler output.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SelectAllAction;

impl SelectAllAction {
    pub fn metadata() -> ActionMetadata {
        ActionMetadata::new("SelectAllAction", "Select All", ActionCategory::Clipboard)
            .with_shortcut("Ctrl+A")
    }
}

/// Action to copy the decompiler signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CopySignatureAction {
    /// The function address.
    pub function_address: Address,
}

impl CopySignatureAction {
    pub fn new(function_address: Address) -> Self {
        Self { function_address }
    }

    pub fn metadata() -> ActionMetadata {
        ActionMetadata::new("CopySignatureAction", "Copy Signature", ActionCategory::Clipboard)
    }
}

/// Action to export decompiler output to C.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportToCAction {
    /// The function address.
    pub function_address: Address,
    /// Output file path (if any).
    pub output_path: Option<String>,
}

impl ExportToCAction {
    pub fn new(function_address: Address) -> Self {
        Self { function_address, output_path: None }
    }

    pub fn metadata() -> ActionMetadata {
        ActionMetadata::new("ExportToCAction", "Export to C", ActionCategory::Clipboard)
    }
}

/// Action to remove an equate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoveEquateAction {
    /// The address of the equate.
    pub address: Address,
}

impl RemoveEquateAction {
    pub fn new(address: Address) -> Self {
        Self { address }
    }

    pub fn metadata() -> ActionMetadata {
        ActionMetadata::new("RemoveEquateAction", "Remove Equate", ActionCategory::Editing)
    }
}

/// Action to set an equate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetEquateAction {
    /// The address.
    pub address: Address,
    /// The equate name.
    pub equate_name: String,
    /// The equate value.
    pub value: u64,
}

impl SetEquateAction {
    pub fn new(address: Address, equate_name: impl Into<String>, value: u64) -> Self {
        Self { address, equate_name: equate_name.into(), value }
    }

    pub fn metadata() -> ActionMetadata {
        ActionMetadata::new("SetEquateAction", "Set Equate", ActionCategory::Editing)
    }
}

/// Action to remove a label.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoveLabelAction {
    /// The address.
    pub address: Address,
}

impl RemoveLabelAction {
    pub fn new(address: Address) -> Self {
        Self { address }
    }

    pub fn metadata() -> ActionMetadata {
        ActionMetadata::new("RemoveLabelAction", "Remove Label", ActionCategory::Editing)
    }
}

/// Action to create a pointer-relative reference.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreatePointerRelativeAction {
    /// The source address.
    pub address: Address,
    /// The offset.
    pub offset: i64,
}

impl CreatePointerRelativeAction {
    pub fn new(address: Address, offset: i64) -> Self {
        Self { address, offset }
    }

    pub fn metadata() -> ActionMetadata {
        ActionMetadata::new("CreatePointerRelativeAction", "Create Pointer-Relative", ActionCategory::Editing)
    }
}

// ============================================================================
// Rename / retype tasks (non-edit)
// ============================================================================

/// Task to rename a struct bit field.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenameStructBitFieldTask {
    /// Address of the structure.
    pub struct_address: Address,
    /// The field path.
    pub field_path: Vec<String>,
    /// The new name.
    pub new_name: String,
}

impl RenameStructBitFieldTask {
    pub fn new(struct_address: Address, field_path: Vec<String>, new_name: impl Into<String>) -> Self {
        Self { struct_address, field_path, new_name: new_name.into() }
    }
}

/// Task to retype a struct field.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetypeStructFieldTask {
    /// Address of the structure.
    pub struct_address: Address,
    /// The field path.
    pub field_path: Vec<String>,
    /// The new type name.
    pub new_type: String,
}

impl RetypeStructFieldTask {
    pub fn new(struct_address: Address, field_path: Vec<String>, new_type: impl Into<String>) -> Self {
        Self { struct_address, field_path, new_type: new_type.into() }
    }
}

/// Task to isolate a variable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsolateVariableTask {
    /// The function address.
    pub function_address: Address,
    /// The variable name.
    pub variable_name: String,
}

impl IsolateVariableTask {
    pub fn new(function_address: Address, variable_name: impl Into<String>) -> Self {
        Self { function_address, variable_name: variable_name.into() }
    }
}

// ============================================================================
// Color provider / token highlight types
// ============================================================================

/// Default color provider for decompiler highlights.
#[derive(Debug, Clone)]
pub struct DefaultColorProvider {
    /// Colors for different highlight types.
    pub colors: Vec<String>,
    /// Current index for cycling.
    pub current_index: usize,
}

impl DefaultColorProvider {
    /// Create a new default color provider.
    pub fn new() -> Self {
        Self {
            colors: vec![
                "#FFFF00".into(), "#00FF00".into(), "#00FFFF".into(),
                "#FF00FF".into(), "#FF8000".into(), "#8000FF".into(),
            ],
            current_index: 0,
        }
    }

    /// Get the next color in the cycle.
    pub fn next_color(&mut self) -> &str {
        let color = &self.colors[self.current_index % self.colors.len()];
        self.current_index += 1;
        color
    }
}

impl Default for DefaultColorProvider {
    fn default() -> Self {
        Self::new()
    }
}

/// Token highlight entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HighlightToken {
    /// The token key.
    pub token_key: u64,
    /// The highlight color.
    pub color: String,
    /// Whether this is a primary highlight.
    pub is_primary: bool,
}

impl HighlightToken {
    /// Create a new highlight token.
    pub fn new(token_key: u64, color: impl Into<String>, is_primary: bool) -> Self {
        Self { token_key, color: color.into(), is_primary }
    }
}

/// Matcher for matching token names.
#[derive(Debug, Clone)]
pub struct NameTokenMatcher {
    /// The name to match.
    pub name: String,
    /// Whether to match case-sensitively.
    pub case_sensitive: bool,
}

impl NameTokenMatcher {
    /// Create a new matcher.
    pub fn new(name: impl Into<String>, case_sensitive: bool) -> Self {
        Self { name: name.into(), case_sensitive }
    }

    /// Check if a token name matches.
    pub fn matches(&self, token_name: &str) -> bool {
        if self.case_sensitive {
            token_name == self.name
        } else {
            token_name.eq_ignore_ascii_case(&self.name)
        }
    }
}

/// CToken highlight matcher for matching decompiler output tokens.
#[derive(Debug, Clone)]
pub struct CTokenHighlightMatcher {
    /// The text to match.
    pub pattern: String,
    /// Whether this is a regex.
    pub is_regex: bool,
}

impl CTokenHighlightMatcher {
    /// Create a new CToken highlight matcher.
    pub fn new(pattern: impl Into<String>, is_regex: bool) -> Self {
        Self { pattern: pattern.into(), is_regex }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_slice_action_backward() {
        let slice = SliceAction::backward(Address::new(0x1000));
        assert_eq!(slice.direction, SliceDirection::Backward);
        assert!(!slice.show_pcode_ops);
    }

    #[test]
    fn test_slice_action_to_pcode_ops() {
        let slice = SliceAction::forward(Address::new(0x2000)).to_pcode_ops();
        assert!(slice.show_pcode_ops);
        assert_eq!(slice.direction, SliceDirection::Forward);
    }

    #[test]
    fn test_secondary_highlight_actions() {
        let set = SetSecondaryHighlightAction::new(Address::new(0x1000), "#ff0000", "hl1");
        assert_eq!(set.color, "#ff0000");
        assert_eq!(set.highlight_id, "hl1");

        let remove = RemoveSecondaryHighlightAction::new("hl1");
        assert_eq!(remove.highlight_id, "hl1");

        let remove_all = RemoveAllSecondaryHighlightsAction;
        assert_eq!(remove_all.metadata().name, "RemoveAllSecondaryHighlightsAction");
    }

    #[test]
    fn test_pcode_cfg_task() {
        let task = PCodeCfgGraphTask::new(Address::new(0x1000), PCodeCfgGraphType::BasicBlock);
        assert_eq!(task.function_address, Address::new(0x1000));
        assert!(task.simplified);
    }

    #[test]
    fn test_pcode_dfg_task() {
        let task = PCodeDfgGraphTask::new(Address::new(0x2000), PCodeDfgGraphType::Selected);
        assert_eq!(task.graph_type, PCodeDfgGraphType::Selected);
    }

    #[test]
    fn test_pcode_combined_task() {
        let task = PCodeCombinedGraphTask::new(Address::new(0x3000));
        assert!(task.show_cfg);
        assert!(task.show_dfg);
    }

    #[test]
    fn test_navigation_actions() {
        assert_eq!(GoToNextBraceAction::metadata().category, ActionCategory::Navigation);
        assert_eq!(GoToPreviousBraceAction::metadata().category, ActionCategory::Navigation);
        assert_eq!(FindAction::metadata().category, ActionCategory::Navigation);
    }

    #[test]
    fn test_override_prototype_action() {
        let action = OverridePrototypeAction::new(Address::new(0x1000));
        assert_eq!(action.function_address, Address::new(0x1000));
        assert!(action.parameters.is_empty());
    }

    #[test]
    fn test_display_type_casts() {
        let action = DisplayTypeCastsAction::new(true);
        assert!(action.show_type_casts);
    }

    #[test]
    fn test_select_all() {
        let meta = SelectAllAction::metadata();
        assert!(meta.has_shortcut());
    }

    #[test]
    fn test_export_to_c() {
        let action = ExportToCAction::new(Address::new(0x1000));
        assert!(action.output_path.is_none());
    }

    #[test]
    fn test_default_color_provider() {
        let mut provider = DefaultColorProvider::new();
        let c1 = provider.next_color().to_string();
        let c2 = provider.next_color().to_string();
        assert_ne!(c1, c2);
    }

    #[test]
    fn test_name_token_matcher() {
        let matcher = NameTokenMatcher::new("main", true);
        assert!(matcher.matches("main"));
        assert!(!matcher.matches("Main"));
    }

    #[test]
    fn test_name_token_matcher_case_insensitive() {
        let matcher = NameTokenMatcher::new("main", false);
        assert!(matcher.matches("MAIN"));
        assert!(matcher.matches("main"));
    }

    #[test]
    fn test_highlight_token() {
        let ht = HighlightToken::new(42, "#ff0000", true);
        assert_eq!(ht.token_key, 42);
        assert!(ht.is_primary);
    }

    #[test]
    fn test_parameter_override() {
        let po = ParameterOverride { index: 0, name: Some("x".into()), type_name: Some("int".into()) };
        assert_eq!(po.index, 0);
    }

    #[test]
    fn test_rename_struct_bit_field() {
        let task = RenameStructBitFieldTask::new(
            Address::new(0x1000),
            vec!["field1".into()],
            "new_name",
        );
        assert_eq!(task.new_name, "new_name");
    }

    #[test]
    fn test_isolate_variable_task() {
        let task = IsolateVariableTask::new(Address::new(0x1000), "var1");
        assert_eq!(task.variable_name, "var1");
    }
}
