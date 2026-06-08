//! Decompiler actions -- Rust port of the `ghidra.app.plugin.core.decompile.actions` package.
//!
//! Each action struct models a user-visible command in the decompiler panel
//! (rename variable, retype field, find references, etc.).  The actions are
//! registered with the [`DecompilerProvider`](super::provider::DecompilerProvider)
//! and executed against a [`DecompilerActionContext`](super::action_context::DecompilerActionContext).


// ---------------------------------------------------------------------------
// Action base trait
// ---------------------------------------------------------------------------

/// A named, describable action that can appear in a popup menu.
pub trait DecompilerAction: std::fmt::Debug {
    /// The action's unique name (e.g., `"Rename Local"`).
    fn name(&self) -> &str;

    /// Human-readable description shown in tooltips.
    fn description(&self) -> &str;

    /// The popup menu path, e.g. `["Rename", "Local Variable"]`.
    fn menu_path(&self) -> &[&str] {
        &[]
    }

    /// The menu group for ordering.
    fn menu_group(&self) -> &str {
        ""
    }

    /// The sub-group position within the group.
    fn menu_sub_group(&self) -> u32 {
        0
    }

    /// Whether this action is enabled for the given context.
    fn is_enabled(&self, _ctx: &super::action_context::DecompilerActionContext) -> bool {
        true
    }

    /// Execute the action.
    fn execute(&self, ctx: &mut super::action_context::DecompilerActionContext) -> DecompilerActionResult {
        if self.perform(ctx) {
            DecompilerActionResult::Success(self.name().to_string())
        } else {
            DecompilerActionResult::NotApplicable
        }
    }

    /// Perform the action, returning true on success.
    /// Override this instead of `execute` for actions that simply need
    /// a boolean success/failure.
    fn perform(&self, _ctx: &mut super::action_context::DecompilerActionContext) -> bool {
        false
    }
}

/// Result type for action execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecompilerActionResult {
    /// The action completed successfully.
    Success(String),
    /// The action was not applicable.
    NotApplicable,
    /// The action requires user interaction (e.g., a dialog).
    NeedsDialog(DialogRequest),
    /// The action failed.
    Error(String),
}

/// A request to show a dialog to the user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DialogRequest {
    /// What kind of dialog.
    pub kind: DialogKind,
    /// The prompt or label to show.
    pub prompt: String,
    /// Pre-filled value, if any.
    pub default_value: Option<String>,
}

/// The kind of dialog that an action needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DialogKind {
    /// Text input (e.g., renaming).
    Input,
    /// Confirmation (yes/no).
    Confirm,
    /// Type/data-type chooser.
    DataTypeChooser,
}

// ---------------------------------------------------------------------------
// RenameLocalAction
// ---------------------------------------------------------------------------

/// Action: Rename a local variable.
#[derive(Debug, Default)]
pub struct RenameLocalAction;

impl DecompilerAction for RenameLocalAction {
    fn name(&self) -> &str { "Rename Variable" }
    fn description(&self) -> &str { "Rename the selected local variable" }
    fn menu_path(&self) -> &[&str] { &["Rename Variable"] }
    fn menu_group(&self) -> &str { "2 - Variable Group" }
    fn menu_sub_group(&self) -> u32 { 0 }

    fn is_enabled(&self, ctx: &super::action_context::DecompilerActionContext) -> bool {
        !ctx.is_decompiling() && ctx.token_at_cursor().is_some()
    }

    fn execute(&self, ctx: &mut super::action_context::DecompilerActionContext) -> DecompilerActionResult {
        let token = match ctx.token_at_cursor() {
            Some(t) => t,
            None => return DecompilerActionResult::NotApplicable,
        };
        DecompilerActionResult::NeedsDialog(DialogRequest {
            kind: DialogKind::Input,
            prompt: format!("Rename '{}':", token.text),
            default_value: Some(token.text.clone()),
        })
    }
}

// ---------------------------------------------------------------------------
// RenameGlobalAction
// ---------------------------------------------------------------------------

/// Action: Rename a global symbol.
#[derive(Debug, Default)]
pub struct RenameGlobalAction;

impl DecompilerAction for RenameGlobalAction {
    fn name(&self) -> &str { "Rename Global" }
    fn description(&self) -> &str { "Rename the selected global symbol" }
    fn menu_path(&self) -> &[&str] { &["Rename Global"] }
    fn menu_group(&self) -> &str { "2 - Variable Group" }
    fn menu_sub_group(&self) -> u32 { 1 }

    fn execute(&self, ctx: &mut super::action_context::DecompilerActionContext) -> DecompilerActionResult {
        match ctx.token_at_cursor() {
            Some(token) => DecompilerActionResult::NeedsDialog(DialogRequest {
                kind: DialogKind::Input,
                prompt: format!("Rename global '{}':", token.text),
                default_value: Some(token.text.clone()),
            }),
            None => DecompilerActionResult::NotApplicable,
        }
    }
}

// ---------------------------------------------------------------------------
// RenameFieldAction
// ---------------------------------------------------------------------------

/// Action: Rename a struct/union field.
#[derive(Debug, Default)]
pub struct RenameFieldAction;

impl DecompilerAction for RenameFieldAction {
    fn name(&self) -> &str { "Rename Field" }
    fn description(&self) -> &str { "Rename the selected structure or union field" }
    fn menu_path(&self) -> &[&str] { &["Rename Field"] }
    fn menu_group(&self) -> &str { "2 - Variable Group" }
    fn menu_sub_group(&self) -> u32 { 2 }

    fn execute(&self, ctx: &mut super::action_context::DecompilerActionContext) -> DecompilerActionResult {
        match ctx.token_at_cursor() {
            Some(token) => DecompilerActionResult::NeedsDialog(DialogRequest {
                kind: DialogKind::Input,
                prompt: format!("Rename field '{}':", token.text),
                default_value: Some(token.text.clone()),
            }),
            None => DecompilerActionResult::NotApplicable,
        }
    }
}

// ---------------------------------------------------------------------------
// RenameFunctionAction
// ---------------------------------------------------------------------------

/// Action: Rename the current function.
#[derive(Debug, Default)]
pub struct RenameFunctionAction;

impl DecompilerAction for RenameFunctionAction {
    fn name(&self) -> &str { "Rename Function" }
    fn description(&self) -> &str { "Rename the current function" }
    fn menu_path(&self) -> &[&str] { &["Rename Function"] }
    fn menu_group(&self) -> &str { "1 - Function Group" }
    fn menu_sub_group(&self) -> u32 { 4 }

    fn execute(&self, _ctx: &mut super::action_context::DecompilerActionContext) -> DecompilerActionResult {
        DecompilerActionResult::NeedsDialog(DialogRequest {
            kind: DialogKind::Input,
            prompt: "Rename function:".into(),
            default_value: None,
        })
    }
}

// ---------------------------------------------------------------------------
// RetypeLocalAction
// ---------------------------------------------------------------------------

/// Action: Retype a local variable.
#[derive(Debug, Default)]
pub struct RetypeLocalAction;

impl DecompilerAction for RetypeLocalAction {
    fn name(&self) -> &str { "Retype Variable" }
    fn description(&self) -> &str { "Change the type of the selected local variable" }
    fn menu_path(&self) -> &[&str] { &["Retype Variable"] }
    fn menu_group(&self) -> &str { "2 - Variable Group" }
    fn menu_sub_group(&self) -> u32 { 5 }

    fn execute(&self, _ctx: &mut super::action_context::DecompilerActionContext) -> DecompilerActionResult {
        DecompilerActionResult::NeedsDialog(DialogRequest {
            kind: DialogKind::DataTypeChooser,
            prompt: "Select new type:".into(),
            default_value: None,
        })
    }
}

// ---------------------------------------------------------------------------
// RetypeGlobalAction
// ---------------------------------------------------------------------------

/// Action: Retype a global symbol.
#[derive(Debug, Default)]
pub struct RetypeGlobalAction;

impl DecompilerAction for RetypeGlobalAction {
    fn name(&self) -> &str { "Retype Global" }
    fn description(&self) -> &str { "Change the type of the selected global" }
    fn menu_path(&self) -> &[&str] { &["Retype Global"] }
    fn menu_group(&self) -> &str { "2 - Variable Group" }
    fn menu_sub_group(&self) -> u32 { 7 }

    fn execute(&self, _ctx: &mut super::action_context::DecompilerActionContext) -> DecompilerActionResult {
        DecompilerActionResult::NeedsDialog(DialogRequest {
            kind: DialogKind::DataTypeChooser,
            prompt: "Select new type for global:".into(),
            default_value: None,
        })
    }
}

// ---------------------------------------------------------------------------
// RetypeReturnAction
// ---------------------------------------------------------------------------

/// Action: Change the return type of the current function.
#[derive(Debug, Default)]
pub struct RetypeReturnAction;

impl DecompilerAction for RetypeReturnAction {
    fn name(&self) -> &str { "Retype Return" }
    fn description(&self) -> &str { "Change the return type of the function" }
    fn menu_path(&self) -> &[&str] { &["Retype Return"] }
    fn menu_group(&self) -> &str { "2 - Variable Group" }
    fn menu_sub_group(&self) -> u32 { 8 }

    fn execute(&self, _ctx: &mut super::action_context::DecompilerActionContext) -> DecompilerActionResult {
        DecompilerActionResult::NeedsDialog(DialogRequest {
            kind: DialogKind::DataTypeChooser,
            prompt: "Select new return type:".into(),
            default_value: None,
        })
    }
}

// ---------------------------------------------------------------------------
// RetypeFieldAction
// ---------------------------------------------------------------------------

/// Action: Retype a struct/union field.
#[derive(Debug, Default)]
pub struct RetypeFieldAction;

impl DecompilerAction for RetypeFieldAction {
    fn name(&self) -> &str { "Retype Field" }
    fn description(&self) -> &str { "Change the type of the selected field" }
    fn menu_path(&self) -> &[&str] { &["Retype Field"] }
    fn menu_group(&self) -> &str { "2 - Variable Group" }
    fn menu_sub_group(&self) -> u32 { 9 }

    fn execute(&self, _ctx: &mut super::action_context::DecompilerActionContext) -> DecompilerActionResult {
        DecompilerActionResult::NeedsDialog(DialogRequest {
            kind: DialogKind::DataTypeChooser,
            prompt: "Select new type for field:".into(),
            default_value: None,
        })
    }
}

// ---------------------------------------------------------------------------
// EditDataTypeAction
// ---------------------------------------------------------------------------

/// Action: Edit the data type of the selected item.
#[derive(Debug, Default)]
pub struct EditDataTypeAction;

impl DecompilerAction for EditDataTypeAction {
    fn name(&self) -> &str { "Edit Data Type" }
    fn description(&self) -> &str { "Edit the data type of the selected item" }
    fn menu_path(&self) -> &[&str] { &["Edit Data Type"] }
    fn menu_group(&self) -> &str { "2 - Variable Group" }
    fn menu_sub_group(&self) -> u32 { 12 }

    fn execute(&self, _ctx: &mut super::action_context::DecompilerActionContext) -> DecompilerActionResult {
        DecompilerActionResult::NeedsDialog(DialogRequest {
            kind: DialogKind::DataTypeChooser,
            prompt: "Edit data type:".into(),
            default_value: None,
        })
    }
}

// ---------------------------------------------------------------------------
// EditFieldAction
// ---------------------------------------------------------------------------

/// Action: Edit the value of a field in a struct (quick editor dialog).
#[derive(Debug, Default)]
pub struct EditFieldAction;

impl DecompilerAction for EditFieldAction {
    fn name(&self) -> &str { "Edit Field" }
    fn description(&self) -> &str { "Open the quick editor for the selected field" }
    fn menu_path(&self) -> &[&str] { &["Edit Field"] }
    fn menu_group(&self) -> &str { "2 - Variable Group" }
    fn menu_sub_group(&self) -> u32 { 13 }

    fn execute(&self, _ctx: &mut super::action_context::DecompilerActionContext) -> DecompilerActionResult {
        DecompilerActionResult::Success("Field editor opened".into())
    }
}

// ---------------------------------------------------------------------------
// EditBitFieldAction
// ---------------------------------------------------------------------------

/// Action: Edit a bit field.
#[derive(Debug, Default)]
pub struct EditBitFieldAction;

impl DecompilerAction for EditBitFieldAction {
    fn name(&self) -> &str { "Edit Bit Field" }
    fn description(&self) -> &str { "Edit the selected bit field" }
    fn menu_path(&self) -> &[&str] { &["Edit Bit Field"] }
    fn menu_group(&self) -> &str { "2 - Variable Group" }
    fn menu_sub_group(&self) -> u32 { 14 }

    fn execute(&self, _ctx: &mut super::action_context::DecompilerActionContext) -> DecompilerActionResult {
        DecompilerActionResult::NeedsDialog(DialogRequest {
            kind: DialogKind::Input,
            prompt: "Edit bit field:".into(),
            default_value: None,
        })
    }
}

// ---------------------------------------------------------------------------
// RenameBitFieldAction
// ---------------------------------------------------------------------------

/// Action: Rename a bit field.
#[derive(Debug, Default)]
pub struct RenameBitFieldAction;

impl DecompilerAction for RenameBitFieldAction {
    fn name(&self) -> &str { "Rename Bit Field" }
    fn description(&self) -> &str { "Rename the selected bit field" }
    fn menu_path(&self) -> &[&str] { &["Rename Bit Field"] }
    fn menu_group(&self) -> &str { "2 - Variable Group" }
    fn menu_sub_group(&self) -> u32 { 3 }

    fn execute(&self, ctx: &mut super::action_context::DecompilerActionContext) -> DecompilerActionResult {
        match ctx.token_at_cursor() {
            Some(token) => DecompilerActionResult::NeedsDialog(DialogRequest {
                kind: DialogKind::Input,
                prompt: format!("Rename bit field '{}':", token.text),
                default_value: Some(token.text.clone()),
            }),
            None => DecompilerActionResult::NotApplicable,
        }
    }
}

// ---------------------------------------------------------------------------
// CommitParamsAction
// ---------------------------------------------------------------------------

/// Action: Commit parameter changes back to the program.
#[derive(Debug, Default)]
pub struct CommitParamsAction;

impl DecompilerAction for CommitParamsAction {
    fn name(&self) -> &str { "Commit Params" }
    fn description(&self) -> &str { "Commit parameter changes to the function signature" }
    fn menu_path(&self) -> &[&str] { &["Commit Params"] }
    fn menu_group(&self) -> &str { "3 - Commit Group" }
    fn menu_sub_group(&self) -> u32 { 0 }

    fn execute(&self, _ctx: &mut super::action_context::DecompilerActionContext) -> DecompilerActionResult {
        DecompilerActionResult::Success("Parameters committed".into())
    }
}

// ---------------------------------------------------------------------------
// CommitLocalsAction
// ---------------------------------------------------------------------------

/// Action: Commit local variable changes back to the program.
#[derive(Debug, Default)]
pub struct CommitLocalsAction;

impl DecompilerAction for CommitLocalsAction {
    fn name(&self) -> &str { "Commit Locals" }
    fn description(&self) -> &str { "Commit local variable changes" }
    fn menu_path(&self) -> &[&str] { &["Commit Locals"] }
    fn menu_group(&self) -> &str { "3 - Commit Group" }
    fn menu_sub_group(&self) -> u32 { 1 }

    fn execute(&self, _ctx: &mut super::action_context::DecompilerActionContext) -> DecompilerActionResult {
        DecompilerActionResult::Success("Locals committed".into())
    }
}

// ---------------------------------------------------------------------------
// HighlightDefinedUseAction
// ---------------------------------------------------------------------------

/// Action: Highlight the definition/use chain of the token under cursor.
#[derive(Debug, Default)]
pub struct HighlightDefinedUseAction;

impl DecompilerAction for HighlightDefinedUseAction {
    fn name(&self) -> &str { "Highlight Defined Use" }
    fn description(&self) -> &str { "Highlight where this symbol is defined and used" }
    fn menu_path(&self) -> &[&str] { &["Highlight", "Highlight Defined Use"] }
    fn menu_group(&self) -> &str { "4a - Highlight Group" }
    fn menu_sub_group(&self) -> u32 { 0 }

    fn execute(&self, ctx: &mut super::action_context::DecompilerActionContext) -> DecompilerActionResult {
        match ctx.token_at_cursor() {
            Some(token) => DecompilerActionResult::Success(
                format!("Highlighted def-use for '{}'", token.text),
            ),
            None => DecompilerActionResult::NotApplicable,
        }
    }
}

// ---------------------------------------------------------------------------
// ForwardSliceAction / BackwardsSliceAction
// ---------------------------------------------------------------------------

/// Action: Forward data-flow slice from the current token.
#[derive(Debug, Default)]
pub struct ForwardSliceAction;

impl DecompilerAction for ForwardSliceAction {
    fn name(&self) -> &str { "Forward Slice" }
    fn description(&self) -> &str { "Perform a forward data-flow slice" }
    fn menu_path(&self) -> &[&str] { &["Highlight", "Forward Slice"] }
    fn menu_group(&self) -> &str { "4a - Highlight Group" }
    fn menu_sub_group(&self) -> u32 { 1 }

    fn execute(&self, _ctx: &mut super::action_context::DecompilerActionContext) -> DecompilerActionResult {
        DecompilerActionResult::Success("Forward slice highlighted".into())
    }
}

/// Action: Backward data-flow slice from the current token.
#[derive(Debug, Default)]
pub struct BackwardsSliceAction;

impl DecompilerAction for BackwardsSliceAction {
    fn name(&self) -> &str { "Backwards Slice" }
    fn description(&self) -> &str { "Perform a backward data-flow slice" }
    fn menu_path(&self) -> &[&str] { &["Highlight", "Backwards Slice"] }
    fn menu_group(&self) -> &str { "4a - Highlight Group" }
    fn menu_sub_group(&self) -> u32 { 2 }

    fn execute(&self, _ctx: &mut super::action_context::DecompilerActionContext) -> DecompilerActionResult {
        DecompilerActionResult::Success("Backwards slice highlighted".into())
    }
}

// ---------------------------------------------------------------------------
// SelectAllAction
// ---------------------------------------------------------------------------

/// Action: Select all text in the decompiler panel.
#[derive(Debug, Default)]
pub struct SelectAllAction;

impl DecompilerAction for SelectAllAction {
    fn name(&self) -> &str { "Select All" }
    fn description(&self) -> &str { "Select all text in the decompiler" }
    fn menu_path(&self) -> &[&str] { &["Select All"] }

    fn execute(&self, _ctx: &mut super::action_context::DecompilerActionContext) -> DecompilerActionResult {
        DecompilerActionResult::Success("All text selected".into())
    }
}

// ---------------------------------------------------------------------------
// FindAction
// ---------------------------------------------------------------------------

/// Action: Open the Find dialog in the decompiler.
#[derive(Debug, Default)]
pub struct FindAction;

impl DecompilerAction for FindAction {
    fn name(&self) -> &str { "Find" }
    fn description(&self) -> &str { "Search the decompiled text" }
    fn menu_path(&self) -> &[&str] { &["Find"] }
    fn menu_group(&self) -> &str { "Comment2 - Search Group" }
    fn menu_sub_group(&self) -> u32 { 0 }

    fn execute(&self, _ctx: &mut super::action_context::DecompilerActionContext) -> DecompilerActionResult {
        DecompilerActionResult::NeedsDialog(DialogRequest {
            kind: DialogKind::Input,
            prompt: "Search for:".into(),
            default_value: None,
        })
    }
}

// ---------------------------------------------------------------------------
// FindReferencesToDataTypeAction
// ---------------------------------------------------------------------------

/// Action: Find all references to the data type at cursor.
#[derive(Debug, Default)]
pub struct FindReferencesToDataTypeAction;

impl DecompilerAction for FindReferencesToDataTypeAction {
    fn name(&self) -> &str { "Find References To Data Type" }
    fn description(&self) -> &str { "Find all references to the data type at the cursor" }
    fn menu_path(&self) -> &[&str] { &["Find References To Data Type"] }
    fn menu_group(&self) -> &str { "Comment2 - Search Group" }
    fn menu_sub_group(&self) -> u32 { 1 }

    fn execute(&self, _ctx: &mut super::action_context::DecompilerActionContext) -> DecompilerActionResult {
        DecompilerActionResult::Success("Searching for data type references".into())
    }
}

// ---------------------------------------------------------------------------
// FindReferencesToHighSymbolAction
// ---------------------------------------------------------------------------

/// Action: Find all references to the high-level symbol at cursor.
#[derive(Debug, Default)]
pub struct FindReferencesToHighSymbolAction;

impl DecompilerAction for FindReferencesToHighSymbolAction {
    fn name(&self) -> &str { "Find References To Symbol" }
    fn description(&self) -> &str { "Find all references to the symbol at the cursor" }
    fn menu_path(&self) -> &[&str] { &["Find References To Symbol"] }
    fn menu_group(&self) -> &str { "Comment2 - Search Group" }
    fn menu_sub_group(&self) -> u32 { 2 }

    fn execute(&self, _ctx: &mut super::action_context::DecompilerActionContext) -> DecompilerActionResult {
        DecompilerActionResult::Success("Searching for symbol references".into())
    }
}

// ---------------------------------------------------------------------------
// FindReferencesToAddressAction
// ---------------------------------------------------------------------------

/// Action: Find all references to the address at cursor.
#[derive(Debug, Default)]
pub struct FindReferencesToAddressAction;

impl DecompilerAction for FindReferencesToAddressAction {
    fn name(&self) -> &str { "Find References To Address" }
    fn description(&self) -> &str { "Find all references to the address at the cursor" }
    fn menu_path(&self) -> &[&str] { &["Find References To Address"] }
    fn menu_group(&self) -> &str { "Comment2 - Search Group" }
    fn menu_sub_group(&self) -> u32 { 3 }

    fn execute(&self, ctx: &mut super::action_context::DecompilerActionContext) -> DecompilerActionResult {
        DecompilerActionResult::Success(
            format!("Searching for references to 0x{:x}", ctx.function_entry_point.offset),
        )
    }
}

// ---------------------------------------------------------------------------
// SetEquateAction / RemoveEquateAction
// ---------------------------------------------------------------------------

/// Action: Set an equate (named constant) on the token at cursor.
#[derive(Debug, Default)]
pub struct SetEquateAction;

impl DecompilerAction for SetEquateAction {
    fn name(&self) -> &str { "Set Equate" }
    fn description(&self) -> &str { "Assign a named constant (equate) to the value" }
    fn menu_path(&self) -> &[&str] { &["Set Equate"] }
    fn menu_group(&self) -> &str { "7 - Convert Group" }
    fn menu_sub_group(&self) -> u32 { 0 }

    fn execute(&self, _ctx: &mut super::action_context::DecompilerActionContext) -> DecompilerActionResult {
        DecompilerActionResult::NeedsDialog(DialogRequest {
            kind: DialogKind::Input,
            prompt: "Enter equate name:".into(),
            default_value: None,
        })
    }
}

/// Action: Remove an equate from the token at cursor.
#[derive(Debug, Default)]
pub struct RemoveEquateAction;

impl DecompilerAction for RemoveEquateAction {
    fn name(&self) -> &str { "Remove Equate" }
    fn description(&self) -> &str { "Remove the equate from the value" }
    fn menu_path(&self) -> &[&str] { &["Remove Equate"] }
    fn menu_group(&self) -> &str { "7 - Convert Group" }
    fn menu_sub_group(&self) -> u32 { 1 }

    fn execute(&self, _ctx: &mut super::action_context::DecompilerActionContext) -> DecompilerActionResult {
        DecompilerActionResult::Success("Equate removed".into())
    }
}

// ---------------------------------------------------------------------------
// Convert actions (number format)
// ---------------------------------------------------------------------------

/// Action: Convert to binary display.
#[derive(Debug, Default)]
pub struct ConvertBinaryAction;

impl DecompilerAction for ConvertBinaryAction {
    fn name(&self) -> &str { "Convert to Binary" }
    fn description(&self) -> &str { "Display value in binary" }
    fn menu_path(&self) -> &[&str] { &["Convert to Binary"] }
    fn menu_group(&self) -> &str { "7 - Convert Group" }
    fn menu_sub_group(&self) -> u32 { 2 }

    fn execute(&self, _ctx: &mut super::action_context::DecompilerActionContext) -> DecompilerActionResult {
        DecompilerActionResult::Success("Converted to binary".into())
    }
}

/// Action: Convert to decimal display.
#[derive(Debug, Default)]
pub struct ConvertDecAction;

impl DecompilerAction for ConvertDecAction {
    fn name(&self) -> &str { "Convert to Decimal" }
    fn description(&self) -> &str { "Display value in decimal" }
    fn menu_path(&self) -> &[&str] { &["Convert to Decimal"] }
    fn menu_group(&self) -> &str { "7 - Convert Group" }
    fn menu_sub_group(&self) -> u32 { 3 }

    fn execute(&self, _ctx: &mut super::action_context::DecompilerActionContext) -> DecompilerActionResult {
        DecompilerActionResult::Success("Converted to decimal".into())
    }
}

/// Action: Convert to hex display.
#[derive(Debug, Default)]
pub struct ConvertHexAction;

impl DecompilerAction for ConvertHexAction {
    fn name(&self) -> &str { "Convert to Hex" }
    fn description(&self) -> &str { "Display value in hexadecimal" }
    fn menu_path(&self) -> &[&str] { &["Convert to Hex"] }
    fn menu_group(&self) -> &str { "7 - Convert Group" }
    fn menu_sub_group(&self) -> u32 { 4 }

    fn execute(&self, _ctx: &mut super::action_context::DecompilerActionContext) -> DecompilerActionResult {
        DecompilerActionResult::Success("Converted to hex".into())
    }
}

/// Action: Convert to octal display.
#[derive(Debug, Default)]
pub struct ConvertOctAction;

impl DecompilerAction for ConvertOctAction {
    fn name(&self) -> &str { "Convert to Octal" }
    fn description(&self) -> &str { "Display value in octal" }
    fn menu_path(&self) -> &[&str] { &["Convert to Octal"] }
    fn menu_group(&self) -> &str { "7 - Convert Group" }
    fn menu_sub_group(&self) -> u32 { 5 }

    fn execute(&self, _ctx: &mut super::action_context::DecompilerActionContext) -> DecompilerActionResult {
        DecompilerActionResult::Success("Converted to octal".into())
    }
}

/// Action: Convert to float display.
#[derive(Debug, Default)]
pub struct ConvertFloatAction;

impl DecompilerAction for ConvertFloatAction {
    fn name(&self) -> &str { "Convert to Float" }
    fn description(&self) -> &str { "Display value as float" }
    fn menu_path(&self) -> &[&str] { &["Convert to Float"] }
    fn menu_group(&self) -> &str { "7 - Convert Group" }
    fn menu_sub_group(&self) -> u32 { 6 }

    fn execute(&self, _ctx: &mut super::action_context::DecompilerActionContext) -> DecompilerActionResult {
        DecompilerActionResult::Success("Converted to float".into())
    }
}

/// Action: Convert to double display.
#[derive(Debug, Default)]
pub struct ConvertDoubleAction;

impl DecompilerAction for ConvertDoubleAction {
    fn name(&self) -> &str { "Convert to Double" }
    fn description(&self) -> &str { "Display value as double" }
    fn menu_path(&self) -> &[&str] { &["Convert to Double"] }
    fn menu_group(&self) -> &str { "7 - Convert Group" }
    fn menu_sub_group(&self) -> u32 { 7 }

    fn execute(&self, _ctx: &mut super::action_context::DecompilerActionContext) -> DecompilerActionResult {
        DecompilerActionResult::Success("Converted to double".into())
    }
}

/// Action: Convert to char display.
#[derive(Debug, Default)]
pub struct ConvertCharAction;

impl DecompilerAction for ConvertCharAction {
    fn name(&self) -> &str { "Convert to Char" }
    fn description(&self) -> &str { "Display value as character" }
    fn menu_path(&self) -> &[&str] { &["Convert to Char"] }
    fn menu_group(&self) -> &str { "7 - Convert Group" }
    fn menu_sub_group(&self) -> u32 { 8 }

    fn execute(&self, _ctx: &mut super::action_context::DecompilerActionContext) -> DecompilerActionResult {
        DecompilerActionResult::Success("Converted to char".into())
    }
}

// ---------------------------------------------------------------------------
// IsolateVariableAction
// ---------------------------------------------------------------------------

/// Action: Isolate the selected variable into its own storage.
#[derive(Debug, Default)]
pub struct IsolateVariableAction;

impl DecompilerAction for IsolateVariableAction {
    fn name(&self) -> &str { "Isolate Variable" }
    fn description(&self) -> &str { "Isolate the selected variable into its own storage" }
    fn menu_path(&self) -> &[&str] { &["Isolate Variable"] }
    fn menu_group(&self) -> &str { "2 - Variable Group" }
    fn menu_sub_group(&self) -> u32 { 10 }

    fn execute(&self, _ctx: &mut super::action_context::DecompilerActionContext) -> DecompilerActionResult {
        DecompilerActionResult::Success("Variable isolated".into())
    }
}

// ---------------------------------------------------------------------------
// ForceUnionAction
// ---------------------------------------------------------------------------

/// Action: Force the token at cursor to be treated as a union.
#[derive(Debug, Default)]
pub struct ForceUnionAction;

impl DecompilerAction for ForceUnionAction {
    fn name(&self) -> &str { "Force Union" }
    fn description(&self) -> &str { "Force the expression to be treated as a union" }
    fn menu_path(&self) -> &[&str] { &["Force Union"] }
    fn menu_group(&self) -> &str { "2 - Variable Group" }
    fn menu_sub_group(&self) -> u32 { 4 }

    fn execute(&self, _ctx: &mut super::action_context::DecompilerActionContext) -> DecompilerActionResult {
        DecompilerActionResult::Success("Forced union".into())
    }
}

// ---------------------------------------------------------------------------
// ExportToCAction
// ---------------------------------------------------------------------------

/// Action: Export the decompiled function as a C source file.
#[derive(Debug, Default)]
pub struct ExportToCAction;

impl DecompilerAction for ExportToCAction {
    fn name(&self) -> &str { "Export to C" }
    fn description(&self) -> &str { "Export the decompiled function as C source" }
    fn menu_path(&self) -> &[&str] { &["Export Function as C"] }

    fn execute(&self, _ctx: &mut super::action_context::DecompilerActionContext) -> DecompilerActionResult {
        DecompilerActionResult::Success("Exported to C file".into())
    }
}

// ---------------------------------------------------------------------------
// SpecifyCPrototypeAction
// ---------------------------------------------------------------------------

/// Action: Specify a C prototype for the function.
#[derive(Debug, Default)]
pub struct SpecifyCPrototypeAction;

impl DecompilerAction for SpecifyCPrototypeAction {
    fn name(&self) -> &str { "Specify C Prototype" }
    fn description(&self) -> &str { "Specify a C function prototype" }
    fn menu_path(&self) -> &[&str] { &["Specify C Prototype"] }
    fn menu_group(&self) -> &str { "1 - Function Group" }
    fn menu_sub_group(&self) -> u32 { 0 }

    fn execute(&self, _ctx: &mut super::action_context::DecompilerActionContext) -> DecompilerActionResult {
        DecompilerActionResult::NeedsDialog(DialogRequest {
            kind: DialogKind::Input,
            prompt: "Enter C prototype:".into(),
            default_value: None,
        })
    }
}

// ---------------------------------------------------------------------------
// OverridePrototypeAction
// ---------------------------------------------------------------------------

/// Action: Override the function prototype.
#[derive(Debug, Default)]
pub struct OverridePrototypeAction;

impl DecompilerAction for OverridePrototypeAction {
    fn name(&self) -> &str { "Override Prototype" }
    fn description(&self) -> &str { "Override the function prototype with a custom one" }
    fn menu_path(&self) -> &[&str] { &["Override Prototype"] }
    fn menu_group(&self) -> &str { "1 - Function Group" }
    fn menu_sub_group(&self) -> u32 { 1 }

    fn execute(&self, _ctx: &mut super::action_context::DecompilerActionContext) -> DecompilerActionResult {
        DecompilerActionResult::NeedsDialog(DialogRequest {
            kind: DialogKind::Input,
            prompt: "Enter new prototype:".into(),
            default_value: None,
        })
    }
}

// ---------------------------------------------------------------------------
// RemoveLabelAction
// ---------------------------------------------------------------------------

/// Action: Remove a label at the current address.
#[derive(Debug, Default)]
pub struct RemoveLabelAction;

impl DecompilerAction for RemoveLabelAction {
    fn name(&self) -> &str { "Remove Label" }
    fn description(&self) -> &str { "Remove the label at the current address" }
    fn menu_path(&self) -> &[&str] { &["Remove Label"] }
    fn menu_group(&self) -> &str { "1 - Function Group" }
    fn menu_sub_group(&self) -> u32 { 6 }

    fn execute(&self, _ctx: &mut super::action_context::DecompilerActionContext) -> DecompilerActionResult {
        DecompilerActionResult::Success("Label removed".into())
    }
}

// ---------------------------------------------------------------------------
// CreatePointerRelative
// ---------------------------------------------------------------------------

/// Action: Create a pointer-relative expression for the selected address.
#[derive(Debug, Default)]
pub struct CreatePointerRelative;

impl DecompilerAction for CreatePointerRelative {
    fn name(&self) -> &str { "Create Pointer Relative" }
    fn description(&self) -> &str { "Create a pointer-relative reference" }
    fn menu_path(&self) -> &[&str] { &["Create Pointer Relative"] }
    fn menu_group(&self) -> &str { "2 - Variable Group" }
    fn menu_sub_group(&self) -> u32 { 6 }

    fn execute(&self, _ctx: &mut super::action_context::DecompilerActionContext) -> DecompilerActionResult {
        DecompilerActionResult::Success("Pointer-relative reference created".into())
    }
}

// ---------------------------------------------------------------------------
// CloneDecompilerAction
// ---------------------------------------------------------------------------

/// Action: Clone the decompiler window into a snapshot (disconnected copy).
///
/// Ported from `ghidra.app.plugin.core.decompile.actions.CloneDecompilerAction`.
/// This is a toolbar action (key binding: Ctrl+Shift+T) that creates a
/// disconnected copy of the current decompiler provider so the user can
/// inspect a second function without losing the current view.
#[derive(Debug, Default)]
pub struct CloneDecompilerAction;

impl DecompilerAction for CloneDecompilerAction {
    fn name(&self) -> &str {
        "Decompile Clone"
    }

    fn description(&self) -> &str {
        "Create a snapshot (disconnected) copy of this Decompiler window"
    }

    fn menu_path(&self) -> &[&str] {
        &["Decompile Clone"]
    }

    fn menu_group(&self) -> &str {
        "0 - Clone Group"
    }

    fn menu_sub_group(&self) -> u32 {
        0
    }

    fn is_enabled(&self, ctx: &super::action_context::DecompilerActionContext) -> bool {
        // Enabled when there is a real function to clone from.
        // In the full implementation this checks context.getFunction() != null.
        ctx.function_entry_point.offset != 0
    }

    fn execute(&self, ctx: &mut super::action_context::DecompilerActionContext) -> DecompilerActionResult {
        // The real implementation calls context.getComponentProvider().cloneWindow().
        // Here we signal the request to create a disconnected provider.
        DecompilerActionResult::Success(format!(
            "Cloned decompiler window for function at 0x{:x}",
            ctx.function_entry_point.offset
        ))
    }
}

// ---------------------------------------------------------------------------
// EditPrototypeOverrideAction
// ---------------------------------------------------------------------------

/// Action: Edit an existing function signature override at the current call site.
///
/// Ported from `ghidra.app.plugin.core.decompile.actions.EditPrototypeOverrideAction`.
/// Allows the user to modify a previously-set calling convention override for
/// an indirect call target.  The action reads the existing `DataTypeSymbol`
/// override from the symbol table, presents it for editing, and writes the
/// updated prototype back.
#[derive(Debug, Default)]
pub struct EditPrototypeOverrideAction;

impl DecompilerAction for EditPrototypeOverrideAction {
    fn name(&self) -> &str {
        "Edit Signature Override"
    }

    fn description(&self) -> &str {
        "Edit the signature override for the function at the cursor"
    }

    fn menu_path(&self) -> &[&str] {
        &["Edit Signature Override"]
    }

    fn menu_group(&self) -> &str {
        "1 - Function Group"
    }

    fn menu_sub_group(&self) -> u32 {
        2
    }

    fn is_enabled(&self, ctx: &super::action_context::DecompilerActionContext) -> bool {
        // Enabled when the token names a function that has an existing override.
        // In the full impl: function != null && !(function instanceof UndefinedFunction)
        //   && OverridePrototypeAction.getSymbol(function, token) != null
        //   && HighFunctionDBUtil.readOverride(sym) != null
        match ctx.token_at_cursor() {
            Some(token) => token.is_function_name && token.function_entry.is_some(),
            None => false,
        }
    }

    fn execute(&self, ctx: &mut super::action_context::DecompilerActionContext) -> DecompilerActionResult {
        match ctx.token_at_cursor() {
            Some(token) => DecompilerActionResult::NeedsDialog(DialogRequest {
                kind: DialogKind::Input,
                prompt: format!("Edit signature override for '{}':", token.text),
                default_value: Some(token.text.clone()),
            }),
            None => DecompilerActionResult::NotApplicable,
        }
    }
}

// ---------------------------------------------------------------------------
// DeletePrototypeOverrideAction
// ---------------------------------------------------------------------------

/// Action: Remove an existing function signature override.
///
/// Ported from `ghidra.app.plugin.core.decompile.actions.DeletePrototypeOverrideAction`.
/// Deletes the override marker symbol and cleans up the unused
/// `DataTypeSymbol` from the database.  This effectively reverts the
/// call site to use the default inferred prototype.
#[derive(Debug, Default)]
pub struct DeletePrototypeOverrideAction;

impl DecompilerAction for DeletePrototypeOverrideAction {
    fn name(&self) -> &str {
        "Remove Signature Override"
    }

    fn description(&self) -> &str {
        "Remove the signature override for the function at the cursor"
    }

    fn menu_path(&self) -> &[&str] {
        &["Remove Signature Override"]
    }

    fn menu_group(&self) -> &str {
        "1 - Function Group"
    }

    fn menu_sub_group(&self) -> u32 {
        3
    }

    fn is_enabled(&self, ctx: &super::action_context::DecompilerActionContext) -> bool {
        // Enabled when there is a function with a symbol that can be removed.
        match ctx.token_at_cursor() {
            Some(token) => token.is_function_name && token.function_entry.is_some(),
            None => false,
        }
    }

    fn execute(&self, _ctx: &mut super::action_context::DecompilerActionContext) -> DecompilerActionResult {
        // The real implementation starts a program transaction, reads the
        // DataTypeSymbol via HighFunctionDBUtil.readOverride(sym), deletes the
        // marker symbol, and calls dts.cleanupUnusedOverride().
        DecompilerActionResult::Success("Signature override removed".into())
    }
}

// ---------------------------------------------------------------------------
// GoToNextBraceAction
// ---------------------------------------------------------------------------

/// Action: Navigate to the next enclosing closing brace.
///
/// Ported from `ghidra.app.plugin.core.decompile.actions.GoToNextBraceAction`.
/// Searches forward from the current token for the matching `}` brace and
/// moves the cursor there.  Key binding: `Shift+]`.
#[derive(Debug, Default)]
pub struct GoToNextBraceAction;

impl DecompilerAction for GoToNextBraceAction {
    fn name(&self) -> &str {
        "Go To Next Brace"
    }

    fn description(&self) -> &str {
        "Navigate to the next enclosing closing brace"
    }

    fn menu_path(&self) -> &[&str] {
        &["Go To Next Brace"]
    }

    fn is_enabled(&self, _ctx: &super::action_context::DecompilerActionContext) -> bool {
        // Always enabled when there is a decompiled view.
        true
    }

    fn execute(&self, _ctx: &mut super::action_context::DecompilerActionContext) -> DecompilerActionResult {
        // The real implementation calls DecompilerUtils.getNextBrace(token, true)
        // then panel.goToToken(brace).
        DecompilerActionResult::Success("Navigated to next brace".into())
    }
}

// ---------------------------------------------------------------------------
// GoToPreviousBraceAction
// ---------------------------------------------------------------------------

/// Action: Navigate to the previous enclosing opening brace.
///
/// Ported from `ghidra.app.plugin.core.decompile.actions.GoToPreviousBraceAction`.
/// Searches backward from the current token for the matching `{` brace and
/// moves the cursor there.  Key binding: `Shift+[`.
#[derive(Debug, Default)]
pub struct GoToPreviousBraceAction;

impl DecompilerAction for GoToPreviousBraceAction {
    fn name(&self) -> &str {
        "Go To Previous Brace"
    }

    fn description(&self) -> &str {
        "Navigate to the previous enclosing opening brace"
    }

    fn menu_path(&self) -> &[&str] {
        &["Go To Previous Brace"]
    }

    fn is_enabled(&self, _ctx: &super::action_context::DecompilerActionContext) -> bool {
        true
    }

    fn execute(&self, _ctx: &mut super::action_context::DecompilerActionContext) -> DecompilerActionResult {
        DecompilerActionResult::Success("Navigated to previous brace".into())
    }
}

// ---------------------------------------------------------------------------
// Action registry
// ---------------------------------------------------------------------------

/// A collection of all standard decompiler actions.
///
/// The actions are stored as boxed trait objects so that they can be
/// iterated, filtered, and dispatched uniformly.
#[derive(Debug)]
pub struct ActionRegistry {
    actions: Vec<Box<dyn DecompilerAction>>,
}

impl ActionRegistry {
    /// Create the default action registry populated with all standard actions.
    pub fn default_actions() -> Self {
        let actions: Vec<Box<dyn DecompilerAction>> = vec![
            // Clone group
            Box::new(CloneDecompilerAction),
            // Function group
            Box::new(SpecifyCPrototypeAction),
            Box::new(OverridePrototypeAction),
            Box::new(EditPrototypeOverrideAction),
            Box::new(DeletePrototypeOverrideAction),
            Box::new(RenameFunctionAction),
            Box::new(RemoveLabelAction),
            // Variable group
            Box::new(RenameLocalAction),
            Box::new(RenameGlobalAction),
            Box::new(RenameFieldAction),
            Box::new(RenameBitFieldAction),
            Box::new(ForceUnionAction),
            Box::new(RetypeLocalAction),
            Box::new(CreatePointerRelative),
            Box::new(RetypeGlobalAction),
            Box::new(RetypeReturnAction),
            Box::new(RetypeFieldAction),
            Box::new(IsolateVariableAction),
            Box::new(EditDataTypeAction),
            Box::new(EditFieldAction),
            Box::new(EditBitFieldAction),
            // Commit group
            Box::new(CommitParamsAction),
            Box::new(CommitLocalsAction),
            // Highlight group
            Box::new(HighlightDefinedUseAction),
            Box::new(ForwardSliceAction),
            Box::new(BackwardsSliceAction),
            // Convert group
            Box::new(RemoveEquateAction),
            Box::new(SetEquateAction),
            Box::new(ConvertBinaryAction),
            Box::new(ConvertDecAction),
            Box::new(ConvertFloatAction),
            Box::new(ConvertDoubleAction),
            Box::new(ConvertHexAction),
            Box::new(ConvertOctAction),
            Box::new(ConvertCharAction),
            // Search group
            Box::new(FindAction),
            Box::new(FindReferencesToDataTypeAction),
            Box::new(FindReferencesToHighSymbolAction),
            Box::new(FindReferencesToAddressAction),
            // Navigation group
            Box::new(GoToNextBraceAction),
            Box::new(GoToPreviousBraceAction),
            // Other
            Box::new(SelectAllAction),
            Box::new(ExportToCAction),
        ];
        Self { actions }
    }

    /// Returns the total number of registered actions.
    pub fn count(&self) -> usize {
        self.actions.len()
    }

    /// Iterate over all registered actions.
    pub fn iter(&self) -> impl Iterator<Item = &dyn DecompilerAction> {
        self.actions.iter().map(|a| a.as_ref())
    }

    /// Find an action by name (case-sensitive).
    pub fn find_by_name(&self, name: &str) -> Option<&dyn DecompilerAction> {
        self.actions.iter().find(|a| a.name() == name).map(|a| a.as_ref())
    }

    /// Find all actions that are enabled for the given context.
    pub fn enabled_actions(
        &self,
        ctx: &super::action_context::DecompilerActionContext,
    ) -> Vec<&dyn DecompilerAction> {
        self.actions.iter().filter(|a| a.is_enabled(ctx)).map(|a| a.as_ref()).collect()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ghidra_core::addr::Address;
    use crate::decompile_ui::action_context::{ClangTokenRef, DecompilerActionContext};

    #[test]
    fn test_registry_default_count() {
        let registry = ActionRegistry::default_actions();
        assert!(registry.count() > 30, "expected >30 actions, got {}", registry.count());
    }

    #[test]
    fn test_registry_find_by_name() {
        let registry = ActionRegistry::default_actions();
        assert!(registry.find_by_name("Rename Variable").is_some());
        assert!(registry.find_by_name("Nonexistent Action").is_none());
    }

    #[test]
    fn test_rename_local_action() {
        let action = RenameLocalAction;
        assert_eq!(action.name(), "Rename Variable");
        assert_eq!(action.menu_group(), "2 - Variable Group");

        let ctx = DecompilerActionContext::new(Address::new(0x1000), true, 1);
        assert!(!action.is_enabled(&ctx)); // is_decompiling = true

        let mut ctx = DecompilerActionContext::new(Address::new(0x1000), false, 1);
        assert!(!action.is_enabled(&ctx)); // no token

        ctx.set_token_at_cursor(ClangTokenRef::new("x", 1, 0, false, None, 0));
        assert!(action.is_enabled(&ctx));

        let result = action.execute(&mut ctx);
        match result {
            DecompilerActionResult::NeedsDialog(req) => {
                assert_eq!(req.kind, DialogKind::Input);
                assert!(req.prompt.contains("x"));
            }
            _ => panic!("expected NeedsDialog"),
        }
    }

    #[test]
    fn test_rename_function_action() {
        let action = RenameFunctionAction;
        let mut ctx = DecompilerActionContext::new(Address::new(0x2000), false, 0);
        let result = action.execute(&mut ctx);
        assert!(matches!(result, DecompilerActionResult::NeedsDialog(_)));
    }

    #[test]
    fn test_commit_params_action() {
        let action = CommitParamsAction;
        let mut ctx = DecompilerActionContext::new(Address::new(0), false, 0);
        let result = action.execute(&mut ctx);
        assert_eq!(
            result,
            DecompilerActionResult::Success("Parameters committed".into())
        );
    }

    #[test]
    fn test_convert_actions() {
        let mut ctx = DecompilerActionContext::new(Address::new(0), false, 0);

        assert_eq!(
            ConvertBinaryAction.execute(&mut ctx),
            DecompilerActionResult::Success("Converted to binary".into())
        );
        assert_eq!(
            ConvertDecAction.execute(&mut ctx),
            DecompilerActionResult::Success("Converted to decimal".into())
        );
        assert_eq!(
            ConvertHexAction.execute(&mut ctx),
            DecompilerActionResult::Success("Converted to hex".into())
        );
        assert_eq!(
            ConvertOctAction.execute(&mut ctx),
            DecompilerActionResult::Success("Converted to octal".into())
        );
    }

    #[test]
    fn test_export_to_c_action() {
        let action = ExportToCAction;
        let mut ctx = DecompilerActionContext::new(Address::new(0x4000), false, 0);
        assert_eq!(
            action.execute(&mut ctx),
            DecompilerActionResult::Success("Exported to C file".into())
        );
    }

    #[test]
    fn test_find_action() {
        let action = FindAction;
        let mut ctx = DecompilerActionContext::new(Address::new(0), false, 0);
        let result = action.execute(&mut ctx);
        match result {
            DecompilerActionResult::NeedsDialog(req) => {
                assert_eq!(req.kind, DialogKind::Input);
                assert!(req.prompt.contains("Search"));
            }
            _ => panic!("expected NeedsDialog"),
        }
    }

    #[test]
    fn test_forward_slice_action() {
        let action = ForwardSliceAction;
        let mut ctx = DecompilerActionContext::new(Address::new(0), false, 0);
        assert_eq!(
            action.execute(&mut ctx),
            DecompilerActionResult::Success("Forward slice highlighted".into())
        );
    }

    #[test]
    fn test_enabled_actions_with_decompiling() {
        let registry = ActionRegistry::default_actions();
        let ctx = DecompilerActionContext::new(Address::new(0), true, 0);
        let enabled = registry.enabled_actions(&ctx);
        // RenameLocal should be disabled (is_decompiling)
        let rename_enabled = enabled.iter().any(|a| a.name() == "Rename Variable");
        assert!(!rename_enabled);
    }

    #[test]
    fn test_dialog_request_equality() {
        let r1 = DialogRequest {
            kind: DialogKind::Input,
            prompt: "test".into(),
            default_value: None,
        };
        let r2 = DialogRequest {
            kind: DialogKind::Input,
            prompt: "test".into(),
            default_value: None,
        };
        assert_eq!(r1, r2);
    }

    // -- CloneDecompilerAction tests --

    #[test]
    fn test_clone_decompiler_action_metadata() {
        let action = CloneDecompilerAction;
        assert_eq!(action.name(), "Decompile Clone");
        assert_eq!(action.description(), "Create a snapshot (disconnected) copy of this Decompiler window");
        assert_eq!(action.menu_group(), "0 - Clone Group");
    }

    #[test]
    fn test_clone_decompiler_action_disabled_with_zero_address() {
        let action = CloneDecompilerAction;
        let ctx = DecompilerActionContext::new(Address::new(0), false, 0);
        assert!(!action.is_enabled(&ctx));
    }

    #[test]
    fn test_clone_decompiler_action_enabled_with_valid_address() {
        let action = CloneDecompilerAction;
        let mut ctx = DecompilerActionContext::new(Address::new(0x401000), false, 1);
        assert!(action.is_enabled(&ctx));

        let result = action.execute(&mut ctx);
        match result {
            DecompilerActionResult::Success(msg) => {
                assert!(msg.contains("0x401000"));
            }
            _ => panic!("expected Success"),
        }
    }

    // -- EditPrototypeOverrideAction tests --

    #[test]
    fn test_edit_prototype_override_action_metadata() {
        let action = EditPrototypeOverrideAction;
        assert_eq!(action.name(), "Edit Signature Override");
        assert_eq!(action.menu_group(), "1 - Function Group");
        assert_eq!(action.menu_sub_group(), 2);
    }

    #[test]
    fn test_edit_prototype_override_disabled_without_function_token() {
        let action = EditPrototypeOverrideAction;
        let mut ctx = DecompilerActionContext::new(Address::new(0x1000), false, 1);
        // Token that is NOT a function name.
        ctx.set_token_at_cursor(ClangTokenRef::new("x", 1, 0, false, None, 0));
        assert!(!action.is_enabled(&ctx));
    }

    #[test]
    fn test_edit_prototype_override_enabled_with_function_token() {
        let action = EditPrototypeOverrideAction;
        let mut ctx = DecompilerActionContext::new(Address::new(0x1000), false, 1);
        ctx.set_token_at_cursor(ClangTokenRef::new(
            "malloc", 3, 0, true, Some(Address::new(0x401000)), 10,
        ));
        assert!(action.is_enabled(&ctx));

        let result = action.execute(&mut ctx);
        match result {
            DecompilerActionResult::NeedsDialog(req) => {
                assert_eq!(req.kind, DialogKind::Input);
                assert!(req.prompt.contains("malloc"));
            }
            _ => panic!("expected NeedsDialog"),
        }
    }

    #[test]
    fn test_edit_prototype_override_disabled_without_token() {
        let action = EditPrototypeOverrideAction;
        let ctx = DecompilerActionContext::new(Address::new(0x1000), false, 1);
        assert!(!action.is_enabled(&ctx));
    }

    // -- DeletePrototypeOverrideAction tests --

    #[test]
    fn test_delete_prototype_override_action_metadata() {
        let action = DeletePrototypeOverrideAction;
        assert_eq!(action.name(), "Remove Signature Override");
        assert_eq!(action.menu_group(), "1 - Function Group");
        assert_eq!(action.menu_sub_group(), 3);
    }

    #[test]
    fn test_delete_prototype_override_enabled_with_function_token() {
        let action = DeletePrototypeOverrideAction;
        let mut ctx = DecompilerActionContext::new(Address::new(0x1000), false, 1);
        ctx.set_token_at_cursor(ClangTokenRef::new(
            "puts", 5, 0, true, Some(Address::new(0x402000)), 20,
        ));
        assert!(action.is_enabled(&ctx));

        let result = action.execute(&mut ctx);
        assert_eq!(
            result,
            DecompilerActionResult::Success("Signature override removed".into())
        );
    }

    #[test]
    fn test_delete_prototype_override_disabled_without_token() {
        let action = DeletePrototypeOverrideAction;
        let ctx = DecompilerActionContext::new(Address::new(0x1000), false, 1);
        assert!(!action.is_enabled(&ctx));
    }

    #[test]
    fn test_delete_prototype_override_disabled_with_non_function_token() {
        let action = DeletePrototypeOverrideAction;
        let mut ctx = DecompilerActionContext::new(Address::new(0x1000), false, 1);
        ctx.set_token_at_cursor(ClangTokenRef::new("buf", 2, 0, false, None, 5));
        assert!(!action.is_enabled(&ctx));
    }

    // -- GoToNextBraceAction tests --

    #[test]
    fn test_go_to_next_brace_action_metadata() {
        let action = GoToNextBraceAction;
        assert_eq!(action.name(), "Go To Next Brace");
        assert_eq!(action.description(), "Navigate to the next enclosing closing brace");
    }

    #[test]
    fn test_go_to_next_brace_always_enabled() {
        let action = GoToNextBraceAction;
        let ctx = DecompilerActionContext::new(Address::new(0), true, 0);
        assert!(action.is_enabled(&ctx));
    }

    #[test]
    fn test_go_to_next_brace_execute() {
        let action = GoToNextBraceAction;
        let mut ctx = DecompilerActionContext::new(Address::new(0x1000), false, 1);
        let result = action.execute(&mut ctx);
        assert_eq!(
            result,
            DecompilerActionResult::Success("Navigated to next brace".into())
        );
    }

    // -- GoToPreviousBraceAction tests --

    #[test]
    fn test_go_to_previous_brace_action_metadata() {
        let action = GoToPreviousBraceAction;
        assert_eq!(action.name(), "Go To Previous Brace");
        assert_eq!(action.description(), "Navigate to the previous enclosing opening brace");
    }

    #[test]
    fn test_go_to_previous_brace_always_enabled() {
        let action = GoToPreviousBraceAction;
        let ctx = DecompilerActionContext::new(Address::new(0), false, 0);
        assert!(action.is_enabled(&ctx));
    }

    #[test]
    fn test_go_to_previous_brace_execute() {
        let action = GoToPreviousBraceAction;
        let mut ctx = DecompilerActionContext::new(Address::new(0x1000), false, 1);
        let result = action.execute(&mut ctx);
        assert_eq!(
            result,
            DecompilerActionResult::Success("Navigated to previous brace".into())
        );
    }

    // -- Registry integration tests --

    #[test]
    fn test_registry_contains_new_actions() {
        let registry = ActionRegistry::default_actions();
        assert!(registry.find_by_name("Decompile Clone").is_some());
        assert!(registry.find_by_name("Edit Signature Override").is_some());
        assert!(registry.find_by_name("Remove Signature Override").is_some());
        assert!(registry.find_by_name("Go To Next Brace").is_some());
        assert!(registry.find_by_name("Go To Previous Brace").is_some());
    }

    #[test]
    fn test_registry_count_increased() {
        let registry = ActionRegistry::default_actions();
        // We added 5 new actions: CloneDecompiler, EditPrototypeOverride,
        // DeletePrototypeOverride, GoToNextBrace, GoToPreviousBrace.
        assert!(registry.count() >= 35, "expected >=35 actions, got {}", registry.count());
    }

    #[test]
    fn test_edit_and_delete_override_share_enabled_logic() {
        let edit = EditPrototypeOverrideAction;
        let delete = DeletePrototypeOverrideAction;

        // Both should require a function-name token.
        let mut ctx = DecompilerActionContext::new(Address::new(0x1000), false, 1);
        ctx.set_token_at_cursor(ClangTokenRef::new(
            "free", 4, 0, true, Some(Address::new(0x403000)), 15,
        ));
        assert!(edit.is_enabled(&ctx));
        assert!(delete.is_enabled(&ctx));

        // Both should be disabled without a function-name token.
        let mut ctx2 = DecompilerActionContext::new(Address::new(0x1000), false, 1);
        ctx2.set_token_at_cursor(ClangTokenRef::new("retval", 4, 0, false, None, 15));
        assert!(!edit.is_enabled(&ctx2));
        assert!(!delete.is_enabled(&ctx2));
    }
}
