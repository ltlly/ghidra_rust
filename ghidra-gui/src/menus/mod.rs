//! Complete context menu and popup action system for the Ghidra GUI.
//!
//! Provides a comprehensive set of popup actions organized by context:
//! - **Listing context menu** (right-click on instruction/data): rename, comment,
//!   disassemble, function operations, data type definition, bookmarks, analysis,
//!   references, patch, copy, color, external program operations.
//! - **Function context menu**: edit signature, return type, calling convention,
//!   stack frame, local variables, graph operations.
//! - **Symbol tree context menu**: go to, rename, delete, categories, import/export.
//!
//! Each action is defined with name, display name, keybinding, enabled condition,
//! and emits an action variant for the application to handle.

use ghidra_core::addr::Address;

// ============================================================================
// Comprehensive Context Menu Action Enum
// ============================================================================

/// All possible actions that can be triggered from a context menu.
///
/// This is a superset of the listing-level [`super::listing::ListingAction`]
/// and covers every context menu item across all views.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum ContextMenuAction {
    // --- Separator ---
    #[default]
    Separator,

    // --- Label Operations ---
    /// Rename the label at the cursor address.  Key: L
    RenameLabel,
    /// Remove the label at the cursor address.
    RemoveLabel,

    // --- Comment Operations ---
    /// Set or edit a comment at the cursor address.  Key: ;
    SetComment,
    /// Edit an existing comment.
    EditComment,
    /// Delete all comments at the cursor address.
    DeleteComment,

    // --- Disassembly Operations ---
    /// Disassemble starting at the cursor address.  Key: D
    Disassemble,
    /// Clear code bytes / undefine.  Key: C
    ClearCodeBytes,

    // --- Function Operations ---
    /// Create a function at the cursor address.  Key: F
    CreateFunction,
    /// Delete the function at the cursor address.  Key: Delete
    DeleteFunction,
    /// Edit the function signature (parameters, return type).
    EditFunctionSignature,
    /// Set the return type of the current function.
    SetReturnType,
    /// Set the calling convention of the current function.
    SetCallingConvention,
    /// Edit the stack frame layout.
    EditStackFrame,
    /// Create a local variable in the current function.
    CreateLocalVariable,
    /// Delete a local variable from the current function.
    DeleteLocalVariable,
    /// Rename a local variable.
    RenameVariable,
    /// Set the type of a local variable.
    SetVariableType,
    /// Graph the control flow of the current function.
    GraphFunction,
    /// Graph all functions called by the current function.
    GraphCalls,
    /// Graph all functions that call the current function.
    GraphCalledBy,

    // --- Data Type Operations ---
    /// Define a byte at the cursor.
    DefineByte,
    /// Define a word (2 bytes) at the cursor.
    DefineWord,
    /// Define a dword (4 bytes) at the cursor.
    DefineDword,
    /// Define a qword (8 bytes) at the cursor.
    DefineQword,
    /// Define a single-precision float at the cursor.
    DefineFloat,
    /// Define a double-precision float at the cursor.
    DefineDouble,
    /// Define a string at the cursor.
    DefineString,
    /// Define a Unicode string at the cursor.
    DefineUnicode,
    /// Define a pointer at the cursor.
    DefinePointer,
    /// Define an array starting at the cursor.
    DefineArray,
    /// Define a struct at the cursor.
    DefineStruct,

    // --- Aggregate Operations ---
    /// Create an array at the selection.
    CreateArray,
    /// Create a pointer at the selection.
    CreatePointer,
    /// Create a structure from the selection.
    CreateStructure,
    /// Apply an existing structure type.
    ApplyStructure,

    // --- Register / Flow ---
    /// Set a register value at the cursor.
    SetRegisterValue,
    /// Set the flow override (branch, call, fallthrough).
    SetFlowOverride,

    // --- Bookmarks ---
    /// Add a bookmark at the cursor.
    AddBookmark,
    /// Remove all bookmarks at the cursor.
    RemoveBookmark,

    // --- Analysis ---
    /// Run auto-analysis starting at the cursor.
    AnalyzeFromHere,

    // --- Patch ---
    /// Patch instruction bytes.  Key: Ctrl+Shift+G
    PatchInstruction,
    /// Patch data bytes at the cursor.
    PatchData,

    // --- References ---
    /// Show all references to the cursor address.
    ShowReferencesTo,
    /// Show all references from the cursor address.
    ShowReferencesFrom,
    /// Show cross-references (both directions) for the cursor address.
    ShowXRefs,

    // --- Copy ---
    /// Copy the address to the clipboard.
    CopyAddress,
    /// Copy a string representation.
    CopyAsString,
    /// Copy raw bytes (hex) to clipboard.
    CopyBytes,
    /// Copy as a C array declaration.
    CopyAsCArray,
    /// Copy as a Python list.
    CopyAsPythonList,
    /// Copy the full instruction text.
    CopyInstruction,
    /// Copy the label text.
    CopyLabel,

    // --- Color ---
    /// Set the background color of the listing row.
    SetBackgroundColor,
    /// Set the text color of the listing row.
    SetTextColor,
    /// Clear all custom colors on the listing row.
    ClearColors,

    // --- External Program ---
    /// Open the selection in a new listing window.
    OpenInNewWindow,
    /// Edit the selection with an external tool (e.g., hex editor).
    EditWithExternalTool,

    // --- Symbol Tree ---
    /// Navigate to the symbol's address.
    GoTo,
    /// Rename a symbol in the tree.
    RenameSymbol,
    /// Delete a symbol from the tree.
    DeleteSymbol,
    /// Create a new category.
    CreateCategory,
    /// Move the symbol to a different category.
    MoveToCategory,
    /// Export symbols to a file.
    ExportSymbols,
    /// Import symbols from a file.
    ImportSymbols,
}

// ============================================================================
// PopupAction -- Named Action with Metadata
// ============================================================================

/// A single popup / context-menu action with full metadata.
///
/// Each action carries its identifying name, the label shown in the menu,
/// an optional keyboard shortcut string, and an enabled flag.  An enabled
/// condition closure allows the menu builder to determine availability at
/// the point a context menu opens.
#[derive(Clone)]
pub struct PopupAction {
    /// Unique programmatic identifier.
    pub name: String,
    /// Human-readable label in the menu (may include "..." suffix).
    pub display_name: String,
    /// Optional shortcut string (e.g. "L", "F", "Ctrl+Shift+G").
    pub keybinding: Option<String>,
    /// The action variant emitted when this item is clicked.
    pub action: ContextMenuAction,
    /// Whether this item is currently enabled.
    pub enabled: bool,
}

impl PopupAction {
    /// Create a new enabled action without a keybinding.
    pub fn new(
        name: impl Into<String>,
        display_name: impl Into<String>,
        action: ContextMenuAction,
    ) -> Self {
        Self {
            name: name.into(),
            display_name: display_name.into(),
            keybinding: None,
            action,
            enabled: true,
        }
    }

    /// Attach a keyboard shortcut label.
    pub fn with_keybinding(mut self, kb: impl Into<String>) -> Self {
        self.keybinding = Some(kb.into());
        self
    }

    /// Disable the action.
    pub fn disabled(mut self) -> Self {
        self.enabled = false;
        self
    }

    /// Enable or disable based on a condition.
    pub fn enabled_if(mut self, cond: bool) -> Self {
        self.enabled = cond;
        self
    }
}

impl std::fmt::Debug for PopupAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PopupAction")
            .field("name", &self.name)
            .field("display_name", &self.display_name)
            .field("keybinding", &self.keybinding)
            .field("action", &self.action)
            .field("enabled", &self.enabled)
            .finish()
    }
}

// ============================================================================
// Context Menu Builder Trait & Implementations
// ============================================================================

/// Trait for contexts that can supply their own context menu action list.
pub trait ContextMenuProvider {
    /// Return the list of popup actions for the current context.
    fn context_menu_actions(&self) -> Vec<PopupAction>;
}

// ============================================================================
// Listing Context Menu
// ============================================================================

/// Build the complete listing context menu action list.
///
/// This returns the full set of popup actions for right-click on an
/// instruction or data item, organized into logical groups (separators).
///
/// Parameters allow individual items to be enabled/disabled based on the
/// current row type (instruction vs. data, whether it has a label, etc.).
pub fn listing_context_actions(
    has_label: bool,
    has_comment: bool,
    is_instruction: bool,
    has_function: bool,
    has_bookmark: bool,
) -> Vec<PopupAction> {
    let mut actions = Vec::new();

    // -- Label Operations --
    actions.push(
        PopupAction::new(
            "rename_label",
            "Rename Label...",
            ContextMenuAction::RenameLabel,
        )
        .with_keybinding("L"),
    );
    actions.push(
        PopupAction::new(
            "remove_label",
            "Remove Label",
            ContextMenuAction::RemoveLabel,
        )
        .enabled_if(has_label),
    );
    actions.push(PopupAction::new("sep1", "", ContextMenuAction::Separator));

    // -- Comment Operations --
    actions.push(
        PopupAction::new(
            "set_comment",
            "Set Comment...",
            ContextMenuAction::SetComment,
        )
        .with_keybinding(";"),
    );
    actions.push(
        PopupAction::new(
            "edit_comment",
            "Edit Comment...",
            ContextMenuAction::EditComment,
        )
        .enabled_if(has_comment),
    );
    actions.push(
        PopupAction::new(
            "delete_comment",
            "Delete Comment",
            ContextMenuAction::DeleteComment,
        )
        .enabled_if(has_comment),
    );
    actions.push(PopupAction::new("sep2", "", ContextMenuAction::Separator));

    // -- Disassembly Operations --
    actions.push(
        PopupAction::new("disassemble", "Disassemble", ContextMenuAction::Disassemble)
            .with_keybinding("D"),
    );
    actions.push(
        PopupAction::new(
            "clear_code_bytes",
            "Clear Code Bytes",
            ContextMenuAction::ClearCodeBytes,
        )
        .with_keybinding("C"),
    );
    actions.push(PopupAction::new("sep3", "", ContextMenuAction::Separator));

    // -- Function Operations --
    actions.push(
        PopupAction::new(
            "create_function",
            "Create Function",
            ContextMenuAction::CreateFunction,
        )
        .with_keybinding("F")
        .enabled_if(!has_function),
    );
    actions.push(
        PopupAction::new(
            "delete_function",
            "Delete Function",
            ContextMenuAction::DeleteFunction,
        )
        .enabled_if(has_function),
    );
    actions.push(
        PopupAction::new(
            "edit_function_signature",
            "Edit Function Signature...",
            ContextMenuAction::EditFunctionSignature,
        )
        .enabled_if(has_function),
    );
    actions.push(PopupAction::new("sep4", "", ContextMenuAction::Separator));

    // -- Data / Create --
    actions.push(PopupAction::new(
        "create_data",
        "Create Data",
        ContextMenuAction::DefineByte,
    ));
    actions.push(PopupAction::new(
        "create_array",
        "Create Array...",
        ContextMenuAction::CreateArray,
    ));
    actions.push(PopupAction::new(
        "create_pointer",
        "Create Pointer",
        ContextMenuAction::CreatePointer,
    ));
    actions.push(PopupAction::new(
        "create_structure",
        "Create Structure...",
        ContextMenuAction::CreateStructure,
    ));
    actions.push(PopupAction::new(
        "apply_structure",
        "Apply Structure...",
        ContextMenuAction::ApplyStructure,
    ));
    actions.push(PopupAction::new("sep5", "", ContextMenuAction::Separator));

    // -- Register / Flow --
    actions.push(PopupAction::new(
        "set_register_value",
        "Set Register Value...",
        ContextMenuAction::SetRegisterValue,
    ));
    actions.push(
        PopupAction::new(
            "set_flow_override",
            "Set Flow Override...",
            ContextMenuAction::SetFlowOverride,
        )
        .enabled_if(is_instruction),
    );
    actions.push(PopupAction::new("sep6", "", ContextMenuAction::Separator));

    // -- Bookmarks --
    actions.push(PopupAction::new(
        "add_bookmark",
        "Add Bookmark...",
        ContextMenuAction::AddBookmark,
    ));
    actions.push(
        PopupAction::new(
            "remove_bookmark",
            "Remove Bookmark",
            ContextMenuAction::RemoveBookmark,
        )
        .enabled_if(has_bookmark),
    );
    actions.push(PopupAction::new("sep7", "", ContextMenuAction::Separator));

    // -- Analysis --
    actions.push(PopupAction::new(
        "analyze_from_here",
        "Analyze From Here",
        ContextMenuAction::AnalyzeFromHere,
    ));
    actions.push(PopupAction::new("sep8", "", ContextMenuAction::Separator));

    // -- Patch --
    actions.push(
        PopupAction::new(
            "patch_instruction",
            "Patch Instruction...",
            ContextMenuAction::PatchInstruction,
        )
        .enabled_if(is_instruction),
    );
    actions.push(
        PopupAction::new("patch_data", "Patch Data...", ContextMenuAction::PatchData)
            .enabled_if(!is_instruction),
    );
    actions.push(PopupAction::new("sep9", "", ContextMenuAction::Separator));

    // -- References --
    actions.push(PopupAction::new(
        "show_references_to",
        "Show References To",
        ContextMenuAction::ShowReferencesTo,
    ));
    actions.push(PopupAction::new(
        "show_references_from",
        "Show References From",
        ContextMenuAction::ShowReferencesFrom,
    ));
    actions.push(PopupAction::new(
        "show_xrefs",
        "Show XRefs",
        ContextMenuAction::ShowXRefs,
    ));
    actions.push(PopupAction::new("sep10", "", ContextMenuAction::Separator));

    // -- Copy --
    actions.push(PopupAction::new(
        "copy_address",
        "Copy Address",
        ContextMenuAction::CopyAddress,
    ));
    actions.push(
        PopupAction::new(
            "copy_instruction",
            "Copy Instruction",
            ContextMenuAction::CopyInstruction,
        )
        .enabled_if(is_instruction),
    );
    actions.push(
        PopupAction::new("copy_label", "Copy Label", ContextMenuAction::CopyLabel)
            .enabled_if(has_label),
    );
    actions.push(PopupAction::new(
        "copy_bytes",
        "Copy Bytes",
        ContextMenuAction::CopyBytes,
    ));
    actions.push(PopupAction::new(
        "copy_as_string",
        "Copy As String",
        ContextMenuAction::CopyAsString,
    ));
    actions.push(PopupAction::new(
        "copy_as_c_array",
        "Copy As C Array",
        ContextMenuAction::CopyAsCArray,
    ));
    actions.push(PopupAction::new(
        "copy_as_python_list",
        "Copy As Python List",
        ContextMenuAction::CopyAsPythonList,
    ));
    actions.push(PopupAction::new("sep11", "", ContextMenuAction::Separator));

    // -- Color --
    actions.push(PopupAction::new(
        "set_background_color",
        "Set Background Color...",
        ContextMenuAction::SetBackgroundColor,
    ));
    actions.push(PopupAction::new(
        "set_text_color",
        "Set Text Color...",
        ContextMenuAction::SetTextColor,
    ));
    actions.push(PopupAction::new(
        "clear_colors",
        "Clear Colors",
        ContextMenuAction::ClearColors,
    ));
    actions.push(PopupAction::new("sep12", "", ContextMenuAction::Separator));

    // -- External Program --
    actions.push(PopupAction::new(
        "open_in_new_window",
        "Open In New Window",
        ContextMenuAction::OpenInNewWindow,
    ));
    actions.push(PopupAction::new(
        "edit_with_external_tool",
        "Edit With External Tool...",
        ContextMenuAction::EditWithExternalTool,
    ));

    actions
}

// ============================================================================
// Data Type Submenu
// ============================================================================

/// Build the "Define Data Type" sub-menu action list.
pub fn data_type_submenu_actions() -> Vec<PopupAction> {
    vec![
        PopupAction::new("dt_byte", "byte", ContextMenuAction::DefineByte).with_keybinding("B"),
        PopupAction::new("dt_word", "word", ContextMenuAction::DefineWord),
        PopupAction::new("dt_dword", "dword", ContextMenuAction::DefineDword),
        PopupAction::new("dt_qword", "qword", ContextMenuAction::DefineQword),
        PopupAction::new("dt_sep1", "", ContextMenuAction::Separator),
        PopupAction::new("dt_float", "float", ContextMenuAction::DefineFloat),
        PopupAction::new("dt_double", "double", ContextMenuAction::DefineDouble),
        PopupAction::new("dt_sep2", "", ContextMenuAction::Separator),
        PopupAction::new("dt_string", "string", ContextMenuAction::DefineString),
        PopupAction::new("dt_unicode", "unicode", ContextMenuAction::DefineUnicode),
        PopupAction::new("dt_sep3", "", ContextMenuAction::Separator),
        PopupAction::new("dt_pointer", "pointer", ContextMenuAction::DefinePointer)
            .with_keybinding("P"),
        PopupAction::new("dt_array", "array...", ContextMenuAction::DefineArray)
            .with_keybinding("["),
        PopupAction::new("dt_struct", "struct...", ContextMenuAction::DefineStruct),
    ]
}

// ============================================================================
// Function Context Menu
// ============================================================================

/// Build the function-specific context menu action list.
///
/// This menu appears when right-clicking on a function entry point or
/// within a function body.
pub fn function_context_actions(
    has_function: bool,
    has_stack_frame: bool,
    has_local_variables: bool,
) -> Vec<PopupAction> {
    let mut actions = Vec::new();

    if !has_function {
        actions.push(
            PopupAction::new(
                "func_create",
                "Create Function",
                ContextMenuAction::CreateFunction,
            )
            .with_keybinding("F"),
        );
        return actions;
    }

    actions.push(PopupAction::new(
        "func_edit_sig",
        "Edit Function Signature...",
        ContextMenuAction::EditFunctionSignature,
    ));
    actions.push(PopupAction::new(
        "func_set_return",
        "Set Return Type...",
        ContextMenuAction::SetReturnType,
    ));
    actions.push(PopupAction::new(
        "func_set_calling",
        "Set Calling Convention...",
        ContextMenuAction::SetCallingConvention,
    ));
    actions.push(PopupAction::new(
        "func_sep1",
        "",
        ContextMenuAction::Separator,
    ));

    actions.push(
        PopupAction::new(
            "func_stack_frame",
            "Edit Stack Frame...",
            ContextMenuAction::EditStackFrame,
        )
        .enabled_if(has_stack_frame),
    );
    actions.push(PopupAction::new(
        "func_local_var",
        "Create Local Variable...",
        ContextMenuAction::CreateLocalVariable,
    ));
    actions.push(
        PopupAction::new(
            "func_del_local",
            "Delete Local Variable",
            ContextMenuAction::DeleteLocalVariable,
        )
        .enabled_if(has_local_variables),
    );
    actions.push(PopupAction::new(
        "func_sep2",
        "",
        ContextMenuAction::Separator,
    ));

    actions.push(PopupAction::new(
        "func_rename_var",
        "Rename Variable...",
        ContextMenuAction::RenameVariable,
    ));
    actions.push(PopupAction::new(
        "func_set_var_type",
        "Set Variable Type...",
        ContextMenuAction::SetVariableType,
    ));
    actions.push(PopupAction::new(
        "func_sep3",
        "",
        ContextMenuAction::Separator,
    ));

    actions.push(PopupAction::new(
        "func_graph",
        "Graph Function",
        ContextMenuAction::GraphFunction,
    ));
    actions.push(PopupAction::new(
        "func_graph_calls",
        "Graph Calls",
        ContextMenuAction::GraphCalls,
    ));
    actions.push(PopupAction::new(
        "func_graph_called_by",
        "Graph Called By",
        ContextMenuAction::GraphCalledBy,
    ));
    actions.push(PopupAction::new(
        "func_sep4",
        "",
        ContextMenuAction::Separator,
    ));

    actions.push(PopupAction::new(
        "func_delete",
        "Delete Function",
        ContextMenuAction::DeleteFunction,
    ));

    actions
}

// ============================================================================
// Symbol Tree Context Menu
// ============================================================================

/// Build the symbol tree context menu action list.
pub fn symbol_tree_context_actions(
    is_leaf: bool,
    is_category: bool,
    has_symbols_selected: bool,
) -> Vec<PopupAction> {
    let mut actions = Vec::new();

    if is_leaf {
        actions.push(PopupAction::new(
            "sym_goto",
            "Go To",
            ContextMenuAction::GoTo,
        ));
        actions.push(PopupAction::new(
            "sym_rename",
            "Rename",
            ContextMenuAction::RenameSymbol,
        ));
        actions.push(
            PopupAction::new("sym_delete", "Delete", ContextMenuAction::DeleteSymbol)
                .with_keybinding("Delete"),
        );
        actions.push(PopupAction::new(
            "sym_sep1",
            "",
            ContextMenuAction::Separator,
        ));
    }

    if is_category {
        actions.push(PopupAction::new(
            "sym_create_cat",
            "Create Category",
            ContextMenuAction::CreateCategory,
        ));
    }

    if is_leaf {
        actions.push(PopupAction::new(
            "sym_move",
            "Move To Category...",
            ContextMenuAction::MoveToCategory,
        ));
        actions.push(PopupAction::new(
            "sym_sep2",
            "",
            ContextMenuAction::Separator,
        ));
    }

    actions.push(
        PopupAction::new(
            "sym_export",
            "Export Symbols...",
            ContextMenuAction::ExportSymbols,
        )
        .enabled_if(has_symbols_selected),
    );
    actions.push(PopupAction::new(
        "sym_import",
        "Import Symbols...",
        ContextMenuAction::ImportSymbols,
    ));

    actions
}

// ============================================================================
// Context Menu Renderer
// ============================================================================

/// Render a popup action as a button inside an egui context menu.
///
/// Returns `Some(ContextMenuAction)` if the button was clicked and the menu
/// should close.
pub fn render_popup_action(action: &PopupAction, ui: &mut egui::Ui) -> Option<ContextMenuAction> {
    let label = match &action.keybinding {
        Some(kb) => format!("{}  [{}]", action.display_name, kb),
        None => action.display_name.clone(),
    };

    let response = ui.add_enabled(action.enabled, egui::Button::new(&label));

    if response.clicked() {
        ui.close_menu();
        Some(action.action.clone())
    } else {
        None
    }
}

/// Render a separator in a context menu.
pub fn render_separator(ui: &mut egui::Ui) {
    ui.separator();
}

/// Render a full list of popup actions into an egui context menu, returning
/// the first triggered action (if any).
pub fn render_context_menu(
    actions: &[PopupAction],
    ui: &mut egui::Ui,
) -> Option<ContextMenuAction> {
    let mut triggered = None;
    for action in actions {
        match &action.action {
            ContextMenuAction::Separator => {
                render_separator(ui);
            }
            _ => {
                if let Some(act) = render_popup_action(action, ui) {
                    triggered = Some(act);
                }
            }
        }
    }
    triggered
}

/// Render the listing context menu with the given row properties and return
/// any triggered action.
pub fn render_listing_context_menu(
    has_label: bool,
    has_comment: bool,
    is_instruction: bool,
    has_function: bool,
    has_bookmark: bool,
    ui: &mut egui::Ui,
) -> Option<ContextMenuAction> {
    render_context_menu(
        &listing_context_actions(
            has_label,
            has_comment,
            is_instruction,
            has_function,
            has_bookmark,
        ),
        ui,
    )
}

/// Render the function context menu and return any triggered action.
pub fn render_function_context_menu(
    has_function: bool,
    has_stack_frame: bool,
    has_local_variables: bool,
    ui: &mut egui::Ui,
) -> Option<ContextMenuAction> {
    render_context_menu(
        &function_context_actions(has_function, has_stack_frame, has_local_variables),
        ui,
    )
}

/// Render the symbol tree context menu and return any triggered action.
pub fn render_symbol_tree_context_menu(
    is_leaf: bool,
    is_category: bool,
    has_symbols_selected: bool,
    ui: &mut egui::Ui,
) -> Option<ContextMenuAction> {
    render_context_menu(
        &symbol_tree_context_actions(is_leaf, is_category, has_symbols_selected),
        ui,
    )
}

// ============================================================================
// Structured Menu Builder (for nested submenus)
// ============================================================================

/// A node in a structured context menu tree.
///
/// Used for building menus that contain sub-menus (like Data Type submenu
/// or Copy Special submenu). Each node can be a leaf action, a separator,
/// or a sub-menu containing more nodes.
#[derive(Debug, Clone)]
pub enum MenuNode {
    /// A clickable action item.
    Action(PopupAction),
    /// A visual separator.
    Separator,
    /// A sub-menu (label, child nodes).
    SubMenu(String, Vec<MenuNode>),
}

/// Build a structured listing context menu tree with sub-menus.
///
/// This provides the full Ghidra-style context menu with all nested submenus:
/// - Data Type submenu
/// - References submenu
/// - Copy Special submenu
/// - Color submenu
/// - External Program submenu
pub fn structured_listing_context_menu(
    has_label: bool,
    has_comment: bool,
    is_instruction: bool,
    has_function: bool,
    has_bookmark: bool,
) -> Vec<MenuNode> {
    vec![
        // -- Label Operations --
        MenuNode::Action(
            PopupAction::new(
                "rename_label",
                "Rename Label...",
                ContextMenuAction::RenameLabel,
            )
            .with_keybinding("L"),
        ),
        MenuNode::Action(
            PopupAction::new(
                "remove_label",
                "Remove Label",
                ContextMenuAction::RemoveLabel,
            )
            .enabled_if(has_label),
        ),
        MenuNode::Separator,
        // -- Comment Operations --
        MenuNode::Action(
            PopupAction::new(
                "set_comment",
                "Set Comment...",
                ContextMenuAction::SetComment,
            )
            .with_keybinding(";"),
        ),
        MenuNode::Action(
            PopupAction::new(
                "edit_comment",
                "Edit Comment",
                ContextMenuAction::EditComment,
            )
            .enabled_if(has_comment),
        ),
        MenuNode::Action(
            PopupAction::new(
                "delete_comment",
                "Delete Comment",
                ContextMenuAction::DeleteComment,
            )
            .enabled_if(has_comment),
        ),
        MenuNode::Separator,
        // -- Disassembly Operations --
        MenuNode::Action(
            PopupAction::new("disassemble", "Disassemble", ContextMenuAction::Disassemble)
                .with_keybinding("D"),
        ),
        MenuNode::Action(
            PopupAction::new(
                "clear_code_bytes",
                "Clear Code Bytes",
                ContextMenuAction::ClearCodeBytes,
            )
            .with_keybinding("C"),
        ),
        MenuNode::Separator,
        // -- Function Operations --
        MenuNode::Action(
            PopupAction::new(
                "create_function",
                "Create Function",
                ContextMenuAction::CreateFunction,
            )
            .with_keybinding("F")
            .enabled_if(!has_function),
        ),
        MenuNode::Action(
            PopupAction::new(
                "delete_function",
                "Delete Function",
                ContextMenuAction::DeleteFunction,
            )
            .enabled_if(has_function),
        ),
        MenuNode::Action(
            PopupAction::new(
                "edit_function_signature",
                "Edit Function Signature...",
                ContextMenuAction::EditFunctionSignature,
            )
            .enabled_if(has_function),
        ),
        MenuNode::Separator,
        // -- Create / Data --
        MenuNode::Action(PopupAction::new(
            "create_data",
            "Create Data",
            ContextMenuAction::DefineByte,
        )),
        // -- Data Type submenu --
        MenuNode::SubMenu(
            "Define Data Type".to_string(),
            vec![
                MenuNode::Action(
                    PopupAction::new("dt_byte", "byte", ContextMenuAction::DefineByte)
                        .with_keybinding("B"),
                ),
                MenuNode::Action(PopupAction::new(
                    "dt_word",
                    "word",
                    ContextMenuAction::DefineWord,
                )),
                MenuNode::Action(PopupAction::new(
                    "dt_dword",
                    "dword",
                    ContextMenuAction::DefineDword,
                )),
                MenuNode::Action(PopupAction::new(
                    "dt_qword",
                    "qword",
                    ContextMenuAction::DefineQword,
                )),
                MenuNode::Separator,
                MenuNode::Action(PopupAction::new(
                    "dt_float",
                    "float",
                    ContextMenuAction::DefineFloat,
                )),
                MenuNode::Action(PopupAction::new(
                    "dt_double",
                    "double",
                    ContextMenuAction::DefineDouble,
                )),
                MenuNode::Separator,
                MenuNode::Action(PopupAction::new(
                    "dt_string",
                    "string",
                    ContextMenuAction::DefineString,
                )),
                MenuNode::Action(PopupAction::new(
                    "dt_unicode",
                    "unicode",
                    ContextMenuAction::DefineUnicode,
                )),
                MenuNode::Separator,
                MenuNode::Action(
                    PopupAction::new("dt_pointer", "pointer", ContextMenuAction::DefinePointer)
                        .with_keybinding("P"),
                ),
                MenuNode::Action(
                    PopupAction::new("dt_array", "array...", ContextMenuAction::DefineArray)
                        .with_keybinding("["),
                ),
                MenuNode::Action(PopupAction::new(
                    "dt_struct",
                    "struct...",
                    ContextMenuAction::DefineStruct,
                )),
            ],
        ),
        MenuNode::Action(PopupAction::new(
            "create_array",
            "Create Array...",
            ContextMenuAction::CreateArray,
        )),
        MenuNode::Action(PopupAction::new(
            "create_pointer",
            "Create Pointer",
            ContextMenuAction::CreatePointer,
        )),
        MenuNode::Action(PopupAction::new(
            "create_structure",
            "Create Structure...",
            ContextMenuAction::CreateStructure,
        )),
        MenuNode::Action(PopupAction::new(
            "apply_structure",
            "Apply Structure...",
            ContextMenuAction::ApplyStructure,
        )),
        MenuNode::Separator,
        // -- Register / Flow --
        MenuNode::Action(PopupAction::new(
            "set_register_value",
            "Set Register Value...",
            ContextMenuAction::SetRegisterValue,
        )),
        MenuNode::Action(
            PopupAction::new(
                "set_flow_override",
                "Set Flow Override...",
                ContextMenuAction::SetFlowOverride,
            )
            .enabled_if(is_instruction),
        ),
        MenuNode::Separator,
        // -- Bookmarks --
        MenuNode::Action(PopupAction::new(
            "add_bookmark",
            "Add Bookmark...",
            ContextMenuAction::AddBookmark,
        )),
        MenuNode::Action(
            PopupAction::new(
                "remove_bookmark",
                "Remove Bookmark",
                ContextMenuAction::RemoveBookmark,
            )
            .enabled_if(has_bookmark),
        ),
        MenuNode::Separator,
        // -- Analysis --
        MenuNode::Action(PopupAction::new(
            "analyze_from_here",
            "Analyze From Here",
            ContextMenuAction::AnalyzeFromHere,
        )),
        MenuNode::Separator,
        // -- Patch --
        MenuNode::Action(
            PopupAction::new(
                "patch_instruction",
                "Patch Instruction...",
                ContextMenuAction::PatchInstruction,
            )
            .enabled_if(is_instruction),
        ),
        MenuNode::Action(
            PopupAction::new("patch_data", "Patch Data...", ContextMenuAction::PatchData)
                .enabled_if(!is_instruction),
        ),
        MenuNode::Separator,
        // -- References submenu --
        MenuNode::SubMenu(
            "References".to_string(),
            vec![
                MenuNode::Action(PopupAction::new(
                    "show_refs_to",
                    "Show References To",
                    ContextMenuAction::ShowReferencesTo,
                )),
                MenuNode::Action(PopupAction::new(
                    "show_refs_from",
                    "Show References From",
                    ContextMenuAction::ShowReferencesFrom,
                )),
                MenuNode::Separator,
                MenuNode::Action(PopupAction::new(
                    "show_xrefs",
                    "Show XRefs",
                    ContextMenuAction::ShowXRefs,
                )),
            ],
        ),
        MenuNode::Separator,
        // -- Copy / Copy Special submenu --
        MenuNode::Action(
            PopupAction::new("copy", "Copy", ContextMenuAction::CopyInstruction)
                .enabled_if(is_instruction),
        ),
        MenuNode::SubMenu(
            "Copy Special".to_string(),
            vec![
                MenuNode::Action(PopupAction::new(
                    "copy_addr",
                    "Copy Address",
                    ContextMenuAction::CopyAddress,
                )),
                MenuNode::Action(PopupAction::new(
                    "copy_bytes",
                    "Copy Bytes",
                    ContextMenuAction::CopyBytes,
                )),
                MenuNode::Separator,
                MenuNode::Action(PopupAction::new(
                    "copy_string",
                    "Copy As String",
                    ContextMenuAction::CopyAsString,
                )),
                MenuNode::Action(PopupAction::new(
                    "copy_c_array",
                    "Copy As C Array",
                    ContextMenuAction::CopyAsCArray,
                )),
                MenuNode::Action(PopupAction::new(
                    "copy_py_list",
                    "Copy As Python List",
                    ContextMenuAction::CopyAsPythonList,
                )),
            ],
        ),
        MenuNode::Separator,
        // -- Color submenu --
        MenuNode::SubMenu(
            "Color".to_string(),
            vec![
                MenuNode::Action(PopupAction::new(
                    "set_bg_color",
                    "Set Background Color...",
                    ContextMenuAction::SetBackgroundColor,
                )),
                MenuNode::Action(PopupAction::new(
                    "set_text_color",
                    "Set Text Color...",
                    ContextMenuAction::SetTextColor,
                )),
                MenuNode::Separator,
                MenuNode::Action(PopupAction::new(
                    "clear_colors",
                    "Clear Colors",
                    ContextMenuAction::ClearColors,
                )),
            ],
        ),
        MenuNode::Separator,
        // -- External Program submenu --
        MenuNode::SubMenu(
            "External Program".to_string(),
            vec![
                MenuNode::Action(PopupAction::new(
                    "new_window",
                    "Open In New Window",
                    ContextMenuAction::OpenInNewWindow,
                )),
                MenuNode::Action(PopupAction::new(
                    "ext_tool",
                    "Edit With External Tool...",
                    ContextMenuAction::EditWithExternalTool,
                )),
            ],
        ),
    ]
}

/// Render a `MenuNode` tree into an egui context menu.
///
/// Recursively renders submenus using `ui.menu_button`. Returns the first
/// triggered action.
pub fn render_menu_node_tree(nodes: &[MenuNode], ui: &mut egui::Ui) -> Option<ContextMenuAction> {
    let mut triggered = None;
    for node in nodes {
        if triggered.is_some() {
            break;
        }
        match node {
            MenuNode::Separator => {
                ui.separator();
            }
            MenuNode::Action(action) => {
                if let Some(act) = render_popup_action(action, ui) {
                    triggered = Some(act);
                }
            }
            MenuNode::SubMenu(label, children) => {
                ui.menu_button(label, |ui| {
                    if let Some(act) = render_menu_node_tree(children, ui) {
                        ui.close_menu();
                        // We can't propagate the action out of the closure easily,
                        // so we use a workaround: store it in the outer scope via
                        // the ui context data.
                        ui.ctx().data_mut(|d| {
                            d.insert_temp(egui::Id::new("ctx_menu_triggered"), act);
                        });
                    }
                });
            }
        }
    }
    // Check for actions triggered from submenus
    if triggered.is_none() {
        triggered = ui
            .ctx()
            .data_mut(|d| d.remove_temp::<ContextMenuAction>(egui::Id::new("ctx_menu_triggered")));
    }
    triggered
}

/// Render the structured listing context menu with nested submenus.
pub fn render_structured_listing_context_menu(
    has_label: bool,
    has_comment: bool,
    is_instruction: bool,
    has_function: bool,
    has_bookmark: bool,
    ui: &mut egui::Ui,
) -> Option<ContextMenuAction> {
    let nodes = structured_listing_context_menu(
        has_label,
        has_comment,
        is_instruction,
        has_function,
        has_bookmark,
    );
    render_menu_node_tree(&nodes, ui)
}

// ============================================================================
// Callback Action Dispatch Map
// ============================================================================

/// A registry of callbacks keyed by action name.
///
/// Each callback receives the `ContextMenuAction` and the address at which
/// the context menu was opened.
pub type ActionCallback = Box<dyn Fn(&ContextMenuAction, Address)>;

/// Registry mapping action names to their handler callbacks.
pub struct ActionCallbackRegistry {
    callbacks: std::collections::HashMap<String, ActionCallback>,
}

impl ActionCallbackRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self {
            callbacks: std::collections::HashMap::new(),
        }
    }

    /// Register a callback for a specific action name.
    pub fn register(
        &mut self,
        action_name: impl Into<String>,
        callback: impl Fn(&ContextMenuAction, Address) + 'static,
    ) {
        self.callbacks
            .insert(action_name.into(), Box::new(callback));
    }

    /// Dispatch an action by name with the given address.
    /// Returns `true` if a callback was found and invoked.
    pub fn dispatch(&self, action: &ContextMenuAction, addr: Address) -> bool {
        let name = action_name(action);
        if let Some(cb) = self.callbacks.get(name) {
            cb(action, addr);
            true
        } else {
            false
        }
    }

    /// Returns `true` if the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.callbacks.is_empty()
    }

    /// Clear all registered callbacks.
    pub fn clear(&mut self) {
        self.callbacks.clear();
    }
}

impl Default for ActionCallbackRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Convert a `ContextMenuAction` to a string name suitable for callback lookup.
pub fn action_name(action: &ContextMenuAction) -> &'static str {
    match action {
        ContextMenuAction::Separator => "separator",
        ContextMenuAction::RenameLabel => "rename_label",
        ContextMenuAction::RemoveLabel => "remove_label",
        ContextMenuAction::SetComment => "set_comment",
        ContextMenuAction::EditComment => "edit_comment",
        ContextMenuAction::DeleteComment => "delete_comment",
        ContextMenuAction::Disassemble => "disassemble",
        ContextMenuAction::ClearCodeBytes => "clear_code_bytes",
        ContextMenuAction::CreateFunction => "create_function",
        ContextMenuAction::DeleteFunction => "delete_function",
        ContextMenuAction::EditFunctionSignature => "edit_function_signature",
        ContextMenuAction::SetReturnType => "set_return_type",
        ContextMenuAction::SetCallingConvention => "set_calling_convention",
        ContextMenuAction::EditStackFrame => "edit_stack_frame",
        ContextMenuAction::CreateLocalVariable => "create_local_variable",
        ContextMenuAction::DeleteLocalVariable => "delete_local_variable",
        ContextMenuAction::RenameVariable => "rename_variable",
        ContextMenuAction::SetVariableType => "set_variable_type",
        ContextMenuAction::GraphFunction => "graph_function",
        ContextMenuAction::GraphCalls => "graph_calls",
        ContextMenuAction::GraphCalledBy => "graph_called_by",
        ContextMenuAction::DefineByte => "define_byte",
        ContextMenuAction::DefineWord => "define_word",
        ContextMenuAction::DefineDword => "define_dword",
        ContextMenuAction::DefineQword => "define_qword",
        ContextMenuAction::DefineFloat => "define_float",
        ContextMenuAction::DefineDouble => "define_double",
        ContextMenuAction::DefineString => "define_string",
        ContextMenuAction::DefineUnicode => "define_unicode",
        ContextMenuAction::DefinePointer => "define_pointer",
        ContextMenuAction::DefineArray => "define_array",
        ContextMenuAction::DefineStruct => "define_struct",
        ContextMenuAction::CreateArray => "create_array",
        ContextMenuAction::CreatePointer => "create_pointer",
        ContextMenuAction::CreateStructure => "create_structure",
        ContextMenuAction::ApplyStructure => "apply_structure",
        ContextMenuAction::SetRegisterValue => "set_register_value",
        ContextMenuAction::SetFlowOverride => "set_flow_override",
        ContextMenuAction::AddBookmark => "add_bookmark",
        ContextMenuAction::RemoveBookmark => "remove_bookmark",
        ContextMenuAction::AnalyzeFromHere => "analyze_from_here",
        ContextMenuAction::PatchInstruction => "patch_instruction",
        ContextMenuAction::PatchData => "patch_data",
        ContextMenuAction::ShowReferencesTo => "show_references_to",
        ContextMenuAction::ShowReferencesFrom => "show_references_from",
        ContextMenuAction::ShowXRefs => "show_xrefs",
        ContextMenuAction::CopyAddress => "copy_address",
        ContextMenuAction::CopyAsString => "copy_as_string",
        ContextMenuAction::CopyBytes => "copy_bytes",
        ContextMenuAction::CopyAsCArray => "copy_as_c_array",
        ContextMenuAction::CopyAsPythonList => "copy_as_python_list",
        ContextMenuAction::CopyInstruction => "copy_instruction",
        ContextMenuAction::CopyLabel => "copy_label",
        ContextMenuAction::SetBackgroundColor => "set_background_color",
        ContextMenuAction::SetTextColor => "set_text_color",
        ContextMenuAction::ClearColors => "clear_colors",
        ContextMenuAction::OpenInNewWindow => "open_in_new_window",
        ContextMenuAction::EditWithExternalTool => "edit_with_external_tool",
        ContextMenuAction::GoTo => "go_to",
        ContextMenuAction::RenameSymbol => "rename_symbol",
        ContextMenuAction::DeleteSymbol => "delete_symbol",
        ContextMenuAction::CreateCategory => "create_category",
        ContextMenuAction::MoveToCategory => "move_to_category",
        ContextMenuAction::ExportSymbols => "export_symbols",
        ContextMenuAction::ImportSymbols => "import_symbols",
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_listing_context_actions_count() {
        let actions = listing_context_actions(true, true, true, true, true);
        // Should be non-empty and include all expected items
        assert!(!actions.is_empty());
        let non_seps: Vec<_> = actions
            .iter()
            .filter(|a| a.action != ContextMenuAction::Separator)
            .collect();
        assert!(non_seps.len() >= 30); // At least 30 real actions
    }

    #[test]
    fn test_listing_context_actions_empty_row() {
        let actions = listing_context_actions(false, false, false, false, false);
        // Even an empty row should have many actions available
        let non_seps: Vec<_> = actions
            .iter()
            .filter(|a| a.action != ContextMenuAction::Separator)
            .collect();
        assert!(non_seps.len() >= 20);
    }

    #[test]
    fn test_data_type_submenu_actions() {
        let actions = data_type_submenu_actions();
        assert!(!actions.is_empty());
        let non_seps: Vec<_> = actions
            .iter()
            .filter(|a| a.action != ContextMenuAction::Separator)
            .collect();
        assert_eq!(non_seps.len(), 11); // byte, word, dword, qword, float, double, string, unicode, pointer, array, struct
    }

    #[test]
    fn test_function_context_actions_with_function() {
        let actions = function_context_actions(true, true, true);
        assert!(!actions.is_empty());
        let non_seps: Vec<_> = actions
            .iter()
            .filter(|a| a.action != ContextMenuAction::Separator)
            .collect();
        assert_eq!(non_seps.len(), 14); // All the function-related items
    }

    #[test]
    fn test_function_context_actions_no_function() {
        let actions = function_context_actions(false, false, false);
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0].action, ContextMenuAction::CreateFunction);
    }

    #[test]
    fn test_symbol_tree_context_actions_leaf() {
        let actions = symbol_tree_context_actions(true, false, true);
        let non_seps: Vec<_> = actions
            .iter()
            .filter(|a| a.action != ContextMenuAction::Separator)
            .collect();
        assert_eq!(non_seps.len(), 6); // Go To, Rename, Delete, Move To, Export, Import
    }

    #[test]
    fn test_symbol_tree_context_actions_category() {
        let actions = symbol_tree_context_actions(false, true, false);
        let non_seps: Vec<_> = actions
            .iter()
            .filter(|a| a.action != ContextMenuAction::Separator)
            .collect();
        assert_eq!(non_seps.len(), 3); // Create Category, Export, Import
    }

    #[test]
    fn test_action_name_roundtrip() {
        for action in &[
            ContextMenuAction::RenameLabel,
            ContextMenuAction::Disassemble,
            ContextMenuAction::CreateFunction,
            ContextMenuAction::DefineByte,
            ContextMenuAction::CopyAddress,
            ContextMenuAction::GoTo,
            ContextMenuAction::ExportSymbols,
        ] {
            let name = action_name(action);
            assert!(!name.is_empty());
        }
    }

    #[test]
    fn test_popup_action_builder() {
        let action = PopupAction::new("test", "Test Action", ContextMenuAction::Disassemble)
            .with_keybinding("D")
            .enabled_if(false);

        assert_eq!(action.name, "test");
        assert_eq!(action.display_name, "Test Action");
        assert_eq!(action.keybinding, Some("D".to_string()));
        assert!(!action.enabled);
    }

    #[test]
    fn test_action_callback_registry() {
        use std::sync::{Arc, Mutex};
        let mut registry = ActionCallbackRegistry::new();
        let called = Arc::new(Mutex::new(false));
        let called_clone = called.clone();

        registry.register("rename_label", move |_action, _addr| {
            *called_clone.lock().unwrap() = true;
        });

        assert!(!registry.is_empty());
        let result = registry.dispatch(&ContextMenuAction::RenameLabel, Address::new(0x1000));
        assert!(result);
        assert!(*called.lock().unwrap());
    }

    #[test]
    fn test_structured_listing_menu() {
        let nodes = structured_listing_context_menu(true, true, true, true, true);
        assert!(!nodes.is_empty());
        // Count the number of submenus
        let submenu_count = nodes
            .iter()
            .filter(|n| matches!(n, MenuNode::SubMenu(_, _)))
            .count();
        assert_eq!(submenu_count, 4); // Data Type, References, Copy Special, Color
    }
}
