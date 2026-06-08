//! Label actions -- Rust port of `RenameLabelAction` from
//! `ghidra.app.plugin.core.decompile.actions`.
//!
//! This action allows the user to rename a label (symbol) at the cursor
//! position in the decompiler panel.  Labels are symbols of type
//! `SymbolType::LABEL` with a `Source` of either `DEFAULT` or
//! `USER_DEFINED`.
//!
//! # Architecture
//!
//! ```text
//! RenameLabelAction    L key
//!   checks: cursor token is a ClangLabelToken
//!   gets:   Symbol at the label's address
//!   opens:  AddEditDialog for label editing
//! ```
//!
//! In the Java source, the action calls either `dialog.addLabel()` or
//! `dialog.editLabel()` depending on whether the symbol is a default-
//! source label or a user-defined one.  In Rust we model the dialog
//! interaction as a `LabelEditRequest` that the provider/tool layer
//! can fulfil.

use super::action_context::DecompilerActionContext;
use super::actions::DecompilerAction;

// ---------------------------------------------------------------------------
// LabelEditRequest -- describes the dialog the provider should open
// ---------------------------------------------------------------------------

/// The kind of label-editing dialog to present.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LabelEditKind {
    /// The symbol is a default-source label; the dialog should offer to
    /// *add* (create) a new label at the address.
    Add,
    /// The symbol is a user-defined or imported label; the dialog should
    /// allow *editing* the existing label.
    Edit,
}

/// A request to open a label add/edit dialog.
///
/// This is the Rust equivalent of the Java `AddEditDialog` interaction.
/// The provider layer is responsible for actually presenting the dialog.
#[derive(Debug, Clone)]
pub struct LabelEditRequest {
    /// The address at which the label resides.
    pub address: u64,
    /// Whether to add a new label or edit an existing one.
    pub kind: LabelEditKind,
    /// The current name of the label (for editing).
    pub current_name: Option<String>,
}

impl LabelEditRequest {
    /// Create an "add label" request at the given address.
    pub fn add(address: u64) -> Self {
        Self {
            address,
            kind: LabelEditKind::Add,
            current_name: None,
        }
    }

    /// Create an "edit label" request at the given address.
    pub fn edit(address: u64, current_name: String) -> Self {
        Self {
            address,
            kind: LabelEditKind::Edit,
            current_name: Some(current_name),
        }
    }
}

// ---------------------------------------------------------------------------
// LabelSource -- mirrors Java's SourceType for symbols
// ---------------------------------------------------------------------------

/// The source of a label symbol.
///
/// Mirrors `SourceType` from the Java `ghidra.program.model.symbol` package.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LabelSource {
    /// The label was automatically generated (e.g., by analysis).
    Default,
    /// The label was created or modified by the user.
    UserDefined,
    /// The label was imported from an external source (e.g., debug info).
    Imported,
    /// The label comes from library analysis.
    Library,
    /// The label was provided by an analysis extension.
    Analysis,
}

impl LabelSource {
    /// Whether this label can be edited (all non-default sources).
    pub fn is_editable(&self) -> bool {
        *self != LabelSource::Default
    }
}

// ---------------------------------------------------------------------------
// LabelInfo -- a snapshot of a label symbol at an address
// ---------------------------------------------------------------------------

/// Information about a label symbol at an address.
#[derive(Debug, Clone)]
pub struct LabelInfo {
    /// The address of the label.
    pub address: u64,
    /// The name of the label.
    pub name: String,
    /// The source of the label.
    pub source: LabelSource,
    /// Whether this is the only symbol at the address.
    pub is_primary: bool,
}

impl LabelInfo {
    /// Determine the edit kind for this label.
    ///
    /// Default-source labels get `Add`; all others get `Edit`.
    pub fn edit_kind(&self) -> LabelEditKind {
        if self.source == LabelSource::Default {
            LabelEditKind::Add
        } else {
            LabelEditKind::Edit
        }
    }

    /// Build a `LabelEditRequest` from this label info.
    pub fn to_edit_request(&self) -> LabelEditRequest {
        match self.edit_kind() {
            LabelEditKind::Add => LabelEditRequest::add(self.address),
            LabelEditKind::Edit => {
                LabelEditRequest::edit(self.address, self.name.clone())
            }
        }
    }
}

// ---------------------------------------------------------------------------
// RenameLabelAction
// ---------------------------------------------------------------------------

/// Action to rename a label (symbol) at the cursor position in the
/// decompiler panel.
///
/// Only enabled when the cursor is on a `ClangLabelToken`.  The action
/// looks up the symbol at the label's address and opens an add/edit
/// dialog.
///
/// Key binding: `L` (no modifier).
///
/// Corresponds to Java's `RenameLabelAction`.
#[derive(Debug, Clone, Default)]
pub struct RenameLabelAction;

impl RenameLabelAction {
    pub const NAME: &'static str = "Rename Label";
    pub const MENU_PATH: &[&str] = &["Rename Label"];
    pub const KEY_BINDING: &str = "L";

    pub fn new() -> Self {
        Self
    }
}

impl DecompilerAction for RenameLabelAction {
    fn name(&self) -> &str {
        Self::NAME
    }

    fn description(&self) -> &str {
        "Rename the label at the current cursor position"
    }

    fn is_enabled(&self, context: &DecompilerActionContext) -> bool {
        // The action is enabled only when the cursor is on a label token.
        context.is_label_token_at_cursor()
    }

    fn perform(&self, context: &mut DecompilerActionContext) -> bool {
        // Look up the label info for the token at the cursor.
        let label_info = match context.label_info_at_cursor() {
            Some(info) => info,
            None => return false,
        };

        let request = label_info.to_edit_request();
        context.request_label_edit(request);
        true
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn label_source_editable() {
        assert!(!LabelSource::Default.is_editable());
        assert!(LabelSource::UserDefined.is_editable());
        assert!(LabelSource::Imported.is_editable());
        assert!(LabelSource::Library.is_editable());
        assert!(LabelSource::Analysis.is_editable());
    }

    #[test]
    fn label_info_edit_kind() {
        let default_label = LabelInfo {
            address: 0x1000,
            name: "LAB_001000".to_string(),
            source: LabelSource::Default,
            is_primary: true,
        };
        assert_eq!(default_label.edit_kind(), LabelEditKind::Add);

        let user_label = LabelInfo {
            address: 0x2000,
            name: "main".to_string(),
            source: LabelSource::UserDefined,
            is_primary: true,
        };
        assert_eq!(user_label.edit_kind(), LabelEditKind::Edit);
    }

    #[test]
    fn label_info_to_edit_request() {
        let default_label = LabelInfo {
            address: 0x1000,
            name: "LAB_001000".to_string(),
            source: LabelSource::Default,
            is_primary: true,
        };
        let req = default_label.to_edit_request();
        assert_eq!(req.address, 0x1000);
        assert_eq!(req.kind, LabelEditKind::Add);
        assert!(req.current_name.is_none());

        let user_label = LabelInfo {
            address: 0x2000,
            name: "main".to_string(),
            source: LabelSource::UserDefined,
            is_primary: true,
        };
        let req = user_label.to_edit_request();
        assert_eq!(req.address, 0x2000);
        assert_eq!(req.kind, LabelEditKind::Edit);
        assert_eq!(req.current_name.as_deref(), Some("main"));
    }

    #[test]
    fn label_edit_request_constructors() {
        let add_req = LabelEditRequest::add(0x4000);
        assert_eq!(add_req.address, 0x4000);
        assert_eq!(add_req.kind, LabelEditKind::Add);
        assert!(add_req.current_name.is_none());

        let edit_req = LabelEditRequest::edit(0x5000, "entry".to_string());
        assert_eq!(edit_req.address, 0x5000);
        assert_eq!(edit_req.kind, LabelEditKind::Edit);
        assert_eq!(edit_req.current_name.as_deref(), Some("entry"));
    }
}
