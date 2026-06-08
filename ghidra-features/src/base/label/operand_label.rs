//! Set-operand-label action and symbol chooser model.
//!
//! Ported from Ghidra's `SetOperandLabelAction` and `SymbolChooserDialog`.
//!
//! Provides:
//! - [`SetOperandLabelAction`] -- logic for setting a label on an operand
//!   reference target
//! - [`SymbolChooserModel`] -- model for the symbol chooser dialog that
//!   lets users pick from existing symbols at a target address
//! - [`OperandLabelContext`] -- context for the set-operand-label action

use ghidra_core::addr::Address;
use ghidra_core::symbol::{SourceType, SymbolType};

use super::actions::LabelActionContext;

// ---------------------------------------------------------------------------
// OperandLabelContext
// ---------------------------------------------------------------------------

/// Context for the set-operand-label action.
///
/// In Ghidra, `SetOperandLabelAction.isEnabledForContext()` checks that
/// the cursor is on an operand field and that the reference target does
/// not already have a user label.
#[derive(Debug, Clone)]
pub struct OperandLabelContext {
    /// The address of the code unit.
    pub address: Address,
    /// The operand index.
    pub operand_index: i32,
    /// The reference target address.
    pub target_address: Address,
    /// Whether the target already has a label.
    pub target_has_label: bool,
    /// The existing symbol name at the target (if any).
    pub existing_label: Option<String>,
    /// Whether the cursor is on an operand field.
    pub on_operand_field: bool,
    /// Whether this is an external reference.
    pub is_external: bool,
}

impl OperandLabelContext {
    /// Creates a new operand label context.
    pub fn new(address: Address, operand_index: i32, target_address: Address) -> Self {
        Self {
            address,
            operand_index,
            target_address,
            target_has_label: false,
            existing_label: None,
            on_operand_field: true,
            is_external: false,
        }
    }

    /// Returns true if the set-operand-label action should be enabled.
    ///
    /// Mirrors `SetOperandLabelAction.isEnabledForContext()`:
    /// - Must be on an operand field
    /// - Must have a target address
    /// - Target must not already have a non-dynamic label
    pub fn is_enabled(&self) -> bool {
        self.on_operand_field && !self.target_address.is_null() && !self.target_has_label
    }
}

/// Checks whether the set-operand-label action should be enabled
/// for the given label action context.
///
/// This is a simplified version that checks the context fields directly.
pub fn is_set_operand_label_enabled(ctx: &LabelActionContext) -> bool {
    ctx.on_operand_field
        && ctx.operand_index.is_some()
        && ctx.ref_address.is_some()
        && !ctx.ref_address.unwrap().is_null()
        && !ctx.has_symbol()
}

// ---------------------------------------------------------------------------
// SymbolChooserModel -- model for the symbol chooser dialog
// ---------------------------------------------------------------------------

/// A symbol entry for the symbol chooser.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymbolChooserEntry {
    /// The symbol ID.
    pub id: u64,
    /// The symbol name.
    pub name: String,
    /// The symbol type.
    pub symbol_type: SymbolType,
    /// The address of the symbol.
    pub address: Address,
    /// The source of the symbol.
    pub source: SourceType,
    /// Whether the symbol is dynamic.
    pub is_dynamic: bool,
    /// The namespace path (if any).
    pub namespace: Option<String>,
}

impl SymbolChooserEntry {
    /// Returns the fully qualified name (namespace::name).
    pub fn qualified_name(&self) -> String {
        match &self.namespace {
            Some(ns) => format!("{}::{}", ns, self.name),
            None => self.name.clone(),
        }
    }
}

/// Data model for the symbol chooser dialog.
///
/// This is the Rust equivalent of `SymbolChooserDialog`, which presents
/// a list of symbols at a target address for the user to select from.
/// When multiple symbols exist at the same address, the user can choose
/// which one to use as the operand label.
#[derive(Debug)]
pub struct SymbolChooserModel {
    /// The address being examined.
    address: Address,
    /// The available symbols at this address.
    entries: Vec<SymbolChooserEntry>,
    /// The currently selected index.
    selected_index: Option<usize>,
    /// The filter text (for narrowing the list).
    filter_text: String,
    /// Cached filtered indices.
    filtered_indices: Vec<usize>,
}

impl SymbolChooserModel {
    /// Creates a new empty model for the given address.
    pub fn new(address: Address) -> Self {
        Self {
            address,
            entries: Vec::new(),
            selected_index: None,
            filter_text: String::new(),
            filtered_indices: Vec::new(),
        }
    }

    /// Returns the address being examined.
    pub fn address(&self) -> &Address {
        &self.address
    }

    /// Adds a symbol entry to the model.
    pub fn add_entry(&mut self, entry: SymbolChooserEntry) {
        self.entries.push(entry);
        self.rebuild_filter();
    }

    /// Sets the available entries.
    pub fn set_entries(&mut self, entries: Vec<SymbolChooserEntry>) {
        self.entries = entries;
        self.selected_index = None;
        self.rebuild_filter();
    }

    /// Returns the total number of entries.
    pub fn total_count(&self) -> usize {
        self.entries.len()
    }

    /// Returns the number of filtered (visible) entries.
    pub fn filtered_count(&self) -> usize {
        self.filtered_indices.len()
    }

    /// Returns the filtered entry at the given visible index.
    pub fn get_filtered_entry(&self, index: usize) -> Option<&SymbolChooserEntry> {
        let idx = *self.filtered_indices.get(index)?;
        self.entries.get(idx)
    }

    /// Returns all entries.
    pub fn entries(&self) -> &[SymbolChooserEntry] {
        &self.entries
    }

    /// Sets the filter text and rebuilds the filter.
    pub fn set_filter_text(&mut self, text: impl Into<String>) {
        self.filter_text = text.into();
        self.rebuild_filter();
    }

    /// Returns the current filter text.
    pub fn filter_text(&self) -> &str {
        &self.filter_text
    }

    /// Selects an entry by visible index.
    pub fn select(&mut self, visible_index: usize) {
        if visible_index < self.filtered_indices.len() {
            self.selected_index = Some(self.filtered_indices[visible_index]);
        }
    }

    /// Returns the currently selected entry, if any.
    pub fn selected_entry(&self) -> Option<&SymbolChooserEntry> {
        let idx = self.selected_index?;
        self.entries.get(idx)
    }

    /// Clears the selection.
    pub fn clear_selection(&mut self) {
        self.selected_index = None;
    }

    /// Returns true if exactly one symbol exists (no need for chooser).
    pub fn is_single_choice(&self) -> bool {
        self.entries.len() == 1
    }

    /// Returns the only entry if there is exactly one.
    pub fn single_entry(&self) -> Option<&SymbolChooserEntry> {
        if self.entries.len() == 1 {
            self.entries.first()
        } else {
            None
        }
    }

    fn rebuild_filter(&mut self) {
        if self.filter_text.is_empty() {
            self.filtered_indices = (0..self.entries.len()).collect();
        } else {
            let filter_lower = self.filter_text.to_lowercase();
            self.filtered_indices = self
                .entries
                .iter()
                .enumerate()
                .filter(|(_, e)| {
                    e.name.to_lowercase().contains(&filter_lower)
                        || e.qualified_name().to_lowercase().contains(&filter_lower)
                })
                .map(|(i, _)| i)
                .collect();
        }
    }
}

// ---------------------------------------------------------------------------
// SetOperandLabelResult -- result of the set-operand-label operation
// ---------------------------------------------------------------------------

/// Result of attempting to set an operand label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SetOperandLabelResult {
    /// A new label was set at the target address.
    LabelSet(String),
    /// An existing label was reused.
    ExistingLabelUsed(String),
    /// The user chose to cancel (e.g., no symbol selected in chooser).
    Cancelled,
    /// The operation failed.
    Error(String),
}

impl SetOperandLabelResult {
    /// Returns true if the operation was successful.
    pub fn is_success(&self) -> bool {
        matches!(
            self,
            SetOperandLabelResult::LabelSet(_) | SetOperandLabelResult::ExistingLabelUsed(_)
        )
    }

    /// Returns the label name, if one was set or used.
    pub fn label_name(&self) -> Option<&str> {
        match self {
            SetOperandLabelResult::LabelSet(name) => Some(name),
            SetOperandLabelResult::ExistingLabelUsed(name) => Some(name),
            _ => None,
        }
    }
}

/// Generates a default label name for a given address.
///
/// In Ghidra, the default label for address 0x401000 is `LAB_00401000`.
/// For register addresses, it uses `DAT_` prefix.
pub fn generate_default_label(addr: &Address) -> String {
    if addr.is_register_address() {
        format!("DAT_{:08X}", addr.offset)
    } else {
        format!("LAB_{:08X}", addr.offset)
    }
}

/// Validates a label name against Ghidra naming rules.
///
/// Returns `Ok(())` if valid, `Err(message)` if invalid.
///
/// Rules:
/// - Must not be empty
/// - Must start with a letter or underscore
/// - Must contain only alphanumeric characters and underscores
/// - Must not be a reserved keyword (like "if", "while", etc.)
pub fn validate_label_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("Label name cannot be empty.".to_string());
    }

    let first = name.chars().next().unwrap();
    if !first.is_ascii_alphabetic() && first != '_' {
        return Err("Label must start with a letter or underscore.".to_string());
    }

    if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err("Label can only contain letters, digits, and underscores.".to_string());
    }

    let reserved = [
        "if", "else", "while", "for", "return", "break", "continue", "switch", "case", "default",
        "do", "goto", "const", "static", "extern", "register", "volatile", "typedef", "struct",
        "union", "enum", "void", "char", "short", "int", "long", "float", "double", "signed",
        "unsigned",
    ];

    if reserved.contains(&name) {
        return Err(format!("'{}' is a reserved keyword.", name));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(offset: u64) -> Address {
        Address::new(offset)
    }

    // ====================================================================
    // OperandLabelContext
    // ====================================================================

    #[test]
    fn test_operand_label_context_enabled() {
        let ctx = OperandLabelContext::new(addr(0x1000), 0, addr(0x2000));
        assert!(ctx.is_enabled());
    }

    #[test]
    fn test_operand_label_context_disabled_has_label() {
        let mut ctx = OperandLabelContext::new(addr(0x1000), 0, addr(0x2000));
        ctx.target_has_label = true;
        assert!(!ctx.is_enabled());
    }

    #[test]
    fn test_operand_label_context_disabled_null_target() {
        let mut ctx = OperandLabelContext::new(addr(0x1000), 0, Address::NULL);
        ctx.target_address = Address::NULL;
        assert!(!ctx.is_enabled());
    }

    #[test]
    fn test_operand_label_context_disabled_not_operand() {
        let mut ctx = OperandLabelContext::new(addr(0x1000), 0, addr(0x2000));
        ctx.on_operand_field = false;
        assert!(!ctx.is_enabled());
    }

    // ====================================================================
    // is_set_operand_label_enabled
    // ====================================================================

    #[test]
    fn test_set_operand_label_enabled() {
        let ctx = LabelActionContext::on_operand(addr(0x1000), Some(addr(0x2000)), 0);
        assert!(is_set_operand_label_enabled(&ctx));
    }

    #[test]
    fn test_set_operand_label_disabled_no_ref() {
        let ctx = LabelActionContext::on_operand(addr(0x1000), None, 0);
        assert!(!is_set_operand_label_enabled(&ctx));
    }

    #[test]
    fn test_set_operand_label_disabled_on_label() {
        let ctx = LabelActionContext::on_symbol(
            addr(0x1000),
            SymbolType::Label,
            SourceType::UserDefined,
            false,
        );
        assert!(!is_set_operand_label_enabled(&ctx));
    }

    // ====================================================================
    // SymbolChooserModel
    // ====================================================================

    fn make_entries() -> Vec<SymbolChooserEntry> {
        vec![
            SymbolChooserEntry {
                id: 1,
                name: "main".to_string(),
                symbol_type: SymbolType::Function,
                address: addr(0x1000),
                source: SourceType::UserDefined,
                is_dynamic: false,
                namespace: None,
            },
            SymbolChooserEntry {
                id: 2,
                name: "entry".to_string(),
                symbol_type: SymbolType::Label,
                address: addr(0x1000),
                source: SourceType::UserDefined,
                is_dynamic: false,
                namespace: None,
            },
            SymbolChooserEntry {
                id: 3,
                name: "helper".to_string(),
                symbol_type: SymbolType::Function,
                address: addr(0x1000),
                source: SourceType::Default,
                is_dynamic: false,
                namespace: Some("sub_1".to_string()),
            },
        ]
    }

    #[test]
    fn test_symbol_chooser_new() {
        let model = SymbolChooserModel::new(addr(0x1000));
        assert_eq!(model.total_count(), 0);
        assert_eq!(model.filtered_count(), 0);
        assert_eq!(*model.address(), addr(0x1000));
    }

    #[test]
    fn test_symbol_chooser_set_entries() {
        let mut model = SymbolChooserModel::new(addr(0x1000));
        model.set_entries(make_entries());
        assert_eq!(model.total_count(), 3);
        assert_eq!(model.filtered_count(), 3);
    }

    #[test]
    fn test_symbol_chooser_filter() {
        let mut model = SymbolChooserModel::new(addr(0x1000));
        model.set_entries(make_entries());
        model.set_filter_text("main");
        assert_eq!(model.filtered_count(), 1);
        assert_eq!(model.get_filtered_entry(0).unwrap().name, "main");
    }

    #[test]
    fn test_symbol_chooser_filter_by_namespace() {
        let mut model = SymbolChooserModel::new(addr(0x1000));
        model.set_entries(make_entries());
        model.set_filter_text("sub_1");
        assert_eq!(model.filtered_count(), 1);
        assert_eq!(model.get_filtered_entry(0).unwrap().name, "helper");
    }

    #[test]
    fn test_symbol_chooser_filter_case_insensitive() {
        let mut model = SymbolChooserModel::new(addr(0x1000));
        model.set_entries(make_entries());
        model.set_filter_text("MAIN");
        assert_eq!(model.filtered_count(), 1);
    }

    #[test]
    fn test_symbol_chooser_select() {
        let mut model = SymbolChooserModel::new(addr(0x1000));
        model.set_entries(make_entries());
        model.select(1);
        let entry = model.selected_entry().unwrap();
        assert_eq!(entry.name, "entry");
    }

    #[test]
    fn test_symbol_chooser_clear_selection() {
        let mut model = SymbolChooserModel::new(addr(0x1000));
        model.set_entries(make_entries());
        model.select(0);
        assert!(model.selected_entry().is_some());
        model.clear_selection();
        assert!(model.selected_entry().is_none());
    }

    #[test]
    fn test_symbol_chooser_single_choice() {
        let mut model = SymbolChooserModel::new(addr(0x1000));
        let entries = vec![make_entries().into_iter().next().unwrap()];
        model.set_entries(entries);
        assert!(model.is_single_choice());
        assert_eq!(model.single_entry().unwrap().name, "main");
    }

    #[test]
    fn test_symbol_chooser_not_single_choice() {
        let mut model = SymbolChooserModel::new(addr(0x1000));
        model.set_entries(make_entries());
        assert!(!model.is_single_choice());
        assert!(model.single_entry().is_none());
    }

    // ====================================================================
    // SymbolChooserEntry
    // ====================================================================

    #[test]
    fn test_entry_qualified_name() {
        let entry = SymbolChooserEntry {
            id: 1,
            name: "func".to_string(),
            symbol_type: SymbolType::Function,
            address: addr(0x1000),
            source: SourceType::UserDefined,
            is_dynamic: false,
            namespace: Some("ns".to_string()),
        };
        assert_eq!(entry.qualified_name(), "ns::func");
    }

    #[test]
    fn test_entry_qualified_name_no_namespace() {
        let entry = SymbolChooserEntry {
            id: 1,
            name: "func".to_string(),
            symbol_type: SymbolType::Function,
            address: addr(0x1000),
            source: SourceType::UserDefined,
            is_dynamic: false,
            namespace: None,
        };
        assert_eq!(entry.qualified_name(), "func");
    }

    // ====================================================================
    // SetOperandLabelResult
    // ====================================================================

    #[test]
    fn test_result_label_set() {
        let r = SetOperandLabelResult::LabelSet("myLabel".to_string());
        assert!(r.is_success());
        assert_eq!(r.label_name(), Some("myLabel"));
    }

    #[test]
    fn test_result_existing() {
        let r = SetOperandLabelResult::ExistingLabelUsed("existing".to_string());
        assert!(r.is_success());
        assert_eq!(r.label_name(), Some("existing"));
    }

    #[test]
    fn test_result_cancelled() {
        let r = SetOperandLabelResult::Cancelled;
        assert!(!r.is_success());
        assert!(r.label_name().is_none());
    }

    #[test]
    fn test_result_error() {
        let r = SetOperandLabelResult::Error("fail".to_string());
        assert!(!r.is_success());
        assert!(r.label_name().is_none());
    }

    // ====================================================================
    // generate_default_label
    // ====================================================================

    #[test]
    fn test_generate_default_label() {
        let label = generate_default_label(&addr(0x401000));
        assert_eq!(label, "LAB_00401000");
    }

    #[test]
    fn test_generate_default_label_small_addr() {
        let label = generate_default_label(&addr(0x100));
        assert_eq!(label, "LAB_00000100");
    }

    // ====================================================================
    // validate_label_name
    // ====================================================================

    #[test]
    fn test_validate_valid_names() {
        assert!(validate_label_name("main").is_ok());
        assert!(validate_label_name("_start").is_ok());
        assert!(validate_label_name("func_123").is_ok());
        assert!(validate_label_name("A").is_ok());
    }

    #[test]
    fn test_validate_empty() {
        assert!(validate_label_name("").is_err());
    }

    #[test]
    fn test_validate_starts_with_digit() {
        assert!(validate_label_name("123abc").is_err());
    }

    #[test]
    fn test_validate_special_chars() {
        assert!(validate_label_name("my-label").is_err());
        assert!(validate_label_name("my label").is_err());
        assert!(validate_label_name("my.label").is_err());
    }

    #[test]
    fn test_validate_reserved_keywords() {
        assert!(validate_label_name("if").is_err());
        assert!(validate_label_name("while").is_err());
        assert!(validate_label_name("return").is_err());
        assert!(validate_label_name("int").is_err());
        assert!(validate_label_name("void").is_err());
    }
}
