//! Processor plugins -- instruction info and language management.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.processors` Java package.
//!
//! Provides:
//!
//! - [`InstructionInfo`] -- detailed operand and encoding information for the
//!   instruction at the current listing location.
//! - [`InstructionInfoProvider`] -- component provider that renders instruction
//!   details (encoding, operands, masks) in a split-pane view.
//! - [`ShowInstructionInfoPlugin`] -- plugin that tracks the current listing
//!   location and updates the info display.
//! - [`LanguageProviderPlugin`] -- application-level plugin that adds the
//!   "Set Language" action to the front-end tool.
//! - [`SetLanguageDialog`] -- dialog for changing a program's language and
//!   compiler specification.
//! - [`ProcessorManual`] -- descriptor for a processor manual PDF.

use ghidra_core::Address;
use std::collections::BTreeMap;
use std::fmt;

// ===========================================================================
// InstructionInfo -- per-instruction details
// ===========================================================================

/// Operand type bit-flags mirroring Ghidra's `OperandType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct OperandType(pub u32);

impl OperandType {
    /// No special type.
    pub const NONE: OperandType = OperandType(0);
    /// Register reference.
    pub const REGISTER: OperandType = OperandType(1);
    /// Scalar / immediate value.
    pub const SCALAR: OperandType = OperandType(2);
    /// Address reference.
    pub const ADDRESS: OperandType = OperandType(4);
    /// Relative branch.
    pub const RELATIVE: OperandType = OperandType(8);
    /// Indirect reference.
    pub const INDIRECT: OperandType = OperandType(16);

    /// Returns true if this operand is a register.
    pub fn is_register(&self) -> bool {
        self.0 & Self::REGISTER.0 != 0
    }

    /// Returns true if this operand is a scalar/immediate.
    pub fn is_scalar(&self) -> bool {
        self.0 & Self::SCALAR.0 != 0
    }

    /// Returns true if this operand is an address.
    pub fn is_address(&self) -> bool {
        self.0 & Self::ADDRESS.0 != 0
    }

    /// Returns true if this operand is a relative branch.
    pub fn is_relative(&self) -> bool {
        self.0 & Self::RELATIVE.0 != 0
    }

    /// Returns true if this operand is indirect.
    pub fn is_indirect(&self) -> bool {
        self.0 & Self::INDIRECT.0 != 0
    }

    /// Get a human-readable description of the operand type.
    pub fn to_description(&self) -> String {
        let mut parts = Vec::new();
        if self.0 == 0 {
            return "NONE".into();
        }
        if self.is_register() {
            parts.push("Register");
        }
        if self.is_scalar() {
            parts.push("Scalar");
        }
        if self.is_address() {
            parts.push("Address");
        }
        if self.is_relative() {
            parts.push("Relative");
        }
        if self.is_indirect() {
            parts.push("Indirect");
        }
        parts.join("|")
    }
}

impl fmt::Display for OperandType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_description())
    }
}

/// Information about a single operand of an instruction.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct OperandInfo {
    /// The operand index.
    pub index: usize,
    /// Default text representation.
    pub representation: String,
    /// Labeled representation list (strings).
    pub labeled_repr: Vec<String>,
    /// Operand type flags.
    pub op_type: OperandType,
    /// Scalar value, if this is a scalar operand.
    pub scalar: Option<i64>,
    /// Address value, if this is an address operand.
    pub address: Option<Address>,
    /// Register name, if this is a register operand.
    pub register: Option<String>,
    /// Formatted operand object strings.
    pub op_objects: Vec<String>,
    /// Debug mask string (from Sleigh debug output).
    pub mask: Option<String>,
    /// Debug masked-value string (from Sleigh debug output).
    pub masked_value: Option<String>,
}

impl OperandInfo {
    /// Create a new operand info with defaults.
    pub fn new(index: usize) -> Self {
        Self {
            index,
            representation: String::new(),
            labeled_repr: Vec::new(),
            op_type: OperandType::NONE,
            scalar: None,
            address: None,
            register: None,
            op_objects: Vec::new(),
            mask: None,
            masked_value: None,
        }
    }
}

/// Detailed information about the instruction at a listing location.
///
/// Corresponds to the data displayed by Ghidra's `InstructionInfoProvider`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct InstructionInfo {
    /// Address of the instruction.
    pub address: Address,
    /// Formatted instruction text (mnemonic + operands).
    pub formatted_text: String,
    /// Instruction length in bytes.
    pub length: usize,
    /// Raw bytes of the instruction encoding.
    pub bytes: Vec<u8>,
    /// Per-operand details.
    pub operands: Vec<OperandInfo>,
    /// Number of operands.
    pub num_operands: usize,
    /// Whether this is a Sleigh-decoded instruction with debug info.
    pub has_sleigh_debug: bool,
}

impl InstructionInfo {
    /// Create new instruction info at the given address.
    pub fn new(address: Address) -> Self {
        Self {
            address,
            formatted_text: String::new(),
            length: 0,
            bytes: Vec::new(),
            operands: Vec::new(),
            num_operands: 0,
            has_sleigh_debug: false,
        }
    }

    /// Whether there is a valid instruction at this address.
    pub fn is_valid(&self) -> bool {
        self.length > 0
    }

    /// Get the operand info for the given index.
    pub fn get_operand(&self, index: usize) -> Option<&OperandInfo> {
        self.operands.get(index)
    }

    /// Get the default representation of an operand.
    pub fn get_operand_representation(&self, index: usize) -> Option<&str> {
        self.operands.get(index).map(|o| o.representation.as_str())
    }

    /// Get the labeled representation list for an operand.
    pub fn get_labeled_representation(&self, index: usize) -> Option<&[String]> {
        self.operands.get(index).map(|o| o.labeled_repr.as_slice())
    }

    /// Get the operand type for the given index.
    pub fn get_operand_type(&self, index: usize) -> Option<OperandType> {
        self.operands.get(index).map(|o| o.op_type)
    }

    /// Get the scalar value for the given operand, if any.
    pub fn get_scalar(&self, index: usize) -> Option<i64> {
        self.operands.get(index).and_then(|o| o.scalar)
    }

    /// Get the address for the given operand, if any.
    pub fn get_address(&self, index: usize) -> Option<Address> {
        self.operands.get(index).and_then(|o| o.address)
    }

    /// Get the register name for the given operand, if any.
    pub fn get_register(&self, index: usize) -> Option<&str> {
        self.operands
            .get(index)
            .and_then(|o| o.register.as_deref())
    }

    /// Get the formatted operand objects for the given operand.
    pub fn get_operand_objects(&self, index: usize) -> Option<&[String]> {
        self.operands.get(index).map(|o| o.op_objects.as_slice())
    }

    /// Get the Sleigh debug mask for the given operand.
    pub fn get_mask(&self, index: usize) -> Option<&str> {
        self.operands.get(index).and_then(|o| o.mask.as_deref())
    }

    /// Get the Sleigh debug masked value for the given operand.
    pub fn get_masked_value(&self, index: usize) -> Option<&str> {
        self.operands
            .get(index)
            .and_then(|o| o.masked_value.as_deref())
    }
}

// ===========================================================================
// InstructionInfoProvider -- component provider
// ===========================================================================

/// Display mode for the instruction info provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InfoDisplayMode {
    /// Static mode: show info for the instruction at the context menu.
    Static,
    /// Dynamic mode: update as the cursor moves.
    Dynamic,
}

/// Component provider that shows instruction detail information.
///
/// Corresponds to Ghidra's `InstructionInfoProvider`.
#[derive(Debug)]
pub struct InstructionInfoProvider {
    /// Provider title.
    pub title: String,
    /// Whether the provider is visible.
    pub visible: bool,
    /// Display mode.
    pub mode: InfoDisplayMode,
    /// Current instruction info.
    pub current_info: Option<InstructionInfo>,
    /// Current address being displayed.
    pub current_address: Option<Address>,
    /// Instruction text (the formatted details pane content).
    pub instruction_text: String,
    /// Operand table rows (row_label -> column_values).
    pub operand_table: Vec<Vec<String>>,
}

impl InstructionInfoProvider {
    /// Create a new instruction info provider.
    pub fn new(title: impl Into<String>, mode: InfoDisplayMode) -> Self {
        Self {
            title: title.into(),
            visible: false,
            mode,
            current_info: None,
            current_address: None,
            instruction_text: String::new(),
            operand_table: Vec::new(),
        }
    }

    /// Set the current program context.
    pub fn set_program(&mut self, _program_name: Option<&str>) {
        // In a full implementation this would bind to the program for
        // instruction decoding.
    }

    /// Set the current address and update the display.
    pub fn set_address(&mut self, address: Option<Address>) {
        self.current_address = address;
    }

    /// Update the display with new instruction info.
    pub fn set_instruction(&mut self, info: Option<InstructionInfo>) {
        self.instruction_text.clear();
        self.operand_table.clear();

        if let Some(ref info) = info {
            self.instruction_text = info.formatted_text.clone();
            self.build_operand_table(info);
        } else {
            self.instruction_text = "-- No Instruction --".into();
        }

        self.current_info = info;
    }

    /// Build the operand table from instruction info.
    fn build_operand_table(&mut self, info: &InstructionInfo) {
        let row_labels = [
            "Operand",
            "Labeled",
            "Type",
            "Scalar",
            "Address",
            "Register",
            "Op-Objects",
            "Operand Mask",
            "Masked Value",
        ];

        for (row_idx, label) in row_labels.iter().enumerate() {
            let mut row = vec![label.to_string()];
            for op_idx in 0..info.num_operands {
                let cell = self.get_operand_cell(info, row_idx, op_idx);
                row.push(cell);
            }
            self.operand_table.push(row);
        }
    }

    /// Get the cell value for a given row and operand.
    fn get_operand_cell(&self, info: &InstructionInfo, row: usize, op_idx: usize) -> String {
        let op = match info.get_operand(op_idx) {
            Some(o) => o,
            None => return String::new(),
        };
        match row {
            0 => op.representation.clone(),
            1 => op
                .labeled_repr
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(", "),
            2 => op.op_type.to_description(),
            3 => op
                .scalar
                .map(|v| format!("0x{:x}", v))
                .unwrap_or_default(),
            4 => op
                .address
                .map(|a| format!("0x{:x}", a.offset))
                .unwrap_or_default(),
            5 => op.register.clone().unwrap_or_default(),
            6 => op
                .op_objects
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(", "),
            7 => op.mask.clone().unwrap_or_else(|| "-none-".into()),
            8 => op
                .masked_value
                .clone()
                .unwrap_or_else(|| "-none-".into()),
            _ => String::new(),
        }
    }

    /// Toggle between static and dynamic modes.
    pub fn toggle_dynamic(&mut self) {
        self.mode = match self.mode {
            InfoDisplayMode::Static => InfoDisplayMode::Dynamic,
            InfoDisplayMode::Dynamic => InfoDisplayMode::Static,
        };
    }

    /// Show the provider.
    pub fn show(&mut self) {
        self.visible = true;
    }

    /// Hide the provider.
    pub fn hide(&mut self) {
        self.visible = false;
    }

    /// Dispose the provider.
    pub fn dispose(&mut self) {
        self.visible = false;
        self.current_info = None;
        self.current_address = None;
        self.instruction_text.clear();
        self.operand_table.clear();
    }
}

// ===========================================================================
// ShowInstructionInfoPlugin -- program plugin
// ===========================================================================

/// Status bar field types for the instruction info plugin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusField {
    /// Current instruction or datatype.
    CodeUnit,
    /// Current function name.
    Function,
    /// Current address.
    Address,
}

/// Plugin that shows raw instruction information at the current listing location.
///
/// Corresponds to Ghidra's `ShowInstructionInfoPlugin extends ProgramPlugin`.
#[derive(Debug)]
pub struct ShowInstructionInfoPlugin {
    /// Plugin name.
    pub name: String,
    /// Current program name.
    pub current_program: Option<String>,
    /// Current listing location address.
    pub current_address: Option<Address>,
    /// Status text for the code unit field.
    pub code_unit_status: String,
    /// Status text for the function field.
    pub function_status: String,
    /// Status text for the address field.
    pub address_status: String,
    /// Registered instruction info providers.
    pub providers: Vec<InstructionInfoProvider>,
    /// The currently connected (active) provider index.
    pub connected_provider_idx: Option<usize>,
    /// Available processor manual paths.
    pub processor_manuals: Vec<ProcessorManual>,
}

impl ShowInstructionInfoPlugin {
    /// Create a new show-instruction-info plugin.
    pub fn new() -> Self {
        Self {
            name: "ShowInstructionInfo".into(),
            current_program: None,
            current_address: None,
            code_unit_status: String::new(),
            function_status: String::new(),
            address_status: String::new(),
            providers: Vec::new(),
            connected_provider_idx: None,
            processor_manuals: Vec::new(),
        }
    }

    /// Register an instruction info provider.
    pub fn register_provider(&mut self, provider: InstructionInfoProvider) -> usize {
        let idx = self.providers.len();
        self.providers.push(provider);
        if self.connected_provider_idx.is_none() {
            self.connected_provider_idx = Some(idx);
        }
        idx
    }

    /// Unregister a provider by index.
    pub fn unregister_provider(&mut self, idx: usize) {
        if idx < self.providers.len() {
            self.providers.remove(idx);
            // Fix connected index
            self.connected_provider_idx = match self.connected_provider_idx {
                Some(i) if i == idx => None,
                Some(i) if i > idx => Some(i - 1),
                other => other,
            };
        }
    }

    /// Handle a program-activated event.
    pub fn program_activated(&mut self, program_name: impl Into<String>) {
        self.current_program = Some(program_name.into());
    }

    /// Handle a program-deactivated event.
    pub fn program_deactivated(&mut self) {
        self.current_program = None;
        self.current_address = None;
        self.code_unit_status.clear();
        self.function_status.clear();
        self.address_status.clear();
    }

    /// Handle a location-changed event.
    pub fn location_changed(&mut self, address: Option<Address>) {
        self.current_address = address;
        if let Some(addr) = address {
            self.address_status = format!("0x{:x}", addr.offset);
        } else {
            self.address_status.clear();
        }
        if let Some(idx) = self.connected_provider_idx {
            if let Some(provider) = self.providers.get_mut(idx) {
                provider.set_address(address);
            }
        }
    }

    /// Update status text for the code unit field.
    pub fn set_code_unit_status(&mut self, text: impl Into<String>) {
        self.code_unit_status = text.into();
    }

    /// Update status text for the function field.
    pub fn set_function_status(&mut self, text: impl Into<String>) {
        self.function_status = text.into();
    }

    /// Connect a specific provider as the active one.
    pub fn connect_provider(&mut self, idx: usize) {
        if idx < self.providers.len() {
            self.connected_provider_idx = Some(idx);
            if let Some(provider) = self.providers.get_mut(idx) {
                provider.set_program(self.current_program.as_deref());
                provider.set_address(self.current_address);
            }
        }
    }

    /// Register a processor manual.
    pub fn register_processor_manual(&mut self, manual: ProcessorManual) {
        self.processor_manuals.push(manual);
    }

    /// Find a processor manual by language ID.
    pub fn find_manual(&self, language_id: &str) -> Option<&ProcessorManual> {
        self.processor_manuals
            .iter()
            .find(|m| m.language_id == language_id)
    }

    /// Browse (show) instruction info for the current context.
    pub fn browse_instruction(&mut self, info: InstructionInfo) {
        // In the full implementation this opens an info provider.
        for provider in &mut self.providers {
            provider.set_instruction(Some(info.clone()));
            provider.show();
        }
    }
}

impl Default for ShowInstructionInfoPlugin {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// ProcessorManual
// ===========================================================================

/// Describes a processor manual PDF file.
///
/// Used by the "Processor Manual" action to locate and display the manual
/// for the current program's processor.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProcessorManual {
    /// Language / processor ID (e.g., "x86:LE:64:default").
    pub language_id: String,
    /// Display name (e.g., "Intel x86 Manual").
    pub name: String,
    /// File path or URL to the PDF.
    pub path: String,
    /// Page count, if known.
    pub page_count: Option<usize>,
}

impl ProcessorManual {
    /// Create a new processor manual descriptor.
    pub fn new(
        language_id: impl Into<String>,
        name: impl Into<String>,
        path: impl Into<String>,
    ) -> Self {
        Self {
            language_id: language_id.into(),
            name: name.into(),
            path: path.into(),
            page_count: None,
        }
    }

    /// Check if the manual file exists at the given path.
    pub fn exists(&self) -> bool {
        std::path::Path::new(&self.path).exists()
    }
}

// ===========================================================================
// Language IDs and Compiler Spec IDs
// ===========================================================================

/// A language identifier string (e.g., `"x86:LE:64:default"`).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize)]
pub struct LanguageId(pub String);

impl LanguageId {
    /// Create a new language ID.
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Get the processor name from the language ID.
    pub fn processor(&self) -> &str {
        self.0.split(':').next().unwrap_or("")
    }
}

impl fmt::Display for LanguageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A compiler specification identifier string (e.g., `"default"`, `"gcc"`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct CompilerSpecId(pub String);

impl CompilerSpecId {
    /// Create a new compiler spec ID.
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }
}

impl fmt::Display for CompilerSpecId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A language + compiler spec pair, used when setting a program's language.
///
/// Corresponds to Ghidra's `LanguageCompilerSpecPair`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LanguageCompilerSpecPair {
    /// The language ID.
    pub language_id: LanguageId,
    /// The compiler spec ID.
    pub compiler_spec_id: CompilerSpecId,
}

impl LanguageCompilerSpecPair {
    /// Create a new language/compiler-spec pair.
    pub fn new(
        language_id: impl Into<String>,
        compiler_spec_id: impl Into<String>,
    ) -> Self {
        Self {
            language_id: LanguageId::new(language_id),
            compiler_spec_id: CompilerSpecId::new(compiler_spec_id),
        }
    }
}

impl fmt::Display for LanguageCompilerSpecPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} [{}]", self.language_id, self.compiler_spec_id)
    }
}

// ===========================================================================
// LanguageDescription -- minimal language metadata
// ===========================================================================

/// Description of a language / processor architecture.
///
/// Mirrors Ghidra's `LanguageDescription` at the model level.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LanguageDescription {
    /// Language ID.
    pub id: LanguageId,
    /// Processor name (e.g., "x86", "ARM", "MIPS").
    pub processor: String,
    /// Endianness: "little" or "big".
    pub endian: String,
    /// Address size in bits (e.g., 32, 64).
    pub size: usize,
    /// Human-readable description.
    pub description: String,
    /// Available compiler specs for this language.
    pub compiler_specs: Vec<CompilerSpecDescription>,
}

/// Description of a compiler specification.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CompilerSpecDescription {
    /// Compiler spec ID.
    pub id: CompilerSpecId,
    /// Human-readable name.
    pub name: String,
    /// Whether this is the default compiler spec for the language.
    pub is_default: bool,
}

// ===========================================================================
// LanguageService -- language registry
// ===========================================================================

/// In-memory language service that provides language descriptions.
///
/// Corresponds to Ghidra's `DefaultLanguageService` at the model level.
#[derive(Debug, Default)]
pub struct LanguageService {
    /// Registered languages.
    languages: BTreeMap<LanguageId, LanguageDescription>,
}

impl LanguageService {
    /// Create a new empty language service.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a language description.
    pub fn register(&mut self, desc: LanguageDescription) {
        self.languages.insert(desc.id.clone(), desc);
    }

    /// Get a language description by ID.
    pub fn get_language(&self, id: &LanguageId) -> Option<&LanguageDescription> {
        self.languages.get(id)
    }

    /// Get all registered language descriptions.
    pub fn get_language_descriptions(&self) -> Vec<&LanguageDescription> {
        self.languages.values().collect()
    }

    /// Get the language IDs matching a processor name.
    pub fn get_languages_for_processor(&self, processor: &str) -> Vec<&LanguageDescription> {
        self.languages
            .values()
            .filter(|d| d.processor.eq_ignore_ascii_case(processor))
            .collect()
    }

    /// Number of registered languages.
    pub fn language_count(&self) -> usize {
        self.languages.len()
    }
}

// ===========================================================================
// SetLanguageDialog -- language selection dialog model
// ===========================================================================

/// Result of the set-language dialog interaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SetLanguageResult {
    /// User selected a language/compiler-spec pair.
    Selected(LanguageCompilerSpecPair),
    /// User cancelled the dialog.
    Cancelled,
}

/// Model for the "Set Language" dialog.
///
/// Corresponds to Ghidra's `SetLanguageDialog`.
#[derive(Debug)]
pub struct SetLanguageDialog {
    /// Dialog title.
    pub title: String,
    /// Currently selected language/compiler-spec pair.
    pub current_pair: Option<LanguageCompilerSpecPair>,
    /// The selected pair after OK.
    pub result: SetLanguageResult,
    /// Available languages from the service.
    pub available_languages: Vec<LanguageDescription>,
    /// Search / filter text.
    pub filter_text: String,
    /// Whether the dialog is open.
    pub is_open: bool,
}

impl SetLanguageDialog {
    /// Create a new set-language dialog.
    pub fn new(
        title: impl Into<String>,
        current_pair: Option<LanguageCompilerSpecPair>,
    ) -> Self {
        Self {
            title: title.into(),
            current_pair,
            result: SetLanguageResult::Cancelled,
            available_languages: Vec::new(),
            filter_text: String::new(),
            is_open: false,
        }
    }

    /// Open the dialog (simulate `tool.showDialog`).
    pub fn open(&mut self) {
        self.is_open = true;
    }

    /// Close the dialog.
    pub fn close(&mut self) {
        self.is_open = false;
    }

    /// Set the available languages (from the language service).
    pub fn set_languages(&mut self, langs: Vec<LanguageDescription>) {
        self.available_languages = langs;
    }

    /// Select a language/compiler-spec pair and close with OK.
    pub fn ok(&mut self, pair: LanguageCompilerSpecPair) {
        self.result = SetLanguageResult::Selected(pair);
        self.close();
    }

    /// Cancel the dialog.
    pub fn cancel(&mut self) {
        self.result = SetLanguageResult::Cancelled;
        self.close();
    }

    /// Get the selected language ID (after OK).
    pub fn get_language_id(&self) -> Option<&LanguageId> {
        match &self.result {
            SetLanguageResult::Selected(pair) => Some(&pair.language_id),
            _ => None,
        }
    }

    /// Get the selected compiler spec ID (after OK).
    pub fn get_compiler_spec_id(&self) -> Option<&CompilerSpecId> {
        match &self.result {
            SetLanguageResult::Selected(pair) => Some(&pair.compiler_spec_id),
            _ => None,
        }
    }

    /// Filter the available languages by text.
    pub fn set_filter(&mut self, text: impl Into<String>) {
        self.filter_text = text.into();
    }

    /// Get the filtered language list.
    pub fn filtered_languages(&self) -> Vec<&LanguageDescription> {
        if self.filter_text.is_empty() {
            return self.available_languages.iter().collect();
        }
        let lower = self.filter_text.to_lowercase();
        self.available_languages
            .iter()
            .filter(|d| {
                d.id.0.to_lowercase().contains(&lower)
                    || d.processor.to_lowercase().contains(&lower)
                    || d.description.to_lowercase().contains(&lower)
            })
            .collect()
    }
}

// ===========================================================================
// LanguageProviderPlugin -- application-level plugin
// ===========================================================================

/// Application-level plugin that provides the "Set Language" action.
///
/// Corresponds to Ghidra's `LanguageProviderPlugin implements
/// ApplicationLevelPlugin`.
#[derive(Debug)]
pub struct LanguageProviderPlugin {
    /// Plugin name.
    pub name: String,
    /// Whether the plugin is initialized.
    pub initialized: bool,
    /// The language service.
    pub language_service: LanguageService,
    /// Whether the set-language action is enabled.
    pub action_enabled: bool,
}

impl LanguageProviderPlugin {
    /// Create a new language provider plugin.
    pub fn new() -> Self {
        Self {
            name: "LanguageProvider".into(),
            initialized: false,
            language_service: LanguageService::new(),
            action_enabled: false,
        }
    }

    /// Initialize the plugin.
    ///
    /// In Ghidra this only runs when the tool is a `FrontEndTool`.
    pub fn init(&mut self, is_front_end: bool) {
        if !is_front_end {
            return;
        }
        self.initialized = true;
        self.action_enabled = true;
    }

    /// Execute the "Set Language" action.
    ///
    /// Returns the new language/compiler-spec pair if the user confirmed, or
    /// `None` if cancelled.
    pub fn execute_set_language(
        &self,
        dialog: &mut SetLanguageDialog,
        pair: Option<LanguageCompilerSpecPair>,
    ) -> Option<LanguageCompilerSpecPair> {
        dialog.current_pair = pair;
        dialog.set_languages(self.language_service.get_language_descriptions().into_iter().cloned().collect());
        dialog.open();

        // In the real app, the dialog blocks until the user picks or cancels.
        // Here, caller must call dialog.ok() or dialog.cancel().
        match &dialog.result {
            SetLanguageResult::Selected(p) => Some(p.clone()),
            _ => None,
        }
    }

    /// Dispose the plugin.
    pub fn dispose(&mut self) {
        self.initialized = false;
        self.action_enabled = false;
    }
}

impl Default for LanguageProviderPlugin {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ----- OperandType tests -----

    #[test]
    fn test_operand_type_flags() {
        let ty = OperandType(OperandType::REGISTER.0 | OperandType::SCALAR.0);
        assert!(ty.is_register());
        assert!(ty.is_scalar());
        assert!(!ty.is_address());
    }

    #[test]
    fn test_operand_type_display() {
        assert_eq!(OperandType::NONE.to_string(), "NONE");
        let ty = OperandType(OperandType::ADDRESS.0 | OperandType::RELATIVE.0);
        assert!(ty.to_string().contains("Address"));
        assert!(ty.to_string().contains("Relative"));
    }

    // ----- InstructionInfo tests -----

    #[test]
    fn test_instruction_info_empty() {
        let info = InstructionInfo::new(Address::new(0x1000));
        assert!(!info.is_valid());
        assert_eq!(info.num_operands, 0);
    }

    #[test]
    fn test_instruction_info_with_operands() {
        let mut info = InstructionInfo::new(Address::new(0x1000));
        info.formatted_text = "MOV EAX, EBX".into();
        info.length = 2;
        info.num_operands = 2;

        let mut op0 = OperandInfo::new(0);
        op0.representation = "EAX".into();
        op0.register = Some("EAX".into());
        op0.op_type = OperandType::REGISTER;

        let mut op1 = OperandInfo::new(1);
        op1.representation = "EBX".into();
        op1.register = Some("EBX".into());
        op1.op_type = OperandType::REGISTER;

        info.operands = vec![op0, op1];

        assert!(info.is_valid());
        assert_eq!(info.get_operand_representation(0), Some("EAX"));
        assert_eq!(info.get_register(1), Some("EBX"));
        assert!(info.get_operand_type(0).unwrap().is_register());
    }

    #[test]
    fn test_instruction_info_scalar_operand() {
        let mut info = InstructionInfo::new(Address::new(0x2000));
        info.length = 5;
        info.num_operands = 1;

        let mut op = OperandInfo::new(0);
        op.representation = "0x42".into();
        op.scalar = Some(0x42);
        op.op_type = OperandType::SCALAR;
        info.operands = vec![op];

        assert_eq!(info.get_scalar(0), Some(0x42));
    }

    #[test]
    fn test_instruction_info_address_operand() {
        let mut info = InstructionInfo::new(Address::new(0x2000));
        info.length = 5;
        info.num_operands = 1;

        let mut op = OperandInfo::new(0);
        op.address = Some(Address::new(0x401000));
        op.op_type = OperandType::ADDRESS;
        info.operands = vec![op];

        assert_eq!(info.get_address(0).unwrap().offset, 0x401000);
    }

    // ----- InstructionInfoProvider tests -----

    #[test]
    fn test_provider_new() {
        let p = InstructionInfoProvider::new("Instruction Info", InfoDisplayMode::Dynamic);
        assert_eq!(p.title, "Instruction Info");
        assert_eq!(p.mode, InfoDisplayMode::Dynamic);
        assert!(!p.visible);
        assert!(p.current_info.is_none());
    }

    #[test]
    fn test_provider_set_instruction() {
        let mut p = InstructionInfoProvider::new("Info", InfoDisplayMode::Static);
        let mut info = InstructionInfo::new(Address::new(0x1000));
        info.formatted_text = "NOP".into();
        info.length = 1;
        p.set_instruction(Some(info));
        assert_eq!(p.instruction_text, "NOP");
    }

    #[test]
    fn test_provider_no_instruction() {
        let mut p = InstructionInfoProvider::new("Info", InfoDisplayMode::Static);
        p.set_instruction(None);
        assert_eq!(p.instruction_text, "-- No Instruction --");
    }

    #[test]
    fn test_provider_operand_table() {
        let mut p = InstructionInfoProvider::new("Info", InfoDisplayMode::Static);
        let mut info = InstructionInfo::new(Address::new(0x1000));
        info.formatted_text = "ADD EAX, 0x10".into();
        info.length = 3;
        info.num_operands = 2;

        let mut op0 = OperandInfo::new(0);
        op0.representation = "EAX".into();
        op0.register = Some("EAX".into());
        op0.op_type = OperandType::REGISTER;

        let mut op1 = OperandInfo::new(1);
        op1.representation = "0x10".into();
        op1.scalar = Some(0x10);
        op1.op_type = OperandType::SCALAR;

        info.operands = vec![op0, op1];
        p.set_instruction(Some(info));

        // 9 rows: Operand, Labeled, Type, Scalar, Address, Register, Op-Objects, Mask, Masked Value
        assert_eq!(p.operand_table.len(), 9);
        // First column is the row label
        assert_eq!(p.operand_table[0][0], "Operand");
        // Second column is operand 0 value
        assert_eq!(p.operand_table[0][1], "EAX");
        // Scalar row for operand 1
        assert_eq!(p.operand_table[3][2], "0x10");
    }

    #[test]
    fn test_provider_toggle_dynamic() {
        let mut p = InstructionInfoProvider::new("Info", InfoDisplayMode::Static);
        p.toggle_dynamic();
        assert_eq!(p.mode, InfoDisplayMode::Dynamic);
        p.toggle_dynamic();
        assert_eq!(p.mode, InfoDisplayMode::Static);
    }

    #[test]
    fn test_provider_visibility() {
        let mut p = InstructionInfoProvider::new("Info", InfoDisplayMode::Dynamic);
        p.show();
        assert!(p.visible);
        p.hide();
        assert!(!p.visible);
    }

    #[test]
    fn test_provider_dispose() {
        let mut p = InstructionInfoProvider::new("Info", InfoDisplayMode::Dynamic);
        let mut info = InstructionInfo::new(Address::new(0x1000));
        info.length = 1;
        p.set_instruction(Some(info));
        p.show();
        p.dispose();
        assert!(!p.visible);
        assert!(p.current_info.is_none());
        assert!(p.instruction_text.is_empty());
    }

    // ----- ShowInstructionInfoPlugin tests -----

    #[test]
    fn test_plugin_new() {
        let p = ShowInstructionInfoPlugin::new();
        assert_eq!(p.name, "ShowInstructionInfo");
        assert!(p.current_program.is_none());
        assert!(p.providers.is_empty());
    }

    #[test]
    fn test_plugin_program_lifecycle() {
        let mut p = ShowInstructionInfoPlugin::new();
        p.program_activated("test.exe");
        assert_eq!(p.current_program.as_deref(), Some("test.exe"));
        p.program_deactivated();
        assert!(p.current_program.is_none());
    }

    #[test]
    fn test_plugin_location_changed() {
        let mut p = ShowInstructionInfoPlugin::new();
        p.location_changed(Some(Address::new(0x401000)));
        assert_eq!(p.current_address.unwrap().offset, 0x401000);
        assert_eq!(p.address_status, "0x401000");
        p.location_changed(None);
        assert!(p.current_address.is_none());
        assert!(p.address_status.is_empty());
    }

    #[test]
    fn test_plugin_register_provider() {
        let mut p = ShowInstructionInfoPlugin::new();
        let provider = InstructionInfoProvider::new("Info", InfoDisplayMode::Dynamic);
        let idx = p.register_provider(provider);
        assert_eq!(idx, 0);
        assert_eq!(p.providers.len(), 1);
        assert_eq!(p.connected_provider_idx, Some(0));
    }

    #[test]
    fn test_plugin_unregister_provider() {
        let mut p = ShowInstructionInfoPlugin::new();
        p.register_provider(InstructionInfoProvider::new("A", InfoDisplayMode::Static));
        p.register_provider(InstructionInfoProvider::new("B", InfoDisplayMode::Dynamic));
        assert_eq!(p.providers.len(), 2);
        // connected_provider_idx is 0 (first registered).
        // Unregistering index 0 (the connected one) sets it to None.
        p.unregister_provider(0);
        assert_eq!(p.providers.len(), 1);
        assert_eq!(p.connected_provider_idx, None);
    }

    #[test]
    fn test_plugin_status_fields() {
        let mut p = ShowInstructionInfoPlugin::new();
        p.set_code_unit_status("Current Instruction: NOP");
        p.set_function_status("main");
        assert_eq!(p.code_unit_status, "Current Instruction: NOP");
        assert_eq!(p.function_status, "main");
    }

    #[test]
    fn test_plugin_processor_manuals() {
        let mut p = ShowInstructionInfoPlugin::new();
        p.register_processor_manual(ProcessorManual::new(
            "x86:LE:64:default",
            "Intel x86 Manual",
            "/docs/x86.pdf",
        ));
        assert!(p.find_manual("x86:LE:64:default").is_some());
        assert!(p.find_manual("ARM:LE:32:v8").is_none());
    }

    // ----- LanguageService tests -----

    #[test]
    fn test_language_service() {
        let mut svc = LanguageService::new();
        svc.register(LanguageDescription {
            id: LanguageId::new("x86:LE:64:default"),
            processor: "x86".into(),
            endian: "little".into(),
            size: 64,
            description: "Intel 64-bit".into(),
            compiler_specs: vec![CompilerSpecDescription {
                id: CompilerSpecId::new("default"),
                name: "GNU".into(),
                is_default: true,
            }],
        });
        assert_eq!(svc.language_count(), 1);
        assert!(svc.get_language(&LanguageId::new("x86:LE:64:default")).is_some());
        assert!(svc.get_language(&LanguageId::new("ARM:LE:32:v8")).is_none());
    }

    #[test]
    fn test_language_service_filter_by_processor() {
        let mut svc = LanguageService::new();
        svc.register(LanguageDescription {
            id: LanguageId::new("x86:LE:64:default"),
            processor: "x86".into(),
            endian: "little".into(),
            size: 64,
            description: "Intel 64-bit".into(),
            compiler_specs: vec![],
        });
        svc.register(LanguageDescription {
            id: LanguageId::new("ARM:LE:32:v8"),
            processor: "ARM".into(),
            endian: "little".into(),
            size: 32,
            description: "ARM v8".into(),
            compiler_specs: vec![],
        });
        let x86 = svc.get_languages_for_processor("x86");
        assert_eq!(x86.len(), 1);
        let arm = svc.get_languages_for_processor("ARM");
        assert_eq!(arm.len(), 1);
    }

    // ----- LanguageId / CompilerSpecId tests -----

    #[test]
    fn test_language_id_processor() {
        let id = LanguageId::new("x86:LE:64:default");
        assert_eq!(id.processor(), "x86");
        assert_eq!(id.to_string(), "x86:LE:64:default");
    }

    #[test]
    fn test_language_compiler_spec_pair() {
        let pair = LanguageCompilerSpecPair::new("x86:LE:64:default", "gcc");
        assert_eq!(pair.language_id.0, "x86:LE:64:default");
        assert_eq!(pair.compiler_spec_id.0, "gcc");
        let s = pair.to_string();
        assert!(s.contains("x86"));
        assert!(s.contains("gcc"));
    }

    // ----- SetLanguageDialog tests -----

    #[test]
    fn test_dialog_new() {
        let dialog = SetLanguageDialog::new("Set Language", None);
        assert_eq!(dialog.title, "Set Language");
        assert!(!dialog.is_open);
        assert_eq!(dialog.result, SetLanguageResult::Cancelled);
    }

    #[test]
    fn test_dialog_open_close() {
        let mut dialog = SetLanguageDialog::new("Set Language", None);
        dialog.open();
        assert!(dialog.is_open);
        dialog.close();
        assert!(!dialog.is_open);
    }

    #[test]
    fn test_dialog_ok() {
        let mut dialog = SetLanguageDialog::new("Set Language", None);
        dialog.open();
        let pair = LanguageCompilerSpecPair::new("ARM:LE:32:v8", "default");
        dialog.ok(pair.clone());
        assert!(!dialog.is_open);
        assert_eq!(dialog.result, SetLanguageResult::Selected(pair));
        assert!(dialog.get_language_id().is_some());
        assert_eq!(dialog.get_language_id().unwrap().0, "ARM:LE:32:v8");
    }

    #[test]
    fn test_dialog_cancel() {
        let mut dialog = SetLanguageDialog::new("Set Language", None);
        dialog.open();
        dialog.cancel();
        assert!(!dialog.is_open);
        assert_eq!(dialog.result, SetLanguageResult::Cancelled);
        assert!(dialog.get_language_id().is_none());
    }

    #[test]
    fn test_dialog_filter() {
        let mut dialog = SetLanguageDialog::new("Set Language", None);
        dialog.set_languages(vec![
            LanguageDescription {
                id: LanguageId::new("x86:LE:64:default"),
                processor: "x86".into(),
                endian: "little".into(),
                size: 64,
                description: "Intel 64-bit".into(),
                compiler_specs: vec![],
            },
            LanguageDescription {
                id: LanguageId::new("ARM:LE:32:v8"),
                processor: "ARM".into(),
                endian: "little".into(),
                size: 32,
                description: "ARM v8".into(),
                compiler_specs: vec![],
            },
        ]);
        dialog.set_filter("x86");
        let filtered = dialog.filtered_languages();
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].id.0, "x86:LE:64:default");
    }

    #[test]
    fn test_dialog_filter_by_description() {
        let mut dialog = SetLanguageDialog::new("Set Language", None);
        dialog.set_languages(vec![
            LanguageDescription {
                id: LanguageId::new("x86:LE:64:default"),
                processor: "x86".into(),
                endian: "little".into(),
                size: 64,
                description: "Intel 64-bit".into(),
                compiler_specs: vec![],
            },
            LanguageDescription {
                id: LanguageId::new("ARM:LE:32:v8"),
                processor: "ARM".into(),
                endian: "little".into(),
                size: 32,
                description: "ARM v8".into(),
                compiler_specs: vec![],
            },
        ]);
        dialog.set_filter("ARM");
        let filtered = dialog.filtered_languages();
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].id.0, "ARM:LE:32:v8");
    }

    // ----- LanguageProviderPlugin tests -----

    #[test]
    fn test_provider_plugin_new() {
        let p = LanguageProviderPlugin::new();
        assert_eq!(p.name, "LanguageProvider");
        assert!(!p.initialized);
        assert!(!p.action_enabled);
    }

    #[test]
    fn test_provider_plugin_init_front_end() {
        let mut p = LanguageProviderPlugin::new();
        p.init(true);
        assert!(p.initialized);
        assert!(p.action_enabled);
    }

    #[test]
    fn test_provider_plugin_init_not_front_end() {
        let mut p = LanguageProviderPlugin::new();
        p.init(false);
        assert!(!p.initialized);
        assert!(!p.action_enabled);
    }

    #[test]
    fn test_provider_plugin_dispose() {
        let mut p = LanguageProviderPlugin::new();
        p.init(true);
        p.dispose();
        assert!(!p.initialized);
        assert!(!p.action_enabled);
    }

    // ----- ProcessorManual tests -----

    #[test]
    fn test_processor_manual() {
        let manual = ProcessorManual::new("x86:LE:64:default", "Intel x86 Manual", "/docs/x86.pdf");
        assert_eq!(manual.language_id, "x86:LE:64:default");
        assert_eq!(manual.name, "Intel x86 Manual");
        assert_eq!(manual.path, "/docs/x86.pdf");
        assert!(manual.page_count.is_none());
    }

    // ----- Integration tests -----

    #[test]
    fn test_full_instruction_info_workflow() {
        let mut plugin = ShowInstructionInfoPlugin::new();
        plugin.program_activated("test.exe");

        let provider = InstructionInfoProvider::new("Instruction Info", InfoDisplayMode::Dynamic);
        let idx = plugin.register_provider(provider);
        plugin.connect_provider(idx);

        // Location changes update the provider
        plugin.location_changed(Some(Address::new(0x401000)));
        assert_eq!(
            plugin.providers[idx].current_address.unwrap().offset,
            0x401000
        );

        // Build instruction info
        let mut info = InstructionInfo::new(Address::new(0x401000));
        info.formatted_text = "CALL 0x402000".into();
        info.length = 5;
        info.num_operands = 1;
        let mut op = OperandInfo::new(0);
        op.representation = "0x402000".into();
        op.address = Some(Address::new(0x402000));
        op.op_type = OperandType(OperandType::ADDRESS.0 | OperandType::RELATIVE.0);
        info.operands = vec![op];

        plugin.browse_instruction(info);
        assert!(plugin.providers[idx].visible);
        assert_eq!(plugin.providers[idx].instruction_text, "CALL 0x402000");
    }

    #[test]
    fn test_set_language_workflow() {
        let mut plugin = LanguageProviderPlugin::new();
        plugin.init(true);
        plugin.language_service.register(LanguageDescription {
            id: LanguageId::new("x86:LE:64:default"),
            processor: "x86".into(),
            endian: "little".into(),
            size: 64,
            description: "Intel 64-bit".into(),
            compiler_specs: vec![CompilerSpecDescription {
                id: CompilerSpecId::new("default"),
                name: "GNU".into(),
                is_default: true,
            }],
        });

        let mut dialog = SetLanguageDialog::new(
            "Set Language: test.exe",
            Some(LanguageCompilerSpecPair::new("x86:LE:64:default", "default")),
        );

        // User picks the same language
        let pair = LanguageCompilerSpecPair::new("x86:LE:64:default", "default");
        dialog.ok(pair.clone());

        let result = plugin.execute_set_language(&mut dialog, None);
        assert!(result.is_some());
    }

    #[test]
    fn test_instruction_info_debug_fields() {
        let mut info = InstructionInfo::new(Address::new(0x1000));
        info.length = 4;
        info.has_sleigh_debug = true;
        info.num_operands = 1;

        let mut op = OperandInfo::new(0);
        op.mask = Some("0xFF00".into());
        op.masked_value = Some("0x4200".into());
        info.operands = vec![op];

        assert_eq!(info.get_mask(0), Some("0xFF00"));
        assert_eq!(info.get_masked_value(0), Some("0x4200"));
    }
}
