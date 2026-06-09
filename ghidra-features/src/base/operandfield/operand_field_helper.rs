//! OperandFieldHelper -- display configuration and operand rendering logic.
//!
//! Ported from Ghidra's `OperandFieldHelper` (`ghidra.app.util.viewer.field`).
//!
//! This module provides:
//! - [`OperandFieldHelper`] -- manages operand field display options (word
//!   wrap, underline, max lines, separator spacing, semicolon wrapping)
//! - [`UnderlineChoice`] -- underline policy for operand references
//! - [`OperandFieldElement`] -- a single element within an operand field
//!   (operand index, sub-operand index, character offset)
//! - [`OperandFieldResult`] -- accumulates rendered operand elements
//! - [`OpInfo`] -- operand representation info for a single operand
//! - Color/style attribute types used to render different operand kinds

use serde::{Deserialize, Serialize};
use std::fmt;

// ============================================================================
// Display option types
// ============================================================================

/// Underline policy for operand reference fields.
///
/// Corresponds to `OperandFieldHelper.UNDERLINE_CHOICE` in Java.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum UnderlineChoice {
    /// Underline operands that have non-primary references.
    Hidden,
    /// Underline all operands that have any reference.
    All,
    /// Never underline operands.
    None,
}

impl Default for UnderlineChoice {
    fn default() -> Self {
        UnderlineChoice::Hidden
    }
}

impl fmt::Display for UnderlineChoice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UnderlineChoice::Hidden => write!(f, "Hidden"),
            UnderlineChoice::All => write!(f, "All"),
            UnderlineChoice::None => write!(f, "None"),
        }
    }
}

impl std::str::FromStr for UnderlineChoice {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Hidden" => Ok(UnderlineChoice::Hidden),
            "All" => Ok(UnderlineChoice::All),
            "None" => Ok(UnderlineChoice::None),
            _ => Err(format!("Unknown UnderlineChoice: {}", s)),
        }
    }
}

// ============================================================================
// OperandFieldDisplayOptions
// ============================================================================

/// Display options for the operand field.
///
/// Corresponds to the options registered by `OperandFieldHelper` in Java:
/// word wrap, max display lines, underline choice, separator spacing, and
/// semicolon wrapping.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperandFieldDisplayOptions {
    /// Enable word wrapping of strings in the operand field.
    pub word_wrap: bool,
    /// Maximum number of lines used to display strings in the operand field.
    pub max_display_lines: usize,
    /// Underline policy for operand references.
    pub underline_choice: UnderlineChoice,
    /// Add a space between separator and next operand.
    pub space_after_separator: bool,
    /// Wrap operand field on semicolons.
    pub wrap_on_semicolon: bool,
}

impl Default for OperandFieldDisplayOptions {
    fn default() -> Self {
        Self {
            word_wrap: false,
            max_display_lines: 2,
            underline_choice: UnderlineChoice::Hidden,
            space_after_separator: false,
            wrap_on_semicolon: false,
        }
    }
}

impl OperandFieldDisplayOptions {
    /// Create new display options with all defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set max display lines (minimum 1).
    pub fn set_max_display_lines(&mut self, lines: usize) {
        self.max_display_lines = lines.max(1);
    }

    /// Returns `true` if word wrapping should be applied for the given
    /// data representation.
    pub fn should_word_wrap(&self, has_error: bool, is_string: bool, is_enum: bool) -> bool {
        if has_error {
            return true;
        }
        if !self.word_wrap {
            return false;
        }
        is_string || is_enum
    }
}

// ============================================================================
// OperandFieldElement
// ============================================================================

/// A single rendered element within an operand field.
///
/// Corresponds to `OperandFieldElement` in Java. Each element carries an
/// operand index, a sub-operand index, and a character offset into the
/// operand representation string.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OperandFieldElement {
    /// The text content of this element.
    pub text: String,
    /// The operand index (0-based).
    pub operand_index: usize,
    /// The sub-operand index within the operand.
    pub sub_operand_index: usize,
    /// The character offset within the operand representation.
    pub character_offset: usize,
}

impl OperandFieldElement {
    /// Create a new operand field element.
    pub fn new(
        text: impl Into<String>,
        operand_index: usize,
        sub_operand_index: usize,
        character_offset: usize,
    ) -> Self {
        Self {
            text: text.into(),
            operand_index,
            sub_operand_index,
            character_offset,
        }
    }

    /// Create a line break sentinel element.
    pub fn line_break() -> Self {
        Self {
            text: String::new(),
            operand_index: 0,
            sub_operand_index: 0,
            character_offset: 0,
        }
    }

    /// Returns `true` if this element is a line break sentinel.
    pub fn is_line_break(&self) -> bool {
        self.text.is_empty() && self.operand_index == 0 && self.sub_operand_index == 0
    }

    /// The length of the text content.
    pub fn len(&self) -> usize {
        self.text.len()
    }

    /// Returns `true` if the text content is empty.
    pub fn is_empty(&self) -> bool {
        self.text.is_empty()
    }
}

impl fmt::Display for OperandFieldElement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.text)
    }
}

// ============================================================================
// OperandFieldResult
// ============================================================================

/// Accumulates rendered operand field elements and tracks character offsets.
///
/// Corresponds to `OpFieldResults` in Java. Used during rendering to collect
/// all elements for one instruction's operands and then assemble them into
/// a displayable field.
#[derive(Debug, Clone)]
pub struct OperandFieldResult {
    /// The accumulated elements.
    elements: Vec<OperandFieldElement>,
    /// Current character offset (incremented as elements are added).
    character_offset: usize,
}

impl OperandFieldResult {
    /// Create a new empty result.
    pub fn new() -> Self {
        Self {
            elements: Vec::new(),
            character_offset: 0,
        }
    }

    /// Add an element and advance the character offset.
    pub fn add(&mut self, element: OperandFieldElement) {
        self.character_offset += element.len();
        self.elements.push(element);
    }

    /// Add a line break sentinel.
    pub fn add_line_break(&mut self) {
        self.elements.push(OperandFieldElement::line_break());
    }

    /// Reset the character offset (called between operands).
    pub fn reset_character_offset(&mut self) {
        self.character_offset = 0;
    }

    /// Returns `true` if no elements have been added.
    pub fn is_empty(&self) -> bool {
        self.elements.is_empty()
    }

    /// Returns the number of elements.
    pub fn len(&self) -> usize {
        self.elements.len()
    }

    /// Returns the current character offset.
    pub fn character_offset(&self) -> usize {
        self.character_offset
    }

    /// Returns a reference to the accumulated elements.
    pub fn elements(&self) -> &[OperandFieldElement] {
        &self.elements
    }

    /// Consume the result and return the elements.
    pub fn into_elements(self) -> Vec<OperandFieldElement> {
        self.elements
    }

    /// Break elements into lines at line-break sentinels.
    ///
    /// Groups all elements between `LINE_BREAK` sentinels into logical
    /// lines. Each line becomes a `Vec<&OperandFieldElement>`.
    pub fn break_into_lines(&self) -> Vec<Vec<&OperandFieldElement>> {
        let mut lines: Vec<Vec<&OperandFieldElement>> = Vec::new();
        let mut current_line: Vec<&OperandFieldElement> = Vec::new();

        for element in &self.elements {
            if element.is_line_break() {
                if !current_line.is_empty() {
                    lines.push(current_line);
                    current_line = Vec::new();
                }
            } else {
                current_line.push(element);
            }
        }
        if !current_line.is_empty() {
            lines.push(current_line);
        }
        lines
    }
}

impl Default for OperandFieldResult {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// OperandKind -- classification of what an operand element represents
// ============================================================================

/// The kind of operand representation element.
///
/// Used to determine the color/style attributes for rendering.
/// Corresponds to the `getOpAttributes` dispatch in Java.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OperandKind {
    /// A register name.
    Register,
    /// A scalar/constant value.
    Scalar,
    /// An address (pointer).
    Address,
    /// A separator character (comma, parentheses).
    Separator,
    /// An equate (named constant).
    Equate,
    /// A variable reference (parameter, local).
    Variable,
    /// A label/symbol reference.
    Label,
    /// A bad/invalid reference.
    BadReference,
    /// An error in operand representation.
    Error,
    /// An external reference.
    External,
    /// A string literal.
    String,
    /// Other/unknown.
    Other,
}

impl Default for OperandKind {
    fn default() -> Self {
        OperandKind::Other
    }
}

// ============================================================================
// OperandFieldHelper
// ============================================================================

/// Core logic for operand field rendering and display.
///
/// This struct manages the display options and provides methods for:
/// - Determining underline state for operand references
/// - Classifying operand elements by kind
/// - Building operand field results for instructions and data
/// - Computing display attributes for different operand types
///
/// This is the Rust port of Ghidra's abstract `OperandFieldHelper` class.
/// GUI-specific rendering (AttributedString, FontMetrics) is abstracted away;
/// this module focuses on the data model and classification logic.
#[derive(Debug, Clone)]
pub struct OperandFieldHelper {
    /// Display options.
    pub options: OperandFieldDisplayOptions,
    /// Whether the helper is enabled.
    enabled: bool,
}

impl OperandFieldHelper {
    /// Create a new helper with default options.
    pub fn new() -> Self {
        Self {
            options: OperandFieldDisplayOptions::default(),
            enabled: true,
        }
    }

    /// Create a new helper with the given options.
    pub fn with_options(options: OperandFieldDisplayOptions) -> Self {
        Self {
            options,
            enabled: true,
        }
    }

    /// Returns `true` if the helper is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Set the enabled state.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Determine whether an operand should be underlined.
    ///
    /// Mirrors `OperandFieldHelper.isUnderlined()`:
    /// - `None` choice: never underline
    /// - `Hidden` choice: underline if there are non-primary references or
    ///   if the primary reference is hidden
    /// - `All` choice: underline if any reference exists
    pub fn is_underlined(
        &self,
        has_references: bool,
        has_non_primary_references: bool,
        primary_reference_hidden: bool,
    ) -> bool {
        match self.options.underline_choice {
            UnderlineChoice::None => false,
            UnderlineChoice::Hidden => primary_reference_hidden || has_non_primary_references,
            UnderlineChoice::All => has_references,
        }
    }

    /// Classify an operand element by its kind.
    ///
    /// This mirrors the dispatch in `OperandFieldHelper.getOpAttributes()`
    /// which determines color/style based on the Java type of the operand
    /// representation object.
    pub fn classify_operand_element(
        &self,
        element_text: &str,
        is_register: bool,
        is_scalar: bool,
        is_address: bool,
        is_separator: bool,
        is_equate: bool,
        is_variable: bool,
        is_label: bool,
        is_bad_ref: bool,
        is_external: bool,
    ) -> OperandKind {
        if is_register {
            OperandKind::Register
        } else if is_scalar {
            OperandKind::Scalar
        } else if is_address {
            OperandKind::Address
        } else if is_separator {
            OperandKind::Separator
        } else if is_equate {
            if is_bad_ref {
                OperandKind::BadReference
            } else {
                OperandKind::Equate
            }
        } else if is_variable {
            OperandKind::Variable
        } else if is_label {
            if is_external {
                OperandKind::External
            } else {
                OperandKind::Label
            }
        } else if is_bad_ref {
            OperandKind::BadReference
        } else {
            // Fall back to text-based heuristics
            if element_text.starts_with("0x") || element_text.starts_with('#') {
                OperandKind::Scalar
            } else if element_text.chars().all(|c| c == ',' || c == '(' || c == ')' || c == '[' || c == ']') {
                OperandKind::Separator
            } else {
                OperandKind::Other
            }
        }
    }

    /// Process a separator and apply the space-after-separator option.
    ///
    /// Returns the separator string, optionally with a trailing space.
    pub fn format_separator(&self, separator: &str) -> String {
        if self.options.space_after_separator {
            format!("{} ", separator)
        } else {
            separator.to_string()
        }
    }

    /// Determine whether word wrapping should be applied.
    ///
    /// Mirrors `OperandFieldHelper.shouldWordWrap()`.
    pub fn should_word_wrap(&self, has_error: bool, value_is_string: bool, data_type_is_enum: bool) -> bool {
        self.options.should_word_wrap(has_error, value_is_string, data_type_is_enum)
    }

    /// Update display options.
    pub fn update_options(&mut self, options: OperandFieldDisplayOptions) {
        self.options = options;
    }

    /// Update a single option by name (mirrors fieldOptionsChanged).
    ///
    /// Returns `true` if the option was recognized and updated.
    pub fn set_option(&mut self, name: &str, value: &str) -> bool {
        match name {
            "word_wrap" | "enable_word_wrap" => {
                self.options.word_wrap = value.parse().unwrap_or(false);
                true
            }
            "max_display_lines" => {
                if let Ok(n) = value.parse::<usize>() {
                    self.options.set_max_display_lines(n);
                    true
                } else {
                    false
                }
            }
            "underline" => {
                if let Ok(choice) = value.parse::<UnderlineChoice>() {
                    self.options.underline_choice = choice;
                    true
                } else {
                    false
                }
            }
            "space_after_separator" => {
                self.options.space_after_separator = value.parse().unwrap_or(false);
                true
            }
            "wrap_on_semicolon" => {
                self.options.wrap_on_semicolon = value.parse().unwrap_or(false);
                true
            }
            _ => false,
        }
    }
}

impl Default for OperandFieldHelper {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// OpInfo -- operand representation info
// ============================================================================

/// Information about a single operand's representation for rendering.
///
/// Corresponds to the inner `OpInfo` class in Java's `OperandFieldHelper`.
/// Wraps the operand index, its representation elements, separator info,
/// and rendering metadata.
#[derive(Debug, Clone)]
pub struct OpInfo {
    /// The operand index.
    pub op_index: usize,
    /// The representation elements (text, objects, lists).
    pub rep_elements: Vec<OpRepElement>,
    /// Whether the operand representation has an error.
    pub has_error: bool,
    /// Whether the primary reference is hidden.
    pub primary_reference_hidden: bool,
    /// The separator text after this operand (if any).
    pub separator: Option<String>,
}

/// A single element in an operand representation list.
///
/// This models the various types that can appear in an
/// `OperandRepresentationList` in Java.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpRepElement {
    /// A text string.
    Text(String),
    /// A register name.
    Register(String),
    /// A scalar/constant value.
    Scalar(i64, usize), // (value, bit_length)
    /// An address reference.
    Address(u64),
    /// An equate (named constant).
    Equate { name: String, value: i64 },
    /// A variable offset reference.
    Variable { name: String, offset: i64 },
    /// A label/symbol reference.
    Label(String),
    /// A separator character.
    Separator(char),
    /// An indirect reference delimiter (e.g., "=>").
    IndirectRef(String),
    /// A nested list of sub-elements.
    SubList(Vec<OpRepElement>),
}

impl fmt::Display for OpRepElement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OpRepElement::Text(s) => write!(f, "{}", s),
            OpRepElement::Register(r) => write!(f, "{}", r),
            OpRepElement::Scalar(v, _) => write!(f, "0x{:x}", v),
            OpRepElement::Address(a) => write!(f, "0x{:x}", a),
            OpRepElement::Equate { name, .. } => write!(f, "{}", name),
            OpRepElement::Variable { name, .. } => write!(f, "{}", name),
            OpRepElement::Label(l) => write!(f, "{}", l),
            OpRepElement::Separator(c) => write!(f, "{}", c),
            OpRepElement::IndirectRef(s) => write!(f, "{}", s),
            OpRepElement::SubList(elements) => {
                for e in elements {
                    write!(f, "{}", e)?;
                }
                Ok(())
            }
        }
    }
}

impl OpRepElement {
    /// Returns `true` if this element is a separator.
    pub fn is_separator(&self) -> bool {
        matches!(self, OpRepElement::Separator(_))
    }

    /// Returns `true` if this element is a register.
    pub fn is_register(&self) -> bool {
        matches!(self, OpRepElement::Register(_))
    }

    /// Returns `true` if this element is a scalar.
    pub fn is_scalar(&self) -> bool {
        matches!(self, OpRepElement::Scalar(_, _))
    }

    /// Returns `true` if this element is an address.
    pub fn is_address(&self) -> bool {
        matches!(self, OpRepElement::Address(_))
    }

    /// Returns `true` if this element is an equate.
    pub fn is_equate(&self) -> bool {
        matches!(self, OpRepElement::Equate { .. })
    }

    /// Returns `true` if this element is a variable reference.
    pub fn is_variable(&self) -> bool {
        matches!(self, OpRepElement::Variable { .. })
    }

    /// Returns `true` if this element is a label.
    pub fn is_label(&self) -> bool {
        matches!(self, OpRepElement::Label(_))
    }

    /// Returns `true` if this element is a sub-list.
    pub fn is_sub_list(&self) -> bool {
        matches!(self, OpRepElement::SubList(_))
    }
}

impl OpInfo {
    /// Create a new OpInfo for the given operand index.
    pub fn new(op_index: usize) -> Self {
        Self {
            op_index,
            rep_elements: Vec::new(),
            has_error: false,
            primary_reference_hidden: false,
            separator: None,
        }
    }

    /// Create an OpInfo with error state.
    pub fn with_error(op_index: usize) -> Self {
        Self {
            op_index,
            rep_elements: Vec::new(),
            has_error: true,
            primary_reference_hidden: false,
            separator: None,
        }
    }

    /// Returns the number of representation elements.
    pub fn rep_count(&self) -> usize {
        self.rep_elements.len()
    }

    /// Returns `true` if the operand has an error.
    pub fn is_invalid(&self) -> bool {
        self.has_error || self.rep_elements.is_empty()
    }

    /// Get the representation element at the given sub-index.
    pub fn get_rep_element(&self, sub_op_index: usize) -> Option<&OpRepElement> {
        self.rep_elements.get(sub_op_index)
    }

    /// Get a text representation of the entire operand.
    pub fn get_rep_text(&self) -> String {
        if self.rep_elements.is_empty() {
            return "<UNSUPPORTED>".to_string();
        }
        self.rep_elements
            .iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join("")
    }
}

// ============================================================================
// OperandFieldAnalyzerInfo -- info about operand analysis for locations
// ============================================================================

/// Information about an operand field location for program location creation.
///
/// Mirrors the data extracted in `OperandFieldHelper.createInstructionLocation()`
/// and `createDataLocation()` when translating a click position to a
/// `ProgramLocation`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperandLocationInfo {
    /// The address of the code unit.
    pub address: u64,
    /// The operand index.
    pub operand_index: i32,
    /// The sub-operand index.
    pub sub_operand_index: i32,
    /// The character offset within the representation string.
    pub character_offset: i32,
    /// The reference target address (if any).
    pub ref_address: Option<u64>,
    /// The display representation string.
    pub rep_string: String,
    /// The equate name (if the operand is an equate).
    pub equate_name: Option<String>,
    /// The equate value (if the operand is an equate).
    pub equate_value: Option<i64>,
    /// Whether this is an instruction (vs data).
    pub is_instruction: bool,
    /// Variable offset info (for stack variable references).
    pub variable_name: Option<String>,
}

impl OperandLocationInfo {
    /// Create a simple operand location.
    pub fn new(address: u64, operand_index: i32, sub_operand_index: i32, character_offset: i32) -> Self {
        Self {
            address,
            operand_index,
            sub_operand_index,
            character_offset,
            ref_address: None,
            rep_string: String::new(),
            equate_name: None,
            equate_value: None,
            is_instruction: true,
            variable_name: None,
        }
    }

    /// Create an unsupported/error location.
    pub fn unsupported(address: u64, operand_index: i32) -> Self {
        Self {
            address,
            operand_index,
            sub_operand_index: 0,
            character_offset: 0,
            ref_address: None,
            rep_string: "<UNSUPPORTED>".to_string(),
            equate_name: None,
            equate_value: None,
            is_instruction: true,
            variable_name: None,
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -- UnderlineChoice --

    #[test]
    fn test_underline_choice_default() {
        assert_eq!(UnderlineChoice::default(), UnderlineChoice::Hidden);
    }

    #[test]
    fn test_underline_choice_display() {
        assert_eq!(format!("{}", UnderlineChoice::Hidden), "Hidden");
        assert_eq!(format!("{}", UnderlineChoice::All), "All");
        assert_eq!(format!("{}", UnderlineChoice::None), "None");
    }

    #[test]
    fn test_underline_choice_from_str() {
        assert_eq!("Hidden".parse::<UnderlineChoice>().unwrap(), UnderlineChoice::Hidden);
        assert_eq!("All".parse::<UnderlineChoice>().unwrap(), UnderlineChoice::All);
        assert_eq!("None".parse::<UnderlineChoice>().unwrap(), UnderlineChoice::None);
        assert!("Invalid".parse::<UnderlineChoice>().is_err());
    }

    // -- OperandFieldDisplayOptions --

    #[test]
    fn test_display_options_default() {
        let opts = OperandFieldDisplayOptions::default();
        assert!(!opts.word_wrap);
        assert_eq!(opts.max_display_lines, 2);
        assert_eq!(opts.underline_choice, UnderlineChoice::Hidden);
        assert!(!opts.space_after_separator);
        assert!(!opts.wrap_on_semicolon);
    }

    #[test]
    fn test_display_options_set_max_lines() {
        let mut opts = OperandFieldDisplayOptions::default();
        opts.set_max_display_lines(0);
        assert_eq!(opts.max_display_lines, 1); // clamped to minimum 1
        opts.set_max_display_lines(5);
        assert_eq!(opts.max_display_lines, 5);
    }

    #[test]
    fn test_should_word_wrap_error() {
        let opts = OperandFieldDisplayOptions::default();
        assert!(opts.should_word_wrap(true, false, false));
    }

    #[test]
    fn test_should_word_wrap_disabled() {
        let opts = OperandFieldDisplayOptions::default();
        assert!(!opts.should_word_wrap(false, true, false));
    }

    #[test]
    fn test_should_word_wrap_enabled_string() {
        let mut opts = OperandFieldDisplayOptions::default();
        opts.word_wrap = true;
        assert!(opts.should_word_wrap(false, true, false));
        assert!(opts.should_word_wrap(false, false, true));
        assert!(!opts.should_word_wrap(false, false, false));
    }

    // -- OperandFieldElement --

    #[test]
    fn test_element_new() {
        let elem = OperandFieldElement::new("EAX", 0, 1, 5);
        assert_eq!(elem.text, "EAX");
        assert_eq!(elem.operand_index, 0);
        assert_eq!(elem.sub_operand_index, 1);
        assert_eq!(elem.character_offset, 5);
        assert_eq!(elem.len(), 3);
        assert!(!elem.is_empty());
        assert!(!elem.is_line_break());
    }

    #[test]
    fn test_element_line_break() {
        let elem = OperandFieldElement::line_break();
        assert!(elem.is_line_break());
        assert!(elem.is_empty());
    }

    #[test]
    fn test_element_display() {
        let elem = OperandFieldElement::new("0xff", 0, 0, 0);
        assert_eq!(format!("{}", elem), "0xff");
    }

    // -- OperandFieldResult --

    #[test]
    fn test_result_new() {
        let result = OperandFieldResult::new();
        assert!(result.is_empty());
        assert_eq!(result.len(), 0);
        assert_eq!(result.character_offset(), 0);
    }

    #[test]
    fn test_result_add() {
        let mut result = OperandFieldResult::new();
        result.add(OperandFieldElement::new("EAX", 0, 0, 0));
        assert_eq!(result.len(), 1);
        assert_eq!(result.character_offset(), 3);

        result.add(OperandFieldElement::new(", ", 0, 0, 3));
        assert_eq!(result.character_offset(), 5);
    }

    #[test]
    fn test_result_reset_offset() {
        let mut result = OperandFieldResult::new();
        result.add(OperandFieldElement::new("EAX", 0, 0, 0));
        result.reset_character_offset();
        assert_eq!(result.character_offset(), 0);
    }

    #[test]
    fn test_result_line_break() {
        let mut result = OperandFieldResult::new();
        result.add(OperandFieldElement::new("EAX", 0, 0, 0));
        result.add_line_break();
        result.add(OperandFieldElement::new("EBX", 1, 0, 0));
        assert_eq!(result.len(), 3);
    }

    #[test]
    fn test_result_break_into_lines() {
        let mut result = OperandFieldResult::new();
        result.add(OperandFieldElement::new("A", 0, 0, 0));
        result.add(OperandFieldElement::new("B", 0, 1, 1));
        result.add_line_break();
        result.add(OperandFieldElement::new("C", 1, 0, 0));

        let lines = result.break_into_lines();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0].len(), 2);
        assert_eq!(lines[0][0].text, "A");
        assert_eq!(lines[0][1].text, "B");
        assert_eq!(lines[1].len(), 1);
        assert_eq!(lines[1][0].text, "C");
    }

    #[test]
    fn test_result_break_into_elements() {
        let mut result = OperandFieldResult::new();
        result.add(OperandFieldElement::new("X", 0, 0, 0));
        let elements = result.into_elements();
        assert_eq!(elements.len(), 1);
        assert_eq!(elements[0].text, "X");
    }

    // -- OperandKind --

    #[test]
    fn test_operand_kind_default() {
        assert_eq!(OperandKind::default(), OperandKind::Other);
    }

    // -- OperandFieldHelper --

    #[test]
    fn test_helper_new() {
        let helper = OperandFieldHelper::new();
        assert!(helper.is_enabled());
        assert!(!helper.options.word_wrap);
        assert_eq!(helper.options.max_display_lines, 2);
    }

    #[test]
    fn test_helper_with_options() {
        let mut opts = OperandFieldDisplayOptions::default();
        opts.word_wrap = true;
        opts.max_display_lines = 5;
        let helper = OperandFieldHelper::with_options(opts);
        assert!(helper.options.word_wrap);
        assert_eq!(helper.options.max_display_lines, 5);
    }

    #[test]
    fn test_helper_enabled() {
        let mut helper = OperandFieldHelper::new();
        assert!(helper.is_enabled());
        helper.set_enabled(false);
        assert!(!helper.is_enabled());
    }

    #[test]
    fn test_is_underlined_none() {
        let mut helper = OperandFieldHelper::new();
        helper.options.underline_choice = UnderlineChoice::None;
        assert!(!helper.is_underlined(true, true, true));
    }

    #[test]
    fn test_is_underlined_all() {
        let mut helper = OperandFieldHelper::new();
        helper.options.underline_choice = UnderlineChoice::All;
        assert!(helper.is_underlined(true, false, false));
        assert!(!helper.is_underlined(false, false, false));
    }

    #[test]
    fn test_is_underlined_hidden() {
        let mut helper = OperandFieldHelper::new();
        helper.options.underline_choice = UnderlineChoice::Hidden;
        // primary_reference_hidden triggers underline
        assert!(helper.is_underlined(false, false, true));
        // non-primary references trigger underline
        assert!(helper.is_underlined(true, true, false));
        // no references and no hidden primary -- no underline
        assert!(!helper.is_underlined(false, false, false));
        // only primary reference, not hidden -- no underline
        assert!(!helper.is_underlined(true, false, false));
    }

    #[test]
    fn test_classify_operand_element_register() {
        let helper = OperandFieldHelper::new();
        let kind = helper.classify_operand_element("EAX", true, false, false, false, false, false, false, false, false);
        assert_eq!(kind, OperandKind::Register);
    }

    #[test]
    fn test_classify_operand_element_scalar() {
        let helper = OperandFieldHelper::new();
        let kind = helper.classify_operand_element("0xff", false, true, false, false, false, false, false, false, false);
        assert_eq!(kind, OperandKind::Scalar);
    }

    #[test]
    fn test_classify_operand_element_address() {
        let helper = OperandFieldHelper::new();
        let kind = helper.classify_operand_element("0x1000", false, false, true, false, false, false, false, false, false);
        assert_eq!(kind, OperandKind::Address);
    }

    #[test]
    fn test_classify_operand_element_separator() {
        let helper = OperandFieldHelper::new();
        let kind = helper.classify_operand_element(",", false, false, false, true, false, false, false, false, false);
        assert_eq!(kind, OperandKind::Separator);
    }

    #[test]
    fn test_classify_operand_element_equate() {
        let helper = OperandFieldHelper::new();
        let kind = helper.classify_operand_element("MY_CONST", false, false, false, false, true, false, false, false, false);
        assert_eq!(kind, OperandKind::Equate);
    }

    #[test]
    fn test_classify_operand_element_bad_equate() {
        let helper = OperandFieldHelper::new();
        let kind = helper.classify_operand_element("BAD", false, false, false, false, true, false, false, true, false);
        assert_eq!(kind, OperandKind::BadReference);
    }

    #[test]
    fn test_classify_operand_element_variable() {
        let helper = OperandFieldHelper::new();
        let kind = helper.classify_operand_element("param_1", false, false, false, false, false, true, false, false, false);
        assert_eq!(kind, OperandKind::Variable);
    }

    #[test]
    fn test_classify_operand_element_label() {
        let helper = OperandFieldHelper::new();
        let kind = helper.classify_operand_element("main", false, false, false, false, false, false, true, false, false);
        assert_eq!(kind, OperandKind::Label);
    }

    #[test]
    fn test_classify_operand_element_external() {
        let helper = OperandFieldHelper::new();
        let kind = helper.classify_operand_element("printf", false, false, false, false, false, false, true, false, true);
        assert_eq!(kind, OperandKind::External);
    }

    #[test]
    fn test_classify_operand_element_bad_ref() {
        let helper = OperandFieldHelper::new();
        let kind = helper.classify_operand_element("???", false, false, false, false, false, false, false, true, false);
        assert_eq!(kind, OperandKind::BadReference);
    }

    #[test]
    fn test_classify_operand_element_hex_text() {
        let helper = OperandFieldHelper::new();
        let kind = helper.classify_operand_element("0x42", false, false, false, false, false, false, false, false, false);
        assert_eq!(kind, OperandKind::Scalar);
    }

    #[test]
    fn test_classify_operand_element_separator_chars() {
        let helper = OperandFieldHelper::new();
        let kind = helper.classify_operand_element(",", false, false, false, false, false, false, false, false, false);
        assert_eq!(kind, OperandKind::Separator);
    }

    #[test]
    fn test_classify_operand_element_other() {
        let helper = OperandFieldHelper::new();
        let kind = helper.classify_operand_element("foo", false, false, false, false, false, false, false, false, false);
        assert_eq!(kind, OperandKind::Other);
    }

    #[test]
    fn test_format_separator_no_space() {
        let helper = OperandFieldHelper::new();
        assert_eq!(helper.format_separator(","), ",");
    }

    #[test]
    fn test_format_separator_with_space() {
        let mut helper = OperandFieldHelper::new();
        helper.options.space_after_separator = true;
        assert_eq!(helper.format_separator(","), ", ");
    }

    #[test]
    fn test_should_word_wrap_delegation() {
        let mut helper = OperandFieldHelper::new();
        assert!(!helper.should_word_wrap(false, true, false));

        helper.options.word_wrap = true;
        assert!(helper.should_word_wrap(false, true, false));
        assert!(!helper.should_word_wrap(false, false, false));
    }

    #[test]
    fn test_set_option_word_wrap() {
        let mut helper = OperandFieldHelper::new();
        assert!(helper.set_option("word_wrap", "true"));
        assert!(helper.options.word_wrap);
    }

    #[test]
    fn test_set_option_max_display_lines() {
        let mut helper = OperandFieldHelper::new();
        assert!(helper.set_option("max_display_lines", "5"));
        assert_eq!(helper.options.max_display_lines, 5);
    }

    #[test]
    fn test_set_option_underline() {
        let mut helper = OperandFieldHelper::new();
        assert!(helper.set_option("underline", "All"));
        assert_eq!(helper.options.underline_choice, UnderlineChoice::All);
    }

    #[test]
    fn test_set_option_unknown() {
        let mut helper = OperandFieldHelper::new();
        assert!(!helper.set_option("unknown_option", "value"));
    }

    // -- OpInfo --

    #[test]
    fn test_op_info_new() {
        let info = OpInfo::new(0);
        assert_eq!(info.op_index, 0);
        assert!(info.rep_elements.is_empty());
        assert!(!info.has_error);
        assert!(info.is_invalid()); // empty = invalid
    }

    #[test]
    fn test_op_info_with_error() {
        let info = OpInfo::with_error(1);
        assert!(info.has_error);
        assert!(info.is_invalid());
    }

    #[test]
    fn test_op_info_rep_count() {
        let mut info = OpInfo::new(0);
        info.rep_elements.push(OpRepElement::Register("EAX".to_string()));
        info.rep_elements.push(OpRepElement::Separator(','));
        assert_eq!(info.rep_count(), 2);
    }

    #[test]
    fn test_op_info_get_rep_text() {
        let mut info = OpInfo::new(0);
        info.rep_elements.push(OpRepElement::Register("EAX".to_string()));
        info.rep_elements.push(OpRepElement::Separator(','));
        info.rep_elements.push(OpRepElement::Register("EBX".to_string()));
        assert_eq!(info.get_rep_text(), "EAX,EBX");
    }

    #[test]
    fn test_op_info_get_rep_text_empty() {
        let info = OpInfo::new(0);
        assert_eq!(info.get_rep_text(), "<UNSUPPORTED>");
    }

    // -- OpRepElement --

    #[test]
    fn test_op_rep_element_display() {
        assert_eq!(format!("{}", OpRepElement::Text("hello".to_string())), "hello");
        assert_eq!(format!("{}", OpRepElement::Register("EAX".to_string())), "EAX");
        assert_eq!(format!("{}", OpRepElement::Scalar(0xff, 8)), "0xff");
        assert_eq!(format!("{}", OpRepElement::Address(0x1000)), "0x1000");
        assert_eq!(
            format!("{}", OpRepElement::Equate { name: "MY_CONST".to_string(), value: 42 }),
            "MY_CONST"
        );
        assert_eq!(format!("{}", OpRepElement::Separator(',')), ",");
    }

    #[test]
    fn test_op_rep_element_is_separator() {
        assert!(OpRepElement::Separator(',').is_separator());
        assert!(!OpRepElement::Register("EAX".to_string()).is_separator());
    }

    #[test]
    fn test_op_rep_element_is_register() {
        assert!(OpRepElement::Register("EAX".to_string()).is_register());
        assert!(!OpRepElement::Scalar(42, 32).is_register());
    }

    #[test]
    fn test_op_rep_element_is_sub_list() {
        let sub = OpRepElement::SubList(vec![
            OpRepElement::Text("a".to_string()),
            OpRepElement::Text("b".to_string()),
        ]);
        assert!(sub.is_sub_list());
        assert_eq!(format!("{}", sub), "ab");
    }

    // -- OperandLocationInfo --

    #[test]
    fn test_location_info_new() {
        let info = OperandLocationInfo::new(0x1000, 0, 1, 5);
        assert_eq!(info.address, 0x1000);
        assert_eq!(info.operand_index, 0);
        assert_eq!(info.sub_operand_index, 1);
        assert_eq!(info.character_offset, 5);
        assert!(info.ref_address.is_none());
        assert!(info.is_instruction);
    }

    #[test]
    fn test_location_info_unsupported() {
        let info = OperandLocationInfo::unsupported(0x1000, 2);
        assert_eq!(info.rep_string, "<UNSUPPORTED>");
        assert_eq!(info.operand_index, 2);
    }
}
