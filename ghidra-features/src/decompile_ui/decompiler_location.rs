//! Decompiler location types -- Rust port of
//! `ghidra.app.decompiler.location` package and
//! `ghidra.app.decompiler.DecompilerLocationInfo`.
//!
//! Models the cursor position inside the decompiler panel.  Ghidra uses
//! a rich `ProgramLocation` hierarchy so that other parts of the tool can
//! react to where the user clicks.  This module provides:
//!
//! * [`DecompilerLocation`] -- a trait that all decompiler location types
//!   implement, exposing the function entry point, decompile results,
//!   current token, line number, and character position.
//! * [`DecompilerLocationInfo`] -- the shared data payload (function entry,
//!   results, token, line/char position) carried by every location variant.
//! * [`DefaultDecompilerLocation`] -- the generic location when the user
//!   clicks on any token that is not a function name or variable.
//! * [`FunctionNameDecompilerLocation`] -- location when the user clicks on
//!   a function name token.
//! * [`VariableDecompilerLocation`] -- location when the user clicks on a
//!   variable token.
//!
//! # Architecture
//!
//! ```text
//! DecompilerLocation (trait)
//!   ├── get_function_entry_point() -> Address
//!   ├── get_decompile()           -> Option<&DecompileResults>
//!   ├── get_token()               -> Option<&ClangToken>
//!   ├── get_token_name()          -> &str
//!   ├── get_line_number()         -> usize
//!   └── get_char_pos()            -> usize
//!
//! DecompilerLocationInfo           (shared payload)
//!   ├── entry_point: Address
//!   ├── results: Option<DecompileResults>
//!   ├── token: Option<ClangToken>
//!   ├── token_name: String
//!   ├── line_number: usize
//!   └── char_pos: usize
//!
//! DefaultDecompilerLocation        (generic click)
//! FunctionNameDecompilerLocation   (function name click)
//! VariableDecompilerLocation       (variable click)
//! ```

use std::fmt;

use ghidra_core::addr::Address;

use super::controller::DecompileResults;
use super::panel::DecompiledToken;

// ---------------------------------------------------------------------------
// ClangToken -- lightweight token representation for location tracking
// ---------------------------------------------------------------------------

/// A single C-language token from the decompiler output.
///
/// In Ghidra this is `ClangToken`.  Here we model the subset needed for
/// location tracking: the text content, syntax type, and source address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClangToken {
    /// The display text of the token.
    text: String,
    /// Syntax type identifier (keyword, variable, type, comment, etc.).
    syntax_type: ClangSyntaxType,
    /// The address in the program this token corresponds to, if any.
    address: Option<Address>,
    /// The parent line number (0-based).
    line_number: usize,
    /// Character offset within the line (0-based).
    char_offset: usize,
}

/// Syntax type classification for C tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClangSyntaxType {
    /// Keyword (if, while, return, ...).
    Keyword,
    /// Type name (int, char, struct, ...).
    TypeName,
    /// Function name.
    FunctionName,
    /// Variable name (local or parameter).
    Variable,
    /// Field name in a struct/union.
    FieldName,
    /// Label name.
    Label,
    /// Numeric constant.
    Constant,
    /// String literal.
    StringLiteral,
    /// Comment text.
    Comment,
    /// Operator (+, -, *, ...).
    Operator,
    /// Punctuation ({, }, ;, ...).
    Punctuation,
    /// Other / unknown.
    Other,
}

impl ClangSyntaxType {
    /// Returns `true` for syntax types whose text may contain
    /// characters that should be transformed by a `NameTransformer`.
    pub fn is_transformable(&self) -> bool {
        matches!(
            self,
            ClangSyntaxType::FunctionName
                | ClangSyntaxType::Variable
                | ClangSyntaxType::TypeName
                | ClangSyntaxType::FieldName
                | ClangSyntaxType::Label
        )
    }
}

impl ClangToken {
    /// Create a new token.
    pub fn new(
        text: impl Into<String>,
        syntax_type: ClangSyntaxType,
        address: Option<Address>,
        line_number: usize,
        char_offset: usize,
    ) -> Self {
        Self {
            text: text.into(),
            syntax_type,
            address,
            line_number,
            char_offset,
        }
    }

    /// Build a spacer (whitespace) token for empty lines.
    pub fn build_spacer(indent: usize, indent_str: &str) -> Self {
        let text = indent_str.repeat(indent);
        Self {
            text,
            syntax_type: ClangSyntaxType::Other,
            address: None,
            line_number: 0,
            char_offset: 0,
        }
    }

    /// The display text of this token.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// The syntax type of this token.
    pub fn syntax_type(&self) -> ClangSyntaxType {
        self.syntax_type
    }

    /// The program address this token refers to, if any.
    pub fn address(&self) -> Option<Address> {
        self.address
    }

    /// The line number this token is on (0-based).
    pub fn line_number(&self) -> usize {
        self.line_number
    }

    /// The character offset within the line (0-based).
    pub fn char_offset(&self) -> usize {
        self.char_offset
    }
}

impl fmt::Display for ClangToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.text)
    }
}

// ---------------------------------------------------------------------------
// DecompilerLocationInfo -- shared location payload
// ---------------------------------------------------------------------------

/// Shared data carried by every decompiler location variant.
///
/// In Ghidra this is `DecompilerLocationInfo`.  It holds the function
/// entry point, the decompile results (if any), the current token,
/// and the line/character position.
#[derive(Debug, Clone)]
pub struct DecompilerLocationInfo {
    /// Entry point of the function being viewed.
    entry_point: Option<Address>,
    /// Decompile results (if available).
    results: Option<DecompileResults>,
    /// The token at the current cursor position.
    token: Option<ClangToken>,
    /// Cached token text (persists even if the token reference changes).
    token_name: String,
    /// Line number (0-based).
    line_number: usize,
    /// Character position within the line (0-based).
    char_pos: usize,
}

impl DecompilerLocationInfo {
    /// Create a new location info from the given components.
    pub fn new(
        entry_point: Address,
        results: Option<DecompileResults>,
        token: Option<ClangToken>,
        line_number: usize,
        char_pos: usize,
    ) -> Self {
        let token_name = token
            .as_ref()
            .map(|t| t.text().to_string())
            .unwrap_or_default();
        Self {
            entry_point: Some(entry_point),
            results,
            token,
            token_name,
            line_number,
            char_pos,
        }
    }

    /// Create an empty location info (for restoring from serialized state).
    pub fn empty() -> Self {
        Self {
            entry_point: None,
            results: None,
            token: None,
            token_name: String::new(),
            line_number: 0,
            char_pos: 0,
        }
    }

    /// The function entry point.
    pub fn get_function_entry_point(&self) -> Option<Address> {
        self.entry_point
    }

    /// The decompile results, if available.
    pub fn get_decompile(&self) -> Option<&DecompileResults> {
        self.results.as_ref()
    }

    /// The token at the cursor, if available.
    pub fn get_token(&self) -> Option<&ClangToken> {
        self.token.as_ref()
    }

    /// The text of the token at the cursor.
    pub fn get_token_name(&self) -> &str {
        &self.token_name
    }

    /// The line number (0-based).
    pub fn get_line_number(&self) -> usize {
        self.line_number
    }

    /// The character position within the line (0-based).
    pub fn get_char_pos(&self) -> usize {
        self.char_pos
    }

    /// Serialize the location info to a simple key-value representation.
    ///
    /// In Ghidra this writes to a `SaveState` XML object.  Here we
    /// produce a flat vector of `(key, value)` pairs.
    pub fn save_state(&self) -> Vec<(String, String)> {
        let mut state = Vec::new();
        if let Some(ep) = &self.entry_point {
            state.push(("_FUNCTION_ENTRY".into(), format!("{}", ep)));
        }
        state.push(("_TOKEN_TEXT".into(), self.token_name.clone()));
        state.push(("_LINE_NUM".into(), self.line_number.to_string()));
        state.push(("_CHAR_POS".into(), self.char_pos.to_string()));
        state
    }

    /// Restore the location info from serialized key-value pairs.
    pub fn restore_state(&mut self, state: &[(String, String)]) {
        let get = |key: &str| -> Option<&str> {
            state
                .iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v.as_str())
        };
        if let Some(addr_str) = get("_FUNCTION_ENTRY") {
            // Parse as a hex address; fall back to 0.
            let addr = u64::from_str_radix(addr_str.trim_start_matches("0x"), 16)
                .unwrap_or(0);
            self.entry_point = Some(Address::new(addr));
        }
        self.token_name = get("_TOKEN_TEXT").unwrap_or("").to_string();
        self.line_number = get("_LINE_NUM").and_then(|s| s.parse().ok()).unwrap_or(0);
        self.char_pos = get("_CHAR_POS").and_then(|s| s.parse().ok()).unwrap_or(0);
    }
}

impl Default for DecompilerLocationInfo {
    fn default() -> Self {
        Self::empty()
    }
}

impl fmt::Display for DecompilerLocationInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DecompilerLocationInfo, line={}, character={}, token={}",
            self.line_number, self.char_pos, self.token_name
        )
    }
}

impl PartialEq for DecompilerLocationInfo {
    fn eq(&self, other: &Self) -> bool {
        self.entry_point == other.entry_point
            && self.token_name == other.token_name
            && self.line_number == other.line_number
            && self.char_pos == other.char_pos
    }
}

impl Eq for DecompilerLocationInfo {}

// ---------------------------------------------------------------------------
// DecompilerLocation -- trait for all decompiler locations
// ---------------------------------------------------------------------------

/// Trait implemented by all decompiler location types.
///
/// This corresponds to Ghidra's `DecompilerLocation` interface.
pub trait DecompilerLocation {
    /// The entry point of the function being viewed.
    fn get_function_entry_point(&self) -> Option<Address>;

    /// The decompile results, if available.
    fn get_decompile(&self) -> Option<&DecompileResults>;

    /// The token at the current cursor position, if available.
    fn get_token(&self) -> Option<&ClangToken>;

    /// The text of the token at the current cursor position.
    fn get_token_name(&self) -> &str;

    /// The line number (0-based).
    fn get_line_number(&self) -> usize;

    /// The character position within the line (0-based).
    fn get_char_pos(&self) -> usize;
}

// ---------------------------------------------------------------------------
// DefaultDecompilerLocation
// ---------------------------------------------------------------------------

/// The default location handed out when the user clicks on a generic
/// token inside the decompiler panel.
///
/// In Ghidra this is `DefaultDecompilerLocation`, which extends
/// `ProgramLocation`.  Here we model it as a standalone struct that
/// implements [`DecompilerLocation`].
#[derive(Debug, Clone)]
pub struct DefaultDecompilerLocation {
    /// The program address at this location.
    address: Address,
    /// The decompiler-specific location payload.
    info: DecompilerLocationInfo,
}

impl DefaultDecompilerLocation {
    /// Create a new default decompiler location.
    pub fn new(address: Address, info: DecompilerLocationInfo) -> Self {
        Self { address, info }
    }

    /// Create an empty location (for restoring from serialized state).
    pub fn empty() -> Self {
        Self {
            address: Address::new(0),
            info: DecompilerLocationInfo::empty(),
        }
    }

    /// The program address at this location.
    pub fn address(&self) -> Address {
        self.address
    }

    /// Serialize the location state.
    pub fn save_state(&self) -> Vec<(String, String)> {
        self.info.save_state()
    }

    /// Restore the location state.
    pub fn restore_state(&mut self, state: &[(String, String)]) {
        self.info.restore_state(state);
    }
}

impl DecompilerLocation for DefaultDecompilerLocation {
    fn get_function_entry_point(&self) -> Option<Address> {
        self.info.get_function_entry_point()
    }

    fn get_decompile(&self) -> Option<&DecompileResults> {
        self.info.get_decompile()
    }

    fn get_token(&self) -> Option<&ClangToken> {
        self.info.get_token()
    }

    fn get_token_name(&self) -> &str {
        self.info.get_token_name()
    }

    fn get_line_number(&self) -> usize {
        self.info.get_line_number()
    }

    fn get_char_pos(&self) -> usize {
        self.info.get_char_pos()
    }
}

impl PartialEq for DefaultDecompilerLocation {
    fn eq(&self, other: &Self) -> bool {
        self.address == other.address && self.info == other.info
    }
}

impl Eq for DefaultDecompilerLocation {}

// ---------------------------------------------------------------------------
// FunctionNameDecompilerLocation
// ---------------------------------------------------------------------------

/// A location created when a function name is clicked in the Decompiler.
///
/// In Ghidra this is `FunctionNameDecompilerLocation`, which extends
/// `FunctionNameFieldLocation`.  Here we carry the function name as an
/// additional field alongside the standard location info.
#[derive(Debug, Clone)]
pub struct FunctionNameDecompilerLocation {
    /// The program address at this location.
    address: Address,
    /// The name of the function that was clicked.
    function_name: String,
    /// The decompiler-specific location payload.
    info: DecompilerLocationInfo,
}

impl FunctionNameDecompilerLocation {
    /// Create a new function name location.
    pub fn new(
        address: Address,
        function_name: impl Into<String>,
        info: DecompilerLocationInfo,
    ) -> Self {
        Self {
            address,
            function_name: function_name.into(),
            info,
        }
    }

    /// Create an empty location (for restoring from serialized state).
    pub fn empty() -> Self {
        Self {
            address: Address::new(0),
            function_name: String::new(),
            info: DecompilerLocationInfo::empty(),
        }
    }

    /// The program address at this location.
    pub fn address(&self) -> Address {
        self.address
    }

    /// The name of the function that was clicked.
    pub fn function_name(&self) -> &str {
        &self.function_name
    }

    /// Serialize the location state.
    pub fn save_state(&self) -> Vec<(String, String)> {
        self.info.save_state()
    }

    /// Restore the location state.
    pub fn restore_state(&mut self, state: &[(String, String)]) {
        self.info.restore_state(state);
    }
}

impl DecompilerLocation for FunctionNameDecompilerLocation {
    fn get_function_entry_point(&self) -> Option<Address> {
        self.info.get_function_entry_point()
    }

    fn get_decompile(&self) -> Option<&DecompileResults> {
        self.info.get_decompile()
    }

    fn get_token(&self) -> Option<&ClangToken> {
        self.info.get_token()
    }

    fn get_token_name(&self) -> &str {
        self.info.get_token_name()
    }

    fn get_line_number(&self) -> usize {
        self.info.get_line_number()
    }

    fn get_char_pos(&self) -> usize {
        self.info.get_char_pos()
    }
}

impl PartialEq for FunctionNameDecompilerLocation {
    fn eq(&self, other: &Self) -> bool {
        self.address == other.address
            && self.function_name == other.function_name
            && self.info == other.info
    }
}

impl Eq for FunctionNameDecompilerLocation {}

// ---------------------------------------------------------------------------
// VariableDecompilerLocation
// ---------------------------------------------------------------------------

/// A location created when a function variable is clicked in the Decompiler.
///
/// In Ghidra this is `VariableDecompilerLocation`, which extends
/// `VariableLocFieldLocation`.  Here we carry the variable name and
/// category (local vs. parameter) alongside the standard location info.
#[derive(Debug, Clone)]
pub struct VariableDecompilerLocation {
    /// The program address at this location.
    address: Address,
    /// The name of the variable that was clicked.
    variable_name: String,
    /// Whether the variable is a parameter (true) or local (false).
    is_parameter: bool,
    /// Ordinal index of the variable (parameter index or local index).
    ordinal: usize,
    /// The decompiler-specific location payload.
    info: DecompilerLocationInfo,
}

impl VariableDecompilerLocation {
    /// Create a new variable location.
    pub fn new(
        address: Address,
        variable_name: impl Into<String>,
        is_parameter: bool,
        ordinal: usize,
        info: DecompilerLocationInfo,
    ) -> Self {
        Self {
            address,
            variable_name: variable_name.into(),
            is_parameter,
            ordinal,
            info,
        }
    }

    /// Create an empty location (for restoring from serialized state).
    pub fn empty() -> Self {
        Self {
            address: Address::new(0),
            variable_name: String::new(),
            is_parameter: false,
            ordinal: 0,
            info: DecompilerLocationInfo::empty(),
        }
    }

    /// The program address at this location.
    pub fn address(&self) -> Address {
        self.address
    }

    /// The name of the variable that was clicked.
    pub fn variable_name(&self) -> &str {
        &self.variable_name
    }

    /// Whether the variable is a parameter.
    pub fn is_parameter(&self) -> bool {
        self.is_parameter
    }

    /// The ordinal index of the variable.
    pub fn ordinal(&self) -> usize {
        self.ordinal
    }

    /// Serialize the location state.
    pub fn save_state(&self) -> Vec<(String, String)> {
        self.info.save_state()
    }

    /// Restore the location state.
    pub fn restore_state(&mut self, state: &[(String, String)]) {
        self.info.restore_state(state);
    }
}

impl DecompilerLocation for VariableDecompilerLocation {
    fn get_function_entry_point(&self) -> Option<Address> {
        self.info.get_function_entry_point()
    }

    fn get_decompile(&self) -> Option<&DecompileResults> {
        self.info.get_decompile()
    }

    fn get_token(&self) -> Option<&ClangToken> {
        self.info.get_token()
    }

    fn get_token_name(&self) -> &str {
        self.info.get_token_name()
    }

    fn get_line_number(&self) -> usize {
        self.info.get_line_number()
    }

    fn get_char_pos(&self) -> usize {
        self.info.get_char_pos()
    }
}

impl PartialEq for VariableDecompilerLocation {
    fn eq(&self, other: &Self) -> bool {
        self.address == other.address
            && self.variable_name == other.variable_name
            && self.is_parameter == other.is_parameter
            && self.ordinal == other.ordinal
            && self.info == other.info
    }
}

impl Eq for VariableDecompilerLocation {}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- ClangToken ---

    #[test]
    fn test_clang_token_new() {
        let tok = ClangToken::new("int", ClangSyntaxType::TypeName, None, 5, 10);
        assert_eq!(tok.text(), "int");
        assert_eq!(tok.syntax_type(), ClangSyntaxType::TypeName);
        assert!(tok.address().is_none());
        assert_eq!(tok.line_number(), 5);
        assert_eq!(tok.char_offset(), 10);
    }

    #[test]
    fn test_clang_token_with_address() {
        let addr = Address::new(0x1000);
        let tok = ClangToken::new("main", ClangSyntaxType::FunctionName, Some(addr), 0, 0);
        assert_eq!(tok.address(), Some(addr));
    }

    #[test]
    fn test_clang_token_display() {
        let tok = ClangToken::new("hello", ClangSyntaxType::StringLiteral, None, 0, 0);
        assert_eq!(format!("{}", tok), "hello");
    }

    #[test]
    fn test_clang_token_build_spacer() {
        let spacer = ClangToken::build_spacer(4, "  ");
        assert_eq!(spacer.text(), "        ");
        assert_eq!(spacer.syntax_type(), ClangSyntaxType::Other);
    }

    #[test]
    fn test_clang_syntax_type_is_transformable() {
        assert!(ClangSyntaxType::FunctionName.is_transformable());
        assert!(ClangSyntaxType::Variable.is_transformable());
        assert!(ClangSyntaxType::TypeName.is_transformable());
        assert!(ClangSyntaxType::FieldName.is_transformable());
        assert!(ClangSyntaxType::Label.is_transformable());
        assert!(!ClangSyntaxType::Keyword.is_transformable());
        assert!(!ClangSyntaxType::Constant.is_transformable());
        assert!(!ClangSyntaxType::Comment.is_transformable());
        assert!(!ClangSyntaxType::Operator.is_transformable());
        assert!(!ClangSyntaxType::Punctuation.is_transformable());
    }

    // --- DecompilerLocationInfo ---

    #[test]
    fn test_location_info_new() {
        let addr = Address::new(0x4000);
        let tok = ClangToken::new("x", ClangSyntaxType::Variable, None, 3, 7);
        let info = DecompilerLocationInfo::new(addr, None, Some(tok), 3, 7);
        assert_eq!(info.get_function_entry_point(), Some(addr));
        assert_eq!(info.get_token_name(), "x");
        assert_eq!(info.get_line_number(), 3);
        assert_eq!(info.get_char_pos(), 7);
    }

    #[test]
    fn test_location_info_empty() {
        let info = DecompilerLocationInfo::empty();
        assert!(info.get_function_entry_point().is_none());
        assert!(info.get_decompile().is_none());
        assert!(info.get_token().is_none());
        assert_eq!(info.get_token_name(), "");
        assert_eq!(info.get_line_number(), 0);
        assert_eq!(info.get_char_pos(), 0);
    }

    #[test]
    fn test_location_info_save_restore() {
        let addr = Address::new(0xDEAD);
        let tok = ClangToken::new("foo", ClangSyntaxType::FunctionName, None, 1, 5);
        let info = DecompilerLocationInfo::new(addr, None, Some(tok), 1, 5);

        let state = info.save_state();
        let mut restored = DecompilerLocationInfo::empty();
        restored.restore_state(&state);

        assert_eq!(restored.get_function_entry_point(), Some(addr));
        assert_eq!(restored.get_token_name(), "foo");
        assert_eq!(restored.get_line_number(), 1);
        assert_eq!(restored.get_char_pos(), 5);
    }

    #[test]
    fn test_location_info_display() {
        let info = DecompilerLocationInfo::new(Address::new(0), None, None, 10, 20);
        let s = format!("{}", info);
        assert!(s.contains("line=10"));
        assert!(s.contains("character=20"));
    }

    #[test]
    fn test_location_info_equality() {
        let a = DecompilerLocationInfo::new(Address::new(0x100), None, None, 1, 2);
        let b = DecompilerLocationInfo::new(Address::new(0x100), None, None, 1, 2);
        assert_eq!(a, b);
    }

    // --- DefaultDecompilerLocation ---

    #[test]
    fn test_default_location() {
        let addr = Address::new(0x1000);
        let info = DecompilerLocationInfo::new(addr, None, None, 0, 0);
        let loc = DefaultDecompilerLocation::new(addr, info);
        assert_eq!(loc.address(), addr);
        assert_eq!(loc.get_function_entry_point(), Some(addr));
    }

    #[test]
    fn test_default_location_equality() {
        let addr = Address::new(0x1000);
        let info1 = DecompilerLocationInfo::new(addr, None, None, 0, 0);
        let info2 = DecompilerLocationInfo::new(addr, None, None, 0, 0);
        let a = DefaultDecompilerLocation::new(addr, info1);
        let b = DefaultDecompilerLocation::new(addr, info2);
        assert_eq!(a, b);
    }

    // --- FunctionNameDecompilerLocation ---

    #[test]
    fn test_function_name_location() {
        let addr = Address::new(0x2000);
        let info = DecompilerLocationInfo::new(addr, None, None, 0, 0);
        let loc = FunctionNameDecompilerLocation::new(addr, "main", info);
        assert_eq!(loc.address(), addr);
        assert_eq!(loc.function_name(), "main");
        assert_eq!(loc.get_function_entry_point(), Some(addr));
    }

    #[test]
    fn test_function_name_location_empty() {
        let loc = FunctionNameDecompilerLocation::empty();
        assert!(loc.function_name().is_empty());
        assert!(loc.get_function_entry_point().is_none());
    }

    // --- VariableDecompilerLocation ---

    #[test]
    fn test_variable_location() {
        let addr = Address::new(0x3000);
        let info = DecompilerLocationInfo::new(addr, None, None, 2, 4);
        let loc = VariableDecompilerLocation::new(addr, "argc", true, 0, info);
        assert_eq!(loc.address(), addr);
        assert_eq!(loc.variable_name(), "argc");
        assert!(loc.is_parameter());
        assert_eq!(loc.ordinal(), 0);
        assert_eq!(loc.get_line_number(), 2);
    }

    #[test]
    fn test_variable_location_local() {
        let addr = Address::new(0x4000);
        let info = DecompilerLocationInfo::new(addr, None, None, 5, 10);
        let loc = VariableDecompilerLocation::new(addr, "buf", false, 3, info);
        assert!(!loc.is_parameter());
        assert_eq!(loc.ordinal(), 3);
    }

    #[test]
    fn test_variable_location_empty() {
        let loc = VariableDecompilerLocation::empty();
        assert!(loc.variable_name().is_empty());
        assert!(!loc.is_parameter());
        assert_eq!(loc.ordinal(), 0);
    }

    // --- Trait dispatch ---

    #[test]
    fn test_trait_dispatch_default() {
        let addr = Address::new(0x5000);
        let info = DecompilerLocationInfo::new(addr, None, None, 1, 2);
        let loc = DefaultDecompilerLocation::new(addr, info);
        let dyn_loc: &dyn DecompilerLocation = &loc;
        assert_eq!(dyn_loc.get_line_number(), 1);
        assert_eq!(dyn_loc.get_char_pos(), 2);
    }

    #[test]
    fn test_trait_dispatch_function_name() {
        let addr = Address::new(0x6000);
        let info = DecompilerLocationInfo::new(addr, None, None, 0, 0);
        let loc = FunctionNameDecompilerLocation::new(addr, "foo", info);
        let dyn_loc: &dyn DecompilerLocation = &loc;
        assert_eq!(dyn_loc.get_function_entry_point(), Some(addr));
    }

    #[test]
    fn test_trait_dispatch_variable() {
        let addr = Address::new(0x7000);
        let info = DecompilerLocationInfo::new(addr, None, None, 3, 8);
        let loc = VariableDecompilerLocation::new(addr, "x", true, 1, info);
        let dyn_loc: &dyn DecompilerLocation = &loc;
        assert_eq!(dyn_loc.get_line_number(), 3);
        assert_eq!(dyn_loc.get_char_pos(), 8);
    }
}
