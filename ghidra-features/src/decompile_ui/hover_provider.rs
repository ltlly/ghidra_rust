//! Decompiler Hover Provider -- Rust port of
//! `ghidra.app.decompiler.component.DecompilerHoverProvider`.
//!
//! In Ghidra, `DecompilerHoverProvider` extends `AbstractHoverProvider` and
//! resolves hover locations over decompiler tokens.  When the user hovers
//! over a token in the decompiler panel, this provider determines the
//! `ProgramLocation` that should be passed to registered hover services.
//!
//! The provider handles several token types:
//!
//! - **`ClangOpToken`** -- operator tokens are ignored (no hover).
//! - **`ClangTypeToken`** -- resolves to the address of the high variable's
//!   representative varnode.
//! - **Other tokens** -- resolves to the token's minimum address, with an
//!   optional reference address for global variables or loaded memory.
//!
//! # Architecture
//!
//! ```text
//! DecompilerHoverProvider
//!   ├── name: String
//!   ├── enabled: bool
//!   ├── services: Vec<HoverServiceRegistration>
//!   │     ├── { service, priority, enabled }
//!   │     └── ...
//!   └── last_hover_location: Option<HoverLocation>
//!
//! HoverLocation
//!   ├── program_address: u64
//!   ├── reference_address: Option<u64>
//!   ├── token_text: String
//!   ├── token_kind: TokenKind
//!   └── line_index: usize
//! ```

use std::fmt;

// ---------------------------------------------------------------------------
// TokenKind -- the kind of decompiler token being hovered
// ---------------------------------------------------------------------------

/// The kind of clang token in the decompiler output.
///
/// This maps to the various `ClangToken` subclasses in Ghidra.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TokenKind {
    /// A syntax/operator token (e.g., `+`, `=`, `(`, `)`).
    OpToken,
    /// A type name token (e.g., `int`, `char*`).
    TypeToken,
    /// A variable token (local, global, parameter).
    VariableToken,
    /// A function name token.
    FuncNameToken,
    /// A field name token (struct/union member access).
    FieldToken,
    /// A label token (goto target).
    LabelToken,
    /// A comment token.
    CommentToken,
    /// A keyword token (e.g., `if`, `return`, `while`).
    SyntaxToken,
    /// A constant/literal token.
    ConstantToken,
    /// A break/separator token.
    BreakToken,
}

impl Default for TokenKind {
    fn default() -> Self {
        Self::SyntaxToken
    }
}

impl fmt::Display for TokenKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OpToken => write!(f, "OpToken"),
            Self::TypeToken => write!(f, "TypeToken"),
            Self::VariableToken => write!(f, "VariableToken"),
            Self::FuncNameToken => write!(f, "FuncNameToken"),
            Self::FieldToken => write!(f, "FieldToken"),
            Self::LabelToken => write!(f, "LabelToken"),
            Self::CommentToken => write!(f, "CommentToken"),
            Self::SyntaxToken => write!(f, "SyntaxToken"),
            Self::ConstantToken => write!(f, "ConstantToken"),
            Self::BreakToken => write!(f, "BreakToken"),
        }
    }
}

// ---------------------------------------------------------------------------
// HighVariableInfo -- information about a high-level variable
// ---------------------------------------------------------------------------

/// Information about a decompiler high variable.
///
/// This corresponds to `HighVariable` in the Ghidra pcode model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HighVariableInfo {
    /// The name of the variable.
    pub name: String,
    /// The address of the representative varnode.
    pub representative_address: u64,
    /// Whether this is a global variable.
    pub is_global: bool,
    /// The data type name (e.g., "int", "char *").
    pub data_type_name: Option<String>,
    /// The size of the variable in bytes.
    pub size: usize,
}

impl HighVariableInfo {
    /// Create a new high variable info.
    pub fn new(name: impl Into<String>, representative_address: u64) -> Self {
        Self {
            name: name.into(),
            representative_address,
            is_global: false,
            data_type_name: None,
            size: 0,
        }
    }

    /// Set whether this is a global variable.
    pub fn global(mut self, yes: bool) -> Self {
        self.is_global = yes;
        self
    }

    /// Set the data type name.
    pub fn data_type(mut self, name: impl Into<String>) -> Self {
        self.data_type_name = Some(name.into());
        self
    }

    /// Set the variable size.
    pub fn size(mut self, size: usize) -> Self {
        self.size = size;
        self
    }
}

// ---------------------------------------------------------------------------
// VarnodeInfo -- information about a varnode
// ---------------------------------------------------------------------------

/// Information about a decompiler varnode.
///
/// This corresponds to `Varnode` in the Ghidra pcode model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VarnodeInfo {
    /// The address of the varnode.
    pub address: u64,
    /// The size of the varnode in bytes.
    pub size: usize,
    /// Whether the address is in loaded memory.
    pub is_loaded_memory: bool,
    /// The high variable this varnode belongs to (if any).
    pub high_variable: Option<HighVariableInfo>,
}

impl VarnodeInfo {
    /// Create a new varnode info.
    pub fn new(address: u64, size: usize) -> Self {
        Self {
            address,
            size,
            is_loaded_memory: false,
            high_variable: None,
        }
    }

    /// Set whether the address is in loaded memory.
    pub fn loaded_memory(mut self, yes: bool) -> Self {
        self.is_loaded_memory = yes;
        self
    }

    /// Set the high variable.
    pub fn high_variable(mut self, hv: HighVariableInfo) -> Self {
        self.high_variable = Some(hv);
        self
    }
}

// ---------------------------------------------------------------------------
// HoverToken -- a token that can be hovered
// ---------------------------------------------------------------------------

/// A decompiler token with hover-relevant information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HoverToken {
    /// The kind of token.
    pub kind: TokenKind,
    /// The text of the token.
    pub text: String,
    /// The minimum address of the token (if any).
    pub min_address: Option<u64>,
    /// The maximum address of the token (if any).
    pub max_address: Option<u64>,
    /// The varnode associated with this token (if any).
    pub varnode: Option<VarnodeInfo>,
    /// The line index in the decompiler output.
    pub line_index: usize,
    /// The column offset within the line.
    pub column_offset: usize,
}

impl HoverToken {
    /// Create a new hover token.
    pub fn new(kind: TokenKind, text: impl Into<String>) -> Self {
        Self {
            kind,
            text: text.into(),
            min_address: None,
            max_address: None,
            varnode: None,
            line_index: 0,
            column_offset: 0,
        }
    }

    /// Set the address range.
    pub fn address(mut self, min: u64, max: u64) -> Self {
        self.min_address = Some(min);
        self.max_address = Some(max);
        self
    }

    /// Set just the minimum address.
    pub fn min_address(mut self, addr: u64) -> Self {
        self.min_address = Some(addr);
        self
    }

    /// Set the varnode.
    pub fn varnode(mut self, vn: VarnodeInfo) -> Self {
        self.varnode = Some(vn);
        self
    }

    /// Set the line and column.
    pub fn position(mut self, line: usize, col: usize) -> Self {
        self.line_index = line;
        self.column_offset = col;
        self
    }
}

// ---------------------------------------------------------------------------
// HoverLocation -- the resolved hover location
// ---------------------------------------------------------------------------

/// The resolved location for a hover event in the decompiler.
///
/// This corresponds to the `ProgramLocation` that the hover provider
/// creates from the token under the cursor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HoverLocation {
    /// The program address for the hover.
    pub program_address: u64,
    /// An optional reference address (for global variables, etc.).
    pub reference_address: Option<u64>,
    /// The text of the token being hovered.
    pub token_text: String,
    /// The kind of token being hovered.
    pub token_kind: TokenKind,
    /// The line index in the decompiler output.
    pub line_index: usize,
    /// The function name (if the hover is within a function).
    pub function_name: Option<String>,
}

impl HoverLocation {
    /// Create a new hover location.
    pub fn new(program_address: u64, token: &HoverToken) -> Self {
        Self {
            program_address,
            reference_address: None,
            token_text: token.text.clone(),
            token_kind: token.kind,
            line_index: token.line_index,
            function_name: None,
        }
    }

    /// Set the reference address.
    pub fn reference_address(mut self, addr: u64) -> Self {
        self.reference_address = Some(addr);
        self
    }

    /// Set the function name.
    pub fn function_name(mut self, name: impl Into<String>) -> Self {
        self.function_name = Some(name.into());
        self
    }
}

// ---------------------------------------------------------------------------
// HoverServiceRegistration -- a registered hover service
// ---------------------------------------------------------------------------

/// A registered hover service in the decompiler hover provider.
#[derive(Debug, Clone)]
pub struct HoverServiceRegistration {
    /// A unique identifier for this registration.
    pub id: String,
    /// The display name of the hover service.
    pub name: String,
    /// The priority (lower values are evaluated first).
    pub priority: i32,
    /// Whether this service is currently enabled.
    pub enabled: bool,
}

impl HoverServiceRegistration {
    /// Create a new registration.
    pub fn new(id: impl Into<String>, name: impl Into<String>, priority: i32) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            priority,
            enabled: true,
        }
    }
}

// ---------------------------------------------------------------------------
// DecompilerHoverProvider -- the main hover provider
// ---------------------------------------------------------------------------

/// The Decompiler Hover Provider.
///
/// This models `DecompilerHoverProvider` from Ghidra, which extends
/// `AbstractHoverProvider` and resolves hover locations over decompiler
/// clang tokens.  When the user moves the mouse over a token in the
/// decompiler panel, this provider examines the token and produces a
/// `HoverLocation` that can be passed to registered hover services.
///
/// In Ghidra:
/// ```java
/// public class DecompilerHoverProvider extends AbstractHoverProvider {
///     protected ProgramLocation getHoverLocation(
///             FieldLocation fieldLocation, Field field,
///             Rectangle fieldBounds, MouseEvent event) {
///         // resolve token -> ProgramLocation
///     }
/// }
/// ```
#[derive(Debug)]
pub struct DecompilerHoverProvider {
    /// The provider name.
    name: String,
    /// Whether the provider is enabled.
    enabled: bool,
    /// Registered hover services.
    services: Vec<HoverServiceRegistration>,
    /// The last computed hover location.
    last_hover_location: Option<HoverLocation>,
    /// The current program address range (for validating addresses).
    program_memory_range: Option<(u64, u64)>,
}

impl DecompilerHoverProvider {
    /// Create a new hover provider.
    pub fn new() -> Self {
        Self {
            name: "DecompilerHoverProvider".to_string(),
            enabled: true,
            services: Vec::new(),
            last_hover_location: None,
            program_memory_range: None,
        }
    }

    // -- Service management --

    /// Add a hover service.
    ///
    /// In Ghidra: `addHoverService(DecompilerHoverService)`.
    pub fn add_hover_service(&mut self, registration: HoverServiceRegistration) {
        self.services.push(registration);
        self.services.sort_by_key(|s| s.priority);
    }

    /// Remove a hover service by id.
    ///
    /// In Ghidra: `removeHoverService(DecompilerHoverService)`.
    pub fn remove_hover_service(&mut self, id: &str) -> bool {
        let len_before = self.services.len();
        self.services.retain(|s| s.id != id);
        self.services.len() < len_before
    }

    /// Get the registered hover services.
    pub fn services(&self) -> &[HoverServiceRegistration] {
        &self.services
    }

    /// Get the number of registered services.
    pub fn service_count(&self) -> usize {
        self.services.len()
    }

    // -- Provider state --

    /// Get the provider name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Whether the provider is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Enable or disable the provider.
    pub fn set_enabled(&mut self, yes: bool) {
        self.enabled = yes;
    }

    /// Set the program memory range for address validation.
    pub fn set_program_memory_range(&mut self, start: u64, end: u64) {
        self.program_memory_range = Some((start, end));
    }

    // -- Hover resolution --

    /// Resolve a hover location from a token.
    ///
    /// This is the core method corresponding to `getHoverLocation()` in
    /// Ghidra.  It examines the token kind and produces a `HoverLocation`.
    ///
    /// Returns `None` if:
    /// - The provider is disabled.
    /// - The token is an `OpToken` (operators don't have hover).
    /// - The token has no address and no usable varnode.
    pub fn get_hover_location(&mut self, token: &HoverToken) -> Option<HoverLocation> {
        if !self.enabled {
            return None;
        }

        // OpTokens are ignored.
        if token.kind == TokenKind::OpToken {
            return None;
        }

        // TypeToken: resolve via high variable's representative address.
        if token.kind == TokenKind::TypeToken {
            if let Some(ref vn) = token.varnode {
                if let Some(ref hv) = vn.high_variable {
                    let mut loc = HoverLocation::new(hv.representative_address, token);
                    loc.reference_address = Some(hv.representative_address);
                    self.last_hover_location = Some(loc.clone());
                    return Some(loc);
                }
            }
            return None;
        }

        // Other tokens: use the token's minimum address.
        let min_addr = token.min_address?;
        if min_addr == 0 {
            return None;
        }

        // Validate the address is within program memory range.
        if let Some((start, end)) = self.program_memory_range {
            if min_addr < start || min_addr > end {
                return None;
            }
        }

        let mut loc = HoverLocation::new(min_addr, token);

        // Determine reference address from varnode.
        if let Some(ref vn) = token.varnode {
            if let Some(ref hv) = vn.high_variable {
                if hv.is_global {
                    // HighGlobal: reference is the representative address.
                    loc.reference_address = Some(hv.representative_address);
                }
            } else if vn.is_loaded_memory {
                // No high variable but loaded memory: reference is the
                // varnode's address.
                loc.reference_address = Some(vn.address);
            }
        }

        self.last_hover_location = Some(loc.clone());
        Some(loc)
    }

    /// Get the last computed hover location.
    pub fn last_hover_location(&self) -> Option<&HoverLocation> {
        self.last_hover_location.as_ref()
    }

    /// Clear the last hover location.
    pub fn clear_hover(&mut self) {
        self.last_hover_location = None;
    }
}

impl Default for DecompilerHoverProvider {
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

    fn make_type_token_with_high_var() -> HoverToken {
        let hv = HighVariableInfo::new("myVar", 0x4000)
            .data_type("int")
            .size(4);
        let vn = VarnodeInfo::new(0x4000, 4)
            .loaded_memory(true)
            .high_variable(hv);
        HoverToken::new(TokenKind::TypeToken, "int")
            .varnode(vn)
            .position(5, 10)
    }

    fn make_variable_token_global() -> HoverToken {
        let hv = HighVariableInfo::new("globalVar", 0x8000)
            .global(true)
            .data_type("char *");
        let vn = VarnodeInfo::new(0x8000, 8)
            .loaded_memory(true)
            .high_variable(hv);
        HoverToken::new(TokenKind::VariableToken, "globalVar")
            .address(0x8000, 0x8008)
            .varnode(vn)
            .position(3, 0)
    }

    fn make_simple_token(kind: TokenKind, text: &str, addr: u64) -> HoverToken {
        HoverToken::new(kind, text)
            .min_address(addr)
            .position(1, 5)
    }

    #[test]
    fn test_hover_provider_creation() {
        let provider = DecompilerHoverProvider::new();
        assert_eq!(provider.name(), "DecompilerHoverProvider");
        assert!(provider.is_enabled());
        assert_eq!(provider.service_count(), 0);
        assert!(provider.last_hover_location().is_none());
    }

    #[test]
    fn test_hover_provider_service_management() {
        let mut provider = DecompilerHoverProvider::new();

        provider.add_hover_service(HoverServiceRegistration::new(
            "svc1", "DataType Hover", 10,
        ));
        provider.add_hover_service(HoverServiceRegistration::new(
            "svc2", "Function Signature Hover", 5,
        ));
        provider.add_hover_service(HoverServiceRegistration::new(
            "svc3", "Reference Hover", 20,
        ));

        // Should be sorted by priority.
        assert_eq!(provider.service_count(), 3);
        assert_eq!(provider.services()[0].name, "Function Signature Hover");
        assert_eq!(provider.services()[1].name, "DataType Hover");
        assert_eq!(provider.services()[2].name, "Reference Hover");

        assert!(provider.remove_hover_service("svc1"));
        assert_eq!(provider.service_count(), 2);
        assert!(!provider.remove_hover_service("nonexistent"));
    }

    #[test]
    fn test_hover_provider_disabled() {
        let mut provider = DecompilerHoverProvider::new();
        provider.set_enabled(false);

        let token = make_simple_token(TokenKind::VariableToken, "x", 0x1000);
        assert!(provider.get_hover_location(&token).is_none());
    }

    #[test]
    fn test_hover_op_token_ignored() {
        let mut provider = DecompilerHoverProvider::new();

        let token = make_simple_token(TokenKind::OpToken, "+", 0x1000);
        assert!(provider.get_hover_location(&token).is_none());
    }

    #[test]
    fn test_hover_type_token_resolves_to_high_variable() {
        let mut provider = DecompilerHoverProvider::new();

        let token = make_type_token_with_high_var();
        let loc = provider.get_hover_location(&token).unwrap();

        assert_eq!(loc.program_address, 0x4000);
        assert_eq!(loc.reference_address, Some(0x4000));
        assert_eq!(loc.token_text, "int");
        assert_eq!(loc.token_kind, TokenKind::TypeToken);
        assert_eq!(loc.line_index, 5);
    }

    #[test]
    fn test_hover_type_token_without_high_variable_returns_none() {
        let mut provider = DecompilerHoverProvider::new();

        // TypeToken without a varnode.
        let token = HoverToken::new(TokenKind::TypeToken, "void");
        assert!(provider.get_hover_location(&token).is_none());

        // TypeToken with varnode but no high variable.
        let vn = VarnodeInfo::new(0x4000, 4);
        let token = HoverToken::new(TokenKind::TypeToken, "void").varnode(vn);
        assert!(provider.get_hover_location(&token).is_none());
    }

    #[test]
    fn test_hover_variable_token_global() {
        let mut provider = DecompilerHoverProvider::new();

        let token = make_variable_token_global();
        let loc = provider.get_hover_location(&token).unwrap();

        assert_eq!(loc.program_address, 0x8000);
        // Global: reference is the representative address.
        assert_eq!(loc.reference_address, Some(0x8000));
        assert_eq!(loc.token_text, "globalVar");
        assert_eq!(loc.token_kind, TokenKind::VariableToken);
    }

    #[test]
    fn test_hover_variable_token_loaded_memory_no_high() {
        let mut provider = DecompilerHoverProvider::new();

        let vn = VarnodeInfo::new(0x5000, 4).loaded_memory(true);
        let token = HoverToken::new(TokenKind::VariableToken, "local_8")
            .address(0x5000, 0x5004)
            .varnode(vn)
            .position(2, 0);

        let loc = provider.get_hover_location(&token).unwrap();
        assert_eq!(loc.program_address, 0x5000);
        // No high variable but loaded memory: reference is varnode address.
        assert_eq!(loc.reference_address, Some(0x5000));
    }

    #[test]
    fn test_hover_token_no_address_returns_none() {
        let mut provider = DecompilerHoverProvider::new();

        let token = HoverToken::new(TokenKind::VariableToken, "local_4");
        assert!(provider.get_hover_location(&token).is_none());
    }

    #[test]
    fn test_hover_token_address_out_of_range() {
        let mut provider = DecompilerHoverProvider::new();
        provider.set_program_memory_range(0x1000, 0x5000);

        let token = make_simple_token(TokenKind::VariableToken, "x", 0x9000);
        assert!(provider.get_hover_location(&token).is_none());
    }

    #[test]
    fn test_hover_token_address_in_range() {
        let mut provider = DecompilerHoverProvider::new();
        provider.set_program_memory_range(0x1000, 0x5000);

        let token = make_simple_token(TokenKind::VariableToken, "x", 0x3000);
        let loc = provider.get_hover_location(&token).unwrap();
        assert_eq!(loc.program_address, 0x3000);
    }

    #[test]
    fn test_hover_func_name_token() {
        let mut provider = DecompilerHoverProvider::new();

        let token = make_simple_token(TokenKind::FuncNameToken, "printf", 0x2000);
        let loc = provider.get_hover_location(&token).unwrap();
        assert_eq!(loc.program_address, 0x2000);
        assert_eq!(loc.token_text, "printf");
    }

    #[test]
    fn test_hover_field_token() {
        let mut provider = DecompilerHoverProvider::new();

        let token = make_simple_token(TokenKind::FieldToken, "offset", 0x3000);
        let loc = provider.get_hover_location(&token).unwrap();
        assert_eq!(loc.program_address, 0x3000);
        assert_eq!(loc.token_kind, TokenKind::FieldToken);
    }

    #[test]
    fn test_hover_last_location_tracked() {
        let mut provider = DecompilerHoverProvider::new();
        assert!(provider.last_hover_location().is_none());

        let token = make_simple_token(TokenKind::SyntaxToken, "return", 0x1000);
        provider.get_hover_location(&token);

        assert!(provider.last_hover_location().is_some());
        assert_eq!(provider.last_hover_location().unwrap().program_address, 0x1000);

        provider.clear_hover();
        assert!(provider.last_hover_location().is_none());
    }

    #[test]
    fn test_hover_label_token() {
        let mut provider = DecompilerHoverProvider::new();
        let token = make_simple_token(TokenKind::LabelToken, "LAB_00401000", 0x401000);
        let loc = provider.get_hover_location(&token).unwrap();
        assert_eq!(loc.token_kind, TokenKind::LabelToken);
        assert_eq!(loc.program_address, 0x401000);
    }

    #[test]
    fn test_token_kind_display() {
        assert_eq!(TokenKind::OpToken.to_string(), "OpToken");
        assert_eq!(TokenKind::TypeToken.to_string(), "TypeToken");
        assert_eq!(TokenKind::VariableToken.to_string(), "VariableToken");
        assert_eq!(TokenKind::FuncNameToken.to_string(), "FuncNameToken");
        assert_eq!(TokenKind::FieldToken.to_string(), "FieldToken");
        assert_eq!(TokenKind::LabelToken.to_string(), "LabelToken");
        assert_eq!(TokenKind::CommentToken.to_string(), "CommentToken");
        assert_eq!(TokenKind::SyntaxToken.to_string(), "SyntaxToken");
        assert_eq!(TokenKind::ConstantToken.to_string(), "ConstantToken");
        assert_eq!(TokenKind::BreakToken.to_string(), "BreakToken");
    }

    #[test]
    fn test_high_variable_info_builder() {
        let hv = HighVariableInfo::new("test", 0x1000)
            .global(true)
            .data_type("uint32_t")
            .size(4);
        assert_eq!(hv.name, "test");
        assert_eq!(hv.representative_address, 0x1000);
        assert!(hv.is_global);
        assert_eq!(hv.data_type_name.as_deref(), Some("uint32_t"));
        assert_eq!(hv.size, 4);
    }

    #[test]
    fn test_varnode_info_builder() {
        let vn = VarnodeInfo::new(0x2000, 8)
            .loaded_memory(true);
        assert_eq!(vn.address, 0x2000);
        assert_eq!(vn.size, 8);
        assert!(vn.is_loaded_memory);
        assert!(vn.high_variable.is_none());
    }

    #[test]
    fn test_hover_location_function_name() {
        let token = make_simple_token(TokenKind::VariableToken, "x", 0x1000);
        let loc = HoverLocation::new(0x1000, &token)
            .function_name("main");
        assert_eq!(loc.function_name.as_deref(), Some("main"));
    }
}
