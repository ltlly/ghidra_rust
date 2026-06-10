//! S_UNAMESPACE -- Using namespace symbol.
//!
//! Ports Ghidra's `ghidra.app.util.bin.format.pdb2.pdbreader.symbol.UsingNamespaceMsSymbol`
//! and the older `UsingNamespaceStMsSymbol`.
//!
//! # V2 Format (0x1124 -- UsingNamespaceMsSymbol)
//!
//! ```text
//! name : UTF-8 NT string
//! ```
//!
//! # St Format (0x1029 -- UsingNamespaceStMsSymbol)
//!
//! ```text
//! name : ST-style string (may include length prefix)
//! ```

use std::fmt;

use super::abstract_ms_symbol::AbstractMsSymbol;
use super::name_ms_symbol::NameMsSymbol;

/// A using-namespace symbol (`S_UNAMESPACE`).
///
/// This symbol records the presence of a C++ `using namespace` directive in the
/// compiled source code. It carries the fully-qualified name of the namespace
/// that was imported. Debuggers and analysis tools use this to resolve
/// unqualified name lookups when evaluating expressions in the context of a
/// particular scope.
///
/// This struct handles both the V2 (0x1124) and St (0x1029) formats. Both
/// formats carry the same logical data; only the string encoding differs.
///
/// # PDB Binary Layout
///
/// ```text
/// name : NT string
/// ```
///
/// This corresponds to `S_UNAMESPACE` (0x1124) and `S_UNAMESPACE_ST` (0x1029)
/// in the CodeView symbol set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SUNamespace {
    /// The fully-qualified namespace name (e.g., `std`, `std::chrono`).
    pub name: String,

    /// Whether this was parsed from the St format (0x1029).
    pub is_st_format: bool,
}

impl SUNamespace {
    /// Create a new using-namespace symbol.
    pub fn new(name: String) -> Self {
        Self {
            name,
            is_st_format: false,
        }
    }

    /// Create a new using-namespace symbol in St format.
    pub fn new_st(name: String) -> Self {
        Self {
            name,
            is_st_format: true,
        }
    }

    /// Parse an S_UNAMESPACE symbol from a byte slice.
    ///
    /// Expects the layout: `name(NT)`.
    pub fn parse(data: &[u8]) -> Option<Self> {
        let name = parse_nt_string(data);
        Some(Self {
            name,
            is_st_format: false,
        })
    }

    /// Parse an S_UNAMESPACE_ST symbol from a byte slice.
    ///
    /// Expects the layout: `name(ST)`.
    pub fn parse_st(data: &[u8]) -> Option<Self> {
        let name = parse_nt_string(data);
        Some(Self {
            name,
            is_st_format: true,
        })
    }
}

impl AbstractMsSymbol for SUNamespace {
    fn pdb_id(&self) -> u16 {
        if self.is_st_format {
            super::super::symbol_kind::S_UNAMESPACE_ST
        } else {
            super::super::symbol_kind::S_UNAMESPACE
        }
    }

    fn symbol_type_name(&self) -> &'static str {
        if self.is_st_format {
            "S_UNAMESPACE_ST"
        } else {
            "S_UNAMESPACE"
        }
    }

    fn emit(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UNAMESPACE: {}", self.name)
    }
}

impl NameMsSymbol for SUNamespace {
    fn name(&self) -> &str {
        &self.name
    }
}

impl fmt::Display for SUNamespace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.emit(f)
    }
}

/// Parse a null-terminated UTF-8 string from a byte slice.
fn parse_nt_string(data: &[u8]) -> String {
    let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
    String::from_utf8_lossy(&data[..end]).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_basic() {
        let data = b"std\0";
        let sym = SUNamespace::parse(data).unwrap();
        assert_eq!(sym.name, "std");
        assert!(!sym.is_st_format);
    }

    #[test]
    fn test_parse_nested() {
        let data = b"std::chrono\0";
        let sym = SUNamespace::parse(data).unwrap();
        assert_eq!(sym.name, "std::chrono");
    }

    #[test]
    fn test_parse_empty() {
        let data = b"\0";
        let sym = SUNamespace::parse(data).unwrap();
        assert_eq!(sym.name, "");
    }

    #[test]
    fn test_parse_no_terminator() {
        let data = b"boost";
        let sym = SUNamespace::parse(data).unwrap();
        assert_eq!(sym.name, "boost");
    }

    #[test]
    fn test_parse_st_basic() {
        let data = b"std\0";
        let sym = SUNamespace::parse_st(data).unwrap();
        assert_eq!(sym.name, "std");
        assert!(sym.is_st_format);
    }

    #[test]
    fn test_parse_st_nested() {
        let data = b"std::chrono\0";
        let sym = SUNamespace::parse_st(data).unwrap();
        assert_eq!(sym.name, "std::chrono");
    }

    #[test]
    fn test_trait_impls() {
        let sym = SUNamespace::new("std".to_string());
        assert_eq!(sym.pdb_id(), 0x1124);
        assert_eq!(sym.symbol_type_name(), "S_UNAMESPACE");
        assert_eq!(sym.name(), "std");
    }

    #[test]
    fn test_trait_impls_st() {
        let sym = SUNamespace::new_st("boost".to_string());
        assert_eq!(sym.pdb_id(), 0x1029);
        assert_eq!(sym.symbol_type_name(), "S_UNAMESPACE_ST");
        assert_eq!(sym.name(), "boost");
    }

    #[test]
    fn test_display() {
        let sym = SUNamespace::new("std::vector".to_string());
        let s = format!("{}", sym);
        assert!(s.contains("UNAMESPACE"));
        assert!(s.contains("std::vector"));
    }

    #[test]
    fn test_display_st() {
        let sym = SUNamespace::new_st("boost::asio".to_string());
        let s = format!("{}", sym);
        assert!(s.contains("UNAMESPACE"));
        assert!(s.contains("boost::asio"));
    }

    #[test]
    fn test_clone_eq() {
        let a = SUNamespace::new("std".to_string());
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn test_clone_eq_st() {
        let a = SUNamespace::new_st("boost".to_string());
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn test_new_st() {
        let sym = SUNamespace::new_st("std".to_string());
        assert!(sym.is_st_format);
        assert_eq!(sym.name, "std");
    }
}
