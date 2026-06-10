//! S_UNAMESPACE -- Using namespace symbol.
//!
//! Ports Ghidra's `ghidra.app.util.bin.format.pdb2.pdbreader.symbol.S_UNamespaceMsSymbol`.

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
/// # PDB Binary Layout
///
/// ```text
/// name : NT string
/// ```
///
/// This corresponds to `S_UNAMESPACE` (0x1124) in the CodeView symbol set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SUNamespace {
    /// The fully-qualified namespace name (e.g., `std`, `std::chrono`).
    pub name: String,
}

impl SUNamespace {
    /// Create a new using-namespace symbol.
    pub fn new(name: String) -> Self {
        Self { name }
    }

    /// Parse an S_UNAMESPACE symbol from a byte slice.
    ///
    /// Expects the layout: `name(NT)`.
    pub fn parse(data: &[u8]) -> Option<Self> {
        let name = parse_nt_string(data);
        Some(Self { name })
    }
}

impl AbstractMsSymbol for SUNamespace {
    fn pdb_id(&self) -> u16 {
        super::super::symbol_kind::S_UNAMESPACE
    }

    fn symbol_type_name(&self) -> &'static str {
        "S_UNAMESPACE"
    }

    fn emit(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UsingNamespace: {}", self.name)
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
    fn test_trait_impls() {
        let sym = SUNamespace::new("std".to_string());
        assert_eq!(sym.pdb_id(), 0x1124);
        assert_eq!(sym.symbol_type_name(), "S_UNAMESPACE");
        assert_eq!(sym.name(), "std");
    }

    #[test]
    fn test_display() {
        let sym = SUNamespace::new("std::vector".to_string());
        let s = format!("{}", sym);
        assert!(s.contains("UsingNamespace"));
        assert!(s.contains("std::vector"));
    }

    #[test]
    fn test_clone_eq() {
        let a = SUNamespace::new("std".to_string());
        let b = a.clone();
        assert_eq!(a, b);
    }
}
