//! AbstractCompile2 -- abstract base for S_COMPILE2 symbols.
//!
//! Ports Ghidra's `ghidra.app.util.bin.format.pdb2.pdbreader.symbol.AbstractCompile2MsSymbol`.

use std::fmt;

use super::abstract_ms_symbol::AbstractMsSymbol;

/// Abstract base for the `S_COMPILE2` CodeView symbol record.
///
/// `S_COMPILE2` records compiler version information. This structure captures
/// the compiler flags, target machine, frontend and backend version numbers,
/// and the compiler version string.
///
/// # Fields
///
/// - `flags` — Compiler flags bitmask.
/// - `machine` — Target machine type (e.g., x86, x64, ARM).
/// - `frontend_major`, `frontend_minor`, `frontend_build` — Frontend version.
/// - `backend_major`, `backend_minor`, `backend_build` — Backend version.
/// - `version_string` — Freeform compiler version string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbstractCompile2 {
    /// Compiler flags bitmask.
    pub flags: u32,

    /// Target machine type.
    pub machine: u16,

    /// Frontend version: major.
    pub frontend_major: u16,

    /// Frontend version: minor.
    pub frontend_minor: u16,

    /// Frontend version: build.
    pub frontend_build: u16,

    /// Backend version: major.
    pub backend_major: u16,

    /// Backend version: minor.
    pub backend_minor: u16,

    /// Backend version: build.
    pub backend_build: u16,

    /// Freeform compiler version string.
    pub version_string: String,
}

impl AbstractCompile2 {
    /// Create a new compile2 symbol.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        flags: u32,
        machine: u16,
        frontend_major: u16,
        frontend_minor: u16,
        frontend_build: u16,
        backend_major: u16,
        backend_minor: u16,
        backend_build: u16,
        version_string: String,
    ) -> Self {
        Self {
            flags,
            machine,
            frontend_major,
            frontend_minor,
            frontend_build,
            backend_major,
            backend_minor,
            backend_build,
            version_string,
        }
    }

    /// Parse a compile2 symbol from a byte slice.
    ///
    /// Expects the layout:
    /// `flags(u32) + machine(u16) + frontend_major(u16) + frontend_minor(u16) +
    /// frontend_build(u16) + backend_major(u16) + backend_minor(u16) +
    /// backend_build(u16) + version_string(NT)`.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 18 {
            return None;
        }
        let flags = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let machine = u16::from_le_bytes([data[4], data[5]]);
        let frontend_major = u16::from_le_bytes([data[6], data[7]]);
        let frontend_minor = u16::from_le_bytes([data[8], data[9]]);
        let frontend_build = u16::from_le_bytes([data[10], data[11]]);
        let backend_major = u16::from_le_bytes([data[12], data[13]]);
        let backend_minor = u16::from_le_bytes([data[14], data[15]]);
        let backend_build = u16::from_le_bytes([data[16], data[17]]);
        let version_string = if data.len() > 18 {
            parse_nt_string(&data[18..])
        } else {
            String::new()
        };
        Some(Self {
            flags,
            machine,
            frontend_major,
            frontend_minor,
            frontend_build,
            backend_major,
            backend_minor,
            backend_build,
            version_string,
        })
    }

    /// Return the frontend version as a formatted string (e.g., "14.29.30133").
    pub fn frontend_version(&self) -> String {
        format!(
            "{}.{}.{}",
            self.frontend_major, self.frontend_minor, self.frontend_build
        )
    }

    /// Return the backend version as a formatted string.
    pub fn backend_version(&self) -> String {
        format!(
            "{}.{}.{}",
            self.backend_major, self.backend_minor, self.backend_build
        )
    }
}

impl AbstractMsSymbol for AbstractCompile2 {
    fn pdb_id(&self) -> u16 {
        super::super::symbol_kind::S_COMPILE2
    }

    fn symbol_type_name(&self) -> &'static str {
        "S_COMPILE2"
    }

    fn emit(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Compile2: Machine: 0x{:04X}, Frontend: {}, Backend: {}, Flags: 0x{:08X}, {}",
            self.machine,
            self.frontend_version(),
            self.backend_version(),
            self.flags,
            self.version_string
        )
    }
}

impl fmt::Display for AbstractCompile2 {
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
        let mut data = Vec::new();
        data.extend_from_slice(&0x00010000u32.to_le_bytes()); // flags
        data.extend_from_slice(&0x014Cu16.to_le_bytes());      // machine (x86)
        data.extend_from_slice(&14u16.to_le_bytes());           // frontend_major
        data.extend_from_slice(&29u16.to_le_bytes());           // frontend_minor
        data.extend_from_slice(&30133u16.to_le_bytes());        // frontend_build
        data.extend_from_slice(&14u16.to_le_bytes());           // backend_major
        data.extend_from_slice(&29u16.to_le_bytes());           // backend_minor
        data.extend_from_slice(&30133u16.to_le_bytes());        // backend_build
        data.extend_from_slice(b"Microsoft (R) Optimizing Compiler\0");

        let sym = AbstractCompile2::parse(&data).unwrap();
        assert_eq!(sym.flags, 0x00010000);
        assert_eq!(sym.machine, 0x014C);
        assert_eq!(sym.frontend_major, 14);
        assert_eq!(sym.frontend_version(), "14.29.30133");
        assert_eq!(sym.version_string, "Microsoft (R) Optimizing Compiler");
    }

    #[test]
    fn test_parse_no_version_string() {
        let mut data = Vec::new();
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());

        let sym = AbstractCompile2::parse(&data).unwrap();
        assert_eq!(sym.version_string, "");
    }

    #[test]
    fn test_parse_truncated() {
        let data = [0x00, 0x01]; // too short
        assert!(AbstractCompile2::parse(&data).is_none());
    }

    #[test]
    fn test_trait_impls() {
        let sym = AbstractCompile2::new(
            0, 0x8664, 14, 29, 30133, 14, 29, 30133, "Clang 15.0".to_string(),
        );
        assert_eq!(sym.pdb_id(), 0x1013);
        assert_eq!(sym.symbol_type_name(), "S_COMPILE2");
        assert_eq!(sym.backend_version(), "14.29.30133");
    }

    #[test]
    fn test_display() {
        let sym = AbstractCompile2::new(
            0x100, 0x014C, 14, 0, 0, 14, 0, 0, "MSVC".to_string(),
        );
        let s = format!("{}", sym);
        assert!(s.contains("Compile2"));
        assert!(s.contains("MSVC"));
        assert!(s.contains("14.0.0"));
    }
}
