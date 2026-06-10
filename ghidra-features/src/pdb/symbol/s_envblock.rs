//! S_ENVBLOCK -- Environment block symbol.
//!
//! Ports Ghidra's `ghidra.app.util.bin.format.pdb2.pdbreader.symbol.EnvironmentBlockMsSymbol`.

use std::fmt;

use super::abstract_ms_symbol::AbstractMsSymbol;

/// An environment block symbol (`S_ENVBLOCK`).
///
/// This symbol contains a set of key-value string pairs that describe the
/// build environment (compiler flags, tool versions, etc.) used to produce
/// the compilation unit. The keys and values are stored as alternating
/// null-terminated strings after a 1-byte flags field.
///
/// # PDB Binary Layout
///
/// ```text
/// flags      : u8
/// fields     : (NT key, NT value)*  -- variable-length pairs
/// ```
///
/// This corresponds to `S_ENVBLOCK` (0x1034) in the CodeView symbol set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SEnvBlock {
    /// Raw flags byte. Meaning is not publicly documented.
    pub flags: u8,

    /// Key-value pairs from the environment block.
    pub fields: Vec<(String, String)>,
}

impl SEnvBlock {
    /// Create a new environment block symbol.
    pub fn new(flags: u8, fields: Vec<(String, String)>) -> Self {
        Self { flags, fields }
    }

    /// Parse an S_ENVBLOCK symbol from a byte slice.
    ///
    /// Expects the layout: `flags(u8) + (NT key, NT value)*`.
    /// Keys and values are parsed as alternating null-terminated strings.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.is_empty() {
            return None;
        }
        let flags = data[0];
        let mut fields = Vec::new();
        let mut pos = 1usize;
        while pos < data.len() {
            let (key, k1) = read_nt_string(data, pos);
            if key.is_empty() {
                break;
            }
            if k1 >= data.len() {
                break;
            }
            let (val, k2) = read_nt_string(data, k1);
            fields.push((key, val));
            pos = k2;
        }
        Some(Self { flags, fields })
    }

    /// Return the number of key-value pairs in this environment block.
    pub fn field_count(&self) -> usize {
        self.fields.len()
    }

    /// Look up a value by key name.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }
}

/// Read a null-terminated UTF-8 string from a byte slice at the given offset.
fn read_nt_string(data: &[u8], offset: usize) -> (String, usize) {
    if offset >= data.len() {
        return (String::new(), offset);
    }
    let end = data[offset..]
        .iter()
        .position(|&b| b == 0)
        .map(|p| offset + p)
        .unwrap_or(data.len());
    let s = String::from_utf8_lossy(&data[offset..end]).to_string();
    let next = if end < data.len() { end + 1 } else { end };
    (s, next)
}

impl AbstractMsSymbol for SEnvBlock {
    fn pdb_id(&self) -> u16 {
        super::super::symbol_kind::S_ENVBLOCK
    }

    fn symbol_type_name(&self) -> &'static str {
        "S_ENVBLOCK"
    }

    fn emit(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "EnvBlock: Flags: {:#04X}, {} fields", self.flags, self.fields.len())?;
        for (i, (key, val)) in self.fields.iter().enumerate() {
            if i > 0 {
                write!(f, "\n")?;
            }
            write!(f, "   {} = {}", key, val)?;
        }
        Ok(())
    }
}

impl fmt::Display for SEnvBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.emit(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_envblock_bytes(flags: u8, pairs: &[(&[u8], &[u8])]) -> Vec<u8> {
        let mut data = Vec::new();
        data.push(flags);
        for (key, val) in pairs {
            data.extend_from_slice(key);
            data.push(0);
            data.extend_from_slice(val);
            data.push(0);
        }
        data
    }

    #[test]
    fn test_parse_basic() {
        let data = make_envblock_bytes(0, &[(b"key1", b"val1"), (b"key2", b"val2")]);
        let sym = SEnvBlock::parse(&data).unwrap();
        assert_eq!(sym.flags, 0);
        assert_eq!(sym.fields.len(), 2);
        assert_eq!(sym.fields[0], ("key1".to_string(), "val1".to_string()));
        assert_eq!(sym.fields[1], ("key2".to_string(), "val2".to_string()));
    }

    #[test]
    fn test_parse_empty() {
        let data = [0x00u8]; // flags only, no fields
        let sym = SEnvBlock::parse(&data).unwrap();
        assert_eq!(sym.flags, 0);
        assert_eq!(sym.fields.len(), 0);
    }

    #[test]
    fn test_parse_no_data() {
        let data: [u8; 0] = [];
        assert!(SEnvBlock::parse(&data).is_none());
    }

    #[test]
    fn test_parse_single_pair() {
        let data = make_envblock_bytes(1, &[(b"W", b"/O2")]);
        let sym = SEnvBlock::parse(&data).unwrap();
        assert_eq!(sym.flags, 1);
        assert_eq!(sym.fields.len(), 1);
        assert_eq!(sym.get("W"), Some("/O2"));
    }

    #[test]
    fn test_get_existing_key() {
        let data = make_envblock_bytes(0, &[(b"CC", b"cl.exe"), (b"CXX", b"cl.exe")]);
        let sym = SEnvBlock::parse(&data).unwrap();
        assert_eq!(sym.get("CC"), Some("cl.exe"));
        assert_eq!(sym.get("CXX"), Some("cl.exe"));
    }

    #[test]
    fn test_get_missing_key() {
        let data = make_envblock_bytes(0, &[(b"CC", b"cl.exe")]);
        let sym = SEnvBlock::parse(&data).unwrap();
        assert_eq!(sym.get("MISSING"), None);
    }

    #[test]
    fn test_field_count() {
        let data = make_envblock_bytes(0, &[(b"A", b"1"), (b"B", b"2"), (b"C", b"3")]);
        let sym = SEnvBlock::parse(&data).unwrap();
        assert_eq!(sym.field_count(), 3);
    }

    #[test]
    fn test_trait_impls() {
        let sym = SEnvBlock::new(0, vec![("CC".into(), "cl.exe".into())]);
        assert_eq!(sym.pdb_id(), 0x1034);
        assert_eq!(sym.symbol_type_name(), "S_ENVBLOCK");
    }

    #[test]
    fn test_display() {
        let sym = SEnvBlock::new(0, vec![("CC".into(), "cl.exe".into())]);
        let s = format!("{}", sym);
        assert!(s.contains("EnvBlock"));
        assert!(s.contains("CC"));
        assert!(s.contains("cl.exe"));
    }

    #[test]
    fn test_clone_eq() {
        let a = SEnvBlock::new(0, vec![("A".into(), "1".into())]);
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn test_parse_trailing_garbage() {
        // After the last complete pair, extra bytes are ignored
        let mut data = Vec::new();
        data.push(0u8); // flags
        data.extend_from_slice(b"K\0V\0");
        data.extend_from_slice(&[0xFF, 0xFE]); // garbage
        let sym = SEnvBlock::parse(&data).unwrap();
        assert_eq!(sym.fields.len(), 1);
    }
}
