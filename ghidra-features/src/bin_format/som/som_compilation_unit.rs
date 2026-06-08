//! SOM compilation_unit structure ported from Ghidra's `SomCompilationUnit.java`.
//!
//! Represents a SOM `compilation_unit` structure.
//!
//! Reference: [The 32-bit PA-RISC Run-time Architecture Document](https://web.archive.org/web/20050502101134/http://devresource.hp.com/drc/STK/docs/archive/rad_11_0_32.pdf)

use std::fmt;
use std::io;

use crate::bin_format::binary_reader::BinaryReader;
use crate::bin_format::binary_writer::{BinaryWritable, BinaryWriter};
use crate::bin_format::types::{DataTypeDescription, StructConverter};

use super::som_exception::SomException;
use super::som_sys_clock::SomSysClock;

/// The size in bytes of a `SomCompilationUnit`.
pub const SOM_COMPILATION_UNIT_SIZE: usize = 0x24;

/// Represents a SOM `compilation_unit` structure.
///
/// Ported from `ghidra.app.util.bin.format.som.SomCompilationUnit`.
#[derive(Debug, Clone)]
pub struct SomCompilationUnit {
    /// The compilation unit name (from symbol strings).
    pub name: String,
    /// The language name (from symbol strings).
    pub language_name: String,
    /// The product ID (from symbol strings).
    pub product_id: String,
    /// The version ID (from symbol strings).
    pub version_id: String,
    /// Whether the compilation unit is not the first SOM in a multiple chunk compilation.
    pub chunk_flag: bool,
    /// Compile time.
    pub compile_time: SomSysClock,
    /// Source time.
    pub source_time: SomSysClock,
}

impl SomCompilationUnit {
    /// Parse a `SomCompilationUnit` from a binary reader at the current position.
    ///
    /// # Arguments
    /// * `reader` - A binary reader positioned at the start of the record.
    /// * `symbol_strings_location` - The starting index of the symbol strings in the file.
    ///
    /// # Errors
    ///
    /// Returns `SomException` if an I/O error occurs.
    pub fn parse(
        reader: &mut BinaryReader,
        symbol_strings_location: u64,
    ) -> Result<Self, SomException> {
        let name_offset = reader.read_next_u32().map_err(SomException::from)? as u64;
        let name = reader.read_cstring_at(symbol_strings_location + name_offset)?;

        let lang_offset = reader.read_next_u32().map_err(SomException::from)? as u64;
        let language_name = reader.read_cstring_at(symbol_strings_location + lang_offset)?;

        let prod_offset = reader.read_next_u32().map_err(SomException::from)? as u64;
        let product_id = reader.read_cstring_at(symbol_strings_location + prod_offset)?;

        let ver_offset = reader.read_next_u32().map_err(SomException::from)? as u64;
        let version_id = reader.read_cstring_at(symbol_strings_location + ver_offset)?;

        let bitfield = reader.read_next_i32().map_err(SomException::from)?;
        let chunk_flag = (bitfield & 0x1) != 0;

        let compile_time = SomSysClock::parse(reader)?;
        let source_time = SomSysClock::parse(reader)?;

        Ok(Self {
            name,
            language_name,
            product_id,
            version_id,
            chunk_flag,
            compile_time,
            source_time,
        })
    }
}

impl StructConverter for SomCompilationUnit {
    fn to_data_type(&self) -> DataTypeDescription {
        DataTypeDescription::Struct {
            name: "compilation_unit".to_string(),
            size: SOM_COMPILATION_UNIT_SIZE as u32,
            fields: vec![
                ("name".into(), DataTypeDescription::DWord),
                ("language_name".into(), DataTypeDescription::DWord),
                ("product_id".into(), DataTypeDescription::DWord),
                ("version_id".into(), DataTypeDescription::DWord),
                ("bitfield".into(), DataTypeDescription::DWord),
                (
                    "compile_time".into(),
                    self.compile_time.to_data_type(),
                ),
                (
                    "source_time".into(),
                    self.source_time.to_data_type(),
                ),
            ],
        }
    }
}

impl BinaryWritable for SomCompilationUnit {
    fn write_to(&self, writer: &mut BinaryWriter) -> io::Result<()> {
        // Write name/language/product/version offsets as 0 (caller must resolve)
        writer.write_u32(0);
        writer.write_u32(0);
        writer.write_u32(0);
        writer.write_u32(0);

        let bitfield: u32 = if self.chunk_flag { 1 } else { 0 };
        writer.write_u32(bitfield);

        self.compile_time.write_to(writer)?;
        self.source_time.write_to(writer)?;
        Ok(())
    }
}

impl fmt::Display for SomCompilationUnit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SomCompilationUnit {{ name=\"{}\", language=\"{}\", product=\"{}\", version=\"{}\" }}",
            self.name, self.language_name, self.product_id, self.version_id
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cu_data(
        name_off: u32,
        lang_off: u32,
        prod_off: u32,
        ver_off: u32,
        chunk_flag: bool,
        compile_sec: u32,
        compile_nano: u32,
        source_sec: u32,
        source_nano: u32,
    ) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&name_off.to_le_bytes());
        data.extend_from_slice(&lang_off.to_le_bytes());
        data.extend_from_slice(&prod_off.to_le_bytes());
        data.extend_from_slice(&ver_off.to_le_bytes());
        data.extend_from_slice(&(if chunk_flag { 1u32 } else { 0u32 }).to_le_bytes());
        data.extend_from_slice(&compile_sec.to_le_bytes());
        data.extend_from_slice(&compile_nano.to_le_bytes());
        data.extend_from_slice(&source_sec.to_le_bytes());
        data.extend_from_slice(&source_nano.to_le_bytes());
        data
    }

    #[test]
    fn test_parse_compilation_unit() {
        let mut buf = vec![0u8; 0x500];
        let name = b"test.c\0";
        let lang = b"C\0";
        let prod = b"cc\0";
        let ver = b"1.0\0";
        buf[0x100..0x100 + name.len()].copy_from_slice(name);
        buf[0x200..0x200 + lang.len()].copy_from_slice(lang);
        buf[0x300..0x300 + prod.len()].copy_from_slice(prod);
        buf[0x400..0x400 + ver.len()].copy_from_slice(ver);

        let cu_data = make_cu_data(0x100, 0x200, 0x300, 0x400, false, 1000, 500, 2000, 600);
        buf[0..cu_data.len()].copy_from_slice(&cu_data);

        let mut reader = BinaryReader::from_bytes(&buf, true);
        let cu = SomCompilationUnit::parse(&mut reader, 0).unwrap();

        assert_eq!(cu.name, "test.c");
        assert_eq!(cu.language_name, "C");
        assert_eq!(cu.product_id, "cc");
        assert_eq!(cu.version_id, "1.0");
        assert!(!cu.chunk_flag);
        assert_eq!(cu.compile_time.seconds(), 1000);
        assert_eq!(cu.compile_time.nano_seconds(), 500);
        assert_eq!(cu.source_time.seconds(), 2000);
        assert_eq!(cu.source_time.nano_seconds(), 600);
    }

    #[test]
    fn test_parse_compilation_unit_chunk_flag() {
        let mut buf = vec![0u8; 0x500];
        let name = b"a\0";
        let lang = b"b\0";
        let prod = b"c\0";
        let ver = b"d\0";
        buf[0x100..0x100 + name.len()].copy_from_slice(name);
        buf[0x200..0x200 + lang.len()].copy_from_slice(lang);
        buf[0x300..0x300 + prod.len()].copy_from_slice(prod);
        buf[0x400..0x400 + ver.len()].copy_from_slice(ver);

        let cu_data = make_cu_data(0x100, 0x200, 0x300, 0x400, true, 0, 0, 0, 0);
        buf[0..cu_data.len()].copy_from_slice(&cu_data);

        let mut reader = BinaryReader::from_bytes(&buf, true);
        let cu = SomCompilationUnit::parse(&mut reader, 0).unwrap();

        assert!(cu.chunk_flag);
    }

    #[test]
    fn test_cu_struct_converter() {
        let mut buf = vec![0u8; 0x500];
        buf[0x100] = b'a';
        buf[0x200] = b'b';
        buf[0x300] = b'c';
        buf[0x400] = b'd';

        let cu_data = make_cu_data(0x100, 0x200, 0x300, 0x400, false, 0, 0, 0, 0);
        buf[0..cu_data.len()].copy_from_slice(&cu_data);

        let mut reader = BinaryReader::from_bytes(&buf, true);
        let cu = SomCompilationUnit::parse(&mut reader, 0).unwrap();

        let dt = cu.to_data_type();
        match &dt {
            DataTypeDescription::Struct { name, fields, .. } => {
                assert_eq!(name, "compilation_unit");
                assert_eq!(fields.len(), 7);
            }
            _ => panic!("Expected Struct"),
        }
    }

    #[test]
    fn test_cu_display() {
        let mut buf = vec![0u8; 0x500];
        let name = b"file.c\0";
        buf[0x100..0x100 + name.len()].copy_from_slice(name);
        buf[0x200] = b'\0';
        buf[0x300] = b'\0';
        buf[0x400] = b'\0';

        let cu_data = make_cu_data(0x100, 0x200, 0x300, 0x400, false, 0, 0, 0, 0);
        buf[0..cu_data.len()].copy_from_slice(&cu_data);

        let mut reader = BinaryReader::from_bytes(&buf, true);
        let cu = SomCompilationUnit::parse(&mut reader, 0).unwrap();

        let s = format!("{}", cu);
        assert!(s.contains("file.c"));
    }

    #[test]
    fn test_cu_truncated() {
        let data = vec![0u8; 10]; // too short
        let mut reader = BinaryReader::from_bytes(&data, true);
        let result = SomCompilationUnit::parse(&mut reader, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_cu_size() {
        assert_eq!(SOM_COMPILATION_UNIT_SIZE, 0x24);
    }
}
