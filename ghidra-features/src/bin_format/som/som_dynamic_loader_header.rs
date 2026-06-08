//! SOM dl_header structure ported from Ghidra's `SomDynamicLoaderHeader.java`.
//!
//! Represents a SOM `dl_header` structure -- the dynamic loader header
//! containing information about shared libraries, imports, exports,
//! dynamic relocations, and linkage tables.
//!
//! Reference: [The 32-bit PA-RISC Run-time Architecture Document](https://web.archive.org/web/20050502101134/http://devresource.hp.com/drc/STK/docs/archive/rad_11_0_32.pdf)

use std::fmt;
use std::io;

use crate::bin_format::binary_reader::BinaryReader;
use crate::bin_format::binary_writer::{BinaryWritable, BinaryWriter};
use crate::bin_format::types::{DataTypeDescription, StructConverter};

use super::som_dlt_entry::SomDltEntry;
use super::som_dynamic_relocation::SomDynamicRelocation;
use super::som_exception::SomException;
use super::som_export_entry::SomExportEntry;
use super::som_export_entry_ext::SomExportEntryExt;
use super::som_import_entry::SomImportEntry;
use super::som_module_entry::SomModuleEntry;
use super::som_plt_entry::SomPltEntry;
use super::som_shlib_list_entry::SomShlibListEntry;

/// The size in bytes of a `SomDynamicLoaderHeader`.
pub const SOM_DYNAMIC_LOADER_HEADER_SIZE: usize = 0x70;

/// Represents a SOM `dl_header` structure.
///
/// Ported from `ghidra.app.util.bin.format.som.SomDynamicLoaderHeader`.
///
/// Note: Unlike the Java version which takes `Program` and `Address` parameters,
/// this Rust version takes raw `BinaryReader`s for the text and data spaces.
#[derive(Debug)]
pub struct SomDynamicLoaderHeader {
    /// Version of the DL header.
    pub hdr_version: i32,
    /// Data-relative offset of the Linkage Table pointer (R19).
    pub ltptr_value: i32,
    /// Text-relative offset of the shared library list.
    pub shlib_list_loc: i32,
    /// Number of entries in the shared library list.
    pub shlib_list_count: i32,
    /// Text-relative offset of the import list.
    pub import_list_loc: i32,
    /// Number of entries in the import list.
    pub import_list_count: i32,
    /// Text-relative offset of the hash table.
    pub hash_table_loc: i32,
    /// Number of slots used in the hash table.
    pub hash_table_size: i32,
    /// Text-relative offset of the export list.
    pub export_list_loc: i32,
    /// Number of export entries.
    pub export_list_count: i32,
    /// Text-relative offset of the string table.
    pub string_table_loc: i32,
    /// Length in bytes of the string table.
    pub string_table_size: i32,
    /// Text-relative offset of the dynamic relocation records.
    pub dreloc_loc: i32,
    /// Number of dynamic relocation records generated.
    pub dreloc_count: i32,
    /// Offset in the $DATA$ space of the Data Linkage Table.
    pub dlt_loc: i32,
    /// Offset in the $DATA$ space of the Procedure Linkage Table.
    pub plt_loc: i32,
    /// Number of entries in the DLT.
    pub dlt_count: i32,
    /// Number of entries in the PLT.
    pub plt_count: i32,
    /// Highest version number of any symbol defined in the shared library.
    pub highwater_mark: i16,
    /// Various flags.
    pub flags: i16,
    /// Text-relative offset of the export extension table.
    pub export_ext_loc: i32,
    /// Text-relative offset of the module table.
    pub module_loc: i32,
    /// Number of modules in the module table.
    pub module_count: i32,
    /// Index into the import table if the elab_ref bit in flags is set.
    pub elaborator: i32,
    /// Index into the import table if init_ref bit in flags is set.
    pub initializer: i32,
    /// Index into the shared library string table.
    pub embedded_path: i32,
    /// Number of initializers declared.
    pub initializer_count: i32,
    /// Size of the TSD area.
    pub tdsize: i32,
    /// Text-relative offset of fastbind info.
    pub fastbind_list_loc: i32,

    // Parsed sub-structures
    /// Parsed shared library list entries.
    pub shlibs: Vec<SomShlibListEntry>,
    /// Parsed import entries.
    pub imports: Vec<SomImportEntry>,
    /// Parsed export entries.
    pub exports: Vec<SomExportEntry>,
    /// Parsed dynamic relocation entries.
    pub drelocs: Vec<SomDynamicRelocation>,
    /// Parsed PLT entries.
    pub plt: Vec<SomPltEntry>,
    /// Parsed DLT entries.
    pub dlt: Vec<SomDltEntry>,
    /// Parsed export entry extensions.
    pub export_extensions: Vec<SomExportEntryExt>,
    /// Parsed module entries.
    pub modules: Vec<SomModuleEntry>,
}

impl SomDynamicLoaderHeader {
    /// Parse a `SomDynamicLoaderHeader` from text and data space readers.
    ///
    /// # Arguments
    /// * `text_reader` - A binary reader for the text space.
    /// * `data_reader` - A binary reader for the data space.
    ///
    /// # Errors
    ///
    /// Returns `SomException` if an I/O error occurs.
    pub fn parse(
        text_reader: &mut BinaryReader,
        data_reader: &mut BinaryReader,
    ) -> Result<Self, SomException> {
        let hdr_version = text_reader.read_next_i32().map_err(SomException::from)?;
        let ltptr_value = text_reader.read_next_i32().map_err(SomException::from)?;
        let shlib_list_loc = text_reader.read_next_i32().map_err(SomException::from)?;
        let shlib_list_count = text_reader.read_next_i32().map_err(SomException::from)?;
        let import_list_loc = text_reader.read_next_i32().map_err(SomException::from)?;
        let import_list_count = text_reader.read_next_i32().map_err(SomException::from)?;
        let hash_table_loc = text_reader.read_next_i32().map_err(SomException::from)?;
        let hash_table_size = text_reader.read_next_i32().map_err(SomException::from)?;
        let export_list_loc = text_reader.read_next_i32().map_err(SomException::from)?;
        let export_list_count = text_reader.read_next_i32().map_err(SomException::from)?;
        let string_table_loc = text_reader.read_next_i32().map_err(SomException::from)?;
        let string_table_size = text_reader.read_next_i32().map_err(SomException::from)?;
        let dreloc_loc = text_reader.read_next_i32().map_err(SomException::from)?;
        let dreloc_count = text_reader.read_next_i32().map_err(SomException::from)?;
        let dlt_loc = text_reader.read_next_i32().map_err(SomException::from)?;
        let plt_loc = text_reader.read_next_i32().map_err(SomException::from)?;
        let dlt_count = text_reader.read_next_i32().map_err(SomException::from)?;
        let plt_count = text_reader.read_next_i32().map_err(SomException::from)?;
        let highwater_mark = text_reader.read_next_i16().map_err(SomException::from)?;
        let flags = text_reader.read_next_i16().map_err(SomException::from)?;
        let export_ext_loc = text_reader.read_next_i32().map_err(SomException::from)?;
        let module_loc = text_reader.read_next_i32().map_err(SomException::from)?;
        let module_count = text_reader.read_next_i32().map_err(SomException::from)?;
        let elaborator = text_reader.read_next_i32().map_err(SomException::from)?;
        let initializer = text_reader.read_next_i32().map_err(SomException::from)?;
        let embedded_path = text_reader.read_next_i32().map_err(SomException::from)?;
        let initializer_count = text_reader.read_next_i32().map_err(SomException::from)?;
        let tdsize = text_reader.read_next_i32().map_err(SomException::from)?;
        let fastbind_list_loc = text_reader.read_next_i32().map_err(SomException::from)?;

        let str_tab = string_table_loc as u64;

        // Parse shared library list
        let mut shlibs = Vec::new();
        if shlib_list_loc > 0 {
            text_reader.set_cursor(shlib_list_loc as u64);
            for _ in 0..shlib_list_count {
                shlibs.push(SomShlibListEntry::parse(text_reader, str_tab)?);
            }
        }

        // Parse import list
        let mut imports = Vec::new();
        if import_list_count > 0 {
            text_reader.set_cursor(import_list_loc as u64);
            for _ in 0..import_list_count {
                imports.push(SomImportEntry::parse(text_reader, str_tab)?);
            }
        }

        // Parse export list
        let mut exports = Vec::new();
        if export_list_count > 0 {
            text_reader.set_cursor(export_list_loc as u64);
            for _ in 0..export_list_count {
                exports.push(SomExportEntry::parse(text_reader, str_tab)?);
            }
        }

        // Parse dynamic relocations
        let mut drelocs = Vec::new();
        if dreloc_count > 0 {
            text_reader.set_cursor(dreloc_loc as u64);
            for _ in 0..dreloc_count {
                drelocs.push(SomDynamicRelocation::parse(text_reader)?);
            }
        }

        // Parse PLT entries (from data space)
        let mut plt = Vec::new();
        if plt_count > 0 {
            data_reader.set_cursor(plt_loc as u64);
            for _ in 0..plt_count {
                plt.push(SomPltEntry::parse(data_reader)?);
            }
        }

        // Parse DLT entries (from data space)
        let mut dlt = Vec::new();
        if dlt_count > 0 {
            data_reader.set_cursor(dlt_loc as u64);
            for _ in 0..dlt_count {
                dlt.push(SomDltEntry::parse(data_reader)?);
            }
        }

        // Parse export extensions
        let mut export_extensions = Vec::new();
        if export_ext_loc > 0 {
            text_reader.set_cursor(export_ext_loc as u64);
            for _ in 0..export_list_count {
                export_extensions.push(SomExportEntryExt::parse(text_reader)?);
            }
        }

        // Parse module entries
        let mut modules = Vec::new();
        if module_count > 0 {
            text_reader.set_cursor(module_loc as u64);
            for _ in 0..module_count {
                modules.push(SomModuleEntry::parse(text_reader)?);
            }
        }

        Ok(Self {
            hdr_version,
            ltptr_value,
            shlib_list_loc,
            shlib_list_count,
            import_list_loc,
            import_list_count,
            hash_table_loc,
            hash_table_size,
            export_list_loc,
            export_list_count,
            string_table_loc,
            string_table_size,
            dreloc_loc,
            dreloc_count,
            dlt_loc,
            plt_loc,
            dlt_count,
            plt_count,
            highwater_mark,
            flags,
            export_ext_loc,
            module_loc,
            module_count,
            elaborator,
            initializer,
            embedded_path,
            initializer_count,
            tdsize,
            fastbind_list_loc,
            shlibs,
            imports,
            exports,
            drelocs,
            plt,
            dlt,
            export_extensions,
            modules,
        })
    }
}

impl StructConverter for SomDynamicLoaderHeader {
    fn to_data_type(&self) -> DataTypeDescription {
        DataTypeDescription::Struct {
            name: "dl_header".to_string(),
            size: SOM_DYNAMIC_LOADER_HEADER_SIZE as u32,
            fields: vec![
                ("hdr_version".into(), DataTypeDescription::DWord),
                ("ltptr_value".into(), DataTypeDescription::DWord),
                ("shlib_list_loc".into(), DataTypeDescription::DWord),
                ("shlib_list_count".into(), DataTypeDescription::DWord),
                ("import_list_loc".into(), DataTypeDescription::DWord),
                ("import_list_count".into(), DataTypeDescription::DWord),
                ("hash_table_loc".into(), DataTypeDescription::DWord),
                ("hash_table_size".into(), DataTypeDescription::DWord),
                ("export_list_loc".into(), DataTypeDescription::DWord),
                ("export_list_count".into(), DataTypeDescription::DWord),
                ("string_table_loc".into(), DataTypeDescription::DWord),
                ("string_table_size".into(), DataTypeDescription::DWord),
                ("dreloc_loc".into(), DataTypeDescription::DWord),
                ("dreloc_count".into(), DataTypeDescription::DWord),
                ("dlt_loc".into(), DataTypeDescription::DWord),
                ("plt_loc".into(), DataTypeDescription::DWord),
                ("dlt_count".into(), DataTypeDescription::DWord),
                ("plt_count".into(), DataTypeDescription::DWord),
                ("highwater_mark".into(), DataTypeDescription::Word),
                ("flags".into(), DataTypeDescription::Word),
                ("export_ext_loc".into(), DataTypeDescription::DWord),
                ("module_loc".into(), DataTypeDescription::DWord),
                ("module_count".into(), DataTypeDescription::DWord),
                ("elaborator".into(), DataTypeDescription::DWord),
                ("initializer".into(), DataTypeDescription::DWord),
                ("embedded_path".into(), DataTypeDescription::DWord),
                ("initializer_count".into(), DataTypeDescription::DWord),
                ("tdsize".into(), DataTypeDescription::DWord),
                ("fastbind_list_loc".into(), DataTypeDescription::DWord),
            ],
        }
    }
}

impl BinaryWritable for SomDynamicLoaderHeader {
    fn write_to(&self, writer: &mut BinaryWriter) -> io::Result<()> {
        writer.write_i32(self.hdr_version);
        writer.write_i32(self.ltptr_value);
        writer.write_i32(self.shlib_list_loc);
        writer.write_i32(self.shlib_list_count);
        writer.write_i32(self.import_list_loc);
        writer.write_i32(self.import_list_count);
        writer.write_i32(self.hash_table_loc);
        writer.write_i32(self.hash_table_size);
        writer.write_i32(self.export_list_loc);
        writer.write_i32(self.export_list_count);
        writer.write_i32(self.string_table_loc);
        writer.write_i32(self.string_table_size);
        writer.write_i32(self.dreloc_loc);
        writer.write_i32(self.dreloc_count);
        writer.write_i32(self.dlt_loc);
        writer.write_i32(self.plt_loc);
        writer.write_i32(self.dlt_count);
        writer.write_i32(self.plt_count);
        writer.write_i16(self.highwater_mark);
        writer.write_i16(self.flags);
        writer.write_i32(self.export_ext_loc);
        writer.write_i32(self.module_loc);
        writer.write_i32(self.module_count);
        writer.write_i32(self.elaborator);
        writer.write_i32(self.initializer);
        writer.write_i32(self.embedded_path);
        writer.write_i32(self.initializer_count);
        writer.write_i32(self.tdsize);
        writer.write_i32(self.fastbind_list_loc);
        Ok(())
    }
}

impl fmt::Display for SomDynamicLoaderHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SomDynamicLoaderHeader {{ version={}, shlibs={}, imports={}, exports={}, drelocs={}, plt={}, dlt={}, modules={} }}",
            self.hdr_version,
            self.shlib_list_count,
            self.import_list_count,
            self.export_list_count,
            self.dreloc_count,
            self.plt_count,
            self.dlt_count,
            self.module_count,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_dl_header_bytes() -> Vec<u8> {
        let mut data = vec![0u8; SOM_DYNAMIC_LOADER_HEADER_SIZE];
        // hdr_version = 1
        data[0..4].copy_from_slice(&1i32.to_le_bytes());
        // ltptr_value = 0x100
        data[4..8].copy_from_slice(&0x100i32.to_le_bytes());
        // All other fields are 0 (no sub-structures)
        data
    }

    #[test]
    fn test_parse_dl_header_basic() {
        let data = make_dl_header_bytes();
        let mut text_reader = BinaryReader::from_bytes(&data, true);
        let mut data_reader = BinaryReader::from_bytes(&[], true);
        let header = SomDynamicLoaderHeader::parse(&mut text_reader, &mut data_reader).unwrap();

        assert_eq!(header.hdr_version, 1);
        assert_eq!(header.ltptr_value, 0x100);
        assert_eq!(header.shlib_list_count, 0);
        assert_eq!(header.import_list_count, 0);
        assert_eq!(header.export_list_count, 0);
        assert!(header.shlibs.is_empty());
        assert!(header.imports.is_empty());
        assert!(header.exports.is_empty());
    }

    #[test]
    fn test_dl_header_struct_converter() {
        let data = make_dl_header_bytes();
        let mut text_reader = BinaryReader::from_bytes(&data, true);
        let mut data_reader = BinaryReader::from_bytes(&[], true);
        let header = SomDynamicLoaderHeader::parse(&mut text_reader, &mut data_reader).unwrap();

        let dt = header.to_data_type();
        match &dt {
            DataTypeDescription::Struct { name, fields, .. } => {
                assert_eq!(name, "dl_header");
                assert_eq!(fields.len(), 29);
            }
            _ => panic!("Expected Struct"),
        }
    }

    #[test]
    fn test_dl_header_write_roundtrip() {
        let data = make_dl_header_bytes();
        let mut text_reader = BinaryReader::from_bytes(&data, true);
        let mut data_reader = BinaryReader::from_bytes(&[], true);
        let header = SomDynamicLoaderHeader::parse(&mut text_reader, &mut data_reader).unwrap();

        let mut writer = BinaryWriter::new(true);
        header.write_to(&mut writer).unwrap();
        let written = writer.into_vec();
        assert_eq!(written, data);
    }

    #[test]
    fn test_dl_header_display() {
        let data = make_dl_header_bytes();
        let mut text_reader = BinaryReader::from_bytes(&data, true);
        let mut data_reader = BinaryReader::from_bytes(&[], true);
        let header = SomDynamicLoaderHeader::parse(&mut text_reader, &mut data_reader).unwrap();

        let s = format!("{}", header);
        assert!(s.contains("version=1"));
        assert!(s.contains("shlibs=0"));
    }

    #[test]
    fn test_dl_header_truncated() {
        let data = vec![0u8; 10]; // too short
        let mut text_reader = BinaryReader::from_bytes(&data, true);
        let mut data_reader = BinaryReader::from_bytes(&[], true);
        let result = SomDynamicLoaderHeader::parse(&mut text_reader, &mut data_reader);
        assert!(result.is_err());
    }

    #[test]
    fn test_dl_header_size() {
        assert_eq!(SOM_DYNAMIC_LOADER_HEADER_SIZE, 0x70);
    }

    #[test]
    fn test_dl_header_with_dlt_entries() {
        let mut data = make_dl_header_bytes();
        // Set dlt_loc = 0x50, dlt_count = 2
        data[56..60].copy_from_slice(&0x50i32.to_le_bytes()); // dlt_loc
        data[64..68].copy_from_slice(&2i32.to_le_bytes());    // dlt_count

        // DLT entries at offset 0x50 in data space
        let mut data_space = vec![0u8; 0x100];
        data_space[0x50..0x54].copy_from_slice(&0xDEADBEEFu32.to_le_bytes());
        data_space[0x54..0x58].copy_from_slice(&0xCAFEBABEu32.to_le_bytes());

        let mut text_reader = BinaryReader::from_bytes(&data, true);
        let mut data_reader = BinaryReader::from_bytes(&data_space, true);
        let header = SomDynamicLoaderHeader::parse(&mut text_reader, &mut data_reader).unwrap();

        assert_eq!(header.dlt_count, 2);
        assert_eq!(header.dlt.len(), 2);
        assert_eq!(header.dlt[0].value, 0xDEADBEEFu32 as i32);
        assert_eq!(header.dlt[1].value, 0xCAFEBABEu32 as i32);
    }

    #[test]
    fn test_dl_header_with_plt_entries() {
        let mut data = make_dl_header_bytes();
        // Set plt_loc = 0x60, plt_count = 1
        data[60..64].copy_from_slice(&0x60i32.to_le_bytes()); // plt_loc
        data[68..72].copy_from_slice(&1i32.to_le_bytes());    // plt_count

        // PLT entry at offset 0x60 in data space
        let mut data_space = vec![0u8; 0x100];
        data_space[0x60..0x64].copy_from_slice(&0x4000i32.to_le_bytes()); // proc_addr
        data_space[0x64..0x68].copy_from_slice(&5i32.to_le_bytes());      // ltptr_value

        let mut text_reader = BinaryReader::from_bytes(&data, true);
        let mut data_reader = BinaryReader::from_bytes(&data_space, true);
        let header = SomDynamicLoaderHeader::parse(&mut text_reader, &mut data_reader).unwrap();

        assert_eq!(header.plt_count, 1);
        assert_eq!(header.plt.len(), 1);
        assert_eq!(header.plt[0].proc_addr, 0x4000);
        assert_eq!(header.plt[0].ltptr_value, 5);
    }
}
