//! Core PDB reader abstraction.
//!
//! Ports Ghidra's `ghidra.app.util.bin.format.pdb2.pdbreader.AbstractPdb`
//! and related Java abstract classes.
//!
//! Defines the [`AbstractPdb`] trait which provides the core interface that
//! all PDB reader implementations must satisfy. This trait abstracts over
//! the underlying data source (file, memory buffer, streaming) and provides
//! methods for accessing the MSF container, reading streams, resolving types,
//! and iterating symbols.
//!
//! Also provides [`PdbReaderContext`] which bundles the parsed PDB state
//! (MSF, info stream, TPI, DBI, IPI) into a single context object.

use std::collections::HashMap;
use std::fmt;
use std::path::Path;

use super::pdb_byte_reader::PdbByteReader;
use super::pdb_exception::PdbException;
use super::{
    MsfFile, PdbFile, PdbInfoStream, TpiStream, IpiStream, DbiStream,
    TypeRecord, SymbolRecord, SymbolStream, MsfError,
    parse_msf, parse_pdb_info_stream, parse_tpi_stream, parse_ipi_stream, parse_dbi_stream,
};

// =============================================================================
// AbstractPdb trait
// =============================================================================
/// Core trait for PDB reader implementations.
///
/// This trait defines the interface that any PDB reader must implement.
/// It covers:
/// - Opening/loading the PDB data
/// - Reading raw stream bytes from the MSF container
/// - Accessing parsed stream objects (Info, TPI, DBI, IPI)
/// - Resolving type indices to type records
/// - Iterating symbol records
/// - Querying metadata (GUID, age, signature, machine type)
pub trait AbstractPdb {
    /// Get the number of streams in the MSF container.
    fn num_streams(&self) -> usize;

    /// Get the size of a stream in bytes, or `None` if the index is invalid.
    fn stream_size(&self, stream_index: u32) -> Option<u32>;

    /// Read the raw bytes of a stream by its index.
    fn read_stream(&self, stream_index: u32) -> Option<Vec<u8>>;

    /// Get the MSF block (page) size in bytes.
    fn block_size(&self) -> u32;

    /// Get a reference to the parsed PDB Info stream (stream 1), if present.
    fn pdb_info(&self) -> Option<&PdbInfoStream>;

    /// Get a reference to the parsed TPI stream (stream 2), if present.
    fn tpi_stream(&self) -> Option<&TpiStream>;

    /// Get a reference to the parsed DBI stream (stream 3), if present.
    fn dbi_stream(&self) -> Option<&DbiStream>;

    /// Get a reference to the parsed IPI stream (stream 4), if present.
    fn ipi_stream(&self) -> Option<&IpiStream>;

    /// Resolve a type index to a type record.
    ///
    /// Type indices < 0x1000 are simple/primitive types. Indices in the
    /// TPI range [type_index_begin, type_index_end) are looked up in the
    /// TPI stream; indices in the IPI range are looked up in the IPI stream.
    fn get_type(&self, type_index: u32) -> Option<&TypeRecord>;

    /// Get the total number of type records in the TPI stream.
    fn type_count(&self) -> usize;

    /// Check whether the PDB has a DBI stream (debug information).
    fn has_debug_info(&self) -> bool;

    /// Get the PDB GUID as a formatted string.
    fn guid_string(&self) -> Option<String>;

    /// Get the PDB age (incremented on each build).
    fn age(&self) -> Option<u32>;

    /// Get the PDB signature (time-date stamp).
    fn signature(&self) -> Option<u32>;

    /// Get the machine type from the DBI header.
    fn machine_type(&self) -> Option<u16>;

    /// Check if a type index refers to a simple/primitive type (index < 0x1000).
    fn is_simple_type(type_index: u32) -> bool
    where
        Self: Sized,
    {
        type_index < 0x1000
    }

    /// Check if a type index falls in the TPI range.
    fn is_tpi_type(&self, type_index: u32) -> bool;

    /// Check if a type index falls in the IPI range.
    fn is_ipi_type(&self, type_index: u32) -> bool;
}

// =============================================================================
// PdbReaderContext -- concrete implementation of AbstractPdb
// =============================================================================
/// A concrete PDB reader context holding all parsed streams.
///
/// This implements [`AbstractPdb`] and provides the standard way to
/// interact with a parsed PDB file. It wraps the MSF container and all
/// four standard streams (Info, TPI, DBI, IPI).
pub struct PdbReaderContext {
    /// The parsed MSF container.
    pub msf: MsfFile,
    /// The PDB Info stream (stream 1).
    pub info: Option<PdbInfoStream>,
    /// The TPI stream (stream 2).
    pub tpi: Option<TpiStream>,
    /// The DBI stream (stream 3).
    pub dbi: Option<DbiStream>,
    /// The IPI stream (stream 4).
    pub ipi: Option<IpiStream>,
    /// Cached type index to name mapping (built from TPI).
    pub(crate) type_names: HashMap<u32, String>,
}

impl PdbReaderContext {
    /// Parse a PDB from raw bytes and build the context.
    pub fn parse(data: &[u8]) -> Result<Self, PdbException> {
        let msf = parse_msf(data)?;

        let info = msf
            .read_stream(1)
            .and_then(|d| parse_pdb_info_stream(&d).ok());

        let tpi = msf
            .read_stream(2)
            .and_then(|d| parse_tpi_stream(&d).ok());

        let ipi = msf
            .read_stream(4)
            .and_then(|d| parse_ipi_stream(&d).ok());

        let dbi = msf
            .read_stream(3)
            .and_then(|d| parse_dbi_stream(&d).ok());

        let type_names = Self::build_type_name_cache(&tpi);

        Ok(Self { msf, info, tpi, dbi, ipi, type_names })
    }

    /// Open a PDB from a file path and parse it.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, PdbException> {
        let data = std::fs::read(path.as_ref())?;
        Self::parse(&data)
    }

    /// Build a type index to name mapping cache from the TPI stream.
    fn build_type_name_cache(tpi: &Option<TpiStream>) -> HashMap<u32, String> {
        let mut map = HashMap::new();
        if let Some(ref tpi) = tpi {
            let base_index = tpi.type_index_begin;
            for (i, rec) in tpi.types.iter().enumerate() {
                let ti = base_index + i as u32;
                if let Some(name) = Self::type_record_name(rec) {
                    map.insert(ti, name);
                }
            }
        }
        map
    }

    /// Extract the name from a type record, if it has one.
    fn type_record_name(record: &TypeRecord) -> Option<String> {
        match record {
            TypeRecord::Class(c) => Some(c.name.clone()),
            TypeRecord::Structure(s) => Some(s.name.clone()),
            TypeRecord::Union(u) => Some(u.name.clone()),
            TypeRecord::Enum(e) => Some(e.name.clone()),
            TypeRecord::Array(a) => Some(a.name.clone()),
            _ => None,
        }
    }

    /// Get the name of a type by its type index.
    pub fn get_type_name(&self, type_index: u32) -> Option<&str> {
        self.type_names.get(&type_index).map(|s| s.as_str())
    }

    /// Get all type records from the TPI stream.
    pub fn type_records(&self) -> &[TypeRecord] {
        self.tpi.as_ref().map(|t| t.types.as_slice()).unwrap_or(&[])
    }

    /// Get all item records from the IPI stream.
    pub fn item_records(&self) -> &[TypeRecord] {
        self.ipi.as_ref().map(|i| i.items.as_slice()).unwrap_or(&[])
    }

    /// Collect all global symbols.
    pub fn global_symbols(&self) -> Option<Vec<SymbolRecord>> {
        let gsi_index = self.dbi.as_ref().map(|d| d.gsi as u32)?;
        let data = self.msf.read_stream(gsi_index)?;
        Some(SymbolStream::new(&data).collect())
    }

    /// Collect all public symbols.
    pub fn public_symbols(&self) -> Option<Vec<SymbolRecord>> {
        let psi_index = self.dbi.as_ref().map(|d| d.psi as u32)?;
        let data = self.msf.read_stream(psi_index)?;
        Some(SymbolStream::new(&data).collect())
    }

    /// Convert this context into a [`PdbFile`].
    pub fn into_pdb_file(self) -> PdbFile {
        // Read global/public symbol streams
        let global_symbol_stream = self
            .dbi
            .as_ref()
            .and_then(|d| self.msf.read_stream(d.gsi as u32));
        let public_symbol_stream = self
            .dbi
            .as_ref()
            .and_then(|d| self.msf.read_stream(d.psi as u32));

        PdbFile {
            msf: self.msf,
            info: self.info,
            tpi: self.tpi,
            dbi: self.dbi,
            ipi: self.ipi,
            global_symbol_stream,
            public_symbol_stream,
        }
    }

    /// Get the PDB GUID as a hex string (delegates to info stream).
    pub fn guid_string_from_info(info: &PdbInfoStream) -> String {
        format!(
            "{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
            u32::from_le_bytes([info.guid[0], info.guid[1], info.guid[2], info.guid[3]]),
            u16::from_le_bytes([info.guid[4], info.guid[5]]),
            u16::from_le_bytes([info.guid[6], info.guid[7]]),
            info.guid[8],
            info.guid[9],
            info.guid[10],
            info.guid[11],
            info.guid[12],
            info.guid[13],
            info.guid[14],
            info.guid[15],
        )
    }
}

impl AbstractPdb for PdbReaderContext {
    fn num_streams(&self) -> usize {
        self.msf.num_streams()
    }

    fn stream_size(&self, stream_index: u32) -> Option<u32> {
        self.msf.stream_size(stream_index)
    }

    fn read_stream(&self, stream_index: u32) -> Option<Vec<u8>> {
        self.msf.read_stream(stream_index)
    }

    fn block_size(&self) -> u32 {
        self.msf.block_size
    }

    fn pdb_info(&self) -> Option<&PdbInfoStream> {
        self.info.as_ref()
    }

    fn tpi_stream(&self) -> Option<&TpiStream> {
        self.tpi.as_ref()
    }

    fn dbi_stream(&self) -> Option<&DbiStream> {
        self.dbi.as_ref()
    }

    fn ipi_stream(&self) -> Option<&IpiStream> {
        self.ipi.as_ref()
    }

    fn get_type(&self, type_index: u32) -> Option<&TypeRecord> {
        if let Some(ref tpi) = self.tpi {
            if let Some(idx) = type_index.checked_sub(tpi.type_index_begin) {
                if let Some(rec) = tpi.types.get(idx as usize) {
                    return Some(rec);
                }
            }
        }
        if let Some(ref ipi) = self.ipi {
            if let Some(idx) = type_index.checked_sub(ipi.type_index_begin) {
                if let Some(rec) = ipi.items.get(idx as usize) {
                    return Some(rec);
                }
            }
        }
        None
    }

    fn type_count(&self) -> usize {
        self.tpi.as_ref().map(|t| t.types.len()).unwrap_or(0)
    }

    fn has_debug_info(&self) -> bool {
        self.dbi.is_some()
    }

    fn guid_string(&self) -> Option<String> {
        self.info.as_ref().map(Self::guid_string_from_info)
    }

    fn age(&self) -> Option<u32> {
        self.info.as_ref().map(|i| i.age)
    }

    fn signature(&self) -> Option<u32> {
        self.info.as_ref().map(|i| i.signature)
    }

    fn machine_type(&self) -> Option<u16> {
        self.dbi.as_ref().map(|d| d.machine)
    }

    fn is_tpi_type(&self, type_index: u32) -> bool {
        if let Some(ref tpi) = self.tpi {
            type_index >= tpi.type_index_begin && type_index < tpi.type_index_end
        } else {
            false
        }
    }

    fn is_ipi_type(&self, type_index: u32) -> bool {
        if let Some(ref ipi) = self.ipi {
            type_index >= ipi.type_index_begin && type_index < ipi.type_index_end
        } else {
            false
        }
    }
}

impl fmt::Debug for PdbReaderContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PdbReaderContext")
            .field("num_streams", &self.num_streams())
            .field("type_count", &self.type_count())
            .field("has_debug_info", &self.has_debug_info())
            .field("guid", &self.guid_string())
            .finish()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_simple_type() {
        assert!(PdbReaderContext::is_simple_type(0x0003)); // int
        assert!(PdbReaderContext::is_simple_type(0x0010)); // float
        assert!(!PdbReaderContext::is_simple_type(0x1000)); // TPI range
        assert!(!PdbReaderContext::is_simple_type(0x2001));
    }

    #[test]
    fn test_type_record_name_class() {
        let rec = TypeRecord::Class(super::super::ClassType {
            count: 1,
            property: super::super::TypeProperty::empty(),
            field_list_type_index: 0,
            derived_type_index: 0,
            vshape_type_index: 0,
            size: 4,
            name: "MyClass".to_string(),
            mangled_name: None,
        });
        assert_eq!(
            PdbReaderContext::type_record_name(&rec),
            Some("MyClass".to_string())
        );
    }

    #[test]
    fn test_type_record_name_structure() {
        let rec = TypeRecord::Structure(super::super::StructureType {
            count: 1,
            property: super::super::TypeProperty::empty(),
            field_list_type_index: 0,
            derived_type_index: 0,
            vshape_type_index: 0,
            size: 8,
            name: "MyStruct".to_string(),
            mangled_name: None,
        });
        assert_eq!(
            PdbReaderContext::type_record_name(&rec),
            Some("MyStruct".to_string())
        );
    }

    #[test]
    fn test_type_record_name_no_name() {
        let rec = TypeRecord::Pointer(super::super::PointerType {
            underlying_type_index: 0,
            attributes: 0,
            pointer_mode: super::super::PointerMode::Pointer,
            size: 4,
            is_const: false,
            is_volatile: false,
            is_unaligned: false,
            is_flat: false,
            pointer_kind: super::super::PointerKind::Flat32,
        });
        assert_eq!(PdbReaderContext::type_record_name(&rec), None);
    }

    #[test]
    fn test_guid_format() {
        let info = PdbInfoStream {
            version: 20000404,
            signature: 0xDEADBEEF,
            age: 1,
            guid: [0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC],
            names: vec![],
            named_streams: vec![],
        };
        let guid = PdbReaderContext::guid_string_from_info(&info);
        assert!(guid.contains("DDCCBBAA"));
        assert!(guid.contains("2211"));
        assert!(guid.contains("4433"));
    }
}
