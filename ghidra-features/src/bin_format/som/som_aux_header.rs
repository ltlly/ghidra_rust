//! SOM auxiliary header types ported from Ghidra's `SomAuxHeader.java`,
//! `SomAuxHeaderFactory.java`, `SomExecAuxHeader.java`,
//! `SomLinkerFootprintAuxHeader.java`, `SomProductSpecificsAuxHeader.java`,
//! and `SomUnknownAuxHeader.java`.
//!
//! Provides the trait and concrete implementations for SOM auxiliary headers.
//!
//! Reference: [The 32-bit PA-RISC Run-time Architecture Document](https://web.archive.org/web/20050502101134/http://devresource.hp.com/drc/STK/docs/archive/rad_11_0_32.pdf)

use std::fmt;
use std::io;

use crate::bin_format::binary_reader::BinaryReader;
use crate::bin_format::binary_writer::{BinaryWritable, BinaryWriter};
use crate::bin_format::types::{DataTypeDescription, StructConverter};

use super::som_constants::SomConstants;
use super::som_exception::SomException;
use super::som_aux_id::{SomAuxId, SOM_AUX_ID_SIZE};
use super::som_sys_clock::SomSysClock;

// ---------------------------------------------------------------------------
// SomAuxHeader trait
// ---------------------------------------------------------------------------

/// Trait for SOM auxiliary headers.
///
/// Every SOM auxiliary header starts with a `SomAuxId` identifier followed
/// by type-specific data. This trait provides a common interface.
pub trait SomAuxHeader: fmt::Debug + StructConverter {
    /// Returns a reference to this header's `SomAuxId`.
    fn aux_id(&self) -> &SomAuxId;

    /// Returns the total length of this auxiliary header in bytes,
    /// including the aux_id.
    fn length(&self) -> u64 {
        self.aux_id().length as u64 + SOM_AUX_ID_SIZE as u64
    }

    /// Returns the auxiliary header type.
    fn aux_type(&self) -> u16 {
        self.aux_id().aux_type
    }
}

// ---------------------------------------------------------------------------
// SomExecAuxHeader
// ---------------------------------------------------------------------------

/// Represents a SOM `som_exec_auxhdr` structure.
///
/// Contains executable layout information: text/data/BSS sizes and offsets.
///
/// Ported from `ghidra.app.util.bin.format.som.SomExecAuxHeader`.
#[derive(Debug, Clone)]
pub struct SomExecAuxHeader {
    /// The aux_id header.
    pub id: SomAuxId,
    /// Text size in bytes.
    pub exec_text_size: u32,
    /// Offset of text in memory.
    pub exec_text_mem: u32,
    /// Location of text in file.
    pub exec_text_file: u32,
    /// Initialized data size in bytes.
    pub exec_data_size: u32,
    /// Offset of data in memory.
    pub exec_data_mem: u32,
    /// Location of data in file.
    pub exec_data_file: u32,
    /// Uninitialized data (BSS) size in bytes.
    pub exec_bss_size: u32,
    /// Offset of entrypoint.
    pub exec_entry: u32,
    /// Loader flags.
    pub exec_flags: u32,
    /// BSS initialization value.
    pub exec_bss_fill: u32,
}

impl SomExecAuxHeader {
    /// Parse a `SomExecAuxHeader` from a binary reader.
    pub fn parse(reader: &mut BinaryReader) -> Result<Self, SomException> {
        let id = SomAuxId::parse(reader)?;
        let exec_text_size = reader.read_next_u32().map_err(SomException::from)?;
        let exec_text_mem = reader.read_next_u32().map_err(SomException::from)?;
        let exec_text_file = reader.read_next_u32().map_err(SomException::from)?;
        let exec_data_size = reader.read_next_u32().map_err(SomException::from)?;
        let exec_data_mem = reader.read_next_u32().map_err(SomException::from)?;
        let exec_data_file = reader.read_next_u32().map_err(SomException::from)?;
        let exec_bss_size = reader.read_next_u32().map_err(SomException::from)?;
        let exec_entry = reader.read_next_u32().map_err(SomException::from)?;
        let exec_flags = reader.read_next_u32().map_err(SomException::from)?;
        let exec_bss_fill = reader.read_next_u32().map_err(SomException::from)?;

        Ok(Self {
            id,
            exec_text_size,
            exec_text_mem,
            exec_text_file,
            exec_data_size,
            exec_data_mem,
            exec_data_file,
            exec_bss_size,
            exec_entry,
            exec_flags,
            exec_bss_fill,
        })
    }
}

impl SomAuxHeader for SomExecAuxHeader {
    fn aux_id(&self) -> &SomAuxId {
        &self.id
    }
}

impl StructConverter for SomExecAuxHeader {
    fn to_data_type(&self) -> DataTypeDescription {
        DataTypeDescription::Struct {
            name: "som_exec_auxhdr".to_string(),
            size: 0,
            fields: vec![
                ("som_auxhdr".into(), self.id.to_data_type()),
                ("exec_tsize".into(), DataTypeDescription::DWord),
                ("exec_tmem".into(), DataTypeDescription::DWord),
                ("exec_tfile".into(), DataTypeDescription::DWord),
                ("exec_dsize".into(), DataTypeDescription::DWord),
                ("exec_dmem".into(), DataTypeDescription::DWord),
                ("exec_dfile".into(), DataTypeDescription::DWord),
                ("exec_bsize".into(), DataTypeDescription::DWord),
                ("exec_entry".into(), DataTypeDescription::DWord),
                ("exec_flags".into(), DataTypeDescription::DWord),
                ("exec_bfill".into(), DataTypeDescription::DWord),
            ],
        }
    }
}

impl BinaryWritable for SomExecAuxHeader {
    fn write_to(&self, writer: &mut BinaryWriter) -> io::Result<()> {
        self.id.write_to(writer)?;
        writer.write_u32(self.exec_text_size);
        writer.write_u32(self.exec_text_mem);
        writer.write_u32(self.exec_text_file);
        writer.write_u32(self.exec_data_size);
        writer.write_u32(self.exec_data_mem);
        writer.write_u32(self.exec_data_file);
        writer.write_u32(self.exec_bss_size);
        writer.write_u32(self.exec_entry);
        writer.write_u32(self.exec_flags);
        writer.write_u32(self.exec_bss_fill);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// SomLinkerFootprintAuxHeader
// ---------------------------------------------------------------------------

/// Represents a SOM `linker_footprint` structure.
///
/// Ported from `ghidra.app.util.bin.format.som.SomLinkerFootprintAuxHeader`.
#[derive(Debug, Clone)]
pub struct SomLinkerFootprintAuxHeader {
    /// The aux_id header.
    pub id: SomAuxId,
    /// Product ID string (12 bytes).
    pub product_id: String,
    /// Version ID string (12 bytes).
    pub version_id: String,
    /// Linker timestamp.
    pub htime: SomSysClock,
}

impl SomLinkerFootprintAuxHeader {
    /// Parse a `SomLinkerFootprintAuxHeader` from a binary reader.
    pub fn parse(reader: &mut BinaryReader) -> Result<Self, SomException> {
        let id = SomAuxId::parse(reader)?;
        let product_id = reader.read_next_fixed_string(12)?;
        let version_id = reader.read_next_fixed_string(12)?;
        let htime = SomSysClock::parse(reader)?;

        Ok(Self {
            id,
            product_id,
            version_id,
            htime,
        })
    }
}

impl SomAuxHeader for SomLinkerFootprintAuxHeader {
    fn aux_id(&self) -> &SomAuxId {
        &self.id
    }
}

impl StructConverter for SomLinkerFootprintAuxHeader {
    fn to_data_type(&self) -> DataTypeDescription {
        DataTypeDescription::Struct {
            name: "linker_footprint".to_string(),
            size: 0,
            fields: vec![
                ("som_auxhdr".into(), self.id.to_data_type()),
                ("product_id".into(), DataTypeDescription::Array {
                    element: Box::new(DataTypeDescription::Byte),
                    count: 12,
                }),
                ("version_id".into(), DataTypeDescription::Array {
                    element: Box::new(DataTypeDescription::Byte),
                    count: 8,
                }),
                ("htime".into(), self.htime.to_data_type()),
            ],
        }
    }
}

impl BinaryWritable for SomLinkerFootprintAuxHeader {
    fn write_to(&self, writer: &mut BinaryWriter) -> io::Result<()> {
        self.id.write_to(writer)?;
        // Write product_id as 12 bytes (padded with zeros)
        let mut pid_bytes = [0u8; 12];
        let pid_src = self.product_id.as_bytes();
        let copy_len = pid_src.len().min(12);
        pid_bytes[..copy_len].copy_from_slice(&pid_src[..copy_len]);
        writer.write_bytes(&pid_bytes);

        // Write version_id as 12 bytes (padded with zeros)
        let mut vid_bytes = [0u8; 12];
        let vid_src = self.version_id.as_bytes();
        let copy_len = vid_src.len().min(12);
        vid_bytes[..copy_len].copy_from_slice(&vid_src[..copy_len]);
        writer.write_bytes(&vid_bytes);

        self.htime.write_to(writer)?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// SomProductSpecificsAuxHeader
// ---------------------------------------------------------------------------

/// Represents a SOM "product specifics" auxiliary header.
///
/// Contains arbitrary product-specific data.
///
/// Ported from `ghidra.app.util.bin.format.som.SomProductSpecificsAuxHeader`.
#[derive(Debug, Clone)]
pub struct SomProductSpecificsAuxHeader {
    /// The aux_id header.
    pub id: SomAuxId,
    /// The product-specific bytes.
    pub bytes: Vec<u8>,
}

impl SomProductSpecificsAuxHeader {
    /// Parse a `SomProductSpecificsAuxHeader` from a binary reader.
    pub fn parse(reader: &mut BinaryReader) -> Result<Self, SomException> {
        let id = SomAuxId::parse(reader)?;
        let mut bytes = vec![0u8; id.length as usize];
        reader
            .read_exact_bytes(&mut bytes)
            .map_err(SomException::from)?;

        Ok(Self { id, bytes })
    }
}

impl SomAuxHeader for SomProductSpecificsAuxHeader {
    fn aux_id(&self) -> &SomAuxId {
        &self.id
    }
}

impl StructConverter for SomProductSpecificsAuxHeader {
    fn to_data_type(&self) -> DataTypeDescription {
        DataTypeDescription::Struct {
            name: "som_product_specifics_auxhdr".to_string(),
            size: 0,
            fields: vec![
                ("som_auxhdr".into(), self.id.to_data_type()),
                ("bytes".into(), DataTypeDescription::Array {
                    element: Box::new(DataTypeDescription::Byte),
                    count: self.id.length as usize,
                }),
            ],
        }
    }
}

impl BinaryWritable for SomProductSpecificsAuxHeader {
    fn write_to(&self, writer: &mut BinaryWriter) -> io::Result<()> {
        self.id.write_to(writer)?;
        writer.write_bytes(&self.bytes);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// SomUnknownAuxHeader
// ---------------------------------------------------------------------------

/// Represents an unknown SOM auxiliary header.
///
/// Used when the auxiliary header type is not recognized.
///
/// Ported from `ghidra.app.util.bin.format.som.SomUnknownAuxHeader`.
#[derive(Debug, Clone)]
pub struct SomUnknownAuxHeader {
    /// The aux_id header.
    pub id: SomAuxId,
    /// The raw bytes of the unknown auxiliary header.
    pub bytes: Vec<u8>,
}

impl SomUnknownAuxHeader {
    /// Parse a `SomUnknownAuxHeader` from a binary reader.
    pub fn parse(reader: &mut BinaryReader) -> Result<Self, SomException> {
        let id = SomAuxId::parse(reader)?;
        let mut bytes = vec![0u8; id.length as usize];
        reader
            .read_exact_bytes(&mut bytes)
            .map_err(SomException::from)?;

        Ok(Self { id, bytes })
    }
}

impl SomAuxHeader for SomUnknownAuxHeader {
    fn aux_id(&self) -> &SomAuxId {
        &self.id
    }
}

impl StructConverter for SomUnknownAuxHeader {
    fn to_data_type(&self) -> DataTypeDescription {
        DataTypeDescription::Struct {
            name: "som_unknown_auxhdr".to_string(),
            size: 0,
            fields: vec![
                ("som_auxhdr".into(), self.id.to_data_type()),
                ("bytes".into(), DataTypeDescription::Array {
                    element: Box::new(DataTypeDescription::Byte),
                    count: self.id.length as usize,
                }),
            ],
        }
    }
}

impl BinaryWritable for SomUnknownAuxHeader {
    fn write_to(&self, writer: &mut BinaryWriter) -> io::Result<()> {
        self.id.write_to(writer)?;
        writer.write_bytes(&self.bytes);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// SomAuxHeaderFactory
// ---------------------------------------------------------------------------

/// Reads the next auxiliary header from a binary reader.
///
/// Inspects the `aux_id` type field and returns the appropriate concrete type.
///
/// Ported from `ghidra.app.util.bin.format.som.SomAuxHeaderFactory`.
pub fn read_next_aux_header(
    reader: &mut BinaryReader,
) -> Result<Box<dyn SomAuxHeader>, SomException> {
    let orig_pos = reader.cursor();
    let aux_id = SomAuxId::parse(reader)?;
    reader.set_cursor(orig_pos);

    match aux_id.aux_type {
        SomConstants::EXEC_AUXILIARY_HEADER => {
            Ok(Box::new(SomExecAuxHeader::parse(reader)?))
        }
        SomConstants::LINKER_FOOTPRINT => {
            Ok(Box::new(SomLinkerFootprintAuxHeader::parse(reader)?))
        }
        SomConstants::PRODUCT_SPECIFICS => {
            Ok(Box::new(SomProductSpecificsAuxHeader::parse(reader)?))
        }
        _ => {
            Ok(Box::new(SomUnknownAuxHeader::parse(reader)?))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_exec_aux_header_bytes() -> Vec<u8> {
        let mut data = Vec::new();
        // aux_id: type=EXEC_AUXILIARY_HEADER(4), length=0x28 (10 dwords)
        let bitfield: u32 = 4; // type=4
        data.extend_from_slice(&bitfield.to_le_bytes());
        data.extend_from_slice(&0x28u32.to_le_bytes()); // length
        // exec fields
        data.extend_from_slice(&0x1000u32.to_le_bytes()); // text_size
        data.extend_from_slice(&0x2000u32.to_le_bytes()); // text_mem
        data.extend_from_slice(&0x100u32.to_le_bytes());  // text_file
        data.extend_from_slice(&0x800u32.to_le_bytes());  // data_size
        data.extend_from_slice(&0x3000u32.to_le_bytes()); // data_mem
        data.extend_from_slice(&0x1100u32.to_le_bytes()); // data_file
        data.extend_from_slice(&0x400u32.to_le_bytes());  // bss_size
        data.extend_from_slice(&0x2000u32.to_le_bytes()); // entry
        data.extend_from_slice(&0x1u32.to_le_bytes());    // flags
        data.extend_from_slice(&0u32.to_le_bytes());      // bss_fill
        data
    }

    #[test]
    fn test_parse_exec_aux_header() {
        let data = make_exec_aux_header_bytes();
        let mut reader = BinaryReader::from_bytes(&data, true);
        let header = SomExecAuxHeader::parse(&mut reader).unwrap();

        assert_eq!(header.aux_type(), SomConstants::EXEC_AUXILIARY_HEADER);
        assert_eq!(header.exec_text_size, 0x1000);
        assert_eq!(header.exec_text_mem, 0x2000);
        assert_eq!(header.exec_text_file, 0x100);
        assert_eq!(header.exec_data_size, 0x800);
        assert_eq!(header.exec_data_mem, 0x3000);
        assert_eq!(header.exec_data_file, 0x1100);
        assert_eq!(header.exec_bss_size, 0x400);
        assert_eq!(header.exec_entry, 0x2000);
        assert_eq!(header.exec_flags, 0x1);
        assert_eq!(header.exec_bss_fill, 0);
    }

    #[test]
    fn test_exec_aux_header_length() {
        let data = make_exec_aux_header_bytes();
        let mut reader = BinaryReader::from_bytes(&data, true);
        let header = SomExecAuxHeader::parse(&mut reader).unwrap();

        // total = aux_id length (0x28) + SOM_AUX_ID_SIZE (8) = 0x30
        assert_eq!(header.length(), 0x30);
    }

    #[test]
    fn test_exec_aux_header_struct_converter() {
        let data = make_exec_aux_header_bytes();
        let mut reader = BinaryReader::from_bytes(&data, true);
        let header = SomExecAuxHeader::parse(&mut reader).unwrap();

        let dt = header.to_data_type();
        match &dt {
            DataTypeDescription::Struct { name, fields, .. } => {
                assert_eq!(name, "som_exec_auxhdr");
                assert_eq!(fields.len(), 11);
            }
            _ => panic!("Expected Struct"),
        }
    }

    #[test]
    fn test_exec_aux_header_write_roundtrip() {
        let data = make_exec_aux_header_bytes();
        let mut reader = BinaryReader::from_bytes(&data, true);
        let header = SomExecAuxHeader::parse(&mut reader).unwrap();

        let mut writer = BinaryWriter::new(true);
        header.write_to(&mut writer).unwrap();
        let written = writer.into_vec();
        assert_eq!(written, data);
    }

    #[test]
    fn test_factory_reads_exec_aux_header() {
        let data = make_exec_aux_header_bytes();
        let mut reader = BinaryReader::from_bytes(&data, true);
        let header = read_next_aux_header(&mut reader).unwrap();

        assert_eq!(header.aux_type(), SomConstants::EXEC_AUXILIARY_HEADER);
        assert_eq!(header.length(), 0x30);
    }

    #[test]
    fn test_factory_reads_unknown_aux_header() {
        let mut data = Vec::new();
        // aux_id: type=99 (unknown), length=4
        let bitfield: u32 = 99;
        data.extend_from_slice(&bitfield.to_le_bytes());
        data.extend_from_slice(&4u32.to_le_bytes());
        // 4 bytes of data
        data.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);

        let mut reader = BinaryReader::from_bytes(&data, true);
        let header = read_next_aux_header(&mut reader).unwrap();

        assert_eq!(header.aux_type(), 99);
        assert_eq!(header.length(), 12); // 4 + 8
    }

    #[test]
    fn test_unknown_aux_header_bytes() {
        let mut data = Vec::new();
        let bitfield: u32 = 99;
        data.extend_from_slice(&bitfield.to_le_bytes());
        data.extend_from_slice(&4u32.to_le_bytes());
        data.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);

        let mut reader = BinaryReader::from_bytes(&data, true);
        let header = SomUnknownAuxHeader::parse(&mut reader).unwrap();

        assert_eq!(header.bytes, vec![0xAA, 0xBB, 0xCC, 0xDD]);
    }

    #[test]
    fn test_product_specifics_aux_header() {
        let mut data = Vec::new();
        let bitfield: u32 = SomConstants::PRODUCT_SPECIFICS as u32;
        data.extend_from_slice(&bitfield.to_le_bytes());
        data.extend_from_slice(&8u32.to_le_bytes()); // length=8
        data.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);

        let mut reader = BinaryReader::from_bytes(&data, true);
        let header = SomProductSpecificsAuxHeader::parse(&mut reader).unwrap();

        assert_eq!(header.aux_type(), SomConstants::PRODUCT_SPECIFICS);
        assert_eq!(header.bytes, vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
    }

    #[test]
    fn test_linker_footprint_aux_header() {
        let mut data = Vec::new();
        let bitfield: u32 = SomConstants::LINKER_FOOTPRINT as u32;
        data.extend_from_slice(&bitfield.to_le_bytes());
        data.extend_from_slice(&28u32.to_le_bytes()); // length = 12 + 12 + 8 = 32, but aux says 28
        // product_id: 12 bytes
        data.extend_from_slice(b"GCC\0\0\0\0\0\0\0\0\0");
        // version_id: 12 bytes
        data.extend_from_slice(b"1.0\0\0\0\0\0\0\0\0\0");
        // SomSysClock: seconds + nano
        data.extend_from_slice(&1000u32.to_le_bytes());
        data.extend_from_slice(&500u32.to_le_bytes());

        let mut reader = BinaryReader::from_bytes(&data, true);
        let header = SomLinkerFootprintAuxHeader::parse(&mut reader).unwrap();

        assert_eq!(header.aux_type(), SomConstants::LINKER_FOOTPRINT);
        assert!(header.product_id.starts_with("GCC"));
        assert!(header.version_id.starts_with("1.0"));
        assert_eq!(header.htime.seconds(), 1000);
    }

    #[test]
    fn test_aux_header_trait_object() {
        let data = make_exec_aux_header_bytes();
        let mut reader = BinaryReader::from_bytes(&data, true);
        let header: Box<dyn SomAuxHeader> = read_next_aux_header(&mut reader).unwrap();

        assert_eq!(header.aux_type(), SomConstants::EXEC_AUXILIARY_HEADER);
        assert_eq!(header.length(), 0x30);
    }
}
