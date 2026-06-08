//! Packed item serialization and deserialization.
//!
//! Provides [`ItemSerializer`] for writing compressed "packed" files and
//! [`ItemDeserializer`] for reading them. A packed file contains a binary
//! header followed by deflated item data in a zip entry.
//!
//! The packed file format:
//! ```text
//! [ObjectOutputStream header]
//!   magic:    i64  (0x2e30212634e92c20)
//!   version:  i32  (1)
//!   itemName: UTF string
//!   contentType: UTF string
//!   fileType: i32
//!   length:   i64
//! [ZipOutputStream]
//!   entry "FOLDER_ITEM" containing deflated content bytes
//! ```
//!
//! Corresponds to `ghidra.framework.store.local.ItemSerializer` and
//! `ghidra.framework.store.local.ItemDeserializer`.

use std::fmt;
use std::fs::File;
use std::io::{self, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::Path;

use crate::error::GhidraError;
use crate::generic::task::TaskMonitor;

use super::StoreResult;

// ============================================================================
// Constants
// ============================================================================

/// Magic number identifying a Ghidra packed file.
/// Read from bytes 6..14 of the file (after the Java ObjectOutputStream header).
pub const MAGIC_NUMBER: i64 = 0x2e30212634e92c20u64 as i64;

/// Current packed file format version.
pub const FORMAT_VERSION: i32 = 1;

/// Name of the zip entry containing the item data.
pub const ZIP_ENTRY_NAME: &str = "FOLDER_ITEM";

/// I/O buffer size for streaming operations.
pub const IO_BUFFER_SIZE: usize = 32 * 1024;

/// Position of the magic number in the file (Java ObjectOutputStream writes
/// a 4-byte magic + 2-byte version before our data).
const MAGIC_NUMBER_POS: u64 = 6;

/// Size of the magic number field.
const MAGIC_NUMBER_SIZE: usize = 8;

// ============================================================================
// PackedFileHeader
// ============================================================================

/// Metadata parsed from a packed file header.
#[derive(Debug, Clone)]
pub struct PackedFileHeader {
    /// Original item name.
    pub item_name: String,
    /// Content type string (may be empty).
    pub content_type: String,
    /// File type code.
    pub file_type: i32,
    /// Uncompressed data length.
    pub length: i64,
}

// ============================================================================
// ItemSerializer
// ============================================================================

/// Facilitates compressing and writing a data stream to a packed file.
///
/// The resulting packed file contains metadata (item name, content type,
/// file type, data length) followed by deflated content.
///
/// Corresponds to `ghidra.framework.store.local.ItemSerializer`.
pub struct ItemSerializer;

impl ItemSerializer {
    /// Write a packed file containing the given item content.
    ///
    /// Reads `length` bytes from `content` and writes them (deflated)
    /// into `packed_file`. A `TaskMonitor` is used to report progress
    /// and support cancellation.
    pub fn output_item<W: Write + Seek, R: Read>(
        item_name: &str,
        content_type: &str,
        file_type: i32,
        length: i64,
        content: &mut R,
        packed_file: &mut W,
        monitor: &TaskMonitor,
    ) -> StoreResult<()> {
        // Write the Java ObjectOutputStream-compatible header.
        // ObjectOutputStream starts with: 0xACED (magic) + 0x0005 (version)
        Self::write_oo_stream_header(packed_file)?;

        // Write our custom fields (using big-endian, matching Java's DataOutputStream)
        write_long(packed_file, MAGIC_NUMBER)?;
        write_int(packed_file, FORMAT_VERSION)?;
        write_utf(packed_file, item_name)?;
        write_utf(packed_file, content_type)?;
        write_int(packed_file, file_type)?;
        write_long(packed_file, length)?;
        packed_file.flush()?;

        // Write zip stream with a single deflated entry
        Self::write_zip_content(packed_file, content, length, monitor)?;

        Ok(())
    }

    /// Check whether `path` points to a packed file by reading the magic
    /// number.
    pub fn is_packed_file(path: &Path) -> io::Result<bool> {
        let mut file = File::open(path)?;
        Self::is_packed_stream(&mut file)
    }

    /// Check whether the current position of `reader` is a packed file
    /// by reading the magic number.
    ///
    /// This method does **not** close or reset the reader position.
    pub fn is_packed_stream<R: Read>(reader: &mut R) -> io::Result<bool> {
        // Skip to the magic number position
        let mut skip_buf = vec![0u8; MAGIC_NUMBER_POS as usize];
        reader.read_exact(&mut skip_buf)?;

        let mut magic_bytes = [0u8; MAGIC_NUMBER_SIZE];
        reader.read_exact(&mut magic_bytes)?;
        let magic = i64::from_be_bytes(magic_bytes);
        Ok(magic == MAGIC_NUMBER)
    }

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    /// Write the Java ObjectOutputStream stream header (magic + version).
    fn write_oo_stream_header<W: Write>(writer: &mut W) -> io::Result<()> {
        // Java ObjectOutputStream magic: 0xACED
        writer.write_all(&[0xAC, 0xED])?;
        // Java ObjectOutputStream version: 0x0005
        writer.write_all(&[0x00, 0x05])?;
        Ok(())
    }

    /// Write the zip-compressed content.
    fn write_zip_content<W: Write, R: Read>(
        writer: &mut W,
        content: &mut R,
        length: i64,
        monitor: &TaskMonitor,
    ) -> StoreResult<()> {
        use flate2::write::DeflateEncoder;
        use flate2::Compression;

        // We implement a minimal zip file with a single deflated entry.
        // ZIP local file header + deflated data + data descriptor + central dir + EOCD.

        let start_pos = stream_position(writer)?;

        // --- Local file header ---
        let lfh_offset = start_pos;
        writer.write_all(&[0x50, 0x4B, 0x03, 0x04])?; // local file header signature
        write_u16_le(writer, 20)?; // version needed (2.0)
        write_u16_le(writer, 0x0800)?; // general purpose: UTF-8
        write_u16_le(writer, 8)?; // compression method: deflate
        write_u16_le(writer, 0)?; // last mod time
        write_u16_le(writer, 0)?; // last mod date
        write_u32_le(writer, 0)?; // CRC-32 (filled in later)
        write_u32_le(writer, 0)?; // compressed size (filled in later)
        write_u32_le(writer, 0)?; // uncompressed size (filled in later)
        let name_bytes = ZIP_ENTRY_NAME.as_bytes();
        write_u16_le(writer, name_bytes.len() as u16)?; // filename length
        write_u16_le(writer, 0)?; // extra field length
        writer.write_all(name_bytes)?;

        // --- Deflated data ---
        let data_start = stream_position(writer)?;
        let mut encoder = DeflateEncoder::new(writer, Compression::default());
        let mut crc = crc32fast::Hasher::new();
        let mut total_written: i64 = 0;
        let mut buf = [0u8; IO_BUFFER_SIZE];

        loop {
            monitor
                .check_cancelled()
                .map_err(|e| GhidraError::Other(anyhow::anyhow!("Cancelled: {}", e)))?;
            let n = content.read(&mut buf)?;
            if n == 0 {
                break;
            }
            crc.update(&buf[..n]);
            encoder.write_all(&buf[..n])?;
            total_written += n as i64;
            monitor.set_progress(total_written);
        }
        let writer = encoder.finish()?;
        let data_end = stream_position(writer)?;
        let crc_val = crc.finalize();
        let compressed_size = (data_end - data_start) as u32;
        let uncompressed_size = total_written as u32;

        if total_written != length {
            return Err(GhidraError::IoError(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!(
                    "Did not write all content - written length is {}, expected {}",
                    total_written, length
                ),
            )));
        }

        // --- Data descriptor ---
        writer.write_all(&[0x50, 0x4B, 0x07, 0x08])?; // data descriptor signature
        write_u32_le(writer, crc_val)?;
        write_u32_le(writer, compressed_size)?;
        write_u32_le(writer, uncompressed_size)?;

        let lfh_end = stream_position(writer)?;

        // --- Central directory ---
        let cd_offset = lfh_end;
        writer.write_all(&[0x50, 0x4B, 0x01, 0x02])?; // central dir signature
        write_u16_le(writer, 20)?; // version made by
        write_u16_le(writer, 20)?; // version needed
        write_u16_le(writer, 0x0800)?; // general purpose
        write_u16_le(writer, 8)?; // compression method
        write_u16_le(writer, 0)?; // last mod time
        write_u16_le(writer, 0)?; // last mod date
        write_u32_le(writer, crc_val)?;
        write_u32_le(writer, compressed_size)?;
        write_u32_le(writer, uncompressed_size)?;
        write_u16_le(writer, name_bytes.len() as u16)?;
        write_u16_le(writer, 0)?; // extra length
        write_u16_le(writer, 0)?; // comment length
        write_u16_le(writer, 0)?; // disk start
        write_u16_le(writer, 0)?; // internal attrs
        write_u32_le(writer, 0)?; // external attrs
        write_u32_le(writer, lfh_offset as u32)?; // relative offset
        writer.write_all(name_bytes)?;

        let cd_end = stream_position(writer)?;

        // --- End of central directory ---
        writer.write_all(&[0x50, 0x4B, 0x05, 0x06])?; // EOCD signature
        write_u16_le(writer, 0)?; // disk number
        write_u16_le(writer, 0)?; // disk with CD
        write_u16_le(writer, 1)?; // entries on disk
        write_u16_le(writer, 1)?; // total entries
        write_u32_le(writer, (cd_end - cd_offset) as u32)?; // CD size
        write_u32_le(writer, cd_offset as u32)?; // CD offset
        write_u16_le(writer, 0)?; // comment length

        writer.flush()?;
        Ok(())
    }
}

impl fmt::Debug for ItemSerializer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ItemSerializer").finish()
    }
}

// ============================================================================
// ItemDeserializer
// ============================================================================

/// Reads and decompresses a packed file created by [`ItemSerializer`].
///
/// After construction, the header metadata (item name, content type,
/// file type, data length) is available. The compressed content can be
/// extracted once via [`save_item`](ItemDeserializer::save_item).
///
/// Corresponds to `ghidra.framework.store.local.ItemDeserializer`.
pub struct ItemDeserializer {
    reader: Option<Box<dyn Read + Send>>,
    header: PackedFileHeader,
    saved: bool,
}

impl ItemDeserializer {
    /// Open a packed file and parse its header.
    pub fn open(path: &Path) -> StoreResult<Self> {
        let file = File::open(path)?;
        let mut reader: Box<dyn Read + Send> = Box::new(BufReader::new(file));
        let header = Self::read_header(&mut reader)?;
        Ok(Self {
            reader: Some(reader),
            header,
            saved: false,
        })
    }

    /// Create a deserializer from an already-open reader.
    pub fn from_reader<R: Read + Send + 'static>(mut reader: R) -> StoreResult<Self> {
        let header = Self::read_header(&mut reader)?;
        Ok(Self {
            reader: Some(Box::new(reader)),
            header,
            saved: false,
        })
    }

    /// Returns the packed item name.
    pub fn item_name(&self) -> &str {
        &self.header.item_name
    }

    /// Returns the packed content type, or `None` if empty.
    pub fn content_type(&self) -> Option<&str> {
        if self.header.content_type.is_empty() {
            None
        } else {
            Some(&self.header.content_type)
        }
    }

    /// Returns the packed file type.
    pub fn file_type(&self) -> i32 {
        self.header.file_type
    }

    /// Returns the uncompressed data length.
    pub fn length(&self) -> i64 {
        self.header.length
    }

    /// Returns the parsed header.
    pub fn header(&self) -> &PackedFileHeader {
        &self.header
    }

    /// Save the item content to the given output stream.
    ///
    /// This method may only be called once. The content is decompressed
    /// from the zip entry and written to `out`.
    pub fn save_item<W: Write>(
        &mut self,
        out: &mut W,
        monitor: &TaskMonitor,
    ) -> StoreResult<()> {
        if self.saved {
            return Err(GhidraError::InvalidState(
                "ItemDeserializer already saved".into(),
            ));
        }
        self.saved = true;

        let reader = self.reader.take().ok_or_else(|| {
            GhidraError::InvalidState("ItemDeserializer already disposed".into())
        })?;

        // Read the zip content
        Self::read_zip_content(reader, out, self.header.length, monitor)?;

        Ok(())
    }

    /// Dispose of the reader, releasing resources.
    pub fn dispose(&mut self) {
        self.reader = None;
    }

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    /// Read and validate the packed file header from `reader`.
    fn read_header<R: Read>(reader: &mut R) -> StoreResult<PackedFileHeader> {
        // Read Java ObjectOutputStream header: 2-byte magic + 2-byte version
        let mut oo_header = [0u8; 4];
        reader.read_exact(&mut oo_header)?;

        // Read our fields (big-endian, matching Java DataOutputStream)
        let magic = read_long(reader)?;
        if magic != MAGIC_NUMBER {
            return Err(GhidraError::InvalidData("Invalid packed file magic".into()));
        }
        let version = read_int(reader)?;
        if version != FORMAT_VERSION {
            return Err(GhidraError::InvalidData(format!(
                "Unsupported packed file version: {}",
                version
            )));
        }

        let item_name = read_utf(reader)?;
        let content_type = read_utf(reader)?;
        let file_type = read_int(reader)?;
        let length = read_long(reader)?;

        Ok(PackedFileHeader {
            item_name,
            content_type,
            file_type,
            length,
        })
    }

    /// Read the zip-compressed content and write decompressed bytes to `out`.
    fn read_zip_content<R: Read, W: Write>(
        mut reader: R,
        out: &mut W,
        expected_length: i64,
        monitor: &TaskMonitor,
    ) -> StoreResult<()> {
        // Find the local file header
        let mut sig = [0u8; 4];
        loop {
            reader.read_exact(&mut sig)?;
            if sig == [0x50, 0x4B, 0x03, 0x04] {
                break;
            }
            // Try one byte at a time for robustness
            // (the OOStream header is already consumed, so this should be immediate)
            return Err(GhidraError::InvalidData(
                "Cannot find zip local file header in packed file".into(),
            ));
        }

        // Read local file header fields
        let _version_needed = read_u16_le(&mut reader)?;
        let _general_purpose = read_u16_le(&mut reader)?;
        let compression_method = read_u16_le(&mut reader)?;
        let _last_mod_time = read_u16_le(&mut reader)?;
        let _last_mod_date = read_u16_le(&mut reader)?;
        let _crc = read_u32_le(&mut reader)?;
        let _compressed_size = read_u32_le(&mut reader)?;
        let _uncompressed_size = read_u32_le(&mut reader)?;
        let name_len = read_u16_le(&mut reader)? as usize;
        let extra_len = read_u16_le(&mut reader)? as usize;

        // Skip filename and extra field
        let mut skip = vec![0u8; name_len + extra_len];
        reader.read_exact(&mut skip)?;

        // Read and decompress
        let mut total_written: i64 = 0;
        let mut buf = [0u8; IO_BUFFER_SIZE];

        match compression_method {
            8 => {
                // Deflate
                use flate2::read::DeflateDecoder;
                let mut decoder = DeflateDecoder::new(reader);
                loop {
                    monitor.check_cancelled().map_err(|e| {
                        GhidraError::Other(anyhow::anyhow!("Cancelled: {}", e))
                    })?;
                    let remaining = expected_length - total_written;
                    let to_read = (remaining.min(buf.len() as i64)) as usize;
                    if to_read == 0 {
                        break;
                    }
                    let n = decoder.read(&mut buf[..to_read])?;
                    if n == 0 {
                        break;
                    }
                    out.write_all(&buf[..n])?;
                    total_written += n as i64;
                    monitor.set_progress(total_written);
                }
            }
            0 => {
                // Stored (no compression)
                loop {
                    monitor.check_cancelled().map_err(|e| {
                        GhidraError::Other(anyhow::anyhow!("Cancelled: {}", e))
                    })?;
                    let n = reader.read(&mut buf)?;
                    if n == 0 {
                        break;
                    }
                    out.write_all(&buf[..n])?;
                    total_written += n as i64;
                    monitor.set_progress(total_written);
                }
            }
            _ => {
                return Err(GhidraError::InvalidData(format!(
                    "Unsupported zip compression method: {}",
                    compression_method
                )));
            }
        }

        out.flush()?;
        Ok(())
    }
}

impl Drop for ItemDeserializer {
    fn drop(&mut self) {
        self.dispose();
    }
}

impl fmt::Debug for ItemDeserializer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ItemDeserializer")
            .field("item_name", &self.header.item_name)
            .field("content_type", &self.header.content_type)
            .field("file_type", &self.header.file_type)
            .field("length", &self.header.length)
            .field("saved", &self.saved)
            .finish()
    }
}

// ============================================================================
// Big-endian I/O helpers (matching Java DataOutputStream/DataInputStream)
// ============================================================================

fn write_int<W: Write>(w: &mut W, v: i32) -> io::Result<()> {
    w.write_all(&v.to_be_bytes())
}

fn write_long<W: Write>(w: &mut W, v: i64) -> io::Result<()> {
    w.write_all(&v.to_be_bytes())
}

fn write_utf<W: Write>(w: &mut W, s: &str) -> io::Result<()> {
    let bytes = s.as_bytes();
    if bytes.len() > u16::MAX as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "UTF string too long",
        ));
    }
    write_u16_be(w, bytes.len() as u16)?;
    w.write_all(bytes)
}

fn read_int<R: Read>(r: &mut R) -> io::Result<i32> {
    let mut buf = [0u8; 4];
    r.read_exact(&mut buf)?;
    Ok(i32::from_be_bytes(buf))
}

fn read_long<R: Read>(r: &mut R) -> io::Result<i64> {
    let mut buf = [0u8; 8];
    r.read_exact(&mut buf)?;
    Ok(i64::from_be_bytes(buf))
}

fn read_utf<R: Read>(r: &mut R) -> io::Result<String> {
    let len = read_u16_be(r)? as usize;
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    String::from_utf8(buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

fn write_u16_be<W: Write>(w: &mut W, v: u16) -> io::Result<()> {
    w.write_all(&v.to_be_bytes())
}

fn read_u16_be<R: Read>(r: &mut R) -> io::Result<u16> {
    let mut buf = [0u8; 2];
    r.read_exact(&mut buf)?;
    Ok(u16::from_be_bytes(buf))
}

fn write_u16_le<W: Write>(w: &mut W, v: u16) -> io::Result<()> {
    w.write_all(&v.to_le_bytes())
}

fn write_u32_le<W: Write>(w: &mut W, v: u32) -> io::Result<()> {
    w.write_all(&v.to_le_bytes())
}

fn read_u16_le<R: Read>(r: &mut R) -> io::Result<u16> {
    let mut buf = [0u8; 2];
    r.read_exact(&mut buf)?;
    Ok(u16::from_le_bytes(buf))
}

fn read_u32_le<R: Read>(r: &mut R) -> io::Result<u32> {
    let mut buf = [0u8; 4];
    r.read_exact(&mut buf)?;
    Ok(u32::from_le_bytes(buf))
}

fn stream_position<W: Write + Seek>(w: &mut W) -> io::Result<u64> {
    w.seek(SeekFrom::Current(0))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_packed_file_roundtrip() {
        let original_data = b"Hello, this is test data for packed file roundtrip!";

        // Serialize
        let mut packed_buf: Vec<u8> = Vec::new();
        let mut content: &[u8] = original_data;
        let monitor = TaskMonitor::new();

        ItemSerializer::output_item(
            "test_item.txt",
            "text/plain",
            1,
            original_data.len() as i64,
            &mut content,
            &mut Cursor::new(&mut packed_buf),
            &monitor,
        )
        .unwrap();

        assert!(!packed_buf.is_empty());

        // Check is_packed_stream
        let mut cursor = Cursor::new(&packed_buf);
        assert!(ItemSerializer::is_packed_stream(&mut cursor).unwrap());

        // Deserialize
        let mut deserializer =
            ItemDeserializer::from_reader(Cursor::new(packed_buf)).unwrap();
        assert_eq!(deserializer.item_name(), "test_item.txt");
        assert_eq!(deserializer.content_type(), Some("text/plain"));
        assert_eq!(deserializer.file_type(), 1);
        assert_eq!(deserializer.length(), original_data.len() as i64);

        let mut output = Vec::new();
        deserializer.save_item(&mut output, &monitor).unwrap();
        assert_eq!(output, original_data);
    }

    #[test]
    fn test_packed_file_empty_content() {
        let original_data = b"";

        let mut packed_buf: Vec<u8> = Vec::new();
        let mut content: &[u8] = original_data;
        let monitor = TaskMonitor::new();

        ItemSerializer::output_item(
            "empty",
            "",
            0,
            0,
            &mut content,
            &mut Cursor::new(&mut packed_buf),
            &monitor,
        )
        .unwrap();

        let mut deserializer =
            ItemDeserializer::from_reader(Cursor::new(packed_buf)).unwrap();
        assert_eq!(deserializer.item_name(), "empty");
        assert_eq!(deserializer.content_type(), None);
        assert_eq!(deserializer.length(), 0);

        let mut output = Vec::new();
        deserializer.save_item(&mut output, &monitor).unwrap();
        assert!(output.is_empty());
    }

    #[test]
    fn test_packed_file_large_content() {
        // 64KB of data
        let original_data: Vec<u8> = (0..65536).map(|i| (i % 256) as u8).collect();

        let mut packed_buf: Vec<u8> = Vec::new();
        let mut content: &[u8] = &original_data;
        let monitor = TaskMonitor::new();

        ItemSerializer::output_item(
            "large_data.bin",
            "application/octet-stream",
            0,
            original_data.len() as i64,
            &mut content,
            &mut Cursor::new(&mut packed_buf),
            &monitor,
        )
        .unwrap();

        // Packed should be smaller due to compression
        assert!(
            packed_buf.len() < original_data.len(),
            "Packed size {} should be less than original {}",
            packed_buf.len(),
            original_data.len()
        );

        let mut deserializer =
            ItemDeserializer::from_reader(Cursor::new(packed_buf)).unwrap();
        assert_eq!(deserializer.length(), original_data.len() as i64);

        let mut output = Vec::new();
        deserializer.save_item(&mut output, &monitor).unwrap();
        assert_eq!(output, original_data);
    }

    #[test]
    fn test_is_packed_file_negative() {
        // A random byte sequence should not be recognized as packed
        let data = b"This is not a packed file";
        let mut cursor = Cursor::new(data);
        assert!(!ItemSerializer::is_packed_stream(&mut cursor).unwrap());
    }

    #[test]
    fn test_deserialize_only_once() {
        let original_data = b"test";

        let mut packed_buf: Vec<u8> = Vec::new();
        let mut content: &[u8] = original_data;
        let monitor = TaskMonitor::new();

        ItemSerializer::output_item(
            "test",
            "text",
            1,
            4,
            &mut content,
            &mut Cursor::new(&mut packed_buf),
            &monitor,
        )
        .unwrap();

        let mut deserializer =
            ItemDeserializer::from_reader(Cursor::new(packed_buf)).unwrap();

        let mut output = Vec::new();
        deserializer.save_item(&mut output, &monitor).unwrap();
        assert_eq!(output, original_data);

        // Second save should fail
        let mut output2 = Vec::new();
        assert!(deserializer.save_item(&mut output2, &monitor).is_err());
    }

    #[test]
    fn test_header_fields() {
        let data = b"some data";

        let mut packed_buf: Vec<u8> = Vec::new();
        let mut content: &[u8] = data;
        let monitor = TaskMonitor::new();

        ItemSerializer::output_item(
            "My Item",
            "application/x-ghidra-program",
            0,
            data.len() as i64,
            &mut content,
            &mut Cursor::new(&mut packed_buf),
            &monitor,
        )
        .unwrap();

        let deserializer =
            ItemDeserializer::from_reader(Cursor::new(packed_buf)).unwrap();
        let header = deserializer.header();
        assert_eq!(header.item_name, "My Item");
        assert_eq!(header.content_type, "application/x-ghidra-program");
        assert_eq!(header.file_type, 0);
        assert_eq!(header.length, data.len() as i64);
    }
}
