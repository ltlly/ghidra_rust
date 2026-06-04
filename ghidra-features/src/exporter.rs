//! Export framework ported from Ghidra's `ghidra.app.util.exporter` package.
//!
//! Provides the trait and concrete exporters for writing programs to various
//! file formats:
//!
//! - [`Exporter`] trait -- common interface for all exporters
//! - [`ExporterError`] -- error type for export failures
//! - [`MemoryModel`] -- byte-level memory storage for export
//! - [`BinaryExporter`] -- exports raw bytes from memory blocks
//! - [`AsciiExporter`] -- exports listing as text
//! - [`IntelHexExporter`] -- exports in Intel HEX format
//! - [`MotorolaHexExporter`] -- exports in Motorola S-Record format
//! - [`XmlExporter`] -- exports as XML representation
//! - [`HtmlExporter`] -- exports as HTML listing
//! - [`ProgramTextOptions`] -- configurable text export layout
//! - [`ProgramTextWriter`] -- writes formatted program listings
//! - [`StringComparer`] -- string comparison utilities for export sorting

use std::collections::HashMap;
use std::fmt;
use std::io::{self, Write};

use crate::base::analyzer::{
    Address, AddressRange, AddressSet, BookmarkType, Program,
};
use crate::loader::framework::{MessageLog as LoaderMessageLog, MessageLevel};

// ---------------------------------------------------------------------------
// MemoryModel -- byte-level storage for export
// ---------------------------------------------------------------------------

/// Stores actual bytes at addresses, used by exporters.
///
/// The `Program.memory` field is an `AddressSet` that tracks which addresses
/// are valid but does not store the byte values. This `MemoryModel` pairs
/// with an `AddressSet` to provide byte-level read access for export.
#[derive(Debug, Clone, Default)]
pub struct MemoryModel {
    /// The byte data indexed by absolute address offset.
    bytes: HashMap<u64, u8>,
}

impl MemoryModel {
    pub fn new() -> Self {
        Self::default()
    }

    /// Store a byte at the given address.
    pub fn set_byte(&mut self, addr: &Address, byte: u8) {
        self.bytes.insert(addr.offset, byte);
    }

    /// Read a byte at the given address.
    pub fn get_byte(&self, addr: &Address) -> Option<u8> {
        self.bytes.get(&addr.offset).copied()
    }

    /// Read bytes into a buffer starting at the given address.
    pub fn get_bytes(&self, start: &Address, buf: &mut [u8]) {
        for (i, byte) in buf.iter_mut().enumerate() {
            let addr = Address::new(start.offset + i as u64);
            *byte = self.bytes.get(&addr.offset).copied().unwrap_or(0);
        }
    }

    /// Store multiple bytes starting at the given address.
    pub fn set_bytes(&mut self, start: &Address, data: &[u8]) {
        for (i, &byte) in data.iter().enumerate() {
            self.bytes.insert(start.offset + i as u64, byte);
        }
    }

    /// Get the number of stored bytes.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

// ---------------------------------------------------------------------------
// ExporterError
// ---------------------------------------------------------------------------

/// Error type for export operations.
///
/// Ported from `ghidra.app.util.exporter.ExporterException`.
#[derive(Debug)]
pub enum ExporterError {
    /// I/O error during export.
    Io(io::Error),
    /// Memory access error (address out of range or uninitialized).
    MemoryAccess(String),
    /// Unsupported domain object type.
    UnsupportedType(String),
    /// Generic export failure.
    Other(String),
}

impl fmt::Display for ExporterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExporterError::Io(e) => write!(f, "Export I/O error: {}", e),
            ExporterError::MemoryAccess(msg) => write!(f, "Memory access error: {}", msg),
            ExporterError::UnsupportedType(msg) => write!(f, "Unsupported type: {}", msg),
            ExporterError::Other(msg) => write!(f, "Export error: {}", msg),
        }
    }
}

impl std::error::Error for ExporterError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ExporterError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for ExporterError {
    fn from(e: io::Error) -> Self {
        ExporterError::Io(e)
    }
}

// ---------------------------------------------------------------------------
// Exporter trait
// ---------------------------------------------------------------------------

/// Trait that all exporters must implement.
///
/// Ported from `ghidra.app.util.exporter.Exporter`.
pub trait Exporter {
    /// Returns the display name of this exporter (e.g., "Raw Bytes", "Intel Hex").
    fn name(&self) -> &str;

    /// Returns the default file extension (e.g., "bin", "hex", "xml").
    fn default_extension(&self) -> &str;

    /// Returns true if this exporter can handle the given program.
    fn can_export(&self, _program: &Program) -> bool {
        true
    }

    /// Returns true if this exporter supports address-restricted export.
    fn supports_address_restricted_export(&self) -> bool {
        true
    }

    /// Export the given program to the writer.
    ///
    /// If `addr_set` is provided, only addresses within the set are exported.
    /// If `memory` is provided, byte data is read from it; otherwise the
    /// export operates on address metadata only.
    fn export(
        &self,
        program: &Program,
        addr_set: Option<&AddressSet>,
        memory: Option<&MemoryModel>,
        writer: &mut dyn Write,
        log: &mut LoaderMessageLog,
    ) -> Result<bool, ExporterError>;

    /// Get the available export options.
    fn options(&self) -> Vec<ExportOption> {
        Vec::new()
    }

    /// Set an export option value.
    fn set_option(&mut self, _name: &str, _value: ExportOptionValue) -> Result<(), ExporterError> {
        Ok(())
    }
}

/// An export option with name and typed value.
#[derive(Debug, Clone)]
pub struct ExportOption {
    pub name: String,
    pub option_type: ExportOptionType,
    pub default_value: ExportOptionValue,
    pub description: Option<String>,
}

/// The type of an export option.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExportOptionType {
    Boolean,
    String,
    Integer,
    HexInteger,
    Choice(Vec<String>),
}

/// The value of an export option.
#[derive(Debug, Clone, PartialEq)]
pub enum ExportOptionValue {
    Boolean(bool),
    String(String),
    Integer(i64),
    HexInteger(u64),
}

impl ExportOptionValue {
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            ExportOptionValue::Boolean(v) => Some(*v),
            _ => None,
        }
    }
    pub fn as_str(&self) -> Option<&str> {
        match self {
            ExportOptionValue::String(v) => Some(v.as_str()),
            _ => None,
        }
    }
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            ExportOptionValue::Integer(v) => Some(*v),
            _ => None,
        }
    }
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            ExportOptionValue::HexInteger(v) => Some(*v),
            ExportOptionValue::Integer(v) => Some(*v as u64),
            _ => None,
        }
    }
}

impl fmt::Display for ExportOptionValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExportOptionValue::Boolean(v) => write!(f, "{}", v),
            ExportOptionValue::String(v) => write!(f, "{}", v),
            ExportOptionValue::Integer(v) => write!(f, "{}", v),
            ExportOptionValue::HexInteger(v) => write!(f, "0x{:x}", v),
        }
    }
}

// ---------------------------------------------------------------------------
// BinaryExporter
// ---------------------------------------------------------------------------

/// Exports memory blocks as raw bytes.
///
/// Ported from `ghidra.app.util.exporter.BinaryExporter`.
pub struct BinaryExporter;

impl BinaryExporter {
    pub fn new() -> Self {
        Self
    }
}

impl Default for BinaryExporter {
    fn default() -> Self {
        Self::new()
    }
}

impl Exporter for BinaryExporter {
    fn name(&self) -> &str {
        "Raw Bytes"
    }

    fn default_extension(&self) -> &str {
        "bin"
    }

    fn export(
        &self,
        program: &Program,
        addr_set: Option<&AddressSet>,
        memory: Option<&MemoryModel>,
        writer: &mut dyn Write,
        log: &mut LoaderMessageLog,
    ) -> Result<bool, ExporterError> {
        let set = match addr_set {
            Some(s) => s.clone(),
            None => program.memory.clone(),
        };

        let mem = memory.ok_or_else(|| {
            ExporterError::MemoryAccess("No memory model provided for binary export".into())
        })?;

        let mut total = 0u64;
        for range in set.iter() {
            let mut addr = range.start;
            while addr.offset <= range.end.offset {
                if let Some(byte) = mem.get_byte(&addr) {
                    writer.write_all(&[byte])?;
                    total += 1;
                }
                addr = addr.add(1);
            }
        }

        log.append_msg(format!("Exported {} bytes to binary", total));
        Ok(true)
    }
}

// ---------------------------------------------------------------------------
// AsciiExporter
// ---------------------------------------------------------------------------

/// Exports the program listing as plain text.
///
/// Ported from `ghidra.app.util.exporter.AsciiExporter`.
pub struct AsciiExporter {
    options: ProgramTextOptions,
}

impl AsciiExporter {
    pub fn new() -> Self {
        Self {
            options: ProgramTextOptions::default(),
        }
    }

    pub fn with_options(options: ProgramTextOptions) -> Self {
        Self { options }
    }
}

impl Default for AsciiExporter {
    fn default() -> Self {
        Self::new()
    }
}

impl Exporter for AsciiExporter {
    fn name(&self) -> &str {
        "Ascii Text"
    }

    fn default_extension(&self) -> &str {
        "txt"
    }

    fn export(
        &self,
        program: &Program,
        addr_set: Option<&AddressSet>,
        memory: Option<&MemoryModel>,
        writer: &mut dyn Write,
        log: &mut LoaderMessageLog,
    ) -> Result<bool, ExporterError> {
        let text_writer = ProgramTextWriter::new(&self.options);
        let set = match addr_set {
            Some(s) => s.clone(),
            None => program.memory.clone(),
        };

        text_writer.write(program, &set, memory, writer, log)?;
        Ok(true)
    }

    fn options(&self) -> Vec<ExportOption> {
        vec![
            ExportOption {
                name: "Show Comments".into(),
                option_type: ExportOptionType::Boolean,
                default_value: ExportOptionValue::Boolean(true),
                description: Some("Include comments in export".into()),
            },
            ExportOption {
                name: "Show Addresses".into(),
                option_type: ExportOptionType::Boolean,
                default_value: ExportOptionValue::Boolean(true),
                description: Some("Include addresses in export".into()),
            },
            ExportOption {
                name: "Show Bytes".into(),
                option_type: ExportOptionType::Boolean,
                default_value: ExportOptionValue::Boolean(false),
                description: Some("Include raw bytes in export".into()),
            },
        ]
    }

    fn set_option(&mut self, name: &str, value: ExportOptionValue) -> Result<(), ExporterError> {
        match name {
            "Show Comments" => {
                if let Some(v) = value.as_bool() {
                    self.options.show_comments = v;
                }
            }
            "Show Addresses" => {
                if let Some(v) = value.as_bool() {
                    self.options.show_addresses = v;
                }
            }
            "Show Bytes" => {
                if let Some(v) = value.as_bool() {
                    self.options.show_bytes = v;
                }
            }
            _ => {}
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// IntelHexExporter
// ---------------------------------------------------------------------------

/// Exports the program in Intel HEX format.
///
/// Ported from `ghidra.app.util.exporter.IntelHexExporter`.
pub struct IntelHexExporter {
    /// Number of data bytes per record (default: 16).
    pub record_size: usize,
    /// If true, only output records whose data matches `record_size`.
    pub drop_extra_bytes: bool,
}

impl IntelHexExporter {
    pub fn new() -> Self {
        Self {
            record_size: 16,
            drop_extra_bytes: false,
        }
    }

    pub fn with_record_size(record_size: usize, drop_extra_bytes: bool) -> Self {
        Self {
            record_size: record_size.min(255),
            drop_extra_bytes,
        }
    }
}

impl Default for IntelHexExporter {
    fn default() -> Self {
        Self::new()
    }
}

impl Exporter for IntelHexExporter {
    fn name(&self) -> &str {
        "Intel Hex"
    }

    fn default_extension(&self) -> &str {
        "hex"
    }

    fn export(
        &self,
        program: &Program,
        addr_set: Option<&AddressSet>,
        memory: Option<&MemoryModel>,
        writer: &mut dyn Write,
        log: &mut LoaderMessageLog,
    ) -> Result<bool, ExporterError> {
        let set = match addr_set {
            Some(s) => s.clone(),
            None => program.memory.clone(),
        };

        let mem = memory.ok_or_else(|| {
            ExporterError::MemoryAccess("No memory model provided for Intel HEX export".into())
        })?;

        // Collect all bytes
        let mut all_bytes: Vec<(u64, u8)> = Vec::new();
        for range in set.iter() {
            let mut addr = range.start;
            while addr.offset <= range.end.offset {
                if let Some(byte) = mem.get_byte(&addr) {
                    all_bytes.push((addr.offset, byte));
                }
                addr = addr.add(1);
            }
        }

        if all_bytes.is_empty() {
            log.append_msg("No bytes to export");
            return Ok(true);
        }

        // Check address space size
        let max_addr = all_bytes.last().map(|(a, _)| *a).unwrap_or(0);
        if max_addr > 0xFFFFFFFF {
            log.append_msg("Cannot use Intel HEX for address spaces larger than 32 bits");
            return Ok(false);
        }

        let records = self.generate_records(&all_bytes);
        for record in &records {
            writeln!(writer, "{}", record)?;
        }

        // EOF record
        writeln!(writer, ":00000001FF")?;

        log.append_msg(format!("Exported {} Intel HEX records", records.len()));
        Ok(true)
    }

    fn options(&self) -> Vec<ExportOption> {
        vec![
            ExportOption {
                name: "Record Size".into(),
                option_type: ExportOptionType::Integer,
                default_value: ExportOptionValue::Integer(16),
                description: Some("Number of data bytes per HEX record (max 255)".into()),
            },
            ExportOption {
                name: "Drop Extra Bytes".into(),
                option_type: ExportOptionType::Boolean,
                default_value: ExportOptionValue::Boolean(false),
                description: Some("Only output full-size records".into()),
            },
        ]
    }

    fn set_option(&mut self, name: &str, value: ExportOptionValue) -> Result<(), ExporterError> {
        match name {
            "Record Size" => {
                if let Some(v) = value.as_i64() {
                    if v > 0 && v <= 255 {
                        self.record_size = v as usize;
                    }
                }
            }
            "Drop Extra Bytes" => {
                if let Some(v) = value.as_bool() {
                    self.drop_extra_bytes = v;
                }
            }
            _ => {}
        }
        Ok(())
    }
}

impl IntelHexExporter {
    fn generate_records(&self, bytes: &[(u64, u8)]) -> Vec<String> {
        let mut records = Vec::new();
        let mut i = 0;

        while i < bytes.len() {
            let base_addr = bytes[i].0;
            let chunk_end = (i + self.record_size).min(bytes.len());
            let chunk_len = chunk_end - i;

            if self.drop_extra_bytes && chunk_len < self.record_size {
                break;
            }

            // Extended linear address record if needed
            let high_addr = (base_addr >> 16) as u16;
            if high_addr != 0 {
                let rec = format!(
                    ":02000004{:04X}{:02X}",
                    high_addr,
                    checksum_u8(&[0x02, 0x00, 0x00, 0x04, (high_addr >> 8) as u8, high_addr as u8])
                );
                records.push(rec);
            }

            // Data record
            let addr16 = (base_addr & 0xFFFF) as u16;
            let data_bytes: Vec<u8> = bytes[i..chunk_end].iter().map(|(_, b)| *b).collect();
            let mut record_data = vec![chunk_len as u8, (addr16 >> 8) as u8, addr16 as u8, 0x00];
            record_data.extend_from_slice(&data_bytes);
            let cs = checksum_u8(&record_data);

            let mut hex_str = String::with_capacity(11 + chunk_len * 2);
            hex_str.push(':');
            for b in &record_data {
                hex_str.push_str(&format!("{:02X}", b));
            }
            hex_str.push_str(&format!("{:02X}", cs));
            records.push(hex_str);

            i = chunk_end;
        }

        records
    }
}

fn checksum_u8(data: &[u8]) -> u8 {
    let sum: u32 = data.iter().map(|&b| b as u32).sum();
    ((!sum) + 1) as u8
}

// ---------------------------------------------------------------------------
// MotorolaHexExporter
// ---------------------------------------------------------------------------

/// Exports the program in Motorola S-Record format.
pub struct MotorolaHexExporter {
    /// Record type (S1=16-bit, S2=24-bit, S3=32-bit address).
    pub record_type: u8,
}

impl MotorolaHexExporter {
    pub fn new() -> Self {
        Self { record_type: 3 }
    }

    pub fn with_record_type(record_type: u8) -> Self {
        Self {
            record_type: record_type.clamp(1, 3),
        }
    }
}

impl Default for MotorolaHexExporter {
    fn default() -> Self {
        Self::new()
    }
}

impl Exporter for MotorolaHexExporter {
    fn name(&self) -> &str {
        "Motorola Hex"
    }

    fn default_extension(&self) -> &str {
        "srec"
    }

    fn export(
        &self,
        program: &Program,
        addr_set: Option<&AddressSet>,
        memory: Option<&MemoryModel>,
        writer: &mut dyn Write,
        log: &mut LoaderMessageLog,
    ) -> Result<bool, ExporterError> {
        let set = match addr_set {
            Some(s) => s.clone(),
            None => program.memory.clone(),
        };

        let mem = memory.ok_or_else(|| {
            ExporterError::MemoryAccess("No memory model provided for Motorola HEX export".into())
        })?;

        let mut all_bytes: Vec<(u64, u8)> = Vec::new();
        for range in set.iter() {
            let mut addr = range.start;
            while addr.offset <= range.end.offset {
                if let Some(byte) = mem.get_byte(&addr) {
                    all_bytes.push((addr.offset, byte));
                }
                addr = addr.add(1);
            }
        }

        if all_bytes.is_empty() {
            log.append_msg("No bytes to export");
            return Ok(true);
        }

        let addr_bytes = self.record_type as usize + 1;
        let max_data = 255 - addr_bytes - 1;
        let mut i = 0;
        let mut record_count = 0u32;

        while i < all_bytes.len() {
            let chunk_end = (i + max_data).min(all_bytes.len());
            let addr = all_bytes[i].0;
            let data: Vec<u8> = all_bytes[i..chunk_end].iter().map(|(_, b)| *b).collect();
            let count = (addr_bytes + 1 + data.len()) as u8;

            let mut sum_bytes = vec![count];
            match self.record_type {
                1 => {
                    sum_bytes.push((addr >> 8) as u8);
                    sum_bytes.push(addr as u8);
                }
                2 => {
                    sum_bytes.push((addr >> 16) as u8);
                    sum_bytes.push((addr >> 8) as u8);
                    sum_bytes.push(addr as u8);
                }
                _ => {
                    sum_bytes.push((addr >> 24) as u8);
                    sum_bytes.push((addr >> 16) as u8);
                    sum_bytes.push((addr >> 8) as u8);
                    sum_bytes.push(addr as u8);
                }
            }
            sum_bytes.extend_from_slice(&data);
            let cs = motorola_checksum(&sum_bytes);

            let addr_hex = match self.record_type {
                1 => format!("{:04X}", addr as u16),
                2 => format!("{:06X}", addr as u32 & 0xFFFFFF),
                _ => format!("{:08X}", addr as u32),
            };
            let data_hex: String = data.iter().map(|b| format!("{:02X}", b)).collect();
            writeln!(
                writer,
                "S{}{:02X}{}{}{:02X}",
                self.record_type, count, addr_hex, data_hex, cs
            )?;

            i = chunk_end;
            record_count += 1;
        }

        // End record
        let end_type = match self.record_type {
            1 => "S9",
            2 => "S8",
            _ => "S7",
        };
        writeln!(writer, "{}03000000FC", end_type)?;

        log.append_msg(format!("Exported {} Motorola S-Records", record_count));
        Ok(true)
    }
}

fn motorola_checksum(data: &[u8]) -> u8 {
    let sum: u32 = data.iter().map(|&b| b as u32).sum();
    (!sum) as u8
}

// ---------------------------------------------------------------------------
// XmlExporter
// ---------------------------------------------------------------------------

/// Exports the program as an XML document.
///
/// Ported from `ghidra.app.util.exporter.XmlExporter`.
pub struct XmlExporter {
    pub include_bytes: bool,
    pub include_symbols: bool,
    pub include_comments: bool,
    pub include_functions: bool,
}

impl XmlExporter {
    pub fn new() -> Self {
        Self {
            include_bytes: true,
            include_symbols: true,
            include_comments: true,
            include_functions: true,
        }
    }
}

impl Default for XmlExporter {
    fn default() -> Self {
        Self::new()
    }
}

impl Exporter for XmlExporter {
    fn name(&self) -> &str {
        "XML"
    }

    fn default_extension(&self) -> &str {
        "xml"
    }

    fn export(
        &self,
        program: &Program,
        addr_set: Option<&AddressSet>,
        memory: Option<&MemoryModel>,
        writer: &mut dyn Write,
        log: &mut LoaderMessageLog,
    ) -> Result<bool, ExporterError> {
        let set = match addr_set {
            Some(s) => s.clone(),
            None => program.memory.clone(),
        };

        writeln!(writer, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>")?;
        writeln!(writer, "<PROGRAM>")?;
        writeln!(
            writer,
            "  <INFO name=\"{}\" image_base=\"0x{:x}\"/>",
            escape_xml(&program.name),
            program.image_base
        )?;

        // Memory blocks
        writeln!(writer, "  <MEMORY>")?;
        for range in set.iter() {
            let start = range.start.offset;
            let end = range.end.offset;
            writeln!(
                writer,
                "    <BLOCK start=\"0x{:x}\" end=\"0x{:x}\" length=\"{}\">",
                start,
                end,
                range.len()
            )?;
            if self.include_bytes {
                if let Some(mem) = memory {
                    let mut addr = range.start;
                    while addr.offset <= range.end.offset {
                        if let Some(byte) = mem.get_byte(&addr) {
                            writeln!(
                                writer,
                                "      <BYTE addr=\"0x{:x}\" val=\"0x{:02x}\"/>",
                                addr.offset, byte
                            )?;
                        }
                        addr = addr.add(1);
                    }
                }
            }
            writeln!(writer, "    </BLOCK>")?;
        }
        writeln!(writer, "  </MEMORY>")?;

        // Symbols
        if self.include_symbols && !program.symbols.is_empty() {
            writeln!(writer, "  <SYMBOLS>")?;
            for (addr, sym) in &program.symbols {
                writeln!(
                    writer,
                    "    <SYMBOL addr=\"0x{:x}\" name=\"{}\"/>",
                    addr.offset,
                    escape_xml(sym)
                )?;
            }
            writeln!(writer, "  </SYMBOLS>")?;
        }

        // Functions (via function_manager)
        if self.include_functions && !program.function_manager.functions.is_empty() {
            writeln!(writer, "  <FUNCTIONS>")?;
            for (addr, func) in &program.function_manager.functions {
                let fname = func.name.as_deref().unwrap_or("unknown");
                writeln!(
                    writer,
                    "    <FUNCTION addr=\"0x{:x}\" name=\"{}\"/>",
                    addr.offset,
                    escape_xml(fname)
                )?;
            }
            writeln!(writer, "  </FUNCTIONS>")?;
        }

        // Bookmarks
        if !program.bookmarks.is_empty() {
            writeln!(writer, "  <BOOKMARKS>")?;
            for (addr, bt, category, comment) in &program.bookmarks {
                writeln!(
                    writer,
                    "    <BOOKMARK addr=\"0x{:x}\" type=\"{}\" category=\"{}\" comment=\"{}\"/>",
                    addr.offset,
                    bt,
                    escape_xml(category),
                    escape_xml(comment)
                )?;
            }
            writeln!(writer, "  </BOOKMARKS>")?;
        }

        writeln!(writer, "</PROGRAM>")?;

        log.append_msg("Exported program as XML");
        Ok(true)
    }
}

fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

// ---------------------------------------------------------------------------
// HtmlExporter
// ---------------------------------------------------------------------------

/// Exports the program listing as an HTML document.
///
/// Ported from `ghidra.app.util.exporter.HtmlExporter`.
pub struct HtmlExporter {
    options: ProgramTextOptions,
    pub address_color: String,
    pub mnemonic_color: String,
    pub comment_color: String,
}

impl HtmlExporter {
    pub fn new() -> Self {
        Self {
            options: ProgramTextOptions::default(),
            address_color: "#808080".into(),
            mnemonic_color: "#0000FF".into(),
            comment_color: "#008000".into(),
        }
    }
}

impl Default for HtmlExporter {
    fn default() -> Self {
        Self::new()
    }
}

impl Exporter for HtmlExporter {
    fn name(&self) -> &str {
        "HTML"
    }

    fn default_extension(&self) -> &str {
        "html"
    }

    fn export(
        &self,
        program: &Program,
        addr_set: Option<&AddressSet>,
        memory: Option<&MemoryModel>,
        writer: &mut dyn Write,
        log: &mut LoaderMessageLog,
    ) -> Result<bool, ExporterError> {
        let set = match addr_set {
            Some(s) => s.clone(),
            None => program.memory.clone(),
        };

        writeln!(writer, "<!DOCTYPE html>")?;
        writeln!(writer, "<html>")?;
        writeln!(writer, "<head>")?;
        writeln!(writer, "  <meta charset=\"UTF-8\">")?;
        writeln!(
            writer,
            "  <title>{} - Ghidra Export</title>",
            escape_html(&program.name)
        )?;
        writeln!(writer, "  <style>")?;
        writeln!(writer, "    body {{ font-family: monospace; background: #1e1e1e; color: #d4d4d4; padding: 10px; }}")?;
        writeln!(writer, "    .addr {{ color: {}; }}", self.address_color)?;
        writeln!(
            writer,
            "    .mnemonic {{ color: {}; font-weight: bold; }}",
            self.mnemonic_color
        )?;
        writeln!(writer, "    .comment {{ color: {}; }}", self.comment_color)?;
        writeln!(writer, "    .bytes {{ color: #808080; }}")?;
        writeln!(writer, "    pre {{ margin: 0; }}")?;
        writeln!(writer, "  </style>")?;
        writeln!(writer, "</head>")?;
        writeln!(writer, "<body>")?;
        writeln!(
            writer,
            "<h2>Listing: {}</h2>",
            escape_html(&program.name)
        )?;
        writeln!(writer, "<pre>")?;

        for range in set.iter() {
            let mut addr = range.start;
            while addr.offset <= range.end.offset {
                if let Some(byte) = memory.and_then(|m| m.get_byte(&addr)) {
                    write!(writer, "<span class=\"addr\">{:08x}</span>  ", addr.offset)?;
                    write!(writer, "<span class=\"bytes\">{:02x}</span>  ", byte)?;
                    if let Some(sym) = program.symbols.get(&addr) {
                        write!(
                            writer,
                            "<span class=\"mnemonic\">{}</span>",
                            escape_html(sym)
                        )?;
                    }
                    writeln!(writer)?;
                }
                addr = addr.add(1);
            }
        }

        writeln!(writer, "</pre>")?;
        writeln!(writer, "</body>")?;
        writeln!(writer, "</html>")?;

        log.append_msg("Exported program as HTML");
        Ok(true)
    }
}

fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

// ---------------------------------------------------------------------------
// ProgramTextOptions
// ---------------------------------------------------------------------------

/// Configuration options for text-based export.
///
/// Ported from `ghidra.app.util.exporter.ProgramTextOptions`.
#[derive(Debug, Clone)]
pub struct ProgramTextOptions {
    pub show_addresses: bool,
    pub address_width: usize,
    pub show_bytes: bool,
    pub bytes_width: usize,
    pub show_comments: bool,
    pub show_labels: bool,
    pub label_width: usize,
    pub show_mnemonic: bool,
    pub mnemonic_width: usize,
    pub show_operands: bool,
    pub operand_width: usize,
    pub show_references: bool,
    pub show_functions: bool,
    pub show_block_names: bool,
    pub show_data_fields: bool,
    pub data_field_width: usize,
    pub label_suffix: String,
    pub comment_prefix: String,
    pub bytes_per_line: usize,
    pub is_html: bool,
}

impl Default for ProgramTextOptions {
    fn default() -> Self {
        Self {
            show_addresses: true,
            address_width: 16,
            show_bytes: false,
            bytes_width: 12,
            show_comments: true,
            show_labels: true,
            label_width: 30,
            show_mnemonic: true,
            mnemonic_width: 12,
            show_operands: true,
            operand_width: 40,
            show_references: true,
            show_functions: true,
            show_block_names: true,
            show_data_fields: false,
            data_field_width: 12,
            label_suffix: ":".into(),
            comment_prefix: ";".into(),
            bytes_per_line: 16,
            is_html: false,
        }
    }
}

// ---------------------------------------------------------------------------
// ProgramTextWriter
// ---------------------------------------------------------------------------

/// Writes formatted program listings.
///
/// Ported from `ghidra.app.util.exporter.ProgramTextWriter`.
pub struct ProgramTextWriter<'a> {
    options: &'a ProgramTextOptions,
}

impl<'a> ProgramTextWriter<'a> {
    pub fn new(options: &'a ProgramTextOptions) -> Self {
        Self { options }
    }

    /// Write the program listing to the given writer.
    pub fn write(
        &self,
        program: &Program,
        addr_set: &AddressSet,
        memory: Option<&MemoryModel>,
        writer: &mut dyn Write,
        log: &mut LoaderMessageLog,
    ) -> Result<(), ExporterError> {
        // Header: functions
        if self.options.show_functions && !program.function_manager.functions.is_empty() {
            writeln!(writer, "; Functions:")?;
            for (addr, func) in &program.function_manager.functions {
                let fname = func.name.as_deref().unwrap_or("unknown");
                writeln!(writer, ";   0x{:x} {}", addr.offset, fname)?;
            }
            writeln!(writer)?;
        }

        // Main listing
        for range in addr_set.iter() {
            if self.options.show_block_names {
                writeln!(
                    writer,
                    "; --- Block: 0x{:x} - 0x{:x} ({}) ---",
                    range.start.offset,
                    range.end.offset,
                    range.len()
                )?;
            }

            // Collect bytes for hex dump
            let mut line_bytes: Vec<(u64, u8)> = Vec::new();
            let mut line_start_addr: Option<u64> = None;

            let mut addr = range.start;
            while addr.offset <= range.end.offset {
                let byte = memory.and_then(|m| m.get_byte(&addr));
                if let Some(byte) = byte {
                    if line_start_addr.is_none() {
                        line_start_addr = Some(addr.offset);
                    }
                    line_bytes.push((addr.offset, byte));

                    if line_bytes.len() >= self.options.bytes_per_line {
                        self.write_line(program, line_start_addr.unwrap(), &line_bytes, writer)?;
                        line_bytes.clear();
                        line_start_addr = None;
                    }
                }
                addr = addr.add(1);
            }

            if !line_bytes.is_empty() {
                if let Some(start) = line_start_addr {
                    self.write_line(program, start, &line_bytes, writer)?;
                }
            }
        }

        log.append_msg("Listing export complete");
        Ok(())
    }

    fn write_line(
        &self,
        program: &Program,
        addr: u64,
        bytes: &[(u64, u8)],
        writer: &mut dyn Write,
    ) -> Result<(), ExporterError> {
        // Address
        if self.options.show_addresses {
            write!(
                writer,
                "{:<width$}",
                format!("0x{:08x}", addr),
                width = self.options.address_width
            )?;
        }

        // Bytes
        if self.options.show_bytes {
            let hex: String = bytes
                .iter()
                .map(|(_, b)| format!("{:02x}", b))
                .collect::<Vec<_>>()
                .join(" ");
            write!(writer, "{:<width$}", hex, width = self.options.bytes_width)?;
        }

        // Label
        if self.options.show_labels {
            let a = Address::new(addr);
            if let Some(sym) = program.symbols.get(&a) {
                write!(
                    writer,
                    "{:<width$}{} ",
                    sym,
                    self.options.label_suffix,
                    width = self.options.label_width
                )?;
            } else {
                write!(
                    writer,
                    "{:<width$}",
                    "",
                    width = self.options.label_width + self.options.label_suffix.len() + 1
                )?;
            }
        }

        // Mnemonic placeholder
        if self.options.show_mnemonic {
            write!(writer, "{:<width$}", "db", width = self.options.mnemonic_width)?;
        }

        // Operand
        if self.options.show_operands {
            let hex_vals: String = bytes
                .iter()
                .map(|(_, b)| format!("0x{:02x}", b))
                .collect::<Vec<_>>()
                .join(", ");
            write!(
                writer,
                "{:<width$}",
                hex_vals,
                width = self.options.operand_width
            )?;
        }

        // Comments
        if self.options.show_comments {
            let a = Address::new(addr);
            for (bm_addr, _bt, _cat, comment) in &program.bookmarks {
                if *bm_addr == a {
                    write!(writer, " {} {}", self.options.comment_prefix, comment)?;
                }
            }
        }

        writeln!(writer)?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// StringComparer
// ---------------------------------------------------------------------------

/// Utility for comparing and sorting strings in exports.
///
/// Ported from `ghidra.app.util.exporter.StringComparer`.
pub struct StringComparer;

impl StringComparer {
    /// Case-insensitive comparison.
    pub fn compare_ignore_case(a: &str, b: &str) -> std::cmp::Ordering {
        a.to_lowercase().cmp(&b.to_lowercase())
    }

    /// Natural number comparison (e.g., "file2" < "file10").
    pub fn natural_compare(a: &str, b: &str) -> std::cmp::Ordering {
        let a_parts = Self::split_natural(a);
        let b_parts = Self::split_natural(b);
        a_parts.cmp(&b_parts)
    }

    fn split_natural(s: &str) -> Vec<NaturalPart<'_>> {
        let mut parts = Vec::new();
        let mut chars = s.char_indices().peekable();
        while let Some(&(i, ch)) = chars.peek() {
            if ch.is_ascii_digit() {
                let start = i;
                while let Some(&(_, c)) = chars.peek() {
                    if c.is_ascii_digit() {
                        chars.next();
                    } else {
                        break;
                    }
                }
                let end = chars.peek().map(|&(i, _)| i).unwrap_or(s.len());
                if let Ok(n) = s[start..end].parse::<u64>() {
                    parts.push(NaturalPart::Number(n));
                }
            } else {
                let start = i;
                chars.next();
                let end = chars.peek().map(|&(i, _)| i).unwrap_or(s.len());
                parts.push(NaturalPart::Text(&s[start..end]));
            }
        }
        parts
    }
}

#[derive(PartialEq, Eq, PartialOrd, Ord)]
enum NaturalPart<'a> {
    Text(&'a str),
    Number(u64),
}

// ---------------------------------------------------------------------------
// Exporter registry
// ---------------------------------------------------------------------------

/// Registry of available exporters.
pub struct ExporterRegistry {
    exporters: Vec<Box<dyn Exporter>>,
}

impl ExporterRegistry {
    pub fn new() -> Self {
        Self {
            exporters: Vec::new(),
        }
    }

    pub fn with_defaults() -> Self {
        let mut reg = Self::new();
        reg.register(Box::new(BinaryExporter::new()));
        reg.register(Box::new(AsciiExporter::new()));
        reg.register(Box::new(IntelHexExporter::new()));
        reg.register(Box::new(MotorolaHexExporter::new()));
        reg.register(Box::new(XmlExporter::new()));
        reg.register(Box::new(HtmlExporter::new()));
        reg
    }

    pub fn register(&mut self, exporter: Box<dyn Exporter>) {
        self.exporters.push(exporter);
    }

    pub fn exporter_names(&self) -> Vec<&str> {
        self.exporters.iter().map(|e| e.name()).collect()
    }

    pub fn find_by_name(&self, name: &str) -> Option<&dyn Exporter> {
        self.exporters
            .iter()
            .find(|e| e.name() == name)
            .map(|e| e.as_ref())
    }

    pub fn find_compatible(&self, program: &Program) -> Vec<&dyn Exporter> {
        self.exporters
            .iter()
            .filter(|e| e.can_export(program))
            .map(|e| e.as_ref())
            .collect()
    }

    pub fn export(
        &self,
        exporter_name: &str,
        program: &Program,
        addr_set: Option<&AddressSet>,
        memory: Option<&MemoryModel>,
        writer: &mut dyn Write,
        log: &mut LoaderMessageLog,
    ) -> Result<bool, ExporterError> {
        let exporter = self.find_by_name(exporter_name).ok_or_else(|| {
            ExporterError::Other(format!("Unknown exporter: {}", exporter_name))
        })?;
        exporter.export(program, addr_set, memory, writer, log)
    }
}

impl Default for ExporterRegistry {
    fn default() -> Self {
        Self::with_defaults()
    }
}

// ---------------------------------------------------------------------------
// BookmarkType Display (needed for XML export)
// ---------------------------------------------------------------------------

impl fmt::Display for BookmarkType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BookmarkType::Analysis => write!(f, "Analysis"),
            BookmarkType::Warning => write!(f, "Warning"),
            BookmarkType::Error => write!(f, "Error"),
            BookmarkType::Info => write!(f, "Info"),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::analyzer::Language;

    fn make_test_program() -> Program {
        let lang = Language {
            processor: "x86".into(),
            variant: "LE".into(),
            size: 64,
        };
        let mut prog = Program::new("test_binary", lang);
        prog.image_base = 0x400000;
        prog.memory
            .add_range(AddressRange::new(Address::new(0x400000), Address::new(0x40001F)));
        prog.symbols.insert(Address::new(0x400000), "_start".into());
        prog.symbols.insert(Address::new(0x400010), "main".into());
        prog
    }

    fn make_test_memory() -> MemoryModel {
        let mut mem = MemoryModel::new();
        for i in 0u8..32 {
            mem.set_byte(&Address::new(0x400000 + i as u64), i);
        }
        mem
    }

    #[test]
    fn test_memory_model() {
        let mut mem = MemoryModel::new();
        assert!(mem.is_empty());

        mem.set_byte(&Address::new(0x1000), 0xAB);
        mem.set_byte(&Address::new(0x1001), 0xCD);
        assert_eq!(mem.len(), 2);
        assert_eq!(mem.get_byte(&Address::new(0x1000)), Some(0xAB));
        assert_eq!(mem.get_byte(&Address::new(0x1001)), Some(0xCD));
        assert_eq!(mem.get_byte(&Address::new(0x1002)), None);
    }

    #[test]
    fn test_memory_model_bytes() {
        let mut mem = MemoryModel::new();
        mem.set_bytes(&Address::new(0x1000), &[1, 2, 3, 4]);
        let mut buf = [0u8; 4];
        mem.get_bytes(&Address::new(0x1000), &mut buf);
        assert_eq!(buf, [1, 2, 3, 4]);
    }

    #[test]
    fn test_exporter_error_display() {
        let e = ExporterError::Other("test error".into());
        assert!(e.to_string().contains("test error"));

        let e = ExporterError::MemoryAccess("out of range".into());
        assert!(e.to_string().contains("Memory access"));
    }

    #[test]
    fn test_exporter_error_from_io() {
        let io_err = io::Error::new(io::ErrorKind::BrokenPipe, "pipe broken");
        let e = ExporterError::from(io_err);
        assert!(e.to_string().contains("Export I/O error"));
    }

    #[test]
    fn test_binary_exporter() {
        let prog = make_test_program();
        let mem = make_test_memory();
        let exporter = BinaryExporter::new();
        assert_eq!(exporter.name(), "Raw Bytes");
        assert_eq!(exporter.default_extension(), "bin");

        let mut output = Vec::new();
        let mut log = LoaderMessageLog::new();
        let result = exporter.export(&prog, None, Some(&mem), &mut output, &mut log);
        assert!(result.is_ok());
        assert_eq!(output.len(), 32);
        assert_eq!(output[0], 0);
        assert_eq!(output[31], 31);
    }

    #[test]
    fn test_binary_exporter_no_memory() {
        let prog = make_test_program();
        let exporter = BinaryExporter::new();
        let mut output = Vec::new();
        let mut log = LoaderMessageLog::new();
        let result = exporter.export(&prog, None, None, &mut output, &mut log);
        assert!(result.is_err());
    }

    #[test]
    fn test_binary_exporter_restricted() {
        let prog = make_test_program();
        let mem = make_test_memory();
        let exporter = BinaryExporter::new();

        let mut set = AddressSet::new();
        set.add_range(AddressRange::new(Address::new(0x400000), Address::new(0x400003)));

        let mut output = Vec::new();
        let mut log = LoaderMessageLog::new();
        let result = exporter.export(&prog, Some(&set), Some(&mem), &mut output, &mut log);
        assert!(result.is_ok());
        assert_eq!(output.len(), 4);
    }

    #[test]
    fn test_ascii_exporter() {
        let prog = make_test_program();
        let mem = make_test_memory();
        let exporter = AsciiExporter::new();
        assert_eq!(exporter.name(), "Ascii Text");

        let mut output = Vec::new();
        let mut log = LoaderMessageLog::new();
        let result = exporter.export(&prog, None, Some(&mem), &mut output, &mut log);
        assert!(result.is_ok());

        let text = String::from_utf8(output).unwrap();
        assert!(text.contains("0x00400000"));
        assert!(text.contains("_start"));
    }

    #[test]
    fn test_intel_hex_exporter() {
        let prog = make_test_program();
        let mem = make_test_memory();
        let exporter = IntelHexExporter::new();
        assert_eq!(exporter.name(), "Intel Hex");

        let mut output = Vec::new();
        let mut log = LoaderMessageLog::new();
        let result = exporter.export(&prog, None, Some(&mem), &mut output, &mut log);
        assert!(result.is_ok());

        let text = String::from_utf8(output).unwrap();
        assert!(text.contains(':'));
        assert!(text.contains(":00000001FF"));
    }

    #[test]
    fn test_intel_hex_exporter_custom_record_size() {
        let prog = make_test_program();
        let mem = make_test_memory();
        let exporter = IntelHexExporter::with_record_size(8, false);

        let mut output = Vec::new();
        let mut log = LoaderMessageLog::new();
        let result = exporter.export(&prog, None, Some(&mem), &mut output, &mut log);
        assert!(result.is_ok());
    }

    #[test]
    fn test_motorola_hex_exporter() {
        let prog = make_test_program();
        let mem = make_test_memory();
        let exporter = MotorolaHexExporter::new();
        assert_eq!(exporter.name(), "Motorola Hex");

        let mut output = Vec::new();
        let mut log = LoaderMessageLog::new();
        let result = exporter.export(&prog, None, Some(&mem), &mut output, &mut log);
        assert!(result.is_ok());

        let text = String::from_utf8(output).unwrap();
        assert!(text.starts_with("S3"));
        assert!(text.contains("S7")); // End record
    }

    #[test]
    fn test_xml_exporter() {
        let prog = make_test_program();
        let mem = make_test_memory();
        let exporter = XmlExporter::new();
        assert_eq!(exporter.name(), "XML");

        let mut output = Vec::new();
        let mut log = LoaderMessageLog::new();
        let result = exporter.export(&prog, None, Some(&mem), &mut output, &mut log);
        assert!(result.is_ok());

        let text = String::from_utf8(output).unwrap();
        assert!(text.contains("<?xml"));
        assert!(text.contains("<PROGRAM>"));
        assert!(text.contains("test_binary"));
        assert!(text.contains("_start"));
    }

    #[test]
    fn test_html_exporter() {
        let prog = make_test_program();
        let mem = make_test_memory();
        let exporter = HtmlExporter::new();
        assert_eq!(exporter.name(), "HTML");

        let mut output = Vec::new();
        let mut log = LoaderMessageLog::new();
        let result = exporter.export(&prog, None, Some(&mem), &mut output, &mut log);
        assert!(result.is_ok());

        let text = String::from_utf8(output).unwrap();
        assert!(text.contains("<!DOCTYPE html>"));
        assert!(text.contains("test_binary"));
        assert!(text.contains("_start"));
    }

    #[test]
    fn test_exporter_registry() {
        let reg = ExporterRegistry::with_defaults();
        let names = reg.exporter_names();
        assert!(names.contains(&"Raw Bytes"));
        assert!(names.contains(&"Intel Hex"));
        assert!(names.contains(&"Motorola Hex"));
        assert!(names.contains(&"XML"));
        assert!(names.contains(&"HTML"));
        assert!(names.contains(&"Ascii Text"));
    }

    #[test]
    fn test_exporter_registry_find() {
        let reg = ExporterRegistry::with_defaults();
        assert!(reg.find_by_name("Raw Bytes").is_some());
        assert!(reg.find_by_name("Nonexistent").is_none());
    }

    #[test]
    fn test_exporter_registry_compatible() {
        let prog = make_test_program();
        let reg = ExporterRegistry::with_defaults();
        let compatible = reg.find_compatible(&prog);
        assert!(!compatible.is_empty());
    }

    #[test]
    fn test_exporter_registry_export() {
        let prog = make_test_program();
        let mem = make_test_memory();
        let reg = ExporterRegistry::with_defaults();
        let mut output = Vec::new();
        let mut log = LoaderMessageLog::new();
        let result = reg.export("Raw Bytes", &prog, None, Some(&mem), &mut output, &mut log);
        assert!(result.is_ok());
        assert_eq!(output.len(), 32);
    }

    #[test]
    fn test_exporter_registry_unknown() {
        let prog = make_test_program();
        let mem = make_test_memory();
        let reg = ExporterRegistry::with_defaults();
        let mut output = Vec::new();
        let mut log = LoaderMessageLog::new();
        let result = reg.export("Unknown", &prog, None, Some(&mem), &mut output, &mut log);
        assert!(result.is_err());
    }

    #[test]
    fn test_program_text_options_defaults() {
        let opts = ProgramTextOptions::default();
        assert!(opts.show_addresses);
        assert!(opts.show_comments);
        assert!(opts.show_labels);
        assert_eq!(opts.address_width, 16);
        assert_eq!(opts.label_suffix, ":");
        assert_eq!(opts.comment_prefix, ";");
    }

    #[test]
    fn test_export_option_value() {
        let v = ExportOptionValue::Boolean(true);
        assert_eq!(v.as_bool(), Some(true));
        assert!(v.as_str().is_none());

        let v = ExportOptionValue::String("test".into());
        assert_eq!(v.as_str(), Some("test"));

        let v = ExportOptionValue::HexInteger(0xFF);
        assert_eq!(v.as_u64(), Some(255));
    }

    #[test]
    fn test_string_comparer() {
        use std::cmp::Ordering;
        assert_eq!(
            StringComparer::compare_ignore_case("abc", "ABC"),
            Ordering::Equal
        );
        assert_eq!(
            StringComparer::natural_compare("file2", "file10"),
            Ordering::Less
        );
        assert_eq!(
            StringComparer::natural_compare("file10", "file2"),
            Ordering::Greater
        );
    }

    #[test]
    fn test_escape_xml() {
        assert_eq!(escape_xml("a<b>c"), "a&lt;b&gt;c");
        assert_eq!(escape_xml("a&b"), "a&amp;b");
        assert_eq!(escape_xml("\"test\""), "&quot;test&quot;");
    }

    #[test]
    fn test_escape_html() {
        assert_eq!(escape_html("a<b>c"), "a&lt;b&gt;c");
        assert_eq!(escape_html("a&b"), "a&amp;b");
    }

    #[test]
    fn test_intel_hex_checksum() {
        let data = [0x03, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00];
        let cs = checksum_u8(&data);
        assert_eq!(cs, 0xFC);
    }

    #[test]
    fn test_motorola_checksum() {
        let data = [0x07, 0x00, 0x00, 0xAA, 0xBB, 0xCC, 0xDD];
        let cs = motorola_checksum(&data);
        let total: u32 = data.iter().map(|&b| b as u32).sum::<u32>() + cs as u32;
        assert_eq!(total & 0xFF, 0xFF);
    }

    #[test]
    fn test_bookmark_type_display() {
        assert_eq!(BookmarkType::Analysis.to_string(), "Analysis");
        assert_eq!(BookmarkType::Warning.to_string(), "Warning");
        assert_eq!(BookmarkType::Error.to_string(), "Error");
        assert_eq!(BookmarkType::Info.to_string(), "Info");
    }
}
