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
    Address, AddressSet, BookmarkType, Program,
};
use crate::loader::framework::MessageLog as LoaderMessageLog;

pub mod binary_exporter;
pub mod html_exporter;
pub mod export_plugin;
pub mod export_service;

pub use binary_exporter::BinaryExporter;
pub use html_exporter::HtmlExporter;

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
// ExportFormat -- user-facing export format enumeration
// ---------------------------------------------------------------------------

/// Export format selection for the ExporterDialog.
///
/// Ported from Ghidra's `ghidra.app.plugin.core.exporter.ExporterDialog`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExportFormat {
    /// Raw binary bytes.
    Binary,
    /// Intel HEX format.
    IntelHex,
    /// Motorola S-Record format.
    MotorolaHex,
    /// Plain text listing.
    AsciiText,
    /// XML representation.
    Xml,
    /// HTML listing.
    Html,
}

impl ExportFormat {
    /// All available export formats.
    pub fn all() -> &'static [ExportFormat] {
        &[
            ExportFormat::Binary,
            ExportFormat::IntelHex,
            ExportFormat::MotorolaHex,
            ExportFormat::AsciiText,
            ExportFormat::Xml,
            ExportFormat::Html,
        ]
    }

    /// Human-readable display name.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Binary => "Raw Binary (*.bin)",
            Self::IntelHex => "Intel Hex (*.hex, *.ihex)",
            Self::MotorolaHex => "Motorola S-Record (*.srec, *.s19)",
            Self::AsciiText => "ASCII Text (*.txt)",
            Self::Xml => "XML (*.xml)",
            Self::Html => "HTML (*.html, *.htm)",
        }
    }

    /// Default file extension for this format.
    pub fn default_extension(&self) -> &'static str {
        match self {
            Self::Binary => "bin",
            Self::IntelHex => "hex",
            Self::MotorolaHex => "srec",
            Self::AsciiText => "txt",
            Self::Xml => "xml",
            Self::Html => "html",
        }
    }

    /// Map to the corresponding exporter name in the registry.
    pub fn exporter_name(&self) -> &'static str {
        match self {
            Self::Binary => "Raw Bytes",
            Self::IntelHex => "Intel Hex",
            Self::MotorolaHex => "Motorola Hex",
            Self::AsciiText => "Ascii Text",
            Self::Xml => "XML",
            Self::Html => "HTML",
        }
    }
}

impl fmt::Display for ExportFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

// ---------------------------------------------------------------------------
// ExportConfig -- configuration for an export operation
// ---------------------------------------------------------------------------

/// Configuration for an export operation.
///
/// Ported from Ghidra's `ghidra.app.plugin.core.exporter.ExporterDialog`.
#[derive(Debug, Clone)]
pub struct ExportConfig {
    /// The selected export format.
    pub format: ExportFormat,
    /// The output file path.
    pub output_path: String,
    /// Whether to export only the selected address range.
    pub export_selection_only: bool,
    /// Custom options for the exporter.
    pub options: Vec<ExportOption>,
}

impl ExportConfig {
    /// Create a new export configuration.
    pub fn new(format: ExportFormat, output_path: impl Into<String>) -> Self {
        Self {
            format,
            output_path: output_path.into(),
            export_selection_only: false,
            options: Vec::new(),
        }
    }

    /// Set whether to export only the selection.
    pub fn with_selection_only(mut self, selection_only: bool) -> Self {
        self.export_selection_only = selection_only;
        self
    }

    /// Add a custom export option.
    pub fn with_option(mut self, option: ExportOption) -> Self {
        self.options.push(option);
        self
    }

    /// Find an option by name.
    pub fn get_option(&self, name: &str) -> Option<&ExportOption> {
        self.options.iter().find(|o| o.name == name)
    }
}

// ---------------------------------------------------------------------------
// ExporterPlugin -- the export plugin model
// ---------------------------------------------------------------------------

/// The export plugin model.
///
/// Ported from Ghidra's `ghidra.app.plugin.core.exporter.ExporterPlugin`.
///
/// Provides methods for initiating export operations from either the
/// front-end project view or from within a tool with an open program.
pub struct ExporterPlugin {
    /// The exporter registry.
    registry: ExporterRegistry,
    /// Event log (for testing).
    events: Vec<String>,
}

impl fmt::Debug for ExporterPlugin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExporterPlugin")
            .field("events", &self.events)
            .finish()
    }
}

impl ExporterPlugin {
    /// Create a new exporter plugin.
    pub fn new() -> Self {
        Self {
            registry: ExporterRegistry::with_defaults(),
            events: Vec::new(),
        }
    }

    /// Get available export formats.
    pub fn available_formats(&self) -> &[ExportFormat] {
        ExportFormat::all()
    }

    /// Get the exporter registry.
    pub fn registry(&self) -> &ExporterRegistry {
        &self.registry
    }

    /// Export a program using the given configuration.
    ///
    /// Returns the number of bytes written on success.
    pub fn export(
        &mut self,
        program: &Program,
        config: &ExportConfig,
        memory: Option<&MemoryModel>,
        writer: &mut dyn Write,
        log: &mut LoaderMessageLog,
    ) -> Result<u64, ExporterError> {
        let exporter_name = config.format.exporter_name();
        self.events
            .push(format!("Export: {} -> {}", exporter_name, config.output_path));

        let mut counting_writer = CountingWriter::new(writer);
        self.registry.export(
            exporter_name,
            program,
            None,
            memory,
            &mut counting_writer,
            log,
        )?;
        Ok(counting_writer.bytes_written())
    }

    /// Get the event log.
    pub fn events(&self) -> &[String] {
        &self.events
    }
}

impl Default for ExporterPlugin {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// CountingWriter -- wrapper that counts bytes written
// ---------------------------------------------------------------------------

/// A writer wrapper that counts the total bytes written.
struct CountingWriter<'a> {
    inner: &'a mut dyn Write,
    count: u64,
}

impl<'a> CountingWriter<'a> {
    fn new(inner: &'a mut dyn Write) -> Self {
        Self { inner, count: 0 }
    }

    fn bytes_written(&self) -> u64 {
        self.count
    }
}

impl<'a> Write for CountingWriter<'a> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.count += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

// ---------------------------------------------------------------------------
// ExportResult -- result of an export operation
// ---------------------------------------------------------------------------

/// Result of an export operation, containing summary information.
///
/// Ported from Ghidra's `ghidra.app.plugin.core.exporter.ExporterDialog`
/// result display logic.
#[derive(Debug, Clone)]
pub struct ExportResult {
    /// Whether the export succeeded.
    pub success: bool,
    /// The output file path.
    pub output_path: String,
    /// The size of the output file in bytes.
    pub output_size: u64,
    /// The format name used for export.
    pub format_name: String,
    /// Log messages from the export operation.
    pub messages: Vec<String>,
    /// Whether the domain file was exported directly (without opening).
    pub exported_domain_file: bool,
}

impl ExportResult {
    /// Create a successful export result.
    pub fn success(
        output_path: impl Into<String>,
        output_size: u64,
        format_name: impl Into<String>,
    ) -> Self {
        Self {
            success: true,
            output_path: output_path.into(),
            output_size,
            format_name: format_name.into(),
            messages: Vec::new(),
            exported_domain_file: false,
        }
    }

    /// Create a failed export result.
    pub fn failure(output_path: impl Into<String>, format_name: impl Into<String>) -> Self {
        Self {
            success: false,
            output_path: output_path.into(),
            output_size: 0,
            format_name: format_name.into(),
            messages: Vec::new(),
            exported_domain_file: false,
        }
    }

    /// Add a message to the result log.
    pub fn add_message(&mut self, msg: impl Into<String>) {
        self.messages.push(msg.into());
    }

    /// Generate a formatted summary string.
    ///
    /// Mirrors `ExporterDialog.displaySummaryResults()`.
    pub fn summary(&self) -> String {
        let mut buf = String::new();
        buf.push_str(&format!("Destination file:       {}\n\n", self.output_path));
        buf.push_str(&format!("Destination file Size:  {}\n", self.output_size));
        buf.push_str(&format!("Format:                 {}\n\n", self.format_name));
        for msg in &self.messages {
            buf.push_str(msg);
            buf.push('\n');
        }
        buf
    }
}

impl fmt::Display for ExportResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.success {
            write!(
                f,
                "Export to {} succeeded ({} bytes, {})",
                self.output_path, self.output_size, self.format_name
            )
        } else {
            write!(f, "Export to {} failed ({})", self.output_path, self.format_name)
        }
    }
}

// ---------------------------------------------------------------------------
// ExporterDialogModel -- state/logic for the export dialog
// ---------------------------------------------------------------------------

/// Validation status for the export dialog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationStatus {
    /// The dialog is ready to export.
    Valid,
    /// No exporter format is selected.
    NoFormatSelected,
    /// No output file path is specified.
    NoOutputFile,
    /// The output path is a directory, not a file.
    OutputIsDirectory,
    /// The output file is read-only.
    OutputReadOnly,
    /// The output file will be overwritten (warning, not error).
    OverwriteWarning(String),
    /// An XML lossy warning should be shown.
    XmlLossyWarning,
    /// A SARIF lossy warning should be shown.
    SarifLossyWarning,
    /// No applicable exporters for the domain object type.
    NoApplicableExporters,
    /// Custom validation error.
    Error(String),
}

impl ValidationStatus {
    /// Returns `true` if the export can proceed.
    pub fn is_valid(&self) -> bool {
        matches!(
            self,
            ValidationStatus::Valid
                | ValidationStatus::OverwriteWarning(_)
                | ValidationStatus::XmlLossyWarning
                | ValidationStatus::SarifLossyWarning
        )
    }

    /// Returns `true` if this is a warning (not an error).
    pub fn is_warning(&self) -> bool {
        matches!(
            self,
            ValidationStatus::OverwriteWarning(_)
                | ValidationStatus::XmlLossyWarning
                | ValidationStatus::SarifLossyWarning
        )
    }

    /// Returns the status message, if any.
    pub fn message(&self) -> Option<&str> {
        match self {
            ValidationStatus::Valid => None,
            ValidationStatus::NoFormatSelected => Some("Please select an exporter format."),
            ValidationStatus::NoOutputFile => Some("Please enter a destination file."),
            ValidationStatus::OutputIsDirectory => Some("The specified output file is a directory."),
            ValidationStatus::OutputReadOnly => Some("The specified output file is read-only."),
            ValidationStatus::OverwriteWarning(path) => Some(path.as_str()),
            ValidationStatus::XmlLossyWarning => Some(
                "Warning: XML is lossy and intended only for transferring data to external tools. \
                 GZF is the recommended format for saving and sharing program data.",
            ),
            ValidationStatus::SarifLossyWarning => Some(
                "Warning: SARIF is lossy and intended only for transferring data to external tools. \
                 GZF is the recommended format for saving and sharing program data.",
            ),
            ValidationStatus::NoApplicableExporters => {
                Some("No available exporters for content type")
            }
            ValidationStatus::Error(msg) => Some(msg.as_str()),
        }
    }
}

impl fmt::Display for ValidationStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.message() {
            Some(msg) => write!(f, "{}", msg),
            None => write!(f, "Valid"),
        }
    }
}

/// The state and logic model for the ExporterDialog.
///
/// Ported from Ghidra's `ghidra.app.plugin.core.exporter.ExporterDialog`.
///
/// This struct manages dialog state without any GUI dependencies -- format
/// selection, output path validation, selection-only mode, option management,
/// and the export execution pipeline.
///
/// # Example
///
/// ```ignore
/// let mut dialog = ExporterDialogModel::new("my_binary.elf");
/// dialog.set_format(ExportFormat::Binary);
/// dialog.set_output_path("/tmp/output.bin");
/// assert!(dialog.validate().is_valid());
/// ```
pub struct ExporterDialogModel {
    /// The name of the domain file being exported.
    domain_file_name: String,
    /// Whether the domain object was supplied by the caller (vs opened internally).
    domain_object_was_supplied: bool,
    /// The currently selected export format.
    selected_format: Option<ExportFormat>,
    /// The output file path.
    output_path: String,
    /// Whether to export only the selected addresses.
    selection_only: bool,
    /// Whether a valid address selection exists.
    has_selection: bool,
    /// The current export options for the selected format.
    options: Vec<ExportOption>,
    /// The exporter registry.
    registry: ExporterRegistry,
    /// Whether we're in front-end mode (no code browser).
    front_end_mode: bool,
    /// Last used format name (for persistence).
    last_used_format: Option<String>,
    /// Export event log.
    events: Vec<String>,
}

impl ExporterDialogModel {
    /// Create a new dialog model for exporting the given domain file.
    pub fn new(domain_file_name: impl Into<String>) -> Self {
        Self {
            domain_file_name: domain_file_name.into(),
            domain_object_was_supplied: false,
            selected_format: None,
            output_path: String::new(),
            selection_only: false,
            has_selection: false,
            options: Vec::new(),
            registry: ExporterRegistry::with_defaults(),
            front_end_mode: false,
            last_used_format: None,
            events: Vec::new(),
        }
    }

    /// Create a new dialog model in front-end mode (no code browser).
    pub fn new_front_end(domain_file_name: impl Into<String>) -> Self {
        let mut model = Self::new(domain_file_name);
        model.front_end_mode = true;
        model
    }

    /// Set whether the domain object was supplied (already open) vs needs opening.
    pub fn set_domain_object_supplied(&mut self, supplied: bool) {
        self.domain_object_was_supplied = supplied;
    }

    /// Get the domain file name being exported.
    pub fn domain_file_name(&self) -> &str {
        &self.domain_file_name
    }

    /// Whether this dialog is in front-end mode.
    pub fn is_front_end_mode(&self) -> bool {
        self.front_end_mode
    }

    // -- Format selection --

    /// Get all applicable export formats.
    pub fn applicable_formats(&self) -> &[ExportFormat] {
        ExportFormat::all()
    }

    /// Set the selected export format.
    pub fn set_format(&mut self, format: ExportFormat) {
        self.selected_format = Some(format);
        self.last_used_format = Some(format.exporter_name().to_string());
        self.events
            .push(format!("Format changed: {}", format.display_name()));
    }

    /// Get the selected export format, if any.
    pub fn selected_format(&self) -> Option<ExportFormat> {
        self.selected_format
    }

    /// Restore the last used format.
    pub fn restore_last_used_format(&mut self) {
        if let Some(ref name) = self.last_used_format {
            for fmt in ExportFormat::all() {
                if fmt.exporter_name() == name {
                    self.selected_format = Some(*fmt);
                    return;
                }
            }
        }
        // Default to Binary if last-used not found
        self.selected_format = Some(ExportFormat::Binary);
    }

    // -- Output path --

    /// Set the output file path.
    pub fn set_output_path(&mut self, path: impl Into<String>) {
        self.output_path = path.into();
    }

    /// Get the output file path.
    pub fn output_path(&self) -> &str {
        &self.output_path
    }

    /// Generate a default output file name based on the domain file name.
    pub fn default_output_filename(&self) -> String {
        let ext = self
            .selected_format
            .map(|f| format!(".{}", f.default_extension()))
            .unwrap_or_default();
        format!("{}{}", self.domain_file_name, ext)
    }

    /// Append the exporter's file extension to the output path if missing.
    pub fn output_path_with_extension(&self) -> String {
        let path = self.output_path.trim().to_string();
        if path.is_empty() {
            return path;
        }
        if let Some(format) = self.selected_format {
            let ext = format!(".{}", format.default_extension());
            if !path.to_lowercase().ends_with(&ext.to_lowercase()) {
                return format!("{}{}", path, ext);
            }
        }
        path
    }

    // -- Selection --

    /// Set whether a valid address selection exists.
    pub fn set_has_selection(&mut self, has: bool) {
        self.has_selection = has;
    }

    /// Set the selection-only flag.
    pub fn set_selection_only(&mut self, selection_only: bool) {
        self.selection_only = selection_only;
    }

    /// Get the selection-only flag.
    pub fn is_selection_only(&self) -> bool {
        self.selection_only
    }

    /// Whether the selection checkbox should be enabled.
    ///
    /// Mirrors `ExporterDialog.shouldEnableCheckbox()`.
    pub fn should_enable_selection_checkbox(&self) -> bool {
        if !self.has_selection {
            return false;
        }
        if self.front_end_mode {
            return false;
        }
        self.selected_format
            .map(|f| {
                let name = f.exporter_name();
                self.registry
                    .find_by_name(name)
                    .map(|e| e.supports_address_restricted_export())
                    .unwrap_or(false)
            })
            .unwrap_or(false)
    }

    // -- Options --

    /// Get the current export options.
    pub fn options(&self) -> &[ExportOption] {
        &self.options
    }

    /// Set the export options.
    pub fn set_options(&mut self, options: Vec<ExportOption>) {
        self.options = options;
    }

    /// Whether the current format has options.
    pub fn has_options(&self) -> bool {
        !self.options.is_empty()
    }

    /// Validate a single option value.
    ///
    /// Returns `Ok(())` if valid, or an error message.
    pub fn validate_option(&self, name: &str, value: &ExportOptionValue) -> Result<(), String> {
        if let Some(opt) = self.options.iter().find(|o| o.name == name) {
            match (&opt.option_type, value) {
                (ExportOptionType::Boolean, ExportOptionValue::Boolean(_)) => Ok(()),
                (ExportOptionType::String, ExportOptionValue::String(_)) => Ok(()),
                (ExportOptionType::Integer, ExportOptionValue::Integer(v)) => {
                    if *v < 0 {
                        Err("Value must be non-negative".into())
                    } else {
                        Ok(())
                    }
                }
                (ExportOptionType::HexInteger, ExportOptionValue::HexInteger(_)) => Ok(()),
                (ExportOptionType::Choice(choices), ExportOptionValue::String(v)) => {
                    if choices.contains(v) {
                        Ok(())
                    } else {
                        Err(format!("Invalid choice: '{}'. Valid: {:?}", v, choices))
                    }
                }
                _ => Err("Option type mismatch".into()),
            }
        } else {
            Err(format!("Unknown option: {}", name))
        }
    }

    // -- Validation --

    /// Validate the current dialog state.
    ///
    /// Mirrors `ExporterDialog.validate()`.
    pub fn validate(&self) -> ValidationStatus {
        if self.selected_format.is_none() {
            return ValidationStatus::NoFormatSelected;
        }

        let path = self.output_path.trim();
        if path.is_empty() {
            return ValidationStatus::NoOutputFile;
        }

        // Check if output path is a directory (in a real system)
        let output_file = std::path::Path::new(path);
        if output_file.exists() && output_file.is_dir() {
            return ValidationStatus::OutputIsDirectory;
        }

        // Check format-specific warnings
        let format = self.selected_format.unwrap();
        match format {
            ExportFormat::Xml => return ValidationStatus::XmlLossyWarning,
            ExportFormat::Html => {} // no warning
            _ => {}
        }

        // Check for SARIF (not in our enum, but check by name pattern)
        if format.exporter_name().contains("SARIF") {
            return ValidationStatus::SarifLossyWarning;
        }

        ValidationStatus::Valid
    }

    // -- Export execution --

    /// Execute the export operation.
    ///
    /// Returns an `ExportResult` with success/failure status and summary info.
    ///
    /// Mirrors `ExporterDialog.ExportTask.run()`.
    pub fn execute_export(
        &mut self,
        program: &Program,
        memory: Option<&MemoryModel>,
        writer: &mut dyn Write,
        log: &mut LoaderMessageLog,
    ) -> ExportResult {
        let format = match self.selected_format {
            Some(f) => f,
            None => {
                let mut result = ExportResult::failure(&self.output_path, "None");
                result.add_message("No export format selected");
                return result;
            }
        };

        let exporter_name = format.exporter_name();
        self.events
            .push(format!("Export started: {} -> {}", exporter_name, self.output_path));

        let mut counting = CountingWriter::new(writer);
        let result = self.registry.export(
            exporter_name,
            program,
            None,
            memory,
            &mut counting,
            log,
        );

        match result {
            Ok(true) => {
                let bytes = counting.bytes_written();
                self.events.push(format!("Export completed: {} bytes", bytes));
                let mut export_result =
                    ExportResult::success(&self.output_path, bytes, format.display_name());
                export_result.exported_domain_file = !self.domain_object_was_supplied;
                export_result
            }
            Ok(false) => {
                self.events.push("Export returned false (partial/empty)".into());
                let mut export_result = ExportResult::failure(&self.output_path, format.display_name());
                export_result.add_message("Export returned false (possibly empty or unsupported address space)");
                export_result
            }
            Err(e) => {
                let msg = format!("Export error: {}", e);
                self.events.push(msg.clone());
                let mut export_result = ExportResult::failure(&self.output_path, format.display_name());
                export_result.add_message(msg);
                export_result
            }
        }
    }

    /// Get the event log.
    pub fn events(&self) -> &[String] {
        &self.events
    }

    /// Get a mutable reference to the exporter registry.
    pub fn registry_mut(&mut self) -> &mut ExporterRegistry {
        &mut self.registry
    }

    /// Get a reference to the exporter registry.
    pub fn registry(&self) -> &ExporterRegistry {
        &self.registry
    }
}

impl Default for ExporterDialogModel {
    fn default() -> Self {
        Self::new("untitled")
    }
}

// ---------------------------------------------------------------------------
// FrontEndExportAction -- project-tree export action
// ---------------------------------------------------------------------------

/// Model for the front-end project-tree export action.
///
/// Ported from Ghidra's `ghidra.app.plugin.core.exporter.ExporterPlugin`
/// (`createFrontEndAction` method).
///
/// This represents the "Export..." action available in the Ghidra project
/// manager's right-click context menu on domain files.
#[derive(Debug, Clone)]
pub struct FrontEndExportAction {
    /// The action name.
    pub name: String,
    /// The owner plugin name.
    pub owner: String,
    /// The popup menu path.
    pub menu_path: Vec<String>,
    /// The menu group.
    pub menu_group: String,
    /// Description text.
    pub description: String,
    /// Help topic.
    pub help_topic: Option<HelpLocation>,
    /// Whether the action is currently enabled.
    enabled: bool,
}

/// Help location for export actions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelpLocation {
    /// The help set name.
    pub help_set: String,
    /// The topic name.
    pub topic: String,
    /// The anchor within the topic.
    pub anchor: Option<String>,
}

impl HelpLocation {
    /// Create a new help location.
    pub fn new(help_set: impl Into<String>, topic: impl Into<String>) -> Self {
        Self {
            help_set: help_set.into(),
            topic: topic.into(),
            anchor: None,
        }
    }

    /// Create a help location with an anchor.
    pub fn with_anchor(mut self, anchor: impl Into<String>) -> Self {
        self.anchor = Some(anchor.into());
        self
    }
}

impl FrontEndExportAction {
    /// Create the standard front-end export action.
    ///
    /// Mirrors the action created in `ExporterPlugin.createFrontEndAction()`.
    pub fn new() -> Self {
        Self {
            name: "Export".into(),
            owner: "ExporterPlugin".into(),
            menu_path: vec!["Export...".into()],
            menu_group: "Export".into(),
            description: "Export Program/Datatype Archives".into(),
            help_topic: Some(HelpLocation::new("ExporterPlugin", "Export")),
            enabled: true,
        }
    }

    /// Check if the action should be enabled for the given context.
    ///
    /// Mirrors `ExporterPlugin.createFrontEndAction().isEnabledForContext()`.
    pub fn is_enabled_for_context(&self, ctx: &ProjectDataContext) -> bool {
        // Not enabled if folders are selected
        if !ctx.selected_folders.is_empty() {
            return false;
        }
        // Must select exactly one file
        if ctx.selected_files.len() != 1 {
            return false;
        }
        // Not enabled for folder links
        let file = &ctx.selected_files[0];
        if file.is_link && file.is_folder_link {
            return false;
        }
        true
    }

    /// Get the selected domain file from the context, if valid.
    pub fn get_selected_file<'a>(&self, ctx: &'a ProjectDataContext) -> Option<&'a DomainFileInfo> {
        if !self.is_enabled_for_context(ctx) {
            return None;
        }
        ctx.selected_files.first()
    }
}

impl Default for FrontEndExportAction {
    fn default() -> Self {
        Self::new()
    }
}

/// Model for the tool-level export action.
///
/// Ported from Ghidra's `ghidra.app.plugin.core.exporter.ExporterPlugin`
/// (`createToolAction` method).
#[derive(Debug, Clone)]
pub struct ToolExportAction {
    /// The action name.
    pub name: String,
    /// The owner plugin name.
    pub owner: String,
    /// The menu bar path.
    pub menu_path: Vec<String>,
    /// The menu group.
    pub menu_group: String,
    /// The menu sub-group (for ordering).
    pub menu_sub_group: String,
    /// The key binding (virtual key code).
    pub key_binding: Option<u32>,
    /// Description text.
    pub description: String,
    /// Help topic.
    pub help_topic: Option<HelpLocation>,
}

impl ToolExportAction {
    /// Create the standard tool export action.
    ///
    /// Mirrors the action created in `ExporterPlugin.createToolAction()`.
    pub fn new() -> Self {
        Self {
            name: "Export Program".into(),
            owner: "ExporterPlugin".into(),
            menu_path: vec!["&File".into(), "Export Program...".into()],
            menu_group: "Import Export".into(),
            menu_sub_group: "z".into(),
            key_binding: Some(79), // VK_O = 79 (Ctrl+O convention)
            description: "This plugin exports a program or datatype archive to an external file."
                .into(),
            help_topic: Some(HelpLocation::new("ExporterPlugin", "Export")),
        }
    }
}

impl Default for ToolExportAction {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// ProjectDataContext / DomainFileInfo -- minimal models for action context
// ---------------------------------------------------------------------------

/// Minimal model of a domain file in the project tree.
///
/// Ported from `ghidra.framework.model.DomainFile`.
#[derive(Debug, Clone)]
pub struct DomainFileInfo {
    /// The file name.
    pub name: String,
    /// Whether this is a link.
    pub is_link: bool,
    /// Whether this is a folder link (only meaningful when `is_link` is true).
    pub is_folder_link: bool,
    /// The content type class name.
    pub content_type: String,
}

impl DomainFileInfo {
    /// Create a new domain file info.
    pub fn new(name: impl Into<String>, content_type: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            is_link: false,
            is_folder_link: false,
            content_type: content_type.into(),
        }
    }

    /// Create a linked domain file info.
    pub fn new_link(
        name: impl Into<String>,
        content_type: impl Into<String>,
        is_folder_link: bool,
    ) -> Self {
        Self {
            name: name.into(),
            is_link: true,
            is_folder_link,
            content_type: content_type.into(),
        }
    }
}

/// Minimal model of the project data context for action enablement.
///
/// Ported from `ghidra.framework.main.datatable.ProjectDataContext`.
#[derive(Debug, Clone, Default)]
pub struct ProjectDataContext {
    /// Selected files in the project tree.
    pub selected_files: Vec<DomainFileInfo>,
    /// Selected folders in the project tree.
    pub selected_folders: Vec<String>,
}

impl ProjectDataContext {
    /// Create a new project data context.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a selected file.
    pub fn with_file(mut self, file: DomainFileInfo) -> Self {
        self.selected_files.push(file);
        self
    }

    /// Add a selected folder.
    pub fn with_folder(mut self, folder: impl Into<String>) -> Self {
        self.selected_folders.push(folder.into());
        self
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::analyzer::AddressRange;
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
    fn test_intel_hex_checksum() {
        let data = [0x03, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00];
        let cs = checksum_u8(&data);
        assert_eq!(cs, 0xFB);
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

    #[test]
    fn test_export_format_display_name() {
        assert_eq!(ExportFormat::Binary.display_name(), "Raw Binary (*.bin)");
        assert_eq!(
            ExportFormat::IntelHex.display_name(),
            "Intel Hex (*.hex, *.ihex)"
        );
        assert_eq!(
            ExportFormat::Html.display_name(),
            "HTML (*.html, *.htm)"
        );
    }

    #[test]
    fn test_export_format_extension() {
        assert_eq!(ExportFormat::Binary.default_extension(), "bin");
        assert_eq!(ExportFormat::Xml.default_extension(), "xml");
        assert_eq!(ExportFormat::Html.default_extension(), "html");
    }

    #[test]
    fn test_export_format_exporter_name() {
        assert_eq!(ExportFormat::Binary.exporter_name(), "Raw Bytes");
        assert_eq!(ExportFormat::IntelHex.exporter_name(), "Intel Hex");
        assert_eq!(ExportFormat::MotorolaHex.exporter_name(), "Motorola Hex");
    }

    #[test]
    fn test_export_format_all() {
        let all = ExportFormat::all();
        assert_eq!(all.len(), 6);
    }

    #[test]
    fn test_export_format_display() {
        assert_eq!(
            format!("{}", ExportFormat::Binary),
            "Raw Binary (*.bin)"
        );
    }

    #[test]
    fn test_export_config() {
        let config = ExportConfig::new(ExportFormat::Binary, "/tmp/output.bin")
            .with_selection_only(true);
        assert_eq!(config.format, ExportFormat::Binary);
        assert_eq!(config.output_path, "/tmp/output.bin");
        assert!(config.export_selection_only);
    }

    #[test]
    fn test_export_config_option() {
        let config = ExportConfig::new(ExportFormat::IntelHex, "/tmp/out.hex")
            .with_option(ExportOption {
                name: "Record Size".into(),
                option_type: ExportOptionType::Integer,
                default_value: ExportOptionValue::Integer(32),
                description: Some("Size of each record".into()),
            });
        let opt = config.get_option("Record Size").unwrap();
        assert_eq!(opt.default_value.as_i64(), Some(32));
    }

    #[test]
    fn test_exporter_plugin() {
        let plugin = ExporterPlugin::new();
        assert_eq!(plugin.available_formats().len(), 6);
        assert!(plugin.events().is_empty());
    }

    #[test]
    fn test_exporter_plugin_export() {
        let mut plugin = ExporterPlugin::new();
        let prog = make_test_program();
        let mem = make_test_memory();
        let config = ExportConfig::new(ExportFormat::Binary, "/tmp/out.bin");

        let mut output = Vec::new();
        let mut log = LoaderMessageLog::new();
        let bytes = plugin
            .export(&prog, &config, Some(&mem), &mut output, &mut log)
            .unwrap();
        assert_eq!(bytes, 32);
        assert_eq!(output.len(), 32);
        assert_eq!(plugin.events().len(), 1);
    }

    // ========================================================================
    // ExportResult tests
    // ========================================================================

    #[test]
    fn test_export_result_success() {
        let result = ExportResult::success("/tmp/out.bin", 1024, "Raw Binary (*.bin)");
        assert!(result.success);
        assert_eq!(result.output_size, 1024);
        assert_eq!(result.format_name, "Raw Binary (*.bin)");
        assert!(result.messages.is_empty());
    }

    #[test]
    fn test_export_result_failure() {
        let result = ExportResult::failure("/tmp/out.bin", "Raw Binary (*.bin)");
        assert!(!result.success);
        assert_eq!(result.output_size, 0);
    }

    #[test]
    fn test_export_result_add_message() {
        let mut result = ExportResult::success("/tmp/out.bin", 100, "XML");
        result.add_message("Exported 100 bytes");
        assert_eq!(result.messages.len(), 1);
        assert_eq!(result.messages[0], "Exported 100 bytes");
    }

    #[test]
    fn test_export_result_summary() {
        let mut result = ExportResult::success("/tmp/test.bin", 256, "Raw Binary (*.bin)");
        result.add_message("No warnings");
        let summary = result.summary();
        assert!(summary.contains("Destination file:       /tmp/test.bin"));
        assert!(summary.contains("Destination file Size:  256"));
        assert!(summary.contains("Format:                 Raw Binary (*.bin)"));
        assert!(summary.contains("No warnings"));
    }

    #[test]
    fn test_export_result_display() {
        let success = ExportResult::success("/tmp/out.bin", 100, "Binary");
        assert!(success.to_string().contains("succeeded"));
        assert!(success.to_string().contains("100 bytes"));

        let failure = ExportResult::failure("/tmp/out.bin", "Binary");
        assert!(failure.to_string().contains("failed"));
    }

    // ========================================================================
    // ValidationStatus tests
    // ========================================================================

    #[test]
    fn test_validation_status_is_valid() {
        assert!(ValidationStatus::Valid.is_valid());
        assert!(ValidationStatus::XmlLossyWarning.is_valid());
        assert!(ValidationStatus::SarifLossyWarning.is_valid());
        assert!(ValidationStatus::OverwriteWarning("exists".into()).is_valid());
        assert!(!ValidationStatus::NoFormatSelected.is_valid());
        assert!(!ValidationStatus::NoOutputFile.is_valid());
        assert!(!ValidationStatus::OutputIsDirectory.is_valid());
        assert!(!ValidationStatus::OutputReadOnly.is_valid());
        assert!(!ValidationStatus::NoApplicableExporters.is_valid());
    }

    #[test]
    fn test_validation_status_is_warning() {
        assert!(ValidationStatus::XmlLossyWarning.is_warning());
        assert!(ValidationStatus::SarifLossyWarning.is_warning());
        assert!(ValidationStatus::OverwriteWarning("x".into()).is_warning());
        assert!(!ValidationStatus::Valid.is_warning());
        assert!(!ValidationStatus::NoFormatSelected.is_warning());
    }

    #[test]
    fn test_validation_status_message() {
        assert!(ValidationStatus::Valid.message().is_none());
        assert_eq!(
            ValidationStatus::NoFormatSelected.message(),
            Some("Please select an exporter format.")
        );
        assert_eq!(
            ValidationStatus::NoOutputFile.message(),
            Some("Please enter a destination file.")
        );
        assert!(ValidationStatus::XmlLossyWarning
            .message()
            .unwrap()
            .contains("XML is lossy"));
        assert!(ValidationStatus::SarifLossyWarning
            .message()
            .unwrap()
            .contains("SARIF is lossy"));
    }

    #[test]
    fn test_validation_status_display() {
        assert_eq!(ValidationStatus::Valid.to_string(), "Valid");
        assert!(ValidationStatus::NoFormatSelected
            .to_string()
            .contains("select an exporter"));
    }

    // ========================================================================
    // ExporterDialogModel tests
    // ========================================================================

    #[test]
    fn test_dialog_model_new() {
        let dialog = ExporterDialogModel::new("test.elf");
        assert_eq!(dialog.domain_file_name(), "test.elf");
        assert!(!dialog.is_front_end_mode());
        assert!(dialog.selected_format().is_none());
        assert!(dialog.output_path().is_empty());
        assert!(!dialog.is_selection_only());
        assert!(dialog.options().is_empty());
    }

    #[test]
    fn test_dialog_model_front_end() {
        let dialog = ExporterDialogModel::new_front_end("test.elf");
        assert!(dialog.is_front_end_mode());
    }

    #[test]
    fn test_dialog_model_format_selection() {
        let mut dialog = ExporterDialogModel::new("test.elf");
        assert!(dialog.selected_format().is_none());

        dialog.set_format(ExportFormat::Binary);
        assert_eq!(dialog.selected_format(), Some(ExportFormat::Binary));

        dialog.set_format(ExportFormat::IntelHex);
        assert_eq!(dialog.selected_format(), Some(ExportFormat::IntelHex));

        assert_eq!(dialog.events().len(), 2);
    }

    #[test]
    fn test_dialog_model_last_used_format() {
        let mut dialog = ExporterDialogModel::new("test.elf");
        dialog.set_format(ExportFormat::IntelHex);

        let mut dialog2 = ExporterDialogModel::new("test.elf");
        dialog2.last_used_format = Some("Intel Hex".to_string());
        dialog2.restore_last_used_format();
        assert_eq!(dialog2.selected_format(), Some(ExportFormat::IntelHex));
    }

    #[test]
    fn test_dialog_model_last_used_format_fallback() {
        let mut dialog = ExporterDialogModel::new("test.elf");
        dialog.last_used_format = Some("Nonexistent".to_string());
        dialog.restore_last_used_format();
        assert_eq!(dialog.selected_format(), Some(ExportFormat::Binary));
    }

    #[test]
    fn test_dialog_model_output_path() {
        let mut dialog = ExporterDialogModel::new("test.elf");
        dialog.set_output_path("/tmp/output.bin");
        assert_eq!(dialog.output_path(), "/tmp/output.bin");
    }

    #[test]
    fn test_dialog_model_default_output_filename() {
        let mut dialog = ExporterDialogModel::new("test.elf");
        dialog.set_format(ExportFormat::Binary);
        assert_eq!(dialog.default_output_filename(), "test.elf.bin");

        dialog.set_format(ExportFormat::Xml);
        assert_eq!(dialog.default_output_filename(), "test.elf.xml");
    }

    #[test]
    fn test_dialog_model_output_path_with_extension() {
        let mut dialog = ExporterDialogModel::new("test.elf");
        dialog.set_format(ExportFormat::Binary);

        // Path already has extension
        dialog.set_output_path("/tmp/out.bin");
        assert_eq!(dialog.output_path_with_extension(), "/tmp/out.bin");

        // Path missing extension
        dialog.set_output_path("/tmp/out");
        assert_eq!(dialog.output_path_with_extension(), "/tmp/out.bin");

        // Case insensitive extension check
        dialog.set_output_path("/tmp/out.BIN");
        assert_eq!(dialog.output_path_with_extension(), "/tmp/out.BIN");

        // Empty path
        dialog.set_output_path("");
        assert_eq!(dialog.output_path_with_extension(), "");
    }

    #[test]
    fn test_dialog_model_selection() {
        let mut dialog = ExporterDialogModel::new("test.elf");
        assert!(!dialog.is_selection_only());

        dialog.set_has_selection(true);
        dialog.set_selection_only(true);
        assert!(dialog.is_selection_only());
    }

    #[test]
    fn test_dialog_model_selection_checkbox() {
        let mut dialog = ExporterDialogModel::new("test.elf");

        // No selection, no format -> disabled
        assert!(!dialog.should_enable_selection_checkbox());

        // Selection exists, no format -> disabled
        dialog.set_has_selection(true);
        assert!(!dialog.should_enable_selection_checkbox());

        // Selection + format -> enabled
        dialog.set_format(ExportFormat::Binary);
        assert!(dialog.should_enable_selection_checkbox());

        // Front-end mode -> disabled
        let mut fe_dialog = ExporterDialogModel::new_front_end("test.elf");
        fe_dialog.set_has_selection(true);
        fe_dialog.set_format(ExportFormat::Binary);
        assert!(!fe_dialog.should_enable_selection_checkbox());
    }

    #[test]
    fn test_dialog_model_options() {
        let mut dialog = ExporterDialogModel::new("test.elf");
        assert!(!dialog.has_options());

        dialog.set_options(vec![
            ExportOption {
                name: "Record Size".into(),
                option_type: ExportOptionType::Integer,
                default_value: ExportOptionValue::Integer(16),
                description: Some("HEX record size".into()),
            },
        ]);
        assert!(dialog.has_options());
        assert_eq!(dialog.options().len(), 1);
    }

    #[test]
    fn test_dialog_model_validate_option() {
        let mut dialog = ExporterDialogModel::new("test.elf");
        dialog.set_options(vec![
            ExportOption {
                name: "Record Size".into(),
                option_type: ExportOptionType::Integer,
                default_value: ExportOptionValue::Integer(16),
                description: None,
            },
            ExportOption {
                name: "Format".into(),
                option_type: ExportOptionType::Choice(vec!["S1".into(), "S2".into(), "S3".into()]),
                default_value: ExportOptionValue::String("S3".into()),
                description: None,
            },
        ]);

        // Valid integer
        assert!(dialog.validate_option("Record Size", &ExportOptionValue::Integer(32)).is_ok());

        // Negative integer
        assert!(dialog.validate_option("Record Size", &ExportOptionValue::Integer(-1)).is_err());

        // Valid choice
        assert!(dialog.validate_option("Format", &ExportOptionValue::String("S1".into())).is_ok());

        // Invalid choice
        assert!(dialog.validate_option("Format", &ExportOptionValue::String("S4".into())).is_err());

        // Unknown option
        assert!(dialog.validate_option("Unknown", &ExportOptionValue::Boolean(true)).is_err());

        // Type mismatch
        assert!(dialog.validate_option("Record Size", &ExportOptionValue::Boolean(true)).is_err());
    }

    #[test]
    fn test_dialog_model_validate() {
        let mut dialog = ExporterDialogModel::new("test.elf");

        // No format selected
        assert_eq!(dialog.validate(), ValidationStatus::NoFormatSelected);

        // Format selected, no output file
        dialog.set_format(ExportFormat::Binary);
        assert_eq!(dialog.validate(), ValidationStatus::NoOutputFile);

        // Format + output -> valid
        dialog.set_output_path("/tmp/out.bin");
        assert_eq!(dialog.validate(), ValidationStatus::Valid);

        // XML format -> lossy warning
        dialog.set_format(ExportFormat::Xml);
        assert_eq!(dialog.validate(), ValidationStatus::XmlLossyWarning);
    }

    #[test]
    fn test_dialog_model_execute_export() {
        let mut dialog = ExporterDialogModel::new("test.elf");
        dialog.set_format(ExportFormat::Binary);
        dialog.set_output_path("/tmp/out.bin");
        dialog.set_domain_object_supplied(true);

        let prog = make_test_program();
        let mem = make_test_memory();
        let mut output = Vec::new();
        let mut log = LoaderMessageLog::new();

        let result = dialog.execute_export(&prog, Some(&mem), &mut output, &mut log);
        assert!(result.success);
        assert_eq!(result.output_size, 32);
        assert_eq!(output.len(), 32);
        assert!(!result.exported_domain_file);
        assert!(result.summary().contains("Raw Binary"));
    }

    #[test]
    fn test_dialog_model_execute_export_no_format() {
        let mut dialog = ExporterDialogModel::new("test.elf");
        // No format set

        let prog = make_test_program();
        let mem = make_test_memory();
        let mut output = Vec::new();
        let mut log = LoaderMessageLog::new();

        let result = dialog.execute_export(&prog, Some(&mem), &mut output, &mut log);
        assert!(!result.success);
        assert!(result.messages[0].contains("No export format selected"));
    }

    #[test]
    fn test_dialog_model_execute_export_domain_file() {
        let mut dialog = ExporterDialogModel::new("test.elf");
        dialog.set_format(ExportFormat::Binary);
        dialog.set_output_path("/tmp/out.bin");
        dialog.set_domain_object_supplied(false);

        let prog = make_test_program();
        let mem = make_test_memory();
        let mut output = Vec::new();
        let mut log = LoaderMessageLog::new();

        let result = dialog.execute_export(&prog, Some(&mem), &mut output, &mut log);
        assert!(result.success);
        assert!(result.exported_domain_file);
    }

    #[test]
    fn test_dialog_model_execute_export_events() {
        let mut dialog = ExporterDialogModel::new("test.elf");
        dialog.set_format(ExportFormat::Binary);
        dialog.set_output_path("/tmp/out.bin");

        let prog = make_test_program();
        let mem = make_test_memory();
        let mut output = Vec::new();
        let mut log = LoaderMessageLog::new();

        dialog.execute_export(&prog, Some(&mem), &mut output, &mut log);

        // Should have format change + export started + export completed
        let events = dialog.events();
        assert!(events.len() >= 3);
        assert!(events.iter().any(|e| e.contains("Format changed")));
        assert!(events.iter().any(|e| e.contains("Export started")));
        assert!(events.iter().any(|e| e.contains("Export completed")));
    }

    #[test]
    fn test_dialog_model_default() {
        let dialog = ExporterDialogModel::default();
        assert_eq!(dialog.domain_file_name(), "untitled");
    }

    // ========================================================================
    // FrontEndExportAction tests
    // ========================================================================

    #[test]
    fn test_front_end_export_action_new() {
        let action = FrontEndExportAction::new();
        assert_eq!(action.name, "Export");
        assert_eq!(action.owner, "ExporterPlugin");
        assert_eq!(action.menu_path, vec!["Export..."]);
        assert!(action.help_topic.is_some());
    }

    #[test]
    fn test_front_end_action_enabled_single_file() {
        let action = FrontEndExportAction::new();
        let ctx = ProjectDataContext::new()
            .with_file(DomainFileInfo::new("test.elf", "Program"));
        assert!(action.is_enabled_for_context(&ctx));
    }

    #[test]
    fn test_front_end_action_disabled_no_selection() {
        let action = FrontEndExportAction::new();
        let ctx = ProjectDataContext::new();
        assert!(!action.is_enabled_for_context(&ctx));
    }

    #[test]
    fn test_front_end_action_disabled_multiple_files() {
        let action = FrontEndExportAction::new();
        let ctx = ProjectDataContext::new()
            .with_file(DomainFileInfo::new("a.elf", "Program"))
            .with_file(DomainFileInfo::new("b.elf", "Program"));
        assert!(!action.is_enabled_for_context(&ctx));
    }

    #[test]
    fn test_front_end_action_disabled_folder_selected() {
        let action = FrontEndExportAction::new();
        let ctx = ProjectDataContext::new()
            .with_file(DomainFileInfo::new("test.elf", "Program"))
            .with_folder("my_folder");
        assert!(!action.is_enabled_for_context(&ctx));
    }

    #[test]
    fn test_front_end_action_disabled_folder_link() {
        let action = FrontEndExportAction::new();
        let ctx = ProjectDataContext::new()
            .with_file(DomainFileInfo::new_link("test.elf", "Program", true));
        assert!(!action.is_enabled_for_context(&ctx));
    }

    #[test]
    fn test_front_end_action_enabled_file_link() {
        let action = FrontEndExportAction::new();
        let ctx = ProjectDataContext::new()
            .with_file(DomainFileInfo::new_link("test.elf", "Program", false));
        assert!(action.is_enabled_for_context(&ctx));
    }

    #[test]
    fn test_front_end_action_get_selected_file() {
        let action = FrontEndExportAction::new();
        let ctx = ProjectDataContext::new()
            .with_file(DomainFileInfo::new("test.elf", "Program"));
        let file = action.get_selected_file(&ctx);
        assert!(file.is_some());
        assert_eq!(file.unwrap().name, "test.elf");
    }

    #[test]
    fn test_front_end_action_get_selected_file_none() {
        let action = FrontEndExportAction::new();
        let ctx = ProjectDataContext::new();
        assert!(action.get_selected_file(&ctx).is_none());
    }

    #[test]
    fn test_front_end_action_default() {
        let action = FrontEndExportAction::default();
        assert_eq!(action.name, "Export");
    }

    // ========================================================================
    // ToolExportAction tests
    // ========================================================================

    #[test]
    fn test_tool_export_action_new() {
        let action = ToolExportAction::new();
        assert_eq!(action.name, "Export Program");
        assert_eq!(action.owner, "ExporterPlugin");
        assert_eq!(action.menu_path, vec!["&File", "Export Program..."]);
        assert_eq!(action.menu_group, "Import Export");
        assert_eq!(action.menu_sub_group, "z");
        assert_eq!(action.key_binding, Some(79)); // VK_O
        assert!(action.description.contains("exports a program"));
    }

    #[test]
    fn test_tool_export_action_default() {
        let action = ToolExportAction::default();
        assert_eq!(action.name, "Export Program");
    }

    // ========================================================================
    // DomainFileInfo tests
    // ========================================================================

    #[test]
    fn test_domain_file_info_new() {
        let file = DomainFileInfo::new("test.elf", "Program");
        assert_eq!(file.name, "test.elf");
        assert_eq!(file.content_type, "Program");
        assert!(!file.is_link);
        assert!(!file.is_folder_link);
    }

    #[test]
    fn test_domain_file_info_new_link() {
        let file = DomainFileInfo::new_link("test.elf", "Program", false);
        assert!(file.is_link);
        assert!(!file.is_folder_link);

        let folder_link = DomainFileInfo::new_link("test.elf", "Program", true);
        assert!(folder_link.is_link);
        assert!(folder_link.is_folder_link);
    }

    // ========================================================================
    // ProjectDataContext tests
    // ========================================================================

    #[test]
    fn test_project_data_context_default() {
        let ctx = ProjectDataContext::new();
        assert!(ctx.selected_files.is_empty());
        assert!(ctx.selected_folders.is_empty());
    }

    #[test]
    fn test_project_data_context_builder() {
        let ctx = ProjectDataContext::new()
            .with_file(DomainFileInfo::new("test.elf", "Program"))
            .with_folder("my_folder");
        assert_eq!(ctx.selected_files.len(), 1);
        assert_eq!(ctx.selected_folders.len(), 1);
    }

    // ========================================================================
    // HelpLocation tests
    // ========================================================================

    #[test]
    fn test_help_location_new() {
        let loc = HelpLocation::new("ExporterPlugin", "Export");
        assert_eq!(loc.help_set, "ExporterPlugin");
        assert_eq!(loc.topic, "Export");
        assert!(loc.anchor.is_none());
    }

    #[test]
    fn test_help_location_with_anchor() {
        let loc = HelpLocation::new("ExporterPlugin", "Export").with_anchor("Options");
        assert_eq!(loc.anchor, Some("Options".into()));
    }

    // ========================================================================
    // Cross-type integration tests
    // ========================================================================

    #[test]
    fn test_full_export_workflow_binary() {
        let mut dialog = ExporterDialogModel::new("program.exe");
        dialog.set_format(ExportFormat::Binary);
        dialog.set_output_path("/tmp/program.exe.bin");
        dialog.set_domain_object_supplied(true);
        dialog.set_has_selection(true);
        dialog.set_selection_only(false);

        let status = dialog.validate();
        assert!(status.is_valid(), "Expected valid, got: {}", status);

        let prog = make_test_program();
        let mem = make_test_memory();
        let mut output = Vec::new();
        let mut log = LoaderMessageLog::new();

        let result = dialog.execute_export(&prog, Some(&mem), &mut output, &mut log);
        assert!(result.success);
        assert_eq!(result.output_size, 32);
        assert!(result.summary().contains("Raw Binary"));
    }

    #[test]
    fn test_full_export_workflow_intel_hex() {
        let mut dialog = ExporterDialogModel::new("firmware.bin");
        dialog.set_format(ExportFormat::IntelHex);
        dialog.set_output_path("/tmp/firmware.hex");
        dialog.set_domain_object_supplied(true);

        let status = dialog.validate();
        assert!(status.is_valid());

        let prog = make_test_program();
        let mem = make_test_memory();
        let mut output = Vec::new();
        let mut log = LoaderMessageLog::new();

        let result = dialog.execute_export(&prog, Some(&mem), &mut output, &mut log);
        assert!(result.success);

        let text = String::from_utf8(output).unwrap();
        assert!(text.contains(":00000001FF"));
    }

    #[test]
    fn test_full_export_workflow_xml_warning() {
        let mut dialog = ExporterDialogModel::new("program.exe");
        dialog.set_format(ExportFormat::Xml);
        dialog.set_output_path("/tmp/program.xml");

        let status = dialog.validate();
        assert!(status.is_valid()); // Warnings are still valid
        assert!(status.is_warning());
        assert!(status.message().unwrap().contains("XML is lossy"));

        let prog = make_test_program();
        let mem = make_test_memory();
        let mut output = Vec::new();
        let mut log = LoaderMessageLog::new();

        let result = dialog.execute_export(&prog, Some(&mem), &mut output, &mut log);
        assert!(result.success);

        let text = String::from_utf8(output).unwrap();
        assert!(text.contains("<?xml"));
    }

    #[test]
    fn test_full_export_workflow_html() {
        let mut dialog = ExporterDialogModel::new("program.exe");
        dialog.set_format(ExportFormat::Html);
        dialog.set_output_path("/tmp/program.html");

        let status = dialog.validate();
        assert!(status.is_valid());

        let prog = make_test_program();
        let mem = make_test_memory();
        let mut output = Vec::new();
        let mut log = LoaderMessageLog::new();

        let result = dialog.execute_export(&prog, Some(&mem), &mut output, &mut log);
        assert!(result.success);

        let text = String::from_utf8(output).unwrap();
        assert!(text.contains("<!DOCTYPE html>"));
    }

    #[test]
    fn test_front_end_action_with_export_dialog() {
        let action = FrontEndExportAction::new();
        let ctx = ProjectDataContext::new()
            .with_file(DomainFileInfo::new("my_binary.elf", "Program"));

        assert!(action.is_enabled_for_context(&ctx));
        let file = action.get_selected_file(&ctx).unwrap();

        let mut dialog = ExporterDialogModel::new(&file.name);
        dialog.set_format(ExportFormat::Binary);
        dialog.set_output_path(format!("/tmp/{}.bin", file.name));

        let status = dialog.validate();
        assert!(status.is_valid());
    }

    #[test]
    fn test_all_formats_through_dialog() {
        let prog = make_test_program();
        let mem = make_test_memory();

        for format in ExportFormat::all() {
            let mut dialog = ExporterDialogModel::new("test");
            dialog.set_format(*format);
            dialog.set_output_path(format!("/tmp/test.{}", format.default_extension()));
            dialog.set_domain_object_supplied(true);

            let mut output = Vec::new();
            let mut log = LoaderMessageLog::new();
            let result = dialog.execute_export(&prog, Some(&mem), &mut output, &mut log);
            assert!(
                result.success,
                "Export failed for format: {}",
                format.display_name()
            );
            assert!(
                !output.is_empty(),
                "No output for format: {}",
                format.display_name()
            );
        }
    }
}
