//! Microsoft PDB (Program Database) Parser
//!
//! This module provides a complete parser for Microsoft PDB files,
//! including the MSF container format, type information (TPI/IPI),
//! debug information (DBI), and symbol records.
//!
//! # Architecture
//!
//! 1. **MSF Layer** — Multi-Stream Format container (v2.00 / v7.00).
//! 2. **Stream Layer** — PDB Info (st.1), TPI (st.2), DBI (st.3), IPI (st.4).
//! 3. **Type Records** — CodeView LF_* leaf records for classes, structs,
//!    unions, enums, pointers, procedures, member functions, and field lists.
//! 4. **Symbol Records** — CodeView S_* records for data, procedures,
//!    publics, labels, locals, thunks, inline sites, etc.
//! 5. **Debug Information** — C13 line numbers, file checksums, section
//!    headers, image function entries, debug stream types.
//! 6. **Register Names** — CV register name mapping for all architectures.
//! 7. **Global/Public Symbol Tables** — GSI/PSI hash table parsing.

pub mod errors;
pub mod debug_info;
pub mod registers;
pub mod globals;
pub mod pdb_applicator;
pub mod symbol_server;

// New modules ported from Ghidra Java PDB implementation
pub mod pdb_kind;
pub mod wrapped_data_type;
pub mod pdb_member;
pub mod pdb_bitfield;
pub mod pdb_categories;
pub mod pdb_program_attributes;
pub mod pdb_namespace_utils;
pub mod composite_member;
pub mod pdb_applicator_options;
pub mod pdb_applicator_metrics;
pub mod pdb_address_calculator;
pub mod find_option;
pub mod pdb_reader;
pub mod default_pdb_import_options;
pub mod pdb_plugin;
pub mod msf_file;
pub mod symbol;
pub mod type_record;

// Core PDB reader abstractions ported from Ghidra Java
pub mod abstract_pdb;
pub mod pdb_byte_reader;
pub mod pdb_exception;
pub mod msf;

// PDB applicator core -- applies parsed PDB data to a program
pub mod applicator;

use std::fmt;

use nom::error::{ErrorKind, ParseError};


// =============================================================================
// Error types
// =============================================================================

/// Errors that can occur during MSF / PDB parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MsfError {
    TruncatedInput { expected: usize, actual: usize },
    UnknownFormat,
    InvalidPageSize(u32),
    InvalidStreamNumber(u32),
    OutOfRangePageNumber(u32),
    NomError(String),
}

impl fmt::Display for MsfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MsfError::TruncatedInput { expected, actual } => {
                write!(f, "MSF truncated input: expected {} bytes, got {}", expected, actual)
            }
            MsfError::UnknownFormat => write!(f, "MSF format not detected (unknown magic)"),
            MsfError::InvalidPageSize(size) => write!(f, "MSF invalid page size: 0x{:08X}", size),
            MsfError::InvalidStreamNumber(n) => write!(f, "MSF invalid stream number: {}", n),
            MsfError::OutOfRangePageNumber(n) => write!(f, "MSF out-of-range page number: {}", n),
            MsfError::NomError(s) => write!(f, "MSF parse error: {}", s),
        }
    }
}

impl std::error::Error for MsfError {}

impl<I> ParseError<I> for MsfError {
    fn from_error_kind(_input: I, _kind: ErrorKind) -> Self {
        MsfError::NomError("nom parse error".to_string())
    }
    fn append(_input: I, _kind: ErrorKind, other: Self) -> Self { other }
}

/// Errors for PDB stream parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamError {
    Truncated { stream: &'static str, expected: usize, actual: usize },
    BadMagic { stream: &'static str, expected: u32, actual: u32 },
    UnsupportedVersion { stream: &'static str, version: u32 },
    ParseError(String),
}

impl fmt::Display for StreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StreamError::Truncated { stream, expected, actual } => {
                write!(f, "{} stream truncated: expected {} bytes, got {}", stream, expected, actual)
            }
            StreamError::BadMagic { stream, expected, actual } => {
                write!(f, "{} stream bad magic: expected 0x{:08X}, got 0x{:08X}", stream, expected, actual)
            }
            StreamError::UnsupportedVersion { stream, version } => {
                write!(f, "{} stream unsupported version: {}", stream, version)
            }
            StreamError::ParseError(s) => write!(f, "stream parse error: {}", s),
        }
    }
}

impl std::error::Error for StreamError {}


// =============================================================================
// MSF Magic Constants
// =============================================================================

const MSF_200_MAGIC: &[u8] = b"Microsoft C/C++ program database 2.00\r\n\x1aJG";
const MSF_700_MAGIC: &[u8] = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS";

// =============================================================================
// MSF Stream info / Directory
// =============================================================================

/// Information about a single stream within the MSF.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MsfStreamInfo {
    pub size: u32,
    pub block_indices: Vec<u32>,
}

/// The MSF directory, listing all streams.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MsfDirectory {
    pub streams: Vec<MsfStreamInfo>,
}

/// A parsed MSF (Multi-Stream Format) file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MsfFile {
    pub blocks: Vec<Vec<u8>>,
    pub block_size: u32,
    pub directory: MsfDirectory,
}

#[derive(Debug)]
struct MsfHeader {
    page_size: u32,
    num_pages: u32,
    free_page_map_page: u32,
    page_number_size: u32,
}

// =============================================================================
// MSF Header parsing
// =============================================================================

/// Parse the complete MSF file from a byte slice.
pub fn parse_msf(data: &[u8]) -> Result<MsfFile, MsfError> {
    let (header, dir_offset, dir_len) = parse_msf_header(data)?;
    let num_pages = header.num_pages;
    let page_size = header.page_size;

    let mut blocks: Vec<Vec<u8>> = Vec::with_capacity(num_pages as usize);
    for i in 0..num_pages as usize {
        let start = i * page_size as usize;
        let end = start + page_size as usize;
        if end > data.len() {
            let mut block = vec![0u8; page_size as usize];
            let available = data.len().saturating_sub(start);
            block[..available].copy_from_slice(&data[start..data.len()]);
            blocks.push(block);
            break;
        }
        blocks.push(data[start..end].to_vec());
    }

    let directory = parse_directory(data, &header, dir_offset, dir_len)?;
    Ok(MsfFile { blocks, block_size: page_size, directory })
}

fn parse_msf_header(data: &[u8]) -> Result<(MsfHeader, usize, u32), MsfError> {
    if data.len() < MSF_200_MAGIC.len() {
        return Err(MsfError::TruncatedInput {
            expected: MSF_200_MAGIC.len(), actual: data.len(),
        });
    }
    if &data[..MSF_200_MAGIC.len()] == MSF_200_MAGIC {
        parse_msf_header_v200(data)
    } else if &data[..MSF_700_MAGIC.len()] == MSF_700_MAGIC {
        parse_msf_header_v700(data)
    } else {
        Err(MsfError::UnknownFormat)
    }
}

fn parse_msf_header_v200(data: &[u8]) -> Result<(MsfHeader, usize, u32), MsfError> {
    let page_size_offset = MSF_200_MAGIC.len() + 2;
    if data.len() < page_size_offset + 4 {
        return Err(MsfError::TruncatedInput { expected: page_size_offset + 4, actual: data.len() });
    }
    let page_size = read_u32_le(data, page_size_offset);
    if !is_power_of_two(page_size) || page_size < 0x0200 || page_size > 0x8000 {
        return Err(MsfError::InvalidPageSize(page_size));
    }
    let fp_offset = page_size_offset + 4;
    let np_offset = fp_offset + 2;
    if data.len() < np_offset + 2 {
        return Err(MsfError::TruncatedInput { expected: np_offset + 2, actual: data.len() });
    }
    let free_page_map_page = read_u16_le(data, fp_offset) as u32;
    let num_pages = read_u16_le(data, np_offset) as u32;
    let dir_info_offset = np_offset + 2;
    let (dir_offset, dir_len) = parse_dir_stream_info(data, dir_info_offset, 2)?;
    Ok((MsfHeader { page_size, num_pages, free_page_map_page, page_number_size: 2 }, dir_offset, dir_len))
}

fn parse_msf_header_v700(data: &[u8]) -> Result<(MsfHeader, usize, u32), MsfError> {
    let page_size_offset = MSF_700_MAGIC.len() + 3;
    if data.len() < page_size_offset + 4 {
        return Err(MsfError::TruncatedInput { expected: page_size_offset + 4, actual: data.len() });
    }
    let page_size = read_u32_le(data, page_size_offset);
    if !is_power_of_two(page_size) || page_size < 0x0200 || page_size > 0x8000 {
        return Err(MsfError::InvalidPageSize(page_size));
    }
    let fp_offset = page_size_offset + 4;
    let np_offset = fp_offset + 4;
    let ndb_offset = np_offset + 4;
    if data.len() < ndb_offset + 4 {
        return Err(MsfError::TruncatedInput { expected: ndb_offset + 4, actual: data.len() });
    }
    let free_page_map_page = read_u32_le(data, fp_offset);
    let num_pages = read_u32_le(data, np_offset);
    let _num_directory_bytes = read_u32_le(data, ndb_offset);
    let dir_info_offset = ndb_offset + 4;
    let (dir_offset, dir_len) = parse_dir_stream_info(data, dir_info_offset, 4)?;
    Ok((MsfHeader { page_size, num_pages, free_page_map_page, page_number_size: 4 }, dir_offset, dir_len))
}

fn parse_dir_stream_info(data: &[u8], offset: usize, page_number_size: u32) -> Result<(usize, u32), MsfError> {
    if offset + 8 > data.len() {
        return Err(MsfError::TruncatedInput { expected: offset + 8, actual: data.len() });
    }
    let stream_length = read_u32_le(data, offset);
    let _map_address = read_u32_le(data, offset + 4);
    if stream_length == 0 { return Ok((0, 0)); }
    let page_size = 0x1000u32;
    let num_dir_pages = (stream_length + page_size - 1) / page_size;
    let mut page_numbers = Vec::with_capacity(num_dir_pages as usize);
    let pn_offset = offset + 8;
    for i in 0..num_dir_pages as usize {
        let cur = pn_offset + i * page_number_size as usize;
        if page_number_size == 2 {
            if cur + 2 > data.len() { break; }
            let pn = read_u16_le(data, cur) as u32;
            if pn == 0 { break; }
            page_numbers.push(pn);
        } else {
            if cur + 4 > data.len() { break; }
            let pn = read_u32_le(data, cur);
            if pn == 0 { break; }
            page_numbers.push(pn);
        }
    }
    let dir_byte_offset = if !page_numbers.is_empty() { page_numbers[0] as usize * 0x1000 } else { 0 };
    Ok((dir_byte_offset, stream_length))
}

// =============================================================================
// Directory parsing (stream 0 contents)
// =============================================================================

fn read_contiguous_stream(data: &[u8], header: &MsfHeader, stream_start_page_offset: usize, stream_len: u32) -> Result<Vec<u8>, MsfError> {
    if stream_len == 0 || stream_len == 0xFFFFFFFF { return Ok(Vec::new()); }
    let page_size = header.page_size as usize;
    let num_pages = ((stream_len as usize) + page_size - 1) / page_size;
    let mut buf = vec![0u8; stream_len as usize];
    let mut written = 0usize;
    for i in 0..num_pages {
        let page_start = stream_start_page_offset + i * page_size;
        let available = data.len().saturating_sub(page_start).min(page_size);
        let to_copy = available.min(buf.len() - written);
        if to_copy == 0 { break; }
        buf[written..written + to_copy].copy_from_slice(&data[page_start..page_start + to_copy]);
        written += to_copy;
    }
    Ok(buf)
}

fn parse_directory(data: &[u8], header: &MsfHeader, dir_offset: usize, dir_len: u32) -> Result<MsfDirectory, MsfError> {
    let dir_bytes = read_contiguous_stream(data, header, dir_offset, dir_len)?;
    parse_directory_from_bytes(&dir_bytes, header)
}

fn parse_directory_from_bytes(dir_bytes: &[u8], header: &MsfHeader) -> Result<MsfDirectory, MsfError> {
    if dir_bytes.is_empty() {
        return Ok(MsfDirectory { streams: Vec::new() });
    }
    if dir_bytes.len() < 4 {
        return Err(MsfError::TruncatedInput { expected: 4, actual: dir_bytes.len() });
    }
    let num_streams = read_u32_le(dir_bytes, 0) as usize;
    let size_offset = 4;
    let sizes_end = size_offset + num_streams * 4;
    if dir_bytes.len() < sizes_end {
        return Err(MsfError::TruncatedInput { expected: sizes_end, actual: dir_bytes.len() });
    }
    let mut streams: Vec<MsfStreamInfo> = Vec::with_capacity(num_streams);
    let page_number_size = header.page_number_size as usize;
    let page_size = header.page_size;
    let mut pn_cursor = sizes_end;
    for i in 0..num_streams {
        let sz = read_u32_le(dir_bytes, size_offset + i * 4);
        let num_pages = if sz == 0 || sz == 0xFFFFFFFF { 0 } else { ((sz + page_size - 1) / page_size) as usize };
        let mut block_indices = Vec::with_capacity(num_pages);
        for _j in 0..num_pages {
            if pn_cursor + page_number_size > dir_bytes.len() { break; }
            let pn = if page_number_size == 2 {
                let v = read_u16_le(dir_bytes, pn_cursor) as u32; pn_cursor += 2; v
            } else {
                let v = read_u32_le(dir_bytes, pn_cursor); pn_cursor += 4; v
            };
            if pn == 0 { break; }
            block_indices.push(pn);
        }
        streams.push(MsfStreamInfo { size: sz, block_indices });
    }
    Ok(MsfDirectory { streams })
}

// =============================================================================
// MsfFile stream reading — Block management
// =============================================================================

impl MsfFile {
    /// Read the entire contents of the stream at `stream_index` into a `Vec<u8>`.
    /// Stream 0 = directory, 1 = PDB Info, 2 = TPI, 3 = DBI, 4 = IPI.
    pub fn read_stream(&self, stream_index: u32) -> Option<Vec<u8>> {
        let info = self.directory.streams.get(stream_index as usize)?;
        if info.size == 0 || info.size == 0xFFFFFFFF { return Some(Vec::new()); }
        let page_size = self.block_size;
        let mut buf = vec![0u8; info.size as usize];
        let mut bytes_written = 0usize;
        for &page_num in &info.block_indices {
            let block = self.blocks.get(page_num as usize)?;
            let to_copy = (page_size as usize).min(buf.len() - bytes_written);
            buf[bytes_written..bytes_written + to_copy].copy_from_slice(&block[..to_copy]);
            bytes_written += to_copy;
            if bytes_written >= buf.len() { break; }
        }
        Some(buf)
    }

    pub fn num_streams(&self) -> usize { self.directory.streams.len() }
    pub fn stream_size(&self, stream_index: u32) -> Option<u32> {
        self.directory.streams.get(stream_index as usize).map(|s| s.size)
    }
}

// =============================================================================
// Low-level helpers
// =============================================================================

#[inline]
fn read_u16_le(data: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([data[offset], data[offset + 1]])
}

#[inline]
fn read_u32_le(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([data[offset], data[offset+1], data[offset+2], data[offset+3]])
}

fn is_power_of_two(n: u32) -> bool { n != 0 && (n & (n - 1)) == 0 }

#[inline]
fn le_u32_at(data: &[u8], offset: usize) -> u32 { read_u32_le(data, offset) }

fn read_null_terminated_string(data: &[u8], offset: usize) -> (String, usize) {
    let mut end = offset;
    while end < data.len() && data[end] != 0 { end += 1; }
    if end >= data.len() { return (String::new(), offset); }
    let s = String::from_utf8_lossy(&data[offset..end]).to_string();
    (s, end + 1)
}

fn parse_null_terminated_string(data: &[u8]) -> String {
    let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
    String::from_utf8_lossy(&data[..end]).to_string()
}

fn split_null_term(data: &[u8], offset: usize) -> (String, usize) {
    if offset >= data.len() { return (String::new(), offset); }
    let mut end = offset;
    while end < data.len() && data[end] != 0 { end += 1; }
    let next = ((end + 1) + 3) & !3;
    let s = String::from_utf8_lossy(&data[offset..end]).to_string();
    (s, next)
}

fn parse_name_pair(data: &[u8]) -> (String, Option<String>) {
    if data.is_empty() { return (String::new(), None); }
    let (name, after_name) = split_null_term(data, 0);
    if after_name >= data.len() || data[after_name] == 0xf4 || data[after_name] == 0xf3 {
        return (name, None);
    }
    let (mangled, _) = split_null_term(data, after_name);
    if mangled.is_empty() { (name, None) } else { (name, Some(mangled)) }
}

fn parse_numeric(data: &[u8], offset: usize) -> (u64, usize) {
    if offset + 2 > data.len() { return (0, offset); }
    let low = read_u16_le(data, offset);
    if low < 0x8000 { return (low as u64, offset + 2); }
    if offset + 3 > data.len() { return (0, offset); }
    let variant = data[offset + 2];
    match variant {
        0x00 => { if offset+5>data.len() {return(0,offset+3);} (read_u16_le(data,offset+3)as u64,offset+5) }
        0x01 => { if offset+5>data.len() {return(0,offset+3);} (i16::from_le_bytes([data[offset+3],data[offset+4]])as u64,offset+5) }
        0x02 => { if offset+7>data.len() {return(0,offset+3);} (read_u32_le(data,offset+3)as u64,offset+7) }
        0x03 => { if offset+7>data.len() {return(0,offset+3);} (i32::from_le_bytes([data[offset+3],data[offset+4],data[offset+5],data[offset+6]])as u64,offset+7) }
        0x10 => { if offset+11>data.len() {return(0,offset+3);} (u64::from_le_bytes([data[offset+3],data[offset+4],data[offset+5],data[offset+6],data[offset+7],data[offset+8],data[offset+9],data[offset+10]]),offset+11) }
        _ => (low as u64, offset + 2),
    }
}


// =============================================================================
// Named stream hash table (open addressing, quadratic probing)
// =============================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamedStreamEntry {
    pub name: String,
    pub stream_index: u32,
}

#[derive(Debug, Clone)]
pub struct NamedStreamHashTable {
    pub entries: Vec<NamedStreamEntry>,
    pub num_buckets: u32,
    pub present_bitmap: Vec<u32>,
    pub deleted_bitmap: Vec<u32>,
}

fn parse_named_stream_hash_table(data: &[u8], offset: usize, str_table_off: usize) -> Option<NamedStreamHashTable> {
    if offset + 8 > data.len() { return None; }
    let num_present = read_u32_le(data, offset);
    let max_streams = read_u32_le(data, offset + 4);
    if max_streams == 0 { return None; }
    let bucket_bits = ((max_streams + 31) / 32) as usize;
    let present_off = offset + 8;
    let mut present = Vec::with_capacity(bucket_bits);
    for i in 0..bucket_bits { let bo = present_off + i*4; if bo+4<=data.len() { present.push(read_u32_le(data,bo)); } }
    let deleted_off = present_off + bucket_bits * 4;
    let mut deleted = Vec::with_capacity(bucket_bits);
    for i in 0..bucket_bits { let bo = deleted_off + i*4; if bo+4<=data.len() { deleted.push(read_u32_le(data,bo)); } }
    let keys_off = deleted_off + bucket_bits*4;
    let indices_off = keys_off + max_streams as usize * 4;
    let mut entries = Vec::with_capacity(num_present as usize);
    for bucket in 0..max_streams as usize {
        let wi = bucket/32; let bi = bucket%32;
        if wi >= present.len() { continue; }
        if (present[wi]>>bi)&1 == 0 { continue; }
        if wi < deleted.len() && (deleted[wi]>>bi)&1 != 0 { continue; }
        let ko = keys_off + bucket*4; let io = indices_off + bucket*4;
        if ko+4>data.len()||io+4>data.len() { continue; }
        let str_off = read_u32_le(data, ko) as usize;
        let si = read_u32_le(data, io);
        let abs_off = str_table_off + str_off;
        if abs_off < data.len() {
            let name = parse_null_terminated_string(&data[abs_off..]);
            if !name.is_empty() { entries.push(NamedStreamEntry{name, stream_index:si}); }
        }
    }
    Some(NamedStreamHashTable{entries, num_buckets:max_streams, present_bitmap:present, deleted_bitmap:deleted})
}

// =============================================================================
// PDB Info Stream (stream 1)
// =============================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PdbInfoStream {
    pub version: u32,
    pub signature: u32,
    pub age: u32,
    pub guid: [u8; 16],
    pub names: Vec<String>,
    pub named_streams: Vec<NamedStreamEntry>,
}

pub fn parse_pdb_info_stream(data: &[u8]) -> Result<PdbInfoStream, StreamError> {
    if data.len() < 28 {
        return Err(StreamError::Truncated { stream: "PDB Info", expected: 28, actual: data.len() });
    }
    let version = read_u32_le(data, 0);
    let signature = read_u32_le(data, 4);
    let age = read_u32_le(data, 8);
    let mut guid = [0u8; 16];
    guid.copy_from_slice(&data[12..28]);
    let tail = &data[28..];
    let named_streams = if tail.len() >= 24 {
        let mp = read_u32_le(tail, 0); let mm = read_u32_le(tail, 4);
        if mm > 0 && mm <= 65536 && mp <= mm {
            parse_named_stream_hash_table(tail, 0, 0).map(|h|h.entries).unwrap_or_default()
        } else { Vec::new() }
    } else { Vec::new() };
    let mut names = Vec::new();
    let mut pos = 0usize;
    while pos < tail.len() {
        let np = match tail[pos..].iter().position(|&b|b==0) { Some(p)=>pos+p, None=>break };
        if np==pos { break; }
        names.push(String::from_utf8_lossy(&tail[pos..np]).to_string());
        pos=np+1; if pos+8>tail.len(){break;} pos+=8;
    }
    Ok(PdbInfoStream{version,signature,age,guid,names,named_streams})
}

// =============================================================================
// DBI Stream (stream 3) types
// =============================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SectionContrib {
    pub section: u16, pub padding1: u16,
    pub offset: u32, pub size: u32,
    pub characteristics: u32,
    pub module_index: u16, pub padding2: u16,
    pub data_crc: u32, pub reloc_crc: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SectionMapEntry {
    pub section_number: u16, pub flags: u16,
    pub section_name: String, pub class_name: String,
    pub offset: u32, pub size: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleInfo {
    pub module_index: u16,
    pub object_name: String, pub module_name: String,
    pub opened: u32,
    pub section_contrib_flags: u16, pub module_sym_stream: u16,
    pub sym_byte_size: u32, pub c11_byte_size: u32, pub c13_byte_size: u32,
    pub source_file_count: u16,
    pub num_symbols: u32, pub symbols_offset: u32, pub symbols_size: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeServerEntry {
    pub signature: u32, pub age: u32, pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DbiStream {
    pub version_signature: i32, pub version_header: u32, pub age: u32,
    pub gsi: u16, pub bn: u16,
    pub psi: u16, pub pdbn: u16,
    pub sri: u16, pub pdb_rbn: u16,
    pub mis: u32, pub scs: u32,
    pub sms: u32, pub fis: u32,
    pub tsms: u32, pub mtsi: u32,
    pub odhs: u32, pub ecss: u32,
    pub flags: u16, pub machine: u16, pub reserved: u32,
    pub modules: Vec<ModuleInfo>, pub sections: Vec<SectionContrib>,
    pub section_map: Vec<SectionMapEntry>, pub type_servers: Vec<TypeServerEntry>,
}

pub fn parse_dbi_stream(data: &[u8]) -> Result<DbiStream, StreamError> {
    if data.len() < 64 {
        return Err(StreamError::Truncated { stream: "DBI", expected: 64, actual: data.len() });
    }
    let vs = i32::from_le_bytes([data[0],data[1],data[2],data[3]]);
    let vh = le_u32_at(data,4);
    let age = le_u32_at(data,8);
    let gsi = u16::from_le_bytes([data[12],data[13]]);
    let bn = u16::from_le_bytes([data[14],data[15]]);
    let psi = u16::from_le_bytes([data[16],data[17]]);
    let pdbn = u16::from_le_bytes([data[18],data[19]]);
    let sri = u16::from_le_bytes([data[20],data[21]]);
    let pdb_rbn = u16::from_le_bytes([data[22],data[23]]);
    let mis = le_u32_at(data,24);
    let scs = le_u32_at(data,28);
    let sms = le_u32_at(data,32);
    let fis = le_u32_at(data,36);
    let tsms = le_u32_at(data,40);
    let mtsi = le_u32_at(data,44);
    let odhs = le_u32_at(data,48);
    let ecss = le_u32_at(data,52);
    let flags = u16::from_le_bytes([data[56],data[57]]);
    let machine = u16::from_le_bytes([data[58],data[59]]);
    let reserved = le_u32_at(data,60);

    let hdr = 64usize;
    let mut modules = Vec::new();
    if mis > 0 && hdr+4 <= data.len() {
        modules = parse_module_info(&data[hdr..], mis);
    }
    let sc_start = hdr + mis as usize;
    let mut sections = Vec::new();
    if scs > 0 && sc_start+4 <= data.len() {
        for i in 0..(scs as usize/28).min(data[sc_start..].len()/28) {
            let off = sc_start + i*28;
            if off+28 > data.len() { break; }
            sections.push(SectionContrib{
                section:u16::from_le_bytes([data[off],data[off+1]]),
                padding1:u16::from_le_bytes([data[off+2],data[off+3]]),
                offset:le_u32_at(data,off+4), size:le_u32_at(data,off+8),
                characteristics:le_u32_at(data,off+12),
                module_index:u16::from_le_bytes([data[off+16],data[off+17]]),
                padding2:u16::from_le_bytes([data[off+18],data[off+19]]),
                data_crc:le_u32_at(data,off+20), reloc_crc:le_u32_at(data,off+24),
            });
        }
    }
    let sm_start = sc_start + scs as usize;
    let mut section_map = Vec::new();
    if sms > 0 && sm_start+4 <= data.len() {
        let mut pos = sm_start;
        while pos < sm_start + sms as usize && pos+8 <= data.len() {
            let fl = u16::from_le_bytes([data[pos],data[pos+1]]);
            let sn = u16::from_le_bytes([data[pos+2],data[pos+3]]);
            let snl = u16::from_le_bytes([data[pos+4],data[pos+5]]);
            let cnl = u16::from_le_bytes([data[pos+6],data[pos+7]]);
            pos += 8;
            let sec_name = if pos+snl as usize <= data.len() { let n=String::from_utf8_lossy(&data[pos..pos+snl as usize]).to_string(); pos+=snl as usize+1; n } else { String::new() };
            let cls_name = if pos+cnl as usize <= data.len() { let n=String::from_utf8_lossy(&data[pos..pos+cnl as usize]).to_string(); pos+=cnl as usize+1; n } else { String::new() };
            let off = if pos+4<=data.len(){let v=le_u32_at(data,pos);pos+=4;v}else{0};
            let sz = if pos+4<=data.len(){let v=le_u32_at(data,pos);pos+=4;v}else{0};
            section_map.push(SectionMapEntry{section_number:sn,flags:fl,section_name:sec_name,class_name:cls_name,offset:off,size:sz});
        }
    }
    let ts_start = sm_start + sms as usize + fis as usize;
    let mut type_servers = Vec::new();
    if tsms > 0 && ts_start+4 <= data.len() {
        let mut pos = ts_start;
        while pos+8<=data.len() && pos<ts_start+tsms as usize {
            let sig = le_u32_at(data,pos); let age2 = le_u32_at(data,pos+4); pos+=8;
            let (name2, np) = read_null_terminated_string(data,pos); pos=np;
            type_servers.push(TypeServerEntry{signature:sig,age:age2,name:name2});
        }
    }

    Ok(DbiStream{version_signature:vs,version_header:vh,age,gsi,bn,psi,pdbn,sri,pdb_rbn,mis,scs,sms,fis,tsms,mtsi,odhs,ecss,flags,machine,reserved,modules,sections,section_map,type_servers})
}

fn parse_module_info(data: &[u8], _size: u32) -> Vec<ModuleInfo> {
    let mut modules = Vec::new();
    let mut pos = 0usize;
    while pos+4 <= data.len() {
        let opened = le_u32_at(data, pos);
        if opened != 0 { pos += 1; continue; }
        if pos+64 > data.len() { break; }
        let ac = pos + 4 + 28;
        if ac+14 > data.len() { break; }
        let scf = u16::from_le_bytes([data[ac],data[ac+1]]);
        let mss = u16::from_le_bytes([data[ac+2],data[ac+3]]);
        let sbs = le_u32_at(data,ac+4);
        let c11 = le_u32_at(data,ac+8);
        let c13 = le_u32_at(data,ac+12);
        let sfc = u16::from_le_bytes([data[ac+16],data[ac+17]]);
        let str_start = ac + 18 + 12;
        let (mn, n1) = read_null_terminated_string(data, str_start);
        let (on, n2) = read_null_terminated_string(data, n1);
        if mn.is_empty() && on.is_empty() { pos += 1; continue; }
        modules.push(ModuleInfo{module_index:modules.len()as u16,object_name:on,module_name:mn,opened,section_contrib_flags:scf,module_sym_stream:mss,sym_byte_size:sbs,c11_byte_size:c11,c13_byte_size:c13,source_file_count:sfc,num_symbols:sbs,symbols_offset:0,symbols_size:sbs});
        pos = n2;
    }
    modules
}


// =============================================================================
// TPI Stream (stream 2)
// =============================================================================

#[derive(Debug, Clone)]
pub struct TpiStream {
    pub version: u32, pub header_offset: u32,
    pub type_index_begin: u32, pub type_index_end: u32,
    pub type_record_bytes: u32,
    pub hash_stream_index: u16, pub hash_aux_stream_index: u16,
    pub hash_key_size: u32, pub num_hash_buckets: u32,
    pub hash_value_buffer_offset: u32, pub hash_value_buffer_length: u32,
    pub index_offset_buffer_offset: u32, pub index_offset_buffer_length: u32,
    pub hash_adj_buffer_offset: u32, pub hash_adj_buffer_length: u32,
    pub types: Vec<TypeRecord>,
}

pub fn parse_tpi_stream(data: &[u8]) -> Result<TpiStream, StreamError> {
    if data.len() < 56 {
        return Err(StreamError::Truncated { stream: "TPI", expected: 56, actual: data.len() });
    }
    let ver = le_u32_at(data,0); let ho = le_u32_at(data,4);
    let tib = le_u32_at(data,8); let tie = le_u32_at(data,12);
    let trb = le_u32_at(data,16);
    let hsi = u16::from_le_bytes([data[20],data[21]]);
    let hasi = u16::from_le_bytes([data[22],data[23]]);
    let hks = le_u32_at(data,24); let nhb = le_u32_at(data,28);
    let hvb = le_u32_at(data,32); let hvl = le_u32_at(data,36);
    let iob = le_u32_at(data,40); let iol = le_u32_at(data,44);
    let hab = le_u32_at(data,48); let hal = le_u32_at(data,52);
    let rd = if ho as usize > data.len() { &[] } else { &data[ho as usize..] };
    let types = parse_type_records_from_tpi(rd, trb);
    Ok(TpiStream{version:ver,header_offset:ho,type_index_begin:tib,type_index_end:tie,type_record_bytes:trb,hash_stream_index:hsi,hash_aux_stream_index:hasi,hash_key_size:hks,num_hash_buckets:nhb,hash_value_buffer_offset:hvb,hash_value_buffer_length:hvl,index_offset_buffer_offset:iob,index_offset_buffer_length:iol,hash_adj_buffer_offset:hab,hash_adj_buffer_length:hal,types})
}

#[derive(Debug, Clone)]
pub struct IpiStream {
    pub version: u32, pub header_offset: u32,
    pub type_index_begin: u32, pub type_index_end: u32,
    pub type_record_bytes: u32, pub items: Vec<TypeRecord>,
}

pub fn parse_ipi_stream(data: &[u8]) -> Result<IpiStream, StreamError> {
    if data.len() < 20 {
        return Err(StreamError::Truncated { stream: "IPI", expected: 20, actual: data.len() });
    }
    let ver = le_u32_at(data,0); let ho = le_u32_at(data,4);
    let tib = le_u32_at(data,8); let tie = le_u32_at(data,12);
    let trb = le_u32_at(data,16);
    let rd = if ho as usize > data.len() { &[] } else { &data[ho as usize..] };
    Ok(IpiStream{version:ver,header_offset:ho,type_index_begin:tib,type_index_end:tie,type_record_bytes:trb,items:parse_type_records_from_tpi(rd,trb)})
}

fn parse_type_records_from_tpi(data: &[u8], _total: u32) -> Vec<TypeRecord> {
    if data.is_empty() { return Vec::new(); }
    let mut recs = Vec::new(); let mut pos = 0usize;
    while pos+2 <= data.len() {
        let rlen = u16::from_le_bytes([data[pos],data[pos+1]]) as usize; pos+=2;
        if rlen==0||pos+rlen>data.len() { break; }
        if let Some(r) = parse_type_record(&data[pos..pos+rlen]) { recs.push(r); }
        pos+=rlen; while pos<data.len()&&pos%4!=0{pos+=1;}
    }
    recs
}

// =============================================================================
// Leaf type record IDs
// =============================================================================

pub mod leaf_id {
    pub const LF_MODIFIER: u16   = 0x0001;
    pub const LF_POINTER: u16    = 0x0002;
    pub const LF_ARRAY: u16      = 0x0003;
    pub const LF_CLASS: u16      = 0x0004;
    pub const LF_STRUCTURE: u16  = 0x0005;
    pub const LF_UNION: u16      = 0x0006;
    pub const LF_ENUM: u16       = 0x0007;
    pub const LF_PROCEDURE: u16  = 0x0008;
    pub const LF_MFUNCTION: u16  = 0x0009;
    pub const LF_VTSHAPE: u16    = 0x000A;
    pub const LF_COBOL0: u16     = 0x000B;
    pub const LF_COBOL1: u16     = 0x000C;
    pub const LF_BARRAY: u16     = 0x000D;
    pub const LF_LABEL: u16      = 0x000E;
    pub const LF_NULL: u16       = 0x000F;
    pub const LF_NOTTRAN: u16    = 0x0010;
    pub const LF_DIMARRAY: u16   = 0x0011;
    pub const LF_VFTPATH: u16    = 0x0012;
    pub const LF_PRECOMP: u16    = 0x0013;
    pub const LF_ENDPRECOMP: u16 = 0x0014;
    pub const LF_OEM: u16        = 0x0015;
    pub const LF_TYPESERVER: u16 = 0x0016;
    pub const LF_SKIP: u16       = 0x0200;
    pub const LF_ARGLIST: u16    = 0x0201;
    pub const LF_DEFARG: u16     = 0x0202;
    pub const LF_FIELDLIST: u16  = 0x0203;
    pub const LF_DERIVED: u16    = 0x0204;
    pub const LF_BITFIELD: u16   = 0x0205;
    pub const LF_METHODLIST: u16 = 0x0206;
    pub const LF_DIMCONU: u16    = 0x0207;
    pub const LF_DIMCONLU: u16   = 0x0208;
    pub const LF_DIMVARU: u16    = 0x0209;
    pub const LF_DIMVARLU: u16   = 0x020A;
    pub const LF_REFSYM: u16     = 0x020B;
    pub const LF_BCLASS: u16     = 0x0400;
    pub const LF_VBCLASS: u16    = 0x0401;
    pub const LF_IVBCLASS: u16   = 0x0402;
    pub const LF_ENUMERATE: u16  = 0x0403;
    pub const LF_FRIENDFCN: u16  = 0x0404;
    pub const LF_INDEX: u16      = 0x0405;
    pub const LF_MEMBER: u16     = 0x0406;
    pub const LF_STMEMBER: u16   = 0x0407;
    pub const LF_METHOD: u16     = 0x0408;
    pub const LF_NESTTYPE: u16   = 0x0409;
    pub const LF_VFUNCTAB: u16   = 0x040A;
    pub const LF_FRIENDCLS: u16  = 0x040B;
    pub const LF_ONEMETHOD: u16  = 0x040C;
    pub const LF_VFUNCOFF: u16   = 0x040D;
    pub const LF_NESTTYPEEX: u16 = 0x040E;
    pub const LF_MEMBERMODIFY: u16 = 0x040F;
    pub const LF_MANAGED: u16    = 0x0410;
    pub const LF_TYPESERVER2: u16 = 0x0017;
    // Additional numeric types
    pub const LF_NUMERIC: u16    = 0x8000;
    pub const LF_CHAR: u16       = 0x8000;
    pub const LF_SHORT: u16      = 0x8001;
    pub const LF_USHORT: u16     = 0x8002;
    pub const LF_LONG: u16       = 0x8003;
    pub const LF_ULONG: u16      = 0x8004;
    pub const LF_REAL32: u16     = 0x8005;
    pub const LF_REAL64: u16     = 0x8006;
    pub const LF_REAL80: u16     = 0x8007;
    pub const LF_REAL128: u16    = 0x8008;
    pub const LF_QUADWORD: u16   = 0x8009;
    pub const LF_UQUADWORD: u16  = 0x800A;
    pub const LF_REAL48: u16     = 0x800B;
    pub const LF_COMPLEX32: u16  = 0x800C;
    pub const LF_COMPLEX64: u16  = 0x800D;
    pub const LF_COMPLEX80: u16  = 0x800E;
    pub const LF_COMPLEX128: u16 = 0x800F;
    pub const LF_VARSTRING: u16  = 0x8010;
}

// =============================================================================
// SimpleTypeMode and SimpleTypeKind — type index resolution
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SimpleTypeMode {
    Direct = 0x00,
    NearPointer = 0x01,
    FarPointer = 0x02,
    HugePointer = 0x03,
    NearPointer32 = 0x04,
    FarPointer32 = 0x05,
    NearPointer64 = 0x06,
    NearPointer128 = 0x07,
}

impl SimpleTypeMode {
    pub fn from_u8(v: u8) -> Self {
        match v { 0=>Self::Direct,1=>Self::NearPointer,2=>Self::FarPointer,3=>Self::HugePointer,4=>Self::NearPointer32,5=>Self::FarPointer32,6=>Self::NearPointer64,7=>Self::NearPointer128,_=>Self::Direct }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SimpleTypeKind {
    None=0x00, Void=0x01, NotTranslated=0x02, HResult=0x03,
    SignedChar=0x04, UnsignedChar=0x05, NarrowChar=0x06, WideChar=0x07,
    Int16Short=0x08, UInt16Short=0x09, Int32=0x0A, UInt32=0x0B,
    Int32Long=0x0C, UInt32Long=0x0D, Int64Quad=0x0E, UInt64Quad=0x0F,
    Real32=0x10, Real64=0x11, Real80=0x12, Real128=0x13,
    Complex32=0x14, Complex64=0x15, Complex80=0x16, Complex128=0x17,
    Bool8=0x18, Bool16=0x19, Bool32=0x1A, Bool64=0x1B,
    Currency=0x1C, Date=0x1D, Variant=0x1E, BStr=0x1F, Char8=0x20, Char16=0x21,
}

impl SimpleTypeKind {
    pub fn from_u8(v: u8) -> Self {
        match v { 1=>Self::Void,2=>Self::NotTranslated,3=>Self::HResult,4=>Self::SignedChar,5=>Self::UnsignedChar,6=>Self::NarrowChar,7=>Self::WideChar,8=>Self::Int16Short,9=>Self::UInt16Short,0x0A=>Self::Int32,0x0B=>Self::UInt32,0x0C=>Self::Int32Long,0x0D=>Self::UInt32Long,0x0E=>Self::Int64Quad,0x0F=>Self::UInt64Quad,0x10=>Self::Real32,0x11=>Self::Real64,0x12=>Self::Real80,0x13=>Self::Real128,0x14=>Self::Complex32,0x15=>Self::Complex64,0x16=>Self::Complex80,0x17=>Self::Complex128,0x18=>Self::Bool8,0x19=>Self::Bool16,0x1A=>Self::Bool32,0x1B=>Self::Bool64,0x1C=>Self::Currency,0x1D=>Self::Date,0x1E=>Self::Variant,0x1F=>Self::BStr,0x20=>Self::Char8,0x21=>Self::Char16,_=>Self::None }
    }
    pub fn size_in_bytes(&self) -> usize {
        match self { Self::None|Self::Void=>0,Self::NotTranslated|Self::HResult|Self::SignedChar|Self::UnsignedChar|Self::NarrowChar|Self::Bool8|Self::Char8=>1,Self::WideChar|Self::Int16Short|Self::UInt16Short|Self::Bool16|Self::Char16=>2,Self::Int32|Self::UInt32|Self::Int32Long|Self::UInt32Long|Self::Real32|Self::Bool32|Self::Complex32=>4,Self::Int64Quad|Self::UInt64Quad|Self::Real64|Self::Bool64|Self::Complex64|Self::Currency|Self::Date=>8,Self::Real80|Self::Complex80=>10,Self::Real128|Self::Complex128=>16,Self::Variant=>16,Self::BStr=>4 }
    }
    pub fn name(&self) -> &'static str {
        match self { Self::None=>"none",Self::Void=>"void",Self::NotTranslated=>"nottran",Self::HResult=>"HRESULT",Self::SignedChar=>"signed char",Self::UnsignedChar=>"unsigned char",Self::NarrowChar=>"char",Self::WideChar=>"wchar_t",Self::Int16Short=>"short",Self::UInt16Short=>"unsigned short",Self::Int32=>"int",Self::UInt32=>"unsigned int",Self::Int32Long=>"long",Self::UInt32Long=>"unsigned long",Self::Int64Quad=>"__int64",Self::UInt64Quad=>"unsigned __int64",Self::Real32=>"float",Self::Real64=>"double",Self::Real80=>"long double",Self::Real128=>"__float128",Self::Complex32=>"float _Complex",Self::Complex64=>"double _Complex",Self::Complex80=>"ld Complex",Self::Complex128=>"__f128 Complx",Self::Bool8=>"bool8",Self::Bool16=>"bool16",Self::Bool32=>"bool32",Self::Bool64=>"bool64",Self::Currency=>"CURRENCY",Self::Date=>"DATE",Self::Variant=>"VARIANT",Self::BStr=>"BSTR",Self::Char8=>"char8_t",Self::Char16=>"char16_t" }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SimpleType {
    pub mode: SimpleTypeMode,
    pub kind: SimpleTypeKind,
    pub is_simple: bool,
}

pub fn resolve_simple_type(type_index: u32) -> SimpleType {
    if type_index > 0x0FFF {
        return SimpleType { mode: SimpleTypeMode::Direct, kind: SimpleTypeKind::None, is_simple: false };
    }
    let mb = ((type_index>>8)&0x0F) as u8;
    let kb = (type_index&0xFF) as u8;
    let mode = SimpleTypeMode::from_u8(mb);
    let kind = SimpleTypeKind::from_u8(kb);
    let is_simple = !(mode==SimpleTypeMode::Direct&&(kind==SimpleTypeKind::None||kb>0x21));
    SimpleType{mode,kind,is_simple}
}

impl SimpleType {
    pub fn byte_size(&self) -> usize {
        match self.mode { SimpleTypeMode::Direct=>self.kind.size_in_bytes(),SimpleTypeMode::NearPointer|SimpleTypeMode::NearPointer32=>4,SimpleTypeMode::FarPointer|SimpleTypeMode::FarPointer32|SimpleTypeMode::HugePointer=>6,SimpleTypeMode::NearPointer64=>8,SimpleTypeMode::NearPointer128=>16 }
    }
    pub fn is_pointer(&self) -> bool { self.mode != SimpleTypeMode::Direct }
    pub fn type_name(&self) -> String { if self.is_pointer() { format!("{}*",self.kind.name()) } else { self.kind.name().to_string() } }
}


// =============================================================================
// TypeProperty flags
// =============================================================================

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct TypeProperty: u16 {
        const PACKED          = 0x0001;
        const CTOR            = 0x0002;
        const OVERLOADED_OPS  = 0x0004;
        const NESTED          = 0x0008;
        const CNT_NESTED      = 0x0010;
        const OVLD_ASSIGN     = 0x0020;
        const CASTING_OPS     = 0x0040;
        const FORWARD_REF     = 0x0080;
        const SCOPED          = 0x0100;
        const HAS_UNIQUE_NAME = 0x0200;
        const SEALED          = 0x0400;
        const INTRINSIC       = 0x0800;
    }
}

// =============================================================================
// Type enums
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PointerMode {
    Pointer, LeftReference, MemberDataPointer, MemberFunctionPointer, RightReference,
}
impl PointerMode {
    fn from_u8(v: u8) -> Self {
        match v { 0=>Self::Pointer,1=>Self::LeftReference,2=>Self::MemberDataPointer,3=>Self::MemberFunctionPointer,4=>Self::RightReference,_=>Self::Pointer }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PointerKind {
    Near16, Far16, Huge16, Flat32, Segmented32, Flat64, Segmented32FromFlat,
}
impl PointerKind {
    fn from_u8(v: u8) -> Self {
        match v { 0=>Self::Near16,1=>Self::Far16,2=>Self::Huge16,3=>Self::Flat32,4=>Self::Segmented32,5=>Self::Flat64,6=>Self::Segmented32FromFlat,_=>Self::Flat32 }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallingConvention {
    NearC, FarC, NearPascal, FarPascal, NearFast, FarFast, Skipped,
    NearStd, FarStd, NearSys, FarSys, ThisCall, MipsCall, Generic,
    AlphaCall, PpcCall, ShCall, ArmCall, Am33Call, TriCall, Sh5Call,
    M32RCall, ClrCall, Inline, NearVector, Reserved,
}
impl CallingConvention {
    fn from_u8(v: u8) -> Self {
        match v { 0x00=>Self::NearC,0x01=>Self::FarC,0x02=>Self::NearPascal,0x03=>Self::FarPascal,0x04=>Self::NearFast,0x05=>Self::FarFast,0x06=>Self::Skipped,0x07=>Self::NearStd,0x08=>Self::FarStd,0x09=>Self::NearSys,0x0A=>Self::FarSys,0x0B=>Self::ThisCall,0x0C=>Self::MipsCall,0x0D=>Self::Generic,0x0E=>Self::AlphaCall,0x0F=>Self::PpcCall,0x10=>Self::ShCall,0x11=>Self::ArmCall,0x12=>Self::Am33Call,0x13=>Self::TriCall,0x14=>Self::Sh5Call,0x15=>Self::M32RCall,0x16=>Self::ClrCall,0x17=>Self::Inline,0x18=>Self::NearVector,_=>Self::Reserved }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemberAccessProtection { None, Private, Protected, Public }
impl MemberAccessProtection {
    fn from_u16(v: u16) -> Self { match v&3 { 1=>Self::Private,2=>Self::Protected,3=>Self::Public,_=>Self::None } }
    fn from_u8(v: u8) -> Self { match v&3 { 1=>Self::Private,2=>Self::Protected,3=>Self::Public,_=>Self::None } }
}


// =============================================================================
// Field records (sub-records inside LF_FIELDLIST)
// =============================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldRecord {
    BaseClass { type_index: u32, access: MemberAccessProtection, offset: u32 },
    VirtualBaseClass { type_index: u32, vbptr_type_index: u32, access: MemberAccessProtection, vbptr_offset: u32, vb_table_offset: u32 },
    IndirectVirtualBaseClass { type_index: u32, vbptr_type_index: u32, access: MemberAccessProtection, vbptr_offset: u32, vb_table_offset: u32 },
    Enumerate { access: MemberAccessProtection, value: i64, name: String },
    Member { access: MemberAccessProtection, type_index: u32, offset: u32, name: String },
    StaticMember { access: MemberAccessProtection, type_index: u32, name: String },
    OverloadedMethod { count: u16, method_list_index: u32, name: String },
    OneMethod { access: MemberAccessProtection, type_index: u32, vftable_offset: u32, name: String },
    NestedType { access: MemberAccessProtection, type_index: u32, name: String },
    FriendFunction { type_index: u32, name: String },
    VirtualFunctionTable { type_index: u32 },
    VirtualFunctionOffset { type_index: u32, vftable_offset: u32 },
    Index { type_index: u32 },
    Bitfield { type_index: u32, length: u8, position: u8 },
    Unknown { leaf_id: u16 },
}

// =============================================================================
// Named type record sub-types
// =============================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcedureType { pub return_type_index: u32, pub calling_convention: CallingConvention, pub arg_list_type_index: u32 }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PointerType { pub underlying_type_index: u32, pub attributes: u32, pub pointer_mode: PointerMode, pub size: u32, pub is_const: bool, pub is_volatile: bool, pub is_unaligned: bool, pub is_flat: bool, pub pointer_kind: PointerKind }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArrayType { pub element_type_index: u32, pub index_type_index: u32, pub size: u64, pub name: String }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassType { pub count: u16, pub property: TypeProperty, pub field_list_type_index: u32, pub derived_type_index: u32, pub vshape_type_index: u32, pub size: u64, pub name: String, pub mangled_name: Option<String> }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructureType { pub count: u16, pub property: TypeProperty, pub field_list_type_index: u32, pub derived_type_index: u32, pub vshape_type_index: u32, pub size: u64, pub name: String, pub mangled_name: Option<String> }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnionType { pub count: u16, pub property: TypeProperty, pub field_list_type_index: u32, pub size: u64, pub name: String, pub mangled_name: Option<String> }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnumType { pub count: u16, pub property: TypeProperty, pub underlying_type_index: u32, pub field_list_type_index: u32, pub name: String, pub mangled_name: Option<String> }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionType { pub return_type_index: u32, pub calling_convention: CallingConvention, pub arg_list_type_index: u32, pub this_type_index: u32 }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberFunctionType { pub return_type_index: u32, pub class_type_index: u32, pub this_type_index: u32, pub calling_convention: CallingConvention, pub arg_list_type_index: u32, pub this_adjustment: u32 }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VtblType { pub class_type_index: u32, pub vshape_type_index: u32 }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModifierType { pub modified_type_index: u32, pub modifiers: u16 }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArgListType { pub count: u32, pub arg_type_indices: Vec<u32> }

// =============================================================================
// Top-level type records
// =============================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypeRecord {
    FieldList { fields: Vec<FieldRecord> },
    Procedure(ProcedureType),
    Pointer(PointerType),
    Array(ArrayType),
    Class(ClassType),
    Structure(StructureType),
    Union(UnionType),
    Enum(EnumType),
    Function(FunctionType),
    MemberFunction(MemberFunctionType),
    VirtualFunctionTable(VtblType),
    Modifier(ModifierType),
    ArgumentList(ArgListType),
    MethodList { methods: Vec<u32> },
    BuildInfo { count: u16, arg_indices: Vec<u32> },
    VtShape { count: u16, descriptors: Vec<u8> },
    TypeServer { signature: u32, age: u32, name: String },
    // New type records ported from Java
    Cobol0Type { type_index: u32, name: String },
    VftPath { count: u16, base_classes: Vec<u32> },
    PrecompiledType { signature: u32, count: u16, names: Vec<String> },
    EndPrecompiled { signature: u32 },
    OemType { oem_id: u16, recog_id: u16, count: u16, raw_data: Vec<u8> },
    DimArrayType { element_type_index: u32, rank: u32, name: String },
    BArrayType { element_type_index: u32, index_type_index: u32 },
    LabelType { mode: u8 },
    DefaultArgument { type_index: u32, expression: Vec<u8> },
    DerivedClassList { count: u32, derived_type_indices: Vec<u32> },
    Simple { leaf_id: u16 },
    Unknown { leaf_id: u16, raw_data: Vec<u8> },
}


// =============================================================================
// Type record parsing entry point
// =============================================================================

pub fn parse_type_record(data: &[u8]) -> Option<TypeRecord> {
    if data.len() < 2 { return None; }
    let lid = u16::from_le_bytes([data[0],data[1]]);
    let payload = &data[2..];
    Some(match lid {
        leaf_id::LF_CLASS => parse_class_type(payload),
        leaf_id::LF_STRUCTURE => parse_structure_type(payload),
        leaf_id::LF_UNION => parse_union_type(payload),
        leaf_id::LF_ENUM => parse_enum_type(payload),
        leaf_id::LF_POINTER => parse_pointer_type(payload),
        leaf_id::LF_PROCEDURE => parse_procedure_type(payload),
        leaf_id::LF_MFUNCTION => parse_member_function_type(payload),
        leaf_id::LF_ARRAY => parse_array_type(payload),
        leaf_id::LF_FIELDLIST => parse_field_list(payload),
        leaf_id::LF_ARGLIST => parse_arglist_type(payload),
        leaf_id::LF_MODIFIER => parse_modifier_type(payload),
        leaf_id::LF_VTSHAPE => parse_vtshape_type(payload),
        leaf_id::LF_VFUNCTAB => parse_vftable_type(payload),
        leaf_id::LF_METHODLIST => parse_methodlist_type(payload),
        leaf_id::LF_BITFIELD => parse_bitfield_type(payload),
        leaf_id::LF_CHAR|leaf_id::LF_SHORT|leaf_id::LF_USHORT|leaf_id::LF_LONG|leaf_id::LF_ULONG|leaf_id::LF_QUADWORD|leaf_id::LF_UQUADWORD|leaf_id::LF_REAL32|leaf_id::LF_REAL64|leaf_id::LF_REAL80|leaf_id::LF_REAL128|leaf_id::LF_COMPLEX32|leaf_id::LF_COMPLEX64|leaf_id::LF_COMPLEX80|leaf_id::LF_COMPLEX128 => TypeRecord::Simple{leaf_id:lid},
        leaf_id::LF_TYPESERVER|leaf_id::LF_TYPESERVER2 => parse_typeserver_type(payload),
        leaf_id::LF_COBOL0 => parse_cobol0_type(payload),
        leaf_id::LF_VFTPATH => parse_vftpath_type(payload),
        leaf_id::LF_PRECOMP => parse_precomp_type(payload),
        leaf_id::LF_ENDPRECOMP => parse_endprecomp_type(payload),
        leaf_id::LF_OEM => parse_oem_type(payload),
        leaf_id::LF_DIMARRAY => parse_dimarray_type(payload),
        leaf_id::LF_BARRAY => parse_barray_type(payload),
        leaf_id::LF_LABEL => parse_label_type(payload),
        leaf_id::LF_DEFARG => parse_defarg_type(payload),
        leaf_id::LF_DERIVED => parse_derived_type(payload),
        leaf_id::LF_SKIP => parse_skip_type(payload),
        leaf_id::LF_NULL => TypeRecord::Simple{leaf_id: lid},
        _ => TypeRecord::Unknown{leaf_id:lid,raw_data:data.to_vec()},
    })
}

// =============================================================================
// Individual type parsers
// =============================================================================

fn parse_class_type(payload: &[u8]) -> TypeRecord {
    if payload.len()<16 { return TypeRecord::Unknown{leaf_id:leaf_id::LF_CLASS,raw_data:payload.to_vec()}; }
    let cnt = u16::from_le_bytes([payload[0],payload[1]]);
    let prop = TypeProperty::from_bits_truncate(u16::from_le_bytes([payload[2],payload[3]]));
    let fl = le_u32_at(payload,4);
    let di = le_u32_at(payload,8);
    let vs = le_u32_at(payload,12);
    let (sz, an) = parse_numeric(payload,16);
    let (name, mn) = parse_name_pair(&payload[an..]);
    TypeRecord::Class(ClassType{count:cnt,property:prop,field_list_type_index:fl,derived_type_index:di,vshape_type_index:vs,size:sz,name,mangled_name:mn})
}

fn parse_structure_type(payload: &[u8]) -> TypeRecord {
    if payload.len()<16 { return TypeRecord::Unknown{leaf_id:leaf_id::LF_STRUCTURE,raw_data:payload.to_vec()}; }
    let cnt = u16::from_le_bytes([payload[0],payload[1]]);
    let prop = TypeProperty::from_bits_truncate(u16::from_le_bytes([payload[2],payload[3]]));
    let fl = le_u32_at(payload,4);
    let di = le_u32_at(payload,8);
    let vs = le_u32_at(payload,12);
    let (sz, an) = parse_numeric(payload,16);
    let (name, mn) = parse_name_pair(&payload[an..]);
    TypeRecord::Structure(StructureType{count:cnt,property:prop,field_list_type_index:fl,derived_type_index:di,vshape_type_index:vs,size:sz,name,mangled_name:mn})
}

fn parse_union_type(payload: &[u8]) -> TypeRecord {
    if payload.len()<8 { return TypeRecord::Unknown{leaf_id:leaf_id::LF_UNION,raw_data:payload.to_vec()}; }
    let cnt = u16::from_le_bytes([payload[0],payload[1]]);
    let prop = TypeProperty::from_bits_truncate(u16::from_le_bytes([payload[2],payload[3]]));
    let fl = le_u32_at(payload,4);
    let (sz, an) = parse_numeric(payload,8);
    let (name, mn) = parse_name_pair(&payload[an..]);
    TypeRecord::Union(UnionType{count:cnt,property:prop,field_list_type_index:fl,size:sz,name,mangled_name:mn})
}

fn parse_enum_type(payload: &[u8]) -> TypeRecord {
    if payload.len()<12 { return TypeRecord::Unknown{leaf_id:leaf_id::LF_ENUM,raw_data:payload.to_vec()}; }
    let cnt = u16::from_le_bytes([payload[0],payload[1]]);
    let prop = TypeProperty::from_bits_truncate(u16::from_le_bytes([payload[2],payload[3]]));
    let ut = le_u32_at(payload,4);
    let fl = le_u32_at(payload,8);
    let (name, mn) = parse_name_pair(&payload[12..]);
    TypeRecord::Enum(EnumType{count:cnt,property:prop,underlying_type_index:ut,field_list_type_index:fl,name,mangled_name:mn})
}

fn parse_pointer_type(payload: &[u8]) -> TypeRecord {
    if payload.len()<12 { return TypeRecord::Unknown{leaf_id:leaf_id::LF_POINTER,raw_data:payload.to_vec()}; }
    let uti = le_u32_at(payload,0);
    let attrs = le_u32_at(payload,4);
    let pm = PointerMode::from_u8(((attrs>>5)&0x07)as u8);
    let pk = PointerKind::from_u8((attrs&0x1F)as u8);
    let sz = (attrs>>13)&0x3F;
    let is_flat = (attrs&0x0100)!=0;
    let is_volatile = (attrs&0x0200)!=0;
    let is_const = (attrs&0x0400)!=0;
    let is_unaligned = (attrs&0x0800)!=0;
    TypeRecord::Pointer(PointerType{underlying_type_index:uti,attributes:attrs,pointer_mode:pm,size:sz,is_const,is_volatile,is_unaligned,is_flat,pointer_kind:pk})
}

fn parse_procedure_type(payload: &[u8]) -> TypeRecord {
    if payload.len()<14 { return TypeRecord::Unknown{leaf_id:leaf_id::LF_PROCEDURE,raw_data:payload.to_vec()}; }
    let rti = le_u32_at(payload,0);
    let cc = CallingConvention::from_u8(payload[4]);
    let _np = u16::from_le_bytes([payload[6],payload[7]]);
    let ali = le_u32_at(payload,8);
    TypeRecord::Procedure(ProcedureType{return_type_index:rti,calling_convention:cc,arg_list_type_index:ali})
}

fn parse_member_function_type(payload: &[u8]) -> TypeRecord {
    if payload.len()<26 { return TypeRecord::Unknown{leaf_id:leaf_id::LF_MFUNCTION,raw_data:payload.to_vec()}; }
    let rti = le_u32_at(payload,0);
    let cti = le_u32_at(payload,4);
    let tti = le_u32_at(payload,8);
    let cc = CallingConvention::from_u8(payload[12]);
    let _np = u16::from_le_bytes([payload[14],payload[15]]);
    let ali = le_u32_at(payload,16);
    let ta = le_u32_at(payload,20);
    TypeRecord::MemberFunction(MemberFunctionType{return_type_index:rti,class_type_index:cti,this_type_index:tti,calling_convention:cc,arg_list_type_index:ali,this_adjustment:ta})
}

fn parse_array_type(payload: &[u8]) -> TypeRecord {
    if payload.len()<10 { return TypeRecord::Unknown{leaf_id:leaf_id::LF_ARRAY,raw_data:payload.to_vec()}; }
    let eti = le_u32_at(payload,0);
    let iti = le_u32_at(payload,4);
    let (sz, an) = parse_numeric(payload,8);
    let name = parse_null_terminated_string(&payload[an..]);
    TypeRecord::Array(ArrayType{element_type_index:eti,index_type_index:iti,size:sz,name})
}

fn parse_field_list(payload: &[u8]) -> TypeRecord {
    let fields = parse_field_records(payload);
    TypeRecord::FieldList{fields}
}

fn parse_bitfield_type(payload: &[u8]) -> TypeRecord {
    if payload.len()<4 { return TypeRecord::Unknown{leaf_id:leaf_id::LF_BITFIELD,raw_data:payload.to_vec()}; }
    let eti = le_u32_at(payload,0);
    let length = if payload.len()>4 { payload[4] } else { 0 };
    let position = if payload.len()>5 { payload[5] } else { 0 };
    TypeRecord::FieldList{fields:vec![FieldRecord::Bitfield{type_index:eti,length,position}]}
}

fn parse_arglist_type(payload: &[u8]) -> TypeRecord {
    if payload.len()<4 { return TypeRecord::ArgumentList(ArgListType{count:0,arg_type_indices:vec![]}); }
    let cnt = le_u32_at(payload,0);
    let mut args = Vec::with_capacity(cnt as usize);
    for i in 0..cnt as usize { let o=4+i*4; if o+4<=payload.len(){args.push(le_u32_at(payload,o));} }
    TypeRecord::ArgumentList(ArgListType{count:cnt,arg_type_indices:args})
}

fn parse_modifier_type(payload: &[u8]) -> TypeRecord {
    if payload.len()<6 { return TypeRecord::Unknown{leaf_id:leaf_id::LF_MODIFIER,raw_data:payload.to_vec()}; }
    TypeRecord::Modifier(ModifierType{modified_type_index:le_u32_at(payload,0),modifiers:u16::from_le_bytes([payload[4],payload[5]])})
}

fn parse_vtshape_type(payload: &[u8]) -> TypeRecord {
    let cnt = if payload.len()>=2 { u16::from_le_bytes([payload[0],payload[1]]) } else { 0 };
    let descs = if payload.len()>2 { payload[2..].to_vec() } else { vec![] };
    TypeRecord::VtShape{count:cnt,descriptors:descs}
}

fn parse_vftable_type(payload: &[u8]) -> TypeRecord {
    if payload.len()<8 { return TypeRecord::Unknown{leaf_id:leaf_id::LF_VFUNCTAB,raw_data:payload.to_vec()}; }
    TypeRecord::VirtualFunctionTable(VtblType{class_type_index:le_u32_at(payload,0),vshape_type_index:le_u32_at(payload,4)})
}

fn parse_methodlist_type(payload: &[u8]) -> TypeRecord {
    let mut methods = Vec::new(); let mut pos=0;
    while pos+4<=payload.len() { methods.push(le_u32_at(payload,pos)); pos+=4; }
    TypeRecord::MethodList{methods}
}

fn parse_typeserver_type(payload: &[u8]) -> TypeRecord {
    if payload.len()<8 { return TypeRecord::Unknown{leaf_id:leaf_id::LF_TYPESERVER,raw_data:payload.to_vec()}; }
    TypeRecord::TypeServer{signature:le_u32_at(payload,0),age:le_u32_at(payload,4),name:parse_null_terminated_string(&payload[8..])}
}

fn parse_cobol0_type(payload: &[u8]) -> TypeRecord {
    if payload.len() < 4 { return TypeRecord::Unknown{leaf_id: leaf_id::LF_COBOL0, raw_data: payload.to_vec()}; }
    let ti = le_u32_at(payload, 0);
    let name = parse_null_terminated_string(&payload[4..]);
    TypeRecord::Cobol0Type{type_index: ti, name}
}

fn parse_vftpath_type(payload: &[u8]) -> TypeRecord {
    if payload.len() < 2 { return TypeRecord::Unknown{leaf_id: leaf_id::LF_VFTPATH, raw_data: payload.to_vec()}; }
    let count = u16::from_le_bytes([payload[0], payload[1]]);
    let mut classes = Vec::with_capacity(count as usize);
    for i in 0..count as usize {
        let off = 2 + i * 4;
        if off + 4 <= payload.len() { classes.push(le_u32_at(payload, off)); }
    }
    TypeRecord::VftPath{count, base_classes: classes}
}

fn parse_precomp_type(payload: &[u8]) -> TypeRecord {
    if payload.len() < 12 { return TypeRecord::Unknown{leaf_id: leaf_id::LF_PRECOMP, raw_data: payload.to_vec()}; }
    let count = u16::from_le_bytes([payload[0], payload[1]]);
    let signature = le_u32_at(payload, 4);
    let name = parse_null_terminated_string(&payload[8..]);
    TypeRecord::PrecompiledType{signature, count, names: vec![name]}
}

fn parse_endprecomp_type(payload: &[u8]) -> TypeRecord {
    if payload.len() < 4 { return TypeRecord::Unknown{leaf_id: leaf_id::LF_ENDPRECOMP, raw_data: payload.to_vec()}; }
    TypeRecord::EndPrecompiled{signature: le_u32_at(payload, 0)}
}

fn parse_oem_type(payload: &[u8]) -> TypeRecord {
    if payload.len() < 8 { return TypeRecord::Unknown{leaf_id: leaf_id::LF_OEM, raw_data: payload.to_vec()}; }
    let oem_id = u16::from_le_bytes([payload[0], payload[1]]);
    let recog_id = u16::from_le_bytes([payload[2], payload[3]]);
    let count = u16::from_le_bytes([payload[4], payload[5]]);
    TypeRecord::OemType{oem_id, recog_id, count, raw_data: payload[6..].to_vec()}
}

fn parse_dimarray_type(payload: &[u8]) -> TypeRecord {
    if payload.len() < 8 { return TypeRecord::Unknown{leaf_id: leaf_id::LF_DIMARRAY, raw_data: payload.to_vec()}; }
    let eti = le_u32_at(payload, 0);
    let rank = le_u32_at(payload, 4);
    let name = parse_null_terminated_string(&payload[8..]);
    TypeRecord::DimArrayType{element_type_index: eti, rank, name}
}

fn parse_barray_type(payload: &[u8]) -> TypeRecord {
    if payload.len() < 8 { return TypeRecord::Unknown{leaf_id: leaf_id::LF_BARRAY, raw_data: payload.to_vec()}; }
    TypeRecord::BArrayType{element_type_index: le_u32_at(payload, 0), index_type_index: le_u32_at(payload, 4)}
}

fn parse_label_type(payload: &[u8]) -> TypeRecord {
    if payload.is_empty() { return TypeRecord::Unknown{leaf_id: leaf_id::LF_LABEL, raw_data: payload.to_vec()}; }
    TypeRecord::LabelType{mode: payload[0]}
}

fn parse_defarg_type(payload: &[u8]) -> TypeRecord {
    if payload.len() < 4 { return TypeRecord::Unknown{leaf_id: leaf_id::LF_DEFARG, raw_data: payload.to_vec()}; }
    let ti = le_u32_at(payload, 0);
    TypeRecord::DefaultArgument{type_index: ti, expression: payload[4..].to_vec()}
}

fn parse_derived_type(payload: &[u8]) -> TypeRecord {
    if payload.len() < 4 { return TypeRecord::Unknown{leaf_id: leaf_id::LF_DERIVED, raw_data: payload.to_vec()}; }
    let count = le_u32_at(payload, 0);
    let mut indices = Vec::with_capacity(count as usize);
    for i in 0..count as usize {
        let off = 4 + i * 4;
        if off + 4 <= payload.len() { indices.push(le_u32_at(payload, off)); }
    }
    TypeRecord::DerivedClassList{count, derived_type_indices: indices}
}

fn parse_skip_type(payload: &[u8]) -> TypeRecord {
    if payload.len() < 2 { return TypeRecord::Unknown{leaf_id: leaf_id::LF_SKIP, raw_data: payload.to_vec()}; }
    // LF_SKIP contains a type index to skip to
    let _skip_to = le_u32_at(payload, 0);
    TypeRecord::Unknown{leaf_id: leaf_id::LF_SKIP, raw_data: payload.to_vec()}
}

// =============================================================================
// Field record parser (inside LF_FIELDLIST)
// =============================================================================

fn parse_field_records(data: &[u8]) -> Vec<FieldRecord> {
    let mut fields = Vec::new(); let mut pos = 0usize;
    while pos+2 <= data.len() {
        let lid = u16::from_le_bytes([data[pos],data[pos+1]]);
        let rec = parse_single_field_record(lid, &data[pos+2..]);
        fields.push(rec);
        pos = advance_field_record(lid, data, pos);
    }
    fields
}

fn advance_field_record(lid: u16, data: &[u8], pos: usize) -> usize {
    let p = &data[pos+2..];
    match lid {
        leaf_id::LF_BCLASS|leaf_id::LF_VBCLASS => pos+2+12,
        leaf_id::LF_IVBCLASS => pos+2+20,
        leaf_id::LF_ENUMERATE => {
            if p.len()<2 {return data.len();}
            let (_,an)=parse_numeric(p,2);
            let (_,nx)=split_null_term(p,an); pos+2+nx
        }
        leaf_id::LF_MEMBER|leaf_id::LF_STMEMBER => {
            if p.len()<10 {return data.len();}
            let (_,nx)=split_null_term(p,10); pos+2+nx
        }
        leaf_id::LF_METHOD => {
            if p.len()<6 {return data.len();}
            let (_,nx)=split_null_term(p,6); pos+2+nx
        }
        leaf_id::LF_ONEMETHOD => {
            if p.len()<12 {return data.len();}
            let (_,nx)=split_null_term(p,12); pos+2+nx
        }
        leaf_id::LF_NESTTYPE|leaf_id::LF_NESTTYPEEX => {
            if p.len()<4 {return data.len();}
            let (_,nx)=split_null_term(p,4); pos+2+nx
        }
        leaf_id::LF_INDEX=>pos+2+4,
        leaf_id::LF_VFUNCTAB=>pos+2+4,
        leaf_id::LF_VFUNCOFF=>pos+2+8,
        leaf_id::LF_FRIENDFCN=>{
            if p.len()<4 {return data.len();}
            let (_,nx)=split_null_term(p,4); pos+2+nx
        }
        leaf_id::LF_BITFIELD=>pos+2+6,
        _=>data.len(),
    }
}

fn parse_single_field_record(lid: u16, p: &[u8]) -> FieldRecord {
    match lid {
        leaf_id::LF_BCLASS=>{
            if p.len()<10{return FieldRecord::Unknown{leaf_id:lid};}
            FieldRecord::BaseClass{access:MemberAccessProtection::from_u16(u16::from_le_bytes([p[0],p[1]])),type_index:le_u32_at(p,2),offset:if p.len()>=14{le_u32_at(p,10)}else{le_u32_at(p,8)}}
        }
        leaf_id::LF_VBCLASS=>{
            if p.len()<16{return FieldRecord::Unknown{leaf_id:lid};}
            FieldRecord::VirtualBaseClass{access:MemberAccessProtection::from_u16(u16::from_le_bytes([p[0],p[1]])),type_index:le_u32_at(p,2),vbptr_type_index:le_u32_at(p,6),vbptr_offset:le_u32_at(p,10),vb_table_offset:le_u32_at(p,14)}
        }
        leaf_id::LF_IVBCLASS=>{
            if p.len()<18{return FieldRecord::Unknown{leaf_id:lid};}
            FieldRecord::IndirectVirtualBaseClass{access:MemberAccessProtection::from_u16(u16::from_le_bytes([p[0],p[1]])),type_index:le_u32_at(p,2),vbptr_type_index:le_u32_at(p,6),vbptr_offset:le_u32_at(p,10),vb_table_offset:le_u32_at(p,14)}
        }
        leaf_id::LF_ENUMERATE=>{
            let acc=if p.len()>=2{MemberAccessProtection::from_u16(u16::from_le_bytes([p[0],p[1]]))}else{MemberAccessProtection::None};
            let (v,an)=parse_numeric(p,2);
            FieldRecord::Enumerate{access:acc,value:v as i64,name:parse_null_terminated_string(&p[an..])}
        }
        leaf_id::LF_MEMBER=>{
            let acc=if p.len()>=2{MemberAccessProtection::from_u16(u16::from_le_bytes([p[0],p[1]]))}else{MemberAccessProtection::None};
            let ti=le_u32_at(p,2);
            let (off,ns)=parse_numeric(p,6);
            FieldRecord::Member{access:acc,type_index:ti,offset:off as u32,name:parse_null_terminated_string(&p[ns..])}
        }
        leaf_id::LF_STMEMBER=>{
            let acc=if p.len()>=2{MemberAccessProtection::from_u16(u16::from_le_bytes([p[0],p[1]]))}else{MemberAccessProtection::None};
            FieldRecord::StaticMember{access:acc,type_index:le_u32_at(p,2),name:parse_null_terminated_string(&p[6..])}
        }
        leaf_id::LF_METHOD=>{
            let cnt=if p.len()>=2{u16::from_le_bytes([p[0],p[1]])}else{0};
            FieldRecord::OverloadedMethod{count:cnt,method_list_index:le_u32_at(p,2),name:parse_null_terminated_string(&p[6..])}
        }
        leaf_id::LF_ONEMETHOD=>{
            let acc=if p.len()>=2{MemberAccessProtection::from_u16(u16::from_le_bytes([p[0],p[1]]))}else{MemberAccessProtection::None};
            let ti=le_u32_at(p,2);
            let vo=if p.len()>=10{le_u32_at(p,6)}else{0xFFFFFFFF};
            FieldRecord::OneMethod{access:acc,type_index:ti,vftable_offset:vo,name:parse_null_terminated_string(&p[10..])}
        }
        leaf_id::LF_NESTTYPE|leaf_id::LF_NESTTYPEEX=>{
            FieldRecord::NestedType{access:MemberAccessProtection::None,type_index:le_u32_at(p,2),name:parse_null_terminated_string(&p[6..])}
        }
        leaf_id::LF_INDEX=>{
            FieldRecord::Index{type_index:if p.len()>=4{le_u32_at(p,0)}else{0}}
        }
        leaf_id::LF_VFUNCTAB=>{
            FieldRecord::VirtualFunctionTable{type_index:if p.len()>=4{le_u32_at(p,0)}else{0}}
        }
        leaf_id::LF_VFUNCOFF=>{
            FieldRecord::VirtualFunctionOffset{type_index:if p.len()>=4{le_u32_at(p,0)}else{0},vftable_offset:if p.len()>=8{le_u32_at(p,4)}else{0}}
        }
        leaf_id::LF_FRIENDFCN=>{
            FieldRecord::FriendFunction{type_index:if p.len()>=4{le_u32_at(p,0)}else{0},name:parse_null_terminated_string(&p[4..])}
        }
        leaf_id::LF_BITFIELD=>{
            FieldRecord::Bitfield{type_index:if p.len()>=4{le_u32_at(p,0)}else{0},length:if p.len()>=6{p[4]}else{0},position:if p.len()>=6{p[5]}else{0}}
        }
        _=>FieldRecord::Unknown{leaf_id:lid},
    }
}


// =============================================================================
// Symbol record kind IDs
// =============================================================================

pub mod symbol_kind {
    pub const S_COMPILE: u16=0x0001; pub const S_REGISTER: u16=0x0002;
    pub const S_CONSTANT: u16=0x0003; pub const S_UDT: u16=0x0004;
    pub const S_SSEARCH: u16=0x0005; pub const S_END: u16=0x0006;
    pub const S_SKIP: u16=0x0007; pub const S_CVRESERVE: u16=0x0008;
    pub const S_OBJNAME: u16=0x0009; pub const S_ENDARG: u16=0x000A;
    pub const S_COBOLUDT: u16=0x000B; pub const S_MANYREG: u16=0x000C;
    pub const S_RETURN: u16=0x000D; pub const S_ENTRYTHIS: u16=0x000E;
    pub const S_BPREL16: u16=0x0100; pub const S_LDATA16: u16=0x0101;
    pub const S_GDATA16: u16=0x0102; pub const S_PUB16: u16=0x0103;
    pub const S_LPROC16: u16=0x0104; pub const S_GPROC16: u16=0x0105;
    pub const S_THUNK16: u16=0x0106; pub const S_BLOCK16: u16=0x0107;
    pub const S_WITH16: u16=0x0108; pub const S_LABEL16: u16=0x0109;
    pub const S_CEXMODEL16: u16=0x010A; pub const S_VFTABLE16: u16=0x010B;
    pub const S_REGREL16: u16=0x010C;
    pub const S_BPREL32: u16=0x0200; pub const S_LDATA32: u16=0x0201;
    pub const S_GDATA32: u16=0x0202; pub const S_PUB32: u16=0x0203;
    pub const S_LPROC32: u16=0x0204; pub const S_GPROC32: u16=0x0205;
    pub const S_THUNK32: u16=0x0206; pub const S_BLOCK32: u16=0x0207;
    pub const S_WITH32: u16=0x0208; pub const S_LABEL32: u16=0x0209;
    pub const S_CEXMODEL32: u16=0x020A; pub const S_VFTABLE32: u16=0x020B;
    pub const S_REGREL32: u16=0x020C; pub const S_LTHREAD32: u16=0x020D;
    pub const S_GTHREAD32: u16=0x020E; pub const S_SLINK32: u16=0x020F;
    pub const S_LPROCMIPS: u16=0x0300; pub const S_GPROCMIPS: u16=0x0301;
    pub const S_PROCREF_ST: u16=0x0400; pub const S_DATAREF_ST: u16=0x0401;
    pub const S_ALIGN: u16=0x0402; pub const S_LPROCREF_ST: u16=0x0403;
    pub const S_PROCREF: u16=0x1125; pub const S_DATAREF: u16=0x1126;
    pub const S_LPROCREF: u16=0x1127;
    pub const S_OEM: u16=0x0404; pub const S_TI16_MAX: u16=0x1000;
    pub const S_REGISTER_ST: u16=0x1001; pub const S_CONSTANT_ST: u16=0x1002;
    pub const S_UDT_ST: u16=0x1003; pub const S_COBOLUDT_ST: u16=0x1004;
    pub const S_MANYREG_ST: u16=0x1005; pub const S_BPREL32_ST: u16=0x1006;
    pub const S_LDATA32_ST: u16=0x1007; pub const S_GDATA32_ST: u16=0x1008;
    pub const S_PUB32_ST: u16=0x1009; pub const S_LPROC32_ST: u16=0x100A;
    pub const S_GPROC32_ST: u16=0x100B; pub const S_VFTABLE32_ST: u16=0x100C;
    pub const S_REGREL32_ST: u16=0x100D; pub const S_LTHREAD32_ST: u16=0x100E;
    pub const S_GTHREAD32_ST: u16=0x100F; pub const S_LPROCMIPS_ST: u16=0x1010;
    pub const S_GPROCMIPS_ST: u16=0x1011; pub const S_FRAMEPROC: u16=0x1012;
    pub const S_COMPILE2: u16=0x1013; pub const S_MANYREG2: u16=0x1014;
    pub const S_LPROCIA64_ST: u16=0x1015; pub const S_GPROCIA64_ST: u16=0x1016;
    pub const S_LOCALSLOT: u16=0x1017; pub const S_PARAMSLOT: u16=0x1018;
    pub const S_ANNOTATION: u16=0x1019; pub const S_GMANDATA: u16=0x101A;
    pub const S_LMANDATA: u16=0x101B; pub const S_MANYLOCAL: u16=0x101C;
    pub const S_GMANPROC: u16=0x101D; pub const S_LMANPROC: u16=0x101E;
    pub const S_TRAMPOLINE: u16=0x101F; pub const S_MANCONSTANT: u16=0x1020;
    pub const S_ATTR_FRAMEREL: u16=0x1021; pub const S_ATTR_REGISTER: u16=0x1022;
    pub const S_ATTR_REGREL: u16=0x1023; pub const S_ATTR_MANYREG: u16=0x1024;
    pub const S_SEPCODE: u16=0x1025; pub const S_LOCAL_2005: u16=0x1026;
    pub const S_DEFRANGE_2005: u16=0x1027; pub const S_DEFRANGE2_2005: u16=0x1028;
    pub const S_SECTION: u16=0x1029; pub const S_COFFGROUP: u16=0x102A;
    pub const S_EXPORT: u16=0x102B; pub const S_CALLSITEINFO: u16=0x102C;
    pub const S_FRAMECOOKIE: u16=0x102D; pub const S_DISCARDED: u16=0x102E;
    pub const S_COMPILE3: u16=0x102F; pub const S_ENVBLOCK: u16=0x1034;
    pub const S_LOCAL_V2: u16=0x1035;
    pub const S_DEFRANGE_REGISTER: u16=0x1036;
    pub const S_DEFRANGE_FRAMEPOINTER_REL: u16=0x1037;
    pub const S_DEFRANGE_SUBFIELD_REGISTER: u16=0x1038;
    pub const S_DEFRANGE_FRAMEPOINTER_REL_FULL_SCOPE: u16=0x1039;
    pub const S_DEFRANGE_REGISTER_REL: u16=0x103A;
    pub const S_LPROC32_ID: u16=0x103B; pub const S_GPROC32_ID: u16=0x103C;
    pub const S_BUILDINFO: u16=0x103D;
    pub const S_INLINESITE: u16=0x103E; pub const S_INLINESITE_END: u16=0x103F;
    pub const S_PROC_ID_END: u16=0x1040;
    pub const S_MANFRAMEREL: u16=0x111E;
    pub const S_REGFRAME: u16=0x111F;
    pub const S_FILESTATIC: u16=0x1120;
    pub const S_HEAPALLOCA: u16=0x115E;
    pub const S_UNAMESPACE_ST: u16=0x1029;
    pub const S_UNAMESPACE: u16=0x1124;
    pub const S_PECOFF_SECTION: u16=0x1136;
    pub const S_PE_COFFGROUP: u16=0x1137;
    pub const S_ANNOTATIONREF: u16=0x1128;
    pub const S_INDIRECT_CALLSITEINFO: u16=0x1139;
    pub const S_ENVBLOCK_V2: u16=0x113D;
    pub const S_BUILDINFO_V2: u16=0x114C;
    pub const S_GPROCREF: u16=0x1125;
    pub const S_DATAREF_V2: u16=0x1126;
    pub const S_LPROCREF_V2: u16=0x1127;
    pub const S_THUNK32_V2: u16=0x1102;
    pub const S_THUNK32_ST: u16=0x1114;
    pub const S_INLINED_FUNCTION_CALLSITE: u16=0x114D;
    pub const S_INLINED_FUNCTION_CALLSITE_EXTENDED: u16=0x115D;
    pub const S_LPROCIA64: u16=0x1118;
    pub const S_GPROCIA64: u16=0x1119;
    pub const S_REGREL32_V2: u16=0x1111;
}


// =============================================================================
// Symbol record sub-types
// =============================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataSymbol { pub type_index: u32, pub offset: u32, pub segment: u16, pub name: String }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcSymbol { pub type_index: u32, pub debug_start: u32, pub debug_end: u32, pub offset: u32, pub segment: u16, pub flags: u8, pub name: String }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicSymbol { pub flags: u32, pub offset: u32, pub segment: u16, pub name: String }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegSymbol { pub type_index: u32, pub register: u16, pub name: String }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegRelSymbol { pub type_index: u32, pub offset: i32, pub register: u16, pub name: String }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BpRelSymbol { pub type_index: u32, pub offset: i32, pub name: String }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConstantSymbol { pub type_index: u32, pub value: u64, pub name: String }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdtSymbol { pub type_index: u32, pub name: String }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThreadSymbol { pub type_index: u32, pub offset: u32, pub segment: u16, pub name: String }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LabelSymbol { pub offset: u32, pub segment: u16, pub flags: u8, pub name: String }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompileInfo { pub flags: u32, pub machine: u16, pub frontend_major: u16, pub frontend_minor: u16, pub frontend_build: u16, pub backend_major: u16, pub backend_minor: u16, pub backend_build: u16, pub version_string: String }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameProcInfo { pub frame_size: u32, pub padding_size: u32, pub padding_offset: u32, pub callee_saved_reg_size: u32, pub exception_handler_offset: u32, pub exception_handler_section: u16, pub flags: u32 }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThunkSymbol { pub parent_offset: u32, pub end_offset: u32, pub next_offset: u32, pub offset: u32, pub segment: u16, pub length: u16, pub thunk_type: u8, pub name: String, pub variant_offset: u32 }

// =============================================================================
// SymbolRecord enum — all supported CV symbol records
// =============================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SymbolRecord {
    GlobalData(DataSymbol),
    GlobalProcedure(ProcSymbol),
    LocalProcedure(ProcSymbol),
    Public(PublicSymbol),
    LocalVariable(DataSymbol),
    RegisterVariable(RegSymbol),
    RegisterRelativeVariable(RegRelSymbol),
    BasePointerRelativeVariable(BpRelSymbol),
    Constant(ConstantSymbol),
    UserDefinedType(UdtSymbol),
    ThreadStorage(ThreadSymbol),
    BlockStart { parent_offset: u32, end_offset: u32, segment: u16, name: String },
    WithStart { parent_offset: u32, end_offset: u32, segment: u16, expression: String },
    End,
    Label(LabelSymbol),
    CompileInfo(CompileInfo),
    ObjectName { signature: u32, name: String },
    FrameProc(FrameProcInfo),
    Thunk(ThunkSymbol),
    ProcedureReference { name: String, module_index: u16, type_index: u32 },
    DataReference { name: String, module_index: u16, type_index: u32 },
    Annotation { offset: u32, segment: u16, count: u16, strings: Vec<String> },
    CallSiteInfo { offset: u32, section: u16, type_index: u32 },
    InlineSite { parent_offset: u32, end_offset: u32, inlinee_type_index: u32, annotations: Vec<u8> },
    InlineSiteEnd,
    Section { section_number: u16, alignment: u8, rva: u32, size: u32, characteristics: u32, name: String },
    CoffGroup { size: u32, characteristics: u32, offset: u32, segment: u16, name: String },
    PeCoffGroup { length: u32, characteristics: u32, offset: u32, segment: u16, name: String },
    AnnotationReference { name: String, module_index: u16, sum_name: u32, offset_actual_symbol: u32 },
    BuildInfo { item_id: u32 },
    SeparatedCode { parent_offset: u32, end_offset: u32, length: u32, separated_code_segment: u16, separated_code_offset: u32, parent_segment: u16 },
    Trampoline { trampoline_type: u16, size: u16, thunk_offset: u32, target_offset: u32, thunk_section: u16, target_section: u16 },
    // New symbol variants ported from Java
    Compile2(CompileInfo),
    Return { flags: u32, return_value_register: u16 },
    EntryThis { flags: u8, this_register: u16 },
    VfTable { type_index: u32, offset: u32, segment: u16, name: String },
    Export { ordinal: u16, flags: u16, name: String },
    FrameCookie { offset: u32, register: u16, cookie_type: u8 },
    ManagedProcedure(ProcSymbol),
    ManagedData(DataSymbol),
    ManyRegister { type_index: u16, count: u8, registers: Vec<u16>, name: String },
    EnvironmentBlock { fields: Vec<(String, String)> },
    LocalV2 { type_index: u32, flags: u16, name: String },
    DefRangeRegister { register: u16, offset_parent: i32, range_offset: u16, range_length: u16 },
    DefRangeFrameRel { frame_offset: i32, range_offset: u16, range_length: u16 },
    DefRangeSubfieldRegister { register: u16, offset_parent: i32, offset_in_parent: u32, range_offset: u16, range_length: u16 },
    DefRangeRegisterRel { register: u16, flags: u16, offset: i32, range_offset: u16, range_length: u16 },
    LocalSlot { type_index: u32, slot: u16, name: String },
    ParamSlot { type_index: u32, slot: u16, name: String },
    LProc32Id(ProcSymbol),
    GProc32Id(ProcSymbol),
    ProcIdEnd,
    Unknown { kind: u16 },
}


// =============================================================================
// Symbol record parsing entry point
// =============================================================================

/// Parse a single symbol record from a byte slice.
/// The slice should include the 2-byte record length prefix.
pub fn parse_symbol_record(data: &[u8]) -> Option<SymbolRecord> {
    if data.len() < 4 { return None; }
    let _rlen = u16::from_le_bytes([data[0],data[1]]) as usize;
    let kind = u16::from_le_bytes([data[2],data[3]]);
    let payload = &data[4..];
    Some(parse_symbol_payload(kind, payload))
}

fn parse_symbol_payload(kind: u16, payload: &[u8]) -> SymbolRecord {
    match kind {
        symbol_kind::S_GDATA32|symbol_kind::S_LDATA32|symbol_kind::S_GDATA32_ST|symbol_kind::S_LDATA32_ST => parse_data_symbol(kind, payload),
        symbol_kind::S_GPROC32|symbol_kind::S_LPROC32|symbol_kind::S_GPROC32_ST|symbol_kind::S_LPROC32_ST => parse_proc_symbol(kind, payload),
        symbol_kind::S_PUB32|symbol_kind::S_PUB32_ST => parse_public_symbol(payload),
        symbol_kind::S_LABEL32|symbol_kind::S_LABEL16 => parse_label_symbol(payload),
        symbol_kind::S_BLOCK32|symbol_kind::S_BLOCK16 => parse_block32(payload),
        symbol_kind::S_WITH32|symbol_kind::S_WITH16 => parse_with32(payload),
        symbol_kind::S_END|symbol_kind::S_ENDARG|symbol_kind::S_PROC_ID_END => SymbolRecord::End,
        symbol_kind::S_REGISTER|symbol_kind::S_REGISTER_ST => parse_register_symbol(payload),
        symbol_kind::S_REGREL32|symbol_kind::S_REGREL32_ST|symbol_kind::S_REGREL16 => parse_regrel_symbol(payload),
        symbol_kind::S_BPREL32|symbol_kind::S_BPREL32_ST|symbol_kind::S_BPREL16 => parse_bprel_symbol(payload),
        symbol_kind::S_CONSTANT|symbol_kind::S_CONSTANT_ST|symbol_kind::S_MANCONSTANT => parse_constant_symbol(payload),
        symbol_kind::S_UDT|symbol_kind::S_UDT_ST => parse_udt_symbol(payload),
        symbol_kind::S_LTHREAD32|symbol_kind::S_GTHREAD32|symbol_kind::S_LTHREAD32_ST|symbol_kind::S_GTHREAD32_ST => parse_thread_symbol(payload, kind),
        symbol_kind::S_COMPILE3 => parse_compile3(payload),
        symbol_kind::S_COMPILE2 => parse_compile3(payload),
        symbol_kind::S_COMPILE => parse_compile_v1(payload),
        symbol_kind::S_OBJNAME => parse_objname(payload),
        symbol_kind::S_FRAMEPROC => parse_frameproc(payload),
        symbol_kind::S_THUNK32|symbol_kind::S_THUNK16 => parse_thunk(payload),
        symbol_kind::S_PROCREF|symbol_kind::S_PROCREF_ST|symbol_kind::S_LPROCREF|symbol_kind::S_LPROCREF_ST|symbol_kind::S_GPROCREF => parse_procref(payload),
        symbol_kind::S_DATAREF|symbol_kind::S_DATAREF_ST|symbol_kind::S_DATAREF_V2 => parse_dataref(payload),
        symbol_kind::S_ANNOTATION => parse_annotation(payload),
        symbol_kind::S_TRAMPOLINE => parse_trampoline(payload),
        symbol_kind::S_SECTION => parse_section_sym(payload),
        symbol_kind::S_COFFGROUP|symbol_kind::S_PE_COFFGROUP => parse_coffgroup(kind, payload),
        symbol_kind::S_ANNOTATIONREF => parse_annotationref(payload),
        symbol_kind::S_SEPCODE => parse_sepcode(payload),
        symbol_kind::S_BUILDINFO => parse_buildinfo_sym(payload),
        symbol_kind::S_INLINESITE => parse_inlinesite(payload),
        symbol_kind::S_INLINESITE_END => SymbolRecord::InlineSiteEnd,
        symbol_kind::S_CALLSITEINFO => parse_callsite(payload),
        symbol_kind::S_RETURN => parse_return_symbol(payload),
        symbol_kind::S_ENTRYTHIS => parse_entry_this(payload),
        symbol_kind::S_VFTABLE32|symbol_kind::S_VFTABLE16|symbol_kind::S_VFTABLE32_ST => parse_vftable_symbol(payload),
        symbol_kind::S_EXPORT => parse_export_symbol(payload),
        symbol_kind::S_FRAMECOOKIE => parse_frame_cookie(payload),
        symbol_kind::S_ENVBLOCK => parse_envblock(payload),
        symbol_kind::S_LOCAL_V2|symbol_kind::S_LOCAL_2005 => parse_local_v2(payload),
        symbol_kind::S_DEFRANGE_REGISTER => parse_defrange_register(payload),
        symbol_kind::S_DEFRANGE_FRAMEPOINTER_REL => parse_defrange_framepointer_rel(payload),
        symbol_kind::S_DEFRANGE_SUBFIELD_REGISTER => parse_defrange_subfield_register(payload),
        symbol_kind::S_DEFRANGE_FRAMEPOINTER_REL_FULL_SCOPE => parse_defrange_framepointer_rel(payload),
        symbol_kind::S_DEFRANGE_REGISTER_REL => parse_defrange_register_rel(payload),
        symbol_kind::S_GMANDATA => { let sym = parse_data_symbol(kind, payload); if let SymbolRecord::GlobalData(d) = sym { SymbolRecord::ManagedData(d) } else { sym } }
        symbol_kind::S_LMANDATA => { let sym = parse_data_symbol(kind, payload); if let SymbolRecord::LocalVariable(d) = sym { SymbolRecord::ManagedData(d) } else { sym } }
        symbol_kind::S_GMANPROC|symbol_kind::S_LMANPROC => { let sym = parse_proc_symbol(kind, payload); SymbolRecord::ManagedProcedure(match sym { SymbolRecord::GlobalProcedure(p)|SymbolRecord::LocalProcedure(p)=>p, _=>ProcSymbol{type_index:0,debug_start:0,debug_end:0,offset:0,segment:0,flags:0,name:String::new()} }) }
        symbol_kind::S_LOCALSLOT => parse_slot_symbol(payload, true),
        symbol_kind::S_PARAMSLOT => parse_slot_symbol(payload, false),
        symbol_kind::S_LPROC32_ID|symbol_kind::S_GPROC32_ID => parse_proc_id_symbol(kind, payload),
        symbol_kind::S_MANYREG2|symbol_kind::S_MANYREG => parse_many_register(payload),
        _ => SymbolRecord::Unknown{kind},
    }
}

// =============================================================================
// Individual symbol parsers
// =============================================================================

fn parse_data_symbol(kind: u16, payload: &[u8]) -> SymbolRecord {
    if payload.len()<10 { return SymbolRecord::Unknown{kind}; }
    let sym = DataSymbol{type_index:le_u32_at(payload,0),offset:le_u32_at(payload,4),segment:u16::from_le_bytes([payload[8],payload[9]]),name:parse_null_terminated_string(&payload[10..])};
    match kind { symbol_kind::S_GDATA32|symbol_kind::S_GDATA32_ST=>SymbolRecord::GlobalData(sym),_=>SymbolRecord::LocalVariable(sym) }
}

fn parse_proc_symbol(kind: u16, payload: &[u8]) -> SymbolRecord {
    if payload.len()<17 { return SymbolRecord::Unknown{kind}; }
    let sym = ProcSymbol{type_index:le_u32_at(payload,0),debug_start:le_u32_at(payload,4),debug_end:le_u32_at(payload,8),offset:le_u32_at(payload,12),segment:u16::from_le_bytes([payload[16],payload[17]]),flags:if payload.len()>18{payload[18]}else{0},name:parse_null_terminated_string(&payload[19..])};
    match kind { symbol_kind::S_GPROC32|symbol_kind::S_GPROC32_ST=>SymbolRecord::GlobalProcedure(sym),_=>SymbolRecord::LocalProcedure(sym) }
}

fn parse_public_symbol(payload: &[u8]) -> SymbolRecord {
    if payload.len()<10 { return SymbolRecord::Unknown{kind:symbol_kind::S_PUB32}; }
    SymbolRecord::Public(PublicSymbol{flags:le_u32_at(payload,0),offset:le_u32_at(payload,4),segment:u16::from_le_bytes([payload[8],payload[9]]),name:parse_null_terminated_string(&payload[10..])})
}

fn parse_label_symbol(payload: &[u8]) -> SymbolRecord {
    if payload.len()<7 { return SymbolRecord::Unknown{kind:symbol_kind::S_LABEL32}; }
    SymbolRecord::Label(LabelSymbol{offset:le_u32_at(payload,0),segment:u16::from_le_bytes([payload[4],payload[5]]),flags:payload[6],name:parse_null_terminated_string(&payload[7..])})
}

fn parse_block32(payload: &[u8]) -> SymbolRecord {
    if payload.len()<10 { return SymbolRecord::Unknown{kind:symbol_kind::S_BLOCK32}; }
    SymbolRecord::BlockStart{parent_offset:le_u32_at(payload,0),end_offset:le_u32_at(payload,4),segment:u16::from_le_bytes([payload[8],payload[9]]),name:parse_null_terminated_string(&payload[10..])}
}

fn parse_with32(payload: &[u8]) -> SymbolRecord {
    if payload.len()<10 { return SymbolRecord::Unknown{kind:symbol_kind::S_WITH32}; }
    SymbolRecord::WithStart{parent_offset:le_u32_at(payload,0),end_offset:le_u32_at(payload,4),segment:u16::from_le_bytes([payload[8],payload[9]]),expression:parse_null_terminated_string(&payload[10..])}
}

fn parse_register_symbol(payload: &[u8]) -> SymbolRecord {
    if payload.len()<6 { return SymbolRecord::Unknown{kind:symbol_kind::S_REGISTER}; }
    SymbolRecord::RegisterVariable(RegSymbol{type_index:le_u32_at(payload,0),register:u16::from_le_bytes([payload[4],payload[5]]),name:parse_null_terminated_string(&payload[6..])})
}

fn parse_regrel_symbol(payload: &[u8]) -> SymbolRecord {
    if payload.len()<10 { return SymbolRecord::Unknown{kind:symbol_kind::S_REGREL32}; }
    SymbolRecord::RegisterRelativeVariable(RegRelSymbol{type_index:le_u32_at(payload,4),offset:i32::from_le_bytes([payload[0],payload[1],payload[2],payload[3]]),register:u16::from_le_bytes([payload[8],payload[9]]),name:parse_null_terminated_string(&payload[10..])})
}

fn parse_bprel_symbol(payload: &[u8]) -> SymbolRecord {
    if payload.len()<8 { return SymbolRecord::Unknown{kind:symbol_kind::S_BPREL32}; }
    SymbolRecord::BasePointerRelativeVariable(BpRelSymbol{type_index:le_u32_at(payload,4),offset:i32::from_le_bytes([payload[0],payload[1],payload[2],payload[3]]),name:parse_null_terminated_string(&payload[8..])})
}

fn parse_constant_symbol(payload: &[u8]) -> SymbolRecord {
    if payload.len()<6 { return SymbolRecord::Unknown{kind:symbol_kind::S_CONSTANT}; }
    let ti = le_u32_at(payload,0);
    let (val, ns) = parse_numeric(payload,4);
    SymbolRecord::Constant(ConstantSymbol{type_index:ti,value:val,name:parse_null_terminated_string(&payload[ns..])})
}

fn parse_udt_symbol(payload: &[u8]) -> SymbolRecord {
    if payload.len()<4 { return SymbolRecord::Unknown{kind:symbol_kind::S_UDT}; }
    SymbolRecord::UserDefinedType(UdtSymbol{type_index:le_u32_at(payload,0),name:parse_null_terminated_string(&payload[4..])})
}

fn parse_thread_symbol(payload: &[u8], kind: u16) -> SymbolRecord {
    if payload.len()<10 { return SymbolRecord::Unknown{kind}; }
    SymbolRecord::ThreadStorage(ThreadSymbol{type_index:le_u32_at(payload,0),offset:le_u32_at(payload,4),segment:u16::from_le_bytes([payload[8],payload[9]]),name:parse_null_terminated_string(&payload[10..])})
}

fn parse_compile3(payload: &[u8]) -> SymbolRecord {
    if payload.len()<18 { return SymbolRecord::Unknown{kind:symbol_kind::S_COMPILE3}; }
    SymbolRecord::CompileInfo(CompileInfo{flags:le_u32_at(payload,0),machine:u16::from_le_bytes([payload[4],payload[5]]),frontend_major:u16::from_le_bytes([payload[6],payload[7]]),frontend_minor:u16::from_le_bytes([payload[8],payload[9]]),frontend_build:u16::from_le_bytes([payload[10],payload[11]]),backend_major:u16::from_le_bytes([payload[12],payload[13]]),backend_minor:u16::from_le_bytes([payload[14],payload[15]]),backend_build:u16::from_le_bytes([payload[16],payload[17]]),version_string:if payload.len()>18{parse_null_terminated_string(&payload[18..])}else{String::new()}})
}

fn parse_objname(payload: &[u8]) -> SymbolRecord {
    if payload.len()<4 { return SymbolRecord::Unknown{kind:symbol_kind::S_OBJNAME}; }
    SymbolRecord::ObjectName{signature:le_u32_at(payload,0),name:parse_null_terminated_string(&payload[4..])}
}

fn parse_frameproc(payload: &[u8]) -> SymbolRecord {
    if payload.len()<28 { return SymbolRecord::Unknown{kind:symbol_kind::S_FRAMEPROC}; }
    SymbolRecord::FrameProc(FrameProcInfo{frame_size:le_u32_at(payload,0),padding_size:le_u32_at(payload,4),padding_offset:le_u32_at(payload,8),callee_saved_reg_size:le_u32_at(payload,12),exception_handler_offset:le_u32_at(payload,16),exception_handler_section:u16::from_le_bytes([payload[20],payload[21]]),flags:le_u32_at(payload,22)})
}

fn parse_thunk(payload: &[u8]) -> SymbolRecord {
    if payload.len()<21 { return SymbolRecord::Unknown{kind:symbol_kind::S_THUNK32}; }
    let nm = parse_null_terminated_string(&payload[21..]);
    let nlen = nm.len();
    SymbolRecord::Thunk(ThunkSymbol{parent_offset:le_u32_at(payload,0),end_offset:le_u32_at(payload,4),next_offset:le_u32_at(payload,8),offset:le_u32_at(payload,12),segment:u16::from_le_bytes([payload[16],payload[17]]),length:u16::from_le_bytes([payload[18],payload[19]]),thunk_type:payload[20],name:nm,variant_offset:le_u32_at(payload,21+nlen+1)})
}

fn parse_procref(payload: &[u8]) -> SymbolRecord {
    if payload.len()<10 { return SymbolRecord::Unknown{kind:symbol_kind::S_PROCREF}; }
    // V2 format: sum_name(u32) + sym_offset(u32) + module_index(u16) + name(NT)
    // Detect V2 by checking if the first bytes look like a checksum (not a printable name char)
    let is_v2 = payload.len() >= 10 && payload[0] != 0 && !payload[0].is_ascii_graphic() && payload[0] != b'_';
    if is_v2 {
        let sum_name = le_u32_at(payload, 0);
        let _sym_offset = le_u32_at(payload, 4);
        let module_index = u16::from_le_bytes([payload[8], payload[9]]);
        let nm = if payload.len() > 10 { parse_null_terminated_string(&payload[10..]) } else { String::new() };
        SymbolRecord::ProcedureReference{name:nm,module_index,type_index:sum_name}
    } else {
        // Name-first (St) format: name(NT) + module_index(u16) + padding(u16) + type_index(u32)
        let nm = parse_null_terminated_string(payload);
        let an = nm.len()+1;
        let aligned = (an + 3) & !3;
        SymbolRecord::ProcedureReference{name:nm,module_index:if aligned+2<=payload.len(){u16::from_le_bytes([payload[aligned],payload[aligned+1]])}else{0},type_index:if aligned+6<=payload.len(){le_u32_at(payload,aligned+2)}else{0}}
    }
}

fn parse_dataref(payload: &[u8]) -> SymbolRecord {
    if payload.len()<10 { return SymbolRecord::Unknown{kind:symbol_kind::S_DATAREF}; }
    // V2 format: sum_name(u32) + sym_offset(u32) + module_index(u16) + name(NT)
    let is_v2 = payload.len() >= 10 && payload[0] != 0 && !payload[0].is_ascii_graphic() && payload[0] != b'_';
    if is_v2 {
        let sum_name = le_u32_at(payload, 0);
        let _sym_offset = le_u32_at(payload, 4);
        let module_index = u16::from_le_bytes([payload[8], payload[9]]);
        let nm = if payload.len() > 10 { parse_null_terminated_string(&payload[10..]) } else { String::new() };
        SymbolRecord::DataReference{name:nm,module_index,type_index:sum_name}
    } else {
        // Name-first (St) format: name(NT) + module_index(u16) + padding(u16) + type_index(u32)
        let nm = parse_null_terminated_string(payload);
        let an = nm.len()+1;
        let aligned = (an + 3) & !3;
        SymbolRecord::DataReference{name:nm,module_index:if aligned+2<=payload.len(){u16::from_le_bytes([payload[aligned],payload[aligned+1]])}else{0},type_index:if aligned+6<=payload.len(){le_u32_at(payload,aligned+2)}else{0}}
    }
}

fn parse_annotation(payload: &[u8]) -> SymbolRecord {
    if payload.len()<8 { return SymbolRecord::Unknown{kind:symbol_kind::S_ANNOTATION}; }
    let off = le_u32_at(payload,0);
    let seg = u16::from_le_bytes([payload[4],payload[5]]);
    let count = u16::from_le_bytes([payload[6],payload[7]]) as usize;
    let mut strings = Vec::new(); let mut pos=8;
    for _ in 0..count {
        if pos+2>payload.len(){break;}
        let len = u16::from_le_bytes([payload[pos],payload[pos+1]]) as usize; pos+=2;
        if len==0||pos+len>payload.len(){break;}
        strings.push(String::from_utf8_lossy(&payload[pos..pos+len]).to_string()); pos+=len;
    }
    SymbolRecord::Annotation{offset:off,segment:seg,count:count as u16,strings}
}

fn parse_annotationref(payload: &[u8]) -> SymbolRecord {
    // V2 format: sum_name(u32) + sym_offset(u32) + module_index(u16) + name(NT)
    if payload.len()<10 { return SymbolRecord::Unknown{kind:symbol_kind::S_ANNOTATIONREF}; }
    let sum_name = le_u32_at(payload,0);
    let offset_actual_symbol = le_u32_at(payload,4);
    let module_index = u16::from_le_bytes([payload[8],payload[9]]);
    let name = if payload.len()>10 { parse_null_terminated_string(&payload[10..]) } else { String::new() };
    SymbolRecord::AnnotationReference{name,module_index,sum_name,offset_actual_symbol}
}

fn parse_trampoline(payload: &[u8]) -> SymbolRecord {
    if payload.len()<16 { return SymbolRecord::Unknown{kind:symbol_kind::S_TRAMPOLINE}; }
    SymbolRecord::Trampoline{trampoline_type:u16::from_le_bytes([payload[0],payload[1]]),size:u16::from_le_bytes([payload[2],payload[3]]),thunk_offset:le_u32_at(payload,4),target_offset:le_u32_at(payload,8),thunk_section:u16::from_le_bytes([payload[12],payload[13]]),target_section:u16::from_le_bytes([payload[14],payload[15]])}
}

fn parse_section_sym(payload: &[u8]) -> SymbolRecord {
    if payload.len()<16 { return SymbolRecord::Unknown{kind:symbol_kind::S_SECTION}; }
    SymbolRecord::Section{section_number:u16::from_le_bytes([payload[0],payload[1]]),alignment:payload[2],rva:le_u32_at(payload,4),size:le_u32_at(payload,8),characteristics:le_u32_at(payload,12),name:parse_null_terminated_string(&payload[16..])}
}

fn parse_coffgroup(kind: u16, payload: &[u8]) -> SymbolRecord {
    if payload.len()<14 { return SymbolRecord::Unknown{kind}; }
    let size = le_u32_at(payload,0);
    let characteristics = le_u32_at(payload,4);
    let offset = le_u32_at(payload,8);
    let segment = u16::from_le_bytes([payload[12],payload[13]]);
    let name = parse_null_terminated_string(&payload[14..]);
    if kind == symbol_kind::S_PE_COFFGROUP {
        SymbolRecord::PeCoffGroup{length:size,characteristics,offset,segment,name}
    } else {
        SymbolRecord::CoffGroup{size,characteristics,offset,segment,name}
    }
}

fn parse_sepcode(payload: &[u8]) -> SymbolRecord {
    if payload.len()<20 { return SymbolRecord::Unknown{kind:symbol_kind::S_SEPCODE}; }
    SymbolRecord::SeparatedCode{parent_offset:le_u32_at(payload,0),end_offset:le_u32_at(payload,4),length:le_u32_at(payload,8),separated_code_segment:u16::from_le_bytes([payload[12],payload[13]]),separated_code_offset:le_u32_at(payload,14),parent_segment:u16::from_le_bytes([payload[18],payload[19]])}
}

fn parse_buildinfo_sym(payload: &[u8]) -> SymbolRecord {
    if payload.len()<4 { return SymbolRecord::Unknown{kind:symbol_kind::S_BUILDINFO}; }
    SymbolRecord::BuildInfo{item_id:le_u32_at(payload,0)}
}

fn parse_inlinesite(payload: &[u8]) -> SymbolRecord {
    if payload.len()<12 { return SymbolRecord::Unknown{kind:symbol_kind::S_INLINESITE}; }
    SymbolRecord::InlineSite{parent_offset:le_u32_at(payload,0),end_offset:le_u32_at(payload,4),inlinee_type_index:le_u32_at(payload,8),annotations:payload[12..].to_vec()}
}

fn parse_callsite(payload: &[u8]) -> SymbolRecord {
    if payload.len()<12 { return SymbolRecord::Unknown{kind:symbol_kind::S_CALLSITEINFO}; }
    SymbolRecord::CallSiteInfo{offset:le_u32_at(payload,0),section:u16::from_le_bytes([payload[4],payload[5]]),type_index:le_u32_at(payload,8)}
}

fn parse_compile_v1(payload: &[u8]) -> SymbolRecord {
    if payload.len() < 6 { return SymbolRecord::Unknown{kind: symbol_kind::S_COMPILE}; }
    let flags = le_u32_at(payload, 0);
    let machine = u16::from_le_bytes([payload[4], payload[5]]);
    let version_string = if payload.len() > 6 { parse_null_terminated_string(&payload[6..]) } else { String::new() };
    SymbolRecord::CompileInfo(CompileInfo{flags, machine, frontend_major: 0, frontend_minor: 0, frontend_build: 0, backend_major: 0, backend_minor: 0, backend_build: 0, version_string})
}

fn parse_return_symbol(payload: &[u8]) -> SymbolRecord {
    if payload.len() < 4 { return SymbolRecord::Unknown{kind: symbol_kind::S_RETURN}; }
    let flags = le_u32_at(payload, 0);
    let reg = if payload.len() >= 6 { u16::from_le_bytes([payload[4], payload[5]]) } else { 0 };
    SymbolRecord::Return{flags, return_value_register: reg}
}

fn parse_entry_this(payload: &[u8]) -> SymbolRecord {
    if payload.len() < 3 { return SymbolRecord::Unknown{kind: symbol_kind::S_ENTRYTHIS}; }
    let flags = payload[0];
    let reg = u16::from_le_bytes([payload[1], payload[2]]);
    SymbolRecord::EntryThis{flags, this_register: reg}
}

fn parse_vftable_symbol(payload: &[u8]) -> SymbolRecord {
    if payload.len() < 4 { return SymbolRecord::Unknown{kind: symbol_kind::S_VFTABLE32}; }
    let ti = le_u32_at(payload, 0);
    let (off, seg) = if payload.len() >= 10 {
        (le_u32_at(payload, 4), u16::from_le_bytes([payload[8], payload[9]]))
    } else { (0, 0) };
    let name_start = if payload.len() >= 10 { 10 } else { 4 };
    let name = if name_start < payload.len() { parse_null_terminated_string(&payload[name_start..]) } else { String::new() };
    SymbolRecord::VfTable{type_index: ti, offset: off, segment: seg, name}
}

fn parse_export_symbol(payload: &[u8]) -> SymbolRecord {
    if payload.len() < 6 { return SymbolRecord::Unknown{kind: symbol_kind::S_EXPORT}; }
    let ordinal = u16::from_le_bytes([payload[0], payload[1]]);
    let flags = u16::from_le_bytes([payload[2], payload[3]]);
    let name = parse_null_terminated_string(&payload[4..]);
    SymbolRecord::Export{ordinal, flags, name}
}

fn parse_frame_cookie(payload: &[u8]) -> SymbolRecord {
    if payload.len() < 6 { return SymbolRecord::Unknown{kind: symbol_kind::S_FRAMECOOKIE}; }
    let offset = le_u32_at(payload, 0);
    let register = u16::from_le_bytes([payload[4], payload[5]]);
    let cookie_type = if payload.len() > 6 { payload[6] } else { 0 };
    SymbolRecord::FrameCookie{offset, register, cookie_type}
}

fn parse_envblock(payload: &[u8]) -> SymbolRecord {
    let mut fields = Vec::new();
    let mut pos = 1usize; // skip flags byte
    while pos < payload.len() {
        let (key, k1) = read_null_terminated_string(payload, pos);
        if key.is_empty() { break; }
        let (val, k2) = read_null_terminated_string(payload, k1);
        fields.push((key, val));
        pos = k2;
    }
    SymbolRecord::EnvironmentBlock{fields}
}

fn parse_local_v2(payload: &[u8]) -> SymbolRecord {
    if payload.len() < 6 { return SymbolRecord::Unknown{kind: symbol_kind::S_LOCAL_V2}; }
    let ti = le_u32_at(payload, 0);
    let flags = u16::from_le_bytes([payload[4], payload[5]]);
    let name = parse_null_terminated_string(&payload[6..]);
    SymbolRecord::LocalV2{type_index: ti, flags, name}
}

fn parse_defrange_register(payload: &[u8]) -> SymbolRecord {
    if payload.len() < 10 { return SymbolRecord::Unknown{kind: symbol_kind::S_DEFRANGE_REGISTER}; }
    let register = u16::from_le_bytes([payload[0], payload[1]]);
    let offset_parent = i32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]);
    let range_offset = u16::from_le_bytes([payload[8], payload[9]]);
    let range_length = if payload.len() >= 12 { u16::from_le_bytes([payload[10], payload[11]]) } else { 0 };
    SymbolRecord::DefRangeRegister{register, offset_parent, range_offset, range_length}
}

fn parse_defrange_framepointer_rel(payload: &[u8]) -> SymbolRecord {
    if payload.len() < 8 { return SymbolRecord::Unknown{kind: symbol_kind::S_DEFRANGE_FRAMEPOINTER_REL}; }
    let frame_offset = i32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
    let range_offset = u16::from_le_bytes([payload[4], payload[5]]);
    let range_length = u16::from_le_bytes([payload[6], payload[7]]);
    SymbolRecord::DefRangeFrameRel{frame_offset, range_offset, range_length}
}

fn parse_defrange_subfield_register(payload: &[u8]) -> SymbolRecord {
    if payload.len() < 14 { return SymbolRecord::Unknown{kind: symbol_kind::S_DEFRANGE_SUBFIELD_REGISTER}; }
    let register = u16::from_le_bytes([payload[0], payload[1]]);
    let offset_parent = i32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]);
    let offset_in_parent = le_u32_at(payload, 8);
    let range_offset = u16::from_le_bytes([payload[12], payload[13]]);
    let range_length = if payload.len() >= 16 { u16::from_le_bytes([payload[14], payload[15]]) } else { 0 };
    SymbolRecord::DefRangeSubfieldRegister{register, offset_parent, offset_in_parent, range_offset, range_length}
}

fn parse_defrange_register_rel(payload: &[u8]) -> SymbolRecord {
    if payload.len() < 12 { return SymbolRecord::Unknown{kind: symbol_kind::S_DEFRANGE_REGISTER_REL}; }
    let register = u16::from_le_bytes([payload[0], payload[1]]);
    let flags = u16::from_le_bytes([payload[2], payload[3]]);
    let offset = i32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]);
    let range_offset = u16::from_le_bytes([payload[8], payload[9]]);
    let range_length = if payload.len() >= 12 { u16::from_le_bytes([payload[10], payload[11]]) } else { 0 };
    SymbolRecord::DefRangeRegisterRel{register, flags, offset, range_offset, range_length}
}

fn parse_slot_symbol(payload: &[u8], is_local: bool) -> SymbolRecord {
    if payload.len() < 6 { return SymbolRecord::Unknown{kind: if is_local { symbol_kind::S_LOCALSLOT } else { symbol_kind::S_PARAMSLOT }}; }
    let ti = le_u32_at(payload, 0);
    let slot = u16::from_le_bytes([payload[4], payload[5]]);
    let name = if payload.len() > 6 { parse_null_terminated_string(&payload[6..]) } else { String::new() };
    if is_local { SymbolRecord::LocalSlot{type_index: ti, slot, name} }
    else { SymbolRecord::ParamSlot{type_index: ti, slot, name} }
}

fn parse_proc_id_symbol(kind: u16, payload: &[u8]) -> SymbolRecord {
    if payload.len() < 17 { return SymbolRecord::Unknown{kind}; }
    let sym = ProcSymbol{type_index:le_u32_at(payload,0),debug_start:le_u32_at(payload,4),debug_end:le_u32_at(payload,8),offset:le_u32_at(payload,12),segment:u16::from_le_bytes([payload[16],payload[17]]),flags:if payload.len()>18{payload[18]}else{0},name:parse_null_terminated_string(&payload[19..])};
    match kind { symbol_kind::S_GPROC32_ID => SymbolRecord::GProc32Id(sym), _ => SymbolRecord::LProc32Id(sym) }
}

fn parse_many_register(payload: &[u8]) -> SymbolRecord {
    if payload.len() < 5 { return SymbolRecord::Unknown{kind: symbol_kind::S_MANYREG2}; }
    let ti = u16::from_le_bytes([payload[0], payload[1]]);
    let count = payload[2];
    let mut regs = Vec::with_capacity(count as usize);
    for i in 0..count as usize {
        let off = 3 + i * 2;
        if off + 2 <= payload.len() {
            regs.push(u16::from_le_bytes([payload[off], payload[off+1]]));
        }
    }
    let name_off = 3 + count as usize * 2;
    let name = if name_off < payload.len() { parse_null_terminated_string(&payload[name_off..]) } else { String::new() };
    SymbolRecord::ManyRegister{type_index: ti, count, registers: regs, name}
}


// =============================================================================
// Symbol stream iteration
// =============================================================================

/// Iterator over symbol records within a symbol stream.
///
/// Symbol streams contain records with a 2-byte length prefix followed by
/// the symbol data. The total length (including the 2-byte prefix) must be
/// a multiple of 4 (32-bit aligned).
pub struct SymbolStream<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> SymbolStream<'a> {
    /// Create a new symbol stream iterator from raw symbol data.
    pub fn new(data: &'a [u8]) -> Self {
        SymbolStream { data, pos: 0 }
    }
}

impl<'a> Iterator for SymbolStream<'a> {
    type Item = SymbolRecord;

    fn next(&mut self) -> Option<Self::Item> {
        while self.pos + 4 <= self.data.len() {
            let record_len = u16::from_le_bytes([self.data[self.pos], self.data[self.pos+1]]) as usize;
            if record_len < 2 || self.pos + record_len > self.data.len() {
                self.pos = self.data.len();
                return None;
            }
            let record_data = &self.data[self.pos..self.pos + record_len];
            self.pos += record_len;
            // Align to 4 bytes
            while self.pos < self.data.len() && self.pos % 4 != 0 {
                self.pos += 1;
            }
            let sym = parse_symbol_record(record_data)?;
            return Some(sym);
        }
        None
    }
}

// =============================================================================
// DBI Header flag constants
// =============================================================================

/// DBI stream header flags.
pub mod dbi_flags {
    /// Was the PDB built incrementally?
    pub const INCREMENTALLY_LINKED: u16 = 0x0001;
    /// Are CTypes present?
    pub const HAS_CTYPES: u16 = 0x0002;
    /// Is private symbol data stripped?
    pub const STRIPPED_PRIVATE_SYMBOLS: u16 = 0x0004;
    /// Is conflicting types information present?
    pub const HAS_CONFLICTING_TYPES: u16 = 0x0008;
}

/// Common machine types used in the DBI header.
pub mod machine_type {
    pub const X86: u16 = 0x014C;
    pub const ARM: u16 = 0x01C0;
    pub const IA64: u16 = 0x0200;
    pub const AMD64: u16 = 0x8664;
    pub const ARM64: u16 = 0xAA64;
    pub const ARMNT: u16 = 0x01C4;
    pub const THUMB: u16 = 0x01C2;
    pub const POWERPC: u16 = 0x01F0;
    pub const MIPS: u16 = 0x0166;
    pub const SH3: u16 = 0x01A2;
    pub const SH4: u16 = 0x01A6;
    pub const EBC: u16 = 0x0EBC;

    /// Get the human-readable name for a machine type.
    pub fn name(machine: u16) -> &'static str {
        match machine {
            X86 => "x86",
            ARM => "ARM",
            IA64 => "IA-64 (Itanium)",
            AMD64 => "x64 (AMD64)",
            ARM64 => "AArch64 (ARM64)",
            ARMNT => "ARM NT",
            THUMB => "Thumb",
            POWERPC => "PowerPC",
            MIPS => "MIPS",
            SH3 => "SuperH SH3",
            SH4 => "SuperH SH4",
            EBC => "EFI Byte Code",
            _ => "Unknown",
        }
    }
}

// =============================================================================
// Public symbol flags
// =============================================================================

/// Public symbol record flags.
pub mod public_sym_flags {
    pub const CODE: u32 = 0x0001;
    pub const FUNCTION: u32 = 0x0002;
    pub const MANAGED_CODE: u32 = 0x0004;
    pub const MSIL: u32 = 0x0008;
}

// =============================================================================
// Procedure flags
// =============================================================================

/// Procedure (function) symbol record flags.
pub mod proc_flags {
    pub const NO_FPO: u8 = 0x01;
    pub const INT_RETURN: u8 = 0x02;
    pub const FAR_RETURN: u8 = 0x04;
    pub const NEVER_RETURN: u8 = 0x08;
    pub const NOTREACHED: u8 = 0x10;
    pub const CUSTOM_CALL: u8 = 0x20;
    pub const NO_INLINE: u8 = 0x40;
    pub const OPTCALLER: u8 = 0x80;
}

// =============================================================================
// PDB compile flags (S_COMPILE3)
// =============================================================================

/// Language flags from the S_COMPILE3 record.
pub mod cv_language {
    pub const C: u8 = 0x00;
    pub const CPP: u8 = 0x01;
    pub const FORTRAN: u8 = 0x02;
    pub const MASM: u8 = 0x03;
    pub const PASCAL: u8 = 0x04;
    pub const BASIC: u8 = 0x05;
    pub const COBOL: u8 = 0x06;
    pub const LINK: u8 = 0x07;
    pub const CVTRES: u8 = 0x08;
    pub const CVTPGD: u8 = 0x09;
    pub const CSHARP: u8 = 0x0A;
    pub const VISUAL_BASIC: u8 = 0x0B;
    pub const ILASM: u8 = 0x0C;
    pub const JAVA: u8 = 0x0D;
    pub const JSCRIPT: u8 = 0x0E;
    pub const MSIL: u8 = 0x0F;
    pub const HLSL: u8 = 0x10;
    pub const RUST: u8 = 0x11;
    pub const SWIFT: u8 = 0x12;
    pub const GO: u8 = 0x13;
    pub const D: u8 = 0x14;
}

/// Thunk type ordinals from S_THUNK32.
pub mod thunk_type {
    pub const STANDARD: u8 = 0;
    pub const THISCALL: u8 = 1;
    pub const NOTHISCALL: u8 = 2;
    pub const STDCALL: u8 = 3;
    pub const PASCAL: u8 = 4;
    pub const CDECL: u8 = 5;
    pub const FASTCALL: u8 = 6;
    pub const NOTHISCALL_THIS: u8 = 7;
}

// =============================================================================
// PdbFile — convenient single-file API
// =============================================================================

/// Holds a fully parsed PDB, combining the MSF container and all standard
/// streams (Info, TPI, DBI, IPI).
#[derive(Debug, Clone)]
pub struct PdbFile {
    pub msf: MsfFile,
    pub info: Option<PdbInfoStream>,
    pub tpi: Option<TpiStream>,
    pub dbi: Option<DbiStream>,
    pub ipi: Option<IpiStream>,
    pub global_symbol_stream: Option<Vec<u8>>,
    pub public_symbol_stream: Option<Vec<u8>>,
}

impl PdbFile {
    /// Open and parse a PDB file from disk.
    pub fn open(path: impl AsRef<std::path::Path>) -> Result<Self, Box<dyn std::error::Error>> {
        let data = std::fs::read(path.as_ref())?;
        Self::parse(&data)
    }

    /// Parse an in-memory PDB file.
    pub fn parse(data: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        let msf = parse_msf(data)?;

        let info = msf.read_stream(1)
            .and_then(|d| parse_pdb_info_stream(&d).ok());

        let tpi = msf.read_stream(2)
            .and_then(|d| parse_tpi_stream(&d).ok());

        let ipi = msf.read_stream(4)
            .and_then(|d| parse_ipi_stream(&d).ok());

        let dbi_raw = msf.read_stream(3);
        let (dbi, global_stream, public_stream) = if let Some(ref db) = dbi_raw {
            let d = parse_dbi_stream(db).ok();
            let gs = d.as_ref().and_then(|dbi| msf.read_stream(dbi.gsi as u32));
            let ps = d.as_ref().and_then(|dbi| msf.read_stream(dbi.psi as u32));
            (d, gs, ps)
        } else {
            (None, None, None)
        };

        Ok(PdbFile { msf, info, tpi, dbi, ipi, global_symbol_stream: global_stream, public_symbol_stream: public_stream })
    }

    /// Return an iterator over all global symbols.
    pub fn global_symbols(&self) -> Option<impl Iterator<Item = SymbolRecord> + '_> {
        self.global_symbol_stream.as_ref().map(|d| SymbolStream::new(d))
    }

    /// Return an iterator over all public symbols.
    pub fn public_symbols(&self) -> Option<impl Iterator<Item = SymbolRecord> + '_> {
        self.public_symbol_stream.as_ref().map(|d| SymbolStream::new(d))
    }

    /// Look up a type record by its type index. Searches TPI first, then IPI.
    pub fn get_type(&self, type_index: u32) -> Option<&TypeRecord> {
        if let Some(ref tpi) = self.tpi {
            if let Some(rec) = tpi.types.get(type_index as usize) {
                return Some(rec);
            }
        }
        if let Some(ref ipi) = self.ipi {
            if let Some(rec) = ipi.items.get(type_index as usize) {
                return Some(rec);
            }
        }
        None
    }

    /// Iterate function definitions (S_GPROC32 records) in the PDB.
    /// Returns a list of (function_name, address_rva).
    pub fn iterate_functions(&self) -> Result<Vec<(String, u32)>, &'static str> {
        let gs_data = self.global_symbol_stream.as_ref().ok_or("no global symbol stream")?;
        let symbols = SymbolStream::new(gs_data);
        let mut funcs = Vec::new();
        for sym in symbols {
            match sym {
                SymbolRecord::GlobalProcedure(ps) => {
                    funcs.push((ps.name, ps.offset));
                }
                _ => {}
            }
        }
        Ok(funcs)
    }

    /// Iterate public symbols.
    pub fn iterate_publics(&self) -> Result<Vec<(String, u32, u16)>, &'static str> {
        let ps_data = self.public_symbol_stream.as_ref().ok_or("no public symbol stream")?;
        let symbols = SymbolStream::new(ps_data);
        let mut pubs = Vec::new();
        for sym in symbols {
            match sym {
                SymbolRecord::Public(ps) => {
                    pubs.push((ps.name, ps.offset, ps.segment));
                }
                _ => {}
            }
        }
        Ok(pubs)
    }

    /// Collect all module information from the DBI stream.
    pub fn modules(&self) -> Vec<&ModuleInfo> {
        self.dbi.as_ref().map(|d| d.modules.iter().collect()).unwrap_or_default()
    }

    /// Collect all section contributions from the DBI stream.
    pub fn section_contributions(&self) -> Vec<&SectionContrib> {
        self.dbi.as_ref().map(|d| d.sections.iter().collect()).unwrap_or_default()
    }

    /// Collect all section map entries from the DBI stream.
    pub fn section_map_entries(&self) -> Vec<&SectionMapEntry> {
        self.dbi.as_ref().map(|d| d.section_map.iter().collect()).unwrap_or_default()
    }

    /// Collect all type server entries from the DBI stream.
    pub fn type_server_entries(&self) -> Vec<&TypeServerEntry> {
        self.dbi.as_ref().map(|d| d.type_servers.iter().collect()).unwrap_or_default()
    }

    /// Get the number of type records in the TPI stream.
    pub fn type_count(&self) -> usize {
        self.tpi.as_ref().map(|t| t.types.len()).unwrap_or(0)
    }

    /// Check if this PDB has debug information.
    pub fn has_dbi(&self) -> bool {
        self.dbi.is_some()
    }

    /// Get the PDB GUID as a hex string.
    pub fn guid_string(&self) -> Option<String> {
        self.info.as_ref().map(|i| {
            format!(
                "{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
                u32::from_le_bytes([i.guid[0],i.guid[1],i.guid[2],i.guid[3]]),
                u16::from_le_bytes([i.guid[4],i.guid[5]]),
                u16::from_le_bytes([i.guid[6],i.guid[7]]),
                i.guid[8], i.guid[9],
                i.guid[10],i.guid[11],i.guid[12],i.guid[13],i.guid[14],i.guid[15],
            )
        })
    }

    /// Get the PDB age (incremented on each build).
    pub fn age(&self) -> Option<u32> {
        self.info.as_ref().map(|i| i.age)
    }

    /// Get the PDB signature (time-date stamp).
    pub fn signature(&self) -> Option<u32> {
        self.info.as_ref().map(|i| i.signature)
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_msf_magic_detection() {
        // Build a minimal v700 MSF header.
        let mut data = Vec::new();
        data.extend_from_slice(MSF_700_MAGIC);
        data.extend_from_slice(&[0u8; 3]); // padding
        let block_size: u32 = 0x1000;
        data.extend_from_slice(&block_size.to_le_bytes());
        // free page map = 1
        data.extend_from_slice(&1u32.to_le_bytes());
        // num pages = 2
        data.extend_from_slice(&2u32.to_le_bytes());
        // num directory bytes = 0
        data.extend_from_slice(&0u32.to_le_bytes());
        // directory stream info: length=0, map=0
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());

        // Padded to full block sizes
        data.resize(2 * 0x1000, 0);

        let msf = parse_msf(&data);
        assert!(msf.is_ok());
        let msf = msf.unwrap();
        assert_eq!(msf.block_size, 0x1000);
    }

    #[test]
    fn test_parse_numeric_small() {
        let data = [0x2Au8, 0x00]; // 42
        let (val, offset) = parse_numeric(&data, 0);
        assert_eq!(val, 42);
        assert_eq!(offset, 2);
    }

    #[test]
    fn test_parse_numeric_u32() {
        let data = [0x00u8, 0x80, 0x02, 0x78, 0x56, 0x34, 0x12]; // 0x12345678
        let (val, offset) = parse_numeric(&data, 0);
        assert_eq!(val, 0x12345678);
        assert_eq!(offset, 7);
    }

    #[test]
    fn test_simple_type_resolution() {
        let st = resolve_simple_type(0x0002); // mode=0, kind=2 = NotTranslated
        assert!(st.is_simple);
        assert_eq!(st.kind, SimpleTypeKind::NotTranslated);
        assert_eq!(st.mode, SimpleTypeMode::Direct);
        assert!(!st.is_pointer());

        let st2 = resolve_simple_type(0x040A); // mode=4 (NearPointer32), kind=0A (Int32)
        assert!(st2.is_simple);
        assert_eq!(st2.kind, SimpleTypeKind::Int32);
        assert_eq!(st2.mode, SimpleTypeMode::NearPointer32);
        assert!(st2.is_pointer());
    }

    #[test]
    fn test_type_parsing() {
        // Minimal LF_CLASS record: count(2)+prop(2)+field_list(4)+derived(4)+vshape(4)+size(2)+name("A\0")
        let mut data = Vec::new();
        data.extend_from_slice(&3u16.to_le_bytes()); // count=3
        data.extend_from_slice(&0u16.to_le_bytes()); // property=0
        data.extend_from_slice(&0x1000u32.to_le_bytes()); // field_list
        data.extend_from_slice(&0u32.to_le_bytes()); // derived
        data.extend_from_slice(&0u32.to_le_bytes()); // vshape
        data.extend_from_slice(&10u16.to_le_bytes()); // size=10 (simple numeric)
        data.push(b'A');
        data.push(0u8); // null terminator
        data.push(0xF4u8); // end marker
        data.push(0u8);
        data.push(0u8);

        let mut record = Vec::new();
        record.extend_from_slice(&leaf_id::LF_CLASS.to_le_bytes());
        record.extend_from_slice(&data);

        let result = parse_type_record(&record);
        assert!(result.is_some());
        if let Some(TypeRecord::Class(cls)) = result {
            assert_eq!(cls.count, 3);
            assert_eq!(cls.name, "A");
            assert_eq!(cls.size, 10);
        } else {
            panic!("Expected Class type record");
        }
    }

    #[test]
    fn test_pointer_type_parsing() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&0x1022u32.to_le_bytes()); // underlying_type_index
        payload.extend_from_slice(&0x040Cu32.to_le_bytes()); // attributes: ptrkind=12, mode=0, is_const(bit10)=1
        payload.extend_from_slice(&0u32.to_le_bytes()); // padding

        let mut record = Vec::new();
        record.extend_from_slice(&leaf_id::LF_POINTER.to_le_bytes());
        record.extend_from_slice(&payload);

        let result = parse_type_record(&record);
        assert!(result.is_some());
        if let Some(TypeRecord::Pointer(ptr)) = result {
            assert_eq!(ptr.underlying_type_index, 0x1022);
            assert_eq!(ptr.pointer_mode, PointerMode::Pointer);
            assert_eq!(ptr.pointer_kind, PointerKind::Flat32);
            assert!(ptr.is_const);
        } else {
            panic!("Expected Pointer type record");
        }
    }

    #[test]
    fn test_modifier_type_parsing() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&0x1000u32.to_le_bytes()); // modified_type_index
        payload.extend_from_slice(&1u16.to_le_bytes()); // const modifier

        let mut record = Vec::new();
        record.extend_from_slice(&leaf_id::LF_MODIFIER.to_le_bytes());
        record.extend_from_slice(&payload);

        let result = parse_type_record(&record);
        assert!(result.is_some());
        if let Some(TypeRecord::Modifier(m)) = result {
            assert_eq!(m.modified_type_index, 0x1000);
            assert_eq!(m.modifiers, 1);
        } else {
            panic!("Expected Modifier type record");
        }
    }

    #[test]
    fn test_symbol_stream_iterator() {
        // Build a minimal symbol stream with one S_END record
        let mut data = Vec::new();
        data.extend_from_slice(&4u16.to_le_bytes()); // record length (includes len+kind)
        data.extend_from_slice(&symbol_kind::S_END.to_le_bytes());

        let mut stream = SymbolStream::new(&data);
        let sym = stream.next();
        assert!(sym.is_some());
        assert_eq!(sym.unwrap(), SymbolRecord::End);
    }

    #[test]
    fn test_data_symbol_parsing() {
        // S_GDATA32: type_index(4) + offset(4) + segment(2) + name("x\0")
        let mut payload = Vec::new();
        payload.extend_from_slice(&0x20u32.to_le_bytes()); // type_index
        payload.extend_from_slice(&0x1000u32.to_le_bytes()); // offset
        payload.extend_from_slice(&1u16.to_le_bytes()); // segment
        payload.push(b'x');
        payload.push(0u8);

        let (name, _) = read_null_terminated_string(&[b'x', 0, 0, 0], 0);

        let mut record_data = Vec::new();
        let total_len = 2 + 2 + payload.len() as u16; // len prefix + kind + payload
        record_data.extend_from_slice(&total_len.to_le_bytes());
        record_data.extend_from_slice(&symbol_kind::S_GDATA32.to_le_bytes());
        record_data.extend_from_slice(&payload);
        // Align to 4
        while record_data.len() % 4 != 0 { record_data.push(0); }

        let result = parse_symbol_record(&record_data);
        assert!(result.is_some());
        if let Some(SymbolRecord::GlobalData(ds)) = result {
            assert_eq!(ds.type_index, 0x20);
            assert_eq!(ds.offset, 0x1000);
            assert_eq!(ds.segment, 1);
        } else {
            panic!("Expected GlobalData symbol record");
        }
    }

    #[test]
    fn test_proc_symbol_parsing() {
        // S_GPROC32: type_index(4)+debug_start(4)+debug_end(4)+offset(4)+segment(2)+flags(1)+name("main\0")
        let mut payload = Vec::new();
        payload.extend_from_slice(&0x1000u32.to_le_bytes());
        payload.extend_from_slice(&0x100u32.to_le_bytes());
        payload.extend_from_slice(&0x200u32.to_le_bytes());
        payload.extend_from_slice(&0x1000u32.to_le_bytes());
        payload.extend_from_slice(&1u16.to_le_bytes());
        payload.push(0u8); // flags
        payload.extend_from_slice(b"main");
        payload.push(0u8);

        let mut record_data = Vec::new();
        let total_len = 2 + 2 + payload.len() as u16;
        record_data.extend_from_slice(&total_len.to_le_bytes());
        record_data.extend_from_slice(&symbol_kind::S_GPROC32.to_le_bytes());
        record_data.extend_from_slice(&payload);
        while record_data.len() % 4 != 0 { record_data.push(0); }

        let result = parse_symbol_record(&record_data);
        assert!(result.is_some());
        if let Some(SymbolRecord::GlobalProcedure(ps)) = result {
            assert_eq!(ps.offset, 0x1000);
            assert_eq!(ps.segment, 1);
        } else {
            panic!("Expected GlobalProcedure symbol record");
        }
    }

    // =====================================================================
    // Tests for new type records
    // =====================================================================

    #[test]
    fn test_procedure_type_parsing() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&0x1022u32.to_le_bytes()); // return_type
        payload.push(0x00); // calling convention = NearC
        payload.push(0); // func_attributes
        payload.extend_from_slice(&0u16.to_le_bytes()); // num_params
        payload.extend_from_slice(&0x1033u32.to_le_bytes()); // arg_list
        payload.extend_from_slice(&0u16.to_le_bytes()); // padding to reach 14 bytes

        let mut record = Vec::new();
        record.extend_from_slice(&leaf_id::LF_PROCEDURE.to_le_bytes());
        record.extend_from_slice(&payload);

        let result = parse_type_record(&record);
        assert!(result.is_some());
        if let Some(TypeRecord::Procedure(p)) = result {
            assert_eq!(p.return_type_index, 0x1022);
            assert_eq!(p.arg_list_type_index, 0x1033);
        } else {
            panic!("Expected Procedure");
        }
    }

    #[test]
    fn test_array_type_parsing() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&0x1000u32.to_le_bytes()); // element type
        payload.extend_from_slice(&0x1001u32.to_le_bytes()); // index type
        payload.extend_from_slice(&10u16.to_le_bytes()); // size = 10
        payload.extend_from_slice(b"arr\0"); // name

        let mut record = Vec::new();
        record.extend_from_slice(&leaf_id::LF_ARRAY.to_le_bytes());
        record.extend_from_slice(&payload);

        let result = parse_type_record(&record);
        assert!(result.is_some());
        if let Some(TypeRecord::Array(a)) = result {
            assert_eq!(a.element_type_index, 0x1000);
            assert_eq!(a.size, 10);
            assert_eq!(a.name, "arr");
        } else {
            panic!("Expected Array");
        }
    }

    #[test]
    fn test_enum_type_parsing() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&5u16.to_le_bytes()); // count
        payload.extend_from_slice(&0u16.to_le_bytes()); // property
        payload.extend_from_slice(&0x1000u32.to_le_bytes()); // underlying type
        payload.extend_from_slice(&0x1001u32.to_le_bytes()); // field list
        payload.extend_from_slice(b"Color\0");

        let mut record = Vec::new();
        record.extend_from_slice(&leaf_id::LF_ENUM.to_le_bytes());
        record.extend_from_slice(&payload);

        let result = parse_type_record(&record);
        assert!(result.is_some());
        if let Some(TypeRecord::Enum(e)) = result {
            assert_eq!(e.count, 5);
            assert_eq!(e.name, "Color");
            assert_eq!(e.underlying_type_index, 0x1000);
        } else {
            panic!("Expected Enum");
        }
    }

    #[test]
    fn test_vtshape_type_parsing() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&4u16.to_le_bytes()); // count
        payload.push(0x0F); // descriptors

        let mut record = Vec::new();
        record.extend_from_slice(&leaf_id::LF_VTSHAPE.to_le_bytes());
        record.extend_from_slice(&payload);

        let result = parse_type_record(&record);
        assert!(result.is_some());
        if let Some(TypeRecord::VtShape { count, .. }) = result {
            assert_eq!(count, 4);
        } else {
            panic!("Expected VtShape");
        }
    }

    #[test]
    fn test_vftpath_type_parsing() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&2u16.to_le_bytes()); // count
        payload.extend_from_slice(&0x1000u32.to_le_bytes());
        payload.extend_from_slice(&0x1001u32.to_le_bytes());

        let mut record = Vec::new();
        record.extend_from_slice(&leaf_id::LF_VFTPATH.to_le_bytes());
        record.extend_from_slice(&payload);

        let result = parse_type_record(&record);
        assert!(result.is_some());
        if let Some(TypeRecord::VftPath { count, base_classes }) = result {
            assert_eq!(count, 2);
            assert_eq!(base_classes, vec![0x1000, 0x1001]);
        } else {
            panic!("Expected VftPath");
        }
    }

    #[test]
    fn test_derived_class_list_parsing() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&3u32.to_le_bytes()); // count
        payload.extend_from_slice(&0x1000u32.to_le_bytes());
        payload.extend_from_slice(&0x1001u32.to_le_bytes());
        payload.extend_from_slice(&0x1002u32.to_le_bytes());

        let mut record = Vec::new();
        record.extend_from_slice(&leaf_id::LF_DERIVED.to_le_bytes());
        record.extend_from_slice(&payload);

        let result = parse_type_record(&record);
        assert!(result.is_some());
        if let Some(TypeRecord::DerivedClassList { count, derived_type_indices }) = result {
            assert_eq!(count, 3);
            assert_eq!(derived_type_indices.len(), 3);
        } else {
            panic!("Expected DerivedClassList");
        }
    }

    #[test]
    fn test_barray_type_parsing() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&0x1000u32.to_le_bytes()); // element type
        payload.extend_from_slice(&0x1001u32.to_le_bytes()); // index type

        let mut record = Vec::new();
        record.extend_from_slice(&leaf_id::LF_BARRAY.to_le_bytes());
        record.extend_from_slice(&payload);

        let result = parse_type_record(&record);
        assert!(result.is_some());
        if let Some(TypeRecord::BArrayType { element_type_index, index_type_index }) = result {
            assert_eq!(element_type_index, 0x1000);
            assert_eq!(index_type_index, 0x1001);
        } else {
            panic!("Expected BArrayType");
        }
    }

    #[test]
    fn test_label_type_parsing() {
        let mut record = Vec::new();
        record.extend_from_slice(&leaf_id::LF_LABEL.to_le_bytes());
        record.push(0x01); // mode

        let result = parse_type_record(&record);
        assert!(result.is_some());
        if let Some(TypeRecord::LabelType { mode }) = result {
            assert_eq!(mode, 1);
        } else {
            panic!("Expected LabelType");
        }
    }

    // =====================================================================
    // Tests for new symbol records
    // =====================================================================

    #[test]
    fn test_compile_v1_symbol() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&0x1234u32.to_le_bytes()); // flags
        payload.extend_from_slice(&0x014Cu16.to_le_bytes()); // x86
        payload.extend_from_slice(b"MSVC 19.0\0");

        let mut record_data = Vec::new();
        let total_len = 2 + 2 + payload.len() as u16;
        record_data.extend_from_slice(&total_len.to_le_bytes());
        record_data.extend_from_slice(&symbol_kind::S_COMPILE.to_le_bytes());
        record_data.extend_from_slice(&payload);
        while record_data.len() % 4 != 0 { record_data.push(0); }

        let result = parse_symbol_record(&record_data);
        assert!(result.is_some());
        if let Some(SymbolRecord::CompileInfo(ci)) = result {
            assert_eq!(ci.flags, 0x1234);
            assert_eq!(ci.machine, 0x014C);
        } else {
            panic!("Expected CompileInfo from S_COMPILE");
        }
    }

    #[test]
    fn test_label_symbol() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&0x2000u32.to_le_bytes()); // offset
        payload.extend_from_slice(&1u16.to_le_bytes()); // segment
        payload.push(0u8); // flags
        payload.extend_from_slice(b"loop_start\0");

        let mut record_data = Vec::new();
        let total_len = 2 + 2 + payload.len() as u16;
        record_data.extend_from_slice(&total_len.to_le_bytes());
        record_data.extend_from_slice(&symbol_kind::S_LABEL32.to_le_bytes());
        record_data.extend_from_slice(&payload);
        while record_data.len() % 4 != 0 { record_data.push(0); }

        let result = parse_symbol_record(&record_data);
        assert!(result.is_some());
        if let Some(SymbolRecord::Label(l)) = result {
            assert_eq!(l.offset, 0x2000);
            assert_eq!(l.name, "loop_start");
        } else {
            panic!("Expected Label");
        }
    }

    #[test]
    fn test_constant_symbol() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&0x1000u32.to_le_bytes()); // type_index
        payload.extend_from_slice(&42u16.to_le_bytes()); // value (small numeric)
        payload.extend_from_slice(b"ANSWER\0");

        let mut record_data = Vec::new();
        let total_len = 2 + 2 + payload.len() as u16;
        record_data.extend_from_slice(&total_len.to_le_bytes());
        record_data.extend_from_slice(&symbol_kind::S_CONSTANT.to_le_bytes());
        record_data.extend_from_slice(&payload);
        while record_data.len() % 4 != 0 { record_data.push(0); }

        let result = parse_symbol_record(&record_data);
        assert!(result.is_some());
        if let Some(SymbolRecord::Constant(c)) = result {
            assert_eq!(c.value, 42);
            assert_eq!(c.name, "ANSWER");
        } else {
            panic!("Expected Constant");
        }
    }

    #[test]
    fn test_register_symbol() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&0x1000u32.to_le_bytes()); // type_index
        payload.extend_from_slice(&0x0011u16.to_le_bytes()); // EAX
        payload.extend_from_slice(b"regvar\0");

        let mut record_data = Vec::new();
        let total_len = 2 + 2 + payload.len() as u16;
        record_data.extend_from_slice(&total_len.to_le_bytes());
        record_data.extend_from_slice(&symbol_kind::S_REGISTER.to_le_bytes());
        record_data.extend_from_slice(&payload);
        while record_data.len() % 4 != 0 { record_data.push(0); }

        let result = parse_symbol_record(&record_data);
        assert!(result.is_some());
        if let Some(SymbolRecord::RegisterVariable(r)) = result {
            assert_eq!(r.register, 0x0011);
            assert_eq!(r.name, "regvar");
        } else {
            panic!("Expected RegisterVariable");
        }
    }

    #[test]
    fn test_udt_symbol() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&0x1020u32.to_le_bytes()); // type_index
        payload.extend_from_slice(b"MyStruct\0");

        let mut record_data = Vec::new();
        let total_len = 2 + 2 + payload.len() as u16;
        record_data.extend_from_slice(&total_len.to_le_bytes());
        record_data.extend_from_slice(&symbol_kind::S_UDT.to_le_bytes());
        record_data.extend_from_slice(&payload);
        while record_data.len() % 4 != 0 { record_data.push(0); }

        let result = parse_symbol_record(&record_data);
        assert!(result.is_some());
        if let Some(SymbolRecord::UserDefinedType(u)) = result {
            assert_eq!(u.type_index, 0x1020);
            assert_eq!(u.name, "MyStruct");
        } else {
            panic!("Expected UDT");
        }
    }

    #[test]
    fn test_objname_symbol() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&0xABCDu32.to_le_bytes()); // signature
        payload.extend_from_slice(b"test.obj\0");

        let mut record_data = Vec::new();
        let total_len = 2 + 2 + payload.len() as u16;
        record_data.extend_from_slice(&total_len.to_le_bytes());
        record_data.extend_from_slice(&symbol_kind::S_OBJNAME.to_le_bytes());
        record_data.extend_from_slice(&payload);
        while record_data.len() % 4 != 0 { record_data.push(0); }

        let result = parse_symbol_record(&record_data);
        assert!(result.is_some());
        if let Some(SymbolRecord::ObjectName { signature, name }) = result {
            assert_eq!(signature, 0xABCD);
            assert_eq!(name, "test.obj");
        } else {
            panic!("Expected ObjectName");
        }
    }

    #[test]
    fn test_section_symbol() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&1u16.to_le_bytes()); // section_number
        payload.push(4u8); // alignment
        payload.push(0u8); // reserved
        payload.extend_from_slice(&0x1000u32.to_le_bytes()); // rva
        payload.extend_from_slice(&0x2000u32.to_le_bytes()); // size
        payload.extend_from_slice(&0x60000020u32.to_le_bytes()); // characteristics
        payload.extend_from_slice(b".text\0");

        let mut record_data = Vec::new();
        let total_len = 2 + 2 + payload.len() as u16;
        record_data.extend_from_slice(&total_len.to_le_bytes());
        record_data.extend_from_slice(&symbol_kind::S_SECTION.to_le_bytes());
        record_data.extend_from_slice(&payload);
        while record_data.len() % 4 != 0 { record_data.push(0); }

        let result = parse_symbol_record(&record_data);
        assert!(result.is_some());
        if let Some(SymbolRecord::Section { section_number, rva, name, .. }) = result {
            assert_eq!(section_number, 1);
            assert_eq!(rva, 0x1000);
            assert_eq!(name, ".text");
        } else {
            panic!("Expected Section");
        }
    }

    #[test]
    fn test_buildinfo_symbol() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&0x1042u32.to_le_bytes()); // item_id

        let mut record_data = Vec::new();
        let total_len = 2 + 2 + payload.len() as u16;
        record_data.extend_from_slice(&total_len.to_le_bytes());
        record_data.extend_from_slice(&symbol_kind::S_BUILDINFO.to_le_bytes());
        record_data.extend_from_slice(&payload);
        while record_data.len() % 4 != 0 { record_data.push(0); }

        let result = parse_symbol_record(&record_data);
        assert!(result.is_some());
        if let Some(SymbolRecord::BuildInfo { item_id }) = result {
            assert_eq!(item_id, 0x1042);
        } else {
            panic!("Expected BuildInfo");
        }
    }

    // =====================================================================
    // Tests for debug info
    // =====================================================================

    #[test]
    fn test_c13_line_record() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x100u32.to_le_bytes()); // offset
        data.extend_from_slice(&0x80000025u32.to_le_bytes()); // bit_vals: line=37, statement=true

        let lr = super::debug_info::C13LineRecord::parse(&data, false);
        assert!(lr.is_some());
        let lr = lr.unwrap();
        assert_eq!(lr.offset, 0x100);
        assert_eq!(lr.line_num_start(), 37);
        assert!(lr.is_statement());
        assert!(!lr.is_special_line());
    }

    #[test]
    fn test_c13_file_checksum() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x42u32.to_le_bytes()); // offset_filename
        data.push(16u8); // length (MD5 = 16 bytes)
        data.push(1u8); // checksum_type = Md5
        data.extend_from_slice(&[0u8; 16]); // 16 bytes of zeros for checksum
        // Align to 4
        while data.len() % 4 != 0 { data.push(0); }

        let result = super::debug_info::C13FileChecksum::parse(&data);
        assert!(result.is_some());
        let (fc, consumed) = result.unwrap();
        assert_eq!(fc.offset_filename, 0x42);
        assert_eq!(fc.length, 16);
        assert_eq!(fc.checksum_type, super::debug_info::C13ChecksumType::Md5);
        assert_eq!(consumed, 24); // 6 + 16 = 22, aligned to 24
    }

    #[test]
    fn test_image_section_header() {
        let mut data = Vec::new();
        data.extend_from_slice(b".data\0\0\0"); // 8 bytes name
        data.extend_from_slice(&0u32.to_le_bytes()); // physical_address
        data.extend_from_slice(&0x2000u32.to_le_bytes()); // virtual_address
        data.extend_from_slice(&0x500u32.to_le_bytes()); // raw_data_size
        data.extend_from_slice(&0x4000u32.to_le_bytes()); // raw_data_pointer
        data.extend_from_slice(&0u32.to_le_bytes()); // relocations_pointer
        data.extend_from_slice(&0u32.to_le_bytes()); // line_numbers_pointer
        data.extend_from_slice(&0u16.to_le_bytes()); // num_relocations
        data.extend_from_slice(&0u16.to_le_bytes()); // num_line_numbers
        data.extend_from_slice(&0xC0000040u32.to_le_bytes()); // characteristics

        let hdr = super::debug_info::ImageSectionHeader::parse(&data);
        assert!(hdr.is_some());
        let hdr = hdr.unwrap();
        assert_eq!(hdr.name, ".data");
        assert_eq!(hdr.virtual_address, 0x2000);
        assert_eq!(hdr.raw_data_size, 0x500);
    }

    #[test]
    fn test_image_function_entry() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x1000u32.to_le_bytes()); // starting_address
        data.extend_from_slice(&0x1080u32.to_le_bytes()); // ending_address
        data.extend_from_slice(&0x1010u32.to_le_bytes()); // end_of_prologue_address

        let entry = super::debug_info::ImageFunctionEntry::parse(&data);
        assert!(entry.is_some());
        let entry = entry.unwrap();
        assert_eq!(entry.starting_address, 0x1000);
        assert_eq!(entry.ending_address, 0x1080);
        assert_eq!(entry.end_of_prologue_address, 0x1010);
    }

    #[test]
    fn test_debug_data_header() {
        let mut data = Vec::new();
        data.extend_from_slice(&0xFFFFu16.to_le_bytes()); // stream 0 = FramePointerOmission = NIL
        data.extend_from_slice(&0xFFFFu16.to_le_bytes()); // stream 1 = Exception = NIL
        data.extend_from_slice(&0xFFFFu16.to_le_bytes()); // stream 2 = Fixup = NIL
        data.extend_from_slice(&0xFFFFu16.to_le_bytes()); // stream 3 = OmapToSrc = NIL
        data.extend_from_slice(&0xFFFFu16.to_le_bytes()); // stream 4 = OmapFromSrc = NIL
        data.extend_from_slice(&5u16.to_le_bytes());       // stream 5 = SectionHeader = 5

        let dd = super::debug_info::DebugData::parse_header(&data);
        assert_eq!(dd.debug_streams.len(), 6);
        assert_eq!(dd.get_stream(super::debug_info::DebugType::SectionHeader), Some(5));
        assert_eq!(dd.get_stream(super::debug_info::DebugType::Exception), None); // 0xFFFF is NIL
        assert_eq!(dd.get_stream(super::debug_info::DebugType::Fixup), None);
    }

    #[test]
    fn test_c13_checksum_type() {
        assert_eq!(super::debug_info::C13ChecksumType::from_u8(0), super::debug_info::C13ChecksumType::None);
        assert_eq!(super::debug_info::C13ChecksumType::from_u8(1), super::debug_info::C13ChecksumType::Md5);
        assert_eq!(super::debug_info::C13ChecksumType::from_u8(2), super::debug_info::C13ChecksumType::Sha1);
        assert_eq!(super::debug_info::C13ChecksumType::from_u8(3), super::debug_info::C13ChecksumType::Sha256);
        assert!(matches!(super::debug_info::C13ChecksumType::from_u8(99), super::debug_info::C13ChecksumType::Unknown(99)));
    }

    // =====================================================================
    // Tests for register names
    // =====================================================================

    #[test]
    fn test_register_name_x86() {
        assert_eq!(super::registers::register_name(0x0011), "EAX");
        assert_eq!(super::registers::register_name(0x0012), "ECX");
        assert_eq!(super::registers::register_name(0x0000), "None");
    }

    #[test]
    fn test_register_name_x64() {
        assert_eq!(super::registers::register_name(0x008F), "RAX");
        assert_eq!(super::registers::register_name(0x0097), "R8");
        assert_eq!(super::registers::register_name(0x009F), "RIP");
    }

    #[test]
    fn test_register_name_arm64() {
        assert_eq!(super::registers::register_name(0x0180), "X0");
        assert_eq!(super::registers::register_name(0x019F), "SP");
        assert_eq!(super::registers::register_name(0x01A0), "PC");
    }

    #[test]
    fn test_register_name_zmm() {
        assert_eq!(super::registers::register_name(0x00F0), "ZMM0");
        assert_eq!(super::registers::register_name(0x010F), "ZMM31");
    }

    #[test]
    fn test_register_name_kmask() {
        assert_eq!(super::registers::register_name(0x0110), "K0");
        assert_eq!(super::registers::register_name(0x0117), "K7");
    }

    // =====================================================================
    // Tests for GSI hash table
    // =====================================================================

    #[test]
    fn test_gsi_hash_header_parse() {
        let mut data = Vec::new();
        data.extend_from_slice(&0xeffeeffe_u32.to_le_bytes()); // version_signature
        data.extend_from_slice(&20040203u32.to_le_bytes()); // version_header
        data.extend_from_slice(&8u32.to_le_bytes()); // hash_record_size
        data.extend_from_slice(&4096u32.to_le_bytes()); // num_buckets

        let header = super::globals::GsiHashHeader::parse(&data);
        assert!(header.is_some());
        let h = header.unwrap();
        assert_eq!(h.version_signature, 0xeffeeffe);
        assert_eq!(h.num_buckets, 4096);
    }

    #[test]
    fn test_pdb_symbol_hash() {
        let h1 = super::globals::pdb_symbol_hash("main");
        let h2 = super::globals::pdb_symbol_hash("main");
        let h3 = super::globals::pdb_symbol_hash("other");
        assert_eq!(h1, h2);
        assert_ne!(h1, h3);
    }

    // =====================================================================
    // Tests for PdbFile convenience API
    // =====================================================================

    #[test]
    fn test_simple_type_pointer() {
        let st = resolve_simple_type(0x0404); // NearPointer32 + SignedChar
        assert!(st.is_pointer());
        assert_eq!(st.mode, SimpleTypeMode::NearPointer32);
        assert_eq!(st.kind, SimpleTypeKind::SignedChar);
        assert_eq!(st.byte_size(), 4); // 32-bit pointer
    }

    #[test]
    fn test_simple_type_non_pointer() {
        let st = resolve_simple_type(0x0010); // Real32
        assert!(!st.is_pointer());
        assert_eq!(st.kind, SimpleTypeKind::Real32);
        assert_eq!(st.byte_size(), 4);
    }

    #[test]
    fn test_type_property_flags() {
        let packed = TypeProperty::PACKED;
        let nested = TypeProperty::NESTED;
        assert!(packed.contains(TypeProperty::PACKED));
        assert!(!packed.contains(TypeProperty::NESTED));
        let combined = packed | nested;
        assert!(combined.contains(TypeProperty::PACKED));
        assert!(combined.contains(TypeProperty::NESTED));
    }

    #[test]
    fn test_member_access_protection() {
        assert_eq!(MemberAccessProtection::from_u8(0), MemberAccessProtection::None);
        assert_eq!(MemberAccessProtection::from_u8(1), MemberAccessProtection::Private);
        assert_eq!(MemberAccessProtection::from_u8(2), MemberAccessProtection::Protected);
        assert_eq!(MemberAccessProtection::from_u8(3), MemberAccessProtection::Public);
    }

    #[test]
    fn test_machine_type_names() {
        assert_eq!(machine_type::name(machine_type::X86), "x86");
        assert_eq!(machine_type::name(machine_type::AMD64), "x64 (AMD64)");
        assert_eq!(machine_type::name(machine_type::ARM64), "AArch64 (ARM64)");
        assert_eq!(machine_type::name(0xFFFF), "Unknown");
    }

    // =====================================================================
    // Test union type parsing
    // =====================================================================

    #[test]
    fn test_union_type_parsing() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&2u16.to_le_bytes()); // count
        payload.extend_from_slice(&0u16.to_le_bytes()); // property
        payload.extend_from_slice(&0x1000u32.to_le_bytes()); // field_list
        payload.extend_from_slice(&8u16.to_le_bytes()); // size = 8
        payload.extend_from_slice(b"U\0");

        let mut record = Vec::new();
        record.extend_from_slice(&leaf_id::LF_UNION.to_le_bytes());
        record.extend_from_slice(&payload);

        let result = parse_type_record(&record);
        assert!(result.is_some());
        if let Some(TypeRecord::Union(u)) = result {
            assert_eq!(u.count, 2);
            assert_eq!(u.name, "U");
            assert_eq!(u.size, 8);
        } else {
            panic!("Expected Union");
        }
    }

    #[test]
    fn test_field_list_parsing() {
        // Build a field list with one LF_MEMBER record
        let mut data = Vec::new();
        // LF_MEMBER: access(2) + type_index(4) + offset(2 numeric) + name("x\0")
        data.extend_from_slice(&leaf_id::LF_MEMBER.to_le_bytes()); // leaf id
        data.extend_from_slice(&3u16.to_le_bytes()); // access = Public
        data.extend_from_slice(&0x1000u32.to_le_bytes()); // type_index
        data.extend_from_slice(&0u16.to_le_bytes()); // offset = 0 (small numeric)
        data.extend_from_slice(b"x\0"); // name
        // Align to 4
        while data.len() % 4 != 0 { data.push(0xF4); }

        let mut record = Vec::new();
        record.extend_from_slice(&leaf_id::LF_FIELDLIST.to_le_bytes());
        record.extend_from_slice(&data);

        let result = parse_type_record(&record);
        assert!(result.is_some());
        if let Some(TypeRecord::FieldList { fields }) = result {
            assert!(!fields.is_empty());
            if let FieldRecord::Member { name, .. } = &fields[0] {
                assert_eq!(name, "x");
            } else {
                panic!("Expected Member field record");
            }
        } else {
            panic!("Expected FieldList");
        }
    }

    #[test]
    fn test_arglist_type_parsing() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&3u32.to_le_bytes()); // count
        payload.extend_from_slice(&0x1000u32.to_le_bytes());
        payload.extend_from_slice(&0x1001u32.to_le_bytes());
        payload.extend_from_slice(&0x1002u32.to_le_bytes());

        let mut record = Vec::new();
        record.extend_from_slice(&leaf_id::LF_ARGLIST.to_le_bytes());
        record.extend_from_slice(&payload);

        let result = parse_type_record(&record);
        assert!(result.is_some());
        if let Some(TypeRecord::ArgumentList(al)) = result {
            assert_eq!(al.count, 3);
            assert_eq!(al.arg_type_indices, vec![0x1000, 0x1001, 0x1002]);
        } else {
            panic!("Expected ArgumentList");
        }
    }
}

