//! Intel HEX and Motorola S-Record loaders.
//!
//! Ported from Ghidra's:
//! - `ghidra.app.util.opinion.IntelHexLoader`
//! - `ghidra.app.util.opinion.MotorolaHexLoader`
//!
//! These text-based hex record formats encode binary data as ASCII hex
//! strings. Each record has a type, address, data, and checksum.

use super::framework::*;
use crate::base::analyzer::{Address, Language, MemoryBlock, Program};

// ---------------------------------------------------------------------------
// Intel HEX format
// ---------------------------------------------------------------------------

/// Intel HEX loader name.
pub const INTEL_HEX_NAME: &str = "Intel Hex";

/// Detect whether `data` looks like an Intel HEX file.
///
/// Intel HEX records start with `:` followed by hex digits.
pub fn is_intel_hex(data: &[u8]) -> bool {
    let text = match std::str::from_utf8(data) {
        Ok(s) => s,
        Err(_) => return false,
    };

    // Skip blank lines, find first non-blank line
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        return trimmed.starts_with(':') && trimmed.len() >= 11;
    }
    false
}

/// A parsed Intel HEX record.
#[derive(Debug, Clone)]
pub struct IntelHexRecord {
    /// Record type (00=Data, 01=EOF, 02=Extended Segment, 03=Start Segment,
    /// 04=Extended Linear, 05=Start Linear).
    pub record_type: u8,
    /// Load address for this record.
    pub address: u16,
    /// Data bytes.
    pub data: Vec<u8>,
}

impl IntelHexRecord {
    /// Parse a single Intel HEX record line.
    pub fn parse(line: &str) -> Result<Self, String> {
        let line = line.trim();
        if !line.starts_with(':') {
            return Err("Record must start with ':'".into());
        }
        if line.len() < 11 {
            return Err("Record too short".into());
        }

        let hex = &line[1..];
        let bytes = hex_to_bytes(hex).map_err(|e| format!("Invalid hex: {}", e))?;

        if bytes.len() < 5 {
            return Err("Record too short after hex decode".into());
        }

        let byte_count = bytes[0];
        let address = u16::from_be_bytes([bytes[1], bytes[2]]);
        let record_type = bytes[3];

        if bytes.len() < 4 + byte_count as usize + 1 {
            return Err("Record data truncated".into());
        }

        let data = bytes[4..4 + byte_count as usize].to_vec();

        Ok(IntelHexRecord {
            record_type,
            address,
            data,
        })
    }
}

/// Parse all Intel HEX records from `data` and return memory regions.
pub fn parse_intel_hex(data: &[u8]) -> Result<Vec<(u64, Vec<u8>)>, String> {
    let text = std::str::from_utf8(data).map_err(|_| "Invalid UTF-8")?;

    let mut base_address: u64 = 0;
    let mut segments: Vec<(u64, Vec<u8>)> = Vec::new();
    let mut current_addr: Option<u64> = None;
    let mut current_data: Vec<u8> = Vec::new();

    for (line_num, line) in text.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || !trimmed.starts_with(':') {
            continue;
        }

        let record = IntelHexRecord::parse(trimmed)
            .map_err(|e| format!("Line {}: {}", line_num + 1, e))?;

        match record.record_type {
            0x00 => {
                // Data record
                let addr = base_address + record.address as u64;
                if current_addr.is_none() {
                    current_addr = Some(addr);
                }

                let expected = current_addr.unwrap() + current_data.len() as u64;
                if addr != expected {
                    // Non-contiguous, flush current segment
                    if !current_data.is_empty() {
                        segments.push((current_addr.unwrap(), current_data));
                    }
                    current_data = Vec::new();
                    current_addr = Some(addr);
                }

                current_data.extend_from_slice(&record.data);
            }
            0x01 => {
                // End of file
                break;
            }
            0x02 => {
                // Extended Segment Address
                if record.data.len() >= 2 {
                    base_address =
                        u16::from_be_bytes([record.data[0], record.data[1]]) as u64 * 16;
                }
            }
            0x03 => {
                // Start Segment Address (ignore)
            }
            0x04 => {
                // Extended Linear Address
                if record.data.len() >= 2 {
                    base_address =
                        u16::from_be_bytes([record.data[0], record.data[1]]) as u64 * 0x10000;
                }
            }
            0x05 => {
                // Start Linear Address (ignore)
            }
            _ => {}
        }
    }

    // Flush remaining
    if !current_data.is_empty() {
        segments.push((current_addr.unwrap(), current_data));
    }

    Ok(segments)
}

/// Load an Intel HEX file into a Program.
pub fn load_intel_hex(data: &[u8], options: &[LoadOption], log: &mut MessageLog) -> Result<Program, LoadError> {
    let segments = parse_intel_hex(data)
        .map_err(|e| LoadError::MalformedInput(format!("Intel HEX error: {}", e)))?;

    let arch_str = get_option_str(options, "Architecture", "x86");
    let base_addr_opt = get_option_u64(options, "Base Address", 0);

    let lang = arch_to_language(arch_str);
    let mut program = Program::new("intel_hex", lang);
    program.executable_format = Some(INTEL_HEX_NAME.to_string());

    let mut total_size = 0u64;
    for (addr, ref seg_data) in &segments {
        let adjusted_addr = if base_addr_opt != 0 {
            base_addr_opt
        } else {
            *addr
        };

        program.memory_blocks.push(MemoryBlock {
            name: format!("HEX_{:x}", addr),
            start: Address::new(adjusted_addr),
            size: seg_data.len() as u64,
            is_read: true,
            is_write: true,
            is_execute: true,
            is_initialized: true,
        });
        program.memory.add_range(crate::base::analyzer::AddressRange::new(
            Address::new(adjusted_addr),
            Address::new(adjusted_addr + seg_data.len() as u64 - 1),
        ));
        total_size += seg_data.len() as u64;
    }

    program.image_base = base_addr_opt;

    log.info(format!(
        "Loaded Intel HEX: {} segments, {} bytes total",
        segments.len(),
        total_size
    ));

    Ok(program)
}

// ---------------------------------------------------------------------------
// Motorola S-Record format
// ---------------------------------------------------------------------------

/// Motorola S-Record loader name.
pub const MOTOROLA_HEX_NAME: &str = "Motorola Hex";

/// Detect whether `data` looks like a Motorola S-Record file.
///
/// S-Records start with `S` followed by a digit (0-9).
pub fn is_motorola_hex(data: &[u8]) -> bool {
    let text = match std::str::from_utf8(data) {
        Ok(s) => s,
        Err(_) => return false,
    };

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.len() < 10 {
            continue;
        }
        let bytes = trimmed.as_bytes();
        if bytes[0] == b'S' || bytes[0] == b's' {
            return bytes[1].is_ascii_digit();
        }
    }
    false
}

/// A parsed Motorola S-Record.
#[derive(Debug, Clone)]
pub struct SRecord {
    /// Record type (S0=header, S1/S2/S3=data, S7/S8/S9=end).
    pub record_type: u8,
    /// Address.
    pub address: u64,
    /// Data bytes.
    pub data: Vec<u8>,
}

impl SRecord {
    /// Parse a single S-Record line.
    pub fn parse(line: &str) -> Result<Self, String> {
        let line = line.trim();
        let bytes = line.as_bytes();

        if bytes.len() < 4 || (bytes[0] != b'S' && bytes[0] != b's') {
            return Err("Not an S-Record".into());
        }

        let record_type = bytes[1] - b'0';
        let hex = &line[2..];
        let raw = hex_to_bytes(hex).map_err(|e| format!("Invalid hex: {}", e))?;

        if raw.is_empty() {
            return Err("Empty record".into());
        }

        let byte_count = raw[0] as usize;
        if raw.len() < byte_count + 1 {
            return Err("Record truncated".into());
        }

        let addr_len = match record_type {
            0 | 1 | 9 => 2,
            2 | 8 => 3,
            3 | 7 => 4,
            _ => return Err(format!("Unknown S-Record type: S{}", record_type)),
        };

        if raw.len() < 1 + addr_len {
            return Err("Address truncated".into());
        }

        let mut address = 0u64;
        for i in 0..addr_len {
            address = (address << 8) | raw[1 + i] as u64;
        }

        let data_start = 1 + addr_len;
        // byte_count includes addr_len + data_len + 1 (checksum)
        // data_len = byte_count - addr_len - 1
        let data_len = byte_count.saturating_sub(addr_len + 1);
        let data = if data_start + data_len <= raw.len() {
            raw[data_start..data_start + data_len].to_vec()
        } else {
            Vec::new()
        };

        Ok(SRecord {
            record_type,
            address,
            data,
        })
    }
}

/// Parse all S-Records from `data` and return memory regions.
pub fn parse_motorola_hex(data: &[u8]) -> Result<Vec<(u64, Vec<u8>)>, String> {
    let text = std::str::from_utf8(data).map_err(|_| "Invalid UTF-8")?;

    let mut segments: Vec<(u64, Vec<u8>)> = Vec::new();
    let mut current_addr: Option<u64> = None;
    let mut current_data: Vec<u8> = Vec::new();

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || !trimmed.starts_with('S') && !trimmed.starts_with('s') {
            continue;
        }

        let record = SRecord::parse(trimmed)?;

        if record.record_type == 0 {
            // Header record, skip
            continue;
        }
        if record.record_type >= 7 {
            // End record
            break;
        }

        let addr = record.address;
        if current_addr.is_none() {
            current_addr = Some(addr);
        }

        let expected = current_addr.unwrap() + current_data.len() as u64;
        if addr != expected {
            if !current_data.is_empty() {
                segments.push((current_addr.unwrap(), current_data));
            }
            current_data = Vec::new();
            current_addr = Some(addr);
        }

        current_data.extend_from_slice(&record.data);
    }

    if !current_data.is_empty() {
        segments.push((current_addr.unwrap(), current_data));
    }

    Ok(segments)
}

/// Load a Motorola S-Record file into a Program.
pub fn load_motorola_hex(
    data: &[u8],
    options: &[LoadOption],
    log: &mut MessageLog,
) -> Result<Program, LoadError> {
    let segments = parse_motorola_hex(data)
        .map_err(|e| LoadError::MalformedInput(format!("Motorola S-Record error: {}", e)))?;

    let arch_str = get_option_str(options, "Architecture", "m68k");
    let base_addr_opt = get_option_u64(options, "Base Address", 0);

    let lang = arch_to_language(arch_str);
    let mut program = Program::new("motorola_hex", lang);
    program.executable_format = Some(MOTOROLA_HEX_NAME.to_string());

    let mut total_size = 0u64;
    for (addr, ref seg_data) in &segments {
        let adjusted_addr = if base_addr_opt != 0 {
            base_addr_opt
        } else {
            *addr
        };

        program.memory_blocks.push(MemoryBlock {
            name: format!("SREC_{:x}", addr),
            start: Address::new(adjusted_addr),
            size: seg_data.len() as u64,
            is_read: true,
            is_write: true,
            is_execute: true,
            is_initialized: true,
        });
        program.memory.add_range(crate::base::analyzer::AddressRange::new(
            Address::new(adjusted_addr),
            Address::new(adjusted_addr + seg_data.len() as u64 - 1),
        ));
        total_size += seg_data.len() as u64;
    }

    program.image_base = base_addr_opt;

    log.info(format!(
        "Loaded Motorola S-Record: {} segments, {} bytes total",
        segments.len(),
        total_size
    ));

    Ok(program)
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Convert hex string to bytes.
fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, String> {
    let hex = hex.trim();
    if hex.len() % 2 != 0 {
        return Err("Odd-length hex string".into());
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for chunk in hex.as_bytes().chunks(2) {
        let high = hex_digit(chunk[0]).ok_or("Invalid hex digit")?;
        let low = hex_digit(chunk[1]).ok_or("Invalid hex digit")?;
        bytes.push((high << 4) | low);
    }
    Ok(bytes)
}

fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Convert architecture string to Language.
fn arch_to_language(arch: &str) -> Language {
    let arch_lower = arch.to_lowercase();
    let (processor, variant, size) = match arch_lower.as_str() {
        "x86" | "i386" | "i686" => ("x86", "LE", 32),
        "x86_64" | "amd64" | "x64" => ("x86", "LE", 64),
        "arm" => ("ARM", "LE", 32),
        "aarch64" | "arm64" => ("AARCH64", "LE", 64),
        "m68k" | "68000" => ("68000", "BE", 32),
        "mips" => ("MIPS", "BE", 32),
        "ppc" | "powerpc" => ("PowerPC", "BE", 32),
        "sparc" => ("SPARC", "BE", 32),
        _ => ("unknown", "LE", 32),
    };

    Language {
        processor: processor.into(),
        variant: variant.into(),
        size,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- Intel HEX ---

    #[test]
    fn test_is_intel_hex_valid() {
        let data = b":03000000020000FC\n:00000001FF\n";
        assert!(is_intel_hex(data));
    }

    #[test]
    fn test_is_intel_hex_invalid() {
        assert!(!is_intel_hex(b"S10F000048656C6C6F20576F726C644C"));
        assert!(!is_intel_hex(b"MZ\x90\x00"));
        assert!(!is_intel_hex(b""));
    }

    #[test]
    fn test_intel_hex_record_parse() {
        let rec = IntelHexRecord::parse(":03000000020000FC").unwrap();
        assert_eq!(rec.record_type, 0);
        assert_eq!(rec.address, 0);
        assert_eq!(rec.data, vec![0x02, 0x00, 0x00]);
    }

    #[test]
    fn test_intel_hex_record_parse_eof() {
        let rec = IntelHexRecord::parse(":00000001FF").unwrap();
        assert_eq!(rec.record_type, 1);
        assert!(rec.data.is_empty());
    }

    #[test]
    fn test_intel_hex_record_parse_extended_linear() {
        let rec = IntelHexRecord::parse(":020000040000FA").unwrap();
        assert_eq!(rec.record_type, 4);
        assert_eq!(rec.data, vec![0x00, 0x00]);
    }

    #[test]
    fn test_intel_hex_record_parse_bad() {
        assert!(IntelHexRecord::parse("not a record").is_err());
        assert!(IntelHexRecord::parse(":00").is_err());
    }

    #[test]
    fn test_parse_intel_hex() {
        // Two data records at consecutive addresses (0x0000..0x0002, then 0x0003..0x0006)
        let input = b":03000000020000FC\n:0400030001020304E6\n:00000001FF\n";
        let segments = parse_intel_hex(input).unwrap();
        assert_eq!(segments.len(), 1); // contiguous, single segment
        assert_eq!(segments[0].0, 0);
        assert_eq!(
            segments[0].1,
            vec![0x02, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04]
        );
    }

    #[test]
    fn test_parse_intel_hex_non_contiguous() {
        let input = b":02000000AABB7E\n:02100000CCDDA1\n:00000001FF\n";
        let segments = parse_intel_hex(input).unwrap();
        assert_eq!(segments.len(), 2);
        assert_eq!(segments[0].0, 0x0000);
        assert_eq!(segments[1].0, 0x1000);
    }

    #[test]
    fn test_parse_intel_hex_extended_linear() {
        let input = b":020000040001F9\n:02000000AABB7C\n:00000001FF\n";
        let segments = parse_intel_hex(input).unwrap();
        assert_eq!(segments.len(), 1);
        assert_eq!(segments[0].0, 0x10000);
    }

    #[test]
    fn test_load_intel_hex() {
        let input = b":02000000AABB7E\n:00000001FF\n";
        let mut log = MessageLog::new();
        let prog = load_intel_hex(input, &[], &mut log).unwrap();
        assert_eq!(prog.executable_format, Some(INTEL_HEX_NAME.to_string()));
        assert!(!prog.memory_blocks.is_empty());
    }

    // --- Motorola S-Record ---

    #[test]
    fn test_is_motorola_hex_valid() {
        let data = b"S1130000285F245F2212226A000424290008237C2A\nS9030000FC\n";
        assert!(is_motorola_hex(data));
    }

    #[test]
    fn test_is_motorola_hex_invalid() {
        assert!(!is_motorola_hex(b":03000000020000FC"));
        assert!(!is_motorola_hex(b""));
    }

    #[test]
    fn test_srecord_parse_s1() {
        let rec = SRecord::parse("S1130000285F245F2212226A000424290008237C2A").unwrap();
        assert_eq!(rec.record_type, 1);
        assert_eq!(rec.address, 0);
        assert!(!rec.data.is_empty());
    }

    #[test]
    fn test_srecord_parse_s0_header() {
        let rec = SRecord::parse("S00F000068656C6C6F202020202000003C").unwrap();
        assert_eq!(rec.record_type, 0);
    }

    #[test]
    fn test_srecord_parse_s9_end() {
        let rec = SRecord::parse("S9030000FC").unwrap();
        assert_eq!(rec.record_type, 9);
    }

    #[test]
    fn test_srecord_parse_invalid() {
        assert!(SRecord::parse("not a record").is_err());
    }

    #[test]
    fn test_parse_motorola_hex() {
        // S1 record: byte_count=0x07, addr=0x0000, data=AABBCCDD, checksum=E6
        // byte_count includes address(2) + data(4) + checksum(1) = 7
        let input = b"S1070000AABBCCDDE6\nS9030000FC\n";
        let segments = parse_motorola_hex(input).unwrap();
        assert_eq!(segments.len(), 1);
        assert_eq!(segments[0].0, 0);
        assert_eq!(segments[0].1, vec![0xAA, 0xBB, 0xCC, 0xDD]);
    }

    #[test]
    fn test_load_motorola_hex() {
        let input = b"S1070000AABBCCDDE6\nS9030000FC\n";
        let mut log = MessageLog::new();
        let prog = load_motorola_hex(input, &[], &mut log).unwrap();
        assert_eq!(prog.executable_format, Some(MOTOROLA_HEX_NAME.to_string()));
    }

    // --- Shared ---

    #[test]
    fn test_hex_to_bytes() {
        assert_eq!(hex_to_bytes("AABB").unwrap(), vec![0xAA, 0xBB]);
        assert_eq!(hex_to_bytes("01020304").unwrap(), vec![1, 2, 3, 4]);
        assert!(hex_to_bytes("ABC").is_err()); // odd length
        assert!(hex_to_bytes("ZZ").is_err()); // invalid hex
    }

    #[test]
    fn test_hex_digit() {
        assert_eq!(hex_digit(b'0'), Some(0));
        assert_eq!(hex_digit(b'9'), Some(9));
        assert_eq!(hex_digit(b'a'), Some(10));
        assert_eq!(hex_digit(b'F'), Some(15));
        assert_eq!(hex_digit(b'G'), None);
    }

    #[test]
    fn test_arch_to_language() {
        let lang = arch_to_language("x86");
        assert_eq!(lang.processor, "x86");
        assert_eq!(lang.variant, "LE");
        assert_eq!(lang.size, 32);

        let lang = arch_to_language("m68k");
        assert_eq!(lang.processor, "68000");
        assert_eq!(lang.variant, "BE");

        let lang = arch_to_language("aarch64");
        assert_eq!(lang.size, 64);
    }
}
