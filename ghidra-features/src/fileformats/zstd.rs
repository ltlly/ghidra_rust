//! Zstandard (ZSTD) compression format parser.
//!
//! Ported from Ghidra's `ghidra.file.formats.zstd` package.
//!
//! References:
//! - RFC 8878: <https://datatracker.ietf.org/doc/html/rfc8878>
//! - Zstandard format specification: <https://github.com/facebook/zstd/blob/dev/doc/zstd_compression_format.md>


// ═══════════════════════════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════════════════════════

/// ZSTD magic number: `0xFD2FB528`.
pub const ZSTD_MAGIC: u32 = 0xFD2FB528;

/// Minimum ZSTD frame header size (magic 4 + frame header descriptor 1 = 5).
pub const ZSTD_MIN_FRAME_HEADER_SIZE: usize = 5;

// Frame header descriptor bit masks.
/// Frame_Content_Size_flag bits 0-1.
pub const FHD_CONTENT_SIZE_MASK: u8 = 0x03;
/// Single_Segment_flag (bit 2).
pub const FHD_SINGLE_SEGMENT: u8 = 0x20;
/// Content_Checksum_flag (bit 2).
pub const FHD_CONTENT_CHECKSUM: u8 = 0x04;
/// Dictionary_ID_flag (bits 0-1 of the low byte).
pub const FHD_DICT_ID_MASK: u8 = 0x03;

// ═══════════════════════════════════════════════════════════════════════════════════
// ZSTD Frame Header
// ═══════════════════════════════════════════════════════════════════════════════════

/// Parsed ZSTD frame header.
#[derive(Debug, Clone)]
pub struct ZstdFrameHeader {
    /// Frame header descriptor byte.
    pub frame_header_descriptor: u8,
    /// Window descriptor byte (if present).
    pub window_descriptor: Option<u8>,
    /// Dictionary ID (if present).
    pub dictionary_id: Option<u32>,
    /// Frame content size (if present).
    pub frame_content_size: Option<u64>,
    /// Whether a content checksum is present.
    pub has_checksum: bool,
    /// Whether single-segment mode.
    pub single_segment: bool,
    /// Total size of the frame header in bytes.
    pub header_size: usize,
}

impl ZstdFrameHeader {
    /// Whether the frame includes a checksum (32-bit xxhash).
    pub fn content_checksum(&self) -> bool {
        self.has_checksum
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Parser
// ═══════════════════════════════════════════════════════════════════════════════════

/// Check if a byte slice starts with ZSTD magic.
pub fn is_zstd(data: &[u8]) -> bool {
    data.len() >= 4 && u32::from_le_bytes([data[0], data[1], data[2], data[3]]) == ZSTD_MAGIC
}

/// Parse a ZSTD frame header. Returns the header and remaining bytes.
pub fn parse_frame_header(data: &[u8]) -> Result<(ZstdFrameHeader, &[u8]), String> {
    if data.len() < ZSTD_MIN_FRAME_HEADER_SIZE {
        return Err("Data too short for ZSTD frame header".to_string());
    }

    let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    if magic != ZSTD_MAGIC {
        return Err(format!("Invalid ZSTD magic: 0x{:08X}", magic));
    }

    let fhd = data[4];
    let single_segment = (fhd & FHD_SINGLE_SEGMENT) != 0;
    let has_checksum = (fhd & FHD_CONTENT_CHECKSUM) != 0;
    let fcs_id = (fhd >> 6) & 0x03;
    let dict_id_field = fhd & FHD_DICT_ID_MASK;

    let mut pos = 5;

    // Window descriptor (present if not single_segment)
    let window_descriptor = if !single_segment {
        if pos >= data.len() {
            return Err("Truncated window descriptor".to_string());
        }
        let wd = Some(data[pos]);
        pos += 1;
        wd
    } else {
        None
    };

    // Dictionary ID (0-4 bytes)
    let dictionary_id = match dict_id_field {
        0 => None,
        1 => {
            if pos + 1 > data.len() {
                return Err("Truncated dict ID".to_string());
            }
            let id = data[pos] as u32;
            pos += 1;
            Some(id)
        }
        2 => {
            if pos + 2 > data.len() {
                return Err("Truncated dict ID".to_string());
            }
            let id = u16::from_le_bytes([data[pos], data[pos + 1]]) as u32;
            pos += 2;
            Some(id)
        }
        3 => {
            if pos + 4 > data.len() {
                return Err("Truncated dict ID".to_string());
            }
            let id = u32::from_le_bytes([
                data[pos],
                data[pos + 1],
                data[pos + 2],
                data[pos + 3],
            ]);
            pos += 4;
            Some(id)
        }
        _ => None,
    };

    // Frame content size (0, 1, 2, 4, or 8 bytes based on fcs_id and single_segment)
    let fcs_size = if single_segment {
        // When single_segment, Window_Descriptor byte is absent, FCS_Size is 1<<fcs_id
        match fcs_id {
            0 => 1,
            1 => 2,
            2 => 4,
            3 => 8,
            _ => 0,
        }
    } else {
        match fcs_id {
            0 => 0,
            1 => 2,
            2 => 4,
            3 => 8,
            _ => 0,
        }
    };

    let frame_content_size = match fcs_size {
        0 => None,
        1 => {
            if pos + 1 > data.len() {
                return Err("Truncated FCS".to_string());
            }
            let val = data[pos] as u64;
            pos += 1;
            Some(val)
        }
        2 => {
            if pos + 2 > data.len() {
                return Err("Truncated FCS".to_string());
            }
            let val = u16::from_le_bytes([data[pos], data[pos + 1]]) as u64;
            pos += 2;
            Some(val)
        }
        4 => {
            if pos + 4 > data.len() {
                return Err("Truncated FCS".to_string());
            }
            let val = u32::from_le_bytes([
                data[pos],
                data[pos + 1],
                data[pos + 2],
                data[pos + 3],
            ]) as u64;
            pos += 4;
            Some(val)
        }
        8 => {
            if pos + 8 > data.len() {
                return Err("Truncated FCS".to_string());
            }
            let val = u64::from_le_bytes([
                data[pos],
                data[pos + 1],
                data[pos + 2],
                data[pos + 3],
                data[pos + 4],
                data[pos + 5],
                data[pos + 6],
                data[pos + 7],
            ]);
            pos += 8;
            Some(val)
        }
        _ => None,
    };

    Ok((
        ZstdFrameHeader {
            frame_header_descriptor: fhd,
            window_descriptor,
            dictionary_id,
            frame_content_size,
            has_checksum,
            single_segment,
            header_size: pos,
        },
        &data[pos..],
    ))
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_zstd() {
        assert!(is_zstd(&ZSTD_MAGIC.to_le_bytes()));
        assert!(!is_zstd(&[0x00, 0x00, 0x00, 0x00]));
    }

    #[test]
    fn test_parse_minimal_header() {
        // Magic + FHD (single_segment, no dict, FCS=0)
        let mut data = Vec::new();
        data.extend_from_slice(&ZSTD_MAGIC.to_le_bytes());
        data.push(FHD_SINGLE_SEGMENT); // single segment, no checksum
        data.push(100); // FCS: single byte (1<<0 = 1 byte)

        let (hdr, _) = parse_frame_header(&data).unwrap();
        assert!(hdr.single_segment);
        assert!(!hdr.has_checksum);
        assert_eq!(hdr.frame_content_size, Some(100));
        assert!(hdr.window_descriptor.is_none());
    }

    #[test]
    fn test_parse_header_with_checksum() {
        let mut data = Vec::new();
        data.extend_from_slice(&ZSTD_MAGIC.to_le_bytes());
        data.push(FHD_SINGLE_SEGMENT | FHD_CONTENT_CHECKSUM); // single seg + checksum
        data.push(0); // FCS = 0 (single segment, fcs_id=0 means 1-byte fcs)

        let (hdr, _) = parse_frame_header(&data).unwrap();
        assert!(hdr.has_checksum);
        assert!(hdr.single_segment);
    }

    #[test]
    fn test_parse_header_non_single_segment() {
        let mut data = Vec::new();
        data.extend_from_slice(&ZSTD_MAGIC.to_le_bytes());
        data.push(0x40); // fcs_id=1 (2-byte FCS), not single segment
        data.push(0x00); // window descriptor
        // 2-byte FCS
        data.extend_from_slice(&256u16.to_le_bytes());

        let (hdr, _) = parse_frame_header(&data).unwrap();
        assert!(!hdr.single_segment);
        assert!(hdr.window_descriptor.is_some());
        assert_eq!(hdr.frame_content_size, Some(256));
    }

    #[test]
    fn test_invalid_magic() {
        assert!(parse_frame_header(&[0x00; 10]).is_err());
    }

    #[test]
    fn test_too_short() {
        assert!(parse_frame_header(&[0x01, 0x02]).is_err());
    }
}
