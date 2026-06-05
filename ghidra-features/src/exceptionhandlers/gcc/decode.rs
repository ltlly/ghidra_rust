//! DWARF EH Decoder
//!
//! Ported from `AbstractDwarfEHDecoder.java`, `DwarfDecoderFactory.java`,
//! and `DwarfEHDecoder.java`.
//!
//! Decodes DWARF-encoded exception handling data values and addresses
//! from binary sections.

use super::{DwarfEhDataApplicationMode, DwarfEhDataDecodeFormat, split_encoding};

/// Trait for DWARF EH decoders.
///
/// Decodes a sequence of program bytes to addresses or integer values
/// according to the DWARF exception handling encoding specification.
pub trait DwarfEhDecoder: std::fmt::Debug {
    /// The data decode format (how the value is stored).
    fn data_format(&self) -> DwarfEhDataDecodeFormat;

    /// The data application mode (how to compute the final address).
    fn data_application_mode(&self) -> DwarfEhDataApplicationMode;

    /// Whether this decoder handles signed data.
    fn is_signed(&self) -> bool {
        self.data_format().is_signed()
    }

    /// Decode a raw integer value from the byte buffer at the given offset.
    ///
    /// Returns the decoded value and the number of bytes consumed.
    fn decode_value(&self, data: &[u8], offset: usize) -> Option<(i64, usize)>;

    /// Decode an address value, applying the application mode adjustment.
    ///
    /// `section_base` is the start address of the section being decoded.
    /// `current_offset` is the offset within the section where the encoded
    /// value begins (needed for PC-relative adjustments).
    fn decode_address(
        &self,
        data: &[u8],
        offset: usize,
        section_base: u64,
        current_offset: u64,
        pointer_size: usize,
    ) -> Option<(u64, usize)>;
}

/// A concrete DWARF EH decoder that handles all encoding combinations.
#[derive(Debug, Clone)]
pub struct StandardDwarfEhDecoder {
    format: DwarfEhDataDecodeFormat,
    mode: DwarfEhDataApplicationMode,
}

impl StandardDwarfEhDecoder {
    /// Create a new decoder from the combined encoding byte.
    pub fn from_encoding(encoding: u8) -> Self {
        let (format, mode) = split_encoding(encoding);
        Self { format, mode }
    }

    /// Create a new decoder with explicit format and mode.
    pub fn new(format: DwarfEhDataDecodeFormat, mode: DwarfEhDataApplicationMode) -> Self {
        Self { format, mode }
    }

    /// Whether the encoding is the "omit" marker (0xff).
    pub fn is_omit(&self) -> bool {
        self.format == DwarfEhDataDecodeFormat::Omit || self.mode == DwarfEhDataApplicationMode::Omit
    }
}

impl DwarfEhDecoder for StandardDwarfEhDecoder {
    fn data_format(&self) -> DwarfEhDataDecodeFormat {
        self.format
    }

    fn data_application_mode(&self) -> DwarfEhDataApplicationMode {
        self.mode
    }

    fn decode_value(&self, data: &[u8], offset: usize) -> Option<(i64, usize)> {
        if offset >= data.len() {
            return None;
        }
        let remaining = &data[offset..];
        match self.format {
            DwarfEhDataDecodeFormat::Absptr | DwarfEhDataDecodeFormat::Signed => {
                // Depends on pointer size; assume 4-byte default
                if remaining.len() < 4 {
                    return None;
                }
                let val = i32::from_le_bytes([
                    remaining[0], remaining[1], remaining[2], remaining[3],
                ]) as i64;
                Some((val, 4))
            }
            DwarfEhDataDecodeFormat::Uleb128 => {
                let (val, consumed) = read_uleb128(remaining)?;
                Some((val as i64, consumed))
            }
            DwarfEhDataDecodeFormat::Sleb128 => {
                let (val, consumed) = read_sleb128(remaining)?;
                Some((val, consumed))
            }
            DwarfEhDataDecodeFormat::Udata2 => {
                if remaining.len() < 2 {
                    return None;
                }
                let val = u16::from_le_bytes([remaining[0], remaining[1]]) as i64;
                Some((val, 2))
            }
            DwarfEhDataDecodeFormat::Udata4 => {
                if remaining.len() < 4 {
                    return None;
                }
                let val = u32::from_le_bytes([
                    remaining[0], remaining[1], remaining[2], remaining[3],
                ]) as i64;
                Some((val, 4))
            }
            DwarfEhDataDecodeFormat::Udata8 => {
                if remaining.len() < 8 {
                    return None;
                }
                let val = i64::from_le_bytes([
                    remaining[0], remaining[1], remaining[2], remaining[3],
                    remaining[4], remaining[5], remaining[6], remaining[7],
                ]);
                Some((val, 8))
            }
            DwarfEhDataDecodeFormat::Sdata2 => {
                if remaining.len() < 2 {
                    return None;
                }
                let val = i16::from_le_bytes([remaining[0], remaining[1]]) as i64;
                Some((val, 2))
            }
            DwarfEhDataDecodeFormat::Sdata4 => {
                if remaining.len() < 4 {
                    return None;
                }
                let val = i32::from_le_bytes([
                    remaining[0], remaining[1], remaining[2], remaining[3],
                ]) as i64;
                Some((val, 4))
            }
            DwarfEhDataDecodeFormat::Sdata8 => {
                if remaining.len() < 8 {
                    return None;
                }
                let val = i64::from_le_bytes([
                    remaining[0], remaining[1], remaining[2], remaining[3],
                    remaining[4], remaining[5], remaining[6], remaining[7],
                ]);
                Some((val, 8))
            }
            DwarfEhDataDecodeFormat::Omit => None,
        }
    }

    fn decode_address(
        &self,
        data: &[u8],
        offset: usize,
        section_base: u64,
        current_offset: u64,
        pointer_size: usize,
    ) -> Option<(u64, usize)> {
        let (mut value, consumed) = match self.format {
            DwarfEhDataDecodeFormat::Absptr => {
                // Read a full pointer-sized value
                match pointer_size {
                    4 => {
                        if offset + 4 > data.len() {
                            return None;
                        }
                        let val = u32::from_le_bytes([
                            data[offset],
                            data[offset + 1],
                            data[offset + 2],
                            data[offset + 3],
                        ]) as u64;
                        (val, 4)
                    }
                    8 => {
                        if offset + 8 > data.len() {
                            return None;
                        }
                        let val = u64::from_le_bytes([
                            data[offset],
                            data[offset + 1],
                            data[offset + 2],
                            data[offset + 3],
                            data[offset + 4],
                            data[offset + 5],
                            data[offset + 6],
                            data[offset + 7],
                        ]);
                        (val, 8)
                    }
                    _ => return None,
                }
            }
            _ => {
                let (v, c) = self.decode_value(data, offset)?;
                (v as u64, c)
            }
        };

        // Apply the application mode
        let result = match self.mode {
            DwarfEhDataApplicationMode::Absptr => value,
            DwarfEhDataApplicationMode::Pcrel => {
                // PC-relative: the value is relative to the position of the encoded data
                let pc = section_base + current_offset;
                pc.wrapping_add(value)
            }
            DwarfEhDataApplicationMode::Datarel => {
                // Data-relative: relative to the section start
                section_base.wrapping_add(value)
            }
            DwarfEhDataApplicationMode::Funcrel => {
                // Function-relative: value is an offset from function start
                // We cannot resolve without knowing the function base
                value
            }
            DwarfEhDataApplicationMode::Textrel => value,
            DwarfEhDataApplicationMode::Aligned => {
                // Aligned: round up consumed to pointer size
                value
            }
            DwarfEhDataApplicationMode::Indirect => {
                // Indirect: value is the address of the actual pointer
                // We would need to read from that address
                value
            }
            DwarfEhDataApplicationMode::Omit => return None,
        };

        Some((result, consumed))
    }
}

/// Create a decoder from a single encoding byte.
pub fn make_decoder(encoding: u8) -> Option<Box<dyn DwarfEhDecoder>> {
    if encoding == 0xff {
        return None;
    }
    Some(Box::new(StandardDwarfEhDecoder::from_encoding(encoding)))
}

/// Read an unsigned LEB128 value from a byte slice.
///
/// Returns `Some((value, bytes_consumed))` or `None` on overflow/underflow.
pub fn read_uleb128(data: &[u8]) -> Option<(u64, usize)> {
    let mut result: u64 = 0;
    let mut shift: u32 = 0;
    let mut consumed = 0;

    for &byte in data {
        consumed += 1;
        let low_bits = (byte & 0x7f) as u64;
        if shift >= 63 && low_bits > 1 {
            return None; // overflow
        }
        result |= low_bits << shift;
        if byte & 0x80 == 0 {
            return Some((result, consumed));
        }
        shift += 7;
    }
    None // truncated
}

/// Read a signed LEB128 value from a byte slice.
///
/// Returns `Some((value, bytes_consumed))` or `None` on overflow/underflow.
pub fn read_sleb128(data: &[u8]) -> Option<(i64, usize)> {
    let mut result: i64 = 0;
    let mut shift: u32 = 0;
    let mut consumed = 0;
    let size: u32 = 64;

    for &byte in data {
        consumed += 1;
        let low_bits = (byte & 0x7f) as i64;
        result |= low_bits << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            if shift < size && (byte & 0x40) != 0 {
                result |= -(1i64 << shift);
            }
            return Some((result, consumed));
        }
    }
    None // truncated
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_uleb128() {
        // 2 = 0x02
        assert_eq!(read_uleb128(&[0x02]), Some((2, 1)));
        // 127 = 0x7f
        assert_eq!(read_uleb128(&[0x7f]), Some((127, 1)));
        // 128 = 0x80, 0x01
        assert_eq!(read_uleb128(&[0x80, 0x01]), Some((128, 2)));
        // 624485 = 0xE5, 0x8E, 0x26
        assert_eq!(
            read_uleb128(&[0xE5, 0x8E, 0x26]),
            Some((624485, 3))
        );
        // Truncated
        assert_eq!(read_uleb128(&[0x80]), None);
        // Empty
        assert_eq!(read_uleb128(&[]), None);
    }

    #[test]
    fn test_read_sleb128() {
        // 2 = 0x02
        assert_eq!(read_sleb128(&[0x02]), Some((2, 1)));
        // -2 = 0x7e
        assert_eq!(read_sleb128(&[0x7e]), Some((-2, 1)));
        // 127 = 0xff, 0x00
        assert_eq!(read_sleb128(&[0xff, 0x00]), Some((127, 2)));
        // -127 = 0x81, 0x7f
        assert_eq!(read_sleb128(&[0x81, 0x7f]), Some((-127, 2)));
        // -123456 = 0xc0, 0xbb, 0x78
        assert_eq!(
            read_sleb128(&[0xc0, 0xbb, 0x78]),
            Some((-123456, 3))
        );
    }

    #[test]
    fn test_decoder_udata4() {
        let decoder = StandardDwarfEhDecoder::new(
            DwarfEhDataDecodeFormat::Udata4,
            DwarfEhDataApplicationMode::Absptr,
        );
        let data = [0x78, 0x56, 0x34, 0x12];
        let (val, consumed) = decoder.decode_value(&data, 0).unwrap();
        assert_eq!(val, 0x12345678);
        assert_eq!(consumed, 4);
    }

    #[test]
    fn test_decoder_pcrel() {
        let decoder = StandardDwarfEhDecoder::new(
            DwarfEhDataDecodeFormat::Udata4,
            DwarfEhDataApplicationMode::Pcrel,
        );
        let data = [0x10, 0x00, 0x00, 0x00]; // value = 0x10
        let (addr, _) = decoder
            .decode_address(&data, 0, 0x1000, 0x200, 4)
            .unwrap();
        // PC = section_base + current_offset = 0x1000 + 0x200 = 0x1200
        // result = 0x1200 + 0x10 = 0x1210
        assert_eq!(addr, 0x1210);
    }

    #[test]
    fn test_decoder_uleb128() {
        let decoder = StandardDwarfEhDecoder::new(
            DwarfEhDataDecodeFormat::Uleb128,
            DwarfEhDataApplicationMode::Absptr,
        );
        let data = [0xE5, 0x8E, 0x26]; // 624485
        let (val, consumed) = decoder.decode_value(&data, 0).unwrap();
        assert_eq!(val, 624485);
        assert_eq!(consumed, 3);
    }

    #[test]
    fn test_make_decoder() {
        assert!(make_decoder(0xff).is_none());
        let decoder = make_decoder(0x0b).unwrap();
        assert_eq!(decoder.data_format(), DwarfEhDataDecodeFormat::Sdata4);
        assert_eq!(
            decoder.data_application_mode(),
            DwarfEhDataApplicationMode::Absptr
        );
    }

    #[test]
    fn test_decoder_is_omit() {
        let decoder = StandardDwarfEhDecoder::new(
            DwarfEhDataDecodeFormat::Omit,
            DwarfEhDataApplicationMode::Absptr,
        );
        assert!(decoder.is_omit());
    }
}
