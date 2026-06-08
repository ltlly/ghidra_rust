//! Utility functions for binary data processing.
//!
//! Ported from Ghidra's binary utility functions including checksums,
//! hashing, and data conversion.

use std::io;

use super::binary_reader::BinaryReader;

/// Read all remaining bytes from a reader into a `Vec<u8>`.
pub fn read_all(reader: &mut BinaryReader) -> io::Result<Vec<u8>> {
    let len = reader.remaining() as usize;
    reader.read_next_bytes(len)
}

/// Compute a CRC32 checksum of the given data.
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFFFFFF;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

/// Compute an MD5 hash of the given data (returns 16 bytes).
pub fn md5(data: &[u8]) -> [u8; 16] {
    use md5::Digest;
    let result = md5::Md5::digest(data);
    let mut out = [0u8; 16];
    out.copy_from_slice(&result);
    out
}

/// Compute a SHA-256 hash of the given data (returns 32 bytes).
pub fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    let result = sha2::Sha256::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Byte array to hex string.
pub fn bytes_to_hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Hex string to byte array. Returns None if the string is not valid hex.
pub fn hex_to_bytes(hex: &str) -> Option<Vec<u8>> {
    if hex.len() % 2 != 0 {
        return None;
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for i in (0..hex.len()).step_by(2) {
        let byte_str = &hex[i..i + 2];
        let byte = u8::from_str_radix(byte_str, 16).ok()?;
        bytes.push(byte);
    }
    Some(bytes)
}

/// Compute an Adler-32 checksum.
pub fn adler32(data: &[u8]) -> u32 {
    let mut a: u32 = 1;
    let mut b: u32 = 0;
    const MOD: u32 = 65521;
    for &byte in data {
        a = (a + byte as u32) % MOD;
        b = (b + a) % MOD;
    }
    (b << 16) | a
}

/// Compute a simple XOR checksum of the given data.
pub fn xor_checksum(data: &[u8]) -> u8 {
    data.iter().fold(0u8, |acc, &b| acc ^ b)
}

/// Compute the sum of all bytes modulo 256.
pub fn byte_sum(data: &[u8]) -> u8 {
    data.iter().fold(0u8, |acc, &b| acc.wrapping_add(b))
}

/// Reverse the bits of a byte.
pub fn reverse_bits_byte(b: u8) -> u8 {
    b.reverse_bits()
}

/// Reverse the bytes of a u16.
pub fn swap_bytes_u16(val: u16) -> u16 {
    val.swap_bytes()
}

/// Reverse the bytes of a u32.
pub fn swap_bytes_u32(val: u32) -> u32 {
    val.swap_bytes()
}

/// Reverse the bytes of a u64.
pub fn swap_bytes_u64(val: u64) -> u64 {
    val.swap_bytes()
}

/// Zero-extend a value: keep the lower `bits` bits, zero the rest.
pub fn zero_extend(value: u64, bits: u32) -> u64 {
    if bits >= 64 {
        return value;
    }
    value & ((1u64 << bits) - 1)
}

/// Sign-extend a value: keep the lower `bits` bits, sign-extend the rest.
pub fn sign_extend(value: u64, bits: u32) -> i64 {
    if bits >= 64 {
        return value as i64;
    }
    let shift = 64 - bits;
    ((value as i64) << shift) >> shift
}

/// Rotate left for u32.
pub fn rotate_left_u32(value: u32, count: u32) -> u32 {
    value.rotate_left(count)
}

/// Rotate right for u32.
pub fn rotate_right_u32(value: u32, count: u32) -> u32 {
    value.rotate_right(count)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crc32() {
        let data = b"123456789";
        let checksum = crc32(data);
        assert_eq!(checksum, 0xCBF43926);
    }

    #[test]
    fn test_crc32_empty() {
        assert_eq!(crc32(b""), 0x00000000);
    }

    #[test]
    fn test_bytes_to_hex() {
        assert_eq!(bytes_to_hex(&[0x01, 0xAB, 0xFF]), "01abff");
        assert_eq!(bytes_to_hex(&[]), "");
    }

    #[test]
    fn test_hex_to_bytes() {
        assert_eq!(hex_to_bytes("01abff"), Some(vec![0x01, 0xAB, 0xFF]));
        assert_eq!(hex_to_bytes(""), Some(vec![]));
        assert_eq!(hex_to_bytes("xyz"), None);
        assert_eq!(hex_to_bytes("1"), None); // odd length
    }

    #[test]
    fn test_hex_roundtrip() {
        let data = vec![0x00, 0x01, 0xFF, 0xAB, 0xCD, 0xEF];
        let hex = bytes_to_hex(&data);
        let decoded = hex_to_bytes(&hex).unwrap();
        assert_eq!(data, decoded);
    }

    #[test]
    fn test_adler32() {
        // Wikipedia example: "Wikipedia" -> 0x11E60398
        let checksum = adler32(b"Wikipedia");
        assert_eq!(checksum, 0x11E60398);
    }

    #[test]
    fn test_adler32_empty() {
        assert_eq!(adler32(b""), 0x00000001);
    }

    #[test]
    fn test_xor_checksum() {
        assert_eq!(xor_checksum(&[0x01, 0x02, 0x03]), 0x00);
        assert_eq!(xor_checksum(&[0xFF, 0xFF]), 0x00);
        assert_eq!(xor_checksum(&[0xAA]), 0xAA);
    }

    #[test]
    fn test_byte_sum() {
        assert_eq!(byte_sum(&[1, 2, 3, 4]), 10);
        assert_eq!(byte_sum(&[255, 1]), 0); // wrapping
    }

    #[test]
    fn test_swap_bytes() {
        assert_eq!(swap_bytes_u16(0x0102), 0x0201);
        assert_eq!(swap_bytes_u32(0x01020304), 0x04030201);
        assert_eq!(swap_bytes_u64(0x0102030405060708), 0x0807060504030201);
    }

    #[test]
    fn test_zero_extend() {
        assert_eq!(zero_extend(0xFF, 8), 0xFF);
        assert_eq!(zero_extend(0x1FF, 8), 0xFF);
        assert_eq!(zero_extend(0xABCD, 12), 0xBCD);
        assert_eq!(zero_extend(0x1234, 64), 0x1234);
    }

    #[test]
    fn test_sign_extend() {
        assert_eq!(sign_extend(0x80, 8), -128);
        assert_eq!(sign_extend(0x7F, 8), 127);
        assert_eq!(sign_extend(0x00, 8), 0);
        assert_eq!(sign_extend(0xFF, 8), -1);
        assert_eq!(sign_extend(0x800, 12), -2048);
        assert_eq!(sign_extend(0x7FF, 12), 2047);
    }

    #[test]
    fn test_rotate() {
        assert_eq!(rotate_left_u32(0x80000000, 1), 0x00000001);
        assert_eq!(rotate_right_u32(0x00000001, 1), 0x80000000);
        assert_eq!(rotate_left_u32(0x12345678, 4), 0x23456781);
    }

    #[test]
    fn test_reverse_bits() {
        assert_eq!(reverse_bits_byte(0b10000000), 0b00000001);
        assert_eq!(reverse_bits_byte(0b11000000), 0b00000011);
        assert_eq!(reverse_bits_byte(0xFF), 0xFF);
        assert_eq!(reverse_bits_byte(0x00), 0x00);
    }
}
